import * as cdk from 'aws-cdk-lib/core';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import { DnsFirewall, InspectionVpc, NetworkFirewallRules, SpokeVpc, TransitGatewayHub } from './constructs';
import { NETWORK_CONFIG } from './network-config';
import { clientUserData, dnsServerUserData } from './ec2/user-data';

export interface AwsCdkNetworkFirewallDnsFirewallStackProps extends cdk.StackProps {
  /** 許可ドメインの single source(DNS Firewall 構文)。DNS Firewall と NFW の SNI/Host 許可の双方を生成する。 */
  readonly allowedDomains: string[];
}

/**
 * DNS Firewall + Network Firewall によるドメインホワイトリスト運用構成。
 *
 * 3 VPC(Client / 自己管理 DNS / Inspection)を Transit Gateway で接続し、全 egress / inter-VPC 通信を
 * Inspection VPC の Network Firewall で検査する集中検査構成。
 */
export class AwsCdkNetworkFirewallDnsFirewallStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: AwsCdkNetworkFirewallDnsFirewallStackProps) {
    super(scope, id, props);

    const inspectionCidr = NETWORK_CONFIG.inspection.cidr;
    const clientCidr = NETWORK_CONFIG.client.cidr;
    const dnsCidr = NETWORK_CONFIG.dns.cidr;
    const machineImage = ec2.MachineImage.latestAmazonLinux2023();

    // --- スポーク VPC(Client / 自己管理 DNS) ---
    const clientVpc = new SpokeVpc(this, 'ClientVpc', { ipAddresses: ec2.IpAddresses.cidr(clientCidr) });
    const dnsVpc = new SpokeVpc(this, 'DnsVpc', { ipAddresses: ec2.IpAddresses.cidr(dnsCidr) });

    // --- 自己管理 DNS サーバー(dnsmasq) ---
    const dnsServerSecurityGroup = new ec2.SecurityGroup(this, 'DnsServerSecurityGroup', {
      vpc: dnsVpc.vpc,
      description: 'Self-managed DNS server',
      allowAllOutbound: true,
    });
    dnsServerSecurityGroup.addIngressRule(ec2.Peer.ipv4(clientCidr), ec2.Port.udp(53), 'DNS UDP from client VPC');
    dnsServerSecurityGroup.addIngressRule(ec2.Peer.ipv4(clientCidr), ec2.Port.tcp(53), 'DNS TCP from client VPC');
    dnsServerSecurityGroup.addIngressRule(dnsVpc.eiceSecurityGroup, ec2.Port.tcp(22), 'SSH from EICE');

    const dnsServer = new ec2.Instance(this, 'DnsServer', {
      vpc: dnsVpc.vpc,
      vpcSubnets: { subnetGroupName: 'Workload' },
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      machineImage,
      securityGroup: dnsServerSecurityGroup,
      userData: dnsServerUserData(),
      requireImdsv2: true,
    });
    const dnsServerIp = dnsServer.instancePrivateIp;

    // --- Network Firewall ルール/ポリシー(DNS サーバー IP と許可ドメインを反映) ---
    const networkFirewallRules = new NetworkFirewallRules(this, 'NetworkFirewallRules', {
      homeNetCidrs: [clientCidr, dnsCidr],
      dnsServerIp,
      allowedDomains: props.allowedDomains,
    });

    // --- Inspection VPC(Network Firewall + NAT Gateway) ---
    const inspectionVpc = new InspectionVpc(this, 'InspectionVpc', {
      ipAddresses: ec2.IpAddresses.cidr(inspectionCidr),
      firewallPolicyArn: networkFirewallRules.firewallPolicy.attrFirewallPolicyArn,
      spokeCidrs: [clientCidr, dnsCidr],
    });

    // --- 検証用クライアント EC2 ---
    const clientSecurityGroup = new ec2.SecurityGroup(this, 'ClientSecurityGroup', {
      vpc: clientVpc.vpc,
      description: 'Client instance',
      allowAllOutbound: true,
    });
    clientSecurityGroup.addIngressRule(clientVpc.eiceSecurityGroup, ec2.Port.tcp(22), 'SSH from EICE');

    const client = new ec2.Instance(this, 'Client', {
      vpc: clientVpc.vpc,
      vpcSubnets: { subnetGroupName: 'Workload' },
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      machineImage,
      securityGroup: clientSecurityGroup,
      userData: clientUserData(),
      requireImdsv2: true,
    });

    // SSM Session Manager 用の権限。VPC エンドポイントは不要(ssm/ssmmessages/ec2messages は
    // *.amazonaws.com 配下のため、DNS Firewall 許可 + NFW の SNI 許可 + NAT 経由のインターネットで到達できる)。
    const ssmManagedPolicy = iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore');
    dnsServer.role.addManagedPolicy(ssmManagedPolicy);
    client.role.addManagedPolicy(ssmManagedPolicy);

    // --- Client VPC の DHCP オプションセット(名前解決先を自己管理 DNS サーバーに固定) ---
    const dhcpOptions = new ec2.CfnDHCPOptions(this, 'ClientDhcpOptions', {
      domainNameServers: [dnsServerIp],
    });
    const dhcpAssociation = new ec2.CfnVPCDHCPOptionsAssociation(this, 'ClientDhcpAssociation', {
      vpcId: clientVpc.vpc.vpcId,
      dhcpOptionsId: dhcpOptions.ref,
    });
    // クライアントは DNS 設定が反映されてから起動させたい
    client.node.addDependency(dhcpAssociation);

    // --- Transit Gateway ハブ ---
    const transitGatewayHub = new TransitGatewayHub(this, 'TransitGatewayHub', {
      inspection: {
        vpcId: inspectionVpc.vpc.vpcId,
        subnetIds: inspectionVpc.tgwSubnets.subnetIds,
        cidr: inspectionCidr,
      },
      spokes: [
        { vpcId: clientVpc.vpc.vpcId, subnetIds: clientVpc.tgwSubnets.subnetIds, cidr: clientCidr },
        { vpcId: dnsVpc.vpc.vpcId, subnetIds: dnsVpc.tgwSubnets.subnetIds, cidr: dnsCidr },
      ],
    });

    // --- スポークのワークロードサブネット: 0.0.0.0/0 -> TGW ---
    const spokeRouting = [
      { vpc: clientVpc, attachment: transitGatewayHub.spokeAttachments[0] },
      { vpc: dnsVpc, attachment: transitGatewayHub.spokeAttachments[1] },
    ];
    spokeRouting.forEach(({ vpc, attachment }, i) => {
      vpc.workloadSubnets.subnets.forEach((subnet, j) => {
        const route = new ec2.CfnRoute(this, `Spoke${i}DefaultRoute${j}`, {
          routeTableId: subnet.routeTable.routeTableId,
          destinationCidrBlock: '0.0.0.0/0',
          transitGatewayId: transitGatewayHub.transitGatewayId,
        });
        route.addDependency(attachment);
      });
    });

    // --- Inspection VPC の Firewall サブネット: スポーク CIDR -> TGW(検査後の転送) ---
    [clientCidr, dnsCidr].forEach((cidr, i) => {
      const route = new ec2.CfnRoute(this, `FirewallToTgw${i}`, {
        routeTableId: inspectionVpc.firewallSubnetRouteTableId,
        destinationCidrBlock: cidr,
        transitGatewayId: transitGatewayHub.transitGatewayId,
      });
      route.addDependency(transitGatewayHub.inspectionAttachment);
    });

    // --- DNS Firewall(全 VPC に関連付け) ---
    new DnsFirewall(this, 'DnsFirewall', {
      allowedDomains: props.allowedDomains,
      vpcIds: [clientVpc.vpc.vpcId, dnsVpc.vpc.vpcId, inspectionVpc.vpc.vpcId],
      // 許可ドメイン(自社/AWS の信頼ドメイン)の CNAME 先は検査せず信頼する。
      // CDN への CNAME 先を whitelist 不要で通せる。第三者ドメインを許可する運用になったら INSPECT に戻すこと。
      redirectionAction: 'TRUST_REDIRECTION_DOMAIN',
    });

    // --- 出力 ---
    new cdk.CfnOutput(this, 'DnsServerPrivateIp', { value: dnsServerIp });
    new cdk.CfnOutput(this, 'ClientInstanceId', { value: client.instanceId });
  }
}
