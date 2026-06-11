import * as cdk from 'aws-cdk-lib/core';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as networkfirewall from 'aws-cdk-lib/aws-networkfirewall';
import { Construct } from 'constructs';

export interface InspectionVpcProps {
  /** VPC に割り当てる CIDR。 */
  readonly ipAddresses: ec2.IIpAddresses;
  /** 適用する Network Firewall ポリシーの ARN。 */
  readonly firewallPolicyArn: string;
  /** 検査対象のスポーク VPC の CIDR 群(戻り/inter-spoke ルーティング用)。 */
  readonly spokeCidrs: string[];
}

/**
 * Inspection VPC。Network Firewall と NAT Gateway を集約し、全 egress / inter-VPC 通信を検査する。
 *
 * 1 AZ 構成。サブネットは 3 層:
 * - Public : NAT Gateway + IGW。戻り通信はスポーク向けを Firewall エンドポイントへ。
 * - Firewall : Network Firewall エンドポイント。0.0.0.0/0 -> NAT、スポーク CIDR -> TGW(TGW ルートは親で付与)。
 * - Tgw : TGW アタッチメント。0.0.0.0/0 -> Firewall エンドポイント。
 */
export class InspectionVpc extends Construct {
  /** Inspection VPC。 */
  public readonly vpc: ec2.IVpc;
  /** Network Firewall。 */
  public readonly firewall: networkfirewall.CfnFirewall;

  constructor(scope: Construct, id: string, props: InspectionVpcProps) {
    super(scope, id);

    this.vpc = new ec2.Vpc(this, 'Vpc', {
      ipAddresses: props.ipAddresses,
      maxAzs: 1,
      natGateways: 0, // NAT は下で明示的に作成し、ルーティングを制御する
      subnetConfiguration: [
        { name: 'Public', subnetType: ec2.SubnetType.PUBLIC, cidrMask: 28 },
        { name: 'Firewall', subnetType: ec2.SubnetType.PRIVATE_ISOLATED, cidrMask: 28 },
        { name: 'Tgw', subnetType: ec2.SubnetType.PRIVATE_ISOLATED, cidrMask: 28 },
      ],
    });

    const publicSubnet = this.vpc.selectSubnets({ subnetGroupName: 'Public' }).subnets[0];
    const firewallSubnets = this.vpc.selectSubnets({ subnetGroupName: 'Firewall' });
    const tgwSubnet = this.vpc.selectSubnets({ subnetGroupName: 'Tgw' }).subnets[0];

    // NAT Gateway(パブリックサブネットに配置)
    const eip = new ec2.CfnEIP(this, 'NatEip', { domain: 'vpc' });
    const natGateway = new ec2.CfnNatGateway(this, 'NatGateway', {
      subnetId: publicSubnet.subnetId,
      allocationId: eip.attrAllocationId,
    });

    // Network Firewall(ファイアウォールサブネットにエンドポイントを作成)
    this.firewall = new networkfirewall.CfnFirewall(this, 'Firewall', {
      firewallName: `${cdk.Names.uniqueResourceName(this, { maxLength: 100 })}-Firewall`,
      firewallPolicyArn: props.firewallPolicyArn,
      vpcId: this.vpc.vpcId,
      subnetMappings: firewallSubnets.subnetIds.map((subnetId) => ({ subnetId })),
    });

    // ロギング(ALERT は drop/alert イベント、FLOW は通過フロー)。検証に必須。
    const alertLogGroup = new logs.LogGroup(this, 'NfwAlertLogGroup', {
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    const flowLogGroup = new logs.LogGroup(this, 'NfwFlowLogGroup', {
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    new networkfirewall.CfnLoggingConfiguration(this, 'FirewallLogging', {
      firewallArn: this.firewall.attrFirewallArn,
      loggingConfiguration: {
        logDestinationConfigs: [
          {
            logType: 'ALERT',
            logDestinationType: 'CloudWatchLogs',
            logDestination: { logGroup: alertLogGroup.logGroupName },
          },
          {
            logType: 'FLOW',
            logDestinationType: 'CloudWatchLogs',
            logDestination: { logGroup: flowLogGroup.logGroupName },
          },
        ],
      },
    });

    // attrEndpointIds は ["<az>:<vpce-id>"] 形式。1 AZ なので先頭要素から vpce-id を取り出す。
    const firewallEndpointId = cdk.Fn.select(
      1,
      cdk.Fn.split(':', cdk.Fn.select(0, this.firewall.attrEndpointIds)),
    );

    // Public サブネット: スポーク宛て(戻り通信)は Firewall エンドポイントへ。0.0.0.0/0 -> IGW は L2 が自動付与。
    props.spokeCidrs.forEach((cidr, i) => {
      new ec2.CfnRoute(this, `PublicToFirewall${i}`, {
        routeTableId: publicSubnet.routeTable.routeTableId,
        destinationCidrBlock: cidr,
        vpcEndpointId: firewallEndpointId,
      });
    });

    // Firewall サブネット: 検査後の egress を NAT へ(スポーク CIDR -> TGW は親スタックで付与)
    new ec2.CfnRoute(this, 'FirewallToNat', {
      routeTableId: firewallSubnets.subnets[0].routeTable.routeTableId,
      destinationCidrBlock: '0.0.0.0/0',
      natGatewayId: natGateway.ref,
    });

    // Tgw サブネット: TGW から入ってきた全通信をまず Firewall エンドポイントへ
    new ec2.CfnRoute(this, 'TgwToFirewall', {
      routeTableId: tgwSubnet.routeTable.routeTableId,
      destinationCidrBlock: '0.0.0.0/0',
      vpcEndpointId: firewallEndpointId,
    });
  }

  /** TGW アタッチメント配置用サブネット。 */
  public get tgwSubnets(): ec2.SelectedSubnets {
    return this.vpc.selectSubnets({ subnetGroupName: 'Tgw' });
  }

  /** Firewall サブネットのルートテーブル ID(親スタックがスポーク CIDR -> TGW ルートを付与する)。 */
  public get firewallSubnetRouteTableId(): string {
    return this.vpc.selectSubnets({ subnetGroupName: 'Firewall' }).subnets[0].routeTable.routeTableId;
  }
}
