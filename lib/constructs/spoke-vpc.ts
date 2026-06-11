import * as ec2 from 'aws-cdk-lib/aws-ec2';
import { Construct } from 'constructs';

export interface SpokeVpcProps {
  /** VPC に割り当てる CIDR。 */
  readonly ipAddresses: ec2.IIpAddresses;
}

/**
 * Transit Gateway 配下のスポーク VPC(Client / DNS サーバー用)。
 *
 * - NAT/IGW を持たず、外部への egress は Transit Gateway 経由(Inspection VPC で検査)とする。
 * - すべてのサブネットを ISOLATED とし、デフォルトルート(0.0.0.0/0 -> TGW)は親スタックで付与する。
 * - 管理アクセス用に EC2 Instance Connect Endpoint(EICE)を配置する(SSM のエンドポイント DNS 依存を避けるため)。
 */
export class SpokeVpc extends Construct {
  /** スポーク VPC。 */
  public readonly vpc: ec2.IVpc;
  /** EICE のセキュリティグループ。インスタンス側はこの SG からの 22 番 ingress を許可する。 */
  public readonly eiceSecurityGroup: ec2.SecurityGroup;

  constructor(scope: Construct, id: string, props: SpokeVpcProps) {
    super(scope, id);

    this.vpc = new ec2.Vpc(this, 'Vpc', {
      ipAddresses: props.ipAddresses,
      maxAzs: 1,
      natGateways: 0,
      subnetConfiguration: [
        { name: 'Workload', subnetType: ec2.SubnetType.PRIVATE_ISOLATED, cidrMask: 24 },
        { name: 'Tgw', subnetType: ec2.SubnetType.PRIVATE_ISOLATED, cidrMask: 28 },
      ],
    });

    this.eiceSecurityGroup = new ec2.SecurityGroup(this, 'EiceSecurityGroup', {
      vpc: this.vpc,
      description: 'Security group for EC2 Instance Connect Endpoint',
      allowAllOutbound: false,
    });
    this.eiceSecurityGroup.addEgressRule(
      ec2.Peer.ipv4(this.vpc.vpcCidrBlock),
      ec2.Port.tcp(22),
      'Allow SSH to instances in this VPC',
    );

    new ec2.CfnInstanceConnectEndpoint(this, 'Eice', {
      subnetId: this.vpc.selectSubnets({ subnetGroupName: 'Workload' }).subnetIds[0],
      securityGroupIds: [this.eiceSecurityGroup.securityGroupId],
      preserveClientIp: false,
    });
  }

  /** ワークロード(インスタンス配置)用サブネット。 */
  public get workloadSubnets(): ec2.SelectedSubnets {
    return this.vpc.selectSubnets({ subnetGroupName: 'Workload' });
  }

  /** Transit Gateway アタッチメント配置用サブネット。 */
  public get tgwSubnets(): ec2.SelectedSubnets {
    return this.vpc.selectSubnets({ subnetGroupName: 'Tgw' });
  }
}
