import * as ec2 from 'aws-cdk-lib/aws-ec2';
import { Construct } from 'constructs';

export interface TransitGatewayTarget {
  /** アタッチする VPC ID。 */
  readonly vpcId: string;
  /** TGW アタッチメントを配置するサブネット ID 群。 */
  readonly subnetIds: string[];
  /** その VPC の CIDR(Inspection ルートテーブルでの宛先指定に使う)。 */
  readonly cidr: string;
}

export interface TransitGatewayHubProps {
  /** Inspection VPC のアタッチ対象。 */
  readonly inspection: TransitGatewayTarget;
  /** スポーク VPC(Client / DNS)のアタッチ対象。 */
  readonly spokes: TransitGatewayTarget[];
}

/**
 * Transit Gateway ハブ。
 *
 * - 自動関連付け / 伝播を無効化し、ルーティングを明示制御する。
 * - Spoke ルートテーブル: 0.0.0.0/0 -> Inspection アタッチメント(全通信を検査へ)。
 * - Inspection ルートテーブル: 各スポーク CIDR -> 対応するスポークアタッチメント(検査後の転送)。
 */
export class TransitGatewayHub extends Construct {
  /** Transit Gateway。 */
  public readonly transitGateway: ec2.CfnTransitGateway;
  /** Inspection VPC のアタッチメント。 */
  public readonly inspectionAttachment: ec2.CfnTransitGatewayVpcAttachment;
  /** スポーク VPC のアタッチメント(props.spokes と同順)。 */
  public readonly spokeAttachments: ec2.CfnTransitGatewayVpcAttachment[];

  constructor(scope: Construct, id: string, props: TransitGatewayHubProps) {
    super(scope, id);

    this.transitGateway = new ec2.CfnTransitGateway(this, 'TransitGateway', {
      description: 'Inspection hub TGW',
      defaultRouteTableAssociation: 'disable',
      defaultRouteTablePropagation: 'disable',
      autoAcceptSharedAttachments: 'disable',
    });

    this.inspectionAttachment = new ec2.CfnTransitGatewayVpcAttachment(this, 'InspectionAttachment', {
      transitGatewayId: this.transitGateway.ref,
      vpcId: props.inspection.vpcId,
      subnetIds: props.inspection.subnetIds,
    });

    this.spokeAttachments = props.spokes.map(
      (spoke, i) =>
        new ec2.CfnTransitGatewayVpcAttachment(this, `SpokeAttachment${i}`, {
          transitGatewayId: this.transitGateway.ref,
          vpcId: spoke.vpcId,
          subnetIds: spoke.subnetIds,
        }),
    );

    const spokeRouteTable = new ec2.CfnTransitGatewayRouteTable(this, 'SpokeRouteTable', {
      transitGatewayId: this.transitGateway.ref,
    });
    const inspectionRouteTable = new ec2.CfnTransitGatewayRouteTable(this, 'InspectionRouteTable', {
      transitGatewayId: this.transitGateway.ref,
    });

    // Inspection アタッチメント -> Inspection ルートテーブルに関連付け
    new ec2.CfnTransitGatewayRouteTableAssociation(this, 'InspectionAssociation', {
      transitGatewayAttachmentId: this.inspectionAttachment.ref,
      transitGatewayRouteTableId: inspectionRouteTable.ref,
    });

    // スポーク -> Spoke ルートテーブル(0.0.0.0/0 -> Inspection)に関連付け + Inspection RT にスポーク CIDR ルート
    this.spokeAttachments.forEach((attachment, i) => {
      new ec2.CfnTransitGatewayRouteTableAssociation(this, `SpokeAssociation${i}`, {
        transitGatewayAttachmentId: attachment.ref,
        transitGatewayRouteTableId: spokeRouteTable.ref,
      });

      new ec2.CfnTransitGatewayRoute(this, `InspectionRouteToSpoke${i}`, {
        transitGatewayRouteTableId: inspectionRouteTable.ref,
        destinationCidrBlock: props.spokes[i].cidr,
        transitGatewayAttachmentId: attachment.ref,
      });
    });

    // Spoke ルートテーブル: 全通信を Inspection アタッチメント経由へ
    new ec2.CfnTransitGatewayRoute(this, 'SpokeDefaultRoute', {
      transitGatewayRouteTableId: spokeRouteTable.ref,
      destinationCidrBlock: '0.0.0.0/0',
      transitGatewayAttachmentId: this.inspectionAttachment.ref,
    });
  }

  /** Transit Gateway ID。 */
  public get transitGatewayId(): string {
    return this.transitGateway.ref;
  }
}
