import * as route53resolver from 'aws-cdk-lib/aws-route53resolver';
import { Construct } from 'constructs';

export interface DnsFirewallProps {
  /** 許可ドメイン(DNS Firewall 構文。例: '*.classmethod.jp')。NFW の SNI 許可と同じ single source。 */
  readonly allowedDomains: string[];
  /** ルールグループを関連付ける VPC ID 群。 */
  readonly vpcIds: string[];
  /**
   * CNAME/DNAME リダイレクトチェーンの検査方法。
   * - INSPECT_REDIRECTION_DOMAIN: チェーン上の全ドメインを検査(より安全。チェーン先も許可リストに必要)。
   * - TRUST_REDIRECTION_DOMAIN: 最初のドメインのみ検査(リダイレクト先は信頼)。
   * @default 'INSPECT_REDIRECTION_DOMAIN'
   */
  readonly redirectionAction?: 'INSPECT_REDIRECTION_DOMAIN' | 'TRUST_REDIRECTION_DOMAIN';
}

/**
 * Route 53 Resolver DNS Firewall。ホワイトリスト方式。
 *
 * - priority 1: 許可ドメインを ALLOW。
 * - priority 2: それ以外(`*`)を BLOCK(NXDOMAIN を返す)。
 * - 指定された全 VPC の Route 53 Resolver に関連付ける。
 */
export class DnsFirewall extends Construct {
  constructor(scope: Construct, id: string, props: DnsFirewallProps) {
    super(scope, id);

    const allowList = new route53resolver.CfnFirewallDomainList(this, 'AllowList', {
      domains: props.allowedDomains,
    });

    const blockList = new route53resolver.CfnFirewallDomainList(this, 'BlockList', {
      domains: ['*'],
    });

    const ruleGroup = new route53resolver.CfnFirewallRuleGroup(this, 'RuleGroup', {
      firewallRules: [
        {
          priority: 1,
          action: 'ALLOW',
          firewallDomainListId: allowList.attrId,
          // CNAME/DNAME 先も検査(許可ドメインからの許可外ドメインへのリダイレクト回避を防ぐ)
          firewallDomainRedirectionAction: props.redirectionAction ?? 'INSPECT_REDIRECTION_DOMAIN',
        },
        {
          priority: 2,
          action: 'BLOCK',
          blockResponse: 'NXDOMAIN',
          firewallDomainListId: blockList.attrId,
        },
      ],
    });

    props.vpcIds.forEach((vpcId, i) => {
      new route53resolver.CfnFirewallRuleGroupAssociation(this, `Association${i}`, {
        firewallRuleGroupId: ruleGroup.attrId,
        vpcId,
        priority: 101,
      });
    });
  }
}
