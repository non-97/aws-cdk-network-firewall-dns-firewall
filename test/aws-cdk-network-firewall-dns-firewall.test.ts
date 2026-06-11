import * as cdk from 'aws-cdk-lib/core';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { AwsCdkNetworkFirewallDnsFirewallStack } from '../lib/aws-cdk-network-firewall-dns-firewall-stack';

const allowedDomains = ['*.classmethod.jp', '*.amazonaws.com'];

// env を指定せず合成(account 非指定 = env-agnostic でダミー AZ を使い、認証なしでも合成可能)
const synth = (): Template => {
  const app = new cdk.App();
  const stack = new AwsCdkNetworkFirewallDnsFirewallStack(app, 'TestStack', { allowedDomains });
  return Template.fromStack(stack);
};

describe('AwsCdkNetworkFirewallDnsFirewallStack', () => {
  test('スナップショット', () => {
    expect(synth().toJSON()).toMatchSnapshot();
  });

  // 意思表示: ホワイトリスト型(Application Layer drop established + STRICT_ORDER)
  test('NFW ポリシーは STRICT_ORDER かつ Application Layer drop established', () => {
    synth().hasResourceProperties('AWS::NetworkFirewall::FirewallPolicy', {
      FirewallPolicy: Match.objectLike({
        StatefulEngineOptions: { RuleOrder: 'STRICT_ORDER' },
        StatefulDefaultActions: ['aws:drop_established_app_layer', 'aws:alert_established_app_layer'],
        StatelessDefaultActions: ['aws:forward_to_sfe'],
      }),
    });
  });

  // 手続き的生成 + props 流入: allowedDomains から Suricata ルールが生成されること
  test('NFW ルールは DNS 限定許可 / 許可ドメイン SNI を含む', () => {
    const ruleGroups = synth().findResources('AWS::NetworkFirewall::RuleGroup');
    const rules = (
      Object.values(ruleGroups)[0] as { Properties: { RuleGroup: { RulesSource: { RulesString: string } } } }
    ).Properties.RuleGroup.RulesSource.RulesString;

    expect(rules).toContain('pass dns $HOME_NET any -> $DNS_SERVER 53');
    // single source の各ドメインが dotprefix + endswith で許可されること
    expect(rules).toContain('tls.sni; content:".classmethod.jp"; dotprefix; endswith; nocase;');
    expect(rules).toContain('tls.sni; content:".amazonaws.com"; dotprefix; endswith; nocase;');
  });

  // 意思表示: ホワイトリスト + ワイルドカード BLOCK(NXDOMAIN)
  test('DNS Firewall は許可リスト ALLOW と ワイルドカード BLOCK(NXDOMAIN)', () => {
    const t = synth();
    t.hasResourceProperties('AWS::Route53Resolver::FirewallDomainList', { Domains: allowedDomains });
    t.hasResourceProperties('AWS::Route53Resolver::FirewallDomainList', { Domains: ['*'] });
    t.hasResourceProperties('AWS::Route53Resolver::FirewallRuleGroup', {
      FirewallRules: Match.arrayWith([
        // ALLOW ルールは CNAME/DNAME 先を信頼する(TRUST_REDIRECTION_DOMAIN)
        Match.objectLike({
          Priority: 1,
          Action: 'ALLOW',
          FirewallDomainRedirectionAction: 'TRUST_REDIRECTION_DOMAIN',
        }),
        Match.objectLike({ Priority: 2, Action: 'BLOCK', BlockResponse: 'NXDOMAIN' }),
      ]),
    });
  });

  // props 駆動のループ: 3 VPC への関連付け
  test('DNS Firewall は 3 つの VPC に関連付けられる', () => {
    synth().resourceCountIs('AWS::Route53Resolver::FirewallRuleGroupAssociation', 3);
  });

  // 意思表示: ルーティングを明示制御するため TGW の自動関連付け/伝播を無効化
  test('TGW は自動関連付け/伝播を無効化している', () => {
    synth().hasResourceProperties('AWS::EC2::TransitGateway', {
      DefaultRouteTableAssociation: 'disable',
      DefaultRouteTablePropagation: 'disable',
    });
  });

  // 意思表示: スポークの名前解決を自己管理 DNS サーバーに固定
  test('Client VPC は DHCP オプションセットを関連付ける', () => {
    synth().resourceCountIs('AWS::EC2::VPCDHCPOptionsAssociation', 1);
  });
});
