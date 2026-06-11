import * as cdk from 'aws-cdk-lib/core';
import * as networkfirewall from 'aws-cdk-lib/aws-networkfirewall';
import { Construct } from 'constructs';

export interface NetworkFirewallRulesProps {
  /** $HOME_NET とする CIDR(スポーク VPC の CIDR 群)。 */
  readonly homeNetCidrs: string[];
  /** 許可する自己管理 DNS サーバーの IP アドレス。 */
  readonly dnsServerIp: string;
  /** 許可ドメイン(DNS Firewall 構文。例: '*.classmethod.jp')。SNI/Host 許可ルールに変換する。 */
  readonly allowedDomains: string[];
}

/**
 * Network Firewall のステートフルルールグループとファイアウォールポリシー。
 *
 * 方針(ホワイトリスト型 / STRICT_ORDER):
 * - ステートフルデフォルトは Application Layer drop established。明示 pass のみ許可し、
 *   空 SNI/Host は pass にマッチせず default drop で遮断される。
 * - SNI/Host の許可は DNS Firewall と同じ単一配列(allowedDomains)から生成する(single source)。
 * - IP リテラルの SNI/Host は pass より前の drop で遮断(content:"." のみだと IP で突破されるため)。
 */
export class NetworkFirewallRules extends Construct {
  /** スポーク VPC の Network Firewall に適用するファイアウォールポリシー。 */
  public readonly firewallPolicy: networkfirewall.CfnFirewallPolicy;

  constructor(scope: Construct, id: string, props: NetworkFirewallRulesProps) {
    super(scope, id);

    const ruleGroup = new networkfirewall.CfnRuleGroup(this, 'StatefulRuleGroup', {
      ruleGroupName: `${cdk.Names.uniqueResourceName(this, { maxLength: 100 })}-StatefulRuleGroup`,
      capacity: 200,
      type: 'STATEFUL',
      ruleGroup: {
        ruleVariables: {
          ipSets: {
            HOME_NET: { definition: props.homeNetCidrs },
            DNS_SERVER: { definition: [`${props.dnsServerIp}/32`] },
          },
        },
        statefulRuleOptions: { ruleOrder: 'STRICT_ORDER' },
        rulesSource: { rulesString: this.buildRulesString(props.allowedDomains) },
      },
    });

    this.firewallPolicy = new networkfirewall.CfnFirewallPolicy(this, 'Policy', {
      firewallPolicyName: `${cdk.Names.uniqueResourceName(this, { maxLength: 100 })}-Policy`,
      firewallPolicy: {
        statelessDefaultActions: ['aws:forward_to_sfe'],
        statelessFragmentDefaultActions: ['aws:forward_to_sfe'],
        statefulEngineOptions: { ruleOrder: 'STRICT_ORDER' },
        // Application Layer drop established(+ alert)。セグメント化された ClientHello を SNI 検出まで通してから判定する。
        statefulDefaultActions: ['aws:drop_established_app_layer', 'aws:alert_established_app_layer'],
        statefulRuleGroupReferences: [{ resourceArn: ruleGroup.attrRuleGroupArn, priority: 1 }],
      },
    });
  }

  /** allowedDomains から Suricata ルール文字列を生成する(STRICT_ORDER の記述順がそのまま評価順)。 */
  private buildRulesString(allowedDomains: string[]): string {
    const lines: string[] = [];
    let sid = 1000001;

    // (1) DNS: 自己管理 DNS サーバー宛てのみ許可。dns アプリ層プロトコルで UDP/TCP の DNS を一括指定
    //     (ポートだけでなく、実際に DNS が話されている通信に限定する)。
    //     dns のフロー pass が応答(戻り)も自動で通すため、応答方向の明示 pass は不要
    //     (実機でクライアントからの名前解決成功を確認済み。pass udp/tcp 53 のポート指定だと戻りは別途必要)。
    lines.push(`pass dns $HOME_NET any -> $DNS_SERVER 53 (msg:"Allow DNS query to self-managed"; flow:to_server; sid:${sid++};)`);

    // (2) 許可ドメインの SNI/Host のみ pass(dotprefix + endswith で境界を正しく処理)。
    //     IP リテラルや許可外ドメインの SNI/Host は、ここにマッチせずデフォルト(drop established)で遮断される。
    //     (許可リスト方式のため、旧来の「IP-in-SNI を明示 drop」ルールは不要)
    for (const domain of allowedDomains) {
      const base = domain.replace(/^\*\./, '');
      lines.push(`pass tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Allow SNI .${base}"; flow:to_server; ssl_state:client_hello; tls.sni; content:".${base}"; dotprefix; endswith; nocase; sid:${sid++};)`);
      // http.host バッファは小文字に正規化されるため nocase は付けない(NFW が冗長として拒否する)
      lines.push(`pass http $HOME_NET any -> $EXTERNAL_NET any (msg:"Allow Host .${base}"; flow:to_server; http.host; content:".${base}"; dotprefix; endswith; sid:${sid++};)`);
    }

    // (3) Application Layer drop established 用の TCP フロー制御 pass(keep-alive ACK / reset)。
    //     これがないと handshake 直後の制御パケットが落ちうる。AWS 公式
    //     「About the application layer drop established action」の例に準拠:
    //     https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-rule-evaluation-order.html
    lines.push(`pass tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Allow TCP keepalive/window to_server"; tcp.flags:A; dsize:0; flow:established,to_server; sid:${sid++};)`);
    lines.push(`pass tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Allow TCP keepalive/window to_client"; tcp.flags:A; dsize:0; flow:established,to_client; sid:${sid++};)`);
    lines.push(`pass tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Allow TCP reset to_server"; tcp.flags:+R; dsize:0; flow:established,to_server; sid:${sid++};)`);
    lines.push(`pass tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Allow TCP reset to_client"; tcp.flags:+R; dsize:0; flow:established,to_client; sid:${sid++};)`);

    return lines.join('\n');
  }
}
