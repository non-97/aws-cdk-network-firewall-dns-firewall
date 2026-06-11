#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib/core';
import { AwsCdkNetworkFirewallDnsFirewallStack } from '../lib/aws-cdk-network-firewall-dns-firewall-stack';

const app = new cdk.App();

new AwsCdkNetworkFirewallDnsFirewallStack(app, 'AwsCdkNetworkFirewallDnsFirewallStack', {
  // バージニアではなく東京リージョンに固定。account は awsume 後の環境変数から解決する。
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: 'ap-northeast-1' },

  // 許可ドメインの single source(DNS Firewall 構文)。
  // ここが唯一の編集点で、DNS Firewall のドメインリストと NFW の SNI/Host 許可ルールの両方を生成する。
  allowedDomains: [
    '*.classmethod.jp', // 検証対象のホワイトリスト
    '*.amazonaws.com', // EC2 起動(AL2023 dnf リポジトリ)に必須のブートストラップ用
  ],
});
