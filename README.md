# DNS Firewall + Network Firewall ドメインホワイトリスト構成

AWS Network Firewall 単独のドメインフィルタは SNI / Host ヘッダー(クライアントの自己申告値)を信頼するため、SNI スプーフィングに脆弱です
(参考: https://dev.classmethod.jp/articles/aws-network-firewall-egress-tls-inspection/)。

本構成は **TLS インスペクションを使わず**(コスト回避)、Route 53 Resolver DNS Firewall と Network Firewall の多層防御でこの脅威を緩和する PoC です。

## 役割分担

- **Route 53 DNS Firewall**: ドメインのホワイトリスト。許可ドメイン以外の名前解決を BLOCK(NXDOMAIN)。CNAME/DNAME 先は信頼する(`TRUST_REDIRECTION_DOMAIN`)。
  - これにより「DNS を使って不正な接続先 IP を得る」経路を封じ、攻撃者を「IP を直接ハードコードする」しかない状況に追い込む。
- **Network Firewall**(ホワイトリスト型 / STRICT_ORDER / `aws:drop_established_app_layer`):
  1. 自己管理 DNS サーバー宛て以外の DNS(53)を遮断(ローグ DNS / DoH 迂回の防止)。
  2. SNI/Host が許可ドメイン(`*.classmethod.jp` 等)に一致した HTTP/HTTPS のみ pass。
  3. それ以外(空 SNI / IP リテラル SNI / でたらめ SNI / 許可外ドメイン)は **default drop で遮断**。

DNS Firewall の許可リストと NFW の SNI/Host 許可ルールは、**`bin/aws-cdk-network-firewall-dns-firewall.ts` の `allowedDomains` という単一配列(single source)から生成**されます(編集点は 1 箇所)。

## アーキテクチャ

3 つの VPC を Transit Gateway で接続し、Inspection VPC の Network Firewall + NAT Gateway を **全 egress / 全 inter-VPC 通信が通過する集中検査構成**(1 AZ / ap-northeast-1)。

```
[Client VPC]              [Self-managed DNS VPC]
  Client EC2                dnsmasq EC2 (169.254.169.253 へ転送)
   |                          |
   +----------- Transit Gateway -----------+
                     |
               [Inspection VPC]
               TGW → Network Firewall → NAT Gateway → IGW → Internet
```

| VPC | 内容 |
|---|---|
| Client VPC | 検証用 EC2。DHCP オプションセットで名前解決先を自己管理 DNS サーバーに固定。 |
| Self-managed DNS VPC | dnsmasq の EC2。上流を VPC Resolver(`169.254.169.253`)へ転送 → DNS Firewall が適用される。 |
| Inspection VPC | Network Firewall + NAT Gateway + IGW。NFW ログ(ALERT/FLOW)を CloudWatch Logs へ出力。 |

- DNS Firewall は全 VPC の Route 53 Resolver に関連付け。
- 管理アクセスは **EC2 Instance Connect Endpoint (EICE)** と **SSM Session Manager** の両方が利用可能。

## Network Firewall ルール(最終形)

STRICT_ORDER。デフォルト `aws:drop_established_app_layer`(= 明示 pass 以外は drop)。

```
# 自己管理 DNS サーバー宛ての DNS のみ許可(dns アプリ層指定。応答はフロー pass で自動許可)
pass dns  $HOME_NET any -> $DNS_SERVER 53 (flow:to_server)
# 許可ドメインの SNI/Host のみ許可(dotprefix+endswith で境界処理)
pass tls  $HOME_NET any -> $EXTERNAL_NET any (tls.sni;  content:".classmethod.jp"; dotprefix; endswith; nocase)
pass http $HOME_NET any -> $EXTERNAL_NET any (http.host; content:".classmethod.jp"; dotprefix; endswith)   # http.host は nocase 不可
pass tls/http ... .amazonaws.com  # EC2 起動(AL2023 dnf リポジトリ)用
# Application Layer drop established 用の TCP フロー制御(keep-alive ACK / reset、双方向)
pass tcp ... tcp.flags:A; dsize:0; flow:established
pass tcp ... tcp.flags:+R; dsize:0; flow:established
```

ポイント:
- DNS は `dns` アプリ層プロトコルで指定。**応答(戻り)も自動で通る**ため戻り用ルールは不要(ポート指定 `pass udp 53` だと戻りが落ちる)。
- `http.host` は小文字正規化されるため `nocase` は付けない(付けると NFW がデプロイ時に拒否する)。
- 空 SNI / IP リテラル SNI / でたらめ SNI は、どの pass にもマッチせず default drop で遮断(専用 drop ルールは不要)。

## 既知の限界(重要)

- **直接 IP + 許可ドメインを詐称した SNI** は通る。SNI はクライアントの自己申告値で、NFW は実際の接続先と照合せず信用するため。TLS インスペクション無しでは塞げない(根本対策はフォワードプロキシ or TLS インスペクション)。本構成は「ロウエフォートな攻撃を遮断する多層防御の一層」。
- DNS Firewall は `TRUST_REDIRECTION_DOMAIN` のため、許可ドメインの **CNAME/DNAME 先は検査せず信頼**する。**自社/AWS の信頼ドメインのみを許可している前提**で許容。第三者ドメインを許可する運用になる場合は `DnsFirewall` の `redirectionAction` を `INSPECT_REDIRECTION_DOMAIN` に戻すこと。
- 1 AZ のため冗長性なし。NFW エンドポイント / NAT / TGW / EICE / EC2 は時間課金。検証後は `pnpm cdk destroy` を推奨。

## 前提

- リージョン: ap-northeast-1 / 1 AZ
- パッケージマネージャ: pnpm
- ローカル認証: `awsume`(実行後 `aws sts get-caller-identity` で確認)

## ディレクトリ構成

```
bin/aws-cdk-network-firewall-dns-firewall.ts   # App。region + allowedDomains を注入
lib/
  aws-cdk-network-firewall-dns-firewall-stack.ts # 全 Construct の配線
  network-config.ts                              # CIDR(SSOT)
  constructs/
    spoke-vpc.ts            # Client/DNS 用 VPC + EICE
    inspection-vpc.ts       # 3層 subnet + NAT + Network Firewall + ログ + ルーティング
    network-firewall-rules.ts # Suricata ルール生成 + ポリシー
    transit-gateway-hub.ts  # TGW + アタッチメント + ルートテーブル
    dns-firewall.ts         # ドメインリスト + ルールグループ + 関連付け
  ec2/user-data.ts          # dnsmasq / クライアントの user-data
test/                       # スナップショット + fine-grained
```

## デプロイ

```sh
awsume <profile>
pnpm install            # 初回。プロンプトが出たら従う
pnpm cdk diff
pnpm cdk deploy
```

## 管理アクセス

**SSM Session Manager**(VPC エンドポイント不要。`*.amazonaws.com` への NAT 経由インターネット egress で到達):
```sh
aws ssm start-session --target i-xxxxxxxx --region ap-northeast-1
# 登録確認: aws ssm describe-instance-information --region ap-northeast-1
```

**EC2 Instance Connect Endpoint (EICE)**:
```sh
aws ec2-instance-connect ssh --instance-id i-xxxxxxxx --region ap-northeast-1
```

## 動作確認(Client EC2 から)

```sh
# 許可ドメイン → 解決成功・接続成功
dig www.classmethod.jp
curl -v https://www.classmethod.jp

# 非許可ドメイン → NXDOMAIN(DNS Firewall BLOCK)
dig www.google.com | grep -i status

# ローグ DNS → タイムアウト(NFW が 53 を drop)
dig @8.8.8.8 www.classmethod.jp +timeout=2 +tries=1

# IP リテラル / SNI 無し → 遮断
curl -vk https://1.1.1.1

# 【限界の実証】許可ドメインを詐称した SNI + IP 直打ち → 通ってしまう
curl -vk --resolve www.classmethod.jp:443:<任意のIP> https://www.classmethod.jp
```

`status: NXDOMAIN` なら DNS 層(DNS Firewall)、`timed out` なら NFW 層での遮断、と切り分けられる。

## ログ確認

- NFW: CloudWatch Logs の `NfwAlertLogGroup`(ALERT)/ `NfwFlowLogGroup`(FLOW)で pass/drop を確認。
- DNS Firewall: VPC Resolver クエリログ(別途有効化している場合)で ALLOW/BLOCK を確認。

## 後始末

```sh
pnpm cdk destroy
```

## 開発コマンド

| コマンド | 内容 |
|---|---|
| `pnpm cdk synth` | CloudFormation テンプレートを合成 |
| `pnpm cdk diff` | デプロイ済みスタックとの差分 |
| `pnpm test` | jest 単体テスト(スナップショット + fine-grained) |
