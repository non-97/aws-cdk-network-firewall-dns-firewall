import * as ec2 from 'aws-cdk-lib/aws-ec2';

/**
 * 自己管理 DNS サーバー(dnsmasq)用の user-data。
 *
 * 上流を VPC Resolver(169.254.169.253)に固定して転送する。これにより、このサーバー経由の
 * 名前解決はすべて Route 53 Resolver を通り、DNS Firewall のホワイトリストが適用される。
 * クライアントからのクエリ許可は VPC 内の Security Group で制御する。
 */
export const dnsServerUserData = (): ec2.UserData => {
  const userData = ec2.UserData.forLinux();
  userData.addCommands(
    'set -euxo pipefail',
    'dnf install -y dnsmasq',
    // 確定的な挙動のため /etc/dnsmasq.conf を最小構成で上書きする
    'cat > /etc/dnsmasq.conf <<\'EOF\'',
    'port=53',
    'no-resolv',
    'server=169.254.169.253',
    'bind-dynamic',
    'EOF',
    'systemctl enable --now dnsmasq',
  );
  return userData;
};

/**
 * 検証用クライアント EC2 の user-data。
 *
 * dig/nslookup のために bind-utils を導入する。名前解決は自己管理 DNS サーバー経由のため、
 * サーバー起動前だと失敗しうる。リトライして冪等にする。
 */
export const clientUserData = (): ec2.UserData => {
  const userData = ec2.UserData.forLinux();
  userData.addCommands(
    'set -uxo pipefail',
    'for i in $(seq 1 30); do',
    '  dnf install -y bind-utils && break',
    '  sleep 20',
    'done',
  );
  return userData;
};
