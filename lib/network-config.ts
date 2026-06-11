/**
 * ネットワーク構成の単一の真実の源(SSOT)。CIDR をここに集約する。
 */
export const NETWORK_CONFIG = {
  /** Inspection VPC(Network Firewall + NAT)。 */
  inspection: { cidr: '10.0.0.0/16' },
  /** Client VPC(検証用 EC2)。 */
  client: { cidr: '10.1.0.0/16' },
  /** 自己管理 DNS サーバー VPC。 */
  dns: { cidr: '10.2.0.0/16' },
} as const;
