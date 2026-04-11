export interface IpCheckResult {
  ok: boolean;
  statusCode?: number;
  error?: string;
}

export interface HttpResult {
  ok: boolean;
  durationMs: number;
  statusCode?: number;
  redirects: string[];
  headers: Record<string, string>;
  error?: string;
  blockedBy?: string;
  ipv4?: IpCheckResult;
  ipv6?: IpCheckResult;
  browserStatusCode?: number;
  browserDiffers?: boolean;
}

export interface TcpResult {
  ok: boolean;
  durationMs: number;
  port: number;
  error?: string;
}

export interface TlsResult {
  ok: boolean;
  durationMs: number;
  protocol?: string;
  cipher?: string;
  certIssuer?: string;
  certValidTo?: string;
  certExpired?: boolean;
  error?: string;
}

export interface DnsResult {
  ok: boolean;
  durationMs: number;
  resolver: string;
  aRecords?: string[];
  aaaaRecords?: string[];
  ttl?: number;
  cdn?: string;
  error?: string;
  errorCode?: string;
}
