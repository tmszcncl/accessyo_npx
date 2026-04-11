export interface NetworkContext {
  publicIp: string | undefined;
  country: string | undefined;
  resolverIp: string;
  resolverLabel: string | undefined;
}

export interface IpCheckResult {
  ok: boolean;
  statusCode?: number;
  durationMs: number;
  error?: string;
}

export interface WwwCheckResult {
  /** 'www→apex' | 'apex→www' | 'both-ok' | 'www-unreachable' | 'skipped' */
  kind: 'www→apex' | 'apex→www' | 'both-ok' | 'www-unreachable' | 'skipped';
}

export interface HstsInfo {
  raw: string;
  maxAge: number;
  includeSubDomains: boolean;
  preload: boolean;
}

export interface HttpResult {
  ok: boolean;
  durationMs: number;
  ttfb?: number;
  statusCode?: number;
  redirects: string[];
  headers: Record<string, string>;
  error?: string;
  blockedBy?: string;
  cdn?: string;
  ipv4?: IpCheckResult;
  ipv6?: IpCheckResult;
  browserStatusCode?: number;
  browserDiffers?: boolean;
  wwwCheck?: WwwCheckResult;
  hsts?: HstsInfo;
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
  certDaysRemaining?: number;
  alpnProtocol?: string;
  hostnameMatch?: boolean;
  error?: string;
}

export interface ResolverComparison {
  /** IPs returned by 1.1.1.1 (Cloudflare) */
  publicIps: string[];
  /** true when system resolver returns private IPs while 1.1.1.1 returns public IPs */
  splitHorizon: boolean;
}

export interface DnsResult {
  ok: boolean;
  durationMs: number;
  resolver: string;
  aRecords?: string[];
  aaaaRecords?: string[];
  cname?: string;
  ttl?: number;
  cdn?: string;
  resolverComparison?: ResolverComparison;
  error?: string;
  errorCode?: string;
}
