import type { DnsResult, TcpResult, TlsResult, HttpResult } from './types.js';

export interface SummaryInput {
  dns: DnsResult;
  tcp: TcpResult | null;
  tls: TlsResult | null;
  http: HttpResult | null;
}

export type SummaryStatus = 'WORKING' | 'DEGRADED' | 'FAIL';
export type SummaryWarningLevel = 'warning' | 'info';

export interface SummaryWarning {
  level: SummaryWarningLevel;
  title: string;
  impact: string[];
}

export interface SummaryResult {
  // kept for CLI exit code and JSON compatibility: true when site is reachable
  allOk: boolean;
  status: SummaryStatus;
  explanation: string;
  warnings: SummaryWarning[];
  problem: string | null;
  likelyCause: string | null;
  whatYouCanDo: string[];
}

export function computeStatus(input: SummaryInput): SummaryStatus {
  const failure = detectCriticalFailure(input);
  if (failure !== null) return 'FAIL';

  const http = input.http;
  if (http === null) return 'FAIL';

  if (isIpv4Unstable(http) || hasRepeatedRetries(http) || isExtremelySlow(http)) {
    return 'DEGRADED';
  }

  return 'WORKING';
}

export function buildSummary(input: SummaryInput): SummaryResult {
  const status = computeStatus(input);
  const failure = detectCriticalFailure(input);
  const warnings = collectWarnings(input);

  if (status === 'FAIL') {
    const failureWarnings: SummaryWarning[] =
      failure === null
        ? []
        : [
            {
              level: 'warning',
              title: failure.problem,
              impact: [failure.likelyCause],
            },
          ];
    return {
      allOk: false,
      status,
      explanation: failure?.problem ?? 'critical connectivity checks failed',
      warnings: [...failureWarnings, ...warnings],
      problem: failure?.problem ?? 'critical connectivity checks failed',
      likelyCause: failure?.likelyCause ?? 'network or server issue',
      whatYouCanDo: failure?.whatYouCanDo ?? ['try from a different network'],
    };
  }

  if (status === 'DEGRADED') {
    return {
      allOk: true,
      status,
      explanation: 'site is reachable but quality is degraded',
      warnings,
      problem: null,
      likelyCause: null,
      whatYouCanDo: [],
    };
  }

  return {
    allOk: true,
    status,
    explanation: 'site is reachable',
    warnings,
    problem: null,
    likelyCause: null,
    whatYouCanDo: [],
  };
}

interface FailureCause {
  problem: string;
  likelyCause: string;
  whatYouCanDo: string[];
}

function detectCriticalFailure(input: SummaryInput): FailureCause | null {
  const { dns, tcp, tls, http } = input;

  if (!dns.ok || tcp === null) {
    return {
      problem: 'Domain cannot be resolved',
      likelyCause: 'DNS misconfiguration or typo in domain name',
      whatYouCanDo: [
        'check domain spelling',
        'try a different DNS resolver (e.g. 1.1.1.1)',
        'try from a different network',
      ],
    };
  }

  if (!tcp.ok) {
    return {
      problem: 'Cannot connect to server',
      likelyCause: 'server is down or firewall is blocking the connection',
      whatYouCanDo: [
        'check if the service is running',
        'try from a different network',
        'disable VPN if active',
      ],
    };
  }

  if (tls !== null && !tls.ok) {
    return {
      problem: 'Secure connection failed',
      likelyCause: 'certificate issue or network interference (ISP / VPN)',
      whatYouCanDo: [
        'check certificate expiry',
        'try from a different network',
        'disable VPN if active',
      ],
    };
  }

  if (http === null || !http.ok) {
    const statusCode = http?.statusCode;
    const blockedBy = http?.blockedBy;

    if (blockedBy ?? (statusCode === 403 || statusCode === 503)) {
      return {
        problem: 'Request blocked',
        likelyCause: 'CDN / firewall / WAF is blocking the request',
        whatYouCanDo: [
          'try from a different network (mobile vs WiFi)',
          'disable VPN if active',
          'contact the website owner',
        ],
      };
    }

    if (statusCode === 404) {
      return {
        problem: 'Page not found (404)',
        likelyCause: 'the URL does not exist on this server',
        whatYouCanDo: ['check the URL is correct', 'contact the website owner'],
      };
    }

    if (statusCode !== undefined && statusCode >= 500) {
      return {
        problem: 'Server error',
        likelyCause: 'the server is returning an error — likely a backend issue',
        whatYouCanDo: ['try again in a few minutes', 'contact the website owner'],
      };
    }

    return {
      problem: 'HTTP request failed',
      likelyCause: 'unexpected response from server',
      whatYouCanDo: ['try from a different network', 'contact the website owner'],
    };
  }

  return null;
}

function collectWarnings(input: SummaryInput): SummaryWarning[] {
  const warnings: SummaryWarning[] = [];
  const http = input.http;
  if (!http) return warnings;

  if (http.ipv6 && !http.ipv6.ok) {
    warnings.push({
      level: 'warning',
      title: 'IPv6',
      impact: ['failed from your network', 'may affect some users'],
    });
  }

  if (http.ttfb !== undefined && http.ttfb > 1000) {
    warnings.push({
      level: 'warning',
      title: `slow response (TTFB ${http.ttfb}ms)`,
      impact: ['response is slower than expected', 'users may see delayed page loads'],
    });
  }

  if (!http.hsts) {
    if (hasRedirectToAnotherHostname(http.redirects)) {
      warnings.push({
        level: 'info',
        title: 'HSTS not set on this hostname',
        impact: ['likely enforced on redirect target'],
      });
    } else {
      warnings.push({
        level: 'warning',
        title: 'missing HSTS',
        impact: ['browser can be downgraded to HTTP', 'transport security is weaker on first visit'],
      });
    }
  }

  if (hasRepeatedRetries(http)) {
    warnings.push({
      level: 'warning',
      title: 'long redirect chain',
      impact: ['multiple redirects before final response', 'may increase page load time'],
    });
  }

  return warnings;
}

function isIpv4Unstable(http: HttpResult): boolean {
  return http.ipv4 !== undefined && !http.ipv4.ok;
}

function hasRepeatedRetries(http: HttpResult): boolean {
  return http.redirects.length >= 3;
}

function isExtremelySlow(http: HttpResult): boolean {
  return (http.ttfb ?? 0) > 3000;
}

function hasRedirectToAnotherHostname(redirects: string[]): boolean {
  if (redirects.length < 2) return false;
  const hosts = new Set<string>();
  for (const raw of redirects) {
    try {
      const hostname = new URL(raw).hostname.toLowerCase();
      if (hostname) hosts.add(hostname);
    } catch {
      // ignore malformed URL entries
    }
  }
  return hosts.size >= 2;
}
