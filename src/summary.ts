import type { DnsResult, TcpResult, TlsResult, HttpResult } from './types.js';

export interface SummaryInput {
  dns: DnsResult;
  tcp: TcpResult;
  tls: TlsResult | null;
  http: HttpResult | null;
}

export interface SummaryResult {
  allOk: boolean;
  problem: string | null;
  likelyCause: string | null;
  whatYouCanDo: string[];
}

export function buildSummary(input: SummaryInput): SummaryResult {
  const { dns, tcp, tls, http } = input;

  if (!dns.ok) {
    return {
      allOk: false,
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
      allOk: false,
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
      allOk: false,
      problem: 'Secure connection failed',
      likelyCause: 'certificate issue or network interference (ISP / VPN)',
      whatYouCanDo: [
        'check certificate expiry',
        'try from a different network',
        'disable VPN if active',
      ],
    };
  }

  if (http !== null && !http.ok) {
    const { statusCode, blockedBy } = http;

    if (blockedBy ?? (statusCode === 403 || statusCode === 503)) {
      return {
        allOk: false,
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
        allOk: false,
        problem: 'Page not found (404)',
        likelyCause: 'the URL does not exist on this server',
        whatYouCanDo: ['check the URL is correct', 'contact the website owner'],
      };
    }

    if (statusCode !== undefined && statusCode >= 500) {
      return {
        allOk: false,
        problem: 'Server error',
        likelyCause: 'the server is returning an error — likely a backend issue',
        whatYouCanDo: ['try again in a few minutes', 'contact the website owner'],
      };
    }

    return {
      allOk: false,
      problem: 'HTTP request failed',
      likelyCause: 'unexpected response from server',
      whatYouCanDo: ['try from a different network', 'contact the website owner'],
    };
  }

  return { allOk: true, problem: null, likelyCause: null, whatYouCanDo: [] };
}
