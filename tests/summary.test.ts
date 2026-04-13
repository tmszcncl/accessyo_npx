import { buildSummary, computeStatus } from '../src/summary.js';
import type { DnsResult, TcpResult, TlsResult, HttpResult } from '../src/types.js';

const okDns: DnsResult = {
  ok: true,
  durationMs: 10,
  resolver: '8.8.8.8',
  aRecords: ['1.2.3.4'],
  aaaaRecords: ['2a00:1450:4009:80b::200e'],
};

const okTcp: TcpResult = { ok: true, durationMs: 20, port: 443 };
const okTls: TlsResult = { ok: true, durationMs: 30 };

function makeHttp(overrides: Partial<HttpResult> = {}): HttpResult {
  return {
    ok: true,
    durationMs: 40,
    statusCode: 200,
    ttfb: 200,
    redirects: [],
    headers: {},
    ipv4: { ok: true, durationMs: 25 },
    ipv6: { ok: true, durationMs: 30 },
    ...overrides,
  };
}

describe('computeStatus', () => {
  it('returns WORKING when critical checks pass and IPv4 is OK', () => {
    const status = computeStatus({ dns: okDns, tcp: okTcp, tls: okTls, http: makeHttp() });
    expect(status).toBe('WORKING');
  });

  it('returns WORKING when IPv6 fails but IPv4 is OK', () => {
    const status = computeStatus({
      dns: okDns,
      tcp: okTcp,
      tls: okTls,
      http: makeHttp({ ipv6: { ok: false, durationMs: 8, error: 'timeout' } }),
    });
    expect(status).toBe('WORKING');
  });

  it('returns DEGRADED when HTTP is OK but IPv4 is unstable', () => {
    const status = computeStatus({
      dns: okDns,
      tcp: okTcp,
      tls: okTls,
      http: makeHttp({ ipv4: { ok: false, durationMs: 120, error: 'timeout' } }),
    });
    expect(status).toBe('DEGRADED');
  });

  it('returns DEGRADED when many redirects indicate repeated retries', () => {
    const status = computeStatus({
      dns: okDns,
      tcp: okTcp,
      tls: okTls,
      http: makeHttp({
        redirects: ['https://a.example/', 'https://b.example/', 'https://c.example/'],
      }),
    });
    expect(status).toBe('DEGRADED');
  });

  it('returns FAIL on DNS failure', () => {
    const status = computeStatus({
      dns: { ...okDns, ok: false, error: 'NXDOMAIN' },
      tcp: okTcp,
      tls: okTls,
      http: makeHttp(),
    });
    expect(status).toBe('FAIL');
  });
});

describe('buildSummary', () => {
  it('builds WORKING summary for healthy host', () => {
    const result = buildSummary({ dns: okDns, tcp: okTcp, tls: okTls, http: makeHttp() });
    expect(result.status).toBe('WORKING');
    expect(result.allOk).toBe(true);
    expect(result.problem).toBeNull();
    expect(result.warnings).toHaveLength(1); // missing HSTS
    expect(result.warnings[0]?.title).toBe('missing HSTS');
    expect(result.warnings[0]?.level).toBe('warning');
  });

  it('keeps WORKING status and emits IPv6 warning when only IPv6 fails', () => {
    const result = buildSummary({
      dns: okDns,
      tcp: okTcp,
      tls: okTls,
      http: makeHttp({ ipv6: { ok: false, durationMs: 10, error: 'timeout' } }),
    });
    expect(result.status).toBe('WORKING');
    expect(result.allOk).toBe(true);
    expect(result.warnings.some((w) => w.title === 'IPv6')).toBe(true);
  });

  it('adds slow response warning when TTFB > 1000ms without degrading status', () => {
    const result = buildSummary({
      dns: okDns,
      tcp: okTcp,
      tls: okTls,
      http: makeHttp({ ttfb: 1200 }),
    });
    expect(result.status).toBe('WORKING');
    expect(result.warnings.some((w) => w.title.includes('slow response'))).toBe(true);
  });

  it('builds DEGRADED summary when IPv4 is unstable', () => {
    const result = buildSummary({
      dns: okDns,
      tcp: okTcp,
      tls: okTls,
      http: makeHttp({ ipv4: { ok: false, durationMs: 100, error: 'timeout' }, ttfb: 1300 }),
    });
    expect(result.status).toBe('DEGRADED');
    expect(result.allOk).toBe(true);
    expect(result.explanation).toMatch(/degraded/i);
  });

  it('adds unusual redirects warning for long redirect chain', () => {
    const result = buildSummary({
      dns: okDns,
      tcp: okTcp,
      tls: okTls,
      http: makeHttp({
        redirects: ['https://a.example/', 'https://b.example/', 'https://c.example/'],
      }),
    });
    expect(result.status).toBe('DEGRADED');
    expect(result.warnings.some((w) => w.title === 'long redirect chain')).toBe(true);
  });

  it('emits HSTS info when missing on source hostname but redirect changes host', () => {
    const result = buildSummary({
      dns: okDns,
      tcp: okTcp,
      tls: okTls,
      http: makeHttp({
        redirects: ['https://google.com/', 'https://www.google.com/'],
      }),
    });
    const hstsInfo = result.warnings.find((w) => w.title === 'HSTS not set on this hostname');
    expect(hstsInfo).toBeDefined();
    expect(hstsInfo?.level).toBe('info');
  });

  it('does not include partial connectivity warning', () => {
    const result = buildSummary({
      dns: okDns,
      tcp: okTcp,
      tls: okTls,
      http: makeHttp({ ipv6: { ok: false, durationMs: 10, error: 'timeout' } }),
    });
    expect(result.warnings.some((w) => w.title.toLowerCase().includes('partial connectivity'))).toBe(
      false,
    );
  });

  it('does not treat browser/client variance as warning', () => {
    const result = buildSummary({
      dns: okDns,
      tcp: okTcp,
      tls: okTls,
      http: makeHttp({ browserDiffers: true, browserStatusCode: 403 }),
    });
    expect(result.status).toBe('WORKING');
    expect(
      result.warnings.some((w) => w.title.toLowerCase().includes('response varies by client')),
    ).toBe(false);
  });

  it('builds FAIL summary when DNS fails', () => {
    const dns: DnsResult = {
      ...okDns,
      ok: false,
      error: 'NXDOMAIN',
      errorCode: 'NXDOMAIN',
    };
    const result = buildSummary({ dns, tcp: null, tls: null, http: null });
    expect(result.status).toBe('FAIL');
    expect(result.allOk).toBe(false);
    expect(result.problem).toMatch(/cannot be resolved/i);
    expect(result.likelyCause).toMatch(/dns/i);
  });
});
