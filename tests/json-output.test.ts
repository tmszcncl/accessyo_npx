import { buildJsonOutput } from '../src/commands/json-output.js';
import type { DnsResult, TcpResult, TlsResult, HttpResult } from '../src/types.js';

const baseDns: DnsResult = {
  ok: true,
  durationMs: 12,
  resolver: '8.8.8.8',
  aRecords: ['1.2.3.4'],
  aaaaRecords: [],
  resolverComparison: {
    publicIps: ['1.2.3.4'],
    splitHorizon: false,
  },
  ttl: 300,
};

const baseTcp: TcpResult = { ok: true, durationMs: 30, port: 443 };

const baseTls: TlsResult = {
  ok: true,
  durationMs: 80,
  protocol: 'TLSv1.3',
  cipher: 'TLS_AES_256_GCM_SHA384',
  certDaysRemaining: 90,
};

const baseHttp: HttpResult = {
  ok: true,
  durationMs: 150,
  statusCode: 200,
  redirects: [],
  headers: {},
};

describe('buildJsonOutput', () => {
  it('includes host and timestamp', () => {
    const out = buildJsonOutput('example.com', baseDns, baseTcp, baseTls, baseHttp);
    expect(out.host).toBe('example.com');
    expect(out.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('includes all check results', () => {
    const out = buildJsonOutput('example.com', baseDns, baseTcp, baseTls, baseHttp);
    expect(out.checks.dns).toBe(baseDns);
    expect(out.checks.tcp).toBe(baseTcp);
    expect(out.checks.tls).toBe(baseTls);
    expect(out.checks.http).toBe(baseHttp);
  });

  it('calculates totalMs as sum of all checks', () => {
    const out = buildJsonOutput('example.com', baseDns, baseTcp, baseTls, baseHttp);
    expect(out.summary.totalMs).toBe(12 + 30 + 80 + 150);
  });

  it('sets summary ok true when all checks pass', () => {
    const out = buildJsonOutput('example.com', baseDns, baseTcp, baseTls, baseHttp);
    expect(out.summary.ok).toBe(true);
    expect(out.summary.problem).toBeNull();
  });

  it('sets summary ok false and problem when DNS fails', () => {
    const failDns: DnsResult = { ok: false, durationMs: 5, resolver: '8.8.8.8', error: 'NXDOMAIN' };
    const out = buildJsonOutput('bad.example', failDns, null, null, null);
    expect(out.summary.ok).toBe(false);
    expect(out.summary.problem).not.toBeNull();
  });

  it('handles null tcp/tls/http gracefully', () => {
    const out = buildJsonOutput('example.com', baseDns, null, null, null);
    expect(out.checks.tcp).toBeNull();
    expect(out.checks.tls).toBeNull();
    expect(out.checks.http).toBeNull();
    expect(out.summary.totalMs).toBe(12);
  });
});
