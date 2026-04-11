import { buildSummary } from '../src/summary.js';
import type { DnsResult, TcpResult, TlsResult, HttpResult } from '../src/types.js';

const okDns: DnsResult = {
  ok: true,
  durationMs: 10,
  resolver: '8.8.8.8',
  aRecords: ['1.2.3.4'],
};

const okTcp: TcpResult = { ok: true, durationMs: 20, port: 443 };

const okTls: TlsResult = { ok: true, durationMs: 30 };

const okHttp: HttpResult = {
  ok: true,
  durationMs: 40,
  statusCode: 200,
  redirects: [],
  headers: {},
};

describe('buildSummary', () => {
  it('returns allOk when all checks pass', () => {
    const result = buildSummary({ dns: okDns, tcp: okTcp, tls: okTls, http: okHttp });
    expect(result.allOk).toBe(true);
    expect(result.problem).toBeNull();
    expect(result.likelyCause).toBeNull();
    expect(result.whatYouCanDo).toHaveLength(0);
  });

  it('diagnoses DNS failure', () => {
    const dns: DnsResult = {
      ok: false,
      durationMs: 5,
      resolver: 'system',
      error: 'NXDOMAIN',
      errorCode: 'NXDOMAIN',
    };
    const result = buildSummary({ dns, tcp: okTcp, tls: okTls, http: okHttp });
    expect(result.allOk).toBe(false);
    expect(result.problem).toMatch(/cannot be resolved/i);
    expect(result.likelyCause).toMatch(/DNS/i);
  });

  it('diagnoses DNS failure when tcp is null (skipped)', () => {
    const dns: DnsResult = {
      ok: false,
      durationMs: 5,
      resolver: 'system',
      error: 'NXDOMAIN',
      errorCode: 'NXDOMAIN',
    };
    const result = buildSummary({ dns, tcp: null, tls: null, http: null });
    expect(result.allOk).toBe(false);
    expect(result.problem).toMatch(/cannot be resolved/i);
    expect(result.likelyCause).toMatch(/DNS/i);
    expect(result.whatYouCanDo.length).toBeGreaterThan(0);
  });

  it('diagnoses TCP failure', () => {
    const tcp: TcpResult = { ok: false, durationMs: 5, port: 443, error: 'ECONNREFUSED' };
    const result = buildSummary({ dns: okDns, tcp, tls: null, http: null });
    expect(result.allOk).toBe(false);
    expect(result.problem).toMatch(/cannot connect/i);
  });

  it('diagnoses TLS failure', () => {
    const tls: TlsResult = { ok: false, durationMs: 5, error: 'certificate expired' };
    const result = buildSummary({ dns: okDns, tcp: okTcp, tls, http: null });
    expect(result.allOk).toBe(false);
    expect(result.problem).toMatch(/secure connection/i);
  });

  it('diagnoses HTTP 403 as blocked', () => {
    const http: HttpResult = {
      ok: false,
      durationMs: 5,
      statusCode: 403,
      redirects: [],
      headers: {},
    };
    const result = buildSummary({ dns: okDns, tcp: okTcp, tls: okTls, http });
    expect(result.allOk).toBe(false);
    expect(result.problem).toMatch(/blocked/i);
    expect(result.likelyCause).toMatch(/CDN/i);
  });

  it('diagnoses HTTP 404', () => {
    const http: HttpResult = {
      ok: false,
      durationMs: 5,
      statusCode: 404,
      redirects: [],
      headers: {},
    };
    const result = buildSummary({ dns: okDns, tcp: okTcp, tls: okTls, http });
    expect(result.problem).toMatch(/not found/i);
  });

  it('diagnoses HTTP 500 as server error', () => {
    const http: HttpResult = {
      ok: false,
      durationMs: 5,
      statusCode: 500,
      redirects: [],
      headers: {},
    };
    const result = buildSummary({ dns: okDns, tcp: okTcp, tls: okTls, http });
    expect(result.problem).toMatch(/server error/i);
  });

  it('handles null tls and http gracefully when all pass', () => {
    const result = buildSummary({ dns: okDns, tcp: okTcp, tls: null, http: null });
    expect(result.allOk).toBe(true);
  });
});
