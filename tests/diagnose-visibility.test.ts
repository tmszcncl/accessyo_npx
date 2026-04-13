import { getDnsResolutionSummary, getVisibleHttpHeaders } from '../src/commands/diagnose.js';
import type { DnsResult } from '../src/types.js';

describe('getDnsResolutionSummary', () => {
  const base: DnsResult = {
    ok: true,
    durationMs: 10,
    resolver: '8.8.8.8',
  };

  it('returns IPv4 + IPv6 when both are present', () => {
    expect(
      getDnsResolutionSummary({
        ...base,
        aRecords: ['1.1.1.1'],
        aaaaRecords: ['2a00:1450:4025:804::65'],
      }),
    ).toBe('resolved (IPv4 + IPv6)');
  });

  it('returns IPv4 when only A records are present', () => {
    expect(
      getDnsResolutionSummary({
        ...base,
        aRecords: ['1.1.1.1'],
      }),
    ).toBe('resolved (IPv4)');
  });

  it('returns IPv6 when only AAAA records are present', () => {
    expect(
      getDnsResolutionSummary({
        ...base,
        aaaaRecords: ['2a00:1450:4025:804::65'],
      }),
    ).toBe('resolved (IPv6)');
  });
});

describe('getVisibleHttpHeaders', () => {
  const headers = {
    server: 'cloudflare',
    'cf-ray': 'abc',
    'cache-control': 'public',
    'strict-transport-security': 'max-age=0',
  };

  it('shows only server header in default mode', () => {
    expect(getVisibleHttpHeaders(headers, false)).toEqual([['server', 'cloudflare']]);
  });

  it('shows all headers except HSTS in debug mode', () => {
    expect(getVisibleHttpHeaders(headers, true)).toEqual([
      ['cache-control', 'public'],
      ['cf-ray', 'abc'],
      ['server', 'cloudflare'],
    ]);
  });
});
