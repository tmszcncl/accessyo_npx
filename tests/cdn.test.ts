import { detectCdnFromIps } from '../src/checks/cdn.js';

describe('detectCdnFromIps', () => {
  it('detects Cloudflare IP from 104.16.0.0/13 range', () => {
    expect(detectCdnFromIps(['104.16.0.1'])).toBe('Cloudflare');
  });

  it('detects Cloudflare IP from 172.64.0.0/13 range', () => {
    expect(detectCdnFromIps(['172.67.161.111'])).toBe('Cloudflare');
  });

  it('detects Cloudflare IP from 188.114.96.0/20 range', () => {
    expect(detectCdnFromIps(['188.114.96.1'])).toBe('Cloudflare');
  });

  it('returns undefined for a non-CDN IP', () => {
    expect(detectCdnFromIps(['46.4.208.155'])).toBeUndefined();
  });

  it('returns undefined for an empty array', () => {
    expect(detectCdnFromIps([])).toBeUndefined();
  });

  it('detects Cloudflare when mixed with non-CDN IPs', () => {
    expect(detectCdnFromIps(['1.2.3.4', '104.21.73.248'])).toBe('Cloudflare');
  });

  it('skips IPv6 addresses', () => {
    expect(detectCdnFromIps(['2606:4700::1'])).toBeUndefined();
  });

  it('returns undefined for localhost', () => {
    expect(detectCdnFromIps(['127.0.0.1'])).toBeUndefined();
  });
});
