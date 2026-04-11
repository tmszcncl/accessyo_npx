import { detectCdn, detectBlock, resolveRedirect } from '../src/checks/http.js';

describe('detectCdn', () => {
  it('detects Cloudflare via cf-ray header', () => {
    expect(detectCdn({ 'cf-ray': '123abc' })).toBe('Cloudflare');
  });

  it('detects Cloudflare via cf-cache-status header', () => {
    expect(detectCdn({ 'cf-cache-status': 'HIT' })).toBe('Cloudflare');
  });

  it('detects Cloudflare via server header', () => {
    expect(detectCdn({ server: 'cloudflare' })).toBe('Cloudflare');
  });

  it('detects Cloudflare via server header case-insensitive', () => {
    expect(detectCdn({ server: 'Cloudflare' })).toBe('Cloudflare');
  });

  it('returns undefined for non-CDN headers', () => {
    expect(detectCdn({ server: 'nginx', 'content-type': 'text/html' })).toBeUndefined();
  });

  it('returns undefined for empty headers', () => {
    expect(detectCdn({})).toBeUndefined();
  });
});

describe('detectBlock', () => {
  it('returns Cloudflare for 403 with cf-ray', () => {
    expect(detectBlock(403, { 'cf-ray': '123' })).toBe('Cloudflare');
  });

  it('returns Cloudflare for 503 with cf-cache-status', () => {
    expect(detectBlock(503, { 'cf-cache-status': 'MISS' })).toBe('Cloudflare');
  });

  it('returns server-side for 403 without CDN', () => {
    expect(detectBlock(403, { server: 'nginx' })).toBe('server-side');
  });

  it('returns undefined for 200 even with Cloudflare headers', () => {
    expect(detectBlock(200, { 'cf-ray': '123' })).toBeUndefined();
  });

  it('returns undefined for 404 without CDN', () => {
    expect(detectBlock(404, {})).toBeUndefined();
  });
});

describe('resolveRedirect', () => {
  it('returns absolute URL unchanged', () => {
    expect(resolveRedirect('https://example.com', 'https://other.com/path')).toBe(
      'https://other.com/path',
    );
  });

  it('resolves relative path against base origin', () => {
    expect(resolveRedirect('https://example.com/old', '/new')).toBe('https://example.com/new');
  });
});
