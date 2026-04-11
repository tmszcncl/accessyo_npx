import http from 'node:http';
import https from 'node:https';
import type { HttpResult, IpCheckResult } from '../types.js';

const MAX_REDIRECTS = 5;
const TIMEOUT_MS = 5000;
const ACCESSYO_UA = 'accessyo/0.1 (+https://github.com/tmszcncl/accessyo_npx)';
const BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

const KEY_HEADERS = ['server', 'content-type', 'location', 'cf-ray', 'cf-cache-status', 'x-powered-by'];

export async function checkHttp(
  host: string,
  aRecords: string[] = [],
  aaaaRecords: string[] = [],
): Promise<HttpResult> {
  const url = host.startsWith('http') ? host : `https://${host}`;
  const start = Date.now();
  const main = await followRedirects(url, [], start);

  // Skip secondary checks if no response was received (timeout / connection error)
  if (main.statusCode === undefined) {
    return main;
  }

  const bothFamilies = aRecords.length > 0 && aaaaRecords.length > 0;

  const [ipv4, ipv6, browserResult] = await Promise.all([
    bothFamilies ? quickCheck(url, { family: 4 }) : Promise.resolve(undefined),
    bothFamilies ? quickCheck(url, { family: 6 }) : Promise.resolve(undefined),
    followRedirects(url, [], Date.now(), BROWSER_UA),
  ]);

  // Only flag as "differs" when the browser request gets a hard failure (4xx/5xx)
  // while the plain request succeeded. 3xx chains that resolve to 200 are normal.
  const browserFinalStatus = browserResult.statusCode ?? 0;
  const mainFinalStatus = main.statusCode;
  const browserDiffers =
    browserFinalStatus >= 400 && mainFinalStatus < 400;

  return {
    ...main,
    ipv4,
    ipv6,
    browserStatusCode: browserResult.statusCode,
    browserDiffers,
  };
}

function followRedirects(
  url: string,
  chain: string[],
  start: number,
  userAgent = ACCESSYO_UA,
): Promise<HttpResult> {
  return new Promise((resolve) => {
    if (chain.length > MAX_REDIRECTS) {
      resolve({
        ok: false,
        durationMs: Date.now() - start,
        redirects: chain,
        headers: {},
        error: 'Too many redirects (redirect loop)',
      });
      return;
    }

    const lib = url.startsWith('https') ? https : http;

    const req = lib.request(
      url,
      { method: 'GET', timeout: TIMEOUT_MS, headers: { 'User-Agent': userAgent } },
      (res) => {
      const { statusCode = 0, headers } = res;

      // consume body to free socket
      res.resume();

      const filteredHeaders = extractHeaders(headers);
      const location = headers.location;

      if (statusCode >= 300 && statusCode < 400 && location) {
        const next = resolveRedirect(url, location);
        void followRedirects(next, [...chain, url], start, userAgent).then(resolve);
        return;
      }

      const blockedBy = detectBlock(statusCode, filteredHeaders);

      resolve({
        ok: statusCode >= 200 && statusCode < 500 && !blockedBy,
        durationMs: Date.now() - start,
        statusCode,
        redirects: chain,
        headers: filteredHeaders,
        blockedBy,
      });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({
        ok: false,
        durationMs: Date.now() - start,
        redirects: chain,
        headers: {},
        error: `Timeout after ${TIMEOUT_MS}ms — server not responding`,
      });
    });

    req.on('error', (err) => {
      resolve({
        ok: false,
        durationMs: Date.now() - start,
        redirects: chain,
        headers: {},
        error: formatHttpError(err),
      });
    });

    req.end();
  });
}

function extractHeaders(raw: http.IncomingHttpHeaders): Record<string, string> {
  const result: Record<string, string> = {};
  for (const key of KEY_HEADERS) {
    const val = raw[key];
    if (val !== undefined) {
      result[key] = Array.isArray(val) ? val.join(', ') : val;
    }
  }
  return result;
}

export function resolveRedirect(base: string, location: string): string {
  if (location.startsWith('http')) return location;
  const origin = new URL(base).origin;
  return `${origin}${location}`;
}

export function detectBlock(status: number, headers: Record<string, string>): string | undefined {
  const isCloudflare =
    'cf-ray' in headers ||
    'cf-cache-status' in headers ||
    headers.server?.toLowerCase().includes('cloudflare');

  if (isCloudflare && (status === 403 || status === 503)) return 'Cloudflare';
  return undefined;
}

function quickCheck(
  url: string,
  options: { family?: 4 | 6; userAgent?: string },
): Promise<IpCheckResult> {
  return new Promise((resolve) => {
    const lib = url.startsWith('https') ? https : http;
    const headers: Record<string, string> = {};
    if (options.userAgent) headers['User-Agent'] = options.userAgent;

    const req = lib.request(
      url,
      { method: 'GET', timeout: TIMEOUT_MS, family: options.family, headers },
      (res) => {
        res.resume();
        const statusCode = res.statusCode ?? 0;
        resolve({ ok: statusCode >= 200 && statusCode < 400, statusCode });
      },
    );

    req.on('timeout', () => {
      req.destroy();
      resolve({ ok: false, error: 'timeout' });
    });

    req.on('error', (err) => {
      resolve({ ok: false, error: err.message });
    });

    req.end();
  });
}

function formatHttpError(err: Error): string {
  if (err.message.includes('ECONNRESET')) return 'Connection reset — possible firewall or backend issue';
  if (err.message.includes('ECONNREFUSED')) return 'Connection refused';
  if (err.message.includes('ENOTFOUND')) return 'Host not found';
  if (err.message.includes('certificate')) return 'TLS/certificate error';
  return err.message;
}
