import http from 'node:http';
import https from 'node:https';
import type { HttpResult, HstsInfo, IpCheckResult, WwwCheckResult } from '../types.js';

const MAX_REDIRECTS = 5;
const TIMEOUT_MS = 5000;
const ACCESSYO_UA = 'accessyo/0.1 (+https://github.com/tmszcncl/accessyo_npx)';
const BROWSER_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

const KEY_HEADERS = [
  'server',
  'content-type',
  'location',
  'cf-ray',
  'cf-cache-status',
  'x-powered-by',
  'strict-transport-security',
];

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

  const [ipv4, ipv6, browserResult, wwwCheck] = await Promise.all([
    bothFamilies
      ? quickCheck(url, { family: 4, userAgent: ACCESSYO_UA })
      : Promise.resolve(undefined),
    bothFamilies
      ? quickCheck(url, { family: 6, userAgent: ACCESSYO_UA })
      : Promise.resolve(undefined),
    followRedirects(url, [], Date.now(), BROWSER_UA),
    checkWwwRedirect(host, main.redirects),
  ]);

  // Only flag as "differs" when the browser request gets a hard failure (4xx/5xx)
  // while the plain request succeeded. 3xx chains that resolve to 200 are normal.
  const browserFinalStatus = browserResult.statusCode ?? 0;
  const mainFinalStatus = main.statusCode;
  const browserDiffers = browserFinalStatus >= 400 && mainFinalStatus < 400;

  const hsts = main.headers['strict-transport-security']
    ? parseHsts(main.headers['strict-transport-security'])
    : undefined;

  return {
    ...main,
    ipv4,
    ipv6,
    browserStatusCode: browserResult.statusCode,
    browserDiffers,
    wwwCheck,
    hsts,
  };
}

export async function checkWwwRedirect(host: string, redirects: string[]): Promise<WwwCheckResult> {
  // Strip protocol if present, get bare hostname
  const bare = host.replace(/^https?:\/\//, '').replace(/\/.*$/, '');

  const isWww = bare.startsWith('www.');
  const withoutWww = isWww ? bare.slice(4) : bare;

  // Only applies to apex domains (exactly 2 labels like "example.com")
  // Subdomains (api.example.com) and single labels (localhost) are skipped
  const apexParts = withoutWww.split('.');
  if (apexParts.length !== 2) {
    return { kind: 'skipped' };
  }

  const apex = withoutWww;
  const www = `www.${withoutWww}`;

  // Check whether the redirect chain visits the counterpart
  const chain = redirects.map((u) => u.replace(/^https?:\/\//, '').replace(/\/.*$/, ''));

  if (!isWww) {
    if (chain.some((h) => h === www || h.startsWith(www + '/'))) {
      return { kind: 'apex→www' };
    }
  } else {
    if (chain.some((h) => h === apex || h.startsWith(apex + '/'))) {
      return { kind: 'www→apex' };
    }
  }

  // No redirect observed — probe the counterpart
  const counterpart = `https://${isWww ? apex : www}`;
  const probe = await quickCheck(counterpart, {});
  if (!probe.ok) {
    return { kind: 'www-unreachable' };
  }
  return { kind: 'both-ok' };
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
        const cdn = detectCdn(filteredHeaders);

        resolve({
          ok: statusCode >= 200 && statusCode < 500 && !blockedBy,
          durationMs: Date.now() - start,
          statusCode,
          redirects: chain.length > 0 ? [...chain, url] : [],
          headers: filteredHeaders,
          blockedBy,
          cdn,
        });
      },
    );

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

export function detectCdn(headers: Record<string, string>): string | undefined {
  if (
    'cf-ray' in headers ||
    'cf-cache-status' in headers ||
    headers.server?.toLowerCase().includes('cloudflare')
  ) {
    return 'Cloudflare';
  }
  return undefined;
}

export function detectBlock(status: number, headers: Record<string, string>): string | undefined {
  const cdn = detectCdn(headers);
  if (cdn && (status === 403 || status === 503)) return cdn;
  if (status === 403) return 'server-side';
  return undefined;
}

function quickCheck(
  url: string,
  options: { family?: 4 | 6; userAgent?: string },
): Promise<IpCheckResult> {
  const start = Date.now();
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
        resolve({
          // A response (even 4xx) means IP-level connectivity is working
          ok: statusCode > 0 && statusCode < 500,
          statusCode,
          durationMs: Date.now() - start,
        });
      },
    );

    req.on('timeout', () => {
      req.destroy();
      resolve({ ok: false, durationMs: Date.now() - start, error: 'timeout' });
    });

    req.on('error', (err) => {
      resolve({ ok: false, durationMs: Date.now() - start, error: err.message });
    });

    req.end();
  });
}

function formatHttpError(err: Error): string {
  if (err.message.includes('ECONNRESET'))
    return 'Connection reset — possible firewall or backend issue';
  if (err.message.includes('ECONNREFUSED')) return 'Connection refused';
  if (err.message.includes('ENOTFOUND')) return 'Host not found';
  if (err.message.includes('certificate')) return 'TLS/certificate error';
  return err.message;
}

export function parseHsts(value: string): HstsInfo {
  const lower = value.toLowerCase();
  const maxAgeMatch = /max-age=(\d+)/.exec(lower);
  const maxAge = maxAgeMatch?.[1] !== undefined ? parseInt(maxAgeMatch[1], 10) : 0;
  const includeSubDomains = lower.includes('includesubdomains');
  const preload = lower.includes('preload');
  return { raw: value, maxAge, includeSubDomains, preload };
}
