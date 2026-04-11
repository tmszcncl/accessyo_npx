import http from 'node:http';
import https from 'node:https';
import type { HttpResult } from '../types.js';

const MAX_REDIRECTS = 5;
const TIMEOUT_MS = 5000;

const KEY_HEADERS = ['server', 'content-type', 'location', 'cf-ray', 'cf-cache-status', 'x-powered-by'];

export function checkHttp(host: string): Promise<HttpResult> {
  const url = host.startsWith('http') ? host : `https://${host}`;
  return followRedirects(url, [], Date.now());
}

function followRedirects(
  url: string,
  chain: string[],
  start: number,
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

    const req = lib.request(url, { method: 'GET', timeout: TIMEOUT_MS }, (res) => {
      const { statusCode = 0, headers } = res;

      // consume body to free socket
      res.resume();

      const filteredHeaders = extractHeaders(headers);
      const location = headers['location'];

      if (statusCode >= 300 && statusCode < 400 && location) {
        const next = resolveRedirect(url, location);
        void followRedirects(next, [...chain, url], start).then(resolve);
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

function resolveRedirect(base: string, location: string): string {
  if (location.startsWith('http')) return location;
  const origin = new URL(base).origin;
  return `${origin}${location}`;
}

function detectBlock(status: number, headers: Record<string, string>): string | undefined {
  const isCloudflare =
    'cf-ray' in headers ||
    'cf-cache-status' in headers ||
    headers['server']?.toLowerCase().includes('cloudflare');

  if (isCloudflare && (status === 403 || status === 503)) return 'Cloudflare';
  return undefined;
}

function formatHttpError(err: Error): string {
  if (err.message.includes('ECONNRESET')) return 'Connection reset — possible firewall or backend issue';
  if (err.message.includes('ECONNREFUSED')) return 'Connection refused';
  if (err.message.includes('ENOTFOUND')) return 'Host not found';
  if (err.message.includes('certificate')) return 'TLS/certificate error';
  return err.message;
}
