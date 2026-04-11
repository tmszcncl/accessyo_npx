import dns from 'node:dns/promises';
import { detectCdnFromIps } from './cdn.js';
import type { DnsResult } from '../types.js';

export async function checkDns(host: string, timeoutMs = 5000): Promise<DnsResult> {
  const start = Date.now();
  const resolver = getResolver();

  try {
    const [aResult, aaaaResult] = await withTimeout(
      Promise.allSettled([dns.resolve4(host, { ttl: true }), dns.resolve6(host)]),
      timeoutMs,
    );

    const aRecords = aResult.status === 'fulfilled' ? aResult.value.map((r) => r.address) : [];
    const aaaaRecords = aaaaResult.status === 'fulfilled' ? aaaaResult.value : [];
    const ttl = aResult.status === 'fulfilled' ? aResult.value[0]?.ttl : undefined;
    const ok = aRecords.length > 0 || aaaaRecords.length > 0;

    if (!ok) {
      const err =
        aResult.status === 'rejected'
          ? aResult.reason
          : aaaaResult.status === 'rejected'
            ? aaaaResult.reason
            : new Error('No DNS records found');
      return {
        ok: false,
        durationMs: Date.now() - start,
        resolver,
        error: formatDnsError(err),
        errorCode: getDnsErrorCode(err),
      };
    }

    const cdn = detectCdnFromIps([...aRecords, ...aaaaRecords]);
    return { ok: true, durationMs: Date.now() - start, resolver, aRecords, aaaaRecords, ttl, cdn };
  } catch (err) {
    return {
      ok: false,
      durationMs: Date.now() - start,
      resolver,
      error: formatDnsError(err),
      errorCode: getDnsErrorCode(err),
    };
  }
}

function getResolver(): string {
  const servers = dns.getServers();
  const first = servers[0];
  if (!first) return 'system';
  // strip port suffix e.g. "8.8.8.8#53" → "8.8.8.8"
  return first.replace(/#\d+$/, '');
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  const timeout = new Promise<never>((_, reject) => {
    timer = globalThis.setTimeout(() => reject(new Error('DNS lookup timed out')), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function formatDnsError(err: unknown): string {
  if (!(err instanceof Error)) return 'Unknown DNS error';
  if (err.message.includes('ENOTFOUND')) return 'NXDOMAIN — domain does not exist';
  if (err.message.includes('ESERVFAIL')) return 'SERVFAIL — DNS server failure';
  if (err.message.includes('timed out')) return `Timed out`;
  if (err.message.includes('ENODATA')) return 'No records found';
  if (err.message.includes('ECONNREFUSED')) return 'DNS resolver unreachable';
  return err.message;
}

function getDnsErrorCode(err: unknown): string | undefined {
  if (!(err instanceof Error)) return undefined;
  if (err.message.includes('ENOTFOUND')) return 'NXDOMAIN';
  if (err.message.includes('ESERVFAIL')) return 'SERVFAIL';
  if (err.message.includes('timed out')) return 'TIMEOUT';
  if (err.message.includes('ENODATA')) return 'ENODATA';
  return undefined;
}
