import dns from 'node:dns/promises';
import fs from 'node:fs/promises';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import type { NetworkContext } from '../types.js';

const KNOWN_RESOLVERS: Record<string, string> = {
  '8.8.8.8': 'Google DNS',
  '8.8.4.4': 'Google DNS',
  '1.1.1.1': 'Cloudflare DNS',
  '1.0.0.1': 'Cloudflare DNS',
  '9.9.9.9': 'Quad9',
  '208.67.222.222': 'OpenDNS',
  '208.67.220.220': 'OpenDNS',
};

export const IPAPI_CACHE_TTL_MS = 60 * 60 * 1000;
export const IPAPI_STALE_IF_ERROR_MS = 24 * 60 * 60 * 1000;
export const IPAPI_NEGATIVE_CACHE_MS = 5 * 60 * 1000;

interface IpApiCacheEntry {
  fetchedAt?: string;
  data?: IpApiNetworkInfo;
  lastFailureAt?: string;
}

export interface IpApiNetworkInfo {
  ip: string;
  countryCode?: string;
  countryName?: string;
  isp?: string;
  asn?: string;
}

export async function getNetworkContext(): Promise<NetworkContext> {
  const ipResult = await getIpApiNetworkInfo();

  const resolverIp = getResolver();
  const resolverLabel = KNOWN_RESOLVERS[resolverIp];

  return {
    publicIp: ipResult?.ip,
    country: ipResult?.countryCode,
    countryName: ipResult?.countryName,
    isp: ipResult?.isp,
    asn: ipResult?.asn,
    resolverIp,
    resolverLabel,
  };
}

type ReadCacheFn = (maxAgeMs: number) => Promise<IpApiNetworkInfo | undefined>;
type FetchRemoteFn = () => Promise<IpApiNetworkInfo | undefined>;
type WriteCacheFn = (data: IpApiNetworkInfo) => Promise<void>;
type HasRecentFailureFn = () => Promise<boolean>;
type MarkFailureFn = () => Promise<void>;
type ClearFailureFn = () => Promise<void>;

export async function getIpApiNetworkInfo(
  readCache: ReadCacheFn = readCachedIpApiInfo,
  fetchRemote: FetchRemoteFn = fetchIpApiNetworkInfo,
  writeCache: WriteCacheFn = writeCachedIpApiInfo,
  hasRecentFailure: HasRecentFailureFn = hasRecentIpApiFailure,
  markFailure: MarkFailureFn = markIpApiFailure,
  clearFailure: ClearFailureFn = clearIpApiFailure,
): Promise<IpApiNetworkInfo | undefined> {
  const fresh = await readCache(IPAPI_CACHE_TTL_MS);
  if (fresh) return fresh;

  if (await hasRecentFailure()) {
    return readCache(IPAPI_STALE_IF_ERROR_MS);
  }

  const fetched = await fetchRemote();
  if (fetched) {
    await writeCache(fetched);
    await clearFailure();
    return fetched;
  }

  await markFailure();
  return readCache(IPAPI_STALE_IF_ERROR_MS);
}

export function maskPublicIp(ip: string): string {
  if (net.isIPv4(ip)) {
    const octets = ip.split('.');
    if (octets.length === 4) {
      return `${octets[0]}.${octets[1]}.xxx.xxx`;
    }
  }

  if (net.isIPv6(ip)) {
    const parts = ip.split(':').filter((part) => part.length > 0);
    const first = parts[0] ?? 'xxxx';
    const second = parts[1] ?? 'xxxx';
    return `${first}:${second}:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx`;
  }

  return ip;
}

async function fetchIpApiNetworkInfo(): Promise<IpApiNetworkInfo | undefined> {
  return new Promise((resolve) => {
    const timer = globalThis.setTimeout(() => {
      req.destroy();
      resolve(undefined);
    }, 2000);

    const req = https.get(
      'https://ipapi.co/json/',
      { headers: { 'User-Agent': 'accessyo/0.1' } },
      (res) => {
        let data = '';
        res.on('data', (chunk: Buffer) => {
          data += chunk.toString();
        });
        res.on('end', () => {
          clearTimeout(timer);
          try {
            const parsed = JSON.parse(data) as {
              ip?: unknown;
              country_code?: string;
              country_name?: string;
              org?: string;
              asn?: string;
            };
            resolve(
              sanitizeIpApiData({
                ip: readString(parsed.ip, 50),
                countryCode: readString(parsed.country_code, 8),
                countryName: readString(parsed.country_name, 120),
                isp: readString(parsed.org, 120),
                asn: readString(parsed.asn, 32),
              }),
            );
          } catch {
            resolve(undefined);
          }
        });
      },
    );

    req.on('error', () => {
      clearTimeout(timer);
      resolve(undefined);
    });
  });
}

async function readCachedIpApiInfo(maxAgeMs: number): Promise<IpApiNetworkInfo | undefined> {
  const entry = await loadCacheEntry();
  if (!entry || typeof entry.fetchedAt !== 'string') return undefined;

  const fetchedAt = Date.parse(entry.fetchedAt);
  if (!Number.isFinite(fetchedAt)) return undefined;
  if (Date.now() - fetchedAt > maxAgeMs) return undefined;

  return sanitizeIpApiData(entry.data ?? {});
}

async function writeCachedIpApiInfo(data: IpApiNetworkInfo): Promise<void> {
  try {
    const payload = (await loadCacheEntry()) ?? {};
    payload.fetchedAt = new Date().toISOString();
    payload.data = data;
    payload.lastFailureAt = undefined;
    await saveCacheEntry(payload);
  } catch {
    // ignore cache write failures - diagnostics should continue
  }
}

async function hasRecentIpApiFailure(): Promise<boolean> {
  const entry = await loadCacheEntry();
  if (!entry || typeof entry.lastFailureAt !== 'string') return false;

  const lastFailureAt = Date.parse(entry.lastFailureAt);
  if (!Number.isFinite(lastFailureAt)) return false;
  return Date.now() - lastFailureAt <= IPAPI_NEGATIVE_CACHE_MS;
}

async function markIpApiFailure(): Promise<void> {
  try {
    const payload = (await loadCacheEntry()) ?? {};
    payload.lastFailureAt = new Date().toISOString();
    await saveCacheEntry(payload);
  } catch {
    // ignore cache write failures - diagnostics should continue
  }
}

async function clearIpApiFailure(): Promise<void> {
  try {
    const payload = await loadCacheEntry();
    if (!payload || payload.lastFailureAt === undefined) return;
    payload.lastFailureAt = undefined;
    await saveCacheEntry(payload);
  } catch {
    // ignore cache write failures - diagnostics should continue
  }
}

async function loadCacheEntry(): Promise<IpApiCacheEntry | undefined> {
  try {
    const raw = await fs.readFile(getCachePath(), 'utf8');
    const parsed = JSON.parse(raw) as Partial<IpApiCacheEntry>;
    if (!parsed || typeof parsed !== 'object') return undefined;
    return parsed;
  } catch {
    return undefined;
  }
}

async function saveCacheEntry(payload: IpApiCacheEntry): Promise<void> {
  const cachePath = getCachePath();
  await fs.mkdir(path.dirname(cachePath), { recursive: true });
  const entry: IpApiCacheEntry = {
      fetchedAt: new Date().toISOString(),
      ...payload,
    };
  if (entry.lastFailureAt === undefined) {
    delete entry.lastFailureAt;
  }
  await fs.writeFile(cachePath, JSON.stringify(entry), 'utf8');
}

function sanitizeIpApiData(data: Partial<IpApiNetworkInfo>): IpApiNetworkInfo | undefined {
  const ip = readString(data.ip, 50);
  if (!ip) return undefined;

  return {
    ip,
    countryCode: readString(data.countryCode, 8),
    countryName: readString(data.countryName, 120),
    isp: readString(data.isp, 120),
    asn: readString(data.asn, 32),
  };
}

function readString(value: unknown, maxLength: number): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > maxLength) return undefined;
  return trimmed;
}

function getCachePath(): string {
  const override = process.env.ACCESSYO_CACHE_DIR?.trim();
  if (override) {
    return path.join(override, 'accessyo', 'network-context.json');
  }
  const baseDir = resolveDefaultCacheDir();
  return path.join(baseDir, 'accessyo', 'network-context.json');
}

function resolveDefaultCacheDir(): string {
  if (process.platform === 'darwin') {
    return path.join(os.homedir(), 'Library', 'Caches');
  }
  if (process.platform === 'win32') {
    return (
      process.env.LOCALAPPDATA ??
      process.env.APPDATA ??
      path.join(os.homedir(), 'AppData', 'Local')
    );
  }
  return process.env.XDG_CACHE_HOME ?? path.join(os.homedir(), '.cache');
}

function getResolver(): string {
  const servers = dns.getServers();
  const first = servers[0];
  if (!first) return 'unknown';
  return first.replace(/#\d+$/, '');
}
