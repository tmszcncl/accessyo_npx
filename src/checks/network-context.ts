import dns from 'node:dns/promises';
import https from 'node:https';
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

export async function getNetworkContext(): Promise<NetworkContext> {
  const [ipResult, ipv6Available] = await Promise.all([fetchPublicIpAndCountry(), checkIpv6()]);

  const resolverIp = getResolver();
  const resolverLabel = KNOWN_RESOLVERS[resolverIp];

  return {
    publicIp: ipResult?.ip,
    country: ipResult?.country,
    resolverIp,
    resolverLabel,
    ipv6Available,
  };
}

function fetchPublicIpAndCountry(): Promise<
  { ip: string; country: string | undefined } | undefined
> {
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
            const parsed = JSON.parse(data) as { ip?: string; country_code?: string };
            const ip = parsed.ip;
            if (!ip || ip.length > 50) {
              resolve(undefined);
              return;
            }
            resolve({ ip, country: parsed.country_code });
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

async function checkIpv6(): Promise<boolean> {
  try {
    const result = await Promise.race([
      dns.resolve6('ipv6.google.com'),
      new Promise<never>((_, reject) =>
        globalThis.setTimeout(() => {
          reject(new Error('timeout'));
        }, 2000),
      ),
    ]);
    return Array.isArray(result) && result.length > 0;
  } catch {
    return false;
  }
}

function getResolver(): string {
  const servers = dns.getServers();
  const first = servers[0];
  if (!first) return 'unknown';
  return first.replace(/#\d+$/, '');
}
