// Offline CDN detection based on resolved IP addresses.
// IP ranges are a hardcoded snapshot — best-effort, not authoritative.
// Sources: https://www.cloudflare.com/ips/

interface CdnRange {
  name: string;
  // CIDR: [network as 32-bit int, prefix length]
  ranges: [number, number][];
}

const CDN_RANGES: CdnRange[] = [
  {
    name: 'Cloudflare',
    ranges: [
      [ipToInt('103.21.244.0'), 22],
      [ipToInt('103.22.200.0'), 22],
      [ipToInt('103.31.4.0'), 22],
      [ipToInt('104.16.0.0'), 13],
      [ipToInt('104.24.0.0'), 14],
      [ipToInt('108.162.192.0'), 18],
      [ipToInt('131.0.72.0'), 22],
      [ipToInt('141.101.64.0'), 18],
      [ipToInt('162.158.0.0'), 15],
      [ipToInt('172.64.0.0'), 13],
      [ipToInt('173.245.48.0'), 20],
      [ipToInt('188.114.96.0'), 20],
      [ipToInt('190.93.240.0'), 20],
      [ipToInt('197.234.240.0'), 22],
      [ipToInt('198.41.128.0'), 17],
    ],
  },
];

export function detectCdnFromIps(ips: string[]): string | undefined {
  for (const ip of ips) {
    const result = matchCdn(ip);
    if (result) return result;
  }
  return undefined;
}

function matchCdn(ip: string): string | undefined {
  // IPv6 — skip for now, ranges not implemented
  if (ip.includes(':')) return undefined;

  const ipInt = ipToInt(ip);
  for (const cdn of CDN_RANGES) {
    for (const [network, prefix] of cdn.ranges) {
      if (inRange(ipInt, network, prefix)) return cdn.name;
    }
  }
  return undefined;
}

function inRange(ip: number, network: number, prefix: number): boolean {
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (ip & mask) === (network & mask);
}

function ipToInt(ip: string): number {
  return ip
    .split('.')
    .reduce((acc, octet) => (acc << 8) | parseInt(octet, 10), 0) >>> 0;
}
