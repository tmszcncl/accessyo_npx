export interface ParsedTarget {
  input: string;
  host: string;
  port: number;
  normalizedTarget: string;
  parsedFrom?: string;
  httpTarget: string;
}

export function parseTarget(input: string, defaultPort = 443): ParsedTarget {
  const raw = input.trim();
  const fromUrl = parseAsUrl(raw);
  if (fromUrl) return fromUrl;

  const parsedHostPort = parseHostPort(raw);
  const host = parsedHostPort?.host ?? stripBrackets(raw);
  const port = parsedHostPort?.port ?? defaultPort;
  return {
    input: raw,
    host,
    port,
    normalizedTarget: formatHostPort(host, port),
    httpTarget: buildHttpTarget('https', host, port, '/'),
  };
}

function parseAsUrl(raw: string): ParsedTarget | null {
  try {
    const url = new URL(raw);
    const protocol = url.protocol === 'http:' ? 'http' : url.protocol === 'https:' ? 'https' : null;
    if (!protocol || !url.hostname) return null;

    const port = readPort(url.port, protocol === 'http' ? 80 : 443);
    const pathname = url.pathname || '/';
    const pathWithQuery = `${pathname}${url.search}`;
    return {
      input: raw,
      host: url.hostname,
      port,
      normalizedTarget: formatHostPort(url.hostname, port),
      parsedFrom: raw,
      httpTarget: buildHttpTarget(protocol, url.hostname, port, pathWithQuery),
    };
  } catch {
    return null;
  }
}

function parseHostPort(raw: string): { host: string; port: number } | null {
  const idx = raw.lastIndexOf(':');
  if (idx <= 0 || idx >= raw.length - 1) return null;

  const hostPart = raw.slice(0, idx).trim();
  const portPart = raw.slice(idx + 1).trim();
  if (!/^\d+$/.test(portPart)) return null;

  const parsedPort = Number.parseInt(portPart, 10);
  if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) return null;

  return {
    host: stripBrackets(hostPart),
    port: parsedPort,
  };
}

function readPort(rawPort: string, fallback: number): number {
  if (!rawPort) return fallback;
  const parsed = Number.parseInt(rawPort, 10);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) return fallback;
  return parsed;
}

function stripBrackets(host: string): string {
  if (host.startsWith('[') && host.endsWith(']')) {
    return host.slice(1, -1);
  }
  return host;
}

function formatHostPort(host: string, port: number): string {
  if (host.includes(':') && !host.startsWith('[')) return `[${host}]:${port}`;
  return `${host}:${port}`;
}

function buildHttpTarget(
  protocol: 'http' | 'https',
  host: string,
  port: number,
  pathWithQuery: string,
): string {
  const hostPort = formatHostPort(host, port);
  const normalizedPath = pathWithQuery.startsWith('/') ? pathWithQuery : `/${pathWithQuery}`;
  return `${protocol}://${hostPort}${normalizedPath}`;
}
