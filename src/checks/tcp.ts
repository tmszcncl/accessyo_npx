import net from 'node:net';
import type { TcpResult } from '../types.js';

export function checkTcp(host: string, port = 443, timeoutMs = 5000): Promise<TcpResult> {
  const start = Date.now();

  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });

    const timer = globalThis.setTimeout(() => {
      socket.destroy();
      resolve({
        ok: false,
        durationMs: Date.now() - start,
        port,
        error: `Timeout after ${timeoutMs}ms — possible firewall or network issue`,
      });
    }, timeoutMs);

    socket.once('connect', () => {
      clearTimeout(timer);
      socket.destroy();
      resolve({ ok: true, durationMs: Date.now() - start, port });
    });

    socket.once('error', (err) => {
      clearTimeout(timer);
      resolve({ ok: false, durationMs: Date.now() - start, port, error: formatTcpError(err) });
    });
  });
}

function formatTcpError(err: Error): string {
  if (err.message.includes('ECONNREFUSED')) return 'Connection refused — port closed or firewall blocking';
  if (err.message.includes('EHOSTUNREACH')) return 'Host unreachable';
  if (err.message.includes('ENETUNREACH')) return 'Network unreachable';
  if (err.message.includes('ETIMEDOUT')) return 'Connection timed out';
  return err.message;
}
