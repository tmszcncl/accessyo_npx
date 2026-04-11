import tls from 'node:tls';
import type { TlsResult } from '../types.js';

export function checkTls(host: string, port = 443, timeoutMs = 5000): Promise<TlsResult> {
  const start = Date.now();

  return new Promise((resolve) => {
    const socket = tls.connect({ host, port, servername: host, ALPNProtocols: ['h2', 'http/1.1'] });

    const timer = globalThis.setTimeout(() => {
      socket.destroy();
      resolve({
        ok: false,
        durationMs: Date.now() - start,
        error: 'Handshake timed out — possible firewall or ISP blocking',
      });
    }, timeoutMs);

    socket.once('secureConnect', () => {
      clearTimeout(timer);

      const cert = socket.getPeerCertificate();
      const protocol = socket.getProtocol() ?? undefined;
      const cipherInfo = socket.getCipher();
      const certIssuer = parseCertIssuer(cert.issuer as Record<string, string> | undefined);
      const certValidTo = cert.valid_to !== '' ? cert.valid_to : undefined;
      const certExpired = certValidTo !== undefined ? new Date(certValidTo) < new Date() : false;
      const certDaysRemaining =
        certValidTo !== undefined
          ? Math.floor((new Date(certValidTo).getTime() - Date.now()) / 86_400_000)
          : undefined;

      const alpnProtocol = socket.alpnProtocol ?? undefined;

      // checkServerIdentity throws if hostname doesn't match — if we reach secureConnect, it matched
      const hostnameMatch = true;

      socket.destroy();
      resolve({
        ok: true,
        durationMs: Date.now() - start,
        protocol,
        cipher: cipherInfo.name,
        certIssuer,
        certValidTo,
        certExpired,
        certDaysRemaining,
        alpnProtocol: typeof alpnProtocol === 'string' ? alpnProtocol : undefined,
        hostnameMatch,
      });
    });

    socket.once('error', (err) => {
      clearTimeout(timer);
      resolve({ ok: false, durationMs: Date.now() - start, error: formatTlsError(err) });
    });
  });
}

function parseCertIssuer(issuer: Record<string, string> | undefined): string | undefined {
  if (!issuer) return undefined;
  return issuer.O ?? issuer.CN;
}

function formatTlsError(err: Error): string {
  const { message } = err;
  if (message.includes('CERT_HAS_EXPIRED')) return 'Certificate expired';
  if (message.includes('DEPTH_ZERO_SELF_SIGNED_CERT') || message.includes('self signed')) {
    return 'Self-signed certificate — not trusted by browsers';
  }
  if (message.includes('ERR_TLS_CERT_ALTNAME_INVALID') || message.includes('hostname')) {
    return 'Certificate hostname mismatch';
  }
  if (message.includes('unable to verify') || message.includes('UNABLE_TO_VERIFY')) {
    return 'Certificate chain verification failed';
  }
  if (message.includes('handshake')) return 'TLS handshake failed';
  return message;
}
