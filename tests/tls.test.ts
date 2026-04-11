import { jest } from '@jest/globals';
import tls from 'node:tls';
import { checkTls } from '../src/checks/tls.js';

type SecureConnectHandler = () => void;
type ErrorHandler = (err: Error) => void;

function makeMockSocket(overrides: {
  alpnProtocol?: string | false;
  protocol?: string;
  cipher?: { name: string; version: string };
  cert?: object;
  error?: Error;
}): jest.Mocked<tls.TLSSocket> {
  const handlers: Record<string, (...args: unknown[]) => void> = {};

  const socket = {
    once(event: string, handler: (...args: unknown[]) => void) {
      handlers[event] = handler;
      return socket;
    },
    destroy: jest.fn(),
    alpnProtocol: overrides.alpnProtocol ?? false,
    getProtocol: jest.fn().mockReturnValue(overrides.protocol ?? 'TLSv1.3'),
    getCipher: jest
      .fn()
      .mockReturnValue(
        overrides.cipher ?? { name: 'TLS_AES_256_GCM_SHA384', version: 'TLSv1/SSLv3' },
      ),
    getPeerCertificate: jest.fn().mockReturnValue(
      overrides.cert ?? {
        issuer: { O: 'Test CA' },
        valid_to: 'Jan 01 00:00:00 2099 GMT',
      },
    ),
    _trigger(event: string, ...args: unknown[]) {
      handlers[event]?.(...args);
    },
  } as unknown as jest.Mocked<tls.TLSSocket> & {
    _trigger: (event: string, ...args: unknown[]) => void;
  };

  // schedule event in microtask so checkTls has time to register handlers
  Promise.resolve().then(() => {
    if (overrides.error) {
      (socket as unknown as { _trigger: (event: string, ...args: unknown[]) => void })._trigger(
        'error',
        overrides.error,
      );
    } else {
      (socket as unknown as { _trigger: (event: string, ...args: unknown[]) => void })._trigger(
        'secureConnect',
      );
    }
  });

  return socket;
}

describe('checkTls', () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let connectSpy: ReturnType<typeof jest.spyOn>;

  afterEach(() => {
    connectSpy?.mockRestore();
  });

  it('passes ALPNProtocols h2 and http/1.1 to tls.connect', async () => {
    const socket = makeMockSocket({});
    connectSpy = jest.spyOn(tls, 'connect').mockReturnValue(socket);

    await checkTls('example.com');

    expect(connectSpy).toHaveBeenCalledWith(
      expect.objectContaining({ ALPNProtocols: ['h2', 'http/1.1'] }),
    );
  });

  it('returns alpnProtocol "h2" when server negotiates HTTP/2', async () => {
    const socket = makeMockSocket({ alpnProtocol: 'h2' });
    connectSpy = jest.spyOn(tls, 'connect').mockReturnValue(socket);

    const result = await checkTls('example.com');

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.alpnProtocol).toBe('h2');
    }
  });

  it('returns alpnProtocol "http/1.1" when server negotiates HTTP/1.1', async () => {
    const socket = makeMockSocket({ alpnProtocol: 'http/1.1' });
    connectSpy = jest.spyOn(tls, 'connect').mockReturnValue(socket);

    const result = await checkTls('example.com');

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.alpnProtocol).toBe('http/1.1');
    }
  });

  it('returns alpnProtocol undefined when no ALPN negotiated (false)', async () => {
    const socket = makeMockSocket({ alpnProtocol: false });
    connectSpy = jest.spyOn(tls, 'connect').mockReturnValue(socket);

    const result = await checkTls('example.com');

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.alpnProtocol).toBeUndefined();
    }
  });

  it('includes protocol and cipher in successful result', async () => {
    const socket = makeMockSocket({
      protocol: 'TLSv1.3',
      cipher: { name: 'TLS_AES_256_GCM_SHA384', version: 'TLSv1/SSLv3' },
    });
    connectSpy = jest.spyOn(tls, 'connect').mockReturnValue(socket);

    const result = await checkTls('example.com');

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.protocol).toBe('TLSv1.3');
      expect(result.cipher).toBe('TLS_AES_256_GCM_SHA384');
    }
  });

  it('returns ok: false on socket error', async () => {
    const socket = makeMockSocket({ error: new Error('ECONNREFUSED') });
    connectSpy = jest.spyOn(tls, 'connect').mockReturnValue(socket);

    const result = await checkTls('example.com');

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('ECONNREFUSED');
    }
  });

  it('passes custom port to tls.connect', async () => {
    const socket = makeMockSocket({});
    connectSpy = jest.spyOn(tls, 'connect').mockReturnValue(socket);

    await checkTls('example.com', 8443);

    expect(connectSpy).toHaveBeenCalledWith(
      expect.objectContaining({ host: 'example.com', port: 8443 }),
    );
  });
});
