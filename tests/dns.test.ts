import { jest } from '@jest/globals';
import dns from 'node:dns/promises';
import { isPrivateIp } from '../src/checks/dns.js';

describe('isPrivateIp', () => {
  it('returns true for 10.x.x.x', () => {
    expect(isPrivateIp('10.0.0.1')).toBe(true);
    expect(isPrivateIp('10.255.255.255')).toBe(true);
  });

  it('returns true for 192.168.x.x', () => {
    expect(isPrivateIp('192.168.1.1')).toBe(true);
    expect(isPrivateIp('192.168.0.100')).toBe(true);
  });

  it('returns true for 172.16-31.x.x', () => {
    expect(isPrivateIp('172.16.0.1')).toBe(true);
    expect(isPrivateIp('172.31.255.255')).toBe(true);
    expect(isPrivateIp('172.20.10.1')).toBe(true);
  });

  it('returns false for 172.15.x.x and 172.32.x.x (outside range)', () => {
    expect(isPrivateIp('172.15.0.1')).toBe(false);
    expect(isPrivateIp('172.32.0.1')).toBe(false);
  });

  it('returns true for loopback 127.x.x.x', () => {
    expect(isPrivateIp('127.0.0.1')).toBe(true);
  });

  it('returns false for public IPs', () => {
    expect(isPrivateIp('8.8.8.8')).toBe(false);
    expect(isPrivateIp('104.21.5.10')).toBe(false);
    expect(isPrivateIp('1.1.1.1')).toBe(false);
  });
});

describe('checkDns resolverComparison', () => {
  let resolve4Spy: ReturnType<typeof jest.spyOn>;
  let resolve6Spy: ReturnType<typeof jest.spyOn>;
  let resolveCnameSpy: ReturnType<typeof jest.spyOn>;
  let ResolverSpy: ReturnType<typeof jest.spyOn>;

  afterEach(() => {
    resolve4Spy?.mockRestore();
    resolve6Spy?.mockRestore();
    resolveCnameSpy?.mockRestore();
    ResolverSpy?.mockRestore();
  });

  function mockResolverClass(publicIps: string[]): void {
    const fakeResolverInstance = {
      setServers: jest.fn(),
      resolve4: jest.fn<() => Promise<string[]>>().mockResolvedValue(publicIps),
    };
    ResolverSpy = jest
      .spyOn(dns, 'Resolver')
      .mockImplementation(() => fakeResolverInstance as unknown as dns.Resolver);
  }

  it('sets splitHorizon true when system returns private IP and 1.1.1.1 returns public', async () => {
    resolve4Spy = jest
      .spyOn(dns, 'resolve4')
      .mockResolvedValue([{ address: '10.0.0.5', ttl: 300 }] as never);
    resolve6Spy = jest.spyOn(dns, 'resolve6').mockResolvedValue([] as never);
    resolveCnameSpy = jest.spyOn(dns, 'resolveCname').mockRejectedValue(new Error('ENODATA'));
    mockResolverClass(['104.21.5.10']);

    const { checkDns } = await import('../src/checks/dns.js');
    const result = await checkDns('example.internal');

    expect(result.ok).toBe(true);
    expect(result.resolverComparison?.splitHorizon).toBe(true);
    expect(result.resolverComparison?.publicIps).toEqual(['104.21.5.10']);
  });

  it('sets splitHorizon false when both system and 1.1.1.1 return public IPs', async () => {
    resolve4Spy = jest
      .spyOn(dns, 'resolve4')
      .mockResolvedValue([{ address: '104.21.5.10', ttl: 300 }] as never);
    resolve6Spy = jest.spyOn(dns, 'resolve6').mockResolvedValue([] as never);
    resolveCnameSpy = jest.spyOn(dns, 'resolveCname').mockRejectedValue(new Error('ENODATA'));
    mockResolverClass(['104.21.5.10']);

    const { checkDns } = await import('../src/checks/dns.js');
    const result = await checkDns('example.com');

    expect(result.ok).toBe(true);
    expect(result.resolverComparison?.splitHorizon).toBe(false);
  });

  it('sets resolverComparison undefined when public resolver fails', async () => {
    resolve4Spy = jest
      .spyOn(dns, 'resolve4')
      .mockResolvedValue([{ address: '104.21.5.10', ttl: 300 }] as never);
    resolve6Spy = jest.spyOn(dns, 'resolve6').mockResolvedValue([] as never);
    resolveCnameSpy = jest.spyOn(dns, 'resolveCname').mockRejectedValue(new Error('ENODATA'));

    const fakeResolverInstance = {
      setServers: jest.fn(),
      resolve4: jest.fn<() => Promise<string[]>>().mockRejectedValue(new Error('network error')),
    };
    ResolverSpy = jest
      .spyOn(dns, 'Resolver')
      .mockImplementation(() => fakeResolverInstance as unknown as dns.Resolver);

    const { checkDns } = await import('../src/checks/dns.js');
    const result = await checkDns('example.com');

    expect(result.ok).toBe(true);
    expect(result.resolverComparison).toBeUndefined();
  });
});
