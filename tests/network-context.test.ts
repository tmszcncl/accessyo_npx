import { jest } from '@jest/globals';
import {
  getIpApiNetworkInfo,
  IPAPI_CACHE_TTL_MS,
  IPAPI_STALE_IF_ERROR_MS,
  maskPublicIp,
  type IpApiNetworkInfo,
} from '../src/checks/network-context.js';

describe('getIpApiNetworkInfo cache policy', () => {
  const sample: IpApiNetworkInfo = {
    ip: '176.104.177.170',
    countryCode: 'PL',
    countryName: 'Poland',
    isp: 'FIBERLINK Sp. z o.o.',
    asn: 'AS50767',
  };

  it('returns fresh cache and skips remote fetch', async () => {
    const readCache = jest
      .fn<(maxAgeMs: number) => Promise<IpApiNetworkInfo | undefined>>()
      .mockResolvedValueOnce(sample);
    const fetchRemote = jest.fn<() => Promise<IpApiNetworkInfo | undefined>>();
    const writeCache = jest.fn<(data: IpApiNetworkInfo) => Promise<void>>();
    const hasRecentFailure = jest.fn<() => Promise<boolean>>();
    const markFailure = jest.fn<() => Promise<void>>();
    const clearFailure = jest.fn<() => Promise<void>>();

    const result = await getIpApiNetworkInfo(
      readCache,
      fetchRemote,
      writeCache,
      hasRecentFailure,
      markFailure,
      clearFailure,
    );

    expect(result).toEqual(sample);
    expect(readCache).toHaveBeenCalledTimes(1);
    expect(readCache).toHaveBeenNthCalledWith(1, IPAPI_CACHE_TTL_MS);
    expect(fetchRemote).not.toHaveBeenCalled();
    expect(hasRecentFailure).not.toHaveBeenCalled();
    expect(markFailure).not.toHaveBeenCalled();
    expect(clearFailure).not.toHaveBeenCalled();
    expect(writeCache).not.toHaveBeenCalled();
  });

  it('fetches remote and writes cache when fresh cache is missing', async () => {
    const readCache = jest
      .fn<(maxAgeMs: number) => Promise<IpApiNetworkInfo | undefined>>()
      .mockResolvedValueOnce(undefined);
    const fetchRemote = jest
      .fn<() => Promise<IpApiNetworkInfo | undefined>>()
      .mockResolvedValueOnce(sample);
    const writeCache = jest
      .fn<(data: IpApiNetworkInfo) => Promise<void>>()
      .mockResolvedValue(undefined);
    const hasRecentFailure = jest.fn<() => Promise<boolean>>().mockResolvedValue(false);
    const markFailure = jest.fn<() => Promise<void>>();
    const clearFailure = jest.fn<() => Promise<void>>();

    const result = await getIpApiNetworkInfo(
      readCache,
      fetchRemote,
      writeCache,
      hasRecentFailure,
      markFailure,
      clearFailure,
    );

    expect(result).toEqual(sample);
    expect(readCache).toHaveBeenCalledTimes(1);
    expect(hasRecentFailure).toHaveBeenCalledTimes(1);
    expect(fetchRemote).toHaveBeenCalledTimes(1);
    expect(writeCache).toHaveBeenCalledTimes(1);
    expect(writeCache).toHaveBeenCalledWith(sample);
    expect(markFailure).not.toHaveBeenCalled();
    expect(clearFailure).toHaveBeenCalledTimes(1);
  });

  it('falls back to stale cache when remote fetch fails', async () => {
    const readCache = jest
      .fn<(maxAgeMs: number) => Promise<IpApiNetworkInfo | undefined>>()
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce(sample);
    const fetchRemote = jest
      .fn<() => Promise<IpApiNetworkInfo | undefined>>()
      .mockResolvedValueOnce(undefined);
    const writeCache = jest.fn<(data: IpApiNetworkInfo) => Promise<void>>();
    const hasRecentFailure = jest.fn<() => Promise<boolean>>().mockResolvedValue(false);
    const markFailure = jest.fn<() => Promise<void>>();
    const clearFailure = jest.fn<() => Promise<void>>();

    const result = await getIpApiNetworkInfo(
      readCache,
      fetchRemote,
      writeCache,
      hasRecentFailure,
      markFailure,
      clearFailure,
    );

    expect(result).toEqual(sample);
    expect(readCache).toHaveBeenCalledTimes(2);
    expect(readCache).toHaveBeenNthCalledWith(1, IPAPI_CACHE_TTL_MS);
    expect(readCache).toHaveBeenNthCalledWith(2, IPAPI_STALE_IF_ERROR_MS);
    expect(hasRecentFailure).toHaveBeenCalledTimes(1);
    expect(fetchRemote).toHaveBeenCalledTimes(1);
    expect(markFailure).toHaveBeenCalledTimes(1);
    expect(clearFailure).not.toHaveBeenCalled();
    expect(writeCache).not.toHaveBeenCalled();
  });

  it('uses stale cache and skips remote fetch when recent failure is cached', async () => {
    const readCache = jest
      .fn<(maxAgeMs: number) => Promise<IpApiNetworkInfo | undefined>>()
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce(sample);
    const fetchRemote = jest.fn<() => Promise<IpApiNetworkInfo | undefined>>();
    const writeCache = jest.fn<(data: IpApiNetworkInfo) => Promise<void>>();
    const hasRecentFailure = jest.fn<() => Promise<boolean>>().mockResolvedValue(true);
    const markFailure = jest.fn<() => Promise<void>>();
    const clearFailure = jest.fn<() => Promise<void>>();

    const result = await getIpApiNetworkInfo(
      readCache,
      fetchRemote,
      writeCache,
      hasRecentFailure,
      markFailure,
      clearFailure,
    );

    expect(result).toEqual(sample);
    expect(readCache).toHaveBeenCalledTimes(2);
    expect(readCache).toHaveBeenNthCalledWith(1, IPAPI_CACHE_TTL_MS);
    expect(readCache).toHaveBeenNthCalledWith(2, IPAPI_STALE_IF_ERROR_MS);
    expect(hasRecentFailure).toHaveBeenCalledTimes(1);
    expect(fetchRemote).not.toHaveBeenCalled();
    expect(markFailure).not.toHaveBeenCalled();
    expect(clearFailure).not.toHaveBeenCalled();
    expect(writeCache).not.toHaveBeenCalled();
  });
});

describe('maskPublicIp', () => {
  it('returns full IPv4 value', () => {
    expect(maskPublicIp('176.104.177.170')).toBe('176.104.177.170');
  });

  it('returns full IPv6 value', () => {
    expect(maskPublicIp('2a00:1450:4025:804::65')).toBe('2a00:1450:4025:804::65');
  });
});
