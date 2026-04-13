import { getClientVarianceInfo } from '../src/commands/diagnose.js';
import type { HttpResult } from '../src/types.js';

function makeHttp(overrides: Partial<HttpResult> = {}): HttpResult {
  return {
    ok: true,
    durationMs: 120,
    statusCode: 200,
    redirects: [],
    headers: {},
    ...overrides,
  };
}

describe('getClientVarianceInfo', () => {
  it('returns neutral info when browser response differs', () => {
    const info = getClientVarianceInfo(
      makeHttp({
        browserDiffers: true,
        browserStatusCode: 403,
      }),
    );
    expect(info).toEqual({
      title: 'response varies by client',
      details: ['server may treat CLI and browsers differently'],
    });
  });

  it('returns null when browser response does not differ', () => {
    expect(getClientVarianceInfo(makeHttp({ browserDiffers: false }))).toBeNull();
    expect(getClientVarianceInfo(makeHttp())).toBeNull();
  });
});
