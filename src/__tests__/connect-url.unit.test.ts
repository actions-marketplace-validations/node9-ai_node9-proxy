import { describe, it, expect, afterEach } from 'vitest';
import { resolveConnectUrl } from '../cli/commands/connect';

describe('resolveConnectUrl', () => {
  const prev = process.env.NODE9_API_URL;
  afterEach(() => {
    if (prev === undefined) delete process.env.NODE9_API_URL;
    else process.env.NODE9_API_URL = prev;
  });

  it('uses --api-url when given (wins over env + default)', () => {
    process.env.NODE9_API_URL = 'https://x/api/v1/intercept';
    expect(resolveConnectUrl('http://localhost:9/cli/connect')).toBe(
      'http://localhost:9/cli/connect'
    );
  });

  it('derives from NODE9_API_URL by swapping /intercept → /cli/connect', () => {
    process.env.NODE9_API_URL = 'https://dev-api.node9.ai/api/v1/intercept';
    expect(resolveConnectUrl()).toBe('https://dev-api.node9.ai/api/v1/cli/connect');
  });

  it('tolerates a trailing slash on NODE9_API_URL', () => {
    process.env.NODE9_API_URL = 'https://dev-api.node9.ai/api/v1/intercept/';
    expect(resolveConnectUrl()).toBe('https://dev-api.node9.ai/api/v1/cli/connect');
  });

  it('falls back to the prod default when nothing is set', () => {
    delete process.env.NODE9_API_URL;
    expect(resolveConnectUrl()).toBe('https://api.node9.ai/api/v1/cli/connect');
  });

  // The endpoints resolved here are where the device key is MINTED. An
  // attacker-controlled NODE9_API_URL (a hook inherits the agent's env) would
  // have the attacker's host issue the key, stored against the real default
  // host: the machine joins the attacker's workspace through node9's own API.
  // Review finding 2026-09-20; the pin is the same one every other seam uses.
  it('refuses a NODE9_API_URL that is not an allowed host, and names the fix', () => {
    process.env.NODE9_API_URL = 'https://evil.example.com/api/v1/intercept';
    expect(() => resolveConnectUrl()).toThrow(/NODE9_API_URL .*evil\.example\.com/);
    expect(() => resolveConnectUrl()).toThrow(/NODE9_API_HOST_ALLOW/);
  });

  it('refuses a hostile --api-url too, rather than silently logging in to prod', () => {
    delete process.env.NODE9_API_URL;
    expect(() => resolveConnectUrl('https://evil.example.com/cli/connect')).toThrow(/--api-url/);
  });

  it('accepts a self-hosted host once NODE9_API_HOST_ALLOW names it', () => {
    const prevAllow = process.env.NODE9_API_HOST_ALLOW;
    process.env.NODE9_API_HOST_ALLOW = 'corp.example';
    process.env.NODE9_API_URL = 'https://node9.corp.example/api/v1/intercept';
    try {
      expect(resolveConnectUrl()).toBe('https://node9.corp.example/api/v1/cli/connect');
    } finally {
      if (prevAllow === undefined) delete process.env.NODE9_API_HOST_ALLOW;
      else process.env.NODE9_API_HOST_ALLOW = prevAllow;
    }
  });
});
