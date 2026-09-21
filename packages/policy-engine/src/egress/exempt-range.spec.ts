// B2: an SSRF floor exemption may name a RANGE, not only one address.
//
// Measured on the shipped build, floor isolated (ssrfStrict on, so only the
// floor can answer):
//   ssrfAllow []                -> curl http://10.0.0.5/  deny
//   ssrfAllow ['10.0.0.5']      -> allow
//   ssrfAllow ['10.0.0.0/8']    -> deny      <- the gap
// The CLI's own help says it: "exact address, not a range". That is what
// stops the panel's x from working on an internal range: x on 100.64.0.0/10
// means "stop treating CGNAT as internal", and no field can hold that.
//
// The safety property this file exists to pin is E2. An exemption is consulted
// ONLY after classifySsrf has answered `overridable` for that exact address,
// so a range can never release a protected address inside it. The case is
// real, not hypothetical: Alibaba's metadata endpoint 100.100.100.200 sits
// inside 100.64.0.0/10 and is in METADATA_ADDRESSES, checked above the range
// test. Measured: tier=metadata, overridable=false.
import { describe, it, expect } from 'vitest';
import { ssrfFloor, classifySsrf } from './ssrf';
import { ssrfDestinationFloor } from './destinations';

const tok = (token: string) => [{ token, binary: 'curl' }];
/** Floor isolated: the strict tier on, so tier-3 addresses reach the floor. */
const strict = { ssrfStrict: true };

describe('E0 known-true: the instrument sees the floor at all', () => {
  it('blocks a private address under the strict tier, and allows it exempted by name', () => {
    expect(ssrfFloor(tok('10.0.0.5'), strict)?.tier).toBe('private');
    expect(ssrfFloor(tok('10.0.0.5'), { ...strict, ssrfAllow: ['10.0.0.5'] })).toBeNull();
  });
});

describe('E1 a range releases the addresses inside it', () => {
  it('CGNAT: one entry covers the peers', () => {
    // The row the panel needs: an operator exempts the mesh-VPN range they
    // use instead of listing peers one at a time.
    const opts = { ...strict, ssrfAllow: ['100.64.0.0/10'] };
    for (const a of ['100.64.0.5', '100.64.0.1', '100.127.255.254', '100.80.3.9']) {
      expect(ssrfFloor(tok(a), opts), a).toBeNull();
    }
  });

  it('RFC1918: /8, /12 and /16 each cover their own range and nothing else', () => {
    expect(ssrfFloor(tok('10.9.9.9'), { ...strict, ssrfAllow: ['10.0.0.0/8'] })).toBeNull();
    expect(ssrfFloor(tok('172.16.5.5'), { ...strict, ssrfAllow: ['172.16.0.0/12'] })).toBeNull();
    expect(ssrfFloor(tok('192.168.1.10'), { ...strict, ssrfAllow: ['192.168.0.0/16'] })).toBeNull();
    // Outside the prefix: still blocked. The address has to be IN a tier for
    // this to mean anything — a public address is never blocked by the floor,
    // exempted or not, so 11.0.0.1 would prove nothing here.
    expect(ssrfFloor(tok('172.16.5.5'), { ...strict, ssrfAllow: ['10.0.0.0/8'] })?.tier).toBe(
      'private'
    );
    expect(ssrfFloor(tok('10.0.0.5'), { ...strict, ssrfAllow: ['192.168.0.0/16'] })?.tier).toBe(
      'private'
    );
  });

  it('a /32 behaves exactly like the bare address', () => {
    expect(ssrfFloor(tok('10.0.0.5'), { ...strict, ssrfAllow: ['10.0.0.5/32'] })).toBeNull();
    expect(ssrfFloor(tok('10.0.0.6'), { ...strict, ssrfAllow: ['10.0.0.5/32'] })?.tier).toBe(
      'private'
    );
  });
});

describe('E2 THE SAFETY PROPERTY: a range cannot release a protected address inside it', () => {
  it("Alibaba's metadata endpoint stays blocked when the whole CGNAT range is exempted", () => {
    // 100.100.100.200 is inside 100.64.0.0/10 and is named in
    // METADATA_ADDRESSES above the range check, so it classifies as metadata.
    expect(classifySsrf('100.100.100.200')?.tier).toBe('metadata');
    expect(classifySsrf('100.100.100.200')?.overridable).toBe(false);

    const opts = { ...strict, ssrfAllow: ['100.64.0.0/10'] };
    expect(ssrfFloor(tok('100.100.100.200'), opts)?.tier).toBe('metadata');
    // ... while its neighbour in the same range IS released.
    expect(ssrfFloor(tok('100.100.100.201'), opts)).toBeNull();
  });

  it('a range that covers link-local or multicast releases neither', () => {
    for (const [range, addr] of [
      ['169.254.0.0/16', '169.254.169.254'],
      ['169.254.0.0/16', '169.254.1.1'],
      ['224.0.0.0/4', '224.0.0.1'],
      ['0.0.0.0/0', '169.254.169.254'],
    ] as const) {
      expect(
        ssrfFloor(tok(addr), { ...strict, ssrfAllow: [range] }),
        `${range} must not release ${addr}`
      ).not.toBeNull();
    }
  });
});

describe('E3 an exact address entry keeps working, and stays exact', () => {
  it('releases that address and not its neighbour', () => {
    const opts = { ...strict, ssrfAllow: ['10.0.0.5'] };
    expect(ssrfFloor(tok('10.0.0.5'), opts)).toBeNull();
    expect(ssrfFloor(tok('10.0.0.6'), opts)?.tier).toBe('private');
  });

  it('still matches any spelling of the same address', () => {
    // Pre-existing behaviour: matching is on the normalized literal.
    const opts = { ...strict, ssrfAllow: ['127.0.0.1'] };
    expect(ssrfFloor(tok('127.1'), opts)).toBeNull();
    expect(ssrfFloor(tok('2130706433'), opts)).toBeNull();
  });
});

describe('E4 both carriers answer identically for every entry form', () => {
  // This is the row that would have caught the drift the change removes: the
  // shell floor and the declared-URL floor each had their OWN spelling of the
  // exemption lookup (normalizeIpLiteral vs classifySsrf().normalized).
  const webFetch = (url: string, opts: Parameters<typeof ssrfDestinationFloor>[2]) =>
    ssrfDestinationFloor('WebFetch', { url, prompt: 'x' }, opts);

  it.each([
    ['exact address', ['10.0.0.5'], '10.0.0.5', true],
    ['range', ['10.0.0.0/8'], '10.0.0.9', true],
    // In a tier, but outside the exempted prefix. A public address would
    // prove nothing: the floor never blocks one, with or without an entry.
    ['range, outside it', ['10.0.0.0/8'], '172.16.0.9', false],
    ['CGNAT range', ['100.64.0.0/10'], '100.64.0.5', true],
    ['CGNAT range vs Alibaba', ['100.64.0.0/10'], '100.100.100.200', false],
    ['no entries', [], '10.0.0.5', false],
  ])('%s: shell and WebFetch agree', (_label, ssrfAllow, addr, expectReleased) => {
    const opts = { ...strict, ssrfAllow };
    const shell = ssrfFloor(tok(addr), opts) === null;
    const tool = webFetch(`http://${addr}/x`, opts) === null;
    expect(shell, `shell released ${addr}?`).toBe(expectReleased);
    expect(tool, `WebFetch released ${addr}?`).toBe(expectReleased);
    expect(tool, 'the two carriers must agree').toBe(shell);
  });
});

describe('E5 a v4 range never matches a v6 address, and the reverse', () => {
  it('families do not cross', () => {
    expect(ssrfFloor(tok('::1'), { ...strict, ssrfAllow: ['0.0.0.0/0'] })?.tier).toBe('private');
    expect(ssrfFloor(tok('10.0.0.5'), { ...strict, ssrfAllow: ['::/0'] })?.tier).toBe('private');
  });

  it('a v6 range releases a v6 address', () => {
    expect(ssrfFloor(tok('::1'), { ...strict, ssrfAllow: ['::1/128'] })).toBeNull();
    expect(ssrfFloor(tok('[::1]'), { ...strict, ssrfAllow: ['::/0'] })).toBeNull();
  });
});

describe('E8 a malformed entry is ignored, never thrown', () => {
  it('never throws, and never releases', () => {
    // This runs on the hook path for every tool call; an exception here would
    // break every command on the machine.
    for (const bad of ['10.0.0.0/33', '10.0.0.0/', '/8', '10.0.0.0/-1', 'not-an-address/8', '/']) {
      expect(() => ssrfFloor(tok('10.0.0.5'), { ...strict, ssrfAllow: [bad] }), bad).not.toThrow();
      expect(ssrfFloor(tok('10.0.0.5'), { ...strict, ssrfAllow: [bad] })?.tier, bad).toBe(
        'private'
      );
    }
  });

  it('a good entry beside a malformed one still works', () => {
    expect(
      ssrfFloor(tok('10.0.0.5'), { ...strict, ssrfAllow: ['10.0.0.0/33', '10.0.0.0/8'] })
    ).toBeNull();
  });
});
