// GAP-5 Phase 2 — egress destination policy evaluation.

import { describe, it, expect } from 'vitest';
import { evaluateEgress, hostMatches, isPrivateHost, type EgressPolicy } from './index';
import type { ShellDestination } from '../shell';

const dest = (host: string, binary = 'curl'): ShellDestination => ({ host, binary, raw: host });
const policy = (over: Partial<EgressPolicy> = {}): EgressPolicy => ({
  enabled: true,
  mode: 'review',
  allow: [],
  deny: [],
  allowPrivate: true,
  ...over,
});

describe('hostMatches', () => {
  it('exact, wildcard-apex, wildcard-subdomain, and "*"', () => {
    expect(hostMatches('github.com', 'github.com')).toBe(true);
    expect(hostMatches('api.github.com', '*.github.com')).toBe(true);
    expect(hostMatches('github.com', '*.github.com')).toBe(true); // apex via *.
    expect(hostMatches('a.b.github.com', '*.github.com')).toBe(true);
    expect(hostMatches('evil.com', '*.github.com')).toBe(false);
    expect(hostMatches('anything.test', '*')).toBe(true);
  });
});

describe('isPrivateHost', () => {
  it('flags loopback / RFC1918 / .local', () => {
    expect(isPrivateHost('localhost')).toBe(true);
    expect(isPrivateHost('127.0.0.1')).toBe(true);
    expect(isPrivateHost('10.0.0.5')).toBe(true);
    expect(isPrivateHost('192.168.1.10')).toBe(true);
    expect(isPrivateHost('172.16.0.1')).toBe(true);
    expect(isPrivateHost('db.local')).toBe(true);
    expect(isPrivateHost('evil.com')).toBe(false);
    expect(isPrivateHost('172.32.0.1')).toBe(false); // outside RFC1918
  });

  // Measured 2026-09-20: under allowPrivate:true, mode:block, the real shell
  // extractor hands over `[::1]` (brackets kept) and this function said false,
  // so a local IPv6 dev server was BLOCKED. A false positive, not a bypass.
  // The address half now comes from classifySsrf, which already normalizes
  // brackets, zone ids and IPv4-mapped IPv6 for the floor, so every spelling
  // that file knows is one spelling here too.
  it('IPv6 loopback, in every spelling the extractors produce', () => {
    for (const h of ['[::1]', '::1', '::1%lo0', '[::ffff:7f00:1]', '::ffff:127.0.0.1']) {
      expect(isPrivateHost(h), h).toBe(true);
    }
  });

  it('unique-local (fc00::/7) is private, as the RFC1918 analogue', () => {
    // The SSRF floor deliberately does not make fc00::/7 a tier (floor design
    // H9: RFC1918 is out of the floor, so its v6 analogue is too). For
    // allowPrivate the same analogy runs the other way: RFC1918 IS private
    // here, so unique-local is too.
    for (const h of ['[fd00::1]', 'fd12:3456:789a::1', 'fc00::1', '[FD00::1]']) {
      expect(isPrivateHost(h), h).toBe(true);
    }
  });

  it('the unspecified address is "this host" in both families', () => {
    expect(isPrivateHost('0.0.0.0')).toBe(true);
    expect(isPrivateHost('::')).toBe(true);
    expect(isPrivateHost('[::]')).toBe(true);
  });

  it("never claims the floor's tiers: link-local, multicast, metadata", () => {
    // allowPrivate must not be able to reach these. evaluateEgress documents
    // that the floor runs first; this function agrees rather than relying on it.
    for (const h of [
      '[fe80::1]',
      'fe80::1%eth0',
      '[ff02::1]',
      '169.254.169.254',
      '169.254.1.1',
      '224.0.0.1',
      'fd00:ec2::254', // AWS IMDS over IPv6: metadata, even though it sits inside fc00::/7
      'metadata.google.internal',
    ]) {
      expect(isPrivateHost(h), h).toBe(false);
    }
  });

  it('CGNAT stays out: a Tailscale peer is not "private" for allowPrivate (founder call, recorded)', () => {
    expect(isPrivateHost('100.64.0.5')).toBe(false);
  });

  it('the hostname half is untouched', () => {
    for (const h of ['LOCALHOST', 'x.internal', 'a.b.localhost', 'svc.local']) {
      expect(isPrivateHost(h), h).toBe(true);
    }
    for (const h of ['localhost.evil.com', 'internal', 'local']) {
      expect(isPrivateHost(h), h).toBe(false);
    }
  });
});

describe('evaluateEgress + allowPrivate agree across address families', () => {
  it('skips the IPv6 loopback exactly as it skips 127.0.0.1', () => {
    const p = policy({ mode: 'block', allowPrivate: true });
    expect(evaluateEgress([dest('127.0.0.1')], p)).toBeNull();
    expect(evaluateEgress([dest('[::1]')], p)).toBeNull();
    expect(evaluateEgress([dest('[fd00::1]')], p)).toBeNull();
  });

  it('still blocks them when allowPrivate is off', () => {
    const p = policy({ mode: 'block', allowPrivate: false });
    expect(evaluateEgress([dest('127.0.0.1')], p)?.verdict).toBe('block');
    expect(evaluateEgress([dest('[::1]')], p)?.verdict).toBe('block');
  });
});

describe('evaluateEgress', () => {
  it('returns null when disabled (even for unknown hosts)', () => {
    expect(evaluateEgress([dest('evil.com')], policy({ enabled: false }))).toBeNull();
  });

  it('unknown host → review (default mode)', () => {
    const v = evaluateEgress([dest('evil.com')], policy());
    expect(v?.verdict).toBe('review');
    expect(v?.host).toBe('evil.com');
  });

  it('unknown host → block when mode=block', () => {
    expect(evaluateEgress([dest('evil.com')], policy({ mode: 'block' }))?.verdict).toBe('block');
  });

  it('unknown host → null when mode=off (but still enabled for deny)', () => {
    expect(evaluateEgress([dest('evil.com')], policy({ mode: 'off' }))).toBeNull();
  });

  it('default allowlist passes (github, npm, anthropic) → null', () => {
    expect(evaluateEgress([dest('api.github.com')], policy())).toBeNull();
    expect(evaluateEgress([dest('registry.npmjs.org')], policy())).toBeNull();
    expect(evaluateEgress([dest('api.anthropic.com')], policy())).toBeNull();
  });

  it('user allowlist passes', () => {
    expect(
      evaluateEgress([dest('internal.corp.com')], policy({ allow: ['*.corp.com'] }))
    ).toBeNull();
  });

  it('deny list blocks — even when also private / mode off', () => {
    expect(
      evaluateEgress([dest('10.0.0.5')], policy({ deny: ['10.0.0.5'], mode: 'off' }))?.verdict
    ).toBe('block');
  });

  it('private hosts pass by default; blocked if allowPrivate=false', () => {
    expect(evaluateEgress([dest('localhost')], policy())).toBeNull();
    expect(evaluateEgress([dest('localhost')], policy({ allowPrivate: false }))?.verdict).toBe(
      'review'
    );
  });

  it('mixed destinations: a deny anywhere wins over an allowed one', () => {
    const v = evaluateEgress(
      [dest('api.github.com'), dest('evil.com')],
      policy({ deny: ['evil.com'] })
    );
    expect(v?.verdict).toBe('block');
    expect(v?.host).toBe('evil.com');
  });

  it('mixed: block-mode unknown wins over a later review-only path', () => {
    const v = evaluateEgress(
      [dest('a.unknown.test'), dest('b.unknown.test')],
      policy({ mode: 'block' })
    );
    expect(v?.verdict).toBe('block');
  });
});

describe("node9's own hosts", () => {
  // Turning egress on used to ask the user to approve node9's own API. The
  // control plane is on the curated default list now, and a user deny entry
  // still beats it, so the default is not a back door nobody can close.
  it('is allowed by default with an empty user allowlist', () => {
    for (const host of ['api.node9.ai', 'app.node9.ai', 'dev-api.node9.ai', 'node9.ai']) {
      expect(evaluateEgress([dest(host)], policy({ mode: 'block' }))).toBeNull();
    }
  });

  it('is still blocked when the user denies it explicitly', () => {
    const v = evaluateEgress([dest('api.node9.ai')], policy({ deny: ['*.node9.ai'] }));
    expect(v?.verdict).toBe('block');
    expect(v?.reason).toContain('deny list');
  });

  it('does not widen to look-alike domains', () => {
    // A suffix match would let evil-node9.ai or node9.ai.evil.com through.
    for (const host of ['evil-node9.ai', 'node9.ai.evil.com', 'notnode9.ai']) {
      expect(evaluateEgress([dest(host)], policy({ mode: 'block' }))?.verdict).toBe('block');
    }
  });
});

describe('isPrivateHost: a hostname that merely STARTS with a private prefix', () => {
  // The old body tested /^127\./, /^10\./, /^192\.168\./ against the raw
  // string, so `10.evil.com` was "private" and allowPrivate skipped the
  // allowlist for it. Found in self-review of the IPv6 rewrite, 2026-09-20.
  // classifySsrf only answers for an IP literal, so a hostname falls through
  // to the suffix list, where these do not match.
  it('is not private', () => {
    for (const h of ['10.evil.com', '127.attacker.net', '192.168.evil.com', '172.16.evil.com']) {
      expect(isPrivateHost(h), h).toBe(false);
    }
  });

  it('and is therefore an unknown host under block + allowPrivate', () => {
    const p = policy({ mode: 'block', allowPrivate: true });
    expect(evaluateEgress([dest('10.evil.com')], p)?.verdict).toBe('block');
  });
});
