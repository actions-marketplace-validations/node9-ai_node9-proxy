// G10 at the engine level: the second extractor reads the same closed table
// the floor reads, and evaluateEgress compares one spelling of an address no
// matter which extractor produced it. The integration file proves the gate;
// this one pins the pieces so a failure there points at a piece.
import { describe, it, expect } from 'vitest';
import {
  evaluateEgress,
  extractToolDestinations,
  extractShellDestinations,
  isPrivateHost,
  type EgressPolicy,
} from '@node9/policy-engine';
import { CARRIERS, NO_VERDICT_ROWS, NORMALIZATION_ROWS } from './fixtures/egress-carriers-corpus';

const policy = (over: Partial<EgressPolicy> = {}): EgressPolicy => ({
  enabled: true,
  mode: 'block',
  allow: [],
  deny: [],
  allowPrivate: false,
  ...over,
});

describe('extractToolDestinations', () => {
  it('yields one host per declared URL for every non-shell carrier in the corpus', () => {
    for (const c of CARRIERS.filter((c) => c.tool !== 'Bash')) {
      const dests = extractToolDestinations(c.tool, c.build('https://evil.example.com/x'));
      expect(
        dests.map((d) => d.host),
        c.id
      ).toEqual(['evil.example.com']);
      expect(dests[0].binary, c.id).toBe(c.tool);
    }
  });

  it('yields nothing for every no-verdict row (closed list, or not a destination)', () => {
    for (const row of NO_VERDICT_ROWS.filter((r) => r.tool !== 'Bash')) {
      expect(extractToolDestinations(row.tool, row.args), `${row.id}: ${row.carrierNote}`).toEqual(
        []
      );
    }
  });

  it("a Bash row is the shell extractor's business, unchanged", () => {
    const echo = NO_VERDICT_ROWS.find((r) => r.id === 'bash-echo-url')!;
    expect(extractToolDestinations('Bash', echo.args)).toEqual([]);
    expect(extractShellDestinations(String(echo.args.command))).toEqual([]);
  });
});

describe('the two extractors feed one evaluator and get one answer', () => {
  const url = 'https://evil.example.com/x';
  const shell = extractShellDestinations(`curl ${url}`);
  it('unknown host: block for both', () => {
    const p = policy();
    expect(evaluateEgress(shell, p)?.verdict).toBe('block');
    for (const c of CARRIERS.filter((c) => c.tool !== 'Bash')) {
      expect(evaluateEgress(extractToolDestinations(c.tool, c.build(url)), p)?.verdict, c.id).toBe(
        'block'
      );
    }
  });
  it('user-allowlisted host: null for both', () => {
    const p = policy({ allow: ['evil.example.com'] });
    expect(evaluateEgress(shell, p)).toBeNull();
    for (const c of CARRIERS.filter((c) => c.tool !== 'Bash')) {
      expect(evaluateEgress(extractToolDestinations(c.tool, c.build(url)), p), c.id).toBeNull();
    }
  });
});

// ── 3.4 / 4.5 normalization inside evaluateEgress ───────────────────────────
describe('one spelling per address before any list is consulted', () => {
  it.each(NORMALIZATION_ROWS.map((r) => [r.id, r] as const))('%s', (_id, row) => {
    for (const spelling of row.spellings) {
      const dest = [{ host: spelling, binary: 'x', raw: spelling }];
      expect(
        evaluateEgress(dest, policy({ deny: [row.listEntry] }))?.verdict,
        `deny [${row.listEntry}] must catch "${spelling}"\n${row.note}`
      ).toBe('block');
      expect(
        evaluateEgress(dest, policy({ allow: [row.listEntry], allowPrivate: false })),
        `allow [${row.listEntry}] must pass "${spelling}"\n${row.note}`
      ).toBeNull();
    }
  });

  it('the verdict still reports the host as written, so the reason matches what the user typed', () => {
    const v = evaluateEgress(
      [{ host: '[::1]', binary: 'curl', raw: '[::1]' }],
      policy({ deny: ['::1'] })
    );
    expect(v?.host).toBe('[::1]');
  });
});

// ── Regression rows for the /code-review findings on this change ───────────
describe('review findings: the shapes the first cut of this change got wrong', () => {
  const dest = (host: string) => [{ host, binary: 'curl', raw: host }];

  it('F2: a list entry is folded too, not just the host', () => {
    // Canonicalizing only the host silently killed every entry stored in a
    // non-canonical spelling: deny failed OPEN, allow failed CLOSED. Entries
    // arrive unnormalized from `node9 egress deny`, a config edit, and the
    // managed list.
    for (const [host, entry] of [
      ['[::1]', '[::1]'],
      ['[::1]', '::1'],
      ['::1', '[::1]'],
      ['evil.example.com', 'evil.example.com.'],
      ['EVIL.example.com.', 'evil.example.com'],
      ['[fd00::1]', 'fd00::1'],
      ['::ffff:7f00:1', '127.0.0.1'],
    ] as const) {
      expect(
        evaluateEgress(dest(host), policy({ mode: 'off', deny: [entry] }))?.verdict,
        `deny ["${entry}"] must catch host "${host}"`
      ).toBe('block');
    }
  });

  it('F2: globs still match what they matched, and nothing more', () => {
    expect(evaluateEgress(dest('a.example.com'), policy({ allow: ['*.example.com'] }))).toBeNull();
    expect(evaluateEgress(dest('example.com'), policy({ allow: ['*.example.com'] }))).toBeNull();
    expect(evaluateEgress(dest('evil.com'), policy({ allow: ['*.example.com'] }))?.verdict).toBe(
      'block'
    );
    expect(evaluateEgress(dest('anything.test'), policy({ allow: ['*'] }))).toBeNull();
  });

  it('F5: a partial egress object does not throw', () => {
    // EgressPolicy.allow/deny are typed required, but PolicyConfig.egress is
    // optional for engine consumers that build a config by hand, and the tool
    // branch now reaches evaluateEgress before the ignored fast path.
    const partial = { enabled: true, mode: 'block' } as unknown as EgressPolicy;
    expect(() => evaluateEgress(dest('evil.example.com'), partial)).not.toThrow();
    expect(evaluateEgress(dest('evil.example.com'), partial)?.verdict).toBe('block');
  });

  it('F6: isPrivateHost folds its own trailing dot, so callers cannot disagree', () => {
    expect(isPrivateHost('localhost.')).toBe(true);
    expect(isPrivateHost('foo.local.')).toBe(true);
    expect(evaluateEgress(dest('localhost.'), policy({ allowPrivate: true }))).toBeNull();
    // Still not private: the floor's tiers and a public host.
    expect(isPrivateHost('metadata.google.internal')).toBe(false);
    expect(isPrivateHost('evil.com.')).toBe(false);
  });

  it('the verdict reports the host AS WRITTEN, so the reason matches what was typed', () => {
    const v = evaluateEgress(dest('[::1]'), policy({ mode: 'off', deny: ['::1'] }));
    expect(v?.host).toBe('[::1]');
  });
});
