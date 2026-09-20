// G10: one egress policy, every carrier. Through the REAL gate.
//
// Measured on dev e748b4a before this change, egress { enabled, mode: 'block',
// allow: [], allowPrivate: false }:
//   Bash curl https://evil.example.com/x        deny
//   WebFetch  https://evil.example.com/x        allow
//   mcp__fetch__fetch  (same url)               allow
//   mcp__Claude_Browser__navigate (same url)    allow
// The allowlist was shell-only. An agent that wants to exfiltrate does not
// need curl. Engine-level tests would not have caught this: evaluateEgress was
// never wrong, nothing handed it the tool carriers.
//
// The property under test is AGREEMENT: one destination, every carrier, the
// same verdict from the same policy. The assertion is that the set of verdicts
// has one member, not a hardcoded verdict per row, so the policy's own
// semantics can change without rewriting this file. On the parent the shell
// rows say deny and the tool rows say allow under block, so the set has two
// members and the failure message prints the gap.
//
// Every row comes from fixtures/egress-carriers-corpus.ts, written before
// this test and before the code, from real caller shapes.
//
// The seven carriers of a row are spawned CONCURRENTLY. Sequentially this file
// was ~267 spawns x 0.3 s = the longest in the suite, and the 4.3 floor row
// timed out at 37 s against testTimeout 30000 under a loaded 4-worker run
// while passing in 6 s alone. The rows share one read-only HOME; the only
// writer, loop-state.json, uses a pid-suffixed tmp file plus rename.
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { execFile } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { DEFAULT_EGRESS_ALLOWLIST, hostMatches } from '@node9/policy-engine';
import { keySafeEnv } from './helpers/env';
import {
  CARRIERS,
  DESTINATIONS,
  NO_VERDICT_ROWS,
  USER_ALLOW_ENTRY,
  USER_DENY_ENTRY,
} from './fixtures/egress-carriers-corpus';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');
const run = promisify(execFile);

type Egress = {
  enabled: boolean;
  mode?: string;
  allow?: string[];
  deny?: string[];
  allowPrivate?: boolean;
};
let home = '';

function makeHome(egress?: Egress): string {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-egress-carriers-'));
  fs.mkdirSync(path.join(h, '.node9'), { recursive: true });
  fs.writeFileSync(
    path.join(h, '.node9', 'config.json'),
    JSON.stringify({
      settings: { mode: 'standard', autoStartDaemon: false },
      policy: egress ? { egress } : {},
    })
  );
  return h;
}

const envFor = (h: string) =>
  keySafeEnv({
    HOME: h,
    USERPROFILE: h,
    NODE9_TESTING: '1',
    NODE9_NO_AUTO_DAEMON: '1',
    NO_COLOR: '1',
  }) as NodeJS.ProcessEnv;

/** execFile rejects on a non-zero exit; `check` exits 2 on deny, so both the
 *  resolve and the reject path carry a real result and must be read. */
async function runCli(h: string, argv: string[]) {
  try {
    const { stdout, stderr } = await run(process.execPath, [CLI, ...argv], {
      encoding: 'utf-8',
      timeout: 60000,
      cwd: os.tmpdir(),
      env: envFor(h),
    });
    return { status: 0, stdout, stderr, error: undefined as Error | undefined };
  } catch (e) {
    const err = e as NodeJS.ErrnoException & { code?: number; stdout?: string; stderr?: string };
    // A numeric `code` is the child's exit status; anything else (ENOENT,
    // ETIMEDOUT) is a spawn failure and must never read as a verdict.
    const status = typeof err.code === 'number' ? err.code : null;
    return {
      status,
      stdout: err.stdout ?? '',
      stderr: err.stderr ?? '',
      error: status === null ? (e as Error) : undefined,
    };
  }
}

/** The gate. The spawn-failure guard lives here once: a silent ENOENT or a
 *  timeout must never read as a passing row, and neither must a crash that
 *  prints nothing (empty stdout would otherwise parse as a silent allow). */
async function check(h: string, tool: string, args: Record<string, unknown>) {
  const payload = JSON.stringify({
    hook_event_name: 'PreToolUse',
    tool_name: tool,
    tool_input: args,
    session_id: 'g10',
    cwd: h,
  });
  const r = await runCli(h, ['check', payload]);
  expect(r.error, `spawn failed for ${tool}`).toBeUndefined();
  let decision = 'allow';
  if (r.stdout.trim()) {
    try {
      decision =
        (JSON.parse(r.stdout) as { hookSpecificOutput?: { permissionDecision?: string } })
          .hookSpecificOutput?.permissionDecision ?? 'allow';
    } catch {
      /* a silent allow prints nothing */
    }
  }
  // CLAUDE.md: assert status, not only error. `check` exits 2 on deny and 0
  // otherwise; a crash on the new carrier path would exit 1 with no stdout and
  // read as a silent allow without this.
  expect(r.status, `${tool}: exit status disagrees with decision "${decision}"\n${r.stderr}`).toBe(
    decision === 'deny' ? 2 : 0
  );
  return { decision, stdout: r.stdout, stderr: r.stderr };
}

/** `node9 explain <tool> <args>`, reduced to the gate's vocabulary. */
async function explain(h: string, tool: string, args: Record<string, unknown>) {
  const argv = tool === 'Bash' ? [String(args.command)] : [JSON.stringify(args)];
  const r = await runCli(h, ['explain', tool, ...argv]);
  expect(r.error, `explain spawn failed for ${tool}`).toBeUndefined();
  expect(r.status, `explain exited non-zero for ${tool}\n${r.stderr}`).toBe(0);
  const out = `${r.stdout}${r.stderr}`;
  const m = /Decision: .*?(ALLOW|BLOCK|REVIEW)/.exec(out);
  expect(m, `explain printed no Decision line for ${tool}:\n${out.slice(0, 400)}`).not.toBeNull();
  return { ALLOW: 'allow', BLOCK: 'deny', REVIEW: 'ask' }[m![1]]!;
}

const BLOCK: Egress = {
  enabled: true,
  mode: 'block',
  allow: [USER_ALLOW_ENTRY],
  deny: [USER_DENY_ENTRY],
  allowPrivate: false,
};
const CONFIGS: Array<[string, Egress | undefined]> = [
  ['egress off', undefined],
  ['block', BLOCK],
  ['review', { ...BLOCK, mode: 'review' }],
  ['block + allowPrivate', { ...BLOCK, allowPrivate: true }],
];

beforeAll(() => {
  if (!fs.existsSync(CLI)) throw new Error(`build first: ${CLI}`);
  // The corpus premise, asserted where it belongs rather than thrown at
  // module load: the 'default-allowlisted' column means nothing if this host
  // ever leaves the curated list.
  const allowlisted = DESTINATIONS.find((d) => d.kind === 'default-allowlisted')!;
  const host = new URL(allowlisted.url).hostname;
  expect(
    DEFAULT_EGRESS_ALLOWLIST.some((p) => hostMatches(host, p)),
    `${host} is no longer on DEFAULT_EGRESS_ALLOWLIST; the corpus row is stale`
  ).toBe(true);
});
afterEach(() => {
  if (home) fs.rmSync(home, { recursive: true, force: true });
});

describe('P0 known-true: the harness sees the gap this file exists for', () => {
  it('under block, Bash curl to an unknown host is denied', async () => {
    home = makeHome(BLOCK);
    const curl = CARRIERS.find((c) => c.tool === 'Bash')!;
    expect((await check(home, 'Bash', curl.build('https://evil.example.com/x'))).decision).toBe(
      'deny'
    );
  });
  it('and so is the same request through WebFetch (this was allow on the parent)', async () => {
    home = makeHome(BLOCK);
    const wf = CARRIERS.find((c) => c.tool === 'WebFetch')!;
    expect((await check(home, 'WebFetch', wf.build('https://evil.example.com/x'))).decision).toBe(
      'deny'
    );
  });
});

// ── 4.1 The matrix: every carrier agrees ────────────────────────────────────
describe.each(CONFIGS)('4.1 agreement under %s', (_label, egress) => {
  it.each(DESTINATIONS.map((d) => [d.kind, d.url] as const))(
    '%s (%s): every carrier returns the same verdict',
    async (_kind, url) => {
      home = makeHome(egress);
      const verdicts = await Promise.all(
        CARRIERS.map(async (c) => `${c.id}=${(await check(home, c.tool, c.build(url))).decision}`)
      );
      const distinct = new Set(verdicts.map((v) => v.split('=')[1]));
      expect(distinct.size, `carriers disagree on ${url}:\n  ${verdicts.join('\n  ')}`).toBe(1);
    }
  );
});

// ── 4.2 The closed list: what the change must NOT see ───────────────────────
describe('4.2 no verdict: tools outside the table, and values that are not destinations', () => {
  it('every row', async () => {
    home = makeHome(BLOCK); // block, so an egress verdict would show as a deny
    await Promise.all(
      NO_VERDICT_ROWS.map(async (row) => {
        const r = await check(home, row.tool, row.args);
        expect(
          r.stdout,
          `${row.id}: an egress verdict reached a row the closed list must not see\n${row.carrierNote}`
        ).not.toMatch(/Node9 Egress \((Blocked|Review)\)/);
        if (!row.tool.startsWith('mcp__')) {
          // Built-in tools outside the table are allowed under standard mode
          // today and must stay so. An unlisted MCP tool may be gated by MCP
          // permissions, so for it only the absence of an egress verdict holds.
          expect(r.decision, `${row.id}: ${row.carrierNote}`).toBe('allow');
        }
      })
    );
  });
});

// ── 4.3 explain and the gate agree (the G8 invariant) ───────────────────────
// The invariant varies by (ignored vs not, shell vs tool), not by which of the
// five tool carriers is used, so three carriers cover it: the shell one, the
// one on ignoredTools (WebFetch), and one that is not (mcp fetch). 4.1 keeps
// all seven, because there carrier identity IS the property.
describe('4.3 node9 explain agrees with node9 check', () => {
  const probes = CARRIERS.filter((c) =>
    ['bash-curl-post-file', 'webfetch', 'mcp-fetch'].some((id) => c.id.startsWith(id))
  );
  const kinds = ['unknown', 'private-v6', 'floor', 'user-denied'];
  it.each(DESTINATIONS.filter((d) => kinds.includes(d.kind)).map((d) => [d.kind, d.url] as const))(
    '%s',
    async (_kind, url) => {
      home = makeHome(BLOCK);
      expect(probes.length, 'corpus ids changed; 4.3 is probing nothing').toBeGreaterThan(1);
      await Promise.all(
        probes.map(async (c) => {
          const args = c.build(url);
          const [gate, exp] = await Promise.all([
            check(home, c.tool, args).then((r) => r.decision),
            explain(home, c.tool, args),
          ]);
          expect(exp, `${c.id} on ${url}: explain says ${exp}, the gate says ${gate}`).toBe(gate);
        })
      );
    }
  );
});

// ── 4.4 Ordering: the floor wins over the egress policy ─────────────────────
describe('4.4 a floor address through a tool carrier reports the floor, not egress', () => {
  it('WebFetch to the metadata endpoint is a Protected Address block, even allowlisted', async () => {
    // If egress answered first, this allow entry could soften a tier-1 block.
    home = makeHome({
      enabled: true,
      mode: 'block',
      allow: ['169.254.169.254'],
      deny: [],
      allowPrivate: true,
    });
    const wf = CARRIERS.find((c) => c.tool === 'WebFetch')!;
    const r = await check(home, 'WebFetch', wf.build('http://169.254.169.254/latest/meta-data/'));
    expect(r.decision).toBe('deny');
    expect(r.stdout).toMatch(/Protected Address/);
    expect(r.stdout).not.toMatch(/Egress \(Blocked\)/);
  });
});

// ── Regression rows for the /code-review findings on this change ───────────
// The first cut routed ignored tools through evaluatePolicy with
// skipIgnoredFastPath. The engine's egress branch already runs before its
// fast path, so the flag bought nothing and cost three behaviours below.
describe('review findings: turning egress on must not change anything else', () => {
  const SMART = (tool: string, field: string) => ({
    name: `block-${tool}`,
    tool,
    conditions: [{ field, op: 'contains', value: 'evil' }],
    conditionMode: 'all',
    verdict: 'block',
    reason: 'rule',
  });
  function homeWith(policy: Record<string, unknown>, mode = 'standard'): string {
    const h = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-egress-rf-'));
    fs.mkdirSync(path.join(h, '.node9'), { recursive: true });
    fs.writeFileSync(
      path.join(h, '.node9', 'config.json'),
      JSON.stringify({
        settings: {
          mode,
          autoStartDaemon: false,
          approvers: { native: false, browser: false, cloud: false, terminal: false },
        },
        policy,
      })
    );
    return h;
  }
  const ALLOWLISTED = 'https://corp.example/x';
  const EG = {
    enabled: true,
    mode: 'block',
    allow: ['corp.example'],
    deny: [],
    allowPrivate: false,
  };

  it('F1: on a STRICT machine an allowlisted WebFetch stays allow, and explain agrees', async () => {
    // Measured before the fix: gate 'ask' (Global Config: Strict Mode Active)
    // while explain said ALLOW. That is the G8 explain/gate gap, reintroduced
    // by the change meant to close it.
    home = homeWith({ egress: EG }, 'strict');
    const wf = CARRIERS.find((c) => c.tool === 'WebFetch')!;
    const args = wf.build(ALLOWLISTED);
    const [gate, exp] = await Promise.all([
      check(home, 'WebFetch', args).then((r) => r.decision),
      explain(home, 'WebFetch', args),
    ]);
    expect(gate).toBe('allow');
    expect(exp, 'explain and the gate must agree').toBe(gate);
    // The unknown host is still denied: this is not egress being switched off.
    expect((await check(home, 'WebFetch', wf.build('https://evil.example.com/x'))).decision).toBe(
      'deny'
    );
  });

  it('F1b: a dangerous word in a WebFetch prompt is not newly reviewable', async () => {
    home = homeWith({ egress: EG });
    const wf = CARRIERS.find((c) => c.tool === 'WebFetch')!;
    const r = await check(home, 'WebFetch', {
      ...wf.build(ALLOWLISTED),
      prompt: 'what does shred do',
    });
    expect(r.decision).toBe('allow');
  });

  it('F3: a smart-rule BLOCK still wins over an egress review, on both carriers', async () => {
    // Measured before the fix: the tool carrier was downgraded to 'ask' while
    // the shell carrier stayed 'deny'. The egress branch was returning ahead
    // of the smart-rule section; the shell branch sits after it.
    const review = { enabled: true, mode: 'review', allow: [], deny: [], allowPrivate: false };
    const url = 'https://evil.example.com/x';
    home = homeWith({ smartRules: [SMART('mcp__fetch__fetch', 'url')], egress: review });
    expect((await check(home, 'mcp__fetch__fetch', { url })).decision, 'tool carrier').toBe('deny');
    fs.rmSync(home, { recursive: true, force: true });
    home = homeWith({ smartRules: [SMART('bash', 'command')], egress: review });
    expect((await check(home, 'Bash', { command: `curl ${url}` })).decision, 'shell carrier').toBe(
      'deny'
    );
  });

  it('F3b: a smart-rule ALLOW lifts the egress block on both carriers (the shell law)', async () => {
    const url = 'https://evil.example.com/x';
    const allowRule = (tool: string, field: string) => ({
      ...SMART(tool, field),
      name: `allow-${tool}`,
      verdict: 'allow',
    });
    home = homeWith({ smartRules: [allowRule('mcp__fetch__fetch', 'url')], egress: EG });
    expect((await check(home, 'mcp__fetch__fetch', { url })).decision, 'tool carrier').toBe(
      'allow'
    );
    fs.rmSync(home, { recursive: true, force: true });
    home = homeWith({ smartRules: [allowRule('bash', 'command')], egress: EG });
    expect((await check(home, 'Bash', { command: `curl ${url}` })).decision, 'shell carrier').toBe(
      'allow'
    );
  });

  it('F4: repeated identical fetches to an allowlisted host are not loop-detected', async () => {
    // Measured before the fix: allow, allow, allow, allow, deny, deny. An
    // ignored tool never reached the loop counter; arming it because egress
    // is ON turned an agent re-reading a page into a hard deny. Egress judges
    // the destination, not the repetition.
    home = homeWith({
      egress: EG,
      loopDetection: { enabled: true, threshold: 3, windowSeconds: 120 },
    });
    const wf = CARRIERS.find((c) => c.tool === 'WebFetch')!;
    const args = wf.build(ALLOWLISTED);
    const seen: string[] = [];
    for (let i = 0; i < 6; i++) seen.push((await check(home, 'WebFetch', args)).decision);
    expect(new Set(seen), `six identical allowlisted fetches: ${seen.join(', ')}`).toEqual(
      new Set(['allow'])
    );
  });
});
