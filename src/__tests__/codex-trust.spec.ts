// The three-state trust assessment must never collapse "not observed" into a
// pass, and must never claim to know what only Codex knows.
//
// Background: Codex trust is keyed to hooks.json content and node9 rewrites
// that file on init/add/self-heal. On 2026-09-22 two Windows machines showed
// "Codex — PreToolUse hook active" in doctor while Codex was skipping every
// hook. The fix is not to compute the trust hash (undocumented, changes
// underneath integrators — openai/codex#21615) but to report the outcome
// honestly: observed, never trusted, or unverified.
import { describe, it, expect } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  assessCodexTrustFrom,
  assessCodexTrust,
  lastCodexAuditTs,
  codexTrustInstruction,
} from '../codex-trust';

describe('assessCodexTrustFrom — the three states', () => {
  const T0 = '2026-09-22T15:15:18.000Z'; // hooks.json written
  const before = '2026-09-22T15:13:22.000Z';
  const after = '2026-09-22T16:00:00.000Z';

  it('observed: a Codex row newer than hooks.json proves the current hooks ran', () => {
    const a = assessCodexTrustFrom({
      hooksDisabled: false,
      trustEntries: 5,
      hooksWrittenAt: T0,
      lastCodexActivityAt: after,
    });
    expect(a.state).toBe('observed');
  });

  it('unverified: trust entries exist but the newest Codex row predates the rewrite', () => {
    // This is exactly machine 2 on 2026-09-22: five entries in config.toml,
    // last hook fired 15:13, hooks.json rewritten 15:15, nothing since. It is
    // ALSO what a machine looks like when the user simply has not opened Codex
    // since the rewrite. The assessment must not pick one.
    const a = assessCodexTrustFrom({
      hooksDisabled: false,
      trustEntries: 5,
      hooksWrittenAt: T0,
      lastCodexActivityAt: before,
    });
    expect(a.state).toBe('unverified');
  });

  it('unverified: trust entries exist and there has never been a Codex row', () => {
    const a = assessCodexTrustFrom({
      hooksDisabled: false,
      trustEntries: 5,
      hooksWrittenAt: T0,
      lastCodexActivityAt: null,
    });
    expect(a.state).toBe('unverified');
  });

  it('never-trusted: zero [hooks.state] entries is certain, regardless of activity', () => {
    // Codex has not reviewed these hooks at all. Even a newer Codex row cannot
    // be from these hooks (a row implies a trusted hook ran), so entries win.
    const a = assessCodexTrustFrom({
      hooksDisabled: false,
      trustEntries: 0,
      hooksWrittenAt: T0,
      lastCodexActivityAt: after,
    });
    expect(a.state).toBe('never-trusted');
  });

  it('disabled: [features].hooks = false overrides everything', () => {
    const a = assessCodexTrustFrom({
      hooksDisabled: true,
      trustEntries: 5,
      hooksWrittenAt: T0,
      lastCodexActivityAt: after,
    });
    expect(a.state).toBe('disabled');
  });

  it('a row at exactly the write time is not "after" it', () => {
    const a = assessCodexTrustFrom({
      hooksDisabled: false,
      trustEntries: 5,
      hooksWrittenAt: T0,
      lastCodexActivityAt: T0,
    });
    expect(a.state).toBe('unverified');
  });
});

describe('lastCodexAuditTs', () => {
  it('returns the newest Codex row and ignores other agents and torn lines', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-trust-'));
    const log = path.join(dir, 'audit.log');
    fs.writeFileSync(
      log,
      [
        JSON.stringify({ ts: '2026-09-22T10:00:00.000Z', agent: 'Claude Code', tool: 'Bash' }),
        JSON.stringify({ ts: '2026-09-22T11:00:00.000Z', agent: 'Codex', tool: 'Bash' }),
        JSON.stringify({ ts: '2026-09-22T12:00:00.000Z', agent: 'Codex', tool: 'Bash' }),
        JSON.stringify({ ts: '2026-09-22T13:00:00.000Z', agent: 'Claude Code', tool: 'Bash' }),
        '{"ts":"2026-09-22T14:00:00.000Z","agent":"Codex","to', // torn tail
      ].join('\n')
    );
    expect(lastCodexAuditTs(log)).toBe('2026-09-22T12:00:00.000Z');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('returns null for a missing log', () => {
    expect(lastCodexAuditTs('/nonexistent/audit.log')).toBeNull();
  });
});

describe('assessCodexTrust — reads the real files', () => {
  it('counts quoted-dotted [hooks.state] keys the way Codex writes them', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-trust-home-'));
    fs.mkdirSync(path.join(home, '.codex'), { recursive: true });
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    fs.writeFileSync(path.join(home, '.codex', 'hooks.json'), '{"hooks":{}}');
    fs.writeFileSync(
      path.join(home, '.codex', 'config.toml'),
      [
        'model = "x"',
        '[hooks.state."C:\\\\Users\\\\u\\\\.codex\\\\hooks.json:pre_tool_use:0:0"]',
        'trusted_hash = "sha256:aaa"',
        '[hooks.state."C:\\\\Users\\\\u\\\\.codex\\\\hooks.json:post_tool_use:0:0"]',
        'trusted_hash = "sha256:bbb"',
        '',
      ].join('\n')
    );
    const a = assessCodexTrust(home);
    expect(a.trustEntries).toBe(2);
    expect(a.hooksWrittenAt).not.toBeNull();
    expect(a.state).toBe('unverified'); // entries, but no audit rows at all
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('is never-trusted when config.toml has no hooks.state at all', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-trust-home-'));
    fs.mkdirSync(path.join(home, '.codex'), { recursive: true });
    fs.writeFileSync(path.join(home, '.codex', 'hooks.json'), '{"hooks":{}}');
    fs.writeFileSync(path.join(home, '.codex', 'config.toml'), 'model = "x"\n');
    expect(assessCodexTrust(home).state).toBe('never-trusted');
    fs.rmSync(home, { recursive: true, force: true });
  });
});

describe('codexTrustInstruction', () => {
  it('never tells the user to run /hooks, and always says what is at stake', () => {
    for (const tui of ['codex', '"C:\\x\\codex.exe"', null]) {
      const text = codexTrustInstruction(tui);
      expect(text).not.toContain('/hooks');
      expect(text).toContain('Trust all and continue');
      expect(text).toMatch(/unprotected/i);
    }
  });

  it('names the desktop limitation when no TUI can be found', () => {
    expect(codexTrustInstruction(null)).toMatch(/desktop app has no hook review screen/);
  });

  it('points at the located binary when there is one', () => {
    expect(codexTrustInstruction('"C:\\x\\codex.exe"')).toContain(
      'run "C:\\x\\codex.exe" in a terminal'
    );
  });
});
