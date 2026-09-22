// Codex hook trust — what node9 can and cannot know about it.
//
// Codex runs a hook only after the user has trusted it. Trust is recorded in
// ~/.codex/config.toml as [hooks.state."<hooks.json>:<event>:<i>:<j>"]
// trusted_hash = "sha256:…", and it is keyed to the hook's CONTENT: rewrite
// hooks.json and every entry goes stale. Codex then skips the hook with no log
// line and no UI signal. node9 rewrites hooks.json on `init`, on `agents add`,
// and on every self-heal, so a routine upgrade silently un-protects the
// machine until the user re-trusts.
//
// Measured 2026-09-22 from Codex's own log (~/.codex/logs_2.sqlite):
//   09-21 13:25Z  the only hook-trust write ever, client_name = "codex-tui"
//   09-22 15:13Z  last hook fired
//   09-22 15:15Z  hooks.json rewritten by `node9 init`
//   after         33 tool calls, zero hook events
//
// Two facts shape everything below:
//
//   1. The hash is not ours to compute. Byte-identical commands under
//      different matchers carry different hashes; 2562 canonicalisation
//      attempts matched none of the stored values. openai/codex#21615 is open
//      because integrators who reverse-engineer it break on every internal
//      change. This module NEVER writes trust state.
//
//   2. The desktop app cannot grant trust. Its startup never calls
//      hooks/list, and codex.exe has no `hooks` subcommand. The review screen
//      ("New hook - review required" / "Trust all and continue") lives in the
//      TUI. So the instruction node9 used to print — "run /hooks" — pointed at
//      something desktop users do not have.
//
// What node9 CAN do is observe the outcome. A Codex audit row newer than
// hooks.json proves the current hooks ran. Zero [hooks.state] entries proves
// they were never reviewed. Everything in between is "not observed", and it
// is reported as exactly that — never as a green tick.

import fs from 'fs';
import path from 'path';
import os from 'os';
import { spawnSync } from 'child_process';
import { parse as parseToml } from 'smol-toml';
import { locatorCommand } from './utils/platform-shell';

export type CodexTrustState =
  /** [features].hooks = false in config.toml — hooks.json is dormant regardless of trust. */
  | 'disabled'
  /** No [hooks.state] entries at all: Codex has never reviewed these hooks. */
  | 'never-trusted'
  /** A Codex audit row is newer than hooks.json: the current hooks demonstrably ran. */
  | 'observed'
  /**
   * Trust entries exist, but nothing from Codex has reached node9 since
   * hooks.json was last written. Stale trust and "user hasn't used Codex
   * since" look identical from here — so this is reported as unverified,
   * not as either.
   */
  | 'unverified';

export interface CodexTrustAssessment {
  state: CodexTrustState;
  /** mtime of hooks.json, ISO. Null when the file is absent. */
  hooksWrittenAt: string | null;
  /** Newest Codex audit row, ISO. Null when none exists. */
  lastCodexActivityAt: string | null;
  /** Number of [hooks.state] entries in config.toml. */
  trustEntries: number;
}

interface CodexConfigToml {
  features?: { hooks?: boolean };
  codex_hooks?: boolean;
  hooks?: { state?: Record<string, unknown> };
}

function readTomlSafe(filePath: string): CodexConfigToml | null {
  try {
    return parseToml(fs.readFileSync(filePath, 'utf-8')) as CodexConfigToml;
  } catch {
    return null;
  }
}

/**
 * Newest `ts` among audit rows whose agent is Codex. Reads the whole log but
 * parses only lines that mention Codex — the file is a few hundred to a few
 * thousand rows on a busy machine, not the transcript corpus.
 */
export function lastCodexAuditTs(auditLogPath: string): string | null {
  let text: string;
  try {
    text = fs.readFileSync(auditLogPath, 'utf-8');
  } catch {
    return null;
  }
  let newest: string | null = null;
  for (const line of text.split('\n')) {
    if (!line.includes('"Codex"')) continue;
    try {
      const row = JSON.parse(line) as { agent?: string; ts?: string };
      if (row.agent !== 'Codex' || typeof row.ts !== 'string') continue;
      if (newest === null || row.ts > newest) newest = row.ts;
    } catch {
      // A torn line at the tail is normal while the daemon writes.
    }
  }
  return newest;
}

/**
 * Pure assessment over already-read inputs. Exported so the three-state logic
 * can be pinned without a filesystem.
 */
export function assessCodexTrustFrom(input: {
  hooksDisabled: boolean;
  trustEntries: number;
  hooksWrittenAt: string | null;
  lastCodexActivityAt: string | null;
}): CodexTrustAssessment {
  const { hooksDisabled, trustEntries, hooksWrittenAt, lastCodexActivityAt } = input;
  let state: CodexTrustState;
  if (hooksDisabled) state = 'disabled';
  else if (trustEntries === 0) state = 'never-trusted';
  else if (hooksWrittenAt && lastCodexActivityAt && lastCodexActivityAt > hooksWrittenAt) {
    state = 'observed';
  } else state = 'unverified';
  return { state, hooksWrittenAt, lastCodexActivityAt, trustEntries };
}

export function assessCodexTrust(
  home: string = os.homedir(),
  auditLogPath: string = path.join(home, '.node9', 'audit.log')
): CodexTrustAssessment {
  const hooksPath = path.join(home, '.codex', 'hooks.json');
  const configPath = path.join(home, '.codex', 'config.toml');

  let hooksWrittenAt: string | null = null;
  try {
    hooksWrittenAt = fs.statSync(hooksPath).mtime.toISOString();
  } catch {
    hooksWrittenAt = null;
  }

  const config = readTomlSafe(configPath);
  const hooksDisabled = config?.features?.hooks === false || config?.codex_hooks === false;
  const trustEntries = Object.keys(config?.hooks?.state ?? {}).length;

  return assessCodexTrustFrom({
    hooksDisabled,
    trustEntries,
    hooksWrittenAt,
    lastCodexActivityAt: lastCodexAuditTs(auditLogPath),
  });
}

/**
 * The command a user can run to reach Codex's hook review screen. Prefers a
 * `codex` on PATH; on Windows falls back to the binary the desktop app
 * bundles (which is a full CLI, just not on PATH). Null when neither is
 * found — the caller then explains the desktop limitation without a path.
 */
export function findCodexTui(env: NodeJS.ProcessEnv = process.env): string | null {
  try {
    const r = spawnSync(locatorCommand(), ['codex'], { encoding: 'utf-8', timeout: 3000 });
    const first = (r.stdout ?? '').split(/\r?\n/).find((l) => l.trim());
    if (r.status === 0 && first) return 'codex';
  } catch {
    // locator missing — fall through
  }
  if (process.platform === 'win32' && env.LOCALAPPDATA) {
    const binDir = path.join(env.LOCALAPPDATA, 'OpenAI', 'Codex', 'bin');
    try {
      for (const d of fs.readdirSync(binDir)) {
        const exe = path.join(binDir, d, 'codex.exe');
        if (fs.existsSync(exe)) return `"${exe}"`;
      }
    } catch {
      // no bundled binary
    }
  }
  return null;
}

/**
 * The instruction node9 prints wherever it used to say "run /hooks". Tells the
 * truth about where trust can be granted, and what is at stake until it is.
 */
export function codexTrustInstruction(tui: string | null = findCodexTui()): string {
  const where = tui
    ? `run ${tui} in a terminal`
    : 'run the Codex CLI (`codex`) in a terminal — the desktop app has no hook review screen';
  return (
    `    ➜  Codex must trust these hooks once: ${where},\n` +
    `       then choose "Trust all and continue" when Codex asks to review them.\n` +
    `       Until then Codex runs unprotected. Every rewrite of hooks.json needs this again.`
  );
}
