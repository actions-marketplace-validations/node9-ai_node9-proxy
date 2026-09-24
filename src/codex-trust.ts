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
// ⚠️ CORRECTED 2026-09-24. This header used to state two "facts" that turned
// out to be wrong in the way that matters:
//
//   1. "The hash is not ours to compute." Still true — byte-identical commands
//      under different matchers carry different hashes, and openai/codex#21615
//      is open because integrators who reverse-engineer it break on every
//      internal change. But we never NEEDED to compute it: `codex app-server`'s
//      `hooks/list` returns `currentHash`, and `config/batchWrite` accepts it
//      back. That is the path Codex's own TUI takes. codex-app-server.ts does
//      exactly that from `node9 init`; this module still never writes trust.
//
//   2. "The desktop app cannot grant trust." Half true. It ships a Hooks
//      settings page, but that page renders "No hooks found" while the
//      app-server returns every hook (upstream bug U1), so in practice a
//      desktop user has no working route. The TUI review screen works but
//      means a terminal, a hashed binary path, and a screen nobody has seen.
//
// Both were stated as reasons NOT to act. Recorded here so the next reader
// does not rebuild the same wall.
//
// This module is now the FALLBACK and the reporting layer: when auto-trust
// cannot run (no binary, RPC failure, protocol change), it prints the manual
// instruction, and doctor/status still infer trust from files. What node9 can
// always do is observe the outcome. A Codex audit row newer than
// hooks.json proves the current hooks ran. Zero [hooks.state] entries proves
// they were never reviewed. Everything in between is "not observed", and it
// is reported as exactly that — never as a green tick.

import fs from 'fs';
import path from 'path';
import os from 'os';
import { spawnSync } from 'child_process';
import { parse as parseToml } from 'smol-toml';
import { locatorCommand } from './utils/platform-shell';
import { findCodexBinary } from './codex-app-server';

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
  // One lookup, not two. This used to scan the hashed build dirs itself and
  // return the FIRST one readdir handed back — which on 2026-09-23 pointed a
  // real machine at a stale binary Codex had left behind after an update.
  // findCodexBinary prefers the CODEX_CLI_PATH the desktop app writes and
  // otherwise sorts by mtime; the manual instruction and auto-trust must name
  // the same binary.
  const bin = findCodexBinary(os.homedir(), env);
  if (bin && fs.existsSync(bin)) return `"${bin}"`;
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
