// Establish Codex hook trust from `node9 init`, using Codex's own app-server.
//
// WHY THIS EXISTS. Codex runs a hook only after the user has trusted it, and
// trust is keyed to the hook's CONTENT — so every rewrite of hooks.json silently
// un-protects the machine (see codex-trust.ts for the measurement). The only
// human route is the bundled CLI's TUI: a terminal, a hashed binary path, and a
// review screen most users have never seen. The desktop app ships a Hooks
// settings page, but it renders "No hooks found" while the app-server returns
// five — an upstream UI bug (U1). Sending users down that road is not shippable,
// so node9 establishes trust itself, inside the command the user already ran.
//
// ⭐ node9 NEVER COMPUTES A HASH. `hooks/list` returns `currentHash`; we hand the
// same value straight back in `config/batchWrite`. This corrects a claim that
// used to live in codex-trust.ts: the hash is not ours to compute, and it does
// not need to be. This is the API path Codex's own TUI takes, not
// reverse-engineering — openai/codex#21615 exists because integrators who DO
// reverse-engineer the hash break on every internal change.
//
// ⚠️ `codex app-server` is labelled experimental upstream. It will change. The
// design that survives that is in §6 of codex-auto-trust-design.md and is
// enforced here: never claim success without re-verifying, and fail into the
// manual instruction rather than into silence.

import fs from 'fs';
import path from 'path';
import os from 'os';
import { spawn, type ChildProcessWithoutNullStreams } from 'child_process';
import { parse as parseToml } from 'smol-toml';

/** How long the whole initialize → list → write → verify exchange may take. */
const RPC_TIMEOUT_MS = 15_000;

export interface CodexHook {
  key: string;
  command?: string;
  matcher?: string;
  eventName?: string;
  sourcePath?: string;
  source?: string;
  pluginId?: string | null;
  isManaged?: boolean;
  currentHash?: string;
  trustStatus?: 'trusted' | 'untrusted' | 'modified' | string;
}

export type TrustOutcome =
  | { ok: true; trusted: string[]; alreadyTrusted: number }
  /** Every failure is actionable by the caller in exactly one way: print the
   *  manual instruction. The reason is for logs, never for a retry loop. */
  | { ok: false; reason: string };

// ── Binary resolution ─────────────────────────────────────────────────────────

/**
 * Where the Codex CLI lives, in order of how much we trust the answer:
 *
 *   1. NODE9_CODEX_BIN            — tests, and an escape hatch for odd installs
 *   2. CODEX_CLI_PATH in config.toml — the desktop app writes this itself and
 *      rewrites it on update, so it is the exact binary the app runs
 *   3. %LOCALAPPDATA%\OpenAI\Codex\bin\<hash>\codex.exe, NEWEST mtime
 *   4. `codex` on PATH            — may be a different (npm) build; acceptable
 *      because CODEX_HOME is shared
 *
 * ⚠️ Step 3 sorts by mtime on purpose. Codex leaves old hashed build dirs
 * behind, and picking the first entry readdir returns pointed a real machine at
 * a stale binary on 2026-09-23.
 */
export function findCodexBinary(
  home: string = os.homedir(),
  env: NodeJS.ProcessEnv = process.env
): string | null {
  if (env.NODE9_CODEX_BIN) return env.NODE9_CODEX_BIN;

  const fromConfig = codexCliPathFromConfig(home);
  if (fromConfig && fs.existsSync(fromConfig)) return fromConfig;

  if (process.platform === 'win32' && env.LOCALAPPDATA) {
    const binDir = path.join(env.LOCALAPPDATA, 'OpenAI', 'Codex', 'bin');
    try {
      const candidates = fs
        .readdirSync(binDir)
        .map((d) => path.join(binDir, d, 'codex.exe'))
        .filter((p) => fs.existsSync(p))
        .map((p) => ({ p, mtime: fs.statSync(p).mtimeMs }))
        .sort((a, b) => b.mtime - a.mtime);
      if (candidates.length > 0) return candidates[0].p;
    } catch {
      /* no bundled binary */
    }
  }
  return null;
}

/** `CODEX_CLI_PATH` out of `[mcp_servers.*.env]` in the user's config.toml. */
export function codexCliPathFromConfig(home: string = os.homedir()): string | null {
  try {
    const cfg = parseToml(
      fs.readFileSync(path.join(home, '.codex', 'config.toml'), 'utf-8')
    ) as Record<string, unknown>;
    const servers = (cfg.mcp_servers ?? {}) as Record<string, { env?: Record<string, unknown> }>;
    for (const s of Object.values(servers)) {
      const p = s?.env?.CODEX_CLI_PATH;
      if (typeof p === 'string' && p) return p;
    }
  } catch {
    /* absent or unparseable */
  }
  return null;
}

// ── Selection ─────────────────────────────────────────────────────────────────

function samePath(a: string | undefined, b: string): boolean {
  if (!a) return false;
  const norm = (s: string) => s.replace(/\\/g, '/').replace(/\/+$/, '');
  const x = norm(a);
  const y = norm(b);
  return process.platform === 'win32' ? x.toLowerCase() === y.toLowerCase() : x === y;
}

/**
 * Which hooks node9 may auto-trust.
 *
 * ⭐ THE SECURITY-CRITICAL PART. `emittedCommands` is the exact set of command
 * strings node9 wrote in THIS run, and a hook qualifies only if its command is
 * byte-identical to one of them.
 *
 * Matching on a node9-shaped regex instead would be a hole: `isNode9Hook`
 * accepts `evil.exe && node9 check`, so anyone able to write hooks.json could
 * have node9 grant them trust on the next `init` — node9 would become a
 * trust-granting vector. We trust our own output, never things that resemble it.
 *
 * The rest is belt and braces: the hook must come from the user-level
 * hooks.json we just wrote, not from a plugin or an MDM-managed layer, and a
 * hook Codex already trusts is left alone.
 */
export function selectHooksToTrust(
  hooks: CodexHook[],
  codexHome: string,
  emittedCommands: Iterable<string>
): CodexHook[] {
  const mine = new Set(emittedCommands);
  const hooksJson = path.join(codexHome, 'hooks.json');
  return hooks.filter(
    (h) =>
      typeof h.command === 'string' &&
      mine.has(h.command) &&
      samePath(h.sourcePath, hooksJson) &&
      h.isManaged !== true &&
      (h.source === undefined || h.source === 'user') &&
      !h.pluginId &&
      h.trustStatus !== 'trusted' &&
      typeof h.currentHash === 'string' &&
      h.currentHash.length > 0
  );
}

/** The `config/batchWrite` params for a selection. Hashes come from the same
 *  `hooks/list` response; nothing here is derived or computed. */
export function buildTrustEdits(selected: CodexHook[]): {
  edits: Array<{ keyPath: string; mergeStrategy: string; value: Record<string, unknown> }>;
  reloadUserConfig: boolean;
} {
  return {
    edits: [
      {
        keyPath: 'hooks.state',
        // upsert, so [hooks.state] entries for hooks that are not ours survive.
        mergeStrategy: 'upsert',
        value: Object.fromEntries(selected.map((h) => [h.key, { trusted_hash: h.currentHash }])),
      },
    ],
    reloadUserConfig: true,
  };
}

// ── Client ────────────────────────────────────────────────────────────────────

/** Newline-delimited JSON over the child's stdio. No `jsonrpc` field. */
class AppServerClient {
  private child: ChildProcessWithoutNullStreams;
  private buf = '';
  private nextId = 1;
  private pending = new Map<number, (m: Record<string, unknown>) => void>();

  constructor(bin: string, codexHome?: string) {
    // A resolved binary is a PATH and is spawned whole: `C:\Users\Some User\…`
    // contains a space, and splitting it would be the same whitespace-in-a-path
    // defect this codebase spent a week removing from hook commands. Only the
    // NODE9_CODEX_BIN test override (`node <fixture>`) is a command line.
    const [file, ...pre] = fs.existsSync(bin) ? [bin] : bin.split(' ');
    this.child = spawn(file, [...pre, 'app-server'], {
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: codexHome ? { ...process.env, CODEX_HOME: codexHome } : process.env,
    }) as ChildProcessWithoutNullStreams;
    this.child.stdout.setEncoding('utf-8');
    this.child.stdout.on('data', (d: string) => this.onData(d));
    // Never let a child's stderr reach our stdout: hook and MCP paths require a
    // clean stdout, and init's output is read by humans.
    this.child.stderr.resume();
  }

  private onData(d: string): void {
    this.buf += d;
    for (let i = this.buf.indexOf('\n'); i >= 0; i = this.buf.indexOf('\n')) {
      const line = this.buf.slice(0, i);
      this.buf = this.buf.slice(i + 1);
      if (!line.trim()) continue;
      try {
        const m = JSON.parse(line) as Record<string, unknown>;
        const id = m.id;
        if (typeof id === 'number') {
          const resolve = this.pending.get(id);
          if (resolve) {
            this.pending.delete(id);
            resolve(m);
          }
        }
      } catch {
        // A line we cannot parse is not fatal on its own — the timeout is the
        // backstop. Silently ignoring a MALFORMED reply we asked for would be,
        // which is why every request has its own pending entry.
      }
    }
  }

  request(method: string, params?: unknown): Promise<Record<string, unknown>> {
    const id = this.nextId++;
    return new Promise((resolve) => {
      this.pending.set(id, resolve);
      this.child.stdin.write(JSON.stringify({ id, method, params }) + '\n');
    });
  }

  notify(method: string, params?: unknown): void {
    this.child.stdin.write(JSON.stringify({ method, params }) + '\n');
  }

  kill(): void {
    try {
      this.child.kill();
    } catch {
      /* already gone */
    }
  }
}

function hooksFrom(result: unknown): CodexHook[] {
  const data = (result as { data?: Array<{ hooks?: CodexHook[] }> } | undefined)?.data;
  if (!Array.isArray(data)) return [];
  const out: CodexHook[] = [];
  const seen = new Set<string>();
  for (const d of data) {
    for (const h of d.hooks ?? []) {
      if (h?.key && !seen.has(h.key)) {
        seen.add(h.key);
        out.push(h);
      }
    }
  }
  return out;
}

/**
 * Ask Codex to trust the hooks node9 just wrote.
 *
 * Returns ok only after a SECOND `hooks/list` confirms every selected hook is
 * `trusted`. A write that reports `{"status":"ok"}` is not evidence: the whole
 * point of this module is that we do not get to decide whether Codex trusts
 * something, so we re-read instead of assuming.
 */
export async function establishCodexTrust(
  emittedCommands: Iterable<string>,
  opts: { home?: string; bin?: string | null; timeoutMs?: number } = {}
): Promise<TrustOutcome> {
  const home = opts.home ?? os.homedir();
  const bin = opts.bin === undefined ? findCodexBinary(home) : opts.bin;
  if (!bin) return { ok: false, reason: 'no Codex binary found' };

  const client = new AppServerClient(bin, path.join(home, '.codex'));
  const timeout = new Promise<TrustOutcome>((resolve) =>
    setTimeout(
      () => resolve({ ok: false, reason: 'timed out talking to codex app-server' }),
      opts.timeoutMs ?? RPC_TIMEOUT_MS
    )
  );

  const exchange = (async (): Promise<TrustOutcome> => {
    const init = await client.request('initialize', {
      clientInfo: { name: 'node9', version: process.env.npm_package_version ?? '0' },
    });
    if (init.error)
      return { ok: false, reason: `initialize failed: ${JSON.stringify(init.error)}` };
    client.notify('initialized');

    // `initialize` reports where Codex keeps config. Trust that over ~/.codex.
    const codexHome =
      ((init.result as { codexHome?: string } | undefined)?.codexHome ?? '') ||
      path.join(home, '.codex');

    const listed = await client.request('hooks/list', { cwds: [home] });
    if (listed.error)
      return { ok: false, reason: `hooks/list failed: ${JSON.stringify(listed.error)}` };
    const hooks = hooksFrom(listed.result);
    if (hooks.length === 0) return { ok: false, reason: 'codex reported no hooks' };

    const selected = selectHooksToTrust(hooks, codexHome, emittedCommands);
    const alreadyTrusted = hooks.filter(
      (h) => h.trustStatus === 'trusted' && [...emittedCommands].includes(h.command ?? '')
    ).length;
    if (selected.length === 0) {
      return alreadyTrusted > 0
        ? { ok: true, trusted: [], alreadyTrusted }
        : { ok: false, reason: 'no node9 hooks found in codex hooks/list' };
    }

    const wrote = await client.request('config/batchWrite', buildTrustEdits(selected));
    if (wrote.error) {
      return { ok: false, reason: `config/batchWrite failed: ${JSON.stringify(wrote.error)}` };
    }

    // Re-verify. This is the line that keeps the module honest.
    const after = await client.request('hooks/list', { cwds: [home] });
    if (after.error) return { ok: false, reason: 'could not re-verify trust' };
    const byKey = new Map(hooksFrom(after.result).map((h) => [h.key, h]));
    const stillUntrusted = selected.filter((h) => byKey.get(h.key)?.trustStatus !== 'trusted');
    if (stillUntrusted.length > 0) {
      return { ok: false, reason: `${stillUntrusted.length} hook(s) still untrusted after write` };
    }
    return { ok: true, trusted: selected.map((h) => h.key), alreadyTrusted };
  })();

  try {
    return await Promise.race([exchange, timeout]);
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : String(e) };
  } finally {
    client.kill();
  }
}
