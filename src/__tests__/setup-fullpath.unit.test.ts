/**
 * Unit tests for fullPathCommand / isStaleHookCommand / isNode9Hook.
 *
 * Regression suite for issue #185: on Windows + Git Bash (which Claude Code
 * uses to run hooks), the previously-generated hook command was the
 * unquoted form `C:\Program Files\nodejs\node.exe C:\Users\...\cli.js
 * check`. Bash split that on whitespace, ran the backslash-unescape on
 * the first token, and ended up trying to exec `C:Program: command not
 * found`. The fix quotes both paths and normalises backslashes to forward
 * slashes — both forms work on Windows, cmd, PowerShell, and POSIX.
 *
 * The existing setup.test.ts suite runs with NODE9_TESTING=1, which makes
 * fullPathCommand short-circuit to the bare `node9 <subcommand>` form and
 * therefore never exercises the production string-builder. This file
 * clears NODE9_TESTING per-test (via vi.stubEnv) and stubs process.execPath
 * + process.argv[1] to exercise the real path.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import {
  fullPathCommand,
  isStaleHookCommand,
  isNode9Hook,
  isLegacyHookFormat,
  needsRewrite,
  isWindowsQuoteBrokenHook,
} from '../setup.js';

// process.execPath is technically settable but not writable on all
// platforms (we run on Linux for CI, so it is). Helper to stub safely
// and restore.
function stubProcess(execPath: string, argv1: string): () => void {
  const origExec = process.execPath;
  const origArgv = process.argv[1];
  Object.defineProperty(process, 'execPath', { value: execPath, configurable: true });
  process.argv[1] = argv1;
  return () => {
    Object.defineProperty(process, 'execPath', { value: origExec, configurable: true });
    process.argv[1] = origArgv;
  };
}

describe('fullPathCommand', () => {
  let restoreProcess: () => void = () => {};

  beforeEach(() => {
    // Clear NODE9_TESTING so the production string-builder runs.
    // vi.stubEnv auto-restores on test teardown.
    vi.stubEnv('NODE9_TESTING', '');
  });

  afterEach(() => {
    restoreProcess();
    vi.unstubAllEnvs();
  });

  it('emits an unquoted leading `node` on Windows (cmd quote-stripping)', () => {
    restoreProcess = stubProcess(
      'C:\\Program Files\\nodejs\\node.exe',
      'C:\\Users\\nadav\\AppData\\Roaming\\npm\\node_modules\\node9-ai\\node_modules\\@node9\\proxy\\dist\\cli.js'
    );
    // The #185 form quoted BOTH paths, which made the string start with a
    // quote and carry four of them. cmd preserves quotes only when there
    // are exactly two, so it stripped the outer pair and split on the space
    // in `Program Files`, tried to exec `C:/Program`, and exited 1. Codex
    // Desktop drops a failing hook silently: no enforcement, no audit row.
    // Dropping the absolute node path removes the leading quote and fixes
    // every shell form, while the still-quoted cli.js keeps #185's
    // space-safety under Git Bash.
    expect(fullPathCommand('check', 'win32')).toBe(
      'node ' +
        '"C:/Users/nadav/AppData/Roaming/npm/node_modules/node9-ai/node_modules/@node9/proxy/dist/cli.js" ' +
        'check'
    );
  });

  it('falls back to the PATH-resolved name for a Windows global binary', () => {
    // The bare-binary branch cannot be quoted (leading quote) and cannot be
    // left bare (a space in the path would split it), so on Windows it
    // resolves via PATH. This is the form verified end-to-end against Codex
    // Desktop on 2026-09-22.
    restoreProcess = stubProcess(
      'C:\\Program Files\\nodejs\\node.exe',
      'C:\\Users\\nadav\\AppData\\Roaming\\npm\\node9'
    );
    expect(fullPathCommand('check', 'win32')).toBe('node9 check');
  });

  it('never begins a Windows hook command with a quote (the cmd invariant)', () => {
    // One assertion standing for the whole class of regressions: whatever
    // shape this function grows on Windows, a leading quote reintroduces
    // the silent-failure bug for every user.
    for (const argv1 of [
      'C:\\Users\\Some User\\AppData\\Roaming\\npm\\node_modules\\node9-ai\\dist\\cli.js',
      'C:\\Users\\Some User\\AppData\\Roaming\\npm\\node9',
    ]) {
      restoreProcess();
      restoreProcess = stubProcess('C:\\Program Files\\nodejs\\node.exe', argv1);
      for (const sub of ['check', 'log', 'check --agent antigravity']) {
        expect(fullPathCommand(sub, 'win32').startsWith('"')).toBe(false);
      }
    }
  });

  it('leaves the POSIX form untouched (issue #185 regression)', () => {
    // #185 quoted both paths so a $HOME with a space survives Git Bash and
    // POSIX shells alike. Windows no longer takes this branch; POSIX still
    // must, and has no cmd quote-stripping rule to trip over.
    restoreProcess = stubProcess(
      '/usr/bin/node',
      '/home/u/.npm-global/lib/node_modules/node9-ai/dist/cli.js'
    );
    expect(fullPathCommand('check', 'linux')).toBe(
      '"/usr/bin/node" "/home/u/.npm-global/lib/node_modules/node9-ai/dist/cli.js" check'
    );
  });

  it('quotes a POSIX path with spaces (e.g. /Users/Some User/...)', () => {
    // macOS users with spaces in their full name end up with a $HOME like
    // "/Users/Some User". The old unquoted form would have broken them
    // too — covered by the same fix.
    restoreProcess = stubProcess(
      '/Users/Some User/.nvm/versions/node/v22.0.0/bin/node',
      '/Users/Some User/.npm-global/lib/node_modules/node9-ai/dist/cli.js'
    );
    expect(fullPathCommand('log', 'linux')).toBe(
      '"/Users/Some User/.nvm/versions/node/v22.0.0/bin/node" ' +
        '"/Users/Some User/.npm-global/lib/node_modules/node9-ai/dist/cli.js" ' +
        'log'
    );
  });

  it('quotes the bare-binary global-install form (no .js suffix)', () => {
    // When the binary itself is a self-contained executable (npm link
    // or some global installs), we skip the `node ${cliScript}` prefix
    // but still need to quote the binary path for the same reason.
    restoreProcess = stubProcess(
      '/usr/local/bin/node', // ignored on this branch
      '/usr/local/bin/node9' // ends without .js
    );
    expect(fullPathCommand('check', 'linux')).toBe('"/usr/local/bin/node9" check');
  });

  it('still emits the bare "node9 <sub>" form under NODE9_TESTING=1', () => {
    // Restore the env short-circuit and confirm we haven't changed test-mode behavior.
    vi.stubEnv('NODE9_TESTING', '1');
    expect(fullPathCommand('check')).toBe('node9 check');
    expect(fullPathCommand('log')).toBe('node9 log');
  });
});

describe('isStaleHookCommand', () => {
  let restoreFs: () => void = () => {};

  beforeEach(() => {
    const spy = vi.spyOn(fs, 'existsSync').mockReturnValue(false);
    restoreFs = () => spy.mockRestore();
  });

  afterEach(() => {
    restoreFs();
  });

  it('treats a quoted POSIX path that does not exist as stale', () => {
    // New quoted form must still get detected as stale when its files
    // are gone — the whole reason we have this helper is to repair
    // hooks left behind by an `npm uninstall`.
    expect(isStaleHookCommand('"/usr/bin/node" "/lib/node_modules/.../dist/cli.js" check')).toBe(
      true
    );
  });

  it('treats a quoted Windows-style path (C:/...) that does not exist as stale', () => {
    // Pre-fix `isStaleHookCommand` only treated `/`-prefixed tokens as
    // absolute, so on Windows the stale-detector never fired — a real
    // bug for any Windows user who uninstalled-then-reinstalled.
    expect(
      isStaleHookCommand('"C:/Program Files/nodejs/node.exe" "C:/Users/u/.../cli.js" check')
    ).toBe(true);
  });

  it('returns false for a bare "node9 check" command (resolved via PATH)', () => {
    expect(isStaleHookCommand('node9 check')).toBe(false);
  });

  it('returns false when every quoted path exists on disk', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    expect(isStaleHookCommand('"/usr/bin/node" "/lib/node_modules/.../dist/cli.js" check')).toBe(
      false
    );
  });
});

describe('isNode9Hook', () => {
  it('recognises the new quoted "cli.js check" form', () => {
    // The character immediately before `cli.js` is now `/` (forward
    // slash), so the existing `[\s/\\]` boundary class still matches —
    // but we want to be explicit and also tolerate a `"` boundary in
    // case the path itself doesn't contain a `/` separator before the
    // filename (e.g. a Windows root install at `C:/cli.js`).
    expect(isNode9Hook('"C:/Users/u/cli.js" check')).toBe(true);
    expect(isNode9Hook('"/usr/local/bin/cli.js" log')).toBe(true);
  });

  it('recognises the quoted bare-binary form (global install, post-#185)', () => {
    // Regression: fullPathCommand quotes the binary path for global installs
    // (`"/path/node9" check`), but isNode9Hook only matched the quoted cli.js
    // form — so freshly wired agy/copilot read back as "not wired" and setup
    // appended duplicate hooks on every re-run. The closing quote sits between
    // `node9` and the subcommand, which the old `node9 ` pattern missed.
    expect(
      isNode9Hook('"/home/u/.nvm/versions/node/v25.9.0/bin/node9" check --agent antigravity')
    ).toBe(true);
    expect(isNode9Hook('"/usr/local/bin/node9" log --agent copilot')).toBe(true);
    expect(isNode9Hook('"C:/Users/u/node9" check')).toBe(true);
  });

  it('still recognises the legacy unquoted form (backward compat)', () => {
    // Hooks already on disk in the old unquoted form must keep being
    // recognised as node9 hooks until the next self-heal rewrites them.
    expect(isNode9Hook('/usr/bin/node /path/cli.js check')).toBe(true);
    expect(isNode9Hook('/usr/local/bin/node9 check')).toBe(true); // unquoted bare
    expect(isNode9Hook('node9 check')).toBe(true);
    expect(isNode9Hook('node9 log')).toBe(true);
  });

  it('does not match unrelated commands', () => {
    expect(isNode9Hook('echo hi')).toBe(false);
    expect(isNode9Hook('echo node9 is cool')).toBe(false); // node9 not followed by check/log
    expect(isNode9Hook('mynode9 check')).toBe(false); // word-boundary
    expect(isNode9Hook('"/usr/bin/mynode9checker" check')).toBe(false); // substring guard
    expect(isNode9Hook(undefined)).toBe(false);
  });
});

describe('isLegacyHookFormat (#185 follow-up)', () => {
  it('flags any command containing a backslash', () => {
    // Pre-#185 unquoted Windows hook — the exact form reported in the bug.
    expect(
      isLegacyHookFormat('C:\\Program Files\\nodejs\\node.exe C:\\Users\\u\\...\\cli.js check')
    ).toBe(true);
    // Also a quoted-but-still-backslash form (some hand-edited configs).
    expect(isLegacyHookFormat('"C:\\path\\node.exe" "C:\\path\\cli.js" check')).toBe(true);
  });

  it('returns false for the new quoted forward-slash form (idempotence)', () => {
    // Once self-heal rewrites a hook, running init again must not retrigger
    // the rewrite or we'd churn settings.json on every invocation.
    expect(
      isLegacyHookFormat('"C:/Program Files/nodejs/node.exe" "C:/Users/u/.../cli.js" check')
    ).toBe(false);
  });

  it('returns false for the legacy unquoted POSIX form (no churn on working hooks)', () => {
    // POSIX users with pre-#185 hooks are still working — no backslashes
    // means no Git Bash break. We deliberately don't rewrite cosmetic
    // differences; only actual breakage.
    expect(isLegacyHookFormat('/usr/bin/node /lib/node_modules/.../cli.js check')).toBe(false);
    expect(isLegacyHookFormat('/usr/local/bin/node9 check')).toBe(false);
  });

  it('returns false for the bare "node9 check" form and empty input', () => {
    expect(isLegacyHookFormat('node9 check')).toBe(false);
    expect(isLegacyHookFormat('')).toBe(false);
  });
});

describe('needsRewrite (#185 follow-up)', () => {
  // needsRewrite ORs the two detection helpers. Spot-check that both
  // branches feed into the result; exhaustive coverage of the
  // underlying conditions lives in the isStaleHookCommand /
  // isLegacyHookFormat blocks above.
  it('returns true when the path is stale', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(false);
    expect(needsRewrite('"/missing/node" "/missing/cli.js" check')).toBe(true);
  });

  it('returns true when the shape is legacy (backslashes)', () => {
    // existsSync left at the test-file default; even if it returns true
    // for every path, the backslash branch should still fire.
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    expect(needsRewrite('C:\\path\\node C:\\path\\cli.js check')).toBe(true);
  });

  it('returns false for a well-formed hook whose paths exist', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    expect(needsRewrite('"/usr/bin/node" "/usr/lib/cli.js" check', 'linux')).toBe(false);
  });
});

describe('isWindowsQuoteBrokenHook (cmd quote-stripping self-heal)', () => {
  // The shape every Windows install carries after running #185-era code.
  const BROKEN =
    '"C:/Program Files/nodejs/node.exe" "C:/Users/u/AppData/Roaming/npm/.../cli.js" check';

  it('flags the #185-era Windows form even when every path still exists', () => {
    // This is the case the other two predicates miss, and the reason those
    // users stayed silently unenforced across upgrades: the files are all
    // present, and the forward-slash normalisation left no backslashes.
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    expect(isStaleHookCommand(BROKEN)).toBe(false);
    expect(isLegacyHookFormat(BROKEN)).toBe(false);
    expect(isWindowsQuoteBrokenHook(BROKEN, 'win32')).toBe(true);
    expect(needsRewrite(BROKEN, 'win32')).toBe(true);
  });

  it('leaves POSIX alone — a leading quote is correct there', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    const posix = '"/usr/bin/node" "/usr/lib/node_modules/node9-ai/dist/cli.js" check';
    expect(isWindowsQuoteBrokenHook(posix, 'linux')).toBe(false);
    expect(needsRewrite(posix, 'linux')).toBe(false);
    // Same string, Windows: still broken, because the rule is about cmd's
    // parser and not about the path it happens to contain.
    expect(isWindowsQuoteBrokenHook(posix, 'win32')).toBe(true);
  });

  it('does not flag the shapes fullPathCommand now emits on Windows', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    for (const cmd of ['node "C:/Users/u/dist/cli.js" check', 'node9 log']) {
      expect(isWindowsQuoteBrokenHook(cmd, 'win32')).toBe(false);
      expect(needsRewrite(cmd, 'win32')).toBe(false);
    }
  });

  it('handles leading whitespace and empty input', () => {
    expect(isWindowsQuoteBrokenHook('   "C:/x/node.exe" "C:/y/cli.js" check', 'win32')).toBe(true);
    expect(isWindowsQuoteBrokenHook('', 'win32')).toBe(false);
  });
});

describe('isNode9Hook recognises the post-fix Windows shapes', () => {
  // Wiring pin, not a helper test. If isNode9Hook stops matching what
  // fullPathCommand emits, setup reads a freshly wired install as "not
  // wired" and appends duplicate hooks on every re-run.
  it('matches the unquoted-node Windows form', () => {
    expect(isNode9Hook('node "C:/Users/u/dist/cli.js" check')).toBe(true);
    expect(isNode9Hook('node "C:/Users/u/dist/cli.js" log')).toBe(true);
    expect(isNode9Hook('node9 check --agent antigravity')).toBe(true);
  });
});

describe('Codex PreToolUse — a foreign hook must not be mistaken for coverage', () => {
  // Dogfound on Windows 2026-09-22: a leftover probe script owned the ^Bash$
  // matcher. `node9 agents remove codex` left it (correctly — it is not ours),
  // and `add` then skipped the matcher because an ENTRY existed, so Bash stayed
  // ungated while setup printed "hooks added" and doctor read the file as
  // wired. The predicate has to be "is node9 present", not "does a matcher
  // entry exist" — the same shape as the UserPromptSubmit/PostToolUse checks
  // a few lines below it in setup.ts.
  it('does not treat a non-node9 command as a node9 hook', () => {
    expect(isNode9Hook('C:\\Users\\u\\.codex\\probes\\probe-flat.cmd')).toBe(false);
    expect(isNode9Hook('some-other-tool --check')).toBe(false);
    expect(isNode9Hook(undefined)).toBe(false);
  });
});
