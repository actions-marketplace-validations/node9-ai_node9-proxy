/**
 * Executes the hook command that fullPathCommand emits, through the shells
 * Windows agents actually use. Windows-only; skipped elsewhere.
 *
 * This file exists because the string-comparison suite could not have caught
 * the bug it guards. fullPathCommand used to emit two quoted paths:
 *
 *   "C:/Program Files/nodejs/node.exe" "C:/.../cli.js" check
 *
 * which begins with a quote and contains four. Per the documented `cmd /?`
 * rules, quotes are preserved only when there are EXACTLY TWO; otherwise cmd
 * strips the leading quote and the last quote, and the remainder splits on the
 * space inside `Program Files`. cmd then tries to execute `C:/Program` and
 * exits 1. Codex Desktop discards a failed hook without surfacing anything, so
 * the result was no enforcement and no audit rows — on every Windows machine,
 * for every agent, silently.
 *
 * `cmd /s` never showed the bug (it only strips when the string also ENDS in a
 * quote), and neither does Node's own `shell: true`, which shells out via
 * `cmd.exe /d /s /c`. Both are why this went unnoticed. The tests below drive
 * cmd WITHOUT /s on purpose, with windowsVerbatimArguments so Node does not
 * re-quote the string on the way in.
 *
 * The broken form is asserted to FAIL. That assertion is the instrument's own
 * calibration: if it ever starts passing, these tests have stopped measuring
 * the thing they were written for.
 */
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fullPathCommand } from '../setup.js';

const isWindows = process.platform === 'win32';

// A directory with a space in its name reproduces `C:\Program Files` without
// depending on where Node happens to be installed on the runner.
let dirWithSpace = '';
let stubScript = '';
let restore: () => void = () => {};

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

function toForwardSlashes(p: string): string {
  return p.replace(/\\/g, '/');
}

// Each runner form, invoked the way an agent harness spawns a hook: the whole
// command as one verbatim string, with a JSON payload on stdin.
const RUNNERS: Array<{ name: string; run: (cmd: string) => number | null }> = [
  {
    name: 'cmd /d /c',
    run: (cmd) =>
      spawnSync('cmd.exe', ['/d', '/c', cmd], {
        input: '{"hook_event_name":"PreToolUse"}',
        windowsVerbatimArguments: true,
        encoding: 'utf-8',
      }).status,
  },
  {
    name: 'cmd /d /s /c',
    run: (cmd) =>
      spawnSync('cmd.exe', ['/d', '/s', '/c', `"${cmd}"`], {
        input: '{"hook_event_name":"PreToolUse"}',
        windowsVerbatimArguments: true,
        encoding: 'utf-8',
      }).status,
  },
  {
    // powershell.exe -Command is parsed TWICE: the Windows command-line
    // parser builds powershell's own argv first and consumes the quotes, then
    // powershell rejoins the remaining tokens with spaces. An unescaped
    // `node "C:/x y/cli.js" check` therefore reaches powershell as
    // `node C:/x y/cli.js check` and dies on the space — a property of how a
    // caller invokes powershell, not of the command being invoked. Escaping
    // the quotes is that caller's job, and is what the CLI docs prescribe.
    name: 'powershell -Command',
    run: (cmd) =>
      spawnSync('powershell.exe', ['-NoProfile', '-Command', cmd.replace(/"/g, '\\"')], {
        input: '{"hook_event_name":"PreToolUse"}',
        windowsVerbatimArguments: true,
        encoding: 'utf-8',
      }).status,
  },
];

describe.skipIf(!isWindows)('hook command launches under every Windows shell', () => {
  beforeAll(() => {
    // vitest.config.mts pins env.NODE9_TESTING = '1', which makes
    // fullPathCommand short-circuit to a bare `node9 <sub>` that is not
    // installed on a CI runner. Without clearing it this file measures nothing
    // but "node9 is not on PATH" — which is how its first run failed. The
    // config has no unstubEnvs, so a beforeAll stub holds for the whole file.
    vi.stubEnv('NODE9_TESTING', '');
    dirWithSpace = fs.mkdtempSync(path.join(os.tmpdir(), 'node9 hook '));
    stubScript = path.join(dirWithSpace, 'cli.js');
    // Stands in for cli.js: drains stdin and exits 0. The question under test
    // is whether the shell can LAUNCH the command, not what node9 decides.
    fs.writeFileSync(
      stubScript,
      'process.stdin.resume();process.stdin.on("end",()=>process.exit(0));\n'
    );
    restore = stubProcess(process.execPath, stubScript);
  });

  afterAll(() => {
    vi.unstubAllEnvs();
    restore();
    if (dirWithSpace) fs.rmSync(dirWithSpace, { recursive: true, force: true });
  });

  for (const runner of RUNNERS) {
    it(`runs the emitted command under ${runner.name}`, () => {
      expect(runner.run(fullPathCommand('check', 'win32'))).toBe(0);
    });
  }

  it('emits a command that does not begin with a quote', () => {
    // The property the runners above depend on, asserted directly so a failure
    // says which half broke: the shape, or its execution.
    expect(fullPathCommand('check', 'win32').startsWith('"')).toBe(false);
  });

  it('confirms the pre-fix form still fails, so these tests still measure something', () => {
    // Two quoted paths, which is what fullPathCommand used to emit. cmd's
    // rule-2 stripping removes the leading quote and the last one, leaving a
    // stray quote welded onto the first token; whether the runner's own node
    // path contains a space only changes which token ends up mangled.
    const broken = `"${toForwardSlashes(process.execPath)}" "${toForwardSlashes(stubScript)}" check`;
    // /s is the documented escape from rule 2 and keeps working — which is
    // exactly why Node's own `shell: true` never surfaced the bug. Only the
    // cmd /d /c runner is asserted: powershell fails this form too, but by a
    // different route (a leading quoted string is a string literal there, not
    // a command), and pinning a second mechanism to the same assertion would
    // make a future failure ambiguous.
    expect(RUNNERS[0].run(broken)).not.toBe(0);
  });
});
