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
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
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
    name: 'powershell -Command',
    run: (cmd) =>
      spawnSync('powershell.exe', ['-NoProfile', '-Command', cmd], {
        input: '{"hook_event_name":"PreToolUse"}',
        windowsVerbatimArguments: true,
        encoding: 'utf-8',
      }).status,
  },
];

describe.skipIf(!isWindows)('hook command launches under every Windows shell', () => {
  beforeAll(() => {
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
    restore();
    if (dirWithSpace) fs.rmSync(dirWithSpace, { recursive: true, force: true });
  });

  for (const runner of RUNNERS) {
    it(`runs the emitted command under ${runner.name}`, () => {
      expect(runner.run(fullPathCommand('check', 'win32'))).toBe(0);
    });
  }

  it('confirms the pre-fix form still fails, so these tests still measure something', () => {
    const broken = `"${toForwardSlashes(process.execPath)}" "${toForwardSlashes(stubScript)}" check`;
    // cmd without /s is the form that breaks; /s is the documented escape and
    // is expected to keep working, which is exactly why it hid the bug.
    expect(RUNNERS[0].run(broken)).not.toBe(0);
    expect(RUNNERS[2].run(broken)).not.toBe(0);
  });
});
