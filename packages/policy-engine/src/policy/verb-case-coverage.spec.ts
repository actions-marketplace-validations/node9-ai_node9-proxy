// Verb matching must not depend on how the agent capitalised the command.
//
// HOW THIS WAS FOUND. Dogfooding node9 on Windows, 2026-09-22. `cat .env`
// blocks; `CAT .env` and `Cat .env` are allowed, and so is `GREP -c . .env`.
// The cause is `FS_OP_PRESCREEN_RE`, built with `new RegExp(pattern)` and no
// `i` flag: a capitalised verb fails the fast path, `analyzeFsOperation`
// returns null, and the AST tier never runs. The membership tests downstream
// are inconsistent too — some call `.toLowerCase()` on the head, some do not.
//
// ⚠️ On Linux this is mostly inert: `CAT` is not an executable. On macOS and
// Windows it is a live bypass, because both default to case-insensitive
// filesystems, so `CAT ~/.aws/credentials` resolves and runs. PowerShell is
// case-insensitive by language, which is why this had to be fixed BEFORE
// adding PowerShell verbs to the set: those verbs arrive capitalised
// (`Get-Content`), so adding them to a case-sensitive matcher would have
// produced a diff that looks complete and changes nothing — the exact failure
// `env-reader-coverage.spec.ts` already warns about for the prescreen.
//
// Rows assert at `evaluatePolicy`, the layer that actually gates.

import { describe, it, expect } from 'vitest';
import { evaluatePolicy, type PolicyConfig } from './index';
import projectJail from '../shields/builtin/project-jail.json';
import type { SmartRule } from '../types';

const config: PolicyConfig = {
  policy: {
    sandboxPaths: [],
    dangerousWords: [],
    ignoredTools: [],
    smartRules: projectJail.smartRules as SmartRule[],
    toolInspection: { bash: 'command', shell: 'command', run_shell_command: 'command' },
    dlp: { enabled: false, scanIgnoredTools: false },
  },
  settings: { mode: 'standard' },
} as unknown as PolicyConfig;

async function G(command: string): Promise<string> {
  const v = await evaluatePolicy(config, 'Bash', { command }, { agent: 'claude' }, {});
  return String(v.decision);
}

// One working read command per verb. Kept small and concrete rather than
// derived from FS_READ_TOOLS, because the verbs do not share an argument shape
// (`dd` needs `if=`, `awk` needs a program). The point being pinned is the
// CASING rule, which does not vary per verb — breadth over the set is
// env-reader-coverage.spec.ts's job.
const READS: Array<[string, string]> = [
  ['cat', 'cat .env'],
  ['head', 'head .env'],
  ['tail', 'tail .env'],
  ['more', 'more .env'],
  ['grep', 'grep -c . .env'],
  ['strings', 'strings .env'],
  ['base64', 'base64 .env'],
  ['sort', 'sort .env'],
  ['nl', 'nl .env'],
];

function upperVerb(command: string): string {
  const [head, ...rest] = command.split(' ');
  return [head.toUpperCase(), ...rest].join(' ');
}

function capitaliseVerb(command: string): string {
  const [head, ...rest] = command.split(' ');
  return [head.charAt(0).toUpperCase() + head.slice(1), ...rest].join(' ');
}

describe('reader verbs are matched without regard to case', () => {
  it('blocks the lowercase form — the control for the two rows below', async () => {
    for (const [verb, command] of READS) {
      expect(await G(command), `${verb} lowercase`).toBe('block');
    }
  });

  it('blocks the ALL-CAPS form', async () => {
    for (const [verb, command] of READS) {
      expect(await G(upperVerb(command)), `${verb} upper`).toBe('block');
    }
  });

  it('blocks the Capitalised form', async () => {
    for (const [verb, command] of READS) {
      expect(await G(capitaliseVerb(command)), `${verb} capitalised`).toBe('block');
    }
  });

  it('still blocks a capitalised read of a credential path, not just .env', async () => {
    // The .env rows above all ride one rule. This one proves the folding is in
    // the verb matcher and not in a single rule's own pattern.
    expect(await G('cat ~/.aws/credentials')).toBe('block');
    expect(await G('CAT ~/.aws/credentials')).toBe('block');
    expect(await G('Cat ~/.ssh/id_rsa')).toBe('block');
  });

  it('folds the PATH too — which was already true before this change', async () => {
    // Measured, not assumed: `cat .ENV` already blocked while `CAT .env` did
    // not, so path matching was case-insensitive and only the VERB was not.
    // Keep it that way. On macOS and Windows `.ENV` genuinely IS `.env`, so
    // folding is the safe reading; on a case-sensitive filesystem it is an
    // over-block on a file the user probably does not have. That trade was
    // already made and this row exists so a future refactor cannot undo it by
    // accident.
    expect(await G('cat .ENV')).toBe('block');
  });
});
