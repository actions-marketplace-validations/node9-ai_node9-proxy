// The pipe-to-shell vocabulary exists in THREE places and they must not drift.
//
//   1. the engine's verb sets  (DOWNLOAD_CMDS, SHELL_INTERPRETERS — shell/index.ts)
//   2. DEFAULT_CONFIG's `review-curl-pipe-shell` regex  (src/config/index.ts)
//   3. bash-safe.json's `block-pipe-to-shell` regex     (engine builtin shield)
//
// (2) is what actually fires on a default install; (3) is the shield copy; (1)
// feeds the AST detectors. On 2026-09-22, (2) and (3) knew curl/wget and
// bash/sh/zsh/fish while an agent on Windows wrote `iwr ... | iex` — the same
// intent, three vocabularies, none of them told. This spec is the cheap
// substitute for unifying them: every downloader the engine knows must appear
// in both regexes' downloader group, and every interpreter the engine knows
// must appear in both regexes' sink group. Add a name in one place and this
// fails until it is in all three.
//
// It reads the regex SOURCE, not the compiled matcher, so it also fails if
// someone restructures a group in a way that drops a name.

import { describe, it, expect } from 'vitest';
import { DEFAULT_CONFIG } from '../config/index.js';
import bashSafe from '../../packages/policy-engine/src/shields/builtin/bash-safe.json';
import { DOWNLOAD_CMDS, SHELL_INTERPRETERS } from '../../packages/policy-engine/src/shell/index.js';

function ruleRegex(rules: unknown, name: string): string {
  const r = (rules as Array<{ name: string; conditions: Array<{ value?: string }> }>).find(
    (x) => x.name === name
  );
  if (!r) throw new Error(`rule ${name} not found`);
  return r.conditions[0].value ?? '';
}

// Alternation groups are pulled by anchoring on the names we KNOW are there
// (curl, bash), so the test does not have to understand the whole regex.
function groupContaining(src: string, anchor: string): string[] {
  const m = src.match(new RegExp(`\\(([^()]*\\b${anchor}\\b[^()]*)\\)`));
  if (!m) throw new Error(`no group containing ${anchor} in: ${src}`);
  return m[1]
    .replace(/^\?:/, '')
    .split('|')
    .map((s) => s.replace(/\\b|\?/g, '').trim())
    .filter(Boolean);
}

const DEFAULT_RULE = ruleRegex(DEFAULT_CONFIG.policy.smartRules, 'review-curl-pipe-shell');
const SHIELD_RULE = ruleRegex(bashSafe.smartRules, 'shield:bash-safe:block-pipe-to-shell');

describe('pipe-to-shell vocabulary: one list, not three', () => {
  it('every engine downloader appears in both regexes', () => {
    const d1 = groupContaining(DEFAULT_RULE, 'curl');
    const d2 = groupContaining(SHIELD_RULE, 'curl');
    for (const name of DOWNLOAD_CMDS) {
      expect(d1, `DEFAULT_CONFIG downloader group lacks ${name}`).toContain(name);
      expect(d2, `bash-safe downloader group lacks ${name}`).toContain(name);
    }
  });

  it('every engine interpreter appears in both regexes as a sink', () => {
    // DEFAULT_CONFIG spells the POSIX shells as `(ba|z|da|fi|c|k)?sh`, so only
    // the NON-POSIX interpreters (the PowerShell ones) can be checked by name
    // there; bash-safe lists shells explicitly and is checked in full.
    const s2 = groupContaining(SHIELD_RULE, 'bash');
    for (const name of SHELL_INTERPRETERS) {
      expect(s2, `bash-safe sink group lacks ${name}`).toContain(name);
    }
    for (const name of [...SHELL_INTERPRETERS].filter((n) => !/^(ba|z|da|fi|c|k)?sh$/.test(n))) {
      expect(DEFAULT_RULE, `DEFAULT_CONFIG sink lacks ${name}`).toMatch(
        new RegExp(`\\b${name}\\b`)
      );
    }
  });

  it('the engine sets themselves know the PowerShell spellings', () => {
    for (const name of ['iwr', 'irm', 'invoke-webrequest', 'invoke-restmethod']) {
      expect(DOWNLOAD_CMDS.has(name), name).toBe(true);
    }
    for (const name of ['iex', 'invoke-expression', 'powershell', 'pwsh']) {
      expect(SHELL_INTERPRETERS.has(name), name).toBe(true);
    }
  });
});
