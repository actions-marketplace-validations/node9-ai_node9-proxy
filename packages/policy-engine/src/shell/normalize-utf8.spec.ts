import { describe, it, expect } from 'vitest';
import { normalizeCommandForPolicy, analyzeFsOperation } from './index';

// ─────────────────────────────────────────────────────────────────────────────
// JAIL-12: ONE NON-ASCII CHARACTER TURNED THE WHOLE JAIL OFF
//
// mvdan-sh reports node positions as BYTE offsets into the command's UTF-8
// encoding. `commandReadingsImpl` fed them to `String.prototype.slice`, which
// counts UTF-16 code units. For a pure-ASCII command the two agree, which is why
// this survived four stages. With one accented character earlier in the string
// every later offset is too large, the de-obfuscation rewrites splice at the
// wrong place, and the command the detectors see is corrupted text:
//
//   echo café && cat ~/.ssh/id_rsa
//     -> "echo café&& ccat//home/u/.ssh/id_rsa"   (before this fix)
//
// No rule matches that, so the credential read was ALLOW. Found by /code-review
// round 4 while reviewing the pattern slot; it is not a pattern-slot bug, it
// disables the jail for EVERY verb, and the same corruption reaches the rm and
// chmod detectors that share this normalizer.
// ─────────────────────────────────────────────────────────────────────────────

const K = '/home/u/.ssh/id_rsa';
const verdict = (c: string) => {
  const r = analyzeFsOperation(c);
  return r ? r.verdict : 'null';
};

describe('JAIL-12 — a non-ASCII character must not move the offsets', () => {
  it.each([
    ['two-byte, before the read', `echo café && cat ${K}`],
    ['two-byte, in the read itself', `grep é ${K}`],
    ['three-byte CJK', `echo 日本語 && cat ${K}`],
    ['four-byte emoji (a surrogate pair in JS)', `echo 🔑 && cat ${K}`],
    ['a Hebrew comment above the read', `echo שלום && cat ${K}`],
    ['accented directory name in the same command', `ls /home/u/café && cat ${K}`],
    ['non-ASCII inside a quoted message', `git commit -m "café" && cat ${K}`],
    ['many, mixed', `echo café 日本 🔑 && cat ${K}`],
  ])('%s', (_label, command) => {
    expect(verdict(command)).toBe('block');
  });

  it('controls: the same commands without the character already blocked', () => {
    expect(verdict(`echo cafe && cat ${K}`)).toBe('block');
    expect(verdict(`cat ${K}`)).toBe('block');
  });

  it('de-obfuscation still works when non-ASCII is present', () => {
    // The reason the offsets exist at all: `r''m` must normalize to `rm`.
    expect(normalizeCommandForPolicy(`echo café && r''m -rf /tmp/x`)).toContain('rm -rf');
    expect(normalizeCommandForPolicy(`r''m -rf /tmp/x`)).toContain('rm -rf');
  });

  it('the normalized text is not corrupted', () => {
    const out = normalizeCommandForPolicy(`echo café && cat ${K}`);
    expect(out).toContain(`cat ${K}`);
    expect(out).not.toContain('ccat');
  });

  it('and the pattern slot still works with non-ASCII present', () => {
    expect(verdict(`echo café && grep -n .env .gitignore`)).toBe('null');
    expect(verdict(`grep -n café ${K}`)).toBe('block');
  });
});
