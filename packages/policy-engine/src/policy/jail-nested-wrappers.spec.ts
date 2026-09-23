import { describe, it, expect } from 'vitest';
import { analyzeFsOperation } from '../shell/index';

// ─────────────────────────────────────────────────────────────────────────────
// STAGE 6, STEP 2: A BRANCH THAT STOPS EARLY, ONE LEVEL OF eval (JAIL-1)
//
// Stage 2 taught the engine to re-parse a string-wrapped command once:
// `eval "cat KEY"`, `sh -c "cat KEY"`, `sudo sh -c "cat KEY"` all block. The
// recursion was guarded by `depth < 1`, so exactly one wrapper was seen and a
// second was invisible:
//
//   eval "cat KEY"                     block
//   eval "eval \"cat KEY\""            ALLOW     measured on 2.20.0
//   sh -c "sh -c \"cat KEY\""          ALLOW
//
// The bound was arbitrary; nobody measured two levels. It becomes three, which
// covers every shape in the exfil corpus and `sudo sh -c "bash -c '...'"`, and
// it STAYS a bound: the parse cache is keyed on the normalised string, and a
// pathological nesting must not become a parse loop. The fourth level is
// recorded below with its verdict stated, not hidden.
//
// Direction of a mistake: more reach, never less. Nothing that blocks today can
// stop blocking. Design: doc/jail-stage6-open-gaps-design.md, 3.4.
// ─────────────────────────────────────────────────────────────────────────────

const K = '/home/u/.ssh/id_rsa';
const v = (c: string) => {
  const r = analyzeFsOperation(c);
  return r ? r.verdict : 'null';
};

describe('JAIL-1 — controls: one level, closed by stage 2', () => {
  it.each([
    [`eval "cat ${K}"`],
    [`sh -c "cat ${K}"`],
    [`bash -lc "cat ${K}"`],
    [`sudo sh -c "cat ${K}"`],
  ])('%s', (c) => expect(v(c)).toBe('block'));
});

describe('JAIL-1 — two and three levels reach the read', () => {
  it.each([
    [`eval "eval \\"cat ${K}\\""`],
    [`sh -c "sh -c \\"cat ${K}\\""`],
    [`bash -c "eval \\"cat ${K}\\""`],
    [`sudo sh -c "bash -c \\"cat ${K}\\""`],
    [`eval "sh -c \\"eval \\\\\\"cat ${K}\\\\\\"\\""`],
  ])('%s', (c) => expect(v(c)).toBe('block'));

  it('a copy two levels down is still a review', () => {
    expect(v(`sh -c "sh -c \\"cp ${K} /tmp/k\\""`)).toBe('review');
  });
});

describe('JAIL-1 — the bound is stated, not hidden', () => {
  it('a fourth level is the accepted limit of this stage', () => {
    // Four wrappers deep. Recorded as the bound: if a later stage raises it, this
    // row is the one that flips, and the reason is written here rather than
    // discovered by a reviewer.
    const four = `eval "eval \\"eval \\\\\\"eval \\\\\\\\\\\\\\"cat ${K}\\\\\\\\\\\\\\"\\\\\\"\\""`;
    expect(['block', 'null']).toContain(v(four));
  });

  it('a dynamic payload is still left to the evalDynamic knob', () => {
    expect(v(`eval "$CMD"`)).toBe('null');
    expect(v(`eval "eval \\"$CMD\\""`)).toBe('null');
  });
});
