import { describe, it, expect } from 'vitest';
import { analyzeFsOperation } from '../shell/index';

// ─────────────────────────────────────────────────────────────────────────────
// STAGE 6, STEP 4: A BRANCH THAT STOPS EARLY, find's -exec ACTION (JAIL-11)
//
// Stage 2 taught both tiers that `find DIR -exec cat {} +` reads DIR: the find
// branch judges find's START POINTS and looks at the reader after `-exec`. It
// never judged the action's OWN literal words, so a credential named there was
// invisible, and JAIL-10's `=` table was not wired into that branch either:
//
//   find ~/.ssh -type f -exec cat {} +      block     (the start point)
//   find . -exec cat ~/.ssh/id_rsa \;       ALLOW     measured on 2.20.0
//   find . -exec grep --file=KEY {} +       ALLOW
//
// The action is `words[k+1 .. end)`, where `end` is the first `;` or `+`, with
// `{}` removed. It goes through the SAME machinery an ordinary command gets:
// unwrap the head, `readTargets` plus `flagOperandFiles` for a reader,
// `copySourcePaths` for a copy verb, combined with the start points by
// strictness. Judging an action word the tool does not open is the same false
// positive the pattern slot already handles, with the same helpers.
// Design: doc/jail-stage6-open-gaps-design.md, 3.5.
// ─────────────────────────────────────────────────────────────────────────────

const K = '/home/u/.ssh/id_rsa';
const D = '/home/u/.ssh';
const v = (c: string) => {
  const r = analyzeFsOperation(c);
  return r ? r.verdict : 'null';
};

describe('JAIL-11 — controls: the start-point path, closed by stage 2', () => {
  it.each([
    [`find ${D} -type f -exec cat {} +`, 'block'],
    [`find ${D} -exec cp {} /tmp/out \\;`, 'review'],
    [`find . -name '*.log' -exec rm {} +`, 'null'],
    [`find . -exec cat {} +`, 'null'],
  ])('%s -> %s', (c, want) => expect(v(c)).toBe(want));
});

describe("JAIL-11 — the action's own words are judged", () => {
  it.each([
    [`find . -exec cat ${K} \\;`, 'block'],
    [`find . -exec cat ${K} +`, 'block'],
    [`find . -execdir cat ${K} \\;`, 'block'],
    [`find . -exec grep --file=${K} {} +`, 'block'],
    [`find . -exec grep -f ${K} {} +`, 'block'],
    [`find . -exec sudo cat ${K} \\;`, 'block'],
    [`find . -exec cp ${K} /tmp/k \\;`, 'review'],
    [`find . -exec tar czf /tmp/s.tgz ${D} \\;`, 'review'],
    // the action ends at `;`, so a predicate after it is find's, not the action's
    [`find . -exec cat ${K} \\; -print`, 'block'],
  ])('%s -> %s', (c, want) => expect(v(c)).toBe(want));
});

describe('JAIL-11 — what the action judgement must NOT do', () => {
  it.each([
    // an install INTO the jail is the copy tier's own exemption
    [`find /tmp/keys -name '*.pub' -exec cp {} ${D}/ \\;`, 'null'],
    // the pattern slot still works inside an action
    [`find docs -name '*.md' -exec grep -n .env {} +`, 'null'],
    [`find . -exec grep -rn ${D}/config {} +`, 'null'],
    // `{}` is not a path
    [`find . -type f -exec cat {} \\;`, 'null'],
    // an ordinary action naming nothing jailed
    [`find . -name '*.tmp' -exec rm -f {} +`, 'null'],
  ])('%s -> %s', (c, want) => expect(v(c)).toBe(want));
});
