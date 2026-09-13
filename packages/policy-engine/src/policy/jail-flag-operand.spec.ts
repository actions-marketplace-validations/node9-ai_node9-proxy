import { describe, it, expect } from 'vitest';
import { analyzeFsOperation } from '../shell/index';

// ─────────────────────────────────────────────────────────────────────────────
// JAIL-10: A JAILED PATH INSIDE A `--flag=value` TOKEN
//
// `positionedArgs` classifies any word starting with `-` as a flag, so the read
// tier never handed the value half of an `=`-joined token to matchSensitivePath.
// `grep -f KEY f.txt` blocked; `grep --file=KEY f.txt` was ALLOW -- the same
// read, one spelling apart.
//
// Every row below was verified under `strace -e openat` against a decoy file
// (2026-09-13) before it was written, because a row is only a bypass if the
// command ACTUALLY OPENS the file. Two candidates were refuted that way and are
// pinned as ALLOW at the bottom: `awk --file=` (mawk rejects the spelling) and
// `tail --follow=` (invalid argument). Neither opens anything.
//
// The fix is a per-verb table of flags whose operand IS A FILE THE VERB OPENS,
// resolved for every spelling (`-f K`, `--file K`, `--file=K`). It is NOT "judge
// every `=` value": measured, that blocks a search EXCLUDING .env, a regex
// naming .env, a sed script naming .aws, and a CI job writing a key into place.
// Design: doc/jail-stage5-pattern-slot-design.md 2.6.
// ─────────────────────────────────────────────────────────────────────────────

const K = '/home/u/.ssh/id_rsa';
const E = '/home/u/project/.env';
const v = (c: string) => {
  const r = analyzeFsOperation(c);
  return r ? r.verdict : 'null';
};

describe('JAIL-10 — the separated spelling, which already worked', () => {
  it.each([
    [`grep -f ${K} f.txt`],
    [`sed -f ${K} f.txt`],
    [`awk -f ${K} f.txt`],
    [`grep --file ${K} f.txt`],
  ])('%s', (c) => expect(v(c)).toBe('block'));
});

describe('JAIL-10 — the `=` spelling must reach the same verdict', () => {
  it.each([
    // strace: OPENED
    [`grep --file=${K} f.txt`],
    [`egrep --file=${K} f.txt`],
    [`fgrep --file=${K} f.txt`],
    [`grep --exclude-from=${K} -r x .`],
    [`grep --include=${K} -r x /home/u`],
    [`sed --file=${K} f.txt`],
    [`sort --files0-from=${K}`],
    // documented, not measurable on this machine (rg / gawk absent)
    [`rg --file=${K} src/`],
    [`rg --ignore-file=${K} src/`],
    // the same, for the .env rule rather than the .ssh rule
    [`grep --file=${E} f.txt`],
    // PLATFORM-DEPENDENT, and therefore judged. mawk (this machine) rejects the
    // `=` spelling and opens nothing; gawk documents `--file=PROGFILE` and does
    // open it. The gate cannot know which awk the user has, and a read gate
    // resolves that by judging, not by assuming the weaker binary.
    [`awk --file=${K} f.txt`],
    [`gawk --file=${K} f.txt`],
  ])('%s', (c) => expect(v(c)).toBe('block'));

  it('reached through a wrapper, like every other read', () => {
    expect(v(`sudo grep --file=${K} f.txt`)).toBe('block');
    expect(v(`env FOO=1 grep --file=${K} f.txt`)).toBe('block');
  });
});

describe('JAIL-10 — what must NOT be judged (measured: opens nothing)', () => {
  it.each([
    // a pattern or a script, not a file
    [`grep --regexp=${E} f.txt`],
    [`sed --expression=s/.aws/x/ f.txt`],
    // EXCLUDING a file from a search reads nothing
    [`grep --exclude=${E} -r x .`],
    [`grep --exclude=.env -r x .`],
    // a delimiter string that happens to be path-shaped
    [`cut --output-delimiter=${E} f.txt`],
    // refuted bypass candidate: GNU tail rejects a path as --follow's operand
    // (`--follow[=HOW]` takes name|descriptor), and tail has no file-operand
    // flag at all. Measured: opens nothing.
    [`tail --follow=${K}`],
  ])('%s', (c) => expect(v(c)).toBe('null'));

  it('a WRITE into the jail stays allowed: the CI key-install case', () => {
    // Corpus rows 10 to 12 install a deploy key. `--output=` is a write, and the
    // read tier must not claim it.
    expect(v(`sort --output=${K} /tmp/newkey`)).toBe('null');
  });

  it('an ordinary flag value is untouched', () => {
    expect(v(`grep --color=always foo f.txt`)).toBe('null');
    expect(v(`grep -A 3 foo f.txt`)).toBe('null');
  });
});

describe('JAIL-10 — controls that must not move', () => {
  it.each([
    [`cat ${K}`, 'block'],
    [`dd if=${K}`, 'block'],
    [`cat ${E}`, 'block'],
    [`cat /home/u/project/.env.example`, 'null'],
  ])('%s -> %s', (c, want) => expect(v(c)).toBe(want));
});
