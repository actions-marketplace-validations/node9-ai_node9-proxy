import { describe, it, expect } from 'vitest';
import {
  analyzeFsOperation,
  PATTERN_VERB_NAMES,
  patternShapeOf,
  fileOperandFlagsOf,
} from '../shell/index';

// ─────────────────────────────────────────────────────────────────────────────
// STAGE 5a: THE SEARCH-PATTERN SLOT
//
// `grep -n .env .gitignore` was a hard block. So were `rg "\.env\.local"` and
// `grep -rn ".ssh/config" docs/`. None of them reads a credential: each hands
// the jail name to a reader as its search PATTERN, and the read tier judged
// every positional word of a reader as a path.
//
// A word is excused by its SLOT, never by its SHAPE. The two rows at the bottom
// of this file are the proof: the same string `<HOME>/.ssh/config` is excused in
// the pattern slot and blocked one slot over.
//
// Four verbs only. `ag`/`ack` are absent because neither is installed on the
// measuring machine and no table could be earned; `sed`/`awk` are absent because
// their program slot can read a file from inside itself (awk getline, sed `r`),
// which the prototype run showed turns an exfil-corpus row into a bypass.
// Design: doc/jail-stage5-pattern-slot-design.md.
// ─────────────────────────────────────────────────────────────────────────────

const K = '/home/u/.ssh/id_rsa';
const D = '/home/u/.ssh';
const E = '/home/u/project/.env';
const v = (c: string) => {
  const r = analyzeFsOperation(c);
  return r ? r.verdict : 'null';
};

// ── 1. Controls. Green before this stage and after it. ───────────────────────
describe('stage 5a — controls: a jailed file in a FILE slot still blocks', () => {
  it.each([
    [`grep -n foo ${K}`],
    [`grep -r TODO ${D}`],
    [`grep -e foo ${K}`],
    [`rg foo /home/u/.aws/credentials`],
    [`grep foo < ${K}`],
    [`sudo grep foo ${K}`],
    [`grep -f ${K} f.txt`],
    [`cat ${E}`],
    [`grep TODO ${E}`],
    [`grep -rn TODO ${D}`],
  ])('%s', (c) => expect(v(c)).toBe('block'));
});

// ── 2. The false positives this stage exists to remove. RED before. ──────────
describe('stage 5a — a search pattern is not a path', () => {
  it.each([
    [`grep -n ".env" .gitignore`],
    [`grep -n '.env' .gitignore`],
    [`rg "\\.env\\.local"`],
    [`rg \\.env\\.local`],
    [`rg .env src/`],
    [`grep -e .env f.txt`],
    [`rg -e .env src/`],
    [`grep -rn ".ssh/config" docs/`],
    [`grep -rn "~/.ssh/config" docs/`],
    [`grep -A 3 .env f.txt`],
    [`rg -g "*.ts" .env src/`],
    [`rg --files-with-matches ".env" .`],
    [`grep -rn ".aws/credentials" docs/`],
  ])('%s', (c) => expect(v(c)).toBe('null'));

  it('the bare token and the rooted spelling are both excused in the slot', () => {
    expect(v(`grep -r .ssh /home/u/p`)).toBe('null');
    expect(v(`rg ${D} src/`)).toBe('null');
  });
});

// ── 3. Every value-taking flag gets a control row, DERIVED from the table. ───
// A flag wrongly listed as value-taking swallows the pattern and excuses the
// FILE. This block is the guard against that, and it grows by itself when a flag
// is added to the table.
describe('stage 5a — a value flag must not swallow the pattern', () => {
  const rows: Array<[string, string]> = [];
  for (const verb of PATTERN_VERB_NAMES) {
    const shape = patternShapeOf(verb)!;
    for (const flag of shape.takesValue) {
      // A pattern flag's operand IS the pattern, and a no-pattern flag means
      // there is none: both are exercised in block 5, not here.
      if (shape.patternFlags.has(flag) || shape.noPatternFlags.has(flag)) continue;
      rows.push([verb, flag]);
    }
  }
  it('the table yields control rows', () => expect(rows.length).toBeGreaterThan(40));
  it.each(rows)('%s %s v foo <jailed> blocks', (verb, flag) => {
    expect(v(`${verb} ${flag} v foo ${K}`)).toBe('block');
  });
});

// ── 4. A switch NOT in the table must not swallow anything. ──────────────────
describe('stage 5a — a switch flag consumes nothing', () => {
  it.each([
    [`grep -n foo ${K}`],
    [`grep -i foo ${K}`],
    [`grep -rl foo ${D}`],
    // `--color` consumes NOTHING (optional argument), so `never` is the pattern
    // and everything after it is a FILE: grep really does open the key here.
    [`grep --color never foo ${K}`],
    [`grep --colour never foo ${K}`],
    [`grep --color never .env f.txt`],
    [`rg -i foo ${K}`],
    [`rg --json foo ${K}`],
    [`rg -l foo ${D}`],
  ])('%s', (c) => expect(v(c)).toBe('block'));
});

// ── 5. Pattern flags and no-pattern flags. ───────────────────────────────────
describe('stage 5a — the pattern can arrive by flag', () => {
  it('a pattern flag operand is excused, and the positional is judged', () => {
    expect(v(`grep -e .env f.txt`)).toBe('null');
    expect(v(`grep -e foo ${K}`)).toBe('block');
    expect(v(`grep --regexp .env f.txt`)).toBe('null');
    expect(v(`grep --regexp foo ${K}`)).toBe('block');
  });

  it('a no-pattern flag means every positional is a FILE', () => {
    expect(v(`grep -f patterns.txt ${K}`)).toBe('block');
    expect(v(`grep -f ${K} f.txt`)).toBe('block');
    // Founder decision 2026-09-13: --files stays BLOCKED on a jailed directory.
    expect(v(`rg --files ${D}`)).toBe('block');
    expect(v(`rg --type-list ${D}`)).toBe('block');
  });
});

// ── 6. The bypass surfaces: bundles and the `=` form. ────────────────────────
// Each of these looks like "the positional is the pattern" to a naive test and
// is in fact a FILE the verb opens.
describe('stage 5a — bundled and `=` spellings must not excuse a file', () => {
  it('a bundled no-pattern flag: -f inside -rnf', () => {
    expect(v(`grep -rnf ${K} f.txt`)).toBe('block');
  });

  it('a pattern flag NOT last in the bundle takes its value from the token', () => {
    // getopt reads `n` as -e's pattern, so KEY is a FILE.
    expect(v(`grep -en ${K}`)).toBe('block');
  });

  it('the pattern arrived inside an `=` token, so the positional is a FILE', () => {
    expect(v(`grep --regexp=foo ${K}`)).toBe('block');
    expect(v(`rg --file=patterns.txt ${K}`)).toBe('block');
  });

  it('a bundled pattern flag that IS last still excuses its operand', () => {
    expect(v(`grep -rne .env f.txt`)).toBe('null');
  });
});

// ── 6b. /code-review round 1 (2026-09-13): three BLOCK -> ALLOW regressions. ─
// Each was measured on the real binary with `strace -e openat` before the row
// was written, and each was a regression introduced by the first cut of this
// stage, not a pre-existing gap.
describe('stage 5a — a long flag ABBREVIATION still resolves', () => {
  // getopt_long accepts any unambiguous PREFIX, so `--regex` IS `--regexp`: the
  // pattern arrives by flag and the positional is a FILE. Exact-name matching
  // missed it and excused the key. Measured: GNU grep opens the key.
  it.each([
    [`grep --regex=foo ${K}`],
    [`grep --rege=foo ${K}`],
    [`grep --reg=foo ${K}`],
    [`rg --regex=foo ${K}`],
    // the separated spelling of a value flag: its operand is still judged
    [`grep --exclude-f ${K} -r x sub`],
    [`grep --exclude-fr ${K} -r x sub`],
  ])('%s', (c) => expect(v(c)).toBe('block'));

  it('and an abbreviation of a no-pattern flag means every positional is a FILE', () => {
    expect(v(`grep --fil patterns.txt ${K}`)).toBe('block');
    expect(v(`rg --file patterns.txt ${K}`)).toBe('block');
  });
});

describe('stage 5a — an OPTIONAL-argument flag consumes nothing', () => {
  // `--group-separator` was listed as value-taking on GNU grep's evidence. In
  // ugrep 7.8.4 -- which is what `grep` resolves to in some shells -- its
  // argument is OPTIONAL, so it eats nothing and the next word is the pattern.
  // Measured: `grep -H --group-separator SECRETLINE KEY` printed the key's line.
  // The engine cannot know which binary is installed, so it must not assume the
  // spelling that excuses a file. Same resolution as `awk --file=`: judge.
  it.each([
    [`grep -H --group-separator SECRET ${K}`],
    [`grep -r --group-separator x ${D}`],
    [`grep --group-separator x ${K}`],
  ])('%s', (c) => expect(v(c)).toBe('block'));
});

// ── 6c. What a value flag's OPERAND is, DERIVED from the two tables. ────────
// Round 1 added this block asserting that a value flag's operand is always
// JUDGED. That was wrong, and it is the reason round 2 found the headline false
// positive fixed in only one of its two spellings: `grep --exclude=.env -r x .`
// ran while `grep --exclude .env -r x .` blocked. A value flag's operand is its
// ARGUMENT -- a count, an action, a label, an exclusion glob, the pattern -- and
// is never opened, EXCEPT for the flags whose operand is a file the verb reads.
// That split is exactly FILE_OPERAND_FLAGS, so both halves are derived from the
// shipped tables and cannot drift from them.
describe("stage 5a — a value flag's operand: file or argument", () => {
  const argRows: Array<[string, string]> = [];
  const fileRows: Array<[string, string]> = [];
  for (const verb of PATTERN_VERB_NAMES) {
    const shape = patternShapeOf(verb)!;
    const fileFlags = fileOperandFlagsOf(verb);
    for (const flag of shape.takesValue) {
      (fileFlags?.has(flag) ? fileRows : argRows).push([verb, flag]);
    }
  }

  it('both halves are populated', () => {
    expect(argRows.length).toBeGreaterThan(40);
    expect(fileRows.length).toBeGreaterThan(3);
  });

  // An ARGUMENT operand reads nothing, so a jailed-looking one is excused.
  it.each(argRows)('%s %s <jailed> foo runs', (verb, flag) => {
    expect(v(`${verb} ${flag} ${K} foo`)).toBe('null');
  });

  // A FILE operand is opened, so it is judged wherever it sits.
  it.each(fileRows)('%s %s <jailed> foo blocks', (verb, flag) => {
    expect(v(`${verb} ${flag} ${K} foo`)).toBe('block');
  });

  // And the guard that matters either way: the FILE slot is never excused.
  it.each([...argRows, ...fileRows])('%s %s v foo <jailed> blocks', (verb, flag) => {
    expect(v(`${verb} ${flag} v foo ${K}`)).toBe('block');
  });
});

// ── 6d. /code-review round 3: four more BLOCK -> ALLOW shapes. ──────────────
describe('stage 5a — a lone dash is not a flag', () => {
  // `positionedArgs` calls `-` a flag; every one of these tools takes it as the
  // PATTERN, so the word after it is a FILE. Measured: `grep - KEY` printed the
  // key. UNKNOWN is the honest state, and it excuses nothing.
  it.each([
    [`grep - ${K}`],
    [`rg - ${K}`],
    [`egrep - ${K}`],
    [`sudo grep - ${K}`],
    [`grep -H - ${K}`],
  ])('%s', (c) => expect(v(c)).toBe('block'));
});

describe('stage 5a — a DYNAMIC pattern hides which slot is the pattern', () => {
  // A dynamic word occupies no slot (stage 3), so the FILE became the first
  // positional and was excused. The pattern may BE the dynamic word, so once one
  // appears ahead of a candidate nothing is excused.
  it.each([
    [`grep "$PAT" ${K}`],
    [`grep "$(cat patterns.txt)" ${K}`],
    [`rg "$PAT" ${K}`],
    [`sudo grep "$P" ${K}`],
  ])('%s', (c) => expect(v(c)).toBe('block'));

  it('a dynamic word AFTER the pattern is harmless and still excuses', () => {
    expect(v(`grep .env "$FILE"`)).toBe('null');
    expect(v(`grep -n .env "$FILE"`)).toBe('null');
  });
});

describe('stage 5a — an UNKNOWN `=` flag is not a free pass', () => {
  // An `=` token carries its own value, so it consumes nothing -- but only if we
  // recognise it. `grep --config=KEY` opens the key on ugrep and echoes its first
  // line back in an error; `--include-from=` and `--ignore-files=` have no
  // separated spelling to fall back on.
  it.each([
    [`grep --config=${K} needle`],
    [`grep --include-from=${K} needle n.txt`],
    [`grep --ignore-files=${K} needle n.txt`],
  ])('%s', (c) => expect(v(c)).toBe('block'));

  it('a RECOGNISED `=` flag stays quiet', () => {
    expect(v(`grep --color=always ${E} f.txt`)).toBe('null');
    expect(v(`grep --label=${E} foo f.txt`)).toBe('null');
    expect(v(`grep --exclude=${E} -r x .`)).toBe('null');
    // A verb with no option table keeps its old behaviour, which is what leaves
    // `sort --output=KEY` -- a WRITE, the CI key-install case -- alone.
    expect(v(`sort --output=${K} /tmp/newkey`)).toBe('null');
  });
});

describe("stage 5a — ripgrep's glob flags name files it OPENS", () => {
  // `-g/--glob/--iglob` decide which files rg SEARCHES, so an operand naming a
  // credential makes rg read it, exactly like grep's --include. Measured:
  // `rg --hidden -g .env AWS tree` printed the file's contents.
  it.each([[`rg --hidden -g .env AWS tree`], [`rg --glob ${E} AWS tree`], [`rg -g ${K} AWS .`]])(
    '%s',
    (c) => expect(v(c)).toBe('block')
  );

  it('and an ordinary glob is still excused', () => {
    expect(v(`rg -g "*.ts" .env src/`)).toBe('null');
  });
});

describe('stage 5a — an attached operand is not a bundle of flags', () => {
  // `-tconfig` is `-t config`, not a bundle containing `-f`. Reading every letter
  // found the `f` in `config` and blocked an ordinary typed search.
  it.each([
    [`rg -tconfig .env src/`],
    [`rg -treact .env src/`],
    [`rg -tvue .env src/`],
    [`rg -t config .env src/`],
  ])('%s', (c) => expect(v(c)).toBe('null'));
});

// ── 7. Reached through a wrapper: the same table. ────────────────────────────
describe('stage 5a — the wrapped read sees the same slots', () => {
  it.each([
    [`sudo grep .env f.txt`, 'null'],
    [`env FOO=1 grep -A 3 .env f.txt`, 'null'],
    [`sudo grep foo ${K}`, 'block'],
    [`env FOO=1 grep foo ${K}`, 'block'],
  ])('%s -> %s', (c, want) => expect(v(c)).toBe(want));
});

// ── 8. stdin, and the one row founder decision 2 settled. ───────────────────
describe('stage 5a — a reader with no file operand', () => {
  it('searches stdin for the string, so the word is the pattern', () => {
    // Founder decision 2026-09-13: accepted. The two ways stdin could BE the
    // key are owned by tiers that run before this branch, asserted next.
    expect(v(`grep ${K}`)).toBe('null');
  });

  it('and the two stdin routes still block', () => {
    expect(v(`grep x < ${K}`)).toBe('block');
    expect(v(`cat ${K} | grep x`)).toBe('block');
  });
});

// ── 9. Slot, not shape. The whole stage in two rows. ────────────────────────
describe('stage 5a — the same string, one slot apart', () => {
  it('excused in the pattern slot, blocked in the file slot', () => {
    expect(v(`grep -rn ${D}/config docs/`)).toBe('null');
    expect(v(`grep -rn foo ${D}/config`)).toBe('block');
  });
});
