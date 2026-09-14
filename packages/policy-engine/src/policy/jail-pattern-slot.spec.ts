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

// ── 3. The DISCRIMINATING derived guard, over noValue. ──────────────────────
// A flag that consumes NOTHING leaves the next word as the pattern and the one
// after it as a FILE, so `VERB FLAG foo <jailed>` must BLOCK. If such a flag is
// ever moved into `takesValue` by mistake, `foo` is swallowed, the credential
// becomes the pattern slot and is EXCUSED, and this row goes red.
//
// That property is the point. /code-review round 4 proved by mutation that the
// previous guard (`VERB FLAG v foo <jailed>`, three positionals) blocks under
// BOTH arity models -- for takesValue, noValue, unknown and even a non-existent
// flag -- so it described the rule without constraining it: moving grep's `-b`
// into takesValue kept all four jail specs green while `grep -b foo ~/.ssh/id_rsa`
// flipped to allow and the real binary printed from the key. This block is red in
// exactly that case.
describe('stage 5a — a no-value flag leaves the FILE judged (mutation guard)', () => {
  const rows: Array<[string, string]> = [];
  for (const verb of PATTERN_VERB_NAMES) {
    const shape = patternShapeOf(verb)!;
    for (const flag of shape.noValue) {
      if (shape.patternFlags.has(flag) || shape.noPatternFlags.has(flag)) continue;
      rows.push([verb, flag]);
    }
  }
  it('the table yields control rows', () => expect(rows.length).toBeGreaterThan(150));
  it.each(rows)('%s %s foo <jailed> blocks', (verb, flag) => {
    expect(v(`${verb} ${flag} foo ${K}`)).toBe('block');
  });

  // And the same shape one word longer, which holds whatever the arity is: the
  // FILE slot is never excused.
  it.each(rows)('%s %s v foo <jailed> blocks', (verb, flag) => {
    expect(v(`${verb} ${flag} v foo ${K}`)).toBe('block');
  });
});

// ── 3b. An INDEPENDENT witness, hand-written on purpose. ────────────────────
// The derived block above cannot catch a flag MOVED between the two sets,
// because moving it also moves its test row: mutation-tested 2026-09-13, `-b`
// relocated from noValue to takesValue, `grep -b foo KEY` flipped to allow, and
// every derived row stayed green. A test generated from the thing under test is
// a description, not a constraint.
//
// So these rows are typed out, once, from the installed binaries' own --help.
// They are the flags an engineer actually types, each asserting the property that
// matters: the flag consumes nothing, so the word after it is the pattern and the
// credential after THAT is still a FILE. Any of them moved into `takesValue` turns
// this block red.
describe('stage 5a — no-value flags, pinned INDEPENDENTLY of the table', () => {
  const GREP_NO_VALUE = [
    '-i',
    '-v',
    '-n',
    '-c',
    '-l',
    '-L',
    '-o',
    '-q',
    '-s',
    '-b',
    '-H',
    '-h',
    '-w',
    '-x',
    '-r',
    '-R',
    '-a',
    '-I',
    '-E',
    '-F',
    '-G',
    '-P',
    '-T',
    '-z',
    '-Z',
    '-U',
    '--ignore-case',
    '--invert-match',
    '--line-number',
    '--count',
    '--recursive',
    '--byte-offset',
    '--with-filename',
    '--no-filename',
    '--word-regexp',
    '--only-matching',
    '--quiet',
    '--text',
    '--binary',
    '--color',
    '--colour',
    '--extended-regexp',
    '--fixed-strings',
    '--perl-regexp',
    '--line-buffered',
  ];
  const RG_NO_VALUE = [
    '-i',
    '-v',
    '-n',
    '-N',
    '-c',
    '-l',
    '-L',
    '-o',
    '-p',
    '-q',
    '-s',
    '-S',
    '-u',
    '-U',
    '-w',
    '-x',
    '-z',
    '-a',
    '-b',
    '-F',
    '-P',
    '-H',
    '-h',
    '-I',
    '-0',
    '-.',
    '--ignore-case',
    '--invert-match',
    '--line-number',
    '--no-line-number',
    '--count',
    '--count-matches',
    '--hidden',
    '--no-ignore',
    '--follow',
    '--multiline',
    '--pcre2',
    '--fixed-strings',
    '--pretty',
    '--column',
    '--vimgrep',
    '--json',
    '--stats',
    '--trim',
    '--sort-files',
    '--unrestricted',
    '--search-zip',
    '--smart-case',
    '--heading',
    '--no-heading',
    '--trace',
  ];

  it.each(GREP_NO_VALUE)('grep %s foo <jailed> blocks', (flag) => {
    expect(v(`grep ${flag} foo ${K}`)).toBe('block');
  });
  it.each(RG_NO_VALUE)('rg %s foo <jailed> blocks', (flag) => {
    expect(v(`rg ${flag} foo ${K}`)).toBe('block');
  });

  // The other half of the same witness: these flags DO consume a word, so the
  // credential two words later is the FILE and must block, and the flag's own
  // operand is its argument and must not be mistaken for one.
  it.each([
    [`grep -A 3 foo ${K}`],
    [`grep -m 1 foo ${K}`],
    [`grep --label x foo ${K}`],
    [`rg -A 3 foo ${K}`],
    [`rg --max-count 1 foo ${K}`],
    [`rg -t ts foo ${K}`],
  ])('%s blocks', (c) => expect(v(c)).toBe('block'));
});

// ── 3c. The tables' CONTENT, so an edit is a conscious act. ─────────────────
// Same idea as CANONICAL_EXTRACTOR_HASH: a change to either set must be typed
// here too, so a silent relocation cannot land.
//
// Sizes alone are not enough, mutation-proved twice. /code-review round 4 moved
// `-b` out of noValue (caught by size). Round 5 SWAPPED `--label` into noValue and
// `--initial-tab` into takesValue, which leaves both sizes identical: 1887 tests
// stayed green while `grep --initial-tab pat ~/.ssh/id_rsa` flipped to allow, and
// the real `-T` takes no argument. So the pin hashes the sorted CONTENTS.
describe('stage 5a — the flag tables are pinned by content', () => {
  const digest = (set: Set<string>): string => {
    let h = 0;
    for (const f of [...set].sort()) for (const ch of f) h = (h * 31 + ch.charCodeAt(0)) | 0;
    return `${set.size}:${(h >>> 0).toString(16)}`;
  };

  // Update these ONLY together with a measurement on the real binary, and say in
  // the commit which flag moved and what the binary did.
  it.each([
    ['grep', 'takesValue', '22:d09f79f5'],
    ['grep', 'noValue', '62:d48d145d'],
    ['rg', 'takesValue', '50:afafdf9b'],
    ['rg', 'noValue', '140:6fb8c373'],
  ])('%s %s', (verb, which, want) => {
    const shape = patternShapeOf(verb)!;
    expect(digest(which === 'takesValue' ? shape.takesValue : shape.noValue)).toBe(want);
  });

  it('the two sets never overlap', () => {
    for (const verb of PATTERN_VERB_NAMES) {
      const shape = patternShapeOf(verb)!;
      for (const f of shape.takesValue)
        expect(shape.noValue.has(f), `${verb} ${f} is in BOTH sets`).toBe(false);
    }
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
describe('stage 5a — `--` ends the options', () => {
  // After `--` the next word is the PATTERN whatever it looks like, and the rest
  // are FILES. `positionedArgs` does not honour it, so a dash-looking pattern
  // occupied no slot and the credential slid into slot 0: `grep -v -- -zzzz KEY`
  // printed the whole key and read allow (/code-review round 4).
  it.each([
    [`grep -v -- -zzzz ${K}`, 'block'],
    [`grep -rv -- -zzzz ${D}`, 'block'],
    [`rg -v -- -zzzz ${K}`, 'block'],
    [`egrep -v -- -zzzz ${K}`, 'block'],
    [`sudo grep -v -- -zzzz ${K}`, 'block'],
    [`grep -- -f ${K}`, 'block'],
    // the ordinary use of `--`, which must still be excused
    [`grep -- .env f.txt`, 'null'],
    [`grep -rn -- .env docs/`, 'null'],
  ])('%s -> %s', (c, want) => expect(v(c)).toBe(want));
});

describe('stage 5a — `--` after the pattern names a FILE', () => {
  // /code-review round 5. The first `--` fix excused the word after `--`
  // unconditionally, so when the pattern was ALREADY given as an earlier
  // positional the excused word was the file: `grep TODO -- KEY` printed the key.
  // The slot walk now resolves the pattern position the way the tool's own parser
  // does, left to right, which covers both orders with one rule.
  it.each([
    [`grep TODO -- ${K}`, 'block'],
    [`egrep TODO -- ${K}`, 'block'],
    [`rg TODO -- ${K}`, 'block'],
    [`sudo grep TODO -- ${K}`, 'block'],
    [`grep -n TODO -- ${K}`, 'block'],
    [`grep -v -- -zzzz ${K}`, 'block'],
    [`grep -- .env f.txt`, 'null'],
    [`grep -rn -- .env docs/`, 'null'],
  ])('%s -> %s', (c, want) => expect(v(c)).toBe(want));
});

describe('stage 5a — the rg table is complete from `rg --help`', () => {
  // Round 5 found 40 documented switches in neither set, so ordinary searches read
  // as UNKNOWN and kept blocking. These are the negated forms an engineer types.
  it.each([
    [`rg --no-heading .env src/`],
    [`rg --no-heading -n .env src/`],
    [`rg --ignore-vcs .env src/`],
    [`rg --no-ignore-parent .env src/`],
    [`rg --unicode .env src/`],
    [`rg --passthrough .env src/`],
    [`rg --messages .env src/`],
  ])('%s', (c) => expect(v(c)).toBe('null'));
});

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

// ── 6e. /code-review round 6: the UNKNOWN abort had no row of its own. ──────
// Mutation-proved: neutering the abort left all 1995 tests green while round 2's
// measured ugrep bypass came back. These rows are the abort's own witness, in the
// SEPARATED spelling, which is the one the walk decides.
describe('stage 5a — an unknown flag before the pattern excuses nothing', () => {
  it.each([
    [`grep --include-from ${K} needle notes.txt`],
    [`grep --ignore-files ${K} needle notes.txt`],
    [`grep --from ${K} needle notes.txt`],
    [`grep --match ${K} notes.txt`],
    [`grep --group-separator ${K} needle`],
    [`rg --no-such-flag ${K} needle`],
    [`sudo grep --from ${K} needle notes.txt`],
  ])('%s', (c) => expect(v(c)).toBe('block'));

  it('and an unknown flag AFTER the pattern does not suppress it', () => {
    // The pattern is resolved left to right, so a flag past it is irrelevant.
    expect(v(`grep -n .env --some-unknown-flag`)).toBe('null');
  });

  it('an `=` token consumes nothing, recognised or not', () => {
    // It cannot take the next word in getopt_long or clap, so the walk continues
    // and the VALUE is judged separately.
    expect(v(`grep --group-separator=--- -A1 .env notes.md`)).toBe('null');
    expect(v(`grep --config=${K} needle`)).toBe('block');
  });
});

// ── 6f. /code-review round 7: five arms that changed behaviour with no row. ─
// Each was found by MUTATION -- neutering the arm left the whole suite green while
// a measured bypass returned. A guard with no witness is a guard that can be
// deleted by the next person reading the file.
describe('stage 5a — the arms that had no witness', () => {
  it('a lone dash: BOTH guards are load-bearing', () => {
    // `positionedArgs` calls `-` a flag and flagEffect has two arms that stop it
    // becoming a no-value flag. Dropping either alone changed nothing; dropping
    // both flipped this row, which is round 3's measured key-printing bypass.
    expect(v(`grep - ${K}`)).toBe('block');
    expect(v(`grep -- - ${K}`)).toBe('block');
    expect(v(`grep -v - ${K}`)).toBe('block');
    expect(v(`rg - ${K}`)).toBe('block');
  });

  it('an UNKNOWN SHORT flag aborts the excuse, like an unknown long one', () => {
    // The long-flag arm got its row in round 6; the short arm had none.
    expect(v(`grep -X ${K} needle`)).toBe('block');
    expect(v(`grep -rX ${K} needle`)).toBe('block');
    expect(v(`rg -Q ${K} needle`)).toBe('block');
  });

  it('an AMBIGUOUS abbreviation is unknown, not a coin toss', () => {
    // `--co` prefixes --color, --count and --context: one takes a value and the
    // others do not, so slots cannot be counted past it. (GNU grep rejects the
    // ambiguity outright, so this costs nothing real.)
    expect(v(`grep --co ${K} needle`)).toBe('block');
  });
});

// ── 6g. /code-review round 8: `--` in the flag-operand EXCUSAL loops. ───────
// Round 5 taught the pattern WALK that `--` ends the options and left these loops
// behind, so the word after a post-`--` flag-looking word was excused as that
// flag's operand. GNU grep opens and prints from the file.
describe('stage 5a — `--` ends the options for the excusal loops too', () => {
  it.each([
    [`grep -- -m ${K}`],
    [`grep -- -A ${K}`],
    [`rg -- --maxdepth ${K}`],
    [`grep -- -e ${K}`],
  ])('%s', (c) => expect(v(c)).toBe('block'));

  it('and a flag BEFORE `--` still excuses its operand', () => {
    expect(v(`grep -m 2 -- .env f.txt`)).toBe('null');
    expect(v(`grep -A 3 .env f.txt`)).toBe('null');
  });

  it('a reader with no PatternShape knows its own value letters', () => {
    // `-v` owns the rest of `-vfile=...`, so there is no `-f` operand to judge.
    expect(v(`awk -vfile=/home/u/.ssh/config 'BEGIN{}'`)).toBe('null');
    expect(v(`awk -f${K} f.txt`)).toBe('block');
    expect(v(`sed -f${K} f.txt`)).toBe('block');
  });
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
