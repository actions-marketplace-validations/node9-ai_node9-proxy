// Measurement harness for the canonical-extractor version bump that the
// verb-case fix requires. The repo's rule: a bump costs every daemon in the
// fleet a full re-scan, so the before/after table in canonical.ts is MEASURED
// through extractCanonicalFindings, never assumed from the gate's verdict.
// This file is that measurement, kept as a test so the claim stays true.
import { describe, it, expect } from 'vitest';
import { extractCanonicalFindings, type ToolCallEntry, type ExtractContext } from './canonical';

const baseCtx = (): ExtractContext => ({
  sessionId: 'sess-1',
  lineIndex: 0,
  project: 'proj-1',
  agent: 'claude',
  rules: [],
  toolInspection: { bash: 'command', execute_bash: 'command' },
  dlpEnabled: false,
});

const call = (command: string): ToolCallEntry => ({
  toolName: 'bash',
  args: { command },
  timestamp: '2026-09-22T10:00:00Z',
});

function astFinding(command: string) {
  return extractCanonicalFindings(call(command), baseCtx()).find((f) => f.type === 'ast-fs-op');
}

describe('canonical extractor sees capitalised reads (v15 → v16)', () => {
  // Emitted nothing at v15: the prescreen rejected the capitalised verb before
  // the AST ran, so these reads happened on real machines and produced no
  // finding at all. That is what makes the re-scan worth its cost.
  const NOW_DETECTED: Array<[string, string, string]> = [
    ['CAT .env', 'shield:project-jail:block-read-env', 'high'],
    ['Cat .env', 'shield:project-jail:block-read-env', 'high'],
    ['GREP -c . .env', 'shield:project-jail:block-read-env', 'high'],
    ['CAT ~/.aws/credentials', 'shield:project-jail:block-read-aws', 'critical'],
  ];

  for (const [command, ruleName, severity] of NOW_DETECTED) {
    it(`emits ast-fs-op for ${command}`, () => {
      const f = astFinding(command);
      expect(f, `${command} produced no ast-fs-op finding`).toBeDefined();
      expect(f!.ruleName).toBe(ruleName);
      expect(f!.verdict).toBe('block');
      expect(f!.severity).toBe(severity);
    });
  }

  it('leaves the lowercase controls exactly where they were', () => {
    expect(astFinding('cat .env')?.ruleName).toBe('shield:project-jail:block-read-env');
    expect(astFinding('cat ~/.aws/credentials')?.ruleName).toBe(
      'shield:project-jail:block-read-aws'
    );
  });

  it('sees PowerShell verbs now — mechanism A landed on top of the case fold', () => {
    // This row was written as a handoff: at v16 it asserted `toBeUndefined`,
    // because `Get-Content` was absent from FS_READ_TOOLS and no amount of
    // case folding could reach it. Folding had to land FIRST — PowerShell
    // verbs arrive capitalised and would not have matched a case-sensitive
    // set. The vocabulary landed next (v17) and the expectation inverted.
    const f = astFinding('Get-Content ~/.ssh/id_rsa');
    expect(f).toBeDefined();
    expect(f!.ruleName).toBe('shield:project-jail:block-read-ssh');
  });

  it('does not invent findings for ordinary capitalised words', () => {
    // The prescreen is case-insensitive now, so more strings reach the AST.
    // Reaching the parser must not mean producing a finding.
    expect(astFinding('git commit -m "Update CAT config"')).toBeUndefined();
    expect(astFinding('echo Hello')).toBeUndefined();
    expect(astFinding('npm run build')).toBeUndefined();
  });
});
