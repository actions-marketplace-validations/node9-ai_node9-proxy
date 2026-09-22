// The wrap node9 writes into an agent's config must be a command node9 can
// actually run.
//
// HOW THIS WAS FOUND. `setup.ts` wrote `['mcp', '--upstream', <cmd>]` at nine
// sites, but `node9 mcp` is a PARENT command (gateway | ungateway | status |
// pin) with no `--upstream` option. Every wrapped server died on startup with
// `error: unknown option '--upstream'`. node9 never noticed, because node9 is
// not what fails — the agent is. It surfaced only in Codex's own log, three
// days in.
//
// The damage exceeds lost governance: the wrap REPLACES the user's server
// command, so it broke the server it was meant to protect.
//
// ⚠️ setup.test.ts asserted the broken args as expected, at five call sites.
// String comparison cannot catch this class of bug, so the row below SPAWNS
// the generated argv and asserts the CLI accepts it.
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'child_process';
import path from 'path';
import { mcpWrapArgs, isMcpWrapSubcommand, repairLegacyMcpWraps } from '../setup.js';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

describe('the generated MCP wrap is a runnable command', () => {
  it('is accepted by the real CLI', () => {
    // --help rather than a live wrap: it exercises argument PARSING, which is
    // the thing that was broken, without starting a gateway or touching config.
    const args = mcpWrapArgs('npx -y some-mcp-server');
    const r = spawnSync(process.execPath, [CLI, args[0], '--help'], { encoding: 'utf-8' });
    expect(r.status, `${args[0]} --help exited ${r.status}`).toBe(0);
    expect(r.stdout).toContain('--upstream');
  });

  it('rejects the legacy subcommand, proving the row above measures something', () => {
    // The control. If `node9 mcp --upstream` ever starts working, this file has
    // stopped testing what it was written for.
    const r = spawnSync(process.execPath, [CLI, 'mcp', '--upstream', 'echo hi'], {
      encoding: 'utf-8',
    });
    expect(r.stderr + r.stdout).toContain("unknown option '--upstream'");
  });
});

describe('legacy wraps are recognised and repaired', () => {
  it('still reads a legacy wrap as ours', () => {
    // Teardown depends on this. If node9 stops recognising its own old output,
    // `agents remove` leaves the user with a dead server and no way to undo it.
    expect(isMcpWrapSubcommand('mcp')).toBe(true);
    expect(isMcpWrapSubcommand('mcp-gateway')).toBe(true);
    expect(isMcpWrapSubcommand('mcp-server')).toBe(false);
    expect(isMcpWrapSubcommand(undefined)).toBe(false);
  });

  it('rewrites a legacy wrap in place and preserves the upstream', () => {
    const servers: Record<string, { command?: string; args?: unknown }> = {
      broken: { command: 'node9', args: ['mcp', '--upstream', 'npx -y server-github'] },
      already: { command: 'node9', args: ['mcp-gateway', '--upstream', 'npx x'] },
      foreign: { command: 'other-tool', args: ['--serve'] },
      ours: { command: 'node9', args: ['mcp-server'] },
    };
    const repaired = repairLegacyMcpWraps(servers);

    expect(repaired).toEqual(['broken']);
    expect(servers.broken.args).toEqual(['mcp-gateway', '--upstream', 'npx -y server-github']);
    // Everything else untouched — a repair that rewrites more than the defect
    // is a new defect.
    expect(servers.already.args).toEqual(['mcp-gateway', '--upstream', 'npx x']);
    expect(servers.foreign.args).toEqual(['--serve']);
    expect(servers.ours.args).toEqual(['mcp-server']);
  });
});
