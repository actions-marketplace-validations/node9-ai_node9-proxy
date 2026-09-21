// Integration: the daemon's credentials reader, through the built CLI.
// CLAUDE.md: behaviour that depends on HOME gets a spawnSync against
// dist/cli.js, not only an in-process import. `node9 policy sync` is the CLI
// entry to runCloudSync, which reads through daemon/sync.ts readCredentials.
//
// The observable that does not depend on the network: getCredentials logs
// `REFUSED apiUrl, using the default instead: <raw>` to hook-debug.log under
// the temp HOME exactly when the pin fires. The request itself then goes to
// the default host with a key that is not real (401), or fails to resolve
// offline; either way the hostile host must appear nowhere in the output.
//
// Measured by hand on 2026-09-20 before this test existed: on the parent the
// same run ended in `getaddrinfo ENOTFOUND evil.example.com`.
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { DEFAULT_API_URL } from '../auth/api-url';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const HOSTILE = 'https://evil.example.com/api/v1/intercept';

function runPolicySync(apiUrl: string) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-reader2-int-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  fs.writeFileSync(
    path.join(home, '.node9', 'credentials.json'),
    JSON.stringify({ default: { apiKey: 'nk_probe_not_a_real_key', apiUrl } })
  );
  const env: Record<string, string> = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    NODE9_TESTING: '1',
    NODE9_NO_AUTO_DAEMON: '1',
    NO_COLOR: '1',
    // Only the policy fetch; the piggyback pushes would each make a request.
    NODE9_BLAST_DISABLE: '1',
    NODE9_SCAN_DISABLE: '1',
    NODE9_POSTURE_DISABLE: '1',
    NODE9_POLICY_MIRROR_DISABLE: '1',
  };
  delete env.NODE9_API_KEY;
  delete env.NODE9_API_URL;
  delete env.NODE9_PROFILE;
  delete env.NODE9_API_HOST_ALLOW;

  const r = spawnSync(process.execPath, [CLI, 'policy', 'sync'], {
    encoding: 'utf-8',
    env,
    timeout: 30_000,
  });
  const logPath = path.join(home, '.node9', 'hook-debug.log');
  const log = fs.existsSync(logPath) ? fs.readFileSync(logPath, 'utf-8') : '';
  try {
    fs.rmSync(home, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
  return { r, log, out: `${r.stdout}${r.stderr}` };
}

describe('node9 policy sync reads credentials through the pin (integration)', () => {
  beforeAll(() => {
    expect(fs.existsSync(CLI), `built CLI missing at ${CLI} — run npm run build`).toBe(true);
  });

  it('KNOWN-TRUE: the real host produces no REFUSED line', () => {
    const { r, log } = runPolicySync(DEFAULT_API_URL);
    expect(r.error).toBeUndefined();
    expect(log).not.toContain('REFUSED apiUrl');
  });

  it('THE ROW: a hostile apiUrl is refused, logged, and never contacted', () => {
    const { r, log, out } = runPolicySync(HOSTILE);
    expect(r.error).toBeUndefined();
    // The fake key is refused by the real host (or the network is down);
    // either way the command fails, and the hostile host is not in the story.
    expect(r.status).not.toBe(0);
    expect(out).not.toContain('evil.example.com');
    expect(log).toContain('REFUSED apiUrl');
    expect(log).toContain('evil.example.com');
  });
});
