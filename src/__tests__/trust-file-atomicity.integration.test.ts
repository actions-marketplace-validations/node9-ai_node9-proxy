// trust.json is written by two functions in src/auth/state.ts, and before this
// change they disagreed:
//
//   writeTrustSession      -> atomicWriteSync(TRUST_FILE, ...)   // even says
//                                                                // "ATOMIC write"
//   getActiveTrustSession  -> fs.writeFileSync(TRUST_FILE, ...)  // the expiry prune
//
// fs.writeFileSync truncates and then writes, so a concurrent reader can land
// on a partial file. In getActiveTrustSession the read is wrapped in a
// try/catch that returns false, so a torn read does not crash: it silently
// reports "no active trust session" for a session that has one. It fails
// closed, which is why this is a correctness bug and not a bypass, but losing a
// live trust session in the trust store is still worth fixing.
//
// This spawns real processes rather than simulating, because the failure only
// exists between processes. It is deliberately probabilistic on the pre-fix
// code (a torn read has to be observed) and deterministic after: zero torn
// reads is the assertion either way.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

let home: string;
const trustPath = () => path.join(home, '.node9', 'trust.json');

/** Big enough that a truncate-then-write is observably non-atomic. */
function seedTrustFile(entries: number): void {
  fs.mkdirSync(path.dirname(trustPath()), { recursive: true });
  const now = Date.now();
  const list = Array.from({ length: entries }, (_, i) => ({
    tool: `Tool${i}_${'p'.repeat(40)}`,
    // Half already expired, so every prune rewrites the file.
    expiry: i % 2 === 0 ? now - 1000 : now + 3_600_000,
  }));
  fs.writeFileSync(trustPath(), JSON.stringify({ entries: list }, null, 2));
}

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-trust-atomic-'));
});
afterEach(() => {
  try {
    fs.rmSync(home, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
});

describe('trust.json is written atomically by every writer', () => {
  it('a concurrent reader never sees a partial file while prunes run', () => {
    seedTrustFile(4000);
    const sizeBefore = fs.statSync(trustPath()).size;
    expect(sizeBefore).toBeGreaterThan(200_000); // large enough to tear

    // A child that hammers the prune path: read, drop expired, write.
    // The prune only writes when something actually expired, so the driver
    // re-seeds before every call. It re-seeds ATOMICALLY (tmp + rename) so the
    // only non-atomic write in the experiment is the one under test; otherwise
    // the probe would be measuring itself.
    const driver = path.join(home, 'driver.ts');
    fs.writeFileSync(
      driver,
      `import fs from 'fs';
       import { getActiveTrustSession } from ${JSON.stringify(path.resolve('src/auth/state.ts'))};
       const p = ${JSON.stringify(trustPath())};
       const seed = fs.readFileSync(p, 'utf-8');
       for (let i = 0; i < 3000; i++) {
         const tmp = p + '.seed' + i + '.tmp';
         fs.writeFileSync(tmp, seed);
         fs.renameSync(tmp, p);
         getActiveTrustSession('Bash');
       }
      `
    );

    const child = spawn(process.execPath, [require.resolve('tsx/cli'), driver], {
      env: { ...process.env, HOME: home, USERPROFILE: home },
      stdio: 'ignore',
    });

    // Meanwhile, read the file the way every consumer does.
    let torn = 0;
    let samples = 0;
    const deadline = Date.now() + 8000;
    let alive = true;
    child.on('exit', () => {
      alive = false;
    });
    while (alive && Date.now() < deadline) {
      samples++;
      try {
        const raw = fs.readFileSync(trustPath(), 'utf-8');
        const parsed = JSON.parse(raw) as { entries: unknown[] };
        if (!Array.isArray(parsed.entries)) torn++;
      } catch {
        // Exactly what getActiveTrustSession's own catch swallows in production.
        torn++;
      }
    }
    try {
      child.kill();
    } catch {
      /* already gone */
    }

    expect(samples).toBeGreaterThan(50); // the probe actually ran
    expect(torn).toBe(0);
  }, 30_000);
});
