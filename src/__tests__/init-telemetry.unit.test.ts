import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { buildTelemetryPayload } from '../cli/commands/init.js';
import { node9Version } from '../setup.js';
import os from 'os';
import { getMachineId } from '../machine-id.js';

describe('init telemetry payload', () => {
  // Prior bug: telemetry sent `node9_version: 'unknown'` for every global
  // install because `process.env.npm_package_version` is only populated by
  // npm-script invocations. Fix replaces that read with `node9Version()`,
  // which reads the shipped package.json relative to the CLI binary.
  describe('node9_version', () => {
    it('returns a real version string, not the literal "unknown"', () => {
      expect(node9Version()).not.toBe('unknown');
    });

    it('matches the version field in the shipped package.json', () => {
      const pkg = JSON.parse(
        fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf-8')
      ) as { version: string };
      expect(node9Version()).toBe(pkg.version);
    });

    it('matches semver shape (X.Y.Z optional prerelease)', () => {
      expect(node9Version()).toMatch(/^\d+\.\d+\.\d+(-[\w.]+)?$/);
    });
  });

  describe('buildTelemetryPayload', () => {
    it('returns the expected event name', () => {
      expect(buildTelemetryPayload([], true).event).toBe('init_completed');
    });

    it('includes detected agents verbatim', () => {
      expect(buildTelemetryPayload(['claude', 'gemini'], true).agents_detected).toEqual([
        'claude',
        'gemini',
      ]);
    });

    it('uses process.platform for os', () => {
      expect(buildTelemetryPayload([], true).os).toBe(process.platform);
    });

    it('resolves node9_version via node9Version() (no env-var fallback)', () => {
      // Regression: if someone reintroduces process.env.npm_package_version,
      // this assertion catches the regression because the env var is
      // undefined when running tests via `npm test` (vitest is the active
      // script, not the package).
      expect(buildTelemetryPayload([], true).node9_version).toBe(node9Version());
      expect(buildTelemetryPayload([], true).node9_version).not.toBe('unknown');
    });

    it('threads first_install through to the payload', () => {
      expect(buildTelemetryPayload([], true).first_install).toBe(true);
      expect(buildTelemetryPayload([], false).first_install).toBe(false);
    });
  });
});

// The durable machine id, carried on the install ping.
//
// Without it the ping has no identity at all, so `first_install` has to guess
// from `!fs.existsSync(configPath)` and the server can only ever count init
// RUNS. Sending the same UUID the machine already keeps for login is what lets
// the server count MACHINES, and lets an install later be recognised as the
// same machine that logged in.
//
// It is the id that already exists in ~/.node9/machine-id, not a second one:
// a separate telemetry id would be another thing to keep in step, and a random
// UUID is no more private than the one already on disk.
describe('machine_id on the install ping', () => {
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

  it('carries a uuid', () => {
    expect(buildTelemetryPayload([], true).machine_id).toMatch(UUID_RE);
  });

  // The point of the whole change: run init twice, count one machine.
  it('is stable across builds, so a re-run is the same machine', () => {
    expect(buildTelemetryPayload([], true).machine_id).toBe(
      buildTelemetryPayload(['claude'], false).machine_id
    );
  });

  // It must be the id login already uses. If these ever diverge, an install
  // and its later login stop being joinable, which is the reason for the field.
  it('is the same id login binds the machine by', () => {
    expect(buildTelemetryPayload([], true).machine_id).toBe(getMachineId());
  });

  // Not derived from anything about the machine. A hostname-based id would be
  // PII-adjacent and would collide; this one says nothing by itself.
  it('is not derived from the hostname or the user', () => {
    const id = buildTelemetryPayload([], true).machine_id;
    expect(id).not.toContain(os.hostname());
    expect(id).not.toContain(os.userInfo().username);
  });
});
