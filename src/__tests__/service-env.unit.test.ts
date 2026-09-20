// The daemon service units carry the environment the daemon needs, because
// launchd/systemd/the Windows startup script do not inherit the installing
// shell. Found in review 2026-09-20: the apiUrl pin (auth/api-url) had just
// been extended into the daemon, its only self-hosted escape hatch is the
// NODE9_API_HOST_ALLOW env var, and no unit carried it, so a self-hosted
// operator's daemon would have rejected its own host and shipped the device
// key to api.node9.ai on every tick while their hooks kept working.
import { describe, it, expect, afterEach, vi } from 'vitest';
import { daemonServiceEnv, systemdUnit, launchdPlist, windowsLauncherVbs } from '../daemon/service';

const NODE = 'C:\\Program Files\\nodejs\\node.exe';
const CLI = 'C:\\Users\\x\\node_modules\\node9\\dist\\cli.js';

describe('daemonServiceEnv', () => {
  afterEach(() => vi.unstubAllEnvs());

  it('always carries the autostart marker', () => {
    vi.stubEnv('NODE9_API_HOST_ALLOW', '');
    expect(daemonServiceEnv()).toEqual({ NODE9_AUTO_STARTED: '1' });
  });

  it('carries NODE9_API_HOST_ALLOW when the installing shell has it', () => {
    vi.stubEnv('NODE9_API_HOST_ALLOW', 'corp.example, *.other.test');
    expect(daemonServiceEnv().NODE9_API_HOST_ALLOW).toBe('corp.example, *.other.test');
  });

  it('drops a value that is not a suffix list rather than writing it into a unit', () => {
    // A quote or a newline is a VBS string break / a plist injection; a
    // hostname never contains either.
    for (const bad of ['corp.example"; rm -rf /', 'a.b\nEnvironment=X=1', '<x>', '']) {
      vi.stubEnv('NODE9_API_HOST_ALLOW', bad);
      expect(daemonServiceEnv(), JSON.stringify(bad)).not.toHaveProperty('NODE9_API_HOST_ALLOW');
    }
  });
});

describe('every launcher renders the same environment', () => {
  afterEach(() => vi.unstubAllEnvs());

  it('systemd', () => {
    vi.stubEnv('NODE9_API_HOST_ALLOW', 'corp.example');
    const unit = systemdUnit('/opt/node9/dist/cli.js');
    expect(unit).toContain('Environment="NODE9_AUTO_STARTED=1"');
    expect(unit).toContain('Environment="NODE9_API_HOST_ALLOW=corp.example"');
  });

  it('launchd', () => {
    vi.stubEnv('NODE9_API_HOST_ALLOW', 'corp.example');
    const plist = launchdPlist('/opt/node9/dist/cli.js');
    expect(plist).toContain('<key>NODE9_AUTO_STARTED</key>');
    expect(plist).toContain('<key>NODE9_API_HOST_ALLOW</key>');
    expect(plist).toContain('<string>corp.example</string>');
  });

  it('windows', () => {
    vi.stubEnv('NODE9_API_HOST_ALLOW', 'corp.example');
    const vbs = windowsLauncherVbs(NODE, CLI);
    expect(vbs).toContain('sh.Environment("PROCESS")("NODE9_AUTO_STARTED") = "1"');
    expect(vbs).toContain('sh.Environment("PROCESS")("NODE9_API_HOST_ALLOW") = "corp.example"');
  });

  it('without the variable, every launcher is exactly as before', () => {
    vi.stubEnv('NODE9_API_HOST_ALLOW', '');
    expect(systemdUnit('/x')).not.toContain('NODE9_API_HOST_ALLOW');
    expect(launchdPlist('/x')).not.toContain('NODE9_API_HOST_ALLOW');
    expect(windowsLauncherVbs(NODE, CLI)).not.toContain('NODE9_API_HOST_ALLOW');
  });
});
