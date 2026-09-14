// redactArgs builds the `args` object that goes into every audit entry. It is
// the last thing between a tool call and the permanent record, so a key that
// silently fails to land there is an audit gap, not a cosmetic bug.
//
// CodeQL js/remote-property-injection flagged the assignment; the exploitable
// reading (prototype pollution) does not hold, because the value is per-object
// and JSON.stringify ignores the prototype. What does hold is the inverse: an
// argument literally named `__proto__` invokes the inherited setter instead of
// creating an own property, so it never reaches the log at all.
import { describe, it, expect } from 'vitest';
import { redactArgs } from '../daemon/state';

/**
 * Build args the way the real caller does. The daemon parses them out of the
 * request body (`readBody` then JSON.parse), and only JSON.parse gives
 * `__proto__` as an OWN property — in an object literal it is prototype
 * syntax and no such key exists, so a literal cannot reproduce this at all.
 */
function argsFromWire(json: string): unknown {
  return JSON.parse(json);
}

/** What the audit log actually stores: the entry after a JSON round-trip. */
function asLogged(args: unknown): Record<string, unknown> {
  return JSON.parse(JSON.stringify(redactArgs(args))) as Record<string, unknown>;
}

describe('redactArgs', () => {
  it('redacts secret-shaped keys and keeps the rest', () => {
    const logged = asLogged({ command: 'curl example.com', apiKey: 'sk-live-1234' });
    expect(logged.command).toBe('curl example.com');
    expect(logged.apiKey).toBe('[REDACTED]');
  });

  it('recurses into nested objects and arrays', () => {
    const logged = asLogged({ outer: { password: 'hunter2', keep: 1 }, list: [{ token: 't' }] });
    expect((logged.outer as Record<string, unknown>).password).toBe('[REDACTED]');
    expect((logged.outer as Record<string, unknown>).keep).toBe(1);
    expect((logged.list as Array<Record<string, unknown>>)[0].token).toBe('[REDACTED]');
  });

  it('records an argument named __proto__ instead of swallowing it', () => {
    const logged = asLogged(argsFromWire('{"__proto__":"payload","command":"ls"}'));
    expect(Object.keys(logged)).toContain('__proto__');
    expect(logged.command).toBe('ls');
  });

  it('still redacts secrets nested under a __proto__ argument', () => {
    const logged = asLogged(
      argsFromWire('{"constructor":"x","__proto__":{"authToken":"sk-live"}}')
    );
    expect(Object.keys(logged)).toEqual(expect.arrayContaining(['__proto__', 'constructor']));
    expect((logged.__proto__ as Record<string, unknown>).authToken).toBe('[REDACTED]');
  });

  it('does not let an argument key change the prototype of the redacted copy', () => {
    const redacted = redactArgs(argsFromWire('{"__proto__":{"polluted":true}}')) as object;
    expect(Object.getPrototypeOf(redacted)).toBeNull();
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('passes non-objects through untouched', () => {
    expect(redactArgs('plain')).toBe('plain');
    expect(redactArgs(null)).toBeNull();
    expect(redactArgs(42)).toBe(42);
  });
});
