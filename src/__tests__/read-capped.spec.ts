// readCapped replaces `statSync().size` guards that the file-system race
// defeats: the guard measures one file and the read takes whatever the path
// points at afterwards.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { readCapped, readCappedText } from '../utils/read-capped';

let dir: string;
const f = (name: string) => path.join(dir, name);

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-read-capped-'));
});
afterEach(() => {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
});

describe('readCapped', () => {
  it('returns the whole file when it fits', () => {
    fs.writeFileSync(f('a'), 'hello');
    const r = readCapped(f('a'), 100)!;
    expect(r.bytes.toString()).toBe('hello');
    expect(r.truncated).toBe(false);
  });

  it('treats a file exactly at the cap as complete', () => {
    fs.writeFileSync(f('a'), 'x'.repeat(64));
    const r = readCapped(f('a'), 64)!;
    expect(r.bytes.length).toBe(64);
    expect(r.truncated).toBe(false);
  });

  it('marks one byte over the cap as truncated', () => {
    fs.writeFileSync(f('a'), 'x'.repeat(65));
    const r = readCapped(f('a'), 64)!;
    expect(r.bytes.length).toBe(64);
    expect(r.truncated).toBe(true);
  });

  it('returns null for a missing path', () => {
    expect(readCapped(f('nope'), 64)).toBeNull();
  });

  it('returns null for a directory', () => {
    fs.mkdirSync(f('d'));
    expect(readCapped(f('d'), 64)).toBeNull();
  });

  it('handles an empty file', () => {
    fs.writeFileSync(f('a'), '');
    const r = readCapped(f('a'), 64)!;
    expect(r.bytes.length).toBe(0);
    expect(r.truncated).toBe(false);
  });

  it('returns exact bytes, not re-encoded text', () => {
    // skill-pin hashes these bytes; a utf8 round trip would corrupt them.
    const raw = Buffer.from([0x00, 0xff, 0xfe, 0x41, 0x80]);
    fs.writeFileSync(f('bin'), raw);
    expect(readCapped(f('bin'), 100)!.bytes.equals(raw)).toBe(true);
  });

  it('THE POINT: the cap holds when the file is swapped after a stat', () => {
    const p = f('swap');
    const CAP = 1024;

    // The shape being replaced: stat a small file, pass the guard...
    fs.writeFileSync(p, 'small');
    const stat = fs.statSync(p);
    expect(stat.size).toBeLessThan(CAP);

    // ...then the file is replaced before the read happens.
    fs.writeFileSync(p, 'x'.repeat(CAP * 64));

    // The old pattern reads the new file in full: the guard bought nothing.
    expect(fs.readFileSync(p, 'utf8').length).toBeGreaterThan(CAP);

    // readCapped enforces the cap at the read instead.
    const r = readCapped(p, CAP)!;
    expect(r.bytes.length).toBe(CAP);
    expect(r.truncated).toBe(true);
  });

  it('allocates by file size, not by the cap', () => {
    // skill-pin passes a budget up to 50 MB. Allocating that per file would be
    // absurd, so the size comes from fstat on the open descriptor.
    fs.writeFileSync(f('tiny'), 'hi');
    const before = process.memoryUsage().heapUsed;
    for (let i = 0; i < 200; i++) readCapped(f('tiny'), 50 * 1024 * 1024);
    const growthMb = (process.memoryUsage().heapUsed - before) / (1024 * 1024);
    expect(growthMb).toBeLessThan(50);
  });

  it('rejects a negative cap rather than allocating', () => {
    fs.writeFileSync(f('a'), 'hello');
    expect(readCapped(f('a'), -1)).toBeNull();
  });
});

describe('readCappedText', () => {
  it('decodes utf8 and carries truncated through', () => {
    fs.writeFileSync(f('a'), 'héllo');
    expect(readCappedText(f('a'), 100)!.text).toBe('héllo');
    fs.writeFileSync(f('b'), 'x'.repeat(10));
    expect(readCappedText(f('b'), 4)!.truncated).toBe(true);
  });

  it('returns null for a missing path', () => {
    expect(readCappedText(f('nope'), 10)).toBeNull();
  });
});
