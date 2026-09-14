import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';

/**
 * Write a file so that no reader ever observes a partial one.
 *
 * `fs.writeFileSync` truncates and then writes, so a concurrent reader can land
 * between the two and get a torn file. Everything node9 keeps in ~/.node9 is
 * read by short-lived hook processes running alongside the writer, which is
 * exactly that situation: a torn `trust.json` parses as garbage and the reader's
 * catch reports "no active trust session" for a session that has one.
 *
 * The temp name carries a UUID rather than the pid, because two concurrent
 * writes inside one process share a pid and would otherwise collide on the same
 * temp path. The temp file is removed on either failure so a crash cannot
 * litter the directory.
 */
export function atomicWriteSync(
  filePath: string,
  data: string,
  options?: fs.WriteFileOptions
): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const tmpPath = `${filePath}.${randomUUID()}.tmp`;
  try {
    fs.writeFileSync(tmpPath, data, options);
  } catch (err) {
    try {
      fs.unlinkSync(tmpPath);
    } catch {
      /* best-effort: file may not have been created */
    }
    throw err;
  }
  try {
    fs.renameSync(tmpPath, filePath);
  } catch (err) {
    try {
      fs.unlinkSync(tmpPath);
    } catch {
      /* best-effort cleanup */
    }
    throw err;
  }
}
