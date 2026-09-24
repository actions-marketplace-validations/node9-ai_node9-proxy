#!/usr/bin/env node
// A stand-in for `codex app-server`, speaking the subset of its protocol that
// node9's auto-trust uses: newline-delimited JSON over stdio, no `jsonrpc` field.
//
// It reads hooks from $CODEX_HOME/hooks.json exactly as Codex lays them out, and
// keeps trust in $CODEX_HOME/fake-trust.json. `currentHash` is computed HERE,
// by the fake, from the hook's key and command — standing in for Codex's own
// hash. node9 must never compute it; it must only echo what hooks/list returns,
// and this fixture is how the tests prove that (a hash node9 invented would not
// match what the fake computes, and the re-verify would fail).
//
// FAKE_CODEX_MODE simulates the failures node9 must survive:
//   error         every request after initialize returns an error
//   hang          never answer hooks/list
//   ignore-write  accept config/batchWrite but do not persist it (the re-verify
//                 must catch this — a write reporting "ok" is not evidence)
//   init-error    initialize itself fails
//
// FAKE_CODEX_LOG, if set, receives one line per request so tests can assert
// which keys node9 actually asked to trust.
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const home = process.env.CODEX_HOME;
const mode = process.env.FAKE_CODEX_MODE || '';
const hooksPath = path.join(home, 'hooks.json');
const trustPath = path.join(home, 'fake-trust.json');

const EVENT_KEY = {
  PreToolUse: 'pre_tool_use',
  PostToolUse: 'post_tool_use',
  UserPromptSubmit: 'user_prompt_submit',
};

function readTrust() {
  try {
    return JSON.parse(fs.readFileSync(trustPath, 'utf8'));
  } catch {
    return {};
  }
}

function listHooks() {
  let file;
  try {
    file = JSON.parse(fs.readFileSync(hooksPath, 'utf8'));
  } catch {
    return [];
  }
  const trust = readTrust();
  const out = [];
  for (const [event, groups] of Object.entries(file.hooks || {})) {
    const ek = EVENT_KEY[event] || event;
    (groups || []).forEach((g, gi) => {
      (g.hooks || []).forEach((h, hi) => {
        const key = `${hooksPath}:${ek}:${gi}:${hi}`;
        const currentHash =
          'sha256:' +
          crypto
            .createHash('sha256')
            .update(key + '\0' + h.command)
            .digest('hex');
        const stored = trust[key];
        const trustStatus = !stored ? 'untrusted' : stored === currentHash ? 'trusted' : 'modified';
        out.push({
          key,
          command: h.command,
          matcher: g.matcher,
          eventName: event,
          sourcePath: hooksPath,
          source: 'user',
          pluginId: null,
          isManaged: false,
          currentHash,
          trustStatus,
        });
      });
    });
  }
  return out;
}

function log(line) {
  if (process.env.FAKE_CODEX_LOG) fs.appendFileSync(process.env.FAKE_CODEX_LOG, line + '\n');
}

function reply(id, body) {
  process.stdout.write(JSON.stringify({ id, ...body }) + '\n');
}

let buf = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (d) => {
  buf += d;
  let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, i);
    buf = buf.slice(i + 1);
    if (!line.trim()) continue;
    const m = JSON.parse(line);
    log(
      `${m.method}${m.params && m.params.edits ? ' ' + JSON.stringify(Object.keys(m.params.edits[0].value)) : ''}`
    );
    if (m.id === undefined) continue; // notification
    if (m.method === 'initialize') {
      if (mode === 'init-error') {
        reply(m.id, { error: { code: -1, message: 'boom' } });
        continue;
      }
      reply(m.id, { result: { codexHome: home } });
      continue;
    }
    if (mode === 'error') {
      reply(m.id, { error: { code: -32000, message: 'fake failure' } });
      continue;
    }
    if (m.method === 'hooks/list') {
      if (mode === 'hang') continue;
      reply(m.id, {
        result: { data: [{ cwd: home, hooks: listHooks(), warnings: [], errors: [] }] },
      });
      continue;
    }
    if (m.method === 'config/batchWrite') {
      if (mode !== 'ignore-write') {
        const trust = readTrust();
        for (const e of m.params.edits) {
          for (const [k, v] of Object.entries(e.value)) trust[k] = v.trusted_hash;
        }
        fs.writeFileSync(trustPath, JSON.stringify(trust));
      }
      reply(m.id, { result: { status: 'ok' } });
      continue;
    }
    reply(m.id, { error: { code: -32601, message: 'method not found' } });
  }
});
