import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { ConfirmationStore, PathPolicy, redact } from '../dist/core.js';

test('path policy rejects traversal and symlink escapes', async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'scriptbox-mcp-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = path.join(directory, 'root'); const outside = path.join(directory, 'outside');
  await mkdir(root); await mkdir(outside); await writeFile(path.join(outside, 'secret'), 'no');
  await symlink(outside, path.join(root, 'escape'));
  const policy = await PathPolicy.create({ install: root, ui: root, api: root }, []);
  assert.equal(await policy.resolveProject('install', '.'), root);
  await assert.rejects(() => policy.resolveProject('install', 'escape/secret'), /outside/i);
  await assert.rejects(() => policy.resolveProject('install', '../outside/secret'), /outside/i);
});

test('confirmation tokens are digest-bound, expiring, and single-use', async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'scriptbox-confirm-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  let now = 1_000;
  const store = new ConfirmationStore(directory, () => now);
  const preview = await store.create({ operation: 'package', sha256: 'a'.repeat(64), path: '/approved/a.zip' });
  assert.equal((await store.consume(preview.token)).sha256, 'a'.repeat(64));
  await assert.rejects(() => store.consume(preview.token), /used|invalid/i);
  const expired = await store.create({ operation: 'ui', sha256: 'b'.repeat(64), path: '/approved/dist' });
  now += 301;
  await assert.rejects(() => store.consume(expired.token), /expired/i);
});

test('audit redaction removes credentials and tokens recursively', () => {
  const clean = redact({ project: 'api', token: 'secret', nested: { password: 'secret', sha256: 'a' } });
  assert.equal(clean.token, '[REDACTED]'); assert.equal(clean.nested.password, '[REDACTED]'); assert.equal(clean.nested.sha256, 'a');
});
