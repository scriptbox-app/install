import assert from 'node:assert/strict';
import test from 'node:test';

import { commandFor, publisherEnvironment } from '../dist/workspace.js';

test('workspace commands are fixed definitions without shells or caller arguments', () => {
  assert.deepEqual(commandFor('install', 'build'), { executable: 'php', args: ['build/compile.php'] });
  assert.deepEqual(commandFor('ui', 'build'), { executable: 'npm', args: ['run', 'build'] });
  assert.throws(() => commandFor('api', 'shell'), /unsupported/i);
});

test('publisher subprocess environment includes only explicit operational keys', () => {
  const result = publisherEnvironment({ PATH: '/bin', HOME: '/secret', DB_HOST: 'db', INSTALLER_TOKEN_SECRET: 'token', RANDOM_SECRET: 'no' });
  assert.equal(result.PATH, '/bin'); assert.equal(result.DB_HOST, 'db'); assert.equal(result.INSTALLER_TOKEN_SECRET, undefined);
  assert.equal(result.HOME, undefined); assert.equal(result.RANDOM_SECRET, undefined);
});
