import { spawn } from 'node:child_process';

import type { ProjectName } from './core.js';

export interface FixedCommand { executable: string; args: string[] }

const COMMANDS: Record<ProjectName, Record<string, FixedCommand>> = {
  install: {
    test: { executable: 'php', args: ['tests/run.php'] },
    build: { executable: 'php', args: ['build/compile.php'] },
    syntax: { executable: 'php', args: ['-l', 'install.php'] },
  },
  ui: {
    test: { executable: 'npm', args: ['test'] },
    lint: { executable: 'npm', args: ['run', 'lint'] },
    build: { executable: 'npm', args: ['run', 'build'] },
  },
  api: {
    test: { executable: 'npm', args: ['test'] },
    syntax: { executable: 'node', args: ['--check', 'src/server.js'] },
    package_validate: { executable: 'node', args: ['src/cli/installer-validate.js'] },
    publish: { executable: 'node', args: ['src/cli/installer-publish.js'] },
  },
};

export function commandFor(project: ProjectName, operation: string): FixedCommand {
  const value = COMMANDS[project]?.[operation];
  if (!value) throw new Error(`Unsupported fixed command: ${project}/${operation}`);
  return { executable: value.executable, args: [...value.args] };
}

const PUBLISH_ENV = new Set([
  'PATH', 'NODE_ENV', 'DB_HOST', 'DB_PORT', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'DB_POOL_SIZE',
  'INSTALLER_SIGNING_KID', 'INSTALLER_SIGNING_PRIVATE_KEY', 'INSTALLER_STORAGE_DRIVER',
  'INSTALLER_LOCAL_STORAGE_PATH', 'INSTALLER_S3_BUCKET', 'INSTALLER_S3_REGION', 'INSTALLER_S3_ENDPOINT',
  'INSTALLER_S3_ACCESS_KEY_ID', 'INSTALLER_S3_SECRET_ACCESS_KEY', 'INSTALLER_S3_FORCE_PATH_STYLE',
]);

export function publisherEnvironment(source: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  return Object.fromEntries(Object.entries(source).filter(([key, value]) => PUBLISH_ENV.has(key) && value !== undefined));
}

export async function runFixed(command: FixedCommand, cwd: string, extraArgs: string[] = [], env: NodeJS.ProcessEnv = { PATH: process.env.PATH }): Promise<{ ok: boolean; code: number; summary: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command.executable, [...command.args, ...extraArgs], {
      cwd, env, shell: false, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10 * 60 * 1000,
    });
    let output = '';
    const capture = (chunk: Buffer) => { if (output.length < 128 * 1024) output += chunk.toString('utf8'); };
    child.stdout.on('data', capture); child.stderr.on('data', capture);
    child.on('error', reject);
    child.on('close', (code) => resolve({ ok: code === 0, code: code ?? -1, summary: sanitizeOutput(output) }));
  });
}

function sanitizeOutput(output: string): string {
  const scrubbed = output
    .replace(/(password|secret|token|authorization|private[_ -]?key)\s*[:=]\s*\S+/gi, '$1=[REDACTED]')
    .replace(/[\t ]+$/gm, '');
  const safeLines = scrubbed.split('\n').filter((line) =>
    /^(?:ok|not ok|# Subtest:|TAP version|1\.\.|tests?|suites?|pass|fail|cancelled|skipped|todo|duration_ms|No syntax errors|✓|dist\/|vite v|found 0 vulnerabilities|npm notice run|\s*\d+ (?:tests|problems)|\s*[A-Za-z0-9_./-]+\.(?:js|jsx|ts|tsx|php)\s*$)/i.test(line.trim()),
  );
  return safeLines.slice(-200).join('\n').slice(-16_000) || 'Command completed; detailed output withheld.';
}
