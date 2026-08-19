import { createHash } from 'node:crypto';
import { readdir, readFile, realpath, stat, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import * as z from 'zod/v4';

import { ConfirmationStore, PathPolicy, type ProjectName, type PublishOperation, redact } from './core.js';
import { commandFor, publisherEnvironment, runFixed } from './workspace.js';

const roots = {
  install: process.env.SCRIPTBOX_INSTALL_ROOT || path.resolve(import.meta.dirname, '../../..'),
  ui: process.env.SCRIPTBOX_UI_ROOT || '/home/tasherul/Documents/GitHub/installUI',
  api: process.env.SCRIPTBOX_API_ROOT || '/home/tasherul/Documents/GitHub/scriptbox-api',
} satisfies Record<ProjectName, string>;
const defaultArtifactRoot = process.env.SCRIPTBOX_MCP_ARTIFACT_ROOT || '/tmp/scriptbox-artifacts';
await mkdir(defaultArtifactRoot, { recursive: true, mode: 0o700 });
const artifactRoots = (process.env.SCRIPTBOX_MCP_ARTIFACT_ROOTS || defaultArtifactRoot).split(path.delimiter).filter(Boolean);
const policy = await PathPolicy.create(roots, artifactRoots);
const confirmations = new ConfirmationStore(process.env.SCRIPTBOX_MCP_STATE_DIR || path.resolve(roots.install, '../.scriptbox-mcp'));

const contracts = {
  protocol: 'installer-v1', bootstrap_algorithm: 'RS256', session_ttl_seconds: 900,
  download_chunk_bytes: 8 * 1024 * 1024,
  routes: ['GET /bootstrap', 'POST /sessions/verify', 'POST /catalog/search', 'GET /catalog/:scriptId', 'POST /licenses/free', 'POST /artifacts/:artifactId/authorize', 'GET /downloads/:token', 'POST /licenses/:licenseId/activate', 'POST /events'],
};
const packageSchema = {
  schema_version: 1, runtime: ['static', 'php'], databases: ['none', 'mysql', 'mariadb', 'pgsql', 'sqlite', 'sqlsrv', 'mongodb'],
  forbidden: ['shell hooks', 'Composer', 'npm', 'symlinks', 'absolute paths', 'traversal', 'device files', 'package-selected URLs'],
};

function buildServer(): McpServer {
  const server = new McpServer({ name: 'scriptbox-three-project', version: '1.0.0' });
  resource(server, 'workspace-overview', 'scriptbox://workspace/overview', async () => ({ projects: roots, transport: 'stdio', production_transport: 'signed HTTPS', mutations: 'preview-token gated publishing only' }));
  for (const project of ['install', 'ui', 'api'] as const) resource(server, `${project}-status`, `scriptbox://projects/${project}/status`, () => projectStatus(project));
  resource(server, 'installer-contract', 'scriptbox://contracts/installer-v1', async () => contracts);
  resource(server, 'package-schema', 'scriptbox://packages/schema', async () => packageSchema);
  resource(server, 'current-releases', 'scriptbox://releases/current', currentReleases);

  server.registerTool('workspace_validate', { title: 'Validate all ScriptBox projects', description: 'Runs the fixed test/build validation suites for all three configured repositories.', annotations: { readOnlyHint: true }, inputSchema: z.object({}) }, async () => toolResult(await validateWorkspace()));
  server.registerTool('project_checks', { title: 'Run fixed project checks', description: 'Runs an allowlisted check set; no command or arguments are accepted.', annotations: { readOnlyHint: true }, inputSchema: z.object({ project: z.enum(['install', 'ui', 'api']) }) }, async ({ project }) => toolResult(await checkProject(project)));
  server.registerTool('contract_validate', { title: 'Validate installer contracts', annotations: { readOnlyHint: true }, inputSchema: z.object({}) }, async () => toolResult({ ok: contracts.routes.length === 9 && packageSchema.runtime.length === 2, contracts, packageSchema }));
  server.registerTool('installer_build', { title: 'Build deterministic install.php', annotations: { readOnlyHint: false }, inputSchema: z.object({}) }, async () => toolResult(await runNamed('install', 'build')));
  server.registerTool('ui_build', { title: 'Build immutable React assets', annotations: { readOnlyHint: false }, inputSchema: z.object({}) }, async () => toolResult(await runNamed('ui', 'build')));
  server.registerTool('package_validate', { title: 'Validate a package ZIP', description: 'Accepts only files under configured artifact input roots.', annotations: { readOnlyHint: true }, inputSchema: z.object({ path: z.string() }) }, async ({ path: input }) => {
    const file = await policy.resolveArtifact(input); const command = commandFor('api', 'package_validate');
    const result = await runFixed(command, policy.projectRoot('api'), ['--file', file]);
    return toolResult({ ...result, sha256: await hashPath(file), bytes: (await stat(file)).size });
  });
  server.registerTool('publish_preview', { title: 'Preview an exact publication', description: 'Hashes an approved package or the fixed UI dist and returns a five-minute single-use token.', annotations: { readOnlyHint: true }, inputSchema: z.discriminatedUnion('operation', [
    z.object({ operation: z.literal('package'), path: z.string(), script_version_id: z.number().int().positive() }),
    z.object({ operation: z.literal('ui'), version: z.string(), base_url: z.string().url().startsWith('https://') }),
  ]) }, async (input) => toolResult(await publishPreview(input), false));
  server.registerTool('publish_execute', { title: 'Execute a confirmed publication', description: 'Consumes a single-use preview token and publishes only the digest-bound input.', annotations: { destructiveHint: true }, inputSchema: z.object({ confirmation_token: z.string() }) }, async ({ confirmation_token }) => toolResult(await publishExecute(confirmation_token)));
  return server;
}

function resource(server: McpServer, name: string, uri: string, callback: () => Promise<unknown>): void {
  server.registerResource(name, uri, { title: name, mimeType: 'application/json' }, async (requested) => ({ contents: [{ uri: requested.href, mimeType: 'application/json', text: JSON.stringify(await callback(), null, 2) }] }));
}

async function projectStatus(project: ProjectName): Promise<object> {
  const root = policy.projectRoot(project); const branch = await git(root, ['branch', '--show-current']); const changed = await git(root, ['status', '--porcelain']);
  return { project, root, branch: branch.trim(), changed_files: changed.trim() ? changed.trim().split('\n').length : 0 };
}

async function git(cwd: string, args: string[]): Promise<string> {
  return new Promise((resolve) => { const child = spawn('git', args, { cwd, shell: false, env: { PATH: process.env.PATH }, stdio: ['ignore', 'pipe', 'ignore'] }); let output = ''; child.stdout.on('data', (value) => { output += value; }); child.on('close', () => resolve(output)); child.on('error', () => resolve('')); });
}

async function runNamed(project: ProjectName, operation: string) { return runFixed(commandFor(project, operation), policy.projectRoot(project)); }
async function checkProject(project: ProjectName) {
  const operations = project === 'install' ? ['test', 'build', 'syntax'] : project === 'ui' ? ['test', 'lint', 'build'] : ['test', 'syntax'];
  const results = []; for (const operation of operations) results.push({ operation, ...(await runNamed(project, operation)) });
  return { project, ok: results.every((result) => result.ok), results };
}
async function validateWorkspace() { const projects = []; for (const project of ['install', 'ui', 'api'] as const) projects.push(await checkProject(project)); return { ok: projects.every((item) => item.ok), projects }; }

async function currentReleases(): Promise<object> {
  const installer = await hashPath(path.join(policy.projectRoot('install'), 'install.php'));
  let ui: string | null = null; try { ui = await hashPath(await realpath(path.join(policy.projectRoot('ui'), 'dist'))); } catch {}
  return { installer_sha256: installer, ui_dist_sha256: ui, api_protocol: 'installer-v1' };
}

async function publishPreview(input: { operation: 'package'; path: string; script_version_id: number } | { operation: 'ui'; version: string; base_url: string }) {
  const target = input.operation === 'package' ? await policy.resolveArtifact(input.path) : await realpath(path.join(policy.projectRoot('ui'), 'dist'));
  const operation: PublishOperation = { ...input, path: target, sha256: await hashPath(target) };
  const confirmation = await confirmations.create(operation); await confirmations.audit({ action: 'publish_preview', operation });
  return { operation: input.operation, target, sha256: operation.sha256, changes: input.operation === 'package' ? 'publish one validated script artifact' : 'supersede active UI release', ...confirmation };
}

async function publishExecute(token: string) {
  const operation = await confirmations.consume(token);
  const target = operation.operation === 'package' ? await policy.resolveArtifact(operation.path) : await realpath(path.join(policy.projectRoot('ui'), 'dist'));
  if (target !== operation.path || await hashPath(target) !== operation.sha256) throw new Error('Publication input changed after preview');
  const args = operation.operation === 'package'
    ? ['package', '--file', target, '--script-version', String(operation.script_version_id)]
    : ['ui', '--dist', target, '--version', String(operation.version), '--base-url', String(operation.base_url)];
  const result = await runFixed(commandFor('api', 'publish'), policy.projectRoot('api'), args, publisherEnvironment(process.env));
  await confirmations.audit({ action: 'publish_execute', operation, result: { ok: result.ok, code: result.code } });
  return { operation: operation.operation, sha256: operation.sha256, ...result };
}

async function hashPath(input: string): Promise<string> {
  const info = await stat(input); const hash = createHash('sha256');
  if (info.isFile()) { hash.update(await readFile(input)); return hash.digest('hex'); }
  const entries = await readdir(input, { withFileTypes: true });
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) { if (entry.isSymbolicLink()) throw new Error('Symlinks are forbidden in publish inputs'); hash.update(entry.name); hash.update(await hashPath(path.join(input, entry.name))); }
  return hash.digest('hex');
}

function toolResult(value: unknown, redactSecrets = true) { const clean = redactSecrets ? redact(value) : value; return { content: [{ type: 'text' as const, text: JSON.stringify(clean, null, 2) }], structuredContent: clean as Record<string, unknown> }; }

serveStdio(() => buildServer());
