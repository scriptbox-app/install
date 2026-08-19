import { createHash, randomBytes } from 'node:crypto';
import { appendFile, chmod, mkdir, readFile, realpath, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';

export type ProjectName = 'install' | 'ui' | 'api';

export class PathPolicy {
  private constructor(private readonly roots: Record<ProjectName, string>, private readonly artifactRoots: string[]) {}

  static async create(roots: Record<ProjectName, string>, artifactRoots: string[]): Promise<PathPolicy> {
    return new PathPolicy({
      install: await realpath(roots.install), ui: await realpath(roots.ui), api: await realpath(roots.api),
    }, await Promise.all(artifactRoots.map((root) => realpath(root))));
  }

  projectRoot(project: ProjectName): string { return this.roots[project]; }

  async resolveProject(project: ProjectName, relative: string): Promise<string> {
    return this.resolveInside(this.roots[project], relative);
  }

  async resolveArtifact(input: string): Promise<string> {
    const resolved = await realpath(input);
    if (!this.artifactRoots.some((root) => isInside(root, resolved))) throw new Error('Artifact path is outside approved artifact roots');
    return resolved;
  }

  private async resolveInside(root: string, relative: string): Promise<string> {
    if (path.isAbsolute(relative)) throw new Error('Absolute paths are outside the project root');
    const candidate = path.resolve(root, relative);
    if (!isInside(root, candidate)) throw new Error('Path is outside the project root');
    const resolved = await realpath(candidate);
    if (!isInside(root, resolved)) throw new Error('Resolved path is outside the project root');
    return resolved;
  }
}

function isInside(root: string, candidate: string): boolean {
  return candidate === root || candidate.startsWith(root + path.sep);
}

const SECRET_PATTERN = /(authorization|cookie|credential|password|private.?key|secret|token|environment)/i;
export function redact(value: unknown): any {
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, SECRET_PATTERN.test(key) ? '[REDACTED]' : redact(item)]));
  }
  return value;
}

export interface PublishOperation { operation: 'package' | 'ui'; sha256: string; path: string; [key: string]: unknown }

export class ConfirmationStore {
  constructor(private readonly root: string, private readonly now: () => number = () => Math.floor(Date.now() / 1000)) {}

  async create(operation: PublishOperation): Promise<{ token: string; expires_at: number }> {
    await this.prepare();
    const token = randomBytes(32).toString('base64url');
    const record = { ...operation, expires_at: this.now() + 300, created_at: this.now() };
    const file = this.file(token);
    await writeFile(file, JSON.stringify(record), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    return { token, expires_at: record.expires_at };
  }

  async consume(token: string): Promise<PublishOperation> {
    if (!/^[A-Za-z0-9_-]{40,64}$/.test(token)) throw new Error('Invalid confirmation token');
    await this.prepare();
    const file = this.file(token); const consumed = `${file}.used`;
    try { await rename(file, consumed); } catch { throw new Error('Confirmation token is invalid or already used'); }
    const record = JSON.parse(await readFile(consumed, 'utf8')) as PublishOperation & { expires_at: number };
    if (record.expires_at < this.now()) throw new Error('Confirmation token has expired');
    return record;
  }

  async audit(event: object): Promise<void> {
    await this.prepare();
    await appendFile(path.join(this.root, 'audit.jsonl'), JSON.stringify({ at: new Date(this.now() * 1000).toISOString(), ...redact(event) }) + '\n', { encoding: 'utf8', mode: 0o600 });
  }

  private file(token: string): string { return path.join(this.root, `confirm-${createHash('sha256').update(token).digest('hex')}.json`); }
  private async prepare(): Promise<void> { await mkdir(this.root, { recursive: true, mode: 0o700 }); await chmod(this.root, 0o700); }
}
