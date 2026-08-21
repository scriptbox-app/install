<?php
declare(strict_types=1);

namespace ScriptBox\Installer;

use RuntimeException;
use Throwable;

final class InstallerException extends RuntimeException
{
    public function __construct(string $message, public readonly string $stableCode = 'INSTALLER_ERROR', int $status = 400)
    {
        parent::__construct($message, $status);
    }
}

final class BuildIdentity
{
    public static function fromRelease(array $release, string $artifactPath): array
    {
        $hash = is_file($artifactPath) ? hash_file('sha256', $artifactPath) : false;
        return [
            'installer_version' => (string)($release['version'] ?? ''),
            'release_timestamp' => (string)($release['release_timestamp'] ?? ''),
            'artifact_sha256' => is_string($hash) ? $hash : null,
        ];
    }
}

final class Crypto
{
    public static function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    public static function base64UrlDecode(string $value): string
    {
        if (!preg_match('/^[A-Za-z0-9_-]+$/', $value)) throw new InstallerException('Invalid base64url value', 'SIGNATURE_INVALID');
        $decoded = base64_decode(strtr($value, '-_', '+/') . str_repeat('=', (4 - strlen($value) % 4) % 4), true);
        if ($decoded === false) throw new InstallerException('Invalid base64url value', 'SIGNATURE_INVALID');
        return $decoded;
    }

    public static function verifyEnvelope(array $envelope, array $publicKeys, ?int $now = null, bool $requireExpiry = true): array
    {
        if (($envelope['alg'] ?? null) !== 'RS256') throw new InstallerException('Unsupported signature algorithm', 'SIGNATURE_INVALID');
        $kid = (string)($envelope['kid'] ?? '');
        if (!isset($publicKeys[$kid])) throw new InstallerException('Unknown signing key', 'SIGNING_KEY_UNKNOWN');
        $payload = (string)($envelope['payload'] ?? '');
        $payloadBytes = self::base64UrlDecode($payload);
        $signature = self::base64UrlDecode((string)($envelope['signature'] ?? ''));
        if (openssl_verify($payloadBytes, $signature, $publicKeys[$kid], OPENSSL_ALGO_SHA256) !== 1) {
            throw new InstallerException('Configuration signature is invalid', 'SIGNATURE_INVALID');
        }
        $decoded = json_decode($payloadBytes, true, 32, JSON_THROW_ON_ERROR);
        $clock = $now ?? time();
        if (!is_array($decoded) || ($requireExpiry && (!isset($decoded['expires_at']) || (int)$decoded['expires_at'] < $clock))) {
            throw new InstallerException('Signed configuration has expired', 'CONFIG_EXPIRED');
        }
        if (isset($decoded['issued_at']) && (int)$decoded['issued_at'] > $clock + 300) {
            throw new InstallerException('Signed configuration is not active', 'CONFIG_NOT_ACTIVE');
        }
        return $decoded;
    }

    public static function verifyFile(string $file, string $sha256, int $bytes): void
    {
        if (!is_file($file) || filesize($file) !== $bytes || !hash_equals(strtolower($sha256), hash_file('sha256', $file))) {
            throw new InstallerException('Downloaded file does not match signed metadata', 'HASH_MISMATCH');
        }
    }
}

final class StateStore
{
    private const SECRET_KEYS = ['password', 'database_password', 'token', 'authorization', 'cookie', 'private_key', 'environment'];

    public function __construct(public readonly string $root)
    {
        if (!is_dir($root) && !mkdir($root, 0700, true) && !is_dir($root)) throw new InstallerException('Cannot create private state directory', 'STATE_UNAVAILABLE', 500);
        chmod($root, 0700);
        if (is_link($root) || !is_writable($root)) throw new InstallerException('State directory is not secure and writable', 'STATE_UNAVAILABLE', 500);
    }

    public static function discover(string $documentRoot, string $installerFile): self
    {
        $configured = getenv('SCRIPTBOX_STATE_DIR');
        $document = rtrim(realpath($documentRoot) ?: $documentRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if ($configured !== false && $configured !== '') {
            $root = $configured;
            if (!self::allowedByOpenBasedir($root, (string)ini_get('open_basedir'))) {
                throw new InstallerException('Configured state directory is outside PHP open_basedir', 'STATE_PATH_RESTRICTED', 500);
            }
        } else {
            $root = self::resolveDefaultRoot(
                $documentRoot,
                $installerFile,
                (string)ini_get('open_basedir'),
                sys_get_temp_dir()
            );
        }
        $candidate = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if (str_starts_with($candidate, $document)) throw new InstallerException('State directory must be outside the document root', 'STATE_INSIDE_WEBROOT', 500);
        return new self($root);
    }

    public static function resolveDefaultRoot(string $documentRoot, string $installerFile, string $openBasedir, string $temporaryRoot): string
    {
        $document = realpath($documentRoot) ?: rtrim($documentRoot, DIRECTORY_SEPARATOR);
        $identity = substr(hash('sha256', realpath($installerFile) ?: $installerFile), 0, 16);
        $sibling = dirname($document) . '/.scriptbox-' . $identity;
        if (self::allowedByOpenBasedir($sibling, $openBasedir) && self::parentWritable($sibling)) return $sibling;

        $temporary = rtrim($temporaryRoot, DIRECTORY_SEPARATOR) . '/scriptbox-installer-' . $identity;
        if (!self::allowedByOpenBasedir($temporary, $openBasedir) || !self::parentWritable($temporary)) {
            throw new InstallerException('No private state directory is permitted by PHP open_basedir', 'STATE_PATH_RESTRICTED', 500);
        }
        return $temporary;
    }

    private static function allowedByOpenBasedir(string $candidate, string $openBasedir): bool
    {
        if (trim($openBasedir) === '') return true;
        $candidate = self::normalizedPath($candidate);
        foreach (array_filter(array_map('trim', explode(PATH_SEPARATOR, $openBasedir))) as $allowed) {
            $allowed = self::normalizedPath($allowed);
            if ($candidate === $allowed || str_starts_with($candidate . '/', rtrim($allowed, '/') . '/')) return true;
        }
        return false;
    }

    private static function normalizedPath(string $path): string
    {
        $path = str_replace('\\', '/', $path);
        if (!str_starts_with($path, '/') && !preg_match('/^[A-Za-z]:\//', $path)) $path = str_replace('\\', '/', getcwd()) . '/' . $path;
        $prefix = str_starts_with($path, '/') ? '/' : (preg_match('/^([A-Za-z]:)\//', $path, $match) ? strtoupper($match[1]) . '/' : '');
        if ($prefix !== '/' && $prefix !== '') $path = substr($path, 3);
        $segments = [];
        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.') continue;
            if ($segment === '..') { array_pop($segments); continue; }
            $segments[] = $segment;
        }
        return rtrim($prefix . implode('/', $segments), '/') ?: $prefix;
    }

    private static function parentWritable(string $path): bool
    {
        if (is_dir($path)) return !is_link($path) && is_writable($path);
        $parent = dirname($path);
        return is_dir($parent) && is_writable($parent);
    }

    public function read(string $name, array $fallback = []): array
    {
        $file = $this->file($name);
        if (!is_file($file)) return $fallback;
        $value = json_decode((string)file_get_contents($file), true);
        return is_array($value) ? $value : $fallback;
    }

    public function write(string $name, array $value): void
    {
        $file = $this->file($name);
        $temporary = $file . '.' . bin2hex(random_bytes(6)) . '.tmp';
        $json = json_encode($this->redact($value), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        if (file_put_contents($temporary, $json . "\n", LOCK_EX) === false) throw new InstallerException('Unable to write installer state', 'STATE_WRITE_FAILED', 500);
        chmod($temporary, 0600);
        if (!rename($temporary, $file)) throw new InstallerException('Unable to commit installer state', 'STATE_WRITE_FAILED', 500);
    }

    public function appendJournal(array $event): void
    {
        $line = json_encode($this->redact($event + ['at' => gmdate(DATE_ATOM)]), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        if (file_put_contents($this->file('journal', 'jsonl'), $line . "\n", FILE_APPEND | LOCK_EX) === false) {
            throw new InstallerException('Unable to append rollback journal', 'JOURNAL_WRITE_FAILED', 500);
        }
    }

    public function readJournal(): array
    {
        $file = $this->file('journal', 'jsonl');
        if (!is_file($file)) return [];
        $events = [];
        $handle = fopen($file, 'rb');
        if ($handle === false) throw new InstallerException('Unable to read rollback journal', 'JOURNAL_READ_FAILED', 500);
        try {
            while (($line = fgets($handle, 64 * 1024)) !== false) {
                $event = json_decode($line, true, 16);
                if (is_array($event)) $events[] = $event;
                if (count($events) > 100_000) throw new InstallerException('Rollback journal exceeds the safe limit', 'JOURNAL_INVALID', 500);
            }
        } finally { fclose($handle); }
        return $events;
    }

    public function clearJournal(): void
    {
        $file = $this->file('journal', 'jsonl');
        if (is_file($file) && !unlink($file)) throw new InstallerException('Unable to clear rollback journal', 'JOURNAL_WRITE_FAILED', 500);
    }

    public function lock()
    {
        $handle = fopen($this->file('install', 'lock'), 'c+');
        if ($handle === false || !flock($handle, LOCK_EX | LOCK_NB)) throw new InstallerException('Another installation is already running', 'INSTALL_LOCKED', 409);
        return $handle;
    }

    public function unlock($handle): void
    {
        flock($handle, LOCK_UN);
        fclose($handle);
    }

    public function path(string $name): string { return $this->file($name); }

    public function remove(string $name): void
    {
        $file = $this->file($name);
        if (is_file($file) && !unlink($file)) throw new InstallerException('Unable to remove installer state', 'STATE_WRITE_FAILED', 500);
    }

    public function removeAll(): void
    {
        if (!is_dir($this->root) || is_link($this->root)) return;
        foreach (scandir($this->root) ?: [] as $entry) if ($entry !== '.' && $entry !== '..' && is_file($this->root . '/' . $entry)) unlink($this->root . '/' . $entry);
        @rmdir($this->root);
    }

    private function file(string $name, string $extension = 'json'): string
    {
        if (!preg_match('/^[a-z0-9_-]+$/', $name)) throw new InstallerException('Invalid state name', 'STATE_INVALID');
        return $this->root . DIRECTORY_SEPARATOR . $name . '.' . $extension;
    }

    private function redact(array $value): array
    {
        $clean = [];
        foreach ($value as $key => $item) {
            if (in_array(strtolower((string)$key), self::SECRET_KEYS, true)) continue;
            $clean[$key] = is_array($item) ? $this->redact($item) : $item;
        }
        return $clean;
    }
}

final class RequestLimits
{
    public const MAX_BODY_BYTES = 1024 * 1024;

    public static function assertBodyLength(string $value): void
    {
        if ($value === '') return;
        if (!preg_match('/^(?:0|[1-9][0-9]{0,15})$/', $value)) throw new InstallerException('Content-Length is invalid', 'REQUEST_SIZE_INVALID');
        if ((int)$value > self::MAX_BODY_BYTES) throw new InstallerException('Request body is too large', 'REQUEST_TOO_LARGE', 413);
    }

    public static function readBody($stream): string
    {
        if (!is_resource($stream)) throw new InstallerException('Request body is unavailable', 'REQUEST_BODY_INVALID');
        $body = stream_get_contents($stream, self::MAX_BODY_BYTES + 1);
        if (!is_string($body)) throw new InstallerException('Request body is unavailable', 'REQUEST_BODY_INVALID');
        if (strlen($body) > self::MAX_BODY_BYTES || !feof($stream)) throw new InstallerException('Request body is too large', 'REQUEST_TOO_LARGE', 413);
        return $body;
    }
}

final class OwnershipProof
{
    private readonly string $scriptPath;

    public function __construct(private readonly StateStore $state, string $scriptPath)
    {
        $path = parse_url($scriptPath, PHP_URL_PATH);
        if (!is_string($path) || !preg_match('#^/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$#', $path)) {
            throw new InstallerException('Installer URL path is invalid', 'OWNERSHIP_PROOF_PATH_INVALID');
        }
        $this->scriptPath = rtrim($path, '/');
    }

    public function create(): array
    {
        $id = bin2hex(random_bytes(12));
        $value = bin2hex(random_bytes(32));
        $this->state->write('proof_' . $id, ['id' => $id, 'value' => $value]);
        return [
            'id' => $id,
            'value' => $value,
            'digest' => hash('sha256', $value),
            'path' => $this->scriptPath . '/.well-known/scriptbox-installer/' . $id,
        ];
    }

    public function read(string $id): ?string
    {
        if (!preg_match('/^[a-f0-9]{24}$/', $id)) return null;
        $stored = $this->state->read('proof_' . $id);
        return isset($stored['id'], $stored['value']) && hash_equals($id, (string)$stored['id']) ? (string)$stored['value'] : null;
    }

    public function remove(string $id): void
    {
        if (preg_match('/^[a-f0-9]{24}$/', $id)) $this->state->remove('proof_' . $id);
    }
}

final class ArchiveInspector
{
    public const MAX_COMPRESSED = 536870912;
    public const MAX_UNPACKED = 2147483648;
    public const MAX_FILES = 20000;
    public const MAX_FILE = 268435456;

    public static function isSafePath(string $path): bool
    {
        if ($path === '' || str_contains($path, "\0") || str_contains($path, '\\') || str_starts_with($path, '/') || preg_match('/^[A-Za-z]:/', $path)) return false;
        foreach (explode('/', $path) as $part) if ($part === '' || $part === '.' || $part === '..') return false;
        return true;
    }

    public static function inspect(string $archive): array
    {
        if (!extension_loaded('zip')) throw new InstallerException('The ZIP extension is required', 'ZIP_EXTENSION_MISSING');
        if (!is_file($archive) || filesize($archive) > self::MAX_COMPRESSED) throw new InstallerException('Package exceeds the compressed size limit', 'PACKAGE_TOO_LARGE');
        $zip = new \ZipArchive();
        if ($zip->open($archive, \ZipArchive::RDONLY) !== true) throw new InstallerException('Package cannot be opened', 'PACKAGE_INVALID');
        try {
            if ($zip->numFiles > self::MAX_FILES) throw new InstallerException('Package contains too many files', 'PACKAGE_LIMIT');
            $unpacked = 0;
            $manifest = null;
            $canonicalEntries = [];
            for ($index = 0; $index < $zip->numFiles; $index++) {
                $stat = $zip->statIndex($index, \ZipArchive::FL_UNCHANGED);
                $name = (string)($stat['name'] ?? '');
                if (!self::isSafePath(rtrim($name, '/'))) throw new InstallerException('Package contains an unsafe path', 'PACKAGE_PATH_INVALID');
                $size = (int)($stat['size'] ?? 0);
                if ($size > self::MAX_FILE) throw new InstallerException('Package contains an oversized file', 'PACKAGE_LIMIT');
                $unpacked += $size;
                if ($unpacked > self::MAX_UNPACKED || ($unpacked > 0 && $unpacked > max(1, filesize($archive)) * 100)) throw new InstallerException('Package expansion ratio is unsafe', 'PACKAGE_BOMB');
                $attributes = $zip->getExternalAttributesIndex($index, $system, $external) ? (($external >> 16) & 0170000) : 0;
                if ($attributes === 0120000 || $attributes === 0060000 || $attributes === 0020000) throw new InstallerException('Links and device files are forbidden', 'PACKAGE_ENTRY_INVALID');
                $kind = str_ends_with($name, '/') || $attributes === 0040000 ? 'directory' : 'file';
                self::recordCanonicalPath($canonicalEntries, $name, $kind);
                if ($name === 'scriptbox.json') $manifest = json_decode((string)$zip->getFromIndex($index), true, 32, JSON_THROW_ON_ERROR);
            }
            if (!is_array($manifest)) throw new InstallerException('Package manifest is missing', 'MANIFEST_MISSING');
            self::validateManifest($manifest);
            return ['manifest' => $manifest, 'files' => $zip->numFiles, 'unpacked_bytes' => $unpacked];
        } finally { $zip->close(); }
    }

    private static function recordCanonicalPath(array &$entries, string $name, string $kind): void
    {
        $canonical = rtrim($name, '/');
        if (isset($entries[$canonical])) throw new InstallerException('Package contains a duplicate or colliding archive path', 'PACKAGE_ENTRY_INVALID');
        $parts = explode('/', $canonical);
        for ($index = 1; $index < count($parts); $index++) {
            if (($entries[implode('/', array_slice($parts, 0, $index))] ?? null) === 'file') {
                throw new InstallerException('Package contains a file-directory archive collision', 'PACKAGE_ENTRY_INVALID');
            }
        }
        if ($kind === 'file') {
            foreach (array_keys($entries) as $existing) {
                if (str_starts_with($existing, $canonical . '/')) throw new InstallerException('Package contains a file-directory archive collision', 'PACKAGE_ENTRY_INVALID');
            }
        }
        $entries[$canonical] = $kind;
    }

    public static function validateManifest(array $manifest): void
    {
        $schema = (int)($manifest['schema_version'] ?? 0);
        if (!in_array($schema, [1, 2], true) || !preg_match('/^[A-Za-z0-9._-]{1,64}$/', (string)($manifest['script_id'] ?? ''))) throw new InstallerException('Package manifest identity is invalid', 'MANIFEST_INVALID');
        if (!in_array($manifest['runtime']['type'] ?? '', ['static', 'php'], true)) throw new InstallerException('Package runtime is unsupported', 'RUNTIME_UNSUPPORTED');
        if (($manifest['runtime']['type'] ?? '') === 'php' && !preg_match('/^(?:>=|>|<=|<|=)?\d+\.\d+(?:\.\d+)?$/', trim((string)($manifest['runtime']['php'] ?? '')))) throw new InstallerException('Package PHP version constraint is invalid', 'MANIFEST_INVALID');
        if ($schema === 2) {
            $frameworks = ['static', 'laravel', 'codeigniter3', 'codeigniter4', 'cakephp', 'raw_php'];
            $framework = (string)($manifest['framework'] ?? '');
            if (!in_array($framework, $frameworks, true)
                || ($framework === 'static') !== (($manifest['runtime']['type'] ?? '') === 'static')) {
                throw new InstallerException('Package framework is unsupported', 'RUNTIME_UNSUPPORTED');
            }
            $seen = [];
            foreach (($manifest['inputs'] ?? []) as $input) {
                $key = (string)($input['key'] ?? '');
                if (!preg_match('/^[a-z][a-z0-9_]{0,63}$/', $key) || isset($seen[$key])
                    || !in_array($input['type'] ?? '', ['text', 'email', 'url', 'password', 'boolean', 'select'], true)) {
                    throw new InstallerException('Package input definition is invalid', 'MANIFEST_INVALID');
                }
                $seen[$key] = true;
            }
            foreach (($manifest['database']['migrations'] ?? []) as $migration) {
                if (is_string($migration)) {
                    if (!self::isSafePath($migration) || !preg_match('/\.jsonl?$/', $migration)) throw new InstallerException('Database migration path is invalid', 'MANIFEST_INVALID');
                    continue;
                }
                if (!is_array($migration) || !self::isSafePath((string)($migration['path'] ?? '')) || !preg_match('/\.jsonl?$/', (string)($migration['path'] ?? '')) || !is_array($migration['parameters'] ?? [])) {
                    throw new InstallerException('Database migration definition is invalid', 'MANIFEST_INVALID');
                }
                foreach ($migration['parameters'] as $parameter) {
                    if (!is_array($parameter)) throw new InstallerException('Database migration parameter is invalid', 'MANIFEST_INVALID');
                    $source = (string)($parameter['source'] ?? '');
                    if (!in_array($source, ['app.url', 'target.url', 'generated.app_key', 'database.driver', 'database.host', 'database.port', 'database.name', 'database.user', 'database.password'], true)
                        && (!preg_match('/^input\.([a-z][a-z0-9_]{0,63})$/', $source, $match) || !isset($seen[$match[1]]))) {
                        throw new InstallerException('Database migration source is invalid', 'MANIFEST_INVALID');
                    }
                    $transform = $parameter['transform'] ?? null;
                    $algorithm = $transform === 'password_hash' ? ($parameter['algorithm'] ?? null) : $transform;
                    if ($transform !== null && !in_array($algorithm, ['bcrypt', 'argon2id'], true)) throw new InstallerException('Database migration password transform is invalid', 'MANIFEST_INVALID');
                    if ($transform === null && isset($parameter['algorithm'])) throw new InstallerException('Database migration password algorithm is invalid', 'MANIFEST_INVALID');
                }
            }
            foreach (($manifest['payload']['writable'] ?? []) as $writable) {
                if (!is_array($writable) || !self::isSafePath((string)($writable['path'] ?? '')) || !in_array((string)($writable['mode'] ?? '0770'), ['0700', '0750', '0755', '0770', '0775'], true)) throw new InstallerException('Writable path definition is invalid', 'MANIFEST_INVALID');
            }
            foreach (($manifest['configuration'] ?? []) as $output) {
                if (!self::isSafePath((string)($output['path'] ?? '')) || !in_array($output['format'] ?? '', ['dotenv', 'json', 'php-array', 'token-template'], true)) throw new InstallerException('Configuration output is invalid', 'MANIFEST_INVALID');
            }
        }
        if (!in_array($manifest['database']['driver'] ?? '', ['none', 'mysql', 'mariadb', 'pgsql', 'sqlite', 'sqlsrv', 'mongodb'], true)) throw new InstallerException('Database driver is unsupported', 'DATABASE_UNSUPPORTED');
        foreach (($manifest['database']['migrations'] ?? []) as $migration) {
            $migrationPath = is_array($migration) ? (string)($migration['path'] ?? '') : (string)$migration;
            if (!self::isSafePath($migrationPath) || !preg_match('/\.jsonl?$/', $migrationPath)) throw new InstallerException('Database migration path is invalid', 'MANIFEST_INVALID');
        }
        if (($manifest['payload']['root'] ?? '') !== 'payload') throw new InstallerException('Package payload must be root-ready', 'MANIFEST_INVALID');
        foreach (['hooks', 'composer', 'npm', 'urls'] as $forbidden) if (array_key_exists($forbidden, $manifest)) throw new InstallerException('Executable hooks and package URLs are forbidden', 'MANIFEST_FORBIDDEN');
    }

    public static function profileHash(array $manifest): string
    {
        self::validateManifest($manifest);
        $schema = (int)$manifest['schema_version'];
        $runtime = $manifest['runtime'];
        $runtime['extensions'] = array_values(array_unique($runtime['extensions'] ?? []));
        $inputs = [];
        foreach ($manifest['inputs'] ?? [] as $input) {
            $normalized = [
                'key' => $input['key'], 'type' => $input['type'], 'label' => self::profileText((string)$input['label'], true),
                'required' => (bool)($input['required'] ?? false), 'secret' => (bool)(($input['secret'] ?? false) || ($input['type'] ?? '') === 'password'),
            ];
            if (($input['type'] ?? '') === 'password') $normalized['minimum_length'] = (int)($input['minimum_length'] ?? 12);
            if (($input['type'] ?? '') === 'select') {
                $normalized['options'] = array_map(fn (array $option): array => ['value' => self::profileText((string)($option['value'] ?? '')), 'label' => self::profileText((string)($option['label'] ?? ''))], $input['options'] ?? []);
            }
            $inputs[] = $normalized;
        }
        $writable = [];
        foreach ($manifest['payload']['writable'] ?? [] as $item) $writable[] = $schema === 2 && is_array($item) ? ['path' => $item['path'], 'mode' => $item['mode'] ?? '0770'] : $item;
        $migrations = [];
        foreach ($manifest['database']['migrations'] ?? [] as $migration) {
            if ($schema !== 2 || is_string($migration)) { $migrations[] = $migration; continue; }
            $parameters = [];
            foreach ($migration['parameters'] ?? [] as $parameter) {
                $normalized = ['source' => $parameter['source']];
                if (!empty($parameter['transform'])) {
                    $algorithm = $parameter['transform'] === 'password_hash' ? $parameter['algorithm'] : $parameter['transform'];
                    $normalized['transform'] = $algorithm;
                    $normalized['algorithm'] = $algorithm;
                }
                $parameters[] = $normalized;
            }
            $migrations[] = ['path' => $migration['path'], 'parameters' => $parameters];
        }
        $configuration = [];
        foreach ($manifest['configuration'] ?? [] as $output) {
            $normalized = ['path' => $output['path'], 'format' => $output['format']];
            if ($schema === 2 && $output['format'] === 'token-template') $normalized['template'] = $output['template'];
            elseif ($schema === 2) $normalized['values'] = $output['values'];
            $configuration[] = $normalized;
        }
        $profile = [
            'schema_version' => $schema,
            'framework' => $schema === 2 ? $manifest['framework'] : (($runtime['type'] ?? '') === 'static' ? 'static' : 'raw_php'),
            'runtime' => $runtime,
            'database' => $schema === 2 ? ['driver' => $manifest['database']['driver'], 'migrations' => $migrations] : ['driver' => $manifest['database']['driver']],
            'inputs' => $inputs,
            'payload' => ['writable' => $writable],
            'configuration' => $configuration,
            'health_check' => $manifest['health_check'],
        ];
        return hash('sha256', self::canonicalJson($profile));
    }

    private static function profileText(string $value, bool $trim = false): string
    {
        if ($trim) $value = trim($value, " \t\n\r\0\x0B");
        if (!preg_match_all('/./us', $value, $characters)) throw new InstallerException('Package profile text is invalid UTF-8', 'MANIFEST_INVALID');
        return implode('', array_slice($characters[0], 0, 120));
    }

    private static function canonicalJson(mixed $value): string
    {
        if (is_array($value)) {
            if (array_is_list($value)) return '[' . implode(',', array_map([self::class, 'canonicalJson'], $value)) . ']';
            ksort($value, SORT_STRING);
            $parts = [];
            foreach ($value as $key => $item) $parts[] = json_encode((string)$key, JSON_THROW_ON_ERROR) . ':' . self::canonicalJson($item);
            return '{' . implode(',', $parts) . '}';
        }
        return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}

final class TargetResolver
{
    private const RESERVED = ['install', '.git', '.svn', '.hg', '.well-known'];

    public static function inspect(string $documentRoot, string $controlDirectory, string $relative): array
    {
        $document = realpath($documentRoot);
        $control = realpath($controlDirectory);
        if ($document === false || !is_dir($document) || is_link($document)) throw new InstallerException('Document root is invalid', 'TARGET_INVALID');
        $relative = trim(str_replace('\\', '/', $relative), '/');
        if ($relative !== '') {
            if (strlen($relative) > 255 || str_contains($relative, '//')) throw new InstallerException('Target subfolder is invalid', 'TARGET_INVALID');
            $segments = explode('/', $relative);
            if (count($segments) > 5) throw new InstallerException('Target subfolder is too deep', 'TARGET_INVALID');
            foreach ($segments as $segment) {
                if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/', $segment) || str_starts_with($segment, '.') || in_array(strtolower($segment), self::RESERVED, true)) {
                    throw new InstallerException(strtolower($segment) === 'install' ? 'Target cannot be the installer control directory' : 'Target subfolder is invalid', strtolower($segment) === 'install' ? 'TARGET_CONTROL_PATH' : 'TARGET_INVALID');
                }
            }
        }
        $target = $document . ($relative === '' ? '' : DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative));
        $current = $document;
        foreach ($relative === '' ? [] : explode('/', $relative) as $segment) {
            $current .= DIRECTORY_SEPARATOR . $segment;
            if (file_exists($current) && is_link($current)) throw new InstallerException('Target cannot contain symbolic links', 'TARGET_SYMLINK');
        }
        $exists = is_dir($target);
        if (file_exists($target) && !$exists) throw new InstallerException('Target must be a directory', 'TARGET_INVALID');
        $parent = $target;
        while (!file_exists($parent)) $parent = dirname($parent);
        $canCreate = !$exists && is_dir($parent) && is_writable($parent);
        $empty = $exists ? self::isEmpty($target, $relative === '' ? $control : false) : true;
        return [
            'relative' => $relative === '' ? '/' : $relative,
            'exists' => $exists,
            'writable' => $exists && is_writable($target),
            'empty' => $empty,
            'can_create' => $canCreate,
            'path' => $target,
        ];
    }

    public static function resolve(string $documentRoot, string $controlDirectory, string $relative, bool $create = false): string
    {
        $status = self::inspect($documentRoot, $controlDirectory, $relative);
        if (!$status['exists'] && $create) {
            if (!$status['can_create'] || !mkdir($status['path'], 0755, true)) throw new InstallerException('Target subfolder cannot be created', 'TARGET_NOT_WRITABLE');
            $status = self::inspect($documentRoot, $controlDirectory, $relative);
        }
        if (!$status['exists'] || !$status['writable']) throw new InstallerException('The installation directory is not writable by PHP-FPM', 'TARGET_NOT_WRITABLE');
        if (!$status['empty']) throw new InstallerException('Target directory must be empty', 'TARGET_NOT_EMPTY');
        return $status['path'];
    }

    private static function isEmpty(string $target, string|false $ignoredControl): bool
    {
        foreach (scandir($target) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..') continue;
            $candidate = realpath($target . DIRECTORY_SEPARATOR . $entry);
            if ($ignoredControl !== false && $candidate !== false && hash_equals($ignoredControl, $candidate)) continue;
            return false;
        }
        return true;
    }
}

final class InstallationRun
{
    public const PHASES = ['preflight', 'license', 'authorization', 'download', 'verify', 'inspect', 'extract', 'database', 'migrate', 'configure', 'permissions', 'promote', 'health', 'activate', 'cleanup', 'complete'];

    public static function prepare(StateStore $state, array $input): array
    {
        $current = $state->read('status');
        if (in_array($current['state'] ?? '', ['complete', 'recovery_required'], true)) throw new InstallerException('Installer is permanently locked', 'INSTALLER_LOCKED', 409);
        if (($current['state'] ?? '') === 'running') throw new InstallerException('An installation run is already active', 'RUN_ACTIVE', 409);
        $run = [
            'run_id' => bin2hex(random_bytes(16)),
            'state' => 'running',
            'phase' => self::PHASES[0],
            'phase_index' => 0,
            'progress_percent' => 0,
            'script_id' => (string)($input['script_id'] ?? ''),
            'version' => (string)($input['version'] ?? ''),
            'target' => (string)($input['target'] ?? '/'),
            'created_at' => gmdate(DATE_ATOM),
        ];
        if (!preg_match('/^[A-Za-z0-9._-]{1,64}$/', $run['script_id']) || !preg_match('/^[A-Za-z0-9._-]{1,64}$/', $run['version'])) throw new InstallerException('Script and version are required', 'INPUT_INVALID');
        $state->write('run', $run);
        $state->write('status', $run);
        return $run;
    }

    public static function status(StateStore $state, string $runId): array
    {
        $run = $state->read('run');
        if ($run === [] || !isset($run['run_id']) || !hash_equals((string)$run['run_id'], $runId)) throw new InstallerException('Installation run was not found', 'RUN_NOT_FOUND', 404);
        $status = $state->read('status');
        $phase = (string)($status['phase'] ?? '');
        $index = array_search($phase, self::PHASES, true);
        if ($index !== false && !in_array($run['phase'] ?? '', ['complete', 'cancelled'], true)) {
            $run['phase'] = $phase;
            $run['phase_index'] = $index;
            $run['progress_percent'] = (int)floor(($index / (count(self::PHASES) - 1)) * 100);
        }
        foreach (['state', 'phase', 'updated_at', 'code', 'license_id', 'health'] as $field) if (array_key_exists($field, $status)) $run[$field] = $status[$field];
        return $run;
    }

    public static function publicStatus(array $status): array
    {
        $safe = ['state' => (string)($status['state'] ?? 'idle')];
        foreach (['phase', 'updated_at', 'code'] as $field) if (isset($status[$field]) && is_scalar($status[$field])) $safe[$field] = $status[$field];
        if (is_array($status['last_error'] ?? null)) {
            $safe['last_error'] = array_intersect_key($status['last_error'], array_flip(['diagnostic_id', 'timestamp', 'code', 'message']));
        }
        return $safe;
    }

    public static function update(StateStore $state, array $run): array
    {
        $state->write('run', $run);
        $state->write('status', $run);
        return $run;
    }

    public static function bindOwner(StateStore $state, string $runId, string $installId): void
    {
        if (!preg_match('/^[a-f0-9]{32}$/', $runId) || !preg_match('/^[a-f0-9]{32}$/', $installId)) throw new InstallerException('Installation run owner is invalid', 'RUN_OWNER_INVALID', 403);
        $state->write('run_owner', ['run_id' => $runId, 'owner_hash' => hash('sha256', $installId)]);
    }

    public static function assertOwner(StateStore $state, string $runId, string $installId): void
    {
        $owner = $state->read('run_owner');
        if (!isset($owner['run_id'], $owner['owner_hash']) || !hash_equals((string)$owner['run_id'], $runId)
            || !hash_equals((string)$owner['owner_hash'], hash('sha256', $installId))) {
            throw new InstallerException('Installation run was not found', 'RUN_NOT_FOUND', 404);
        }
    }

    public static function canCancel(string $phase): bool
    {
        $index = array_search($phase, self::PHASES, true);
        $promotion = array_search('promote', self::PHASES, true);
        return $index !== false && $promotion !== false && $index < $promotion;
    }
}

final class ReleaseFinalizer
{
    private const FILES = ['index.php', 'install.php', 'install.php.sha256', 'release.json'];

    public static function eligible(string $directory): bool
    {
        if (!is_dir($directory) || is_link($directory) || is_dir($directory . '/.git')) return false;
        $entries = array_values(array_diff(scandir($directory) ?: [], ['.', '..']));
        sort($entries); $expected = self::FILES; sort($expected);
        if ($entries !== $expected) return false;
        foreach (self::FILES as $name) if (!is_file($directory . '/' . $name) || is_link($directory . '/' . $name)) return false;
        try { $release = json_decode((string)file_get_contents($directory . '/release.json'), true, 16, JSON_THROW_ON_ERROR); }
        catch (Throwable) { return false; }
        if (($release['bundle_files'] ?? null) !== self::FILES) return false;
        $installerHash = hash_file('sha256', $directory . '/install.php');
        $launcherHash = hash_file('sha256', $directory . '/index.php');
        if (!is_string($installerHash) || !is_string($launcherHash)) return false;
        if (!hash_equals((string)($release['installer_sha256'] ?? ''), $installerHash) || !hash_equals((string)($release['launcher_sha256'] ?? ''), $launcherHash)) return false;
        return trim((string)file_get_contents($directory . '/install.php.sha256')) === $installerHash . '  install.php';
    }

    public static function schedule(string $directory): bool
    {
        if (!self::eligible($directory)) return false;
        register_shutdown_function(static function () use ($directory): void {
            foreach (self::FILES as $name) @unlink($directory . '/' . $name);
            @rmdir($directory);
        });
        return true;
    }
}

final class Router
{
    public static function resolve(string $method, string $uri): string
    {
        $path = parse_url($uri, PHP_URL_PATH) ?: '/';
        $fixed = [
            'GET /' => 'shell',
            'GET /api/runtime' => 'runtime',
            'GET /api/bootstrap' => 'bootstrap',
            'GET /api/status' => 'status',
            'POST /api/session' => 'session',
            'POST /api/preflight' => 'preflight',
            'POST /api/database/test' => 'database_test',
            'POST /api/catalog/search' => 'catalog_search',
            'POST /api/install' => 'install',
            'POST /api/install/prepare' => 'install_prepare',
            'POST /api/install/advance' => 'install_advance',
            'GET /api/install/status' => 'install_status',
            'POST /api/install/cancel' => 'install_cancel',
            'POST /api/finalize' => 'finalize',
            'POST /api/recover' => 'recover',
        ];
        $key = strtoupper($method) . ' ' . $path;
        if (isset($fixed[$key])) return $fixed[$key];
        if (strtoupper($method) === 'GET' && preg_match('#^/api/catalog/([A-Za-z0-9._-]{1,64})$#', $path)) return 'catalog_detail';
        if (strtoupper($method) === 'GET' && preg_match('#^/\.well-known/scriptbox-installer/([A-Za-z0-9-]{8,100})$#', $path)) return 'ownership_proof';
        if (strtoupper($method) === 'GET' && preg_match('#^/assets/[a-f0-9]{64}\.(?:js|css|json|png)$#', $path)) return 'asset';
        throw new InstallerException('Route not found', 'ROUTE_NOT_FOUND', 404);
    }
}

final class OriginDetector
{
    public static function detect(array $server, StateStore $state, string $trustedProxies): array
    {
        $configured = $state->read('server');
        if (isset($configured['public_url'])) return ['origin' => self::validate((string)$configured['public_url']), 'source' => 'cli'];
        $remote = (string)($server['REMOTE_ADDR'] ?? '');
        if (self::trusted($remote, $trustedProxies)) {
            $proto = (string)($server['HTTP_X_FORWARDED_PROTO'] ?? '');
            $host = (string)($server['HTTP_X_FORWARDED_HOST'] ?? '');
            if ($proto === 'https' && !str_contains($host, ',')) return ['origin' => self::validate('https://' . $host), 'source' => 'trusted_proxy'];
        }
        $https = strtolower((string)($server['HTTPS'] ?? ''));
        $scheme = in_array($https, ['on', '1'], true) || strtolower((string)($server['REQUEST_SCHEME'] ?? '')) === 'https' ? 'https' : 'http';
        if ($scheme !== 'https') throw new InstallerException('A public HTTPS origin is required', 'ORIGIN_INVALID');
        return ['origin' => self::validate('https://' . (string)($server['HTTP_HOST'] ?? '')), 'source' => 'request'];
    }

    private static function validate(string $origin): string
    {
        $url = parse_url($origin);
        $host = strtolower((string)($url['host'] ?? ''));
        if (!is_array($url) || ($url['scheme'] ?? '') !== 'https' || $host === '' || isset($url['user']) || isset($url['pass']) || isset($url['query']) || isset($url['fragment']) || !in_array($url['path'] ?? '', ['', '/'], true)) {
            throw new InstallerException('A public HTTPS origin is required', 'ORIGIN_INVALID');
        }
        if (filter_var($host, FILTER_VALIDATE_IP) !== false || strlen($host) > 253 || !preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $host)) {
            throw new InstallerException('The installer host is invalid', 'ORIGIN_INVALID');
        }
        $port = isset($url['port']) ? (int)$url['port'] : 443;
        if ($port < 1 || $port > 65535) throw new InstallerException('The installer port is invalid', 'ORIGIN_INVALID');
        return 'https://' . $host . ($port === 443 ? '' : ':' . $port);
    }

    private static function trusted(string $remote, string $configured): bool
    {
        $address = @inet_pton($remote);
        if ($address === false) return false;
        foreach (array_filter(array_map('trim', explode(',', $configured))) as $range) {
            [$network, $bits] = array_pad(explode('/', $range, 2), 2, null);
            $packed = @inet_pton($network);
            if ($packed === false || strlen($packed) !== strlen($address)) continue;
            $prefix = $bits === null ? strlen($packed) * 8 : (int)$bits;
            if ($prefix < 0 || $prefix > strlen($packed) * 8) continue;
            $bytes = intdiv($prefix, 8); $remainder = $prefix % 8;
            if (substr($address, 0, $bytes) !== substr($packed, 0, $bytes)) continue;
            if ($remainder === 0 || ((ord($address[$bytes]) ^ ord($packed[$bytes])) & (0xff << (8 - $remainder))) === 0) return true;
        }
        return false;
    }
}

final class Preflight
{
    public static function supportsPhp(string $constraint, string $version = PHP_VERSION): bool
    {
        if (!preg_match('/^(>=|>|<=|<|=)?(\d+\.\d+(?:\.\d+)?)$/', trim($constraint), $match)) return false;
        return version_compare($version, $match[2], $match[1] ?: '>=');
    }

    public static function assertWritableTarget(string $target): void
    {
        if (!is_dir($target) || !is_writable($target)) {
            throw new InstallerException('The installation directory is not writable by PHP-FPM', 'TARGET_NOT_WRITABLE');
        }
    }

    public static function capabilities(string $target): array
    {
        $extensions = array_values(array_intersect(
            ['curl', 'json', 'openssl', 'zip', 'pdo_mysql', 'pdo_pgsql', 'pdo_sqlite', 'pdo_sqlsrv', 'mongodb'],
            get_loaded_extensions()
        ));
        return [
            'php' => ['version' => PHP_VERSION, 'supported' => version_compare(PHP_VERSION, '8.3.0', '>=')],
            'extensions' => $extensions,
            'required' => [
                'curl' => extension_loaded('curl'),
                'json' => extension_loaded('json'),
                'openssl' => extension_loaded('openssl'),
                'zip' => extension_loaded('zip'),
            ],
            'databases' => [
                'none' => true,
                'mysql' => extension_loaded('pdo_mysql'),
                'mariadb' => extension_loaded('pdo_mysql'),
                'pgsql' => extension_loaded('pdo_pgsql'),
                'sqlite' => extension_loaded('pdo_sqlite'),
                'sqlsrv' => extension_loaded('pdo_sqlsrv'),
                'mongodb' => extension_loaded('mongodb'),
            ],
            'filesystem' => ['target_writable' => is_dir($target) && is_writable($target)],
            'limits' => [
                'compressed_bytes' => ArchiveInspector::MAX_COMPRESSED,
                'unpacked_bytes' => ArchiveInspector::MAX_UNPACKED,
                'files' => ArchiveInspector::MAX_FILES,
                'file_bytes' => ArchiveInspector::MAX_FILE,
                'upload_max_filesize' => (string)ini_get('upload_max_filesize'),
                'post_max_size' => (string)ini_get('post_max_size'),
                'memory_limit' => (string)ini_get('memory_limit'),
                'disk_free_bytes' => is_float($disk = disk_free_space($target)) ? (int)$disk : (is_int($disk) ? $disk : null),
            ],
            'platform' => ['os_family' => PHP_OS_FAMILY, 'sapi' => PHP_SAPI, 'web_server' => substr((string)($_SERVER['SERVER_SOFTWARE'] ?? 'unknown'), 0, 120)],
        ];
    }

    public static function assertPackageRequirements(array $manifest): void
    {
        $runtime = (string)($manifest['runtime']['type'] ?? '');
        if (!in_array($runtime, ['static', 'php'], true)) throw new InstallerException('Package runtime is unsupported', 'RUNTIME_UNSUPPORTED');
        if ($runtime === 'php' && !self::supportsPhp((string)($manifest['runtime']['php'] ?? ''))) throw new InstallerException('Installed PHP version does not satisfy the signed package', 'PHP_VERSION_UNSUPPORTED');
        $missing = array_values(array_filter($manifest['runtime']['extensions'] ?? [], fn (mixed $extension): bool => !is_string($extension) || !extension_loaded($extension)));
        if ($missing !== []) throw new InstallerException('Required PHP extensions are missing: ' . implode(', ', array_map('strval', $missing)), 'PHP_EXTENSION_MISSING');
        $driver = (string)($manifest['database']['driver'] ?? 'none');
        $available = self::capabilities(sys_get_temp_dir())['databases'];
        if (!($available[$driver] ?? false)) throw new InstallerException('Required database adapter is not installed', 'DATABASE_EXTENSION_MISSING');
    }
}

final class ApiClient
{
    private const METHODS = [
        'GET /bootstrap', 'POST /sessions/verify', 'POST /catalog/search',
        'GET /catalog/{id}', 'POST /licenses/free', 'POST /artifacts/{id}/authorize',
        'POST /licenses/{id}/activate', 'POST /events',
    ];

    public function __construct(private readonly string $baseUrl, private readonly int $timeout = 20)
    {
        if (!str_starts_with($baseUrl, 'https://')) throw new InstallerException('Installer API must use HTTPS', 'API_TLS_REQUIRED');
    }

    public function request(string $method, string $path, ?array $body = null, ?string $token = null, ?string $origin = null): array
    {
        $this->assertAllowed($method, parse_url($path, PHP_URL_PATH) ?: $path);
        $handle = curl_init($this->baseUrl . $path);
        if ($handle === false) throw new InstallerException('Cannot initialize HTTPS client', 'API_UNAVAILABLE');
        $headers = ['Accept: application/json'];
        if ($token !== null) $headers[] = 'Authorization: Bearer ' . $token;
        if ($origin !== null) $headers[] = 'X-ScriptBox-Origin: ' . $origin;
        if ($body !== null) $headers[] = 'Content-Type: application/json';
        curl_setopt_array($handle, [
            CURLOPT_CUSTOMREQUEST => strtoupper($method), CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 8, CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS, CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_MAXREDIRS => 0, CURLOPT_USERAGENT => 'ScriptBox-Installer/1.0',
        ]);
        if ($body !== null) curl_setopt($handle, CURLOPT_POSTFIELDS, json_encode($body, JSON_THROW_ON_ERROR));
        $response = curl_exec($handle);
        $status = curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $error = curl_error($handle);
        curl_close($handle);
        if ($response === false) throw new InstallerException('Installer API is unavailable: ' . $error, 'API_UNAVAILABLE', 502);
        $decoded = json_decode($response, true, 32, JSON_THROW_ON_ERROR);
        if ($status < 200 || $status >= 300 || ($decoded['success'] ?? false) !== true) {
            $remote = $decoded['error'] ?? [];
            throw new InstallerException((string)($remote['message'] ?? 'Installer API request failed'), (string)($remote['code'] ?? 'API_ERROR'), $status ?: 502);
        }
        return $decoded['data'];
    }

    public function download(string $token, string $destination, int $expectedBytes, string $expectedHash, ?callable $renewToken = null): void
    {
        $offset = is_file($destination) ? filesize($destination) : 0;
        if ($offset > $expectedBytes) { unlink($destination); $offset = 0; }
        $firstChunk = true;
        while ($offset < $expectedBytes) {
            if (!$firstChunk && $renewToken !== null) {
                $renewed = $renewToken();
                if (!is_string($renewed) || $renewed === '') throw new InstallerException('Artifact authorization renewal failed', 'DOWNLOAD_AUTHORIZATION_FAILED', 502);
                $token = $renewed;
            }
            $end = min($expectedBytes - 1, $offset + 8 * 1024 * 1024 - 1);
            $output = fopen($destination, $offset > 0 ? 'ab' : 'wb');
            if ($output === false) throw new InstallerException('Cannot open download destination', 'DOWNLOAD_WRITE_FAILED');
            $handle = curl_init($this->baseUrl . '/downloads/' . rawurlencode($token));
            curl_setopt_array($handle, [
                CURLOPT_FILE => $output, CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 1,
                CURLOPT_CONNECTTIMEOUT => 8, CURLOPT_TIMEOUT => 0, CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
                CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS, CURLOPT_HTTPHEADER => ["Range: bytes={$offset}-{$end}"],
            ]);
            $ok = curl_exec($handle);
            $status = curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
            $error = curl_error($handle);
            curl_close($handle); fclose($output);
            if ($ok === false || ($offset > 0 ? $status !== 206 : !in_array($status, [200, 206], true))) throw new InstallerException('Artifact download failed: ' . $error, 'DOWNLOAD_FAILED', 502);
            $next = filesize($destination);
            if ($next <= $offset || $next > $expectedBytes || $next > $end + 1) throw new InstallerException('Artifact download made invalid progress', 'DOWNLOAD_FAILED', 502);
            $offset = $next;
            $firstChunk = false;
        }
        Crypto::verifyFile($destination, $expectedHash, $expectedBytes);
    }

    private function assertAllowed(string $method, string $path): void
    {
        $static = ['/bootstrap', '/sessions/verify', '/catalog/search', '/licenses/free', '/events'];
        $normalizedPath = parse_url($path, PHP_URL_PATH) ?: $path;
        if ($normalizedPath === '/catalog/media' || str_starts_with($normalizedPath, '/catalog/media/')) {
            throw new InstallerException('Remote operation is not allowlisted', 'API_OPERATION_DENIED');
        }
        if (!in_array($normalizedPath, $static, true)) {
            $normalizedPath = preg_replace('#^/catalog/[A-Za-z0-9._-]+$#', '/catalog/{id}', $normalizedPath);
            $normalizedPath = preg_replace('#^/artifacts/[A-Za-z0-9._-]+/authorize$#', '/artifacts/{id}/authorize', $normalizedPath);
            $normalizedPath = preg_replace('#^/licenses/[A-Za-z0-9._-]+/activate$#', '/licenses/{id}/activate', $normalizedPath);
        }
        $normalized = strtoupper($method) . ' ' . $normalizedPath;
        if (!in_array($normalized, self::METHODS, true)) throw new InstallerException('Remote operation is not allowlisted', 'API_OPERATION_DENIED');
    }
}

final class ConfigurationWriter
{
    public static function write(string $root, array $output, array $runtimeValues): void
    {
        $relative = (string)($output['path'] ?? '');
        if (!ArchiveInspector::isSafePath($relative)) throw new InstallerException('Configuration path is unsafe', 'CONFIG_PATH_INVALID');
        $values = [];
        foreach (($output['values'] ?? []) as $key => $value) {
            if (!preg_match('/^[A-Za-z_][A-Za-z0-9_.-]*$/', (string)$key)) throw new InstallerException('Configuration key is invalid', 'CONFIG_INVALID');
            $values[$key] = is_string($value) && preg_match('/^\{\{([A-Za-z0-9_.-]+)\}\}$/', $value, $match)
                ? ValueResolver::source($match[1], $runtimeValues) : $value;
        }
        $format = $output['format'] ?? '';
        $content = match ($format) {
            'dotenv' => self::dotenv($values),
            'json' => json_encode($values, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n",
            'php-array' => "<?php\nreturn " . var_export($values, true) . ";\n",
            'token-template' => self::tokenTemplate((string)($output['template'] ?? ''), $runtimeValues),
            default => throw new InstallerException('Configuration format is unsupported', 'CONFIG_FORMAT_INVALID'),
        };
        $destination = $root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative);
        $directory = dirname($destination);
        if (!is_dir($directory) && !mkdir($directory, 0750, true) && !is_dir($directory)) throw new InstallerException('Cannot create configuration directory', 'CONFIG_WRITE_FAILED');
        if (file_put_contents($destination, $content, LOCK_EX) === false) throw new InstallerException('Cannot write application configuration', 'CONFIG_WRITE_FAILED');
        chmod($destination, 0600);
    }

    private static function tokenTemplate(string $template, array $runtimeValues): string
    {
        if (strlen($template) > 262144) throw new InstallerException('Configuration template is too large', 'CONFIG_INVALID');
        $content = preg_replace_callback('/\{\{([a-z0-9_.]+)\|([a-z-]+)\}\}/i', function (array $match) use ($runtimeValues): string {
            $value = ValueResolver::source($match[1], $runtimeValues);
            $scalar = is_bool($value) ? ($value ? 'true' : 'false') : (is_scalar($value) || $value === null ? (string)$value : throw new InstallerException('Configuration value must be scalar', 'CONFIG_INVALID'));
            return match ($match[2]) {
                'dotenv' => str_replace(["\\", "\n", "\r", '"'], ["\\\\", '\\n', '\\r', '\\"'], $scalar),
                'json-string' => substr(json_encode($scalar, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), 1, -1),
                'php-string' => substr(var_export($scalar, true), 1, -1),
                'ini-string' => str_replace(["\\", '"', "\n", "\r"], ["\\\\", '\\"', '\\n', '\\r'], $scalar),
                'url-component' => rawurlencode($scalar),
                default => throw new InstallerException('Configuration token encoder is unsupported', 'CONFIG_INVALID'),
            };
        }, $template);
        if (!is_string($content) || str_contains($content, '{{') || str_contains($content, '}}')) throw new InstallerException('Configuration template contains an invalid token', 'CONFIG_INVALID');
        return $content;
    }

    private static function dotenv(array $values): string
    {
        $lines = [];
        foreach ($values as $key => $value) {
            $scalar = match (true) {
                is_bool($value) => $value ? 'true' : 'false',
                $value === null => '',
                is_scalar($value) => (string)$value,
                default => throw new InstallerException('Dotenv values must be scalar', 'CONFIG_INVALID'),
            };
            $escaped = str_replace(["\\", "\n", "\r", '"'], ["\\\\", '\\n', '\\r', '\\"'], $scalar);
            $lines[] = $key . '="' . $escaped . '"';
        }
        return implode("\n", $lines) . "\n";
    }
}

final class ValueResolver
{
    private const FIXED = ['app.url', 'target.url', 'generated.app_key', 'database.driver', 'database.host', 'database.port', 'database.name', 'database.user', 'database.password'];

    public static function source(string $source, array $values): mixed
    {
        if (!in_array($source, self::FIXED, true) && !preg_match('/^input\.[a-z][a-z0-9_]{0,63}$/', $source)) throw new InstallerException('Value source is not allowlisted', 'CONFIG_INVALID');
        if (!array_key_exists($source, $values)) throw new InstallerException('Configuration value is missing', 'CONFIG_INVALID');
        return $values[$source];
    }

    public static function generatedAppKey(): string
    {
        return 'base64:' . base64_encode(random_bytes(32));
    }

    public static function migrationParameter(array $parameter, array $values): mixed
    {
        $hasSource = array_key_exists('source', $parameter);
        $hasValue = array_key_exists('value', $parameter);
        if ($hasSource === $hasValue) throw new InstallerException('Migration parameter must contain exactly one value source or literal', 'MIGRATION_INVALID');
        if ($hasValue) {
            if (array_keys($parameter) !== ['value'] || !(is_null($parameter['value']) || is_scalar($parameter['value']))) {
                throw new InstallerException('Migration literal must be a JSON scalar', 'MIGRATION_INVALID');
            }
            return $parameter['value'];
        }
        $value = self::source((string)($parameter['source'] ?? ''), $values);
        $transform = $parameter['transform'] ?? null;
        if ($transform === null) return $value;
        $requested = $transform === 'password_hash' ? ($parameter['algorithm'] ?? null) : $transform;
        $algorithm = match ($requested) {
            'bcrypt' => PASSWORD_BCRYPT,
            'argon2id' => defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : throw new InstallerException('Argon2id is not supported by this PHP build', 'PREFLIGHT_FAILED'),
            default => throw new InstallerException('Password transform is unsupported', 'MIGRATION_INVALID'),
        };
        $hashed = password_hash((string)$value, $algorithm);
        if (!is_string($hashed)) throw new InstallerException('Password hashing failed', 'MIGRATION_INVALID');
        return $hashed;
    }
}

final class MigrationReader
{
    private const MAX_JSON_BYTES = 8 * 1024 * 1024;
    private const MAX_JSONL_BYTES = 4 * 1024 * 1024;
    private const MAX_LINE_BYTES = 1024 * 1024;

    public static function operations(string $archive, array $manifest): \Generator
    {
        $zip = new \ZipArchive();
        if ($zip->open($archive, \ZipArchive::RDONLY) !== true) throw new InstallerException('Migration archive cannot be opened', 'MIGRATION_INVALID');
        try {
            foreach (($manifest['database']['migrations'] ?? []) as $migration) {
                $file = is_array($migration) ? ($migration['path'] ?? '') : $migration;
                if (!ArchiveInspector::isSafePath((string)$file) || !preg_match('/\.jsonl?$/', (string)$file)) {
                    throw new InstallerException('Migration path is invalid', 'MIGRATION_INVALID');
                }
                if (str_ends_with((string)$file, '.jsonl')) {
                    yield from self::jsonLines($zip, (string)$file);
                    continue;
                }
                $stat = $zip->statName((string)$file, \ZipArchive::FL_UNCHANGED);
                $declaredBytes = is_array($stat) ? ($stat['size'] ?? null) : null;
                if (!is_int($declaredBytes) || $declaredBytes < 0 || $declaredBytes > self::MAX_JSON_BYTES) {
                    throw new InstallerException('Migration file is missing or too large', 'MIGRATION_INVALID');
                }
                $content = $zip->getFromName((string)$file);
                if ($content === false || strlen($content) > self::MAX_JSON_BYTES) throw new InstallerException('Migration file is missing or too large', 'MIGRATION_INVALID');
                try { $decoded = json_decode($content, true, 64, JSON_THROW_ON_ERROR); }
                catch (\JsonException) { throw new InstallerException('Migration JSON is invalid', 'MIGRATION_INVALID'); }
                foreach (is_array($decoded) && array_is_list($decoded) ? $decoded : [$decoded] as $operation) {
                    if (!is_array($operation)) throw new InstallerException('Migration operation is invalid', 'MIGRATION_INVALID');
                    yield $operation;
                }
            }
        } finally { $zip->close(); }
    }

    private static function jsonLines(\ZipArchive $zip, string $file): \Generator
    {
        $stream = $zip->getStream($file);
        if ($stream === false) throw new InstallerException('Migration file is missing', 'MIGRATION_INVALID');
        $bytes = 0;
        try {
            while (($line = fgets($stream, self::MAX_LINE_BYTES + 2)) !== false) {
                $lineBytes = strlen($line); $bytes += $lineBytes;
                if ($lineBytes > self::MAX_LINE_BYTES || $bytes > self::MAX_JSONL_BYTES
                    || (!str_ends_with($line, "\n") && !feof($stream))) {
                    throw new InstallerException('Migration JSONL line or file is too large', 'MIGRATION_INVALID');
                }
                $line = trim($line);
                if ($line === '') continue;
                try { $operation = json_decode($line, true, 64, JSON_THROW_ON_ERROR); }
                catch (\JsonException) { throw new InstallerException('Migration JSONL is invalid', 'MIGRATION_INVALID'); }
                if (!is_array($operation) || array_is_list($operation)) throw new InstallerException('Migration operation is invalid', 'MIGRATION_INVALID');
                yield $operation;
            }
        } finally { fclose($stream); }
    }
}

final class MigrationValidator
{
    public static function placeholderCount(string $sql): int
    {
        $count = 0; $quote = null; $lineComment = false; $blockComment = false; $length = strlen($sql);
        for ($index = 0; $index < $length; $index++) {
            $character = $sql[$index]; $next = $index + 1 < $length ? $sql[$index + 1] : '';
            if ($lineComment) {
                if ($character === "\n" || $character === "\r") $lineComment = false;
                continue;
            }
            if ($blockComment) {
                if ($character === '*' && $next === '/') { $blockComment = false; $index++; }
                continue;
            }
            if ($quote !== null) {
                if ($quote === ']' && $character === ']') {
                    if ($next === ']') { $index++; continue; }
                    $quote = null; continue;
                }
                if ($character === '\\' && $quote !== '`' && $index + 1 < $length) { $index++; continue; }
                if ($character === $quote) {
                    if ($next === $quote) { $index++; continue; }
                    $quote = null;
                }
                continue;
            }
            if (($character === '-' && $next === '-') || $character === '#') {
                $lineComment = true;
                if ($character === '-') $index++;
                continue;
            }
            if ($character === '/' && $next === '*') { $blockComment = true; $index++; continue; }
            if (in_array($character, ["'", '"', '`'], true)) { $quote = $character; continue; }
            if ($character === '[') { $quote = ']'; continue; }
            if ($character === '?') $count++;
        }
        return $count;
    }

    public static function assertSafeSql(string $sql): void
    {
        $executable = self::executableSql($sql);
        $unsafeClause = '/\b(?:DROP|TRUNCATE|RENAME|USE|DEFINER|GRANT|REVOKE|CREATE\s+(?:USER|ROLE|PROCEDURE|FUNCTION|TRIGGER|EVENT|ASSEMBLY)|ALTER\s+ASSEMBLY|INSTALL\s+(?:PLUGIN|COMPONENT)|UNINSTALL\s+(?:PLUGIN|COMPONENT)|LOAD\s+DATA|BULK\s+INSERT|OUTFILE|DUMPFILE|INFILE|ATTACH|DETACH|PRAGMA|VACUUM|PREPARE|EXECUTE|DEALLOCATE|CALL|HANDLER|DELIMITER)\b/i';
        $unsafeFunction = '/\b(?:LOAD_FILE|PG_READ_FILE|PG_READ_BINARY_FILE|PG_LS_DIR|PG_LS_LOGDIR|PG_LS_WALDIR|PG_LS_ARCHIVE_STATUSDIR|PG_LS_LOGICALMAPDIR|PG_LS_LOGICALSNAPDIR|PG_LS_REPLSLOTDIR|PG_LS_TMPDIR|PG_STAT_FILE|PG_FILE_WRITE|PG_FILE_SYNC|PG_FILE_RENAME|PG_FILE_UNLINK|PG_LOGDIR_LS|LO_IMPORT|LO_EXPORT|READFILE|WRITEFILE|LOAD_EXTENSION|OPENROWSET|OPENDATASOURCE|OPENQUERY|XP_CMDSHELL)\s*\(/i';
        if (preg_match($unsafeClause, $executable) || preg_match($unsafeFunction, $executable)) {
            throw new InstallerException('Migration SQL contains an unsafe executable clause', 'MIGRATION_INVALID');
        }
        if (preg_match('/^INSERT\s+INTO\b/i', $executable)
            && (!preg_match('/\bVALUES\s*\(/i', $executable) || preg_match('/\bSELECT\b/i', $executable))) {
            throw new InstallerException('Migration INSERT SQL must use prepared literal VALUES', 'MIGRATION_INVALID');
        }
    }

    private static function executableSql(string $sql): string
    {
        $result = ''; $quote = null; $lineComment = false; $blockComment = false; $length = strlen($sql);
        for ($index = 0; $index < $length; $index++) {
            $character = $sql[$index]; $next = $index + 1 < $length ? $sql[$index + 1] : '';
            if ($lineComment) {
                if ($character === "\n" || $character === "\r") { $lineComment = false; $result .= $character; }
                else $result .= ' ';
                continue;
            }
            if ($blockComment) {
                if ($character === '*' && $next === '/') { $result .= '  '; $blockComment = false; $index++; }
                else $result .= ' ';
                continue;
            }
            if ($quote !== null) {
                $result .= ' ';
                if ($quote === ']' && $character === ']') {
                    if ($next === ']') { $result .= ' '; $index++; }
                    else $quote = null;
                    continue;
                }
                if ($character === '\\' && $quote !== '`' && $index + 1 < $length) { $result .= ' '; $index++; continue; }
                if ($character === $quote) {
                    if ($next === $quote) { $result .= ' '; $index++; }
                    else $quote = null;
                }
                continue;
            }
            if (($character === '-' && $next === '-') || $character === '#') {
                $lineComment = true; $result .= $character === '-' ? '  ' : ' ';
                if ($character === '-') $index++;
                continue;
            }
            if ($character === '/' && $next === '*') { $blockComment = true; $result .= '  '; $index++; continue; }
            if (in_array($character, ["'", '"', '`'], true)) { $quote = $character; $result .= ' '; continue; }
            if ($character === '[') { $quote = ']'; $result .= ' '; continue; }
            $result .= $character;
        }
        return $result;
    }

    public static function mongoCommand(array $command): array
    {
        $keys = array_keys($command); $name = $keys[0] ?? '';
        $allowed = match ($name) {
            'create' => ['create'],
            'insert' => ['insert', 'documents', 'ordered'],
            'createIndexes' => ['createIndexes', 'indexes'],
            'collMod' => ['collMod', 'validator', 'validationLevel', 'validationAction'],
            default => throw new InstallerException('MongoDB migration command is unsafe', 'MIGRATION_INVALID'),
        };
        if (array_diff($keys, $allowed) !== []) throw new InstallerException('MongoDB migration command contains an unknown field', 'MIGRATION_INVALID');
        if (!is_string($command[$name] ?? null) || !preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/', $command[$name])) {
            throw new InstallerException('MongoDB collection name is invalid', 'MIGRATION_INVALID');
        }
        if ($name === 'insert' && (!isset($command['documents']) || !is_array($command['documents']) || count($command['documents']) < 1 || count($command['documents']) > 1000)) {
            throw new InstallerException('MongoDB insert documents are invalid', 'MIGRATION_INVALID');
        }
        if ($name === 'createIndexes' && (!isset($command['indexes']) || !is_array($command['indexes']) || count($command['indexes']) < 1 || count($command['indexes']) > 100)) {
            throw new InstallerException('MongoDB indexes are invalid', 'MIGRATION_INVALID');
        }
        if ($name === 'collMod' && !array_key_exists('validator', $command)) throw new InstallerException('MongoDB collMod requires a validator', 'MIGRATION_INVALID');
        self::mongoValue($command);
        return $command;
    }

    private static function mongoValue(mixed $value, int $depth = 0): void
    {
        if ($depth > 32) throw new InstallerException('MongoDB migration value exceeds the nesting limit', 'MIGRATION_INVALID');
        if ($value === null || is_string($value) || is_bool($value) || is_int($value)) return;
        if (is_float($value)) {
            if (!is_finite($value)) throw new InstallerException('MongoDB migration number is invalid', 'MIGRATION_INVALID');
            return;
        }
        if (!is_array($value) || count($value) > 1000) throw new InstallerException('MongoDB migration value is invalid', 'MIGRATION_INVALID');
        foreach ($value as $key => $nested) {
            if (is_string($key) && ($key === '' || strlen($key) > 256 || preg_match('/[\x00-\x1f\x7f]/', $key)
                || preg_match('/^(?:\$where|mapReduce|eval|function)$/i', $key))) {
                throw new InstallerException('MongoDB migration field is unsafe', 'MIGRATION_INVALID');
            }
            self::mongoValue($nested, $depth + 1);
        }
    }
}

final class DatabaseSession
{
    private const RECOVERY_OBJECT = '__scriptbox_install_recovery';

    private function __construct(private readonly string $driver, private readonly ?\PDO $pdo, private readonly mixed $mongo = null) {}

    public static function connect(array $config): self
    {
        $driver = (string)($config['driver'] ?? 'none');
        if ($driver === 'none') return new self('none', null);
        if ($driver === 'mongodb') {
            if (!class_exists('MongoDB\\Driver\\Manager')) throw new InstallerException('MongoDB extension is not installed', 'DATABASE_EXTENSION_MISSING');
            $uri = (string)($config['uri'] ?? '');
            if (!str_starts_with($uri, 'mongodb://') && !str_starts_with($uri, 'mongodb+srv://')) throw new InstallerException('MongoDB URI is invalid', 'DATABASE_CONFIG_INVALID');
            return new self($driver, null, new \MongoDB\Driver\Manager($uri));
        }
        $map = ['mysql' => 'mysql', 'mariadb' => 'mysql', 'pgsql' => 'pgsql', 'sqlite' => 'sqlite', 'sqlsrv' => 'sqlsrv'];
        if (!isset($map[$driver])) throw new InstallerException('Database driver is unsupported', 'DATABASE_UNSUPPORTED');
        $pdoDriver = $map[$driver];
        if (!in_array($pdoDriver, \PDO::getAvailableDrivers(), true)) throw new InstallerException('Required PDO driver is not installed', 'DATABASE_EXTENSION_MISSING');
        if ($driver === 'sqlite') {
            $file = (string)($config['path'] ?? '');
            if ($file === '' || !str_starts_with($file, DIRECTORY_SEPARATOR)) throw new InstallerException('SQLite path must be absolute', 'DATABASE_CONFIG_INVALID');
            $dsn = 'sqlite:' . $file;
        } else {
            $host = (string)($config['host'] ?? '127.0.0.1');
            $port = (int)($config['port'] ?? ($driver === 'pgsql' ? 5432 : ($driver === 'sqlsrv' ? 1433 : 3306)));
            $database = (string)($config['name'] ?? '');
            if (!preg_match('/^[A-Za-z0-9_-]{1,64}$/', $database)) throw new InstallerException('Database name is invalid', 'DATABASE_CONFIG_INVALID');
            $dsn = $pdoDriver . ':host=' . $host . ';port=' . $port . ';dbname=' . $database;
            if ($pdoDriver === 'mysql') $dsn .= ';charset=utf8mb4';
        }
        $pdo = new \PDO($dsn, (string)($config['user'] ?? ''), (string)($config['password'] ?? ''), [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        return new self($driver, $pdo);
    }

    public function assertEmpty(array $config): void
    {
        if ($this->driver === 'none') return;
        if ($this->driver === 'mongodb') {
            $database = (string)($config['name'] ?? '');
            $cursor = $this->mongo->executeCommand($database, new \MongoDB\Driver\Command(['listCollections' => 1, 'nameOnly' => true]));
            foreach ($cursor as $_) throw new InstallerException('Database must be empty', 'DATABASE_NOT_EMPTY');
            return;
        }
        $query = match ($this->driver) {
            'mysql', 'mariadb' => 'SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()',
            'pgsql' => "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema')",
            'sqlsrv' => "SELECT COUNT(*) FROM sys.tables",
            'sqlite' => "SELECT COUNT(*) FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%'",
        };
        if ((int)$this->pdo->query($query)->fetchColumn() !== 0) throw new InstallerException('Database must be empty', 'DATABASE_NOT_EMPTY');
    }

    public function applyOperations(iterable $operations, array $config, array $runtimeValues = []): void
    {
        foreach ($operations as $operation) {
                if ($this->driver === 'none') throw new InstallerException('Package requires database operations', 'DATABASE_REQUIRED');
                if (!is_array($operation) || ($operation['driver'] ?? null) !== $this->driver) throw new InstallerException('Migration driver does not match', 'MIGRATION_INVALID');
                if ($this->driver === 'mongodb') {
                    $command = $operation['command'] ?? null;
                    if (!is_array($command)) throw new InstallerException('MongoDB operation is unsafe', 'MIGRATION_INVALID');
                    $this->mongo->executeCommand((string)$config['name'], new \MongoDB\Driver\Command(MigrationValidator::mongoCommand($command)));
                } else {
                    $sql = rtrim(trim((string)($operation['sql'] ?? '')), ';');
                    if ($sql === '' || str_contains($sql, "\0") || str_contains($sql, ';') || !preg_match('/^(CREATE\s+(?:TABLE|INDEX|VIEW)|ALTER\s+TABLE|INSERT\s+INTO|UPDATE\s+)/i', $sql)) throw new InstallerException('Migration operation is unsafe', 'MIGRATION_INVALID');
                    MigrationValidator::assertSafeSql($sql);
                    $parameters = $operation['parameters'] ?? [];
                    if (!is_array($parameters) || count($parameters) > 1000) throw new InstallerException('Migration parameters are invalid', 'MIGRATION_INVALID');
                    if (MigrationValidator::placeholderCount($sql) !== count($parameters)) throw new InstallerException('Migration parameter count does not match', 'MIGRATION_INVALID');
                    $resolved = [];
                    foreach ($parameters as $parameter) {
                        if (!is_array($parameter)) throw new InstallerException('Migration parameter is invalid', 'MIGRATION_INVALID');
                        $resolved[] = ValueResolver::migrationParameter($parameter, $runtimeValues);
                    }
                    $statement = $this->pdo->prepare($sql);
                    foreach ($resolved as $index => $value) {
                        $type = match (true) {
                            $value === null => \PDO::PARAM_NULL,
                            is_bool($value) => \PDO::PARAM_BOOL,
                            is_int($value) => \PDO::PARAM_INT,
                            is_float($value), is_string($value) => \PDO::PARAM_STR,
                            default => throw new InstallerException('Migration parameter must resolve to a scalar', 'MIGRATION_INVALID'),
                        };
                        $statement->bindValue($index + 1, is_float($value) ? (string)$value : $value, $type);
                    }
                    $statement->execute();
                }
            }
    }

    public function createRecoveryMarker(array $config, string $marker): void
    {
        if ($this->driver === 'none') return;
        if (!preg_match('/^[a-f0-9]{64}$/', $marker)) throw new InstallerException('Database recovery marker is invalid', 'DATABASE_RECOVERY_FAILED');
        if ($this->driver === 'mongodb') {
            $database = (string)($config['name'] ?? '');
            $this->mongo->executeCommand($database, new \MongoDB\Driver\Command(['create' => self::RECOVERY_OBJECT]));
            $this->mongo->executeCommand($database, new \MongoDB\Driver\Command(['insert' => self::RECOVERY_OBJECT, 'documents' => [['_id' => 'marker', 'value' => $marker]]]));
            return;
        }
        $create = match ($this->driver) {
            'mysql', 'mariadb' => 'CREATE TABLE `' . self::RECOVERY_OBJECT . '` (`marker` VARCHAR(64) NOT NULL PRIMARY KEY)',
            'pgsql', 'sqlite' => 'CREATE TABLE "' . self::RECOVERY_OBJECT . '" ("marker" VARCHAR(64) NOT NULL PRIMARY KEY)',
            'sqlsrv' => 'CREATE TABLE [' . self::RECOVERY_OBJECT . '] ([marker] VARCHAR(64) NOT NULL PRIMARY KEY)',
        };
        $this->pdo->exec($create);
        $statement = $this->pdo->prepare('INSERT INTO ' . $this->quotedRecoveryObject() . ' (marker) VALUES (?)');
        $statement->execute([$marker]);
    }

    public function recoveryMarkerMatches(array $config, string $expectedDigest): bool
    {
        if (!preg_match('/^[a-f0-9]{64}$/', $expectedDigest)) return false;
        try {
            if ($this->driver === 'mongodb') {
                $cursor = $this->mongo->executeQuery((string)($config['name'] ?? '') . '.' . self::RECOVERY_OBJECT, new \MongoDB\Driver\Query(['_id' => 'marker'], ['limit' => 1]));
                foreach ($cursor as $document) return hash_equals($expectedDigest, hash('sha256', (string)($document->value ?? '')));
                return false;
            }
            if ($this->pdo === null) return false;
            $value = $this->pdo->query('SELECT marker FROM ' . $this->quotedRecoveryObject())->fetchColumn();
            return is_string($value) && hash_equals($expectedDigest, hash('sha256', $value));
        } catch (Throwable) { return false; }
    }

    public function dropRecoveryMarker(array $config): void
    {
        if ($this->driver === 'none') return;
        if ($this->driver === 'mongodb') {
            $this->mongo->executeCommand((string)($config['name'] ?? ''), new \MongoDB\Driver\Command(['drop' => self::RECOVERY_OBJECT]));
            return;
        }
        $this->pdo?->exec('DROP TABLE ' . $this->quotedRecoveryObject());
    }

    private function quotedRecoveryObject(): string
    {
        return match ($this->driver) {
            'mysql', 'mariadb' => '`' . self::RECOVERY_OBJECT . '`',
            'sqlsrv' => '[' . self::RECOVERY_OBJECT . ']',
            default => '"' . self::RECOVERY_OBJECT . '"',
        };
    }

    public function resetToEmpty(array $config): void
    {
        if ($this->driver === 'none') return;
        if ($this->driver === 'mongodb') {
            $database = (string)($config['name'] ?? '');
            $cursor = $this->mongo->executeCommand($database, new \MongoDB\Driver\Command(['listCollections' => 1, 'nameOnly' => true]));
            foreach ($cursor as $collection) $this->mongo->executeCommand($database, new \MongoDB\Driver\Command(['drop' => $collection->name]));
            return;
        }
        if ($this->driver === 'sqlite') {
            $objects = $this->pdo->query("SELECT type,name FROM sqlite_master WHERE type IN ('table','view','trigger') AND name NOT LIKE 'sqlite_%'")->fetchAll(\PDO::FETCH_ASSOC);
            foreach (array_reverse($objects) as $object) $this->pdo->exec('DROP ' . strtoupper($object['type']) . ' IF EXISTS "' . str_replace('"', '""', $object['name']) . '"');
            return;
        }
        if (in_array($this->driver, ['mysql', 'mariadb'], true)) {
            $this->pdo->exec('SET FOREIGN_KEY_CHECKS=0');
            $objects = $this->pdo->query('SELECT table_name, table_type FROM information_schema.tables WHERE table_schema = DATABASE()')->fetchAll(\PDO::FETCH_ASSOC);
            foreach ($objects as $object) $this->pdo->exec('DROP ' . ($object['TABLE_TYPE'] === 'VIEW' ? 'VIEW' : 'TABLE') . ' IF EXISTS `' . str_replace('`', '``', $object['TABLE_NAME']) . '`');
            $this->pdo->exec('SET FOREIGN_KEY_CHECKS=1');
            return;
        }
        if ($this->driver === 'pgsql') {
            $this->pdo->exec('DROP SCHEMA public CASCADE; CREATE SCHEMA public');
            return;
        }
        $tables = $this->pdo->query('SELECT name FROM sys.tables')->fetchAll(\PDO::FETCH_COLUMN);
        foreach ($tables as $table) $this->pdo->exec('DROP TABLE [' . str_replace(']', ']]', $table) . ']');
    }
}

final class InstallEngine
{
    public function __construct(
        private readonly ApiClient $api,
        private readonly StateStore $state,
        private readonly string $target,
        private readonly array $publicKeys,
        private readonly ?string $ignoredControlDirectory = null,
    ) {}

    public function install(array $input): array
    {
        $lock = $this->state->lock();
        $promoted = [];
        $database = null;
        $databaseChanged = false;
        $activated = false;
        $license = null;
        $health = null;
        try {
            $status = $this->state->read('status');
            if (in_array($status['state'] ?? '', ['complete', 'recovery_required'], true)) throw new InstallerException('Installer is permanently locked', 'INSTALLER_LOCKED', 409);
            if ($this->journalHasMutation()) {
                $this->phase('recovery_required', ['state' => 'recovery_required', 'code' => 'INTERRUPTED_MUTATION']);
                throw new InstallerException('An interrupted installation requires recovery before retrying', 'RECOVERY_REQUIRED', 409);
            }
            $this->assertTargetEmpty();
            $this->phase('preflight');
            $capabilities = Preflight::capabilities($this->target);
            if (!$capabilities['php']['supported'] || in_array(false, $capabilities['required'], true)) throw new InstallerException('Server does not meet installer requirements', 'PREFLIGHT_FAILED');
            $origin = $this->httpsOrigin((string)($input['origin'] ?? ''));
            $applicationUrl = $this->httpsApplicationUrl((string)($input['target_url'] ?? $origin));
            $token = (string)($input['token'] ?? '');
            $renewSession = is_callable($input['renew_session'] ?? null) ? $input['renew_session'] : null;
            $license = $this->sessionRequest('POST', '/licenses/free', [
                'script_id' => $input['script_id'] ?? null, 'version' => $input['version'] ?? null,
                'capabilities' => $capabilities,
            ], $token, $origin, $renewSession);
            $this->phase('license', ['license_id' => $license['id']]);
            $artifactId = (string)($license['artifact_id'] ?? '');
            $this->phase('authorization');
            $authorization = $this->sessionRequest('POST', '/artifacts/' . rawurlencode($artifactId) . '/authorize', ['license_id' => $license['id']], $token, $origin, $renewSession);
            $this->phase('verify');
            $signed = Crypto::verifyEnvelope($authorization['manifest'], $this->publicKeys, null, false);
            $manifest = $signed['manifest'] ?? null;
            if (!is_array($manifest)) throw new InstallerException('Signed package manifest is missing', 'MANIFEST_INVALID');
            $signedArtifact = $signed['artifact'] ?? null;
            if (!is_array($signedArtifact) || (int)($signedArtifact['bytes'] ?? -1) !== (int)$authorization['bytes'] || !hash_equals((string)($signedArtifact['sha256'] ?? ''), (string)$authorization['sha256'])) {
                throw new InstallerException('Artifact authorization differs from signed metadata', 'ARTIFACT_METADATA_MISMATCH');
            }
            ArchiveInspector::validateManifest($manifest);
            Preflight::assertPackageRequirements($manifest);
            if (isset($signed['profile_sha256']) && (!is_string($signed['profile_sha256']) || !hash_equals($signed['profile_sha256'], ArchiveInspector::profileHash($manifest)))) {
                throw new InstallerException('Package profile differs from signed metadata', 'PROFILE_MISMATCH');
            }
            $archive = $this->state->path('artifact') . '.zip';
            $this->phase('download');
            $renewArtifact = function () use ($artifactId, $license, &$token, $origin, $renewSession, $manifest, $signedArtifact): string {
                $renewed = $this->sessionRequest('POST', '/artifacts/' . rawurlencode($artifactId) . '/authorize', ['license_id' => $license['id']], $token, $origin, $renewSession);
                $payload = Crypto::verifyEnvelope($renewed['manifest'], $this->publicKeys, null, false);
                if (($payload['manifest'] ?? null) !== $manifest || ($payload['artifact']['sha256'] ?? null) !== ($signedArtifact['sha256'] ?? null)
                    || (int)($renewed['bytes'] ?? -1) !== (int)($signedArtifact['bytes'] ?? -2)) {
                    throw new InstallerException('Renewed artifact authorization differs from signed metadata', 'ARTIFACT_METADATA_MISMATCH');
                }
                return (string)($renewed['token'] ?? '');
            };
            $this->api->download((string)$authorization['token'], $archive, (int)$authorization['bytes'], (string)$authorization['sha256'], $renewArtifact);
            $this->phase('inspect');
            $inspected = ArchiveInspector::inspect($archive);
            if ($inspected['manifest'] !== $manifest) throw new InstallerException('ZIP manifest differs from signed manifest', 'MANIFEST_MISMATCH');
            $stage = $this->state->root . '/stage';
            $this->removeTree($stage);
            mkdir($stage, 0700, true);
            $this->phase('extract');
            $this->extractPayload($archive, $stage);
            $dbConfig = is_array($input['database'] ?? null) ? $input['database'] : ['driver' => 'none'];
            if (($dbConfig['driver'] ?? 'none') !== ($manifest['database']['driver'] ?? 'none')) throw new InstallerException('Selected database does not match package', 'DATABASE_MISMATCH');
            $this->phase('database');
            $database = DatabaseSession::connect($dbConfig);
            $database->assertEmpty($dbConfig);
            $runtime = $this->configurationValues($input, $applicationUrl);
            $this->phase('migrate');
            if (($manifest['database']['migrations'] ?? []) !== []) {
                $databaseChanged = true;
                $marker = bin2hex(random_bytes(32));
                $this->state->write('recovery', ['target' => $this->target, 'database_changed' => true, 'database_driver' => (string)($dbConfig['driver'] ?? 'none'), 'database_marker_sha256' => hash('sha256', $marker)]);
                $this->state->appendJournal(['phase' => 'database_mutation_started']);
                $database->createRecoveryMarker($dbConfig, $marker);
                $database->applyOperations(MigrationReader::operations($archive, $manifest), $dbConfig, $runtime);
            }
            $this->phase('configure');
            foreach (($manifest['configuration'] ?? []) as $output) ConfigurationWriter::write($stage, $output, $runtime);
            $this->phase('permissions');
            $this->applyWritablePaths($stage, $manifest);
            $this->phase('promote');
            if ($this->state->read('recovery') === []) $this->state->write('recovery', ['target' => $this->target, 'database_changed' => false, 'database_driver' => 'none']);
            $this->promote($stage, $promoted);
            $this->phase('health');
            $health = $this->healthCheck($applicationUrl, (string)($manifest['health_check']['path'] ?? '/'));
            $this->phase('activate');
            $this->sessionRequest('POST', '/licenses/' . rawurlencode((string)$license['id']) . '/activate', ['health' => $health], $token, $origin, $renewSession);
            $activated = true;
            $this->phase('cleanup');
            @unlink($archive);
            $this->removeTree($stage);
            if ($databaseChanged && $database !== null) $database->dropRecoveryMarker($dbConfig);
            $this->state->clearJournal();
            $this->state->remove('recovery');
            $this->phase('complete', ['state' => 'complete', 'license_id' => $license['id'], 'script_id' => $manifest['script_id'], 'version' => $manifest['version']]);
            return ['state' => 'complete', 'license_id' => $license['id'], 'health' => $health];
        } catch (Throwable $error) {
            if (!self::rollbackAllowedAfterActivation($activated) && is_array($license) && is_array($health)) {
                try {
                    $this->phase('complete', [
                        'state' => 'complete', 'license_id' => $license['id'],
                        'code' => 'POST_ACTIVATION_CLEANUP_INCOMPLETE',
                    ]);
                } catch (Throwable) {
                    // Never erase an activated application because local cleanup state could not be recorded.
                }
                return ['state' => 'complete', 'license_id' => $license['id'], 'health' => $health, 'cleanup_warning' => 'POST_ACTIVATION_CLEANUP_INCOMPLETE'];
            }
            $cleanupOkay = $this->rollbackFiles($promoted);
            if ($databaseChanged && $database !== null) {
                try { $database->resetToEmpty($input['database']); } catch (Throwable) { $cleanupOkay = false; }
            }
            if ($cleanupOkay) {
                if (!self::preservesPartialDownloadFor($error)) @unlink($this->state->path('artifact') . '.zip');
                $this->removeTree($this->state->root . '/stage');
                try { $this->state->clearJournal(); $this->state->remove('recovery'); } catch (Throwable) { $cleanupOkay = false; }
            }
            $this->phase($cleanupOkay ? 'failed' : 'recovery_required', [
                'state' => $cleanupOkay ? 'failed' : 'recovery_required',
                'code' => $error instanceof InstallerException ? $error->stableCode : 'INSTALL_FAILED',
            ]);
            throw $error;
        } finally { $this->state->unlock($lock); }
    }

    public static function preservesPartialDownloadFor(Throwable $error): bool
    {
        return $error instanceof InstallerException
            && in_array($error->stableCode, ['DOWNLOAD_FAILED', 'DOWNLOAD_AUTHORIZATION_FAILED'], true);
    }

    public static function rollbackAllowedAfterActivation(bool $activated): bool
    {
        return !$activated;
    }

    public function recover(array $input = []): array
    {
        $lock = $this->state->lock();
        try {
            $status = $this->state->read('status');
            $events = $this->state->readJournal();
            if (($status['state'] ?? '') === 'complete') return $status;
            if (($status['state'] ?? '') !== 'recovery_required' && !$this->journalHasMutation($events)) return $status + ['state' => $status['state'] ?? 'idle'];
            $recovery = $this->state->read('recovery');
            $root = (string)($recovery['target'] ?? $this->target);
            if (!is_dir($root) || is_link($root)) throw new InstallerException('Recovery target is unavailable', 'RECOVERY_MANUAL', 409);
            $filesOkay = $this->rollbackJournal($events, $root);
            $databaseOkay = !($recovery['database_changed'] ?? false);
            if (!$databaseOkay && is_array($input['database'] ?? null)) {
                $databaseInput = $input['database'];
                if (($databaseInput['driver'] ?? null) !== ($recovery['database_driver'] ?? null)) throw new InstallerException('Recovery database driver does not match', 'RECOVERY_MANUAL', 409);
                try {
                    $recoveryDatabase = DatabaseSession::connect($databaseInput);
                    if (!$recoveryDatabase->recoveryMarkerMatches($databaseInput, (string)($recovery['database_marker_sha256'] ?? ''))) throw new InstallerException('Recovery database identity does not match', 'RECOVERY_MANUAL', 409);
                    $recoveryDatabase->resetToEmpty($databaseInput); $databaseOkay = true;
                } catch (Throwable) { $databaseOkay = false; }
            }
            if (!$filesOkay || !$databaseOkay) {
                $this->phase('recovery_required', ['state' => 'recovery_required', 'code' => $databaseOkay ? 'ROLLBACK_INCOMPLETE' : 'DATABASE_RECOVERY_REQUIRED']);
                throw new InstallerException('Recovery requires valid database credentials and an empty-schema reset', 'RECOVERY_MANUAL', 409);
            }
            @unlink($this->state->path('artifact') . '.zip');
            $this->removeTree($this->state->root . '/stage');
            $this->state->clearJournal();
            $this->state->remove('recovery');
            $recovered = ['state' => 'failed', 'phase' => 'failed', 'code' => 'ROLLBACK_COMPLETE', 'updated_at' => gmdate(DATE_ATOM)];
            $this->state->write('status', $recovered);
            return $recovered;
        } finally { $this->state->unlock($lock); }
    }

    private function phase(string $phase, array $extra = []): void
    {
        $event = ['phase' => $phase, 'updated_at' => gmdate(DATE_ATOM)] + $extra;
        $this->state->appendJournal($event);
        $this->state->write('status', $event + ['state' => $extra['state'] ?? 'running']);
    }

    private function sessionRequest(string $method, string $path, ?array $body, string &$token, string $origin, ?callable $renewSession): array
    {
        try { return $this->api->request($method, $path, $body, $token, $origin); }
        catch (InstallerException $error) {
            if ($error->stableCode !== 'UNAUTHORIZED' || $renewSession === null) throw $error;
            $renewed = $renewSession();
            if (!is_string($renewed) || $renewed === '') throw $error;
            $token = $renewed;
            return $this->api->request($method, $path, $body, $token, $origin);
        }
    }

    private function assertTargetEmpty(): void
    {
        foreach (scandir($this->target) ?: [] as $entry) {
            if (in_array($entry, ['.', '..', basename($_SERVER['SCRIPT_FILENAME'] ?? 'install.php')], true)) continue;
            $candidate = realpath($this->target . DIRECTORY_SEPARATOR . $entry);
            if ($this->ignoredControlDirectory !== null && $candidate !== false && realpath($this->ignoredControlDirectory) === $candidate) continue;
            if ($entry === '.well-known' && $this->treeContainsNoFiles($this->target . '/.well-known')) continue;
            throw new InstallerException('Target directory must be empty', 'TARGET_NOT_EMPTY');
        }
    }

    private function httpsOrigin(string $origin): string
    {
        $url = parse_url($origin);
        if (!is_array($url) || ($url['scheme'] ?? '') !== 'https' || empty($url['host']) || isset($url['user']) || isset($url['path']) && !in_array($url['path'], ['', '/'], true)) throw new InstallerException('A public HTTPS origin is required', 'ORIGIN_INVALID');
        return 'https://' . strtolower($url['host']) . (isset($url['port']) ? ':' . (int)$url['port'] : '');
    }

    private function httpsApplicationUrl(string $url): string
    {
        $parsed = parse_url($url);
        $path = (string)($parsed['path'] ?? '');
        if (!is_array($parsed) || ($parsed['scheme'] ?? '') !== 'https' || empty($parsed['host']) || isset($parsed['user']) || isset($parsed['pass']) || isset($parsed['query']) || isset($parsed['fragment']) || str_contains($path, '..')) {
            throw new InstallerException('Application URL is invalid', 'ORIGIN_INVALID');
        }
        return rtrim($url, '/');
    }

    private function extractPayload(string $archive, string $stage): void
    {
        $zip = new \ZipArchive(); $zip->open($archive, \ZipArchive::RDONLY);
        try {
            for ($index = 0; $index < $zip->numFiles; $index++) {
                $name = (string)$zip->getNameIndex($index, \ZipArchive::FL_UNCHANGED);
                if (!str_starts_with($name, 'payload/')) continue;
                $relative = substr($name, 8);
                if ($relative === '') continue;
                $destination = $stage . '/' . $relative;
                if (str_ends_with($name, '/')) { if (!is_dir($destination)) mkdir($destination, 0755, true); continue; }
                if (!is_dir(dirname($destination))) mkdir(dirname($destination), 0755, true);
                $source = $zip->getStream($name); $output = fopen($destination, 'wb');
                if ($source === false || $output === false) throw new InstallerException('Package extraction failed', 'EXTRACTION_FAILED');
                stream_copy_to_stream($source, $output); fclose($source); fclose($output); chmod($destination, 0644);
            }
        } finally { $zip->close(); }
    }

    private function configurationValues(array $input, string $origin): array
    {
        $database = is_array($input['database'] ?? null) ? $input['database'] : [];
        $values = [
            'app.url' => $origin, 'target.url' => (string)($input['target_url'] ?? $origin), 'generated.app_key' => ValueResolver::generatedAppKey(),
            'database.driver' => $database['driver'] ?? 'none', 'database.host' => $database['host'] ?? '',
            'database.port' => $database['port'] ?? '', 'database.name' => $database['name'] ?? '',
            'database.user' => $database['user'] ?? '', 'database.password' => $database['password'] ?? '',
        ];
        foreach (($input['inputs'] ?? []) as $key => $value) if (preg_match('/^[a-z][a-z0-9_]{0,63}$/', (string)$key)) $values['input.' . $key] = $value;
        return $values;
    }

    private function applyWritablePaths(string $stage, array $manifest): void
    {
        foreach (($manifest['payload']['writable'] ?? []) as $writable) {
            $relative = is_array($writable) ? ($writable['path'] ?? '') : $writable;
            $mode = is_array($writable) ? (string)($writable['mode'] ?? '0770') : '0775';
            if (!ArchiveInspector::isSafePath((string)$relative)) throw new InstallerException('Writable path is unsafe', 'MANIFEST_INVALID');
            $path = $stage . '/' . $relative;
            if (!file_exists($path)) throw new InstallerException('Declared writable path is missing', 'MANIFEST_INVALID');
            if (!in_array($mode, ['0700', '0750', '0755', '0770', '0775'], true)) throw new InstallerException('Writable mode is unsafe', 'MANIFEST_INVALID');
            chmod($path, is_dir($path) ? octdec($mode) : 0660);
        }
    }

    private function promote(string $stage, array &$promoted): void
    {
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($stage, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::SELF_FIRST);
        foreach ($iterator as $item) {
            $relative = substr($item->getPathname(), strlen($stage) + 1);
            $destination = $this->target . '/' . $relative;
            if ($item->isDir()) { if (!is_dir($destination)) { $this->state->appendJournal(['phase' => 'promote_intent', 'relative' => $relative, 'directory' => true]); mkdir($destination, 0755); $promoted[] = ['path' => $destination, 'directory' => true]; $this->state->appendJournal(['phase' => 'promoted', 'relative' => $relative, 'directory' => true]); } continue; }
            if (file_exists($destination)) throw new InstallerException('Promotion would overwrite an existing file', 'TARGET_CONFLICT');
            $bytes = $item->getSize(); $sha256 = hash_file('sha256', $item->getPathname());
            if (!is_int($bytes) || !is_string($sha256)) throw new InstallerException('Cannot fingerprint a staged file', 'PROMOTION_FAILED');
            $this->state->appendJournal(['phase' => 'promote_intent', 'relative' => $relative, 'directory' => false, 'bytes' => $bytes, 'sha256' => $sha256]);
            if (!rename($item->getPathname(), $destination)) throw new InstallerException('File promotion failed', 'PROMOTION_FAILED');
            $promoted[] = ['path' => $destination, 'directory' => false]; $this->state->appendJournal(['phase' => 'promoted', 'relative' => $relative, 'directory' => false, 'bytes' => $bytes, 'sha256' => $sha256]);
        }
    }

    private function healthCheck(string $origin, string $path): array
    {
        if (!str_starts_with($path, '/') || str_contains($path, '..')) throw new InstallerException('Health-check path is invalid', 'HEALTH_PATH_INVALID');
        $handle = curl_init($origin . $path);
        curl_setopt_array($handle, [CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => false, CURLOPT_TIMEOUT => 15, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS]);
        curl_exec($handle); $status = curl_getinfo($handle, CURLINFO_RESPONSE_CODE); curl_close($handle);
        if ($status < 200 || $status >= 400) throw new InstallerException('Application health check failed', 'HEALTH_CHECK_FAILED');
        return ['ok' => true, 'status' => $status];
    }

    private function rollbackFiles(array $files): bool
    {
        $okay = true;
        foreach (array_reverse($files) as $entry) {
            $path = $entry['path'];
            if (($entry['directory'] ?? false) ? (is_dir($path) && !rmdir($path)) : (is_file($path) && !unlink($path))) $okay = false;
        }
        return $okay;
    }

    private function journalHasMutation(?array $events = null): bool
    {
        foreach ($events ?? $this->state->readJournal() as $event) if (in_array($event['phase'] ?? '', ['database_mutation_started', 'promote_intent', 'promoted'], true)) return true;
        return false;
    }

    private function rollbackJournal(array $events, string $root): bool
    {
        $okay = true; $base = rtrim(realpath($root) ?: $root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR; $entries = [];
        foreach ($events as $event) {
            if (!in_array($event['phase'] ?? '', ['promote_intent', 'promoted'], true) || !ArchiveInspector::isSafePath((string)($event['relative'] ?? ''))) continue;
            $key = (($event['directory'] ?? false) ? 'd:' : 'f:') . $event['relative'];
            $entries[$key] ??= ['relative' => $event['relative'], 'directory' => ($event['directory'] ?? false) === true, 'completed' => false, 'bytes' => $event['bytes'] ?? null, 'sha256' => $event['sha256'] ?? null];
            if (($event['phase'] ?? '') === 'promoted') $entries[$key]['completed'] = true;
        }
        uasort($entries, function (array $left, array $right): int {
            $depth = substr_count((string)$right['relative'], '/') <=> substr_count((string)$left['relative'], '/');
            return $depth !== 0 ? $depth : ((int)$left['directory'] <=> (int)$right['directory']);
        });
        foreach ($entries as $entry) {
            $path = $base . str_replace('/', DIRECTORY_SEPARATOR, (string)$entry['relative']);
            if (!str_starts_with($path, $base)) { $okay = false; continue; }
            if ($entry['directory']) {
                if (is_dir($path) && (!$entry['completed'] || !@rmdir($path))) $okay = false;
                continue;
            }
            if (!file_exists($path)) continue;
            $bytes = filesize($path); $sha256 = hash_file('sha256', $path);
            if (!is_int($entry['bytes']) || !is_string($entry['sha256']) || $bytes !== $entry['bytes'] || !is_string($sha256) || !hash_equals($entry['sha256'], $sha256) || !@unlink($path)) $okay = false;
        }
        return $okay;
    }

    private function treeContainsNoFiles(string $root): bool
    {
        if (!is_dir($root) || is_link($root)) return false;
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS));
        foreach ($iterator as $item) if (!$item->isDir()) return false;
        return true;
    }

    private function removeTree(string $root): void
    {
        if (!is_dir($root) || is_link($root)) return;
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($iterator as $item) $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        @rmdir($root);
    }
}

final class AssetManager
{
    public function __construct(private readonly ApiClient $api, private readonly StateStore $state, private readonly array $publicKeys) {}

    public static function downloadFailureMessage(int $httpStatus, int $curlError): string
    {
        $status = $httpStatus > 0 ? 'HTTP ' . $httpStatus : 'no HTTP response';
        if ($curlError === 0) return 'UI asset download failed (' . $status . ')';
        $reason = match ($curlError) {
            6 => 'host resolution failed',
            7 => 'connection failed',
            18 => 'incomplete transfer',
            28 => 'transfer timed out',
            35, 60 => 'TLS verification failed',
            default => 'transport error',
        };
        return 'UI asset download failed (' . $status . ', cURL ' . $curlError . ': ' . $reason . ')';
    }

    public function bootstrap(bool $refresh = false): array
    {
        $cached = $this->state->read('bootstrap');
        if (!$refresh && isset($cached['envelope'])) {
            try { return Crypto::verifyEnvelope($cached['envelope'], $this->publicKeys); } catch (Throwable) {}
        }
        if ($this->publicKeys === []) throw new InstallerException('This release has no pinned production signing keys', 'SIGNING_KEYS_NOT_CONFIGURED', 503);
        $envelope = $this->api->request('GET', '/bootstrap?installer_version=1.0.0');
        $payload = Crypto::verifyEnvelope($envelope, $this->publicKeys);
        $minimum = (string)($payload['protocol']['minimum'] ?? '');
        $maximum = (string)($payload['protocol']['maximum'] ?? '');
        if ($minimum === '' || version_compare('1.0.0', $minimum, '<') || !str_starts_with($maximum, '1.')) throw new InstallerException('Installer protocol is incompatible', 'PROTOCOL_INCOMPATIBLE');
        foreach (($payload['ui']['assets'] ?? []) as $asset) $this->cacheAsset($asset);
        $this->state->write('bootstrap', ['envelope' => $envelope]);
        return $payload;
    }

    public function pathForRequest(string $requestPath): array
    {
        if (!preg_match('#^/assets/([a-f0-9]{64})\.(js|css|json|png)$#', $requestPath, $match)) throw new InstallerException('Asset not found', 'ASSET_NOT_FOUND', 404);
        $file = $this->state->root . '/asset-' . $match[1] . '.' . $match[2];
        if (!is_file($file) || !hash_equals($match[1], hash_file('sha256', $file))) throw new InstallerException('Asset not found', 'ASSET_NOT_FOUND', 404);
        $types = ['js' => 'text/javascript; charset=utf-8', 'css' => 'text/css; charset=utf-8', 'json' => 'application/json; charset=utf-8', 'png' => 'image/png'];
        return ['file' => $file, 'type' => $types[$match[2]]];
    }

    public function runtimeAssets(string $scriptName): array
    {
        $payload = $this->bootstrap();
        $prefix = rtrim($scriptName, '/');
        $result = [];
        foreach (($payload['ui']['assets'] ?? []) as $asset) {
            if (!isset($asset['role']) || !in_array($asset['type'] ?? '', ['json', 'png'], true)) continue;
            $result[(string)$asset['role']] = $prefix . '/assets/' . $asset['sha256'] . '.' . $asset['type'];
        }
        return $result;
    }

    private function cacheAsset(array $asset): void
    {
        $type = $asset['type'] ?? '';
        $hash = strtolower((string)($asset['sha256'] ?? ''));
        $bytes = (int)($asset['bytes'] ?? -1);
        $url = (string)($asset['url'] ?? '');
        if (!in_array($type, ['js', 'css', 'json', 'png'], true) || !preg_match('/^[a-f0-9]{64}$/', $hash) || $bytes < 1 || $bytes > ($type === 'png' ? 20 * 1024 : ($type === 'json' ? 5 : 50) * 1024 * 1024) || !str_starts_with($url, 'https://')) throw new InstallerException('Signed UI asset metadata is invalid', 'ASSET_METADATA_INVALID');
        $file = $this->state->root . '/asset-' . $hash . '.' . $type;
        if (is_file($file)) { Crypto::verifyFile($file, $hash, $bytes); return; }
        $temporary = $file . '.tmp';
        $output = fopen($temporary, 'wb');
        $handle = curl_init($url);
        curl_setopt_array($handle, [CURLOPT_FILE => $output, CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 1, CURLOPT_TIMEOUT => 60, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS, CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS]);
        $ok = curl_exec($handle); $status = curl_getinfo($handle, CURLINFO_RESPONSE_CODE); $curlError = curl_errno($handle); curl_close($handle); fclose($output);
        if ($ok === false || $status < 200 || $status >= 300) { @unlink($temporary); throw new InstallerException(self::downloadFailureMessage($status, $curlError), 'ASSET_DOWNLOAD_FAILED', 502); }
        Crypto::verifyFile($temporary, $hash, $bytes); chmod($temporary, 0600); rename($temporary, $file);
    }
}

final class Application
{
    public function __construct(
        private readonly ApiClient $api,
        private readonly StateStore $state,
        private readonly AssetManager $assets,
        private readonly string $target,
        private readonly array $publicKeys,
        private readonly array $buildIdentity = [],
        private readonly ?string $controlDirectory = null,
    ) {}

    public function handle(string $method, string $uri, array $headers, string $rawBody): void
    {
        $this->securityHeaders();
        $headers = array_change_key_case($headers, CASE_LOWER);
        try {
            $route = Router::resolve($method, $uri);
            if ($route === 'shell') { $this->shell(); return; }
            if ($route === 'asset') { $this->asset(parse_url($uri, PHP_URL_PATH)); return; }
            if ($route === 'ownership_proof') { $this->ownershipProof(parse_url($uri, PHP_URL_PATH)); return; }
            if ($method !== 'GET') $this->csrf($headers);
            $body = $rawBody === '' ? [] : json_decode($rawBody, true, 32, JSON_THROW_ON_ERROR);
            if (!is_array($body)) throw new InstallerException('JSON object required', 'INPUT_INVALID');
            $data = match ($route) {
                'runtime' => $this->runtime(),
                'bootstrap' => $this->assets->bootstrap((bool)($body['refresh'] ?? false)),
                'status' => InstallationRun::publicStatus($this->state->read('status', ['state' => 'idle'])),
                'preflight' => $this->preflight($body),
                'database_test' => $this->databaseTest($body),
                'session' => $this->createSession($body),
                'catalog_search' => $this->api->request('POST', '/catalog/search', $body),
                'catalog_detail' => $this->api->request('GET', '/catalog/' . rawurlencode(basename(parse_url($uri, PHP_URL_PATH))), null),
                'install' => $this->legacyInstall($body),
                'install_prepare' => $this->prepareInstall($body),
                'install_advance' => $this->advanceInstall($body),
                'install_status' => $this->installStatus($uri),
                'install_cancel' => $this->cancelInstall($body),
                'finalize' => $this->finalize($body),
                'recover' => $this->browserRecover($body),
                default => throw new InstallerException('Route not found', 'ROUTE_NOT_FOUND', 404),
            };
            $this->json(['success' => true, 'data' => $data, 'error' => null]);
        } catch (Throwable $error) {
            $diagnostic = $this->recordDiagnostic($error);
            $status = $error instanceof InstallerException ? max(400, min(599, $error->getCode())) : 500;
            $message = $status >= 500 && !($error instanceof InstallerException && str_starts_with($error->stableCode, 'MEDIA_'))
                ? 'Installer operation failed' : $error->getMessage();
            $this->json(['success' => false, 'data' => null, 'error' => ['code' => $diagnostic['code'], 'message' => $message, 'diagnostic_id' => $diagnostic['diagnostic_id']]], $status);
        }
    }

    private function runtime(): array
    {
        try { $origin = OriginDetector::detect($_SERVER, $this->state, (string)(getenv('SCRIPTBOX_TRUSTED_PROXIES') ?: '')); }
        catch (Throwable) { $origin = ['origin' => null, 'source' => null]; }
        $control = $this->controlDirectory ?? $this->target;
        $target = TargetResolver::inspect($this->target, $control, '');
        unset($target['path']);
        $verified = $this->sessionIsVerified();
        $run = $verified ? $this->state->read('run', []) : [];
        if ($verified && isset($run['run_id'])) {
            try {
                InstallationRun::assertOwner($this->state, (string)$run['run_id'], (string)$_SESSION['install_id']);
                $run = InstallationRun::status($this->state, (string)$run['run_id']);
            } catch (Throwable) { $run = []; }
        }
        return ['csrf_token' => $_SESSION['csrf'], 'capabilities' => Preflight::capabilities($this->target), 'initial_target' => $target, 'status' => InstallationRun::publicStatus($this->state->read('status', ['state' => 'idle'])), 'paid_checkout' => false,
            'installation_run' => $run,
            'session_verified' => $verified,
            'detected_origin' => $origin['origin'], 'origin_source' => $origin['source'], 'can_verify_origin' => $origin['origin'] !== null,
            'build' => $this->buildIdentity,
            'ui_assets' => $this->assets->runtimeAssets((string)($_SERVER['SCRIPT_NAME'] ?? '/install.php'))];
    }

    private function createSession(array $body): array
    {
        if (($body['consent'] ?? false) !== true) throw new InstallerException('Telemetry consent is required', 'CONSENT_REQUIRED');
        $origin = OriginDetector::detect($_SERVER, $this->state, (string)(getenv('SCRIPTBOX_TRUSTED_PROXIES') ?: ''))['origin'];
        $policyVersion = (string)($body['policy_version'] ?? '2026-08-19');
        $data = $this->issueRemoteSession($origin, (string)$_SESSION['install_id'], $policyVersion);
        $expiresIn = max(1, min(900, (int)($data['expires_in'] ?? 900)));
        $_SESSION['api_token'] = $data['token']; $_SESSION['origin'] = $origin; $_SESSION['api_token_expires_at'] = time() + $expiresIn; $_SESSION['policy_version'] = $policyVersion; $_SESSION['verified'] = true;
        session_regenerate_id(true);
        return ['verified' => true, 'expires_in' => $expiresIn];
    }

    private function issueRemoteSession(string $origin, string $installId, string $policyVersion): array
    {
        $proofs = new OwnershipProof($this->state, (string)($_SERVER['SCRIPT_NAME'] ?? '/install.php'));
        $proof = $proofs->create();
        try {
            return $this->api->request('POST', '/sessions/verify', [
                'install_id' => $installId, 'origin' => $origin, 'proof_id' => $proof['id'],
                'proof_digest' => $proof['digest'], 'proof_path' => $proof['path'], 'consent' => true,
                'policy_version' => $policyVersion,
            ]);
        } finally { $proofs->remove($proof['id']); }
    }

    private function preflight(array $body): array
    {
        $relative = (string)($body['target'] ?? '');
        $control = $this->controlDirectory ?? $this->target;
        $target = TargetResolver::inspect($this->target, $control, $relative === '/' ? '' : $relative);
        $path = $target['path'];
        unset($target['path']);
        $capabilities = Preflight::capabilities($target['exists'] ? $path : dirname($path));
        $profile = is_array($body['profile'] ?? null) ? $body['profile'] : [];
        $runtime = (string)($profile['runtime']['type'] ?? 'php');
        $framework = (string)($profile['framework'] ?? ($runtime === 'static' ? 'static' : 'raw_php'));
        $requiredExtensions = array_values(array_filter($profile['runtime']['extensions'] ?? [], 'is_string'));
        $missingExtensions = array_values(array_diff($requiredExtensions, get_loaded_extensions()));
        $requiredPhp = (string)($profile['runtime']['php'] ?? '>=8.3');
        $phpCompatible = $runtime !== 'php' || Preflight::supportsPhp($requiredPhp);
        $database = (string)($profile['database']['driver'] ?? 'none');
        $compatible = in_array($runtime, ['static', 'php'], true)
            && in_array($framework, ['static', 'laravel', 'codeigniter3', 'codeigniter4', 'cakephp', 'raw_php'], true)
            && ($runtime !== 'php' || $capabilities['php']['supported'])
            && $phpCompatible
            && $missingExtensions === []
            && ($capabilities['databases'][$database] ?? false)
            && ($target['writable'] || $target['can_create'])
            && $target['empty'];
        return [
            'compatible' => $compatible,
            'target' => $target,
            'capabilities' => $capabilities,
            'requirements' => ['runtime' => $runtime, 'framework' => $framework, 'database' => $database, 'required_php' => $requiredPhp, 'php_compatible' => $phpCompatible, 'required_extensions' => $requiredExtensions, 'missing_extensions' => $missingExtensions],
        ];
    }

    private function databaseTest(array $body): array
    {
        $this->requireVerifiedSession();
        $database = is_array($body['database'] ?? null) ? $body['database'] : [];
        $session = DatabaseSession::connect($database);
        $session->assertEmpty($database);
        return ['connected' => true, 'empty' => true, 'driver' => (string)($database['driver'] ?? 'none')];
    }

    private function prepareInstall(array $body): array
    {
        $this->requireVerifiedSession();
        $lock = $this->state->lock();
        try {
            $check = $this->preflight($body);
            if (!$check['compatible']) throw new InstallerException('Server or target does not meet package requirements', 'PREFLIGHT_FAILED');
            $relative = (string)($body['target'] ?? '');
            TargetResolver::resolve($this->target, $this->controlDirectory ?? $this->target, $relative === '/' ? '' : $relative, true);
            $run = InstallationRun::prepare($this->state, $body);
            InstallationRun::bindOwner($this->state, (string)$run['run_id'], (string)$_SESSION['install_id']);
            return $run;
        } finally { $this->state->unlock($lock); }
    }

    private function advanceInstall(array $body): array
    {
        $this->requireVerifiedSession();
        InstallationRun::assertOwner($this->state, (string)($body['run_id'] ?? ''), (string)$_SESSION['install_id']);
        $run = InstallationRun::status($this->state, (string)($body['run_id'] ?? ''));
        $relative = $run['target'] === '/' ? '' : (string)$run['target'];
        $target = TargetResolver::resolve($this->target, $this->controlDirectory ?? $this->target, $relative, true);
        if (($run['phase'] ?? '') === 'preflight') {
            $lock = $this->state->lock();
            try {
                $run = InstallationRun::status($this->state, (string)($body['run_id'] ?? ''));
                if (($run['phase'] ?? '') !== 'preflight') return $run;
                $run['phase'] = 'ready'; $run['progress_percent'] = 5;
                return InstallationRun::update($this->state, $run);
            } finally { $this->state->unlock($lock); }
        }
        $targetUrl = rtrim((string)$_SESSION['origin'], '/') . ($relative === '' ? '' : '/' . implode('/', array_map('rawurlencode', explode('/', $relative))));
        $token = (string)$_SESSION['api_token']; $origin = (string)$_SESSION['origin'];
        $installId = (string)$_SESSION['install_id']; $policyVersion = (string)($_SESSION['policy_version'] ?? '2026-08-19');
        $sessionId = session_id(); $renewedSession = null;
        $renewSession = function () use ($origin, $installId, $policyVersion, &$renewedSession): string {
            $renewedSession = $this->issueRemoteSession($origin, $installId, $policyVersion);
            return (string)($renewedSession['token'] ?? '');
        };
        if (session_status() === PHP_SESSION_ACTIVE) session_write_close();
        try {
            $result = (new InstallEngine($this->api, $this->state, $target, $this->publicKeys, $relative === '' ? ($this->controlDirectory ?? null) : null))->install([
                'script_id' => $run['script_id'], 'version' => $run['version'], 'database' => is_array($body['database'] ?? null) ? $body['database'] : ['driver' => 'none'],
                'inputs' => is_array($body['inputs'] ?? null) ? $body['inputs'] : [], 'target_url' => $targetUrl,
                'token' => $token, 'origin' => $origin, 'renew_session' => $renewSession,
            ]);
        } finally { $this->persistRenewedSession($sessionId, $renewedSession, $origin, $installId, $policyVersion); }
        return InstallationRun::update($this->state, array_merge($run, $result, ['phase' => 'complete', 'progress_percent' => 100]));
    }

    private function installStatus(string $uri): array
    {
        $this->requireVerifiedSession();
        parse_str((string)(parse_url($uri, PHP_URL_QUERY) ?? ''), $query);
        $runId = (string)($query['run_id'] ?? ($this->state->read('run')['run_id'] ?? ''));
        InstallationRun::assertOwner($this->state, $runId, (string)$_SESSION['install_id']);
        return InstallationRun::status($this->state, $runId);
    }

    private function cancelInstall(array $body): array
    {
        $this->requireVerifiedSession();
        InstallationRun::assertOwner($this->state, (string)($body['run_id'] ?? ''), (string)$_SESSION['install_id']);
        $lock = $this->state->lock();
        try {
            $run = InstallationRun::status($this->state, (string)($body['run_id'] ?? ''));
            if (!InstallationRun::canCancel((string)($run['phase'] ?? ''))) throw new InstallerException('Installation cannot be cancelled safely at this phase', 'CANCEL_UNSAFE', 409);
            $archive = $this->state->path('artifact') . '.zip';
            if (is_file($archive)) @unlink($archive);
            $this->removePrivateTree($this->state->root . '/stage');
            return InstallationRun::update($this->state, array_merge($run, ['state' => 'cancelled', 'phase' => 'cancelled']));
        } finally { $this->state->unlock($lock); }
    }

    private function finalize(array $body): array
    {
        $this->requireVerifiedSession();
        $runId = (string)($this->state->read('run')['run_id'] ?? '');
        InstallationRun::assertOwner($this->state, $runId, (string)$_SESSION['install_id']);
        $lock = $this->state->lock();
        try {
            $status = $this->state->read('status');
            if (($status['state'] ?? '') !== 'complete') throw new InstallerException('Installer can be finalized only after success', 'FINALIZE_NOT_READY', 409);
            $status['installer_locked'] = true;
            $status['cleanup_requested'] = ($body['remove_installer'] ?? false) === true;
            $this->state->write('status', $status);
            $scheduled = $status['cleanup_requested'] && $this->controlDirectory !== null && is_dir($this->controlDirectory)
                ? ReleaseFinalizer::schedule($this->controlDirectory) : false;
            return ['locked' => true, 'cleanup_scheduled' => $scheduled, 'manual_cleanup_required' => $status['cleanup_requested'] && !$scheduled];
        } finally { $this->state->unlock($lock); }
    }

    private function removePrivateTree(string $path): void
    {
        if (!file_exists($path) || is_link($path)) return;
        if (is_file($path)) { @unlink($path); return; }
        foreach (scandir($path) ?: [] as $entry) if ($entry !== '.' && $entry !== '..') $this->removePrivateTree($path . DIRECTORY_SEPARATOR . $entry);
        @rmdir($path);
    }

    private function legacyInstall(array $body): array
    {
        $this->requireVerifiedSession();
        $token = (string)$_SESSION['api_token']; $origin = (string)$_SESSION['origin'];
        $installId = (string)$_SESSION['install_id']; $policyVersion = (string)($_SESSION['policy_version'] ?? '2026-08-19');
        $sessionId = session_id(); $renewedSession = null;
        $renewSession = function () use ($origin, $installId, $policyVersion, &$renewedSession): string {
            $renewedSession = $this->issueRemoteSession($origin, $installId, $policyVersion);
            return (string)($renewedSession['token'] ?? '');
        };
        if (session_status() === PHP_SESSION_ACTIVE) session_write_close();
        try { return (new InstallEngine($this->api, $this->state, $this->target, $this->publicKeys))->install($body + ['token' => $token, 'origin' => $origin, 'renew_session' => $renewSession]); }
        finally { $this->persistRenewedSession($sessionId, $renewedSession, $origin, $installId, $policyVersion); }
    }

    private function browserRecover(array $body): array
    {
        $this->requireVerifiedSession();
        $runId = (string)($this->state->read('run')['run_id'] ?? '');
        InstallationRun::assertOwner($this->state, $runId, (string)$_SESSION['install_id']);
        return (new InstallEngine($this->api, $this->state, $this->target, $this->publicKeys))->recover($body);
    }

    private function persistRenewedSession(string $sessionId, ?array $renewed, string $origin, string $installId, string $policyVersion): void
    {
        if ($renewed === null || empty($renewed['token']) || $sessionId === '') return;
        if (session_status() === PHP_SESSION_ACTIVE) session_write_close();
        session_id($sessionId);
        if (!session_start()) throw new InstallerException('Renewed installer session could not be persisted', 'SESSION_PERSIST_FAILED', 500);
        $expiresIn = max(1, min(900, (int)($renewed['expires_in'] ?? 900)));
        $_SESSION['api_token'] = $renewed['token']; $_SESSION['origin'] = $origin; $_SESSION['install_id'] = $installId;
        $_SESSION['policy_version'] = $policyVersion; $_SESSION['api_token_expires_at'] = time() + $expiresIn; $_SESSION['verified'] = true;
        session_write_close();
    }

    private function requireVerifiedSession(): void
    {
        if (!$this->sessionIsVerified()) throw new InstallerException('Verified session required', 'SESSION_REQUIRED', 401);
    }

    private function sessionIsVerified(): bool
    {
        return ($_SESSION['verified'] ?? false) === true
            && !empty($_SESSION['install_id'])
            && !empty($_SESSION['origin']);
    }

    private function authenticatedRequest(string $method, string $path, ?array $body): array
    {
        $this->requireVerifiedSession();
        return $this->api->request($method, $path, $body, $_SESSION['api_token'], $_SESSION['origin']);
    }

    private function shell(): void
    {
        $links = ''; $scripts = ''; $diagnostic = null;
        try {
            $bootstrap = $this->assets->bootstrap();
            foreach (($bootstrap['ui']['assets'] ?? []) as $asset) {
                $prefix = rtrim((string)($_SERVER['SCRIPT_NAME'] ?? '/install.php'), '/');
                $local = $prefix . '/assets/' . $asset['sha256'] . '.' . $asset['type'];
                if ($asset['type'] === 'css') $links .= '<link rel="stylesheet" href="' . htmlspecialchars($local, ENT_QUOTES) . '">';
                elseif ($asset['type'] === 'js') $scripts .= '<script type="module" src="' . htmlspecialchars($local, ENT_QUOTES) . '"></script>';
            }
        } catch (Throwable $error) { $diagnostic = $this->recordDiagnostic($error); }
        $fallback = '<main><h1>ScriptBox Installer</h1><p>The signed installer UI is unavailable.</p>';
        if ($diagnostic !== null) {
            $fallback .= '<section role="alert"><p><strong>Error code:</strong> <code>' . htmlspecialchars($diagnostic['code'], ENT_QUOTES) . '</code></p>'
                . '<p><strong>Details:</strong> ' . htmlspecialchars($diagnostic['message'], ENT_QUOTES) . '</p>'
                . '<p><strong>Diagnostic ID:</strong> <code>' . htmlspecialchars($diagnostic['diagnostic_id'], ENT_QUOTES) . '</code></p></section>';
        }
        $fallback .= '<p>Run <code>php install.php status</code> to view the last recorded diagnostic.</p></main>';
        header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ScriptBox Installer</title>' . $links . '</head><body><div id="root">' . $fallback . '</div>' . $scripts . '</body></html>';
    }

    private function recordDiagnostic(Throwable $error): array
    {
        $diagnostic = [
            'diagnostic_id' => bin2hex(random_bytes(8)),
            'timestamp' => gmdate(DATE_ATOM),
            'code' => $error instanceof InstallerException ? $error->stableCode : 'SERVER_ERROR',
            'message' => $error instanceof InstallerException ? $error->getMessage() : 'An unexpected installer error occurred',
        ];
        try { $this->state->write('last_error', $diagnostic); } catch (Throwable) {}
        error_log(sprintf('ScriptBox installer diagnostic %s [%s]: %s', $diagnostic['diagnostic_id'], $diagnostic['code'], $diagnostic['message']));
        return $diagnostic;
    }

    private function asset(string $path): void
    {
        $asset = $this->assets->pathForRequest($path); header('Content-Type: ' . $asset['type']); header('Cache-Control: public, max-age=31536000, immutable'); readfile($asset['file']);
    }

    private function ownershipProof(string $path): void
    {
        $id = basename($path);
        $proof = (new OwnershipProof($this->state, (string)($_SERVER['SCRIPT_NAME'] ?? '/install.php')))->read($id);
        if ($proof === null) throw new InstallerException('Ownership proof not found', 'OWNERSHIP_PROOF_NOT_FOUND', 404);
        header('Content-Type: text/plain; charset=utf-8'); header('Cache-Control: no-store'); echo $proof;
    }

    private function csrf(array $headers): void
    {
        $provided = $headers['x-scriptbox-csrf'] ?? '';
        if (!is_string($provided) || !hash_equals($_SESSION['csrf'], $provided)) throw new InstallerException('CSRF validation failed', 'CSRF_FAILED', 403);
    }

    private function securityHeaders(): void
    {
        header('Content-Security-Policy: ' . self::contentSecurityPolicy());
        header('X-Frame-Options: DENY'); header('X-Content-Type-Options: nosniff'); header('Referrer-Policy: no-referrer'); header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
        header('Cache-Control: no-store');
    }

    public static function contentSecurityPolicy(): string
    {
        return "default-src 'self'; connect-src 'self'; img-src 'self' data: https:; style-src 'self'; script-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
    }

    private function json(array $data, int $status = 200): void
    {
        http_response_code($status); header('Content-Type: application/json; charset=utf-8'); echo json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
}

define('SCRIPTBOX_COMPILED_RELEASE', array (
  'version' => '1.0.0-dev',
  'release_timestamp' => '2026-08-21T00:00:00+00:00',
  'api_base_url' => 'https://api.scriptbox.app/installer/v1',
  'public_keys' => 
  array (
    'installer-root-2026-01' => '-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA7PQG2KVVS/joy1zsvM56
YkKSzya8FTe4GFrNEGqATccdg24sNm/kfq6/V9FFoidX3ljoPf3/qqXEiZKEf1wG
yzyfospnd09aMVqjQGD0TBpydUEPxz2w30I8SjeGMvHwtjbjx6y9FsrpDMiw/8KT
iPRMK37QpjXGqFTOW0eVMYd/HClCMyjkqjJQLek31d3mmCihaWH/usOBwdXxlUBK
xTKPQ290WP8Z4xnwqOhzKU0ZGoy8SmuEOdc6EdwqEW41UY4jb3YsMU8dZBxPeG9K
y6OiB+K1aCQevo7pnl5e3f4jkm4pB3P+vbaHt3DKzBkUg6Y9RFhRazPeiSZQjA9v
RMWpXCJJqHhoJntDTE/T1noRWfNjfXNqMg3Id8hITh+6kEmPmR2L7/tDyLIEcD/3
eJg/etjCwi+Yru2GeRRdBGd8INTS9vhe1wK8eRvdujg31i8LHgw83xJIbxpYZF9m
0J2dOlk170AtOZPlpC2I0hCF4firiJVW22ayTaAsjJVVAgMBAAE=
-----END PUBLIC KEY-----
',
  ),
));

if (!class_exists(Application::class)) require __DIR__ . '/Installer.php';
if (PHP_SAPI !== 'cli') ini_set('display_errors', '0');
$release = defined('SCRIPTBOX_COMPILED_RELEASE') ? SCRIPTBOX_COMPILED_RELEASE : require __DIR__ . '/../config/release.php';
$installerFile = defined('SCRIPTBOX_INSTALLER_FILE') ? SCRIPTBOX_INSTALLER_FILE : (realpath($_SERVER['SCRIPT_FILENAME'] ?? __FILE__) ?: (__FILE__));
$controlDirectory = dirname($installerFile);
$controlPath = defined('SCRIPTBOX_LAUNCHER') ? $controlDirectory : $installerFile;
$configuredDocumentRoot = PHP_SAPI === 'cli' ? false : realpath((string)($_SERVER['DOCUMENT_ROOT'] ?? ''));
$target = is_string($configuredDocumentRoot) && is_dir($configuredDocumentRoot) ? $configuredDocumentRoot : $controlDirectory;
$state = StateStore::discover($target, $installerFile);

if (PHP_SAPI === 'cli') {
    $command = $argv[1] ?? 'help';
    if ($command === 'init') {
        $state->write('status', ['state' => 'initialized', 'phase' => 'ready', 'install_id' => bin2hex(random_bytes(16))]);
        fwrite(STDOUT, "ScriptBox installer initialized. State: {$state->root}\n");
        exit(0);
    }
    if ($command === 'status') {
        $status = $state->read('status', ['state' => 'idle']);
        $lastError = $state->read('last_error');
        if ($lastError !== []) $status['last_error'] = $lastError;
        fwrite(STDOUT, json_encode($status, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
        exit(0);
    }
    if ($command === 'recover') {
        $api = new ApiClient($release['api_base_url']);
        $result = (new InstallEngine($api, $state, $target, $release['public_keys']))->recover();
        fwrite(STDOUT, json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
        exit(0);
    }
    if ($command === 'serve') {
        $options = array_slice($argv, 2);
        $publicIndex = array_search('--public-url', $options, true);
        if ($publicIndex === false || empty($options[$publicIndex + 1]) || !str_starts_with($options[$publicIndex + 1], 'https://')) {
            fwrite(STDERR, "Usage: php install.php serve --public-url=https://example.com [--listen=127.0.0.1:8080]\n"); exit(2);
        }
        $listen = '127.0.0.1:8080';
        foreach ($options as $option) if (str_starts_with($option, '--listen=')) $listen = substr($option, 9);
        if (!preg_match('/^(?:127\.0\.0\.1|\[::1\]):[0-9]{2,5}$/', $listen)) { fwrite(STDERR, "--listen must use a loopback address\n"); exit(2); }
        $state->write('server', ['public_url' => $options[$publicIndex + 1], 'listen' => $listen]);
        if (PHP_OS_FAMILY !== 'Windows') putenv('PHP_CLI_SERVER_WORKERS=2');
        passthru(escapeshellarg(PHP_BINARY) . ' -S ' . escapeshellarg($listen) . ' ' . escapeshellarg($_SERVER['SCRIPT_FILENAME']), $exitCode);
        exit($exitCode);
    }
    fwrite(STDOUT, "ScriptBox Installer {$release['version']}\nCommands: init, status, serve, recover\n");
    exit(0);
}

try { RequestLimits::assertBodyLength((string)($_SERVER['CONTENT_LENGTH'] ?? '')); }
catch (InstallerException $error) { http_response_code($error->getCode()); header('Content-Type: application/json'); echo json_encode(['success' => false, 'data' => null, 'error' => ['code' => $error->stableCode, 'message' => $error->getMessage()]]); exit; }
$requestStream = fopen('php://input', 'rb');
try { $requestBody = RequestLimits::readBody($requestStream); }
catch (InstallerException $error) { http_response_code($error->getCode()); header('Content-Type: application/json'); echo json_encode(['success' => false, 'data' => null, 'error' => ['code' => $error->stableCode, 'message' => $error->getMessage()]]); exit; }
finally { if (is_resource($requestStream)) fclose($requestStream); }
$sessionDirectory = $state->root . '/sessions';
if (!is_dir($sessionDirectory)) mkdir($sessionDirectory, 0700);
ini_set('session.use_strict_mode', '1'); ini_set('session.use_only_cookies', '1'); ini_set('session.save_path', $sessionDirectory);
session_name('scriptbox_installer');
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
session_start();
$_SESSION['install_id'] ??= bin2hex(random_bytes(16)); $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
$api = new ApiClient($release['api_base_url']);
$assets = new AssetManager($api, $state, $release['public_keys']);
$uri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url($uri, PHP_URL_PATH) ?: '/';
$launcher = defined('SCRIPTBOX_LAUNCHER');
$scriptName = (string)($_SERVER['SCRIPT_NAME'] ?? ($launcher ? '/install/index.php' : '/install.php'));
if ($scriptName === '') $scriptName = '/';
if ($launcher && rtrim($path, '/') === rtrim(str_replace('\\', '/', dirname($scriptName)), '/')) $path = '/';
elseif (str_starts_with($path, $scriptName)) $path = substr($path, strlen($scriptName)) ?: '/';
$_SERVER['SCRIPT_NAME'] = $scriptName;
$normalizedUri = $path . (($query = parse_url($uri, PHP_URL_QUERY)) ? '?' . $query : '');
$headers = function_exists('getallheaders') ? getallheaders() : [];
(new Application($api, $state, $assets, $target, $release['public_keys'], BuildIdentity::fromRelease($release, $installerFile), $controlPath))->handle($_SERVER['REQUEST_METHOD'] ?? 'GET', $normalizedUri, $headers, $requestBody);
