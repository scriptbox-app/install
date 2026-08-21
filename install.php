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
        $root = $configured !== false && $configured !== ''
            ? $configured
            : dirname(realpath($documentRoot) ?: $documentRoot) . '/.scriptbox-' . substr(hash('sha256', realpath($installerFile) ?: $installerFile), 0, 16);
        $document = rtrim(realpath($documentRoot) ?: $documentRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        $candidate = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if (str_starts_with($candidate, $document)) throw new InstallerException('State directory must be outside the document root', 'STATE_INSIDE_WEBROOT', 500);
        return new self($root);
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
                if ($name === 'scriptbox.json') $manifest = json_decode((string)$zip->getFromIndex($index), true, 32, JSON_THROW_ON_ERROR);
            }
            if (!is_array($manifest)) throw new InstallerException('Package manifest is missing', 'MANIFEST_MISSING');
            self::validateManifest($manifest);
            return ['manifest' => $manifest, 'files' => $zip->numFiles, 'unpacked_bytes' => $unpacked];
        } finally { $zip->close(); }
    }

    public static function validateManifest(array $manifest): void
    {
        if (($manifest['schema_version'] ?? null) !== 1 || !preg_match('/^[A-Za-z0-9._-]{1,64}$/', (string)($manifest['script_id'] ?? ''))) throw new InstallerException('Package manifest identity is invalid', 'MANIFEST_INVALID');
        if (!in_array($manifest['runtime']['type'] ?? '', ['static', 'php'], true)) throw new InstallerException('Package runtime is unsupported', 'RUNTIME_UNSUPPORTED');
        if (!in_array($manifest['database']['driver'] ?? '', ['none', 'mysql', 'mariadb', 'pgsql', 'sqlite', 'sqlsrv', 'mongodb'], true)) throw new InstallerException('Database driver is unsupported', 'DATABASE_UNSUPPORTED');
        if (($manifest['payload']['root'] ?? '') !== 'payload') throw new InstallerException('Package payload must be root-ready', 'MANIFEST_INVALID');
        foreach (['hooks', 'composer', 'npm', 'urls'] as $forbidden) if (array_key_exists($forbidden, $manifest)) throw new InstallerException('Executable hooks and package URLs are forbidden', 'MANIFEST_FORBIDDEN');
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
            'GET /api/media' => 'catalog_media',
            'POST /api/session' => 'session',
            'POST /api/catalog/search' => 'catalog_search',
            'POST /api/install' => 'install',
            'POST /api/recover' => 'recover',
        ];
        $key = strtoupper($method) . ' ' . $path;
        if (isset($fixed[$key])) return $fixed[$key];
        if (strtoupper($method) === 'GET' && preg_match('#^/api/media/([A-Za-z0-9._-]{20,2048})$#', $path)) return 'catalog_media';
        if (strtoupper($method) === 'GET' && preg_match('#^/api/catalog/([A-Za-z0-9._-]{1,64})$#', $path)) return 'catalog_detail';
        if (strtoupper($method) === 'GET' && preg_match('#^/\.well-known/scriptbox-installer/([A-Za-z0-9-]{8,100})$#', $path)) return 'ownership_proof';
        if (strtoupper($method) === 'GET' && preg_match('#^/assets/[a-f0-9]{64}\.(?:js|css|json)$#', $path)) return 'asset';
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
            ],
            'platform' => ['os_family' => PHP_OS_FAMILY, 'sapi' => PHP_SAPI],
        ];
    }
}

final class MediaBuffer
{
    public const MAX_BYTES = 8 * 1024 * 1024;

    private bool $limitExceeded = false;

    public function __construct(private $stream) {}

    public function write(mixed $handle, string $chunk): int
    {
        $stat = fstat($this->stream);
        $bytes = is_array($stat) ? ($stat['size'] ?? null) : null;
        if (!is_int($bytes) || strlen($chunk) > self::MAX_BYTES - $bytes) {
            $this->limitExceeded = true;
            return 0;
        }
        $written = fwrite($this->stream, $chunk);
        return is_int($written) ? $written : 0;
    }

    public function limitExceeded(): bool
    {
        return $this->limitExceeded;
    }

    public function assertWithinLimit(): void
    {
        if ($this->limitExceeded) throw new InstallerException('Catalog media size is invalid', 'MEDIA_SIZE_INVALID', 502);
    }

    public static function validatedSize($stream): int
    {
        $stat = fstat($stream);
        $bytes = is_array($stat) ? ($stat['size'] ?? null) : null;
        if (!is_int($bytes) || $bytes < 1 || $bytes > self::MAX_BYTES) {
            throw new InstallerException('Catalog media size is invalid', 'MEDIA_SIZE_INVALID', 502);
        }
        return $bytes;
    }
}

final class CatalogMedia
{
    private const TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/avif'];

    public static function validate(bool $transportSucceeded, int $status, string $contentType, $stream): array
    {
        if (!$transportSucceeded) throw new InstallerException('Catalog media download failed', 'MEDIA_DOWNLOAD_FAILED', 502);
        if ($status !== 200) throw new InstallerException('Catalog media upstream response is unavailable', 'MEDIA_UPSTREAM_STATUS', 502);
        $type = trim(explode(';', strtolower($contentType))[0]);
        if (!in_array($type, self::TYPES, true)) throw new InstallerException('Catalog media type is unsupported', 'MEDIA_TYPE_UNSUPPORTED', 502);
        return ['content_type' => $type, 'bytes' => MediaBuffer::validatedSize($stream)];
    }
}

final class ApiClient
{
    private const METHODS = [
        'GET /bootstrap', 'POST /sessions/verify', 'POST /catalog/search',
        'GET /catalog/{id}', 'POST /licenses/free', 'POST /artifacts/{id}/authorize',
        'POST /licenses/{id}/activate', 'POST /events', 'GET /catalog/media', 'GET /catalog/media/{id}',
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

    public function download(string $token, string $destination, int $expectedBytes, string $expectedHash): void
    {
        $offset = is_file($destination) ? filesize($destination) : 0;
        if ($offset > $expectedBytes) { unlink($destination); $offset = 0; }
        while ($offset < $expectedBytes) {
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
            if ($ok === false || !in_array($status, [200, 206], true)) throw new InstallerException('Artifact download failed: ' . $error, 'DOWNLOAD_FAILED', 502);
            $next = filesize($destination);
            if ($next <= $offset) throw new InstallerException('Artifact download made no progress', 'DOWNLOAD_FAILED', 502);
            $offset = $next;
        }
        Crypto::verifyFile($destination, $expectedHash, $expectedBytes);
    }

    public function streamCatalogMedia(string $token): void
    {
        if (!preg_match('/^[A-Za-z0-9._-]{20,2048}$/', $token)) throw new InstallerException('Catalog media token is invalid', 'MEDIA_NOT_FOUND', 404);
        $path = '/catalog/media?token=' . rawurlencode($token);
        $this->assertAllowed('GET', $path);
        $temporary = tmpfile();
        if ($temporary === false) throw new InstallerException('Cannot create media buffer', 'MEDIA_UNAVAILABLE', 502);
        $buffer = new MediaBuffer($temporary);
        $handle = curl_init($this->baseUrl . $path);
        curl_setopt_array($handle, [CURLOPT_WRITEFUNCTION => [$buffer, 'write'], CURLOPT_FOLLOWLOCATION => false, CURLOPT_CONNECTTIMEOUT => 8, CURLOPT_TIMEOUT => 20, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS]);
        $ok = curl_exec($handle); $status = curl_getinfo($handle, CURLINFO_RESPONSE_CODE); $type = (string)curl_getinfo($handle, CURLINFO_CONTENT_TYPE); curl_close($handle);
        try {
            $buffer->assertWithinLimit();
            $media = CatalogMedia::validate($ok === true, $status, $type, $temporary);
            header('Content-Type: ' . $media['content_type']); header('Content-Length: ' . $media['bytes']); header('Cache-Control: private, max-age=3600'); rewind($temporary); fpassthru($temporary);
        } finally {
            fclose($temporary);
        }
    }

    private function assertAllowed(string $method, string $path): void
    {
        $static = ['/bootstrap', '/sessions/verify', '/catalog/search', '/catalog/media', '/licenses/free', '/events'];
        $normalizedPath = parse_url($path, PHP_URL_PATH) ?: $path;
        if (!in_array($normalizedPath, $static, true)) {
            $normalizedPath = preg_replace('#^/catalog/[A-Za-z0-9._-]+$#', '/catalog/{id}', $normalizedPath);
            $normalizedPath = preg_replace('#^/catalog/media/[A-Za-z0-9._-]{20,2048}$#', '/catalog/media/{id}', $normalizedPath);
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
                ? ($runtimeValues[$match[1]] ?? '') : $value;
        }
        $format = $output['format'] ?? '';
        $content = match ($format) {
            'dotenv' => self::dotenv($values),
            'json' => json_encode($values, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n",
            'php-array' => "<?php\nreturn " . var_export($values, true) . ";\n",
            default => throw new InstallerException('Configuration format is unsupported', 'CONFIG_FORMAT_INVALID'),
        };
        $destination = $root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative);
        $directory = dirname($destination);
        if (!is_dir($directory) && !mkdir($directory, 0750, true) && !is_dir($directory)) throw new InstallerException('Cannot create configuration directory', 'CONFIG_WRITE_FAILED');
        if (file_put_contents($destination, $content, LOCK_EX) === false) throw new InstallerException('Cannot write application configuration', 'CONFIG_WRITE_FAILED');
        chmod($destination, 0600);
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

final class DatabaseSession
{
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

    public function applyOperations(array $operations, array $config): void
    {
        if ($this->driver === 'none') {
            if ($operations !== []) throw new InstallerException('Package requires database operations', 'DATABASE_REQUIRED');
            return;
        }
        foreach ($operations as $operation) {
            if (!is_array($operation) || ($operation['driver'] ?? $this->driver) !== $this->driver) throw new InstallerException('Migration driver does not match', 'MIGRATION_INVALID');
            if ($this->driver === 'mongodb') {
                $command = $operation['command'] ?? null;
                $allowed = ['create', 'insert', 'createIndexes', 'collMod'];
                if (!is_array($command) || count(array_intersect(array_keys($command), $allowed)) !== 1) throw new InstallerException('MongoDB operation is unsafe', 'MIGRATION_INVALID');
                $this->mongo->executeCommand((string)$config['name'], new \MongoDB\Driver\Command($command));
            } else {
                $sql = rtrim(trim((string)($operation['sql'] ?? '')), ';');
                if ($sql === '' || str_contains($sql, "\0") || str_contains($sql, ';') || !preg_match('/^(CREATE\s+(?:TABLE|INDEX|VIEW)|ALTER\s+TABLE|INSERT\s+INTO|UPDATE\s+)/i', $sql)) throw new InstallerException('Migration operation is unsafe', 'MIGRATION_INVALID');
                $this->pdo->exec($sql);
            }
        }
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
    ) {}

    public function install(array $input): array
    {
        $lock = $this->state->lock();
        $promoted = [];
        $database = null;
        $databaseChanged = false;
        try {
            $status = $this->state->read('status');
            if (in_array($status['state'] ?? '', ['complete', 'recovery_required'], true)) throw new InstallerException('Installer is permanently locked', 'INSTALLER_LOCKED', 409);
            $this->assertTargetEmpty();
            $this->phase('preflight');
            $capabilities = Preflight::capabilities($this->target);
            if (!$capabilities['php']['supported'] || in_array(false, $capabilities['required'], true)) throw new InstallerException('Server does not meet installer requirements', 'PREFLIGHT_FAILED');
            $origin = $this->httpsOrigin((string)($input['origin'] ?? ''));
            $token = (string)($input['token'] ?? '');
            $license = $this->api->request('POST', '/licenses/free', [
                'script_id' => $input['script_id'] ?? null, 'version' => $input['version'] ?? null,
                'capabilities' => $capabilities,
            ], $token, $origin);
            $this->phase('license_issued', ['license_id' => $license['id']]);
            $artifactId = (string)($license['artifact_id'] ?? '');
            $authorization = $this->api->request('POST', '/artifacts/' . rawurlencode($artifactId) . '/authorize', ['license_id' => $license['id']], $token, $origin);
            $signed = Crypto::verifyEnvelope($authorization['manifest'], $this->publicKeys, null, false);
            $manifest = $signed['manifest'] ?? null;
            if (!is_array($manifest)) throw new InstallerException('Signed package manifest is missing', 'MANIFEST_INVALID');
            $signedArtifact = $signed['artifact'] ?? null;
            if (!is_array($signedArtifact) || (int)($signedArtifact['bytes'] ?? -1) !== (int)$authorization['bytes'] || !hash_equals((string)($signedArtifact['sha256'] ?? ''), (string)$authorization['sha256'])) {
                throw new InstallerException('Artifact authorization differs from signed metadata', 'ARTIFACT_METADATA_MISMATCH');
            }
            ArchiveInspector::validateManifest($manifest);
            $archive = $this->state->path('artifact') . '.zip';
            $this->phase('downloading');
            $this->api->download((string)$authorization['token'], $archive, (int)$authorization['bytes'], (string)$authorization['sha256']);
            $inspected = ArchiveInspector::inspect($archive);
            if ($inspected['manifest'] !== $manifest) throw new InstallerException('ZIP manifest differs from signed manifest', 'MANIFEST_MISMATCH');
            $stage = $this->state->root . '/stage';
            $this->removeTree($stage);
            mkdir($stage, 0700, true);
            $this->extractPayload($archive, $stage);
            $dbConfig = is_array($input['database'] ?? null) ? $input['database'] : ['driver' => 'none'];
            if (($dbConfig['driver'] ?? 'none') !== ($manifest['database']['driver'] ?? 'none')) throw new InstallerException('Selected database does not match package', 'DATABASE_MISMATCH');
            $this->phase('database');
            $database = DatabaseSession::connect($dbConfig);
            $database->assertEmpty($dbConfig);
            $operations = $this->migrationOperations($archive, $manifest);
            if ($operations !== []) { $databaseChanged = true; $database->applyOperations($operations, $dbConfig); }
            $runtime = $this->configurationValues($input, $origin);
            foreach (($manifest['configuration'] ?? []) as $output) ConfigurationWriter::write($stage, $output, $runtime);
            $this->applyWritablePaths($stage, $manifest);
            $this->phase('promoting');
            $this->promote($stage, $promoted);
            $health = $this->healthCheck($origin, (string)($manifest['health_check']['path'] ?? '/'));
            $this->api->request('POST', '/licenses/' . rawurlencode((string)$license['id']) . '/activate', ['health' => $health], $token, $origin);
            $this->phase('complete', ['state' => 'complete', 'license_id' => $license['id'], 'script_id' => $manifest['script_id'], 'version' => $manifest['version']]);
            @unlink($archive);
            $this->removeTree($stage);
            return ['state' => 'complete', 'license_id' => $license['id'], 'health' => $health];
        } catch (Throwable $error) {
            $cleanupOkay = $this->rollbackFiles($promoted);
            if ($databaseChanged && $database !== null) {
                try { $database->resetToEmpty($input['database']); } catch (Throwable) { $cleanupOkay = false; }
            }
            $this->phase($cleanupOkay ? 'failed' : 'recovery_required', [
                'state' => $cleanupOkay ? 'failed' : 'recovery_required',
                'code' => $error instanceof InstallerException ? $error->stableCode : 'INSTALL_FAILED',
            ]);
            throw $error;
        } finally { $this->state->unlock($lock); }
    }

    public function recover(): array
    {
        $status = $this->state->read('status');
        if (($status['state'] ?? '') !== 'recovery_required') return $status + ['state' => $status['state'] ?? 'idle'];
        throw new InstallerException('Automatic recovery is unsafe; restore the empty database and remove journaled files', 'RECOVERY_MANUAL', 409);
    }

    private function phase(string $phase, array $extra = []): void
    {
        $event = ['phase' => $phase] + $extra;
        $this->state->appendJournal($event);
        $this->state->write('status', $event + ['state' => $extra['state'] ?? 'running']);
    }

    private function assertTargetEmpty(): void
    {
        foreach (scandir($this->target) ?: [] as $entry) {
            if (in_array($entry, ['.', '..', basename($_SERVER['SCRIPT_FILENAME'] ?? 'install.php')], true)) continue;
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

    private function migrationOperations(string $archive, array $manifest): array
    {
        $operations = []; $zip = new \ZipArchive(); $zip->open($archive, \ZipArchive::RDONLY);
        try {
            foreach (($manifest['database']['migrations'] ?? []) as $file) {
                if (!ArchiveInspector::isSafePath((string)$file) || !str_ends_with((string)$file, '.json')) throw new InstallerException('Migration path is invalid', 'MIGRATION_INVALID');
                $content = $zip->getFromName((string)$file);
                if ($content === false || strlen($content) > 8 * 1024 * 1024) throw new InstallerException('Migration file is missing or too large', 'MIGRATION_INVALID');
                $decoded = json_decode($content, true, 64, JSON_THROW_ON_ERROR);
                foreach (is_array($decoded) && array_is_list($decoded) ? $decoded : [$decoded] as $operation) $operations[] = $operation;
            }
        } finally { $zip->close(); }
        return $operations;
    }

    private function configurationValues(array $input, string $origin): array
    {
        $database = is_array($input['database'] ?? null) ? $input['database'] : [];
        return [
            'app.url' => $origin, 'app.key' => bin2hex(random_bytes(32)),
            'database.driver' => $database['driver'] ?? 'none', 'database.host' => $database['host'] ?? '',
            'database.port' => $database['port'] ?? '', 'database.name' => $database['name'] ?? '',
            'database.user' => $database['user'] ?? '', 'database.password' => $database['password'] ?? '',
        ];
    }

    private function applyWritablePaths(string $stage, array $manifest): void
    {
        foreach (($manifest['payload']['writable'] ?? []) as $relative) {
            if (!ArchiveInspector::isSafePath((string)$relative)) throw new InstallerException('Writable path is unsafe', 'MANIFEST_INVALID');
            $path = $stage . '/' . $relative;
            if (!file_exists($path)) throw new InstallerException('Declared writable path is missing', 'MANIFEST_INVALID');
            chmod($path, is_dir($path) ? 0775 : 0664);
        }
    }

    private function promote(string $stage, array &$promoted): void
    {
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($stage, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::SELF_FIRST);
        foreach ($iterator as $item) {
            $relative = substr($item->getPathname(), strlen($stage) + 1);
            $destination = $this->target . '/' . $relative;
            if ($item->isDir()) { if (!is_dir($destination)) { mkdir($destination, 0755); $promoted[] = ['path' => $destination, 'directory' => true]; } continue; }
            if (file_exists($destination)) throw new InstallerException('Promotion would overwrite an existing file', 'TARGET_CONFLICT');
            if (!rename($item->getPathname(), $destination)) throw new InstallerException('File promotion failed', 'PROMOTION_FAILED');
            $promoted[] = ['path' => $destination, 'directory' => false]; $this->state->appendJournal(['phase' => 'promoted', 'relative' => $relative]);
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
        if (!preg_match('#^/assets/([a-f0-9]{64})\.(js|css|json)$#', $requestPath, $match)) throw new InstallerException('Asset not found', 'ASSET_NOT_FOUND', 404);
        $file = $this->state->root . '/asset-' . $match[1] . '.' . $match[2];
        if (!is_file($file) || !hash_equals($match[1], hash_file('sha256', $file))) throw new InstallerException('Asset not found', 'ASSET_NOT_FOUND', 404);
        $types = ['js' => 'text/javascript; charset=utf-8', 'css' => 'text/css; charset=utf-8', 'json' => 'application/json; charset=utf-8'];
        return ['file' => $file, 'type' => $types[$match[2]]];
    }

    public function runtimeAssets(string $scriptName): array
    {
        $payload = $this->bootstrap();
        $prefix = rtrim($scriptName, '/');
        $result = [];
        foreach (($payload['ui']['assets'] ?? []) as $asset) {
            if (($asset['type'] ?? '') !== 'json' || !isset($asset['role'])) continue;
            $result[(string)$asset['role']] = $prefix . '/assets/' . $asset['sha256'] . '.json';
        }
        return $result;
    }

    private function cacheAsset(array $asset): void
    {
        $type = $asset['type'] ?? '';
        $hash = strtolower((string)($asset['sha256'] ?? ''));
        $bytes = (int)($asset['bytes'] ?? -1);
        $url = (string)($asset['url'] ?? '');
        if (!in_array($type, ['js', 'css', 'json'], true) || !preg_match('/^[a-f0-9]{64}$/', $hash) || $bytes < 1 || $bytes > ($type === 'json' ? 5 : 50) * 1024 * 1024 || !str_starts_with($url, 'https://')) throw new InstallerException('Signed UI asset metadata is invalid', 'ASSET_METADATA_INVALID');
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
    ) {}

    public function handle(string $method, string $uri, array $headers, string $rawBody): void
    {
        $this->securityHeaders();
        $headers = array_change_key_case($headers, CASE_LOWER);
        try {
            $route = Router::resolve($method, $uri);
            if ($route === 'shell') { $this->shell(); return; }
            if ($route === 'asset') { $this->asset(parse_url($uri, PHP_URL_PATH)); return; }
            if ($route === 'catalog_media') {
                parse_str((string)(parse_url($uri, PHP_URL_QUERY) ?? ''), $query);
                $token = (string)($query['token'] ?? basename(parse_url($uri, PHP_URL_PATH)));
                $this->api->streamCatalogMedia($token);
                return;
            }
            if ($route === 'ownership_proof') { $this->ownershipProof(parse_url($uri, PHP_URL_PATH)); return; }
            if ($method !== 'GET') $this->csrf($headers);
            $body = $rawBody === '' ? [] : json_decode($rawBody, true, 32, JSON_THROW_ON_ERROR);
            if (!is_array($body)) throw new InstallerException('JSON object required', 'INPUT_INVALID');
            $data = match ($route) {
                'runtime' => $this->runtime(),
                'bootstrap' => $this->assets->bootstrap((bool)($body['refresh'] ?? false)),
                'status' => $this->state->read('status', ['state' => 'idle']),
                'session' => $this->createSession($body),
                'catalog_search' => $this->api->request('POST', '/catalog/search', $body),
                'catalog_detail' => $this->api->request('GET', '/catalog/' . rawurlencode(basename(parse_url($uri, PHP_URL_PATH))), null),
                'install' => (new InstallEngine($this->api, $this->state, $this->target, $this->publicKeys))->install($body + ['token' => $_SESSION['api_token'] ?? '', 'origin' => $_SESSION['origin'] ?? '']),
                'recover' => (new InstallEngine($this->api, $this->state, $this->target, $this->publicKeys))->recover(),
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
        return ['csrf_token' => $_SESSION['csrf'], 'capabilities' => Preflight::capabilities($this->target), 'status' => $this->state->read('status', ['state' => 'idle']), 'paid_checkout' => false,
            'detected_origin' => $origin['origin'], 'origin_source' => $origin['source'], 'can_verify_origin' => $origin['origin'] !== null,
            'build' => $this->buildIdentity,
            'ui_assets' => $this->assets->runtimeAssets((string)($_SERVER['SCRIPT_NAME'] ?? '/install.php'))];
    }

    private function createSession(array $body): array
    {
        if (($body['consent'] ?? false) !== true) throw new InstallerException('Telemetry consent is required', 'CONSENT_REQUIRED');
        Preflight::assertWritableTarget($this->target);
        $origin = OriginDetector::detect($_SERVER, $this->state, (string)(getenv('SCRIPTBOX_TRUSTED_PROXIES') ?: ''))['origin'];
        $proofs = new OwnershipProof($this->state, (string)($_SERVER['SCRIPT_NAME'] ?? '/install.php'));
        $proof = $proofs->create();
        try {
            $data = $this->api->request('POST', '/sessions/verify', [
                'install_id' => $_SESSION['install_id'], 'origin' => $origin, 'proof_id' => $proof['id'],
                'proof_digest' => $proof['digest'], 'proof_path' => $proof['path'], 'consent' => true,
                'policy_version' => (string)($body['policy_version'] ?? '2026-08-19'),
            ]);
        } finally { $proofs->remove($proof['id']); }
        $_SESSION['api_token'] = $data['token']; $_SESSION['origin'] = $origin;
        session_regenerate_id(true);
        return ['verified' => true, 'expires_in' => $data['expires_in'] ?? 900];
    }

    private function authenticatedRequest(string $method, string $path, ?array $body): array
    {
        if (empty($_SESSION['api_token']) || empty($_SESSION['origin'])) throw new InstallerException('Verified session required', 'SESSION_REQUIRED', 401);
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
        header("Content-Security-Policy: default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
        header('X-Frame-Options: DENY'); header('X-Content-Type-Options: nosniff'); header('Referrer-Policy: no-referrer'); header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
        header('Cache-Control: no-store');
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
$release = defined('SCRIPTBOX_COMPILED_RELEASE') ? SCRIPTBOX_COMPILED_RELEASE : require __DIR__ . '/../config/release.php';
$target = dirname(realpath($_SERVER['SCRIPT_FILENAME'] ?? __FILE__) ?: __FILE__);
$state = StateStore::discover($target, $_SERVER['SCRIPT_FILENAME'] ?? __FILE__);

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

if (strlen((string)($_SERVER['CONTENT_LENGTH'] ?? '0')) > 1024 * 1024) { http_response_code(413); exit; }
$sessionDirectory = $state->root . '/sessions';
if (!is_dir($sessionDirectory)) mkdir($sessionDirectory, 0700);
ini_set('session.use_strict_mode', '1'); ini_set('session.use_only_cookies', '1'); ini_set('session.save_path', $sessionDirectory); ini_set('display_errors', '0');
session_name('scriptbox_installer');
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
session_start();
$_SESSION['install_id'] ??= bin2hex(random_bytes(16)); $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
$api = new ApiClient($release['api_base_url']);
$assets = new AssetManager($api, $state, $release['public_keys']);
$uri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url($uri, PHP_URL_PATH) ?: '/';
$scriptName = $_SERVER['SCRIPT_NAME'] ?? '/install.php';
if (str_starts_with($path, $scriptName)) $path = substr($path, strlen($scriptName)) ?: '/';
$normalizedUri = $path . (($query = parse_url($uri, PHP_URL_QUERY)) ? '?' . $query : '');
$headers = function_exists('getallheaders') ? getallheaders() : [];
(new Application($api, $state, $assets, $target, $release['public_keys'], BuildIdentity::fromRelease($release, (string)($_SERVER['SCRIPT_FILENAME'] ?? __FILE__))))->handle($_SERVER['REQUEST_METHOD'] ?? 'GET', $normalizedUri, $headers, (string)file_get_contents('php://input'));
