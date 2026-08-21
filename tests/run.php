<?php
declare(strict_types=1);

require __DIR__ . '/../src/Installer.php';

use ScriptBox\Installer\ArchiveInspector;
use ScriptBox\Installer\Crypto;
use ScriptBox\Installer\InstallerException;
use ScriptBox\Installer\StateStore;
use ScriptBox\Installer\Router;
use ScriptBox\Installer\Preflight;
use ScriptBox\Installer\ConfigurationWriter;
use ScriptBox\Installer\ApiClient;
use ScriptBox\Installer\Application;
use ScriptBox\Installer\AssetManager;
use ScriptBox\Installer\BuildIdentity;
use ScriptBox\Installer\OwnershipProof;
use ScriptBox\Installer\OriginDetector;
use ScriptBox\Installer\TargetResolver;
use ScriptBox\Installer\InstallationRun;
use ScriptBox\Installer\ValueResolver;
use ScriptBox\Installer\ReleaseFinalizer;
use ScriptBox\Installer\RequestLimits;
use ScriptBox\Installer\DatabaseSession;
use ScriptBox\Installer\InstallEngine;
use ScriptBox\Installer\MigrationReader;
use ScriptBox\Installer\MigrationValidator;

$tests = [];
function test(string $name, callable $callback): void { global $tests; $tests[$name] = $callback; }
function expect(bool $condition, string $message = 'Expectation failed'): void { if (!$condition) throw new RuntimeException($message); }
function expectThrows(callable $callback, string $contains): void {
    try { $callback(); } catch (Throwable $error) {
        expect(str_contains(strtolower($error->getMessage()), strtolower($contains)), $error->getMessage());
        return;
    }
    throw new RuntimeException('Expected exception was not thrown');
}
function expectInstallerFailure(callable $callback, string $code, int $status): void {
    try { $callback(); }
    catch (InstallerException $error) {
        expect($error->stableCode === $code, 'Expected ' . $code . ', got ' . $error->stableCode);
        expect($error->getCode() === $status, 'Expected HTTP ' . $status . ', got ' . $error->getCode());
        return;
    }
    throw new RuntimeException('Expected installer exception was not thrown');
}

function writeStoredZip(string $file, array $entries): void {
    $locals = ''; $central = ''; $offset = 0;
    foreach ($entries as [$name, $body]) {
        $crc = crc32($body); $size = strlen($body); $nameBytes = strlen($name);
        $local = pack('VvvvvvVVVvv', 0x04034b50, 20, 0, 0, 0, 0, $crc, $size, $size, $nameBytes, 0) . $name . $body;
        $external = str_ends_with($name, '/') ? (0040755 << 16) : (0100644 << 16);
        $central .= pack('VvvvvvvVVVvvvvvVV', 0x02014b50, 0x0314, 20, 0, 0, 0, 0, $crc, $size, $size,
            $nameBytes, 0, 0, 0, 0, $external, $offset) . $name;
        $locals .= $local; $offset += strlen($local);
    }
    $count = count($entries);
    $eocd = pack('VvvvvVVv', 0x06054b50, 0, 0, $count, $count, strlen($central), strlen($locals), 0);
    file_put_contents($file, $locals . $central . $eocd);
}

test('signed bootstrap verifies RS256, key id, and expiry', function (): void {
    $pair = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($pair, $private);
    $public = openssl_pkey_get_details($pair)['key'];
    $payloadBytes = json_encode(['issued_at' => 900, 'expires_at' => 1100, 'protocol' => ['minimum' => '1.0.0']], JSON_THROW_ON_ERROR);
    $payload = Crypto::base64UrlEncode($payloadBytes);
    openssl_sign($payloadBytes, $signature, $private, OPENSSL_ALGO_SHA256);
    $decoded = Crypto::verifyEnvelope(['kid' => 'test', 'alg' => 'RS256', 'payload' => $payload, 'signature' => Crypto::base64UrlEncode($signature)], ['test' => $public], 1000);
    expect($decoded['expires_at'] === 1100);
    expectThrows(fn () => Crypto::verifyEnvelope(['kid' => 'other', 'alg' => 'RS256', 'payload' => $payload, 'signature' => Crypto::base64UrlEncode($signature)], ['test' => $public], 1000), 'unknown');
    expectThrows(fn () => Crypto::verifyEnvelope(['kid' => 'test', 'alg' => 'RS256', 'payload' => $payload, 'signature' => Crypto::base64UrlEncode($signature)], ['test' => $public], 1200), 'expired');
});

test('committed installer checksum and release metadata match the compiled artifact', function (): void {
    $root = dirname(__DIR__);
    $actualHash = hash_file('sha256', $root . '/install.php');
    $checksumParts = preg_split('/\s+/', trim((string)file_get_contents($root . '/install.php.sha256')));
    $metadata = json_decode((string)file_get_contents($root . '/release.json'), true, 32, JSON_THROW_ON_ERROR);
    expect(($checksumParts[0] ?? '') === $actualHash, 'install.php.sha256 is stale');
    expect(($metadata['installer_sha256'] ?? '') === $actualHash, 'release.json installer hash is stale');
    expect(is_file($root . '/index.php'), 'index.php launcher is missing');
    expect(($metadata['launcher_sha256'] ?? '') === hash_file('sha256', $root . '/index.php'), 'release.json launcher hash is stale');
    expect(($metadata['bundle_files'] ?? []) === ['index.php', 'install.php', 'install.php.sha256', 'release.json'], 'release bundle inventory is stale');
    $release = require $root . '/config/release.php';
    expect(($metadata['signing_key_ids'] ?? []) === array_keys($release['public_keys']), 'release signing key ids are stale');
    expect(($metadata['release_timestamp'] ?? '') === $release['release_timestamp'], 'release.json timestamp is stale');
});

test('installer cleanup accepts only an exact checksum-bound minimal bundle', function (): void {
    $directory = sys_get_temp_dir() . '/scriptbox-finalize-' . bin2hex(random_bytes(6));
    mkdir($directory, 0700);
    try {
        file_put_contents($directory . '/install.php', '<?php echo "installer";');
        file_put_contents($directory . '/index.php', '<?php require __DIR__ . "/install.php";');
        $installerHash = hash_file('sha256', $directory . '/install.php');
        $metadata = ['installer_sha256' => $installerHash, 'launcher_sha256' => hash_file('sha256', $directory . '/index.php'), 'bundle_files' => ['index.php', 'install.php', 'install.php.sha256', 'release.json']];
        file_put_contents($directory . '/install.php.sha256', $installerHash . "  install.php\n");
        file_put_contents($directory . '/release.json', json_encode($metadata, JSON_THROW_ON_ERROR));
        expect(ReleaseFinalizer::eligible($directory), 'exact minimal bundle should be cleanup eligible');
        file_put_contents($directory . '/unknown.txt', 'user file');
        expect(!ReleaseFinalizer::eligible($directory), 'unknown files must prevent automatic cleanup');
        unlink($directory . '/unknown.txt');
        mkdir($directory . '/.git');
        expect(!ReleaseFinalizer::eligible($directory), 'Git checkouts must prevent automatic cleanup');
        rmdir($directory . '/.git');
        file_put_contents($directory . '/install.php.sha256', str_repeat('0', 64) . "  install.php\n");
        expect(!ReleaseFinalizer::eligible($directory), 'checksum mismatches must prevent automatic cleanup');
    } finally {
        foreach (array_diff(scandir($directory) ?: [], ['.', '..']) as $entry) is_dir($directory . '/' . $entry) ? @rmdir($directory . '/' . $entry) : @unlink($directory . '/' . $entry);
        @rmdir($directory);
    }
});

test('installer shell reports and records a safe bootstrap diagnostic', function (): void {
    $root = sys_get_temp_dir() . '/scriptbox-diagnostic-' . bin2hex(random_bytes(4));
    $state = new StateStore($root);
    $api = new ApiClient('https://example.invalid/installer/v1');
    $assets = new AssetManager($api, $state, []);
    $application = new Application($api, $state, $assets, $root, []);
    $_SERVER['SCRIPT_NAME'] = '/install.php';
    ob_start();
    $application->handle('GET', '/', [], '');
    $html = (string)ob_get_clean();
    $diagnostic = $state->read('last_error');
    expect(str_contains($html, 'SIGNING_KEYS_NOT_CONFIGURED'), 'Browser response hides the stable error code');
    expect(str_contains($html, 'This release has no pinned production signing keys'), 'Browser response hides the safe error message');
    expect(($diagnostic['code'] ?? '') === 'SIGNING_KEYS_NOT_CONFIGURED', 'Diagnostic was not recorded');
    expect(isset($diagnostic['diagnostic_id'], $diagnostic['timestamp']), 'Diagnostic metadata is incomplete');
    $state->removeAll();
});

test('asset download diagnostics expose safe HTTP and transport status', function (): void {
    expect(
        AssetManager::downloadFailureMessage(200, 28) === 'UI asset download failed (HTTP 200, cURL 28: transfer timed out)',
        'Timed-out asset diagnostics are not actionable'
    );
    expect(
        AssetManager::downloadFailureMessage(503, 0) === 'UI asset download failed (HTTP 503)',
        'HTTP asset diagnostics are not actionable'
    );
});

test('state is private, atomic, and redacts secrets', function (): void {
    $root = sys_get_temp_dir() . '/scriptbox-test-' . bin2hex(random_bytes(4));
    $store = new StateStore($root);
    $store->write('status', ['phase' => 'preflight', 'database_password' => 'secret']);
    $value = $store->read('status');
    expect($value['phase'] === 'preflight');
    expect(!isset($value['database_password']));
    expect((fileperms($root) & 0777) === 0700);
    $store->removeAll();
});

test('state discovery stays inside open_basedir without using the parent hosting account root', function (): void {
    $documentRoot = '/www/wwwroot/Demo/install.scriptbox.app';
    $installerFile = $documentRoot . '/install/install.php';
    $root = StateStore::resolveDefaultRoot(
        $documentRoot,
        $installerFile,
        $documentRoot . '/:/tmp/',
        '/tmp'
    );
    expect(str_starts_with($root, '/tmp/scriptbox-installer-'), 'Restricted hosting must use its allowed private temporary directory');
    expect(!str_starts_with($root, '/www/wwwroot/Demo/'), 'State must not escape into the parent hosting account directory');
});

test('browser error display is disabled before private state discovery', function (): void {
    $entry = (string)file_get_contents(dirname(__DIR__) . '/src/entry.php');
    $suppression = strpos($entry, "ini_set('display_errors', '0')");
    $discovery = strpos($entry, 'StateStore::discover(');
    expect($suppression !== false && $discovery !== false && $suppression < $discovery, 'Raw PHP warnings must be disabled before state discovery');
});

test('open_basedir fallback does not probe the forbidden parent directory', function (): void {
    $root = dirname(__DIR__);
    $php = <<<'PHP'
require %s;
set_error_handler(static function (int $severity, string $message): never { throw new ErrorException($message, 0, $severity); });
$state = ScriptBox\Installer\StateStore::discover(%s, %s);
if (!str_starts_with($state->root, '/tmp/scriptbox-installer-')) exit(2);
$state->removeAll();
PHP;
    $program = sprintf($php, var_export($root . '/src/Installer.php', true), var_export($root, true), var_export($root . '/install.php', true));
    $command = escapeshellarg(PHP_BINARY) . ' -d ' . escapeshellarg('open_basedir=' . $root . ':/tmp') . ' -r ' . escapeshellarg($program) . ' 2>&1';
    exec($command, $output, $exitCode);
    expect($exitCode === 0, 'Restricted state discovery emitted a warning: ' . implode("\n", $output));
});

test('ownership proof uses the installer route and private state', function (): void {
    $root = sys_get_temp_dir() . '/scriptbox-proof-' . bin2hex(random_bytes(4));
    $state = new StateStore($root);
    $proofs = new OwnershipProof($state, '/install/install.php');
    $proof = $proofs->create();
    expect(str_starts_with($proof['path'], '/install/install.php/.well-known/scriptbox-installer/'));
    expect($proofs->read($proof['id']) === $proof['value']);
    $proofs->remove($proof['id']);
    expect($proofs->read($proof['id']) === null);
    $state->removeAll();
});

test('archive path validation rejects traversal, absolute paths, and symlinks', function (): void {
    expect(ArchiveInspector::isSafePath('payload/index.php'));
    expect(!ArchiveInspector::isSafePath('../index.php'));
    expect(!ArchiveInspector::isSafePath('/etc/passwd'));
    expect(!ArchiveInspector::isSafePath('payload\\evil.php'));
});

test('archive inspection rejects duplicate canonical paths and file-directory collisions', function (): void {
    $root = sys_get_temp_dir() . '/scriptbox-duplicate-zip-' . bin2hex(random_bytes(4));
    mkdir($root, 0700, true);
    $manifest = json_encode([
        'schema_version' => 1,
        'script_id' => 'SCR-001',
        'version' => '1.0.0',
        'runtime' => ['type' => 'static'],
        'database' => ['driver' => 'none', 'migrations' => []],
        'payload' => ['root' => 'payload', 'writable' => []],
        'health_check' => ['path' => '/'],
    ], JSON_THROW_ON_ERROR);
    try {
        foreach (['manifest', 'payload', 'file-directory'] as $case) {
            $file = $root . '/' . $case . '.zip';
            $entries = [['scriptbox.json', $manifest]];
            if ($case === 'manifest') $entries[] = ['scriptbox.json', str_replace('SCR-001', 'SCR-OTHER', $manifest)];
            elseif ($case === 'payload') $entries = [...$entries, ['payload/index.html', 'first'], ['payload/index.html', 'second']];
            else $entries = [...$entries, ['payload/config', 'file'], ['payload/config/', '']];
            writeStoredZip($file, $entries);
            expectInstallerFailure(fn() => ArchiveInspector::inspect($file), 'PACKAGE_ENTRY_INVALID', 400);
        }

        $file = $root . '/migration.zip';
        $migrationManifest = json_encode([
            'schema_version' => 2,
            'script_id' => 'SCR-001',
            'version' => '1.0.0',
            'framework' => 'raw_php',
            'runtime' => ['type' => 'php', 'php' => '>=8.2', 'extensions' => ['pdo_mysql']],
            'database' => ['driver' => 'mysql', 'migrations' => ['migrations/001.jsonl']],
            'inputs' => [], 'configuration' => [],
            'payload' => ['root' => 'payload', 'writable' => []],
            'health_check' => ['path' => '/'],
        ], JSON_THROW_ON_ERROR);
        writeStoredZip($file, [
            ['scriptbox.json', $migrationManifest],
            ['payload/index.php', '<?php'],
            ['migrations/001.jsonl', "{\"driver\":\"mysql\",\"sql\":\"CREATE TABLE x (id INT)\",\"parameters\":[]}\n"],
            ['migrations/001.jsonl', "{\"driver\":\"mysql\",\"sql\":\"CREATE TABLE y (id INT)\",\"parameters\":[]}\n"],
        ]);
        expectInstallerFailure(fn() => ArchiveInspector::inspect($file), 'PACKAGE_ENTRY_INVALID', 400);
    } finally {
        foreach (glob($root . '/*') ?: [] as $file) @unlink($file);
        @rmdir($root);
    }
});

test('installer state lock is exclusive', function (): void {
    $root = sys_get_temp_dir() . '/scriptbox-lock-' . bin2hex(random_bytes(4));
    $first = new StateStore($root);
    $second = new StateStore($root);
    $lock = $first->lock();
    expectThrows(fn () => $second->lock(), 'already');
    $first->unlock($lock);
    $first->removeAll();
});

test('request size enforcement parses bytes instead of the Content-Length digit count', function (): void {
    RequestLimits::assertBodyLength('1048576');
    expectInstallerFailure(fn () => RequestLimits::assertBodyLength('1048577'), 'REQUEST_TOO_LARGE', 413);
    expectInstallerFailure(fn () => RequestLimits::assertBodyLength('invalid'), 'REQUEST_SIZE_INVALID', 400);
    $stream = fopen('php://temp', 'w+b');
    fwrite($stream, str_repeat('x', RequestLimits::MAX_BODY_BYTES + 1)); rewind($stream);
    expectInstallerFailure(fn () => RequestLimits::readBody($stream), 'REQUEST_TOO_LARGE', 413);
    fclose($stream);
});

test('router exposes only fixed local API operations', function (): void {
    expect(Router::resolve('GET', '/api/runtime') === 'runtime');
    expect(Router::resolve('POST', '/api/catalog/search') === 'catalog_search');
    expect(Router::resolve('GET', '/api/catalog/SCR-001') === 'catalog_detail');
    expect(Router::resolve('GET', '/assets/' . str_repeat('a', 64) . '.json') === 'asset');
    expect(Router::resolve('POST', '/api/preflight') === 'preflight');
    expect(Router::resolve('POST', '/api/database/test') === 'database_test');
    expect(Router::resolve('POST', '/api/install/prepare') === 'install_prepare');
    expect(Router::resolve('POST', '/api/install/advance') === 'install_advance');
    expect(Router::resolve('GET', '/api/install/status') === 'install_status');
    expect(Router::resolve('POST', '/api/install/cancel') === 'install_cancel');
    expect(Router::resolve('POST', '/api/finalize') === 'finalize');
    expect(Router::resolve('GET', '/assets/' . str_repeat('a', 64) . '.png') === 'asset');
    expectThrows(fn () => Router::resolve('POST', '/api/proxy'), 'not found');
    expectThrows(fn () => Router::resolve('GET', '/api/fetch?url=https://evil.example'), 'not found');
});

test('target resolver defaults to document root and validates bounded relative subfolders', function (): void {
    $root = sys_get_temp_dir() . '/scriptbox-target-' . bin2hex(random_bytes(4));
    mkdir($root . '/install', 0755, true);
    file_put_contents($root . '/install/install.php', 'installer');
    $default = TargetResolver::inspect($root, $root . '/install', '');
    expect($default['relative'] === '/');
    expect($default['empty'] === true, 'The verified installer control directory must be ignored');
    $nested = TargetResolver::inspect($root, $root . '/install', 'apps/shop');
    expect($nested['relative'] === 'apps/shop');
    expect($nested['can_create'] === true);
    expectThrows(fn () => TargetResolver::inspect($root, $root . '/install', '../outside'), 'target');
    expectThrows(fn () => TargetResolver::inspect($root, $root . '/install', '.hidden'), 'target');
    expectThrows(fn () => TargetResolver::inspect($root, $root . '/install', 'install'), 'control');
    unlink($root . '/install/install.php'); rmdir($root . '/install'); rmdir($root);
});

test('standalone install.php is the only ignored root entry', function (): void {
    $root = sys_get_temp_dir() . '/scriptbox-standalone-' . bin2hex(random_bytes(4));
    mkdir($root, 0755);
    $installer = $root . '/install.php';
    file_put_contents($installer, 'installer');
    expect(TargetResolver::inspect($root, $installer, '')['empty'] === true);
    file_put_contents($root . '/existing.php', 'website');
    expect(TargetResolver::inspect($root, $installer, '')['empty'] === false);
    unlink($root . '/existing.php'); unlink($installer); rmdir($root);
});

test('schema v2 manifests allow supported PHP frameworks and structured inputs but block Node', function (): void {
    $manifest = [
        'schema_version' => 2, 'script_id' => 'SCR-001', 'version' => '2.0.0', 'framework' => 'laravel',
        'runtime' => ['type' => 'php', 'php' => '>=8.3', 'extensions' => ['curl']],
        'database' => ['driver' => 'mysql', 'migrations' => ['migrations/001.json']],
        'inputs' => [['key' => 'admin_password', 'type' => 'password', 'label' => 'Password', 'secret' => true, 'minimum_length' => 12]],
        'payload' => ['root' => 'payload', 'writable' => [['path' => 'storage', 'mode' => '0770']]],
        'configuration' => [['path' => '.env', 'format' => 'dotenv', 'values' => ['APP_URL' => '{{app.url}}']]],
        'health_check' => ['path' => '/'],
    ];
    ArchiveInspector::validateManifest($manifest);
    $manifest['database']['migrations'] = ['migrations/001.jsonl'];
    ArchiveInspector::validateManifest($manifest);
    $manifest['database']['migrations'] = ['migrations/unsafe.sql'];
    expectInstallerFailure(fn () => ArchiveInspector::validateManifest($manifest), 'MANIFEST_INVALID', 400);
    $manifest['database']['migrations'] = ['migrations/001.json'];
    $manifest['framework'] = 'nextjs';
    expectInstallerFailure(fn () => ArchiveInspector::validateManifest($manifest), 'RUNTIME_UNSUPPORTED', 400);
});

test('migration reader retains JSON compatibility and streams JSONL operations', function (): void {
    $archive = sys_get_temp_dir() . '/scriptbox-migrations-' . bin2hex(random_bytes(4)) . '.zip';
    $zip = new ZipArchive(); $zip->open($archive, ZipArchive::CREATE | ZipArchive::OVERWRITE);
    $zip->addFromString('migrations/001.json', json_encode([
        ['driver' => 'sqlite', 'sql' => 'CREATE TABLE first_table (id INT)', 'parameters' => []],
    ], JSON_THROW_ON_ERROR));
    $zip->addFromString('migrations/002.jsonl',
        json_encode(['driver' => 'sqlite', 'sql' => 'CREATE TABLE second_table (id INT)', 'parameters' => []], JSON_THROW_ON_ERROR) . "\n" .
        json_encode(['driver' => 'sqlite', 'sql' => 'INSERT INTO second_table (id) VALUES (?)', 'parameters' => [['value' => 7]]], JSON_THROW_ON_ERROR) . "\n"
    );
    $zip->close();
    try {
        $operations = iterator_to_array(MigrationReader::operations($archive, ['database' => ['migrations' => ['migrations/001.json', 'migrations/002.jsonl']]]), false);
        expect(count($operations) === 3);
        expect(($operations[2]['parameters'][0]['value'] ?? null) === 7);
    } finally { @unlink($archive); }
});

test('migration reader rejects malformed and oversized JSONL lines', function (): void {
    foreach (["{not-json}\n", json_encode(['driver' => 'sqlite', 'sql' => 'UPDATE x SET y = 1', 'parameters' => [], 'padding' => str_repeat('x', 1024 * 1024)], JSON_THROW_ON_ERROR) . "\n"] as $content) {
        $archive = sys_get_temp_dir() . '/scriptbox-bad-migration-' . bin2hex(random_bytes(4)) . '.zip';
        $zip = new ZipArchive(); $zip->open($archive, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        $zip->addFromString('migrations/001.jsonl', $content); $zip->close();
        try { expectInstallerFailure(fn () => iterator_to_array(MigrationReader::operations($archive, ['database' => ['migrations' => ['migrations/001.jsonl']]])), 'MIGRATION_INVALID', 400); }
        finally { @unlink($archive); }
    }
});

test('legacy JSON migration size is rejected from ZIP metadata before allocation', function (): void {
    $directory = sys_get_temp_dir() . '/scriptbox-legacy-size-' . bin2hex(random_bytes(4)); mkdir($directory, 0700);
    $json = $directory . '/oversized.json'; $stream = fopen($json, 'wb');
    fwrite($stream, '[');
    for ($index = 0; $index < 9; $index++) fwrite($stream, str_repeat(' ', 1024 * 1024));
    fwrite($stream, ']'); fclose($stream);
    $archive = $directory . '/oversized.zip'; $zip = new ZipArchive(); $zip->open($archive, ZipArchive::CREATE | ZipArchive::OVERWRITE);
    $zip->addFile($json, 'migrations/001.json'); $zip->setCompressionName('migrations/001.json', ZipArchive::CM_DEFLATE, 9); $zip->close();
    try {
        $baseline = memory_get_usage(true); memory_reset_peak_usage();
        expectInstallerFailure(
            fn () => iterator_to_array(MigrationReader::operations($archive, ['database' => ['migrations' => ['migrations/001.json']]])),
            'MIGRATION_INVALID',
            400,
        );
        expect(memory_get_peak_usage(true) - $baseline < 4 * 1024 * 1024, 'Oversized legacy JSON was allocated before rejection');
    } finally { @unlink($archive); @unlink($json); @rmdir($directory); }
});

test('MongoDB migration validation rejects command smuggling and excessive nesting', function (): void {
    expectInstallerFailure(fn () => MigrationValidator::mongoCommand(['dropDatabase' => 1, 'create' => 'users']), 'MIGRATION_INVALID', 400);
    expectInstallerFailure(fn () => MigrationValidator::mongoCommand(['insert' => 'users', 'documents' => [['_id' => 1]], 'bypassDocumentValidation' => true]), 'MIGRATION_INVALID', 400);
    $nested = 'value'; for ($index = 0; $index < 40; $index++) $nested = ['child' => $nested];
    expectInstallerFailure(fn () => MigrationValidator::mongoCommand(['insert' => 'users', 'documents' => [$nested]]), 'MIGRATION_INVALID', 400);
    expect(MigrationValidator::mongoCommand(['insert' => 'users', 'documents' => [['_id' => 1]], 'ordered' => true])['insert'] === 'users');
});

test('migration placeholder counting ignores quoted literals and SQL comments', function (): void {
    $sql = "INSERT INTO notes (id, body) VALUES (?, '? literal') /* ? */ -- ?\n";
    expect(MigrationValidator::placeholderCount($sql) === 1, 'Only executable placeholders may be counted');
    expect(MigrationValidator::placeholderCount("UPDATE notes SET body='it''s ?' WHERE id=?") === 1);
    expect(MigrationValidator::placeholderCount('UPDATE `?table` SET body="?" WHERE id=?') === 1);
});

test('migration placeholder counting follows database-specific SQL syntax', function (): void {
    expect(MigrationValidator::placeholderCount('UPDATE t SET value=?--?', 'mysql') === 2, 'MySQL -- without whitespace must stay executable');
    expect(MigrationValidator::placeholderCount('UPDATE t SET value=?-- ?', 'mysql') === 1, 'MySQL -- plus whitespace must start a comment');
    expect(MigrationValidator::placeholderCount('UPDATE t SET value=?#?', 'pgsql') === 2, 'PostgreSQL # must not start a comment');
    expect(MigrationValidator::placeholderCount('UPDATE t SET value=? /*!80000 + ? */', 'mysql') === 2, 'MySQL executable comments must stay executable');
    expect(MigrationValidator::placeholderCount('UPDATE t SET value=(ARRAY[?])[?]', 'pgsql') === 2, 'PostgreSQL array brackets must stay executable');
    expect(MigrationValidator::placeholderCount('UPDATE [question?table] SET value=?', 'sqlsrv') === 1, 'SQL Server bracket identifiers must stay quoted');
    expect(MigrationValidator::placeholderCount('UPDATE t SET value=$$?$$ WHERE id=?', 'pgsql') === 1, 'PostgreSQL untagged dollar strings must hide placeholders');
    expect(MigrationValidator::placeholderCount('UPDATE t SET value=$safe$?$safe$ WHERE id=?', 'pgsql') === 1, 'PostgreSQL tagged dollar strings must hide placeholders');
    expect(MigrationValidator::placeholderCount('UPDATE t SET value=$$?$$', 'mysql') === 1, 'MySQL must not treat PostgreSQL dollar syntax as a string');
    expectInstallerFailure(fn() => MigrationValidator::placeholderCount('UPDATE t SET value=$broken$?', 'pgsql'), 'MIGRATION_INVALID', 400);
    expectInstallerFailure(fn() => MigrationValidator::placeholderCount("UPDATE t SET value='safe\\' + LOAD_FILE(?) -- '", 'mysql'), 'MIGRATION_INVALID', 400);
    expectInstallerFailure(fn() => MigrationValidator::placeholderCount("UPDATE t SET value=E'safe\\' || pg_read_file(?) -- '", 'pgsql'), 'MIGRATION_INVALID', 400);
    expect(MigrationValidator::placeholderCount("UPDATE t SET value='O''Reilly' WHERE id=?", 'mysql') === 1, 'Doubled quotes must remain unambiguous');
});

test('migration SQL validation rejects executable INSERT clauses but ignores quoted data', function (): void {
    expectInstallerFailure(
        fn() => MigrationValidator::assertSafeSql('INSERT INTO copied (id) SELECT id FROM private_rows'),
        'MIGRATION_INVALID', 400
    );
    expectInstallerFailure(
        fn() => MigrationValidator::assertSafeSql('INSERT INTO audit (message) VALUES (?) INTO OUTFILE ?'),
        'MIGRATION_INVALID', 400
    );
    MigrationValidator::assertSafeSql("INSERT INTO audit (message) VALUES ('DROP DEFINER OUTFILE is customer data')");
    MigrationValidator::assertSafeSql('INSERT INTO audit (message) VALUES (?)');
});

test('migration SQL rejects nested filesystem imports but ignores quoted data and comments', function (): void {
    foreach ([
        'UPDATE files SET body=LOAD_FILE(?)',
        'UPDATE files SET body=pg_read_file(?)',
        'UPDATE files SET body=pg_read_binary_file(?)',
        'UPDATE files SET oid=lo_import(?)',
        'UPDATE files SET body=OPENROWSET(BULK ?, SINGLE_CLOB)',
        'UPDATE files SET oid=lo_export(?, ?)',
        'UPDATE files SET body=pg_ls_dir(?)',
        'UPDATE files SET body=pg_ls_logdir()',
        'UPDATE files SET body=pg_ls_waldir()',
        'UPDATE files SET body=pg_ls_archive_statusdir()',
        'UPDATE files SET body=pg_ls_logicalmapdir()',
        'UPDATE files SET body=pg_ls_logicalsnapdir()',
        'UPDATE files SET body=pg_ls_replslotdir(?)',
        'UPDATE files SET body=pg_ls_tmpdir()',
        'UPDATE files SET body=pg_stat_file(?)',
        'UPDATE files SET body=pg_file_write(?, ?, ?)',
        'UPDATE files SET body=pg_file_sync(?)',
        'UPDATE files SET body=pg_file_rename(?, ?)',
        'UPDATE files SET body=pg_file_unlink(?)',
        'UPDATE files SET body=pg_logdir_ls()',
        'UPDATE files SET body=readfile(?)',
        'UPDATE files SET body=writefile(?, ?)',
        'UPDATE files SET body=load_extension(?)',
        'UPDATE files SET body=OPENDATASOURCE(?, ?)',
        'UPDATE files SET body=OPENQUERY(?, ?)',
        'UPDATE files SET body=xp_cmdshell(?)',
        'UPDATE files SET body=INSTALL PLUGIN ?',
        'UPDATE files SET body=INSTALL COMPONENT ?',
        'UPDATE files SET body=CREATE ASSEMBLY ?',
        'INSERT INTO files (body) VALUES (?) INTO DUMPFILE ?',
    ] as $sql) {
        expectInstallerFailure(fn() => MigrationValidator::assertSafeSql($sql), 'MIGRATION_INVALID', 400);
    }
    MigrationValidator::assertSafeSql("UPDATE notes SET body='LO_EXPORT PG_LS_DIR PG_STAT_FILE LOAD_EXTENSION PG_FILE_WRITE READFILE WRITEFILE OPENQUERY OPENDATASOURCE XP_CMDSHELL INSTALL PLUGIN CREATE ASSEMBLY' /* pg_file_unlink */");
    MigrationValidator::assertSafeSql('UPDATE notes SET body=? /* LO_EXPORT PG_LS_DIR PG_LS_LOGDIR PG_LS_WALDIR PG_LS_ARCHIVE_STATUSDIR PG_LS_LOGICALMAPDIR PG_LS_LOGICALSNAPDIR PG_LS_REPLSLOTDIR PG_LS_TMPDIR PG_STAT_FILE PG_FILE_WRITE PG_FILE_SYNC PG_FILE_RENAME PG_FILE_UNLINK PG_LOGDIR_LS READFILE WRITEFILE LOAD_EXTENSION OPENDATASOURCE OPENQUERY XP_CMDSHELL INSTALL PLUGIN INSTALL COMPONENT CREATE ASSEMBLY */');
});

test('migration SQL cannot hide file access behind another database comment dialect', function (): void {
    foreach ([
        ['mysql', "UPDATE t SET value=0--LOAD_FILE('/etc/passwd')"],
        ['pgsql', "UPDATE t SET value=0#length(pg_read_file('/etc/passwd'))"],
        ['mysql', "UPDATE t SET value=0 /*!80000 + LENGTH(LOAD_FILE('/etc/passwd')) */"],
        ['mariadb', "UPDATE t SET value=0 /*M!100000 + LENGTH(LOAD_FILE('/etc/passwd')) */"],
        ['pgsql', "UPDATE t SET value=(ARRAY[1,2])[length(pg_read_file('/etc/passwd'))]"],
    ] as [$driver, $sql]) {
        expectInstallerFailure(fn() => MigrationValidator::assertSafeSql($sql, $driver), 'MIGRATION_INVALID', 400);
    }
    MigrationValidator::assertSafeSql("UPDATE t SET value=0 -- LOAD_FILE('/etc/passwd')", 'mysql');
    MigrationValidator::assertSafeSql("UPDATE t SET value=0 /* pg_read_file('/etc/passwd') */", 'pgsql');
    MigrationValidator::assertSafeSql('UPDATE [PG_READ_FILE(?)] SET value=?', 'sqlsrv');
});

test('PostgreSQL dollar-quoted strings cannot hide later executable file access', function (): void {
    foreach ([
        'UPDATE t SET value=$$-- inert text$$ || pg_read_file(\'/etc/passwd\')',
        'UPDATE t SET value=$safe$/* inert text */$safe$ || pg_stat_file(\'/etc/passwd\')',
    ] as $sql) {
        expectInstallerFailure(fn() => MigrationValidator::assertSafeSql($sql, 'pgsql'), 'MIGRATION_INVALID', 400);
    }
    MigrationValidator::assertSafeSql('UPDATE t SET value=$$pg_read_file(\'/etc/passwd\') -- LOAD_EXTENSION(?)$$', 'pgsql');
    MigrationValidator::assertSafeSql('UPDATE t SET value=$safe$pg_stat_file(?)$safe$', 'pgsql');
    expectInstallerFailure(
        fn() => MigrationValidator::assertSafeSql('UPDATE t SET value=$broken$pg_read_file(?)', 'pgsql'),
        'MIGRATION_INVALID', 400,
    );
    expectInstallerFailure(
        fn() => MigrationValidator::assertSafeSql('UPDATE t SET value=$$LOAD_FILE(\'/etc/passwd\')$$', 'mysql'),
        'MIGRATION_INVALID', 400,
    );
});

test('migration SQL rejects ambiguous backslash quotes and preserves bound data', function (): void {
    foreach ([
        ['mysql', "UPDATE t SET value='safe\\' + LOAD_FILE(?) -- '"],
        ['mariadb', "UPDATE t SET value='safe\\' + LOAD_FILE(?) -- '"],
        ['pgsql', "UPDATE t SET value='safe\\' || pg_read_file(?) -- '"],
        ['pgsql', "UPDATE t SET value=E'safe\\' || pg_read_file(?) -- '"],
    ] as [$driver, $sql]) {
        expectInstallerFailure(fn() => MigrationValidator::assertSafeSql($sql, $driver), 'MIGRATION_INVALID', 400);
    }
    MigrationValidator::assertSafeSql("UPDATE notes SET body='O''Reilly'", 'mysql');
    MigrationValidator::assertSafeSql("UPDATE notes SET body='C:\\customer\\export'", 'pgsql');
    $operation = ['driver' => 'mysql', 'sql' => 'UPDATE notes SET body=?', 'parameters' => [['value' => "C:\\customer\\O\\'Reilly"]]];
    expect(MigrationValidator::placeholderCount($operation['sql'], 'mysql') === count($operation['parameters']), 'Bound backslash data must not affect SQL lexing');
});

test('migration reader is restartable and keeps large JSONL imports below 64 MiB', function (): void {
    $directory = sys_get_temp_dir() . '/scriptbox-large-migration-' . bin2hex(random_bytes(4)); mkdir($directory, 0700);
    $jsonl = $directory . '/001.jsonl'; $output = fopen($jsonl, 'wb');
    $operation = json_encode(['driver' => 'sqlite', 'sql' => 'INSERT INTO rows_table (id,body) VALUES (?,?)', 'parameters' => [['value' => 1], ['value' => str_repeat('x', 80)]]], JSON_THROW_ON_ERROR) . "\n";
    for ($index = 0; $index < 15000; $index++) fwrite($output, $operation);
    fclose($output);
    $archive = $directory . '/large.zip'; $zip = new ZipArchive(); $zip->open($archive, ZipArchive::CREATE | ZipArchive::OVERWRITE);
    $paths = [];
    for ($chunk = 1; $chunk <= 7; $chunk++) { $path = 'migrations/' . str_pad((string)$chunk, 3, '0', STR_PAD_LEFT) . '.jsonl'; $paths[] = $path; $zip->addFile($jsonl, $path); }
    $zip->close();
    $manifest = ['database' => ['migrations' => $paths]];
    try {
        $partial = 0;
        foreach (MigrationReader::operations($archive, $manifest) as $_) { $partial++; if ($partial === 10) break; }
        expect($partial === 10, 'stream must be safely interruptible');
        memory_reset_peak_usage();
        $count = 0; foreach (MigrationReader::operations($archive, $manifest) as $_) $count++;
        expect($count === 105000, 'stream must restart from the signed archive');
        expect(memory_get_peak_usage(true) < 64 * 1024 * 1024, 'large JSONL migration exceeded 64 MiB peak memory');
    } finally { @unlink($archive); @unlink($jsonl); @rmdir($directory); }
});

test('profile hashes use the same Unicode code-point contract as the Node publisher', function (): void {
    $label = " \t" . str_repeat('🧰', 119) . 'বাংলা-extra ';
    $manifest = [
        'schema_version' => 2, 'script_id' => 'SCR-001', 'version' => '1.2.3', 'framework' => 'laravel',
        'runtime' => ['type' => 'php', 'php' => '>=8.3', 'extensions' => ['curl', 'zip']],
        'database' => ['driver' => 'mysql', 'migrations' => ['database/mysql/001.json']],
        'inputs' => [['key' => 'site_name', 'type' => 'select', 'label' => $label, 'options' => [['value' => $label, 'label' => $label]]]],
        'payload' => ['root' => 'payload', 'writable' => [['path' => 'storage', 'mode' => '0770']]],
        'health_check' => ['path' => '/health'],
    ];
    expect(ArchiveInspector::profileHash($manifest) === 'e5243e25f8843fb89c5f9d01ee2d08ac67f7e727e0811661b90e21e15624fb1b');
});

test('installation run state is resumable, bounded, and never persists request secrets', function (): void {
    $root = sys_get_temp_dir() . '/scriptbox-run-' . bin2hex(random_bytes(4));
    $state = new StateStore($root);
    $run = InstallationRun::prepare($state, ['script_id' => 'SCR-001', 'version' => '2.0.0', 'target' => 'shop', 'database' => ['password' => 'secret'], 'inputs' => ['admin_password' => 'secret']]);
    expect(($run['phase'] ?? '') === 'preflight');
    expect(!str_contains((string)file_get_contents($state->path('run')), 'secret'));
    $state->write('status', ['state' => 'running', 'phase' => 'download']);
    $status = InstallationRun::status($state, $run['run_id']);
    expect($status['run_id'] === $run['run_id']);
    expect($status['phase'] === 'download' && $status['progress_percent'] > 0, 'run status must expose the engine phase safely');
    expect(InstallationRun::canCancel('extract'), 'cancellation before promotion must remain safe');
    expect(!InstallationRun::canCancel('promote') && !InstallationRun::canCancel('health') && !InstallationRun::canCancel('complete'), 'cancellation at or after promotion must be rejected');
    expectInstallerFailure(fn () => InstallationRun::prepare($state, ['script_id' => 'SCR-001', 'version' => '2.0.0', 'target' => 'shop']), 'RUN_ACTIVE', 409);
    expectInstallerFailure(fn () => InstallationRun::status($state, 'wrong-run'), 'RUN_NOT_FOUND', 404);
    $state->removeAll();
});

test('installation runs are bound to the verified browser installation id', function (): void {
    $root = sys_get_temp_dir() . '/scriptbox-run-owner-' . bin2hex(random_bytes(4));
    $state = new StateStore($root);
    try {
        $run = InstallationRun::prepare($state, ['script_id' => 'SCR-001', 'version' => '2.0.0', 'target' => '/']);
        $owner = bin2hex(random_bytes(16));
        InstallationRun::bindOwner($state, $run['run_id'], $owner);
        InstallationRun::assertOwner($state, $run['run_id'], $owner);
        expectInstallerFailure(
            fn () => InstallationRun::assertOwner($state, $run['run_id'], bin2hex(random_bytes(16))),
            'RUN_NOT_FOUND',
            404
        );
        expectInstallerFailure(
            fn () => InstallationRun::assertOwner($state, str_repeat('0', 32), $owner),
            'RUN_NOT_FOUND',
            404
        );
    } finally {
        $state->removeAll();
    }
});

test('interrupted downloads keep resumable bytes but invalid artifacts do not', function (): void {
    expect(InstallEngine::preservesPartialDownloadFor(new InstallerException('interrupted', 'DOWNLOAD_FAILED', 502)));
    expect(InstallEngine::preservesPartialDownloadFor(new InstallerException('expired', 'DOWNLOAD_AUTHORIZATION_FAILED', 502)));
    expect(!InstallEngine::preservesPartialDownloadFor(new InstallerException('hash mismatch', 'FILE_HASH_MISMATCH', 400)));
});

test('an activated license is an irreversible boundary for local rollback', function (): void {
    expect(InstallEngine::rollbackAllowedAfterActivation(false));
    expect(!InstallEngine::rollbackAllowedAfterActivation(true));
});

test('direct-only media removes local and remote proxy routes while preserving HTTPS image CSP', function (): void {
    expectThrows(fn () => Router::resolve('GET', '/api/media?token=header.payload.signature'), 'not found');
    expectThrows(fn () => Router::resolve('GET', '/api/media/header.payload.signature'), 'not found');
    $client = new ApiClient('https://example.invalid/installer/v1');
    $assertAllowed = new ReflectionMethod($client, 'assertAllowed');
    expectThrows(fn () => $assertAllowed->invoke($client, 'GET', '/catalog/media?token=header.payload.signature'), 'allowlisted');
    expectThrows(fn () => $assertAllowed->invoke($client, 'GET', '/catalog/media/header.payload.signature'), 'allowlisted');
    expect(str_contains(Application::contentSecurityPolicy(), "img-src 'self' data: https:"));
});

test('runtime build identity uses the configured release timestamp and running artifact hash', function (): void {
    $artifact = tempnam(sys_get_temp_dir(), 'scriptbox-artifact-');
    expect($artifact !== false, 'Cannot create runtime identity fixture');
    file_put_contents($artifact, 'installer-artifact');
    $identity = BuildIdentity::fromRelease([
        'version' => 'test-1.2.3',
        'release_timestamp' => '2026-08-21T00:00:00+00:00',
    ], $artifact);
    expect($identity === [
        'installer_version' => 'test-1.2.3',
        'release_timestamp' => '2026-08-21T00:00:00+00:00',
        'artifact_sha256' => 'd65ac6977a444a0db947102d2d45658a2183db86084675a69eeffafbb1f7519a',
    ], 'Runtime identity must be release-pinned and hash the served artifact');
    unlink($artifact);
});

test('origin detection uses direct HTTPS without trusting browser input', function (): void {
    $root = sys_get_temp_dir() . '/scriptbox-origin-' . bin2hex(random_bytes(4));
    $state = new StateStore($root);
    $detected = OriginDetector::detect([
        'HTTPS' => 'on', 'HTTP_HOST' => 'install.example.com', 'SERVER_PORT' => '443', 'REMOTE_ADDR' => '198.51.100.10',
    ], $state, '');
    expect($detected['origin'] === 'https://install.example.com');
    expect($detected['source'] === 'request');
    expectThrows(fn () => OriginDetector::detect(['HTTPS' => 'off', 'HTTP_HOST' => 'install.example.com'], $state, ''), 'https');
    $state->removeAll();
});

test('origin detection rejects request-host userinfo', function (): void {
    $root = sys_get_temp_dir() . '/scriptbox-origin-userinfo-' . bin2hex(random_bytes(4));
    $state = new StateStore($root);
    expectThrows(fn () => OriginDetector::detect(['HTTPS' => 'on', 'HTTP_HOST' => 'attacker@install.example.com', 'REMOTE_ADDR' => '203.0.113.5'], $state, ''), 'HTTPS origin');
    $state->removeAll();
});

test('origin detection accepts forwarded HTTPS only from a trusted proxy', function (): void {
    $root = sys_get_temp_dir() . '/scriptbox-proxy-' . bin2hex(random_bytes(4));
    $state = new StateStore($root);
    $server = ['HTTPS' => 'off', 'HTTP_HOST' => 'internal.local', 'REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_PROTO' => 'https', 'HTTP_X_FORWARDED_HOST' => 'public.example.com'];
    $detected = OriginDetector::detect($server, $state, '10.0.0.0/24');
    expect($detected['origin'] === 'https://public.example.com');
    expect($detected['source'] === 'trusted_proxy');
    expectThrows(fn () => OriginDetector::detect($server, $state, '10.1.0.0/24'), 'https');
    $state->removeAll();
});

test('origin detection gives configured CLI public URL precedence', function (): void {
    $root = sys_get_temp_dir() . '/scriptbox-cli-origin-' . bin2hex(random_bytes(4));
    $state = new StateStore($root);
    $state->write('server', ['public_url' => 'https://cli.example.com']);
    $detected = OriginDetector::detect(['HTTPS' => 'off', 'HTTP_HOST' => 'internal.local'], $state, '');
    expect($detected['origin'] === 'https://cli.example.com');
    expect($detected['source'] === 'cli');
    $state->removeAll();
});

test('preflight reports PHP and database adapters without phpinfo or secrets', function (): void {
    $result = Preflight::capabilities(sys_get_temp_dir());
    expect(version_compare($result['php']['version'], '8.3.0', '>='));
    expect(isset($result['extensions']) && is_array($result['extensions']));
    expect(!array_key_exists('phpinfo', $result));
    expect(isset($result['databases']['sqlite']));
    expect(Preflight::supportsPhp('>=8.3', '8.3.1'));
    expect(!Preflight::supportsPhp('>=8.4', '8.3.1'));
    expect(!Preflight::supportsPhp('^8.3', '8.3.1'));
    expectInstallerFailure(fn () => Preflight::assertPackageRequirements(['runtime' => ['type' => 'php', 'php' => '>=99.0', 'extensions' => []], 'database' => ['driver' => 'none']]), 'PHP_VERSION_UNSUPPORTED', 400);
});

test('preflight blocks a target that PHP-FPM cannot write', function (): void {
    expectThrows(fn () => Preflight::assertWritableTarget('/path/that/does/not/exist'), 'not writable');
});

test('configuration writers escape dotenv, JSON, and PHP array values', function (): void {
    $root = sys_get_temp_dir() . '/scriptbox-config-' . bin2hex(random_bytes(4));
    mkdir($root, 0700);
    ConfigurationWriter::write($root, ['path' => '.env', 'format' => 'dotenv', 'values' => ['APP_NAME' => 'Demo "Site"']], []);
    expect(str_contains((string)file_get_contents($root . '/.env'), 'APP_NAME="Demo \\"Site\\""'));
    ConfigurationWriter::write($root, ['path' => 'config/app.json', 'format' => 'json', 'values' => ['enabled' => true]], []);
    expect(json_decode((string)file_get_contents($root . '/config/app.json'), true)['enabled'] === true);
    ConfigurationWriter::write($root, ['path' => 'config/app.php', 'format' => 'php-array', 'values' => ['quote' => "a'b"]], []);
    expect(str_starts_with((string)file_get_contents($root . '/config/app.php'), '<?php'));
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($iterator as $item) $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
    rmdir($root);
});

test('signed PNG assets are served locally and direct HTTPS images are allowed by CSP', function (): void {
    $root = sys_get_temp_dir() . '/scriptbox-png-' . bin2hex(random_bytes(4));
    $state = new StateStore($root);
    $bytes = "\x89PNG\r\n\x1a\nlogo";
    $hash = hash('sha256', $bytes);
    file_put_contents($root . '/asset-' . $hash . '.png', $bytes);
    $asset = (new AssetManager(new ApiClient('https://example.invalid/installer/v1'), $state, []))->pathForRequest('/assets/' . $hash . '.png');
    expect($asset['type'] === 'image/png');
    expect(str_contains(Application::contentSecurityPolicy(), "img-src 'self' data: https:"));
    $state->removeAll();
});

test('token templates encode allowlisted values and migration password transforms never expose plaintext', function (): void {
    $root = sys_get_temp_dir() . '/scriptbox-template-' . bin2hex(random_bytes(4));
    mkdir($root, 0700);
    ConfigurationWriter::write($root, [
        'path' => 'config/local.php', 'format' => 'token-template',
        'template' => "<?php return ['name' => '{{input.site_name|php-string}}'];\n",
    ], ['input.site_name' => "O'Reilly"]);
    expect(str_contains((string)file_get_contents($root . '/config/local.php'), "O\\'Reilly"));
    $hash = ValueResolver::migrationParameter(['source' => 'input.admin_password', 'transform' => 'bcrypt'], ['input.admin_password' => 'secret-password']);
    expect($hash !== 'secret-password' && password_verify('secret-password', $hash));
    $documentedHash = ValueResolver::migrationParameter([
        'source' => 'input.admin_password', 'transform' => 'password_hash', 'algorithm' => 'bcrypt',
    ], ['input.admin_password' => 'secret-password']);
    expect($documentedHash !== 'secret-password' && password_verify('secret-password', $documentedHash));
    expect(ValueResolver::migrationParameter(['value' => 42], []) === 42);
    expect(ValueResolver::migrationParameter(['value' => null], []) === null);
    expectInstallerFailure(fn () => ValueResolver::migrationParameter(['value' => ['unsafe']], []), 'MIGRATION_INVALID', 400);
    expectInstallerFailure(fn () => ValueResolver::migrationParameter(['source' => 'input.admin_password', 'value' => 'secret-password'], ['input.admin_password' => 'secret-password']), 'MIGRATION_INVALID', 400);
    expectInstallerFailure(fn () => ValueResolver::source('environment.SECRET', []), 'CONFIG_INVALID', 400);
    unlink($root . '/config/local.php'); rmdir($root . '/config'); rmdir($root);
});

test('generated application keys use the Laravel base64 key contract', function (): void {
    $key = ValueResolver::generatedAppKey();
    expect(str_starts_with($key, 'base64:'), 'Generated application key is missing the Laravel base64 prefix');
    $decoded = base64_decode(substr($key, 7), true);
    expect(is_string($decoded) && strlen($decoded) === 32, 'Generated application key must decode to exactly 32 bytes');
});

test('database recovery markers bind reset credentials to the original database', function (): void {
    $first = sys_get_temp_dir() . '/scriptbox-db-first-' . bin2hex(random_bytes(4)) . '.sqlite';
    $second = sys_get_temp_dir() . '/scriptbox-db-second-' . bin2hex(random_bytes(4)) . '.sqlite';
    touch($first); touch($second);
    $config = ['driver' => 'sqlite', 'path' => $first];
    $database = DatabaseSession::connect($config);
    $database->assertEmpty($config);
    $marker = bin2hex(random_bytes(32)); $digest = hash('sha256', $marker);
    $database->createRecoveryMarker($config, $marker);
    expect($database->recoveryMarkerMatches($config, $digest));
    expect(!DatabaseSession::connect(['driver' => 'sqlite', 'path' => $second])->recoveryMarkerMatches(['driver' => 'sqlite', 'path' => $second], $digest));
    $database->resetToEmpty($config); $database->assertEmpty($config);
    unlink($first); unlink($second);
});

test('database sessions consume streamed literal operations and reject a mismatched driver', function (): void {
    $file = sys_get_temp_dir() . '/scriptbox-stream-db-' . bin2hex(random_bytes(4)) . '.sqlite'; touch($file);
    $config = ['driver' => 'sqlite', 'path' => $file];
    $database = DatabaseSession::connect($config);
    try {
        $operations = (function (): Generator {
            yield ['driver' => 'sqlite', 'sql' => 'CREATE TABLE imported (id INT, name TEXT)', 'parameters' => []];
            yield ['driver' => 'sqlite', 'sql' => 'INSERT INTO imported (id,name) VALUES (?,?)', 'parameters' => [['value' => 1], ['value' => 'Demo']]];
        })();
        $database->applyOperations($operations, $config);
        $pdo = new PDO('sqlite:' . $file);
        expect($pdo->query('SELECT name FROM imported WHERE id = 1')->fetchColumn() === 'Demo');
        expectInstallerFailure(fn () => $database->applyOperations((function (): Generator { yield ['driver' => 'mysql', 'sql' => 'UPDATE imported SET name = ?', 'parameters' => [['value' => 'Unsafe']]]; })(), $config), 'MIGRATION_INVALID', 400);
    } finally { @unlink($file); }
});

test('database sessions bind every PDO scalar with an explicit safe type', function (): void {
    $file = sys_get_temp_dir() . '/scriptbox-bind-db-' . bin2hex(random_bytes(4)) . '.sqlite'; touch($file);
    $config = ['driver' => 'sqlite', 'path' => $file];
    $database = DatabaseSession::connect($config);
    try {
        $database->applyOperations((function (): Generator {
            yield ['driver' => 'sqlite', 'sql' => 'CREATE TABLE scalar_values (null_value, bool_value, int_value, float_value, string_value)', 'parameters' => []];
            yield [
                'driver' => 'sqlite',
                'sql' => 'INSERT INTO scalar_values VALUES (?,?,?,?,?)',
                'parameters' => [
                    ['value' => null], ['value' => true], ['value' => 42], ['value' => 1.25], ['value' => '42'],
                ],
            ];
        })(), $config);
        $pdo = new PDO('sqlite:' . $file);
        $types = $pdo->query('SELECT typeof(null_value), typeof(bool_value), typeof(int_value), typeof(float_value), typeof(string_value) FROM scalar_values')->fetch(PDO::FETCH_NUM);
        expect($types === ['null', 'integer', 'integer', 'text', 'text'], 'PDO scalar types were not bound explicitly');

        $database->applyOperations((function (): Generator {
            yield [
                'driver' => 'sqlite',
                'sql' => "INSERT INTO scalar_values (int_value, string_value) VALUES (?, '? customer text') /* ? */ -- ?\n",
                'parameters' => [['value' => 7]],
            ];
        })(), $config);
        expect((int)$pdo->query('SELECT COUNT(*) FROM scalar_values')->fetchColumn() === 2, 'Quoted question marks must not consume parameters');
    } finally { @unlink($file); }
});

test('MySQL package migrations never bypass foreign-key integrity checks', function (): void {
    $source = (string)file_get_contents(dirname(__DIR__) . '/src/Installer.php');
    $start = strpos($source, 'public function applyOperations(');
    $end = strpos($source, 'public function createRecoveryMarker(', $start ?: 0);
    $method = $start !== false && $end !== false ? substr($source, $start, $end - $start) : '';
    expect($method !== '' && !str_contains($method, 'SET FOREIGN_KEY_CHECKS=0'), 'Package migrations must not disable MySQL foreign-key validation');
});

test('journal recovery deletes only hash-bound files and completed directories', function (): void {
    $root = sys_get_temp_dir() . '/scriptbox-journal-target-' . bin2hex(random_bytes(4)); mkdir($root, 0700);
    $stateRoot = sys_get_temp_dir() . '/scriptbox-journal-state-' . bin2hex(random_bytes(4)); $state = new StateStore($stateRoot);
    file_put_contents($root . '/owned.php', 'owned'); file_put_contents($root . '/changed.php', 'changed'); mkdir($root . '/intent-only');
    $events = [
        ['phase' => 'promote_intent', 'relative' => 'owned.php', 'directory' => false, 'bytes' => 5, 'sha256' => hash('sha256', 'owned')],
        ['phase' => 'promote_intent', 'relative' => 'changed.php', 'directory' => false, 'bytes' => 8, 'sha256' => hash('sha256', 'original')],
        ['phase' => 'promote_intent', 'relative' => 'intent-only', 'directory' => true],
    ];
    $engine = new InstallEngine(new ApiClient('https://example.invalid/installer/v1'), $state, $root, []);
    $rollback = new ReflectionMethod($engine, 'rollbackJournal');
    expect($rollback->invoke($engine, $events, $root) === false, 'unproven entries must keep recovery locked');
    expect(!file_exists($root . '/owned.php'), 'matching installer file must be removed');
    expect(is_file($root . '/changed.php'), 'changed file must never be removed');
    expect(is_dir($root . '/intent-only'), 'intent-only directory must never be removed');
    unlink($root . '/changed.php'); rmdir($root . '/intent-only'); rmdir($root); $state->removeAll();
});

$failures = 0;
foreach ($tests as $name => $callback) {
    try { $callback(); fwrite(STDOUT, "ok - {$name}\n"); }
    catch (Throwable $error) { $failures++; fwrite(STDERR, "not ok - {$name}: {$error->getMessage()}\n"); }
}
fwrite(STDOUT, count($tests) . " tests, {$failures} failures\n");
exit($failures === 0 ? 0 : 1);
