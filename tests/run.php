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
use ScriptBox\Installer\CatalogMedia;
use ScriptBox\Installer\MediaBuffer;
use ScriptBox\Installer\OwnershipProof;
use ScriptBox\Installer\OriginDetector;
use ScriptBox\Installer\TargetResolver;
use ScriptBox\Installer\InstallationRun;
use ScriptBox\Installer\ValueResolver;
use ScriptBox\Installer\ReleaseFinalizer;
use ScriptBox\Installer\RequestLimits;
use ScriptBox\Installer\DatabaseSession;
use ScriptBox\Installer\InstallEngine;

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
    expect(Router::resolve('GET', '/api/media?token=header.payload.signature') === 'catalog_media');
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
    $manifest['framework'] = 'nextjs';
    expectInstallerFailure(fn () => ArchiveInspector::validateManifest($manifest), 'RUNTIME_UNSUPPORTED', 400);
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

test('API allowlist accepts the fixed catalog media query route', function (): void {
    $client = new ApiClient('https://example.invalid/installer/v1');
    $assertAllowed = new ReflectionMethod($client, 'assertAllowed');
    $assertAllowed->invoke($client, 'GET', '/catalog/media?token=header.payload.signature');
    expectThrows(fn () => $assertAllowed->invoke($client, 'GET', '/admin?token=header.payload.signature'), 'allowlisted');
});

test('media validation measures buffered bytes when the stream cursor is zero', function (): void {
    $temporary = tmpfile();
    expect($temporary !== false, 'Cannot create temporary media stream');
    fwrite($temporary, 'catalog-image-bytes');
    rewind($temporary);
    expect(ftell($temporary) === 0, 'Regression setup requires a zero cursor');
    expect(MediaBuffer::validatedSize($temporary) === 19, 'Media validation must use the buffered stream size, not its cursor');
    fclose($temporary);
});

test('bounded media writer aborts before accepting bytes beyond the size limit', function (): void {
    $temporary = tmpfile();
    expect($temporary !== false, 'Cannot create temporary media stream');
    $buffer = new MediaBuffer($temporary);
    $limit = str_repeat('x', MediaBuffer::MAX_BYTES);
    expect($buffer->write(null, $limit) === MediaBuffer::MAX_BYTES, 'Writer must accept bytes through the size limit');
    expect($buffer->write(null, 'x') === 0, 'Writer must abort the transfer before writing an oversized chunk');
    expect($buffer->limitExceeded(), 'Writer must retain the safe oversized-media outcome');
    expectInstallerFailure(fn () => $buffer->assertWithinLimit(), 'MEDIA_SIZE_INVALID', 502);
    expect(fstat($temporary)['size'] === MediaBuffer::MAX_BYTES, 'Writer must not buffer bytes beyond the limit');
    fclose($temporary);
});

test('catalog media validation accepts a supported type after normalizing its parameters', function (): void {
    $temporary = tmpfile();
    expect($temporary !== false, 'Cannot create temporary media stream');
    fwrite($temporary, 'catalog-image-bytes');
    expect(CatalogMedia::validate(true, 200, 'image/png; charset=binary', $temporary) === ['content_type' => 'image/png', 'bytes' => 19]);
    fclose($temporary);
});

test('catalog media validation reports a transport failure without cURL details', function (): void {
    $temporary = tmpfile();
    expect($temporary !== false, 'Cannot create temporary media stream');
    expectInstallerFailure(fn () => CatalogMedia::validate(false, 0, '', $temporary), 'MEDIA_DOWNLOAD_FAILED', 502);
    fclose($temporary);
});

test('catalog media validation reports a non-200 upstream response', function (): void {
    $temporary = tmpfile();
    expect($temporary !== false, 'Cannot create temporary media stream');
    expectInstallerFailure(fn () => CatalogMedia::validate(true, 503, 'image/png', $temporary), 'MEDIA_UPSTREAM_STATUS', 502);
    fclose($temporary);
});

test('catalog media validation reports an unsupported content type', function (): void {
    $temporary = tmpfile();
    expect($temporary !== false, 'Cannot create temporary media stream');
    fwrite($temporary, 'catalog-image-bytes');
    expectInstallerFailure(fn () => CatalogMedia::validate(true, 200, 'text/html', $temporary), 'MEDIA_TYPE_UNSUPPORTED', 502);
    fclose($temporary);
});

test('catalog media validation reports an empty media buffer', function (): void {
    $temporary = tmpfile();
    expect($temporary !== false, 'Cannot create temporary media stream');
    expectInstallerFailure(fn () => CatalogMedia::validate(true, 200, 'image/png', $temporary), 'MEDIA_SIZE_INVALID', 502);
    fclose($temporary);
});

test('catalog media validation reports an oversized media buffer', function (): void {
    $temporary = tmpfile();
    expect($temporary !== false, 'Cannot create temporary media stream');
    expect(ftruncate($temporary, 8 * 1024 * 1024 + 1) === true, 'Cannot create oversized media fixture');
    expectInstallerFailure(fn () => CatalogMedia::validate(true, 200, 'image/png', $temporary), 'MEDIA_SIZE_INVALID', 502);
    fclose($temporary);
});

test('catalog media rejects an invalid local token with a 404', function (): void {
    $client = new ApiClient('https://example.invalid/installer/v1');
    expectInstallerFailure(fn () => $client->streamCatalogMedia('invalid token'), 'MEDIA_NOT_FOUND', 404);
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
    expectInstallerFailure(fn () => ValueResolver::source('environment.SECRET', []), 'CONFIG_INVALID', 400);
    unlink($root . '/config/local.php'); rmdir($root . '/config'); rmdir($root);
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
