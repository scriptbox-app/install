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
    expect(($metadata['signing_key_ids'] ?? []) === array_keys((require $root . '/config/release.php')['public_keys']), 'release signing key ids are stale');
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

test('router exposes only fixed local API operations', function (): void {
    expect(Router::resolve('GET', '/api/runtime') === 'runtime');
    expect(Router::resolve('POST', '/api/catalog/search') === 'catalog_search');
    expect(Router::resolve('GET', '/api/catalog/SCR-001') === 'catalog_detail');
    expectThrows(fn () => Router::resolve('POST', '/api/proxy'), 'not found');
    expectThrows(fn () => Router::resolve('GET', '/api/fetch?url=https://evil.example'), 'not found');
});

test('preflight reports PHP and database adapters without phpinfo or secrets', function (): void {
    $result = Preflight::capabilities(sys_get_temp_dir());
    expect(version_compare($result['php']['version'], '8.3.0', '>='));
    expect(isset($result['extensions']) && is_array($result['extensions']));
    expect(!array_key_exists('phpinfo', $result));
    expect(isset($result['databases']['sqlite']));
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

$failures = 0;
foreach ($tests as $name => $callback) {
    try { $callback(); fwrite(STDOUT, "ok - {$name}\n"); }
    catch (Throwable $error) { $failures++; fwrite(STDERR, "not ok - {$name}: {$error->getMessage()}\n"); }
}
fwrite(STDOUT, count($tests) . " tests, {$failures} failures\n");
exit($failures === 0 ? 0 : 1);
