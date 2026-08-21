<?php
declare(strict_types=1);

namespace ScriptBox\Installer;

if (!class_exists(Application::class)) require __DIR__ . '/Installer.php';
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
ini_set('session.use_strict_mode', '1'); ini_set('session.use_only_cookies', '1'); ini_set('session.save_path', $sessionDirectory); ini_set('display_errors', '0');
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
