<?php
declare(strict_types=1);

$root = dirname(__DIR__);
require $root . '/build/compile.php';
$release = require $root . '/config/release.php';
$hash = hash_file('sha256', $root . '/install.php');
$metadata = ['version' => $release['version'], 'protocol' => 'installer-v1', 'installer_sha256' => $hash, 'signing_key_ids' => array_keys($release['public_keys']), 'release_timestamp' => $release['release_timestamp']];
$json = json_encode($metadata, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
file_put_contents($root . '/release.json', $json, LOCK_EX);
file_put_contents($root . '/install.php.sha256', $hash . "  install.php\n", LOCK_EX);
$keyFile = getenv('SCRIPTBOX_RELEASE_SIGNING_KEY');
if ($keyFile !== false && $keyFile !== '') {
    $key = openssl_pkey_get_private((string)file_get_contents($keyFile));
    if ($key === false || !openssl_sign($json, $signature, $key, OPENSSL_ALGO_SHA256)) throw new RuntimeException('Release signing failed');
    file_put_contents($root . '/release.json.sig', rtrim(strtr(base64_encode($signature), '+/', '-_'), '=') . "\n", LOCK_EX);
} else {
    fwrite(STDERR, "Release metadata is unsigned; set SCRIPTBOX_RELEASE_SIGNING_KEY for a production release.\n");
}
