<?php
declare(strict_types=1);

$root = dirname(__DIR__);
$source = (string)file_get_contents($root . '/src/Installer.php');
$entry = (string)file_get_contents($root . '/src/entry.php');
$release = require $root . '/config/release.php';
$marker = "namespace ScriptBox\\Installer;";
$offset = strpos($entry, $marker);
if ($offset === false || !str_starts_with($source, '<?php')) throw new RuntimeException('Installer source format is invalid');
$entry = ltrim(substr($entry, $offset + strlen($marker)));
$compiled = rtrim($source) . "\n\ndefine('SCRIPTBOX_COMPILED_RELEASE', " . var_export($release, true) . ");\n\n" . $entry;
$compiled = str_replace("\r\n", "\n", $compiled);
if (file_put_contents($root . '/install.php', $compiled, LOCK_EX) === false) throw new RuntimeException('Unable to write install.php');
chmod($root . '/install.php', 0644);
fwrite(STDOUT, hash('sha256', $compiled) . "  install.php\n");
