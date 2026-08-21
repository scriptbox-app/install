# Deterministic release

This public guide covers building and verifying the open-source PHP artifact. Private signing-key custody, production UI publication, database changes, and artifact promotion belong to the confidential API operator runbook.

## Inputs

- PHP 8.3+.
- Reviewed source and tests.
- Approved current and optional next public PEM keys in `config/release.php`.
- The public API base URL and installer version.

Never put a private key, token, password, `.env` value, or storage credential in this repository or generated `install.php`.

## Build

```bash
php tests/run.php
php build/release.php
php -l install.php
sha256sum -c install.php.sha256
```

`build/release.php` compiles the focused PHP source modules into the committed single file, updates the checksum and release metadata, and optionally signs release metadata when an approved offline release-signing key is explicitly supplied. The release timestamp is an explicit reviewed value in `config/release.php`; no build command inserts the current wall-clock time into the compiled installer.

## Determinism check

```bash
first=$(sha256sum install.php | cut -d' ' -f1)
php build/compile.php
second=$(sha256sum install.php | cut -d' ' -f1)
test "$first" = "$second"
```

Generated output must be byte-for-byte identical for the same source, release configuration, PHP version, and compiler inputs.

## Public release contents

- Versioned `install.php`.
- `install.php.sha256`.
- `release.json` containing version, protocol, installer hash, public signing-key IDs, and the immutable release timestamp.
- Public documentation, changelog, security policy, privacy policy, and license.
- Safe examples and test fixtures without production trust material.

## Verification by users

Users should download the installer and checksum from an approved release, calculate SHA-256 locally, and compare before upload. A mismatch stops deployment. After upload, request `https://example.com/install.php/api/runtime` and confirm `data.build.artifact_sha256` equals the same reviewed SHA-256 fingerprint; this verifies the artifact actually running on the host. Public release metadata signatures, when supplied, should be verified through the separately published release-verification procedure.

## Cross-project release rule

If PHP/API/UI behavior or contracts change, all affected repositories must be tested together. UI and package bytes are immutable once published; fixes use a new version. An older installer remains supported only while its declared protocol overlaps the API compatibility window.

Never use example/development keys in production.
