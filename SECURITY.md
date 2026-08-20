# Security policy

Security reports must be sent privately through the ScriptBox security contact or the repository host’s private vulnerability-reporting feature. Do not open a public issue containing exploit details, credentials, private artifact URLs, customer information, or server logs with sensitive values.

Include the affected installer version and checksum, PHP/runtime versions, stable error code, reproduction steps, impact, and a minimal proof of concept. Remove tokens, passwords, file contents, raw databases, and identifying customer data.

## Supported scope

Security support covers the current released installer-v1 line. Development snapshots are accepted for coordinated testing but should not be deployed as production releases.

## Required security properties

- Only RS256 envelopes signed by compiled current/next public keys are trusted.
- UI and package bytes must match signed hashes and sizes exactly.
- Remote operations are limited to fixed HTTPS `/installer/v1` routes.
- Origin verification rejects redirects, invalid TLS, private/reserved addresses, and unsafe proof paths.
- Archives reject traversal, absolute paths, links, devices, unbounded files, and expansion bombs.
- Installations require an empty target and database, exclusive lock, staging, journal, health check, and proven rollback.
- Installer state remains outside the document root with restrictive permissions.
- Secrets never enter telemetry, diagnostics, logs, release metadata, public documentation, or MCP resources.
- Paid checkout remains disabled until a separately reviewed entitlement and payment design is released.

## Safe deployment

Verify the published SHA-256 before uploading `install.php`. Use PHP 8.3+, HTTPS, a dedicated empty target, least-privilege PHP-FPM ownership, and a pre-created restricted database user. Never use `0777`, disable TLS verification, bypass signature checks, edit signed hashes, or expose private state through the web server.

Public keys are not secrets. Trust comes from validating signatures and immutable bytes. No key embedded in public source can protect a symmetric encryption scheme from the person running that source.

## If compromise is suspected

Stop installation, preserve the installer checksum and sanitized diagnostic ID, revoke exposed credentials or tokens, isolate the affected target, and contact ScriptBox privately. Do not retry after a signature, package-integrity, or recovery failure until the release or server state has been reviewed.

Before production, rotate every credential previously committed to Project 2, keep FTP routes unregistered, configure exact HTTPS CORS/proxy ranges, and confirm startup rejects defaults. Public keys are not secrets—trust comes from signatures and validation, not obfuscation.
