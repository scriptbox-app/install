# ScriptBox Signed Installer

ScriptBox provides a single-file PHP installer for deploying approved static and PHP applications from the ScriptBox catalog. A user uploads `install.php`, opens it over HTTPS, completes the guided React interface, and lets the installer perform validated download, configuration, database migration, health checking, and rollback.

```text
Browser → install.php → signed ScriptBox API → private application package
            ├─ verifies the signed UI and package
            ├─ checks PHP, filesystem, and database support
            ├─ stages changes before promotion
            └─ rolls back when an installation fails
```

This repository is public. It contains no production private keys, API credentials, customer secrets, or hidden encryption keys.

## Why use it

- One portable `install.php` works with cPanel, aaPanel, Apache, Nginx/PHP-FPM, VPS, and compatible cloud hosting.
- The browser interface does not need Node.js on the customer server.
- Signed bootstrap metadata pins the approved React assets and their exact SHA-256 hashes and sizes.
- Application archives are private, short-lived, and verified before extraction.
- ZIP traversal, links, device files, expansion bombs, arbitrary hooks, Composer, npm, and shell commands are rejected.
- Installations use staging, an exclusive lock, an append-only journal, health checks, and rollback.
- Database passwords and application secrets remain on the customer server and are excluded from telemetry and diagnostics.
- Stable error codes and diagnostic IDs make support possible without exposing raw exceptions.

## Supported applications

Version 1 installs self-contained applications with runtime type `static` or `php`. Node.js and Next.js applications may appear in the catalog but cannot be automatically installed. Packages cannot install operating-system packages, PHP extensions, Composer dependencies, npm dependencies, services, cron jobs, or arbitrary commands.

Database support depends on extensions already installed in PHP:

| Database | Required PHP capability |
|---|---|
| None | No database extension |
| MySQL / MariaDB | `pdo_mysql` |
| PostgreSQL | `pdo_pgsql` |
| SQLite | `pdo_sqlite` |
| SQL Server | `pdo_sqlsrv` |
| MongoDB | `mongodb` |

## Server requirements

- PHP 8.3 or newer for both PHP-FPM and CLI commands.
- PHP extensions: cURL, OpenSSL, JSON, and ZIP.
- A publicly reachable HTTPS hostname with a valid certificate.
- An empty, dedicated installation directory writable by the PHP-FPM pool user.
- A pre-created empty database when the selected application needs one.
- Outbound HTTPS access from PHP to `api.scriptbox.app`.
- Enough disk space for the compressed archive, staging copy, promoted application, and temporary rollback data.

Do not use a directory containing an existing website. Do not use mode `0777` to solve permission problems.

## How `install.php` works

1. Loads only its compiled API URL and pinned public signing keys.
2. Requests the signed installer bootstrap over HTTPS.
3. Verifies the key ID, RS256 signature, protocol version, issue/expiry times, and UI metadata.
4. Downloads the React JavaScript, CSS, and optional Lottie JSON into private state and verifies every size and SHA-256 hash. Only JavaScript and CSS are injected; animations are served as same-origin data.
5. Reports PHP, extension, database-driver, and target-directory capabilities to the local UI.
6. Stores a one-time ownership proof outside the document root and exposes it through the installer’s same-origin route.
7. Asks the API to verify the public HTTPS origin without following redirects or accepting private/reserved addresses.
8. Shows the anonymous, sanitized catalog immediately. Ownership and consent are requested only after Install is pressed.
9. Issues an anonymous idempotent license for a compatible free package.
10. Downloads the private ZIP with a short-lived authorization and resumable byte ranges.
11. Verifies signed package metadata, archive limits, inventory, permissions, and paths.
12. Extracts into staging, writes configuration safely, confirms the target and database are empty, and runs ordered data operations.
13. Promotes files with a rollback journal, performs the HTTPS health check, activates the license, cleans temporary data, and permanently locks the successful installer.

Paid items show a preview only. Version 1 does not take payment or start checkout.

## cPanel, aaPanel, or File Manager installation

1. Create a new domain or subdomain with HTTPS enabled.
2. Create an empty directory dedicated to the new application.
3. Upload the released `install.php` into that directory.
4. Compare the uploaded file with the published checksum:

   ```bash
   sha256sum install.php
   ```

5. Make the directory writable by the PHP-FPM pool user. On aaPanel the user is commonly `www`:

   ```bash
   install_target=/www/wwwroot/example.com/install
   chown -R www:www "$install_target"
   find "$install_target" -type d -exec chmod 0750 {} \;
   find "$install_target" -type f -exec chmod 0640 {} \;
   ```

6. Open either a root or subdirectory installation URL:

   ```text
   https://example.com/install.php
   https://example.com/install/install.php
   ```

7. Browse the catalog and open script details. The installer detects the public HTTPS origin from the request; there is no editable domain field.
8. Press Install on a compatible free application, review requirements and privacy consent, then provide an empty database when requested. The one-time ownership proof is created and removed automatically.
9. Keep the page open until the completion screen confirms activation and permanent lock. Paid items only open a phase-2 preview and cannot charge you.

Verify the server capability response when the UI reports a permission problem:

```bash
curl --fail --silent https://example.com/install/install.php/api/runtime
```

`capabilities.filesystem.target_writable` must be `true`.

## VPS and CLI usage

Run CLI commands with the same PHP version and extensions as the web pool:

```bash
php -v
php install.php init
php install.php status
php install.php serve --public-url=https://example.com --listen=127.0.0.1:8080
```

The built-in server listens only on loopback. Put it behind an HTTPS reverse proxy; never expose the PHP development server directly to the internet.

| Command | Purpose |
|---|---|
| `php install.php init` | Initialize private installer state |
| `php install.php status` | Show installation state and the last sanitized diagnostic |
| `php install.php serve --public-url=...` | Start the loopback browser endpoint |
| `php install.php recover` | Retry journal-based cleanup after `recovery_required` |

On aaPanel, an explicit binary may be required:

```bash
/www/server/php/83/bin/php install.php status
```

## Browser workflow

The Project 4-style UI displays the catalog and script details immediately. Server inspection, privacy consent, automatic HTTPS ownership verification, database configuration, installation progress, and completion or recovery guidance appear inside the installation flow after Install is pressed. Runtime or API errors remain in a danger alert above the usable catalog.

The UI never stores credentials or bearer tokens in local storage or JavaScript cookies. Sensitive sessions use secure, HttpOnly, SameSite cookies managed by `install.php`.

## Failure, rollback, and recovery

Normal failures trigger automatic cleanup of files and database objects created during the current attempt. If cleanup cannot be proven complete, the installer enters `recovery_required` and blocks another installation.

```bash
php install.php status
php install.php recover
```

Do not delete the journal, private state, or partially installed files manually before recording the diagnostic. Follow the [error catalog](docs/errors.md) and [deployment and recovery checklist](docs/deployment-checklist.md).

If the React UI cannot start, the server-rendered page shows a stable error code, safe message, and diagnostic ID. The same sanitized record is available through the CLI status command and PHP server log.

## Privacy summary

Telemetry is disabled until the user gives explicit consent. The allowed record is limited to the verified domain, API-observed public IP, random installation/license identifiers, coarse runtime versions and extension names, script/version, phase, stable error code, policy version, and consent time.

Database credentials, environment variables, cookies, authorization tokens, file contents, file paths, `phpinfo()`, and raw exceptions are never sent. See [PRIVACY.md](PRIVACY.md).

## Security model

The source code is intentionally readable. Security comes from pinned public keys, RS256 signatures, exact hashes, HTTPS validation, strict local routes, private state, short-lived scoped tokens, archive validation, empty-target enforcement, and rollback—not obfuscation.

Verify release checksums before uploading. Stop when signatures or hashes fail; never edit metadata or disable verification. See [SECURITY.md](SECURITY.md) and the [threat model](docs/threat-model.md).

## Building from source

End users normally download the released single file. Contributors can rebuild it deterministically:

```bash
php tests/run.php
php build/release.php
php -l install.php
sha256sum -c install.php.sha256
```

Changing `config/release.php` does not change an already generated `install.php`; rebuild and deploy the new single file. Only public keys belong in this repository.

## Documentation

- [Architecture and sequence](docs/architecture.md)
- [Deployment and recovery checklist](docs/deployment-checklist.md)
- [Stable error catalog](docs/errors.md)
- [Installer protocol](docs/protocol.md)
- [Package format](docs/package-format.md)
- [Release verification](docs/release.md)
- [Threat model](docs/threat-model.md)
- [MCP development server](docs/mcp.md)
- [Paid installation status](docs/paid-phase2.md)
- [Safe example package](examples/README.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

Internal API deployment, signing-key custody, UI publication, artifact publication, and production rollback procedures belong to the private `scriptbox-api` operator documentation and are intentionally not duplicated here.
