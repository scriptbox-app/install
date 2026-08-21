# ScriptBox Signed Installer

ScriptBox provides a dependency-free PHP installer for deploying approved static and PHP applications from the ScriptBox catalog. A user uploads the four-file release bundle (or standalone `install.php`), opens it over HTTPS, completes the resumable React wizard, and lets the installer perform validated download, configuration, database migration, health checking, and rollback.

```text
Browser → install.php → signed ScriptBox API → private application package
            ├─ verifies the signed UI and package
            ├─ checks PHP, filesystem, and database support
            ├─ stages changes before promotion
            └─ rolls back when an installation fails
```

This repository is public. It contains no production private keys, API credentials, customer secrets, or hidden encryption keys.

## Why use it

- A minimal `index.php` launcher gives `/install/` a clean URL; standalone `install.php` remains supported.
- The browser interface does not need Node.js on the customer server.
- Signed bootstrap metadata pins the approved React assets and their exact SHA-256 hashes and sizes.
- Application archives are private, short-lived, and verified before extraction.
- ZIP traversal, links, device files, expansion bombs, arbitrary hooks, Composer, npm, and shell commands are rejected.
- Installations use staging, an exclusive lock, an append-only journal, health checks, and rollback.
- Database passwords and application secrets remain on the customer server and are excluded from telemetry and diagnostics.
- Stable error codes and diagnostic IDs make support possible without exposing raw exceptions.

## Supported applications

Version 1 installs complete `static` and `php` packages using the `static`, `laravel`, `codeigniter3`, `codeigniter4`, `cakephp`, or `raw_php` profile. Node.js and Next.js applications may appear in the catalog but cannot be automatically installed. Packages cannot install operating-system packages, PHP extensions, Composer dependencies, npm dependencies, services, cron jobs, or arbitrary commands.

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
- A writable document root. The selected destination must be empty; only the verified `/install` control bundle is ignored for a root installation.
- A pre-created empty database when the selected application needs one.
- Outbound HTTPS access from PHP to `api.scriptbox.app`.
- Enough disk space for the compressed archive, staging copy, promoted application, and temporary rollback data.

The installer keeps private state outside the public document root. When PHP `open_basedir` permits the hosting-account parent, that sibling location is used. On cPanel/aaPanel policies that permit only the domain document root and `/tmp`, the installer automatically uses a private mode-`0700` directory under `/tmp`; it never tries to write into the parent account root. Administrators may set `SCRIPTBOX_STATE_DIR` only to an allowed, writable path outside the document root.

Do not use a directory containing an existing website. Do not use mode `0777` to solve permission problems.

## How `install.php` works

1. Loads only its compiled API URL and pinned public signing keys.
2. Requests the signed installer bootstrap over HTTPS.
3. Verifies the key ID, RS256 signature, protocol version, issue/expiry times, and UI metadata.
4. Downloads the React JavaScript, CSS, and ScriptBox PNG logo into private state and verifies every size and SHA-256 hash. New UI releases contain no Lottie runtime or animation JSON.
5. Reports PHP, extension, database-driver, and target-directory capabilities to the local UI.
6. Stores a one-time ownership proof outside the document root and exposes it through the installer’s same-origin route.
7. Asks the API to verify the public HTTPS origin without following redirects or accepting private/reserved addresses.
8. Shows the anonymous, sanitized catalog immediately. Ownership and consent are requested only after Install is pressed.
9. Issues an anonymous idempotent license for a compatible free package.
10. Creates a private run ID and downloads the private ZIP with a short-lived authorization and resumable byte ranges. Safe progress can be read again after a browser refresh; credentials are requested again when a resumed phase needs them.
11. Verifies signed package metadata, archive limits, inventory, permissions, and paths.
12. Extracts into staging, writes configuration safely, confirms the target and database are empty, and runs ordered data operations.
13. Promotes files with a rollback journal, performs the HTTPS health check, activates the license, cleans temporary data, and permanently locks the successful installer.

Paid items show a preview only. Version 1 does not take payment or start checkout.

## cPanel, aaPanel, or File Manager installation

1. Create a new domain or subdomain with HTTPS enabled.
2. Create an empty `install/` control directory in the document root.
3. Upload the complete minimal release bundle:

   ```text
   install/
   ├── index.php
   ├── install.php
   ├── install.php.sha256
   └── release.json
   ```

   A legacy standalone deployment may upload only `install.php` and open it directly.
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

6. Open either the clean launcher or standalone URL:

   ```text
   https://example.com/install/
   https://example.com/install/install.php
   ```

7. Browse the catalog and open script details. The installer detects the public HTTPS origin from the request; there is no editable domain field.
8. Press Install on a compatible free application. Choose a signed version, refresh the server checks, select `/` or a safe relative destination such as `shop`, review privacy consent, enter only package-declared setup fields, and test an empty database when requested. The one-time ownership proof is created and removed automatically.
9. Keep the page open until the completion screen confirms activation and permanent lock. Paid items only open a phase-2 preview and cannot charge you.

Verify the server capability response when the UI reports a permission problem:

```bash
curl --fail --silent https://example.com/install/install.php/api/runtime
```

`capabilities.filesystem.target_writable` must be `true`.

The same response includes `build.installer_version`, the immutable `build.release_timestamp`, and `build.artifact_sha256`. Compare `build.artifact_sha256` with the SHA-256 fingerprint of the exact `install.php` uploaded to the server. A mismatch means the deployed artifact is not the reviewed release; stop and replace it rather than editing the file in place.

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
| `php install.php recover` | Retry hash-bound file cleanup; database recovery continues in the browser with the original connection |

On aaPanel, an explicit binary may be required:

```bash
/www/server/php/83/bin/php install.php status
```

## Browser workflow

The Project 4-style UI first displays a page-shaped CSS skeleton, then the catalog and script details. Catalog images use API-validated public HTTPS URLs with no referrer; offscreen images load lazily and failures retain a fixed-size fallback. Server inspection, target selection, privacy consent, automatic HTTPS ownership verification, structured application setup, database testing, a redacted configuration preview, real progress, and completion/recovery guidance appear only after Install is pressed. Runtime or API errors remain in a danger alert above the usable catalog.

The target field never reveals an absolute server path. `/` means the validated document root. Relative paths use no more than five safe segments, cannot be hidden/reserved or point at the installer control directory, and cannot escape through a symlink. Existing targets must be empty; a missing target is created only below a writable validated parent.

The UI never stores credentials or bearer tokens in local storage or JavaScript cookies. Sensitive sessions use secure, HttpOnly, SameSite cookies managed by `install.php`.

## Failure, rollback, and recovery

Normal failures trigger automatic cleanup of files and database objects created during the current attempt. If cleanup cannot be proven complete, the installer enters `recovery_required` and blocks another installation.

```bash
php install.php status
php install.php recover
```

Do not delete the journal, private state, or partially installed files manually before recording the diagnostic. If migration was interrupted, reopen the wizard and enter the original database connection. A random pre-migration marker binds destructive reset to that exact database; a different same-driver database is rejected. Credentials remain request-only. Follow the [error catalog](docs/errors.md) and [deployment and recovery checklist](docs/deployment-checklist.md).

If the React UI cannot start, the server-rendered page shows a stable error code, safe message, and diagnostic ID. The same sanitized record is available through the CLI status command and PHP server log.

Current catalog preview images load directly from API-validated public HTTPS URLs using `no-referrer`. The legacy `install.php/api/media?token=...` route remains temporarily for release rollback but is not used by the current UI. Never place private artifact or storage URLs in catalog image fields.

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
php build/compile.php
php build/release.php
php -l install.php
php -l index.php
sha256sum -c install.php.sha256
```

Changing `config/release.php` does not change an already generated `install.php`; rebuild and deploy the new single file. Only public keys belong in this repository.

## Documentation

- [Architecture and sequence](docs/architecture.md)
- [Deployment and recovery checklist](docs/deployment-checklist.md)
- [Stable error catalog](docs/errors.md)
- [Installer protocol](docs/protocol.md)
- [Package format](docs/package-format.md)
- [Wizard, target, resume, and cleanup](docs/wizard.md)
- [Release verification](docs/release.md)
- [Threat model](docs/threat-model.md)
- [MCP development server](docs/mcp.md)
- [Paid installation status](docs/paid-phase2.md)
- [Safe example package](examples/README.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

Internal API deployment, signing-key custody, UI publication, artifact publication, and production rollback procedures belong to the private `scriptbox-api` operator documentation and are intentionally not duplicated here.
