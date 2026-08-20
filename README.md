# ScriptBox Signed Installer

ScriptBox installs validated static or PHP applications into an empty web root. Production uses `React UI → install.php → ScriptBox API`; the local MCP server is an optional development/publishing control plane.

## Requirements

- PHP 8.3+ with cURL, OpenSSL, JSON, and ZIP.
- A publicly reachable HTTPS origin.
- An empty target and, if requested, pre-created empty database.
- A release whose [pinned public keys](config/release.php) match the API signing keys.

The installer never installs OS packages/extensions and never runs shell, Composer, npm, or package hooks.

## Quick starts

For cPanel, upload the released `install.php` to an empty HTTPS document root, verify its published SHA-256, then open `/install.php`. For source builds:

```bash
php tests/run.php
php build/compile.php
php -l install.php
```

Copy only the generated `install.php` to the empty target. For a VPS behind an HTTPS reverse proxy:

```bash
php install.php init
php install.php serve --public-url=https://app.example --listen=127.0.0.1:8080
php install.php status
```

If the signed UI cannot load, the fallback page displays a stable error code and diagnostic ID.
Run `php install.php status` on the server to see the last sanitized diagnostic, then use the
[error catalog](docs/errors.md). Do not bypass signature or asset-hash failures.

Changing `config/release.php` does not change an already compiled `install.php`. After pinning the API public key, always run `php build/compile.php` and deploy the newly generated single file. The matching private key remains only in the `scriptbox-api` production environment. The complete Docker release sequence is documented in `scriptbox-api/docs/installer-production-release.md` when the three repositories are checked out as siblings.

For recovery run `php install.php recover`. Normal failures roll back; uncertain cleanup becomes `recovery_required` and blocks another install.

See [architecture](docs/architecture.md), [package format](docs/package-format.md), [MCP setup](docs/mcp.md), [release guide](docs/release.md), [SECURITY.md](SECURITY.md), and [PRIVACY.md](PRIVACY.md).
