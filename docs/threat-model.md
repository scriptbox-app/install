# Threat model

## Assets

- Customer web root, configuration, database, credentials, and application availability.
- Integrity of `install.php`, the React UI, package manifests, archives, and migrations.
- API signing keys, short-lived session/download tokens, license state, private artifact storage, and telemetry.
- Developer workspaces and publication authorization exposed through MCP.

## Trust boundaries

- Browser ↔ same-origin PHP installer.
- PHP installer ↔ public ScriptBox API.
- API ↔ customer origin during ownership proof and health check.
- Publisher ↔ private storage and production metadata database.
- Installer ↔ local filesystem, ZIP parser, supported database, and installed application.
- AI client ↔ local stdio MCP server.

## Representative threats and controls

| Threat | Primary controls |
|---|---|
| Modified API bootstrap or UI | Pinned key IDs, RS256 verification, issue/expiry checks, exact size/SHA-256 |
| Compromised storage bytes | Signed immutable metadata and verification before use |
| SSRF or DNS rebinding | HTTPS-only public origins, address classification, DNS pinning, no redirects, valid TLS |
| Cross-site request forgery/session theft | Secure HttpOnly SameSite cookie, CSRF header, session rotation, CSP/frame denial |
| ZIP traversal, links, devices, or bombs | Canonical relative paths, entry-type rejection, file/count/size/ratio limits |
| Existing-site overwrite | Dedicated empty target/database enforcement, staging, journal, exclusive lock |
| Partial install or failed migration | Empty snapshot, created-object tracking, rollback, `recovery_required` lockout |
| Secret leakage | Redacted state/events, allowlisted telemetry, safe messages, no raw exceptions/phpinfo |
| Package command execution | No shell, Composer, npm, hooks, or package-selected URLs |
| MCP path/command abuse | Realpath containment, fixed shell-free argv, bounded resources, two-step publication |
| Paid entitlement bypass | Paid install disabled in version 1 |

## Assumptions

- The hosting administrator and PHP-FPM account can modify the target and therefore remain trusted for that server.
- ScriptBox reviews and signs packages but cannot make malicious application logic safe solely through archive validation.
- The operating system, PHP runtime, TLS trust store, database server, and extensions are maintained by the hosting provider.
- A public key embedded in open source authenticates signatures but does not conceal data.

## Residual risk

Residual risks include malicious-but-valid application behavior, a compromised production signing key, vulnerable PHP/extensions, hosting-administrator abuse, database engine defects, denial of service against the public API, and user disclosure of credentials. Least privilege, package review, key rotation, monitoring, backups, and incident response remain necessary.

## Security invariants

- Signature/hash failure never falls back to unsigned content.
- User/application secrets never cross into telemetry, public diagnostics, or MCP resources.
- Package content never writes outside the dedicated target.
- A second install never starts while a lock, recovery requirement, or success lock is active.
- Remote URLs and executable behavior are controlled by the installer/API release, not the package.
