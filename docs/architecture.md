# Architecture and sequence

ScriptBox separates the user interface, local privileged work, remote trust service, and optional development control plane. The browser never contacts private artifact storage directly and never receives database credentials back from PHP.

```text
Optional development plane
AI client ─stdio─> local MCP ─fixed validation/build tools─> three repositories

Production plane
Publisher ─> private disk or S3 ─┐
                                ├─> ScriptBox installer-v1 API
Metadata/licenses/events ─> DB ─┘             │ signed HTTPS
                                               ▼
Browser React UI ─same origin─> install.php ─> staged local application
```

## Component responsibilities

### React UI

Displays capabilities, consent, catalog, compatibility, database inputs, progress, errors, recovery, and completion. It calls fixed same-origin routes under the deployed `install.php`; it does not call the remote API directly and does not persist credentials or bearer tokens.

### `install.php`

Pins public signing keys, verifies the signed UI and package metadata, owns the secure session and CSRF controls, inspects local capabilities, manages one-time ownership proof state, downloads and validates packages, operates supported databases, writes configuration, promotes staged files, checks health, and performs rollback.

### ScriptBox API

Signs immutable bootstrap metadata, verifies public HTTPS ownership, returns sanitized catalog data, issues anonymous free licenses, authorizes short-lived private downloads, activates successful installations, and accepts consented redacted events.

### Private storage

Contains immutable UI assets and validated application packages. Storage locations are never present in public catalog responses. Local disk and S3-compatible backends share the same signed metadata contract.

### MCP server

Provides optional local developer resources and bounded validation/build/publish tools over stdio. It is not used by customer installations and is not a production transport.

## Browser startup sequence

```text
GET install.php
  → fetch signed bootstrap
  → verify signature and protocol
  → download CSS/JS into private state
  → verify size and SHA-256
  → serve verified assets from same-origin immutable routes
  → UI requests local runtime capabilities
  → UI renders the anonymous catalog and query-string detail route immediately
```

## Ownership sequence

```text
UI submits consent after the user presses Install
  → install.php derives the HTTPS origin from CLI configuration, a trusted proxy, or the validated request
  → install.php checks target writability
  → creates random proof in private state
  → sends proof ID, digest, and same-origin installer path to API
  → API validates public DNS/TLS and pins the resolved public address
  → API requests the exact proof path without redirects
  → install.php returns the proof from private state
  → API compares the digest and issues a scoped 15-minute session
  → install.php deletes the proof
```

Both `/install.php` and `/install/install.php` deployments use this flow. The browser cannot supply or edit the origin.

## Installation sequence

Preflight and lock → free license → artifact authorization → resumable download → hash/signature/archive verification → staging and configuration → empty database verification → ordered operations → journaled file promotion → HTTPS health check → license activation → cleanup and permanent lock.

Failure unwinds files and database objects created after the empty snapshot. If cleanup cannot be proven complete, the state becomes `recovery_required` and no new installation may start.

## Trust boundaries

- Browser ↔ PHP: secure session cookie, CSRF token, strict CSP, fixed routes, bounded JSON.
- PHP ↔ API: TLS verification, fixed host/routes, signed envelopes, scoped short-lived tokens.
- API ↔ public origin: public-address validation, DNS pinning, valid TLS, no redirects.
- Installer ↔ ZIP/database/filesystem: explicit limits, empty-only targets, staging, journal, rollback.
- AI client ↔ MCP: stdio-only protocol, root containment, fixed commands, confirmation-gated publishing.
