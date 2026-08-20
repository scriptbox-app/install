# Installer v1 protocol

This public summary explains the contract relied on by `install.php`. It contains no API credentials or production signing material.

## Response envelope

Every JSON operation returns:

```json
{
  "success": true,
  "data": {},
  "error": null,
  "request_id": "uuid"
}
```

Errors use the same shape with `success: false`, `data: null`, and a stable `error.code` plus safe message.

## Signed bootstrap

`GET https://api.scriptbox.app/installer/v1/bootstrap?installer_version=1.0.0` returns data shaped as:

```json
{
  "kid": "installer-root-2026-01",
  "alg": "RS256",
  "payload": "base64url-json",
  "signature": "base64url-signature"
}
```

The signature covers the decoded JSON payload bytes, not the base64url text. The payload contains protocol compatibility, issue/expiry times, immutable UI asset URLs/paths/hashes/sizes, feature flags, operational limits, and telemetry policy. It contains no secret.

Unknown keys, unsupported algorithms, invalid signatures, expired/future configuration, incompatible protocols, and asset hash/size mismatches fail closed.

## Session and ownership

The browser sends consent and the origin to local `install.php`. PHP creates a random proof in private state and sends its ID, digest, and strictly validated same-origin `proof_path` to the API. This supports both `/install.php` and subdirectory `/install/install.php` without placing proof files inside the application target.

The API validates a public HTTPS hostname, rejects redirects and private/reserved addresses, pins DNS for the proof request, checks TLS, fetches the exact proof path, and compares its digest. Session tokens expire after 15 minutes and are bound to installation, origin, and action scopes.

## Catalog, license, and artifact flow

```text
POST /sessions/verify
POST /catalog/search
GET  /catalog/{scriptId}
POST /licenses/free
POST /artifacts/{artifactId}/authorize
GET  /downloads/{token}
POST /licenses/{licenseId}/activate
POST /events
```

Catalog data contains public compatibility information but never storage keys or download URLs. Free licenses are anonymous and idempotent for the verified origin, installation ID, script, and version. Artifact authorizations are short-lived and scoped; downloads support bounded ranges. Activation occurs only after a successful same-origin health check.

## Compatibility and evolution

Published installer releases declare their protocol version. Additive optional fields may be introduced within installer-v1. Required-field, signing, path, token-scope, or semantic changes require a coordinated compatibility window across the API, PHP installer, UI, OpenAPI, tests, and MCP contract resources.

Clients branch on stable codes, not message text. Raw exceptions and secrets are never part of a public response.
