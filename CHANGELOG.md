# Changelog

All notable public installer changes are recorded here. Dates use UTC and versions follow the generated installer release metadata.

## Unreleased

- Added private-state ownership proofs that support both `/install.php` and subdirectory `/install/install.php` deployments.
- Added `TARGET_NOT_WRITABLE`, safe browser diagnostics, CLI last-error output, and actionable asset-download transport details.
- Added API storage-size validation so broken UI releases are rejected before incomplete files are streamed.
- Fixed catalog-media validation to measure buffered bytes rather than stream position, with safe `MEDIA_*` diagnostics for token, transport, status, type, and size failures.
- Added runtime installer version, immutable release timestamp, and the running artifact SHA-256 fingerprint for post-upload verification.
- Added UI capability gating for unsupported PHP, missing extensions, and non-writable targets.
- Expanded all public user, security, privacy, package, recovery, protocol, contributor, and release documentation.

## 1.0.0-dev — 2026-08-19

- Added deterministic dependency-free signed PHP installer, secure browser/CLI flows, resumable validation, database adapters, rollback/recovery, signed React UI integration, and permanent success lock.
- Added constrained three-project MCP v2 stdio server with confirmation-gated publishing.
- Added anonymous free-license installation and paid-package preview without payment processing.

## Compatibility policy

- Patch releases may improve validation, diagnostics, and documentation without changing the installer-v1 contract.
- Protocol changes require coordinated installer, UI, API, OpenAPI, package-schema, and MCP updates.
- Published UI and package versions are immutable; corrections use a new version rather than overwriting old bytes.
