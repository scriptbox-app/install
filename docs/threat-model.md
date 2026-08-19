# Threat model

Assets include customer web roots/database credentials, package integrity, signing keys, artifact storage, licenses, and telemetry. Boundaries are browser↔PHP, PHP↔API, publisher↔storage/database, and AI client↔MCP.

Controls: pinned signatures/hashes resist API/storage tampering; public HTTPS DNS/IP pinning and no redirects resist SSRF/rebinding; archive inspection resists traversal/bombs; empty-only staging, lock, journal and rollback constrain destruction; HttpOnly Strict sessions, CSRF and CSP protect the browser; realpath containment, fixed `shell:false` argv, allowlisted environment and digest-bound tokens constrain MCP. Residual risk includes malicious-but-valid app logic and hosting administrators; package review and least privilege remain mandatory.
