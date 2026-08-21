# Installer privacy

The ScriptBox installer is designed to install software without sending hosting credentials or application contents to ScriptBox. Telemetry is opt-in and cannot be submitted before explicit consent.

## Data permitted after consent

Policy `2026-08-19` permits only:

- Verified HTTPS origin and the public egress IP observed by the API.
- Random installation, session, and license identifiers.
- Coarse operating-system family, web-server type, PHP version, and PHP extension names.
- Selected script and version.
- Installation phase and stable error code.
- Consent time and policy version.

## Data never collected

- Database host, port, name, username, or password.
- Environment variables, `.env` values, cookies, session contents, or application secrets.
- Authorization, session, license-download, or artifact tokens.
- Customer file names, paths, contents, source code, database rows, or schema contents.
- `phpinfo()` output, raw stack traces, or raw exceptions.
- Payment credentials; paid checkout is not implemented in version 1.

## Local data

`install.php` keeps sessions, cached signed UI assets, download progress, the rollback journal, and transient ownership proofs in a private state directory outside the document root. Files use restrictive permissions. Database passwords are used in memory for the requested installation and are excluded from persisted state and diagnostics.

Catalog preview images load directly from administrator-controlled public HTTPS image URLs with no referrer. The image host can still observe the visitor's public IP and normal transport metadata. Images are presentation-only and do not receive installer cookies, authorization headers, database values, or the verified origin as a referrer.

## Retention

Detailed consented events expire after 30 days. Minimal license identity is retained only while needed to operate installation and reinstallation controls, then revoked or anonymized according to the service policy. Temporary ownership proofs and download authorizations expire within minutes and are single-purpose.

## User choices

Declining telemetry consent prevents the ownership-verified online installation flow. Users can close and remove the installer without sending installation telemetry. Consent applies to the displayed policy version; a materially changed policy requires renewed consent.

## Support diagnostics

Browser and CLI diagnostics contain a stable error code, safe message, time, and random diagnostic ID. They intentionally omit credentials and raw exceptions. Review diagnostic output before sharing it and report any suspected privacy issue through the private security-reporting channel described in [SECURITY.md](SECURITY.md).

Never collected: database host/name/user/password, environment variables, cookies, file contents/paths, `phpinfo()`, authorization/download tokens, or raw exceptions. Detailed events expire after 30 days. Minimal license identity is kept only while operational and is then revoked or anonymized.
