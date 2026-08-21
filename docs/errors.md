# Stable errors

Stable codes identify the failed boundary without exposing raw exceptions. Use the code, safe message, and diagnostic ID together.

| Code | Meaning | User action |
|---|---|---|
| `API_TLS_REQUIRED` | Compiled API URL is not HTTPS | Use an official release; do not edit the generated file |
| `API_UNAVAILABLE` / `API_ERROR` | Remote service, DNS, TLS, proxy, or API response failed | Confirm outbound HTTPS and retry; retain the diagnostic ID |
| `SIGNING_KEYS_NOT_CONFIGURED` | Release has no approved pinned public key | Replace it with an approved release |
| `SIGNING_KEY_UNKNOWN` | API used a key ID not pinned by this release | Update through an approved installer release |
| `SIGNATURE_INVALID` | Signed metadata did not verify | Stop; do not bypass validation |
| `CONFIG_EXPIRED` / `CONFIG_NOT_ACTIVE` | Signed bootstrap time window is invalid | Check server time and request a fresh release/configuration |
| `PROTOCOL_INCOMPATIBLE` | Installer and API contract versions do not overlap | Upgrade `install.php` |
| `ASSET_METADATA_INVALID` | Signed UI metadata is malformed or outside limits | Stop and report the diagnostic |
| `ASSET_DOWNLOAD_FAILED` | UI transfer failed | Check reported HTTP/cURL status, outbound HTTPS, and proxy behavior |
| `ASSET_NOT_FOUND` | Verified cached UI asset is absent | Reload to refresh bootstrap; replace damaged private state only with support guidance |
| `MEDIA_UNAVAILABLE` | The installer could not create its private temporary media buffer | Check temporary-directory permissions and available disk space, then retry |
| `MEDIA_NOT_FOUND` | Local catalog-media token is malformed or unavailable | Reload the catalog; do not reuse or share the token |
| `MEDIA_DOWNLOAD_FAILED` | Catalog-media HTTPS download did not complete | Confirm outbound HTTPS and retry; retain the diagnostic ID |
| `MEDIA_UPSTREAM_STATUS` | Catalog-media service did not return a successful response | Retry later; retain the diagnostic ID without sharing the media URL |
| `MEDIA_TYPE_UNSUPPORTED` | Catalog-media service returned a non-image or unsupported image type | Report the stable code and diagnostic ID; do not download it directly |
| `MEDIA_SIZE_INVALID` | Catalog-media response was empty or outside the 1 byte–8 MiB limit | Retry once; report the stable code if it persists |
| `HASH_MISMATCH` | Downloaded bytes differ from signed size/hash | Stop; never edit hashes or use the file |
| `TARGET_NOT_WRITABLE` | PHP-FPM cannot write the installation directory | Correct owner/group and restrictive permissions; never use `0777` |
| `TARGET_NOT_EMPTY` | Existing files were found | Use a new empty directory |
| `DATABASE_UNSUPPORTED` | Required PHP database extension is absent | Enable the extension before installation |
| `DATABASE_NOT_EMPTY` | Existing database objects were found | Use a new empty database/schema |
| `OWNERSHIP_PROOF_PATH_INVALID` | Installer is mounted at an unsafe URL path | Use a normal root/subdirectory path without encoded traversal |
| `OWNERSHIP_PROOF_NOT_FOUND` | API requested an expired or missing proof | Retry ownership verification once |
| `SESSION_REQUIRED` | Catalog/install action lacks a verified session | Return to consent and verify ownership again |
| `CSRF_FAILED` | Local session/token pair is stale or invalid | Reload the installer over HTTPS and retry |
| `DOWNLOAD_FAILED` | Package range download stopped or made no progress | Check disk/network and retry before authorization expires |
| `PACKAGE_*` / `MANIFEST_*` | Package structure, limits, or manifest is unsafe | Choose another version and report the package |
| `CONFIG_*` | Package configuration output is unsafe or cannot be written | Confirm target permission; report package metadata problems |
| `HEALTH_CHECK_FAILED` | Installed application did not pass HTTPS health check | Allow rollback; verify application/domain configuration |
| `INSTALL_LOCKED` | Another installation holds the exclusive lock | Wait for it to finish; do not remove the lock manually |
| `RECOVERY_REQUIRED` | Automatic rollback could not prove cleanup | Stop and follow audited recovery guidance |

## Finding diagnostics

If React cannot start, the server-rendered fallback shows the code, safe message, and diagnostic ID. The same sanitized record is stored outside the document root:

```bash
php install.php status
```

Use the PHP 8.3 binary serving the site. PHP’s server log receives the same diagnostic ID and safe message, never credentials, tokens, raw exceptions, or customer file contents.

## What to share with support

Share the installer checksum, public URL, PHP version, stable code, diagnostic ID, approximate time, and whether the target/database were empty. Do not share passwords, `.env` files, cookies, tokens, private URLs, database dumps, or application source.
