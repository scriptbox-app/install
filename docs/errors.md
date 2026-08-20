# Stable errors

| Code | Action |
|---|---|
| `SIGNING_KEYS_NOT_CONFIGURED` | Build an approved keyed release |
| `SIGNATURE_INVALID` | Stop and audit publishing/key rotation |
| `HASH_MISMATCH` | Republish the UI/package with a new immutable version; never edit signed hashes manually |
| `ASSET_DOWNLOAD_FAILED` | Check the reported HTTP/cURL status, then verify the published asset size and reverse-proxy streaming |
| `PREFLIGHT_FAILED` | Correct PHP/extension/filesystem capability |
| `TARGET_NOT_EMPTY` / `DATABASE_NOT_EMPTY` | Use an empty target/database |
| `PACKAGE_*` / `MANIFEST_*` | Fix and republish the package |
| `DOWNLOAD_FAILED` | Retry before authorization expires |
| `HEALTH_CHECK_FAILED` | Correct app configuration; rollback runs |
| `RECOVERY_REQUIRED` | Complete manual audited recovery |

Clients branch on codes, not message text. Production 5xx responses suppress exceptions.

If the React UI cannot start, the server-rendered fallback page shows the stable error code,
a safe message, and a diagnostic ID. The same sanitized record is stored outside the document
root and is available with `php install.php status`. PHP's server error log receives the same
diagnostic ID and safe message; credentials, tokens, raw exceptions, and file contents are not
recorded.
