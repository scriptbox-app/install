# Stable errors

| Code | Action |
|---|---|
| `SIGNING_KEYS_NOT_CONFIGURED` | Build an approved keyed release |
| `SIGNATURE_INVALID` / `HASH_MISMATCH` | Stop and audit publishing/key rotation |
| `PREFLIGHT_FAILED` | Correct PHP/extension/filesystem capability |
| `TARGET_NOT_EMPTY` / `DATABASE_NOT_EMPTY` | Use an empty target/database |
| `PACKAGE_*` / `MANIFEST_*` | Fix and republish the package |
| `DOWNLOAD_FAILED` | Retry before authorization expires |
| `HEALTH_CHECK_FAILED` | Correct app configuration; rollback runs |
| `RECOVERY_REQUIRED` | Complete manual audited recovery |

Clients branch on codes, not message text. Production 5xx responses suppress exceptions.
