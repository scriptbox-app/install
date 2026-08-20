# Package format

This document is for public package authors. Every ZIP contains `scriptbox.json` at the archive root and root-ready application files below `payload/`. The installer treats the archive as untrusted even after publication.

## Minimal manifest

```json
{
  "schema_version": 1,
  "script_id": "SCR-001",
  "version": "1.0.0",
  "runtime": {
    "type": "php",
    "php": ">=8.3",
    "extensions": ["pdo_mysql"]
  },
  "database": {
    "driver": "mysql",
    "migrations": ["migrations/001.json"]
  },
  "payload": {
    "root": "payload",
    "writable": ["storage"]
  },
  "configuration": [
    {
      "path": ".env",
      "format": "dotenv",
      "values": {
        "APP_URL": "{{app.url}}",
        "APP_KEY": "{{app.key}}",
        "DB_PASSWORD": "{{database.password}}"
      }
    }
  ],
  "health_check": {
    "path": "/health"
  }
}
```

## Required concepts

- `schema_version` is `1`.
- `script_id` and `version` must match the catalog version being published.
- `runtime.type` is `static` or `php`.
- `database.driver` is `none`, `mysql`, `mariadb`, `pgsql`, `sqlite`, `sqlsrv`, or `mongodb`.
- `payload.root` is exactly `payload`; its children are promoted to the target root.
- `health_check.path` is a same-origin path used after promotion.
- Configuration outputs are explicit and may use only the supported runtime placeholders.

## Archive layout

```text
scriptbox.json
migrations/
  001.json
payload/
  index.php
  public/
  storage/
```

Migration files contain ordered, driver-matching JSON operations. They are data descriptions, not executable SQL or shell scripts. A package must not assume it can install an extension or start a service.

## Configuration outputs

Supported formats are dotenv, JSON, and PHP array. Output paths must be relative and remain inside the target. Values are escaped by the installer. Package authors declare placeholders but never supply customer credentials or package-selected remote URLs.

## Limits

| Limit | Maximum |
|---|---:|
| Compressed archive | 512 MiB |
| Unpacked content | 2 GiB |
| File count | 20,000 |
| Individual file | 256 MiB |
| Expansion ratio | 100:1 |
| Download chunk | 8 MiB |

The manifest inventory must agree with actual package files, sizes, permissions, and SHA-256 metadata.

## Forbidden content

- Shell, Composer, npm, or arbitrary executable hooks.
- Symlinks, hard links, device files, sockets, or unsafe special entries.
- Absolute paths, drive paths, backslashes, empty segments, `.` or `..` traversal.
- Writes outside the target or package-selected external download URLs.
- Bundled customer secrets, credentials, private keys, or environment values.
- Runtime types that require a background Node.js/Next.js service in version 1.

Validate the safe example in [`examples/package`](../examples/README.md) before submitting a real package.
