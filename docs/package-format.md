# Package format

This document is for public package authors. Every ZIP contains `scriptbox.json` at the archive root and root-ready application files below `payload/`. The installer treats the archive as untrusted even after publication.

## Schema v2 manifest

```json
{
  "schema_version": 2,
  "script_id": "SCR-001",
  "version": "1.0.0",
  "framework": "laravel",
  "runtime": {
    "type": "php",
    "php": ">=8.3",
    "extensions": ["pdo_mysql"]
  },
  "database": {
    "driver": "mysql",
    "migrations": ["migrations/001.json"]
  },
  "inputs": [
    {"key":"admin_email","type":"email","label":"Administrator email","required":true,"secret":false},
    {"key":"admin_password","type":"password","label":"Administrator password","required":true,"secret":true,"minimum_length":12}
  ],
  "payload": {
    "root": "payload",
    "writable": [{"path":"storage","mode":"0770"}]
  },
  "configuration": [
    {
      "path": ".env",
      "format": "dotenv",
      "values": {
        "APP_URL": "{{app.url}}",
        "APP_KEY": "{{generated.app_key}}",
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

- `schema_version` is `2` for new packages. Existing schema-v1 packages remain supported.
- `framework` is `static`, `laravel`, `codeigniter3`, `codeigniter4`, `cakephp`, or `raw_php`. It selects safe presentation/configuration behavior and never an executable hook.
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

Migration files contain ordered, driver-matching JSON operations. Parameterized SQL values are bound through prepared statements and may reference declared inputs. Password values may use only `bcrypt` or `argon2id`. A package must not assume it can install an extension or start a service.

## Structured setup inputs

Supported types are `text`, `email`, `url`, `password`, `boolean`, and `select`. Keys match `^[a-z][a-z0-9_]{0,63}$`. Secret values appear only in the current browser request and local installer memory; they are never persisted in the run state, journal, diagnostic, or telemetry.

## Configuration outputs

Supported formats are `dotenv`, `json`, `php-array`, and `token-template`. Output paths must be safe relative paths inside the target. Values are escaped by the installer. Token templates require an explicit encoder: `dotenv`, `json-string`, `php-string`, `ini-string`, or `url-component`.

Allowed sources are `app.url`, `target.url`, `generated.app_key`, the declared `database.*` fields, and `input.<declared-key>`. Raw unescaped replacement is forbidden.

Framework guidance:

- Laravel and CodeIgniter 4: generated `.env`.
- CodeIgniter 3: exact token template for `application/config/database.php`, or a packaged environment adapter.
- CakePHP: PHP-array output or exact token template for `config/app_local.php`.
- Raw PHP: dotenv, JSON, PHP array, or exact signed template.
- Static: no database/configuration unless explicitly declared.

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
