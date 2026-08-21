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
    "migrations": ["migrations/001.jsonl"]
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
  001.jsonl
payload/
  index.php
  public/
  storage/
```

Migration files contain ordered, driver-matching JSON operations. Parameterized SQL values are bound through prepared statements and may reference declared inputs. Password values may use only `bcrypt` or `argon2id`. A package must not assume it can install an extension or start a service.

JSON remains supported for small migrations. JSONL is one UTF-8 operation object per line and is streamed from the ZIP. Each line is at most 1 MiB, builder chunks are at most 4 MiB, and each relational operation has at most 1,000 parameters. Files run in manifest order. Raw SQL files are never accepted or executed.

## Structured setup inputs

Supported types are `text`, `email`, `url`, `password`, `boolean`, and `select`. Keys match `^[a-z][a-z0-9_]{0,63}$`. Secret values appear only in the current browser request and local installer memory; they are never persisted in the run state, journal, diagnostic, or telemetry.

## Configuration outputs

Supported formats are `dotenv`, `json`, `php-array`, and `token-template`. Output paths must be safe relative paths inside the target. Values are escaped by the installer. Token templates require an explicit encoder: `dotenv`, `json-string`, `php-string`, `ini-string`, or `url-component`.

Allowed sources are `app.url`, `target.url`, `generated.app_key`, the declared `database.*` fields, and `input.<declared-key>`. Raw unescaped replacement is forbidden.

Framework guidance:

- Laravel and CodeIgniter 4: generated `.env`.
- CodeIgniter 3: exact token template for `application/config/database.php`, or a packaged environment adapter.
- CakePHP: exact token template for the nested `Datasources.default` configuration in `config/app_local.php`.
- Raw PHP: dotenv, JSON, PHP array, or exact signed template.
- Static: no database/configuration unless explicitly declared.

The automatic builder's built-in CodeIgniter 3, CodeIgniter 4, and CakePHP profiles are MySQL/MariaDB-specific. For PostgreSQL, SQLite, SQL Server, or MongoDB, an operator must supply a reviewed explicit profile with matching non-empty configuration and application extensions. The builder adds only the selected installer database extension; it must not carry `mysqli` or `pdo_mysql` into that explicit non-MySQL profile unless the application independently requires them.

## Complete framework examples

Every payload is a complete production release. The examples below show every required top-level manifest field. Replace IDs, versions, extensions, inputs, configuration, and health paths only with reviewed application facts.

### Static

```json
{
  "schema_version": 2,
  "script_id": "SCR-STATIC",
  "version": "1.0.0",
  "framework": "static",
  "runtime": {"type": "static"},
  "database": {"driver": "none", "migrations": []},
  "inputs": [],
  "payload": {"root": "payload", "writable": []},
  "configuration": [],
  "health_check": {"path": "/"}
}
```

Ship `payload/index.html` and already-built assets.

### Laravel

```json
{
  "schema_version": 2,
  "script_id": "SCR-LARAVEL",
  "version": "1.0.0",
  "framework": "laravel",
  "runtime": {"type": "php", "php": ">=8.2", "extensions": ["curl", "openssl", "pdo_mysql"]},
  "database": {"driver": "mysql", "migrations": ["migrations/001.jsonl"]},
  "inputs": [
    {"key": "site_name", "type": "text", "label": "Site name", "required": true, "secret": false},
    {"key": "admin_email", "type": "email", "label": "Administrator email", "required": true, "secret": false},
    {"key": "admin_password", "type": "password", "label": "Administrator password", "required": true, "secret": true, "minimum_length": 12}
  ],
  "payload": {"root": "payload", "writable": [{"path": "storage", "mode": "0770"}, {"path": "bootstrap/cache", "mode": "0770"}]},
  "configuration": [{"path": ".env", "format": "dotenv", "values": {
    "APP_ENV": "production", "APP_DEBUG": "false", "APP_NAME": "{{input.site_name}}",
    "APP_URL": "{{app.url}}", "APP_KEY": "{{generated.app_key}}",
    "DB_CONNECTION": "{{database.driver}}", "DB_HOST": "{{database.host}}", "DB_PORT": "{{database.port}}",
    "DB_DATABASE": "{{database.name}}", "DB_USERNAME": "{{database.user}}", "DB_PASSWORD": "{{database.password}}"
  }}],
  "health_check": {"path": "/"}
}
```

Ship `artisan`, `composer.json`, `vendor/autoload.php`, `public/index.php`, complete production dependencies, and compiled assets. `{{generated.app_key}}` is generated as Laravel's `base64:` prefix followed by a value that decodes to exactly 32 random bytes. Configure hosting so the public entrypoint is exposed safely; the installer does not edit the web server.

### CodeIgniter 3

```json
{
  "schema_version": 2,
  "script_id": "SCR-CI3",
  "version": "1.0.0",
  "framework": "codeigniter3",
  "runtime": {"type": "php", "php": ">=8.1", "extensions": ["mysqli", "pdo_mysql"]},
  "database": {"driver": "mysql", "migrations": ["migrations/001.jsonl"]},
  "inputs": [],
  "payload": {"root": "payload", "writable": [{"path": "application/cache", "mode": "0770"}, {"path": "application/logs", "mode": "0770"}]},
  "configuration": [{"path": "application/config/database.php", "format": "token-template", "template": "<?php\ndefined('BASEPATH') OR exit('No direct script access allowed');\n$active_group = 'default';\n$query_builder = true;\n$db['default'] = [\n 'hostname' => '{{database.host|php-string}}',\n 'port' => '{{database.port|php-string}}',\n 'username' => '{{database.user|php-string}}',\n 'password' => '{{database.password|php-string}}',\n 'database' => '{{database.name|php-string}}',\n 'dbdriver' => 'mysqli',\n 'db_debug' => false,\n];\n"}],
  "health_check": {"path": "/"}
}
```

Ship `application/`, `system/`, and `index.php`.

### CodeIgniter 4

```json
{
  "schema_version": 2,
  "script_id": "SCR-CI4",
  "version": "1.0.0",
  "framework": "codeigniter4",
  "runtime": {"type": "php", "php": ">=8.1", "extensions": ["intl", "mbstring", "mysqli", "pdo_mysql"]},
  "database": {"driver": "mysql", "migrations": ["migrations/001.jsonl"]},
  "inputs": [],
  "payload": {"root": "payload", "writable": [{"path": "writable", "mode": "0770"}]},
  "configuration": [{"path": ".env", "format": "dotenv", "values": {
    "CI_ENVIRONMENT": "production", "app.baseURL": "{{app.url}}",
    "database.default.hostname": "{{database.host}}", "database.default.port": "{{database.port}}", "database.default.database": "{{database.name}}",
    "database.default.username": "{{database.user}}", "database.default.password": "{{database.password}}",
    "database.default.DBDriver": "MySQLi"
  }}],
  "health_check": {"path": "/"}
}
```

Ship `spark`, `app/`, `public/index.php`, production dependencies, and compiled assets.

### CakePHP

```json
{
  "schema_version": 2,
  "script_id": "SCR-CAKE",
  "version": "1.0.0",
  "framework": "cakephp",
  "runtime": {"type": "php", "php": ">=8.2", "extensions": ["intl", "mbstring", "pdo_mysql"]},
  "database": {"driver": "mysql", "migrations": ["migrations/001.jsonl"]},
  "inputs": [],
  "payload": {"root": "payload", "writable": [{"path": "tmp", "mode": "0770"}, {"path": "logs", "mode": "0770"}]},
  "configuration": [{"path": "config/app_local.php", "format": "token-template",
    "template": "<?php\nreturn [\n 'App' => [\n  'fullBaseUrl' => '{{app.url|php-string}}',\n ],\n 'Datasources' => [\n  'default' => [\n   'className' => 'Cake\\\\Database\\\\Connection',\n   'driver' => 'Cake\\\\Database\\\\Driver\\\\Mysql',\n   'persistent' => false,\n   'host' => '{{database.host|php-string}}',\n   'port' => '{{database.port|php-string}}',\n   'username' => '{{database.user|php-string}}',\n   'password' => '{{database.password|php-string}}',\n   'database' => '{{database.name|php-string}}',\n   'encoding' => 'utf8mb4',\n  ],\n ],\n];\n"}],
  "health_check": {"path": "/"}
}
```

Ship `bin/cake`, `config/`, `src/`, `webroot/index.php`, `vendor/autoload.php`, dependencies, and assets.

### Raw PHP

```json
{
  "schema_version": 2,
  "script_id": "SCR-PHP",
  "version": "1.0.0",
  "framework": "raw_php",
  "runtime": {"type": "php", "php": ">=8.1", "extensions": ["pdo_mysql"]},
  "database": {"driver": "mysql", "migrations": ["migrations/001.jsonl"]},
  "inputs": [],
  "payload": {"root": "payload", "writable": [{"path": "storage", "mode": "0770"}]},
  "configuration": [{"path": "config/install.php", "format": "php-array", "values": {
    "APP_URL": "{{app.url}}", "DB_HOST": "{{database.host}}", "DB_PORT": "{{database.port}}",
    "DB_NAME": "{{database.name}}", "DB_USER": "{{database.user}}", "DB_PASSWORD": "{{database.password}}"
  }}],
  "health_check": {"path": "/"}
}
```

Ship `index.php`; explicitly declare every extension, writable path, input, and configuration destination.

### Node and Next.js

There is intentionally no valid automatic-install manifest. Do not use `runtime.type: "node"` or `framework: "nextjs"`. These applications need dependency installation, long-running process supervision, port allocation, and reverse-proxy administration outside this installer.

## Migration examples

Relational operations use only `CREATE TABLE|INDEX|VIEW`, `ALTER TABLE`, `INSERT INTO`, or `UPDATE`, contain no embedded semicolon, and bind each `?` with one descriptor.

MySQL/MariaDB JSONL:

```json
{"driver":"mysql","sql":"CREATE TABLE users (id BIGINT PRIMARY KEY, email VARCHAR(255) NOT NULL)","parameters":[]}
{"driver":"mysql","sql":"INSERT INTO users (id,email) VALUES (?,?)","parameters":[{"value":1},{"value":"demo@invalid.test"}]}
{"driver":"mysql","sql":"INSERT INTO admins (email,password) VALUES (?,?)","parameters":[{"source":"input.admin_email"},{"source":"input.admin_password","transform":"password_hash","algorithm":"bcrypt"}]}
```

PostgreSQL JSONL:

```json
{"driver":"pgsql","sql":"CREATE TABLE users (id BIGINT PRIMARY KEY, email VARCHAR(255) NOT NULL)","parameters":[]}
{"driver":"pgsql","sql":"INSERT INTO users (id,email) VALUES (?,?)","parameters":[{"value":1},{"value":"demo@invalid.test"}]}
```

SQLite JSONL:

```json
{"driver":"sqlite","sql":"CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL)","parameters":[]}
{"driver":"sqlite","sql":"INSERT INTO users (id,email) VALUES (?,?)","parameters":[{"value":1},{"source":"input.admin_email"}]}
```

SQL Server JSONL:

```json
{"driver":"sqlsrv","sql":"CREATE TABLE users (id BIGINT PRIMARY KEY, email NVARCHAR(255) NOT NULL)","parameters":[]}
{"driver":"sqlsrv","sql":"INSERT INTO users (id,email) VALUES (?,?)","parameters":[{"value":1},{"value":"demo@invalid.test"}]}
```

MongoDB JSONL allows one `create`, `insert`, `createIndexes`, or `collMod` command per line:

```json
{"driver":"mongodb","command":{"create":"users"}}
{"driver":"mongodb","command":{"insert":"users","documents":[{"_id":1,"email":"demo@invalid.test"}]}}
```

Generated literal descriptors contain only one JSON scalar `value`. Installer-time values contain one allowlisted `source`; a password source may add `password_hash` with `bcrypt` or `argon2id`. Arrays/objects as relational literal parameters, mixed `value` and `source`, unknown fields, raw `.sql`, executable hooks, and arbitrary commands are rejected.

Executable SQL may not read or write server files, even when nested inside an otherwise allowlisted statement. Rejected constructs include MySQL `LOAD_FILE` and `INTO OUTFILE`/`DUMPFILE`, PostgreSQL `pg_read_file`, `pg_read_binary_file`, and `lo_import`, and SQL Server `OPENROWSET(BULK ...)`. Detection ignores quoted literals and comments, so bound text containing these words is not treated as executable SQL.

Question marks inside quoted strings, quoted identifiers, and SQL comments are data, not placeholders. Foreign-key checks remain enabled while migrations run, so create and seed referenced parent rows before child rows. Referential-integrity failures stop installation and trigger rollback.

## Preparing a clean ZIP from another domain

1. Build production dependencies and frontend assets in a trusted build system.
2. Make a clean release copy. Exclude `.env`, credentials, private keys, `.git`, framework runtime logs/caches/sessions, test output, backups, compiled Laravel views, and customer uploads. Keep dependency source paths such as `vendor/psr/cache` and `vendor/symfony/cache`; their names do not make them runtime cache data.
3. Use a sanitized database copy containing only schema and approved seed/reference data. Remove people, messages, orders, tokens, password hashes, audit data, and source-site secrets.
4. Export MySQL/MariaDB without `DROP`, users, grants, routines, triggers, events, filesystem statements, or delimiter changes. Other database dumps must be converted offline to reviewed JSON/JSONL.
5. Build the package root exactly as documented, validate it, and test it on a disposable HTTPS domain and pre-created empty database.
6. Test health, configuration, permissions, rollback, recovery, and absence of source-domain data before publication.

An archive or SQL converter cannot decide which live data is private; sanitization remains the author's responsibility.

## Limits

| Limit | Maximum |
|---|---:|
| Compressed archive | 512 MiB |
| Unpacked content | 2 GiB |
| File count | 20,000 |
| Individual file | 256 MiB |
| Expansion ratio | 100:1 |
| Download chunk | 8 MiB |

The file-count and unpacked-byte ceilings apply to the aggregate normalized payload, generated or reviewed migrations, required directories, and manifest—not to each part independently. Preparation stops before copying or writing a migration chunk that would cross either ceiling, in both `check` and `build` mode, and removes private temporary output after failure.

The manifest inventory must agree with actual package files, sizes, permissions, and SHA-256 metadata. Archives containing duplicate canonical paths are rejected before extraction, including repeated manifest, payload, or migration names and file/directory collisions such as `payload/config` together with `payload/config/`.

## Forbidden content

- Shell, Composer, npm, or arbitrary executable hooks.
- Symlinks, hard links, device files, sockets, or unsafe special entries.
- Absolute paths, drive paths, backslashes, empty segments, `.` or `..` traversal.
- Writes outside the target or package-selected external download URLs.
- Bundled customer secrets, credentials, private keys, or environment values.
- Runtime types that require a background Node.js/Next.js service in version 1.

Validate the safe example in [`examples/package`](../examples/README.md) before submitting a real package.
