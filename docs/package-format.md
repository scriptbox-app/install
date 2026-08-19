# Package format

Every ZIP has `scriptbox.json` at its root and root-ready files below `payload/`.

```json
{"schema_version":1,"script_id":"SCR-001","version":"1.0.0","runtime":{"type":"php","php":">=8.3","extensions":["pdo_mysql"]},"database":{"driver":"mysql","migrations":["migrations/001.json"]},"payload":{"root":"payload","writable":["storage"]},"configuration":[{"path":".env","format":"dotenv","values":{"DB_PASSWORD":"{{database.password}}"}}],"health_check":{"path":"/health"}}
```

Migration files contain ordered driver-matching JSON operations. Allowed databases: none, MySQL/MariaDB, PostgreSQL, SQLite, SQL Server, and MongoDB when the PHP extension exists. Limits: 512 MiB compressed, 2 GiB unpacked, 20,000 files, 256 MiB/file, 100:1 expansion, and 8 MiB chunks. Hooks, Composer/npm, links, absolute/traversal/device paths, outside writes, and package-selected URLs are forbidden.
