# Contributing

Thank you for improving the public ScriptBox installer. Contributions should preserve a readable single-file release, fail-closed security, bounded memory use, deterministic output, and safe recovery.

## Development requirements

- PHP 8.3 or newer with cURL, OpenSSL, JSON, ZIP, and available database extensions.
- Node.js 24 for the React UI and MCP server.
- Git and a POSIX-compatible shell for the supplied build commands.
- The sibling `installUI` and `scriptbox-api` repositories for contract or end-to-end work.

## Workflow

1. Preserve unrelated working-tree changes.
2. Describe the user-visible or security behavior being changed.
3. Add a focused failing regression test before implementation.
4. Make the smallest change that satisfies the test.
5. Run the relevant component checks and the deterministic installer build.
6. Update every affected public contract and Markdown document.
7. Review the diff for credentials, private paths, raw exceptions, generated noise, and accidental compatibility changes.

```bash
php tests/run.php
php build/release.php
php -l install.php
sha256sum -c install.php.sha256
git diff --check
```

## Design constraints

- `install.php` remains dependency-free at runtime and must not execute shell, Composer, npm, or package-provided hooks.
- Remote communication stays on fixed HTTPS installer-v1 routes; do not add arbitrary proxy or URL-fetch features.
- Archives may not create absolute, traversal, link, device, or outside-target entries.
- State and temporary files stay outside the document root with restrictive permissions.
- Logs, diagnostics, telemetry, and tests must not contain credentials, tokens, environment variables, database connection details, or customer file contents.
- The MCP server may expose only bounded resources and fixed tools; do not add arbitrary shell, SQL, URL, or filesystem access.

## Cross-project changes

Protocol changes must update the PHP installer, React client, API service, OpenAPI document, tests, package schema when applicable, MCP contract summaries, and public documentation in the same release. Maintain backward compatibility during a rollout whenever an older deployed installer may still call the API.

## Documentation style

Write for the stated audience, use copy-paste-safe commands, mark placeholders, avoid claiming that a public key is secret, and never include production credentials. Public installer documents explain user behavior; confidential production operations belong only in the private API repository.

See [release verification](docs/release.md), [security policy](SECURITY.md), and [threat model](docs/threat-model.md).
