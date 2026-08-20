# Three-project MCP server

The optional MCP server helps local contributors inspect and validate the installer, UI, and API repositories from an AI client. Customer installations do not need MCP, and production traffic never passes through it.

## Requirements

- Node.js 24.
- All three repositories checked out at configured, trusted paths.
- Approved package input directories when package validation/publication is needed.
- A local AI client that supports MCP over stdio.

## Build and test

```bash
cd tools/mcp
npm ci
npm run build
npm test
```

## Client configuration

```json
{
  "mcpServers": {
    "scriptbox": {
      "command": "node",
      "args": ["/absolute/path/install/tools/mcp/dist/server.js"],
      "env": {
        "SCRIPTBOX_MCP_ARTIFACT_ROOTS": "/approved/package/input"
      }
    }
  }
}
```

The server uses stdout only for JSON-RPC. Diagnostics go to stderr so logging cannot corrupt the protocol.

## Resources

- `scriptbox://workspace/overview`
- `scriptbox://projects/{project}/status`
- `scriptbox://contracts/installer-v1`
- `scriptbox://packages/schema`
- `scriptbox://releases/current`
- Sanitized build, test, and capability summaries

Resources never expose `.env`, Git internals, signing keys, credentials, unrestricted source files, raw databases, or secret-bearing logs.

## Tools

| Tool | Purpose |
|---|---|
| `workspace_validate` | Validate configured repository roots and public contracts |
| `project_checks` | Run the fixed test/lint checks for one approved project |
| `contract_validate` | Compare installer-v1 and package contracts |
| `installer_build` | Produce and validate deterministic `install.php` |
| `ui_build` | Run fixed React tests, lint, and production build |
| `package_validate` | Inspect an approved ZIP against package rules |
| `publish_preview` | Return exact paths, hashes, target, and a five-minute token |
| `publish_execute` | Execute only the single-use previewed publication |

## Security boundaries

Every configured path is resolved with `realpath` and must remain inside an approved repository or artifact input root. Commands use fixed executables and arguments with no shell. Publisher subprocesses receive an allowlisted environment. Mutating tools write redacted audit events.

Publishing requires preview, human review of the exact target/hash/change, and a five-minute single-use token. MCP cannot activate/revoke licenses, rotate keys, administer payments, edit production records, deploy servers, run arbitrary shell/SQL/URLs, or provide unrestricted filesystem access.

## Troubleshooting

- If the client cannot initialize, run the compiled server manually and inspect stderr.
- If a root is rejected, check its configured absolute path and symlink resolution.
- If a build tool fails, run that project’s documented fixed command directly.
- If a preview expires or is used, request a new preview; tokens cannot be replayed.
