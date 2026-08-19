# Three-project MCP server

```bash
cd tools/mcp
npm ci
npm run build
npm test
```

```json
{"mcpServers":{"scriptbox":{"command":"node","args":["/absolute/path/install/tools/mcp/dist/server.js"],"env":{"SCRIPTBOX_MCP_ARTIFACT_ROOTS":"/approved/package/input"}}}}
```

Resources cover overview, three project statuses, installer contract, package schema, and release hashes. Tools are `workspace_validate`, `project_checks`, `contract_validate`, `installer_build`, `ui_build`, `package_validate`, `publish_preview`, and `publish_execute`.

Publishing requires preview, human review of exact target/hash/change, then a five-minute single-use token. MCP cannot manage licenses/keys/payments, deploy, run arbitrary shell/SQL/URLs, or expose sensitive files. JSON-RPC alone uses stdout; diagnostics use stderr.
