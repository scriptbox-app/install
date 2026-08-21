# Installation wizard, resume, and cleanup

The catalog and details are always available before verification. Installation starts only after a compatible free script's **Install** button is pressed. Paid scripts remain preview-only.

## Wizard order

1. **Version** — selects the newest signed artifact by default and shows runtime/database compatibility.
2. **Server requirements** — checks PHP, extensions, database adapter, SAPI, memory/disk limits, and offers Refresh.
3. **Target and permissions** — chooses `/` or a safe relative folder and checks exists/writable/empty/can-create.
4. **Privacy and ownership** — explains limited support telemetry, records explicit consent, and verifies the automatically detected HTTPS origin.
5. **Application setup** — shows only typed fields declared by the signed package; there is no raw `.env` or PHP editor.
6. **Database** — appears only when required, tests the connection, and confirms the pre-created database is empty.
7. **Configuration preview** — lists output destinations/formats and writable paths with secret values redacted.
8. **Confirmation** — summarizes script, version, URL, target, runtime, database, and cleanup preference.
9. **Progress** — displays the private run's current phase and safe percentage. Refreshing recovers the run ID; secrets are requested again if the pending local phase still needs them.
10. **Completion or recovery** — shows the installed URL/license result, permanent lock, and safe cleanup/recovery guidance.

## Target rules

- `/` is the validated document root. Only the exact verified `install/` control directory is ignored when checking whether the root is empty.
- Relative paths such as `shop` and `apps/shop` are allowed.
- Each segment starts with an ASCII letter or digit and then uses only letters, digits, `.`, `_`, or `-`; maximum segment length is 64, depth is five, and combined length is 255.
- Absolute paths, traversal, symlinks, hidden/reserved segments, the installer control path, and escapes outside the document root are rejected.
- A missing destination is created only when the validated parent is writable. An existing destination must be empty.
- The browser receives `/` or the relative URL and readiness booleans. It never receives an absolute server path.

## Resume and secrets

Each run has a random identifier stored in private installer state. Status responses contain only script/version/relative target, phase, progress, timestamps, and stable diagnostics. Database and application secrets are not written to state, rollback journals, logs, local storage, telemetry, or the ScriptBox API. After a page reload, the wizard requests secrets again only when the pending local phase requires them.

Downloads use 8 MiB ranges and renew expired authorization without discarding verified bytes. A failure before promotion removes download/staging data. A failure after mutation invokes the append-only rollback journal. If complete cleanup cannot be proven, `recovery_required` blocks a new run.

File recovery replays hash-bound promotion intents under the exclusive installer lock. If migration was interrupted, the recovery form requests the original connection again and verifies a random marker created before database changes before allowing reset. The CLI handles file-only recovery and never accepts database credentials.

## Cleanup

After successful activation the installer is permanently locked. Removing the minimal bundle is safe only when the control directory contains exactly `index.php`, `install.php`, `install.php.sha256`, and `release.json`, with no symlinks or unknown entries and matching release metadata. Git checkouts, directories containing `.git`, and folders with unexpected files are never recursively deleted. When safe automatic removal is unavailable, keep the permanent lock and remove the four public files manually after recording the checksum/license reference.

`release.json.sig` is an external verification artifact, not part of the deployed four-file directory. Keeping it beside the installer intentionally disables automatic self-removal.

```bash
/www/server/php/83/bin/php install.php status
```

Never delete the private state or journal while recovery is incomplete.
