# Deployment and recovery checklist

This public checklist is for the hosting administrator deploying `install.php`. Internal API release operations are documented separately in the private API repository.

## Before upload

- [ ] Use a dedicated HTTPS domain or subdomain with a valid certificate.
- [ ] Confirm PHP-FPM and CLI use PHP 8.3 or newer.
- [ ] Enable cURL, OpenSSL, JSON, ZIP, and the selected database extension.
- [ ] Upload the signed four-file bundle under `/install`, or use the reviewed standalone `install.php` deployment.
- [ ] Confirm the intended root or relative destination is empty; do not place the installer over an existing site.
- [ ] Make the target writable by the PHP-FPM pool user with least privilege; never use `0777`.
- [ ] Create an empty database and restricted database user when required.
- [ ] Confirm outbound HTTPS to `api.scriptbox.app` is allowed.
- [ ] If PHP uses `open_basedir`, include `/tmp` or configure a writable `SCRIPTBOX_STATE_DIR` outside the public document root. The installer must not use the hosting account’s parent directory when that path is restricted.
- [ ] Download `index.php`, `install.php`, `install.php.sha256`, and `release.json` from the same approved release.
- [ ] Compare `sha256sum install.php` with the published value.
- [ ] Record that SHA-256 fingerprint for the post-upload runtime check.

## After upload

- [ ] Open the installer only through HTTPS.
- [ ] Request `install.php/api/runtime` and confirm `data.build.artifact_sha256` matches the recorded release fingerprint and `data.build.release_timestamp` is the expected release value.
- [ ] Confirm the wizard reports supported PHP/extensions and the selected relative target as writable, empty, or safely creatable without revealing an absolute path.
- [ ] Confirm the read-only detected origin matches the deployed HTTPS domain; no browser domain input is required.
- [ ] Read the privacy notice before consenting.
- [ ] Select only a free package marked compatible with the detected runtime/database.
- [ ] Use the wizard database test and reconfirm that the pre-created database is empty before submission.
- [ ] Keep the browser open through download, validation, migration, promotion, health check, and activation.

## Successful completion

- [ ] Confirm the completion screen and permanent installer lock.
- [ ] Open the installed application through its final HTTPS URL.
- [ ] Confirm sensitive configuration files are not publicly downloadable.
- [ ] Accept automatic minimal-bundle cleanup only for a verified four-file release. Git checkouts or directories with unknown files require manual removal after permanent lock.
- [ ] Store the script/version/license reference needed for support without storing database credentials.

## When installation fails

1. Record the stable error code and diagnostic ID.
2. Run `php install.php status` using the same PHP version as PHP-FPM.
3. Read [errors.md](errors.md) before changing permissions, files, database state, or network rules.
4. Allow automatic rollback to finish.
5. Do not manually delete journaled files or retry if the state is `recovery_required`.

Current catalog images load from sanitized public HTTPS URLs. A failed image keeps its placeholder and does not stop installation. Legacy rollback releases may still report `MEDIA_*` diagnostics for the tokenized proxy route; never share a token, response body, or private URL.

## Recovery

For recovery, stop traffic and preserve the redacted journal. Run the CLI for file-only cleanup. When database mutation is recorded, reopen the browser wizard and supply the original database connection; the installer verifies its private recovery-marker digest before resetting it. A different same-driver database is rejected.

```bash
php install.php status
php install.php recover
```

If recovery cannot prove the target and database are clean, contact support with the diagnostic ID. Never send passwords, `.env` contents, tokens, raw database exports, or customer files.
