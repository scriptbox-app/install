# Deployment and recovery checklist

This public checklist is for the hosting administrator deploying `install.php`. Internal API release operations are documented separately in the private API repository.

## Before upload

- [ ] Use a dedicated HTTPS domain or subdomain with a valid certificate.
- [ ] Confirm PHP-FPM and CLI use PHP 8.3 or newer.
- [ ] Enable cURL, OpenSSL, JSON, ZIP, and the selected database extension.
- [ ] Create an empty target directory; do not place the installer over an existing site.
- [ ] Make the target writable by the PHP-FPM pool user with least privilege; never use `0777`.
- [ ] Create an empty database and restricted database user when required.
- [ ] Confirm outbound HTTPS to `api.scriptbox.app` is allowed.
- [ ] Download `install.php` and its checksum from the same approved release.
- [ ] Compare `sha256sum install.php` with the published value.

## After upload

- [ ] Open the installer only through HTTPS.
- [ ] Confirm the runtime panel reports supported PHP, required extensions, and `target: writable`.
- [ ] Confirm the read-only detected origin matches the deployed HTTPS domain; no browser domain input is required.
- [ ] Read the privacy notice before consenting.
- [ ] Select only a free package marked compatible with the detected runtime/database.
- [ ] Reconfirm that the database is empty before submission.
- [ ] Keep the browser open through download, validation, migration, promotion, health check, and activation.

## Successful completion

- [ ] Confirm the completion screen and permanent installer lock.
- [ ] Open the installed application through its final HTTPS URL.
- [ ] Confirm sensitive configuration files are not publicly downloadable.
- [ ] Remove installation access if the release instructs you to do so; do not delete private state before success is confirmed.
- [ ] Store the script/version/license reference needed for support without storing database credentials.

## When installation fails

1. Record the stable error code and diagnostic ID.
2. Run `php install.php status` using the same PHP version as PHP-FPM.
3. Read [errors.md](errors.md) before changing permissions, files, database state, or network rules.
4. Allow automatic rollback to finish.
5. Do not manually delete journaled files or retry if the state is `recovery_required`.

## Recovery

For recovery, stop traffic, preserve the redacted journal, remove only journaled promoted files, restore the pre-created database to empty, then clear recovery state only through an audited operator procedure.

```bash
php install.php status
php install.php recover
```

If recovery cannot prove the target and database are clean, contact support with the diagnostic ID. Never send passwords, `.env` contents, tokens, raw database exports, or customer files.
