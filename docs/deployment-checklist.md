# Deployment and recovery checklist

- Rotate committed FTP credentials; verify FTP routes are absent.
- Configure unique JWT/installer/signing/database/storage secrets, exact HTTPS CORS origins, and proxy CIDRs.
- Apply installer migrations and provision private disk or S3/MinIO.
- Verify catalog has no artifact URLs; test cPanel/Apache, Nginx/FPM, VPS proxy, disk and MinIO.
- Interrupt/resume and inject failure after every phase; confirm target/database return empty.
- Confirm success/recovery lock, telemetry redaction, and 30-day cleanup.

For recovery, stop traffic, preserve the redacted journal, remove only journaled promoted files, restore the pre-created database to empty, then clear recovery state only through an audited operator procedure.
