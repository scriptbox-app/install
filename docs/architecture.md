# Architecture and sequence

```text
AI client ─stdio─> local MCP ─fixed commands─> three repositories
Admin ZIP/UI dist ─trusted publisher─> private disk or S3
Browser React UI ─same origin─> install.php ─signed HTTPS─> /installer/v1 API
                                  └─stage → empty DB → promote → health → activate
```

Sequence: preflight/lock → anonymous free license → artifact authorization → ranged download → hash/signature/ZIP verification → staging/configuration → empty database snapshot → ordered JSON migration → journaled promotion → HTTPS health check → activation → cleanup/permanent lock. Failure unwinds created files/database objects; uncertain cleanup produces `recovery_required`.
