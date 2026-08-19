# Installer privacy

Telemetry is opt-in. Policy `2026-08-19` permits only the verified domain, API-observed public egress IP, random installation/license IDs, coarse OS/web-server/PHP version, extension names, script/version, phase, stable error code, consent time, and policy version.

Never collected: database host/name/user/password, environment variables, cookies, file contents/paths, `phpinfo()`, authorization/download tokens, or raw exceptions. Detailed events expire after 30 days. Minimal license identity is kept only while operational and is then revoked or anonymized.
