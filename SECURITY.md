# Security policy

Report vulnerabilities privately to the production ScriptBox security contact. Never publish production credentials or customer data.

Required properties: only RS256 envelopes signed by compiled current/next public keys are trusted; UI/package bytes match signed hashes and sizes; remote operations are fixed HTTPS `/installer/v1` routes; archives reject traversal, links, devices and bombs; installs require an empty target/database, exclusive lock, journal and proven rollback; state remains outside the web root; secrets never enter state, telemetry, logs, or MCP resources; paid checkout is disabled.

Before production, rotate every credential previously committed to Project 2, keep FTP routes unregistered, configure exact HTTPS CORS/proxy ranges, and confirm startup rejects defaults. Public keys are not secrets—trust comes from signatures and validation, not obfuscation.
