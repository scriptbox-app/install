# Safe fixtures

`package/` is a no-database static example. Create a ZIP with `scriptbox.json` and `payload/` at the archive root, then run Project 2’s `installer-validate` CLI.

Tests generate ephemeral 2048-bit RSA keys at runtime. For manual development keys, run `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out test-private.pem` and derive `test-public.pem` with `openssl pkey -in test-private.pem -pubout`. These files are development-only, ignored, and must never become production trust roots.
