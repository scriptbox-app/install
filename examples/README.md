# Safe fixtures

`package/` is a public, no-database static example for learning the package layout and exercising validation without customer data.

## Contents

```text
package/
├── scriptbox.json
└── payload/
    └── index.html
```

Create the ZIP so `scriptbox.json` and `payload/` are at the archive root, not inside an additional parent directory:

```bash
cd examples/package
zip -r ../safe-static-example.zip scriptbox.json payload
```

Validate it with the trusted package validator documented by the API project. Validation must succeed before any publication attempt. Do not add symlinks, hooks, absolute paths, external URLs, credentials, private keys, `.env` files, or generated dependency directories.

The example is not a production application and its identifiers must not be reused for a real catalog release. See [package format](../docs/package-format.md) for the complete contract.

## Development signing keys

Tests generate ephemeral 2048-bit RSA keys at runtime. For manual development keys, run `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out test-private.pem` and derive `test-public.pem` with `openssl pkey -in test-private.pem -pubout`. These files are development-only, ignored, and must never become production trust roots.

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out test-private.pem
openssl pkey -in test-private.pem -pubout -out test-public.pem
```

Delete development private keys when testing ends. Never copy them into `config/release.php`, documentation, fixtures, commits, CI logs, or production environments.
