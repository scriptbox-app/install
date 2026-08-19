# Deterministic release

1. Put approved current and next public PEM keys in `config/release.php`—never private keys.
2. Run `php tests/run.php && php build/compile.php && php -l install.php` twice and compare SHA-256.
3. With Node 24 run Project 1 tests/lint/build and publish its hashed `dist` through Project 2.
4. Validate and publish packages only through the trusted CLI.
5. Release metadata records installer hash, version, key ID, UI release, protocol, and an offline signature.

Never use example/development keys in production.
