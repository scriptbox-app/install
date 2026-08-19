# Installer v1 protocol

Bootstrap: `https://api.scriptbox.app/installer/v1/bootstrap`. Response data is `{kid,alg:"RS256",payload,signature}` using unpadded base64url. Payload contains compatibility, issue/expiry, immutable UI assets, limits, features, and telemetry policy—no secret. Unknown keys, bad signatures, expiry, future issue time, incompatibility, or asset mismatch fail closed.

Sessions/artifacts expire after 15 minutes and are origin/action scoped. Public catalog responses contain capability information but never storage paths or download URLs. Errors use stable codes and safe messages.
