# Security policy

ZeroPW is pre-release software. Its tests use synthetic credentials and controlled endpoints. No production security certification is claimed. Read [the security design](docs/security-design.md) and [known implementation limits](docs/implementation.md) before deploying it.

## Reporting a vulnerability

Do not post a working credential, vault backup, private key, administrator/recovery passphrase, caller token or invitation in a public issue or pull request.

Use the repository's private vulnerability-reporting channel if enabled. While that channel is unavailable, contact a repository maintainer through an existing private channel to arrange a report. Include the affected commit, synthetic reproduction, impact and environment. Do not include production credentials. A public reporting contact must be finalized before launch; this file does not invent one.

## Scope and limits

Agents may exercise their allowed grants. Keeping original credentials out of the agent does not prevent misuse of authorized actions or protect a compromised trusted gateway, vault, signer or member device.

The local same-user development setup is not OS-level isolation. Deploy trusted components separately from agent authority. Shared secrets are decryptable by member devices; roles are policy controls, not cryptographic protection from a member who owns the device. Offline devices receive revocation only after synchronization. Removing a member requires provider-side credential rotation.

The gateway buffers supported responses and blocks known credential reflections. Arbitrary transformed leakage and unvalidated service endpoints are not universally safe. Unsupported protocols fail without secret injection. Stopping a local SSH client cannot guarantee that an already-started remote process terminates.

## Releases

A release must name its exact source commit and include checksums and license information. Checksums from the same release host detect corruption, not compromise of the publisher. Do not label a release production-ready solely because a previous commit passed tests or review.
