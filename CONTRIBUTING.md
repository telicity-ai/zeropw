# Contributing to ZeroPW

Use Rust for product changes. Read [product intent](docs/product-intent.md), [security design](docs/security-design.md) and [implementation limits](docs/implementation.md) before changing behavior. Keep the agent boundary intact: original credentials must not enter agent processes, environments, arguments, files or tool output. SSH signing remains a core feature. Unsupported integrations must fail explicitly without plaintext fallback.

## Development

Use a disposable runner or isolated VM with no production vault, gateway, signer, administrator, deployment or coordinator authority. Test with synthetic credentials and controlled endpoints. Do not put real credentials into fixtures, test environments, issues or pull requests.

```sh
cargo build --locked --manifest-path rust/Cargo.toml --bins
rust/verify.sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

`rust/verify.sh` runs the full test matrix, including real OpenSSH E2E and signer resource probes. Install OpenSSH server/client tooling and Perl in the verification environment. Missing E2E prerequisites must be reported as unavailable, never counted as success.

For installer changes, test successful installation and failure boundaries: wrong checksums, traversal, links, missing helpers and existing-file behavior. For product changes, add tests for observable behavior and meaningful failure boundaries. Do not weaken a test or change the review harness merely to make a result pass.

The Python prototype no longer runs as a product backend. Fixed fixtures preserve stored-state and wire-format compatibility. Do not silently regenerate or translate cryptographic fixtures. Explain intentional user-facing output changes separately from state/wire compatibility.

## Pull requests

Describe the concrete behavior changed, affected boundaries, tests run, remaining limits and unresolved findings. Use English for maintained documentation and user-facing output. Keep `README-ko.md` as the Korean entry point. Preserve useful Unicode test data even when its content is not English.

Do not claim a test or review PASS for a different commit. Do not substitute self-review for an independent review required by the project. Repository permissions, production deployment and public visibility remain maintainer decisions.

Contributions to this repository are offered under its [MIT license](LICENSE). Dependencies keep their own licenses and notices. Record added dependencies and any redistribution obligations in release preparation.
