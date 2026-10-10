# Release preparation

The repository remains private. Its owner will change visibility after the release gates pass. No installer URL is advertised as working until its matching release assets have been uploaded and verified.

## Gates

1. Run the complete Rust verification matrix on Linux and macOS at the release commit. Include real SSH, separate-process CLI, three-node team synchronization, incident response, revocation, recovery, and signer resource probes. Preserve skips and failures explicitly.
2. Review current source and Git history for private information. English is the default for maintained documentation and product output; `README-ko.md` retains Korean. Preserve fixed interoperability fixtures instead of silently rewriting their bytes.
3. Build the five binaries for Apple Silicon macOS, Intel macOS, and x86-64 Linux. Install from the produced archive into a fresh prefix and run the installed demo and CLI checks on disposable runners.
4. Check archive SHA-256 values, reject unsafe archive entries, include the selected license, and test the Homebrew formula against the exact release.
5. Obtain the required review for the exact commit; keep release artifacts tied to that commit. Do not reuse an earlier PASS.

## Packaging tools

`python3 scripts/package-release.py --version v0.1.0 --target TARGET --bin-dir DIR --out-dir DIR` creates a flat binary archive and its checksum. The license is MIT. Supported targets are `aarch64-apple-darwin`, `x86_64-apple-darwin`, and `x86_64-unknown-linux-gnu`.

`scripts/install.sh --version v0.1.0` downloads the matching archive and SHA256SUMS from GitHub Releases. Before publication, use `--archive FILE --sha256 HEX` with a verified local archive. The default prefix is `$HOME/.local`; `--prefix /absolute/path` overrides it. Existing binaries are preserved unless `--force` is supplied.

The installer does not use sudo, initialize a vault, start a service, modify shell profiles, or execute downloaded binaries. Checksums detect corruption but are not an independent signature: the release host and publisher remain trusted. Updates replace five staged binaries individually; this is not an atomic transaction across the entire installation. Stop running processes before an upgrade.

## Current evidence

- Installer tests use synthetic executables and disposable directories.
- Full product validation and real release-archive installation are pending for this preparation branch. GitHub Actions was verified disabled; no hosted run has started. An isolated existing Linux VM has no host mounts, no agent forwarding and no product authority and is being prepared as an independent execution path.
- Release assets, Homebrew validation, English documentation migration, private-information audit, exact-commit adversarial review remain open.

## Homebrew source installation

Before versioned release bottles exist, use a source formula pinned to the repository's main branch:

```sh
brew tap telicity-ai/zeropw https://github.com/telicity-ai/zeropw
brew install --HEAD telicity-ai/zeropw/zeropw
brew test telicity-ai/zeropw/zeropw
```

This needs Git access while the repository is private. Public users can use the same commands after the owner changes visibility. `--HEAD` follows main and builds with Rust; it is not a versioned binary release. A versioned formula with exact archive checksums remains a release gate.

For CI, create an isolated local Homebrew tap from the formula and point its source at the exact checked-out commit. This validates the formula without requiring product secrets or changing the public tap.

Default documentation already translated: README, GUIDE, product intent and security design. Remaining maintained documents and user-facing demo/notification strings are still being migrated. Historical fixtures remain unchanged.

For the user-selected Mac mini execution path, see [self-hosted runner setup](self-hosted-runner.md). Hosted verification is manual-only to avoid consuming hosted minutes on pushes and PRs.

## Preparation evidence: 2026-10-10

At `e81fd0b`, the complete Linux ARM64 verification matrix ran in the existing isolated Lima VM under an unprivileged verification user. The matrix finished with `VERIFY_FAILED=test:runs`: `timeout_and_spawn_failure_are_terminal` observed `running` rather than `failed` after its unchanged four-second wait. All four separately selected signer resource probes passed. This is a failed overall result, not a release PASS. The original log is retained in the private VM job evidence.

At `29faaa1`, six affected integration targets passed: `cli_commands` (10), `native_response_cli` (13), `response` (27), `response_contract` (8), `response_parity_gaps` (8), and `runs` (19): 85 tests total. This validates the English incident report and decoded SMTP delivery and preserves the historical Korean fixtures. The timeout test also passed, but the original matrix failure remains unexplained and open. Later documentation-only commits do not extend this evidence into a full release claim.

The tracked-tree information scan examined 336 files: 18 file-level personal-path findings and three file-level private-key-marker findings require classification. No GitHub-token or AWS-access-key pattern was found by these narrow rules. This is not proof of a comprehensive clean secret audit; history and other token formats remain to be examined. The scanner reports paths, categories and counts without printing matched values.
