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
