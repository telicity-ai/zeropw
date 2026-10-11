# Release preparation

The repository is public. The owner selected Apple Silicon macOS and ARM64 GNU/Linux binary support for v0.1.0 on 2026-10-11. Intel macOS and x86-64 Linux binaries are deferred until native execution is verified.

## Gates

1. Run the complete Rust verification matrix on Linux and macOS at the release commit. Include real SSH, separate-process CLI, three-node team synchronization, incident response, revocation, recovery, and signer resource probes. Preserve skips and failures explicitly.
2. Review current source and Git history for private information. English is the default for maintained documentation and product output; `README-ko.md` retains Korean. Preserve fixed interoperability fixtures instead of silently rewriting their bytes.
3. Build the five binaries natively for both v0.1.0 targets: Apple Silicon macOS and ARM64 Linux. Install from the produced archive into a fresh prefix and run the installed demo and CLI checks on disposable runners.
4. Check archive SHA-256 values, reject unsafe archive entries, include the selected license, and test the Homebrew formula against the exact release.
5. Obtain the required review for the exact commit; keep release artifacts tied to that commit. Do not reuse an earlier PASS.

## Packaging tools

`python3 scripts/package-release.py --version v0.1.0 --target TARGET --bin-dir DIR --out-dir DIR --third-party-licenses NOTICES_FILE` creates a flat binary archive and its checksum. Generate the target notices first with `python3 scripts/dependency-licenses.py --target TARGET --output NOTICES_FILE`. The license is MIT. The builder recognizes four targets; v0.1.0 publishes only `aarch64-apple-darwin` and `aarch64-unknown-linux-gnu`. Recognition by the tooling is not a support claim.

`scripts/install.sh --version v0.1.0` downloads the matching archive and its matching `.tar.gz.sha256` asset from GitHub Releases. Before publication, use `--archive FILE --sha256 HEX` with a verified local archive. The default prefix is `$HOME/.local`; `--prefix /absolute/path` overrides it. Existing binaries are preserved unless `--force` is supplied.

The installer does not use sudo, initialize a vault, start a service, modify shell profiles, or execute downloaded binaries. Checksums detect corruption but are not an independent signature: the release host and publisher remain trusted. Updates replace five staged binaries individually; this is not an atomic transaction across the entire installation. Stop running processes before an upgrade.

## v0.1.0 evidence and installation

Product source is main commit `e157422353b5967cf5c7d61deccbbf30feba9b0e`, with the same complete tree as reviewed source `5f741334ac74ebb020fa27cb9ae75e925391f45b`. The release preparation changes formula and documentation only; binary hashes and product source remain bound to this baseline.

At that product source, native macOS ARM64 passed 1,384 Rust tests and four resource probes; native Ubuntu 24.04 ARM64 passed 1,381 Rust tests and four resource probes. Tooling passed 25 tests; the harness passed 80 tests and compilation. Installed archives passed all 47 demo checks on each native host. An empty Linux runtime containing glibc dependencies and no shared OpenSSL also passed all 47 checks. Claude Opus 5.5 completed the final local review with no unresolved findings. These counts do not claim Intel or x86-64 runtime verification.

The release archives statically link an authenticated OpenSSL 3.5.9 SDK. All five binaries on each target passed linkage checks. MIT and target-specific dependency notices are included. The source formula previously passed native macOS installation and all demo checks; the stable formula pins the two release archive SHA-256 values. Publication and public-download checks are recorded separately in the release verification asset.

The tracked-tree and reachable-history scans classified key markers as SSH parser literals and synthetic fixtures. Historical personal paths are development evidence. No GitHub-token or AWS-access-key shape was found by these rules. This is a narrow scan, not a guarantee against every secret format.

On Apple Silicon macOS:

```sh
brew tap telicity-ai/zeropw https://github.com/telicity-ai/zeropw
brew install telicity-ai/zeropw/zeropw
brew test telicity-ai/zeropw/zeropw
```

Linux Homebrew installation is unverified; ARM64 Linux users should use the archive installer below. The stable macOS formula installs the checksummed v0.1.0 archive without Rust or a separate OpenSSL dependency. `--HEAD` is an optional source build using Rust and Homebrew OpenSSL; it follows main and is not the versioned release. On Linux, the binary baseline is Ubuntu 24.04; older glibc versions are unverified.

For ARM64 Linux, or macOS without Homebrew, download `scripts/install.sh` from the release tag, inspect it, and run:

```sh
bash install.sh --version v0.1.0 --prefix "$HOME/.local"
"$HOME/.local/bin/zeropw-demo"
```

GitHub Actions remains disabled; native verification used the local Mac and an isolated ARM64 Linux VM. No hosted minutes were used. The historical records below retain their original failures and source bindings.

## Preparation evidence: 2026-10-10

At `e81fd0b`, the complete Linux ARM64 verification matrix ran in the existing isolated Lima VM under an unprivileged verification user. The matrix finished with `VERIFY_FAILED=test:runs`: `timeout_and_spawn_failure_are_terminal` observed `running` rather than `failed` after its unchanged four-second wait. All four separately selected signer resource probes passed. This is a failed overall result, not a release PASS. The original log is retained in the private VM job evidence.

At `29faaa1`, six affected integration targets passed: `cli_commands` (10), `native_response_cli` (13), `response` (27), `response_contract` (8), `response_parity_gaps` (8), and `runs` (19): 85 tests total. This validates the English incident report and decoded SMTP delivery and preserves the historical Korean fixtures. The timeout test also passed, but the original matrix failure remains unexplained and open. Later documentation-only commits do not extend this evidence into a full release claim.

The tracked-tree information scan examined 336 files: 18 file-level personal-path findings and three file-level private-key-marker findings require classification. No GitHub-token or AWS-access-key pattern was found by these narrow rules. This is not proof of a comprehensive clean secret audit; history and other token formats remain to be examined. The scanner reports paths, categories and counts without printing matched values.

### Native archive installation: Linux ARM64

Product binaries built from `a1a9ea7` were packaged as `zeropw-v0.1.0-aarch64-unknown-linux-gnu.tar.gz` in the isolated Linux VM. The first installer invocation failed before installation because a clean environment had no `HOME`, even with an explicit prefix. Installer commit `1ffd57a` fixes that and adds the corresponding regression test.

With the corrected installer, the existing verified archive was installed into a fresh explicit prefix with no `HOME`. Both installed CLI help commands succeeded; the installed demo passed all 47 checks and finished with `INSTALLED_ARCHIVE_VERIFICATION_PASS`. No real vault was initialized, and no production credentials were used. This establishes native Linux ARM64 archive installation, not x86-64 Linux/macOS or public HTTPS download availability. The archive has not been published.

At `1f7f064`, all 80 harness unit tests and harness compilation passed after its operating documentation was translated. All 13 current installation/information-scanner tests pass after the explicit-prefix fix. The isolated single timeout test also passed at unchanged product source `a1a9ea7`; this does not identify the earlier full-matrix failure mechanism.

### Dependency notice inventory

The locked Cargo dependency inventory ran in the isolated Linux VM after `cargo fetch --locked`. Original root notice text was collected without exposing local cache paths. Case-insensitive filename handling was added for upstream packages using lowercase `license-*` names. Two packages in the complete metadata graph still lack root notice files: `r-efi 6.0.0` and `yasna 0.5.2`. Their published README/source describe alternative licenses, but their redistribution notices require explicit classification before bundling. This inventory includes development and non-native dependencies; it does not yet establish the precise runtime closure for each release target or completed licensing compliance.

### Target-specific notices and installation

The runtime/build dependency closure was collected for all four declared targets (Apple Silicon/Intel macOS, x86-64/ARM64 Linux) with Cargo's platform-filtered metadata. Root notices were found for every package in those closures. The earlier missing-root findings belong to the complete development/non-native graph; they remain documented rather than being rewritten as production dependencies.

Packaging/installer tooling at `3c89f02` includes `THIRD_PARTY_LICENSES.md` alongside README and MIT license and installs them under `share/doc/zeropw`. In the isolated Linux ARM64 VM, repackaging the existing `a1a9ea7` release binaries and installing into a fresh prefix passed both installed CLI checks and all 47 demo checks, with `INSTALLED_NOTICES_VERIFICATION_PASS`. Binary source and packaging source are deliberately recorded separately. Notice collection covers declared licenses and upstream root notice files; it is not an independent legal review of all nested source.

All 15 current installer/information-scanner tests pass, including refusal of a missing notice file and symlinked documentation directories.

### Current verification and documentation status

The unchanged product execution target at source snapshot `3c89f02` passed three complete default-parallel `runs` repetitions (19 tests each), retaining the original timeout assertions. This is stress evidence, not proof of the historical failure mechanism. The complete Linux matrix at `d4a99ec` ended with Clippy and native CLI E2E failures; those original logs remain in the isolated VM. Subsequent fixes require separate exact-source evidence.

Compromise-response and implementation documentation are now English, including rule thresholds, recovery order, known limits, and all original acceptance-table test identifiers. Team protocol documentation is now English. All 18 installer/scanner/licensing tests pass, and updated documentation links/shell examples were checked.

The repository currently has zero registered self-hosted runners. The owner has authorized local macOS and Homebrew verification instead of a Mac mini runner; no hosted-minute or repository-setting changes were made.

Binary archives must be built with `python3 scripts/build-release.py --target TARGET --version v0.1.0 --out-dir dist` on a matching native host. The builder verifies the pinned OpenSSL 3.5.9 source SHA-256, builds a static SDK with system certificate paths, and includes its notices. `bundled-openssl` alone does not select an unpatched source crate: the build gate requires the release SDK and static libraries. Homebrew source installation uses its declared OpenSSL dependency. Bundled archives must not link to Homebrew or system OpenSSL. GNU/Linux archives require a compatible glibc runtime (build baseline Ubuntu 24.04); they are not musl binaries. Packaging normalizes tar and gzip metadata so identical files produce identical archive bytes on the same packaging runtime.

The pinned source is from the [official OpenSSL release](https://github.com/openssl/openssl/releases/tag/openssl-3.5.9). Check [OpenSSL advisories](https://openssl-library.org/news/vulnerabilities-3.5/) when updating the pin. The earlier 3.6.3 vendor experiment is not a release artifact.
