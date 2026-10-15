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

`python3 scripts/build-release.py --target TARGET --out-dir DIR --bin NAME [--bin NAME ...]` builds only the named release binaries in the same way (pinned static OpenSSL, `--features bundled-openssl`, linkage check, `DIR/THIRD_PARTY_LICENSES.md`) and copies them to `DIR/bin` without creating an archive. The desktop app builds its sidecars this way.

`scripts/install.sh --version v0.1.0` downloads the matching archive and its matching `.tar.gz.sha256` asset from GitHub Releases. Before publication, use `--archive FILE --sha256 HEX` with a verified local archive. The default prefix is `$HOME/.local`; `--prefix /absolute/path` overrides it. Existing binaries are preserved unless `--force` is supplied.

The installer does not use sudo, initialize a vault, start a service, modify shell profiles, or execute downloaded binaries. Checksums detect corruption but are not an independent signature: the release host and publisher remain trusted. Updates replace five staged binaries individually; this is not an atomic transaction across the entire installation. Stop running processes before an upgrade.

## Desktop app (macOS .dmg)

The desktop app (docs/desktop-app.md) can be packaged as an Apple Silicon disk image without any signing credential. Packaging is not publishing: no desktop image has been released, and whether to publish one, under which tag and with which signature is the owner's decision. Never attach a desktop image to an existing release such as v0.1.0; its evidence is bound to its own commit and its archives contain different product source. Use a new tag.

### Gates

The five gates above apply to the desktop image:

1. Run the complete Rust matrix and `desktop/verify.sh` on Linux and macOS at the release commit. The bundled `zeropw-admin`, `zeropw_session` and `zeropw-agent` are built from `rust/` at that commit, not taken from an earlier CLI release.
2. Review current source and history for private information, including `desktop/`.
3. Package natively on an Apple Silicon Mac that holds no vault, signing or notarization keys, with the command below. Then download the published image in a browser on a clean Apple Silicon Mac, verify its checksum, approve it in Gatekeeper, launch it, create a throwaway vault, start the relay and run an agent command, so the sidecars run from the installed app. The packaging script does not run the app.
4. Keep the `.dmg.sha256` beside the image. The image contains the MIT `LICENSE` and the desktop `THIRD_PARTY_LICENSES.md`; publish the same notices as a separate asset.
5. Obtain the required review for the exact commit and bind the image's SHA-256 to it. Do not reuse an earlier PASS.

### Packaging

```sh
python3 desktop/scripts/package-macos.py --work-dir /path/outside/the/checkout/work --out-dir /path/outside/the/checkout/out
```

It needs Apple Silicon macOS with the Xcode command line tools, the Rust toolchain, Node.js and npm, Perl and make (for OpenSSL), and network access for crates, npm packages and the OpenSSL source. `CARGO_TARGET_DIR` is honored. The script:

1. refuses to start while any `APPLE_*` variable or another signing, notarization or updater credential variable is set. Tauri reads those variables from the environment of the whole build, which also runs npm, Vite and every Cargo build script; credentials never belong there;
2. requires a clean tracked tree and builds a copy of the committed `HEAD` in the work directory, so nothing is written into the checkout;
3. requires the desktop version fields to agree: `tauri.conf.json`, `package.json`, `package-lock.json`, `src-tauri/Cargo.toml`, `core/Cargo.toml` and the two workspace entries in `desktop/Cargo.lock`. They give the release version `vX.Y.Z`; bump them together. The sidecars report the version of `rust/Cargo.toml`;
4. runs `npm ci --ignore-scripts`, then `desktop/scripts/prepare-sidecars.sh`, which builds the three sidecars with `scripts/build-release.py --bin` (pinned static OpenSSL 3.5.9, `--features bundled-openssl`, linkage check) and writes the notices, then `tauri build --config src-tauri/tauri.bundle.conf.json --bundles app,dmg` with `CI=true`, which skips the Finder window layout step;
5. verifies the image before anything reaches the output directory: `hdiutil verify`; mounted read-only, the app, the three sidecars, `LICENSE` and `THIRD_PARTY_LICENSES.md` are present and equal to their sources; `otool -L` lists no `/opt/homebrew`, `/usr/local`, `libssl` or `libcrypto` library for any of the four executables; each executable is arm64 with minimum macOS 11.0 and an ad hoc signature with the hardened runtime; the bundle has sealed resources and passes `codesign --verify --deep --strict`; `Info.plist` has the version, `LSMinimumSystemVersion` 11.0 and `NSLocalNetworkUsageDescription`. `spctl -a -vv` is recorded and is expected to reject an ad hoc signed app; that is not a packaging failure.

Artifacts, never replaced once present in the output directory:

| File | Contents |
| --- | --- |
| `zeropw-desktop-vX.Y.Z-aarch64-apple-darwin.dmg` | `ZeroPW.app` and an `Applications` link |
| `zeropw-desktop-vX.Y.Z-aarch64-apple-darwin.dmg.sha256` | `<hex>  <name>`, the same format as the CLI archives |
| `zeropw-desktop-vX.Y.Z-aarch64-apple-darwin-THIRD_PARTY_LICENSES.md` | the notices shipped in `Contents/Resources` |
| `zeropw-desktop-vX.Y.Z-aarch64-apple-darwin-verification.txt` | source commit, checksums and every verification command with its output; packaging evidence, not a release asset |

`ZeroPW.app/Contents/MacOS` holds `zeropw-desktop`, `zeropw-admin`, `zeropw_session` and `zeropw-agent`; `Contents/Resources` holds `LICENSE` and `THIRD_PARTY_LICENSES.md`. The image is arm64 only; Intel Macs are not supported. `Info.plist` declares macOS 11.0 as the minimum, but only the macOS versions actually tested may be stated as supported.

The notices cover the Rust crates of the app executable for `aarch64-apple-darwin`, the sidecars' crates with the statically linked OpenSSL, and the npm packages bundled into the web interface, including the Pretendard and JetBrains Mono fonts (OFL-1.1). A few crates publish no notice file; `desktop/licenses/supplement.json` names a reviewed replacement for each exact version, and a new version fails the collection until it is reviewed. The file ends with source locations for the MPL-2.0 components. Like the CLI notices, this is an inventory, not a legal review.

### Ad hoc signature and Developer ID

The release config signs with the ad hoc identity `"-"`: Tauri signs each sidecar, then the bundle, with the hardened runtime. The whole bundle is sealed, so `codesign --verify --deep --strict` detects modified or added files, but an ad hoc signature names no publisher, is not notarized and cannot be revoked. Gatekeeper rejects it, and users have to override that decision once.

A Developer ID signature with notarization names the publisher, passes Apple's malware check, can be revoked and opens without the override. It requires a paid Apple Developer Program membership and is the recommended way to distribute an app that holds credentials. It is a separate procedure on a trusted Mac, never part of the build.

### What users see on macOS 15 and later

A browser download is quarantined. Opening the ad hoc signed app shows that Apple could not verify that ZeroPW is free of malware, with Done and Move to Trash; Control-click › Open no longer bypasses this since macOS 15. To open it anyway:

1. Try to open ZeroPW once and close the dialog with Done.
2. Open System Settings › Privacy & Security, scroll to Security, and click Open Anyway next to the message about ZeroPW. The button is offered for about an hour after the attempt.
3. Confirm with the login password, then choose Open.

Release notes must say that the app is not notarized and show these steps. Do not tell users to remove the quarantine attribute (`xattr -cr`) or to turn Gatekeeper off (`spctl --master-disable`). Whether macOS assesses the ad hoc signed sidecars again when the approved app starts them is not verified; gate 3 covers it. Sources: Apple's Mac User Guide, "Open a Mac app from an unknown developer", and Apple Developer News, 2024-08-06.

### Checksum verification

With both files in one folder:

```sh
shasum -a 256 -c zeropw-desktop-vX.Y.Z-aarch64-apple-darwin.dmg.sha256
```

It prints `zeropw-desktop-vX.Y.Z-aarch64-apple-darwin.dmg: OK`. As with the CLI archives, a checksum published next to the image detects corruption but is not a signature; the release host and publisher remain trusted.

### Developer ID signing and notarization

Run this only on a trusted Mac that keeps the Developer ID Application identity in its keychain and a `notarytool` keychain profile, and that never builds or runs submitted code. Start from an image that `package-macos.py` produced and verified; do not rebuild there, and never pass the certificate, its password, an Apple ID, an app-specific password or an API key to a build.

```sh
dmg=zeropw-desktop-vX.Y.Z-aarch64-apple-darwin.dmg
id="Developer ID Application: <name> (<team id>)"
mkdir -p work/root
hdiutil attach -readonly -nobrowse -mountpoint work/mnt "$dmg"
ditto work/mnt/ZeroPW.app work/root/ZeroPW.app
hdiutil detach work/mnt
# inside out: the sidecars, then the bundle (which signs the app executable)
for bin in zeropw-admin zeropw_session zeropw-agent; do
  codesign --force --options runtime --timestamp --sign "$id" "work/root/ZeroPW.app/Contents/MacOS/$bin"
done
codesign --force --options runtime --timestamp --sign "$id" work/root/ZeroPW.app
codesign --verify --deep --strict --verbose=2 work/root/ZeroPW.app
codesign -dvv work/root/ZeroPW.app    # Authority=Developer ID Application, Timestamp=
ln -s /Applications work/root/Applications
hdiutil create -volname ZeroPW -srcfolder work/root -format UDZO -o "signed-$dmg"
codesign --force --timestamp --sign "$id" "signed-$dmg"
xcrun notarytool submit "signed-$dmg" --keychain-profile <profile> --wait
xcrun stapler staple "signed-$dmg"
xcrun stapler validate "signed-$dmg"
spctl -a -vv -t open --context context:primary-signature "signed-$dmg"    # accepted, Notarized Developer ID
```

If notarization fails, read `xcrun notarytool log <submission id> --keychain-profile <profile>`. No entitlements are expected (the web view runs its JIT in Apple's WebContent process); add none without a failing launch that requires it. Then rename the signed image to the release name, write a new `.sha256`, mount it and repeat the `otool`, `codesign --verify --deep --strict` and `spctl -a -vv -t exec` checks (now accepted), and record the identity, the notarization submission ID and the new SHA-256 in the release evidence. The ad hoc and the Developer ID image have different checksums; publish only one.

## v0.1.0 evidence and installation

Product source is main commit `e157422353b5967cf5c7d61deccbbf30feba9b0e`, with the same complete tree as reviewed source `5f741334ac74ebb020fa27cb9ae75e925391f45b`. The release preparation changes formula and documentation only; binary hashes and product source remain bound to this baseline.

At that product source, native macOS ARM64 passed 1,384 Rust tests and four resource probes; native Ubuntu 24.04 ARM64 passed 1,381 Rust tests and four resource probes. Tooling passed 25 tests; the harness passed 80 tests and compilation. Installed archives passed all 47 demo checks on each native host. An empty Linux runtime containing glibc dependencies and no shared OpenSSL also passed all 47 checks. Claude Opus 5.5 completed the final local review with no unresolved findings. These counts do not claim Intel or x86-64 runtime verification.

The release archives statically link an authenticated OpenSSL 3.5.9 SDK. All five binaries on each target passed linkage checks. MIT and target-specific dependency notices are included. The source formula previously passed native macOS installation and all demo checks; the stable formula pins the two release archive SHA-256 values. Publication and public-download checks are recorded separately in the release verification asset.

The tracked-tree and reachable-history scans classified key markers as SSH parser literals and synthetic fixtures. Historical personal paths are development evidence. No GitHub-token or AWS-access-key shape was found by these rules. This is a narrow scan, not a guarantee against every secret format.

On Apple Silicon macOS (tested on macOS 26.5; older versions are unverified):

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
