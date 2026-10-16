# Release preparation

The repository is public. The owner selected Apple Silicon macOS and ARM64 GNU/Linux binary support for v0.1.0 on 2026-10-11. Intel macOS and x86-64 Linux binaries are deferred until native execution is verified.

## v0.2.0 owner decisions

The owner made decisions 1 to 6 on 2026-10-16 in the coordinator session:

1. v0.2.0 is one product release: CLI archives for `aarch64-apple-darwin` and `aarch64-unknown-linux-gnu` plus an ad hoc signed preview desktop `.dmg`, no Developer ID or notarization.
2. This Mac is authorized as the macOS build and verification host.
3. The Homebrew formula stays at 0.1.0 in the v0.2.0 tag, and the formula and the team onboarding files move to 0.2.0 together in a follow-up PR right after publication, with the onboarding validation cases re-run against the published release.
4. Homebrew install, upgrade and test on this Mac are allowed in that follow-up.
5. Desktop gate 3's clean-Mac install and first launch through Gatekeeper is waived for this preview.
6. Of desktop gate 3's remaining checks, the coordinator performs the same-account agent check on this Mac, and the other-account agent check, the observation of how macOS treats the ad hoc signed sidecars after Open Anyway, and quitting the app with its own Quit are waived for this preview.

On 2026-10-15 in the desktop design review the owner asked for the interface text in plain, minimal Korean.

The numbered items above are the owner's decisions; the rest of this section is the release process's reading of them. "This Mac" in decisions 2, 4 and 6 is the owner's Apple Silicon Mac on which the coordinator session runs. Because that Mac holds coordinator authority, it does not meet the build-host rule of desktop gate 3 or the README's rule for builds, so decision 2 is an exception to both, and desktop gate 3 requires the release evidence to record that exception and the account the build ran in. Each archive and the image have their `.sha256` file; "Ad hoc signature and Developer ID" below describes what the image's signature does and does not show. Following the 2026-10-15 instruction, the desktop app's interface is Korean only, an exception to the English default of gate 2; no English interface is part of v0.2.0. The README's known limits for the desktop app list the checks that decisions 5 and 6 waive.

Why the onboarding files move together with the formula (decision 3): the team onboarding manuals (`docs/team-onboarding.*.html`), prompts (`docs/team-agent-prompts.*.txt`), validator guides, schemas and examples (`docs/onboarding-*`), `scripts/validate-onboarding.py` and its tests between them pin the v0.1.0 formula and archive digests and the v0.1.0 version and tag. `docs/onboarding-validation-manifest.json` binds the onboarding cases validated by Claude Opus (`claude-opus-5-5`) to the hashes of these files and of `Formula/zeropw.rb`. They do not pin a tap commit: the manuals and examples leave it as a placeholder that a human fills in after checking the tap. A formula moved alone would be refused by the manuals' install check and would fail the tests that check this binding, and editing only the pinned digests would rewrite the validation evidence; hence the re-run in the follow-up. Until the follow-up, the manuals describe the Homebrew installation of 0.1.0.

The release commit sets 0.2.0 in `rust/Cargo.toml`, the `zeropw` entry of `rust/Cargo.lock` and every desktop version field together ("Packaging", step 3). `scripts/build-release.py` refuses an archive `--version` other than `v` plus the `rust/Cargo.toml` version; the workflows read it with `python3 scripts/build-release.py --print-version`. In the v0.2.0 tag, `README.md`, `README-ko.md` and `GUIDE.md` state version 0.2.0, install it with `scripts/install.sh --version v0.2.0`, and say that Homebrew installs 0.1.0 until the follow-up; `Formula/zeropw.rb` and the onboarding files keep their v0.1.0 pins. Because the formula changes only in the follow-up, the gate 4 test of the formula against the release can run only there. Review the remaining matches of `git grep -n '0\.1\.0'` before tagging; historical records keep their v0.1.0 references. Build the CLI archives and the image with one Rust toolchain and record its release and commit in the release evidence; the notices name it (during preparation on 2026-10-16 both hosts had rustc 1.98.1, commit `48a229ceaefd4985c50990b14116b6d856af0985`).

Against the gates below, decision 2 is an exception to the build-host rule of desktop gate 3, decision 3 moves gate 4's test of the formula against the release to the follow-up, decision 5 waives desktop gate 3's install and first launch on a clean Mac, and decision 6 has the same-account agent check of desktop gate 3 performed on that Mac and waives the other three desktop gate 3 checks it names. Nothing else in the gates is replaced.

## v0.2.0 changes since v0.1.0

- Desktop app preview. `zeropw-desktop-v0.2.0-aarch64-apple-darwin.dmg` holds the administrator app of `desktop/` ([desktop app specification](desktop-app.md), in Korean) as an ad hoc signed Apple Silicon image with a Korean-only interface; its notices are a separate asset. The app bundles `zeropw-admin`, `zeropw_session` and `zeropw-agent` built from `rust/` at the release commit.
- One-day team invite links. `team invite --link` also prints a `zeropw://join#…` link, its `invite_id` and `expires_at`, with the lifetime fixed at 24 hours. `team invites` lists this device's invitations without secrets, `team revoke-invite` blocks an unused one, and `team invite-info --stdin` previews an invitation or link offline. `team join` accepts a link, reads the invitation from standard input with `--stdin`, and refuses an invitation more than five minutes past its expiry before it connects. Every invitation address must be `HOST:PORT` when an invitation is created, previewed or used ([team synchronization](team-sync.md)). ZeroPW 0.1.0 cannot read these links.
- `zeropw-admin status`, a read-only command that prints `stopped`, `restore_pending` and `incident_open`, and the global options `--input-envelope` and `--require-admin`, with which the desktop app passes passphrases, values and invitations on standard input and has the administrator passphrase checked before a command runs. `--help` lists none of the three.
- Each CLI archive's `THIRD_PARTY_LICENSES.md` also covers the statically linked Rust standard library.
- `scripts/build-release.py` runs every build step with an allowlisted environment, remaps source paths, refuses binaries that contain a local path, accepts on macOS only libraries under `/usr/lib` and `/System/Library`, builds named binaries without an archive (`--bin`), and requires the archive version to match `rust/Cargo.toml` (`--print-version` prints it).
- The teammate onboarding manuals in English and Korean (`docs/team-onboarding.*.html`), the agent verification prompts (`docs/team-agent-prompts.*.txt`), the onboarding validator `scripts/validate-onboarding.py` with its guides, schemas, examples and validation manifest, and `scripts/observe-onboarding-brew.py` are new in this tag. They describe the Homebrew installation of 0.1.0 until the follow-up of decision 3.

## Gates

1. Run the complete Rust verification matrix on Linux and macOS at the release commit. Include real SSH, separate-process CLI, three-node team synchronization, incident response, revocation, recovery, and signer resource probes. Preserve skips and failures explicitly.
2. Review current source and Git history for private information. English is the default for maintained documentation and product output; `README-ko.md` retains Korean. Exception by owner instruction (2026-10-15, desktop design review; see "v0.2.0 owner decisions"): the desktop app's interface is Korean only, including the description macOS shows in the Local Network permission prompt; the README lists this as a known limit. The desktop specification (`docs/desktop-app.md`) and design rules (`DESIGN.md`) are also written only in Korean; that is a recorded departure from the default, not covered by a separate decision. Preserve fixed interoperability fixtures instead of silently rewriting their bytes.
3. Build the five binaries natively for both release targets of v0.1.0 and v0.2.0: Apple Silicon macOS and ARM64 Linux. Install from the produced archive into a fresh prefix and run the installed demo and CLI checks on disposable runners.
4. Check archive SHA-256 values, reject unsafe archive entries, include the selected license, and test the Homebrew formula against the exact release.
5. Obtain the required review for the exact commit; keep release artifacts tied to that commit. Do not reuse an earlier PASS.

## Packaging tools

`python3 scripts/package-release.py --version vX.Y.Z --target TARGET --bin-dir DIR --out-dir DIR --third-party-licenses NOTICES_FILE` creates a flat binary archive and its checksum. Generate the target notices first with `python3 scripts/dependency-licenses.py --target TARGET --output NOTICES_FILE`. The license is MIT. The builder recognizes four targets; v0.1.0 publishes only `aarch64-apple-darwin` and `aarch64-unknown-linux-gnu`, and v0.2.0 the same two. Recognition by the tooling is not a support claim.

Every release binary links the Rust standard library statically, so `dependency-licenses.py` ends the notices with a "Rust standard library (rustc X.Y.Z, commit)" section taken from the toolchain that builds the release: `share/doc/rust/COPYRIGHT-library.html`, `COPYRIGHT.html` and `licenses/` of its sysroot. The builder therefore needs a rustup-installed toolchain with the release target's standard library. The file records the SHA-256 of the `Cargo.lock` it read and is written only when every notice is found; otherwise nothing is written. The CLI archives' `THIRD_PARTY_LICENSES.md` includes that section.

`python3 scripts/build-release.py --target TARGET --out-dir DIR --bin NAME [--bin NAME ...]` builds only the named release binaries in the same way (pinned static OpenSSL, `--features bundled-openssl`, linkage and local-path checks, `DIR/THIRD_PARTY_LICENSES.md`) and copies them to `DIR/bin` without creating an archive. The desktop app builds its sidecars this way. In both modes `DIR` must be new, empty or created by an earlier run (it then holds `DIR/.zeropw-build-release`); anything else is refused before a file is touched.

What the builder's steps see and what its binaries contain:

- Every step sees only `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `TMPDIR`, `LANG`, `LC_*`, `TERM`, `CARGO_HOME`, `RUSTUP_HOME`, `RUSTUP_TOOLCHAIN`, `DEVELOPER_DIR` and `MACOSX_DEPLOYMENT_TARGET` (which must look like a macOS version), plus what the builder sets itself. Credentials and toolchain overrides such as `RUSTFLAGS`, `CC` or `OPENSSL_DIR` are dropped.
- Rust and C source paths are remapped: the checkout to `/zeropw`, `DIR` to `/build`, `CARGO_HOME` to `/cargo` and `RUSTUP_HOME` to `/rustup` (`--remap-path-prefix`, `-ffile-prefix-map`; the C flags skip a path that contains whitespace, which the path check below still catches).
- OpenSSL is configured with the prefix `/nonexistent/zeropw-openssl` and installed under `DIR` with `DESTDIR`, so its compiled-in `ENGINESDIR` and `MODULESDIR` name no host path; nothing is installed at that prefix.
- A binary that contains the home directory, the checkout, `DIR`, `CARGO_HOME`, `RUSTUP_HOME`, `/Volumes/` or any account home (`/Users/`, `/home/`) is refused. `HOME` must be an absolute path: without it cargo and rustup would use the account home unseen by this check, so the builder refuses to start.
- No binary may link libssl, libcrypto or a Homebrew library; on macOS only libraries under `/usr/lib` and `/System/Library` may be linked.
- Builds are not bit-for-bit reproducible: two runs can produce binaries with different hashes, so record the hashes of what is actually shipped.

`scripts/install.sh --version vX.Y.Z` downloads the matching archive and its matching `.tar.gz.sha256` asset from GitHub Releases. Before publication, use `--archive FILE --sha256 HEX` with a verified local archive. The default prefix is `$HOME/.local`; `--prefix /absolute/path` overrides it. Existing binaries are preserved unless `--force` is supplied.

The installer does not use sudo, initialize a vault, start a service, modify shell profiles, or execute downloaded binaries. Checksums detect corruption but are not an independent signature: the release host and publisher remain trusted. Updates replace five staged binaries individually; this is not an atomic transaction across the entire installation. Stop running processes before an upgrade.

## Desktop app (macOS .dmg)

The desktop app (docs/desktop-app.md) can be packaged as an Apple Silicon disk image without any signing credential; packaging is not publishing. v0.2.0 is the first release with a desktop image: by owner decision 1 (2026-10-16) it is an ad hoc signed preview without Developer ID signing or notarization ("Ad hoc signature and Developer ID" below). The image's version, the `rust/Cargo.toml` version and the release tag must be the same `vX.Y.Z`; pass the tag to the packager with `--tag`. Never attach a desktop image to an existing release such as v0.1.0; its evidence is bound to its own commit and its archives contain different product source.

### Gates

The five gates above apply to the desktop image:

1. Run the complete Rust matrix and `desktop/verify.sh` on Linux and macOS at the release commit. The bundled `zeropw-admin`, `zeropw_session` and `zeropw-agent` are built from `rust/` at that commit, not taken from an earlier CLI release.
2. Review current source and history for private information, including `desktop/`. The interface is Korean only, by the owner's exception to gate 2.
3. Package natively on an Apple Silicon Mac with the command below, then check the published image as a user receives it (the packaging script does not run the app).
   - Build host. Packaging runs third-party build code: Cargo build scripts and procedural macros, the npm packages Vite runs, and the OpenSSL build. Like any build of this repository (README), it belongs on a host without vault, gateway, signer, coordinator, signing, notarization or repository and release-publishing credentials, for example a separate macOS account or VM in which `gh` is not logged in. The packager only limits which environment variables the build sees; it does not keep build code away from the files, keychain or logged-in tools of the account it runs in. For v0.2.0 the owner authorized the coordinator's Mac as the build and verification host (decision 2) although it does not meet this rule; record that exception, and the account the build ran in, in the release evidence.
   - Install and first launch. On a clean Apple Silicon Mac or a clean macOS virtual machine that has never run ZeroPW (a fresh account on a machine that has run it is not enough: Gatekeeper and launch state can be machine wide). Download the published image in a browser, verify its checksum, drag ZeroPW to Applications, eject the image, and open it from Applications with the Gatekeeper steps below. Create a throwaway vault and start the relay. Waived for v0.2.0 (decision 5).
   - Agent in the same account. Create an agent that runs in this account and run the suggested `/Applications/ZeroPW.app/Contents/MacOS/zeropw-agent list-connections` in the app's terminal. For v0.2.0 the coordinator performs this check on the build Mac (decision 6); record how it ran in the release evidence.
   - Agent as another account. Create an agent for another, standard macOS account. In the app's terminal run both suggested commands: `sudo --preserve-env=ZEROPW_GATEWAY_URL,ZEROPW_CALLER_TOKEN,no_proxy -u <account> -i`, then the same `zeropw-agent list-connections` path. It must run as that account from `/Applications` and reach the relay. Waived for v0.2.0 (decision 6).
   - In both accounts, record whether macOS blocks or prompts for the ad hoc signed sidecars after Open Anyway, for example with `log stream --predicate 'subsystem == "com.apple.syspolicy"'` running during the checks. Waived for v0.2.0 (decision 6).
   - Quit. Quit the app with its own Quit (Cmd+Q) and confirm that its `zeropw-admin serve` sidecar has stopped. Waived for v0.2.0 (decision 6).
4. Keep the `.dmg.sha256` beside the image. The image contains the MIT `LICENSE` and the desktop `THIRD_PARTY_LICENSES.md`; publish the same notices as a separate asset.
5. Obtain the required review for the exact commit and bind the image's SHA-256 to it. Do not reuse an earlier PASS.

### Packaging

```sh
env -i HOME="$HOME" PATH="$PATH" python3 desktop/scripts/package-macos.py \
  --work-dir /path/outside/the/checkout/work --out-dir /path/outside/the/checkout/out --tag vX.Y.Z
```

It needs Apple Silicon macOS with the Xcode command line tools, a rustup-installed Rust toolchain with the `aarch64-apple-darwin` standard library, Node.js and npm, Perl and make (for OpenSSL), and network access for crates, npm packages and the OpenSSL source. Start it with `env -i` as above: a normal login session sets variables it refuses, such as `SSH_AUTH_SOCK`. `HOME` must be an absolute path (without it cargo and rustup would use the account home unseen by the path check), and `--tag` is required and must be `v` plus the release version. `PATH` must still reach `python3`, `cargo`, `node` and `npm`. `--work-dir`, `--out-dir` and `CARGO_TARGET_DIR` must be outside the checkout, or the script refuses to start. `CARGO_TARGET_DIR` is honored when set; the default is `<work-dir>/target`. The work directory must be new, empty or created by an earlier run (it then holds `.zeropw-package-macos`); anything else is refused before a file is touched. The script:

1. refuses to start while a variable is set whose name starts with `ZEROPW_` or contains `TOKEN`, `SECRET`, `PASSW`, `PASSPHRASE`, `_KEY`, `AUTH`, `CSC_`, `P12` or `APPLE_` in any case, or another signing, notarization or updater name (`TAURI_SIGNING_*`, `APP_STORE_CONNECT_*`, names containing `NOTARY`, `CODESIGN`, `KEYCHAIN` or `CERTIFICATE`, and others). The message names the variables, never their values. Every build step (npm, the sidecar build, Vite, Cargo build scripts and the Tauri bundler) then sees only the variables `scripts/build-release.py` allows ("Packaging tools" above) plus `CI=true`, `MACOSX_DEPLOYMENT_TARGET=11.0`, `CARGO_TARGET_DIR` and the path-remapping `CARGO_ENCODED_RUSTFLAGS` and `CFLAGS`. Toolchain overrides such as `RUSTFLAGS`, `CC` and `OPENSSL_DIR` are dropped. Tauri reads signing and notarization credentials from the environment of the whole build, which runs third-party code; credentials never belong there;
2. requires a clean tracked tree and builds a copy of the committed `HEAD` in the work directory, so nothing is written into the checkout;
3. requires `rust/Cargo.toml` (`[package]` version), the `zeropw` entry of `rust/Cargo.lock` and every desktop version field to agree on one `MAJOR.MINOR.PATCH`: `tauri.conf.json`, `package.json`, both versions in `package-lock.json`, `src-tauri/Cargo.toml`, `core/Cargo.toml`, the two workspace entries in `desktop/Cargo.lock`, and `tauri.bundle.conf.json` if it sets one. They give the release version `vX.Y.Z`; bump them together. With `--tag`, any other tag is refused. The sidecars print no product version; they are built from `rust/` at the same commit;
4. runs `npm ci --ignore-scripts`, then `desktop/scripts/prepare-sidecars.sh`, which builds the three sidecars with `scripts/build-release.py --bin` (pinned static OpenSSL 3.5.9, `--features bundled-openssl`, linkage and local-path checks) and writes the notices, then `tauri build --config src-tauri/tauri.bundle.conf.json --bundles app,dmg` with `CI=true`, which skips the Finder window layout step. Rust and C source paths are remapped: the checkout copy to `/zeropw`, the work directory to `/build`, `CARGO_TARGET_DIR` to `/target`, `CARGO_HOME` to `/cargo`, `RUSTUP_HOME` to `/rustup` and the checkout to `/checkout`. Before the Tauri build each `src-tauri/binaries/<name>-aarch64-apple-darwin` must be byte-identical to the binary `build-release.py` produced, and it must be unchanged afterwards; the log records the SHA-256 of the three sidecars and of the app executable as linked, before signing;
5. verifies the image before anything reaches the output directory:
   - `hdiutil verify` passes;
   - mounted read-only, the image has an `Applications` link; the app, the three sidecars, `LICENSE` and `THIRD_PARTY_LICENSES.md` are present, and `LICENSE` and `THIRD_PARTY_LICENSES.md` are byte-identical to their sources;
   - each of the four executables, with its signature removed (`codesign --remove-signature` on copies), is byte-identical to the built binary with its signature removed, except for the `__LINKEDIT` segment's vmsize field, which codesign enlarges for its signature, and has the same `LC_UUID`. The signed files themselves cannot be compared byte for byte, because Tauri signs them;
   - `otool -L` lists only libraries under `/usr/lib` and `/System/Library`, and no libssl or libcrypto, for each executable;
   - each executable is arm64 with minimum macOS 11.0, ad hoc signed with the hardened runtime and without entitlements, and contains none of the home directory, the work directory, the checkout, `CARGO_TARGET_DIR`, `CARGO_HOME`, `RUSTUP_HOME`, `/Volumes/` or any account home (`/Users/`, `/home/`);
   - every file under `Contents/MacOS` and `Contents/Resources` is readable by every account;
   - the bundle has no entitlements, has sealed resources and passes `codesign --verify --deep --strict`;
   - `Info.plist` has the version, `LSMinimumSystemVersion` 11.0 and `NSLocalNetworkUsageDescription`;
   - the image detaches; a failed detach, even with `-force`, fails the run.

   `spctl -a -vv` is recorded and is expected to reject an ad hoc signed app; that is not a packaging failure;
6. only then copies the artifacts into the output directory.

Artifacts. The script refuses to start if one of them already exists in the output directory, and creates each one exclusively (`O_EXCL`) when it copies it; if one appears during the run, it removes the files it created and publishes nothing.

| File | Contents |
| --- | --- |
| `zeropw-desktop-vX.Y.Z-aarch64-apple-darwin.dmg` | `ZeroPW.app` and an `Applications` link |
| `zeropw-desktop-vX.Y.Z-aarch64-apple-darwin.dmg.sha256` | `<hex>  <name>`, the same format as the CLI archives |
| `zeropw-desktop-vX.Y.Z-aarch64-apple-darwin-THIRD_PARTY_LICENSES.md` | the notices shipped in `Contents/Resources` |
| `zeropw-desktop-vX.Y.Z-aarch64-apple-darwin-verification.txt` | source commit, product version, release tag, checksums, the SHA-256 of the four executables before signing, and every verification command with its output; packaging evidence, not a release asset |

`ZeroPW.app/Contents/MacOS` holds `zeropw-desktop`, `zeropw-admin`, `zeropw_session` and `zeropw-agent`; `Contents/Resources` holds `LICENSE` and `THIRD_PARTY_LICENSES.md`. The image is arm64 only; Intel Macs are not supported. `Info.plist` declares macOS 11.0 as the minimum, but only the macOS versions actually tested may be stated as supported.

The notices cover five parts: the Rust crates of the app executable for `aarch64-apple-darwin`; the sidecars' crates with the statically linked OpenSSL; the Rust standard library linked into all four executables, included once; the npm packages bundled into the web interface, including the Pretendard and JetBrains Mono fonts (OFL-1.1) and Pretendard's upstream notice, which names the fonts it is built from with their copyright and Reserved Font Name statements; and build-tool code emitted into the bundle (Rolldown's runtime helper, and the module-preload polyfill that came from es-module-shims through Vite). `desktop/licenses/supplement.json` holds the reviewed entries for each exact version: crates that publish no notice file get the upstream copyright lines, checked against the repository's license files at the published commit, and a `source`; npm entries list every notice file of each OFL font and pin the Rolldown and Vite versions whose code is emitted. `desktop/scripts/third-party-licenses.py` refuses sidecar notices that are incomplete, collected from another `rust/Cargo.lock`, or collected with another Rust toolchain or target. The file ends with source locations for the MPL-2.0 components. Like the CLI notices, this is an inventory, not a legal review.

Upgrading Vite, Rolldown or a font, updating a crate the supplement covers, or a Rust toolchain whose standard library adds a crate makes notice collection fail until the entry is reviewed again (`desktop/licenses/supplement.json`; for the standard library, `STD_IN_TREE` and `STD_NOT_LINKED` in `scripts/dependency-licenses.py`). For a build tool, build once with `npx vite build --sourcemap` and check which emitted code has no source.

### Ad hoc signature and Developer ID

The release config signs with the ad hoc identity `"-"`: Tauri signs each sidecar, then the bundle, with the hardened runtime. The whole bundle is sealed, so `codesign --verify --deep --strict` detects modified or added files, but an ad hoc signature names no publisher, is not notarized and cannot be revoked. Gatekeeper rejects it, and users have to override that decision once.

A Developer ID signature with notarization names the publisher, passes Apple's malware check, can be revoked and opens without the override. It requires a paid Apple Developer Program membership and is the recommended way to distribute an app that holds credentials. It is a separate procedure on a trusted Mac, never part of the build.

For v0.2.0 the owner decided on 2026-10-16 to ship the desktop app as an ad hoc signed preview without Developer ID signing or notarization, departing from that recommendation. Users therefore have to override Gatekeeper, and nothing in the signature tells them who built the image; the checksum beside it comes from the same release host. Release notes must call the image a preview and say this.

### What users see on macOS 15 and later

A browser download is quarantined. Opening the ad hoc signed app shows that Apple could not verify that ZeroPW is free of malware, with Done and Move to Trash; Control-click › Open no longer bypasses this since macOS 15. To install and open it:

1. Open the downloaded `.dmg`, drag ZeroPW onto the Applications link, and eject the image. Open the app only from Applications. Opened straight from the image, a quarantined app can be run by macOS from a randomized temporary location (App Translocation), and the agent command the app suggests is built from the app's own location, so it could point where another account cannot run it.
2. Open ZeroPW from Applications once and close the dialog with Done.
3. Open System Settings › Privacy & Security, scroll to Security, and click Open Anyway next to the message about ZeroPW. The button is offered for about an hour after the attempt; if it is gone, repeat step 2.
4. Confirm with the login password, then choose Open.

Release notes must say that the app is a preview, is not notarized and has a Korean-only interface, and must show these steps. Do not tell users to remove the quarantine attribute (`xattr -cr`) or to turn Gatekeeper off (`spctl --master-disable`). Whether macOS assesses the ad hoc signed sidecars again when the approved app starts them, or when another account runs `zeropw-agent` from the installed app, is not verified: desktop gate 3 includes that observation, and for v0.2.0 the owner waived it (decision 6). Sources: Apple's Mac User Guide, "Open a Mac app from an unknown developer", and Apple Developer News, 2024-08-06.

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
# hdiutil chooses the mount point (a custom -mountpoint is refused on some volumes); read it from the plist
mnt=$(hdiutil attach -readonly -nobrowse -noautoopen -plist "$dmg" | python3 -I -c 'import plistlib, sys; print(*[e["mount-point"] for e in plistlib.loads(sys.stdin.buffer.read())["system-entities"] if "mount-point" in e], sep="\n")')
ditto "$mnt/ZeroPW.app" work/root/ZeroPW.app
hdiutil detach "$mnt"
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

Binary archives must be built with `python3 scripts/build-release.py --target TARGET --version vX.Y.Z --out-dir dist` on a matching native host; `--version` must be `v` followed by the `[package]` version of `rust/Cargo.toml`, and `dist` must be new, empty or created by an earlier run ("Packaging tools"). The builder verifies the pinned OpenSSL 3.5.9 source SHA-256, builds a static SDK with system certificate paths, and includes its notices. `bundled-openssl` alone does not select an unpatched source crate: the build gate requires the release SDK and static libraries. Homebrew source installation uses its declared OpenSSL dependency. Bundled archives must not link to Homebrew or system OpenSSL. GNU/Linux archives require a compatible glibc runtime (build baseline Ubuntu 24.04); they are not musl binaries. Packaging normalizes tar and gzip metadata so identical files produce identical archive bytes on the same packaging runtime.

The pinned source is from the [official OpenSSL release](https://github.com/openssl/openssl/releases/tag/openssl-3.5.9). Check [OpenSSL advisories](https://openssl-library.org/news/vulnerabilities-3.5/) when updating the pin. The earlier 3.6.3 vendor experiment is not a release artifact.
