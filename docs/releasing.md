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

## v0.2.0 evidence and installation

The v0.2.0 tag names the commit that adds this section. Its parent, `3654a211cf5bf3ec7397cc7184ffd82f3ca87067` ("docs(release): v0.2.0 documentation corrections"), is the product source: all three binary assets were built from it with a clean tracked tree. It follows `1a4eba3b16f1b92769f34a501cf04597f994da42` ("docs(release): v0.2.0 user documentation") and the version bump `b55cdb2194890ca1640696f574bfa466a5ee753f` ("chore(release): version 0.2.0"), which sets 0.2.0 in `rust/Cargo.toml`, the `zeropw` entry of `rust/Cargo.lock` and every desktop version field on top of main `9fe630da3955c745f28d846f8f6a4d473ba909c9`. The two documentation commits change only `README.md`, `README-ko.md`, `GUIDE.md`, `docs/desktop-app.md` and `docs/releasing.md`. The commit that adds this section changes only `docs/releasing.md`: `README.md`, `README-ko.md`, `GUIDE.md` and `LICENSE` stay byte-identical to `3654a21`, and so do the `README.md` and `LICENSE` in both archives. Two earlier candidates were built from `b55cdb2` (the first) and from `1a4eba3` (the second). They were superseded because the documentation, including the README inside the archives, changed afterwards, and their assets are not published.

Gates 1 and 2, gates 3 and 4 for the two archives and the image, and the checks below cover `3654a21`; the Rust and desktop matrices of gate 1 do so by carry-over from `b55cdb2`. Of desktop gate 3, a same-account agent check was performed with the bundled `zeropw-agent` in the environment the app's terminal gives an agent, outside the app's interface and terminal and from a copy of the app rather than `/Applications` (details below); the other checks were waived (decisions 5 and 6). Gate 4's test of the Homebrew formula belongs to the follow-up of decision 3.

Gate 1. `rust/verify.sh` and `desktop/verify.sh` ran at `b55cdb2` on both hosts on 2026-10-16 and were not run again. They carry over by tree identity: `git diff --quiet b55cdb2 3654a21 -- rust desktop` exits 0, `git diff --stat` for those paths prints nothing, and the `rust` tree (`967f43facf5d48c9b049c393c38397b2f42786e3`) and the `desktop` tree (`977cbbbb4a21e94bad06b657a9697dab20535d43`) are the same objects in `b55cdb2`, `1a4eba3` and `3654a21`, as are `scripts`, `tests`, `harness`, `Formula` and `.github`. Of the five files that change between those commits, only `docs/desktop-app.md` is read by a gate 1 check: the static check of `desktop/verify.sh` (`npm run check`) requires it to state the app's content security policy, so `npm run check` ran again at `3654a21`.

- Linux, at `b55cdb2`, on native Ubuntu 24.04.4 ARM64 (an isolated Lima VM with kernel 6.8.0-146 and glibc 2.39, under an unprivileged account): `rust/verify.sh` passed all 95 steps with 1,418 tests (547 library and binary tests, 871 in 90 integration targets, no doc tests) and the four signer resource probes. The matrix includes real OpenSSH against `sshd` (`signer_e2e`, 6 tests, which fail rather than skip without `sshd`), separate-process CLI (`native_cli_e2e`, 5), team synchronization (`native_team_e2e`, 3; `native_team_cli`, 14), incident response (`response`, 27; `native_response_cli`, 13) and `runs` (21). `desktop/verify.sh` passed all eight steps.
- macOS, at `b55cdb2`, on macOS 26.5 (build 25F71, Apple Silicon): `rust/verify.sh` passed all 95 steps with 1,421 tests and the four probes. It ran under `env -i` with an empty `HOME` and Homebrew OpenSSL 3 for the verification build (`OPENSSL_DIR`); the release builds below use the pinned static SDK. `desktop/verify.sh` passed all eight steps.
- On both hosts `desktop/verify.sh` ran static checks of 60 web source files and of 63 Tauri commands in 127 files, 199 front-end tests in 10 files and 129 desktop Rust tests with ignored tests included. Both scripts ended with an empty `VERIFY_FAILED=` on both hosts. The only ignored tests in the Rust matrix are the four probes, which the probe step ran; no test failed or was skipped.
- At `3654a21`, in the Linux VM: the 122 tooling tests (`python3 -m unittest discover -s tests`), the 80 harness tests, `python3 -m compileall -q harness scripts tests desktop/scripts`, and `npm ci --ignore-scripts` followed by `npm run check` in `desktop/` (60 files; 63 commands in 127 files) passed. On macOS the 122 tooling tests passed. At the commit that adds this section the 122 tooling tests passed again in the VM.

Toolchain. Both hosts tested and built with rustc 1.98.1 (commit `48a229ceaefd4985c50990b14116b6d856af0985`; LLVM 22.1.8 on macOS) and cargo 1.98.1, and the notices name that toolchain. The Linux VM had Python 3.12.3, Node.js 22.20.0, npm 10.9.3, glibc 2.39 and binutils 2.42. macOS had cargo 1.98.1 (797e8a9bc 2026-08-05), Python 3.12.14 (a plain `python3` is the system Python 3.9.6), Node.js 26.11.1 and npm 11.20.0.

Gate 2. The scans ran in the Linux VM on a clone of `3654a21`. The scanner exits 1 whenever it reports findings; every finding was classified without printing matched values. The tracked-tree scan (510 files) reported 8 findings in 7 files: private-key markers in 6 files and personal paths in 2 files (3 occurrences); `tests/test_publication_audit.py` has both. The scan of history reachable from `3654a21` (2,236 blobs) reported 39 findings in 38 blobs: 22 personal-path and 17 private-key-marker findings. Neither found a GitHub-token or AWS-access-key shape. Private-key markers are SSH parser format literals (`rust/src/sshwire.rs`, `desktop/core/src/sshkey.rs` and, in history, the removed prototype's `zeropw/sshwire.py`), synthetic test literals (`rust/tests/sshwire.rs`, `desktop/core/tests/core_fake_admin.rs`, `tests/test_publication_audit.py` and, in history, `tests/test_sshwire.py`) and one fixed synthetic interoperability fixture (`rust/tests/fixtures/python/sshwire/from-python.key`), which is preserved under the fixture rule. The personal paths in the current tree are three synthetic account homes in `tests/test_desktop_package.py` and `tests/test_publication_audit.py`; checked on the Mac and in the VM, none is a local account. The owner's macOS account home appears only in history (42 occurrences in 20 blobs: 15 old review records, two Rust test files and three fixture `GENERATE.md` files), none of them in the current tree; that is historical development evidence. The findings are the same as for the second candidate, and the five blobs new in `3654a21` have none. Scanning the remote-tracking refs and tags as of the last fetch as well (21 refs, 608 commits, 2,359 blobs) gave the same 39 findings. The `docs/releasing.md` of the commit that adds this section matches none of the scanner's rules. This is a narrow scan, not a guarantee against every secret format.

Gate 3, Linux. In a fresh clone of `3654a21` in the VM with `HOME` set, `python3 scripts/build-release.py --target aarch64-unknown-linux-gnu --version v0.2.0 --out-dir DIR` exited 0, and the clone had no changed files afterwards. With no `HOME`, `scripts/install.sh --archive FILE --sha256 HEX` installed the archive into a fresh prefix (exit 0). The installed files matched the archive entries, `zeropw-agent --help` and `zeropw-admin --help` exited 0, and the installed demo passed all 47 checks (`INSTALLED_ARCHIVE_VERIFICATION_PASS`). The demo left the SSH signer's empty mode-0700 socket folder (`zpws-*`) in its `TMPDIR`. `ldd` lists only `linux-vdso`, `libgcc_s`, `libm` (not in `zeropw_session`), `libc` and the dynamic loader. String and raw-byte searches for `/home/`, `/Users/` and `/Volumes/` found none in any binary. `zeropw-admin` and `zeropw-demo` need GLIBC_2.39 (`pidfd_spawnp` and `pidfd_getpid`; `__isoc23_strtol` needs 2.38), while `zeropw-agent`, `zeropw_session` and `zeropw-democli` need at most GLIBC_2.34; no version need is weak. The Linux archive therefore needs glibc 2.39 or later (Ubuntu 24.04 or later), as the README says.

Gate 3, macOS. In a detached worktree of `3654a21`, with an empty `HOME` on an external volume and a build environment that held only `CARGO_HOME`, `HOME`, `PATH` and `RUSTUP_HOME`, `scripts/build-release.py --target aarch64-apple-darwin --version v0.2.0` and then `desktop/scripts/package-macos.py --tag v0.2.0` exited 0; the worktree had no tracked changes before or after either build. With no `HOME`, `scripts/install.sh --archive FILE --sha256 HEX` installed the archive into a fresh prefix (exit 0). The installed files matched the archive entries, both help commands exited 0, and the installed demo passed all 47 checks (`INSTALLED_ARCHIVE_VERIFICATION_PASS`). `otool -L` lists only `/usr/lib` and `/System/Library` for each of the five binaries, which are arm64 with minimum macOS 11.0 and SDK 26.5. String and raw-byte searches for 11 build-host path patterns (account homes, `/Volumes/`, Homebrew prefixes, temporary folders, the build home, the release folder, the worktree folder and the external volume's name) found none in any binary.

On both targets the release builds link the authenticated OpenSSL 3.5.9 SDK statically, all five binaries passed the builder's linkage and local-path checks, and nothing links libssl or libcrypto.

Desktop image. `package-macos.py` ran without signing or notarization variables (Tauri skipped notarization). Its verification file names source commit `3654a21` and release tag v0.2.0 and ends `RESULT: PASS`; its `spctl -a -vv -t exec` check rejected the ad hoc signed app (exit 3), as expected. Mounted read-only, the image (UDZO) holds `ZeroPW.app`, the `Applications` link and the volume icon. `Info.plist` has version 0.2.0, `LSMinimumSystemVersion` 11.0 and `NSLocalNetworkUsageDescription`. The app is ad hoc signed with the hardened runtime, without entitlements and with sealed resources (6 files), and passes `codesign --verify --deep --strict`. Its four executables are arm64 with minimum macOS 11.0 and SDK 26.5, link only system libraries and contain no build-host path. Its `LICENSE` is byte-identical to the commit's, and its `THIRD_PARTY_LICENSES.md` to the desktop notices asset. The packager's verification file records the bundled `zeropw_session` before signing with the same SHA-256 as the macOS CLI archive's; `zeropw-admin` and `zeropw-agent` are separate builds of the same source. The volume root and the 16 entries below it carry the build host's `com.apple.provenance` extended attribute; it was not removed.

Same-account agent check (decision 6). It was performed in the coordinator session on the build Mac, against a copy of the app rather than an installation in `/Applications`: `ditto` copied `ZeroPW.app` from the mounted image into a folder on the external volume, where all nine files were byte-identical to the image's, had no quarantine attribute and passed `codesign --verify --deep --strict`. Nothing was copied into `/Applications`.

- Setup. With a fresh `HOME`, the copy's `zeropw-admin --input-envelope init` created a throwaway vault in the app's data folder under that `HOME` from synthetic passphrases on standard input. The copy's `zeropw-desktop`, started under `env -i` with `HOME`, `USER`, `LOGNAME`, `SHELL`, `TMPDIR` and the system `PATH`, started its `zeropw-admin serve` sidecar on `127.0.0.1:47380` in its own process group, and `/healthz` answered `200 OK`.
- Agent. The copy's `zeropw-admin --state-dir=STATE --input-envelope principal create --id rc3-same-account --runtime default` with `{}` on standard input, the call the app makes to create an agent, exited 0 and returned a caller token. The token stayed in memory; it was never printed, written or passed as an argument. The copy's `Contents/MacOS/zeropw-agent list-connections` then ran as a child process with the environment the app's terminal gives an agent (`build_env` in `desktop/core/src/terminal.rs`: the bundle's `MacOS` folder first on `PATH`, `ZEROPW_GATEWAY_URL=http://127.0.0.1:47380`, `ZEROPW_CALLER_TOKEN`, `no_proxy` and `NO_PROXY`). The agent was not created through the app's interface, and the command was not typed into the app's terminal. With the issued token it exited 0 and printed `{"connections": []}`; with a wrong token of the same form it exited 1 with `{"error": "AuthFailed", "reason": "caller_token_invalid", "status": 401}`. The audit log recorded `init`, `principal_create`, `tools_list_connections` for that agent and `auth_failed` (`caller_token_invalid`).
- Stop. The app was stopped with SIGTERM (wait status 143), not with its own Quit, whose check decision 6 waives. The sidecar was reparented to process 1 and kept serving until it got its own SIGTERM, as with the earlier candidates; afterwards nothing listened on the port and no process from the copy or the image remained.
- Account home. Although `HOME` pointed at the fresh folder, WebKit wrote its cache and website data under the account's own `~/Library` (`Caches/ai.telicity.zeropw/WebKit` and `WebKit/ai.telicity.zeropw/WebsiteData`). No `Application Support/ZeroPW` folder or vault was created there, and `/Applications/ZeroPW.app` did not exist before or after.
- Quarantine. Another copy, given a `com.apple.quarantine` attribute on all 14 entries with `xattr -w` (it was not downloaded), passed `codesign --verify --deep --strict`. `spctl -a -vv -t exec` rejected it (exit 3), and `syspolicy_check distribution` reported "Adhoc Signed App" (warning) and "Notary Ticket Missing" (fatal) with exit 70. That copy was not opened through Gatekeeper.

Waived checks. For this preview the owner waived the install and first launch through Gatekeeper on a clean Apple Silicon Mac or clean macOS virtual machine (decision 5), and the agent check as another account, the observation of how macOS treats the ad hoc signed sidecars after Open Anyway, and quitting the app with its own Quit (decision 6). None of these was done, so the steps in "What users see on macOS 15 and later" were not tried with this image on any Mac.

Build and verification hosts. The macOS CLI archive and the desktop image were built and verified on the owner's Apple Silicon Mac (macOS 26.5, build 25F71), in the owner's own login account (uid 501), which is also the coordinator's account. That Mac holds coordinator authority and does not meet the build-host rule of desktop gate 3 or the README's rule for builds; decision 2 is the exception. The builds ran under `env -i` with an empty `HOME`, which limits what build code sees in its environment but does not keep it away from the account's files, keychain or logged-in tools. The Linux archive was built and verified in the isolated Lima VM under its unprivileged account. No other host was used.

Notices. Each archive's `THIRD_PARTY_LICENSES.md` records the `rust/Cargo.lock` SHA-256 of the product source, `fb0dbbf2a2b25c111a419f3b2102d51d2859a1745e28afca9b8d59339340d840`, and contains exactly one "Rust standard library (rustc 1.98.1, 48a229ceaefd4985c50990b14116b6d856af0985)" section and the "OpenSSL 3.5.9 (statically linked release SDK)" section (116 level-2 headings on Linux, 129 on macOS). The license is MIT. The desktop notices asset is byte-identical to `Contents/Resources/THIRD_PARTY_LICENSES.md` in the image; it records the SHA-256 of `desktop/Cargo.lock` (`8e2001dd9ab8bca2b977e017aad82c36409567e2813d15b7e64a40f81e115f7a`) and of `rust/Cargo.lock` and contains one Rust standard library section and one OpenSSL 3.5.9 section. Both CLI notices and the desktop notices are byte-identical to the second candidate's.

Gate 4. In the VM `sha256sum -c` passed for the Linux archive, and on the Mac `shasum -a 256 -c` passed for all three `.sha256` files, including the copied Linux archive's. Each CLI archive holds exactly eight regular files: the five binaries (mode 0755) and `README.md`, `LICENSE` and `THIRD_PARTY_LICENSES.md` (mode 0644), in POSIX ustar headers owned by 0:0 with empty owner names and mtime 0, with flat names and no absolute, `..`, link, special or duplicate entries; the gzip mtime is 0. The archived `README.md` (SHA-256 `33c3696cc3c7affec04cda100273c3ec41bfd1203d24376725f9d3a3bf6ed47b`, "Version 0.2.0") and `LICENSE` are byte-identical to `3654a21`. The per-entry hashes and the hashes of the files in the image are in the release's `VERIFICATION.json` asset.

| Asset | Bytes | SHA-256 |
| --- | --- | --- |
| `zeropw-v0.2.0-aarch64-apple-darwin.tar.gz` | 14,681,456 | `68493ecb7bf5e47c6924bcbaee8dde994b8dde17acfa4c836522baacec6f8d5d` |
| `zeropw-v0.2.0-aarch64-unknown-linux-gnu.tar.gz` | 16,312,552 | `5f1dc52a5081e3386f71843c51a7f15f5e95d1b13153c446e08975b0eba70d86` |
| `zeropw-desktop-v0.2.0-aarch64-apple-darwin.dmg` | 16,601,058 | `3a4315bfd1b17e41294a46c754581a9373750d61e77f3717de310b4dc481c77e` |
| `zeropw-desktop-v0.2.0-aarch64-apple-darwin-THIRD_PARTY_LICENSES.md` | 4,417,360 | `47d938bd3e51ae51807777bfa331b84e4e0e9b080db3fab1f4721436432aaead` |

Each archive and the image have their `.sha256` file. The packager's `-verification.txt` and a renamed copy of the Linux archive's notices are evidence files, not release assets. Builds are not bit-for-bit reproducible. Compared with the second candidate, the Linux `zeropw-agent`, `zeropw_session` and `zeropw-democli` are byte-identical, and `zeropw-admin` and `zeropw-demo` differ only in their GNU build ID and OpenSSL's "built on" timestamp. On macOS the archive's `zeropw-agent`, `zeropw_session` and `zeropw-democli` and the app's `zeropw-desktop`, `zeropw_session` and `zeropw-agent` before signing are identical, while `zeropw-admin` and `zeropw-demo` differ.

Homebrew. By owner decision 3, `Formula/zeropw.rb` stays at 0.1.0 in this release: it is byte-identical to the v0.1.0 formula (SHA-256 `f01165bea5b6dfadfcdb57b3ed7f82eaa91478f026e7354df2663c45dd79bf2d`) and installs the v0.1.0 archives. Gate 4's test of the formula against the release is therefore part of the follow-up pull request that moves the formula and the team onboarding files to 0.2.0 right after publication; there the onboarding validation cases are re-run against the published release, and Homebrew install, upgrade and test on the owner's Mac are allowed (decision 4). The tap reads the formula from the default branch, so that follow-up can reach main only after the v0.2.0 assets are published. No Homebrew command ran for this evidence.

Gate 5. The required review is of the exact commit that adds this section, the commit the v0.2.0 tag names, and it is published with the release as the `OPUS-REVIEW.json` asset. No earlier PASS is reused; the reviews of the two earlier candidates did not pass. The public download, installer and checksum checks after publication are recorded in the release's `VERIFICATION.json` asset.

On Apple Silicon macOS or ARM64 Linux, download `scripts/install.sh` from the release tag, inspect it, and run:

```sh
bash install.sh --version v0.2.0 --prefix "$HOME/.local"
"$HOME/.local/bin/zeropw-demo"
```

The installer keeps existing files; to replace a v0.1.0 installation, stop running ZeroPW processes and add `--force`. The macOS binaries were tested on macOS 26.5; older versions are unverified. The Linux binaries need glibc 2.39 or later. Until the follow-up, `brew install telicity-ai/zeropw/zeropw` installs 0.1.0, which cannot read the invite links the desktop app creates; a teammate who joins with the CLI should install 0.2.0 with the installer.

The desktop preview is for Apple Silicon Macs only. It was launched only on macOS 26.5, on the Mac that built it, without the quarantine attribute that a downloaded file carries. Download `zeropw-desktop-v0.2.0-aarch64-apple-darwin.dmg` and its `.dmg.sha256` from the [v0.2.0 release](https://github.com/telicity-ai/zeropw/releases/tag/v0.2.0) into one folder and check the image before opening it:

```sh
shasum -a 256 -c zeropw-desktop-v0.2.0-aarch64-apple-darwin.dmg.sha256
```

It prints `zeropw-desktop-v0.2.0-aarch64-apple-darwin.dmg: OK`. Then install and open it with the steps in "What users see on macOS 15 and later" above, which were not tried with this image on any Mac. Do not remove the quarantine attribute or turn Gatekeeper off. The app is a preview with a Korean-only interface; it is not notarized, and its ad hoc signature does not identify who built it.

## v0.2.0 follow-up: Homebrew formula and team onboarding

By owner decision 3, PR #25 moves `Formula/zeropw.rb` to the v0.2.0 archives (formula SHA-256 `1cc8493ac6964201eac9778ba591e285ddf8637926741aa475a43078c11830b6`) together with the team onboarding files, which now accept 0.2.0 only. The seven onboarding validation cases of 2026-10-11 were re-run against the published release on 2026-10-16: see the [re-run report](onboarding-validation-v0.2.0-2026-10-16.md). It is the current evidence for these files. The 2026-10-11 reports and `onboarding-validation-manifest-2026-10-11.json` remain the record for v0.1.0. The re-run again does not establish an actual ready pair: B keeps one `team_author_unknown` rejection record, which the validator keeps blocking.

Gate 4, Homebrew, before merge. By decision 4 the test ran on the owner's Mac (macOS 26.5, build 25F71, Homebrew 7.0.9-110-g9bd5746), where 0.1.0 was installed from the tap `telicity-ai/zeropw` and no ZeroPW process was running. The Homebrew commands in the test log (`info`, `upgrade`, `cleanup`, `test`, `linkage` and the step-1 block's `reinstall`) ran with `HOMEBREW_NO_AUTO_UPDATE=1` and `HOMEBREW_NO_INSTALL_CLEANUP=1`; a few read-only queries such as `brew --prefix` ran with the first one or with neither. The installed tap fetched the PR branch and was checked out detached at the candidate `b43c3ab43d559d0305c456e8b372783f89f2e3de`. Its formula had the pinned digest, it was the only Ruby file that differs from `9c92e5e`, and `brew info` parsed the macOS URL with checksum `68493ecb…`. `brew upgrade telicity-ai/zeropw/zeropw` upgraded 0.1.0 to 0.2.0. Because install cleanup was off, `brew cleanup telicity-ai/zeropw/zeropw` then removed the 0.1.0 keg. Afterwards:

- `brew list --versions zeropw` printed `zeropw 0.2.0`. The keg's receipt names tap `telicity-ai/zeropw`, tap commit `b43c3ab…`, spec `stable` and version 0.2.0. The tap stayed clean at that commit with the pinned formula digest.
- `scripts/observe-onboarding-brew.py --approved-tap b43c3ab…`, run with the system Python 3.9.6 from a clean clone, printed that commit, `stable` and `binaries_resolve_to_keg: true`, and exited 0.
- `brew test` passed. `zeropw-agent --help` and `zeropw-admin --help` exited 0, and the installed demo under `env -i` passed all 47 checks. A first demo attempt stopped with `socket_path_too_long` because its `TMPDIR` path was too long for a Unix socket; with a short `TMPDIR` it passed.
- The five binaries and three documents in the keg have the same SHA-256 as the entries of Homebrew's cached download, of a separate download of the published archive and of the release's `VERIFICATION.json`.
- `brew linkage` lists only `/usr/lib` libraries and system frameworks.
- The English manual's step-1 block, run verbatim under zsh from a clean clone with that commit filled in, passed its tap checks, reinstalled 0.2.0 once, passed the observer, `brew test` and the demo, and exited 0.

No vault or app data folder was created in the account's home. This is not a `/2` installation PASS, because the account holds coordinator authority, and not a first installation on a clean Mac. Linux Homebrew remains unverified. The tap stays at the candidate until the merge, after which it moves to the merge commit on main.

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
