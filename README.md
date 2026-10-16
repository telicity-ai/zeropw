# ZeroPW

[한국어](README-ko.md)

ZeroPW stores credentials in an encrypted vault and lets agents use supported HTTP APIs and SSH without receiving the original secrets. Configure a service connection once, then use different operations within its allowed scope. A trusted gateway adds HTTP authentication; a separate signer handles SSH authentication.

ZeroPW is a Rust CLI project with a preview desktop app for Apple Silicon macOS. Version 0.2.0 is an early release, tested with synthetic credentials and controlled endpoints. It does not support every CLI, and its local development setup does not isolate agents from the vault when they run as the same OS user. Read the [security design](docs/security-design.md) and [implementation limits](docs/implementation.md) before using real credentials.

## Start here

The [guide](GUIDE.md) covers the demo, administrator setup, team sharing, and agent use. The [agent skill](skills/zeropw-agent/SKILL.md) helps agents select and use existing connections without reading secrets.

For teammate onboarding, download the [English HTML manual](docs/team-onboarding.en.html) or [Korean HTML manual](docs/team-onboarding.ko.html) and open it in a browser. Copyable verification prompts are also available in [English](docs/team-agent-prompts.en.txt) and [Korean](docs/team-agent-prompts.ko.txt). The manuals and prompts describe the Homebrew installation of version 0.2.0. Version 0.1.0 cannot read invite links, the only kind of invitation the desktop app creates (see [Team sharing](#team-sharing)).

```sh
cargo build --locked --manifest-path rust/Cargo.toml --bins
rust/target/debug/zeropw-demo
```

Build and run tests on a disposable CI runner or isolated VM without vault, gateway, signer, or coordinator credentials. Rust must support edition 2024. The demo uses an embedded test server and synthetic credentials; exit code 0 means its checks passed.

## Install

Version 0.2.0 binary downloads support Apple Silicon macOS and ARM64 GNU/Linux. Intel macOS and x86-64 Linux binaries are not included. The macOS binaries were tested on macOS 26.5; older versions are unverified. The Linux binaries need glibc 2.39 or later (Ubuntu 24.04 or later): `zeropw-admin` and `zeropw-demo` use GLIBC_2.39 symbols and do not start with an older glibc.

The release assets are `zeropw-v0.2.0-aarch64-apple-darwin.tar.gz` and `zeropw-v0.2.0-aarch64-unknown-linux-gnu.tar.gz`, each with a `.tar.gz.sha256` file. Each archive holds the five binaries, `README.md`, `LICENSE` and `THIRD_PARTY_LICENSES.md`. To install 0.2.0 on either platform, download `scripts/install.sh` from the v0.2.0 tag, read it, and run it:

```sh
curl -fsSLO https://raw.githubusercontent.com/telicity-ai/zeropw/v0.2.0/scripts/install.sh
bash install.sh --version v0.2.0 --prefix "$HOME/.local"
"$HOME/.local/bin/zeropw-demo"
```

The installer downloads the archive for your platform and its `.sha256` file from the v0.2.0 release, checks the SHA-256 and the archive entries, and installs the binaries into `PREFIX/bin` and the documents into `PREFIX/share/doc/zeropw`. It does not use sudo, create a vault, start a service, edit shell profiles or run the downloaded binaries. It does not overwrite existing files: to replace an earlier installation, stop running ZeroPW processes and add `--force`. For an archive you downloaded yourself, use `--archive FILE --sha256 HEX` instead of `--version`. A checksum detects corruption but is not a signature; the release host and publisher remain trusted. The [release guide](docs/releasing.md#packaging-tools) has the details.

On Apple Silicon macOS, these commands install version 0.2.0 with Homebrew; `brew list --versions zeropw` shows the installed version. If an earlier version is installed, run `brew update` and `brew upgrade telicity-ai/zeropw/zeropw` instead of `brew install`:

```sh
brew tap telicity-ai/zeropw https://github.com/telicity-ai/zeropw
brew install telicity-ai/zeropw/zeropw
brew test telicity-ai/zeropw/zeropw
zeropw-demo
```

The stable formula installs a checksummed release archive; Rust and Homebrew OpenSSL are not required. Linux Homebrew installation has not been verified; on ARM64 Linux, use the installer above. If both Homebrew and the installer have installed ZeroPW, the copy found first on `PATH` runs; check with `command -v zeropw-admin`.

## Binaries

| Binary | Purpose | Where it runs |
| --- | --- | --- |
| `zeropw-admin` | Initialize state; manage projects, secrets, connections, identities, grants, audit records, incidents and team membership; run `serve` | Trusted administrator host |
| `zeropw-agent` | `list-connections`, `request`, `exec`, `status`, `cancel` | Agent environment without original credentials |
| `zeropw_session` | Execution helper; install beside `zeropw-admin` | Trusted execution host |
| `zeropw-demo` | Demonstrate the workflow with synthetic credentials | Disposable demo environment |
| `zeropw-democli` | Example CLI using a gateway base URL and opaque handle | Tests and demos |

The agent receives `ZEROPW_GATEWAY_URL` and its restricted `ZEROPW_CALLER_TOKEN`, never administrator passphrases or vault credentials. A missing execution helper makes `exec` fail with `spawn_failed`; there is no plaintext fallback.

## Team sharing

Share one project environment with invited devices over a LAN or team VPN. Each device has its own keys and trusted process. Signed changes and encrypted secrets synchronize directly between devices; there is no central server or leader.

Caller identities and grants remain local to each device. Offline devices can keep using their last synchronized state, so revocation is delayed until they reconnect. Removing a member cannot erase secrets they could previously decrypt: rotate those credentials at the provider. Roles prevent mistakes and record authority; they do not cryptographically prevent a device owner from extracting a shared secret.

Concurrent administrator removals can leave different accepted membership facts. Check `team status` → `rejected_removals`; an active admin must review and reissue the intended removals.

Version 0.1.0 cannot read invite links (`zeropw://join#…`), which `team invite --link` prints and which are the only kind of invitation the desktop app creates. A teammate who joins with the CLI needs 0.2.0: install it with Homebrew or the installer above, and upgrade an earlier Homebrew installation with `brew upgrade telicity-ai/zeropw/zeropw`. Teams that mix 0.1.0 and 0.2.0 devices have not been tested.

ZeroPW does not import or export a complete `.env` file. Applications that require raw credentials in their environment, or database drivers without a dedicated integration, are unsupported. The tested CLI paths are the demo CLI and OpenSSH with destination-bound signing.

## Desktop app (preview)

`desktop/` contains a preview Tauri desktop app for the administrator workflow: vault setup, keys, connections, agents and grants, records, stop-all, incidents, backup and recovery, and team invite links. It runs the bundled `zeropw-admin` as a child process for each command instead of linking the vault code. The v0.2.0 release includes it as an ad hoc signed preview disk image for Apple Silicon Macs, `zeropw-desktop-v0.2.0-aarch64-apple-darwin.dmg`, with its `.dmg.sha256` file. The image was built on one Mac with macOS 26.5 and launched only there, without the quarantine attribute that a downloaded file carries; other macOS versions are unverified, and the Gatekeeper steps below were not tested. The [desktop app specification](docs/desktop-app.md) and the [design rules](DESIGN.md) are written in Korean.

To install it:

1. Download the image and its `.dmg.sha256` file from the [v0.2.0 release](https://github.com/telicity-ai/zeropw/releases/tag/v0.2.0) into one folder, and verify the checksum before you open the image. It must print `zeropw-desktop-v0.2.0-aarch64-apple-darwin.dmg: OK`.

   ```sh
   shasum -a 256 -c zeropw-desktop-v0.2.0-aarch64-apple-darwin.dmg.sha256
   ```

2. Open the image, drag ZeroPW onto the Applications link, and eject the image. Open the app only from Applications.
3. Open ZeroPW from Applications. macOS says that Apple could not verify that ZeroPW is free of malware; close that dialog with Done.
4. Within about an hour, open System Settings › Privacy & Security, scroll to Security, and click Open Anyway next to the message about ZeroPW. Confirm with your login password, then choose Open. If the button is gone, repeat step 3.

These steps follow Apple's documentation for macOS 15 and later; they were not tried with this image on any Mac (see the limits below). Do not remove the quarantine attribute or turn Gatekeeper off. The [release guide](docs/releasing.md#what-users-see-on-macos-15-and-later) explains why the app must be opened from Applications.

Known limits:

- Korean only. The app's interface is in Korean, with no English version (an owner decision). So is the explanation the app supplies for the macOS Local Network permission prompt; the prompt's title and buttons come from macOS.
- Apple Silicon (arm64) only on macOS. There is no Intel or universal build.
- Ad hoc signed preview, not notarized. The `.dmg` has no Developer ID signature, so its signature does not identify who built it, and Gatekeeper blocks the first open until you allow it with the steps above.
- Not tested for this preview. The Gatekeeper steps above were not tried with this image on any Mac; the owner waived the check of installing a download on a clean Mac and opening it through Gatekeeper the first time. The owner also waived three more checks: running the suggested agent command as another macOS account, watching whether macOS blocks or asks about the app's ad hoc signed helper programs (`zeropw-admin`, `zeropw_session`, `zeropw-agent`) after Open Anyway, and quitting the app with its own Quit (Cmd+Q).
- No auto-update. Replace the app yourself to get fixes.
- Closing the window does not quit the app. The app, its relay and the agent terminals keep running; reopen the window from the Dock and quit with Cmd+Q. If the app is killed instead of quit, for example with Force Quit, the relay keeps running.
- Some agents outlive their terminal. Closing an agent's terminal or quitting the app stops the processes started in that terminal, but not agents started as another account (as the app suggests) or processes detached from the terminal (`setsid`, tmux, screen, daemons). They keep running with their caller token; only disabling the agent in the app stops that token.
- No isolation within one macOS account. Any program running as the same user, agents included, can read the development device key file and the vault ([#21](https://github.com/telicity-ai/zeropw/issues/21)). The app suggests running agents as a different account.
- Recovery limits ([#22](https://github.com/telicity-ai/zeropw/issues/22)). Recovery with the recovery code needs the existing device key file. It re-wraps the same data key, so it is not a response to a leaked key file, and backups made before it can no longer be restored.
- No password change. Neither the app nor the CLI can change the administrator password or the recovery code, although the [compromise response](docs/compromise-response.md) asks for both to be changed before a global incident is closed.
- Typed passwords can leave copies in memory. Passwords sent from the app's window to its core can leave copies in Tauri's IPC buffers. The administrator password and a recovery code you choose yourself are sent at every keystroke for the strength check, so several copies can remain.
- Teammates need 0.2.0. The app creates only invite links, which version 0.1.0 cannot read (see [Team sharing](#team-sharing)).
- Copied values can persist. The app clears a copied token, invite link or revealed value from the clipboard after 60 seconds if it is still there, and marks it for clipboard history tools to skip. A tool that ignores the mark can keep it, and Universal Clipboard can pass it to your other Apple devices.
- Do not count on screen-capture exclusion. On macOS the app only asks the window system to leave its window out of captures while a recovery code, token, invite link or revealed key is shown. Capture, recording and screen-sharing tools built on ScreenCaptureKit reportedly ignore that request from macOS 15 on, and it has not been tested on a release build. Linux has no such request. Do not show these values while you share or record your screen.

## Verify changes

```sh
rust/verify.sh              # Full Rust matrix, including E2E and signer resource probes
rust/verify.sh --list       # List integration targets
rust/verify.sh signer_e2e   # Run one integration target
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

The Rust matrix includes formatting, strict Clippy, library and binary tests, every integration target, ignored signer resource probes, and documentation tests. SSH E2E requires `ssh`, `sshd`, `ssh-keygen`, and `perl`. Python is used for installation tooling tests and the development harness, not as the product runtime.

Fixed fixtures under `rust/tests/fixtures/python/` preserve compatibility evidence from the removed Python prototype. Their original bytes and language are test inputs, not current product output. The [porting contract](rust/PORTING.md) defines compatibility boundaries.

## Documentation

- [Guide](GUIDE.md)
- [Product intent](docs/product-intent.md)
- [Security design](docs/security-design.md)
- [Implementation and known limits](docs/implementation.md)
- [Team synchronization](docs/team-sync.md)
- [Compromise response](docs/compromise-response.md)
- [Rust acceptance record](docs/rust-completion.md)
- [Release preparation](docs/releasing.md)
- [Desktop app (preview, Korean)](docs/desktop-app.md) and its [design rules](DESIGN.md)

Historical review records and archived specifications are evidence for their recorded revisions only. They are not a security approval for current code. The Python prototype was removed after the Rust transition on 2026-10-03 and remains in Git history.

## License

[MIT](LICENSE). Third-party dependencies retain their own licenses.
