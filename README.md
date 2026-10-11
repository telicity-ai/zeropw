# ZeroPW

[한국어](README-ko.md)

ZeroPW stores credentials in an encrypted vault and lets agents use supported HTTP APIs and SSH without receiving the original secrets. Configure a service connection once, then use different operations within its allowed scope. A trusted gateway adds HTTP authentication; a separate signer handles SSH authentication.

ZeroPW is a Rust CLI project. Version 0.1.0 is an initial release, tested with synthetic credentials and controlled endpoints. It does not support every CLI, and its local development setup does not isolate agents from the vault when they run as the same OS user. Read the [security design](docs/security-design.md) and [implementation limits](docs/implementation.md) before using real credentials.

## Start here

The [guide](GUIDE.md) covers the demo, administrator setup, team sharing, and agent use. The [agent skill](skills/zeropw-agent/SKILL.md) helps agents select and use existing connections without reading secrets.

```sh
cargo build --locked --manifest-path rust/Cargo.toml --bins
rust/target/debug/zeropw-demo
```

Build and run tests on a disposable CI runner or isolated VM without vault, gateway, signer, or coordinator credentials. Rust must support edition 2024. The demo uses an embedded test server and synthetic credentials; exit code 0 means its checks passed.

Version 0.1.0 binary downloads support Apple Silicon macOS and ARM64 GNU/Linux (Ubuntu 24.04 build baseline). Intel macOS and x86-64 Linux binaries are not included.

```sh
brew tap telicity-ai/zeropw https://github.com/telicity-ai/zeropw
brew install telicity-ai/zeropw/zeropw
brew test telicity-ai/zeropw/zeropw
zeropw-demo
```

The formula installs checksummed release binaries; Rust and Homebrew OpenSSL are not required for this version. The [release guide](docs/releasing.md) describes the archive installer and verification scope.

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

ZeroPW does not import or export a complete `.env` file. Applications that require raw credentials in their environment, or database drivers without a dedicated integration, are unsupported. The tested CLI paths are the demo CLI and OpenSSH with destination-bound signing.

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

Historical review records and archived specifications are evidence for their recorded revisions only. They are not a security approval for current code. The Python prototype was removed after the Rust transition on 2026-10-03 and remains in Git history.

## License

[MIT](LICENSE). Third-party dependencies retain their own licenses.
