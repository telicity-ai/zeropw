# ZeroPW Rust port — equivalence contract

The Python prototype in `../zeropw/` is the specification. This crate reimplements it in Rust with
**the same functionality and the same observable behaviour**. A reviewer checks every ported module
against its Python source and its Python tests; "looks reasonable" is not the bar, "behaves the same" is.

Read first: `../docs/security-design.md`, `../docs/implementation.md`, then the Python module you port
and its tests.

## 1. First-half scope

| Work unit | Rust files | Python sources | Python tests to port |
| --- | --- | --- | --- |
| A foundation | `pyjson.rs`, `store.rs`, `projects.rs`, `audit.rs`, `handles.rs` | `json` usage, `store.py`, `projects.py`, `audit.py`, `handles.py` | `test_core_audit_handles.py`, store/projects cases elsewhere |
| B crypto+kms | `crypto/chacha20poly1305.rs`, `crypto/ed25519.rs`, `crypto/x25519.rs`, `kms.rs` | `crypto/*.py`, `kms.py` | `test_crypto_chacha20poly1305.py`, `test_crypto_ed25519.py`, `test_x25519.py`, kms cases in `test_core_vault.py` |
| C sshwire | `sshwire.rs` | `sshwire.py` | `test_sshwire.py` |
| D policy | `policy.rs` | `policy.py` | `test_core_policy.py` |
| E vault+context | `vault.rs`, `context.rs` | `vault.py`, `context.py` | `test_core_vault.py` |
| F gateway | `gateway.rs`, `fake_upstream.rs` | `gateway.py`, `fake_upstream.py` | `test_gateway.py`, `test_fake_upstream.py` |
| G signer | `signer.rs` | `signer.py` | `test_signer.py` |
| H team data | `team/{identity,envelope,commit,fold,humanview}.rs` | `team/identity.py`, `envelope.py`, `commit.py`, `fold.py`, `humanview.py` | `test_team_identity.py`, `test_team_envelope.py`, `test_team_commit.py`, `test_team_fold.py`, `test_team_facts.py` (data-layer cases) |

Not in this half: `runs`, `tools`, `server`, `incident`, `intrusion`, `notify`, `admin_cli`, `agent_cli`,
`demo`, `team/transport`, `team/sync`, `team/membership`. Where an in-scope Python module lazily imports one of those, port the in-scope behaviour and
leave a `// SECOND-HALF: <what>` note at the seam; do not invent the missing module.

Shared contract already in place (do not rewrite): `errors.rs`, `secret.rs`, `clock.rs`, `oracle.rs`.

## 2. What "same behaviour" means

Identical, unless listed in §3:

- Public operations, arguments, return values, defaults, constants, limits and ordering.
- Errors: same `ErrorClass` (the Python base class a caller would `except`), same `name`
  (`type(exc).__name__`), same `reason`, same `detail`. Where Python raises a built-in exception
  (e.g. `ValueError` subclasses `WireError`, `AuthenticationError`) model it as a module-local error
  enum with the same names and messages.
- Persistent state: same relative paths, file and directory modes (0700/0600), atomic replace,
  fsync, `flock` locking, and **byte-identical JSON** as Python's `json.dump(s)` with the same
  `sort_keys` / `separators` / `indent` / `ensure_ascii` arguments — use `pyjson` for every JSON
  write. A state directory written by Python must load in Rust and vice versa.
- Every digest, HMAC, signature or AEAD input is byte-identical (JSON canonical forms, key ids as
  associated data, base64 alphabet and padding, hex case).
- Wire formats (SSH agent/wire, HTTP relay requests and responses) are byte-identical.
- Audit records and alerts: same events, fields, whitelisting, truncation and write-failure behaviour.
- Time: take a `Clock` (`clock.rs`) wherever Python takes `clock`; `iso()` formatting identical.
- Concurrency semantics: std threads and blocking I/O, like the Python prototype. No async runtime in
  this half.

## 3. Allowed deviations (and only these)

1. Cryptographic primitives come from audited crates (`chacha20poly1305`, `ed25519-dalek`, `sha2`,
   `hmac`, `scrypt`) instead of hand-written code. The Python RFC test vectors must still pass.
2. Raw secret bytes live in `SecretBytes` (zeroised, redacted `Debug`, no `Display`/`Serialize`).
   Types holding secrets must not derive `Debug` that prints them.
3. Secret and MAC comparisons are constant time.
4. Python-only mechanisms become explicit seams with identical behaviour: monkeypatched module
   globals (e.g. `gateway._getaddrinfo`) → an injectable trait or function field; `weakref` sets →
   explicit registration; duck-typed `ctx: Any` → the concrete `Context`.

Anything else that differs must be recorded in `DEVIATIONS.md` (module, Python behaviour, Rust
behaviour, why). An unrecorded difference is a defect.

## 4. Engineering rules

- No `unsafe` except the `libc::flock` call in `store.rs`. No `unwrap`/`expect`/indexing panics on
  untrusted input (files, sockets, agent-supplied data): return an error as Python would.
- Rust naming, but keep Python names recognisable (`read_json`, `write_json`, `Policy::grant_create`...)
  so a reviewer can map each item back. Each public item's doc comment names the Python function if the
  name differs.
- Tests: port **every** test case of the listed Python test files that exercises your modules, as Rust
  tests with the same intent and assertions (unit tests in the module or `rust/tests/*.rs`). Add
  differential tests with `crate::oracle::python(...)` for every cross-language format you own
  (JSON bytes, digests, wire bytes, state directory round trips in both directions).
- Build and test offline: `~/.cargo/bin/cargo test --offline`, `~/.cargo/bin/cargo clippy --offline
  --all-targets -- -D warnings`, `~/.cargo/bin/cargo fmt`. Use `python3.12` (plain `python3` is 3.9).
- Only edit the files of your work unit (plus `DEVIATIONS.md` and new test files). If you truly need a
  new crate, add it to `Cargo.toml` and say so in your report. Do not change `errors.rs`, `secret.rs`,
  `clock.rs`, `oracle.rs`, `lib.rs` — ask the coordinator.
- Do not modify anything outside `rust/`.
