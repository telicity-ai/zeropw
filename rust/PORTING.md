# ZeroPW Rust port — equivalence contract

The Python prototype in `../zeropw/` is the specification. This crate reimplements it in Rust with
**the same functionality and the same observable behaviour**. A reviewer checks every ported module
against its Python source and its Python tests; "looks reasonable" is not the bar, "behaves the same" is.

Read first: `../docs/security-design.md`, `../docs/implementation.md`, then the Python module you port
and its tests.

## 1. Complete-port scope

The 2026-09-22 user decision expands the earlier first-half milestone to all
existing functionality. It also replaces new Opus judgments with independent
reviews by the explicitly selected Astra model. Implementation uses explicitly
selected Sol workers. An old PASS never approves new code; current acceptance
and unresolved findings are tracked in `../docs/rust-completion.md`.

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

The formerly excluded modules are now required:

| Work unit | Rust files | Python sources and required tests |
| --- | --- | --- |
| Execution and HTTP tools | `runs.rs`, `tools.rs`, `server.rs` | same-named Python modules; `test_runs.py`, `test_tools.py`, server cases in `test_gateway.py` and `test_agent_cli.py` |
| Response and notifications | `incident.rs`, `intrusion.rs`, `notify.rs` | same-named modules and their complete test files; compromise-response process E2E |
| Team networking | `team/{transport,sync,membership}.rs` | same-named modules; transport, sync, membership, snapshot, facts and team E2E tests |
| Native interfaces | `admin_cli.rs`, `agent_cli.rs`, `demo.rs`, `bin/` | admin/agent/demo modules and example CLI; CLI, demo, HTTP/SSH/team process E2E tests |

There is no plaintext fallback or Python product backend. Python remains a
test oracle/driver only. A module's existence or a representative smoke test
does not satisfy the full behavioral and boundary-test obligations below.

Native deployments that include `exec` must build and ship the trusted
`zeropw_session` binary beside the server executable (`cargo build --bins`).
`runs.rs` locates this sibling by the executable directory, never by an
agent-controlled `PATH`; if the helper is absent, execution fails closed as
`spawn_failed`. The helper uses safe `rustix::process::setsid` then `exec`,
with a close-on-exec acknowledgement socket to preserve synchronous spawn
failure semantics. Because libc `execvp` retries `ENOEXEC` through
`/bin/sh` where Python's direct `execve` fails, the helper first picks the
file `execve` would run (Python's `PATH` walk past refused candidates) and
reports a file in no kernel-executable format (`#!`, native ELF/Mach-O) as
the spawn failure; see the `zeropw_session` row in `DEVIATIONS.md`. Its ACK socket lives in a per-run private short-path
temporary directory, independent of the configured SSH socket directory.
Before the final `exec`, `close_fds` 0.3.2 marks every descriptor from 3 upward
close-on-exec, matching Python's `close_fds=True` for unrelated inheritable
trusted descriptors; the ACK socket stays open only until that `exec`. The
crate uses Linux `close_range(CLOEXEC)` when available and enumerates file
descriptors otherwise, including macOS `/dev/fd`. Its safe API does not report
individual `fcntl(F_SETFD)` failures, so this boundary assumes a functioning
local kernel descriptor API; `astra_cli_runtime_round2` tests the actual
inheritable-FD case through a native child. No `unsafe` was added to this
repository for this helper. This is a packaged Rust helper, not a Python backend.

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

5. Coordinator ruling (2026-09-17): where Python lets a *built-in* exception escape uncaught (`TypeError`,
   `ValueError`, `UnicodeEncodeError`, `IndexError`, `json.JSONDecodeError`, ... — anything not from
   `errors.py` or a module's own documented error types), that escape is not specified behaviour. Rust
   returns the closest ZeroPW error a caller of that function already handles (fail closed), recorded in
   `DEVIATIONS.md` citing §3.5. This does not cover documented error types or any case where Python
   *returns* a value.
6. Coordinator ruling (2026-09-17): JSON strings containing lone UTF-16 surrogate escapes (`"\ud800"`)
   cannot be represented as Rust `String`; Rust rejects them as malformed input (state file →
   `state_corrupt`, peer/agent message → that path's malformed-input error), recorded under §3.6.

7. Coordinator ruling (2026-09-17): an input that can only exist if it was authenticated with a trusted
   secret key (e.g. a handle payload with a valid HMAC that the issuer itself never emits) may be handled
   more strictly than Python — rejected with the error that path already uses for malformed input — as
   long as every value the issuer *does* emit behaves identically. Record each such case in
   `DEVIATIONS.md` citing §3.7. This never applies to input an agent, peer or file can supply without the
   key.

Anything else that differs must be recorded in `DEVIATIONS.md` (module, Python behaviour, Rust
behaviour, why). An unrecorded difference is a defect.

## 3b. Canonical Python-semantics helpers (coordinator ruling, 2026-09-18)

Three separate units re-implemented CPython's `int(str)` grammar and each got the same detail wrong
(`int()` strips only ` \t\n\v\f\r`, **not** U+001C-U+001F, which `str.isspace()`/`str.strip()` do
include; and it accepts every Unicode `Nd` digit). Emulations of CPython behaviour therefore live in
ONE place and are reused, never copied:

| Semantics | Canonical home |
| --- | --- |
| `str.isspace`, `str.isprintable`, `repr(str)` | `crate::pystr` |
| `repr()` of a `json.loads`-decoded value (also what `str()` falls back to for a `list`/`dict`) | `crate::pystr::repr_value` |
| `int(str)` grammar (its own whitespace set, `_` separators, sign, Unicode `Nd` digits) | `crate::pystr` |
| `repr()`/`str()` of a single JSON number token (int/float split, overflow to `inf`/`-inf`) | `crate::pystr::repr_number` |
| `urllib.parse.unquote` (ASCII/non-ASCII run splitting, then `%XX` decode within a run) | `crate::pystr::unquote` |
| `base64` (lenient `b64decode`, urlsafe, encode) | `crate::pybase64` |
| `json.dump`/`load` byte compatibility | `crate::pyjson` |

A unit that needs one of these uses the canonical helper. If it is missing a case, extend the canonical
helper (and its full-codepoint oracle test) rather than writing a local variant; a local copy of any of
these semantics is a review finding.

**Enforcement (coordinator ruling, 2026-09-18).** This rule was written after the `int(str)` incident and
was then violated four more times, in four different units, inside a single review round: two
byte-identical private `repr` copies (`handles.rs`, `vault.rs`) plus a third rendering containers as JSON
in `team/commit.rs` (H-R5-1); a strict-engine base64 decode bypassing `pybase64` (F-R4-3); and floats
rendered through `serde_json`'s literal text instead of `pyjson::python_float_repr` in `gateway.rs`
(F-R4-5) and `policy.rs` (D-PO-1). Fixing instances did not close the class, so the rule now has a
mechanism: `rust/tests/canonical_helpers.rs` reads this crate's own source text and fails on a bypass
outside the canonical home. Rules for it:

- A new bypass is not made legal by adding it to the guard's allowlist. Extend the canonical helper.
- Every allowlist entry carries a one-line reason. An entry that is genuinely a different Python function
  (e.g. `base64.b64decode(..., validate=True)` in `crypto/ed25519.rs`, which is not the lenient decoder
  `pybase64` reproduces) is legitimate and permanent; an entry that records an unfixed bypass is **debt**
  and must name the finding id that owns it.
- The guard is only worth its cost if it actually fires. Whoever changes it re-verifies that reverting a
  real fix is still caught.
- **Promoting a helper is itself a change that must be measured.** Finding X-10: when two private `repr`
  copies were promoted to `pystr::repr_value`, the promotion picked one without checking which was right.
  The chosen implementation branched on `serde_json::Number::is_f64()`, which is `false` for an
  overflowing literal under `arbitrary_precision`, so `1E400` rendered as `"1e+400"` where CPython gives
  `'inf'` — while two OTHER copies (`kms.rs`, `policy.rs`) branched on the literal text and were correct.
  Consolidation made the codebase uniformly wrong at the place it was meant to make it uniformly right.
  So: before deleting copies, probe every one against CPython and promote the one that matches; and
  deleting a copy is only correct when the canonical helper's semantics are the same — `vault.rs`'s
  `python_str_scalar` was left in place because its `String` arm is `str()` (unquoted), not `repr()`.

## 3c. A justification is a claim about CPython, and claims get measured (coordinator ruling, 2026-09-18)

Every `DEVIATIONS.md` row and every doc comment that says "Python raises here", "this field is never a
float", "no test exercises this" is a factual claim. Round 7 measured them and found nine that were
false, across every unit — including ones that had survived several reviews:

- `projects.rs` claimed every caller raises `TypeError`; `create`'s `if name in doc` is a *substring*
  test on a `str` and raises the documented `InvalidInput("project_exists")` instead (A-R7-1).
- `pyjson`'s row claimed no vault/policy/handle document holds a float; `policy/grants.json` and
  `policy/control.json` both persist raw `time.time()` floats (A-R7-3).
- `DEVIATIONS.md` E-5 claimed closing the temp-dir gap "would need `unsafe` `libc::atexit`" and that it
  was "not exercised by any test"; `std::process::exit` is never called in this crate, a safe
  `Arc<Context>` closes it, and one test reproduced it on every suite run (E-R7-1).
- `policy.rs` claimed gating a read on a non-empty set "reproduces Python's laziness exactly"; Python's
  laziness is in the `.get()`, not in `read_json`, so a corrupt document was silently ignored (D-R7-2).
- `policy.rs` cited §3.5 for `dict([[1,"a"]])`, which Python *returns a value* for (D-R7-5).

Therefore: a justification must be accompanied by the probe that establishes it, and **a justification
that measurement contradicts is itself a review finding**, at the severity of whatever it was hiding. §3.5
covers an exception CPython leaves uncaught — never a case where CPython returns a value, and never a
documented error type. Cite it only after measuring which of those three you are in.

## 3d. A representational failure must not widen its blast radius (coordinator ruling, 2026-09-18)

Rust's typed structs cannot hold every shape Python's dynamic dicts can, so this port sometimes fails
where Python succeeds. That is allowed under §3 only at the ORIGINAL SCOPE: Python raising inside a
per-item loop skips one item, and the Rust equivalent must skip that one item too. Three findings in two
rounds were the same mistake:

- `validate_document_shape` rejected nine documents Python folds without error (H-R5-6).
- `derive_vault`'s `secrets` type check ran unconditionally, aborting `derive_local` for a document with
  nothing to derive, where Python only fails inside the loop body (H-R5-7).
- `derive_connections` propagated one connection's `state_corrupt` out of the whole loop with `?`, so
  `write_json` never ran and every OTHER connection's and secret's derivation was silently discarded —
  reachable by one signed peer op, i.e. denial of sync for the environment (H-R6-1).

Therefore: a `team::fold` derive-stage site that reconstructs a typed struct from a document entry which
already passed `fold()`'s op-application validation must not let a purely representational reconstruction
failure abort more than that one entry. It skips the entry, records it the way Python's `_op_*`
catch-and-skip does, and continues. The same rule applies to any other per-item loop over document
entries (`Policy`/`Vault` document loading included): measure the SCOPE of Python's failure, not just its
identity, and reproduce that scope.

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
  --all-targets -- -D warnings`, `~/.cargo/bin/cargo fmt`. Use `python3.12` (plain `python3` is 3.9)
  at the latest 3.12 patch release, which is what CI installs: stdlib behaviour changes between 3.12
  patch releases (see the `notify header folding (CPython patch level)` row in `DEVIATIONS.md`).
- Only edit the files of your work unit (plus `DEVIATIONS.md` and new test files). If you truly need a
  new crate, add it to `Cargo.toml` and say so in your report. Do not change `errors.rs`, `secret.rs`,
  `clock.rs`, `oracle.rs`, `lib.rs` — ask the coordinator.
- Do not modify anything outside `rust/`.
