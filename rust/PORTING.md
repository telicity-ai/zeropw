# ZeroPW Rust implementation — compatibility contract

The `zeropw` crate in this directory is the product. It replaced a Python
prototype that implemented the same requirements first; the prototype was
removed from the repository on 2026-10-03 (it remains in git history). This
file states what the Rust code must stay compatible with, how that is
checked, and the engineering rules for changing it. Product behaviour itself
is specified by `../docs/product-intent.md`, `../docs/security-design.md`,
`../docs/compromise-response.md` and `../docs/team-sync.md`.

## 1. Compatibility boundaries (user decision, 2026-10-03)

Rust does not reproduce the prototype's behaviour in general. It must stay
compatible with the prototype only at these boundaries:

1. **Persisted state.** Every state directory, document, audit log, backup
   and team snapshot/commit the prototype could write in normal operation
   loads in Rust and keeps its meaning. Rust-written JSON keeps the same
   layout (key order, separators, escaping, number spelling), file and
   directory modes (0600/0700), `flock` locking and atomic replacement.
2. **Wire and cryptographic formats.** Anything another party verifies or
   parses stays byte-compatible: canonical JSON used for signatures, digests
   and AEAD associated data; handle tokens; team transport and sync
   messages; the SSH agent protocol; gateway upstream requests; backup
   archives.
3. **Features.** Every command, API, tool and process the prototype offered
   works with the same intent and the outputs a user or agent relies on.
4. **Security requirements** in `../docs/security-design.md`: secrets never
   reach agent-controlled processes, outputs, errors or logs; unsupported or
   malformed input fails closed.

Outside those boundaries Rust may differ. Malformed or hand-edited state,
adversarial input and interpreter-specific behaviour get a clear,
fail-closed Rust error, not the prototype's. `DEVIATIONS.md` is the
historical record of how the port differed while both implementations
existed; a row there is not a defect unless it breaks one of the four
boundaries.

## 2. How compatibility is checked

The prototype generated golden fixtures once, before it was removed, under
`tests/fixtures/python/<area>/`: state directories it wrote, canonical and
signed bytes, gateway request bytes, SSH agent replies, team commits and
snapshots, backups, SMTP message bytes and CLI outputs for normal features.
Each directory's `GENERATE.md` holds the exact script and command that
produced it (CPython 3.12.14). The tests load these files through
`tests/python_fixtures/` and compare what Rust reads or writes against them.
The fixtures cannot be regenerated now that the prototype is gone; treat them
as frozen. A new persisted or wire format needs its own Rust tests, not a
new fixture.

The modules `pyjson.rs`, `pystr.rs`, `pyint.rs`, `pybase64.rs`, `pyidna.rs`
and `argparse.rs` exist for boundaries 1–3: they read and write the
prototype's JSON byte layout, exact integer sizes, base64 and IDNA forms and
command-line argument rules. Use them for every JSON write and every parse
of persisted or wire data; `tests/canonical_helpers.rs` fails the build when
code bypasses them.

## 3. Crate layout

| Area | Files (`src/`) |
| --- | --- |
| Foundation | `errors.rs`, `secret.rs` (`SecretBytes`: zeroised, redacted `Debug`), `clock.rs`, `store.rs`, `context.rs`, `projects.rs`, `audit.rs`, `handles.rs` |
| Cryptography and keys | `crypto/{chacha20poly1305,ed25519,x25519}.rs` (audited `chacha20poly1305`, `ed25519-dalek`, `x25519-dalek` crates; RFC vectors), `kms.rs` |
| Vault and policy | `vault.rs`, `policy.rs` |
| HTTP authentication relay | `gateway.rs`, `fake_upstream.rs` (test upstream) |
| SSH signer | `signer.rs`, `sshwire.rs` |
| Agent tools and execution | `tools.rs`, `runs.rs`, `server.rs`, `bin/zeropw_session.rs` |
| Compromise response | `incident.rs`, `intrusion.rs`, `notify.rs`, `smtp.rs` |
| Team sharing | `team/{identity,envelope,commit,fold,humanview,transport,sync,membership}.rs` |
| Command-line interfaces | `admin_cli.rs` (`zeropw-admin`), `agent_cli.rs` (`zeropw-agent`), `mac_proxies.rs` (macOS system proxies for the agent), `demo.rs` (`zeropw-demo`), `bin/zeropw-democli.rs` |
| Compatibility helpers | `pyjson.rs`, `pystr.rs`, `pyint.rs`, `pybase64.rs`, `pyidna.rs`, `argparse.rs` (§2) |

Deployments that include `exec` must build and ship the trusted
`zeropw_session` binary beside the server executable (`cargo build --bins`).
`runs.rs` finds it by the executable's directory, never through an
agent-controlled `PATH`; if it is missing, execution fails closed as
`spawn_failed` and never falls back to a plaintext credential path. The
helper calls `setsid`, marks every descriptor from 3 up close-on-exec, and
`execve`s the fixed program through the ordered `PATH` candidates; the
kernel decides executable formats and interpreter (shebang) rules, so XNU
and Linux differ there. A close-on-exec acknowledgement socket in a private
per-run directory reports spawn failures synchronously.

## 4. Engineering rules

- No `unsafe` in product code except the `libc::flock` calls in `store.rs`
  (`lib.rs` has `#![deny(unsafe_code)]`). Never change process-wide state
  such as the umask from library code: the server is multithreaded.
- No `unwrap`/`expect`/indexing panics on untrusted input (state files,
  sockets, agent or peer data); return the error the caller handles.
  Arithmetic on values read from state uses exact integers (`PyInt`) or
  checked operations, never wrapping.
- Secrets live in `SecretBytes`; types holding them must not derive a
  printing `Debug`, `Display` or `Serialize`. Secret and MAC comparisons are
  constant time. Errors, audit records and logs never carry secret values.
- Every behaviour change comes with tests for the behaviour and its failure
  boundaries, in the module's `tests` module or `tests/<target>.rs`.
- Verify with `verify.sh` (formatting, strict Clippy, library and binary
  tests, every integration target, the ignored signer resource probes, doc
  tests) on Linux and macOS, in an isolated environment: never build or run
  product code on a host holding gateway, vault, signer or administrator
  credentials.
