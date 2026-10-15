# Rust transition acceptance record

Recorded 2026-10-04 for branch `claude/rust-parity-close`.

ZeroPW's product implementation is the Rust crate under `rust/`. The Python prototype that first implemented the same requirements was removed on 2026-10-03. This record describes acceptance evidence at that transition, not approval of later commits. The 2026-09-22 through 2026-10-03 work-unit, review-round and intermediate-validation history remains in [the archive](archive/2026-10-03-rust-completion-history.md).

## 1. Acceptance boundary

The 2026-10-03 user decision stopped requiring Rust to reproduce arbitrary prototype behavior. Compatibility is required at four boundaries ([porting contract](../rust/PORTING.md), section 1):

1. Read persisted state written by normal prototype operation without changing meaning: state directories, documents, audit records, backups, team snapshots and commits.
2. Preserve the bytes that peers validate or interpret: canonical JSON for signatures/digests, handles, team transport, SSH agent protocol, upstream requests and backups.
3. Provide every prototype command, API, tool and process with the same purpose and output contract.
4. Preserve the [security requirements](security-design.md). Original secrets must not enter agent-side processes, output, errors or logs. Unsupported or corrupt input must fail closed.

The transition removed code that had attempted to match CPython internals beyond those boundaries: encoded-word codec tables, resolver FFI (`sys_hostent`), reimplementations of `email` and `http.client`, and `str.lower()` tables.

## 2. Compatibility evidence

Tests that used the running prototype as an oracle changed in two ways:

- Stored-state and wire-format tests compare fixed fixtures generated once before prototype removal, under `rust/tests/fixtures/python/<area>/` (about 760KB). Each directory's `GENERATE.md` records its generation script and commands.
- Other tests use Rust's own expected results, or were removed when they tested only out-of-scope CPython behavior, such as exception classes for corrupt state, integer grammar edges, Unicode and codec internals. Rust tests retain fail-closed and no-secret-output checks.

## 3. Transition verification

At `f2042c0`, `rust/verify.sh` ran formatting, strict Clippy, library/binary tests, every integration target, signer resource measurements and doc tests. Commands named `python`, `python3` and `python3.12` were blocked with immediate failure; no calls were recorded.

| Platform | Environment | Result |
| --- | --- | --- |
| Linux | Isolated Lima VM `zeropw-parity`, ARM64 Ubuntu 24.04, unprivileged user, OpenSSL 3.0.13, Rust 1.98.1 | 93/93 steps passed; 1,365 tests passed, 0 failed |
| macOS | macOS 26.5 ARM64, Homebrew OpenSSL 3.6.5, Rust 1.98.1 | 93/93 steps passed; 1,368 tests passed, 0 failed |

The four ignored signer resource probes ran as a separate verification step. Native macOS execution on the coordinator host was explicitly authorized by the 2026-10-03 user decision for that transition. This does not grant automatic permission for later execution on a trusted host. The original logs remain outside the repository in the transition evidence collection: `isolated-runner/verify-sh-nopython-f2042c0.log` and `macos-verify-sh-final.log`.

The pre-transition `116345f` also passed the 107-step full Linux matrix, including live prototype comparisons and all 1,099 prototype tests.

## 4. Product defects fixed during transition

- **macOS signer umask race.** Temporarily narrowing the process-wide umask while binding a signer socket could remove execute permission from directories another thread created, causing `exec` to fail with `spawn_failed`. The signer now binds inside a 0700 socket directory and then sets the socket to 0600. Linux uses `fchmod` before binding to establish 0600 from the start.
- **CPython startup imitation.** Removed native binary startup rejection based on `PYTHONINTMAXSTRDIGITS`. Integer strings use a fixed 4,300-digit limit.

## 5. Remaining work at transition

- `signer_e2e` requires OpenSSH (`ssh`, `sshd`, `ssh-keygen`) and `perl`.
- GitHub Actions was disabled. Current release preparation uses manual self-hosted verification; see [runner setup](self-hosted-runner.md).
- The team incident-sharing hook `send_incident_for_all_envs` was not connected to `open_incident` ([implementation](implementation.md), section 11.2).
- Integration names such as `astra_*` and `*_parity` retain work-stage terminology. Renaming them to feature names remains a separate task.
- Deployment, operational isolation and managed KMS remain separate decisions and implementation work.

Later release preparation and exact-commit evidence belong in [releasing.md](releasing.md). This dated transition record must not be reused as a PASS for a newer commit.
