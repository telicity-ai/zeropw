# Astra resource cleanup / terminal publication control

- Actual independent reviewer: `gpt-6-astra`.
- Exact product: `d6fdee402d9d915eb9288a4ce97bbc1662fac7bb`.
- Worktree `${HOME}/Code/zeropw-rust-runtime-final` was clean before detaching at this revision; its saved branch was preserved. Only this unique report and independent regression were added.
- **Socket disappearance is not a terminal-run publication barrier.** No new product defect is demonstrated by this control.

## Observed failure and ordering

The coordinator's frozen full macOS run at d6f passed 22 of 23 team contract tests, failing the immediate status assertion in `remote_connection_disabled_fact_closes_existing_signer_socket`: it observed `running`, expected `cancelled`, after the policy-disabled and socket-absent waits succeeded. Its earlier socket-present and replacement-session barrier passed. That failure remains preserved, not relabeled a pass by a later rerun.

In Rust, `tools::Resources::drop` closes its SignerBinding. `tools::exec` supplies resource destruction as the run cleanup callback. `runs::supervise` calls that cleanup **before** `finalize`, which audits and then publishes terminal state/output. A concurrent HTTP status read can consequently observe socket absence before cancelled state. The Python implementation has the same relevant ordering: `tools._make_cleanup` closes the binding; `RunRegistry._supervise` invokes cleanup before `_finalize`. Waiting for socket removal does not mean an in-progress cancellation call has returned or finalization completed.

## Independent controlled proof

`rust/tests/astra_cleanup_publication_order.rs` invokes both actual original-Python and native RunRegistry APIs. Each creates a synthetic Unix listening socket and supplies a cleanup callback that closes/unlinks it, signals entry, and waits on a bounded five-second release barrier. A separate cancellation thread requests withdrawal. While cleanup is paused, the test requires all three facts simultaneously:

- socket path absent;
- run state still `running`;
- cancellation requested.

Releasing cleanup must let cancellation finish and publish exactly `cancelled`. No guessed sleep creates the observed window. The child has a four-second timeout; callback entry/release and completion synchronization are bounded. Python finally releases the barrier and shuts down; Rust's release guard releases it on unwinding. No product hook, existing assertion or test deadline was changed.

This uses a **generic actual Unix socket**, not a newly created SignerBinding or a complete team/HTTP scenario. The source path above connects the controlled run-lifecycle mechanism to signer cleanup; the experiment does not claim to record the precise scheduler interleaving in the original failed run. It demonstrates that the failed test's assumed implication is invalid in both implementations.

## Execution and disposition

Using the released existing mailbox target cache (no new build cache):

```sh
env -i PATH=${HOME}/.cargo/bin:${HOME}/.local/bin:/usr/bin:/bin CARGO_TARGET_DIR=${HOME}/Code/zeropw-rust-mailbox-final/rust/target cargo test --offline --test astra_cleanup_publication_order -- --nocapture
```

Result: **1 passed**, 2.71s, including the original-Python comparison. Strict Clippy for this new test and `git diff --check` passed.

The bounded fixture correction should observe socket absence **and** cancelled state within the same existing ten-second socket-completion deadline, then retain both exact assertions. Do not add another ten-second allowance, accept `running`, remove socket checks, or change product finalization/audit ordering. Fresh affected checks and final exact-head full macOS/Linux results remain required. This report is controlled ordering evidence, not overall acceptance or permission to waive the historical failure.
