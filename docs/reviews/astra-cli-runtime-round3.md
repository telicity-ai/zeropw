# Astra CLI and runtime review, round 3

- Actual reviewer model: `gpt-6-astra`, independent reviewer; no Opus verdict is claimed.
- Review date: 2026-09-22.
- Fix revision reviewed and tested: `db4fc5ee9e23f3c3f118e88137039501cc8a4bad`, incorporating runtime fix `837ae6f` and interactive prompt fix `db4fc5e`.
- Final source comparison: `d27b97780a99fca4f2ae896888db69240790b5fe`. The three reviewed product files (`runs.rs`, `admin_cli.rs`, `bin/zeropw_session.rs`) are unchanged between these revisions. Intervening documentation/team-test commits are not accepted by this bounded review.
- Scope: AR-RUNTIME-05/06 and the descriptor criterion of AR-RUNTIME-02; AR-CLI-01 and terminal interruption/EOF; the reported intermittent native demo output assertion.
- Decision: **REVISE. AR-RUNTIME-07 and AR-CLI-02 are confirmed and open. No full-product or Linux acceptance is claimed.**

All credentials, state, descriptor contents and subprocess output were synthetic. Commands ran with a clean environment: `env -i PATH=${HOME}/.local/bin:${HOME}/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin`. No product files or earlier finding reports/tests were changed. The latest user decision in `docs/rust-completion.md` controls reviewer/model authority.

## Existing finding dispositions

Original IDs, severities and evidence remain unchanged in rounds 1 and 2.

| ID / original severity | Disposition and fresh evidence |
| --- | --- |
| AR-RUNTIME-05 — P1 / High | Resolved for the exercised macOS boundary. The unchanged synthetic inheritable-file-descriptor regression now passes, including the original Python `close_fds=True` oracle. The single-thread session helper marks all descriptors >=3 CLOEXEC before target exec; stdin/stdout/stderr remain available. Existing session, ACK/exec failure and cancellation tests pass. Linux verification remains pending. |
| AR-RUNTIME-06 — P2 / Medium | Resolved. The unchanged valid-but-uncreated configured socket-directory test passes. ACK now uses an owned short private temporary directory under `/tmp`, independent of the configured SSH socket path, with RAII cleanup. The original response principal-lockdown cancellation test now passes unchanged. |
| AR-RUNTIME-02 — Medium | Its remaining descriptor criterion is resolved by the AR-RUNTIME-05 evidence above; unchanged session/group/no-controlling-terminal and cancellation tests pass. This is bounded macOS evidence, not a claim of a Linux run. |
| AR-CLI-01 — P2 / Medium | The prompt-before-noecho leak is fixed: unchanged immediate-input PTY test passes for both administrator and recovery prompts. EOF restoration also passes. Its full interruption-restoration criterion remains open through new AR-CLI-02 below. |
| AR-RUNTIME-01 / 03 / 04 — Medium / Low / Low | Prior resolved dispositions retained; unchanged independent runtime tests and HEAD/logging boundary tests pass. No new CLI contract-wide acceptance is inferred. |

The `close_fds 0.3.2` implementation was inspected locally, including its Linux `close_range(CLOEXEC)` fast path and descriptor-enumeration fallback. The public `set_fds_cloexec(3, &[])` API returns no error; its individual `fcntl(F_GETFD/F_SETFD)` fallback ignores failures. Consequently this review does not claim that every kernel-level failure is reported or that fail-closed behavior under arbitrary `fcntl` failure was proved. The single-thread helper matches the dependency's usage assumptions, and no surviving unrelated descriptor was reproduced after the fix under the controlled normal-OS test. This documented limitation is not invented into a new demonstrated exploit; neither is it hidden behind the passing regression. Product code adds no direct unsafe block.

## New findings

### AR-RUNTIME-07 — P2 / Medium — Terminal status can precede captured output publication

Location: `rust/src/runs.rs:709–758`, especially terminal state/exit/timestamp writes at 715–718 and output writes at 745–748.

`finalize` publishes the terminal state and releases the run lock before recording `run_finish`. Only after that synchronous audit operation returns does it publish captured stdout/stderr and truncation metadata. Concurrent status readers can therefore observe `completed` with empty stdout for a child that successfully printed business output. A client treating terminal status as final can permanently miss the result; if the audit later fails it can also have observed a premature success before the final failure outcome.

Independent deterministic reproduction: `ar_runtime_07_terminal_status_never_precedes_captured_output_publication` starts `/usr/bin/printf business-output` and pauses a synchronous `run_finish` audit listener behind a bounded condition-variable gate. While finalization is paused, an independent status query returns `state=completed, stdout=[]`. Releasing the gate produces the eventual correct `completed` result with `business-output`. The test accepts either a nonterminal early view or a query that waits for complete publication; it rejects only terminal/incomplete output. The gate is released and the child/finalizer are allowed to complete before assertion failure.

The same controlled audit gate against original Python `_finalize` returns terminal status together with `business-output`: Python updates the fields together under its lock. This comparison establishes the observable parity regression; it is not a recommendation to copy Python's pre-audit output visibility into Rust. Rust must preserve its existing fail-closed output withholding on audit failure.

This is a proven mechanism consistent with the reported intermittent native demo failure (`child receives routing only, not state authority`, missing/undecodable captured `env_names`). That historical failure was not captured sufficiently to prove its exact cause, so this review does not assert a definitive retrospective attribution or dismiss it as harmless flakiness.

Fix criteria: stage outcome and audit metadata, finish the required audit, then publish terminal state, reason, exit code, timestamp, stdout/stderr and truncation metadata as one consistent result. Preserve output suppression on audit failure, completion notification, ownership, cancellation and idempotency. Do not hold the run mutex across arbitrary synchronous audit listeners merely to hide this race: listeners may themselves query or cancel runs. Retain the deterministic regression.

### AR-CLI-02 — P2 / Medium — Ctrl-C leaves the caller's terminal echo disabled

Location: `rust/src/admin_cli.rs:425–453`, outer terminal-restoration guard around `rpassword::prompt_password`.

The outer guard correctly disables echo before showing the prompt. However, `rpassword 7.5.4` then captures that already-noecho terminal mode as its own original mode. Its Ctrl-C handling restores its own saved mode and sends SIGINT. Default signal termination occurs before the outer Rust guard's Drop can restore the actual caller's original settings. The caller returns to a terminal with ECHO disabled.

Independent reproduction: `ar_cli_02_interrupt_restores_original_terminal_modes` uses a real controlling PTY with a surviving session keeper and a separate foreground process group for the CLI. Immediately after the administrator prompt appears, the test sends Ctrl-C and checks terminal settings from the surviving keeper. Original Python restores the settings and passes. Native Rust exits from SIGINT (`-2`), with `lflag` changing from 1483 to 1475: the ECHO bit (8) is absent. This is actual terminal state after target exit, not an inference from absent output.

The companion `terminal_eof_restores_original_terminal_modes` sends Ctrl-D at the same prompt and passes for both Python and Rust. The success-path immediate-input regression also passes unchanged. The PTY comparator ignores only macOS's transient PENDIN queued-input flag, not echo, signal, canonical or other configured terminal modes. Earlier non-surviving-session fixture attempts encountered terminal teardown and were discarded as fixture failures, not counted as product findings.

Fix criteria: restore the caller's real original terminal mode before signal termination, or handle interruption in a way that permits reliable restoration before exiting. Preserve noecho-before-prompt behavior and normal success/error/EOF semantics. Retain real PTY immediate-input, Ctrl-C and EOF tests; a delay before input or a changed initial noecho fixture is not an acceptable fix.

## Verification

Executed on macOS against the reviewed product source:

```text
cargo test --offline --test astra_cli_runtime_round2 --test astra_runtime_review --test runtime_fix_boundaries --test runs -- --test-threads=1
  astra_cli_runtime_round2: 3 passed (unchanged)
  astra_runtime_review: 5 passed (unchanged)
  runs: 16 passed
  runtime_fix_boundaries: 2 passed

cargo test --offline --test response principal_lockdown_cancels_only_its_live_run -- --exact --nocapture
  1 passed (unchanged)

cargo test --offline --test astra_cli_runtime_round3 -- --test-threads=1
  1 passed: terminal EOF restores original terminal modes
  2 failed: AR-RUNTIME-07 and AR-CLI-02, documented above

cargo clippy --offline --test astra_cli_runtime_round3 -- -D warnings
  passed

git diff --check
  passed
```

Artifacts: this report and `rust/tests/astra_cli_runtime_round3.rs`, left uncommitted for the coordinator. The new tests intentionally retain the two failing reproductions. Python is used only for controlled original-behavior oracles and PTY fixtures. No forthcoming fix is approved by this report; both IDs require fresh unchanged-test reruns. Linux, complete behavioral inventory mapping, broader team QA and final product acceptance remain separate work.
