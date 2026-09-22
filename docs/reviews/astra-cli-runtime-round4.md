# Astra CLI and runtime review, round 4

Actual reviewer: **gpt-6-astra**, 2026-09-22. No Opus review is claimed.
Product fix reviewed: **d2c87eb9ebce64b409a2421ad4e09e3a7b897c40**.
Initial tested checkout: **76e4eed03d35330c2bd9498a764ab5a4bd1c4626**.
Final source comparison: **f0de879965337aa92554efcfe8630039f4528435**.
`runs.rs`, `admin_cli.rs`, `tools.rs`, and `agent_cli.rs` are unchanged between
those tested/comparison revisions (`git diff` verified). Concurrent response
fixes and test/documentation changes are not accepted by this lifecycle review.

Decision: **REVISE**. The original AR-RUNTIME-07 and AR-CLI-02 defects are
resolved in the measured macOS scope. Three separately demonstrated findings
remain: AR-CLI-03 (P2), AR-RUNTIME-08 (P2), AR-CLI-04 (P3). Original reports,
IDs, severity and test assertions remain intact.

All state, passphrases, subprocesses, PTYs and contents were synthetic and
locally controlled. Commands use a clean test environment. No product source,
old review/test, coordinator tool test or runtime configuration was edited.
Only this report and `rust/tests/astra_cli_runtime_round4.rs` are added.

## Original finding disposition

| ID / original severity | Disposition and fresh evidence |
| --- | --- |
| AR-RUNTIME-07 — P2 / Medium | Resolved. The unchanged audit-gated terminal/output regression passes. Final outcome metadata is staged, the run lock is released before synchronous audit callbacks, and terminal state/reason/exit/timestamp/output/truncation are published together after audit succeeds. Existing audit-failure tests still suppress output. Worker reentrant callback test and new independent sibling-cancellation test pass. |
| AR-CLI-02 — P2 / Medium | Resolved for original active-prompt interruption. The unchanged real controlling-PTY Ctrl-C and EOF tests pass. New native SIGTERM-at-prompt test also observes restored original terminal modes. The nested rpassword termios owner is removed. A newly introduced post-prompt signal lifetime defect is AR-CLI-03 below, not a severity change or rewrite of AR-CLI-02. |
| AR-CLI-01 — P2 / Medium | Resolved for original noecho-before-prompt criterion. Unchanged immediate-input administrator and recovery prompt regression passes; active Ctrl-C/EOF/SIGTERM restoration now has measured evidence. |
| AR-RUNTIME-05 / 06 — P1 / P2 | Prior dispositions retained and unchanged round-2 descriptor-inheritance and absent-configured-socket-directory tests pass. Evidence remains macOS only; no Linux run is claimed. |
| AR-RUNTIME-01–04 | Prior dispositions retained. Existing ownership, session/group, spawn, cancellation, HEAD and logging boundaries pass in the selected suites. This does not expand the original acceptance scope. |

Finalization's flag prevents a synchronous `run_finish` callback from trying
to wait on its own unfinished callback. The new
`finish_audit_callback_can_cancel_another_live_run` independently verifies that
this exclusion does not skip another still-running child: the listener reads
the finisher as running with no output, cancels its sibling with the expected
reason, and returns; the finisher subsequently publishes its complete output.
No newly demonstrated lost live-child cancellation was found in this bounded
review. This is not a proof of every possible scheduling interleaving.

## New findings

### AR-CLI-03 — P2 / Medium — Completed password prompts leave termination signals ignored

Location: `rust/src/admin_cli.rs:425–441,451–477,508`.

The prompt installs SIGINT/SIGTERM actions with signal-hook, then its Drop
closes the iterator and joins its watcher. Dropping those registrations does
not restore the default/previous OS signal handler. The installed
signal-hook-registry `unregister` documentation explicitly states this: after
the last action is removed, SIGTERM can be effectively ignored. No remaining
action in this CLI path handles these signals after successful prompt return.

Independent reproduction:
`terminal_prompt_completion_preserves_later_interrupt_and_termination` uses
the actual native administrator binary and a real controlling PTY. A surviving
session keeper avoids terminal-teardown artifacts. After `restore-ack` has
shown its administrator prompt, the test replaces only the synthetic next
verification input with an anchored FIFO, submits a synthetic passphrase,
observes ECHO restoration, and sends SIGINT or SIGTERM while that read waits.
The same fixture runs the original Python CLI.

| Signal after prompt completion | Original Python | Native Rust |
| --- | --- | --- |
| SIGINT | Exits 130 | Remains alive; test must kill it |
| SIGTERM | Exits from signal 15 | Remains alive; test must kill it |

Both languages have already restored terminal modes; this is lost interrupt
handling after input completion. Two runs reproduce the native failure.
Initial fixtures that made the target the terminal session leader hit macOS
terminal teardown even for Python; those were discarded as fixture failures,
not counted as product evidence. The retained keeper fixture cleanly observes
and cleans up each target.

Fix criteria: preserve normal signal behavior after successful/error prompt
cleanup as well as restoring original termios before active-prompt signal
termination. Retain the immediate-input, Ctrl-C, EOF, active SIGTERM and
post-prompt SIGINT/SIGTERM regressions. Do not fix by leaving signals ignored
or delaying password input.

### AR-RUNTIME-08 — P2 / Medium — Per-run directories lose the required private mode

Location: `rust/src/tools.rs:676–679`; the same default builder is used for the
internal ACK directory at `rust/src/runs.rs:565–567`.

The coordinator's direct port of the original fixed-program/private-directory
contract was independently rerun unchanged:
`tools_server::original_fixed_program_and_fresh_private_run_directories` fails
at line 1230 with actual mode decimal 493 (**0755**) versus expected 448
(**0700**). It reads the directory used as HOME by an actual running controlled
child. A fresh original Python `tempfile.TemporaryDirectory` under umask 0022
independently reports 0700.

Rust's `tempfile::Builder` call does not specify permissions. The installed
Unix implementation uses `std::fs::DirBuilder` without a mode unless explicitly
provided, giving the ambient 0777-and-umask result. The ACK builder under `/tmp`
has the same source-level defect despite its private-directory comment; its
short-lived live mode was not separately captured in this review. Context's
existing private-directory helper already creates directories atomically as
0700, so this is not an accepted project-wide permissions change.

Fix criteria: create both per-run and internal ACK directories atomically with
0700 regardless of permissive ambient umask; preserve uniqueness, cleanup and
short Unix socket paths. Do not rely on the enclosing run-root directory or
change the user's process umask. The demonstrated defect is mode-contract
failure; no cross-UID credential read or ACK takeover was attempted or claimed.

### AR-CLI-04 — P3 / Low — Agent help is treated as an invalid command

Location: `rust/src/agent_cli.rs:447–455` and its argument parser.

With gateway/token variables absent, original
`python3.12 -m zeropw.agent_cli --help` exits 0 and prints command/options help
to stdout. The native binary exits 2, printing `invalid choice: --help` to
stderr. This removes an existing offline CLI operation and leaves users unable
to discover the native client's options through the documented help flag.

Independent command comparison and
`native_agent_help_is_a_successful_offline_operation` both reproduce this.
Fix top-level `-h`/`--help` and original subcommand help behavior without
requiring connection configuration or making network calls. The retained test
includes those forms; its current first failure is top-level `--help`.

## Executed evidence and limits

- Unchanged `astra_cli_runtime_round2`: **3 passed**, 8.16s.
- Unchanged `astra_cli_runtime_round3`: **3 passed**, 2.61s.
- `runs`: **17 passed**, 36.16s, including audit failure/output suppression,
  listener cancellation before spawn and listener query/cancellation during
  finalization.
- `runtime_fix_boundaries`: **2 passed**, 4.50s.
- Full `native_cli_e2e`: **8 passed**, 231.12s. This executes the original
  administrator and agent contracts, real-sshd SSH, HTTP, team, compromise,
  response CLI and response polling scenarios using native product binaries.
- New round-4 PTY/help run: **1 passed, 2 failed**, 8.96s; active-prompt SIGTERM
  restoration passed, post-prompt signals and help failed as above.
- New independent sibling-cancellation case: **1 passed**, 2.68s.
- Original private-directory contract: **1 failed**, 2.74s; exact mode evidence
  above. The coordinator-owned reproduction is committed in `c5124a9` and was
  not edited by this reviewer.
- `cargo clippy --offline --test astra_cli_runtime_round4 -- -D warnings`:
  **passed**, 1.03s.

Selected tests were executed while the coordinator added separate test/docs
and response fixes; the four reviewed product files remained unchanged. These
results are component evidence bound to the identified source revisions, not
a full exact-head CI result. Linux, complete behavior inventory and final
product acceptance remain separate work. No merge or deployment was performed.
