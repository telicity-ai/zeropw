# Astra final bounded CLI/runtime review

Actual reviewer: `gpt-6-astra`, 2026-09-22; no Opus verdict is claimed.
Product revision: `318386de404ccbff4cdd8c3e0a79dbb1a4aa25e0`.
Final source comparison: `9bc858ef588a61076809f69a4f96ceb605e85b6a`.
The five reviewed product files (`admin_cli.rs`, `agent_cli.rs`, `runs.rs`,
`tools.rs`, `server.rs`) have no diff between those revisions. Concurrent
documentation/review changes do not extend this review's scope.

Decision: **PASS for the bounded macOS CLI/runtime fixes.** AR-CLI-03,
AR-RUNTIME-08 and AR-CLI-04 are resolved with the evidence below. Earlier
AR-CLI-01/02 and AR-RUNTIME-01–07 dispositions remain resolved in their
previously stated scope. No new finding was demonstrated. This is not complete
product acceptance, Linux verification, or approval of deployment isolation.
Original reports, IDs, severity and assertions are retained unchanged.

## Findings and fix verification

| Original ID / severity | Independent disposition |
| --- | --- |
| AR-CLI-03 / P2 | Resolved. Unchanged round-4 controlling-PTY reproduction now terminates after a successful prompt for both SIGINT and SIGTERM, with original terminal modes restored. Python exits 130 / signal 15; native exits signal 2 / signal 15. Conditional default handlers remain registered for process lifetime and are armed outside the serialized prompt region. The restoration guard restores termios before arming them, closing the iterator and joining the watcher. |
| AR-RUNTIME-08 / P2 | Resolved. The unchanged original private-run-directory test passes, including a separate run under umask 000. Both HOME and internal ACK directory builders explicitly supply mode 0700 before creation. Inspected locked tempfile Unix implementation forwards that permission to `DirBuilderExt::mode` before `create`, so there is no create-then-chmod interval. ACK's short owned directory and cleanup remain unchanged. Live ACK mode was not separately sampled; its atomic creation evidence is source plus the dependency implementation, not an asserted cross-UID attack test. |
| AR-CLI-04 / P3 | Resolved. Root `-h`/`--help` and all five subcommand help operations match original Python stdout/stderr/status with gateway configuration absent. `exec --connection synthetic -- --help` retains literal child arguments and fails with `gateway_url_unset` rather than showing agent help. Unknown-command behavior is retained. |

Active Ctrl-C and SIGTERM restore terminal modes; EOF also restores them.
The unchanged immediate-input test verifies both administrator and recovery
passphrases remain hidden without an input delay. The new independent
`astra_runtime_final` adds recovery-prompt Ctrl-C, EOF and invalid UTF-8 input
after a completed first prompt. All three terminate unsuccessfully and restore
the caller's terminal modes. This reuses the original surviving-session PTY
fixture without changing its original tests or weakening any assertion.
Source inspection confirms early setup errors occur before noecho is applied;
after the restoration guard is constructed, subsequent mode/write/read errors
unwind through that guard. Arbitrary kernel failures and every possible signal
interleaving are not exhaustively injected.

Audit-gated terminal publication, suppression of output on audit failure,
reentrant audit queries/cancellation, sibling cancellation, owner checks,
unrelated-descriptor closure, new sessions, spawn failure and group cancellation
all pass their retained regressions. Sanitized optional logs and HEAD error
framing also pass. The new fixes do not change those product paths.

## Fixture-only change 07e816d

Independently inspected the diff: it keeps script(1)'s input pipe open until
the CLI consumes the recovery password and exits, adds a 15-second deadline,
and preserves success/state/no-passphrase-output assertions. Immediate close
can truncate PTY delivery. A fresh original Python probe initially succeeded
once; eight subsequent original Python runs all exited 1 with `EOFError`.
The native immediate-close probe also exited 1. With input held open, both
Python and native exited 0, initialized state, and omitted both synthetic
passphrases from output. This is a measured fixture race, not a waiver for a
native prompt defect. The distinct immediate-response controlling-PTY test
remains unchanged and passes.

## Executed checks

All children, credentials, state and endpoints were synthetic/local. Commands
used an empty inherited environment and explicit Cargo/Python/system PATH.
An initial Cargo attempt failed before compilation because disk space was
exhausted; after the coordinator removed completed worker build caches, the
following fresh reruns passed. No failed storage test was counted as success.

| Suite | Result |
| --- | --- |
| `agent_help` | 2 passed |
| `astra_cli_runtime_round2` | 3 passed |
| `astra_cli_runtime_round3` | 3 passed |
| `astra_cli_runtime_round4` | 4 passed |
| `astra_runtime_final` | 1 passed, three recovery-prompt failure modes |
| `astra_runtime_review` | 5 passed |
| `runs` | 17 passed |
| `runtime_fix_boundaries` | 2 passed |
| `tools_server` | 25 passed |
| `cli_commands` | 12 passed |
| Private-directory case with umask 000 | 1 additional pass |
| Clippy for `astra_runtime_final`, warnings denied | passed |
| `git diff --check` | passed |

The principal invocation was `cargo test --offline --test agent_help --test
astra_cli_runtime_round2 --test astra_cli_runtime_round3 --test
astra_cli_runtime_round4 --test astra_runtime_final --test astra_runtime_review
--test runs --test runtime_fix_boundaries --test tools_server --
--test-threads=1`; `cli_commands` and the final strengthened new test ran
separately. Native process E2E and whole-product integration are coordinator
work and are not presented as fresh reviewer results here. Linux and complete
original-feature acceptance remain pending separately.

Changed artifacts: this report and `rust/tests/astra_runtime_final.rs` only.
No product, old test/report, CI, harness, instruction or trusted-checkout edit;
no merge, push or deployment. Unresolved IDs within this bounded review: none.
