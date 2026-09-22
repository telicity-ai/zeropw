# Astra CLI and runtime review, round 2

- Actual reviewer model: `gpt-6-astra`, independent reviewer. No Opus verdict is claimed.
- Review date: 2026-09-22.
- Initial revision: `6aed2eac3902535eff7fd16444a9c29bb9ee2ab9`; final reviewed revision: `7536e49647fe322e954f37d65a530d9cd2b5499f`.
- Product sources under review: runtime changes `391e097f05a6803ca61a64ba47242130329d1492`, boundary tests `d44eebe85dc6dd83fc57b3ba576a9b8135356af2`, integrated CLI fixes including the final quiet-mode wiring at `7536e49`.
- Scope: original AR-RUNTIME-01–04, retained registry ownership, session helper/ACK/spawn/cancellation/descriptor boundaries, HEAD errors and optional logging; significant administrator CLI fixes, recovery/restore/audit/error paths and interactive passphrase entry.
- Decision: **REVISE. Two new reproduced runtime findings and one new CLI finding remain open. This bounded review is not full-product acceptance.**

All state, file contents, keys and passphrases used here were synthetic. Children and listeners were controlled locally. Test commands used `env -i PATH=/Users/ys/.local/bin:/Users/ys/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin`. No product code or old finding evidence was changed. The latest user decision in `docs/rust-completion.md` controls reviewer/model authority.

## Original runtime IDs

Original evidence and severity are retained in `astra-runtime-round1.md`.

| Original ID / severity | Disposition | Fresh evidence |
| --- | --- | --- |
| AR-RUNTIME-01 — Medium | Resolved | Unchanged independent discarded-return-value test passes. Context now strongly retains the registry, which holds a weak Context reference; directly constructed registries retain a direct Context owner. `installed_registry_retains_history_without_return_owner_and_drops_without_cycle` passes repeated installation identity, completed lookup/idempotency retention, revocation invocation, weak Context expiry and owned run-directory cleanup. Running supervision holds Context through completion. |
| AR-RUNTIME-02 — Medium | Partially resolved; remaining fix criterion open through AR-RUNTIME-05 | Unchanged new-session probe passes. Existing new session/group/no-controlling-terminal and descendant-cancellation tests pass. Trusted helper calls `setsid`, uses CLOEXEC ACK to distinguish successful exec from explicit failure, and preserves group cancellation. However, original fix criteria explicitly require closed unrelated descriptors; the independent AR-RUNTIME-05 test proves this boundary is still absent. |
| AR-RUNTIME-03 — Low | Resolved | Unchanged HEAD framing-error reproduction passes. Added Sol cases pass malformed header, duplicate Content-Length, Transfer-Encoding and absolute-URI errors; each returns HTTP 400 without HEAD body bytes. |
| AR-RUNTIME-04 — Low | Resolved at `7536e49` | Optional logging unit test passes: default quiet produces no entries; nonquiet output is nonempty, excludes query strings, and replaces handle routes with `/h/<handle>/...`. The coordinator identified `run_serve` initially omitted the quiet argument; final source now calls `new_with_quiet(..., quiet)`. No raw headers/bodies are added to the logger. |

## New findings

### AR-RUNTIME-05 — P1 / High — Unrelated trusted descriptors survive into the agent child

Locations: `rust/src/runs.rs:593` onward (`Command::new(helper)` spawn) and `rust/src/bin/zeropw_session.rs:10–35` (helper ACK/setsid/exec). Python reference: `zeropw/runs.py:306–308`, explicit `close_fds=True`.

Rust's spawn and subsequent helper exec do not close unrelated inheritable descriptors. The helper marks only its own ACK stream CLOEXEC. A caller can therefore enter the otherwise-clean execution path while a trusted descriptor remains open; the agent child can read its contents or use its authority. A clean environment and a new session do not remove these descriptors. This is a proven child-boundary defect, not a claim that a production secret was inspected or leaked.

Independent reproduction: `ar_runtime_05_unrelated_inheritable_descriptor_is_closed_in_agent_child` opens a temporary file containing `synthetic-trusted-fd-value-round2`, clears CLOEXEC on that one descriptor, and starts a controlled Python test child through the Rust registry. The child reads the descriptor and captures that value. Expected stdout is `closed\n`; actual stdout is `synthetic-trusted-fd-value-round2\n`. A Python subprocess oracle first verifies the same descriptor is available to its parent, then uses the original `close_fds=True,start_new_session=True` contract and obtains `closed\n`.

Fix criteria: close or mark CLOEXEC every unrelated descriptor before the target exec, including descriptors inherited into the trampoline. Preserve stdin/stdout/stderr, ACK success/failure semantics, target argv/environment, session isolation and group cancellation. Follow the safe-spawn/no-new-direct-unsafe project constraint. Retain the unchanged failing regression and test on macOS and Linux. Do not rely on all surrounding libraries or embedding callers always creating CLOEXEC descriptors.

### AR-RUNTIME-06 — P2 / Medium — HTTP execution now requires an existing SSH socket directory

Location: `rust/src/runs.rs:553–578`, ACK listener construction under `ctx.config.socket_dir`. Configuration contract: `rust/src/context.rs:306–327` accepts a supplied external directory without creating it.

A valid Context with a caller-supplied socket directory that does not yet exist previously supported ordinary HTTP-only CLI execution. The new trampoline binds an ACK socket inside that directory before every run. Without an unrelated prior signer setup, bind fails and `/usr/bin/true` becomes `failed/spawn_failed` without running. This is an introduced execution regression; it also makes a response containment test report zero cancelled runs because neither requested child ever started.

Independent reproduction: `ar_runtime_06_http_execution_accepts_uncreated_configured_socket_directory` initializes a Context with fresh external `provided-sockets` and `provided-runs` paths and starts `/usr/bin/true` directly through the registry. It gets `failed`, reason `spawn_failed`, expected `completed`. Unchanged `response::principal_lockdown_cancels_only_its_live_run` also fails at the original assertion `runs_cancelled == 1`, actual 0. The previous registry directly spawned the child; Python's original spawn path has no SSH socket-directory dependency.

Fix criteria: establish a private, usable ACK endpoint without requiring preinstalled SSH signer state; account for Unix socket path length, ownership/mode, cleanup and failed setup. Re-run both the independent case and original response cancellation case. Changing the response fixture to precreate the path would mask this product regression.

### AR-CLI-01 — P2 / Medium — Fast terminal passphrase entry is echoed before no-echo mode is enabled

Location: `rust/src/admin_cli.rs:425–437`, the `rpassword::prompt_password` call. Locked dependency: `rpassword 7.5.4`, `src/lib.rs:275–291` writes and flushes the prompt before `read_password_with_config` applies terminal settings in `src/unix.rs:129–148`.

The terminal prompt becomes visible while the terminal still has ECHO enabled. An immediate response, such as pasted or automated terminal input, can be echoed into the terminal transcript before the helper disables echo. Both administrator and recovery passphrases were observed in the synthetic transcript. The original Python getpass path disables echo before prompting and does not exhibit the same result.

Independent reproduction: `ar_cli_01_terminal_prompts_hide_both_passphrases` creates a real controlling PTY (`setsid` plus `TIOCSCTTY`), launches `init` with no passphrase environment variables, and writes each synthetic passphrase immediately after its prompt is visible. It first runs the identical PTY interaction against original Python and verifies successful initialization with neither passphrase in output. Native Rust also initializes successfully but its transcript contains both `synthetic-tty-admin-round2` and `synthetic-tty-recovery-round2`. The completed controlling-PTY reproduction failed twice before the final full test run. This is a timing-dependent echo window; the report does not claim ordinary slow typing always exposes a passphrase.

Fix criteria: establish no-echo mode before exposing either prompt, retain hidden interactive entry, and restore terminal settings on success/error/interruption. Keep the immediate-response test; adding a sleep before input would hide the boundary. An early fixture without a controlling terminal failed before prompt entry and was discarded as test setup, not finding evidence.

## CLI-C1 through CLI-C10 disposition

The original IDs/priorities and evidence remain in `native-cli-contract-round1.md`. The coordinator reports the original native admin 55-case contract, response CLI 8-case contract and agent 6-case contract passing after fixes. This reviewer inspected the relevant source and independently reran the highest-priority original restore case, but did not rerun all those suites. Therefore the rows distinguish the source/evidence review from a new complete independent CLI run.

| ID / original priority | Disposition in this bounded review |
| --- | --- |
| CLI-C1 — P1 | Resolved: connection-disable audit now includes the connection identity. Independently reran original `test_cli_restore_keeps_revocations_and_used_approvals`: PASS, 16 native admin launches, 3.824 seconds. Audit-only recovery keeps disabled authority and used approvals. |
| CLI-C2 — P2 | Fix accepted from source plus coordinator original-suite evidence: failed reveal, restore-ack/resume and recovery authentication emit value-free `auth_failed` records through the explicit failure helper. New interactive echo issue is separately tracked as AR-CLI-01. |
| CLI-C3 — P2 | Fix accepted from source plus coordinator original-suite evidence: denied secret/rotation/connection saves record `cli_env_contains_credential` and relevant identities; local save checks/write retain the state lock. Deterministic cross-process save-time-race evidence is still separately required below. |
| CLI-C4 — P2 | Fix accepted from source plus coordinator original-suite evidence: activation records `connection_switch_credential` with connection/policy/secret/version fields before activation. The final lexical-only formatting correction does not change integer version semantics. |
| CLI-C5 — P2 | Fix accepted from source plus coordinator original-suite evidence: unusable credential version preserves its documented status detail. |
| CLI-C6 — P2 | Fix accepted from source plus coordinator original-suite evidence: SSH host key handling uses the common canonical parser and preserves invalid-key error mapping. |
| CLI-C7 — P2 | Fix accepted from source plus coordinator original-suite evidence: malformed authority is checked with the original invalid-host ordering. |
| CLI-C8 — P2 | Fix accepted from source plus coordinator original-suite evidence: nonexistent backup parent maps to `file_not_found`; no parent is silently created. |
| CLI-C9 — P2 | Fix accepted from source plus coordinator original-suite evidence: semantic state errors expose only the fixed permitted exception-class detail, syntactically invalid JSON retains document identity, wrapped-key errors retain their specific reason. The original malformed-state matrix permits a set of built-in identities; this review does not claim exact subclass identity beyond those assertions. |
| CLI-C10 — P2 | Fix accepted from source plus coordinator original-suite evidence: ASCII digits, recognized unit, range and duration multiplication are enforced. Earlier SSH/team E2E success is coordinator evidence, not a new run in this review. |

Original Python tests that monkeypatch `sys.modules['zeropw.tools']` or `sys.modules['zeropw.signer']` to None are **inapplicable as dynamic-module-removal tests** to statically linked Rust modules. They are not fake-passed or silently covered by a success test. The equivalent product requirement is that linked functionality is present and actual initialization failure produces a safe explicit error; native server initialization error paths still propagate errors. Missing trampoline artifacts are a distinct runtime setup failure, not the Python optional-module condition. The original captured-Context serve revocation and save-time-lock-race tests also remain explicitly unmapped by the adapter; native process evidence and a separately controlled race test must satisfy their behavioral intent.

## Verification and limits

Executed original/worker regression suites on the integrated runtime:

```text
cargo test --offline --test astra_runtime_review --test runtime_fix_boundaries --test runs -- --test-threads=1
  astra_runtime_review: 5 passed
  runs: 16 passed
  runtime_fix_boundaries: 2 passed

cargo test --offline --test response principal_lockdown_cancels_only_its_live_run -- --exact --nocapture
  failed: runs_cancelled expected 1, actual 0 (explained by AR-RUNTIME-06)

cargo test --offline --test astra_cli_runtime_round2 -- --test-threads=1
  0 passed, 3 failed, 7.78 seconds (all three documented reproductions)

cargo clippy --offline --test astra_cli_runtime_round2 -- -D warnings
  passed
```

The new independent `rust/tests/astra_cli_runtime_round2.rs` intentionally preserves the three failing reproductions for the new IDs. Python subprocesses are test oracles only. No result here approves forthcoming Sol fixes; these require fresh unchanged-test reruns against the new SHA. No new process E2E or Linux execution is claimed. Full test inventory mapping, host isolation, the previously recorded team coverage gaps and complete integration acceptance remain separate work.

Review artifacts: this report and `rust/tests/astra_cli_runtime_round2.rs`, left uncommitted for the coordinator. Open IDs: AR-RUNTIME-02's descriptor fix criterion, AR-RUNTIME-05, AR-RUNTIME-06, AR-CLI-01.
