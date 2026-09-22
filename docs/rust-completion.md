# Complete Rust implementation and acceptance

Current user decision (2026-09-22): implement all existing ZeroPW functionality
in Rust in parallel. Astra is the product owner and QA/reviewer; a new Opus
verdict is no longer required. This supersedes the previous first-half scope
and Opus review requirement for this task. Existing security requirements and
the Python behavioral-equivalence contract still apply.

Implementation uses three explicitly selected `gpt-5.6-sol` workers in separate
local worktrees, with coordinator-owned runtime integration. This execution is
local; it is not described as an always-on cloud worker. Independent review
will explicitly select `gpt-6-astra` and record the code revision reviewed,
findings, fixes, and rerun evidence. Earlier PASS results do not approve new code.

## Full scope and acceptance evidence

Latest component checkpoint: the additional offline-fact delivery finding
ASTRA-TEAM-T6/P1 and concurrent ordinary-fact processing finding
ASTRA-TEAM-T7/P2 have independent bounded Astra closures. Their final tested
product is included in `2e88f88`; see the post-Linux handoff below. The failed
Linux run `35706839572` at `e8610ac` remains historical failure evidence, not
approval of this revision. Full-platform acceptance must use the exact final
PR head and its actual check results; component closure does not replace it.

| Area | Required implementation and proof | State |
| --- | --- | --- |
| Existing first half | Existing Rust foundation, crypto, vault, policy, gateway, signer and team data continue to pass their complete suites | Full integrated snapshots 318386d and 019b92e pass; persisted-project A-R2-6(b) correction independently accepted |
| Execution | Run registry, ownership, bounded capture, redaction, idempotency, timeout, process-group cancellation, audit failure boundaries | Astra bounded runtime acceptance at 318386d; all eight runtime findings resolved, including creation-time directory modes |
| Native tools and server | All five tools, HTTP relay, strict framing, caller authentication, listener limits, polling and shutdown | Bounded runtime review and 25 tool/server tests pass; final-head platform acceptance pending |
| Incident response | Incident assessment/lockdown/widen/close, detector rules, SMTP delivery and retry, value-free outputs | Astra bounded response acceptance at 897c9a6: all 16 findings resolved, 72 selected test functions pass |
| Team networking | Authenticated transport, sync, facts, snapshots, invitation/join/removal, DEK rotation, incident sharing | Prior bounded 104 checks and original native process E2E pass; T6/P1 reconnect catch-up and T7/P2 concurrent ordinary-fact processing independently closed with 27 and nine selected checks; 62-method map and explicit native API distinctions retained |
| User interfaces | Full administrator and agent CLI command trees, demo, native Rust executables | Original native-oracle contracts pass; AR-CLI-01–06 resolved, including handled SIGINT status and exact-owned-directory cleanup |
| Integration QA | Cross-language state/wire compatibility; separate-process CLI/API/SSH/team scenarios; negative tests for secret leakage and authorization | Original HTTP, real-sshd SSH, three-node team and compromise E2E pass; final overall decision must use exact PR-head checks and the handoff below |
| Astra review | Independent product and adversarial review of integrated revision; all findings resolved with evidence and a clean rerun | All recorded remediation findings, including T6/P1 and T7/P2, have independent bounded closures. Original reports remain immutable. Component PASS is not itself final-head platform/deployment approval |

Completion requires the full Python feature inventory, meaningful behavioral
tests for each feature and failure boundary, Linux and macOS verification where
platform behavior matters, and Astra review with no unresolved findings.
Python subprocesses are permitted as test oracles only, never as a Rust product
backend. Missing APIs, placeholder successes, and silently unsupported existing
commands do not satisfy acceptance. Deployment and merging are separate actions.

## Initial integrated evidence (historical, not current status)

At integration `63ff815` the native execution/tools suites pass 30 tests and
all-target Clippy passes with warnings denied. The earlier integrated CLI/team
test run passes 6 CLI and 7 team cases. These are bounded results, not acceptance.

`rust/tests/native_cli_e2e.py` is a test-only launch adapter for the original
Python multi-process cases. It leaves their assertions and controlled endpoints
unchanged, replaces admin/agent launches with Rust binaries, and uses the native
demo CLI. The original compromise-response E2E passes (18 admin launches, 6 agent
launches), including automatic lockdown, SMTP delivery, recovery and leak scans.
The initial original HTTP case fails because native democli lacks `whoami`;
the SSH and team cases fail because the CLI TTL parser treats `1h` as one second.
These are confirmed implementation defects assigned to the Sol CLI worker,
not approved deviations. Real sshd started successfully in the local SSH run;
that run is not a full SSH PASS.

Response review is by actual `gpt-6-astra` at
`692fc7566005f2dcd25e9b48fd401031f01c79de`: 2 P1 and 12 P2 findings remain open
until fixes are independently verified. Existing 18 response tests passed but
6 added independent review cases failed. The report is preserved as
`docs/reviews/astra-response-round1.md` in the response worker branch and will
be integrated with its fixes. Recording a capability removal in DEVIATIONS
does not waive a finding.

## Subsequent verification and remaining work

The TTL/demo failures above were fixed and the four unchanged original process
scenarios now pass using native binaries: HTTP (13 admin/17 agent launches), real
sshd SSH (13/20), three-node team (38/6), and compromise response (18/6). SSH was
actually exercised, not skipped. The full original black-box administrator
contract subsequently passed 55 cases with 553 native launches; response CLI
passed 8 cases with 42 launches; agent CLI passed 6 cases. See the test-only
adapter in `rust/tests/native_cli_e2e.py` for its explicitly unmapped in-process
mock cases. `native_atomic_cli` separately passes 24 real-process save races.

Actual Astra reports are retained in `docs/reviews/astra-response-round1.md`,
`astra-team-round1.md`, and `astra-runtime-round1.md`. Runtime round 1 identifies
four defects; its independent tests demonstrated three failing cases. A Sol
worker is fixing retained registry ownership, new-session isolation, HEAD error
framing, and optional value-free request logging. Response/team fixes passing
their original regression tests do not yet amount to independent round-2
approval. `native-cli-contract-round1.md` is coordinator test evidence, not an
Astra review. Its original C1–C10 findings have passing worker rerun evidence.

All figures are bounded results, not a blanket port-completion claim. Complete
integrated tests, remaining original-feature coverage, independent review, and
Linux/macOS verification remain acceptance work. No merge or deployment has
been performed.

## Later review rounds and integrated checks

Team round 2 independently resolves all five original IDs with eight additional
tests, 13 previous networking/review tests and 105 team library cases passing.
It explicitly retains a mapping/coverage limit. A subsequent team QA task was
interrupted twice by the review tool; its partial handoff and coordinator-only
fixture corrections/eight passing lifecycle tests are recorded separately in
`docs/reviews/astra-team-round3-partial.md`, not counted as independent approval.

Response round 2 independently verifies both original P1 fixes, successful
trusted STARTTLS/SMTPS, certificate rejection and CRAM authentication, but keeps
four original functional IDs open (AUTH/ENVELOPE/ERRORS/SHAPE), adds two P2 IDs
(COUNTER/CONFIG), and leaves its coverage gate open. A Sol worker is implementing
those fixes against the unchanged new reproductions.

CLI/runtime round 2 found an inherited-descriptor boundary (P1), dependency on
an uncreated configured socket directory (P2), and prompt-before-no-echo race
(P2). Fixes through `db4fc5e` pass their three original independent regressions
in the worker run; the coordinator separately passes the two runtime cases.
Fresh Astra follow-up has identified terminal-state/output publication and
Ctrl-C terminal-restoration defects; those are not waived by earlier passes.

Bounded integrated execution also passed the 502 default library tests and all
four separately selected signer resource tests. The long policy differential
passed (465.85s), and the eight native process/CLI adapter tests passed
(162.93s). A then-current broad run failed the original live-run containment
test due to the already-confirmed missing socket-directory regression; after
that fix, the unchanged response 27, contract 8, runs 16, tools/server 17 and
remaining selected first-half integration suites pass. Builds changed during
this ongoing work: these are component results, **not** a single exact-head full
suite PASS. Final integrated verification and Linux CI remain required.

## Round-3/round-4 work (historical, 2026-09-22)

Actual Astra response round 3 retains four P2 functional IDs: ENVELOPE, ERRORS,
SHAPE and COUNTER. The immutable report is bound to `92abed0`. Sol's follow-up
`cef8ed3`, integrated as `4a526a2`, passes the original 8, round-2 10 and round-3
6 response review tests, response 27, contract 8, integer 2, canonical 4 and
affected team oracle 33 in worker verification. Those are fix evidence, not
independent acceptance. The worker corrected its own DATA-timeout expectation
only after measuring Python's `SMTPServerDisconnected`; no Astra assertion was
changed.

Coordinator native-process coverage now observes an actual live signer socket
before an externally declared manual incident, then verifies both HTTP/SSH run
cancellation and socket removal. The three process cases pass with 44 native
administrator and six native agent launches. `rust/RESPONSE_TEST_MAP.md` records
this evidence; it does not retrospectively change the round-3 review verdict.

Sol's `team_remaining_contract` adds nine cases, independently rerun by the
coordinator at `927690d`: share conversion and grant staleness, excluded local
connections, reauthentication/duplicate refusal, session renewal, nonempty TCP
capture, native listener behavior, remote widening cancelling a live HTTP run,
and remote disable removing a live signer socket. `rust/TEAM_TEST_MAP.md` maps
all 62 original methods and explicitly labels remaining partial assertions.

Lifecycle fix `d2c87eb` passes the unchanged terminal-publication and active
Ctrl-C restoration reproductions. Further Astra checking confirmed that after
a successful password prompt, SIGINT/SIGTERM can be ignored; coordinator and
Astra also reproduce new run directories created as 0755 instead of Python's
0700, and agent `--help` exits 2 instead of 0. These findings are assigned to
Sol and remain open. Original tool preflight/ownership/audit contracts pass six
new cases and the real relay text/binary/header-filter case passes; the fresh
private-directory assertion is intentionally retained failing until fixed.

## Compatibility checkpoint (historical, 2026-09-22)

The current table above supersedes the historical progress sections, which are
retained to preserve failures and their chronology. Actual `gpt-6-astra` reports
now independently close runtime/CLI findings AR-RUNTIME-01–08 and AR-CLI-01–04
(`astra-runtime-final.md`), all original team findings and bounded coverage
(`astra-team-round4-addendum.md`), and all sixteen response findings
(`astra-response-acceptance.md`, product `897c9a6`). The final response run
includes 334 Python-derived mailbox comparisons without discarding empty
results, and sixteen independent native/Python SMTP envelope fixtures.

The PO inventory (`astra-po-acceptance-checklist.md`) identified the obsolete
first-half scope waiver for persisted project shapes, A-R2-6(b). This is being
corrected, not accepted as a loss of functionality. A separate PO compatibility
disposition requires ordinary administrator SIGINT to return exit 130 as Python
does, rather than terminate by signal 2 (`Popen.returncode == -2`). This is
AR-CLI-05/P3, distinct from the already-resolved AR-CLI-03 termination/TTY issue.
Neither correction is counted as accepted before independent review.

Coordinator verification on the frozen exact revision
`318386de404ccbff4cdd8c3e0a79dbb1a4aa25e0` completed the unchanged
`cargo test --offline --locked --manifest-path rust/Cargo.toml --all-targets`
suite successfully. Its library result is 503 passed/four ignored; its long
policy differential passed in 452.87 seconds and all eight original native
process/CLI adapter tests passed. Formatting and all-target Clippy with warnings
denied also passed at that revision. The first loaded-host library attempt
failed the unchanged ten-cycle signer latency ceiling (57.759ms versus 25ms);
the full unchanged retry passed after concurrent build/review load subsided.
No threshold, assertion, CI or harness was changed to obtain that result.

All four normally ignored signer resource probes then ran serially and passed
at the same frozen revision (21.32 seconds). Measurements: 0.00/0.01 seconds
process CPU over five idle seconds with one/nine bindings; three descriptors
per binding, one server descriptor per client; 32 clients served at the host's
1048575 descriptor limit, cap refusal recorded, accept loop still alive. These
are host measurements, not a new cross-platform performance guarantee.

Later SMTP changes are outside that frozen full-run result and have their own
fresh affected-suite/Astra evidence. Final product-head integration and Linux
CI remain pending. Disk exhaustion during duplicate worker builds was an
environment failure; only regenerable completed-worker build caches were
cleaned, and affected checks were rerun. No source/review evidence was deleted.
No merge or deployment has occurred, and no full-product PASS is claimed yet.

## Earlier compatibility handoff (historical, 2026-09-22)

Actual Astra has now closed the remaining current-scope compatibility gates:

- Persisted project shapes: `astra-projects-and-signal-addendum.md`, product
  `cb88215`, preserves Python-successful iterable environments and arbitrary
  creation-time JSON without coercing environment membership.
- Ordinary administrator SIGINT status: AR-CLI-05/P3, product `80c7eea`, verified
  for active/completed prompts and non-prompt input; handled exit 130 remains
  distinct from OS signal termination. SIGTERM and graceful serve behavior
  retain their separate contracts.
- Owned-directory cleanup: AR-CLI-06/P2, `astra-sigint-cleanup-final.md`, product
  `c71ec3d` plus comment-only `ec58f8d`; 45 selected checks pass. The normal
  SIGINT watcher restores an active terminal before cleanup/exit, removes exact
  registered Context-owned paths, and prevents late registrations. Configured
  and unrelated paths remain untouched. Filesystem work is not performed in
  an asynchronous signal callback. This does not claim arbitrary exception
  unwinding, transaction rollback, or cleanup after every OS signal.

The complete frozen `019b92e` all-target suite also passed: library 504 passed
and four ignored, policy differential 459.98 seconds, all eight original native
process/CLI adapters 150.75 seconds. This includes the final mailbox and project
fixes but predates AR-CLI-06, so it is not proof of that later product revision.
At final cleanup snapshot `ec58f8d`, formatting and all-target strict Clippy
pass, default library tests pass 505/four ignored, and all four explicitly
selected signer resource probes pass (22.10 seconds). Resource measurements
remain three descriptors/binding and one server descriptor/client, cap 32
enforced with the accept loop alive. Idle CPU was below the macOS ps tool's
0.01-second resolution over each five-second sample. The full all-target run
for that snapshot was in progress when this handoff was written; its eventual
result must be recorded separately, not inferred from these component counts.

Two actual Linux candidate runs remain historical evidence:

- `35703888623`, head `5e2a131`: harness/format/Clippy/library pass; original
  Python PTY comparison times out and one unchanged Python team case fails.
  The latter is not a demonstrated Rust regression. A controlled reconnect
  reproduces a stale-session spy false negative, but the exact hosted
  interleaving remains unobserved (`astra-team-ci-triage.md`).
- `35705000593`, head `019b92e`: all 1099 original Python tests and harness pass;
  new ordinary/prompt SIGINT cases pass on Linux, but the new serve test races
  Python's post-banner handler installation. `astra-serve-readiness.md` records
  deterministic before-registration exit 130 and after-registration exit 0.
  The corrected fixture waits on an explicit readiness pipe and preserves the
  original graceful-exit assertions and startup deadline.

`astra-pty-portability.md` separately records controlled ignored/blocked-signal
inheritance and its fixture-only normalization. Neither fixture correction
changes a product behavior, skips a check, accepts the wrong outcome, or
relaxes a deadline. No Python product, original Python test, harness or CI file
was changed during this completion work.

Final acceptance is bound to the exact head and check results on
[PR 6](https://github.com/handlecusion/zeropw/pull/6), with a final Astra PO
disposition after integrated/platform validation. Do not treat an earlier
candidate's green checks or any historical report as approval of a later head.
This handoff records component closure and the evidence available at writing;
merge, deployment and production host-isolation approval remain separate.

## Post-Linux team correction handoff (2026-09-22)

Linux run `35706839572` at `e8610ac` passed the original 1099 Python tests and
harness checks but failed the Rust remote signer test in a generic wait.
The exact failed stage remains unknown; the later long policy step was skipped.
The independent triage report preserves this distinction. The completed full
macOS run at earlier cleanup product `ec58f8d` passed all integration targets,
including the 463.22-second policy differential and eight native process/CLI
adapters (151.01 seconds). That result is not proof of subsequent team changes.

Controlled investigation exposed required offline emergency-fact delivery
missing in both Python and Rust. Astra PO required correction under team
specification §6.6, not acceptance of the original defect. Sol implemented
authenticated reconnect catch-up in `5b9995c`, retaining receiver authorization,
signature/target/environment checks, INCIDENT isolation, removed-peer guards,
and exact-session cursor ownership. An additional actual concurrency test
found 20 stored ordinary facts but 22 application audit events; Sol's
`af1d455` gates ordinary side effects on atomic insertion ownership. Incident
artifact recovery and its ACK/outbox retries remain separate and unchanged.

Independent actual `gpt-6-astra` closures:

- `astra-team-fact-catchup-final.md`: T6/P1 resolved at `2e88f88`, 27 selected
  checks pass, including offline sender restart, more than one replay batch,
  malformed/incident/cross-environment/tampered outbound filtering, revoked
  version effects, current-role rejection, removed-peer restrictions, and
  actual cancellation of an already-running native SSH signer and run.
- `astra-team-fact-dedup-final.md`: T7/P2 resolved at `af1d455`, nine selected
  checks pass, including the unchanged 20-row/20-application regression and
  existing incident retry/restart/admin-removal boundaries. Product source is
  unchanged from `af1d455` through `2e88f88`.

The intermediate ledger-before-refold test failures and a worker's missing
socket assertion remain recorded. Test-only correction `2e88f88` waits for
ledger arrival and revocation within the same original 10-second bound and
publishes the synthetic signer marker by rename after writing it. Security
postconditions remain unchanged. Neither correction proves the cause of the
earlier unlabelled Linux failure or the worker's missing-socket observation.

Replay examines at most 64 ledger lines per VECTOR, not a bounded total ledger
read/CPU/memory budget. Already-admitted network sends cannot be retracted by
a concurrent removal. Current-role authorization at receipt is retained;
author-supplied timestamps do not restore revoked privilege. Ordinary fact
insertion ownership is not a crash-transactional exactly-once guarantee.
These measured boundaries are not universal CLI/network/RFC compatibility,
production isolation, or deployment approval.

The coordinator's new full macOS verification is frozen at `2e88f88`; at this
handoff's writing, formatting, strict all-target Clippy and 507 library tests
pass, with all-target integration still running. Subsequent reports/handoff
documentation do not change its product or test sources. Final completion is
recorded against the exact published head on PR 6 only after that run, the
final Linux checks, and Astra PO verification finish. No Python product,
original Python test, harness, CI or instruction file was changed, and no
merge or deployment occurred.

## Latest platform gate and refusal-callback correction (2026-09-22)

The complete frozen macOS run at `2e88f88` finished successfully: formatting,
strict all-target Clippy, 507 default library tests (four ignored), and every
integration target pass. The policy differential took 423.59 seconds, all
eight original native process/CLI adapters took 150.41 seconds, and the
22-case team contract suite took 19.72 seconds. All four separately selected
signer resource probes also pass (21.29 seconds). These are results for that
snapshot, not a claim that a subsequently changed test file was already run.

Linux run `35713108864` at `aab6306` passed all 1099 unchanged Python tests,
all 80 harness tests, and Rust formatting, strict Clippy, and library tests.
Its Rust job failed with exit 101 after 29 minutes 40 seconds, not an overall
job timeout. The team contract suite passed 21 of 22 tests; the explicit-empty-
membership test observed an empty responder callback list instead of the
exact `not_member` and initiator-fingerprint tuple. The dial was refused and
the no-acceptance assertion passed. All new T6/T7 cases and both offline/live
native SSH cancellation cases passed. Later suites and policy were skipped.

Independent actual Astra triage found that both Rust and Python close the
channel before invoking the failure callback. The Linux failure appeared
about 90 milliseconds after suite startup; only the first, in-process branch
lacked callback synchronization, whereas TCP already waited up to three
seconds. A controlled Python probe returned a refused dial before recording
the callback in ten of ten cases, then recorded the exact expected tuple
after release. This supports an in-process test-ordering race, not a failed
refusal. The historical Linux failure remains a failed gate. Sol's test-only
correction adds the same bounded callback observation to the in-process case
and a controlled ordering regression; exact refusal, identity, and no-acceptance
requirements remain. Independent review and the next exact-head platform
results determine acceptance, not this diagnosis alone.

The bounded callback correction subsequently received independent Astra
acceptance at `97a8d0f`: 23 team tests pass (21.39 seconds), with both focused
cases, strict focused Clippy and formatting also passing. The report is
`astra-team-refusal-callback-final.md`; the final published `8be0103` differs
only by that report. A fresh complete macOS run frozen at `97a8d0f` also
passes formatting, strict all-target Clippy, 507 library tests (four ignored)
and every integration target. The policy differential took 412.47 seconds,
eight original native process/CLI adapters took 150.55 seconds, the 23-case
team suite took 19.97 seconds, and the final tools/vault suites also passed.

Linux run `35717335672` at `8be0103` passed all 1099 original Python tests
(370.786 seconds), the harness job, Rust formatting/strict Clippy, and 507
library tests (four ignored; 153.43 seconds). Its Rust job exited 101 after
five minutes, not an overall timeout. The round-three terminal suite passed
two of three cases; the original Python branch of the Ctrl+C restoration
comparison did not exit within its unchanged eight-second child deadline.
The corresponding Rust branch and all later targets, including the newly
corrected team contract and policy, were not reached. They are not Linux
passes for this head.

`astra-pty-linux-second-triage.md` preserves independent evidence: ten local
instrumented original-Python repetitions pass, and source inspection does
not support a prompt-before-noecho explanation. The earlier inherited-signal
normalization is already present. No new product defect or specific hosted
signal-loss mechanism is established. Additional failure-only process-group,
terminal and selected signal-state diagnostics are the next bounded step;
the one Ctrl+C stimulus, original deadline and terminal-restoration assertion
must remain. This is an open platform gate, not an approved workaround.

The diagnostic instrumentation and its dependent-test assertion guard were
independently reviewed in `astra-pty-timeout-diagnostic-review.md` and
`astra-derived-pty-assertion-addendum.md`. A forced ISIG-off case still failed
after 8.05 seconds; a separate successful-native-initialization negative
control was rejected only when the restored nonzero-exit assertion was
present. All three affected targets (five tests) and strict all-target
Clippy/formatting passed freshly at `69e9bf9`. No product behavior changed.

Subsequent Linux run `35718792047` at `17bce17` passed all 1099 original
Python tests (369.908 seconds), the harness job, Rust formatting/Clippy and
507 library tests (four ignored; 73.68 seconds). The previously failing PTY
case, inheritance portability, and derived repeated-prompt case passed on
that run. This is not proof of their historical timeout's mechanism.
The Rust job exited 101 after 13 minutes 50 seconds: `runs` passed 16 of 17
tests, failing the immediate post-drop Context-cycle assertion. Later
targets and the long policy step were skipped, not passed; the overall CI
time limit was not reached.

Source inspection identified a legitimate temporary strong Context owner
in the supervisor thread. Completion notification precedes that closure's
return and release; waiting for terminal state is not joining the thread.
Installed registries and revocation callbacks retain weak backreferences.
The test correction observes both actual Context destruction and owned-
directory removal within the original four-second completion budget, while
a separate no-worker test retains immediate no-cycle proof. Independent
controlled lifecycle testing and a new exact-head Linux run remain required;
the original failed result is not waived or relabeled a product leak.
