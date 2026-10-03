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

## Current full-equivalence continuation (2026-10-03 KST)

Full equivalence remains unproven. The current candidate branch is
`codex/rust-full-parity`, with `rust/parity-status.json` tracking the historical
residual inventory and exact revision evidence. The current implementation
workers are actually `gpt-6-sol`; this local session coordinates and reviews.
The 2026-10-03 user decision disables GitHub Actions for this repository.
The repository Actions API was updated and read back as `enabled: false`.
Workflow files remain as historical test manifests; disabling automation does
not remove any test or acceptance requirement.

Verification now uses the dedicated `zeropw-parity` Lima Linux VM, with no
host-directory mounts, SSH-agent forwarding, proxy environment propagation,
or automatic application-port forwarding. An unprivileged `parity` user
receives a committed source archive, with its SHA and archive digest recorded
outside the guest. Guest firewall rules reject that user's connections to
private/link-local networks; loopback synthetic endpoints remain available.
No repository, model, vault, gateway or signer administrator credentials are
provided to the guest. Product builds and tests execute there, never directly
on the coordinator host. Rust 1.98.1 and CPython 3.12.14 (source commit
`2abcf904b8dac8c999d2b3aac76681abb333798a`) match the prior verification tools.
This ARM64 Linux environment does not replace required macOS platform tests.
Older local-run reports below are historical evidence and do not describe
this execution arrangement.

At `f2091e8309cea8cc843020c3ee562bf106db4d7f`, hosted run
[37041858065](https://github.com/handlecusion/zeropw/actions/runs/37041858065)
passed the TLS, CLI and native E2E groups on Linux and macOS. Linux library
results were 531 passed and four ignored. macOS library results were 529
passed, two failed and four ignored: the remaining failures concern native
SMTP hostname aliases. Both platforms passed the IDNA boundary and exhaustive
single-Unicode-scalar comparisons against CPython 3.12.14. These are bounded
results, not a full-suite or final-head PASS. The overall run failed: it also
found a Clippy diagnostic and an incorrect ledger NaN test oracle, both
addressed in the next candidate.

Candidate `17416f1ddfbedcdab9826f3ac2465db4bd6bcc8e` adds macOS system
proxy support, exact large grant limits, and stored `ca_file` shape handling.
Its [run 37043238441](https://github.com/handlecusion/zeropw/actions/runs/37043238441)
passed CLI, data and native E2E on both platforms. Linux library tests passed
532/four ignored; macOS passed 533 with the same two SMTP alias failures and
four ignored. The run failed overall: macOS Clippy found an unnecessary lazy
evaluation, and both TLS jobs exposed a missing repository import path in a
new Python oracle (not a TLS product decision mismatch). Both are corrected
in the next candidate. Subsequent validation
expands to every discovered Rust integration target, library/binary and
documentation tests, the four explicit signer resource probes, and the full
Python reference and harness suites on both platforms. A result only supports
the exact tested SHA; no earlier PASS carries over to later changes.

Candidate `dd7fdca48d580c88f24b2aabca0618f1a1d074b8` widens vault and
credential versions and handle timestamps, adds MIME group/domain-literal
handling, and preserves Python stored-header coercion. Local formatting and
diff checks passed. Hosted [run 37048435634](https://github.com/handlecusion/zeropw/actions/runs/37048435634)
rejected all 18 jobs before their first step because GitHub reported failed
account payments or a spending limit. The preceding `0cd4cb7` run had the
same infrastructure failure. Neither run provides compilation or runtime
validation. This blocked hosted verification at the time. The later user decision above
disables Actions and establishes an isolated VM execution path instead.

The earlier `949207b` full matrix passed both platforms' Python reference
(1099), harness (80), explicit signer probes (4), native E2E/fake upstream,
data group and remaining integration shard 0. That run still failed overall
on compile errors and retained snapshot/helper/vault expectations, macOS SMTP
aliases, and a macOS Python serve signal timeout. Later corrections remain
unverified. These results neither approve `dd7fdca` nor close the full goal.

Open work includes SMTP host aliases, MIME grammar, remaining accepted
persisted-value representations, snapshot lazy-access semantics, and exact
replay status propagation. Independent final review and full-platform
acceptance still apply. Recording a residual never waives the user's full
rewrite objective.

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
`astra-run-context-lifetime-review.md` accepts the bounded correction with
19 fresh passing tests at `ca9683a`, including its real-supervisor lease probe
and all 18 run tests. The unique probe is included in `c27f8e6`. A new exact-
head Linux run remains required; the original failed result is not waived or
relabeled a product leak.

## Active-terminal-read platform gate (2026-09-22)

A fresh complete macOS run at exact `6becf5a` passes formatting, strict
all-target Clippy, all 507 default library tests (four ignored), and every
integration target. The policy differential took 409.64 seconds and all eight
native process/CLI adapters took 150.71 seconds. All four separately selected
signer resource probes also pass (21.38 seconds): three descriptors per
binding, one server-side descriptor per client, enforced 32-client refusal,
and a surviving accept loop. Idle CPU was below the macOS measurement
resolution for both one and nine bindings. This is not a Linux result.

Linux run `35720818752` at the same `6becf5a` passed all 1099 unchanged
Python tests (371.173 seconds), the harness job, Rust formatting/Clippy and
507 library tests (four ignored; 103.20 seconds). The Rust job exited 101
after 3 minutes 49 seconds, not an overall timeout. Round-three terminal
tests passed two of three cases; the original Python Ctrl+C comparison again
exceeded its eight-second child wait. Later Rust targets were skipped.

The failure-only diagnostics recorded the actual child as the foreground
process group before input and at timeout, ISIG enabled, ECHO disabled,
VINTR Ctrl+C, SIGINT unblocked/unignored with a handler installed, and
`wait_woken`. Kernel pending-signal sets were empty; these do not expose
CPython's interpreter-pending flags. This rules out the recorded foreground
and signal-mode explanations, not every possible cause or the precise hosted
signal/read interleaving. Controlled local investigation demonstrates a
CPython pending-signal-before-read mechanism, but does not reproduce the
historical hosted interleaving and is not claimed as its proof.

Actual Astra PO authorizes the original-Python interrupt comparison on Linux
to observe a positive-length read of the controlled terminal by the exact
foreground child before the single Ctrl+C. The observation must share the
existing five-second startup deadline, fail explicitly if unavailable, and
retain the eight-second child wait and terminal restoration checks. Native
Rust's immediate-prompt interrupt path must remain unchanged. Sol's bounded
test-only implementation and independent Astra review are in progress at
this entry. Neither this decision nor the macOS pass closes the Linux gate.
No Python product/test, harness, CI or instruction file is changed for it.

The initial coordinator affected-target run at observer snapshot `cd17bf1`
passed all three terminal cases but failed the unchanged runtime-output case
`ar_runtime_07_terminal_status_never_precedes_captured_output_publication`:
final stdout was empty instead of the synthetic `business-output` (three
passed, one failed; 9.54 seconds). That assertion preceded the state/reason
checks, so the failure did not reveal whether the process failed to start,
timed out, failed audit, or completed without output. No cause or new product
defect is established by the empty output alone. An unchanged focused retry
passed in 2.56 seconds; an unchanged complete affected-target retry passed
all six cases (5.19, 0.35 and 0.14 seconds). These do not explain or erase the
first failed run. Failure-only selected state/audit metadata and elapsed
timing are being added under independent Astra review, retaining every
existing assertion and timeout. Fresh final-platform validation is required.

## Python-parity gap audit and closure (2026-09-26)

A Claude Code session took over PR #6 at `d1b51df` and audited the Rust port
against the Python modules, which are the specification. It was not an Astra
review and is not final-head platform approval. The audit covered six groups:
administrator/agent CLI, demo, runtime/server/gateway, response
(notify/SMTP/intrusion/incident), and team sync.

Each claimed gap was confirmed by running the same input through the Python
module and the Rust binary or API before anything was changed. The branch
`claude/vigilant-johnson-nv4fx1` holds the fixes and their differential tests.
Three workers ran in separate worktrees (response, team, runtime), and the
coordinator merged their branches. Python is only a test oracle; no product
path calls it.

Defects found and fixed, by area:

- **Build.** The branch no longer compiled or passed strict Clippy on the
  current stable toolchain. Fixed first.
- **Administrator and agent CLI.**
  - `rust/src/argparse.rs` ports CPython 3.12 `argparse` exactly: abbreviation
    rules, nargs patterns, error text, and `HelpFormatter`/`textwrap` wrapping.
    Before this, many inputs that Python rejects or accepts were handled
    differently.
  - `rotation activate` could re-activate a retired version or pin a missing
    one. It now validates the version status first.
  - Non-UTF-8 argv panicked and printed the raw token.
  - `serve` never printed its request log, and the log grew without bound.
  - Audit records were missing fields, and team share did not audit
    `auth_failed`.
  - restore-ack was not atomic.
  - `~` and `~user` were not expanded, so a literal `~` directory was created.
  - `--cli-env` was not validated in insertion order.
  - The agent CLI ignored `*_proxy`/`no_proxy`, including CONNECT tunnels and
    `Proxy-Authorization`.
  - Integer options did not follow Python's arbitrary-precision acceptance.
- **Demo.** `zeropw-demo` and `zeropw-democli` now produce the Python output
  (47 checks), including errors and URL handling.
- **Runtime, server and gateway.**
  - A file without `#!` ran through `/bin/sh`; it is now refused as
    `ENOEXEC` like `execve`.
  - Request header names were not validated.
  - A handler panic leaked its connection slot, and an accept error ended the
    accept loop.
  - HTTP framing did not match `http.server`.
  - A pinned self-signed `CA:TRUE` certificate was rejected where OpenSSL
    accepts it. `PinnedCaVerifier` now accepts it only when it is
    byte-identical to the pinned certificate, and still checks SAN, validity,
    EKU and key usage.
  - Handshake failures did not map to Python's reasons.
  - The run registry's shutdown, revoke and resolution rules did not match
    Python.
- **Response.**
  - notify took the owner uid from `/usr/bin/id`; it now compares the real uid
    directly.
  - A panicking detector decision poisoned its lock.
  - smtplib/`EmailMessage` behaviour did not match, including header folding,
    RFC 2047 encoding, comment and address parsing, the `mail FROM:` spelling,
    EHLO hostname, and error class names.
  - Incident `failed_steps` and counter handling and `principal_not_found`
    did not match.
- **Team.**
  - The relaxed-document refold was an unbounded-work DoS.
  - Local commits were not picked up.
  - `peer_vectors`/`overridden_alerted` loading and corrupt-document handling
    did not match Python.
  - A session whose broadcast send failed was not dropped.
  - `stop()` closed the transport before joining the poll thread.

New differential tests:

- `cli_parity` (78 argv/state cases in `cli_parity_cases.json`).
- `agent_proxy_parity`, `serve_request_log` and `democli_parity`.
- `gateway_tls_parity`, which includes the unhandled-critical-extension guard.
- `runtime_parity_gaps`, `server_accept_resilience`, `response_parity_gaps`
  and `team_parity_gaps`.
- Additions to `gateway`, `fake_upstream` and `signer_e2e`.

Every remaining difference has a `rust/DEVIATIONS.md` row with its probe.
The rows added here cover:

- non-UTF-8 argv;
- integer saturation above 2^63-1;
- `~user` through `/etc/passwd` rather than every NSS source;
- macOS System Configuration proxies, which Rust does not read;
- urllib's extra headers and exception granularity;
- the exec-format pre-check;
- the pinned-CA exception, with its P-521 and non-CA key-usage residuals;
- residual SMTP header shapes and `local_hostname`;
- hand-edited incident and team documents.

Known residual, low severity. `last_snapshot_total` in team `register_env`
sums only integer vector values. The snapshot file is local state that only
this node writes, so a difference needs a hand-edited snapshot. Python would
raise `TypeError` on a non-numeric value, and Rust ignores it.

Validation at the head that carries this section:
Linux container, 4 CPUs, rustc 1.94.1, CPython 3.12.11 as the oracle. This is
not a macOS result and not a hosted CI run.

- `cargo fmt --check` and `cargo clippy --locked --all-targets -- -D
  warnings` are clean.
- `cargo test --lib`: 527 passed, 4 ignored, three consecutive runs as a
  non-root user. As root, the four store permission-denied tests fail by
  design because root bypasses the permission check.
- Every integration target passed, run one target at a time as CI does, as
  root. The exceptions are the root-sensitive cases, which were re-run as a
  non-root user and passed: `signer_e2e` (6),
  `native_cli_e2e::original_real_ssh_end_to_end_on_native_binaries` and
  `gateway::audit_unavailable_refuses_before_credential_use`.
  `policy_differential` passed in 97.48 seconds.
- Python product suite: 1099 tests OK (355 seconds, non-root).
- Harness: 80 tests OK; `compileall` is clean.
- No Python product, Python test, harness, CI or instruction file changed.

Test robustness change: `signer::tests::accept_latency_is_not_bound_by_a_fixed_poll_interval`
failed in one of three full root `--lib` runs. It passed every time when run
alone. Under sustained CPU saturation this kernel (`CONFIG_HZ=250`) delayed
each wakeup to a 4 ms tick. That gave about 4 ms per cycle, which is
scheduling delay and not a poll interval in the code.

The 25 ms bound and the workload are unchanged. The assertion now applies to
the fastest of up to three runs. A fixed poll interval raises the floor of
every run, so it still fails. Sustained external CPU saturation can still
fail the test; it is a wall-clock latency pin by design.

### Hosted CI on CPython 3.12.14 (2026-10-02)

The owner chose to merge PR #6 on local Linux validation. The branch was
fast-forwarded to `9a0d203`, and that push triggered hosted run
`36951471833`. Its harness and Python product jobs passed. The Rust job
failed in `smtp::message_tests::generated_header_shapes_match_python_bytes`.

The cause is the oracle version. `setup-python` installs the latest 3.12,
which is 3.12.14, while the local oracle was 3.12.11. In 3.12.14, CPython's
`email` package:

- keeps a comment's parentheses when it refolds the comment;
- narrows `WhiteSpaceTerminal.startswith_fws`;
- makes `BytesGenerator` raise `HeaderWriteError` for a fold that leaves a
  line without leading whitespace.

Older 3.12 releases send such a header instead. `378925e` ports all three
changes and adds session and CLI cases for the refusal.

Validation of that commit with CPython 3.12.14 as the oracle:

- library: 527 passed, twice, as a non-root user;
- every integration target, `policy_differential` included, passed;
- the eight root-sensitive cases passed when re-run as non-root, and
  `native_cli_e2e` passed 10/10 without skips.

The next hosted run, at `b6087dc`, found two more failures.

- `rust-tests`: the `cli_parity` key mask matched only a generated key
  whose comment began with `root@`. It had been validated as root, and CI
  runs as `runner`. The mask now covers any invoking user.
- `product-tests`: the original Python test
  `test_removed_peer_session_is_receive_only_during_drain` failed. It
  races: both nodes dial each other, and the spied session can be replaced.
  The unchanged test also fails locally 2 of 25 times. It was left
  unchanged, and a test-only patch was proposed on the PR.

After these, every integration test binary was run as a non-root user with
CPython 3.12.14, which is CI's setting, and all 67 targets passed. The
library suite also passed as non-root: 527 tests.

`rust/PORTING.md` now asks for the latest 3.12 patch release as the oracle.
`rust/DEVIATIONS.md` records the 3.12.11 difference. Against 3.12.11 the
header oracle reports 69 mismatches and the `header_write_refused` session
differs, by design.
