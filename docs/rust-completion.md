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

Current blocking addendum: Linux run `35706839572` failed at head `e8610ac`
in the remote SSH fact test; its generic timeout did not identify the failing
stage. The later policy step was skipped, not passed. Controlled TCP triage
also exposed a separate required product defect: emergency facts published
offline remain absent after authenticated reconnection in both Python and
Rust, contrary to `docs/team-sync.md` §6.6. Astra PO requires this functionality;
parity with the original defect is not acceptance. A bounded native catch-up
fix and independent review are in progress. Earlier component closures below
remain historical evidence, not closure of this new gate.

| Area | Required implementation and proof | State |
| --- | --- | --- |
| Existing first half | Existing Rust foundation, crypto, vault, policy, gateway, signer and team data continue to pass their complete suites | Full integrated snapshots 318386d and 019b92e pass; persisted-project A-R2-6(b) correction independently accepted |
| Execution | Run registry, ownership, bounded capture, redaction, idempotency, timeout, process-group cancellation, audit failure boundaries | Astra bounded runtime acceptance at 318386d; all eight runtime findings resolved, including creation-time directory modes |
| Native tools and server | All five tools, HTTP relay, strict framing, caller authentication, listener limits, polling and shutdown | Bounded runtime review and 25 tool/server tests pass; final-head platform acceptance pending |
| Incident response | Incident assessment/lockdown/widen/close, detector rules, SMTP delivery and retry, value-free outputs | Astra bounded response acceptance at 897c9a6: all 16 findings resolved, 72 selected test functions pass |
| Team networking | Authenticated transport, sync, facts, snapshots, invitation/join/removal, DEK rotation, incident sharing | Prior bounded 104 checks and original native process E2E pass; new required offline emergency-fact catch-up finding remains open; 62-method map and explicit native API distinctions retained |
| User interfaces | Full administrator and agent CLI command trees, demo, native Rust executables | Original native-oracle contracts pass; AR-CLI-01–06 resolved, including handled SIGINT status and exact-owned-directory cleanup |
| Integration QA | Cross-language state/wire compatibility; separate-process CLI/API/SSH/team scenarios; negative tests for secret leakage and authorization | Original HTTP, real-sshd SSH, three-node team and compromise E2E pass; final overall decision must use exact PR-head checks and the handoff below |
| Astra review | Independent product and adversarial review of integrated revision; all findings resolved with evidence and a clean rerun | Prior remediation findings have independent bounded closures; new offline-fact functionality gate remains open. Original reports remain immutable. Component PASS is not itself platform/deployment approval |

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

## Final compatibility handoff (2026-09-22)

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
