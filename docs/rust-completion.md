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

| Area | Required implementation and proof | State |
| --- | --- | --- |
| Existing first half | Existing Rust foundation, crypto, vault, policy, gateway, signer and team data continue to pass their complete suites | Baseline 04a5634; rerun after integration |
| Execution | Run registry, ownership, bounded capture, redaction, idempotency, timeout, process-group cancellation, audit failure boundaries | Implemented; Astra found retained-registry and session-isolation defects; Sol fixes in progress |
| Native tools and server | All five tools, HTTP relay, strict framing, caller authentication, listener limits, polling and shutdown | Implemented; Astra HEAD-error and sanitized logging findings being fixed |
| Incident response | Incident assessment/lockdown/widen/close, detector rules, SMTP delivery and retry, value-free outputs | Round-1 fixes integrated; 27 worker tests, 8 original Astra regressions and 6 additional coordinator tests pass; independent re-review pending |
| Team networking | Authenticated transport, sync, facts, snapshots, invitation/join/removal, DEK rotation, incident sharing | Five Astra fixes plus transport/retry corrections integrated; original three-node process E2E passes; Astra re-review active; coverage incomplete |
| User interfaces | Full administrator and agent CLI command trees, demo, native Rust executables | Original native-oracle admin 55/55, response 8/8 and agent 6/6 pass; independent CLI review pending |
| Integration QA | Cross-language state/wire compatibility; separate-process CLI/API/SSH/team scenarios; negative tests for secret leakage and authorization | Original HTTP, real-sshd SSH, three-node team and compromise E2E all pass; full integrated suite/platform acceptance pending |
| Astra review | Independent product and adversarial review of integrated revision; all findings resolved with evidence and a clean rerun | Original reports retained; implemented fixes are not accepted until independent verification; no full PASS |

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
