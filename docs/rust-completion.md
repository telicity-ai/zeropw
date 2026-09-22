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
| Execution | Run registry, ownership, bounded capture, redaction, idempotency, timeout, process-group cancellation, audit failure boundaries | Implemented; 13 native tests pass at 63ff815; independent review pending |
| Native tools and server | All five tools, HTTP relay, strict framing, caller authentication, listener limits, polling and shutdown | Implemented; 17 boundary/integration tests pass at 63ff815; independent review pending |
| Incident response | Incident assessment/lockdown/widen/close, detector rules, SMTP delivery and retry, value-free outputs | Implemented; Astra round 1 found 14 open findings; Sol fixes in progress |
| Team networking | Authenticated transport, sync, facts, snapshots, invitation/join/removal, DEK rotation, incident sharing | Implemented; 7 direct native tests pass; independent Astra review in progress; coverage incomplete |
| User interfaces | Full administrator and agent CLI command trees, demo, native Rust executables | Implemented; 6 native tests pass; TTL/demo/prompt/HTTP compatibility corrections in progress |
| Integration QA | Cross-language state/wire compatibility; separate-process CLI/API/SSH/team scenarios; negative tests for secret leakage and authorization | Original process E2E assertions now exercise native binaries; initial run 1 pass / 3 failures, details below |
| Astra review | Independent product and adversarial review of integrated revision; all findings resolved with evidence and a clean rerun | Response round 1 complete with findings; team round 1 active; runtime/CLI review pending |

Completion requires the full Python feature inventory, meaningful behavioral
tests for each feature and failure boundary, Linux and macOS verification where
platform behavior matters, and Astra review with no unresolved findings.
Python subprocesses are permitted as test oracles only, never as a Rust product
backend. Missing APIs, placeholder successes, and silently unsupported existing
commands do not satisfy acceptance. Deployment and merging are separate actions.

## Integrated evidence and current blockers

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
