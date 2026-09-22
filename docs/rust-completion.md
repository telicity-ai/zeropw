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
| Execution | Run registry, ownership, bounded capture, redaction, idempotency, timeout, process-group cancellation, audit failure boundaries | In progress |
| Native tools and server | All five tools, HTTP relay, strict framing, caller authentication, listener limits, polling and shutdown | In progress |
| Incident response | Incident assessment/lockdown/widen/close, detector rules, SMTP delivery and retry, value-free outputs | Sol worker in progress |
| Team networking | Authenticated transport, sync, facts, snapshots, invitation/join/removal, DEK rotation, incident sharing | Sol worker in progress |
| User interfaces | Full administrator and agent CLI command trees, demo, native Rust executables | Sol worker in progress |
| Integration QA | Cross-language state/wire compatibility; separate-process CLI/API/SSH/team scenarios; negative tests for secret leakage and authorization | Pending integrated runtime |
| Astra review | Independent product and adversarial review of integrated revision; all findings resolved with evidence and a clean rerun | Pending |

Completion requires the full Python feature inventory, meaningful behavioral
tests for each feature and failure boundary, Linux and macOS verification where
platform behavior matters, and Astra review with no unresolved findings.
Python subprocesses are permitted as test oracles only, never as a Rust product
backend. Missing APIs, placeholder successes, and silently unsupported existing
commands do not satisfy acceptance. Deployment and merging are separate actions.
