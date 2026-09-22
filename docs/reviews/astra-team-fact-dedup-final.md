# Astra bounded fact deduplication closure

- Actual reviewer model: `gpt-6-astra`.
- Exact independently reviewed/tested product: `af1d455f0aab60a121baddb0b38bf9c905c3309b`; HEAD remained unchanged throughout these runs.
- **ASTRA-TEAM-T7 / P2: resolved for the demonstrated concurrent duplicate application/audit defect.**
- Historical failure remains immutable in `astra-team-duplicate-fact-finding.md` and commit `1931ede`: product `af45e512` produced 20 ledger rows but 22 application audit events. This closure neither rewrites that result nor lowers severity.

## Source disposition

`store_fact` now returns an inserted boolean while holding the existing state/environment locks. Duplicate storage returns false. Ordinary receive, local publication and local-file pickup gate downstream refold/application audit/rebroadcast on the insertion winner. This closes the observed check-then-store race without removing receiver signature, target, environment, role or removal checks.

Incident reception intentionally does not suppress missing-artifact recovery merely because the signed fact already exists: it still reconstructs a missing incident artifact before ACK. Outbox delivery/retry likewise remains independent of the insertion boolean. The incident path retains author/session identity, signature, current-role and receiver-admin checks. This distinction is necessary recovery behavior, not an exception allowing ordinary duplicates to emit application audits.

The change does not make ledger persistence, derived policy refolding, auditing and network transmission one atomic transaction. This review does not claim crash-exactly-once side effects, transactional recovery from every intermediate failure, or exhaustive concurrent incident artifact behavior. Its resolved scope is the demonstrated ordinary fact duplicate-processing race. No credential disclosure or policy bypass was demonstrated by the original finding.

## Independent validation

All commands used `env -i PATH=/Users/ys/.cargo/bin:/Users/ys/.local/bin:/usr/bin:/bin cargo test --offline` from `rust/`, with synthetic disposable state only.

| Selected test invocation suffix | Result |
| --- | --- |
| `--test astra_team_fact_duplicate_diagnostic -- --nocapture` | 1 passed, 7.12s; **unique=20 ledger_rows=20 application_audits=20** |
| `--test astra_team_fact_catchup -- --nocapture` | 1 passed, 6.22s |
| `--test astra_team_reconnect_diagnostic -- --nocapture` | 1 passed, 6.39s |
| `--lib team::sync::retry_tests -- --nocapture` | 3 passed, 2.82s: atomic insertion winner, retry backoff, replay replacement/drain |
| `--test astra_team_round2 user_authority_incident_retry_restart_and_admin_removal_dek_isolation -- --exact` | 1 passed, 6.20s |
| `--test astra_team_round3 incident_mandatory_rotation_is_monotone_and_nonadmin_never_acks -- --exact` | 1 passed, 6.85s |
| `--test team_membership_sync live_emergency_facts_each_record_one_apply_audit -- --exact` | 1 passed, 3.44s |

Total: **9 selected tests passed**. The first three test targets were invoked together; the table separates their reported results. The independent duplicate test retains its exact 20-row/20-audit assertions and queue-drain barriers. It uses controlled Session adapters and actual receive threads, not a TCP authentication-handshake test.

## Remaining gates

This is a T7 component verdict, **not overall acceptance**. T6's complete real runtime catch-up/cancellation checks, full integration and Linux CI must pass on the final exact product head. Source identity through later test-only/documentation changes must be established separately. No original review, regression assertion, product source, harness or CI file was changed for this closure.
