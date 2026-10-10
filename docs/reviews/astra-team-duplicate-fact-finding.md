# Astra concurrent fact application finding

- Actual reviewer model: `gpt-6-astra`.
- Finding: **ASTRA-TEAM-T7 / P2 — concurrent duplicate receipt repeats application auditing**.
- Exact tested product: `af45e512d59a31b23b1530a2277fcacd626ce443`.
- Status: **OPEN** pending narrow implementation and independent recheck. ASTRA-TEAM-T6 remains separately P1; this does not alter prior evidence.

## Controlled reproduction

`rust/tests/astra_team_fact_duplicate_diagnostic.rs` creates disposable synthetic nodes and valid signed membership/FACT records. Two registered Session adapters drive the actual independent receive threads. Twenty distinct signed disable facts are each queued on both sessions. Subsequent VECTOR messages on each queue must produce COMMIT responses, establishing that both queues finished processing their preceding FACTs before counts are checked. No product hooks or sleeps substitute for that barrier.

This adapter test exercises concurrency and signature/role validation, not the TCP authentication handshake; no claim of an end-to-end network exploit is made.

Executed from `rust/`:

```sh
env -i PATH=${HOME}/.cargo/bin:${HOME}/.local/bin:/usr/bin:/bin cargo test --offline --test astra_team_fact_duplicate_diagnostic -- --nocapture
```

Result: **0 passed / 1 failed**, 7.25 seconds:

```text
unique=20 ledger_rows=20 application_audits=22
assertion failed: duplicate application audit after concurrent receipt
left: 22
right: 20
```

Twenty persisted rows show ledger hash deduplication still works. Twenty-two `team_fact_apply` audit events demonstrate duplicate application processing. The race is scheduled naturally and the exact excess count need not repeat on every run; one observed violation is sufficient. No credential disclosure, policy bypass, or duplicate persisted emergency fact was demonstrated.

## Cause, requirement, bounded correction

`validate_incoming_fact` checks the hash under the environment lock, releases it, and performs signature/role checks. Two receiver threads can both pass. `store_fact` correctly checks again and skips duplicate storage, but returns the same success value for insertion and duplicate suppression. `handle_fact` consequently refolds, records application auditing, and rebroadcasts even when its own insertion did nothing.

`docs/team-sync.md` §7.4 says the same fact is processed once by hash. The concrete extra processing/audit violates that contract. This is pre-existing receive-path behavior, also exercised by reconnect replay; the finding is not a claim that the pending replay patch introduced it or that duplicates repeat indefinitely after hashes are remembered.

The bounded fix should distinguish newly stored facts from duplicate no-ops and gate downstream application/audit/rebroadcast on actual insertion while retaining all signature, role, target, environment, removal/drain and persistence-error boundaries. Keep the desired regression's exact 20-row/20-audit assertions. Independent passing rechecks plus the final exact-head integration/Linux gates remain necessary; this report is not acceptance.
