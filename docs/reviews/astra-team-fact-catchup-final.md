# Astra bounded offline fact catch-up closure

- Actual independent reviewer model: `gpt-6-astra`.
- Exact reviewed/tested source: `2e88f8890d2b501030df640149eb898ee1401e24`; HEAD and product/test sources remained unchanged throughout the runs below.
- **ASTRA-TEAM-T6 / P1: resolved within the measured offline catch-up, effect, authorization and replay-boundary scope.**
- This is not overall product acceptance. Final exact-head macOS integration and Linux CI remain separate gates.

## Preserved failure evidence

The original P1 finding remains unchanged in `astra-team-offline-fact-finding.md`: product `5dd9b1ad5861a7c2357f2b286c723fa3e781ea2c` failed the desired authenticated-reconnect delivery regression in 15.86s, at its original 10-second catch-up bound. Historical diagnostic/report commit `d1f6ace` remains evidence of missing replay, not an accepted permanent omission. The explicitly authorized `af45e51` conversion of `astra_team_reconnect_diagnostic.rs` requires delivery and exact persisted deduplication rather than retaining the old defect-characterization assertion.

At intermediate product `5b9995c5056839e14edd7a0becb4f2256d6fabec`, this reviewer independently observed:

- `astra_team_fact_catchup`: 1 passed, 6.21s.
- `astra_team_reconnect_diagnostic`: 1 passed, 6.48s.
- `team_remaining_contract`: **21 passed, 1 failed**, 116.38s. `offline_facts_catch_up_after_sender_restart_in_bounded_batches` reached recipient ledger length 2, then its immediate assertion at line 1773 observed vault status `active`, not `revoked`.
- One finite, unchanged isolated rerun failed the same assertion in 6.48s. These failures are not rewritten as passes.

Source inspection established that ordinary receipt persists the fact before refolding derived vault/policy state. Waiting only for ledger length therefore did not synchronize completion of the asserted effect. The separate test-only correction in `2e88f88` now requires both ledger length 2 and revoked status inside the **same existing 10-second, 20ms-poll wait**, then retains both exact assertions. It adds neither an extra timeout allowance nor a relaxed result. The final successful run below validates that corrected observable boundary.

The historical Linux run `35706839572`, job `106677707785`, failed at an unstaged generic live-signer wait. Neither this ledger/effect observation nor the signer fixture correction establishes which stage or cause produced that historical failure.

## Source and fixture review

The T6 product change (`b3093a7`, integrated as `5b9995c`) follows commit catch-up with persisted ordinary FACT replay on authenticated VECTOR handling. Its cursor examines at most 64 raw ledger lines per exchange, including rejected lines, advances in log order, and cycles at EOF. Session acceptance/replacement resets the peer cursor; session drop/stop removes it. An exact `Arc` identity check prevents an old replay operation from overwriting the replacement session's cursor.

Before outbound serialization, replay parses and validates the fact, environment, target and signature against a known author; INCIDENT is excluded from generic FACT replay. Before each valid send it rechecks the exact canonical session, active recipient membership and absence of receive-only drain. No environment mutex is held across the send callback. Receiver-side signature, target, environment, current-role and removal-exception authorization remain authoritative. Per the explicit PO interpretation of §7.4, an ordinary delayed fact from a now-demoted author is not authorized by its self-asserted historical HLC. INCIDENT retains its separate admin-only outbox/ACK protocol.

The final recording-session test separately includes malformed JSON, signed INCIDENT, cross-environment, malformed-target and **valid-target-shape/bad-signature** rows, and inspects the exact emitted FACT frames. Replacement occurs at valid line 0 before the old scan reaches a nonzero cursor boundary; the replacement starts at zero and receives valid lines 0 and 64 over two batches. Appending a new valid tail after EOF is exercised on the same live session. A first-send callback starts receive-only drain; a further replay call that would otherwise reach valid line 64 emits nothing additional. These final assertions address the earlier draft evidence gaps without modifying the independent regressions.

The separate native-signer fixture writes its synthetic socket-path marker to a temporary file and renames it after the write, preventing existence from exposing partial marker contents. The existing socket-existence requirement remains; additional status/path diagnostics run only on failure. The harmless signed-commit replacement-session barrier remains a live-session readiness check, not a substitute for offline replay. No product or security postcondition is weakened by these test-only changes.

Concurrent ordinary-fact duplicate application is the separate **ASTRA-TEAM-T7 / P2** finding, independently closed in `astra-team-fact-dedup-final.md` at `af1d455f0aab60a121baddb0b38bf9c905c3309b`. That fix is included in this tested source. This T6 report does not supersede its distinct evidence or expand its exactly-once claim.

## Independent final validation

Commands ran locally on macOS from `rust/`, using synthetic disposable state and controlled local endpoints:

```text
env -i PATH=/Users/ys/.local/bin:/Users/ys/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin /Users/ys/.cargo/bin/cargo test --offline --test astra_team_fact_catchup --test astra_team_reconnect_diagnostic --test team_remaining_contract -- --test-threads=1
env -i PATH=/Users/ys/.local/bin:/Users/ys/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin /Users/ys/.cargo/bin/cargo test --offline --lib team::sync::retry_tests -- --test-threads=1
```

| Test target | Independently observed result |
| --- | --- |
| `astra_team_fact_catchup` | 1 passed, 7.98s |
| `astra_team_reconnect_diagnostic` | 1 passed, 6.48s |
| `team_remaining_contract` | 22 passed, 121.55s |
| `team::sync::retry_tests` | 3 passed, 7.67s |

**27 selected tests passed.** This includes authenticated TCP reconnect, offline sender restart, a valid tail beyond 128 rejected rows, appended-tail revocation with actual derived effect, persistent exact-row deduplication, monotonicity across subsequent commit refold, current-role rejection after demotion, removed-peer handshake refusal, replacement/drain boundaries, and native offline FACT cancellation of a live signer socket and run. The unchanged live signer, HTTP stale-grant cancellation, TCP/in-process convergence and original synthetic wire-scanner cases in the selected suite also passed. No full-suite or Linux pass is inferred from this selection.

## Residual limits and disposition

The 64-line cap bounds the examined replay slice and potential transmissions, **not** full-ledger reading or total CPU/memory: the implementation reads the ledger and author verification can refold history. Eligibility is checked before sending without holding a mutex across transport callbacks; an already admitted send can race a concurrent membership/session change. The tests demonstrate deterministic replacement/drain suppression, not an impossible-in-flight-message guarantee. No universal networking, cryptographic security, crash-transactional exactly-once processing or instantaneous offline revocation claim is made.

Within this bounded scope, persisted still-authorized emergency facts are recovered after reconnect and produce the required local effects; no additional T6 finding remains. Original P1 severity and failed evidence are preserved. Only this new report was added by the reviewer; no product, existing regression/report, harness or CI file was edited for this closure.
