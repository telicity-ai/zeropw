# Astra team port review, round 2

- Actual reviewer model: `gpt-6-astra`; independent review and QA, no product implementation. No Opus review was performed or claimed.
- Date: 2026-09-22.
- Product revision reviewed: `f7d160bd927f008c3b87974331f861c62d87b3e1`, including Sol fixes `391efb4240088611420fdac5c98b1d72ed5c30fe` and `97adcc75c8c83823929b225a7f1d82d2a164679b`.
- Final test-run checkout: `6f5a617a9af98107bca34e893b3520a2d2d2fcda`. `git diff f7d160bd927f008c3b87974331f861c62d87b3e1 -- rust/src/team` is empty. Concurrent coordinator changes outside this scope are not approved by this report.
- Scope: original ASTRA-TEAM-T1 through T5 findings, their fixes, transport authentication/canonicalization/deadlines, invite consumption, live incident retry/restart and member-removal/DEK boundaries.
- Result: **All five original findings resolved with fresh evidence; no new confirmed finding within this bounded review. Full team/full-product acceptance remains pending the coverage gaps below.**

The original report and reproduction evidence remain unchanged in `astra-team-round1.md`. The user correction in `docs/rust-completion.md` makes Astra the reviewer for this full Rust implementation. No earlier PASS or scope exclusion is used as acceptance evidence.

## Original finding disposition

| Original ID and severity | Disposition | Evidence on reviewed product revision |
| --- | --- | --- |
| ASTRA-TEAM-T1 — P2 / Medium | Resolved | Unchanged `astra_t1_untrusted_unicode_inviter_cannot_panic_join` passes. `membership.rs:440` uses `chars().take(8)`; accepted Unicode inviter produces the expected join failure without panic and without a project override. |
| ASTRA-TEAM-T2 — P2 / Medium | Resolved | Unchanged `astra_t2_live_fact_publication_records_apply_audit` passes. `sync.rs:1020–1023` persists, refolds, audits, then broadcasts, matching Python ordering. Existing `live_emergency_facts_each_record_one_apply_audit` independently checks all three emergency kinds and author/environment fields; it passes. Audit helper retains Python's nonfatal handling. |
| ASTRA-TEAM-T3 — P2 / Medium | Resolved | Unchanged padded-invite reproduction passes. Sol's `base32_padding_and_malformed_inputs_match_python` passes its Python-oracle corpus covering padding lengths, invalid residues, embedded padding, case and whitespace. |
| ASTRA-TEAM-T4 — P3 / Low | Resolved | Unchanged string-pair reproduction passes. Conversion reuses the Python mapping helpers; new oracle corpus verifies empty input, string pairs, bool/int/float dictionary-key collisions, `None` versus string key collisions and Unicode pairs. Later signed-fact target validation remains in place. |
| ASTRA-TEAM-T5 — P2 / Medium | Resolved | Unchanged complete ISO-expiry consumption reproduction passes. New independent test rejects expired numeric/string state, invalid/null dates and mismatched transcript proof, verifies failed proof leaves invite unused, then races four valid consumers and observes exactly one success. Numeric/ISO parser unit tests also pass. |

## Executed verification

All credentials, device keys and state were synthetic and temporary. Network tests use local controlled listeners. Python is used only as a test oracle, never as a product backend.

Run from `rust/` using `/Users/ys/.cargo/bin/cargo`:

```text
cargo test --offline --test astra_team_review --test team_membership_sync --test team_transport -- --test-threads=1
  astra_team_review: 5 passed
  team_membership_sync: 5 passed
  team_transport: 3 passed

cargo test --offline --test astra_team_round2 -- --test-threads=1
  8 passed, 0 failed (final complete run, 8.95 seconds)

cargo test --offline --lib team:: -- --test-threads=1
  105 passed, 0 failed

cargo clippy --offline --test astra_team_round2 -- -D warnings
  passed
```

The 105 library cases include the added absolute socket deadline and successful-dial backoff-reset regressions. Source comparison confirms `read_exact_until` recalculates remaining time on every read. The payload allowance remains the original Python `deadline + SOCKET_OP_TIMEOUT_SECONDS`; this is not a newly introduced whole-handshake hard deadline. `dial_attempt` clears both retry maps after successful peer-identity verification and before wiring the session.

New independent file `rust/tests/astra_team_round2.rs` adds:

1. Raw TCP nonmember, wrong-environment, malformed-environment and low-order-point rejection. Each rejected handshake produces EOF without response bytes and the expected refusal reason.
2. A genuine signature from the correct key using the wrong handshake role prefix; rejection before session acceptance.
3. A previous responder message replayed into a fresh initiation; rejection with `signature_invalid`.
4. An actual authenticated TCP session carrying 150-level JSON and an integer beyond 64 bits; canonical parser preserves both. Subsequent ciphertext tampering closes the session with `frame_authentication_failed`.
5. Connection-cap refusal before handshake and successful reuse of capacity after closing the accepted session.
6. Incident sanitizer and Fact conversion boundary corpora against original Python, including Unicode character limits, control characters, boolean/float/integer values, list limits, deduplication and invalid incident path tokens.
7. Invite expiry/transcript boundaries and concurrent single consumption described above.
8. A user-role join with shared-secret derivation; denial of administrator fact/invite operations; incident queue persistence across object restart with no route; delivery and acknowledgement on reconnect; sanitized admin receipt and mandatory rotation marker; administrator removal and a new DEK generation. Removed device receives no new wrap/local key, cannot decrypt new-generation ciphertext with its old DEK, and reconnect is refused. Existing old secret remains available, as the product explicitly documents.

Two initial failures in the new combined test were test-fixture mistakes and are not product findings: the snapshot/document key is `dek.current`, and Python explicitly permits `dial()` to return before the responder rejects the last handshake flight. The corrected test asserts refusal on the first `recv()`, matching the original removal test. The final eight-case run above uses these corrected assertions.

## Coverage mapping and remaining acceptance work

The following maps newly closed gaps from the original 62-case networking inventory. It does not claim every original method is now covered by one successful E2E scenario.

| Original test area | Evidence added or rerun here | Still not established by this review |
| --- | --- | --- |
| Transport (14 Python cases) | Mutual in-process/TCP exchange, nonmember and removed-peer refusal, environment format/scope, low-order points, role separation, responder replay, tampering, connection cap; canonical transport extension and deadline regression | No separate original optional-constructor-default test: Rust constructors require explicit membership callbacks. |
| Membership (12) | Real join/secret derivation, invite reuse, expiry/proof/atomicity, user authority, self-removal existing test, admin removal/new-generation isolation | Complete share-existing-connections/grant-reevaluation scenario and two-admin mutual-removal scenario not rerun here. |
| Sync (26) | Live fact propagation, all emergency-kind audit events, sanitizer oracle, user incident send, no-route persistence/restart, ack/rotation flag, retry reset | Three-node/offline conflict suites, simultaneous removals, explicit receive-only drain assertions, third-party-removal exemption rejection, exec cancellation, signer socket closure, wire secret/DEK sweep, session renewal, nonadmin incident receiver/no-ack, later recommended flag not downgrading mandatory, and override exactly-once still lack a complete mapped run here. Some are covered partially by coordinator E2E, which must be cited separately. |
| Facts (5) | Fact canonical/signature/target conversion and live propagation | CLI fact-versus-commit behavior, complete replay deduplication and backup/restore reapplication assertions not rerun here. |
| Snapshots (4) | Existing compaction/protected-history/resulting-document test passes | Automatic threshold, lagging-member compaction refusal, append-after-gap assertions not rerun here. |
| Multi-process team E2E (1) | Coordinator reports the original native three-node scenario passed | This reviewer did not rerun it; its source revision, launch adapter and results remain coordinator evidence. |

TeamSync's weak ownership is not a reported defect: construction has an explicit caller owner and native `run_serve` keeps its local `Arc`. No test failure establishes a lifetime bug. No claim is made that these in-process and loopback tests replace Linux platform verification or the full product acceptance gate.

Artifacts added by this reviewer only: `rust/tests/astra_team_round2.rs` and this report. No product code, original finding report, harness or CI was changed. These files are left uncommitted for the coordinator to collect.
