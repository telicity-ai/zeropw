# Astra required offline emergency-fact catch-up

- Actual reviewer model: `gpt-6-astra`; independent PO/security review.
- Finding: **ASTRA-TEAM-T6 — P1 — emergency facts permanently missed across authenticated reconnect**.
- Reproduced native product: `5dd9b1ad5861a7c2357f2b286c723fa3e781ea2c`.
- Historical controlled Python/native diagnostic: commit `d1f6ace`, `docs/reviews/astra-team-linux-signer-triage.md`, inspecting `e8610ace7e897be442234ddba49d763b66d71036`.
- Disposition at this report: **OPEN; implementation and independent acceptance required**. No previous report is rewritten or downgraded.

## Requirement and observed failure

`docs/team-sync.md` §6.6 explicitly requires offline commits **and emergency facts** to arrive when connectivity returns. Its next paragraph and §11 accept stale revocation state while offline, not permanent omission after successful reconnect. §7.4 requires persistent, hash-deduplicated, monotone facts to be reapplied after resynchronization. This is required existing functionality, not a new optional enhancement.

The immutable d1f6ace diagnostic established actual authenticated TCP sessions, disconnected B, persisted a disable fact at A, replaced B using its same state/identity, then delivered a new signed commit and a newly published connected fact while the older fact remained absent. Its controlled original-Python experiment produced the same omission. Matching the original defect is not fulfillment of §6.6. This failure can withhold emergency disable/revocation controls from a reconnected replica; severity is P1. No production credential, exploit against a real service, or observed real credential misuse is claimed.

The separate Linux failure at run `35706839572`, job `106677707785`, had a generic live-signer wait timeout whose exact stage was not known. This deterministic catch-up reproduction does **not** establish that the Linux failure had this cause. Repairing the live-signer readiness barrier is legitimate but does not resolve this finding.

## Independent desired-behavior regression

New `rust/tests/astra_team_fact_catchup.rs` reuses the diagnostic's controlled TCP setup, not its defect-locking expectation. It requires the old fact to arrive within the existing 10-second bound after replacement authentication and a successful commit roundtrip, then checks its monotone disabled-target set survives a later commit refold. It also requires subsequent live fact publication to continue working. Synthetic identifiers and disposable local state only.

On exact product `5dd9b1ad5861a7c2357f2b286c723fa3e781ea2c`:

```text
cargo test --offline --test astra_team_fact_catchup -- --nocapture
0 passed; 1 failed; 0 ignored; finished in 15.86s
catch-up stage failed: offline fact is caught up after authenticated reconnect
```

Initial shell lookup of unqualified cargo failed before executing any test; rerun used the installed toolchain with a clean PATH. The recorded failure above is a product assertion failure, not that setup error. The historical diagnostic's intentionally negative assertion must not remain a contradictory acceptance requirement after the fix; preserve its report and Git evidence when explicitly superseding it.

## Bounded fix acceptance and security boundaries

Authenticated reconnect must recover persisted, still-authorized emergency facts, including after sender/receptor restart and beyond one bounded transmission batch; repeated vectors/reconnections must deduplicate rather than reapply/audit indefinitely. A recovered fact must affect derived policy, not only arrive as an unused row. Existing signature, environment, target, role and monotone refold checks must remain enforced. Invalid stored rows must not prevent later valid catch-up.

Every outbound replay must check the exact current authenticated session and removal/drain state. §4.4 prohibits **all** outbound traffic to removed peers, including retransmissions; its receive-only mutual-removal exception does not authorize replay to them. Keep existing independent drain/mutual-removal tests. Generic FACT replay must exclude INCIDENT: §9 has a separate admin-only, non-relayed outbox/ACK protocol, including its own retry requirements.

PO authorization decision: §7.4 says the receiver checks the sender's role in its membership at receipt and explicitly singles out the member-removal exception. Preserve current-role fail-closed validation: a delayed ordinary fact from a now-demoted author is not newly authorized merely by its signed, author-controlled HLC. Historical-role reconstruction is not implied by this transport repair. This explicitly qualifies catch-up as delivery subject to existing authorization; it is not permission to drop still-valid facts. Any broader historical authorization design needs its own specified security rules.

The existing historical/security assertions remain required. Worker tests and independent rechecks should cover reconnect/persistence/dedup and retained authorization/drain boundaries; the new regression is not a replacement for those tests. Final approval also requires full integration and Linux CI on the final exact head. This report is failure evidence, not acceptance of the pending implementation.
