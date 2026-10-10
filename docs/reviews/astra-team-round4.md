# Astra team review — round 4 bounded recheck

- Actual reviewer model: `gpt-6-astra`.
- Initial tested checkout: `a6e3e9e0babb0e4c59c529a8e5c6677617b70a10`.
- Final observed checkout and separately rerun native three-process E2E: `318386de404ccbff4cdd8c3e0a79dbb1a4aa25e0`.
- `git diff a6e3e9e..318386d -- rust/src/team rust/src/canonical.rs rust/src/context.rs` is empty. Concurrent SMTP/runtime changes are not accepted by this team-only report.
- Scope: original 62-method team-runtime mapping, completed Sol fixtures, prior independent regressions, local synthetic state and controlled endpoints. No production credentials, external targets, product edits, CI/harness edits, or changed historical tests/reports.

## Result

No new product failure was demonstrated. All 102 selected existing native tests and the original native three-process lifecycle passed. This is not a complete assertion-by-assertion acceptance of all 62 mapped methods: two precise mapping gaps below remain unverified. Linux and the final integrated product gate remain separate.

The interrupted round-three history remains unchanged. Its corrected eight tests passed in this new review; that does not retrospectively turn the interrupted review into a completed acceptance.

## Original findings

| ID and original severity | Disposition in measured scope |
| --- | --- |
| ASTRA-TEAM-T1 — P2 / Medium | Remains resolved: unchanged Unicode inviter regression passes without panic. |
| ASTRA-TEAM-T2 — P2 / Medium | Remains resolved: unchanged live fact audit regression and all-three-kind audit test pass. |
| ASTRA-TEAM-T3 — P2 / Medium | Remains resolved: unchanged padded invitation Python-oracle regression passes. |
| ASTRA-TEAM-T4 — P3 / Low | Remains resolved: unchanged string-pair conversion regression and broader dictionary/oracle tests pass. |
| ASTRA-TEAM-T5 — P2 / Medium | Remains resolved: unchanged ISO expiry regression plus transcript/expiry/concurrent single-consumption cases pass. |

## Executed evidence

Clean-environment invocation, with the installed Cargo and Python interpreter directories on PATH:

```text
cargo test --offline --test team_remaining_contract --test astra_team_review \
  --test astra_team_round2 --test astra_team_round3 --test team_membership_sync \
  --test team_transport --test team_fold --test team_oracle -- --test-threads=1
```

| Target | Result |
| --- | --- |
| astra_team_review | 5 passed, 8.08s |
| astra_team_round2 | 8 passed, 10.56s |
| astra_team_round3 | 8 passed, 52.08s |
| team_fold | 22 passed, 67.56s |
| team_membership_sync | 5 passed, 14.39s |
| team_oracle | 33 passed, 4.30s |
| team_remaining_contract | 18 passed, 86.93s |
| team_transport | 3 passed, 0.08s |

Separately, `cargo test --offline --test native_cli_e2e original_team_end_to_end_on_native_binaries -- --exact --nocapture` passed. The unchanged original Python lifecycle test completed in 13.884s with 38 native admin and 6 native agent launches, not a Python product backend.

## Mapping and assertion inspection

Read the six original Python modules, current team contract, mapping, and relevant mapped assertions. Confirmed measured coverage includes:

- Share conversion retains connection/secret data and stales the existing grant. Revoked-only/cross-project secrets stay local; those connections and their existing grant remain active and unversioned by the conversion. Wrong passphrase and duplicate share are refused.
- Actual native admin fact commands return fact rather than commit metadata without increasing commit count. Secret put and connection update produce commits and increase that count.
- Exact two-node reciprocal catch-up over both TCP and in-process transport observes both independently authored connections, equal documents, and populated synchronization timestamps.
- Remote signed TCP widening reaches native `run_serve`, stales the grant, and cancels a running HTTP-kind child with `grant_stale`. Remote disable reaches native `run_serve` and removes the real signer socket whose path was observed from a live child. These two fixtures host `run_serve` in a Rust thread, matching the original Python fixture topology; they are not separate serve OS processes. The separately executed original three-process E2E covers actual process startup, shared relay, remote narrowing, partition/reconnect, removal, and output/state scanning.
- User fact publication refusal, receive-only removal drain, no replies/commit processing during drain, third-party removal restriction, eventual session closure/fresh-dial refusal, old-value retention, and inability to decrypt a newly authored post-removal version with the old DEK.
- Actual restart for snapshot compaction, backup/restore fact reapplication, and exactly-once loser alerts. Pending incident outbox reload and eventual admin ACK, mandatory rotation monotonicity, and no nonadmin receiver ACK/storage.
- Nonempty bidirectional raw TCP relay capture during authenticated full TeamSync gossip, followed by original `tests.leakcheck.find_secret` checks on each stream and their concatenation for the actual synthetic secret and unwrapped DEK. This is bounded leak-scan evidence, not a universal security claim.
- Rust's two constructor APIs require an explicit membership callback. Their empty callback fails closed. The mapping correctly identifies this API-shape difference rather than claiming Python's omitted-argument call shape exists in Rust.

The no-`team-listen` fixture observes a null startup field and a selected unused port remaining closed; it is not a process-wide socket inventory. Source additionally creates TeamSync only inside the `Some(team_listen)` branch.

### Mapping gaps, not demonstrated product defects

1. `test_self_removal_by_user_role_still_works` maps to `removed_peer_drain_is_receive_only_and_accepts_self_removal`, but that fixture explicitly gives the peer role `admin`. The other membership self-removal fixture also joins an admin. A user being allowed to send incidents or denied admin facts does not prove the user self-removal success path.
2. `test_two_admins_remove_each_other` checks local `membership.remove_member(..., team_sync=None)` and the returned `dek_rotated` values: true before removal, false when the author has already been removed. The mapped AR3 mutual-removal test injects signed facts and checks convergence; it does not call that local API or assert those rotation results.

These distinctions do not invalidate the passing convergence/drain tests, but their narrower assertions cannot be relabeled as the missing assertions. Supplemental regression work is required before claiming the complete original mapping is accepted.

## Tool limitation

An ordinary `apply_patch` attempt to add the unique supplemental `rust/tests/astra_team_round4.rs` failed with exit 1 and `Failed to write file ${HOME}/Code/zeropw-rust-complete/rust/tests/astra_team_round4.rs`, with no further cause returned. Read-only checks confirmed the tests directory exists, the new file does not, and the checkout was clean. No bypass, alternative write mechanism, or weakened assertion was used. The proposed tests were not executed and are not counted above.
