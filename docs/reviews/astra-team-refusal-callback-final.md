# Astra bounded refusal-callback fixture acceptance

- Actual independent reviewer model: `gpt-6-astra`.
- Exact final reviewed/tested source: `97a8d0fe6027124df83944401a3f90e4061ecc0e`.
- **PASS for the scoped test-only callback synchronization correction and bounded diagnostic.** No failed membership refusal or new product defect was demonstrated by this review.
- Not overall acceptance: a fresh final-candidate Linux run and full macOS validation remain coordinator-owned gates. Historical failed CI is not reclassified as passing.

## Preserved Linux evidence

At candidate `aab630691c32a0d1c1bedf280966e9d7d7bcc771`, GitHub Actions run `35713108864`, job `106698160843`, exited 101, not a job timeout. The independently retrieved failed log reports `team_remaining_contract`: **21 passed, 1 failed**, 133.75s. The failure was `explicit_empty_membership_refuses_inprocess_and_tcp_handshakes`, line 640:

```text
left: []
right: [("not_member", Some("wsauaqrfth5wcmpanew22bl74y"))]
```

That value is the initiator's **fingerprint**, not the environment ID. The test had already asserted failed dialing and no accepted-session callback before reaching this assertion. The observed failure concerns completion of the responder's diagnostic hook, not successful admission of a nonmember.

The log begins the suite at `10:22:48.267` and reports this failed test at `10:22:48.357`, approximately 90ms later. The original loop checks in-process first, without waiting for its callback; TCP already had a three-second wait while the callback list remained empty. These timings and source order strongly localize the failed assertion to the in-process branch. The log did not directly record callback scheduling, so that specific interleaving is an evidence-backed diagnosis, not a captured trace.

## Source and original-Python checks

Both Rust `InProcessTransport::dial` and original Python `InProcessTransport.dial` run the responder on a separate thread and close the channel **before** invoking its failure hook. Initiator dialing can therefore observe closure before the responder hook finishes. Python's original refusal tests also immediately inspect that callback list; synchronous callback completion is not guaranteed by the implementation used as the oracle.

At unchanged `aab6306`, this reviewer ran:

- The native empty-membership case unchanged: 1 passed, 0.09s.
- Original Python nonmember refusal, removed-member refusal, and white-box environment-mismatch refusal tests: 3 passed, 0.112s. The white-box assertion retains zero responder bytes.
- A finite controlled Python diagnostic: **10/10** cases held the original failure callback before it appended its result. Dialing had already failed with `handshake_channel_closed`, the list was empty and no session was accepted. Releasing the callback produced exactly `("not_member", initiator_fingerprint)`. It used disposable generated identities and bounded events, without modifying Python source or original tests. An initial diagnostic-only access to nonexistent `SessionClosed.reason` was corrected to `str(exc)` before this ten-case run; that driver error is not product evidence.

The membership refusal itself remains before responder key/signature message transmission in the unchanged transport source. No callback reason or peer identity is sent to the rejected peer by the test correction. No secret, authentication material, production state or external target was used.

## Reviewed corrections and boundedness

Sol `ee3a20bcabcac1acb0dde17e10c1cb8121074eff`, integrated as `7315c9136d39ff45ce870d63efbc77bb8b0ddbb6`, adds the same three-second/10ms callback wait to the previously unsynchronized in-process branch. Failed dialing, no accepted session, and the exact singleton `not_member`/fingerprint list assertion remain. A diagnostic label now distinguishes TCP from in-process on failure. The existing TCP wait is unchanged.

At `7315c913`, the corrected case passed independently in 0.07s and the first controlled ordering diagnostic passed in 0.02s. However, that new diagnostic used unbounded barriers and synchronous dialing. Its ability to finish depended on current callback thread/order behavior. This reviewer requested bounded coordination rather than accepting a diagnostic that could hang under a future ordering regression; no current product hang was claimed.

Sol `0b5eaa6f0bdf5217afcbed550078f92cf0562b73`, integrated as final `97a8d0f`, replaces those barriers with channels. Dialing runs on a separately observed thread; dial result, hook start and hook completion each use three-second receive timeouts. The callback's release wait has a ten-second escape. The main test sends release before post-observation assertions, and there is no unbounded join. The test verifies refusal before hook completion, no accepted session, explicit release, and exact final reason/fingerprint. The original corrected test still verifies the exact singleton callback list. These coordination bounds address the review concern without weakening refusal assertions or changing product code.

## Independent final validation

All final commands ran locally on macOS at unchanged `97a8d0fe6027124df83944401a3f90e4061ecc0e`, using the existing integration build target. Cargo tests/Clippy used `env -i PATH=${HOME}/.local/bin:${HOME}/.cargo/bin:/usr/bin:/bin ${HOME}/.cargo/bin/cargo` from `rust/`.

| Command suffix | Independently observed result |
| --- | --- |
| `test --offline --test team_remaining_contract explicit_empty_membership_refuses_inprocess_and_tcp_handshakes -- --exact --nocapture` | 1 passed, 0.07s |
| `test --offline --test team_remaining_contract inprocess_refusal_can_return_before_responder_hook_finishes -- --exact --nocapture` | 1 passed, 0.01s |
| `test --offline --test team_remaining_contract` | **23 passed**, 21.39s; normal test-runner concurrency |
| `clippy --offline --test team_remaining_contract -- -D warnings` | Passed |
| `fmt --all -- --check` | Passed |

The two focused cases are included in the full 23-test suite, not 25 distinct tests. The suite also passed both native live/offline signer cases, offline replay/revocation, removal/refusal, convergence and synthetic wire-scanner assertions. These local results do not turn the earlier Linux run green or substitute for another Linux run.

Only `rust/tests/team_remaining_contract.rs` and additive acceptance documentation differ between `aab6306` and this tested revision; product source and CI workflows are unchanged. This reviewer added only this new immutable report and did not edit product, existing tests/reviews, harness, CI, job timeouts or the coordinator's acceptance document.
