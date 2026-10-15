# Astra run supervisor lifetime review

- Actual independent reviewer: `gpt-6-astra`.
- Failed Linux candidate: `17bce17`, run `35718792047`, job `106716515269`.
- Test-only correction: Sol `474197697a463e6989d2e2421feb892768dcdf1a`, integrated `ca9683adc651096b80991ae6921be10eb829da53`.
- **Bounded lifecycle test correction accepted; no persistent product Arc cycle demonstrated. Overall Linux acceptance remains pending.**

## Failure and source evidence

The hosted log confirms `runs` 16 passed / 1 failed in 26.53s, exit 101. `installed_registry_retains_history_without_return_owner_and_drops_without_cycle` failed its immediate Weak-Context assertion at line 450. The log does not identify the remaining strong-reference owner or whether it subsequently disappeared. It is not proof of a persistent ownership cycle.

The installed registry has a Weak Context backreference, no direct Context owner, and a Weak registry capture in the policy revocation callback. In contrast, the spawned supervisor intentionally owns a strong Context lease. `finalize` publishes completed state/output and signals the completion condition before returning; `supervise` then returns and its enclosing closure releases the lease. `registry.wait` therefore does not mean the thread and its Context owner have already been destroyed. Weak upgrade becoming unavailable also does not mean Context's destructor has finished removing owned directories.

Ten finite unchanged local repetitions of the original test all passed, 2.45–2.68s each. They neither reproduce nor waive the hosted failure. The specific failed-host interleaving remains unobserved.

## Controlled independent evidence

New `rust/tests/astra_run_context_lease.rs` blocks the real supervisor at its existing cleanup callback using channels, without product hooks or an extra strong Context clone. While that callback is blocked, the test drops the caller's Context and observes that Weak upgrade still succeeds and the owned directory remains. It releases the callback, observes completed state, drops its registry reference, then requires both Weak upgrade failure and directory disappearance within the same four-second lifecycle deadline. The callback precedes finalization; this probe does not claim to deterministically pause the precise post-publication window on the hosted runner.

The controlled probe passed on unchanged `17bce17` in 2.54s; strict Clippy on that new test passed. This demonstrates a legitimate temporary supervisor lease followed by release, not a leak or a fabricated delay in product code.

## Correction and fresh validation

The existing test now starts its completion deadline immediately before its original four-second wait. It uses only the remaining portion of that same budget to observe **both** zero Context strong owners and absence of the owned execution directory, then retains the original exact no-cycle and directory assertions. It does not add another four seconds or sleep for a guessed settling time. A separate no-worker test demands immediate Context destruction and directory cleanup, preserving direct proof against an installed ownership cycle without any thread-timing allowance.

Fresh independent command from `rust/`, exact integrated `ca9683adc651096b80991ae6921be10eb829da53`:

```sh
env -i PATH=${HOME}/.cargo/bin:${HOME}/.local/bin:/usr/bin:/bin cargo test --offline --test runs --test astra_run_context_lease
```

Result: **19 passed** — independent lease test 1/1 (2.70s), complete runs suite 18/18 (6.81s). The latter includes no-worker immediate destruction, pre-completion cleanup, output/audit publication, cancellation, ownership and timeout boundaries.

Only the unique independent test and this report are contributed by this reviewer. Sol's correction changes an existing test, not product behavior, CI, or a timeout setting. Historical failure evidence remains intact. These results justify the bounded synchronization correction; they do not establish the exact hosted cause or replace final-head Linux/full-suite evidence.
