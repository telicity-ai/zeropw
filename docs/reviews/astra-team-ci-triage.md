# Astra bounded triage: original Python team drain CI failure

- Actual model: `gpt-6-astra`.
- Failed candidate: `5e2a131e32dcd8e0beb7cca1d77129038e550545`.
- Initial local inspection: `5c2d3e8204a08a18390b5ccc33c8b6a56563fedf`; final observation: `019b92e1704a6b326cd04a0d23de5daa0c90d6e3`.
- Python team source/test and native team source/AR3 test have no diff from the failed candidate through the final observed head. Python team source and the failing test also have no diff from port base `6ed440f` to the candidate.
- Read-only triage except this unique report. No changes to product, original tests, CI, harness, or prior reviews; only synthetic local fixtures were run.

## What failed

`gh run view 35703888623 --job 106668064658 --log-failed` confirms the original Python `product-tests` job failed **1 of 1099 tests**, after 362.447s, using Python 3.12.14 on the hosted Linux runner. The failure was:

```text
tests/test_team_sync.py:506
FactsTestCase.test_removed_peer_session_is_receive_only_during_drain
AssertionError: False is not true : the outgoing member_removed FACT was not sent to carol
```

This is an actual failed CI run. Nothing below changes that result or makes it a PASS.

## Finite unchanged local repetitions

On local macOS with Python 3.12.11, the unmodified case passed **10 of 10** sequential executions in 25.561s:

```sh
env -i PATH=/Users/ys/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin python3.12 -c 'import unittest; name="tests.test_team_sync.FactsTestCase.test_removed_peer_session_is_receive_only_during_drain"; suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for _ in range(10)); result=unittest.TextTestRunner(verbosity=2).run(suite); raise SystemExit(not result.wasSuccessful())'
```

This does not reproduce the hosted failure naturally and is not a Linux result.

## Concrete race in the observation fixture

The test configures both A-to-Carol and Carol-to-A peer dialing, waits only for Carol's fingerprint to appear in A's session map, then captures that one concrete session object and replaces only its `send` method with a spy (lines 482–495). Publication broadcasts through the **current** session map, not necessarily that captured object.

Python `TeamSync._accept_or_replace_session` (around line 817) explicitly permits replacement during simultaneous authenticated connections: the lower fingerprint retains outbound, the higher retains inbound, and the losing object is closed. Thus presence of the fingerprint does not guarantee that the captured object's identity remains canonical. `_broadcast` snapshots the current non-draining sessions; `publish_fact` calls it before `_drop_member_sessions` marks the peer draining. Source ordering alone does not show the fact being dropped.

### Controlled diagnostic, not an unchanged-test rerun

One temporary in-memory diagnostic preserved the original test and its assertions but inserted a controlled disconnect/reconnect after the test installed its spy and before the original `publish_fact` body ran:

1. Close A's and Carol's current sessions using their existing `_close_session` operations.
2. Let the existing peer pollers establish a fresh authenticated connection; wait for a nonclosed replacement distinct from the spied object.
3. Call the original `publish_fact` unchanged. A temporary class-level `_EncryptedSession.send` observer records successful sends after the original send returns.
4. Observe Carol's own document for receipt of its removal, then let the original test's assertion run unchanged.

Result: the **same line-506 assertion failed**, in 2.748s, even though the fact was successfully sent on the replacement and Carol received it:

```json
{"carol_received_own_removal":true,"fact_sent_on_replacement":true,"no_unexpected_errors":true,"old_session_closed":true,"replaced_spied_session":true,"same_assertion_message":true}
```

The temporary wrappers were restored in `finally`; no source file was modified. This demonstrates a concrete false-negative mechanism in the session-object spy. It does **not** prove that this exact interleaving occurred in the hosted run, whose log contains no session-identity trace. The initial diagnostic attempt used an extra forced duplicate handshake instead of a disconnect/reconnect; its diagnostic code hit a missing-session `KeyError`. That attempt was discarded and is not product-failure evidence.

## Native evidence and limits

The unchanged native `astra_team_round3::removed_peer_drain_is_receive_only_and_accepts_self_removal` passed again in **5.48s** with:

```text
cargo test --offline --test astra_team_round3 removed_peer_drain_is_receive_only_and_accepts_self_removal -- --exact
```

It observes the outgoing removal fact on an explicitly adopted queue session, proves receive-only drain (no commit acceptance or vector reply), accepts a permitted self-removal fact, and observes eventual closure. It intentionally does not create competing inbound/outbound handshakes, so it establishes native drain behavior but cannot diagnose the Python test's captured-session race. The prior team-round-four TCP and separate native multi-process evidence remains separate evidence, not a substitute for this failed CI job.

## Disposition

**No Rust regression or Python product defect demonstrated by this triage. A concrete fixture false-negative mechanism is demonstrated; the exact hosted failure cause remains unconfirmed.** The unchanged local repetitions and source inspection support a timing-sensitive observation race, but do not warrant declaring the original CI failure definitively fixture-only or waiving its gate. Preserve the initial failure and rerun the unmodified CI job on the final exact head. If it recurs, collect session-identity/send/receive diagnostics rather than weaken the assertion or silently alter the Python oracle.
