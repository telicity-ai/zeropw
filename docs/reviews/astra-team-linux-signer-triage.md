# Astra bounded Linux team signer-test triage

- Actual model: `gpt-6-astra`.
- Exact inspected and locally tested product: `e8610ace7e897be442234ddba49d763b66d71036`.
- Failed Linux run: `35706839572`, Rust job `106677707785`.
- No product, shared test, CI, harness, or previous review edits. Added only this report and a unique controlled diagnostic. All fixtures use synthetic state and local authenticated TCP peers.

## Confirmed failure, unconfirmed stage

`gh run view 35706839572 --job 106677707785 --log-failed` confirms `team_remaining_contract` finished **17 passed / 1 failed**, 100.33s. The failing test is `remote_connection_disabled_fact_closes_existing_signer_socket`; a native `run_serve` startup line was printed. It panicked at the shared `wait` helper, line 1147, with `remote live runtime condition did not occur`. The log has no backtrace or stage label.

That helper is used at four distinct points in this test: HTTP listener readiness, child marker existence, remote policy becoming disabled, and signer path disappearing. The failure therefore cannot be assigned specifically to signer cleanup from this log. A startup payload alone does not establish that the child marker, remote fact, or disabled policy was observed. The complete Rust CI gate remains failed/incomplete; skipped later suites are not passes.

## Finite unchanged local repetitions

The unmodified failing test passed **10 of 10** sequential local macOS repetitions, each 5.48–5.88s, using the same 10-second helper bound:

```sh
for trial in 1 2 3 4 5 6 7 8 9 10; do
  env -i PATH=${HOME}/.local/bin:${HOME}/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin RUST_BACKTRACE=1 ${HOME}/.cargo/bin/cargo test --offline --test team_remaining_contract remote_connection_disabled_fact_closes_existing_signer_socket -- --exact --nocapture || break
done
```

No natural local failure was reproduced. These results are not Linux acceptance and do not override the hosted failure.

## Fixture readiness and transport semantics

`RemoteFixture` first opens authenticated A/B sessions, then this test stops B's original TeamSync/transport and replaces B with `run_serve` using the same state and team address. The SSH test waits for HTTP startup and its child marker but does **not** wait for the replacement authenticated team session before calling A's `publish_fact`. The adjacent HTTP widening test has a session-map wait; moreover its change is a commit, which participates in vector catch-up.

Both products publish a fact by persisting/applying it locally and broadcasting once to current sessions. Their VECTOR handlers exchange/replay commits, not historical facts. Consequently a fact published in the disconnected interval can be absent at the replacement B even after later successful reconnection. HTTP startup is not proof that A has a usable authenticated team session to the replacement B. A map entry could also refer to an old connection, so a robust fixture should establish replacement readiness, not only assume a previously observed fingerprint remains usable.

### Independent controlled TCP evidence

The unique `rust/tests/astra_team_reconnect_diagnostic.rs` isolates this possibility without changing the original fixture or product:

1. Establish real authenticated TCP membership between A and B.
2. Stop B; wait until A reports no session to B.
3. Publish a synthetic disable fact and verify it is persisted at A but absent at B.
4. Start a fresh B TeamSync on the same state/address; observe authenticated sessions in both directions.
5. Author a new barrier commit and observe it at B. The offline fact remains absent.
6. Publish another synthetic disable fact while connected; observe that fact at B. The earlier fact is still absent.

`cargo test --offline --test astra_team_reconnect_diagnostic -- --nocapture`: **1 passed**, 5.98s. `cargo clippy --offline --test astra_team_reconnect_diagnostic -- -D warnings`: passed, 0.16s. This test records current behavior for diagnosis, not a new desired-behavior requirement or permission to retain missed revocations indefinitely. Its waits retain a 10-second bound and use explicit stage labels. The initial compilation used the wrong reference type for the transport trait; only that new diagnostic's adapter was corrected before executing it.

A separate controlled original-Python TCP sequence, using `_Node`, a fresh `TeamSync` over B's same state, and the same publication/barrier sequence, produced:

```json
{"offline_fact_absent_after_reconnect":true,"barrier_commit_delivered":true,"connected_fact_delivered":true}
```

Thus the missed-offline-fact mechanism is not a demonstrated Rust/Python parity regression. The working team documentation's offline fact-delivery statement is broader than this measured behavior in both implementations; that pre-existing product/spec limitation is not silently resolved by this triage.

## Disposition and bounded next step

**Concrete missing-readiness risk demonstrated; actual Linux failure stage/cause remains unconfirmed. No signer-cleanup product defect or Rust parity defect was demonstrated.** A controlled disconnected-peer diagnostic is not proof that this exact timing occurred in the hosted test.

The implementation worker should first give each existing wait a stage-specific diagnostic and establish an authenticated replacement-peer readiness precondition before publishing the fact. Preserve the original policy-disabled, real-socket-removal and run-cancel assertions and the 10-second bound. Then rerun the original suite and final exact-head Linux CI. Do not weaken the timeout/assertions, label the existing failure a pass, or introduce unrelated CI/VM/harness changes. Any desired change to offline fact replay is a separate product decision, not an implicit fixture fix.
