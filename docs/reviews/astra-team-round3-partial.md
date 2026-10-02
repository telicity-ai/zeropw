# Team round-3 partial QA handoff

Actual test author: `gpt-6-astra`. This is **not an acceptance review**.
The review tool interrupted the task twice, including after a request to use
standard safeguards. No completed round-3 independent verdict was returned.

The partial test artifact was authored at `db4fc5e`; team product sources match
`5089848`. The reviewer reported four passing cases: conflict alerts, monotonic
rotation/nonadmin acknowledgement, mutual-removal convergence and third-party
removal restriction. The reviewer explicitly left two snapshot cases and the
drain case unconfirmed, and identified incomplete restart fixture setup.

Coordinator execution of the unchanged draft at `8e2ae50` ran eight tests:
six passed, two failed (48.78s). Failures were the restore and compaction tests
re-registering an existing TeamSync after changing persisted state; registration
is intentionally idempotent. The draft conflict case also claimed a restart
without constructing a new TeamSync. These are test-fixture issues, not product
findings. The original Python compaction test creates a fresh sync instance after
writing peer vectors, and restore explicitly re-derives state after restart.

The original draft is preserved in Git before coordinator fixture corrections.
Any corrected test execution is coordinator QA, not a fabricated continuation of
the interrupted independent review. No product source was changed by this task.

## Coordinator fixture correction and execution

At product revision `8e2ae50`, the coordinator added a test-only `Node::restart`
that stops the prior sync and constructs a fresh transport/TeamSync before
registering persisted state. Restore and compaction now perform this real
restart, and the conflict-alert test now actually restarts both nodes. Original
assertions and product code were unchanged. The helper is consistent with the
original Python `_offline_sync`/`_redocument` setup; persisted override-alert
bookkeeping also explicitly spans restart in the Python implementation.

The corrected eight-test suite passes (49.78s, `--test-threads=1`, clean
environment). This supplies coordinator evidence for receive-only drain,
mutual/third-party removal, monotonic notification flags/no-ack, snapshot
threshold/compaction/gap append, fact deduplication/restore and conflict alert
exactly-once persistence. It does not turn the interrupted review into a PASS.
