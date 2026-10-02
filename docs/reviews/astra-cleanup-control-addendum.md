# Cleanup control: cancellation snapshot boundary

Actual reviewer: `gpt-6-astra`. Addendum to unchanged report/commit `ae70d39`; product remains `d6fdee402d9d915eb9288a4ce97bbc1662fac7bb`.

Coordinator review identified an unnecessary assumption in the new control: the Rust assertion required `cancel()`'s returned snapshot to already be terminal. The API performs a bounded internal completion wait; that does not promise every returned snapshot is terminal under every scheduling interleaving. The Python control already checks eventual terminal state separately.

The Rust control now requires a successful cancellation result with `cancel_requested`, then retains its existing bounded `registry.wait` assertion for exactly `cancelled`. The resource-absent / still-running / cancellation-requested barrier proof is unchanged, as are every timeout and cleanup guard. The test documents this intent inline. No product or pre-existing test was changed, and the original report is preserved.

Fresh independent test: **1 passed**, 2.57s, including original Python comparison. Strict Clippy for this test passed. This corrects only an overstrong assertion in the newly added control; it does not change the source-ordering conclusion or establish full-platform acceptance.
