# M2a dependency option: compatibility failure

Actual Sol ran the copied unchanged `pyjson.rs`/`errors.rs` and pinned serde_json1.0.151 in a synthetic-only Lima experiment. The fixed36-input corpus has12 changed inputs in both pyjson and direct Value paths when adding only `raw_value` to the same final locked dependency graph. Commands exited0; the comparison is a **compatibility failure**, not a product test PASS.

The full report and all outcomes are preserved here. Raw commands, feature graphs, archives, preparation failures, source and binary hashes remain in `/Users/ys/Code/zeropw-mlp-evidence/m2a-raw-value-feature-probe-20261107/run-20261107T070736Z/` with SHA256SUMS.evidence. Both configurations use the same probe lock; that minimal lock has several stated proc-macro/transitive differences from the full product lock, so this is not a full product matrix claim.

No root Cargo feature, legacy helper or product source was changed. The original Astra schema remains preserved; its raw_value implementation choice is blocked pending an actual Astra revision. No new Opus verdict, native validation or supported snapshot onboarding follows from this experiment.
