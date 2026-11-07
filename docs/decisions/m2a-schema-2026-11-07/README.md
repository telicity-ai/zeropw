# M2a design provenance and factual clarification

The two sibling documents are the unchanged outputs of actual `gpt-6-astra`, ultra reasoning, in T3 Code. The design inspected parent `feca56633e5ad0ce4e0cd1d7c839877bfbb3f172`, Rust tree `2882ba592e2204eb62723d95e240525e75196f64`. The coordinator copied both byte-for-byte and verified the hashes supplied in the completion report:

- `decision.md`: `564bcf4c312b04507e815e35cc8eed9f5c6ae8f74ee539ccecf88cff8f0595b2`
- `implementation-task.md`: `3d6520c88fb88558ead2ee380bc322ae897de9c4bb5b67c6d60e37b184e2a58f`

This is an approved bounded design, not implementation, test execution, Opus review, full M2 or release acceptance. M2-G01 through M2-G10 remain open. The actual schema is unchanged by this record.

Factual clarification by the Sol coordinator: decision section 12 calls the prior log check “seven synthetic service-secret scans.” The source-bound E2E record actually reports **one separate scan covering seven synthetic service secrets**, in addition to 66 scenario assertions. Preserve that distinction in implementation and acceptance reports. No test was rerun for this document collection.

Parser-choice blocker found after the design: the [isolated36-input dependency probe](../../evidence/2026-11-07-m2a-raw-value-feature-probe/README.md) observed12 legacy behavior changes when adding raw_value. Do **not** enable that feature or implement the blocked parser choice from the original task until a separate Astra revision resolves it. Wire fields/hash definitions are unchanged. The original design/task bytes above remain an audit record, not proof of dependency compatibility.

A subsequent actual Astra ultra revision is now collected unchanged: [parser-compatibility-revision.md](parser-compatibility-revision.md), SHA256 `0ce1fabf72cb7c116a422dd5fc521383174c55a38145c2aff1ab07e8df5cf370`, and [revised-implementation-task.md](revised-implementation-task.md), SHA256 `27a49588eab8553bf81cef67547b6e9d581ee991dc9cd10fae2a4d92268db395`. It removes all Cargo/dependency changes and supersedes only the parser clauses listed in its section3. Wire/hash/fixture contracts remain unchanged. PC-R1–R5 and M2-G01–G10 are unexecuted/open; the first implementation must pass PC-R1–R4 before proceeding to the broader bounded slice. This is a design decision, not runtime or Opus acceptance.
