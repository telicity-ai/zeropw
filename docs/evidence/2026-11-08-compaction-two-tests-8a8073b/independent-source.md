# Independent source DATA collection

Actual gpt-6.1-sol / ultra. Read-only collection and limited static scope inspection, with no subagents. This is not an Opus review, execution result or Astra acceptance.

All source bindings and preservation checks match at `8a8073b3d876bb3f83a628a7fdbd2902e8b40851`. Full tree `a43f60ea5438355879c90f9bf4bb6c63cd0e6679`, Rust tree `d63be7c07896e271bb48610463f4a6e027581f59`, Desktop tree `2413844c89265a3e239be2372d34b1e6e1b2d4bb`.

Exactly three paths differ from `5f4d045f289c53c41178f3f062f6c6f74fb561e2`: `rust/src/team/commit.rs`, `rust/src/team/compaction_heads.rs`, and `rust/src/team/sync.rs`. All 1,464 tracked files match the canonical manifest and Git by bytes, SHA-256, independently calculated Git blob, Git mode and current POSIX mode. All 1,461 protected paths retain exact bytes/blobs/modes. The archive has exactly 1,464 unique regular-file members with matching bytes and modes; nothing was extracted. The canonical patch is byte-identical to trusted Git's diff. Every freeze-bound artifact and both full Astra scope documents match their recorded hashes.

Removing the one specified cfg(test) statement restores commit.rs byte-for-byte. Removing the second statement plus the two variants, one optional scope field and two scoped wrappers restores compaction_heads.rs byte-for-byte. sync.rs retains the entire original prefix and closing brace, appending private helpers and exactly the two specified tests. Every changed line is an insertion: old loader/decoder/error statements, test/helper bodies, CI, harness, dependencies, features, fixtures and schema remain exact. The two test module boundaries are explicitly cfg(test). No old production behavior was edited outside the two test-only call sites.

The new test definitions were read in full with the decision and implementation task. They use owned root/env scoped one-shot gates, bounded channel waits, scoped threads with joins, resume/reset guards, exact file inventories, literal HLC oracles, and direct authorization/receipt paths. The deferred test covers its seven progressed rows and still-gap control; the fact test covers cache-wins, remembered advance and corrupt cache. This narrow reading found no source/scope discrepancy. It does not prove those assertions execute or that production semantics satisfy them.

No product, helper, compiler, formatter, dependency or test code was run. No process, VM, SSH, network endpoint, credential or active test-run directory was inspected. No checkout/ref/index change occurred; before/after HEAD, index and clean status match. No full semantic review of protected source was performed. Non-test artifact absence, runtime test counts and both-OS validation require their own evidence. All original findings remain OPEN at their original severities; actual Opus re-review, Astra acceptance, physical two-Mac, Oracle and release gates remain pending.

Machine-readable checks and exact artifact bindings are in REPORT.json.
