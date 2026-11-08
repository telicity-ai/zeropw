# Root03 read-only preservation audit

Audited 2026-11-08T07:13:54.741769+00:00 using actual gpt-6.1-sol / ultra. DATA-only trusted Git and independently written standard-library hashing; no project code, toolchain, tests, VM, runtime, credential, refs or index mutation.

Base and observed HEAD: `e47ab31a1886237ee970749508bde99df38d97f3`. Exactly the three Root03-allowed product paths differ; 1438 other tracked files match base Git blobs (direct working bytes hashed as Git objects). All tracked canonical Git executable modes match the base. The index has no diff. This binds the current hashes in audit.json; later edits require a new comparison.

| Path | Added / removed | Changed scope |
| --- | --- | --- |
| rust/src/team/compaction_heads.rs | 239 / 5 | Necessary Component import; fixed layout error; preflight beside persistence helpers; snapshot type check before existing read_json; cfg(test) hook actions and three new tests. |
| rust/src/team/sync.rs | 204 / 0 | Preflight call immediately after total, before identity/prepare/write; cfg(test) BeforeLayout and three new regression tests/helpers. |
| rust/tests/team_compaction_heads.rs | 101 / 0 | Three new real-path/regression tests only. |

The five removed lines are the old Path/PathBuf import and the four-line read_json argument spelling replaced by its one-line equivalent using the new local path. No original test line is deleted or rewritten. The synchronization and integration files contain additions only. The original prepare, strict cache decoding, schema/caps, record/cache fsync checks, publication/unlink bodies and early/no-op gates have no removed or rewritten lines. No added production hunk outside the documented Root03 preflight/readback/import/error/call scope was found.

Astra implementation-task Root03 section (lines 27–31) is the scope reference. Both document hashes match the handoff: decision `59d17e08875b8a3f844f579c22a1f37926ef8e162c9f1152be4db768f81aeab1`, task `71ebc802025c07e69d5b854d3276732e6a4ae28e4c2a7de396d0c29278341223`.

The final edit adds dangling snapshot/record destination-link assertions to the new unit test; the other later edits only reflow new lines. Final diff totals: 544 additions / 5 removals. No DATA preservation/scope mismatch found. This is not a compiler check, behavioral review, Opus review or acceptance. Every product test is **NOTRUN**; all findings remain **OPEN**.

Git whitespace-only check exit: 0. It is not formatting/toolchain validation.
