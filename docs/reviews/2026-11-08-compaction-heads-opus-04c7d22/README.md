# Actual Opus compaction review: REVISE

Actual Claude Opus claude-opus-5-5 through Claude Agent SDK/T3 Code reviewed the new four-file Rust change at HEAD04c7d22ae3f4317e9f203e5d7ca703974f8f1f69/Rustafc41fcb. Static only: no compilation, runtime repro, network or VM operation. Effort/thinking budget/tier were not exposed. The complete unchanged report, coverage and input verification are retained; the independent DATA collection found no integrity/schema gap.

| Finding | Severity | Status |
| --- | --- | --- |
| ZPCHEAD-OPUS-01: receipt registry admits public records from ops that fold skips; cache lookup only sees folded members | medium | OPEN |
| ZPCHEAD-OPUS-02: pruned predecessor HLC is not checked at receipt, later cache monotonicity refuses compaction | medium | OPEN; protected-scope decision required |
| ZPCHEAD-OPUS-03: unsupported symlink directory chain refused after snapshot/record writes | low | OPEN |

All three fail closed; Opus found no unlink before the durability barrier or data loss. The first two can persistently prevent later compaction. Recommendations are review DATA, not permission to bypass the frozen four-file scope or change compatibility. Coordinator is requesting bounded Astra decisions before protected receipt changes; no fix, runtime repro or resolved finding is claimed. The small preflight/readback implementation belongs to Root after the chosen policy; no separate implementation worker for that small item.

Original native1843/0/5 and Linux1840/0/5 remain valid exact-source test observations, not review PASS. Mac10unexplainedidentityHOLD, all M2/runtime/physical/Oracle/release gates and canonical global findings remain unchanged. This first Rust review is separate from interrupted Go Opus3eb. The latter was not retried/rephrased/replaced/continued. Snapshot onboarding remains unsupported.

Coverage is selective outside the changed code; see COVERAGE.md. No claim that all9888sync.rs lines or helper internals were reviewed. Original artifact hashes are in independent-collection.json/finding-status.json. Four original artifact byte copies remain unchanged. The collector's own DATA schema-projection correction is disclosed in independent-collection.md.

Subsequent [bounded Astra decision](../../decisions/compaction-heads-review-fixes-2026-11-08/controller-binding.md) now freezes the five-file01/02 scope. Root03 source is implemented at10aac874 and [frozen as unvalidated](../../evidence/2026-11-08-compaction-heads-root03/REPORT.md). All three findings remain OPEN; no old review/test result covers the fix. Fresh OS validation and new Rust review/acceptance remain pending.

Subsequent01/02 source is implemented and [focused Linux diagnostics](../../evidence/2026-11-08-compaction-fixes-focused-linux-9679097/README.md) at product9679097/Rust915528 passed29 library+27 integration tests after retaining/fixing one invalid synthetic fixture. This is not full verifier/release/macOS/re-review evidence. Two deterministic tests remain unwritten pending a narrow test-hook scope. Original severities and all findings remain OPEN.
