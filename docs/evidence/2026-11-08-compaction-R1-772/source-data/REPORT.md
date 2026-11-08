# Independent fixed-source DATA audit: 772e845

**Source preservation checks matched. This is not semantic validation, Opus review, or Astra acceptance. All HIGH/global holds remain OPEN.**

Actual worker: gpt-6.1-sol / ultra; effective service tier unexposed. Trusted Git reads and agent-authored Python standard-library DATA comparisons only. No subagents.

Pinned source `772e84517a188ad8ee60f2f247bf6413ac8fe88f` (Rust `a6d89b2e6855e7647e4aa3044a07dcca73f6fc40`) was compared to baseline `1a20a2dd03229925a5657ec011bb337542e5b4e1` and prior `f80baa0e6a1fe94a46cc0b7228f61e32f944333d`. Both source inventories contain exactly 1,519 paths. All Git modes match; exactly the four allowed Rust paths differ, while **1,515 protected paths match exact bytes, blobs and modes**. All baseline manifest entries and saved four before-files match their fixed Git objects. 1354 distinct blob objects were independently read and hashed.

Preservation checks:

- `commit.rs`: all old lines remain insertion-only; the old test-module prefix is exact. Two production helper insertions and one appended test region are the only three insertion boundaries.
- `compaction_heads.rs`: reverting only `checked_cache` and its nearby comment restores the whole baseline file.
- `prepare`, `device_registry`, `retained_device_registry`, `cached_hlc_not_above_previous`, and `observe_cached_hlcs` are exact; hashes are recorded in JSON.
- `sync.rs`: the entire old prefix, including production, scoped gates, helpers, old tests and Root03, is exact. New code is appended inside the existing test module.
- Integration: reverting only the approved earlier=true Y:2 assertion block and removing the one appended test restores all old source. Earlier compaction refusal, later=false, corrected `0o0`, owner-wrap fixtures and other original tests remain exact.
- Exactly seven new test names match the f80 audit; two new internal `pub(super)` helpers are the only added internal API surface. Added-line scans found no external public function, suppression, unsafe block, scoped gate or process/environment hook. All dependency, CI, harness, schema and permission-policy files are protected and unchanged.

Relative to fixed f80, **only new test bodies in `commit.rs` and `sync.rs` differ**: invalid expected self-signature negative; alias-only negative before writing the canonical huge-sequence file; and the absent-evidence row's audit expectation plus exact audit length. Both production areas and the entire integration file are identical to f80. These statements map source text, not test outcomes.

The actual Astra decision/task were read in the prior audit and rehashed here; both match the assigned digests. The earlier independent f80 JSON also matches its published digest. All bindings, test names, preservation checks and limits are in REPORT.json.

Observed Root HEAD was `772e84517a188ad8ee60f2f247bf6413ac8fe88f`; tracked status was ''. This is separate non-atomic metadata, not a moving-worktree validation claim; the audit applies only to fixed 772e845.

No product/helper/compiler/formatter/test/harness/dependency code ran. No runtime/process/cache/VM/SSH/network/credential was queried. No source/index/ref writes occurred. Original failures remain preserved; no current diagnostic or final validation status was independently inspected. **ZPCHEAD-OPUS-R1-01 HIGH and all original/global holds remain OPEN.**
