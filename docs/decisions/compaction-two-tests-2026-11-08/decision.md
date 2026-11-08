# Finite Astra decision: two deterministic tests

2026-11-08. Actual gpt-6-astra / ultra, T3 Code through Codex. Requested tier default; effective tier unexposed. Personal static source/test-scope planning only: no implementation, agents/workflows/other models/Opus review/recheck/acceptance.

READY for Root personally to implement exactly two unit tests and two narrow cfg(test) gates specified in implementation-task.md. No implementation delegate. READY is bounded source-only scope, not runtime authority or validated behavior. ZPCHEAD-OPUS-01 MEDIUM,02 MEDIUM,03 LOW remain OPEN.

## Binding and verification

Worktree /Users/ys/.t3/worktrees/zeropw/t3-3729f0e4.
HEAD5f4d045f289c53c41178f3f062f6c6f74fb561e2.
Full tree981db6aee4577652f8d1b651bccf97f53294a316.
Rust915528f2f83a8ce863cb2543cd22858569adea20.
Desktop2413844c89265a3e239be2372d34b1e6e1b2d4bb.

First operation hashed ALL8,673 brief bytes using own stdlib, required the invocation SHA-256, then read its complete text. Exact SHA-256 bindings:

- /tmp/zeropw-compaction-two-test-scope-astra-20261108.md: 27cb97b84b828aa29d98bcd966de4f369f508376df4d61b93af13afe1e3a6a8d
- preparation/source-manifest.json,455,893 bytes: 4ab451fb86d4430b26587a661fd8d1f97a51456da7d858e3b8e1b582b281c0b5
- preparation/input-bindings.json,1,927 bytes: b56c8f370dccb9fe4c61bb164a75a736a3c21d554eea6cbbf5b1e2946c8debbb

Preparation is /Users/ys/Code/zeropw-mlp-evidence/compaction-two-test-scope-astra-preparation-20261108. Fully read input-bindings.json and all ten bound documents; their exact paths/lengths/hashes are transitively bound above. Before/after output, all1,464 tracked path sets/lengths/SHA-256/independently computed Git blobs/HEAD-index entries/Git modes/POSIX modes match; checkout clean, trees unchanged. Exact16 docs-only adaptation paths from9679097 match adaptation.json; Rust unchanged. No drift waiver. Hashing all files is not reviewing all source.

## Static coverage and choice

Fully read AGENTS, product-intent/security-design, docs/harness, harness/README, PORTING §1; complete current review-fixes decision/task/controller-binding; original Opus report.json/report.md/COVERAGE, unchanged review schema and finding-status; worker report/freeze/oracle map; focused-Linux README and runtime-independent-collection. Relevant original scope/fault-test clauses were read. Evidence is not permission.

Full relevant source bodies read: compaction_heads load/decode/prepare/checked_cache/clock helpers/testing and corrected clock-helper test; commit Hlc/CommitStore/registry/receipt/release/new tests/issue52 deferred tests; sync authorized signing, adjacent submit/publish/store paths, compact, Fixture/publication_files/change_before_layout, ClockSession/clock_candidate and new receipt/serialization tests; membership load_environment/new compaction test module. Also StateDir locking, fact validation/sign/verify/role/load_facts, register_env/refold, selected fold_env, audit/tombstone paths, relevant deferred integration cases and full verify.sh. Necessary truncated portions were reread. Remaining legacy tests, most sync/fold/checkpoint/crypto/Desktop/raw evidence were not comprehensively inspected. No runtime/resource inquiry.

The release gate is after the unlocked gap filter passes, before per-item lock. Real forward receipt can change last4 to5 during this pause. Fresh last_seq must select duplicate/equivocation/pruned-drop before cache; stale last instead reaches helper's fresh non-next check and append's duplicate error, leaving the deferred file. Literal inventories discriminate this error.

The cache gate is AFTER actual File::open/descriptor type check, BEFORE bounded read, within authorized signing's real cache load while StateDir is held. This is not a caller-side pause before observe_cached_hlcs, nor a simulated blocked kernel read. Controller positively acquiring envs here proves the intended availability at this point.

## Only superseded restrictions

References are to docs/decisions/compaction-heads-review-fixes-2026-11-08/implementation-task.md at this base.

- Lines19/21/25 closed-hunk/extra-hunk STOP expands ONLY for cfg(test) statements at commit.rs:2226–2227 and compaction_heads.rs:233–234, private scoped channel support in its existing testing module, and two new tests/helpers appended inside sync.rs's existing compaction_heads_tests. No other old hunk reopens.
- Line64 “Present cache uses unchanged load/decode”: allow ONLY that test statement in load; every old loader check/open/read/decode/error statement remains exact. Decode entirely protected. Historical worker loader-preservation statements remain unedited.
- Original compaction task's closed fault-point list/“faults at new-code boundaries” expands ONLY by these two points. Current line78 authored-wall hook remains at its SAME three tick sites; no fourth override.
- Old staged Sol01/02 assignment is superseded ONLY for this slice: Root personally implements, no new worker.

Current decision lines59–67/task lines68/72–80 semantics stay unchanged. Root03 preflight/readback/barriers, original findings/schema/evidence, valid-wrap correction and every existing test/assertion/helper remain protected. Historical missing-test statements remain true for their frozen source.

Only rust/src/team/{commit.rs,compaction_heads.rs,sync.rs}; no membership/integration edit needed. Outside two inserted cfg(test) statements all existing non-test source stays byte-exact. Append narrow test definitions; no fixture refactor/broad formatting/public API/callback/global or env switch/unsafe/dependency/features/CI/harness/golden/oracle/production-behavior change. Extra file/non-hook production hunk => STOP with concrete dependency.

Gates: private, one-shot, thread-local, exact owned root/env scoped, channels only, bounded waits/cleanup. Non-test release artifacts contain neither hook nor switch; optimized unit tests intentionally compile cfg(test). No backward-history fixture is needed/authorized; locked still-gap defense remains, without claiming forward-only tests exercise backward history.

## NOTRUN and unchanged holds

Linux29+27 PASS is prior Rust915528 evidence, not future-hook/full/both-OS/release/exact evidence. Preserve genuine initial fmt/invalid_wraps/R3 fmt and DATA/collection failures. Collector verified117 frozen files/11 phases/four variants/pins;8,194 upstream hashes were saved assertions, not independent rehashes of absent bytes. This task did not extend that collection.

Future source-bound fresh isolated Linux AND macOS full unchanged rust/verify.sh, focused debug/release, same-source paired features and seven exact selectors both profiles14/OS remain NOTRUN. Actual Opus re-review/acceptance remain missing, not authorized now. No resource grant/query/reuse/clear: cf01 stopped/retained is DATA; old stopped Mac/native10 HOLD not RELEASED.

All OPEN: compaction01/02 MEDIUM,03 LOW; DOS-1 HIGH/ca01275/OPUS03/03-R1/SEC03; interrupted GoOpus3eb/case12 custody/cancellation quarantine; M2-G01–G10/runtime/READY/import/receipt/ACK/journal/coherent epoch/general-gap/interacting-removal/continuation; wide-commit timeout; physical two-Mac/sleep-wake/GUI/macOSACL/packaging/Oracle/capacity/release/acceptance. Snapshot onboarding unsupported. No Go retry/rephrase/provider replacement/continuation/campaign; no merge/deploy/installer/provider readiness.

Own stdlib DATA/trusted read-only Git/text only. No product/helper/compiler/formatter/build/test/dependency execution, source/ref/index/coordination changes, or VM/process/SSH/network/cache/HOME/key/admin/production access. In-memory drafts31,013 and25,674 bytes failed pre-write size guards, writing nothing. A wrapper metadata check failed before shell dispatch; it wrote nothing. Final output exactly decision.md and implementation-task.md externally, combined<=24,576 bytes.
