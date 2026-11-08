# Coverage (exact, static)

## Fully read
- `rust/src/team/compaction_heads.rs`: all 881 lines, including the cfg(test) `testing` module and the 5 unit tests.
- `rust/tests/team_compaction_heads.rs`: all 680 lines and 11 tests.
- `rust/src/team/mod.rs` diff: one `mod compaction_heads;` line.
- `rust/src/team/sync.rs`: the complete c413c92..0d3fdc5 diff (612 insertions/13 deletions: import, the compact body changes and all 8 `compaction_heads_tests` tests) and the complete post-change `TeamSync::compact` body (lines 9174-9339).
- The brief; AGENTS.md (in context); docs/product-intent.md; docs/security-design.md; docs/harness.md; harness/README.md; harness/review.schema.json; rust/PORTING.md lines 1-40 (§1); docs/whole-secret-deletion.md; docs/decisions/compaction-heads-2026-11-08/{decision.md, implementation-task.md, controller-binding.md}.

## Selectively read (actual dependencies only)
- `rust/src/store.rs`: StateDir struct/new/join, create/require/subdir, lock/locked_by_current_thread/acquire/release, read_json, write_json, mkdir_parent, tmp naming (about lines 30-268 and 540-562).
- `rust/src/team/fold.rs`: fold (1566-1586), snapshot_of_prefix (1620-1631), save_snapshot / load_latest_snapshot (2076-2105), snapshot_record / save_snapshot_record (2791-2823), op_member_add (983-1031), FoldResult (259-290), fold vector computation (2040-2062), plus grep-level views of the 1880-1960 area.
- `rust/src/team/commit.rs`: Hlc observe/tick/render/now_ms/order_key (280-330), snapshot_floor/vector/last_seq/append (1960-2060), hlc_not_above_previous / release_deferred head (2130-2200), device_registry/receive_commit (2263-2303), receive (2368-2460).
- `rust/src/team/sync.rs` outside compact: sign_authorized_fact/publish_signed_fact/store_and_apply_fact/store_fact head (6460-6540), submit_commit (6395-6440), handle_commit/persist_peer_vectors (7610-7700), the status tail before compact (9150-9172), and grep hits (canon at 69, COMPACT_MIN_AGE_MS at 64, hlc init at 5607).
- `rust/src/audit.rs`: subscribe/notify_listeners/record head (355-400). `pyjson.rs`: MAX_JSON_DEPTH value only. `vault.rs`: grep for state.lock only.
- Evidence (DATA only): docs/evidence/2026-11-08-compaction-heads-0d3fdc5/README.md; the head of FINAL-NATIVE-SUMMARY.json; the head of linux/validation-summary.json; a grep of native-full.stdout for compaction_heads test lines.

## Not read / skipped
- The remaining roughly 9,000+ lines of sync.rs (I did NOT read all 9,888); the rest of fold.rs, commit.rs, store.rs and vault.rs; identity.rs, pyint.rs and pyjson.rs internals beyond the call sites (DeviceRecord::from_dict/verify/to_dict, PyInt::from_json_integer, pyjson::loads/dumps behaviour taken from names and comments); membership.rs; load_facts body; refold body; checkpoint/**; gateway/signer; admin_cli caller beyond the grep; desktop.
- docs/team-sync.md, remote-sync*, M2 decision documents, and PORTING beyond line 40.
- All other evidence files (WORKER-REPORT, independent-collection, OWN-RESOURCE-HOLD, hold diagnosis, linux REPORT/phase files, stderr logs, the external frozen worker package).
- No Go repo, old service package, case12, VM, process or resource state.
