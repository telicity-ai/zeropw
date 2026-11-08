# Actual-Sol task: retain original signed heads before compaction

Bounded specification only; no task launch/resource assignment. Use actual Sol and record actual model/settings. Root must separately supply worker checkout and isolated Linux/macOS assignments. Do not edit this design/coordinator checkout or use R2's exclusive UID2000/newrg01, unassigned Mac501 or old Go quarantine. No model/provider substitution, subagent/workflow or review authorized here.

Implement retention in real TeamSync::compact while preserving live-log deletion behavior. This is a prerequisite, not snapshot transfer/import, general semantic verification or acceptance. Read decision.md fully. All M2-G01–G10 OPEN.

## Base and finite edit scope

HEAD `06ab4784d9ac387307f96bc976df1bbc20de2bb1`; full tree `006a9879da19ec21424e9a12d160a97f20b369b8`; Rust `4352ebbd0fa84bde0fb444c4d0902ef2510d0620`; Desktop `2413844c89265a3e239be2372d34b1e6e1b2d4bb`; code origin ee26e36997797fe9893ed9a8314ea497963961e2. Verify all1352 paths/bytes/lengths/blobs/modes against preparation source-manifest.json SHA-256 `070cd8b861adf274391e3bfeb550cfb5ee377d45f01066625a43242b4fe62ded`. No silent rebase; coordinator binds collected diff/readiness to exact changed head.

Read AGENTS, product-intent/security-design, docs/harness/harness README, PORTING §1, whole-secret-deletion, team-sync §7.3, complete M2 milestone/checklist, remote-sync, M2a/parser-amendment/M2b/M2b2 decisions and both required-generation documents. Required-generation hashes: `d4f80f910a3209b4d4399e302f8c63c65316ae78a06421f46043bacf9630b158` and `4d8990b5c6a38ff7c6224c7c1e734998a18b8416c579b211d9489663e40ed1c8`. Preserve fixtures/canonical helpers/evidence. No cancelled f95251c9 output.

Only these files may change:

| File | Permitted edit |
| --- | --- |
| rust/src/team/mod.rs | Private `mod compaction_heads;` only, no public export. |
| rust/src/team/compaction_heads.rs (new) | Private cache selection/validation, bounded I/O, durability barrier, cfg(test) fault tests. |
| rust/src/team/sync.rs | Imports; bounded TeamSync::compact integration/lock scope; private cfg(test) compaction hooks/tests only. |
| rust/tests/team_compaction_heads.rs (new) | Synthetic real-compactor integration tests/independent expectations. |

All else protected: existing tests/fixtures; fold/commit/checkpoint/**; membership/pairing/envelope/identity; store/Context/KMS/vault/policy/tombstone/gateway/signer; CLI/Desktop/link/server; Cargo manifest/lock/features/dependencies/helpers; CI/harness/verify.sh; AGENTS, operating/authority/evidence/docs. No generator/dependency/unsafe code/public debug API/production failure switch. Protected-file need means STOP with evidence. Later product-document updates belong to coordinator/Astra. Existing persisted/wire formats remain unchanged.

## Frozen local cache contract

Path `team/{env_id}/compaction_heads.json` under trusted StateDir. Additive local evidence, never frame/live commit/receipt/admission/vector floor. Exact keys:

```
{
  "format": "zeropw-team-compaction-heads-v1",
  "env_id": existing_valid_environment_id,
  "vector": {author_fingerprint: positive_exact_PyInt, ...},
  "heads": [{"author": ..., "author_seq": ..., "hlc": ...,
             "commit_hash": ..., "device": full_DeviceRecord,
             "commit": full_original_Commit_including_sig}, ...]
}
```

Heads sorted by author, exactly one per vector key/no extras. Omit zero vector components, reject negatives. Preserve exact PyInt and original signed HLC; no f64/u64 narrowing. Device is existing DeviceRecord::to_dict; commit is complete Commit::to_dict, all ops/original signature. Preserve canonical_json(false) signed bytes and canonical_json(true) hashed bytes exactly. File indentation is not signed evidence. Never reconstruct/project/re-sign originals.

Use unchanged PyInt/pyjson/Commit/DeviceRecord helpers. Validate closed schema, env/author/fingerprint/slot/HLC/hash, full record self-signature and commit::verify_commit. Require new-cache bytes equal pyjson::dumps(parsed_image, DumpOptions::pretty_sorted()), and decoded originals equal their canonical representations. Thus duplicate/extra fields, trailing bytes and normalization changes refuse. This is StateDir::write_json spelling. Round-trip prospective image through the same loader before publication. No raw_value feature/new parser/number codec/crypto. Legacy reserved-key or depth incompatibility refuses before deletion; no normalization fallback. Do not impose checkpoint depth64 on legacy commits.

Caps:256 nonzero authors;16,777,216 serialized UTF-8 bytes. Read at most cap+1 before parsing new cache; reject non-file/oversized/unsupported/corrupt cache. Finish prospective shape/size/round-trip checks before any new snapshot/cache write. Never omit authors to fit. Additional indexes scale with selected heads; no long-lived second history archive or new 1..max-sequence enumeration. Existing all_commits/fold/canonicalization work remains; no total memory/time or DOS-1-fix claim.

One replaceable cache, not one per snapshot. New vector includes all prior nonzero authors and is componentwise nondecreasing. Equal slots require identical canonical originals/full records; higher slots require increasing parsed HLC. Refuse regression/corruption instead of discarding old evidence. If absent, initialize only when every exact required head remains live. No GC/background migration/network repair/arbitrary earlier-cut fallback or cache-derived live vector advancement.

This preserves the latest compaction cut's heads. Future current-cut export must copy exact live/cache evidence under lock and own immutable copies for in-flight cuts. It must separately establish authority/facts/gapped semantics. Cache authenticity cannot prove membership authority, omitted completeness, removal semantics or eligibility.

## Private APIs and real algorithm

No public export:

```
pub(super) fn prepare(
    state: &StateDir, env_id: &str, snapshot: &FoldResult,
    live: &[Commit], identity_document: &Value
) -> Result<PreparedHeads>;

pub(super) fn persist_before_prune(
    state: &StateDir, env_id: &str, total: &PyInt,
    prepared: PreparedHeads
) -> Result<()>;
```

PreparedHeads: private fields/constructor, no public Serialize/Clone/record-bearing Debug, key getter or checkpoint/receipt conversion. It is an I/O plan only. Both helpers check actual StateDir::locked_by_current_thread(), never caller Boolean. Bind env/vector/total to plan and matching on-disk snapshot vector. Only production caller is compact with real locked state; no external callback supplies a security decision.

1. Acquire self.ctx.state.lock() before compaction inputs; hold through selection, durable publication and deletion. Lock order: StateDir then short envs acquisition, as refold. Never wait for StateDir holding envs; no disk/fold/network under envs or network wait/sleep under StateDir.
2. Confirm registered environment; briefly copy peer vectors from envs. Reload facts through load_facts and read CommitStore::all_commits under state lock. Derive current members through fold::fold_with_snapshot with those fresh facts/commits, not stale cached members. Existing load_facts may maintain receipts/rejected facts/tombstones; preserve it and do not claim refusal rolls that maintenance back. New module never issues receipts/unwraps keys.
3. Preserve current age cutoff, active-peer vector rule, total ordering, exclusions and result schema (env_id/removed/blocked_by/existing no-old reason). No-old/blocked attempts publish no cache/delete nothing. Build snapshot_of_prefix with fresh facts/full live slice as now; PyInt-sum its vector. Select that vector's heads including prior coverage, not only old live-prefix maxima.
4. For identity material use existing fold::fold(env_id, live.to_vec(), None, None, None, None), as load_facts does. Parse full members' DeviceRecords, including inactive/removed records. This supplies public signature-verification material only, not remote authority proof. No derive_local/decryption/key creation in head module.
5. prepare validates old cache and finds every exact (author,snapshot.vector[author]) in live/cache. If both exist, canonical bytes/full records must agree; never choose one equivocation. Cached originals verify and match full local record. Newer live head beyond cutoff cannot replace required slot. Missing exact original/full record refuses; self-reported hash alone proves nothing.
6. Complete all checks before mutation. Call unchanged fold::save_snapshot and save_snapshot_record for matching vector/total. Keep snapshot_record(Some(&facts), &commits), never provenance. Either write failure: no unlink.
7. Before cache replacement, durably publish snapshot and record: writers already sync files; explicitly sync directories/relevant ancestors beneath and including StateDir root using safe File::open(dir)?.sync_all(). Atomically write cache with StateDir::write_json, sync its parent/required ancestors. Bounded disk reload must equal prepared evidence/signatures and match snapshot vector. Any write/rename/readback/fsync failure stops before deletion; never ignore unsupported directory-fsync error. Do not rewrite StateDir or call rename alone durable.
8. Only after barrier run existing unlink loop. Exact exclusions: env.init/member.add/member.set_role/member.remove/owner.transfer/dek.rotate. Any mixed commit stays live. Preserve successful-unlink counting and existing best-effort individual unlink behavior; failure leaves extra live copies. Never delete cache/authority originals to roll back later error; no broad temp cleanup.
9. Update last_snapshot_total consistently; release outer StateDir before existing refold/audit/result handling. Never convert their errors into success/onboarding completion. Existing trusted derivation/grants unchanged.

Safety: **no new unlink before durable snapshot/record plus exact signed-head evidence**. Not a multi-file atomic import transaction. Before barrier, crash may leave extra metadata but all scheduled originals remain. After barrier, partial deletions require durable cache heads and snapshot data/order. Existing loaders ignore cache; repeated compact reloads it. Recovery need outside these files means STOP, not an invented installer journal.

## Refusals and non-effects

New errors use Error::state with fixed reasons/no input-bearing details:

| Reason | Trigger |
| --- | --- |
| team_compaction_head_unavailable | Missing exact original or full local record, including legacy compaction loss. |
| team_compaction_head_invalid | Malformed/unsupported/corrupt cache; canonical/signature/hash/env/slot/record conflict; vector/HLC regression. |
| team_compaction_head_limit_exceeded | >256 heads, >16 MiB serialization, required new-cache depth unsupported by unchanged helpers. |
| team_compaction_head_persist_failed | Cache write/readback or required durability barrier failure. |
| team_compaction_lock_required | Private helper called without real lock; invariant failure, no user approval flow. |

Existing fold/fact/snapshot errors retain reasons. Evidence refusals precede new snapshot/cache writes/unlinks; persistence errors may leave metadata but no unlink before barrier success. Never invent missing seq/HLC/signature or waive history-required refusal. No plaintext/raw DEKs/private signing/agreement/KMS/invite material/local receipt copies in cache/logs/errors/artifacts; no decryption to preserve commits.

No new capability/frame/candidate getter/installer/approval store/READY/receipt/ACK/activation/synced/joined signal, CLI/GUI option, server vault storage or agent credential release. Preserve M1 whole-secret deletion/fact ACK/revocations and HTTP/SSH grant enforcement. SSH core; unsupported integrations explicit refusal. Existing backup omits cache, loss does not authorize reconstruction. Task bounds do not permanently prohibit future runtime work.

## Independent and failure-boundary oracles: future, NOT RUN here

Exercise real TeamSync::compact, not only prepare. Manually specify expected slots/HLCs/deletion sets and secret/version/order outcomes. Retain pre-compaction original canonical bytes as second preservation oracle. Expectations must not come from new selector. verify_commit/ordinary-fold comparison are correlated checks, not independent proof. Existing synthetic signing helpers only; no generator or changed fixture.

| Case | Required outcome |
| --- | --- |
| Final data head | Genesis1/old data2: removed=1/live2 absent; cache exact2, unchanged signed/hash bytes/HLC/full record; literal secret/version/order survives. |
| Newer live head | Old2/recent3: cache cutoff2, not3;3 stays live; later compact replaces with exact newer head. |
| Idle/restarted author | Multiple authors, one unchanged in second compact. Reopen Context/TeamSync between attempts. Prior vector/idle original survives through cache; active head advances; deleted paths stay absent; next ordinary sequence works. |
| Authority/removals | Six kinds/mixed commits/rotation/self-removal witnesses byte-identical live; removal/fact semantics unchanged; removed record need not be active. |
| Legacy compacted state | Legitimate old snapshot/deleted data head/no cache: unavailable before new snapshots/cache/unlinks. Existing ordinary local behavior unchanged; no lower-head substitution. |
| Corruption/equivocation | One-axis mutations of env/author/slot/HLC/hash/signature; same signing fingerprint/different agreement key/full record; duplicate/extra keys/trailing bytes/version; absent head; same-slot conflict; vector/HLC regression. Exact refusal/no prune/publication. |
| Bounds/compatibility | At/over256 and16 MiB; oversized read before parse. PyInt beyond u64 in private selector tests without huge scan. Legacy floats/opaque fields/depth preserve bytes or explicitly refuse before deletion; legacy parser tests unchanged. |
| No-old/lag/freshness | Original results/blocked_by/deletion sets; no cache. Normal writer's facts/members before lock acquisition reflected despite stale TeamSync cache. |
| Real serialization | Two StateDir holders/compactors serialize without lost heads/deadlock. Barriers/channels/bounded joins, no timing-only sleeps. Edits/facts cannot enter between selection/unlink. |
| Fault ordering | cfg(test) points at snapshot/record calls, directory barrier, cache write/rename/readback/fsync, before/after first unlink. Inject write/disk/sync failure. Independent ordered-effect assertions: every unlink follows both durable images; pre-barrier zero unlinks. No production callback/Boolean controls authority. |
| Interruption/reopen | Assigned subprocesses or deterministic effect-prefix fixtures stop at new boundaries/partial deletion; reopen through existing public loaders/refold. Literal secret/version/order/vector/facts survive supported fixtures; exact heads available live/cache. No fabricated success/receipt/activation. Process interruption is not hardware power-loss proof. |
| M1/restore/separation | Original whole-secret tombstones/version revocations effective across compact/restart; late put unusable. Backup not claimed to archive cache; absent/corrupt cache grants nothing; checkpoint gap refusal/no-getter/no-install boundaries unchanged. |

Inject faults at new-code boundaries and use real test-owned filesystem failures for unchanged StateDir calls. Do not claim hooks inside its protected writer. Private fault tests/hooks stay in allowed modules; no public injection API. Test-only effects target own paths/current thread; spawned children joined within assignment bounds. Never touch other jobs. Existing tests cannot be deleted/ignored/renamed or weakened. Unexpected legacy failure: scope STOP with exact case.

## Future isolated Linux/macOS matrix

Not executed here. Root separately assigns each OS, source/cache bindings, synthetic accounts/fixtures, budgets and own-process cancellation/release. No production authority; account changes are Root's job. No R2/unassigned runtime access. Missing OS assignment means NOTRUN/overall incomplete, not permission to reuse released runner.

On each assigned exact worker tree capture commands/status/counts, head/diff hashes, before/after features and own-resource receipts. Job-owned targets/approved dependencies; set CARGO_NET_OFFLINE=true inside the assigned sandbox. Missing cache stops; no network install/cache rewrite/fixture regeneration:

```
cargo tree --locked --manifest-path rust/Cargo.toml -e features
cargo test --locked --manifest-path rust/Cargo.toml --lib compaction_heads
cargo test --locked --manifest-path rust/Cargo.toml --test team_compaction_heads
cargo test --locked --manifest-path rust/Cargo.toml --release --lib compaction_heads
cargo test --locked --manifest-path rust/Cargo.toml --release --test team_compaction_heads
bash rust/verify.sh
cargo tree --locked --manifest-path rust/Cargo.toml -e features
```

Private fault-test names/paths include compaction_heads so filter selects them; verify nonzero counts. Unchanged verify.sh covers fmt/strict Clippy/lib+binaries/all integrations/signer probes/doc tests. New target auto-discovered; no harness/CI change. Preserve compaction/fold/oracle/M1/tombstone/canonical/checkpoint/required-generation/native-CLI/signer coverage. Reconcile actual counts, never copy 106-target historical totals. No subset replaces full script.

Repeat seven exact selectors in both debug/release per OS (14 commands/OS): `cargo test --locked --manifest-path rust/Cargo.toml [--release] --test TARGET SELECTOR -- --exact`. Require exactly one executed test each. Actual 256 KiB test bodies unchanged; no stack-variable substitute.

| Target | Selector |
| --- | --- |
| team_checkpoint_payload | full_verifier_total_depth_64_65_and_post_parse_helpers_on_256_kib_stack |
| team_checkpoint_admission | semantic_depth_64_success_error_drop_on_256_kib_stack_and_65_refusal |
| team_checkpoint_semantic_cut | complete_candidate_depth64_success_late_error_repeat_drop_and_65_refusal_on_256_kib |
| team_checkpoint_semantic_cut | complete_fold_depth64_on_actual_256_kib_stack |
| team_checkpoint_required_generations | required_generation_depth64_success_late_error_repeat_drop_on_actual_256_kib |
| team_checkpoint_required_generations | required_generation_depth65_refuses_before_crypto_on_actual_256_kib |
| team_checkpoint_required_generations | required_wrap_depth64_success_error_repeat_drop_on_actual_256_kib |

Preserve every failure/timeout/exact input. No restarted 23,000-op campaign or capacity inference from smaller distributed input. Stop at limits/join only own children through assigned lifecycle. Feature-after may be collected after failure if assigned; unrun never PASS; original Linux NOTRUN immutable.

## Stops and handoff

STOP: base/inventory drift, protected-file need, missing real lock/fold/device evidence, irrecoverable history, canonical incompatibility, unsupported durability, legacy regression, wrong/zero exact-test selection, dependency/feature drift, secret exposure, budget failure or ambiguous resource authority. Preserve concrete case/diff/results; no weakened refusal/alternate model/review/runtime. No merge/push/publish/deploy/release/account/VM/permission change.

Return exact changed files/diff/head, schema/limitations, oracle-test map, every command/result/count/timeout/NOTRUN by OS, source/dependency preservation and assigned own-resource completion receipts. Coordinator decides readiness; no invented Opus verdict/acceptance.

Retain original Linux FAIL1812/4/5, feature-after NOTRUN/all14 exact PASS; shell correction and management DenyUsers before R2 product execution; fourth blank-stderr cause inferred. R2 PENDING until coordinator supplies completed evidence. Historical native1819/0/5/all14PASS does not validate changed head. DOS-1 HIGH/OPEN_NOT_FIXED_PARTIALLY_MITIGATED; ca01275 REVISE; OPUS03/03-R1 OPEN; SEC03 INSUFFICIENT_EVIDENCE; original resolved/new LOW-nit statuses unchanged; interrupted Opus3eb no accepted verdict. All M2/runtime/physical/Oracle/capacity/release and old Go authority/cancellation holds OPEN; no original finding resolved by this task.
