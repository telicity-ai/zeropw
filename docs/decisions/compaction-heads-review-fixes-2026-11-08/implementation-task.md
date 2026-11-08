# Implementation handoff: Root03, then bounded Sol01/02

Static design: actual gpt-6-astra/ultra, requested default tier (effective tier unexposed),2026-11-08. Read decision.md. No launch/execution/review/acceptance claim. Original actual Claude Opus5.5 REVISE: ZPCHEAD-OPUS-01 medium,02 medium,03 low ALL OPEN; original reports/evidence immutable.

## Base and stages

HEAD e8fa90e74bab30088761d717f59fe8104ed3d670; Rust afc41fcb5d55aaec2bc2fead7c7d8a94f312cc9f; Desktop2413844c89265a3e239be2372d34b1e6e1b2d4bb. The1,434-file manifest at decision.md's preparation path has SHA-2562860c7e81cf10827ae47202a3c985c7fbea3b43f7056957602b6e4f471b63672. Verify bytes/lengths/SHA/blobs/modes before/after.

Root **actual Sol personally implements03**, no extra worker/concurrent checkout editing. Freeze03 exact head/tree/diff/full manifest plus tests/NOTRUN. Root may explicitly adapt larger worker base: only enumerated03 hunks plus recorded docs-only changes differ from e8fa, all other product bytes/modes identical. No moving base/silent rebase. Separately assigned actual Sol then implements01/02, preserving03; record actual model/settings. No subagent/workflow/model substitution; further product drift=>new decision.

Source-only work is not execution permission on coordinator/key-bearing host. Fresh Linux/macOS allocations separately frozen; native10 HOLD, retired Linuxch01, Go quarantine and Astra49df resources/outputs cannot be reused/queried.

## Closed files/hunks

Anchors at e8fa; adapt by content to frozen03. Only necessary imports allowed.

| File | Allowed hunk |
| --- | --- |
| rust/src/team/compaction_heads.rs | 03: preflight beside persistence helpers, regular snapshot check366–395, narrow cfg(test) actions/tests. 01/02: prepare251–364 identity parameter/source, private checked-clock helpers reusing loader, tests. Schema/caps/strict decode/monotonicity/barrier unchanged. |
| rust/src/team/sync.rs | 03: preflight after total9251–9254 before prepare/write; tests. 01: identity fold9255–9259 replaced by registry. 02: authorized signing6484–6494 clock observation/short envs merge; new compaction_heads_tests. No fact-admission/early/refold/unlink changes. |
| rust/src/team/commit.rs | 01/02: device_registry2263–2290 visibility/comment only; snapshot_floor1974 visibility only; one retained-file registry method; receive2368 entry lock; hlc_not_above_previous2146–2157 and calls2448/2207; fresh sequence check after release2199; new separate cfg(test) compaction_heads tests. append/get/vector/all_commits/digit_stems/sign/verify bodies protected. |
| rust/src/team/membership.rs | 02: author_commit349–360 cached observation/reuse live slice; authorized fact clock431–437; narrow test-only wall-time input at ticks/new tests. Standing/rotation/refold/receipt/publication protected. |
| rust/tests/team_compaction_heads.rs | Add real-path cases/narrow fixture helpers. Preserve existing11 outcomes; Root03 first, larger worker01/02 additions. |

No other file/module; mod.rs unchanged. Existing compaction_heads unit fixtures may mechanically replace identity(Value) with typed record maps; preserve all assertions/caps/huge-int/corruption expectations. Legacy tests/goldens/raw logs untouched. No broad formatting/unsafe/dependencies/generator/public evidence export/production switch. fold/checkpoint/identity/envelope/pairing/other membership, StateDir/Context/clock/helpers/crypto/KMS/vault/policy/tombstone/gateway/signer, CLI/Desktop/link/server, Cargo/features/CI/harness/schema/verify.sh/AGENTS/docs/evidence protected. Extra file/hunk=>STOP.

## Root03 contract

`pub(super) fn preflight_layout(state: &StateDir, env_id: &str, total: &PyInt) -> Result<()>`: actual lock, valid env, component containment. Non-following metadata requires real directories at root/team/env/snapshots/snapshot_records. Inspect root without final slash/dot disguise; don't change StateDir/trusted ancestors above root. Existing snapshot/record `{total}.json` and cache must be regular non-symlink. Missing prospective children allowed/no mkdir. Missing root/I/O=>persist_failed; type/containment=>layout_unsupported; details empty. Readback absence/nonregular/symlink=>persist_failed BEFORE both snapshot reads. All record/cache checks/fsync remain.

Call after no-old/peer gates/total, before prepare/write. No rollback claim for .lock/load_facts. Real-path tests: symlink root/team/env including dangling/slash-dot spelling => exact refusal, unchanged snapshot/record/cache inventories/all originals, zero unlinks (baseline AFTER registration/refold). Missing prospective dirs/files => successful literal count/head/document; existing regular paths permit repeat. Non-directory ancestor/nonregular destination => prepublication refusal. Replace snapshot at readback with symlink to IDENTICAL JSON, directory or absence => persist_failed/no unlink; retain rename/fsync tests. Hooks cfg(test)/own paths/current-thread only. No TOCTOU/hardware guarantee. Freeze03 before01/02.

## Private interfaces

```
// commit.rs; existing selection, internal visibility only
pub(super) fn device_registry(live: &[Commit]) -> HashMap<String, DeviceRecord>;
// existing CommitStore method, body unchanged; NEVER cache-derived
pub(super) fn snapshot_floor(&self) -> Result<BTreeMap<String, PyInt>>;
// new CommitStore method: actual filenames only
pub(super) fn retained_device_registry(&self) -> Result<HashMap<String, DeviceRecord>>;

// compaction_heads.rs
pub(super) fn prepare(state: &StateDir, env_id: &str, snapshot: &FoldResult,
    live: &[Commit], records: &HashMap<String, DeviceRecord>) -> Result<PreparedHeads>;
pub(super) fn cached_hlc_not_above_previous(store: &CommitStore<'_>,
    candidate: &Commit, live: Option<&[Commit]>) -> Result<bool>;
pub(super) fn observe_cached_hlcs(store: &CommitStore<'_>,
    live: &[Commit], clock: &mut Hlc) -> Result<()>;
```

Normal lifetime/import spelling allowed. Some(live) is fresh all_commits ALREADY read under this lock; None is deferred release. Helpers assert actual lock/bind store+env. Return only rejection predicate/update caller Hlc; originals remain inside helper/dropped before return. No record-bearing getter/Debug/Serialize/Clone package or evidence handle across lock epoch. PreparedHeads retains private ownership/binding. Shared internal validator allowed; no caller Boolean certifies disk state.

prepare receives device_registry(actual ordered live), not members. First verified normalized complete record; missing=>unavailable, invalid/full conflict=>invalid. Raw extra/coerced fields stay in signed ops; separate device uses to_dict. No active-member filter, skipped-vector omission or relaxed same-slot/higher-HLC checks. load_facts unchanged.

### Retained-file registry

Receipt/local signing reuse live; deferred must NOT add all_commits() (1..vector scan). New method enumerates actual author directories in vector's sorted traversal, applies unchanged digit_stems, sorts/deduplicates positive PyInt stems, calls get(author,seq) only for actual stems. Canonical path lookup is essential: Unicode/leading-zero stems must not become newly accepted alternate files. Skip absent/falsy results; preserve digit_stems errors. Stable-sort internal retained commits with sort_total_order then SAME device_registry. Return only private record map, never history Vec/getter. No writes/repair/all_commits/vector/get rewrite. Cache helper maps new read failures to fixed local evidence errors.

Tests prove literal first-record order/equal-HLC stable ties/op order/sparse files/alternate stems; unchanged all_commits registry parity is secondary. Cost scales with actual files, no new1..peer_seq loop; temporary retained input is not a persistent archive. Cache caps don't bound legacy history/resolve DOS-1. Protected need=>STOP.

### Validation and clock use

After require_lock, absent cache is legacy no-op (no new schema/env/cap restriction on absence). Present cache uses unchanged load/decode: regular cap+1 bounded read, exact pretty spelling/closed keys, exact positive PyInt/sorted heads, env/author/slot/HLC/hash/full record/signature/original canonical equality. Caps256/16,777,216 remain.

Registry from Some(live) or retained-file method, NEVER incoming bootstrap fallback/cache. Every cached record equals current first full retained record: missing=>unavailable/different=>invalid. Every C component covered by unchanged S=snapshot_floor and V=vector; missing coverage/ahead=>invalid. Exact cached slot also live=>identical signed/hashed canonical bytes/full record. At most256 exact get calls, no range scan. Don't identify unknown authors/increase V from cache.

Candidate n>1 exactly V[A]+1: require HLC above live n-1 AND cached A if present. If n-1 missing under present cache, require EXACT cached n-1; older/absent=>unavailable. n<=1/non-next returns false without cache; branch order unchanged. Eligible validation precedes HLC rejection. Absence never creates unavailable. observe_cached_hlcs validates fully before updating clock, observes all cached HLCs; caller observes live. With present cache, each positive V head must be exact live/cache (index supplied live, no1..seq); missing later head=>unavailable. Older cache allowed if newer heads live; S needn't equal C. No writes/repair.

## Entry points, locks, errors

receive locks store.state at entry before state reads/quarantine writes, holds through decision/write. submit/handle reenter SAME StateDir; never second StateDir for nesting. Keep format/env/ops/bootstrap/unknown/signature/duplicate order, future-before-gap, early/quarantine/audit fields. Pass existing live slice to new predecessor check. No new network/callback under lock; TeamSync handling/broadcast positions unchanged.

release keeps unlocked due/gap prefilter. Under per-item lock reread lastseq; still-gap leaves file. <=last duplicate/equivocation/drop before cache. Now-next passes None: local Err BEFORE rejected write/deferred unlink; true=>existing HLC reject/audit/removal; false=>existing append. Don't swallow cache error in append.is_err or replace release by receive; no deferred membership re-admission. append/sign_commit unchanged; inspected production append paths guarded. Direct append only for labeled pre-fix fixtures, not main02 tests.

author_commit retains lock/standing/rotation, reuses live, observes cache before tick/sign; seen stays ordinary vector/fresh authorization fold. Standalone authorized facts same. TeamSync authorized signing collects live/cache with StateDir held/envs released, briefly merges into env.hlc/ticks without lowering. No I/O/StateDir acquisition under envs. Startup/refold/vault reads don't consult cache.

Clock-reset tests may add cfg(test) thread-local optional authored wall time in compaction_heads::testing at ONLY these three tick sites. Production None/system time; no environment/global clock switch. Test author wall only, not compact age/receipt time; reset hook. Exercise actual author_commit/fact paths.

Fixed Error::state/empty detail: team_compaction_layout_unsupported (preflight type/containment); team_compaction_head_unavailable (missing originals/records/exact predecessor/head); team_compaction_head_invalid (corrupt/unreadable/nonregular/unsupported/bad binding/conflict/coverage); team_compaction_head_limit_exceeded (caps); team_compaction_head_persist_failed (publication/readback/fsync); team_compaction_lock_required (helper misuse). True time failure remains team_hlc_not_monotone via reject_commit. Unrelated parse/format/append/audit errors unchanged. Cache failures expose no path/record/ciphertext/create no rejected candidate/team_commit_rejected. Existing TeamSync local error propagation stays; no new quarantine/disconnect policy or arbitrary-callback guarantee.

## Independent regressions

Synthetic only. PRIMARY: literal slots/HLC/deletion sets/document/version/order plus original signed/hashed canonical bytes/hash/signature saved BEFORE operation. No expected result from new selector/registry. verify_commit/fold parity secondary. Preserve original tests/evidence; map cases to original IDs.

1. **01 actual receive/compact:** A:init1 at1000000; A:add B(user)2 at+1; B:add Y1 at+2 (receive accepts, fold not_admin); Y:data1 at+3 received; A:valid data3 at+4; A:remove B4 at+5. Only A active/no fabricated ACK. Compact removed=2(Y1,A3), C={A:4,B:1,Y:1}; skipped B add identical live, Y1 exact cached original/record; Y absent members/derived vault, A literal data/order retained. Reopen/recompact removed0/same heads; legitimate A advance preserves idle Y. Add demotion-before-add race/first-record conflicting agreement keys/op order/raw-extra/coerced-base64/earlier conflicting record=>invalid/no overwrite. Prove no Y member/fact authority.
2. **02 actual receipt:** A:init1=1000000-0000,data2=1000001-0007; compact removed1/live2 absent/C,V=2. Separate receive_commit/live cases:3 equal1000001-0007 or lower1000000-0009=>rejected/team_hlc_not_monotone, one-call audit, no live3/defer/metadata/vector/data change. Quarantine preserves original plus reason.3=1000001-0008=>accepted; real next compact removed1/cache exact3/reopen. Exercise submit_commit AND actual handle_commit; removed-author variants retain status/data/existing fold authority.
3. **Deferred:** actual receive at early now defers future/gapped3 BEFORE2; receive2 normally, real compact2, release3 due. Equal/lower=>reject/audit/deferred removal; newer=>accept once. Corrupt cache=>local Err/exact deferred retained/no rejection/prune. Synthetic restore of exact saved bytes (not recovery feature), reopen/repeat. Still-gap no-lock, already-live duplicate/conflict, pruned deferred drop.
4. **Sequence/status:** live gap early/no writes, requested repeat existing gap quarantine, unknown admission early, waits_on_deferred suppresses quarantine, future gap deferred not admitted by cache. Matching live duplicate/live conflict/pruned receipt equivocation/pruned deferred drop. Literal audit/rejected/deferred inventories/V unchanged; no ACK/receipt invented. Preserve issue28/52 tests.
5. **Pre-fix stored:** real compact then labeled previously accepted regressed3 inserted by trusted test append/disk. Real compact repeatedly/reopen refuses invalid,3+cache preserved. New4>3 but<=cache2 rejects; >both may accept/ordinary aged compact advances. Idle/removed has no retroactive rewrite/quarantine/repair. Genuine legacy snapshot/prune/no-cache SEPARATE from real compact/cache loss: reads/legacy receipt preserved, missing idle head=>unavailable/no images. No-cache/all heads live may initialize.
6. **Evidence failures:** corrupt JSON/unreadable/nonfile/oversize/full-record mismatch/live-cache conflict/missing S coverage/ahead-of-S,V=>fixed local error/no valid-peer quarantine; preserve originals/cache/snapshot/deferred. Older valid cache+live predecessor succeeds; missing exact predecessor unavailable. Include signing/reopen/reads. No vector advancement/cache lowering/deletion remedy.
7. **Local clocks/locks:** reopen real compact, author wall below deleted head; actual author_commit with/without TeamSync yields literal HLC above cache/exact next seq/role+DEK constraints. Later remote cached head also observed. Both authorized fact paths/non-admin+removed denial. Missing/corrupt evidence=>error before candidate sign/store, vault reads usable. Deterministic channels/barriers: compact vs direct receive/release/local signing/two StateDir holders; post-lock evidence, envs available during I/O/no send under lock. Join own threads; no sleep-only oracle.
8. **Compatibility/cost:** unchanged counts/six exclusions/mixed authority bytes/M1 deletion/version revocation/backup exclusion/canonical wire/goldens. Literal registry first-record tests plus finite-history secondary parity. Sparse huge PyInt only new walker, not huge legacy range loop. Keep caps/negative vector/same-slot/strict HLC/raw opaque tests. Faults preserve originals/metadata/no pre-barrier unlink; no hardware claim.

## Later verification and STOP

**NOT RUN here.** Root assigns fresh isolated Linux/macOS identities/source/dependencies/budgets/ownership/cancellation; absence=>NOTRUN/no reuse. Locked/offline approved dependencies/job-owned targets. Each OS: features before/after; focused debug+release `--lib compaction_heads` and `--test team_compaction_heads`, nonzero counts (name new unit tests accordingly); unchanged full **bash rust/verify.sh** (fmt/strict Clippy/libs/binaries/all integrations/signer probes/docs). No subset/CI change replaces full. Capture exact source/all commands/status/counts/failures/timeouts/NOTRUN; prior counts aren't fix evidence.

Seven unchanged --exact selectors in BOTH debug/release, exactly one executed per command,14/OS:

| Target | Selector |
| --- | --- |
| team_checkpoint_payload | full_verifier_total_depth_64_65_and_post_parse_helpers_on_256_kib_stack |
| team_checkpoint_admission | semantic_depth_64_success_error_drop_on_256_kib_stack_and_65_refusal |
| team_checkpoint_semantic_cut | complete_candidate_depth64_success_late_error_repeat_drop_and_65_refusal_on_256_kib |
| team_checkpoint_semantic_cut | complete_fold_depth64_on_actual_256_kib_stack |
| team_checkpoint_required_generations | required_generation_depth64_success_late_error_repeat_drop_on_actual_256_kib |
| team_checkpoint_required_generations | required_generation_depth65_refuses_before_crypto_on_actual_256_kib |
| team_checkpoint_required_generations | required_wrap_depth64_success_error_repeat_drop_on_actual_256_kib |

STOP: base/manifest drift, extra hunk, legacy/golden regression, unproved record order, missing original, canonical incompatibility, lock inversion/new network wait, unclear error classification, dependency drift, wrong/zero selector, resource/budget/secret failure. Preserve evidence; no relaxed rules/changed oracle/deleted or re-signed originals/scope expansion/replacement campaign. Expected unavailable-history tests aren't permission to call unexpected defects solved.

Return files/hunks/diff/head/tree, original-ID evidence/open limitations, oracle map, OS commands/results/counts/failures/NOTRUN, protected/dependency checks, Root03 preservation/assigned resource receipts. No push/merge/deploy/trusted-checkout edit, invented Opus result or acceptance. All product boundaries and OPEN holds in decision.md remain unchanged.
