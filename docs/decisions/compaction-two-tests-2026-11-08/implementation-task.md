# Root-only implementation task

Static design,2026-11-08: actual gpt-6-astra / ultra; requested default tier, effective tier unexposed. Read decision.md. Root personally implements; no delegate/agents/workflow/other-model/review. SOURCE ONLY: no host product/helper/compiler/formatter/build/test/dependency execution or runtime/resource grant.

## Base and closed additions

HEAD5f4d045f289c53c41178f3f062f6c6f74fb561e2; Rust915528f2f83a8ce863cb2543cd22858569adea20; Desktop2413844c89265a3e239be2372d34b1e6e1b2d4bb. Verify prepared1,464-file manifest and ten bindings pinned in decision.md. No moving base/rebase/adaptation.

| File / base anchor | Only addition |
| --- | --- |
| rust/src/team/commit.rs:2226–2227 | cfg(test) gate after initial gap continue, before per-item state.lock. |
| rust/src/team/compaction_heads.rs:233–234 | cfg(test) gate after open/descriptor type check, before Vec/read_to_end. |
| Same, testing module:683–846 | Two Boundary variants, optional exact scope in Trace, two small wrappers below; reuse pause/hit/reset/events. |
| rust/src/team/sync.rs, compaction_heads_tests, before final brace:10400 | Exactly two new #[test] functions below and private helpers/guards only they use. |

No imports outside cfg(test) needed. Preserve existing Fixture/ClockSession/clock_candidate and every old test/helper body. No membership/integration changes, production signing edit or broad formatting. Outside two inserted statements all old non-test code stays byte-exact. Extra file/non-hook production hunk => STOP with concrete dependency.

## Gates and bounded lifetime

Add Boundary::DeferredPrefilterPassed and Boundary::CacheOpenedBeforeRead. Insert these calls, normal line wrapping only:

    #[cfg(test)]
    super::compaction_heads::testing::hit_scoped(
        super::compaction_heads::testing::Boundary::DeferredPrefilterPassed,
        self.state, &self.env_id,
    )?;

    #[cfg(test)]
    testing::hit_scoped(testing::Boundary::CacheOpenedBeforeRead, state, env_id)?;

First immediately BEFORE release_deferred's existing let _lock. Second immediately BEFORE load's existing let mut bytes. Never move fresh_last, open/type/cap checks, reads, branches or errors. A pause before the caller's observe_cached_hlcs is insufficient.

Inside existing cfg(test) testing module:

    pub(crate) fn scoped_pause(
        boundary: Boundary, root: PathBuf, env_id: String,
        entered: std::sync::mpsc::SyncSender<()>,
        resume: std::sync::mpsc::Receiver<()>,
    );
    pub(crate) fn hit_scoped(
        boundary: Boundary, state: &StateDir, env_id: &str,
    ) -> Result<()>;

Add Trace.scoped: Option<(PathBuf,String)>; default/reset clears it. scoped_pause accepts ONLY the two new boundaries, requires no pending scope/pause, stores exact owned absolute root without ParentDir plus env, and installs existing pause. No canonicalization, file mutation, callback, record payload or public capability.

hit_scoped returns Ok without events/lock inspection unless pending pause boundary AND state.path AND env match. Consume scope once, release RefCell borrow, assert actual StateDir ownership on THIS thread: false for DeferredPrefilterPassed, true for CacheOpenedBeforeRead. Then existing hit records event, consumes pause, sends (), waits its existing <=5 seconds and retains existing test-only error. Old hit/pause/actions/SnapshotMutation/author-wall bodies unchanged. Unarmed loads must not perturb old event expectations.

Both gate channels use sync_channel(1), one signal each, avoiding blocking notification send. Controller receives <=5-second timeout; no sleeps/polling/signals/processes. Scoped threads, every own thread joined. New local sync-test RAII guard: create/reset in worker; Drop resets trace and author_wall(None) even on Err/panic; never move across threads. Controller resume guard releases once and try_send/drop on early failure. Record observations, resume/drop and join before asserting where possible. Propagate panic/timeout; no detached worker/leaked hook. External isolated phase timeout is only backstop, not oracle. Non-test release contains neither hook nor switch; optimized unit tests intentionally retain cfg(test).

## Test 1: forward receipt makes prefilter stale

Exact name:
compaction_heads_deferred_prefilter_stale_forward_receipt_uses_locked_sequence

One table-driven test in sync compaction_heads_tests. Fresh existing Fixture each row. A narrow new helper may sign chosen sequence/settings; no changes to existing helpers.

Common literal setup:
1. Fixture A:init1=1000000-0000, put2=1000001-0007, settings3=1000002-0007/settings19. Save original canonical signed/hashed bytes/hash/signature and physical bytes BEFORE operations. Real compact removes2 (2,3), retains1; C=S=V={A:3}, cache exact3.
2. Sign D at A:5/settings37 with row HLC. Real receive_commit(D, now=0) => deferred at V3, both future and gapped. No append/defer/disk admission bypass for D.
3. Except still-gap control: real receive A:4/HLC1000003-0007/settings31 at now1_000_010 => accepted. Real compact removes1 (4); only live1; C=S=V4, cache exact4. Equal/lower5 thus was deferred legitimately BEFORE4 existed.
4. Baseline deferred is precisely A-0000000005.json with D bytes; rejected/rejection-audit suffix empty. No fabricated ACK/receipt/peer-vector.
5. Worker arms exact-root/env DeferredPrefilterPassed, calls real release_deferred(1_000_010, Some(audit)). Controller MUST receive entered before advancing. Unlocked last4 is already read, D passed filter, worker owns no StateDir lock, D intact. A “thread started” flag is insufficient.

D newer=1000003-0008; equal=1000003-0007; lower=1000002-0009. A denotes fixture.fp. Use newer D for matching/conflicting/pruned/next-good/next-local-error/still-gap; equal/lower only for their named rows.

| Row | Controller while paused | Exact release outcome |
| --- | --- | --- |
| matching | Real receive SAME newer D => accepted/live5/V5; corrupt only owned cache to fixed malformed regular bytes under controller StateDir lock. | Ok empty; D removed from deferred; live5 exact D; no rejected/audit; V5. |
| conflicting | Real receive competing A:5, SAME newer HLC/settings41 => accepted; same corruption. | Ok empty; D removed; competing live5 exact; one D quarantine and one team_author_equivocation audit; V5. |
| pruned | Real receive SAME newer D => accepted; real compact removes1/live5 absent/C=S=V5/cache exact D; then same corruption. | Ok empty; D removed; only live1; no rejected/audit; V5 from snapshot. |
| next-good | No advance; valid C4. | Ok [D] exactly once; live1,5/V5; deferred/rejected empty, no audit. |
| next-equal | No advance; valid C4. | Ok empty; no5/V4; D quarantine/team_hlc_not_monotone and one audit; deferred empty. |
| next-lower | Same, lower D. | Same rejection inventories; original lower signature preserved. |
| next-local-error | No advance; corrupt owned cache while paused. | Err State/team_compaction_head_invalid/empty detail; only live1/V4; exact deferred D retained; no quarantine/audit/candidate mutation. |

Corruption is labeled synthetic local-evidence error, never rollback/recovery. It follows legitimate concurrent receipt/compact. Controller drops its lock BEFORE resume. Preserve bad bytes in assertions, no repair/deletion workaround.

Baseline AFTER controller actions, BEFORE resume. Assert exact live/deferred/rejected path sets and bytes/modes; all unrelated originals/snapshot/record/cache inventories equal across release. Rejected filename A-0000000005-<saved D hash first12>.json. Strip ONLY rejected_reason and compare full original dictionary/canonical signed/hashed bytes/hash/signature. Audit: exact baseline prefix and suffix count; single rejection fields env_id/A/author_seq5/result denied/literal reason; no other event. Do not guess timestamps. Signature verification secondary; expected statuses/slots/HLC never come from new cache helpers.

After join, ordinary load_environment retains gone/VERSION staged; settings31 for reject/error,37 for good/matching/pruned,41 for conflict. Compare preserved copies to originals, never re-sign expectations. Re-release completed rows => empty/no new audit; local-error retains original without recovery retry. Bad cache must not affect ordinary loading.

Still-gap control INSIDE same test: fresh common setup through deferred5 at V3/C3. Main holds StateDir; child arms same gate and invokes due release. Require positive completion Ok empty within timeout WHILE main retains lock, zero new gate events, identical deferred/snapshot/cache/live/rejected/audit inventories. Drop main lock/resume guard before join even on failure. This proves initial-gap lock bypass without sleep-only inference. Preserve issue52 tests; do not fabricate or claim coverage of a backward-history fresh locked-gap case.

Regression sensitivity: substituting stale last4 for fresh_last makes duplicate rows reach helper's non-next fast path then append duplicate error, leaving D deferred; conflict also loses quarantine/audit. Required inventories must fail. This reasoning is not permission to mutate production or execute mutation tests here.

## Test 2: authorized fact paused within cache load

Exact name:
compaction_heads_authorized_fact_cache_read_pause_keeps_envs_available

One table-driven test: cache-wins / remembered-advances / corrupt, fresh Fixture each. Real compact removes2; only live1; C/S/V3, cache original3/HLC1000002-0007. Owner active/admin; gone present. Exercise actual team.sign_authorized_fact(env, "secret_deleted", {"secret_id":"gone"}), never substitute raw sign_fact.

After registration/refold/compact, initialize env.hlc=Hlc::new(1,0) solely as owned clock-reset fixture. Attach existing ClockSession recorder for observation, without invented ACK/receipt/vector/authority or transport changes. Capture document, relevant Facts sets/maps, fact_hashes, known_fact_lines, clock, empty deferred_sends and recorder.sent. Capture exact team/<env> regular-file inventory (commits/cache/snapshots/records/facts/admissions/rejected/deferred), audit baseline and vault/tombstones.json presence/bytes; no KMS/key inventory. For corrupt row replace ONLY owned cache with fixed malformed regular bytes BEFORE baseline.

Worker guard sets existing authored wall Some(1), arms exact CacheOpenedBeforeRead, calls signer. Gate is after authorization/actual cache open/type check. Ownership assertion before entered proves worker StateDir ownership; no controller outer lock manufactures it.

At entered controller uses envs.try_lock, NEVER blocking lock. Record positive acquisition, clock STILL1-0000, identical document/facts/hashes/known lines/raw disk inventory; no candidate fact/admission/tombstone/quarantine/audit/send/queued send and no completed result. Do not call state-locking loaders during pause; only raw owned fixture DATA and envs guard. Release envs promptly. Failed try_lock is failure, but resume/join before asserting.

| Row | During pause | Literal resumed oracle |
| --- | --- | --- |
| cache-wins | Leave remembered1-0000. | First fact1000002-0008; second call SAME worker/authored wall1 =>1000002-0009. |
| remembered-advances | After unchanged baseline, under acquired envs guard observe literal1000003-0041; drop envs BEFORE resume. | First1000003-0042; second1000003-0043. |
| corrupt | Leave remembered1-0000. | Strict decode Err State/team_compaction_head_invalid/empty detail; no Fact/second call; clock1-0000 unchanged. |

Remembered advance is forward in-memory fixture activity, not disk rollback; it detects replacing fresh remembered HLC with stale disk observation. One-shot gate is consumed; second call runs normally. Capture results/events and join; assert one hit, cleared hook, no worker StateDir ownership after each call, envs available after completion. Successful Facts: exact existing FACT_FORMAT/env/kind/target/author, literal HLCs, valid signatures against fixture public record. Canonical roundtrip/signature verification are secondary, not derived clock oracles.

Sign ONLY, do not publish/store. Candidate disk/fact state and sent/queued sends unchanged after calls; corrupt row cannot tick clock. Preserve standalone/non-admin/removed/generation tests byte-exact. Empty-fact fixture avoids prior admission maintenance; no general rollback promise for load_facts.

Proves envs availability while StateDir held INSIDE opened-cache/pre-read interval. Not every syscall, blocked kernel read, all fact kinds or whole-program deadlock freedom. Recorder proves no observed send/queued send in signing-only path before/after resume; NOT publication/broadcast/FACT delivery or universal no-send-under-lock. Existing positive COMMIT-send observer tests and publication lock-drop logic protected.

Regression sensitivity: envs held across cache I/O => try_lock failure; StateDir dropped before I/O => ownership assertion failure; cached observation omitted => missed gate/wrong cache-wins HLC; remembered clock lowered/replaced => wrong remembered-advances literals. No source-spelling oracle.

## Preservation and later gates

Root before/after: independently verify protected paths/bytes/blobs/modes/index/ref; exactly three changed paths, two cfg(test) production-body insertions, private support, two new tests. Compare old test/helper bodies including Root03 nine, Sol01/02 twenty-three and valid-wrap correction. Preserve genuine failures. No host formatter; separately isolated later formatting must be constrained and diff-checked.

Return actual model/settings, changed hunks/source binding, literal oracle map, bounded cleanup/errors, limitations and original IDs OPEN. STOP for baseline drift, extra file/hook/non-test hunk, changed old tests/goldens, unclear error/order, unbounded cleanup, parser/cap/schema/role/dependency deviation. Identify concrete dependency, no architecture delegate or evidence/severity rewrite.

Separate future grants must bind changed source/resources/identity/public dependencies/ownership/budget/cancellation. Each fresh isolated Linux AND macOS:
- Full unchanged bash rust/verify.sh (no subset): fmt/strict Clippy/library/binaries/all integrations/signer probes/docs.
- Focused debug AND release --lib compaction_heads and --test team_compaction_heads; nonzero counts, both new names observed (additional2 library tests, none removed). Check non-test release omits gates/switch; release-profile unit hooks intentional.
- Same-source features before/after, unchanged Cargo/features/pins/protected-source inventory.
- Seven --exact selectors below, one test per command in BOTH profiles14/OS.

| Target | Exact selector |
| --- | --- |
| team_checkpoint_payload | full_verifier_total_depth_64_65_and_post_parse_helpers_on_256_kib_stack |
| team_checkpoint_admission | semantic_depth_64_success_error_drop_on_256_kib_stack_and_65_refusal |
| team_checkpoint_semantic_cut | complete_candidate_depth64_success_late_error_repeat_drop_and_65_refusal_on_256_kib |
| team_checkpoint_semantic_cut | complete_fold_depth64_on_actual_256_kib_stack |
| team_checkpoint_required_generations | required_generation_depth64_success_late_error_repeat_drop_on_actual_256_kib |
| team_checkpoint_required_generations | required_generation_depth65_refuses_before_crypto_on_actual_256_kib |
| team_checkpoint_required_generations | required_wrap_depth64_success_error_repeat_drop_on_actual_256_kib |

All NOTRUN here. Preserve zero counts/failures/timeouts. Prior56 focused passes do not cover future hooks. Actual Opus re-review/acceptance remain missing, not authorized now. All decision.md findings/Go/native/M2/onboarding/physical/Oracle/release holds OPEN. No resource query/reuse/clear/runtime grant/merge/deploy/installer/provider readiness.
