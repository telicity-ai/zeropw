# Root-personal implementation task

Static plan, 2026-11-08, actual gpt-6-astra/ultra, requested default tier (effective tier unexposed). decision.md binds all inputs, policy, supersessions, coverage and OPEN gates. **Root actual gpt-6.1-sol/ultra implements personally; no delegate.** Source scope only, no runtime/review/acceptance grant. R1-01 HIGH OPEN/UNFIXED; original01/02 MEDIUM,03 LOW OPEN.

Base HEAD a1e3bf8f2ddf10c7a2614fd4dfc89e9ec633475f; Rust7cfa2b85d103b50bc5d941f3b6165fe38b51cbd5. Reverify pins/all1,503 files/22 docs-only paths. No moving base/coordinator-checkout edit.

## Exact four-path scope

| Path | Allowed hunks |
| --- | --- |
| rust/src/team/compaction_heads.rs | checked_cache (370–418): retained full-record equality on first-record mismatch; live head checked with cached device; comment only otherwise |
| rust/src/team/commit.rs | New internal matcher beside device_registry (2304–2335), new actual-file method beside retained_device_registry (2094–2127); append two tests |
| rust/src/team/sync.rs | Append four tests/new private test-local fixtures in compaction_heads_tests only; NO production edits |
| rust/tests/team_compaction_heads.rs | Append one control/restart test; revise ONLY specified old earlier-conflict assertion block |

Necessary imports allowed. No membership.rs edit: public author_fact exercises standalone path from sync tests. No other path, old helper/fixture/test body (except named block), exported API, new hook/callback/env switch/global state, unsafe, dependency or suppression. Freeze mod/fold/checkpoint/identity/crypto/scalar/canonical/StateDir/Context/audit/vault/KMS/gateway/signer/CLI/Desktop; Cargo/features, CI/harness/schema/verify.sh/AGENTS/docs/evidence/goldens. Freeze Root03 layout/readback/durability, both scoped gates/tests/helpers, three authored-wall sites, corrected owner wrap and from_mode(0o0). No broad formatting/refactor.

## Production changes

Keep prepare, device_registry and retained_device_registry bodies and callsites unchanged: candidate authentication/current-first compaction retain their existing semantics. Add only these internal roles (ordinary type spelling permitted):

    pub(super) fn matching_device_records(
        commits: &[Commit], expected: &HashMap<String, DeviceRecord>
    ) -> HashSet<String>;

    // CommitStore method
    pub(super) fn retained_matching_device_records(
        &self, expected: &HashMap<String, DeviceRecord>
    ) -> Result<HashSet<String>>;

Matcher scans EVERY op, including nonfirst: exactly env.init.owner_device/member.add.device with unchanged object/from_dict/verify semantics. Match complete normalized expected[key]; ignore malformed/nonverifying as before. No role filter, enclosing-commit reinterpretation or original-byte change.

File method requires StateDir lock; mirror retained_device_registry's sorted directories/digit_stems/deduplicated positive PyInt/canonical get. Preserve alternate spellings and order_key/HLC validation. Finish scan, including later errors. No all_commits/1..vector/per-head scan; only retained commits, not deferred/rejected/cache/snapshot members. Small parallel walker preserves old helpers.

checked_cache sequence:

1. Keep lock/load/binding/current-first registry/floor/vector logic; absent cache returns None unchanged.
2. Build <=256-entry expected map only for available first records differing from cached devices. Missing records are NOT replaced by candidate/bootstrap data.
3. Empty map: no extra scan. Otherwise scan supplied fresh locked live, or ONE retained-file walk for None/deferred. Read/parse failures => fixed invalid/empty detail.
4. Preserve per-head floor/vector checks and missing-first unavailable. Equal first passes source equality; different first requires matching retained fingerprint, else invalid. Preserve HLC/canonical/signature/live-copy checks.
5. Exact store.get live original must use Head::checked(original, head.device.clone(), env), not the differing first device. Preserve same_original and supplied-live duplicate comparisons.
6. No writes/cache replacement. cached_hlc_not_above_previous and observe_cached_hlcs stay exact; all cached clocks and locked predecessor checks remain.

One extra actual-file scan, <=256 names; not a global cost bound. Existing range scans/folds/DOS-1 remain; no schema change.

Sole old test change: compaction_heads_01_later_conflicting_record_cannot_override_and_earlier_arrival_refuses, earlier=true Y:2/HLC1000007-0000 receipt. Replace unwrap_err/invalid/empty-detail/no-Y2 assertions with literal accepted, exact saved signed+hashed original at Y/2.json, no rejected/deferred candidate or rejection audit. Cache first_cache unchanged; Y absent from members; settings101 has no authority. Preserve earlier X acceptance, compaction invalid/no images, later=false and original-byte assertions/name. Clarify only obsolete comment. This deliberately supersedes the dangerous old expectation.

## Real fixture and literal history

Seven new #[test] functions, TO IMPLEMENT/NOTRUN. New private r1_ helpers; old utilities unchanged. Existing wall RAII/real methods/private handle_vector/handle_commit/advance_env suffice; no hooks.

A=synthetic owner Context; Y=second Context's actual device/user/sole insider. Y'=same sign_seed/different agree_private: assert same fingerprint, unequal full records, both self-signatures valid. X also Y-controlled. No secret logs.

Use existing valid IDs/encryption. A:1 has genuine owner DEK wrap G; Y gets permitted wraps:{} (public ops/no DEK entitlement). Removed-Y data under G bypasses no rotation. Old wrap/rekey tests frozen.

All initial commits enter through real receive_commit, accepted in this order:

| Original | HLC | Ops |
| --- | --- | --- |
| A:1 | 1000000-0000 | env.init, valid owner wrap G |
| A:2 | 1000010-0000 | member.add Y/user/wraps:{} |
| Y:1 | 1000001-0007 | settings.update interval17; sorts before admission, fold-skipped |
| A:3 | 1000020-0007 | encrypted secret.put_version s/V1, G |
| A:4, removed rows only | 1000021-0000 | member.remove Y; no baseline removal fact |

Register owner TeamSync normally. Current-Y rows: real-receive originals into Y's second store; handle_vector from Y's actual public Session fixture with its literal vector {A:3,Y:1}. No direct peer_vectors injection or fake ACK/READY; this tests vector processing, not handshake. Removed rows have no active blocker.

Initial real compact removes exactly A:3 and Y:1 (count2). Live={A:1,A:2}[+A:4]; C=S=V={A:3,Y:1} or {A:4,Y:1}. Cache Y=original Y:1/fullY, A=3 or4. Save original signed/hashed canonical bytes/hash/sig and complete cache/inventory/audit baseline.

Four attack rows, fresh fixture per independent action:

| Row | Real accepted attack |
| --- | --- |
| Y-alone/current or removed | Y:2 @1000002-0000 member.add Y'/user/wraps:{} |
| Y-adds-X/current or removed | Y:2 @1000030-0000 member.add X/user/wraps:{}; then X:1 @1-0000 member.add Y'/user/wraps:{} |

Y-alone exceeds cached Y:1 but precedes A:2; no collaborator needed. Y-adds-X's operations are fold-skipped; X supplies receipt signatures, never membership. Current-first Y becomes Y', original equal A:2/Y remains retained. Preserve accepted attack originals, no conflict quarantine. Fold: owner A unchanged, Y user/removed, X absent, s/V1 intact.

N=3 current,4 removed. With authored wall1, owner operation's exact H:
- Y-alone/current:1000020-0008;
- Y-alone/removed:1000021-0001;
- Y-adds-X either:1000030-0001.

For TeamSync fact clocks set remembered HLC1-0000 using existing owned test fixture convention before each fresh action; RAII restores wall. Never derive expected results from new matcher.

## Seven finite regression tests

All new names have compaction_heads prefix for focused selection.

**1. commit::compaction_heads_r1_exact_announcements_include_nonfirst_ops**

Literal expected match sets: earlier different/later equal => Y; same-commit [different,equal] and [equal,different] => Y; only different, bad self-signature or unrelated key => empty. Same sign_pub/different agree_pub/sig is not equal. Test env.init and member.add; raw legacy array/base64 coercions/extra keys normalize to equal without changing signed op bytes. Independently assert first-record registry's old literal choices. No deferred/candidate records supplied as retained evidence.

**2. commit::compaction_heads_r1_retained_matches_use_canonical_sparse_files**

Owned actual-file storage-boundary fixture under real lock: exact/nonexact across files and later ops; huge sparse positive PyInt stem; zero/negative exclusion; zero-padded/Unicode alternatives cannot override canonical get. Literal sets, absent directory empty, malformed canonical commit/HLC error, unlocked call team_compaction_lock_required. Compare supplied-live parity only after independent literal oracle. No max-seq traversal. Existing sparse/registry tests unchanged.

**3. sync::compaction_heads_r1_other_author_receipt_handle_and_compaction**

Four attacks x receive_commit/actual handle_commit on fresh state: A:N+1 settings37 @1000040-0007, valid signature/seen, different author from Y. Direct accepted; handle Ok(()); exact original persisted, V[A]=N+1, settings37 after normal load/refold; no candidate rejection/defer/rejection audit. Repeat direct duplicate, repeat handle Ok, no new file/broadcast. Recording observer Session distinct from sender: first handle exactly one matching COMMIT after lock release, no candidate FACT. Preserve send-under-lock checks.

Compaction: current Y intentionally behind first yields blocked_by=[Y]. Real-receive exact originals into Y's store and handle its updated actual vector; do not let lag mask mismatch. Removed Y needs no peer update. Then compact => StateError/team_compaction_head_invalid/empty detail; unchanged cache/snapshot/record/live files, no unlink/team_compact. Reopen Context/TeamSync, retain legitimate vectors, repeat identical refusal. No claim restart repairs it.

**4. sync::compaction_heads_r1_deferred_release_preserves_clock_and_evidence**

Four attacks x good/equal/lower/corrupt-cache. Submit D=A:N+1 with receive(now=0) while A:N missing (before A:3 current, A:4 removed): deferred, no rejection. Then receive predecessor, genuinely compact and introduce attack. No direct deferred-file fabrication.

| D HLC / condition | release_deferred(1000100) |
| --- | --- |
| good1000040-0007 | exactly[D], live original once, V[A]=N+1, deferred removed, no rejection/audit |
| equal current1000020-0007 / removed1000021-0000 | [], V[A]=N, original quarantine/team_hlc_not_monotone, exactly1 rejection event, deferred removed |
| lower current1000020-0006 / removed1000020-0009 | same exact rejection outcome |
| malformed owned cache after valid setup/attack | local invalid/empty detail; exact D remains deferred, no live/rejected D or rejection audit |

Repeat release => []/no new effects, except corrupt repeats same error. For good current-Y rows of both attack forms also use actual advance_env: Ok(None), D stored/cleared; repeat tick no duplicate D broadcast. Empty fact/incident baseline avoids unrelated repairs. This is not whole-loop/network liveness coverage. Both old deterministic gate tests remain unchanged.

**5. sync::compaction_heads_r1_owner_data_removal_and_both_fact_paths**

Four attacks, fresh state per operation; attached=false/true for author_commit, wall1:

- Owner membership::author_commit encrypted s/V2/G => A:N+1/H accepted, exact original stored, version_order [V1,V2], both staged. G is safe because only A has its wrap.
- Owner member.remove Y => current rows A:4/H succeeds/Y removed/exact removal retained; already removed rows NotFound/member_not_found, no new commit. Do not turn ordinary permission failures into success/cache errors.
- Standalone PUBLIC membership::author_fact(ctx,None,...) independently for member_removed(Y) and secret_deleted(s). Decode returned dictionary as Fact: exact kind/target/env/A/H, valid signature; exactly1 new admitted fact hash, signed admission line and facts line; member_removed denies Y, secret_deleted tombstones s/makes unusable. No rejected_facts; original cache/commits preserved. This exercises standalone signer+publication.
- TeamSync sign_authorized_fact for both kinds on separate rows: exact H/signature; no fact/admission/tombstone/live/deferred/rejected/send changes. Second sign increments counter1, never lowers remembered clock. Account for ordinary pre-sign load audit separately.
- TeamSync publish_fact for both kinds on fresh rows: same literal stored fact/deny effects; exercise receipt_fact/fact_role_ok, not raw sign_fact. VECTOR is not tombstone ACK/readiness.
- After successful current-Y removal, an owner settings commit still succeeds; compact still invalid once reached. Removal does not repair compaction.

**6. sync::compaction_heads_r1_local_failures_and_authority_remain_closed**

Four attacks x malformed-cache/no-equal-retained. Add one representative row each unreadable/nonregular/oversize cache. No-equal is explicitly LOCAL corruption: remove equal announcement op from retained stored dictionary, leave verified different Y' and cache unchanged; not peer admission or recovery. Deferred candidates were admitted before failure.

Separate fresh state per direct receive, handle, due release, owner author_commit, standalone author_fact, TeamSync sign and publish (both fact kinds). Literal local invalid, or limit_exceeded for oversize, empty detail; no candidate quarantine/team_commit_rejected; D unchanged; TeamSync failed sign does not tick remembered clock. Unreadable uses existing owned0o0/RAII in unprivileged runner; fail fixture if readable. Ordinary reads remain usable where authority history is intact, no promise for deliberately corrupted authority history.

Absent-source subcase: all retained Y announcements absent, cached idle Y remains, independently valid owner A source => unavailable. An incoming equal-Y announcement cannot cure that call; if different prior Y' exists, result invalid. Deferred-only equal evidence cannot count.

Actual user/removed-Y Contexts must fail owner data/settings and deletion under normal authority: not_admin without removal fact; member_removed when admitted removal fact removes author; team_fact_not_authorized for secret_deleted. Assert one literal class/reason per fixture. Preserve legitimate self-removal fact exception; owner A cannot be removed. X gains no membership/wrap/use or raw unreceipted fact authority. Include wrong-G owner put => team_rekey_pending, not a cache bypass. Old authority tests stay exact.

**7. integration::compaction_heads_r1_prior_conflicts_identical_and_absence_controls**

Use old received_fixture/candidate/received/member_op/team helpers unchanged; no active peer blocker (removed/fold-skipped pattern). Each row has literal original sets/counts before action:

- Earlier identical Y: eligible next receive accepted; compact succeeds; full cache device unchanged.
- Later differing Y': first remains Y; next receive accepted, compact succeeds; original announcement bytes retained.
- Earlier differing Y': other-author receipt accepted, compact invalid, repeated after reopen. Create stored conflict by real receipt before reopening, no fabricated cache/migration write.
- Cache genuinely initialized when first was Y': receipt/compact normal while equal Y' remains first. “Original” is not arrival-first.
- Genuine no-cache/live history initializes exact heads. Genuine prior prune/no-cache with required idle missing original => unavailable before new images/unlinks. Separate cache-loss control records legacy receipt/no anti-rollback; never delete cache to rescue conflict.
- Keep old stored-HLC regression/same-slot mismatch/ahead-of-S,V/missing predecessor/caps/removed-idle tests as independent guards. Pruned receipt equivocation and deferred pruned-drop unchanged.

## Exact inventory oracles

Inventory exact team-relative paths/bytes/modes: commits/cache/snapshots/records/deferred/rejected/facts/admissions/rejected_facts, owned tombstone file/audit prefix. Save canonical(false/true)/hash/sig BEFORE action; no re-signing/logging originals. Literal statuses/slots/HLCs/sets/version order primary; helper parity secondary.

Direct receipt/release success: empty audit suffix. Regression: exactly1 team_commit_rejected, denied/team_hlc_not_monotone with env/fingerprint/author_seq; quarantine <fp>-<seq padded10>-<saved hash first12>.json. Strip ONLY rejected_reason then compare whole original dictionary and canonical/signature bytes. Local evidence errors produce no rejection event or candidate file; prefix immutable.

Enumerate ordinary refold/publication/pre-sign audit events (team_op_skipped/derive/team_fact_apply) with literal reasons/targets/counts from unchanged paths. Settle baseline first; no broad catch/multiple outcomes/arbitrary filters/M1 suppression. Only timestamps vary; unexplained extras STOP. Compaction refusal preserves publication images, not load_facts rollback. Repeat/restart adds no candidate/fact/rejection; separate signs advance HLC.

## Later validation and completion

No execution here. Root binds diff/head/tree/manifest/model/settings and frozen-body preservation. No secret-host tests, runtime/resource/admin action or publication grant.

Later separately authorized, source-bound, secret-free isolated Linux AND macOS:

1. fmt check and strict Clippy early (--locked --manifest-path rust/Cargo.toml --all-targets -- -D warnings); retain corrected0o0.
2. Focused debug+release --lib compaction_heads and --test team_compaction_heads, nonzero counts, seven new names observed.
3. Separately execute exact existing compaction_heads_deferred_prefilter_stale_forward_receipt_uses_locked_sequence and compaction_heads_authorized_fact_cache_read_pause_keeps_envs_available, one each/profile; preserve both bodies/gates.
4. FULL unchanged bash rust/verify.sh, every target, signer probes/docs; no subsets or CI/schema/dependency/oracle weakening.
5. Same-source features before/after, non-test release gate absence and unchanged pins. All seven existing stack selectors in two-tests implementation-task.md table (team_checkpoint_payload, admission, semantic_cut x2, required_generations x3), debug+release, exactly1 each command/14 per OS.
6. Retain errors/timeouts/NOTRUN; test pass counts do not override overallFAIL. New independent actual Opus review and separate actual Astra acceptance remain future gates.

STOP on binding drift, additional path/old-body/hook/API/persistence/crypto/authority change, unexplained role/data loss, lock inversion, changed failure boundary, wrong/zero selector or absent runtime grant. Report exact dependency; no policy relaxation, evidence deletion, new delegate or workaround.

Return changed files/hunks, exact diff/head/tree, preservation checks, new test names and per-OS results/NOTRUN, each original finding's evidence/open status and residual compaction refusal. Implementation alone does not close R1. Preserve decision.md's frozen runtime DATA; DO NOT QUERY. No push/merge/deploy/review/acceptance follows this handoff.
