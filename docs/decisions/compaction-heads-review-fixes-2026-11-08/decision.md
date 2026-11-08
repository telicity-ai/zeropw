# Bounded compaction fix decision

2026-11-08. Actual **gpt-6-astra / ultra**, T3 Code through Codex. Requested tier **default**; effective provider tier not independently exposed. Personally performed STATIC product/compatibility planning only. No implementation, adversarial-review substitution, acceptance, subagents, workflow or alternate model. **ZPCHEAD-OPUS-01 medium, -02 medium, -03 low remain OPEN.**

## Input binding and coverage

First operation hashed the entire brief, matched the required digest, then read it fully. Checkout `/Users/ys/.t3/worktrees/zeropw/t3-ea56bc5c`: HEAD `e8fa90e74bab30088761d717f59fe8104ed3d670`, Rust `afc41fcb5d55aaec2bc2fead7c7d8a94f312cc9f`, Desktop `2413844c89265a3e239be2372d34b1e6e1b2d4bb`. The11 changed paths beyond reviewed `04c7d22ae3f4317e9f203e5d7ca703974f8f1f69` are review/evidence/docs only. No source fix exists.

SHA-256 bindings:

| Input | Digest |
| --- | --- |
| /tmp/zeropw-compaction-review-fix-scope-astra-20261108.md | 4da057a6f58118daba6a665dd629ef704c52969dd125d2efae1e1d6a218aa508 |
| /Users/ys/Code/zeropw-mlp-evidence/compaction-heads-fix-scope-preparation-20261108/source-manifest.json | 2860c7e81cf10827ae47202a3c985c7fbea3b43f7056957602b6e4f471b63672 |
| docs/reviews/2026-11-08-compaction-heads-opus-04c7d22/report.json | 4e7296a50f281a3e066eb91998a7c3e79f6767b8ee8d17fcd60d77219bcb8ec0 |
| same review directory / report.md | fd53253fe211a80c2debc87ac6893d617e638a85cd295cf3fb4529b97da419b1 |
| same review directory / COVERAGE.md | a55f63c7c8cb99e5c4b9209bf9c23ae362ec671be6dbdc1bdd3bd0e0ccd658fb |
| same review directory / input-verification.json | 41b914a68958d7a32f74486eafaa0d8315737d7ad2391d7ee43c06e18bbe939d |
| /Users/ys/Code/zeropw-mlp-evidence/compaction-heads-opus-collection-20261108/REPORT.md | 6e38bfd1359488862993edd0c6e1182e8d6fadfc3d1ba5a181cec06093ffd84b |
| docs/decisions/compaction-heads-2026-11-08/decision.md | f9c6c1d19d7cca852d58d79eee4bd2712b550d0944dc9bd3bb4d3c47b51f16d6 |
| same decision directory / implementation-task.md | 942a6a5cec0b28c2b186e7b33e496dd9203625c26d1eff1566061207a332bf1a |
| same decision directory / controller-binding.md | 66c8cac829faf257a6bb4f9b015e3a0b39b801d13521c3abcaf641d1ab0cb609 |

Before/after output, all **1,434** tracked paths match manifest lengths/SHA-256/independently computed Git blobs/filesystem modes/Git modes; index equals HEAD tree. Manifest405,644 bytes. Inventory hashing is not semantic review. Only own stdlib Python DATA/text/hash and read-only Git/text; no project imports/source/helper/compiler/test/build/generator/formatter execution, network/SSH/VM/process/key/environment/admin query. Exactly two external documents <=32,768 bytes combined. Oversized drafts failed a pre-write guard; no files were written by them.

Fully read brief, AGENTS, product-intent/security-design, docs/harness, harness/README, PORTING including §1, whole-secret-deletion, prior Astra decision/task/controller-binding, complete original report.json/report.md/COVERAGE/input-verification and independent REPORT. Recorded reviewer is actual Claude Opus `claude-opus-5-5`, static REVISE; effort/thinking/tier unexposed. Recommendations are data, not scope permission.

Bounded semantic reads (Rust paths, line anchors at e8fa):

| Source | Read coverage |
| --- | --- |
| src/team/compaction_heads.rs; tests/team_compaction_heads.rs | ALL881 and680 lines, production/helpers/all5+11 tests. |
| src/team/commit.rs | 245–457 Hlc/order/canonical;745–840 sign/verify;1939–2478 entire store/registry/receipt/deferred;2815–2865,3120–3430 tests. |
| src/team/sync.rs | 5140–5311 load_facts;6050–6170 refold;6385–6535 submit/sign/publish;7650–7787 handle/early;8250–8315 incident;8520–8600 poll/deferred;9170–9888 compact/all8 tests;2500–2765,2870–2942 early/clock tests. |
| src/team/membership.rs; identity.rs | membership180–235,305–455 author/fact paths; identity1–290 including actual record parse/verify/normalization. |
| src/team/fold.rs; src/store.rs | fold975–1045,1566–1640,2038–2106,2780–2835; store25–280,540–565,600–615. |
| Other | audit.rs350–446; clock.rs1–35; vault.rs1810–1920; admin_cli.rs3095–3115,3820–3860,3930–3955; team_membership_sync.rs500–630; astra_team_round3.rs440–565; verify.sh full. |

Read team-sync §§5.2–5.4,7.1–7.4; searched relevant headings/text and production sign/receive/live/deferred/append/author/tick/observe sites. Desktop Rust search found no commit receipt/signing calls. Searches are not full-body inspection. Unlisted ranges, most legacy tests/goldens, pyjson/PyInt/crypto/checkpoint internals, gateway/signer implementation, remaining Desktop/raw logs/VM history were not reviewed. Used truncated source/report bodies were reread; whole team-sync.md is not claimed read. Incorrect test-path discovery queries were corrected by search without inferring contents.

## Exact superseded clauses

Original protected-file STOP was correct; this user-requested decision supplies a new closed scope, not the review recommendations:

- Prior four-file/protected commit.rs/membership.rs clauses: permit ONLY implementation-task.md's listed hunks, including sync's authorized clock hunk. mod.rs unchanged; all remaining protections persist.
- Prior algorithm step4/fact-free member source: replace with receipt's retained public-record registry. load_facts' separate authority logic is unchanged.
- Prior task/decision/controller-binding “cache never affects admission”: permit a negative HLC check on signature-checked exactly-next commits and local clock observation. No cache-derived vector/lastseq, missing history, member/use authority, receipt/ACK or import capability.
- prepare's private identity_document becomes typed public records. “Ordinary behavior unchanged” now excludes the specified evidence errors/shared signing clock change; reads/derive/vault stay cache-independent.
- Publication adds03 layout preflight and regular snapshot readback; StateDir is unchanged.

Keep strict cache HLC/sequence monotonicity, same-slot full equality, complete cut vector, original signed bytes, six authority exclusions, deletion counts and snapshot semantics. No dropped evidence, relaxed permission or raised floor to hide02.

## Chosen contracts

**01 — shared first-record rule.** Use existing device_registry privately on fresh all_commits under lock: numeric HLC then author, stable ties retaining store fingerprint/ascending-sequence traversal, original op order. env.init.owner_device/member.add.device must be objects, parse and self-verify; FIRST record per computed fingerprint wins. Registry does not reverify enclosing stored commits or decide membership; Head::checked still verifies selected originals.

Actual DeviceRecord::from_dict ignores extra keys and accepts legacy string/base64 coercions. Cache its complete normalized to_dict record; do NOT apply cache's closed-three-key record() check to raw announcements. Preserve raw nested fields in signed original ops/canonical bytes. Cache decode remains strict/full-record-equal. Later conflicting agreement records do not override first. Earlier-in-order arrival changing first to a conflicting full record => invalid/no overwrite; missing retained record=>unavailable. Removed/fold-skipped authors remain signature material. Y's cache slot grants no membership, wrap, fact authority or permission. Never omit a vector author.

**02 — actual preventive receipt/deferred fix.** receive acquires StateDir lock itself, including direct public receipt. Existing format/env/ops/identity/signature/duplicate branches retain order. Only n>1, n=lastseq+1 consumes cache. Let V=unchanged vector, S=unchanged snapshot_floor, C=cache. Strictly validate whole cache; every positive C component must be covered by S and V, match retained full record and any live copy's signed/hashed original bytes. Missing coverage/ahead/conflict=>invalid. Older cache than a subsequent regular refold snapshot is allowed; do not require entire-vector equality.

Next A:n must exceed live predecessor HLC and any cached A HLC. If predecessor is missing with cache PRESENT, require exact cached A:n-1 with C[A]=V[A]=n-1 and S[A]>=n-1; older/missing A=>unavailable. With cache ABSENT, keep legacy live-predecessor-only behavior. This preserves legacy/cache-loss use, not a claim to recover deleted HLC. Cache never supplies a sequence floor.

True time failure uses existing team_hlc_not_monotone quarantine/audit. Corrupt/unreadable/oversized/inconsistent LOCAL evidence returns fixed State error, no candidate write/quarantine/team_commit_rejected; deferred original stays intact. Gaps/unknown authors retain early/rejection behavior; future gaps still defer before append. Release keeps unlocked gap prefilter/fresh locked recheck. Current duplicate asymmetry stays: receipt of pruned sequence=>equivocation; already-compacted deferred=>drop. No new duplicate receipt policy.

append remains trusted sequence-only storage, not receipt validation; inspected production callers receive/release both get guard. Raw sign_commit remains stateless. Trusted direct append/state writes can construct inconsistent history; compact refuses it. External callers bypassing receipt are not covered.

**Local clocks.** author_commit currently starts at zero and sees only live commits/optional live predecessor. Observe all validated cached heads before tick/sign in it and both existing authorized fact-signing paths, using unchanged Hlc arithmetic. TeamSync reads disk outside envs, then briefly merges observation into its remembered clock and ticks, never lowering it. Roles/rotation/publication unchanged. With present cache, every positive V head must exist live or exactly cached; older evidence cannot fill a missing later head. Absent cache keeps live-only legacy behavior. Errors may stop shared signing, not personal-vault/ordinary snapshot reads. Existing load_facts/standing/rekey maintenance may precede error; no rollback promise. Inspected unsequenced send_incident tick is unchanged/outside commit/removal signing; no broader clock claim.

| Actual pre-fix stored case | Selected outcome |
| --- | --- |
| C=A:2, live2 pruned, incoming equal/regressed3 | Current receive accepts then compact refuses. New receive rejects before append, preserving evidence/data. |
| Regressed3 ALREADY stored below C:2 | Keep3+cache; compact remains invalid while3 required. New4 must exceed BOTH clocks; only legitimate newer aged-head replacement may proceed. Idle/removed A retains refusal; no retroactive repair. |
| Legacy prune/no-cache or actual cache loss | Preserve ordinary reads/legacy receipt. Missing required idle original=>compact unavailable. No guessed HLC or omitted author. |
| No cache/all required originals live | First-cache initialization remains possible. |
| Corrupt/unreadable/nonregular/oversized cache | Current receipt ignores; new eligible receipt/signing returns local error. Reads/derive unchanged. |
| Older cache/newer live predecessor | Check both clocks; missing newer predecessor=>unavailable; C ahead of S/V=>invalid. |

Cache deletion is indistinguishable from legacy absence; authentic older cache cannot prove a newer one was lost. No anti-rollback guarantee. Deleted signatures/HLC and signed regressions cannot be repaired without violating originals. Defined residual outcome: explicit compaction refusal, supported reads, preserved evidence for separately scoped recovery. No operator decryption/bypass/reset/delete, forced edit/key rotation/new reauth workaround. Limitations are not risk acceptance or finding resolution.

**03 — small Root fix.** Choose prospective fixed refusal, not StateDir canonicalization/rewrite. Before publication require non-following metadata: real directories at configured root and below through team/env/snapshots/snapshot_records, validated env/component containment. Inspect root without final slash/dot disguise. Trusted ancestors ABOVE root retain resolution (e.g. platform /tmp alias). Existing snapshot/record/cache destinations must be regular non-symlink; missing prospective children allowed, inspect existing ancestors, create nothing in preflight. Missing root/I/O=>persist_failed; type/containment=>team_compaction_layout_unsupported, empty detail. Dangling link is not absence. Missing/nonregular/symlink READBACK=>persist_failed; check snapshot type before BOTH reads. Keep all fsync/record/cache barriers.

Call after no-old/lagging gates/cut/total, before prepare/write; no-op schemas unchanged. .lock/load_facts maintenance isn't rolled back. No TOCTOU/hostile-filesystem/multi-file-atomicity/hardware-power-loss claim. Root actual Sol personally implements03+tests then freezes base. No extra03 worker requested/launched.

## Prerequisites and holds

Later Root must freeze source/model/checkout and separately assign isolated Linux AND macOS. All runtime UNASSIGNED/NOTRUN here. Native10 unexplained-PID HOLD persists; Linuxch01 retired/deleted, no reuse. Astra49df's active VM-history assessment was not queried/polled/read or borrowed.

Prior native1843/0/5, Linux1840/0/5, focused13+11/profile and14 exact passes are PRIOR-source evidence only. New matrices/independent collection/actually authorized new Rust Opus assessment/separate acceptance remain future gates.

Preserve service-once configuration/trusted HTTP gateway/separate SSH signer core/no OriginalSecrets/explicit unsupported/no SilentLoss. DOS-1 HIGH/OPEN_NOT_FIXED_PARTIALLY_MITIGATED, ca01275 REVISE, OPUS03/03-R1, SEC03, interrupted Go Opus3eb, old Go quarantine/authority/cancellation, M2-G01–G10/general-gap/interacting-removal/continuation, runtime/READY/import/receipt/ACK/journal/coherent epoch, physical two-Mac/sleep-wake/GUI, packaging/macOSACL, Oracle/capacity/release holds stay OPEN. No old Go retry/replacement/continuation/campaign. Snapshot onboarding unsupported. No source/ref/index/PR/merge/deploy/admin/runtime authority for this planning turn.
