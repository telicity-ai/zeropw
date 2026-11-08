# Next M2 prerequisite: preserve original signed compaction heads

2026-11-08. STATIC planning by actual **gpt-6-astra / ultra**, T3 Code through Codex. Runtime identifies model/effort. Dispatch requested `serviceTier=default`; effective provider tier is not independently exposed. No subagent/workflow/model substitution, implementation, execution, review or acceptance. Cancelled medium-effort task f95251c9 and its partial outputs were neither read nor reused.

**Planning READY only for bounded actual-Sol work in implementation-task.md.** Preserve original signed heads in actual TeamSync::compact before deletion. Snapshot onboarding remains unavailable; all M2-G01–G10 remain OPEN.

First operation hashed `/tmp/zeropw-next-runtime-slice-astra-ultra-20261108.md`, matching required SHA-256 `f4e4c3bc35f9ff1f0fee43adc184c7836d23a42c6d33e7bbe16f8dfd48904551`, then read it fully. Only host standard-library DATA/text/hash and read-only Git operations were used. Only this file and its sibling task are written, combined <=32 KiB.

## Source binding and inspection

| Item | Binding |
| --- | --- |
| Checkout | /Users/ys/.t3/worktrees/zeropw/t3-94fa787b |
| HEAD | 06ab4784d9ac387307f96bc976df1bbc20de2bb1 |
| Full tree | 006a9879da19ec21424e9a12d160a97f20b369b8 |
| Rust tree | 4352ebbd0fa84bde0fb444c4d0902ef2510d0620 |
| Desktop tree | 2413844c89265a3e239be2372d34b1e6e1b2d4bb |
| Code origin | ee26e36997797fe9893ed9a8314ea497963961e2 |
| Inventory | 1352 files; /Users/ys/Code/zeropw-mlp-evidence/required-generation-next-slice-preparation-20261108/source-manifest.json |
| Inventory SHA-256 | 070cd8b861adf274391e3bfeb550cfb5ee377d45f01066625a43242b4fe62ded |

Before planning, every path matched lengths/bytes/SHA-256, independently computed Git blobs, Git modes and filesystem modes; trees and clean status matched. Repeat after writing both outputs and report the result. Whole-inventory hashing is not whole-source semantic review.

Fully read AGENTS, product-intent, security-design, docs/harness, harness/README, PORTING including §1, whole-secret-deletion, remote-sync, full remote-sync-next-milestones and current turn-checklist. Read team-sync compaction/removal/continuation text. Read M2a decision/parser amendment, M2b admission decision, substantive M2b2 complete-cut decision/completion text. M2b2's large inventory appendix was hash-bound, not individually interpreted. Both required-generation documents were fully read; required hashes matched: decision `d4f80f910a3209b4d4399e302f8c63c65316ae78a06421f46043bacf9630b158`; task `4d8990b5c6a38ff7c6224c7c1e734998a18b8416c579b211d9489663e40ed1c8`.

Static semantic inspection, with paths relative to rust/src unless specified:

| Source/API inspected | Finding |
| --- | --- |
| team/checkpoint originals, removal, semantics, semantics/required_generations, provenance (full) | Exact original heads/signatures; complete supplied sequence coverage; finite isolated removals; unflushed fold/order/final overlay. Opaque SecretBytes required-DEK checks have no getter/install/receipt conversion. Provenance is inert. |
| checkpoint manifest:1–270, payload:1–145, admission:1–275, document:1–170 | ExpectedContext/SemanticLocalInputs bind supplied observations, not durable approval or collection. Public JSON is not authority. |
| team/commit:330–455,770–840,1939–2093 | canonical_json/hash/verify_commit; exact PyInt/HLC; get/all_commits/vector and local snapshot floor. Existing sequence-range scan cost remains. |
| team/sync facts:5139–5309, identity:5405–5411; construction/register/refold/submit/admit; compact:9173–9301 | Real locks/peer vectors/compaction. load_facts can maintain receipts/tombstones/rejected facts. Compact currently saves before taking its deletion lock. |
| team/fold Facts/RemovalSchedule, snapshot selection/check/save/load/records; membership:196–221 | snapshot_of_prefix/save_snapshot/record/fold_with_snapshot/load_environment are local-cache operations, not remote installers. |
| membership:991–1208; pairing approval paths; sync admit_member | Invite used/used_by/approved_fingerprint and original member.add exist; full two-sided snapshot authorization/session transaction does not. Join returns on active membership. |
| store:1–368; Context fields/open; Vault open/use/backup/restore ranges | StateDir reentrant lock+flock; file fsync+rename, no directory-fsync or multi-file visibility journal. Vault caches DEK. Backup excludes proposed cache; restore_pending is not an import transaction. |
| gateway:3370–3528; signer:745–772,1075–1175 | Cached policy/connection selection precedes credential use; a write lock alone does not supply coherent installation epochs. SSH separately parses bytes/checks public metadata. |
| admin_cli:3940; desktop/core pairing and commands/remote approval/join | Real compact caller; service enrollment/inviter approval exist, but Desktop joined follows native join success, not committed snapshot provenance. |
| verify.sh full; three compaction test bodies; M1 convergence/compaction body; tombstone test index | Auto-discovered integration matrix; frozen deletion counts/paths and M1 retention oracles. |

Non-checkpoint Rust text search found no verify_required_generations/verify_complete_cut_semantics/BOOTSTRAP_REQUEST/BOOTSTRAP_READY/CandidateProvenanceV1 references. This is not a whole-program proof. Unlisted source ranges, all earlier implementation briefs, huge evidence catalogs and every raw log were not comprehensively reviewed. No source/helper/dependency/generator/test/build/Cargo execution, production-state/key inspection, or runtime query occurred.

## Decision and dependency

Actual compact can delete an author's final data-only commit. A snapshot vector retains its sequence but cannot recover original signature/hash/HLC. Checkpoint originals.rs requires that exact head. Complete coverage also requires every sequence through the cut: **head retention does not make gaps pass**, and current candidate/required-generation APIs stay unchanged/noninstallable.

Keep one versioned local cache of original signed heads/full public records for every nonzero component of the latest compaction vector, including idle/removed authors. Publish durably before unlink. Future current-cut export copies exact live/cache slots under lock, then separately proves original authority/facts and supported gapped semantics. Cache presence never advances vector/fold/admission/receipt/use authority; arbitrary historical cuts are not promised.

Keeping heads in the live log is rejected: existing tests require deleted paths/counts (compact_preserves_membership_history_and_snapshot_document; a_second_compact_keeps_what_the_first_compacted; snapshots_refuse_lagging_member_preserve_history_and_allow_gap_append). Preserve all six retained authority kinds and mixed commits, including rotation/self-removal witnesses. Missing legacy heads force refusal before new snapshot/cache writes/deletion; never guess zero/HLC, select an older head, synthesize a signature or substitute an administrator attestation. Ordinary local use remains unchanged. Omitted completeness remains administrator-attested, not proven by signatures.

An installer now would invent approval/collector/freshness/visibility authority. A gapped verifier first would still lack legitimate compacted heads. This prerequisite prevents further real loss and supplies future export evidence. Complete-history-only onboarding remains possible later but does not solve compacted vaults or the missing runtime boundaries. This task does not permanently prohibit runtime development.

## Requirements remaining OPEN

- Gapped/general/interacting-removal and continuation proofs: original genesis/admission/authority/removal witnesses, all original facts/tombstones, unflushed snapshot/order/final overlay hash, DEK selectors, signed heads/floors. Explicit late-precut/history-required refusal while enforcing known monotone restrictions.
- Protected-backend collector of actual inventory/collisions/revisions/restrictions/restore barriers under lock. Durable joining-human pin of full inviter record as administrator, separate inviter approval of exact recipient/role/mapping, original admission and idempotent invite use. Service invite/TLS/fingerprint/Boolean/callback/public JSON/DeviceRecord alone is insufficient.
- Fresh request/onboarding/session nonces, finalize challenge and authenticated signed READY over exact cut; current consent/revocation/eligibility/revision recheck. No network wait under lock/cross-session resume. v1 original invite expiry; later v2 renewal separately authorized.
- Raw transport before Value parsing; snapshot capability; manifest64 KiB/payload16 MiB/chunks64 KiB max256/encoded frames128 KiB/four outstanding512 KiB queue/devices256/records65,536/depth64; staging64 MiB/128 MiB process/one per env/two per process/ten-minute total/thirty-second idle. Real cancellation and authority-free public validation separate from trusted key work. Library checks are not runtime enforcement.
- Fresh environments only; no established-state overwrite/merge. Journal/file+directory fsync/recovery/one visibility commit/coherent read and gateway/signer use epochs. KMS-wrapped required DEKs only. Committed provenance before receipt/ACK/activation/displayed completion; fresh M1 fact/vector ACKs still needed.
- Restart/restore/imported-state compaction/downgrade/offline edits/deletes/revocations and physical Mac interruptions. Existing backup omits cache; loss must refuse export. No whole-database overwrite/server vault copy/version-history expansion.

Cache caps256 heads/16 MiB serialized are new retention limits: exceeding them refuses compaction, not legacy reads/wire traffic. Existing load/fold/canonical work remains; no total memory/latency/capacity guarantee. Required-generation authentication proves AEAD storage bytes, including empty/non-UTF8/malformed SSH bytes, not provider/credential readiness. SecretBytes zeroization retains dependency/compiler/OS limits. No plaintext/raw DEK persistence or exposure to agent processes/tools; trusted HTTP gateway and separate SSH signer remain mandatory.

## Evidence and holds preserved

Read both required-generation evidence READMEs/REPORTs/STATIC-COLLECTIONs, full native release receipt, Linux ACCOUNT-DIAGNOSIS/four account-correction-management-forced-route stdout receipts/OWN-RESOURCE-RELEASE as saved DATA only.

Native exact1328-source ee26/Rust4352: historical111 steps/106 targets,1819 passed/0 failed/5 ignored, all14 exact256 KiB PASS. Valid23,000-op single-commit TIMEOUT1800s; distributed32-op input is different, production algorithm unchanged. Raw-DEK2 MiB excludes indexes/allocator. Not validation of this slice or capacity.

Original Linux exact7d27fd7/1338 sources stays **FAIL1812/4/5**,111 steps/106 targets,109 successful/two failed targets;27 passing phases; feature-after **NOTRUN**; all14 exact PASS. Root changed dedicated rgrun shell only from nologin to /bin/bash, password locked/groups unchanged, then verified management `DenyUsers rgrun` **before R2 product execution**. Fixture temporary sshd -f configs have no Include and remained unchanged. Forced UID2000/groups[]/NNP1/caps0/source/cache checks matched. Fourth blank-stderr cause remains inferred.

R2 actual-Sol task6da68e8e exclusively uses UID2000/newrg01; outcomes PENDING/NOTRUN here. No in-progress files/state/VM/SSH/account/process/resource/cache/target query/execution/polling. Mac501 released/unassigned. Old Go case12 quarantine+lease UNRELEASED, AUTHORITY_NOTREADY/CANCELLATION_EVIDENCE_NOTREADY unchanged. No resources allocated.

DOS-1 HIGH/OPEN_NOT_FIXED_PARTIALLY_MITIGATED; ca01275 REVISE; OPUS03/03-R1 OPEN; SEC03 INSUFFICIENT_EVIDENCE. Original resolved/new LOW-nit statuses unchanged. Opus3eb interrupted, no accepted verdict; no review/recheck/retry/replacement. All M2/runtime/READY/receipt/ACK, physical two-Mac/sleep-wake/GUI/packaging, Oracle HTTPS/TURN, capacity and release holds OPEN.
