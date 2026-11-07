# Ready Sol brief — M2b.2a complete supplied cut semantic candidate

Prepared 2026-11-07 by actual **gpt-6-astra / ultra**, personally, design only in T3 Code through Codex. No subagents/workflows, execution, review/recheck, Opus or acceptance occurred. Read `decision.md` in this directory in full; it supplies the normative contracts, rationale, inspection ranges and complete immutable-source SHA256/mode inventory. This is one finite task **within** M2b.2, not completion of the entire row.

Requested future implementer: actual **gpt-6.1-sol**, **ultra** reasoning. Controller must select/record the real model/settings; role text does not select them. No silent fallback or worker launch is authorized by this document. Controller assigns isolated synthetic-only runners. Native is reserved to the service task and cannot be borrowed or polled. Unassigned Linux/native = NOT RUN and bounded validation incomplete.

## 1. Base, prerequisites and deliverable

Use only a controller/T3-prepared isolated source checkout based exactly on:

- HEAD `9e76a1dae165863ad97f5af976d5037c12e4d0e7`.
- Full tree `fef2952c65cc6120ac6f55b941eeab007c6b0f1d`.
- Rust tree `5d3acbd546c5dc3490e95635342572cb064007eb`.
- Desktop tree `2413844c89265a3e239be2372d34b1e6e1b2d4bb`.
- 1,122-file byte/mode inventory in decision Appendix A; TSV hash `816c1e7c33ca3160350919aae7045ec1b79a27703a76dce8a6063b1d0b59aaf0`.

Verify HEAD, full/Rust/Desktop trees, every working file's Git blob/SHA256/length/executable mode and clean status before editing. Do not transplant to another base without a new controller-bound brief. Read AGENTS, product/security/harness/harness README, PORTING §1, full remote-sync M2/G01–G10 contract, whole-secret-deletion contract, current source-bound reports, all M2a decisions/revision and M2b decision/task. Those files are frozen. This exact base contains real M1, Personal Vault fixes, inert M2a and M2b.1; do not replace any with a stub.

Deliver only the allowed source/test diff implementing `verify_complete_cut_semantics` and opaque `CompleteCutSemanticCandidate`, plus controller-requested evidence outside the repository. Do not edit Root's checkout or PR74/PR73, create shell worktrees, change refs, commit/push/merge/deploy, administer repository/model/runtime/VMs, or acquire credentials. The controller binds the collected diff to its exact final head and publishes separately. An isolated worker source artifact must include full tree/blob/mode inventory if no commit exists; testing the base SHA alone is not testing the diff.

This design's source composition has new Linux validation pending elsewhere. Do not query that worker, the service task or native environment. Its eventual result is not a prerequisite permission to execute on the coordinator host, and it will not validate this future diff. Test only in separately assigned authority-free isolation.

## 2. Finite allowed files

Only these **existing** files may change:

| Path | Allowed change |
| --- | --- |
| `rust/src/team/checkpoint/admission.rs` | Extract/reuse private original-authentication helpers; preserve old public API, scope rejection, errors and all frozen behavior; add focused private tests only if needed |
| `rust/src/team/checkpoint/mod.rs` | Declare/re-export new sibling semantic API/type, correct module-level assurance description, add compile-fail contracts; no existing wire/error/feature changes |
| `rust/src/team/fold.rs` | Narrow pure reuse/extraction of scheduler/op-loop/overlay with compact observations for new complete-cut analysis; ordinary fold/snapshot behavior and all existing tests unchanged |

Only these **new** source/test files may be created:

- `rust/src/team/checkpoint/originals.rs` — private authenticated originals and immutable binding/index ownership.
- `rust/src/team/checkpoint/semantics.rs` — public checked entry, private candidate, orchestration and closed refusal mapping.
- `rust/src/team/checkpoint/removal.rs` — provisional schedule comparison, supported topology and basis/contradiction analysis.
- `rust/src/team/checkpoint/document.rs` — strict known-field/relationship and version-order checks; pure public generation-reference summary.
- `rust/tests/team_checkpoint_semantic_cut.rs` — sibling API, document/overlay/local/binding and negative integration tests.
- `rust/tests/team_checkpoint_removal_oracle.rs` — independent complete ordinary-fold/literal removal oracle tests.
- `rust/tests/common/team_checkpoint_m2b2.rs` — separate synthetic fixture builder, canonical/signing helpers and mutations. Include by explicit path from the two new tests; do not edit `common/mod.rs` or the old builder.

New fixture root is exactly `rust/tests/fixtures/team_checkpoint_m2b2_v1/`. Allowed root files: `README.md`, `SHA256SUMS`. Allowed case directories: `C01-admin`, `C02-owner`, `C03-historical`, `R01-other`, `R02-multiple`, `R03-self`, `R04-pending`, `D01-overlay`, `D02-policy`, `N01-reciprocal`, `N02-cycle`, `N03-same-commit`. Within each case only these eight files are allowed: `history.canon`, `facts.canon`, `payload.json`, `manifest.json`, `literal-trace.json`, `expected-unflushed.canon`, `expected-final.canon`, `expected.json`. Negative variants otherwise remain in-memory test mutations. Synthetic originals and hash/signature arrays are in history/facts/expected, so no unbounded per-record file proliferation is needed. Maximum new fixture files: 98. New files regular 100644, no executable/generator sidecars.

Everything else is frozen byte-for-byte and mode-for-mode: Cargo.toml/lock/features, all numeric/canonical/crypto/base64 helpers, strict_json/manifest/payload/provenance, sync/membership/identity/tombstone/vault/policy/derive/runtime, all old tests and fixtures/builders/SHA256SUMS, desktop, Go/service, harness/CI/verify scripts, AGENTS, docs, decisions, reviews and existing evidence. Do not broaden an old fixture's meaning. If a required function's visibility or stack behavior outside these paths prevents the task, report the exact dependency rather than editing it. Narrow shared helper visibility inside the three allowed existing files is permitted; new public raw-proof constructors are not.

## 3. Implement the exact checked layering

Add:

```rust
pub fn verify_complete_cut_semantics<'m, 'p, 'b>(
    manifest: &'m ManifestAttestation,
    payload: &'p IntegrityCheckedPayload<'b>,
    local: &'m SemanticLocalInputs,
) -> Result<CompleteCutSemanticCandidate<'m, 'p, 'b>, SemanticError>;
```

The result borrows all three inputs and owns private original-fact/basis, schedule/trace, exact order and computed final-state data. Only fixed metadata/digest/count/revision observations are public. No install/Facts/receipt conversion, raw Value/JSON constructor, `Default`, deserialization, callback validator, trusted bool, mutable field, final document getter or serialization into an authoritative stage. Debug redacts payload/local content; failures return no partial candidate.

Build private `AuthenticatedOriginals` using the existing checked originals path, factoring only demonstrably common checks from admission.rs. Both APIs must enter it directly; the new API cannot consume an old retained-authority candidate as removal authorization. Share original device/signature/hash/schema/target/environment and immutable span identity validation, local binding/inventory/deny/collision checks and slot/head/seen checks. Keep original full device equality everywhere. Recompute the new schedule, authority intervals, all fact bases, data/order relationships and final digest. Unchanged original signatures need not be repeated after private immutable span binding, but replacement inputs/revision require a new call.

`verify_retained_authority` keeps its exact current signature/type, removal metadata/link/fact refusals, no-removal pure trace and limited final-digest meaning. Keep coherent false-final-digest tests passing at that stage. M2a `CandidateProvenanceV1` and all current wire formats stay unchanged. Do not accept its JSON as an input to the new proof.

Spans retain original source bytes, offsets and ancestor depth; never reparse a nested slice at depth zero. Keep signed HLC spelling and all op array order. Preserve canonical identity before trusted typed materialization; no custom numeric/JSON codec or Cargo feature changes. Complete source data is not cloned into a new public proof object that can be substituted independently of the original binding.

## 4. Complete-cut eligibility and removal algorithm

First require every original positive author sequence from 1 through its covered vector, exact signed head and all existing M2b.1 constraints. Sort bounded provided slots and compare adjacency/counts with `PyInt`; do not iterate to a numeric head or coerce huge counters to machine integers. Gaps return `HistoryProofUnavailable`. A complete provided cut remains administrator-attested for omissions outside that cut and for historical fact admission.

Support only isolated other-author removal targets and self-only targets: never mixed self/other for one target, and an other-author remover may not itself be a target of any removal fact. Refuse reciprocal pairs, any directed cycle and removal chains with `ScopeUnsupported`; preserve all signed evidence. Commit-only removal/demotion remains part of actual replay and can invalidate a basis.

For every other-author fact, select the lowest author-sequence original commit by that same author containing a matching `dek.rotate.removal_fact_hash`. Missing exact original witness fails. Another admin's repair is not a substitute. Per target: minimum witness `seen[target]` (absent zero) is bound; earliest numeric other-author fact HLC is pending cut. Self-only: lowest target-authored original commit containing own `member.remove` is placement/bound, and actual earliest matching op must apply. Bare self-removal fails missing proof. Compare full bounds, pending, self-placed and exact unique witness hash union with the payload. Refuse dangling/non-removal linkage and linked wraps containing the target. All selected rotation ops must apply; full DEK projection/effective selected wrap equality remains mandatory, without claiming decryption.

Observe authority immediately before each pending HLC batch and self placing op. For each other-author target group require every remover active admin and target admitted, active and nonowner just before its earliest cut. For self require active admitted nonowner target equal author. Target already removed by a commit is outside this conservative supported basis. Do not interpret HLC/wall time as original admission time. Validate every fact against this scheduled trace; no filter-and-retry fixed point.

Final all-fact replay preserves ordinary equal-HLC-before-commit pending placement, original same-commit order, sequence-bound blocking even for backdating, and unconditional block of owner transfer to any fact-removed target. Any skipped authority op fails. Head/vector above a fact-removal bound fails as retained contradiction; no truncating the cut. A removed author's valid head at its self bound is allowed. Remaining future pending cuts flush after all original ops.

Historical non-removal facts need applicable surviving final-trace active-admin interval (incident: active-member interval), exact original signature/target and administrator-attested exact admitted-set binding. Later demotion/removal does not erase a real interval. A removed author's old receipt or an arbitrary historical admin interval cannot authorize unrelated live member removal. No receipt imports/outputs, `relaxed_document` authorization, local `load_facts`, inferred admission clocks or omniscient chronology.

Use existing `sync::apply_fact` and actual M1 `tombstone_gate::digest`. Preserve original hash-keyed objects including all same-ID deletions and no-version tombstones. Enforce all independent local irreversible restrictions, original known-fact subset/digest/support requirements and collision/inventory checks; an empty remote set cannot reset them. Do not inject missing local facts into the signed remote digest to hide a mismatch.

## 5. Document/order and actual computation

Follow decision §§5–6 exactly. Validate known containers and fields before projections, reject embedded `_version_order`, verify full identity relationships, secret kinds/status/generation/nonce/ciphertext/public, active pointers, deleted-state constraints and connection policy/ID/secret selection. Pure existing policy builders only; no CA path reads or program execution. Explicit unknown version pin fails, never becomes follow-active; inactive/deleted selections remain unusable. Preserve opaque legacy public values and current numeric semantics. Separate version-order arrays preserve last-occurrence one-based indexing, duplicates and historical absent-version entries; every present version requires a usable index. Then compare exact complete arrays to the actual history result, without normalizing arrays into equality.

Compute complete history from real genesis using shared existing fold handlers and all provisional authenticated facts. Expose narrow fixed observations from the same scheduler/op engine; no callback-based proof authority or duplicate interpreter. Keep one compact trace, not a document clone per op. Compute the true existing unflushed point after all ops but before remaining pending/removal/fact flush. Facts already influence operation guards, so a fact-free document is not an equivalent oracle. Compare the entire supplied unflushed snapshot/order/vector with that independently computed result. Never seed from sender final state and replay already covered data.

Flush remaining pending and reapply the complete working facts with existing handlers. Validate final relationships and compare `SHA256(C(final_document))` with both signed expected values. Every original immutable put field must agree with its produced version. Differing duplicate version identity refuses; it is not a last-writer choice. Allow only data skips `secret_deleted` on put/status/activate and `version_revoked` on status/activate after normal authority checks; preserve any already inserted ciphertext/order. Other skipped data is finite scope refusal (or the stronger contradiction/authority error if applicable). All authority skips fail. This limited exception preserves M1 restrictive behavior and does not close full M2's broader no-skipped-op gate.

Compute public generation references, original applied/effective recipient wrap selectors and the required union across **all active/staged versions of nondeleted secrets**, not only granted/active connections. This is an inert summary; key availability/ciphertext AEAD remains unproved. No KMS/private keys/decryption/derived vault state.

Reuse closed `SemanticError`: original M2a errors as today; binding mismatch as current binding error; gaps/witness absence as HistoryProofUnavailable; unsupported topology/ordinary nonauthority skip as ScopeUnsupported; unauthorized/skipped authority as AuthorityUnproven; incompatible fact basis/link/head-bound as FactContradicted; schedule/document/order/final digest mismatch as SemanticMismatch; preserve local eligibility/restriction mappings. No new peer-controlled error detail or logging. Unit tests pin exact variants for each class.

## 6. Independent fixtures and oracles

Build synthetic keys/history only within assigned isolation; no production identities/values or host execution. New builder must not call the new verifier to generate expected output or overwrite old fixtures. Test signatures/canonical bytes independently; freeze exact new fixture bytes/SHA256SUMS after deriving literal expectations. No need for plaintext decryption tests in this slice.

Use these fixed cases (symbolic O owner, A admin, R recipient, D removed device are synthetic identities, not authority tokens):

| Case | Required semantics and literal expectations |
| --- | --- |
| C01-admin | Complete P1-like history: O1 init@1000, O2 add A/admin@2000, A1 add R/user@3000, O3 put V1@4000, O4 put V2@5000, A2 activate V2@6000. Include O3; pin A. Exact unflushed/final data/order, zero removals. Old gapped P1 still passes only M2b.1. |
| C02-owner | Complete C01 plus O5 transfer to A@9000, A3 demote O@10000; original O revoke/delete facts retain applicable historical basis. Pin A. No invented genesis owner change. |
| C03-historical | Complete commit-only removal and demotion variants, including D's historical no-version tombstone whose HLC lies after removal. Explicitly prove HLC is not admission time, and pin a still-active admin. |
| R01-other | O1 init@1000; O2 add A/admin@2000; O3 add D/admin@3000; A1 add R/user@4000; D1 settings@4500; A removal of D@5000; A2 linked rotation@6000 seen[D]=1. D head=1, cutoff=5000, bound=1, witness=A2. A remains pinned admin; R exact approved role. |
| R02-multiple | R01 with independent O removal of D and O4 matching rotation. Both facts/witnesses retained; exact minimum-bound semantics. Passing case uses bounds compatible with D head. Unequal minimum below D's head is a negative, not a trimmed positive. Add unrelated independent target variant in memory. |
| R03-self | Same setup; D2 self-remove@5000, self fact with deliberately different HLC (e.g.9000), bound D2, no other-author fact for D. Preserve D's historical deletion facts. Skipped self-placement and absent exact placing commit are negatives. |
| R04-pending | Original linked witness retained before a fact's numerically later cutoff; pending cut after last commit. Do not infer admission/witness chronology from clocks. Literal unflushed D active, final D removed; public linked rotation excludes D. No required-key claim. |
| D01-overlay | Complete data history with two distinct original same-ID deletion facts, no-version deletion, revoked version and incident. Put into deleted ID retains ciphertext/order before skip; final all relevant versions revoked, active null, no synthetic secret for absent ID. Exact sorted original tombstone hashes/M1 digest. |
| D02-policy | Valid HTTP and SSH policy shapes, follow-active and explicit pin, staged/active/retired/revoked data and real version-order relationships. Include literal canonical legacy numeric/private-name public values. References do not open files, invoke CLI or derive credentials. |
| N01-reciprocal | Original mutually removing A/D facts and matching rotations, including a rotation made ineffective by final schedule; ScopeUnsupported for topology. Ordinary fold/literal trace still records real schedule effects, not invented success. |
| N02-cycle | Three-member directed cycle and chain variants; fixed fail-closed topology outcome, all originals preserved in test input. Do not topologically sort cyclic admission or filter a fact. |
| N03-same-commit | Valid role-change/data sequencing in positive in-memory variant; removal/demotion preceding rotation or admin-only data fails appropriate role/scope checks. Same-HLC removal occurs before equal-HLC commit. Preserve op array order. |

For each positive, require all three oracle sources:

1. Literal per-op active-member/admin/owner and exact skips, pre-cut/placing state, chosen witness identities/bounds/pending, unflushed/final data/order and original fact/hash lists. These literals are independently written, not produced by the candidate under test.
2. Existing ordinary complete uncompacted `fold` plus actual M1 fact application, not the new checkpoint trace. Compare complete final document/vector/order/skips. For unflushed data use a literal canonical image and the ordinary snapshot/prefix path in isolated synthetic test state if required. Shared-handler correlation is why literals are compulsory.
3. Existing canonical/signature helpers against literal canonical files, sorted-original-hash digests and actual M1 digest. Recompute expected outer metadata independently of verifier output. Include synthetic key identity checks.

Old tests/fixtures remain byte-identical; read them for regressions without relabeling their candidate-only images. New builders use separately named helpers and fixtures. All 145 M2a and 149 M2b.1 checksum entries must remain equal before/after.

## 7. Mandatory negative and regression families

Every **inner-semantic** mutation must repair payload length/counts/component/raw/chunk hashes and validly sign a fresh outer manifest using the synthetic pinned key. Assert M2a manifest/payload success first. For removal-free cases also assert M2b.1's intended limited result before asserting the stronger error. A bad outer hash is not an inner-negative test.

- Coherent wrong expected-final digest; coherent invented unflushed ciphertext/public/kind, missing encrypted version, wrong activation/status/deleted state, connection policy or settings; both outer expected claims agree yet computed inner result fails.
- Wrong/missing/order-reordered version arrays, missing present index, coercive order entries, embedded `_version_order`, fabricated active pin/follow selection, unknown explicit pin, ID/key mismatch, malformed known container/member/device/generation/wrap. Preserve last-occurrence semantics in private shape tests rather than converting arrays to sets.
- Missing earlier same-author witness; selecting a later one; another-admin repair substituted; unknown/non-removal hash; wrong witness union/bounds/pending/self set; multiple matching ops; skipped rotation; target still wrapped; shadowed effective wrap; head above minimum bound/backdated commit. Correct outer set/signatures do not override contradiction.
- Removal target owner/not yet admitted/already commit-removed at cut; remover not admin; bare self, skipped self placement, self mixed with other, reciprocal/multi-remover reciprocal, 3-cycle and chains; unrelated removal and commit removal cannot be cleared to make a view favorable. Do not claim the refusal diagnoses maliciousness.
- Non-removal fact author whose only qualifying interval is eliminated by scheduled proof; unknown authors/invalid targets; old sender receipt-shaped data gives no authority. Conversely legitimate surviving historical interval remains after later demotion/removal regardless of fact HLC.
- Missing known local same-ID/no-version tombstone, unresolved support digest, stale restore, local removal/disable/revoke deny, occupied unrelated/private IDs, changed revision and conflicting mapping; all existing binding/eligibility tests remain.
- Original signature/environment/schema, duplicate slot/hash, inconsistent device agreement key under same signing fingerprint, genesis/admission/authority-reference/seen/head errors; preserve old exact behavior and legacy huge numeric/HLC semantics.
- Gapped old payload => HistoryProofUnavailable in new API, with old M2b.1 result unchanged. No loop/allocation proportional to huge vector. A signer omitting information beyond its declared cut remains the documented attestation trust limit, not a claimed detectable negative without local evidence.
- Compile-fail external construction/deserialization/default/from-Value/Facts conversion/receipt/install/mutation tests for the new type, and attempted use of old candidate/provenance JSON as new proof. No production runtime caller/capability.
- Input byte/hash/local-observation identity unchanged after success, error, repeated call and drop; no runtime files/receipts/logs/mappings/status mutations. Synthetic marker text never appears in errors/Debug.

## 8. Stack/resources and isolated verification

Respect existing raw limits and total original depth. No custom codec, unsafe, stacker, global stack/environment workaround, Cargo change or hidden less-deep reparse. Exercise 256 KiB thread success, late failure, repeated use and destruction at depth64 plus early depth65 rejection, **debug and release**, both assigned Linux and native macOS. Use deepest legacy nested values inside an original record and snapshot, carrying correct envelope ancestor depth. A zero-test filtered command is NOT RUN, not success. Tests must record actual selected case counts.

Bound memory by source/input count: borrowed original spans plus bounded indexes/records, one working state and at most one additional unflushed/final image. No full-document-per-op trace. Index witnesses once rather than rescan candidate metadata as authority. Report actual peak RSS and elapsed semantic phase separately on near-limit snapshots/record sets, many removals/witnesses and negative late exits. Record machine limits; 16 MiB payload does not mean 16 MiB RSS. An expensive inherited fold is a measured limitation, not a permission to relax bounds or claim DOS-1 fixed. If 256 KiB fails due frozen clone/canonical/drop/helper behavior, preserve failure and return the exact dependency; do not work around it outside the allowlist.

Commands below are **future assigned isolated runner instructions only**. None was run by the design author. Run focused tests during implementation, then one unchanged full suite per platform on final source; rerun after material changes/failures as appropriate:

```sh
cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_semantic_cut
cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_removal_oracle
cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_admission --test team_checkpoint_authority_oracle
cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_manifest --test team_checkpoint_payload --test team_checkpoint_provenance --test team_checkpoint_legacy_parser_regression
cargo test --locked --offline --manifest-path rust/Cargo.toml --test whole_secret_tombstone
cargo test --locked --offline --manifest-path rust/Cargo.toml --lib team::checkpoint
cargo test --locked --offline --release --manifest-path rust/Cargo.toml --lib team::checkpoint
cargo test --locked --offline --release --manifest-path rust/Cargo.toml --test team_checkpoint_semantic_cut --test team_checkpoint_removal_oracle
bash rust/verify.sh
```

Use the actual test location for stack/resource tests and record it, rather than relying on an unrelated filter. Full verify covers formatting, strict Clippy, library/binaries, every integration target, signer probes and doc tests; new targets are auto-discovered by the existing script. Preserve Cargo feature resolution and 36-input old-parser regression. No host Cargo/rustfmt/build/helper/generator execution; no production vault/model/deployment/admin/recovery keys. No borrowing native, modifying VM/runtime or querying others. If offline dependencies or a runner are unavailable, report exact prerequisite and NOT RUN.

No harness changes are authorized, hence no harness test execution is needed for this task. No installer mock, crash/ENOSPC or readiness simulation is accepted as proof of later runtime gates. Ordinary oracle synthetic state operations run only inside the assigned test isolation.

## 9. Evidence and stop conditions

Record actual model/settings, prompt/design hashes, source/base/final head or collected-diff identity/full and Rust trees, every changed file/mode and complete before/after inventories; protect all frozen paths by SHA256/mode equality. Record OS/toolchain/dependency features, commands/exits/per-target counts, raw logs, fixture/builder hashes, literal/ordinary/canonical oracle identities and resource metrics. Preserve every failed attempt under its actual source; do not rewrite original findings or erase prior logs. Static source audit must show no production caller, KMS/decryption/receipt/state/transport side effect.

Stop at the finite scope. Concrete missing source API, unavailable original history, unsupported interacting removal, frozen helper stack issue or missing runner is reported separately, not bypassed with an attestation flag or broader runtime work. The controller may assign a separate dependency task. Deliver code plus accurate NOT RUN gaps when a runner is unavailable; do not call bounded verification complete. No final acceptance/review is implied by implementation completion.

Final worker report: changed files; exact implemented API and finite class; original-fact/irreversible restriction preservation; all tests and platform gaps; original failures and unresolved finding IDs; source/mode/protected-hash binding; explicit remaining M2b.2 dependencies. The controller collects, publishes and binds later readiness/review to the exact new head. No PR/ref/admin operations in this worker task.

Canonical original status stays unchanged: `ZPLINK-OPUS-01/02` RESOLVED for original scenarios; `-03` OPEN with `-03-R1`; `ZPL-SEC-01/02/04` RESOLVED; `ZPL-SEC-03` INSUFFICIENT_EVIDENCE. `DOS-1` original **HIGH OPEN**, partially mitigated only. Preserve original new low/nit findings and canonical evidence/severity, original 8258 native pairing failures and later source-bound corrections. The interrupted newer actual Opus run remains interrupted; do not retry it or self-supply a verdict. This task is not adversarial review, recheck, service review or acceptance.

All gates remain explicitly open: **M2-G01 OPEN** M1 integration/session ACK; **G02 OPEN** full original/removal authority/integration; **G03 OPEN** general historical admission/removal/gapped final semantics; **G04 OPEN** compaction/floors/continuation; **G05 OPEN** required generation/ciphertext usability; **G06 OPEN** durable approvals/authenticated transport/budgets; **G07 OPEN** challenged READY and locked cut checks; **G08 OPEN** journal/recovery/coherent read/use epoch; **G09 OPEN** committed provenance before receipt/ACK/activation; **G10 OPEN** final-head Linux/native/crash/concurrency/physical/direct/TURN and actual Opus. **Key availability, runtime onboarding and release gates all OPEN.** Native unassigned and current-source Linux pending are separate from future-slice test gaps; neither is filled by historical 795babd Linux 107-step/1,735-test evidence.

## Completion integrity record

Repeated after drafting on 2026-11-07: HEAD `9e76a1dae165863ad97f5af976d5037c12e4d0e7`, full tree `fef2952c65cc6120ac6f55b941eeab007c6b0f1d`, Rust `5d3acbd546c5dc3490e95635342572cb064007eb`, Desktop `2413844c89265a3e239be2372d34b1e6e1b2d4bb` remained exact. All 1,122 tracked file bytes and actual POSIX/executable modes matched the initial inventory and their Git blobs; seven executable files, zero drift, clean tracked/untracked Git status. The repeated inventory SHA256 remains `816c1e7c33ca3160350919aae7045ec1b79a27703a76dce8a6063b1d0b59aaf0`. Canonical ca01275 review hashes were also checked unchanged. All protected source/fixture/instruction/review/evidence files are covered by this equality. No source or ref changes occurred.

Exactly two output files exist in the requested external directory: `decision.md` and `implementation-task.md`. No product execution, isolated execution, test, review/recheck or acceptance occurred. No other checkout/ref, active worker/native/service environment, production authority or external service was used. DOS-1 HIGH OPEN; all M2-G01–G10, key, runtime and release gates OPEN. Final document hashes are supplied with the handoff; a document cannot contain its own whole-file hash without a circular definition.

Normative accompanying decision SHA256: `5d297d887dda694d0d36881a6402c5e94faeb194558329a1f82287206806df2c`. The complete exact source inventory and semantic inspection ranges are in that decision.
