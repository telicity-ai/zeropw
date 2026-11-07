# M2b.2 decision: complete supplied cut semantics, bounded first implementation

Date: 2026-11-07 (Asia/Seoul). Author: actual **gpt-6-astra**, **ultra** reasoning, running personally in T3 Code through the Codex harness. This is design/decision only. No subagent, workflow, other model, Opus invocation, external review/recheck, acceptance, service-review substitution or interrupted-review retry occurred. No product/helper/dependency/fixture/generator/build/formatter/test execution or import occurred, on host or in a VM. Read-only Git and text reads, and standalone Python `-I` standard-library byte/hash/JSON-data inspection, are not product execution. No credentials, production data, external service, worker/native polling or runtime/VM changes were used.

The entire general M2b.2 row is **not ready as one implementation** from this source. The ready task is its finite complete-provided-cut subset, called **M2b.2a** here to prevent claiming the whole row is finished. It adds original-removal analysis, strict document/order checks and a recomputed final overlay for an explicitly restricted class. It produces a stronger opaque **noninstallable** candidate. The gapped-prefix and interacting-removal classes remain explicit dependencies below. This does not change the full M2 contract, M2b.1 acceptance/rejection meanings, existing M1 behavior or any existing decision file.

## 1. Exact input and authority boundary

Only `/Users/ys/.t3/worktrees/zeropw/t3-222b3c6c` was used as source. It is the existing T3-prepared isolated checkout, branch `t3/m2b2-semantic-removal-overlay`. No checkout/worktree was shell-created and no other checkout's source was read or edited. Reading Git's worktree metadata did not inspect those other working trees. Root's draft PR74 stacked on PR73 is background context from the user; neither PR/ref was queried, edited, pushed or merged.

| Binding | Verified starting value |
| --- | --- |
| HEAD | `9e76a1dae165863ad97f5af976d5037c12e4d0e7` |
| Full tree | `fef2952c65cc6120ac6f55b941eeab007c6b0f1d` |
| Rust tree | `5d3acbd546c5dc3490e95635342572cb064007eb` |
| Desktop tree | `2413844c89265a3e239be2372d34b1e6e1b2d4bb` |
| Tracked files | 1,122 regular files: 561 under Rust, 190 under Desktop; seven executable files |
| Worktree | Clean, every tracked file's actual bytes match its Git blob; every executable bit matches Git |
| Complete TSV inventory SHA256 | `816c1e7c33ca3160350919aae7045ec1b79a27703a76dce8a6063b1d0b59aaf0` |

Appendix A lists every path, Git mode/blob, actual SHA256/length/POSIX mode. Thus protected hashes include all instructions, existing decisions/reviews/evidence, strict parser, canonical/numeric helpers, Cargo/features, tests/fixtures, harness/CI, M1/Personal Vault/desktop and unrelated code. A full hash inventory is **not** a full code review. Semantic inspection is enumerated in §11. Completion integrity is recorded after the inventory.

Current source includes real M1 deletion, the Personal Vault pairing/adoption corrections, inert M2a and M2b.1 retained-authority analysis. Historical evidence for worker `795babd269e9c0ed0a6498a476c67c21894f875f` binds Rust tree `9c7d432b44ff7f7244dcd58f9a416c83b31e6c76`, not this Rust tree. Its Linux 107-step/1,735-test result is historical evidence only; native was NOT ASSIGNED / NOT RUN. Current 9e composition's new Linux validation is pending in another task per the user. It was not queried. These gaps authorize neither execution here nor acceptance.

## 2. Dependency map and selected finite scope

| Row | Concrete dependency and disposition |
| --- | --- |
| M2b.2a: this ready task | All original commits for every nonzero covered author sequence, all attested original facts, original identity/authority/wrap evidence, and independent local observations. Public-only pure analysis, complete supplied cut, isolated removal topology defined below. |
| M2b.2 remaining: gapped data | Existing payload contains a full-cut unflushed image, not a separately authenticated earlier data base plus all its subsequent operations. Retained `activate`, update, disable, duplicate put and order effects cannot generally be proved by replaying on an empty document or replaying again on the already covered image. Need a separate bounded design for target-specific retained constraints against the attested prefix, or exact missing original sequences. Missing originals can make this task's complete-cut route eligible without a wire change. No fetching is implemented here. |
| M2b.2 remaining: interacting removal | Reciprocal removals, targets that also remove another device, mixed self/other removal for one target, bare self-removal and histories whose earlier admission is invalidated by retroactive placement need exact applicable original evidence and a defined counterfactual trace. V1 does not record fact-admission chronology. Receipts/HLC cannot fill it. This task returns finite scope/history refusal, retains all evidence, and adds negative fixtures. |
| M2b.3 | Required generation availability and ciphertext usability in separate trusted key-bearing memory. Public wrap-source checks here are prerequisites, not decryption evidence. |
| M2b.4 / later rows | Proof-retaining compaction, floors, continuation/history-required behavior. No compaction or receive-path relaxation here. |
| M2c/M2d and full M2 | Durable approvals, raw session transport/budgets/deadlines, challenged READY, install/recovery/epochs, provenance/receipts/ACK, credential/runtime/status/UI integration and release validation. All separate. |

The restriction is intentional and testable: require original slots `(author, 1..vector[author])` exactly, with signed head matching the last slot. Check adjacency and counts over supplied sorted slots with existing arbitrary-precision integers, never allocate/iterate to an attacker-selected numeric vector maximum. Zero-vector devices need no commit. Sequence continuity proves coverage **within the supplied declared cut**; it cannot prove no author, later head or historical fact was omitted by the pinned administrator. Trust remains `administrator_attested`, even for this class. No terminology such as complete reconstructed-history proof is permitted.

Supported fact-removal topology is finite: each target has either one or more other-author removal facts, or one or more self-removal facts, never both. For each other-author fact, its author must not be a target of any fact removal in the same admitted set. Thus reciprocal pairs, cycles of any length, and chains where a removed target removes a different target are refused. Multiple independent removers of one target and one still-active remover of several targets are supported. Commit-only removal/demotion is still processed normally and may make the fact basis fail. A self-remover may author historical non-removal facts. Every signed fact remains in the result; none is filtered to satisfy this topology.

This is a subset of the prior M2b conservative algorithm, not a new permissive interpretation of it. Full M2 still requires its broader normal removal/ownership/compacted cases; a green M2b.2a result does not close that obligation.

## 3. API layering and typed ownership

Keep `verify_retained_authority` and `RetainedAuthorityCandidate` unchanged in public signature and assurance. It continues to reject `member_removed`, every op containing removal linkage, and nonempty bounds/pending/self-placement/witness metadata with its existing refusal. It still does not validate the final digest. Existing false-final-digest successes at this limited stage remain successes. Do not turn that type into a removal proof or add a permissive flag.

Add a sibling entry with this ownership contract (names are prescribed):

```rust
pub fn verify_complete_cut_semantics<'m, 'p, 'b>(
    manifest: &'m ManifestAttestation,
    payload: &'p IntegrityCheckedPayload<'b>,
    local: &'m SemanticLocalInputs,
) -> Result<CompleteCutSemanticCandidate<'m, 'p, 'b>, SemanticError>;
```

No public constructor, `Default`, `Deserialize`, `From<Value>`, raw-JSON proof factory, callback validator, trusted boolean, public `Facts`/receipt conversion, final document getter or install method. Do not serialize a new provenance stage and treat the string as authority. M2a's `CandidateProvenanceV1` and its wire bytes/stage remain unchanged. Redacted Debug and fixed errors only. Public observations are manifest hash, locally bound revision, covered-cut hash, recomputed-final digest, admitted-fact/tombstone digests and counts; no credential or runtime authority.

Refactor the common **original authentication**, not the two scope policies, into a private `AuthenticatedOriginals<'m,'p,'b>` in `checkpoint/originals.rs`. Its sole constructor is private to checkpoint. It borrows the three original inputs, keeps the payload's private span/index ownership and owns bounded indexes/typed original records. It verifies the same original self-signed full device records, canonical record equality, original hashes/signatures/environment/schema/targets, genesis/admission identities, authority-reference set, slots/heads/seen/HLC constraints and local binding/inventory restrictions currently checked in admission.rs. It authenticates data; it does not itself prove replay roles or fact admission. A private enum/field must not be presented as a caller-supplied assurance toggle.

Each public API calls that checked path itself. The old API applies its original early scope rejection and old no-fact-removal trace; the new API checks complete coverage, computes provisional removal placement and performs the stronger trace. A caller does **not** need, and cannot use, an old `RetainedAuthorityCandidate` to bypass original authentication for a removal-bearing package. Preserve old error mapping/observable validation order for existing inputs; if refactoring would change a frozen expectation, leave the corresponding old check in place and share a smaller helper instead.

Original binding is `(manifest hash, payload source bytes and signed payload hash, exact component/record span including ancestor depth, original canonical identity/hash, full device copies, local bindings/revision)`. Keep raw bytes borrowed and immutable. No independently reparsed string slice at depth zero, normalized HLC rewrite, changed op order, reconstructed commit, or signature over rewritten JSON. A rematerialization of the **same private span** may reuse the already checked signature/hash identity. It must use the same inherited-depth parser and cannot accept replacement Value or record. Rechecking signature on identical immutable bytes is unnecessary; rechecking all new semantic roles/bounds/overlay/identity relationships is mandatory. A different payload, manifest, local observation or revision requires a new public call. Later finalization must reobserve current state; borrowing an immutable metadata snapshot is not a freshness lock.

The stronger candidate owns (privately) the original facts keyed by **original hash**, their bounded basis descriptors, trace/schedule indexes, exact final order and final computed document. Original commits may remain immutable spans with compact indexes; do not keep duplicate full trees merely for convenience. Every fact object, signature and hash, including two deletions of the same ID and deletion of a no-version ID, is retained. Private analysis `Facts` are built by the existing `sync::apply_fact` only after each original is authenticated; candidate construction remains impossible until **every** basis/contradiction check passes. Local receipt creation is absent.

## 4. Removal placement and historical admission rules

Grounding: `fold.rs:115–390,1480–1819`; `sync.rs:4880–5330,7770–7935`; `membership.rs:1208–1520`. The scheduler is a placement algorithm over admitted facts, not a fact authenticator. Ordinary incoming fact validation and local receipt loading have different authority contexts; do not call those I/O paths from this API.

For every other-author fact, choose the whole original commit by **that fact's author** with the smallest author sequence containing `dek.rotate.removal_fact_hash == fact.hash`. The exact hash linkage is mandatory. All candidate originals are searched, including earlier possible witnesses. A later repair by another admin is not the fact's witness. Missing witness is `HistoryProofUnavailable`, even though ordinary M1 may use HLC-only fallback. If a chosen commit has multiple matching ops, preserve its identity and all op indexes; each authority op must apply. The per-target bound is the minimum of these witnesses' `seen[target]`, absent meaning zero. Pending placement is the earliest numeric fact HLC among other-author removals of that target. Fact HLC places that cut; it is **not an admission timestamp**. No extra claim that a witness proves when the fact was received, or that wall-clock causality can be inferred, is allowed.

For self-only facts, select the lowest author-sequence whole commit authored by the target with `member.remove` of itself. Its sequence is the bound; identify the earliest matching op in that commit and evaluate it in original op order. Self-fact HLC does not place it. Bare self-removal lacks this supported basis and is refused. The old scheduler's removed-from-start fallback and use of even a skipped self op as a bound remain untouched for ordinary folds; this checkpoint route must refuse a skipped placing operation.

Recompute bounds, numeric-tuple-sorted pending list, self-placed set and the exact unique witness-commit union. Compare **all** transferred metadata, including absence/extra entries, to that computed schedule. Repair rotation commits remain signed history but are not inserted into the witness set just because they reference a removal. Every removal link must name an included original `member_removed` fact; a non-removal/unknown hash is a contradiction. Only applied rotation ops supply generation/wrap evidence. Publicly require a linked rotation's wraps to exclude its named target; compare the entire DEK/current/removal-hash projection to the actual fold. This is a new checkpoint eligibility check grounded in `remove_member`/`rotate_dek_bound`; the bare fold handler does not enforce the exclusion. It is not proof of key secrecy or successful rekeying.

Build the provisional complete-set schedule and trace **without publishing a candidate**. Observe pre-cut authority before each equal-HLC pending batch (all removals at that HLC apply before any commit with that HLC) and immediately before each self placing op. For an other-author group, all its fact authors must be active admins and the target admitted, active and not owner in the view immediately before the target's earliest cut. Requiring active target is a conservative restriction: a redundant later removal of a target already commit-removed may be legitimate ordinary traffic, but this task refuses it rather than inventing admission chronology. For self placement require the author/target active, admitted, nonowner, and the actual op successful. The provisional trace does not grant roles; all assumptions are checked against that same complete signed set before success. Removal only restricts; no deletion/retry fixed point may manufacture a favorable trace.

Final replay uses **all** facts and schedule. A commit past its author's bound contributes no ops, irrespective of backdated HLC. Pending cuts apply before equal-HLC commits. `owner.transfer` to any fact-removed target is blocked at any position, even before its cut. Reject every skipped authority op. A head/vector above a removal bound is a retained contradiction: refuse the package, never lower vector, discard a head or trim evidence. A removed author's head exactly at a supported self bound is not intrinsically invalid. A pending cut after the last commit still flushes at final overlay; its pre-cut view is the end-of-ops view. A target introduced only later than its cut has no basis. Same-commit role grant, removal, rotation and demotion are checked in **original array order**; sorting operations by kind is forbidden.

Reciprocal and cyclic cases are consciously refused in this task. The actual incoming rule may counterfactually clear an author's fact-removal only when the author was removed solely by the current target, retaining unrelated facts and commit removals. `relaxed_document` (clear every fact removal) is an identity lookup aid, not authorization. A future extension must reproduce the exact relation and final trace; even an eligible counterfactual fact can leave its signed rotation skipped in the final all-fact fold. Such a package cannot satisfy the no-skipped-authority requirement. Same-HLC cycles have no legitimate arbitrary topological tie break. An old sender receipt, guessed arrival order or transport of recipient-local receipt authority is not a solution. This task's refusal is a scope limit, not a new finding against M1 or an accusation of maliciousness.

For non-removal facts, reuse the existing target validator and M2b.1 historical basis rule on the **final scheduled** authority intervals: some active-member interval for incident, some active-admin interval for disable/revoke/delete. Keep original target data and exact device-copy equality. A later demotion/removal does not erase an interval actually present. A fact HLC before admission or after demotion is not itself proof of actual admission time. The signed exact admitted set supplies the administrator-attested historical admission claim; retained proof must not contradict its applicable basis. A removal eliminating the only qualifying interval causes refusal. Incident has no document overlay effect; disable/revoke/delete/removal use existing effects. Unknown authors/targets, malformed schema and ineligible basis are not cured by the outer signature.

Local known original facts and independently observed irreversible restrictions are separate inputs. Preserve M2b.1's original-hash subset/support-digest checks and deny/collision/stale-restore checks. Missing known local tombstone cannot be excused by an empty remote digest. Do not merge an untransported local fact into the remote signed set to make its digest agree; refuse inconsistency. Do not reduce local deletion/removal/disabled/revoked restrictions to the remote image. Recipient-local receipts are neither payload inputs nor outputs. `sync::load_facts` writes receipts/ledgers/rejection logs and must never be called here.

## 5. Strict document and version-order semantics

Validate shape **before** projection/equality can accidentally ignore malformed data. Then require complete canonical equality to independently computed full-cut unflushed state. This route does not normalize a sender image into a passing image. Keep the old permissive snapshot loader unchanged.

- Document must be an object with exact format/environment and correctly typed owner, members, DEK, connections, secrets and settings containers. `_version_order` must be absent, even if it looks equal. Unknown legacy fields inside legacy values retain their exact values; they do not extend known semantics, and complete-cut equality will reject unsupported invented content. No blanket float/large-integer/private-name ban in legacy subtrees.
- Member map keys must be exact device fingerprints; embedded full records must verify and equal the unique device table and signed admission copies. Names/roles/statuses have the existing shapes. Owner must resolve to the replay's active admin. DEK current/generation identities, wraps and any removal linkage must exactly match applied original authority operations, including overwritten historical values where represented. No invented generation or effective wrap may be accepted from image-only membership.
- Secret IDs and version IDs use existing op identity validators, not lossy string/number coercion. Kind is one of `api_key`, `password`, `env_var`, `ssh_private_key`; versions is an object. Each version has exact recognized status `staged|active|retired|revoked`, a valid existing generation ID, nonce/ciphertext strings and public object, preserving opaque public data. Active pointer is null or an existing active version; one active status iff that pointer is nonnull. Deleted flag, if present, is boolean; deleted means no active pointer and every version revoked in the **final** image. Validate structural pointers in unflushed state too, but do not require a not-yet-overlaid deletion fact already to be reflected there.
- Separate version order is a map of valid secret IDs to arrays of valid version-ID strings. Preserve complete arrays, duplicates and historical entries for absent versions; never sort/deduplicate/renumber. `version_index_from_order` uses last occurrence and one-based position. Every present version has a usable index. Complete-cut equality additionally rejects any array not actually produced by that history. General shape validation must not redefine legacy last-occurrence semantics as a bijection.
- Connection key equals its `id` and passes existing connection-name validation. Status is active/disabled; known policy/description/secret selector fields must have the shapes produced by `build_connection_fields`, reusing the existing **pure** builder/validators, not reimplementing HTTP/SSH/CLI policy. Created/updated timestamps are strings for this finite from-genesis class. Referenced secret exists; nonnull explicit version pin resolves to a present version with its real order index. Unknown pin is an error, never coerced to follow-active. A pin to retired/revoked/deleted data remains unusable; it does not reactivate it. Null follow-active may have no current usable selection. Validate both active and disabled entries structurally. No opening `ca_file`, CLI execution or secret lookup.
- Settings known values use the current `settings.update` validator and canonical folded representation. Preserve legacy numeric behavior rather than convert through a new integer/float policy. Fields not generated in this complete class cannot be justified merely by sender attestation.

For every put, compare original immutable kind/generation/nonce/ciphertext/public against the produced version, retaining op identity and order. Different content at an already used version ID is a contradiction, not a last-writer choice. Original duplicate puts that ordinary fold skips are outside this minimal class. An M1 tombstoned put **inserts its ciphertext/version-order entry before returning `secret_deleted`**; that effect must remain. No-version deletion facts remain in the hash-keyed fact map even when reapply creates no secret entry.

## 6. Complete fold, unflushed image and final overlay

Use existing `new_document`, `RemovalSchedule`, `apply_op`, pending flush and `reapply_facts`. Extend a narrow pure shared fold entry to expose observations, not a second hand-coded op interpreter. All complete original commits are folded from true genesis with all authenticated candidate facts in the provisional working set. This is a genuine complete supplied history, never an empty fake prefix for gapped retained data. Ordinary original order is numeric `(HLC.wall,HLC.counter,author)`, then array op order; signed spelling and arbitrary-precision numeric values stay intact.

The unflushed image is exactly the existing `fold_scheduled` checkpoint **after all original ops and before remaining pending removals/final reapply**. Facts already influence op guards; it is not generally a fact-free fold. Commit-derived disable/revoke effects accumulated by handlers remain included. Compare the full unflushed document, complete order arrays and covered vector with the supplied snapshot. Do not compare only authority projection. Do not replay covered data on the snapshot. After validation, flush pending removals and reapply the complete working facts once via shared existing code; validate final relationships and compare `SHA256(C(final_document))` to both signed expected claims. Final ownership/members/DEK, original bytes and version order must agree with the complete computation.

Every skipped authority op fails. For data ops, permit only the existing monotone fact refusals `secret_deleted` (put/status/activate) and `version_revoked` (status/activate) after the normal author/schema guards, preserving any prior mutation such as the put insertion. All other skipped data ops are an explicit finite `ScopeUnsupported` unless their cause is a stronger authority/fact contradiction, which keeps that error. This does not weaken ordinary behavior or certify all historical conflict cases. It permits meaningful M1 deletion positives while keeping an auditable finite class. Record allowed skips in the private trace and literal oracle; do not report them as successful activations. Full M2's broader no-skipped-operation obligation remains open.

A snapshot accepted at M2b.1 can have an invented final digest, ciphertext or data policy consistent with its limited authority projection. New inner negatives must repair all outer bytes/counts/component/raw/chunk hashes and validly sign the manifest, so M2a succeeds and the new inner equality/overlay check fails. Rehashing the sender image alone is insufficient.

Generation analysis here is public only: list referenced generations, applied source selectors and the union required by all active/staged versions of nondeleted secrets, independent of local grants. Verify semantic references and exact original selected/effective wraps. No unwrap, private key, KMS, AEAD decryption, derived credentials or key availability claim. A missing required usable key still belongs to M2b.3; candidate success is explicitly compatible with later key failure. Do not invoke `derive_local` as an oracle.

## 7. Errors, resource ownership and stack boundary

Reuse the existing closed `SemanticError`; do not add peer text, dynamic detail strings or new error schema. Map: changed manifest/payload/local binding to `Checkpoint(BindingMismatch)`; original schema/signature/integrity to current exact errors; gapped supplied sequences or missing original witness/placement to `HistoryProofUnavailable`; unsupported removal topology/unsupported nonauthority skip to `ScopeUnsupported`; invalid role or skipped authority to `AuthorityUnproven`; wrong fact kind/target/basis or contradictory head/bound/link to `FactContradicted`; document/order/schedule/digest disagreements to `SemanticMismatch`; original local eligibility/deny/collision failures preserve their existing mapping. A failure does not return partial candidates, filtered sets or a preferred repair.

Keep M2a's caps: 64 KiB manifest, 16 MiB decoded payload, 256 devices, combined 65,536 commit/fact/version count and total original JSON depth 64. No new wire/feature/dependency/canonical helpers. Large numbers are compared with `PyInt`; absence is not zero except the existing witness `seen[target]` rule. Preserve legacy nonfinite/numeric/private-name behavior only where existing parser/validator permits it; canonical operations use the existing helper. No custom codec, unsafe, process-global stack changes or bigger worker stacks to hide production recursion.

Bound indexes by observed record/op counts and input bytes. Index original hashes, author slots, fact-target groups, earliest witness links and operation locations once. Reuse borrowed original spans; do not store a full document at every op. Store compact role intervals and pre-cut/placing observations (bounded by fact/device/op counts), at most the bounded original materialization plus working image and one unflushed/final image at a time. Release temporary clones before making the candidate. If safe existing Value clone/canonical/drop operations cannot meet the required stack bound, report that concrete dependency; do not edit frozen parser/numeric code as a shortcut.

Mandatory future isolated evidence: success, late error after materialization, repeated call and **drop** on a 256 KiB thread stack at total depth 64, plus depth 65 refusal before semantic allocation, in debug and release on Linux and native macOS. Include deeply nested legacy public/policy values and originals at maximum ancestor depth, not just shallow manifests. Measure peak RSS and elapsed semantic work for maximum reachable bounded records, large snapshots and witness distributions, with actual platform/source/limits. Payload size is not an RSS cap; current legacy fold scans may remain expensive. Report measured behavior and complexity, never claim DOS-1 is closed or runtime queue/deadline enforcement exists here.

## 8. Test oracle and new fixture contract

Create a separate `team_checkpoint_m2b2_v1` fixture family and separate builder. Existing M2a 145 checksum entries and M2b.1 149 entries were byte-verified as data, with no mismatch. Their meanings stay frozen. In particular P1/P2/P3/P6 omit a data slot and are valid limited-stage examples; new API must return missing history for those exact gapped payloads. P4 is commit-only removal with a removed author's historical tombstone; P5 checks intra-commit role order. The new family may reuse **copied exact signed originals as data**, but cannot regenerate or alter old fixture directories/builder.

Three independent expectations are required: (1) hand-written literal per-op role/owner/skip/removal-bound tables and final data/order/fact identities; (2) existing ordinary `fold` on complete uncompacted history, with existing M1 fact application and no new semantic entry used as its oracle; (3) literal canonical files, original signatures/hashes and independently calculated sorted-hash digest plus actual `tombstone_gate::digest`. A shared-handler oracle alone is correlated, hence mandatory literal tables. For unflushed expected state, include a literal canonical image and use the ordinary existing snapshot/prefix path in synthetic isolated test state where needed, never the candidate output as expected data.

The implementation brief fixes the finite new paths and enumerates cases. Essential positives: nonowner admin, new owner with old owner historical facts, later demotion/commit-only removal, independent other-author removals and same-author earliest witness, self placement, same-commit op order, equal-HLC pending order, pending after head, multiple independent removers/minimum bound, same-ID and no-version deletions, ciphertext/order preserved under restrictive skips, policy/pin/order relationships and numeric/depth compatibility. Essential refusals: repaired/signature-valid false digest/data image/order, missing/incorrect witness, skipped placing or rotation, mixed/reciprocal/cyclic/chain removal, author interval eliminated, target owner/not admitted, author head above bound/backdated commits, unknown removal linkage, bad selected/effective wrap and all old binding/local-restriction regressions. Missing historical knowledge is refused, not silently treated as false or true.

## 9. No side effects and future handoff

No production runtime caller or capability advertisement is allowed. Production signatures accept no `Context`, `StateDir`, path, file/network handle, audit sink, clock, private `DeviceKey`, KMS, receipt authority, installer or session. Pure failures/success/drop do not mutate facts, logs, mappings, vault, journal, recipient receipts, status or readiness. Synthetic test state for the independent ordinary oracle stays within assigned isolated scratch space. Source grep/call-graph review must establish inertness; a passing unit test cannot establish deployment safety.

Only the controller assigns synthetic-only Linux/native runners and collects source-bound evidence. Native is currently reserved to the service task; this design/worker must not borrow or poll it. The ready worker is requested as **actual gpt-6.1-sol, ultra**, not a prompt role alias or silent fallback to a cloud default model. If unavailable, report unavailable rather than substitute. No worker/Opus was launched here. The implementation brief authorizes no push/merge/deploy/permissions, no trusted coordinator checkout changes and no runtime administration.

## 10. Evidence limits and unchanged gates

Each gap is independent:

1. This design executed no product code. Hash agreement and static reasoning are not tests or adversarial review.
2. M2b.1's exact 795babd Linux 107-step/1,735-test evidence is not evidence for current 9e composition or future changed code. Its native outcome remains NOT RUN.
3. Current composition's Linux run is pending elsewhere, unqueried. Even eventual success would not test the future M2b.2a diff.
4. Historical Personal Vault/M1 reports include later 63d2 isolated Linux/native corrections; the original 8258 two native pairing failures remain original evidence. Exact tested trees, not similar file names, govern applicability. Neither result accepts the current Rust composition.
5. New focused/oracle/debug/release/stack/resource tests have not been implemented or run. Future Linux and native full `rust/verify.sh` are mandatory. Unassigned native means bounded verification incomplete, not waived.
6. Key availability and ciphertext authenticity/usable synthetic plaintext are unproved here, irrespective of public wrap equality.
7. Durable approvals, transport deadlines/budgets/READY, compaction/continuation, install recovery/epochs and recipient receipts/ACK/status are absent. No crash-safety or concurrent reader claim follows from a pure library.
8. Physical two-Mac, direct/forced TURN TLS with UDP blocked, service/deployment/packaging/capacity and native release evidence are separate gates. No environment was contacted.
9. No current-head Opus review, recheck or Astra acceptance was performed. The interrupted newer Opus run remains interrupted; this is not its retry or substitute.

Canonical originals are preserved byte-for-byte. The completed ca01275 actual Claude Opus 5.5 report remains its bounded **REVISE** record, not a verdict on this source/design. `ZPLINK-OPUS-01` medium and `-02` low remain RESOLVED for their original scenarios; `-03` low remains OPEN with `-03-R1` rotation crash consistency. `ZPL-SEC-01/02/04` low remain RESOLVED for their original scenarios, `ZPL-SEC-03` low remains INSUFFICIENT_EVIDENCE. New `ZPLINK-OPUS-04..10` remain low; `-11` retains the source JSON nit / Markdown NIT/LOW representation. **DOS-1 original HIGH remains OPEN** (canonical status OPEN_NOT_FIXED_PARTIALLY_MITIGATED); residual assessment is not a severity downgrade. No IDs are invented for M2b.2. Canonical report SHA256: JSON `81e95b6a3665607b510f0cc77ab5cdd27bf78ed71f4688faaa94acb8a3e50c90`, Markdown `63c400a776a51ddbc58a1c33d2a6260a9ef78421044a8a1514d79053d30a381a`.

| Gate | Status and remaining obligation |
| --- | --- |
| M2-G01 | **OPEN** — exact-head M1 integration, original complete tombstones, historical admission and durable session ACK/runtime behavior |
| M2-G02 | **OPEN** — full retained original/authority/removal classes, device consistency and exact-head full integration; finite candidate is insufficient |
| M2-G03 | **OPEN** — general historical admission/removal contradictions, gapped final overlay and all original irreversible facts; only bounded subset proposed |
| M2-G04 | **OPEN** — future compaction witnesses/heads, exact floors and continuation/history-required refusal |
| M2-G05 | **OPEN** — required DEKs, valid decryptable recipient wraps and currently usable ciphertext verification |
| M2-G06 | **OPEN** — persisted two-sided approvals, exactly-once admission, authenticated raw transport/capabilities/budgets/deadlines |
| M2-G07 | **OPEN** — fresh challenged READY and locked exact cut/approval/revocation checks |
| M2-G08 | **OPEN** — fresh-state eligibility at publication, journal/fsync/recovery and coherent epoch at reads and credential use |
| M2-G09 | **OPEN** — durable provenance before local receipt/ACK/activation, restart/compaction retention and downgrade boundary |
| M2-G10 | **OPEN** — exact-head isolated Linux/native, complete signed/compacted acceptance, crash/concurrency, native/physical two-Mac/direct/TURN and actual Opus review |

All key availability, runtime and release gates remain **OPEN**. This decision does not close any finding, accept the PR stack or label checkpoint onboarding supported.

## 11. Exact semantic inspection scope and omissions

Line ranges refer only to HEAD 9e76a1d. All paths below are relative to that checkout. Full-file lengths are noted where useful; lines beyond listed ranges were not semantically inspected, even though every file was hashed.

| Files | Semantic inspection |
| --- | --- |
| `AGENTS.md`; `docs/product-intent.md`; `docs/security-design.md`; `docs/harness.md`; `harness/README.md`; `rust/PORTING.md` | Full files, including current operating decision and PORTING §1 |
| `docs/remote-sync-next-milestones.md`; `docs/whole-secret-deletion.md` | Full M1/M2 contract, all acceptance/continuation/installation sections |
| `docs/decisions/m2a-schema-2026-11-07/{README.md,decision.md,implementation-task.md,parser-compatibility-revision.md,revised-implementation-task.md}` | Full contents; decision 1–970, initial task 1–326, revision 1–408, revised task 1–335 |
| `docs/decisions/m2b-admission-2026-11-07/{decision.md,implementation-task.md}` | Full 1–271 / 1–188; removal algorithm and final overlay clauses reread |
| `docs/evidence/2026-11-07-m1-source/REPORT.md`; `2026-11-07-m1-personal-vault-63d2e4d/{README.md,REPORT.md,combined-protected-boundaries.json}`; `2026-11-07-m2a-7bcecfd/REPORT.md`; `2026-11-07-m2b1-795babd/{README.md,REPORT.md,STATIC-COLLECTION.md,final-head.json}` | Source-bound reports read as data, not reexecuted; all under `docs/evidence/` |
| `docs/reviews/2026-11-07-link-ca01275-opus/README.md`; `docs/evidence/2026-11-07-link-3eb-review-interrupted/README.md`; canonical `report.json` | READMEs full; JSON original statuses/DOS/new-ID severities/verdict selected as data. Original code/evidence claims not rechecked. `report.md` hash-only here. |
| `rust/src/team/checkpoint/admission.rs`; `mod.rs`; `payload.rs`; `provenance.rs` | Full 1–974 / 1–133 / 1–558 / 1–82 |
| `rust/src/team/checkpoint/manifest.rs`; `strict_json.rs` | Manifest 1–270; strict JSON 1–70 and 1530–1624 (span/index/materialization boundary). Remaining parser/manifest implementation not re-reviewed; frozen tests/design govern unchanged contract. |
| `rust/src/team/fold.rs` | 1–1447; 1480–1819; 1870–2017; 2026–2450; 2493–2650; 2670–2710; 2930–3087; 3360–3405; tests 4780–5282. Covers full removal scheduler, authority/data handlers, overlay, snapshot/refold/removal matching and order/pin derivation; intervening and remaining tests omitted. |
| `rust/src/team/sync.rs` | 2735–2860; 3320–3420; 4808–5385; 7322–7380; 7770–7935; 9170–9365 (to EOF where shorter). Covers full fact shape/signature/role/receipt/load admission, incoming reciprocal view and compact retention. Rest of transport/runtime not reviewed. |
| `rust/src/team/membership.rs` | 1208–1520: remove, linked rotation/repair path; remainder not reviewed |
| `rust/src/team/commit.rs` | 250–345; 785–812; 860–900; 1036–1934: HLC/order, signature, validation and pure policy builders. Constructors/storage and other tests not reviewed. |
| `rust/src/team/identity.rs`; `rust/src/team/tombstone_gate.rs`; `rust/src/tombstone.rs` | 80–180; full gate 1–205; full tombstone source 1–359. Identity remainder not reviewed. |
| `rust/src/vault.rs` | `SECRET_KINDS` line 57 located; no full vault review. Required-generation contract also grounded in prior M2b decision §8; no key-bearing path executed. |
| `rust/tests/team_checkpoint_admission.rs`; `team_checkpoint_authority_oracle.rs`; `common/team_checkpoint_semantics.rs` | Full 1–1388 / 1–264 / 1–614 |
| `rust/tests/team_membership_sync.rs`; `whole_secret_tombstone.rs` | 425–523; 188–308. Other M1 test names searched, not whole-file reviewed. |
| `rust/tests/fixtures/team_checkpoint_semantics_v1` | README full; history/facts/literal trace/expected data across P1,P2,P3,P4,P5,P6-empty,P6-nonempty inspected as JSON data, with P3–P5 reread using field projections after output truncation. Payload structure/retained subsets observed; all 149 SHA256SUMS entries checked. Signature/ciphertext strings hashed/read as synthetic fixture data, never verified/decrypted by execution. |
| `rust/tests/fixtures/team_checkpoint_v1` | All 145 SHA256SUMS entries checked; no new full semantic inspection of every fixture. Existing parser tests and builder were read only where included above. |
| `rust/verify.sh` | Full script read as text to confirm auto-discovered integration targets; not run |

Omissions: no full Rust audit, desktop/adoption code audit, service code audit, exhaustive current fixture cryptographic verification, legacy numeric/parser implementation review, dependency execution, historical logs revalidation, active runner inspection or external source lookup. Attempted nonexistent-path reads and truncated outputs were not treated as completed source inspection; necessary semantic sections were reread. Any future implementation touching a source dependency outside the finite allowlist must return that dependency to the controller rather than expand this task.

# Appendix A — complete immutable input inventory

Initial inspection: all 1122 tracked files equal their HEAD blob bytes; executable-bit equality holds. No tracked/untracked changes. Inventory is hashing, not semantic review. Columns: path, Git mode, Git blob SHA-1, SHA-256, bytes, actual POSIX mode. Inventory TSV SHA-256: `816c1e7c33ca3160350919aae7045ec1b79a27703a76dce8a6063b1d0b59aaf0`.

```text
.github/workflows/harness-ci.yml	100644	d54660221db46b9eada937672e034e4159694a7d	307bd902f26ed7ce59019884e94584315f2de789d7ad7563c1b263fdc75f8ab3	3782	0o644
.github/workflows/self-hosted-verification.yml	100644	a9a8f8b4b37119e9e82e4267be2d62df1e29e5a1	efe7037fa3e85ba2baa2c2c5a355e76f5d72e4ac7b9977ec1a89a2e1d1ec22ea	3293	0o644
.gitignore	100644	0b94635e1d076d8f2c04a5d6ffaae551274e179e	f47755350064caf7c6e9839a4d4496f9827fdf23e0ea2569e682338276e7394e	139	0o644
AGENTS.md	100644	6b3b75e3dd1b39e7d90ac7dff6be5d49c70f1f30	08c4fbc5a439a1344d3ad309455483f3aa755438bbd626062256469d8f508b93	3921	0o644
CONTRIBUTING.md	100644	098805fd2f7cf0ab39bc9c804fa369fa122aab2f	fe319c1a5d9bbba386b42d673d8c913374cbdfa57fd786ccdb6469f22326fbaa	2545	0o644
DESIGN.md	100644	10bb6905d5ceaa28af48fcc0320bb31356012d39	62dfa30c15a8c33a0a08f4e86ca51d96a62bbeed843fecdcd5cd8305114099b5	14275	0o644
Formula/zeropw.rb	100644	3bff81376f08878bf2b0e7724009b6d355fb2843	1cc8493ac6964201eac9778ba591e285ddf8637926741aa475a43078c11830b6	1754	0o644
GUIDE.md	100644	366452fb60e6cbe69a87374b74d00cf72aa71531	150d042764065c4ab4f507ae162a0d1d8eda5bc73a4f492193595d00c37b2d83	13696	0o644
LICENSE	100644	2866aa72296cd7f36a951ed25eb7e28af192d24d	14ec2569c0a96d2091a4b2ca47681f41ecd06d4998ad3f385aadc740406b2b62	1076	0o644
README-ko.md	100644	9e1bf051504cb1cf059e56bc81df3001f88666cc	6354c72455c860a6f08d170cb36f7e2d4d28e3c536795d52903df51562805070	17397	0o644
README.md	100644	9668dbed9750f29077fe4df7febd5082427e7900	37e6d1d54520dd41d9372ba967a04fc8e62e726eb3e9b9e5d1ca29e38b3d9294	16331	0o644
SECURITY.md	100644	7fc6948c68a280db84f875650cb2822a21748a70	a23cb6b35964bc5b8453ba64ddf9927631bd09202ee15f7476ba5e79267b1129	2120	0o644
desktop/.gitignore	100644	2060e072c7aa0881bbd792c4d06d2e413d034387	262dbdd90688d206df71676d5f458444bc0dde1f0a0fbd69adc0ee60d11437df	137	0o644
desktop/Cargo.lock	100644	be7bcbb60c6ba0ec8bff37190aa7a70cceaa8de4	8e2001dd9ab8bca2b977e017aad82c36409567e2813d15b7e64a40f81e115f7a	139306	0o644
desktop/Cargo.toml	100644	caa2289bd3ddc7db2f395fd972deec95b3e27014	d2b6ce371237d8167cbb46b8a603f961ee657f92c8c7e3625c9e777a34454cca	329	0o644
desktop/core/Cargo.toml	100644	c00a1cd3ad0296b685f1521e03df736483d31871	5f036d6bc11eea18621d086466b6fc14982712fcf5398302967a97942040e589	870	0o644
desktop/core/src/admin.rs	100644	32535c9ef0bb608167a1e34b4293acd6b85392cd	1e2c8067b009c92b3aff8dc0542b7e6e5a11c688817409a03213d94cf33aa98f	22378	0o644
desktop/core/src/commands.rs	100644	c9f7f6c98838d92146819f42f5f8f6f74c559a06	def223f709c129cb118745d76522b96537e9f38e86a687335d79fc1b5d98f14d	92058	0o644
desktop/core/src/commands/remote.rs	100644	3a2e2b3b6807ea4db36b7a4632500e1f35c81191	209c16cffcffe7140b876f0610d2b689ffa36b984ef97f6bd0044d1efe85e590	50216	0o644
desktop/core/src/devices.rs	100644	4a4cbe66c316593b74752335493a3cc47f379410	778973bd0342bcc52a00d16f245bbc76e804e629cfeeb0a9359e819fe093d859	14554	0o644
desktop/core/src/error.rs	100644	8ad59edba424673455a33eca4eacceac96e96342	0b249032e944d15d0beac4849d8a496c97aa311bbaefa7843e79a4cc5ae1842e	9418	0o644
desktop/core/src/hooks.rs	100644	1a8c0a5ba4e3a5fd5bf72419c1bae9d2d5371751	0bc7e80f251d128bcd5dbc0f0b49b0de35acb2510552f97087a6a674600711d0	7387	0o644
desktop/core/src/lib.rs	100644	41b6f7ee95141f6ca53b8f529de1ca9a9301d4c3	ae1a56e7235f63782aa3a6e7cea6294decdeee5b9af1b7ac74de1e7114673ee1	1756	0o644
desktop/core/src/link.rs	100644	ee9897d6dd6ec5d44e3993f406c9d02aa4630179	5c717af2966ae6da3dbaf05455dd8f0cb776a3bc5dc975a24b9c754d8887efb6	44677	0o644
desktop/core/src/netif.rs	100644	da6186e4ac5889127312dba4d9365166294ee8d4	b83a2b6b799da5229961ecd4d6ab18f774d27c1f97055871fef51ca857235035	4224	0o644
desktop/core/src/onetime.rs	100644	143f407d0fd9963cb80fbd76358e6c922e895eb5	09b5788031d0d25fa803450485e4bade111f308fc63eff22b08046127663dbfd	28853	0o644
desktop/core/src/pairing.rs	100644	7824ba9750ae09711d2ed136d9eb544fdcad864d	bcb81884523303a188c72775d18f5c26e0fad9a9451eb924c81a0674bf3ddaa6	13127	0o644
desktop/core/src/paths.rs	100644	9c93d1906053e5050c7b9d4955705c2019b249a8	f1a25149ebcfc05f59fe34844b713afdf33f238a5fbd8f720d03fef6021c54c9	9258	0o644
desktop/core/src/recovery.rs	100644	ea750b59a90d7ffb1912bd647e693aa46fac8ac0	9cacd800cc663daff8e999c8e93aa22d511ed3b32520e8f5051a7272aa80e512	5448	0o644
desktop/core/src/secret.rs	100644	496fdeadd8ab4da5eadf2f1a7c03698b10effce2	74085bfd6b3a7f7cfe238808b6ae9e22a61340bd81f3241b19dcaf13740fc1db	3421	0o644
desktop/core/src/serve.rs	100644	0f8ad4d086217afbf63654223be66dfe3a8ab6bb	c53e0abdd5e78d90dd7c9499b0d28fe87950bf1a3007fefd00113baaca7fa53f	33505	0o644
desktop/core/src/settings.rs	100644	93b6c0e90bdac2da2ca881bf92b3b579338ad1af	4e37ef0e0b91a640774c337378ee927faae9d7171853a48be48aa0441fab1b62	9267	0o644
desktop/core/src/sshkey.rs	100644	6d652c65bba077e04334f9dbde6c71f30f6be3be	b3f2da7944c618c01645331d40eb7c68c361df091d85aa8132974266e73da8f9	8468	0o644
desktop/core/src/strength.rs	100644	c55322a75a28ddf86c717858d17c2d1f259769b9	15c90da8d49617daacc534cbbe1abfb34310e693ab4c09748413e8c0777d990f	4367	0o644
desktop/core/src/terminal.rs	100644	99533064e245a9ed8e7ab751fd99c23a609368b0	4d3eac8222c22ab82cefb332ded0884df98e22b67482e8aa5ca196c1fd724405	58982	0o644
desktop/core/tests/common/mod.rs	100644	19a52eb06cacc5ccd4678074d016c1edc732debf	6b8298b955bf5d30390ae3f67f95b2325238c18ec6a2086c7df8efc3089aac56	14747	0o644
desktop/core/tests/core_fake_admin.rs	100644	eae70e7fc7c2e2f0b0a8e227d7d618766f36a3be	ffebde34b8c19da57c3749696a16555bc604f948d9dad3b74fa2252fca47fd44	56056	0o644
desktop/core/tests/core_reauth_reattach.rs	100644	4a89f555d6790d638481a30647cd3ae709f56c70	11233baf2c0d0445cd253fe188f01e3e0b7f6c4db7c0f0ea4005637d3b37b455	21952	0o644
desktop/core/tests/e2e_env_import.rs	100644	5f3f199c8cd195c2f737d3004ffc7017fa42a661	cf2e58719832378ade0ff35d299cb8f49d985c13ff1554f83994e087eb8e8260	10456	0o644
desktop/core/tests/e2e_real_admin.rs	100644	5c88a0e0e3bfdcb2616b250069894964019768ce	f75c09a0dae10e020d1c0d96468969029d21f8eb2eac4018c528a1f240a043f7	31122	0o644
desktop/core/tests/e2e_remote_pairing.rs	100644	b604396ae2d850e4891ca21608b08622eef74e11	666bac22e908314ce867db798a6b70b13fa2242524fab53e12818bdc216f1fbc	28644	0o644
desktop/core/tests/fixtures/fake-zeropw-admin.sh	100755	4a078bf94e14885394291649da17e7812a68c7a9	c93f3240913cd574d0901ba22f54910e9db18c5e6852f00e940a547672ad4f15	4650	0o755
desktop/core/tests/link_supervisor.rs	100644	689bc8802a3f376266697bb63e892967490f8f2f	b6497e1c5d1982c562d9a886b438c395fea61046a6f2e2a4dad4757ff90a89ca	10551	0o644
desktop/core/tests/remote_sync.rs	100644	c72c4680cf560b3d1c24668303a47e7e443a3e20	b2cce3055882fb160438e2913a830aedca273a92dd4f32d0a17e296b4e1b07de	43946	0o644
desktop/core/tests/serve_supervisor.rs	100644	3f175fbc6058b69d32442381e265e4b6b7b3ca61	4be01e9a703cf013477f13f5da81da0ca420ed444c9848f468708043e80a05f6	19260	0o644
desktop/core/tests/terminal_close_leak.rs	100644	343c618c944ab15fb06adfd209eabd84f54102e8	521102481bc4e0ba70dc55df35013e7a765c85bce904e11d449a624deb02c4d5	3672	0o644
desktop/core/tests/terminal_pty.rs	100644	53627fef8051a90c2edfb7326945c71b1f5a7faa	16e5192b6b68fbdaeeb8fde4a12e3b6fbac283a03dd2c57ba12785cc19f5c72e	26261	0o644
desktop/index.html	100644	dbf5e0657b524e4431430180fd3b1efebca29df1	d31309f2165a23012907db9029195eb543e72b63e953a087420b140f12ee7390	339	0o644
desktop/licenses/MIT.txt	100644	9cf106272ac3b56b0c4c80218e8fc10a664ca5f4	508a77d2e7b51d98adeed32648ad124b7b30241a8e70b2e72c99f92d8e5874d1	1036	0o644
desktop/licenses/MPL-2.0.txt	100644	14e2f777f6c395e7e04ab4aa306bbcc4b0c1120e	fab3dd6bdab226f1c08630b1dd917e11fcb4ec5e1e020e2c16f83a0a13863e85	16726	0o644
desktop/licenses/es-module-shims-LICENSE-2d7ce60c.txt	100644	e67426b5f4157427f0e5ab00547c0b726c5b56bf	13dc18f97f767475f7ad48fdd12a2e45be30fb309c604730f406f625cf7d8f7f	1085	0o644
desktop/licenses/pretendard-LICENSE-0189074f.txt	100644	160421b6039671e5c85e1646bee4167844a5d69c	82e9c8a4b203261f10ddba1296422d64914ff3d4b7bd8a12896d03f0f088d70a	4816	0o644
desktop/licenses/supplement.json	100644	368333624bda77f6f7ab56ef73b9935da6924ae4	cecba325fa08990079da614f05d3f7a44dad4910b57e9c0ec1c5e6f67465d42d	12230	0o644
desktop/package-lock.json	100644	7380e583f1bcf505fbf932968622f20cca343705	371553acf4d4e68aec5577d0bf0c95991cf9e907e34658f8d8119c89e7de2d2f	69457	0o644
desktop/package.json	100644	ebdb14d775a110bac72bb9b4a730a69f18bd1ab4	f6508027e1f9b4625427855c929206a41877e990e4f9542121219f829a321e8c	899	0o644
desktop/scripts/build-link-sidecar.py	100644	a1fdc9be8bb1cc1750de41bd80660eccea568e37	99925eaea639935d0f3329d13664edf6d32d6d162e4f89d6c540e40197906e0b	15979	0o644
desktop/scripts/check-static.mjs	100644	809befbb49b60d1d62015121881088d0f4054082	60f15748dbd0b5cd377facda7573015c607de87e7e334b950546735f7e3428eb	3150	0o644
desktop/scripts/check-tauri.mjs	100644	1dbbc43d8aa291a9def50c548add3c474e110c7d	020b137b278bc9f725ca61883efc17e8d6e27609da9c9cb8e89410e8b43e2a75	22639	0o644
desktop/scripts/package-macos.py	100644	ba1aa8c46d3832f43603572a26a65f4ad81e70af	58261e70ae7d8276270458f77787e033308101de1d2a1d9699d229d6476fc7d4	33335	0o644
desktop/scripts/prepare-sidecars.sh	100755	2570538338a2820b8be74e201d04dd25d304593e	cb09bd068398296e1cbf0f16789a5f165a25a17f0b20bf29fbd3ac816e4d306d	3814	0o755
desktop/scripts/third-party-licenses.py	100644	876b228e5d903ee1875a0237ee44b9ab1291e2b3	9167ad1b317183b104dfa7700fdc822c7361be209f548ea5c3e1f9f0587dd24d	18594	0o644
desktop/src-tauri/Cargo.toml	100644	4dfe3a21652f3a373dac622559d59eaaf661caa8	92cc869bd352fadc9dcdee22a52c1bd54408e14ad12617726c1d7a9afe5edd20	1018	0o644
desktop/src-tauri/Info.release.plist	100644	211b300cadd571507c85e6d3375aef690227cdcf	16fd81f6167d87c00239900d2ca40f6d0560084655b691b4b8feb1c469a0d432	326	0o644
desktop/src-tauri/build.rs	100644	aeda447dda0ef74ed907ce565452a96ea6545a29	c3c0d63d7cc04f7a820c526245c335f9d448fdfb9c094ac8c4645231bbb6afc6	3270	0o644
desktop/src-tauri/build/png.rs	100644	ce52d3615ac7017578860d23b42ea08676ec887f	14dabd96cba31b3e31c55a876ee68b8cfad807e7e32cdff16cb2c21dcfb9dbaf	10549	0o644
desktop/src-tauri/capabilities/default.json	100644	9dd8f909a2d533727378d8efcdacd4b2459b6cdf	eb5f71f845136bb3d38bf2d279c233e697dff241e077470a647271e86bc1d84f	2578	0o644
desktop/src-tauri/src/commands.rs	100644	6bcf1ccb2209dab520e79865e65e580e229350d8	1edc14eabd73f70fe6d8be6f4384d59c67914d724204d6c78110a8c572beae8a	32251	0o644
desktop/src-tauri/src/deeplink.rs	100644	8a6c6f4a0bed0afc1d966577c282f0f1b3861fbb	f8b0a7102d2c100a62117206ad66d6ae4e7d1ef71c1f75c9062d446634c5103f	5356	0o644
desktop/src-tauri/src/freeze_prototype.js	100644	421bd661598493cc463554c004007b045e0983db	e0b56c8485efd606d684eaf68a43486c28a750eb7b190dea7bae39fc832e740e	1628	0o644
desktop/src-tauri/src/glue.rs	100644	0824570e295b07ff03133c6efad1a1583482740d	c2a6d11bb457cd2d0dcc36bc3f757a2aeee669e8bc9b857a2799c300d91b11f7	5061	0o644
desktop/src-tauri/src/main.rs	100644	286c6fff066ac4f1e52a698b60afda6a0d49e05a	0a80ab4ccc5dc5568979ab2f16473298da06d52c8d56ff413714d5affa009b02	789	0o644
desktop/src-tauri/src/shell.rs	100644	43340a5af96f121648dcf7956be96fe8c8aabc93	981f387d9e29c45c174ca45e2da0299b0e4082ef901feb31ce71be741c956fcc	14696	0o644
desktop/src-tauri/tauri.bundle.conf.json	100644	c167b56bfaa807e79015c4e2afc6c08103d40347	0b6f83b9299c05b57cddc16b16102c5bfe7de76ce13a5301ef7ea181a550216e	430	0o644
desktop/src-tauri/tauri.conf.json	100644	826593514ac2bb72e48eca1afefd6de83b8647bc	2d5a8edc7b650384ad7d0a81d0ddc97694761b48e87c926c39df6eb700390421	1430	0o644
desktop/src/app/App.tsx	100644	5f90802d3ba777aff533dca973368fff3a1e7bb1	2fdc0d28d91bae77257829875726a40b69e9f3673ddd50c6fe8df4475010bd14	8197	0o644
desktop/src/app/LockScreen.tsx	100644	4b5051a1d95dd43939cd93892856c931ae9c316a	af9662d5c576510df5fbe658806084422eae3eb1eb574dd50628505f892014e9	2509	0o644
desktop/src/app/OpenVault.tsx	100644	ed579d63584fa8d99241e87205526139df1fe9a1	0b409e0e3a4fe6c4470428cc38710989e8d4679a35637b1aec2d76b51472a599	12990	0o644
desktop/src/app/Sidebar.tsx	100644	175c011b0959a20996a118f558122fbd4463422b	dc741e0d3e859a4faeda9fc73cb274d0d093a1e2019ca213b7fd5e373f978791	6110	0o644
desktop/src/app/shell.ts	100644	0568c11eeed8741577423c8d5751e274468bef01	3a8dce62b82139e97403a3337ef636a236c3fd289f5e38c1f4f074130fea7320	3920	0o644
desktop/src/copy/activity.ts	100644	523659d2f7988bf4384509df0a0b576e29cedacc	7438c4afda270d8d1af4423097a8544603dd3afad4fa93bf2eb0050837592225	8142	0o644
desktop/src/copy/backend.ts	100644	7906cc65f0c16a1f0e5c72e64d42788ec9c90653	f986651b9e146a9acd7b67e03bcf90943f97f094c49d0f1cdba14de9dc582b62	35767	0o644
desktop/src/copy/common.ts	100644	d10d710dcd17daf7c08d4ca8120b5d5c15f9bb8d	4ceade7d031b135428e331c7cffe302ae7c9eaf37d88161368884c2a35f57b53	10471	0o644
desktop/src/copy/developer.ts	100644	eff67ad139a4775192da8b2b8d2b8580af89d397	9317e89c3f1cd59557c7a7d5610b3500e2a9a49db0a94fd909c298a54d9788ed	26740	0o644
desktop/src/copy/devices.ts	100644	7fe51de5ab7d582b940f2e23a71e9cb7bdadd25c	68a3ecb5afb1d88666cc3214ee7660fc53cfe05aa2f6dfb69d363f151596c949	16489	0o644
desktop/src/copy/index.ts	100644	6dc747783354c7b14403e65e73fbb192575fd662	84b6100c1a7903d495c1cd8be5103759ebe55d24e6d6fa8b3333b2aadd7a3d1e	3640	0o644
desktop/src/copy/onboarding.ts	100644	240d08a6932b9be27530563eee8d59374ad4c491	fc4c593ec3d92309fd2472526472b12597f82c13d82193c5a0687dd3f4f21f34	10780	0o644
desktop/src/copy/services.ts	100644	7b3612de870edb9d58df62549725a9503bd18d7c	c46a9f5f4d3f68c42093a2c1ae82edd4bac19bf29443df577ec303b62256c798	19083	0o644
desktop/src/copy/settings.ts	100644	bbb60ce6d28eaa79cacce3997ad291e63e50dc1c	eec51509c07302030fc61d833c0933141a79e21a486babf8274e5ac05ddb8786	19489	0o644
desktop/src/copy/types.ts	100644	d70facad2342a5f7ae33385e3c9f8664ff910d6d	305984103d33129cf4f1cfc5c8ea51e4ea990b705867f69652ef2cefcd74cb02	159	0o644
desktop/src/copy/vault.ts	100644	8146c7ece0d8e9b6b8b04bd7b521a414df12e0e6	b7646b6bf9e45c3b19f96f03cf3fc283219ccdcb60e6b844f8a08e17bd2c316b	20754	0o644
desktop/src/ipc/client.ts	100644	e5160132c2d34cfb0e6a2b95f5ef63d912d71921	e4dc0bfdec1bc68f45976cfa8991d259b79f8dc484b93df0d07a1eb2cd1ab3f8	6051	0o644
desktop/src/ipc/contract.ts	100644	0967279205bd72e4457a165542df562795293a9f	9b558c8d2ede1199f4c93a951b154f841920e3e03b9cf0d36766638b4407654e	22172	0o644
desktop/src/ipc/events.ts	100644	c74ec546d102dd7282863b3bd60d60d3deca3066	a6e0cb6cff916fd5a721f3ba8029fa3db56752bc8d9b7d86b03fd87e9249c975	1202	0o644
desktop/src/ipc/mock.ts	100644	3cfebd1e2f660639223ae05bb1525bb5a83ca6e2	2c5069204214a07cb1a031576e2d83ce09e1ad604b91a923969a37314a584f0d	98428	0o644
desktop/src/lib/dash.ts	100644	1e5f1201002b48fae54d22e58b86e376d99c9daf	874434c8c4455d99ee2a5527dcaf582c132693fed2083c3dca529cb96a91182d	26528	0o644
desktop/src/lib/devices.ts	100644	f2a0401efecce673fce27d07e21d0cea9ddb280f	7d8e3fbae97625323005601bed4644fd7a3f953bd0789065e1990d4b9c4af477	6665	0o644
desktop/src/lib/envimport.ts	100644	aae38f4931074e57d528606c27f4de303688301f	6feae8c50fdb0bc4dc91d6a85e2cfb4498e74006c5e408f822743c68827414e2	5231	0o644
desktop/src/lib/format.ts	100644	760ef9ea3b2a29c8e7707f7ce9f3c655649a5593	8d5e339323ddb1a74ee8d7d28d788c9d52fe3b52dc8c5daa5b335b969534d8ab	666	0o644
desktop/src/lib/invite.ts	100644	00dce2e00838372e2d7382dbdcab41e403a4b560	97a5228dadc1933a89a960a9d1c5704c49934d840848e1d7b087b100133139c7	1374	0o644
desktop/src/lib/invitePreview.ts	100644	2ea1539c96627b00a6f7c14b7c35c94f50a079aa	b1d036e61730fdd53df3b5fe5ca6dc900878570bbde5892a32d39ab8436b2eb6	913	0o644
desktop/src/lib/pairing.ts	100644	eb937db580cd4630b5a554f14c1fc361c7cf7469	8b3c406cf96565c6c3fa7c0cf33948dfe0ec3b22d6e1987e19bb17739dbd5282	7937	0o644
desktop/src/lib/pendingInvite.ts	100644	72aa476201346e12edda2845bfed0320fae23f5e	53d3885681348dd7e9d5e723c3fe865aab4924a9cb16e012b0e16ba08152246c	717	0o644
desktop/src/lib/places.ts	100644	f1dad018e3ab6d44a1e9998fa7f2681bed9a8369	8cfd7c6d3330ba03d40a67aeed0a7645df9efb469af3626a625ec5ed309d46c4	614	0o644
desktop/src/lib/poll.ts	100644	3c6d433c59dbc271c0c553dc6bc1b6db5d07540e	808d3db4315fd283a94938dc88fc9197c0b4ce0e6172206448629a575c93627f	2747	0o644
desktop/src/lib/reasons.ts	100644	a7ad2ec52235850c8e65b379c0ff002222eb248b	56a59e18cb1c72db72203d52e955788bdd635b86262b5306802cb1e7979dca6b	7667	0o644
desktop/src/lib/records.ts	100644	034f052d133e91e04a012195f598ba534bfdd014	9babe5e48d54471072669ed53d28299d4fe9c0df4b34771ad6bd1c4675e800d9	17955	0o644
desktop/src/lib/relay.ts	100644	322cbe363c592ca81f454e2879824a7ad3a3cd31	d53edfd8c8bc153d329c7aaf63b03c7d876abb8c3e8f5f444ea252da5db495f1	6177	0o644
desktop/src/lib/rng.ts	100644	936b3bc01f81459c5f585c6ae6e0a9a9e37540f8	9b4e6c8a07995596cd8e4bfeb642ab962bee42d1ebeb29b6f347260a5019ad92	741	0o644
desktop/src/lib/validators.ts	100644	317d3c9cda07a9b4f13c15556681708b41f79912	dfc3d84196e07309acaeda7c1663cb1f3211b8b0a8ca2bf09e16e9c90fd7f9d5	7837	0o644
desktop/src/lib/watch.ts	100644	65245c3f28a67638bb6dd1957d690cf6a6b8594c	542d2ecd683100f991cf909dd28b8a41eef65e3e596743bcd96c1a075b818545	1963	0o644
desktop/src/main.tsx	100644	5591720633881756e83c3c35bf20a9c4dddc44a7	34a0f724d254157c0472f41b2d541298157de71969e09e3dda7057eee77350f1	531	0o644
desktop/src/screens/activity/ActivityPage.tsx	100644	fe7730b5e8919ce1da9efc5b9aa6cc71b425fcd9	61c33a97185f742c20b7169b049c3e2ff1ba2f1eb79a9e6d87e434cc0e99ef8f	12577	0o644
desktop/src/screens/activity/DeclareDialog.tsx	100644	dca039a99ac87ab6d2a08cecb4510d759cbd9957	bf1e2581dc2c9a584954d5d9b387fe0c6d5440a38728b94ec83a48153b9e6568	7895	0o644
desktop/src/screens/developer/AgentsTab.tsx	100644	8e82ff1cd72eb08d7d98d9e38a0f6952b31bcce0	b3f2b8e6f514a36fdb6e0bade58d7bf126ed8b0f51e3216d363ecc3140999760	22182	0o644
desktop/src/screens/developer/ApprovalsTab.tsx	100644	f5c83f9d3e702544d5ac707561f9350165b067d6	9570bfa4ba855828c00621967e8ea65f679f5c838b9bc33f0a0a1dacb8a271a5	4354	0o644
desktop/src/screens/developer/Choice.tsx	100644	8eb4b566c4238c26cdd5a162038933798896d89b	68a6cec0aff8c60f02f8e583c96bfb2f10d71f904a40a727278e1c167942de82	1247	0o644
desktop/src/screens/developer/DeveloperPage.tsx	100644	9dd69169195f6040b3c521c4305f489d54742726	b6e9d7227325fc581b5cb633d759d5fde1f1d660770bbaf97e32ff6e309b8a5d	2387	0o644
desktop/src/screens/developer/ListenSetup.tsx	100644	71570ff3922e7fb3121066a17dae24ac93dd0122	15f813c2772d605a2eea91135fe54652429feaf74e3220a2c5ba1c1d07d43ea0	4193	0o644
desktop/src/screens/developer/SharingTab.tsx	100644	866d010d7255a6b8760a1f3b07a00f8b6709be18	e9083cfe2818247cf328c88da6d1986185a1ea4bb1e5fed5f9eabad243b0d737	37470	0o644
desktop/src/screens/developer/common.ts	100644	28d2adc248ebad0efbc29a7a4ff6b585d9d03173	77dc4cb9a37ff8c2767c8f11280baf30775666c5fcaf5ae6dbd45094d1db20e5	1918	0o644
desktop/src/screens/devices/AddMacDialog.tsx	100644	c9ace97627c7569ccf391d917faf7f24f6ba223c	216a97ee9d663017111f0b06c6233efcafb31f2ea68aea0bbaa8f92592afc1af	11721	0o644
desktop/src/screens/devices/ConnectMenu.tsx	100644	ce8316a0ebb499274cbbdb9c0804f8535fd53c15	56405fb54295c0683e14b5463139752b0eb1b20f916b26f93e1cb52a54640402	2812	0o644
desktop/src/screens/devices/DevicesPage.tsx	100644	c68cb14210054a8cb0b0099af6d214c0ac426780	61a6f1b3d39c0b6cfd7c844a6cf610aff87e61909bfdab24c34553c57686dbd3	15466	0o644
desktop/src/screens/devices/EnrollCard.tsx	100644	018a1cea35734800aec42c4f288d6aa31243c479	57280d8d8d465318ca9b114f8b8da1e324263f1834c0efbe24a58dcd1b27bee6	3794	0o644
desktop/src/screens/devices/JoinMacDialog.tsx	100644	ecee29234c8ed96c244203d671dd816e8eda0658	8b0a8cd7e79e7d1e3b91dd86ddafe7bb977a08c7f1a7f289787f354249269c14	5370	0o644
desktop/src/screens/devices/states.ts	100644	823df4e6e34055f250629345a4d13da872c55684	a622bf31bb3224550d894c27efd5111a91ca25f2d540d9725c2d3908e474cf51	3182	0o644
desktop/src/screens/devices/usePairJoin.ts	100644	f21dcb1fd3ff6dbca70749ba6dc57cae4efcc3c2	ffdb0f2b0cd99cda7b8a3894f24b54a341fa8a8b4f699cf5b8d29797096c07dd	6170	0o644
desktop/src/screens/onboarding/Onboarding.tsx	100644	a845b853739ecda2fc5af6b2d3d55b1b94b17991	353367273bbdcc66916a077e58e52de1773d7414481da94d759f57cf59060ba2	7055	0o644
desktop/src/screens/onboarding/flow.ts	100644	39b0d12c397f88cfba6abb9056d2444b7b8419b3	25c4b1122b70e8ca3b741affbc3fd358d20c2e2269275b0a1542568b20d4c9d6	2603	0o644
desktop/src/screens/onboarding/steps.tsx	100644	bbb202723482d954dc8a54056457a9dd66663810	2c1d40c978c386ebbe9271852a89b5b3655cfbbb840054f4efcdedd6bd66f2c5	20721	0o644
desktop/src/screens/onboarding/strength.ts	100644	ac35bb168545454a65a6863fb15213e18032e15b	6848719118af52005f66861aa1c72d0c1f8691def670f871e90237a7f5843af4	1586	0o644
desktop/src/screens/onboarding/vault.ts	100644	f78dbd7cd00b8cd3fbdde646e4bad0ecd9c92217	186cc9c17c4511e62fe59d09f199d67df6b2689068e82a0147bbcc99509806a3	4006	0o644
desktop/src/screens/services/CreateConnection.tsx	100644	8938aa82d92fae2e163fa1a9a92c749b7a891cbf	cbae5bf22a45b68d8106c40b6b0825f79be56af0d77e824131382bcc5c3f49ed	24406	0o644
desktop/src/screens/services/ServicesPage.tsx	100644	99bcf6fd59a156ca155f7b2cf3211638b2700eee	29fa1a51314bfe6756572eb324cb55322686b4063b5780b13373f8d5adbbd817	17427	0o644
desktop/src/screens/services/logic.ts	100644	aace1442d30b2123e9611323c6bf36603b6ec062	31b5404e9c607199fdb7bcdf6403968271393d6698d6438f36c9671907cacbff	5255	0o644
desktop/src/screens/settings/SettingsPage.tsx	100644	ddb642816490232b785218851188b12470fcc901	6241c20b8aeb91d2c3d8b1d48523f245352d49c55627b23e94efc7bb815496e0	8161	0o644
desktop/src/screens/settings/sections.tsx	100644	68dd2448eafd6cc8a71a1bdd6c6c679c86c8e383	37b0794b830c2341d58adf43498b757d32fef1fad38f636d9df23587bebd86f1	24113	0o644
desktop/src/screens/vault/AddItemDialog.tsx	100644	89a660d6a6ef57436a3942d83d8448e7406f974b	2fdfc0dc82a757094c015cf0f181f7a8902199b6c536ea7f94721e4477fc64bc	9707	0o644
desktop/src/screens/vault/ImportDialog.tsx	100644	7ba119e28046532d33b5298a30fe9ad493eb70ab	2583d6adee4042c8d526e9f2e001981aa416168bcf6e47aadea34ce0e9543b14	12115	0o644
desktop/src/screens/vault/ItemDetail.tsx	100644	83ec2b3dd9af170a365cab82755b64e10c6c1ec5	b753c8e8ce062310d22c8c057242c2efe9d57ebdbc8a95ba94ccc284d7b5a68d	7821	0o644
desktop/src/screens/vault/PlaceDialog.tsx	100644	3bc7dc7cdc3a3bc7ac1dc7b7a52b08bdc79522fc	8c0fc2eb284895e5bff6850d24d56ab58ba7336e5c4a02ee9c13104a88301728	3358	0o644
desktop/src/screens/vault/RevealDialog.tsx	100644	4e94a28205f5d483371832959257113fa7668a11	4ee01eb1c53e4268525d25467dc586a5b71e266108d1da78579413d9167c9d8b	4200	0o644
desktop/src/screens/vault/VaultPage.tsx	100644	6d39372fd58391d1da60d8db48b3d4574845c9bc	636e736ace1d40a85273c42ceeea9f53ff5703135f58dbb57f716fe903fcc0f4	14505	0o644
desktop/src/screens/vault/logic.ts	100644	21aa7b4ea8a3dbf78e920ff171abfe23133e5510	4682e9c38d14379cfef07d1559eb8e05935fad70765f1a1b479e9e9179cf1b5a	4149	0o644
desktop/src/screens/vault/parts.tsx	100644	1fb2694479384ab30b85ae3d39b6350ee234b3e3	27fc21763a2779990cb0ec0e00cf51c60422985a5e5a6972ead0150885b0e795	1539	0o644
desktop/src/styles/base.css	100644	2d5372e75010658000cd0cb77e81e9c6015884b9	802653c1c603349a8f104305032e0942b4691f887c2c6a07b703b34945bb2826	2269	0o644
desktop/src/styles/screens.css	100644	393073f3889b3d3aba883a1d24a3368859695b54	d1184f0f61dae3e0d0a127a7843b569d95da8711d852b4e9dc2e25f6d36fed83	292	0o644
desktop/src/styles/screens/activity.css	100644	4e0a0eb0030132f103c065b491927ae7b1bc0d54	b21617fe269385b823a4dbc32f2626f38bf9a04a15a6dd17dd734addb25afb50	2487	0o644
desktop/src/styles/screens/developer.css	100644	728bd4643f2ee9843050fca959b17743e18e2178	21fea9046d02e8038dc891bb955f2ee464f02fce7998a86ae0e3d9978c7c5ef5	7349	0o644
desktop/src/styles/screens/devices.css	100644	a8ad5d846949e9984acc9c25a272d8ea3a2f93db	e4965538520b4bbfb87cdcc895e06b701a598d3b591ca329b2b7eef99a504d2f	4296	0o644
desktop/src/styles/screens/onboarding.css	100644	0592cb5e29245e7065e1f36e4e5b1e46ba916216	ce72041e5bb2d639ea3fb8cd7b6777692eefc69da9f1c75ad3b0c0454b1f4cce	6249	0o644
desktop/src/styles/screens/services.css	100644	3c46e1e6af6ee3df1d01d158e83f7fa2852101ab	19a08cd4b0f9d7dae6c3695595ee31b91ce55376908dd76c835f1005a2bda327	2285	0o644
desktop/src/styles/screens/settings.css	100644	7a966dfd99e01f21662e4702ee701116a866c14e	0118b909e627f05dda45823db6fe8b501c76a7a9ad2ea5370025694ac75a5ef3	395	0o644
desktop/src/styles/screens/vault.css	100644	d362fd31f79442e1958af5f056963c2b07c0a979	941abe2bda4d1fd3ece82d3dff147b16644576212565ece313ec244b35c892b6	3760	0o644
desktop/src/styles/shell.css	100644	8711239ae9d603c5f8d8aa859ba78fd8979b869d	ed7d3e2e94495ddfe0f888daa83263361240ec9a275e465686cc720e02a95986	14652	0o644
desktop/src/styles/tokens.css	100644	fbfbc09ebcc9756e1f2c5cf0d17c5cb44c456226	34bc2e418253e53a16291bd105ed02ccf5778a2c87dff0e0f13b3b90ea6ee750	8524	0o644
desktop/src/styles/ui.css	100644	6640b1cbddc70d184921d46f62cb1fc05aa3b414	9c5f483fc3bb8ce4b5859dd9ebfcd796784aa590867a802b2ac7f23e06f01fba	21667	0o644
desktop/src/ui/Dialog.tsx	100644	561c77d12f4f5c7de5d46a516ae463ad4dee930f	a80f950c1ef8271f5854b5f691cd756ed246bc27e3de1937b5a9041736908f7e	9669	0o644
desktop/src/ui/LanguageSelect.tsx	100644	a59c66f607fe81396f4c539d3e940eefbe67ee1d	411c320368e424c27611e00693ebd232e0574857a46c4deb88dc3c5c1f9ddef8	1445	0o644
desktop/src/ui/OneTime.tsx	100644	35fc0f1343feed93a2abcb8c1f4b7a0e97b6566e	4c9f0954db0b969e414e1d9ddbb189985225eee0db48dc827c0643a50bc39bc4	5187	0o644
desktop/src/ui/Terminal.tsx	100644	7bcd4968bd56178aaaa0d8883f965c8cecf68b9e	eeb64d228caa1efa2d53f2e978a00cd9b7aaa44ad5da71d28208545b6832e3ec	11860	0o644
desktop/src/ui/app.ts	100644	3f8d242cb7fe47cb290f6b98d6050b2b4f86a0c6	a1d6080cce2296d8dcaf5932f5aec4a483ffb653ba0207838aa83844b880419c	1161	0o644
desktop/src/ui/controls.tsx	100644	512aad752377c26626352f471e213022ba978ad6	18310f59015be917c3323fef997865159f1289da99723115ff3fbdfc0ae73fe5	11486	0o644
desktop/src/ui/disclosure.tsx	100644	51741229ae5f240317f6c60b36fe3031166701d9	7f939ecabb3a5dfcb64d4123ce7f581bcca57869c5ef20cc3886e97b6e47452b	3806	0o644
desktop/src/ui/feedback.tsx	100644	45586375fe77efb289d8ea02b1e1cb9f77e98b3d	0fcd8df3e39c20af860d3aa1db6a60df79b52a0543c33e78b465132b7b1ca9c7	5189	0o644
desktop/src/ui/fonts.ts	100644	e86f18d49985daf009e3706851d6d924226dc6e3	ca540b2614bb2e90bbb46477e1e986e186c0c927feac3653f2e529a734465e55	1180	0o644
desktop/src/ui/hooks.ts	100644	64a79630e23bac19f20929b29162e32a4c546667	08d5134a1947bfb251e0cc86ca5c63b569360c01e6dfe7ab00e3041e941e917c	5434	0o644
desktop/src/ui/icons.tsx	100644	ecca85323efa8497e53d0ac3d9a56142f13e7f09	fad5fca7dde609caa79020f2c712474275f947fd0737d8b895b1ba0580205f3f	8366	0o644
desktop/src/ui/layout.tsx	100644	f9cf39b7ee0cda1a4e4edd23910745cb12858da4	c8f75332e879ba84af64eb6efe2bb3f1f08003af6d6f92d8a2d0f9e5c2febec9	6006	0o644
desktop/src/ui/secure.ts	100644	403f14b14ac235e9ec3f901a1e83977505b82f8d	442a793be7d3f549eaf0743244b425f13184a81f3e106077074344e9c23b7ec4	3788	0o644
desktop/src/ui/terminalInput.ts	100644	798e2d9568c2134cd3c8132d4e6dd10e860a7899	61423662d7901d1b5f551b2fd4ea6cfee0c81efeb184afd13e9deaee1fdf2a41	3425	0o644
desktop/src/ui/terminalSize.ts	100644	721e702b9c4d24529bed2fcbcd5bf74b38798d2b	f59e8e6cec9efaf434ffd6f9066a3b68c22febc9096cf87341606c9470718309	1454	0o644
desktop/test/activity.test.ts	100644	db5e8fa737aefd14eedd3c080419b455be0e35b3	ec909b472f31ad273819ef8eda6bd9570dddae81731fde0c3f960ab71c87524f	5700	0o644
desktop/test/app.test.ts	100644	2f9d586b042aaf7674a3152df2fe5babefb774af	70ecebe01bc9008c8af946e2790409671cf89010bbcd60ce0e55d2ba8d3df7fa	8928	0o644
desktop/test/copy.test.ts	100644	1749132e929101edc29bd649d1cbf9ce1a012c6a	a4c1e009e5fc70a6dc179d2c561a2d4d114a03c52088d1b78b02a342eb04d27d	3992	0o644
desktop/test/dash.test.ts	100644	38aed540aaf50f02c196d8a24b769fb4238e42c7	09271fb6851c77ee9107a1d0473806ffc317975694364390a9aaa07fa0a4a9f7	27202	0o644
desktop/test/design.test.ts	100644	1950217ffab1fcfda3b1ddb520d3c689d2a29967	8cb0df70ddcbfc3bad8b280e55b541d74d8af74a0449f38ea206a3b4ee7f758f	2650	0o644
desktop/test/developer.test.ts	100644	27b6e6298d3e087ca17384c5f34d2fd99becab51	a85b499040b2fa890662e02144f7c3613fc703c65383dd1a979305c1d8cff354	12849	0o644
desktop/test/devices.test.ts	100644	8f3b692e3deb7386c5bbe2e99657d4e8faa86183	5973270139d141d431d49c73437c2c9e9d054249a58fb7c177e8a6c3b9691bed	17292	0o644
desktop/test/envimport.test.ts	100644	be34c06bc64290b0fbc5b2c51f73c71807d5994c	f8580ed1f0f90bde22a53cc045a4cc521f27a3d74f3c076b4d38b32f9e0d9c81	11128	0o644
desktop/test/fonts.test.ts	100644	900aaef43c438de241457bd82b8991c7c4dedc74	813a7e100918c653e2649a2994fe17db70d6ddabb6e2107415bf1a6f98a83d60	2730	0o644
desktop/test/format.test.ts	100644	8d8e97d917bd3be0afc74f4a3460ac1871be892e	b7550af52026b3a2fa51a38f2f60369f0bcb2ef6b270189a4c5434d0fb6621ce	600	0o644
desktop/test/invite-preview.test.ts	100644	1d88b7b3fdbace2e716fb3796c3e1d3ae88ce118	df9341f1c757745f0b66884ec1f3abb631341620a4d0b46d78580c5a5a9a7483	3518	0o644
desktop/test/invite.test.ts	100644	8db1f6b264d939595f1c686e96a3e02da8e84467	a7132c5979cb4aad287208d0fa47d7b1f42d5965101ea1b9f56f1670be7bf307	2423	0o644
desktop/test/ipc-events.test.ts	100644	e8272667e4d6ca8dd37a8189a69b7f4e2f110d2c	58421ce96040f6aed58a1a0e68f8ed7eb2dbd8b11cb6891548c297cce184fc12	2217	0o644
desktop/test/mock-dashboard.test.ts	100644	24788fd1d3e07592763648fdafa7bc01a5dbacd8	79916328bd6b221a5d123f4202b00c4b89a0310de847df85d77b139e552f7bc8	58445	0o644
desktop/test/mock-ipc.test.ts	100644	c7f89d53497f98abe8ec01619ec570e3ea7b263b	3fb647bad3b8daaaf7791063da5df1a5989dc6c7700dead9b1d539880286d422	11603	0o644
desktop/test/onboarding.test.ts	100644	57d8430a078d891fa71b802e421fd4f5acb354d1	99e5d09f45e6bf097efc74a7c607920f60eb376427e5a86e83b8bde8642b00c5	14461	0o644
desktop/test/pending-invite.test.ts	100644	a32efa8228c42940cba50be833be7da714748d50	0f3a0df00eaf4c47663802313478c074ac10d738001f9d9889b1378df0866313	1171	0o644
desktop/test/reasons.test.ts	100644	4ba7a2bbd21010bb519033fcca41a50a21d48155	493f19f9cd2fe40b6e7a612dde3e1112f8c0c4b88152611133f5fb97ff5f739c	12366	0o644
desktop/test/records.test.ts	100644	1b37e96f7322abb40a3ab3e0012a1cc389ee4c4b	1c434d591f62a0f4a2c2fb6ca983c6882a7ca7c2d37420bf1cc81518da10dbf5	19204	0o644
desktop/test/remote-sync-lib.test.ts	100644	cacd629d89854abe65e5f19823f9670bbc236e79	a75ebeee6f7271a9d83c6391acdd2570f46edabceeea96ce6bd507b1fb64fd53	14473	0o644
desktop/test/services.test.ts	100644	d3df52e22b0a4cb3702dc03d143c035683c26de8	c542ca04dc29763c8402e87233cc4d91cc8a834878933c2117ae8b653b9ab4f6	12743	0o644
desktop/test/settings.test.ts	100644	b8dddde08032f41bf99203ea8ed225c3c8c8fe92	33a4771f629a9271b7cd62c4c478982925d5a456974f5d566d48b10df9bc0db9	8194	0o644
desktop/test/terminal-input.test.ts	100644	ce9a384b6de3e345143cbd21ac6477aa51c4ecf9	8c3c7828760c74f431ab11dab29cb4368799352fd0f9495dc161206c1841145f	7502	0o644
desktop/test/terminal-size.test.ts	100644	25aa9dc3664360ef1ac74ef5e13c7ea8efb6a234	ec5c845fb816be9dda0e46864809420f9b9d0fb4ba5f8bebeb8ddeae61c2997a	2167	0o644
desktop/test/validators.test.ts	100644	00103cf1b89e83679af70d30c93407b0cc4674f3	87d3d27e08f5318e32a2390c8b39361bc2f973ab2c83c0253a3bb5ecbf90c7a6	9781	0o644
desktop/test/vault.test.ts	100644	4fb2a124e231a595ba86dc267e4f126e21de3b12	9ad481a6d9199b5a260606eea5a8e061047e26f9213ac3f5b17c7eca89f17641	18955	0o644
desktop/tsconfig.json	100644	162ca45abfd48f8e95afd5e218a9401d40d9d9b3	e2067ec287db07cc3f2ad90601a60ffa08d42d7a0d13b5e5b05a560fe219473f	646	0o644
desktop/verify.sh	100755	8e3c1e36b1407c2c7969a07059ab058ac453b826	19738142111463b13045964d001ef91a753fabaa88a107db964a762b40bac336	1527	0o755
desktop/vite.config.ts	100644	3f2250aad2a40fc72ecfa0aaac3d872fb85f62c6	a176e2f1f61785990fb8ebb40fe64e06f3f8666ef391fd888d432eb4cbd62971	868	0o644
desktop/zeropw-link.json	100644	a1061fb18368333390d2b82ba1e842a542dc4711	50b5c2b1877e9e759267222c5615217367034248e765a702bdccc2c8fd464cfe	431	0o644
docs/archive/2026-09-12-before-auth-delegation/README.md	100644	0235f8136d483d3e86d5a57d217e0e134d6581c8	624184f10c2c15629b77ab373d25c5b39905e1b910118292f39804cea2123773	349	0o644
docs/archive/2026-09-12-before-auth-delegation/harness.md	100644	39fa34a88dd08e41995eb0a3901fc5c0cca4910a	e9a4a524a727db15cb3d9fa65daf1f2fc8e414958a7b468f67d8a488aa4b40fb	7297	0o644
docs/archive/2026-09-12-before-auth-delegation/manifest.json	100644	947176914362e7d5281a73d9752448a05a439487	61fe864185f25c40feddb5aa5aeebc5209974224f44b8f0df229cb9c77a54e5c	1043	0o644
docs/archive/2026-09-12-before-auth-delegation/product-intent.md	100644	1a51f0fdf94353bd56fb0a835af2a7cb8e6446d1	faa17717f82f05117d3ecf06774fd1b707f8e1e29fcb635d39f48827544c29ce	14625	0o644
docs/archive/2026-09-12-before-auth-delegation/review-summary.md	100644	5594b0fcee799b64f1901a4afc943903d552fa61	5eb161f7fc3593b7d9be36ab7742e073e6a3d9373e8871ac52c4ed26de17aece	3299	0o644
docs/archive/2026-09-12-before-auth-delegation/security-design.md	100644	7502c14f213af3bcec5549e47c4cddff8cce7809	888cef3b3ece5f21e87991963477c0e2596083b91a7e7e2cdb72a4fbe055c571	16682	0o644
docs/archive/2026-09-12-before-auth-delegation/zeropw-product-definition.pdf	100644	05916ca9a59ee991d24226a647c2e4a4bf8974c7	9ef00fdedcd49d24d007051c10ca3af8909c488f04436f1e6e5e8d5e7409018f	155853	0o644
docs/archive/2026-10-03-rust-completion-history.md	100644	f93edbeaabd8cab8e6891fa83279975f28e9075f	3c22a44c3933921f8dca90df920374929f8693552c1bbd27721edc1e181c34db	49717	0o644
docs/compromise-response.md	100644	453e2dbfd73e3c0c85b0a4d39e2efd74b9677c45	26ce664eec89b3efd66c15ce3a09158ec1aa055a411128a32874fa8ee83bc6e6	24233	0o644
docs/decisions/2026-11-07-signer-socket-path.md	100644	4a9ca1c277d491a020bc187c2ea0f270f1cf06b9	4f752c79032ffb7b4d25d79137bb96b2e2506a0eff94dccf2d7936f24de679a1	5202	0o644
docs/decisions/m2a-schema-2026-11-07/README.md	100644	bbb5f0bf2544c27f47ecfa17e487fdd0e3c92f97	945b670daccd36cf9da8508e4802c9c6ec85f3128623589ee7ea3123ff8c7d55	2367	0o644
docs/decisions/m2a-schema-2026-11-07/decision.md	100644	b7f39d49a25745413d423a884aa47f898ccba5df	564bcf4c312b04507e815e35cc8eed9f5c6ae8f74ee539ccecf88cff8f0595b2	60768	0o644
docs/decisions/m2a-schema-2026-11-07/implementation-task.md	100644	5e44f07c0d0048925d3d289d6c602b3999945ef1	3d6520c88fb88558ead2ee380bc322ae897de9c4bb5b67c6d60e37b184e2a58f	19907	0o644
docs/decisions/m2a-schema-2026-11-07/parser-compatibility-revision.md	100644	efa63a31e3f33251453fd043796cbcafef10301b	0ce1fabf72cb7c116a422dd5fc521383174c55a38145c2aff1ab07e8df5cf370	29281	0o644
docs/decisions/m2a-schema-2026-11-07/revised-implementation-task.md	100644	7449d1da7cc218b5a85bd74818cee3bf26e4c229	27a49588eab8553bf81cef67547b6e9d581ee991dc9cd10fae2a4d92268db395	21771	0o644
docs/decisions/m2b-admission-2026-11-07/decision.md	100644	7ec50720d17280a154c1a833ac6f705c9f94baa8	1baef6b989a53765ef76a05f43a7e2a30914ed94de18deddfdbd4218b853f248	56986	0o644
docs/decisions/m2b-admission-2026-11-07/implementation-task.md	100644	6e996fdc7302d95f37ef143ce83226476927e5b8	79af320ed9bf9f31c026e41a1cf09b9164ca6a494748b8522437032a568aeaa2	29275	0o644
docs/desktop-app.md	100644	1946721400f5e27f3d73c03044736330de7513db	a7f73507028a3096fe1a4fc2f647e43a99139f940897b9b0387af44bdfb9d6db	77340	0o644
docs/desktop-ux-e2e-2026-10-26.md	100644	108d2aa1dab069e838339cae7db0a5aab35eb8d2	d590381e1d5eff283484cbc2cc0eecb7dc8026d68473f829faddf173136e79f1	18988	0o644
docs/env-import.md	100644	7f8d88b93813b06419164d5dd67122e3bbe9604e	2ab8aa9a5897040dbb23379f67a7b6695126b140bea8899d05734d8cacd13853	21621	0o644
docs/evidence/2026-11-07-grant-expiry-diagnostic.json	100644	8e68f85d67fa441981895c91b83d589f40571856	ad3571bcf91623fdfe080637234bd4afdc8439e25f7fe1e31951e6eaaeb4bcb8	997	0o644
docs/evidence/2026-11-07-link-3eb-review-interrupted/README.md	100644	4cc5c114dbb966b458df44ca2cb4c7a56532e9f5	5fabdea8fdef8cffdb5e9aefc9a59194ea9d6cbc3578dfd13e1e6adcedc03223	1155	0o644
docs/evidence/2026-11-07-link-3eb-review-interrupted/interruption.json	100644	7b793a7ccf6f3e708b48bdcbfc2ad31bb2cb5de5	bea4996e2b3a521cc65db3f1c32474f52a4a31244e3e03cf0e4764a4043b1cd1	2080	0o644
docs/evidence/2026-11-07-link-3eb-review-interrupted/report.partial.md	100644	fcde6c105bbfbc3e7dbcc87e7272e2ab58dd2764	7997fa68e23b478272ba7a5f7acacaca3a4d7ca3b95c37297fc47a72b5f24d00	6010	0o644
docs/evidence/2026-11-07-link-4af5ac8-review-unavailable.json	100644	cb42dfe0122c72aaad61be2ef568083363663c84	d6d0ed7b1e91bc3733bf66dec7b114c7633b9d4882eb2e3726acb2aedb73a4eb	1161	0o644
docs/evidence/2026-11-07-link-build-4af5ac8.json	100644	5c4c5c4f3c42ade7a40a3d459dcedb4dfd3fa21b	41b4943205753d189272d1c3b8b113d337d0ddc760d4a253a5da8cf113a61d18	2176	0o644
docs/evidence/2026-11-07-link-e115879.json	100644	441d58be6e825f9ad4039f208f5bef7ee2e8dc02	d73205fc821c1abb66644e505d6f2a03c4c6f4ef614f1223534bae5cd7e59579	1373	0o644
docs/evidence/2026-11-07-link-installer-5a9f581.json	100644	f29f266b8683bfa8cd1f5e6003981d6ae6000d80	c181d71d9ef65d0a95525a911086c673df2563d2b58b19258dc94a0d6886e0cd	9288	0o644
docs/evidence/2026-11-07-link-native-final.json	100644	e096196853acebe3f9f0b3b697ceec5ae3983d78	ca1349081ceaf6524db48c5dc42dd9a8d195e53bb3001cacac377e1f5dc5a89e	2453	0o644
docs/evidence/2026-11-07-linux-rust-7f0421a.json	100644	e902c1ff5fa955700c3672af039aa14206a59446	3d594626edd6e8c4b1910490791822c5abdca6531f8a7d32ae22e01007414c0d	8976	0o644
docs/evidence/2026-11-07-linux-rust-945e6a6.json	100644	1c3dd25c46f7115e7c17cfa41ea3e39bd35a8592	b648ea6ca2ceca6f8c2d085d830b45a71cbb54d9c32d47bc8d0d83275087080c	9852	0o644
docs/evidence/2026-11-07-m1-m2a-composition/README.md	100644	91c28020d321034e0abfb1e1fbc905ad2db9bac3	c881e00dfc497d9f15b18f921dc1641d87eadc182ee56a4470d5a8fc7c51627c	1599	0o644
docs/evidence/2026-11-07-m1-m2a-composition/TASK-PREFLIGHT.md	100644	bbdb3dcf6e6b4e283270f542b19f652f0d571a6a	b1e4689c6135439e518cc75f025719759bfef39fe4ae687e8760cee100069024	16840	0o644
docs/evidence/2026-11-07-m1-m2a-composition/composition.json	100644	80cf43f0db75aa5d1e6fc7bf6328148cd22babca	d576a8baa74de2c1e08703355416346e2ae6b42cf88f5d8f050570b72bf428c0	1878	0o644
docs/evidence/2026-11-07-m1-personal-vault-63d2e4d/EXTERNAL-SHA256SUMS	100644	1099dc0dc0d4027664ee37075b638319bc0b333c	9386ded5f2816ddc3e5c990cfb122835b3e2b77cf2936b620763e1bf2da42815	20240	0o644
docs/evidence/2026-11-07-m1-personal-vault-63d2e4d/README.md	100644	8305161addaa12284d95f95b80881bd504e29472	5924880685d7b38b3a988ed0874cf659ab8cc7bd4e1cc1d63b4fe869f42e1995	2008	0o644
docs/evidence/2026-11-07-m1-personal-vault-63d2e4d/REPORT.md	100644	59c1012f8a6d7d83f49a80c122cfd358b5c01f21	c539ee235e8bee4f4440d5f9a8b8a86fcf7eec1fcc307e74c15404bd6b367315	15324	0o644
docs/evidence/2026-11-07-m1-personal-vault-63d2e4d/STATIC-COLLECTION.md	100644	5c3f765add66e602804c3201983e2ec72896afd4	0762a07f1c6b26bbce7d7e535481350dc50443232171fa0b69b3db99f9438b6c	7524	0o644
docs/evidence/2026-11-07-m1-personal-vault-63d2e4d/collection.json	100644	d3202e779008b990b8a784ecfab6cadc400d681a	e5927aa80f45b645c9b905a8d4d28019be205274f08ed1d92c7e21285953668a	1988	0o644
docs/evidence/2026-11-07-m1-personal-vault-63d2e4d/combined-changed-files.txt	100644	c66cef40ec1d84aef0c3c9c0764726a4d3eea264	9e2bb5e87c505957dfba22d388f8a54bdb7df92c89f975b52d92e3fe2985e722	1712	0o644
docs/evidence/2026-11-07-m1-personal-vault-63d2e4d/combined-commit-binding.json	100644	01d347abeb5d70e4300758a4de41da2137f2e8e4	03df9b688cf8aa3a4b4bfc5197d11ffeea62d375c867d200e1522721aae0a2b7	328	0o644
docs/evidence/2026-11-07-m1-personal-vault-63d2e4d/combined-commits.txt	100644	ae4d1a657913ec9ec7a2b8f72111a7aa3abb9829	7847be7c50c99c0d830f317c6914ce9c7496a072ffcb35b408a5035b243801f2	762	0o644
docs/evidence/2026-11-07-m1-personal-vault-63d2e4d/combined-protected-boundaries.json	100644	2c3e1dcbeb4c9f2702055606592be1fb07dd1494	31d1eaf9c10e15fdbe2de9264a7618bb504d17421c38f0055eee2632ca614a70	781	0o644
docs/evidence/2026-11-07-m1-personal-vault-63d2e4d/final-source-bindings.json	100644	b7bb0a5b21932a7ff2dec895b3f9222cc9a8b76a	52c27ef4cc3e68c33731bacb6afff1bdf1aaf9d6473e2f870343204f8b11bf65	3570	0o644
docs/evidence/2026-11-07-m1-personal-vault-63d2e4d/verification-summary.json	100644	df582db5576d9b96db20e362f1bdb73da61f89a6	bb289d13d71ae6275455f52f6b038e709158e6c20b3be27ccdf20a3d910f4835	25680	0o644
docs/evidence/2026-11-07-m1-source/REPORT.md	100644	47d30b6165d6cfadf80ff4bcebc414955fa290a7	a1c47913bfb45f84a80880925f756a154cb3f845321f3742d46662bcba8d214d	15993	0o644
docs/evidence/2026-11-07-m1-source/collection.json	100644	ac461d9cc03e0fdb1b63eae0c6c81b03754d1045	c617e645b0255ca57145f93a07c8933ea0e5429e50106cc7e5db9aee2e5d4075	1048	0o644
docs/evidence/2026-11-07-m1-source/final-source-bindings.json	100644	bc6f2d2295bd34c424af15721f605ae4b0e62aab	628151aff7ec08c5cdf6f2b0e70a5611b02f789d1eaa59f14bd1fe8e2b69f304	955	0o644
docs/evidence/2026-11-07-m1-source/raw-value-feature-boundary.json	100644	7a5d4f66909dfe59165e0221f4e348991ee7d836	c8d5c70ed45f2413c460042a9885c7b690c8046adb1d1f83358a4670b153a3a1	382	0o644
docs/evidence/2026-11-07-m1-source/unchanged-boundaries.json	100644	b0cb982f6b0e558f68757e76a5074473b03d17f7	7cc49d7e40e40dce1717a606a7185fbc989d2d2878aeeab4d313881b192ad8db	270	0o644
docs/evidence/2026-11-07-m2a-7bcecfd/INTEGRITY-STATIC.md	100644	09e51935f57d8cb35429640db297c1341c8f9140	0a49fe72610d2522daa4ce2178a6338b291e673c9879eaa562cba80335af3fe0	13282	0o644
docs/evidence/2026-11-07-m2a-7bcecfd/PARSER-STATIC.md	100644	5ff6132f0dea848f5fcd757226b693f8895621a0	a62818431bb000bc67336824f9d1f5845f4876a6c5d30386e2350eb7627fa18d	15526	0o644
docs/evidence/2026-11-07-m2a-7bcecfd/REPORT.md	100644	4259766b5f526bbff3eb600728a9e2dbc42f8e76	6d2b7c53720ff365fa7a9d784b7dc12bcc717f7144f1b43c15252a254ee573f6	24681	0o644
docs/evidence/2026-11-07-m2a-7bcecfd/collection.json	100644	c7da464daa29c80f2e9607757731a7b4e7085b91	d7dc380fce262bb6d1717508cfd5b31e9100595c456df77451a49920f86223bf	2134	0o644
docs/evidence/2026-11-07-m2a-7bcecfd/final-validation-summary.json	100644	bb7c98e0d1ea59c66d21221f5f82999ba8217ae7	373a17f1a667bf422c9f8fab12b1c58830bd64e1e9105173d9561a923dd7fda2	28447	0o644
docs/evidence/2026-11-07-m2a-7bcecfd/source-test-bindings.json	100644	87cb44a35bf75c245ab2d3e56ef158f4bfff15e8	2af7ae2023e5b4b99b0706700baab7f0c9d28e79314f654566185926fae8d461	2457	0o644
docs/evidence/2026-11-07-m2a-fixtures/REPORT.md	100644	19c113e891236215aaa21303f63c2ddd1814a798	241ae325f35b2e74f6c186f361258ed949e0bfe604243d254a3d7d4f73b85380	13255	0o644
docs/evidence/2026-11-07-m2a-fixtures/STATIC-AUDIT.md	100644	161b1c620b82f74c3e559347342db0ce761aec8a	6f6afa2d52214f140117f6518605735f9310f646d261f4b519866cc62ff98def	17743	0o644
docs/evidence/2026-11-07-m2a-fixtures/collection.json	100644	d0d854771c427c5587cdf58284efdf3a599c4674	dcee6fdea8cc02b7f633ea2efef0ea5d61d8232341b82322c2a154f0b1a329a2	1276	0o644
docs/evidence/2026-11-07-m2a-raw-value-feature-probe/README.md	100644	5e7445d576015ae025a7347040ff07bc5de10a22	c1b12cbef6e58895abb3d5fdf93d9e99c52a22091b1cf7811c57d9c71040bc14	1178	0o644
docs/evidence/2026-11-07-m2a-raw-value-feature-probe/REPORT.md	100644	ad899c21bd57fa76d5043929965ea888492ba76a	c0f184d14fdbbdfced9ef31b8e5e3f7247954c7e5be122f3b3fc9dc7fe27ab66	9148	0o644
docs/evidence/2026-11-07-m2a-raw-value-feature-probe/comparison.json	100644	d79f5df58550f25171c11f8c016911119971fc79	3189549cd2b66eafe52f84340a396336b7cc1a5451b5556f9f334794f68460d9	51699	0o644
docs/evidence/2026-11-07-m2a-raw-value-feature-probe/input-final.json	100644	7b637d40834aa425d34633b76afaa736e05e70df	1f336368e9c75d21aa944deb984c566ae32657ec9e90cf59ac62e9f459feee3d	2225	0o644
docs/evidence/2026-11-07-m2a-raw-value-feature-probe/inputs.jsonl	100644	3f97c147753245abcb0204d25ffb2d925d7385d1	bea637d8a3a1b1494c01e447697431ec45c4ae5e534d0f7d77c13e45b923df2d	3218	0o644
docs/evidence/2026-11-07-m2b1-795babd/14-resource-measurements.json	100644	ae20800f689415579665150507ccd5b1429a1dd1	7f606e6f3c5e96133ba709cd057e0b595c6544154599487ef245110c3784a64c	866	0o644
docs/evidence/2026-11-07-m2b1-795babd/EXTERNAL-SHA256SUMS	100644	bc67bf06292587fa4f28c6563e26269321696579	e438a34cd62abbaaefb7860d3e783a929bb62abf9374fe1bf5cbeeffd45986d7	7871	0o644
docs/evidence/2026-11-07-m2b1-795babd/README.md	100644	7a24a4b6f414330ae4d07ea833508ae4b3001d43	8bd53f30dee36ae20acd94acb3d347d415ef1e5605a8625433e1a3dd9ce3a19d	2272	0o644
docs/evidence/2026-11-07-m2b1-795babd/REPORT.md	100644	9af4134c543db780e9a86098eb702694c4ffc6ef	9d7ef3d0093ff1e4d5051727894943f4d7c9ebeae322bd9c658d13a6608a88d8	19836	0o644
docs/evidence/2026-11-07-m2b1-795babd/STATIC-COLLECTION.md	100644	2a43cf9c40f4ba9dac20e7e565767ba20b827f68	2c2c46118f14fbf9d2b149ee77c62ab47dca6dbea4a5f44866e0451be371c50e	6740	0o644
docs/evidence/2026-11-07-m2b1-795babd/collection.json	100644	3c494a2002acfd3b92fa6941ae9f2fcdb04a04b5	597ddec6e3680f6edd8149b26b18b637937b7251313a6911a4d04f441fba1485	2536	0o644
docs/evidence/2026-11-07-m2b1-795babd/final-binary-sha256.txt	100644	f6580858b1de03ce463dab2ee65a4206c75be033	c655d9933157a4f3e5546d2fa54dfa1204d38957df775c3ae0164f93775622f3	1543	0o644
docs/evidence/2026-11-07-m2b1-795babd/final-head.json	100644	4dedefab92e4cc88c26dd7545d16e6fea70e8c45	aba7b6835ed3ffbf9c7b7798080af3d66d75fbf99d5d3dd00d493d62af06dd6e	189	0o644
docs/evidence/2026-11-07-m2b1-795babd/final-host-source-check.json	100644	6514c39a9e755f8e9d8452f63ed4ac19e51c3a6a	b2efc029a88f5f4a0039bf7c5f88184e34910b831bc40b6701a095238c5de0ec	378	0o644
docs/evidence/2026-11-07-m2b1-795babd/final-static-boundaries.json	100644	2334f0caa521c7df374f95f20444af58b7a8c04b	c0d4594a48caab0c69fd9ad4156ce43320ae9dce1a9944b7da52efe680781a5c	3102	0o644
docs/evidence/2026-11-07-m2b1-795babd/final-validation-summary.json	100644	4446f25c8b8ef5a651fca0ca01153c624c6d704b	8221bc8b8b8aaa3db17b35dbf896c3fed0d635bba40082c205217f99fbf7ee73	37249	0o644
docs/evidence/2026-11-07-m2b1-795babd/independent-fixture-data-hashes.json	100644	0c9505f18aca32efff0155055a5b6b72fabc487d	4a4d15e5601808681fb0039f317659f44694068ba06ef17d55acc0539e05089a	1706	0o644
docs/evidence/2026-11-07-macos-rust-d942263.json	100644	29b6b83995da7bed75579de3de5019cb91895513	fdc33e794feb7056b627f419589f3f00bda6e2f790565d0760101af79cbbc940	8206	0o644
docs/evidence/2026-11-07-macos-v2-final.json	100644	9689b20ef3386c242b8e4cede0773e5fb62ff25d	653d4e44538ebc8144115762d832dd6567a898a64fc7d1aa6d2a60b3933af051	17579	0o644
docs/evidence/2026-11-07-personal-vault-ui-merge/README.md	100644	7738ad0f8467f560f0124e04b127ee395c420a0a	b3c32c02ae50c84e40e2c2b557adf91a0df46d9a17b6654d48bfec5213fd98c3	1659	0o644
docs/evidence/2026-11-07-personal-vault-ui-merge/merge.json	100644	1f5d598290959b8ae4b679380eed6a8754ef1606	2db50be35dfc2a5345792f561a7c2dc39a23c598e273828b44eb1dee216c315c	1210	0o644
docs/evidence/2026-11-07-signer-bd065fc.json	100644	662b79035ddd02e4dab0c2961d9e06cfbbf33365	d69488ef6b6ca908483623b2da960165d7b9851884c91351f98d21165c023205	28374	0o644
docs/evidence/desktop-ux-2026-10-26/confirm-auth-retry.jpg	100644	e5fd2c3ea8c58ecd62c6ab4e4e1b62aece6d2aca	db78a32cdbf649a87bded1483791ec943cc317a50b8f23a770b5da97e11eaba4	35181	0o644
docs/evidence/desktop-ux-2026-10-26/confirm-retry-success.jpg	100644	aaab40c161b9ff25ca0517bb6e513172a6b21967	9520f00b3407a753066d8db939ca575fc26bd6d4e472e6c24bd3caefdb17c925	31701	0o644
docs/evidence/desktop-ux-2026-10-26/final-clipboard-invite-revoked.jpg	100644	2c2c132f88977d0111951855ad625cb3c7085089	30ace18c9473bb3d577cec04e7d6512ff838a25ea39ee85c2402ecbaa18a369d	51854	0o644
docs/evidence/desktop-ux-2026-10-26/final-connections.jpg	100644	a62c9509d9d48cfcdd07d1fadf44f633e433c571	560765d21e689c07c2663b4357a5c3ee99c102d517cc05bc34b5f6c804c26396	24325	0o644
docs/evidence/desktop-ux-2026-10-26/final-home-agent-shortcut.jpg	100644	99a731ed77460956e4bf107f15a367c9fa855cbc	be24533ec6c12dc8f5331e67521def8bcfabb6692931a7a6a1777ef9311f48a1	30211	0o644
docs/evidence/desktop-ux-2026-10-26/final-home.jpg	100644	9dc899790ae6cebdfcc266251a07136eb4de2591	b60a3dea2dabe6108f941b1abce4c4cc74b3f51b1214ad9126f20eb77fba12b3	29079	0o644
docs/evidence/desktop-ux-2026-10-26/final-incidents.jpg	100644	e8232b040d0e7097897e73a7c7403f8837e32264	3bdde7f10a9fca62e1277ab8fbf5715bca884b51eb06a1226113a2c28511a0ab	24335	0o644
docs/evidence/desktop-ux-2026-10-26/final-keys.jpg	100644	28016a5a2b44368c9c60b308a40534602debb4f1	20f1c8a018a9f90be3f88d0192a47c3ab8a6385fca1aca08dc4d4bfa5e85758f	26303	0o644
docs/evidence/desktop-ux-2026-10-26/final-native-clipboard-cleared.jpg	100644	247605795efdc37612c22ddd5ea527029c36b365	9cd56c7888b23e3f017d6295725e94a433430567d261810eef9bf439a871bed0	52192	0o644
docs/evidence/desktop-ux-2026-10-26/final-native-copy.jpg	100644	8ef5449d9227689603475393b08321461530bd31	0da40fa628cee12344d790c776fca76b9054a5cdaeb16e3bce122ebe9eee1787	62650	0o644
docs/evidence/desktop-ux-2026-10-26/final-native-paste-preview.jpg	100644	aad4b06108b2bf05ef58186d0597481a9b6f6428	38030a96ba6de71dd893932a53b131243e1240803dde4b89eab7aab48a4eccb6	66139	0o644
docs/evidence/desktop-ux-2026-10-26/final-records.jpg	100644	05f8dcdcdaaff32f8cc1e7f50ef9e6de5f26d65b	c4caeb851953d8a0e023f40ae8252c7bda4c13cfcce6dae7467d244532c41efa	48471	0o644
docs/evidence/desktop-ux-2026-10-26/final-settings.jpg	100644	e2374b982de303e8d26e2a1804d16f7a1729a4a3	ddfedae4f2dab440a0a0b5cee5bbfbf97e9a4bbb1f420649c0665e23fd45e78a	32402	0o644
docs/evidence/desktop-ux-2026-10-26/invite-auth-retry.jpg	100644	3c0bd6d0e22b4707239763e1b96008cc96e941a8	ca859d7e82d074d18d6151d89b483c2b33fa7711de6193eed0ad4719d33a1fbe	36177	0o644
docs/evidence/desktop-ux-2026-10-26/invite-created.jpg	100644	6e8f563362d099229cf246f4db76e133642a138d	b520f6c6c2bc11d4f06ed2666da7f138410d8cd0fc15268f3f8f003617eee653	37481	0o644
docs/evidence/desktop-ux-2026-10-26/join-error-focus.jpg	100644	6bd52e221ea34564387e155f1b1a6668bb4d4d41	bbdc71c07f618bee5089c6cc4d58913971074ef6c75c79e1adda92338f7e58c7	41286	0o644
docs/evidence/desktop-ux-2026-10-26/join-error-retained-after-edit.jpg	100644	51d3aa49e1626784f8d85352eeaf1f43fa4a813c	12a7071bc51507409998c7ab72fd6c7cfc5969b68ada83537f760f845524d855	40632	0o644
docs/evidence/desktop-ux-2026-10-26/join-repair-collapse-before-fix.jpg	100644	62803c56c98ad24ef65d49df56ef8f98a5072161	c5b4d4e7ffcd59ec90155647e6a7b2cc8a1109198225d0a2f073dd561fa90675	39344	0o644
docs/evidence/desktop-ux-2026-10-26/join-repair-open-after-fix.jpg	100644	587e032f12f7988e733ba9760dfe256c5a522bc0	eb3e3acbab780c3db209e7848b42d781cf9435339096fa4cd69ecb6c9e83c27c	39950	0o644
docs/evidence/desktop-ux-2026-10-26/onboarding-four-steps.jpg	100644	045e677bafa7fe4b92a4f574218caa254808f810	bab4a48c8a69de8afeee264a14a523bf1398fd3f2c95bb29fa8280ce9b4c9aa2	43393	0o644
docs/evidence/desktop-ux-2026-10-26/team-joined.jpg	100644	fcc90ac91bc6c06445fbe1a565c313cc978413f6	5938b9203eac4b92671cae120fd413ae1de30d42e9cb29e5913ca5723c54840a	31895	0o644
docs/evidence/desktop-ux-2026-10-26/used-invite-rejected.jpg	100644	31b786feeff263f0db25ea15ec5ae88c1bc6154e	11bdcd99321aabde743b1105f8642acf4712524fcc34e331962a467c719f45df	39496	0o644
docs/evidence/personal-vault-2026-11-07/01-first-run-welcome.jpg	100644	e4af53730888624b8fd82041342da7b246ffb803	072147512c46cea2b717d9e72932084a66aef1a11dbcaa32054fe838f16d6ba4	61200	0o644
docs/evidence/personal-vault-2026-11-07/02-first-run-created.jpg	100644	f65b722370558208ce54b1a9f3561ddd70492425	42e241c2caae03402a659ae38a75250eefc796402e4eb7cd27f2b146394a99cd	56861	0o644
docs/evidence/personal-vault-2026-11-07/03-first-run-done.jpg	100644	8d37c1bdf622b22347b5cc97cbcffe7af4e2b19d	9fac0f6a0a9f611bbf00bdd82e6c10c368ff3d06700cfc41b130649e13889dfc	51612	0o644
docs/evidence/personal-vault-2026-11-07/04-locked.jpg	100644	74d10f80e60cb1434053e8f9a5b436d5323cf8e4	2e976b98cbe4731405d23f8636879001ef762d0929a397bf36651bc1adee2b6b	26762	0o644
docs/evidence/personal-vault-2026-11-07/05-vault-item.jpg	100644	6b100b2cb26f15a94b615cc5abfdd88f78f02921	4786cfd19663c1298b45b92d364ac26c871de0dc677e21f646b6407ff7ac8d06	93630	0o644
docs/evidence/personal-vault-2026-11-07/06-add-item.jpg	100644	e1993e62ae98e154e736a2dfbb7c262869b5c2b4	948a7197a58e79114378c4f10173a16b9fa843dff54fde8b39219c6f8ea6dabe	108274	0o644
docs/evidence/personal-vault-2026-11-07/07-my-macs-not-enrolled.jpg	100644	6fef427f5a4da074880101d30ac0bf36221f90eb	5f889ec5ce3866d6d77a1237d16fdf49789783b6f2e1ad38e73b94dd850ffa1b	99171	0o644
docs/evidence/personal-vault-2026-11-07/08-enrolment-network-failure.jpg	100644	c85447b029e60613cac36e44a5d007574f7bb44a	58c2d6416ae853937054d82f3df17ea67b6e2075fa728f9eee58c10fa1de2485	105781	0o644
docs/evidence/personal-vault-2026-11-07/09-service-connection.jpg	100644	51da4bc8909bd6ee15cc6b646bb893d509d246a5	9ce4543ca5ec3c7d3b19db7d2f0a174bf94da094c0135fea8cd1fd8a81951880	98316	0o644
docs/evidence/personal-vault-2026-11-07/10-agent-terminal-list-connections.jpg	100644	83258e82ae2451592763fd787e47802f2180bca4	8c7a5b7fc426a5bbaf254a13b6b5f1cf36b0333d34212f81e2deee059191b7e4	97813	0o644
docs/evidence/personal-vault-2026-11-07/11-activity-records.jpg	100644	bd0384318edba5bb4cb61ba8368d0fbfc380b75a	a6179139bb4b508c2316e5cc55dcef92daa3ab81e79112292837e4e64512dc07	119016	0o644
docs/evidence/personal-vault-2026-11-07/12-settings-link-server.jpg	100644	9e08baed3f83df86e23b46ff46a475c1c8cdf084	82fa6df8a49350e0e92db49e7e0a089e871adaae8bf017aab28921445e636fb3	113067	0o644
docs/evidence/personal-vault-2026-11-07/13-vault-dark.jpg	100644	1c8a397dd09168fd95eb4adbac4e41c37446cb2a	9a32eadd048e152d3ab2888bf68b10b9e81965da5114cbc665a21830d1e270cd	89355	0o644
docs/evidence/personal-vault-2026-11-07/14-my-macs-dark.jpg	100644	88bffd81ee5b375415e3991f8739b03f8ee4bb00	a7ea4e2994661a6bbd5232492911a0c90043f2341688e030e8918b8625d5fd1e	94809	0o644
docs/evidence/personal-vault-2026-11-07/15-small-window-dark.jpg	100644	9595815d1ca078110a84e0f76f6b00e039f5f1e4	6c32ee670a8f732b4dc5f22e0bd627abf9a5353c3163382f3871ec82a16d8e9b	61402	0o644
docs/evidence/personal-vault-2026-11-07/16-glass-first-run-welcome.jpg	100644	daebc8cba9e250d5fd33d430f8e87501f58b0e54	f3e57d226c69f8e2af421690d895696e9c6dfd4bab9f79eebdb1fc2852129d15	143504	0o644
docs/evidence/personal-vault-2026-11-07/17-glass-first-run-password.jpg	100644	5c983220c4b82f8a6db624eae29542ebf527ac2c	50033a970c18b74974816771e369be4c4f551017386a67c022dc9d73b4a953c6	160234	0o644
docs/evidence/personal-vault-2026-11-07/18-glass-locked.jpg	100644	1b47a2b8f1b8849bae7760e6a0cc92cef988c260	abe81a4f3c5579640f9a5d39e41faa8aa70eab36b6b3e68e86dbe2f8ff413c9b	53213	0o644
docs/evidence/personal-vault-2026-11-07/19-glass-vault.jpg	100644	ce1440637bfdde9d3402cadc0b9b106c71ae56c5	8065708234500d07cc9b8bcf909fa11f0913bcb5b3a4ea3a2c1171b49b73a16c	95480	0o644
docs/evidence/personal-vault-2026-11-07/20-glass-add-item-essentials.jpg	100644	d2393a4e9cf302f73799df2bedbc8bbaae6f8c7f	7d287a63590f56d66064bf1f6f44a220863e76abf59c88baaca43dc22c680a15	103758	0o644
docs/evidence/personal-vault-2026-11-07/21-glass-services.jpg	100644	453424ea1f7e6662bcfcf1ed639ec4f517ce3a01	b5181a3f06a0dafd70159ee46b6c1ce79b1b8eac16ae89979e50f64843a9c470	91969	0o644
docs/evidence/personal-vault-2026-11-07/22-glass-my-macs.jpg	100644	fd16d6c12a5c3050a9d3322cf55a05bbad1c0182	b14a97fbfcfd7d15ffc684d1eb29bcf6525f29806e6d5f344c70ccd11c9017f4	97482	0o644
docs/evidence/personal-vault-2026-11-07/23-glass-developer.jpg	100644	2ae72d35fc1ce67510b6917ec0fe7e1c5eb58ba3	f3de7520575bd0357eea61b5b974ca8c873a9c22726bdd7fc54939c2e76e2d0f	72690	0o644
docs/evidence/personal-vault-2026-11-07/24-glass-activity.jpg	100644	f6edfe418a6f6a48dd79bb610d1f67185a19fc04	3e24dfd6fdd925c48d8d8be7d7db73a7b50e9a9739e8c47958125618efe3d903	87930	0o644
docs/evidence/personal-vault-i18n-2026-11-07/astra-product-review-fe5d3fe.json	100644	3346e687c48b7d05a9b6bb4414840dbe7fa699b9	f722998b3a3507f1461910e757038d89635f8c36efbc25d34cc56d0267d52832	3940	0o644
docs/evidence/personal-vault-i18n-2026-11-07/changed-files.txt	100644	49f3b64ca7f2168b9b273657bc141b97a71a99e3	714eeb4c66faae0bbc8190f38b46155a0ef7b79a270f08bfe71897e53671023f	2473	0o644
docs/evidence/personal-vault-i18n-2026-11-07/code-source.json	100644	cea03bc0ff5f1bd63a08a00b01e7c48d92dfd061	303564177c6904ae55549617d838d4121386b630b8b345c203297bc631173591	49412	0o644
docs/evidence/personal-vault-i18n-2026-11-07/cold-start.json	100644	0c7da63aeb6a101077f964a051b1a6458e658d8e	687c517d17f0136c0155cbf0a9d5cb400eed628b4a3af3616dcf2b99002cbb9e	242	0o644
docs/evidence/personal-vault-i18n-2026-11-07/dialog-overflow-before-grid.json	100644	cf224130b55cc40ac53ed175866d2dc42443da14	63f0b902cfc6c2ecfac83fed01233208224ba78f480224eb82e80f31c5ea04af	707	0o644
docs/evidence/personal-vault-i18n-2026-11-07/fixture-en-add-before-grid.png	100644	324ceda6d9f69b490877f0b465b35e2f90678010	45015af97fb1b99d8d3a1489e622d363882b98e9d6a2b801d4526a185bf5e5ef	53644	0o644
docs/evidence/personal-vault-i18n-2026-11-07/fixture-en-add-dark-grid.png	100644	7f7e9fe765dbc6fb7e9c48189a871818dc218136	74b58fecc6f9cd1c96b0813da125df76c186a04e5328e22f4f0f10a7a90ee41c	38871	0o644
docs/evidence/personal-vault-i18n-2026-11-07/fixture-en-add-light-grid.png	100644	4508e964d63cdd39921ed6d3e386f184a6c99058	ea022e8db12cc1e21376e901ab03aaf69e4cb6ae6da8cf3bf1366af02f066cf0	41695	0o644
docs/evidence/personal-vault-i18n-2026-11-07/fixtures-64.json	100644	1178d9733c77a05a61e85c7341261c15580ee2b9	69cc893058f7d6af8f0ae7f474b3f6e3801fac8324e99626653045154d89ef0c	117066	0o644
docs/evidence/personal-vault-i18n-2026-11-07/fixtures-final-16.json	100644	3cb7be613685f0f2ffbf03daa2923e6b514c92bf	3d01be62a2718c22ff2226d1ed7a68e58e8ba713bed0bc51eb3588a7aa573ab6	24425	0o644
docs/evidence/personal-vault-i18n-2026-11-07/fixtures-head-before-grid.json	100644	93edd9194f6953ae7ecdf245f38fc80f7d44d51e	266dc2e24e031654d7c70620a5de123611f0237cd55152f17c9f0f0248558b94	5205	0o644
docs/evidence/personal-vault-i18n-2026-11-07/fixtures-head-grid.json	100644	16b2686acd7d65fb29b93cc4a171dce31300a8d8	7da5e62cee9acf9b5616b83f7ff07cbae20ae1169f2263d6af20b9db460de22c	20603	0o644
docs/evidence/personal-vault-i18n-2026-11-07/fixtures-recheck.json	100644	e280ae8943732f3ecde803312a3e4dd6cf10e950	1bd81853a43bd4996a041475e50c51e7e00b864344e287883509778670756333	1175	0o644
docs/evidence/personal-vault-i18n-2026-11-07/fixtures-source.json	100644	25cca62139c8dbb4fb56264c5a95b78d9b3acbbe	310078e8a7aeeb096557ad05cf4437ad810ea753a015e578570a9f790b544956	14075	0o644
docs/evidence/personal-vault-i18n-2026-11-07/impeccable-dark-final.json	100644	84f77b2a72db7c3ef9ac05faa81d185a7cd72233	7838bc2da409336b24a0b050f8c4938e11a248a92f54538b2f351076114aceb4	446	0o644
docs/evidence/personal-vault-i18n-2026-11-07/impeccable-head.json	100644	29d814ba5236ce30c707d2cf2898191ec008c9aa	cf02c80e4193586f2c441ce9e48bf43ea7f6986818e881dd609b24ee6e585b18	2047	0o644
docs/evidence/personal-vault-i18n-2026-11-07/impeccable-i18n-1.json	100644	6878b6f069e51fe18805786fd4868117167a5338	750271fc610dd9584900bd4f240ae408817c2cf66aff9ffb1c321bba7e66bec1	8767	0o644
docs/evidence/personal-vault-i18n-2026-11-07/impeccable-i18n-2.json	100644	84f77b2a72db7c3ef9ac05faa81d185a7cd72233	7838bc2da409336b24a0b050f8c4938e11a248a92f54538b2f351076114aceb4	446	0o644
docs/evidence/personal-vault-i18n-2026-11-07/impeccable-light-final.json	100644	84f77b2a72db7c3ef9ac05faa81d185a7cd72233	7838bc2da409336b24a0b050f8c4938e11a248a92f54538b2f351076114aceb4	446	0o644
docs/evidence/personal-vault-i18n-2026-11-07/linux/final-frontend-logs/frontend-build.log	100644	0faa21a6812457525c0d0cb39f7c39d760fa343f	4ebe6458a7d2e9933c4820c2959e2975bd297ee55eb84c3e9d10efe2cefbafa1	7216	0o644
docs/evidence/personal-vault-i18n-2026-11-07/linux/final-frontend-logs/frontend-check.log	100644	a247f178697043cad9c0f06c18ac685f20692b70	92bf85139b7c73c0f6cbbac8e3640b7550ba12a9a6cbcb9d2d7b8d2463406fd3	172	0o644
docs/evidence/personal-vault-i18n-2026-11-07/linux/final-frontend-logs/frontend-result.txt	100644	68e06aaf4f0f0ad7ea4a775cce33e1c26e36384b	5c17ccaba31e20abd7bac043c622517e39d65e625e9cd8a0b565fee95ef77ee6	97	0o644
docs/evidence/personal-vault-i18n-2026-11-07/linux/final-frontend-logs/frontend-tests.log	100644	42cd3a304697799e1254d28aff8161b621f7d9d7	25f967c0e5f3324d1d364f9ab0766c2ba57d580b117fdff89f6f7e1474c51c54	6494	0o644
docs/evidence/personal-vault-i18n-2026-11-07/linux/full-run-logs/desktop-result.txt	100644	b80cf608683fc19f564d29a0b6fb4fd2678ced56	f98f89ba89ed60fadef95286c228d979be4313b1e31b94833d22672e5ce83a31	59	0o644
docs/evidence/personal-vault-i18n-2026-11-07/linux/full-run-logs/desktop-verify.log	100644	a43aca74e2fb59eeb7aa0112ec0edf396e6bbafa	4449866af845b96c00024ee64115e0f3917b0779a567c68648bfc4f70a6bc802	55247	0o644
docs/evidence/personal-vault-i18n-2026-11-07/linux/full-run-logs/full-run-summary.json	100644	59d421baf7813089b73d2a1a919df9ecebe30a15	22c3acbddea0ea3f5f4d83aadf78c8213414788aef8cbd1b12bcb89372d36b14	832	0o644
docs/evidence/personal-vault-i18n-2026-11-07/linux/full-run-logs/isolation-metadata.txt	100644	f86d834fa99e454438d76de9937032fa811d4488	3b80e71f13b2086e4f862fe25516b9c316f83b7ba07641c8950c4664affdae1e	878	0o644
docs/evidence/personal-vault-i18n-2026-11-07/linux/full-run-logs/rust-result.txt	100644	04db1e482092d7c1bbb45e10f027bdcfbe00d6dc	c66db591494a3f0e78aa653307540a55eff2a5718baf7a75759b03a1fa657c03	59	0o644
docs/evidence/personal-vault-i18n-2026-11-07/linux/full-run-logs/rust-verify.log	100644	c64fe7cff66b2cd39400df487afe51a1afa43bfb	1d1e720f234b583682ea1c288c8d9d14b886242eebed8a5e4df4df182c30deb0	159471	0o644
docs/evidence/personal-vault-i18n-2026-11-07/linux/initial-snapshot.json	100644	5644867e609b1eded6c520b4e7b754087cfeda60	725d4c333f81f68c204892a903f8a0b08d0fc4968d5ebe2b13e0afd9f50ed014	271	0o644
docs/evidence/personal-vault-i18n-2026-11-07/linux/source-binding.json	100644	dbeeea9bfd3f6996a6f0cba6b08a1df851e70f0f	a4efbb53058d8a7350705da9e72130c108c47493069a16b7319b72367a987aae	626	0o644
docs/evidence/personal-vault-i18n-2026-11-07/linux/verification-summary.json	100644	7d59298ab50504f5e2c578a6b30c509ee93a2ba0	86d25a97ab25ac540f4b60af99d010a31c6adb27302e660da479ffa15c0d72a1	3563	0o644
docs/evidence/personal-vault-i18n-2026-11-07/macos-core-remote_sync.log	100644	56c46c23f2f08b77430626f59a4bbcfd29072c28	c7eb64237c3e92355f74ed59a9e48c34d9ee739853341b2b7cde233261c582bf	1639	0o644
docs/evidence/personal-vault-i18n-2026-11-07/macos-core-serve_supervisor.log	100644	6d2a8c50ce3c9354a35aaed026ab2a86107428f3	2ad0a2e913b0393849a99b3f8adc1e3b8977cfe36daec4ecf355681b143e0228	1003	0o644
docs/evidence/personal-vault-i18n-2026-11-07/macos-core-terminal_close_leak.log	100644	1d56b804e56ff4b1a762bfb24adb1f9352f565a3	e2f8bbc7e2bb46efb492ce16c7c4eeaa3e6b7736270fb54af33685d331198bfa	372	0o644
docs/evidence/personal-vault-i18n-2026-11-07/macos-core-terminal_pty.log	100644	8173bd5992b968ccc952dfb47615f8cdcd02eee6	e5f9db8202159496e48ad63e084180b069eee0e05d1c7df0ed302d35ad9fd6c3	822	0o644
docs/evidence/personal-vault-i18n-2026-11-07/macos-desktop-verify.log	100644	ad44dcca11838732b59e81725b95ed73badd4150	43c208db086f61895098ae04c20848478df840ffe931618b4845c9229210698f	30068	0o644
docs/evidence/personal-vault-i18n-2026-11-07/macos-final-ui.log	100644	ff230f4f3c5fcef0dfd54c43f84b5c891aab9e8c	9c1ef8fe233aa13bcad5bae14ce924d0cc86bba93182611ab4d4829365429b3b	13726	0o644
docs/evidence/personal-vault-i18n-2026-11-07/macos-link-supervisor-baseline.log	100644	8a52c105aaee1a070a1187baeb9c54862187912b	237a42897b976764b899b1105197255c31ab27e45388e3047491327ccc08538a	1607	0o644
docs/evidence/personal-vault-i18n-2026-11-07/macos-link-supervisor.log	100644	854ec0a852bfab1f3c4138b8d5056100ef675520	e034b8cf370224ab782357f231ece55c479f2b557a714ca2f7746dbf3fcdfdf7	1550	0o644
docs/evidence/personal-vault-i18n-2026-11-07/macos-rust-verify.log	100644	2cda1fc2c03e709cad9753df4a38b1446a3513f2	8f2995e35ed159b23d11cabf5e2d7e8abb1886abe4ac6aa3b4c545fc671e102b	160476	0o644
docs/evidence/personal-vault-i18n-2026-11-07/macos-tls-baseline.log	100644	60f5a6c069bb411ea8311e33ce0d9093cb61c9b5	5e4125388891e00c82308a5b5201ff847b11cbe8f3dd3110fb63797c0f2bfbfd	932	0o644
docs/evidence/personal-vault-i18n-2026-11-07/macos-ui-source-transfer-race.log	100644	efa8a42e1c391d07c08197c44dfa621e96cc2b18	84ea75eb1419cebd0f344dece27938e3cd0cc10179384bdbfbb645b2fa8c11e4	738	0o644
docs/evidence/personal-vault-i18n-2026-11-07/manifest.json	100644	1fa6480a7bea5b56d01cb6a348bf8af101045ed5	9c57d57d3520307be9cf43461e9c8115dd1f844c3211d6f8b6d27f15b5984575	9186	0o644
docs/evidence/personal-vault-i18n-2026-11-07/native-cold-start-without-vite.png	100644	d7d283dd4566ac2168dfd8939abfb23eafe5255d	e2115689250eabfc192346bc81762d344d4517ba90a23ff1939f2ba97139f24e	107376	0o644
docs/evidence/personal-vault-i18n-2026-11-07/native-en-add-small-dark.png	100644	219347e1660cfc510f4465081c64db8e4f4e2c8b	37744baf7e9d7e1ed488016bf07a695786063bcf2838c6bd5a1e40a5a5f30caf	156049	0o644
docs/evidence/personal-vault-i18n-2026-11-07/native-en-language-settings.png	100644	aea8c7856567257143d5d4eedef661613f91aff7	d96baaff0bb2cc2f5e874f879c4ce9b89c7edb712a328fcc1fd56a78a691bd50	258600	0o644
docs/evidence/personal-vault-i18n-2026-11-07/native-en-vault-dark.png	100644	cf096c347d5557caa06d66d667099d24665de82b	aed9a5039510e1844a37c43f2b90268fcdf31f99dbb7baa24296c4d8868fd29d	250716	0o644
docs/evidence/personal-vault-i18n-2026-11-07/native-en-vault-light.png	100644	9afaa202a26dcc5e3a6382951634056e650ff604	071085ffde182fb8e5d304d575ecdd9ff5c9bd7a075b3e7ba794923d387bdaa1	253173	0o644
docs/evidence/personal-vault-i18n-2026-11-07/native-ko-locked-dark.png	100644	856f4df93b9dcf5fb67ef8a7f0ef0b8e66140884	641e7b95ea85dfea1baa9ef40629f530c06914f9ac0194e4b5323cafc8129b76	85056	0o644
docs/evidence/personal-vault-i18n-2026-11-07/native-ko-vault-light.png	100644	6c8bc5dc3c7d00af6b39cafcda6f93c737943218	2f0df3dd37487d05c867c609f5825cf299ad75be00a780870c6195968b808c93	217237	0o644
docs/evidence/personal-vault-i18n-2026-11-07/production-guard.json	100644	b94fec1025521213fd35e0762345dbb8e154ea0d	72680499b1f5790df3e3cda785f7b16991a8f476f307cbc1356b1ad2f85c3c3f	153	0o644
docs/evidence/personal-vault-i18n-2026-11-07/screens.html	100644	7eca448bb4ea4393e2f34d154697fdb8a02eb7c8	1adec4053cd8be5ae1bf38fa93b80e03ce6753faeccaff3d80a488922636f531	2370	0o644
docs/evidence/personal-vault-i18n-2026-11-07/source-head-grid.json	100644	c1a82027f684eab23a852da7dafca58ed8d9e71f	ad366c9445ac30957b8dc8f7ce3910ce466064c778d1a1a1d856504da9cee28a	14150	0o644
docs/evidence/remote-sync-e2e-2026-11-07-858ddc/README.md	100644	40f16864653f165e01293d80fefecac617dfb5d9	7ea6651efa6bf3d5b2b8647045fa056d3b2516c02a89f2e9b462e0c9417d8cf0	4070	0o644
docs/evidence/remote-sync-e2e-2026-11-07-858ddc/assertions.json	100644	ccfaab352c439f124e77e56f88187401c6a12432	2f0b5f8c77f5bed8388a79ba78b543319ea62e05049d5eecf883bf8417b882f5	6497	0o644
docs/evidence/remote-sync-e2e-2026-11-07-858ddc/manifest.json	100644	ad84a7fc6dc9f9adc173ea22cabb456331ee170d	c3096bd320338f1b17c9db894eb35e70697bd906a347f96deb90daf72a9ed66d	1542	0o644
docs/evidence/remote-sync-e2e-2026-11-07-bd-4af/README.md	100644	a7be2eb54223df632f59dd228142cebf11f87fdb	a57685d45a3373761db85ae4743c53f35a083f59a3c61ff4fef08c90fe48b8ec	5746	0o644
docs/evidence/remote-sync-e2e-2026-11-07-bd-4af/assertions.json	100644	08febff026242e16ff683bc89eb407922c9fee66	07ae4d16876dc18afb3eb61e74bf9711a7ea52ab57fa99bf6e4cba18509264d6	6497	0o644
docs/evidence/remote-sync-e2e-2026-11-07-bd-4af/manifest.json	100644	339638f29e25f4f6c0e7eca8d49a36068307061c	8dce24abea0bf1bad752048a462da7e02fcafc5a1c50b61d88e01a803fbe3be9	9719	0o644
docs/evidence/remote-sync-e2e-2026-11-07-d77-f544/README.md	100644	0ccc288553a99779c0fbda42f724687fa4c869ff	ca3f799c32d148fd0ba313e8ca11c44841a899d68e9e983d970aeece2e1d252b	5009	0o644
docs/evidence/remote-sync-e2e-2026-11-07-d77-f544/assertions.json	100644	ec3a633a8fddbed8151c7445c6825d9c4e59ce3e	f53219ae6f6420f0b61aeea9c0faf844de4050543d2abf1e20dd0a979f72fb96	6497	0o644
docs/evidence/remote-sync-e2e-2026-11-07-d77-f544/manifest.json	100644	23aa5ef5c9fee411dbe78a38318cb349ccc7a325	68da749f86794137698bdcf39195e5051cc4a20e42ea14019379a9115be4c334	2417	0o644
docs/evidence/remote-sync-e2e-2026-11-07/README.md	100644	0bdc3a7bf4c5fd606601b850f4e80cc9a8c7e93f	ee71a24b1629df1067bfb2d762ab4cd6adc675f3084edda41cbbe1c8ea81b03f	7336	0o644
docs/evidence/remote-sync-e2e-2026-11-07/assertions.json	100644	1fe4c68ca91102523417904603b83239665b732c	5b7587e9887fed479cc98d7c244866182463ac6e55644378c391cebd9c9a4da5	6497	0o644
docs/evidence/remote-sync-e2e-2026-11-07/manifest.json	100644	44d2c039f1c20bafc6f7b75d1cd75d51f9d68760	0973ed6ded63ce19c18cb5c2e299f482de75ba7013062e12a382107a4cf40bf6	1463	0o644
docs/harness.md	100644	5cd902d585e7d2103f8f50d24a3d36b885b7cb7a	feab029523480dd8f1b7cf2c969685de5da52f8f96531ccafec6668ab446e6f6	6219	0o644
docs/implementation.md	100644	0571514346fae5fcedf5598f39f34c4a14bdb043	92e9cb351129cdfea80f8f4ba9aa58ecbd32b7279314ce233e52844a3a6010fa	36899	0o644
docs/local-validation-2026-10-10.md	100644	50c4d02485eafbe7945d82830f8cb53c960b086b	4229b4d9026a8598d597af570d53c472d402011937cd90891ccbf7623e4316a3	5313	0o644
docs/onboarding-artifact.example.json	100644	3869f5060bb8c76b8e64e1d5a5ba977fe36a00ae	1db0b93e1b6120fd73a7a16b93758c4cf3fdfdbe3208fac6c7cbaa9019e3b12d	292	0o644
docs/onboarding-opus-test-2026-10-11.md	100644	4b7fb0c7c514bc3590cd69b46e083ed48c6d9cb6	0d026767464beffd8d0d0dc98ecc9d7e4474d5327da5b76ab0d6e823bb10e5e2	5543	0o644
docs/onboarding-policy.example.json	100644	08c6a02d19578befe46f5adc049f54962dcd1293	35d8cb787acbdfce0d3d70c6c9597cdb7a4ff9237e6721382f39b4d90cd3f782	1395	0o644
docs/onboarding-schemas/artifact.schema.json	100644	5d12ca0f2c1fd749883f81bbd1e1b0d0d4dd9213	45b3add2321d7070c288a2220224826742a00adf233d2e39c7392a53a170bcba	1318	0o644
docs/onboarding-schemas/install.schema.json	100644	c26159dea5891c8684203acec9e6caf1033c2154	6984fc1b12f73f0c65f0a13457d1e8b946339d5344431808aeb3ff9d52b2f4e2	5792	0o644
docs/onboarding-schemas/local.schema.json	100644	c93be4bb7a0b1b83f9d74f494e0ed54f0f24f3ab	e14366428739cbc431b5b0788bb0960dd7562df968372cd9a0785eaa2d5109dd	13700	0o644
docs/onboarding-schemas/pair.schema.json	100644	bd91b8db7089df28ff34da149aa2861d3edad656	f2649dd01dca410411e2e0806c1fd3e05f16e88e60b99fc4a47fe401fd85bbef	2208	0o644
docs/onboarding-schemas/policy.schema.json	100644	755b83b77591ec9dcc93fb126bed64ec0baf8cd5	fb1480e704f3547429c19e2810b3f262331b617019162549185dc1502fd17c64	7025	0o644
docs/onboarding-security-improvements-2026-10-11.md	100644	ed044cc7ea0d642acd909ea2e9c450a8ed353660	a88348b36d32425da56601ff945d75b1c15e02045dde1fd0a190b1d4d6226b30	7968	0o644
docs/onboarding-validation-manifest-2026-10-11.json	100644	01f312241eddf6c3f656c23bb023899205cc51e7	8166c4771799ff1de1396e10d43cf7573c8138bcf52bf8876b20b42a0284aec2	7090	0o644
docs/onboarding-validation-manifest.json	100644	3eac05d0a88a27f85d84f70b6335085f2052f129	23316a28d5db9b3c008872fcb5c01cf4f36606ea4539966a3963ad872e796e13	7254	0o644
docs/onboarding-validation-v0.2.0-2026-10-16.md	100644	58772cb9dc8ba8dfb35c4109df7af73c11bfe870	952990c18d73c98e53d961f8ed8f167bc726b96fbd75fa410867d97cd0ea1f99	10539	0o644
docs/onboarding-validator.ko.md	100644	aafedfb5116b08c09efca03a187cd66a081604a0	33d1996bb1f5edcff2c1cc5ee5d75c6c39ec2342d334c541334d28cd19f258f3	8974	0o644
docs/onboarding-validator.md	100644	80c4c44b6ec5487e49b2c81ac287882588a0569e	b6ba2c0008bb01a73e6ff4f1360a2529f5013182795dcc89ab9ce19d4bd9098f	8687	0o644
docs/personal-vault-frontend-2026-11-07.md	100644	72da5c929e5f4ec2417359fcd95bc5b60fd8f97a	e88b74c8c05c46395246ff57231054e624a86640c634e7b31d3f383596dec54b	15220	0o644
docs/personal-vault-i18n-2026-11-07.md	100644	82f8639051088f860cd7febb60af0eae0c6bffea	2d712a610c4d6f5e560fe535c7de6761e1975714f52331dd0b04ba58a7b525c6	14285	0o644
docs/product-intent.md	100644	d09a34aa7abcf839e792ccafbfa5e484898858d3	79dd92c5459a5f76180810fabc02083e4f0d19bfa4d9e44a14ea9e98dfc8020d	9048	0o644
docs/publication-audit.md	100644	e1dd425ac5a543cf615fdd5464836c99fb1facd5	90b89993cd76623cee420eaf1de1ea9194bea9ee3fe98c4808e3fa0cecbb7867	5741	0o644
docs/releasing.md	100644	ff5b036e3da43cb70a89371210cf6fd3ddfe3a96	e111c4172856a52bd0dbfde11076c88612c4dbadd1486369dd7335cb9e4468b3	65697	0o644
docs/remote-sync-next-milestones.md	100644	a9fb043066ca16cfa929deafdc0aad2cda55cbd3	42e813c846bcafec30adceef6c41e57a6571393b73b54181e9432ad5010bf8d9	40803	0o644
docs/remote-sync-turn-checklist.md	100644	d295091221b0010787dd2ea6f31012454678a843	c60874adf0ce15e1d8b41926580767c31f3d2edc9e286e6c1259a928f649369d	40735	0o644
docs/remote-sync-validation-2026-11-07.md	100644	cffb252ab841498ef835875f2acd99bcf4d942ab	f7dc90275cf35705110d3d1f20f07ad8bfdb00f8ba5af551ccec001271add187	55908	0o644
docs/remote-sync.md	100644	27b1844be754282c5327030ddb3c8d9062efbce4	78a4f04eba221380d34e3c5991582fceea7b373d5d68494cea7f31e2f0564b9a	10414	0o644
docs/reviews/2026-09-12-auth-delegation-delivery.json	100644	6b2dcbe1ffd1916e9a448c8ccee83b130a53259c	7b52c68084a11ae98e86ab33b91133aeda5a405813a73c22b77218526210cd8e	2781	0o644
docs/reviews/2026-09-12-intent-alignment-once-inputs.json	100644	5840ab8320f99a41ee31d4c84064364c9f9d0c78	a335e8cda4fe91418733087b2a335a575380a78fb49f911f454f11aedd66b6a1	1757	0o644
docs/reviews/2026-09-12-intent-alignment-once.json	100644	84efdc8b79adda00f9b8eedcbb0366a80982806c	f45bb0668f0495300069d955db8b5cd62cbc396701476fcc95f80c760d1e7169	6164	0o644
docs/reviews/2026-09-12-intent-alignment-once.md	100644	af65f2696367103b97765388d8e7cc6be0235dbe	0dad9f6b8505e0f320ffe20629fc9fec13fb90619954d953c68a0f98fa8d1479	4035	0o644
docs/reviews/2026-10-10-open-source-opus.json	100644	0b061b9be47706930f09e974d4cd50a487c8ac56	ab5a4efe4694d9ec6669761305dd3b336ddf08c9c789c9043182330d4bf6597e	13304	0o644
docs/reviews/2026-10-11-open-source-opus-round2.json	100644	71144119b0c89913ddfb3be09028c52d7e1f1b82	7ea1850190604069bc6483501947b80b9cd73ddaa60a22852ba5ec2f5c385916	17944	0o644
docs/reviews/2026-10-11-open-source-opus-round3.json	100644	857aa4c34b5ea044882dbb5a65bdccc7ef864b62	5c5553ed069d4b38b8023952ec8a447f27d16bea35d6233943b6657c8ca42823	20069	0o644
docs/reviews/2026-10-11-open-source-opus-round4.json	100644	cb80b4a7363c4c3ae064017edfb4a2f578ba7fed	fd7c454413d3c131dfd21a0e3407eddbc3d1689f13b5a32100d5ae6beb443c8b	17722	0o644
docs/reviews/2026-10-11-open-source-opus-round5.json	100644	4d10547d5f53cef9d8024a40b9e7762211f7152a	c65184fc4eb12ab0011d129ea585898b4bc5e4bf2c70c34dba249b831fda7362	18674	0o644
docs/reviews/2026-10-11-open-source-opus-round6.json	100644	f722d00595c5fc0d3115d0e3b92687cc5222d0d2	5cc5f19f582b4be99374d2068a922b154666201476458787b285a46d4603ea2d	17707	0o644
docs/reviews/2026-10-11-open-source-opus-round7.json	100644	0b98459056aa651632aed22762785609f348bf27	bd314386b3223d73a824479ffcf0fe4383f20501b17fc255f6898a9c59d320ab	10607	0o644
docs/reviews/2026-10-26-desktop-linux-full-rust-steps.json	100644	c2b9ace9206928245a710eec074fc5956db5eb73	64b4f218f76b4ed568e53a4f5155eecf56f143c8054dd78c15514c8c37488027	13018	0o644
docs/reviews/2026-10-26-desktop-linux-pty-evidence.json	100644	0c953d3c826ff5ca6727371d70a425aed2a2f219	1c9c3eb8117c75cb99e705987b890c225c68ec8cfe9738d52862a14a5c605048	6359	0o644
docs/reviews/2026-10-26-desktop-linux-source-260.sha256	100644	27f618416bc2f35a240152292e06580a4b0ece3c	7d91a115ea273b5b185a2afea50730036fe4a423f86d99cf2261aedd1e291d86	58332	0o644
docs/reviews/2026-10-26-desktop-linux-unchanged-rust-279.sha256	100644	1b9aae48ce03fd5bf45fcfed709b6552c9a2cc43	38659d06ba3a645360fbcd207192fb38bfa2b1a618baa7d54e45675f977fdbc8	30028	0o644
docs/reviews/2026-10-26-desktop-linux-unchanged-workspace.sha256	100644	a9b8a0e6947f1f3734efd2b47173c75c98cba2c6	66a3a2bf4eafad75bf8107d68915ca4059225e0898b223f32532b99106280a2c	174	0o644
docs/reviews/2026-10-26-desktop-linux-validation.json	100644	9d0aff104ab5707004800852e7d5ac68400d2f46	7fa9ddd4ea5dd05851db941f3be7267eb5da99ad5fcb5edc39924671fe9b111f	22007	0o644
docs/reviews/2026-10-26-desktop-native-linux-clipboard-fixture.json	100644	4cc4d7e09957110f87e88a2d930bfb84a0c579cc	83d99b6c42946f00e4dccc26ca0208b9c68218dcaaa9b3e9132d0375f274fe0d	463	0o644
docs/reviews/2026-10-26-desktop-native-linux-crosscheck.json	100644	208401951fce3b2a91afe7066c8ca934b89cbdc6	e5bf487a4284540dcf669e15a2100704db9cefc544752c6eff7e232ed5a423ca	2918	0o644
docs/reviews/2026-10-26-desktop-native-linux-final-fixture.json	100644	a9699c501f372e416a1912d87ece29ff8f461160	854914a66ad0d10ffca3fa6be171ae5b5dac8f6b26d2ebb532087cacfb5fd93d	344	0o644
docs/reviews/2026-10-26-desktop-ux-linux-final-ui.json	100644	08ed734f63c1afbc0ca62cfb7a68f926b3326d42	653c55b42b7664d6a18ae62749a8fa024eeb2bb493a8b6c29f27eddecac9639b	6026	0o644
docs/reviews/2026-10-26-desktop-ux-linux-native-crosscheck.json	100644	452613954d2f9b270c7777e3a7a5c3d26fb6c7b1	ef9f024fbd29488db3db5ed4d13ed83d2c10f57e88bedc1712275248db8ee718	1677	0o644
docs/reviews/2026-10-26-desktop-ux-macos-source-manifest.json	100644	96e6ad69cce3137d7d8d0928f00a5a8434775fa0	18f670ad42aafaa2e87afe8fde98329fc9b6524c43761a6b4909424af8e50913	61095	0o644
docs/reviews/2026-10-26-desktop-ux-macos-validation.json	100644	1e0411f67ac11bfa99db6714e1063a3a143be8cc	df8dcec0b5b88b52f5ce7a7c81175f190f9bb1179cc89ed658705835899744e6	5889	0o644
docs/reviews/2026-10-26-desktop-ux-macos-validation.md	100644	aad9f760c913c9b1d9646502070db565a8e95a13	e9f7357bb0ed3167490569806d9423c2f922552262fce4fa4a42830991c29b43	5565	0o644
docs/reviews/2026-10-26-desktop-ux-opus-round1.json	100644	1c3e4074b09f34486b8cead1c8f0b9619e4b62bd	dc9d609e393e2149c15163f69fc060d3665285e2a171651ed4a978808cd0aa1f	13820	0o644
docs/reviews/2026-10-26-desktop-ux-opus-round2.json	100644	36d859a1ff1599b697833d1304198f38c91a392e	b280a761c07a923ce67cc13808e5050742416776122f7ec98a4d277789099e78	15532	0o644
docs/reviews/2026-10-26-desktop-ux-opus-round3.json	100644	9d7e1c829887c0914cca2d207b0217379180f672	528748fb349a3e6950863d7f2996d355c70198e5f13c1ccbd4b8f0c62f162192	11705	0o644
docs/reviews/2026-10-26-desktop-ux-opus-round4.json	100644	d7d54e6d5921c447f6948c5a3df445a508425705	056e4d27666ed74cac662530cba40560f4326c4d7fe585caa32bc65d6f6bebd1	7850	0o644
docs/reviews/2026-10-26-desktop-ux-opus-round5.json	100644	f5085e8abc8a5a260bec92ff4b9740ad8b79a5b1	9fc2b6c740c949a545d95c0919bfe5b320fe21c4b013fde0509af556390c8f7d	8192	0o644
docs/reviews/2026-10-26-desktop-ux-opus-round6.json	100644	78fbc2ca658f39ab2df29f239eda0db401f85b1c	32bbbaf849097ee81369e483cb8f5b23b7c0406ba99fc07ab54afe11b28e7278	11075	0o644
docs/reviews/2026-10-26-desktop-ux-opus-round7.json	100644	841791c32cd77a245f6d8b2a8787d6b0cc4722d6	d73710257b46d8c63337749c938410e3e0baf8a238ed47f82b203c82387b2056	7418	0o644
docs/reviews/2026-10-26-desktop-ux-review-manifest.json	100644	c549fb17c0350a9176e7373f3a193bd56690126f	2a1fef53d3dc1db1073b0305efc6a9f34517f8a4c72bead43a889c0fa5ac598c	16380	0o644
docs/reviews/2026-10-26-desktop-ux-source-crosscheck.json	100644	1268d0c9a023520415be6f27fcd78d8d3eb21970	628a0b0c9df9018262e40b3916689e188222125ca291a97473bec9b50b2e0990	2861	0o644
docs/reviews/2026-11-07-link-ca01275-opus/README.md	100644	aba3c47aa8fdf7c3bd832130e8ff60b6baacfd3c	62cb9a032616efce414e2eb798ae707dbe02c1f33c7ac730a43864949647fc96	2672	0o644
docs/reviews/2026-11-07-link-ca01275-opus/report.json	100644	05099e0975cbb58d0b78a88b423167498349e77f	81e95b6a3665607b510f0cc77ab5cdd27bf78ed71f4688faaa94acb8a3e50c90	21221	0o644
docs/reviews/2026-11-07-link-ca01275-opus/report.md	100644	f917a4d9e8019ea010ce444048e59925dbf819b6	63c400a776a51ddbc58a1c33d2a6260a9ef78421044a8a1514d79053d30a381a	33400	0o644
docs/reviews/2026-11-07-link-initial.partial.json	100644	e2223443078002437d85b0da1987c3e52e02bf0c	d16fbc727b77d21ac096b07cf162a11793b037ba6eeaa2b3801e6f35af350516	49059	0o644
docs/reviews/2026-11-07-signer-bd065fc-astra.md	100644	e6f99e01aa9bf977278075dcc726040f996f5534	7ff4e0a3adbada3a8f87af8ba364c68a5130e3d3f2b44330957c6e98e2b48801	5071	0o644
docs/reviews/astra-cleanup-control-addendum.md	100644	a78b6b748e31ff4cbccfc9891af92e68eeacf5d5	153c95d3dde945a81b7757d1e592149bb97e068ae3e9af00c470859ed7d6d10a	1273	0o644
docs/reviews/astra-cleanup-publication-order.md	100644	bf62a01b50fdd5a842dbc679a0b5585ae96fac11	28908ae72a7dc148baca071af79bbe9b384fafa771cd0202a91787d2fdc071d8	3855	0o644
docs/reviews/astra-cli-runtime-round2.md	100644	c1f3b75de515fe09dfcc2972e2fc217838ed40c7	c6b654db3ecb8690fc4b7a3357d8c6160589685a0eac6e62a51a5de39348c904	14073	0o644
docs/reviews/astra-cli-runtime-round3.md	100644	43910437ec986af52ec3f62ae1037d5d81888d3c	06cfd48efa251f682743d396c2393d9a238d2bb3d14f86b1398615fe272c903a	9750	0o644
docs/reviews/astra-cli-runtime-round4.md	100644	18048a3bf7ed0e791d5cdff1df474aac991b4aec	88165efa50c6ea735666ffdec354ab283a9b619526355b80f06fae2aae554b8d	9378	0o644
docs/reviews/astra-derived-pty-assertion-addendum.md	100644	ef9f4ef206f9ec7e40a45d87e278c9d01ca9c7b8	17302ddebcf51df1bda4fa6c3a7e3a22fb09802f80811b93fb25afebd9b07d10	2541	0o644
docs/reviews/astra-linux-python-tty-readiness.md	100644	7cd4c21ad0b167052a2fd7fa3ab88f17fa0de723	19b61431c1cc3c0c9c8920c3f17821588eb7efb28c38315c8cd17c41bd0057ee	7669	0o644
docs/reviews/astra-po-acceptance-checklist.md	100644	1feb9a7b3684862c270de782f84aa03fe2cd14ba	b0dbb7dac114cf7c9223c5c9845f2ae81a8d3d3094f056df88ae503473fb7548	12029	0o644
docs/reviews/astra-projects-and-signal-addendum.md	100644	7c50c6b2c5d63aadd4d210e0d064ed11a84fee3b	06ca795f81acfec8ff6352f76b3624ba9ce799488134a1a41f7dd7f7a5db44d4	5376	0o644
docs/reviews/astra-pty-linux-second-triage.md	100644	734f7c36e911efdfdc0c5c0cc8d0291758a7f1c5	b1206e97622424a7f2af2847c7958b06d84a0af812859ffdf531b9b8d3ede0c7	4098	0o644
docs/reviews/astra-pty-portability.md	100644	660313d683b21489797afe001ea26a16842b9b08	8261c6695b705d822f1240739a0dfb595e10454c1e415a2d44ed49ec5d7d3d3f	3396	0o644
docs/reviews/astra-pty-timeout-diagnostic-review.md	100644	b1bc1bf3f7c272799e12f8707242dd6eeb892975	6644808042fa8aeb23746b08ff43218cad3ddcb0245c9fd23a2018beac37dd96	3390	0o644
docs/reviews/astra-response-acceptance.md	100644	4e19b31a820ce1c288a44705aa7ecfaa980750ea	2d0145f6cdb0d5aaa813f8909424ceb5ee2179e28477e5555cba4dd0e6cbe45c	6170	0o644
docs/reviews/astra-response-final-recheck.md	100644	cb4f82343b62aa946ab53e676de1e4a14f482fea	9dee7a4f565077d088dc93d00d8022d7fa9b9ba4755f8dde8dab344e31b9a68e	4361	0o644
docs/reviews/astra-response-final.md	100644	b1513af42818f2fe1c0480f1d6ad16f388495095	99d858a1371df298e3a61a52cf3f16bebb343efec214944bf9a441453578cfc9	5635	0o644
docs/reviews/astra-response-round1.md	100644	fc85e6d4330aa6e27d9c1dfb02d8c0777c71fc35	ac6d781ac4ec9a3b507b2391478680dfbec8be2f0253f580f3ff587863e5fe7d	14629	0o644
docs/reviews/astra-response-round2.md	100644	b6a3c72df5832f1bbe0b71f5411a3435f75efcfe	0c360e27e9a052de194a7fdcd8005a03590955e5b533ce78de7548a73f647894	12100	0o644
docs/reviews/astra-response-round3.md	100644	bcba8495c20c5cfa7bccc87522541a4e548dad7c	f9b3a6189e9c7f2bc9a6d0cd02ebcd44d60ca754c66101fce804b0b9e3c2ee1c	11741	0o644
docs/reviews/astra-response-round4.md	100644	5fd9805b8582b343d5da11eb7e92f59c3b3d60c0	2246a0b542687132dd11f54a02ea1ff4cbe86b19648a8df367e07aaaead71113	8766	0o644
docs/reviews/astra-run-context-lifetime-review.md	100644	497729c924eb288eca4ad85db06bcaf56092d873	e4d93eb9cf81e9a04190be04ed397d4c06d250f8d65da2c1a8a1a77ea1b0d182	4054	0o644
docs/reviews/astra-runtime-final.md	100644	774e5293d25fcec7af9c58f47c77140b6bb0b070	f1f5de83820bd12c31815e08b141eb4596a5455618e832e397170adba4220962	6143	0o644
docs/reviews/astra-runtime-round1.md	100644	136188212c420e928182a15c66f5b48f3d215012	52cfc2fea680c841b339652a9af165c51888f944c772096d7569ecba0d37c828	8714	0o644
docs/reviews/astra-serve-readiness.md	100644	5afb88d75ddc11b78702122e064a7da268c82306	30462a40cf8173b628ea85474c2e05f12a0e7d4700cbd778a73a1c74a9b3a3b5	3275	0o644
docs/reviews/astra-sigint-cleanup-final.md	100644	6621500ebe59cf5ab45cebe37be748ebf7982b84	bca286fe951b0672e245df99a7a134e6e885882e9a7b0b054fa19f90d371d310	4937	0o644
docs/reviews/astra-sigint-cleanup.md	100644	05513d0013fcdd22ee820ed757e6c37c75d6d83e	1ed1bd13f703cc77de4379044179e0cbb362ce7d7ce74e48d419a2d44afb5cdd	4384	0o644
docs/reviews/astra-signer-terminal-wait-review.md	100644	f3c2621e1dd8cb6bc697f3cb483bac29c915e045	5a6175b75cb1762968a00d3c4907acac0c010ffa7714bf6d350c9e83e442ed79	2641	0o644
docs/reviews/astra-team-ci-triage.md	100644	53a2fbec5e66b699036c93e2fe89486367d84f44	a390a6e4a2022ec788ecc8e5f826809fc49bfb73405edf240ea2c9aba7a89f17	5853	0o644
docs/reviews/astra-team-duplicate-fact-finding.md	100644	7bfc42d644fad5e6c94a6f1ac704821ea5731b7f	884a70b9f1ce89b8028aaf588d634fdda78c6b459d218a6c52b00316ae84dcbe	3109	0o644
docs/reviews/astra-team-fact-catchup-final.md	100644	7a46fa8ade9591d4826629e659e2638afec03d42	33aaccb83934c85b6d7c0690d082c4b225ce27140b3282a56203154b57edc8db	7745	0o644
docs/reviews/astra-team-fact-dedup-final.md	100644	da0bc4691582bf79c23c70602624ff9cb7572c30	899d32ced07df445b24934bcaaf5298d9f096cff1f4425a037d0d4c73011e45c	3719	0o644
docs/reviews/astra-team-linux-signer-triage.md	100644	867b5af469b7cf68cd44d69ce3ee706764609ee0	64ddb114895d58701e9744a316e8b2568ad47d5c41982a9461eed32548fa7f66	5793	0o644
docs/reviews/astra-team-offline-fact-finding.md	100644	92f7fe49549abb476c8f2874ad758fba7ae41234	928e6f5b5f9db1c0bc502b2e63b024dcfabc575692ab17b3a45e564a09f79cc7	5248	0o644
docs/reviews/astra-team-refusal-callback-final.md	100644	cda7da9b409dcf1e035a0b6c904e4c5142924c6f	1218f166688833c51013d83b3b6c02379a01c670ab7af297e2aab225bba4d926	6668	0o644
docs/reviews/astra-team-round1.md	100644	2ee98b86de09a23e50156fc6102ba63e53c8bfde	6345ed2514aafc3b41cea4d0d18b52dbbce33bcc1a943a4bfdec75f0b92987c9	11487	0o644
docs/reviews/astra-team-round2.md	100644	f17600ca5330558b467a4a8041be5a799c70388d	259b25835f7e9f13225898848dd31eefe024e9037cea9b711988de4b9abd6c67	9110	0o644
docs/reviews/astra-team-round3-partial.md	100644	aba1266d8426b4e48a08a4d420f3fd0b20360319	22fb8b10fe6f351e6f4a2c15422e6ec2138664c1c2fee283990ac505d86b615e	2410	0o644
docs/reviews/astra-team-round4-addendum.md	100644	46ab4501678c3373d942587d9df01f4228407c71	9852117cb5731b0203dd0183a171f3fc3b6dfa5090d88158994a8528e5bd400a	3291	0o644
docs/reviews/astra-team-round4.md	100644	032d90b44abb81f3da34c59513bb61f7ce2ce8c5	2243d4ce9495b264175a718c4e78c37a82110119a83328bea131c07434b0200a	7201	0o644
docs/reviews/delivery-digests.json	100644	989e0202bd16db113e1eb165cc10615d4161e283	959cab4986e22be477e2edc67b2db159229b1b71e76291679e48f73ac402208c	502	0o644
docs/reviews/native-cli-contract-round1.md	100644	601532de68dbf63a7047653f8485350c32ee9d93	bd62d995e59a00a32315d7af7eb3d1f3b1e95b1227acadf1cffa1a67a46f84cc	5041	0o644
docs/reviews/native-hostent-proposal.md	100644	5ede13e793434bea455144739f3a30cc8737825f	3afd8b3ed3faa06a94c0fee2f44c7f06ecc6ae76fa0ba21fa07a2e18db5c1730	13681	0o644
docs/reviews/opus-final-input-digests.json	100644	18a0c62c92de85282b59a5aee5f42676eb201672	e0fbb6a1029b990d4b22bf22fa93b5e7bb61ccc9a1c04feb43090952ce25d099	573	0o644
docs/reviews/opus-final.json	100644	70d04fb51fe823c18ded52f4ad449fc86e90d618	db636b81a3c13f6b3cd567155659c2600de309e01c8a1766c39c01e2575d9dda	8383	0o644
docs/reviews/opus-final.md	100644	d2f15e586bceaffbc383cb42a296b16c6478fe0c	ec8969ae56aee07469ed63b4bb118c5a7fc351c1222c88e5a7142fc2c1e7dc00	6184	0o644
docs/reviews/opus-initial.json	100644	fb9544b6f6e9e69ed7704b59ae1930d6e4c3e418	cfc3b5263c5f884772d16ba460c06f1ecbcd0c10cafee4a1660f732865b7fcce	14058	0o644
docs/reviews/opus-initial.md	100644	902bb4adc067613fcab7963342c7239a41229d3a	c52416aba99bb8b548cadaf88d1574a18c21241c777987c868c306ad1b9fd010	11791	0o644
docs/reviews/opus-revised.json	100644	2508a85c2548fb5dbcda552f433c193c6d5a461a	db93c0196233a452d35002872e8f7a177e13ba3b82518ff4d44b43582625dd1f	13127	0o644
docs/reviews/opus-revised.md	100644	c99496b2c67ca5d661dfcc9fee4bccbeee4fff2c	7676eea79eddfb2b54ce0d17192c00b8781fd588b8284ed8734fb0b7a586d478	10862	0o644
docs/reviews/review-summary.md	100644	f87c4c9449568346d76a442ac148dbd637c53750	1175d77255d65d78fff4e1d3200e6d8b4aa3f0135d3f1e2d1c875f5c7b97233a	2325	0o644
docs/reviews/revised-input-digests.json	100644	b6bcea20a5341a7b5dd0a494f3377737a88525fa	7ed2c1f799472680f344b8936f9879df499373bf8e1993e3bb4f0944a2498669	469	0o644
docs/reviews/revision-response.md	100644	c2b4068bfcf99997e6e28d01570e4c87bd0aa426	c317a043ff4156b1e63805d68229f8cd8d9fbc82d08b138d2be2122fa96bb451	2563	0o644
docs/reviews/source-check.md	100644	319f25bb7363eb6c74708994e5de3decf05030e5	5e3b276e040c1e744ea86c1d42d395ee38eb971d741ae8c70b4a1f49452943c5	1758	0o644
docs/rust-completion.md	100644	a04d74cb8583b90aa745ecf67a1d15dc91dafa98	2c232f8c01d6890a4cc8332b06b2b5797486ef15457e59724e027991a5210b7e	4835	0o644
docs/security-design.md	100644	3b2d4a6093a1a2b9158d9e0417292910ca1703bb	20a151a1b563a8c6a6c2ca3c1c2caaef0a27b098764cd01deba208f14ec036d0	9731	0o644
docs/self-hosted-runner.md	100644	aa2e1da715c36fe2767dfbeaf76bea3a3a0ae72a	d3f8f6b43816b6555b8608109072e98aea9c178c73018f6d427cce599d0b5ff4	2934	0o644
docs/team-agent-prompts.en.txt	100644	76eee2d023fe8a5757bf5e878e3481dfe9080023	2d30c2a89b2c9ec780ef806fe53776c28f18362c29369ec4d9d9d60d88d0e4fd	27845	0o644
docs/team-agent-prompts.ko.txt	100644	421f0ae0477e8efbf7d358026dabff8436fd2c75	614d3935ec01bad1f2ea208bea1c122d5acf9788ab382ccb772d1717786a3ca9	29961	0o644
docs/team-onboarding.en.html	100644	1ebc683a18cc8623922dd658f201ebe793c0e5a4	ea4e7d1caed0374970f343fe4c8d9fd11240257bd8ecb1945292e7c7f0bf2a0b	51489	0o644
docs/team-onboarding.ko.html	100644	feb05b1399011b0059337ffbe8e52315c876c659	8eb08ca36f6f759051ac6d9ece83ffef3ee1093cf195ddbe0c2393791d19c505	54995	0o644
docs/team-sync.md	100644	5fcb5c163af1f549af161df5efa75d6d79d8e954	a514b4569bdd2d2a0a0757620c93cc0778d8b8e5d2155ddff604dcb3496b919a	52691	0o644
docs/whole-secret-deletion.md	100644	573e6cff9a78eea0e1910460f6311f6410462dd6	df6c8719265b57d1fbc36b14b72d3b55c10b1e83a093ef736167e736424af53d	6613	0o644
harness/README.md	100644	799de240f0843856c1b51e5774d458435f3f982f	92bb2ff8dce48c15d434d5a12c6cfebb2358b4c83c08f20c7d9138870c08f121	8784	0o644
harness/cloud_runner.py	100644	05c5445e61fb3035782a90038e32a6d79bc7a4a2	b43baae7025915b8aa9a517eb636656fa39300f36c9b580e692251b974b11166	28164	0o644
harness/cloud_setup.sh	100755	71c49874dc86736b616d7ab15ab45e25728c26e7	9a09b3d1c89ac27e9a53a6f2bb9f8a99dbcc51252adcd35df18eed7b151acc63	475	0o755
harness/config.example.json	100644	f1156e9d147401dd920cc7f32ca0e90c959640cc	95f2ab2224e51c8893e82924d6a2f6fe42515807d0b144c85fa4ea6d3b33764b	182	0o644
harness/controller.py	100644	718d96df962612d5d35fa3382931269be951dfad	18b6eb9103a4b6fab595c09dbe27089b744fe992c5360ad1cd2249ef4c6e8d92	16801	0o644
harness/prompts/m1-cloud.txt	100644	dc165ef4581c6c90eb918a63e13831afcbd42d76	663d230a7183d631b0564e7520fe38ea8fa3a72db784cb29436fcef3fa7bdfb8	2745	0o644
harness/prompts/opus-review.txt	100644	674ef125a47ad04ff02e87d71e72722703f7ab09	4a458a6ebdea13267e967534be9f8a73e0616c2f1508d9095bf174fd489022b2	2207	0o644
harness/review.schema.json	100644	e75586947ef54af6cb09f41a0cb4719f9147f969	1bf6caf7edf8548ea2c653937cd130c5e2db7a217f7fa1dadd0ce7696e9be5a0	888	0o644
harness/test_cloud_runner.py	100644	af060243edb812688950f380d64596fec9c9091e	3281386e66007f5c434f81927db29984c79f83d9a83d969df29713dff42cebce	20359	0o644
harness/test_controller.py	100644	4373cd78ef16f35203da29cab63ce17878c8e464	2a6c4aa0aed67e82e6bd14a41f295a95d544a0d0e2dc64d27a6556c2f9c0bd5a	21660	0o644
harness/test_harness.py	100644	030b1ab7d731b78a6f21188055361ebfe2979afd	4504b59d96ba238144470559201ec54831479ec78e930f165d2f7e942d9fedb7	21908	0o644
harness/zeropw_harness.py	100644	087f8e61383d655ac387a7183ec39cb9500d939a	34755f6eedc8b96d62bed2dc75a9275f42de13199952ae2bbd84ee8b218a4157	34684	0o644
output/pdf/zeropw-product-definition.pdf	100644	95ac934a17af326a3f297147734dd3081609f187	2f4425bf90cf896ca14cb09eb9ccdd1eac6aa06455cdb4208e75d93420cbf9fe	125873	0o644
rust/.gitignore	100644	ea8c4bf7f35f6f77f75d92ad8ce8349f6e81ddba	44c92e3a70ad3307b7056871c2bdb096d8bfa9373f5bf06a79bb6324a20ff2fb	8	0o644
rust/Cargo.lock	100644	0405bfab2c64b4dc62dd9242d09ce5922190f6d3	fb0dbbf2a2b25c111a419f3b2102d51d2859a1745e28afca9b8d59339340d840	40799	0o644
rust/Cargo.toml	100644	b62a0264891bd73d319ef54c04d66747afc1552c	4ae4261cf2bdc9e9a7099eb9a0c898282997115d17da01a7953c75bba6c9a1a6	1802	0o644
rust/DEVIATIONS.md	100644	425e3a6a33d722034e38b067aa7b9cf54e13c571	65e5d36b88c4b7d79f6748285932da0ed392139b0e554827d177b18cc3930fe9	281782	0o644
rust/PORTING.md	100644	85371993a5d424477e993f894ceda402012443dc	6ec057c0f800a2f4afe2e6766fd57c694245118dc79d64937871f75d0ec35b8c	6279	0o644
rust/build.rs	100644	741ee0c7b7261019649e0f70d09d8388f57cc940	f1dea8703c49ec3b0427f67699c70a81431e4daad29b2f5a13c4490aac27511a	1846	0o644
rust/src/admin_cli.rs	100644	5dbf665dd48ec426b7537368ae99b630cd007d1d	d8fbf3852f59531ae6d765bb133e4e0f40ca5999d1776354863405014a4f6c25	178719	0o644
rust/src/agent_cli.rs	100644	9ff94ae8ec874d936138d6715a63e966d40b2dca	ceef5827f18f96fb64a8e4e8cd6ac2395bbf3f90e4f7e04ad341ce275b18b832	34894	0o644
rust/src/argparse.rs	100644	90a285d6dd9b8b48595ba0b034997f0e9325964d	7fed59aaf9cae4d85ac553d5cb4f78e65320cbdfcb43adbecc5140ccf6e00dc8	68038	0o644
rust/src/audit.rs	100644	f3f1085241855566832d6c78304e71f02c20877b	b7783c110acac3036e5261bdd6258dca148d33e592550d32f4f46658f38be089	51129	0o644
rust/src/bin/zeropw-admin.rs	100644	0b5f6376d2d3ae25261bea170f3ed9993971319f	978a2ceb00f427f44f77777855b288c155fd5c581b73487ed59238abfcc6f9b2	120	0o644
rust/src/bin/zeropw-agent.rs	100644	e3d7afe57f371e0f7d5f3575c9b7f7992d9a00f4	2e8943097b63d621a2e481312bdd9f3d51ada2d2a24402468096279a7d50a19e	120	0o644
rust/src/bin/zeropw-demo.rs	100644	576d280244fdec8eb022415d8782f584430437da	5e59fff92a917c94aa929e0366ec526594ce1519a33f8288185933e015eb352a	60	0o644
rust/src/bin/zeropw-democli.rs	100644	a50fa90235632a25a350baddb28fee37e235097c	e6c198c5eec2d69221c6d70a3bac8e567133ec72e98daf09283cd8723e62cd26	11680	0o644
rust/src/bin/zeropw_session.rs	100644	f19a90f9fff9828b45fccef2c10eb6cddd64c404	a7be625b53e4efa94770f8f1b1e1fd30b38b6ab10753335f22468c9125f7acda	3443	0o644
rust/src/clock.rs	100644	7ad70835b6915706beec11527accdd5a10fe733a	53fb169709e46c0e6647c8ec771bb40c7ec83205ee4b6221ff45a8bd560ac944	636	0o644
rust/src/context.rs	100644	d43d6adf2dc83c18d650583e43b76aa10b7d7067	38ab58d9a1cb9b12db743b14268ecb9a74f055d7d4f82e7c4b54a32ad10189aa	54769	0o644
rust/src/crypto/chacha20poly1305.rs	100644	9a3eccba6c4822eb1cf858771b10182647f10b22	404103e6ce63ee118f53aee295da384d80d2fe7eaf5114fb26402c974d1629ee	34532	0o644
rust/src/crypto/ed25519.rs	100644	a1f60c33fbef1ee9298bf51a25e61f3ca5a16d40	fa61391dcea14927b2b4cec618b91f2de44df30eb2c4dd1826912421ca908898	46579	0o644
rust/src/crypto/mod.rs	100644	8e1c76e9a109c4b40aa3c1006ec90f02caf40681	b8a4ee3bd873e4647dac5f80d22627cbcb82b4d9602d1f144998e26e553fcb7c	90	0o644
rust/src/crypto/x25519.rs	100644	5259ed04c18f727da70fedee31c2c3e99a50a8db	90de719375afa69c6e6a20fed3730f50b8713cce1f3161104d8e67ce0d533346	17523	0o644
rust/src/demo.rs	100644	ff422a0fe7231f945c09491b591530e58523c4e7	8399b8bc21dfdb5d51560b9e65a24ec6a09d560fdd1f0b7217912d14911b5ae3	30093	0o644
rust/src/envfile.rs	100644	1458d62d848689e33935448843356513284ffa65	df20a31295165405d9741657437230f443b6d4192cafdd345f5a11977cd29c60	27573	0o644
rust/src/errors.rs	100644	a1f3dac8c5a731a3b633c60cf3784d4e0dbe916f	5a3e93d697fd2a2815bea39225f96dd796b6f59b00d45a63d655ced72ec5becd	8000	0o644
rust/src/fake_upstream.rs	100644	e5effcad4335a1cb7c1c2b813771b60f2666a605	87dcabba6ffb3ef150938b8ea2b3c636a90030ddb97fe0f60aa2ac9d62b8c6bd	46351	0o644
rust/src/gateway.rs	100644	45c1ea0fc5a23e9dbe81e094a5c173e34380d621	913e2de54ff5056c6e3da9772af3338ac532edfb24147cfec2296de49b48416e	186058	0o644
rust/src/handles.rs	100644	b7a46bb9e02c714e3645214122347a224538c452	8b1ddf8bc80cfdb8e4e15b1e879427c773cfc18f0d112818a75deb523054185b	30588	0o644
rust/src/incident.rs	100644	18ccb4fb4ccdc74358a8f9076adf68ad51946fe9	f335ea529217930d8f6c7378837a5bce13ef8be1ffb2c37a19f5e0911d28a346	28807	0o644
rust/src/input_envelope.rs	100644	5f1b53aa73fc398510798325f8e226f93b00733a	1af3294c0a6504b0ea2d10b937d3157769b3c40d57ba0e48d0be7f0eafd253dc	22723	0o644
rust/src/intrusion.rs	100644	93c67b8a121fb774cd581fb3cefa8e19e451680a	f92bcd953329a8405ba0e4613f016e147ddcd890097c75d1193c2385f54fb7db	24130	0o644
rust/src/kms.rs	100644	1dcdb5abf1167db57eeb420ca64493a3db4ea681	76b3bbbd53388410ce4bcad8c93c85b56d672f006bcd81ab268cb307beb75b1c	29559	0o644
rust/src/lib.rs	100644	46190701606996d877286c7e574560c193dc8b6a	973f02d9322511f51fd0f368135b618ec396474175bfbf549f6d5dd817c10c53	1101	0o644
rust/src/mac_proxies.rs	100644	9d737f812959457cfc8908d49cda142ac3773c12	b665cfbbd10bad0d19d21e986c13427cddd0156c394467c1c050a98dd3f557e2	13399	0o644
rust/src/notify.rs	100644	ccb74a5d39cb5f9e1741f42082893c6525f04a36	e275be6f416bb473a3f87854af001b3e77ae89c3c2e127b60410ff6ad47d4710	24063	0o644
rust/src/policy.rs	100644	ff25fdd68edbc3cd186a2da0df7ffbf7d5337b71	2cb29b865cd5735b13062061ee6c1557e1070bf5f1e26ac658fcbb4b69d3bd35	378279	0o644
rust/src/projects.rs	100644	0f7b1f4d58f3d69e419e40265aa6c827cf08130d	0a919bef6977832dcd1f0e090ddf36172591b738d7ff103fab3290f50e4d5bf4	26342	0o644
rust/src/pybase64.rs	100644	9c0618717f293694ca6465c52748c933dfcb64ba	71304fcf6829ed845db6d8bde43054194543215f979fd8c5264fe4c644d56e9e	14157	0o644
rust/src/pyidna.rs	100644	8dacc04f1e73bb99c848977ac6bbbbcb65b75067	700890ebbf28e022ff88d9952450e2fa2267e58f69f3d38292e95a7fe33dd10c	72156	0o644
rust/src/pyint.rs	100644	1ab2206efe0d43304e0d0fba75b1680db3992ad1	5562f68911c2df1ed4f8683ed9344ed8749a38b68d2399b07d973be0fde8c21a	13925	0o644
rust/src/pyjson.rs	100644	4bc9bb9812615ae722eb1f0a97bfe980686881fe	edf803df92c51dd0ba55e1da8745dec87fb5fa0687b6293d2db999926bf30d32	102105	0o644
rust/src/pystr.rs	100644	9b543c98e45f2453e7ee85a5428890b0aec481cd	1e71413bc2cccb03737b78c4d28b9ab1402609031055ceddc1a98ae928e9353c	83941	0o644
rust/src/runs.rs	100644	a11c60f5e77d2a88c4aee0e20afc02853f2cc2c1	94db6e3e92a94909d83f9fd7e2d5ab0ac7ac37038d989126250b6916b46d8fdf	40202	0o644
rust/src/secret.rs	100644	094581975453c2d9405a3e0d3397ea4822c8b1fa	5a50da1641a190ca23b9171d156df1a109ef5b3f9db4b18637b6012df4de8d59	1879	0o644
rust/src/server.rs	100644	bb995a4eaa70e82aefeea76bf4be493db525262b	3aed1d7c3cfd4143b3bd1be5c9c4305a4ce0e3cbee93fbfce9c2b3b754b6305a	47160	0o644
rust/src/signer.rs	100644	f001b7c5396a1eeb449902c99c471498ee81e69d	b128090e053a0f78c14858f87cfe96dc0cadbf3b24097ee4b650a84cd97ca882	181897	0o644
rust/src/smtp.rs	100644	031765cfa268e188daa7ddd9fda65678eb6a369b	ca2eefee5d17f78a214df06837dd657bab34e24e2645e9df571c71ac6224e8c8	100658	0o644
rust/src/sshwire.rs	100644	95e956588684a334389e0872e55568ed7589bee1	b07c19a5784d65324ad78725adb7582332f8de4980155481e34a47f360a8e6b8	80510	0o644
rust/src/store.rs	100644	ee81907ed1614a98b00dbe33ced0d0b35fc4ff30	5790088c3598134638cf2f5db8ed13d9c34cd4963b9980640d46592118fe2c4e	62987	0o644
rust/src/team/checkpoint/admission.rs	100644	7a20baff57aa1b2858fe6a8794aaebde14c5685f	70d8ad493bb66b615e73215c44d2143c13f2f766544e87960872643f95e305eb	35324	0o644
rust/src/team/checkpoint/manifest.rs	100644	ef49315db5a00babb66e37c707ffe49252189a42	e391324cef4932f27607931664573534ab3023f9d06f6555dcd607fdcf45a082	16967	0o644
rust/src/team/checkpoint/mod.rs	100644	f9e74d22dcb72a9cae264fc73c860aa752d511ee	9b98d8e3f28a275e75a713ce1e4d27d5e9db1ceff77737e53fd5e4b82635a350	5037	0o644
rust/src/team/checkpoint/payload.rs	100644	e1f889d0b5914b2fed7fae3d3dd5cdd19b623c9f	ff9a84bcf4adbdfeb39744d329feba311245184b3416ca42f81a8a45063093e9	19170	0o644
rust/src/team/checkpoint/provenance.rs	100644	8328e33664394530a36ce477f770771b19c5be4d	afed96a7e74089393986a9178f68fadd84449fabfa6ecbc83aec2d8941dfc06e	2662	0o644
rust/src/team/checkpoint/strict_json.rs	100644	cb52bab6d84500f680385e7ae68c1e87ecbff595	39a38110cc67c40135548c09b01e1297cb3960334539e57f36bffede40a7e2cf	56831	0o644
rust/src/team/commit.rs	100644	3bab9c2d3d46f736ceb569c1ce867f74b2c26b9c	251ee8f849b3367241c6a958a2c821a9972854b59f0841fb7e61b8cd41c00f00	144676	0o644
rust/src/team/envelope.rs	100644	70481a3c9f2992a4c727cb33f3f486834139dfb8	517e5d55ab19febeedb38fae9c8339d55ed5c33e6c6c50524fb6f73a249798e6	15748	0o644
rust/src/team/fold.rs	100644	3d7843ba4d0b3507f70c044015fe9a9357ed2bf8	e1bbf0209cd8fa796610aae7220ff9892e2d3fffc76d073ffb178ed32b705c63	285962	0o644
rust/src/team/humanview.rs	100644	09ff52bd677c01a2cd20e9d16c91a217f531a08a	74a4ac3944e67f7c1699236f9ed1bd2f6b59049d84e00f34a2773205a2ea1708	30020	0o644
rust/src/team/identity.rs	100644	b2a46ada6f69cf80d1e56921f10561f5d993f07c	c0d7b0c6cbdb64b36b78e9ba50e54c114db55f3c5b5a45ea38f4c03a07e436e8	18396	0o644
rust/src/team/link.rs	100644	9646e9b85fc3f7c71e88229973b747cb087f642e	4bec31623e78e8ee13570a1b9c69e24ce06754961ff5c2757de939dee4d82454	34965	0o644
rust/src/team/membership.rs	100644	2d0512ed6a5586c20d1772fd076de0d9d75ead3e	c27f4624fd7b839570c9c3c0347c4377ce1f63e59b75fe2508adbd72f7dc31f3	68210	0o644
rust/src/team/mod.rs	100644	6b2d0fa0dae402c0ec836d1ce21dfa972eccf114	1902d781a57a11e63bd75e84422782312cc11d4bbe4e469c77980f19f23292c0	7883	0o644
rust/src/team/pairing.rs	100644	59d2ab62c8036ace278519aa5c50e4fa0f3a6965	a8ce5bd89eccec76de9c67bf0c58af2d314462d2b63a5717932581f0896a99fe	18523	0o644
rust/src/team/sync.rs	100644	b652cc99e8cd9d8440ac0875f880344905a07e65	64582265ed3df0555968a5811b1c49c13e8eefbb1e96454e512782e37061ec4a	365712	0o644
rust/src/team/sync_status.rs	100644	7f499297bcb43b22815f7ada641183d97efdddfd	3f093c1ffd199a69fc06d04bb82067fd9e941354d9e46c010bfd3653074181c7	17880	0o644
rust/src/team/tombstone_gate.rs	100644	5c22ef929976829eafa813d45e537dcf10df7f1e	fd90fdd9f24c30e40e091a6d86c6037a48230f0ee79964c234a75b38801469f1	7286	0o644
rust/src/team/transport.rs	100644	d1bbf1c003b3eec91ef9a1c5b9bb7f0e5f5fc68b	ac6c221b44702d06ebcdf07427d7c810a61e1e440f1e67fe8035c98448dde339	59113	0o644
rust/src/tombstone.rs	100644	2a569f533a45e956ba74fe3df6f0e2f6589412a6	09603817d0db3dc6ee93feca74a89883f94826fc98142d0303f5fc732863ebdc	11950	0o644
rust/src/tools.rs	100644	6009608dec50d1406b2c9390be40032b288e9755	fa38596f25410e94a7dd8b81ff4a8568c40e00eb9679fe379b4e65f9bcfb71fa	36077	0o644
rust/src/vault.rs	100644	558a48f10b15223b5806cdb3855ba2615b67ef6f	7de91ad47bf196c5639e2c80f1792f0a464daec6a08327ad36681915d437e1dc	108613	0o644
rust/tests/admin_expanduser_parity.rs	100644	52fe3a3c01fb0bccd5e25df5203f56858d89610b	f06f320449142a58030237952a252f617d08b291170a8c80f8a0791bd691c0da	2431	0o644
rust/tests/admin_input_envelope.rs	100644	9f37ecd130c6bf42ef632abdc0d3d6a6a8171e2e	b3a4771a388b2728f5eed5b2d654631e8cc4847c38cf1fb1f67ce0de451e8c09	24286	0o644
rust/tests/admin_secret_import.rs	100644	66bac327d207c612a87ac4739e2e1e638d673ede	7d2efd51ab3ae510d25d2e71e3b46032cc063b59d5cf776b980f9345e9f68963	17287	0o644
rust/tests/admin_sigint_cleanup_boundaries.rs	100644	bcd17029fbf13f3aa9c77afdf39f6f6e3fec15dd	441fb07530396aae8adee1cd4b8f4f46984f3924922519129f2e90e7e8687a95	4726	0o644
rust/tests/admin_sigint_exit.rs	100644	fd709467a2423d406fe434a1c001e64ea7082e24	29f270635a30274da7646e8b7c9a49cfe6eb5ccf7c1d08ed63674d5dac84db1a	6383	0o644
rust/tests/agent_help.rs	100644	a059e20b29cf9b0b04c5ac60da8f4383aecf3caa	46c3cca28d642bea314d2068ea8c0b86bcb839dffc8ee8d24e570d7a3b89169b	2187	0o644
rust/tests/agent_proxy_parity.rs	100644	24695f1d5d4617bdd815060f910a9858fc8c4bdf	c25955eab4a79bbc3b9afb434b3c68a97512ee786abbcef423da6b14a9bf9cf5	7872	0o644
rust/tests/astra_cleanup_publication_order.rs	100644	7b92e8736431828b5270ddeccf4c1510a6d12302	f47ce743947dd6180073bf83c29699caf8d7107d81f99832e000c27185c978c7	2975	0o644
rust/tests/astra_cli_runtime_round2.rs	100644	2b67bebe89b1065e6ecefdf920be971a9093443d	e7545eeefa559d41578b6c138f42163c8775db790ff42323a476e6b0c6804ba6	4353	0o644
rust/tests/astra_cli_runtime_round3.rs	100644	3018c4aba5d2098f1be4df300af62ca2b5b64e03	a99305c6c5846e30316d747ead8faabdb5c57c3f73c44fbd170d8479adb9e0e5	5466	0o644
rust/tests/astra_cli_runtime_round4.rs	100644	6f68571189e9543804526121188ac70fbebb7947	41514e7b19bad64f114bcef93ecaeeb62badaac8faa54b2a5722d744ec7d68fd	6001	0o644
rust/tests/astra_projects_final.rs	100644	ab3652b1a9b57ed56e69e3b0f00ebb526f886e2f	a80f33ab630d45426d303298488702ac08b9152af3476f3cca6ca5e8d3a487a9	2981	0o644
rust/tests/astra_pty_portability.rs	100644	ddfa92f0008b14c3ad44938c848ebe6220ee68eb	dcc494402be9872b4633262bb72bf8dbfe94e7cd8009698daca757a51435ecdf	537	0o644
rust/tests/astra_response_acceptance.rs	100644	599c30e6c88e16b270dda3e355f895541767af0c	fcfddde6bc6d22ad8d78926fd328839d8f794339160a2aff414144c558147c5e	775	0o644
rust/tests/astra_response_final.rs	100644	5d554c05571029d90c0a20604f053ceee151353c	1aab65048a91181ab1f4b7a712e2bd954f7a9ddc9b2af9b109c8861ad29c2976	473	0o644
rust/tests/astra_response_final_recheck.rs	100644	6dbc0aa6b571fedebd6f770ecf34625e953c6537	e7238c74499678c5f1c4d6433d2d30a78b591a1d70e92a2e87564c8b408295aa	718	0o644
rust/tests/astra_response_review.rs	100644	3f8f7a3ceaca6539d910a223da5b47d008982620	0ef5291cc1299e29c6a028b07fcb755e384771f9720e911c0b2d5a77cdcc257c	11815	0o644
rust/tests/astra_response_round2.rs	100644	31247f0c8e2f6dc98d74a817244fb35ad2e45dbb	68c66eaac88ab79339ac9ebc7ee2c3050faaffd73d99bd933e2d3642305b6523	15979	0o644
rust/tests/astra_response_round3.rs	100644	6000824434743c2965ce1657f90a9aa327223490	358d8afb8561a799c8689efd04a86488b6d5897960e30abb29277974e373b1fd	6371	0o644
rust/tests/astra_response_round4.rs	100644	bf6d86eb40aaf4b794ba6337e9991b54d96c0954	8d9bbc29dc068fa60abb886a1a5d6866bbe488b152589743af2396e20eebf90a	1936	0o644
rust/tests/astra_run_context_lease.rs	100644	aeb69b663ac3dc135d6e5fb52627ccb12c75ab4b	2b1ed11cd4965321f298c687d0cb26c9d64ccf248c38fa2b7b8d457d79700341	2456	0o644
rust/tests/astra_runtime_final.rs	100644	a477341cb70120b7ab879c161e3008925265663b	88a1ed50dc49a11ae4160c1fa47c2320854387d3d9e1d918100c050df0cc3439	1693	0o644
rust/tests/astra_runtime_review.rs	100644	08650f2b281111a78fb0483780d0646cdb5fc448	7162f24b7aa65314b0b5b33b5061cfefcdc4d4d0bca2c4fd14f2272b3786bd99	6605	0o644
rust/tests/astra_sigint_cleanup.rs	100644	07e0d86d8ec47bb1b25d4e2a620366e78bba8058	7bb4b1087db02cb862c1e697ddb304ba079c105a941cd52bdb0a5ce68266062d	2516	0o644
rust/tests/astra_sigint_cleanup_final.rs	100644	a6f4a2c941f7e1b3641530e7b578ff1f16a22b4c	aa3b14ef0be14ca04bb89b421a2223ac8c12a5b09e33154272eb10261f5dd11c	3776	0o644
rust/tests/astra_team_fact_catchup.rs	100644	70e29426d584063468dfa0bb9aa312a1d5a866b8	cf068f8cb0990300b9d54bc0bcecad76fe99283c7e7cf2e5a5beb18d13c6b250	6299	0o644
rust/tests/astra_team_fact_duplicate_diagnostic.rs	100644	1e6a33061395a3feead1a2313ee255ed17c17507	d54c3fe28f96a26c57865b1321e503e646a0025b54d61757a06ed3b3ae0d7e8c	7966	0o644
rust/tests/astra_team_reconnect_diagnostic.rs	100644	9ae77ec022f93969b36fdcd019c991e57693d870	1d1d04f1ad35501ffa0788c73c0979f79e7b15293eaff78b4790f94ed74c22ae	6752	0o644
rust/tests/astra_team_review.rs	100644	3079c92c944f4379addac374946b992bdfed9d6d	beec67a914d580c0c74e8f3ab79095f1fd7a5a2c5a4b98f1e969db327f40253b	6836	0o644
rust/tests/astra_team_round2.rs	100644	a7deadf57955eb75b7e2a4a19788ca8bb65393de	1a614f224a4d7e6028c6e52f933e2affa942cdd1dd6886999f994bc588f82976	21794	0o644
rust/tests/astra_team_round3.rs	100644	3476800d0fd6329d90c155174cf026648186837c	2501c73b99dd743699aaad06fe985f9de4433c35a62db86aa8e1c96348e7f3f2	25844	0o644
rust/tests/astra_team_round4.rs	100644	12352dba71f87656d6e31b3e37a86f939b1b229c	17a8312f2fb8fd3dd00d4b1b7089705310aca27ca08bcfdcbd6e770b07059383	5689	0o644
rust/tests/base_cli_error_parity.rs	100644	886ff9c5388f7c6959b7f4b42821f3175279551e	d214f522e1a9dc7cfb680d82f0b38e799a005fa5f38072669ca6eaa60f4f4365	9848	0o644
rust/tests/canonical_helpers.rs	100644	9cce6f53e37e0cd024789a46ed057fe57358f6bc	8fd9700dc1f0ac04786bceb0883ded8fe0350e8bfc745fd16971e8cc686041f8	29799	0o644
rust/tests/cli_commands.rs	100644	63b4c33ab1ab63280c433a86721a2429692e74ef	580bfe5f27f8cbb5df59eb651b36941c337c268991c38a6e990690135c9b5014	26713	0o644
rust/tests/cli_grant_limits_parity.rs	100644	f28ac2aeaf7e320e05fe3b8a08ef735772626d60	359f6dbd04049a76d863804edf8ec3a521fa5461aa749bc2d0f0dc6cbcaaab8f	4441	0o644
rust/tests/cli_parity.rs	100644	5889a2a71298775a74dfc627bd8c3584c1a2334c	3526786664464d8b7e2e984779d5e24e775a39c74887458998f7c59561722179	8635	0o644
rust/tests/cli_pty/mod.rs	100644	495f847f8ab6c992e82813d4d18f4deac1464ab6	5737d355a14ad6b22df3ee77bded0ebaa8bb01d0884667d1c2d994b27fb201df	17435	0o644
rust/tests/common/team_checkpoint.rs	100644	bb94cf445c72a4497d719074de1979ed47aa8232	d284a641ab430ee5744c1e114fc760e15c8d62b83b29b08406f358536515615d	66796	0o644
rust/tests/common/team_checkpoint_semantics.rs	100644	1dc31d6963a02f016e63bb677baf22aaa5e27b05	bb8ae70ae698ba9034d5f1ae9bbcd73c50773502215fe51707d4139690108390	24005	0o644
rust/tests/democli_parity.rs	100644	f129e149a70399a09ac3bfd95445b75d38bc6006	271a1828d2e7b24ed411000987a563cd95b71cdb09395ca2e3f0facb605dd4ba	7894	0o644
rust/tests/escaped_builtin_http_parity.rs	100644	467ae706f45184a33a0cdff79a62679a3c59e309	6cd595dccfc3045cc8d660b65715a66d0b67211941d51c73519cdc0b8b7367b0	5960	0o644
rust/tests/fake_upstream.rs	100644	29e89f3cd3886e73c3062520d827a0b742a98aae	2a7f059540a99befd11fbd14c837a3951f58fd40c55c2864b0e1a463eb3e3ba0	43629	0o644
rust/tests/fixtures/english/response/README.md	100644	e1ef9864dfc3e50791b1f2903b9216ca1509c653	9a86c1567602c474d233bb1d55e9cf41f1712a384dff00c8fd926e9296f0a271	1039	0o644
rust/tests/fixtures/english/response/generate-smtp-expectations.py	100644	8c0cebf58016e711dc31e586cc720457392ab02a	205d68f5fabcc89cd9035c1ae07fce644e4ef5d7f2ba9a7805ec157de00914f7	3016	0o644
rust/tests/fixtures/english/response/incident_emails.json	100644	d80f1ff8d6c7f585c251e5b5fe92a21f1ae16dca	de3bec8d9f3ad7601f635fc7dbb3d288bced6fc3589f66d82c25dd618dfceeb6	5281	0o644
rust/tests/fixtures/english/response/scope_emails.json	100644	cf8a9eef71336808540eb340e7c4eaa24d2b3617	bb89130b5706dc181967ee90ee9f97180f081a94e03c85638e0191fcc86c0c9c	19996	0o644
rust/tests/fixtures/english/response/smtp_sessions.json	100644	f36456b10c7787b7ea1b5c9b070c3bb28c9581d0	b8088e7fcdec9da4894408cc24e72904d1e5ede1acd966c94d4635b2bb93ee8f	23354	0o644
rust/tests/fixtures/python/argparse/GENERATE.md	100644	7c90a1e2277139f3c86604bdb5e96defb96cfe52	d1c58070d0d00b5aac7cf9cd5fa6e4c35b912893426be36d1cb3294b09bc819d	7162	0o644
rust/tests/fixtures/python/argparse/cases.json	100644	f1a129ac2a3a7639b2c91801b9beee270834781e	e6f15c35f71667d7267638718f874bc3f0470eba60a4d849763502bcb4ca75c2	21171	0o644
rust/tests/fixtures/python/audit/GENERATE.md	100644	169fe0117be8bc12bb1005cccf4ba6626209e2c6	8b21d39f4c76025b70048a390866c561f791178cf5b123ce6f79db7c06d8ab3b	3091	0o644
rust/tests/fixtures/python/audit/incident-alerts.jsonl	100644	ed1585ca8336b7e4f8f79061a5a6326e59a27c02	6a3b6e8d4a4a1ad71a2fe12e1dcb8e82642d45f0c5774a1d7d83dbf96cd5ae16	1401	0o644
rust/tests/fixtures/python/audit/records-alerts.jsonl	100644	b90d2474554a58568a659a7cecb93ff653fbd834	38fda38ccb1b72e55225723382b3abfa006de08a42a233614cc23b0b9e259995	805	0o644
rust/tests/fixtures/python/audit/records-audit.jsonl	100644	0e372a1abd156822ee5242fda845d05a08f9841c	85112e8fc0f56544b68297a1abdc40b5dade90654d740eebb6529ee1f4e00ec0	1494	0o644
rust/tests/fixtures/python/cli/GENERATE.md	100644	d45122e8366a6b15fc9ff6abeeabad1923e80fa5	186c3a2f2911aa5b9dc293a43e0c026863bf566960a3702c4eaeaff058e37a02	11572	0o644
rust/tests/fixtures/python/cli/agent_help.json	100644	07ad24cf30f557fd5219de392bc9540083d420bb	a6c3c38962aa97aec9e262aa50029a9146918fd5c949d379d107510ad6f72034	2967	0o644
rust/tests/fixtures/python/cli/cli_parity.json	100644	8f0f7349326cb86097f07dec3ecd1f5cb0134641	8ad6dc3b981b7e85190b8616aa05f80339062ed86c1a6359cab042c2d6ba99a6	62124	0o644
rust/tests/fixtures/python/cli/democli.json	100644	aef7a8adc273d63c2ae5158d59cf47d7a05aaaa6	01e13f6ffe3030ccfcf85e912ad0106e5e2037bf23995a5fb3dcc811ec1bc2de	7173	0o644
rust/tests/fixtures/python/crypto/GENERATE.md	100644	fdb17032a4800d9793a1b61bfa7344b19da7c0d3	62a6e9605b842c7dedfe3b6011c034325faf6d21c97388cae749d654d70bb267	4838	0o644
rust/tests/fixtures/python/crypto/vectors.json	100644	6f8e66500b019ee1145400159eadae681ccb3421	3d90a4efab248977465984f9b23a02317e9e2fc2ecb73ccc37e42daf67813c36	4827	0o644
rust/tests/fixtures/python/fake_upstream/GENERATE.md	100644	7f2bb24ab93560321c8204a11d7ef87dac7ef996	f02f5dafe3d01b498e92f1c56ab4cf0e0e7b45232c481b5c7234167ede5007f1	3342	0o644
rust/tests/fixtures/python/fake_upstream/replies.json	100644	d5ba615b2744500c75ed74958d09c09221992991	6e4c359dc95255bfa7ba55d668b9cbe4ea51a42ef67330e9c193ecbeae83ddcc	7615	0o644
rust/tests/fixtures/python/gateway/GENERATE.md	100644	071e4d4b31dbb4e1d3ec49df7731aa6f44fb2401	2f32a3a77977628ba80351a5d950f14cfcea5ecfe38e9ddda918eb20b157af51	14580	0o644
rust/tests/fixtures/python/gateway/client_hello.json	100644	6d7ca9bbbc15e101af88aee02524e2856e90534b	9d0e7495093a5776551ca2e5154ccd6c9314a0bbdad268722619b93c97db6568	2205	0o644
rust/tests/fixtures/python/gateway/credential_patterns.json	100644	4750f67fcbe6a4d3402ab15de1a0be700d073bc3	de461573643f4042b1c9c7374f608f7d593c4dc7ab7d69c9f27155d8287659fd	7605	0o644
rust/tests/fixtures/python/gateway/request_bytes.json	100644	f1555ce23752b73f956757503e04ee2a8990d0de	01e1cd4c85206da15e6135df33b0118e14a99f729950c76614ddcfac7b4b9514	7256	0o644
rust/tests/fixtures/python/handles/GENERATE.md	100644	c2c56264915f0c6e2577054c7747840a1ee312aa	b9d5a0f404187c05f8955c4d5c48e1556f3f98b9932d0f19a7dff53a9bb7c8af	2242	0o644
rust/tests/fixtures/python/handles/tokens.json	100644	732ae61d1e5418ce06a648988088fb2a3fc10edc	f011dd21b3070983b7fa2e2ca68938babb4a9c4a562b2f890bf51843fe8e8bfd	1476	0o644
rust/tests/fixtures/python/kms/GENERATE.md	100644	8083497060fd050e72982d304ca3fc547b55135f	ba9ce1c551feed2087aff5926cfd7feaa8f2af24460182920ce768fddddc6aa4	1367	0o644
rust/tests/fixtures/python/kms/oracle.key	100644	e2ba1d1e39bc45026b6f12be41bb12102ff7cf8a	189400449b5150becc76a9f6e4c56f04a375a6d76963b1cba211ec90f0ef7aec	56	0o644
rust/tests/fixtures/python/kms/wrapped.json	100644	9691498b06d07cc727040085063d412f98bffb7b	cd4140aff2bee8f91555de399eb872ea560c00edef3bdf6abc3ffd8e05f8817c	248	0o644
rust/tests/fixtures/python/policy/GENERATE.md	100644	9cd4ecf83cbf3bc90353c11596017cba5e0abffe	24ec81d997d572a96cf347a36f4fb589c1cd01d3c354768c8f7440989fc15f11	2879	0o644
rust/tests/fixtures/python/policy/digests.json	100644	a963fdcc4def5e3ffdc5e45f50e1903fa9ef47b8	7309461166a9d69f6d079f3b315979b19460485914f051547e8f773c92c0b0c1	1223	0o644
rust/tests/fixtures/python/policy/state-meta.json	100644	c4f51804076e04cfe2ffe34334ba305e3e9ec8ac	b60317567704e837031ed44288ce1d0e93be9fec0f8cac2b1882a5fc3a1d6315	112	0o644
rust/tests/fixtures/python/policy/state/.lock	100644	e69de29bb2d1d6434b8b29ae775ad8c2e48c5391	e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855	0	0o644
rust/tests/fixtures/python/policy/state/policy/connections.json	100644	26387d9321aa909ed2972df3adb709bdd8586bba	5c06ae8798c29ec552cd351cb100aa71ad4c07232ff3dc90c308b5069d1eeee2	885	0o644
rust/tests/fixtures/python/policy/state/policy/grants.json	100644	d0a8ccbc4d0c6ef92b3f552108e0693765a35a2f	86744c52ee93216859f56d31c11e13a55d6a3323af76ae245eed59216d988783	332	0o644
rust/tests/fixtures/python/policy/state/policy/principals.json	100644	53ee5963dbc47bdeb88a33adbdfd544f875cac2f	8265f156e5045d6b55952aa5f3b94dd8efae8b984c7f0e7d10b3de355b939bbc	199	0o644
rust/tests/fixtures/python/pyjson/GENERATE.md	100644	5636dc3863c46f62148200b60619dd4a78238de3	86a65c324f2efaf20dee3a7b53ab1f7fac08aa0c0c580c02d4b5233de50debf9	4026	0o644
rust/tests/fixtures/python/pyjson/cases.json	100644	8e4b7dcf065eadd07ab79cfd5186a23d830d256d	b67d7f43375623edf40413b4f08c01b079df8d62bb4bee7f3dee0a108e6d4edb	59421	0o644
rust/tests/fixtures/python/response/GENERATE.md	100644	4b32314fcf1f9318577db032ab6a458a69a210fd	0fd9d258ccdd74e6fa3bfa66113decc9c6961b0a64d13143b88bd748fee4f191	11636	0o644
rust/tests/fixtures/python/response/denial_rules.json	100644	96d6982360b201238cef893be548a1b5fa9afb71	c43b9fff80cf50e57f917e3be24779fecdb6a3b7b5ee2875e023e8a3c5fe2da5	8211	0o644
rust/tests/fixtures/python/response/envelope_comments.json	100644	ac94f24ef1e6f7eb31e90cb554299568e14778c1	f841ddd5b37d9209dfa5300acf00c8cfa7509d2427efcacff4c9e9a17c51b42d	34162	0o644
rust/tests/fixtures/python/response/incident_emails.json	100644	00f84cf51f03adba428ed82639d90f87c50b8073	af390f7697d731a49a6678b45c2fd5a54fad559514206fa7552a693a2dda9dfb	4599	0o644
rust/tests/fixtures/python/response/scope_emails.json	100644	c1a8b8be26faeffe41076926f38d56cad7984dd1	0baeff80a29d3528e9b8fd68a5db26aa9006ede6bbfec41c68de6d47f122d2c5	18209	0o644
rust/tests/fixtures/python/response/smtp_messages.json	100644	178074745a5de04244de59ba23cd86bab5998c67	0f90531b16001f1d551322ce9f3b3f6dd0960f1e2ea8066ef1c3af29d41af4ae	107866	0o644
rust/tests/fixtures/python/response/smtp_sessions.json	100644	4912dd850b713006d84999cab6bd25d2a21ac39a	c083d9bf4876794fe8c3657c2440346f5c286158ff2847d7535f823b3f1036e9	23264	0o644
rust/tests/fixtures/python/runs/GENERATE.md	100644	6890a532e7e1c180579c83edf4b5b2ce696aa36f	e0565152c6bf58ad1b693973c693c047aaaeb3b3e037e2d63152a78c5505c182	1712	0o644
rust/tests/fixtures/python/runs/credential_patterns.json	100644	cf818fc37f1d59d5e4f4bce5d442cca1ac5e60c4	fd0eda26c64e8faa5d2a1b63e1437e26b53d25eb81f8df3dbc5960d83c27f093	15974	0o644
rust/tests/fixtures/python/signer/GENERATE.md	100644	3f29b19768a64833923e5554b63b2733fce93813	c685db1710b2444a59fe6c1e3cd224d6e1c16f05843bc6472a7f58517a78bfb2	5930	0o644
rust/tests/fixtures/python/signer/agent_replies.json	100644	1b4577efaf9074e501a0154cf88b66985faac5c3	7ac2554a71dc826c8f5abc7caf666ed27ab09f05880e0b38d9237595861b1455	6760	0o644
rust/tests/fixtures/python/sshwire/GENERATE.md	100644	91fadfc0114a1f551e26b0fa7ef63657a15b45ae	ce3048a7319b8abb4f2aa1b41283fbf44485cb391dcf1e25dd47dd152ac03fb1	2448	0o644
rust/tests/fixtures/python/sshwire/from-python.key	100644	1579722bf96f5e2c8b5b54743e8383d0d8fe585d	533c2b2c7dc3d54cea016bdecac6ceefecfa572249294d8fe11c60a67cdd1956	399	0o644
rust/tests/fixtures/python/sshwire/from-python.pub	100644	3ec96d23a875849653df296f03d3598e6b1e028d	9bf03d04d4abef34650212050ea3813f867702b76613cf369e6b7f5bf85691c9	92	0o644
rust/tests/fixtures/python/sshwire/vectors.json	100644	0af339e2f33a7bddffab25de1119757f5133642e	5cbbd40a4865b52d264fcec0b2227d600f730cac6335b547f02e57515b96444e	6475	0o644
rust/tests/fixtures/python/store/GENERATE.md	100644	97052cb270272f4ffc89b292bdb5354aaaefd911	145d0367f5a1f0cb3ff2c9c38b4eeeee9c8168d5b738b31f357f5f51a8f2e1a0	1502	0o644
rust/tests/fixtures/python/store/projects-state/.lock	100644	e69de29bb2d1d6434b8b29ae775ad8c2e48c5391	e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855	0	0o644
rust/tests/fixtures/python/store/projects-state/projects.json	100644	d8f53cf9da4c583aa1da37d1227a7736ea20bfe8	c66762ebf6fbc7b8dfa0d462e3a6faa73cb0434ac3fde8481a03955aa1af8d7b	231	0o644
rust/tests/fixtures/python/store/write-json-state/doc.json	100644	849094d451c430b9be4fcba246401ce2d0170258	9adf5da00ce5bf60a473eefe1d8a05d7e42015572a94b3576610d57d8f624110	110	0o644
rust/tests/fixtures/python/team/invites/GENERATE.md	100644	9f96de37dbf1b7afd37a054084505561bd97fc19	82ff0839a69e538a56b30521817d78b7d83ead52bff6cb2021c2f2b61c0a19f8	3516	0o644
rust/tests/fixtures/python/team/invites/cases.json	100644	eeed50f2db7df091eb57445fea3781f76934eca9	32e9590757a8a3e76ae04f48166436d9fd106177193aac7aae88a0bb6ece09be	33772	0o644
rust/tests/fixtures/python/team/oracle/GENERATE.md	100644	6e0fa8c355faafe793fe272098467fbd475018b0	ad30526de33d0b9aa5e0ad4773bd2c78fc071cb5a931901398ec3b73ea67d24a	8072	0o644
rust/tests/fixtures/python/team/oracle/oracle.json	100644	f0f8ad3e6fc32b995db548ca95987921a1346227	85e76ff92d1382f05c6cfc7ef3a47a60242adf7a0f05da5b27fd4ab4a8dec396	22663	0o644
rust/tests/fixtures/python/team/oracle/state/team/ph5tr32bj27nk7zphjn2qf4z5u-0123456789abcdef0123456789abcdef/commits/bzvg5rt5tkjvxcwso3hp2nurtm/1.json	100644	690190123fc4fd03b7585370eaa64cd5882f02b1	ed9e62ae9bf15ec438fa965cdb81205384951db27c452fa30b807810e089dfbe	885	0o644
rust/tests/fixtures/python/team/oracle/state/team/ph5tr32bj27nk7zphjn2qf4z5u-0123456789abcdef0123456789abcdef/commits/bzvg5rt5tkjvxcwso3hp2nurtm/2.json	100644	2bb63e2cce8a94f77413f2de64ed2d735be124ae	b1e93ab2b4799d1365274694e79a589c3da9ff9a0b5ce21c2f72c2af6ac827d7	405	0o644
rust/tests/fixtures/python/team/oracle/state/team/ph5tr32bj27nk7zphjn2qf4z5u-0123456789abcdef0123456789abcdef/commits/ph5tr32bj27nk7zphjn2qf4z5u/1.json	100644	903ffbb416cd4ba146938dde61927728e4a1ea8a	89c7906d6e23c34455390c6a60068352d00e4bdfc771b7ea395d1f8cd8b3898c	874	0o644
rust/tests/fixtures/python/team/oracle/state/team/ph5tr32bj27nk7zphjn2qf4z5u-0123456789abcdef0123456789abcdef/commits/ph5tr32bj27nk7zphjn2qf4z5u/2.json	100644	d3aa4e16d918f9a2c9eae6a54ef317e8362cfd49	a08375bcaa86936db00e082e03acbefe3c6726dfe45ac7f719b02d95c7864c7b	679	0o644
rust/tests/fixtures/python/team/oracle/state/team/ph5tr32bj27nk7zphjn2qf4z5u-0123456789abcdef0123456789abcdef/commits/ph5tr32bj27nk7zphjn2qf4z5u/3.json	100644	37f153d4f64e4ae60267346596728025e8aad81c	62647fb2ae9f1798652038bf537e0666eca346f376127d300d61c5962cfe6fbb	617	0o644
rust/tests/fixtures/python/team/oracle/state/team/ph5tr32bj27nk7zphjn2qf4z5u-0123456789abcdef0123456789abcdef/commits/ph5tr32bj27nk7zphjn2qf4z5u/4.json	100644	d46d9b22b78cab0c0763afa822fd6a9ac3dfb17e	366eb30c9e7731ceaf691d7e973f0d451939f8b0b6a5aecc8c097e18fcdb8fbe	881	0o644
rust/tests/fixtures/python/team/oracle/state/team/ph5tr32bj27nk7zphjn2qf4z5u-0123456789abcdef0123456789abcdef/commits/ph5tr32bj27nk7zphjn2qf4z5u/5.json	100644	bbc5440de138b7490f4ae02a35ebed9ca7ee3332	bfd29804d7e98861c1e785db73d9e58e78caf629cb2e7ccf69d3978718b6a283	391	0o644
rust/tests/fixtures/python/team/oracle/state/team/ph5tr32bj27nk7zphjn2qf4z5u-0123456789abcdef0123456789abcdef/commits/ph5tr32bj27nk7zphjn2qf4z5u/6.json	100644	b29d6177a9603a5307d85fd22ebea0ee5d8669b3	365307edeb331e02aecb8993faa3b5147beed4a80500ed5db2b15f7217c10b25	426	0o644
rust/tests/fixtures/python/team/oracle/state/team/ph5tr32bj27nk7zphjn2qf4z5u-0123456789abcdef0123456789abcdef/snapshots/1.json	100644	ee9947b83d9bd1efaffb52a256ea2c246700b1c0	0ce25b5bbdaab6ae29d143fcc4fcb8dab0f959d6f36ef16fefb08b0d875b5283	3835	0o644
rust/tests/fixtures/python/team/snapshots/GENERATE.md	100644	569d87cb4956cdc0be39e07e5b98aa23f4564d86	2327d629a7cf1d6eeaf952fe4164f2bbce532cbc4bb7de38dfc3778962855c8e	1966	0o644
rust/tests/fixtures/python/team/snapshots/cases.json	100644	8768eeccb10f0ddb80e97326b0b2c722dcea3d3f	03bd221118c715ae281f5fc6923ec4c111d419ea2295f299eb3735c29f49bb6b	2635	0o644
rust/tests/fixtures/python/vault/GENERATE.md	100644	f99d31144b23152fa8978ad73e2d61dd134594cb	6447aeb5d67b9efa18c03e8a1a35aefc4805c680439a8de303b20225fca57428	3285	0o644
rust/tests/fixtures/python/vault/backup.json	100644	e30dd1ceb60df7078154b26d49d878586d3ae513	7e5e7092953f8fa9b8b98035d390258f783a5023c7da30d1aea51837e5efdb9a	2241	0o644
rust/tests/fixtures/python/vault/meta.json	100644	ab96d68fc16a9def0058515445be50f6e3f65f4f	35c076cdba0d922319a12eb29dff6bc80fe2840bdc51efaf0fcf069f62097f7b	655	0o644
rust/tests/fixtures/python/vault/state/.lock	100644	e69de29bb2d1d6434b8b29ae775ad8c2e48c5391	e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855	0	0o644
rust/tests/fixtures/python/vault/state/admin.json	100644	ad46b7a44f613701a69b880e07368736476a02a0	cf29ba3fd1a71bd15a8c95cc3fb6f9bd2d8b2a3126343ba47dcdaa288e76df1a	138	0o644
rust/tests/fixtures/python/vault/state/audit/audit.jsonl	100644	2292fd99e2f7cc91c72ec90f14f0663fae788ba4	b3f35a52c6f0cdbef9a4cccef41b9d1986af5504ce80f84227c2da4b7112c9f8	793	0o644
rust/tests/fixtures/python/vault/state/kms/master.key	100644	792d3b3dfa3e044cb5dc414f50cf6e35f64d3171	cfe822e303d7d491665804e070510807971028d4742089462450bbfb54eff28d	61	0o644
rust/tests/fixtures/python/vault/state/policy/connections.json	100644	a4fc3161f3c8a158d67fc5dbc7ab80433eca0197	9ec52e99af00d5da5c81b2708d3f056c77e0d871c769f22e2e0a379d2435f275	775	0o644
rust/tests/fixtures/python/vault/state/policy/grants.json	100644	4e4409c68f60611647c1c83977119a456cbf049b	b072bf1dca67fdd06533010f539cc4321ec68c9f83cc01a12b99b8a47344c8b2	329	0o644
rust/tests/fixtures/python/vault/state/policy/handle.key	100644	065337bf4793385e902038f9ea75f54edfd9fe87	22cb4ec0c9d2ee04a819fc61952c6b96d4726a212a3786b7fe68f042a477fb03	32	0o644
rust/tests/fixtures/python/vault/state/policy/principals.json	100644	1aaa3d8b9b08032485d6c4f9722bb90521bfbcc1	ba55a314c09adbc827c36aa2096c9f6483ae35dc759524e08fc4ca36632430df	199	0o644
rust/tests/fixtures/python/vault/state/projects.json	100644	a219e08a5acf8c0ebc4f9b4a677f1b2a10394dc0	c81f17c24c9745b3738f8a5a0c2b5f831892f8d6ddc3d30a05fdf6072df6850b	132	0o644
rust/tests/fixtures/python/vault/state/vault/secrets.json	100644	5df04a0cc8d91aba2650b87e512b586a4bc0d6b7	184bbaa1ce0017637533ba60754f1ca21af1c31d0f62bdedc9f48d3c59ae0d11	862	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P1/commit-000.signed.canon	100644	382d1fea7e176af3fba92c951e151a17208f57d7	d9df662b66bc0ccdcc2868f7a354ae02157a48e31cfd4199bf0cff3ffb3e500e	801	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P1/commit-000.unsigned.canon	100644	8a65534f51c4a9f3c61386a439cd10c1828d941e	4cb54efd0480bf85a1cb5d9d569b547b9e27572a59523d1c0dd91e681aa00545	704	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P1/commit-001.signed.canon	100644	3c9e98aeed561e525fe848bae5c4f9fe39b95c93	70b6a41d58fea8438265fe474160db65b0d7ee030a9cf95990b8c6575976054c	791	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P1/commit-001.unsigned.canon	100644	f05aae6781cb08706f18db7c45aeea47dc0bbea1	8dfe68715b09ebf64fe994b835d4cf232242b23089dc7f81b563a38a81181049	694	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P1/commit-002.signed.canon	100644	bc05b07a0bc85f1fe6303ac4e907216b6a49e0f5	f3da224fe060380e12e6890124031af76f7e434a05fbb4ae547a64423a3ee34b	794	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P1/commit-002.unsigned.canon	100644	c6c6b64ae747ba670111e2bb52d157e37fe36f0e	4d5676231c365c01b02d3badea8a079dd63d2654fd26b4b5e1108d4a02429487	697	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P1/commit-003.signed.canon	100644	cd2ca0446fa7e30c073a7a0080c4493686db88d7	19437bed0db21e4777b9cdf4da3528cd4db1df348b14e19b134045af5060ebe2	616	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P1/commit-003.unsigned.canon	100644	c6ea6bfdd62b680b93587c79ab2fe0f3afa44080	80df908de8127c8f026bab9f26b53930d478624ab7555b7517cd221020392a1c	519	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P1/commit-004.signed.canon	100644	300ed47772e7aa9fa0cae260d897878f41f098cf	fb1ccd34bf5a625b68ad6c2792263d502315bebc4dca9498b3d244b74ecaecbc	616	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P1/commit-004.unsigned.canon	100644	cc486ee09cd8af6baf0e8d792ca75d9b31a76092	b497f521d9377708248d9243709832eb9bf1cc12d36216d88f7f4098db9281a5	519	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P1/commit-005.signed.canon	100644	a92f53be0363a5da7533c28827dcf7cc4f6ed064	9f1781e228007775685fa691604726ade6cf44874729d938620edc505a00d080	439	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P1/commit-005.unsigned.canon	100644	70b73ee1f72fe28a755fcc7cb468a74405a122a4	791138d6f4411f5d438482469a98b2beab3e049f609b9aa9cadf47a300af73d7	342	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P1/expected.json	100644	3b50b71a620eb75de446fe2476cbb5929be7d3ea	a3c49786c927167934174eef277ea76e5be1413acda4bee2567c8c1daa0a569d	3234	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P1/facts.canon	100644	0637a088a01e8ddab3bf3fa98dbe804cbde1a0dc	4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945	2	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P1/history.canon	100644	2929be1847ca669f3f230d824cce423e1aacdd66	91acb311c7b17d46a0340eb749f013e8fa19135be3c17a34d4c4263f15f528ad	4064	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P1/literal-trace.json	100644	36e9474cc1722a345276f620c87614d6b938644b	767c1acd44f8ae9f91eb36629e67984549c33a0fa2ea26ca804b17aa5584ac2a	1289	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P1/manifest.json	100644	90213df2afab7b2486148b8da5bc5f01b00674f8	c0f1ae45ebe4b3bfe033a66c946d02edf562a14b167d01c6b990e093b1b96ddb	2954	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P1/payload.json	100644	d7fc747ebdd690bac9e2514aef1e19a1834ee291	10f7368429ff531373c56991b6e1bfb8d86ae496cb5b4a070a3a0587b2febfff	8502	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/commit-000.signed.canon	100644	382d1fea7e176af3fba92c951e151a17208f57d7	d9df662b66bc0ccdcc2868f7a354ae02157a48e31cfd4199bf0cff3ffb3e500e	801	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/commit-000.unsigned.canon	100644	8a65534f51c4a9f3c61386a439cd10c1828d941e	4cb54efd0480bf85a1cb5d9d569b547b9e27572a59523d1c0dd91e681aa00545	704	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/commit-001.signed.canon	100644	3c9e98aeed561e525fe848bae5c4f9fe39b95c93	70b6a41d58fea8438265fe474160db65b0d7ee030a9cf95990b8c6575976054c	791	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/commit-001.unsigned.canon	100644	f05aae6781cb08706f18db7c45aeea47dc0bbea1	8dfe68715b09ebf64fe994b835d4cf232242b23089dc7f81b563a38a81181049	694	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/commit-002.signed.canon	100644	bc05b07a0bc85f1fe6303ac4e907216b6a49e0f5	f3da224fe060380e12e6890124031af76f7e434a05fbb4ae547a64423a3ee34b	794	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/commit-002.unsigned.canon	100644	c6c6b64ae747ba670111e2bb52d157e37fe36f0e	4d5676231c365c01b02d3badea8a079dd63d2654fd26b4b5e1108d4a02429487	697	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/commit-003.signed.canon	100644	cd2ca0446fa7e30c073a7a0080c4493686db88d7	19437bed0db21e4777b9cdf4da3528cd4db1df348b14e19b134045af5060ebe2	616	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/commit-003.unsigned.canon	100644	c6ea6bfdd62b680b93587c79ab2fe0f3afa44080	80df908de8127c8f026bab9f26b53930d478624ab7555b7517cd221020392a1c	519	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/commit-004.signed.canon	100644	300ed47772e7aa9fa0cae260d897878f41f098cf	fb1ccd34bf5a625b68ad6c2792263d502315bebc4dca9498b3d244b74ecaecbc	616	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/commit-004.unsigned.canon	100644	cc486ee09cd8af6baf0e8d792ca75d9b31a76092	b497f521d9377708248d9243709832eb9bf1cc12d36216d88f7f4098db9281a5	519	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/commit-005.signed.canon	100644	a92f53be0363a5da7533c28827dcf7cc4f6ed064	9f1781e228007775685fa691604726ade6cf44874729d938620edc505a00d080	439	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/commit-005.unsigned.canon	100644	70b73ee1f72fe28a755fcc7cb468a74405a122a4	791138d6f4411f5d438482469a98b2beab3e049f609b9aa9cadf47a300af73d7	342	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/commit-006.signed.canon	100644	2495bc6d5f28560443ef0132938548fd1c9fc24f	372b875dc4a13b9e33d20a93a2577eeda32f86f99de80e3c2d08519371bba21c	434	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/commit-006.unsigned.canon	100644	d803eddee31457b3b3dd222843ef6760c635569c	26ef68dbcbdb86f8f11db7ba87afbd86dd6bb60eb679bfbb90528771c2f857c4	337	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/expected.json	100644	838d6ed1bef5042e0bb28cd019994eca9efab92d	484ccb519eaa9449bfcefe761afb493275eeb05e02c3e8df8fb525ca28bfaea7	3702	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/fact-000.signed.canon	100644	4753ee8d392cf9e50c078799b8f0a13209314a75	1b30f2a74fda60bd6dccacb91d8e449b932d10d315479a494e573190dd2387b4	319	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/fact-000.unsigned.canon	100644	68fb2d740a0602065ca80688779528ab16065e39	8aed7a5faa0347fbffa7f132fc1495280f2a568a42c034508a2d10734434b612	222	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/fact-001.signed.canon	100644	783c6e83a43a09816d99eaeeffe9943e8b617142	42e26df925e2c19b027a79cf241f3a8695a8d8bedb9f69a594b14341d3c29d32	321	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/fact-001.unsigned.canon	100644	9fb0eb6ec3f512a3a826ed4fb4462358dfcbc0fd	f48be731498ba48964a1ba5de64a1d9212884d577bdf0faef88c96df954d71e9	224	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/fact-002.signed.canon	100644	28b2cc7b9a8fda54a4b47f56957677cb97ff9737	3d903609020666a31a0360e8d01245be027445e19c379857ef2d5c7409b1ed59	321	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/fact-002.unsigned.canon	100644	d880771b48acbdde13fc20d04f9b69d1d82db7be	1ff7c94f5936ffdde7a7ba7b958c9398dc82ada9eeadbfc2cbf237c2fa39ef6d	224	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/facts.canon	100644	105d701a86ac51c7ef758535a56799c51817b888	b80b6f795f8c801993058f625052033811cffe0aeaeed8739c90d7fb7f7207ca	965	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/history.canon	100644	b0c3ecdc5095e426ea72f8ca5254944803bdb471	2bceb379dc27d0df47799c4042b5a4d54cd9569bfc116e91823206c826d7e32c	4499	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/literal-trace.json	100644	65e77d25ad3273de457edc00f9b4d424df41bae4	29aa513e953d51624dcc193d75ca2a4407add1d16ccc8d8bfd602c8d4d124f94	1494	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/manifest.json	100644	2bf4c9396b1a6a1dabe5593ee29073f69a08f7e2	c18d039a14e0159cc9f16bfdb062168cd013a96276b72301235e21b13fcf7304	2958	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P2/payload.json	100644	3990c0d098f2896d0575ea7857247be1eb84d711	df2061b7cb5d1a745e55f819a4fe50e1068cf067914af87dbffb5fbaec86fa98	10706	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/commit-000.signed.canon	100644	382d1fea7e176af3fba92c951e151a17208f57d7	d9df662b66bc0ccdcc2868f7a354ae02157a48e31cfd4199bf0cff3ffb3e500e	801	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/commit-000.unsigned.canon	100644	8a65534f51c4a9f3c61386a439cd10c1828d941e	4cb54efd0480bf85a1cb5d9d569b547b9e27572a59523d1c0dd91e681aa00545	704	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/commit-001.signed.canon	100644	3c9e98aeed561e525fe848bae5c4f9fe39b95c93	70b6a41d58fea8438265fe474160db65b0d7ee030a9cf95990b8c6575976054c	791	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/commit-001.unsigned.canon	100644	f05aae6781cb08706f18db7c45aeea47dc0bbea1	8dfe68715b09ebf64fe994b835d4cf232242b23089dc7f81b563a38a81181049	694	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/commit-002.signed.canon	100644	bc05b07a0bc85f1fe6303ac4e907216b6a49e0f5	f3da224fe060380e12e6890124031af76f7e434a05fbb4ae547a64423a3ee34b	794	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/commit-002.unsigned.canon	100644	c6c6b64ae747ba670111e2bb52d157e37fe36f0e	4d5676231c365c01b02d3badea8a079dd63d2654fd26b4b5e1108d4a02429487	697	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/commit-003.signed.canon	100644	cd2ca0446fa7e30c073a7a0080c4493686db88d7	19437bed0db21e4777b9cdf4da3528cd4db1df348b14e19b134045af5060ebe2	616	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/commit-003.unsigned.canon	100644	c6ea6bfdd62b680b93587c79ab2fe0f3afa44080	80df908de8127c8f026bab9f26b53930d478624ab7555b7517cd221020392a1c	519	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/commit-004.signed.canon	100644	300ed47772e7aa9fa0cae260d897878f41f098cf	fb1ccd34bf5a625b68ad6c2792263d502315bebc4dca9498b3d244b74ecaecbc	616	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/commit-004.unsigned.canon	100644	cc486ee09cd8af6baf0e8d792ca75d9b31a76092	b497f521d9377708248d9243709832eb9bf1cc12d36216d88f7f4098db9281a5	519	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/commit-005.signed.canon	100644	a92f53be0363a5da7533c28827dcf7cc4f6ed064	9f1781e228007775685fa691604726ade6cf44874729d938620edc505a00d080	439	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/commit-005.unsigned.canon	100644	70b73ee1f72fe28a755fcc7cb468a74405a122a4	791138d6f4411f5d438482469a98b2beab3e049f609b9aa9cadf47a300af73d7	342	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/commit-006.signed.canon	100644	92e321e8520e149043f78f26aae9b90b3f1ab2df	c677c07f5d5be0ccf51dafdc664bca8a98f04d2875d0e40d34a572ee84b587dc	419	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/commit-006.unsigned.canon	100644	b7efc84b1187b9795bb960a27cb12b00202279dc	33f8131f8cf90b1a44f576adab35e9ce96e66a9b95db2d46b2ca19af13cc68e6	322	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/commit-007.signed.canon	100644	36e56f0eeeaa1275e5c7c4f99ccfb0c33380434a	9fb7c4a4b723b157d972f3471d82f89ca856f6f79729c77095b2111431c02524	435	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/commit-007.unsigned.canon	100644	b0c91b581672cb438e928ed2427164985eb73e4a	dd040333b94c76dbb1be153e92831162f7fa50e42aa49f6e1627f7ed16af7ce7	338	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/expected.json	100644	7626a190b675981bb940d2050f604913fa689254	4e578a85efe51444366c72c639513106e1f46a0bdd0505324643b6243af67b1d	3570	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/fact-000.signed.canon	100644	ac6f9c35d2bd5f99c4379d64aaad5c111a476d9b	515bc3dfb9b556f5ebb3f6dd078c6d5d26ac555bfcedc64f1760dcf51710718a	319	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/fact-000.unsigned.canon	100644	5c57579a2233bcf16a8cf38811e3b59a9d72c1b4	0915cf6b65c936fb912b9f96e821a94e861116fc172c0a079648671c47dc97d7	222	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/fact-001.signed.canon	100644	c2627891f0051c39296ce8535994983a092f61ae	6e43d58ee9eaf0d7639b8dcb2eb4b2319ad2e61eb5a288d57ec43c8ebc1e560e	361	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/fact-001.unsigned.canon	100644	a99e854f0a347942fa10c6dfaa4aae2da762187e	74ce09cf4aa25d9be165672eb366d9dc697a198d6dbe643a0f8ed90f95c62b83	264	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/facts.canon	100644	87c9d3438000cc9cb9877464659b61abbc65a453	0cdced42a86f6736bac3c163cba9babcef9e3902a886faa945eb71eef8fbc300	683	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/history.canon	100644	2ac91bf2ecf01488792e42afe7770b82573f3ae0	5a347feecdeb443771513c1020e5bf8ea5ace68eac73db8251de3533f330965a	4920	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/literal-trace.json	100644	210f0cdaf7acf1b3482e88bf434e7db6db190401	730ef5251ea56a99a15fc94d56e6a91797f6c5a1ee193b4a55ca00bd07491db9	1728	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/manifest.json	100644	ea57c9cd5cff07f3db5a1e45bf27dc434b2360e5	f8232108a4b02c6075df789091497ec203f6ed544dd746760fb504101271c576	2959	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P3/payload.json	100644	91dd07aa0fe65a379491532ecc30eb9ee8586654	699aff96ea150f0f10e3b87937db31ee5ad617340f5af3ccf7f77bc8682a5813	10711	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P4/commit-000.signed.canon	100644	382d1fea7e176af3fba92c951e151a17208f57d7	d9df662b66bc0ccdcc2868f7a354ae02157a48e31cfd4199bf0cff3ffb3e500e	801	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P4/commit-000.unsigned.canon	100644	8a65534f51c4a9f3c61386a439cd10c1828d941e	4cb54efd0480bf85a1cb5d9d569b547b9e27572a59523d1c0dd91e681aa00545	704	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P4/commit-001.signed.canon	100644	3c9e98aeed561e525fe848bae5c4f9fe39b95c93	70b6a41d58fea8438265fe474160db65b0d7ee030a9cf95990b8c6575976054c	791	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P4/commit-001.unsigned.canon	100644	f05aae6781cb08706f18db7c45aeea47dc0bbea1	8dfe68715b09ebf64fe994b835d4cf232242b23089dc7f81b563a38a81181049	694	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P4/commit-002.signed.canon	100644	a8714ff7463caca995624ea20178a1446929c160	3117c7be3afc4fbc266f6af4262c4ac95de7ecb05f690a2e70aecdbab585c415	792	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P4/commit-002.unsigned.canon	100644	eb1e21e0fcd85aec7ffb9226839ab5afa9441d17	85043bb32069da0994ddec8e1c55ca4c906a17b3543c33f1945b8889dd2e0ee0	695	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P4/commit-003.signed.canon	100644	1ce99dabcc3367c81cdea03a2a838643deed9381	87e9c4890f616182ae0e04b94893c7b2d0c9ac429ccaa2d6479e6918408c82d5	794	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P4/commit-003.unsigned.canon	100644	459b9c83ccba92fad63935547a552512ba155361	5f1d532d29aa1882c78cbb9e4f7123e295036358505201743c47cd217d8275d5	697	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P4/commit-004.signed.canon	100644	f29fb1135dad2ba32ba51f138a64de8c282df33a	c72d36834cd46828bdb3e4f158bb61fbfa436a4bc43c8cbdeccd6902d6526703	404	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P4/commit-004.unsigned.canon	100644	22b4927fe5441d630ca48c6e1fd804c545db62d2	58459cc167e93c63920cbec147936883438b715f7f4a0e4f8bed6967e467f313	307	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P4/commit-005.signed.canon	100644	850e2910747219d4af80631fee2d5e9490ffb9c0	6c7ef2ede2a25afcf5c2aec68d3881be91a9c87418fcfdca9073eb0509271600	387	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P4/commit-005.unsigned.canon	100644	5eab8dc79529128d7866b944448f75ae6f22cf07	4fdff6fe8d750b8bfe0ce3c99226c7d33a706dbff5a80e5658c0f88a9bc5c286	290	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P4/expected.json	100644	c8808e6928435f6d3ce6b89c4cf52f62b73c44d8	e80b7a9aa8dfcd443d7c43c72be78e2615e13c2f40239c4ab30a6789b1f4f947	3371	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P4/fact-000.signed.canon	100644	91dcf9729abdf91521379e9a50a18cc701113402	2850f32f3efd52c9aa2f89a28a20cb32561ea13e3d02ecbc3a2f9f7f951a305e	319	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P4/fact-000.unsigned.canon	100644	29066272bf726f79eb8454d1ed4891c3f6b552b5	02fcb8f9948ef2cba6961cf3938253c061485627dffb96d47a88e1b1187af61d	222	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P4/facts.canon	100644	f3bf1eba1474a7ef3e02da8d366f34d1d0ff32c1	102892427ead9adca62ce08d9752f432d4fea8cb3b180db9832d08662563132d	321	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P4/history.canon	100644	d790fd17dcf154706a03669e9cd46d24f01f6699	329a69e0542944e029147bf7b9f120062778877b39c36718b3dd7849d62dcbf0	3976	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P4/literal-trace.json	100644	cccae81d7e13a2926c7a6ce861e80bdfef8c4207	ee2959d0198aded8ad980cb7025c8149081c97708799ca85b4d2d8662304be58	1434	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P4/manifest.json	100644	429d5bb49e7079375e0b2c85d4fccdac5857a39c	4729f959f0b23d69b36563f69816a451858c4032c7abcc209c7e6921d8d6a609	3160	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P4/payload.json	100644	ef8ff88b8ec180118eb03dc89a679cf597e62816	eb2b65ec9ea28b8df7681dd762cd56833612d7512dd67a26e8a493b51de3eb1a	10090	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P5/commit-000.signed.canon	100644	382d1fea7e176af3fba92c951e151a17208f57d7	d9df662b66bc0ccdcc2868f7a354ae02157a48e31cfd4199bf0cff3ffb3e500e	801	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P5/commit-000.unsigned.canon	100644	8a65534f51c4a9f3c61386a439cd10c1828d941e	4cb54efd0480bf85a1cb5d9d569b547b9e27572a59523d1c0dd91e681aa00545	704	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P5/commit-001.signed.canon	100644	18c79519ac06a1f5b33c964d1accea077eb74670	9f8b57bac3521de7d1c7f028ac903fdee2d7692af2202013c683eec0e221f875	790	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P5/commit-001.unsigned.canon	100644	fec32a328812d7de8d719734bb5412afc825a9ad	5950e9ec8397440ee2e9d5144bde891a7c4634b376d45517001a0ad5f97663e1	693	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P5/commit-002.signed.canon	100644	613b15821544f9a9126aa363fa0fea9291830df9	b5aa2f90c5520b77876cc07bd90c0160704e8b336aae0c8bdba3120067037cc1	456	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P5/commit-002.unsigned.canon	100644	cadd7e0acd886b7b3cdd76f212d6c7746863c079	3fe43e997a88000d015aa5cad8e69884957666481d5802c58c35c17f686bfd9e	359	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P5/commit-003.signed.canon	100644	1ce99dabcc3367c81cdea03a2a838643deed9381	87e9c4890f616182ae0e04b94893c7b2d0c9ac429ccaa2d6479e6918408c82d5	794	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P5/commit-003.unsigned.canon	100644	459b9c83ccba92fad63935547a552512ba155361	5f1d532d29aa1882c78cbb9e4f7123e295036358505201743c47cd217d8275d5	697	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P5/commit-004.signed.canon	100644	ced74cad1d1aa6ce4eeefefcc801e0cce7df4609	c5652974259247980ce95913d51adb8b3309f2405d65fa0b8fbf9ca53197f47c	455	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P5/commit-004.unsigned.canon	100644	06e1b118bef27477e179fdebffdd49b4498f9c06	c9ba7e50754215b2647b7ed5f3bea1f7ba3f9f53dd525510d42305e1b4ab1d94	358	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P5/expected.json	100644	805ebe52b2e092a04edabc5e648d800430727a46	0d6302d6cf5e6283ef5990cfdb6495d36bb142e6d68ec95041d8c833f90c0c81	2668	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P5/facts.canon	100644	0637a088a01e8ddab3bf3fa98dbe804cbde1a0dc	4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945	2	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P5/history.canon	100644	37ca82dad22dc4dce967534556314d71a61b4b04	7f02b4cf055d27956cd1b3eaf574e09f2fe87b833909aed59e32e1c01b968253	3302	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P5/literal-trace.json	100644	271e90b14fafdc7645253609b851264f38ec03fa	e24c3edbb1d40ac3ff1751e98e81dfb51265b1cfe85f12473b9f1b6ffe205c73	1407	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P5/manifest.json	100644	98d0f3871d427734409402874dd3f2f3b4105dca	dfce6c9f5876f4b56e08645a6393efe382ded6f6b0b5866eca4ac4d7ed51dd91	2954	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P5/payload.json	100644	ff223ee25215bbb843489c7c5be1a698b06e40c9	a7a13bf9ba095809d03a0881b633e9cf53fca4d89ab1b50c65b71a4232a25dae	7992	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-empty/commit-000.signed.canon	100644	382d1fea7e176af3fba92c951e151a17208f57d7	d9df662b66bc0ccdcc2868f7a354ae02157a48e31cfd4199bf0cff3ffb3e500e	801	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-empty/commit-000.unsigned.canon	100644	8a65534f51c4a9f3c61386a439cd10c1828d941e	4cb54efd0480bf85a1cb5d9d569b547b9e27572a59523d1c0dd91e681aa00545	704	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-empty/commit-001.signed.canon	100644	3c9e98aeed561e525fe848bae5c4f9fe39b95c93	70b6a41d58fea8438265fe474160db65b0d7ee030a9cf95990b8c6575976054c	791	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-empty/commit-001.unsigned.canon	100644	f05aae6781cb08706f18db7c45aeea47dc0bbea1	8dfe68715b09ebf64fe994b835d4cf232242b23089dc7f81b563a38a81181049	694	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-empty/commit-002.signed.canon	100644	bc05b07a0bc85f1fe6303ac4e907216b6a49e0f5	f3da224fe060380e12e6890124031af76f7e434a05fbb4ae547a64423a3ee34b	794	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-empty/commit-002.unsigned.canon	100644	c6c6b64ae747ba670111e2bb52d157e37fe36f0e	4d5676231c365c01b02d3badea8a079dd63d2654fd26b4b5e1108d4a02429487	697	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-empty/commit-003.signed.canon	100644	cd2ca0446fa7e30c073a7a0080c4493686db88d7	19437bed0db21e4777b9cdf4da3528cd4db1df348b14e19b134045af5060ebe2	616	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-empty/commit-003.unsigned.canon	100644	c6ea6bfdd62b680b93587c79ab2fe0f3afa44080	80df908de8127c8f026bab9f26b53930d478624ab7555b7517cd221020392a1c	519	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-empty/commit-004.signed.canon	100644	300ed47772e7aa9fa0cae260d897878f41f098cf	fb1ccd34bf5a625b68ad6c2792263d502315bebc4dca9498b3d244b74ecaecbc	616	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-empty/commit-004.unsigned.canon	100644	cc486ee09cd8af6baf0e8d792ca75d9b31a76092	b497f521d9377708248d9243709832eb9bf1cc12d36216d88f7f4098db9281a5	519	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-empty/commit-005.signed.canon	100644	a92f53be0363a5da7533c28827dcf7cc4f6ed064	9f1781e228007775685fa691604726ade6cf44874729d938620edc505a00d080	439	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-empty/commit-005.unsigned.canon	100644	70b73ee1f72fe28a755fcc7cb468a74405a122a4	791138d6f4411f5d438482469a98b2beab3e049f609b9aa9cadf47a300af73d7	342	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-empty/expected.json	100644	2ce23036bb0adfce9f686429ad5df5c5b64ae5c6	d6c0b69520c14af3ae54854547ab9e7fb8e982b8471ada72f514b8a256c9b991	3240	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-empty/facts.canon	100644	0637a088a01e8ddab3bf3fa98dbe804cbde1a0dc	4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945	2	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-empty/history.canon	100644	2929be1847ca669f3f230d824cce423e1aacdd66	91acb311c7b17d46a0340eb749f013e8fa19135be3c17a34d4c4263f15f528ad	4064	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-empty/literal-trace.json	100644	36e9474cc1722a345276f620c87614d6b938644b	767c1acd44f8ae9f91eb36629e67984549c33a0fa2ea26ca804b17aa5584ac2a	1289	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-empty/manifest.json	100644	90213df2afab7b2486148b8da5bc5f01b00674f8	c0f1ae45ebe4b3bfe033a66c946d02edf562a14b167d01c6b990e093b1b96ddb	2954	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-empty/payload.json	100644	d7fc747ebdd690bac9e2514aef1e19a1834ee291	10f7368429ff531373c56991b6e1bfb8d86ae496cb5b4a070a3a0587b2febfff	8502	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/commit-000.signed.canon	100644	382d1fea7e176af3fba92c951e151a17208f57d7	d9df662b66bc0ccdcc2868f7a354ae02157a48e31cfd4199bf0cff3ffb3e500e	801	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/commit-000.unsigned.canon	100644	8a65534f51c4a9f3c61386a439cd10c1828d941e	4cb54efd0480bf85a1cb5d9d569b547b9e27572a59523d1c0dd91e681aa00545	704	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/commit-001.signed.canon	100644	3c9e98aeed561e525fe848bae5c4f9fe39b95c93	70b6a41d58fea8438265fe474160db65b0d7ee030a9cf95990b8c6575976054c	791	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/commit-001.unsigned.canon	100644	f05aae6781cb08706f18db7c45aeea47dc0bbea1	8dfe68715b09ebf64fe994b835d4cf232242b23089dc7f81b563a38a81181049	694	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/commit-002.signed.canon	100644	bc05b07a0bc85f1fe6303ac4e907216b6a49e0f5	f3da224fe060380e12e6890124031af76f7e434a05fbb4ae547a64423a3ee34b	794	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/commit-002.unsigned.canon	100644	c6c6b64ae747ba670111e2bb52d157e37fe36f0e	4d5676231c365c01b02d3badea8a079dd63d2654fd26b4b5e1108d4a02429487	697	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/commit-003.signed.canon	100644	cd2ca0446fa7e30c073a7a0080c4493686db88d7	19437bed0db21e4777b9cdf4da3528cd4db1df348b14e19b134045af5060ebe2	616	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/commit-003.unsigned.canon	100644	c6ea6bfdd62b680b93587c79ab2fe0f3afa44080	80df908de8127c8f026bab9f26b53930d478624ab7555b7517cd221020392a1c	519	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/commit-004.signed.canon	100644	300ed47772e7aa9fa0cae260d897878f41f098cf	fb1ccd34bf5a625b68ad6c2792263d502315bebc4dca9498b3d244b74ecaecbc	616	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/commit-004.unsigned.canon	100644	cc486ee09cd8af6baf0e8d792ca75d9b31a76092	b497f521d9377708248d9243709832eb9bf1cc12d36216d88f7f4098db9281a5	519	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/commit-005.signed.canon	100644	a92f53be0363a5da7533c28827dcf7cc4f6ed064	9f1781e228007775685fa691604726ade6cf44874729d938620edc505a00d080	439	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/commit-005.unsigned.canon	100644	70b73ee1f72fe28a755fcc7cb468a74405a122a4	791138d6f4411f5d438482469a98b2beab3e049f609b9aa9cadf47a300af73d7	342	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/expected.json	100644	f07f1c9ecb0bfa57bd4738387594719a9fa0f268	583ccce011506d2b05d0fe1b4371031354affd651aff7d6c8c13361ef558a86d	3643	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/fact-000.signed.canon	100644	4753ee8d392cf9e50c078799b8f0a13209314a75	1b30f2a74fda60bd6dccacb91d8e449b932d10d315479a494e573190dd2387b4	319	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/fact-000.unsigned.canon	100644	68fb2d740a0602065ca80688779528ab16065e39	8aed7a5faa0347fbffa7f132fc1495280f2a568a42c034508a2d10734434b612	222	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/fact-001.signed.canon	100644	783c6e83a43a09816d99eaeeffe9943e8b617142	42e26df925e2c19b027a79cf241f3a8695a8d8bedb9f69a594b14341d3c29d32	321	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/fact-001.unsigned.canon	100644	9fb0eb6ec3f512a3a826ed4fb4462358dfcbc0fd	f48be731498ba48964a1ba5de64a1d9212884d577bdf0faef88c96df954d71e9	224	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/fact-002.signed.canon	100644	28b2cc7b9a8fda54a4b47f56957677cb97ff9737	3d903609020666a31a0360e8d01245be027445e19c379857ef2d5c7409b1ed59	321	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/fact-002.unsigned.canon	100644	d880771b48acbdde13fc20d04f9b69d1d82db7be	1ff7c94f5936ffdde7a7ba7b958c9398dc82ada9eeadbfc2cbf237c2fa39ef6d	224	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/facts.canon	100644	105d701a86ac51c7ef758535a56799c51817b888	b80b6f795f8c801993058f625052033811cffe0aeaeed8739c90d7fb7f7207ca	965	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/history.canon	100644	2929be1847ca669f3f230d824cce423e1aacdd66	91acb311c7b17d46a0340eb749f013e8fa19135be3c17a34d4c4263f15f528ad	4064	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/literal-trace.json	100644	36e9474cc1722a345276f620c87614d6b938644b	767c1acd44f8ae9f91eb36629e67984549c33a0fa2ea26ca804b17aa5584ac2a	1289	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/manifest.json	100644	710eeeedfa6950ca3f5b5c0eda94d33da211974b	c30b8ca2a56e44249491a4a49d01d20172fb437ba74d44acc749445d5b5ce8ac	2958	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/P6-nonempty/payload.json	100644	87a4ff2c913fbe0bcd49df230c7356283af8823e	5b0a75110fc557718b73ae933d73854718a8cd204d246b0f5aee9d2f9ae86380	10120	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/README.md	100644	2918d445d593e9e2dc072dd729346bf853bc3178	c011caea353f426243b2f44c825a32bc1f6813e2aa7d1bf1f74d7e58b47b19af	5648	0o644
rust/tests/fixtures/team_checkpoint_semantics_v1/SHA256SUMS	100644	75be4c9a834dbaa2a75b6f5b50762017ca725627	74877c9b8a930aa21a0c3a8fc5cf3519e11c97c6cd13ba1e3a6107235e19a199	13828	0o644
rust/tests/fixtures/team_checkpoint_v1/README.md	100644	f44de19ce2e2ec32c4d681edef0aabc9e149e9b5	e814000438f2146fbbd849b7803cc24d8942942bf8cc7058535016918b8d5d49	8929	0o644
rust/tests/fixtures/team_checkpoint_v1/SHA256SUMS	100644	135a28d8275047aee65d3fb17a39587337d6e0d3	a5981856f26e687352a97836372816eaba0f98c285f8a8a41645678c8f8ebc88	15076	0o644
rust/tests/fixtures/team_checkpoint_v1/approval.json	100644	d333f2aa01b645179ecc1569354a77d6c5ffb955	b6b29bfd0fb8a9d2392a7f8613fc565e4fb79ddb2dd709088d5f6db8d8218fa6	640	0o644
rust/tests/fixtures/team_checkpoint_v1/candidate.json	100644	462a298646ad730027861e7c9903a7e69d48f7f0	b872fdcd44a841d4ed857e62d6d1910efca163d681b3a0c025ad2eaa660f2ac9	2871	0o644
rust/tests/fixtures/team_checkpoint_v1/chunk-000.json	100644	b6c9686193737eac429f74a7fb8898d9a56f7be5	fedac01b177352be4853f2dd60ea4becb525b75f9f6dc8ae9a472b5b204c0ca9	11524	0o644
rust/tests/fixtures/team_checkpoint_v1/chunks/000.bin	100644	d7fc747ebdd690bac9e2514aef1e19a1834ee291	10f7368429ff531373c56991b6e1bfb8d86ae496cb5b4a070a3a0587b2febfff	8502	0o644
rust/tests/fixtures/team_checkpoint_v1/components/commits.json	100644	6c5a9b012c8c937cb2854a6bac6cf782df8bea3d	fa67fa3bceacbc21157b2c8fb1dc86ae43277df66dc0bcd316e1538da30ca0d4	4303	0o644
rust/tests/fixtures/team_checkpoint_v1/components/devices.json	100644	3754feab5fed8907fb6cbe8206d42a3fe35378c5	1cb8ada1d14fd4213260fedfe6393f350b007633ae826620fb2c291b1b256e34	811	0o644
rust/tests/fixtures/team_checkpoint_v1/components/facts.json	100644	28835ddb1327742674e4e6ce3b8babbd94da2fc6	217a71f8a5bb2300575422ae9f52a3f286746838e3354ea5b8d815086b4330c3	67	0o644
rust/tests/fixtures/team_checkpoint_v1/components/recipient_dek_wraps.json	100644	08cca19e3348ea82b989b93b8b8600559e537dc1	4d69857aaaf1483481f4298ab6cd0bd5e8f3e0d289e2a7dc7c2927cd874e401d	401	0o644
rust/tests/fixtures/team_checkpoint_v1/components/removals.json	100644	2615c6eca4db8bb1cb6cd1c939f90bdf589103ba	3be0d6465ac1068210d148a2f511cae810ad53fd24108250072e8cfb9ec0fed3	70	0o644
rust/tests/fixtures/team_checkpoint_v1/components/snapshot.json	100644	0183b80aabc638f2e0f0ab1f2405d8e945aeb374	2bfbf2c958742c8ebac828d2a3851850e0f991f967a2b42cef266209937202b9	2539	0o644
rust/tests/fixtures/team_checkpoint_v1/context.json	100644	702b11e6237fd0c2082992fb3cecb98f4d7ef800	7bf062332c17ffb76c1dc8a299dd03ea01d55b43878091640e9eadeb39834b53	1222	0o644
rust/tests/fixtures/team_checkpoint_v1/expected.json	100644	9cf325ce6560c80fd5cf9523000c04e77c8c4ca7	5d11024d8b8c3f8d6e9f8f2e6d8d57e6e469cf397a3a2d15ec33db7161180015	5008	0o644
rust/tests/fixtures/team_checkpoint_v1/history/A-1.signed.canon	100644	bc05b07a0bc85f1fe6303ac4e907216b6a49e0f5	f3da224fe060380e12e6890124031af76f7e434a05fbb4ae547a64423a3ee34b	794	0o644
rust/tests/fixtures/team_checkpoint_v1/history/A-1.unsigned.canon	100644	c6c6b64ae747ba670111e2bb52d157e37fe36f0e	4d5676231c365c01b02d3badea8a079dd63d2654fd26b4b5e1108d4a02429487	697	0o644
rust/tests/fixtures/team_checkpoint_v1/history/A-2.signed.canon	100644	a92f53be0363a5da7533c28827dcf7cc4f6ed064	9f1781e228007775685fa691604726ade6cf44874729d938620edc505a00d080	439	0o644
rust/tests/fixtures/team_checkpoint_v1/history/A-2.unsigned.canon	100644	70b73ee1f72fe28a755fcc7cb468a74405a122a4	791138d6f4411f5d438482469a98b2beab3e049f609b9aa9cadf47a300af73d7	342	0o644
rust/tests/fixtures/team_checkpoint_v1/history/O-1.signed.canon	100644	382d1fea7e176af3fba92c951e151a17208f57d7	d9df662b66bc0ccdcc2868f7a354ae02157a48e31cfd4199bf0cff3ffb3e500e	801	0o644
rust/tests/fixtures/team_checkpoint_v1/history/O-1.unsigned.canon	100644	8a65534f51c4a9f3c61386a439cd10c1828d941e	4cb54efd0480bf85a1cb5d9d569b547b9e27572a59523d1c0dd91e681aa00545	704	0o644
rust/tests/fixtures/team_checkpoint_v1/history/O-2.signed.canon	100644	3c9e98aeed561e525fe848bae5c4f9fe39b95c93	70b6a41d58fea8438265fe474160db65b0d7ee030a9cf95990b8c6575976054c	791	0o644
rust/tests/fixtures/team_checkpoint_v1/history/O-2.unsigned.canon	100644	f05aae6781cb08706f18db7c45aeea47dc0bbea1	8dfe68715b09ebf64fe994b835d4cf232242b23089dc7f81b563a38a81181049	694	0o644
rust/tests/fixtures/team_checkpoint_v1/history/O-3-compacted.signed.canon	100644	cd2ca0446fa7e30c073a7a0080c4493686db88d7	19437bed0db21e4777b9cdf4da3528cd4db1df348b14e19b134045af5060ebe2	616	0o644
rust/tests/fixtures/team_checkpoint_v1/history/O-3-compacted.unsigned.canon	100644	c6ea6bfdd62b680b93587c79ab2fe0f3afa44080	80df908de8127c8f026bab9f26b53930d478624ab7555b7517cd221020392a1c	519	0o644
rust/tests/fixtures/team_checkpoint_v1/history/O-4.signed.canon	100644	300ed47772e7aa9fa0cae260d897878f41f098cf	fb1ccd34bf5a625b68ad6c2792263d502315bebc4dca9498b3d244b74ecaecbc	616	0o644
rust/tests/fixtures/team_checkpoint_v1/history/O-4.unsigned.canon	100644	cc486ee09cd8af6baf0e8d792ca75d9b31a76092	b497f521d9377708248d9243709832eb9bf1cc12d36216d88f7f4098db9281a5	519	0o644
rust/tests/fixtures/team_checkpoint_v1/history/expected.json	100644	7f54f0d5c69417b48a4726b2da1f8f9c23e440e7	718aae45c6a58b029f0915a7caf6df559e85f4898e9cf9792d4f7626afab8107	2022	0o644
rust/tests/fixtures/team_checkpoint_v1/manifest.json	100644	90213df2afab7b2486148b8da5bc5f01b00674f8	c0f1ae45ebe4b3bfe033a66c946d02edf562a14b167d01c6b990e093b1b96ddb	2954	0o644
rust/tests/fixtures/team_checkpoint_v1/manifest.signed.canon	100644	90213df2afab7b2486148b8da5bc5f01b00674f8	c0f1ae45ebe4b3bfe033a66c946d02edf562a14b167d01c6b990e093b1b96ddb	2954	0o644
rust/tests/fixtures/team_checkpoint_v1/manifest.unsigned.canon	100644	e1a9701d1ddd03b9665b83aa525ec1eac87a88c4	4f64b7bb3960bb8176917ee3647b421a202535ccb10df995665b893090868e3d	2857	0o644
rust/tests/fixtures/team_checkpoint_v1/numeric-records/commit.signed.canon	100644	cb160e954cdf54fd26672295d3af68614869ad40	0e7ee5b295f506164743ede63700b1f220b7d09309e12a1b205aacec37c4b9af	771	0o644
rust/tests/fixtures/team_checkpoint_v1/numeric-records/commit.unsigned.canon	100644	6cf8e07a31ba83f075f2867e3b3e84367322071e	8b3dc185d0fc4b4d9c093ef0935186d3d93563c0d1ed8765468ece3cc4955eb9	674	0o644
rust/tests/fixtures/team_checkpoint_v1/numeric-records/expected.json	100644	bc2d041106b4a571311cf56b91d2b35c7d0a4691	94cf3bece3f760b71dd430e5aaeac5afa90174260ea169c3d00e505043abcb73	795	0o644
rust/tests/fixtures/team_checkpoint_v1/numeric-records/fact.signed.canon	100644	588fa9b42b8bf9204b6929aede615728b96880d4	f43b3bd3357a62fd8e17b569567d0065b146fb3b4ac3c1f9935a37e5d234e031	418	0o644
rust/tests/fixtures/team_checkpoint_v1/numeric-records/fact.unsigned.canon	100644	e8e714603f0f892ac807f94e00bbcedd3634dd1f	b22d1dcb8c28658ca03a76792163134003c74058cf373625f27cd35613739fd3	321	0o644
rust/tests/fixtures/team_checkpoint_v1/payload.json	100644	d7fc747ebdd690bac9e2514aef1e19a1834ee291	10f7368429ff531373c56991b6e1bfb8d86ae496cb5b4a070a3a0587b2febfff	8502	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/control-bool.json	100644	a2da306b6393438cbcbeb84909741727bc90f367	f9db5b292fc3f6b7d8f9af2eb6df992db1c3612b4915479d8be56b375e494b5d	20	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/control-exponent.json	100644	7b5ddcecbff3c206cfeefdfae314617c775d569f	54608a82ce360184c97680b7412a96d20672fb79ea0f4eb3792a3e4f0f422d09	19	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/control-float.json	100644	38fac6dea197816a979d485bba7a49d35c5214f6	7684948afccd71572334b5669f9ee03bd020bea3f123c7a8a64471856ba6485d	19	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/control-huge-count.json	100644	08072747dbc9819f8ac8cbbe9f249b434b8897cb	b2d45c3212864c3bd96f70714266554a8924c3c58d86cbcb0dc8d441a661b21e	52	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/control-negative-zero.json	100644	ccd4e511b26d17f9b4b874f6a262aab38b811831	d89b37837f5d024701a856a06be7456a134a247bf2c16e5d74be2805b2f76e63	18	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/control-negative.json	100644	2b662560a285a962c4494743b0f7a15d8df7154a	01d3f686251568c5e531064fa69a9efffabe81b9b9c560df3f5152541a9b1d5d	18	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/control-string.json	100644	c7171beb26a4a72a4a745f83e0eff66a11488eb5	aec784a44b5d47730960b3c74651129ca95b0be7588bc79c96580c9e8177fab4	19	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/depth-4096.json	100644	bd8e881517e91ce34d095871cde14fb93aca7a48	c03c44d3bcf0dd8df80e0ea327ed362af817e2e4e7f011835b1fc060117628f4	8193	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/depth-64.json	100644	8eb0eaa7719dec04c54c654b017475bc46bbb987	f0244ae1938270f711155b0a26a4307cde7050495140dd858a88a1cfc378cf40	129	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/depth-65.json	100644	91f723d8ba2ae5fa96f1c489c79c7007a7fa903a	2574b71c86249bc36bf15157b4883f41da049924b6ddd4477f68af56d73d76b2	131	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/duplicate-deep-second.json	100644	99356dd4002b72c2ad12b7a8428a115b47237f79	4026ca379157da1573c2344f992818bd854eb792c3d308d0d3bd32fb3430cbd8	145	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/duplicate-escaped.json	100644	c3bcbcaddbd31ce1b708eac42a202b05bdbde2ce	9b76ab5d01163a68899e361838ef85cf791c1a4aee792d8c714db00237a32647	18	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/duplicate-large-second.json	100644	87761525cdeed9d0affb609a87eb283c9c8f915e	ce1f00a0605109a19de12237dbe5e94dbea322ed02ff11366924d8fe9f895dfa	4110	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/duplicate-nested.json	100644	25931d0c0bf8a4aee130f167f018dcb8a5eac8fe	c64f24c22f5732533b69dcd22c83cae1fc9d83064cd47c3a430d1e9811fe660c	39	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/duplicate-pair-key.json	100644	de7c91c47e6de1d3fc495f452cf7c621c3aafc15	4c8c2c2ba95cecf1caf183908d12b121cdbdc27565e1d054a856fec74e17cee7	27	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/duplicate-reordered.json	100644	a32e95217f3132764d100e2422cf04030e3aa089	4724aa5917860a3a8945078b4f04c768389d4c330ca79016f9b8cb5ba18c4cbf	19	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/duplicate-target.json	100644	b61b769077d527aaf98a8f448b5f319f1ab807ba	0d52ed3c7247da9966bfb3b9aadf6992a5d0bdce059fc5900b4e250b95a5efa9	44	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/duplicate-top.json	100644	0ac4d39a2a3334aa1a9e87e77126a3402be4ed40	8e088c0ec4a3bbe867bf4c363560ba878c4b2c38437b27ecc3363fd0b8b9a0dc	13	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/exact-headers.json	100644	122315cced5fed36fcc7ef2180fc810cbeac7266	f35bb4b7821c1ec7232640c75a0ef8c032f022e8eb47c35f0d34fd6aece9f8f8	178	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/index.json	100644	2bf6312e189ff6d7d43421f669fc4d58ae72b400	b7b5e6f9091991502125abd8d19cc539f1224066e3707ee14893b60c24be1779	8782	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/invalid-utf8.bin	100644	86f66c420bb2a085dc651fadbe6e2e19f37dd52a	991c1eb7c700faddabb3272c2a90aa4b66bd8822c18f47539c93618bd52697a1	7	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/legacy-numbers.expected.canon	100644	4712567ccda4f5587ebcfed5702dfddb4ca1325e	a0c50c76de2715e3bd0fdf3e74f024f450fd88cdc2c2f73bc2e8b3f6242e136f	67	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/legacy-numbers.json	100644	77ce6eeecf5d5e005a37dfd2ac2291158fb4c37d	27b84dbf1298739e96da59a47bc838f3ae1ad427583e4e75d721ca60d6abb52e	65	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/legacy-total-depth-64.json	100644	c8bfba81d21996e10a5475481447df539578a0e4	66ce311156eec048e28feafb85e142ba93fbb105354c252a35045d3757afbe29	147	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/legacy-total-depth-65.json	100644	c1936e1907c4680f2f326d00458e2c160f39b9d6	76afed4bcecb589c459cc3689347233aeb00b9c3d16d4137d75dd7ad79e6e48d	149	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/lone-high-surrogate.json	100644	b00fc93d76f1028ec183ea6250737d07a9d9da52	7d38e2388498cec03881027e7753b07826c5af2d61dd589b4c1caaab14ec2cc4	17	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/lone-low-surrogate-key.json	100644	7061f954eae65b8d8933af6c37c6349eae361a56	e517199aef349e145e72c45deaf1352c09e96265ce9404d0d8aa804901879f49	12	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/manifest-extra-field.json	100644	0888f7deff9901d35ed9330921dcb4bca8e22da7	aa89035cf9c84b28b0216f73742f5741fda22442d2f3bc6b71cb33b768d8562a	2966	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/manifest-missing-type.json	100644	30b60d4858e3b779b82f028e8351d28c80a10c66	2673c5b3a5988f0d62c7c3576a1d4ea1d8278a5a6f7db99daadf6e4259e87d74	2926	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/manifest-unknown-feature.json	100644	a45a81d1b00b405b80ec2390f9486e23902ecfe7	2b9de17e68b9121111d33d682337dbafb30695603fb0259eb4de6d82bea3f145	2953	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/overflow-float.json	100644	b91b7771b652cfb5bb6aea162591234b6562cfce	d1be45f13826177ddf94093e2a0f34e79d1d8b89bd5e2fbd9a157100093367eb	8	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/payload-extra-component.json	100644	2b0a2261e65054ef2d61f31e7b50349c83487e03	e21b1cd988e41a18dc7de3d930be356394327dde1c84beb80891c273af381f70	8531	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/payload-reordered-components.json	100644	aae37972a94f80e55dced4ee469e06fd0c8ebb48	b050be6810d70a653935f3c53ac2251e60c9fbe6b285c81826b2dd3e5ca0eb3b	8502	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/private-number-duplicate.json	100644	625bd490def018fd396662ce3cf704c862354590	bcf0ccac1a8b3d1b09e45ab57bcfc5e31e23f40b16e020d0e3221c2a0ed0b4d2	76	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/private-number-multi.json	100644	3da136392159a05b9b3eade455f5bcb92a0d8df4	18fcfef284591d8b2dd77bc5beeeeb3fc91ed88a756542e2b8f940fd1a381b39	46	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/private-number-single.json	100644	16c85c87aaa122813e310b03c248d84fa8786fe0	ca469fa9696713e49f8e5d810082f74af6bbdfd4c02e8c06ee67635f19e0bd6a	51	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/private-raw-duplicate.json	100644	c7d1f388ea454a9216977ab69306f8b17a29cfb2	fc82abf2616e0473fdb6e5c84e8e04839d217e1dadcc058ce8902697cce2f9ff	80	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/private-raw-multi.json	100644	a21b5ae05c669ff39c52e56c24a0d87172238809	478b4a088627522ab55f27e6d8b7da364ca6c5660176f55939079fffb0ffe24d	48	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/private-raw-single.json	100644	ed5c2790fe90027c77c102b171164faf28badef0	f37d11971001bf19a2f5dfe2dcd5318e011f3dea0f713bb4fc5d475d439dec9a	40	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/string-delimiters.json	100644	6fd8db9725152809fa9298213ecefec7dec818e1	5c608ccbc71cb85042d702897ab3c0c0ff912b6d1d11531527724d212ebd28a6	24	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/surrogate-pair.json	100644	e97b454269e52d0c26a6b5e7b87f13207ab52b58	be8780ac8910eb4ca52c59333113f7289f3312a35293cf6ddc38953a36fa904a	23	0o644
rust/tests/fixtures/team_checkpoint_v1/raw-cases/trailing-json.json	100644	44cad18fb4aac37b664ab2ad02f461a2931fe438	6c1bd26e549ea058bfb8f4be8dcc58632031fde4c153afa7474579c66013a238	5	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/changed-final-digest/approval.json	100644	d333f2aa01b645179ecc1569354a77d6c5ffb955	b6b29bfd0fb8a9d2392a7f8613fc565e4fb79ddb2dd709088d5f6db8d8218fa6	640	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/changed-final-digest/candidate.json	100644	070c14004ff87bf25bc9cc604c8dafe47b50052e	6f1b477fb9401b2c2e4df790811b491a0c93fe02eb072342567c234dc49e7cbe	2871	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/changed-final-digest/chunk-000.json	100644	12fd096133db33e04f4bed8d8e4c1f8c4556cae0	b8a95951882c8ea4fe0becc8608a68ce6510dcb811f7c4485a8a9ad8341d5864	11524	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/changed-final-digest/chunks/000.bin	100644	3f6cef7c348c1a995b1cf8fd7da1e54baf22a0f1	d5874257212eb3a39a3e21a7168bd65c1788791c1265878e5789667bfe1f57e8	8502	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/changed-final-digest/components/commits.json	100644	6c5a9b012c8c937cb2854a6bac6cf782df8bea3d	fa67fa3bceacbc21157b2c8fb1dc86ae43277df66dc0bcd316e1538da30ca0d4	4303	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/changed-final-digest/components/devices.json	100644	3754feab5fed8907fb6cbe8206d42a3fe35378c5	1cb8ada1d14fd4213260fedfe6393f350b007633ae826620fb2c291b1b256e34	811	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/changed-final-digest/components/facts.json	100644	28835ddb1327742674e4e6ce3b8babbd94da2fc6	217a71f8a5bb2300575422ae9f52a3f286746838e3354ea5b8d815086b4330c3	67	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/changed-final-digest/components/recipient_dek_wraps.json	100644	08cca19e3348ea82b989b93b8b8600559e537dc1	4d69857aaaf1483481f4298ab6cd0bd5e8f3e0d289e2a7dc7c2927cd874e401d	401	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/changed-final-digest/components/removals.json	100644	2615c6eca4db8bb1cb6cd1c939f90bdf589103ba	3be0d6465ac1068210d148a2f511cae810ad53fd24108250072e8cfb9ec0fed3	70	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/changed-final-digest/components/snapshot.json	100644	13d0315712f025187ba9020aa317de2a1d4fb93a	f22199149d9f37263b965e940b1cae0f048f7dfdc892200f0e560b7cfe2f480d	2539	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/changed-final-digest/context.json	100644	702b11e6237fd0c2082992fb3cecb98f4d7ef800	7bf062332c17ffb76c1dc8a299dd03ea01d55b43878091640e9eadeb39834b53	1222	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/changed-final-digest/expected.json	100644	df7ab33134aaa9471b5634c83793a7bfe78f364f	2adf87d4700b68cfaac1cb14aa99a4bc84947e833982b927ceb3ed9020b2d6bd	5030	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/changed-final-digest/manifest.json	100644	a7727cf125748b19be8a88ce7d6f97d096754bb1	9c1869522eaef6ae7b793a5de21f17bbb17a50c84fe990bbaf07703283739e93	2954	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/changed-final-digest/manifest.signed.canon	100644	a7727cf125748b19be8a88ce7d6f97d096754bb1	9c1869522eaef6ae7b793a5de21f17bbb17a50c84fe990bbaf07703283739e93	2954	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/changed-final-digest/manifest.unsigned.canon	100644	c37e779dd01a25412bf4494ccc15894f91fe60c2	b40b9950f5f2c3c148af71d28b9d2a7784e26de229cc1acd3a698502becdebd6	2857	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/changed-final-digest/payload.json	100644	3f6cef7c348c1a995b1cf8fd7da1e54baf22a0f1	d5874257212eb3a39a3e21a7168bd65c1788791c1265878e5789667bfe1f57e8	8502	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-empty/approval.json	100644	d333f2aa01b645179ecc1569354a77d6c5ffb955	b6b29bfd0fb8a9d2392a7f8613fc565e4fb79ddb2dd709088d5f6db8d8218fa6	640	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-empty/candidate.json	100644	40d743bb0d7de4c880895b8cf2e9e21832e28c45	9ad35547c338d95f9905eb572453d516fbd1b9eb14bced6469da2782e75069f5	3276	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-empty/chunk-000.json	100644	6c362f7b19551c73d8fa26469a94fc09375634be	83234197a6dd9c618dcca17a67bc42598d9925d6dc47e4b155b54f067d809551	12240	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-empty/chunks/000.bin	100644	8a003b3f208ec19f3ad15121382802e8cbcce71b	0b6f4c06c805dc0a6e17b643905080747fa52c8739d93b450b77e68b0a68d358	9038	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-empty/components/commits.json	100644	6c5a9b012c8c937cb2854a6bac6cf782df8bea3d	fa67fa3bceacbc21157b2c8fb1dc86ae43277df66dc0bcd316e1538da30ca0d4	4303	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-empty/components/devices.json	100644	3754feab5fed8907fb6cbe8206d42a3fe35378c5	1cb8ada1d14fd4213260fedfe6393f350b007633ae826620fb2c291b1b256e34	811	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-empty/components/facts.json	100644	120b1a93aa67ad64e9a33127b9d60f97d7b92ea5	5a65a158ddfbb58a60a8e2376ae69eee4907f970eec245c439ed8a6dd94bbcc9	603	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-empty/components/recipient_dek_wraps.json	100644	08cca19e3348ea82b989b93b8b8600559e537dc1	4d69857aaaf1483481f4298ab6cd0bd5e8f3e0d289e2a7dc7c2927cd874e401d	401	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-empty/components/removals.json	100644	2615c6eca4db8bb1cb6cd1c939f90bdf589103ba	3be0d6465ac1068210d148a2f511cae810ad53fd24108250072e8cfb9ec0fed3	70	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-empty/components/snapshot.json	100644	0183b80aabc638f2e0f0ab1f2405d8e945aeb374	2bfbf2c958742c8ebac828d2a3851850e0f991f967a2b42cef266209937202b9	2539	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-empty/context.json	100644	702b11e6237fd0c2082992fb3cecb98f4d7ef800	7bf062332c17ffb76c1dc8a299dd03ea01d55b43878091640e9eadeb39834b53	1222	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-empty/expected.json	100644	ce5e451ec433aec22db92e91503936c21b5badfc	f52b2856942e7baa642e7e46f48fe5c8e97d6abe868ceba8ee7542e0073a6787	5157	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-empty/manifest.json	100644	6f12c1b438eff5399a11c1080a24c5217ac93830	d64f6fce32b7a2d07a84f02a0b44d050ec35d991115b8da2bd013c0fb9a80410	2955	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-empty/manifest.signed.canon	100644	6f12c1b438eff5399a11c1080a24c5217ac93830	d64f6fce32b7a2d07a84f02a0b44d050ec35d991115b8da2bd013c0fb9a80410	2955	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-empty/manifest.unsigned.canon	100644	9b8e7799ba37d8386c4b1d67e7b3685b58e1bc43	98717b2d60585917da290e738ccec0e06a6fd80d9cf67b833ab8b17cd1219348	2858	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-empty/payload.json	100644	8a003b3f208ec19f3ad15121382802e8cbcce71b	0b6f4c06c805dc0a6e17b643905080747fa52c8739d93b450b77e68b0a68d358	9038	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-empty/records/fact.signed.canon	100644	4753ee8d392cf9e50c078799b8f0a13209314a75	1b30f2a74fda60bd6dccacb91d8e449b932d10d315479a494e573190dd2387b4	319	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-empty/records/fact.unsigned.canon	100644	68fb2d740a0602065ca80688779528ab16065e39	8aed7a5faa0347fbffa7f132fc1495280f2a568a42c034508a2d10734434b612	222	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-retained/approval.json	100644	d333f2aa01b645179ecc1569354a77d6c5ffb955	b6b29bfd0fb8a9d2392a7f8613fc565e4fb79ddb2dd709088d5f6db8d8218fa6	640	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-retained/candidate.json	100644	bda567882493beee4e46b58c4372a8373e953fed	37f1867d39564b94e47238d365c05b4d86df1361decb4a52e02438779d6667ca	3276	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-retained/chunk-000.json	100644	acfe920b87191a7d8f3775e3219e3136a562a36b	90177ff4841887c78dcf4851d7713b4a0f0c753f0c7c15037bfab393afabd199	12244	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-retained/chunks/000.bin	100644	fbcca3019162b687feacbc50dc73f12ab7909d57	d3ce18f58ef95cc856a7ea9db8b81b4ee9bbe77ffa5a6d4db8a1d25f7b18807c	9040	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-retained/components/commits.json	100644	6c5a9b012c8c937cb2854a6bac6cf782df8bea3d	fa67fa3bceacbc21157b2c8fb1dc86ae43277df66dc0bcd316e1538da30ca0d4	4303	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-retained/components/devices.json	100644	3754feab5fed8907fb6cbe8206d42a3fe35378c5	1cb8ada1d14fd4213260fedfe6393f350b007633ae826620fb2c291b1b256e34	811	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-retained/components/facts.json	100644	7c3e4769321ac31ad501bd0dc3eb0c9106d8d947	1590e2ac26d892ed99f8397da1f1dc0cf59747c118277e2767e4ba75a320d75f	605	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-retained/components/recipient_dek_wraps.json	100644	08cca19e3348ea82b989b93b8b8600559e537dc1	4d69857aaaf1483481f4298ab6cd0bd5e8f3e0d289e2a7dc7c2927cd874e401d	401	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-retained/components/removals.json	100644	2615c6eca4db8bb1cb6cd1c939f90bdf589103ba	3be0d6465ac1068210d148a2f511cae810ad53fd24108250072e8cfb9ec0fed3	70	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-retained/components/snapshot.json	100644	0183b80aabc638f2e0f0ab1f2405d8e945aeb374	2bfbf2c958742c8ebac828d2a3851850e0f991f967a2b42cef266209937202b9	2539	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-retained/context.json	100644	702b11e6237fd0c2082992fb3cecb98f4d7ef800	7bf062332c17ffb76c1dc8a299dd03ea01d55b43878091640e9eadeb39834b53	1222	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-retained/expected.json	100644	a90936613e6af86c15145b7f2858b8a23cd7dcc7	5318756c3a57c0e54eec84dc12753e02d3734a45b8327e244a868c95747b3a82	5160	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-retained/manifest.json	100644	f311a22f79d03477d1bfcb49d8c3aff8b420cce2	699a41cbee5527e8465f1ecd30657cd1d5180cc104c9e2ecd288d9bd18439412	2955	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-retained/manifest.signed.canon	100644	f311a22f79d03477d1bfcb49d8c3aff8b420cce2	699a41cbee5527e8465f1ecd30657cd1d5180cc104c9e2ecd288d9bd18439412	2955	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-retained/manifest.unsigned.canon	100644	b7fdc0a8f31ffe50cba68093a2e9b1aa5e636f9a	7fb18ec232c2456be5e521a9a8fcd1d3d2a138c59b7170940e5a9f20f02de689	2858	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-retained/payload.json	100644	fbcca3019162b687feacbc50dc73f12ab7909d57	d3ce18f58ef95cc856a7ea9db8b81b4ee9bbe77ffa5a6d4db8a1d25f7b18807c	9040	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-retained/records/fact.signed.canon	100644	783c6e83a43a09816d99eaeeffe9943e8b617142	42e26df925e2c19b027a79cf241f3a8695a8d8bedb9f69a594b14341d3c29d32	321	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/deleted-retained/records/fact.unsigned.canon	100644	9fb0eb6ec3f512a3a826ed4fb4462358dfcbc0fd	f48be731498ba48964a1ba5de64a1d9212884d577bdf0faef88c96df954d71e9	224	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/invalid-inner-signature/approval.json	100644	d333f2aa01b645179ecc1569354a77d6c5ffb955	b6b29bfd0fb8a9d2392a7f8613fc565e4fb79ddb2dd709088d5f6db8d8218fa6	640	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/invalid-inner-signature/candidate.json	100644	d9da6aa0b29e43aa1845481506a60bf051f9f65f	55b9de47f4819e50ebcc97c39475be002df447809748b6bc80d76a10fbf34997	2871	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/invalid-inner-signature/chunk-000.json	100644	523aa272d4d5826dc58e532d26b7e58354cfb80f	7b9da304240d12c383c084d0013ab5509a68617588f070ca59007dcf127f7b2c	11524	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/invalid-inner-signature/chunks/000.bin	100644	661d9709c0149dcf987231aabd2176ac21c9ae6a	d30bf92eef5334cfc21f6dea0b72ed23544f5ac191982c44885760e203f9a33b	8502	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/invalid-inner-signature/components/commits.json	100644	09b0c9e6d52f7c60f0183d7ae0f0b75751105bb0	a4731aaa0b66ea3c40ff22b40f1490f1a58b1239b99cd4f3f06524fd4e1bd557	4303	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/invalid-inner-signature/components/devices.json	100644	3754feab5fed8907fb6cbe8206d42a3fe35378c5	1cb8ada1d14fd4213260fedfe6393f350b007633ae826620fb2c291b1b256e34	811	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/invalid-inner-signature/components/facts.json	100644	28835ddb1327742674e4e6ce3b8babbd94da2fc6	217a71f8a5bb2300575422ae9f52a3f286746838e3354ea5b8d815086b4330c3	67	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/invalid-inner-signature/components/recipient_dek_wraps.json	100644	08cca19e3348ea82b989b93b8b8600559e537dc1	4d69857aaaf1483481f4298ab6cd0bd5e8f3e0d289e2a7dc7c2927cd874e401d	401	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/invalid-inner-signature/components/removals.json	100644	2615c6eca4db8bb1cb6cd1c939f90bdf589103ba	3be0d6465ac1068210d148a2f511cae810ad53fd24108250072e8cfb9ec0fed3	70	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/invalid-inner-signature/components/snapshot.json	100644	0183b80aabc638f2e0f0ab1f2405d8e945aeb374	2bfbf2c958742c8ebac828d2a3851850e0f991f967a2b42cef266209937202b9	2539	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/invalid-inner-signature/context.json	100644	702b11e6237fd0c2082992fb3cecb98f4d7ef800	7bf062332c17ffb76c1dc8a299dd03ea01d55b43878091640e9eadeb39834b53	1222	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/invalid-inner-signature/expected.json	100644	515c3cdf5153a1f4f853949ede67ec83db69d845	7d7a503e1aac2afa6fc680d5241ce89aa7729757ee70bd42a593b2bd6f1cb08f	5034	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/invalid-inner-signature/manifest.json	100644	afe57e59f066cc27330883dc302cef3c2a69d9bc	ade85b0c7cad22ef2decb26975c7a4c309ddcc18797c2a221cb9db465baa2696	2954	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/invalid-inner-signature/manifest.signed.canon	100644	afe57e59f066cc27330883dc302cef3c2a69d9bc	ade85b0c7cad22ef2decb26975c7a4c309ddcc18797c2a221cb9db465baa2696	2954	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/invalid-inner-signature/manifest.unsigned.canon	100644	a076b1fb97001be5d0cfe9852570a192064d2c72	22877fbe08454805a26cfd21b41cbbe58195f413a82d71855f5f2c71dd96ecd0	2857	0o644
rust/tests/fixtures/team_checkpoint_v1/variants/invalid-inner-signature/payload.json	100644	661d9709c0149dcf987231aabd2176ac21c9ae6a	d30bf92eef5334cfc21f6dea0b72ed23544f5ac191982c44885760e203f9a33b	8502	0o644
rust/tests/gateway.rs	100644	71c71d1d2322c5341ff11aca56ceeed917dde6af	cf5b85f20c775b4ffd77468917dd13694f7ee3be2a6de206d7d667f2260e1ce3	237837	0o644
rust/tests/gateway_oracle.rs	100644	3732bc265d207821548b18ea23489ffc38c80639	64c95b9b23823a1035f05d2564cf60101474780b75ee5841a09bee80c1cba577	9767	0o644
rust/tests/gateway_replay_status_parity.rs	100644	5963e6af917e0dcd5c28b14f10276bcc3b9dbd15	e5c40a5e2b09dffbcbeb4540f39f287861c810003b6232e517061e9ebc485e34	2006	0o644
rust/tests/gateway_tls_parity.rs	100644	322a886f92f27625e796c89e77e6a5855d94d01d	cc0ce7c4bafa228af0940af6b875a76b3890967351b9ef6d9c21c52c111d3c34	34733	0o644
rust/tests/gateway_x1_credential_e2e.rs	100644	37e90e5539778537aaf453c2ab3dd6bedbc3d31e	84a2b3350b3eed64e860fc8596c69ff596473ecf491079e5e302dbe8342d0674	8887	0o644
rust/tests/ledger_float_parity.rs	100644	1045866fdce2d241868db357eb52fa7a9932dbc8	03d412078ef599161da63a43cb2f772ad36fac9686397951e9160ce2539f9f93	2450	0o644
rust/tests/link_daemon/mod.rs	100644	6b475ca19ff8cd11f1bdca133ba313428ec0639a	7a9dc534eb3bede0b5b9be3eae133bee038007342078e48ba8c46be2e86c4619	13758	0o644
rust/tests/native_admin_cli.rs	100644	b42839bdae877f51daf88625a32844e285634304	a76377339cdb476a1c5e18b29cdd1a867e30fa89e79a24aa3643dc17b09828c3	51335	0o644
rust/tests/native_admin_cli_more.rs	100644	9ff4c02d3c3f691ba27cdf4bf369e8eeac9916eb	1c9db68ff0f7eb60ff7e7abce908a88619762bdb04f4e108c011d1e3992e1ed7	66786	0o644
rust/tests/native_agent_cli.rs	100644	45995d189a8558dec45bafd06fc68347941ef341	2fad794c6ef43059dbec188f833885c3646e5b5bc8983c1756fae4c3fc34fbfd	17174	0o644
rust/tests/native_atomic_cli.rs	100644	4a395438de22c80c3bb509dd6daa622c34ef4321	90fc72a690095b27dbfe5dfa69f3263d13c2da571da59777186a537cfbec5edf	4497	0o644
rust/tests/native_cli_e2e.rs	100644	54d75f0d784f7602dd08fe1341c6d887186a954a	8f87714fb531814c33ed7b86ce461608d6e5b11ed69d0bb28daae9c6a48f1741	41177	0o644
rust/tests/native_e2e/mod.rs	100644	52cead39f2528c6d1f825e9cedc73949a42af5d2	b4239c02483426754125967ad55817f4ce54fc18622f29aca7db50b8ab34d607	54582	0o644
rust/tests/native_response_cli.rs	100644	830a7709db66e311711615fdffc0091287cd6180	534d0c12c876081907c6fdafa4029298a26df82891fe4a1569e2f90d255f64c4	28927	0o644
rust/tests/native_team_cli.rs	100644	50d5390a4c3bd1f32212972960276b70360ebd50	deede8c0f07f5f1a8acd8e7e2524ac9d0e1c258124a82ea68ed33dbe7b7bc796	38001	0o644
rust/tests/native_team_e2e.rs	100644	df080885fd240eca29e31105b79c3b61a25ea420	5d6125ef085acef5a2e1ad12e636c73667e641e7a5417670c92c08aadeb1a19f	27519	0o644
rust/tests/notify_envelopes/mod.rs	100644	702933cef58ff23e6e07dcf0be4e0f616b41fc26	0417910934e9806c9d309004bb979bf6837a49ae31860c2b01c827c32131d6db	6510	0o644
rust/tests/policy_oracle.rs	100644	a030b0b2171e11a3d6eb236873ef5341d316e0e0	1d3cc1dc1ea5c68febd63e7e2e71cf3e3dcd92070e0df3a26bc133e90e116060	74475	0o644
rust/tests/policy_parity_close.rs	100644	986754013452c69183f60f221200e4faddab3dea	72ebae65705a88a2e346e7c335f80b9c47d69fc17df4cba0ff26c9a2fb114a64	4457	0o644
rust/tests/python_fixtures/mod.rs	100644	4f1f0056c046f646e5b3c0639c81f4d3e6f2be4d	a494555c51150daef08958678ebb7a45794b7fcbac4c49ef7f2c0d09cd6b1377	3663	0o644
rust/tests/python_numeric_comparison_parity.rs	100644	d2c81debc4826bb7062518efc1e84bfd0ecd5783	8da63b0a07679c875342faa03078661975c4fba3ef6994cd42151f039b193ad0	1632	0o644
rust/tests/relay_escape_parity.rs	100644	4ca51e257d5fae7a4dc7927eb512f4c6def9a74e	df5d4bcda035682bf2e817df6ee83d24e278e46d623d68fa7bd1549fd5362871	20740	0o644
rust/tests/response.rs	100644	59d6d831f5c556f3c3ec0cec6b5777b988e5bda8	9eefc47943537e930b0f7f20e25152342f928d4709727b5c310191732538d7a4	47308	0o644
rust/tests/response_contract.rs	100644	6a25dd189fc9194daf9e49c42adf678c0646f043	b9f71901dd8d4f728b9c5b5b3490fcd3e4a6e875edc7ca30a4d9621a9d26b8ac	12769	0o644
rust/tests/response_integer_boundaries.rs	100644	798ffe726fb6faacc2dcf313e810f4c9dfa33150	4b36c354fa09aca1e62817145a3fc01bdbd6035d252dcebceed7442fcfa5b87a	2524	0o644
rust/tests/response_parity_gaps.rs	100644	943a88e174482348fba1c9624e3ac7a55d676302	4dc79474fb345d47903554a3fe6066214983bba712acc41616fd96f050f52fc4	34951	0o644
rust/tests/runs.rs	100644	040a316ce6dca0e96a38696c71505c740dc5f4e7	fea03267a0f4a1170e8a6539b2162221c60fa5c6320b149b7849e231893cdfbb	21273	0o644
rust/tests/runtime_fix_boundaries.rs	100644	9d652a4ac339c80af58eb13fa4497cb5b92b597d	9155b92853c71d1d5b22278c3e929f8f2d317581a2765ade15e744b279ba0a54	3156	0o644
rust/tests/runtime_parity_gaps.rs	100644	47fdab56e995049c8d81c6e04b0ee3a8a0fea112	d2763df2e608bff262f2c8c6c27da430f31d9bd95baec6ca4b9b5df0d3f7c6e0	38317	0o644
rust/tests/serve_request_log.rs	100644	8e2103a3745221b8989e5e35233f60574363df72	286b5fa36ad47a84e0547fe6fd40e9275cfae28a799463af5d2649c1bd6166f4	3140	0o644
rust/tests/server_accept_resilience.rs	100644	c90f7107cea93634edb485c9c166106dae0aaf59	baeb81322dd0d143f7fa89ef57e81689524c5e24996a02a4248f09b3fc643a30	2952	0o644
rust/tests/session_probe/mod.rs	100644	3f6fd4c5a2c1f58e77e8ad7620530ac01ff9f2f8	d0a72c7133a6ea53eca580666d7c60e214b18ce7af205f039ef1f6493db3ef1b	1726	0o644
rust/tests/signer_e2e.rs	100644	d1bb9230312b149b60479a1b04ccc82701151425	e84e2e4a44b7e194f1bcaed915905dc6bd3f7657958d42bf01a77fecd50287ed	39281	0o644
rust/tests/signer_oracle.rs	100644	87b613d13710538080769bc86f2a2f0edaf4213a	54fe35c5603e81eb3b7e2d49c23606483f4e65e72d55acbd3e888b892a41d6a9	18485	0o644
rust/tests/sshwire.rs	100644	786e57be1198d806aea35bc908c2960e3b489210	82760a28fb83d8e5cfbec19039800359aee5133cdff8f3d7d2f214ed3c30b335	81588	0o644
rust/tests/state_dir_cross_language.rs	100644	6fd223d2621ba758b632a26a6b50c0360ed73cd6	2ed19b7a978f5891d0b9ffa4f356bb5525b5516a632d959aad3660e1bcfac876	7513	0o644
rust/tests/store_cross_process_lock.rs	100644	a09dd0d02124b92f9d10ece73839cf64e1e650eb	d3757a28332d5ed7665cc1d579e21fb9940292977a831b3510d453f4e599c4d6	6345	0o644
rust/tests/store_oracle.rs	100644	f39f0ce3c9c6ccf3b0b7c505e04031ce5ca3a4d4	31792e82eff2d63cb55e054c8a10d1d96c625c93abfc04ad7146cfdd3782a110	3330	0o644
rust/tests/team_checkpoint_admission.rs	100644	b0b02f2438564c0e11041363f24a222e6cd90a37	7071270eacf8cfaab3201da6ae04bb53927fdfad2f8ee5dba9e75d58681d0758	50096	0o644
rust/tests/team_checkpoint_authority_oracle.rs	100644	477c67585c9e159d6701283f93ddbab70dd5a721	12751c497e2b89eac572d57141f61757f118d1684630817a65643528454f5da7	11120	0o644
rust/tests/team_checkpoint_legacy_parser_regression.rs	100644	e03d2717d6b2a8611c78a5c9aab38a03a4ef6615	dd3296c048f5036fa5ae8f07988390b54f9067879ee31ace0522770ae8e34080	2057	0o644
rust/tests/team_checkpoint_manifest.rs	100644	51b6a359f863eaeae5dc6b3de7fd1d0152f431a5	f2d25f4d3596723d6af859b2aa944799cd93a919f1c1faee0cee6387a6243db5	9942	0o644
rust/tests/team_checkpoint_payload.rs	100644	9b43701e60f304cc46ecce500a46f31f52aeaeda	79585c26d99116c7f8e32fb2e62dfd5d8efd414c78bb0c0ca963f8dacadc0a89	30290	0o644
rust/tests/team_checkpoint_provenance.rs	100644	95c2d664fb38963f071b26889afda473e0675f65	d7ab23cda62e0e3923b0b1b920c09e8b98ebe976678b936640c9a24020506ff5	5678	0o644
rust/tests/team_derive_lazy_parity.rs	100644	120e6055d7ce626b91696b2328282505d5d4d5da	3096bb876050ff2ffd050f48eafaaa48131aa27068370dba288be9858a5e58b8	18024	0o644
rust/tests/team_envelope_parity_edges.rs	100644	861e41462fef72ad321c2ac869d43f15eeded500	11af65a9a64c8d0263b421cfa0d8790e834d9dd7f99c3c5c18b1adf40122db03	3816	0o644
rust/tests/team_fold.rs	100644	f259f6c24bf35ddc7ea7ad9a94ea284de1372100	dc34005271262c492f189522bcdd2e026318499d1141cb2e5d7b09a4807b897f	70899	0o644
rust/tests/team_fold_lazy_parity.rs	100644	a75a37ca4e69260a0782a037331acf36292cdecd	1253ae450e909f5e8015cdf07b0492effe29e589be2d22aa4fc912a14a901971	13548	0o644
rust/tests/team_invite_link.rs	100644	3dcd8ece3250519820fff9454f14c8f76e8786e6	29601347eff55576cf1fe4def072f0ddcf8ea89de8b95318e79d211251399c39	45976	0o644
rust/tests/team_link_transport.rs	100644	788c2b1f686c897aed3221d57a624da32aa95705	c5eec887f0cbe861897d635ad48cc5b9a72129387972da1e7dbb560555e0418f	40586	0o644
rust/tests/team_membership_sync.rs	100644	6e8d64efb44a2ffd056a6ebfd9df9d93d2bfc5ce	c015b9b9d48c18d1253f857fe014885f20aa7594151febae17d74040fed32107	29925	0o644
rust/tests/team_oracle.rs	100644	7ca10d1368e125b6c4ae7b3139c6b13e5eb342ee	0690e2cb8f85c25f8c669dd42855b3947e03e5638423ec71c72689450da5a7ed	88911	0o644
rust/tests/team_pairing_approval.rs	100644	103573161e8d42ccd930d289098e710a71df2ed7	d01834967ec561272ac592c201851ba4fbcfe75f4bafdcbef86deaeb598f9ee2	35821	0o644
rust/tests/team_parity_gaps.rs	100644	0f0449821d2bc29d530c2aafc2842f5d948a6046	31a4eb147b26436d0528cd78a848d8c42a6e4c98d9d179800729353d688a2601	32445	0o644
rust/tests/team_remaining_contract.rs	100644	bf25290fc0fb7e46ca9439613332c2791a411f70	6b3da49c1db7b8909808f39acce57e331d20367b7fd2660db1dfbef90354fa28	78226	0o644
rust/tests/team_secret_import.rs	100644	c2a2ddf837fff79a33486ca784587813053d3dca	0df6d88027acdfce99d81128689967ab49ce80f7d2ac12d7448cb3d6e3b74b6d	10110	0o644
rust/tests/team_share_policy_version_parity.rs	100644	7acd16244c6795d74fd5888515cc6f4d9598d422	79abdd4a499a519804741f735850a3d2ecddc4a70838fbcc65041de55fd1a529	3048	0o644
rust/tests/team_snapshot_total_parity.rs	100644	a8dd848f57338d9b43a1db0037edf21d98302171	7f784bf4e62e60789ce5732ed03089baa5cfdfaa76bb20d9a2e9e32f52f85f69	4219	0o644
rust/tests/team_snapshot_version_order_parity.rs	100644	979736683674036a7646e382fe6e9737778c8ce0	79b5a40504b9202dbff8626fca6488507bd361c23f5313263a1882f6c43fcfe2	8032	0o644
rust/tests/team_sync_status.rs	100644	baa1002eeb481d43660df1e2090eeb96a9a5a893	1cee5fbf089157ef6268436b62ca70575eac9efc9e6143dbdfed161249c7c1c3	24160	0o644
rust/tests/team_transport.rs	100644	d311280b75099da5e771ba877926ef380a0a2686	d96f44c09e5236c01ecaf94cd70ac1ca78d258257a5beb625f836993d424c4b8	3997	0o644
rust/tests/team_uncaught_scope_parity.rs	100644	53478d892157308d31dc94037e9b7b5443f43837	d3e906a4c39a80666c9a3c48a5302dbc58a087ff872a62374a4ec1247ee3ed0d	16762	0o644
rust/tests/tools_server.rs	100644	759662d465ce57c2bdc84d4738b3a279f0c61c52	b4547e0287a68419b56c29c1dec6430719f44c6f15dd57164f47865fb60f0977	48370	0o644
rust/tests/vault_context.rs	100644	8189d5c9fa3f639038c87652e3252555235f1899	fe3080f95fda49fd26fd11b494e887cd7f061ea7d606ba4788cd35b7c46d3765	67365	0o644
rust/tests/vault_context_oracle.rs	100644	bb988951169c1878301d7351d6bc4fe39404afd7	6085b10d29b58f827c907cb2c45fe0bf486918a37a9ca44c79b57e3370c30b2d	49559	0o644
rust/tests/vault_public_parity.rs	100644	4c0ad3aeb3d2a38fc82fa231ee2cc13212ca3fd4	8860077acf0e988e109b8a965bcae7813f7b1904bac2e80191326f8dc97f29a0	3393	0o644
rust/tests/whole_secret_tombstone.rs	100644	32f8697274b1feeee0cc7a737a7b9dff5e7d05f1	2896f663a07f50567b0298b993ba5db05920d6489fec9750fef1981885b27cfe	20866	0o644
rust/verify.sh	100755	cd343186ca5bc736c4a28dfa31dd1abd1cb33e53	6a7c3ae7608553d2c2527f804daed752ced4117d1fc80eb5d58f98dee50c24ca	1610	0o755
scripts/audit-publication.py	100644	a764d624d771d125edb1f8dfe89b0f1a51fcd440	cf6d29c5b94aa9c24e83c4fe346c9d3cf349205120d755cb36e68ae9a7cdd94c	2621	0o644
scripts/build-release.py	100644	fa4c1b739a5e85f5379b89cb25f8cf02624aa826	7b51114c043ecd8c68ca385a685d54d0ff6daab10270870fb235f8346d075b0b	15204	0o644
scripts/dependency-licenses.py	100644	5b98b9e79a537321da09acabd0af107ce6c052de	14eeacfcc1ea1734627db19fd18db5c7a6d8472763b4eb99756e9a8a383f896f	20574	0o644
scripts/e2e-remote-sync/README.md	100644	3e04f2b8845da101e8b98a2e57355f95db0722f6	c551580c34b3ac929d18fcea94c7eb8310180694090a96fff0512d3bd6e1d5be	4311	0o644
scripts/e2e-remote-sync/run.sh	100644	a5df14121a662de9cdc1f0048af5c569a57d406d	51abd3effd5906ccc39cf01e9d5e90aad0e9ed58d8229f9b40ad337ca6e1d315	2543	0o644
scripts/e2e-remote-sync/scenarios.py	100644	135cc036d1ce21a885891f1cb285594176a76d4e	5675f0d59fa7744f841e61fce0e7c5a2360418c0d26f392dbbff05c42e6e2539	23140	0o644
scripts/homebrew-source.py	100644	64d998ffd061ded818591c9aa6988bec86ca434f	fd713e59618109289786b496878b9993a607e376ebe85d139895c4964a914fe8	1036	0o644
scripts/install.sh	100755	c0ee71a93f4c8e7592a28f521eec3cfade5c09ab	cb9389664b339f5c1a977da66a1267980ac8934cee938e9828112f9af67552f5	5500	0o755
scripts/observe-onboarding-brew.py	100644	4d696f6f5f3ea20ab15fe18ad7380e1cb0cc09bc	539ad5a8ac6e6aea28aef12207faa05d5f0f8380ca35be5cea27336e26d9141a	2821	0o644
scripts/package-release.py	100644	1de6dc5ac3e312351ccc2c11376bda0ec5f8e9cb	5ffc9eb987999c1780e84cf226b0656ee4ce5a284f854ea35fd5f88d6aa82e56	2174	0o644
scripts/test-homebrew.sh	100755	6b08f9a9f256397e8a08afa6e1afac7574f4284a	ab62aec380143630ff87d624a0c17f1732ff508e3f885b33fffac89be86985a4	646	0o755
scripts/validate-onboarding.py	100644	59e8b532388d5eccdb565f9c8e6c155afd4877ea	f89f88b975a0ab6bf471520f98355e87314844f93a3c1de3c6a0c2373dbfde3c	16346	0o644
skills/zeropw-agent/SKILL.md	100644	f0bb2bb01163c35c5ebcb9755dc99807de1a3b61	5d835aacc8a15a03c88bcbd039e4d217747171a14c7c934e72185c733178d572	4348	0o644
skills/zeropw-agent/agents/openai.yaml	100644	a3eab56fa9d4476f81975c078cce57e495c176ce	2076491c767e070e88b0d904bac32950f233040006191308f2feb8167689d2f8	220	0o644
tests/test_dependency_licenses.py	100644	06e8a1b33fddbc56cacbef49599726cede4190fb	e861a21a49c6890b69076208d4067b61b50a2f2efdba0cf4f2ae795e09c6987b	15581	0o644
tests/test_desktop_licenses.py	100644	31685a74f2a2cc35e5add98e9119efa37594b586	65178154453bfd8e135d87fd50eab0435a097dcbcd2112a5a7c64895d3f916ed	25967	0o644
tests/test_desktop_link_sidecar.py	100644	82cb04518e91976f8c0aa294fe414aa45633e21e	e5ab121345db32e9da44e66b590c66ca9095f936361c3ee71e6b27b2e01abfd0	13692	0o644
tests/test_desktop_package.py	100644	180295891501acaa22717dc5af8a21cb5135af64	5d76629c0c16757d5a841e48da3c73ebb9ffe69a14ca3f3a74b52b3ffe8efd8a	44209	0o644
tests/test_installer.py	100644	2e1c9ecfec3ecef8faac8c60a11cd5c744753479	10cea34056101c8b1b229e339672a035ade14cb19c26df825ecd06e676fb3119	6498	0o644
tests/test_onboarding_brew_observer.py	100644	14cd90b38d6b19986da15c469cb7de702d30246d	1f06a27cfc63d5afcb4022fe8c69c533bbd1bd2c7b64db79af8f836aa4ed5ff9	4300	0o644
tests/test_onboarding_evidence.py	100644	d1a7a828975dd2d9a3c346627e7ae0e5d98b2992	bfc68722e7495e6020c784e7d2ad73ddac0aacfedaa5eb9e0eb8a84a77b6dd29	5385	0o644
tests/test_onboarding_pins.py	100644	3f62ea27739de522e881b0adac886c3fe16338c4	4ce4c5e5629e708828a126a52715981163242884c674c793bd7f697a79bf4060	9767	0o644
tests/test_onboarding_report.py	100644	c06190c8d881cc59a52dfc66d7063ac91e8d1566	54c2cad30f1d905b793b08cd9c8704a4cf5a22e6f76108b34ea28085d79ec97f	1767	0o644
tests/test_onboarding_validator.py	100644	aed8d35910d47bb97240c08a69e38954c8381022	3c61723866dc478580846fbbd46f9f7611b4b0442756fe6d2ab639c1336343bc	18225	0o644
tests/test_publication_audit.py	100644	277b8080a332b7e2e510f0fd844a4e3aceceff58	97d39ba19e749ff5c63afa1fa2add5270e2f3d1c8b534c2f745f8e47778061e9	3069	0o644
tests/test_release_binaries.py	100644	27919950ea8edee2a5bf932115aeb24b8e73cc35	c5f29d2983cc180ef7c4b2d72a9769a3982b03729067d8cdf5aef29137397d21	18168	0o644
tests/test_release_fixes.py	100644	61e615c5e9d78e8df8f39b4d6525d5b399008e40	3e196b5e9e14cc736fd65963d70116aca4de873a8fda7509d6afcdbb2b216200	11082	0o644
```

## Completion integrity record

Repeated after drafting on 2026-11-07: HEAD `9e76a1dae165863ad97f5af976d5037c12e4d0e7`, full tree `fef2952c65cc6120ac6f55b941eeab007c6b0f1d`, Rust `5d3acbd546c5dc3490e95635342572cb064007eb`, Desktop `2413844c89265a3e239be2372d34b1e6e1b2d4bb` remained exact. All 1,122 tracked file bytes and actual POSIX/executable modes matched the initial inventory and their Git blobs; seven executable files, zero drift, clean tracked/untracked Git status. The repeated inventory SHA256 remains `816c1e7c33ca3160350919aae7045ec1b79a27703a76dce8a6063b1d0b59aaf0`. Canonical ca01275 review hashes were also checked unchanged. All protected source/fixture/instruction/review/evidence files are covered by this equality. No source or ref changes occurred.

Exactly two output files exist in the requested external directory: `decision.md` and `implementation-task.md`. No product execution, isolated execution, test, review/recheck or acceptance occurred. No other checkout/ref, active worker/native/service environment, production authority or external service was used. DOS-1 HIGH OPEN; all M2-G01–G10, key, runtime and release gates OPEN. Final document hashes are supplied with the handoff; a document cannot contain its own whole-file hash without a circular definition.
