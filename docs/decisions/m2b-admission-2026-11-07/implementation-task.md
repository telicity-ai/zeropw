# Sol task: M2b.1 retained authority and original M1 fact analysis

Prepared 2026-11-07 by actual **gpt-6-astra**, **ultra** reasoning, T3 Code/Codex harness. Requested implementation model: **gpt-6.1-sol**, ultra. Record the actual invocation model/settings; this brief does not authorize a substitute/default worker. Do the bounded work yourself, without subagents or workflows. No Opus review is requested of the worker.

## 1. Exact base and prerequisites

Read the complete sibling [decision.md](decision.md), SHA-256 `1baef6b989a53765ef76a05f43a7e2a30914ed94de18deddfdbd4218b853f248`, all four documents in `docs/decisions/m2a-schema-2026-11-07/`, AGENTS, product/security/harness docs, harness README, PORTING §1, the full M2/G01–G10 contract, and the M1/M2a reports. The decision's §15 binds their inspected hashes. The coordinator must supply this decision and task with their final SHA-256, actual invocation prompt hash and prepared base SHA/tree in the task packet. Do not invent a combined-source SHA.

Required source composition is exact:

- Cumulative M1 backend from immutable `8258a8d2eac7541e229f414151271bb3faa215f8`, Rust tree `8406f25c3793077b1919467273bd69f788f56f82`.
- M2a from `7bcecfda8571ae40047fae406915f73d2e25bde0`, Rust tree `24fceecbec4b559aa8d1e31331ef5be0033ca2fa`, collected through `5686afe49e55859c7cdf342b0346a45924f8748e`, `b7d92525e970ba097e44d11cda84eb99dcc100b1`, `74bb09ade04d6b0b078dd2e8cec0753eab32091a`.
- Specifically, add the five M2a checkpoint source files, four checkpoint integration targets, frozen `tests/common/team_checkpoint.rs` and `tests/fixtures/team_checkpoint_v1/` to the M1 base, plus its checkpoint module declaration alongside M1's module declarations. Keep all other M1 product blobs. M2a's pre-M1 `sync/fold/pyjson` must **not** replace M1's files. The frozen helper hash is `d284a641ab430ee5744c1e114fc760e15c8d62b83b29b08406f358536515615d`; fixture SHA256SUMS hash is `a5981856f26e687352a97836372816eaba0f98c285f8a8a41645678c8f8ebc88`.

The coordinator prepares this composition in the worker's own T3 worktree/isolated export and records the actual base. Do not create another checkout or touch another ref/worktree. A later coordinator-supplied combined M1/PersonalVault/M2a head may substitute as the starting base only with an exact path/blob reconciliation to these dependencies. No uncommitted worker tree, polling of the active integration task, invented M1 adapter or empty facts shim. If preparation is missing, return that **source preparation dependency** before implementing against a pre-M1 backend; the design itself is ready.

M1 source/readiness and desktop/native failures are separate from this composition. Completion here never certifies the active integration worker's result.

## 2. Finite outcome

Implement a pure original-record semantic analysis API that consumes an already paired `ManifestAttestation` and `IntegrityCheckedPayload` plus independent local observations, and produces only `RetainedAuthorityCandidate`.

Success must establish:

1. Every retained original commit/fact signature, schema, environment and canonical identity; all device copies including agreement keys match.
2. Original genesis and complete retained authority-op set; exact per-author signed head/HLC consistency; ordered authority/role transitions using existing handlers.
3. Successful named recipient admission with approved role; active approved signer/recipient at the cut; exact snapshot owner/member/DEK projection.
4. Applicable retained historical authority for every **non-removal** fact, explicitly administrator-attested historical admission basis, original fact preservation and M1's actual complete tombstone digest.
5. Refusal of observed existing state/collisions/known irreversible contradictions, independently of remote attestation.

**Scope guard:** any `member_removed` fact, nonempty removal bounds/pending/self-placement/witness claims, or need for fact-removal scheduling returns `team_bootstrap_semantic_scope_unsupported`. Signature/shape validation must still be correct; do not erase facts and continue. Commit-only `member.remove` without a removal fact is supported using the ordinary handler, with no fabricated schedule. These are finite library coverage limits, not a permanent full-M2 alternative.

Do not implement final data fold/digest verification, removal-fact admission, compaction, continuation storage, generation decryption, approval persistence, v2 renewal, transport, runtime budgets, install/journal, ACK/READY, status/join or credential behavior. No runtime caller, capability advertisement, source-format migration or public install ticket. False final digests may still reach this deliberately limited candidate; test and document that boundary. Snapshot onboarding remains unsupported.

## 3. Allowed changes

| Path | Allowed purpose |
| --- | --- |
| `rust/src/team/checkpoint/admission.rs` (new) | Entry, semantic errors, local observation types, private stage, record/index checks, fact basis and eligibility analysis. Split private implementation into `authority.rs`/`facts.rs` under this same directory if needed. |
| `rust/src/team/checkpoint/mod.rs` | Narrow pure exports/module wiring and compile-fail documentation; no change to existing M2a assurance meanings/reasons. |
| `rust/src/team/checkpoint/payload.rs` | Retain existing checked index metadata and immutable disjoint spans for sibling semantic access. No public unchecked constructor, no relaxed integrity/schema check. |
| `rust/src/team/fold.rs` | Add a narrowly scoped pure `checkpoint_authority_trace` over existing handlers, with no I/O/keys. Share helpers only as needed; preserve ordinary fold results/skip behavior exactly. Keep tests of the seam in this file if private access is needed. |
| `rust/src/team/sync.rs` | Only expose/reuse existing pure `apply_fact` through crate/team-scoped visibility or an equivalent narrow pure wrapper. No body-semantic changes and no edits to receipt/loader/incoming-fact/session/runtime methods. |
| `rust/tests/team_checkpoint_admission.rs` (new) | Black-box signature/binding/genesis/authority/fact/collision regressions. |
| `rust/tests/team_checkpoint_authority_oracle.rs` (new) | Independent complete-history and literal semantic expectations, permutations and unchanged legacy behavior. |
| `rust/tests/common/team_checkpoint_semantics.rs` (new) | Separate synthetic signing/fixture builder, independent of the new verifier. Never modify/import the frozen builder as an authority oracle. |
| `rust/tests/fixtures/team_checkpoint_semantics_v1/` (new) | Separate deterministic source histories, literal expected traces/digests and provenance README/SHA256SUMS. Existing candidate fixtures stay frozen. |
| `docs/evidence/<coordinator-assigned-m2b1-source-directory>/` | Bounded source-bound report, commands/results/hashes and limitations; no governing-doc rewrite. |

`strict_json.rs`, `manifest.rs` and `provenance.rs` remain byte-identical. Reuse original span materialization; do not reopen the parser/schema to get a convenient `Value`. It is permissible to materialize the checked snapshot component once in the **new semantic phase**, extract its authority projection, then release that tree; do not clone it into several proof objects or keep a whole-payload tree. Retain/measure its working memory honestly. If a different traversal is required for acceptable resource behavior, return that narrow dependency instead of silently changing the parser.

All other product paths, original tests/goldens/GENERATE files, Cargo manifests/locks/features, canonical/numeric/crypto helpers, canonical-helper guard/allowlists, `rust/verify.sh`, CI/harness, AGENTS and old evidence/designs are frozen. `raw_value` is forbidden. No new dependency, homemade crypto/JSON codec, unsafe code, test bypass or global stack/thread workaround. No desktop, gateway, signer, state or runtime edit in this slice.

## 4. API and construction contract

Implement the proposed signatures/ownership from decision §5. Public local input constructor is explicitly `from_local_observation`, taking typed grouped inputs, **not** remote JSON or an approval Boolean. It must include the complete recipient record, independent manifest/approval/environment/session bindings, intended mapping, revision identifier, existing-state inventory, occupied-ID ownership/scopes, known original facts and M1 deny/binding/support observations. No missing field becomes an empty/default authorization.

`RetainedAuthorityCandidate` has private fields, redacted Debug/Display, no deserializer/default/unchecked constructor/serialization-to-proof roundtrip, and no conversion into `Facts`, receipt or future install authority. It borrows the exact paired immutable manifest/payload/local observation and owns only bounded summaries and the exact original fact set needed by the next stage. Read-only public hashes/counts/coverage are sufficient for integration tests. Avoid public unbounded peer-content diagnostics.

An internal `AuthorityTrace` records total-order positions, original op indices, applied/skipped outcome, active member/admin intervals, final owner/members/DEK projection, named recipient admission and source-wrap operation applicability. Its construction is private to checked analysis; a raw helper return is never a public proof. Do not model facts with a “trusted” Boolean. Per-fact internal analysis has:

```text
fact_hash, original_fact,
basis = administrator_attested_historical,
qualifying_role_interval = original commit hash/op-index endpoints,
manifest_hash, payload_sha256, approved_signer_record,
approval_sha256
```

Every fact receives a basis or the entire bundle fails. The result is still `retained_authority_checked_not_admitted`: real persisted approvals, final semantic fold, generations, READY and durable import are not established.

Use the decision's closed reasons. Invalid M2a pairing is binding mismatch; bad original signatures fail signature; never/incorrectly authorized records fail authority; contradictory original facts fail fact contradiction; unsupported removal-fact scope has its own reason. Do not expose arbitrary wrapped library error strings.

## 5. Implementation sequence

1. Record protected blobs/features/fixture hashes and exact prepared base. Confirm the real M1 `Facts.deleted_secrets/tombstone_facts`, target validator, digest and loader behavior are present. No product execution outside assigned credential-free isolation.
2. Retain M2a's already validated spans/index inside the integrity result. All original M2a integration/parser/compile-fail outcomes must remain unchanged. Preserve the private manifest pairing and total ancestor depth. Do not widen M2a's public construction boundary.
3. Complete the original device/commit/fact signature/schema pass. Use existing `verify_commit`, M1 `verify_fact/validate_fact_target`, `DeviceRecord` verification and canonical/hash functions. Verify every original whole record, not only those named as authorities or heads.
4. Apply explicit no-removal-fact scope check, then implement decision §6 in order. The only retained gaps admitted are evidence gaps with an attested prefix; no ordinary sequential receive call. Check authority-set equality, genesis, device copies, head/vector/seen/HLC consistency and named recipient admission.
5. Implement the pure authority trace using existing handlers. Keep mixed commits in original op order. For nonauthority ops check schema and active-admin prerequisite but do not fabricate data-target execution on an empty document. Preserve skipped reasons; skipped authority/unauthorized retained operations refuse the candidate. Check owner transfer, demotion/removal, and current signer/recipient roles.
6. Canonically compare complete snapshot owner/members/DEK projection, including names, removed records, generation wraps and source operation applicability. Do not compare only counts, current admin names or generation IDs. All known embedded device copies must equal the table in full.
7. Apply decision §7 non-removal fact basis. Historical active-admin/member intervals come from successful transitions; never from document self-claims, unused device table entries or skipped grants. Do not impose a false fact-HLC admission clock. Use existing pure M1 effects and `tombstone_gate::digest`; compare complete original sets, not deleted-ID sets. No loader/receipt call on candidate data.
8. Validate local-observation existing-state/collision/restriction conditions, retaining their binding in the result. Test independent checks with a perfectly valid remote attestation. This does not claim a runtime scan/lock occurred.
9. Produce only the private limited stage. No writes, KMS/device private-key inputs, network handles or runtime calls in production analysis. Inspect the final diff for scope and authority imports before isolated verification.

## 6. Deterministic inputs and independent oracle

Build new fixtures in isolation using **synthetic public deterministic** signing seeds and agreement scalars. They are test material, never product defaults. Reuse existing signing/canonical/AEAD primitives, not the new verifier, to author them. State exact source/model/toolchain/generation commands. No expected signature or SHA value is invented in this document; the worker must compute, independently check and freeze the actual bytes.

Use O/A/R signing seeds byte `00/01/02` repeated 32 and agreement scalars `03/04/05` repeated 32, as in the frozen candidate package. Add D signing seed `11` repeated 32/agreement scalar `12` repeated 32 for a former admin; X signing seed `13`/agreement scalar `14` for never-admitted identity tests. Use original M2a fixed environment suffix, IDs/nonces/times, G=`a`*16, V1=`b`*16, V2=`c`*16, and deterministic synthetic DEK/ciphertext construction. Supply each fixture's independent local expectation pin; do not let its manifest select that pin.

Required positive histories (separate branches of the test data, not branches/refs to create):

| Case | Construction / literal expected semantics |
| --- | --- |
| P1 nonowner admin | O:1 init at1000; O:2 add A/admin at2000; A:1 add R/user at3000; O:3 put V1 at4000; O:4 put V2 at5000; A:2 activate V2 at6000. Retain all except O:3, with exact signed heads O:4/A:2 and R:0. Pinned A is active admin; recipient R/user; original authority set is exactly O:1/O:2/A:1. This source history is created independently of the frozen candidate package. |
| P2 historical deletions | Start from P1. Two original A deletion facts at7000/8000 target `deleted-empty`/`retained-secret`; O:5 demotes A/user at9000. Pin O, not demoted A. Both original facts retain historical admin basis and exact distinct hashes; the no-version target still contributes to M1 digest. Add a second independently signed deletion of `retained-secret` to prove same target does not deduplicate hashes. |
| P3 new owner | Start from P1. O:5 transfers ownership to A at9000; A:3 demotes O/user at10000. Pin A. Genesis owner remains O in env_id, current owner A/admin, O/user, R/user. Original O historical revocation/deletion remains eligible. |
| P4 commit-only removal | Separate history O:1 init; O:2 add A/admin; O:3 add D/admin; A:1 add R/user; D:1 settings update; D:2 self `member.remove` in increasing HLC order. No `member_removed` facts. Pin A; D is removed, signed D:2 head remains, and a D fact with an earlier active-admin basis remains analyzed as historical. Removal component is empty because it describes **fact** schedule. |
| P5 intra-commit order | A valid whole commit contains successful authority changes plus data ops. Literal expected authority checks follow op order, not grouping by op name. Include an initial admin grant then an allowed following operation, and a later demotion making the following admin-only operation fail in the negative variant. |
| P6 empty and nonempty original sets | Empty capable tombstone set uses actual M1 empty digest; nonempty original set is invariant to delivery/input construction order and contains all distinct hashes. No absent-field fallback. |

Use exact numeric HLCs/sequence values in signed records, preserving original HLC spelling. Add huge-sequence/head fixtures independently without pretending gaps are sequentially received. For valid causal `seen` values use only prior known sequences; negative tests mutate them explicitly.

The oracle has **three separate sources**, none the new verifier:

1. Literal hand-specified per-step authority/role/device/skip tables for the small histories above; literal expected set membership and exact expected original-hash identities.
2. The existing complete-history `fold` on the **uncompacted** signed history (and existing M1 effects where appropriate), run without the new authority-analysis entry. Compare owner/members/DEK projection, op skips and version order. The compacted candidate's retained subset is not the oracle input. Because shared-handler bugs could correlate, the literal tables are mandatory too.
3. Existing independent canonical/signature primitives plus literal canonical files/SHA256SUMS. Recompute expected tombstone digests from the literal sorted original fact-hash array and also compare the actual M1 digest API. Do not calculate all expected results by serializing the candidate under test.

Keep every original fact object/signature in fixtures, including facts whose targets have no versions and facts by later demoted/removed devices. The M2a frozen deletion variants retain unverified final-overlay claims and remain **candidate-only**; do not relabel them as semantic successes or “fix” their hashes. The new stronger final-fold oracle will belong to M2b.2.

## 7. Mandatory negative and regression families

For inner-semantic negatives, recompute component/raw/chunk/count/hash metadata and validly sign the enclosing manifest with the synthetic pinned key. A failure only at outer integrity is not evidence of an inner check.

- Bad original commit/fact signature with valid manifest; malformed ops/targets; wrong environment; unknown author; unknown fact kind; incorrect canonical identity; forged/substituted genesis, seq>1 init, init not first op, duplicate init.
- Same signing fingerprint but different valid self-signed agreement key in approval, table, recipient local input, admission or snapshot; invalid self-signature; extra/missing/coercively encoded device fields; inconsistent full copies. Never use fingerprint-only equality.
- Authority reference subset/extra reference; missing recipient admission; recipient added as another role then claimed correct; multiple admission attempts; self-claimed admin snapshot; nonadmin inviter; signer/recipient demoted/removed at cut; failed owner role change, owner removal, transfer by nonowner, transfer to absent/removed target, re-add removed identity.
- Intra-commit demote-then-admin-op and remove-then-admin-op; unauthorized retained data op; no dropped/skipped authority record to make the result pass. Confirm ordinary fold still records its original skip while checkpoint eligibility refuses.
- Duplicate author slot, missing signed nonzero head, mismatching hash/sequence/HLC, nonmonotone retained HLC across a gap, ahead-of-vector `seen`, self-seen at this/future sequence, retained seen reference with impossible HLC. Zero vector must not manufacture a head. Huge integers remain exact.
- Snapshot member name/device/status/role, owner, generation/current/wrap mismatch with replay; selected wrap from an inapplicable admission/rotation; wrong source index. No required-generation usability claim from these public tests.
- Non-removal fact author never a member/admin; grant only in a skipped authority op; schema-valid fact with wrong target kind/shape; `secret_deleted` malformed target; changed original sig/hash; substituted fact environment; omitted one of two same-ID deletions; wrong M1 digest despite equal vectors.
- Historical fact by now-demoted/commit-removed admin succeeds **only** with actual qualifying retained interval and the exact approved attested set. Ordinary M1 incoming-fact rejection remains unchanged. Add a loader/receipt regression showing `secret_deleted` has no new receipt-free historical shortcut; existing admitted/receipted facts still survive later role change. Do not weaken the existing tests or bypass receipts to manufacture the result.
- Any `member_removed` fact, including valid by-admin, self-removal, reciprocal removal, owner removal, unrelated removed-admin attempt and malformed original signature, cannot yield M2b.1 success. Well-formed/signature-valid cases return the explicit unsupported scope. Nonempty removal metadata with no corresponding fact is also refused, not silently cleared.
- Valid remote attestation plus occupied private/shared secret ID, occupied connection ID, conflicting mapping, existing admitted commit/fact/checkpoint, unsent edit, pending/completed import or stale-restore marker refuses. Include deleted/no-version IDs and M1 restored bindings; remote empty sets cannot clear independent local restrictions. Unrelated scopes remain in the observation unchanged.
- Pair another manifest, payload, approval hash, recipient agreement key, environment or session/onboarding nonce; refuse before producing a candidate. The local observation revision is bound into the result, not a manifest field: changing only that revision requires fresh analysis and later activation revalidation, not a fabricated remote-mismatch assertion. Inputs/results remain immutable and errors/debug never echo synthetic sensitive markers.
- Compile-fail examples prohibit constructing/deserializing/converting the new result into install authority or local receipt. Candidate JSON from M2a is not an accepted semantic input. A coherently attested false final-document digest can yield **only** this limited candidate; no API reports final-digest verification. No decrypt/KMS/derive call exists.
- Preserve all M2a parser/canonical/strictness tests, including private-name objects and original-byte semantics, all frozen fixture bytes and all old compatibility behavior. Test small-stack success/error/drop in debug/release for newly materialized semantic paths at total depth64, and early depth65 refusal. If existing helpers cannot meet it, report the boundary; no production stack workaround.

Use deterministic permutations of input construction/hash order and repeated calls to show deterministic observations, not an unbounded randomized campaign. Measure the new phase's peak memory and elapsed work separately on large bounded snapshots/record counts in isolation; report actual source/platform/process scope. Do not claim a 16 MiB payload caps RSS or that this pure library enforces queues/deadlines.

## 8. Side effects, crash and isolation boundary

Production analysis takes no `Context`, `StateDir`, KMS, private `DeviceKey`, audit writer, session, path or filesystem/network handle. It has no success/failure persistent mutation to crash-test. Assert inputs and M1 ordinary state are unchanged in fixture-based integration tests; source inspection must show no production runtime caller. Repeated/failed analysis cannot create local receipts, journal facts, DEKs, mappings, ACK or joined state.

Do **not** simulate an installer to claim crash safety in this task. Later M2c/M2d must test invitation/admission recovery, journal/fsync/visibility/receipt/ACK boundaries, ENOSPC/process termination, and concurrent preexisting gateway/signer readers as specified in decision §§11–12. Keep those gates explicitly NOT RUN here.

All source/helper/dependency/fixture/build/test execution is confined to assigned synthetic-only isolated environments without vault/gateway/signer/coordinator/model/administration authority. Use only owned source/target/cache/temp directories. Do not request or inspect production credentials, mutate VMs/runtime configuration, use another worker's native runner, or execute submitted code on the coordinator host. Native scheduling/provisioning is coordinator-owned; do not poll the active M1 integration task.

## 9. Required verification and evidence

Run focused tests while developing, then unchanged full `rust/verify.sh` on **Linux and native macOS**, source-bound to the final head. No platform exemption follows from macOS-first MLP. If a platform is not assigned/available, deliver code with that platform **NOT RUN**, and mark bounded validation incomplete; do not appropriate another job/VM or turn old results into this head's evidence.

Commands below are for the isolated worker only; none were run by this design task:

```sh
git rev-parse HEAD HEAD:rust
git status --short
rustc --version
cargo --version
cargo tree --locked --offline --manifest-path rust/Cargo.toml --target all -e features -i serde_json
cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_admission
cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_authority_oracle
cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_legacy_parser_regression
cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_manifest --test team_checkpoint_payload --test team_checkpoint_provenance
cargo test --locked --offline --manifest-path rust/Cargo.toml --test whole_secret_tombstone
cargo test --locked --offline --manifest-path rust/Cargo.toml --lib team::checkpoint
cargo test --locked --offline --release --manifest-path rust/Cargo.toml --lib team::checkpoint
bash rust/verify.sh
git diff --check
git diff --name-only
```

Place new stack tests under `team::checkpoint` or explicitly run their actual target in both profiles; a filtered command selecting zero tests is not evidence. Full verification includes formatting, strict Clippy, library/binaries, every discovered integration target, all signer probes and docs. New targets are automatically included by unchanged `verify.sh`; no CI/script edit is needed. Keep lock/features identical, including M1's additive control parser and M2a's 36-input old-path regression.

Bind OS/toolchain/model/base/head/Rust tree, supplied prompt/design hashes, exact commands/exits/per-target results, original failures, source/exec-bit before/after inventories, protected-file hashes, fixture/generator hashes, raw logs and measured resource limits. Preserve all failed attempts under their actual source; fix only allowed code and rerun relevant tests. Broaden/repeat only for changed code, a failure or a specific unresolved concern. Do not skip or weaken the grant-expiry/native pairing failures if encountered. Desktop/native release stack verification belongs to the separately supplied combined integration source and later final-M2 acceptance; Rust success here does not certify those paths.

## 10. Handoff and exact remaining gates

Return actual model/settings, starting/final SHA/tree, changed files, implemented API and stage limits, deterministic oracle sources, original-fact preservation evidence, full focused/Linux/macOS outcomes, remaining limitations, every unresolved original finding ID and the exact diff. A bounded local worker commit is permitted for source binding; no push/PR/merge/deployment/permission change/coordinator-runtime edit is authorized. The controller collects/publishes separately and binds any later review to the actual head.

Explicitly retain:

- **M2-G01 OPEN:** actual M1+PersonalVault combined runtime source and evidence still required.
- **M2-G02 OPEN:** next slice's covered class is not complete removal-dependent authority/full integration.
- **M2-G03 OPEN:** removal admission/placement and recomputed final overlay are not implemented here.
- **M2-G04 OPEN:** proof-preserving compaction and continuation/floor/history-required behavior remain.
- **M2-G05 OPEN:** required-generation and ciphertext usability remain unverified.
- **M2-G06 OPEN:** durable approvals/renewal, live raw-byte transport and enforced budgets/deadlines remain.
- **M2-G07 OPEN:** fresh separately signed READY and lock-protected cut recheck remain.
- **M2-G08 OPEN:** journal/recovery/coherent epoch at all reads and credential use remain.
- **M2-G09 OPEN:** durable provenance-before-receipt/ACK/join and restart retention remain.
- **M2-G10 OPEN:** final-head actual Opus, crash/concurrency, native/physical two-Mac, direct and forced TURN TLS/UDP-blocked acceptance remain.

Preserve `ZPLINK-OPUS-01/02/03`, `ZPL-SEC-01/02/03/04`, `DOS-1` with original severity/evidence, both 8258 native desktop pairing failures, prior Linux grant-expiry/ENOSPC/superseded runs and all unrelated release gaps. No actual M2b Opus IDs exist in this brief. Native Go/service Opus results cannot close Rust review. Do not relabel this task as Opus, full-M2 or release PASS.

Ready brief: **On the exact coordinator-prepared immutable M1+M2a composition, implement only the pure retained-authority/non-removal-fact candidate and independent tests above. Preserve original M1 rules and all frozen bytes. Refuse removal-fact scope explicitly. Deliver source-bound isolated Linux/macOS results and a noninstallable output; leave all runtime/release gates open.**
