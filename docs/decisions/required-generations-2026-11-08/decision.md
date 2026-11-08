# Required-generation availability and ciphertext authentication: bounded decision

2026-11-08, Asia/Seoul. Actual author/runtime: **OpenAI gpt-6-astra, ultra reasoning, T3 Code through the Codex harness**. The requested model/settings were used, without substitution, delegates or workflows. This is independent product dependency planning under the original macOS personal-vault implementation goal. It is not implementation, execution, adversarial review, service review, acceptance, deployment or release.

## 1. Decision and exact assurance

**READY for one later bounded Sol/ultra implementation task:** add an opaque, noninstallable required-generation/ciphertext candidate reached only from an existing `CompleteCutSemanticCandidate` and the exact recipient's in-memory `DeviceKey`. Check every required generation and authenticate every active/staged ciphertext of every nondeleted secret in that candidate's privately computed final document. Keep the recovered required DEKs privately in zeroizing memory, discard each plaintext immediately, and return no result on any failure. Add no runtime caller.

This advances the required-generation availability and currently usable ciphertext check in separate trusted key-bearing memory. Here “currently usable ciphertext” means **the ciphertexts whose final statuses make their values eligible for trusted vault retrieval**, not a promise that each value works with a provider, forms a valid HTTP header, or is a usable SSH key. The result's name and stage must say ciphertext checking, never credential readiness. It covers all four existing secret kinds as stored bytes; it is not restricted to API keys or to currently granted connections. Section 5 explains the deliberate assurance boundary against actual vault, gateway and signer code. Full M2-G05 remains OPEN, including integration and any stronger credential usability claim.

No missing public-source dependency prevents this finite stage. Narrow private access and envelope temporary ownership changes are included in the attached task. The **runtime prerequisites remain absent**: a trusted persisted-approval/local-state collector, authenticated live transfer, independently assigned execution environment, freshness/publication lock and installer. None is invented to make this library stage ready. If the worker cannot implement the specified cleanup/access within the finite allowlist, it must return that exact dependency rather than widen the task.

Use this capability name rather than renumbering milestones. The older M2b admission decision labels compaction M2b.3 and puts later trusted generation checks under M2c; the later complete-cut decision calls generation work M2b.3 and compaction M2b.4. These are local cross-references, not a changed full-M2 contract. This document does not rewrite either decision.

The settled product remains two explicitly approved Macs synchronizing encrypted personal-vault versions, eventually with authenticated initial snapshot onboarding; separate opaque link/service repository and own coturn; local vaults; no operator decryption/server offline vault copy. Local HTTP gateway and separate SSH signer boundaries remain. SSH is a core feature. Unsupported arbitrary secret-consuming CLIs fail explicitly without plaintext fallback. Python and retired UI are not restored.

## 2. Verified source and input binding

The first operation hashed `/tmp/zeropw-required-generation-astra-20261108.md` with host Python `-I -S` standard-library DATA operations and refused reading on mismatch. Its SHA256 matched `33b0223d0b09bb999caab1f6897a17b50387c5dd5d11a574db05361f768ca278`. All twelve inputs below were then independently hashed before source inspection, with zero mismatches.

Source inspection used the T3-supplied checkout `/Users/ys/.t3/worktrees/zeropw/t3-c31bd371`; no checkout was created. The brief's original input copies under `/Users/ys/.t3/worktrees/zeropw/t3-e26a33fa` were read only as hash-bound DATA.

| Binding | Verified value |
| --- | --- |
| HEAD | `8ca2cf0163bc7b3c9681d9a0df4e9f4b81e820e0` |
| Full tree | `3d889eed2755e3491184f9bec7962c80a7fbfadc` |
| Rust tree | `4536b42fb5206b446d4c6760c37c80281bcd3cbe` |
| Desktop tree | `2413844c89265a3e239be2372d34b1e6e1b2d4bb` |
| Bound inventory | 1,266 entries, all actual SHA256/length/POSIX modes and Git modes/blobs matched; Git blob identities independently recomputed with host hashlib |
| Repository changes | No tracked diff at initial inspection; no repository/source/ref/PR/runtime edits authorized or made |

In the following table, `original/` means `/Users/ys/.t3/worktrees/zeropw/t3-e26a33fa/`; `preparation/` means `/Users/ys/Code/zeropw-mlp-evidence/m2-required-generation-preparation-20261108/`.

| Input | SHA256 |
| --- | --- |
| original/docs/decisions/m2b2-semantics-2026-11-07/decision.md | `5d297d887dda694d0d36881a6402c5e94faeb194558329a1f82287206806df2c` |
| original/docs/decisions/m2b2-semantics-2026-11-07/implementation-task.md | `dfc0a4e455f8f4a20e5d81627c52eb7dde19c399f4ec48ce5177c5834f178c51` |
| original/docs/remote-sync-next-milestones.md | `d6b35644435080b030399f050ed2a9c7d6c94c606f1c9c2567a3914b71a8bfca` |
| original/docs/evidence/2026-11-08-m2b2a-native-2936202/collection.json | `838b7ecefb20c0804737d83176047bae0515cf1b5922a0ec8f7d5e1d19764120` |
| original/docs/evidence/2026-11-08-m2b2a-native-2936202/STATIC-COLLECTION.md | `22b60a29881cd34af1c20aa3a30c52c4616c880cf373765a3c9d35dcbfb01a80` |
| original/rust/src/team/checkpoint/mod.rs | `2dc07f96491bd97b4d2f0821d737b06c2af8dbc4b6f59c8cf8e58da49e8e9af5` |
| original/rust/src/team/checkpoint/semantics.rs | `fafb1f22624a9930892a5a8dc4d9ac2e2b6df660f37b28252b19283c9fdcd688` |
| original/rust/src/team/checkpoint/document.rs | `8193dc0d5cd6d2829919981aad68efcf487d58172d9640b879d6c4ca6cc13a9c` |
| original/rust/src/team/envelope.rs | `517e5d55ab19febeedb38fae9c8339d55ed5c33e6c6c50524fb6f73a249798e6` |
| original/rust/src/secret.rs | `5a50da1641a190ca23b9171d156df1a109ef5b3f9db4b18637b6012df4de8d59` |
| preparation/source-binding.json | `71f74767549fc40af057ad2d375176934a64c29549ea7531e349ffa0a8998619` |
| preparation/source-manifest.tsv | `ef6c0c06d5047df10f261e3b63bbe7449bc2c6677bce7a3e8b02ed6c0f0ec3a8` |

The complete preparation manifest remains the finite before/after baseline for every protected file. Hashing all source is not reviewing all source. Frozen fixture checks were DATA only: all 145 `team_checkpoint_v1`, 149 `team_checkpoint_semantics_v1`, and 97 `team_checkpoint_m2b2_v1` SHA256SUMS entries matched. Their catalogue digests are respectively `a5981856f26e687352a97836372816eaba0f98c285f8a8a41645678c8f8ebc88`, `74877c9b8a930aa21a0c3a8fc5cf3519e11c97c6cd13ba1e3a6107235e19a199`, and `950e7bc521197d24dc9d86ae60438fba3beb5901c4627f34c70926887bae1fcf`. No fixture was generated, signed or decrypted here.

## 3. Actual checked route and private evidence

`verify_complete_cut_semantics<'m,'p,'b>(&ManifestAttestation, &IntegrityCheckedPayload<'b>, &SemanticLocalInputs)` is the only constructor of `CompleteCutSemanticCandidate<'m,'p,'b>`. Its fields are private: `originals`, `removal`, `trace`, `_bases`, `_document`, `_order`, `generations` and bound digests. `_document` is the computed **final** result, not the supplied unflushed image. Existing observations expose digests/counts and referenced/required generation IDs, not the document or keys.

The checked route calls `AuthenticatedOriginals::authenticate`, `check_history` and `complete_coverage`; authenticates full original device/commit/fact identities; requires unique recipient admission and complete supplied author slots; checks the finite removal class; calls the actual complete fold; compares full unflushed image/order and final digest; preserves M1 facts/local restrictions; and requires final active signer/admin and exact active recipient role. It borrows the exact manifest, integrity-checked original payload spans and local observations. `SemanticLocalInputs::from_local_observation` is shape-checked caller input, **not proof that a trusted collector observed approvals or current storage**.

`document::validate` computes `GenerationReferences.required` from every nondeleted secret version with status `active` or `staged`. `referenced` includes every generation in the DEK map, including generations with no required versions. It checks generation existence, exact version indices, active/deleted relationships and connection pins. `document::check_puts` binds original kind/generation/nonce/ciphertext/public values to the produced versions. The new stage traverses this same private final document, checks its required-set equality to the private summary and counts every required version. It does not derive its authority from a caller's generation list, connection list, image, `Value`, path or string.

`payload::selected_wraps` and `recipient_wraps` select only original whole-commit operations:

- `member.add`: `ops[source_op_index].wraps[generation_id]`; that operation's full device record has the manifest recipient fingerprint.
- `env.init` / `dek.rotate`: `ops[source_op_index].wraps[recipient]`; the operation has the matching generation ID.

Entries are sorted/unique by generation/source hash/op index, contain the manifest recipient, and equal the original selected wrap canonically. The unavailable list cannot overlap selected entries. These are structural checks, not standalone permission.

`CheckpointCompleteTrace::operation` records `applicable_wraps` only for successful operations. In `member.add`, a wrap applies only if its generation exists at that operation's position; the ordinary `op_member_add` silently ignores wraps for absent generations. `effective_wrap_sources[(generation,recipient)]` tracks the last applied source position. `verify_complete_cut_semantics` already checks every selected entry against applicability and, when it names the effective source, against the final document wrap. It does **not** require that every required generation has its effective source listed, or that any wrap decrypts. Its existing unavailable-required-generation successes are intentional and must remain unchanged.

The new stage must require the **effective source selector itself** in the selected entries for each required generation, check its exact final wrap binding, and use it. An image-only wrap, an old successfully decryptable historical wrap, or a selected historical source with the effective source missing is insufficient. It must also check all other **selected** wraps for that required generation and require 32-byte results constant-time equal to its effective DEK. No first-success search, alternate generation fallback or success after discarding a bad selected wrap. This proves consistency of selected wraps; it does not claim every unselected historical wrap has been decrypted. Nonrequired selected wraps remain structurally/semantically checked by the original candidate but cryptographically unassessed here.

New-recipient support is grounded in `TeamSync::admit_member`: it wraps each locally available generation for the new full device record and emits an original signed `member.add`. Existing generations can therefore be supplied at that original admission without a new crypto/wire format. Absent sender keys are skipped by that producer; they are not conjured by the verifier. The original unique admission, final role and source applicability are already checked. The two separate human decisions remain the recipient's explicit pinned administrator approval and the inviter's explicit recipient approval, bound by the manifest's existing IDs/hash/nonces/admission fields. Their durable reality is a later gate. Do not require invented fact-receipt chronology, require that the new member existed before the generation, or authorize an unsigned later rewrap. If the effective original required wrap is unavailable, return unavailable; obtaining exact originals or designing a future authenticated repair is outside this task.

## 4. Required-set and failure contract

Let Q be all `(secret_id, version_id, generation_id)` from the candidate's final nondeleted secrets whose versions are active or staged; let R be their generation union. Use original IDs and exact final entry maps. All Q are checked, including multiple versions on one DEK, staged versions with no active pointer, no-grant secrets, disabled/unreferenced connections and older generations. `dek.current` alone is never the criterion. Existing pin/follow/order semantics remain intact; no unknown pin becomes follow-active and no retired/revoked/deleted pin becomes usable.

For every generation in R: absence from final DEK metadata, absence of a required selected effective original wrap, explicit unavailability, malformed wrap, low-order point, wrong key/environment/generation/recipient, invalid nonce/tag, non-32-byte DEK, or disagreement between selected historical/effective DEKs fails the whole new stage. All previously obtained keys and temporary plaintext are dropped through zeroizing owners. For every tuple in Q call the existing `envelope::decrypt_secret` with that DEK and exact environment/secret/version/entry. Authenticate each blob; one good blob per generation is insufficient.

Retired/revoked versions of nondeleted secrets and every version of deleted secrets remain in the encrypted candidate, with exact order/history/facts. They are not in Q and are not decrypted. Explicitly unavailable nonrequired generations are allowed and preserved. A nonrequired generation absent from the unavailable list is merely unassessed, not newly declared available. Corrupt historical ciphertext is not reactivated or erased to pass this stage. Final deletion, including restrictive put-then-delete effects and same-ID/no-version tombstones, determines exclusion. If R and Q are empty, identity and candidate binding checks still run; a zero-count noninstallable candidate is valid and no unwrap/decrypt occurs. It does not mean there is a usable credential.

Use the existing closed `SemanticError`. Recipient key derivation/identity mismatch maps to `Checkpoint(BindingMismatch)`. Required wrap absence/explicit unavailability/crypto failure/length mismatch/selected-key disagreement/required ciphertext failure maps to `GenerationUnavailable`. Checked resource-limit failure maps to `Checkpoint(LimitExceeded)`; an internal final-summary inconsistency maps to `SemanticMismatch`. Do not expose underlying error detail or new peer-controlled strings. No partial proof, keys, successful-prefix report or failed-secret identifier is returned.

## 5. Existing crypto and the limit of “usable”

`envelope::unwrap_dek(wrap, env, generation, device) -> Result<Vec<u8>>` uses the existing X25519 contributory check, HKDF-SHA256 and ChaCha20-Poly1305. Its info/AAD is `DEK_INFO_PREFIX || env || generation || device.fingerprint()` where the prefix is `zeropw-team-dek-v1`. It checks the ephemeral point length; AEAD checks nonce/tag. It currently returns any authenticated plaintext length. The new candidate must independently require exactly 32 bytes, after immediately adopting the returned allocation into `SecretBytes`.

`envelope::decrypt_secret(dek, env, secret_id, version_id, &Map<String,Value>) -> Result<Vec<u8>>` uses existing AAD `env || NUL || secret_id || NUL || version_id`. Generation ID and kind are **not** added to this AAD. The signed semantic candidate supplies their association. Use the existing helper unchanged; never add a hand-written cipher/KDF/AAD, a new codec, or alternate key lookup. Identical DEK bytes deliberately reused under different generation IDs cannot be distinguished solely by secret AEAD; the original selected-wrap generation binding is still mandatory. Independent negative fixtures must use distinct DEKs when testing wrong-generation key substitution, and document this AAD limit rather than claiming extra cryptographic binding.

Envelope field decoding uses existing lenient `pybase64` and Python-string compatibility; the new checkpoint entries already have string fields. Do not use manifest `fixed_b64` (strict re-encoding) to redefine legacy envelope parsing. Any decoded-size preflight uses the existing decoder. Existing numeric/canonical/span helpers, total depth, `raw_value` absence and all legacy parser behavior are frozen.

`Vault::secret_for_trusted_use` checks identity/deletion/version/status and decrypts to `SecretBytes`; its active/staged read does not validate an arbitrary value's plaintext syntax. `Vault::public_metadata` parses SSH on local secret input. At actual SSH use, `signer::public_key` parses stored public metadata; `signer::sign` separately parses the decrypted OpenSSH key and checks its public key against metadata before signing. The HTTP gateway separately validates header/auth encoding after retrieval. Therefore AEAD-valid bytes, including empty/non-UTF8 values, are valid ciphertext-authentication results, but can be unusable for a particular connection.

**No kind-specific plaintext parser is necessary for the exact assurance chosen here.** Do not call `Vault::public_metadata`, `sshwire` parsing, `auth_header`, a gateway, signer or remote provider in this stage. In particular an AEAD-valid malformed SSH value may pass this stage and must not be described as signing-ready. Include an explicit limitation oracle demonstrating this distinction using the existing parser in an isolated test, with no request/signing operation. Before any stronger imported-credential/SSH-ready claim, validate the relevant existing syntax/metadata/connection rules in trusted memory as a separately bounded dependency. This preserves SSH rather than silently declaring invalid keys usable or excluding SSH from stored-byte verification. Full M2 cannot be accepted by relabeling this narrower result.

Inspection also found that `sshwire::decode_openssh_pem`/`parse_openssh_private_key` allocate a PEM body String, decoded blob, private section, private field, comment and seed array beyond the final `SecretBytes` seed. Adding that parser here while promising comprehensive cleanup would require an additional precisely scoped ownership change. This task does not invoke it in production or claim those existing temporaries were fixed.

## 6. Type, memory and process boundary

Place the implementation in a child of `checkpoint::semantics` so it can borrow the parent's already-private fields without adding public raw document/selectors getters. The single entry is prescribed in the implementation task. The result borrows the exact complete-cut candidate and **owns only its required DEKs as a private map of `SecretBytes`** plus bounded nonsecret counts. It does not retain any credential plaintext or clone the DeviceKey. The DeviceKey is borrowed only during validation; the successful result owns the recovered keys. It must not implement Clone, Default, Deserialize, Serialize, Deref/AsRef-to-key, key/plaintext callbacks, conversions to Facts/receipts/provenance, or any export/install/use method. Debug is a fixed redacted name, with no nested derived Debug. Public methods are fixed stage/trust strings, existing candidate binding digests/revision and aggregate required-generation/checked-ciphertext counts only.

First derive `device.record()` and require full equality (`sign_pub`, `agree_pub`, `sig`) with `originals.local.bindings.recipient_record` and the authenticated device-table recipient. Check its fingerprint against the signed recipient. Fingerprint alone binds only the signing public key; a changed agreement key with the same signing seed must fail before unwrap. Malformed private-key lengths must produce a fixed binding error. All candidate checks and nonsecret selector/size checks precede expensive private-key operations except the necessary identity derivation.

`SecretBytes` is `Zeroizing<Vec<u8>>`, with redacted Debug, public expose/ct_eq and existing Clone. Preserve that public API; its existing Clone does not permit a new proof to clone or expose private map values. `SecretBytes::new` takes ownership without copying. Immediately adopt each successful unwrap/decrypt Vec, before any fallible branch, comparison, logging or accumulation. Keep at most one credential plaintext alive, drop it before the next version, and retain no plaintext-derived digest or value in result/errors/tests' public observations.

Caller wrapping alone does not clean all existing envelope temporaries. `unwrap_dek` currently owns an X25519 shared-secret array and a plain HKDF key Vec; `hkdf` owns a plain PRK; extract/expand materialize MAC output, block and output buffers, replacing blocks and truncating expanded output. Allow a minimal internal ownership-only change in `envelope.rs`: zeroizing guards for named shared/key/PRK/block/output allocations; wipe discarded HKDF tail before truncation and replaced block contents; wipe explicit MAC-output byte buffers after copying/moving their needed bytes. Preserve every public signature, output byte, HKDF boundary, error reason/class, lenient parsing and old test. A guard transfer may move the final Vec out to preserve the old API; the new caller immediately adopts it. No generic secret-returning RPC/helper is added.

This is a scoped cleanup guarantee for the new code and named envelope-owned buffers on ordinary completion/error/unwind. It is **not** proof that existing HMAC/AEAD/X25519/Ed25519 dependencies, compiler/register copies, allocator remnants, swap/core dumps, abort or power loss zeroize everything. The actual X25519 wrapper itself uses by-value arrays; dependency internals were not inspected or executed here. Do not hide that limit or add unsafe/Cargo features/library rewrites to claim otherwise. If stronger whole-process erasure is necessary for a later claim, return it as a prerequisite.

The library is part of the trusted Rust backend. `server`/`gateway`/`signer` use trusted Context/vault state; `agent_cli` is a JSON client and does not open the state directory; desktop core spawns existing admin/agent binaries and does not link this crate. None of those callers is changed. No key crosses to agent execution, CLI arguments/env/files, connection adapters, link service, tool/HTTP responses, errors, logs or tracing. A Rust type alone is not process isolation: the eventual caller must run in the separately protected vault/backend, never in a validation worker or process holding agent-submitted code. This task provides no new caller or credential-loading path.

The proof is an observation of one immutable bound cut. Borrowing a local metadata snapshot is not a lock. Dropping it wipes owned keys; it creates no receipt, restart authority or persistent cache. A later changed payload/manifest/record/local revision needs a fresh checked route. Before any eventual publication, independently recollect current approvals, membership/removal, facts, collisions, eligibility, epoch and live-session/READY state under the proper synchronization and abort stale results. Keeping this object alive does not make its snapshot fresh.

## 7. Finite work and no side effects

Retain 64 KiB manifest, 16 MiB decoded payload, 256 devices, combined commits+facts+versions <=65,536, depth64. Recipient-wrap count is separately bounded in current manifest code by 16,777,216 and actual bounded payload bytes; do not incorrectly claim it is part of the 65,536 combined count. Iterate observed spans/versions/operations, never a numeric vector, peer count reservation or generation token range.

Let P be payload bytes, O observed operations, W selected wrap entries, V required versions and K required generations. K <= V <=65,536, so DEK payload bytes are at most 2,097,152, exclusive of map/string/allocator overhead. Index actual selectors/required version references once; avoid K-by-W scans or repeated complete folds. Extra storage is bounded indexes plus K DEKs and one wrap/one ciphertext/plaintext work unit. Do not clone the final document, accumulate plaintext history or build a document per operation. Materialize a selected wrap only from its original private inherited-depth span. Use checked sums/reservations based on observed lengths; do not expand before checking existing byte caps. A required wrap's decoded sizes are point32/nonce12/ciphertext48; use compatible decoding for preflight and free its nonsecret buffers before the existing unwrap if decoding twice. Bound per-version decoding by the existing P cap. No decompression or paths.

This is an algorithmic bound, not an operational RSS/CPU guarantee. Existing complete-candidate construction is still a prerequisite with its own cost. The earlier 1,050,672 KiB fixture-process peak includes fixtures/parser/prior-test state and is neither runtime nor Oracle capacity. Future measurements must separate fixture construction, semantic-candidate construction and the new key stage, include late failures and maximum reachable cases, and preserve results. Actual 256 KiB stack success/error/repeat/drop at depth64 and depth65 refusal are required in debug/release on assigned Linux/macOS. Never enlarge stacks or weaken tests to hide failure.

No Context/StateDir/path/KMS/clock/session/audit/installer input. No `derive_local`, local DB/KMS request, normal incoming fact admission, `load_facts`, approval persistence, raw transport, READY, local binding migration, journal/recovery/epoch, receipt/ACK, UI/status, capability advertisement or credential dispatch. Full runtime queue/staging/concurrency/deadline/cancel enforcement remains later: four outstanding chunks, 512 KiB queued frames, 64/128 MiB staging, one transfer/environment and two/process, ten-minute total and 30-second idle, with a demonstrated execution boundary. This static task allocates no runtime resource or lease.

## 8. Evidence and unchanged gates

Attributed existing execution, read as saved DATA: earlier Linux exact Rust4536 passed109 steps/1,766 tests. Native HEAD `29362020ed7a57451d0984eefb6eeb4e6c110b0c`, same Rust4536, passed unchanged109 steps/104 integration targets/1,769 tests,0 failures; all20 phases exit0, each of four actual256KiB selectors ran exactly1. Focused phases overlap and are not summed. All1,259 native source byte/mode entries matched before/after;172 archives/8,194 cache-file audit is attributed runtime evidence, not a new local archive rehash. `raw_value` absent. Native was virtual macOS26.6.2 arm64,2vCPU/4GiB,SIPdisabled, not physical/GUI/network validation. Mac501 was explicitly RELEASED at 2026-11-07T18:03:28.343444Z. There is no VM/resource assignment to this design or implicit permission to reuse it. Two collector-only errors and every prior failed/NOTRUN job remain preserved. Later documentation at HEAD8ca is not a new whole-head execution. No result covers the future diff.

The separate Go service remains under **Linux case12 quarantine / UNRELEASED lease**. The actual Astra custody disposition and its one fixed-object DATA check found no independent custody packet, as supplied in the controlling brief. I did not query custody or inspect live service state. No root fix, new query/campaign/D0/canary/test, restart/reset, deployment or custody bypass is authorized. This product dependency cannot release that hold.

Canonical ca01275 remains REVISE with unchanged evidence and severity: `ZPLINK-OPUS-01/02` resolved only for their original scenarios; `-03` OPEN with `-03-R1` rotation crash consistency; `ZPL-SEC-01/02/04` resolved for original scenarios; `ZPL-SEC-03` INSUFFICIENT_EVIDENCE; new04–10 LOW and11 JSON nit/Markdown NIT/LOW preserved. **DOS-1 remains original HIGH / OPEN_NOT_FIXED_PARTIALLY_MITIGATED.** Canonical JSON/Markdown were independently hashed unchanged: `81e95b6a3665607b510f0cc77ab5cdd27bf78ed71f4688faaa94acb8a3e50c90` / `63c400a776a51ddbc58a1c33d2a6260a9ef78421044a8a1514d79053d30a381a`. No finding is reassessed here. Actual Opus3eb remains interrupted with no completed accepted verdict. No retry/rephrase/recheck/review substitute/provider/model replacement was started or authorized.

| Gate | Status / still required |
| --- | --- |
| M2-G01 | OPEN: final-head M1 integration, complete original tombstones and durable session ACK/runtime behavior |
| M2-G02 | OPEN: full original authority/removal classes, exact device identity and integration; finite complete-cut candidate is insufficient |
| M2-G03 | OPEN: general/gapped historical admission and interacting-removal/final-state proofs; no missing chronology invented |
| M2-G04 | OPEN: proof-retaining repeated compaction, signed heads/floors/continuation and explicit history-required refusal |
| M2-G05 | OPEN: this stage is planned, unimplemented/unvalidated; required-key/ciphertext checks, stronger credential assurance where claimed, and full import integration still required |
| M2-G06 | OPEN: durable two-sided approvals/exactly-once admission, authenticated raw transport/capability, budgets/deadlines/cancellation |
| M2-G07 | OPEN: fresh challenge/READY and locked exact-cut/current-approval/revocation checks |
| M2-G08 | OPEN: current eligibility/collisions, journal/fsync/recovery, coherent committed epochs across readers/cached credential use |
| M2-G09 | OPEN: durable committed provenance before receiver-local receipt/ACK/activation; restart/compaction retention and downgrade boundary |
| M2-G10 | OPEN: future exact-head isolated Linux/macOS full/focused/privacy/resource/crash/concurrency evidence, physical two-Mac/direct/forced TURN TLS with UDP blocked, actual Opus and Astra acceptance |

Packaging, deployed HTTPS/TURN, Oracle deployment/capacity, macOS ACL residual evidence, offline-revocation limits and release remain independent gaps. No old PASS or current pure result closes them.

## 9. Inspection scope and omissions

Read as text/data: AGENTS; product intent/security design/harness; harness README; PORTING §1; complete remote-sync milestone contract; whole-secret deletion; complete substantive M2b2 decision/task including integrity footers (inventory appendix hash-bound, not semantically reviewed); relevant M2a approval/selectors and M2b generation/compaction/runtime/milestone sections; native collection and static collection; canonical/interrupted review READMEs and canonical file hashes. Dated statements about reserved/pending native resources in earlier decisions are superseded by the brief's explicit release, not repeated as current state.

| Source (at HEAD8ca/Rust4536) | Actual semantic inspection |
| --- | --- |
| checkpoint/mod.rs; document.rs; semantics.rs | Full files; checked route, private final image/order, generation refs, selected-wrap checks, metadata APIs, literal test boundary |
| checkpoint/originals.rs | Full file: authentication/binding/device copies, unique admission/history/complete coverage |
| checkpoint/admission.rs | SemanticError, binding/local input types/constructor, original retained-route scope refusals and authority/wrap flow (not whole file) |
| checkpoint/payload.rs | private candidate/span ownership and `selected_wraps`/`recipient_wraps` (not whole parser) |
| checkpoint/manifest.rs | expectation/approval types/constructor boundary; names/counts; numeric/count/length bounds and helper locations; not full manifest review |
| team/fold.rs | member.add, generation/init handlers; complete trace operation/applicable/effective selectors; generation lookup, derive_vault and derive_dek_generations; no full fold re-review |
| team/sync.rs | `TeamSync::admit_member` original admission/wrap production; no service/session state-machine review |
| team/envelope.rs | Full file: HKDF, wrap/unwrap, secret AAD/encrypt/decrypt and existing tests |
| team/identity.rs | 1–300: full DeviceRecord and DeviceKey definitions/record/fingerprint/sign/load/store; later recovery not reviewed |
| secret.rs; Cargo.toml | Full SecretBytes; Cargo dependency/features entries including existing zeroize, serde_json, HMAC/AEAD/X25519 |
| crypto/chacha20poly1305.rs; crypto/x25519.rs | AEAD constants/decrypt (245–274) and X25519 production wrappers1–180; dependency implementations not reviewed |
| vault.rs | generation-key lookup, `public_metadata` and `secret_for_trusted_use`; no full vault audit |
| sshwire.rs | private-key type/API locations; full PEM decoder and private parser985–1170; not complete reader/public parser review |
| signer.rs; gateway.rs | signer public metadata selection745–771 and private parse/public-key match1120–1165; gateway secret retrieval/auth-header dispatch3480–3525; no full protocol audit |
| lib.rs; agent_cli.rs; server.rs; desktop/core/src/lib.rs | module/process boundaries, client initial interface and trusted listener setup; no desktop audit |
| tests/team_checkpoint_semantic_cut.rs | test/API inventory and generation public-only regression845–925 |
| tests/common/team_checkpoint_m2b2.rs | helper/API inventory and synthetic deterministic crypto construction1–85; not whole builder reviewed |
| tests/team_checkpoint_removal_oracle.rs | oracle function inventory only, not a new review of its whole contents |
| rust/verify.sh | Full script as text: automatic top-level integration-target discovery and five non-target steps; never run |

No full Rust/dependency/desktop/service audit, generated adversarial review, cryptographic execution, current-runner inspection, production credential reading or external lookup occurred. Truncated tool results were not used as proof of complete inspection; required API sections were read separately. All repository bytes were hashed, but only the stated sections were semantically inspected. The accompanying task is normative for the finite allowed changes, independent oracles and prospective validation.

Only the requested external `decision.md` and `implementation-task.md` are deliverables. Final whole-file SHA256 values for both are provided with the handoff; a file does not embed a circular whole-file hash of itself. Source integrity is rechecked after document creation. Static planning establishes neither implementation nor tests nor an Opus/Astra acceptance verdict.
