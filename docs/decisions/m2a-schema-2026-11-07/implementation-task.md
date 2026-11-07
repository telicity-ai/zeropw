# Sol implementation task: M2a original-byte attestation and integrity

This is a bounded implementation brief, not an execution record or acceptance.
Design author: actual **gpt-6-astra**, **ultra** reasoning, Codex harness in
T3 Code, 2026-11-07. Requested worker: **Sol (`gpt-6.1-sol`)**. Record the actual
selected worker model/settings from the invocation; a role name is not model
selection. This brief does not approve a different/default Cloud worker, invoke
one, or authorize any Opus substitution.

## 1. Exact governing inputs

Read the complete sibling [decision.md](decision.md), SHA-256:

```text
564bcf4c312b04507e815e35cc8eed9f5c6ae8f74ee539ccecf88cff8f0595b2
```

Its absolute design path is
`/Users/ys/.t3/worktrees/zeropw/t3-b90cf5b0/docs/decisions/m2a-schema-2026-11-07/decision.md`.
An isolated worker receives a frozen copy with that digest; do not access the
coordinator path or another running worker's checkout to obtain it.

Read project `AGENTS.md`, `docs/product-intent.md`, `docs/security-design.md`,
`docs/harness.md`, `harness/README.md`, `rust/PORTING.md` (especially section 1),
and the entire accepted M2 section of `docs/remote-sync-next-milestones.md`.
The latter must be blob `938a4213f23855c727c9b18dd3cf4d8a97340200` at the design
input. The approved design brief was
`/tmp/zeropw-m2a-schema-astra-task.md`, SHA-256
`1e439b31fec70682d9866ddc284d284747dc9ab743388085effe36f9082557d4`;
the read-only Sol preparation note had SHA-256
`8bb75f7e1af65dc90d73097772b059c7cbf9ca577ebe742f236cac24894d59ca`.
They are source references, not instructions to inspect the coordinator's other
files or runtime. The sibling decision supersedes tentative schema choices in
the preparation note and preserves the already accepted M2 trust contract.

Implementation baseline is Rust tree
`2882ba592e2204eb62723d95e240525e75196f64`, from product source
`52e87b07380a2f752c127c5f89e5f8f76c38937f`; prepared parent docs-only HEAD is
`feca56633e5ad0ce4e0cd1d7c839877bfbb3f172`. Record your actual base and its Rust
tree before changes. If a supplied prepared checkout has a different product
tree, identify the differences and report the integration dependency rather than
guessing M1 APIs. Do not inspect/copy the independent M1 worker's uncommitted tree.

## 2. Outcome and non-goals

Implement only:

1. Original-byte strict JSON parsing and bounded v1 schema validation.
2. Canonical manifest signature verification against separately supplied pinned
   expectations and wall time, returning `ManifestAttestation`.
3. Pure chunk-frame and raw payload/component integrity checks, plus the precisely
   enumerated structural record/hash/count references, returning `CheckedChunk`
   or `IntegrityCheckedPayload`.
4. Serialization of inert `CandidateProvenanceV1` with exact per-fact candidate
   binding; it must never constitute an admission or installation receipt.

The product remains **snapshot onboarding unsupported**. No capability or
runtime call path is added. Full administrator/recipient authority replay, all
original commit/fact signatures and target checks, historical fact admission,
M1 overlay, final fold/digest proof, required DEK availability, finalize freshness
and durable coherent import remain unimplemented gates. Do not add a function
which pretends to verify these, a Boolean callback accepting them, an empty
tombstone shim, `assume_valid`, or a constructor for a `VerifiedCheckpoint`.

No network/routing, READY/ACK, join/status, invitation consumption, approval
persistence, journal, filesystem staging, KMS, decrypt/derive, receipt creation,
credential activation or publication code. Do not change the ordinary sequential
commit/fact admission path to accommodate gaps. The test fixture generator may
use public synthetic crypto and pure folds in isolation; that is not a production
semantic adapter or runtime integration.

## 3. Allowed files

| File | Required work |
| --- | --- |
| `rust/src/team/checkpoint/mod.rs` | Public pure module, narrow re-exports, closed errors and redacted proof/result types; documentation makes each assurance stage explicit |
| `rust/src/team/checkpoint/strict_json.rs` | Private original-byte guard, borrowed RawValue traversal, decoded-key detection, exact scalar conversion, raw spans and bounded container counters |
| `rust/src/team/checkpoint/manifest.rs` | Exact new schema/types, local expectation constructor, canonical unsigned/signed bytes, pinned-key validation, wall checks, fixed limits and partition rules |
| `rust/src/team/checkpoint/payload.rs` | Raw payload/chunk/component hashing and layout; counts; canonical Commit/Fact hash preservation and the decision's structural references only |
| `rust/src/team/checkpoint/provenance.rs` | Candidate construction and canonical export, no deserializer or disk path |
| `rust/src/team/mod.rs` | Exactly the minimum `pub mod checkpoint;` declaration (format ordering as appropriate) |
| `rust/Cargo.toml` | Add `raw_value` to the existing serde_json feature list; retain all existing features and dependency versions |
| `rust/tests/team_checkpoint_manifest.rs` | Black-box manifest/binding/signature/bounds tests |
| `rust/tests/team_checkpoint_payload.rs` | Black-box payload/chunk/span/count/reference/legacy-number tests |
| `rust/tests/team_checkpoint_provenance.rs` | Stage separation, exact candidate output and redaction tests |
| `rust/tests/common/team_checkpoint.rs` | Test-only deterministic fixture builder/support, if needed; no production bypass |
| `rust/tests/fixtures/team_checkpoint_v1/` | New fixture package exactly as decision section 10; never regenerate old fixtures |

Internal parser/count/small-stack unit tests belong in the new module's files;
they can exercise private guards without adding an unchecked public parse API.
Compile-fail doctests belong beside the public proof-type/API documentation.
The integration targets are automatically discovered by the existing
`rust/verify.sh`; run the unchanged full matrix so they participate in existing
validation. Do not edit CI, the harness, verifier scripts, canonical-helpers
guards or their allowlists. No new dependency or version/lockfile churn is planned;
the existing raw_value feature should not require a package update. Report any
unexpected dependency/guard conflict instead of weakening a check.

No edits to `sync.rs`, `fold.rs`, `membership.rs`, `pairing.rs`, `transport.rs`,
`sync_status.rs`, existing identity/commit/envelope/crypto/pyjson/pyint helpers,
product requirements or this governing schema. M1 integration will be a separate
task bound to its exact completed head. A need to widen these files is an
unresolved scope dependency, not permission to broaden this milestone.

## 4. API contract

Use these names and stages; implementation-private helper names are free.
The signatures below specify ownership and input trust, not a demand for a
particular error library wrapper:

```rust
pub struct ExpectedContext { /* private, caller-supplied local expectations */ }
pub struct ManifestAttestation { /* private, no Deserialize/unchecked ctor */ }
pub struct CheckedChunk { /* private, at most 65536 decoded bytes */ }
pub struct IntegrityCheckedPayload<'a> { /* immutable original-byte borrow */ }
pub struct CandidateProvenanceV1 { /* private, inert metadata only */ }

pub fn verify_manifest_bytes(
    original: &[u8],
    expected: &ExpectedContext,
    check_time: VerificationWallTime,
) -> Result<ManifestAttestation, CheckpointError>;

pub fn verify_chunk_frame_bytes(
    attestation: &ManifestAttestation,
    original_frame: &[u8],
) -> Result<CheckedChunk, CheckpointError>;

pub fn verify_payload_bytes<'a>(
    attestation: &ManifestAttestation,
    original_payload: &'a [u8],
) -> Result<IntegrityCheckedPayload<'a>, CheckpointError>;

pub fn candidate_provenance(
    attestation: &ManifestAttestation,
    payload: &IntegrityCheckedPayload<'_>,
) -> Result<CandidateProvenanceV1, CheckpointError>;
```

`ExpectedContext::from_local_expectations` takes explicit typed local approval
description, full authenticated peer record, session environment, local recipient,
session nonce and request nonce. The local approval fields/hash are exactly
decision section 4. This constructor checks shape and consistent expectations;
it cannot authenticate a human or prove persistence, and its name/docs must not
claim otherwise. It does not take a manifest or parse remote JSON. No production
callers are added. Use typed structs for grouped arguments; no loose map carrying
approval Booleans. `VerificationWallTime` contains a checked WallMs value, not a
system-clock read or a fake monotonic timer.

Expose read-only metadata/accessors sufficient for tests and eventual callers:
manifest hash, cut/head metadata and signed descriptors; checked chunk index and
decoded encrypted bytes; immutable component spans and canonical record hashes;
candidate `canonical_json()` using `pyjson`. Mutating the inputs/results or
deserializing candidate JSON cannot manufacture a proof result. Keep the
attestation identity privately in the payload result and reject a different
manifest when constructing provenance. Do not expose constructors that accept
`Value` or claimed validation flags. There is no install/admission type/API.

All limits are fixed by decision sections 5/8, not caller-increasable options.
Tests can directly exercise private counter/guard functions without adding a
production bypass or optional insecure feature. Result/error Debug and Display
must omit raw peer content and synthetic sensitive-marker strings.

## 5. Implementation order and invariants

1. **Strict raw boundary first.** Enforce input byte/depth limits before nested
   serde parsing; container root depth is 1 and 65 is refused at its opening
   delimiter. Use the pinned dependency's borrowed RawValue plus explicit
   container visitors, not `deserialize_any` into Value. Detect duplicate decoded
   keys before insertion, including all legacy children. Preserve literal serde
   private-number/raw-value-key objects as objects. Use scalar `pyjson::loads`
   and manually constructed containers, so a real magic-key object never enters
   serde's private-number interpretation. Reuse the existing canonical writer.
2. **Exact typed control fields.** Original token grammar first, then
   `PyInt::from_json_integer`. Unbounded sequences/HLC counters remain PyInt;
   sizes/counts/indices/times have checked conversions. No coercive numeric helper
   or global float restriction. Retain integer/float distinction in embedded
   legacy signed/document values and preserve their canonical hashes.
3. **Pinned manifest.** Enforce every exact field, both feature names, all supplied
   expected bindings, full pinned/session device-record equality, fixed chunk
   partition, counted bounds, times and signature. Signature = C(manifest minus
   only top-level sig); manifest hash = SHA(C(full signed manifest)). No payload
   decode or reserve before attestation succeeds. There is no pin from payload.
4. **Raw data integrity.** Whole length/hash and each exact contiguous chunk hash
   before payload JSON work; six required components in fixed order; hash the
   original `data` spans, not reserialized values. Enforce counts while traversing
   before large container materialization. Preserve every retained encrypted
   version and the version-order arrays unchanged.
5. **Limited references.** Device self-signatures/fingerprints, canonical
   Commit/Fact hash equality, unique author sequences and hashes, exact vector/head
   references, all declared fact hashes and tombstone-kind hash subset, explicit
   removal witnesses and original wrap selectors. Original commit/fact signature
   validity and semantics are not evaluated here. No `verify_fact`/`load_facts`,
   filtered unknown M1 data or a second production tombstone-admission helper.
6. **Inert output.** Construct only the exact candidate representation in decision
   section 9. It carries `administrator_attested`,
   `integrity_checked_not_admitted` and per-fact candidate bindings. No local or
   sender receipt signature; no full-history label or persist/install action.

The schema tables/code blocks in decision.md are normative; do not substitute
new JSON names, component encodings, chunk partitions, domain prefixes, digest
rules, time units or canonical-number rules. Unknown required metadata is a
refusal. Legacy payload fields remain legacy data rather than a global field or
float ban. Original record headers use their canonical stored representation;
existing standalone legacy loaders are untouched.

## 6. Required tests and fixture acceptance

Implement every test family in decision section 10, including its exact synthetic
baseline graph/IDs/seeds/times and original canonical fixture byte files. Do not
replace adversarial raw bytes with serde map construction. A test that cannot
represent a duplicate key is not a duplicate-key test. A test that fails only the
outer hash does not exercise an inner schema/consistency rejection: repair and
re-sign the enclosing claims for those negative cases.

At minimum the evidence must distinguish:

- A pinned signature succeeds at the manifest stage, while an unpinned snapshot
  admin, changed role/approval/request/session or expired manifest fails.
- Exact raw component spans/whole payload are bound, including whitespace;
  ciphertext/version/order changes, missing declared facts and mismatched heads
  fail the appropriate integrity/structure stage.
- Empty tombstone declaration uses explicit `[]` and its derived digest; nonempty
  synthetic deletion candidates retain original fact hashes even with no secret
  versions. No fallback digest exists. `secret_deleted` fixture signing is
  test-only and never presented as pre-M1 admission support.
- Huge sequence/HLC integers remain exact; original embedded finite floats retain
  canonical bytes. Real objects with serde private keys remain objects.
- Original inner signature failures, false final-overlay claims or unproven roles
  can never become semantic success or install authority. Explicitly test the
  documented limited candidate behavior for coherently re-attested bad inner
  signatures; do not call such a result `VerifiedCheckpoint`.
- Allocation/count/depth refusal is early, including deep input on a 256 KiB
  stack and unchecked absurd sizes in tiny input. Test drop/error paths too.
- Candidate output is immutable, bound to one attestation, not deserializable
  into authority, and redacted from incidental debug/error output. Check absence
  of production runtime callers and state/authority imports by source inspection.

Run all unchanged prototype/canonical compatibility tests in the full matrix.
Record old-fixture Git blobs before/after; do not regenerate or edit them. Add new
fixtures only in `team_checkpoint_v1`. Keep deterministic generator commands and
literal canonical/signature/hash expectations with their source/model provenance;
do not calculate every expected result through the new verifier under test.

## 7. Isolation and verification commands

All product/dependency/fixture/build/test execution occurs in the assigned
synthetic-only isolated worker, never on the coordinator host or a machine holding
gateway/vault/signer/coordinator administration/model credentials. Use its own
checkout and target/cache; do not touch the independent M1 worker or its native
Mac runner. No production vault/key inspection, deployment endpoint or host
runtime configuration changes. Do not spawn another agent.

Record exact source SHA/tree, patch, Rust/Cargo versions, OS, actual model/settings,
commands, exit codes and logs in worker evidence. Do not print environment dumps
or credentials. Example commands **for the isolated worker only**, from its
repository root (these were not executed by the design session):

```sh
git rev-parse HEAD HEAD:rust
git status --short
rustc --version
cargo --version
cargo test --locked --manifest-path rust/Cargo.toml --lib team::checkpoint
cargo test --locked --manifest-path rust/Cargo.toml --test team_checkpoint_manifest
cargo test --locked --manifest-path rust/Cargo.toml --test team_checkpoint_payload
cargo test --locked --manifest-path rust/Cargo.toml --test team_checkpoint_provenance
bash rust/verify.sh
git diff --check
```

The focused runs help develop meaningful boundaries; the unchanged full Linux
`rust/verify.sh` remains required, including formatting, strict Clippy, library/
binary tests, every integration target, ignored signer resource probes and doc
tests. Once passing, repeat only for a changed/failing or unresolved concern.
Keep logs and bind the final result to the actual committed code head. A commit
of bounded worker code is permitted; no push or PR is authorized here.

**Native macOS is NOT RUN for this component unless separately scheduled after
the exclusive M1 runner is released.** Do not use it, claim coverage from old
native tests, or wait for it to return bounded code. Code can be delivered with
that explicit limitation, but macOS full verification is still a required product
gate, as are full M2 integration and actual Opus final-head review.

Preserve the known bd065fc Linux full-matrix grant-expiry failure (1630 passes,
one failure as reported in the brief) and the fact that ten diagnostic passes did
not establish its cause. If it recurs, report the exact result as failed; do not
skip, weaken, rewrite or broaden this task to hide it. Prior native 1634 PASS,
the 66+7 synthetic Linux E2E report, and link validation do not validate this new
head or close M1/M2/native/IPv6/OCI-capacity/release gaps. Mac-only MLP scope does
not exempt Linux CI.

## 8. Completion report and unresolved gates

Return bounded code plus:

- Actual worker model/settings, base/head SHA and Rust tree; supplied design SHA
  and actual prompt hash; source/input differences if any.
- Changed files and a short account of the parser, signature, raw-integrity and
  non-authorizing output contracts implemented.
- Exact focused/full Linux commands, exits, per-target failures and source-bound
  logs; native macOS **NOT RUN** unless separately authorized and actually run.
- New fixture paths/hashes and proof that old prototype fixtures/canonical helpers,
  harness/CI, M1 runtime paths and trust requirements were unchanged.
- Explicit still-open planning gates **M2-G01 through M2-G10** from decision.md:
  actual M1, all retained signatures/authority/facts/removals, compaction/head
  evidence, required generations, approved session/raw-frame/budgets and later
  renewal/receipt-query binding, finalize, coherent durable epoch import,
  committed provenance/ACK, and full acceptance.
- All actual original review IDs supplied with any later fix assignment and their
  unchanged severity/evidence. This task supplies no actual M2a Opus findings;
  do not invent IDs, mark unavailable review PASS, or close unrelated findings.

Do not merge, deploy, alter repository permissions, change coordinator runtime,
push, create a PR or claim release readiness. Do not invoke/retry Opus: the actual
prior attempt was quota-blocked before reading source, and this is the separate
project-prescribed Astra design, not its replacement. The controller separately
collects an implementation diff and manages any authorized publication/review
against its exact head. There is no always-on coordinator-service claim.

If the raw parser cannot satisfy the locked dependency's private-number handling,
small-stack safety, or unchanged legacy canonical contract within these files,
return the precise blocker and remaining tests. If M1 integration or a wider
schema decision is needed, stop at the pure bounded boundary; do not provide a
permissive adapter to manufacture completion. A delivered implementation is still
not supported snapshot onboarding, full M2 acceptance or an Opus review.
