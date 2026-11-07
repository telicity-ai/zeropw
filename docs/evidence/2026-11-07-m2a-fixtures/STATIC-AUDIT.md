# M2a fixture static audit — 2026-11-07

Actual auditor: gpt-6.1-sol, inherited ultra reasoning effort, local Codex coordinator sub-agent. This is a bounded static/data audit, not Claude Opus review, a parser/test PASS, M2 semantic acceptance, or release approval.

Reviewed immutable worker commit `c38523ad7321270521745a0112dc90743beb0371` from `/Users/ys/.t3/worktrees/zeropw/t3-0d4c5eb4`. No product, helper, dependency, build, test, crypto, model, VM, or runtime code was executed. Only Git reads and independent Python standard-library byte/JSON/hash inspection were used. No checkout, fixture, credentials, native Mac, production state, or other agent was modified or invoked. This report is the sole written artifact.

## Outcome and strongest objections

No concrete incorrect current golden, schema/hash/graph/seed mismatch, production scope change, or runtime authority effect was found in this bounded audit. The package is coherent integrity-only test data under Astra’s §10 contract. That observation does not establish original cryptographic validity, semantic admissibility, M1 overlay correctness, or strict parser behavior.

The test-only validation helper has narrow coverage gaps listed below. They concern hypothetical consistently modified input to `validate`, not the immutable current package. The original generator and byte-for-byte regeneration test make the strongest counterargument: arbitrary modifications would fail the regeneration comparison, and the current literal data independently has the required full lengths, unique sets and ordering. The implementation worker must enforce the real schema/count/set requirements independently and must not use this helper or candidate golden as an admission oracle.

## Coverage and source binding

Read every line 1–1658 of `rust/tests/common/team_checkpoint.rs`; read Astra decision §§1–10, including all normative fixture requirements in §10. Decision §§11–12 were not part of this reread. Read the fixture README in full. Read all 146 fixture Git blobs as bytes, checked the complete 145-entry SHA256SUMS inventory, and structurally inspected all five complete packages, historical/numeric canonical records, expected metadata, and raw-case index. The exact 146 paths are listed below; reading/hashing a raw case is distinguished from running a strict parser on it.

Targeted existing-source excerpts were read from `rust/src/team/envelope.rs` (DEK HKDF/wrap/decrypt/AAD), `rust/src/team/identity.rs` (record/signature/fingerprint), `rust/src/team/commit.rs` (signed/unsigned canonical/hash), `rust/src/team/sync.rs` (Fact canonical/hash), and `rust/src/pyjson.rs` (compact_sorted/ensure_ascii). These files were not read in full. No claims about their whole implementation or independent review acceptance are made.

- Exact Rust tree including the new test data: `9982d235d7b464edf7a520c450f1db4c33ad86d0`.
- Base `ce796bdcf5069af8e6cd85ab3c953cc22e1bf1a4` Rust tree independently resolves to frozen product tree `2882ba592e2204eb62723d95e240525e75196f64`.
- Helper SHA-256: `d284a641ab430ee5744c1e114fc760e15c8d62b83b29b08406f358536515615d`.
- Astra decision SHA-256: `564bcf4c312b04507e815e35cc8eed9f5c6ae8f74ee539ccecf88cff8f0595b2`.
- Unchanged product Cargo.lock SHA-256: `fb0dbbf2a2b25c111a419f3b2102d51d2859a1745e28afca9b8d59339340d840`.
- The commit adds exactly 147 files: this one test helper and the 146 fixture files. No existing file, production source, lock, old fixture, CI, harness, or feature was changed by this commit.
- The README helper/decision/lock hashes match the actual immutable blobs. Its narrow task hash and claims about isolated execution are recorded provenance; the external task file and worker execution logs were not independently examined in this audit.

## Independently checked current data

Python standard-library inspection used original Git blob bytes and `json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)` for canonical comparison, without importing project code or the helper.

All five packages have matching signed/unsigned manifest canonical bytes (only top-level `sig` removed), manifest/approval/candidate/raw-payload/component SHA-256 and lengths, component raw spans and order, canonical component bytes, recomputed counts, device fingerprints derived from public signing-key bytes, retained signed-record identities, vector/head references and HLCs, and recipient wrap/source-operation binding. All five single-chunk files, frame Base64 round trips, frame manifest/transfer/index binding, chunk SHA/length and payload reconstruction match. This is byte consistency, not signature or AEAD verification.

| Package | devices/commits/facts/versions/wraps | Raw payload bytes | Manifest SHA-256 |
| --- | --- | --- | --- |
| baseline | 3/5/0/2/1 | 8502 | `c0f1ae45ebe4b3bfe033a66c946d02edf562a14b167d01c6b990e093b1b96ddb` |
| deleted-empty | 3/5/1/2/1 | 9038 | `d64f6fce32b7a2d07a84f02a0b44d050ec35d991115b8da2bd013c0fb9a80410` |
| deleted-retained | 3/5/1/2/1 | 9040 | `699a41cbee5527e8465f1ecd30657cd1d5180cc104c9e2ecd288d9bd18439412` |
| changed-final-digest | 3/5/0/2/1 | 8502 | `9c1869522eaef6ae7b793a5de21f17bbb17a50c84fe990bbaf07703283739e93` |
| invalid-inner-signature | 3/5/0/2/1 | 8502 | `ade85b0c7cad22ef2decb26975c7a4c309ddcc18797c2a221cb9db465baa2696` |

The actual unflushed document SHA is `e050a65fe9508cc5a3eb4d553416adfd64c86c9f9ce3989ebd0d0a04e80d0fde`. The changed-final-digest claim is intentionally `f` repeated 64. Deletion and invalid-signature variants preserve the unflushed snapshot and explicitly do not verify the final overlay claim.

The fixed six-record history is O:1 env.init, O:2 add admin A, A:1 add user R, O:3 V1, O:4 V2, A:2 activate V2. Original HLCs and seen vectors match §10. Payload omits only O:3 and retains O:1/O:2/O:4/A:1/A:2; positive vector/head identities are O4/A2, R0 has no head; authority set is O1/O2/A1, admission A1. Both encrypted versions and order [V1,V2] remain, with V2 active. Recipient G wrap points to A:1 operation 0 and equals that operation’s original wrap for R. Device/commit/fact hashes include the correct signed record, and fingerprint encoding matches the existing primitive. All specified synthetic seed/nonce/value/ID constants and generation/wrap construction in the helper match the unchanged §10 contract; deterministic key/AEAD derivation was not independently executed.

The deleted-empty fact targets a secret absent from the snapshot; deleted-retained targets the existing retained-secret while preserving both encrypted versions. Their fact identity arrays/digests are nonempty and internally exact; they are not represented as admitted M1 facts. Invalid-inner-signature deliberately replaces O:4 signature with zero bytes, updates its canonical identity/head and reattests outer metadata; that is the prescribed separation of outer integrity from inner validity. Candidate files retain `administrator_attested` and `integrity_checked_not_admitted` with no installation/admission conversion.

Numeric Commit/Fact canonical signed/unsigned bytes and literal hashes match the independent stdlib canonical calculation, preserving exact large integer headers and the intended legacy finite-number forms. All 40 raw-case index length/hash entries match their original case bytes. No strict parser was run on malformed, duplicate, depth, Unicode, private-name or numeric cases. Some malformed manifest/payload examples retain baseline outer attestation and therefore require fresh reattestation in future structural-path tests to reach the intended deeper rejection; this limitation is explicitly disclosed by the package.

## Test-helper coverage observations — not current bad-golden findings

These are local audit labels, not original Opus finding IDs. Static reproduction conditions below were reasoned from source and were not executed. They do not authorize accepting altered fixtures.

1. **STATIC-C01 — low, unmatched expected-record suffix is not checked.** `rust/tests/common/team_checkpoint.rs:1301` zips the actual records with `expected.retained_commits` without comparing lengths; `:1330` checks only the five processed record map entries. Narrow condition: append an extra entry to `expected.retained_commits` while preserving the first five entries and the existing expected counts; update the test-data inventory if invoking top-level validate. The suffix has no corresponding iteration and is otherwise unexamined by `validate_records`. The actual package has exactly five matching entries. The deterministic regeneration test at `:1594` would detect the modified expected file; this is a validation-only coverage gap rather than evidence of incorrect current data.

2. **STATIC-C02 — low, some required sorted/distinct collections are not independently enforced by validate_records.** `:1346–1352` checks authority list length three and membership, without uniqueness, required O1/O2/A1 identities, or order. `:1298–1329` inserts retained records into a BTreeMap without asserting input hash order; `:1360–1382` uses a set for head authors without checking their wire ordering. Narrow condition: a separately reattested synthetic package can replace the authority list by three repeats of one retained hash, or permute record/expected pairs (and the mirrored head expectations) while updating affected canonical payload/components/spans/hashes. These particular helper checks do not reject on distinctness/order alone. The committed authority/record/head collections are correct and independently checked; the fixed generator/regeneration comparison catches changed goldens. The future production verifier must enforce its own closed sets and ordered-list requirements.

3. **STATIC-C03 — low, manifest schema closure is not the helper’s contract.** `validate_package` at `:1170–1221` checks canonical bytes, outer signature and selected context equality but does not implement a closed manifest key set or independently require every manifest type/domain/version/feature constant. Narrow condition: add an otherwise unused manifest member, re-sign with the public synthetic pin and refresh dependent golden hashes/candidate/inventory. There is no extra-field rejection check in this validation path. Candidate output has its own explicit closed-key check at `:1496–1537`; the manifest must still be independently parsed by the real verifier. Current manifests match the normative schema. This observation is consistent with the README’s explicit statement that the helper is not a strict parser.

## Scope, limits and required independent work

The helper’s use of test-only DeviceKey/SecretBytes, signing, original readers and pure fold is permitted by the §10 fixture task; it is not a forbidden production M2a authority dependency. Static source inspection found no StateDir/Context/Kms/runtime onboarding, network or production credential side effect. Its owned-path filesystem generation and test assertions are test tooling. These four helper tests are exercised by the temporary isolated example documented in the README; the new common module alone does not establish that rust/verify.sh or any integration target runs them automatically.

No fresh generator/regeneration/helper/full Rust tests, cryptographic signature checks, unwrap/decrypt checks, worker-log audit, strict parser run, M1 semantic/fact overlay validation, complete M2 retained-history verification, Opus adversarial review, native macOS, physical two-Mac, OCI, capacity or deployment check was performed here. In particular the current document was not recomputed by independently executing fold; only the static pure-fold construction and literal document/hash relationships were examined. No old or future PASS is transferred to this commit. All originally open M2 gates and snapshot-onboarding limitations remain open.

## Exact fixture blobs read as bytes

Paths are relative to `rust/tests/fixtures/team_checkpoint_v1/` at the exact commit above. Structured checks were performed on the package/history/numeric metadata; malformed raw cases were retained and inspected as original bytes, not fed to a product parser.

```text
README.md
SHA256SUMS
approval.json
candidate.json
chunk-000.json
chunks/000.bin
components/commits.json
components/devices.json
components/facts.json
components/recipient_dek_wraps.json
components/removals.json
components/snapshot.json
context.json
expected.json
history/A-1.signed.canon
history/A-1.unsigned.canon
history/A-2.signed.canon
history/A-2.unsigned.canon
history/O-1.signed.canon
history/O-1.unsigned.canon
history/O-2.signed.canon
history/O-2.unsigned.canon
history/O-3-compacted.signed.canon
history/O-3-compacted.unsigned.canon
history/O-4.signed.canon
history/O-4.unsigned.canon
history/expected.json
manifest.json
manifest.signed.canon
manifest.unsigned.canon
numeric-records/commit.signed.canon
numeric-records/commit.unsigned.canon
numeric-records/expected.json
numeric-records/fact.signed.canon
numeric-records/fact.unsigned.canon
payload.json
raw-cases/control-bool.json
raw-cases/control-exponent.json
raw-cases/control-float.json
raw-cases/control-huge-count.json
raw-cases/control-negative-zero.json
raw-cases/control-negative.json
raw-cases/control-string.json
raw-cases/depth-4096.json
raw-cases/depth-64.json
raw-cases/depth-65.json
raw-cases/duplicate-deep-second.json
raw-cases/duplicate-escaped.json
raw-cases/duplicate-large-second.json
raw-cases/duplicate-nested.json
raw-cases/duplicate-pair-key.json
raw-cases/duplicate-reordered.json
raw-cases/duplicate-target.json
raw-cases/duplicate-top.json
raw-cases/exact-headers.json
raw-cases/index.json
raw-cases/invalid-utf8.bin
raw-cases/legacy-numbers.expected.canon
raw-cases/legacy-numbers.json
raw-cases/legacy-total-depth-64.json
raw-cases/legacy-total-depth-65.json
raw-cases/lone-high-surrogate.json
raw-cases/lone-low-surrogate-key.json
raw-cases/manifest-extra-field.json
raw-cases/manifest-missing-type.json
raw-cases/manifest-unknown-feature.json
raw-cases/overflow-float.json
raw-cases/payload-extra-component.json
raw-cases/payload-reordered-components.json
raw-cases/private-number-duplicate.json
raw-cases/private-number-multi.json
raw-cases/private-number-single.json
raw-cases/private-raw-duplicate.json
raw-cases/private-raw-multi.json
raw-cases/private-raw-single.json
raw-cases/string-delimiters.json
raw-cases/surrogate-pair.json
raw-cases/trailing-json.json
variants/changed-final-digest/approval.json
variants/changed-final-digest/candidate.json
variants/changed-final-digest/chunk-000.json
variants/changed-final-digest/chunks/000.bin
variants/changed-final-digest/components/commits.json
variants/changed-final-digest/components/devices.json
variants/changed-final-digest/components/facts.json
variants/changed-final-digest/components/recipient_dek_wraps.json
variants/changed-final-digest/components/removals.json
variants/changed-final-digest/components/snapshot.json
variants/changed-final-digest/context.json
variants/changed-final-digest/expected.json
variants/changed-final-digest/manifest.json
variants/changed-final-digest/manifest.signed.canon
variants/changed-final-digest/manifest.unsigned.canon
variants/changed-final-digest/payload.json
variants/deleted-empty/approval.json
variants/deleted-empty/candidate.json
variants/deleted-empty/chunk-000.json
variants/deleted-empty/chunks/000.bin
variants/deleted-empty/components/commits.json
variants/deleted-empty/components/devices.json
variants/deleted-empty/components/facts.json
variants/deleted-empty/components/recipient_dek_wraps.json
variants/deleted-empty/components/removals.json
variants/deleted-empty/components/snapshot.json
variants/deleted-empty/context.json
variants/deleted-empty/expected.json
variants/deleted-empty/manifest.json
variants/deleted-empty/manifest.signed.canon
variants/deleted-empty/manifest.unsigned.canon
variants/deleted-empty/payload.json
variants/deleted-empty/records/fact.signed.canon
variants/deleted-empty/records/fact.unsigned.canon
variants/deleted-retained/approval.json
variants/deleted-retained/candidate.json
variants/deleted-retained/chunk-000.json
variants/deleted-retained/chunks/000.bin
variants/deleted-retained/components/commits.json
variants/deleted-retained/components/devices.json
variants/deleted-retained/components/facts.json
variants/deleted-retained/components/recipient_dek_wraps.json
variants/deleted-retained/components/removals.json
variants/deleted-retained/components/snapshot.json
variants/deleted-retained/context.json
variants/deleted-retained/expected.json
variants/deleted-retained/manifest.json
variants/deleted-retained/manifest.signed.canon
variants/deleted-retained/manifest.unsigned.canon
variants/deleted-retained/payload.json
variants/deleted-retained/records/fact.signed.canon
variants/deleted-retained/records/fact.unsigned.canon
variants/invalid-inner-signature/approval.json
variants/invalid-inner-signature/candidate.json
variants/invalid-inner-signature/chunk-000.json
variants/invalid-inner-signature/chunks/000.bin
variants/invalid-inner-signature/components/commits.json
variants/invalid-inner-signature/components/devices.json
variants/invalid-inner-signature/components/facts.json
variants/invalid-inner-signature/components/recipient_dek_wraps.json
variants/invalid-inner-signature/components/removals.json
variants/invalid-inner-signature/components/snapshot.json
variants/invalid-inner-signature/context.json
variants/invalid-inner-signature/expected.json
variants/invalid-inner-signature/manifest.json
variants/invalid-inner-signature/manifest.signed.canon
variants/invalid-inner-signature/manifest.unsigned.canon
variants/invalid-inner-signature/payload.json
```
