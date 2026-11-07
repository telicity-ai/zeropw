# M2a parser collection static audit — 2026-11-07

Actual auditor: gpt-6.1-sol, inherited ultra reasoning effort, local Codex coordinator sub-agent. Exact audited worker commit: `7bcecfda8571ae40047fae406915f73d2e25bde0`, Rust tree `24fceecbec4b559aa8d1e31331ef5be0033ca2fa`, prepared implementation base `21ed45c9ea1814b40d91b7d994fb075152852571`. Source was read through Git-pinned blobs in `/Users/ys/.t3/worktrees/zeropw/t3-fd2a1b1c`; the checked-out HEAD matched that commit and its status was clean when initially inspected.

**No concrete blocking parser mismatch or security bug was found within the explicitly read scope.** This is a bounded static collection audit, not an Opus adversarial review, executed parser gate, platform acceptance, semantic M2 verification, or release approval. No product/helper/dependency/formatter/build/test/model code was executed or imported, and no VM, native Mac, credentials, runtime state or other task was accessed/polled. Only trusted Git/read/hash/Python-standard-library data inspection was used. This report is the only written artifact; no checkout/ref/source changes were made and no subagent was invoked.

## Exact read scope

Full reads in this audit:

- `rust/src/team/checkpoint/strict_json.rs`, all 1,624 lines, including all production code and 12 parser test functions.
- `rust/tests/team_checkpoint_legacy_parser_regression.rs`, all 53 lines.
- `rust/tests/team_checkpoint_manifest.rs`, all 275 lines.
- `rust/tests/team_checkpoint_payload.rs`, all 808 lines.
- `rust/src/team/checkpoint/mod.rs`, all 106 lines.
- Astra `docs/decisions/m2a-schema-2026-11-07/parser-compatibility-revision.md`, all 408 lines, and `revised-implementation-task.md`, all 335 lines.

Targeted additional reads: original `decision.md` lines 532–673 (unchanged parsing obligations, verification order, resource bounds and closed errors); `rust/src/team/checkpoint/payload.rs` lines 1–305 (chunk boundary, raw prerequisites, component spans and first commit structural path); the complete Git diff of `rust/src/team/mod.rs`; worker `REPORT.md` source/gate/commands/resource/failure/limitations sections and final summary as attributed data. The 36-row committed comparison corpus was decoded with Python stdlib only to verify its count and source hash; this audit did not independently replay its baseline outcomes.

Byte/hash comparisons, not full semantic rereads: Cargo manifest/lock, old pyjson/pyint/canonical guard/verify script, frozen helper/fixture Git identities and pre-existing path inventories. All explicitly read source hashes appear below.

Omissions: no full review of `manifest.rs`, `provenance.rs`, `payload.rs` after line 305, or `team_checkpoint_provenance.rs`; no dependency-source/API implementation audit; no full reread of old pyjson/pyint, crypto/canonical/Commit/Fact helpers or frozen fixture generator; no line-by-line final raw test-log audit, VM before/after source manifests, heap instrumentation or feature-graph command replay. Full assurance for the entire new module must not be inferred from this parser-focused result.

## Static checks against the amendment

| Requirement | Evidence and assessment in the read scope |
| --- | --- |
| Feature/helper neutrality | Source Git comparisons to the prepared base show Cargo.toml, Cargo.lock, pyjson.rs, pyint.rs, canonical_helpers.rs and rust/verify.sh byte-identical. The entire frozen helper/package is unchanged since supplied fixture parent `e781a21074f64bf610a34f01035f613df9e19f76`. New `strict_json` imports only public Serde seed/visitor APIs plus existing scalar helpers; it adds no feature or parser dependency. Feature-graph execution remains worker-attributed. |
| Original lexical kind and scalar semantics | `strict_json.rs:370–413` frames only original scalar text and requires the scalar helper's resulting kind to match that first byte. `:338–344` and `:602–617` apply the frozen UInt text predicate before exact PyInt conversion; strings/bools/decimal/exponent/negative/-0 cannot become UInt by normalization. `IgnoredAny` is used at `:619` only after scalar framing and scalar-helper success; object/array branches use typed dispatch at `:628–650`, never whole-container Value deserialization. |
| Cursor/Serde synchronization | Keys are separately scalar-decoded and compared with Serde's String result before advancing (`:539–554`). Object/array visitors require exact punctuation, key/element Some/None agreement and closing tokens (`:660–750`). EndSeed refuses any unexpected callback. Root success requires Deserializer::end, exhausted original cursor and empty frames (`:790–799`). No offset getter, resynchronization, private Number/RawValue layout, unsafe aliasing or process-global cursor is used. |
| Duplicate before value | `map_child` inserts the decoded key into the per-object BTreeSet and returns Duplicate at `:690–696`, before colon-side child dispatch and next_value_seed at `:681–684`. Neither a Value nor an IgnoredAny path consumes the duplicate's value. Current tests include escaped-equivalent/non-BMP and reserved-name duplicates, invalid/large/deep second values, and a private before-value hook that would panic on a second value seed (`:1088–1121`, `:1327–1343`). |
| Original spans and depth ownership | `Span` privately retains immutable source borrow, checked traversal range and ancestor depth (`:25–39`). `finish` publishes a span only after a successful typed child/container traversal (`:463–524`); component start excludes colon-side exterior whitespace. Re-materialization takes the original private Span and runs preflight with its recorded ancestors (`:754–758`, `:1591–1595`), so it cannot reset total depth. Exported ComponentSpan borrows these same bytes (`payload.rs:38–51`). |
| Pre-recursion depth and caps | `preflight` checks cap and UTF-8 before State/tree creation, scans with fixed [u8;64] framing state and rejects a new container at total depth 65 before pushing (`:289–335`). Public manifest/frame/payload limits are 65,536/131,072/16,777,216 original bytes (`:1539–1562`). Public payload length/whole/chunk raw SHA prerequisites precede the strict JSON call (`payload.rs:117–146`). |
| Count-first traversal | Per-role counters execute at `start` before framing/decoding the child (`:425–434`); Device 256, Chunk 256 and combined CommitEntry/FactEntry/Version 65,536 counters are checked at `:212–243`. Array quotas for heads/descriptors/components/pending/self-placed and Vector's 256-member bound are also checked before their next child (`:705–708`, `:730–748`). Component index fixes schema role even when data precedes name (`:154–168`, `:180–197`). Legacy fields named versions elsewhere are Role::Any and do not change record counts. |
| Metadata projection and early shape refusal | Role/container tables and schema field closure are explicit (`:92–197`, `:1428–1526`); the Seed rejects a wrong required container or a container/non-string for Text before entering its children (`:574–586`). `payload` validates/counts the complete original bytes first, drops that pass, then builds only projected metadata and selective spans (`:1556–1588`). `start.collect` suppresses individual commit/fact/wrap entries, secret data, version-ID lists and opaque document fields from the metadata Value (`:443–457`). The new metadata test at `:1602–1621` asserts container refusal before any scalar or nested child decoder. This covers the specific projection failure described by the worker. |
| Bounded lifetime/work and errors | Recursive visitor state and frames are heap-backed through Box<State>/Vec<Frame>; there is no whole-payload token tree or payload clone. Repeated passes are whole-input validation/projection plus individual original-span materialization, not per-descendant rescans of every ancestor. BTreeSet keys and bounded record spans can cost much more heap than raw bytes; the source/test/report do not claim equal-to-input memory or new production queue/process budgets. Static Error variants map to closed public errors; Serde details and decoded duplicate names are discarded (`:420–423`, `:558–566`, `:790–795`; mod.rs:49–92). Errors unwind local owned state; failed spans/proofs are not published. |

No unsound offset/lifetime path, reserved-object coercion mechanism, duplicate-after-value decode, count-after-record construction, public unchecked strict witness, production parsing thread workaround or new runtime caller was identified in these reads. A Git-pinned search for the new public verification symbols found their declarations/exports only under the new checkpoint module. The only pre-existing Rust product edit is `pub mod checkpoint;` in team/mod.rs. This observation is narrower than full acceptance of every schema/reference path in the omitted files.

## Test quality and 256 KiB obligations

The tests are meaningful boundary tests rather than merely replaying the generator:

- The separate old-path target compares every field of both baseline outcome objects for all 36 original input strings, including successful kind/debug/serialization/canonical fields and error category/location/message (`team_checkpoint_legacy_parser_regression.rs:6–53`). It does not use the raw_value outcome or reserialize the represented object as input.
- The private new-parser corpus test (`strict_json.rs:892–971`) uses independently constructed literal/manual expectations for reserved objects and real numeric tokens, then checks unchanged Commit/Fact canonical/hash reconstruction and snapshot legacy preservation. Ordinary-grammar insertion/replacement/deletion mutations are separated from strict-only duplicate/magic-key expectations (`:974–1121`).
- Span tests have literal ranges 25..28 and 24..73, raw UTF-8/escape/brace-looking content and interior-versus-exterior SHA scopes (`:1124–1159`); public tests separately re-attest changed whole/component bindings (`team_checkpoint_payload.rs:411–451`). Some/None mismatch tests drive both directions for maps and sequences (`strict_json.rs:1346–1424`).
- Actual 256/257 device/chunk syntactic arrays and 65,536/65,537 commit/fact/cross-component quotas are tested before children; minimal syntactic records/private counter tests are explicitly used where fully formed maximum records would not fit a legal payload (`:1162–1200`). Numeric tests compare literal canonical strings, with huge controls and finite legacy forms (`:1203–1224`); public header tests repair outer hashes to reach the relevant structural boundary (`team_checkpoint_payload.rs:553–603`, `:648–678`).
- Private tests request a 256 KiB thread for D64 arrays and alternating escaped-key object/array trees, validation/materialization, deepest exact scalar conversion, post-return canonical/hash/equality, duplicate/malformed near-limit errors, partial/completed drop and D65/4096 preflight refusal (`strict_json.rs:822–838`, `:1227–1271`). The public payload test independently nests legacy data to total wrapper depth64 and checks full verification/candidate serialization on a 256 KiB thread, then adds one level and expects LimitExceeded (`team_checkpoint_payload.rs:604–646`). Production code does not spawn parser threads.
- The permanent wide test exercises 16,777,216 raw bytes with 1,370,000 distinct opaque keys and long 10,000/100,000-digit numeric tokens (`strict_json.rs:1274–1319`). Its RSS includes test input construction/allocator/other process overhead. This is measured worker evidence, not a new per-transfer memory/latency guarantee.

These source tests cover the requested categories. Static inspection cannot demonstrate their execution or prove every malicious input. The worker report expressly preserves failed early gate attempts and corrected literal span/canonical-oracle mistakes; this audit did not rerun or erase them.

## Attributed execution evidence — not this audit's execution

Read worker report `/Users/ys/Code/zeropw-mlp-evidence/m2a-feature-neutral-fd2a1b1c/REPORT.md` and parsed `final-validation-summary.json` as data. Both identify the same final head/tree. The summary lists 104 steps, 1,681 passed, zero failed, four ordinary library ignores and no failed steps; it attributes final release parser exit0, release public small-stack exit0 and full Linux verifier exit0. The report says 12 final private parser tests in debug/release, one selected release public depth test, all99 integration targets, four explicitly executed signer probes and ten doc tests. The ordinary ignores are not represented as skipped final signer evidence.

Reported environment: isolated credential-free owned Lima export, Linux aarch64 kernel6.8.0-147-generic, rustc1.98.1/cargo1.98.1, full unchanged product lock, offline/j1/incremental0 and dev/test debug info0. Its actual locked registry archive/source and resolved-feature checks are attributed to the worker. This audit made no VM access, ran no Cargo/feature graph, verified no actual binary, and did not independently validate the before/after810-source-file VM manifests.

The final raw log was read only as bytes to verify SHA-256 `bc3ce91a59eea59ee1834229aed117d93ae562090e71cd5235c66b953593e638`; the summary file SHA is `373a17f1a667bf422c9f8fab12b1c58830bd64e1e9105173d9561a923dd7fda2` and the read worker report SHA is `6d2b7c53720ff365fa7a9d784b7dc12bcc717f7144f1b43c15252a254ee573f6`. These hashes preserve the evidence being attributed; they do not transform it into our own test run.

Still not established here: isolated native macOS validation, final-head actual Opus review, M1 exact-head reconciliation, full-M2 semantics/admission/import, physical two-Mac, OCI/deployment or capacity. M2-G01–M2-G10 stay open and snapshot onboarding remains unsupported. No original M2a Opus finding IDs were supplied or invented.

## Exact input hashes

SHA-256 of immutable source/report bytes read or compared in this audit:

```text
39a38110cc67c40135548c09b01e1297cb3960334539e57f36bffede40a7e2cf  rust/src/team/checkpoint/strict_json.rs
dd3296c048f5036fa5ae8f07988390b54f9067879ee31ace0522770ae8e34080  rust/tests/team_checkpoint_legacy_parser_regression.rs
f2d25f4d3596723d6af859b2aa944799cd93a919f1c1faee0cee6387a6243db5  rust/tests/team_checkpoint_manifest.rs
79585c26d99116c7f8e32fb2e62dfd5d8efd414c78bb0c0ca963f8dacadc0a89  rust/tests/team_checkpoint_payload.rs
7a7952509b47364225ee064f5fd492ae2bd5baf10e41b415e3de0a67129e5515  rust/src/team/checkpoint/mod.rs
0ce1fabf72cb7c116a422dd5fc521383174c55a38145c2aff1ab07e8df5cf370  docs/decisions/m2a-schema-2026-11-07/parser-compatibility-revision.md
27a49588eab8553bf81cef67547b6e9d581ee991dc9cd10fae2a4d92268db395  docs/decisions/m2a-schema-2026-11-07/revised-implementation-task.md
3189549cd2b66eafe52f84340a396336b7cc1a5451b5556f9f334794f68460d9  docs/evidence/2026-11-07-m2a-raw-value-feature-probe/comparison.json
4ae4261cf2bdc9e9a7099eb9a0c898282997115d17da01a7953c75bba6c9a1a6  rust/Cargo.toml
fb0dbbf2a2b25c111a419f3b2102d51d2859a1745e28afca9b8d59339340d840  rust/Cargo.lock
eb8d93c099c2ab2ac38b3dedd0f6e8fdbf0d26fb4f8fb87fa8ceeba0ce5deeef  rust/src/pyjson.rs
5562f68911c2df1ed4f8683ed9344ed8749a38b68d2399b07d973be0fde8c21a  rust/src/pyint.rs
8fd9700dc1f0ac04786bceb0883ded8fe0350e8bfc745fd16971e8cc686041f8  rust/tests/canonical_helpers.rs
6a7c3ae7608553d2c2527f804daed752ced4117d1fc80eb5d58f98dee50c24ca  rust/verify.sh
d284a641ab430ee5744c1e114fc760e15c8d62b83b29b08406f358536515615d  rust/tests/common/team_checkpoint.rs
```
