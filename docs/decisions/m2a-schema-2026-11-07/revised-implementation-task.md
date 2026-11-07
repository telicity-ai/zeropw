# Revised Sol task: feature-neutral M2a parser and bounded integrity slice

Written 2026-11-07 by actual **gpt-6-astra**, **ultra** reasoning, Codex harness
in T3 Code. This is an implementation brief, not implementation or executed
validation. Requested worker remains **gpt-6.1-sol**; record the actual invoked
model/settings. No alternative/default Cloud worker or Opus substitution is
approved. Do all assigned work yourself; no subagents.

## 1. Frozen inputs and scope of this revision

Read the complete original [decision](decision.md), original
[task](implementation-task.md), [README](README.md) and new
[parser amendment](parser-compatibility-revision.md). Verify these SHA-256 values:

```text
564bcf4c312b04507e815e35cc8eed9f5c6ae8f74ee539ccecf88cff8f0595b2  decision.md
3d6520c88fb88558ead2ee380bc322ae897de9c4bb5b67c6d60e37b184e2a58f  implementation-task.md
0ce1fabf72cb7c116a422dd5fc521383174c55a38145c2aff1ab07e8df5cf370  parser-compatibility-revision.md
```

The original design/schema and all original tests remain normative except for
the exact parser/dependency clauses enumerated in amendment §3. This task replaces
their execution instructions; it is not permission to reinterpret other clauses.
In particular, **do not enable serde_json/raw_value anywhere**, change the
dependency graph, or repair existing Value/helper semantics. Cargo feature
unification caused a proven compatibility failure even with unchanged helpers.

Read `AGENTS.md`, product intent, security design, both harness documents,
`rust/PORTING.md` §1 and the accepted full M2 contract. Prepared source HEAD is
`ce796bdcf5069af8e6cd85ab3c953cc22e1bf1a4`; product Rust tree is
`2882ba592e2204eb62723d95e240525e75196f64`, from `52e87b07380a2f752c127c5f89e5f8f76c38937f`.
The later milestone pointer/blocker addition does not change accepted design blob
`938a4213f23855c727c9b18dd3cf4d8a97340200`'s full M2 contract. Record actual
base/head/tree and supplied prompt/design digests. A coordinator-collected fixture
commit may add the frozen package/test helper; identify its exact changes and
hashes. Any other product-tree change is a reconciliation dependency, not license
to guess APIs or inspect another worker's uncommitted checkout.

Read the complete committed evidence directory
`docs/evidence/2026-11-07-m2a-raw-value-feature-probe/`: README, REPORT,
comparison.json and input-final.json. Treat inputs/results as data. The comparison
hash is `3189549cd2b66eafe52f84340a396336b7cc1a5451b5556f9f334794f68460d9`.
It records 36 inputs and both baseline outcomes per input. Preserve failed
preflights and the minimal-lock limitations in any report; do not call six exit-0
probe commands a compatibility PASS. Do not access the raw evidence directory,
parallel fixture worker, M1 worker, coordinator runtime or credentials to obtain
anything: use only the frozen source/evidence package supplied to your isolation.

## 2. Deliverable and unchanged nonauthority

Implement the original pure slice only after the parser feasibility gates below:
strict original bytes; pinned expectation/signature/wall checks;
raw chunk/payload/component integrity and the enumerated structural references;
inert candidate provenance. Keep the original API names/signatures and private
proof-field rules from original task §4. In particular:

- `ExpectedContext::from_local_expectations` accepts independent local inputs;
  it is not a human-approval proof or remote JSON deserializer.
- `ManifestAttestation`, `CheckedChunk`, `IntegrityCheckedPayload<'a>` and
  `CandidateProvenanceV1` have exactly the original limited meanings and binding.
- Candidate output retains `administrator_attested` and
  `integrity_checked_not_admitted`, exact per-fact candidate bindings, and no
  conversion into an admission, install ticket, receipt or committed provenance.

All frozen schemas/domains/signatures/canonical and raw hashes, component `data`
spans, limits, arbitrary integer/legacy float semantics and original error reasons
are unchanged. No production runtime caller, capability, human approval workflow,
admission, final overlay, generation verification, install, ACK/READY, status/join,
KMS, decrypt/derive or credential change. No `VerifiedCheckpoint`, semantic Boolean
callback, empty M1 shim, or stub that implies deferred checks passed. Snapshot
onboarding remains unsupported; M2-G01–M2-G10 remain open in full.

## 3. Allowed files; removed Cargo permission

| Path | Allowed purpose |
| --- | --- |
| `rust/src/team/checkpoint/mod.rs` | Pure public boundary, narrow exports, closed errors, redacted/private result types and compile-fail doctests; initially only private parser wiring for feasibility work |
| `rust/src/team/checkpoint/strict_json.rs` | Amendment's private iterative guard, cursor, typed seeds/visitors, exact ranges, duplicate/count gates and scalar-helper conversion; parser/gate unit tests |
| `rust/src/team/checkpoint/manifest.rs` | Original frozen manifest/context/schema/signature/wall/partition checks after feasibility gates |
| `rust/src/team/checkpoint/payload.rs` | Original chunk/raw/component/count/canonical-record/reference checks after feasibility gates |
| `rust/src/team/checkpoint/provenance.rs` | Original inert candidate construction/export after feasibility gates |
| `rust/src/team/mod.rs` | Only the minimum `pub mod checkpoint;` declaration |
| `rust/tests/team_checkpoint_legacy_parser_regression.rs` | New test-only 36-input regression for unchanged old pyjson and direct Value paths |
| `rust/tests/team_checkpoint_manifest.rs` | Original manifest/binding/signature/limit tests |
| `rust/tests/team_checkpoint_payload.rs` | Original payload/chunk/span/count/reference/number tests and amendment-specific integration cases |
| `rust/tests/team_checkpoint_provenance.rs` | Original output/binding/redaction/stage tests |
| `rust/tests/common/team_checkpoint.rs` | Test-only fixture support; preserve any coordinator-supplied frozen baseline helper and report conflicts before changing it |
| `rust/tests/fixtures/team_checkpoint_v1/` | Original §10 package and additional raw negative/golden parser cases; collected baseline bytes remain unchanged |

`rust/Cargo.toml` and `rust/Cargo.lock` are **not writable task paths**. No normal,
dev, build, platform or feature change; no dependency alias, patch/fork, new parser,
serde_stacker or package/version update. The old task's raw_value row is revoked.

Keep every old canonical/numeric/base64/crypto/Commit/Fact helper, canonical guard
and allowlist, existing fixtures/GENERATE files, harness, CI, verifier script,
governing/archive documents and runtime modules byte-identical. Specifically no
edits to `pyjson.rs`, `pyint.rs`, `sync.rs`, `fold.rs`, `transport.rs`, membership,
pairing, identity, envelope, status or credential paths. A genuinely unavoidable
wider dependency is an unresolved blocker, not permission to work around a test.

The unchanged `rust/verify.sh` automatically discovers the new integration target.
Keep private parser tests private; do not expose an unchecked parser/proof
constructor just to make integration tests convenient. Read the committed corpus
as test data (for example compile-time inclusion from its existing docs path),
without modifying it or adding a runtime dependency on evidence files.

## 4. Stop/go gate before broader implementation

First implement only the minimal private parser route, its tests, old-path
regression target and module wiring. Do not implement the remaining attestation/
payload/provenance product surface until PC-R1–R4 succeed in isolation. This
sequencing is an engineering gate, not a requirement to seek another permission
after it passes. No semantic stub is necessary to compile the private module.

### PC-R1: public APIs and the unchanged product dependency graph

Use the exact product lock, not a regenerated minimal lock. Verify registry
archive/source identity for serde_json 1.0.151 against lock checksum
`c841b55ecdae098c80dcae9cf767f6f8a0c2cdb3416bbef72181df4d0fe73f14` and record the
actual serde/serde_core 1.0.229 sources. Retain existing features
`arbitrary_precision,preserve_order,unbounded_depth` and existing defaults.
Record the product's actual resolved feature graph, including test/build edges
and relevant target resolution, before and after. No `raw_value` may appear.
If the supplied graph already enables it unexpectedly, stop and report the
introducing edge; changing feature declarations is outside scope.

Compile the amendment §5 protocol using public `DeserializeSeed`, typed
`deserialize_map`/`deserialize_seq`, separate key/value seeds and scalar-only
`IgnoredAny`. No private API or name/layout test. Pass exclusive mutable cursor
state through seeds; no unsafe, global/thread-local state or reader-lookahead
offset inference. Keep each offset/range checked and tied to its immutable source.

### PC-R2: two deliberately separate parser oracles

Run all **36** `comparison.json` rows through unchanged `pyjson::loads` and direct
`serde_json::Value` parsing with baseline features. Compare each path to that
row's **baseline**, not `raw_value`, including success/error, Value kind, stored
serialized/debug/canonical fields and error category/line/column/message where
recorded. Decode the corpus's `input` string back to its original JSON text; do
not feed a reserialization of the represented object. No omission of the 24
unchanged rows or of legacy errors/private-Number behavior. Test-only direct
Value use here is solely an old-path regression, not the new parser mechanism.

Separately exercise all 36 inputs in the new private parser with explicit
object-preserving expectations. The reserved Number/RawValue names have no magic
meaning there: singleton, multi-entry, both first-key orders, escaped and nested
objects stay objects, including string values `not-json`, `null` or JSON-looking
text, and non-string values. Real huge numeric tokens remain exact numbers.
Use literal expected canonical bytes/manual structural expectations, independent
of the new parser; do not use old whole-object `pyjson::loads` as that oracle.
Preserve these objects inside a Commit op, Fact target and snapshot legacy field;
check existing canonical/hash equality from explicit materialization.

### PC-R3: cursor, grammar, spans, duplicates and limits

Implement/test all amendment §5 invariants. Minimum adversarial cases:

- Exact component spans with whitespace before/after `data` and inside it,
  empty containers, nesting, backslash runs, escaped quotes, literal UTF-8,
  escaped non-BMP characters and brace/bracket-looking strings. Golden offsets
  and raw bytes must be literal expectations, not recomputed by the cursor under
  test. Mutating interior versus exterior whitespace changes exactly the frozen
  component/whole-payload hash scopes; re-attest as needed to reach the parser.
- Key/value Some/None synchronization, object/array first and subsequent entries,
  missing/extra comma/colon, trailing commas, missing/mismatched closes, scalar
  adjacency (`1true`, `1 2`, `"a""b"`), bad numbers (`01`, `+1`, `1.`, `1e`,
  `--1`), truncations, comments, BOM, non-JSON whitespace and trailing values.
  Successful preflight or `IgnoredAny` alone must never constitute acceptance.
- Invalid UTF-8; bad/truncated escapes; lone high/low surrogates; valid pairs;
  decoded-equivalent `x`/`\u0078` and literal/escaped non-BMP keys. Distinct
  composed/decomposed Unicode keys remain distinct; no normalization.
- Duplicate keys at root, nested legacy values, targets and both reserved names,
  regardless of ordering. The second value can be a large valid string/container,
  invalid scalar or deeply nested structure. A test-only child-decoder hook must
  prove no value seed/materialization was invoked for the duplicate. The global
  framing scan may have read bytes and may reject depth first; error precedence
  for multiply-invalid input remains unspecified.
- Count-first traversal before Values: actual 256/257 devices and chunk
  descriptors; 65,536/65,537 combined records; no reserve from size hints or tiny
  input declaring absurd lengths. Use private counter tests where real records
  cannot fit. Test cross-component counter accumulation and fields reordered,
  especially `data` before `name`, so counts cannot depend on encounter order.
- UInt rejection of bool/string/decimal/exponent/negative/`-0`; exact
  `9007199254740993` and `1844674407370955161600000000000000000001` sequences/HLC;
  signed huge integers and finite legacy `1.0`, `-0.0`, `1e-7`, exponents;
  overflowing float refusal. Compare literal canonical bytes, not f64 equality.
- Deterministic grammar/mutation coverage against existing grammar acceptance
  for ordinary nonduplicate, nonmagic-key inputs, plus independently expected
  strict-only cases. Do not treat known legacy coercions or duplicate collapse
  as the new parser oracle. Cover error paths as well as valid trees.

### PC-R4: stack, allocation and work

Use the original D(64)/D(65) definition and a legacy child at total wrapper depth
64/65. On a **256 KiB test thread stack**, cover alternating arrays/objects,
escaped keys, deepest scalar conversion, successful validation/materialization,
canonical writing/hash/equality after traversal returns, duplicate and malformed
errors near the depth limit, and dropping partial/completed Values. Run in debug
and release. Refuse very deep input at preflight before a container callback.
Do not reduce depth 64 or mask an abort with a larger production thread/process.

Use heap-backed large state and small visitor frames; do not invoke canonical
writers under the full recursive parser stack. Record maximum exercised bytes,
counts, long numeric-token work and heap overhead for wide inputs. Prove counts
precede record construction and the design does not retain full payload clones,
a whole-payload token tree, or repeatedly rescan every ancestor per descendant.
Raw framing, typed traversal and scalar parsing should be a bounded number of
passes; BigInt/canonical work retains the existing algorithms and requires honest
measurement. Do not assert a new memory/latency capacity from the byte cap alone.

If a gate fails, preserve exact commands/exits, failure bytes, source/patch,
dependency graph and logs. Fix only within allowed new files and rerun the
affected gates. If public APIs, existing helpers or stack constraints require
wider change, stop with that precise unresolved dependency. No fallback parser,
feature, legacy semantic change, guard edit or additional limit is approved.

## 5. Complete the original bounded slice after the gates

Implement original task §5 items 2–6 without behavioral changes. In particular:

1. Manifest bytes cap and strict schema; independent pinned/full peer-record
   equality, exact approval/request/session binding, freshness, canonical
   signature excluding only top-level `sig`, and hash including it.
2. Original chunk schema/strict canonical base64 checks; payload length, whole
   SHA and deterministic raw chunk SHA checks before payload decoding; six exact
   component `data` spans, counts and structural references only.
3. Original canonical Commit/Fact representations and hashes, exact head/vector/
   HLC comparisons, declared full fact and tombstone hash sets, removal references
   and original wrap selectors. Do not call original fact/commit admission
   verifiers as a substitute for deferred authority replay.
4. Original candidate representation, identity pairing and no authority conversion.
   Invalid inner signatures, unproven roles, malformed M1 targets and false
   final-overlay claims cannot become semantic success. Device-record
   self-signatures still require the existing check.

Run **every** original decision §10 test family plus PC-R1–R4. Preserve its exact
section 10 deterministic fixture contract and literal canonical/hash/signature
files, including nonempty deletion and no-version tombstone candidates and their
explicitly unverified overlay claims. Do not produce an M1 success fixture.

The parallel Sol task only builds the already-frozen baseline using existing
baseline helpers. Consume its **committed, coordinator-supplied** fixture package
and generator/helper hashes when available. Do not inspect its uncommitted tree,
regenerate conflicting golden values with the new parser, or repurpose that task
to implement this parser. Compare baseline files byte-for-byte to the collected
package. Add negative/raw cases separately. If a helper, file collision or literal
expected value conflicts, report the exact bytes/contracts for coordinator
resolution instead of changing the baseline or archive. Parser feasibility work
does not depend on that worker's availability.

Original prototype fixtures and helper/guard blobs must be unchanged before/after.
Check error and Debug redaction with synthetic markers; no raw Serde errors escape.
Inspect the source for production runtime callers and forbidden authority imports.
No peer-controlled filename/path is used; no network or filesystem runtime code
belongs in the slice.

## 6. Isolated commands and evidence

All compilation, fixture generation, dependency/product execution and tests run
only in the assigned synthetic-only isolated Linux worker, with its owned
checkout/cache/target/temp paths and no gateway/vault/signer/coordinator authority.
No submitted-code execution on the coordinator host. No credentials/environment
dumps, production access, native Mac, runtime changes, push, PR, merge, deploy or
permission changes. Do not invoke or retry Opus. These commands are instructions
for that worker, **NOT RUN by this design session**, from repository root:

```sh
git rev-parse HEAD HEAD:rust
git status --short
rustc --version
cargo --version
shasum -a 256 rust/Cargo.toml rust/Cargo.lock rust/src/pyjson.rs rust/src/pyint.rs
cargo tree --locked --offline --manifest-path rust/Cargo.toml -e features -i serde_json
cargo tree --locked --offline --manifest-path rust/Cargo.toml --target all -e features -i serde_json
cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_legacy_parser_regression
cargo test --locked --offline --manifest-path rust/Cargo.toml --lib team::checkpoint::strict_json
cargo test --locked --offline --release --manifest-path rust/Cargo.toml --lib team::checkpoint::strict_json
```

The full-lock dependency graph is distinct from the historical minimal probe;
record any cache/preflight failures honestly. Do not regenerate the lock to make
`--locked` work. If source availability prevents offline validation, report the
missing package/environment dependency; provisioning does not authorize wider
source or runtime changes. Use the exact locked registry sources for the gate.

Once gates pass and the original slice is complete:

```sh
cargo test --locked --manifest-path rust/Cargo.toml --test canonical_helpers
cargo test --locked --manifest-path rust/Cargo.toml --lib team::checkpoint
cargo test --locked --manifest-path rust/Cargo.toml --test team_checkpoint_manifest
cargo test --locked --manifest-path rust/Cargo.toml --test team_checkpoint_payload
cargo test --locked --manifest-path rust/Cargo.toml --test team_checkpoint_provenance
bash rust/verify.sh
git diff --check
git diff --name-only
```

Run the unchanged full Linux matrix: formatting, strict Clippy, lib/bins, every
integration target, ignored signer probes and doc tests. Preserve per-target
failures and bind logs to the actual implementation head/tree and patch. Do not
skip the known grant-expiry failure if it recurs; earlier diagnostic passes did
not establish its cause. Broaden/repeat checks only for changed code, a failure
or an unresolved concern. A bounded local commit in the worker is allowed by the
original implementation brief; publication remains the coordinator's job.

**macOS verification is NOT RUN** in this assignment; M1 owns that runner. Do not
poll, use it or claim coverage from old native results. Full isolated macOS
verification remains mandatory before product acceptance. The historical E2E
record is 66 assertions plus one scan covering seven synthetic service secrets;
it supplies no acceptance evidence for this code.

## 7. Completion or blocker report

Return changed files, actual model/settings, base/head/Rust tree, task/design/
fixture/corpus hashes and all PC-R1–R5 states with commands, exits and source-bound
logs. Explain the cursor/span proof, duplicate/count timing, object/number
behavior, stack/heap measurements and each unexecuted obligation. Report both
36-input old-path comparison results and the distinct new-parser expectations.
Show unchanged Cargo/helper/guard/old-fixture/CI/harness/archive bindings and the
collected baseline fixture bindings; no graph change can be hidden by source-only
helper equality. Keep partial work/failed preflights reviewable if blocked.

Explicitly list M2-G01–M2-G10 as open, preserving original decision §11 in full:
actual M1, retained signatures/authority/facts/removals and final fold, compaction
proof/continuation, generations, real approved sessions/raw transport/budgets,
fresh finalize, coherent durable import epoch, committed provenance/ACK and full
platform/native/review acceptance. No actual M2a Opus IDs are supplied by this
task. If a later fix brief supplies real findings, preserve their original IDs,
severity and evidence; do not relabel these design gates as Opus findings.

Do not claim the parser gates were run by Astra, compatibility is proven from
static reading, a candidate is admitted, snapshot onboarding is supported, or
full M2/release acceptance has occurred. A passed implementation test matrix is
still not the required actual Opus review of its final head.
