# M2a parser compatibility revision

Date: 2026-11-07. Actual design model: **gpt-6-astra**, reasoning effort
**ultra**, through the Codex harness in T3 Code. Model/settings are those exposed
by this session; no additional model revision or sampling settings were exposed.
This is a **new Astra design amendment**, not an Opus review. No product,
dependency, fixture-generator, build or test code was executed for this amendment.

## 1. Decision and exact authority

Replace the blocked `RawValue` implementation with a **private, original-byte
cursor synchronized with typed Serde seeds/visitors**, preceded by an iterative
depth/framing guard. Keep the product Cargo manifest, lockfile, resolved features
and every existing canonical helper unchanged. Add no dependency. The cursor
supplies lexical kind and byte ranges; Serde validates container grammar; unchanged
`pyjson::loads` validates and converts individual scalar tokens; unchanged
`pyjson::dumps` supplies canonical bytes. Never deserialize an input container
through `serde_json::Value`, including after a duplicate check.

This is a concrete implementation choice with an isolated feasibility gate, **not
a claim that the new cursor/visitor implementation exists or passes**. The gate
must establish public-API compilation, cursor alignment, early refusal, canonical
compatibility and small-stack behavior before the rest of M2a is implemented.
A failed gate is a blocker, not permission to enable `raw_value`, change helpers,
reduce depth 64, or choose another library without a further decision.

Task input `/tmp/zeropw-m2a-parser-revision-astra-task.md` was read completely;
its SHA-256 is
`48571525a00dbb2fb0e6605a7e071ed723f990bfa975349f3593fdbe3645dcfc`.
Only this prepared checkout was inspected:
`/Users/ys/.t3/worktrees/zeropw/t3-85d45cbb`, initially clean, HEAD
`ce796bdcf5069af8e6cd85ab3c953cc22e1bf1a4`, Rust tree
`2882ba592e2204eb62723d95e240525e75196f64`.

The complete governing documents remain immutable audit inputs:

| Document | SHA-256 |
| --- | --- |
| [Original decision](decision.md) | `564bcf4c312b04507e815e35cc8eed9f5c6ae8f74ee539ccecf88cff8f0595b2` |
| [Original task](implementation-task.md) | `3d6520c88fb88558ead2ee380bc322ae897de9c4bb5b67c6d60e37b184e2a58f` |
| [Sibling provenance/blocker README](README.md) | `d3388aa610f592c5005bf9508763547c064c2c65a93ab7e82822b9346b622ee8` |

Read `AGENTS.md`, product intent, security design, harness design/README,
`rust/PORTING.md` section 1 and the complete accepted M2 contract. A static Git
comparison against milestone blob `938a4213f23855c727c9b18dd3cf4d8a97340200`
shows only the added M2a pointer/blocker paragraph; the full M2 contract is intact.
No parallel Sol or M1 checkout, raw worker/runtime directory, credentials,
production state or native Mac runner was inspected. No subagents, Opus invocation,
push, PR, deployment, permission or runtime changes occurred.

## 2. Proven blocker; evidence is not a product PASS

The complete committed [report](../../evidence/2026-11-07-m2a-raw-value-feature-probe/REPORT.md),
[comparison](../../evidence/2026-11-07-m2a-raw-value-feature-probe/comparison.json),
[input binding](../../evidence/2026-11-07-m2a-raw-value-feature-probe/input-final.json)
and sibling evidence README were read as data. Actual Sol's isolated Lima probe
reports 36 inputs, two feature configurations and two parse paths, with **12
changed inputs in both legacy paths and 24 unchanged inputs**. All six final
feature-graph/build/run commands exited 0; that means execution completed, not
compatibility passed. This amendment did not rerun the probe.

For example, original bytes `{"$serde_json::private::RawValue":"123"}` produce
an object under the baseline and number `123` with `raw_value`. Escaped keys,
nested objects and first-key multi-entry objects also change or fail. Restricting
the import of `RawValue` to a new module cannot prevent Cargo feature unification
from changing existing Value visitors. Merely keeping `pyjson.rs` unchanged is
therefore insufficient.

The pair used unchanged copied helpers and the same final minimal lock in both
configurations. Its `equivalent`, `syn` and `unicode-ident` versions differ from
the product lock as recorded in `input-final.json`. Preserve the initial failed
checksum preflight and rejected seed-lock preflight in the existing evidence;
neither ran the experiment. This controlled counterexample blocks the feature
choice, but is not the full product dependency matrix. No fix or alternative
parser was executed by that probe.

## 3. Precisely superseded clauses

| Original location | Superseded instruction | Replacement |
| --- | --- | --- |
| Decision §7, paragraph beginning `Decision: add only` | Add `raw_value`; use borrowed `RawValue` subvalues | No dependency/feature change; use the cursor and typed visitor protocol in §§5–7 below |
| Decision §7, `Why this choice` paragraph | Borrowed raw values supply the lexical discriminator and ranges | Cursor offsets and original first bytes supply them; private map representations never determine kind |
| Decision §7, parsing properties 1 and 3–5 | RawValue scanning/borrowing and preflight Unicode checks before that scan | Iterative framing/depth preflight; synchronized container traversal; unchanged scalar helper validates every key/string/number before acceptance. No RawValue scan exists. Duplicate and count refusal remain before value materialization |
| Decision §7, final dependency-validation paragraph | Prove the selected RawValue path | Prove this feature-neutral route at the isolated gates below; no automatic fallback |
| Original task §3, `strict_json.rs` row | Borrowed RawValue traversal | Private cursor/seeds, raw ranges, count-first traversal and explicit materialization |
| Original task §3, `rust/Cargo.toml` row and following raw_value sentence | Permission to add that feature | Remove this permission: Cargo.toml and Cargo.lock are frozen, including dev/build/target feature effects |
| Original task §5 item 1 | Borrowed RawValue strict boundary | This amendment's exact parser protocol |
| Original task §§6–8, parser-specific validation/blocker instructions | Validate the blocked parser as part of implementation | Run the preimplementation gate and added corpus/cursor tests in the revised task; preserve all original tests and failure reporting |

Decision §7's original-byte public boundary, total-depth definition, decoded-key
uniqueness, early count refusal, literal-object preservation, exact UInt rule,
stack requirement and all other externally observable requirements remain in
force. Moving Unicode checking from a separate preflight decoder into the existing
scalar helper changes mechanism/timing only: invalid UTF-8, malformed escapes and
lone surrogates still cannot produce any successful result. The preflight never
decodes a duplicate key's second value merely to check Unicode.

No wire/schema/crypto clause is superseded. Decision §§2–6 and §§8–11 remain
normative, including every field/domain, canonical/signature/hash definition,
original `data` span, arbitrary integer and finite legacy float semantics,
fixed bound, expectation binding, error reason and assurance stage. All section
10 baseline bytes/IDs/seeds/times/graph and fixture roles stay frozen. The sibling
[revised implementation task](revised-implementation-task.md) operationalizes
only this amendment; the original two files and README are not rewritten.

## 4. Old and new assurance boundaries

| Boundary | Required behavior after implementation |
| --- | --- |
| Existing `pyjson::loads` and direct Value callers | Every recorded baseline outcome stays unchanged, including the existing Number-reserved-key coercions/errors. No repair of legacy semantics is authorized |
| New M2a private parser | Literal objects with either reserved name remain objects at every nesting level, irrespective of first-key order, spelling or contents; duplicates are refused. This was already the frozen M2a contract |
| New parser's numbers/writer | Real numeric tokens use existing scalar conversion and canonical writer; no global float ban, precision loss or new number codec |
| Public M2a results | Only `ManifestAttestation`, `CheckedChunk`, `IntegrityCheckedPayload` and inert `CandidateProvenanceV1`, with original private-field and binding rules |
| Runtime | No new caller, capability, approval, admission, install, receipt, join/status or credential behavior. Snapshot onboarding remains unsupported |

In particular, the new parser must accept the valid literal object
`{"$serde_json::private::Number":"not-json"}` as an object in a legacy-data
position, while the old loader must retain its recorded error for those same
standalone bytes. These are separate boundaries, not conflicting test oracles.
Closed M2a metadata schemas may reject such keys as unknown fields; the internal
syntax/materialization tests must demonstrate object preservation directly and
inside permitted opaque legacy data.

No gate M2-G01–M2-G10 is closed, weakened or renamed. Inner commit/fact signatures,
authority/target/history/M1 semantics, final overlay, generation usability and
durable import remain outside M2a exactly as before. Device self-signature checks
remain required. No empty M1 adapter or semantic success stub is permitted.

## 5. Concrete parser mechanism

### 5.1 Public APIs and ownership

The implementation uses locked `serde_json` 1.0.151 and `serde`/`serde_core`
1.0.229. Cargo's existing `arbitrary_precision`, `preserve_order` and
`unbounded_depth`, plus existing resolved defaults, are unchanged. The new parser
does not disable Serde's recursion limit. A private entry creates
`serde_json::Deserializer::from_slice(original)` and passes it to a private
`DeserializeSeed`. It calls `end()` after successful root traversal.
[Pinned Deserializer API](https://docs.rs/serde_json/1.0.151/serde_json/struct.Deserializer.html).

State passed through seeds holds the immutable original slice, an absolute byte
cursor, total depth, schema position, counters and a small output sink. Seeds and
visitors are private and are used only with this entry's concrete slice-backed
deserializer, never an arbitrary caller's deserializer or a Value deserializer.
Ordinary exclusive mutable reborrows suffice; no unsafe aliasing, thread-local
state or process-global cursor is needed. Stateful deserialization is the public
purpose of `DeserializeSeed`.
[Pinned seed API](https://docs.rs/serde_core/1.0.229/serde_core/de/trait.DeserializeSeed.html).

Use `deserialize_map` only after the cursor sees `{`, and `deserialize_seq` only
after it sees `[`. Use separate `MapAccess::next_key_seed` and `next_value_seed`,
and `SeqAccess::next_element_seed`; never `next_entry`, which requests the value
before the caller can reject a duplicate. The key/value separation is a public
API, not a dependency on private map layouts.
[Pinned MapAccess API](https://docs.rs/serde_core/1.0.229/serde_core/de/trait.MapAccess.html).

The locked source shows typed container dispatch, seeded child visits and scalar
`deserialize_ignored_any` consumption. These are the source grounds for the
protocol below, not evidence of its implementation's safety.
[Pinned de.rs](https://docs.rs/serde_json/1.0.151/src/serde_json/de.rs.html).

### 5.2 Preflight and token framing

Before any owned input copy, reserve, tree or recursive traversal:

1. Enforce the original entry-specific byte cap. For payloads, the original
   attestation/length/whole SHA/chunk SHA prerequisites still precede JSON work.
2. Validate the entire input using `std::str::from_utf8`, without replacement.
3. Scan iteratively with a fixed-capacity stack of at most 64 delimiter kinds,
   quote state and escape state. Outside strings, an opening object/array at
   total depth 65 fails before pushing/recursing. Root container depth is 1;
   scalar/key depth is zero additional containers. Never reset at a component.
   A mismatched closing delimiter, unterminated quote/escape or incomplete
   framing can fail here. This scan allocates no decoded strings or Values.

The quote scanner only locates unescaped ASCII quotes: after backslash, skip its
next byte with checked bounds. It does not decode escapes, normalize Unicode,
parse numbers or certify JSON. All string tokens later pass unchanged through
`pyjson::loads`, which supplies the existing Unicode policy. Invalid framing may
be rejected early; successful framing alone is never successful JSON parsing.

For the traversal cursor, JSON whitespace is exactly SP/TAB/CR/LF. A string span
ends just after its unescaped closing quote. An atom span runs to whitespace,
EOF, or structural punctuation (`{}[],:` or a quote). Do not parse sign/digits,
exponents, escapes or literals in this scanner. Atom candidates have a scalar
first byte (`-`, digit, `t`, `f`, `n`); other leading bytes fail. `pyjson::loads`
of the complete scalar span, including its own end check, supplies the grammar.
Thus malformed `01`, `1e`, `truefalse`, invalid escapes, controls and non-finite
floats cannot be accepted merely because the scanner found an endpoint.

### 5.3 Exact cursor/visitor protocol

The cursor denotes the next unconsumed original byte, not a Serde byte-offset
getter. It advances monotonically. At a value seed, skip only JSON whitespace,
remember `start`, then dispatch by the original first byte:

- **Object:** consume `{` in the shadow cursor and call `deserialize_map` with
  the object visitor. Before a non-first member, consume exactly one comma in
  the cursor; before a first member, consume none. If the cursor instead sees
  `}`, require `next_key_seed` to return `None`, without invoking a key seed,
  then consume `}`. Otherwise require `Some(key)` from a key seed at a quote.
  The seed locates that exact raw string span, decodes it with scalar `pyjson`,
  consumes the Serde key using `String::deserialize`, requires equal decoded
  strings, and advances only after success. Unexpected Some/None/callbacks fail.
- Check the decoded key in a per-object set (or the already-built explicit map).
  On duplicate, return immediately **before** consuming/requesting its value,
  including before `next_value_seed`. Do not use `next_entry` or skip it with
  `IgnoredAny`. For a unique allowed key, perform schema/count checks, consume
  exactly `:` in the cursor, and call `next_value_seed` with the child seed.
  After the child succeeds, continue to the next member/end. The Serde container
  call must itself succeed, including its closing-delimiter check, before a
  completed object span is published.
- **Array:** consume `[`, call `deserialize_seq`, and synchronize commas and
  closing `]` similarly. At `]`, require `next_element_seed` to return `None`
  without calling a child seed. At an element require `Some`. A counted child
  seed checks/increments its quota before scanning/decoding/materializing that
  element. A serde lookahead is not an allocation of the element.
- **Scalar:** frame its complete original token; apply the UInt source-text test
  first where the schema requires it, then call `pyjson::loads` on only that
  token. Require a scalar result of the lexical kind. Consume the same scalar
  from the enclosing deserializer with `serde::de::IgnoredAny::deserialize` and
  advance the cursor to the framed end only after both succeed. This use of
  `IgnoredAny` is **scalar-only**; it must never skip a container or a duplicate
  value. Its returned unit carries no numeric representation. All actual scalar
  values, especially numbers and Unicode strings, come from `pyjson`.

The private visitors reject unexpected callback kinds with static errors. They
never inspect a map implementation's type name, a private key token, Number's
layout or RawValue's layout. Large numbers do not enter the custom map visitor:
the scalar branch consumes them without interpreting a synthetic map and obtains
their exact value through the old scalar helper.

After the root seed succeeds, require both `Deserializer::end()` and cursor
completion with only JSON whitespace left. No recovery/resynchronization, search
for a later matching token, partial success or ignoring extra root data is allowed.
Every rejection is mapped to the original closed checkpoint reasons; never expose
Serde's input-bearing details or the decoded duplicate name.

### 5.4 Why span association is implementable, and its proof obligation

There is no public nested-byte-offset facility on `MapAccess`, `SeqAccess` or a
generic seed deserializer. `StreamDeserializer::byte_offset` is a stream-level
successful-value offset, not a live nested cursor. Do not use it as one or use
reader lookahead/line-column positions to guess span boundaries.
[Pinned stream API](https://docs.rs/serde_json/1.0.151/serde_json/struct.StreamDeserializer.html).

The proposed association is instead by induction over a **single traversal of the
same immutable bytes**. At root both start at byte zero modulo JSON whitespace.
At each container, typed Serde dispatch must agree with the literal opening byte.
Each key is matched with the next raw string and independently decoded equality;
commas/colons and Some/None results must agree; each successful child consumes
exactly one framed value. For an atom/string, its separate scalar parse requires
the complete token, so a prefix parse cannot silently move the cursor farther.
For a container, the matched closing delimiter and successful typed call complete
the induction. Final exhaustion excludes overlooked suffixes.

This is an implementation invariant to prove in tests and review, not a guarantee
conferred by using Serde. A token tape blindly zipped to `deserialize_any` events
would not satisfy it. Any mismatch refuses; no span or proof survives an error.
The implementation must document callback entry/exit cursor positions and test
both directions of Some/None mismatch, commas, missing colons, scalar adjacency,
escapes and error unwinding. Private offsets have checked bounds and originate
only from this traversal, never peer-supplied offsets.

For component `data`, save the child's `start` after colon-side whitespace and
its successful `end` immediately after the closing container token. Hash exactly
`original[start..end]`. Leading/trailing exterior whitespace stays outside that
component; interior whitespace/escapes stay inside. Keep the immutable source and
absolute range/lifetime bound together. A later subspan materialization carries
its recorded ancestor depth; it cannot reset the total-depth limit or manufacture
a validation witness from arbitrary bytes.

## 6. Counts, materialization, numeric semantics and stack

Perform a validation/index pass before constructing large legacy trees. It
validates every child, including opaque legacy children, and retains only bounded
schema metadata, six component spans, needed record/reference spans and decoded
key sets for currently open objects. No token/node tree for the entire payload,
no untrusted `size_hint` reserve and no allocation from declared lengths alone.

Schema position is carried by seeds, not inferred from magic data keys. It must
work when object fields are reordered: for example, component array index fixes
the expected role, and `name` must eventually equal it even if `data` comes first.
Count snapshot versions only at `snapshot.document.secrets/<id>/versions/<id>`;
do not count arbitrary legacy fields named `versions`. Commits/facts/version
entries share the original 65,536 counter across all components. Refuse the
257th device and 65,537th combined record before its materialization. All other
original container/count/shape/unknown-field bounds remain in force, including
256 chunk descriptors; test count boundaries independently of payload size.
Do not add a new arbitrary cap on opaque legacy object keys or integer digits.

After validation/counts, materialize only needed individual legacy objects through
the same explicit object/array builder plus scalar helper. Snapshot data need not
become a whole Value tree just to count or hash it. Drop individual temporary
Commit/Fact/Value/canonical buffers when done; retain required summaries/ranges.
Use the existing Commit/Fact constructors, canonical equality and hashes exactly
as originally specified, with no serialize-then-Value-deserialize round trip.
Keep original wrap selectors and use bounded indexes; avoid reparsing/cloning
the entire payload per record or wrap. The old helpers may copy an individual
record internally; this is not permission to retain multiple full payload copies.

The only new numeric recognizer is the already-frozen UInt predicate `0` or
`[1-9][0-9]*` on the original bytes. After scalar parsing, use
`PyInt::from_json_integer`; preserve arbitrary precision for sequences/HLC.
Use checked conversions/arithmetic for bounded sizes, indices and wall times.
Do not substitute f64/u64 visits, `coerce_from_json`, `from_python_int`, number
display strings, inferred zero or decimal/exponent normalization. Original `-0`
must fail UInt before its scalar value can lose the source spelling. Legacy
`1.0`, `-0.0`, `1e-7`, finite exponents and signed huge integers retain existing
canonical outputs. Float overflow still fails via the helper.

Preflight is iterative. Typed container traversal has at most 64 container
levels, but **64 levels alone does not prove 256 KiB stack safety**. Put large
visitor/schema/build state on the heap, keep recursive frames small and do not
call canonical writers while the full traversal stack is live. The gate must
exercise validation, explicit materialization, existing canonical/hash helpers
after traversal, equality where used, and success/error/drop paths on a 256 KiB
stack in both debug and release. A test-only small-stack thread is permitted;
production thread-per-message parsing, process/stack changes and serde_stacker
are not. Scalar-only `pyjson::loads` cannot select its deep-document thread path.
If existing canonical helpers cannot meet this boundary, report the dependency;
their rewrite or a lower wire depth is not authorized.

Heap use is bounded by actual input, open-object decoded keys and allowed index
entries, not equal to input size. A wide 16 MiB legacy object can have substantial
allocation overhead even without a payload Value tree. Measure that overhead and
long numeric-token costs in isolation; do not describe the later staging/process
budgets as already enforced by this library. No new capacity claim is made.

## 7. Strongest objections and rejected alternatives

| Objection/alternative | Decision and remaining burden |
| --- | --- |
| Two cursors can drift | Use exact callback/punctuation/exhaustion agreement and scalar whole-token validation; no resynchronization. This is the main new correctness risk and a mandatory isolated/adversarial test gate |
| A framing guard becomes a second JSON implementation | It supplies depth, token endpoints and cursor assertions only. Serde checks container grammar, `pyjson` supplies all scalar grammar/Unicode/numbers. Never accept from framing alone or add escape/number codecs |
| `IgnoredAny` can bypass duplicates or Unicode | Allowed only after a scalar has been isolated and validated by `pyjson`; never on a container or second duplicate value |
| A preflight might decode the huge second duplicate value | Preflight scans framing bytes only. Key callback refuses before value seed; test with a deep/large second value and a never-invoked value-decoder hook |
| Generic Value parsing followed by duplicate inspection or reserialization | Rejected: duplicates and original ranges are lost and Number-reserved objects may already have changed kind |
| Identify private Number/RawValue by `type_name`, key text, unsafe layout or downcast | Rejected. Those are neither a public type discriminator nor evidence of the input token's kind |
| Separate alias of the same crate, enable feature only for dev/test/new module | Rejected: no authorized feature-graph change; this does not isolate the legacy visitor |
| Fork/upgrade serde_json, change old helpers, spawn parser subprocess/thread | Rejected; broader compatibility/authority/resource work, not this parser revision |
| New independent parser dependency | Not selected: the public seed API supports a concrete candidate without one. If this route fails, return the exact gate/evidence for a separate design; no unvalidated fallback library is preapproved |

## 8. Isolated validation gates and unresolved status

These are new engineering gates, **not Opus findings**, all **NOT RUN** here:

| Gate | Required evidence |
| --- | --- |
| PC-R1 | Full product lock/manifest and helper hashes unchanged; actual target/dev/build feature graph has no serde_json/raw_value or new package/version; minimal private route compiles using only public APIs |
| PC-R2 | All 36 committed corpus inputs reproduce both complete baseline legacy outcomes; new parser separately preserves every literal object and exact real numeric canonical bytes |
| PC-R3 | Cursor/visitor alignment, complete grammar, Unicode, original spans, reordered fields and duplicate-before-value behavior, including malformed/truncated inputs and guarded count refusal |
| PC-R4 | Total depth 64/65, very deep early refusal, 256 KiB success/error/drop and post-parse canonical paths in debug/release; measured heap/work boundaries without whole-payload clones |
| PC-R5 | Frozen section 10 fixtures and all original test families; focused tests and unchanged full isolated Linux matrix bound to actual implementation head; macOS and actual Opus evidence remain separately required |

PC-R1–R4 are a stop/go gate **before broader M2a implementation**. Passing them
would justify proceeding with this mechanism, not semantic/full-M2/release
acceptance. The revised task supplies file permissions, commands and concrete
cases. If a gate fails, preserve failed logs, exact corpus, feature graph and
source/patch; fix only within the allowed parser files or return the blocker.

The parallel Sol assignment produces only already-frozen baseline fixtures with
existing baseline helpers/features. This revision changes none of its byte
contracts. Consume its committed package only after coordinator collection and
hash verification; do not inspect its uncommitted work or ask it to validate this
parser. No fixture conflict is implied by this revision, but generated bytes were
not inspected here; any actual conflict goes back to the coordinator, not into a
quiet fixture/schema rewrite.

Both Linux/macOS product validation, native two-Mac/full-M2 work and final-head
actual Opus review remain open. Native Mac is exclusively M1's runner for this
task; no access/polling is authorized. The known Linux grant-expiry failure and
unresolved release findings are not closed by this design. No actual M2a Opus
finding IDs were supplied; none is invented or marked resolved.

## 9. Static source bindings and research limits

Read local source for scalar loading/guards/writing in `rust/src/pyjson.rs`, exact
integer conversion in `pyint.rs`, the existing Commit/Fact canonical constructors,
Cargo declarations/pins, canonical-helper guard and `rust/verify.sh`. These were
static reads, not executed validation. Public pinned API/source pages linked in
§5 were read on 2026-11-07. Some docs.rs requests for separate Serde/SeqAccess,
read.rs, Value-deserializer and IgnoredAny pages returned tool errors; no claims
are based on those failed fetches. The available pinned `de.rs` covers the chosen
container/seed/scalar-consumption calls. No remote source was run or installed.
The worker must verify actual registry bytes against the product lock; reading
docs.rs alone is not that archive verification.

| Inspected input | SHA-256 |
| --- | --- |
| Evidence README | `c1b12cbef6e58895abb3d5fdf93d9e99c52a22091b1cf7811c57d9c71040bc14` |
| Evidence REPORT.md | `c0f184d14fdbbdfced9ef31b8e5e3f7247954c7e5be122f3b3fc9dc7fe27ab66` |
| Evidence comparison.json | `3189549cd2b66eafe52f84340a396336b7cc1a5451b5556f9f334794f68460d9` |
| Evidence input-final.json | `1f336368e9c75d21aa944deb984c566ae32657ec9e90cf59ac62e9f459feee3d` |
| rust/Cargo.toml | `4ae4261cf2bdc9e9a7099eb9a0c898282997115d17da01a7953c75bba6c9a1a6` |
| rust/Cargo.lock | `fb0dbbf2a2b25c111a419f3b2102d51d2859a1745e28afca9b8d59339340d840` |
| rust/src/pyjson.rs | `eb8d93c099c2ab2ac38b3dedd0f6e8fdbf0d26fb4f8fb87fa8ceeba0ce5deeef` |
| rust/src/pyint.rs | `5562f68911c2df1ed4f8683ed9344ed8749a38b68d2399b07d973be0fde8c21a` |
| rust/tests/canonical_helpers.rs | `8fd9700dc1f0ac04786bceb0883ded8fe0350e8bfc745fd16971e8cc686041f8` |
| docs/remote-sync-next-milestones.md | `b315247a4ec158287e7aa53d2acc253f7bea9563e659736e72e404ddbc2b55f6` |

All unchanged governing-document hashes besides the milestone pointer are those
already recorded in decision §12 and were checked again in this checkout.
The README correction remains applicable: the prior E2E evidence reports 66
scenario assertions plus **one scan covering seven synthetic service secrets**,
not seven independent scans. None of that historical evidence validates this
unimplemented route. The only outputs of this design task are this amendment and
its revised implementation brief.
