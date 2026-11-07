# M2a: bounded checkpoint attestation and byte-integrity contract

Date: 2026-11-07. Actual design model: **gpt-6-astra**, reasoning effort
**ultra**, running through the Codex harness in T3 Code. These are the runtime
settings supplied to this session; no additional model version, temperature or
provider execution settings were exposed. This is the separately requested Astra
design decision. It is **not an Opus review, implementation, executed test result,
M2 acceptance or release approval**.

## 1. Decision, authority and exact inputs

Proceed with M2a as an independent, pure library slice: strict original-byte
parsing, a signature checked against caller-pinned context, raw payload/component
integrity, bounded structural consistency, and inert candidate provenance.
Do not implement a partial semantic checkpoint verifier or connect it to runtime
onboarding. Names and contracts below are the normative design for this slice;
they do not describe existing product APIs.

The accepted M2 administrator-attested trust and coherent durable import contract
in `docs/remote-sync-next-milestones.md` remains unchanged. In full M2 the joining
human explicitly approves the particular inviter key as checkpoint administrator,
and that administrator separately approves the recipient. Invitation possession,
an encrypted session, a valid signature, and roles in a supplied document do not
establish either decision. The admitted prefix remains `administrator_attested`,
never `full_history_verified`. Even a fully implemented M2 cannot discover an
unknown historical omission consistently attested by a malicious approved admin.

Inspected only this prepared worktree:
`/Users/ys/.t3/worktrees/zeropw/t3-b90cf5b0`. Initial tracked/untracked status was
clean. Its HEAD is `feca56633e5ad0ce4e0cd1d7c839877bfbb3f172`; its Rust tree is
`2882ba592e2204eb62723d95e240525e75196f64`, identical to source
`52e87b07380a2f752c127c5f89e5f8f76c38937f`. A read-only Git comparison found no Rust
path changes between those commits. The accepted milestones blob is
`938a4213f23855c727c9b18dd3cf4d8a97340200`.

The complete task was read from `/tmp/zeropw-m2a-schema-astra-task.md`, with its
requested SHA-256 verified as
`1e439b31fec70682d9866ddc284d284747dc9ab743388085effe36f9082557d4`.
The complete preparation note was read from
`/Users/ys/Code/zeropw-mlp-evidence/m2-verifier-slice-prep-20261107.md`, with its
requested SHA-256 verified as
`8bb75f7e1af65dc90d73097772b059c7cbf9ca577ebe742f236cac24894d59ca`.
It is a Sol suggestion, not an authorization or review result.

All prescribed project documents were read, including `rust/PORTING.md` section 1
and all of M2. Source comments and historical reports were treated as evidence to
inspect, not operating instructions. No other checkout, M1 uncommitted work,
native runner, credentials, production state or coordinator runtime configuration
was inspected. No product, dependency, build or test code was executed. No other
agents or model providers were invoked. Only the two new planning documents in
this directory are authorized outputs of this task.

## 2. Supported result and deliberately absent authority

| Result | What it establishes | What it does not establish |
| --- | --- | --- |
| `ManifestAttestation` | Strict v1 manifest; canonical Ed25519 signature under the explicitly supplied pinned key; equality to supplied approval/request/session expectations; signed bounds; wall-clock freshness at the supplied check time | Real human approval/persistence, live session state, admin or recipient role, current revocation, replay prevention, retained history validity |
| `CheckedChunk` | One original frame's binding, index, decoded size and hash against that attestation | Transfer ordering, queue limits, durable staging, timeout enforcement or resume state |
| `IntegrityCheckedPayload` | Exact raw length/hash and ordered chunk hashes; exact raw component lengths/hashes; strict syntax; declared counts, canonical record identities and structural cross-references below | Original commit/fact signature validity, operation/target authorization, admitted history completeness, M1 semantics, fold result, generation usability or import eligibility |
| `CandidateProvenanceV1` | An inert record tying those limited results to the supplied approval, pinned key, manifest and exact candidate fact/tombstone hash sets | A fact admission receipt, committed provenance, a checkpoint install ticket or `VerifiedCheckpoint` |

Device-record self-signatures shall be checked with the existing
`DeviceRecord` primitive; this binds public signing/agreement keys only. **Original
commit/fact signature and semantic verification is deferred together.** M2a
computes their existing canonical hashes, including the signature field, without
calling a function named or treated as full fact admission. A malicious pinned
signer can therefore attest structurally coherent bytes containing an invalid
inner signature and obtain an integrity-only candidate. Tests must demonstrate
this limit, rather than silently suggest that the candidate is usable.

No `VerifiedCheckpoint`, `VerifiedFactAdmission`, `install`, `derive`, `approve`,
`assume_valid`, semantic-validator callback returning a Boolean, or test bypass
exists in production M2a. No use of `StateDir`, `Context`, `Kms`, private
`DeviceKey`, local fact receipts, vault loading or filesystem/network handles is
needed. There are no runtime callers, CLI commands, capability advertisements,
status/join changes, ACK/READY messages or credential effects. The product must
continue to describe snapshot onboarding as unsupported.

## 3. Common wire notation and byte definitions

Every new schema object below has **exactly** the listed keys, all required.
There are no defaulted, optional, nullable or extension fields unless explicitly
specified. An unknown field, even one claiming to be optional, is refused in v1.
Arrays called sorted sets are strictly ascending, without duplicates; reject an
unsorted input rather than silently sorting it. String ordering is Rust/Python
Unicode code-point order, not locale order or normalized Unicode. Fixed hashes
and identifiers are ASCII. JSON object order and insignificant whitespace need
not be canonical on input. There is no BOM, trailing JSON or trailing non-space
data. JSON whitespace is only space, tab, CR and LF.

| Name | Exact representation |
| --- | --- |
| `H` | String of exactly 64 lowercase hexadecimal characters; SHA-256 unless a nonce is explicitly named |
| `I128` | String of exactly 32 lowercase hexadecimal characters; identifier, not an integer |
| `N256` | String of exactly 64 lowercase hexadecimal characters carrying a fresh 256-bit nonce |
| `FP` | Existing device fingerprint: 26 lowercase characters in `[a-z2-7]`; an actual record's `fingerprint()` must equal it |
| `Env` | Existing valid environment ID, `FP` + `-` + 32 lowercase hex characters; reuse `commit::valid_env_id` |
| `UInt` | JSON number whose original token matches `0` or `[1-9][0-9]*`; no minus (including `-0`), bool, string, decimal point or exponent |
| `Seq` | `UInt`, retained as `PyInt`, no u64/i128 ceiling; positive for a commit/head and nonnegative in a vector |
| `WallMs` | `UInt` in `[0, 9223372036854775807]`, Unix milliseconds; checked arithmetic, separate from HLC and monotonic time |
| `Hlc` | Exact object `{"wall_ms":Seq,"counter":Seq}`; both nonnegative, arbitrary precision |
| `Vector` | Object from `FP` to `Seq`, at most 256 entries; missing author is not evidence of a signed zero head |
| `Token` | Existing generation/version token: 16 through 64 lowercase hex characters; never shorten, regenerate or reinterpret an existing token |
| `B64(k)` | JSON string, standard padded base64, exactly k decoded bytes; use `pybase64::b64decode_strict` and require re-encoding to equal the string for these new fixed-size fields |

`C(x)` means UTF-8 bytes of
`pyjson::dumps(x, DumpOptions::compact_sorted())`, with no newline, BOM, domain
prefix or alternative serializer. `SHA(bytes)` is lowercase hexadecimal
SHA-256 via `sha2`. Do not introduce bespoke crypto, JCS, serde's writer, or a
different float renderer. `SetHash(A) = SHA(C(A))` for the already sorted unique
array of lowercase record hashes. The empty set uses exactly the bytes `[]`;
it is never inferred from an absent field.

The new integer-only rule applies to new control metadata and canonical integer
record headers, **not recursively to legacy document/operation/target contents**.
Finite legacy floats, signed integers, nulls, booleans and strings in those
contents retain the existing canonical semantics. In particular `1.0`, `-0.0`,
finite exponent values and arbitrary integers must not be rewritten as new
control integers. Existing non-finite-number rejection stays in force.

## 4. Approval and session expectations

Freeze this recipient-local approval description for hashing; it contains public
metadata only and has no signature or filesystem path:

```text
{
  "domain": "zeropw-team-bootstrap-local-approval-v1",
  "v": 1,
  "trust_model": "administrator_attested",
  "approval_id": I128,
  "env_id": Env,
  "signer": FP,
  "signer_record": DeviceRecord.to_dict(),
  "recipient": FP,
  "recipient_role": "admin" | "user",
  "invite_id": I128,
  "invitation_expires_at_ms": WallMs
}
```

`approval_sha256 = SHA(C(description))`. The approval ID is freshly generated
for that human-approved description. Altering the key, environment, recipient,
role or invitation requires a new approval. The ID and hash are binding metadata,
not bearer authority; knowing either cannot grant approval. The full description
is local candidate metadata, not a new invitation format.

`ExpectedContext` contains that complete description, the authenticated session's
peer **full** `DeviceRecord`, its environment, the local recipient fingerprint, a
`session_nonce`, and an `onboarding_nonce`. The trusted request layer will create
the 256-bit `session_nonce` once for this authenticated session and a separate
256-bit onboarding nonce for each attempt. It will carry both in its encrypted
request and retain the local association with the particular live session. This
is an explicit session tag, **not a claimed handshake transcript exporter**;
no such exporter is exposed by the inspected `Session` API. No handshake changes
or tag generation are implemented here.

M2a checks equality of the manifest with these independently supplied values,
verifies the pinned record and its fingerprint, and requires the session peer
record to equal the pinned full record. It never obtains the pinned key from the
payload or manifest. `ExpectedContext` is a caller-supplied expectation, not a
proof-bearing human-approval type. Its constructor is explicitly named
`from_local_expectations`; it has no JSON/remote deserializer, no approval Boolean
and no fallback key lookup. There is no production caller in this slice. A future
trusted caller must load a persisted, unrevoked local approval before constructing
it. Unit/integration tests construct synthetic expectations directly.

The inviter's separate approval is bound in the manifest by the exact recipient,
role, invitation, `recipient_authorization_id`, admission commit hash and
authorization expiry. That ID identifies the later sender-side durable onboarding
authorization record. Its existence, exactly-once admission and actual approval
cannot be established by this library; all remain a full-M2 gate. Neither a
self-claimed authorization ID nor a signed role can promote the M2a result.

The eventual REQUEST must convey at least the exact fields `env_id`, `recipient`,
`recipient_role`, `invite_id`, `approval_id`, `approval_sha256`, `session_nonce`,
`onboarding_nonce` inside the authenticated session. Its transport state machine,
wire handler, 4 KiB control-frame enforcement and durable approval workflow are
outside this implementation task. No new wire handler is approved by this design.

## 5. Exact manifest v1

```text
{
  "type": "BOOTSTRAP_MANIFEST",
  "domain": "zeropw-team-bootstrap-v1",
  "v": 1,
  "trust_model": "administrator_attested",
  "env_id": Env,
  "signer": FP,
  "recipient": FP,
  "recipient_role": "admin" | "user",
  "invite_id": I128,
  "approval_id": I128,
  "approval_sha256": H,
  "session_nonce": N256,
  "onboarding_nonce": N256,
  "transfer_id": I128,
  "recipient_authorization_id": I128,
  "recipient_admission_commit_hash": H,
  "authorization_expires_at_ms": WallMs,
  "created_at_ms": WallMs,
  "expires_at_ms": WallMs,
  "required_features": ["secret_tombstone_v1", "snapshot_bootstrap_v1"],
  "vector": Vector,
  "heads": [AuthorHead, ...],
  "counts": {"devices": UInt, "commits": UInt, "facts": UInt,
             "versions": UInt, "recipient_wraps": UInt},
  "components": [ComponentDescriptor, ...],
  "admitted_fact_hashes_sha256": H,
  "tombstone_digest": H,
  "expected_final_document_sha256": H,
  "payload": {"byte_length": UInt, "sha256": H,
              "chunks": [ChunkDescriptor, ...]},
  "sig": B64(64)
}
```

`required_features` is exactly the two-element sorted array above in v1, even
when the declared tombstone set is empty. Missing, duplicate or extra required
features are unsupported. Merely parsing this array does not negotiate or
advertise either feature.

`AuthorHead` is exactly
`{"author":FP,"author_seq":Seq,"commit_hash":H,"hlc":Hlc}`.
Heads are sorted by author, at most 256, and have exactly one entry for each
strictly positive vector entry and none for zero entries. A head's sequence
equals its vector value. A supplied head HLC is a numeric pair, compared to
`Hlc::parse(original_commit.hlc)`; **never rewrite the original signed HLC
string**, including its zero padding or other historically accepted spelling.
Missing signed head evidence is not supplied by a guessed zero/HLC. Structural
head binding is checked in M2a; whether it is the last admitted head remains later
semantic work.

`ComponentDescriptor` is exactly
`{"name":Name,"byte_length":UInt,"sha256":H,"item_count":UInt}`.
There are exactly six descriptors, in this exact order, and matching payload
components in that order:

| `Name` | `item_count` | Matching manifest count |
| --- | --- | --- |
| `devices` | Length of device array | `devices` |
| `snapshot` | Exactly 1 | Its encrypted version entries are counted separately as `versions` |
| `commits` | Length of `records` | `commits` |
| `facts` | Length of `records` | `facts` |
| `removals` | Exactly 1 | No additional commit/fact records; witnesses reference `commits` |
| `recipient_dek_wraps` | Length of `entries` | `recipient_wraps` |

All component lengths are positive and at most the payload length. All count
values must fit their actual bounded containers, with checked conversion before
reservation. Devices are at most 256. The checked sum of commits + facts +
snapshot encrypted version records is at most 65,536; references and repeated
copies of a wrap are not new commits/facts/versions. No declared count can excuse
a larger actual array. The device cap at this stage applies to the explicit
device table; consistency of all embedded device copies with that table is a
later semantic requirement, not permission for additional admitted identities.

`ChunkDescriptor` is exactly
`{"index":UInt,"byte_length":UInt,"sha256":H}`.
For raw payload length L, `1 <= L <= 16,777,216`, N is `ceil(L / 65,536)`, and
`1 <= N <= 256`. Descriptor index equals its array position. All but the last
chunk have exactly 65,536 bytes; the last has `L - 65,536*(N-1)` bytes, in
`1..=65,536`. These nonoverlapping byte ranges cover the payload exactly, without
gaps or offsets selected by a peer. Hash each raw range. Check arithmetic and
array count before allocating; no empty chunks or arbitrary partition variants.

The manifest signature is Ed25519 over **`C(M minus only top-level sig)`**.
Its domain, type, version, all identity/approval/session fields, times, features,
cut, digests, counts and chunk descriptions are signed. Use the expected pinned
signing key and existing `crypto::ed25519::verify`. The **manifest hash is
`SHA(C(M))`, including `sig`**. It is not the hash of raw manifest whitespace,
unsigned bytes, payload bytes, or a frame wrapper. Do not remove another `sig`
field recursively. This format has no detached signature document.

M2a enforces the 65,536-byte limit against original manifest bytes before parsing.
All bounds can coexist only if the entire manifest fits: 256 devices, 256 chunks
and arbitrarily large sequences are independent ceilings, not a promise that
their simultaneous maxima fit in 64 KiB. Oversize valid states fail explicitly.

At supplied verification wall time T, enforce:

```text
created_at_ms < expires_at_ms
expires_at_ms - created_at_ms <= 600000
T < expires_at_ms
created_at_ms <= T + 60000
expires_at_ms <= authorization_expires_at_ms
authorization_expires_at_ms <= local approval's invitation_expires_at_ms
```

All times are checked exact integers; comparisons use checked arithmetic (or an
equivalent subtraction avoiding overflow). At exact expiry the result is expired;
creation exactly 60 seconds ahead is allowed. There is no clock-skew grace after
expiry. These checks do **not** enforce the receiver's ten-minute monotonic
request deadline or 30-second idle deadline. The later coordinator must enforce
both, regardless of wall-clock movement, and revalidate on finalize/publication.
No supplied wall time can extend a local deadline. Transfer-ID freshness and
single-use nonce tracking also belong to that coordinator; M2a only checks their
shape and the request/session equality available in its inputs.

This bounded manifest contract handles an authorization within its original
invitation expiry. It does not define the later human renewal or completed-import
receipt-query workflow. The accepted full-M2 requirement to renew authorization
for an already admitted identity without a second invitation consumption or
`member.add` remains mandatory; expiry/approval binding for that workflow must be
resolved in its separate coordinator design. Do not reinterpret an expired
invitation or silently lift the bound above to claim renewal support in M2a.

## 6. Raw payload and component layouts

The payload is one uncompressed UTF-8 JSON object:

```text
{
  "format": "zeropw-team-bootstrap-payload-v1",
  "v": 1,
  "env_id": Env,
  "components": [
    {"name": "devices", "data": Devices},
    {"name": "snapshot", "data": Snapshot},
    {"name": "commits", "data": Commits},
    {"name": "facts", "data": Facts},
    {"name": "removals", "data": Removals},
    {"name": "recipient_dek_wraps", "data": RecipientWraps}
  ]
}
```

Each component hash/length is over the **exact contiguous original JSON value
bytes of its `data` member**, from its opening `[`/`{` to matching closing token,
including interior whitespace/escapes. Whitespace between the colon and opening
token or after its closing token is outside that component, but inside the whole
payload hash/length. Do not hash `name`, the component wrapper, reserialized
`Value`, a path, or decoded ciphertext instead. A future exporter should emit each
component and the outer object with the existing canonical writer for stable
fixtures, but receivers do not require a canonical raw spelling. Changing raw
whitespace inside a component requires both its descriptor and the overall
payload digest to change, even if the parsed values agree.

The payload deliberately contains no manifest hash, which would create a circular
digest dependency. Its environment is independently checked against the manifest.
Components cannot be missing, duplicated, reordered or added. There is no archive,
compression, file-name/path field, URI fetch, extension blob or alternate codec.
Legacy strings such as a connection's `ca_file` may exist as signed data, but
M2a never follows them or accepts them as staging paths.

### 6.1 Devices

`Devices` is an array of exactly
`{"fingerprint":FP,"record":{"sign_pub":B64(32),"agree_pub":B64(32),"sig":B64(64)}}`,
sorted by fingerprint with unique fingerprints and no conflicting records.
Construct and verify each `DeviceRecord` through the existing API; require its
computed fingerprint to match. Include signer, recipient, environment genesis
owner and all retained record authors. The signer's full record must equal the
locally pinned record. This table conveys key identity, never membership or role.
Every fingerprint referenced by a vector (including zero entries), head, commit
`seen` map, removal bound/pending/self-placed entry or retained record author must
have an entry in this table. No missing key is synthesized from the document.

### 6.2 Snapshot

`Snapshot` is exactly:

```text
{"document": LegacyEnvironmentDocument,
 "vector": Vector,
 "version_order": LegacyVersionOrder,
 "expected_final_document_sha256": H}
```

`document` is the **unflushed** current full-cut document, not an active-value
summary or old compaction cache. It is an object with existing `format` equal to
`zeropw-team-env-v1`, `env_id` equal to the manifest, and `secrets` an object.
For counting, each secret entry is an object containing a `versions` object;
each version is an object. Count every `(secret_id, version_id)` entry, including
staged, retired, revoked and encrypted unavailable-generation versions. Preserve
all other legacy fields and their JSON values without filtering; do not impose
a new closed field list on the legacy document. Full document validation is later.

`LegacyVersionOrder` is an object of secret IDs to arrays of original version-ID
strings. Preserve each array exactly; do not sort, deduplicate, renumber, infer
missing entries or recreate it from active versions. M2a checks this container
shape only. The semantic verifier must establish that it is the correct existing
fold order, including the appropriate treatment of evidence whose versions have
subsequently been removed. Do not invent a new bijection or ordering rule here.

The snapshot vector must equal the manifest vector as exact integers. Its final
document hash must equal the manifest claim. **Neither comparison recomputes the
final overlay.** Its eventual meaning is `SHA(C(final_document))`, computed after
validated facts/removals/M1 tombstones using the actual semantic fold. There is
no assumed empty overlay or use of the unflushed document's hash as a substitute.
No ciphertext is decoded, re-encrypted or dropped by M2a.

### 6.3 Retained commits and original canonical representation

`Commits` is exactly:

```text
{"records": [{"hash":H,"record":LegacyCommit}, ...],
 "genesis_commit_hash": H,
 "recipient_admission_commit_hash": H,
 "authority_commit_hashes": [H, ...]}
```

Records are sorted by `hash`, unique by hash and by `(author, author_seq)`.
`authority_commit_hashes` is a sorted set referring to `records`.
Both named commits must be present; the recipient admission hash equals the
manifest field. Genesis is a reference, not proof of an authorized `env.init`.
The later verifier establishes all authority operations and their completeness.

Each `LegacyCommit` uses the complete existing `Commit::to_dict()` representation:
`format`, `env_id`, `author`, `author_seq`, `hlc`, `seen`, `ops`, `sig`, with the
existing format `zeropw-team-commit-v1`. String header fields remain strings;
`author_seq` is a positive exact integer, `seen` is a fingerprint-to-nonnegative
integer object, `hlc` is the unchanged existing HLC string, `ops` is an array of
complete operation objects, and `sig` is a string. No operation is extracted from
its whole signed commit. Environment and author references must match.

After duplicate-safe materialization, use `Commit::from_dict`,
`Commit::canonical_json(true)` and `Commit::hash`. Require `C(record)` to equal
the existing canonical bytes; this prevents silent coercion, dropped top-level
fields or accidental normalization of an original record. This condition is on
the new envelope's embedded canonical record representation, **not a change to
legacy receive or stored-file parsers**. `ops` values retain their old finite
float/large-integer canonical semantics. Do not use `verify_commit` as a substitute
for retained-authority replay; M2a does not call it.

Each commit's author is in Devices, its sequence is at most that author's vector,
and its parsed HLC is at most the head HLC. Every positive vector head references
the matching record, exact author/sequence/hash and numeric HLC. Retained gaps are
allowed as evidence gaps, not fed to the ordinary sequential admission path.
Do not make the vector up to the maximum supplied subset or supply missing heads.

### 6.4 All candidate admitted facts and tombstone declaration

`Facts` is exactly:

```text
{"records": [{"hash":H,"record":LegacyFact}, ...],
 "admitted_fact_hashes": [H, ...],
 "tombstone_fact_hashes": [H, ...]}
```

Records are sorted by hash without duplicates. The admitted hash array is a
sorted set exactly equal to all record hashes. The tombstone array is a sorted
set exactly equal to hashes of records whose `kind` is `secret_deleted`.
Both empty arrays must be explicit. All fact hashes include the original `sig`.
Multiple different facts for one deleted secret remain distinct entries.

`LegacyFact` has exactly the existing canonical fields `format`, `env_id`, `kind`,
`target`, `author`, `hlc`, `sig`; format is `zeropw-team-fact-v1`, target is an
object, other fields are strings. Recognized v1 kind names are `incident`,
`connection_disabled`, `secret_version_revoked`, `member_removed`,
`secret_deleted`; a new kind requires a later format/capability decision, not
silent filtering. Environment/author references and existing HLC syntax are
checked. Preserve target values, including legacy numeric types. Use existing
`Fact::from_dict`, `canonical_json(true)` and `hash`, with the same canonical
equality condition as commits. Do **not** call or modify `verify_fact`,
`validate_fact_target`, `apply_fact`, `load_facts` or `receipt_fact` in this slice.
Kind recognition and canonical hashing are not signature/target/role admission.

Compare `SetHash(admitted_fact_hashes)` with `admitted_fact_hashes_sha256`, and
`SetHash(tombstone_fact_hashes)` with `tombstone_digest`. This fixes exactly the
M1 signed-fact-hash digest shape. A generic hash-array operation is permitted
here only for checking this declared set; it is not a second M1 tombstone-state
implementation. Later semantic integration must use M1's actual shared admitted
set/digest API and compare the complete proven set. No missing M1 adapter, unknown
target or missing field may be converted to an empty tombstone set. A declared
empty set consistent with its supplied records remains only an attestation about
an empty set, not proof that no deletion ever happened.

### 6.5 Removal claims and witnesses

`Removals` is exactly:

```text
{"bounds": Vector,
 "pending": [[Seq, Seq, FP], ...],
 "self_placed": [FP, ...],
 "witness_commit_hashes": [H, ...]}
```

These are the existing snapshot-record schedule shapes: pending entries are
`[wall_ms, counter, fingerprint]`, sorted by that exact numeric/numeric/string
tuple; each fingerprint occurs at most once there. `self_placed` and witness
hashes are sorted sets; no fingerprint is both pending and self-placed. Bounds,
pending and self-placed entries refer to Devices and each has at most 256 entries;
bounds need not be narrowed to the current vector by an invented rule. Every
witness hash refers to a whole retained commit. M2a checks shape, references and
ordering, **not** the validity/completeness of placement or removal cutoffs.

This is a new transfer component, not an imported sender `snapshot_records` file.
Its facts come from the exact signed fact component, not a lossy folded target
list. Later replay must recompute the claimed pending/bounds/self-placement using
the actual existing removal rules and all required witnesses. A legacy compacted
source missing a necessary signed head or witness remains unsupported.

### 6.6 Recipient DEK wraps

`RecipientWraps` is exactly:

```text
{"entries": [
  {"generation_id":Token,"recipient":FP,"source_commit_hash":H,
   "source_op_index":UInt,"wrap":LegacyWrap}, ...
 ],
 "unavailable_generations": [Token, ...]}
```

Entries are sorted and unique by `(generation_id, source_commit_hash,
source_op_index)`; multiple historical signed wraps for one generation may be
retained. All recipients equal the manifest recipient. The unavailable list is
a sorted set and cannot overlap an entry's generation. `LegacyWrap` is the
original object with string `eph_pub`, `nonce`, `ciphertext`, retaining any legacy
fields/values covered by the original commit. It is **not separately signed**:
its original signature is the containing whole commit's signature.

M2a checks source hash presence, checked op index bounds and exact `C(wrap)`
equality to the referenced operation's selected wrap. The only selectors are:
`member.add` -> `ops[index].wraps[generation_id]` with that op's device fingerprint
equal to recipient; `env.init` or `dek.rotate` -> `ops[index].wraps[recipient]`
with matching `generation_id`. No JSON pointer or arbitrary path is supplied by
the peer. This is a structural byte/value reference check, not authorization of
the source operation. Reject a wrong selector, wrong recipient or changed wrap.

Do not unwrap, decrypt, create a wrap, obtain local KMS material or infer required
generations. An explicitly unavailable generation is preserved as a claim.
Full M2 must determine the generations required by currently usable credentials
and refuse the import when any required generation is unavailable or invalid.

## 7. Original-byte parser contract and choice

Current `transport::Session::recv` returns `Value`; `EncryptedSession::recv`
calls `pyjson::loads` on decrypted bytes before `sync::handle_message`. Object
duplicates have already been lost by that point. **No M2a API accepts a `Value`
or a reserialization as evidence that original checkpoint bytes were strict.**
Eventual new-frame integration must retain original bounded decrypted bytes, or
a private strict-validation witness tied to those exact immutable bytes, before
the current conversion. It must discriminate new frames safely and leave legacy
frame/persisted parsers unchanged. That transport change waits for M1's exact head.

Decision: add only the `raw_value` feature to the already pinned serde_json
dependency (lockfile presently 1.0.151); use borrowed `RawValue` subvalues and
**explicit map/sequence visitors**, with a nonrecursive preflight depth/string
guard. Retain `arbitrary_precision`, `preserve_order`, `unbounded_depth`. Do not
upgrade dependencies or change legacy `pyjson::loads`.

Why this choice: a generic seeded `deserialize_any` visitor can observe the
arbitrary-precision number's private synthetic map representation. Treating its
magic key as numeric also risks accepting a real input object as a number;
converting numeric visits through f64/u64 loses information. A typed seeded
visitor could be safe only with a separately proven lexical discriminator for
every number and object. Borrowed raw spans give that discriminator, exact hash
ranges and unchanged numeric token text without designing a second number codec.
`RawValue` alone is **not** sufficient: it does not enforce decoded-key uniqueness,
our depth bound, counts, or unknown-field policy.

Required parsing order and implementation properties:

1. Check original byte size before UTF-8 conversion, parsing, ownership/copy,
   base64 expansion or size-derived reserve. Check UTF-8; do not replace invalid
   bytes. Preflight the full JSON byte string with an iterative container-depth
   and escape/surrogate guard, before RawValue's nested-value scan. The guard is
   not a replacement JSON grammar: serde validates delimiters, numbers, strings,
   trailing commas and `end()` afterward. Reject malformed Unicode escapes and
   lone UTF-16 surrogates, including object keys; do not substitute U+FFFD.
2. Depth is the count of enclosing/open JSON arrays and objects: root object or
   array is depth 1, its child container depth 2; scalar values and object keys
   add no depth. At the opening delimiter that would create depth 65, refuse
   **before recursing or allocating that container**. Exactly 64 is admitted
   syntactically. Count across the entire payload, including wrappers and legacy
   content, with no reset at a component or record boundary. The outer format's
   depth limit may explicitly exclude a deeper otherwise-valid legacy state
   from bootstrap; it must not alter that state's existing loader.
3. Borrow the original root/subvalue spans. Dispatch based on the actual first
   token: `{` uses an explicit object visitor, `[` a sequence visitor, scalar
   tokens use the existing scalar JSON helper. Object visitors decode the key,
   check it in a per-object set, and reject a duplicate **before inserting it
   into any Value/map or requesting/materializing its value**. This includes
   `"x"`/`"\u0078"` and literal non-BMP/paired-surrogate equivalents. Do not
   normalize Unicode; distinct composed/decomposed strings remain distinct.
4. Traverse every child, including legacy opaque contents. Borrowing a RawValue
   must not become a skip-duplicates loophole. Validate container shape/counts
   incrementally; stop at the 257th device or 65,537th combined record before
   reserving/materializing it. Never reserve from an untrusted serde size hint
   or unchecked declared count. Build only bounded indexes/raw references first;
   materialize individual legacy records as needed, not an unbounded Value tree
   before checking counts. Do not retain several full payload clones.
5. Materialize containers explicitly after their keys pass the checks; do not
   pass an untrusted object back through `Value::deserialize` or whole-object
   `pyjson::loads`. In particular literal objects with keys
   `$serde_json::private::Number` and `$serde_json::private::RawValue` stay objects,
   even if singleton or escaped. Never reinterpret these keys as serde metadata.
   This is necessary even after duplicate rejection. Use `pyjson::loads` for
   isolated scalar tokens and the existing canonical writer for materialized
   values, preserving exact integer tokens and legacy finite-number semantics.
6. For new numeric controls check the **original token's** UInt grammar before
   `PyInt::from_json_integer`; keep sequence/HLC values exact. Bounded sizes,
   indices, counts and wall times then use checked range/conversion. No
   `coerce_from_json`, `from_python_int`, `as_f64`, truncating cast, inferred zero,
   or raw serde number map is allowed as the control-number boundary.
7. Keep parsing/traversal iterative or with independently bounded stack use;
   test on a 256 KiB thread stack at depth 64 and very deep refused input. Do
   not rely on recursion checks after a recursive allocation has occurred.
   Do not use a thread-per-message workaround or modify process-wide stack/state.

The locked dependency source/private representation has not been executed or
probed during this design task. The worker must prove the chosen path with the
fixtures below in isolation. If it cannot preserve the stated private-map and
number contracts, report the blocker; do not fall back to a generic Value parser
or weaken compatibility guards. A structural guard local to the new module is
permitted; a new JSON grammar, number serializer or global helper rewrite is not.

## 8. Verification order, bounds and failure reporting

`verify_manifest_bytes` completes pinned key/request/approval/session equality,
wall freshness and signature validation before any payload is accepted by the
payload/chunk APIs. `ManifestAttestation` has private fields and no public
deserializer or unchecked constructor. Manifest parsing can allocate only within
its 64 KiB input bound; it never reserves a payload from a signed length alone.

`verify_payload_bytes(&attestation, original_bytes)` requires the byte length to
equal the signed L, and L to satisfy the cap, before parse/copy. Check the whole
raw SHA and each deterministic raw chunk range before detailed JSON parsing.
After strict structural traversal, hash the exact component spans, compare counts
and the stated structural references, then construct the limited result. The
caller owns the input bytes: this function cannot retroactively prevent a caller
from already allocating them. A later network receiver must obtain an attestation
before allocating/staging that buffer. Keep raw bytes immutable and lifetimes or
private owned buffers bound to the returned result; do not keep mutable aliases.

The pure per-chunk API in this task takes original bytes of this exact
frame, never a `Value`:

```text
{"type":"BOOTSTRAP_CHUNK","v":1,"transfer_id":I128,
 "manifest_hash":H,"index":UInt,"data_b64":String}
```

It checks raw frame size <=131,072 and strict schema, then manifest/transfer/index
bindings and the signed chunk length. Before base64 decode, require the encoded
string length to be `4*ceil(signed_chunk_length/3)` with checked arithmetic; strict
decode and exact re-encode must agree, then decoded length and SHA must match.
No whitespace, URL-safe alphabet or noncanonical padding bits are accepted in
this new encoding. It creates at most one <=65,536-byte decoded chunk. It does
not track next index, accept a transfer, stage bytes or provide cross-session
resume. Checking the same exact frame twice is statelessly identical; ordering
and idempotent duplicate delivery are the later transfer coordinator's job.

| Accepted M2 bound | M2a enforcement / remaining responsibility |
| --- | --- |
| Manifest 64 KiB | Enforced on original bytes |
| Payload 16 MiB | Enforced on original total bytes |
| Chunk 64 KiB, <=256; chunk frame 128 KiB | Signed partition and pure chunk-frame checks; no network handler |
| JSON depth 64 | Enforced before container recursion/materialization, including embedded data |
| Devices 256; commits + facts + versions 65,536 | Actual table/container counts; later semantic verifier reconciles all identity/evidence copies |
| ACK 64 KiB; other controls 4 KiB | No ACK/other-control APIs or emission here; later transfer component must enforce |
| Four outstanding chunks; 512 KiB queued frames | Later coordinator; not enforced or advertised here |
| Staging 64 MiB/transfer, 128 MiB/process; one/environment, two total | Later coordinator/storage; no staging here |
| Ten-minute monotonic total, 30-second idle | Later coordinator; only manifest wall checks here |

Closed error reasons for this slice: `team_checkpoint_json_invalid`,
`team_checkpoint_duplicate_key`, `team_checkpoint_limit_exceeded`,
`team_checkpoint_schema_unsupported`, `team_checkpoint_binding_mismatch`,
`team_checkpoint_expired`, `team_checkpoint_signature_invalid`,
`team_checkpoint_integrity_mismatch`, `team_checkpoint_structure_invalid`.
Use static reason enums and, if useful, a bounded component enum/index. Do not
return serde's input-bearing error detail, peer key names/strings, raw input,
ciphertext, signature bytes, paths or a claimed secret value in Debug/Display,
logs or errors. Precedence among errors in a multiply invalid input is not an
acceptance condition; refusal and allocation boundaries are.

## 9. Inert candidate provenance, exact schema

Construct only from the paired manifest attestation and integrity-checked payload,
never from another manifest's metadata. This is an in-memory, serializable
candidate; M2a has no disk writer or import reader. Its exact JSON representation:

```text
{
  "format": "zeropw-team-checkpoint-candidate-v1",
  "v": 1,
  "trust_model": "administrator_attested",
  "stage": "integrity_checked_not_admitted",
  "env_id": Env,
  "manifest_hash": H,
  "signer": FP,
  "signer_record": DeviceRecord.to_dict(),
  "recipient": FP,
  "recipient_role": "admin" | "user",
  "invite_id": I128,
  "approval_id": I128,
  "approval_sha256": H,
  "session_nonce": N256,
  "onboarding_nonce": N256,
  "transfer_id": I128,
  "recipient_authorization_id": I128,
  "recipient_admission_commit_hash": H,
  "vector": Vector,
  "heads": [AuthorHead, ...],
  "components": [ComponentDescriptor, ...],
  "payload_sha256": H,
  "admitted_fact_hashes_sha256": H,
  "tombstone_digest": H,
  "expected_final_document_sha256": H,
  "candidate_fact_bindings": [
    {"fact_hash":H,"manifest_hash":H,"approved_signer":FP,
     "approval_sha256":H,"basis":"administrator_attested_candidate"}, ...
  ],
  "candidate_tombstone_fact_hashes": [H, ...]
}
```

Candidate fact bindings are sorted by fact hash and cover every supplied fact
exactly once. They bind the proposed attested admission individually, including
historical facts whose eventual admission basis needs the approved administrator's
exact-set attestation. They are **not admitted facts**. No sender-local receipt
signatures are included. Do not deserialize this JSON back into a proof type;
serialization is an inspection/fixture facility, not persistence authority.

All cryptographic and candidate result types have private fields and redacted
Debug/Display. Do not add `Deserialize`, `From<Value>`, unchecked setters or a
conversion from candidate to a future committed type. The later durable importer
will define a distinct committed-provenance record binding semantic verification,
approval revalidation and the committed import epoch. Reading candidate JSON or
recomputing its hash can never substitute for that transaction.

## 10. Fixture and test contract

The Sol task must add its own deterministic synthetic fixtures under
`rust/tests/fixtures/team_checkpoint_v1/`; existing prototype fixtures and their
GENERATE files remain byte-identical. No host fixture generation is authorized.
Generate and verify any signatures only in the isolated worker. Fixtures are
new-format evidence, not replacement Python oracles.

Freeze fixture filenames and roles:

| File(s) | Required meaning |
| --- | --- |
| `README.md` | Actual generator/model/source/toolchain, public deterministic seeds marked synthetic, commands, exact expected stage and unsupported gates |
| `approval.json`, `context.json` | Exact local approval description and independent expected session/request inputs; test-only context serialization, no production context deserializer |
| `manifest.json`, `manifest.unsigned.canon`, `manifest.signed.canon` | Raw valid manifest; literal canonical signature bytes; literal canonical hash bytes, all without a trailing newline in `.canon` files |
| `payload.json`, `components/{name}.json` | Exact raw payload and the six exact `data` byte spans; no component file path appears in the wire payload |
| `chunks/000.bin` etc., `chunk-000.json` etc. | Deterministic consecutive raw chunk slices and canonical test frames |
| `candidate.json`, `expected.json`, `SHA256SUMS` | Exact inert output, literal expected manifest/payload/component/record/set digests and counts, hashes of every fixture except SHA256SUMS itself |
| `raw-cases/` | Handcrafted original-byte duplicates, private-key-name ambiguities, invalid UTF-8/Unicode, numeric and depth cases; never generated through a map that already discards duplicates |

Use public deterministic Ed25519 seeds `00` repeated 32 bytes for owner,
`01` repeated 32 bytes for an active non-owner admin, and `02` repeated 32 bytes
for recipient; deterministic synthetic agreement-key material must be stated in
README. Set environment suffix to `0123456789abcdef0123456789abcdef`, invitation
ID to `10` repeated 16 bytes, local approval ID to `20` repeated 16 bytes, sender
authorization ID to `30` repeated 16 bytes, transfer ID to `40` repeated 16 bytes,
session nonce to `50` repeated 32 bytes, onboarding nonce to `60` repeated 32 bytes.
Set creation to `1800000000000`, check time to `1800000000001`, expiry to
`1800000600000`, authorization/invitation expiry to `1800003600000`. These are
fixture constants, not production key/randomness examples.

The baseline graph is fixed as follows. O/A/R denote those owner/admin/recipient
fingerprints; generation G is `a` repeated 16 characters, version V1 is `b`
repeated 16, V2 is `c` repeated 16. Device agreement private test scalars are
hex bytes `03`, `04`, `05`, each repeated 32 times, respectively. Each commit
contains one operation, and all header/signature bytes use the original helpers.

| Commit | HLC | `seen` | Operation |
| --- | --- | --- | --- |
| O:1 | `1000-0000` | `{}` | `env.init`, owner name `owner`, owner record O, G and original wrap for O |
| O:2 | `2000-0000` | `{O:1}` | `member.add`, name `admin`, device A, role `admin`, G wrap for A |
| A:1 | `3000-0000` | `{O:2}` | `member.add`, name `recipient`, device R, role `user`, G wrap for R |
| O:3 | `4000-0000` | `{O:2,A:1}` | `secret.put_version`, ID `retained-secret`, kind `api_key`, G, V1, ciphertext and empty public metadata |
| O:4 | `5000-0000` | `{O:3,A:1}` | Same operation for V2 and its distinct ciphertext |
| A:2 | `6000-0000` | `{O:4,A:1}` | `secret.activate`, ID `retained-secret`, V2 |

Build the baseline snapshot/version order from this complete synthetic history
without facts, using existing pure fold helpers in the isolated fixture builder.
Retain O:1, O:2, O:4, A:1, A:2 in the payload (O:3 is the intentionally compacted
gap). Declare vector `{O:4,A:2,R:0}`, heads O:4 and A:2, authority references
O:1/O:2/A:1, recipient admission A:1, no removals, explicit empty fact arrays,
and the recipient G wrap referencing A:1 op index 0. Counts are devices 3,
commits 5, facts 0, versions 2, recipient wraps 1. Its no-fact final-document
claim is the canonical pure fold result. This exercises an attested missing
prefix, not a claim that M2a verified that prefix.

For deterministic encrypted fixtures use test DEK byte `06` repeated 32, values
ASCII `synthetic-checkpoint-v1` / `synthetic-checkpoint-v2`, and distinct 12-byte
nonces `07` / `08` repeated. Use existing ChaCha20-Poly1305 with the existing
AAD `Env || NUL || secret_id || NUL || version_id`. Deterministic original wraps
use ephemeral test scalars `09`/`0a`/`0b` repeated 32 for O/A/R, and nonces
`0c`/`0d`/`0e` repeated 12; reuse existing X25519, `envelope::hkdf`, and AEAD,
with the existing info `zeropw-team-dek-v1 || Env || G || recipient`. This
test-only construction must round-trip through the existing unwrap/decrypt
helpers in isolation; it does not add deterministic encryption to product code.

Construct real signed synthetic retained records (using existing signing helpers
where supported) and at least two encrypted versions. One fixture must contain
nonempty `secret_deleted` facts and one no-version tombstone case, with an exact
nonempty declared set. Since pre-M1 `sign_fact` rejects that kind, the test fixture
may form the unchanged `Fact` canonical bytes and sign them with the existing
Ed25519 primitive in **test-only code**; it must label that fixture an integrity
candidate, not an admitted M1 deletion. No production permissive M1 adapter.
Do not invent a full semantic success fixture before the actual M1 head exists.
Use A's deletion facts at HLC `7000-0000`, target `{"secret_id":"deleted-empty"}`,
and `8000-0000`, target `{"secret_id":"retained-secret"}`, in separately labeled
candidate variants. The first has no corresponding secret/version entry. The
second keeps both encrypted versions in the unflushed snapshot. Compute both
declared tombstone digests from the exact nonempty fact-hash arrays. Any retained
baseline final-document claim in these variants is explicitly an unverified
claim; do not synthesize an M1 fold/overlay to make it look verified. A separate
changed-final-digest candidate tests that M2a does not pretend to verify overlay.

Required meaningful test families:

1. Top-level, nested, legacy-target and escaped-equivalent duplicate decoded
   keys; reordered duplicate names; a duplicate whose second value is huge/deep;
   invalid UTF-8, lone surrogates, valid surrogate pairs, trailing JSON, missing
   fields, extra fields/components, array reordering and unknown required features.
2. Root-depth fixtures: `D(n)` is exactly n `[` bytes, ASCII `0`, n `]` bytes;
   D(64) passes the internal syntax guard and D(65) fails there. An object fixture
   with a nested legacy value reaching **total** depth 64 passes that syntax
   boundary; changing to total 65 fails. Brackets/escaped quotes inside strings
   do not count. A very deep input is refused on the small-stack test before
   recursive serde work, including on error/drop paths.
3. Literal singleton/multi-key objects containing
   `$serde_json::private::Number`/`$serde_json::private::RawValue` remain objects;
   escaped duplicate versions are refused. Large actual numeric tokens remain
   numbers. Prove canonical bytes, not merely approximate numeric equality.
4. Exact integer fixtures include `9007199254740993` and
   `1844674407370955161600000000000000000001` in vector/author sequences and HLC
   pairs. Each must remain exact through comparison and canonical hashing.
   Reject control `true`, `"1"`, `1.0`, `1e0`, `-0`, negative sizes and overflowing
   bounded counts. Embedded legacy `1.0`, `-0.0`, `1e-7`, finite exponent values
   and large signed integers preserve existing canonical outputs. Overflowing
   float literals remain refused. Never reject all floats globally.
5. Valid synthetic pinned manifest; invalid signature, substituted key or full
   device record, corrupted signed byte, wrong domain/version/environment,
   recipient, role, invitation, local approval ID/hash, either nonce, stale
   session context and bad feature set. A self-claimed snapshot admin cannot
   supply the pin. Test expiry equality, future +60,000/+60,001 ms, duration
   600,000/600,001 ms, authorization/invitation bounds and integer overflow.
6. Raw sizes at each exact limit and one over; count limits independently from
   payload-size limits (use the internal bounded container/count helper where
   real records cannot all fit); manifest chunk descriptors 256/257 and exact
   partition arithmetic. Hash/length checks must precede payload JSON work;
   denied manifest/context must not invoke a payload decoder. No huge reserve
   from a tiny input declaring an enormous length.
7. Chunk wrong manifest/transfer/index, wrong size/digest, truncated data,
   noncanonical base64 and 128 KiB frame boundary; reversed/changed concatenated
   chunks fail `verify_payload_bytes`. Do not claim a stateless API enforced
   receive ordering, monotonic timeouts or queue/process budgets.
8. Component span golden bytes, whitespace inside versus outside a component,
   wrong signed counts, missing/extra/duplicate components, changed version IDs,
   ciphertext or version-order arrays; fact-set/tombstone-set omissions relative
   to the manifest, duplicate hashes, duplicate author sequences, missing heads,
   inconsistent vector/HLC, unknown author, bad device record, missing witness or
   wrap source, changed wrap/recipient/index. Re-sign mutations when testing
   structure rather than an earlier whole-payload hash failure.
9. Existing Commit/Fact canonical bytes/hashes equal their embedded representation,
   including legacy numeric cases; do not regenerate existing fixtures. Real
   original signatures in the baseline fixture are independently checked in
   tests, while an invalid inner signature with coherently re-attested hashes
   can reach only `IntegrityCheckedPayload`. Likewise a well-formed self-claimed
   admin role, malformed M1 target, and false final-overlay digest must never be
   described as semantic success. These are explicit full-M2 obligations.
10. Candidate output exact-stage/trust/key/approval/manifest/fact binding;
    mismatched attestations cannot be paired; unknown/full-history trust labels
    are never emitted. Public API compile-fail doctests prohibit proof-type
    construction, deserialization and any install/receipt conversion. Errors and
    Debug output do not echo synthetic sensitive-marker strings from malformed
    inputs. The slice imports no runtime authority APIs and has no production
    caller from sync/join/derive.

Literal canonical byte files, hashes and signatures must be independently
inspected against the existing primitives and then checked in; tests must not
derive every expected value through the function under test. State the actual
generator and evidence rather than call a new Rust fixture a Python oracle.
Exact oversized/count fixtures may be generated deterministically in tests to
avoid checking in tens of MiB. This design supplies no generated signature/hash
values for them and makes no claim that these tests have run.

## 11. Mandatory later gates and unresolved dependencies

These IDs are **planning gates**, not invented Opus findings. None is resolved by
M2a; there are no supplied M2a Opus finding IDs to mark fixed.

| ID | Required before full M2 can be supported |
| --- | --- |
| M2-G01 | Actual M1 exact-head integration: admitted original tombstone facts, complete monotone set/shared digest, historical target/authority rules and durable session ACK; no empty shim or filtered unknown facts |
| M2-G02 | All original commit/fact signatures, schemas and targets; genesis owner/key/signature; retained authority replay in existing total order, including owner transfer, prior demotion/removal, no skipped operations, exact recipient role and active admin signer; full device-copy consistency |
| M2-G03 | Every historical fact admission basis and irreversible effect; attested admission only where permitted, reject retained contradictory proof; complete removal witnesses, bounds and placement; recompute final fold/digest and preserve every original fact/tombstone |
| M2-G04 | Future compaction retains heads/removal witnesses; legacy missing proof explicitly unsupported; continuation uses exact sequence/HLC floors and fails `team_checkpoint_history_required` for unavailable precut reconciliation without allowing deleted credentials |
| M2-G05 | Required DEK generations and valid recipient original wraps; currently usable credentials with missing generations fail; no KMS/derive work until semantic verification |
| M2-G06 | Real persisted two-sided human approvals, exactly-once invitation/admission authorization, fresh-session feature gate, original-byte transport seam, all budgets/timeouts/cancel/resume rules; no cross-session partial-byte resume |
| M2-G07 | Fresh finalize challenge and separately domain-signed READY (`zeropw-team-bootstrap-ready-v1`), same live session; lock/recheck entire cut, approval, signer/recipient and known revocation; restart on changed cut |
| M2-G08 | Fresh-environment/collision eligibility; journal, recovery, fsync and durable completed import record; coherent committed epoch at reads **and credential use**, including cached contexts and already-running gateway/signer; no unlocked flag/read race or per-file atomicity claim |
| M2-G09 | Provenance durably committed before any receiver local receipt, ACK, joined/readiness or activation; subsequent restart/compaction retains provenance and M1 facts; old-binary downgrade remains unsupported for new state |
| M2-G10 | Real signed repeated-compaction onboarding, continuation, all M1 cases, crash/disk-full/concurrent-reader tests, direct and forced TURN, isolated Linux/macOS full verification, physical/native two-Mac evidence and actual Opus review of the final implementation head |

Failure conditions retain the accepted names
`team_bootstrap_authority_unproven`,
`team_bootstrap_existing_state_unsupported`, and
`team_checkpoint_history_required` for their later runtime cases. M2a does not
add fake runtime handlers merely to return them.

Unresolved implementation dependencies are the actual completed M1 APIs/head,
proof-preserving future compaction, trusted request/approval persistence and raw
transport seam, renewal/receipt-query binding, semantic replay/fold API, and
coherent import epoch machinery.
Their design/implementation must be reconciled before integration. There is no
unresolved choice about the bounded M2a manifest names, raw hash ranges, numeric
forms or parser behavior: those are fixed here. Dependency behavior/small-stack
safety and fixture generation remain unexecuted engineering validation, not
assumptions to report as proven. Do not silently change this schema if a later
integration finds a conflict; return that conflict for a separate decision.

## 12. Source references and evidence limits

Key inspected seams, all in the Rust tree identified above:

| Source | Relevant inspected location |
| --- | --- |
| `rust/src/pyjson.rs` | Canonical numeric rules; `loads` 553+, `parse_and_validate` 579+, guard 621+, literal classification 754+, writer 942+ |
| `rust/src/pyint.rs` | `from_json_integer` 59+, exact values/conversions 78+ |
| `rust/src/pybase64.rs` | Existing compatibility/strict base64 boundary, not a new decoder |
| `rust/src/team/identity.rs` | `DeviceRecord` 80+, verification/fingerprint 105–128, canonical dictionary/parser 132–177 |
| `rust/src/team/commit.rs` | HLC 250–290, total order 326+, canonical records/hashes 345–455, signature validator 785+, IDs 816+, wrap selectors/shapes 1744–1853 |
| `rust/src/team/sync.rs` | Fact 4312+, canonical/hash/parser 4322+, verification 4395+, local-only receipt 4463+; M1 kind absent from inspected source |
| `rust/src/team/fold.rs` | Facts/removal schedule 93–240, document 242+, version order 295+, unflushed snapshot 1412+, snapshot record 2332+ |
| `rust/src/team/transport.rs` | `Session::recv` 114–118, encrypted receive and Value conversion 266–297 |
| `rust/src/team/membership.rs`, `pairing.rs` | Invitation ID, role/expiry/admission approval fields; no approval-secret or runtime-state reads |
| `rust/src/team/envelope.rs` | Original `wrap_dek` output 121–162; no separate wrap signature |
| `rust/tests/fixtures/python/team/oracle/state/team/ph5tr32bj27nk7zphjn2qf4z5u-0123456789abcdef0123456789abcdef/snapshots/1.json` | Read-only legacy snapshot/document/version-order example, not a new valid M2 fixture |
| `rust/tests/canonical_helpers.rs`, `rust/verify.sh` | Existing guard and full matrix/automatic integration-target discovery; not executed |

SHA-256 of prescribed documents read at this worktree:

```text
08c4fbc5a439a1344d3ad309455483f3aa755438bbd626062256469d8f508b93  AGENTS.md
79dd92c5459a5f76180810fabc02083e4f0d19bfa4d9e44a14ea9e98dfc8020d  docs/product-intent.md
20a151a1b563a8c6a6c2ca3c1c2caaef0a27b098764cd01deba208f14ec036d0  docs/security-design.md
feab029523480dd8f1b7cf2c969685de5da52f8f96531ccafec6668ab446e6f6  docs/harness.md
92bb2ff8dce48c15d434d5a12c6cfebb2358b4c83c08f20c7d9138870c08f121  harness/README.md
6ec057c0f800a2f4afe2e6766fd57c694245118dc79d64937871f75d0ec35b8c  rust/PORTING.md
53e30740e5fef4f764dfa8c96cb3eafdb1e96c834c3e611e5c042a812b37f0fe  docs/remote-sync-next-milestones.md
```

The committed source-bound E2E report
`docs/evidence/remote-sync-e2e-2026-11-07-bd-4af/README.md` was read (SHA-256
`a57685d45a3373761db85ae4743c53f35a083f59a3c61ff4fef08c90fe48b8ec`). It reports
66 original assertions plus seven synthetic service-secret scans at the stated
52e87b Rust tree and link 4af5ac source; those results were **not rerun here** and
do not cover M1/M2, native, IPv6 or OCI capacity.

The supplied brief also reports prior bd065fc native full PASS 1634, Linux full
FAIL with 1630 passes and one grant-expiry failure; ten diagnostic passes did not
establish a cause. It reports link 4af5ac8 Go/vet/race/crossbuild/installer checks,
new native privacy probes NOT RUN, and an actual Opus re-review blocked by quota
before source was read, with a provider-reported 2026-11-07 17:50 KST reset. These
are attributed historical context, not independently verified or newly performed
results. No retry, substitute review or release conclusion is part of this task.
Oracle DNS/ACME work is not product deployment. macOS MLP scope does not remove
Linux CI or clear that Linux failure. The accepted milestones' independent
macOS ACL finding and other unresolved release-review scopes are not closed;
no exact original review ID for those was supplied here, and none is invented.

Linux full `rust/verify.sh` is required of the later isolated M2a implementation.
The native Mac runner remains exclusively with the independent M1 task: M2a may
return committed code with native verification explicitly **NOT RUN**, but no
full-M2 or release acceptance. Both platform gates and actual final-head Opus
review remain mandatory. This design was checked by source reading and document
inspection only; all implementation/runtime/platform/review validation is NOT RUN.
