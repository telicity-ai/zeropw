# Synthetic checkpoint-v1 goldens

Actual author: gpt-6.1-sol, ultra reasoning effort, T3 Code/Codex harness.
No additional model version, temperature or sampling settings were exposed.
Input base ce796bdcf5069af8e6cd85ab3c953cc22e1bf1a4; original Rust tree 2882ba592e2204eb62723d95e240525e75196f64.
Decision SHA-256 564bcf4c312b04507e815e35cc8eed9f5c6ae8f74ee539ccecf88cff8f0595b2; narrow task SHA-256
8f89a1caa07c5c54afb24bcf14193889dd9d6fda241b98d532fc181b85e33272.
Generator: rust/tests/common/team_checkpoint.rs SHA-256 d284a641ab430ee5744c1e114fc760e15c8d62b83b29b08406f358536515615d.
Unchanged product Cargo.lock SHA-256 fb0dbbf2a2b25c111a419f3b2102d51d2859a1745e28afca9b8d59339340d840.

This package is fixture/crypto/golden consistency evidence, never semantic M2
admission or a parser PASS. Candidate JSON is an exact expected inert output,
constructed in test code. No production checkpoint verifier exists in this slice.
The pin is the non-owner admin A, independently supplied in approval/context.
context.json is test-only serialization, not a production deserializer contract.

All generation/crypto/test execution occurs in owned credential-free exports in
Lima zeropw-parity (Linux aarch64, kernel 6.8.0-147-generic), rustc 1.98.1
(48a229cea 2026-09-01), cargo 1.98.1 (797e8a9bc 2026-08-05). No host product
execution, native macOS/M1 runner, production keys, networking or runtime changes.
The exact VM scripts, command exits, source/driver manifests and before/after
tracked blob/mode manifests are retained in the external task evidence directory
/Users/ys/Code/zeropw-mlp-evidence/m2a-fixtures-sol-20261107/.

## Public deterministic material (synthetic ONLY)

O/A/R Ed25519 seeds: byte 00/01/02 repeated 32; X25519 private test scalars:
03/04/05 repeated 32. DEK: 06 repeated 32. Values: ASCII
synthetic-checkpoint-v1 and synthetic-checkpoint-v2. Version nonces: 07/08 repeated
12. Wrap ephemeral private test scalars: 09/0a/0b repeated 32; wrap nonces:
0c/0d/0e repeated 12. Existing X25519, envelope::hkdf and ChaCha20-Poly1305
primitives construct these; existing unwrap_dek/decrypt_secret check them.
These are intentionally public insecure test constants, never production examples.
No plaintext value or DEK/private key is embedded in a wire payload.

Suffix: 0123456789abcdef0123456789abcdef. G/V1/V2: a/b/c repeated 16.
Invite/approval/authorization/transfer IDs: 10/20/30/40 repeated 16.
Session/onboarding nonces: 50/60 repeated 32. Creation/check/expiry:
1800000000000/1800000000001/1800000600000 ms; authorization/invitation expiry:
1800003600000 ms. The exact six-commit graph is decision section 10. Original
whole records and signed/unsigned canonical bytes are in history/; O:3 is evidence
for generation only and is deliberately absent from the payload. Payload retains
O:1,O:2,O:4,A:1,A:2; vector O4/A2/R0, heads O4/A2, authority O1/O2/A1,
admission A1. Three devices, five commits, zero facts, two versions, one recipient
G wrap from A1 operation 0. No removals, explicit empty fact/tombstone arrays.

The snapshot comes from the unchanged pure fold of all six commits with no
facts/removals; its empty overlay changes nothing, so this IS the unflushed
full-cut document. V1 remains staged; V2 active; original version order [V1,V2].
No gapped-history fold, active-value summary or M1 overlay is invented.

## Files and limited variants

Root is the baseline. Each variants/ directory is a complete separately signed
manifest/payload/component/chunk/candidate/expected package using the same pin and
context. Raw payload, components and .canon files have no trailing newline.
expected.json contains literal hashes, counts, record signatures, heads and raw
span offsets. SHA256SUMS covers every fixture file except itself, including this
README and raw-case corpus. history/expected.json binds all six original commits.

- deleted-empty: A secret_deleted fact at 7000-0000 for deleted-empty, which has
  no snapshot secret/version entry; exact nonempty admitted/tombstone hash set.
- deleted-retained: A secret_deleted fact at 8000-0000 for retained-secret;
  snapshot retains BOTH original encrypted versions and original order.
- changed-final-digest: signed final-document claim is f repeated 64; same raw
  document. This explicitly false overlay claim remains unverified.
- invalid-inner-signature: O4 signature is zero bytes; original canonical/hash,
  head and all outer hashes/signature are coherently re-attested. Independent
  crypto check expects exactly one invalid original commit signature.

Deletion signatures use unchanged Fact canonical bytes plus existing Ed25519 in
test code because pre-M1 sign_fact refuses secret_deleted. They are NOT admitted
M1 facts. All variant final-overlay claims are explicitly UNVERIFIED, including
retained baseline claims. They are integrity-only candidate goldens, not proof
that a new parser accepts them. The invalid-inner-signature variant illustrates
that outer attestation cannot establish original signature validity.

raw-cases/ contains handcrafted original bytes, including duplicates, private
serde names, malformed Unicode/UTF-8, exact integers, legacy numbers, D64/D65,
total-depth64/65 and small very-deep/large-second-value representatives. Its index
states intended FUTURE contracts and parser_executed=false. No new parser runs
against it here. Large size/count boundaries must be generated in later verifier
tests; no tens-of-MiB checked-in bulk. The literal legacy numeric canonical
golden is checked using the unchanged canonical helper; private-name objects are
literal byte oracles, never passed through a map-deserializer that could collapse
their meaning. Parser choice amendment does not change these wire/hash contracts.
numeric-records/ adds separately signed Commit/Fact canonical oracles with exact
large headers and legacy finite floats/signed integers. They are not in the fixed
baseline graph and are not semantically admitted facts or checkpoint candidates.

## Reproduction and checks (isolated VM only)

The ONLY temporary driver addition to each owned source export is
rust/examples/checkpoint_fixture.rs (untracked/uncommitted in the VM export):

```rust
#[path = "../tests/common/team_checkpoint.rs"]
mod fixture;
fn main() -> fixture::FixtureResult<()> {
    let args: Vec<String> = std::env::args().collect();
    let root = std::path::Path::new(&args[2]);
    match args[1].as_str() {
        "generate" => fixture::generate(root),
        "validate" => fixture::validate(root),
        _ => Err("expected generate or validate".into()),
    }
}
```

Use the original product package/lock, never a separately resolved path package.
Copy ONLY product-lock registry packages and cached public index into an owned
Cargo home; no credentials/config. Exact shell orchestration is in external
evidence. VM command settings:

```sh
export CARGO_HOME=/home/parity/jobs/m2a-fixtures-sol-20261107/cargo-home
export CARGO_TARGET_DIR=/home/parity/jobs/m2a-fixtures-sol-20261107/target
export TMPDIR=/home/parity/jobs/m2a-fixtures-sol-20261107/tmp
export CARGO_BUILD_JOBS=1 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true
cargo run --offline --locked --manifest-path rust/Cargo.toml --example checkpoint_fixture -- generate rust/tests/fixtures/team_checkpoint_v1
cargo run --offline --locked --manifest-path rust/Cargo.toml --example checkpoint_fixture -- validate rust/tests/fixtures/team_checkpoint_v1
cargo test --offline --locked --manifest-path rust/Cargo.toml --example checkpoint_fixture
```

The helper validates stored literal expectations independently of generation:
device bindings, all baseline original signatures, manifest signature, original
Commit/Fact canonical/hash equality, exact raw spans/chunks/lengths/hashes,
counts/sets/vector/heads/source wraps, both ciphertexts and all three wraps via
existing readers, and exact candidate schema/metadata. A clean temporary output
is regenerated and compared byte-for-byte. A separate Python standard-library
inspection independently checks raw hashes/partition/canonical ASCII bytes and
literal candidate mapping without invoking the Rust builder or any M2 verifier.
Generation/validation/reproduction command results are reported in external logs.

No rust/verify.sh full matrix, native macOS, M1 admission, M2 implementation,
Opus review, physical two-Mac, OCI/capacity or release acceptance is claimed.
All original M2-G01 through M2-G10 remain OPEN: actual M1; retained signatures/
authority/fact/removal semantics; compaction/head evidence; required generations;
durable two-sided approvals/session/raw frames/budgets and renewal/receipt query;
finalize; coherent durable epoch import; committed provenance/ACK; full acceptance.
Snapshot onboarding remains unsupported. No original Opus finding IDs were
supplied for this fixture task. Old fixtures, source, lock and features are frozen.
