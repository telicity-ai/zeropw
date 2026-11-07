# Synthetic retained-authority histories v1

Authored by actual gpt-6.1-sol, ultra reasoning, T3 Code/Codex, 2026-11-07.
Exposed service tier: default. Prepared base 9819c648640f401a54a42970fcb0515ac9654e9a,
Rust tree 54bb9bf3f9dae054fa76c96d3203c427225f3e28. The bounded source and execution
archives are outside the repository under
/Users/ys/Code/zeropw-mlp-evidence/m2b1-authority-20261107/t3-f453296e/.
These are new deterministic Rust fixtures, not Python, M2a, or acceptance oracles.
The frozen team_checkpoint_v1 package and its generator were neither imported
as semantic expectations nor modified.

All keys are PUBLIC SYNTHETIC TEST MATERIAL. O/A/R signing seeds are bytes
00/01/02 repeated 32 times; agreement scalars are 03/04/05 repeated 32 times.
D uses 11/12 and X uses 13/14, respectively. Nothing here is a production key or
product default. The independent local pin for each case is in expected.json;
tests construct it directly from the fixed identity, never from the manifest.

The separate builder is tests/common/team_checkpoint_semantics.rs. It uses
existing signature/canonical/X25519/HKDF/AEAD and ordinary full fold primitives.
Its literal_steps function hand-specifies EVERY op's owner, active admin/member
sets and empty skip table, including mixed-commit positions. A private trace test
compares every position to these literals; complete uncompacted ordinary folds
independently check every complete signed prefix and final projection/order.
The retained-authority candidate is never the expected-result generator.

Generation took place only in the owned credential-free Lima Linux aarch64 job
m2b1-f453296e-20261107-a94c, parity uid 2000, Rust/Cargo 1.98.1, with offline locked
dependencies, one build job, incremental/debug information disabled, ordinary
022 umask, and a private 57-character mode-0700 TMPDIR. The successful expanded
generation command in 08-focused-corrected.log was:

    ZEROPW_GENERATE_SEMANTIC_FIXTURES=tests/fixtures/team_checkpoint_semantics_v1 cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_authority_oracle deterministic_original_histories_and_literal_oracles -- --nocapture

Cargo runs the test from rust/, explaining the relative output path. The initial
05 generation used an extra rust/ prefix; its misplaced transient outputs were
not collected. The corrected 07 run collected the six aggregate files per case;
08 additionally wrote each signed/unsigned canonical original. Failed runs and
their source archives remain separately preserved. Normal tests never rewrite
these files: they independently rebuild the synthetic histories and require
byte-for-byte equality. SHA256SUMS independently inventories every fixture here.

- P1: nonowner admin A pins the cut, R/user, with omitted O:3 and signed O:4/A:2 heads.
- P2: A's two original deletions plus O's distinct same-ID deletion survive A's
  later demotion; O is pinned. No-version deleted-empty still contributes its hash.
- P3: genesis owner O transfers to A; A demotes O. O's original deletion and
  version revocation retain an actual earlier qualifying interval.
- P4: D/admin performs work then commit-only self-removal. A remains pinned and
  D's original deletion retains historical basis. There are no removal facts.
- P5: admin grant followed by data in one signed commit, and data followed by
  self-demotion in another. Literal expectations preserve intra-commit order.
- P6-empty/P6-nonempty: exact M1 empty digest versus all three distinct signed
  tombstones; deterministic input permutations preserve every original hash.

history.canon is COMPLETE uncompacted signed history, including omitted data.
facts.canon and per-record .canon files retain all original signatures/objects.
expected.json includes independently hashed original sets and ordinary fold output;
literal-trace.json contains the separate literal expectations. The independent
canonical sorted original-hash array is compared to the actual M1 digest API.
Manifest/payload component, chunk and record integrity is repaired and signed
for each in-memory inner negative so it reaches its intended boundary. Some
malformed original shapes are already refused by unchanged M2a checks; those
tests explicitly identify that earlier stage.

The snapshot/final digest claims are not a data-stage proof. In the nonempty-fact
cases the stored claim is deliberately the fact-free ordinary document digest;
M2b.1 verifies the authority projection and original fact basis/set only. Tests
separately exercise the actual M1 irreversible overlay on complete histories,
and explicitly allow a coherently false final digest to reach ONLY
retained_authority_checked_not_admitted. Required-generation usability is also
unverified by this stage. Test-only wrap/ciphertext round trips add no production
key-bearing analysis.

A known same-ID original omitted from the unchanged signed set fails integrity.
A coherently reattested omission fails when an independent local known original
or deny restriction contradicts it. Without independent evidence, absence of an
otherwise unknown original is undetectable; the test preserves that limitation.
Completeness and historical admission remain administrator_attested.

No runtime caller, persisted human approval, full overlay, removal-fact scheduling,
compaction/continuation, transport/budgets, READY, journal/import, receipt/ACK/join,
status or credential behavior is established. All M2-G01 through M2-G10 remain
OPEN. Native macOS is NOT RUN unless separately assigned and actually verified;
Linux test results are source-bound evidence, not Opus review or release acceptance.
