# Bounded M2a implementation report

Bounded implementation and required isolated Linux verification are complete at the exact head below. This is not full M2, native-platform, Opus or release acceptance. Snapshot onboarding remains unsupported.

## Source, author and inputs

Actual implementation model: **gpt-6.1-sol**, **ultra** reasoning, Codex harness in T3 Code. No additional model revision, temperature or sampling settings exposed. No subagents or Opus invocation. This is implementation and isolated testing, not an Opus review or an always-on cloud coordinator.

Prepared base `21ed45c9ea1814b40d91b7d994fb075152852571`, initial Rust tree `2882ba592e2204eb62723d95e240525e75196f64`.

Final source head `7bcecfda8571ae40047fae406915f73d2e25bde0`, Rust tree `24fceecbec4b559aa8d1e31331ef5be0033ca2fa`. Local commits: collected fixture cherry-pick `e781a21074f64bf610a34f01035f613df9e19f76`; parser feasibility `43723aecad3c1f3fca471d155ed5418b9f784329`; bounded library `1aa5525e6166b99c0465eb888e9de947bac89433`; early metadata type refusal and permanent cap-sized wide test `7bcecfda8571ae40047fae406915f73d2e25bde0`. No push, PR, merge, deployment, permission or coordinator-runtime changes. The separate M1/UI heads were neither integrated nor inspected; reconciliation remains the coordinator's work.

Input SHA256 values:

- Prompt `/tmp/zeropw-m2a-feature-neutral-sol-task.md`: `59aede42ca50af3546854e5b98dc1598281e04f651395b00f15fd4fd12aff081`.
- Original decision: `564bcf4c312b04507e815e35cc8eed9f5c6ae8f74ee539ccecf88cff8f0595b2`.
- Original implementation task: `3d6520c88fb88558ead2ee380bc322ae897de9c4bb5b67c6d60e37b184e2a58f`.
- Revised implementation task: `27a49588eab8553bf81cef67547b6e9d581ee991dc9cd10fae2a4d92268db395`.
- Parser amendment: `0ce1fabf72cb7c116a422dd5fc521383174c55a38145c2aff1ab07e8df5cf370`.
- Complete 36-input comparison: `3189549cd2b66eafe52f84340a396336b7cc1a5451b5556f9f334794f68460d9`.
- Actual prepared README: `945b670daccd36cf9da8508e4802c9c6ec85f3128623589ee7ea3123ff8c7d55`; the amendment's d338... refers to its earlier README. Current additions are coordinator provenance/pointers, not a wire change.

`protected-source-sha256.txt` records every prescribed input, canonical helper, Cargo pin and guard hash. `milestones-pointer-only.diff` proves the accepted M2 blob `938a4213f23855c727c9b18dd3cf4d8a97340200` differs only by the supplied M2a pointer paragraph. Nothing in its full M2 contract was rewritten.

## Changed files and implemented boundary

New product files: `rust/src/team/checkpoint/{mod.rs,strict_json.rs,manifest.rs,payload.rs,provenance.rs}`. The only change to an existing product file is one `pub mod checkpoint;` line in `rust/src/team/mod.rs`.

New integration targets: `rust/tests/team_checkpoint_{legacy_parser_regression,manifest,payload,provenance}.rs`. The committed frozen helper/package is identified separately below. `changed-files.txt` is the exact complete path inventory.

The parser uses a fixed-depth iterative framing preflight, an original-byte cursor and public typed `DeserializeSeed`/map/sequence APIs. It never deserializes an input container through Value or whole-object pyjson. Key seeds compare independently decoded strings; duplicate refusal precedes requesting a value seed. A test-only instance-local callback panics if a duplicate value decoder is entered. Array quotas run before child framing/materialization. Projected metadata strings and string-array elements reject containers during validation, before their descendants can be decoded or projected; an instance-local hook proves this timing. Some/None disagreement is tested in both directions; punctuation, grammar, final exhaustion, Unicode, literal private names, numeric source spelling and total-depth spans are checked. Component ranges originate only from successful traversal of their immutable source. Their ancestor depth is retained during later individual materialization.

A validation/index pass traverses every legacy child and accumulates combined counts before projected metadata construction. Snapshot encrypted trees, original version-order arrays, record bodies and wrap entries are not retained as a whole payload Value. The second pass builds only bounded/schema metadata; individual Commit/Fact envelopes and referenced wrap entries are then materialized separately. Record subranges are disjoint; no per-record ancestor/payload rescan is used. Original wrap selectors are indexed once per retained commit. Existing helpers may copy an individual record internally; the slice retains no full payload clone or whole-payload token tree.

The public APIs enforce closed manifest/chunk/payload metadata schemas, independently supplied pinned/full peer-record equality, approval/request/session bindings, exact UInt headers, supplied wall freshness, existing Ed25519 canonical manifest signatures and signed deterministic chunk partitions. Whole/chunk raw checks precede JSON work; component hashes cover precisely original `data` tokens. Device self-signatures, canonical Commit/Fact equality/hash identity, exact heads/vector/HLC, sorted/distinct declarations, all count keys, removals, and original wrap selectors are checked independently of the frozen helper.

Candidate output is exactly `administrator_attested` / `integrity_checked_not_admitted`, privately paired to the manifest hash and carrying every individual fact candidate binding. It has no deserializer, authority conversion, install action or receipt. Compile-fail documentation checks private construction, deserialization and attempted install/fact conversion. Errors and result Debug are redacted. No production runtime caller or filesystem/network/KMS/private-key authority was added.

## Isolation, toolchain and commands

Every product/dependency/fixture/formatter/build/test execution used the owned credential-free Lima `zeropw-parity` export `/home/parity/jobs/m2a-neutral-fd2a1b1c/src`. Own target `/home/parity/jobs/m2a-neutral-fd2a1b1c/target`; own Cargo home with symlinks only to the public registry cache/source/index; no config or credentials copied. Clean `env -i`; `CARGO_NET_OFFLINE=true`, `CARGO_BUILD_JOBS=1`, `CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_PROFILE_TEST_DEBUG=0`, `CARGO_INCREMENTAL=0`. Private 57-ASCII-character TMPDIR `/tmp/m2a-fd2a1b1c-000000000000000000000000000000000000000`.

Toolchain: rustc `1.98.1 (48a229cea 2026-09-01)`, cargo `1.98.1 (797e8a9bc 2026-08-05)`, Linux aarch64 kernel `6.8.0-147-generic`. Initial free disk 3.3 GiB; this worker deleted or changed no other job/cache/old fixture. During validation, the coordinator separately reported reclaiming ONLY the completed old M1 target after preserving five normal binaries and checking no matching process, free space1.59GB->23.30GB; attributed record `/Users/ys/Code/zeropw-mlp-evidence/completed-m1-cache-reclaim-20261107T0832.json`. It states this worker's files/processes/caches were untouched. No M1 state was inspected here. No ENOSPC occurred. No dependency provisioning or lock regeneration was needed.

`registry-check.py` executed in this job verifies lock archive SHA256 and every archived source file: serde_json 1.0.151, 89 files, checksum `c841b55ecdae098c80dcae9cf767f6f8a0c2cdb3416bbef72181df4d0fe73f14`; serde 1.0.229, 33 files, `4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba`; serde_core 1.0.229, 27 files, `67dca2c9c51e58a4791a4b1ed58308b39c64224d349a935ab5039aa360942a48`.

The additional isolated `registry-check-all.py` check matched all172 locked registry-package archives and all8,194 archived source files, with no missing package/source. `registry-all-packages.json` records each exact pin/checksum and count. Cache availability/source identity is not native-platform compilation or execution.

Exact Cargo commands (all from isolated export root, with settings above):

```sh
cargo tree --locked --offline --manifest-path rust/Cargo.toml -e features -i serde_json
cargo tree --locked --offline --manifest-path rust/Cargo.toml --target all -e features -i serde_json
cargo tree --locked --offline --manifest-path rust/Cargo.toml --target all -e features
cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_legacy_parser_regression
cargo test --locked --offline --manifest-path rust/Cargo.toml --lib team::checkpoint::strict_json -- --nocapture --test-threads=1
cargo test --locked --offline --release --manifest-path rust/Cargo.toml --lib team::checkpoint::strict_json -- --nocapture --test-threads=1
cargo test --locked --offline --manifest-path rust/Cargo.toml --lib team::checkpoint -- --nocapture --test-threads=1
cargo test --locked --offline --manifest-path rust/Cargo.toml --test canonical_helpers --test team_checkpoint_manifest --test team_checkpoint_payload --test team_checkpoint_provenance --test team_checkpoint_legacy_parser_regression -- --test-threads=1
cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_payload -- --test-threads=1
cargo clippy --locked --offline --manifest-path rust/Cargo.toml --all-targets -- -D warnings
cargo test --locked --offline --release --manifest-path rust/Cargo.toml --test team_checkpoint_payload full_verifier_total_depth_64_65_and_post_parse_helpers_on_256_kib_stack -- --nocapture --test-threads=1
bash rust/verify.sh
```

`final-validation.sh` is the exact final script, with individual release-parser, release-payload-stack and complete unchanged verifier exit statuses. `final-validation.log` retains all per-target results. The verifier is unchanged and discovers every integration target, strict Clippy, lib/bins, ignored signer probes and docs. No target was removed, filtered or skipped in that full-matrix command. The release payload command intentionally selects the small-stack obligation; it is not a full release integration-matrix claim.

Final commands/exits: release parser0 (12 tests); release public payload depth/stack0 (1 selected test); unchanged full Linux `bash rust/verify.sh`0, **104 steps / 1,681 tests passed / zero failures**, including all99 integration targets, four signer probes and ten doc tests. Four probes are ignored in the ordinary library phase and all four are then actually executed/passed by the unchanged signer-probes step. `final-validation-summary.json` contains every per-step exit and result line. `git diff --check`, protected-path comparison, and frozen-package comparison exit0; prepared checkout is clean.

Exact primary evidence SHA256 values:

```text
bc3ce91a59eea59ee1834229aed117d93ae562090e71cd5235c66b953593e638  final-validation.log
373a17f1a667bf422c9f8fab12b1c58830bd64e1e9105173d9561a923dd7fda2  final-validation-summary.json
26d39d99d9a7c0fad35d5b0b28013efa8f4412a4e614dffde66218975c73b419  metadata-early-refusal-debug.log
f9ef80ce4733b15f482b50202153fa404d4e01db0477a8afb6b30f06d23f7a75  parser-gates-debug-attempt2.log
71e1f91c71488b76025c0a1f149dfdd318e150a41c559a8651972f1924921a1e  parser-gates-release-attempt1.log
e10d047e29dbf5d6e98d1229596ece68797117eb8e07f31187ba4ece34ccc447  final-source-7bcecfd.tgz
19050604065a11e8bd860512b0e1ebf135eaa5eb648b8d606b484b1a17076357  implementation-only.patch
7927464c1dde342b1c8cecb3b802b8a0801da1d2c58a82a3f5bd01283be52bfa  final-7bcecfd.patch
5a3091d1cd5278ac454da8cb3fbd0dead6ab263e77e17ebd3778ec18efc4108e  final-all-git-blobs.txt
```

`final-binary-sha256.txt` records the final debug/release library-test binaries and all four new integration binaries. `SHA256SUMS.evidence` inventories all task evidence except itself. Before and after final verification, all810 source blobs and modes match7bcecfd. Final fixture inventory remains145/145 matching; serde/serde_core/serde_json source/archive validation repeats successfully afterward.

`final-all-git-blobs.txt`, `final-source-7bcecfd.tgz`, `final-7bcecfd.patch`, `implementation-only.patch` (relative to collected fixture parent) and the before/after blob checks bind execution to the final committed source. Before validation, all **810** tracked source entries matched Git blobs and executable/symlink modes. The earlier scoped source check covered609 entries. The export contains no .git directory; HEAD/tree were recorded from the prepared host checkout and byte/mode equality checked inside the isolated worker. The earlier `1aa5525` source/patch/matrix remain separately archived under their actual head, never substituted for final-head validation.

## Gate status and resource evidence

PC-R1: PASS at parser gate. Full original product lock/manifest/helper hashes unchanged; public APIs compile; retained features arbitrary_precision/preserve_order/unbounded_depth/defaults. Inverse host/all-target graphs and complete all-target feature graph have no raw_value. Complete final graph equals the gate graph byte-for-byte. Test/build and target resolution are included; macOS compilation/execution is NOT RUN.

PC-R2: PASS. All **36** original input strings reproduce **both complete baseline legacy outcomes** (72 comparisons), including errors, category/line/column/message, Value kind, debug, stored serialization and canonical fields. Separately all 36 new-parser object-preserving oracles pass; literal reserved objects survive Commit op / Fact target / snapshot legacy fields, with original canonical/hash equality. Expected canonical literals/manual materialization are independent of whole-object old loading and the parser under test.

PC-R3: PASS at parser gate, repeated after schema/index changes in debug. Covers punctuation/Some/None/exhaustion, deterministic ordinary-grammar insertion/replacement/deletion mutations, Unicode/UTF-8/surrogates, duplicates before child decode, literal span offsets, exterior/interior hash scopes, data-before-name role routing, UInt original tokens, 256/257 actual device/chunk containers and 65,536/65,537 record/cross-component guards. Private quota tests use minimal syntactic children where full canonical records cannot fit; they do not claim simultaneous maximum valid-wire capacity. Public tests separately exercise schemas/count/reference failure after re-attesting outer claims.

PC-R4: PASS at parser gate in debug/release and repeated at corrected final head. All12 final parser tests pass in both profiles; final public depth/stack test also passes in release. Tests request 256 KiB threads for D64, alternating escaped-key containers, deepest scalar conversion, post-traversal canonical/hash/equality, partial/completed drop and near-limit duplicate/malformed errors; D65 and very deep framing refuse before recursive traversal. Full public verification/candidate construction at total wrapper depth64, with depth65 refusal, is separately tested in debug and selected in release. No production stack changes, parsing thread workaround, unsafe code, new dependency or helper rewrite.

Maximum raw payload exercised: 16,777,216 bytes with independently re-attested raw/chunk bindings; one over refused. Maximum individual chunk 65,536; frame boundary 131,072; manifest boundary65,536. These are separate thresholds, not a combined capacity assertion.

Wide-input measurement is now a permanent normal unit test: **16,777,216 raw bytes / 1,370,000 actual distinct opaque entries**, including permitted trailing whitespace to reach the exact cap. Corrected-head debug run:4,306 ms, process VmHWM/VmRSS134,656 KiB. Corrected-head release run:1,094 ms, process VmHWM/VmRSS130,436 KiB. Test State600 bytes, heap Frame168 bytes, maximum two live frames in this wide test. Process RSS includes input generation, the allocator and test process; it is not exact per-transfer allocation. Decoded-key-set overhead can greatly exceed input size. Debug numeric tokens10,000/100,000 digits took3/138 ms; release took0/8 ms (millisecond granularity, zero means below1 ms). The earlier2,288,891-byte/200,000-entry measurements (including `/usr/bin/time -v` maxRSS28,980 KiB) remain under their original source/log bindings. No temporary diagnostic source variant was executed; the full-cap case is in the committed normal suite. Existing BigInt/canonical algorithms remain unchanged; no new latency/memory capacity guarantee follows.

PC-R5 required Linux/fixture portion: PASS. Corrected-head focused tests PASS:12 private parser,10 manifest/fixture-consistency,13 payload,4 provenance,1 full36-input legacy regression,4 canonical-helper guards. Final corrected-head matrix passes104 steps /1,681 tests, including all99 integration targets, four signer probes and ten doc tests. The earlier1aa5525 complete matrix passed104 steps/1,680 tests and remains separately archived. A resource-boundary check subsequently found that projected metadata string fields could reach projection with container values before eventual refusal;7bcecfd rejects those types before child decoding and includes the cap-wide measurement in CI. No extra review model was invoked. Native macOS and actual final-head Opus review remain NOT RUN and required separately; no full M2 or release acceptance.

## Frozen fixtures and protected inputs

Coordinator-supplied original fixture commit `c38523ad7321270521745a0112dc90743beb0371` (coordinator mapping `ac7a00cacf3415aa3f90ae176e65ec2c706d8a10`), tested fixture Rust tree `9982d235d7b464edf7a520c450f1db4c33ad86d0`. Local cherry-pick has that exact tree before parser changes. Frozen helper SHA256 `d284a641ab430ee5744c1e114fc760e15c8d62b83b29b08406f358536515615d`; SHA256SUMS file `a5981856f26e687352a97836372816eaba0f98c285f8a8a41645678c8f8ebc88`; all145 listed entries verified. All baseline/variant/canonical/raw bytes remain unchanged. In-memory negative tests and mutations live in the new tests, without adding or rewriting baseline golden files.

The supplied internal Sol static fixture audit hash `6f6afa2d52214f140117f6518605735f9310f646d261f4b519866cc62ff98def` is coordinator-attributed context, not an Opus finding or an audit performed here. Its three LOW helper-coverage observations (zip lengths, ordering/distinctness and schema closure) did not authorize helper changes. Production checks independently enforce exact counts, strict sets and closed schemas, with re-attested negatives. The frozen helper is used only for fixture consistency/independent baseline crypto/regeneration tests, not as the production oracle.

Base has654 tracked entries. Only one pre-existing file changed: team/mod.rs with one declaration. Every other pre-existing blob/mode is unchanged, including prototype fixtures/GENERATE, canonical/numeric/base64/crypto/Commit/Fact helpers, all runtime/M1 paths, Cargo files, guards/allowlists, CI, harness, verifier and governing/archive documents. Total final810 entries consist of147 fixture/helper additions and9 new implementation/test files, plus that one allowed existing-file edit.

## Failed attempts and exact limits

- Historical raw_value experiment is preserved as data: first missing vendor-only checksum-file preflight and then rejected manually seeded minimal-lock preflight ran no probe. Six later exit0 commands meant execution, not compatibility:12/36 inputs changed in both old paths;24 unchanged. Its equivalent1.0.3/syn3.0.9/unicode-ident1.0.27 differed from product1.0.2/3.0.5/1.0.24. This implementation neither enables that feature nor regenerates a minimal lock.
- `parser-gates-debug-attempt1.log`: exit101,7 passed/2 failed. Incorrect literal complex-span oracle23..83 was corrected to independently counted24..73 (`independent-span-count.log`). Raw Value equality across canonical1e0->1.0 was replaced with the required canonical-byte equality. No legacy behavior changed. Exact failure input/assertions are in the log and tool transcript; `parser-first.rs` retains the initial minimal parser. The complete archive of gate attempt2/release attempt1 is `parser-gate-source.tgz`; it is not misrepresented as a byte archive of failed expanded attempt1.
- Two initial readback commands returned permission denied (exit1); readback was repeated as the job owner. Final810-blob/mode validation proves restored source equality. No product ran on the host.
- `slice-first-debug.log`: exit101, four compile errors from DeviceRecord fingerprint's actual String return type and strict-base64's Result return type. Corrected only in new files; old APIs unchanged.
- `clippy-attempt1.log`: exit101, collapsible-if/extra frame Box diagnostics; frames remain heap-backed via Vec and success/error/drop paths rerun. `clippy-attempt2.log`: exit101, a no-effect replacement in a quota test. Removed without altering the actual overflow mutation. `clippy-attempt3.log`: exit0.
- `slice-focused-attempt1.log`: exit0 for11 library tests but a shared name filter selected ZERO payload/provenance integration tests. That command is not counted as integration validation. `slice-focused-attempt2.log` runs them unfiltered; later complete focused runs cover final additions.
- No ENOSPC, cache miss, package update, lock generation, native Mac access, M1 rebase, runtime support/admission/install, production keys/endpoints, push/PR/merge/deploy or Opus invocation. No actual M2a Opus IDs were supplied or invented.
- The known historical Linux grant-expiry failure and ten diagnostic passes do not establish a cause. Neither complete1aa5525 nor corrected7bcecfd full matrix reproduced it; its historical cause remains unresolved. No old product test/code was changed, skipped, weakened or rerun to manufacture a PASS.

## All full-M2 gates remain OPEN

The following retains decision section11 in full. None is closed by a manifest signature, integrity candidate, passing local tests or the separately completed M1 source.

| ID | Required before full M2 can be supported |
| --- | --- |
| M2-G01 | Actual M1 exact-head integration: admitted original tombstone facts, complete monotone set/shared digest, historical target/authority rules and durable session ACK; no empty shim or filtered unknown facts |
| M2-G02 | All original commit/fact signatures, schemas and targets; genesis owner/key/signature; retained authority replay in existing total order, including owner transfer, prior demotion/removal, no skipped operations, exact recipient role and active admin signer; full device-copy consistency |
| M2-G03 | Every historical fact admission basis and irreversible effect; attested admission only where permitted, reject retained contradictory proof; complete removal witnesses, bounds and placement; recompute final fold/digest and preserve every original fact/tombstone |
| M2-G04 | Future compaction retains heads/removal witnesses; legacy missing proof explicitly unsupported; continuation uses exact sequence/HLC floors and fails team_checkpoint_history_required for unavailable precut reconciliation without allowing deleted credentials |
| M2-G05 | Required DEK generations and valid recipient original wraps; currently usable credentials with missing generations fail; no KMS/derive work until semantic verification |
| M2-G06 | Real persisted two-sided human approvals, exactly-once invitation/admission authorization, fresh-session feature gate, original-byte transport seam, all budgets/timeouts/cancel/resume rules; no cross-session partial-byte resume |
| M2-G07 | Fresh finalize challenge and separately domain-signed READY (zeropw-team-bootstrap-ready-v1), same live session; lock/recheck entire cut, approval, signer/recipient and known revocation; restart on changed cut |
| M2-G08 | Fresh-environment/collision eligibility; journal, recovery, fsync and durable completed import record; coherent committed epoch at reads and credential use, including cached contexts and already-running gateway/signer; no unlocked flag/read race or per-file atomicity claim |
| M2-G09 | Provenance durably committed before any receiver local receipt, ACK, joined/readiness or activation; subsequent restart/compaction retains provenance and M1 facts; old-binary downgrade remains unsupported for new state |
| M2-G10 | Real signed repeated-compaction onboarding, continuation, all M1 cases, crash/disk-full/concurrent-reader tests, direct and forced TURN, isolated Linux/macOS full verification, physical/native two-Mac evidence and actual Opus review of the final implementation head |

Later runtime errors team_bootstrap_authority_unproven, team_bootstrap_existing_state_unsupported and team_checkpoint_history_required remain planning requirements; this slice adds no fake runtime handlers. Monotonic deadlines, queue/process/staging budgets, freshness renewal/receipt query, durable coherent epochs, ACK/READY, required DEK usability, native/physical/IPv6/OCI capacity and release acceptance are not implemented or validated here. Snapshot onboarding remains unsupported.
