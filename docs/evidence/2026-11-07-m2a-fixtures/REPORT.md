# Bounded checkpoint-v1 fixture completion

Actual implementation model: **gpt-6.1-sol**, reasoning **ultra**, T3 Code through
Codex harness. No further model revision, temperature or sampling settings were
exposed. This session performed the work itself; no child agent/provider, Opus,
cloud implementation task or native Mac/M1 runner was invoked.

Committed locally: `c38523ad7321270521745a0112dc90743beb0371`.
Root tree: `997aa6d590aa14d809523a1ee134cc0f79d49c79`.
Rust tree: `9982d235d7b464edf7a520c450f1db4c33ad86d0`.
Base: `ce796bdcf5069af8e6cd85ab3c953cc22e1bf1a4`.
Base root tree: `4eb93934bb46099bd1ceba2aaf5ff8ad4265a910`.
Base Rust tree: `2882ba592e2204eb62723d95e240525e75196f64` (exact requested product).
Branch: `t3/team-checkpoint-fixtures`; final checkout clean.
No push, PR, merge, deploy, permission or runtime modification.

Governing narrow task SHA-256:
`8f89a1caa07c5c54afb24bcf14193889dd9d6fda241b98d532fc181b85e33272`.
Original decision SHA-256:
`564bcf4c312b04507e815e35cc8eed9f5c6ae8f74ee539ccecf88cff8f0595b2`.
Future wider implementation-task SHA-256:
`3d6520c88fb88558ead2ee380bc322ae897de9c4bb5b67c6d60e37b184e2a58f`.
Complete prescribed project docs and original decision were read in this checkout.
No independent M1 tree was inspected. The parallel parser-choice amendment is not
needed for this fixture-only task; wire/hash/seed/graph contracts remain frozen.
No `raw_value`, dependency, lock or production source change.

## Delivered files and bindings

147 added tracked files, restricted to the two authorized paths:

- `rust/tests/common/team_checkpoint.rs`: test-only generator/support, 1,658 lines.
  SHA-256 `d284a641ab430ee5744c1e114fc760e15c8d62b83b29b08406f358536515615d`.
- `rust/tests/fixtures/team_checkpoint_v1/`: 146 files, 368,308 total bytes.
  Five complete manifest/payload/six-component/chunk/candidate/expected packages,
  original signed/unsigned six-commit history, standalone numeric Commit/Fact
  goldens, README, 40 handcrafted raw inputs/index and SHA256SUMS.
- `SHA256SUMS` SHA-256:
  `a5981856f26e687352a97836372816eaba0f98c285f8a8a41645678c8f8ebc88`.
  It binds every fixture file except itself, including README/raw inputs.

| Package | Raw payload bytes | Counts devices/commits/facts/versions/wraps | Signed canonical manifest hash |
| --- | ---: | --- | --- |
| baseline | 8502 | 3/5/0/2/1 | c0f1ae45ebe4b3bfe033a66c946d02edf562a14b167d01c6b990e093b1b96ddb |
| deleted-empty | 9038 | 3/5/1/2/1 | d64f6fce32b7a2d07a84f02a0b44d050ec35d991115b8da2bd013c0fb9a80410 |
| deleted-retained | 9040 | 3/5/1/2/1 | 699a41cbee5527e8465f1ecd30657cd1d5180cc104c9e2ecd288d9bd18439412 |
| changed-final-digest | 8502 | 3/5/0/2/1 | 9c1869522eaef6ae7b793a5de21f17bbb17a50c84fe990bbaf07703283739e93 |
| invalid-inner-signature | 8502 | 3/5/0/2/1 | ade85b0c7cad22ef2decb26975c7a4c309ddcc18797c2a221cb9db465baa2696 |

Every package has one exact consecutive chunk. O/A/R fingerprints are
`copdsqhgjnkjc4rardm2bv2bmi` / `gr2q7gf5lh6pzfdnurnkvputhm` /
`ni4ahvpqlgicuhdnv66jxjdssi`. O3 is absent from retained payloads, present only in
original-history generation evidence. Vector is O4/A2/R0; heads O4/A2; retained
whole commits O1/O2/O4/A1/A2, authority O1/O2/A1; recipient admission/wrap A1 op0.
V1 remains staged and V2 active, original version-order array [V1,V2]. The pure
six-commit no-fact fold applies all six operations with zero skips. With no facts
or removals the final empty overlay leaves the unflushed document unchanged.
No operation/field/seed/ID/time was changed to make this fold pass.

Deletion variants sign original Fact canonical bytes using existing Ed25519 in
test-only code. They do not call a permissive M1 admission adapter. deleted-empty
has no corresponding secret/version entry, deleted-retained preserves both
ciphertexts, and each declares its exact nonempty signed-fact hash set/digest.
All variant final-overlay claims remain explicitly unverified. The changed-final
claim is deliberately false; invalid-inner-signature has exactly one invalid
original commit signature despite coherent outer attestation. These are only
inert candidate goldens; no new M2 parser was tested and no admission is claimed.

## Isolated execution and declared additions

All product/dependency/generator/test/crypto execution occurred as unprivileged
parity in credential-free Lima `zeropw-parity`, owned job
`/home/parity/jobs/m2a-fixtures-sol-20261107`. Only the authorized trusted
`/Users/ys/Code/zeropw-mlp-tools/vmrun.sh` exported source; no mounts/agent
forwarding. The source/job process starts with `env -i` and the explicit HOME/PATH
in the launch command below. No credentials were read/requested; no production
endpoints used. Metadata checks verified no SSH_AUTH_SOCK, ~/.ssh or private
Cargo credentials. Mount inspection found no source/host mount. The own Cargo home
contains only public cached index plus 172 lock-pinned registry package archives,
whose SHA-256 equals the unchanged lock checksums. Source unpacking and compilation
stay private. Original lock `fb0dbbf2a2b25c111a419f3b2102d51d2859a1745e28afca9b8d59339340d840`,
Cargo.toml `4ae4261cf2bdc9e9a7099eb9a0c898282997115d17da01a7953c75bba6c9a1a6`.
The active feature tree uses product serde_json 1.0.151 without raw_value; there is
no external path-dependent package, separately resolved lock or dependency drift.

Linux aarch64 kernel 6.8.0-147-generic, rustc 1.98.1 (48a229cea 2026-09-01),
cargo 1.98.1 (797e8a9bc 2026-08-05). CARGO_BUILD_JOBS=1, both dev/test debug=0,
incremental=0, offline=true, locked=true. Private own target, Cargo home and
umask-077 TMPDIR: job/target, job/cargo-home, job/tmp. Final usage 463 MiB target +
164 MiB Cargo home; filesystem still had 3.3 GiB free. No other caches/exports or
M1 runner were modified/deleted; no ENOSPC.

Exactly ONE temporary source addition in each owned export:
`rust/examples/checkpoint_fixture.rs`, SHA-256
`89b416be8b547a6843fd9bb15e16f30d3085142e752d6437e07f906b63a48d04`.
Its exact code is `fixture-driver.rs` and the tracked fixture README. It is never
committed or copied into product source. Before/with/after driver SHA manifests
record it; a metadata comparison verified this is the only added export file.
Orchestration scripts (`job-script.sh`, `final-script.sh`, trusted helper `run.sh`),
independent_check.py, metadata manifests and evidence live OUTSIDE src in the own
VM job. Their complete authored source is retained beside this report. No hidden
fixture driver/feature/lock change is omitted from the source manifests.

Host activity was data-only source/document reading/editing, metadata hashing,
tar export/import and the authorized local Git commit; no submitted code, crypto,
product, dependency or generator was executed on the host.

## Commands, exits and final source binding

The exact generation and final-validation shell scripts are `vm-generate.sh` and
`vm-final-validate.sh`. Their environment and every command/exit appear in
`generation-02.log` and `final-validation.log`; both completed exit **0**. Launch:

```sh
script_b64=$(base64 < EVIDENCE/vm-final-validate.sh | tr -d '\n')
VMRUN_JOBS=1 /Users/ys/Code/zeropw-mlp-tools/vmrun.sh /Users/ys/.t3/worktrees/zeropw/t3-0d4c5eb4 m2a-fixtures-sol-20261107 env -i HOME=/home/parity PATH=/home/parity/.cargo/bin:/usr/local/bin:/usr/bin:/bin bash -c "printf %s $script_b64 | base64 -d > /home/parity/jobs/m2a-fixtures-sol-20261107/final-script.sh; exec bash /home/parity/jobs/m2a-fixtures-sol-20261107/final-script.sh"
```

EVIDENCE denotes this report's absolute containing directory. Python checker and
frozen-byte manifest were streamed as data to the own VM job before launch.
The initial generation used the same invocation with vm-generate.sh/job-script.sh.
All final focused commands below exited 0, without overwriting exported goldens:

```sh
rustfmt --check --edition 2024 rust/tests/common/team_checkpoint.rs
cargo run --offline --locked --manifest-path rust/Cargo.toml --example checkpoint_fixture -- validate rust/tests/fixtures/team_checkpoint_v1
cargo test --offline --locked --manifest-path rust/Cargo.toml --example checkpoint_fixture
cargo clippy --offline --locked --manifest-path rust/Cargo.toml --example checkpoint_fixture -- -D warnings
python3 /home/parity/jobs/m2a-fixtures-sol-20261107/independent_check.py rust/tests/fixtures/team_checkpoint_v1
cargo tree --offline --locked --manifest-path rust/Cargo.toml -e features
```

Generation-02 additionally ran `cargo run --offline --locked --manifest-path
rust/Cargo.toml --example checkpoint_fixture -- generate
rust/tests/fixtures/team_checkpoint_v1`, exit0. Final tests: **4 passed, 0 failed**,
including stored crypto/literal expectations, clean temporary regeneration with
byte-for-byte whole-file-set equality, explicit variant snapshot preservation and
a corruption check. Independent stdlib inspection passed five packages,146 files,
40 raw cases. Rust checked device bindings, all six baseline original signatures,
expected invalid O4 signature, Fact/Commit canonical+hash equality (including exact
huge headers/legacy finite numeric records), all three DEK wraps and both secret
ciphertexts through existing readers, manifest signatures, raw span/chunk hashes,
sets/vector/heads/counts and candidate schema/metadata. No new M2 implementation
under test derived the expectations. Python independently used hashlib/base64/json
against trusted canonical generated files; raw-case inputs were checked as bytes
ONLY. No production/private-name/depth parser PASS is claimed.

The final fresh export first validated frozen literal fixtures, then regenerated
ONLY into private temporary directories in the tests. Before/after entire source
SHA manifests compare equal (exit0), including driver and every fixture.
Final helper and SHA256SUMS hashes match the committed files. `final-export/`
contains source/pin/driver/feature manifests; `run-02/` contains generation inputs.
The local commit used `git -c core.hooksPath=/dev/null -c commit.gpgSign=false
commit --quiet -m "test: add deterministic checkpoint v1 fixture goldens"`, exit0;
no host hooks or signing-key access. `head.txt` binds exact committed trees.
`git diff --check base HEAD` passed; final Git status empty.

Historical failed metadata-only probe as default Lima user lacked access to
parity's registry/toolchain; corrected to sudo-u-parity without inspecting keys.
Intermediate generation-01 log is retained, but its host wrapper used zsh's
read-only `status` variable and exited1 before capturing VM exit. That run reached
its terminal disk report; no exact VM exit was separately captured and it is NOT
the final source-bound test evidence. Generation-02/final logs have explicit
COMMAND_EXIT and VM_SCRIPT_EXIT=0 markers and saved .exit files. No failure was
rewritten or used as a PASS.

## Unchanged-source proof and remaining limits

`frozen-tracked-bytes.json` binds all **652 original tracked files**. Final VM and
postcommit host metadata checks show all bytes unchanged. Original Rust and old
fixture blob/mode/stage/file-set manifests compare identical:

- before-rust-git-files.txt == after-rust-original-git-files.txt, SHA-256
  `ed5cd55fd46ca608f0af8a86029801c6083c94f3e4adaebb2c08bd762235544a`.
- before-old-fixtures.txt == after-old-fixtures.txt, SHA-256
  `6a6e026a2e0c30a012430ed34e09dd13ade61a40f36adcb60a88bf00ddc0db5a`.

`committed-paths.txt` has only147 authorized additions. A Git comparison of all
other paths against ce796bd was empty, exit0: production Rust, old fixtures and
GENERATEs, canonical helpers, Cargo pins/features/lock, docs/harness/CI and M1
runtime paths remain byte/mode identical. This data-only slice introduces no
runtime capability, admission/install/status or production parser/verifier.

No API/schema blocker occurred for the narrow fixture generator. The pre-M1
secret_deleted authoring limitation is handled ONLY by the explicitly authorized
Fact-canonical/Ed25519 test construction, never a product bypass. The original
raw_value legacy-compatibility blocker remains a parser-task dependency; it was
not enabled, bypassed or claimed resolved here.

**NOT RUN / NOT CLAIMED:** unchanged full rust/verify.sh Linux or macOS matrix,
native/physical two-Mac, M1 admission/overlay, M2 semantic/runtime implementation,
Opus review, OCI/capacity, deployment or release acceptance. Existing unrelated
Linux grant-expiry failure and macOS ACL/review/release gaps are not closed. The
prior E2E report was one scan covering seven secrets, not seven separate scans;
none was rerun as this task. No actual Opus finding IDs supplied or fabricated.

All original planning gates remain OPEN with their original meaning: M2-G01
actual M1; G02 original signatures/authority/schema semantics; G03 historical
facts/removals/final fold; G04 proof-preserving compaction/continuation; G05 required
generations/wrap usability; G06 durable two-sided approval, live session/raw frames,
budgets and renewal/receipt-query binding; G07 fresh finalize/READY; G08 coherent
durable epoch/import recovery and credential-use barrier; G09 committed provenance
before receipts/ACK; G10 full repeated-compaction/continuation/crash/network/native
acceptance and actual final-head Opus review. Snapshot onboarding unsupported.
