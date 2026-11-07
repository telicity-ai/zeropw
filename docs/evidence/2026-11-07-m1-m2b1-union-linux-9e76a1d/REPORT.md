# Linux test evidence for immutable M1 Personal Vault + M2b.1

All required Linux product checks passed on **9e76a1dae165863ad97f5af976d5037c12e4d0e7**. The unchanged Rust matrix completed **107/107 steps, 102 integration targets, 1,737 passed / 0 failed**. The unchanged Desktop matrix completed **8/8 steps, 343 frontend tests across 26 files and 198 core/workspace tests passed / 0 failed**. This is source-bound isolated testing only, not Opus review, finding disposition, Astra acceptance or release validation.

All 12 driver phase commands exited0. The original driver and trusted wrapper completed normally with known **exit1**, solely because the evidence auditor treated **187 declared Desktop generated build files** as unexpected source. Its original source-after result contains **zero changed/missing original files** and is preserved, including traceback. The independent after-run guest archive auditor exited0 and verifies the exact source set/bytes/modes. No product check was rerun for this evidence-only correction.

Actual exposed model/settings: **gpt-6.1-sol, reasoningEffort ultra, serviceTier default, provider instance codex**, T3 Code/Codex harness. No further revision/sampling setting was exposed. `actual-t3-settings-response.json` preserves the direct read-only response; `t3-thread-input.json` and `dispatch.txt` bind the supplied assignment. No subagent, workflow, substitute model or Opus invocation occurred.

The prepared base and final/tested HEAD are both `9e76a1dae165863ad97f5af976d5037c12e4d0e7`. Full tree: `fef2952c65cc6120ac6f55b941eeab007c6b0f1d`. Rust tree: `5d3acbd546c5dc3490e95635342572cb064007eb`. Desktop tree: `2413844c89265a3e239be2372d34b1e6e1b2d4bb`. Prepared branch `t3/validate-m1-m2b1-composition` and worktree remain at this exact source and are clean. There were no repository source/test/CI/harness/doc changes or commits by this worker.

The shared repository-wide ref inventory changed during the run: the feature and remote feature refs moved to f812030e32fe412404a6ea232f4183f0c6fd0c8e, another branch appeared, and orchestration checkpoint refs appeared. `git-refs-delta.json` records every before/after value. This worker ran no ref-mutating command and does not undo shared changes; their actor is not established by the audit. **The prepared branch/HEAD did not move. This evidence covers9e76a1d only and does not certify f812030 or any other concurrent head.**

Source freezing preceded validation. All **1,122** wrapper-staged paths exactly matched Git blobs/executable modes and the original POSIX modes. Host before/after and two guest after-run views agree on every original byte/mode. All **733 protected paths** remain identical, including helpers, Cargo/Node manifests/locks, verifiers, fixtures/generators, AGENTS, CI, harness and governing/evidence documents. The independent after-run tar audit checks every original path before classifying generated files, inventories all187 build files separately, and excludes only the declared installed/build outputs from the source set. `node_modules` is npm-ci output; target/cache directories remain outside the staged source.

Archives and SHA256:

- `source-head.tar`: `edfa891c2ae0d16d46d849694f44a85b052d130ff7f35ddd6e22af66cfc9679e` — Git archive of actual9e HEAD; 1,122 file bytes and Git modes independently matched.
- `staged-source.tar`: `68e2edf2c8b4dc59f74fd1cdf2f6306b2a729b147a53f2477a3f18cf9c176326` — full frozen wrapper input; 1,122 file bytes and modes matched.
- `guest-source-after-with-build-output.tar`: `020fd8281b87e895a397bf5e5a1ba6f8fe592495d4fb13ac4356e4860d71a0ff` — independent final guest source plus generated build outputs, with mode metadata.
- `source-vs-worker-795babd.diff` preserves the actual composition differences; old worker/Desktop PASS labels were not used as new execution evidence.

`static-source-audit.json` independently verifies145 M2a and149 M2b frozen fixture-inventory entries. Frozen helper and inventory hashes match the committed evidence exactly: M2a helper `d284a641ab430ee5744c1e114fc760e15c8d62b83b29b08406f358536515615d`, M2a SHA256SUMS `a5981856f26e687352a97836372816eaba0f98c285f8a8a41645678c8f8ebc88`, semantic helper `bb8ae70ae698ba9034d5f1ae9bbcd73c50773502215fe51707d4139690108390`, semantic SHA256SUMS `74877c9b8a930aa21a0c3a8fc5cf3519e11c97c6cd13ba1e3a6107235e19a199`. All remained unchanged afterward.

Execution used only the newly owned **m2b1-m1-union-9e76a1d** job through the unchanged trusted `/Users/ys/Code/zeropw-mlp-tools/vmrun.sh` with the prepared checkout. The job and wrapper temporary path were absent before staging. parity uid/gid2000; Linux aarch64 kernel6.8.0-147-generic; Rust1.98.1 (48a229cea 2026-09-01), Cargo1.98.1 (797e8a9bc 2026-08-05), Node22.20.0/npm10.9.3, Python3.12.14, OpenSSL3.0.13. The initial absence/profile logs, complete limits and clean runtime environment are retained. Initial pre-staging available space was15,547,264 KiB; no ENOSPC or cache deletion occurred. Shared system disk free space can change with other assignments and is not an owned-job usage measurement.

Product runtime was clean `env -i`, with correct HOME=/home/parity, owned CARGO_HOME/target/npm cache/XDG directories, CARGO_BUILD_JOBS=1, dev/test/release debug0, incremental0 and CARGO_NET_OFFLINE=true. Explicit focused Cargo commands used --locked --offline; unchanged full scripts use --locked and inherit offline=true. No Cargo config/credentials were copied. All **622** locked registry archives were independently SHA256-verified against the lock and freshly fetched official public index data (543 indexes); only verified public archive bytes were copied/downloaded into this job's Cargo home. No compiled cache or prior module binary was imported. The wrapper touches all new staged sources; compiler/build logs identify this job's fresh Rust/Desktop source paths. npm-ci used the unchanged --ignore-scripts command and an owned cache with empty own user config.

Private TMPDIR was `/home/parity/jobs/m2b1-m1-union-9e76a1d/ttttttttttttttttt`, exactly57 ASCII characters, directory mode0700, uid2000. The real parent directory ownership/type and no-symlink path were verified before product execution; shared directory permissions were not changed. Ordinary umask022 and original resource guards/timeouts remained. Limits include stack8MiB, open files1024, core dumps0, with the full resource-limit record in `guest/evidence/environment.json`. Only existing synthetic controlled fixtures and public pinned dependencies were used. No production/coordinator credentials, native Mac, other job processes/source/targets/caches or runtime authority were accessed. Guest NAT and this assigned Lima environment are the tested boundary; no physical-host isolation or native claim follows.

Focused results: **17 admission + 3 authority-oracle tests passed**. The combined focused command also passed legacy parser1, manifest10, payload13, provenance4 and whole-secret-tombstone9, for57 passed /0 failed /0 ignored. Debug checkpoint library13 and release checkpoint library13 passed, including the literal every-op authority unit test and parser tests.

All four exact stack selections ran **one test**, passed with exit0, and did not count a zero-selection invocation:

- Public target `team_checkpoint_payload`, exact test `full_verifier_total_depth_64_65_and_post_parse_helpers_on_256_kib_stack`, debug and release.
- Semantic target `team_checkpoint_admission`, exact test `semantic_depth_64_success_error_drop_on_256_kib_stack_and_65_refusal`, debug and release.

The new composed M1 regressions both passed in the full library run: `team::sync::retry_tests::m1_checked_adoption_does_not_report_success_after_caps_send_failure` and `team::transport::unix_channel_tests::m1_pending_requires_receiving_the_authenticated_frame_before_send_failure`. This directly covers the adoption/transport changes missing from worker795babd's tree.

The full unchanged `bash rust/verify.sh` includes formatting, strict Clippy, lib/bins, every integration target, explicit ignored probes and docs. Four probes were ignored in the ordinary library invocation, then all four actually executed/passed in the dedicated unchanged step:

- `signer::tests::idle_cpu_with_one_and_nine_live_bindings`: passed.
- `signer::tests::per_binding_fd_cost_matches_python_ratio_of_one`: passed.
- `signer::tests::per_client_fd_cost_matches_python_ratio_of_one`: passed.
- `signer::tests::rlimit_probe_served_clients_and_accept_loop_survival`: passed.

All17 doc/compile-fail tests passed. No skipped required test, assertion/guard relaxation, timeout increase or source edit occurred. Full Desktop `bash desktop/verify.sh` includes npm-ci with install scripts disabled, static/type/build/frontend checks, strict workspace formatting/Clippy, freshly built Rust product bins and the complete core workspace with --include-ignored. Core/workspace totals198 passed /0 failed /0 ignored. Normal zero-test bins/docs are retained in raw output and are not additional successful selected probes.

Actual phase exits and UTC intervals (exact argv/cwd and raw logs are in `guest/evidence/*.command.json`, `phases.json`, numbered logs and wrapper records):

- `01-profile`: exit **0**, 2026-11-07T11:44:38.713034+00:00 → 2026-11-07T11:44:39.435402+00:00.
- `01b-public-registry`: exit **0**, 2026-11-07T11:44:39.435728+00:00 → 2026-11-07T11:44:43.141536+00:00.
- `02-features`: exit **0**, 2026-11-07T11:44:43.141719+00:00 → 2026-11-07T11:44:44.542595+00:00.
- `03-focused`: exit **0**, 2026-11-07T11:44:44.542853+00:00 → 2026-11-07T11:45:51.531970+00:00.
- `04-checkpoint-debug`: exit **0**, 2026-11-07T11:45:51.532712+00:00 → 2026-11-07T11:46:18.264623+00:00.
- `05-payload-stack-debug`: exit **0**, 2026-11-07T11:46:18.265977+00:00 → 2026-11-07T11:46:18.474858+00:00.
- `06-semantic-stack-debug`: exit **0**, 2026-11-07T11:46:18.475426+00:00 → 2026-11-07T11:46:18.634611+00:00.
- `05-payload-stack-release`: exit **0**, 2026-11-07T11:46:18.634909+00:00 → 2026-11-07T11:48:27.472185+00:00.
- `06-semantic-stack-release`: exit **0**, 2026-11-07T11:48:27.473942+00:00 → 2026-11-07T11:48:32.690175+00:00.
- `07-checkpoint-release`: exit **0**, 2026-11-07T11:48:32.690651+00:00 → 2026-11-07T11:49:46.208710+00:00.
- `08-full-rust`: exit **0**, 2026-11-07T11:49:46.210740+00:00 → 2026-11-07T12:07:48.176180+00:00.
- `09-full-desktop`: exit **0**, 2026-11-07T12:07:48.179954+00:00 → 2026-11-07T12:15:48.513191+00:00.

Preserved execution/evidence issues:

- An initial evidence-only JavaScript call failed `ReferenceError: btoa is not defined` before any nested command executed; dispatch copying used apply_patch instead. A scratch temporary-path calculation printed59; no product ran with it, and the actual driver calculated/verified57 before execution.
- Initial wrapper staging exited255: `mux_client_request_session: write packet: Broken pipe` and `tar: Write error`. The owned job was independently still absent afterward; no product executed. `attempt-01-transport-failure/` retains exact source/driver/command/log/exit bindings. Sending the owned driver/input files as data and using a short wrapper invocation fixed only execution plumbing.
- Final original driver/wrapper exit1 is preserved under `guest/evidence/source-after-exception.txt`, `source-after.json`, `driver-result.json`, `wrapper-result.json` and `wrapper-driver.log`. It reports zero original source changes and187 generated extra files. `guest-independent-source-after-audit.json`, the complete final tar and the static analysis exit0 correct this evidence-script classification. No product rerun or silent retry occurred.
- Host Python3.9.6 lacks Python3.12's tar extraction filter argument; the collector was adapted before execution to validate every archive member as a relative regular-file/directory path in its owned evidence/input namespace. Collection and final analysis exited0. `execution-notes.json` retains setup details.

The canonical ca01275 dispositions and original severities remain unchanged. In particular, resolved ZPLINK-OPUS-01/02 and ZPL-SEC-01/02/04 stay resolved; ZPLINK-OPUS-03/03-R1, ZPL-SEC-03, ZPLINK-OPUS-04..11 retain their exact recorded open/insufficient-evidence status/severity; DOS-1 stays **HIGH/OPEN (partial original output)**. `canonical-finding-dispositions-reference.md` is copied source data, not this worker's adjudication. Worker blanket ID lists do not reopen resolved findings. Historical grant-expiry, ENOSPC/superseded and native pairing failures remain preserved under their original heads/reports; later Linux success does not erase or diagnose them.

**M2-G01 through M2-G10 all remain OPEN.** Native macOS for this composition is **NOT ASSIGNED / NOT RUN**; its exclusively assigned service worker was not queried or used. No two-physical-Mac proof, native M2b.1, GUI walkthrough, deliberate crash/fsync/ENOSPC/concurrency acceptance campaign, final document overlay, required-generation usability, persisted approvals/renewal, runtime onboarding/READY/import/committed epochs/receipts/ACK, deployment or target-capacity proof was performed. Existing suite tests are not substituted for those later gates. No Opus invocation/replacement/retry, Astra acceptance or release validation occurred.

The Linux driver assignment is released after normal completion with known exits; `assignment-release.json` records it. Prepared source and all owned guest/external artifacts are left intact. No other assignment was released, cleaned, stopped or modified. `verification-summary.json` gives per-suite counts/probes and actual exits; `SHA256SUMS` inventories the complete external evidence except itself.
