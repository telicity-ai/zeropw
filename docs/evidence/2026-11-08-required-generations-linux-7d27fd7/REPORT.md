**Required-generation Linux validation: FAIL / stopped; incomplete.**

Personally executed by actual **gpt-6.1-sol / ultra**, T3 Code through the Codex harness. Service tier is not exposed in this session runtime. No provider/model substitution, subagents, workflow, Opus/Astra invocation, review/recheck, source/ref/index edits, commit, publication, merge or deployment occurred. Host operations were standard-library DATA/hash/archive, Git reads and the exact restricted SSH transport. No submitted source/helper/dependency/build/test/generator executed on the host.

The frozen 29-phase plan was attempted in order once until its first nonzero phase result: **27 PASS, 1 FAIL, 1 NOTRUN**. All 14 debug/release exact256KiB selectors actually ran exactly one passing test. Phase27 ran the unchanged `bash rust/verify.sh` once and returned test exit1, driver/SSH exit125, without timeout. The controller then stopped. Phase28 `28-features-after` is NOTRUN; no substitute graph command or test retry was issued.

The unchanged full verifier runs its own remaining internal steps after a failed target. Its complete raw run contains **111 ordered begin/end markers, 106 integration targets, 109 successful steps and 2 failed steps**. Independent parsing of 114 test summaries gives **1812 passed, 4 failed, 5 ignored**. Focused overlaps are not added. Formatting, strict Clippy, lib/bins, all four explicit signer probes and 48 doc tests passed. The four library signer tests remain counted as ignored in the normal library run and then passed explicitly; the fifth ignored test is the synthetic fixture generator.

The exact failed targets are `native_cli_e2e` and `signer_e2e`, each exit101 with 4 passed/2 failed. Three failures explicitly report “This account is currently not available.” The fourth asserts a failed SSH-client status with blank stderr. Hash-bound preparation DATA creates UID2000 account `rgrun` with `/usr/sbin/nologin`; the tests choose the current account. This is consistent with a runner-account prerequisite, not a verified runtime-account diagnosis or a PASS. No runtime account query/change, authority change, source/test fix, waiver, retry, resource/stack/deadline increase or new campaign was made. See [failure-evidence.json](failure-evidence.json) and unchanged raw logs.

- `test_ssh_connection_through_admin_serve_agent_processes_and_real_sshd`
- `test_ssh_connection_without_its_ssh_is_repaired_in_place`
- `exec_tool_runs_two_remote_commands_on_one_connection`
- `real_ssh_client_authenticates_through_signer_without_private_key`

The exact source is bound below. Every one of the 1338 host entries and every before/after entry in all 28 executed guest receipts matches SHA256, byte length, Git blob, POSIX mode and executable mode. The source archive was checked as DATA with its `src/` packaging prefix. The frozen preparation catalogue has all 54 entries matching before and after. Git DATA shows ten docs additions plus one existing-doc modification after product commit ee26e36; Rust and Desktop trees are identical.

| Binding | Value |
| --- | --- |
| head | `7d27fd7ec500e36f0e5cc548325e1ae5b34864d8` |
| full_tree | `329404aa15163928d9c61c43020b5e3764eac9ad` |
| rust_tree | `4352ebbd0fa84bde0fb444c4d0902ef2510d0620` |
| desktop_tree | `2413844c89265a3e239be2372d34b1e6e1b2d4bb` |
| source_files | `1338` |
| source_manifest_sha256 | `7e6387f6709cd8cf8ab01a17b6fb0d9468fa509d71e74df4a87066f5f76c1cca` |
| source_archive_sha256 | `17e95b2c58bcdc0baadcc6e2f547692baa8c872e641dd4beaba338c9850243f4` |
| host_before_after_exact | `True` |
| all_28_executed_guest_source_before_after_exact | `True` |
| source_ref_index_edits | `False` |
| before_after_fixture_catalogues_exact | `True` |
| public_cache_audits_before_after_match | `True` |
| feature_after | `NOTRUN` |
| feature_comparison | `NOTRUN` |
| feature_before_raw_value_present | `False` |

The supplied brief was hashed before reading. The decisive input digests are below; [input-bindings.json](input-bindings.json) retains paths, lengths, source-derived matrix order and every frozen argv.

| Input | SHA256 |
| --- | --- |
| `/Users/ys/.t3/worktrees/zeropw/t3-31850657/docs/decisions/required-generations-2026-11-08/decision.md` | `d4f80f910a3209b4d4399e302f8c63c65316ae78a06421f46043bacf9630b158` |
| `/Users/ys/.t3/worktrees/zeropw/t3-31850657/docs/decisions/required-generations-2026-11-08/implementation-task.md` | `4d8990b5c6a38ff7c6224c7c1e734998a18b8416c579b211d9489663e40ed1c8` |
| `/Users/ys/Code/zeropw-mlp-evidence/required-generation-linux-preparation-20261108/PREPARATION-FREEZE.json` | `5e3b91784da07fb970d2564693e58f4f0cc7ddba841d32fd8eac8ab460e3d2c6` |
| `/Users/ys/Code/zeropw-mlp-evidence/required-generation-linux-preparation-20261108/assignment.json` | `900b10df8ae841ab9dbff2116f6f57adc6c10454a9e210707488ff23aed45cc8` |
| `/Users/ys/Code/zeropw-mlp-evidence/required-generation-linux-preparation-20261108/driver/command-plan.json` | `3719bdc0fef932d8fbf9d851574c1627bd8dd940664907d225899cb1fbf28608` |
| `/Users/ys/Code/zeropw-mlp-evidence/required-generation-linux-preparation-20261108/driver/linux_verify_driver.py.txt` | `703f7c29492465aaba64278697df7d77692bf6988a463337002774ed182b0282` |
| `/Users/ys/Code/zeropw-mlp-evidence/required-generation-linux-preparation-20261108/public-setup-result.json` | `7ce656db4d5c047e89a1814b3f080051dcef8ad1d56ef2b000425991e5f26784` |
| `/Users/ys/Code/zeropw-mlp-evidence/required-generation-linux-preparation-20261108/restricted-ssh-argv.json` | `a6635a284aed6efab75437a781a51a4d0a0f176d18ea4c7d841a557c3c09865e` |
| `/Users/ys/Code/zeropw-mlp-evidence/required-generation-linux-preparation-20261108/source-7d27fd7.tar.gz` | `17e95b2c58bcdc0baadcc6e2f547692baa8c872e641dd4beaba338c9850243f4` |
| `/Users/ys/Code/zeropw-mlp-evidence/required-generation-linux-preparation-20261108/source-manifest.json` | `7e6387f6709cd8cf8ab01a17b6fb0d9468fa509d71e74df4a87066f5f76c1cca` |
| `/tmp/zeropw-required-generation-linux-sol-20261108.md` | `eed5536abd69700572df1bd54d88c63d2260bd52c2abbb4a80da2bf567ce05a1` |

Environment: coordinator-prepared fresh Ubuntu24.04 arm64, kernel6.8.0-147,2CPU/4GiB/8GiB; pinned Rust/Cargo1.99.0. Those machine/toolchain/network properties are attributed to the frozen preparation, not new VM administration or physical/network acceptance. Own forced-route audits directly observed UID2000, groups[], NNP1 and all capabilities0. Preparation records loopback IPv4/IPv6 success and external IPv4 refusal. No mounts, agent/proxy or production credentials were assigned. Only the hash-bound SSH argv was used, with PATH=/usr/bin:/bin, LANG=C and LC_ALL=C; the new test-only private-key path was used by SSH only and its private bytes were never inspected, hashed or copied.

Every executed child used the root-owned frozen driver and plan, fixed private HOME/Cargo/target, offline dependencies, jobs1/debug0/incremental0, C locale and exactly57 ASCII private TMP bytes. Actual argv, fixed environment, source/control hashes, OS identity, raw-stream hashes, exits, timeout/cancellation, child wait and assigned-UID residual identities are retained in the individual collected receipts. The source and public-cache audits before/after independently rehashed 172 Cargo.lock-pinned archives,8194 upstream files and checked172 generated checksum documents. Host DATA parsing independently matched all172 archive digests to Cargo.lock. No live unassigned cache was used.

Frozen fixture catalogues all match before/after; source modes also match. New fixture/oracle source intentionally contains synthetic material and is excluded from runtime leakage classification.

| Fixture family | Entries | Catalogue SHA256 |
| --- | ---: | --- |
| team_checkpoint_v1 | 145 | `a5981856f26e687352a97836372816eaba0f98c285f8a8a41645678c8f8ebc88` |
| team_checkpoint_semantics_v1 | 149 | `74877c9b8a930aa21a0c3a8fc5cf3519e11c97c6cd13ba1e3a6107235e19a199` |
| team_checkpoint_m2b2_v1 | 97 | `950e7bc521197d24dc9d86ae60438fba3beb5901c4627f34c70926887bae1fcf` |
| team_checkpoint_required_generations_v1 | 57 | `76deb4be8ad0d9cca38cf623e8a98ee008302bc328d4b19bd6e28628bd0b8e19` |

Feature graph before: `84f9ca7320bd9beb87d293ea74b3b268339709acb1ff05c6c916d7a4c2dc4308`, `raw_value` absent. Feature graph after and resolved before/after comparison are **NOTRUN** because the campaign stopped after phase27. Unchanged Cargo/source bytes do not replace that missing observation.

The phase table uses actual test summaries only. Compile/features phases have no executed test summary. Counts are passed/failed/ignored; separate summaries in a multi-target command stay separate. All timeout flags are false. A dash for phase28 means no product command ran.

| Phase / state | Actual argv | Test / driver / SSH exits | Seconds (driver) | Actual P/F/I summaries | Cap |
| --- | --- | --- | ---: | --- | ---: |
| `00-features-before` PASS | `cargo tree --locked --offline --manifest-path rust/Cargo.toml -e features` | 0/0/0 | 0.117 | N/A | 1800 |
| `01-new-debug-compile` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_required_generations --test team_checkpoint_generation_oracle --no-run` | 0/0/0 | 42.762 | N/A | 1800 |
| `02-new-release-compile` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --release --test team_checkpoint_required_generations --test team_checkpoint_generation_oracle --no-run` | 0/0/0 | 117.512 | N/A | 1800 |
| `03-required-debug` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_required_generations -- --nocapture` | 0/0/0 | 1026.066 | 22/0/0 | 1800 |
| `04-oracle-debug` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_generation_oracle -- --nocapture` | 0/0/0 | 30.543 | 6/0/1 | 1800 |
| `05-new-release` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --release --test team_checkpoint_required_generations --test team_checkpoint_generation_oracle -- --nocapture` | 0/0/0 | 193.720 | 6/0/1; 22/0/0 | 1800 |
| `06-envelope-debug` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --lib team::envelope` | 0/0/0 | 11.864 | 13/0/0 | 1800 |
| `07-checkpoint-debug` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --lib team::checkpoint` | 0/0/0 | 3.561 | 15/0/0 | 1800 |
| `08-checkpoint-release` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --release --lib team::checkpoint` | 0/0/0 | 72.426 | 15/0/0 | 1800 |
| `09-old-semantics` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_semantic_cut --test team_checkpoint_removal_oracle` | 0/0/0 | 203.305 | 1/0/0; 17/0/0 | 1800 |
| `10-old-authority` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_admission --test team_checkpoint_authority_oracle` | 0/0/0 | 6.555 | 17/0/0; 3/0/0 | 1800 |
| `11-old-parser` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_manifest --test team_checkpoint_payload --test team_checkpoint_provenance --test team_checkpoint_legacy_parser_regression` | 0/0/0 | 6.130 | 1/0/0; 10/0/0; 13/0/0; 4/0/0 | 1800 |
| `12-m1-tombstone` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --test whole_secret_tombstone` | 0/0/0 | 12.957 | 9/0/0 | 1800 |
| `13-debug-exact-1` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_payload full_verifier_total_depth_64_65_and_post_parse_helpers_on_256_kib_stack -- --exact --nocapture` | 0/0/0 | 0.069 | 1/0/0 | 1800 |
| `14-debug-exact-2` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_admission semantic_depth_64_success_error_drop_on_256_kib_stack_and_65_refusal -- --exact --nocapture` | 0/0/0 | 0.175 | 1/0/0 | 1800 |
| `15-debug-exact-3` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_semantic_cut complete_candidate_depth64_success_late_error_repeat_drop_and_65_refusal_on_256_kib -- --exact --nocapture` | 0/0/0 | 0.174 | 1/0/0 | 1800 |
| `16-debug-exact-4` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_semantic_cut complete_fold_depth64_on_actual_256_kib_stack -- --exact --nocapture` | 0/0/0 | 0.067 | 1/0/0 | 1800 |
| `17-debug-exact-5` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_required_generations required_generation_depth64_success_late_error_repeat_drop_on_actual_256_kib -- --exact --nocapture` | 0/0/0 | 3.468 | 1/0/0 | 1800 |
| `18-debug-exact-6` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_required_generations required_generation_depth65_refuses_before_crypto_on_actual_256_kib -- --exact --nocapture` | 0/0/0 | 1.741 | 1/0/0 | 1800 |
| `19-debug-exact-7` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --test team_checkpoint_required_generations required_wrap_depth64_success_error_repeat_drop_on_actual_256_kib -- --exact --nocapture` | 0/0/0 | 3.461 | 1/0/0 | 1800 |
| `20-release-exact-1` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --release --test team_checkpoint_payload full_verifier_total_depth_64_65_and_post_parse_helpers_on_256_kib_stack -- --exact --nocapture` | 0/0/0 | 2.240 | 1/0/0 | 1800 |
| `21-release-exact-2` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --release --test team_checkpoint_admission semantic_depth_64_success_error_drop_on_256_kib_stack_and_65_refusal -- --exact --nocapture` | 0/0/0 | 4.211 | 1/0/0 | 1800 |
| `22-release-exact-3` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --release --test team_checkpoint_semantic_cut complete_candidate_depth64_success_late_error_repeat_drop_and_65_refusal_on_256_kib -- --exact --nocapture` | 0/0/0 | 4.918 | 1/0/0 | 1800 |
| `23-release-exact-4` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --release --test team_checkpoint_semantic_cut complete_fold_depth64_on_actual_256_kib_stack -- --exact --nocapture` | 0/0/0 | 0.071 | 1/0/0 | 1800 |
| `24-release-exact-5` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --release --test team_checkpoint_required_generations required_generation_depth64_success_late_error_repeat_drop_on_actual_256_kib -- --exact --nocapture` | 0/0/0 | 0.220 | 1/0/0 | 1800 |
| `25-release-exact-6` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --release --test team_checkpoint_required_generations required_generation_depth65_refuses_before_crypto_on_actual_256_kib -- --exact --nocapture` | 0/0/0 | 0.171 | 1/0/0 | 1800 |
| `26-release-exact-7` PASS | `cargo test --locked --offline --manifest-path rust/Cargo.toml --release --test team_checkpoint_required_generations required_wrap_depth64_success_error_repeat_drop_on_actual_256_kib -- --exact --nocapture` | 0/0/0 | 0.229 | 1/0/0 | 1800 |
| `27-full-matrix` FAIL | `bash rust/verify.sh` | 1/125/125 | 2677.240 | 703/0/4; 0/0/0; 0/0/0; 0/0/0; 0/0/0; 0/0/0; 1/0/0; 12/0/0; 9/0/0; 3/0/0; 4/0/0; 2/0/0; 4/0/0; 1/0/0; 4/0/0; 5/0/0; 5/0/0; 2/0/0; 2/0/0; 1/0/0; 1/0/0; 1/0/0; 6/0/0; 5/0/0; 3/0/0; 2/0/0; 1/0/0; 2/0/0; 6/0/0; 2/0/0; 3/0/0; 1/0/0; 1/0/0; 1/0/0; 5/0/0; 8/0/0; 9/0/0; 2/0/0; 5/0/0; 4/0/0; 10/0/0; 2/0/0; 1/0/0; 4/0/0; 2/0/0; 20/0/0; 149/0/0; 3/0/0; 2/0/0; 8/0/0; 1/0/0; 2/0/0; 26/0/0; 26/0/0; 8/0/0; 1/0/0; 4/2/0; 17/0/0; 20/0/0; 3/0/0; 26/0/0; 1/0/0; 1/0/0; 4/0/0; 32/0/0; 8/0/0; 2/0/0; 9/0/0; 21/0/0; 2/0/0; 15/0/0; 2/0/0; 1/0/0; 4/2/0; 4/0/0; 86/0/0; 6/0/0; 3/0/0; 2/0/0; 17/0/0; 3/0/0; 6/0/1; 1/0/0; 10/0/0; 13/0/0; 4/0/0; 1/0/0; 22/0/0; 17/0/0; 1/0/0; 1/0/0; 31/0/0; 1/0/0; 19/0/0; 12/0/0; 10/0/0; 35/0/0; 13/0/0; 16/0/0; 26/0/0; 3/0/0; 1/0/0; 1/0/0; 3/0/0; 8/0/0; 3/0/0; 3/0/0; 27/0/0; 46/0/0; 32/0/0; 1/0/0; 9/0/0; 4/0/0; 48/0/0 | 7200 |
| `28-features-after` NOTRUN | `cargo tree --locked --offline --manifest-path rust/Cargo.toml -e features` | - | - | NOTRUN | 1800 |

All exact selectors used the prescribed actual256KiB thread tests and frozen source. Raw test-name lines, one successful test summary and receipts agree.

| Profile | Target :: exact selector | Passed / failed / ignored |
| --- | --- | --- |
| debug | `team_checkpoint_payload::full_verifier_total_depth_64_65_and_post_parse_helpers_on_256_kib_stack` | 1/0/0 |
| debug | `team_checkpoint_admission::semantic_depth_64_success_error_drop_on_256_kib_stack_and_65_refusal` | 1/0/0 |
| debug | `team_checkpoint_semantic_cut::complete_candidate_depth64_success_late_error_repeat_drop_and_65_refusal_on_256_kib` | 1/0/0 |
| debug | `team_checkpoint_semantic_cut::complete_fold_depth64_on_actual_256_kib_stack` | 1/0/0 |
| debug | `team_checkpoint_required_generations::required_generation_depth64_success_late_error_repeat_drop_on_actual_256_kib` | 1/0/0 |
| debug | `team_checkpoint_required_generations::required_generation_depth65_refuses_before_crypto_on_actual_256_kib` | 1/0/0 |
| debug | `team_checkpoint_required_generations::required_wrap_depth64_success_error_repeat_drop_on_actual_256_kib` | 1/0/0 |
| release | `team_checkpoint_payload::full_verifier_total_depth_64_65_and_post_parse_helpers_on_256_kib_stack` | 1/0/0 |
| release | `team_checkpoint_admission::semantic_depth_64_success_error_drop_on_256_kib_stack_and_65_refusal` | 1/0/0 |
| release | `team_checkpoint_semantic_cut::complete_candidate_depth64_success_late_error_repeat_drop_and_65_refusal_on_256_kib` | 1/0/0 |
| release | `team_checkpoint_semantic_cut::complete_fold_depth64_on_actual_256_kib_stack` | 1/0/0 |
| release | `team_checkpoint_required_generations::required_generation_depth64_success_late_error_repeat_drop_on_actual_256_kib` | 1/0/0 |
| release | `team_checkpoint_required_generations::required_generation_depth65_refuses_before_crypto_on_actual_256_kib` | 1/0/0 |
| release | `team_checkpoint_required_generations::required_wrap_depth64_success_error_repeat_drop_on_actual_256_kib` | 1/0/0 |

The complete final matrix below is parsed from the one full run. Begin/end names and order agree with source discovery; success fails on the two nonzero targets. The driver’s combined ordered-success-marker check is therefore false, as preserved in its receipt.

| Ordered step | Exit | Actual P/F/I summaries |
| --- | ---: | --- |
| `fmt` | 0 | N/A |
| `clippy` | 0 | N/A |
| `lib-and-bins` | 0 | 703/0/4; 0/0/0; 0/0/0; 0/0/0; 0/0/0; 0/0/0 |
| `test:admin_expanduser_parity` | 0 | 1/0/0 |
| `test:admin_input_envelope` | 0 | 12/0/0 |
| `test:admin_secret_import` | 0 | 9/0/0 |
| `test:admin_sigint_cleanup_boundaries` | 0 | 3/0/0 |
| `test:admin_sigint_exit` | 0 | 4/0/0 |
| `test:agent_help` | 0 | 2/0/0 |
| `test:agent_proxy_parity` | 0 | 4/0/0 |
| `test:astra_cleanup_publication_order` | 0 | 1/0/0 |
| `test:astra_cli_runtime_round2` | 0 | 4/0/0 |
| `test:astra_cli_runtime_round3` | 0 | 5/0/0 |
| `test:astra_cli_runtime_round4` | 0 | 5/0/0 |
| `test:astra_projects_final` | 0 | 2/0/0 |
| `test:astra_pty_portability` | 0 | 2/0/0 |
| `test:astra_response_acceptance` | 0 | 1/0/0 |
| `test:astra_response_final` | 0 | 1/0/0 |
| `test:astra_response_final_recheck` | 0 | 1/0/0 |
| `test:astra_response_review` | 0 | 6/0/0 |
| `test:astra_response_round2` | 0 | 5/0/0 |
| `test:astra_response_round3` | 0 | 3/0/0 |
| `test:astra_response_round4` | 0 | 2/0/0 |
| `test:astra_run_context_lease` | 0 | 1/0/0 |
| `test:astra_runtime_final` | 0 | 2/0/0 |
| `test:astra_runtime_review` | 0 | 6/0/0 |
| `test:astra_sigint_cleanup` | 0 | 2/0/0 |
| `test:astra_sigint_cleanup_final` | 0 | 3/0/0 |
| `test:astra_team_fact_catchup` | 0 | 1/0/0 |
| `test:astra_team_fact_duplicate_diagnostic` | 0 | 1/0/0 |
| `test:astra_team_reconnect_diagnostic` | 0 | 1/0/0 |
| `test:astra_team_review` | 0 | 5/0/0 |
| `test:astra_team_round2` | 0 | 8/0/0 |
| `test:astra_team_round3` | 0 | 9/0/0 |
| `test:astra_team_round4` | 0 | 2/0/0 |
| `test:base_cli_error_parity` | 0 | 5/0/0 |
| `test:canonical_helpers` | 0 | 4/0/0 |
| `test:cli_commands` | 0 | 10/0/0 |
| `test:cli_grant_limits_parity` | 0 | 2/0/0 |
| `test:cli_parity` | 0 | 1/0/0 |
| `test:democli_parity` | 0 | 4/0/0 |
| `test:escaped_builtin_http_parity` | 0 | 2/0/0 |
| `test:fake_upstream` | 0 | 20/0/0 |
| `test:gateway` | 0 | 149/0/0 |
| `test:gateway_oracle` | 0 | 3/0/0 |
| `test:gateway_replay_status_parity` | 0 | 2/0/0 |
| `test:gateway_tls_parity` | 0 | 8/0/0 |
| `test:gateway_x1_credential_e2e` | 0 | 1/0/0 |
| `test:ledger_float_parity` | 0 | 2/0/0 |
| `test:native_admin_cli` | 0 | 26/0/0 |
| `test:native_admin_cli_more` | 0 | 26/0/0 |
| `test:native_agent_cli` | 0 | 8/0/0 |
| `test:native_atomic_cli` | 0 | 1/0/0 |
| `test:native_cli_e2e` | 101 | 4/2/0 |
| `test:native_response_cli` | 0 | 17/0/0 |
| `test:native_team_cli` | 0 | 20/0/0 |
| `test:native_team_e2e` | 0 | 3/0/0 |
| `test:policy_oracle` | 0 | 26/0/0 |
| `test:policy_parity_close` | 0 | 1/0/0 |
| `test:python_numeric_comparison_parity` | 0 | 1/0/0 |
| `test:relay_escape_parity` | 0 | 4/0/0 |
| `test:response` | 0 | 32/0/0 |
| `test:response_contract` | 0 | 8/0/0 |
| `test:response_integer_boundaries` | 0 | 2/0/0 |
| `test:response_parity_gaps` | 0 | 9/0/0 |
| `test:runs` | 0 | 21/0/0 |
| `test:runtime_fix_boundaries` | 0 | 2/0/0 |
| `test:runtime_parity_gaps` | 0 | 15/0/0 |
| `test:serve_request_log` | 0 | 2/0/0 |
| `test:server_accept_resilience` | 0 | 1/0/0 |
| `test:signer_e2e` | 101 | 4/2/0 |
| `test:signer_oracle` | 0 | 4/0/0 |
| `test:sshwire` | 0 | 86/0/0 |
| `test:state_dir_cross_language` | 0 | 6/0/0 |
| `test:store_cross_process_lock` | 0 | 3/0/0 |
| `test:store_oracle` | 0 | 2/0/0 |
| `test:team_checkpoint_admission` | 0 | 17/0/0 |
| `test:team_checkpoint_authority_oracle` | 0 | 3/0/0 |
| `test:team_checkpoint_generation_oracle` | 0 | 6/0/1 |
| `test:team_checkpoint_legacy_parser_regression` | 0 | 1/0/0 |
| `test:team_checkpoint_manifest` | 0 | 10/0/0 |
| `test:team_checkpoint_payload` | 0 | 13/0/0 |
| `test:team_checkpoint_provenance` | 0 | 4/0/0 |
| `test:team_checkpoint_removal_oracle` | 0 | 1/0/0 |
| `test:team_checkpoint_required_generations` | 0 | 22/0/0 |
| `test:team_checkpoint_semantic_cut` | 0 | 17/0/0 |
| `test:team_derive_lazy_parity` | 0 | 1/0/0 |
| `test:team_envelope_parity_edges` | 0 | 1/0/0 |
| `test:team_fold` | 0 | 31/0/0 |
| `test:team_fold_lazy_parity` | 0 | 1/0/0 |
| `test:team_invite_link` | 0 | 19/0/0 |
| `test:team_link_transport` | 0 | 12/0/0 |
| `test:team_membership_sync` | 0 | 10/0/0 |
| `test:team_oracle` | 0 | 35/0/0 |
| `test:team_pairing_approval` | 0 | 13/0/0 |
| `test:team_parity_gaps` | 0 | 16/0/0 |
| `test:team_remaining_contract` | 0 | 26/0/0 |
| `test:team_secret_import` | 0 | 3/0/0 |
| `test:team_share_policy_version_parity` | 0 | 1/0/0 |
| `test:team_snapshot_total_parity` | 0 | 1/0/0 |
| `test:team_snapshot_version_order_parity` | 0 | 3/0/0 |
| `test:team_sync_status` | 0 | 8/0/0 |
| `test:team_transport` | 0 | 3/0/0 |
| `test:team_uncaught_scope_parity` | 0 | 3/0/0 |
| `test:tools_server` | 0 | 27/0/0 |
| `test:vault_context` | 0 | 46/0/0 |
| `test:vault_context_oracle` | 0 | 32/0/0 |
| `test:vault_public_parity` | 0 | 1/0/0 |
| `test:whole_secret_tombstone` | 0 | 9/0/0 |
| `signer-probes` | 0 | 4/0/0 |
| `doc-tests` | 0 | 48/0/0 |

All four explicit signer-probe names were present with passing raw test lines:

- `signer::tests::idle_cpu_with_one_and_nine_live_bindings`: PASS
- `signer::tests::per_binding_fd_cost_matches_python_ratio_of_one`: PASS
- `signer::tests::per_client_fd_cost_matches_python_ratio_of_one`: PASS
- `signer::tests::rlimit_probe_served_clients_and_accept_loop_survival`: PASS

Privacy: 117 collected raw stdout/stderr streams, 271199 bytes, scanned with10 explicit synthetic fixture/builder samples and55 bounded raw/base64/base64url/hex/JSON/percent variants, including full synthetic SSH PEM/body/decoded blob. **Zero matches.** No sample values or plaintext-derived hashes are published. Short/empty samples, arbitrary transformations/fragmentation, intentional source/fixture/oracle/archive DATA and unrelated credentials/environments are outside this scan. It is not universal secrecy. See [privacy-scan.json](privacy-scan.json).

Resources: minimum observed host free before the31 transports 5129396224 bytes (guard2147483648); minimum guest free before executed phases 2199924736 bytes (guard536870912). Maximum Linux waited-child ru_maxrss 1336912 KiB. This is the child/its waited-descendant peak observation, not a sum, isolated key-stage RSS, quota, physical erasure or Oracle capacity. Raw MEASURE/STRESS lines separate fixture construction/packaging, complete semantic construction and key-stage timings and retain parser/prior-state effects; map/index/allocator overhead is not a quota. See [resource-measurements.json](resource-measurements.json).

First SSH 2026-11-07T23:55:59.746878+00:00; last SSH 2026-11-08T01:11:47.631265+00:00; observed span 4547.884 seconds. Whole assignment at release 4914.876 seconds against21600. Focused/compile/exact caps1800 and full7200 were unchanged. Host transport caps allowed driver cleanup; all own stdin handles closed and children/transports were joined. No timeout, TERM/KILL cancellation, unknown-PID kill/adoption or uncertain transport occurred. One transport exit125 is the recorded remote full-matrix failure, not a lost-connection replay.

Every raw failure and NOTRUN remains preserved. Own host DATA collector errors also remain recorded: an omitted src/ archive prefix caused an initial comparison assertion; an optional comparison assumed an external source-final.json existed in the repository; another optional comparison assumed ten changed paths rather than ten additions plus one docs modification. Correct DATA interpretation found no frozen-source/control mismatch. These were not product fixes or test retries. The original entries and corrections are in [collector-archive-comparison.json](collector-archive-comparison.json), [host-data-audit.json](host-data-audit.json) and [native-source-comparison.json](native-source-comparison.json). Frozen preparation’s earlier tomllib/plan-field setup errors remain attributed in its unchanged catalogue.

Historical native compiler phase02/fixture phase04 failures and every earlier NOTRUN remain under their original inputs. The valid native23000-operation single-commit phase13 **1800s TIMEOUT, exit-15, INCOMPLETE** is unchanged. Its historical source archive SHA256 is `6be1765a3dfa5dd0093263a4b11e3862848b34edc32ebe60ac489f6260ff982d`. The final32-operation commit distribution is a different input with the same production algorithm, not a repair or successful reclassification of that timeout. The archived metadata was read only as tracked DATA; no old native/VM/case12 state was queried.

Assurance remains required-DEK/all-required-ciphertext AEAD-byte authentication only. Empty/nontext or malformed SSH retrieval bytes can pass this narrow stage; provider/header/SSH-use readiness is not established. SSH remains core and unchanged. There is no runtime caller, installer, full-M2/READY, receipt or ACK capability. Driver receipts are saved observations, not cryptographic attestation against same-UID test code. Named zeroizing-owner evidence does not prove dependency/compiler/register/allocator/OS/swap/core/abort/power-loss erasure.

All M2-G01–G10 remain OPEN: original/general/gapped/interacting-removal/compaction semantics; required-key/ciphertext integration and stronger claimed credential usability; durable two-sided approvals/live transfer/budgets/deadlines/cancellation; fresh locked READY; journal/fsync/recovery/coherent epochs; committed provenance before receipt/ACK; crash/concurrency/physical-two-Mac/direct/forced-TURN and actual reviews/acceptance. Snapshot onboarding remains unsupported. Packaging/macOS ACL/Oracle HTTPS+TURN/deployment/capacity and product release gaps remain OPEN.

Canonical ca01275 severities/evidence remain unchanged: DOS-1 original HIGH / OPEN_NOT_FIXED_PARTIALLY_MITIGATED; OPUS-03 and03-R1 OPEN; SEC-03 INSUFFICIENT_EVIDENCE; earlier resolved scenarios and04–10 LOW/11 JSON nit–Markdown NIT/LOW are not reclassified. Actual interrupted Opus3eb was not retried/rephrased/rechecked/replaced. This is test collection, not Opus review or Astra acceptance. Old Go case12 remains UNRELEASED / AUTHORITY_NOTREADY / CANCELLATION_EVIDENCE_NOTREADY and was not queried; Mac501 remains released/unassigned and was not used.

**OWN UID2000 job and direct SSH resources: RELEASED.** All28 executed product children were waited, their saved assigned-UID residual checks were empty, all31 direct SSH transports ended/joined, and both owned execution/collection supervisors ended. Only read-only audit/bundle requests followed the final product residual check, and both ended. No further remote/resource calls will follow this worker release. Whole rg01 remains coordinator-owned and was not stopped or released by this worker; no whole-VM idle or physical-erasure claim is made. Product/service release holds are unchanged.

Artifacts: [validation-summary.json](validation-summary.json), [source-binding.json](source-binding.json), [independent-analysis.json](independent-analysis.json), [full-matrix-analysis.json](full-matrix-analysis.json), [failure-evidence.json](failure-evidence.json), [OWN-RESOURCE-RELEASE.json](OWN-RESOURCE-RELEASE.json), [guest-evidence.tar.gz](guest-evidence.tar.gz), [ARTIFACT-CATALOG.json](ARTIFACT-CATALOG.json). Collected originals remain below collected/evidence/. SHA256SUMS binds the final report, catalogue and packaged evidence archive without circular self-hashes.
