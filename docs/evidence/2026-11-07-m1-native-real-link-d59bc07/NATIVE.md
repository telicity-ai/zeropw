Native macOS product verification completed on **d59bc07ff25abdc69cf10ffd9d6f8cfc45bd4b5a**. Every one of the13 driver phase commands exited0. The unchanged Rust matrix passed **107/107 steps,102 integration targets,1,740 tests**. The unchanged Desktop matrix passed **8/8 steps,343 frontend tests in26 files and198 Rust core/workspace tests**. There were no product test failures.

The original main driver nevertheless ended with **exit1**, which is retained: its source auditor inventoried187 generated Desktop files and rejected the88 Tauri-generated files outside its dist/build allowance. The99 dist files were already allowed. All1,136 original file bytes/blobs/modes matched in that original source-after record. A separate after-run collector and independent host tar auditor exited0 and verified every original again, while inventorying all187 generated outputs. No product check was rerun to change that evidence classification, and no assertion/timeout/guard was edited. Do not call the original driver exit0.

Actual model: gpt-6.1-sol, reasoningEffort ultra, serviceTier default, Codex provider/T3 Code harness. Personal execution; no subagents/workflows/Opus/Astra acceptance or release. Exact settings are in ../actual-settings.json.

Exact source:

- Full tree bdbf0c0372146ba1c890dfe1924adc2567806bf1.
- Rust tree5d3acbd546c5dc3490e95635342572cb064007eb.
- Desktop tree2413844c89265a3e239be2372d34b1e6e1b2d4bb.
- All1,136 prepared and native original paths matched before and after. source-after-originals.tar contains complete original after-run bytes/modes; ../source.tar and ../source-before.json hold the before state. independent-host-source-after.json independently checks the archive against the host/Git manifest. The prepared worktree remains clean at the supplied head.

Execution used ONLY the exclusively assigned existing zeropw-mlp-macos guest and fresh /Volumes/ZeroPWBuild/m1-m2b1-native-d59bc07. Its absence was checked before staging. No unrelated VM, VM start/stop/reconfiguration, host mount or credential change occurred. The supplied SSH key was used by path only, without reading its bytes; every native SSH invocation used all required identity/agent/forwarding/local-command/host-key/batch restrictions.

Actual native platform: **macOS26.6.2, build25G83, arm64, Darwin25.6.0 VMAPPLE, SIP disabled**, admin uid501/gid20. This is a virtual-NAT guest, not a physical-Mac/native networking proof. Rust/Cargo1.98.1, Node24.22.0/npm11.19.1, Python3.12.15 and Homebrew OpenSSL3.5.9 at /opt/homebrew/opt/openssl@3 were recorded. The public toolchain/cache locations were obtained from the existing recorded M1 native environment as data. No broad home/process/environment scan occurred.

Fresh own target, Cargo home, npm cache, HOME and XDG directories were used. Build jobs1, debug0 for dev/test/release, incremental0, locked/offline Cargo, ordinary022 umask. All622 locked registry archives were independently checked against lock SHA256 and543 freshly fetched official public sparse indexes before copying/downloading bytes into the own Cargo home. No compiled cache, Cargo config or credentials were copied. Full scripts are unchanged and inherit CARGO_NET_OFFLINE=true. npm-ci is the unchanged --ignore-scripts invocation with an own empty user config/cache and /dev/null global config.

The fresh TMPDIR is exactly57 ASCII characters, directly under real/no-symlink /Volumes/ZeroPWBuild, owner501/mode0700. Real ancestors and ownership were checked; no shared directory was chmodded. A source-derived kernel socket probe successfully bound representative Rust signer90-byte, Rust exec-ACK75-byte and Desktop85-byte paths. The Go103-byte limit is separate; no Go/native networking claim follows. The probe ran **before Desktop verification, after full Rust verification had already begun**. It must not be described as preceding every Rust test. Its script, paths, hash and exit0 are retained.

Selected nonzero results and exits:

| Phase | Result | Exit |
| --- | --- | --- |
| Profile/public registry/features | public data and clean runtime recorded | 0 each |
| Focused M2b.1/admission/oracle/M1 targets |57 passed, including admission17/oracle3/tombstone9 |0 |
| M1 library/session selection |14 passed |0 |
| Checkpoint library debug |13 passed |0 |
| Exact payload256KiB/depth64/65 debug |1 selected and passed |0 |
| Exact semantic success/error/drop256KiB/depth64/65 debug |1 selected and passed |0 |
| Exact payload256KiB/depth64/65 release |1 selected and passed |0 |
| Exact semantic success/error/drop256KiB/depth64/65 release |1 selected and passed |0 |
| Checkpoint library release |13 passed |0 |
| Unchanged bash rust/verify.sh |107 steps,1,740 passed/0 failed |0 |
| Unchanged bash desktop/verify.sh |8 steps,343 frontend +198 Rust passed/0 failed |0 |

The exact selectors are full_verifier_total_depth_64_65_and_post_parse_helpers_on_256_kib_stack and semantic_depth_64_success_error_drop_on_256_kib_stack_and_65_refusal. Each profile used --exact and actually selected1 test; no zero-selection invocation was counted. The full Rust ordinary library run's four ignored signer probes were subsequently all executed/passed by the unchanged explicit signer-probes step. All17 doc/compile-fail tests passed. Normal empty binary/doc targets are retained and are not additional selected probes. summary.json retains each command/cwd/timestamp/exit/count, all phase logs, source bindings and actual built binary hashes.

Full Rust ran2026-11-07T12:55:29.330216Z to13:27:53.343922Z; full Desktop ran13:27:53.348700Z to13:36:53.903624Z. Main native driver END was13:36:56.394211Z, exit1 for the evidence auditor described above. The source-audit traceback and original assertions remain intact. Generated outputs are99 dist files,80 autogenerated command-permission TOMLs,4 Tauri schema files and4 generated icons; all are individually inventoried with hash/size/mode. node_modules is declared npm installation output, excluded from the original source set.

Other preserved failures/limitations:

- The first SSH preflight used a nonexistent /usr/bin/test and stopped before staging/product execution. Shell builtin test corrected only that fixture preflight. The actual shell child exit was not separately captured by the initial compound host command; its raw diagnostic is retained in the tool transcript and initial-setup-attempt.json.
- Native attempt01 source audit failed before tests because BSD tar inherited staging umask077 and reduced every original file's POSIX mode. Every byte/blob already matched. The complete original evidence is retained in attempt01-evidence.tar and the guest's attempt01-evidence/. Re-extracting the frozen own export with tar -p restored intended modes. The original driver was unchanged for attempt02, and no product ran in attempt01.
- The public Rust toolchain repeatedly emitted nonfatal rust-objcopy warnings: Library not loaded: @rpath/libLLVM.dylib. They remain in raw logs; no toolchain/environment workaround was applied. All required commands still returned0.
- An optional read-only live-count query exited1 with Python SyntaxError because literal newline escapes reached -c. No product executed or state changed; that query was not repeated. The final file-based analyzer derived counts from retained logs. live-count-query-failure.json and the exact T3 tool transcript retain this evidence-query failure.
- The original native driver exit1 is not erased by later independent data audits. The generated-output inventory correction does not constitute a product retry or altered test guard.

All native drivers, path probe and collector ended. **This assignment explicitly RELEASED zeropw-mlp-macos** after collection; ../native-ownership.json records the release. Only this job's ownership was released. All native source, targets, caches, logs, evidence and TMPDIR artifacts remain intact.

This is native functional matrix evidence, not native real-Go pairing/direct/TURN, a GUI walkthrough, two physical Macs, sleep/wake, authenticated snapshot onboarding, crash/fsync/ENOSPC/concurrency acceptance, review, release, deployment or capacity proof. Fake core link daemons are not evidence about current native Mac networking. All M2-G01..G10 remain OPEN; DOS-1 HIGH/OPEN and all canonical review/finding/physical/runtime/release gates remain unchanged. The Linux real-link arm is documented separately.
