M2B2a frozen-driver native execution handoff — 2026-11-08 KST

Execution/collection completed. The exact frozen driver was invoked with --run once and ended REQUESTED_PHASES_PASSED; first_failure is null. All 20 platform, product and feature phase records have exit 0. No requested native phase is NOTRUN. This is execution evidence, with no review, acceptance or release decision.

Actual settings: T3 Code / Codex instance codex, gpt-6.1-sol, reasoning ultra, service tier default, full-access runtime, default interaction mode. Confirmed by a read-only t3_thread_configure call; no model fallback, subagent or workflow was used. Host operations were Git or Python standard-library DATA/hash/transport/report operations. Frozen source, helper, dependency, product, formatter and test code ran only on the assigned credential-free virtual Mac as UID 501.

Source HEAD 29362020ed7a57451d0984eefb6eeb4e6c110b0c; Rust tree 4536b42fb5206b446d4c6760c37c80281bcd3cbe. T3 supplied /Users/ys/.t3/worktrees/zeropw/t3-134681c5. No checkout was created and no repository files were changed; final git status is empty. The coordinator checkout was not edited.

Input and immutable artifact bindings:

- Brief SHA256 91078b9b87f32c9f13eecbe6dad26f769c6dbc3ea345dcd96f528e6a40d30257 was verified with host stdlib DATA before reading it.
- driver-binding.json SHA256 206fd909887d2493cd5347053983004344e538555acbb411a877ba34af1f5bb4.
- cache-binding.json SHA256 d252e18159201add148483dc86943ea3702360984a65cfdeb1fe9a64261e7d64.
- Frozen host DATA copy and VM driver SHA256 bbfc67b219fcaa1089776b087b08458fee4ecf971b49dd4b27278441016053a7; the VM driver matched before launch and after completion.
- Prestaged source manifest SHA256 611ea64e6adc9e36544b350e26057a805ab9284f7e647fdcd212e922cc270d06.
- Adopted cache preparation report SHA256 bd2d18ca1ecf73a912d4cf13ff9d4debfe7f2e14e93dd0d623f4505387c92250 remained exact. Only the explicitly authorized cargo-home-verified was reused.

Runner facts from this invocation: zeropw-mlp-macos, admin@192.168.64.2, UID 501; ARM64_VMAPPLE / aarch64-apple-darwin; virtual macOS 26.6.2 build 25G83 / Darwin 25.6.0; SIP disabled; 4 GiB RAM and 2 vCPUs. Actual Homebrew Rust and Cargo 1.99.0, Python 3.15.0, OpenSSL 3.5.9, LLVM 23.1.2. These are observed platform facts, with no physical Mac, GUI, sleep, network acceptance or capacity claim.

Exact native command, transported once with the brief-bound synthetic test key path and strict known-hosts file; key bytes were never read by the agent:

```text
/usr/bin/env -i PATH=/opt/homebrew/bin:/usr/bin:/bin HOME=/Volumes/ZeroPWBuild/m2b2a-native-r1-2936202/home TMPDIR=/Volumes/ZeroPWBuild/m2b2a-native-r1-2936202/txxxxxxxxxxx LC_ALL=C /opt/homebrew/bin/python3 -I -S -B /Volumes/ZeroPWBuild/m2b2a-native-r1-2936202/control-coordinator/native-driver.py --run
```

launch-intent.json records the SSH argument vector, disabled agent/forwarding/multiplexing, actual settings and single-launch guard. The frozen driver used jobs=1, incremental=0, debug info=0, locked/offline Cargo, an explicit clean child environment, private HOME/CARGO_HOME and the unchanged private 57-ASCII-byte TMPDIR. No setup correction, source export, chmod, cache/config edit, new product driver or product retry occurred.

Native test execution results (each line is its own phase; repeated tests across phases/profiles are not combined):

- Focused debug: removal oracle 1 passed and semantic cut 17 passed; 18 passed, 0 failed.
- Debug candidate and fold 256 KiB exact selectors: each selected exactly 1 test, passed 1, failed 0, filtered 16.
- Seven historical regression targets: 57 passed, 0 failed, with all seven result summaries present.
- Checkpoint library debug: 14 passed, 0 failed, filtered 693.
- Checkpoint library release: 14 passed, 0 failed, filtered 693.
- Focused release: removal oracle 1 passed and semantic cut 17 passed; 18 passed, 0 failed.
- Release candidate and fold 256 KiB exact selectors: each selected exactly 1 test, passed 1, failed 0, filtered 16.
- Unchanged rust/verify.sh: all 109 expected steps exited 0 in exact source-derived order, including format check, strict Clippy, library/binaries, all 104 integration targets, four ignored signer probes and doc tests. The matrix itself has 112 test-result summaries and 1,769 passed / 0 failed. Library/binaries contributed 703 passed and 4 initially ignored; the signer-probes step separately ran those 4 successfully. Doc tests passed 27. This count is derived only from this native full-verify.log; no focused/profile count or historical Linux count is added to it.
- Features before/after: exit 0, byte-identical graphs, raw_value absent.

Both exact selector names and all command/environment/exit/count bindings are retained in raw/phases.json, phase-counts.json and postcollection-checks.json. Product/driver failed stage: NONE. Native requested phases NOTRUN: NONE. Historical Linux1766 is untouched historical evidence and was not executed, reused, relabeled or added to native counts.

Before/after audits: all 1,259 source files, Git blobs and modes match the prestaged manifest; mismatch count 0, generated source files 0, source manifests byte-identical. The supplied host worktree also matches all 1,259 files/modes after collection. The 172 locked archives and 8,194 extracted source files passed the frozen cache audit before/after; registry reports are byte-identical. All 20 original coordinator-preflight evidence files retained their before-run path/size/SHA catalogue. No source, cache or driver was manually changed, and no prior failure evidence or unrelated job was queried or modified.

Privacy and collection: only 32 own regular text JSON/log files (1,183,306 bytes) were scanned and exported, with original bytes and hashes preserved. Bounds: 128 files, 16 MiB per file and 64 MiB total. Nine source-defined synthetic credential sentinels produced 50 literal/encoded variants; those plus private-key, authorization/credential-token, SQLite and NUL-text rules had zero hits. No target, executable, private database, key/token/TLS file or secret-reveal output was exported. This bounded scan is not general leakage or security acceptance. collection-manifest.json preserves the file inventory, scan rules/bounds and post-run bindings.

Two collector-only failed attempts are preserved separately from native product results in collector-errors.json. Initial prelaunch DATA collection compared a preparation-report digest to the different preflight registry report, causing exit 1; the intended preparation artifact then matched the required digest, with no actual required input mismatch or product launch at that point. A later host collection snippet had a nested-quote SyntaxError before executing any code or starting SSH; only transport/data quoting was corrected. Neither error changed any frozen source/cache/driver/setup or caused another product invocation. Original prelaunch.stderr remains intact; the syntax error remains in the task tool timeline.

Native driver end: 2026-11-07T18:01:16.883798+00:00. Main SSH wait returned at 2026-11-07T18:01:17.256045+00:00. Final collection transport ended at 2026-11-07T18:03:03.316480+00:00. Explicit resource-release.json records RELEASED at 2026-11-07T18:03:28.343444+00:00 after the one driver and every own transport ended. No further SSH or product execution occurred. Release is based on synchronous wait receipts and the frozen driver release record; no unrelated process scan or independent machine-idle claim was made. The VM was not stopped or resized.

Actual Astra: NOTRUN; its separate static two-capability-document task was not performed or replaced by this Sol test agent. Actual Opus review/recheck/replacement: NOTRUN. Repository targets containing astra/opus in their names are tests, not model reviews. No root parser, acceptance verdict, commit, push, PR, permission change, merge, deployment or release was performed.

Unresolved findings and gates remain unchanged: DOS-1 HIGH OPEN; all canonical finding IDs/severities/evidence unchanged; all M2-G01–G10 OPEN; actual Opus/Astra, runtime, generation usability, installation, READY, journal, receipt, ACK, physical/crash/GUI, deployment, capacity, packaging and release OPEN. Native80a and every other historical failed job retain their original failures, with no rerun or reclassification. The brief-bound predecessor release remains 2026-11-07T16:52:14.679515Z.

Changed files: repository NONE. New files are confined to this external evidence directory: safe raw evidence, input/launch/transport bindings, preserved collector failures, phase counts, postcollection checks, scope/open-gate status, explicit native resource release and this report. checksum-catalogue.json lists the SHA256, byte count and mode of every evidence file except the catalogue itself; its final verification is recorded in the tool handoff.
