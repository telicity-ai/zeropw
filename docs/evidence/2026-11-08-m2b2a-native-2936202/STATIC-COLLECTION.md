# M2b.2a frozen native execution: independent static collection

2026-11-08. Collector: **gpt-6.1-sol / ultra**, native child `/root/collect_native_m2b2a`, inherited settings. Host standard-library DATA/hash and read-only Git only; no VM/SSH/network/root calls, source/helper/dependency imports or execution, formatter, tests or product run. No subagents. Only this external report was created; repository/ref/PR/runtime/source/evidence files were not changed.

**Collected result: the exact native source2936202 has109 full-verification steps,104 integration targets,112 test summaries and1,769 passed/0 failed. All20 phase exits are0. Each of four exact stack selectors ran1 test.** These counts were independently recomputed from saved raw logs, not copied from the worker's aggregate. This is static consistency checking of attributed runtime records, not a new execution, code review, acceptance or release verdict.

## Exact source and evidence

- Executed HEAD `29362020ed7a57451d0984eefb6eeb4e6c110b0c`; Rust tree `4536b42fb5206b446d4c6760c37c80281bcd3cbe`; full tree `51a473212393407cd01a09442bebbe63b6960412`.
- At collection start/end the coordinator checkout had this exact HEAD and empty Git status. All1,259 tracked path/blob/byte/POSIX-mode entries match the pinned Git tree, original prestaged manifest and exported before/after manifests. Modes:1,252×0644 and7×0755. Git blob hashes were independently recomputed from current file bytes. Both source-audit reports contain0 mismatches and0 generated files.
- Prestaged expected manifest SHA256 `611ea64e6adc9e36544b350e26057a805ab9284f7e647fdcd212e922cc270d06`. Raw exported before/after manifests are byte-identical, SHA256 `ef0c51ab71230f396545ae04f5726924ad980be7e0e13b99795c1d27b81395a4`. Their JSON row values agree exactly with the original manifest; different serialization hashes are not represented as equal.
- Final evidence catalogue: **77 regular non-symlink files,1,653,025 bytes**, every size/mode/hash matched. Complete local inventory equals the77 catalogue paths plus the self-excluded catalogue. Catalogue SHA256 `9de94417b32fcc99c6ef99e0bfc93613c0288c69e212c6ccfa323778f39c3503`.
- Export inventory:32 own regular JSON/log files,1,183,306 bytes; every local raw byte count/hash matched collection-manifest. The recorded privacy scan has0 hits over its bounded9-sentinel/50-variant rules; I did not rerun that scanner or claim general leakage prevention.
- All4 input binding paths were independently rehashed. Original frozen driver is `bbfc67b219fcaa1089776b087b08458fee4ecf971b49dd4b27278441016053a7` and is present as a host DATA copy only; it was not imported/run here. Driver-binding SHA256 `206fd909887d2493cd5347053983004344e538555acbb411a877ba34af1f5bb4`; cache-binding SHA256 `d252e18159201add148483dc86943ea3702360984a65cfdeb1fe9a64261e7d64`.

The before/after registry reports are byte-identical, SHA256 `f887874b0091e269e4dc1bceb2e007e092648b04b395cd805153d83818e6a8a9`. Their172 package/version/archive-checksum entries exactly match all172 registry entries in pinned Cargo.lock; summed source inventory counts are8,194. Both exported audits report MATCH/OFFLINE. **The actual remote crate archives and8,194 extracted file bytes were not exported here and were not independently rehashed by this collector.** Their runtime cache audit remains attributed to the frozen VM driver; local consistency with Cargo.lock and before/after identities was independently checked.

## Raw native counts, without cross-phase aggregation

[t3-134681c5 full-verify.log](/Users/ys/Code/zeropw-mlp-evidence/m2b2a-native-frozen-driver-20261108/t3-134681c5/raw/full-verify.log) SHA256 `144f6bdd94d4a13817ec64716f4048cfa2e4503fadf3f2e6eee3655614467d72`.

Read `rust/verify.sh` as text and derived the expected matrix from the pinned104 top-level rust/tests/*.rs paths. All109 BEGIN/END names agree in exact order: fmt, strict Clippy, lib/bins,104 integration targets, four ignored signer probes, docs. Every END exit is0; VERIFY_FAILED is empty. All112 result summaries sayok/0 failed and sum to1,769 passed. Library/binaries:703 passed,4 initially ignored across6 summaries; signer probe step:4 passed; docs:27 passed. Integration targets together contribute1,035 passed. Initial ignored probes are not fabricated extra passes: their actual later signer step is separately present in the same matrix.

Separate phases, deliberately not added to the1,769 matrix total:

|Phase|Summaries|Passed|Failed|
|---|---:|---:|---:|
|focused debug removal+semantic cut|2|18|0|
|focused release removal+semantic cut|2|18|0|
|seven historical regression targets|7|57|0|
|checkpoint library debug|1|14|0|
|checkpoint library release|1|14|0|

Four stack phases each have exactly one successful test-result summary:1 passed,0 failed,16 filtered. Every command includes--exact and the raw test name agrees with its selector:

- debug/release candidate: `complete_candidate_depth64_success_late_error_repeat_drop_and_65_refusal_on_256_kib`;
- debug/release fold: `complete_fold_depth64_on_actual_256_kib_stack`.

All20 phase records have distinct names,statePASS,exit0 and matching raw-log digests. Jobs1/incremental0/offline/private cache and57-byte TMPDIR fields agree. Feature graphs before/after are byte-identical, SHA256 `8a7c0c5312007819b8a4c4b5883daeb31671a738df81128fd98028affd44162a`, raw_value absent. Historical Linux1,766 remains separate and was not executed/reused/added to native totals.

## Environment and release are attributed records

The saved platform records identify credential-free Tart `zeropw-mlp-macos`/Mac501, UID501, virtual macOS26.6.2 build25G83, arm64, SIPdisabled,2vCPU/4GiB, Rust/Cargo1.99.0, Python3.15.0, OpenSSL3.5.9. These are the worker's observed runtime records, not my independent live VM inspection. Actual executor: gpt-6.1-sol/ultra/default tier, one frozen--run invocation; no model fallback/subagents/workflows reported.

Driver ends `2026-11-07T18:01:16.883798+00:00`; driver release record is consistent. Main transport wait ends18:01:17.256045Z; collection transport ends18:03:03.316480Z. Explicit [resource-release.json](/Users/ys/Code/zeropw-mlp-evidence/m2b2a-native-frozen-driver-20261108/t3-134681c5/resource-release.json), SHA256 `13ea3de38100206ac7c24af3a2bcaaaf4635b721de9afda108e70a557a9fca05`, records RELEASED at **2026-11-07T18:03:28.343444Z**, after all own synchronous commands/transports ended. The saved record explicitly makes no independent machine-idle/process-family-scan claim and says the VM was neither stopped nor resized. No new lease/resource assignment is inferred by this collection.

## Preserved failures and limits

[collector-errors.json](/Users/ys/Code/zeropw-mlp-evidence/m2b2a-native-frozen-driver-20261108/t3-134681c5/collector-errors.json) records2 collection-only failures: first compared the preparation digest to a differently structured preflight report (exit1 before product launch); second was a host nested-quote SyntaxError before any code/SSH launch. Their original evidence references remain. The required preparation artifact subsequently matched without source/cache/driver correction, and no second product invocation is claimed. I did not query the historical task timeline to independently retrieve the SyntaxError tool item; it is attributed to its retained collector record. Earlier mode/cache/native failed jobs remain unchanged and are not relabeled as this successful exact-source run.

This collection does not establish physical-two-Mac, GUI, sleep/wake, direct/TURN/network acceptance, runtime authenticated snapshot onboarding, generation usability, installation/READY/journal/receipt/ACK, crash/recovery, Oracle deployment/capacity, packaging or release. Tests containing Astra/Opus names are tests, not model reviews. Actual Astra/Opus acceptance/review remain NOTRUN or pending. **All M2-G01–G10 and canonical finding IDs/severities/evidence stay OPEN/unchanged; DOS-1 HIGH remains OPEN.** No Opus substitute/retry/rephrase/provider fallback or overall product/readiness PASS.

Primary execution [REPORT.md](/Users/ys/Code/zeropw-mlp-evidence/m2b2a-native-frozen-driver-20261108/t3-134681c5/REPORT.md) SHA256 `850189ef3a7a02851fbd68b5ad61194d9b8641f3025e437e9a6576867a6bf12f`. This independently collected report binds only the recorded source above; any later doc/source head needs its own explicit relationship and must not inherit a fabricated new full-head PASS.
