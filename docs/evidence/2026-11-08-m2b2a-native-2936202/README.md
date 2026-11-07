# M2b.2a native verification, exact source2936202

The actual Sol/ultra worker invoked the preflight-passed frozen driver once in
credential-free Mac501. All20 requested platform/product/feature phases exited0
and the driver reported REQUESTED_PHASES_PASSED. This is Rust source verification,
not full M2/runtime onboarding, physical-device, review, acceptance or release.
All M2-G01–G10 and DOS-1 HIGH remain OPEN.

Executed HEAD `29362020ed7a57451d0984eefb6eeb4e6c110b0c`, Rust tree
`4536b42fb5206b446d4c6760c37c80281bcd3cbe`. Later documentation commits do not
become a new whole-head execution result. The Rust tree equals the earlier
Linux-tested export; Desktop was not changed or rerun in this native task.

## Actual native results

- Unchanged rust/verify.sh:109 steps in exact expected order,104 integration
  targets,112 result summaries,1,769 passed/0 failed. The full-matrix count
  includes four explicit signer probes and27 doc tests. Tests with astra/opus
  in their names are repository tests, not model reviews.
- Focused semantics/removal oracle:18 passed each debug/release; checkpoint
  library14 each; seven historical targets57; each of four exact256KiB stack
  selectors ran exactly one test and passed. These overlap; no unique-test sum.
- Feature graphs before/after byte-identical; raw_value absent. All1,259 source
  files/Git blobs/POSIX and executable modes match before/after; zero generated
  source or mismatches. Driver/cache/preflight bindings stayed exact.
- Cache audit recorded172 locked archives/8,194 extracted source files before
  and after. Static collection validates saved audits and Cargo.lock bindings;
  it does not pretend to rehash live remote cache bytes without VM execution.

Environment: virtual macOS26.6.2/build25G83,arm64,2vCPU/4GiB,SIP disabled;
Rust/Cargo1.99.0,Python3.15.0,OpenSSL3.5.9. Execution only asUID501 in the
assigned credential-free VM, locked/offline, jobs1,incremental0,debug-info0,
private caches/HOME and unchanged57-byte private TMPDIR. No host product execution.
No GUI, two physical Macs, network/sleep/wake, packaging or capacity inference.

[Original report](REPORT.md), [safe phase/selector summary](validation-summary.json),
[explicit resource release](resource-release.json), [exact bindings](collection.json)
and [independent static collection](STATIC-COLLECTION.md) preserve source/outcome
attribution. Static collection checked77 evidence files/1,653,025 bytes plus all
1,259 current source paths/blobs/modes; it did not rerun the VM or review code.
Raw logs and complete inventories remain external, hash-bound in collection.json.

## Failures and limits preserved

Two collector-only errors are retained in collector-errors.json: prelaunch DATA
compared the preparation digest with the wrong preflight-report file; later host
collection quoting caused a SyntaxError before SSH. The correct immutable input
matched. No source/cache/driver/setup change, product retry or second invocation
occurred. Earlier mode-extraction and missing-checksum jobs stay failed/NOTRUN;
this separate successful invocation does not rewrite their historical outcomes.
The bounded exported-text privacy scan had zero hits, not general leakage acceptance.

Mac501 was explicitly released at2026-11-07T18:03:28.343444Z after the one driver
and all own transports ended. No VM stop/resize, unrelated-process scan or entire
machine-idle claim. A new native task needs its own explicit resource assignment.

Authenticated snapshot installation/READY/receipt/ACK, key/ciphertext usability,
gapped/interacting-removal proofs, compaction, runtime budgets, crash/concurrency,
actual Astra/Opus acceptance, physical two-Mac, deployment and release remain
pending. The service's separate pidfd crash quarantine and DOS-1 HIGH are not
closed by this Rust result. No sidecar pin, production installation or deployment.
