# Remote sync MLP: validation and open work, 2026-11-07

Status: **incomplete; no release acceptance and no aggregate Opus PASS**. This is
a dated evidence record, not a change to the acceptance requirements. The
[TURN checklist](remote-sync-turn-checklist.md) keeps its completion gates open.

Latest service-fix evidence: link `e115879f6a73d8f95e359a116da38ebb334d5ced`
passed isolated Linux vet, the full Go suite, server/daemon race checks and
CGO-free Darwin arm64 CLI/test cross-builds, with all 162 Git blobs, modes and
file sets matching before/after ([record](evidence/2026-11-07-link-e115879.json)).
This includes bounded connection admission, requesting-network session challenge
quotas, mandatory independently pinned deployment archives and descriptor-based
state/CA ancestor checks with native Darwin ACL APIs. The artifact unit suite
at `5a9f581` passed 118 checks, including 24 artifact boundaries. Its separate
[installer/rollback E2E record](evidence/2026-11-07-link-installer-5a9f581.json)
reports 119 checks passed, exit0, with 153 source files unchanged and all 12
installed release files matching the independently pinned synthetic archives.
This is a disposable systemd-nspawn fixture, not an OCI deployment. Native execution
of the new ACL, standard-root-alias and retained-directory-FD boundaries remains
NOTRUN; prior f544 native tests do not validate these changes. Link `4af5ac8`
subsequently adds Darwin redistribution notices to build outputs. Its separate
[one-build artifact verification](evidence/2026-11-07-link-build-4af5ac8.json)
passed all five cross-build targets and 33 artifact checks, with all 162 source
files unchanged. This is neither native execution nor a second-build
reproducibility comparison. No new Opus
verdict, OCI product deployment or final sidecar-pin integration is claimed.
This factual addendum was recorded by actual `gpt-6.1-sol`.

The [new Opus attempt at 4af5ac8](evidence/2026-11-07-link-4af5ac8-review-unavailable.json)
failed before source review because Claude's five-hour API quota was exhausted.
The provider reported reset at 2026-11-07 17:50 KST. No new review verdict exists,
the original ca01275 REVISE is unchanged, and no substitute-model approval or
production deployment is claimed. Independent implementation and isolated
verification continue; retry must be a new review task after that reset.

## Source and execution identity

| Item | Exact source or scope |
| --- | --- |
| Pre-fix ZeroPW source compared | `1f60bc2a3f2b91fa691dfa9f79c81bfb131aabe1` on `feature/remote-sync-mlp`; comparison revision before this documentation update |
| ZeroPW product source tested | `41d217f26a030042c9f0b1caac9417715470c0e1`; its Rust tree `f2c67647fcba83ae78dd6fd10418b6f42a58a6f8` is byte-identical to the compared revision's Rust tree |
| Rust reader-fix source (later verification below) | `d77ce9ed7170f9e2689bc1ecf5244aa9602cc587`; Rust tree `181f99ddbffedb3b7f5c158d7484afca37be8a8a`, different from the earlier passing Linux tree |
| Later test-only correction | `7f0421af335911b4ff21aebf7eb8447dbe20de5c` changes only `rust/tests/team_link_transport.rs`; product source remains the `d77ce9e` implementation. Full Linux verification passed at this revision; later native-fixture correction `d942263` has separate focused evidence |
| Earlier diagnostic-record fix | `945e6a6fa9865f015c51cb0dcabd43b0b1e2c6af` serializes complete wire-capture records across threads/processes. Its regression was added at `55c833b`. Focused and complete Linux checks passed at this revision, Rust tree `f147723da8e8b5b6e42ae678819f20d57ffc36bb`; native verification remains separate |
| Integrated signer correction | `bd065fc4c66a79133a2b7f24f462200858080b60`, collected by exact fast-forward cherry-pick; Rust tree `2882ba592e2204eb62723d95e240525e75196f64`. macOS full Rust PASS; Linux full Rust FAILED on an unresolved grant-expiry assertion. Bounded Astra design assessment is not two-platform or Opus acceptance |
| Current link fixes and sidecar pin | ACL fix `f544478a48cea66be816efbed50967bafcacc8ac`; working `desktop/zeropw-link.json` now pins it. Three native ACL regressions subsequently passed, but full native Go failed; post-fix Opus returned REVISE at `ca01275` before that evidence was collected. The new `d77ce9e`/`f544478` E2E and pin-packaging checks passed; native acceptance remains separate |
| Link README follow-up | `ca01275c60037b2e008714e646c79a57aa6c1462` changes only the root README after `f544478` |
| E2E fixture/evidence | Earlier fixture/evidence commit `28abd9a450d8328424db5334443f1dd4bbd5cc24`; final `858ddc` run evidence is committed under `docs/evidence/remote-sync-e2e-2026-11-07-858ddc/` at the compared revision. Both runs use CLI source `41d217f26a030042c9f0b1caac9417715470c0e1` |
| Link publication | Private [telicity-ai/zeropw-link](https://github.com/telicity-ai/zeropw-link), [draft PR #1](https://github.com/telicity-ai/zeropw-link/pull/1); not merged or release accepted |
| Link initial review input | `bcdaaecd569a71bf4df07c738869e1e0c7a577e1`; later fix commits `cc733dc`, `858ddc` and `f544478` are outside that review |
| Earlier implementation workers | Actual `claude-opus-5-5`; these were not Sol executions |
| Current local coordinator and fix work | Actual `gpt-6.1-sol`; session-based coordination, not an always-on cloud service |
| Current real-network E2E worker | Actual `gpt-6.1-sol` |
| This documentation recorder | Actual `gpt-6-astra`; evidence reconciliation, not an Opus review |
| Valid initial review scopes | Actual `claude-opus-5-5`: crypto/auth and secrets/logs, including the seven finding verification results |
| Initial incomplete network reviewer | Logs contain `claude-opus-5-5` and `claude-opus-4-8`; malformed/truncated output, not an accepted complete review |

External raw test logs are under `/Users/ys/Code/zeropw-mlp-evidence/`.
Paths below are relative to that directory. Logs and test source must be retained
with the tested revision; predecessor component results do not validate a new
integration or security-fix commit.

## Implemented versus verified

The integrated source contains the `zpl:` transport adapter, link sidecar packaging,
explicit fingerprint approval, pairing commands, sync-status metadata and the
desktop devices/pairing flow. The separate link repository contains the connection
module, service API, daemon and deployment scripts. This is implementation status;
it does not establish working native macOS delivery or a deployed service.

| Check | Environment and evidence | Result and limit |
| --- | --- | --- |
| Desktop static checks, unit tests and build | Isolated Linux job `/home/parity/jobs/integ-dverify`, source `41d217f26a030042c9f0b1caac9417715470c0e1`; `integ/desktop-verify-2.log` | PASS for the recorded scope: static checks, 336 Vitest tests in 21 files, build, formatting, strict Clippy, product binaries and desktop core tests; overall `EXIT=0` |
| Desktop pairing integration tests | Same source/job; tail of `integ/desktop-verify-2.log`, `E2E_EXIT=0` | Two tests passed. They use a fake link daemon. The test name `two_macs_pair_through_the_link_daemon_only_after_explicit_approval` is not evidence of two physical Macs or actual ICE/TURN networking |
| Earlier full Linux Rust verification | Isolated Linux job `/home/parity/jobs/integ-rverify`, source `41d217f26a030042c9f0b1caac9417715470c0e1`; first `integ/rust-verify-41d217f-resume.log`, retry `integ/rust-verify-41d217f-retry-space.log` | First run FAILED due to disk exhaustion. Complete retry PASS, process exit 0: 100 steps; 1,621 passed, 0 failed; 4 ignored in ordinary library run, all four signer probes subsequently run and passed |
| Earlier real service/daemon/coturn plus ZeroPW sync | Isolated Lima `zeropw-parity` Ubuntu 24.04 arm64 VM, kernel `6.8.0-147-generic`, Go 1.27.3, coturn 4.18.0; ZeroPW `41d217f` + link `858ddc`; [final committed evidence](evidence/remote-sync-e2e-2026-11-07-858ddc/README.md) | PASS, exit 0: 66/66 scenario assertions plus separate log scan for seven synthetic service secrets. Earlier `cc733dc` run retained separately |
| New Rust/link real-network E2E | ZeroPW `d77ce9ed7170f9e2689bc1ecf5244aa9602cc587` + link `f544478a48cea66be816efbed50967bafcacc8ac`, isolated Linux; [new evidence](evidence/remote-sync-e2e-2026-11-07-d77-f544/README.md) | PASS, exit 0 confirmed by coordinator execution session 5035: 66 scenario assertions plus one separate log scan covering seven synthetic service secrets |
| Link component network lab | Predecessor link-core `49d6f8d`, isolated Ubuntu 24.04 aarch64 VM, kernel 6.8, Go 1.27.3; `link-core/netns-final-49d6f8d-plain.log` and `link-core/netns-final-49d6f8d-turn-nat.log`; scenario descriptions in `zeropw-link/docs/connection.md` §7 | Component evidence for direct, forced TURN UDP/TCP/TLS, UDP blocking, outage/restart and expiry scenarios. This does not establish integrated vault sync or macOS behavior |
| Earlier deployment lab | Isolated Ubuntu 24.04 arm64 VM and systemd-nspawn test containers; `deploy/` logs; source-specific reports in `zeropw-link/docs/operations.md` | Historical installation/coturn evidence only; neither an OCI deployment nor validation of the committed review fixes |
| Link review-fix tests | Isolated Linux job, fixes committed as `cc733dc`; `zl-review-fixes-10.log`, coordinator recorded process exit 0 | PASS: `go vet`, full Go suite, server/daemon race tests and shell lint (18 scripts). Historical full-run failures remain recorded below |
| Revoked-orphan follow-up | Link `858ddc`, isolated Linux; `zl-review-orphan-revoked-retry.log` | PASS: `go vet`, full Go suite and server/daemon race tests, including `TestRevokedOrphanRotatesKeyAfterRestart`. Initial `zl-review-orphan-revoked.log` failed from disk exhaustion; retained |
| Link state-ACL fix Linux verification | `f544478`, isolated Linux; `zl-acl-fix-linux-private-tmp.log`, exit 0 | PASS: vet, full Go suite, server/daemon race tests and `CGO_ENABLED=0` Darwin arm64 test cross-compilation. This is not native product acceptance |
| macOS ACL platform API probe | `macos/acl-chmod-fd-api-probe.log`, OS-only experiment | Mode 0700/0600 directory/file remained readable by `nobody` before ACL removal; checked-descriptor `/bin/chmod -N` returned 0 for both and access was denied afterward. Not a native product regression pass |
| Deployment unit suite | Root job inside isolated Linux VM; `zl-review-deploy-unit.log` | PASS: 106 passed, 0 failed |
| Fixed coturn build | Isolated Linux VM; `zl-review-coturn-build.log`, process exit 0 | PASS: pinned coturn 4.18.0 source build under a unique build UID and non-root probes. Installed only at `/opt/zeropw-coturn-review-cc733dc`; not deployed to OCI |
| Darwin cross-build | Linux; `zl-review-darwin-crossbuild.log`, process exit 0, link `cc733dc`; latest retry `zl-review-darwin-858ddc-crossbuild.log` | PASS for both `cc733dc` and final `858ddc`: arm64 and amd64 Mach-O binaries produced. No native macOS runtime test |
| Desktop packaging tooling | Linux with fixtures, `desktop/package-cc733dc.log`; latest retry `desktop/package-858ddc.log` | PASS for both `cc733dc` and final `858ddc` pin: 61 Python tests per run. Not real macOS packaging or a signed/released app |
| ACL-fix sidecar pin packaging | Isolated Linux, `desktop/package-f544478.log` | PASS, exit 0: 61 tests for the `f544478` pin; still fixture-based tooling, not native app packaging |
| Frozen-source native macOS Rust verification | Isolated Tart macOS 26.6.2 arm64 VM, synthetic-only, no host-directory mounts; Rust 1.98.1; frozen `1f60bc2`, `macos/rust-verify-1f60bc2.log` | FINISHED FAILED, exit 1: 100 steps, 99 passed and only `lib-and-bins` failed. Aggregate 1,622 tests passed, 2 failed, 4 ordinary-run ignored; signer probes ran separately. Both closed-peer library failures are retained |
| New Rust fix verification | `d77ce9e`, tree `181f99ddbffedb3b7f5c158d7484afca37be8a8a` | Linux strict all-target Clippy and 244 focused team tests PASS. Full `integ/rust-verify-d77ce9e-linux.log` FINISHED FAILED: 100 steps; 1,621 tests passed, 1 failed, 4 ordinary-run ignored; only `test:team_link_transport` failed on capture/delivery accounting |
| Test-only correction verification | `7f0421a`, `integ/link-wire-capture-proof-linux.log` and `integ/rust-verify-7f0421a-linux.log`; [full result manifest](evidence/2026-11-07-linux-rust-7f0421a.json) | PASS, exit 0: strict Clippy/12-test target, then all 100 unchanged full-matrix steps; 1,622 passed, 0 failed, 4 ordinary-library ignored with all four signer probes explicitly run |
| Native-fixture correction | `d94226364eae32a67a739312a8cd393cc64f3909`, `integ/link-fixture-concurrent-writer-linux.log` | Linux strict library Clippy and all eight link unit tests PASS, exit 0. Native v2 driver reports 8/8 link and 2/2 Unix-frame tests passed; complete native Rust subsequently FAILED as recorded below |
| New native verification handoff | Replacement driver 8090, frozen `d942263` Rust/core and `f544478` Go; `/Volumes/ZeroPWBuild/verification-20261107-v2/` | Full Rust FINISHED FAILED, exit 1: 100 steps, four failed steps, 1,621 passed/4 failed/4 ordinary ignored. Driver finished 03:57:48 UTC, all-required-pass false; subsequent Go/core results are below. Original driver 7245 remains archived/interrupted, never PASS. VM execution is not two physical Macs |
| Frozen native full failure evidence | [Exact phase/source/log manifest](evidence/2026-11-07-macos-rust-d942263.json), `macos/v2-collection-20261107035319Z/rust-d942-full.log` | Failed steps: `lib-and-bins`, `test:signer_e2e`, `test:team_link_transport`, `test:vault_context`. Includes the historical capture-format failure and three signer directory/cleanup assertions subsequently covered by unchanged passing regressions at `bd065fc`. This frozen run remains FAILED |
| Native capture-proof failure | `d942263`, `macos/rust-d942-targeted-link-integration.log` | FAILED, exit 101: 11 passed, 1 failed on an invalid capture direction token. This is separate from the earlier writer deadlock. Original strict format and all secret scans remain; malformed records were not skipped |
| Diagnostic capture concurrency regression | `55c833b` then `945e6a6`, isolated Linux; `integ/wire-capture-concurrency-before-fix.log` and `integ/wire-capture-concurrency-after-fix.log` | Before-fix regression FAILED, exit 101; a retained synthetic capture confirms interleaved records. Fix PASS, exit 0: strict all-target Clippy, the 512-record/two-process/eight-thread test and all 12 link integration tests. Native verification remains separate |
| Earlier complete Linux Rust verification | `945e6a6`, `integ/rust-verify-945e6a6-linux.log`; [result manifest](evidence/2026-11-07-linux-rust-945e6a6.json) | PASS, exit 0: all 100 unchanged script steps, 1,623 passed, 0 failed, 4 ordinary-library ignored and all four signer probes explicitly run. This covers only the `945e6a6` Rust tree, not later signer/M1/M2 or frontend changes |
| Integrated signer macOS verification | `bd065fc`; [source-specific evidence](evidence/2026-11-07-signer-bd065fc.json), `signer-path-fix-20261107/macos-vm-evidence/` | PASS, exit 0: all 100 unchanged full-matrix steps, 1,634 passed, 0 failed, 4 ordinary ignored; four signer probes explicitly passed. SIP-disabled VM, not physical two-Mac/desktop packaging evidence |
| Integrated signer Linux verification | Same `bd065fc`; `signer-path-fix-20261107/linux-vm-evidence/` | FAILED, exit 1: 100 steps completed, 99 successful and `test:tools_server` failed; 1,630 passed, 1 failed, 4 ordinary ignored; four signer probes explicitly passed. Unresolved expired-grant assertion, not a two-platform PASS |
| Two physical Macs | Two-device test environment unavailable | NOTRUN |
| 200-device/24-hour capacity, reconnect target and combined 1 GB VM budget | No completed current-source measurements | NOTRUN; no 100-user capacity claim |

The earlier full Go runs in `zl-review-fixes-5.log` and
`zl-review-fixes-8.log` failed `TestAcceptAndDialBounds` because it assumed opening
a QUIC stream from a cached connection could never succeed before the peer's
shutdown packet arrived. The committed test keeps the original offline/timeout
error assertions and additionally requires any provisionally opened stream to
close with zero bytes within three seconds; a read timeout fails. The passing
full run follows that bounded behavior check. Isolated retries alone are not the
resolution evidence, and the earlier failures have not been erased.

The first resumed Rust matrix failed from VM `ENOSPC`: the final integration
targets `tools_server`, `vault_context`, `vault_context_oracle` and
`vault_public_parity`, signer probes and doc tests did not pass. The coordinator
removed only incremental build caches from the current MLP jobs
`integ-rverify`, `integ-dverify`, `rust-pairing-verify`, `rust-link-main` and
`integ-desktop` (about 6.9 GB), preserving sources, binaries, logs, evidence and
unrelated jobs. The complete matrix restarted with about 5.8 GB free and then
completed successfully. Its log SHA-256 is
`38a9a3f9748d367e4ba2237e841052047dd60207dc5a6e78ce7e6d3e27d472cb`.
The first failure remains a failure; the separate complete retry is the PASS
evidence. Read-only Git tree comparison confirms the tested Rust tree equals
`1f60bc2a3f2b91fa691dfa9f79c81bfb131aabe1:rust`; this does not relabel older
desktop tests as checks of every changed file in a later commit.

The successful `cc733dc` real-network run is archived as `e2e/run-9-cc733dc.log`,
SHA-256 `2fa04fc567c43e4cfa058d82f68c8cd280d1141d6764c33d9bea25eff829d066`.
The final `858ddc` run is `e2e/run-10-858ddc.log`, SHA-256
`a69edb050f8ef736c1e4da12b56256ee8a8f211fb4092c455d2ac09cd602d6d8`.
Its [manifest](evidence/remote-sync-e2e-2026-11-07-858ddc/manifest.json) binds the
exact source, binaries, unchanged fixture and assertions. It covers explicit approval, signed
history, later/offline/concurrent versions, direct and forced TURN UDP/TLS paths,
UDP blocking, process pause/restart, coturn restart, invite/token reuse/expiry,
version and device revocation, malformed IPC and sampled secret observations.
It does not cover initial snapshots, whole-secret deletion, native Mac sleep/wake,
power-loss durability or production capacity. Point-in-time memory sampling is
not a proof against every transient value or encoding.

## Native failure and Rust fix under verification

The frozen native run at `1f60bc2` failed
`team::link::tests::reply_lines_are_bounded_complete_and_timely` and
`team::link::tests::the_client_sends_one_contract_request_line`. The coordinator
reproduced Darwin `SO_RCVTIMEO` returning errno 22 after a Unix peer fully closes,
even though buffered data remains readable; open and half-closed control cases
succeeded. Evidence is in `macos/unix-timeout-after-close-probe.log` and
`macos/unix-timeout-after-close-controls.log`. These are real native failures,
not a reason to omit or relabel the tests.

Fix `d77ce9ed7170f9e2689bc1ecf5244aa9602cc587` replaces that path with polling
and safe `rustix` `net`/`DONTWAIT` reads for replies and frames, preserving
deadlines, size limits and cancellation. It adds raw buffered reply/frame, EOF
and truncation assertions for a closed peer. It enables the `net` feature on
existing `rustix`, without adding a new dependency. The fix is implemented;
Linux strict all-target Clippy and 244 focused team tests passed. The full Linux
matrix subsequently finished with one capture-accounting assertion failure,
detailed below; it did not pass overall. The new `d77ce9e`/`f544478` E2E passed
for its scenario scope. The durable guest handoff subsequently finished with the source-specific
failures and ACL passes recorded below; there is no overall native success.

## Product gaps and unverified boundaries

- **Initial snapshot is not implemented.** Joining currently bootstraps signed
  history through the existing vector exchange. A device cannot join an environment
  whose required history has been compacted. This leaves checklist D03 incomplete;
  describing the signed-history fallback does not fulfill the snapshot requirement.
- **Whole-secret deletion without resurrection needs separate evidence.** Revoking
  one credential version can leave an older valid version active. A passing version
  revocation test is not a passing whole-secret deletion/tombstone test. The
  [specification](remote-sync.md) now explicitly distinguishes these semantics;
  it does not claim the broader requirement has been implemented or verified.
- Process separation and encrypted transport alone do not establish the complete
  OS isolation boundary. macOS inherited-ACL handling remains an open finding.
- Linux component transfers and fake-daemon UI tests do not establish native Mac
  pairing, sleep/wake, network changes, revocation, failure recovery or packaging.
- Both devices must be online. No server-side offline vault copy is implemented
  or approved by this record. Existing SSH signing remains in scope.

## Initial adversarial review and post-fix REVISE

The lossless [partial review archive](reviews/2026-11-07-link-initial.partial.json)
preserves the original finding severity, location, failure scenario, evidence and
fix recommendation, alongside each rebuttal-verification result and source agent
ID. All seven completed-scope findings have `real: true`. Those verifications
confirm the original findings; they are not post-fix acceptance.

| Finding | Original severity | Original issue | Status at this record |
| --- | --- | --- | --- |
| ZPLINK-OPUS-01 | medium | Unauthenticated challenges can exhaust the shared pool needed for session renewal | RESOLVED by static post-fix Opus at `ca01275` for the original scenario; implementation/test evidence at `cc733dc` remains separate |
| ZPLINK-OPUS-02 | low | Enrollment failure-budget check/charge race under concurrent requests | RESOLVED by static post-fix Opus at `ca01275` for the original scenario; implementation/test evidence at `cc733dc` remains separate |
| ZPLINK-OPUS-03 | low | Lost enrollment response leaves an orphan device and a stuck local identity | OPEN at `ca01275`: lost-response/restart recovery present, but rotation can crash between device/config writes (ZPLINK-OPUS-03-R1) |
| ZPL-SEC-01 | low | Socket client sends invite/link tokens without checking server peer UID | RESOLVED by static post-fix Opus at `ca01275` for the original scenario; implementation/test evidence at `cc733dc` remains separate |
| ZPL-SEC-02 | low | Service-CA ownership/path checks and separate stat/read permit trust substitution | RESOLVED by static post-fix Opus at `ca01275` for the original scenario; implementation/test evidence at `cc733dc` remains separate |
| ZPL-SEC-03 | low | macOS inherited ACLs can bypass mode-only state privacy checks | INSUFFICIENT_EVIDENCE in the review: native results were unavailable then. Later three native ACL regressions passed; readback/detection, OPUS-08 and renewed review remain open |
| ZPL-SEC-04 | low | Root executes coturn build output writable by shared `nobody` UID | RESOLVED by static post-fix Opus at `ca01275` for the original scenario; implementation/test evidence at `cc733dc` remains separate |
| DOS-1 | high (partial output) | No pre-HTTP global/per-client connection cap at `internal/server/server.go:343` | HIGH / OPEN at `ca01275`: cap partially mitigates single-IP exhaustion; small-set network monopolization, fairness/tunability and target-shape measurement remain unresolved |
| Deployment/operations scope | Initial reviewer returned no verdict | New static scope reviewed at `ca01275`, within explicit omissions | REVISE; OPUS-07/09/10/11 and deployment acceptance remain open |

The fixes include separate registered-device session-challenge capacity, atomic
enrollment failure-budget reservations, session-based recovery of a committed
but lost enrollment response, same-user Unix-socket peer checks, descriptor-based
CA ownership/path checks, and a dedicated coturn build UID with non-root probes.
Regression tests include `TestEnrollmentChallengesCannotStarveRegisteredSession`,
`TestConcurrentEnrollmentAttemptsReserveFailureBudget`,
`TestSuccessfulEnrollmentRefundsFailureReservation`,
`TestEnrollRecoversWhenCommittedResponseIsLost`, and
`TestServiceCARefusesSymlinkAndWritableParent`. The DOS-1 cap has
`TestIdleSocketsAreLimitedBeforeHTTPAndCapacityReturns`. ZPL-SEC-03 remains open.
The original lost-response regression at `cc733dc` did not cover an operator
subsequently revoking the orphan identity. Follow-up commit
`858ddc07007eedaa978bdbb9ecafeebb7f332668` persists revoked state and recognizes
it at startup so the next enrollment rotates the key after restart.
`TestRevokedOrphanRotatesKeyAfterRestart` uses actual service-DB revocation and
passed with the full Go suite and race tests in
`zl-review-orphan-revoked-retry.log`. The initial disk-full attempt is retained.
These implementation/test claims do not replace post-fix Opus review.

The state-ACL fix at `f544478a48cea66be816efbed50967bafcacc8ac` clears the
checked private state directory's ACL before creating an identity, and clears
file ACLs before reads/writes. It uses the fixed `/bin/chmod` path, a sanitized
non-secret environment, only the checked descriptor as fd 3, a two-second
deadline and fail-closed errors. It does not modify a custom CA or ancestor
directories. Protection against ACLs on custom-CA files/ancestors remains
**NOT VERIFIED**. Initially a coordinator self-assessment, this is now the
independent LOW finding ZPLINK-OPUS-06 in the post-fix Opus report. ZPL-SEC-03
remains open for its residual requirements and subsequent Opus acceptance. Later native regression evidence is recorded separately below; it does
not resolve the readback/detection requirement or OPUS-08.

Native guest metadata in `macos/acl-helper-platform-integrity.log` confirms
`/bin/chmod` passes Apple-anchor code-signature verification, with SHA-256
`b0451fa7b5995805519855783cc208a2ade4925b30735258639bc0cca68da10d`.
However, `csrutil` reports **System Integrity Protection disabled** in the
upstream Tart image. No security setting was changed for this task. This is a
material environment limit: the VM's checks are not proof of production macOS
OS isolation, and a VM is not two physical Macs. The Apple signature check does
not erase that limit or close ZPL-SEC-03.

The first Linux ACL-fix attempt (`zl-acl-fix-linux.log`) failed CA ancestry checks
because the wrapper's `TMPDIR` had mode 0775. The isolated test environment was
corrected to 0700; the checks were not weakened. The subsequent
`zl-acl-fix-linux-private-tmp.log` completed with exit 0. Both logs are retained.

To avoid another Linux VM disk-full interruption, only the inactive MLP build
cache `rust-pairing-verify/target` was reclaimed. Its five normal product binaries
were first moved to `preserved-product-bins` and their SHA values recorded;
sources, logs and prior E2E inputs were preserved. Evidence is
`linux-cache-reclaim-20261107.log`; about 11 GB was free afterward. This cleanup
is environment maintenance, not test success or a change to acceptance criteria.

The initial network review's raw `StructuredOutput` remains malformed/truncated,
with mixed-model logs; the initial deployment reviewer returned no result. Neither
historical run is relabeled complete. After the previously recorded 12:50 KST
limit reset, a new actual `claude-opus-5-5` review returned **REVISE** for exact
link head `ca01275c60037b2e008714e646c79a57aa6c1462`, written
2026-11-07T04:10:22Z. Its [lossless archive](reviews/2026-11-07-link-ca01275-opus/README.md)
contains the original JSON/Markdown and hashes. Coordinator-requested T3 effort
was `medium`, fast mode `false`; the reviewer reported visible effort **10**.
Both observations are recorded without rewriting the original report.

The new network/resource and deployment/operations scopes returned a verdict
within the report's explicit omissions. The reviewer ran **no product tests or
runtime probes**; the original-scenario RESOLVED dispositions are static review,
not new test results. Most node/signaling state-machine code, streams, several
daemon/service-client/store paths, deployment helpers and test harnesses were not
fully reviewed. Exact coverage is in report §1. No aggregate PASS exists.

| New finding | Original returned severity | Open issue at `ca01275` |
| --- | --- | --- |
| ZPLINK-OPUS-04 | low | Known active-device public key can exhaust that device's session-challenge quota |
| ZPLINK-OPUS-05 | low | One five-device account can occupy all configured TURN allocations/bandwidth |
| ZPLINK-OPUS-06 | low | macOS ACL modification rights on custom CA and ancestors are unchecked |
| ZPLINK-OPUS-07 | low | Healthcheck executes network-facing probe parsers as unsandboxed root |
| ZPLINK-OPUS-08 | low | State paths re-resolved after checks permit parent-swap/inherited-ACL exposure |
| ZPLINK-OPUS-09 | low | Monthly bandwidth/cost wording omits 31-day months, overhead and per-direction semantics |
| ZPLINK-OPUS-10 | low | Self-attesting artifact digests and weaker coturn-bundle extraction do not bind installed artifacts to reviewed bytes |
| ZPLINK-OPUS-11 | nit (JSON); NIT/LOW (Markdown) | Stale ACL/recovery documentation and missing IPv6 SSH lockout guard |

These are returned findings, not implementation or reproduction claims. Original
severity/evidence/rebuttals remain unchanged. DOS-1 stays HIGH/OPEN despite its
separate residual assessment; OPUS-03-R1 and SEC-03 remain release blockers.
The [signer path decision](decisions/2026-11-07-signer-socket-path.md) separately
bounds the ZeroPW macOS long-TMPDIR correction; it is not part of this link review
and supplies no passing test evidence.

## Oracle provisioning and deployment

The coordinator confirmed the actual Oracle account `handlecu`, region
`ap-chuncheon-1`, and Free Tier. Instance creation for `zeropw-link-beta` succeeded
at **2026-11-07 00:58:19 UTC**; the console showed **Running**. The selected image
was Ubuntu 24.04 `2026.10.27-0`, shape `VM.Standard.E2.1.Micro`, with the
46.6 GB default boot volume (displayed as 47 GB after creation). Public IP is
`168.107.31.44`, private IP `10.0.0.234`. The existing VCN/subnet
`vcn-20240403-0113` / `subnet-20240403-0113` and `zeropw-gha-runner` were preserved.
Only the existing `zeropw-link-oci.pub` public key was used for provisioning; this
record contains no private key or operational secret.

The read-only SSH baseline in `oracle-os-baseline-20261107.log` recorded Linux
`7.0.0-1013-oracle`, memory total 998,367,232 bytes, used 249,581,568 bytes and
available 748,785,664 bytes; no swap. The root filesystem had 47,321,268,224 bytes
total and 2,228,187,136 bytes used. Shortly after boot its load averages were
1.81 / 0.89 / 0.34. These are **OS-only baseline observations**, not combined
coturn/service capacity, sustained CPU utilization or an MLP load test.

Cloudflare has a DNS-only A record `zeropw-turn.telicity.ai` →
`168.107.31.44`, confirmed through resolvers `1.1.1.1` and `8.8.8.8`. The primary
VNIC is now attached to NSG `zeropw-link-beta`. Its seven verified ingress rules
are stateful TCP 80, 443, 3478 and 5349; stateful UDP 3478; stateless UDP
61000–62023; and stateful ICMP type 3/code 4. Existing shared subnet/security lists
were left unchanged. The OS INPUT chain now permits port 80 before its default
REJECT. Persistence is verified in `oracle-acme-persistence-20261107.log`:
`netfilter-persistent save` exited 0, existing iptables rules were saved and the
service is enabled (packages 1.0.20). Product ports are not yet opened in the OS
firewall; preserving port 80 does not establish product firewall acceptance.

Trusted Ubuntu certbot 2.9.0 issued a Let's Encrypt certificate for
`zeropw-turn.telicity.ai`, expiring **2027-02-05**, and `certbot.timer` is enabled.
Evidence is in `oracle-acme-20261107.log` and
`oracle-cert-metadata-20261107.log`. The private key stayed server-side and was
not read or returned to a worker or tool response. Certificate issuance and an
enabled renewal timer do not establish a running TLS service or successful future
renewals. The renewal dry-run completed with exit 0 in
`oracle-acme-renew-dryrun-no-jitter-20261107.log`. The first dry-run was
interrupted during randomized sleep; its earlier log is retained and is not
recorded as a renewal failure or a passing run. A dry-run pass is not a guarantee
of future renewal availability.

No product service, HTTPS listener or TURN listener has been deployed. Public
HTTPS/TURN reachability and complete cloud/host firewall acceptance remain
incomplete. DNS, NSG attachment and a certificate are infrastructure evidence,
not evidence that the named host is a working ZeroPW endpoint.

## Latest verification results and work still running

`integ/rust-verify-d77ce9e-linux.log` is the full Linux matrix for the changed
Rust reader tree. `integ/admin-build-d77ce9e.log` records a successful locked
build of its real admin binary. `e2e/run-11-d77-f544.log` is a new real-network
run combining that binary with link `f544478`; it completed with exit 0 and
66/66 scenario assertions, plus **one separate log scan of seven synthetic
service secrets**. The [manifest](evidence/remote-sync-e2e-2026-11-07-d77-f544/manifest.json)
records exact source, fixture and binary identities. The raw log SHA-256 is
`0c37d13e7396fbc15311ef41394620635a82460b37f04c4fa44d74d05f404390`,
assertions SHA-256
`f53219ae6f6420f0b61aeea9c0faf844de4050543d2abf1e20dd0a979f72fb96`,
and tested admin binary SHA-256
`73779b093bfdb50c1c77d76deb3b24731ce707c94d1d82e6d081205b48692635`.
`desktop/package-f544478.log` separately passed all 61 tooling tests with exit 0.
The snapshot, whole-secret deletion, native Mac, capacity and review gaps remain.

The frozen native `1f60bc2` matrix has finished **FAILED**, exit 1: 100 steps,
99 successful steps and `lib-and-bins` failed on the two closed-peer tests above.
Cargo-result totals are 1,622 passed, 2 failed and 4 ordinary-library ignored;
signer probes were explicitly run. `macos/baseline-result-1f60bc2.json` records
the result. The raw log SHA-256 is
`1a4dc46fd7f9c0da30dd76aa038380996e973d9d37bfeb04f4349a0d27506453`.

The Linux `d77ce9e` matrix also finished **FAILED**: 100 steps, 1,621 tests passed,
1 failed and 4 ordinary-library ignored. Only `test:team_link_transport` failed,
at `rust/tests/team_link_transport.rs:825`: “a captured frame did not cross the
link”. The raw log SHA-256 is
`9dfb47eddbf478c2a754d0709b755ec61bc6d9c58daee460c9c7df07365628b4`.
This was not a plaintext-leak assertion failure. The capture records every send
attempt before writing; shutdown can interrupt an attempt before the frame is
forwarded, so not every captured attempt is a delivered frame.

Test-only correction `7f0421af335911b4ff21aebf7eb8447dbe20de5c` preserves all
capture/relay/hex secret scans and proof that every received frame appears in the
relay bytes. It adds a guard requiring more than three received frames, rather
than assuming interrupted send attempts must have been delivered. It changes no
product code, verification script, harness, CI or original review severity.
Strict Clippy and the full 12-test target passed with exit 0 in
`integ/link-wire-capture-proof-linux.log`. The unchanged full matrix subsequently
passed with exit 0 in `integ/rust-verify-7f0421a-linux.log`: 100 steps, 1,622 passed,
0 failed and 4 ordinary-library ignored, with all four signer probes explicitly
run. Raw-log SHA-256 is
`6e0d69a7ad8c1a238564d57b79c6b1c5353886ba1656f0891d2ccd5348bc3ed3`.
Its [result manifest](evidence/2026-11-07-linux-rust-7f0421a.json) binds source
`7f0421a` and Rust tree `27d5fd04acc4fde77ec459b0bef509fce20e36f6` to every step.
The failed full-run logs remain retained; this later PASS does not rewrite them
or validate future M1/M2 code.

After the frozen native baseline, driver 7245 started `d77ce9e` targeted tests,
but the oversized-line fixture blocked before its reader started. Stack sampling
located `UnixStream::write_all`; native controls measured 8,192-byte send/receive
buffers, successful 8,191/8,192-byte synchronous sends and an 8,193-byte send that
timed out with exactly 8,192 bytes buffered. A concurrent reader consumed all
8,193 bytes. Evidence is under `macos/diagnosis-20261107T025800Z/`.

Test-only `d942263` makes the mock writer concurrent and bounds its write and
held-peer wait to two seconds. It preserves all exact 8,192/8,193-byte, EOF and
absolute-deadline assertions. The original controller/status/script/logs/lock
were retained and classified `interrupted_test_fixture_deadlock`, never PASS.
Only its owned controller and hung phase process group were stopped.

Replacement driver 8090 uses verified `d942263` sources and `f544478` Go in a new
directory, `/Volumes/ZeroPWBuild/verification-20261107-v2/`. Its SHA-256 is
`ca197b102230ff2434fe81c6a486a9c40f57a9f37b1d62c17147f12af79b320f`.
The old directory contains a `CURRENT-RUN.json` pointer; replacement actions are
in `macos/v2-owned-replacement.log`. Targeted phases have a 600-second bound and
15-second status heartbeats. Eight native link tests and two native Unix-frame
tests passed. Full frozen Rust then finished with exit 1 and four failed steps:
`lib-and-bins`, `test:signer_e2e`, `test:team_link_transport`, `test:vault_context`.
Its Cargo-result totals are 1,621 passed, 4 failed and 4 ordinary ignored.
Raw-log SHA-256:
`aa1bf6b07a71539572f2e835d5eec4a5449b30a08417e2c72cec477f72a67e03`.
The [native failure manifest](evidence/2026-11-07-macos-rust-d942263.json)
retains each completed phase and identical before/after source manifests.
In addition to the capture assertion below, two signer teardown tests and the
configured signer socket-directory assertion failed. Their retained failures were later addressed by the bounded signer correction
and unchanged regression passes at `bd065fc`, recorded below; the original
failed result is not rewritten and the test TMPDIR was not shortened.
As of 03:53:15 UTC Go vet was running; native Go/ACL/core phases had not started.
This local driver is not an always-on cloud service or two-Mac evidence.

The v2 targeted link integration then failed on its strict direction-token check
(11 passed, 1 failed, exit 101). The raw log SHA-256 is
`c07a16d24d28dfc0ef6d1ddbdf6e1a69864fbc8e36d812887db5972cb8807795`;
`macos/v2-capture-proof-failure.md` preserves the open result. The complete frozen
v2 Rust matrix failed separately as recorded above. The independent Go/core
checks subsequently finished without source mutation, with failures below.

The coordinator added a concurrent-record regression at `55c833b`. Two processes
with four threads each write 64 uniquely tagged 64-byte records per thread. The
test failed against the original capture implementation: `writeln!` can make
several writes, while `O_APPEND` alone does not keep a whole formatted record
contiguous. The synthetic corrupt capture is retained as
`integ/wire-capture-corrupt-before.hex`, SHA-256
`67e42343cdc8a8da2184bdb98059b33242303f06d55487368796b3cd53265817`.
Before-fix log SHA-256:
`68c173d307c36d767312a099a2dee3b51da20be40e2168ce1d5d713b488a3128`.

Fix `945e6a6` holds a safe rustix file lock for the complete diagnostic record,
including cross-process writers, and retries interrupted acquisition. It leaves
the format, strict direction check, frame proofs and every confidentiality scan
intact. Linux strict all-target Clippy, all 512 unique complete records and the
12-test link target passed with exit 0. After-fix log SHA-256:
`75dfd72b71324e5b8a8c960d00af16d14c421015ba330af179b6cabda3af7f18`.
The unchanged full script then passed with exit 0 at `945e6a6` in
`integ/rust-verify-945e6a6-linux.log`: all 100 steps, 1,623 passed, 0 failed and
4 ordinary-library ignored, with all four signer probes explicitly run.
Raw-log SHA-256:
`644ee90c14d10b0d01519bdd05a7b1041222080f6516c3bdd8c544daf2d9dea7`.
The [result manifest](evidence/2026-11-07-linux-rust-945e6a6.json) binds this
run to Rust tree `f147723da8e8b5b6e42ae678819f20d57ffc36bb`. Native validation
of this fix is still required. The M1 worker was steered to include these bounded
fixes before its own final verification. This is a diagnostic I/O fix, not an
Opus review or a reason to erase any prior failure.

To make room for new verification, inactive MLP jobs `integ-dverify`,
`integ-desktop` and `desktop-core` had their normal product executables moved to
each job's `preserved-product-bins` with SHA-256 records before their remaining
compiled target caches were removed. Sources, logs, prior E2E inputs and the
active verification target were preserved. This separate reclamation is logged
in `linux-cache-reclaim-m1-capacity-20261107.log`; the VM then had about 18 GiB
free. It is not a product test or resource-capacity result.

## Later collected native Go, ACL and desktop results

Collection `macos/v2-collection-20261107T041605Z/` records driver 8090 finished
at 03:57:48 UTC with **all required phases passed = false**. These results were
not available to the Opus review; they supplement evidence without rewriting its
original INSUFFICIENT_EVIDENCE disposition or claiming external acceptance.

| Frozen source / phase | Result |
| --- | --- |
| Link `f544478`, Go vet | PASS |
| Link `f544478`, full Go | FAILED: 265 passed, 1 failed, including subtests |
| Link `f544478`, server/daemon race | FAILED: 76 passed, 1 failed, including subtests |
| Link `f544478`, native Darwin ACL regressions | All three PASS in both full/race runs; this is product-test evidence in the SIP-disabled guest, not overall native acceptance |
| Original link `858ddc` ACL reproduction | Another UID could read the synthetic seed under 0700/0600 modes; no seed value was collected |
| Desktop `d942263`, fmt | FAILED: `Failed to find targets`; not a formatting PASS |
| Desktop `d942263`, Clippy and binaries | PASS |
| Desktop `d942263`, core | FAILED: 137 passed, 2 pairing tests failed with `handshake_channel_closed` |

Both Go failures are `TestIdleSocketsAreLimitedBeforeHTTPAndCapacityReturns`:
Darwin could not bind `127.0.0.2` (`can't assign requested address`). Preserve the
failure and repair/verify the platform fixture explicitly; do not treat it as a
passing listener-cap test. The three native ACL passes supply missing runtime
evidence for SEC-03, but do not close its post-normalization readback/detection
concerns, OPUS-08 state-path race or post-fix review requirement. The original
exposure reproduction is synthetic evidence, not inspection of a production key.
Desktop pairing failures remain unresolved; the signer correction does not
by itself explain or fix them. This v2 run has no full native PASS; later
`bd065fc` Rust verification is separate and supplies no two-Mac acceptance.

## Integrated signer correction: bounded acceptance, Linux failure retained

Exact worker commit `bd065fc4c66a79133a2b7f24f462200858080b60` was collected by
fast-forward cherry-pick. Its [evidence manifest](evidence/2026-11-07-signer-bd065fc.json)
and [Astra assessment](reviews/2026-11-07-signer-bd065fc-astra.md) bind the changed
source and results. Actual worker model was `gpt-6.1-sol`; actual bounded assessor
was `gpt-6-astra`. Only `rust/src/signer.rs` and `rust/DEVIATIONS.md` changed.
Selection uses the real 18-character basename within the existing 100-character
budget; the separate 103-character bind guard remains. Fresh fallback directories
have an explicit owner, reusable shutdown retains them, and final teardown removes
only an empty owned leaf. Caller/Context ownership and nonrecursive cleanup remain.

Eight new behavior tests, the three byte-unchanged original signer/context
regressions and all four signer probes passed on both platforms. The full macOS
Rust matrix passed all 100 steps (1,634 passed/0 failed/4 ordinary ignored).
The full Linux matrix completed 100 steps with 99 successful and one failed step
(1,630 passed/1 failed/4 ordinary ignored). Both used private 57-character TMPDIR
paths; the native length matches the earlier failing v2 environment. Context,
verification script and frozen fixtures are unchanged. This closes the bounded
signer regressions with evidence, not the earlier failed log or every native gate.

Linux failed the unchanged `original_public_url_and_expired_grant_contract` at
`rust/tests/tools_server.rs:1242`: execution returned a running result instead of
`grant_expired`. The clock-journal/backwards-event explanation is only a hypothesis,
not an established cause. Do not label the test flaky, replace this failure with
the earlier `945e6a6` PASS, or infer harmlessness from the macOS pass. Astra accepts
the bounded design implementation; **full two-platform acceptance remains open**.

A subsequent [fixed ten-attempt diagnostic](evidence/2026-11-07-grant-expiry-diagnostic.json)
added only isolated test logging of the wall clock, monotonic clock and grant
expiry, preserving the original TTL, sleep and assertions. All ten attempts
passed; the original failure was not reproduced and its cause remains
unconfirmed. A historical guest clock correction overlapped the approximate
test-binary run, but no per-test timestamp proves causation. The diagnostic
results do not replace the failed full Linux run. The original executable and
failure log were preserved; the diagnostic build cache is explicitly distinct
from that frozen executable.

The macOS reservation was released to M1 after signer verification completed.
The M1 worker may cherry-pick this exact commit on its own branch, but its combined
source still requires full native verification; these results do not validate M1
or a future merged tree. No link Opus REVISE finding or scope omission changes.
SIP remains disabled in the test VM, physical two-Mac/desktop acceptance remains
separate, and orderly empty-leaf cleanup makes no broad temporary-residue claim.

## Remaining acceptance work

Earlier Linux Rust verification, `858ddc` real-network E2E, cross-build and
packaging tooling checks retain their source-specific evidence above. Preserve
the completed failed native baseline and Linux `d77ce9e` matrix. Linux `7f0421a`
full verification is now passed; reconcile every replacement native handoff phase.
Earlier `945e6a6` complete Linux verification passed. Integrated `bd065fc` full
macOS Rust verification passed, but its full Linux expired-grant failure requires
diagnosis and verification; no prior PASS validates subsequent code changes.
The new
Rust/link E2E and `f544478` packaging-tooling checks passed;
resolve the returned `ca01275` REVISE findings and obtain exact-head Opus
acceptance without changing original severities; cover the listed network and
operations omissions; implement/verify initial snapshots and whole-secret deletion;
obtain isolated macOS and two-Mac evidence, including ACL protection; then validate
the deployed HTTPS/TURN service and its operating limits. Finish product
firewall/listener/TLS acceptance and complete native
packaging/runtime checks on the final ZeroPW head. Preserve the historical d942 native failures and f544 Go/race/desktop failures.
The later bd065fc full native Rust PASS does not close those separate Go/desktop
gates, the current Linux failure or combined M1 verification. The bounded proposed
[next milestones](remote-sync-next-milestones.md) address authenticated snapshot
onboarding and whole-secret tombstones; they are not implemented work.

This report does not mark any unrun test passed or accept risk on the user's behalf.

## First fixes after the ca01275 REVISE review

The unchanged Opus report was published as a commit-bound [COMMENT review](https://github.com/telicity-ai/zeropw-link/pull/1#pullrequestreview-5810064781). No approval or later Opus PASS exists. Link follow-up commits `d2fa9be` and `f366757` remove root health-probe execution and make revoked identity rotation recoverable across durable prefixes. Linux vet, focused/full Go and server/daemon races passed at f366; native focused rotation tests also passed at exactly that source (three named tests and four durable-prefix subtests, source146-file before/after checks, exit0). Native log SHA256: `c9094dd88b06fd8440f54dd934c43faf70cf2036cfb8ee79b819581a9d801264`. These are injected persistence interruptions, not OS power-loss tests.

Link `83eb55d` additionally refuses an IPv6 SSH lockout before applying the IPv4-only firewall. Linux lint and all114 deployment checks passed. An earlier108-check PASS covered the health-probe change; the initial run and direct diagnostic failed ENOSPC and are retained. Only inactive completed integ-rverify caches were reclaimed, after normal executables were moved and hashed; active M1 source/target/logs stayed untouched. This housekeeping does not validate code.

The [finished native v2 manifest](evidence/2026-11-07-macos-v2-final.json) preserves frozen d942/f544 phase results, including three native ACL regressions passing but full Go/race failures on the unassigned127.0.0.2 address, full Rust failures and desktop fmt/core failures. It is not the f366 focused result and establishes no full native PASS.

Follow-up link documentation at `5444fed` binds these fixes to evidence and corrects TURN fairness, monthly-cost and lost-VM recovery claims. The ZeroPW sidecar remains pinned to f544 until a final reviewed integration. DOS-1, remaining state/CA protection and artifact-gate findings, full post-fix review and deployment remain open. The bounded Rust signer correction is now integrated as `bd065fc`, with Astra design assessment, full macOS Rust PASS and the unresolved full Linux expiry failure recorded above. It does not close the link review findings.
