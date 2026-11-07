# Remote sync MLP: validation and open work, 2026-11-07

Status: **incomplete; no release acceptance and no aggregate Opus PASS**. This is
a dated evidence record, not a change to the acceptance requirements. The
[TURN checklist](remote-sync-turn-checklist.md) keeps its completion gates open.

## Source and execution identity

| Item | Exact source or scope |
| --- | --- |
| Pre-fix ZeroPW source compared | `1f60bc2a3f2b91fa691dfa9f79c81bfb131aabe1` on `feature/remote-sync-mlp`; comparison revision before this documentation update |
| ZeroPW product source tested | `41d217f26a030042c9f0b1caac9417715470c0e1`; its Rust tree `f2c67647fcba83ae78dd6fd10418b6f42a58a6f8` is byte-identical to the compared revision's Rust tree |
| New Rust fix awaiting full verification | `d77ce9ed7170f9e2689bc1ecf5244aa9602cc587`; Rust tree `181f99ddbffedb3b7f5c158d7484afca37be8a8a`, different from the earlier passing Linux tree |
| Current link fixes and sidecar pin | ACL fix `f544478a48cea66be816efbed50967bafcacc8ac`; working `desktop/zeropw-link.json` now pins it. Native product regression and post-fix Opus acceptance are pending. Earlier packaging/E2E checks use `858ddc`, not this pin |
| Link README follow-up | `ca01275c60037b2e008714e646c79a57aa6c1462` changes only the root README after `f544478` |
| E2E fixture/evidence | Earlier fixture/evidence commit `28abd9a450d8328424db5334443f1dd4bbd5cc24`; final `858ddc` run evidence is committed under `docs/evidence/remote-sync-e2e-2026-11-07-858ddc/` at the compared revision. Both runs use CLI source `41d217f26a030042c9f0b1caac9417715470c0e1` |
| Link publication | Private [telicity-ai/zeropw-link](https://github.com/telicity-ai/zeropw-link), [draft PR #1](https://github.com/telicity-ai/zeropw-link/pull/1); not merged or release accepted |
| Link initial review input | `bcdaaecd569a71bf4df07c738869e1e0c7a577e1`; later fix commits `cc733dc`, `858ddc` and `f544478` are outside that review |
| Earlier implementation workers | Actual `claude-opus-5-5`; these were not Sol executions |
| Current local coordinator and fix work | Actual `gpt-6.1-sol`; session-based coordination, not an always-on cloud service |
| Current real-network E2E worker | Actual `gpt-6.1-sol` |
| This documentation recorder | Actual `gpt-6-astra`; evidence reconciliation, not an Opus review |
| Valid initial review scopes | Actual `claude-opus-5-5`: crypto/auth and secrets/logs, including the seven finding verification results |
| Incomplete network reviewer | Logs contain `claude-opus-5-5` and `claude-opus-4-8`; malformed/truncated output, not an accepted complete review |

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
| Real service/daemon/coturn plus ZeroPW sync | Isolated Lima `zeropw-parity` Ubuntu 24.04 arm64 VM, kernel `6.8.0-147-generic`, Go 1.27.3, coturn 4.18.0; ZeroPW `41d217f` + link `858ddc`; [final committed evidence](evidence/remote-sync-e2e-2026-11-07-858ddc/README.md) | PASS, exit 0: 66/66 scenario assertions plus separate log scan for seven synthetic service secrets. Earlier `cc733dc` run retained separately |
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
| ACL-fix sidecar pin packaging | Isolated Linux, `desktop/package-f544478.log` | PASS: 61 tests for the `f544478` pin; still fixture-based tooling, not native app packaging |
| Frozen-source native macOS Rust verification | Isolated Tart macOS 26.6.2 arm64 VM, synthetic-only, no host-directory mounts; Rust 1.98.1; frozen `1f60bc2`, `macos/rust-verify-1f60bc2.log` | IN PROGRESS WITH FAILURES: fmt and strict Clippy passed; library 662 passed, 2 failed, 4 ignored. Full matrix continues; no overall PASS |
| New Rust fix verification | `d77ce9e`, tree `181f99ddbffedb3b7f5c158d7484afca37be8a8a` | Linux strict all-target Clippy and 244 focused team tests PASS. After strengthening one assertion, full Linux matrix `integ/rust-verify-d77ce9e-linux.log` is IN PROGRESS; no overall PASS. New complete macOS verification pending; earlier source results do not cover this tree |
| Native Go verification | Same isolated Tart VM, Go 1.27.3, unchanged link `858ddc`; delegated to `real_sync_e2e` | IN PROGRESS; no final result recorded. VM execution is not two physical Macs |
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
Linux strict all-target Clippy and 244 focused team tests passed. After one
assertion was strengthened, the full Linux matrix started and remains in progress;
new full macOS verification is pending. Neither the earlier Linux
PASS nor the E2E run using the earlier Rust binary is acceptance of the new tree.

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

## Initial adversarial review and fixes

The lossless [partial review archive](reviews/2026-11-07-link-initial.partial.json)
preserves the original finding severity, location, failure scenario, evidence and
fix recommendation, alongside each rebuttal-verification result and source agent
ID. All seven completed-scope findings have `real: true`. Those verifications
confirm the original findings; they are not post-fix acceptance.

| Finding | Original severity | Original issue | Status at this record |
| --- | --- | --- | --- |
| ZPLINK-OPUS-01 | medium | Unauthenticated challenges can exhaust the shared pool needed for session renewal | FIX IMPLEMENTED/TESTED at `cc733dc`; post-fix Opus acceptance pending |
| ZPLINK-OPUS-02 | low | Enrollment failure-budget check/charge race under concurrent requests | FIX IMPLEMENTED/TESTED at `cc733dc`; post-fix Opus acceptance pending |
| ZPLINK-OPUS-03 | low | Lost enrollment response leaves an orphan device and a stuck local identity | FIX IMPLEMENTED/TESTED at `858ddc`, including revoked-orphan recovery after restart; post-fix Opus acceptance pending |
| ZPL-SEC-01 | low | Socket client sends invite/link tokens without checking server peer UID | FIX IMPLEMENTED/TESTED at `cc733dc`; post-fix Opus acceptance pending |
| ZPL-SEC-02 | low | Service-CA ownership/path checks and separate stat/read permit trust substitution | FIX IMPLEMENTED/TESTED at `cc733dc`; post-fix Opus acceptance pending |
| ZPL-SEC-03 | low | macOS inherited ACLs can bypass mode-only state privacy checks | OPEN: fix committed at `f544478`, Linux checks and OS-only API probe passed; native product regression and Opus acceptance pending |
| ZPL-SEC-04 | low | Root executes coturn build output writable by shared `nobody` UID | FIX IMPLEMENTED/TESTED at `cc733dc`; post-fix Opus acceptance pending |
| DOS-1 | high (partial output) | No pre-HTTP global/per-client connection cap at `internal/server/server.go:343` | Cap implemented/tested at `cc733dc`; original full review and post-fix acceptance remain INCOMPLETE |
| Deployment/operations scope | No verdict returned | Reviewer did not finish | INCOMPLETE |

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
**NOT VERIFIED**; this is a coordinator self-assessment, not a new external
Opus finding. ZPL-SEC-03 remains open until native product regression and Opus
acceptance, regardless of the successful OS-only API probe.

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

The network review's raw `StructuredOutput` input ends mid-sentence; the archive
preserves that input without reconstructing the missing text. Its mixed-model log
does not become a valid Opus 5.5 review by assigning it an Opus role name. The
deployment/operations reviewer returned no result. Claude reported a five-hour
limit resetting **2026-11-07 12:50 KST**; it has not been retried in this record.
No aggregate PASS exists, and no new review covers the security fixes.

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

## Latest verification still running

`integ/rust-verify-d77ce9e-linux.log` is the full Linux matrix for the changed
Rust reader tree. `integ/admin-build-d77ce9e.log` records a successful locked
build of its real admin binary. `e2e/run-11-d77-f544.log` is a new real-network
run combining that binary with link `f544478`; it is still in progress and is
not included in the earlier 66/66 PASS claims. Native verification is likewise
in progress. Completion must be reconciled from final exit markers and logs.

To make room for new verification, inactive MLP jobs `integ-dverify`,
`integ-desktop` and `desktop-core` had their normal product executables moved to
each job's `preserved-product-bins` with SHA-256 records before their remaining
compiled target caches were removed. Sources, logs, prior E2E inputs and the
active verification target were preserved. This separate reclamation is logged
in `linux-cache-reclaim-m1-capacity-20261107.log`; the VM then had about 18 GiB
free. It is not a product test or resource-capacity result.

## Remaining acceptance work

Earlier Linux Rust verification, `858ddc` real-network E2E, cross-build and
packaging tooling checks retain their source-specific evidence above. Finish
the failed frozen native matrix and complete new Linux/macOS verification for
`d77ce9e`, plus affected real-network checks of the new Rust binary. Run affected
packaging/E2E checks for the new link pin `f544478`, and obtain post-fix Opus
acceptance at the committed link head
without changing the original severities; complete the network and operations
review scopes; implement/verify initial snapshots and whole-secret deletion;
obtain isolated macOS and two-Mac evidence, including ACL protection; then validate
the deployed HTTPS/TURN service and its operating limits. Finish product
firewall/listener/TLS acceptance and complete native
packaging/runtime checks on the final ZeroPW head. Native full Rust and Go tests
in the Tart VM are in progress with the frozen Rust failures preserved; no
overall native PASS is recorded. The bounded proposed
[next milestones](remote-sync-next-milestones.md) address authenticated snapshot
onboarding and whole-secret tombstones; they are not implemented work.

This report does not mark any unrun test passed or accept risk on the user's behalf.
