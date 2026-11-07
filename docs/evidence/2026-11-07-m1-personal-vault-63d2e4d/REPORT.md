# M1 / Personal Vault integration with inert M2a dependency

Implementation and requested isolated verification are complete at **63d2e4d8d1f0d6f2b834401767026da8fddb1b9c**. Worktree is clean. This is source-bound implementation/test evidence, not Opus review, Astra acceptance, deployment or full M2 support.

Actual runtime: **gpt-6.1-sol, ultra reasoning, T3 Code through the Codex harness**. No subagents. No Opus invocation or substitute review. The controller's latest coordination reports a provider-interrupted Opus review and a declined fallback; no completed new verdict or deployment is claimed here.

## Exact local source and collection

Prepared base: `44e898db3ae0f48991a1fd821c4700e5d1a1eff5`. Own branch: `t3/m1-personal-vault-integration`, worktree `/Users/ys/.t3/worktrees/zeropw/t3-70c85200`.

Final tree: `489d517b1cf0f75a3610b6c789a38257bae09f88`. Rust tree: `4b628201f8dc089c0579ebbe75ee768ae9861f6c`. Desktop tree: `2413844c89265a3e239be2372d34b1e6e1b2d4bb`.

All local commits were made with `core.hooksPath=/dev/null` and `commit.gpgSign=false`:

```text
d93e9946104caf224a646105fcd70d13df58b970 Integrate M1 permanent deletion into Personal Vault
143cf1b015a2c2d3395226d3e8f7ea4c4b02a885 Keep failed adoption explicit and fix native pairing fixture stream mode
290061380026f9b72b3a67362dd450083fbb441c Reconcile Personal Vault feature table with permanent deletion
50f53af16b4960b5b0be375ad149aefd214d6475 feat: add feature-neutral strict checkpoint parser feasibility gates
67c11dad1f3b13a21f4facca36ec27a2157d9570 feat: implement bounded checkpoint attestation integrity and inert candidates
5ae386b6300c193b02db698ee4ea06662f40ab61 fix: refuse metadata containers before checkpoint projection
63d2e4d8d1f0d6f2b834401767026da8fddb1b9c Observe fixture daemon startup before restart assertions and type delete stubs
```

The three local M2a copies correspond respectively to original `43723aecad3c1f3fca471d155ed5418b9f784329`, `1aa5525e6166b99c0465eb888e9de947bac89433`, and `7bcecfda8571ae40047fae406915f73d2e25bde0`. The controller already collected those originals as `5686afe49e55859c7cdf342b0346a45924f8748e`, `b7d92525e970ba097e44d11cda84eb99dcc100b1`, and `74bb09ade04d6b0b078dd2e8cec0753eab32091a`. Fixture commit e781 was not replayed.

The controller subsequently prepared its own original-M1/M2a Rust union at f0c2263 / published 9819c64. Per source-owner instruction, this worker did not rebase onto it or import M2b. That controller source preparation is not a test result for this branch. Collection must reconcile the final path/hunk diff with the already collected original Rust/M2a code and preserve the additional pairing/adoption corrections; the seven commits are a provenance series, not instructions to blindly replay duplicate source. No other checkout/ref was edited. No push, PR action, merge, deployment, repository-permission or coordinator-runtime change occurred.

`combined-changed-files.txt` lists all **54 changed paths**. `combined-source.diff` is the complete final diff against the prepared base. `m1-integration-provenance.json` accounts for the nine requested cumulative M1 commits and the four parent copies excluded from replay.

## Implemented behavior

The complete cumulative M1 backend is integrated: fresh-admin permanent stable-ID deletion; active shared-environment admin authorization; idempotent retry and no reuse; signed secret_deleted facts; a monotone durable deny/fact ledger independent of vectors; restore union and known-identity provenance; retained encrypted history and shared/unrelated encryption credentials; and rejection of the next HTTP authentication or SSH signature, including existing handles and bound sockets.

The encrypted-session extension retains existing handshake/AEAD/canonical formats. CAPS precedes ordinary data. Bounded original control bytes, exact complete admitted-fact digests, current-session durable ACKs, empty-set capable agreement, five-second unsupported-peer refusal, reconnect/change invalidation, six-second capable status leases and atomic initial transport publication are preserved together. No partial unknown-fact subset or vector-only deletion completion was introduced. Version revoke remains separate.

The current Personal Vault owns the action: ItemDetail has a distinct permanent item delete, and VaultPage uses the existing danger ConfirmDialog with fresh password, busy/duplicate protection, localized errors and password clearing. It sends only id/admin_passphrase. Real metadata is secret_id, deleted status, permanent_id=true, provider_revocation_required=true, local|pending, optionally the signed fact. Shared deletion reports pending after local durability. Success reloads durable local metadata; failures retain the item/dialog appropriately. Explicit deleted state, history visibility, blocked reveal/copy/replace and existing one-version revoke are retained. The mock command remains explicitly unsupported. KO/EN keys/placeholders, events/reasons and unsupported-device copy are complete; actual backend caller=null delete audit records are not assigned an invented administrator attribution.

Core/IPC/Tauri additions preserve vault_unlock, language/settings, remote commands and the sidecar pin. All 19 clean cumulative Rust paths were recomputed at the actual starting base; signer/transport additions were narrow. Existing signer/path/ownership and concurrent wire-capture fixes remain. team/link.rs and DEVIATIONS.md were already identical and retained. Removed dashboard/copy/team-components paths were not restored. No layout redesign, labels feature or extra secret types were added.

The authorized M2a dependency adds exactly the five checkpoint module files and four tests plus pub mod checkpoint. All nine new files remain byte-identical to 7bcecfd. M1 pyjson/sync/ledger/provenance and the UI were preserved. This library produces administrator_attested / integrity_checked_not_admitted inspection candidates. It adds no runtime caller, admission receipt, installer, KMS/private-key authority, transport feature or UI support. M2 snapshot onboarding and all M2-G01 through M2-G10 remain open. No M2b module was imported.

## Diagnosed corrections and preserved evidence

The initial integrated d93e994 native run reproduced both unchanged pairing failures before approval, with handshake_channel_closed instead of pending. A separately frozen 8258a8d diagnostic export ran the predetermined refusal-alone, approval-alone and parallel-pair cases. Metadata-only traces show fake UnixStream bridge io::copy reads returning WouldBlock/errno35 and shutting down before handshake completion. One parallel initiator independently reached the true-after-CAPS-failure path with errno22 and then timed out. These are fake Rust daemons/Unix bridges, not evidence against the f544 Go daemon or TURN.

Accepted fake-daemon sockets are now explicitly blocking. Original first-pending, approval/denial and fingerprint assertions remain. Checked wiring reports team_session_closed when an accepted session has already closed without an actually received pending mark. Generic closes/timeouts were never reclassified as pending. A regression fails before this correction, and all 79 sync/retry tests then pass. A controlled real UnixStream test completes a valid synthetic HMAC invitation proof: normal receipt authenticates pending; delaying until the unchanged responder linger closes yields explicit CAPS/receive failure, not fabricated pending. The original failed-send/backoff/receiver assertions remain.

The complete M1-only 2900613 runs passed Rust on both OSes (101 steps, Linux1659/native1662) and frontend343, but desktop failed: the new test stubs used an overly broad Vitest getMockImplementation type, and unchanged supervisor tests observed zero recorded starts. Those full logs/source audits remain in final-linux/final-native. Native original pairing scenarios passed in that source. The supervisor core target stopped later targets, so those old partial core counts (Linux157passed/1failed, native156passed/2failed) are not complete core passes.

The stub correction captures backend.call.bind(backend); TypeScript/Vite and 17 vault tests pass. An independent controlled child barrier proves a ready status socket can precede the owned child's start record. Test-local stable-start markers now follow the initial exit_after decision, and affected tests observe that precondition before SIGKILL/configuration/count assertions. The shared helper is unchanged. All four original supervisor tests and the diagnostic pass together. Original counts, 650/1300ms backoff assertions and existing timeouts are unchanged. See diagnosis.md and supervisor-diagnosis.md for exact limits and raw files.

Earlier negative/setup results are retained: absent delete UI/copy tests, missing vitest after wrapper source replacement, DOM disabled-versus-aria-disabled test mismatch, formatting output, a zero-test ignored native invocation, and diagnostic attempts that reused old Cargo artifacts before source mtimes were corrected. These are not manufactured passes or accepted source/binary bindings. The actual bounded diagnostic trio was rebuilt and remains failed under its original assertions. The 143cf1b full runs were explicitly superseded for a factual documentation correction; only proven descendants of the owned drivers were signalled, raw logs retained, and all922 source bytes/modes still matched afterward. They are incomplete, not PASS. preparation-notes.json records these boundaries.

Original M1 source/logs and the historical Linux grant-expiry failure are unchanged. Later success does not establish that historical failure's cause, erase it or label it flaky. The original M1 and M2a reports/hashes are retained by reference. Both mandatory plan hashes matched the supplied values. The completed old M1 cache reclamation record is copied as data; this worker deleted no cache or other job and never touched the preserved five Linux binaries.

## Exact final verification

All following results are for **63d2e4d8d1f0d6f2b834401767026da8fddb1b9c**, with 931 committed source files/executable bits matching before and after both OSes. Every phase and driver exit is zero.

| Check | Linux Lima | macOS Tart |
| --- | --- | --- |
| Unchanged bash rust/verify.sh | 105/105 steps, 1709 passed, 0 failed | 105/105 steps, 1712 passed, 0 failed |
| Ordinary ignored signer probes | 4, all four separately executed/passed | 4, all four separately executed/passed |
| Unchanged bash desktop/verify.sh | 8/8 steps, 343 frontend + 198 core passed | 8/8 steps, 343 frontend + 198 core passed |
| Release private parser | 12 passed | 12 passed |
| Release public payload depth/256KiB stack | 1 selected test passed | 1 selected test passed |
| Source audit | 931/931 before/after match | 931/931 before/after match |

The full Rust command includes strict formatting/Clippy, lib/bins, all100 integration targets, four explicit signer probes and ten doc tests. Desktop includes npm-ci with install scripts disabled, static/type/build checks, all frontend tests, formatting/strict Clippy, freshly built product bins and the complete core workspace with ignored integration tests included. No target/assertion was skipped or relaxed. The release commands are separate obligations, not a claim of an entire release-profile integration matrix:

```sh
cargo test --locked --offline --release --manifest-path rust/Cargo.toml --lib team::checkpoint::strict_json -- --nocapture --test-threads=1
cargo test --locked --offline --release --manifest-path rust/Cargo.toml --test team_checkpoint_payload full_verifier_total_depth_64_65_and_post_parse_helpers_on_256_kib_stack -- --nocapture --test-threads=1
bash rust/verify.sh
bash desktop/verify.sh
```

## Environment and binding limits

Every product, dependency, formatter, helper, build and test execution occurred in the authorized credential-free guests. Host work was Git, source/evidence text/archive/hash operations and authorized guest transports. No production vault/model/deployment/recovery/admin key was requested or inspected. The dedicated synthetic SSH key was used only by its supplied path, with no agent/forwarding, strict dedicated known hosts and no key-byte readback.

Linux: zeropw-parity, parity uid/gid2000, aarch64 kernel6.8.0-147-generic; Rust/Cargo1.98.1, Go1.27.3, Node22.20.0/npm10.9.3, Python3.12.14. Own job m1-personal-vault-integration through the trusted vmrun wrapper. Native: only zeropw-mlp-macos, macOS26.6.2/25G83 arm64; Rust/Cargo1.98.1, Go1.27.3, Node24.22.0/npm11.19.1, Python3.12.15, OpenSSL3.5.9 at the supplied openssl@3/pkg-config paths. Native target is an owned APFS clone of the completed M1 cache; the original remains untouched. No unrelated UI VM, other job, Tart reconfiguration, host mount or network/credential configuration was changed.

Both profiles: CARGO_BUILD_JOBS=1, CARGO_INCREMENTAL=0, DEV_DEBUG=0, TEST_DEBUG=0, CARGO_NET_OFFLINE=true, ordinary022 process umask. TMPDIRs are owned0700; native is exactly57 ASCII characters, Linux36. Release uses the unchanged Cargo release profile. No assertion-disabling or stack-size workaround was added. Environment/isolation logs and exact driver scripts are retained. Guest NAT and disabled native SIP remain limitations, not physical-host isolation evidence.

combined-commit-binding.json independently matches all931 bytes to Git blobs. combined-protected-boundaries.json verifies all protected paths, full M2/M2a contract text and original pyjson prefix unchanged; Cargo/locks/features, canonical/common helpers, fixtures, verifiers, AGENTS, CI, harness and sidecar pin are preserved. No RawValue API or raw_value feature was enabled. final-source-bindings.json contains primary hashes and both source audits. verification-summary.json retains every step/exit/count. Normal binary hashes identify built artifacts; provenance is additionally bound through the source/build logs. SHA256SUMS inventories all evidence except itself.

## Remaining acceptance and work

No new real-link-daemon deletion E2E, two physical Macs, sleep/wake, signed/notarized packaging, native GUI deletion walkthrough, IPv6/OCI capacity or exhaustive deliberate crash/ENOSPC injection at every new durable write was run. Existing storage/derive failure tests and historical real failures remain. Provider keys/copies and existing external operations are not erased by vault deletion. Old binaries cannot apply new deletion facts; unsupported downgrade/offline limits remain as documented.

M1 external acceptance, all full-M2 gates, M2b work and deployment remain controller/Astra-owned. Per the unchanged ca01275 tracker: DOS-1 remains HIGH/OPEN (partial original output); ZPLINK-OPUS-03/03-R1, ZPL-SEC-03 and ZPLINK-OPUS-04..11 retain their tracked open/insufficient-evidence status and original severity. Original scenarios already resolved in that review are not reopened or reclosed here. No finding was adjudicated by this worker, and no old or interrupted review is applied to this final source.

Both owned verification drivers finished. Guest source, caches and raw evidence are left in place for collection; no other task was interrupted. The controller's future semantic branch and published9819c64 are not covered by this final-head result.
