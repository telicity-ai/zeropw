# Real transport E2E rerun — zeropw-link 858ddc0

A fresh isolated Linux run completed on 2026-11-07 with exit 0 and
`E2E_RESULT=PASS`: all 66 scenario assertions in [assertions.json](assertions.json)
and the separate log scan for seven synthetic service secrets passed.
This run tests the inputs below independently of the preserved
[earlier cc733dc run](../remote-sync-e2e-2026-11-07/README.md).

The actual runner was a local Codex subagent using **gpt-6.1-sol**. All product
code and test execution stayed inside the isolated Linux `zeropw-parity` Lima
VM with synthetic credentials and controlled endpoints. No production vault,
model, deployment, recovery or administrator keys were supplied.

| Input | Exact identity |
| --- | --- |
| ZeroPW CLI source | `41d217f26a030042c9f0b1caac9417715470c0e1` |
| zeropw-link source | `858ddc07007eedaa978bdbb9ecafeebb7f332668` |
| Environment | Linux arm64, Ubuntu 24.04, kernel `6.8.0-147-generic` |
| Go / coturn | `go1.27.3 linux/arm64` / `4.18.0` |
| Time window | 2026-11-07 10:10–10:13 KST |
| Result | 66 passed, 0 failed; separate seven-secret log scan passed |

The existing Rust binary was copied without rebuilding a duplicate Rust target.
The link source was archived at the exact stated commit and built in the VM
using the existing Go cache. The scripts are byte-identical to the earlier run:
there are no removed checks, weakened assertions or special cases for this
commit. [manifest.json](manifest.json) records all source, executable, script,
fixture and artifact digests.

The fresh run observed:

- Approval-required pairing and fingerprint confirmation; signed-history initial
  transfer; decrypted login, password and API-key equality; later version
  changes; offline edits and reconnect; retention of both concurrent values and
  a visible conflict alert; delivery of an irreversible version-revocation fact.
- Actual `direct`, forced `relay-udp`, and forced `relay-tls` paths. The TLS case
  drops all UDP on both peers and verifies decrypted changed data. Process pause,
  actual coturn restart, and application/daemon restart recover without duplicate
  commits; active sessions and durable vectors are checked.
- Used invite and link-token refusal, real elapsed one-minute invite expiry,
  service-enrolled C failing vault join (`team_join_timeout`) with no secrets,
  malformed protocol refusal without reflection, and separate vault-member and
  service-device revocation preventing new access.
- No observed synthetic vault values in runtime logs, CLI error output or network
  capture in plaintext/base64/hex forms. Three checkpoints sample both actual Go
  daemons' writable memory, environment and argv. The separate scan finds none of
  seven synthetic service secrets in daemon/client/service/coturn logs.

The raw archive is `zeropw-mlp-evidence/e2e/run-10-858ddc.log`, SHA-256
`a69edb050f8ef736c1e4da12b56256ee8a8f211fb4092c455d2ac09cd602d6d8`.
The VM runtime directory was `/tmp/zpe.RCAVNX`; fixture namespaces and processes
were cleaned on exit. Reproduction and detailed methodology remain in
[the unchanged fixture instructions](../../../scripts/e2e-remote-sync/README.md).

This evidence does not cover physical Macs, native macOS UI or ACL behavior,
actual sleep/wake, authenticated snapshot onboarding from compacted history,
whole-secret deletion, power-loss durability, deliberate packet corruption/loss,
long-duration credential renewal, OCI deployment or OCI capacity. Revoking one
version may select an older valid version under the existing fold policy; that
is not whole-secret deletion. Memory sampling is point-in-time observation, not
a proof against every transient value or encoding, and mapped bytes sampled are
not RSS measurements.

The new revoked-orphan enrollment/restart regression test in the link repository
is separate from these unchanged 66 assertions; this fixture does not claim to
execute that specific subcase. This task performs no Opus review and closes no
Opus finding by itself. Later source or executable changes require their own
evidence.
