# Real transport E2E rerun — ZeroPW d77ce9e / zeropw-link f544478

A fresh isolated Linux run completed on 2026-11-07 with process exit 0 and
`E2E_RESULT=PASS`: all 66 scenario assertions in [assertions.json](assertions.json)
and a separate log scan for seven synthetic service secrets passed. The seven
secret values were checked in one scan; they are separate from the 66 scenario
assertions. This run tests the inputs below independently of the preserved
[earlier 858ddc0 run](../remote-sync-e2e-2026-11-07-858ddc/README.md).

The actual runner was the local Codex coordinator using **gpt-6.1-sol**. All
product code and test execution stayed inside the isolated Linux
`zeropw-parity` Lima VM with synthetic credentials and controlled endpoints.
No production vault, model, deployment, recovery or administrator keys were
supplied. The coordinator confirmed the execution session returned exit 0;
this evidence collection performed no product execution.

| Input | Exact identity |
| --- | --- |
| ZeroPW CLI source | `d77ce9ed7170f9e2689bc1ecf5244aa9602cc587` |
| ZeroPW Rust source tree | `181f99ddbffedb3b7f5c158d7484afca37be8a8a` |
| zeropw-link source | `f544478a48cea66be816efbed50967bafcacc8ac` |
| Environment | Isolated Linux arm64 Lima VM, kernel `6.8.0-147-generic` |
| Go / coturn | `go1.27.3 linux/arm64` / `4.18.0` |
| Date / logged time window | 2026-11-07; fixture timestamps 11:18:32–11:21:08 (timezone not printed) |
| Result | 66 passed, 0 failed; separate seven-secret log scan passed; process exit 0 |

The log records the input source commits, executable digests and fixture-script
digests. The `zeropw-admin`, `zeropw-link` and `zeropw-linkd` hashes were also
read from this run's VM directory and matched the printed hashes. The admin
and client hashes are specific to this run. The scripts are byte-identical to
the earlier run: there are no removed checks, weakened assertions or special
cases for these commits. [manifest.json](manifest.json) records the source,
executable, script and artifact digests.

The later ZeroPW documentation/pin head
`7b146ec00924e788d286edff20a637417e914f37` has the same Rust tree as the tested
ZeroPW source. The later zeropw-link head
`ca01275c60037b2e008714e646c79a57aa6c1462` differs from the tested link source
only in `README.md`. These equivalences do not assert that
new executable artifacts built from later heads were tested.

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

The raw archive is `zeropw-mlp-evidence/e2e/run-11-d77-f544.log`, SHA-256
`0c37d13e7396fbc15311ef41394620635a82460b37f04c4fa44d74d05f404390`.
The VM runtime directory was `/tmp/zpe.0Xb0AT`; fixture namespaces and processes
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

The revoked-orphan enrollment/restart regression test in the link repository
is separate from these unchanged 66 assertions; this fixture does not claim to
execute that specific subcase. A Linux run cannot validate the macOS-specific
ACL code in the tested link commit. This task performs no Opus review and
closes no Opus finding by itself. Later source or executable changes require
their own evidence.
