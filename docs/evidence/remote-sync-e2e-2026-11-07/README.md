# Linux real transport E2E — 2026-11-07

The final run completed with exit 0 and `E2E_RESULT=PASS`: all 66 scenario
assertions in [assertions.json](assertions.json), plus the separate runtime log
scan for seven synthetic service secrets, passed. This is component integration
evidence for the exact inputs below. It is not macOS release acceptance or an
Opus review, and does not cover a later changed source or binary.

Implemented and run by a local Codex subagent using **gpt-6.1-sol**, inside the
isolated `zeropw-parity` Lima VM. No product code, test or build script ran on the
macOS coordinator. The VM had no production vault, model, deployment or
administrator credentials; its network endpoints and values were synthetic.

## Inputs and environment

| Input | Exact identity |
| --- | --- |
| ZeroPW CLI source | `41d217f26a030042c9f0b1caac9417715470c0e1` |
| zeropw-link source | `cc733dcacf9f1c170dcb7469d7d258b368726ed7` |
| OS | Linux arm64, kernel `6.8.0-147-generic`, Ubuntu 24.04 VM |
| Go | `go1.27.3 linux/arm64` |
| coturn | `4.18.0` |
| Time window | 2026-11-07 10:04–10:07 KST |
| Process separation | Two trusted CLI/serve nodes and two real Go daemons; separate NAT namespaces; actual HTTPS service and coturn |

[manifest.json](manifest.json) records source, script, fixture and executable
digests. The `zeropw-admin` binary was copied from the coordinator's isolated
`integ-rverify` build of the stated source. Go binaries were built inside the VM
from an archive of the stated link commit with `-mod=readonly -trimpath`.

The topology reuses zeropw-link's maintained `test/daemon-netns/run.sh` fixture:
two different private networks behind separate stateful NAT routers, an isolated
TEST-NET WAN, and an HTTPS service plus coturn at `198.51.100.10`. Vault CLIs and
device daemons run as the unprivileged `parity` user. Root is used only within the
isolated VM for namespaces, captures and synthetic service fixtures.

## Observed results

| Scenario | Observed result |
| --- | --- |
| Explicit approval | B gets `join_pending_approval`; it is absent from members until A approves the exact requested fingerprint. |
| Initial transfer | Signed history reaches B; decrypted synthetic login, password and API key match. This is not a snapshot implementation. |
| Later versions | Changes to all three kinds arrive and decrypt to the expected values. |
| Offline editing | B edits while its serve and link daemon are stopped; the local edit stays local, then reaches A after reconnection. |
| Concurrent edits | Both values remain decryptable on both nodes; version/status and active value converge; an overridden-operation conflict alert exists. Local import timestamps are deliberately excluded from replication identity. |
| Irreversible fact | A version-revocation fact reaches a stale peer and the revoked version stays revoked. Delivery is checked separately from commit vector equality. |
| Direct | Actual daemon status reports `direct`; signed history and values synchronize. |
| Forced TURN UDP | Both daemons use `--relay-only`; actual status reports `relay-udp`; the changed value arrives and decrypts. |
| Forced TURN TLS, UDP blocked | Both daemons use relay-only/TLS-only settings and both peers drop all UDP in both directions; actual status reports `relay-tls`; the changed value arrives and decrypts. |
| Pause/resume | A two-second SIGSTOP/SIGCONT of B's serve and daemon is followed by successful TLS sync. This is process simulation, not macOS sleep/wake. |
| coturn restart | The actual coturn process is identified, stopped and replaced while UDP remains blocked; the existing daemons automatically reconnect and deliver the next version over TLS. |
| Application/daemon restart | Both sides restart, establish active sessions and converge without duplicate commits. |
| Invite/token reuse and expiry | A third daemon is refused a used server invite and used link token; an independently created one-minute server invite is refused after real elapsed expiry. |
| Service versus vault access | C successfully joins the same service account with a fresh link token but cannot use the consumed vault invitation (`team_join_timeout`) and has no secrets. |
| Malformed local protocol | Invalid JSON, duplicate keys and unknown fields return `invalid_request`; an input marker is not reflected. |
| Vault and service revocation | A removes B, then writes a new value that B cannot read; A separately revokes B at the link service, B reports revoked, and a subsequent join fails. |
| Secret observations | Plaintext/base64/hex forms of synthetic values are absent from both CLI output streams except intended trusted reveal output, runtime logs and captured packets. Three checkpoints sample both daemons' writable memory, argv and environment without finding synthetic vault values. The separate fixture scan finds none of seven synthetic service secrets in daemon/client/service/coturn logs. |

The observed stored commit counts progress from 8 after joining to 28 after the
coturn restart. The assertions require active sessions as well as equal durable
commit vectors; old readiness log lines are not reused after a process restart.

Memory sampling is point-in-time evidence, not proof against every transient
value, every encoding or an arbitrary compromised component. The numbers of
mapped bytes read are not RSS or production capacity measurements.

## Reproduction and artifacts

See [the fixture instructions](../../../scripts/e2e-remote-sync/README.md).
The final coordinator archive is `zeropw-mlp-evidence/e2e/run-9-cc733dc.log`,
SHA-256 `2fa04fc567c43e4cfa058d82f68c8cd280d1141d6764c33d9bea25eff829d066`.
Trial logs `run-1.log` through `run-8.log` are retained in the same private
archive as fixture-development history, not as acceptance of the final inputs.
The final runtime directory was `/tmp/zpe.QNCIEG` inside the isolated VM;
namespaces and test processes were removed on exit.

Fixture-development corrections included stdout versus stderr JSON conventions
of the two CLIs, local import timestamps, fact delivery separate from commit
vectors, coturn retaining a stale pid file after exit, and fresh process
readiness. No product requirement or original review finding was lowered.

## Limits and remaining work

- No physical Mac or native macOS UI was exercised. These results do not satisfy
  two-Mac pairing, actual sleep/wake, macOS socket/ACL or macOS verification.
- There is no OCI deployment or OCI CPU/RSS/traffic measurement in this run, and
  no claim of 100-user/200-device capacity or long-duration reliability.
- Initial onboarding uses signed history. Authenticated snapshot onboarding from
  compacted history remains outside this evidence.
- Revoking one active version can select an older valid version under the
  existing fold policy. Whole-secret deletion/no-resurrection was not tested or
  inferred from version revocation.
- Power-loss/crash durability, deliberate packet corruption/reordering/loss, ACK
  loss, mixed-version upgrade behavior and long-lived credential renewal need
  separate evidence. Unit/integration results elsewhere are not relabelled as
  scenarios executed here.
- This task performed no Opus review and closes no Opus review ID. The partial
  original review and coordinator fix evidence retain their separate status.
