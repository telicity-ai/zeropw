# Real remote synchronization E2E

This fixture runs the real `zeropw-admin`, two real `zeropw-link` daemons,
`zeropw-linkd`, and coturn. It complements the desktop core tests, which use an
in-process stand-in for the link service and daemons.

Run it **only inside an isolated Linux development VM with no production keys,
vaults, agent sockets, host mounts, or coordinator credentials**. It creates
synthetic credentials and TEST-NET addresses. Root is needed for private network
namespaces; the vault CLIs and link daemons run as the unprivileged `parity`
user (override with `ZPD_USER`). It does not change the VM host's network rules.

Requirements: a separately checked out `zeropw-link` source tree, Go matching its
`go.mod`, an already built `zeropw-admin`, Python 3 standard library, `iproute2`,
`iptables`, `tcpdump`, `setpriv`, and coturn 4.18.0 at
`/opt/coturn/current/bin/turnserver` (override with `ZPD_TURNSERVER`). Build the
Rust binaries as the unprivileged user before invoking this root-only fixture.

Inside the isolated VM:

```sh
# Record both actual source commits; these are provenance, not review approval.
sudo env ZPE_ZEROPW_SHA=<zeropw-commit> ZPE_LINK_SHA=<zeropw-link-commit> \
  bash scripts/e2e-remote-sync/run.sh /source/zeropw-link /built/zeropw-admin
```

The wrapper reuses the separate repository's maintained
`test/daemon-netns/run.sh` topology, test CA, service, enrollment, and coturn
fixture functions. It checks that fixture's entry point before sourcing the
functions, prints its digest, and uses unique namespace and temporary directory
names. An incompatible fixture fails explicitly. All source remains untrusted
and runs only in the isolated VM.

The topology places the two devices behind separate NAT routers with inbound
filtering. Tests assert:

- B proves the vault invitation and remains outside membership until A approves
  the exact fingerprint; initial history and three decrypted synthetic values
  (login, password, API key) then agree.
- Later versions arrive, an offline B edit reaches A on reconnect, and concurrent
  edits retain both decrypted versions, choose the same active value, and create
  a conflict alert.
- A signed revocation fact reaches a stale peer and stays revoked. Commit vector
  equality alone is not used as evidence of fact delivery. Revoking one version
  can select an older valid version under the existing fold policy; it is not
  treated as deletion of every version of a secret.
- The observed transport is direct, forced TURN UDP, and forced TURN TLS while
  **both devices drop all UDP**. Values are checked after each path change.
- Application and daemon restarts, a two-second process pause, and coturn restart
  recover; replay after restart does not create duplicate commits.
- Server invitations and link tokens are single use; a one-minute server invite
  is rejected after real elapsed expiry. Server enrollment alone grants no vault
  membership. Malformed local protocol requests are refused without reflection.
- Vault member removal and separate service revocation prevent new data access.
- Plaintext/base64/hex forms of synthetic values are absent from runtime logs,
  captured network packets, and sampled writable daemon memory, argv, and
  environment. Memory sampling is an observation at named checkpoints, not proof
  against every possible transient value or encoding.

Only fixed operation labels, counts, paths, and reason codes are printed. Secret
reveal output stays in test memory. The temporary directory printed as `work=`
contains `assertions.json`, logs, binaries and packet capture; namespaces and
processes are removed on exit, and the fixture deletes its synthetic server
secret files. A nonzero exit means incomplete or failed; only `E2E_RESULT=PASS`
marks full completion. Keep the raw log and source/binary/script digests together.

This is Linux simulation of two devices, **not two physical Macs**. The process
pause is not macOS sleep/wake. This fixture does not exercise the native macOS UI,
an OCI deployment, long-duration capacity, power-loss durability, deliberate
packet corruption/reordering, or onboarding from compacted history. Signed
revocation is tested; the product's separate user-facing deletion behavior is not
inferred from it. These require their own evidence.
