# zeropw-link adversarial review: exact head 3eb9727

- Repository: `telicity-ai/zeropw-link`
- Reviewed head: `3eb972745ced7d8d60806254e8703c04b475099f` (frozen package). The last tested implementation is `6e7939d`; `3eb9727` adds only docs/evidence. No new full-head runtime PASS exists, and I did not run one.
- Date: 2026-11-07, written about 09:50Z.
- Actual model: `claude-opus-5-5` (Claude Opus 5.5), Claude Code harness in T3 Code. The harness showed a reasoning-effort value of 10. No other sampling settings were visible. No subagents, workflows or delegates were used.
- This is a new review. It does not continue or accept anything from the failed `4af` attempt.
- **Aggregate: REVISE.** DOS-1 (original HIGH) stays OPEN. This is not a release, deployment, native-acceptance, two-Mac or product approval.

## 1. Input integrity (verified)

- `manifest.json` SHA-256: `b82fb9191a0e992fa4eab21f08c578d8c359fe6b7ebf5778b7325459f4f92737`. It matches the brief.
- 169/169 files under `source/` match their manifest `sha256`, byte count and Git blob SHA-1.
  - No files are extra or missing, and there are no symlinks.
  - Every file is a read-only regular UTF-8 file with no execute bits.
  - The manifest records Git mode 100755 for 21 shell scripts and 100644 for the rest.
- I used the context files as listed in `context/context-files.json`. I read them as untrusted data: the original ca01275 report, the original partial archive, the native/Linux collection and the parent 44e docs/evidence. I did not modify `source/` or `context/`.

## 2. Method and limits

- Static review only, using `cat/sed/grep/wc/shasum` and one stdlib `python3 -I` hashing script kept outside the package.
- I executed no product, test, harness, build or install code. I made no network, SSH or keychain access and read no credentials.
- The Darwin ACL ABI was checked against my knowledge of Apple's public `<sys/acl.h>` API, not against freshly fetched documentation. That is a stated limitation.
- Runtime evidence cited below is Sol's (gpt-6.1-sol) isolated-VM evidence, as recorded in `source/docs/evidence/2026-11-07-native-final-6e7939d/`. I did not rerun it.

### Scope read fully

- **Server:** `internal/server/{connections,server,ratelimit,netlog,handlers,challenge,httputil,turn,coturn,secrets,mailbox}.go`
- **Store:** `internal/store/{records,store,journal,backup}.go`
- **Daemon:** `internal/daemon/{ca_unix,ca_other,trust_alias_darwin,trust_alias_other,acl_native_darwin,state_acl_darwin,state_acl_other,state,daemon,socket,accept,client,peercred_darwin,peercred_linux,service}.go`
- **Link:** `link/{node,signal,replay,quic,packetconn,ice,stream,pionlog}.go`, plus `link/types.go` lines 60-122
- **Service client:** `serviceclient/wire.go`, and `serviceclient/client.go` lines 1-446
- **Commands:** `cmd/zeropw-linkd/main.go`, and `cmd/zeropw-link/main.go` lines 200-319
- **Deploy scripts:** `deploy/{lib/common.sh, lib/artifacts.sh, release.sh, install.sh, healthcheck.sh, rollback.sh, bin/zeropw-linkctl}`, `deploy/coturn/{build-coturn.sh, assemble-runtime.sh, turnserver.conf.tmpl}`, `deploy/nftables/zeropw-link.nft.tmpl`, `deploy/deploy.env.example`
- **Units:** `zeropw-linkd.service.tmpl`, `coturn.service.tmpl`, `zeropw-healthcheck.{service,timer}`, `zeropw-turnsweep.service`
- **Deploy-only STUN:** `deploy/internal/turnclient/stun.go`
- **Tests:** `internal/server/{connections_policy_test, connections_linux_test, session_challenge_fairness_test}.go`, `internal/daemon/{state_acl_darwin_test, trusted_acl_darwin_test}.go`, `internal/daemon/security_regression_test.go` lines 16-83
- **Evidence and status:** `docs/review-fixes-2026-11-07.md` and every file in the 6e7939d evidence directory

### Scope read in part

- `deploy/restore-db.sh` 30-95 and `deploy/backup-db.sh` 30-76
- `internal/coturncli/client.go`: command validation and bounds
- `deploy/internal/turnclient/client.go`: TxID and integrity checks only
- `internal/server/tlsreload.go`: structure only
- `internal/daemon/proto.go`: bounds only
- Test helpers: `internal/daemon/helpers_test.go` `raw()`, `internal/daemon/state_test.go` 180-260, `link/node_test.go` 549-590
- Docs:
  - `docs/service.md` 376-410, plus greps
  - `docs/operations.md` 120-240 and 508-536
  - `docs/self-host.md` 200-227
  - `docs/daemon.md` 30-80 and 376-398
  - `README.md` 40-60

### Not reviewed (actual omissions; they limit the depth of the conclusions)

- **Tests** other than those listed above. This includes:
  - most of `link/*_test.go`, `internal/server/*_test.go`, `internal/daemon/*_test.go` and `internal/store/store_test.go`
  - `cmd/*/main_test.go`, `serviceclient/client_test.go`
  - `deploy/**/_test.go`, `test/coturnit`
- **Test harnesses:** `test/{netns, daemon-netns, zeropw-interop, sockxfer}`, `deploy/test/*`
- **Link, client and command code:**
  - `link/{errors.go, id.go (only grep), export_test.go}`
  - `serviceclient/client.go` 446-485
  - `cmd/linkprobe`
  - the rest of `cmd/zeropw-link/main.go`
  - `internal/{xfer, testpki, testsig}`
- **coturn CLI:** `internal/coturncli/{cancel.go, fakecoturn}`, `deploy/internal/coturncli`
- **Deploy tools:** `deploy/{turnprobe, turnsweep}`, `deploy/internal/turnclient/{client.go (rest), cred.go}`
- **Deploy scripts:** `deploy/{measure.sh, certbot/deploy-hook.sh, coturn/render-turnserver.sh}`, `scripts/build.sh`
- **Other units:** the timers and journald/rsyslog configs not listed above
- **Docs:** full `docs/protocol.md` and `docs/connection.md`, `docs/darwin-acl.md`, and the rest of `docs/{daemon,operations,self-host,service}.md`

The brief asked for the ca omissions to be completed. Done: `link/node.go`, `link/signal.go`, `serviceclient/wire.go`, the daemon/store code and the deploy STUN parser. Not completed: all tests, and the full protocol/connection/service docs.

## 3. Original findings at 3eb9727

Original severities are preserved. The ca01275 history is kept: that report's verdicts stand as written for that head.

### ZPLINK-OPUS-01 (MEDIUM): RESOLVED.