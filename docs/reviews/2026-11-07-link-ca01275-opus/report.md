# zeropw-link post-fix adversarial review: exact head ca01275

- Repository: `telicity-ai/zeropw-link`
- Reviewed SHA: `ca01275c60037b2e008714e646c79a57aa6c1462`. Tested code head is `f544478a48cea66be816efbed50967bafcacc8ac`; per the brief, ca01275 changes only README.md.
- Original review baseline: `bcdaaecd569a71bf4df07c738869e1e0c7a577e1`, status INCOMPLETE and never a PASS.
- Date: 2026-11-07, written 2026-11-07T04:10Z.
- Actual model: `claude-opus-5-5` (Claude Opus 5.5), running in the Claude Code harness inside T3 Code.
  - Reasoning-effort value shown to the model by the harness: 10. No other sampling settings were visible.
  - No subagents, workflows or delegates were used. One session did all the work.
- Task brief: `/tmp/zeropw-link-review-ca01275-task.md`, SHA-256 `632d63ba…5617bee`. I verified the hash before reading the brief.
- Overall verdict: **REVISE**. DOS-1 (High lead) is not fixed. This is not a PASS and implies no deployment, native, two-Mac or product acceptance.

## 1. Method and authority boundary

Static review only. On the coordinator host I used only `cat`, `sed`, `grep`, `wc`, `shasum`, plus one inline `python3 -I` script. That script hashed the package files and compared them to `manifest.json`. It imported nothing from the package.

I did not execute any product, dependency, build, test, harness or install code. I read no credentials, made no production or network probes and did not use SSH. I did not modify the reviewed source, the parent checkout, the archive or the evidence.

Every runtime claim below is **static reasoning**, not a test result. Source comments, docs, the old review archive and the validation report were treated as untrusted data.

### Input integrity (verified)

- `manifest.json` SHA-256: `d566b310670cb7dd7cf20498cc4d174852abbe72ae0a5fdb08352324dbc1fb3d` (matches the brief).
- All 146 files under `source/` match both their manifest `sha256` and their Git blob SHA-1. There are no extra or missing files. The manifest records Git modes of 100644 for 125 files and 100755 for 21. The package copies are deliberately non-executable, so I did not compare filesystem modes.
- Original archive `context/2026-11-07-link-initial.partial.json`: SHA-256 `d16fbc72…f516`, which matches `manifest.original_review_archive_sha256`.
- Factual supplement: parent checkout `/Users/ys/.t3/worktrees/zeropw/t3-e26a33fa` at HEAD `4e0e60c1563631566542490c6030dd3bbbe5ab75`.
  - Its `docs/remote-sync-validation-2026-11-07.md` has SHA-256 `654159a8…5c4c`.
  - I read it for status only. It is not review evidence.

### Scope coverage

Read fully, line by line:

- `internal/server/`: `server.go`, `connections.go`, `ratelimit.go`, `challenge.go`, `handlers.go`, `httputil.go`, `netlog.go`, `turn.go`, `coturn.go`, `secrets.go`, plus `tlsreload.go` lines 1-80
- `internal/store/records.go`; `internal/store/journal.go` lines 60-200
- `internal/daemon/`: `client.go`, `peercred_{darwin,linux,other}.go`, `ca_unix.go`, `ca_other.go`, `state.go`, `state_acl_darwin.go`, `state_acl_other.go`, `daemon.go`, `socket.go`
- `link/`: `ice.go`, `quic.go`, `packetconn.go`, `replay.go`
- `deploy/`: `install.sh`, `lib/common.sh`, `release.sh`, `rollback.sh`, `backup-db.sh`, `restore-db.sh`, `healthcheck.sh`, `certbot/deploy-hook.sh`, `bin/zeropw-linkctl`, `coturn/build-coturn.sh`, `coturn/assemble-runtime.sh`, `coturn/render-turnserver.sh`, `coturn/turnserver.conf.tmpl`, `coturn/coturn.lock`, `nftables/zeropw-link.nft.tmpl`, `deploy.env.example`
- `deploy/systemd/`: every unit and conf except the two timers
- `README.md`, `go.mod`

Read in part or skimmed:

- `link/node.go`: lines 1-140, 1180-1330, and its limits and goroutine sites
- `link/signal.go` and `link/types.go`: limits and contracts
- `internal/server/mailbox.go`: bounds only
- `internal/store/store.go`: pragmas
- `cmd/zeropw-linkd/main.go`: lines 190-345 and output sites
- `internal/coturncli/client.go`: bounds and command validation
- `deploy/turnprobe/main.go`, `deploy/turnsweep/main.go`: output sites
- `deploy/internal/turnclient/cred.go`
- `internal/daemon/service.go`: `newHTTPClient`
- `serviceclient/client.go`: redirect policy and scheme
- `internal/daemon/state_acl_darwin_test.go`: test names and fixtures only
- `docs/operations.md`: §4, §7, §10-11 and greps
- `docs/self-host.md`: §8-10
- `docs/daemon.md`: §1-3 and §8.5

Not reviewed (omissions; they affect the depth of the network/link conclusions):

- The rest of `link/node.go` and `link/signal.go`, `link/stream.go`, `link/id.go`, `link/errors.go`, `link/pionlog.go`
- `serviceclient/wire.go`; the rest of `serviceclient/client.go`
- `internal/daemon/{service.go (rest), accept.go, proto.go}`
- `internal/store/{store.go (rest), backup.go}`
- `internal/xfer`, `internal/testpki`, `internal/testsig`
- `cmd/zeropw-link/main.go`, `cmd/linkprobe`
- `deploy/internal/turnclient/{stun.go, client.go}`, `deploy/internal/coturncli`, `deploy/measure.sh`, `scripts/build.sh`
- `docs/{protocol,connection,service}.md` in full
- All `*_test.go` files and the test harnesses under `test/` and `deploy/test/`

## 2. Original findings: disposition at ca01275

None of the original severities has been changed. Each verdict below rests on post-fix code; I did not treat an existing test as proof of a fix.

### ZPLINK-OPUS-01 (MEDIUM, original): **RESOLVED** for the original scenario, with residuals

What the fix does:

- `internal/server/handlers.go:43-55` looks up session-purpose challenges with `s.st.DeviceActive` (`internal/store/records.go:380-388`).
- Only an active device's key goes into the separate `sessionCh` table (`server.go:61,124`), keyed by *device ID* (`handlers.go:53`).
- Unknown and revoked keys land in the enrollment table `s.ch`, so unauthenticated keys can no longer use up renewal capacity for registered devices.
- `takeChallenge` (`handlers.go:69-84`) still checks purpose and key.

Strongest objection: an attacker can still fill `sessionCh` (10,000 entries) if they know about 625 active device public keys. Getting that many requires many accounts, which require operator invites. The original unauthenticated, all-accounts attack is closed.

Residuals:

- The enrollment pool `s.ch` (`challenge.go:42-46`) can still be filled by about 625 IPv4 networks. That blocks new enrollments globally. Availability only, and enrollment is rare.
- When a table is full, the sweep is still O(n) under the global mutex.
- A new, targeted per-device variant is reported as **ZPLINK-OPUS-04**.

### ZPLINK-OPUS-02 (LOW, original): **RESOLVED**

`handlers.go:94-111` now takes a reservation from the per-network and global failure buckets before any body, challenge or invite work (`ratelimit.go:183-206, 238-242`). A non-failure refunds the reservation through a once-guarded `CancelAt`.

So N concurrent attempts need N tokens. When the bucket is empty, the request gets 429 before any lookup.

Strongest objection: outcomes that are not failures are refunded, namely `already_enrolled`, `device_revoked`, `device_limit` and internal errors. But:

- `keyFree` runs before the invite or token lookup (`records.go:197, 232`), so the first two reveal nothing about invites.
- `device_limit` reveals that a 256-bit link token is valid, which an attacker cannot guess.

No bypass found.

### ZPLINK-OPUS-03 (LOW, original): **OPEN**. Original lost-response path resolved; follow-up "safe key rotation" criterion not met

Resolved part:

- On any enrollment error, `socket.go:328-338` proves possession of the stored key (`client.Session`, then `client.Devices`, checking `Self == id`) and adopts the committed enrollment. No new invite is consumed.
- On `device_revoked`, `socket.go:339-357` persists `DeviceID` and `RevokedAt` and sets `phaseRevoked`.
- After a restart, `daemon.go:203-205` restores `phaseRevoked`, and the next enrollment rotates the key (`socket.go:290-310`).
- The shutdown-after-commit case also recovers: the retry gets `already_enrolled`, then session adoption succeeds.

Residual (ZPLINK-OPUS-03-R1, rotation is not crash-consistent):

- Rotation writes the new `device.json` first (`socket.go:296`), then rewrites `config.json` (`socket.go:299-300`).
- At that moment `config.json` holds the *old* `device_id` and `revoked_at` (written at `socket.go:347-348` or `daemon.go:478-484`).
- If the process crashes, loses power or hits ENOSPC between the two atomic renames, every later `Start()` fails permanently at `daemon.go:166-168` ("config.json belongs to device X, not to the key in device.json"). Only deleting files by hand recovers it.
- If `writeConfig` fails in-process, it returns `internal` while the on-disk key already differs from the in-memory `d.id`.

Resolution condition (any one of):

- Clear or tombstone `config.json` before writing the new key. A stale revoked key then self-heals through `device_revoked`, then rotate.
- Have `Start` treat "RevokedAt set and DeviceID ≠ key" as a completed rotation.
- Add a crash-point regression test.

### ZPL-SEC-01 (LOW, original): **RESOLVED**

`internal/daemon/client.go:33-46`: after the dial, `connect` reads the listener's credentials (`SO_PEERCRED` / `LOCAL_PEERCRED`, `peercred_*.go`) and refuses any UID other than the client's own euid. That happens before any invite code or link token is written.

All socket users go through `connect`: `Call`, `CallInto`, `Dial` and `Accept`. A grep finds no other `"unix"` dialer in non-test code. Platforms without peer credentials refuse.

Residual, not a reopen: `prepareStateDir` still checks only the final path component and later re-resolves paths. Socket substitution through a writable parent is now caught by the client peer check. The related state-file race is reported as ZPLINK-OPUS-08.

### ZPL-SEC-02 (LOW, original): **RESOLVED** for the original owner, parent and stat/read-race scenario. macOS-ACL analog reported as ZPLINK-OPUS-06

`internal/daemon/ca_unix.go:18-76`:

- Resolves the parent with `EvalSymlinks`.
- Walks every component from `/` with `openat(O_NOFOLLOW|O_DIRECTORY)`, keeping each directory pinned by descriptor.
- Requires every ancestor to be owned by root or the euid and not group/other-writable, unless the directory is sticky.
- Opens the final file `O_NOFOLLOW|O_NONBLOCK`, requires owner root/euid, a regular file and no 022 bits.
- `loadCA` (`daemon.go:260-291`) then reads from that same descriptor, capped at 1 MiB.

The original owner-A scenario and the stat/read race are closed.

What it does not check: macOS extended ACLs on the file or any ancestor. That is the same mode-only blind spot as SEC-03, and the fix explicitly does not touch the CA. Reported separately as ZPLINK-OPUS-06 so this disposition does not blur.

### ZPL-SEC-03 (LOW, original): **INSUFFICIENT_EVIDENCE**. Fix present and statically plausible; native verification NOTRUN

What the code does:

- `state_acl_darwin.go:20-30` runs `/bin/chmod -N /dev/fd/3`. The checked descriptor is fd 3, the environment is set explicitly to `PATH`/`LC_ALL`, the timeout is 2 s, and any failure refuses the operation.
- It is applied to:
  - the state directory after the owner/type/mode checks (`state.go:100`)
  - every private file read (`state.go:142`), before its bytes are read
  - every temp file before its first byte is written (`state.go:180`)
  - the lock file (`state.go:313`)
- Clearing the directory ACL first means later files inherit nothing from it.

Why it is not RESOLVED:

1. The XNU fdesc setattr forwarding that makes `chmod -N /dev/fd/3` act on the underlying vnode is established only by an OS-only probe in a SIP-disabled guest. The product's native Darwin regression tests (`state_acl_darwin_test.go`) have not run. Status at preparation: "native Go/ACL phases had not started."
2. Nothing checks afterwards that the ACL is actually gone. The guarantee rests entirely on `/bin/chmod`'s exit status.
3. Normalization is silent. The daemon never tells the user an ACL was found, so the docs' advice to revoke and re-enroll after prior exposure (`docs/daemon.md:65-67`) can't be acted on.
4. ZPLINK-OPUS-08 describes a race that defeats the "before the first byte" property when the state directory's parent is attacker-writable.

### ZPL-SEC-04 (LOW, original): **RESOLVED**, with notes

`deploy/coturn/build-coturn.sh`:

- Creates a per-build system user `zpl-build-<random>` (lines 110-119).
- `$work` is 0711, and `src/` and `build/` are 0700 and owned by that user (lines 120, 133-134).
- `ldd` and `--version` run as the build user, never as root (lines 170-176).
- Every build-user process is killed (`pkill -KILL -u`) and the tree is chowned to root *before* root copies anything (lines 179-180). The `chown -R` default `-P` does not follow symlinks.
- The source tarball is digest-pinned before extraction (lines 128-132).
- The upstream LICENSE is shipped (line 190).

Notes, none severe enough to reopen:

- (a) `installed_ok` and the bundle-path `check_links` still use the shared `nobody` UID (lines 41, 48-52, 60-67). They run root-owned copies, so `nobody` gains no authority.
- (b) Root `install` (line 188) follows a symlink planted in the build tree. Only the pinned build itself could plant one, and that build is already trusted to produce the TURN binary.
- (c) Bundle-path concerns are in ZPLINK-OPUS-10.

### DOS-1 (HIGH, original incomplete lead): **OPEN / NOT FIXED** at this head. Partially mitigated

Implemented:

- `internal/server/connections.go:23-55` wraps the listener before TLS (`server.go:361-369`).
- Caps: 256 connections in total and 32 per network (IPv4 address or IPv6 /64, `ratelimit.go:52-53`, `netlog.go:41-50`).
- Over-cap sockets are closed at accept.
- Slots are released once per connection in `Close`. TLS, h1, h2 and shutdown all close the underlying connection.
- The TLS handshake is bounded by `ReadHeaderTimeout` 5 s (`server.go:350`).
- `LimitNOFILE=8192` leaves plenty of headroom. The original single-IP FD/OOM path (about 8192 connections from one IP) is closed.

Still reachable (static reasoning):

- The global cap is a single first-come pool with no fairness and no reservation for authenticated or established clients.
- Eight IPv4 addresses × 32, or one IPv6 /61 if IPv6 is enabled (`--listen :443` is dual-stack, and nftables accepts 443 for `inet`), can hold all 256 slots indefinitely.
- Holding a slot is cheap: keep each h1 keep-alive or h2 connection idle under `IdleTimeout` 90 s (`server.go:353`) with one cheap request, for example a 404 or a 429, every <90 s. That is about 3 req/s in total, far under `RequestsPerIP` (50/s, burst 200).
- Or simply re-handshake every 5 s.
- Every legitimate client that reconnects is then refused at accept: laptop sleep, network change, daemon restart, a new enrollment, or the session-renewal path after its long-poll connection drops.
- So this is still the original *service-wide denial* outcome, now at a lower attacker cost in addresses but no longer one IP.

Also:

- The limits are not operator-tunable. `cmd/zeropw-linkd` exposes no flags for them.
- With `--trust-proxy-header`, all clients share the proxy's 32-connection allowance, because the connection limiter keys on RemoteAddr (`connections.go:29-35`).
- There is no pre-TLS handshake-rate limit per network. On the 1/8 OCPU target, a handshake flood that stays within the connection cap is a CPU-exhaustion path. Not measured.

Memory, goroutines and FDs are bounded in the static sense: 256 connections, per-IP request and challenge limits, an 8 KiB body cap and a 64 MiB mailbox. No load test under 256 hostile h2 connections exists (NOTRUN).

Resolution conditions:

- Per-network fairness that cannot be beaten by a small set of networks. For example, reserve a share for connections that authenticate, or evict idle unauthenticated connections first, with an idle timeout before the first request much shorter than 90 s.
- Lower idle timeouts for connections that have not authenticated.
- Tunable limits, and documented behavior behind a proxy.
- A measured load test on the 1 GB / 1/8 OCPU shape.

Severity of the original lead: HIGH, preserved. My own assessment of the residual: availability-only. On the documented IPv4-only deployment it needs ≥8 distinct addresses, and it denies new connections service-wide. That is at least MEDIUM. It remains a release blocker for a public endpoint.

## 3. New independent findings

### ZPLINK-OPUS-04 (LOW): anyone who knows an active device's public key can block that device's session renewal

- **Where:** `internal/server/handlers.go:43-56`, `internal/server/challenge.go:42-46`, `internal/server/ratelimit.go:55-56`.
- **Trigger:**
  - The session-challenge quota is 16 per *device*, and the device is chosen by whoever asks. Anyone may request `purpose=session` for any active device's public key.
  - From one network (1/s, burst 20), or a few networks for bursts, an attacker keeps 16 live challenges per 60 s TTL for a victim device.
  - The victim's own `POST /v1/challenge` gets 429. When freed slots are swept every 5 s, the attacker races for them.
  - The victim cannot renew its 1 h session, and loses device lists, TURN credentials, signaling and self-service revoke.
- **Who knows the key:** public keys are not secret.
  - They are returned to every account member by `GET /v1/devices` (`handlers.go:290`).
  - They are retained by former or revoked members and by anything that logged device lists.
- **Mitigations:** no data exposure, and the operator CLI still works. A current account member can already revoke the victim outright, so the material extra attackers are revoked devices, former members and anyone holding old device lists.
- **Strongest objection:** the attack needs the public key, which the service does not publish to strangers. Accepted as reducing severity to LOW, not as a refutation.
- **Resolution:**
  - Stateless challenges: `HMAC(server key, purpose || pub || nonce || expiry)` plus a bounded set of consumed IDs.
  - Or a sub-quota per (device, requesting network), so one network cannot fill a device's quota.

### ZPLINK-OPUS-05 (LOW): one account can take all TURN capacity, and docs imply per-device fairness

- **Where:** `deploy/deploy.env.example:27-32`, `deploy/coturn/turnserver.conf.tmpl:79-85`, `docs/operations.md:138-169`.
- **Trigger:**
  - `user-quota=24` per device with `total-quota=120` and `bps-capacity` equal to 120 × `max-bps`.
  - The documented maximum of 5 devices per account × 24 = 120.
  - So one account's devices, honest and fully meshed with restart overlap as the docs size it, or deliberately abusive, can hold every allocation and the whole bandwidth reservation. Every other account gets 486.
- **Doc conflict:** `operations.md:164` says "the cap keeps one device from using the whole VM". That holds per device, but per account the cap equals the server total.
- **Mitigations:** a personal deployment usually has one account. Self-host §8 warns about letting others use the server.
- **Strongest objection:** the target is a personal server. Accepted for severity. But self-host.md explicitly allows other people, and TURN capacity across accounts is not stated.
- **Resolution:**
  - Document that TURN capacity is about one fully relayed account (about 20 relayed pairs).
  - Or add a per-account cap or lower `user-quota`.

### ZPLINK-OPUS-06 (LOW): service-CA trust ignores macOS ACLs on the CA file and its ancestors

- **Where:** `internal/daemon/ca_unix.go:60-76`, `internal/daemon/daemon.go:257-259`, `docs/daemon.md:33-37`.
- **Trigger:**
  - On macOS, an ACE granting another user `write`, `append`, `delete`, `add_file`, `delete_child` or `writesecurity` on the CA file or any ancestor directory passes the mode-bit check.
  - Example: `/Users/Shared/zpl/ca.pem` inside a directory with an inherited `group:staff allow write,delete_child`.
  - That user can then replace the roots the daemon uses for service HTTPS and TURN TLS. The change takes effect on the next start.
- **Impact:** the same as SEC-02. With a network man-in-the-middle position, the attacker gets operator-level power over the victim's link account, but no vault access.
- **Mitigations:** someone (the owner or an admin) has to set the ACL, and an active MITM is also needed.
- **Strongest objection:** the user chose the CA location. That reduces the severity but does not satisfy the code's own rationale, "whoever can change it can impersonate the service".
- **Resolution:**
  - On Darwin, refuse a CA path whose file or ancestors carry ACL entries that grant modification to others.
  - Or document plainly that ACLs on the CA path are not checked, and recommend a root- or own-owned location without ACLs.

### ZPLINK-OPUS-07 (LOW): healthcheck runs release binaries as unsandboxed root, parsing data from internet-facing coturn

- **Where:** `deploy/systemd/zeropw-healthcheck.service:1-7` (no `User=`, no hardening), `deploy/healthcheck.sh:75-93`, `deploy/install.sh:276`. This contrasts with `deploy/release.sh:172-175`, which says "the new binary runs unprivileged here, never as root".
- **Trigger:**
  - The timer runs `zeropw-turnprobe check` and `zeropw-turnsweep status` from `/opt/zeropw-link/current` as root.
  - These parse STUN/TURN and coturn CLI responses with bespoke parsers in `deploy/internal/turnclient` and `internal/coturncli`.
  - coturn runs as `turnserver` and faces the internet.
  - A coturn compromise combined with a logic bug in those Go parsers would give root, a privilege boundary root never needed to cross.
- **Mitigations:** Go is memory-safe; the binaries are first-party release artifacts; the parsers are bounded.
- **Strongest objection:** an exploitable Go parser bug is unlikely. Accepted, hence LOW.
- **Resolution:**
  - Run the probe and sweep as `zeropw-linkd` (via `runuser`, or `User=` in the unit). The TURN and CLI secret files are already group-readable by that user.
  - Add the same systemd hardening as `zeropw-turnsweep.service`.

### ZPLINK-OPUS-08 (LOW): state files are re-resolved by path after the directory checks; with a writable parent on macOS, the seed can be read through an fd opened before ACL removal

- **Where:**
  - `internal/daemon/state.go:74-104`: the check opens the directory by path, verifies it, clears its ACL, then *closes* it.
  - `state.go:158-201` and `:205-277`: every later create, read and rename uses `filepath.Join(dir, …)` path strings.
  - `daemon.go:144-162` is the order of operations.
- **Trigger:**
  1. Another user can rename entries in the state directory's parent (non-sticky and group-writable, or delegated by ACL).
  2. Between the check and `writeDevice`, they swap in their own directory, which carries an inheritable `user:attacker allow read,file_inherit` ACE.
  3. The victim's temp `device.json` is created there and inherits the ACE.
  4. The attacker opens it as soon as it appears (kqueue/FSEvents on a directory they own). The `/bin/chmod` fork and exec take milliseconds.
  5. The victim's `chmod -N` then removes the ACE, but an already-open fd keeps read access.
  6. The seed is written and read through that fd.
- **Linux:** not affected. A zero group mask masks inherited default-ACL entries.
- **Mitigations:** the precondition, an attacker-writable parent, is non-default. Sticky `/Users/Shared` prevents the swap.
- **Strongest objection:** an exotic precondition. Accepted, hence LOW. It still breaks the documented "cleared before the first byte" guarantee and SEC-03's intent.
- **Resolution:**
  - Do all state I/O relative to the pinned directory descriptor (Go `os.Root` or `openat`/`renameat`), so the swap no longer matters.
  - Or refuse a state directory whose parent is writable by others.

### ZPLINK-OPUS-09 (LOW): the "saturated month stays below 10 TB" cost claim is false for 31-day months and ignores overhead

- **Where:** `docs/self-host.md:214-217`, `docs/operations.md:166-169`, `deploy/deploy.env.example:30-31`.
- **Trigger:**
  - `bps-capacity` = 3,750,000 B/s per direction.
  - 30-day month: 3,750,000 × 2,592,000 s = 9.72 × 10¹² B, which is what the docs say.
  - 31-day month: 3,750,000 × 2,678,400 s = 10.04 × 10¹² B. That exceeds 10 TB before counting IP/UDP/ChannelData and TCP/TLS framing overhead (several percent at 1200-byte QUIC packets), API egress and ACME traffic.
  - The self-host wording "capped at 30 Mbit/s in total" also hides that the cap is per direction.
- **Mitigations:** saturation for a whole month is unlikely, and budget alerts exist (the docs correctly say alerts do not stop charges).
- **Strongest objection:** it is a margin, not a design flaw. Accepted, hence LOW. Cost truthfulness is in the brief's scope.
- **Resolution:** lower `bps-capacity` with explicit headroom (for example ≤3.5 MB/s), or state the 30-day and payload-only assumption and the per-direction semantics.
- Note: coturn byte-accounting semantics are static reasoning from the docs and comments here, not measured.

### ZPLINK-OPUS-10 (LOW): release and coturn-bundle digests are self-attesting, and bundle extraction is less strict than release extraction

- **Where:**
  - `deploy/release.sh:147-154` and `deploy/coturn/build-coturn.sh:71-80` take the expected digest from a `.sha256` file shipped next to the artifact.
  - `build-coturn.sh:78`: `tar --no-same-owner -xzf` as root, without `--no-same-permissions`.
  - The bundle path has no equivalent of `check_listing` (`release.sh:99-112`), so links and special files are not refused.
  - The bundle `BUILDINFO` check is a self-declared text line.
- **Trigger:** whoever can substitute the artifact on the transfer path can substitute its digest. Root then installs it, and a bundle may carry setuid bits or symlinks into `/opt/coturn/<ver>`.
- **Mitigations:** single-operator SSH/SCP transfer.
- **Strongest objection:** the operator is trusted. Accepted for severity. But the brief requires "only reviewed artifacts can enter protected release path", and nothing mechanical binds an installed binary to a reviewed digest.
- **Resolution:**
  - Pin the reviewed release and bundle digests out of band (an operator-supplied `--sha256` from the review record, or a signature).
  - Normalize bundle permissions (`--no-same-permissions`, then `chmod`) and refuse non-regular entries, as `release.sh` already does.

### ZPLINK-OPUS-11 (NIT/LOW): docs and operations accuracy

1. `docs/daemon.md:365-371` (§8.5) is stale. It says the macOS-specific code is only `LOCAL_PEERCRED` and the socket-path limit; it now includes the `chmod -N` ACL helper. The service-CA rule in §1 (`:33-37`) understates the new owner and ancestor checks and does not say that ACLs are not checked.
2. Lost-VM recovery (`operations.md:503-506`) warns that invite uses after the backup are lost. It does not say that **revocations made after the last off-VM journal copy are lost too**, so revoked devices come back active. It should tell operators to re-check and re-revoke after a disaster recovery.
3. `install.sh:143-152` only checks the admin CIDR when `SSH_CONNECTION` is IPv4. An operator connected over IPv6 is not warned, and the ruleset (`zeropw-link.nft.tmpl:59`, `ip saddr @admin_v4` only) then blocks new IPv6 SSH. The live session survives through established state.

Resolution: doc edits, plus an IPv6-aware lockout guard (or refuse when `SSH_CONNECTION` is IPv6).

## 4. Scope notes with no finding

Network and link:

- QUIC runs only over the ICE-selected pair (`packetconn.go`) with fixed addresses and no migration.
- TLS 1.3 only, a pinned per-node certificate bound in the device-signed offer and answer, no session resumption (`quic.go:79-140`).
- Bounded: 1200-byte packets with PMTUD off, 64 incoming bidirectional streams and no unidirectional streams.
- Remote candidates are filtered to literal unicast UDP. Loopback is allowed only with the test policy; link-local, multicast, mDNS and zoned addresses are refused (`ice.go:296-347`).
- TURN URL scheme, transport, ambiguity and count filtering; DTLS and STUNS dropped; the TURN TLS dialer uses the daemon's roots with TLS ≥1.2 (`ice.go:78-261`).
- Negotiations are capped at 16 in total and 3 per peer, with 3 connections per peer, an accept queue of 16, and a replay cache that fails closed (`node.go:45-67`, `replay.go`).
- Primary dependencies are pion/ice v4.4.8, pion/stun, pion/turn and quic-go v0.65.0. No bespoke congestion control. The bespoke parts are the signaling, replay and pinning layers and the deploy-only STUN/TURN probe client.
- Not exhaustively traced: the full `node.go` state machine, stream and header handling, and backpressure under stopped peers. No WebRTC or TCP-443 promise is made (`README.md:97-99`).

Server and coturn:

- TURN credentials: TTL 600 s plus a 300 s bucket. After a revocation, `coturn.go` cancels sessions immediately and re-sweeps every 30 s for TTL + bucket + 60 s. At startup it sweeps every revoked key (`coturn.go:279-292`), with `zeropw-turnsweep` as the backstop.
- So a revoked device can make new allocations for at most about 16 min, each living ≤ about 30 s. `operations.md §7` documents this honestly.
- Peer denial covers IPv4 internal ranges, ::ffff-mapped, NAT64, ULA, link-local and multicast, plus an nftables `turn_out` mirror and an IPv6 relay drop. The CLI is loopback-only with a UID filter. The secrets go only into the systemd-credential-assembled runtime config (`assemble-runtime.sh`).
- The logs I checked carry no tokens or secrets: `writeError` codes are fixed strings, client networks are truncated to /24 or /48, and the HTTP error-log text is reduced to categories.
- Path candidates are logged as type/protocol only (`types.go:94-105`).

Deploy:

- `deploy.env` is parsed, never sourced, with a restricted character set.
- Secrets are generated once and never printed (`common.sh:292-314`).
- Units are hardened and use `UMask=0077`. Journald retention is 24 h / 200 MB, and rsyslog drops these programs' messages.
- Release extraction refuses links and special files, and the version probe runs as the service user.
- Rollback restores `previous`. Restore merge keeps revocations monotone through the journal, and replace mode replays the live journal.
- API 443 and TURN TLS 5349 are on separate ports; the ACME deploy hook validates the chain and key before an atomic install.

## 5. Unresolved release blockers

1. **DOS-1** (HIGH lead, open): service-wide connection-cap monopolization with ≥8 networks; untunable limits; no load measurement on the target shape.
2. **ZPL-SEC-03**: native macOS ACL regression and post-fix native evidence are missing. Also needs a post-normalization check or a detection signal (Opus-03 style residual), and ZPLINK-OPUS-08.
3. **ZPLINK-OPUS-03-R1**: key rotation must be crash-consistent.
4. Deployment gate: no mechanical binding of installed artifacts to reviewed digests (ZPLINK-OPUS-10). Nothing has been deployed, and no deployment was reviewed live.
5. Product gaps outside this service review, which this review does not accept: ZeroPW's authenticated snapshot bootstrap and whole-ID tombstone are separate milestones.

## 6. Evidence status: explicitly NOTRUN

Nothing was executed by this review. In particular, none of the following were run:

- `go vet`, `go test`, race tests, the Darwin cross-build, or the native macOS Go/ACL regressions (`state_acl_darwin_test.go`)
- netns E2E or coturn lab tests
- `deploy/test/*`
- a load or DoS test of the 256/32 caps
- an h2 idle or slow-peer memory test
- a TURN bandwidth or cost measurement
- a crash-point rotation test
- the session-challenge exhaustion repro
- an ACL race repro
- any install, release or rollback rehearsal

Results reported by others and not re-verified here (taken from the dated validation report, treated as untrusted context):

- f544 Linux vet, full suite and race tests PASS
- d77ce9e + f544 netns E2E: 66 assertions plus a 7-secret scan, PASS
- macOS OS-only `chmod -N` FD probe, in a SIP-disabled guest
- frozen d942 native Rust FINISHED FAILED: 4 failed steps
- native f544 Go/ACL phases not started at 03:53:15 UTC

None of these is physical two-Mac, native packaging, sleep/wake or deployment evidence.

Suggested tests for the coordinator's isolated synthetic VMs:

- 8-source idle-connection monopolization against `Serve`
- per-device session-challenge exhaustion
- a kill between `writeDevice` and `writeConfig`
- native Darwin `state_acl_darwin_test.go` plus a post-`chmod` ACL readback
- the parent-swap ACL race on APFS
- a CA-path ACL refusal test
- a non-root healthcheck run
- a bundle containing setuid and symlink entries

## 7. Aggregate verdict

**REVISE.** Seven original findings:

| Finding | Severity | Status |
| --- | --- | --- |
| ZPLINK-OPUS-01 | MEDIUM | RESOLVED (with residuals) |
| ZPLINK-OPUS-02 | LOW | RESOLVED |
| ZPLINK-OPUS-03 | LOW | OPEN (rotation crash-consistency) |
| ZPL-SEC-01 | LOW | RESOLVED |
| ZPL-SEC-02 | LOW | RESOLVED (ACL analog is new finding 06) |
| ZPL-SEC-03 | LOW | INSUFFICIENT_EVIDENCE |
| ZPL-SEC-04 | LOW | RESOLVED |

DOS-1 (HIGH) is OPEN.

There are 8 new findings, 04 through 11, all LOW or NIT. The network/resource and deployment/operations scopes are complete in this report, within the omissions listed in §1.

This verdict does not imply deployment readiness, native macOS acceptance, two-Mac acceptance, snapshot or deletion completion, or ZeroPW product acceptance.
