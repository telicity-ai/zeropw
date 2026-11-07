# Remote sync between my own Macs (MLP)

Written 2026-11-06 as the working specification for the macOS MLP. Implementation
evidence, test runs and deployment state are recorded separately; this file is not a
claim that any of it passed.

## 1. Decisions (user, 2026-11-06)

These supersede earlier documents where they conflict, including the "no NAT
traversal / no public relay" limit of [team-sync.md](team-sync.md) §2 and §11 for
this feature only.

- Target: individual users and individual developers. "Connect my two Macs and my
  logins, passwords and API keys sync, encrypted."
- macOS only for this MLP. Linux and Windows are not release conditions. Existing
  Linux CI and tests are not weakened or relabelled.
- Sync runs version by version while both devices are online. Each device keeps its
  vault locally. The server stores no vault plaintext, no decryption key and no
  offline copy of the vault.
- Server use is enrolled with an invite code, without e-mail accounts.
- Direct connection first; otherwise a self-operated coturn relays. No VPN, no SSH
  server, no full WebRTC stack for the user. No full Iroh SDK.
- The connection module and the service layer live in a separate repository
  (`zeropw-link`). ZeroPW keeps the adapter, vault pairing approval, encrypted
  version sync and the macOS experience.
- Oracle Cloud free VM to start; temporary loss of remote sync is acceptable. TCP
  443-only corporate networks are not a release condition (TURN TLS runs on 5349).

## 2. What is reused

Remote sync is the existing team replication ([team-sync.md](team-sync.md)) carried
over a new transport. Existing v1 signed bytes, handshake and encrypted frames
remain unchanged. M1 adds a fact kind and encrypted session controls as specified
in [the deletion contract](whole-secret-deletion.md), preserving the old
nondeleted formats under `rust/PORTING.md` §1 boundaries 1 and 2:

| Requirement | Existing mechanism reused |
| --- | --- |
| Version identity and predecessor | Signed commit `(author, author_seq)`, consecutive per author; `seen` vector; HLC + fingerprint total order (team-sync §5.2, §7.1). Device clocks alone never decide order. |
| Initial sync | A joining device receives the signed history through `VECTOR` exchange and verifies every commit (§6.3). This is signed history, not a snapshot transfer; compacted history cannot onboard a new device (§7.3 limit). |
| Later sync | Only commits missing from the peer's version vector are sent (§6.3). |
| Offline edits | Stored locally as commits; exchanged both ways on reconnect (§6.6). |
| Concurrent edits | Every `secret.put_version` is kept; mutable fields resolve by total order and the losing author gets `team_op_overridden` (§7.2). Nothing is silently lost: the overridden version stays in history and in the vault. |
| Single-version revocation and connection disable | These irreversible facts (§7.4) are re-applied after every fold, so a stale peer cannot reactivate the revoked version or disabled connection. Revoking one version can leave an older valid version active. M1 adds permanent whole-ID deletion and a conditional session agreement gate; see [the deletion contract](whole-secret-deletion.md). Acceptance remains open. |
| Duplicates, lost ACKs, restarts | Hash deduplication, consecutive sequences and vector repair; a commit is applied only after it is durably stored under the state lock. |
| Authenticity before apply | Signature, environment, sequence, role and format checks before folding (§5.4). |
| End-to-end encryption | The team handshake (X25519 + Ed25519, SIGMA-style) and ChaCha20-Poly1305 frames run inside the link stream. TURN TLS and QUIC TLS are not relied on for this. |

The encrypted vault file is never copied or overwritten between devices.

## 3. New pieces in ZeroPW

### 3.1 Link transport adapter

- Address form `zpl:<device-id>` where the device ID is 26 characters `[a-z2-7]`
  (zeropw-link protocol §1). Accepted wherever team addresses are accepted
  (`team invite --address`, invitations, `team peers --add`, `PEERS` gossip).
- `serve --link-socket PATH` and `team join --link-socket PATH` route `zpl:`
  addresses through the local `zeropw-link daemon` socket; `HOST:PORT` addresses keep
  using TCP. `serve` also accepts inbound link streams (service label `zeropw-team`)
  and runs the unchanged team handshake on them. Without `--link-socket` nothing
  changes.
- After an inbound link session authenticates as member `F`, the node records
  `zpl:<link peer>` as an address of `F`, so either device can dial the other.
- A peer with several addresses is dialled through them in turn: a failed dial moves
  that peer to its next address for the next attempt. This keeps LAN TCP sync
  available when the link service is down.
- The link daemon is a separate process. It receives only the bytes of the encrypted
  team session. It never receives vault keys, DEKs, plaintext secrets or the
  administrator passphrase.

### 3.2 Explicit pairing approval

An invitation may require approval: `team invite ... --approval`. Its output adds
`"approval":"required"`.

- When a device proves such an invitation in the handshake, the inviter does not
  consume it yet. It records a join request `{request_id, invite_id, fingerprint,
  first_seen_at, last_seen_at, attempts}` (at most 8 per invitation, newest kept),
  completes the encrypted handshake, sends one `{"type":"JOIN_PENDING"}` frame and
  closes. Only a party that proved the invitation secret ever sees that frame.
- `team join` then fails with reason `join_pending_approval`; `detail` carries
  `self_fingerprint` and `inviter_fingerprint` so both screens can show them.
- `team join-requests --env P/E` →
  `{"env_id","requests":[{"request_id","invite_id","fingerprint","first_seen_at","last_seen_at","attempts"}]}`.
- `team approve-join --env P/E --fingerprint FP` marks every pending approval
  invitation of this environment that has a request from `FP` as approved for exactly
  `FP` → `{"env_id","fingerprint","approved_invites":[...]}`. The desktop runs it with
  administrator re-authentication.
- `team deny-join --env P/E --fingerprint FP` revokes those invitations →
  `{"env_id","fingerprint","revoked_invites":[...]}`.
- The next join attempt from `FP` consumes the invitation exactly as before
  (state lock, single use, `member.add` with wraps). A different fingerprint still
  gets a pending request, never membership.
- Approval is per device key. The user compares the fingerprint the requesting Mac
  shows with the one the approving Mac shows. Possession of the pairing code alone
  is not enough.

Server enrolment (zeropw-link invite or link token) is separate from this approval.
An operator who can issue server invites cannot produce the invitation secret or the
approval, so cannot add a device to a vault environment.

### 3.3 Sync status for the UI

`serve` writes `team/ENV_ID/sync_state.json` (0600, atomic replace, at most every
2 s and only on change):
`{"updated_at","self","peers":{FP:{"session":bool,"since","peer_vector","vector_received_at","transport":"link"|"tcp"|null,"dial_failures","next_attempt_at","last_error","last_contact_at"}}}`.
Values are metadata only.

`team sync-status --env P/E` combines that file with the local store →
`{"env_id","self","serve_updated_at","conflicts":N,"peers":[{"fingerprint","name","state","session","transport","last_contact_at","next_attempt_at","last_error"}]}`
where `state` is one of:

| state | meaning |
| --- | --- |
| `up_to_date` | session open, fresh equal stored commit vectors, and (for capable peers or known deletion state) exact current-session durable deletion agreement |
| `syncing` | session open, vectors differ |
| `retrying` | no session, a dial failed and another is scheduled |
| `offline` | no session and no recent contact |
| `never_connected` | no address or no contact yet |

`conflicts` counts unacknowledged `team_op_overridden` alerts for the environment
("충돌 확인 필요"). `up_to_date` is never reported before the commit is durably
stored on both sides, because vectors are built from stored commits.

## 4. User flow (desktop)

Device A: existing or new vault → "내 기기" → enter server invite code once →
"기기 추가" produces a one-time pairing code (`zeropw://pair#…`) after administrator
re-authentication. The code carries the service URL, a one-time link token, A's
link device ID and one approval-required team invitation per shared environment.

Device B: new vault (or existing) → "다른 Mac과 연결" → paste the pairing code → B
enrols to the service with the link token, shows its own and A's fingerprints and
asks A. A shows the request with B's fingerprint; the user confirms they match and
approves. B joins each environment, receives history, and both show the sync state.

Removing a device: "연결 해제" on either device publishes the team removal (and DEK
rotation where applicable) and revokes the device at the link service. ICE,
allocations and similar terms appear only in the diagnostics view.

## 5. Limits

- Initial snapshot transfer is not implemented. Onboarding uses signed history;
  a new device cannot recover the required deleted history after compaction.
- M1 implements permanent whole-secret tombstones, administrator deletion and
  deletion-aware session agreement. [Its contract](whole-secret-deletion.md)
  separates implementation from platform verification and external acceptance.
  Old binaries cannot synchronize tombstoned state; update the other device.
- Sync needs both devices online. Nothing is queued on the server.
- A server outage blocks new remote connections; local vaults and LAN TCP sync (when
  configured) keep working.
- Revocation at the link service stops new rendezvous and new TURN credentials at
  once; an existing TURN allocation can outlive it up to credential expiry plus
  allocation lifetime. Vault access is refused by the team layer independently.
- Environments created after pairing need another pairing code.
- Two physical Macs were not available to the implementer at writing time; see the
  [dated validation report](remote-sync-validation-2026-11-07.md) for what was and
  was not run, and the [proposed next milestones](remote-sync-next-milestones.md)
  for the snapshot and deletion gaps.
