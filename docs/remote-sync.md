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
| `syncing` | session open; commit vectors differ or the required current-session deletion agreement is still pending |
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

- Initial snapshot transfer has a bounded Personal Vault implementation described
  below. Other histories still require their signed originals and refuse missing
  prefixes. Platform validation and external acceptance are separate gates.
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

## 6. First Personal Vault snapshot onboarding

The private runtime in `rust/src/team/bootstrap/`,
`rust/src/team/checkpoint/personal.rs` and `rust/src/import_barrier.rs` supports a
sole genesis owner A adding a fresh administrator B after data compaction. A has
the only positive cut vector. Previous memberships, removals, demotions, ownership
transfers, restore history, ambiguous/deferred/rejected evidence, suffix gaps and
local collisions refuse this profile. Retained A rotations and A-authored
non-removal restrictions remain supported. Ordinary uncompacted joining retains
its existing protocol and authority checks.

Both people reauthenticate. A approves the displayed full B DeviceRecord binding,
including the agreement key; B explicitly accepts the full A record as the
checkpoint attestor for this environment, role, invitation and local mapping.
The existing signing-key fingerprint algorithm is unchanged. A changed full key
or request requires fresh confirmation. The missing DATA prefix and historical
fact completeness are explicitly `administrator_attested`; signatures cannot
detect an approved owner omitting an otherwise unknowable historical deletion.

The exporter freezes the complete admitted cut under the state lock, preserves
original encrypted versions/order, retained authority and data originals, all
admitted facts, current head and current editing generation. B validates original
authenticated JSON bytes, signatures, retained replay, fact overlays and required
ciphertexts in trusted memory. This private runtime plan does not confer the
older complete-history proof guarantees. Keys remain zeroizing trusted memory
and are wrapped locally for installation.

Each encrypted session uses fresh session/onboarding nonces and a fresh challenged,
signed READY after A rechecks its immutable cut. No network wait holds the state
or environment-cache lock. One durable admission intent precedes invitation
consumption; retries recover the same original `member.add`. Renewal requires
both new human approvals and retains that admission. Lost READY before intent
requires a fresh transfer. Cancellation before intent closes that attempt and
discards staging; an accepted install intent must recover or remain blocked.

The private install journal advances PREPARED → INSTALLING → COMMITTED. It reserves
IDs/mapping before ordinary writes, patches shared documents by identity, fsyncs
and reads back writes and parents, and requires the metadata audit before a signed
visibility epoch commits. Receipt and journal bind the cut, approval, challenged
READY, original provenance and target patch digest. All credential starts recheck
the same guarded view through authorization and decrypt/sign start. Lists hide
pending or corrupt imported entries; unrelated state remains usable where surviving
evidence scopes the denial. A lost ACK uses a fresh authenticated challenged
query for the original durable receipt, without reinstalling or claiming convergence.

Desktop requests the private invite probe when existing public member metadata
names one active administrator owner, independent of the local place name. This
routing observation conveys no authority: the CLI validates the complete retained
history and owner profile under its lock before enabling snapshot onboarding.
Other member layouts retain the ordinary invitation command.

Desktop polls the durable attempt every three seconds. It shows approval_pending,
transferring, verifying, installing, installed_syncing, ready, unsupported or
recovery_required. Membership admission alone never reports joined or discards
the pairing code. `ready` still requires fresh ordinary vector/fact/M1 agreement.
Explicit failures distinguish history, key/approval, collision, expiry/renewal,
cut change, timeout, storage and offline peer outcomes.
A receiver retains its transfer lease through terminal status publication and
staging cleanup, so an old failed worker cannot overwrite a renewed attempt.
A closed connection during approval remains an offline retry; both human
approvals and all normal transfer/validation gates still apply.

Post-cut A/B commits retain ordinary signature, next-sequence, HLC, role and
generation checks. Conflicts, monotone deletion, B removal/rotation, restart and
compaction retain the attested floor and originals. Unknown authenticated pre-cut
work, or a removal requiring an unavailable prefix, is preserved privately and
blocks affected derivation/use with `team_checkpoint_history_required`. Known
restrictions deny even when derivation fails. Backups preserve original provenance
and receipts; copied receipts confer no replacement-device authority, and restore
retains the existing restore-pending and current-restriction gates.

Selected history operations share one private lock-bound work budget across
nested acquisition, settlement, append and deferred release: 67,108,864 work,
1,073,741,824 charged bytes and five monotonic seconds after the first lock.
Actual retained canonical slots, original JSON bytes, full record bindings and
complete raw revisions determine the view; a large sequence number never drives
a numeric history walk. Supported sparse histories remain explicitly attested.
Unsupported layouts or limits refuse without dropping originals or restrictions.

Fresh external CLI/Desktop sync-status readers carry the same selected operation
through Runtime fact settlement and the current snapshot-seeded fold, vector and
bounded metadata. Reopened status retains the existing six-second freshness and
M1 digest/ACK gates; persisted receipt or attempt labels alone never prove live
agreement. Authenticated metadata stays readable after removal while credentials
remain denied.

An authenticated effective local removal durably publishes a private monotone
denial before publishing its removing commit. Whole-document before/after folds,
including mixed or ignored operations, determine the effect. The denial and the
ordinary admitted member-removal FACT witness form a monotone union. Any later
failure leaves the denial; retry validates the original again. Committed journal
recovery preserves immutable evidence without reinstalling or reactivating the
recipient. Backup restore cannot replace a current denial with an older allow
view. Metadata remains available while credential projection and new use deny.
All-evidence rollback and external provider revocation remain outside this claim.

Hard transfer ceilings are 64 KiB manifest/ACK, 16 MiB payload, 64 KiB decoded
chunks, 128 KiB chunk frames, 256 chunks, 4 KiB other controls, 1 KiB capabilities,
depth 64 and 65,536 combined commit/fact/version records. This profile has two
devices. The sender keeps one chunk outstanding (below the four/512 KiB maximum).
Private staging and prospective journal/target images are conservatively bounded
to 64 MiB per transfer, with one transfer per environment and two per process
(128 MiB total staging ceiling). Local inventory/environment preflights may refuse
earlier. Total monotonic lifetime is ten minutes with a thirty-second idle limit;
authorization expires with the invitation. Restart discards partial receives and
uses fresh nonces and a full transfer. No compression, archive peer paths or
plaintext fallback is available.

The new runtime/crash/visibility tests and scoped fault/reader tests are synthetic
loopback evidence. Linux results must be bound to the exported final source; WIP
passes do not validate later edits. New native macOS validation is NOTREADY/NOTRUN
and combined validation remains INCOMPLETE until Root validates the same frozen
candidate. Actual new Opus review and Astra acceptance remain separate. Direct and
forced TURN-TLS E2E, physical two-Mac/sleep-wake/GUI/packaging/Oracle/capacity/release
and all historical global resource holds remain OPEN or NOTRUN as previously recorded.
