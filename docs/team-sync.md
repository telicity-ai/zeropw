# Team sharing: direct environment replication

Written 2026-09-16 as a design specification. Four implementation stages were subsequently ported to Rust; current limitations are explicit below. This is not an independent security review PASS.

Share one project environment between invited devices. There is no cloud service, central server or leader. Equal nodes exchange signed commits directly and fold concurrent changes under the same deterministic rules. Preserve the [product](product-intent.md) and [security](security-design.md) boundaries: original secrets never enter agent processes, execution code or tool responses.

## 1. Workflow

1. A promotes `my-app/staging` with `team share`. Connection definitions and encrypted secret versions form an environment document; edits become commits.
2. A invites B. B creates device keys, joins A and receives history. DEKs are wrapped to B's public key.
3. B's agent uses B's trusted `serve`, which relays HTTP or signs SSH from its local replica without exposing original values.
4. An admin edits locally and immediately applies/broadcasts a commit. Other nodes verify/derive it; widening makes their local grants stale and removed connections lose active authority.
5. Concurrent edits converge under total ordering. Irreversible disable/revoke/remove facts always override ordinary commits.

## 2. Decisions

The 2026-09-16 user decision selected direct equal-node replication, not a leased-leader approval scheme. The shared unit is one project environment, independent of project Git. Personal environments remain local. Identities belong to devices; two devices owned by one person require two invitations. A valid one-time invitation is sufficient enrollment approval without a second human step.

Admin/user roles are environment-specific; users consume connections and admins edit/invite. Every member receives the environment DEK because its trusted gateway authenticates locally. Roles are policy, not cryptographic isolation from a device owner.

Use direct host:port connectivity over LAN/team VPN. No NAT traversal or public relay. Offline replicas remain usable and expose synchronization age; revocation cannot reach them until reconnection. Usage audit remains local; only sanitized incident summaries are sent to admins. JSON is input/storage; YAML is output-only through `team/humanview.rs`. TCP is the reference transport behind an interface.

## 3. Model

| Term | Meaning |
| --- | --- |
| Node | One device's trusted `serve` and state directory. |
| Device keys | Ed25519 signing and X25519 agreement keys. Fingerprint is base32 of the first 16 SHA-256 bytes of the signing public key. |
| Member | An invited device; display names do not merge identities across devices. |
| Environment | ID `OWNER_FINGERPRINT-RANDOM_128_BIT_HEX`. Only that owner can author valid `env.init`; advancing another clock cannot claim initial ownership. Local project/environment names may differ. |
| Commit | Signed edits with author fingerprint, consecutive author sequence and HLC. |
| Document | The fold of known commits: connections, secret metadata/ciphertext, members and wrapped DEK generations. |
| Fact | Monotonic irreversible connection disable, secret-version revoke, member removal or incident publication. |

### 3.1 Replicated and local state

Replicate connection target/auth/scope/profile/status, secret metadata/version ciphertext, members/device records, DEK generations/wraps, and admin-only incident summaries. Keep caller identities/tokens, grants, approvals, handle key/handles, policy versions, runs/signer sockets, full audit/alerts, administrator/recovery passphrases, local KMS and unshared environments local.

Local callers represent that device's runtime. Users must be able to grant their local agents authority offline. On any effective connection-definition change, increment the local policy version monotonically. Widening (`HttpScope.widens` or target/auth changes) makes that node's grants stale. Every node applies these rules independently to its own authority.

## 4. Identity and encryption

### 4.1 Device keys

`team init` creates keys with the Rust Ed25519/X25519 modules. Wrap private keys under local KMS in 0600 `team/device.key`. A signed device record binds the agreement key to the signing identity. Private keys never leave the device and have no export command. Device identity does not replace passphrase reauthentication for local secret reveal, recovery or incident closure.

### 4.2 Environment DEK generations

A shared environment has its own DEK, distinct from the local vault DEK. Encrypt secret versions with ChaCha20-Poly1305 and AAD containing environment, secret and version IDs. Commits carry only ciphertext.

Every version records its generation. Retain all decryptable generations; removal creates a new generation and concurrent rotations remain valid, with the later folded generation used for future encryption. Generation IDs in the current implementation are random 128-bit hex tokens chosen before wrapping, not commit hashes. This corrects inconsistent wording in the original section 4.2; section 5.3 and `team/membership.rs::rotate_dek` already specified/generated random IDs.

Wrap each generation separately for each member using ephemeral X25519 agreement, HKDF-SHA256 with `zeropw-team-dek-v1`, environment/generation/recipient context, then ChaCha20-Poly1305. Unwrap only the local share and rewrap under local KMS at `team/ENV_ID/dek/GENERATION.json`. Vault trusted-use/scanning/reveal contracts remain; shared versions select their generation key rather than local DEK.

An admin's `secret put` encrypts locally under the current generation. Messages contain neither plaintext secrets nor unwrapped DEKs.

### 4.3 Invitation and enrollment

An admin creates `team invite --env PROJECT/ENV --role user|admin --name NAME`. The base32 invitation contains environment ID, inviter fingerprint, addresses, a 32-byte secret, expiry (default 24 hours), role and name. Store the secret KMS-wrapped with metadata/consumption state in 0600 `team/ENV_ID/invites.json`. It is bootstrap enrollment material, not a vault credential; HMAC verification needs the original invitation secret.

`team join INVITATION` creates device keys if needed and dials the inviter. Handshake message three proves the invite with ID (first 16 bytes of secret SHA-256) and HMAC over the transcript. The inviter verifies it, marks it used under the state lock, then creates/applies/broadcasts `member.add` with the new device and wraps for all generations the inviter can unwrap. No second approval: possession of the valid unused invitation is authorization.

The joining node receives/folds history and derives its local environment, with names overridable at join. Both nodes display fingerprints. Fingerprint comparison supplements the separately transmitted invitation. Keep invitation strings out of chat/issues/agent context. Before expiry, a leaked invite can enroll whoever consumes it first; enrollment is visible in members/audit and can be removed.

### 4.4 Removal and rotation

`team remove --env PROJECT/ENV --device FINGERPRINT` publishes an irreversible fact. On removal, stop every outbound path immediately, including VECTOR, COMMIT/FACT replay, PEERS and INCIDENT. Reject new handshakes.

An already-open removed-member session gets a receive-only drain window (`team_removed_drain_seconds`, default 5 seconds), not an immediate unconditional disconnect. Accept only a valid `member_removed` fact signed by the drained peer: it may target a device that removed that peer, or the peer itself. A self-removal only confirms the already removed device and cannot remove another member. Reject and audit unrelated removal attempts; ignore other messages and send no responses. Close afterward. This permits simultaneous mutual removals to converge.

An authorized admin removing another device then rotates DEK with wraps for remaining members. New secret versions use the new generation; old ciphertext is not reencrypted because removed members already possess old keys and data. For admin removal of another device, mark active secrets `rotation_recommended` and alert admins. Provider-side rotation alone invalidates previously accessible credentials. There is no automatic provider rotation. Members may remove their own non-owner device; the owner cannot be removed and must transfer ownership first. After receiving a signed self-removal, an active admin creates a new generation excluding the departed device. The rotation records the removal fact hash, so a restart repairs an interrupted rotation without repeating a completed one. New local secret writes fail with `team_rekey_pending` until this rotation is complete; a version prepared with the previous generation must be prepared again. An offline peer cannot apply a removal it has not received. All participants must run a build containing this fix: older builds do not enforce this pending-rekey boundary. Provider-side rotation still invalidates credentials the departed member already knew.

## 5. Documents and commits

### 5.1 Environment document

Store canonical JSON (sorted keys, compact separators) in `team/ENV_ID/document.json` with its folded version vector. Top-level fields are `env_id`, `format` (`zeropw-team-env-v1`), `owner`, `members`, `dek`, `connections`, `secrets`, `settings`.

Members contain name, admin/user role, active/removed status and signed device record (`sign_pub`, `agree_pub`, `sig`). DEK state has `current` and `generations`, each with recipient `wraps` (`eph_pub`, `nonce`, `ciphertext`). Connections carry the existing serialized definition without local policy_version. Secrets contain kind, active_version and per-version staged/active/retired/revoked status, generation, nonce/ciphertext and public metadata. Default `sync_interval_seconds` is 10. Caller/grant/approval/handle/policy-version state is absent.

Recompute `shared_env: ENV_ID` entries in local policy/vault files after folding. Manual edits of derived shared entries are overwritten; unmarked local entries are never overwritten. Skip a colliding local ID and record `local_id_conflict`. Do not derive versions whose generation cannot be unwrapped: only dependent connections become `credential_unavailable`, without breaking other connections or all-vault scanning.

Version IDs are random 128-bit hex tokens in `secret.put_version`, not commit hashes: AAD needs the version ID before ciphertext exists, while commit hashes depend on that ciphertext. Signatures protect IDs; duplicate IDs within a secret are skipped. Local integer version numbers are assigned from fold order starting at 1 and may change after an earlier concurrent commit arrives. Commits and connection definitions reference stable version IDs; integer numbers are local display/API compatibility only.

### 5.2 Commit

```json
{
  "format": "zeropw-team-commit-v1",
  "env_id": "ENVIRONMENT_ID",
  "author": "DEVICE_FINGERPRINT",
  "author_seq": 42,
  "hlc": "1789200000123-0007",
  "seen": {"DEVICE_FINGERPRINT": 41, "OTHER_FINGERPRINT": 17},
  "ops": [{"op": "connection.update", "id": "gh", "http_scope": {}}],
  "sig": "ED25519_SIGNATURE_OVER_CANONICAL_JSON_WITHOUT_SIG"
}
```

This illustrates shape, not a valid signed operation. Each author sequence starts at 1 and increases without gaps. Fill gaps through synchronization; identical sequence/hash is deduplicated, but a different hash for the same author/sequence is rejected/audited as `team_author_equivocation`.

Per-author HLC must strictly increase or reject `team_hlc_not_monotone`. A device cannot insert work before its own first commit; work sorted before its admission is skipped because it lacks membership then. HLC consists of millisecond wall time and logical counter, advanced above the greatest observed clock when authoring/receiving. A commit authored after observing another always sorts later, irrespective of physical-clock skew.

`seen` records the author's folded vector for causality/debugging; ordering uses HLC plus fingerprint, not seen. Hash the canonical commit including sig with SHA-256; store at `team/ENV_ID/commits/FINGERPRINT/AUTHOR_SEQ.json`.

### 5.3 Operations

| Operation | Input and effect | Authority |
| --- | --- | --- |
| `connection.create` | Existing definition with stable secret version ID; first same-ID creation wins. Secret must belong to this environment. | Admin |
| `connection.update` | Replace target/auth/scope/profile/description; derive local version and stale decisions. | Admin |
| `connection.switch_credential` | Shared secret/version or follow-active reference; existing rules. | Admin |
| `connection.disable` | Irreversible fact; reuse requires a fresh ID. | Admin |
| `secret.put_version` | Secret/kind/generation/version/ciphertext/public data; staged. Skip unknown generation. | Admin |
| `secret.set_status` | Active/retired status; revoked uses a fact instead. | Admin |
| `secret.activate` | Replace active version and rebind follow-active connections. | Admin |
| `member.add` | Signed device/name/role/wraps for every available generation. Removed fingerprint cannot rejoin; use new keys. | Admin |
| `member.set_role` | Change a non-owner member role. | Admin |
| `member.remove` | Irreversible removal of non-owner member. | Admin or the target itself |
| `owner.transfer` | Transfer ownership. | Owner |
| `dek.rotate` | New random 128-bit generation ID and wraps; later ordered generation becomes current. | Admin |
| `settings.update` | Synchronization settings. | Admin |

Users cannot author editing commits; local `grant create` is not a shared commit. Removal authority here follows implemented validation and the original detailed operation/mutual-removal rules. The original summary table incorrectly restricted admin removal to the owner and allowed owner self-removal; no product behavior is changed by this documentation correction.

### 5.4 Validation

Every node validates independently, never trusting another node's checks:

1. Correct environment and exactly next author sequence.
2. Signature against the author's device key; membership admission must precede it in folding. Role checks occur at application time.
3. Future wall-clock HLC more than 5 minutes ahead is deferred under `team/ENV_ID/deferred/` until the time catches up.
4. State-independent operation format via existing Connection/HttpTarget/SshTarget/CliProfile/HttpScope validators. State/role/target/profile-secret checks occur while folding.

Failed identity/sequence/signature/format checks go to `rejected/` with `team_commit_rejected` reason/author/sequence audit and block subsequent author sequence. Code-version disagreement can cause rejection; inspect `team status`.

### 5.5 Human view

`team show --format json|yaml` omits ciphertext/wraps/signatures. Log shows ordered commits, times, authors and operations; diff compares views at two commits. YAML is an output-only subset; inputs are CLI/JSON.

## 6. Synchronization

### 6.1 Transport

Transport exposes listen/dial/close, with environment ID and optional invitation proof when dialing. Sessions expose authenticated peer record, send, timed receive and close. Membership/invitation/failure callbacks are additional configuration. The in-process queue implementation is for tests; TCP is the reference.

Frames contain a 4-byte length and ChaCha20-Poly1305 ciphertext, maximum 4 MiB. Team listening is separate from loopback tools/relay. `serve --team-listen HOST:PORT` explicitly binds LAN/VPN; without it synchronization is disabled. Failed handshakes return no descriptive information.

### 6.2 Handshake

Three mutually authenticated steps with ephemeral agreement:

1. Initiator sends protocol version, environment ID, ephemeral X25519 `Ea`, device record and 32-byte nonce.
2. Responder sends `Eb`, its device record and Ed25519 signature over the complete first message plus Eb/responder record. Respond only to an active member or an enrolling initiator that will prove an invitation.
3. Initiator signs the transcript and, when joining, includes invitation HMAC.

Derive directional session keys with HKDF-SHA256 from X25519 agreement, transcript hash and direction context. Full-transcript signatures prevent cross-session replay. Per-direction counters supply frame nonces. Recreate sessions after 10 minutes or membership changes. This is a SIGMA-style composition of standard primitives, not an independent protocol certification. RFC 7748 vectors test X25519; reject all-zero agreement in handshakes and DEK wrapping.

### 6.3 Messages and vectors

Maintain environment vectors mapping fingerprint to last accepted sequence.

| Message | Purpose |
| --- | --- |
| `VECTOR` | At session start/periodically, exchange vector and send missing commits. |
| `COMMIT` | Broadcast new commits immediately; verify and forward received commits except to their sender, deduplicated by hash. |
| `FACT` | Verify/apply/forward irreversible facts. |
| `INCIDENT` | Direct node-to-admin sanitized incident, not relayed. |
| `INCIDENT_ACK` | Admin acknowledges fact hash; sender retries until acknowledged. |
| `PEERS` | Exchange known member addresses for discovery. |

Names/descriptions are bounded administrator data with no controls and length 200, not arbitrary agent strings.

### 6.4 Discovery and connection

Store per-device successful addresses in `team/ENV_ID/peers.json`. Invitations bootstrap addresses; save gossip addresses only after authenticating the expected device.

The original design includes signed UDP multicast discovery at `239.192.47.42:47420` every 30 seconds, containing environment hash/fingerprint/port, as an untrusted hint for a handshake rather than authentication. It is not implemented. Current discovery uses invitations, manual `team peers --add` and verified PEERS gossip; full mDNS is not provided.

Try to maintain sessions to all known members with exponential retry from 5 seconds to 5 minutes. Intended scale is at most dozens of devices. Commit forwarding through a third node permits synchronization without direct connectivity between every pair.

### 6.5 Applying folded changes

Derive effective state under one state lock and audit `team_commit_apply` with author/sequence, operation-kind counts and changed connection IDs, never values.

| Change | Local reaction |
| --- | --- |
| Create connection | Derive at policy version 1; callers see it only with a local grant. |
| Widen/change target or auth | Increment policy version, stale grants, invalidate approvals/old handles; poll cancels live runs/sockets. Admin regrants. |
| Narrow scope | Increment policy version, reevaluate grants in place; live work uses the new scope at the next authentication. |
| Disable | Deny immediately, cancel runs and close sockets. |
| Version/activation/status | Derive vault entries and rebind follow-active connections via `credential_versions_changed`. |
| Membership/roles | Reevaluate sessions; removed sessions stop outbound traffic immediately and follow the receive-only drain rule. |
| DEK generation | Unwrap local share and rewrap with KMS; if no share exists, mark detached and disable that environment's connections. |

The drain rule resolves the original section 6.5 shorthand saying removal immediately closes a session; section 4.4 defines the actual bounded exception.

### 6.6 Offline behavior

Push COMMIT/FACT immediately on live sessions; exchange VECTOR every configurable 10 seconds to repair gaps. Offline nodes use their replica and admins may edit. Reconnect exchanges both directions, including offline facts/commits. Show synchronization age in `team status` and `list_connections.synced_at`; age alone does not deny use. Offline revocation delay is an explicit limit.

## 7. Convergence

### 7.1 Total order

Order by numeric HLC wall milliseconds, numeric logical counter, then author fingerprint, not lexicographic timestamp strings. Identical HLCs on different devices still order deterministically; one author's HLC is strictly monotone. Observed-before-authored work orders causally; unseen concurrent edits use clocks/fingerprints as tie resolution.

### 7.2 Folding

Fold known commits in total order against state at each step. Skip operations when the author lacks active membership/role, targets are absent or facts forbid them. Inspect profile variables against local vault values; skip with `team_op_skipped`/`cli_env_contains_credential` if they match. This check can differ between nodes because their private vaults differ; it affects that node's usability, not other nodes' personal secrets.

Later mutable same-target operations determine effective state; each node reevaluates its local authority. Skips appear in log. A losing author's node gets a deduplicated `team_op_overridden` alert so a human can inspect/reconsider. Late earlier-sorted commits trigger re-folding from the latest usable snapshot and the same derivation rules. Environments are expected to contain dozens of connections/secrets.

### 7.3 Compaction

Store folded snapshots/vectors under `team/ENV_ID/snapshots/`. Compact history before a commit only after every active member's vector includes it and it is at least 30 days old. Otherwise refuse and identify absent members. Never delete env.init, membership, ownership or DEK-generation commits because verification reconstructs identity history from them.

Snapshot transfer is unimplemented and unspecified: a new/long-offline node after compaction cannot fetch deleted history. Do not promise automatic onboarding recovery from compacted snapshots.

### 7.4 Irreversible facts

Signed facts contain environment, kind, target, author, HLC and signature. Validate authority/signature, apply immediately and forward with hash deduplication. Persist `facts.jsonl` outside backup, like the local revocation ledger.

Facts are a monotonic overlay reapplied after folding, restore and synchronization; ordinary commits cannot undo them. Disabled connection IDs, removed fingerprints and revoked versions cannot be reused/reactivated. Use new IDs/keys/versions instead.

Two admins concurrently removing each other can both produce valid reciprocal facts even after the peer-removal fact was received; both end removed and the owner can reenroll fresh keys. The protected owner remains available. Receive-only draining is necessary to avoid losing a reciprocal fact in flight: stop sends immediately, accept only the relevant removal exception during the bounded window, then close. Other traffic remains forbidden.

## 8. Local grants and roles

Owners/admins edit connections/secrets and invite/manage non-owner members. Only the owner transfers ownership; the owner cannot be removed. A member can remove its own non-owner device. Every member can create/revoke local caller grants, authorize local risky requests and view sanitized environment/history. Only admins receive incident summaries.

No node sees another node's caller/grant state. A user's local grants are reevaluated when a shared admin narrows policy. Manual derived-policy edits are overwritten at folding. Roles deter mistakes and preserve accountable history; a device owner already has decryption capability, so they do not establish cryptographic secrecy from a malicious human.

## 9. Incident sharing

The protocol sends sanitized incident ID/time/scope/rule, affected secret/connection IDs, mandatory/recommended tiers and first/last-use/counts to admins. Exclude values, headers, paths, request IDs and handles; scan before sending. Queue signed summaries in `incident_outbox.jsonl` and retry with backoff until a directly connected admin acknowledges the fact hash. No intermediate-node relaying.

Admins persist `team/ENV_ID/incidents/FINGERPRINT-INCIDENT_ID.json`, local rotation flags and alerts. Do not automatically stop other nodes. Provider rotation followed by secret activation distributes a replacement; admins can publish connection-disable facts to contain environment-wide access. Keep summaries after closure; full usage records never leave the node.

Current implementation provides and tests `send_incident_for_all_envs`/`on_incident_open`, but `incident.rs::open_incident` is not wired to it. The protocol exists; automatic incident creation does not yet trigger cross-device notifications. See [implementation](implementation.md), section 11.2.

## 10. Threats

Mutual authentication/encryption and independent verification preserve agent non-disclosure, but shared decryptable replicas increase the number of trusted devices.

| Threat | Control and limit |
| --- | --- |
| Malicious user device owner | Local reveal requires passphrase/audit, but the owner controls state and can extract shared secrets. Trust humans explicitly. |
| Runtime/trusted-process compromise | Local containment and the incident protocol help; trusted-process compromise exposes the shared environment and requires provider rotation. Automatic incident-hook wiring is still absent. |
| Removed member | Deny new sessions/traffic and rotate generations; prior credentials require provider rotation. |
| Forgery/replay/sequence skipping | Signatures, environment binding, consecutive sequences, shape/role/target checks; signing-key compromise remains a limit. |
| Clock manipulation | Defer over-5-minute future commits; within-limit skew can influence concurrent ordering, with signed history. |
| Malicious admin | Can exercise granted administration until removed; signed history provides evidence, not prevention of authorized abuse. |
| Network observation | Encrypted frames hide content, not traffic existence/size; discovery hints are not trust. |
| Listener flooding | Failed handshakes disclose no detail; caps/rate limits reduce impact, not guaranteed DoS prevention. LAN/VPN remains assumed. |
| Backup leakage | Wrapped DEKs/ciphertext protect values; ciphertext length remains visible. |
| Leaked invitation | One-time expiry limits exposure, but first valid consumer can enroll; inspect/remove and rotate as needed. |

Team listener, tools and relay share a trusted process. Team sharing does not fix same-host development isolation limits.

## 11. Non-goals and limits

No central server, leader, quorum, write locks, NAT traversal/public relay, full usage-audit replication, cross-device human identity merging, YAML input, cryptographic user/admin secrecy or provider auto-rotation. Convergence does not guarantee every author's edit wins. Offline replicas retain old authority until synchronization.

There is no reactivation of disabled connections/removed members/revoked versions. To effectively unshare, remove other members and keep the environment ID; provider rotation is still needed to invalidate their previously accessible credentials.

## 12. CLI

`zeropw-admin --state-dir DIR` provides:

| Command | Result |
| --- | --- |
| `team init` | Create device keys once, report fingerprint. |
| `team share --project P --environment E [--name N]` | Reauthenticated promotion; create environment/generation, reencrypt active/staged versions, reissue shared connections as commits. Connections not referencing shared secrets remain local with not_shared. Old local grants become stale. |
| `team invite --env P/E --role R --name N [--ttl 24h]` | One-time invitation; use --address for reachable inviter addresses. |
| `team join INVITATION [--project P --environment E]` | Authenticate/enroll and display fingerprints; enable team-listen for inbound connections later. |
| `team members --env P/E` | Fingerprints/names/roles/state/sync age. |
| `team remove --env P/E --device FINGERPRINT` | Removal fact and eligible DEK rotation; cannot remove owner. |
| `team set-role`, `team transfer-owner` | Role/ownership rules in section 5.3. |
| `team status --env P/E` | Vectors, folded/skipped/rejected/pending counts, sessions and sync age. |
| `team log`, `team show`, `team diff` | Sanitized history/views. |
| `team peers --env P/E [--add host:port --device FINGERPRINT]` | Address management bound to specific devices. |
| `team compact --env P/E` | Conditional local history compaction. |
| `team incidents --env P/E` | Received admin incident summaries and rotation flags. |
| `serve --team-listen host:port` | Enable the separate team listener. |

Existing connection/secret/rotation commands emit commits for mutable changes or facts for disable/revoke, applying locally immediately. Results add `commit: {author_seq, hlc}` or `fact: {hash}` and `propagated_to`. The separate administrator process owns no sessions, so its propagated_to is 0; running serve discovers and forwards changes on its next poll. Shared secret/rotation output uses stable version_id. Principals/grants/approvals stay local. `connection update-scope` remains an alias for `connection update`.

## 13. Implementation and validation stages

All four stages were first implemented in 2026-09-16 prototype work and ported before its 2026-10-03 removal. Test evidence belongs to exact commits, not this plan.

1. **Keys/envelopes/commits/folding:** X25519 RFC vectors, device identity, HKDF wrapping, signatures/shape/HLC/sequence, deterministic fold/facts/snapshots/derivation and stable-version-to-local-number mapping. Targets include team_fold, team_oracle, team_envelope_parity_edges and module tests. Validate roles/skips, signature/environment/sequence failures, future-clock deferral, permutation convergence, late re-folding, monotonic local policies/stale widening, irreversible overlays, generation keys, overwritten derived edits and no plaintext in documents/history.
2. **Transport/synchronization:** TCP/in-process transport, vectors/commits/facts/peers, replay/deduplication, sessions/retries and withdrawal effects. team_transport, team_parity_gaps, team_remaining_contract and sync tests cover membership/authentication, replay/frame tampering, bidirectional and three-node catch-up, concurrent convergence, socket/run withdrawal and no plaintext/DEK on wire. Multicast discovery remains absent.
3. **Membership/facts/CLI:** Invitation consumption, enrollment, removal/generation rotation, monotonic facts and CLI integration. team_membership_sync, astra_team_fact_catchup, astra_team_round2–4 and native_team_cli cover expiry/single-use, history, removed-peer traffic/draining/reconnect denial, new-generation secrecy, mutual removal, restore/facts, conditional compaction and value-free output.
4. **Incidents/E2E:** Signed outbox/ACK/admin flags, override alerts and three-process native_team_e2e. Verify scope narrowing at next request rather than immediate live-run cancellation, offline concurrent edits converging with loser alerts, removed members unable to decrypt new generations and no values in state/output/raw wire capture (`ZEROPW_TEAM_WIRE_CAPTURE`, test-only). Sync/adversarial team tests cover incident delivery and override details. Automatic incident-open hook wiring remains absent.

## 14. Defaults and design decisions

Confirmed choices were immediate leaderless application, invitation auto-acceptance, device-specific keys and continued use of stale offline replicas. Original proposed defaults are 5-minute future-clock tolerance, 10-second sync, 24-hour invitation, 10-minute session regeneration, 30-day compaction, multicast `239.192.47.42:47420`, share-time passphrase reauthentication and node-dependent private-vault profile checks. Multicast is a planned default, not an implemented discovery claim.
