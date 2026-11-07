# Permanent secret deletion (M1)

Implemented for review on 2026-11-07 by gpt-6.1-sol, ultra reasoning,
T3 Code / Codex harness. Verification and external acceptance are separate.
Authenticated network snapshots remain M2 and are not implemented here.

Run `zeropw-admin secret delete --id <stable-id>` or choose **모든 버전 영구 삭제**
in the Personal Vault item detail (**Permanently Delete All Versions** in English). The human must reauthenticate as administrator.
A shared environment also requires this device to be an active team administrator.
The command returns metadata, never a value. Retrying the same deletion succeeds.
The user-chosen ID is permanent: register a replacement under a different ID.
There is no display-name expansion or provider-side deletion.

All current versions and versions received later become unusable. Retiring or
revoking one version keeps its existing separate meaning. A concurrent/offline
edit to a deleted identity stays in encrypted history, is marked unusable and
records `team_op_skipped` with reason `secret_deleted`. Current local attempts to
put or activate the ID fail explicitly. Unrelated local entries and shared DEK
generations remain intact; deleting an identity does not delete a shared key.
HTTP requests and SSH signatures check the durable deny state, including already
issued handles and already bound signer sockets. Existing external operations and
SSH sessions cannot be undone. Vault deletion does not revoke the credential at
the provider or erase copies a human already obtained.

A shared deletion is a signed `secret_deleted` v1 fact with exactly
`{"secret_id":"<stable-id>"}` as target. Existing environment, signature,
active-member and administrator admission checks apply. Previously admitted facts
keep their signed local admission receipts across later role changes. New facts
from removed or non-admin authors are refused. Each distinct admitted signed fact
hash remains part of the deletion set, even when several facts target one ID.

`vault/tombstones.json` is an additive, deny-only ledger, created only when needed.
It retains private identity metadata, all admitted shared deletion facts by hash,
local provenance of derived deleted identities, and environments with authenticated
nonempty peer announcements. Admission writes
the local receipt and durable deny ledger before ordinary fact-log application.
An interrupted append can therefore be repaired from the ledger. Fold applies
deletion independently of commit vectors, at every final overlay, including local
snapshot seeds. The ledger and fact log outlive compaction. No network snapshot
trust is inferred from those local caches.

Encrypted backups add the ledger only when it exists. Restore unions it with
current deny state; an old archive never replaces current facts. Known shared
ownership and deletion provenance also survive a backup made before sharing,
while unmarked local collisions remain independent. Restore keeps
execution blocked until administrator acknowledgement reapplies current facts and
derivation. Missing authority history for a restored signed tombstone fails
closed. After loss of every current state copy, an old backup cannot know about a
later deletion that it never received. No operator recovery or promise of erasing
already obtained copies is introduced. Downgrading a tombstoned vault to an old
binary is unsupported.

## Encrypted session extension

The existing handshake, AEAD frames, signed commit/fact bytes and all nondeleted
v1 persisted fixtures remain unchanged. New sessions send this control before
ordinary replication:

`{"type":"SYNC_CAPS","v":1,"features":["secret_tombstone_v1"]}`

The additive controls are at most 1 KiB. Their root keys are unique and exact;
version is integer 1; capabilities contain at most 16 unique ASCII feature
strings of at most 64 characters. Unknown features do not imply support.
Malformed controls close the session. Capability state belongs to the current
authenticated peer/session/environment only.

Capable peers exchange `TOMBSTONE_STATE` and `TOMBSTONE_ACK`, each containing
`type`, `digest` (64 lowercase hexadecimal characters), and `request_id` (32
lowercase hexadecimal characters). Digest is SHA-256 of canonical sorted JSON of
the sorted unique array of all admitted deletion-fact hashes. Empty sets use the
same rule. Request IDs contain 128 random bits and change with the local set and
session. At most one current request and one peer state are retained per peer.
Announcements precede ordinary data. Bounded existing fact replay (64 persisted
lines per vector) reconciles both directions to the union; no deletion is
downgraded to a version revoke or omitted for an unsupported peer.

ACKs are computed from the complete locally admitted set, after signature/role
checks, durable storage and successful durable fold/derivation. An advertisement
is neither deletion authority nor proof of storage. A matching request can be
retried after ACK loss. Disk or derivation failure produces no ACK. Wrong digest,
request, old session and replayed ACKs cannot establish agreement. A new deletion,
changed reverse state, membership change, disconnect or restart clears readiness.

Capable peers need a fresh current-session ACK even for an empty set, plus a
fresh equal stored commit vector and matching reverse state. A genuinely
nondeleted legacy peer retains v1 vector-only behavior. Any known admitted or
advertised nonempty deletion set makes capability mandatory. Established legacy
sessions close; new unsupported sessions close after five seconds without
capability (`team_peer_feature_unsupported`). Offline/unsupported peers remain
pending; local deletion remains durable. The desktop explains when the other app
needs updating. Session status contains only metadata; capable agreement also has
a six-second status lease renewed by the live process. This lease does not prove
that a remote offline binary has applied a new fact.

## Acceptance remains open

Source integration is based on M1 `8258a8d` over coordinator `44e898d`, with the current Personal Vault UI preserved. The task evidence is stored separately under `m1-personal-vault-integration-20261107`; source-bound results must be read there. The original M1 native desktop pairing failures remain preserved and are not acceptance for this integration.
No Opus review or physical two-Mac acceptance is claimed. M1 remains open until
both platform matrices and external review cover the final head. M2 authenticated
snapshot onboarding remains a separate proposal.
