# Proposed remote-sync milestones: snapshots and whole-secret deletion

Prepared 2026-11-07 by `gpt-6-astra` from read-only inspection of ZeroPW Rust
source `41d217f26a030042c9f0b1caac9417715470c0e1` (Rust tree
`f2c67647fcba83ae78dd6fd10418b6f42a58a6f8`, unchanged in compared revision
`1f60bc2a3f2b91fa691dfa9f79c81bfb131aabe1`). **This is an engineering
proposal, not implemented behavior, test evidence or release acceptance.** No
product code, existing protocol or requirement changes accompany this plan.
Current evidence remains in the [validation report](remote-sync-validation-2026-11-07.md).

## Existing mechanisms and gaps

| Source | What exists | What the next slice must add |
| --- | --- | --- |
| `rust/src/team/sync.rs`: `handle_vector`, message dispatch, `early_commit_quarantined` | `VECTOR`/`COMMIT`/`FACT` exchange; missing history is requested and eventually quarantined when the peer cannot supply it | Explicit capability negotiation and authenticated snapshot bootstrap; never label a missing compacted prefix as synchronized |
| `rust/src/team/sync.rs`: `TeamSync::compact` | Requires old commits and active-peer coverage; saves a prefix snapshot/record and retains identity, membership, ownership and DEK-generation history | A transferable checkpoint with a separately specified trust contract; retain the existing compaction gates |
| `rust/src/team/fold.rs`: `snapshot_of_prefix`, `fold_with_snapshot`, `snapshot_record` | Local snapshots preserve the fold before later removals/facts overlay, vectors and version order; records track facts and removal schedules | Validate a network checkpoint independently of local cache loading. A local snapshot record is not a peer signature or authorization proof |
| `rust/src/team/sync.rs`: `Fact`, `validate_fact_target`, `verify_fact`, `fact_role_ok`, `receipt_fact`, `send_fact_catchup` | Signed, authorized, replayed facts; local admission receipts authenticate local decisions only | Whole-secret tombstone type, validation, admission, persistence and replay, with explicit compatibility behavior |
| `rust/src/team/fold.rs`: `Facts`, `op_secret_put_version`, `set_secret_status`, facts overlay, `derive_local` | Revocation set contains `(secret_id, version_id)`; secret entries contain multiple versions and an active version | Monotone whole-secret state that blocks all versions and later reactivation of the deleted identity, including after a snapshot/restore |
| `rust/src/vault.rs`: version states and status mutation | `staged`, `active`, `retired`, `revoked`; local version selection and connection rebinding | Separate whole-secret deletion semantics; do not redefine existing single-version revocation as deletion |

The existing snapshot files are useful local fold caches, not remotely
authenticated checkpoints. The missing signed commits cannot be independently
reverified once deleted. Adding a sender signature authenticates who attested to
a state; it does not prove that state equals every deleted historical commit.
That trust distinction must be explicit in the new contract.

## M1: Whole-secret tombstone, with no implicit resurrection

Bound this slice to one project/environment's secret identity, its derived local
credentials and dependent HTTP/SSH authorization. Do not add provider-side
credential deletion, generic file synchronization or automatic secret recreation.

1. Implement `secret delete --id <stable-id>` with administrator reauthentication
   and, for a shared environment, active team-administrator authority. The existing
   user-chosen `--id` is the identity: deletion permanently tombstones that ID,
   including unknown versions. Reuse is rejected; recreation must explicitly use
   another ID. Do not add a display-name feature. A concurrent/later `put_version`,
   activation or replay cannot revive the deleted ID. Use the additive signed
   `secret_deleted` fact with target `{"secret_id":"<stable-id>"}`, bound to the
   existing environment and fact-authority/signature rules.
2. Extend fact shape/signature/admission/replay and `Facts` monotonically. Apply
   the deletion overlay on every fold and derivation, including snapshot-seeded
   folds. Preserve the tombstone even if encrypted versions are later removed.
   Do not rely on commit-vector equality: facts have their own delivery path.
3. Make derivation leave no usable active credential for a deleted identity and
   invalidate dependent usage capabilities before new gateway requests or SSH
   signatures. Preserve unmarked local entries and the existing ID-collision
   protections. Keep single-version revoke semantics unchanged.
4. Add an explicit authenticated administrator delete command/desktop action and
   metadata-only audit result. Define idempotent retry behavior. Explain that
   vault deletion neither revokes a provider key nor erases copies a human already
   obtained. Preserve deletion state across restart, compaction and backup restore;
   do not permit execution from a stale restore before current facts are applied.
5. Implement the additive session capability and durable-ack gate below. Current
   peers reject unknown fact kinds, and commit-vector equality does not include
   facts. Do not silently omit deletion or downgrade it to version revocation.

### M1 decision: minimal compatible session gate

Astra decision, 2026-11-07: the command policy above and this bounded contract are
ready for the implementation worker. They remain **unimplemented**, require tests
and external review, and do not close any current release gate. Grounding:
`TeamSync::handle_message` ignores unknown message types, `send_vector` currently
sends before feature negotiation, `handle_vector` records only commit sequences,
and facts replay separately. Every send path and readiness calculation must honor
the new gate; adding only a handler is insufficient.

- Keep existing signed commits/facts, handshake, encrypted frame format and all
  v1 canonical bytes unchanged. Add three bounded control messages **inside the
  existing authenticated, encrypted team session**, never through service-account
  metadata or an unauthenticated socket announcement. Use existing canonical JSON
  helpers. Do not change old persisted fixture meaning or rewrite nondeleted v1
  state merely to add empty defaults.
- On each new authenticated session send
  `{"type":"SYNC_CAPS","v":1,"features":["secret_tombstone_v1"]}` before the
  new implementation's ordinary data frames. Remember capability only for this
  session and authenticated peer/environment; never reuse a prior-session result.
  Each new control frame is at most 1 KiB. Validate types, duplicate/unknown keys,
  version, at most 16 feature strings and 64 ASCII characters per feature. A
  well-formed unknown feature is not support for tombstones.
- A legacy session in an environment with **no known admitted or advertised
  nonempty tombstone set** retains existing v1 behavior; old peers may ignore
  `SYNC_CAPS` and retain the old vector-based status without an ACK. Once the local
  environment contains a tombstone, or an authenticated peer announces a nonempty
  tombstone set, require current-session `secret_tombstone_v1` before ordinary
  replication. Gate initial/periodic `VECTOR`, fact replay, commit/incident
  broadcasts, held queues, inbound processing and status. Clear readiness
  immediately. Existing legacy sessions are closed; a new peer that supplies no
  capability within five seconds of session authentication is closed with local
  reason `team_peer_feature_unsupported`. Do not send a partial unknown-fact subset
  and call the replication successful. Never drop stored edits or tombstones.
- Compute `tombstone_digest` as lowercase hex SHA-256 of the existing canonical
  encoding of a sorted, unique array of hashes of **all locally admitted signed
  `secret_deleted` facts** for that environment. Include neither rejected facts
  nor unverified announcements. The empty-set digest is derived by the same rule.
  Multiple valid facts for one deleted ID remain distinct hashes; ordering or
  duplicate delivery cannot change the digest. Preserve this set through fold,
  compaction and restore. Existing signature/role admission remains mandatory.
- For a capable session send
  `{"type":"TOMBSTONE_STATE","digest":"<64-hex>","request_id":"<32-hex>"}`.
  Capable peers exchange this state and its durable ACK even for the empty set;
  they use the ACK to establish fresh current-session agreement, not legacy mode.
  Generate the 128-bit random request ID anew per session and per changed local
  set; keep at most one current request per peer. Announce before resuming ordinary
  vectors, then use the existing bounded fact replay to converge the sets. The
  digest is a reconciliation hint, not proof or authority to install/delete data.
  On an incoming changed digest or newly admitted tombstone, clear readiness
  immediately; receiving the reverse-direction fact must not leave an earlier
  equality result valid.
- Reply
  `{"type":"TOMBSTONE_ACK","digest":"<64-hex>","request_id":"<32-hex>"}`
  only after signature/authority checks, durable fact storage and durable local
  application/derivation are complete, and the receiver's own complete admitted
  set computes to that exact digest. Never echo an unverified advertised digest
  as an ACK. If sets differ, exchange missing facts in both directions until the
  union converges; a smaller set cannot acknowledge away additional local facts.
  A storage/derive error yields no ACK and leaves readiness false. An ACK lost in
  transit may be retried idempotently on the same request.
- The readiness gate is conditional: **capable peers, or any known nonempty
  admitted/advertised tombstone set**, require the existing fresh commit-vector
  condition **and** an ACK on the current authenticated session matching the
  sender's current request ID and exact current local tombstone digest, with no
  conflicting reverse-direction state pending. Revoke this proof on disconnect,
  restart, local/received deletion or peer digest change. Announcements, a cached
  capability, vector equality and an ACK from another session do not establish
  durable deletion delivery. Add metadata/reason handling for unsupported or
  waiting peers without leaking secret values.
- The only ACK-free exception is a genuinely nondeleted legacy peer that ignores
  capabilities, with no known nonempty admitted/advertised set. Once any tombstone
  is admitted, its monotone fact set must never become empty or be omitted through
  fold, compaction, restart or restore; missing compatibility metadata cannot
  downgrade that environment to legacy readiness. An unresolved nonempty peer
  announcement also blocks the exception: later silence or an omitted field is
  not proof that deletion vanished. Do not rewrite old nondeleted fixtures or
  persist empty default fields to implement this distinction.

Delete remains locally durable while peers are offline or unsupported; report
that they have not synchronized, rather than waiting forever or undoing deletion.
An already-old binary's offline vault/UI cannot be forced to apply a new fact.
When tombstones are required, the upgraded side must disconnect/report unsupported
and never claim that peer is up-to-date. This is the same offline revocation
limitation, not permission to
allow resurrection after a supported peer receives the tombstone. Replacing a
new binary with old software is not a supported downgrade for tombstoned state;
state that limitation explicitly without changing old fixture bytes.

Additional gate tests: unchanged nondeleted v1 interoperability; old peer that
ignores capability frames; cap timeout and reconnect; false/malformed capability;
new deletion during an established legacy session; ACK before durable application,
wrong digest/request/session ACK and replay; reverse-direction concurrent deletes;
commit vectors equal while facts differ; duplicate facts, lost ACK, restart,
disk-full/derive failure; unknown feature names; size/queue limits. Test empty-set
capable peers waiting for their fresh ACK separately from genuinely nondeleted
legacy peers retaining vector-only status. A peer lacking support must never be
reported as synchronized by the upgraded CLI/UI when tombstones are required.

Acceptance cases: delete a secret with several usable versions; delete while an
offline peer adds or activates a version; deliver delete before/after the commits;
duplicate and replay it; restart and compact on both sides; replay an older
snapshot and restore an old backup; attempt deletion as user/removed member and
from another environment; try both HTTP and SSH use after application. Assert
that no prior or unseen version becomes active and useful unrelated connections
still work. Test explicit new-identity creation separately from resurrection.

Deliverable: one bounded PR with the format/compatibility contract, CLI/UI behavior,
meaningful failure-boundary tests, isolated Linux/macOS verification and an actual
Opus review of its exact head. Keep this milestone open while either platform or
review evidence is missing.

## M2: Authenticated snapshot onboarding after compaction

The separate [M2a schema decision](decisions/m2a-schema-2026-11-07/decision.md)
and [bounded Sol task](decisions/m2a-schema-2026-11-07/implementation-task.md)
freeze the first pure byte/parser/attestation/integrity component. These are
actual Astra design outputs, not implemented snapshot support. M2-G01 through
M2-G10 remain open; there is no runtime capability, admission or installation
authority in that first slice. A subsequent isolated dependency probe found
legacy behavior changes from the proposed `raw_value` feature. The separate
[parser revision](decisions/m2a-schema-2026-11-07/parser-compatibility-revision.md)
selects original-byte cursors and typed Serde seeds without Cargo/feature changes;
the bounded implementation at source `7bcecfda8571ae40047fae406915f73d2e25bde0`
passed PC-R1–R4 and the Linux portion of PC-R5, including the unchanged full
104-step/1,681-test Rust matrix. [Source-bound implementation report](evidence/2026-11-07-m2a-7bcecfd/REPORT.md).
Its private attestation/integrity candidates remain inert. Native macOS,
actual Opus review, M1/UI combined verification and every full-M2 gate remain
open. The full contract below remains required.

### Decision and exact trust boundary

Astra decision, 2026-11-07: implement **administrator-attested bootstrap** for a
freshly approved recipient, under the contract below. This is a design decision,
not implementation, validation or Opus acceptance. It requires M1's admitted
monotone tombstone set and compatibility gate. This inspection used the parent
checkout at `2c38d44d63cb30919cf3b60e1b29e0425f28531c`; it did not inspect the
separate M1 implementation worktree.

The trust anchor is the **specific inviter device key explicitly accepted by the
joining human as this environment's checkpoint administrator**, together with
that administrator's explicit approval of the recipient fingerprint. Merely
pasting an invitation, possessing its secret, finding a key in the snapshot,
joining the link service or completing TLS does not grant checkpoint authority.
Extend the trusted join confirmation to identify the environment and inviter
fingerprint and explain that the device attests to compacted state. Persist this
local approval before requesting a checkpoint. Keep it separate from the
inviter-side approval of the joining device; those are two different decisions.
Use the existing human administrative surface and reauthentication boundary,
never an agent tool or secret-bearing CLI argument.

Grounding in current code:

- `membership::join` checks the authenticated session peer against the invitation
  fingerprint. `transport::{initiate,respond}` signs the environment-bound
  ephemeral handshake and establishes encrypted sessions. This proves possession
  of the pinned key, not that its holder is an administrator.
- `pairing::approve_join` binds an approval invitation to the exact recipient;
  `membership::match_invite` consumes it once and records `used_by`.
  `TeamSync::admit_member` emits signed `member.add` and available recipient DEK
  wraps. None of these is currently a checkpoint attestation.
- `TeamSync::compact` retains every whole commit containing `env.init`,
  `member.add`, `member.set_role`, `member.remove`, `owner.transfer` or `dek.rotate`.
  Other author sequences may be missing. `snapshot_of_prefix` retains an
  unflushed fold and version order; `snapshot_record` binds fact effects and
  removal placement locally. Neither is a network authorization proof.
- `receipt_fact` explicitly creates **local-only** signed admission receipts.
  `load_facts` checks original signatures and local/historical authority.
  Copying the sender's receipt file cannot authorize recipient admission.

The approved administrator attests that the supplied checkpoint and exact fact
set are the complete, locally admitted state of that device at the declared cut,
including retained authority history. The receiver independently verifies all
supplied original signatures and consistency/authorization checks below. It
**cannot prove the absence of an omitted historical commit, deletion or removal**
from signatures on the surviving subset. Nor can it prove the inviter knows every
offline peer's latest edits. Trust in completeness and the omitted data prefix
comes from the explicit administrator approval and signed attestation. A malicious
approved administrator can lie about that prefix; this is not equivalent to
independent verification of full signed history or consensus among devices.
Record provenance as `administrator_attested`, never `full_history_verified`.

No automatic alternative attestor or delegation is allowed in this slice. A new
administrator after ownership/role change needs a new explicit recipient approval;
the existing transfer is aborted. Retained history must establish the selected
signer's active admin role and recipient's active approved membership at the cut,
not merely repeat roles from the snapshot document. If the checks cannot establish
this, fail `team_bootstrap_authority_unproven`; do not silently trust the document.

### Admission, authority and payload contract

Only one fresh local environment is eligible. An invitation preview/mapping and
this transaction's own unpublished staging are allowed. Any existing admitted
commit, fact, checkpoint, derived team entry, unsent local edit or conflicting
local project/environment mapping is `team_bootstrap_existing_state_unsupported`.
An exact completed-import receipt permits ACK recovery only, never replacement.
Preserve existing local secret/connection collision protections; discover a
collision before publication and leave unrelated state untouched. Repair/merge of
an established or stale restored environment is outside M2.

The sender exports an immutable cut under its existing state synchronization,
after the approved recipient's `member.add` is durable. Export the **current full
covered vector**, using the existing snapshot-seeded fold across all retained
commits. Do not export an old compaction cache alone. Hold normal replication for
this onboarding session until installation; close on bounded-buffer exhaustion
rather than dropping live edits. Concurrent local edits remain durable; they
invalidate finalization of this cut and require a fresh export.

The versioned payload contains these separately hashed components:

1. The unflushed snapshot document, vector and version order, plus the expected
   final document digest after the existing fact/removal overlay. Preserve every
   retained encrypted version and its original identifiers/ciphertext; a visible
   active-secret list is not a checkpoint.
2. All retained whole authority-changing commits listed above, original signatures
   intact, including genesis and the recipient's admission. Also retain complete
   commits needed by the removal schedule and the last admitted commit for each
   nonzero author-vector entry, with its HLC/hash. Those heads provide continuation
   bounds; they do not reconstruct missing sequences. Existing compacted state
   without sufficient head/removal evidence is explicitly unsupported until the
   evidence is available; never invent a last HLC or treat a sequence gap as zero.
   M2 must first extend future compaction to retain these signed per-author heads
   and removal witnesses, without rewriting old snapshot formats. Test onboarding
   after compaction under that rule. A legacy compacted source missing a head
   needs that exact original signed commit from another peer; if none retains it,
   report this precise unsupported condition rather than claim universal legacy
   compacted-state migration.
3. Every admitted signed fact, including removed-member facts, connection disables,
   version revocations and all M1 `secret_deleted` facts; sorted unique fact hashes,
   the exact M1 tombstone digest, and removal bounds/pending/self-placement data.
   The attestation explicitly covers this admitted set, not a filtered subset.
4. Original signed recipient DEK wraps from admission/generation history. No raw
   DEK, local KMS wrapper, vault database, private device key, invitation secret,
   local receipt signature or plaintext secret goes in the payload. A generation
   the sender cannot unwrap remains explicitly unavailable under existing rules;
   do not fabricate a wrap or claim all retained values are usable. Missing a
   required generation for a currently usable credential fails this first slice.

Use a dedicated checkpoint verifier, not the permissive local snapshot-cache
loader. Starting from the genesis owner embedded in `env_id`, verify its device
record and original genesis signature. Verify every retained record/commit/fact,
its environment, schema, canonical signature bytes and unique hash/identity.
Replay the retained authority operations in existing total order, with existing
owner-transfer and removal scheduling rules. Reject skipped/unauthorized authority
operations, unknown signers, inconsistent device records, conflicting sequences,
heads outside the vector and snapshot authority/DEK state inconsistent with that
replay. The signer must be active admin and recipient active with the exact
approved role. Completeness of this retained authority sequence is part of the
pinned administrator's attestation; signatures alone do not prove completeness.
Do not pass gapped retained history through the ordinary sequential receive path
and weaken its gap checks to make bootstrap succeed.

For historical facts, verify each original author signature and establish that
its claimed kind/target had an applicable authority basis in retained history.
Keep already admitted irreversible facts after later demotion/removal, following
existing historical admission semantics and removal cutoffs. Where compacted
history prevents independent reconstruction of the original admission decision,
the administrator's signed **exact admitted-fact hash set** is the explicit
checkpoint admission authority. Persist that distinct provenance and its approved
key/manifest binding; never import the sender's local receipts or label this a
normal independently replayed admission. Reject facts contradicted by retained
proofs, unknown authors or malformed kinds/targets even if listed in the manifest.
The new admission path is available only during this fresh, approved import;
ordinary incoming `FACT` validation remains unchanged. A receiver may issue its
own local receipt only after this checkpoint admission has been durably recorded.

Recompute fact effects, removal placement and final document from the validated
components and compare the signed digests. M1 tombstones survive overlay,
compaction and restart even if no secret versions remain. Preserve the original
fact objects/hashes for subsequent M1 reconciliation; a folded deleted-ID list is
insufficient. Reject inconsistency instead of deleting inconvenient evidence.

### Authenticated transfer and finite bounds

Add `snapshot_bootstrap_v1` to M1's session capabilities, without changing M1's
legacy/tombstone rules. Both endpoints must advertise it on the current encrypted
team session. An old peer may continue existing uncompacted signed-history join;
when a compacted prefix is missing, return explicit unsupported status. Never
announce synchronization based on a partial history. New checkpoint messages use
strict new schemas; old signed and persisted formats retain their exact bytes.

Use these messages only inside the existing authenticated end-to-end session:

- `BOOTSTRAP_REQUEST`: environment, recipient fingerprint, invitation ID and a
  freshly generated 256-bit `onboarding_nonce` (64 lowercase hex characters).
  Bind the request to the locally approved inviter key, current authenticated
  peer and local monotonic deadline. The nonce is not the invitation proof.
- `BOOTSTRAP_MANIFEST`: an Ed25519 signature by that pinned key over existing
  canonical JSON with domain `zeropw-team-bootstrap-v1`, schema version 1,
  environment, signer/recipient fingerprints, invitation ID, onboarding nonce,
  fresh 128-bit transfer ID, creation/expiry times, required feature set, complete
  vector and per-author head hashes/HLCs, component digests/counts, tombstone
  digest, exact payload length/SHA-256 and ordered chunk SHA-256 values. The
  signature excludes only its own field. Hashes use lowercase hex; no floats,
  duplicate keys, unrecognized required fields or lossy integer coercions.
- `BOOTSTRAP_CHUNK`: transfer ID, manifest hash, zero-based index and strict
  base64 bytes. Each chunk must match its signed size/hash before being staged.
  Whole-payload hashing and component validation are still mandatory.
- `BOOTSTRAP_FINALIZE`: after validating all data, the recipient sends a fresh
  256-bit finalize challenge with the exact transfer/manifest hash. The sender
  rechecks approval, active signer/recipient and the entire cut under its lock.
  It signs `BOOTSTRAP_READY` with domain `zeropw-team-bootstrap-ready-v1`, both
  nonces, all identity/transfer bindings and manifest hash only if its vector,
  authority and full fact set still match. Any changed cut requires restart.
- `BOOTSTRAP_ACK`: recipient sends manifest hash, transfer ID, covered vector and
  tombstone digest only after durable installation. This acknowledges that exact
  installed cut; current `up_to_date` still requires fresh ordinary vector and
  M1 tombstone-state/ACK convergence. READY or a received manifest is not an ACK.

Initial limits are refusal thresholds, not capacity claims: 64 KiB manifest;
16 MiB total decoded payload; 64 KiB chunks, at most 256; 128 KiB encoded chunk
frame; at most 4 outstanding chunks and 512 KiB queued transfer frames; 256 device
records, 65,536 total commit/fact/version records and JSON depth 64. All other
control frames are at most 4 KiB, except ACK (which contains the vector) is
bounded by the same 64 KiB limit as the manifest. Existing canonical integer/crypto formats stay
unchanged; oversized otherwise-valid states fail explicitly. Do not compress or
accept paths/archive entries. Limit staging to 64 MiB per transfer and 128 MiB per
process, one transfer per environment and at most two total. File/parent ownership,
mode and ACL protections apply to staging too; staged data contains encrypted
payloads or locally encrypted derivations, never plaintext temporary values.

The receiver's monotonic total deadline is ten minutes from request; idle timeout
is 30 seconds. Manifest expiry is no more than ten minutes after creation; reject
expiry or a creation time more than 60 seconds in the future. Neither wall-clock
freshness nor signed timestamps substitute for the request nonce. Signature/key,
recipient and bound checks precede substantial allocation or staging. Apply size
and queue limits before JSON/base64 expansion. Cancel/timeout drops readiness and
cleans unpublished staging; disk errors fail closed without ACK.

Within the same authenticated session, resume by requesting the next contiguous
chunk index for the exact manifest. Identical already-verified duplicates are
idempotent; mixed IDs, changed bytes or out-of-order chunks are rejected. **No
cross-session partial-byte resume in M2:** after disconnect/restart discard partial
staging and request a new nonce, manifest and full transfer. This bounds replay
state and avoids treating an old session's authorization as fresh. Reauthentication
uses the same device identity and existing approved membership, not a second
invitation consumption or `member.add`.

Persist sender-side onboarding authorization for the approved invitation ID and
recipient, with an idempotent link to its admission commit and an expiry no later
than the original invitation expiry. Each transfer still has the ten-minute
request bound. After authorization expires, a new human-approved onboarding
authorization for the same already admitted identity is required; it does not
re-admit the member. Recover the existing
`used_by`/admission state after a crash between invitation consumption and creating
that record; do not consume a different invitation, grant a different role or
create a second admission. Cancellation revokes the onboarding attempt, not
silently the already admitted membership. Only an explicitly renewed attempt may
start again. Loss of the final ACK permits a new authenticated receipt query with
a fresh challenge; the recipient returns its durable exact manifest receipt,
without reinstalling data or assuming current convergence.

A learned signer/recipient removal immediately cancels staging or blocks
publication. READY is valid only in the same live session for the outstanding
challenge and expires with the request. No online protocol can detect an unknown
offline revocation or revoke bytes already delivered: this contract guarantees
checks against locally known state at finalization and applies subsequent signed
removals through normal replication. It does not promise globally instantaneous
revocation across the network.

### Durable installation and continuation

Current `StateDir` writes fsync a file and rename it individually; they do not
provide a transaction across snapshots, facts, mappings, DEKs and derived vault
state. M2 must add an import-specific transaction and visibility barrier, without
changing the meaning of old state or treating several renames as one atomic commit.

The barrier check and affected state read/use must be serialized with import
publication, or all values and the authorization/use decision must be validated
against the same committed import epoch. A flag check followed by unlocked reads
of several files is insufficient. An epoch change or pending import invalidates
the assembled view: discard/reload it or fail closed before using credentials or
reporting joined/synchronized state. The implementation must audit every affected
read path, including already-running gateway/signer processes, cached credentials,
long-lived contexts and background sync; checking only startup or a newly created
`Context` does not satisfy this requirement. Cached state must carry its validated
epoch and participate in the same serialization or revalidation at use. No new
credential operation may begin from an invalidated view; this does not promise to
undo an external operation already authorized and started before the barrier.

The importer/recovery code alone may access unpublished state through an internally
scoped bypass that cannot be selected through agent APIs or user-supplied flags.
Scope the barrier to affected environments and their derived entries; do not
require a global stop of unrelated environments. These are new implementation
requirements, not claims that existing `StateDir` locks already provide read/write
transactions or coherent cached views.

1. Under the state lock, validate freshness/collisions again and durably create a
   pending-import journal binding the local approval, manifest and staging paths.
   Set a fail-closed barrier for this environment before any ordinary state file
   is changed. All team loading, join success, local edits, credential lookup,
   gateway/SSH use and sync-status paths must respect it, including after restart.
   Until activation the new environment is absent or `bootstrap_pending`; it is
   never partially usable. Unrelated environments retain their existing behavior.
2. Stage and fsync the verified immutable bundle, provenance and derived encrypted
   state. Use local generated paths, no peer-provided filesystem paths. Record
   deterministic install operations and fsync the journal and containing
   directories before publishing any files. Check READY and known revocations
   again. Existing locks serialize this import with concurrent local mutation;
   do not hold them while waiting on network frames.
3. Install the snapshot/record, retained proof commits, facts and checkpoint
   admission provenance, DEK wraps/local encrypted derivation and mapping.
   Revalidate installed digests and fsync files and parent directories. Publish
   a durable completed-import record as the single **visibility** commit under
   the lock, then release the barrier and send ACK. No reader may observe the
   intermediate file set; file-by-file physical installation is not itself atomic.
4. After a crash, process pending journals before exposing affected state. Before
   any install begins, an abandoned transaction can be discarded. Once installation
   begins, recover by idempotently completing verified journal operations under
   the barrier; corruption, missing staged bytes or no space leaves the environment
   unavailable for explicit recovery, never an automatic partial rollback exposed
   to readers. A crash after the completed record permits receipt-based ACK retry.
   Verify the durable record and installed digests before clearing any barrier.

Bootstrap initializes the covered author floors **and their HLC/head evidence**;
ordinary new commits still require the next sequence and original signature,
environment, monotonic HLC and operation checks. Do not turn missing compacted
sequences into permission to admit arbitrary later commits. Retained duplicate
hashes can be recognized; a missing pre-cut commit cannot be declared equivalent
to an attested missing commit merely because its sequence is below the vector.
Reject/quarantine it without claiming full-history verification.

Continue with normal incremental replication only after installation. A late
commit or new removal that would require refolding unavailable pre-checkpoint
history is `team_checkpoint_history_required`: clear readiness, preserve received
evidence and fail closed for affected derivation rather than silently recomputing
from an incomplete subset. Already authenticated monotone restrictions, especially
M1 tombstones and member removal, must still block use immediately; unavailable
history is never a reason to retain a usable deleted credential. Unrelated
operations must not erase the checkpoint.
General reconciliation of that case is a later slice. Subsequent local compaction
must retain bootstrap provenance, authority proofs, author head bounds and the
complete admitted tombstone set; it cannot turn an attested prefix into a purported
fully verified history or revert a tombstoned environment to legacy readiness.

### Implementation boundaries and acceptance

Implement in this order within a separate M2 change: strict manifest/payload
verifier and trust/provenance record; approved session transfer and bounds;
transaction/recovery barrier; join/status/continuation integration. A verifier
that trusts document membership or a transfer without crash-safe publication is
not a partial implementation to label supported. Existing invite/handshake,
commit/fact and prototype persisted fixtures remain unchanged; add new-format
fixtures and tests rather than regenerating the old ones. Old software is not a
supported downgrade reader for an imported checkpoint requiring new provenance
or tombstone semantics; disclose that limit and gate upgraded peer status.

Acceptance must build real signed history, compact repeatedly, then approve a
fresh recipient and compare all retained encrypted versions, available decrypted
synthetic values, version order, vectors, authority/removal state and every
admitted fact hash. Include prior demotion/removal, ownership transfer, unavailable
generations and M1 deletion before/after compaction. Test a non-owner active-admin
inviter and a new-owner inviter separately. Test continued next-sequence edits,
post-cut removal and the explicit late-precut-history refusal.

Negative cases include unapproved/mismatched inviter or recipient, self-claimed
snapshot admin, substituted genesis/history/facts, missing tombstone, revoked
signer, inconsistent cut/heads, cross-environment/session/nonce replay, old-peer
capability failure, local collisions/divergent state, every length/count/queue
limit, malformed/truncated/reordered/duplicate chunks, timeout/cancel, lost READY
or ACK, and concurrent edits/revocation during finalization. A correctly signed
but malicious pinned administrator's omission is a documented trust limitation,
not a test the protocol can magically detect without independent evidence.

Inject disk-full and process termination before/after each journal, file,
directory-fsync and visibility boundary; prove no credential is usable while
pending and restart never presents partial state as joined. Test interruption
immediately after invite consumption and admission for exactly-once recovery.
Add concurrent-reader tests that pause a reader between the barrier check and
state reads, between separate file reads, and between cached authorization and
credential use while import/recovery crosses each visibility boundary. Exercise
pre-existing contexts and running gateway/signer processes, not only reopened
readers. Assert that every observed view and use belongs to one committed epoch
or is refused, unpublished state is inaccessible outside scoped recovery, and
unrelated environments remain usable.
Run real direct and forced TURN TLS/UDP-blocked onboarding with synthetic values,
then isolated Linux/macOS full verification and native two-Mac pairing. Check
link/service observations for secrets. Require actual adversarial Opus review of
the final implementation head; this decision provides no such review or acceptance.

## Follow-on work and unchanged release gates

Existing-device repair after compaction, arbitrary concurrent snapshot merge and
long-running capacity testing are separate milestones. The outstanding macOS ACL
finding, native macOS/physical two-Mac validation, incomplete Opus scopes and
undeployed HTTPS/TURN service remain current release gaps independently of M1/M2.
The synthetic-only Tart macOS 26.6.2 VM is running native full Rust and Go tests;
results remain pending. Completed Linux verification/E2E, DNS/NSG setup and
certificate issuance do not satisfy the remaining native or deployed-service gates. This proposal
neither closes those findings nor changes `rust/PORTING.md`, the
security design, harness or CI requirements.
