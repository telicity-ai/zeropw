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

1. Specify an additive, signed deletion fact, provisionally `secret_deleted`,
   bound to environment and stable secret identity. Require the existing
   administrator authority checks. Define deletion as permanent for that identity,
   including versions unknown to the deleting device. A concurrent or later
   `put_version`, activation or old replay cannot revive it. Creating a new secret
   with the same display name must use a distinct identity; decide and document
   the CLI behavior before implementing ID reuse.
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
5. Define compatibility before publishing the new fact. Current peers reject
   unknown fact kinds, and silent omission would be unsafe. Use an explicit
   capability/version gate with a clear unsupported result for peers unable to
   honor tombstones; retain all supported existing canonical bytes and fixture
   meanings. No automatic downgrade that turns deletion into version revocation.

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

Bound the first slice to a newly approved device joining one environment after
compaction. Do not silently overwrite an existing divergent local environment.
Existing-device repair with unsent local changes needs a separate reconciliation
slice; until then return an explicit unsupported/conflict result without loss.

1. Write and review the checkpoint trust contract first. A proposed basis is an
   explicit checkpoint attestation from the existing administrator device whose
   fingerprint the user approved during pairing, bound to that recipient and
   onboarding attempt. Preserve and verify retained identity/membership/ownership/
   DEK history and signed facts. Specify how signer authority and removal cutoffs
   are established without trusting membership claimed only by the snapshot.
   Decide how future ownership changes and compaction affect that proof. Do not
   grant the service operator, link account membership or a transport TLS key any
   checkpoint authority. If this proof/trust contract is insufficient, keep
   compacted-history onboarding unsupported rather than bypassing validation.
2. Define a new versioned manifest and chunk-transfer contract inside the existing
   authenticated, encrypted team session. Bind environment, sender, recipient,
   fresh bootstrap nonce, transfer ID, schema/capabilities, covered vector,
   retained-history/fact digests, version order, removal schedule, payload length
   and digest. Snapshot contents remain encrypted versions and metadata; keys/wraps
   stay in the trusted team protocol. The link daemon and service receive opaque
   bytes, never the vault file, plaintext values or decryption keys.
3. Export a consistent checkpoint from the existing locked fold/compaction state.
   Carry the required facts and retained authorization history together with the
   snapshot, not only the folded visible document. Continue incremental commits
   after the checkpoint vector. Preserve existing treatment of later removals,
   late commits, unavailable generations and ciphertext validation; do not feed
   untrusted remote JSON directly to the local snapshot-cache loader.
4. Authenticate and authorize before substantial staging. Set concrete bounds for
   manifest bytes, total bytes, chunks, concurrent transfers, temporary disk and
   elapsed time. Verify every bound, digest and signature before installing the
   result. Resume only the exact authenticated transfer; reject substituted,
   mixed-environment, expired or replayed manifests and re-check membership before
   final application. A digest alone is not authorization.
5. Stage durable data, then atomically publish the checkpoint/history/facts and
   derived state under the state lock. Specify crash recovery so a reader sees
   either the old valid state or the complete new state. Send completion ACK only
   after durable installation. An ACK loss must permit an idempotent retry, not a
   duplicate member admission or invitation consumption. Show pending/failure
   honestly; do not report up-to-date before the authenticated state is durable.

Acceptance cases: build real signed history, compact once and repeatedly, then
approve a fresh device and compare all retained encrypted versions, decrypted
synthetic values, vectors, membership and tombstones. Include a deleted secret,
removed member, earlier facts and later commits. Test wrong signer/recipient/
environment, forged or missing history/facts, stale checkpoint against known local
facts, unsupported versions, malformed/oversized/truncated chunks, duplicate and
reordered chunks, timeout/cancel, disk-full and process termination before/after
each durable boundary, ACK loss, and signer/recipient revocation mid-transfer.
Run through direct and forced TURN TLS with UDP blocked, then native two-Mac
pairing. Assert no secret material in link/service outputs or observations.

Deliverable: a separate bounded PR after M1's semantics and the checkpoint trust
contract are fixed, with compatibility tests for existing state and signed/wire
fixtures plus new Rust-format tests. Do not regenerate prototype fixtures or
change their meaning. Run the full isolated verification and actual external
review on the final head; retain failed and unrun cases explicitly.

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
