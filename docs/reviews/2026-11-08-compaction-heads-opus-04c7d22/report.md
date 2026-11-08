# Opus static review: Rust original signed compaction heads (PR77)

**Verdict: REVISE.** There are three findings: two medium and one low. The full list is in `report.json`, which follows the unchanged `harness/review.schema.json`.

## Reviewer, settings, nature
- Model: actual **Claude Opus, `claude-opus-5-5`**, running through Claude Code (Claude Agent SDK harness) inside T3 Code. The reasoning effort, thinking budget and service tier are not exposed to me, so I don't claim any value for them. I did the review myself: no subagents, no workflow, no other provider or model. This is the FIRST review of this four-path change. It is not a retry, rephrase, recheck, replacement or continuation of Go service Opus3eb or of the ca01275 findings.
- **Static only.** I ran no product, helper, compiler, build, test, formatter or generator code, and used no SSH, VM, process inspection, network, secrets, admin, PR, staging or commit operations. The only tools used were read-only Git and text reads, plus my own standard-library Python (`-I`) for hashing and checking manifest and schema DATA. I inspected no original secrets or keys; the code read contained only documented synthetic test material.
- Execution figures (native 1843/0/5, Linux 1840/0/5, focused 13+11 per profile, 14 exact selectors) are other parties' **claims/evidence**. I only checked that the selected raw native stdout lists the 13 focused library test names as `ok`. I did not reproduce any of it.

## Input binding
- The brief `/tmp/zeropw-compaction-heads-opus-review-20261108.md` SHA-256 `638b4210…7a9b90` matched the dispatch and was hashed first. The manifest `review-input-manifest.json` SHA-256 `9c319540…77b230a` also matched.
- Before and after the review, all 1426 tracked files matched the manifest: bytes, length, SHA-256, independently computed Git blob, index mode and filesystem mode. HEAD was `04c7d22a…`, the Rust tree `afc41fcb…`, and the working tree was clean. Details are in `input-verification.json`.
- `git diff c413c92 0d3fdc5` touches exactly the four allowed paths (+2161/−13). `git diff 0d3fdc5 HEAD -- rust` is empty, so HEAD adds evidence and docs only.

## Findings (all static reasoning; no repro executed or invented)
1. **ZPCHEAD-OPUS-01 (medium):** a stored author with no member record in the fact-free fold blocks compaction permanently. Receipt's `device_registry` accepts devices from member.add ops that fold skipped (e.g. `not_admin`). The fold vector counts those authors' commits, but `prepare` looks up records only in `identity.members`, so it returns `team_compaction_head_unavailable` forever. Any author-capable member can trigger this, and so can an ordinary role-change race.
2. **ZPCHEAD-OPUS-02 (medium):** receipt checks HLC monotonicity only against a stored previous sequence (`commit.rs:2149`). After compaction deletes head n-1, a regressed HLC at seq n is admitted. The new cache rule (`compaction_heads.rs:320`) then refuses every later compaction until a higher, aged, monotone head exists, which never happens for idle or removed authors. Fixing this at admission needs protected-file scope, so it goes to the coordinator/Astra as a STOP.
3. **ZPCHEAD-OPUS-03 (low):** a symlinked StateDir root or inner directory, which `StateDir::require` accepts, makes every compaction fail. The refusal comes only after the new snapshot and record have been written, not as a prospective check.

All three fail closed: no data loss and no unlink before the barrier. The required changes are bounded: semantics plus real-path tests, as listed in `report.json`.

## What held up under adversarial reading (bounded)
- **Cache format:** closed keys and format string; whole-file `pretty_sorted` equality, which also rejects duplicates, trailing bytes and normalization; read bounded to cap+1; symlink/non-file refusal before open; 256-author and 16 MiB limits checked prospectively; exact `PyInt`; original HLC string; full self-verified DeviceRecord equal to the local record; `verify_commit`; and canonical (sig and hash) byte equality of the stored dict. The prospective image is round-tripped through the same `decode` before any write.
- **Head selection:** same-slot cache and live equality; vector componentwise nondecreasing; exact cut slot even when newer live heads exist; legacy missing head refused before any snapshot, record or cache write; no fallback, synthesis or re-signing.
- **Locking:** `StateDir` lock taken before envs (same order as refold and `sign_authorized_fact`), and the envs hold is short. Facts, commits and members are reloaded fresh under the lock. Both helpers check `locked_by_current_thread()`. Audit listeners run without their mutex, so I found no new deadlock edge.
- **Durability barrier:** the snapshot file is written and fsynced (write_json fsyncs then renames), then the record. The record readback is compared with the expected record. Then the directory chain is fsynced up to the root, the cache is written atomically, its directory chain is fsynced, and the cache bytes, snapshot digest/vector and record are all read back. Only then does the existing unlink loop run, with the same six authority exclusions and the same counting. Every error before that point returns before any unlink.
- **Test controls:** the hooks are `#[cfg(test)]` thread-locals in private modules. Integration tests link the non-test library, so production has no switch.
- **Privacy:** errors carry fixed reasons with empty detail. The cache holds the original public commits, including encrypted ciphertext (consistent with "stays in encrypted history" in whole-secret-deletion), plus public device records. No plaintext, DEK, private key or receipt goes into it. PreparedHeads/Head/Image have no Debug, Clone or Serialize. Backup still omits the cache.

## Limits and non-findings stated explicitly
- Fsync and fault-hook tests prove neither hardware power-loss safety nor a multi-file transaction. The fault "prefixes" are injected error returns, not process kills.
- The StateDir lock is now held across three full folds and the all_commits load, so it blocks other state-lock users, vault paths included. The frozen task requires this, it overlaps the existing DOS-1, and operational DoS is outside this task. It is noted, not filed.
- Permanent refusal after cache loss (backup restore) or a legacy compaction with idle or removed authors follows the frozen decision. I don't file it, but it is a lasting operational consequence.
- Not assessed: the Go service, old service package, case12, runtime, VM state, the native 10-identity resource HOLD (still intact), and Linux ch01 deletion custody.

## Unresolved wider gates (unchanged, not resolved by this review)
Snapshot onboarding is still unsupported. All M2-G01–G10 holds remain OPEN, along with runtime/READY/receipt/ACK, journal/crash/coherent epoch, general gap/interacting removal/continuation, physical two-Mac/sleep-wake/GUI, packaging/macOS ACL, Oracle deployment/capacity, release, DOS-1 HIGH, OPUS03/03-R1, SEC03, ca01275 REVISE, the interrupted Opus3eb and old Go quarantine. The native own-resource HOLD remains. This REVISE is no MLP, deployment or risk-acceptance decision.
