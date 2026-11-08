# Opus static re-review: ZPCHEAD-OPUS-R1-01 fix at 772e845

**Verdict: BLOCKED.** I found no new source defect, and R1-01 HIGH is **resolved in source (static)** under the actual Astra policy (b). The review still cannot PASS for two reasons:
- The schema forbids PASS with findings, and the four original records must stay listed, verbatim and OPEN.
- Validation is **incomplete**: there is no same-source both-OS full PASS and no actual Astra acceptance.

Source disposition, validation and acceptance are separate statuses below. This is not a release PASS, readiness or acceptance.

## Reviewer, settings, nature
- **Model:** actual Claude Opus, `claude-opus-5-5`.
- **Runtime:** Claude Code (Claude Agent SDK harness) inside T3 Code, in the prepared worktree `/Users/ys/.t3/worktrees/zeropw/t3-fcfc5b9a`.
- **Settings:** reasoning effort, thinking budget, service tier and provider options are **not exposed** to me, so I claim no value for them.
- **Independence:** I worked personally, with no subagents, workflows, delegates or other models. This is a NEW review, not a continuation, retry or recheck of the interrupted Go Opus3eb review.
- **Static only.** I used read-only Git, text reads, and my own `python3 -I` standard-library scripts in `/tmp/opus-r1-772-scripts/` (outside the worktree) for hashing, the manifest check and composing/validating the schema DATA. I executed no product, helper, compiler, formatter, build, test or dependency code, and made no runtime, VM, process, daemon, SSH, network, cache or credential queries.

## Input binding (details in `input-verification.json`)
- **Brief and bindings.** I hashed `brief.txt` first: `c43b1dbb…7aab` (6,072 B) matched, and I read it in full. `input-bindings.json` `cad005fa…c907` matched, and `source-manifest.json` `5599ea9b…07ef` matched its binding.
- **External inputs.** All 14 bound files matched bytes and SHA-256: the Astra decision and task, both independent reports, the a63c800 and 04c7d22 reports, finding-status and the four plans.
- **Source.** HEAD is `772e84517a188ad8ee60f2f247bf6413ac8fe88f` and `HEAD:rust` is `a6d89b2e6855e7647e4aa3044a07dcca73f6fc40`. The index has 1519 entries, equal to the manifest path set. Each entry's Git mode and blob matched, and each worktree file's bytes, SHA-256 and POSIX mode matched. There were 0 mismatches, both before and after.
- **Status.** Tracked status was clean before. Afterwards the only change is the untracked output directory.
- **Branch name.** The worktree branch is `t3/compaction-r1-opus-review`; the start-of-session snapshot showed `t3/fcfc5b9a`, a T3 rename at the same commit. I made no ref or index edit.
- **Diff scope.** `git diff 1a20a2d..HEAD` touches exactly the four allowed paths: commit.rs +293/-0, compaction_heads.rs +24/-4, sync.rs +1390/-0 (one hunk inside `mod compaction_heads_tests`), tests/team_compaction_heads.rs +230/-10.
- **Added-line scan.** Added lines contain no `unsafe`, `allow`, env/process hook, new `pub fn`/`pub(crate) fn`, or Cargo/harness/CI/verify.sh change. They contain exactly 7 new `#[test]`.

## Original findings: preserved, with static disposition
`report.json` holds all four original records, copied byte-for-byte as JSON values (I checked equality programmatically). R1-01 comes from a63c800 `report.json` (`58a81935…`), and 01/02/03 come from 04c7d22 `report.json` (`4e7296a5…`). The ledger is unchanged.

| ID | Original severity | New static source disposition | Validation | Acceptance |
| --- | --- | --- | --- | --- |
| ZPCHEAD-OPUS-R1-01 | **high** | **RESOLVED IN SOURCE (static), within Astra policy (b).** Receipt, deferred release, local commit and both fact-signing paths no longer halt when an alternate self-signed Y′ becomes the current first record, provided an equal full retained announcement exists. The approved residual remains: compaction still refuses. | **OPEN / INCOMPLETE** | **OPEN** |
| ZPCHEAD-OPUS-01 | **medium** | Remains resolved in source; no regression. `prepare` and the `compact` record source are byte-identical. | OPEN | OPEN |
| ZPCHEAD-OPUS-02 | **medium** | Remains resolved in source for new admissions; no regression. `cached_hlc_not_above_previous` and `observe_cached_hlcs` are byte-identical, and every cached clock is still enforced once the cache validates. | OPEN | OPEN |
| ZPCHEAD-OPUS-03 | **low** | Remains resolved in source; no regression. `preflight_layout` and `check_snapshot` are unchanged. | OPEN | OPEN |

## Production review (static reasoning, not executed)

### `checked_cache` (`compaction_heads.rs:374-440`)
- **Unchanged parts.** The lock, `load`, root/env binding, current-first `records` (fresh `live`, else `retained_device_registry`), `snapshot_floor` and `vector` are unchanged. An absent cache still returns `None` before any new code runs.
- **The expected map (`:388-396`)** holds only cached authors whose current-first record exists and differs. Since `image.heads` is at most 256 (`decode`), the map is too. Missing first records are never substituted; they still reach `unavailable` at `:414`.
- **The extra scan (`:397-406`) happens only when the map is non-empty.**
  - With `live: Some` (receive passes `existing = all_commits()`, taken under the lock before append; `author_commit`, `author_fact` and `sign_authorized_fact` pass `all_commits()`), the scan is in memory. That list excludes the candidate, deferred, rejected, snapshot and cache contents.
  - With `None` (`release_deferred`), it is ONE retained-file walk. Errors map to fixed `invalid` with empty detail.
- **Pass rule (`:415`).** The first-record check now passes when first == cached, OR when the cached fingerprint is in the matching set. The floor/vector checks (`:408-412`) still run first.
- **Live original (`:421`)** is verified with `head.device`, the cached record. The trailing live loop (`:426-438`) already used `head.device`. `same_original` (canonical false/true plus device equality) is unchanged.
- **Integrity argument.** Fingerprint = SHA-256(sign_pub)[:16]. The cached device passed `record()` (verify, fingerprint==author, canonical form) in `decode`, and `verify_commit` depends only on `sign_pub`. So verifying with the cached device versus the first device gives identical commit-signature results. agree_pub plays no role in these paths, and nothing here grants membership, wrap, use or fact authority.
- **Monotone.** For every input, the only behavioural change is that some former `invalid` results become a pass. There is no new denial: the new scan runs only when the old code would already have returned `invalid`. In the `None` path, a walk failure implies the immediately preceding `retained_device_registry` walk over the same locked files would already have failed.
- **No writes.** The cache, snapshot, record and commit files are untouched; nothing is replaced, migrated or deleted.

### `matching_device_records` (`commit.rs:2378-2409`)
- It has the same op selector as `device_registry`: `env.init.owner_device` / `member.add.device`, object-only, `DeviceRecord::from_dict`, `verify()`.
- It iterates **every op of every commit**, so nonfirst ops are included.
- Membership requires `expected[fp] == record`, which is full byte equality of sign_pub, agree_pub and sig (derived `PartialEq`). The fingerprint alone is never enough. A same-sign/different-agree record does not match.
- It has no role filter and does not reinterpret the enclosing commit. Signed bytes are never modified (the record is a decoded copy).

### `retained_matching_device_records` (`commit.rs:2128-2167`)
- It requires the lock and is line-for-line the walk of `retained_device_registry` (`:2092-2126`): sorted dirs, `digit_stems`, sort+dedup, `> 0`, canonical `get`, then `sort_total_order`. This preserves alias/zero-padded/Unicode-digit canonicalisation and fails on later malformed files and HLCs.
- It has no `all_commits` path, no `1..vector` loop and no per-head scan. The old `device_registry` and `retained_device_registry` bodies are untouched.

### Lock/freshness/order
- **Receipt** order is: lock → format/env/ops → bootstrap → registry signature verification → duplicate/equivocation → `hlc_not_above_previous` (cache validation, then HLC) → defer/append. A local evidence error is returned before any reject, defer or append.
- **Release** keeps the unlocked gap prefilter plus the locked `fresh_last` recheck; a local error leaves the deferred file intact (`?` before `remove_file`).
- **Signing.** TeamSync `sign_authorized_fact` validates before taking the `envs` lock and before the clock tick. The two `#[cfg(test)]` scoped gates and Root03 code are byte-identical.

### Strict compaction
`prepare` (`:256-366`) still compares `local_record(author)` (current first) with every cached `head.device` and refuses with `invalid` before any image write. The conflicting earlier-different case therefore still refuses compaction, as the policy deliberately allows. Removal of Y cannot repair it (the residual in decision.md).

## Test review (static; NOTRUN by me)

| # | Test | Real paths / independence | Assessment |
| --- | --- | --- | --- |
| 1 | `commit::compaction_heads_r1_exact_announcements_include_nonfirst_ops` (`commit.rs:2811`) | `matching_device_records` and the old `device_registry` on signed announcements | Literal expected sets: [different, equal] and [equal, different] within one commit; earlier different then later equal. It independently checks the old first-record choice and covers legacy array-wrapped fields plus an extra key, for both env.init and member.add. Signed and hashed bytes are unchanged. Negatives: different record, bad-sig record (as op and as expected), unrelated key, `{}` → empty. |
| 2 | `commit::compaction_heads_r1_retained_matches_use_canonical_sparse_files` (`:2918`) | Real StateDir lock and actual files | Covers unlocked → `team_compaction_lock_required`; empty directory → ∅; the `01`, Arabic-indic `١`, `0` and `-1` aliases → ∅ (canonical `1.json` is nonmatching); a 40-digit sparse PyInt canonical file → match; supplied-live parity checked only after the literal oracle; a later malformed HLC → `hlc_malformed`; malformed JSON → `state_corrupt`. If a max-seq traversal existed it would hang rather than fail (timeout-detected only). |
| 3 | `sync::compaction_heads_r1_other_author_receipt_handle_and_compaction` (`sync.rs:11484`) | 4 attacks × direct/handle, fresh fixture each; real `receive_commit`/`handle_commit`/`handle_vector`/`compact`; reopen | Owner A:N+1 accepted. Checks the exact file inventory delta, literal audit suffix, the observer receiving exactly one COMMIT (`ClockSession::send` asserts the lock is not held), and a duplicate producing no effect. The current-Y case is first `blocked_by:[Y]`; after real coverage of the peer vector, compaction gives a literal `invalid` with empty detail, unchanged files and unchanged cache, and the result repeats after reopen. **The a63c800 rule would fail this test** (a hard `Err` on receipt). |
| 4 | `sync::compaction_heads_r1_deferred_release_preserves_clock_and_evidence` (`:11590`) | D deferred via real `receive(now=0)` before its predecessor; real `release_deferred`, `advance_env` | Exercises the **retained-file walk** path (`live=None`) under a mismatched first record. good → released once, no audit. equal/lower → literal quarantine name, whole dictionary after stripping only `rejected_reason`, one literal audit event, V unchanged. corrupt → `invalid`, D bytes intact, no audit. The repeat release has no effect, and `advance_env` sends exactly one COMMIT on the first tick and none on the second. |
| 5 | `sync::compaction_heads_r1_owner_data_removal_and_both_fact_paths` (`:11835`) | Real `author_commit` (attached/standalone), `author_fact`, `sign_authorized_fact`, `publish_fact`, `publish_signed_fact` | Literal H per row (current Y-alone `1000020-0008` proves the cached pruned A:3 clock was observed). Data → `[V1,V2]` staged. remove → Y removed, then a later owner settings commit succeeds and compaction still refuses. An already-removed Y → `NotFound/member_not_found` with no change. Facts: the exact signed fact, one facts line, one signed admission line (signature verified), deny/tombstone effects, no `rejected_facts`, and a duplicate publish creating no second admission. Two signs → counter +1, no disk change. |
| 6 | `sync::compaction_heads_r1_local_failures_and_authority_remain_closed` (`:12072`) | 8 mutations (current/no-X) + 2 × 3 other configs, × 10 actions = **140 rows**, fresh fixture each | Literal class and reason with empty detail (`limit_exceeded` for oversize, `unavailable` for all-absent, otherwise `invalid`). Inventory unchanged, literal audit suffix, TeamSync clock still `1-0000`, D unchanged. `incoming-equal` (candidate carries the equal record) and `deferred-equal` (deferred D carries it) both remain `invalid`, so neither incoming nor deferred evidence counts. The unreadable row uses 0o0 with an RAII restore and fails the fixture if the file is readable. The authority tail covers Y not_admin, `team_fact_not_authorized`, self-removal allowed then `member_removed`, owner removal refused, wrong-G `team_rekey_pending`, X absent, and X's forged fact rejected. |
| 7 | `integration::compaction_heads_r1_prior_conflicts_identical_and_absence_controls` (`tests/team_compaction_heads.rs:2005`) | Old unchanged helpers; real receipts only | Rows: earlier-identical, later-different, initial-alternative (cache initialised with Y′) → receipt accepted, compaction succeeds, cached device literal. earlier-different → receipt accepted, compaction `invalid`, unchanged after reopen. lost-cache → legacy receipt, compaction `unavailable` before writes. A genuine no-cache control initialises exact heads. |
| — | Sole old change: `compaction_heads_01_…earlier_arrival_refuses` earlier=true block (`:1667-1699`) | — | `unwrap_err/invalid` was replaced by `accepted`, with the exact original (canonical false/true, sig), no rejection, no rejected/deferred entries, cache bytes unchanged, Y absent from members and settings still 10. The earlier compaction refusal, the later=false branch, the name and the trailing original-byte/slot asserts are kept. The diff shows only this block and the appended test. |

**Literal-oracle quality.** Expected HLCs, sequences, vectors, file paths, audit records and error reasons are literals, or are derived from fixture constants rather than from the new matcher. The core rows (3, 4 good, 5) would fail against the pre-fix rule, so they are not tautological mirrors.

### Test-strength observations (no finding, no severity)
- **O1.** In test 4, the `removed` equal/lower rows are decided by the **live** A:4 predecessor (`member.remove`, never pruned), not by the cached clock. The cache-specific HLC regression evidence comes from the current-Y rows (A:3 pruned). This matches the HLCs the task prescribes.
- **O2.** In test 6, the `deferred-equal` D′ uses the same `deferred/{fp}-{seq:010}.json` name, so it **replaces** the fixture's D. The test asserts exactly one deferred entry, not which one. The `release` × `deferred-equal` row therefore releases D′ itself, which is still a valid negative: its own member.add is not retained evidence.
- **O3.** In test 6, the Y-authority tail runs in Y's own Context, which **has no compaction cache**, so it does not exercise the new rule. Statically this is adequate, because `checked_cache` feeds no authority decision. It is evidence of unchanged ordinary authority, not of authority "under" the conflict. Literal reasons such as `not_admin` for an already-removed Y and the success of a removed-Y self-removal fact depend on unchanged fold/fact rules that I did not re-derive in full. Runtime evidence decides them.
- **O4.** The sparse-PyInt guard (test 2) detects a huge traversal only as a hang or timeout.
- **O5.** The rows prescribe no new concurrency schedules. The existing two scoped gate tests are unchanged and are not extended to the matcher path. The added walk happens entirely under the same lock, so I see no new race.

## Residual (approved by policy, not a new finding)
- Any holder of a cached author's signing key can, with a single insider action, make strict compaction refuse permanently (no recovery, no anti-rollback). Commits then stop being pruned, which overlaps DOS-1.
- While the conflict persists, each deferred release under it makes two full retained walks. That is "at most one extra scan", not a global cost bound.
- Corrupting or losing local authority history still halts shared operations by design.

## Runtime status (other parties' claims; NOT my execution; INCOMPLETE)
- `pr-body.md` (unbound DATA, read only) claims Linux diagnostic phases 01–09 passed and macOS phases 03–07 passed.
- The coordinator's newest observation, which is moving and **not frozen evidence**: Linux phases 01–11 (driver/test0, source matched) completed, with 12 (release) active; native phases 01–07 passed, with 08 active.
- The final23 plans for both OSes are **NOTRUN** until diagnostic13 completes, and I read only their bound plan files as DATA. No same-source full `rust/verify.sh` PASS exists on either OS. I infer no test outcome from plan files.

## Commands/tests NOTRUN by me
`cargo fmt`, `cargo clippy`, `cargo test` (lib, focused, exact, all integration targets, debug and release), `rust/verify.sh`, signer probes, doc tests, feature equality, release gate-symbol absence, the 14 stack selectors, the two scoped-gate tests, and the harness unittest/compileall. Everything is NOTRUN by this reviewer.

## Unresolved (all OPEN, unchanged)
These all remain OPEN:
- ZPCHEAD-OPUS-R1-01 HIGH; ZPCHEAD-OPUS-01/02 MEDIUM; ZPCHEAD-OPUS-03 LOW. All are pending same-source both-OS full validation and actual Astra acceptance.
- DOS-1 HIGH, OPUS03/03-R1, SEC03, ca01275 REVISE, Go case12 quarantine/custody/cancellation, and the interrupted Go Opus3eb.
- The native 10-identity/old native50110 process HOLD.
- M2-G01–G10/runtime/READY/install/import/receipt/ACK/journal/pruned history/coherent epoch/general gap/interacting removal/continuation.
- Wide-commit timeout; physical two-Mac/sleep-wake/GUI/macOS ACL/packaging; Oracle deployment/capacity; release/acceptance.

Snapshot onboarding remains unsupported. This review authorizes no commit, push, merge, deployment, release or acceptance.
