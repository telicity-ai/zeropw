# Coverage: Opus static review of 772e845 (R1-01 fix)

Reviewer: actual `claude-opus-5-5`, working personally in Claude Code inside T3 Code. Effort, thinking and tier are unexposed. This review is static only.

## Read completely
- **Preparation directory.** `brief.txt`, `input-bindings.json` and `pr-body.md` (unbound DATA) were read in full. `source-manifest.json` was parsed in full, not read as prose.
- **Astra.** `decision.md` and `implementation-task.md` were read in full.
- **Independent reports.** `compaction-R1-scope-772-independent-20261108/REPORT.md` and `compaction-conflicting-decision-independent-20261108/REPORT.md` were read in full. Their two `REPORT.json` files were hashed only.
- **Original reviews.**
  - a63c800 `report.json` was read in full, including the complete R1-01 record. a63c800 `report.md` was read in full.
  - 04c7d22 `report.json` was read in full. `finding-status.json` was hashed only; my partial print failed because of a shell quoting error, and I did not reread it.
- **Project docs.** `AGENTS.md` (supplied in context), `docs/security-design.md`, `docs/harness.md` and `harness/review.schema.json`. I also grepped `harness/*.py` for the rules on PASS and BLOCKED.

## Source read (semantic)
- **The full diff `1a20a2d..HEAD`** for all four allowed paths: every production hunk and every added test line.
- **`rust/src/team/compaction_heads.rs` 1–520.** This covers:
  - the helpers, `record`, `Head` and `decode`;
  - `load` (including the scoped gate);
  - `prepare` (256–366);
  - `checked_cache` (374–440);
  - `cached_hlc_not_above_previous` and `observe_cached_hlcs`;
  - the start of `preflight_layout`.
- **`rust/src/team/commit.rs`:**
  - 2040–2130: `append`, `get`, `all_commits`, `retained_device_registry` and the new walker;
  - 2185–2300: `deferred_path`, `deferred_commits`, `hlc_not_above_previous`, `release_deferred` and its gate;
  - 2335–2410: `device_registry` and the new matcher;
  - 2445–2600: `reject_commit`, `receive` and the test-module prelude;
  - the new tests at 2811–3030.
- **`rust/src/team/identity.rs` 40–135:** the `DeviceRecord` definition, its `PartialEq`, `verify` and `fingerprint`.
- **`rust/src/team/membership.rs`:** 335–372 (the `author_commit` clock and cache observation) and 425–470 (`sign_authorized_fact`, standalone, and `publish_signed_fact`).
- **`rust/src/team/sync.rs`:**
  - 6460–6530: TeamSync `sign_authorized_fact`, `publish_signed_fact` and `store_and_apply_fact`;
  - 9225–9345: `compact` (blocking, snapshot, preflight, the `device_registry` records, `prepare`, persistence and the six authority exclusions);
  - the `ClockSession::send` lock assertion (around 10115);
  - all new R1 fixtures and tests, 11005–12420.
- **`rust/tests/team_compaction_heads.rs`:** 1593–1725 (the old earlier-conflict test, including the approved changed block) and 2003–2200 (the new test).

## Hashed or compared only (not semantically re-reviewed)
- **All 1519 tracked files.** For each I checked bytes, SHA-256 and POSIX mode, and compared the index Git mode and blob against the manifest, before and after the review.
- **The 1515 protected files** are covered by that check and by `git diff --numstat`. Beyond the excerpts listed above, I did not re-read them semantically.
- **The four runtime plans** (`test-plan.json` and the three `command-plan.json` files) were hash-verified only.

## Skipped
- **Production code:**
  - the rest of `sync.rs` (handshake, poll loop beyond the cited paths, fact load/receipt internals, `role_document_for_removal`, `handle_fact`, `advance_env` internals);
  - fold.rs; the rest of membership.rs (`refuse_unauthorized_ops`, `fact_role_ok` and its rules);
  - checkpoint, crypto, scalar, store, vault, gateway, signer and Desktop.
- **Tests:** the existing old tests other than the named one, the two scoped-gate tests (unchanged per diff), and the Root03 tests.
- **Docs and evidence:** `docs/product-intent.md`, `rust/PORTING.md`, team-sync docs, raw runtime logs and evidence directories.
- **Literal reasons I did not re-derive.** These depend on fold/fact authority rules I did not fully re-derive: Y `not_admin` when removed, success of a removed-Y self-removal fact, X's forged fact giving `team_fact_signature_invalid`, and the audit-skip counts. Runtime evidence decides them.

## NOTRUN (by this reviewer)
- **Rust toolchain:** `cargo fmt --check`, strict Clippy, every `cargo test` selector (focused lib/integration, the seven new exact names, the two scoped-gate tests, the 14 stack selectors) in debug and release, `bash rust/verify.sh`, signer probes, doc tests, the feature-equality check and the non-test release gate-symbol check.
- **Harness:** `python3 -m unittest`, `compileall`.
- **Queries:** no VM, process, SSH, network, cache or credential queries.

## Tools actually used
- `shasum`, `git rev-parse`, `diff`, `ls-files`, `status`, `sed`, `grep` and `cat`.
- My own `python3 -I` stdlib scripts:
  - `/tmp/opus-r1-772-scripts/verify.py` for manifest, index and input verification;
  - `/tmp/opus-r1-772-scripts/compose.py` for the verbatim finding copy and the stdlib schema conformance check.
