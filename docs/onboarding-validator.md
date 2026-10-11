# Verify exchanged onboarding results

The `/2` result schemas add an approved roster, artifact identity and execution context. `/1` results are superseded for this guide. A model verdict is provisional: a human or trusted coordinator runs this checker independently before accepting it. The checker verifies JSON structure and consistency; it cannot prove that reported commands ran, that receipts are authentic, or that isolation exists.

Use a reviewed checkout containing `scripts/validate-onboarding.py` and `docs/onboarding-schemas/`. Python 3.11+ and its standard library are sufficient. Do not run a script supplied inside a peer result. The checker reads only the named JSON files. It never reads environment variables, vault state, credentials or the network, and does not execute commands from inputs.

## Approve the policy before exchanging results

Copy `docs/onboarding-policy.example.json` to `policy.json`. Replace every placeholder, including env_id, with metadata independently confirmed by humans. Include the **complete** approved member list, including existing and removed members. A must be the sole active admin/owner; B must be active, have the invited role and `owner=false`. Do not derive the policy from a peer result. Agree on the probe, expected successful HTTP status, response-rule wording and synthetic/real context.

For each platform, verify the archive SHA-256 against the v0.1.0 release before running it. For Homebrew, also compare the tap commit and formula URL/SHA-256 with that release. Record this in `artifact_receipts.A/B`; platforms can have different archive hashes. `tap_commit` is a verified 40-character commit for Homebrew or `null` for an archive install. Receipts remain human-reported, not signed attestations.

| Released archive | SHA-256 |
| --- | --- |
| ARM64 macOS | `7f7218e467f2f913e73bbc20785caeb96bc9f63a916fdca4e217abcdd37deef9` |
| ARM64 Linux | `c8c48db2dab796790248115cc74b366c5be7ecba3bb9c40db9b308697297ac75` |

Release: [v0.1.0](https://github.com/telicity-ai/zeropw/releases/tag/v0.1.0). These hashes are also pinned in the JSON Schemas. A matching checksum establishes consistency with this release; it does not add publisher signature verification.

## Run the checker

Save the complete raw JSON objects as `install.json`, `A.json` and `B.json`. Reject prose, Markdown fences, duplicate keys and extra fields. Preserve original files; do not fix contradictory values to obtain a pass.

```sh
python3 scripts/validate-onboarding.py install install.json --artifact approved-artifact.json
python3 scripts/validate-onboarding.py local A.json --policy policy.json
python3 scripts/validate-onboarding.py local B.json --policy policy.json
python3 scripts/validate-onboarding.py pair A.json B.json --policy policy.json
```

An exit code of **0** is required. Any other exit code blocks acceptance. The pair command computes its own verdict rather than trusting a model's `ready`. To compare an agent's full pair result with that computed object, add `--reported pair.json`; every field must match. Prefer the checker's computed pair result for exchange.

Times must be UTC `YYYY-MM-DDTHH:MM:SSZ`. Every check/sample must be within ten minutes of the current time, with no more than thirty seconds of clock lead. Samples must be at least five seconds apart, no more than ten minutes before the local check, and within the same agreed write pause. Collect fresh receipts after any write or expiry. The human-approved policy does not replace the common session ID and pause time in receipts.

A synthetic `ready` remains a labeled test result. Real credentials require humans to confirm isolation on both devices. This validator cannot attest that confirmation.

## Rejection history

Any nonzero `rejected_commits` blocks `/2`, even if A/B vectors match and HTTP calls succeed. A human checks every quarantine record ID and reason, compares it with the accepted content excluding only the rejection annotation, confirms the author was approved at acceptance, and confirms the record set/count stayed unchanged during sampling. Preserve the private evidence. Do not send raw commits or vault files to an agent.

This review does **not** waive the zero-rejection gate. Do not delete records, reset counters or change receipt values. Handling reviewed history needs a separate product decision and versioned outcome. The current v0.1.0 onboarding test has not established a `ready` pair.

## Reason and action codes

The checker reports `blocked` for stale evidence; collect new human receipts. Installation additionally requires `install_isolation_confirmed=true` and the independently approved artifact file supplied with `--artifact`. A model pair mismatch retains the computed causes and adds `reported_pair_mismatch`.

Invariant failure codes: `artifact_identity_mismatch`, `artifact_identity_unverified`, `environment_mismatch`, `execution_context_mismatch`, `human_receipt_missing`, `installation_action_missing`, `installation_checks_failed`, `installation_exit_failed`, `installation_isolation_unconfirmed`, `installation_not_pass`, `invalid_sampling_interval`, `invalid_utc_time`, `invalid_vector_count`, `local_result_not_pass`, `members_mismatch`, `planned_fingerprint_mismatch`, `probe_mismatch`, `readonly_request_unverified`, `rejected_commits_nonzero`, `reported_pair_mismatch`, `role_mismatch`, `self_fingerprint_role_mismatch`, `stale_or_future_evidence`, `unexecuted_install_exit`, `unexpected_member_present`, `unknown_vector_author`, `unresolved_team_state`, `unstable_vector`, `vectors_mismatch`, `verification_session_mismatch`, `version_unverified`, `writes_not_paused`. Schema/parse failures use fixed categories (`schema_type`, `schema_enum`, `schema_missing`, `schema_extra`, `schema_size`, `schema_pattern`, `schema_range`, `duplicate_json_key`, `nonfinite_json`, `invalid_input`, `invalid_arguments`, `input_too_large`, `unsupported_schema_keyword`).

Rejection actions are `review_quarantine_records`, `confirm_identical_accepted_commit`, `confirm_author_approved_at_acceptance`, `confirm_rejection_set_stable`. Other failures use `review_evidence_and_repeat`. These are action codes, not permission to delete evidence or change grants.

Complete failure/outcome vocabulary: `artifact_identity_mismatch`, `artifact_identity_unverified`, `credential_exposure_suspected`, `duplicate_json_key`, `duplicate_member`, `environment_mismatch`, `execution_context_mismatch`, `human_receipt_missing`, `input_too_large`, `installation_action_missing`, `installation_checks_failed`, `installation_exit_failed`, `installation_isolation_unconfirmed`, `installation_not_pass`, `invalid_arguments`, `invalid_expected_roster`, `invalid_input`, `invalid_probe_input`, `invalid_sampling_interval`, `invalid_utc_time`, `invalid_vector_count`, `local_result_not_pass`, `members_mismatch`, `needs_human_homebrew`, `needs_human_install`, `needs_human_receipt`, `needs_human_runtime_config`, `needs_human_settings`, `needs_human_version`, `nonfinite_json`, `planned_fingerprint_mismatch`, `probe_mismatch`, `production_isolation_unconfirmed`, `readonly_request_unverified`, `rejected_commits_nonzero`, `reported_pair_mismatch`, `role_mismatch`, `self_fingerprint_role_mismatch`, `skill_conflict`, `stale_or_future_evidence`, `unexecuted_install_exit`, `unexpected_member_present`, `unknown_vector_author`, `unresolved_team_state`, `unstable_vector`, `unsupported_schema_keyword`, `vectors_mismatch`, `verification_session_mismatch`, `version_unverified`, `writes_not_paused`.

Homebrew evidence requires approved formula_sha256 plus actual observed_tap_commit/observed_formula_sha256 matching the approved receipt. Disable automatic updates and check a clean tap before and after installation/test; archive evidence and observations use null. Never echo input as an observation. The reviewed v0.1.0 formula SHA-256 is `f01165bea5b6dfadfcdb57b3ed7f82eaa91478f026e7354df2663c45dd79bf2d`.

For brew evidence, run `python3 scripts/observe-onboarding-brew.py --approved-tap <APPROVED_40_HEX_TAP_COMMIT>` from the same reviewed checkout before ZeroPW execution. Require its installed_tap_commit to match the approved tap, installed_spec=stable and binaries_resolve_to_keg=true for all five real paths. The script reads the actual public INSTALL_RECEIPT.json and PATH resolutions without printing paths or executing ZeroPW. Unknown data blocks. Archive installs use null for these fields. Prompt 0 does not accept verify_existing as an installation pass; an existing install needs an explicitly authorized guarded reinstall.
