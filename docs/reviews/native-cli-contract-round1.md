# Native CLI contract run, round 1

This is coordinator test evidence, not an independent Astra acceptance verdict.
The original Python assertions run through the test-only adapter in
`rust/tests/native_cli_e2e.py`; only the CLI launch helper is replaced by a
native binary. Python inspects the resulting state as a compatibility oracle.

Product binary revision: integration `63ff815` (before CLI fix `fb8ca9b`).
Adapter revision: `5293128` (the final change adds single-case selection).
Date: 2026-09-22. All state, credentials and endpoints are synthetic.

Results: original admin contract **55 cases, 38 passed, 16 failed, 1 error**,
149.314 seconds. Original agent contract **6 passed**, 30 native invocations,
2.408 seconds. Four admin cases using in-process Python monkeypatches are
explicitly unmapped, not reported as covered: missing tools module, missing
signer module, captured-context serve revocation, and save-time lock race.
The serve revocation intent additionally has original native process E2E
coverage in progress. Compiled-module availability and lock-race coverage
still require explicit review/mapping.

Reproduce a single original admin case (after building the native binaries):

```text
python3.12 rust/tests/native_cli_e2e.py --admin rust/target/debug/zeropw-admin --agent rust/target/debug/zeropw-agent --democli rust/target/debug/zeropw-democli native_admin_contract:test_cli_restore_keeps_revocations_and_used_approvals
```

Use `native_admin_contract` without a suffix for all 55 cases. Assertions are
not rewritten to accommodate Rust. The original test class overrides unittest's
`fail` method for CLI errors, so a mismatch can display a second usage error;
the initial assertion text and original source line identify the real mismatch.

## Confirmed differences requiring fixes or independent disposition

| ID | Priority | Original case / evidence | Required outcome |
| --- | --- | --- | --- |
| CLI-C1 | P1 | `test_cli_restore_keeps_revocations_and_used_approvals`: with revocation journal removed, restore reports `(principals, connections)=(1,0)`, expected `(1,1)`; `connection_disable` audit lacks connection identity | Preserve the disabled connection using audit-only recovery; do not resurrect authority |
| CLI-C2 | P2 | `test_backup_restore_and_restore_ack`, `test_recover_rotates_kms_and_revokes_grants`, `test_reveal_requires_passphrase_and_is_audited`: wrong passphrase produces no `auth_failed` event | Preserve reauthentication failure audit events and their fields |
| CLI-C3 | P2 | `test_cli_env_holding_the_credential_is_refused_at_save_time`, `test_new_secret_matching_any_connection_cli_env_is_refused`: refusal occurs but denied audit events/reasons are missing | Preserve value-free denial audit for connection, secret put and rotation |
| CLI-C4 | P2 | `test_rotation_start_activate_finish`: no `connection_switch_credential` event after activate | Preserve rotation/switch audit event order and metadata |
| CLI-C5 | P2 | `test_connection_create_requires_a_usable_secret_version`: `secret_version_unusable` lacks expected `detail=retired` | Preserve documented unusable-version error identity/detail |
| CLI-C6 | P2 | `test_ssh_host_keys_are_stored_in_canonical_form`: valid tab-separated, padded and authorized-keys-options inputs rejected as `unsupported_host_key`; `test_connection_create_ssh`: wrong error for invalid input | Normalize all Python-supported host-key forms, with matching invalid-key refusal |
| CLI-C7 | P2 | `test_connection_target_malformed_bracket_hosts_are_invalid_host`: `http:` produces `invalid_scheme`, expected `invalid_host` | Preserve URL validation/error ordering |
| CLI-C8 | P2 | `test_backup_ignores_planted_tmp_symlink_and_keeps_0600`: nonexistent parent produces `backup_write_failed`, expected `file_not_found`; earlier symlink/mode assertions pass | Preserve file-error mapping, without creating missing parent directories |
| CLI-C9 | P2 | `test_semantically_corrupt_state_reports_state_corrupt`: grant document error detail is `grant`, expected an original handled built-in error identity | Compare the full malformed-state matrix and preserve the CLI's safe public error contract; no raw state values |
| CLI-C10 | P2 | `test_grant_lifecycle`, `test_grant_ttl_rejects_non_ascii_digits`, `test_only_reveal_prints_a_secret_value_across_the_command_surface`, `test_restore_keeps_a_global_stop_and_restore_ack_does_not_lift_it`: TTL unit was discarded (`1h`→1 second, `31d`→31 seconds, `1x` accepted) | Correct unit/range/grammar behavior, then rerun every downstream case; implementation fix is in `fb8ca9b`, not yet a complete original-suite rerun |

The initial original process E2E also confirms native democli missing `whoami`
and TTL-caused early SSH/team failures. `fb8ca9b` implements corrections and
the next native process run will verify them. No finding is closed merely
because a fix commit exists. CLI-C1 must retain its priority through the
implementation/review cycle. No merge or deployment is authorized by this report.
