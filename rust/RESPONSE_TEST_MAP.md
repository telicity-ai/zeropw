# Response port test map

Source inventory: 26 cases in `tests/test_incident.py`, 37 in
`tests/test_intrusion.py`, and 29 in `tests/test_notify.py`. This document
distinguishes direct Rust assertions from original Python end-to-end checks.
It is not a claim that 92 cases have one-for-one Rust tests.

## Coordinator verification supplement (2026-09-22)

The detailed matrix below records the round-1 worker handoff. These subsequent
results close some of its stated gaps, but do not constitute independent Astra
round-2 acceptance:

- `response_contract` passes eight additional tests: 1,250 denial-rule inputs
  compared with the actual Python matcher; byte-for-byte subject/body comparison
  for principal/runtime/all incident fixtures; clock-advanced weak expiry and
  unattributed expired handles; lifetime first-use, half-of-usable and combined
  enumeration/burst/denial boundaries; normal traffic/status polling; and invalid
  threshold/window/ratio configuration with default-preserving overrides;
  used/held/ungranted exposure tiers excluding pre-principal usage; and merging
  two principals' exposure into one mandatory secret with one use count.
- The original eight response administrator/notification CLI cases pass against
  the native binary (42 native administrator launches on CLI worker `b267a4b`).
  Their original assertions are unchanged. This covers declaration, widening,
  authentication refusal, show/list, resume/close, and notify-test behavior.
- The original separate-process compromise E2E passes against native binaries,
  including automatic containment, SMTP delivery, recovery, and leak scans.
- `native_response_process` passes three additional native-process scenarios:
  serve retries a pending email after SMTP starts, widening resends with the new
  runtime scope, a closed pending incident is never retried, and a separately
  declared manual incident cancels a live native CLI run (41 admin/5 agent
  launches). These translate the original mocked serve assertions to real
  processes; they do not assert the internal signer binding object.

Still not proven by those results: cross-process manual-incident release of an
already-live signer binding and successful TLS SMTP interoperability. The three
rendering fixtures do not stand in for every possible incident shape. The
round-1 exposure-tier/merge gaps below are closed by the two new direct tests.

## Incident

| Original behavior/cases | Rust evidence | Remaining boundary |
| --- | --- | --- |
| principal, partial runtime, covering runtime, all scope: `test_disables_only_target_and_keeps_the_other_principal_alive`, `test_partial_runtime_disables_its_principals_but_does_not_stop_all`, `test_runtime_covering_every_active_principal_stops_all`, `test_all_scope_stops_everything_and_marks_every_secret_mandatory` | `principal_scope_disables_only_selected_and_keeps_other_handle_key`, `runtime_scope_rotates_key_and_stops_only_when_covering_every_active_principal`, `all_scope_marks_every_active_secret_mandatory` | None known in those assertions. |
| equal/wider open, explicit widen, refusal, close/resume: `test_opening_while_one_is_open_at_an_equal_scope_returns_it_unchanged`, `test_opening_with_a_wider_scope_widens_the_existing_incident_instead`, `test_widen_principal_to_runtime_adds_the_others_and_rotates_the_key`, `test_widen_refuses_a_narrower_or_equal_scope`, `test_resume_refused_while_open_then_allowed_after_close`, `test_close_refuses_a_closed_incident` | `widening_adds_principals_and_close_does_not_resume`; original native CLI end-to-end assertions are coordinator-owned | Exact CLI error and post-close resume assertions require coordinator run. |
| `test_apply_lockdown_twice_with_the_same_targets_does_not_double_count`, `test_rotate_handle_key_failure_does_not_block_the_rest_of_the_lockdown` | `lockdown_reapplication_is_idempotent_and_rotation_failure_continues` | None known. |
| exposure tiers, merge, SSH, no values, revoked grant, widened grant, pre-principal audit: `test_mandatory_recommended_and_none_tiers`, `test_two_principals_merge_into_one_mandatory_secret`, `test_ssh_secret_carries_fingerprint_and_target`, `test_incident_file_never_contains_a_vault_value`, `test_recommended_tier_survives_open_incidents_own_grant_revocation`, `test_recommended_tier_survives_widening` | `audit_use_makes_secret_mandatory_and_incident_file_has_no_value`, `principal_scope_disables_only_selected_and_keeps_other_handle_key`, `ssh_assessment_carries_fingerprint_target_and_mandatory_tier`, `widening_keeps_previously_held_secret_recommended`, `assessment_ignores_audit_use_before_principal_creation` | No direct assertion for two principals sharing one secret or exact `none` tier. |
| admin/CLI: `test_unknown_tool_is_audited_with_caller_and_never_the_tool_name`, `test_scope_all_without_the_admin_passphrase_is_refused`, `test_incident_close_requires_admin_reauth`, `test_incident_show_and_list_carry_the_assessment_and_no_values`, `test_resume_reports_the_open_incident_id`, `test_declare_absorbs_a_narrower_or_equal_request_without_extra_lockdown`, `test_declare_widens_an_open_incident_when_the_new_scope_is_wider`, `test_serve_applies_an_incident_declared_by_another_process` | Coordinator-owned native CLI/server original-suite adapter, not response-unit tests | Await integrated coordinator result for each exact original assertion. |
| live run and signer containment (asserted across original cases) | `principal_lockdown_cancels_only_its_live_run`, `ssh_assessment_carries_fingerprint_target_and_mandatory_tier` also asserts bound signer socket closes | None known for these unit boundaries. |

## Intrusion

| Original behavior/cases | Rust evidence | Remaining boundary |
| --- | --- | --- |
| strong rules and denial matching: `test_unknown_tool_strong_rule_opens_principal_scope_at_its_threshold`, `test_signer_misuse_strong_rule_opens_runtime_scope`, `test_output_exfiltration_strong_rule_opens_runtime_scope`, `test_below_threshold_strong_signals_open_nothing`, `test_every_documented_combination_maps_to_its_rule`, `test_global_stop_and_restore_pending_never_match_any_rule`, `test_unauthorized_connection_reasons_do_not_match_on_http_relay`, `test_ok_and_unmatched_records_return_no_rule` | `strong_detector_is_synchronous_and_scope_aware`, `signer_signal_and_unattributed_forgery_scopes`, `weak_signals_accumulate_but_global_stop_does_not_score`; `match_denial_rule` public API | Explicit table-driven assertion for every documented combination still desirable. |
| unattributed and weak scopes: `test_unattributed_handle_forgery_opens_principal_scope_over_every_active_principal`, `test_unattributed_expired_handle_weak_points_also_trip_the_global_bucket`, `test_weak_points_accumulate_across_rules_to_the_default_threshold`, `test_window_expiry_drops_old_weak_signals`, `test_global_stop_and_restore_pending_denials_are_not_scored` | `signer_signal_and_unattributed_forgery_scopes`, `weak_signals_accumulate_but_global_stop_does_not_score`, `large_accepted_weak_weights_do_not_poison_detection` | Clock-advanced window expiry and global expired-handle are not directly asserted. |
| enumeration: `test_enumeration_triggers_only_once_distinct_use_reaches_min_and_half_of_usable`, `test_repeated_use_of_the_same_connections_is_not_enumeration`, `test_using_an_old_connection_again_is_not_a_new_first_use`, `test_enumeration_fires_once_per_crossing_not_once_per_additional_connection`, `test_using_most_granted_connections_plus_heavy_status_polling_opens_nothing` | `enumeration_counts_first_uses_and_burst_ignores_status_polling` | Old-use lifetime and rearm/crossing need clock-advanced direct test. |
| burst: `test_burst_trips_once_the_per_caller_record_count_exceeds_the_configured_limit`, `test_burst_fires_once_per_crossing_not_once_per_record_past_the_limit`, `test_burst_ignores_non_credential_using_events`, `test_enumeration_burst_and_unauthorized_connection_together_still_open_an_incident` | `burst_fires_once_when_crossing_limit_not_on_every_later_record`, `enumeration_counts_first_uses_and_burst_ignores_status_polling` | Combined-signal case is not directly asserted. |
| scope/location and synchronous decision: `test_two_principals_in_one_runtime_escalate_a_pure_http_trip_to_runtime_scope`, `test_a_single_principal_with_only_http_signals_stays_principal_scoped`, `test_widening_when_a_runtime_located_signal_follows_an_open_principal_incident`, `test_normal_list_two_requests_one_exec_opens_nothing`, `test_the_very_next_call_after_the_tripping_record_is_already_refused`, `test_open_triggered_inside_record_completes_without_recursion_or_deadlock`, `test_two_threads_tripping_at_once_produce_exactly_one_incident`, `test_a_failing_open_incident_is_counted_not_raised` | `two_callers_with_http_signals_escalate_to_runtime`, `strong_detector_is_synchronous_and_scope_aware`, `concurrent_detector_trips_open_one_incident_without_reentrancy`, `detector_install_is_idempotent_and_decision_failure_is_counted` | Normal-use trio and exact next-call request path await native tools integration. |
| configuration/lifetime/serve: `test_config_overrides_change_when_a_rule_trips`, `test_from_mapping_merges_overrides_onto_defaults`, `test_context_config_intrusion_dict_flows_into_the_installed_detector`, `test_install_is_idempotent`, `test_strong_threshold_must_be_a_positive_int_and_cannot_disable_a_rule`, `test_weak_threshold_and_window_are_validated_too`, `test_serve_installs_the_detector_and_locks_down_on_unknown_tool` | `config_merges_thresholds_and_rejects_disabled_strong_rule`, `detector_install_is_idempotent_and_decision_failure_is_counted`, `installed_detector_survives_dropped_return_value`; original serve case coordinator-owned | Additional invalid threshold variants and exact serve assertion await coordinator integrated run. |

## Notification

| Original behavior/cases | Rust evidence | Remaining boundary |
| --- | --- | --- |
| rendering (`test_rendering_is_pure_and_deterministic` through `test_every_vault_secret_kind_has_a_dedicated_step_block`, first 12 cases) | `email_render_has_ordered_sections_and_no_detail_or_value`, `all_scope_marks_every_active_secret_mandatory`, `rendered_value_leak_blocks_delivery_without_opening_socket`; original native compromise end-to-end email/recovery passed in coordinator baseline | Exact subject, each kind-specific block, URL absence and every wording variant are not individually asserted in Rust. |
| config and security (`test_missing_config_file_means_not_configured` through `test_deliver_with_an_insecure_config_goes_pending_not_a_crash`, next 7 cases) | `insecure_notify_config_is_pending_and_never_sends`, `notify_config_rejects_header_and_smtp_command_injection`, `notify_secure_mode_includes_special_bits` | STARTTLS/SMTPS valid non-loopback configuration has no direct local test. |
| SMTP send, password, retry, leak, widening (`test_successful_send_delivers_subject_body_and_auth_from_the_password_file` through `test_widening_resends_the_email_mentioning_the_wider_scope`, next 7 cases) | `smtp_delivery_uses_password_file_and_marks_sent_without_logging_password`, `smtp_plain_auth_only_server_is_supported`, `failed_smtp_delivery_goes_pending_and_due_retry_sends`, `rendered_value_leak_blocks_delivery_without_opening_socket`, `smtp_python_interoperability_matrix`, `smtp_transport_failure_names_track_the_failing_phase` | Retry pointer-only and widening resend exact assertions not yet direct; TLS handshake has not been exercised. |
| serve retry and notify-test (`test_serve_poll_retries_a_pending_notification_once_the_smtp_server_is_up`, `test_notify_test_sends_through_the_configured_path`, `test_notify_test_without_config_reports_not_configured`) | `smtp_transport_failure_names_track_the_failing_phase` uses `send_test_message`; coordinator original native compromise E2E passed serve/SMTP/recovery | Original serve retry and CLI notify-test exact assertions require coordinator integrated run. |

The independent `astra_response_review` suite additionally checks detector lifetime,
overflow, corruption, dynamic incident shapes, special mode bits, and a
Python/Rust SMTP interoperability matrix. Its 8 tests are not counted as
substitutes for original CLI/server end-to-end assertions.
