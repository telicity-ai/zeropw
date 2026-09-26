# Original team runtime test map (62 methods)

This maps the 62 methods in `tests/test_team_{e2e,facts,snapshot,transport,sync,membership}.py` at the `6ed440f` base. `Covered` means the stated native test drives that behavior, sometimes across several cases. Two constructor rows retain an explicit API-shape difference and are not claimed as exact equivalence. The 2026-09-22 native process lifecycle case is run through `native_cli_e2e.py` as a driver, not a Python product backend. This is Sol implementation evidence, not an Astra acceptance verdict.

Abbreviations: `TM` = `team_membership_sync.rs`, `TR` = `team_transport.rs`, `AR2` = `astra_team_round2.rs`, `AR3` = `astra_team_round3.rs`, `RC` = `team_remaining_contract.rs`, `FE` = `team_fold.rs`, `NE` = `native_cli_e2e.rs`. A row naming several methods is one-to-one: each listed original method counts once.

| Original area / method | Native evidence | State |
| --- | --- | --- |
| e2e / `test_full_team_lifecycle` | NE / `original_team_end_to_end_on_native_binaries` runs the unchanged original test with native binaries | Covered |
| facts / `test_connection_disable_is_a_fact_no_commit` | RC / `shared_admin_fact_commands_do_not_author_commits_or_emit_secret_fields`: native CLI fact output, no commit field or commit-count increase, disabled derived state, no secret fields | Covered |
| facts / `test_replaying_the_identical_fact_bytes_does_not_duplicate` | AR3 / `facts_replay_deduplicates_and_restore_cannot_undo_later_revocation` | Covered |
| facts / `test_secret_revoke_is_a_fact_no_commit` | RC / same native fact CLI test: no commit-count increase, revoke applied | Covered |
| facts / `test_secret_put_and_connection_update_are_commits` | RC / `shared_admin_secret_put_and_connection_update_author_commits`: both native CLI outputs and increasing commit count | Covered |
| facts / `test_facts_not_in_backup_and_reapplied_after_restore` | AR3 / `facts_replay_deduplicates_and_restore_cannot_undo_later_revocation` | Covered |
| snapshot / `test_auto_snapshot_every_n_commits` | AR3 / `snapshot_is_created_at_production_threshold_and_not_before` | Covered |
| snapshot / `test_blocked_while_member_is_behind` | AR3 / `snapshots_refuse_lagging_member_preserve_history_and_allow_gap_append` | Covered |
| snapshot / `test_succeeds_when_member_covered_and_preserves_protected_commits` | AR3 / same snapshot test; TM / `compact_preserves_membership_history_and_snapshot_document` | Covered |
| snapshot / `test_append_after_compaction_tolerates_the_gap` | AR3 / same snapshot test | Covered |
| transport / `test_mutual_handshake_and_message_exchange` | TR / `inprocess_mutual_handshake_and_messages` | Covered |
| transport / `test_non_member_refused_no_bytes` | RC / `explicit_empty_membership_refuses_inprocess_and_tcp_handshakes`: in-process failure hook reports `not_member` and no session callback; AR2 raw TCP proves no response bytes | Covered |
| transport / `test_removed_member_refused` | RC / `removed_member_session_drains_then_fresh_tcp_dial_is_refused` plus the same `not_member` membership callback boundary in RC / explicit-empty test | Covered |
| transport / `test_env_id_mismatch_refused` | AR2 / `raw_tcp_rejects_nonmember_wrong_env_invalid_env_and_low_order_without_response` | Covered |
| transport / `test_invalid_env_id_format_refused` | AR2 / same raw TCP test | Covered |
| transport / `test_low_order_ephemeral_point_refused` | AR2 / same raw TCP test | Covered |
| transport / `test_replayed_msg2_from_previous_session_refused` | AR2 / `raw_tcp_replayed_responder_message_is_rejected_in_new_session` | Covered |
| transport / `test_responder_signature_presented_as_initiator_signature_refused` | AR2 / `raw_tcp_wrong_role_signature_is_rejected` | Covered |
| transport / `test_mutual_handshake_over_real_socket` | TR / `tcp_mutual_handshake_and_messages` | Covered |
| transport / `test_non_member_refused_socket_eof` | AR2 / raw TCP rejection | Covered |
| transport / `test_frame_tampering_closes_session` | AR2 / `raw_tcp_canonical_deep_json_and_frame_tamper_boundaries` | Covered |
| transport / `test_max_connections_enforced` | AR2 / `tcp_connection_cap_is_released_after_session_close` | Covered |
| transport / `test_inprocess_defaults_to_refuse_all` | RC / `explicit_empty_membership_refuses_inprocess_and_tcp_handshakes`: fail-closed equivalent measured; Rust constructor requires an explicit `MembershipCheck`, so Python's omitted-argument API has no native expression | API-shape difference, not exact equivalence |
| transport / `test_tcp_defaults_to_refuse_all` | RC / same test and measured constructor signature; explicit empty check refuses before session acceptance | API-shape difference, not exact equivalence |
| sync / `test_inprocess_transport` | RC / `original_two_node_convergence_inprocess`: reciprocal sessions, independently authored commits delivered both ways, same document with both connections, nonnull `synced_at` | Covered |
| sync / `test_tcp_transport` | RC / `original_two_node_convergence_tcp`: same assertions over real TCP | Covered |
| sync / `test_relay_through_middle_node` | NE unchanged three-node team lifecycle | Covered |
| sync / `test_offline_concurrent_edit_then_reconnect` | NE team E2E includes offline/conflict/reconnect | Covered |
| sync / `test_connection_disabled_fact_propagates_and_dedupes` | TM fact publish; AR3 fact replay | Covered |
| sync / `test_non_admin_cannot_publish_fact` | RC / `user_member_cannot_publish_connection_disabled_fact_to_live_team`: connected user role denied; owner ledger and connection unchanged | Covered |
| sync / `test_mutual_simultaneous_member_removal_converges` | AR3 / `mutual_removal_converges_when_second_fact_arrives_on_draining_peer` | Covered |
| sync / `test_member_removed_fact_closes_session_and_refuses_future_dial` | RC / `removed_member_session_drains_then_fresh_tcp_dial_is_refused`; AR3 proves receive-only drain | Covered |
| sync / `test_removed_peer_session_is_receive_only_during_drain` | AR3 / `removed_peer_drain_is_receive_only_and_accepts_self_removal` | Covered |
| sync / `test_removed_by_third_party_cannot_then_remove_someone_else` | AR3 / `removed_by_third_party_cannot_remove_an_unrelated_admin` | Covered |
| sync / `test_self_removal_by_user_role_still_works` | AR3 / `removed_peer_drain_is_receive_only_and_accepts_self_removal` | Covered |
| sync / `test_widening_commit_cancels_running_exec` | RC / `remote_widening_commit_cancels_existing_http_run_with_grant_stale`: signed remote TCP commit reaches native `serve`, stales grant, cancels live HTTP-kind run with `grant_stale` | Covered |
| sync / `test_connection_disabled_fact_closes_signer_socket` | RC / `remote_connection_disabled_fact_closes_existing_signer_socket`: signed remote TCP fact reaches native `serve`, removes a real active signer socket | Covered |
| sync / `test_no_secret_or_dek_on_the_wire` | RC / `full_team_sync_tcp_wire_uses_original_encoding_leak_scanner`: independent bidirectional TCP relay captures full authenticated TeamSync gossip, confirms delivery and nonempty streams, invokes original `tests.leakcheck.find_secret` on each stream and concatenation for synthetic value + unwrapped DEK; direct-transport capture remains supplementary | Covered |
| sync / `test_old_session_is_closed_and_replaced` | RC / `old_session_is_closed_then_replaced_by_a_new_authenticated_session` | Covered |
| sync / `test_team_listen_opens_a_socket` | RC / `native_serve_with_team_listen_accepts_tcp` | Covered |
| sync / `test_serve_without_team_listen_opens_no_team_socket` | RC / `native_serve_without_team_listen_does_not_start_team_tcp` checks the original null startup field and absence of a team-listen argument; a selected free port remains closed | Covered for original contract; no whole-process listener inventory claimed |
| sync / `test_summary_sanitized_unknown_keys_and_bad_values_dropped` | TM / `fact_sign_verify_and_sanitize`; AR2 sanitizer boundary corpus | Covered |
| sync / `test_summary_missing_incident_id_raises` | AR2 sanitizer boundary corpus | Covered |
| sync / `test_summary_non_token_incident_id_raises` | TM sanitizer test; AR2 boundary corpus | Covered |
| sync / `test_user_role_member_may_also_send_an_incident` | AR2 / `user_authority_incident_retry_restart_and_admin_removal_dek_isolation` | Covered |
| sync / `test_incident_delivered_and_acked_clears_outbox_and_flags_rotation` | TM / `share_invite_join_and_secret_derivation`; AR2 user incident test | Covered |
| sync / `test_mandatory_rotation_reason_is_never_downgraded_by_a_later_recommended` | AR3 / `incident_mandatory_rotation_is_monotone_and_nonadmin_never_acks` | Covered |
| sync / `test_non_admin_recipient_ignores_incident_and_sends_no_ack` | AR3 / same incident test | Covered |
| sync / `test_outbox_persists_when_no_route_to_an_admin` | AR2 / user incident retry test | Covered |
| sync / `test_loser_is_alerted_once_winner_is_not` | AR3 / `conflict_override_alert_is_exactly_once_and_only_on_loser_including_restart` | Covered |
| membership / `test_join_receives_history_and_can_decrypt` | TM / `share_invite_join_and_secret_derivation` | Covered |
| membership / `test_invite_is_one_time` | TM / same join test; AR2 concurrent single-consumption test | Covered |
| membership / `test_invite_expiry_refused` | AR2 / `invite_expiry_transcript_and_concurrent_single_consumption` | Covered |
| membership / `test_proof_over_different_transcript_refused` | AR2 / same invite test | Covered |
| membership / `test_non_invited_device_cannot_connect` | TR / `nonmember_is_refused_without_session`; AR2 raw TCP rejection | Covered |
| membership / `test_share_converts_and_reevaluates_grant` | RC / `share_converts_existing_connection_and_stales_its_grant` | Covered |
| membership / `test_share_leaves_connection_with_unshared_secret_untouched` | RC / `share_leaves_revoked_and_cross_project_secret_connections_local` | Covered |
| membership / `test_share_refuses_when_already_shared` | RC / `share_refuses_duplicate_and_wrong_admin_passphrase` | Covered |
| membership / `test_share_requires_correct_admin_passphrase` | RC / same rejection test | Covered |
| membership / `test_removal_closes_session_rotates_dek_and_blocks_new_version` | AR2 / admin removal/DEK isolation; RC / `removed_member_keeps_old_version_but_cannot_get_new_generation_version` adds new signed version after drain and proves old value survives, old DEK cannot decrypt it, removed node has no new DEK or vault version; RC fresh-dial test | Covered across cases |
| membership / `test_removal_by_self_does_not_rotate_dek` | TM / `share_invite_join_and_secret_derivation` | Covered |
| membership / `test_two_admins_remove_each_other` | AR3 / mutual removal test | Covered |

`Covered` is a mapping for these behaviors, not an assertion that all Python tests or the full Rust suite passed at this head. The two constructor rows remain an explicit **API-shape difference**: Python permits an omitted membership callback; Rust's type requires one, and the supplied empty callback is verified fail-closed. This is not represented as exact Python call-signature coverage. The remote live-runtime cases use the receiving native `serve` with an active run or signer socket; a state-only stale grant or fact log was not counted as their substitute.

## Parity-gap regressions (not original Python test methods)

These cover behaviour an audit found differing from `zeropw/team/sync.py`/`membership.py`; they are additional to the 62-method map above. `PG` = `team_parity_gaps.rs`; `SU` = `team::sync` unit tests (`cargo test --lib team::sync::`).

| Behaviour (Python source) | Native evidence |
| --- | --- |
| `_relaxed_document` vector-keyed cache, cleared only by `_refold` | SU / `relaxed_document_is_cached_by_store_vector_like_python` (fold counts compared with CPython's wrapped `F.fold`; Rust-only replay folds once per pass) |
| Pickup baseline moved only by `_pick_up_local_commits`; `_LruSet` rebroadcast dedup | PG / `cli_commit_written_before_a_received_commit_is_still_picked_up_once`, `cli_commit_written_before_a_submitted_commit_is_still_picked_up_once`, `released_deferred_commit_is_broadcast_once_across_polls`; SU / `lru_seen_set_matches_python` |
| `_handle_incident` unknown author audited `team_fact_signature_invalid` | PG / `incident_from_unknown_author_is_audited_like_python` |
| `_admit_member` audit `extra` carries `role` | PG / `member_add_audit_records_role_like_python` |
| `_send_peers` payload filtering/sorting; `_persist_peer_address` over falsy/non-dict documents; `_load_env_locked` over a non-dict document | PG / `peers_frame_is_filtered_and_sorted_like_python`, `falsy_peers_document_is_an_empty_dict`, `non_dict_peers_document_is_never_sent`, `join_with_non_dict_peers_document_fails_before_dialing` |
| `parse_invite` `str()` coercion, `addresses` default and iteration, `_b32d` `strip().upper()` | PG / `parse_invite_accepts_every_shape_python_accepts` |
| `_drop_member_sessions` clears backoff/next-attempt | SU / `member_removal_forgets_dial_backoff_state` |
| `_apply_incident_rotation_flags` over a corrupt flags document | SU / `corrupt_rotation_flags_fail_the_incident_like_python` |
| `_wire_dialed_session` starts `self._start_receiver`; `stop` joins receive threads with `join(timeout=5)` | PG / `outbound_receiver_belongs_to_the_adopting_instance`, `stop_joins_receiver_threads`, `stop_join_is_bounded_like_python` |
| `_load_env_locked` over every `peer_vectors.json`/`overridden_alerted.json` shape; `_handle_vector` Python-int edge values | SU / `peer_state_documents_load_like_python`, `peer_vector_ints_are_exact_like_python` |
