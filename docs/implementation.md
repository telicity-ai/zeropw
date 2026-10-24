# ZeroPW implementation status

Written 2026-09-14; compromise response added 2026-09-16; revised for Rust 2026-10-04. Tests use synthetic credentials and controlled endpoints. This record describes implemented scope, not security certification or deployment readiness. The Python prototype was removed 2026-10-03. Current release-commit evidence is in [releasing.md](releasing.md), separate from this dated implementation record.

## 1. Overview

The Rust crate implements vault, policy, audit, HTTP authentication relay, SSH signing, native agent tools and administrator CLI. Different operations reuse one connection without per-operation registration. Original credentials stay in trusted components.

Real OpenSSH/sshd E2E is in `rust/tests/signer_e2e.rs`; separate-process administration, server and agent workflows are in `rust/tests/native_cli_e2e.rs`. Missing OpenSSH prerequisites fail rather than being counted as a pass.

```sh
cargo build --locked --manifest-path rust/Cargo.toml --bins
rust/verify.sh
rust/target/debug/zeropw-demo
```

Run builds/tests only on a disposable runner without product or coordinator authority. Demo exit code 0 means its synthetic checks passed.

## 2. Components and trust

All paths below are under `rust/src/`.

| Module | Responsibility | Boundary |
| --- | --- | --- |
| `crypto/chacha20poly1305.rs`, `crypto/ed25519.rs`, `crypto/x25519.rs` | RFC 8439 AEAD, RFC 8032 signing, RFC 7748 agreement through Rust crypto crates; RFC vectors and SSH interoperability tests | Trusted |
| `secret.rs` | `SecretBytes`, zeroization on drop and redacted Debug | Trusted |
| `kms.rs` | Envelope encryption; `LocalFileKms` is a development substitute for managed KMS | Trusted |
| `vault.rs` | Versions, trusted reads, reauthenticated reveal, rotation, backup/restore/recovery | Trusted |
| `policy.rs` | Callers, connections, grants, expiry/usage/policy versions, revocation, stop and approval | Trusted |
| `audit.rs` | Value-free audit/alerts; mandatory audit failure denies authentication | Trusted |
| `handles.rs` | Short-lived HMAC-signed opaque capabilities | Trusted issuance |
| `gateway.rs` | Fixed destinations, authentication insertion, reflection blocking, duplicate ledger | Trusted |
| `signer.rs`, `sshwire.rs` | SSH agent protocol and session/destination binding | Trusted |
| `tools.rs`, `runs.rs`, `server.rs`, `bin/zeropw_session.rs` | Tool API, run tracking, server and execution helper | Trusted |
| `agent_cli.rs`, `bin/zeropw-democli.rs` | Agent client and example supported CLI | No original secrets |
| `incident.rs`, `intrusion.rs` | Incident state, assessment and synchronous detection/containment | Trusted |
| `notify.rs`, `smtp.rs` | Rotation guidance, SMTP/TLS delivery and retries | Trusted |
| `admin_cli.rs` | Administration and `serve` | Human administrator |
| `context.rs`, `store.rs`, `projects.rs` | 0700/0600 state, atomic replacement, flock, projects/environments and components | Trusted |
| `fake_upstream.rs`, `demo.rs` | Synthetic upstream and demonstration | Tests/demos |
| `team/identity.rs`, `team/envelope.rs` | Device signing/agreement keys, fingerprints and wrapped DEK generations | Trusted |
| `team/commit.rs`, `team/fold.rs`, `team/humanview.rs` | Signed commits, HLC ordering, deterministic folding, derivation, snapshots and display | Trusted |
| `team/transport.rs`, `team/sync.rs` | Authenticated TCP transport, message/session handling, synchronization and incident exchange | Trusted |
| `team/membership.rs`, administrator `team *` commands | Invitation, enrollment, removal and DEK rotation | Trusted/human |
| `pyjson.rs`, `pystr.rs`, `pyint.rs`, `pybase64.rs`, `pyidna.rs`, `argparse.rs` | Persisted JSON/signature bytes, integer/base64/IDNA/CLI compatibility; not a Python runtime backend | Trusted |

Agents receive a gateway URL and restricted caller token (`zpwc_...`). HTTP CLI execution additionally receives a handle-bearing base URL (`.../h/zpw1....`); SSH receives a signer socket. These are usage authority, not original keys. Handles are bound to caller, connection, grant and policy version; leaked capabilities may be usable within scope until expiry/revocation.

## 3. Workflow

A human initializes trusted state (KMS master key, vault DEK and independent administrator/recovery passphrases), creates a project, stores a secret via stdin/file and configures one HTTP/SSH connection with destination/scope. No task catalog is required.

Create a principal with `--runtime ID` (default `default`) and a grant with expiry/usage. Runtime IDs group callers on one host/container for incident classification, not project dev/staging/prod environments. Start `serve`; agents list connections and call `request` or `exec`.

Humans inspect audit/alerts and revoke grants, disable principals/connections or stop globally. State changes affect the next authentication immediately; already-running work and sockets are enforced on the 0.25-second poll. Detection can open incidents automatically; humans can declare them manually. Open incidents reject resume. Review assessment, rotate credentials, close with reauthentication, create fresh identities/grants and resume.

## 4. HTTP relay

- Clients send relative paths, methods and data. Connection scheme/host/port are fixed. Ignore submitted Host and reject absolute targets and CONNECT.
- Reject dot/empty path segments, backslashes, controls and one/two-stage percent-encoded traversal before upstream access. Forward query strings but omit them from audit/logs.
- Forward allowlisted request headers only; discard Authorization, Proxy-Authorization, Cookie, X-ZeroPW-*, Host and hop-by-hop headers. Placeholder CLI credentials do not reach upstream.
- Insert bearer, Basic or configured header credentials only inside the gateway. Unsupported modes or unsafe header characters fail closed.
- Do not follow redirects or return Location. Allowlist response headers; strip Set-Cookie and WWW-Authenticate. Reject compressed responses that cannot be inspected.
- Buffer bodies up to 8 MiB, including chunked responses; streaming passthrough is unsupported. Inspect headers/body for original, standard/URL-safe base64 (with/without padding), percent encoding (upper/lower hex, +/%20 space), upper/lower hex, JSON/HTML escaping and Basic user:password encoding. Reflection yields `credential_reflection_blocked`, not masked content.
- HTTPS verifies hostname/server identity; controlled tests can configure `ca_file`.
- Resolve a hostname once per request, inspect every returned address and connect directly to a verified address, without a second resolution. Address checks precede approval consumption, usage decrement and credential access.
- Reject any non-public answer (loopback/private/CGNAT/site-local/reserved/documentation) with `target_address_not_allowed`. Reject link-local/metadata addresses with `metadata_address_not_allowed`, including AWS `fd00:ec2::/64`, GCP `fd20:ce::254`, OCI `fd00:c1::a9fe:a9fe`, Alibaba `100.100.100.200` and Azure `168.63.129.16`; record alerts.
- Inspect embedded IPv4 in NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, compatible `::/96`, SIIT `::ffff:0:0:0/96`, 6to4 and Teredo. Thus translated metadata targets are rejected; well-known NAT64 with public IPv4 is allowed.
- `--allow-private-network` explicitly permits private DNS answers, never metadata/link-local. Enabling it broadens scope and makes existing grants stale. Administrator-selected IP literals reject metadata/link-local/unspecified/multicast, including embedded IPv4. Older forbidden literal connections remain listable/disableable but fail before transmission on use. HTTPS SNI/certificate checks use the configured hostname while connecting to the pinned address. Self-targeting fails with `self_referential_target`.
- `X-ZeroPW-Request-Id` binds caller, ID and input digest. Different input with the same ID fails; in-flight/uncertain transmitted requests return 409 rather than replaying a write. Completed results can replay.
- `confirm_methods` requires one-time approval bound to caller, connection, method, path and body digest. Changed input needs new approval.
- Usage is charged after policy and mandatory audit but before credential access. Audit failure charges no usage and sends no request.

## 5. SSH signing

Each execution creates a 0600 Unix socket bound to one caller/connection/grant. Possession is restricted use authority.

`REQUEST_IDENTITIES` returns one configured Ed25519 public key without reading a private value. `session-bind@openssh.com` requires an allowed server key, valid signature over session ID, non-forwarding flag and first binding on that client connection. Supported clients need OpenSSH 8.9+ session binding; unvalidated clients receive no signatures.

Only strictly parsed `SSH_MSG_USERAUTH_REQUEST` is signed: session ID and any hostbound key must match the binding; username, algorithm and client key must match the connection. Recheck revocation, expiry, usage, stop and restore-pending immediately before signing, and audit first. Reject key add/remove/lock/smartcard/protocol-1 messages, arbitrary signing (`ssh-add -T`), pre-binding signing, rebinding and forwarding with `SSH_AGENT_FAILURE`. No private-key export protocol is provided.

Revocation, disabling, stop and restore-pending close affected sockets. In-process notifications apply immediately; cross-process administration is checked every 0.25 seconds. Requests during that interval still undergo policy recheck.

SSH `exec` fixes the profile program, uses `-F /dev/null` and supplies only managed `known_hosts` and public `id.pub` files. Options are `IdentitiesOnly=yes`, explicit IdentityAgent, `ForwardAgent=no`, `StrictHostKeyChecking=yes`, `BatchMode=yes`. Agents supply remote-command arguments only.

An SSH connection created without `--cli-program` has no profile, and `exec` refuses it with `cli_not_supported`; the desktop app made such connections before it sent one. `connection update --id ID --cli-program PATH` gives an active SSH connection without a program one, under the same id. It refuses a connection that is not SSH (`cli_requires_ssh`), is disabled (`connection_disabled`) or already has a program (`cli_already_set`): changing a program stays disable and recreate. The check and the change hold one state lock. A new program widens the connection, so its grants become stale until regranted. In a shared environment the change is a `connection.update` commit carrying `cli` ([team-sync.md](team-sync.md) section 12).

Real sshd E2E verifies two commands directly and two through `exec`, captures child files/environment to prove no PEM/blob/seed private key, rejects a wrong server key and rejects execution after revocation.

## 6. Execution, policy and lifecycle

Execution directories, HOME/TMPDIR and signer sockets are fresh 0700 directories outside trusted state; `Context` rejects state-local execution paths. Child environments contain only PATH, HOME, LANG, TMPDIR, run ID, HTTP base URL or SSH_AUTH_SOCK and approved non-secret profile settings.

Before any handle/socket/directory/child creation, inspect profile variable names/values against every vault secret/version, including other projects and retired/revoked versions, in original/base64/hex/URL forms. The connection's own credential, the version its runs carry, is matched as it is at any length, inside other text too; its encoded and whitespace-stripped forms count once they are at least 8 bytes long, as for every value. Another value is matched inside other text when it is at least 8 bytes long. A shorter one matches unrelated text, so one short vault value would refuse every profile (issue #60): it is refused when a variable name or value equals it, or equals it without its surrounding whitespace, and through its forms of at least 8 bytes. Reject `cli_env_contains_credential` with value-free audit. Administrator connection creation and secret/rotation insertion perform matching checks under one state lock, preventing concurrent bypass; a new version is matched at any length against the connections that use its secret. Errors include connection IDs, never values.

Register work before spawn so cancellation can reach it, then recheck policy immediately before spawning. Revocation, stop or exhausted usage prevents launch. In-process withdrawal callbacks apply immediately; polling independently evaluates each live run/socket for cross-process grant revocation, stale widening, disabled identity/connection, stop or restore-pending. Cancel with audit and close sockets when authority disappears. Expiry/usage exhaustion denies the next authentication rather than cancelling already-running work. Reload rotated handle keys after restore/recovery.

Inspect captured stdout/stderr for known encodings of secrets/handles; replace blocked output with a fixed marker and state `blocked`. This is supplemental credential defense because the child must not hold original values. Arbitrary rearrangements/splitting are not universally detected. Duplicate exec registration/lookup uses one lock and yields one execution.

Default-deny grants bind caller/connection/expiry/usage/policy version and are evaluated before relay/sign/spawn. Destination/authentication/scope widening makes grants stale rather than automatically extending them. Narrowing and credential rotation reevaluate in place. Policy-version changes invalidate old handles.

Global stop denies new authentication/spawns, cancels live/queued runs and closes sockets, but cannot terminate already-authenticated remote work.

Encrypted backups contain vault ciphertext, DEK wrapped by KMS and independent recovery passphrase, SSH public metadata, projects and policy. No plaintext secret or secret hash is included; ciphertext reveals lengths. Profile settings are plaintext non-secret policy data and checked at administrator save time. Reject backups the current KMS cannot unwrap before writes. Restore blocks authentication with `restore_pending`, preserves existing stop state and the open incident, and reapplies current revocations. Incident files are not archived, so the archived `incident_open` is ignored: an incident opened after the backup still refuses `resume`, and one closed since does not come back. `restore-ack` clears only restore-pending after human reconciliation; `resume` separately clears stop.

Recovery unwraps DEK with recovery material, rewraps under a new KMS key, revokes grants and rotates handle keys. It also wraps the team device key and each shared environment's generation keys again under the new key, so the node stays in its teams. A recovery that fails once its new key is in place records `recover` as `failed` with state `incomplete`. A key file still wrapped under a key an earlier recovery retired is wrapped again too, so running `recover` again completes one that stopped that way or that an earlier build ran; a recovery in the same second as another keeps that one's retired key as a separate file. A key file no retired key unwraps is left as it was. Keep the retired key files (`kms/master.key.retired-*`) until a recovery has completed: completing one needs them. The invitations the node issued and that were not used yet are revoked and their secrets dropped. Stop `serve` before recovery and start it again afterwards: a running one keeps the old key in memory, and generation keys it writes meanwhile stay under that key until `recover` runs again. The desktop app stops and starts its `serve` around `recover` itself, and a start asked for meanwhile waits for the recovery to end. Losing both KMS and recovery passphrase prevents recovery. `secret reveal` is human-only, reauthenticated, audited and alerted; no bulk plaintext export. Lists expose no value-derived metadata except SSH public information. Rotation registers, activates/switches and retires versions; provider revocation remains a human operation. Activating a version retires the one it replaces. Connections that follow the active version are re-bound, in a shared environment too. `secret put` and `rotation activate` also move the connections pinned to the retired version (as `rotation activate` pins the connection it switches) to the new one and report them as `moved_connections`; the vault API itself keeps re-binding only followers. In a shared environment the move is computed from this node's replica and written in the activation's commit, so a concurrent edit by another administrator can still leave a connection on a retired version; `connection switch-credential --follow-active` returns a connection to following the active version. `secret retire` and `rotation finish` refuse the active version and any version a connection is pinned to, shared or not. `secret import` stores the keys of one `.env` file at once ([.env import](env-import.md)): the file is parsed as data (`rust/src/envfile.rs`, only the forms `dotenv`, `python-dotenv` and Docker Compose read alike; ambiguous lines stop it with line numbers and reasons, never their text), entries that look like keys are selected by default, and the selection is written all or nothing: one vault write in a personal environment (`Vault::put_secrets`), one commit in a shared one. `--dry-run` previews without values; the desktop app uses it for its import sheet, which also opens when a `.env` file is dropped on the window. Tested by `envfile` unit tests, `admin_secret_import`, `team_secret_import` and the desktop core's `e2e_env_import`.

## 7. Compromise response

[Response design](compromise-response.md) stages 1–5 are implemented, not a guarantee of complete detection.

Incident JSON contains ID/time/status, scope/runtime/principals, manual/automatic trigger, rule, actions, assessment and notification state. Scan serialized data against all versions before writes, in the forms the profile check above uses, looking only for those of at least 8 bytes: a shorter one matches unrelated text (issue #60). Unexpected value reflection replaces assessment with `{"redacted": true}`. A scan that cannot run keeps the assessment, the record of what to rotate, and adds `assessment_unchecked` to the failed steps. `incident_open` blocks resume at every scope; closing does not lift stop.

Contain principal, runtime or global authority. Stop globally only for global scope or a runtime containing all active principals. Disable/revoke affected identities; rotate the single handle key only for runtime/global scope. Precise cancellation counts use a snapshot before disabling, unlike broader generic withdrawal callbacks. A declaring administrator process without live managers records `applied_by_serve: true`; the running server applies withdrawal on polling. Wider signals contain only newly added identities and update assessment/email; narrowing is forbidden.

Assessment starts at each identity's token creation, without a time window. Successful HTTP/SSH or started execution is mandatory. Active/stale held grants and grants revoked by this incident (`revoked_at >= opened_at`) without recorded use remain recommended; otherwise assessment after revocation would lose their evidence. Global scope marks every active secret mandatory and sets `recover_required`. Assessment reads audit, not secret values; serialized-output scanning is a separate protective check.

The synchronous detector implements the strong/weak rules and numeric thresholds in response design section 4.2. Enumeration/burst add points once per crossing and rearm after the window clears. Exclude global-stop/restore-pending from principal-specific scoring. Unattributed handle signals target all active principals under principal scope. Signer/output signals or two affected identities in a runtime classify runtime scope. Separate aggregation and try-lock decision locks prevent reentrant audit callbacks or simultaneous trips from opening duplicate incidents; errors/panics increment `decision_errors` without disabling subsequent detection.

Notification configuration/password files require 0600 and ownership checks. Read SMTP passwords only for delivery and discard them afterward. Plain mode is loopback-only. Missing settings record not_configured; invalid settings/delivery failures retry pending with 1, 2, 4… seconds, capped at 300, until closure. Poll only the open-incident pointer. Render six structured sections without links/agent-selected data; scan against vault values before send. Reflected values fail delivery with `rendered_value_detected`. A vault that cannot be scanned holds delivery `pending` with `leak_check_unavailable`, retried like a delivery failure. Widening sends a revised email; ordinary updates do not. `notify-test` uses transport without opening an incident; audit omits recipients/addresses.

CLI supports runtime-associated identity creation, incident declare/escalate/list/show/close and notification test. Global declaration and closure require administrator reauthentication; closure is not resume.

## 8. Acceptance-test mapping

The following retained test identifiers map to [security acceptance requirements](security-design.md). Integration targets live under `rust/tests/`; unit tests are in module `tests` sections. `rust/verify.sh` runs the matrix. Listed tests describe coverage, not current-head PASS.

| Behavior | Test identifiers and relevant contract tokens |
| --- | --- |
| Different operations on one connection | `tools_server::one_connection_supports_multiple_api_operations_without_registration`, `native_agent_cli`, `request`, `exec`, `status`, `cancel`, `signer_e2e`, `ssh`, `native_cli_e2e`, `serve`, `sshd`, `zeropw-demo` |
| Original-key extraction | `tools_server`, `any_vault_value_in_profile_is_refused_before_handle_or_child`, `ssh_cli_keeps_private_key_in_signer_and_fixes_local_ssh_options`, `native_admin_cli_more`, `cli_env_holding_the_credential_is_refused_at_save_time`, `cli_env_holding_any_vault_value_is_refused_at_save_time`, `only_reveal_prints_a_secret_value_across_the_command_surface`, `democli_parity`, `zeropw-democli steal`, `signer_e2e`, `exec`, `native_cli_e2e`, `serve`, `vault_context::put_and_trusted_use_never_persists_plaintext` |
| Response/error/log leakage | `gateway`, `reflection_in_body_and_headers_is_blocked`, `lowercase_percent_encoded_reflection_is_blocked`, `credential_reflection_is_caught_via_latin1_bytes_not_utf8`, `redirects_are_not_followed_and_location_never_forwarded`, `relay_escape_parity`, `runs::output_encodings_block_both_streams`, `tools_server::handle_output_is_blocked_and_revocation_denies_new_work` |
| Connection/destination substitution | `gateway`, `tampered_or_foreign_handles_are_unauthorized`, `handle_is_bound_to_its_connection_caller_and_grant`, `path_traversal_and_smuggling_rejected`, `hostname_resolving_to_loopback_is_refused_without_opt_in`, `metadata_answer_is_refused_even_for_private_opt_in`, `address_refusal_spends_no_grant_use_approval_or_credential`, `peer_check_catches_a_dns_resolved_self_reference`, `tools_server::proxy_tunnels_absolute_targets_and_self_reference_are_refused`, `signer`, `destination_binding`, `session_binding_and_reuse`, `signer_e2e::wrong_destination_host_key_is_refused` |
| SSH key misuse | `signer`, `arbitrary_data_never_signed`, `sign_without_bind_refused`, `forwarding_bind_refused`, `key_management_messages_refused`, `ssh_add_lists_key_but_cannot_sign_random_data_or_delete` |
| Unsupported CLI | `tools_server::original_cli_preflight_missing_profiles_and_programs_never_spawn`, `gateway::unsupported_auth_mode_and_unsafe_credential_fail_closed`, `runtime_parity_gaps`, `native_admin_cli::connection_update_gives_an_ssh_connection_without_one_its_ssh`, `native_cli_e2e::test_ssh_connection_without_its_ssh_is_repaired_in_place`, `native_team_cli::shared_ssh_connection_gets_its_ssh_on_every_node` |
| Expiry/revocation/global stop | `policy`, `policy_oracle`, `gateway`, `global_stop_and_resume`, `stale_policy_version_on_handle_after_narrowing_change`, `widening_change_makes_grant_stale_until_regrant`, `signer::policy_checked_at_bind_and_sign_time`, `runs::revocation_targets_grant_and_global_stop_cancels_rest`, `tools_server::queued_work_rechecks_revocation_stop_and_exhaustion_before_spawn`, `signer_e2e`, `revoked_grant_cannot_authenticate`, `exec_tool_after_revocation_is_denied_before_ssh_starts`, `native_cli_e2e`, `grant revoke`, `connection disable`, `stop-all`, `resume`, `serve`, `sshd` |
| Operational/recovery bypass | `vault_context`, `backup_restore_blocks_until_ack_and_recovery_rewraps`, `restore_reapplies_revocations_rotates_handle_key_and_never_reopens_approvals`, `kms_unwrap_rejects_other_master_key`, `recover_rotates_kms_revokes_grants_and_handles`, `native_admin_cli_more`, `restore_keeps_a_global_stop_and_restore_ack_does_not_lift_it`, `restore_refuses_an_archive_the_current_kms_cannot_open`, `tools_server::original_dispatch_shape_limits_are_enforced` |
| Automatic containment and assessment | `response`, `native_response_cli`, `serve`, `resume`, `incident close`, `native_cli_e2e::test_auto_lockdown_exposure_assessment_email_and_recovery`, `zeropw-demo` |
| Rotation email | `response`, `not_configured`, `pending`, `native_response_cli`, `notify-test`, `serve`, `native_cli_e2e` |

## 9. Known limits

- Same-user development directory/socket permissions and clean environments are not isolation; a child knowing the trusted state path can read it. Deployment needs different identities, hosts and networks.
- LocalFileKms is a file master key, not managed KMS. SecretBytes zeroizes on drop but does not prevent swap, core dumps or copied buffers. Constant-time secret/MAC comparison and Rust crypto crates do not constitute complete system certification.
- Ed25519 uses the RFC verification equation without rejecting small-order public keys. The signer verifies configured server keys, not caller-selected untrusted destinations.
- Reflection and output checks cover known encodings only, not arbitrary transformed/split/encrypted leakage. A child can reconstruct a split handle from status output; default lifetime is 900 seconds and use remains scoped until expiry/revocation/version change.
- DNS checks trust the OS resolver and recognize standard embedded-IPv4 forms, not operator-specific NAT64 prefixes or every provider-private metadata address. Private-network opt-in permits arbitrary private DNS changes. Public-address changes are not blocked; HTTP lacks certificate identity. Use HTTPS and independently restricted egress for deployment.
- Save-time profile checks cover administrator CLI, not direct Policy API writes. Known-encoding checks cannot prevent an administrator intentionally transforming a secret; exec preflight remains the last check.
- AEAD ciphertext reveals plaintext length plus 16 bytes; no padding is applied.
- Cross-process cancellation/socket closure can lag by 0.25 seconds, and completed external work cannot be undone. Some principal-disable/restore cross-process behavior was manually tested with synthetic data on 2026-09-14 rather than covered automatically; preserve that evidence distinction.
- SSH cancellation ends the local client, not remote processes. Non-PTY remote `sleep 60` was observed surviving disconnection; server control is needed for forced termination.
- Generic in-process principal/connection disabling or widening can cancel all runs/sockets because the callback lacks target IDs; cross-process polling checks each scope precisely.
- Run records and relay ledgers use trusted memory/state; restart does not reconstruct in-flight runs and loses the detector's weak-window/lifetime-first-use state. Strong rules still work after restart.
- Streaming passthrough, real service CLI profiles, management UI, managed storage, provider auto-rotation and IPv6 tool listening are unimplemented. Tested CLIs are democli and OpenSSH, not universal compatibility.
- There is one handle key; runtime/global rotation affects handles outside that runtime too. Unattributed expired-handle accumulation can disable every active principal, including after long-running CLI retries.
- HTTP-only malware can be classified principal-only. Email warns to rebuild/escalate before creating new identities, but cannot prove runtime safety.
- Email is a copy, not authentication. Pending delivery retries until closure; invalid config and transport failure share pending behavior, while absent config is not_configured.
- Origin/first_origin tracking is unimplemented and current tool listening is loopback-only.
- A secret's service label is taken from the first sorted connection using it; other service labels may not appear in email.

## 10. Command examples

See [the guide](../GUIDE.md) for human setup and agent usage. The controlled example below assumes debug binaries are on PATH and a test API accepts only `synthetic-token-1`. FakeUpstream is a library test server; `zeropw-demo` embeds it for a one-command demonstration.

A human runs administration in a trusted test terminal; never use these known synthetic passphrases for production:

```sh
export ZEROPW_ADMIN_PASSPHRASE='admin-passphrase-1' ZEROPW_RECOVERY_PASSPHRASE='recovery-passphrase-1'
zeropw-admin --state-dir /tmp/zpw init
zeropw-admin --state-dir /tmp/zpw project create demo
printf 'synthetic-token-1' | zeropw-admin --state-dir /tmp/zpw secret put --id gh --kind api_key --project demo --environment dev --stdin
zeropw-admin --state-dir /tmp/zpw connection create-http --id gh --project demo --environment dev --service fake --secret-id gh --target '<TEST_API_URL>' --auth bearer --methods GET,POST --path-prefixes /repos,/me --cli-program "$PWD/rust/target/debug/zeropw-democli"
zeropw-admin --state-dir /tmp/zpw principal create --id agent-1
zeropw-admin --state-dir /tmp/zpw grant create --principal agent-1 --connection gh --ttl 1h --max-uses 100
zeropw-admin --state-dir /tmp/zpw serve
```

The caller token is printed once. `serve` prints its URL then handles SIGINT/SIGTERM. CLI paths must be absolute. A literal loopback test destination works as shown; private hostname resolution requires explicit private-network opt-in. Profile variables must be non-secret.

Create separate runtime identities when appropriate:

```sh
zeropw-admin --state-dir /tmp/zpw principal create --id agent-2 --runtime box-1
```

A human configures protected `notify.json` and a separate SMTP password file, never a business vault connection:

```json
{
  "host": "smtp.example.com", "port": 587, "mode": "starttls",
  "sender": "zeropw@example.com", "recipients": ["admin@example.com"],
  "username": "zeropw-notify", "password_file": "/path/to/smtp-password-file"
}
```

```sh
zeropw-admin --state-dir /tmp/zpw incident declare --scope principal --principal agent-2 --reason "Suspected token leak"
zeropw-admin --state-dir /tmp/zpw incident show --id '<INCIDENT_ID>'
zeropw-admin --state-dir /tmp/zpw incident close --id '<INCIDENT_ID>'
```

In the agent's separate runtime, configure only its gateway URL and restricted caller token:

```sh
export ZEROPW_GATEWAY_URL='<GATEWAY_URL>' ZEROPW_CALLER_TOKEN='<CALLER_TOKEN>'
zeropw-agent list-connections
zeropw-agent request --connection gh --method GET --path /repos
zeropw-agent exec --connection gh -- list-repos
zeropw-agent status --run '<RUN_ID>'
```

A contained caller receives AuthFailed/principal_disabled with status 401 and CLI exit code 1. Native CLI E2E tests exercise this workflow in separate processes.

## 11. Team sharing

The four implementation stages are present: keys/envelopes/commits/folding; authenticated transport/synchronization; invites/membership/removal/facts/CLI; incident-message exchange and three-process E2E. See [team synchronization](team-sync.md) for protocol detail.

Coverage includes `team_oracle`, `team_fold`, envelope/snapshot ordering, transport/parity/remaining-contract targets, membership, fact catch-up, native team CLI, adversarial team rounds and `native_team_e2e`. `team_op_overridden` detects author transitions between successful same-target mutable operations; only the losing local author gets one notification per outcome, without duplicates after re-folding.

Incident summaries use INCIDENT_ALLOWED_KEYS, bounded strings/integers/string lists and no controls, then signed incident Facts. Incident IDs are restricted hex tokens because they enter a persisted filename; reject traversal rather than accepting arbitrary strings. Send INCIDENT only to directly connected admins, not full-mesh relays. Persist outbox and retry with exponential backoff until an admin acknowledges the fact hash. Admins store the summary, rotation-required/recommended flags and alerts; users neither store nor acknowledge it. `team incidents` displays sanitized summaries and flags.

The automatic `open_incident` path still does not call `send_incident_for_all_envs`/`on_incident_open`; the tested hook is not wired into real incident creation. Do not claim automatic cross-device incident notification.

Desktop app hooks (issue #19): one-day invitation links live in `team/membership.rs` and only wrap the unchanged invitation string as `zeropw://join#…`. Untrusted previews and joins go through `parse_invite_or_link` (strict link grammar, at most 16 `HOST:PORT` addresses of 128 bytes, a fingerprint-shaped inviter, a UTC expiry); the library's `parse_invite` keeps the prototype's lenient grammar. `create_invite_with` stores only addresses that pass the same `valid_invite_address` rule, link or not, so the CLI never creates an invitation its own `team join` refuses. `invites.json` entries gain optional `created_at`, `revoked_at`, `used_at` and `used_by`, used or revoked entries drop `wrapped_secret`, and the joiner's fingerprint comes from the handshake invite check (`invite_check` to `consume_invite_by`). CLI: `team invite --link`, `team invites`, `team revoke-invite`, `team invite-info --stdin`, `team join --stdin`; tested by `team_invite_link`. `project list` adds `team_environments` (`project`, `environment`, `env_id` for every `team/envs.json` mapping, shared or joined, sorted by name; left out when there is none), since `team join` maps the joined environment without adding a project; tested by `team_invite_link::project_list_names_shared_and_joined_environments`. The hidden global options `--input-envelope` (passphrases, key values and invitations as one JSON object on stdin, read by a strict hand-written reader that decodes each string straight into a zeroizing buffer instead of serde_json's unwiped scratch buffer) and `--require-admin` (verify the envelope's admin passphrase before any command, auditing `auth_failed`), and the read-only `status`, are tested by `admin_input_envelope`.

Remaining team limits: no snapshot transfer after local compaction; no UDP multicast discovery (`239.192.47.42:47420`); addresses come from invitations, manual peers and verified peer gossip; direct LAN/VPN only, no NAT traversal/public relay; every member gets the DEK, so roles are not cryptographic secrecy from device owners; incidents require direct admin sessions; override alerts concern connection updates/credential switches, role changes and activation, not irreversible creation/disable/revoke/remove facts.
