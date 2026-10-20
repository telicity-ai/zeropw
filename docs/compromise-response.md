# Compromise response: containment and rotation guidance

Written 2026-09-15; decisions and stages 1–5 updated 2026-09-16. Stages 1–5 were first implemented in the prototype, then ported to Rust. Stage 6 is not implemented.

This design assumes an agent runtime has been fully compromised. The trusted process detects suspicious behavior, contains its authority and emails the administrator guidance for rotating credentials potentially abused before containment. It elaborates the grant, revocation, audit and alert requirements in [product intent](product-intent.md) and [security design](security-design.md), without changing their boundaries. Tests use synthetic credentials and controlled servers. See [implementation](implementation.md), sections 7 and 9, for actual behavior and limits; test success is not security certification.

## 1. Response

When detection crosses its threshold, ZeroPW:

1. Disables principals, revokes grants, cancels runs and closes signer sockets in the assessed principal/runtime/global scope. Runtime/global containment also rotates the handle key; global stop depends on scope as defined below.
2. Uses audit records since each affected token's creation to assess exposed credentials and stores a value-free incident.
3. Emails what happened, what was contained and which credentials need rotation, in order.
4. Refuses `resume` while an incident remains open.

Provider-side rotation is ultimately needed to invalidate abused credentials. ZeroPW narrows stolen material to usage capabilities by keeping original keys out of the runtime, but the administrator still performs provider-side rotation and reviews external activity. See the [dated 1Password comparison](#appendix-a-dated-1password-comparison).

## 2. Threat model

The attacker may control the entire agent runtime, including root: caller tokens (`zpwc_...`), issued handles, open signer sockets, gateway URL, execution directories and all agent-visible business results.

The attacker must not control original secrets, trusted state, administrator/recovery passphrases, KMS keys, audit storage or notification configuration. This requires separate trusted identity/host boundaries. The same-host development setup does not establish it.

Suspicious behavior includes:

- Requests for secret retrieval/export through nonexistent tools (`reveal_secret`, `export`) or trusted-state path probing.
- Forged/malformed handles, expired-handle reuse and unauthorized connection IDs.
- Signer key management, arbitrary signing (`ssh-add -T`), forwarding or signing before session binding.
- Enumeration: first use of many permitted connections soon after listing them.
- Out-of-scope methods/paths, risky operations without approval or use after revocation.
- Output containing credentials or handles.

Distinguish runtime malware from compromise of one caller token. The latter includes external use of a leaked token, another compromised agent or prompt-injected behavior by the user's agent; ZeroPW cannot distinguish those three. Such an attacker has the token and any leaked handles, not the entire runtime. Scope classification is in section 4.3.

Trusted-host compromise is outside automatic detection: an attacker there can disable detection itself. A human declares it from a separate host; assess the entire vault and use managed KMS plus separately deployed trusted components as the underlying defense.

## 3. Stolen material and rotation

| Material | Meaning | Automatic response | Human response |
| --- | --- | --- | --- |
| Caller token | Principal identity | Disable permanently; resume does not revive it. | Create a new principal and rebuild the compromised runtime. |
| Connection handle | Short-lived usage capability | Grant revocation invalidates bound handles; runtime/global handle-key rotation invalidates all handles. | None for the handle itself. |
| Signer socket | Live usage capability | Close socket and cancel execution. | None for the socket itself. |
| Credential for a connection used since token creation | Original value stayed trusted, but the attacker may have performed external actions or obtained sessions/data. Quiet abuse is indistinguishable from legitimate use. | Mark mandatory rotation. | Revoke/reissue at provider, rotate vault version and review provider activity. |
| Used SSH connection | Existing authenticated remote work may survive containment. | End local client; record destination and public-key fingerprint. | Inspect/terminate server sessions and replace the key in `authorized_keys`. |
| Granted connection without recorded use | Mandatory audit means there is no unaudited authentication through ZeroPW. | Mark recommended rotation. | Decide whether to rotate. |
| Other connection | Compromised principal had no grant. | Not affected. | None. |

A manual trusted-host/global incident marks every active secret mandatory and requires KMS recovery plus administrator/recovery passphrase changes.

## 4. Detection and containment

### 4.1 Detector placement

The detector subscribes synchronously to sanitized audit events inside `serve`, alongside policy, run tracking and signer state. This allows immediate in-process containment without waiting for polling. Manual administrator declarations persist state from another process and are applied by the existing 0.25-second `serve` poll.

### 4.2 Rules

Observe per-principal signals in a default 120-second sliding window. Strong signals are not expected from normal agents or supported OpenSSH clients and contain independently at their count threshold. Weak signals accumulate points because legitimate use can produce them.

| Signal | Audit evidence | Strength | Default contribution/threshold |
| --- | --- | --- | --- |
| Unknown tool | `tools_unknown`, denied; do not record the submitted tool name. | Strong | 2 events |
| Forged/malformed handle | `http_relay` denial: `handle_signature`, `handle_malformed`, `handle_version` | Strong | 2 events |
| Unauthorized connection | `tools_request`/`tools_exec`: `no_grant`, `grant_unknown`, `connection_unknown` | Weak | 2 points |
| Signer key management/arbitrary signing/forwarding | `ssh_agent_refused`: `unsupported_agent_message`, `unsupported_extension`; `ssh_bind`: `agent_forwarding_not_allowed`; `ssh_sign`: `not_userauth_request`, `no_session_bind`, `unsupported_sign_flags` | Strong | 1 event |
| Credential/handle in execution output | `run_finish`: `output_credential_blocked` | Strong | 1 event |
| Revoked/stale/disabled authority | `grant_revoked`, `grant_stale`, `principal_disabled`. Exclude `global_stop` and `restore_pending`: those administrator-wide states do not identify one principal. | Weak | 3 points |
| Out-of-scope method/path or missing risky-operation approval | Scope/approval denials from `http_relay`/`tools_request` | Weak | 1 point |
| Expired handle | `http_relay`: `handle_expired` | Weak | 1 point |
| Enumeration | First-use connection count in the window reaches N (default 4) and at least half the principal's usable connections. First use is lifetime within this `serve` process. Add once on crossing; rearm after the window condition clears. | Weak | 4 points |
| Request burst | More than default 60 `tools_request`/`tools_exec`/`http_relay` events in the window. Add once on crossing; exclude status polling, handle issuance and run records. | Weak | 2 points |

Contain at 8 weak-signal points. Legitimate-looking use of a stolen handle cannot be distinguished by detection; handle-key rotation addresses it during containment.

Unattributed forged/malformed/expired-handle signals use a global bucket. Their containment disables all active principals under `principal` scope, not `all`, so it does not require global stop or vault recovery. Long-running CLI work past the default 15-minute handle lifetime can generate expired-handle false positives. Thresholds are configurable, but strong rules cannot be disabled. Preserve fail-closed defaults: false positives cause recoverable interruption; missed detection permits continued abuse.

Manual declarations use `incident declare --scope principal --principal ID`, `--scope runtime --runtime ID`, or `--scope all`. Global trusted-host declaration requires administrator reauthentication.

### 4.3 Scope classification

A principal is associated at creation with `--runtime ID` (default `default`). A runtime is an agent host/container, distinct from a project's dev/staging/prod environment.

| Classification | Evidence | Scope |
| --- | --- | --- |
| Caller compromise | Signals possible using only HTTP tools/relay: leaked-token use, another compromised agent or prompt injection. | `principal`: the affected caller |
| Runtime compromise | Signer-socket misuse, execution-output exfiltration, or signals from at least two principals in one runtime. | `runtime`: every principal in that runtime |
| Trusted-host compromise | Human declaration only. | `all`: every principal and global stop |

Principal containment removes the token authority, but malware may remain if the administrator recreates an identity on the same compromised runtime. The email warns against this and explains `incident escalate --id ID --scope runtime|all`. Wider subsequent signals also widen an open incident automatically. There is no scope-narrowing path.

Origin tracking is future deployment work: record each principal's first authenticated source address and identify suspicious events from a different address as external-origin use. Current `serve` is loopback-only, so this signal has no useful deployment meaning and stage 6 is unimplemented.

### 4.4 Containment order

Each step is idempotent. Failure must not prevent subsequent denial steps; record failed steps and retry on polling. Audit failure must not prevent containment.

1. Persist incident ID, scope and evidence as `incident_open` in control state. Any open incident blocks `resume`, regardless of scope.
2. Stop globally for `all`, or for `runtime` when its scope includes every active principal. Otherwise callers outside scope continue.
3. Disable affected principals permanently.
4. Revoke all affected grants; bound handles fail validation.
5. For `runtime`/`all`, rotate the single handle key. This also invalidates handles outside scope. Do not rotate it for `principal`: grant revocation already rejects affected handles and unrelated runs should continue.
6. Cancel affected runs and close signer sockets through in-process revocation callbacks. Record cancellation/socket counts.
7. Compute assessment and write `incidents/ID.json`.
8. Send notification; failures become `pending` retries.
9. Record `incident_open` and an `intrusion` alert with sanitized reason, scope, principals and rule.

Further signals accumulate in the same open incident. Widening reapplies steps 3–6 to the new scope, updates assessment and sends a revised email. Other signals do not create duplicate incidents/emails. Signals after closure open a new incident.

## 5. Exposure assessment

Use audit evidence only: no values, headers or bodies enter assessment. For each affected principal, start at its token creation, without a narrowing time window. A connection is used if `http_relay` or `ssh_sign` succeeded, or `run_start` occurred, after that point. Quiet pre-detection abuse cannot be separated from legitimate use. Merge assessments across affected principals using each one's creation time.

For example, a token created September 1 and contained September 15 makes every connection used in that period mandatory, including one last used September 5. An unused granted connection is recommended. Include first/last use and counts so the administrator can prioritize. There is no setting to narrow assessment; short principal lifetimes reduce its span.

| Tier | Condition | Guidance |
| --- | --- | --- |
| Mandatory | Credential of a connection used since token creation. | Provider revoke/reissue, vault rotation and external activity review. |
| Recommended | Active/stale grant without recorded use. | Administrator decision. |
| Not affected | Other connections. | None. |
| Global | `--scope all` | All active secrets mandatory; include recovery and passphrase changes. |

Record secret ID/kind, project/environment, service, connection IDs, destinations, first/last use, count and active version. SSH adds public-key fingerprint and username. Validate incident files with `values_for_trusted_scan` against all vault values/versions before writing. That scan, like the one of the rendered email, looks for a value's forms of at least 8 bytes: a shorter value matches unrelated text, so one would redact every assessment (issue #60). When the vault cannot be scanned, the file keeps its assessment and records `assessment_unchecked` in its failed steps, and the notification waits until it can be checked. Kind names in the original design include `env`; the implemented storage kind is `env_var`.

## 6. Rotation email

### 6.1 Transport

`serve` sends using the built-in client in `rust/src/smtp.rs`. State-local `notify.json` must be 0600 and owned by the current user; the SMTP password is a separate 0600 file. Configuration keys are `host`, `port`, `mode`, `username`, `password_file`, `sender`, `recipients`, `timeout_seconds`. Support verified STARTTLS or SMTPS. Test-only `plain` is allowed only on loopback; TLS verification cannot be disabled.

Invalid or loose-permission configuration becomes `pending`, like delivery failure. `incident notify-test` checks setup. SMTP credentials are ZeroPW bootstrap authority, never business connections or vault entries, and must not be accessible to the agent.

Absent configuration records `not_configured` in incident state, stderr and alerts while containment still completes. Failed delivery retries on polling with exponential backoff until incident closure. Email is notification, not authentication; containment does not depend on it.

### 6.2 Content

The current English subject is `[ZeroPW] Intrusion detected: service stopped, credential rotation required (incident ID)`. English plain-text guidance preserves the original six-section contract:

1. Incident time, scope, detection evidence/rule, affected IDs and token creation times; signal summaries contain counts only.
2. Completed actions: global stop, disabled principals, revoked grants, handle-key rotation, cancelled runs and closed sockets.
3. Mandatory rotation by secret kind:
   - API/environment keys: provider revoke/reissue, then `rotation start` → `rotation activate` → `rotation finish`; review provider activity since token creation.
   - Basic passwords: change at provider, rotate vault version and terminate service sessions.
   - SSH keys: generate a new key, replace the fingerprint in each server's `authorized_keys`, inspect/terminate sessions (`who`, `ss -tnp`), then rotate the vault version.
4. Recommended rotation list and reasons.
5. Rebuild instructions for runtime/global compromise; principal scope warns to rebuild/escalate if malware cannot be excluded. Old tokens never revive.
6. `incident show`, complete rotations, `incident close`, create new principal/grants and `resume`.

Do not include links or agent-selected paths, headers, request IDs or arguments. Only sanitized administrator-defined IDs/service names are allowed. Never include values, bodies, headers, handles or tokens. The rendered email must pass the same all-version secret scan before sending. Historical Korean fixtures remain unchanged; English golden output is tested separately.

## 7. Recovery

1. A human on a separate host inspects `incident show`, alerts and audit.
2. Perform mandatory provider-side rotation first, then vault rotation. SSH requires server sessions and `authorized_keys` changes too.
3. Rebuild affected runtimes for `runtime`/`all`. Keep the runtime for principal-only incidents only when runtime compromise can be excluded; otherwise escalate and rebuild.
4. Close the incident with administrator reauthentication. Closure does not lift global stop.
5. Create new principals and grants; leave disabled old principals disabled.
6. Resume if stopped. An open incident rejects resume.

Before closing a global incident, use `recover` for a new KMS key, grant revocation and handle-key rotation, and change both administrator and recovery passphrases. On a team node, `recover` keeps the device in its teams by wrapping its device key and generation keys again under the new key, and revokes the invitations the node issued that were not used yet; stop `serve` before `recover`, start it afterwards and issue new invitations. When the host itself was compromised, treat those keys as exposed: `recover` keeps them, and a removed device can never rejoin with them. The owner cannot be removed, so on a node that owns an environment first transfer ownership to another member with `team transfer-owner`. Another administrator then removes the device with `team remove`, which rotates the environment key. The rebuilt host starts from a new state directory, where `team join` creates a new device key, and joins each of its environments with a new invitation. A recovery that stops with an error after its new key is in place is completed by running `recover` again.

## 8. Limits

- Trusted-host compromise cannot be automatically detected where the attacker can disable detector/audit/notification. Use separate deployment and human declaration.
- Already-processed external actions and authenticated SSH remote work cannot be undone; email tells the administrator what to inspect.
- A stolen caller token can deliberately trigger containment: this is fail-closed denial of service. There is no automatic resume.
- HTTP-only malware can look like principal compromise. Tokens are removed, but malware may remain; rebuild/escalate guidance is essential. Misclassification in the opposite direction only broadens containment.
- Normal agents can invent tool names or send truncated handles; thresholds permit two unknown-tool/handle-forgery events before containment.
- Older principals imply more mandatory rotations. There is no narrowing assessment setting; replace identities periodically.
- Provider-side automatic rotation remains future scope.
- A team node cannot replace its device key in place. After a host compromise it is rebuilt from a new state directory and invited again to each of its environments (section 7), and its local secrets are put again there once rotated.
- SMTP is additional bootstrap authority; use an alert-only account without other permissions.
- Email can be lost. Incident state, alerts and stderr are authoritative; email is a copy.

## 9. Implementation stages

Stages 1–5 were implemented in the 2026-09-16 Python prototype and ported to Rust before prototype removal on 2026-10-03. Paths below refer to `rust/src/` and integration targets under `rust/tests/`. Stage 6 remains future deployment work.

### Stage 1: incident state and manual containment

`incident.rs` provides `Incident`, `open_incident`, widening-only `widen_incident`, persisted incident state and closure. `policy.rs` associates runtimes, finds runtime principals, records `incident_open`, rejects resume with `InvalidInput("incident_open")`, and revokes a principal's grants. `audit.rs` permits incident open/widen/close/notify and unknown-tool events plus sanitized `incident_id`, `scope`, `runtime`, `rule`, `tier`. Server/tools record unknown-tool denial without submitted names. Administrator CLI provides declare/escalate/list/show/close and runtime association; polling applies cross-process declarations.

`response` and `native_response_cli` cover scope-specific containment, preservation of unrelated principal handles/runs, runtime invalidation, global stop when all active principals are covered, order/idempotence, widening and rejected narrowing, resume rejection, permanent disabled identities, cross-context cancellation/socket closure and containment despite audit failure.

### Stage 2: exposure assessment

`incident.rs::assess` reads audit since each principal's creation. Tests cover used/held/unaffected tiers, merging principals, global promotion, SSH fingerprints/destinations, first/last use/counts and absence of all-version plaintext/base64/hex values in incident state.

### Stage 3: automatic detection

Audit subscription invokes listeners synchronously after recording; listener exceptions do not block audit. `intrusion.rs::Detector` implements windows, strong counts, weak scores, first-use enumeration, request burst and signal-access classification. Two affected principals in a runtime escalate to runtime scope. Crossed thresholds open incidents; wider signals widen existing incidents. `context.rs::Config` exposes allowed thresholds/window settings; `serve` installs detection.

`response`, `response_contract` and native CLI E2E cover every strong rule, weak accumulation, non-triggering normal usage/status polling, enumeration, scope/widening, synchronous containment within `record`, configuration validation and the inability to disable strong rules.

### Stage 4: notification

`notify.rs` and `smtp.rs` load protected configuration/password files, render guidance, deliver verified TLS and track pending/backoff. `serve` retries pending notifications. `response`, native response CLI and adversarial response targets cover leakage-free rendering, kind-specific guidance, absent settings, failures/retries and scripted loopback SMTP.

### Stage 5: E2E and documentation

`native_cli_e2e::test_auto_lockdown_exposure_assessment_email_and_recovery` exercises separate-process attacks, containment, SMTP receipt, refused resume and recovery with a new caller. The demo includes intrusion simulation. Implementation records describe tested scope and limits.

The original plan proposed product/security documentation changes for human approval; implementation of this plan did not itself authorize broader product scope or relax security requirements.

### Stage 6: origin tracking

Add sanitized address-only `origin` to audit, `first_origin` to principals and external-origin signals to incident/email. Removing loopback-only tool listening belongs to separate trusted-service deployment work, not this response plan.

## Decision record

The 2026-09-16 user decision selected type-dependent principal/runtime/manual-global scope; two events for unknown-tool/forged-handle strong rules and one for other strong rules; direct SMTP; and mandatory rotation for every used connection since token creation, with recommended rotation for held-but-unused grants and no narrowing time window.

## Appendix A. Dated 1Password comparison

The 2026-09-15 research found that a fully compromised device cannot be made safe by a secrets tool alone. The referenced 1Password materials describe exposure reduction, revocation/reissue, device verification, Secret Key regeneration and device deauthorization, while acknowledging previously acquired key material can retain access to ciphertext. Credential rotation remains the user's work. Service-account token compromise can expose its permitted vaults.

ZeroPW instead keeps original keys out of the agent runtime and automates containment plus audit-based rotation guidance. This comparison is historical design context, not a claim about currently shipping features of another product.

- [1Password Security Design White Paper, Appendix A](https://agilebits.github.io/security-design/leopard.html)
- [Local threats and device protections](https://1password.com/blog/local-threats-device-protections)
- [Lost or stolen device](https://support.1password.com/lost-device/)
- [SSH agent security](https://www.1password.dev/ssh/agent/security)
- [Service-account security](https://www.1password.dev/service-accounts/security/)
- [Device Trust](https://1password.com/product/device-trust)
