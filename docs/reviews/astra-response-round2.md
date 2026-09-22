# Astra response review, round 2

Actual reviewer: **gpt-6-astra**, 2026-09-22. No Opus review is claimed.
Reviewed product revision: **d44eebe85dc6dd83fc57b3ba576a9b8135356af2**.
During review the coordinator added tests/docs through
**b9e9e25ade1e8744dea0d37495ee3dd09191045f**. The response product sources
`incident.rs`, `intrusion.rs`, `notify.rs`, and `smtp.rs` are identical at those
two revisions; this was checked with `git diff`.

Result: **CHANGES REQUIRED**. Four original functional findings remain open,
the original coverage finding cannot yet be closed, and two new P2 findings are
confirmed. The two original P1 defects are fixed. Severity and original
evidence in `astra-response-round1.md` are unchanged.

Scope: response fixes b3d7384/f3f2641, Python response counterparts, response
unit/contract suites, independent SMTP/incident/configuration tests, and
inspection of the coordinator's new native response process tests. Runtime,
CLI, team, first-half modules and Linux acceptance are **not** independently
approved by this report. No product source or existing test was changed by this
reviewer. Synthetic local credentials, local SMTP receivers, and temporary
local TLS certificates were used exclusively.

## Original finding disposition

| Original ID | Severity | Disposition and evidence |
| --- | --- | --- |
| R-INTRUSION-LIFETIME | P1 | Resolved. Context owns a strong `Arc<Detector>`, detector owns a weak Context, and the callback is weak. Original drop-return-value test passes; installation is idempotent. Coordinator native compromise E2E supplies actual serve-path containment evidence. |
| R-SMTP-PARSER | P1 | Resolved for original defects. Replies are byte-oriented and each line has the Python 8192-byte boundary. Original malformed UTF-8 boundary and oversized-line differential cases pass without a panic. |
| R-SMTP-CRAM | P2 | Resolved. Audited HMAC/MD5 primitives implement CRAM-MD5; original differential passes. New `cram_verified` receiver computes and checks the synthetic challenge response, and both implementations deliver successfully. |
| R-SMTP-AUTH | P2 | **Open, partially fixed.** Original advertised PLAIN-to-LOGIN fallback and PLAIN challenge cases pass. Python-supported old-style `AUTH=PLAIN` capability remains unsupported; details below. |
| R-SMTP-RECIPIENT | P2 | Resolved. Original partial-refusal and 251-forwarding differentials pass; source attempts the full recipient list and fails when none is accepted. |
| R-SMTP-ENVELOPE | P2 | **Open, partially fixed.** Angle-bracket display addresses and international SMTPUTF8 now send; comment-form mailboxes still produce invalid envelopes. |
| R-SMTP-HELO | P2 | Resolved. Original EHLO rejection / HELO success differential passes. STARTTLS remains dependent on advertised capability and a verified handshake. |
| R-SMTP-ERRORS | P2 | **Open, partially fixed.** Original greeting and new worker phase cases pass, but QUIT and certificate-verification error identities still differ. |
| R-INTRUSION-OVERFLOW | P2 | Resolved for original accepted-i64 arithmetic defect. Attributed and global sums saturate without poisoning; original extreme-weight regression passes. Broader accepted-input range losses are separately recorded as R-INTRUSION-CONFIG. |
| R-INCIDENT-CORRUPT | P2 | Resolved. `open_incident`, retry and assessment distinguish NotFound from state read/JSON errors; original corrupt-file differential passes. |
| R-INCIDENT-SHAPE | P2 | **Open, partially fixed.** Original five examples pass, but pair-list dictionary key conversion still changes successful Python values and accepts Python-rejected keys. |
| R-NOTIFY-MODE | P2 | Resolved. Shared config/password helper now checks `07777`; original 04600 regression passes. |
| R-SMTP-SECRET-LIFETIME | P2 | Resolved by source inspection and synthetic auth execution. Password ownership and reversible PLAIN/LOGIN buffers are transferred into `SecretBytes`, trimming borrows the secret buffer, base64 output is wrapped without a cloning String, and auth writes borrow zeroizing buffers. No memory dump or real credential was examined. |
| R-RESPONSE-COVERAGE | P2 | **Open pending integration verification.** Coverage substantially expanded, including actual trusted SMTPS/STARTTLS, exposure merge/absence, and coordinator live serve retry/cancellation. However the unchanged principal live-run cancellation unit test fails on the reviewed integrated runtime revision (see evidence); original case-to-test mapping and a green integrated rerun remain required. |

## Remaining original defects

### R-SMTP-AUTH — P2

`rust/src/smtp.rs:196–204` only parses capability strings beginning `AUTH `.
Against a receiver advertising `250 AUTH=PLAIN`, Python sends AUTH PLAIN and
delivers; Rust returns `SMTPNotSupportedError` before authenticating. This is an
existing Python-supported SMTP negotiation path, not a new requested feature.

Repro: `smtp_remaining_address_capability_and_completion_parity`, scenario
`auth_equals`. Restore the original capability parsing/negotiation semantics,
including the old-style AUTH form, while retaining current challenge/fallback
successes and zeroizing secret buffers.

### R-SMTP-ENVELOPE — P2

`rust/src/smtp.rs:183–189` only handles angle brackets. A valid configured
`sender@example.com (Synthetic Sender)` becomes Python envelope
`sender@example.com`; Rust emits the comment inside `<...>`. The controlled
receiver accepts Python and rejects Rust with `SMTPSenderRefused`.

Repro: same matrix, scenario `comment_address`. Parse the supported mailbox
forms for both sender and recipient envelopes while retaining their display
headers. The tested non-ASCII SMTPUTF8 recipient succeeds in both languages.

### R-SMTP-ERRORS — P2

`rust/src/smtp.rs:171` discards the QUIT result. A receiver returning 500 to
QUIT yields Python `SMTPResponseException`, while Rust reports `sent`.
`smtp.rs:io_error` maps all TLS `InvalidData` errors to `SSLError`; an untrusted
certificate produces Python `SSLCertVerificationError`, but Rust `SSLError`,
in both STARTTLS and SMTPS. These are the public persisted/CLI error strings.

Repros: matrix `quit_failure` and
`smtp_tls_verified_starttls_smtps_and_untrusted_cert_parity`. The latter proves
that the certificate is rejected **before any SMTP application command**;
there is no observed fail-open TLS vulnerability. Preserve the error identity
and completion semantics without incorporating server reply text or secrets.

### R-INCIDENT-SHAPE — P2

`rust/src/incident.rs:148` calls Python-like `str` on dictionary keys, which is
not Python's `dict` followed by JSON serialization. Across actions, assessment
and notification, `[[true,1]]` serializes to Python `{"true":1}` but Rust
`{"True":1}`; null similarly becomes `null` versus `None`. `[[[],1]]` is
Python `incident_corrupt` (unhashable key) but Rust silently accepts `{"[]":1}`.

Repro: `incident_full_shape_differential`: 168 inputs across all fourteen model
fields, with nine differences. Preserve successful conversion/key semantics
and reject Python's documented `incident_corrupt` cases; do not silently
reinterpret keys. These examples are not covered by the built-in-exception
deviation: Python returns a value or a documented ZeroPW error.

## New findings

### R-NOTIFY-COUNTER — P2 — persisted attempts can panic after successful send

`rust/src/notify.rs:425–430,439–442,477–479` narrows notification attempts to
`u64` and adds one without overflow handling. Load an incident with
`attempts=18446744073709551615` and successfully deliver through a controlled
SMTP receiver. Python records `sent`, attempts `18446744073709551616`; Rust
panics at line 479 **after the server accepted the message**. Release arithmetic
would wrap. Repeated retries can resend without persisting successful delivery.
This value comes from accepted state, not from a feasible natural retry count.

The same normalization changes a negative accepted count: with `attempts=-1`
and invalid notify configuration, Python records attempts 0 and next attempt
at clock+0.5; Rust records attempts 1 and clock+1. The independent oracle fixes
both clocks at 1700000000.0.

Repros: `successful_delivery_of_maximum_persisted_attempt_count_does_not_panic`
and `persisted_negative_notification_attempt_count_matches_python`. Preserve
Python's successful persisted-count behavior and avoid overflow/panic/wrap on
every terminal/pending/success path. Do not reset accepted values silently.

### R-INTRUSION-CONFIG — P2 — accepted configuration is ignored or rejected

`rust/src/intrusion.rs:156–160` returns defaults for non-object JSON, whereas
Python first applies `dict(data or {})`. The valid pair list
`[["weak_threshold",1]]` becomes threshold 1 in Python and silently becomes
threshold 8 in Rust. A configured first-signal trip is therefore delayed.

`intrusion.rs:181,195` also rejects positive thresholds/weights above i64:
`18446744073709551616` is accepted by Python as a threshold or scope-violation
weight, but Rust returns `intrusion_weak_threshold_invalid` or
`intrusion_weak_points_invalid`. A single denial with the latter weight should
cross the default threshold. This is a known-field behavior change, not the
documented ignored-unknown-key variation.

Repro: `detector_valid_pair_list_and_large_configuration_parity`. Honor every
successfully converted configuration and comparison without narrowing integer
ranges, silently defaulting, or weakening configured detection.

## Executed evidence and limits

- Original unchanged `astra_response_review`: **8 passed** (six review cases
  plus two oracle helpers), 3.52 seconds.
- Worker `response`: **26 passed, 1 failed**, 24.56 seconds. The failing
  `principal_lockdown_cancels_only_its_live_run` expects actions.runs_cancelled=1
  and observes 0 at line 411. An isolated repeat fails identically in 2.31
  seconds. The independent runtime reviewer subsequently confirmed the cause
  as **AR-RUNTIME06 (P2)**: an explicitly configured but absent socket directory
  makes the new execution acknowledgement socket fail to bind, so the HTTP-only
  run fails to start. That issue is assigned to the runtime Sol worker and is
  cross-referenced here, not duplicated as a response finding. The runtime
  review's separate **AR-RUNTIME05 (P1)** descriptor-isolation finding also
  remains an integration acceptance blocker outside this response scope.
- `response_contract`: **8 passed**, 6.03 seconds, after the coordinator added
  the two exposure cases. Includes the 1,250-input denial matcher differential,
  exact all-scope message rendering, weak expiry and first-use/combined signals.
- New independent `astra_response_round2`: the nine-test run had **3 helper
  passes and 6 failing review tests**, 10.90 seconds. Its subsequently added
  exposure merge/absence differential separately **passes**, 2.41 seconds.
  The failing assertions are retained for the implementation worker.
- The new SMTP tests successfully deliver over a temporary trusted certificate
  in **both SMTPS and STARTTLS**, using isolated child-process trust settings.
  Both modes reject untrusted certificates before application commands. CRAM
  challenge-response bytes are checked, SMTPUTF8 delivers, and all-auth-refused
  returns the same `SMTPAuthenticationError` in Python and Rust.
- `cargo clippy --offline --test astra_response_round2 -- -D warnings` passes.
- The coordinator reports all three native process scenarios pass: pending SMTP
  retry plus wider-scope resend, external incident cancellation of a live
  process, and no retry of a closed pending incident (41 administrator / 5 agent
  launches). Their test source was inspected; they were not rerun by this
  reviewer. Prior native compromise/response CLI results are supporting
  coordinator evidence, not independently rerun CLI acceptance.

Only the unique review test and this report were added. No merge, deployment,
runtime-state change, original-finding severity change, or feature waiver was
performed. Fixes require a fresh exact-revision review and integrated rerun.
