# Astra response-unit review, round 1

Reviewed commit: `692fc7566005f2dcd25e9b48fd401031f01c79de`.
Actual reviewer model: **gpt-6-astra**. Review date: 2026-09-22.
Result: **CHANGES REQUIRED — 14 open findings**. No Opus review is claimed.

Authority: the current user requested every existing Python feature in Rust, with no feature loss, and replaced the earlier Opus requirement with independent Astra review. Merely entering an incompatibility in `DEVIATIONS.md` does not approve it.

Scope: `incident.rs`, `intrusion.rs`, `notify.rs`, their Context/audit/containment contracts, Python counterparts, all 26 incident + 37 intrusion + 29 notify Python cases, and the 18 Rust `response.rs` cases. Read current product intent, security design, implementation, compromise-response design and Rust porting contract. This is a bounded response-unit review, not acceptance of the other concurrently implemented modules.

## Evidence

- `cargo test --offline --test response`: **18 passed**, 9.54 seconds.
- Added independent `rust/tests/astra_response_review.rs`, without editing product code or existing tests.
- `cargo test --offline --test astra_response_review -- --nocapture`: **2 helper tests passed, all 6 actual review tests failed**, 5.44 seconds. Failures reproduce the findings below and intentionally express the required behavior.
- SMTP probes used loopback receivers, synthetic users and no production credentials. Python `zeropw.notify._send` and Rust `send_test_message` used identical SMTP configuration and server behavior; SMTP paths converge on each implementation's actual transport.
- No full-suite PASS is claimed. The coordinator's integrated run must supply that evidence.

## Open findings

### R-INTRUSION-LIFETIME — P1 — installed protection disappears when the return value is dropped

Location: `rust/src/intrusion.rs:571`, especially 583–591.

Both `ctx.intrusion` and the audit callback hold only `Weak<Detector>`. The temporary returned by `intrusion::install(ctx, None)?;` is the only strong reference and drops at statement end. Two subsequent `tools_unknown` denials leave the principal active and no incident open. Python `install` retains the detector on Context and through the bound callback. Existing Rust tests conceal this by retaining `_d`.

Repro: `installed_detector_survives_dropped_return_value`.

Fix criteria: installing attaches live protection for Context/server lifetime independently of whether the caller retains the return value; repeated installation returns the same detector; do not introduce a Context/Detector strong-reference leak. Verify automatic containment through the actual serve installation path as well.

### R-SMTP-PARSER — P1 — a server response can panic; reply reads also lose Python's size boundary

Location: `rust/src/notify.rs:672–685`.

The raw network string is sliced at UTF-8 byte positions 3 and 4. Greeting `22é hi\r\n` panics at line 681, where Python raises `SMTPConnectError`, which the delivery layer records as pending. A panic is not converted by `deliver` into pending. When invoked within a detector decision, unwinding can poison its decision mutex; when invoked from a serve retry loop it can terminate that loop. Separately, the read has no line bound: a `220 ` greeting plus 9,000 ASCII characters is accepted and Rust sends, while Python raises `SMTPResponseException` before proceeding. Unbounded allocation is also a resource-exhaustion risk.

Repro: `smtp_python_interoperability_matrix`, scenarios `malformed_utf8_boundary` and `long_reply`.

Fix criteria: bounded byte-oriented SMTP response parsing, no UTF-8 slicing panic, Python-equivalent response/error behavior, and malformed/oversized reply regression tests through deliver and detector/serve paths.

### R-SMTP-CRAM — P2 — existing CRAM-MD5 SMTP authentication was removed

Location: `rust/src/notify.rs:621–632`; `rust/DEVIATIONS.md:11`.

The receiver advertises only `AUTH CRAM-MD5`. Python authenticates and sends; Rust returns `SMTPException` without issuing AUTH. This confirms the previously open finding. The deviation row is not an accepted feature waiver.

Repro: matrix scenario `cram`.

Fix criteria: restore CRAM-MD5 negotiation using an approved/audited primitive dependency, with synthetic challenge-response verification and a real delivery test. Preserve Python's supported authentication negotiation instead of documenting removal.

### R-SMTP-AUTH — P2 — PLAIN challenge flow and authentication fallback are missing

Location: `rust/src/notify.rs:621–630`.

With `AUTH PLAIN LOGIN`, a server refusing PLAIN with 535 but accepting LOGIN receives mail from Python. Rust aborts immediately after PLAIN. A PLAIN server returning a 334 challenge also works in Python, which responds with the auth payload, but Rust expects 235 immediately and aborts. Both are separate compatibility paths beyond CRAM-MD5.

Repro: matrix scenarios `auth_fallback`, `plain_challenge`.

Fix criteria: implement advertised-mechanism fallback and the complete challenge flow, preserving successful SMTP AUTH statuses and keeping credentials out of errors/logging.

### R-SMTP-RECIPIENT — P2 — one recipient refusal suppresses mail to every valid recipient

Location: `rust/src/notify.rs:635–639`.

Given `[bad@example.com, good@example.com]`, a 550 for the first address makes Rust abort before attempting the good address. Python continues, sends to the accepted address, and `_send` succeeds. Rust also rejects 251 (successful forwarding) because it requires exactly 250 for every RCPT. The configured incident notification may therefore stay pending forever despite a reachable valid administrator address.

Repro: matrix scenarios `partial_recipient`, `recipient_251`.

Fix criteria: accept the same successful recipient statuses, attempt the recipient list, send when any recipient is accepted, and report the Python-equivalent failure when all recipients fail.

### R-SMTP-ENVELOPE — P2 — display-name addresses produce invalid SMTP envelopes

Location: `rust/src/notify.rs:635–637`.

`sender = "Display Name <sender@example.com>"` is a valid existing configuration. Python sends `mail FROM:<sender@example.com>`; Rust sends `MAIL FROM:<Display Name <sender@example.com>>`, which the controlled server rejects. Recipients use the same raw interpolation.

Repro: matrix scenario `display_address`.

Fix criteria: retain display names in message headers but derive SMTP envelope mailbox addresses with Python-equivalent address parsing. Cover sender and recipient display names and international address behavior supported by the Python path.

### R-SMTP-HELO — P2 — previously supported SMTP servers without EHLO no longer work

Location: `rust/src/notify.rs:582`, `663–667`.

A plain SMTP receiver returns 500 to EHLO and 250 to HELO. Python falls back to HELO and sends; Rust aborts immediately. No authentication or TLS downgrade is involved in the reproducer: it is the existing loopback plain transport mode.

Repro: matrix scenario `helo`.

Fix criteria: preserve the SMTP greeting fallback where Python permits it, while continuing to require STARTTLS when configured.

### R-SMTP-ERRORS — P2 — persisted transport error identities lose the public Python contract

Location: `rust/src/notify.rs:547–551`, `658–683`.

The server's ordinary `554 unavailable` greeting becomes Python `SMTPConnectError`, but Rust reports generic `SMTPException`. The same generic response helper collapses authentication, sender, recipient, data, disconnect and other failures. `deliver` persists these names in `notification.last_error` and audit reasons; `notify-test` exposes them as `error`, so this is observable behavior, not just an internal exception type.

Repro: matrix scenario `greeting_rejected` (the malformed response also illustrates the required distinction).

Fix criteria: map each transport phase to the existing exception identity, with focused tests for greeting/auth/sender/all-recipients/DATA/TLS/disconnect/timeout failures. Do not put server-supplied reply text or authentication values into errors.

### R-INTRUSION-OVERFLOW — P2 — accepted settings can disable all subsequent detection

Location: `rust/src/intrusion.rs:444`, `502`, and mutex acquisition in `on_record`.

Set `weak_threshold=9223372036854775807` and `weak_points.scope_violation=4611686018427387904`. Both values are valid and accepted. Two scope denials should exceed the threshold; Python opens an incident (separately verified). Rust's i64 sum overflows. In debug it panics under the bookkeeping mutex; Audit swallows the panic, but the poisoned mutex makes all future `on_record` calls silently skip. An ensuing one-shot SSH misuse signal also opens nothing. In unchecked release arithmetic the total wraps instead of reaching the threshold.

Repro: `large_accepted_weak_weights_do_not_poison_detection`.

Fix criteria: preserve nonnegative accumulated-score comparisons without overflow for every accepted configuration, for attributed and global buckets. A failure must not permanently disable unrelated strong detection. Do not fix by silently narrowing accepted Python settings or allowing integer wrap.

### R-INCIDENT-CORRUPT — P2 — corrupt existing incidents are silently replaced or ignored

Location: `rust/src/incident.rs:412–414`, `rust/src/notify.rs:491`.

Point policy control at `inc-broken` and write `{` to its incident JSON. Python retry and open both raise documented `StateError(state_corrupt)`. Rust retry returns `Ok(0)`, and Rust open succeeds with a fresh incident and replaces the control pointer. Python only absorbs `NotFound` for the explicitly supported lost-file/corrupt-model cases; Rust catches every error. This conceals damaged state and loses the original incident's identity/assessment context.

Repro: `corrupted_incident_is_not_treated_as_missing`, including the Python oracle.

Fix criteria: distinguish NotFound from state I/O/JSON corruption and propagate the latter as Python does. Apply the same exception-scope discipline to `assess` principal/connection reads, which also use catch-all `if let Ok` where Python catches only NotFound.

### R-INCIDENT-SHAPE — P2 — deserialization silently loses state accepted by Python

Location: `rust/src/incident.rs:43–111`.

Measured `Incident.from_dict` returns versus Rust:

| Field/input | Python result | Rust result |
| --- | --- | --- |
| `notification={}` | default `not_configured`, attempts 0 | empty object |
| `principals="ab"` | `["a","b"]` | empty list |
| `actions=[["stopped",true]]` | `{"stopped":true}` | empty object |
| `trigger=12` | string `"12"` | string `"manual"` |
| `runtime=12` | number `12` | null |

These are successful Python returns, so PORTING §3.5 cannot excuse their loss. Mutating/resaving these loaded incidents rewrites their contents. The same typed filtering appears on rule/detail/closed_at/widened_from.

Repro: `incident_document_python_roundtrip_shapes`, differential Python oracle.

Fix criteria: preserve Python's successful conversion/default rules and exact values; fail with `incident_corrupt` only where Python does so or a specifically permitted representational exception applies. Add roundtrip/differential tests for the entire model.

### R-NOTIFY-MODE — P2 — secure-file validation ignores special mode bits

Location: `rust/src/notify.rs:39`.

A valid notify file set to mode `04600` passes Rust's `mode & 0777 == 0600`. Python compares `stat.S_IMODE`, including special permission bits, and rejects it as `notify_config_insecure`. The same helper checks password files.

Repro: `notify_secure_mode_includes_special_bits`.

Fix criteria: enforce exactly the same mode mask/ownership rule on both files and test special bits as well as ordinary group/other access bits.

### R-SMTP-SECRET-LIFETIME — P2 — SMTP passwords bypass the required zeroizing secret type

Location: `rust/src/notify.rs:606–630`.

This is a direct source finding: password bytes are read into ordinary `String`, copied with `trim().to_owned()`, formatted into another ordinary String, then base64 encoded and formatted into command Strings. None is zeroized. PORTING §3.2 and the all-module deviation promise require raw secret bytes to live in `SecretBytes`; SMTP is ZeroPW's own foundational credential. Dropping normal Strings after send does not erase these allocations. No memory dump or production credential inspection was performed.

Fix criteria: keep plaintext and reversible auth payloads in zeroizing/redacted buffers for every success/error path, including temporary formatting/encoding buffers. Retain the current prohibition on credentials in logs and error responses. Verify by code review plus synthetic auth transport tests; a crash-memory dump is not required.

### R-RESPONSE-COVERAGE — P2 — the mandatory behavioral port is incomplete

Location: `rust/tests/response.rs`, against all three Python test files.

There are 92 original cases and only 18 representative Rust cases. Count alone would not prove loss, but inspection shows missing assertions for principal-specific live-run cancellation and socket release while another principal's run survives; idempotent containment counts; handle-rotation failure continuation; SSH fingerprint assessment; pre-principal audit exclusion; recommended assessment after widening; enumeration lifetime and latch rearming; burst once-per-crossing; reentrant/concurrent detector execution; decision failure recovery; actual serve installation/retry and cross-process incident application. These are explicit PORTING §4 test obligations and key security boundaries. Existing green tests did not catch the concrete failures above.

Fix criteria: port every original case's intent/assertions (combining fixtures is fine), provide a case-to-test mapping, and add the new regressions. Coordinate CLI/serve-owned cases with those workers; do not mark them covered by response-only tests or substitute API-only checks for original integration checks.

## Handoff constraints

All 14 IDs are open at the reviewed SHA. The existing CRAM/MIME deviation row does not authorize removal; no newly discovered feature loss is waived. Product changes were not made by this reviewer. The independent regression file is intentionally failing until fixes land; maintain its assertions and expand tests rather than ignoring it. Re-review must bind to the next exact SHA and inspect all fixes, then run the integrated suite. Verified TLS handshakes, complete CLI/server wiring, and remaining first-half modules were not executed by this bounded review.
