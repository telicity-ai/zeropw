# Astra response review, round 3

Actual reviewer: **gpt-6-astra**, 2026-09-22. No Opus review is claimed.
Exact product revision reviewed and tested:
**92abed0b02fe4c31963ada64e5a2d047276cf833**.

Result: **CHANGES REQUIRED**. Four existing functional P2 IDs remain open:
R-SMTP-ENVELOPE, R-SMTP-ERRORS, R-INCIDENT-SHAPE, and R-NOTIFY-COUNTER.
R-RESPONSE-COVERAGE remains open with the specific integration/assertion
boundary below. No new ID or severity downgrade is introduced. The round-1
and round-2 reports and their evidence are preserved.

This is a bounded independent compatibility review of the response fixes,
their Python counterparts, SMTP success/error behavior, incident conversion,
and notification/detector integer boundaries. All credentials are synthetic;
SMTP endpoints are loopback and TLS certificates are temporary test roots.
Only a new test file and this report are added. No product source, previous
test assertion, harness, CI, runtime state or trusted checkout is changed.

## Finding disposition

| Existing ID | Original severity | Round-3 disposition and evidence |
| --- | --- | --- |
| R-INTRUSION-LIFETIME | P1 | Resolved. The unchanged dropped-return-value regression passes; Context retains its detector and detector/callback references avoid a strong cycle. Existing installation/idempotence tests pass. |
| R-SMTP-PARSER | P1 | Resolved for original panic/line-boundary defects. Original malformed UTF-8 and oversized-line differentials pass; byte-based bounded reply parsing is retained. |
| R-SMTP-CRAM | P2 | Resolved. Original CRAM and independent verified synthetic HMAC challenge-response tests pass. |
| R-SMTP-AUTH | P2 | Resolved for the original and round-2 reproductions. PLAIN challenge, PLAIN-to-LOGIN fallback and old-style AUTH=PLAIN succeed; all-auth-refused identity matches Python. Zeroizing authentication buffers remain in use. |
| R-SMTP-RECIPIENT | P2 | Resolved. Partial recipient refusal and 251-forwarding differentials pass; transport attempts the list and delivers to accepted recipients. |
| R-SMTP-ENVELOPE | P2 | **Open, partially fixed.** Display-angle addresses, spaced trailing comments and SMTPUTF8 pass. Prefix comments and trailing comments without a preceding space still fail; four new measured differences below. |
| R-SMTP-HELO | P2 | Resolved. Original EHLO rejection/HELO success case passes; configured STARTTLS still requires advertised support and a verified handshake. |
| R-SMTP-ERRORS | P2 | **Open, partially fixed.** QUIT failure and both certificate-verification identities now pass. An SMTP greeting read timeout still exposes the wrong exception name. |
| R-INTRUSION-OVERFLOW | P2 | Resolved. Original extreme accepted-i64 test and exact >u64 combined-weight threshold test pass. Attributed/global accumulation now uses arbitrary-precision integers without wrapping or poisoning detection. |
| R-INCIDENT-CORRUPT | P2 | Resolved. Original corrupt-state differential passes; incident open/retry/assessment preserve the distinction between NotFound and read/JSON corruption. |
| R-INCIDENT-SHAPE | P2 | **Open, partially fixed.** Original and round-2 shape oracles pass, including bool/null keys and unhashable rejection. Newly reused dictionary helpers merge distinct large numeric keys and reject a Python-supported pair iterable. |
| R-NOTIFY-MODE | P2 | Resolved. Unchanged exact special-mode-bit regression passes; shared secure-file helper checks 07777. |
| R-SMTP-SECRET-LIFETIME | P2 | Resolved by source review and synthetic transport tests. Password bytes and reversible AUTH payloads remain in SecretBytes; the new changes do not introduce plaintext credential Strings or error/log output. |
| R-RESPONSE-COVERAGE | P2 | **Open with bounded remaining evidence gap.** The original case-group mapping exists, response/contract tests are green, and the previously failing principal cancellation test now passes. The mapping still explicitly lacks the original cross-process manual-incident assertion that an already-live signer binding is released. This review does not independently execute the native process suite or final integrated/Linux checks. Details below distinguish these obligations. |
| R-NOTIFY-COUNTER | P2 | **Open, partially fixed.** u64 overflow, signed integer counts and negative pending backoff are repaired. Successful delivery still silently normalizes Python-accepted floating counts to zero before incrementing. |
| R-INTRUSION-CONFIG | P2 | Resolved for the documented finding. Valid pair-list configuration and >u64 known thresholds/weights pass Python differential tests. Public fields use PyInt with decimal JSON serialization, and exact large weights trip at the correct second signal. No accepted integer narrowing was found in those comparisons. |

## Remaining functional evidence

### R-SMTP-ENVELOPE — P2

Location: `rust/src/smtp.rs:194–203`.

`mailbox` handles angle brackets and otherwise splits only on `" ("`. The
existing Python EmailMessage/send_message path accepts both
`sender@example.com(Synthetic Sender)` and
`(Synthetic Sender) sender@example.com`, producing envelope
`sender@example.com`. Rust sends the comment as part of the envelope. A local
receiver checking the expected mailbox delivers Python's message and rejects
Rust's with `SMTPSenderRefused`. The corresponding two recipient forms yield
Python `sent` versus Rust `SMTPRecipientsRefused`. The spaced trailing-comment
control succeeds in both implementations.

Repro: `smtp_supported_comment_mailbox_forms_match_python` in the new
`rust/tests/astra_response_round3.rs` (four differences across five fixtures).
Restore supported mailbox parsing for sender and recipients, retaining display
headers and the current CR/LF rejection. A special case for only one comment
position does not meet the original address-parsing fix criterion.

### R-SMTP-ERRORS — P2

Location: `rust/src/smtp.rs:24–40,321–330`.

A loopback receiver accepts the connection and withholds its greeting beyond
the configured 50ms read timeout. Python `_send` raises
`SMTPServerDisconnected`; Rust's public notify-test result reports
`TimeoutError`. CPython `smtplib.SMTP.getreply` catches `OSError` from its reply
read (including socket timeout) and raises `SMTPServerDisconnected`. Rust
routes all reads through generic OS error classification instead. This changes
persisted notification errors and public CLI output.

Repro: `smtp_reply_timeout_identity_matches_python`, independently failing on
the exact reviewed revision. Preserve the transport-phase exception identity;
a connect timeout and an SMTP reply-read timeout are distinct paths. Retain
the now-passing TLS certificate and QUIT behavior. The older worker
`smtp_transport_failure_names_track_the_failing_phase` hardcodes `TimeoutError`
for its DATA reply timeout; its green result is not Python-equivalence proof.
That assertion was not edited by this reviewer and requires an explicit
oracle-backed correction by the implementation worker.

### R-INCIDENT-SHAPE — P2

Location: `rust/src/incident.rs:141–169`, through
`rust/src/team/commit.rs:622–645,665–684`.

The promoted helper compares numeric dictionary keys through f64. For
`[[9007199254740992,"first"],[9007199254740993,"second"]]`, Python preserves
two dictionary entries; Rust overwrites the first with the second. A float
`9007199254740992.0` and integer `9007199254740993` likewise remain distinct in
Python and collapse in Rust. All three incident dictionary fields (actions,
assessment, notification) show the same loss.

Python also successfully converts `[{"a":0,"b":1}]` to `{"a":"b"}`: its
inner dictionary is a two-element iterable over keys. The shared helper only
supports arrays and strings as pair items, so Rust returns `incident_corrupt`.

Repro: `incident_dictionary_keys_keep_exact_python_numeric_identity`: nine
differences across eighteen fixtures. True/1 collision, null/string output
collision and unhashable-key rejection controls pass. Fix exact Python key
equality and supported pair iteration in the common helper with regression
coverage for its existing consumers; do not add another local emulation.
Every reported mismatch is a successful Python return, so PORTING §3.5 does
not apply.

### R-NOTIFY-COUNTER — P2

Location: `rust/src/notify.rs:425–429,493–494`.

The pending/terminal-failure Python branches intentionally normalize non-int
counts, but the successful-send branch uses `previous_attempts + 1` directly.
Rust applies the integer-only helper to success too. After actual successful
SMTP delivery, the differential returns:

| Persisted attempts | Python successful attempts | Rust successful attempts |
| --- | --- | --- |
| 1.5 | 2.5 | 1 |
| -2.5 | -1.5 | 1 |
| 1.0 | 2.0 | 1 |

Repro: `successful_notification_numeric_attempts_match_python`; true and
positive/negative integers beyond u64 are passing controls. These are measured
successful returns, not uncaught TypeError/ValueError cases. PORTING §3.5
therefore cannot justify silently resetting them. Preserve each branch's
Python behavior while keeping the arbitrary-precision integer repair.

## Coverage and execution

Fresh unchanged suites at the reviewed product revision:

- `astra_response_review`: **8 passed**, 3.41s.
- `astra_response_round2`: **10 passed**, 9.73s, including trusted SMTPS and
  STARTTLS handshakes, rejection before application commands for untrusted
  certificates, and the fixed original AUTH/QUIT/key/counter cases.
- `response`: **27 passed**, 21.93s. The earlier failed
  `principal_lockdown_cancels_only_its_live_run` now passes.
- `response_contract`: **8 passed**, 5.82s.
- `response_integer_boundaries`: **2 passed**, 2.31s.
- `canonical_helpers`: **4 passed**, 0.04s.
- New `astra_response_round3`: **2 helper passes, 4 failing review tests**,
  3.10s. The three original probes reproduced again in this combined run;
  the added timeout probe also independently fails (2.84s).
- `python3.12 -m unittest tests.test_incident tests.test_intrusion
  tests.test_notify -q`: **421 passed**, 69.482s. The loader includes imported
  and inherited test cases in addition to the 92 methods defined in these
  response modules; this is not a claim of 421 distinct response requirements.
- `cargo clippy --offline --test astra_response_round3 -- -D warnings`:
  **passed**, 2.82s.

The prior response test changes between the integrated fix and this revision
are only `.into()` adapters in three DetectorConfig fixtures; their assertions
remain intact. The original review tests were not weakened.

`rust/RESPONSE_TEST_MAP.md` supplies the original 26/37/29 case-group mapping;
it does not claim a one-for-one Rust translation. Subsequent response-contract
and independent review tests supply the listed rule-table, rendering,
exposure-merge/absence, window, integer and actual TLS evidence. The native
process script supplies concrete pending retry, widening resend, closed retry
and external manual run-cancellation assertions. Its own stated outstanding
cross-process already-live signer-binding release is still not asserted by
those scenarios; an API-only signer shutdown check does not replace it.

R-RESPONSE-COVERAGE therefore remains open for that specific original response
assertion and a refreshed mapping/evidence check. Separately, final exact-head
integrated testing and Linux acceptance are whole-product obligations; they
should not be represented as response-unit defects or as completed by the
bounded green suites here. Runtime AR-RUNTIME-07 and AR-CLI-02 work is owned by
the coordinator's separate review/fix cycle and is not duplicated here. This
report approves neither forthcoming fixes nor unrelated modules, and makes no
universal SMTP-compatibility claim.
