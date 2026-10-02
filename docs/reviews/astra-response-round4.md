# Astra response review, round 4

Actual reviewer: **gpt-6-astra**, 2026-09-22. No Opus review is claimed.
Reviewed product fix: **4a526a2f391477596561f26b95e60cc92024313e** (Sol worker
`cef8ed3`). Tested integrated revision:
**584ac71d1db4cbae19d2f13eba5ec8398ee4d487**.
Final source comparison: **381b8e6dbaa14ae425fd09e12effc43be4799976**;
the response sources and shared dictionary helper are unchanged between the
tested and final comparison revisions (`git diff` verified).

Result: **CHANGES REQUIRED — R-SMTP-ENVELOPE remains open at P2**. Its preserved
reproductions pass, but a directly related supported-comment case still fails.
R-SMTP-ERRORS, R-INCIDENT-SHAPE and R-NOTIFY-COUNTER are resolved within the
measured scope. The specific original response coverage finding is closed by
the mapped behavioral tests and independently executed native live-signer
cleanup scenario. Full-product exact-head CI and Linux acceptance remain
separate, pending obligations.

Only this report and a new independent test file are added. Previous review
reports and reproductions are preserved. All values are synthetic and all SMTP
receivers are loopback. Python is a test oracle/driver, never a product backend.

## Existing finding disposition

| Existing ID | Original severity | Current disposition |
| --- | --- | --- |
| R-INTRUSION-LIFETIME | P1 | Resolved; unchanged detector-lifetime regression and installation tests pass. |
| R-SMTP-PARSER | P1 | Resolved for the original byte-boundary panic and line-limit defects; original malformed/oversized reply oracles pass. |
| R-SMTP-CRAM | P2 | Resolved; original CRAM and independently verified synthetic HMAC response tests pass. |
| R-SMTP-AUTH | P2 | Resolved for original challenge/fallback/old-style AUTH reproductions; unchanged matrices pass. |
| R-SMTP-RECIPIENT | P2 | Resolved; partial refusal and 251 forwarding cases pass. |
| R-SMTP-ENVELOPE | P2 | **Open, partially fixed.** All earlier fixtures pass; four interior-comment examples still fail as detailed below. |
| R-SMTP-HELO | P2 | Resolved; original EHLO-to-HELO fallback passes. |
| R-SMTP-ERRORS | P2 | Resolved for documented findings. Greeting and DATA reply timeouts now map to SMTPServerDisconnected; QUIT and certificate identities remain correct. |
| R-INTRUSION-OVERFLOW | P2 | Resolved; original large-weight and exact beyond-u64 cumulative-threshold checks pass. |
| R-INCIDENT-CORRUPT | P2 | Resolved; original corruption/NotFound differential passes. |
| R-INCIDENT-SHAPE | P2 | Resolved for documented shape/key findings. The full prior model corpus and exact numeric-key/pair-iterable reproductions pass; affected shared-helper team oracles pass. |
| R-NOTIFY-MODE | P2 | Resolved; exact special-bit secure-file regression passes. |
| R-SMTP-SECRET-LIFETIME | P2 | Resolved; zeroizing credential/auth-buffer ownership remains unchanged, and synthetic auth paths pass. |
| R-RESPONSE-COVERAGE | P2 | Resolved for the original response behavioral mapping and specific missing live-binding assertion; details and bounded limits below. |
| R-NOTIFY-COUNTER | P2 | Resolved for original overflow/signed-count and successful floating-count findings; unchanged differential tests pass. |
| R-INTRUSION-CONFIG | P2 | Resolved for original pair-list and arbitrary-precision accepted-config findings; prior mapping and exact-weight tests pass. |

## Remaining R-SMTP-ENVELOPE — P2

Location: `rust/src/smtp.rs:194–237`, especially insertion of a space when an
unquoted comment starts.

The new parser removes comments but inserts a literal space in their place.
Python's existing EmailMessage/send_message path accepts comments adjacent to
the local-part/domain boundary and derives the original bare mailbox:

| Configured sender | Python envelope | Rust envelope/result |
| --- | --- | --- |
| `sender(Internal)@example.com` | `sender@example.com`, sent | `sender @example.com`, SMTPSenderRefused |
| `sender@(Internal)example.com` | `sender@example.com`, sent | `sender@ example.com`, SMTPSenderRefused |

The same two recipient forms produce Python `sent` versus Rust
`SMTPRecipientsRefused`. These are ordinary successful Python sends through
the original product function, not uncaught-exception inputs or a new promise
of universal RFC support.

Independent reproduction:
`astra_response_round4::supported_comments_inside_mailbox_match_python` runs
original Python notification delivery and the actual native administrator
`incident notify-test` against a local receiver checking the intended mailbox.
It records the envelope commands and confirms four differences across six
fixtures; nested prefix and nested trailing-comment controls pass. No original
test was modified.

Fix criterion: derive the supported mailbox without introducing comment
whitespace into its envelope, preserving quoted content, display headers,
sender/recipient handling, existing SMTPUTF8 success and CR/LF rejection. Keep
the new test plus all prior address matrices. The scope is the demonstrated
original behavior; no universal SMTP/RFC compatibility claim is requested.

## Verified fixes and coverage

The dictionary helper now preserves integer keys as arbitrary-precision values
and distinguishes integers from binary64 floats. Mixed comparisons reconstruct
the exact integer represented by an integral finite float instead of rounding
both operands. Two-key object entries are treated as iterable key pairs in
insertion order. Existing bool/int collisions, unhashable rejection, distinct
large integers and supported pair conversions pass; the 33 affected team
oracle cases also pass. No duplicate private numeric emulation was introduced.

Successful notification counts have their own addition path, so accepted
floating values retain Python's successful `previous + 1` behavior while
integer values keep exact precision. Pending/terminal-failure normalization
remains separate. All original count reproductions pass.

SMTP reply-read failures are now wrapped as SMTPServerDisconnected. TLS
handshaking happens before reply parsing, preserving certificate-verification
errors; trusted STARTTLS/SMTPS and untrusted rejection tests pass. The worker's
one changed assertion in `response.rs` (DATA timeout: TimeoutError to
SMTPServerDisconnected) is justified, not a weakening: a new independent
DATA-timeout differential in this round explicitly observes
`{"status":"failed","error":"SMTPServerDisconnected"}` from both original
Python and native Rust. The immutable round-3 greeting-timeout test also passes.

`RESPONSE_TEST_MAP.md` maps the original 26 incident, 37 intrusion and 29
notification methods by behavioral intent, including the subsequent contract
and process supplements. The previously missing cross-process assertion now
uses a real native signer socket. The independently rerun process scenario
first confirms that socket exists and accepts a local Unix connection, then
declares an incident through a separate native administrator process, observes
both HTTP and SSH child cancellation in native audit output, and asserts the
signer socket disappears. It also checks subsequent authority denial and
synthetic-value absence. The companion scenarios verify retry after SMTP
becomes available, resend after widening and no retry of a closed incident.

This closes the particular response-area coverage gap without claiming that
every conceivable input is tested or that the complete product has passed
Linux/exact-head integration. The original compromise/CLI process tests also
passed in this reviewer's immediately preceding lifecycle run; this round
specifically reran the updated response polling process adapter.

## Executed evidence

- `astra_response_review`: **8 passed**, 3.19s.
- `astra_response_round2`: **10 passed**, 9.44s.
- Immutable `astra_response_round3`: **6 passed**, 3.01s; all four formerly
  failing functional tests now pass.
- `response`: **27 passed**, 21.92s.
- `response_contract`: **8 passed**, 5.80s.
- `response_integer_boundaries`: **2 passed**, 2.29s.
- `canonical_helpers`: **4 passed**, 0.05s.
- `team_oracle`: **33 passed**, 1.72s.
- Native `response_polling_boundaries_in_native_processes`: **passed**,
  14.77s; underlying **3 process cases passed**, 14.685s, **44 native admin /
  6 native agent launches**.
- New interior-comment review test: **failed**, 0.96s, with the four concrete
  differences above.
- New DATA-timeout differential: **passed**, 1.15s.
- `cargo clippy --offline --test astra_response_round4 -- -D warnings`:
  **passed**, 0.14s.

No merge, deployment, CI/harness alteration, production credential access or
future-fix acceptance was performed. The independent response verdict remains
REVISE solely for the retained P2 envelope finding within this bounded scope.
