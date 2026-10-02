# Astra response fix recheck

Actual reviewer: **gpt-6-astra**, 2026-09-22. No Opus review is claimed.
Reviewed and tested product revision:
**318386de404ccbff4cdd8c3e0a79dbb1a4aa25e0**.
Latest bounded product fix: `8d2f2b65376e3715c1b76a35486e2931227af131`
(Sol source `5dbac36`).

Result: **CHANGES REQUIRED — R-SMTP-ENVELOPE remains open at its original P2**.
The immutable round-4 failure is repaired, and every prior response review,
response, contract and integer-boundary test passes. Independently measuring
the new fix's own fourteen-case claimed Python-oracle corpus reveals one
incorrect expected value, confirmed through actual Python/native SMTP sends.
This report's filename does not signify approval.

Only this report and `rust/tests/astra_response_final.rs` are added. Original
reports, reproductions, product source, harness, CI and trusted checkout are
unchanged. All state, credentials and SMTP endpoints are synthetic/local.

## Retained finding: R-SMTP-ENVELOPE — P2

Locations: `rust/src/smtp.rs:194` (comment deletion), `:257` (envelope CFWS),
and `:503` (the new corpus's false Python expectation).

The new parser deletes unquoted nested comments without inserting spaces and
tracks quoted/escaped angle brackets. This repairs the four previous
sender/recipient cases around `@`; nested prefix/trailing controls still pass.
It also unconditionally joins domain fragments on either side of a comment.
That is not what the original Python product does for the fixture the worker
itself added, `sender@exa(comment)mple.com`.

The independent native-process regression captures the SMTP envelope commands
from the original `send_test_message` and native administrator
`incident notify-test`. Its receiver accepts every mailbox so the observation
does not depend on domain validity or external mail routing. Both products
return `{"status":"sent"}` in every case:

| Configured field | Original Python command mailbox | Rust command mailbox |
| --- | --- | --- |
| Sender `sender@exa(comment)mple.com` | `<sender@exa>` | `<sender@example.com>` |
| Recipient `recipient@exa(comment)mple.com` | `<recipient@exa>` | `<recipient@example.com>` |
| Control: comment immediately after `@` | `<sender@example.com>` / `<recipient@example.com>` | Identical |

Thus the current Rust transport changes the configured envelope destination
relative to the original behavior. This is a successful Python send, not an
uncaught exception covered by PORTING section 3.5. The claim in the new unit
test that its expected mailbox was measured with Python is contradicted by
measurement: independently applying Python 3.12 EmailMessage, getaddresses and
quoteaddr agrees with thirteen expectations and disagrees with this one. The
actual transport test confirms the same difference for sender and recipient.

Fix criterion: reproduce the original successful envelope extraction for the
demonstrated comment-in-domain case; correct the false worker expectation
using measured evidence. Preserve the immutable new regression and all prior
comment, quoted-content, SMTPUTF8 and injection cases. This is bounded to
existing behavior and the fix's own corpus; no universal RFC parser is required.

## Other dispositions and exact-revision evidence

Round 4's resolved findings remain resolved within their documented scope:
R-INTRUSION-LIFETIME and R-SMTP-PARSER (P1); R-SMTP-CRAM, R-SMTP-AUTH,
R-SMTP-RECIPIENT, R-SMTP-HELO, R-SMTP-ERRORS, R-INTRUSION-OVERFLOW,
R-INCIDENT-CORRUPT, R-INCIDENT-SHAPE, R-NOTIFY-MODE, R-SMTP-SECRET-LIFETIME,
R-RESPONSE-COVERAGE, R-NOTIFY-COUNTER and R-INTRUSION-CONFIG (P2).
Their original IDs, severities and evidence are unchanged. The latest product
patch changes only SMTP mailbox parsing and its local tests. Zeroizing auth
ownership, read-error classification and header injection checks are retained.

Executed with a cleared inherited environment and explicit Python 3.12/Cargo
PATH, using offline Cargo:

| Suite | Result | Duration |
| --- | --- | --- |
| Immutable `astra_response_review` | 8 passed | 3.17s |
| Immutable `astra_response_round2` | 10 passed | 9.60s |
| Immutable `astra_response_round3` | 6 passed | 2.83s |
| Immutable `astra_response_round4` | 2 passed | 1.59s |
| `response` | 27 passed | 21.95s |
| `response_contract`, clean rerun | 8 passed | 5.57s |
| `response_integer_boundaries` | 2 passed | 2.30s |
| `smtp::mailbox_tests` | 1 passed, fourteen hardcoded fixtures | 0.00s |
| New `astra_response_final` | 1 failed, two envelope differences and one passing control | 1.28s |

`cargo clippy --offline --test astra_response_final -- -D warnings` passes
(2.92s). Before committing this report, HEAD advanced to
`b7e9c58c729e38d659e2a00b37ffec3a5124c845`; a targeted Git diff confirms SMTP,
notification, incident, intrusion and the shared dictionary helper are
unchanged from the tested product revision.

The first contract run had three passes and five `state_write_failed` failures
while the host exhausted disk space; a separate shell command simultaneously
failed with `no space left on device`. Its unchanged rerun passes all eight.
No product fix or assertion modification was used to obtain that rerun.

Round 4 independently executed the original response coverage supplement,
including a live signer socket that disappeared after an incident declared by
another native process. This unchanged evidence closes that specific coverage
ID; it was not re-executed in this narrow mailbox recheck. Full-product
exact-head integration, Linux/CI and unrelated module acceptance remain the
coordinator's separate obligations. No merge, push or deployment was performed.
