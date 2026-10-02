# Astra response mailbox recheck

Actual reviewer: **gpt-6-astra**, 2026-09-22. No Opus review is claimed.
Exact tested product revision: **55f95de0eec36d5261542fc6510c22be752eb726**
(Sol source `b39814e`).

Result: **CHANGES REQUIRED — R-SMTP-ENVELOPE remains P2**. The previous
comment-in-domain reproductions are fixed. A bounded check of comments in the
local part, domain, and adjacent to dots finds missing local-part quoting in
the new parser. No other response finding is reopened or severity changed.
All earlier reports and tests remain immutable.

## Verified fix and retained finding

The new code preserves a comment's position with whitespace and ends the
selected domain when that whitespace separates domain atoms. The prior actual
sender/recipient regression now passes: `sender@exa(comment)mple.com` selects
`sender@exa`, matching Python. The incorrect hardcoded worker expectation is
corrected. Its generated oracle genuinely queries Python EmailMessage and
getaddresses rather than duplicating Rust expectations. There are **25
generated inputs, 21 compared outputs**: the script filters four cases whose
first parsed address is empty. This is bounded domain evidence, not a 25-case
assertion or general RFC acceptance.

The same new whitespace is retained between local-part words without quoting
the resulting local part. Source: `rust/src/smtp.rs:222` (comment marker) and
`:257` (`envelope_cfws`, particularly its local-part whitespace return path).
An independent fourteen-fixture SMTP check demonstrates:

| Configured address position | Original Python SMTP mailbox | Native Rust SMTP mailbox |
| --- | --- | --- |
| Sender `sen(comment)der@example.com` | `<"sen der"@example.com>` | `<sen der@example.com>` |
| Recipient `sen(comment)der@example.com` | `<"sen der"@example.com>` | `<sen der@example.com>` |

The synthetic loopback receiver accepts both forms; original Python
`send_test_message` and the actual native `incident notify-test` command both
return `{"status":"sent"}`. The test captures their actual MAIL/RCPT command
bytes, so the discrepancy is not inferred from a separate parser. Rust emits
an unquoted local-part space where the original emits a quoted mailbox.

Twelve controls pass: sender and recipient variants of comments immediately
before/after `@`, immediately before/after a local-part dot, and immediately
before/after a domain dot. No external mail service, production credential or
DNS lookup is involved. The unchanged previous regression is separate and
still passes.

Reproduction: new immutable
`rust/tests/astra_response_final_recheck.rs::local_and_domain_comment_boundaries_preserve_transport_envelopes`.
Fix criterion: preserve Python's successful local-part quoting for these
comment forms while retaining the domain-boundary repair and all earlier
address, quoted-content, SMTPUTF8 and injection tests. This remains the
existing P2 envelope finding and the same supported-comment scope; it does not
request universal SMTP/RFC support.

## Executed evidence

Clean inherited environment, explicit Cargo/Python 3.12 PATH, offline Cargo:

| Suite | Result | Duration |
| --- | --- | --- |
| Immutable `astra_response_final` | 1 passed | 0.90s |
| Immutable `astra_response_review` | 8 passed | 3.43s |
| Immutable `astra_response_round2` | 10 passed | 9.82s |
| Immutable `astra_response_round3` | 6 passed | 2.84s |
| Immutable `astra_response_round4` | 2 passed | 0.55s |
| `response` | 27 passed | 21.28s |
| `response_contract` | 8 passed | 5.75s |
| `response_integer_boundaries` | 2 passed | 2.28s |
| `smtp::mailbox_tests` | 2 passed (14 fixed fixtures; 21 generated comparisons) | 0.04s |
| New `astra_response_final_recheck` | 1 failed: 2 differences, 12 passing controls | 0.90s |

Strict Clippy on the new independent test passes (0.78s). An independent
read-only execution of the generated Python oracle established the 21/25
count above; an explicit assertion of 25 outputs fails and is not used as
product evidence. No original assertion or worker test was modified.

Only this report and the unique new regression are added. The bounded result
does not reopen round 4's response coverage disposition or substitute for
whole-product exact-head testing, Linux/CI, or other reviewers' acceptance.
No product edits, merge, push, deployment or trusted-checkout changes were
performed.
