# Astra response acceptance, bounded final recheck

Actual reviewer: **gpt-6-astra**, 2026-09-22. No Opus review is claimed.
Exact reviewed and tested product revision:
**897c9a67cbe059c155e46f9a310fcb604fb2f93d** (Sol source `20d3979`).

Result: **PASS for the bounded response review; R-SMTP-ENVELOPE (original P2)
is resolved. No response review finding remains open.** This accepts the
documented fixes and measured compatibility scope, not universal RFC parsing,
full-product integration, Linux/CI, deployment, or unrelated modules.

The original round 1–4, final, and final-recheck reports and reproductions
remain preserved. This reviewer adds only this report and
`rust/tests/astra_response_acceptance.rs`; no product code or earlier test
assertion was changed.

## Closure evidence for R-SMTP-ENVELOPE

The parser retains comment boundaries, distinguishes local-part words from
domain atoms, quotes local parts containing comment-derived spaces, and keeps
Python's empty mailbox results for the documented malformed comment/dot
positions. Quoted/escaped parentheses and structural angle brackets are
handled independently. Configured message headers remain unmodified, and
existing header-injection rejection and SMTPUTF8 transport still pass.

Both immutable actual-transport reproductions now pass:

- `astra_response_final` verifies that comment-separated domain atoms select
  the same original mailbox for MAIL and RCPT.
- `astra_response_final_recheck` verifies that `sen(comment)der@example.com`
  produces `<"sen der"@example.com>` for both sender and recipient, alongside
  its twelve original local/domain/dot controls.

The new implementation corpus derives expectations from actual Python 3.12
EmailMessage, getaddresses and **smtplib.quoteaddr**, including final envelope
quoting. It inserts three comment forms at every character boundary in four
representative local, dotted, quoted and display-name addresses, and retains
the twenty-five domain cases. Independent execution and counting confirm
**334 comparisons, including four empty outputs**. There is no empty-output
filter; an absent parser result instead fails an assertion. All 334 comparisons
pass. The eighteen explicitly recorded mailbox fixtures also pass.

The new independent test goes beyond pure parser comparisons without widening
the scope: a synthetic loopback receiver captures actual original Python and
native administrator MAIL/RCPT commands for sixteen cases. Each of the four
empty-result forms is tested as sender and recipient, together with the
previous local comment, quoted local part, escaped parenthesis and display
controls in both positions. Both implementations successfully send and their
envelope commands match in all sixteen cases, including `<>` where Python
selects an empty mailbox. No external SMTP service or production credential is
used. Python is exclusively a test oracle/driver, not a product backend.

## Existing finding dispositions

| Original ID | Original severity | Disposition |
| --- | --- | --- |
| R-INTRUSION-LIFETIME | P1 | Resolved; unchanged lifetime regression passes. |
| R-SMTP-PARSER | P1 | Resolved for recorded byte-boundary and line-limit defects; original transport matrix passes. |
| R-SMTP-CRAM | P2 | Resolved; original and verified challenge-response cases pass. |
| R-SMTP-AUTH | P2 | Resolved; challenge, fallback, and old-style AUTH cases pass. |
| R-SMTP-RECIPIENT | P2 | Resolved; partial refusal and forwarding regressions pass. |
| R-SMTP-ENVELOPE | P2 | Resolved with immutable regressions, 334 derived comparisons and sixteen additional actual-transport cases above. |
| R-SMTP-HELO | P2 | Resolved; unchanged greeting fallback passes. |
| R-SMTP-ERRORS | P2 | Resolved; greeting/DATA read timeout, QUIT and TLS identity differentials pass. |
| R-INTRUSION-OVERFLOW | P2 | Resolved; exact large integer threshold cases pass. |
| R-INCIDENT-CORRUPT | P2 | Resolved; original state-corruption distinction passes. |
| R-INCIDENT-SHAPE | P2 | Resolved for recorded conversion/key findings; unchanged model and exact-key oracles pass. |
| R-NOTIFY-MODE | P2 | Resolved; exact special-mode-bit regression passes. |
| R-SMTP-SECRET-LIFETIME | P2 | Resolved; zeroizing authentication ownership is unchanged by mailbox fixes, synthetic auth paths pass. |
| R-RESPONSE-COVERAGE | P2 | Resolved in round 4 for the mapped original response assertions, including independently executed cross-process live-signer removal; narrow mailbox fixes do not change that evidence. |
| R-NOTIFY-COUNTER | P2 | Resolved; large/signed/floating successful count reproductions pass. |
| R-INTRUSION-CONFIG | P2 | Resolved for recorded pair-list and arbitrary-precision configuration cases; unchanged differentials pass. |

Severity and historical evidence have not been downgraded or rewritten.

## Exact-revision execution

Offline Cargo; cleared inherited environment; explicit Cargo/Python 3.12 PATH.

| Suite | Result | Duration |
| --- | --- | --- |
| `astra_response_final` | 1 passed | 1.11s |
| `astra_response_final_recheck` | 1 passed | 0.52s |
| `astra_response_review` | 8 passed | 6.34s |
| `astra_response_round2` | 10 passed | 13.81s |
| `astra_response_round3` | 6 passed | 2.83s |
| `astra_response_round4` | 2 passed | 0.59s |
| `canonical_helpers` | 4 passed | 0.07s |
| `response` | 27 passed | 20.73s |
| `response_contract` | 8 passed | 5.54s |
| `response_integer_boundaries` | 2 passed | 2.30s |
| `smtp::mailbox_tests` | 2 passed | 0.13s |
| New `astra_response_acceptance` | 1 passed (sixteen transport fixtures) | 0.89s |

Total: **72 test functions passed**, with the nested corpus/fixture counts
reported separately above. Strict Clippy for the new independent test passes
(0.84s); its rustfmt check and Git whitespace check pass. No full all-targets
suite was duplicated during this bounded review.

The original response coverage process scenario was independently executed in
round 4 and is not claimed as a fresh run here. Final integrated exact-head
acceptance and Linux/CI remain separate coordinator obligations. No merge,
push, deployment, trusted-checkout edit or production secret access occurred.
