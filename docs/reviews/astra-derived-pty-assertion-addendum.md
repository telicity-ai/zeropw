# Astra derived PTY assertion correction

- Actual reviewer: `gpt-6-astra`.
- Sol fix: `8bf24e8b07b34dc4f4ea668a705b71f1cfa3e142`; integration: `69e9bf99780140f5763d7dcc43fb69fbaa6b636d`.
- **Bounded test-integrity correction accepted.** This is not a product fix, diagnosis of the historical Linux timeout, or overall acceptance.

The coordinator found a concrete omission after the diagnostic instrumentation: `astra_runtime_final.rs` derives its keeper from round three using a textual replacement of ` p.wait(timeout=8)` with a nonzero-exit assertion. Adding `try:` in the source keeper made that replacement silently match nothing. The earlier diagnostic review `astra-pty-timeout-diagnostic-review.md` remains immutable but did not catch this dependent-test defect; its local diagnostic-path result does not prove preservation of this separate assertion.

The correction checks that the new exact wait anchor occurs **once**, performs one replacement, and explicitly checks the resulting nonzero assertion is present. Source drift now fails loudly rather than silently deleting the expected nonzero-child condition. The existing repeated-prompt/noecho assertions and timeout values remain.

## Independent negative control

The reviewer extracted the proposed source and applied the same derived-driver transformations. Only in this disposable probe, the second-prompt abort bytes were replaced with a valid synthetic recovery passphrase, allowing actual native initialization to finish successfully. Two variants then established the assertion's effect:

- Without the nonzero guard: driver exit **0**.
- With `try:assert p.wait(timeout=8)!=0`: successful native initialization JSON appeared, then the keeper raised AssertionError and the driver exited **1**.

Thus the corrected derived test rejects the successful-child case it is intended to reject. The probe did not edit product or fixture files. An initial probe accidentally referenced a nonexistent worker binary and stopped at prompt timeout; it was corrected to the actual integration binary before either result above. The binary uses unchanged current product source; only the extracted driver was varied.

The worker separately reports all three affected suites plus strict Clippy/fmt passing. Those worker runs are not relabeled independent execution. The exact historical Linux signal failure still requires evidence; this addendum only restores and verifies the dependent test's original exit-status proof. No prior finding, assertion or historical failure is waived.
