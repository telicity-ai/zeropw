# Local Opus onboarding test: 2026-10-11

Actual model: `claude-opus-5-5`; local Claude Code CLI: `2.1.287`; effort: medium. Documentation baseline: PR #11 at `ef2d51cf1ccfc0ac01d53a90c2850e20af69ef65`, followed by the prompt changes bound to hashes below.

## Scope

The trusted local coordinator ran Claude Code with no built-in shell, file or other tools. A bounded MCP bridge executed fixed installation commands on the local Apple Silicon Mac and fixed agent commands under a separate Unix identity in an isolated Ubuntu 24.04 ARM64 VM. Model authentication stayed in the coordinator. The VM contained two synthetic trusted nodes; the fixture controller supplied the human-role receipts. These are two node identities in one VM, not two physical teammate machines. No production credentials were supplied.

The installation test reinstalled an existing stable 0.1.0 through the public Homebrew tap. It does not establish first-time installation on a clean Mac or install Homebrew itself. The trusted fixture created the vaults, enrollment and grants; Opus did not perform administrator setup.

## Results

| Case | Actual result | Evidence |
| --- | --- | --- |
| Installation Prompt 0, English | PASS | Opus invoked actual Homebrew reinstall and test; five binaries present; direct demo 47/47; actual command exit codes 0. |
| Missing agent binary, English | `needs_human_install` | A real empty agent PATH; no connection request attempted. |
| Local connection A, English | PASS | Installed published Linux archive binary; real connection listing and HTTP 200 with expected items array; receipt counters 0. |
| Local connection B, Korean | BLOCKED | Binary/configuration/connection/HTTP checks passed; both receipt samples retained `rejected_commits=1`. |
| Compare actual A/B results | BLOCKED | Members, stable vectors and read-only requests matched. A blocked local result was not promoted to ready. |
| Inject mismatched B vector | BLOCKED | Synthetic negative input; Opus reported `vectors_match=false`. No live product state was changed. |

All six final calls returned a single JSON object without prose or Markdown fences. Every actual assistant model ID was `claude-opus-5-5`; process exit codes were 0. The coordinator checked installation claims against actual tool-call logs rather than accepting the model report alone.

## Problems found and corrections

- The original prompts verify an existing installation and stop when the binary is absent. Added installation-only Prompt 0 in both languages. Administrator operations remain human-managed.
- The first missing-binary response wrapped JSON in prose and Markdown. Preserved that failed format attempt and tightened the final-response contract.
- The first installation run encountered a test-bridge clock error: the coordinator used a Linux-style date path on macOS. The model nevertheless returned pass with a nonempty failure list. Corrected the bridge, specified the exact UTC date command and made any required failure/unknown block pass. The corrected run has no failed checks.
- Pair comparison lacked the expected HTTP condition and an explicit common write-pause interval. Added non-secret probe expectations, a shared verification-session ID and pause timestamp. Sampling can be sequential during the same agreed pause; response-rule wording must match across languages.

## Remaining readiness limit

On normal synthetic enrollment, B retained a `team_author_unknown` quarantine record for a `member.add` commit. Trusted inspection confirmed that the same commit, excluding its rejection annotation, was subsequently present identically in the accepted commit store. A/B had converged, and both gateways authenticated requests to the controlled upstream. However, `team status` still counts that historical record, while the current conservative prompt requires zero rejected records.

This test therefore does **not** establish an end-to-end `ready` pair. The history was preserved; no counter was rewritten and no product, harness, CI or release artifact was changed to obtain a pass. The manuals now disclose this human-review gate. A separate product/policy decision is needed before treating reviewed historical rejections differently from current failures.

## Evidence binding

Raw model responses, inputs and tool logs are retained privately with the local coordinator; they are not reproduced in public documentation. The structured test summary includes their hashes. Prompt evidence is bounded test execution, not a new adversarial review PASS, production isolation audit or remote attestation.

| Final document | SHA-256 |
| --- | --- |
| `team-agent-prompts.en.txt` | `383920c556956962716c37100251b26d08f5b356ea2284d2c5623f6d14184f4d` |
| `team-agent-prompts.ko.txt` | `ff790582429725160de335351813d727bddf8568cc408fc197a10bef54fa11e8` |
| `team-onboarding.en.html` | `14b772cda9fb3e28fcb5eb9fde022ed10f67d549e1c02d3c8e189893c24c3591` |
| `team-onboarding.ko.html` | `89b6120ca134c9695c60ea5a33dc2f617f86b91245273a5426bbb95e726c9db5` |
