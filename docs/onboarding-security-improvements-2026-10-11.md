# Onboarding verification and security improvements — 2026-10-11

Scope: bilingual manuals, `/2` verification prompts, JSON Schemas and an offline deterministic validator. No product binaries, admission rules, quarantine history, release assets, harness or CI definitions changed. The existing CI `tests/test_*.py` job includes the new boundary and evidence-binding tests; Actions remains disabled and CI was not run.

Local Claude Code `2.1.287` used actual `claude-opus-5-5`. Adversarial review ran without tools, MCP or hooks; bounded execution used only the fixed synthetic test MCP bridge, not administrator tools. Original findings and failed/superseded attempts are preserved privately.

## Changes

- Compare the full independently approved member roster, sole owner, vector authors and environment ID. Matching peer lists alone are insufficient.
- Validate result types, enums, freshness, the shared write pause, input syntax, expected successful HTTP condition and empty failure lists. Compute pairing from both raw results plus separately approved policy; a model verdict is provisional.
- Keep any nonzero rejection strictly blocked. Publish fixed human review actions without deleting history or waiving the gate.
- Record credential class, isolation confirmation and human-verified release identity. Homebrew requires a verified clean observed tap commit and pinned formula digest before and after install/test, matching the independently approved artifact. Installed stable-keg receipt and all-five PATH bindings must also match; verify_existing cannot pass installation; archive evidence uses a null tap commit. Installation additionally needs separate isolation confirmation and artifact approval.
- Restrict probe values and pass separate argv. Skills cannot expand authority. Publish typed Schemas, reason codes and English/Korean checker instructions.

## Current execution results

Two synthetic node identities run in one isolated ARM64 Ubuntu VM, not two physical teammate machines. The coordinator independently rechecked the public Linux archive SHA-256 `c8c48db2dab796790248115cc74b366c5be7ecba3bb9c40db9b308697297ac75` and matched all five installed test executables to archive bytes. The agent has no vault read authority; original fixture authentication stays in the trusted controller/gateway. Human-role receipts are controller-supplied test evidence, not remote attestation.

| Case | Actual model result | Independent interpretation |
| --- | --- | --- |
| A, English local check | pass | Real bounded list/request execution; HTTP 200/items array; validator agrees. |
| B, Korean local check | blocked | Actual retained rejection count 1; validator also blocks. |
| Missing binary | needs_human_install | Real empty agent PATH; no installation attempted. |
| Installation without isolation/provenance approval | blocked | Negative precondition test; no installation command allowed. |
| Compare actual A/B | blocked | Actual blocked B is never promoted to ready. |
| Unapproved additional member | blocked | Pure comparator fixture; no live membership changes. |
| Hypothetical zero-rejection pair | ready, synthetic | Pure comparator positive fixture. **Not** evidence of actual ready enrollment. |

All seven latest responses pass their `/2` JSON Schema. Strict `--reported` rejected `pair-extra-member` because its action/failure codes differed. Other pair objects matched exactly. Per-case reported_matches_computed is recorded in the manifest. Independently computed results remain authoritative. The independently computed comparator verdicts are blocked, blocked and synthetic ready respectively. Use the checker output, not the model verdict.

Actual assistant model IDs and process exit codes are recorded per case. The original native Homebrew reinstall/demo result is historical `/1` evidence, not a `/2` installation PASS: the existing coordinator account did not satisfy the new disposable-environment precondition. No fresh isolated macOS install is claimed.

All earlier `/1` and intermediate `/2` executions are superseded for the current prompts. No history was deleted or receipt counter changed in the actual A/B cases. Counter changes exist only in separately labeled hypothetical comparator inputs, which must never be exchanged as actual evidence.

## Remaining product limit

Normal v0.1.0 enrollment retained a `team_author_unknown` rejection that was subsequently accepted identically. A and B converge, but this record remains. `/2` intentionally blocks it even after human review. This work does **not** establish an actual ready pair or fix the product's historical-rejection accounting. A separate product/policy change and its own verification are needed before any reviewed-history accommodation. This documented fail-closed limit is not an open exception in the new validator.

## Verification and evidence binding

The local Python suite passed 49 tests (including 15 validator methods, five observer methods and four evidence/document/guard checks) and covers boundary rejection and CLI behavior; bilingual checks cover HTML structure, grayscale styling, anchors, shell syntax/parity, prompt equality and JSON example shape. Rust product code is unchanged, so the native product verification matrix was not rerun. Prompt execution is distinct from an adversarial review verdict.

`onboarding-validation-manifest.json` binds current prompts, manuals, Schemas, validator and tests to SHA-256. The new test recomputes those hashes in the existing local/CI test loop. Raw input, response and tool-log hashes below bind each execution; raw logs stay private. A null tool-log hash means the model issued no tool call. The policy file hash is recorded in the manifest. The manifest/report themselves are bound by the Git commit, avoiding a self-hash cycle.

| Case | Prompt file SHA-256 | Input SHA-256 | Response SHA-256 | Tool-log SHA-256 |
| --- | --- | --- | --- | --- |
| A-final | `5e39ad56cacc88fd27ee0c7286963c457e9885fb77bc7a58d3671f56a2387026` | `d29ddd1adff16beb0b7c8697ad0f17b26f8a4a3d7ce17163007700502b90b4b4` | `28fac469a004791ee0c1402ecabb86537689105cf0e013d1b265f6d8c2a4712b` | `5e1cdbcc9c10393ddef5f71bf50ed7103e4cca425d3f1b15a7cc6e37f946f660` |
| B-final | `6b8f4f5be6df58dd6060e1d1f934c57be15c16ccb7402a753251b88a7bfdbdae` | `974b06c7e52d2e79abd796401fc9bdf850d6f933aa6d442dadc9e18e2275d682` | `549bf5fcd98bf6bba87a62f8b45fdf9af21750ea1a6641847a11b943aac5bae5` | `f252cc14b3bc6edc2b95f337faa6ae82d7617d7b66eac87617d21bcc26e13107` |
| missing-final2 | `5e39ad56cacc88fd27ee0c7286963c457e9885fb77bc7a58d3671f56a2387026` | `13e9cdb70bb03b8f67e54c98e60d8291b68b9cd89666768075eb368e747a04b6` | `fe2cf0c897b5463197b92375357e67d23116df9feb544b3e29693f30044a91be` | `46e62bc07fbf7102289759da4b713cce83c01e35b99a95164a353b2b54d713d3` |
| installer-unapproved-blocked | `5e39ad56cacc88fd27ee0c7286963c457e9885fb77bc7a58d3671f56a2387026` | `2a54c15e988fc3c0a0b4d04ca92b5b937f4613df066e2794c50d533515dd8db9` | `8e9321e12a092669d45b892beebb9c2f0d2e2a9e44162ca4c93235df102fc5b9` | null — no calls |
| pair-actual-final | `5e39ad56cacc88fd27ee0c7286963c457e9885fb77bc7a58d3671f56a2387026` | `975ade705819ae9c7f758ee28a2df05cc263ba36c199c5a5ea3c8a619beb4e1b` | `da141b9b971c2097d6ce94cf737aa0be848b180d46d1e48021f34ffa5a6bc6f9` | `a55733a61f97d29cb777d050f291d366d04d56c61442f6ec04da438b881b8b3f` |
| pair-extra-member | `5e39ad56cacc88fd27ee0c7286963c457e9885fb77bc7a58d3671f56a2387026` | `96ad6bacf467dd417e95819bc0bfe0b4798326a15cdeb2ccf41c325b78c3dce1` | `ed04161c8b091198a09e9f8fe7e4c34e96e2ab2120f41fa062959a65d9a83797` | `a8497ae5304e13822efb9a0e1edaf657e383836055f88e4b9a102cfcfd1045dd` |
| pair-synthetic-positive | `5e39ad56cacc88fd27ee0c7286963c457e9885fb77bc7a58d3671f56a2387026` | `07adf3173770c3ca99cc8e5184563c92a926d31c8a57dff4aa3e14766b89a114` | `a1ed01727e233626e42c46aa4c80db16197f3221dcb64015bbdfd8f83dd59ba6` | `9a1b0811d4d0f0ca1dbcafb6722e1eaaa6d06b3f81ed8fbab0983621d9ccd112` |
