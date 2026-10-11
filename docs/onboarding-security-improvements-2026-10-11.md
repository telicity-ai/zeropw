# Onboarding verification and security improvements — 2026-10-11

Scope: bilingual manuals, `/2` verification prompts, JSON Schemas and an offline deterministic validator. No product binaries, admission rules, quarantine history, release assets, harness or CI definitions changed. The existing CI `tests/test_*.py` job includes the new boundary and evidence-binding tests; Actions remains disabled and CI was not run.

Local Claude Code `2.1.287` used actual `claude-opus-5-5`. Adversarial review ran without tools, MCP or hooks; bounded execution used only the fixed synthetic test MCP bridge, not administrator tools. Original findings and failed/superseded attempts are preserved privately.

## Changes

- Compare the full independently approved member roster, sole owner, vector authors and environment ID. Matching peer lists alone are insufficient.
- Validate result types, enums, freshness, the shared write pause, input syntax, expected successful HTTP condition and empty failure lists. Compute pairing from both raw results plus separately approved policy; a model verdict is provisional.
- Keep any nonzero rejection strictly blocked. Publish fixed human review actions without deleting history or waiving the gate.
- Record credential class, isolation confirmation and human-verified release identity. Homebrew requires a tap commit; archive evidence uses a null tap commit. Installation additionally needs separate isolation confirmation and artifact approval.
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

All seven final responses pass their `/2` JSON Schema. The three model pair objects differ from the independently computed objects in action codes or redundant failure codes, so strict `--reported` comparison rejects them with `reported_pair_mismatch`; those model objects are not accepted as final pairing evidence. The independently computed comparator verdicts are blocked, blocked and synthetic ready respectively. Use the checker output, not the model verdict.

 actual assistant model IDs and process exit codes are recorded per case. The original native Homebrew reinstall/demo result is historical `/1` evidence, not a `/2` installation PASS: the existing coordinator account did not satisfy the new disposable-environment precondition. No fresh isolated macOS install is claimed.

All earlier `/1` and intermediate `/2` executions are superseded for the current prompts. No history was deleted or receipt counter changed in the actual A/B cases. Counter changes exist only in separately labeled hypothetical comparator inputs, which must never be exchanged as actual evidence.

## Remaining product limit

Normal v0.1.0 enrollment retained a `team_author_unknown` rejection that was subsequently accepted identically. A and B converge, but this record remains. `/2` intentionally blocks it even after human review. This work does **not** establish an actual ready pair or fix the product's historical-rejection accounting. A separate product/policy change and its own verification are needed before any reviewed-history accommodation. This documented fail-closed limit is not an open exception in the new validator.

## Verification and evidence binding

The local Python suite passed 40 tests (including 14 validator methods and the evidence-binding check) and covers boundary rejection and CLI behavior; bilingual checks cover HTML structure, grayscale styling, anchors, shell syntax/parity, prompt equality and JSON example shape. Rust product code is unchanged, so the native product verification matrix was not rerun. Prompt execution is distinct from an adversarial review verdict.

`onboarding-validation-manifest.json` binds current prompts, manuals, Schemas, validator and tests to SHA-256. The new test recomputes those hashes in the existing local/CI test loop. Raw input, response and tool-log hashes below bind each execution; raw logs stay private. A null tool-log hash means the model issued no tool call. The policy file hash is recorded in the manifest. The manifest/report themselves are bound by the Git commit, avoiding a self-hash cycle.

| Case | Prompt file SHA-256 | Input SHA-256 | Response SHA-256 | Tool-log SHA-256 |
| --- | --- | --- | --- | --- |
| A-final | `e783992ecbe7a78d349480c1ed6cfe32983494e0417f32b250afa417db1d005f` | `82ab394cea42bfb0721a4acbc45c2b51f225debc5ed3d17a4908a455a313cd82` | `b6d095d417b3b4241cfef5a284b19b7d80e1418fba26e77ba7f4c8e4051809cc` | `783678e02ea217ccf21df6758d3d36b09f2c20af0b4af6057240c953c3efa4bc` |
| B-final | `c30c8e0246d614aa31fb1543d43390415257c369321ae319b29ee8ccff0b3d16` | `63f87bbb0db049829d037bbdd76b92fd59221f626e2bf69a0d1c888d9caf26f1` | `337c216a22f72e92111b04ea3c493fd6e32c3752a4ca372bb480d463b0f68efe` | `6defbe0d6da673fc9bd19bb1c34f9b96d3eaf59fb0bff2f426895e28e80004b7` |
| missing-final2 | `e783992ecbe7a78d349480c1ed6cfe32983494e0417f32b250afa417db1d005f` | `ea622c8c51dc6339559430b28e276e4ea6351d20ba65039fbe76d27ae9aea51a` | `95b267e32af89dd7ee740fae2bcbf9477051052a08c439c79502e985fc435222` | `c8bc5c773697d3365a6868e0fac9b75a86e34199fc80726e5a9dc8f91b6b00b8` |
| installer-unapproved-blocked | `e783992ecbe7a78d349480c1ed6cfe32983494e0417f32b250afa417db1d005f` | `226865a450de3562804156b31021916c47303f00dda4991e627143c0ca45f2f7` | `75afd5a007b78ee8913b2c5dcf76e06d085c8b7e0aee255e63e87523f978a8d6` | null — no calls |
| pair-actual-final | `e783992ecbe7a78d349480c1ed6cfe32983494e0417f32b250afa417db1d005f` | `05a76a348f26cd08e4f1b0336419f62a27b3c1eb9d66e7787997952429bac165` | `309ca8b461f4fabdd02b0dbfdd3cd412909d4a5257acfaf96ce87abf62b17feb` | `268b5c30f321c58392317fe39c31042a721d9ad612ad8772709fa6fd72f19e63` |
| pair-extra-member | `e783992ecbe7a78d349480c1ed6cfe32983494e0417f32b250afa417db1d005f` | `6b5bb560c38a2e2ad1ed3a96825fd8438dc90bcb29909c610b14434c3be76a6e` | `016aa4b1ef6cb6daaa4d83b41c99f3f16a0452fd249b86c5ce3c6a840c461139` | `4d9e87067ce0e248ad040457311e4eb7d61228f5696d2ca01054b5ba22e2341e` |
| pair-synthetic-positive | `e783992ecbe7a78d349480c1ed6cfe32983494e0417f32b250afa417db1d005f` | `01e5a6122b8c7d769271131339297381d8df0b67f41d471738e318e376b8fc08` | `a236aa7ea0dbbabe346b8ae14068b077070db08512846f66910a9384695a02c5` | `2ea422e1348813a7a423a17411259d408fa90f67df556a829e1c570fde608cf9` |
