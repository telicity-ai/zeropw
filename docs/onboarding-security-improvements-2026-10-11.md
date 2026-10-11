# Onboarding verification and security improvements — 2026-10-11

Scope: bilingual manuals, `/2` verification prompts, JSON Schemas and an offline deterministic validator. No product binaries, admission rules, quarantine history, release assets, harness or CI definitions changed. The existing CI `tests/test_*.py` job includes the new boundary and evidence-binding tests; Actions remains disabled and CI was not run.

Local Claude Code `2.1.287` used actual `claude-opus-5-5`. Adversarial review ran without tools, MCP or hooks; bounded execution used only the fixed synthetic test MCP bridge, not administrator tools. Original findings and failed/superseded attempts are preserved privately.

## Changes

- Compare the full independently approved member roster, sole owner, vector authors and environment ID. Matching peer lists alone are insufficient.
- Validate result types, enums, freshness, the shared write pause, input syntax, expected successful HTTP condition and empty failure lists. Compute pairing from both raw results plus separately approved policy; a model verdict is provisional.
- Keep any nonzero rejection strictly blocked. Publish fixed human review actions without deleting history or waiving the gate.
- Record credential class, isolation confirmation and human-verified release identity. Homebrew requires a verified clean observed tap commit and pinned formula digest before and after install/test, matching the independently approved artifact; archive evidence uses a null tap commit. Installation additionally needs separate isolation confirmation and artifact approval.
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

All seven latest responses pass their `/2` JSON Schema. The three model pair objects differ from the independently computed objects in action codes or redundant failure codes, so strict `--reported` comparison rejects them with `reported_pair_mismatch`; those model objects are not accepted as final pairing evidence. The independently computed comparator verdicts are blocked, blocked and synthetic ready respectively. Use the checker output, not the model verdict.

 actual assistant model IDs and process exit codes are recorded per case. The original native Homebrew reinstall/demo result is historical `/1` evidence, not a `/2` installation PASS: the existing coordinator account did not satisfy the new disposable-environment precondition. No fresh isolated macOS install is claimed.

All earlier `/1` and intermediate `/2` executions are superseded for the current prompts. No history was deleted or receipt counter changed in the actual A/B cases. Counter changes exist only in separately labeled hypothetical comparator inputs, which must never be exchanged as actual evidence.

## Remaining product limit

Normal v0.1.0 enrollment retained a `team_author_unknown` rejection that was subsequently accepted identically. A and B converge, but this record remains. `/2` intentionally blocks it even after human review. This work does **not** establish an actual ready pair or fix the product's historical-rejection accounting. A separate product/policy change and its own verification are needed before any reviewed-history accommodation. This documented fail-closed limit is not an open exception in the new validator.

## Verification and evidence binding

The local Python suite passed 43 tests (including 14 validator methods and four evidence/document/guard checks) and covers boundary rejection and CLI behavior; bilingual checks cover HTML structure, grayscale styling, anchors, shell syntax/parity, prompt equality and JSON example shape. Rust product code is unchanged, so the native product verification matrix was not rerun. Prompt execution is distinct from an adversarial review verdict.

`onboarding-validation-manifest.json` binds current prompts, manuals, Schemas, validator and tests to SHA-256. The new test recomputes those hashes in the existing local/CI test loop. Raw input, response and tool-log hashes below bind each execution; raw logs stay private. A null tool-log hash means the model issued no tool call. The policy file hash is recorded in the manifest. The manifest/report themselves are bound by the Git commit, avoiding a self-hash cycle.

| Case | Prompt file SHA-256 | Input SHA-256 | Response SHA-256 | Tool-log SHA-256 |
| --- | --- | --- | --- | --- |
| A-final | `2e775683229fb8bb74cc288e40b1136107f08ae2755e7b79e59593ee1fef553c` | `e07c7a979a45dec51e1fb6831c07d71b76892497ba4746a0dc845d038a130a78` | `ad77a13a53d3ab64daafd8c2317b201a901a951c87d37e8d754a2c9d86b45f68` | `ba75ea931df50d375f010b625b83544f227f1535ee45263a7c80919c0781a994` |
| B-final | `7b8f9eb583c426e4808bdea44f1ed1770667bd0342e812c59301debdbffb95f5` | `a7cd42122a17d25da044adbde8c90feed17450df605d7eb725cbc51bb52b41f2` | `d68c806b785eb47f9d87dbacb509e1655bc48474202712e88ce5c5c697a9281c` | `032d96b3aef394da5dbab53b22392d1cd3233ed929a3aebd01df5e5a75086975` |
| missing-final2 | `2e775683229fb8bb74cc288e40b1136107f08ae2755e7b79e59593ee1fef553c` | `6e4313d48d472974e0799223302382b9c7aa5fb927f7e1e52b322a49bf3fe258` | `9bcb33ad26c34ba4d290e3c4867d9338da19984aea5844805ba090edc5d6261e` | `f3a312a2e91056888ba3cf6e90ba1776db41d22062668020aeccbe6fbbd3b988` |
| installer-unapproved-blocked | `2e775683229fb8bb74cc288e40b1136107f08ae2755e7b79e59593ee1fef553c` | `f4b7bf9b0ec62fc6000bc109196f71131c01d774e9472f6c84f7f615fb4a2f8f` | `da7a1832ac9a82e9e7cc939c491121cfba0c90af7ace2f63810fdadfa3bb8ca0` | null — no calls |
| pair-actual-final | `2e775683229fb8bb74cc288e40b1136107f08ae2755e7b79e59593ee1fef553c` | `04cc25aa7147c9861fdf42dc16c6568a9018d85e258bcf8b8f5b533dda36a4f6` | `f8d38a38fceff11a7794c5b61296f60eba0d313326ba9e1dcb3b2189984ac0d2` | `a85a6abe664120c0586e69b4b285f742d53dc1df52c4efd44fd7148846afcc21` |
| pair-extra-member | `2e775683229fb8bb74cc288e40b1136107f08ae2755e7b79e59593ee1fef553c` | `b1144a267e0e9cccdf06f1b4e9beee344a1ae6e79157b15cc5b5028500c0852c` | `482c8cb6e1a2fd7e74186ae23ded05596e74531f0f7c25599011defc93b2a8a3` | `480c8e3943496aef2e81b84732feee2075640db5061b53d2b524520ebbd5de4b` |
| pair-synthetic-positive | `2e775683229fb8bb74cc288e40b1136107f08ae2755e7b79e59593ee1fef553c` | `18596eb5983636b9001c5cf801bcd0434df6c070b00be6f8ec1cab8ab74ba1ff` | `05a7558b8c72848dd80b57107749626eaec9a338c7f32f42ecac8bf5cad19e61` | `02e83cd05b59914fba1d7b8535a5b4e12e25165b749f7e86bb2814d0ab77d763` |
