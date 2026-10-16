# Onboarding validation re-run for v0.2.0: 2026-10-16

Owner decision 3 of the v0.2.0 release ([docs/releasing.md](releasing.md)) moves `Formula/zeropw.rb` and the team onboarding files to 0.2.0 together and requires the onboarding validation cases to be re-run against the published release. This report records that re-run of the seven cases of 2026-10-11. It is the current evidence for the v0.2.0 onboarding files. The 2026-10-11 reports and `onboarding-validation-manifest-2026-10-11.json` remain the record for v0.1.0.

## What ran

- **Files.** A clean clone of commit `b43c3ab43d559d0305c456e8b372783f89f2e3de` (PR #25). Since 2026-10-11 the prompts changed only in their version and digest pins, 13 places in each language. The manuals also changed in step 1 (update an existing tap first, stop ZeroPW before the guarded reinstall) and in steps 2 to 4 (commands joined with `&&`, `team join --stdin`).
- **Model.** Every init and assistant message names `claude-opus-5-5`. Claude Code CLI 2.1.287, effort medium. Each case ran as its own `claude -p` process with no built-in tools (`--tools ''`), only the bounded onboarding MCP bridge (`run_command` and `check_runtime_config`, `--strict-mcp-config`), hooks disabled, no setting sources, no session persistence and an allowlisted environment.
- **Fixture.** Same design as 2026-10-11. One isolated Ubuntu 24.04 ARM64 VM holds two synthetic nodes: A, the sole owner, and B, role `user`. A trusted controller created them by running manual steps 2 to 7 with v0.2.0 binaries from the public `install.sh --version v0.2.0`, including `team join --stdin` with a `HOST:PORT` invite address. These are two node identities in one VM, not two teammate machines.
- **Agent side.** The bridge ran agent commands as a separate Unix account (`zeropw-onboarding-agent`, uid 2001, no login shell) that cannot read either vault. Its five binaries are a root-owned copy whose SHA-256 values equal the entries of the published Linux archive (`5f1dc52a5081e3386f71843c51a7f15f5e95d1b13153c446e08975b0eba70d86`) and of the release's `VERIFICATION.json`. The bridge accepts only a fixed list of commands. Credentials were synthetic and the only upstream was a controlled stub.
- **Receipts.** The human-role receipts are controller-supplied test evidence, not remote attestation: two status samples 5 seconds apart for each node, with writes paused. Both artifact receipts in the policy are the Linux archive receipt: release `v0.2.0`, archive `5f1dc52a…`, no tap commit, source `human_verified_release`.

## Results

| Case | Model result | Validator, computed at binding |
| --- | --- | --- |
| Installation Prompt 0, English, without isolation or artifact approval | `blocked`: `install_isolation_not_confirmed`, `artifact_identity_unverified`, `artifact_receipt_missing`, `reinstall_not_permitted` | Schema valid. No tool call, so no installation command was issued. |
| Missing agent binary, English | `needs_human_install` | Blocked: `agent_binary_missing`, `local_result_not_pass`, `readonly_request_unverified`, `version_unverified`. No request was attempted. |
| Local check A, English | `pass` | Pass. `list-connections` and `GET /v1/items` ran; HTTP 200 with the expected items array. |
| Local check B, Korean | `blocked`: `rejected_commits_nonzero` | Blocked: `local_result_not_pass`, `rejected_commits_nonzero`. |
| Compare actual A and B | `blocked` | Blocked. The model's object equals the computed one. |
| Synthetic input with an unapproved third member | `blocked` | Blocked. Same failure codes in a different order, so the strict comparison reports a mismatch. |
| Synthetic zero-rejection pair | `ready` | Ready, synthetic. A comparator fixture, not evidence of an actual ready pair. |

- All seven final responses were one JSON object that passed its `/2` schema, and every CLI exit code was 0.
- Tool calls: A made 5. B made 6: it first sent the request as a JSON array string, which the bridge refused as not allowed (exit 126), and then sent the allowed command. The three pair cases called only `date -u`; the installation case made no call. A refused command never reaches a shell.
- The upstream stub received 2 authenticated requests, from A and B, and no unauthenticated request. A scan of 82 evidence and agent output files found neither the synthetic upstream secret nor a caller token.
- The first receipt refresh was at 15:15:50Z and the binding instant at 15:16:54Z, inside the validator's 10-minute window.

## Remaining product limit

Unchanged on v0.2.0. B kept one rejected record, reason `team_author_unknown`, for A's `member.add` commit, while both nodes folded A's five commits with equal vectors. The prompts and the validator keep any nonzero rejection blocking, so this re-run does **not** establish an actual ready pair. No record was deleted and no counter was changed.

## Homebrew

The coordinator tested the Homebrew formula separately on the owner's Mac; see the v0.2.0 follow-up section of [docs/releasing.md](releasing.md). That is not a `/2` installation PASS: the account holds coordinator authority and does not meet Prompt 0's isolation precondition, and no case asked the model to install anything.

## Evidence binding

`onboarding-validation-manifest.json` binds 21 files, the 20 of 2026-10-11 plus `tests/test_onboarding_pins.py`, and the seven cases below. `tests/test_onboarding_evidence.py` recomputes the file hashes. The policy file hash is in the manifest. Raw inputs, responses and tool logs stay private with the coordinator. A null tool-log hash means the model made no tool call.

| Case | Prompt file SHA-256 | Input SHA-256 | Response SHA-256 | Tool-log SHA-256 |
| --- | --- | --- | --- | --- |
| A-v020 | `2d30c2a89b2c9ec780ef806fe53776c28f18362c29369ec4d9d9d60d88d0e4fd` | `6422b8dd4fb1c4be3ff8a9454b16671fb49302d5568f88300b013fca88d08793` | `db7c972f00fa6418b39282c003895cf6d0ef3f9f57adbbc4d7c3e385ec47662b` | `2a973a180f87c0a730d604db6eb2b62313cd96a0d262c5883464308763ad0352` |
| B-v020 | `614d3935ec01bad1f2ea208bea1c122d5acf9788ab382ccb772d1717786a3ca9` | `26b909ffa1eece7f41eca3961908dbeb17d92f1147b9a3430fb76014e28a84ba` | `b5b877433f721b75678259719226b76542d47aed71957c0ff3371360694fba61` | `49ac5eafe487095a76f4719a6d883036b2a531bc1459960bb0e0946073edd26b` |
| missing-v020 | `2d30c2a89b2c9ec780ef806fe53776c28f18362c29369ec4d9d9d60d88d0e4fd` | `4fc1019dd965cd7572032757ee0d3ec825fd3907da2aebe51c269996a8b6f7eb` | `70a8b385fe2d0f0b74ca4e5679b789f1dd255180388c32b7f81dbc9cba0f3138` | `f8e76a01645889a00bad200a4c96adb3a4ca875468d13a81cee6527ffb2946cb` |
| installer-unapproved-blocked-v020 | `2d30c2a89b2c9ec780ef806fe53776c28f18362c29369ec4d9d9d60d88d0e4fd` | `8d2cc11143d6ede1da28fab37649d101829e3016483e0d9761beaa14cac43719` | `e88b3c55fa4a2f5443a9a5aefe59347085fd5eb7bfcf34ac1152f383f2e19cd8` | null (no calls) |
| pair-actual-v020 | `2d30c2a89b2c9ec780ef806fe53776c28f18362c29369ec4d9d9d60d88d0e4fd` | `6dda087e8de5d42bed9fd2b18b0817fd9533ee610adedd7d2c47e61565866ab8` | `5581d93f80de6c3570d159810817ab8e42c4cffb71116de3b6d1aa382b181e39` | `2a5ba9e5fcdbbc64ebbfd29e34a5c0c3bf604e791594df5ef6a38284e0c5aa8e` |
| pair-extra-member-v020 | `2d30c2a89b2c9ec780ef806fe53776c28f18362c29369ec4d9d9d60d88d0e4fd` | `a42f08b5162e36a9fc2f7472c6fb535a777c8f04d6350da8efef5a6ae3a930a8` | `a148e103be313c402dce02bf209056d4e27f0c18e58bb65c80ca3e6c3f4937cd` | `dc6cb8d9ec7d85c574d9dcc7f9264fd7e01a1975259b029032f8923000dc841d` |
| pair-synthetic-positive-v020 | `2d30c2a89b2c9ec780ef806fe53776c28f18362c29369ec4d9d9d60d88d0e4fd` | `9366436dbb84c958374a1428993507fcaf824c939d03da20e557f6e804e9b579` | `841a07377ece97dcd4d0306141e3cc3877214baf13bbcb0e62463c730879f88c` | `3c1d916fb446aa82739628724d5f72438725f59474c750434d9fb131463fc9c1` |
