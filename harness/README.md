# ZeroPW task and review harness

This harness collects completed cloud implementation work, invokes Claude Opus review from a local coordinator, publishes the review on a GitHub PR, and submits bounded fixes when authorized. The repository is `telicity-ai/zeropw`. Product and original model keys never go to implementation workers.

## Operating arrangement

- The cloud worker implements and tests the supplied milestone.
- The local coordinator owns scope, state checks, exception handling and acceptance.
- The configured local Claude CLI runs Opus without external tools, MCP or hooks. Verify the model in initialization and actual response messages; a billing list may also include helper models and is not sufficient evidence.
- GitHub stores source, exact head commits, CI and reviews.
- A thread-linked heartbeat invokes `controller.py tick`; unchanged state does not produce repeated notifications.

There is no public HTTP callback that injects messages directly into a conversation. Heartbeats fetch completion state. The app and local execution host must be available; sleep or shutdown does not provide immediate callbacks or a continuously available service.

At the original operating decision, the Cloud default model was not caller-selectable. A separate Sol runner is needed to preserve that implementation condition. The supplied Cloud submitter opens only after an explicit user choice recorded in runtime configuration. A role name in a prompt is not model selection.

## Initial setup

The coordinator needs Python 3.11+, Git and authenticated `gh`, `codex` and `claude` CLIs. Use those sessions only in the trusted coordinator. Do not copy keys or session tokens into source or task prompts.

1. Authorize repository access in the Cloud GitHub connection and create an environment for this repository. Do not broaden unrelated repository permissions.
2. Configure `bash harness/cloud_setup.sh`. Setup checks available commands and isolated Python compilation; it does not run tests. Worker steps and CI run tests separately. Do not put real keys or tokens in environment Secrets. Added product dependencies need separately verified installation steps.
3. Record the actual environment ID and user-selected worker mode in ignored `.zeropw-harness/config.json`.
4. Run doctor and tests before submission.

`config.example.json` is the template. Set `cloud_default_model_accepted` only after actual user authorization. It must not contain API keys.

```sh
python3 harness/zeropw_harness.py doctor
python3 -m unittest discover -s harness -p 'test_*.py' -v
python3 harness/cloud_runner.py submit --prompt-file harness/prompts/m1-cloud.txt --branch main
python3 harness/controller.py tick
```

Doctor success verifies CLI availability, not repository access, model invocation or a complete Cloud round trip. Building this harness does not deploy ZeroPW.

## Collection and review

Record remote starting SHA, prompt hash, Cloud environment, task ID and local run ID. Never blindly resubmit an uncertain external write.

When a task is READY, collect its diff into an index in a temporary bare repository. Do not check out or execute submitted code on the trusted coordinator. Publish a branch/PR and bind these markers to its actual head:

```text
<!-- zeropw:ready-for-review -->
<!-- zeropw-ready-sha:ACTUAL_40_CHARACTER_COMMIT_SHA -->
```

Before collection, the response task ID and `environment_id` must exactly match recorded values. An `--env` list filter or environment name is insufficient. Missing, null or empty IDs stop status/diff collection and publication. A 2026-09-13 CLI observation returned a different environment name and null ID; that response format cannot complete automatic collection. Successful environment creation/setup does not prove task identification or the complete submit/collect path.

Markers alone cannot start review. Verify repository, main base, non-draft state, current head/marker equality, required CI and trusted CI definitions. Current product tests are Rust; the historical Python `tests/test_*.py` CI path must not be used as evidence of Rust validation. Release preparation uses manual self-hosted checks described in [runner setup](../docs/self-hosted-runner.md).

Changes to `.github/`, `harness/`, `AGENTS.md`, `docs/harness.md`, `docs/product-intent.md` or `docs/security-design.md` stop automatic push. The coordinator must inspect those changes and publish them separately. Workers cannot redefine product requirements, review rules or CI to make their own code pass.

Review inputs include base/head source for changed files and trusted product specifications. Verify source, Git blobs and input hashes. Stop on truncation or unsupported binaries/symlinks rather than silently omitting them and obtaining a PASS. Reject error responses, another model, malformed JSON, out-of-scope locations and PASS reports retaining findings.

The patch collector does not support Git-quoted path headers. Reject the entire patch for an unsupported quoted path, including non-ASCII/special-character paths; never skip just the affected file. Expected per-PR validation failures become attention records and do not stop other PRs. Unexpected errors involving uncertain external writes preserve the coordinator lock.

The historical configured review uses Opus, medium effort and a 20-minute limit. Record the actual configuration/model. On timeout or abnormal exit, preserve input, partial/raw stdout, exit code and stderr privately and mark review incomplete. A failing process printing PASS-shaped JSON is not accepted. Do not repeat a rate-limited call before its known reset time.

Publish results as GitHub COMMENT reviews bound to the exact commit. They are not GitHub approval or merge commands. An old review does not cover a changed head.

| State | Next action |
| --- | --- |
| Cloud running / CI pending | Wait; do not repeat unchanged notifications. |
| CI failure | Report the failure; do not bypass with a review PASS or blind retry. |
| Opus PASS | Present for acceptance; no automatic merge or deployment. |
| Opus REVISE | Preserve original findings and severity; request fixes against the current PR SHA. |
| BLOCKED / uncertain result | Inspect inputs/integration; stop automatic progress. |
| Incomplete settings | Review publication may proceed; fix submission waits for configuration. |
| Operating-control changes | Stop automatic push for coordinator inspection. |
| Three automatic fix rounds | Stop and preserve unresolved findings and records. |

## Commands and recovery

```sh
python3 harness/cloud_runner.py collect --run RUN_UUID
python3 harness/zeropw_harness.py scan
python3 harness/zeropw_harness.py review --pr PR_NUMBER
python3 harness/zeropw_harness.py publish --pr PR_NUMBER --sha REVIEWED_SHA
```

Ignored `.zeropw-harness/runs/` stores submission/collection records; `.zeropw-harness/reviews/PR/SHA/` stores review inputs/results. `controller-events.json` prevents repeated state notifications. These are not secret storage and must not contain operational tokens. They include source and review data and should not be disclosed indiscriminately.

After interruption or an uncertain request, do not delete locks or records automatically. Inspect whether the process ended, a Cloud task was created, or branch/PR/review publication already happened; reconcile records before resuming. Avoid duplicate requests.

Keep the coordinator on its reviewed harness checkout. Never apply a cloud patch there or execute a worker-modified harness automatically. No product or harness auto-merge is supplied; update the trusted checkout only to a human-selected accepted version.

## Dated setup evidence

On 2026-09-13 a dedicated environment was created and repository checkout, Python 3.12.13, Git/SSH and setup execution were verified. No real secrets or user environment values were registered, and agent Internet access was disabled. Inline runtime checks allowed setup before the harness existed on main. Setup did not run tests. Ignored `.zeropw-harness/cloud-environment.json` preserves actual environment/configuration evidence. Default-worker authorization and task environment identification remain separate conditions.

`prompts/m1-cloud.txt` is the initial HTTP relay task prompt, not a current complete-product acceptance record. SSH signing remained a core later implementation milestone and is present in the Rust product. This development harness itself does not implement secret isolation.

Historical official references checked 2026-09-12: [Cloud](https://learn.chatgpt.com/docs/cloud), [environments](https://learn.chatgpt.com/docs/environments/cloud-environment), [models](https://learn.chatgpt.com/docs/models). These dated observations are not current feature guarantees.
