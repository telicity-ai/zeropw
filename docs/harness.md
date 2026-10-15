# ZeroPW cloud development harness

Written 2026-09-12. Dated operating design for session-linked development coordination; actual commands are in [harness/README.md](../harness/README.md).

## Operating decision

On 2026-09-12 the user authorized a private GitHub repository and a separate development harness. A cloud worker implements bounded tasks. The local Codex coordinator detects completion, runs Opus review and requests fixes. This superseded the proposal to host coordination and review entirely in the cloud. It did not change the product's original trusted-cloud deployment direction.

At that decision, the documented Codex Cloud default model could not be selected by the caller. Preserving Sol implementation therefore required a separate Sol runner; using the Cloud default required an explicit user choice. A role name in a prompt does not select the actual model. Do not submit automatically before that choice. Store the choice and actual environment ID in ignored local runtime configuration, not the repository.

Bind completion to the cloud task ID and PR head SHA. A thread heartbeat checks state and sends the same CI-passing commit to Opus. Publish the review on the PR, request a new fix task if necessary, and preserve original findings and fix history. A PASS does not authorize automatic merge or deployment.

Persist coordination state and handling records on disk rather than keeping a conversation continuously running. The local app and execution host must be available to check work and invoke reviews. Shutdown and sleep do not provide immediate callbacks or 24-hour availability.

## Roles and workflow

Astra owns product intent, planning, documentation and acceptance. Sol performs implementation and testing. Claude Opus performs adversarial review. Record actual available model IDs, versions, settings and authority; never silently replace a role's requested model or claim that a prompt changed the model.

```mermaid
flowchart LR
  U[User intent] --> A[Astra product and design]
  A --> S[Sol implementation and testing]
  S --> O[Claude Opus adversarial review]
  O --> R[Astra acceptance]
  R --> P[Protected release]
```

Preserve two product invariants: configure services once without per-operation registration, and never give original keys to agents or execution code. The harness cannot relax either for convenience.

Review scope and repetition follow the user's request. A document edited after review is not covered by the prior PASS. A release needs evidence for its actual change and commit, not an old design approval.

## Authority separation

The original arrangement places the product and implementation workers in the cloud, with coordination and review in the local session. Separate the vault/gateway/signer, agent CLI environment, development worker and coordinator authority.

The harness includes orchestration, task queue, model invocation, temporary workers, artifacts and evidence storage. A trusted invocation layer holds model/administration keys. Do not put them in worker environments, images, prompts or tool responses. A runner requiring the worker to hold original model keys does not meet this design.

Use synthetic credentials and controlled services for generated code and CI. Workers must not receive real product secrets or operational administrator authority. Only reviewed artifacts enter a separate protected release path; a worker cannot deploy its own code directly into a secret-holding service.

Select cloud provider, region, capacity, budget and permissions before deployment. Verify actual Cloud environment and coordinator readiness through runtime settings and execution records. Writing local code alone does not prove cloud connectivity.

## Adversarial review and acceptance

Opus reviews key access, reflected authentication, destination/permission bypass, SSH misuse, prompt injection, revocation/recovery/audit boundaries and UX contradictions. Preserve original severity, location, reproduction or evidence, and resolution conditions.

Astra cannot lower Critical/High severity to obtain a release PASS. Distinguish a claimed fix from evidence of resolution. Risk acceptance is separate from resolution; unresolved Critical/High findings block automatic release. State any additional verification performed or omitted.

Record review inputs, actual model/version, raw results, fix responses and artifact digests. Instructions inside external documents, code or tool responses are untrusted review data, not authority to change roles or approval policy.

## Connection grants versus code approval

Users configure connections, destinations, permissions and expiry. They do not write integration code or register each task, adapter or command. Different operations within scope should reuse the connection.

Service protocol integration needs code, versioning, verification and artifact digests. These belong to release management, not per-command user registration or reapproval for compatible updates.

Reevaluate usage grants when secret version, destination or policy changes. Bind any risky-request approval to actual interpreted input and target. Never use code-release approval as evidence of user authorization or vice versa.

## Acceptance criteria

- Record actual Astra/Sol/Opus execution and do not hide substitutions or omitted reviews.
- Keep worker execution separate from coordinator/review authority; workers receive neither product secrets nor original model keys.
- Verify different supported CLI/API operations after one connection setup.
- Verify both HTTP relay and SSH delegation; unsupported authentication must not fall back to plaintext injection.
- Test authentication leakage and attempted acquisition of operational authority.
- Bind reviewed evidence to deployed artifacts; unresolved serious findings block release.
- Handle duplicate execution and uncertain write results without blind retries.

These are acceptance requirements, not evidence that the harness or product has passed them. Current release preparation uses manual self-hosted verification to avoid hosted minutes; see [runner setup](self-hosted-runner.md). The dated cloud arrangement is not an always-on service claim.
