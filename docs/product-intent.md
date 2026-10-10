# ZeroPW product intent

Written 2026-09-12; team-sharing scope added 2026-09-16. This is the working product specification. Implementation evidence is separate.

## 1. Product

ZeroPW is a personal credential vault that lets agents use supported CLIs and APIs without receiving original secret values. Connect a service and its credential once, then use different operations within that connection's scope. ZeroPW performs authentication outside the agent and execution code.

Core capabilities are encrypted environment-variable/API-key/password storage, project environments, HTTP authentication relay, SSH signing delegation, access grants, expiry, revocation and usage records. The initial product scope focuses on one person's CLI/API usage. The subsequent [team-sharing scope](team-sync.md) shares one project environment directly between teammate devices without a central server or leader.

The original deployment direction uses trusted cloud services; team synchronization uses local trusted processes. The development coordinator is session-based and is not an always-on cloud service. Development implementation, coordination and review are separate from the product runtime; see [the harness](harness.md) for the dated operating arrangement.

This specification supersedes the proposal requiring per-operation registration. Requirements here are not proof of deployment or specific CLI compatibility. Current implementation status is in [implementation.md](implementation.md).

## 2. Workflow

1. A human stores a secret through a separate administrative surface and associates it with a project/environment, service destination, allowed scope and expiry.
2. The agent selects a connection and runs supported CLI commands or API requests. Individual commands, subcommands and API operations need no separate registration.
3. Native tools prepare routing and non-secret configuration. HTTP requests go through the authentication gateway; SSH clients request authentication signatures.
4. The gateway or signer checks grants and authenticates. The agent receives business results without original credentials.
5. Reuse the connection for other operations within its scope. Change connection policy to expand destination or permissions. The human can inspect usage and revoke authority.

A code-hosting connection should, for example, support both listing resources and creating an issue. This is a UX requirement, not a claim of support for a particular service. Protocol integration belongs to the product; users do not write a task catalog.

## 3. Storage versus use

The vault stores environment values, API keys, passwords and SSH private keys encrypted. Agents can use only authentication methods that can be relayed or signed without giving original values to the client.

Client environments contain service addresses, non-secret settings and opaque connection references. An arbitrary program that requires the original secret cannot simultaneously read it and be prevented from accessing it. Mark such execution unsupported; never inject real secrets through environment variables, arguments, files or credential-helper output as a compatibility fallback.

Original keys may exist in the trusted vault, gateway and signer. Depending on the protocol, the external service also receives a credential. This is not a zero-knowledge guarantee against compromise of those trusted components. Limit and revoke allowed authority separately to address agent misuse.

Useful text and API results are allowed. Do not restrict all output to success/failure or fixed enums. Separately block reflected authentication material in responses, errors and logs. Business data may reach the agent and its model provider: ZeroPW does not promise privacy for every piece of data. Output masking supplements, rather than replaces, the no-original-key client boundary.

## 4. Scope

| Capability | Requirement |
| --- | --- |
| Encrypted vault | Store environment values, API keys, passwords and SSH private keys with version history. Managed secret storage and KMS are the deployment design. |
| Projects and environments | Separate dev, staging and prod connections and permissions. |
| Service connections | Configure service, credential, destination and permissions once per connection. No per-task registration. |
| HTTP authentication relay | Trusted gateway performs supported authentication; agents handle requests and business responses without original keys. |
| SSH signing | Authenticate supported SSH clients without private-key export. This is a core first-version feature. |
| Native agent tools | List/select connections, run supported CLIs, request APIs, inspect state and cancel. No secret-value retrieval tool. |
| Grants and revocation | Restrict caller, connection, destination, scope, time and usage. Revoke individual grants and stop all execution. |
| Usage records and alerts | Record who used which connection/destination without values. Alert on failures and abnormal behavior. |
| Rotation and recovery | Manual credential rotation, encrypted backup and human recovery. Provider-specific automatic rotation is later scope. |
| Team sharing | Following the initial personal scope, share one project environment with invited devices as equal nodes. Any authorized device can edit, and states converge. Environment-specific admin/user roles, device keys, one-time invites, removal and rotation guidance are required. See [team-sync.md](team-sync.md). |

Browser autofill, TOTP/passkeys, payment-card storage, family sharing, enterprise SSO/SCIM and multi-cloud operation are outside scope. Team sharing was defined after the initial personal version and is implemented as described in the implementation record.

Team sharing maintains the agent boundary: original secrets do not enter agent processes, execution code or tool results. Because there is no cloud service, every member's trusted device can decrypt shared credentials. Humans are trusted; agents are not. Admin/user roles provide policy and history rather than cryptographic separation. Removing a member does not invalidate credentials they could previously read; rotate those at the external provider.

ZeroPW's KMS, administration, audit, backup, recovery, billing and DNS authority, and the development harness's model/administration keys, must never be agent business connections. Keep bootstrap authority in a separate trust domain.

## 5. Support and acceptance

| Candidate integration | Required conditions | Otherwise |
| --- | --- | --- |
| HTTP API/CLI | Gateway-delegated authentication with controllable proxy/base URL/TLS route, destination validation and response handling. | Unsupported. |
| SSH CLI | Agent protocol integration with validated session/server/destination binding. | Unsupported; no key-file fallback. |
| Password authentication | A supported relay protocol such as HTTP Basic. Database and other protocols need dedicated verification. | Unsupported until integrated and verified. |
| Programs computing with raw secrets | The client itself requires original values. | Storage only; execution unsupported. |

If an integration cannot meet its conditions, mark it unsupported. A private-key-file-only client or an SSH client without destination binding must fail explicitly.

Acceptance tests cover normal success, different operations on one connection, blocked extraction, authentication material in responses/errors/streams/logs, and effective revocation. A failed condition must produce an explicit failure, never a plaintext workaround.

Specific services, CLIs, cloud providers, regions and budgets are not universally specified. Validate actual candidates before listing support. Do not promise every unmodified CLI will work.

## 6. References

Reference material was checked on 2026-09-12; it is design context, not current compatibility evidence.

1Password environment management and secret references inform vault UX. Its `op run` injects real secrets into child environments, so it does not satisfy ZeroPW's execution boundary. Masking output does not prevent a child from reading its values.

The 1Password SSH agent's non-exported keys and signature service inform SSH design. Distinguish management MCP tools from wrappers injecting secrets into an external MCP server's environment. Using MCP does not by itself hide credentials from execution code.

Envoy's credential injector informs gateway-side HTTP authentication. It does not alone solve user grants, destination limits, reflected credentials or universal CLI compatibility; ZeroPW must validate those separately.

- [1Password environments](https://www.1password.dev/environments)
- [1Password op run](https://www.1password.dev/cli/reference/commands/run)
- [1Password SSH agent security](https://www.1password.dev/ssh/agent/security)
- [1Password secure AI access](https://www.1password.dev/get-started/secure-ai-access)
- [Envoy credential injector](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/credential_injector_filter)
