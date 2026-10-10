# Getting started with ZeroPW

ZeroPW synchronizes encrypted secrets between trusted devices. Agents use supported APIs and SSH without receiving the original keys. The product currently runs through Rust CLIs and is pre-release software.

## Choose your starting point

| Goal | Start here |
| --- | --- |
| See how it works | Build and demo |
| Create a team environment | Administrator setup, then team sharing |
| Join a team | Device B under team sharing |
| Use it from an agent | Agent usage, then install the skill |
| Inject an existing `.env` into an application | Unsupported; first check the application's authentication path |

There is no whole-file `.env` import or export. Store API keys in the vault and keep non-secret settings, such as service URLs, in application configuration. Applications that read a raw key from `process.env`, or database drivers that directly require a password, need a dedicated integration. The tested CLI paths are `zeropw-democli` and OpenSSH.

## 1. Build and demo

Run from the repository root. You need a toolchain supporting Rust edition 2024. On Linux, prepare your distribution's development build tools. Some dependency configurations may need OpenSSL development headers and pkg-config. If using Homebrew OpenSSL 3 on macOS, set:

```sh
export OPENSSL_DIR="$(brew --prefix openssl@3)"
```

```sh
cargo build --locked --manifest-path rust/Cargo.toml --bins
export PATH="$PWD/rust/target/debug:$PATH"
zeropw-demo
```

The demo uses synthetic credentials and an embedded test server. Exit code 0 means all demo checks passed. Build and run the product on a disposable CI runner or isolated VM without real vault or coordinator authority. When deploying `exec`, install `zeropw_session` beside `zeropw-admin`.

## 2. Administrator setup

A human administrator performs this section in a trusted terminal separated from the agent. Never give the agent administrator or recovery passphrases, original credentials, or `.env` contents. The agent must not run these administration commands on your behalf.

```sh
export ZPW_STATE="$HOME/.local/share/zeropw"
zeropw-admin --state-dir "$ZPW_STATE" init
zeropw-admin --state-dir "$ZPW_STATE" project create team-app
```

When `init` prompts, choose administrator and recovery passphrases and store them separately. The file path and target below are examples: replace them with administrator-verified values. The value file contains one credential, not a complete `.env`.

```sh
zeropw-admin --state-dir "$ZPW_STATE" secret put \
  --id service-key --kind api_key --project team-app --environment dev \
  --value-file /trusted/path/service-key
zeropw-admin --state-dir "$ZPW_STATE" connection create-http \
  --id service-api --project team-app --environment dev --service team-service \
  --secret-id service-key --target https://api.example.com \
  --auth bearer --methods GET --path-prefixes /v1
```

After successful import, the administrator safely removes any temporary plaintext value file. Before connecting a real service, verify credential-query and reflection endpoints and how the gateway handles their responses. Creating a connection does not establish safe service compatibility. HTTP API requests do not require `--cli-program`; CLI execution requires a separately validated profile.

Create a caller identity and grant on each device. The caller token is printed once. It authorizes restricted operations, so do not put it in public documents, Git, or chat logs.

```sh
zeropw-admin --state-dir "$ZPW_STATE" principal create --id agent-1 --runtime dev-box
zeropw-admin --state-dir "$ZPW_STATE" grant create \
  --principal agent-1 --connection service-api --ttl 1h --max-uses 100
zeropw-admin --state-dir "$ZPW_STATE" serve
```

Keep `serve` running. Pass only its first JSON response's `url` and the caller token to the agent environment. The tools API accepts connections only over loopback. Running the agent and vault as the same OS user does not provide security isolation. Prepare deployment isolation separately and test onboarding only with synthetic credentials.

## 3. Team sharing

Devices connect directly over the same LAN or team VPN. No central server is needed, but each device's `serve` must be running to synchronize. The example uses VPN addresses `10.8.0.2` for A and `10.8.0.3` for B. Substitute real addresses and expose the team listener port only to the team network.

### Administrator A

Share the `team-app/dev` environment created above. If a normal `serve` process is already running, stop it and restart with a team listener.

```sh
zeropw-admin --state-dir "$ZPW_STATE" team init
zeropw-admin --state-dir "$ZPW_STATE" team share --project team-app --environment dev --name owner
zeropw-admin --state-dir "$ZPW_STATE" serve --team-listen 10.8.0.2:47420
```

In another trusted terminal, set the same `ZPW_STATE` and create the invitation:

```sh
zeropw-admin --state-dir "$ZPW_STATE" team invite \
  --env team-app/dev --role user --name teammate --ttl 1h --address 10.8.0.2:47420
```

An invitation is a one-time enrollment capability. Send it only to the intended teammate through a secure channel. Do not expose it to agents, issues, reviews, or chat logs. Give `admin` only to teammates who need editing and invitation authority.

### Teammate B

Build the binaries on B, initialize B's own vault, and create its device keys. Do not share administrator passphrases.

```sh
export ZPW_STATE="$HOME/.local/share/zeropw"
zeropw-admin --state-dir "$ZPW_STATE" init
zeropw-admin --state-dir "$ZPW_STATE" team init
zeropw-admin --state-dir "$ZPW_STATE" team join '<ONE_TIME_INVITATION>' --project team-app --environment dev
zeropw-admin --state-dir "$ZPW_STATE" team status --env team-app/dev
zeropw-admin --state-dir "$ZPW_STATE" team members --env team-app/dev
zeropw-admin --state-dir "$ZPW_STATE" serve --team-listen 10.8.0.3:47420
```

`team join` currently receives the invitation as a command argument. Run it only in B's trusted terminal and account for shell history and process-argument visibility. Compare the device fingerprints and member lists on A and B. A's pre-sharing grants become `stale` and must be reissued. B must also run `principal create` and `grant create` locally. Caller identities, grants and tokens are not synchronized between devices.

When an admin changes a secret or connection, connected nodes receive the change. Use `team status` to inspect synchronization state. Offline devices catch up after reconnecting, but can continue using their previous state in the meantime, including grants revoked elsewhere. Do not run `team compact` during initial onboarding: transferring compacted snapshots to new devices is not implemented.

To remove a member, the administrator runs `team remove --env team-app/dev --device '<FINGERPRINT>'`. Replace credentials at the provider to invalidate keys that the removed member could previously read. Even a `user` device's trusted process can decrypt shared secrets; invite only teammates you trust as people.

## 4. Agent usage

The administrator configures `ZEROPW_GATEWAY_URL` and `ZEROPW_CALLER_TOKEN` in the agent runtime. The agent does not need to print the token or inspect configuration files.

```sh
zeropw-agent list-connections
zeropw-agent request --connection service-api --method GET --path /v1/items
```

If the administrator has configured a validated CLI profile or SSH connection:

```sh
zeropw-agent exec --connection '<CONNECTION_ID>' -- '<PROFILE_ARGUMENTS>'
zeropw-agent status --run '<RETURNED_RUN_ID>'
zeropw-agent cancel --run '<RETURNED_RUN_ID>'
```

Arguments after `--` belong to the configured program; they are not a replacement executable path. For SSH they are remote-command arguments. SSH requires OpenSSH 8.9 or later with session-bind support and administrator-verified server host keys. Do not give the agent a private-key file. Different operations within the same connection's allowed scope need no new registration.

After `exec`, inspect the returned run ID with `status` until it reaches a terminal state. Starting a run does not mean the command completed. SSH cancellation ends the local client; it cannot guarantee termination of an already-started remote process.

## 5. Install the agent skill

The [ZeroPW agent skill](skills/zeropw-agent/SKILL.md) describes connection selection, API and CLI use, and execution status. It keeps human administration separate from agent usage. A human user copies it to the personal Codex skills directory. If a skill with the same name already exists, compare it first.

```sh
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
cp -R skills/zeropw-agent "${CODEX_HOME:-$HOME/.codex}/skills/"
```

Once loaded, ask the agent:

> $zeropw-agent List available connections and use service-api to retrieve /v1/items.

Never put secrets, administrator state paths or invitations into the skill. Other agents can load `SKILL.md` through their own skill mechanism.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| `zeropw-agent` is missing | Check the build, deployed binaries and PATH |
| `gateway_unreachable` | Administrator checks `serve` and the loopback access path |
| Connection absent from the list | Administrator checks this device's caller identity, grant and synchronization |
| `stale`, expiry, revocation, `principal_disabled` | Ask the administrator to check grants or incident state; the agent must not resume or widen permissions |
| `spawn_failed` | Administrator checks the CLI profile and `zeropw_session` placement |
| Enrollment connection fails | Administrator checks VPN, listener address, port and invitation expiry |
| Uncertain write result | Inspect status and business state before retrying |
| Unsupported authentication or credential reflection blocked | Check the supported integration; do not fall back to plaintext `.env` injection |

Details: [implementation](docs/implementation.md), [team synchronization](docs/team-sync.md), and [security boundaries](docs/security-design.md). Following this guide does not establish production readiness or a new security review PASS.
