# Required-generation Linux runner-account diagnosis — static DATA

2026-11-08. Actual author: **gpt-6.1-sol / ultra**, T3 Code through Codex. No subagents. Read-only source, saved log and preparation DATA inspection only; no VM/account/process query, source/helper/test/build execution, key inspection, source/ref/index edit, product decision, adversarial review or acceptance. The original Linux result remains **FAIL:1812 passed/4 failed/5 ignored**, with feature-after NOTRUN.

## Finding and narrow conclusion

The frozen preparation explicitly creates dedicated synthetic `rgrun` UID/GID2000 with `/usr/sbin/nologin` and locked password (`--password '!'`). The SSH tests deliberately use the current operating-system account as the username of a real, non-root, loopback `sshd`. The fixed test environment does not provide USER or LOGNAME. Their success assertions require that account to run ordinary remote shell commands.

Three saved failures return remote exit1 and the message “This account is currently not available.” on stdout, with empty stderr. Combined with the account setup and unchanged fixture path, this strongly supports a runner login-shell prerequisite mismatch. It is not an independent runtime passwd lookup or traced proof of the installed sshd/nologin binaries. No product change is indicated by these saved observations alone.

Replacing the dedicated synthetic account's shell with `/bin/bash` addresses that visible prerequisite without changing product/test/CI bytes, expected assertions, UID/GID, password lock, groups, sudo permissions, HOME or source/controls. **A shell-only change does not by itself establish preservation of every isolation boundary:** if the management sshd permits direct `rgrun` logins, the runner can create an authorized_keys file in its own HOME and attempt loopback login through that root-run daemon. Such a session need not inherit the forced test route's NNP1 and empty bounding capabilities. This is a conditional static risk; this task did not query management-daemon policy or demonstrate a login.

The coordinator should establish an effective management-daemon `DenyUsers rgrun` (or an equivalent rgadmin-only login policy) before any product execution after the shell correction. Keep the password locked, no extra groups/sudo privileges, no host mounts/forwarded agent, root-owned read-only controls/vendor/toolchain, forced test transport UID2000/groups[]/NNP1/caps0 and loopback-only network policy. A runnable account shell is then an ordinary controlled test prerequisite, not a privilege grant to the implementation worker. Verify the actual effective policy and boundary probes; do not infer them solely from this document.

## Source-to-log path

| Exact source location | Observed contract |
| --- | --- |
| `rust/tests/native_e2e/mod.rs:1363` | `username()` queries `nix::unistd::User::from_uid(Uid::current())`; UID2000 selects the rgrun account from the passwd database, independently of HOME or user env. |
| `rust/tests/native_cli_e2e.rs:549`, `:765` | Both failing native CLI cases use that username when creating an SSH connection to the synthetic server. Their first successful command assertions are at608 and868. |
| `rust/tests/signer_e2e.rs:384` | `whoami()` checks USER, then LOGNAME, then executes `id -un`. The frozen FIXED_ENV has neither variable, so the intended fallback is the current account. |
| `rust/tests/signer_e2e.rs:333`, `:469`, `:996` | The fixture stores that username and uses it for direct signer-client and exec-tool SSH targets. |
| `rust/tests/native_e2e/mod.rs:1297` and `rust/tests/signer_e2e.rs:234` | Each fixture writes its own complete temporary config: loopback listener, fresh synthetic host key and absolute authorized_keys; PubkeyAuthentication yes, PasswordAuthentication no, KbdInteractiveAuthentication no, UsePAM no, StrictModes no; forwarding and PermitUserEnvironment disabled. Neither generated config contains Include, DenyUsers or ForceCommand. |
| Fixture launch arguments | Both invoke real `sshd -D -e -f <temporaryconfig>` as the current non-root user. Their chosen config does not include the management daemon's sshd_config.d policy. A management-only DenyUsers restriction therefore need not disable these fixture servers, which inherit the runner's restricted process credentials. |
| Frozen setup line6 | `useradd --uid 2000 --gid 2000 --home-dir /opt/rgjob/home --no-create-home --shell /usr/sbin/nologin --password '!' rgrun`. Private HOME is subsequently created0700 for rgrun. |

The fixtures' absolute authorized_keys paths and StrictModes no mean that moving the account HOME or unlocking a password is not an identified requirement. UsePAM no in these temporary configs is not a suggestion to change the management daemon's PAM/security policy. No change to the generated fixture config is recommended.

## Four failures, with uncertainty preserved

- `test_ssh_connection_through_admin_serve_agent_processes_and_real_sshd`: expected completed/exit0/echo output; recorded completed/exit1/nologin message on stdout (raw full log1496–1499).
- `test_ssh_connection_without_its_ssh_is_repaired_in_place`: same exit1/message pattern at the repaired SSH connection's expected echo result (raw1504–1507).
- `exec_tool_runs_two_remote_commands_on_one_connection`: first command completed/exit1 with the same stdout message; expected exit0 (raw1807–1810).
- `real_ssh_client_authenticates_through_signer_without_private_key`: fails at signer_e2e.rs473 on `first.status.success()`. Its assertion formats **only first.stderr**, which is blank. It does not print first.stdout or the actual exit status. A nologin failure writing stdout would therefore be compatible with this blank failure, but the saved log does not prove that fourth failure's cause. Different remote nonzero/signal/session failures are not excluded. Successful rerun evidence under a corrected runner is still needed; do not silently attribute or reclassify it.

The raw full verifier ran the remaining internal steps after the failed targets. That behavior does not make its overall result pass. No test should be skipped, assertion loosened, source changed or earlier failure overwritten for this environment correction.

## Coordinator sequencing, attributed only

During this static task the coordinator reported that it changed only the dedicated synthetic account shell, preserving password lock/groups, after confirming the assigned UID had no live work, and that **no product phase or new worker assignment occurred afterward**. On receiving the management-login caveat, the coordinator said it would add and verify management `DenyUsers rgrun` and reload before product execution. These are attributed coordinator messages, not runtime actions or verification by this author. The coordinator must bind its actual before/after account, effective daemon policy, isolation probes and any later execution to separate receipts. Original failed source/results remain unchanged.

## Exact inputs and limits

Inspected repository HEAD `7d27fd7ec500e36f0e5cc548325e1ae5b34864d8`, Rust tree4352 as supplied. Source sections above were read semantically; this is not a full product/SSH/OpenSSH audit.

| Input | SHA256 |
| --- | --- |
| native_cli_e2e.rs | `8f87714fb531814c33ed7b86ce461608d6e5b11ed69d0bb28daae9c6a48f1741` |
| native_e2e/mod.rs | `b4239c02483426754125967ad55817f4ce54fc18622f29aca7db50b8ab34d607` |
| signer_e2e.rs | `e84e2e4a44b7e194f1bcaed915905dc6bd3f7657958d42bf01a77fecd50287ed` |
| preparation04-os-setup.sh.txt | `3d0cb872293e179fc92fe4dbd16068d4a7ff8c9d3888a5f6366ef9085ffc9b77` |
| preparation driver text | `703f7c29492465aaba64278697df7d77692bf6988a463337002774ed182b0282` |
| failure-evidence.json | `eb15cdcb80b78d9daccfedd6fd3a24ea1de9d5c11db143435053ec82fef32ade` |
| collected/evidence/27-full-matrix.stdout | `c48fa00eda0ad47516c2f183de9a784568eea514b195c6f0a4d2d0d04c2e7f25` |

Saved forced-command and isolation-probe receipts were read as attributed DATA. Their presence is not a new live boundary test. I did not inspect shadow/password bytes, SSH private keys, model/vault/deployment/recovery credentials, management daemon runtime/config state, other VMs or case12 objects. One read-only rg query failed on an absent shell glob, then was corrected to the explicit native_e2e directory; no product command ran. All own text/DATA read processes ended.

DOS-1 HIGH, interrupted Opus3eb, old Go quarantine/lease, Linux validation failure, all M2/runtime/review/physical/Oracle/release gates remain unchanged and OPEN. This note authorizes no review retry or authority bypass and claims no PASS.
