# Python-generated fixtures: `signer`

Generated once, on 2026-10-03, from the Python prototype at commit
`942a963` (CPython 3.12.14 linked against OpenSSL 3.0.13, Ubuntu 24.04
aarch64 in the isolated `zeropw-parity` VM), before the prototype was
deleted. Synthetic credentials and loopback endpoints only.

Files: `agent_replies.json` (fixed seeds and session ids, each scenario's request messages as built by `zeropw.sshwire`, and the replies `zeropw.signer` sent).

Used by: `rust/tests/signer_oracle.rs`.

## Command

Run from the repository root of a checkout that still has `zeropw/`
(`vmrun.sh` streams the worktree into the VM and runs there with
`python3.12` first on `PATH`):

```sh
${HOME}/Code/zeropw-parity-evidence-20261003/vmrun.sh <worktree> cvnet bash -c '
  set -e; out=$(mktemp -d)
  PYTHONPATH=$PWD PYTHONDONTWRITEBYTECODE=1 python3.12 - "$out" >&2 <<"PYGEN"
<the script below>
PYGEN
  cd "$out" && tar -cf - . | base64 -w0' \
  | base64 -d | tar -xf - -C rust/tests/fixtures/python/signer
```

## Script

```python
"""One-off generator for rust/tests/fixtures/python/signer: the Python
prototype's SSH agent (zeropw.signer) answering request messages built with
zeropw.sshwire from fixed seeds. Writes agent_replies.json into argv[1]."""
import hashlib
import json
import socket
import sys
import tempfile
from pathlib import Path

from zeropw import policy as P
from zeropw import signer as S
from zeropw import sshwire as w
from zeropw.context import Config, Context
from zeropw.crypto.ed25519 import public_key_from_seed

OUT = Path(sys.argv[1])


def fixed(label: str) -> bytes:
    return hashlib.sha256(b"zeropw-signer-fixture/" + label.encode()).digest()


def key_from_seed(seed, comment):
    return w.Ed25519PrivateKey(seed=seed, public=w.Ed25519PublicKey(public_key_from_seed(seed)), comment=comment)


user_key = key_from_seed(fixed("user"), "agent-key")
host_key = key_from_seed(fixed("host"), "host")
other_host_key = key_from_seed(fixed("other-host"), "other-host")
session_id = fixed("session")
other_session_id = fixed("other-session")


def bind(key, sid, forwarding):
    return w.build_session_bind(key.public.blob(), sid, w.encode_ssh_signature(key.sign(sid)), forwarding)


def userauth(username, sid):
    return w.build_userauth_request(sid, username, "ssh-ed25519", user_key.public.blob(), host_key_blob=None)


SCENARIOS = [
    ("valid_flow", [bind(host_key, session_id, False),
                    w.build_sign_request(user_key.public.blob(), userauth("deploy", session_id), 0)]),
    ("wrong_user", [bind(host_key, session_id, False),
                    w.build_sign_request(user_key.public.blob(), userauth("root", session_id), 0)]),
    ("wrong_session_id", [bind(host_key, session_id, False),
                          w.build_sign_request(user_key.public.blob(), userauth("deploy", other_session_id), 0)]),
    ("second_bind", [bind(host_key, session_id, False), bind(host_key, session_id, False)]),
    ("forwarding_bind", [bind(host_key, session_id, True)]),
    ("unknown_host_key", [bind(other_host_key, session_id, False)]),
    ("arbitrary_data_sign", [bind(host_key, session_id, False),
                             w.build_sign_request(user_key.public.blob(), b"not a userauth request at all", 0)]),
    ("add_remove_key", [bytes([w.SSH_AGENTC_ADD_IDENTITY]) + b"\x00" * 8,
                        bytes([w.SSH_AGENTC_REMOVE_IDENTITY]) + b"\x00" * 8]),
    ("lock", [bytes([w.SSH_AGENTC_LOCK]) + b"\x00" * 4]),
    ("request_identities", [bytes([w.SSH_AGENTC_REQUEST_IDENTITIES])]),
]

with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
    ctx = Context.initialize(Path(tmp) / "state", "admin-passphrase-1", "recovery-passphrase-1",
                             Config(), lambda: 1700000000.0)
    ctx.projects.create("demo")
    ctx.vault.put_secret("box-key", "ssh_private_key", user_key.to_openssh_private_key().encode(), "demo", "dev")
    ctx.policy.create_principal("agent-1")
    ctx.policy.create_connection(P.Connection(
        id="box", project="demo", environment="dev", service="ssh-box", kind="ssh", secret_id="box-key",
        secret_version=None, description="", http_target=None, http_auth=None, http_scope=None,
        ssh_target=P.SshTarget("127.0.0.1", 2222, "deploy", (host_key.public.to_authorized_key("host"),)),
        cli=None, policy_version=0, status="active", created_at="", updated_at=""))
    grant = ctx.policy.create_grant("agent-1", "box", 3600, 20)
    manager = S.install(ctx)
    binding = manager.bind("agent-1", "box", grant.id)
    scenarios = []
    for name, messages in SCENARIOS:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(str(binding.socket_path))
        conn = w.AgentConnection(sock)
        replies = []
        for m in messages:
            try:
                replies.append(conn.request(m).hex())
            except Exception:
                replies.append("ERR")
        sock.close()
        scenarios.append({"name": name, "messages": [m.hex() for m in messages], "replies": replies})
    # An oversized length prefix: the connection is closed without a reply.
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(str(binding.socket_path))
    sock.sendall((w.MAX_AGENT_MESSAGE + 1).to_bytes(4, "big") + b"\x0d")
    try:
        oversized = sock.recv(1024)
    except OSError:
        oversized = b""
    sock.close()
    manager.shutdown()
    ctx.close()

(OUT / "agent_replies.json").write_text(json.dumps({
    "user_seed": user_key.seed.hex(),
    "host_seed": host_key.seed.hex(),
    "other_host_seed": other_host_key.seed.hex(),
    "session_id": session_id.hex(),
    "other_session_id": other_session_id.hex(),
    "username": "deploy",
    "max_agent_message": w.MAX_AGENT_MESSAGE,
    "scenarios": scenarios,
    "oversized_reply": oversized.hex(),
}, indent=1) + "\n")
```
