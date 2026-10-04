# Python-prototype fixtures: `policy`

Policy digests (`approval_digest`, `hash_token`) and a policy-only state directory (principal, HTTP connection, grant) written by `zeropw.policy.Policy` with the clock fixed at 1700000000. `state-meta.json` records the random grant id and the synthetic caller token.

Used by rust/tests/policy_oracle.rs. Everything here is synthetic test material; no real
credential, key or host is involved.

Generated once on 2026-10-03, before the Python prototype was deleted, with
CPython 3.12.14 in the isolated `zeropw-parity` VM, from the repository root
of branch `claude/pc-cvcore` (based on `claude/rust-parity-close` 942a963):

```
rm -rf rust/tests/fixtures/python/policy
PYTHONPATH=. PYTHONDONTWRITEBYTECODE=1 python3.12 policy.py rust/tests/fixtures/python/policy
```

(`vmrun.sh <worktree> cvcore bash -c '...'` ran that command against a copy of
the worktree and streamed the output directory back as a tar archive.)
Re-running produces different random keys, ids and salts; the tests only
depend on what the files record, not on particular random values.

`policy.py`:

```python
# Generates rust/tests/fixtures/python/policy/ from the Python prototype.
import json, pathlib, sys
from zeropw.store import StateDir
from zeropw import policy as P

out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True)

# digests.json: approval_digest/hash_token over synthetic inputs.
cases = [
    ("agent-1", "gh", "DELETE", "/repos/demo", b""),
    ("agent-1", "gh", "DELETE", "/repos/demo", b"{}"),
    ("agent-1", "gh", "DELETE", "/repos/other", b""),
    ("", "", "", "", b""),
    ("agent-é", "gh2", "GET", "/a/b?c=1", b"\x00\x01\xffbinary"),
]
tokens = ["zpwc_abc123", "", "zpwc_" + "a" * 64]
digests = {
    "approval_digest": [[c, n, m, p, b.hex(), P.approval_digest(c, n, m, p, b)] for c, n, m, p, b in cases],
    "hash_token": [[t, P.hash_token(t)] for t in tokens],
}
(out / "digests.json").write_text(json.dumps(digests, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

# state/: a policy-only state directory written by Python's Policy.
state = StateDir(out / "state")
state.create()
policy = P.Policy(state, clock=lambda: 1700000000.0)
token = policy.create_principal("agent-1")
conn = P.Connection(
    id="gh", project="demo", environment="dev", service="fake-github", kind="http",
    secret_id="gh-token", secret_version=None, description="demo",
    http_target=P.HttpTarget("http", "127.0.0.1", 8080),
    http_auth=P.HttpAuth("bearer"),
    http_scope=P.HttpScope(("GET", "POST"), ("/repos", "/me"), ("DELETE",)),
    ssh_target=None, cli=None, policy_version=0, status="active", created_at="", updated_at="",
)
policy.create_connection(conn)
grant = policy.create_grant("agent-1", "gh", 3600, None)
(out / "state-meta.json").write_text(json.dumps({"grant_id": grant.id, "principal_token": token}, indent=2) + "\n")
```
