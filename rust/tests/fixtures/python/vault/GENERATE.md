# Python-prototype fixtures: `vault`

A complete state directory written by `zeropw.context.Context.initialize` (KMS key, vault with one synthetic secret, admin credential, handle key, project, principal, connection, grant, audit log), the `Vault.backup` archive of it, a handle issued by its `HandleIssuer`, and the file names `Context.recover` produced on a copy at a later clock. `meta.json` holds the synthetic passphrases and secret value used.

Used by rust/tests/vault_context_oracle.rs. Everything here is synthetic test material; no real
credential, key or host is involved.

Generated once on 2026-10-03, before the Python prototype was deleted, with
CPython 3.12.14 in the isolated `zeropw-parity` VM, from the repository root
of branch `claude/pc-cvcore` (based on `claude/rust-parity-close` 942a963):

```
rm -rf rust/tests/fixtures/python/vault
PYTHONPATH=. PYTHONDONTWRITEBYTECODE=1 python3.12 vault.py rust/tests/fixtures/python/vault
```

(`vmrun.sh <worktree> cvcore bash -c '...'` ran that command against a copy of
the worktree and streamed the output directory back as a tar archive.)
Re-running produces different random keys, ids and salts; the tests only
depend on what the files record, not on particular random values.

`vault.py`:

```python
# Generates rust/tests/fixtures/python/vault/ from the Python prototype.
import json, pathlib, shutil, sys, tempfile
from zeropw import policy as P
from zeropw.context import Context, Config

out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True)
now = 1700000000.0
ctx = Context.initialize(out / "state", "admin-passphrase-1", "recovery-passphrase-1", Config(), lambda: now)
ctx.projects.create("demo")
ctx.vault.put_secret("gh-token", "api_key", b"cross-lang-secret-py-to-rust", "demo", "dev")
ctx.policy.create_principal("agent-1")
ctx.policy.create_connection(P.Connection(
    id="gh", project="demo", environment="dev", service="fake", kind="http", secret_id="gh-token",
    secret_version=None, description="", http_target=P.HttpTarget("http", "127.0.0.1", 1),
    http_auth=P.HttpAuth("bearer"), http_scope=P.HttpScope(), ssh_target=None, cli=None,
    policy_version=0, status="active", created_at="", updated_at=""))
grant = ctx.policy.create_grant("agent-1", "gh", 3600, None)
handle = ctx.handles.issue("agent-1", "gh", grant.id, grant.policy_version, 300, now=now)
ctx.vault.backup(out / "backup.json")
ctx.close()
# Disaster recovery of a copy of that state at a later clock.
with tempfile.TemporaryDirectory() as tmp:
    copy = pathlib.Path(tmp) / "state"
    shutil.copytree(out / "state", copy)
    rctx = Context.open(copy, Config(), lambda: 1700000123.75)
    revoked = rctx.recover("recovery-passphrase-1")
    rctx.close()
    recover = {
        "clock": 1700000123.75,
        "revoked": revoked,
        "kms_files": sorted(p.name for p in (copy / "kms").iterdir()),
        "kms_key_id": (copy / "kms" / "master.key").read_text().splitlines()[0],
    }
(out / "meta.json").write_text(json.dumps({
    "admin_passphrase": "admin-passphrase-1",
    "recovery_passphrase": "recovery-passphrase-1",
    "secret_id": "gh-token",
    "secret_value": "cross-lang-secret-py-to-rust",
    "grant_id": grant.id,
    "handle": handle,
    "now": now,
    "recover": recover,
}, indent=2) + "\n")
```
