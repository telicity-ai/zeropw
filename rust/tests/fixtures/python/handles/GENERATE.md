# Python-prototype fixtures: `handles`

Handle tokens issued by `zeropw.handles.HandleIssuer` with a fixed key and a fixed `jti` (`secrets.token_bytes` patched), and what the prototype's `verify` returned for them.

Used by rust/src/handles.rs (`oracle_tests`). Everything here is synthetic test material; no real
credential, key or host is involved.

Generated once on 2026-10-03, before the Python prototype was deleted, with
CPython 3.12.14 in the isolated `zeropw-parity` VM, from the repository root
of branch `claude/pc-cvcore` (based on `claude/rust-parity-close` 942a963):

```
rm -rf rust/tests/fixtures/python/handles
PYTHONPATH=. PYTHONDONTWRITEBYTECODE=1 python3.12 handles.py rust/tests/fixtures/python/handles
```

(`vmrun.sh <worktree> cvcore bash -c '...'` ran that command against a copy of
the worktree and streamed the output directory back as a tar archive.)
Re-running produces different random keys, ids and salts; the tests only
depend on what the files record, not on particular random values.

`handles.py`:

```python
# Generates rust/tests/fixtures/python/handles/ from the Python prototype.
import json, pathlib, secrets, sys
from unittest import mock
from zeropw.handles import HandleIssuer

out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True)
KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
JTI_HEX = "0102030405060708090a0b0c"
issuer = HandleIssuer(bytes.fromhex(KEY_HEX))
result = {"key_hex": KEY_HEX, "jti_hex": JTI_HEX, "tokens": []}
for now in (1700000000.0, 1e30):
    with mock.patch.object(secrets, "token_bytes", return_value=bytes.fromhex(JTI_HEX)):
        token = issuer.issue("agent-1", "gh", "g-1", 4, 300, now=now)
    h = issuer.verify(token, now=now + 10)
    result["tokens"].append({
        "now": now, "caller": "agent-1", "connection": "gh", "grant": "g-1", "policy_version": 4,
        "ttl": 300, "token": token,
        "verified": {"caller": h.caller, "connection": h.connection, "grant": h.grant,
                     "policy_version": str(h.policy_version), "issued_at": str(h.issued_at),
                     "expires_at": str(h.expires_at), "handle_id": h.handle_id},
    })
(out / "tokens.json").write_text(json.dumps(result, indent=2) + "\n")
```
