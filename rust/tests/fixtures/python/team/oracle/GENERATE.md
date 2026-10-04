# Python prototype fixtures for `tests/team_oracle.rs`

Generated once (2026-10-03) from the retired Python prototype (CPython
3.12.14, repository at commit 942a963) before `zeropw/` was deleted. All keys
are fixed synthetic seeds; env ids use a fixed suffix. The output is
deterministic except `envelope.wrap` (Python's own random ephemeral key and
nonce, stored exactly as produced).

- `oracle.json` -- measured values: device record, a Python-made DEK wrap,
  a signed bootstrap commit, the fixed history (commits, folded document,
  stripped document, YAML), the snapshot-seeded and nested-connections YAML,
  and the `ca_file`/`value_prefix` history.
- `state/team/<env_id>/` -- the commit store (`commits/<fp>/<seq>.json`)
  and snapshot (`snapshots/1.json`) written by Python's `CommitStore.append`
  and `fold.save_snapshot`.

Command (repository root, `PYTHONPATH=.`), writing into a scratch
directory that was then copied here:

```
PYTHONPATH=. python3.12 - /tmp/fx/oracle < gen_oracle.py
```

`gen_oracle.py`:

```python
"""One-off generator for rust/tests/fixtures/python/team/oracle/.

Run from the repository root with the retired Python prototype importable
(PYTHONPATH=.). Writes the fixture tree under the directory given as argv[1].
Every key is a fixed synthetic seed; every env id uses a fixed suffix, so the
output is deterministic except for the ephemeral key and nonce inside the one
Python-made DEK wrap (stored as produced).
"""
import json
import sys
import tempfile
from pathlib import Path

from zeropw.store import StateDir
from zeropw.team import commit as C
from zeropw.team import envelope
from zeropw.team import fold as F
from zeropw.team import humanview as H
from zeropw.team.identity import DeviceKey

OUT = Path(sys.argv[1])
SUFFIX = "0123456789abcdef0123456789abcdef"
GEN0 = "0" * 16


def device(seed, scalar):
    return DeviceKey(bytes([seed]) * 32, bytes([scalar]) * 32)


def env_for(record):
    return f"{record.fingerprint}-{SUFFIX}"


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def env_init_op(record, name, generation_id):
    wraps = {record.fingerprint: {"eph_pub": "AAAA", "nonce": "AAAA", "ciphertext": "AAAA"}}
    return {"op": "env.init", "owner_device": record.to_dict(), "owner_name": name,
            "generation_id": generation_id, "wraps": wraps}


def conn_op(conn_id):
    return {"op": "connection.create", "id": conn_id, "project": "demo", "environment": "dev",
            "service": "github", "kind": "http", "secret_id": "gh-token", "secret_version": None,
            "description": "", "http_target": {"scheme": "https", "host": "api.github.com", "port": 443},
            "http_auth": {"mode": "bearer"},
            "http_scope": {"methods": ["GET"], "path_prefixes": ["/repos"]}}


out = {}

# Device identity.
d = device(0x11, 0x22)
out["device_record"] = {"seeds": [0x11, 0x22], "record": compact(d.record.to_dict()),
                        "fingerprint": d.record.fingerprint}

# DEK wrap made by Python (random ephemeral key and nonce, stored as made).
r = device(0x55, 0x66)
wrap_env = "0123456789abcdef0123456789abcdef"
wrap_gen = "deadbeefcafef00d"
out["envelope"] = {"seeds": [0x55, 0x66], "env_id": wrap_env, "generation_id": wrap_gen,
                   "dek_hex": "aa" * 32,
                   "wrap": envelope.wrap_dek(bytes.fromhex("aa" * 32), wrap_env, wrap_gen, r.record)}

# A signed bootstrap commit.
o = device(0x77, 0x88)
env = env_for(o.record)
c = C.sign_commit(o, env, 1, "1000-0000", {}, [env_init_op(o.record, "alice-laptop", GEN0)])
assert C.verify_commit(c, o.record)
out["sign_commit"] = {"seeds": [0x77, 0x88], "env_id": env, "commit": compact(c.to_dict()),
                      "hash": c.hash}

# The fixed history (owner 0x10/0x20, second admin 0x30/0x40).
owner, second = device(0x10, 0x20), device(0x30, 0x40)
env = env_for(owner.record)
history = [
    C.sign_commit(owner, env, 1, "1000-0000", {}, [env_init_op(owner.record, "alice", GEN0)]),
    C.sign_commit(owner, env, 2, "2000-0000", {}, [{"op": "member.add", "device": second.record.to_dict(),
                                                    "name": "bob", "role": "admin"}]),
    C.sign_commit(owner, env, 3, "2500-0000", {}, [{
        "op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key", "generation_id": GEN0,
        "version_id": "1" * 16, "ciphertext": {"nonce": "AAAA", "ciphertext": "BBBB"}, "public": {}}]),
    C.sign_commit(owner, env, 4, "3000-0000", {}, [conn_op("gh")]),
    C.sign_commit(second, env, 1, "3000-0000", {}, [conn_op("gitlab")]),
    C.sign_commit(owner, env, 5, "4000-0000", {}, [{"op": "connection.disable", "id": "gh"}]),
    C.sign_commit(second, env, 2, "5000-0000", {}, [{"op": "settings.update", "sync_interval_seconds": 42}]),
]
result = F.fold(env, history)
assert not result.skipped, result.skipped
stripped = H.strip_document(result.document)
out["history"] = {"env_id": env, "commits": [compact(x.to_dict()) for x in history],
                  "document": compact(result.document), "stripped": compact(stripped),
                  "yaml": H.to_yaml(stripped)}

# Snapshot-seeded second fold: Python's own commit store and snapshot files.
update = C.sign_commit(owner, env, 6, "6000-0000", {}, [{"op": "connection.update", "id": "gitlab",
                                                       "description": "updated"}])
with tempfile.TemporaryDirectory() as tmp:
    state = StateDir(Path(tmp) / "state")
    state.create()
    store = C.CommitStore(state, env)
    for x in history + [update]:
        store.append(x)
    F.save_snapshot(state, env, 1, F.fold(env, history))
    result2 = F.fold_with_snapshot(env, store.all_commits(), state)
    tree = {}
    root = state.path / "team" / env
    for path in sorted(root.rglob("*.json")):
        tree[str(path.relative_to(state.path))] = path.read_text(encoding="utf-8")
out["snapshot_seeded"] = {"commit": compact(update.to_dict()),
                          "yaml": H.to_yaml(H.strip_document(result2.document)),
                          "files": sorted(tree)}
state_dir = OUT / "state"
for rel, text in tree.items():
    target = state_dir / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")

# A secret's public metadata nesting a "connections" key that collides with "gh".
trap = C.sign_commit(owner, env, 6, "6000-0000", {}, [{
    "op": "secret.put_version", "secret_id": "s-trap", "kind": "api_key", "generation_id": GEN0,
    "version_id": "2" * 16, "ciphertext": {"nonce": "AAAA", "ciphertext": "BBBB"},
    "public": {"connections": {"gh": {"http_scope": {"methods": ["GET"]}}}}}])
result3 = F.fold(env, history + [trap])
out["nested_connections"] = {"commit": compact(trap.to_dict()),
                             "yaml": H.to_yaml(H.strip_document(result3.document))}

# Non-string ca_file/value_prefix pass through a fold verbatim.
o = device(0xF1, 0xF2)
env = env_for(o.record)
ca = [
    C.sign_commit(o, env, 1, "1000-0000", {}, [env_init_op(o.record, "alice", GEN0)]),
    C.sign_commit(o, env, 2, "2000-0000", {}, [{
        "op": "secret.put_version", "secret_id": "tok", "kind": "api_key", "generation_id": GEN0,
        "version_id": "2" * 16, "ciphertext": {"nonce": "AAAA", "ciphertext": "BBBB"}, "public": {}}]),
    C.sign_commit(o, env, 3, "3000-0000", {}, [{
        "op": "connection.create", "id": "svc", "project": "demo", "environment": "dev", "service": "api",
        "kind": "http", "secret_id": "tok", "secret_version": None, "description": "",
        "http_target": {"scheme": "https", "host": "api.example.com", "port": 443, "ca_file": 5},
        "http_auth": {"mode": "bearer", "value_prefix": 7}, "http_scope": {"methods": ["GET"]}}]),
]
out["ca_file"] = {"env_id": env, "commits": [compact(x.to_dict()) for x in ca],
                  "document": compact(F.fold(env, ca).document)}

(OUT / "oracle.json").write_text(json.dumps(out, indent=1, sort_keys=True, ensure_ascii=False) + "\n",
                                 encoding="utf-8")
```
