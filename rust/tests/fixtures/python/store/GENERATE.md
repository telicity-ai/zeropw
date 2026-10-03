# Python-prototype fixtures: `store`

`projects.json` written by `zeropw.projects.Projects` and a `StateDir.write_json` document.

Used by rust/tests/state_dir_cross_language.rs. Everything here is synthetic test material; no real
credential, key or host is involved.

Generated once on 2026-10-03, before the Python prototype was deleted, with
CPython 3.12.14 in the isolated `zeropw-parity` VM, from the repository root
of branch `claude/pc-cvcore` (based on `claude/rust-parity-close` 942a963):

```
rm -rf rust/tests/fixtures/python/store
PYTHONPATH=. PYTHONDONTWRITEBYTECODE=1 python3.12 store.py rust/tests/fixtures/python/store
```

(`vmrun.sh <worktree> cvcore bash -c '...'` ran that command against a copy of
the worktree and streamed the output directory back as a tar archive.)
Re-running produces different random keys, ids and salts; the tests only
depend on what the files record, not on particular random values.

`store.py`:

```python
# Generates rust/tests/fixtures/python/store/ from the Python prototype.
import pathlib, sys
from zeropw.store import StateDir
from zeropw.projects import Projects

out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True)

state = StateDir(out / "projects-state")
state.create()
projects = Projects(state)
projects.create("acme", ("dev", "staging", "prod"))
projects.create("beta", ("dev",))

state = StateDir(out / "write-json-state")
state.create()
state.write_json("doc.json", {"b": [1, 2, {"z": True, "a": None}], "a": "hello é", "n": 3.5})
```
