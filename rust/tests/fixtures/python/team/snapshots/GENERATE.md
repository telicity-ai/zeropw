# Python prototype fixtures for snapshot saving

`cases.json`: for each snapshot (`team/env/snapshots/1.json` content), the
retired Python prototype's `fold_with_snapshot("env", [], state)` result
`version_order` and the exact text `save_snapshot(state, "env", 2, result)`
wrote. Used by `tests/team_snapshot_version_order_parity.rs`.

Generated once (2026-10-03, CPython 3.12.14, repository at commit 942a963);
deterministic. Command (repository root):

```
PYTHONPATH=. python3.12 - /tmp/fx/snapshots < gen_snapshots.py
```

`gen_snapshots.py`:

```python
"""One-off generator for rust/tests/fixtures/python/team/snapshots/cases.json.

For each snapshot below, Python's `fold_with_snapshot("env", [], state)`
result `version_order` and the exact bytes `save_snapshot(state, "env", 2,
result)` wrote. Deterministic.
"""
import json
import sys
import tempfile
from pathlib import Path

from zeropw.store import StateDir
from zeropw.team import fold as F

cases = [
    (None, {"sid": [1, True, None, "v", 1.5]}),
    (None, {"sid": "a\U0001f642"}),
    (None, {"sid": {"first": 1, "second": 2}}),
    ({"_version_order": 5}, {"ignored": ["v1"]}),
    ({"env_id": "env", "connections": {"bad": {}}}, {}),
]
out = []
for document, version_order in cases:
    snapshot = {"document": document, "vector": {}, "version_order": version_order}
    with tempfile.TemporaryDirectory() as tmp:
        state = StateDir(Path(tmp) / "state")
        state.create()
        state.write_json("team/env/snapshots/1.json", snapshot)
        result = F.fold_with_snapshot("env", [], state)
        F.save_snapshot(state, "env", 2, result)
        saved = (state.path / "team/env/snapshots/2.json").read_text(encoding="utf-8")
    out.append({"snapshot": snapshot, "version_order": result.version_order, "saved": saved})
out_dir = Path(sys.argv[1])
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / "cases.json").write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
```
