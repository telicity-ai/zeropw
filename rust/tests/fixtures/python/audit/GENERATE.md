# Python-prototype fixtures: `audit`

`audit.jsonl`/`alerts.jsonl` written by `zeropw.audit.Audit` (clock fixed at 1700000000) for a fixed sequence of records.

Used by rust/src/audit.rs (`oracle_tests`). Everything here is synthetic test material; no real
credential, key or host is involved.

Generated once on 2026-10-03, before the Python prototype was deleted, with
CPython 3.12.14 in the isolated `zeropw-parity` VM, from the repository root
of branch `claude/pc-cvcore` (based on `claude/rust-parity-close` 942a963):

```
rm -rf rust/tests/fixtures/python/audit
PYTHONPATH=. PYTHONDONTWRITEBYTECODE=1 python3.12 audit.py rust/tests/fixtures/python/audit
```

(`vmrun.sh <worktree> cvcore bash -c '...'` ran that command against a copy of
the worktree and streamed the output directory back as a tar archive.)
Re-running produces different random keys, ids and salts; the tests only
depend on what the files record, not on particular random values.

`audit.py`:

```python
# Generates rust/tests/fixtures/python/audit/ from the Python prototype.
import pathlib, shutil, sys, tempfile
from zeropw.audit import Audit
from zeropw.store import StateDir

out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True)

def fresh():
    tmp = tempfile.mkdtemp()
    state = StateDir(pathlib.Path(tmp) / "state")
    state.create()
    return tmp, state, Audit(state, lambda: 1700000000.0)

tmp, state, audit = fresh()
audit.record("http_relay", caller="agent-1", connection="gh", target="127.0.0.1:8080",
             action="GET", result="ok", policy_version=3,
             extra={"path": "/repos?token=x", "status": 200})
audit.record("secret_reveal", caller="admin", connection="gh")
audit.record("http_relay", caller="agent-1", result="denied", reason="grant_revoked")
audit.record("team_incident_received", caller="dev-2", connection="gh")
audit.record("http_relay", target="a\nb\x00c\x7f", reason="x" * 250)
audit.record("incident_open", caller="admin", extra={"scope": "connection", "incident_id": "inc-1"})
shutil.copy(state.path / "audit" / "audit.jsonl", out / "records-audit.jsonl")
shutil.copy(state.path / "audit" / "alerts.jsonl", out / "records-alerts.jsonl")
shutil.rmtree(tmp)

tmp, state, audit = fresh()
audit.record("incident_open", caller="admin", extra={"scope": "connection", "incident_id": "inc-1"})
audit.record("incident_open", caller="admin", extra={"scope": 3, "incident_id": "inc-2"})
audit.record("incident_open", caller="admin", reason="manual", extra={"scope": True, "incident_id": "inc-3"})
audit.record("incident_open", caller="admin", reason="", extra={"scope": False, "incident_id": "inc-4"})
audit.record("incident_open", caller="admin", extra={"scope": 1.5, "incident_id": "inc-5"})
audit.record("incident_open", caller="admin", extra={"incident_id": "inc-6"})
audit.record("incident_widen", caller="admin", extra={"scope": "project", "incident_id": "inc-1"})
audit.record("incident_widen", caller="admin", extra={"scope": None, "incident_id": "inc-1"})
shutil.copy(state.path / "audit" / "alerts.jsonl", out / "incident-alerts.jsonl")
shutil.rmtree(tmp)
```
