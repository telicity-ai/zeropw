# Python-prototype fixtures: `kms`

A `LocalFileKms` key file and a DEK wrapped by it.

Used by rust/src/kms.rs. Everything here is synthetic test material; no real
credential, key or host is involved.

Generated once on 2026-10-03, before the Python prototype was deleted, with
CPython 3.12.14 in the isolated `zeropw-parity` VM, from the repository root
of branch `claude/pc-cvcore` (based on `claude/rust-parity-close` 942a963):

```
rm -rf rust/tests/fixtures/python/kms
PYTHONPATH=. PYTHONDONTWRITEBYTECODE=1 python3.12 kms.py rust/tests/fixtures/python/kms
```

(`vmrun.sh <worktree> cvcore bash -c '...'` ran that command against a copy of
the worktree and streamed the output directory back as a tar archive.)
Re-running produces different random keys, ids and salts; the tests only
depend on what the files record, not on particular random values.

`kms.py`:

```python
# Generates rust/tests/fixtures/python/kms/ from the Python prototype.
import json, pathlib, sys
from zeropw.kms import LocalFileKms

out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True)
dek = bytes.fromhex("30313233343536373839303132333435363738393031323334353637383930")
kms = LocalFileKms.create(out / "oracle.key", key_id="oracle-kms")
wrapped = kms.wrap(dek)
(out / "wrapped.json").write_text(json.dumps({"dek_hex": dek.hex(), "wrapped": wrapped.to_dict()}, indent=2) + "\n")
```
