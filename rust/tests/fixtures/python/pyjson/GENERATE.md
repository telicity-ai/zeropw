# Python-prototype fixtures: `pyjson`

CPython 3.12 `json.dumps` output for the option presets the crate uses, a state document, `ensure_ascii` cases and `repr(float)` for a representative float sample (fixed random seed).

Used by rust/src/pyjson.rs (`oracle_tests`). Everything here is synthetic test material; no real
credential, key or host is involved.

Generated once on 2026-10-03, before the Python prototype was deleted, with
CPython 3.12.14 in the isolated `zeropw-parity` VM, from the repository root
of branch `claude/pc-cvcore` (based on `claude/rust-parity-close` 942a963):

```
rm -rf rust/tests/fixtures/python/pyjson
PYTHONPATH=. PYTHONDONTWRITEBYTECODE=1 python3.12 pyjson.py rust/tests/fixtures/python/pyjson
```

(`vmrun.sh <worktree> cvcore bash -c '...'` ran that command against a copy of
the worktree and streamed the output directory back as a tar archive.)
Re-running produces different random keys, ids and salts; the tests only
depend on what the files record, not on particular random values.

`pyjson.py`:

```python
# Generates rust/tests/fixtures/python/pyjson/ from the Python prototype.
import json, pathlib, random, struct, sys

out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True)
v = {}

values = [270784837363767.125, 599995984171052.25, 275078784986996.625,
          0.000000059604644775390625, 1.5, 0.1, -0.0]
presets = {
    "compact_sorted": dict(sort_keys=True, separators=(",", ":")),
    "pretty_sorted": dict(sort_keys=True, indent=2),
    "default_sorted": dict(sort_keys=True),
    "plain": {},
}
v["float_documents"] = {
    "values": [struct.pack(">d", x).hex() for x in values],
    "outputs": {name: [json.dumps({"value": x, "list": [x, 1, "x"], "count": 3}, **kw) for x in values]
                for name, kw in presets.items()},
}
v["compact_sorted_records"] = [json.dumps(r, sort_keys=True, separators=(",", ":")) for r in [
    {"b": 1, "a": "x\ny", "c": None, "d": True, "e": 3.5},
    {"ts": "2023-11-14T22:13:20Z", "event": "http_relay", "reason": None, "policy_version": 3},
    {"unicode": "café テスト \U0001F600", "empty_list": [], "empty_obj": {}},
    {"nested": {"z": [1, 2, {"y": 3}], "a": -0.0}},
]]
v["pretty_sorted"] = json.dumps({"z": [1, 2, 3], "a": {"nested": True, "b": None}, "empty": {}},
                                sort_keys=True, indent=2)
s = "café \U0001F600 \x00\x1f\x7f \\ \" \n\t"
v["ensure_ascii"] = {"input": s, "ascii": json.dumps(s), "unicode": json.dumps(s, ensure_ascii=False)}
v["state_document"] = json.dumps(
    {"secrets": {"s1": {"version": 3, "created_at": "2023-01-01T00:00:00Z"}}, "count": 5, "ratio": 0.1},
    sort_keys=True, indent=2)

# repr() of a representative float sample (shortest round-trip digits):
# named values, exact ties, powers of two at the exponent extremes, and a
# fixed-seed random sample.
rng = random.Random(20261003)
floats = [270784837363767.125, 599995984171052.25, 275078784986996.625, 1.5, 0.1, 0.0, -0.0,
          5e-324, sys.float_info.max, -sys.float_info.max, 1e16, 1e22, 1e-5, 1.0 / 3.0,
          2.0 ** -24, 1e-7, 123456789.0, 0.30000000000000004]
for base in (10 ** 13, 10 ** 14, 10 ** 15, 10 ** 16):
    for _ in range(25):
        denom = 2 ** rng.randint(1, 12)
        floats.append((base + rng.randrange(10 ** 6)) + rng.randrange(1, denom, 2) / denom)
for e in range(0, 2047, 23):
    b = e << 52
    for bb in (b - 1, b, b + 1):
        if 0 <= bb < (2047 << 52):
            floats.append(struct.unpack(">d", struct.pack(">Q", bb))[0])
for _ in range(100):
    floats.append(struct.unpack(">d", struct.pack(">Q", rng.getrandbits(52)))[0])
while len(floats) < 900:
    x = struct.unpack(">d", struct.pack(">Q", rng.getrandbits(64)))[0]
    if x == x and abs(x) != float("inf"):
        floats.append(x)
for e in range(-20, 20):
    floats.append(rng.randrange(10 ** 9) / 1e6 * 10.0 ** e)
v["float_repr"] = [[struct.pack(">d", x).hex(), repr(x)] for x in floats]
(out / "cases.json").write_text(json.dumps(v, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
```
