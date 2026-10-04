# Python prototype fixtures for `parse_invite`

`cases.json`: every invite text (Python-encoded variants of a synthetic
invite payload plus malformed texts) with the outcome of the retired Python
prototype's `zeropw.team.membership.parse_invite` -- the parsed fields
(`invite_secret` base64-encoded) or `[exception class, reason]`. Used by
`tests/team_parity_gaps.rs::parse_invite_accepts_every_shape_python_accepts`.

Generated once (2026-10-03, CPython 3.12.14, repository at commit 942a963);
deterministic. Command (repository root):

```
PYTHONPATH=. python3.12 - /tmp/fx/invites < gen_invites.py
```

`gen_invites.py`:

```python
"""One-off generator for rust/tests/fixtures/python/team/invites/cases.json.

Every invite text (valid, Python-encoded, and malformed variants) with the
Python prototype's parse_invite outcome. Deterministic.
"""
import base64, json, sys
from pathlib import Path
from zeropw.team.membership import parse_invite, INVITE_FORMAT
base = {"format": INVITE_FORMAT, "env_id": "aaaaaaaaaaaaaaaaaaaaaaaaaa-0123456789abcdef0123456789abcdef",
        "inviter": "x", "addresses": ["a:1"], "invite_secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "expires_at": "2099-01-01T00:00:00Z", "role": "user", "name": "synthetic"}
DROP = object()
variants = [
    {}, {"addresses": DROP}, {"addresses": None}, {"addresses": "ab"}, {"addresses": {"k1": 1, "k2": [2]}},
    {"addresses": 5}, {"addresses": True}, {"addresses": [1, 1.5, -0.0, 1e20, 12345678901234567890, None, True,
     False, [1, "a", None], {"a": [1.5]}, "s", "é\x01"]},
    {"inviter": 12}, {"inviter": None}, {"inviter": [1, "x"]}, {"inviter": {"k": "é\x7f"}}, {"inviter": 2.5},
    {"inviter": DROP}, {"name": 42}, {"name": True}, {"name": None}, {"name": 1e-7}, {"name": ["x" * 100, "y" * 100]},
    {"name": ""}, {"name": DROP}, {"expires_at": 1.5}, {"expires_at": 4102444800}, {"expires_at": None},
    {"expires_at": DROP}, {"invite_secret": [1]}, {"invite_secret": None}, {"invite_secret": 5},
    {"invite_secret": "AAAA"}, {"invite_secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
    {"invite_secret": "AA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}, {"role": True}, {"role": "admin"},
    {"role": "owner"}, {"role": DROP}, {"env_id": 5}, {"env_id": DROP}, {"format": DROP}, {"format": "other"},
]
texts = []
for over in variants:
    payload = dict(base)
    for k, v in over.items():
        if v is DROP:
            payload.pop(k)
        else:
            payload[k] = v
    texts.append(base64.b32encode(json.dumps(payload).encode()).decode().rstrip("=").lower())
plain = texts[0]
texts += [plain + "\x1c", "\x1f" + plain, " " + plain + "　", plain.upper(),
          plain.replace("s", "ſ"), plain.replace("i", "ı"), plain + "é", plain + "=",
          base64.b32encode(json.dumps(base).encode()).decode(), plain[:-1], "", "!!",
          base64.b32encode(b"[1, 2]").decode(), base64.b32encode(b"\xff\xfe").decode(),
          base64.b32encode(json.dumps(dict(base, extra=[1])).encode()).decode()]
out = []
for text in texts:
    try:
        r = parse_invite(text)
        r["invite_secret"] = base64.b64encode(r["invite_secret"]).decode()
        out.append({"text": text, "ok": r})
    except Exception as e:
        out.append({"text": text, "err": [type(e).__name__, getattr(e, "reason", None)]})
out_dir = Path(sys.argv[1])
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / "cases.json").write_text(json.dumps(out, indent=1, ensure_ascii=True) + "\n", encoding="utf-8")
```
