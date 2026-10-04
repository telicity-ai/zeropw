# Python-prototype fixtures: `sshwire`

Ed25519 public keys/signatures for fixed seeds, a public-key fingerprint, SSH `mpint` encodings, and an OpenSSH private key container built by `zeropw.sshwire`.

Used by rust/src/sshwire.rs. Everything here is synthetic test material; no real
credential, key or host is involved.

Generated once on 2026-10-03, before the Python prototype was deleted, with
CPython 3.12.14 in the isolated `zeropw-parity` VM, from the repository root
of branch `claude/pc-cvcore` (based on `claude/rust-parity-close` 942a963):

```
rm -rf rust/tests/fixtures/python/sshwire
PYTHONPATH=. PYTHONDONTWRITEBYTECODE=1 python3.12 sshwire.py rust/tests/fixtures/python/sshwire
```

(`vmrun.sh <worktree> cvcore bash -c '...'` ran that command against a copy of
the worktree and streamed the output directory back as a tar archive.)
Re-running produces different random keys, ids and salts; the tests only
depend on what the files record, not on particular random values.

`sshwire.py`:

```python
# Generates rust/tests/fixtures/python/sshwire/ from the Python prototype.
import json, pathlib, sys
from zeropw import sshwire as w
from zeropw.crypto.ed25519 import generate_seed, public_key_from_seed, sign

out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True)

def seed_from(byte):
    return bytes((byte + i) & 0xFF for i in range(32))

v = {}
v["public_keys"] = [[b, public_key_from_seed(seed_from(b)).hex()] for b in (0, 1, 32, 255)]
v["signatures"] = [[b, msg.hex(), sign(seed_from(b), msg).hex()]
                   for b, msg in ((0, b""), (7, b"hello"), (255, b"zeropw sshwire oracle message"))]
blob = w.Ed25519PublicKey(bytes([9] * 32)).blob()
v["fingerprint"] = {"key_hex": bytes([9] * 32).hex(), "fingerprint": w.parse_public_key_blob(blob).fingerprint()}
mp = []
for expr in ("2**255", "2**256 - 1", "2**4096 + 12345", "-(2**255)", "-(2**256)", "-(2**256 - 1)", "-(2**4096 + 12345)"):
    n = eval(expr)
    mag = -n if n < 0 else n
    mp.append([expr, n < 0, mag.to_bytes((mag.bit_length() + 7) // 8, "big").hex(), w.encode_mpint(n).hex()])
v["mpint"] = mp
(out / "vectors.json").write_text(json.dumps(v, indent=2) + "\n")

seed = generate_seed()
key = w.Ed25519PrivateKey(seed=seed, public=w.Ed25519PublicKey(public_key_from_seed(seed)), comment="from-python")
(out / "from-python.key").write_text(key.to_openssh_private_key())
(out / "from-python.pub").write_text(key.public.to_authorized_key("from-python"))
```
