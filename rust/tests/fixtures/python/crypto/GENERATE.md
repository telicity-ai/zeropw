# Python-prototype fixtures: `crypto`

ChaCha20-Poly1305, Ed25519 and X25519 vectors from `zeropw.crypto` (including signatures forged against non-canonical small-order point encodings, built with the prototype's own point arithmetic).

Used by rust/src/crypto/{chacha20poly1305,ed25519,x25519}.rs. Everything here is synthetic test material; no real
credential, key or host is involved.

Generated once on 2026-10-03, before the Python prototype was deleted, with
CPython 3.12.14 in the isolated `zeropw-parity` VM, from the repository root
of branch `claude/pc-cvcore` (based on `claude/rust-parity-close` 942a963):

```
rm -rf rust/tests/fixtures/python/crypto
PYTHONPATH=. PYTHONDONTWRITEBYTECODE=1 python3.12 crypto.py rust/tests/fixtures/python/crypto
```

(`vmrun.sh <worktree> cvcore bash -c '...'` ran that command against a copy of
the worktree and streamed the output directory back as a tar archive.)
Re-running produces different random keys, ids and salts; the tests only
depend on what the files record, not on particular random values.

`crypto.py`:

```python
# Generates rust/tests/fixtures/python/crypto/ from the Python prototype.
import json, pathlib, sys
from zeropw.crypto import chacha20poly1305 as aead
from zeropw.crypto import ed25519 as m
from zeropw.crypto import x25519

out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True)
v = {}

key, nonce, aad = bytes([0x12]) * 32, bytes([0x34]) * 12, b"zeropw-oracle-aad"
plaintext = b"zeropw rust/python chacha20poly1305 oracle check"
v["chacha20poly1305"] = {"key": key.hex(), "nonce": nonce.hex(), "aad": aad.hex(),
                         "plaintext": plaintext.hex(), "sealed": aead.encrypt(key, nonce, plaintext, aad).hex()}

seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
message = b"zeropw rust/python ed25519 oracle check"
v["ed25519_sign"] = {"seed": seed.hex(), "message": message.hex(),
                     "signature": m.sign(seed, message).hex(), "public_key": m.public_key_from_seed(seed).hex()}

P, B = m._P, m._B
def encode_y(y_int, sign):
    b = bytearray(y_int.to_bytes(32, "little"))
    assert b[31] & 0x80 == 0
    if sign:
        b[31] |= 0x80
    return bytes(b)

# A signature valid for the identity point under any message; only the
# canonical identity encoding may verify.
R = m._point_encode(m._scalar_mult(5, B))
sig = R + (5).to_bytes(32, "little")
msg = b"forged under a non-canonical identity encoding"
ident = {"signature": sig.hex(), "message": msg.hex(),
         "pk_canonical": (1).to_bytes(32, "little").hex(),
         "pk_signbit": encode_y(1, True).hex(),
         "pk_p_plus_1": encode_y(P + 1, False).hex(),
         "pk_p_plus_1_signbit": encode_y(P + 1, True).hex()}
assert m.verify(bytes.fromhex(ident["pk_canonical"]), msg, sig) is True
for k in ("pk_signbit", "pk_p_plus_1", "pk_p_plus_1_signbit"):
    assert m.verify(bytes.fromhex(ident[k]), msg, sig) is False
v["ed25519_forged_identity"] = ident

# The same for the order-2 point (0, -1): needs an even challenge.
pk_canonical = encode_y(P - 1, False)
pk_signbit = encode_y(P - 1, True)
R = m._point_encode(B)
msg = None
for i in range(10_000):
    candidate = f"order2-forge-{i}".encode()
    if m._sha512_mod_l(R, pk_signbit, candidate) % 2 == 0:
        msg = candidate
        break
sig = R + (1).to_bytes(32, "little")
assert m.verify(pk_canonical, msg, sig) is True
assert m.verify(pk_signbit, msg, sig) is False
v["ed25519_forged_order2"] = {"signature": sig.hex(), "message": msg.hex(),
                              "pk_canonical": pk_canonical.hex(), "pk_signbit": pk_signbit.hex()}

cases = [b"", b"\xa5", b"\xa5" * 31, b"\xff" * 32, b"\xff" * 33, b"\xff" * 64, b"\xff" * 257,
         b"\xff" * 32 + b"\x00" * 32]
clamp = []
for raw in cases:
    try:
        clamp.append([raw.hex(), x25519.clamp_scalar(raw).to_bytes(len(raw), "little").hex()])
    except Exception as exc:
        clamp.append([raw.hex(), type(exc).__name__])
v["x25519_clamp"] = clamp
k = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
v["x25519_scalarmult"] = {"k": k.hex(), "u": u.hex(), "result": x25519.scalarmult(k, u).hex()}
a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
b = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
v["x25519_exchange"] = {"a_priv": a.hex(), "b_priv": b.hex(),
                        "a_pub": x25519.public_key(a).hex(), "b_pub": x25519.public_key(b).hex(),
                        "shared": x25519.shared_secret(a, x25519.public_key(b)).hex()}
assert x25519.shared_secret(b, x25519.public_key(a)).hex() == v["x25519_exchange"]["shared"]
(out / "vectors.json").write_text(json.dumps(v, indent=2) + "\n")
```
