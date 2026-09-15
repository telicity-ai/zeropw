"""Tests for zeropw.crypto.ed25519 (pure-Python RFC 8032 Ed25519).

Covers the RFC 8032 section 7.1 vectors, tamper and malformed-input cases,
strict scalar/point encoding checks, random round trips, the performance
budget, and interoperability with OpenSSH's ``ssh-keygen`` in both directions
(skipped when ``ssh-keygen`` is not installed).

The OpenSSH tests deliberately parse the openssh-key-v1 private key format
and the SSHSIG armor with a tiny reader defined here rather than importing
``zeropw.sshwire``, so this suite stays independent of sibling modules.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from zeropw.crypto import ed25519

# --- RFC 8032 section 7.1 test vectors ----------------------------------------

_SHA_ABC_MESSAGE = hashlib.sha512(b"abc").digest()
assert _SHA_ABC_MESSAGE.hex().startswith("ddaf35a193617aba")

RFC_VECTORS: list[tuple[str, str, str, bytes, str]] = [
    (
        "TEST 1",
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        b"",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "TEST 2",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        bytes.fromhex("72"),
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "TEST 3",
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        bytes.fromhex("af82"),
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
    (
        "TEST SHA(abc)",
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        _SHA_ABC_MESSAGE,
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    ),
]

# Group order L, duplicated here so the tests do not depend on module internals.
_L = 2**252 + 27742317777372353535851937790883648493
_P = 2**255 - 19


def _flip_bit(data: bytes, bit_index: int) -> bytes:
    out = bytearray(data)
    out[bit_index // 8] ^= 1 << (bit_index % 8)
    return bytes(out)


def _with_scalar(signature: bytes, s: int) -> bytes:
    return signature[:32] + s.to_bytes(32, "little")


# --- Minimal SSH wire helpers (test-local; do not import zeropw.sshwire) -------


def _ssh_uint32(n: int) -> bytes:
    return n.to_bytes(4, "big")


def _ssh_string(data: bytes) -> bytes:
    return _ssh_uint32(len(data)) + data


class _Reader:
    """Strict big-endian SSH wire reader used only by these tests."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def take(self, n: int) -> bytes:
        if self._pos + n > len(self._data):
            raise ValueError("truncated SSH wire data")
        chunk = self._data[self._pos : self._pos + n]
        self._pos += n
        return chunk

    def uint32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def string(self) -> bytes:
        return self.take(self.uint32())

    def rest(self) -> bytes:
        return self._data[self._pos :]


def _dearmor(text: str, label: str) -> bytes:
    lines = [line.strip() for line in text.strip().splitlines()]
    if lines[0] != f"-----BEGIN {label}-----" or lines[-1] != f"-----END {label}-----":
        raise ValueError(f"not a {label} block")
    return base64.b64decode("".join(lines[1:-1]), validate=True)


def _armor(blob: bytes, label: str) -> str:
    b64 = base64.b64encode(blob).decode("ascii")
    body = "\n".join(b64[i : i + 70] for i in range(0, len(b64), 70))
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n"


def _parse_ed25519_public_blob(blob: bytes) -> bytes:
    reader = _Reader(blob)
    if reader.string() != b"ssh-ed25519":
        raise ValueError("not an ssh-ed25519 blob")
    key = reader.string()
    if len(key) != 32 or reader.rest():
        raise ValueError("malformed ssh-ed25519 blob")
    return key


def _parse_openssh_private_key(pem: str) -> tuple[bytes, bytes]:
    """Return (seed, public_key) from an unencrypted openssh-key-v1 ed25519 key."""
    blob = _dearmor(pem, "OPENSSH PRIVATE KEY")
    magic = b"openssh-key-v1\x00"
    if not blob.startswith(magic):
        raise ValueError("bad openssh-key-v1 magic")
    reader = _Reader(blob[len(magic) :])
    cipher, kdf, _kdf_options = reader.string(), reader.string(), reader.string()
    if cipher != b"none" or kdf != b"none":
        raise ValueError("encrypted keys are not supported by this test parser")
    if reader.uint32() != 1:
        raise ValueError("expected exactly one key")
    public_from_header = _parse_ed25519_public_blob(reader.string())
    private = _Reader(reader.string())
    if private.uint32() != private.uint32():
        raise ValueError("checkint mismatch")
    if private.string() != b"ssh-ed25519":
        raise ValueError("not an ed25519 private key")
    public = private.string()
    secret = private.string()
    _comment = private.string()
    padding = private.rest()
    if padding != bytes(range(1, len(padding) + 1)):
        raise ValueError("bad private section padding")
    if len(public) != 32 or len(secret) != 64 or secret[32:] != public:
        raise ValueError("malformed ed25519 private section")
    if public != public_from_header:
        raise ValueError("public key mismatch between header and private section")
    return secret[:32], public


def _sshsig_signed_data(namespace: bytes, hash_algorithm: bytes, message: bytes) -> bytes:
    digest = hashlib.new(hash_algorithm.decode("ascii"), message).digest()
    return (
        b"SSHSIG"
        + _ssh_string(namespace)
        + _ssh_string(b"")
        + _ssh_string(hash_algorithm)
        + _ssh_string(digest)
    )


def _parse_sshsig(text: str) -> tuple[bytes, bytes, bytes, bytes]:
    """Return (public_key, namespace, hash_algorithm, raw_signature64) from SSHSIG armor."""
    blob = _dearmor(text, "SSH SIGNATURE")
    if not blob.startswith(b"SSHSIG"):
        raise ValueError("bad SSHSIG magic")
    reader = _Reader(blob[6:])
    if reader.uint32() != 1:
        raise ValueError("unsupported SSHSIG version")
    public_key = _parse_ed25519_public_blob(reader.string())
    namespace = reader.string()
    reserved = reader.string()
    hash_algorithm = reader.string()
    sig_reader = _Reader(reader.string())
    if reserved != b"" or reader.rest():
        raise ValueError("malformed SSHSIG")
    if sig_reader.string() != b"ssh-ed25519":
        raise ValueError("SSHSIG inner signature is not ssh-ed25519")
    raw_signature = sig_reader.string()
    if sig_reader.rest():
        raise ValueError("trailing data in SSHSIG signature")
    return public_key, namespace, hash_algorithm, raw_signature


def _build_sshsig(public_key: bytes, namespace: bytes, hash_algorithm: bytes, raw_signature: bytes) -> str:
    blob = (
        b"SSHSIG"
        + _ssh_uint32(1)
        + _ssh_string(_ssh_string(b"ssh-ed25519") + _ssh_string(public_key))
        + _ssh_string(namespace)
        + _ssh_string(b"")
        + _ssh_string(hash_algorithm)
        + _ssh_string(_ssh_string(b"ssh-ed25519") + _ssh_string(raw_signature))
    )
    return _armor(blob, "SSH SIGNATURE")


# --- Tests --------------------------------------------------------------------


class ConstantsTests(unittest.TestCase):
    def test_sizes(self) -> None:
        self.assertEqual(ed25519.SEED_SIZE, 32)
        self.assertEqual(ed25519.PUBLIC_KEY_SIZE, 32)
        self.assertEqual(ed25519.SIGNATURE_SIZE, 64)


class RfcVectorTests(unittest.TestCase):
    def test_public_key_derivation(self) -> None:
        for name, seed_hex, public_hex, _message, _sig_hex in RFC_VECTORS:
            with self.subTest(vector=name):
                derived = ed25519.public_key_from_seed(bytes.fromhex(seed_hex))
                self.assertEqual(derived.hex(), public_hex)

    def test_signatures_match_vectors(self) -> None:
        for name, seed_hex, _public_hex, message, sig_hex in RFC_VECTORS:
            with self.subTest(vector=name):
                signature = ed25519.sign(bytes.fromhex(seed_hex), message)
                self.assertEqual(signature.hex(), sig_hex)

    def test_vector_signatures_verify(self) -> None:
        for name, _seed_hex, public_hex, message, sig_hex in RFC_VECTORS:
            with self.subTest(vector=name):
                self.assertTrue(
                    ed25519.verify(bytes.fromhex(public_hex), message, bytes.fromhex(sig_hex))
                )


class TamperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.seed = bytes.fromhex(RFC_VECTORS[2][1])
        self.public_key = bytes.fromhex(RFC_VECTORS[2][2])
        self.message = b"The quick brown fox jumps over the lazy dog"
        self.signature = ed25519.sign(self.seed, self.message)
        self.assertTrue(ed25519.verify(self.public_key, self.message, self.signature))

    def test_flipped_message_bit(self) -> None:
        for bit in (0, 7, 100, len(self.message) * 8 - 1):
            with self.subTest(bit=bit):
                tampered = _flip_bit(self.message, bit)
                self.assertFalse(ed25519.verify(self.public_key, tampered, self.signature))

    def test_message_extension_and_truncation(self) -> None:
        self.assertFalse(ed25519.verify(self.public_key, self.message + b"\x00", self.signature))
        self.assertFalse(ed25519.verify(self.public_key, self.message[:-1], self.signature))
        self.assertFalse(ed25519.verify(self.public_key, b"", self.signature))

    def test_flipped_signature_bits(self) -> None:
        # Bits in R (first 32 bytes) and in S (last 32 bytes).
        for bit in (0, 100, 255, 256, 300, 511):
            with self.subTest(bit=bit):
                tampered = _flip_bit(self.signature, bit)
                self.assertFalse(ed25519.verify(self.public_key, self.message, tampered))

    def test_wrong_public_key(self) -> None:
        other = ed25519.public_key_from_seed(bytes.fromhex(RFC_VECTORS[0][1]))
        self.assertFalse(ed25519.verify(other, self.message, self.signature))

    def test_signature_swapped_between_messages(self) -> None:
        other_sig = ed25519.sign(self.seed, b"another message")
        self.assertFalse(ed25519.verify(self.public_key, self.message, other_sig))

    def test_non_canonical_scalar_s_plus_l_rejected(self) -> None:
        s = int.from_bytes(self.signature[32:], "little")
        self.assertLess(s, _L)
        malleable = _with_scalar(self.signature, s + _L)
        # A lax verifier that reduces S mod L would accept this; RFC 8032 requires rejection.
        self.assertFalse(ed25519.verify(self.public_key, self.message, malleable))

    def test_scalar_equal_to_l_rejected(self) -> None:
        self.assertFalse(ed25519.verify(self.public_key, self.message, _with_scalar(self.signature, _L)))

    def test_scalar_all_ones_rejected(self) -> None:
        self.assertFalse(
            ed25519.verify(self.public_key, self.message, _with_scalar(self.signature, 2**256 - 1))
        )

    def test_wrong_lengths_return_false(self) -> None:
        cases = [
            (self.public_key, self.message, self.signature[:-1]),
            (self.public_key, self.message, self.signature + b"\x00"),
            (self.public_key, self.message, b""),
            (self.public_key[:-1], self.message, self.signature),
            (self.public_key + b"\x00", self.message, self.signature),
            (b"", self.message, self.signature),
            (b"", b"", b""),
        ]
        for public_key, message, signature in cases:
            with self.subTest(pk=len(public_key), sig=len(signature)):
                self.assertFalse(ed25519.verify(public_key, message, signature))

    def test_non_bytes_inputs_return_false(self) -> None:
        cases = [
            ("not bytes", self.message, self.signature),
            (self.public_key, "not bytes", self.signature),
            (self.public_key, self.message, "not bytes"),
            (None, self.message, self.signature),
            (self.public_key, None, self.signature),
            (self.public_key, self.message, None),
            (list(self.public_key), self.message, self.signature),
            (42, self.message, self.signature),
        ]
        for public_key, message, signature in cases:
            with self.subTest(types=(type(public_key), type(message), type(signature))):
                self.assertFalse(ed25519.verify(public_key, message, signature))  # type: ignore[arg-type]

    def test_bytearray_and_memoryview_accepted(self) -> None:
        self.assertTrue(
            ed25519.verify(
                bytearray(self.public_key), memoryview(self.message), bytearray(self.signature)
            )
        )
        self.assertEqual(ed25519.sign(bytearray(self.seed), memoryview(self.message)), self.signature)
        self.assertEqual(ed25519.public_key_from_seed(memoryview(self.seed)), self.public_key)

    @staticmethod
    def _released(data: bytes) -> memoryview:
        view = memoryview(bytes(data))
        view.release()
        return view

    def test_released_memoryview_returns_false(self) -> None:
        # A released memoryview is bytes-like by type but raises on read; the
        # contract says verify() never raises for malformed input.
        cases = [
            (self._released(self.public_key), self.message, self.signature),
            (self.public_key, self._released(self.message), self.signature),
            (self.public_key, self.message, self._released(self.signature)),
            (self._released(self.public_key), self._released(self.message), self._released(self.signature)),
        ]
        for public_key, message, signature in cases:
            with self.subTest(released=[isinstance(v, memoryview) for v in (public_key, message, signature)]):
                self.assertIs(ed25519.verify(public_key, message, signature), False)

    def test_released_memoryview_seed_or_message_raises_type_error(self) -> None:
        with self.assertRaises(TypeError):
            ed25519.public_key_from_seed(self._released(self.seed))
        with self.assertRaises(TypeError):
            ed25519.sign(self._released(self.seed), self.message)
        with self.assertRaises(TypeError):
            ed25519.sign(self.seed, self._released(self.message))

    def test_bytes_subclass_dunder_bytes_override_is_bypassed(self) -> None:
        # bytes(value) honours a __bytes__ override on bytes subclasses, so a
        # hostile subclass could make verify() raise or substitute data.  The
        # buffer protocol ignores __bytes__: the real contents are used and no
        # exception escapes (ED25519-V-1).
        class Boom(bytes):
            def __bytes__(self) -> bytes:
                raise RuntimeError("boom")

        class Swap(bytes):
            def __bytes__(self) -> bytes:
                return b"\x00" * len(self)

        for cls in (Boom, Swap):
            with self.subTest(cls=cls.__name__):
                self.assertIs(ed25519.verify(cls(self.public_key), self.message, self.signature), True)
                self.assertIs(ed25519.verify(self.public_key, cls(self.message), self.signature), True)
                self.assertIs(ed25519.verify(self.public_key, self.message, cls(self.signature)), True)
                self.assertIs(
                    ed25519.verify(cls(self.public_key), cls(self.message), cls(self.signature)), True
                )
                # Genuine contents still decide the outcome.
                self.assertIs(
                    ed25519.verify(cls(self.public_key), cls(self.message), cls(_flip_bit(self.signature, 5))),
                    False,
                )
                # sign / public_key_from_seed read the buffer too, never __bytes__.
                self.assertEqual(ed25519.public_key_from_seed(cls(self.seed)), self.public_key)
                self.assertEqual(ed25519.sign(cls(self.seed), cls(self.message)), self.signature)

    @unittest.skipIf(sys.version_info < (3, 12), "PEP 688 __buffer__ override needs Python 3.12+")
    def test_bytes_subclass_raising_buffer_returns_false(self) -> None:
        # With conversion going through the buffer protocol, a __buffer__
        # override (PEP 688) is the remaining way a bytes-like object can fail
        # to be read; verify() must still return False rather than propagate.
        class BufBoom(bytes):
            def __buffer__(self, flags: int) -> memoryview:
                raise RuntimeError("bufboom")

        cases = [
            (BufBoom(self.public_key), self.message, self.signature),
            (self.public_key, BufBoom(self.message), self.signature),
            (self.public_key, self.message, BufBoom(self.signature)),
        ]
        for public_key, message, signature in cases:
            with self.subTest(hostile=[type(v).__name__ for v in (public_key, message, signature)]):
                self.assertIs(ed25519.verify(public_key, message, signature), False)
        # Signing paths report the unusable object as a TypeError, not the raw error.
        with self.assertRaises(TypeError):
            ed25519.public_key_from_seed(BufBoom(self.seed))
        with self.assertRaises(TypeError):
            ed25519.sign(self.seed, BufBoom(self.message))

    def test_verify_never_raises_on_random_garbage(self) -> None:
        rng = secrets.SystemRandom()
        for _ in range(60):
            public_key = secrets.token_bytes(rng.choice([0, 31, 32, 32, 32, 33, 64]))
            message = secrets.token_bytes(rng.randrange(0, 40))
            signature = secrets.token_bytes(rng.choice([0, 63, 64, 64, 64, 65]))
            result = ed25519.verify(public_key, message, signature)
            self.assertIs(result, False)


class PointDecodingTests(unittest.TestCase):
    """Malformed point encodings must make verify() return False, never raise."""

    def setUp(self) -> None:
        self.seed = bytes.fromhex(RFC_VECTORS[0][1])
        self.public_key = bytes.fromhex(RFC_VECTORS[0][2])
        self.message = b"point decoding"
        self.signature = ed25519.sign(self.seed, self.message)

    def _encode_y(self, y: int, sign_bit: int) -> bytes:
        return (y | (sign_bit << 255)).to_bytes(32, "little")

    def test_public_key_y_not_below_p_rejected(self) -> None:
        for y in (_P, _P + 1, 2**255 - 1):
            for sign_bit in (0, 1):
                with self.subTest(y=y, sign=sign_bit):
                    bad_key = self._encode_y(y, sign_bit)
                    self.assertFalse(ed25519.verify(bad_key, self.message, self.signature))

    def test_r_y_not_below_p_rejected(self) -> None:
        bad_sig = self._encode_y(_P, 0) + self.signature[32:]
        self.assertFalse(ed25519.verify(self.public_key, self.message, bad_sig))

    def test_x_zero_with_sign_bit_rejected(self) -> None:
        # y = 1 is the identity (x = 0); the sign bit must then be clear.
        self.assertFalse(ed25519.verify(self._encode_y(1, 1), self.message, self.signature))
        self.assertFalse(
            ed25519.verify(self.public_key, self.message, self._encode_y(1, 1) + self.signature[32:])
        )
        # y = p - 1 gives the order-2 point (0, -1); same rule applies.
        self.assertFalse(ed25519.verify(self._encode_y(_P - 1, 1), self.message, self.signature))

    def test_point_not_on_curve_rejected(self) -> None:
        # y = 2 has no matching x on edwards25519 (x^2 candidate is a non-residue).
        self.assertFalse(ed25519.verify(self._encode_y(2, 0), self.message, self.signature))
        self.assertFalse(
            ed25519.verify(self.public_key, self.message, self._encode_y(2, 0) + self.signature[32:])
        )

    def test_small_order_public_key_does_not_raise(self) -> None:
        # The identity (y = 1, x = 0) decodes but cannot satisfy the equation for a real signature.
        self.assertIs(ed25519.verify(self._encode_y(1, 0), self.message, self.signature), False)


class RoundTripTests(unittest.TestCase):
    def test_generate_seed(self) -> None:
        a, b = ed25519.generate_seed(), ed25519.generate_seed()
        self.assertEqual(len(a), 32)
        self.assertEqual(len(b), 32)
        self.assertNotEqual(a, b)

    def test_random_round_trips(self) -> None:
        for i in range(12):
            seed = ed25519.generate_seed()
            public_key = ed25519.public_key_from_seed(seed)
            message = secrets.token_bytes(i * 37)
            with self.subTest(i=i):
                signature = ed25519.sign(seed, message)
                self.assertEqual(len(signature), 64)
                self.assertTrue(ed25519.verify(public_key, message, signature))
                self.assertFalse(ed25519.verify(public_key, message + b"x", signature))

    def test_signatures_are_deterministic(self) -> None:
        seed = ed25519.generate_seed()
        self.assertEqual(ed25519.sign(seed, b"m"), ed25519.sign(seed, b"m"))
        self.assertNotEqual(ed25519.sign(seed, b"m"), ed25519.sign(seed, b"n"))

    def test_large_message(self) -> None:
        seed = ed25519.generate_seed()
        message = secrets.token_bytes(200_000)
        signature = ed25519.sign(seed, message)
        self.assertTrue(ed25519.verify(ed25519.public_key_from_seed(seed), message, signature))

    def test_bad_seed_errors_do_not_leak_seed(self) -> None:
        short = b"\x5a" * 31
        with self.assertRaises(ValueError) as ctx:
            ed25519.sign(short, b"m")
        self.assertNotIn(short.hex(), str(ctx.exception))
        self.assertNotIn(repr(short), str(ctx.exception))
        with self.assertRaises(ValueError):
            ed25519.public_key_from_seed(b"\x00" * 33)
        with self.assertRaises(TypeError):
            ed25519.public_key_from_seed("x" * 32)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            ed25519.sign(b"\x00" * 32, "m")  # type: ignore[arg-type]


class PerformanceTests(unittest.TestCase):
    def test_sign_and_verify_under_50ms(self) -> None:
        seed = ed25519.generate_seed()
        public_key = ed25519.public_key_from_seed(seed)
        message = b"performance budget check"
        sign_times: list[float] = []
        verify_times: list[float] = []
        for _ in range(5):
            start = time.perf_counter()
            signature = ed25519.sign(seed, message)
            sign_times.append(time.perf_counter() - start)
            start = time.perf_counter()
            ok = ed25519.verify(public_key, message, signature)
            verify_times.append(time.perf_counter() - start)
            self.assertTrue(ok)
        self.assertLess(min(sign_times), 0.050)
        self.assertLess(min(verify_times), 0.050)


_SSH_KEYGEN = shutil.which("ssh-keygen")


@unittest.skipIf(_SSH_KEYGEN is None, "ssh-keygen not installed")
class OpenSSHInteropTests(unittest.TestCase):
    NAMESPACE = b"zeropw-test"

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="zeropw-ed25519-")
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.key_path = self.dir / "key"
        self._run(["-q", "-t", "ed25519", "-N", "", "-C", "zeropw interop", "-f", str(self.key_path)])
        self.seed, self.public_key = _parse_openssh_private_key(self.key_path.read_text())

    def _run(self, args: list[str], stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
        assert _SSH_KEYGEN is not None
        return subprocess.run(
            [_SSH_KEYGEN, *args],
            input=stdin,
            capture_output=True,
            timeout=60,
            check=False,
            cwd=self.dir,
        )

    def test_derived_public_key_matches_openssh(self) -> None:
        pub_line = (self.dir / "key.pub").read_text().split()
        self.assertEqual(pub_line[0], "ssh-ed25519")
        pub_from_file = _parse_ed25519_public_blob(base64.b64decode(pub_line[1]))
        self.assertEqual(pub_from_file, self.public_key)
        self.assertEqual(ed25519.public_key_from_seed(self.seed), self.public_key)

    def test_verify_signature_made_by_ssh_keygen(self) -> None:
        data_path = self.dir / "data"
        message = b"zeropw ed25519 interop message\n" + secrets.token_bytes(100)
        data_path.write_bytes(message)
        proc = self._run(["-Y", "sign", "-f", str(self.key_path), "-n", self.NAMESPACE.decode(), str(data_path)])
        self.assertEqual(proc.returncode, 0, proc.stderr.decode(errors="replace"))
        sig_text = (self.dir / "data.sig").read_text()
        public_key, namespace, hash_algorithm, raw_signature = _parse_sshsig(sig_text)
        self.assertEqual(public_key, self.public_key)
        self.assertEqual(namespace, self.NAMESPACE)
        self.assertIn(hash_algorithm, (b"sha512", b"sha256"))
        self.assertEqual(len(raw_signature), 64)

        signed = _sshsig_signed_data(namespace, hash_algorithm, message)
        self.assertTrue(ed25519.verify(public_key, signed, raw_signature))
        # Any change to the message, namespace or hash algorithm must break verification.
        self.assertFalse(
            ed25519.verify(public_key, _sshsig_signed_data(namespace, hash_algorithm, message + b"!"), raw_signature)
        )
        self.assertFalse(
            ed25519.verify(public_key, _sshsig_signed_data(b"other", hash_algorithm, message), raw_signature)
        )
        self.assertFalse(ed25519.verify(public_key, signed, _flip_bit(raw_signature, 3)))

    def test_ssh_keygen_accepts_our_signature(self) -> None:
        message = b"signed by zeropw's pure-python ed25519\n"
        signed = _sshsig_signed_data(self.NAMESPACE, b"sha512", message)
        raw_signature = ed25519.sign(self.seed, signed)
        sig_path = self.dir / "ours.sig"
        sig_path.write_text(_build_sshsig(self.public_key, self.NAMESPACE, b"sha512", raw_signature))

        good = self._run(
            ["-Y", "check-novalidate", "-n", self.NAMESPACE.decode(), "-s", str(sig_path)],
            stdin=message,
        )
        self.assertEqual(good.returncode, 0, good.stderr.decode(errors="replace"))

        bad_message = self._run(
            ["-Y", "check-novalidate", "-n", self.NAMESPACE.decode(), "-s", str(sig_path)],
            stdin=message + b"x",
        )
        self.assertNotEqual(bad_message.returncode, 0)

        bad_namespace = self._run(
            ["-Y", "check-novalidate", "-n", "wrong-namespace", "-s", str(sig_path)],
            stdin=message,
        )
        self.assertNotEqual(bad_namespace.returncode, 0)


if __name__ == "__main__":
    unittest.main()
