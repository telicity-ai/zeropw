"""Tests for zeropw.sshwire: wire codec, OpenSSH key formats, agent protocol.

Format-only tests run against a deterministic *fake* Ed25519 backend that is
patched into ``sys.modules`` so they do not depend on the real
``zeropw.crypto.ed25519`` module (developed in parallel).  Interoperability
tests with ``ssh-keygen`` need the real backend and are skipped, with a
reason, while it is absent.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib
import io
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Iterator
from unittest import mock

from zeropw import sshwire as w

SSH_KEYGEN = shutil.which("ssh-keygen")


def _real_ed25519_available() -> bool:
    try:
        module = importlib.import_module("zeropw.crypto.ed25519")
    except ImportError:
        return False
    return all(
        callable(getattr(module, name, None))
        for name in ("public_key_from_seed", "sign", "verify", "generate_seed")
    )


REAL_ED25519 = _real_ed25519_available()


def _fake_ed25519_module() -> types.ModuleType:
    """A deterministic stand-in with the contract's API but no real cryptography."""
    module = types.ModuleType("zeropw.crypto.ed25519")

    def public_key_from_seed(seed: bytes) -> bytes:
        return hashlib.sha256(b"fake-ed25519-public:" + bytes(seed)).digest()

    def sign(seed: bytes, message: bytes) -> bytes:
        return hashlib.sha512(b"fake-ed25519-sig:" + bytes(seed) + bytes(message)).digest()

    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        return len(bytes(signature)) == 64 and len(bytes(public_key)) == 32

    def generate_seed() -> bytes:
        return secrets.token_bytes(32)

    module.SEED_SIZE = 32
    module.PUBLIC_KEY_SIZE = 32
    module.SIGNATURE_SIZE = 64
    module.public_key_from_seed = public_key_from_seed
    module.sign = sign
    module.verify = verify
    module.generate_seed = generate_seed
    return module


@contextlib.contextmanager
def fake_ed25519() -> Iterator[types.ModuleType]:
    module = _fake_ed25519_module()
    with mock.patch.dict(sys.modules, {"zeropw.crypto.ed25519": module}):
        yield module


def _run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, timeout=60, **kwargs)  # type: ignore[call-overload]


# ---------------------------------------------------------------------------
# Wire primitives
# ---------------------------------------------------------------------------


class EncodeTests(unittest.TestCase):
    def test_uint32(self) -> None:
        self.assertEqual(w.encode_uint32(0), b"\x00\x00\x00\x00")
        self.assertEqual(w.encode_uint32(0xDEADBEEF), b"\xde\xad\xbe\xef")
        self.assertEqual(w.encode_uint32(0xFFFFFFFF), b"\xff\xff\xff\xff")
        for bad in (-1, 2**32):
            with self.assertRaises(ValueError):
                w.encode_uint32(bad)

    def test_string(self) -> None:
        self.assertEqual(w.encode_string(b""), b"\x00\x00\x00\x00")
        self.assertEqual(w.encode_string(b"abc"), b"\x00\x00\x00\x03abc")
        self.assertEqual(w.encode_string("ssh-ed25519"), b"\x00\x00\x00\x0bssh-ed25519")
        self.assertEqual(w.encode_string(bytearray(b"xy")), b"\x00\x00\x00\x02xy")
        self.assertEqual(w.encode_string("é"), b"\x00\x00\x00\x02\xc3\xa9")
        with self.assertRaises(TypeError):
            w.encode_string(5)  # type: ignore[arg-type]

    def test_bool(self) -> None:
        self.assertEqual(w.encode_bool(True), b"\x01")
        self.assertEqual(w.encode_bool(False), b"\x00")

    def test_mpint_rfc4251_vectors(self) -> None:
        self.assertEqual(w.encode_mpint(0), bytes.fromhex("00000000"))
        self.assertEqual(w.encode_mpint(0x9A378F9B2E332A7), bytes.fromhex("0000000809a378f9b2e332a7"))
        self.assertEqual(w.encode_mpint(0x80), bytes.fromhex("000000020080"))
        self.assertEqual(w.encode_mpint(0x7F), bytes.fromhex("000000017f"))
        self.assertEqual(w.encode_mpint(0x100), bytes.fromhex("000000020100"))
        # RFC 4251 section 5 negative examples (two's complement).
        self.assertEqual(w.encode_mpint(-0x1234), bytes.fromhex("00000002edcc"))
        self.assertEqual(w.encode_mpint(-0xDEADBEEF), bytes.fromhex("00000005ff21524111"))

    def test_mpint_negative_minimal_encoding(self) -> None:
        self.assertEqual(w.encode_mpint(-1), bytes.fromhex("00000001ff"))
        self.assertEqual(w.encode_mpint(-0x7F), bytes.fromhex("0000000181"))
        self.assertEqual(w.encode_mpint(-0x80), bytes.fromhex("0000000180"))  # fits one byte
        self.assertEqual(w.encode_mpint(-0x81), bytes.fromhex("00000002ff7f"))  # needs the sign byte
        self.assertEqual(w.encode_mpint(-0x100), bytes.fromhex("00000002ff00"))
        self.assertEqual(w.encode_mpint(-(2**255)), w.encode_string(b"\x80" + b"\x00" * 31))
        self.assertEqual(w.encode_mpint(-(2**256)), w.encode_string(b"\xff" + b"\x00" * 32))  # 33 bytes: outside 256-bit range

    def test_mpint_round_trip(self) -> None:
        values = (0, 1, 0x7F, 0x80, 0xFF, 0x100, 2**255, 2**256 - 1, 2**4096 + 12345)
        for value in (*values, *(-v for v in values), -0x80, -0x81, -(2**256)):
            with self.subTest(value=value):
                self.assertEqual(w.Reader(w.encode_mpint(value)).mpint(), value)
        for value in range(-600, 600):
            self.assertEqual(w.Reader(w.encode_mpint(value)).mpint(), value)


class ReaderTests(unittest.TestCase):
    def test_sequential_reads_and_eof(self) -> None:
        buf = w.encode_string(b"hello") + w.encode_uint32(7) + b"\x01" + b"\x2a"
        r = w.Reader(buf)
        self.assertEqual(r.remaining(), len(buf))
        self.assertFalse(r.eof())
        self.assertEqual(r.string(), b"hello")
        self.assertEqual(r.uint32(), 7)
        self.assertTrue(r.boolean())
        self.assertEqual(r.byte(), 0x2A)
        self.assertTrue(r.eof())
        self.assertEqual(r.remaining(), 0)
        r.expect_eof()
        self.assertEqual(r.rest(), b"")

    def test_truncated_string_raises(self) -> None:
        with self.assertRaises(w.WireError):
            w.Reader(b"\x00\x00\x00\x05abc").string()
        with self.assertRaises(w.WireError):
            w.Reader(b"\x00\x00\x00").string()
        with self.assertRaises(w.WireError):
            w.Reader(b"").string()

    def test_truncated_primitives_raise(self) -> None:
        with self.assertRaises(w.WireError):
            w.Reader(b"\x00\x00\x00").uint32()
        with self.assertRaises(w.WireError):
            w.Reader(b"").byte()
        with self.assertRaises(w.WireError):
            w.Reader(b"").boolean()
        with self.assertRaises(w.WireError):
            w.Reader(b"ab").raw(3)

    def test_trailing_bytes_detected(self) -> None:
        r = w.Reader(w.encode_string(b"x") + b"junk")
        r.string()
        self.assertFalse(r.eof())
        self.assertEqual(r.remaining(), 4)
        with self.assertRaises(w.WireError):
            r.expect_eof("thing")
        self.assertEqual(r.rest(), b"junk")
        self.assertTrue(r.eof())

    def test_boolean_is_strict(self) -> None:
        self.assertFalse(w.Reader(b"\x00").boolean())
        self.assertTrue(w.Reader(b"\x01").boolean())
        for value in (b"\x02", b"\xff"):
            with self.assertRaises(w.WireError):
                w.Reader(value).boolean()

    def test_text_requires_utf8(self) -> None:
        self.assertEqual(w.Reader(w.encode_string("héllo")).text(), "héllo")
        with self.assertRaises(w.WireError):
            w.Reader(w.encode_string(b"\xff\xfe")).text()
        # Opt-in lenient decoding for informational fields only.
        self.assertEqual(w.Reader(w.encode_string(b"caf\xe9")).text(errors="replace"), "caf\ufffd")
        with self.assertRaises(w.WireError):
            w.Reader(w.encode_string(b"caf\xe9")).text(errors="strict")

    def test_mpint_strictness(self) -> None:
        self.assertEqual(w.Reader(bytes.fromhex("00000000")).mpint(), 0)
        self.assertEqual(w.Reader(bytes.fromhex("000000020080")).mpint(), 0x80)
        # Negative values are two's complement (RFC 4251 section 5).
        self.assertEqual(w.Reader(bytes.fromhex("0000000180")).mpint(), -0x80)
        self.assertEqual(w.Reader(bytes.fromhex("00000001ff")).mpint(), -1)
        self.assertEqual(w.Reader(bytes.fromhex("00000002ff7f")).mpint(), -0x81)
        self.assertEqual(w.Reader(bytes.fromhex("00000002edcc")).mpint(), -0x1234)
        self.assertEqual(w.Reader(bytes.fromhex("00000005ff21524111")).mpint(), -0xDEADBEEF)
        with self.assertRaises(w.WireError):  # non-minimal leading 0xff (0x80 alone is -128)
            w.Reader(bytes.fromhex("00000002ff80")).mpint()
        with self.assertRaises(w.WireError):  # non-minimal leading 0xff (0xff alone is -1)
            w.Reader(bytes.fromhex("00000002ffff")).mpint()
        with self.assertRaises(w.WireError):  # non-minimal leading zero
            w.Reader(bytes.fromhex("00000002007f")).mpint()
        with self.assertRaises(w.WireError):  # lone zero byte (should be empty)
            w.Reader(bytes.fromhex("0000000100")).mpint()
        with self.assertRaises(w.WireError):  # truncated
            w.Reader(bytes.fromhex("0000000401")).mpint()

    def test_accepts_bytearray_and_memoryview(self) -> None:
        self.assertEqual(w.Reader(bytearray(b"\x00\x00\x00\x01z")).string(), b"z")
        self.assertEqual(w.Reader(memoryview(b"\x00\x00\x00\x01z")).string(), b"z")


# ---------------------------------------------------------------------------
# Public keys, authorized_keys, signature blobs
# ---------------------------------------------------------------------------

PUB_BYTES = bytes(range(32))


class PublicKeyTests(unittest.TestCase):
    def test_blob_round_trip(self) -> None:
        key = w.Ed25519PublicKey(PUB_BYTES)
        blob = key.blob()
        self.assertEqual(blob, b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + PUB_BYTES)
        self.assertEqual(w.parse_public_key_blob(blob), key)
        self.assertEqual(w.Ed25519PublicKey.from_blob(blob), key)

    def test_length_validation(self) -> None:
        with self.assertRaises(w.WireError):
            w.Ed25519PublicKey(b"\x00" * 31)
        with self.assertRaises(w.WireError):
            w.Ed25519PublicKey(b"\x00" * 33)
        with self.assertRaises(TypeError):
            w.Ed25519PublicKey("not bytes")  # type: ignore[arg-type]

    def test_blob_parse_rejections(self) -> None:
        with self.assertRaises(w.UnsupportedKeyType):
            w.parse_public_key_blob(w.encode_string("ssh-rsa") + w.encode_string(b"\x01") + w.encode_string(b"\x02"))
        with self.assertRaises(w.UnsupportedKeyType):
            w.parse_public_key_blob(
                w.encode_string("ssh-ed25519-cert-v01@openssh.com") + w.encode_string(PUB_BYTES)
            )
        with self.assertRaises(w.WireError):
            w.parse_public_key_blob(w.encode_string("ssh-ed25519") + w.encode_string(PUB_BYTES[:31]))
        with self.assertRaises(w.WireError):
            w.parse_public_key_blob(w.encode_string("ssh-ed25519") + w.encode_string(PUB_BYTES) + b"\x00")
        with self.assertRaises(w.WireError):
            w.parse_public_key_blob(w.encode_string("ssh-ed25519"))
        with self.assertRaises(w.WireError):
            w.parse_public_key_blob(b"")

    def test_fingerprint_format(self) -> None:
        key = w.Ed25519PublicKey(PUB_BYTES)
        fp = key.fingerprint()
        self.assertTrue(fp.startswith("SHA256:"))
        self.assertNotIn("=", fp)
        digest = base64.b64decode(fp[len("SHA256:") :] + "=")
        self.assertEqual(digest, hashlib.sha256(key.blob()).digest())
        self.assertEqual(len(fp), len("SHA256:") + 43)

    def test_authorized_key_line(self) -> None:
        key = w.Ed25519PublicKey(PUB_BYTES)
        b64 = base64.b64encode(key.blob()).decode()
        self.assertEqual(key.to_authorized_key(), f"ssh-ed25519 {b64}")
        self.assertEqual(key.to_authorized_key("me@host"), f"ssh-ed25519 {b64} me@host")
        for bad in ("a\nb", "a\rb", "a\x00b"):
            with self.assertRaises(ValueError):
                key.to_authorized_key(bad)

    def test_frozen_and_hashable(self) -> None:
        key = w.Ed25519PublicKey(PUB_BYTES)
        self.assertEqual(len({key, w.Ed25519PublicKey(PUB_BYTES)}), 1)
        with self.assertRaises(Exception):
            key.key_bytes = b"\x00" * 32  # type: ignore[misc]


class AuthorizedKeysTests(unittest.TestCase):
    key = w.Ed25519PublicKey(PUB_BYTES)
    line = key.to_authorized_key("user@example")

    def test_plain_line(self) -> None:
        self.assertEqual(w.parse_authorized_key(self.line), self.key)
        entry = w.parse_authorized_key_entry(self.line)
        self.assertEqual(entry.options, "")
        self.assertEqual(entry.key, self.key)
        self.assertEqual(entry.comment, "user@example")

    def test_line_without_comment_and_with_whitespace(self) -> None:
        self.assertEqual(w.parse_authorized_key(self.key.to_authorized_key()), self.key)
        self.assertEqual(w.parse_authorized_key("  " + self.line + "  \n"), self.key)
        entry = w.parse_authorized_key_entry(self.key.to_authorized_key() + "\n")
        self.assertEqual(entry.comment, "")

    def test_comment_with_spaces(self) -> None:
        entry = w.parse_authorized_key_entry(self.key.to_authorized_key("a comment with  spaces"))
        self.assertEqual(entry.comment, "a comment with  spaces")

    def test_options_prefix(self) -> None:
        opts = 'command="echo ssh-ed25519 \\"fake\\" AAAA",no-pty,from="10.0.0.0/8"'
        entry = w.parse_authorized_key_entry(f"{opts} {self.line}")
        self.assertEqual(entry.options, opts)
        self.assertEqual(entry.key, self.key)
        self.assertEqual(entry.comment, "user@example")
        entry = w.parse_authorized_key_entry(f"restrict\t{self.key.to_authorized_key()}")
        self.assertEqual(entry.options, "restrict")
        self.assertEqual(entry.comment, "")

    def test_other_key_types_unsupported(self) -> None:
        for key_type in (
            "ssh-rsa",
            "ssh-dss",
            "ecdsa-sha2-nistp256",
            "sk-ssh-ed25519@openssh.com",
            "ssh-ed25519-cert-v01@openssh.com",
            "rsa-sha2-512",
            "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
            "x509v3-ssh-rsa",
            "x509v3-ecdsa-sha2-nistp256",
        ):
            with self.subTest(key_type=key_type):
                with self.assertRaises(w.UnsupportedKeyType):
                    w.parse_authorized_key(f"{key_type} AAAAB3NzaC1yc2EAAAADAQABAAAAgQ== c")
                with self.assertRaises(w.UnsupportedKeyType):
                    w.parse_authorized_key(f'command="x" {key_type} AAAAB3NzaC1yc2EAAAADAQABAAAAgQ== c')

    def test_unknown_key_type_followed_by_blob_is_unsupported(self) -> None:
        # A type name outside the known prefixes is still the key type when the
        # next field is a wire blob, so callers can tell "unsupported" from "malformed".
        blob = base64.b64encode(w.encode_string("future-alg@example.com") + w.encode_string(b"\x01")).decode()
        for line in (
            f"future-alg@example.com {blob}",
            f"future-alg@example.com {blob} a comment",
            f'command="x",restrict future-alg@example.com {blob} c',
            f"restrict\tfuture-alg@example.com {blob}",
        ):
            with self.subTest(line=line):
                with self.assertRaises(w.UnsupportedKeyType) as cm:
                    w.parse_authorized_key(line)
                self.assertIn("future-alg@example.com", str(cm.exception))
        # Without a decodable wire blob after it, an unknown token is not a key type.
        for line in ("future-alg@example.com AAAA", "future-alg@example.com not*base64*", "garbage more"):
            with self.subTest(line=line):
                with self.assertRaises(w.WireError) as cm:
                    w.parse_authorized_key(line)
                self.assertNotIsInstance(cm.exception, w.UnsupportedKeyType)

    def test_multi_line_input_rejected(self) -> None:
        # Only one line at a time: a whole file (or a smuggled second key) is an error,
        # and never hides inside the comment.
        for text in (
            self.line + "\n" + self.line,
            self.line + "\r\n" + self.line + "\n",
            self.line + "\n# trailing comment",
            "ssh-ed25519\n" + self.line.split()[1],
            self.line + "\x00",
        ):
            with self.subTest(text=text[:24]):
                with self.assertRaises(w.WireError):
                    w.parse_authorized_key(text)
        # A single surrounding line break is still fine, and the parsed comment
        # is always something to_authorized_key() accepts.
        self.assertEqual(w.parse_authorized_key(self.line + "\r\n"), self.key)
        entry = w.parse_authorized_key_entry("\n" + self.line + "\n")
        self.assertEqual(entry.key.to_authorized_key(entry.comment), self.line)

    # Whitespace OpenSSH never treats as a field separator; all of it is str.isspace().
    EXOTIC_WHITESPACE = {
        "NBSP": " ", "VT": "\x0b", "FF": "\x0c", "NEL": "\x85", "FS": "\x1c",
        "LINE SEPARATOR": " ", "IDEOGRAPHIC SPACE": "　",
    }
    # Positions where the character lands inside a field for OpenSSH (strcspn(cp, " \t")),
    # so sshd/ssh-keygen refuse the line while str.split() would have accepted it ...
    REFUSED_BY_OPENSSH = ("between type and blob", "between blob and comment", "leading", "after options")
    # ... and positions OpenSSH silently tolerates (comment, quoted option value).
    IGNORED_BY_OPENSSH = ("inside comment", "trailing", "inside quoted option")

    def _exotic_lines(self, ws: str) -> dict[str, str]:
        typ, b64 = self.key.to_authorized_key().split(" ")
        return {
            "between type and blob": f"{typ}{ws}{b64} c",
            "between blob and comment": f"{typ} {b64}{ws}c",
            "leading": f"{ws}{typ} {b64}",
            "after options": f'command="x"{ws}{typ} {b64}',
            "inside comment": f"{typ} {b64} a{ws}b",
            "trailing": f"{typ} {b64} c{ws}",
            "inside quoted option": f'command="x{ws}y" {typ} {b64}',
            "inside blob": f"{typ} {b64[:10]}{ws}{b64[10:]}",
        }

    def test_only_ascii_space_and_tab_separate_fields(self) -> None:
        # Any whitespace other than ASCII space/tab is refused wherever it appears: between
        # fields OpenSSH refuses the line too, elsewhere refusing is the conservative choice.
        typ, b64 = self.key.to_authorized_key().split(" ")
        for name, ws in self.EXOTIC_WHITESPACE.items():
            self.assertTrue(ws.isspace(), name)
            for where, text in self._exotic_lines(ws).items():
                with self.subTest(ws=name, where=where):
                    with self.assertRaises(w.WireError) as cm:
                        w.parse_authorized_key_entry(text)
                    self.assertNotIsInstance(cm.exception, w.UnsupportedKeyType)
        # Any mix of ASCII space and tab still delimits the fields exactly like OpenSSH.
        for text, options, comment in (
            (f"{typ}\t{b64}\tc", "", "c"),
            (f" \t{typ} \t {b64}\t c d \t\r\n", "", "c d"),
            (f"restrict\t{typ}\t{b64}", "restrict", ""),
            (f'command="a\tb" {typ} {b64}\t', 'command="a\tb"', ""),
        ):
            with self.subTest(text=text):
                entry = w.parse_authorized_key_entry(text)
                self.assertEqual((entry.options, entry.key, entry.comment), (options, self.key, comment))

    @unittest.skipIf(SSH_KEYGEN is None, "ssh-keygen not available")
    def test_exotic_whitespace_handling_agrees_with_ssh_keygen(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="zeropw-akeys-"))
        self.addCleanup(shutil.rmtree, tmp, True)

        def ssh_keygen_accepts(text: str) -> bool:
            path = tmp / "line.pub"
            path.write_text(text + "\n", encoding="utf-8")
            return _run([SSH_KEYGEN, "-l", "-f", str(path)]).returncode == 0

        typ, b64 = self.key.to_authorized_key().split(" ")
        for control in (f"{typ} {b64} c", f"{typ}\t{b64}\tc", f"restrict\t{typ}\t{b64}"):
            self.assertTrue(ssh_keygen_accepts(control), control)
            self.assertEqual(w.parse_authorized_key(control), self.key)
        for name, ws in self.EXOTIC_WHITESPACE.items():
            for where, text in self._exotic_lines(ws).items():
                with self.subTest(ws=name, where=where):
                    with self.assertRaises(w.WireError):
                        w.parse_authorized_key_entry(text)
                    if where in self.REFUSED_BY_OPENSSH:
                        self.assertFalse(ssh_keygen_accepts(text))
                    elif where in self.IGNORED_BY_OPENSSH:
                        self.assertTrue(ssh_keygen_accepts(text))
                    # "inside blob": OpenSSH's base64 decoder skips C isspace() (VT, FF) but
                    # nothing else; our strict decoder refuses all of them, so no assertion.

    def test_type_mismatch_between_line_and_blob(self) -> None:
        rsa_blob = w.encode_string("ssh-rsa") + w.encode_string(b"\x01\x00\x01") + w.encode_string(b"\x05")
        line = "ssh-ed25519 " + base64.b64encode(rsa_blob).decode()
        with self.assertRaises(w.WireError):
            w.parse_authorized_key(line)

    def test_malformed_lines(self) -> None:
        for bad in (
            "",
            "   ",
            "# comment line",
            "ssh-ed25519",
            "ssh-ed25519 not*base64* c",
            "ssh-ed25519 AAAA c",
            'command="unterminated ssh-ed25519 AAAA',
            "garbage",
            "garbage more",
            "restrict",
        ):
            with self.subTest(line=bad):
                with self.assertRaises(w.WireError):
                    w.parse_authorized_key(bad)


class SignatureBlobTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        sig = bytes(range(64))
        blob = w.encode_ssh_signature(sig)
        self.assertEqual(blob, w.encode_string("ssh-ed25519") + w.encode_string(sig))
        self.assertEqual(w.parse_ssh_signature(blob), sig)

    def test_rejections(self) -> None:
        with self.assertRaises(w.WireError):
            w.encode_ssh_signature(b"\x00" * 63)
        with self.assertRaises(w.WireError):
            w.parse_ssh_signature(w.encode_string("rsa-sha2-256") + w.encode_string(b"\x00" * 64))
        with self.assertRaises(w.WireError):
            w.parse_ssh_signature(w.encode_string("ssh-ed25519") + w.encode_string(b"\x00" * 65))
        with self.assertRaises(w.WireError):
            w.parse_ssh_signature(w.encode_string("ssh-ed25519") + w.encode_string(b"\x00" * 64) + b"\x00")
        with self.assertRaises(w.WireError):
            w.parse_ssh_signature(w.encode_string("ssh-ed25519") + w.encode_string(b"\x00" * 64)[:-1])


# ---------------------------------------------------------------------------
# OpenSSH private key format (crypto-agnostic, uses the fake backend)
# ---------------------------------------------------------------------------

MAGIC = b"openssh-key-v1\x00"
BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----"
END = "-----END OPENSSH PRIVATE KEY-----"


def _pem(blob: bytes) -> str:
    b64 = base64.b64encode(blob).decode()
    return "\n".join([BEGIN, *[b64[i : i + 70] for i in range(0, len(b64), 70)], END]) + "\n"


def _section(
    pub: bytes,
    seed: bytes,
    comment: bytes = b"c",
    *,
    check1: int = 0x01020304,
    check2: int | None = None,
    key_type: str = "ssh-ed25519",
    priv: bytes | None = None,
    padding: bytes | None = None,
) -> bytes:
    body = (
        w.encode_uint32(check1)
        + w.encode_uint32(check1 if check2 is None else check2)
        + w.encode_string(key_type)
        + w.encode_string(pub)
        + w.encode_string(seed + pub if priv is None else priv)
        + w.encode_string(comment)
    )
    if padding is None:
        padding = bytes(range(1, (-len(body)) % 8 + 1))
    return body + padding


def _container(
    pub_blob: bytes,
    section: bytes,
    *,
    cipher: str = "none",
    kdf: str = "none",
    kdfoptions: bytes = b"",
    nkeys: int = 1,
    magic: bytes = MAGIC,
    trailing: bytes = b"",
) -> bytes:
    return (
        magic
        + w.encode_string(cipher)
        + w.encode_string(kdf)
        + w.encode_string(kdfoptions)
        + w.encode_uint32(nkeys)
        + w.encode_string(pub_blob)
        + w.encode_string(section)
        + trailing
    )


class PrivateKeyFormatTests(unittest.TestCase):
    def setUp(self) -> None:
        self._ctx = fake_ed25519()
        self.fake = self._ctx.__enter__()
        self.addCleanup(self._ctx.__exit__, None, None, None)
        self.seed = bytes(range(32, 64))
        self.pub = self.fake.public_key_from_seed(self.seed)
        self.key = w.Ed25519PrivateKey.from_seed(self.seed, "test comment")

    def test_from_seed_and_generate(self) -> None:
        self.assertEqual(self.key.public.key_bytes, self.pub)
        self.assertEqual(self.key.comment, "test comment")
        generated = w.generate_ed25519_private_key("gen")
        self.assertEqual(len(generated.seed), 32)
        self.assertEqual(generated.public.key_bytes, self.fake.public_key_from_seed(generated.seed))
        self.assertEqual(generated.comment, "gen")
        self.assertNotEqual(generated.seed, w.generate_ed25519_private_key().seed)

    def test_sign_delegates_to_backend(self) -> None:
        self.assertEqual(self.key.sign(b"msg"), self.fake.sign(self.seed, b"msg"))
        self.assertEqual(len(self.key.sign(b"")), 64)
        self.assertTrue(self.key.public.verify(b"msg", self.key.sign(b"msg")))

    def test_repr_hides_seed(self) -> None:
        text = repr(self.key)
        self.assertNotIn(self.seed.hex(), text)
        self.assertNotIn(repr(self.seed), text)
        self.assertIn(self.key.public.fingerprint(), text)
        self.assertIn("test comment", text)

    def test_validation(self) -> None:
        with self.assertRaises(w.WireError):
            w.Ed25519PrivateKey(seed=b"\x00" * 31, public=self.key.public)
        with self.assertRaises(w.WireError):
            w.Ed25519PrivateKey.from_seed(b"\x00" * 33)
        with self.assertRaises(TypeError):
            w.Ed25519PrivateKey(seed=self.seed, public=b"x")  # type: ignore[arg-type]

    def test_pem_shape(self) -> None:
        pem = self.key.to_openssh_private_key()
        lines = pem.splitlines()
        self.assertEqual(lines[0], BEGIN)
        self.assertEqual(lines[-1], END)
        self.assertTrue(pem.endswith(END + "\n"))
        for line in lines[1:-1]:
            self.assertLessEqual(len(line), 70)
        for line in lines[1:-2]:
            self.assertEqual(len(line), 70)
        blob = base64.b64decode("".join(lines[1:-1]), validate=True)
        r = w.Reader(blob)
        self.assertEqual(r.raw(len(MAGIC)), MAGIC)
        self.assertEqual(r.text(), "none")
        self.assertEqual(r.text(), "none")
        self.assertEqual(r.string(), b"")
        self.assertEqual(r.uint32(), 1)
        self.assertEqual(r.string(), self.key.public.blob())
        section = r.string()
        r.expect_eof()
        self.assertEqual(len(section) % 8, 0)
        sr = w.Reader(section)
        c1, c2 = sr.uint32(), sr.uint32()
        self.assertEqual(c1, c2)
        self.assertEqual(sr.text(), "ssh-ed25519")
        self.assertEqual(sr.string(), self.pub)
        self.assertEqual(sr.string(), self.seed + self.pub)
        self.assertEqual(sr.text(), "test comment")
        padding = sr.rest()
        self.assertLess(len(padding), 8)
        self.assertEqual(padding, bytes(range(1, len(padding) + 1)))

    def test_checkint_is_random(self) -> None:
        def checkint(pem: str) -> int:
            blob = base64.b64decode("".join(pem.splitlines()[1:-1]))
            r = w.Reader(blob)
            r.raw(len(MAGIC))
            r.text(), r.text(), r.string(), r.uint32(), r.string()
            return w.Reader(r.string()).uint32()

        values = {checkint(self.key.to_openssh_private_key()) for _ in range(8)}
        self.assertGreater(len(values), 1)

    def test_round_trip(self) -> None:
        for comment in ("", "c", "a longer comment with spaces", "ünïcödé"):
            with self.subTest(comment=comment):
                key = w.Ed25519PrivateKey.from_seed(self.seed, comment)
                pem = key.to_openssh_private_key()
                parsed = w.parse_openssh_private_key(pem)
                self.assertEqual(parsed, key)
                self.assertEqual(parsed.seed, self.seed)
                self.assertEqual(parsed.public, key.public)
                self.assertEqual(parsed.comment, comment)
                self.assertEqual(w.parse_openssh_private_key(pem.encode("ascii")), key)
                self.assertEqual(w.parse_openssh_private_key(pem.replace("\n", "\r\n")), key)

    def test_padding_lengths_all_accepted(self) -> None:
        # Vary the comment length so every padding length 0..7 is exercised.
        for n in range(16):
            with self.subTest(comment_len=n):
                key = w.Ed25519PrivateKey.from_seed(self.seed, "x" * n)
                self.assertEqual(w.parse_openssh_private_key(key.to_openssh_private_key()), key)

    def test_hand_built_container_parses(self) -> None:
        pem = _pem(_container(self.key.public.blob(), _section(self.pub, self.seed, b"hand")))
        parsed = w.parse_openssh_private_key(pem)
        self.assertEqual(parsed.seed, self.seed)
        self.assertEqual(parsed.comment, "hand")

    def test_encrypted_keys_unsupported(self) -> None:
        good = _section(self.pub, self.seed)
        pub_blob = self.key.public.blob()
        with self.assertRaises(w.UnsupportedKeyType):
            w.parse_openssh_private_key(
                _pem(_container(pub_blob, good, cipher="aes256-ctr", kdf="bcrypt", kdfoptions=b"\x00" * 24))
            )
        with self.assertRaises(w.UnsupportedKeyType):
            w.parse_openssh_private_key(_pem(_container(pub_blob, good, cipher="aes256-ctr")))
        with self.assertRaises(w.UnsupportedKeyType):
            w.parse_openssh_private_key(_pem(_container(pub_blob, good, kdf="bcrypt")))

    def test_other_pem_labels_unsupported(self) -> None:
        with self.assertRaises(w.UnsupportedKeyType):
            w.parse_openssh_private_key("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n")
        with self.assertRaises(w.UnsupportedKeyType):
            w.parse_openssh_private_key("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")

    def test_non_ed25519_key_unsupported(self) -> None:
        rsa_blob = w.encode_string("ssh-rsa") + w.encode_string(b"\x01\x00\x01") + w.encode_string(b"\x05")
        section = w.encode_uint32(1) * 2 + w.encode_string("ssh-rsa") + w.encode_string(b"\x05") + b"\x01\x02"
        section += bytes(range(1, (-len(section)) % 8 + 1))
        with self.assertRaises(w.UnsupportedKeyType):
            w.parse_openssh_private_key(_pem(_container(rsa_blob, section)))

    def test_malformed_containers(self) -> None:
        pub_blob = self.key.public.blob()
        good = _section(self.pub, self.seed)
        other_seed = bytes(range(64, 96))
        cases = {
            "bad magic": _container(pub_blob, good, magic=b"openssh-key-v2\x00"),
            "kdfoptions present": _container(pub_blob, good, kdfoptions=b"\x00"),
            "zero keys": _container(pub_blob, good, nkeys=0),
            "trailing bytes": _container(pub_blob, good, trailing=b"\x00"),
            "checkint mismatch": _container(pub_blob, _section(self.pub, self.seed, check2=0x01020305)),
            "section type mismatch": _container(pub_blob, _section(self.pub, self.seed, key_type="ssh-rsa")),
            "section pub mismatch": _container(pub_blob, _section(bytes(32), self.seed)),
            "priv wrong length": _container(pub_blob, _section(self.pub, self.seed, priv=self.seed)),
            "priv pub half mismatch": _container(pub_blob, _section(self.pub, self.seed, priv=self.seed + bytes(32))),
            "seed does not derive pub": _container(pub_blob, _section(self.pub, other_seed, priv=other_seed + self.pub)),
            "bad padding values": _container(pub_blob, _section(self.pub, self.seed, b"", padding=b"\x00" * 5)),
            "padding too long": _container(pub_blob, _section(self.pub, self.seed, b"", padding=bytes(range(1, 14)))),
            "unaligned section": _container(pub_blob, _section(self.pub, self.seed, b"", padding=b"\x01\x02")),
            "truncated section": _container(pub_blob, good[:-9]),
            "empty section": _container(pub_blob, b""),
        }
        for name, blob in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(w.WireError):
                    w.parse_openssh_private_key(_pem(blob))
        with self.assertRaises(w.UnsupportedKeyType):
            w.parse_openssh_private_key(_pem(_container(pub_blob, good, nkeys=2)))

    def test_non_utf8_comment_is_decoded_leniently(self) -> None:
        # ssh-keygen -C copies argv bytes verbatim, so a valid key may carry a
        # non-UTF-8 comment; it is informational and must not make the key unusable.
        for raw, expected in ((b"caf\xe9", "caf\ufffd"), (b"\xff\xfe", "\ufffd\ufffd")):
            with self.subTest(comment=raw):
                pem = _pem(_container(self.key.public.blob(), _section(self.pub, self.seed, raw)))
                parsed = w.parse_openssh_private_key(pem)
                self.assertEqual(parsed.seed, self.seed)
                self.assertEqual(parsed.public, self.key.public)
                self.assertEqual(parsed.comment, expected)
                # The replaced comment is a plain str that serialises and round-trips.
                self.assertEqual(w.parse_openssh_private_key(parsed.to_openssh_private_key()), parsed)

    def test_malformed_pem_wrapping(self) -> None:
        pem = self.key.to_openssh_private_key()
        lines = pem.splitlines()
        cases = {
            "empty": "",
            "no header": "\n".join(lines[1:]),
            "no footer": "\n".join(lines[:-1]),
            "bad base64": "\n".join([lines[0], "!!!!", lines[-1]]),
            "truncated body": "\n".join([lines[0], *lines[1:-2], lines[-1]]),
            "empty body": "\n".join([lines[0], lines[-1]]),
            "garbage": "hello world",
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(w.WireError):
                    w.parse_openssh_private_key(text)
        with self.assertRaises(w.WireError):
            w.parse_openssh_private_key(pem.encode("ascii") + "é".encode("utf-8"))
        with self.assertRaises(TypeError):
            w.parse_openssh_private_key(123)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Interoperability with OpenSSH tooling (needs the real Ed25519 backend)
# ---------------------------------------------------------------------------


@unittest.skipIf(SSH_KEYGEN is None, "ssh-keygen not installed")
@unittest.skipUnless(REAL_ED25519, "zeropw.crypto.ed25519 is not available yet")
class SshKeygenInteropTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="zeropw-sshwire-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _keygen(self, *args: str) -> subprocess.CompletedProcess[str]:
        assert SSH_KEYGEN is not None
        proc = _run([SSH_KEYGEN, *args])
        self.assertEqual(proc.returncode, 0, f"ssh-keygen {' '.join(args)} failed: {proc.stderr}")
        return proc

    def _generate_with_ssh_keygen(self, comment: str = "c") -> Path:
        path = self.tmp / "key"
        self._keygen("-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(path))
        return path

    def _write_private(self, key: w.Ed25519PrivateKey, name: str) -> Path:
        path = self.tmp / name
        path.write_text(key.to_openssh_private_key())
        os.chmod(path, 0o600)
        return path

    def test_parse_key_made_by_ssh_keygen(self) -> None:
        path = self._generate_with_ssh_keygen("c")
        key = w.parse_openssh_private_key(path.read_text())
        self.assertEqual(key.comment, "c")
        pub_line = path.with_suffix(".pub").read_text().strip()
        entry = w.parse_authorized_key_entry(pub_line)
        self.assertEqual(entry.key, key.public)
        self.assertEqual(entry.comment, "c")
        self.assertEqual(key.public.to_authorized_key("c"), pub_line)
        self.assertEqual(w.parse_openssh_private_key(path.read_bytes()), key)

    def test_parse_key_made_by_ssh_keygen_with_non_utf8_comment(self) -> None:
        assert SSH_KEYGEN is not None
        path = self.tmp / "nonutf8"
        argv: list[str | bytes] = [SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", b"caf\xe9", "-f", str(path)]
        proc = subprocess.run(argv, capture_output=True, timeout=60)  # bytes argv: comment is not UTF-8
        if proc.returncode != 0:
            self.skipTest(f"ssh-keygen refused a non-UTF-8 comment: {proc.stderr!r}")
        key = w.parse_openssh_private_key(path.read_bytes())
        self.assertEqual(key.comment, "caf\ufffd")
        pub_fields = path.with_suffix(".pub").read_bytes().split()
        self.assertEqual(pub_fields[0], b"ssh-ed25519")
        self.assertEqual(key.public, w.parse_public_key_blob(base64.b64decode(pub_fields[1], validate=True)))
        # ssh-keygen -y agrees on the public key for the very same file.
        out = subprocess.run([SSH_KEYGEN, "-y", "-f", str(path)], capture_output=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.split()[:2], key.public.to_authorized_key().encode("ascii").split())

    def test_fingerprint_matches_ssh_keygen(self) -> None:
        path = self._generate_with_ssh_keygen("fp-comment")
        key = w.parse_openssh_private_key(path.read_text())
        out = self._keygen("-l", "-E", "sha256", "-f", str(path.with_suffix(".pub"))).stdout
        self.assertIn(key.public.fingerprint(), out.split())

    def test_our_private_key_accepted_by_ssh_keygen_y(self) -> None:
        key = w.generate_ed25519_private_key("zeropw generated")
        path = self._write_private(key, "ours")
        out = self._keygen("-y", "-f", str(path)).stdout.strip().split(None, 2)
        expected = key.public.to_authorized_key().split()
        self.assertEqual(out[:2], expected)
        if len(out) == 3:  # newer ssh-keygen also prints the comment
            self.assertEqual(out[2], "zeropw generated")

    def test_reserialised_ssh_keygen_key_prints_same_public_line(self) -> None:
        path = self._generate_with_ssh_keygen("round trip")
        original = self._keygen("-y", "-f", str(path)).stdout.strip()
        key = w.parse_openssh_private_key(path.read_text())
        ours = self._write_private(key, "reserialised")
        self.assertEqual(self._keygen("-y", "-f", str(ours)).stdout.strip(), original)
        self.assertEqual(w.parse_openssh_private_key(ours.read_text()), key)

    def test_ssh_keygen_signs_and_verifies_with_our_key_file(self) -> None:
        key = w.generate_ed25519_private_key("signer")
        path = self._write_private(key, "sigkey")
        message = self.tmp / "message.txt"
        message.write_bytes(b"zeropw interop message\n")
        assert SSH_KEYGEN is not None
        proc = _run([SSH_KEYGEN, "-Y", "sign", "-f", str(path), "-n", "zeropw-test", str(message)])
        if proc.returncode != 0 and "unknown option" in proc.stderr.lower():
            self.skipTest("ssh-keygen lacks -Y sign")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        allowed = self.tmp / "allowed_signers"
        allowed.write_text("tester " + key.public.to_authorized_key() + "\n")
        with message.open("rb") as fh:
            proc = subprocess.run(
                [SSH_KEYGEN, "-Y", "verify", "-f", str(allowed), "-I", "tester", "-n", "zeropw-test",
                 "-s", str(message) + ".sig"],
                stdin=fh, capture_output=True, text=True, timeout=60,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        # Our own sign() over the same message verifies with the derived public key.
        signature = key.sign(message.read_bytes())
        self.assertTrue(key.public.verify(message.read_bytes(), signature))
        self.assertFalse(key.public.verify(message.read_bytes() + b"x", signature))


# ---------------------------------------------------------------------------
# Agent protocol framing
# ---------------------------------------------------------------------------


class _RecordingRecv:
    """recv(n) over a byte string that records how much was requested."""

    def __init__(self, data: bytes, chunk: int | None = None) -> None:
        self.buf = io.BytesIO(data)
        self.requests: list[int] = []
        self.chunk = chunk

    def __call__(self, n: int) -> bytes:
        self.requests.append(n)
        return self.buf.read(n if self.chunk is None else min(n, self.chunk))


class AgentFramingTests(unittest.TestCase):
    def test_frame(self) -> None:
        self.assertEqual(w.frame_agent_message(b"\x0b"), b"\x00\x00\x00\x01\x0b")
        payload = b"\x0d" + b"x" * 10
        self.assertEqual(w.frame_agent_message(payload), w.encode_uint32(11) + payload)
        with self.assertRaises(w.WireError):
            w.frame_agent_message(b"")
        with self.assertRaises(w.WireError):
            w.frame_agent_message(b"\x00" * (w.MAX_AGENT_MESSAGE + 1))
        self.assertEqual(len(w.frame_agent_message(b"\x00" * w.MAX_AGENT_MESSAGE)), w.MAX_AGENT_MESSAGE + 4)

    def test_read_round_trip_with_callable(self) -> None:
        data = w.frame_agent_message(b"\x0b") + w.frame_agent_message(b"\x0d" + b"abc")
        recv = io.BytesIO(data).read
        self.assertEqual(w.read_agent_message(recv), b"\x0b")
        self.assertEqual(w.read_agent_message(recv), b"\x0dabc")
        self.assertIsNone(w.read_agent_message(recv))
        self.assertIsNone(w.read_agent_message(recv))

    def test_read_with_short_recv_chunks(self) -> None:
        payload = bytes(range(256)) * 3
        recv = _RecordingRecv(w.frame_agent_message(payload), chunk=7)
        self.assertEqual(w.read_agent_message(recv), payload)
        self.assertIsNone(w.read_agent_message(recv))

    def test_read_with_object_having_recv(self) -> None:
        class Sock:
            def __init__(self, data: bytes) -> None:
                self.buf = io.BytesIO(data)

            def recv(self, n: int) -> bytes:
                return self.buf.read(n)

        self.assertEqual(w.read_agent_message(Sock(w.frame_agent_message(b"\x05"))), b"\x05")
        with self.assertRaises(TypeError):
            w.read_agent_message(object())

    def test_truncated_length_prefix(self) -> None:
        for prefix in (b"\x00", b"\x00\x00", b"\x00\x00\x00"):
            with self.subTest(prefix=prefix):
                with self.assertRaises(w.WireError):
                    w.read_agent_message(io.BytesIO(prefix).read)

    def test_truncated_payload(self) -> None:
        data = w.encode_uint32(10) + b"12345"
        with self.assertRaises(w.WireError):
            w.read_agent_message(io.BytesIO(data).read)

    def test_zero_length_frame(self) -> None:
        with self.assertRaises(w.WireError):
            w.read_agent_message(io.BytesIO(w.encode_uint32(0) + b"\x05").read)

    def test_oversize_rejected_before_reading_payload(self) -> None:
        recv = _RecordingRecv(w.encode_uint32(w.MAX_AGENT_MESSAGE + 1) + b"x" * 64)
        with self.assertRaises(w.WireError):
            w.read_agent_message(recv)
        self.assertEqual(sum(recv.requests), 4)
        recv = _RecordingRecv(w.encode_uint32(0xFFFFFFFF))
        with self.assertRaises(w.WireError):
            w.read_agent_message(recv)
        self.assertEqual(sum(recv.requests), 4)

    def test_max_size_accepted(self) -> None:
        payload = b"\x0d" + b"\x00" * (w.MAX_AGENT_MESSAGE - 1)
        self.assertEqual(w.read_agent_message(io.BytesIO(w.frame_agent_message(payload)).read), payload)

    def test_recv_returning_too_much_rejected(self) -> None:
        def greedy(n: int) -> bytes:
            return b"\x00" * (n + 1)

        with self.assertRaises(w.WireError):
            w.read_agent_message(greedy)

    def test_write_with_callable_and_object(self) -> None:
        sent: list[bytes] = []
        w.write_agent_message(sent.append, b"\x06")
        self.assertEqual(sent, [b"\x00\x00\x00\x01\x06"])

        class Sock:
            def __init__(self) -> None:
                self.data = b""

            def sendall(self, data: bytes) -> None:
                self.data += data

        sock = Sock()
        w.write_agent_message(sock, b"\x05")
        self.assertEqual(sock.data, b"\x00\x00\x00\x01\x05")
        with self.assertRaises(w.WireError):
            w.write_agent_message(sent.append, b"")
        with self.assertRaises(TypeError):
            w.write_agent_message(object(), b"\x05")

    def test_agent_connection_over_socketpair(self) -> None:
        a, b = socket.socketpair()
        client, server = w.AgentConnection(a), w.AgentConnection(b)
        try:
            client.write_message(w.build_extension_query())
            request = server.read_message()
            self.assertEqual(request, w.build_extension_query())
            server.write_message(w.build_extension_query_response(["session-bind@openssh.com"]))
            reply = client.read_message()
            self.assertIsNotNone(reply)
            assert reply is not None
            self.assertEqual(reply[0], w.SSH_AGENT_SUCCESS)
            self.assertEqual(w.parse_extension_query_response(reply[1:]), ["session-bind@openssh.com"])
            # request() helper does the write/read pair.
            payload = w.build_sign_request(b"blob", b"data", 0)
            b.sendall(w.frame_agent_message(w.build_failure()))
            self.assertEqual(client.request(payload), w.build_failure())
            self.assertEqual(server.read_message(), payload)
        finally:
            server.close()
        # Peer closed cleanly: EOF at a message boundary reports None...
        self.assertIsNone(client.read_message())
        # ...and request() turns EOF-before-reply into a WireError.
        with self.assertRaises((w.WireError, OSError)):
            client.request(w.build_extension_query())
        client.close()

    def test_agent_connection_truncated_peer_message(self) -> None:
        a, b = socket.socketpair()
        with w.AgentConnection(a) as client:
            b.sendall(w.encode_uint32(100) + b"partial")
            b.close()
            with self.assertRaises(w.WireError):
                client.read_message()


# ---------------------------------------------------------------------------
# Agent messages
# ---------------------------------------------------------------------------

KEY_BLOB = w.Ed25519PublicKey(PUB_BYTES).blob()
HOST_KEY_BLOB = w.Ed25519PublicKey(bytes(range(100, 132))).blob()
SESSION_ID = hashlib.sha256(b"session").digest()
SIG_BLOB = w.encode_ssh_signature(bytes(range(64)))


class AgentMessageTests(unittest.TestCase):
    def test_constants(self) -> None:
        self.assertEqual(w.SSH_AGENT_FAILURE, 5)
        self.assertEqual(w.SSH_AGENT_SUCCESS, 6)
        self.assertEqual(w.SSH_AGENTC_REQUEST_IDENTITIES, 11)
        self.assertEqual(w.SSH_AGENT_IDENTITIES_ANSWER, 12)
        self.assertEqual(w.SSH_AGENTC_SIGN_REQUEST, 13)
        self.assertEqual(w.SSH_AGENT_SIGN_RESPONSE, 14)
        self.assertEqual(w.SSH_AGENTC_ADD_IDENTITY, 17)
        self.assertEqual(w.SSH_AGENTC_REMOVE_IDENTITY, 18)
        self.assertEqual(w.SSH_AGENTC_REMOVE_ALL_IDENTITIES, 19)
        self.assertEqual(w.SSH_AGENTC_ADD_SMARTCARD_KEY, 20)
        self.assertEqual(w.SSH_AGENTC_REMOVE_SMARTCARD_KEY, 21)
        self.assertEqual(w.SSH_AGENTC_LOCK, 22)
        self.assertEqual(w.SSH_AGENTC_UNLOCK, 23)
        self.assertEqual(w.SSH_AGENTC_ADD_ID_CONSTRAINED, 25)
        self.assertEqual(w.SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED, 26)
        self.assertEqual(w.SSH_AGENTC_EXTENSION, 27)
        self.assertEqual(w.SSH_AGENT_EXTENSION_FAILURE, 28)
        self.assertEqual(w.MAX_AGENT_MESSAGE, 256 * 1024)
        self.assertEqual(w.build_failure(), b"\x05")
        self.assertEqual(w.build_success(), b"\x06")

    def test_sign_request_round_trip(self) -> None:
        msg = w.build_sign_request(KEY_BLOB, b"to-sign", 0)
        self.assertEqual(msg[0], w.SSH_AGENTC_SIGN_REQUEST)
        self.assertEqual(msg, b"\x0d" + w.encode_string(KEY_BLOB) + w.encode_string(b"to-sign") + w.encode_uint32(0))
        req = w.parse_sign_request(msg[1:])
        self.assertEqual(req, w.SignRequest(key_blob=KEY_BLOB, data=b"to-sign", flags=0))
        req = w.parse_sign_request(w.build_sign_request(KEY_BLOB, b"", 2)[1:])
        self.assertEqual(req.flags, 2)
        self.assertEqual(req.data, b"")

    def test_sign_request_rejections(self) -> None:
        body = w.build_sign_request(KEY_BLOB, b"d", 0)[1:]
        with self.assertRaises(w.WireError):
            w.parse_sign_request(body + b"\x00")
        for i in range(len(body)):
            with self.subTest(cut=i):
                with self.assertRaises(w.WireError):
                    w.parse_sign_request(body[:i])

    def test_identities_answer_round_trip(self) -> None:
        keys = [(KEY_BLOB, "first"), (HOST_KEY_BLOB, "")]
        msg = w.build_identities_answer(keys)
        self.assertEqual(msg[0], w.SSH_AGENT_IDENTITIES_ANSWER)
        self.assertEqual(msg[1:5], w.encode_uint32(2))
        self.assertEqual(w.parse_identities_answer(msg[1:]), keys)
        empty = w.build_identities_answer([])
        self.assertEqual(empty, b"\x0c\x00\x00\x00\x00")
        self.assertEqual(w.parse_identities_answer(empty[1:]), [])

    def test_identities_answer_non_utf8_comment_is_decoded_leniently(self) -> None:
        body = w.encode_uint32(1) + w.encode_string(KEY_BLOB) + w.encode_string(b"caf\xe9")
        self.assertEqual(w.parse_identities_answer(body), [(KEY_BLOB, "caf\ufffd")])

    def test_identities_answer_rejections(self) -> None:
        body = w.build_identities_answer([(KEY_BLOB, "c")])[1:]
        with self.assertRaises(w.WireError):
            w.parse_identities_answer(body + b"\x00")
        with self.assertRaises(w.WireError):
            w.parse_identities_answer(body[:-1])
        with self.assertRaises(w.WireError):
            w.parse_identities_answer(w.encode_uint32(0xFFFFFFFF))
        with self.assertRaises(w.WireError):
            w.parse_identities_answer(w.encode_uint32(2) + w.encode_string(KEY_BLOB) + w.encode_string(b"c"))

    def test_sign_response_round_trip(self) -> None:
        msg = w.build_sign_response(SIG_BLOB)
        self.assertEqual(msg, b"\x0e" + w.encode_string(SIG_BLOB))
        self.assertEqual(w.parse_sign_response(msg[1:]), SIG_BLOB)
        self.assertEqual(w.parse_ssh_signature(w.parse_sign_response(msg[1:])), bytes(range(64)))
        with self.assertRaises(w.WireError):
            w.parse_sign_response(msg[1:] + b"\x00")
        with self.assertRaises(w.WireError):
            w.parse_sign_response(msg[1:-1])

    def test_extension_query(self) -> None:
        msg = w.build_extension_query()
        self.assertEqual(msg, b"\x1b" + w.encode_string("query"))
        name, rest = w.parse_extension(msg[1:])
        self.assertEqual((name, rest), ("query", b""))
        reply = w.build_extension_query_response(["session-bind@openssh.com", "other@example"])
        self.assertEqual(reply[0], w.SSH_AGENT_SUCCESS)
        # draft-miller-ssh-agent-04 §4.7.1 layout: SUCCESS then string[] names; the type
        # byte alone keeps it distinct from a sign response (OpenSSH never sends "query").
        self.assertEqual(reply, w.build_success() + w.encode_string("session-bind@openssh.com")
                         + w.encode_string("other@example"))
        self.assertNotEqual(reply[0], w.SSH_AGENT_SIGN_RESPONSE)
        self.assertEqual(w.parse_extension_query_response(reply[1:]), ["session-bind@openssh.com", "other@example"])
        self.assertEqual(w.parse_extension_query_response(b""), [])
        with self.assertRaises(w.WireError):
            w.parse_extension_query_response(b"\x00\x00\x00\x05abc")

    def test_extension_parse(self) -> None:
        body = w.encode_string("some-ext@example") + b"\x01\x02\x03"
        self.assertEqual(w.parse_extension(body), ("some-ext@example", b"\x01\x02\x03"))
        with self.assertRaises(w.WireError):
            w.parse_extension(b"")
        with self.assertRaises(w.WireError):
            w.parse_extension(w.encode_string(b""))
        with self.assertRaises(w.WireError):
            w.parse_extension(w.encode_string(b"\xff"))
        with self.assertRaises(w.WireError):
            w.parse_extension(b"\x00\x00\x00\x09abc")

    def test_session_bind_round_trip(self) -> None:
        for forwarding in (False, True):
            with self.subTest(forwarding=forwarding):
                msg = w.build_session_bind(HOST_KEY_BLOB, SESSION_ID, SIG_BLOB, forwarding)
                self.assertEqual(msg[0], w.SSH_AGENTC_EXTENSION)
                name, rest = w.parse_extension(msg[1:])
                self.assertEqual(name, "session-bind@openssh.com")
                bind = w.parse_session_bind(rest)
                self.assertEqual(
                    bind,
                    w.SessionBind(
                        host_key_blob=HOST_KEY_BLOB,
                        session_id=SESSION_ID,
                        signature=SIG_BLOB,
                        is_forwarding=forwarding,
                    ),
                )

    def test_session_bind_rejections(self) -> None:
        _, rest = w.parse_extension(w.build_session_bind(HOST_KEY_BLOB, SESSION_ID, SIG_BLOB, False)[1:])
        with self.assertRaises(w.WireError):
            w.parse_session_bind(rest + b"\x00")
        with self.assertRaises(w.WireError):  # non-canonical boolean
            w.parse_session_bind(rest[:-1] + b"\x02")
        for i in range(len(rest)):
            with self.subTest(cut=i):
                with self.assertRaises(w.WireError):
                    w.parse_session_bind(rest[:i])
        empties = (
            w.encode_string(b"") + w.encode_string(SESSION_ID) + w.encode_string(SIG_BLOB) + b"\x00",
            w.encode_string(HOST_KEY_BLOB) + w.encode_string(b"") + w.encode_string(SIG_BLOB) + b"\x00",
            w.encode_string(HOST_KEY_BLOB) + w.encode_string(SESSION_ID) + w.encode_string(b"") + b"\x00",
        )
        for data in empties:
            with self.assertRaises(w.WireError):
                w.parse_session_bind(data)


# ---------------------------------------------------------------------------
# SSH_MSG_USERAUTH_REQUEST strictness
# ---------------------------------------------------------------------------


class UserAuthRequestTests(unittest.TestCase):
    def _fields(
        self,
        *,
        session_id: bytes = SESSION_ID,
        msg: int = 50,
        username: bytes = b"deploy",
        service: bytes = b"ssh-connection",
        method: bytes = b"publickey",
        flag: bytes = b"\x01",
        algorithm: bytes = b"ssh-ed25519",
        blob: bytes = KEY_BLOB,
        extra: bytes = b"",
    ) -> bytes:
        return (
            w.encode_string(session_id)
            + bytes([msg])
            + w.encode_string(username)
            + w.encode_string(service)
            + w.encode_string(method)
            + flag
            + w.encode_string(algorithm)
            + w.encode_string(blob)
            + extra
        )

    def test_build_matches_layout(self) -> None:
        built = w.build_userauth_request(SESSION_ID, "deploy", "ssh-ed25519", KEY_BLOB)
        self.assertEqual(built, self._fields())
        hostbound = w.build_userauth_request(
            SESSION_ID, "deploy", "ssh-ed25519", KEY_BLOB, host_key_blob=HOST_KEY_BLOB
        )
        self.assertEqual(
            hostbound,
            self._fields(method=b"publickey-hostbound-v00@openssh.com", extra=w.encode_string(HOST_KEY_BLOB)),
        )
        custom = w.build_userauth_request(SESSION_ID, "u", "ssh-ed25519", KEY_BLOB, service="other")
        self.assertEqual(custom, self._fields(username=b"u", service=b"other"))

    def test_parse_plain(self) -> None:
        req = w.parse_userauth_request(self._fields())
        self.assertEqual(
            req,
            w.UserAuthRequest(
                session_id=SESSION_ID,
                username="deploy",
                service="ssh-connection",
                method="publickey",
                has_signature=True,
                algorithm="ssh-ed25519",
                public_key_blob=KEY_BLOB,
                host_key_blob=None,
            ),
        )

    def test_parse_hostbound(self) -> None:
        data = w.build_userauth_request(SESSION_ID, "deploy", "ssh-ed25519", KEY_BLOB, host_key_blob=HOST_KEY_BLOB)
        req = w.parse_userauth_request(data)
        self.assertEqual(req.method, "publickey-hostbound-v00@openssh.com")
        self.assertEqual(req.host_key_blob, HOST_KEY_BLOB)
        self.assertEqual(req.public_key_blob, KEY_BLOB)
        self.assertEqual(req.username, "deploy")
        self.assertEqual(w.parse_userauth_request(data, allow_hostbound=True), req)
        with self.assertRaises(w.WireError):
            w.parse_userauth_request(data, allow_hostbound=False)
        # Restricting to the plain method never affects plain requests.
        plain = w.parse_userauth_request(self._fields(), allow_hostbound=False)
        self.assertEqual((plain.method, plain.host_key_blob), ("publickey", None))
        with self.assertRaises(w.WireError):  # hostbound without the host key
            w.parse_userauth_request(self._fields(method=b"publickey-hostbound-v00@openssh.com"))
        with self.assertRaises(w.WireError):  # hostbound with empty host key
            w.parse_userauth_request(
                self._fields(method=b"publickey-hostbound-v00@openssh.com", extra=w.encode_string(b""))
            )
        with self.assertRaises(w.WireError):  # hostbound with trailing bytes
            w.parse_userauth_request(data + b"\x00")
        with self.assertRaises(w.WireError):  # plain method must not carry a host key
            w.parse_userauth_request(self._fields(extra=w.encode_string(HOST_KEY_BLOB)))

    def test_each_field_wrong_is_rejected(self) -> None:
        cases = {
            "empty session id": self._fields(session_id=b""),
            "msg 51 (USERAUTH_FAILURE)": self._fields(msg=51),
            "msg 60": self._fields(msg=60),
            "msg 0": self._fields(msg=0),
            "empty username": self._fields(username=b""),
            "username invalid utf8": self._fields(username=b"\xff\xfe"),
            "service ssh-userauth": self._fields(service=b"ssh-userauth"),
            "service empty": self._fields(service=b""),
            "service case": self._fields(service=b"SSH-CONNECTION"),
            "method password": self._fields(method=b"password"),
            "method none": self._fields(method=b"none"),
            "method empty": self._fields(method=b""),
            "method hostbased": self._fields(method=b"hostbased"),
            "method publickey-ish": self._fields(method=b"publickey2"),
            "flag FALSE": self._fields(flag=b"\x00"),
            "flag non-canonical": self._fields(flag=b"\x02"),
            "flag 0xff": self._fields(flag=b"\xff"),
            "empty algorithm": self._fields(algorithm=b""),
            "algorithm invalid utf8": self._fields(algorithm=b"\xff"),
            "empty blob": self._fields(blob=b""),
            "trailing byte": self._fields(extra=b"\x00"),
            "trailing string": self._fields(extra=w.encode_string(b"x")),
            "empty": b"",
        }
        for name, data in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(w.WireError):
                    w.parse_userauth_request(data)

    def test_every_truncation_is_rejected(self) -> None:
        data = self._fields()
        for i in range(len(data)):
            with self.subTest(cut=i):
                with self.assertRaises(w.WireError):
                    w.parse_userauth_request(data[:i])

    def test_arbitrary_data_is_rejected(self) -> None:
        for junk in (b"hello world", secrets.token_bytes(64), b"\x00" * 40, w.encode_string(SESSION_ID) + b"\x32"):
            with self.subTest(junk=junk[:8]):
                with self.assertRaises(w.WireError):
                    w.parse_userauth_request(junk)

    def test_other_algorithms_parse_but_are_reported(self) -> None:
        # The parser is shape-strict; algorithm/key policy belongs to the signer.
        req = w.parse_userauth_request(self._fields(algorithm=b"rsa-sha2-512", blob=b"\x00\x00\x00\x07ssh-rsa"))
        self.assertEqual(req.algorithm, "rsa-sha2-512")


if __name__ == "__main__":
    unittest.main()
