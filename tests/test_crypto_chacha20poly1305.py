"""Tests for zeropw.crypto.chacha20poly1305 against the RFC 8439 vectors.

Every vector below is transcribed from RFC 8439 (the section or appendix is
named in each test).  The AEAD vectors tie the ChaCha20 stream, the Poly1305
key derivation and the Poly1305 MAC together, so a transcription slip in any
of them shows up as a failing tag rather than a silently accepted value.
"""

from __future__ import annotations

import secrets
import time
import unittest

from zeropw.crypto import chacha20poly1305 as aead
from zeropw.crypto.chacha20poly1305 import (
    KEY_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    AuthenticationError,
    chacha20_block,
    chacha20_encrypt,
    decrypt,
    encrypt,
    poly1305_key_gen,
    poly1305_mac,
)


def _hex(text: str) -> bytes:
    """Parse RFC-style hex dumps: whitespace and ':' separators are ignored."""
    return bytes.fromhex("".join(text.split()).replace(":", ""))


# --- RFC 8439 section 2.4.2 / 2.8.2 plaintext ("sunscreen") --------------
SUNSCREEN = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you only one "
    b"tip for the future, sunscreen would be it."
)

# --- RFC 8439 section 2.3.2: block function test vector -------------------
BLOCK_KEY = _hex(
    "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:"
    "18:19:1a:1b:1c:1d:1e:1f"
)
BLOCK_NONCE = _hex("00:00:00:09:00:00:00:4a:00:00:00:00")
BLOCK_COUNTER = 1
BLOCK_OUTPUT = _hex(
    """
    10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4
    c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e
    d2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2
    b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e
    """
)

# --- RFC 8439 appendix A.1 test vector #1: all-zero key and nonce ---------
ZERO_BLOCK_OUTPUT = _hex(
    """
    76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28
    bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7
    da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37
    6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86
    """
)

# --- RFC 8439 section 2.4.2: encryption test vector -----------------------
ENC_KEY = BLOCK_KEY
ENC_NONCE = _hex("00:00:00:00:00:00:00:4a:00:00:00:00")
ENC_COUNTER = 1
ENC_CIPHERTEXT = _hex(
    """
    6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81
    e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b
    f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57
    16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8
    07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e
    52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36
    5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42
    87 4d
    """
)

# --- RFC 8439 section 2.5.2: Poly1305 test vector -------------------------
POLY_KEY = _hex(
    "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:"
    "4a:bf:f6:af:41:49:f5:1b"
)
POLY_MESSAGE = b"Cryptographic Forum Research Group"
POLY_TAG = _hex("a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9")

# --- RFC 8439 section 2.6.2: Poly1305 key generation test vector ----------
KEYGEN_KEY = _hex(
    "80:81:82:83:84:85:86:87:88:89:8a:8b:8c:8d:8e:8f:90:91:92:93:94:95:96:97:"
    "98:99:9a:9b:9c:9d:9e:9f"
)
KEYGEN_NONCE = _hex("00:00:00:00:00:01:02:03:04:05:06:07")
KEYGEN_OUTPUT = _hex(
    """
    8a d5 a0 8b 90 5f 81 cc 81 50 40 27 4a b2 94 71
    a8 33 b6 37 e3 fd 0d a5 08 db b8 e2 fd d1 a6 46
    """
)

# --- RFC 8439 section 2.8.2: AEAD encryption test vector ------------------
AEAD_KEY = KEYGEN_KEY
AEAD_AAD = _hex("50:51:52:53:c0:c1:c2:c3:c4:c5:c6:c7")
# nonce = 32-bit constant 07:00:00:00 || 64-bit IV 40:41:42:43:44:45:46:47
AEAD_NONCE = _hex("07:00:00:00:40:41:42:43:44:45:46:47")
AEAD_ONE_TIME_KEY = _hex(
    "7b:ac:2b:25:2d:b4:47:af:09:b6:7a:55:a4:e9:55:84:0a:e1:d6:73:10:75:d9:eb:"
    "2a:93:75:78:3e:d5:53:ff"
)
AEAD_CIPHERTEXT = _hex(
    """
    d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2
    a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6
    3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b
    1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36
    92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58
    fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc
    3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b
    61 16
    """
)
AEAD_TAG = _hex("1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91")

# --- RFC 8439 appendix A.5: AEAD decryption test vector -------------------
A5_KEY = _hex(
    """
    1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0
    47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0
    """
)
A5_CIPHERTEXT = _hex(
    """
    64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd
    5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2
    4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0
    bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf
    33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81
    14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55
    97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38
    36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4
    b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9
    90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e
    af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a
    0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a
    0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e
    ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10
    49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30
    30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29
    a6 ad 5c b4 02 2b 02 70 9b
    """
)
A5_NONCE = _hex("00 00 00 00 01 02 03 04 05 06 07 08")
A5_AAD = _hex("f3 33 88 86 00 00 00 00 00 00 4e 91")
A5_TAG = _hex("ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38")
A5_PLAINTEXT = (
    "Internet-Drafts are draft documents valid for a maximum of six months "
    "and may be updated, replaced, or obsoleted by other documents at any "
    "time. It is inappropriate to use Internet-Drafts as reference material "
    "or to cite them other than as /“work in progress./”"
).encode("utf-8")


class ConstantsTests(unittest.TestCase):
    def test_sizes_match_rfc(self) -> None:
        self.assertEqual(KEY_SIZE, 32)
        self.assertEqual(NONCE_SIZE, 12)
        self.assertEqual(TAG_SIZE, 16)

    def test_authentication_error_is_value_error(self) -> None:
        self.assertTrue(issubclass(AuthenticationError, ValueError))


class ChaCha20BlockTests(unittest.TestCase):
    def test_quarter_round_rfc_2_1_1(self) -> None:
        # Internal helper, but the RFC gives a vector for it, so pin it down.
        result = aead._quarter_round(0x11111111, 0x01020304, 0x9B8D6F43, 0x01234567)
        self.assertEqual(result, (0xEA2A92F4, 0xCB1CF8CE, 0x4581472E, 0x5881C4BB))

    def test_block_function_rfc_2_3_2(self) -> None:
        self.assertEqual(len(BLOCK_OUTPUT), 64)
        self.assertEqual(chacha20_block(BLOCK_KEY, BLOCK_COUNTER, BLOCK_NONCE), BLOCK_OUTPUT)

    def test_block_function_zero_key_appendix_a1(self) -> None:
        self.assertEqual(chacha20_block(b"\x00" * 32, 0, b"\x00" * 12), ZERO_BLOCK_OUTPUT)

    def test_block_counter_changes_output(self) -> None:
        first = chacha20_block(BLOCK_KEY, 0, BLOCK_NONCE)
        second = chacha20_block(BLOCK_KEY, 1, BLOCK_NONCE)
        self.assertNotEqual(first, second)
        self.assertEqual(len(first), 64)

    def test_block_rejects_bad_sizes_and_counters(self) -> None:
        with self.assertRaises(ValueError):
            chacha20_block(b"\x00" * 31, 0, b"\x00" * 12)
        with self.assertRaises(ValueError):
            chacha20_block(b"\x00" * 33, 0, b"\x00" * 12)
        with self.assertRaises(ValueError):
            chacha20_block(b"\x00" * 32, 0, b"\x00" * 11)
        with self.assertRaises(ValueError):
            chacha20_block(b"\x00" * 32, 0, b"\x00" * 16)
        with self.assertRaises(ValueError):
            chacha20_block(b"\x00" * 32, -1, b"\x00" * 12)
        with self.assertRaises(ValueError):
            chacha20_block(b"\x00" * 32, 1 << 32, b"\x00" * 12)
        with self.assertRaises(TypeError):
            chacha20_block(b"\x00" * 32, 1.0, b"\x00" * 12)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            chacha20_block("0" * 32, 0, b"\x00" * 12)  # type: ignore[arg-type]

    def test_block_accepts_max_counter(self) -> None:
        self.assertEqual(len(chacha20_block(b"\x00" * 32, 0xFFFFFFFF, b"\x00" * 12)), 64)


class ChaCha20StreamTests(unittest.TestCase):
    def test_sunscreen_plaintext_length(self) -> None:
        self.assertEqual(len(SUNSCREEN), 114)

    def test_encrypt_rfc_2_4_2(self) -> None:
        self.assertEqual(len(ENC_CIPHERTEXT), 114)
        self.assertEqual(chacha20_encrypt(ENC_KEY, ENC_COUNTER, ENC_NONCE, SUNSCREEN), ENC_CIPHERTEXT)

    def test_decrypt_rfc_2_4_2_is_symmetric(self) -> None:
        self.assertEqual(chacha20_encrypt(ENC_KEY, ENC_COUNTER, ENC_NONCE, ENC_CIPHERTEXT), SUNSCREEN)

    def test_zero_key_appendix_a2(self) -> None:
        self.assertEqual(chacha20_encrypt(b"\x00" * 32, 0, b"\x00" * 12, b"\x00" * 64), ZERO_BLOCK_OUTPUT)

    def test_empty_data(self) -> None:
        self.assertEqual(chacha20_encrypt(ENC_KEY, 1, ENC_NONCE, b""), b"")

    def test_partial_block_matches_prefix_of_keystream(self) -> None:
        full = chacha20_encrypt(ENC_KEY, 1, ENC_NONCE, b"\x00" * 128)
        self.assertEqual(chacha20_encrypt(ENC_KEY, 1, ENC_NONCE, b"\x00" * 70), full[:70])
        self.assertEqual(full[:64], chacha20_block(ENC_KEY, 1, ENC_NONCE))
        self.assertEqual(full[64:], chacha20_block(ENC_KEY, 2, ENC_NONCE))

    def test_counter_overflow_rejected(self) -> None:
        with self.assertRaises(ValueError):
            chacha20_encrypt(ENC_KEY, 0xFFFFFFFF, ENC_NONCE, b"\x00" * 65)
        # Exactly one block at the last counter value is still fine.
        self.assertEqual(len(chacha20_encrypt(ENC_KEY, 0xFFFFFFFF, ENC_NONCE, b"\x00" * 64)), 64)


class Poly1305Tests(unittest.TestCase):
    def test_mac_rfc_2_5_2(self) -> None:
        self.assertEqual(len(POLY_MESSAGE), 34)
        self.assertEqual(poly1305_mac(POLY_KEY, POLY_MESSAGE), POLY_TAG)

    def test_mac_all_zero_key_appendix_a3_vector_1(self) -> None:
        self.assertEqual(poly1305_mac(b"\x00" * 32, b"\x00" * 64), b"\x00" * 16)

    def test_mac_with_r_zero_returns_s_appendix_a3_vector_2(self) -> None:
        # With r = 0 the polynomial evaluates to 0 and the tag is exactly s,
        # whatever the message is (Appendix A.3, test vector #2).
        s = _hex("36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e")
        self.assertEqual(poly1305_mac(b"\x00" * 16 + s, b"any message at all"), s)
        self.assertEqual(poly1305_mac(b"\x00" * 16 + s, b""), s)

    def test_mac_empty_message(self) -> None:
        # Empty message: acc stays 0, tag = s.
        self.assertEqual(poly1305_mac(POLY_KEY, b""), POLY_KEY[16:])

    def test_mac_rejects_wrong_key_size(self) -> None:
        with self.assertRaises(ValueError):
            poly1305_mac(POLY_KEY[:31], POLY_MESSAGE)
        with self.assertRaises(ValueError):
            poly1305_mac(POLY_KEY + b"\x00", POLY_MESSAGE)

    def test_key_gen_rfc_2_6_2(self) -> None:
        self.assertEqual(poly1305_key_gen(KEYGEN_KEY, KEYGEN_NONCE), KEYGEN_OUTPUT)

    def test_key_gen_zero_appendix_a4(self) -> None:
        self.assertEqual(poly1305_key_gen(b"\x00" * 32, b"\x00" * 12), ZERO_BLOCK_OUTPUT[:32])

    def test_key_gen_rfc_2_8_2_one_time_key(self) -> None:
        self.assertEqual(poly1305_key_gen(AEAD_KEY, AEAD_NONCE), AEAD_ONE_TIME_KEY)


class AeadVectorTests(unittest.TestCase):
    def test_encrypt_rfc_2_8_2(self) -> None:
        out = encrypt(AEAD_KEY, AEAD_NONCE, SUNSCREEN, AEAD_AAD)
        self.assertEqual(len(out), len(SUNSCREEN) + TAG_SIZE)
        self.assertEqual(out[:-TAG_SIZE], AEAD_CIPHERTEXT)
        self.assertEqual(out[-TAG_SIZE:], AEAD_TAG)
        self.assertEqual(out, AEAD_CIPHERTEXT + AEAD_TAG)

    def test_decrypt_rfc_2_8_2(self) -> None:
        self.assertEqual(decrypt(AEAD_KEY, AEAD_NONCE, AEAD_CIPHERTEXT + AEAD_TAG, AEAD_AAD), SUNSCREEN)

    def test_decrypt_appendix_a5(self) -> None:
        self.assertEqual(len(A5_CIPHERTEXT), 265)
        self.assertEqual(len(A5_PLAINTEXT), 265)
        self.assertEqual(decrypt(A5_KEY, A5_NONCE, A5_CIPHERTEXT + A5_TAG, A5_AAD), A5_PLAINTEXT)

    def test_encrypt_appendix_a5_reproduces_vector(self) -> None:
        self.assertEqual(encrypt(A5_KEY, A5_NONCE, A5_PLAINTEXT, A5_AAD), A5_CIPHERTEXT + A5_TAG)


class AeadTamperTests(unittest.TestCase):
    """Every modification of any AEAD input must be rejected with AuthenticationError."""

    def setUp(self) -> None:
        self.key = AEAD_KEY
        self.nonce = AEAD_NONCE
        self.aad = AEAD_AAD
        self.sealed = AEAD_CIPHERTEXT + AEAD_TAG

    def _assert_rejected(self, key: bytes, nonce: bytes, sealed: bytes, aad: bytes) -> None:
        with self.assertRaises(AuthenticationError):
            decrypt(key, nonce, sealed, aad)

    def test_ciphertext_bit_flip_rejected(self) -> None:
        for position in (0, 1, 63, 64, len(AEAD_CIPHERTEXT) - 1):
            for bit in (0, 7):
                tampered = bytearray(self.sealed)
                tampered[position] ^= 1 << bit
                self._assert_rejected(self.key, self.nonce, bytes(tampered), self.aad)

    def test_every_tag_bit_flip_rejected(self) -> None:
        for bit in range(TAG_SIZE * 8):
            tampered = bytearray(self.sealed)
            tampered[len(AEAD_CIPHERTEXT) + bit // 8] ^= 1 << (bit % 8)
            self._assert_rejected(self.key, self.nonce, bytes(tampered), self.aad)

    def test_aad_mismatch_rejected(self) -> None:
        self._assert_rejected(self.key, self.nonce, self.sealed, b"")
        self._assert_rejected(self.key, self.nonce, self.sealed, self.aad + b"\x00")
        self._assert_rejected(self.key, self.nonce, self.sealed, self.aad[:-1])
        flipped = bytearray(self.aad)
        flipped[0] ^= 0x01
        self._assert_rejected(self.key, self.nonce, self.sealed, bytes(flipped))

    def test_nonce_mismatch_rejected(self) -> None:
        other = bytearray(self.nonce)
        other[-1] ^= 0x01
        self._assert_rejected(self.key, bytes(other), self.sealed, self.aad)
        self._assert_rejected(self.key, b"\x00" * NONCE_SIZE, self.sealed, self.aad)

    def test_key_mismatch_rejected(self) -> None:
        other = bytearray(self.key)
        other[0] ^= 0x80
        self._assert_rejected(bytes(other), self.nonce, self.sealed, self.aad)
        self._assert_rejected(b"\x00" * KEY_SIZE, self.nonce, self.sealed, self.aad)

    def test_truncated_ciphertext_rejected(self) -> None:
        # Still long enough to hold a tag, but the tag no longer matches.
        self._assert_rejected(self.key, self.nonce, self.sealed[1:], self.aad)
        self._assert_rejected(self.key, self.nonce, self.sealed[:-1], self.aad)
        self._assert_rejected(self.key, self.nonce, self.sealed + b"\x00", self.aad)

    def test_input_shorter_than_tag_rejected(self) -> None:
        for length in range(TAG_SIZE):
            self._assert_rejected(self.key, self.nonce, self.sealed[:length], self.aad)
        self._assert_rejected(self.key, self.nonce, b"", self.aad)

    def test_swapped_ciphertext_and_tag_rejected(self) -> None:
        self._assert_rejected(self.key, self.nonce, AEAD_TAG + AEAD_CIPHERTEXT, self.aad)

    def test_tag_only_input_rejected_when_plaintext_was_not_empty(self) -> None:
        self._assert_rejected(self.key, self.nonce, AEAD_TAG, self.aad)


class SizeValidationTests(unittest.TestCase):
    def test_encrypt_rejects_wrong_key_size_with_plain_value_error(self) -> None:
        for bad in (b"", b"\x00" * 16, b"\x00" * 31, b"\x00" * 33, b"\x00" * 64):
            with self.assertRaises(ValueError) as ctx:
                encrypt(bad, AEAD_NONCE, b"x")
            self.assertNotIsInstance(ctx.exception, AuthenticationError)

    def test_encrypt_rejects_wrong_nonce_size_with_plain_value_error(self) -> None:
        for bad in (b"", b"\x00" * 8, b"\x00" * 11, b"\x00" * 13, b"\x00" * 16, b"\x00" * 24):
            with self.assertRaises(ValueError) as ctx:
                encrypt(AEAD_KEY, bad, b"x")
            self.assertNotIsInstance(ctx.exception, AuthenticationError)

    def test_encrypt_rejects_non_bytes(self) -> None:
        with self.assertRaises(TypeError):
            encrypt("k" * 32, AEAD_NONCE, b"x")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            encrypt(AEAD_KEY, AEAD_NONCE, "text")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            encrypt(AEAD_KEY, AEAD_NONCE, b"x", aad="aad")  # type: ignore[arg-type]

    def test_decrypt_rejects_wrong_key_size_with_authentication_error(self) -> None:
        sealed = AEAD_CIPHERTEXT + AEAD_TAG
        for bad in (b"", AEAD_KEY[:31], AEAD_KEY + b"\x00"):
            with self.assertRaises(AuthenticationError):
                decrypt(bad, AEAD_NONCE, sealed, AEAD_AAD)

    def test_decrypt_rejects_wrong_nonce_size_with_authentication_error(self) -> None:
        sealed = AEAD_CIPHERTEXT + AEAD_TAG
        for bad in (b"", AEAD_NONCE[:11], AEAD_NONCE + b"\x00", b"\x00" * 16):
            with self.assertRaises(AuthenticationError):
                decrypt(AEAD_KEY, bad, sealed, AEAD_AAD)

    def test_decrypt_rejects_non_bytes_with_authentication_error(self) -> None:
        # DESIGN.md: decrypt "raises AuthenticationError on any failure".  A
        # caller wrapping decrypt in ``except AuthenticationError`` must never
        # see a TypeError escape, whichever argument is the wrong type.
        sealed = AEAD_CIPHERTEXT + AEAD_TAG
        good = {"key": AEAD_KEY, "nonce": AEAD_NONCE, "ciphertext_and_tag": sealed, "aad": AEAD_AAD}
        non_bytes = (None, 0, 1.5, True, "text", "k" * KEY_SIZE, sealed.hex(), [], (), {}, object())
        for name in good:
            for bad in non_bytes:
                args = dict(good, **{name: bad})
                with self.subTest(argument=name, value=type(bad).__name__):
                    with self.assertRaises(AuthenticationError) as ctx:
                        decrypt(**args)  # type: ignore[arg-type]
                    # The message names the argument and its type only; it
                    # must not echo key, nonce, ciphertext or aad material.
                    message = str(ctx.exception)
                    self.assertIn(name, message)
                    self.assertIn(type(bad).__name__, message)
                    for secret in (AEAD_KEY.hex(), AEAD_NONCE.hex(), sealed.hex()):
                        self.assertNotIn(secret, message)

    def test_decrypt_rejects_released_memoryview_with_authentication_error(self) -> None:
        # Regression: ``bytes(memoryview)`` raises a plain ValueError once the
        # view has been released.  decrypt must map that conversion failure
        # to AuthenticationError like every other rejected input, whichever
        # argument the released view is passed as.
        sealed = AEAD_CIPHERTEXT + AEAD_TAG
        good = {"key": AEAD_KEY, "nonce": AEAD_NONCE, "ciphertext_and_tag": sealed, "aad": AEAD_AAD}
        for name in good:
            released = memoryview(bytes(good[name]))
            released.release()
            args = dict(good, **{name: released})
            with self.subTest(argument=name):
                with self.assertRaises(AuthenticationError) as ctx:
                    decrypt(**args)
                self.assertIsInstance(ctx.exception.__cause__, ValueError)
                message = str(ctx.exception)
                for secret in (AEAD_KEY.hex(), AEAD_NONCE.hex(), sealed.hex()):
                    self.assertNotIn(secret, message)


class RoundTripTests(unittest.TestCase):
    def test_round_trip_various_lengths_with_aad(self) -> None:
        key = secrets.token_bytes(KEY_SIZE)
        aad = b"synthetic-associated-data"
        for length in (0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 1000, 4096 + 3):
            with self.subTest(length=length):
                nonce = secrets.token_bytes(NONCE_SIZE)
                plaintext = secrets.token_bytes(length)
                sealed = encrypt(key, nonce, plaintext, aad)
                self.assertEqual(len(sealed), length + TAG_SIZE)
                self.assertEqual(decrypt(key, nonce, sealed, aad), plaintext)

    def test_round_trip_empty_plaintext(self) -> None:
        key = secrets.token_bytes(KEY_SIZE)
        nonce = secrets.token_bytes(NONCE_SIZE)
        sealed = encrypt(key, nonce, b"", b"aad")
        self.assertEqual(len(sealed), TAG_SIZE)
        self.assertEqual(decrypt(key, nonce, sealed, b"aad"), b"")

    def test_round_trip_empty_aad_default(self) -> None:
        key = secrets.token_bytes(KEY_SIZE)
        nonce = secrets.token_bytes(NONCE_SIZE)
        plaintext = b"synthetic secret value"
        sealed = encrypt(key, nonce, plaintext)
        self.assertEqual(decrypt(key, nonce, sealed), plaintext)
        self.assertEqual(decrypt(key, nonce, sealed, b""), plaintext)
        self.assertEqual(encrypt(key, nonce, plaintext, b""), sealed)

    def test_round_trip_empty_plaintext_and_empty_aad(self) -> None:
        key = secrets.token_bytes(KEY_SIZE)
        nonce = secrets.token_bytes(NONCE_SIZE)
        sealed = encrypt(key, nonce, b"")
        self.assertEqual(len(sealed), TAG_SIZE)
        self.assertEqual(decrypt(key, nonce, sealed), b"")

    def test_bytes_like_inputs_accepted(self) -> None:
        key = bytearray(secrets.token_bytes(KEY_SIZE))
        nonce = memoryview(secrets.token_bytes(NONCE_SIZE))
        plaintext = bytearray(b"bytearray plaintext")
        sealed = encrypt(key, nonce, plaintext, memoryview(b"aad"))
        self.assertIsInstance(sealed, bytes)
        self.assertEqual(decrypt(key, nonce, bytearray(sealed), bytearray(b"aad")), bytes(plaintext))

    def test_encryption_is_deterministic_and_nonce_dependent(self) -> None:
        key = secrets.token_bytes(KEY_SIZE)
        nonce_a = secrets.token_bytes(NONCE_SIZE)
        nonce_b = secrets.token_bytes(NONCE_SIZE)
        plaintext = b"same plaintext"
        self.assertEqual(encrypt(key, nonce_a, plaintext), encrypt(key, nonce_a, plaintext))
        self.assertNotEqual(encrypt(key, nonce_a, plaintext), encrypt(key, nonce_b, plaintext))

    def test_ciphertext_differs_from_plaintext(self) -> None:
        key = secrets.token_bytes(KEY_SIZE)
        nonce = secrets.token_bytes(NONCE_SIZE)
        plaintext = b"\x00" * 200
        self.assertNotEqual(encrypt(key, nonce, plaintext)[:200], plaintext)

    def test_aad_is_not_included_in_output(self) -> None:
        key = secrets.token_bytes(KEY_SIZE)
        nonce = secrets.token_bytes(NONCE_SIZE)
        aad = b"synthetic-aad-marker-that-must-not-appear"
        sealed = encrypt(key, nonce, b"hello", aad)
        self.assertEqual(len(sealed), 5 + TAG_SIZE)
        self.assertNotIn(aad, sealed)


class PerformanceTests(unittest.TestCase):
    def test_one_mebibyte_encrypts_in_reasonable_time(self) -> None:
        key = secrets.token_bytes(KEY_SIZE)
        nonce = secrets.token_bytes(NONCE_SIZE)
        plaintext = secrets.token_bytes(1024 * 1024)
        start = time.perf_counter()
        sealed = encrypt(key, nonce, plaintext, b"aad")
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 60.0, f"1 MiB encryption took {elapsed:.1f}s")
        self.assertEqual(len(sealed), len(plaintext) + TAG_SIZE)
        # Multi-block correctness on a large message, not just speed.
        self.assertEqual(decrypt(key, nonce, sealed, b"aad"), plaintext)


if __name__ == "__main__":
    unittest.main()
