"""DEK generation wrapping and per-secret encryption (docs/team-sync.md section 4.2)."""

from __future__ import annotations

import unittest

from zeropw.errors import InvalidInput
from zeropw.team import envelope
from zeropw.team.identity import DeviceKey, DeviceRecord

ENV_ID = "0123456789abcdef0123456789abcdef"
GENERATION_ID = "deadbeefcafef00d"
SECRET_ID = "gh-token"
VERSION_ID = "abc123ef00112233"
SYNTHETIC = b"synthetic-secret-value-0123456789"


class HkdfTestCase(unittest.TestCase):
    def test_rfc5869_case_1(self) -> None:
        # RFC 5869 appendix A.1 (HKDF-SHA256 test case 1).
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        okm = envelope.hkdf(salt, ikm, info, 42)
        expected = bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )
        self.assertEqual(okm, expected)


class DekWrapTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.dek = bytes(range(32))
        self.device = DeviceKey.generate()
        self.other_device = DeviceKey.generate()

    def test_wrap_unwrap_roundtrip(self) -> None:
        wrap = envelope.wrap_dek(self.dek, ENV_ID, GENERATION_ID, self.device.record)
        self.assertNotIn(self.dek.hex(), str(wrap))
        recovered = envelope.unwrap_dek(wrap, ENV_ID, GENERATION_ID, self.device)
        self.assertEqual(recovered, self.dek)

    def test_wrong_device_cannot_unwrap(self) -> None:
        wrap = envelope.wrap_dek(self.dek, ENV_ID, GENERATION_ID, self.device.record)
        with self.assertRaises(InvalidInput):
            envelope.unwrap_dek(wrap, ENV_ID, GENERATION_ID, self.other_device)

    def test_wrong_env_or_generation_id_fails(self) -> None:
        wrap = envelope.wrap_dek(self.dek, ENV_ID, GENERATION_ID, self.device.record)
        with self.assertRaises(InvalidInput):
            envelope.unwrap_dek(wrap, "other-env-id", GENERATION_ID, self.device)
        with self.assertRaises(InvalidInput):
            envelope.unwrap_dek(wrap, ENV_ID, "other-generation", self.device)

    def test_two_wraps_use_independent_ephemeral_keys(self) -> None:
        wrap_a = envelope.wrap_dek(self.dek, ENV_ID, GENERATION_ID, self.device.record)
        wrap_b = envelope.wrap_dek(self.dek, ENV_ID, GENERATION_ID, self.device.record)
        self.assertNotEqual(wrap_a["eph_pub"], wrap_b["eph_pub"])
        self.assertNotEqual(wrap_a["ciphertext"], wrap_b["ciphertext"])

    def test_malformed_wrap_rejected(self) -> None:
        with self.assertRaises(InvalidInput):
            envelope.unwrap_dek({"eph_pub": "!!!", "nonce": "AAAA", "ciphertext": "AAAA"}, ENV_ID, GENERATION_ID,
                                self.device)

    def test_invalid_dek_size_rejected(self) -> None:
        with self.assertRaises(InvalidInput):
            envelope.wrap_dek(b"too-short", ENV_ID, GENERATION_ID, self.device.record)

    def test_wrap_refuses_low_order_recipient_point(self) -> None:
        """F5: an all-zero agreement key is a low-order (small-order) X25519 point -- contributes
        no secrecy at all, so wrapping for such a "recipient" must be refused outright rather than
        silently produce a DEK wrap anyone who sees the ciphertext could also derive the key for.
        """
        low_order_record = DeviceRecord(self.device.record.sign_pub, b"\x00" * 32, self.device.record.sig)
        with self.assertRaises(InvalidInput) as ctx:
            envelope.wrap_dek(self.dek, ENV_ID, GENERATION_ID, low_order_record)
        self.assertEqual(ctx.exception.reason, "x25519_low_order_point")

    def test_unwrap_refuses_low_order_ephemeral_point(self) -> None:
        """The same check on the receiving side: an attacker-supplied wrap with an all-zero
        ephemeral public key must not be processed as if it carried real entropy.
        """
        forged_wrap = {"eph_pub": envelope._b64e(b"\x00" * 32), "nonce": envelope._b64e(b"\x00" * 12),
                       "ciphertext": envelope._b64e(b"\x00" * 48)}
        with self.assertRaises(InvalidInput) as ctx:
            envelope.unwrap_dek(forged_wrap, ENV_ID, GENERATION_ID, self.device)
        self.assertEqual(ctx.exception.reason, "x25519_low_order_point")


class SecretEncryptionTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.dek = bytes(range(1, 33))

    def test_roundtrip(self) -> None:
        entry = envelope.encrypt_secret(self.dek, ENV_ID, SECRET_ID, VERSION_ID, SYNTHETIC)
        self.assertNotIn(SYNTHETIC.decode(), str(entry))
        recovered = envelope.decrypt_secret(self.dek, ENV_ID, SECRET_ID, VERSION_ID, entry)
        self.assertEqual(recovered, SYNTHETIC)

    def test_wrong_version_id_fails_aad_check(self) -> None:
        entry = envelope.encrypt_secret(self.dek, ENV_ID, SECRET_ID, VERSION_ID, SYNTHETIC)
        with self.assertRaises(InvalidInput):
            envelope.decrypt_secret(self.dek, ENV_ID, SECRET_ID, "other-version", entry)

    def test_wrong_secret_id_fails_aad_check(self) -> None:
        entry = envelope.encrypt_secret(self.dek, ENV_ID, SECRET_ID, VERSION_ID, SYNTHETIC)
        with self.assertRaises(InvalidInput):
            envelope.decrypt_secret(self.dek, ENV_ID, "other-secret", VERSION_ID, entry)

    def test_wrong_key_fails(self) -> None:
        entry = envelope.encrypt_secret(self.dek, ENV_ID, SECRET_ID, VERSION_ID, SYNTHETIC)
        other_dek = bytes(range(32, 0, -1))
        with self.assertRaises(InvalidInput):
            envelope.decrypt_secret(other_dek, ENV_ID, SECRET_ID, VERSION_ID, entry)


if __name__ == "__main__":
    unittest.main()
