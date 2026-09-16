"""Device identity: key generation, persistence via the local KMS, fingerprints, record signature."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from zeropw.errors import InvalidInput, StateError
from zeropw.kms import LocalFileKms
from zeropw.store import StateDir
from zeropw.team.identity import DeviceKey, DeviceRecord


class DeviceKeyTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = StateDir(self.root / "state")
        self.state.create()
        self.kms = LocalFileKms.create(self.root / "state" / "kms" / "master.key")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_generate_and_record_roundtrip(self) -> None:
        device = DeviceKey.generate()
        record = device.record
        self.assertTrue(record.verify())
        self.assertEqual(record.fingerprint, device.fingerprint)
        self.assertTrue(record.fingerprint.islower())
        self.assertTrue(all(c in "abcdefghijklmnopqrstuvwxyz234567" for c in record.fingerprint))

    def test_record_roundtrips_through_dict(self) -> None:
        device = DeviceKey.generate()
        record = device.record
        restored = DeviceRecord.from_dict(record.to_dict())
        self.assertEqual(restored, record)
        self.assertTrue(restored.verify())

    def test_tampered_agree_pub_fails_verification(self) -> None:
        device = DeviceKey.generate()
        record = device.record
        other_agree = DeviceKey.generate().record.agree_pub
        forged = DeviceRecord(record.sign_pub, other_agree, record.sig)
        self.assertFalse(forged.verify())

    def test_malformed_record_dict_rejected(self) -> None:
        with self.assertRaises(InvalidInput):
            DeviceRecord.from_dict({"sign_pub": "not-base64!!", "agree_pub": "x", "sig": "y"})
        with self.assertRaises(InvalidInput):
            DeviceRecord.from_dict({"sign_pub": "AAAA", "agree_pub": "AAAA", "sig": "AAAA"})

    def test_create_persists_wrapped_and_no_export(self) -> None:
        device = DeviceKey.create(self.state, self.kms)
        raw = (self.state.path / "team" / "device.key").read_text()
        self.assertNotIn(device.sign_seed.hex(), raw)
        self.assertNotIn(device.agree_private.hex(), raw)
        loaded = DeviceKey.load(self.state, self.kms)
        self.assertEqual(loaded.sign_seed, device.sign_seed)
        self.assertEqual(loaded.agree_private, device.agree_private)
        self.assertEqual(loaded.fingerprint, device.fingerprint)
        # No public API returns the raw private key material by name.
        self.assertFalse(hasattr(DeviceKey, "export"))
        self.assertFalse(hasattr(DeviceKey, "export_private"))

    def test_create_refuses_when_already_exists(self) -> None:
        DeviceKey.create(self.state, self.kms)
        with self.assertRaises(StateError):
            DeviceKey.create(self.state, self.kms)

    def test_load_missing_raises(self) -> None:
        with self.assertRaises(StateError):
            DeviceKey.load(self.state, self.kms)

    def test_load_or_create_is_idempotent(self) -> None:
        first = DeviceKey.load_or_create(self.state, self.kms)
        second = DeviceKey.load_or_create(self.state, self.kms)
        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_sign_produces_verifiable_signature(self) -> None:
        device = DeviceKey.generate()
        from zeropw.crypto import ed25519

        message = b"zeropw-team-test-message"
        sig = device.sign(message)
        self.assertTrue(ed25519.verify(device.record.sign_pub, message, sig))


if __name__ == "__main__":
    unittest.main()
