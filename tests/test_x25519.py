"""X25519 against the RFC 7748 section 5.2 and 6.1 test vectors."""

from __future__ import annotations

import unittest

from zeropw.crypto import x25519
from zeropw.errors import InvalidInput


def h(text: str) -> bytes:
    return bytes.fromhex(text)


class X25519VectorsTestCase(unittest.TestCase):
    # RFC 7748 section 5.2, single-iteration test vectors.
    def test_vector_1(self) -> None:
        scalar = h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u = h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        expected = h("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        self.assertEqual(x25519.scalarmult(scalar, u), expected)

    def test_vector_2(self) -> None:
        scalar = h("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
        u = h("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
        expected = h("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
        self.assertEqual(x25519.scalarmult(scalar, u), expected)

    def test_iteration_1(self) -> None:
        k = u = h("0900000000000000000000000000000000000000000000000000000000000000"[:64])
        self.assertEqual(len(k), 32)
        result = x25519.scalarmult(k, u)
        self.assertEqual(result, h("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"))

    def test_iteration_1000(self) -> None:
        k = u = h("0900000000000000000000000000000000000000000000000000000000000000"[:64])
        for _ in range(1000):
            k, u = x25519.scalarmult(k, u), k
        self.assertEqual(k, h("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"))

    # The RFC's 1,000,000-iteration vector is skipped: pure-Python big-int
    # arithmetic makes it too slow for a unit test (the 1 and 1,000 iteration
    # vectors above already exercise the same ladder code).

    def test_diffie_hellman_6_1(self) -> None:
        alice_private = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        bob_private = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        alice_public = x25519.public_key(alice_private)
        bob_public = x25519.public_key(bob_private)
        self.assertEqual(alice_public, h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
        self.assertEqual(bob_public, h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
        shared_alice = x25519.scalarmult(alice_private, bob_public)
        shared_bob = x25519.scalarmult(bob_private, alice_public)
        self.assertEqual(shared_alice, shared_bob)
        self.assertEqual(shared_alice, h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"))

    def test_generate_private_is_clamped_and_usable(self) -> None:
        priv = x25519.generate_private()
        self.assertEqual(len(priv), 32)
        self.assertEqual(priv[0] & 0x07, 0)
        self.assertEqual(priv[31] & 0x80, 0)
        self.assertEqual(priv[31] & 0x40, 0x40)
        pub = x25519.public_key(priv)
        self.assertEqual(len(pub), 32)

    def test_shared_secret_matches_both_directions(self) -> None:
        a = x25519.generate_private()
        b = x25519.generate_private()
        pa, pb = x25519.public_key(a), x25519.public_key(b)
        self.assertEqual(x25519.scalarmult(a, pb), x25519.scalarmult(b, pa))

    def test_shared_secret_refuses_all_zero_low_order_point(self) -> None:
        """F5: the all-zero u-coordinate is a small-order point (fixed by the curve equation,
        independent of the scalar) -- shared_secret must refuse it rather than return the all-zero
        "secret" every peer using it would derive too.  scalarmult itself stays a bare primitive.
        """
        priv = x25519.generate_private()
        self.assertEqual(x25519.scalarmult(priv, b"\x00" * 32), b"\x00" * 32)
        with self.assertRaises(InvalidInput) as ctx:
            x25519.shared_secret(priv, b"\x00" * 32)
        self.assertEqual(ctx.exception.reason, "x25519_low_order_point")

    def test_shared_secret_normal_case_matches_scalarmult(self) -> None:
        a, b = x25519.generate_private(), x25519.generate_private()
        expected = x25519.scalarmult(a, x25519.public_key(b))
        self.assertEqual(x25519.shared_secret(a, x25519.public_key(b)), expected)

    def test_wrong_size_inputs_rejected(self) -> None:
        with self.assertRaises(ValueError):
            x25519.scalarmult(b"short", b"\x00" * 32)
        with self.assertRaises(ValueError):
            x25519.scalarmult(b"\x00" * 32, b"short")
        with self.assertRaises(TypeError):
            x25519.scalarmult("not-bytes", b"\x00" * 32)


if __name__ == "__main__":
    unittest.main()
