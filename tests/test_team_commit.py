"""Commit model: signing/verification, HLC, format validation, sequence store, deferral."""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from zeropw.errors import InvalidInput
from zeropw.store import StateDir
from zeropw.team import commit as C
from zeropw.team.identity import DeviceKey

ENV_ID = "env-0123456789abcdef"  # used only where env.init / receive_commit's owner binding is not exercised


def env_init_op(owner: DeviceKey, name: str = "alice-laptop", generation_id: str = "0" * 16) -> dict:
    wraps = {owner.fingerprint: {"eph_pub": "AAAA", "nonce": "AAAA", "ciphertext": "AAAA"}}
    return {"op": "env.init", "owner_device": owner.record.to_dict(), "owner_name": name,
            "generation_id": generation_id, "wraps": wraps}


def connection_create_op(conn_id: str = "gh") -> dict:
    return {"op": "connection.create", "id": conn_id, "project": "demo", "environment": "dev",
            "service": "github", "kind": "http", "secret_id": "gh-token", "secret_version": None,
            "description": "", "http_target": {"scheme": "https", "host": "api.github.com", "port": 443},
            "http_auth": {"mode": "bearer"}, "http_scope": {"methods": ["GET"], "path_prefixes": ["/repos"]}}


class HlcTestCase(unittest.TestCase):
    def test_tick_advances_and_zeroes_counter_on_wall_advance(self) -> None:
        hlc = C.Hlc()
        first = hlc.tick(1000)
        second = hlc.tick(2000)
        self.assertEqual(first, "1000-0000")
        self.assertEqual(second, "2000-0000")

    def test_tick_increments_counter_when_wall_does_not_advance(self) -> None:
        hlc = C.Hlc()
        hlc.tick(1000)
        second = hlc.tick(1000)
        third = hlc.tick(500)  # behind: still increments off the retained wall value
        self.assertEqual(second, "1000-0001")
        self.assertEqual(third, "1000-0002")

    def test_observe_raises_clock_and_causal_tick_sorts_after(self) -> None:
        hlc = C.Hlc()
        remote = "5000-0003"
        hlc.observe(remote)
        nxt = hlc.tick(1000)  # local wall behind remote
        self.assertEqual(C.Hlc.parse(nxt), (5000, 4))
        self.assertGreater(C.Hlc.parse(nxt), C.Hlc.parse(remote))

    def test_observe_tie_takes_max_counter(self) -> None:
        hlc = C.Hlc(wall_ms=5000, counter=1)
        hlc.observe("5000-0007")
        self.assertEqual(hlc.counter, 7)

    def test_parse_rejects_malformed(self) -> None:
        with self.assertRaises(InvalidInput):
            C.Hlc.parse("not-an-hlc")
        with self.assertRaises(InvalidInput):
            C.Hlc.parse("1000")

    def test_total_order_numeric_not_lexicographic(self) -> None:
        # "999-..." must sort before "1000-..." numerically, even though the
        # opposite holds under plain string comparison.
        low = C.Hlc.parse("999-0000")
        high = C.Hlc.parse("1000-0000")
        self.assertLess(low, high)


class SignAndVerifyTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.owner = DeviceKey.generate()

    def test_sign_then_verify(self) -> None:
        c1 = C.sign_commit(self.owner, ENV_ID, 1, "1000-0000", {}, [env_init_op(self.owner)])
        self.assertTrue(C.verify_commit(c1, self.owner.record))

    def test_tampered_op_fails_verification(self) -> None:
        c1 = C.sign_commit(self.owner, ENV_ID, 1, "1000-0000", {}, [env_init_op(self.owner)])
        tampered_ops = (dict(c1.ops[0], owner_name="mallory"),)
        tampered = replace(c1, ops=tampered_ops)
        self.assertFalse(C.verify_commit(tampered, self.owner.record))

    def test_wrong_signer_fails_verification(self) -> None:
        c1 = C.sign_commit(self.owner, ENV_ID, 1, "1000-0000", {}, [env_init_op(self.owner)])
        other = DeviceKey.generate()
        self.assertFalse(C.verify_commit(c1, other.record))

    def test_hash_changes_with_sig(self) -> None:
        c1 = C.sign_commit(self.owner, ENV_ID, 1, "1000-0000", {}, [env_init_op(self.owner)])
        c2 = replace(c1, sig="")
        self.assertNotEqual(c1.hash, c2.hash)

    def test_malformed_ops_refused_at_sign_time(self) -> None:
        with self.assertRaises(InvalidInput):
            C.sign_commit(self.owner, ENV_ID, 1, "1000-0000", {}, [{"op": "no.such.op"}])
        with self.assertRaises(InvalidInput):
            C.sign_commit(self.owner, ENV_ID, 1, "1000-0000", {}, [])

    def test_to_dict_from_dict_roundtrip(self) -> None:
        c1 = C.sign_commit(self.owner, ENV_ID, 1, "1000-0000", {}, [connection_create_op()])
        restored = C.Commit.from_dict(c1.to_dict())
        self.assertEqual(restored.hash, c1.hash)
        self.assertTrue(C.verify_commit(restored, self.owner.record))


class OpValidationTestCase(unittest.TestCase):
    def test_connection_create_accepts_valid_shape(self) -> None:
        C.validate_op(connection_create_op())

    def test_connection_create_rejects_bad_host(self) -> None:
        op = connection_create_op()
        op["http_target"]["host"] = "not a host!!"
        with self.assertRaises(InvalidInput):
            C.validate_op(op)

    def test_connection_update_rejects_unknown_field(self) -> None:
        with self.assertRaises(InvalidInput):
            C.validate_op({"op": "connection.update", "id": "gh", "status": "disabled"})

    def test_connection_update_requires_a_field(self) -> None:
        with self.assertRaises(InvalidInput):
            C.validate_op({"op": "connection.update", "id": "gh"})

    def test_secret_put_version_shape(self) -> None:
        op = {"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
              "generation_id": "0" * 16, "version_id": "1" * 16,
              "ciphertext": {"nonce": "AAAA", "ciphertext": "BBBB"}, "public": {}}
        C.validate_op(op)
        bad = dict(op, version_id="not-hex")
        with self.assertRaises(InvalidInput):
            C.validate_op(bad)

    def test_member_add_shape(self) -> None:
        device = DeviceKey.generate()
        op = {"op": "member.add", "device": device.record.to_dict(), "name": "bob", "role": "user"}
        C.validate_op(op)
        with self.assertRaises(InvalidInput):
            C.validate_op({**op, "role": "superadmin"})

    def test_unknown_op_rejected(self) -> None:
        with self.assertRaises(InvalidInput):
            C.validate_op({"op": "delete.everything"})

    def test_non_dict_op_rejected(self) -> None:
        with self.assertRaises(InvalidInput):
            C.validate_op("connection.create")

    def test_dek_rotate_shape(self) -> None:
        fp = DeviceKey.generate().fingerprint
        op = {"op": "dek.rotate", "generation_id": "a" * 16,
              "wraps": {fp: {"eph_pub": "AA", "nonce": "AA", "ciphertext": "AA"}}}
        C.validate_op(op)
        with self.assertRaises(InvalidInput):
            C.validate_op({"op": "dek.rotate", "generation_id": "a" * 16, "wraps": {}})


class CommitStoreTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state = StateDir(Path(self.tmp.name) / "state")
        self.state.create()
        self.owner = DeviceKey.generate()
        self.env_id = C.new_env_id(self.owner.fingerprint)
        self.store = C.CommitStore(self.state, self.env_id)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _bootstrap(self) -> C.Commit:
        c1 = C.sign_commit(self.owner, self.env_id, 1, C.Hlc().tick(1_000_000), {}, [env_init_op(self.owner)])
        self.assertEqual(C.receive_commit(self.store, c1, 1_000_000), "accepted")
        return c1

    def test_append_enforces_contiguous_sequence(self) -> None:
        c1 = self._bootstrap()
        with self.assertRaises(InvalidInput):
            self.store.append(c1)  # duplicate
        gap = C.sign_commit(self.owner, self.env_id, 3, C.Hlc().tick(1_000_100), {}, [connection_create_op()])
        with self.assertRaises(InvalidInput):
            self.store.append(gap)  # gap: seq 2 missing

    def test_vector_and_all_commits(self) -> None:
        self._bootstrap()
        c2 = C.sign_commit(self.owner, self.env_id, 2, C.Hlc().tick(1_000_100), self.store.vector(),
                           [connection_create_op()])
        self.store.append(c2)
        self.assertEqual(self.store.vector(), {self.owner.fingerprint: 2})
        self.assertEqual([c.author_seq for c in self.store.all_commits()], [1, 2])

    def test_receive_commit_rejects_env_id_mismatch(self) -> None:
        self._bootstrap()
        other_env = C.sign_commit(self.owner, "different-env", 2, C.Hlc().tick(2_000_000), {},
                                  [connection_create_op()])
        self.assertEqual(C.receive_commit(self.store, other_env, 2_000_000), "rejected")

    def test_receive_commit_rejects_unknown_author(self) -> None:
        stranger = DeviceKey.generate()
        c1 = C.sign_commit(stranger, self.env_id, 1, C.Hlc().tick(1_000_000), {}, [connection_create_op()])
        self.assertEqual(C.receive_commit(self.store, c1, 1_000_000), "rejected")

    def test_receive_commit_rejects_bad_signature(self) -> None:
        c1 = C.sign_commit(self.owner, self.env_id, 1, C.Hlc().tick(1_000_000), {}, [env_init_op(self.owner)])
        forged = replace(c1, sig=C.base64.b64encode(b"\x00" * 64).decode())
        self.assertEqual(C.receive_commit(self.store, forged, 1_000_000), "rejected")

    def test_receive_commit_rejects_replayed_seq_after_bootstrap(self) -> None:
        self._bootstrap()
        replay = C.sign_commit(self.owner, self.env_id, 1, C.Hlc().tick(2_000_000), {}, [env_init_op(self.owner)])
        self.assertEqual(C.receive_commit(self.store, replay, 2_000_000), "rejected")

    def test_clock_skew_defers_then_releases(self) -> None:
        self._bootstrap()
        far_future_ms = 1_000_000 + C.MAX_CLOCK_SKEW_MS + 60_000
        skewed = C.sign_commit(self.owner, self.env_id, 2, C.Hlc().tick(far_future_ms), self.store.vector(),
                               [connection_create_op()])
        result = C.receive_commit(self.store, skewed, 1_000_000)
        self.assertEqual(result, "deferred")
        self.assertEqual(self.store.vector(), {self.owner.fingerprint: 1})
        # Not yet due: releasing at the original time changes nothing.
        self.assertEqual(self.store.release_deferred(1_000_000), [])
        released = self.store.release_deferred(far_future_ms)
        self.assertEqual([c.hash for c in released], [skewed.hash])
        self.assertEqual(self.store.vector(), {self.owner.fingerprint: 2})

    def test_second_bootstrap_from_same_author_rejected_by_sequence(self) -> None:
        self._bootstrap()
        again = C.sign_commit(self.owner, self.env_id, 1, C.Hlc().tick(3_000_000), {}, [env_init_op(self.owner)])
        self.assertEqual(C.receive_commit(self.store, again, 3_000_000), "rejected")

    # ---- F2: environment ownership hijack -------------------------------------------------
    def test_forged_early_bootstrap_from_non_owner_rejected(self) -> None:
        """A member other than the fingerprint the env id names cannot become owner by racing hlc=0."""
        forger = DeviceKey.generate()
        forged = C.sign_commit(forger, self.env_id, 1, "0-0000", {}, [env_init_op(forger)])
        self.assertEqual(C.receive_commit(self.store, forged, 1_000_000), "rejected")
        self.assertEqual(self.store.vector(), {})
        # The real owner's genesis still works afterwards.
        self._bootstrap()
        self.assertEqual(self.store.vector(), {self.owner.fingerprint: 1})

    def test_non_monotone_hlc_rejected(self) -> None:
        self._bootstrap()
        c2 = C.sign_commit(self.owner, self.env_id, 2, C.Hlc().tick(1_000_100), {}, [connection_create_op()])
        self.assertEqual(C.receive_commit(self.store, c2, 1_000_100), "accepted")
        non_monotone = C.sign_commit(self.owner, self.env_id, 3, "1000100-0000",  # same hlc as c2, not greater
                                     {}, [connection_create_op("gitlab")])
        self.assertEqual(C.receive_commit(self.store, non_monotone, 1_000_100), "rejected")
        self.assertEqual(self.store.vector(), {self.owner.fingerprint: 2})

    # ---- F4: duplicate vs equivocation -----------------------------------------------------
    def test_exact_duplicate_is_silently_accepted_as_duplicate(self) -> None:
        c1 = self._bootstrap()
        self.assertEqual(C.receive_commit(self.store, c1, 1_000_000), "duplicate")
        rejected_dir = self.state.path / self.store.root / "rejected"
        self.assertFalse(rejected_dir.exists() and any(rejected_dir.iterdir()))

    def test_conflicting_commit_at_same_slot_is_equivocation(self) -> None:
        self._bootstrap()
        c2 = C.sign_commit(self.owner, self.env_id, 2, C.Hlc().tick(1_000_100), {}, [connection_create_op("gh")])
        self.assertEqual(C.receive_commit(self.store, c2, 1_000_100), "accepted")
        conflicting = C.sign_commit(self.owner, self.env_id, 2, C.Hlc().tick(1_000_200), {},
                                    [connection_create_op("gitlab")])
        self.assertEqual(C.receive_commit(self.store, conflicting, 1_000_200), "rejected")
        rejected_dir = self.state.path / self.store.root / "rejected"
        self.assertTrue(any("team_author_equivocation" in p.read_text() for p in rejected_dir.glob("*.json")))


if __name__ == "__main__":
    unittest.main()
