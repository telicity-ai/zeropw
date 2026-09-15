"""Deterministic fold, facts, derivation into local policy/vault state (docs/team-sync.md sections 7, 6.5)."""

from __future__ import annotations

import itertools
import json
import random
import secrets
import tempfile
import unittest
from pathlib import Path

from zeropw import policy as P
from zeropw.context import Config, Context
from zeropw.errors import NotFound
from zeropw.store import StateDir
from zeropw.team import commit as C
from zeropw.team import envelope
from zeropw.team import fold as F
from zeropw.team.identity import DeviceKey
from tests.leakcheck import find_secret, find_secret_in_tree

GEN0 = "0" * 16
SYNTHETIC_SECRET = b"synthetic-shared-secret-0123456789"
BOOTSTRAP_SECRET_VALUE = b"synthetic-bootstrap-placeholder-secret"


def env_init_commit(env_id: str, owner: DeviceKey, dek: bytes, hlc: str = "1000-0000", name: str = "alice",
                    bootstrap_secret_id: str | None = "gh-token") -> C.Commit:
    """The genesis commit: owner + first DEK generation, plus (by default) a staged, never-activated
    version of ``bootstrap_secret_id`` -- most tests below wire a connection to "gh-token" and, since
    F3, ``connection.create`` requires that secret to already exist in the document.  Pass
    ``bootstrap_secret_id=None`` for tests that want to control the secret's existence themselves.
    """
    wraps = {owner.fingerprint: envelope.wrap_dek(dek, env_id, GEN0, owner.record)}
    op_init = {"op": "env.init", "owner_device": owner.record.to_dict(), "owner_name": name,
               "generation_id": GEN0, "wraps": wraps}
    ops = [op_init]
    if bootstrap_secret_id:
        version_id = secrets.token_hex(8)
        ct = envelope.encrypt_secret(dek, env_id, bootstrap_secret_id, version_id, BOOTSTRAP_SECRET_VALUE)
        ops.append({"op": "secret.put_version", "secret_id": bootstrap_secret_id, "kind": "api_key",
                    "generation_id": GEN0, "version_id": version_id, "ciphertext": ct, "public": {}})
    return C.sign_commit(owner, env_id, 1, hlc, {}, ops)


def connection_create_commit(env_id: str, author: DeviceKey, seq: int, hlc: str, conn_id: str = "gh",
                             methods=("GET",), paths=("/repos",), secret_id: str = "gh-token") -> C.Commit:
    scope = {"methods": list(methods) if methods is not None else None,
             "path_prefixes": list(paths) if paths is not None else None}
    op = {"op": "connection.create", "id": conn_id, "project": "demo", "environment": "dev",
          "service": "github", "kind": "http", "secret_id": secret_id, "secret_version": None,
          "description": "", "http_target": {"scheme": "https", "host": "api.github.com", "port": 443},
          "http_auth": {"mode": "bearer"}, "http_scope": scope}
    return C.sign_commit(author, env_id, seq, hlc, {}, [op])


def member_add_commit(env_id: str, author: DeviceKey, seq: int, hlc: str, new_device: DeviceKey, role: str,
                      name: str = "bob") -> C.Commit:
    op = {"op": "member.add", "device": new_device.record.to_dict(), "name": name, "role": role}
    return C.sign_commit(author, env_id, seq, hlc, {}, [op])


class BasicFoldTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.owner = DeviceKey.generate()
        self.env_id = C.new_env_id(self.owner.fingerprint)
        self.dek = bytes(range(32))
        self.c1 = env_init_commit(self.env_id, self.owner, self.dek)

    def test_env_init_sets_owner_and_generation(self) -> None:
        result = F.fold(self.env_id, [self.c1])
        doc = result.document
        self.assertEqual(doc["owner"], self.owner.fingerprint)
        self.assertEqual(doc["members"][self.owner.fingerprint]["role"], "admin")
        self.assertEqual(doc["dek"]["current"], GEN0)
        self.assertEqual(result.skipped, [])

    def test_connection_create_by_admin_applies(self) -> None:
        c2 = connection_create_commit(self.env_id, self.owner, 2, "2000-0000")
        result = F.fold(self.env_id, [self.c1, c2])
        self.assertIn("gh", result.document["connections"])
        self.assertEqual(result.skipped, [])

    def test_env_init_only_valid_as_first_commit(self) -> None:
        # A second env.init from the same author, later, must not re-bootstrap.
        c2 = connection_create_commit(self.env_id, self.owner, 2, "2000-0000")
        result = F.fold(self.env_id, [self.c1, c2])
        forged_init = C.sign_commit(self.owner, self.env_id, 3, "3000-0000", {},
                                    [{"op": "env.init", "owner_device": self.owner.record.to_dict(),
                                      "owner_name": "mallory", "generation_id": "1" * 16,
                                      "wraps": {self.owner.fingerprint: {"eph_pub": "AA", "nonce": "AA",
                                                                        "ciphertext": "AA"}}}])
        result2 = F.fold(self.env_id, [self.c1, c2, forged_init])
        self.assertEqual(result2.document["dek"]["current"], GEN0)
        reasons = [reason for _, _, reason in result2.skipped]
        self.assertIn("env_already_initialized", reasons)

    def test_env_init_from_wrong_owner_skipped(self) -> None:
        """F2: env.init only ever binds to the fingerprint the env id itself names."""
        forger = DeviceKey.generate()
        forged = C.sign_commit(forger, self.env_id, 1, "0-0000", {},
                               [{"op": "env.init", "owner_device": forger.record.to_dict(),
                                 "owner_name": "mallory", "generation_id": GEN0,
                                 "wraps": {forger.fingerprint: {"eph_pub": "AA", "nonce": "AA",
                                                                "ciphertext": "AA"}}}])
        # Fold both commits together (out of band -- this is what a fold would see if the forged
        # commit somehow reached the store despite receive_commit's own rejection of it).
        result = F.fold(self.env_id, [forged, self.c1])
        self.assertEqual(result.document["owner"], self.owner.fingerprint)
        reasons = [reason for _, _, reason in result.skipped]
        self.assertIn("env_init_wrong_owner", reasons)


class RoleBasedOpsTestCase(unittest.TestCase):
    """Role-based accept/skip for every commit-issuing op (docs/team-sync.md section 5.3)."""

    def setUp(self) -> None:
        self.owner = DeviceKey.generate()
        self.env_id = C.new_env_id(self.owner.fingerprint)
        self.dek = bytes(range(32))
        self.user_device = DeviceKey.generate()
        self.c1 = env_init_commit(self.env_id, self.owner, self.dek)
        self.c2 = member_add_commit(self.env_id, self.owner, 2, "2000-0000", self.user_device, "user")

    def _fold(self, extra):
        return F.fold(self.env_id, [self.c1, self.c2, *extra])

    def test_user_cannot_create_connection(self) -> None:
        bad = connection_create_commit(self.env_id, self.user_device, 1, "3000-0000")
        result = self._fold([bad])
        self.assertNotIn("gh", result.document["connections"])
        self.assertIn(("not_admin"), [r for _, _, r in result.skipped])

    def test_admin_can_create_connection(self) -> None:
        good = connection_create_commit(self.env_id, self.owner, 3, "3000-0000")
        result = self._fold([good])
        self.assertIn("gh", result.document["connections"])

    def test_user_cannot_add_member(self) -> None:
        third = DeviceKey.generate()
        bad = member_add_commit(self.env_id, self.user_device, 1, "3000-0000", third, "user")
        result = self._fold([bad])
        self.assertNotIn(third.fingerprint, result.document["members"])

    def test_user_can_remove_self(self) -> None:
        self_remove = C.sign_commit(self.user_device, self.env_id, 1, "3000-0000", {},
                                    [{"op": "member.remove", "fingerprint": self.user_device.fingerprint}])
        result = self._fold([self_remove])
        self.assertEqual(result.document["members"][self.user_device.fingerprint]["status"], "removed")

    def test_owner_cannot_be_removed_by_admin(self) -> None:
        admin_device = DeviceKey.generate()
        add_admin = member_add_commit(self.env_id, self.owner, 3, "3000-0000", admin_device, "admin")
        remove_owner = C.sign_commit(admin_device, self.env_id, 1, "4000-0000", {},
                                     [{"op": "member.remove", "fingerprint": self.owner.fingerprint}])
        result = self._fold([add_admin, remove_owner])
        self.assertEqual(result.document["members"][self.owner.fingerprint]["status"], "active")
        self.assertIn("cannot_remove_owner", [r for _, _, r in result.skipped])

    def test_owner_transfer_only_by_owner(self) -> None:
        admin_device = DeviceKey.generate()
        add_admin = member_add_commit(self.env_id, self.owner, 3, "3000-0000", admin_device, "admin")
        bad_transfer = C.sign_commit(admin_device, self.env_id, 1, "4000-0000", {},
                                     [{"op": "owner.transfer", "fingerprint": admin_device.fingerprint}])
        result = self._fold([add_admin, bad_transfer])
        self.assertEqual(result.document["owner"], self.owner.fingerprint)
        good_transfer = C.sign_commit(self.owner, self.env_id, 3, "4000-0000", {},
                                      [{"op": "owner.transfer", "fingerprint": admin_device.fingerprint}])
        result2 = F.fold(self.env_id, [self.c1, self.c2, add_admin, good_transfer])
        self.assertEqual(result2.document["owner"], admin_device.fingerprint)


class SignatureSeqEnvMismatchTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.owner = DeviceKey.generate()
        self.env_id = C.new_env_id(self.owner.fingerprint)
        self.dek = bytes(range(32))
        self.tmp = tempfile.TemporaryDirectory()
        self.state_path = Path(self.tmp.name) / "state"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _store(self):
        state = StateDir(self.state_path)
        state.create()
        return C.CommitStore(state, self.env_id)

    def test_signature_mismatch_rejected(self) -> None:
        store = self._store()
        c1 = env_init_commit(self.env_id, self.owner, self.dek)
        self.assertEqual(C.receive_commit(store, c1, C.now_ms()), "accepted")
        stranger = DeviceKey.generate()
        forged = connection_create_commit(self.env_id, stranger, 2, "2000-0000")
        self.assertEqual(C.receive_commit(store, forged, C.now_ms()), "rejected")

    def test_seq_gap_rejected(self) -> None:
        store = self._store()
        c1 = env_init_commit(self.env_id, self.owner, self.dek)
        self.assertEqual(C.receive_commit(store, c1, C.now_ms()), "accepted")
        skip_ahead = connection_create_commit(self.env_id, self.owner, 5, "2000-0000")
        self.assertEqual(C.receive_commit(store, skip_ahead, C.now_ms()), "rejected")

    def test_env_id_mismatch_rejected(self) -> None:
        store = self._store()
        c1 = env_init_commit(self.env_id, self.owner, self.dek)
        self.assertEqual(C.receive_commit(store, c1, C.now_ms()), "accepted")
        other = C.sign_commit(self.owner, "some-other-env", 2, "2000-0000", {},
                              [{"op": "connection.disable", "id": "gh"}])
        self.assertEqual(C.receive_commit(store, other, C.now_ms()), "rejected")


class ClockSkewTestCase(unittest.TestCase):
    def test_far_future_commit_deferred_then_released(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        state = StateDir(Path(tmp.name) / "state")
        state.create()
        owner = DeviceKey.generate()
        env_id = C.new_env_id(owner.fingerprint)
        store = C.CommitStore(state, env_id)
        dek = bytes(range(32))
        c1 = env_init_commit(env_id, owner, dek, hlc=C.Hlc().tick(1_000_000))
        self.assertEqual(C.receive_commit(store, c1, 1_000_000), "accepted")
        far_future = 1_000_000 + C.MAX_CLOCK_SKEW_MS + 30_000
        c2 = connection_create_commit(env_id, owner, 2, C.Hlc().tick(far_future))
        self.assertEqual(C.receive_commit(store, c2, 1_000_000), "deferred")
        self.assertEqual(store.all_commits(), [c1])
        released = store.release_deferred(far_future)
        self.assertEqual([c.hash for c in released], [c2.hash])
        result = F.fold(env_id, store.all_commits())
        self.assertIn("gh", result.document["connections"])
        tmp.cleanup()


class TotalOrderDeterminismTestCase(unittest.TestCase):
    """The same commit set, folded from any arrival order, yields byte-identical documents."""

    def _build_commits(self):
        owner = DeviceKey.generate()
        second = DeviceKey.generate()
        env_id = C.new_env_id(owner.fingerprint)
        dek = bytes(range(32))
        c1 = env_init_commit(env_id, owner, dek, hlc="1000-0000")
        c2 = member_add_commit(env_id, owner, 2, "2000-0000", second, "admin")
        c3 = connection_create_commit(env_id, owner, 3, "3000-0000", conn_id="gh")
        c4 = connection_create_commit(env_id, second, 1, "3000-0000", conn_id="gitlab")  # same wall, different author
        c5 = C.sign_commit(owner, env_id, 4, "4000-0000", {}, [{"op": "connection.disable", "id": "gh"}])
        c6 = C.sign_commit(second, env_id, 2, "5000-0000", {},
                           [{"op": "settings.update", "sync_interval_seconds": 42}])
        return env_id, [c1, c2, c3, c4, c5, c6]

    def test_random_arrival_orders_converge(self) -> None:
        env_id, commits = self._build_commits()
        canonical = None
        for seed in range(8):
            rnd = random.Random(seed)
            shuffled = commits[:]
            rnd.shuffle(shuffled)
            result = F.fold(env_id, shuffled)
            as_json = json.dumps(result.document, sort_keys=True, separators=(",", ":"))
            if canonical is None:
                canonical = as_json
            else:
                self.assertEqual(as_json, canonical, f"seed {seed} diverged")
            # skip set should also be order-independent (same reasons, as a set)
            self.assertEqual({(h, i, r) for h, i, r in result.skipped},
                             {(h, i, r) for h, i, r in F.fold(env_id, commits).skipped})

    def test_all_permutations_small_set_converge(self) -> None:
        owner = DeviceKey.generate()
        env_id = C.new_env_id(owner.fingerprint)
        dek = bytes(range(32))
        c1 = env_init_commit(env_id, owner, dek, hlc="1000-0000")
        c2 = connection_create_commit(env_id, owner, 2, "2000-0000", conn_id="a")
        c3 = connection_create_commit(env_id, owner, 3, "3000-0000", conn_id="b")
        results = set()
        for perm in itertools.permutations([c1, c2, c3]):
            result = F.fold(env_id, perm)
            results.add(json.dumps(result.document, sort_keys=True, separators=(",", ":")))
        self.assertEqual(len(results), 1)


class LateArrivalTestCase(unittest.TestCase):
    """A commit not previously known is folded in; policy_version only increases, never regresses."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ctx = Context.initialize(self.root / "state", "admin-pass-1", "recovery-pass-1", Config())
        self.ctx.projects.create("demo")
        self.owner = DeviceKey.create(self.ctx.state, self.ctx.kms)
        self.env_id = C.new_env_id(self.owner.fingerprint)
        self.dek = bytes(range(32))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_late_insert_monotonic_policy_version(self) -> None:
        c1 = env_init_commit(self.env_id, self.owner, self.dek, hlc="1000-0000")
        c2 = connection_create_commit(self.env_id, self.owner, 2, "2000-0000")
        result1 = F.fold(self.env_id, [c1, c2])
        F.derive_local(result1, self.ctx.state, self.ctx.vault, self.ctx.policy, self.ctx.audit, device=self.owner)
        pv1 = self.ctx.state.read_json("policy/connections.json")["gh"]["policy_version"]

        # A commit not previously known (sorting after c2) is discovered and folded in: fold()
        # always recomputes from scratch in total order, so there is no separate "insert in the
        # middle" code path to test apart from this.
        widen = C.sign_commit(self.owner, self.env_id, 3, "3000-0000", {},
                              [{"op": "connection.update", "id": "gh",
                                "http_scope": {"methods": None, "path_prefixes": None}}])
        result2 = F.fold(self.env_id, [c1, c2, widen])
        F.derive_local(result2, self.ctx.state, self.ctx.vault, self.ctx.policy, self.ctx.audit, device=self.owner)
        pv2 = self.ctx.state.read_json("policy/connections.json")["gh"]["policy_version"]
        self.assertGreater(pv2, pv1)

        # Folding forward again with nothing new must not move the version backwards or re-bump it.
        result3 = F.fold(self.env_id, [c1, c2, widen])
        F.derive_local(result3, self.ctx.state, self.ctx.vault, self.ctx.policy, self.ctx.audit, device=self.owner)
        pv3 = self.ctx.state.read_json("policy/connections.json")["gh"]["policy_version"]
        self.assertEqual(pv3, pv2)


class WidenNarrowTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ctx = Context.initialize(self.root / "state", "admin-pass-1", "recovery-pass-1", Config())
        self.ctx.projects.create("demo")
        self.owner = DeviceKey.create(self.ctx.state, self.ctx.kms)
        self.env_id = C.new_env_id(self.owner.fingerprint)
        self.dek = bytes(range(32))
        self.token = self.ctx.policy.create_principal("agent-1")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _derive(self, commits):
        result = F.fold(self.env_id, commits)
        F.derive_local(result, self.ctx.state, self.ctx.vault, self.ctx.policy, self.ctx.audit, device=self.owner)
        return result

    def test_widen_marks_grants_stale(self) -> None:
        c1 = env_init_commit(self.env_id, self.owner, self.dek)
        c2 = connection_create_commit(self.env_id, self.owner, 2, "2000-0000")
        self._derive([c1, c2])
        grant = self.ctx.policy.create_grant("agent-1", "gh", 3600, None)
        c3 = C.sign_commit(self.owner, self.env_id, 3, "3000-0000", {},
                           [{"op": "connection.update", "id": "gh",
                             "http_scope": {"methods": None, "path_prefixes": None}}])
        self._derive([c1, c2, c3])
        self.assertEqual(self.ctx.policy.get_grant(grant.id).status, "stale")

    def test_narrow_reevaluates_in_place(self) -> None:
        c1 = env_init_commit(self.env_id, self.owner, self.dek)
        c2 = connection_create_commit(self.env_id, self.owner, 2, "2000-0000", methods=None, paths=None)
        self._derive([c1, c2])
        grant = self.ctx.policy.create_grant("agent-1", "gh", 3600, None)
        c3 = C.sign_commit(self.owner, self.env_id, 3, "3000-0000", {},
                           [{"op": "connection.update", "id": "gh",
                             "http_scope": {"methods": ["GET"], "path_prefixes": ["/repos"]}}])
        self._derive([c1, c2, c3])
        self.assertEqual(self.ctx.policy.get_grant(grant.id).status, "active")

    def test_disable_invalidates_grants(self) -> None:
        c1 = env_init_commit(self.env_id, self.owner, self.dek)
        c2 = connection_create_commit(self.env_id, self.owner, 2, "2000-0000")
        self._derive([c1, c2])
        grant = self.ctx.policy.create_grant("agent-1", "gh", 3600, None)
        c3 = C.sign_commit(self.owner, self.env_id, 3, "3000-0000", {}, [{"op": "connection.disable", "id": "gh"}])
        self._derive([c1, c2, c3])
        self.assertEqual(self.ctx.policy.get_connection("gh").status, "disabled")
        self.assertEqual(self.ctx.policy.get_grant(grant.id).status, "stale")


class FactsWinTestCase(unittest.TestCase):
    def test_disabled_fact_blocks_create_regardless_of_order(self) -> None:
        owner = DeviceKey.generate()
        env_id = C.new_env_id(owner.fingerprint)
        dek = bytes(range(32))
        c1 = env_init_commit(env_id, owner, dek, hlc="1000-0000")
        # This create sorts AFTER a hypothetical disable fact (issued out of band, not as a commit
        # in this set at all) yet must still be blocked: facts are order-independent.
        c2 = connection_create_commit(env_id, owner, 2, "9999999999-0000")
        facts = F.Facts(disabled_connections={"gh"})
        result = F.fold(env_id, [c1, c2], facts)
        self.assertNotIn("gh", result.document["connections"])

    def test_member_removed_fact_blocks_readd(self) -> None:
        owner = DeviceKey.generate()
        env_id = C.new_env_id(owner.fingerprint)
        dek = bytes(range(32))
        target = DeviceKey.generate()
        c1 = env_init_commit(env_id, owner, dek)
        c2 = member_add_commit(env_id, owner, 2, "2000-0000", target, "user")
        facts = F.Facts(removed_members={target.fingerprint})
        result = F.fold(env_id, [c1, c2], facts)
        self.assertNotIn(target.fingerprint, result.document["members"])

    def test_revoked_version_fact_blocks_activate(self) -> None:
        owner = DeviceKey.generate()
        env_id = C.new_env_id(owner.fingerprint)
        dek = bytes(range(32))
        version_id = "a" * 16
        c1 = env_init_commit(env_id, owner, dek, bootstrap_secret_id=None)
        ct = envelope.encrypt_secret(dek, env_id, "gh-token", version_id, SYNTHETIC_SECRET)
        # put_version is unaffected by the fact (a fresh random token never collides with a
        # previously revoked one in practice); only activating the now-revoked version is blocked.
        c2 = C.sign_commit(owner, env_id, 2, "2000-0000", {},
                           [{"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
                             "generation_id": GEN0, "version_id": version_id, "ciphertext": ct, "public": {}}])
        c3 = C.sign_commit(owner, env_id, 3, "3000-0000", {},
                           [{"op": "secret.activate", "secret_id": "gh-token", "version_id": version_id}])
        facts = F.Facts(revoked_versions={("gh-token", version_id)})
        result = F.fold(env_id, [c1, c2, c3], facts)
        self.assertEqual(result.document["secrets"]["gh-token"]["versions"][version_id]["status"], "revoked")
        self.assertIsNone(result.document["secrets"]["gh-token"]["active_version"])
        self.assertIn("version_revoked", [r for _, _, r in result.skipped])

    def test_disable_then_later_create_same_id_skipped_within_one_fold(self) -> None:
        """A disable op earlier in order blocks a create for the same id later in order."""
        owner = DeviceKey.generate()
        env_id = C.new_env_id(owner.fingerprint)
        dek = bytes(range(32))
        c1 = env_init_commit(env_id, owner, dek, hlc="1000-0000")
        c2 = connection_create_commit(env_id, owner, 2, "2000-0000")
        c3 = C.sign_commit(owner, env_id, 3, "3000-0000", {}, [{"op": "connection.disable", "id": "gh"}])
        c4 = connection_create_commit(env_id, owner, 4, "4000-0000")
        result = F.fold(env_id, [c1, c2, c3, c4])
        self.assertEqual(result.document["connections"]["gh"]["status"], "disabled")
        reasons = [r for _, _, r in result.skipped]
        self.assertIn("connection_id_taken", reasons)


class SharedSecretGenerationKeyTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ctx = Context.initialize(self.root / "state", "admin-pass-1", "recovery-pass-1", Config())
        self.ctx.projects.create("demo")
        self.owner = DeviceKey.create(self.ctx.state, self.ctx.kms)
        self.env_id = C.new_env_id(self.owner.fingerprint)
        self.dek = bytes(range(32))
        self.version_id = "1" * 16

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _commits(self):
        c1 = env_init_commit(self.env_id, self.owner, self.dek, bootstrap_secret_id=None)
        ct = envelope.encrypt_secret(self.dek, self.env_id, "gh-token", self.version_id, SYNTHETIC_SECRET)
        c2 = C.sign_commit(self.owner, self.env_id, 2, "2000-0000", {},
                           [{"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
                             "generation_id": GEN0, "version_id": self.version_id, "ciphertext": ct, "public": {}}])
        c3 = C.sign_commit(self.owner, self.env_id, 3, "3000-0000", {},
                           [{"op": "secret.activate", "secret_id": "gh-token", "version_id": self.version_id}])
        return [c1, c2, c3]

    def test_generation_key_decrypts_local_dek_does_not(self) -> None:
        result = F.fold(self.env_id, self._commits())
        F.derive_local(result, self.ctx.state, self.ctx.vault, self.ctx.policy, self.ctx.audit, device=self.owner)
        value = self.ctx.vault.secret_for_trusted_use("gh-token")
        self.assertEqual(value, SYNTHETIC_SECRET)

        import base64

        from zeropw.crypto import chacha20poly1305 as aead

        doc = self.ctx.state.read_json("vault/secrets.json")
        entry = doc["secrets"]["gh-token"]["versions"]["1"]
        with self.assertRaises(aead.AuthenticationError):
            aead.decrypt(self.ctx.vault._dek, base64.b64decode(entry["nonce"]),
                        base64.b64decode(entry["ciphertext"]), self.ctx.vault._aad("gh-token", 1))

    def test_values_for_trusted_scan_includes_shared_secret(self) -> None:
        result = F.fold(self.env_id, self._commits())
        F.derive_local(result, self.ctx.state, self.ctx.vault, self.ctx.policy, self.ctx.audit, device=self.owner)
        values = self.ctx.vault.values_for_trusted_scan()
        self.assertIn(SYNTHETIC_SECRET, values)


class GenerationAvailabilityTestCase(unittest.TestCase):
    """F1: a shared secret version this node cannot decrypt must never break scan or exec elsewhere."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ctx = Context.initialize(self.root / "state", "admin-pass-1", "recovery-pass-1", Config())
        self.ctx.projects.create("demo")
        self.owner = DeviceKey.create(self.ctx.state, self.ctx.kms)
        self.env_id = C.new_env_id(self.owner.fingerprint)
        self.dek = bytes(range(32))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_unknown_generation_id_skipped_at_fold_time(self) -> None:
        c1 = env_init_commit(self.env_id, self.owner, self.dek, bootstrap_secret_id=None)
        bogus_ct = {"nonce": "AAAA", "ciphertext": "AAAA"}
        c2 = C.sign_commit(self.owner, self.env_id, 2, "2000-0000", {},
                           [{"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
                             "generation_id": "f" * 16, "version_id": "1" * 16, "ciphertext": bogus_ct,
                             "public": {}}])
        result = F.fold(self.env_id, [c1, c2])
        self.assertNotIn("gh-token", result.document["secrets"])
        self.assertIn("generation_unknown", [r for _, _, r in result.skipped])

    def test_unwrappable_generation_excluded_and_does_not_break_scan_or_exec(self) -> None:
        # A dek.rotate that hands the new generation's DEK only to a *different* device: this
        # node (the owner) has no wrap for GEN1 and can never unwrap it.
        other = DeviceKey.generate()
        c1 = env_init_commit(self.env_id, self.owner, self.dek)  # stages a GEN0 "gh-token" version
        gen1 = "1" * 16
        other_dek = bytes(range(32, 0, -1))
        rotate_op = {"op": "dek.rotate", "generation_id": gen1,
                     "wraps": {other.fingerprint: envelope.wrap_dek(other_dek, self.env_id, gen1, other.record)}}
        c2 = C.sign_commit(self.owner, self.env_id, 2, "2000-0000", {}, [rotate_op])
        version_id = "2" * 16
        ct = envelope.encrypt_secret(other_dek, self.env_id, "gh-token", version_id, SYNTHETIC_SECRET)
        c3 = C.sign_commit(self.owner, self.env_id, 3, "3000-0000", {},
                           [{"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
                             "generation_id": gen1, "version_id": version_id, "ciphertext": ct, "public": {}}])
        c4 = C.sign_commit(self.owner, self.env_id, 4, "4000-0000", {},
                           [{"op": "secret.activate", "secret_id": "gh-token", "version_id": version_id}])

        # An unrelated, purely local secret this node owns -- this is exactly what a broken
        # shared version must not collaterally break access to.
        self.ctx.vault.put_secret("local-secret", "api_key", b"synthetic-local-value", "demo", "dev")

        result = F.fold(self.env_id, [c1, c2, c3, c4])
        F.derive_local(result, self.ctx.state, self.ctx.vault, self.ctx.policy, self.ctx.audit, device=self.owner)

        doc = self.ctx.state.read_json("vault/secrets.json")
        # The GEN1 version (local number 2) must be entirely absent; no active version locally
        # (GEN1 is what "secret.activate" pointed at).
        self.assertNotIn("2", doc["secrets"]["gh-token"]["versions"])
        self.assertIsNone(doc["secrets"]["gh-token"]["active_version"])

        # This is the actual regression: scanning every vault value (what an exec call with a
        # CLI profile does before every run) must not raise just because one shared secret has
        # an undecryptable version.
        values = self.ctx.vault.values_for_trusted_scan()
        self.assertIn(b"synthetic-local-value", values)

        # The shared secret itself correctly reports "no usable credential" rather than raising
        # an internal StateError -- NotFound is what the gateway turns into a scoped
        # credential_unavailable for *that* connection only.
        with self.assertRaises(NotFound):
            self.ctx.vault.secret_for_trusted_use("gh-token")


class LocalIdConflictTestCase(unittest.TestCase):
    """F3: a shared environment must never overwrite (or redirect) a node's pre-existing local id."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ctx = Context.initialize(self.root / "state", "admin-pass-1", "recovery-pass-1", Config())
        self.ctx.projects.create("demo")
        self.owner = DeviceKey.create(self.ctx.state, self.ctx.kms)
        self.env_id = C.new_env_id(self.owner.fingerprint)
        self.dek = bytes(range(32))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_connection_create_referencing_undeclared_secret_skipped(self) -> None:
        c1 = env_init_commit(self.env_id, self.owner, self.dek, bootstrap_secret_id=None)
        c2 = connection_create_commit(self.env_id, self.owner, 2, "2000-0000", secret_id="never-declared")
        result = F.fold(self.env_id, [c1, c2])
        self.assertNotIn("gh", result.document["connections"])
        self.assertIn("secret_not_found", [r for _, _, r in result.skipped])

    def test_local_connection_survives_colliding_shared_id(self) -> None:
        self.ctx.policy.create_connection(P.Connection(
            id="gh", project="demo", environment="dev", service="my-private-github", kind="http",
            secret_id="local-secret", secret_version=None, description="",
            http_target=P.HttpTarget("https", "private.example.com", 443),
            http_auth=P.HttpAuth("bearer"), http_scope=P.HttpScope(("GET",), ("/",)),
            ssh_target=None, cli=None, policy_version=0, status="active", created_at="", updated_at="",
        ))
        c1 = env_init_commit(self.env_id, self.owner, self.dek)
        c2 = connection_create_commit(self.env_id, self.owner, 2, "2000-0000", conn_id="gh")
        result = F.fold(self.env_id, [c1, c2])
        F.derive_local(result, self.ctx.state, self.ctx.vault, self.ctx.policy, self.ctx.audit, device=self.owner)
        local = self.ctx.policy.get_connection("gh")
        self.assertEqual(local.service, "my-private-github")
        self.assertEqual(local.http_target.host, "private.example.com")
        raw = self.ctx.state.read_json("policy/connections.json")["gh"]
        self.assertNotIn("shared_env", raw)

    def test_local_secret_survives_colliding_shared_secret_id(self) -> None:
        self.ctx.vault.put_secret("gh-token", "api_key", b"synthetic-local-value", "demo", "dev")
        c1 = env_init_commit(self.env_id, self.owner, self.dek)  # bundles a "gh-token" bootstrap version
        result = F.fold(self.env_id, [c1])
        F.derive_local(result, self.ctx.state, self.ctx.vault, self.ctx.policy, self.ctx.audit, device=self.owner)
        meta = self.ctx.vault.get_meta("gh-token")
        self.assertEqual(meta.project, "demo")
        value = self.ctx.vault.secret_for_trusted_use("gh-token")
        self.assertEqual(value, b"synthetic-local-value")


class DerivedDocOverwriteTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ctx = Context.initialize(self.root / "state", "admin-pass-1", "recovery-pass-1", Config())
        self.ctx.projects.create("demo")
        self.owner = DeviceKey.create(self.ctx.state, self.ctx.kms)
        self.env_id = C.new_env_id(self.owner.fingerprint)
        self.dek = bytes(range(32))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_hand_edit_is_overwritten_on_next_fold(self) -> None:
        c1 = env_init_commit(self.env_id, self.owner, self.dek)
        c2 = connection_create_commit(self.env_id, self.owner, 2, "2000-0000")
        result = F.fold(self.env_id, [c1, c2])
        F.derive_local(result, self.ctx.state, self.ctx.vault, self.ctx.policy, self.ctx.audit, device=self.owner)

        doc = self.ctx.state.read_json("policy/connections.json")
        doc["gh"]["service"] = "hand-edited-service"
        doc["gh"]["http_scope"]["methods"] = None
        self.ctx.state.write_json("policy/connections.json", doc)

        F.derive_local(result, self.ctx.state, self.ctx.vault, self.ctx.policy, self.ctx.audit, device=self.owner)
        restored = self.ctx.state.read_json("policy/connections.json")
        self.assertEqual(restored["gh"]["service"], "github")
        self.assertEqual(restored["gh"]["http_scope"]["methods"], ["GET"])


class SnapshotTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state = StateDir(Path(self.tmp.name) / "state")
        self.state.create()
        self.owner = DeviceKey.generate()
        self.env_id = C.new_env_id(self.owner.fingerprint)
        self.dek = bytes(range(32))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_fold_from_snapshot_matches_full_fold(self) -> None:
        c1 = env_init_commit(self.env_id, self.owner, self.dek, hlc="1000-0000")
        c2 = connection_create_commit(self.env_id, self.owner, 2, "2000-0000", conn_id="a")
        full_before = F.fold(self.env_id, [c1, c2])
        F.save_snapshot(self.state, self.env_id, 1, full_before)

        c3 = connection_create_commit(self.env_id, self.owner, 3, "3000-0000", conn_id="b")
        full = F.fold(self.env_id, [c1, c2, c3])
        from_snapshot = F.fold_with_snapshot(self.env_id, [c1, c2, c3], self.state)

        self.assertEqual(json.dumps(full.document, sort_keys=True), json.dumps(from_snapshot.document, sort_keys=True))
        self.assertEqual(full.version_order, from_snapshot.version_order)


class AuditCommitApplyCountTestCase(unittest.TestCase):
    """F6: team_commit_apply's count is commits folded, not ops skipped."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ctx = Context.initialize(self.root / "state", "admin-pass-1", "recovery-pass-1", Config())
        self.ctx.projects.create("demo")
        self.owner = DeviceKey.create(self.ctx.state, self.ctx.kms)
        self.env_id = C.new_env_id(self.owner.fingerprint)
        self.dek = bytes(range(32))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_count_is_commits_folded_not_ops_skipped(self) -> None:
        user = DeviceKey.generate()
        c1 = env_init_commit(self.env_id, self.owner, self.dek)
        c2 = member_add_commit(self.env_id, self.owner, 2, "2000-0000", user, "user")
        # Two skipped ops from a single extra (fourth) commit: three commits folded overall.
        bad = C.sign_commit(user, self.env_id, 1, "3000-0000", {},
                            [{"op": "connection.disable", "id": "gh"}, {"op": "settings.update",
                              "sync_interval_seconds": 5}])
        result = F.fold(self.env_id, [c1, c2, bad])
        self.assertEqual(len(result.skipped), 2)
        self.assertEqual(sum(result.vector.values()), 3)
        F.derive_local(result, self.ctx.state, self.ctx.vault, self.ctx.policy, self.ctx.audit, device=self.owner)
        applies = [r for r in self.ctx.audit.tail(50) if r["event"] == "team_commit_apply"]
        self.assertEqual(applies[-1]["count"], 3)


class DerivedProjectNameTestCase(unittest.TestCase):
    """F7: the placeholder project/environment names for derived secrets must be valid and listable."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ctx = Context.initialize(self.root / "state", "admin-pass-1", "recovery-pass-1", Config())
        self.ctx.projects.create("demo")
        self.owner = DeviceKey.create(self.ctx.state, self.ctx.kms)
        self.env_id = C.new_env_id(self.owner.fingerprint)
        self.dek = bytes(range(32))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_placeholder_names_are_valid_and_listable(self) -> None:
        from zeropw.projects import validate_name

        c1 = env_init_commit(self.env_id, self.owner, self.dek)
        result = F.fold(self.env_id, [c1])
        F.derive_local(result, self.ctx.state, self.ctx.vault, self.ctx.policy, self.ctx.audit, device=self.owner)
        meta = self.ctx.vault.get_meta("gh-token")
        validate_name(meta.project, "project")  # raises InvalidInput if it violates NAME_RE
        validate_name(meta.environment, "environment")
        self.assertNotIn(":", meta.project)
        listed = self.ctx.vault.list_secrets(project=meta.project, environment=meta.environment)
        self.assertTrue(any(m.id == "gh-token" for m in listed))


class NoLeakageTestCase(unittest.TestCase):
    """No vault value, in any encoding, ever appears in a commit, document, snapshot or state file."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ctx = Context.initialize(self.root / "state", "admin-pass-1", "recovery-pass-1", Config())
        self.ctx.projects.create("demo")
        self.owner = DeviceKey.create(self.ctx.state, self.ctx.kms)
        self.env_id = C.new_env_id(self.owner.fingerprint)
        self.dek = bytes(range(32))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_no_leak_across_commits_documents_snapshots_state(self) -> None:
        version_id = "9" * 16
        c1 = env_init_commit(self.env_id, self.owner, self.dek)
        ct = envelope.encrypt_secret(self.dek, self.env_id, "gh-token-2", version_id, SYNTHETIC_SECRET)
        c2 = C.sign_commit(self.owner, self.env_id, 2, "2000-0000", {},
                           [{"op": "secret.put_version", "secret_id": "gh-token-2", "kind": "api_key",
                             "generation_id": GEN0, "version_id": version_id, "ciphertext": ct, "public": {}}])
        c3 = connection_create_commit(self.env_id, self.owner, 3, "3000-0000")
        commits = [c1, c2, c3]

        result = F.fold(self.env_id, commits)
        F.save_snapshot(self.ctx.state, self.env_id, 1, result)
        F.derive_local(result, self.ctx.state, self.ctx.vault, self.ctx.policy, self.ctx.audit, device=self.owner)

        secrets_to_check = [SYNTHETIC_SECRET, BOOTSTRAP_SECRET_VALUE, self.dek, self.owner.sign_seed,
                            self.owner.agree_private]
        for commit in commits:
            hit = find_secret(json.dumps(commit.to_dict()), secrets_to_check)
            self.assertIsNone(hit, f"leak in commit: {hit}")
        hit = find_secret(json.dumps(result.document, sort_keys=True), secrets_to_check)
        self.assertIsNone(hit, f"leak in document: {hit}")
        hit = find_secret_in_tree(self.ctx.state.path, secrets_to_check)
        self.assertIsNone(hit, f"leak in state directory: {hit}")


if __name__ == "__main__":
    unittest.main()
