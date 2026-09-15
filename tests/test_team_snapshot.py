"""Snapshots and ``team compact`` (docs/team-sync.md section 7.3; stage-3 test list in section
13): periodic auto-snapshotting, compaction blocked by a lagging member and succeeding once every
active member's known vector covers the cutoff, protected (membership/DEK) commits never deleted,
and a fresh fold from snapshot + remaining commits equalling the full pre-compaction fold.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from zeropw.context import Config, Context
from zeropw.team import commit as C
from zeropw.team import fold as F
from zeropw.team import sync as S
from zeropw.team.identity import DeviceKey
from zeropw.team.transport import InProcessTransport
from tests.test_team_fold import BOOTSTRAP_SECRET_VALUE, GEN0, connection_create_commit, env_init_commit, member_add_commit
from tests.leakcheck import find_secret_in_tree

DAY_MS = 24 * 3600 * 1000


class SnapshotIntervalTestCase(unittest.TestCase):
    def test_auto_snapshot_every_n_commits(self) -> None:
        original = S.SNAPSHOT_INTERVAL_COMMITS
        S.SNAPSHOT_INTERVAL_COMMITS = 3
        try:
            with tempfile.TemporaryDirectory() as tmp:
                ctx = Context.initialize(Path(tmp) / "state", "admin-pass-1", "recovery-pass-1", Config())
                owner = DeviceKey.create(ctx.state, ctx.kms)
                env_id = C.new_env_id(owner.fingerprint)
                dek = bytes(range(32))
                transport = InProcessTransport(owner)
                sync = S.TeamSync(ctx, transport, owner)
                sync.start(None)
                self.addCleanup(sync.stop)
                sync.register_env(env_id)

                c1 = env_init_commit(env_id, owner, dek, bootstrap_secret_id=None)
                self.assertEqual(sync.submit_commit(env_id, c1), "accepted")
                self.assertIsNone(F.load_latest_snapshot(ctx.state, env_id))
                # connection.create needs a declared secret; settings.update is cheap, dependency-free,
                # and still a real commit that advances the vector.
                for i in range(2, 5):
                    op = {"op": "settings.update", "sync_interval_seconds": i}
                    commit_obj = C.sign_commit(owner, env_id, i, f"{1000 * i}-0000", {}, [op])
                    self.assertEqual(sync.submit_commit(env_id, commit_obj), "accepted")
                snapshot = F.load_latest_snapshot(ctx.state, env_id)
                self.assertIsNotNone(snapshot, "no snapshot was saved after crossing the interval")
                self.assertGreaterEqual(sum(snapshot["vector"].values()), 3)
        finally:
            S.SNAPSHOT_INTERVAL_COMMITS = original


def _old_hlc(days_ago: int, counter: int = 0) -> str:
    return f"{C.now_ms() - days_ago * DAY_MS}-{counter:04d}"


class CompactTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ctx = Context.initialize(self.root / "state", "admin-pass-1", "recovery-pass-1", Config())
        self.owner = DeviceKey.create(self.ctx.state, self.ctx.kms)
        self.env_id = C.new_env_id(self.owner.fingerprint)
        self.dek = bytes(range(32))
        self.member = DeviceKey.generate()
        self.store = C.CommitStore(self.ctx.state, self.env_id)
        c1 = env_init_commit(self.env_id, self.owner, self.dek, hlc=_old_hlc(40), bootstrap_secret_id=None)
        c2 = member_add_commit(self.env_id, self.owner, 2, _old_hlc(39), self.member, "admin", name="bob")
        self.store.append(c1)
        self.store.append(c2)
        # Several old, compactable connection.create commits (needs a secret to reference: put one
        # first) plus one recent commit that must never be compacted (too young).
        secret_op = {"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
                    "generation_id": GEN0, "version_id": "aa11bb22cc33dd44", "ciphertext": {"nonce": "x", "ciphertext": "y"},
                    "public": {}}
        c3 = C.sign_commit(self.owner, self.env_id, 3, _old_hlc(38), {}, [secret_op])
        self.store.append(c3)
        for i, seq in enumerate(range(4, 8)):
            op = {"op": "connection.create", "id": f"conn-{seq}", "project": "demo", "environment": "dev",
                 "service": "svc", "kind": "http", "secret_id": "gh-token", "secret_version": None,
                 "description": "", "http_target": {"scheme": "https", "host": "example.com", "port": 443},
                 "http_auth": {"mode": "bearer"}, "http_scope": {"methods": ["GET"], "path_prefixes": None}}
            commit_obj = C.sign_commit(self.owner, self.env_id, seq, _old_hlc(37 - i), {}, [op])
            self.store.append(commit_obj)
        # One RECENT commit (today): must survive compaction regardless of coverage, since it is
        # not yet 30 days old.
        recent_op = {"op": "connection.disable", "id": "conn-4"}
        recent_commit = C.sign_commit(self.owner, self.env_id, 8, _old_hlc(0), {}, [recent_op])
        self.store.append(recent_commit)
        self.full_fold_before = F.fold(self.env_id, self.store.all_commits())

    def _offline_sync(self) -> S.TeamSync:
        transport = InProcessTransport(self.owner)
        sync = S.TeamSync(self.ctx, transport, self.owner)
        sync.register_env(self.env_id)
        return sync

    def _write_peer_vectors(self, vectors: dict) -> None:
        self.ctx.state.write_json(f"team/{self.env_id}/peer_vectors.json", vectors)

    def test_blocked_while_member_is_behind(self) -> None:
        self._write_peer_vectors({self.member.fingerprint: {self.owner.fingerprint: 3}})  # far behind
        sync = self._offline_sync()
        result = sync.compact(self.env_id)
        self.assertEqual(result["removed"], 0)
        self.assertIn(self.member.fingerprint, result["blocked_by"])
        # Nothing was deleted.
        self.assertEqual(len(self.store.all_commits()), 8)

    def test_succeeds_when_member_covered_and_preserves_protected_commits(self) -> None:
        full_vector = self.store.vector()
        self._write_peer_vectors({self.member.fingerprint: dict(full_vector)})
        sync = self._offline_sync()
        result = sync.compact(self.env_id)
        self.assertEqual(result["blocked_by"], [])
        self.assertGreater(result["removed"], 0)

        remaining = self.store.all_commits()
        remaining_ops = {op.get("op") for c in remaining for op in c.ops}
        # env.init and member.add are protected: never deleted, regardless of age/coverage.
        self.assertIn("env.init", remaining_ops)
        self.assertIn("member.add", remaining_ops)
        # The too-recent commit (connection.disable, today) must also still be present.
        self.assertTrue(any(op.get("op") == "connection.disable" for c in remaining for op in c.ops))

        snapshot = F.load_latest_snapshot(self.ctx.state, self.env_id)
        self.assertIsNotNone(snapshot)

        from_snapshot = F.fold_with_snapshot(self.env_id, self.store.all_commits(), self.ctx.state)
        self.assertEqual(json.dumps(from_snapshot.document, sort_keys=True),
                         json.dumps(self.full_fold_before.document, sort_keys=True),
                         "fold(snapshot + remaining commits) must equal the pre-compaction full fold")

    def test_append_after_compaction_tolerates_the_gap(self) -> None:
        full_vector = self.store.vector()
        self._write_peer_vectors({self.member.fingerprint: dict(full_vector)})
        sync = self._offline_sync()
        sync.compact(self.env_id)
        # The owner's next commit continues from its TRUE last seq (9), not from whatever the
        # lowest remaining on-disk file happens to be -- vector()/last_seq() must not be fooled by
        # a hole left by compaction (docs/team-sync.md section 7.3's "gaps tolerated" requirement).
        next_op = {"op": "settings.update", "sync_interval_seconds": 42}
        next_commit = C.sign_commit(self.owner, self.env_id, 9, _old_hlc(0, counter=1), {}, [next_op])
        self.store.append(next_commit)  # must not raise team_seq_gap
        self.assertEqual(self.store.last_seq(self.owner.fingerprint), 9)

    def tearDown(self) -> None:
        hit = find_secret_in_tree(self.ctx.state.path, [BOOTSTRAP_SECRET_VALUE, self.dek])
        self.assertIsNone(hit, f"leak found: {hit}")


if __name__ == "__main__":
    unittest.main()
