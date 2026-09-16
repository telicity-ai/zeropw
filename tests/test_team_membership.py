"""Invite/join/remove/share (docs/team-sync.md sections 4.3, 4.4, 12; stage-3 test list in
section 13): invite one-time-ness and expiry, proof over the wrong transcript, join receiving the
full history and being able to decrypt via ``secret_for_trusted_use``, a non-invited device never
connecting, ``share_environment`` converting an existing local project (secrets + connections +
grant re-evaluation), removal closing sessions and refusing redial, DEK rotation leaving the
removed node able to decrypt only what it already had, and two admins removing each other.
"""

from __future__ import annotations

import hashlib
import hmac
import tempfile
import time
import unittest
from pathlib import Path

from zeropw import policy as P
from zeropw.errors import InvalidInput, NotFound, PolicyDenied, StateError
from zeropw.team import commit as C
from zeropw.team import envelope
from zeropw.team import membership as M
from zeropw.team import sync as S
from zeropw.team.identity import DeviceKey
from zeropw.team.transport import HandshakeFailed, InProcessTransport, SessionClosed, TcpTransport
from tests.leakcheck import find_secret, find_secret_in_tree
from tests.test_team_sync import _Node, make_context, wait_until

SYNTHETIC_VALUE = b"synthetic-shared-secret-membership-0123456789"
SYNTHETIC_VALUE_2 = b"synthetic-shared-secret-membership-rotated-2"


def _addr(node: _Node) -> str:
    assert node.address is not None
    return node.address


class InviteJoinTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.a = _Node(self.root, "a", tcp=True, sync_interval=0.1)
        self.addCleanup(self.a.stop)
        self.a.ctx.projects.create("demo", ("dev",))
        self.a.ctx.vault.put_secret("gh-token", "api_key", SYNTHETIC_VALUE, "demo", "dev", activate=True)
        self.env_id = M.share_environment(self.a.ctx, None, "demo", "dev", "alice", "admin-a-pass")["env_id"]
        self.a.start()

    def _make_invite(self, role: str = "user", ttl_seconds: int = 86400) -> str:
        return M.create_invite(self.a.ctx, self.env_id, role, "bob", ttl_seconds, [_addr(self.a)])

    def _join_node(self, name: str, invite_text: str, project: str = "shared-demo",
                   environment: str = "dev") -> _Node:
        node = _Node(self.root, name, tcp=True, sync_interval=0.1)
        self.addCleanup(node.stop)
        node.start(listen=False)
        M.join(node.ctx, invite_text, node.transport, node.sync, project=project, environment=environment)
        return node

    def test_join_receives_history_and_can_decrypt(self) -> None:
        invite_text = self._make_invite(role="admin")
        b = self._join_node("b", invite_text)
        self.assertTrue(b.sync.is_active_member(self.env_id, b.device.fingerprint))
        wait_until(lambda: self.a.sync.is_active_member(self.env_id, b.device.fingerprint),
                  msg="A never saw B's member.add commit")
        meta = b.ctx.vault.get_meta("gh-token")
        self.assertEqual(meta.active_version, 1)
        value = b.ctx.vault.secret_for_trusted_use("gh-token")
        self.assertEqual(value, SYNTHETIC_VALUE)

    def test_invite_is_one_time(self) -> None:
        invite_text = self._make_invite()
        self._join_node("b", invite_text)
        eve = _Node(self.root, "eve", tcp=True, sync_interval=0.1)
        self.addCleanup(eve.stop)
        eve.start(listen=False)
        with self.assertRaises(StateError):
            M.join(eve.ctx, invite_text, eve.transport, eve.sync, project="x", environment="y")
        self.assertFalse(eve.sync.is_active_member(self.env_id, eve.device.fingerprint))

    def test_invite_expiry_refused(self) -> None:
        invite_text = self._make_invite(ttl_seconds=1)
        time.sleep(1.2)
        eve = _Node(self.root, "eve", tcp=True, sync_interval=0.1)
        self.addCleanup(eve.stop)
        eve.start(listen=False)
        with self.assertRaises(StateError):
            M.join(eve.ctx, invite_text, eve.transport, eve.sync, project="x", environment="y")

    def test_proof_over_different_transcript_refused(self) -> None:
        invite_text = self._make_invite()
        payload = M.parse_invite(invite_text)
        real_transcript_hash = b"x" * 32
        proof_for_real_transcript = hmac.new(payload["invite_secret"], real_transcript_hash, hashlib.sha256).digest()
        # A proof correctly computed over ONE transcript hash does not verify against another --
        # e.g. a relayed/mixed-up handshake attempt, or an attacker who captured a valid proof from
        # one session and tries to replay it into a different one.
        different_transcript_hash = b"y" * 32
        self.assertIsNone(M.consume_invite(self.a.ctx, self.env_id, different_transcript_hash,
                                           proof_for_real_transcript))
        # The same (transcript_hash, proof) pair, correctly matched, does verify -- and consumes
        # the invite (proving the mismatch above did not spend it).
        self.assertIsNotNone(M.consume_invite(self.a.ctx, self.env_id, real_transcript_hash,
                                              proof_for_real_transcript))
        # One-time: the same proof over the same transcript a second time is refused (already used).
        self.assertIsNone(M.consume_invite(self.a.ctx, self.env_id, real_transcript_hash,
                                           proof_for_real_transcript))

    def test_non_invited_device_cannot_connect(self) -> None:
        eve = _Node(self.root, "eve", tcp=True, sync_interval=0.1)
        self.addCleanup(eve.stop)
        eve.start(listen=False)
        with self.assertRaises(SessionClosed):
            eve.transport.dial(_addr(self.a), self.env_id)  # no invite_proof at all: an ordinary,
                                                             # non-member dial must be refused too

    def tearDown(self) -> None:
        needles = [SYNTHETIC_VALUE, SYNTHETIC_VALUE_2]
        for path in (self.a.ctx.state.path,):
            hit = find_secret_in_tree(path, needles)
            self.assertIsNone(hit, f"leak found: {hit}")


class ShareConvertsExistingEnvTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        node = _Node(self.root, "owner", tcp=True, sync_interval=0.1)
        self.node = node
        self.addCleanup(node.stop)
        self.ctx = node.ctx
        self.ctx.projects.create("demo", ("dev",))
        self.ctx.vault.put_secret("gh-token", "api_key", SYNTHETIC_VALUE, "demo", "dev", activate=True)
        http_target = P.HttpTarget("https", "api.github.com", 443, None, False)
        http_auth = P.HttpAuth("bearer")
        http_scope = P.HttpScope(("GET",), ("/repos",), ())
        connection = P.Connection(id="gh", project="demo", environment="dev", service="github", kind="http",
                                  secret_id="gh-token", secret_version=None, description="",
                                  http_target=http_target, http_auth=http_auth, http_scope=http_scope,
                                  ssh_target=None, cli=None, policy_version=0, status="active",
                                  created_at="", updated_at="")
        stamped = self.ctx.policy.create_connection(connection)
        self.conn_id = stamped.id
        token = self.ctx.policy.create_principal("agent-1")
        self.grant = self.ctx.policy.create_grant("agent-1", self.conn_id, 3600, None)

    def test_share_converts_and_reevaluates_grant(self) -> None:
        before_version = self.ctx.policy.get_connection(self.conn_id).policy_version
        env_id = M.share_environment(self.ctx, None, "demo", "dev", "owner", "admin-owner-pass")["env_id"]
        after = self.ctx.policy.get_connection(self.conn_id)
        raw = self.ctx.state.read_json(P.CONNECTIONS, {}) or {}
        self.assertEqual(raw.get(self.conn_id, {}).get("shared_env"), env_id)
        self.assertGreater(after.policy_version, before_version)
        grants = {g.id: g for g in self.ctx.policy.list_grants()}
        self.assertEqual(grants[self.grant.id].status, "stale",
                         "a grant on the pre-existing local connection must be re-evaluated, not silently kept")
        # The secret and connection survive the conversion with their original data intact.
        value = self.ctx.vault.secret_for_trusted_use("gh-token")
        self.assertEqual(value, SYNTHETIC_VALUE)
        self.assertEqual(after.http_target.host, "api.github.com")

    def test_share_leaves_connection_with_unshared_secret_untouched(self) -> None:
        """H1 regression: a connection whose secret is not actually carried over (here, its only
        version is revoked -- the other case, a cross-project secret reference, is exercised
        below) must survive `team share` as a plain, still-active local connection, reported in
        `not_shared`, with its existing grant left alone (never staled)."""
        self.ctx.vault.put_secret("dead-token", "api_key", b"synthetic-dead-token-value", "demo", "dev",
                                  activate=True)
        self.ctx.vault.set_version_status("dead-token", 1, "revoked")  # no active/staged version left
        dead_connection = P.Connection(
            id="dead", project="demo", environment="dev", service="deadsvc", kind="http",
            secret_id="dead-token", secret_version=None, description="",
            http_target=P.HttpTarget("https", "dead.example.com", 443, None, False),
            http_auth=P.HttpAuth("bearer"), http_scope=P.HttpScope(("GET",), None, ()),
            ssh_target=None, cli=None, policy_version=0, status="active", created_at="", updated_at="")
        self.ctx.policy.create_connection(dead_connection)
        dead_grant = self.ctx.policy.create_grant("agent-1", "dead", 3600, None)

        # A second case: a connection in THIS project/environment whose secret_id belongs to a
        # DIFFERENT project/environment entirely (never a candidate for this share at all).
        self.ctx.projects.create("other", ("otherenv",))
        self.ctx.vault.put_secret("other-token", "api_key", b"synthetic-other-token-value", "other", "otherenv",
                                  activate=True)
        cross_connection = P.Connection(
            id="cross", project="demo", environment="dev", service="crosssvc", kind="http",
            secret_id="other-token", secret_version=None, description="",
            http_target=P.HttpTarget("https", "cross.example.com", 443, None, False),
            http_auth=P.HttpAuth("bearer"), http_scope=P.HttpScope(("GET",), None, ()),
            ssh_target=None, cli=None, policy_version=0, status="active", created_at="", updated_at="")
        self.ctx.policy.create_connection(cross_connection)

        result = M.share_environment(self.ctx, None, "demo", "dev", "owner", "admin-owner-pass")
        env_id = result["env_id"]
        not_shared = {entry["connection"]: entry["reason"] for entry in result["not_shared"]}
        self.assertEqual(not_shared, {"dead": "secret_not_shared", "cross": "secret_not_shared"})

        # Both connections are untouched: still active, still plain local (no shared_env tag).
        raw = self.ctx.state.read_json(P.CONNECTIONS, {}) or {}
        for conn_id in ("dead", "cross"):
            self.assertNotIn("shared_env", raw[conn_id])
            self.assertEqual(raw[conn_id]["status"], "active")
        dead_after = self.ctx.policy.get_connection("dead")
        self.assertEqual(dead_after.policy_version, 1)  # never bumped: no widen/reevaluation ran on it

        # The grant on the untouched connection is not staled.
        grants = {g.id: g for g in self.ctx.policy.list_grants()}
        self.assertEqual(grants[dead_grant.id].status, "active")

        # The happy-path connection ("gh", referencing the properly-shared "gh-token") still
        # converts exactly as before.
        raw_gh = self.ctx.state.read_json(P.CONNECTIONS, {}) or {}
        self.assertEqual(raw_gh[self.conn_id].get("shared_env"), env_id)
        doc = M.load_environment(self.ctx, env_id).document
        self.assertIn("gh-token", doc["secrets"])
        self.assertNotIn("dead-token", doc["secrets"])
        self.assertNotIn("other-token", doc["secrets"])
        self.assertNotIn("dead", doc["connections"])
        self.assertNotIn("cross", doc["connections"])
        self.assertIn("gh", doc["connections"])

    def test_share_refuses_when_already_shared(self) -> None:
        M.share_environment(self.ctx, None, "demo", "dev", "owner", "admin-owner-pass")
        with self.assertRaises(InvalidInput):
            M.share_environment(self.ctx, None, "demo", "dev", "owner", "admin-owner-pass")

    def test_share_requires_correct_admin_passphrase(self) -> None:
        from zeropw.errors import AuthFailed

        with self.assertRaises(AuthFailed):
            M.share_environment(self.ctx, None, "demo", "dev", "owner", "wrong-passphrase")


class RemovalAndRotationTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.a = _Node(self.root, "a", tcp=True, sync_interval=0.1)
        self.addCleanup(self.a.stop)
        self.a.ctx.projects.create("demo", ("dev",))
        self.a.ctx.vault.put_secret("gh-token", "api_key", SYNTHETIC_VALUE, "demo", "dev", activate=True)
        self.env_id = M.share_environment(self.a.ctx, None, "demo", "dev", "alice", "admin-a-pass")["env_id"]
        self.a.start()
        invite_text = M.create_invite(self.a.ctx, self.env_id, "admin", "bob", 86400, [_addr(self.a)])
        self.b = _Node(self.root, "b", tcp=True, sync_interval=0.1)
        self.addCleanup(self.b.stop)
        self.b.start(listen=False)
        M.join(self.b.ctx, invite_text, self.b.transport, self.b.sync, project="shared", environment="dev")
        wait_until(lambda: self.a.sync.is_active_member(self.env_id, self.b.device.fingerprint))
        wait_until(lambda: self.b.ctx.vault.secret_for_trusted_use("gh-token") == SYNTHETIC_VALUE)

    def test_removal_closes_session_rotates_dek_and_blocks_new_version(self) -> None:
        old_generation = self.a.sync.document(self.env_id)["dek"]["current"]
        result = M.remove_member(self.a.ctx, self.a.sync, self.env_id, self.b.device.fingerprint)
        self.assertTrue(result["dek_rotated"])
        new_generation = result["new_generation"]
        self.assertNotEqual(new_generation, old_generation)

        wait_until(lambda: self.b.device.fingerprint not in self.a.sync.status(self.env_id)["sessions"],
                  msg="A never closed B's session after removing B")
        # B's own reconnection attempt must be refused: it is no longer an active member.  The
        # handshake's last flight (msg3) has no synchronous ack (section 6.2), so ``dial()`` itself
        # returns a session; A's asynchronous rejection surfaces as the socket being closed under
        # the very first read.
        session = self.b.transport.dial(_addr(self.a), self.env_id)
        self.addCleanup(session.close)
        with self.assertRaises(SessionClosed):
            session.recv(5.0)

        # B still has the OLD generation's key (it was a member when that generation was current)
        # and can still decrypt the version it already knew about.
        self.assertEqual(self.b.ctx.vault.secret_for_trusted_use("gh-token"), SYNTHETIC_VALUE)

        # A puts a new version under the NEW generation; B is gone and never receives this commit,
        # so it is not even present in B's local vault -- and, more directly, B's own (old
        # generation's) key cannot decrypt it even if it somehow obtained the ciphertext.
        from zeropw.kms import WrappedKey

        wrapped = self.a.ctx.state.read_json(f"team/{self.env_id}/dek/{new_generation}.json")
        new_dek = self.a.ctx.kms.unwrap(WrappedKey.from_dict(wrapped))
        version_id = "deadbeefcafef00d"
        ciphertext = envelope.encrypt_secret(new_dek, self.env_id, "gh-token", version_id, SYNTHETIC_VALUE_2)
        commit_obj = M.author_commit(self.a.ctx, self.a.sync, self.env_id,
                                     [{"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
                                       "generation_id": new_generation, "version_id": version_id,
                                       "ciphertext": ciphertext, "public": {}}])
        self.assertIsNotNone(commit_obj)

        old_wrapped = self.b.ctx.state.read_json(f"team/{self.env_id}/dek/{old_generation}.json")
        old_dek_at_b = self.b.ctx.kms.unwrap(WrappedKey.from_dict(old_wrapped))
        with self.assertRaises(InvalidInput):
            envelope.decrypt_secret(old_dek_at_b, self.env_id, "gh-token", version_id, ciphertext)
        # B never even received the new commit (session was already closed before it was authored).
        b_meta = self.b.ctx.vault.get_meta("gh-token")
        self.assertEqual(sorted(v.version for v in b_meta.versions), [1])

    def test_removal_by_self_does_not_rotate_dek(self) -> None:
        result = M.remove_member(self.b.ctx, self.b.sync, self.env_id, self.b.device.fingerprint)
        self.assertFalse(result["dek_rotated"])

    def test_two_admins_remove_each_other(self) -> None:
        """The section 7.4 mutual-removal exemption (``_document_for_removal_author_check``):
        once carol has learned she was removed by bob, her own removal-of-bob fact must still be
        authorized.  Exercised at the node-local level (``team_sync=None``, no live network) so
        the assertion is about the exemption's *authorization* logic, not about which of several
        racing in-flight network deliveries happens to win -- that liveness property (every node
        eventually converges once both facts are delivered by whatever path) is covered live by
        ``tests/test_team_sync.py``'s ``test_mutual_simultaneous_member_removal_converges``.
        """
        invite_text = M.create_invite(self.a.ctx, self.env_id, "admin", "carol", 86400, [_addr(self.a)])
        carol = _Node(self.root, "carol", tcp=True, sync_interval=0.1)
        self.addCleanup(carol.stop)
        carol.start(listen=False)
        M.join(carol.ctx, invite_text, carol.transport, carol.sync, project="shared", environment="dev")
        wait_until(lambda: self.a.sync.is_active_member(self.env_id, carol.device.fingerprint))
        wait_until(lambda: self.b.sync.is_active_member(self.env_id, carol.device.fingerprint))
        carol.stop()  # from here on, drive both removals purely locally (team_sync=None)

        b_fp, carol_fp = self.b.device.fingerprint, carol.device.fingerprint
        result_b = M.remove_member(self.b.ctx, None, self.env_id, carol_fp)
        self.assertTrue(result_b["dek_rotated"])
        # Simulate "carol's node has already received bob's fact" (the precondition for the
        # exemption) by appending the same signed fact line to her own facts.jsonl directly.
        fact_line = self.b.ctx.state.read_lines(f"team/{self.env_id}/facts.jsonl")[-1]
        carol.ctx.state.append_line(f"team/{self.env_id}/facts.jsonl", fact_line)

        # Without the exemption, carol -- who now sees herself as removed -- would be refused.
        result_c = M.remove_member(carol.ctx, None, self.env_id, b_fp)
        self.assertFalse(result_c["dek_rotated"])  # carol was removed by the time she acted: not "admin removing another"
        doc = M.load_environment(carol.ctx, self.env_id).document
        self.assertNotIn(b_fp, doc.get("members", {}))
        self.assertNotIn(carol_fp, doc.get("members", {}))

    def tearDown(self) -> None:
        needles = [SYNTHETIC_VALUE, SYNTHETIC_VALUE_2]
        for node in (self.a, self.b):
            hit = find_secret_in_tree(node.ctx.state.path, needles)
            self.assertIsNone(hit, f"leak found in {node.device.fingerprint}: {hit}")


if __name__ == "__main__":
    unittest.main()
