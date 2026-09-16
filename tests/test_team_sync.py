"""Team sync runtime: session lifecycle, VECTOR/COMMIT/FACT/PEERS gossip,
convergence across nodes, and the apply step reaching a running ``serve``
process exactly like a local policy change does (docs/team-sync.md sections
6.3-6.6, 7.4; stage 2 test list in section 13).
"""

from __future__ import annotations

import contextlib
import io
import itertools
import json
import os
import secrets
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from zeropw import admin_cli
from zeropw.context import Config, Context
from zeropw.errors import InvalidInput, NotFound, PolicyDenied
from zeropw.store import StateDir
from zeropw.team import commit as C
from zeropw.team import envelope
from zeropw.team import fold as F
from zeropw.team import sync as S
from zeropw.team import transport as T
from zeropw.team.identity import DeviceKey
from tests.leakcheck import find_secret
from tests.test_team_fold import (BOOTSTRAP_SECRET_VALUE, GEN0, connection_create_commit, env_init_commit,
                                  member_add_commit)

PYTHON_ = __import__("sys").executable
_ADDR_SEQ = itertools.count()


@contextlib.contextmanager
def _stopped_tempdir(testcase):
    """A temporary directory that is removed only AFTER the test's registered cleanups ran.

    ``with tempfile.TemporaryDirectory()`` removes the tree when the block exits, which is
    before ``addCleanup``-registered ``TeamSync.stop`` calls run; a poll or session thread
    can then still be writing under the state directory and ``rmtree`` fails with
    "Directory not empty" (seen in CI on Linux).  Running ``doCleanups`` first stops every
    thread and closes every socket before the directory goes away.
    """
    tmp = tempfile.TemporaryDirectory()
    try:
        yield tmp.name
    finally:
        testcase.doCleanups()
        tmp.cleanup()


def _addr(prefix: str = "node") -> str:
    return f"{prefix}-{next(_ADDR_SEQ)}"


def wait_until(predicate, timeout: float = 25.0, interval: float = 0.02, msg: str = "condition not met") -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval)
    raise AssertionError(msg)


def http_connection_op(conn_id: str, secret_id: str, cli_program: str, methods=("GET",), paths=("/repos",)) -> dict:
    return {"op": "connection.create", "id": conn_id, "project": "demo", "environment": "dev", "service": "svc",
            "kind": "http", "secret_id": secret_id, "secret_version": None, "description": "",
            "http_target": {"scheme": "http", "host": "127.0.0.1", "port": 8080},
            "http_auth": {"mode": "bearer"},
            "http_scope": {"methods": list(methods) if methods is not None else None,
                          "path_prefixes": list(paths) if paths is not None else None},
            "cli": {"program": cli_program, "kind": "http"}}


def ssh_connection_op(conn_id: str, secret_id: str, host_key_line: str) -> dict:
    return {"op": "connection.create", "id": conn_id, "project": "demo", "environment": "dev", "service": "svc",
            "kind": "ssh", "secret_id": secret_id, "secret_version": None, "description": "",
            "ssh_target": {"host": "127.0.0.1", "port": 2222, "username": "deploy", "host_keys": [host_key_line]}}


def make_context(root: Path, name: str, sync_interval: float = 0.1) -> Context:
    cfg = Config(team_sync_interval_seconds=sync_interval, team_dial_backoff=(0.05, 0.3),
                team_session_max_age_seconds=600.0)
    return Context.initialize(root / name, f"admin-{name}-pass", f"recovery-{name}-pass", cfg)


def canonical_document(ctx: Context, env_id: str) -> str:
    store = C.CommitStore(ctx.state, env_id)
    result = F.fold(env_id, store.all_commits())
    return json.dumps(result.document, sort_keys=True, separators=(",", ":"))


class _Node:
    """Test fixture: one full ``Context`` plus a ``TeamSync`` over ``InProcessTransport`` or ``TcpTransport``."""

    def __init__(self, root: Path, name: str, *, tcp: bool = False, sync_interval: float = 0.1) -> None:
        self.ctx = make_context(root, name, sync_interval)
        self.device = DeviceKey.create(self.ctx.state, self.ctx.kms)
        self.transport = T.TcpTransport(self.device) if tcp else T.InProcessTransport(self.device)
        self.sync = S.TeamSync(self.ctx, self.transport, self.device)
        self.tcp = tcp
        self.address: str | None = None

    def start(self, listen: bool = True) -> None:
        if not listen:
            self.sync.start(None)
            return
        addr = "127.0.0.1:0" if self.tcp else _addr(f"inproc-{self.device.fingerprint[:6]}")
        self.sync.start(addr)
        self.address = self.transport.bound_address if self.tcp else addr

    def peer(self, other: "_Node", env_id: str) -> None:
        assert other.address is not None
        self.sync.set_peer_address(env_id, other.device.fingerprint, other.address)

    def store(self, env_id: str) -> C.CommitStore:
        return C.CommitStore(self.ctx.state, env_id)

    def stop(self) -> None:
        self.sync.stop()


def seed_commits(node: _Node, env_id: str, commits: list) -> None:
    store = node.store(env_id)
    for commit_obj in commits:
        store.append(commit_obj)


class TwoNodeConvergenceTestCase(unittest.TestCase):
    """Bidirectional catch-up between two ``Context``s (section 13 stage-2 required test)."""

    def _run(self, tcp: bool) -> None:
        with _stopped_tempdir(self) as tmp:
            root = Path(tmp)
            a = _Node(root, "a", tcp=tcp, sync_interval=0.1)
            b = _Node(root, "b", tcp=tcp, sync_interval=0.1)
            self.addCleanup(a.stop)
            self.addCleanup(b.stop)

            env_id = C.new_env_id(a.device.fingerprint)
            dek = bytes(range(32))
            c1 = env_init_commit(env_id, a.device, dek)
            c2 = member_add_commit(env_id, a.device, 2, "2000-0000", b.device, "admin")
            seed_commits(a, env_id, [c1, c2])
            seed_commits(b, env_id, [c1, c2])

            a.start()
            b.start()
            a.peer(b, env_id)
            b.peer(a, env_id)

            wait_until(lambda: b.device.fingerprint in a.sync.status(env_id)["sessions"],
                      msg="A never opened a session to B")
            wait_until(lambda: a.device.fingerprint in b.sync.status(env_id)["sessions"],
                      msg="B never opened a session to A")

            # A authors a connection under its own sequence; B authors a DIFFERENT one under its
            # own -- each locally, then both must reach the other node purely through sync.
            c3 = connection_create_commit(env_id, a.device, 3, "3000-0000", conn_id="gh-a")
            c4 = connection_create_commit(env_id, b.device, 1, "3500-0000", conn_id="gh-b")
            self.assertEqual(a.sync.submit_commit(env_id, c3), "accepted")
            self.assertEqual(b.sync.submit_commit(env_id, c4), "accepted")

            wait_until(lambda: a.store(env_id).last_seq(b.device.fingerprint) >= 1,
                      msg="A never learned B's commit")
            wait_until(lambda: b.store(env_id).last_seq(a.device.fingerprint) >= 3,
                      msg="B never learned A's commit")

            self.assertEqual(canonical_document(a.ctx, env_id), canonical_document(b.ctx, env_id))
            doc = json.loads(canonical_document(a.ctx, env_id))
            self.assertIn("gh-a", doc["connections"])
            self.assertIn("gh-b", doc["connections"])
            # synced_at is populated once a VECTOR exchange has happened.
            wait_until(lambda: a.sync.status(env_id)["synced_at"] is not None)
            wait_until(lambda: b.sync.status(env_id)["synced_at"] is not None)
            a.stop()  # before the TemporaryDirectory context exits, so no thread/socket is still
            b.stop()  # touching the directory when rmtree runs

    def test_inprocess_transport(self) -> None:
        self._run(tcp=False)

    def test_tcp_transport(self) -> None:
        self._run(tcp=True)


class ThreeNodeRelayTestCase(unittest.TestCase):
    """A and C, never directly peered, still converge because both talk to B."""

    def test_relay_through_middle_node(self) -> None:
        with _stopped_tempdir(self) as tmp:
            root = Path(tmp)
            a = _Node(root, "a")
            b = _Node(root, "b")
            c = _Node(root, "c")
            self.addCleanup(a.stop)
            self.addCleanup(b.stop)
            self.addCleanup(c.stop)

            env_id = C.new_env_id(a.device.fingerprint)
            dek = bytes(range(32))
            c1 = env_init_commit(env_id, a.device, dek)
            c2 = member_add_commit(env_id, a.device, 2, "2000-0000", b.device, "admin", name="bob")
            c3 = member_add_commit(env_id, a.device, 3, "3000-0000", c.device, "admin", name="carol")
            for node in (a, b, c):
                seed_commits(node, env_id, [c1, c2, c3])

            a.start()
            b.start()
            c.start()
            a.peer(b, env_id)
            b.peer(a, env_id)
            b.peer(c, env_id)
            c.peer(b, env_id)
            # A and C are deliberately never told about each other.

            wait_until(lambda: b.device.fingerprint in a.sync.status(env_id)["sessions"])
            wait_until(lambda: c.device.fingerprint in b.sync.status(env_id)["sessions"])

            c4 = connection_create_commit(env_id, a.device, 4, "4000-0000", conn_id="only-a")
            self.assertEqual(a.sync.submit_commit(env_id, c4), "accepted")

            wait_until(lambda: c.store(env_id).last_seq(a.device.fingerprint) >= 4,
                      timeout=10.0, msg="C never received A's commit relayed through B")
            self.assertEqual(canonical_document(a.ctx, env_id), canonical_document(c.ctx, env_id))
            # Note: A and C are never given each other's address directly, but section 6.4's PEERS
            # discovery (correctly) may still connect them directly once B introduces them -- that
            # is a feature, not a leak of this test's setup, so it is not asserted against here.
            # What this test isolates is that delivery does not *require* a configured direct link.
            a.stop()
            b.stop()
            c.stop()


class ConcurrentEditConvergenceTestCase(unittest.TestCase):
    """A and B author conflicting commits while disconnected; reconnecting via a third node
    converges all three nodes to the identical, deterministically-ordered document."""

    def test_offline_concurrent_edit_then_reconnect(self) -> None:
        with _stopped_tempdir(self) as tmp:
            root = Path(tmp)
            a = _Node(root, "a")
            b = _Node(root, "b")
            c = _Node(root, "c")
            self.addCleanup(a.stop)
            self.addCleanup(b.stop)
            self.addCleanup(c.stop)

            env_id = C.new_env_id(a.device.fingerprint)
            dek = bytes(range(32))
            c1 = env_init_commit(env_id, a.device, dek)
            c2 = member_add_commit(env_id, a.device, 2, "2000-0000", b.device, "admin", name="bob")
            c3 = member_add_commit(env_id, a.device, 3, "3000-0000", c.device, "admin", name="carol")
            c4 = connection_create_commit(env_id, a.device, 4, "4000-0000", conn_id="gh",
                                          methods=("GET",), paths=("/repos",))
            baseline = [c1, c2, c3, c4]
            for node in (a, b, c):
                seed_commits(node, env_id, baseline)

            # While fully offline (no TeamSync started at all yet), A and B each author a
            # conflicting connection.update for "gh" with the SAME hlc (a genuine tie, broken only
            # by author fingerprint) -- each stored only in its own node.
            a_edit = C.sign_commit(a.device, env_id, 5, "9000-0000", {},
                                   [{"op": "connection.update", "id": "gh",
                                     "http_scope": {"methods": ["GET", "POST"], "path_prefixes": None}}])
            b_edit = C.sign_commit(b.device, env_id, 1, "9000-0000", {},
                                   [{"op": "connection.update", "id": "gh",
                                     "http_scope": {"methods": None, "path_prefixes": ["/repos", "/orgs"]}}])
            seed_commits(a, env_id, [a_edit])
            seed_commits(b, env_id, [b_edit])

            # Now bring everyone online: A and B are still never peered directly, only via C.
            a.start()
            b.start()
            c.start()
            a.peer(c, env_id)
            c.peer(a, env_id)
            b.peer(c, env_id)
            c.peer(b, env_id)

            wait_until(lambda: a.store(env_id).last_seq(b.device.fingerprint) >= 1, timeout=15.0,
                      msg="A never caught up on B's offline edit via C")
            wait_until(lambda: b.store(env_id).last_seq(a.device.fingerprint) >= 5, timeout=15.0,
                      msg="B never caught up on A's offline edit via C")
            wait_until(lambda: c.store(env_id).last_seq(a.device.fingerprint) >= 5 and
                      c.store(env_id).last_seq(b.device.fingerprint) >= 1, timeout=15.0)

            doc_a = canonical_document(a.ctx, env_id)
            doc_b = canonical_document(b.ctx, env_id)
            doc_c = canonical_document(c.ctx, env_id)
            self.assertEqual(doc_a, doc_b)
            self.assertEqual(doc_b, doc_c)
            # The total order (section 7.1) is (hlc, author); with a tied hlc the higher
            # fingerprint sorts later and so wins -- whichever it is, every node agrees.
            winner = max(a.device.fingerprint, b.device.fingerprint)
            doc = json.loads(doc_a)
            scope = doc["connections"]["gh"]["http_scope"]
            if winner == a.device.fingerprint:
                self.assertEqual(scope["methods"], ["GET", "POST"])
            else:
                self.assertIsNone(scope["methods"])
            a.stop()
            b.stop()
            c.stop()


class FactsTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.a = _Node(self.root, "a")
        self.b = _Node(self.root, "b")
        self.addCleanup(self.a.stop)
        self.addCleanup(self.b.stop)
        self.env_id = C.new_env_id(self.a.device.fingerprint)
        dek = bytes(range(32))
        c1 = env_init_commit(self.env_id, self.a.device, dek)
        c2 = member_add_commit(self.env_id, self.a.device, 2, "2000-0000", self.b.device, "admin", name="bob")
        c3 = connection_create_commit(self.env_id, self.a.device, 3, "3000-0000", conn_id="gh")
        for node in (self.a, self.b):
            seed_commits(node, self.env_id, [c1, c2, c3])
        self.a.start()
        self.b.start()
        self.a.peer(self.b, self.env_id)
        self.b.peer(self.a, self.env_id)
        wait_until(lambda: self.b.device.fingerprint in self.a.sync.status(self.env_id)["sessions"])
        wait_until(lambda: self.a.device.fingerprint in self.b.sync.status(self.env_id)["sessions"])

    def test_connection_disabled_fact_propagates_and_dedupes(self) -> None:
        self.b.sync.publish_fact(self.env_id, "connection_disabled", connection_id="gh")
        # Check the DOCUMENT (the actually-observable, derived state), not the intermediate
        # ``facts`` set: ``_store_fact`` updates that set a moment before the accompanying
        # ``_refold`` (same atomic critical section) finishes updating the document, so polling
        # the set alone can report "done" one step early and race the assertion right after it.
        # A bare, out-of-band FACT (no accompanying commit) is fed into every fold from the very
        # start, so section 5.3's "never let a disabled id (re)exist" rule retroactively skips
        # "gh"'s own connection.create too: the id disappears from the document rather than
        # showing status "disabled" (that happens instead when disabling via a
        # ``connection.disable`` COMMIT, which flips an already-present entry in place -- see
        # ``tests/test_team_fold.py``'s ``WidenNarrowTestCase.test_disable_invalidates_grants``).
        # Either way the *local* derived view must stop granting use immediately (section 6.5),
        # which is what the vanished-connection handling in ``fold.py``'s ``_derive_connections``
        # is for.
        wait_until(lambda: "gh" not in self.a.sync._envs[self.env_id].document["connections"],
                  msg="the FACT never reached A's document")
        wait_until(lambda: self.a.ctx.state.read_json("policy/connections.json", {})["gh"]["status"] == "disabled")
        # Re-publishing (or re-delivering) the identical fact must not duplicate the ledger entry.
        lines_before = self.a.ctx.state.read_lines(f"team/{self.env_id}/facts.jsonl", None)
        self.b.sync._broadcast(self.env_id, {"type": "FACT", "fact": {
            "format": S.FACT_FORMAT, "env_id": self.env_id, "kind": "connection_disabled",
            "target": {"connection_id": "gh"}, "author": self.b.device.fingerprint, "hlc": "1-0000", "sig": "x"}})
        time.sleep(0.2)
        lines_after = self.a.ctx.state.read_lines(f"team/{self.env_id}/facts.jsonl", None)
        self.assertEqual(lines_before, lines_after)

    def test_non_admin_cannot_publish_fact(self) -> None:
        eve = _Node(self.root, "eve")
        self.addCleanup(eve.stop)
        c4 = member_add_commit(self.env_id, self.a.device, 4, "4000-0000", eve.device, "user", name="eve")
        # submit_commit (not a bare store append) so A's own live, already-cached document -- the
        # one its running handshake ``membership`` callback actually consults -- picks up the new
        # member immediately, and B learns it too via the already-open A<->B session.
        self.assertEqual(self.a.sync.submit_commit(self.env_id, c4), "accepted")
        wait_until(lambda: self.b.store(self.env_id).last_seq(self.a.device.fingerprint) >= 4)
        seed_commits(eve, self.env_id, self.a.store(self.env_id).all_commits())
        eve.start()
        eve.peer(self.a, self.env_id)
        wait_until(lambda: self.a.device.fingerprint in eve.sync.status(self.env_id)["sessions"])
        with self.assertRaises(PolicyDenied):
            eve.sync.publish_fact(self.env_id, "connection_disabled", connection_id="gh")
        # A user's rejected attempt must never reach or affect the other nodes.
        time.sleep(0.2)
        self.assertNotIn("gh", self.a.sync._envs[self.env_id].facts.disabled_connections)

    def test_mutual_simultaneous_member_removal_converges(self) -> None:
        # The owner is never a valid removal target (section 4.4/8), so this needs two ADMINS
        # that are neither the owner: add carol as a second admin, then have bob and carol remove
        # each other "at the same time" -- neither fact depends on the other, and both must apply
        # on every node regardless of delivery order.
        carol = _Node(self.root, "carol")
        self.addCleanup(carol.stop)
        c4 = member_add_commit(self.env_id, self.a.device, 4, "4000-0000", carol.device, "admin", name="carol")
        self.assertEqual(self.a.sync.submit_commit(self.env_id, c4), "accepted")
        wait_until(lambda: self.b.store(self.env_id).last_seq(self.a.device.fingerprint) >= 4)
        seed_commits(carol, self.env_id, self.a.store(self.env_id).all_commits())
        carol.start()
        carol.peer(self.a, self.env_id)
        carol.peer(self.b, self.env_id)
        self.b.peer(carol, self.env_id)
        wait_until(lambda: self.a.device.fingerprint in carol.sync.status(self.env_id)["sessions"])
        wait_until(lambda: carol.device.fingerprint in self.b.sync.status(self.env_id)["sessions"],
                  msg="B never connected to carol")

        self.b.sync.publish_fact(self.env_id, "member_removed", fingerprint=carol.device.fingerprint)
        carol.sync.publish_fact(self.env_id, "member_removed", fingerprint=self.b.device.fingerprint)

        def converged(node: _Node) -> bool:
            # Check the DOCUMENT (the actually-observable, derived state), not the intermediate
            # ``facts`` set: ``_store_fact`` updates that set a moment before the accompanying
            # ``_refold`` (same atomic critical section) finishes updating the document, so
            # polling the set alone can report "done" one step early.
            members = node.sync._envs[self.env_id].document["members"]
            return self.b.device.fingerprint not in members and carol.device.fingerprint not in members

        wait_until(lambda: converged(self.a), msg="A never converged")
        wait_until(lambda: converged(self.b), msg="B never converged")
        wait_until(lambda: converged(carol), msg="carol never converged")

        doc_a = self.a.sync._envs[self.env_id].document
        doc_b = self.b.sync._envs[self.env_id].document
        doc_c = carol.sync._envs[self.env_id].document
        # Both facts are bare (no accompanying commit), so section 5.3's "never let a removed
        # fingerprint (re)exist" rule retroactively skips each one's OWN member.add too on a full
        # refold (matching tests/test_team_fold.py's FactsWinTestCase.test_member_removed_fact_blocks_readd):
        # both entries vanish from the document entirely, on every node, rather than showing
        # status "removed".  The owner (never a target here) is unaffected.
        for doc in (doc_a, doc_b, doc_c):
            self.assertNotIn(self.b.device.fingerprint, doc["members"])
            self.assertNotIn(carol.device.fingerprint, doc["members"])
            self.assertIn(self.a.device.fingerprint, doc["members"])
        self.assertEqual(json.dumps(doc_a, sort_keys=True), json.dumps(doc_b, sort_keys=True))
        self.assertEqual(json.dumps(doc_b, sort_keys=True), json.dumps(doc_c, sort_keys=True))

    def test_member_removed_fact_closes_session_and_refuses_future_dial(self) -> None:
        self.a.sync.publish_fact(self.env_id, "member_removed", fingerprint=self.b.device.fingerprint)
        wait_until(lambda: self.b.device.fingerprint not in self.a.sync.status(self.env_id)["sessions"],
                  msg="A did not drop B's session after removing B")
        # B's own dial back to A must not re-establish either, since A no longer considers B a
        # member and refuses the handshake.
        time.sleep(0.3)
        self.assertNotIn(self.a.device.fingerprint, self.a.sync.status(self.env_id)["sessions"])

    def test_removed_by_third_party_cannot_then_remove_someone_else(self) -> None:
        """G1 regression: X removed by Z must never be able to remove anyone else, even though
        X's own signature and role are still resolvable (docs/team-sync.md section 7.4's mutual
        exemption is precise -- it exempts X from being treated as removed ONLY when evaluating a
        fact from the exact fingerprint that removed X, never for any other target)."""
        z = _Node(self.root, "z")
        w = _Node(self.root, "w")
        self.addCleanup(z.stop)
        self.addCleanup(w.stop)
        c4 = member_add_commit(self.env_id, self.a.device, 4, "4000-0000", z.device, "admin", name="zed")
        c5 = member_add_commit(self.env_id, self.a.device, 5, "5000-0000", w.device, "admin", name="wendy")
        self.assertEqual(self.a.sync.submit_commit(self.env_id, c4), "accepted")
        self.assertEqual(self.a.sync.submit_commit(self.env_id, c5), "accepted")
        wait_until(lambda: self.b.store(self.env_id).last_seq(self.a.device.fingerprint) >= 5)
        for node in (z, w):
            seed_commits(node, self.env_id, self.a.store(self.env_id).all_commits())
            node.start()
            node.peer(self.a, self.env_id)
            self.a.peer(node, self.env_id)
        wait_until(lambda: z.device.fingerprint in self.a.sync.status(self.env_id)["sessions"])
        wait_until(lambda: w.device.fingerprint in self.a.sync.status(self.env_id)["sessions"])

        # Z legitimately removes X (self.b) -- an ordinary, unexceptional removal.
        z.sync.publish_fact(self.env_id, "member_removed", fingerprint=self.b.device.fingerprint)
        wait_until(lambda: self.b.device.fingerprint not in self.a.sync._envs[self.env_id].document["members"])
        wait_until(lambda: self.b.device.fingerprint not in self.b.sync._envs[self.env_id].document["members"],
                  msg="X never learned it was removed")

        # X, now removed BY Z (not by W), must be refused when it tries to publish a fact removing
        # W: the local role gate on X's own node raises immediately...
        with self.assertRaises(PolicyDenied):
            self.b.sync.publish_fact(self.env_id, "member_removed", fingerprint=w.device.fingerprint)
        self.assertIn(w.device.fingerprint, self.b.sync._envs[self.env_id].document["members"])

        # ...and a node RECEIVING such a fact (as if X's own gate had been bypassed) must
        # independently reach the same verdict: rejected, audited, W stays active.
        forged_hlc = self.b.sync._envs[self.env_id].hlc.tick()
        forged = S.sign_fact(self.b.device, self.env_id, "member_removed",
                             {"fingerprint": w.device.fingerprint}, forged_hlc)
        self.a.sync._apply_remote_fact(self.env_id, forged, exclude_fp=None)
        self.assertIn(w.device.fingerprint, self.a.sync._envs[self.env_id].document["members"])
        rejections = [r for r in self.a.ctx.audit.tail(500)
                     if r["event"] == "team_fact_rejected" and r.get("reason") == "team_fact_not_authorized"]
        self.assertTrue(rejections, "the forged removal was not audited as rejected")

    def test_self_removal_by_user_role_still_works(self) -> None:
        """G1 regression: the author==target self-removal path is untouched by the precise
        mutual-removal exemption -- any role, including a plain user, may still remove itself."""
        erin = _Node(self.root, "erin")
        self.addCleanup(erin.stop)
        c4 = member_add_commit(self.env_id, self.a.device, 4, "4000-0000", erin.device, "user", name="erin")
        self.assertEqual(self.a.sync.submit_commit(self.env_id, c4), "accepted")
        wait_until(lambda: self.b.store(self.env_id).last_seq(self.a.device.fingerprint) >= 4)
        seed_commits(erin, self.env_id, self.a.store(self.env_id).all_commits())
        erin.start()
        erin.peer(self.a, self.env_id)
        self.a.peer(erin, self.env_id)
        wait_until(lambda: self.a.device.fingerprint in erin.sync.status(self.env_id)["sessions"])

        result = erin.sync.publish_fact(self.env_id, "member_removed", fingerprint=erin.device.fingerprint)
        self.assertEqual(result["kind"], "member_removed")
        wait_until(lambda: erin.device.fingerprint not in self.a.sync._envs[self.env_id].document["members"],
                  msg="self-removal by a user-role member never reached A")


class RemoteWideningCancelsRunningExecTestCase(unittest.TestCase):
    """A remote (widening) commit cancels a running exec on the receiving node's live ``serve``,
    exactly as a local policy change would (docs/team-sync.md section 6.5; pattern reused from
    ``tests/test_admin_cli.py``'s ``test_serve_cancels_runs_and_closes_signer_sockets_...``)."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state_b = self.root / "b"

        cfg = Config(team_sync_interval_seconds=0.1, team_dial_backoff=(0.05, 0.2))
        setup_ctx = Context.initialize(self.state_b, "admin-b-pass", "recovery-b-pass", cfg)
        self.dev_b = DeviceKey.create(setup_ctx.state, setup_ctx.kms)
        setup_ctx.close()

        self.ctx_a = Context.initialize(self.root / "a", "admin-a-pass", "recovery-a-pass", cfg)
        self.addCleanup(self.ctx_a.close)
        self.dev_a = DeviceKey.create(self.ctx_a.state, self.ctx_a.kms)

        self.env_id = C.new_env_id(self.dev_a.fingerprint)
        self.dek = bytes(range(32))
        self.sleeper = self.root / "sleeper.py"
        self.sleeper.write_text(f"#!{PYTHON_}\nimport sys, time\nopen(sys.argv[2], 'w').write('ready')\n"
                                "time.sleep(float(sys.argv[1]))\nopen(sys.argv[3], 'w').write('finished')\n")
        self.sleeper.chmod(0o700)

        wraps = {self.dev_a.fingerprint: envelope.wrap_dek(self.dek, self.env_id, GEN0, self.dev_a.record),
                self.dev_b.fingerprint: envelope.wrap_dek(self.dek, self.env_id, GEN0, self.dev_b.record)}
        version_id = secrets.token_hex(8)
        ct = envelope.encrypt_secret(self.dek, self.env_id, "gh-token", version_id, b"unused-http-secret-value")
        c1 = C.sign_commit(self.dev_a, self.env_id, 1, "1000-0000", {},
                           [{"op": "env.init", "owner_device": self.dev_a.record.to_dict(), "owner_name": "alice",
                             "generation_id": GEN0, "wraps": wraps},
                            {"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
                             "generation_id": GEN0, "version_id": version_id, "ciphertext": ct, "public": {}},
                            {"op": "secret.activate", "secret_id": "gh-token", "version_id": version_id}])
        c2 = C.sign_commit(self.dev_a, self.env_id, 2, "2000-0000", {},
                           [{"op": "member.add", "device": self.dev_b.record.to_dict(), "name": "bob", "role": "admin"}])
        c3 = C.sign_commit(self.dev_a, self.env_id, 3, "3000-0000", {},
                           [http_connection_op("gh", "gh-token", str(self.sleeper), methods=("GET",), paths=("/repos",))])
        C.CommitStore(self.ctx_a.state, self.env_id).append(c1)
        C.CommitStore(self.ctx_a.state, self.env_id).append(c2)
        C.CommitStore(self.ctx_a.state, self.env_id).append(c3)
        store_b = C.CommitStore(StateDir(self.state_b), self.env_id)
        store_b.append(c1)
        store_b.append(c2)
        store_b.append(c3)

        prep_ctx = Context.open(self.state_b, cfg)
        result = F.fold(self.env_id, store_b.all_commits())
        F.derive_local(result, prep_ctx.state, prep_ctx.vault, prep_ctx.policy, prep_ctx.audit, device=self.dev_b)
        prep_ctx.close()

        self.env_patch = patch.dict(os.environ, {admin_cli.ADMIN_PASSPHRASE_ENV: "admin-b-pass",
                                                 admin_cli.RECOVERY_PASSPHRASE_ENV: "recovery-b-pass"})
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    def _run_cli(self, *argv: str) -> dict:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), patch("sys.stdin", io.StringIO("")):
            code = admin_cli.main(["--state-dir", str(self.state_b), *argv])
        self.assertEqual(code, 0, err.getvalue())
        return json.loads(out.getvalue())

    def test_widening_commit_cancels_running_exec(self) -> None:
        from zeropw import tools

        self._run_cli("principal", "create", "--id", "agent-1")
        grant = self._run_cli("grant", "create", "--principal", "agent-1", "--connection", "gh")

        captured: list[Context] = []
        startup: list[dict] = []
        original_emit = admin_cli._emit

        class CapturingContext(Context):
            @classmethod
            def open(cls, *args, **kwargs):  # type: ignore[override]
                ctx = Context.open(*args, **kwargs)
                captured.append(ctx)
                return ctx

        def emit(payload, *, compact=False):
            if compact:
                startup.append(payload)
            else:
                original_emit(payload)

        stop = threading.Event()
        with patch.object(admin_cli, "_emit", emit), patch.object(admin_cli, "Context", CapturingContext):
            serve_thread = threading.Thread(
                target=admin_cli.run_serve, args=(self.state_b, "127.0.0.1:0"),
                kwargs={"quiet": True, "stop_event": stop, "install_signals": False, "team_listen": "127.0.0.1:0"},
                daemon=True)
            serve_thread.start()
            self.addCleanup(serve_thread.join, 30)
            self.addCleanup(stop.set)
            wait_until(lambda: bool(startup), timeout=15.0, msg="serve did not start")
        serve_ctx = captured[0]
        self.assertIsNotNone(serve_ctx.team)
        wait_until(lambda: serve_ctx.team.transport.bound_address is not None,
                  msg="team listener never bound")

        transport_a = T.TcpTransport(self.dev_a)
        self.addCleanup(transport_a.close)
        sync_a = S.TeamSync(self.ctx_a, transport_a, self.dev_a)
        sync_a.start(None)
        self.addCleanup(sync_a.stop)
        sync_a.set_peer_address(self.env_id, self.dev_b.fingerprint, serve_ctx.team.transport.bound_address)
        wait_until(lambda: self.dev_b.fingerprint in sync_a.status(self.env_id)["sessions"], timeout=15.0,
                  msg="A never connected to B's team listener")

        ready, finished = self.root / "ready", self.root / "finished"
        view = tools.exec(serve_ctx, "agent-1", "gh", ["30", str(ready), str(finished)])
        run = serve_ctx.runs.get(view["run_id"], "agent-1")
        wait_until(lambda: ready.exists(), msg="the run never started")
        self.assertEqual(serve_ctx.runs.view(run)["state"], "running")

        widen = C.sign_commit(self.dev_a, self.env_id, 4, "4000-0000", {},
                              [{"op": "connection.update", "id": "gh",
                                "http_scope": {"methods": None, "path_prefixes": None}}])
        self.assertEqual(sync_a.submit_commit(self.env_id, widen), "accepted")

        wait_until(lambda: serve_ctx.runs.view(run)["state"] == "cancelled", timeout=15.0,
                  msg="run was not cancelled after the remote widening commit")
        self.assertEqual(serve_ctx.runs.view(run)["reason"], "grant_stale")
        self.assertFalse(finished.exists())


class RemoteFactClosesSignerSocketTestCase(unittest.TestCase):
    """A remote ``connection_disabled`` FACT closes a live signer socket on the receiving node."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state_b = self.root / "b"
        cfg = Config(team_sync_interval_seconds=0.1, team_dial_backoff=(0.05, 0.2))
        setup_ctx = Context.initialize(self.state_b, "admin-b-pass", "recovery-b-pass", cfg)
        self.dev_b = DeviceKey.create(setup_ctx.state, setup_ctx.kms)
        setup_ctx.close()
        self.ctx_a = Context.initialize(self.root / "a", "admin-a-pass", "recovery-a-pass", cfg)
        self.addCleanup(self.ctx_a.close)
        self.dev_a = DeviceKey.create(self.ctx_a.state, self.ctx_a.kms)

        self.env_id = C.new_env_id(self.dev_a.fingerprint)
        self.dek = bytes(range(32))

        from zeropw import sshwire

        self.ssh_key = sshwire.generate_ed25519_private_key("demo")
        self.ssh_pem = self.ssh_key.to_openssh_private_key()
        self.host_key = sshwire.generate_ed25519_private_key("host").public.to_authorized_key("host")

        wraps = {self.dev_a.fingerprint: envelope.wrap_dek(self.dek, self.env_id, GEN0, self.dev_a.record),
                self.dev_b.fingerprint: envelope.wrap_dek(self.dek, self.env_id, GEN0, self.dev_b.record)}
        version_id = secrets.token_hex(8)
        ct = envelope.encrypt_secret(self.dek, self.env_id, "box-key", version_id, self.ssh_pem.encode())
        c1 = C.sign_commit(self.dev_a, self.env_id, 1, "1000-0000", {},
                           [{"op": "env.init", "owner_device": self.dev_a.record.to_dict(), "owner_name": "alice",
                             "generation_id": GEN0, "wraps": wraps},
                            {"op": "secret.put_version", "secret_id": "box-key", "kind": "ssh_private_key",
                             "generation_id": GEN0, "version_id": version_id, "ciphertext": ct, "public": {}}])
        c2 = C.sign_commit(self.dev_a, self.env_id, 2, "2000-0000", {},
                           [{"op": "member.add", "device": self.dev_b.record.to_dict(), "name": "bob", "role": "admin"}])
        c3 = C.sign_commit(self.dev_a, self.env_id, 3, "3000-0000", {},
                           [ssh_connection_op("box", "box-key", self.host_key)])
        for commit_obj in (c1, c2, c3):
            C.CommitStore(self.ctx_a.state, self.env_id).append(commit_obj)
        store_b = C.CommitStore(StateDir(self.state_b), self.env_id)
        for commit_obj in (c1, c2, c3):
            store_b.append(commit_obj)

        prep_ctx = Context.open(self.state_b, cfg)
        result = F.fold(self.env_id, store_b.all_commits())
        F.derive_local(result, prep_ctx.state, prep_ctx.vault, prep_ctx.policy, prep_ctx.audit, device=self.dev_b)
        prep_ctx.close()

        self.env_patch = patch.dict(os.environ, {admin_cli.ADMIN_PASSPHRASE_ENV: "admin-b-pass",
                                                 admin_cli.RECOVERY_PASSPHRASE_ENV: "recovery-b-pass"})
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    def _run_cli(self, *argv: str) -> dict:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), patch("sys.stdin", io.StringIO("")):
            code = admin_cli.main(["--state-dir", str(self.state_b), *argv])
        self.assertEqual(code, 0, err.getvalue())
        return json.loads(out.getvalue())

    def test_connection_disabled_fact_closes_signer_socket(self) -> None:
        self._run_cli("principal", "create", "--id", "agent-2")
        grant = self._run_cli("grant", "create", "--principal", "agent-2", "--connection", "box")

        captured: list[Context] = []
        startup: list[dict] = []
        original_emit = admin_cli._emit

        class CapturingContext(Context):
            @classmethod
            def open(cls, *args, **kwargs):  # type: ignore[override]
                ctx = Context.open(*args, **kwargs)
                captured.append(ctx)
                return ctx

        def emit(payload, *, compact=False):
            if compact:
                startup.append(payload)
            else:
                original_emit(payload)

        stop = threading.Event()
        with patch.object(admin_cli, "_emit", emit), patch.object(admin_cli, "Context", CapturingContext):
            serve_thread = threading.Thread(
                target=admin_cli.run_serve, args=(self.state_b, "127.0.0.1:0"),
                kwargs={"quiet": True, "stop_event": stop, "install_signals": False, "team_listen": "127.0.0.1:0"},
                daemon=True)
            serve_thread.start()
            self.addCleanup(serve_thread.join, 30)
            self.addCleanup(stop.set)
            wait_until(lambda: bool(startup), timeout=15.0, msg="serve did not start")
        serve_ctx = captured[0]
        wait_until(lambda: serve_ctx.team.transport.bound_address is not None)

        transport_a = T.TcpTransport(self.dev_a)
        self.addCleanup(transport_a.close)
        sync_a = S.TeamSync(self.ctx_a, transport_a, self.dev_a)
        sync_a.start(None)
        self.addCleanup(sync_a.stop)
        sync_a.set_peer_address(self.env_id, self.dev_b.fingerprint, serve_ctx.team.transport.bound_address)
        wait_until(lambda: self.dev_b.fingerprint in sync_a.status(self.env_id)["sessions"], timeout=15.0)

        binding = serve_ctx.signer_manager.bind("agent-2", "box", grant["id"])
        self.assertTrue(Path(binding.socket_path).exists())

        sync_a.publish_fact(self.env_id, "connection_disabled", connection_id="box")

        wait_until(lambda: binding not in serve_ctx.signer_manager.active_bindings(), timeout=15.0,
                  msg="signer binding not released after the remote FACT")
        wait_until(lambda: not Path(binding.socket_path).exists(), timeout=15.0,
                  msg="signer socket not removed after the remote FACT")


class WireCaptureTestCase(unittest.TestCase):
    """No vault value, in any encoding, and no unwrapped DEK ever appear in the raw TCP wire
    bytes (handshake plaintext or post-handshake ciphertext)."""

    def test_no_secret_or_dek_on_the_wire(self) -> None:
        with _stopped_tempdir(self) as tmp:
            root = Path(tmp)
            a = _Node(root, "a", tcp=True, sync_interval=0.1)
            b = _Node(root, "b", tcp=True, sync_interval=0.1)
            self.addCleanup(a.stop)
            self.addCleanup(b.stop)

            env_id = C.new_env_id(a.device.fingerprint)
            dek = bytes(range(32))
            secret_value = b"synthetic-wire-capture-secret-0123456789"
            version_id = secrets.token_hex(8)
            ct = envelope.encrypt_secret(dek, env_id, "gh-token", version_id, secret_value)
            c1 = C.sign_commit(a.device, env_id, 1, "1000-0000", {},
                               [{"op": "env.init", "owner_device": a.device.record.to_dict(), "owner_name": "alice",
                                 "generation_id": GEN0,
                                 "wraps": {a.device.fingerprint: envelope.wrap_dek(dek, env_id, GEN0, a.device.record),
                                          b.device.fingerprint: envelope.wrap_dek(dek, env_id, GEN0, b.device.record)}},
                                {"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
                                 "generation_id": GEN0, "version_id": version_id, "ciphertext": ct, "public": {}}])
            c2 = member_add_commit(env_id, a.device, 2, "2000-0000", b.device, "admin", name="bob")
            for node in (a, b):
                seed_commits(node, env_id, [c1, c2])

            captured: list[bytes] = []
            original_send = T._SocketChannel.send
            original_recv = T._SocketChannel.recv

            def send_wrapper(self, data):  # noqa: ANN001
                captured.append(bytes(data))
                return original_send(self, data)

            def recv_wrapper(self, timeout):  # noqa: ANN001
                result = original_recv(self, timeout)
                if result is not None:
                    captured.append(bytes(result))
                return result

            with patch.object(T._SocketChannel, "send", send_wrapper), \
                 patch.object(T._SocketChannel, "recv", recv_wrapper):
                a.start()
                b.start()
                a.peer(b, env_id)
                b.peer(a, env_id)
                wait_until(lambda: b.device.fingerprint in a.sync.status(env_id)["sessions"])
                wait_until(lambda: a.device.fingerprint in b.sync.status(env_id)["sessions"])
                c3 = connection_create_commit(env_id, a.device, 3, "3000-0000", conn_id="gh", secret_id="gh-token")
                a.sync.submit_commit(env_id, c3)
                wait_until(lambda: b.store(env_id).last_seq(a.device.fingerprint) >= 3)
                time.sleep(0.3)  # let a couple of VECTOR round trips happen too

            self.assertTrue(captured, "no wire traffic was captured")
            needles = [secret_value, dek]
            for blob in captured:
                hit = find_secret(blob, needles)
                self.assertIsNone(hit, f"leak in a single frame: {hit}")
            joined = b"".join(captured)
            hit = find_secret(joined, needles)
            self.assertIsNone(hit, f"leak across concatenated wire capture: {hit}")
            a.stop()
            b.stop()


class SessionRekeyTestCase(unittest.TestCase):
    """A session older than ``team_session_max_age_seconds`` is closed and redialed (section 6.2:
    "세션은 10분 뒤 또는 팀원 목록이 바뀔 때 다시 만든다"; the node-local knob is
    ``Config.team_session_max_age_seconds`` rather than a literal 10 minutes, so tests can use a
    small value instead of actually waiting)."""

    def test_old_session_is_closed_and_replaced(self) -> None:
        with _stopped_tempdir(self) as tmp:
            root = Path(tmp)
            cfg = Config(team_sync_interval_seconds=0.1, team_dial_backoff=(0.05, 0.2),
                        team_session_max_age_seconds=0.3)
            ctx_a = Context.initialize(root / "a", "admin-a-pass", "recovery-a-pass", cfg)
            ctx_b = Context.initialize(root / "b", "admin-b-pass", "recovery-b-pass", cfg)
            dev_a = DeviceKey.create(ctx_a.state, ctx_a.kms)
            dev_b = DeviceKey.create(ctx_b.state, ctx_b.kms)
            env_id = C.new_env_id(dev_a.fingerprint)
            dek = bytes(range(32))
            c1 = env_init_commit(env_id, dev_a, dek)
            c2 = member_add_commit(env_id, dev_a, 2, "2000-0000", dev_b, "admin", name="bob")
            for ctx in (ctx_a, ctx_b):
                store = C.CommitStore(ctx.state, env_id)
                store.append(c1)
                store.append(c2)

            transport_a = T.InProcessTransport(dev_a)
            transport_b = T.InProcessTransport(dev_b)
            sync_a = S.TeamSync(ctx_a, transport_a, dev_a)
            sync_b = S.TeamSync(ctx_b, transport_b, dev_b)
            self.addCleanup(sync_a.stop)
            self.addCleanup(sync_b.stop)
            addr_a, addr_b = _addr("a"), _addr("b")
            sync_a.start(addr_a)
            sync_b.start(addr_b)
            sync_a.set_peer_address(env_id, dev_b.fingerprint, addr_b)
            sync_b.set_peer_address(env_id, dev_a.fingerprint, addr_a)
            wait_until(lambda: dev_b.fingerprint in sync_a.status(env_id)["sessions"])

            first_session = sync_a._envs[env_id].sessions[dev_b.fingerprint]
            wait_until(lambda: first_session.closed, timeout=10.0, msg="aged session was never closed")
            # And a fresh one takes its place (the sync layer redials on its own).
            wait_until(lambda: dev_b.fingerprint in sync_a.status(env_id)["sessions"] and
                      sync_a._envs[env_id].sessions[dev_b.fingerprint] is not first_session,
                      timeout=10.0, msg="no replacement session was dialed after rekey")


class ServeTeamListenTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.env_patch = patch.dict(os.environ, {admin_cli.ADMIN_PASSPHRASE_ENV: "admin-pass-x",
                                                 admin_cli.RECOVERY_PASSPHRASE_ENV: "recovery-pass-x"})
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        self.addCleanup(self.tmp.cleanup)

    def _run_cli(self, *argv: str) -> dict:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), patch("sys.stdin", io.StringIO("")):
            code = admin_cli.main(["--state-dir", str(self.state), *argv])
        self.assertEqual(code, 0, err.getvalue())
        return json.loads(out.getvalue())

    def _serve(self, *, team_listen: str | None):
        captured: list[Context] = []
        startup: list[dict] = []
        original_emit = admin_cli._emit

        class CapturingContext(Context):
            @classmethod
            def open(cls, *args, **kwargs):  # type: ignore[override]
                ctx = Context.open(*args, **kwargs)
                captured.append(ctx)
                return ctx

        def emit(payload, *, compact=False):
            if compact:
                startup.append(payload)
            else:
                original_emit(payload)

        stop = threading.Event()
        kwargs = {"quiet": True, "stop_event": stop, "install_signals": False}
        if team_listen is not None:
            kwargs["team_listen"] = team_listen
        with patch.object(admin_cli, "_emit", emit), patch.object(admin_cli, "Context", CapturingContext):
            thread = threading.Thread(target=admin_cli.run_serve, args=(self.state, "127.0.0.1:0"),
                                      kwargs=kwargs, daemon=True)
            thread.start()
            self.addCleanup(thread.join, 30)
            self.addCleanup(stop.set)
            wait_until(lambda: bool(startup), timeout=15.0, msg="serve did not start")
        return captured[0], startup[0]

    def test_team_listen_opens_a_socket(self) -> None:
        self._run_cli("init")
        ctx, payload = self._serve(team_listen="127.0.0.1:0")
        self.assertEqual(payload["team_listen"], "127.0.0.1:0")
        self.assertIsNotNone(ctx.team)
        wait_until(lambda: ctx.team.transport.bound_address is not None)
        import socket

        host, port = ctx.team.transport.bound_address.rsplit(":", 1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        try:
            sock.connect((host, int(port)))  # a real listening socket accepts the TCP handshake
        finally:
            sock.close()

    def test_serve_without_team_listen_opens_no_team_socket(self) -> None:
        self._run_cli("init")
        ctx, payload = self._serve(team_listen=None)
        self.assertIsNone(payload["team_listen"])
        self.assertIsNone(ctx.team)


class IncidentSharingTestCase(unittest.TestCase):
    """Section 9/deliverable 1: sanitizing, signing, admin-only delivery, the ack-gated outbox, and
    the rotation flags an admin node derives from a received incident summary."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.a = _Node(self.root, "a")   # owner/admin
        self.b = _Node(self.root, "b")   # admin
        self.addCleanup(self.a.stop)
        self.addCleanup(self.b.stop)
        self.env_id = C.new_env_id(self.a.device.fingerprint)
        dek = bytes(range(32))
        c1 = env_init_commit(self.env_id, self.a.device, dek)
        c2 = member_add_commit(self.env_id, self.a.device, 2, "2000-0000", self.b.device, "admin", name="bob")
        for node in (self.a, self.b):
            seed_commits(node, self.env_id, [c1, c2])
        self.a.start()
        self.b.start()
        self.a.peer(self.b, self.env_id)
        self.b.peer(self.a, self.env_id)
        wait_until(lambda: self.b.device.fingerprint in self.a.sync.status(self.env_id)["sessions"])
        wait_until(lambda: self.a.device.fingerprint in self.b.sync.status(self.env_id)["sessions"])

    def _summary(self, incident_id: str = "a1a1a1a1a1a1a1a1", **extra) -> dict:
        base = {"incident_id": incident_id, "ts": "2026-09-16T00:00:00Z", "scope": "device",
               "secret_ids_mandatory": ["gh-token"], "secret_ids_recommended": ["dead-token"],
               "not_a_real_field": "dropped-not-raised", "uses": 3}
        base.update(extra)
        return base

    def test_summary_sanitized_unknown_keys_and_bad_values_dropped(self) -> None:
        clean = S.sanitize_incident_summary(self._summary(uses="not-an-int", also_bad=object()))
        self.assertNotIn("not_a_real_field", clean)
        self.assertNotIn("also_bad", clean)
        self.assertNotIn("uses", clean)  # wrong type: dropped, not raised
        self.assertEqual(clean["incident_id"], "a1a1a1a1a1a1a1a1")
        self.assertEqual(clean["secret_ids_mandatory"], ["gh-token"])

    def test_summary_missing_incident_id_raises(self) -> None:
        with self.assertRaises(InvalidInput):
            S.sanitize_incident_summary({"ts": "2026-09-16T00:00:00Z"})
        with self.assertRaises(InvalidInput):
            S.sanitize_incident_summary("not-even-a-dict")

    def test_summary_non_token_incident_id_raises(self) -> None:
        """incident_id becomes a literal path component (``team/<env>/incidents/<fp>-<id>.json``);
        a free-form string (path separators, ``..``) must be refused, not merely sanitized."""
        for bad in ("../../etc/passwd", "inc-1", "a" * 15, "A1A1A1A1A1A1A1A1", ""):
            with self.assertRaises(InvalidInput):
                S.sanitize_incident_summary(self._summary(incident_id=bad))

    def test_user_role_member_may_also_send_an_incident(self) -> None:
        eve = _Node(self.root, "eve")
        self.addCleanup(eve.stop)
        c3 = member_add_commit(self.env_id, self.a.device, 3, "3000-0000", eve.device, "user", name="eve")
        self.assertEqual(self.a.sync.submit_commit(self.env_id, c3), "accepted")
        wait_until(lambda: self.b.store(self.env_id).last_seq(self.a.device.fingerprint) >= 3)
        seed_commits(eve, self.env_id, self.a.store(self.env_id).all_commits())
        eve.start()
        eve.peer(self.a, self.env_id)
        wait_until(lambda: self.a.device.fingerprint in eve.sync.status(self.env_id)["sessions"])
        fact = eve.sync.send_incident(self.env_id, self._summary(incident_id="a2a2a2a2a2a2a2a2"))
        wait_until(lambda: self.a.ctx.state.exists(
            f"team/{self.env_id}/incidents/{eve.device.fingerprint}-a2a2a2a2a2a2a2a2.json"))
        wait_until(lambda: fact["hash"] not in eve.sync._envs[self.env_id].incident_outbox)

    def test_incident_delivered_and_acked_clears_outbox_and_flags_rotation(self) -> None:
        fact = self.b.sync.send_incident(self.env_id, self._summary())
        wait_until(lambda: fact["hash"] not in self.b.sync._envs[self.env_id].incident_outbox,
                  msg="B's outbox entry was never acknowledged")
        path = f"team/{self.env_id}/incidents/{self.b.device.fingerprint}-a1a1a1a1a1a1a1a1.json"
        record = self.a.ctx.state.read_json(path, None)
        self.assertIsNotNone(record, "A never stored the received incident")
        self.assertEqual(record["secret_ids_mandatory"], ["gh-token"])
        self.assertNotIn("not_a_real_field", record)
        flags = self.a.ctx.state.read_json(f"team/{self.env_id}/rotation_flags.json", {})
        self.assertEqual(flags["gh-token"]["reason"], "rotation_required")
        self.assertEqual(flags["dead-token"]["reason"], "rotation_recommended")
        events = {r["event"] for r in self.a.ctx.audit.tail(200)}
        self.assertIn("team_incident_received", events)
        alerts = {al["alert"] for al in self.a.ctx.audit.alerts(200)}
        self.assertIn("team_incident_received", alerts)
        # B, the sender, is never an admin RECEIVER of its own incident and must not store one.
        self.assertFalse(self.b.ctx.state.exists(path.replace(self.b.device.fingerprint, "nobody")))
        blob = json.dumps(record, sort_keys=True)
        for forbidden in ("ciphertext", "\"sig\"", "wraps"):
            self.assertNotIn(forbidden, blob)

    def test_mandatory_rotation_reason_is_never_downgraded_by_a_later_recommended(self) -> None:
        first = self.b.sync.send_incident(self.env_id, self._summary(
            incident_id="a3a3a3a3a3a3a3a3", secret_ids_mandatory=["gh-token"], secret_ids_recommended=[]))
        wait_until(lambda: first["hash"] not in self.b.sync._envs[self.env_id].incident_outbox)
        second = self.b.sync.send_incident(self.env_id, self._summary(
            incident_id="a4a4a4a4a4a4a4a4", secret_ids_mandatory=[], secret_ids_recommended=["gh-token"]))
        wait_until(lambda: second["hash"] not in self.b.sync._envs[self.env_id].incident_outbox)
        flags = self.a.ctx.state.read_json(f"team/{self.env_id}/rotation_flags.json", {})
        self.assertEqual(flags["gh-token"]["reason"], "rotation_required")

    def test_non_admin_recipient_ignores_incident_and_sends_no_ack(self) -> None:
        """Defence in depth: even if an INCIDENT message somehow reached a non-admin node (its role
        was demoted after the message was already in flight, say), that node must store nothing
        and must not ack -- the sender's outbox is only cleared by an ACTUAL admin's ack."""

        class _FakeSession:
            def __init__(self, peer_fp: str) -> None:
                self.peer = type("Peer", (), {"fingerprint": peer_fp})()
                self.sent: list[dict] = []

            def send(self, message: dict) -> None:
                self.sent.append(message)

        eve = _Node(self.root, "eve")
        self.addCleanup(eve.stop)
        c3 = member_add_commit(self.env_id, self.a.device, 3, "3000-0000", eve.device, "user", name="eve")
        self.assertEqual(self.a.sync.submit_commit(self.env_id, c3), "accepted")
        wait_until(lambda: self.b.store(self.env_id).last_seq(self.a.device.fingerprint) >= 3)
        seed_commits(eve, self.env_id, self.a.store(self.env_id).all_commits())
        eve.start()
        eve.peer(self.a, self.env_id)
        wait_until(lambda: self.a.device.fingerprint in eve.sync.status(self.env_id)["sessions"])

        fact = self.b.sync.send_incident(self.env_id, self._summary(incident_id="a5a5a5a5a5a5a5a5"))
        fake_session = _FakeSession(self.b.device.fingerprint)
        eve.sync._handle_incident(self.env_id, fake_session, {"type": "INCIDENT", "fact": fact})
        self.assertEqual(fake_session.sent, [], "a non-admin must never send an INCIDENT_ACK")
        self.assertFalse(eve.ctx.state.exists(
            f"team/{self.env_id}/incidents/{self.b.device.fingerprint}-a5a5a5a5a5a5a5a5.json"))

    def test_outbox_persists_when_no_route_to_an_admin(self) -> None:
        """A member with no known peer address at all can still queue an incident; it survives a
        process restart (a fresh ``TeamSync`` over the same state directory) undelivered."""
        carol = _Node(self.root, "carol")
        self.addCleanup(carol.stop)
        c3 = member_add_commit(self.env_id, self.a.device, 3, "3000-0000", carol.device, "admin", name="carol")
        self.assertEqual(self.a.sync.submit_commit(self.env_id, c3), "accepted")
        wait_until(lambda: self.b.store(self.env_id).last_seq(self.a.device.fingerprint) >= 3)
        seed_commits(carol, self.env_id, self.a.store(self.env_id).all_commits())
        carol.start(listen=False)  # never peered with anyone: no route to any admin at all

        fact = carol.sync.send_incident(self.env_id, self._summary(incident_id="a6a6a6a6a6a6a6a6"))
        time.sleep(0.3)  # several poll ticks: prove nothing happens without a route
        self.assertIn(fact["hash"], carol.sync._envs[self.env_id].incident_outbox)
        lines = carol.ctx.state.read_lines(f"team/{self.env_id}/incident_outbox.jsonl", None)
        self.assertTrue(any(lines), "the outbox file was never written")

        reloaded = S.TeamSync(carol.ctx, T.InProcessTransport(carol.device), carol.device)
        reloaded.register_env(self.env_id)
        self.assertIn(fact["hash"], reloaded._envs[self.env_id].incident_outbox,
                     "a fresh TeamSync over the same state dir must reload the pending outbox entry")


class OverrideAlertTestCase(unittest.TestCase):
    """Section 7.2's ``team_op_overridden`` alert: the loser of a same-target concurrent edit is
    told, exactly once, that another device's later commit won."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.a = _Node(self.root, "a")
        self.b = _Node(self.root, "b")
        self.addCleanup(self.a.stop)
        self.addCleanup(self.b.stop)
        self.env_id = C.new_env_id(self.a.device.fingerprint)
        dek = bytes(range(32))
        c1 = env_init_commit(self.env_id, self.a.device, dek)
        c2 = member_add_commit(self.env_id, self.a.device, 2, "2000-0000", self.b.device, "admin", name="bob")
        c3 = connection_create_commit(self.env_id, self.a.device, 3, "3000-0000", conn_id="gh")
        for node in (self.a, self.b):
            seed_commits(node, self.env_id, [c1, c2, c3])
        self.a.start()
        self.b.start()
        self.a.peer(self.b, self.env_id)
        self.b.peer(self.a, self.env_id)
        wait_until(lambda: self.b.device.fingerprint in self.a.sync.status(self.env_id)["sessions"])
        wait_until(lambda: self.a.device.fingerprint in self.b.sync.status(self.env_id)["sessions"])

    def test_loser_is_alerted_once_winner_is_not(self) -> None:
        # A edits first; B observes A's commit (via the live session) before authoring its own, so
        # section 5.2's clock rule (hlc strictly increases with what a node has seen) puts B's edit
        # after A's in every node's total order -- A's is overridden.
        a_edit = C.sign_commit(self.a.device, self.env_id, 4, "4000-0000", {},
                               [{"op": "connection.update", "id": "gh",
                                 "http_scope": {"methods": ["GET", "POST"], "path_prefixes": None}}])
        self.assertEqual(self.a.sync.submit_commit(self.env_id, a_edit), "accepted")
        wait_until(lambda: self.b.store(self.env_id).last_seq(self.a.device.fingerprint) >= 4)

        b_edit = C.sign_commit(self.b.device, self.env_id, 1, "5000-0000", {},
                               [{"op": "connection.update", "id": "gh",
                                 "http_scope": {"methods": None, "path_prefixes": ["/repos"]}}])
        self.assertEqual(self.b.sync.submit_commit(self.env_id, b_edit), "accepted")
        wait_until(lambda: self.a.store(self.env_id).last_seq(self.b.device.fingerprint) >= 1)

        def a_alerted() -> bool:
            return any(rec["event"] == "team_op_overridden" for rec in self.a.ctx.audit.tail(200))

        wait_until(a_alerted, msg="A was never alerted that its edit was overridden")
        self.assertFalse(any(rec["event"] == "team_op_overridden" for rec in self.b.ctx.audit.tail(200)),
                         "B (the winner) must not be alerted")
        alerts = {al["alert"] for al in self.a.ctx.audit.alerts(200)}
        self.assertIn("team_op_overridden", alerts)

        # Every poll tick re-folds unconditionally; the alert must not be written more than once.
        time.sleep(0.3)
        count = sum(1 for rec in self.a.ctx.audit.tail(500) if rec["event"] == "team_op_overridden")
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
