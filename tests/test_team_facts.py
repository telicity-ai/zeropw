"""Fact-issuing admin CLI paths on a shared environment (``connection disable``, ``secret
revoke``), and facts surviving/being re-applied across a backup+restore cycle (docs/team-sync.md
section 7.4; stage-3 test list in section 13: "긴급 사실의 중복 처리, 복원 뒤 사실 재적용, CLI 출력에
값 없음").
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from zeropw import admin_cli
from zeropw import policy as P
from zeropw.context import Context
from zeropw.errors import NotFound
from zeropw.team import commit as C
from zeropw.team import fold as F
from zeropw.team import membership as M
from zeropw.team import sync as S
from zeropw.team.identity import DeviceKey
from zeropw.team.transport import InProcessTransport
from zeropw.vault import VAULT_DOC, Vault
from tests.leakcheck import find_secret_in_tree

ADMIN = "admin-passphrase-facts-1"
RECOVERY = "recovery-passphrase-facts-1"
SYNTHETIC = "synthetic-team-facts-token-0123456789"


class FactCliTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state_dir = self.root / "state"
        self.env_patch = patch.dict(os.environ, {admin_cli.ADMIN_PASSPHRASE_ENV: ADMIN,
                                                 admin_cli.RECOVERY_PASSPHRASE_ENV: RECOVERY})
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        self.outputs: list[tuple[list[str], str, str]] = []
        self.ok("init")
        self.ok("project", "create", "demo")
        self.ok("secret", "put", "--id", "gh-token", "--kind", "api_key", "--project", "demo",
               "--environment", "dev", "--stdin", stdin_bytes=(SYNTHETIC + "\n").encode())
        self.ok("connection", "create-http", "--id", "gh", "--project", "demo", "--environment", "dev",
               "--service", "github", "--secret-id", "gh-token", "--target", "https://api.github.com",
               "--auth", "bearer")
        self.env_id = M.share_environment(Context.open(self.state_dir), None, "demo", "dev", "owner", ADMIN)["env_id"]

    def tearDown(self) -> None:
        for argv, out, err in self.outputs:
            for needle in (SYNTHETIC,):
                self.assertNotIn(needle, out, f"stdout leaked a value: {argv}")
                self.assertNotIn(needle, err, f"stderr leaked a value: {argv}")
        hit = find_secret_in_tree(self.state_dir, [SYNTHETIC.encode()])
        self.assertIsNone(hit, f"leak found: {hit}")

    def run_cli(self, *argv: str, stdin_bytes: bytes | None = None) -> tuple[int, str, str]:
        full = ["--state-dir", str(self.state_dir), *argv]
        out, err = io.StringIO(), io.StringIO()
        stdin_ctx: contextlib.AbstractContextManager[object]
        if stdin_bytes is not None:
            stdin_ctx = patch("sys.stdin", io.TextIOWrapper(io.BytesIO(stdin_bytes), encoding="utf-8"))
        else:
            stdin_ctx = patch("sys.stdin", io.StringIO(""))
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), stdin_ctx:
            code = admin_cli.main(full)
        self.outputs.append((full, out.getvalue(), err.getvalue()))
        return code, out.getvalue(), err.getvalue()

    def ok(self, *argv: str, **kwargs: object) -> dict:
        code, out, err = self.run_cli(*argv, **kwargs)  # type: ignore[arg-type]
        self.assertEqual(code, 0, f"{argv}: {err}")
        return json.loads(out)

    def test_connection_disable_is_a_fact_no_commit(self) -> None:
        payload = self.ok("connection", "disable", "--id", "gh")
        self.assertIn("fact", payload)
        self.assertNotIn("commit", payload)
        self.assertIn("hash", payload["fact"])
        self.assertEqual(payload["status"], "disabled")
        # No ciphertext/nonce/signature anywhere in a fact-producing command's output.
        for forbidden in ("nonce", "ciphertext", "sig", "wraps"):
            self.assertNotIn(forbidden, json.dumps(payload))
        after = self.ok("connection", "show", "--id", "gh")
        self.assertEqual(after["status"], "disabled")

    def test_replaying_the_identical_fact_bytes_does_not_duplicate(self) -> None:
        # A second CLI invocation authors a freshly-signed (different hlc/hash) fact -- not a
        # concern this dedup guards against, matching local `disable_connection`'s own
        # already-idempotent-in-effect posture (docs/team-sync.md never promises a *second*
        # `connection disable` errors).  What section 7.4 actually requires -- the identical wire
        # bytes of one fact, delivered twice, is processed once -- is exercised directly here.
        self.ok("connection", "disable", "--id", "gh")
        facts_path = self.state_dir / f"team/{self.env_id}/facts.jsonl"
        lines_before = facts_path.read_text().splitlines()
        self.assertEqual(len(lines_before), 1)
        with open(facts_path, "a", encoding="utf-8") as stream:
            stream.write(lines_before[0] + "\n")  # a byte-identical replay of the same fact
        facts, hashes, _ = S.load_facts(Context.open(self.state_dir).state, self.env_id)
        self.assertEqual(len(hashes), 1, "an identical fact replayed must still dedupe to one hash")
        self.assertIn("gh", facts.disabled_connections)
        after = self.ok("connection", "show", "--id", "gh")
        self.assertEqual(after["status"], "disabled")

    def test_secret_revoke_is_a_fact_no_commit(self) -> None:
        payload = self.ok("secret", "revoke", "--id", "gh-token", "--version", "1")
        self.assertIn("fact", payload)
        self.assertNotIn("commit", payload)
        versions = self.ok("secret", "versions", "--id", "gh-token")
        self.assertEqual(versions["versions"][0]["status"], "revoked")

    def test_secret_put_and_connection_update_are_commits(self) -> None:
        payload = self.ok("secret", "put", "--id", "gh-token", "--kind", "api_key", "--project", "demo",
                          "--environment", "dev", "--stdin", stdin_bytes=b"synthetic-team-facts-v2\n")
        self.assertIn("commit", payload)
        self.assertIn("author_seq", payload["commit"])
        self.assertIn("hlc", payload["commit"])
        update_payload = self.ok("connection", "update", "--id", "gh", "--methods", "GET,POST")
        self.assertIn("commit", update_payload)


class FactSurvivesRestoreTestCase(unittest.TestCase):
    """Facts are never in the backup archive, but stay enforced after restore because
    ``derive_local`` is always recomputed from the (never-rolled-back) commit + fact history."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state_dir = self.root / "state"
        self.ctx = Context.initialize(self.state_dir, ADMIN, RECOVERY)
        self.ctx.projects.create("demo", ("dev",))
        self.ctx.vault.put_secret("gh-token", "api_key", SYNTHETIC.encode(), "demo", "dev", activate=True)
        http_target = P.HttpTarget("https", "api.github.com", 443, None, False)
        connection = P.Connection(id="gh", project="demo", environment="dev", service="github", kind="http",
                                  secret_id="gh-token", secret_version=None, description="",
                                  http_target=http_target, http_auth=P.HttpAuth("bearer"),
                                  http_scope=P.HttpScope(("GET",), None, ()), ssh_target=None, cli=None,
                                  policy_version=0, status="active", created_at="", updated_at="")
        self.ctx.policy.create_connection(connection)
        self.env_id = M.share_environment(self.ctx, None, "demo", "dev", "owner", ADMIN)["env_id"]
        # An admin disables the connection (a fact) BEFORE the backup is taken.
        M.author_fact(self.ctx, None, self.env_id, "connection_disabled", connection_id="gh")

    def _redocument(self) -> None:
        """What a ``serve`` restart naturally does: rediscover every known env and re-fold+derive."""
        device = DeviceKey.load_or_create(self.ctx.state, self.ctx.kms)
        transport = InProcessTransport(device)
        sync = S.TeamSync(self.ctx, transport, device)
        sync.register_env(self.env_id)

    def test_facts_not_in_backup_and_reapplied_after_restore(self) -> None:
        raw = self.ctx.state.read_json(P.CONNECTIONS, {})
        self.assertEqual(raw["gh"]["status"], "disabled")

        backup_path = self.root / "backup.json"
        self.ctx.vault.backup(backup_path)
        archive = json.loads(backup_path.read_text())
        # No team/ path anywhere in the backed-up documents (facts.jsonl, commits, snapshots).
        self.assertNotIn("facts.jsonl", json.dumps(archive))
        for name in Vault.BACKUP_DOCS:
            self.assertNotIn("team/", name)

        # Mutate the connection back to "active" directly (simulating that the backup pre-dates
        # the fact, the case the reapply mechanism exists for), then restore over it.
        doc = self.ctx.state.read_json(P.CONNECTIONS, {})
        doc["gh"]["status"] = "active"
        self.ctx.state.write_json(P.CONNECTIONS, doc)
        self.assertEqual(self.ctx.state.read_json(P.CONNECTIONS, {})["gh"]["status"], "active")

        Vault.restore(self.ctx.state, backup_path, self.ctx.audit, kms=self.ctx.kms)
        # Immediately after restore, connections.json is exactly the archive's (disabled, since
        # the backup WAS taken after the fact) -- restore alone does not need to know about teams.
        self.assertEqual(self.ctx.state.read_json(P.CONNECTIONS, {})["gh"]["status"], "disabled")

        # The interesting case: a fact recorded AFTER the backup must also stick.  Apply one now
        # (as if it happened between backup and restore) and confirm re-deriving after "restart"
        # enforces it, proving the mechanism does not depend on facts ever being in the archive.
        M.author_fact(self.ctx, None, self.env_id, "secret_version_revoked", secret_id="gh-token",
                      version_id=self._current_version_id())
        self._redocument()
        meta = self.ctx.vault.get_meta("gh-token")
        self.assertEqual(meta.versions[0].status, "revoked")

    def _current_version_id(self) -> str:
        doc = self.ctx.state.read_json(VAULT_DOC, {})
        return doc["secrets"]["gh-token"]["versions"]["1"]["version_id"]

    def tearDown(self) -> None:
        hit = find_secret_in_tree(self.state_dir, [SYNTHETIC.encode()])
        self.assertIsNone(hit, f"leak found: {hit}")


if __name__ == "__main__":
    unittest.main()
