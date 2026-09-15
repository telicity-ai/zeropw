"""Vault, KMS, admin re-authentication, backup/restore and recovery."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from zeropw import policy as P
from zeropw.context import Config, Context
from zeropw.errors import AuthFailed, InvalidInput, NotFound, StateError
from zeropw.kms import LocalFileKms
from zeropw.vault import AdminAuth, Vault

ADMIN = "admin-passphrase-1"
RECOVERY = "recovery-passphrase-1"
SYNTHETIC = b"synthetic-token-0123456789"


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_700_000_000.0

    def __call__(self) -> float:
        return self.now


class VaultTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.clock = FakeClock()
        self.ctx = Context.initialize(self.root / "state", ADMIN, RECOVERY, Config(), self.clock)
        self.ctx.projects.create("demo")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def all_state_text(self) -> str:
        chunks = []
        for path in (self.root / "state").rglob("*"):
            if path.is_file():
                chunks.append(path.read_bytes().decode("utf-8", "replace"))
        return "\n".join(chunks)

    def test_state_directory_permissions(self) -> None:
        state = self.root / "state"
        self.assertEqual(state.stat().st_mode & 0o777, 0o700)
        for path in state.rglob("*"):
            if path.is_file():
                self.assertEqual(path.stat().st_mode & 0o077, 0, path)

    def test_put_and_trusted_use_never_persists_plaintext(self) -> None:
        version = self.ctx.vault.put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev")
        self.assertEqual(version, 1)
        self.assertEqual(self.ctx.vault.secret_for_trusted_use("gh-token"), SYNTHETIC)
        self.assertNotIn(SYNTHETIC.decode(), self.all_state_text())
        meta = self.ctx.vault.get_meta("gh-token")
        self.assertEqual(meta.active_version, 1)
        self.assertEqual(meta.versions[0].status, "active")
        self.assertEqual(meta.versions[0].public, {})  # nothing value-derived for non-SSH kinds

    def test_non_ssh_kinds_store_no_value_derived_metadata(self) -> None:
        """A hash prefix or exact length in listings and backups would be an offline oracle for low-entropy values."""
        low_entropy = b"synthetic-pw"
        for secret_id, kind in (("api", "api_key"), ("pw", "password"), ("env", "env_var")):
            self.ctx.vault.put_secret(secret_id, kind, low_entropy, "demo", "dev")
            self.assertEqual(self.ctx.vault.get_meta(secret_id).versions[0].public, {})
            self.assertEqual(Vault._public_metadata(kind, low_entropy), {})
        doc = self.ctx.state.read_json("vault/secrets.json")
        for entry in doc["secrets"].values():
            for record in entry["versions"].values():
                self.assertEqual(record["public"], {})
                self.assertEqual(set(record), {"nonce", "ciphertext", "created_at", "status", "public"})
        text = self.all_state_text()
        for needle in ("sha256_prefix", '"length"', hashlib.sha256(low_entropy).hexdigest()[:8]):
            self.assertNotIn(needle, json.dumps(doc["secrets"]), needle)
        # The exact length must not be stored as a field value.  (A substring search for "12" was flaky: random
        # base64 ciphertexts, nonces and timestamps contain it by chance.)
        for entry in doc["secrets"].values():
            for record in entry["versions"].values():
                self.assertNotIn(len(low_entropy), [v for v in record.values() if isinstance(v, int)])
                self.assertNotIn(str(len(low_entropy)), [v for v in record.values() if isinstance(v, str)])
        self.assertNotIn("sha256_prefix", text)
        backup = self.root / "backup.json"
        self.ctx.vault.backup(backup)
        self.assertNotIn("sha256_prefix", backup.read_text())

    def test_versioning_and_status_transitions(self) -> None:
        self.ctx.vault.put_secret("gh-token", "api_key", b"v1-synthetic", "demo", "dev")
        self.ctx.vault.put_secret("gh-token", "api_key", b"v2-synthetic", "demo", "dev", activate=False)
        meta = self.ctx.vault.get_meta("gh-token")
        self.assertEqual(meta.active_version, 1)
        self.assertEqual([v.status for v in meta.versions], ["active", "staged"])
        self.assertEqual(self.ctx.vault.secret_for_trusted_use("gh-token"), b"v1-synthetic")
        self.assertEqual(self.ctx.vault.secret_for_trusted_use("gh-token", 2), b"v2-synthetic")
        self.ctx.vault.set_version_status("gh-token", 2, "active")
        meta = self.ctx.vault.get_meta("gh-token")
        self.assertEqual(meta.active_version, 2)
        self.assertEqual([v.status for v in meta.versions], ["retired", "active"])
        with self.assertRaises(NotFound):
            self.ctx.vault.secret_for_trusted_use("gh-token", 1)
        self.ctx.vault.set_version_status("gh-token", 1, "revoked")
        with self.assertRaises(InvalidInput):
            self.ctx.vault.set_version_status("gh-token", 1, "active")
        with self.assertRaises(InvalidInput):
            self.ctx.vault.put_secret("gh-token", "password", b"x", "demo", "dev")
        with self.assertRaises(NotFound):
            self.ctx.vault.put_secret("other", "api_key", b"x", "demo", "qa")

    def test_reveal_requires_fresh_reauth_and_is_audited(self) -> None:
        self.ctx.vault.put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev")
        with self.assertRaises(AuthFailed):
            self.ctx.admin.verify("wrong-passphrase")
        auth = self.ctx.admin.verify(ADMIN, now=self.clock())
        self.assertEqual(self.ctx.vault.reveal("gh-token", None, auth, now=self.clock()), SYNTHETIC)
        events = [r["event"] for r in self.ctx.audit.tail(100)]
        self.assertIn("secret_reveal", events)
        self.assertNotIn(SYNTHETIC.decode(), self.all_state_text())
        stale = AdminAuth(self.clock() - 120)
        with self.assertRaises(AuthFailed):
            self.ctx.vault.reveal("gh-token", None, stale, now=self.clock())
        self.assertIn("secret_reveal_denied", [r["event"] for r in self.ctx.audit.tail(100)])
        self.assertTrue(any(a["alert"] == "secret_reveal" for a in self.ctx.audit.alerts()))

    def test_ssh_private_key_public_metadata_only(self) -> None:
        from zeropw import sshwire

        key = sshwire.generate_ed25519_private_key("demo")
        pem = key.to_openssh_private_key().encode()
        self.ctx.vault.put_secret("box-key", "ssh_private_key", pem, "demo", "dev")
        meta = self.ctx.vault.get_meta("box-key")
        self.assertEqual(meta.versions[0].public["fingerprint"], key.public.fingerprint())
        self.assertTrue(meta.versions[0].public["public_key"].startswith("ssh-ed25519 "))
        self.assertNotIn("PRIVATE", self.all_state_text().replace("BEGIN OPENSSH PRIVATE KEY", ""))
        with self.assertRaises(InvalidInput):
            self.ctx.vault.put_secret("bad-key", "ssh_private_key", b"not a key", "demo", "dev")

    def test_kms_unwrap_rejects_other_master_key(self) -> None:
        self.ctx.vault.put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev")
        other = LocalFileKms.create(self.root / "other.key", key_id="local-dev-kms-1")
        doc = self.ctx.state.read_json("vault/secrets.json")
        from zeropw.kms import KmsError, WrappedKey

        with self.assertRaises(KmsError):
            other.unwrap(WrappedKey.from_dict(doc["dek"]))

    def test_backup_restore_blocks_until_ack_and_recovery_rewraps(self) -> None:
        self.ctx.vault.put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev")
        token = self.ctx.policy.create_principal("agent-1")
        self.assertTrue(token)
        self.ctx.policy.create_connection(P.Connection(
            id="gh", project="demo", environment="dev", service="fake", kind="http", secret_id="gh-token",
            secret_version=None, description="", http_target=P.HttpTarget("http", "127.0.0.1", 1),
            http_auth=P.HttpAuth("bearer"), http_scope=P.HttpScope(), ssh_target=None, cli=None,
            policy_version=0, status="active", created_at="", updated_at=""))
        grant = self.ctx.policy.create_grant("agent-1", "gh", 3600, None)
        backup = self.root / "backup.json"
        manifest = self.ctx.vault.backup(backup)
        self.assertNotIn(SYNTHETIC.decode(), backup.read_text())
        self.assertEqual(backup.stat().st_mode & 0o077, 0)

        # Revoke after the backup, then restore: the restored state must stay closed.
        self.ctx.policy.revoke_grant(grant.id)
        Vault.restore(self.ctx.state, backup, self.ctx.audit)
        self.assertTrue(self.ctx.policy.restore_pending())
        self.assertEqual(self.ctx.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/")).reason, "restore_pending")
        # The revocation that post-dates the backup is re-applied by the restore itself (F10).
        self.assertEqual(self.ctx.policy.get_grant(grant.id).status, "revoked")
        self.ctx.policy.set_restore_pending(False)
        self.assertEqual(self.ctx.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/")).reason, "grant_revoked")

        tampered = self.root / "tampered.json"
        archive = json.loads(backup.read_text())
        archive["documents"]["policy/grants.json"][grant.id]["max_uses"] = None
        archive["documents"]["policy/grants.json"][grant.id]["expires_at"] = None
        archive["documents"]["policy/grants.json"][grant.id]["status"] = "tampered-active"
        tampered.write_text(json.dumps(archive))
        with self.assertRaises(StateError):
            Vault.restore(self.ctx.state, tampered, self.ctx.audit)

        reopened = Context.open(self.root / "state", Config(), self.clock)
        self.assertEqual(reopened.vault.secret_for_trusted_use("gh-token"), SYNTHETIC)
        self.assertEqual(manifest["format"], "zeropw-backup-v1")

    def test_recover_rotates_kms_revokes_grants_and_handles(self) -> None:
        self.ctx.vault.put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev")
        self.ctx.policy.create_principal("agent-1")
        self.ctx.policy.create_connection(P.Connection(
            id="gh", project="demo", environment="dev", service="fake", kind="http", secret_id="gh-token",
            secret_version=None, description="", http_target=P.HttpTarget("http", "127.0.0.1", 1),
            http_auth=P.HttpAuth("bearer"), http_scope=P.HttpScope(), ssh_target=None, cli=None,
            policy_version=0, status="active", created_at="", updated_at=""))
        grant = self.ctx.policy.create_grant("agent-1", "gh", 3600, None)
        handle = self.ctx.handles.issue("agent-1", "gh", grant.id, 1, 60, now=self.clock())
        old_key_id = self.ctx.kms.key_id
        with self.assertRaises(AuthFailed):
            self.ctx.recover("wrong-recovery-passphrase")
        self.assertEqual(self.ctx.vault.secret_for_trusted_use("gh-token"), SYNTHETIC)
        revoked = self.ctx.recover(RECOVERY)
        self.assertEqual(revoked, 1)
        self.assertNotEqual(self.ctx.kms.key_id, old_key_id)
        self.assertEqual(self.ctx.vault.secret_for_trusted_use("gh-token"), SYNTHETIC)
        self.assertEqual(self.ctx.policy.get_grant(grant.id).status, "revoked")
        with self.assertRaises(AuthFailed):
            self.ctx.handles.verify(handle, now=self.clock())
        reopened = Context.open(self.root / "state", Config(), self.clock)
        self.assertEqual(reopened.vault.secret_for_trusted_use("gh-token"), SYNTHETIC)

    # ---------------------------------------------------------- lifecycle fixes
    def http_setup(self, cid: str = "gh", secret_version: int | None = None) -> P.Grant:
        if not self.ctx.vault.list_secrets():
            self.ctx.vault.put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev")
        try:
            self.ctx.policy.get_principal("agent-1")
        except NotFound:
            self.ctx.policy.create_principal("agent-1")
        self.ctx.policy.create_connection(P.Connection(
            id=cid, project="demo", environment="dev", service="fake", kind="http", secret_id="gh-token",
            secret_version=secret_version, description="", http_target=P.HttpTarget("http", "127.0.0.1", 1),
            http_auth=P.HttpAuth("bearer"), http_scope=P.HttpScope(None, None, ("DELETE",)), ssh_target=None, cli=None,
            policy_version=0, status="active", created_at="", updated_at=""))
        return self.ctx.policy.create_grant("agent-1", cid, 3600, None)

    def test_new_active_version_rebinds_unpinned_connections_and_invalidates_handles(self) -> None:
        """F12: activating a new version changes the policy version, so earlier handles are stale."""
        grant = self.http_setup()
        self.http_setup("pinned", secret_version=1)
        self.assertEqual(grant.credential_version, 1)
        before = self.ctx.policy.get_connection("gh").policy_version
        self.ctx.vault.put_secret("gh-token", "api_key", b"synthetic-token-v2", "demo", "dev")
        after = self.ctx.policy.get_connection("gh")
        self.assertEqual(after.policy_version, before + 1)
        self.assertEqual(self.ctx.policy.get_connection("pinned").policy_version, 1)
        refreshed = self.ctx.policy.get_grant(grant.id)
        self.assertEqual((refreshed.status, refreshed.policy_version, refreshed.credential_version),
                         ("active", after.policy_version, 2))
        rebound = [r for r in self.ctx.audit.tail(50) if r["event"] == "connection_update"]
        self.assertEqual([(r["connection"], r["policy_version"], r["detail"]) for r in rebound],
                         [("gh", after.policy_version, "credential_version")])
        # A staged version, or a retire that leaves no active version, uses no other credential: no bump.
        self.ctx.vault.put_secret("gh-token", "api_key", b"synthetic-token-v3", "demo", "dev", activate=False)
        self.ctx.vault.set_version_status("gh-token", 2, "retired")
        self.assertEqual(self.ctx.policy.get_connection("gh").policy_version, after.policy_version)
        self.ctx.vault.set_version_status("gh-token", 3, "active")
        self.assertEqual(self.ctx.policy.get_connection("gh").policy_version, after.policy_version + 1)
        self.assertEqual(self.ctx.policy.get_grant(grant.id).credential_version, 3)

    def test_restore_reapplies_revocations_rotates_handle_key_and_never_reopens_approvals(self) -> None:
        """F10 / PL-3: nothing revoked after the backup, and no used approval, comes back."""
        grant = self.http_setup()
        policy = self.ctx.policy
        used = P.approval_digest("agent-1", "gh", "DELETE", "/repos/used", b"")
        archive_only = P.approval_digest("agent-1", "gh", "DELETE", "/repos/archive-only", b"")
        for digest, path in ((used, "/repos/used"), (archive_only, "/repos/archive-only")):
            policy.request_approval(digest, "agent-1", "gh", "DELETE", path)
            policy.approve(digest)
        handle = self.ctx.handles.issue("agent-1", "gh", grant.id, 1, 600, now=self.clock())
        backup = self.root / "backup.json"
        self.ctx.vault.backup(backup)
        # After the backup: the approval is used, then everything is revoked through the core API (not audited).
        self.assertTrue(policy.consume_approval(used, "agent-1", "gh"))
        control = self.ctx.state.read_json(P.CONTROL)
        del control["approvals"][archive_only]        # the current state no longer has this approval at all
        self.ctx.state.write_json(P.CONTROL, control)
        policy.revoke_grant(grant.id)
        policy.disable_connection("gh")
        policy.disable_principal("agent-1")
        self.ctx.vault.set_version_status("gh-token", 1, "revoked")

        writes: list[tuple[str, object]] = []
        original = self.ctx.state.write_json

        def recording(name: str, value: object) -> None:
            writes.append((name, json.loads(json.dumps(value))))
            original(name, value)

        self.ctx.state.write_json = recording  # type: ignore[assignment]
        try:
            Vault.restore(self.ctx.state, backup, self.ctx.audit, kms=self.ctx.kms)
        finally:
            self.ctx.state.write_json = original  # type: ignore[assignment]
        # restore_pending reaches the current control document before any other document is overwritten.
        self.assertEqual(writes[0][0], P.CONTROL)
        self.assertTrue(writes[0][1]["restore_pending"])

        self.assertEqual(policy.get_grant(grant.id).status, "revoked")
        self.assertEqual(policy.get_connection("gh").status, "disabled")
        self.assertEqual(policy.get_principal("agent-1").status, "disabled")
        self.assertEqual(self.ctx.vault.get_meta("gh-token").versions[0].status, "revoked")
        self.assertIsNone(self.ctx.vault.get_meta("gh-token").active_version)
        approvals = policy.list_approvals()
        self.assertEqual(approvals[used]["status"], "consumed")
        self.assertNotIn(archive_only, approvals)
        reapplied = self.ctx.state.read_json(P.CONTROL)["restore_reapplied"]
        self.assertEqual(reapplied, {"grants": 1, "principals": 1, "connections": 1, "secret_versions": 1,
                                     "approvals_dropped": 1})
        policy.set_restore_pending(False)
        self.assertFalse(policy.consume_approval(used, "agent-1", "gh"))
        # A new process reads the rotated handle key: a handle issued (or leaked) before the restore is dead.
        reopened = Context.open(self.root / "state", Config(), self.clock)
        with self.assertRaises(AuthFailed):
            reopened.handles.verify(handle, now=self.clock())
        self.assertEqual(Vault.reapply_revocations(self.ctx.state),
                         {"grants": 0, "principals": 0, "connections": 0, "secret_versions": 0})

    def test_restore_replays_audit_revocations_when_the_ledger_is_missing(self) -> None:
        grant = self.http_setup()
        backup = self.root / "backup.json"
        self.ctx.vault.backup(backup)
        self.ctx.policy.revoke_grant(grant.id)
        self.ctx.audit.record("grant_revoke", caller="admin", connection="gh", result="ok", extra={"grant": grant.id})
        (self.root / "state" / P.REVOCATIONS).unlink()
        Vault.restore(self.ctx.state, backup, self.ctx.audit, kms=self.ctx.kms)
        self.assertEqual(self.ctx.policy.get_grant(grant.id).status, "revoked")

    def test_open_requires_existing_state(self) -> None:
        with self.assertRaises(StateError):
            Context.open(self.root / "missing")
        with self.assertRaises(StateError):
            Context.initialize(self.root / "state", ADMIN, RECOVERY)

    def test_secret_value_limits(self) -> None:
        with self.assertRaises(InvalidInput):
            self.ctx.vault.put_secret("x", "api_key", b"", "demo", "dev")
        with self.assertRaises(InvalidInput):
            self.ctx.vault.put_secret("x", "api_key", b"a" * (64 * 1024 + 1), "demo", "dev")
        with self.assertRaises(InvalidInput):
            self.ctx.vault.put_secret("x", "card", b"a", "demo", "dev")
        with self.assertRaises(InvalidInput):
            self.ctx.vault.put_secret("Bad Id", "api_key", b"a", "demo", "dev")


if __name__ == "__main__":
    unittest.main()
