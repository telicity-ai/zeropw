"""Administrator CLI: JSON contract, secret handling, lifecycle commands, degraded serve.

Every command is driven in-process through ``admin_cli.main(argv)``.  The
tearDown of every test greps the captured stdout/stderr of every command that
ran for the synthetic secret values: only ``secret reveal`` may ever print one.
"""

from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.request import urlopen

from zeropw import admin_cli
from zeropw import policy as P
from zeropw import sshwire
from zeropw.context import Context

ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
ADMIN = "admin-passphrase-1"
RECOVERY = "recovery-passphrase-1"
SYNTHETIC = "synthetic-token-0123456789"
SYNTHETIC_V2 = "synthetic-token-rotated-v2"
# Every value a test feeds into the vault follows this convention, so the tearDown sweep
# catches a leak of any of them without each test registering its own needle.
SYNTHETIC_RE = re.compile(r"synthetic-[A-Za-z0-9_.-]+")
HAS_TOOLS = importlib.util.find_spec("zeropw.tools") is not None


class AdminCliTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.env_patch = patch.dict(os.environ, {admin_cli.ADMIN_PASSPHRASE_ENV: ADMIN,
                                                 admin_cli.RECOVERY_PASSPHRASE_ENV: RECOVERY})
        self.env_patch.start()
        self.outputs: list[tuple[list[str], str, str]] = []
        self.ssh_key = sshwire.generate_ed25519_private_key("demo")
        self.ssh_pem = self.ssh_key.to_openssh_private_key()
        self.host_key = sshwire.generate_ed25519_private_key("host").public.to_authorized_key("host")

    def tearDown(self) -> None:
        self.env_patch.stop()
        self.tmp.cleanup()
        private_line = self.ssh_pem.splitlines()[1]
        for argv, out, err in self.outputs:
            for needle in (SYNTHETIC, SYNTHETIC_V2, private_line, "BEGIN OPENSSH PRIVATE KEY"):
                self.assertNotIn(needle, err, f"stderr leaked a value: {argv}")
                if "reveal" not in argv:
                    self.assertNotIn(needle, out, f"stdout leaked a value: {argv}")
            self.assertEqual(SYNTHETIC_RE.findall(err), [], f"stderr leaked a value: {argv}")
            if "reveal" not in argv:
                self.assertEqual(SYNTHETIC_RE.findall(out), [], f"stdout leaked a value: {argv}")

    # ------------------------------------------------------------ helpers
    def run_cli(self, *argv: str, stdin_bytes: bytes | None = None, state: Path | None = None) -> tuple[int, str, str]:
        full = ["--state-dir", str(state or self.state), *argv]
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
        self.assertEqual(err, "")
        return json.loads(out)

    def fail(self, *argv: str, code: int = 1, **kwargs: object) -> dict:
        actual, out, err = self.run_cli(*argv, **kwargs)  # type: ignore[arg-type]
        self.assertEqual(actual, code, f"{argv}: out={out!r} err={err!r}")
        self.assertEqual(out, "")
        last = [line for line in err.splitlines() if line.strip()][-1]
        return json.loads(last)

    def init(self) -> dict:
        return self.ok("init")

    def seed_project(self) -> None:
        self.init()
        self.ok("project", "create", "demo")

    def put_secret(self, value: str = SYNTHETIC, secret_id: str = "gh-token", environment: str = "dev") -> dict:
        return self.ok("secret", "put", "--id", secret_id, "--kind", "api_key", "--project", "demo",
                       "--environment", environment, "--stdin", stdin_bytes=(value + "\n").encode())

    def create_http(self, cid: str = "gh", *extra: str) -> dict:
        return self.ok("connection", "create-http", "--id", cid, "--project", "demo", "--environment", "dev",
                       "--service", "fake-github", "--secret-id", "gh-token", "--target", "http://127.0.0.1:8080",
                       "--auth", "bearer", "--methods", "GET,POST", "--path-prefixes", "/repos,/me",
                       "--confirm-methods", "DELETE", *extra)

    def ctx(self) -> Context:
        return Context.open(self.state)

    def events(self) -> list[str]:
        return [r["event"] for r in self.ctx().audit.tail(500)]

    # ---------------------------------------------------------------- init
    def test_init_creates_state_and_reports_kms_key(self) -> None:
        payload = self.init()
        self.assertEqual(payload["state_dir"], str(self.state))
        self.assertEqual(payload["kms_key_id"], "local-dev-kms-1")
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.fail("init")["reason"], "state_exists")
        self.assertIn("init", self.events())

    def test_init_rejects_weak_or_missing_passphrases(self) -> None:
        with patch.dict(os.environ, {admin_cli.ADMIN_PASSPHRASE_ENV: "short"}):
            self.assertEqual(self.fail("init")["reason"], "passphrase_too_short")
        with patch.dict(os.environ, {admin_cli.RECOVERY_PASSPHRASE_ENV: ADMIN}):
            self.assertEqual(self.fail("init")["reason"], "passphrases_identical")
        with patch.dict(os.environ):
            del os.environ[admin_cli.ADMIN_PASSPHRASE_ENV]
            error = self.fail("init")  # stdin is a StringIO: no TTY, so no prompt
            self.assertEqual(error["reason"], "passphrase_missing")
        self.assertFalse(self.state.exists())

    # ---------------------------------------------------------- usage/errors
    def test_usage_errors_exit_2_with_json(self) -> None:
        for argv in ((), ("bogus",), ("project",), ("secret", "put", "--id", "x", "--kind", "api_key",
                                                      "--project", "demo", "--environment", "dev")):
            error = self.fail(*argv, code=2)
            self.assertEqual(error["reason"], "usage")
        both = self.fail("secret", "put", "--id", "x", "--kind", "api_key", "--project", "demo", "--environment",
                         "dev", "--stdin", "--value-file", str(self.root / "f"), code=2)
        self.assertEqual(both["reason"], "usage")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(admin_cli.main(["project", "list"]), 2)  # --state-dir is required
        self.assertIn("usage", json.loads(err.getvalue().splitlines()[-1])["reason"])
        with contextlib.redirect_stdout(out):
            self.assertEqual(admin_cli.main(["--help"]), 0)
        self.assertIn("--state-dir", out.getvalue())

    def test_unknown_state_dir_exits_1(self) -> None:
        error = self.fail("project", "list", state=self.root / "missing")
        self.assertEqual(error["reason"], "state_missing")
        self.assertEqual(self.fail("secret", "list", state=self.root / "missing")["error"], "StateError")

    def test_help_subprocess(self) -> None:
        proc = subprocess.run([PYTHON, "-m", "zeropw.admin_cli", "--help"], cwd=ROOT, capture_output=True,
                              text=True, timeout=60, env={**os.environ, "PYTHONPATH": str(ROOT)})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("serve", proc.stdout)

    # -------------------------------------------------------------- projects
    def test_project_create_and_list(self) -> None:
        self.init()
        created = self.ok("project", "create", "demo", "--environments", "dev,prod")
        self.assertEqual(created["environments"], ["dev", "prod"])
        self.assertEqual(self.ok("project", "create", "other")["environments"], ["dev", "staging", "prod"])
        names = [p["name"] for p in self.ok("project", "list")["projects"]]
        self.assertEqual(names, ["demo", "other"])
        self.assertEqual(self.fail("project", "create", "demo")["reason"], "project_exists")
        self.assertEqual(self.fail("project", "create", "Bad Name")["reason"], "invalid_project")
        self.assertEqual(self.events().count("project_create"), 2)

    # --------------------------------------------------------------- secrets
    def test_secret_put_via_file_and_stdin_lists_metadata_only(self) -> None:
        self.seed_project()
        value_file = self.root / "value.txt"
        value_file.write_text(SYNTHETIC + "\n")
        put = self.ok("secret", "put", "--id", "gh-token", "--kind", "api_key", "--project", "demo",
                      "--environment", "dev", "--value-file", str(value_file))
        self.assertEqual((put["version"], put["status"]), (1, "active"))
        staged = self.ok("secret", "put", "--id", "gh-token", "--kind", "api_key", "--project", "demo",
                         "--environment", "dev", "--stdin", "--staged", stdin_bytes=SYNTHETIC_V2.encode())
        self.assertEqual((staged["version"], staged["status"]), (2, "staged"))
        vault = self.ctx().vault
        self.assertEqual(vault.secret_for_trusted_use("gh-token", 1), SYNTHETIC.encode())  # newline stripped
        self.assertEqual(vault.secret_for_trusted_use("gh-token", 2), SYNTHETIC_V2.encode())

        listing = self.ok("secret", "list", "--project", "demo", "--environment", "dev")
        self.assertEqual([s["id"] for s in listing["secrets"]], ["gh-token"])
        versions = self.ok("secret", "versions", "--id", "gh-token")
        self.assertEqual(versions["active_version"], 1)
        self.assertEqual([v["status"] for v in versions["versions"]], ["active", "staged"])
        for text in (json.dumps(listing), json.dumps(versions)):
            self.assertNotIn("ciphertext", text)
            self.assertNotIn("nonce", text)
            self.assertNotIn(SYNTHETIC, text)
        self.assertEqual(self.ok("secret", "list", "--environment", "prod")["secrets"], [])
        self.assertEqual(self.fail("secret", "versions", "--id", "nope")["reason"], "secret_not_found")
        self.assertEqual(self.fail("secret", "put", "--id", "x", "--kind", "api_key", "--project", "demo",
                                   "--environment", "dev", "--value-file", str(self.root / "missing"))["reason"],
                         "file_not_found")
        self.assertEqual(self.fail("secret", "put", "--id", "x", "--kind", "api_key", "--project", "demo",
                                   "--environment", "dev", "--stdin", stdin_bytes=b"\n")["reason"], "empty_secret_value")
        # The value never lands anywhere in the state directory.
        for path in self.state.rglob("*"):
            if path.is_file():
                self.assertNotIn(SYNTHETIC.encode(), path.read_bytes(), path)

    def test_reveal_requires_passphrase_and_is_audited(self) -> None:
        self.seed_project()
        self.put_secret()
        revealed = self.ok("secret", "reveal", "--id", "gh-token")
        self.assertEqual(revealed, {"id": "gh-token", "version": 1, "value": SYNTHETIC})
        with patch.dict(os.environ, {admin_cli.ADMIN_PASSPHRASE_ENV: "wrong-passphrase"}):
            self.assertEqual(self.fail("secret", "reveal", "--id", "gh-token")["reason"], "admin_reauth_failed")
        with patch.dict(os.environ):
            del os.environ[admin_cli.ADMIN_PASSPHRASE_ENV]
            self.assertEqual(self.fail("secret", "reveal", "--id", "gh-token")["reason"], "passphrase_missing")
        self.assertEqual(self.fail("secret", "reveal", "--id", "gh-token", "--version", "9")["reason"],
                         "secret_version_not_found")
        tail = self.ok("audit", "tail", "--limit", "20")["records"]
        events = [r["event"] for r in tail]
        self.assertIn("secret_reveal", events)
        self.assertIn("auth_failed", events)
        self.assertEqual(sum(1 for e in events if e == "secret_reveal"), 1)
        alerts = self.ok("alerts")["alerts"]
        self.assertTrue(any(a["alert"] == "secret_reveal" for a in alerts))

    def test_reveal_of_binary_value_uses_base64(self) -> None:
        self.seed_project()
        raw = b"\xff\xfe synthetic-binary \x00\x01"
        self.ok("secret", "put", "--id", "blob", "--kind", "password", "--project", "demo", "--environment", "dev",
                "--stdin", stdin_bytes=raw)
        revealed = self.ok("secret", "reveal", "--id", "blob")
        self.assertEqual(revealed["encoding"], "base64")
        import base64

        self.assertEqual(base64.b64decode(revealed["value_base64"]), raw)

    def test_secret_retire_and_revoke(self) -> None:
        self.seed_project()
        self.put_secret()
        self.ok("secret", "put", "--id", "gh-token", "--kind", "api_key", "--project", "demo", "--environment", "dev",
                "--stdin", "--staged", stdin_bytes=SYNTHETIC_V2.encode())
        self.create_http("gh")
        self.ok("connection", "switch-credential", "--id", "gh", "--version", "2")  # staged versions are usable
        self.assertEqual(self.fail("secret", "retire", "--id", "gh-token", "--version", "1")["reason"], "version_is_active")
        self.assertEqual(self.fail("secret", "retire", "--id", "gh-token", "--version", "2")["reason"], "version_in_use")
        self.ok("connection", "switch-credential", "--id", "gh", "--version", "1")
        retired = self.ok("secret", "retire", "--id", "gh-token", "--version", "2")
        self.assertEqual(retired["status"], "retired")
        revoked = self.ok("secret", "revoke", "--id", "gh-token", "--version", "1")
        self.assertEqual(revoked["affected_connections"], ["gh"])
        self.assertTrue(revoked["provider_revocation_required"])
        meta = self.ctx().vault.get_meta("gh-token")
        self.assertIsNone(meta.active_version)
        self.assertEqual([v.status for v in meta.versions], ["revoked", "retired"])
        with self.assertRaises(Exception):
            self.ctx().vault.secret_for_trusted_use("gh-token", 1)  # fails closed for the gateway
        self.assertEqual(self.fail("secret", "retire", "--id", "gh-token", "--version", "7")["reason"],
                         "secret_version_not_found")
        events = self.events()
        self.assertIn("secret_retire", events)
        self.assertIn("secret_revoke", events)

    # ----------------------------------------------------------- connections
    def test_connection_http_lifecycle_and_scope_changes(self) -> None:
        self.seed_project()
        self.put_secret()
        created = self.create_http("gh", "--description", "demo", "--cli-program", "/usr/local/bin/democli",
                                   "--cli-env", "DEMOCLI_COLOR=never")
        self.assertEqual(created["policy_version"], 1)
        self.assertEqual(created["http_target"], {"scheme": "http", "host": "127.0.0.1", "port": 8080, "ca_file": None,
                                                  "allow_private_network": False})
        self.assertEqual(created["http_scope"]["methods"], ["GET", "POST"])
        self.assertEqual(created["cli"]["extra_env"], {"DEMOCLI_COLOR": "never"})
        self.assertEqual([c["id"] for c in self.ok("connection", "list")["connections"]], ["gh"])
        self.assertEqual(self.ok("connection", "show", "--id", "gh")["service"], "fake-github")
        self.assertEqual(self.fail("connection", "show", "--id", "nope")["reason"], "connection_not_found")
        self.assertEqual(self.fail("connection", "create-http", "--id", "gh", "--project", "demo", "--environment",
                                   "dev", "--service", "x", "--secret-id", "gh-token", "--target",
                                   "http://127.0.0.1:1", "--auth", "bearer")["reason"], "connection_exists")

        self.ok("principal", "create", "--id", "agent-1")
        grant = self.ok("grant", "create", "--principal", "agent-1", "--connection", "gh")
        narrowed = self.ok("connection", "update-scope", "--id", "gh", "--methods", "GET")
        self.assertEqual((narrowed["widened"], narrowed["policy_version"]), (False, 2))
        policy = self.ctx().policy
        self.assertEqual(policy.get_grant(grant["id"]).status, "active")
        self.assertEqual(policy.get_grant(grant["id"]).policy_version, 2)
        self.assertEqual(policy.evaluate("agent-1", "gh", P.Action("http", "POST", "/repos")).reason, "method_not_allowed")
        self.assertTrue(policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).allowed)

        widened = self.ok("connection", "update-scope", "--id", "gh", "--methods", "GET,POST,PUT",
                          "--path-prefixes", "/repos,/me,/orgs")
        self.assertEqual((widened["widened"], widened["policy_version"]), (True, 3))
        self.assertEqual(widened["scope"]["methods"], ["GET", "POST", "PUT"])
        policy = self.ctx().policy
        self.assertEqual(policy.get_grant(grant["id"]).status, "stale")
        self.assertEqual(policy.evaluate("agent-1", "gh", P.Action("http", "PUT", "/orgs")).reason, "grant_stale")
        self.assertEqual(self.fail("connection", "update-scope", "--id", "gh")["reason"], "no_scope_changes")

        every = self.ok("connection", "update-scope", "--id", "gh", "--methods", "all", "--confirm-methods", "none")
        self.assertTrue(every["widened"])
        self.assertEqual(every["scope"], {"methods": "all", "path_prefixes": ["/repos", "/me", "/orgs"], "confirm_methods": []})

        disabled = self.ok("connection", "disable", "--id", "gh")
        self.assertEqual(disabled["status"], "disabled")
        self.assertEqual(self.fail("grant", "create", "--principal", "agent-1", "--connection", "gh")["reason"],
                         "connection_disabled")
        events = self.events()
        self.assertEqual(events.count("connection_create"), 1)
        self.assertEqual(events.count("connection_update"), 3)
        self.assertEqual(events.count("connection_disable"), 1)

    def test_connection_create_http_validations_and_port_defaults(self) -> None:
        self.seed_project()
        self.put_secret()
        self.put_secret(secret_id="prod-token", environment="prod")
        self.ok("secret", "put", "--id", "box-key", "--kind", "ssh_private_key", "--project", "demo",
                "--environment", "dev", "--stdin", stdin_bytes=self.ssh_pem.encode())
        base = ["connection", "create-http", "--project", "demo", "--environment", "dev", "--service", "svc"]
        self.assertEqual(self.fail(*base, "--id", "a", "--secret-id", "gh-token", "--target",
                                   "http://127.0.0.1:8080/api", "--auth", "bearer")["reason"], "target_must_be_origin")
        self.assertEqual(self.fail(*base, "--id", "a", "--secret-id", "gh-token", "--target",
                                   "ftp://127.0.0.1", "--auth", "bearer")["reason"], "invalid_scheme")
        self.assertEqual(self.fail(*base, "--id", "a", "--secret-id", "nope", "--target",
                                   "http://127.0.0.1", "--auth", "bearer")["reason"], "secret_not_found")
        self.assertEqual(self.fail(*base, "--id", "a", "--secret-id", "prod-token", "--target",
                                   "http://127.0.0.1", "--auth", "bearer")["reason"], "secret_scope_mismatch")
        self.assertEqual(self.fail(*base, "--id", "a", "--secret-id", "box-key", "--target",
                                   "http://127.0.0.1", "--auth", "bearer")["reason"], "secret_kind_mismatch")
        self.assertEqual(self.fail(*base, "--id", "a", "--secret-id", "gh-token", "--target",
                                   "http://127.0.0.1", "--auth", "basic")["reason"], "invalid_basic_username")
        self.assertEqual(self.fail(*base, "--id", "a", "--secret-id", "gh-token", "--target",
                                   "http://127.0.0.1", "--auth", "header")["reason"], "invalid_header_name")
        self.assertEqual(self.fail(*base, "--id", "a", "--secret-id", "gh-token", "--secret-version", "5",
                                   "--target", "http://127.0.0.1", "--auth", "bearer")["reason"], "secret_version_not_found")
        self.assertEqual(self.fail(*base, "--id", "a", "--secret-id", "gh-token", "--target", "http://127.0.0.1",
                                   "--auth", "bearer", "--ca-file", str(self.root / "no.pem"))["reason"], "ca_file_missing")
        self.assertEqual(self.fail(*base, "--id", "a", "--secret-id", "gh-token", "--target", "http://127.0.0.1",
                                   "--auth", "bearer", "--cli-program", "x", "--cli-env", "novalue")["reason"], "invalid_cli_env")
        self.assertEqual(self.fail("connection", "create-http", "--project", "demo", "--environment", "qa",
                                   "--service", "svc", "--id", "a", "--secret-id", "gh-token", "--target",
                                   "http://127.0.0.1", "--auth", "bearer")["reason"], "environment_not_found")
        self.assertEqual(self.ok("connection", "list")["connections"], [])

        https = self.ok(*base, "--id", "secure", "--secret-id", "gh-token", "--target", "https://api.example.com",
                        "--auth", "header", "--header-name", "X-Api-Key")
        self.assertEqual(https["http_target"]["port"], 443)
        self.assertEqual(https["http_scope"], {"methods": ["GET", "HEAD"], "path_prefixes": None, "confirm_methods": []})
        plain = self.ok(*base, "--id", "plain", "--secret-id", "gh-token", "--target", "http://example.com",
                        "--auth", "basic", "--basic-username", "bot", "--methods", "all", "--secret-version", "1")
        self.assertEqual((plain["http_target"]["port"], plain["secret_version"]), (80, 1))
        self.assertIsNone(plain["http_scope"]["methods"])

    def test_connection_create_ssh(self) -> None:
        self.seed_project()
        self.ok("secret", "put", "--id", "box-key", "--kind", "ssh_private_key", "--project", "demo",
                "--environment", "dev", "--stdin", stdin_bytes=self.ssh_pem.encode())
        second = sshwire.generate_ed25519_private_key("host2").public.to_authorized_key("host2")
        created = self.ok("connection", "create-ssh", "--id", "box", "--project", "demo", "--environment", "dev",
                          "--service", "ssh-box", "--secret-id", "box-key", "--host", "127.0.0.1", "--port", "2222",
                          "--username", "deploy", "--host-key", self.host_key, "--host-key", second,
                          "--cli-program", "ssh")
        self.assertEqual(created["kind"], "ssh")
        self.assertEqual(created["ssh_target"]["host_keys"], [self.host_key, second])
        self.assertEqual(created["fingerprint"], self.ssh_key.public.fingerprint())
        self.assertTrue(created["public_key"].startswith("ssh-ed25519 "))
        self.assertEqual(created["cli"], {"program": "ssh", "kind": "ssh", "base_url_env": "ZEROPW_API_BASE_URL",
                                          "extra_env": {}})
        self.assertEqual(self.fail("connection", "create-ssh", "--id", "bad", "--project", "demo", "--environment",
                                   "dev", "--service", "s", "--secret-id", "box-key", "--host", "127.0.0.1",
                                   "--username", "deploy", "--host-key", "ssh-rsa AAAAB3Nza")["reason"], "invalid_host_key")
        self.assertEqual(self.fail("connection", "create-ssh", "--id", "bad", "--project", "demo", "--environment",
                                   "dev", "--service", "s", "--secret-id", "box-key", "--host", "127.0.0.1",
                                   "--username", "deploy", "--host-key", "ssh-ed25519 not-base64!!")["reason"],
                         "invalid_host_key")
        self.assertEqual(self.fail("connection", "update-scope", "--id", "box", "--methods", "GET")["reason"],
                         "scope_requires_http")
        self.assertIn("connection_create", self.events())

    def test_switch_credential_validates_version_state(self) -> None:
        self.seed_project()
        self.put_secret()
        self.put_secret(SYNTHETIC_V2)
        self.create_http("gh")
        self.assertEqual(self.fail("connection", "switch-credential", "--id", "gh", "--version", "3")["reason"],
                         "secret_version_not_found")
        self.assertEqual(self.fail("connection", "switch-credential", "--id", "gh", "--version", "1")["reason"],
                         "secret_version_unusable")
        switched = self.ok("connection", "switch-credential", "--id", "gh", "--version", "2")
        self.assertEqual((switched["secret_version"], switched["policy_version"]), (2, 2))
        self.assertIn("connection_switch_credential", self.events())

    # ------------------------------------------------------------ principals
    def test_principal_create_prints_token_once_and_list_hides_it(self) -> None:
        self.init()
        created = self.ok("principal", "create", "--id", "agent-1")
        token = created["token"]
        self.assertTrue(token.startswith("zpwc_"))
        self.assertEqual(self.ctx().policy.authenticate(token).id, "agent-1")
        listing = self.ok("principal", "list")
        self.assertEqual(listing["principals"], [{"id": "agent-1", "status": "active", "runtime": "default",
                                                  "created_at": listing["principals"][0]["created_at"]}])
        self.assertNotIn(token, json.dumps(listing))
        self.assertNotIn(P.hash_token(token), json.dumps(listing))
        self.assertEqual(self.fail("principal", "create", "--id", "agent-1")["reason"], "principal_exists")
        self.assertEqual(self.ok("principal", "disable", "--id", "agent-1")["status"], "disabled")
        self.assertEqual(self.ok("principal", "list")["principals"][0]["status"], "disabled")
        self.assertEqual(self.fail("principal", "disable", "--id", "ghost")["reason"], "principal_not_found")
        events = self.events()
        self.assertIn("principal_create", events)
        self.assertIn("principal_disable", events)
        # The token appears in exactly one command output: the create.
        self.assertEqual(sum(1 for _, out, _ in self.outputs if token in out), 1)

    # ---------------------------------------------------------------- grants
    def test_grant_lifecycle(self) -> None:
        self.seed_project()
        self.put_secret()
        self.create_http("gh")
        self.ok("principal", "create", "--id", "agent-1")
        grant = self.ok("grant", "create", "--principal", "agent-1", "--connection", "gh", "--ttl", "30m", "--max-uses", "3")
        self.assertEqual((grant["status"], grant["max_uses"], grant["policy_version"]), ("active", 3, 1))
        self.assertTrue(grant["expires_at"].endswith("Z"))
        self.assertEqual(self.fail("grant", "create", "--principal", "agent-1", "--connection", "gh", "--ttl", "soon")["reason"],
                         "invalid_ttl")
        self.assertEqual(self.fail("grant", "create", "--principal", "agent-1", "--connection", "gh", "--ttl", "31d")["reason"],
                         "invalid_ttl")
        self.assertEqual(self.fail("grant", "create", "--principal", "ghost", "--connection", "gh")["reason"],
                         "principal_not_found")
        listing = self.ok("grant", "list", "--principal", "agent-1")["grants"]
        self.assertEqual([g["id"] for g in listing], [grant["id"]])
        self.assertEqual(self.ok("grant", "list", "--principal", "other")["grants"], [])
        policy = self.ctx().policy
        self.assertTrue(policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).allowed)

        self.ok("connection", "update-scope", "--id", "gh", "--methods", "GET,POST,PUT")  # widening -> stale
        self.assertEqual(self.ok("grant", "list")["grants"][0]["status"], "stale")
        fresh = self.ok("grant", "regrant", "--id", grant["id"])
        self.assertEqual((fresh["status"], fresh["policy_version"], fresh["replaces"]), ("active", 2, grant["id"]))
        self.assertEqual(fresh["max_uses"], 3)
        self.assertTrue(self.ctx().policy.evaluate("agent-1", "gh", P.Action("http", "PUT", "/repos")).allowed)
        self.assertEqual(self.fail("grant", "regrant", "--id", grant["id"])["reason"], "grant_not_regrantable")

        revoked = self.ok("grant", "revoke", "--id", fresh["id"])
        self.assertEqual(revoked["status"], "revoked")
        self.assertEqual(self.ctx().policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).reason, "grant_revoked")
        self.assertEqual(self.fail("grant", "revoke", "--id", "g-missing")["reason"], "grant_not_found")
        events = self.events()
        for event in ("grant_create", "grant_regrant", "grant_revoke"):
            self.assertIn(event, events)

    # ---------------------------------------------------------- stop/resume
    def test_stop_all_and_resume_reflected_in_policy(self) -> None:
        self.seed_project()
        self.put_secret()
        self.create_http("gh")
        self.ok("principal", "create", "--id", "agent-1")
        self.ok("grant", "create", "--principal", "agent-1", "--connection", "gh")
        stopped = self.ok("stop-all")
        self.assertEqual(stopped, {"stopped": True, "restore_pending": False, "incident_open": None})
        policy = self.ctx().policy
        self.assertTrue(policy.is_stopped())
        self.assertEqual(policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).reason, "global_stop")
        self.assertEqual(policy.usable_connections("agent-1"), [])
        resumed = self.ok("resume")
        self.assertEqual(resumed["stopped"], False)
        self.assertTrue(self.ctx().policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).allowed)
        events = self.events()
        self.assertIn("stop_all", events)
        self.assertIn("resume", events)

    # ------------------------------------------------------------- approvals
    def test_approvals_list_and_approve(self) -> None:
        self.seed_project()
        self.put_secret()
        self.create_http("gh")
        self.ok("principal", "create", "--id", "agent-1")
        self.assertEqual(self.ok("approvals", "list")["approvals"], [])
        digest = P.approval_digest("agent-1", "gh", "DELETE", "/repos/demo", b"")
        self.ctx().policy.request_approval(digest, "agent-1", "gh", "DELETE", "/repos/demo")  # what the gateway does
        pending = self.ok("approvals", "list")["approvals"]
        self.assertEqual([(a["digest"], a["status"], a["method"]) for a in pending], [(digest, "pending", "DELETE")])
        approved = self.ok("approvals", "approve", "--digest", digest)
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(self.fail("approvals", "approve", "--digest", digest)["reason"], "approval_not_pending")
        self.assertEqual(self.fail("approvals", "approve", "--digest", "0" * 64)["reason"], "approval_not_found")
        self.assertTrue(self.ctx().policy.consume_approval(digest, "agent-1", "gh"))
        self.assertIn("approval_grant", self.events())

    # -------------------------------------------------------------- rotation
    def test_rotation_start_activate_finish(self) -> None:
        self.seed_project()
        self.put_secret()
        self.create_http("gh")
        self.ok("principal", "create", "--id", "agent-1")
        grant = self.ok("grant", "create", "--principal", "agent-1", "--connection", "gh")

        started = self.ok("rotation", "start", "--secret-id", "gh-token", "--stdin", stdin_bytes=SYNTHETIC_V2.encode())
        self.assertEqual((started["version"], started["status"], started["previous_active"]), (2, "staged", 1))
        vault = self.ctx().vault
        self.assertEqual(vault.get_meta("gh-token").active_version, 1)
        self.assertEqual(vault.secret_for_trusted_use("gh-token"), SYNTHETIC.encode())
        self.assertEqual(vault.secret_for_trusted_use("gh-token", 2), SYNTHETIC_V2.encode())
        self.assertEqual(self.fail("rotation", "start", "--secret-id", "nope", "--stdin", stdin_bytes=b"x")["reason"],
                         "secret_not_found")

        activated = self.ok("rotation", "activate", "--connection", "gh", "--version", "2")
        self.assertEqual((activated["version"], activated["previous_active"], activated["policy_version"]), (2, 1, 2))
        ctx = self.ctx()
        meta = ctx.vault.get_meta("gh-token")
        self.assertEqual(meta.active_version, 2)
        self.assertEqual([v.status for v in meta.versions], ["retired", "active"])
        connection = ctx.policy.get_connection("gh")
        self.assertEqual((connection.secret_version, connection.policy_version), (2, 2))
        self.assertEqual(ctx.vault.secret_for_trusted_use(connection.secret_id, connection.secret_version), SYNTHETIC_V2.encode())
        self.assertEqual(ctx.policy.get_grant(grant["id"]).status, "active")  # rotation is not widening
        self.assertTrue(ctx.policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).allowed)
        self.assertEqual(self.fail("rotation", "activate", "--connection", "gh", "--version", "9")["reason"],
                         "secret_version_not_found")

        finished = self.ok("rotation", "finish", "--secret-id", "gh-token", "--version", "1")
        self.assertEqual(finished["status"], "retired")
        self.assertTrue(finished["provider_revocation_required"])
        self.assertIn("provider", finished["reminder"])
        self.assertEqual(self.fail("rotation", "finish", "--secret-id", "gh-token", "--version", "2")["reason"],
                         "version_is_active")
        events = self.events()
        self.assertIn("rotation", events)
        self.assertIn("secret_retire", events)
        self.assertIn("connection_switch_credential", events)

    # ---------------------------------------------------- backup / restore
    def test_backup_restore_and_restore_ack(self) -> None:
        self.seed_project()
        self.put_secret()
        self.create_http("gh")
        self.ok("principal", "create", "--id", "agent-1")
        grant = self.ok("grant", "create", "--principal", "agent-1", "--connection", "gh")
        archive = self.root / "backup.json"
        backup = self.ok("backup", "--out", str(archive))
        self.assertEqual(backup["manifest"]["format"], "zeropw-backup-v1")
        self.assertTrue(archive.exists())
        self.assertNotIn(SYNTHETIC, archive.read_text())
        self.assertEqual(archive.stat().st_mode & 0o077, 0)

        self.ok("grant", "revoke", "--id", grant["id"])
        restored = self.ok("restore", "--in", str(archive))
        self.assertTrue(restored["restore_pending"])
        self.assertEqual(restored["reapplied"]["grants"], 1)
        policy = self.ctx().policy
        self.assertTrue(policy.restore_pending())
        self.assertEqual(policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).reason, "restore_pending")
        self.assertEqual(policy.get_grant(grant["id"]).status, "revoked")  # the post-backup revocation stays
        self.assertEqual(self.fail("restore", "--in", str(self.root / "nope.json"))["reason"], "backup_malformed")

        with patch.dict(os.environ, {admin_cli.ADMIN_PASSPHRASE_ENV: "wrong-passphrase"}):
            self.assertEqual(self.fail("restore-ack")["reason"], "admin_reauth_failed")
        self.assertTrue(self.ctx().policy.restore_pending())
        acked = self.ok("restore-ack")
        self.assertEqual((acked["restore_pending"], acked["active_grants"], acked["active_grant_ids"]),
                         (False, 0, []))
        self.assertEqual(acked["stopped"], False)
        self.assertEqual(self.ctx().policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).reason,
                         "grant_revoked")
        fresh = self.ok("grant", "create", "--principal", "agent-1", "--connection", "gh")
        self.assertTrue(self.ctx().policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos"), fresh["id"]).allowed)
        events = self.events()
        for event in ("backup", "restore", "restore_ack", "auth_failed"):
            self.assertIn(event, events)

    def test_recover_rotates_kms_and_revokes_grants(self) -> None:
        self.seed_project()
        self.put_secret()
        self.create_http("gh")
        self.ok("principal", "create", "--id", "agent-1")
        grant = self.ok("grant", "create", "--principal", "agent-1", "--connection", "gh")
        with patch.dict(os.environ, {admin_cli.RECOVERY_PASSPHRASE_ENV: "wrong-recovery-1"}):
            self.assertEqual(self.fail("recover")["reason"], "recovery_passphrase_invalid")
        self.assertEqual(self.ctx().policy.get_grant(grant["id"]).status, "active")
        recovered = self.ok("recover")
        self.assertNotEqual(recovered["kms_key_id"], "local-dev-kms-1")
        self.assertEqual(recovered["grants_revoked"], 1)
        ctx = self.ctx()
        self.assertEqual(ctx.kms.key_id, recovered["kms_key_id"])
        self.assertEqual(ctx.policy.get_grant(grant["id"]).status, "revoked")
        self.assertEqual(self.ok("secret", "reveal", "--id", "gh-token")["value"], SYNTHETIC)
        events = self.events()
        self.assertIn("recover", events)
        self.assertIn("auth_failed", events)

    # ---------------------------------------------------------- audit output
    def test_audit_tail_and_alerts_are_json(self) -> None:
        self.seed_project()
        self.put_secret()
        tail = self.ok("audit", "tail", "--limit", "2")["records"]
        self.assertEqual(len(tail), 2)
        self.assertEqual(tail[-1]["event"], "secret_put")
        self.assertEqual(set(tail[-1]) >= {"ts", "event", "caller", "result"}, True)
        self.assertEqual(self.ok("alerts", "--limit", "5")["alerts"], [])
        self.ok("secret", "reveal", "--id", "gh-token")
        alerts = self.ok("alerts")["alerts"]
        self.assertEqual(alerts[-1]["alert"], "secret_reveal")

    # ------------------------------------- verification findings (admin round 0)
    def test_secret_value_on_argv_is_a_usage_error_and_never_echoed(self) -> None:
        """admin-argv-abbrev-echo / ADM-8: ``--value`` is not an abbreviation of ``--value-file``."""
        self.seed_project()
        self.put_secret()
        base = ("secret", "put", "--id", "x", "--kind", "api_key", "--project", "demo", "--environment", "dev")
        cases = (["--value", SYNTHETIC], ["--val", SYNTHETIC], ["--value=" + SYNTHETIC],
                 ["--stdin", "--value", SYNTHETIC], ["--stdin", "--value=" + SYNTHETIC],
                 ["--stdin", "--value", "-" + SYNTHETIC],            # a value that itself looks like a flag
                 ["--stdin", "--value", "--" + SYNTHETIC + "=1"],
                 ["--stdin", "--bogus", SYNTHETIC], ["--stdin", SYNTHETIC])
        for extra in cases:
            error = self.fail(*base, *extra, code=2, stdin_bytes=b"synthetic-other\n")
            self.assertEqual((error["error"], error["reason"]), ("UsageError", "usage"), extra)
            self.assertNotIn(SYNTHETIC, json.dumps(error), extra)
        # The mistyped option is named; the stray value never is, even when it starts with "-".
        for extra in (["--stdin", "--value", SYNTHETIC], ["--stdin", "--value", "-" + SYNTHETIC],
                      ["--stdin", "--value", "--" + SYNTHETIC + "=1"]):
            error = self.fail(*base, *extra, code=2, stdin_bytes=b"synthetic-other\n")
            self.assertEqual(error["detail"], "unrecognized arguments: 2 (not accepted: --value); values are not echoed")
        error = self.fail(*base, "--stdin", "--bogus", SYNTHETIC, code=2, stdin_bytes=b"synthetic-other\n")
        self.assertEqual(error["detail"], "unrecognized arguments: 2; values are not echoed")
        error = self.fail("project", "list", "--id", SYNTHETIC, code=2)  # an option of another subcommand
        self.assertEqual(error["detail"], "unrecognized arguments: 2 (not accepted: --id); values are not echoed")
        self.assertEqual(self.fail("rotation", "start", "--secret-id", "gh-token", "--value", SYNTHETIC, code=2)["reason"],
                         "usage")
        self.assertEqual(self.fail("rotation", "start", "--secret-id", "gh-token", "--stdin", "--val", "-" + SYNTHETIC,
                                   code=2, stdin_bytes=b"synthetic-other\n")["detail"],
                         "unrecognized arguments: 2 (not accepted: --val); values are not echoed")
        # Nothing reached the vault from any of those attempts.
        self.assertEqual([v["version"] for v in self.ok("secret", "versions", "--id", "gh-token")["versions"]], [1])
        self.assertEqual(self.fail("secret", "versions", "--id", "x")["reason"], "secret_not_found")
        # A missing --value-file is reported without the path: it could be a value typed by mistake.
        error = self.fail(*base, "--value-file", str(self.root / SYNTHETIC))
        self.assertEqual(error, {"error": "FileNotFoundError", "reason": "file_not_found"})
        error = self.fail("rotation", "start", "--secret-id", "gh-token", "--value-file", str(self.root / SYNTHETIC))
        self.assertEqual(error, {"error": "FileNotFoundError", "reason": "file_not_found"})
        for parser in (admin_cli.build_parser(),):
            self.assertFalse(parser.allow_abbrev)
            for action in parser._actions:
                if isinstance(getattr(action, "choices", None), dict):
                    for sub in action.choices.values():
                        self.assertFalse(sub.allow_abbrev, sub.prog)
        # tearDown additionally sweeps every captured stdout/stderr for the synthetic values.

    def test_secret_listings_carry_no_value_derived_metadata(self) -> None:
        """secret-listing-hash-length-oracle: non-SSH kinds expose ``public == {}``, on the CLI and on disk."""
        self.seed_project()
        for secret_id, kind, value in (("gh-token", "api_key", SYNTHETIC), ("db-pass", "password", "synthetic-pw"),
                                       ("env", "env_var", "synthetic-env")):
            self.ok("secret", "put", "--id", secret_id, "--kind", kind, "--project", "demo", "--environment", "dev",
                    "--stdin", stdin_bytes=value.encode())
        self.ok("rotation", "start", "--secret-id", "gh-token", "--stdin", stdin_bytes=SYNTHETIC_V2.encode())
        listing = self.ok("secret", "list")
        self.assertEqual([s["id"] for s in listing["secrets"]], ["db-pass", "env", "gh-token"])
        for secret in listing["secrets"]:
            for version in secret["versions"]:
                self.assertEqual(version["public"], {}, secret["id"])
        versions = self.ok("secret", "versions", "--id", "gh-token")
        self.assertEqual([v["public"] for v in versions["versions"]], [{}, {}])
        for text in (json.dumps(listing), json.dumps(versions)):
            for needle in ("sha256_prefix", "length", "sha256", "ciphertext", "nonce"):
                self.assertNotIn(needle, text)
        # Nothing derived from a value is persisted either (it would end up in every backup archive).
        doc = json.loads((self.state / "vault" / "secrets.json").read_text(encoding="utf-8"))
        for entry in doc["secrets"].values():
            for record in entry["versions"].values():
                self.assertEqual(record["public"], {})
        archive = self.root / "backup.json"
        self.ok("backup", "--out", str(archive))
        self.assertNotIn("sha256_prefix", archive.read_text(encoding="utf-8"))
        # SSH keys keep their genuinely public material and nothing else.
        self.ok("secret", "put", "--id", "box-key", "--kind", "ssh_private_key", "--project", "demo",
                "--environment", "dev", "--stdin", stdin_bytes=self.ssh_pem.encode())
        ssh = self.ok("secret", "versions", "--id", "box-key")["versions"][0]["public"]
        self.assertEqual(set(ssh), set(admin_cli.PUBLIC_METADATA_KEYS))
        self.assertEqual(ssh["fingerprint"], self.ssh_key.public.fingerprint())
        self.assertEqual(ssh["public_key"], self.ssh_key.public.to_authorized_key("demo"))

    def test_connection_create_requires_a_usable_secret_version(self) -> None:
        """ADM-2: a pinned version must be active/staged; an unpinned connection needs an active version."""
        self.seed_project()
        self.put_secret()
        self.ok("secret", "put", "--id", "gh-token", "--kind", "api_key", "--project", "demo", "--environment", "dev",
                "--stdin", "--staged", stdin_bytes=SYNTHETIC_V2.encode())
        self.ok("secret", "retire", "--id", "gh-token", "--version", "2")
        base = ["connection", "create-http", "--project", "demo", "--environment", "dev", "--service", "svc",
                "--secret-id", "gh-token", "--target", "http://127.0.0.1:1", "--auth", "bearer"]
        error = self.fail(*base, "--id", "pin-retired", "--secret-version", "2")
        self.assertEqual((error["error"], error["reason"], error["detail"]), ("InvalidInput", "secret_version_unusable", "retired"))
        self.ok("secret", "revoke", "--id", "gh-token", "--version", "1")  # the active version: active_version -> None
        error = self.fail(*base, "--id", "pin-revoked", "--secret-version", "1")
        self.assertEqual((error["reason"], error["detail"]), ("secret_version_unusable", "revoked"))
        error = self.fail(*base, "--id", "unpinned")
        self.assertEqual((error["error"], error["reason"]), ("NotFound", "secret_no_active_version"))
        self.assertEqual(self.fail(*base, "--id", "pin-missing", "--secret-version", "9")["reason"], "secret_version_not_found")
        self.assertEqual(self.ok("connection", "list")["connections"], [])
        self.assertNotIn("connection_create", self.events())
        # A staged version is usable when pinned (rotation), an active one when unpinned.
        self.ok("secret", "put", "--id", "gh-token", "--kind", "api_key", "--project", "demo", "--environment", "dev",
                "--stdin", "--staged", stdin_bytes=b"synthetic-v3")
        self.assertEqual(self.ok(*base, "--id", "pin-staged", "--secret-version", "3")["secret_version"], 3)
        self.assertEqual(self.fail(*base, "--id", "still-unpinned")["reason"], "secret_no_active_version")
        self.ok("secret", "put", "--id", "gh-token", "--kind", "api_key", "--project", "demo", "--environment", "dev",
                "--stdin", stdin_bytes=b"synthetic-v4")
        self.assertIsNone(self.ok(*base, "--id", "unpinned")["secret_version"])
        # SSH connections go through the same check.
        self.ok("secret", "put", "--id", "box-key", "--kind", "ssh_private_key", "--project", "demo",
                "--environment", "dev", "--stdin", "--staged", stdin_bytes=self.ssh_pem.encode())
        ssh = ["connection", "create-ssh", "--project", "demo", "--environment", "dev", "--service", "s",
               "--secret-id", "box-key", "--host", "127.0.0.1", "--username", "deploy", "--host-key", self.host_key]
        self.assertEqual(self.fail(*ssh, "--id", "box")["reason"], "secret_no_active_version")
        self.assertEqual(self.ok(*ssh, "--id", "box", "--secret-version", "1")["secret_version"], 1)

    def test_connection_target_malformed_bracket_hosts_are_invalid_host(self) -> None:
        """ADM-3: urlsplit's ValueError for malformed bracketed hosts is a fixed reason code, not internal_error."""
        self.seed_project()
        self.put_secret()
        base = ["connection", "create-http", "--id", "a", "--project", "demo", "--environment", "dev", "--service", "svc",
                "--secret-id", "gh-token", "--auth", "bearer", "--target"]
        for target in ("http://[::1", "http://[evil]:80", "http://[evil]", "http://[", "http://][", "http://", "http:"):
            error = self.fail(*base, target)
            self.assertEqual((error["error"], error["reason"]), ("InvalidInput", "invalid_host"), target)
        for target in ("http://127.0.0.1:99999", "http://127.0.0.1:0x50", "http://127.0.0.1:-1"):
            error = self.fail(*base, target)
            self.assertEqual((error["error"], error["reason"]), ("InvalidInput", "invalid_port"), target)
        self.assertEqual(self.fail(*base, "http://user:pw@127.0.0.1")["reason"], "target_must_be_origin")
        self.assertEqual(self.ok("connection", "list")["connections"], [])
        created = self.ok(*base, "http://[::1]:8080")  # a well-formed IPv6 literal is a valid target
        self.assertEqual((created["http_target"]["host"], created["http_target"]["port"]), ("::1", 8080))

    def test_grant_ttl_rejects_non_ascii_digits(self) -> None:
        """ADM-4: only ASCII digits form a TTL; Unicode digit-class characters are invalid_ttl."""
        self.seed_project()
        self.put_secret()
        self.create_http("gh")
        self.ok("principal", "create", "--id", "agent-1")
        for ttl in ("²", "٣٠m", "①h", "1³m", "１０m", "", " ", "30 m", "1.5h", "+30m",
                    "0", "0m", "1x", "m"):
            self.assertTrue(ttl == "" or ttl.strip() == "" or not ttl.isascii() or True)  # documents the mix of cases
            error = self.fail("grant", "create", "--principal", "agent-1", "--connection", "gh", "--ttl", ttl)
            self.assertEqual((error["error"], error["reason"]), ("InvalidInput", "invalid_ttl"), repr(ttl))
        self.assertEqual(self.ok("grant", "list")["grants"], [])
        self.assertEqual(admin_cli._parse_ttl(" 45S "), 45)
        self.assertEqual(admin_cli._parse_ttl("2d"), 172800)
        self.assertEqual(admin_cli._parse_ttl("90"), 90)

    def test_ssh_host_keys_are_stored_in_canonical_form(self) -> None:
        """ADM-5: tab-separated, padded or options-prefixed authorized_keys lines are normalised."""
        self.seed_project()
        self.ok("secret", "put", "--id", "box-key", "--kind", "ssh_private_key", "--project", "demo",
                "--environment", "dev", "--stdin", stdin_bytes=self.ssh_pem.encode())
        public = sshwire.generate_ed25519_private_key("h").public
        b64 = public.to_authorized_key().split()[1]
        canonical = public.to_authorized_key("myhost")
        lines = [f"ssh-ed25519\t{b64}\tmyhost",
                 f'no-port-forwarding,command="/bin/true" ssh-ed25519 {b64} myhost',
                 f"  ssh-ed25519  {b64}   myhost  ",
                 f"ssh-ed25519 {b64}"]
        argv = ["connection", "create-ssh", "--project", "demo", "--environment", "dev", "--service", "s",
                "--secret-id", "box-key", "--host", "127.0.0.1", "--port", "2222", "--username", "deploy"]
        for line in lines:
            argv += ["--host-key", line]
        created = self.ok(*argv, "--id", "box")
        self.assertEqual(created["ssh_target"]["host_keys"], [canonical, canonical, canonical, public.to_authorized_key()])
        for stored in self.ctx().policy.get_connection("box").ssh_target.host_keys:
            self.assertTrue(stored.startswith("ssh-ed25519 "))
            self.assertNotIn("\t", stored)
            self.assertEqual(sshwire.parse_authorized_key(stored).key_bytes, public.key_bytes)
        # known_hosts markers are not host keys, and a comment line is not a key.
        for bad in (f"@revoked ssh-ed25519 {b64}", f"@cert-authority ssh-ed25519 {b64}", f"# ssh-ed25519 {b64}"):
            self.assertEqual(self.fail(*argv, "--id", "bad", "--host-key", bad)["reason"], "invalid_host_key", bad)
        self.assertEqual([c["id"] for c in self.ok("connection", "list")["connections"]], ["box"])

    def test_audit_limit_validation_and_unparseable_lines(self) -> None:
        """ADM-6: --limit must be >= 1 (usage error) and one bad line does not hide the log."""
        self.seed_project()
        self.put_secret()
        for argv in (("audit", "tail", "--limit", "0"), ("audit", "tail", "--limit", "-1"), ("alerts", "--limit", "0"),
                     ("alerts", "--limit", "-5"), ("audit", "tail", "--limit", "x"), ("audit", "tail", "--limit", "1.5")):
            self.assertEqual(self.fail(*argv, code=2)["reason"], "usage", argv)
        before = self.ok("audit", "tail", "--limit", "500")
        self.assertEqual(before["unparseable_lines"], 0)
        total = len(before["records"])
        self.assertEqual(len(self.ok("audit", "tail", "--limit", "1")["records"]), 1)
        with (self.state / "audit" / "audit.jsonl").open("a", encoding="utf-8") as stream:
            stream.write('{"event": "secret_put", "truncated\n')
            stream.write("[1, 2, 3]\n")
        tail = self.ok("audit", "tail", "--limit", "2")
        self.assertEqual(len(tail["records"]), 2)
        self.assertEqual(tail["records"][-1]["event"], "secret_put")
        self.assertEqual(tail["unparseable_lines"], 2)
        self.assertEqual(len(self.ok("audit", "tail", "--limit", "500")["records"]), total)
        (self.state / "audit" / "alerts.jsonl").write_text("not json\n", encoding="utf-8")
        self.assertEqual(self.ok("alerts"), {"alerts": [], "unparseable_lines": 1})

    def test_serve_refuses_ipv6_loopback_explicitly(self) -> None:
        """ADM-7: the server is AF_INET only, so IPv6 loopback is an explicit unsupported error."""
        self.init()
        for listen in ("[::1]:0", "::1:0", "[0:0:0:0:0:0:0:1]:0"):
            error = self.fail("serve", "--listen", listen)
            self.assertEqual((error["error"], error["reason"]), ("Unsupported", "listen_ipv6_unsupported"), listen)
        self.assertEqual(self.fail("serve", "--listen", "[::]:0")["reason"], "listen_not_loopback")
        self.assertEqual(self.fail("serve", "--listen", "[fe80::1]:0")["reason"], "listen_not_loopback")

    def test_semantically_corrupt_state_reports_state_corrupt(self) -> None:
        """ADM-9: valid JSON with missing or mistyped fields is a fixed StateError, never internal_error."""
        self.seed_project()
        self.put_secret()
        self.create_http("gh")
        self.ok("principal", "create", "--id", "agent-1")
        grant = self.ok("grant", "create", "--principal", "agent-1", "--connection", "gh")
        self.ok("stop-all")
        self.ok("resume")  # materialises policy/control.json
        dek = json.loads((self.state / "vault" / "secrets.json").read_text(encoding="utf-8"))["dek"]
        cases = [
            ("policy/grants.json", {"g-bogus": {"foo": "bar"}}, ("grant", "list")),
            ("policy/grants.json", {grant["id"]: {"id": grant["id"]}}, ("grant", "revoke", "--id", grant["id"])),
            ("policy/grants.json", {grant["id"]: "not-a-dict"}, ("grant", "list")),
            ("policy/connections.json", {"gh": {"id": "gh", "kind": "http"}}, ("connection", "show", "--id", "gh")),
            ("policy/connections.json", {"gh": "not-a-dict"}, ("connection", "list")),
            ("policy/connections.json", {"gh": {"id": "gh", "kind": "http"}},
             ("grant", "create", "--principal", "agent-1", "--connection", "gh")),
            ("policy/principals.json", {"agent-1": {"status": "active"}}, ("principal", "list")),
            ("policy/principals.json", {"agent-1": 5}, ("principal", "list")),
            ("policy/control.json", {"stopped": False, "restore_pending": False, "approvals": "nope"}, ("approvals", "list")),
            ("policy/control.json", [1, 2], ("stop-all",)),
            ("vault/secrets.json", {"dek": dek, "secrets": {"gh-token": {"project": "demo"}}}, ("secret", "list")),
            ("vault/secrets.json", {"dek": dek, "secrets": {"gh-token": {
                "project": "demo", "environment": "dev", "kind": "api_key", "active_version": 1,
                "versions": {"1": {"status": "active"}}}}}, ("secret", "versions", "--id", "gh-token")),
            ("vault/secrets.json", {"dek": dek, "secrets": "x"}, ("secret", "list")),
            ("vault/secrets.json", {"secrets": {}}, ("secret", "list")),
            ("projects.json", {"demo": "oops"}, ("project", "list")),
            ("projects.json", {"demo": {"name": "demo"}}, ("project", "list")),
            ("admin.json", {"salt": "AAAA"}, ("secret", "reveal", "--id", "gh-token")),
        ]
        for name, doc, argv in cases:
            path = self.state / name
            good = path.read_text(encoding="utf-8")
            path.write_text(json.dumps(doc), encoding="utf-8")
            try:
                error = self.fail(*argv)
            finally:
                path.write_text(good, encoding="utf-8")
            self.assertEqual((error["error"], error["reason"]), ("StateError", "state_corrupt"), (name, argv))
            self.assertIn(error["detail"], {"KeyError", "TypeError", "AttributeError", "ValueError"}, (name, argv))
            self.assertEqual(set(error), {"error", "reason", "detail"})
        # Malformed JSON is the store's own state_corrupt (naming the document); a malformed
        # wrapped DEK keeps its specific code.  The state is intact after all of the above.
        path = self.state / "policy" / "grants.json"
        good = path.read_text(encoding="utf-8")
        path.write_text("{not json", encoding="utf-8")
        self.assertEqual(self.fail("grant", "list"), {"error": "StateError", "reason": "state_corrupt", "detail": "policy/grants.json"})
        path.write_text(good, encoding="utf-8")
        path = self.state / "vault" / "secrets.json"
        good = path.read_text(encoding="utf-8")
        path.write_text(json.dumps({"dek": "x", "secrets": {}}), encoding="utf-8")
        self.assertEqual(self.fail("secret", "list")["reason"], "wrapped_key_malformed")
        path.write_text(good, encoding="utf-8")
        self.assertEqual([g["id"] for g in self.ok("grant", "list")["grants"]], [grant["id"]])
        self.assertEqual(self.ok("secret", "reveal", "--id", "gh-token")["value"], SYNTHETIC)

    def test_backup_ignores_planted_tmp_symlink_and_keeps_0600(self) -> None:
        """backup-tmp-symlink-mode-bypass: the temp file is O_EXCL|O_NOFOLLOW with an unpredictable name."""
        self.seed_project()
        self.put_secret()
        outdir = self.root / "backups"
        outdir.mkdir()
        victim = self.root / "victim.txt"
        victim.write_text("victim-content", encoding="utf-8")
        os.chmod(victim, 0o644)
        out = outdir / "backup.json"
        (outdir / "backup.json.tmp").symlink_to(victim)  # the old predictable temp name
        out.symlink_to(victim)                            # and the destination itself
        result = self.ok("backup", "--out", str(out))
        self.assertEqual(victim.read_text(encoding="utf-8"), "victim-content")
        self.assertEqual(victim.stat().st_mode & 0o777, 0o644)
        self.assertFalse(out.is_symlink())
        self.assertEqual(out.stat().st_mode & 0o777, 0o600)
        self.assertTrue((outdir / "backup.json.tmp").is_symlink())  # untouched: never used as a temp name
        self.assertEqual(sorted(p.name for p in outdir.iterdir()), ["backup.json", "backup.json.tmp"])
        archive = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(archive["manifest"], result["manifest"])
        self.assertNotIn(SYNTHETIC, out.read_text(encoding="utf-8"))
        # A failed write leaves no temp file behind.
        self.assertEqual(self.fail("backup", "--out", str(self.root / "nodir" / "b.json"))["reason"], "file_not_found")
        self.assertFalse((self.root / "nodir").exists())

    def test_restore_keeps_a_global_stop_and_restore_ack_does_not_lift_it(self) -> None:
        """restore-reverts-global-stop: an archive taken while running never lifts a later stop-all."""
        self.seed_project()
        self.put_secret()
        self.create_http("gh")
        self.ok("principal", "create", "--id", "agent-1")
        self.ok("grant", "create", "--principal", "agent-1", "--connection", "gh")
        archive = self.root / "backup.json"
        self.ok("backup", "--out", str(archive))
        control = json.loads(archive.read_text(encoding="utf-8"))["documents"]["policy/control.json"]
        self.assertFalse((control or {}).get("stopped"))
        self.ok("stop-all")
        restored = self.ok("restore", "--in", str(archive))
        self.assertEqual((restored["stopped"], restored["restore_pending"]), (True, True))
        self.assertIn("global stop stays set until resume", restored["next"])
        policy = self.ctx().policy
        self.assertTrue(policy.is_stopped())
        # Both flags deny; restore_pending is reported first because it is checked first.
        self.assertEqual(policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).reason, "restore_pending")
        self.assertEqual(policy.usable_connections("agent-1"), [])
        acked = self.ok("restore-ack")
        self.assertEqual((acked["stopped"], acked["restore_pending"]), (True, False))
        self.assertIn("global stop is still set", acked["note"])
        policy = self.ctx().policy
        self.assertTrue(policy.is_stopped())
        self.assertFalse(policy.restore_pending())
        self.assertEqual(policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).reason, "global_stop")
        self.assertEqual(policy.usable_connections("agent-1"), [])
        self.assertEqual(self.ok("resume"), {"stopped": False, "restore_pending": False, "incident_open": None})
        self.assertTrue(self.ctx().policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).allowed)
        # resume before restore-ack lifts only the stop; restore_pending still closes execution.
        self.ok("stop-all")
        self.ok("restore", "--in", str(archive))
        resumed = self.ok("resume")
        self.assertEqual((resumed["stopped"], resumed["restore_pending"]), (False, True))
        self.assertIn("restore-ack", resumed["note"])
        self.assertEqual(self.ctx().policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).reason, "restore_pending")
        acked = self.ok("restore-ack")
        self.assertEqual((acked["stopped"], acked["restore_pending"]), (False, False))
        self.assertIn("execution is open", acked["note"])

    def test_restore_refuses_an_archive_the_current_kms_cannot_open(self) -> None:
        """restore-kms-mismatch-bricks-reopen / ADM-1: nothing is written and the state still opens."""
        self.seed_project()
        self.put_secret()
        self.create_http("gh")
        archive = self.root / "pre-recover.json"
        self.ok("backup", "--out", str(archive))
        recovered = self.ok("recover")  # rotates the KMS key: the archive's DEK is wrapped under the old one
        self.assertNotEqual(recovered["kms_key_id"], "local-dev-kms-1")
        self.ok("connection", "update-scope", "--id", "gh", "--methods", "GET")  # post-recover state that must survive
        error = self.fail("restore", "--in", str(archive))
        self.assertEqual(error, {"error": "StateError", "reason": "backup_kms_mismatch"})
        ctx = self.ctx()  # still opens
        self.assertEqual(ctx.kms.key_id, recovered["kms_key_id"])
        self.assertEqual(ctx.policy.get_connection("gh").http_scope.methods, ("GET",))
        self.assertFalse(ctx.policy.restore_pending())
        self.assertEqual(ctx.vault.secret_for_trusted_use("gh-token"), SYNTHETIC.encode())
        self.assertEqual(self.ok("secret", "reveal", "--id", "gh-token")["value"], SYNTHETIC)
        restores = [(r["result"], r["reason"]) for r in ctx.audit.tail(500) if r["event"] == "restore"]
        self.assertEqual(restores, [("denied", "backup_kms_mismatch")])
        # A backup of another state directory (same key id, different master key) is refused the same way.
        other, fresh = self.root / "other", self.root / "fresh"
        self.ok("init", state=other)
        foreign = self.root / "foreign.json"
        self.ok("backup", "--out", str(foreign), state=other)
        self.assertEqual(json.loads(foreign.read_text(encoding="utf-8"))["manifest"]["kms_key_id"], "local-dev-kms-1")
        self.ok("init", state=fresh)
        self.assertEqual(self.fail("restore", "--in", str(foreign), state=fresh)["reason"], "backup_kms_mismatch")
        self.assertEqual(self.ok("project", "list", state=fresh)["projects"], [])
        self.assertFalse(Context.open(fresh).policy.restore_pending())
        # An archive the current key can open restores normally.
        current = self.root / "current.json"
        self.ok("backup", "--out", str(current))
        self.assertTrue(self.ok("restore", "--in", str(current))["restore_pending"])
        self.assertEqual(self.ok("restore-ack")["restore_pending"], False)

    def test_only_reveal_prints_a_secret_value_across_the_command_surface(self) -> None:
        """Every command family runs once; exactly the ``secret reveal`` outputs carry a value."""
        self.seed_project()
        self.put_secret()
        self.ok("secret", "put", "--id", "box-key", "--kind", "ssh_private_key", "--project", "demo",
                "--environment", "dev", "--stdin", stdin_bytes=self.ssh_pem.encode())
        self.ok("secret", "list")
        self.ok("secret", "versions", "--id", "gh-token")
        self.create_http("gh")
        self.ok("connection", "create-ssh", "--id", "box", "--project", "demo", "--environment", "dev", "--service", "s",
                "--secret-id", "box-key", "--host", "127.0.0.1", "--username", "deploy", "--host-key", self.host_key)
        self.ok("connection", "list")
        self.ok("connection", "show", "--id", "gh")
        self.ok("connection", "update-scope", "--id", "gh", "--methods", "GET")
        self.ok("principal", "create", "--id", "agent-1")
        self.ok("principal", "list")
        grant = self.ok("grant", "create", "--principal", "agent-1", "--connection", "gh")
        self.ok("grant", "list")
        self.ok("rotation", "start", "--secret-id", "gh-token", "--stdin", stdin_bytes=SYNTHETIC_V2.encode())
        self.ok("rotation", "activate", "--connection", "gh", "--version", "2")
        self.ok("rotation", "finish", "--secret-id", "gh-token", "--version", "1")
        self.ok("secret", "put", "--id", "gh-token", "--kind", "api_key", "--project", "demo", "--environment", "dev",
                "--stdin", "--staged", stdin_bytes=b"synthetic-v3")
        self.ok("connection", "switch-credential", "--id", "gh", "--version", "3")
        self.ok("connection", "switch-credential", "--id", "gh", "--version", "2")
        self.ok("secret", "retire", "--id", "gh-token", "--version", "3")
        self.ok("secret", "revoke", "--id", "gh-token", "--version", "3")
        self.ok("stop-all")
        self.ok("resume")
        digest = P.approval_digest("agent-1", "gh", "DELETE", "/repos/demo", b"")
        self.ctx().policy.request_approval(digest, "agent-1", "gh", "DELETE", "/repos/demo")
        self.ok("approvals", "list")
        self.ok("approvals", "approve", "--digest", digest)
        archive = self.root / "backup.json"
        self.ok("backup", "--out", str(archive))
        self.ok("restore", "--in", str(archive))
        self.ok("restore-ack")
        self.ok("connection", "update-scope", "--id", "gh", "--methods", "GET,POST")  # widening -> stale
        fresh = self.ok("grant", "regrant", "--id", grant["id"])
        self.ok("grant", "revoke", "--id", fresh["id"])
        self.ok("connection", "disable", "--id", "box")
        self.ok("principal", "disable", "--id", "agent-1")
        self.ok("recover")
        self.ok("audit", "tail", "--limit", "500")
        self.ok("alerts")
        self.fail("serve", "--listen", "0.0.0.0:1")
        self.assertEqual(self.ok("secret", "reveal", "--id", "gh-token", "--version", "2")["value"], SYNTHETIC_V2)
        self.assertEqual(self.ok("secret", "reveal", "--id", "gh-token", "--version", "1")["value"], SYNTHETIC)
        self.assertGreaterEqual(len(self.outputs), 40)
        printed = [argv for argv, out, _ in self.outputs if SYNTHETIC_RE.search(out)]
        self.assertEqual([argv[2:4] for argv in printed], [["secret", "reveal"], ["secret", "reveal"]])
        self.assertEqual([argv for argv, _, err in self.outputs if SYNTHETIC_RE.search(err)], [])
        private_line = self.ssh_pem.splitlines()[1]
        self.assertEqual([argv for argv, out, err in self.outputs if private_line in out + err], [])
        for path in self.state.rglob("*"):
            if path.is_file():
                data = path.read_bytes()
                for needle in (SYNTHETIC, SYNTHETIC_V2, "synthetic-v3", private_line):
                    self.assertNotIn(needle.encode(), data, path)

    # ------------------------------------------------------------------ serve
    def test_serve_without_tools_fails_with_json(self) -> None:
        self.init()
        with patch.dict(sys.modules, {"zeropw.tools": None}):
            error = self.fail("serve", "--listen", "127.0.0.1:0")
        self.assertEqual(error["reason"], "tools_unavailable")

    def test_serve_refuses_non_loopback_and_bad_listen(self) -> None:
        self.init()
        self.assertEqual(self.fail("serve", "--listen", "0.0.0.0:0")["reason"], "listen_not_loopback")
        self.assertEqual(self.fail("serve", "--listen", "127.0.0.1")["reason"], "invalid_listen")
        self.assertEqual(self.fail("serve", "--listen", "127.0.0.1:99999")["reason"], "invalid_listen")

    @unittest.skipUnless(HAS_TOOLS, "zeropw.tools is not available yet")
    def test_serve_reports_signer_unavailable_when_missing(self) -> None:
        self.init()
        stop = threading.Event()
        out = io.StringIO()
        problems: list[str] = []

        def client() -> None:
            try:
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline and "\n" not in out.getvalue():
                    time.sleep(0.05)
                lines = out.getvalue().splitlines()
                if not lines:
                    problems.append("no startup line")
                    return
                startup = json.loads(lines[0])
                with urlopen(startup["url"] + "/healthz", timeout=5) as response:
                    if response.status != 200:
                        problems.append(f"healthz status {response.status}")
            except Exception as exc:  # noqa: BLE001 - reported through the assertion below
                problems.append(repr(exc))
            finally:
                stop.set()

        worker = threading.Thread(target=client, daemon=True)
        worker.start()
        try:
            with patch.dict(sys.modules, {"zeropw.signer": None}), contextlib.redirect_stdout(out):
                payload = admin_cli.run_serve(self.state, "127.0.0.1:0", quiet=True, stop_event=stop, install_signals=False)
        finally:
            stop.set()
            worker.join(10)
        self.assertEqual(problems, [])
        self.assertEqual(payload["ssh_signer"], "unavailable")
        self.assertTrue(payload["url"].startswith("http://127.0.0.1:"))
        self.assertEqual(json.loads(out.getvalue().splitlines()[0]), payload)

    @unittest.skipUnless(HAS_TOOLS, "zeropw.tools is not available yet")
    def test_serve_subprocess_smoke(self) -> None:
        self.init()
        env = {**os.environ, "PYTHONPATH": str(ROOT)}
        proc = subprocess.Popen([PYTHON, "-m", "zeropw.admin_cli", "--state-dir", str(self.state), "serve",
                                 "--listen", "127.0.0.1:0", "--quiet"], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self._kill, proc)
        first: dict[str, str] = {}

        def reader() -> None:
            assert proc.stdout is not None
            first["line"] = proc.stdout.readline()

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        thread.join(30)
        self.assertIn("line", first, "serve did not print its startup line")
        startup = json.loads(first["line"])
        self.assertIn("url", startup)
        self.assertEqual(startup["pid"], proc.pid)
        self.assertIn(startup["ssh_signer"], ("available", "unavailable"))
        with urlopen(startup["url"] + "/healthz", timeout=5) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read())["status"], "ok")
        proc.send_signal(signal.SIGTERM)
        _, stderr = proc.communicate(timeout=30)
        self.assertEqual(proc.returncode, 0, stderr)

    @unittest.skipUnless(HAS_TOOLS, "zeropw.tools is not available yet")
    def test_serve_cancels_runs_and_closes_signer_sockets_revoked_by_another_process(self) -> None:
        """PL-2: grant revoke / principal disable / restore from a separate admin_cli reach a running serve."""
        from zeropw import tools
        from zeropw.errors import AuthFailed as AuthFailedError

        self.seed_project()
        self.put_secret()
        sleeper = self.root / "sleeper.py"
        sleeper.write_text(f"#!{PYTHON}\nimport sys, time\nopen(sys.argv[2], 'w').write('ready')\n"
                           "time.sleep(float(sys.argv[1]))\nopen(sys.argv[3], 'w').write('finished')\n")
        sleeper.chmod(0o700)
        self.create_http("gh", "--cli-program", str(sleeper))
        self.ok("secret", "put", "--id", "box-key", "--kind", "ssh_private_key", "--project", "demo",
                "--environment", "dev", "--stdin", stdin_bytes=self.ssh_pem.encode())
        self.ok("connection", "create-ssh", "--id", "box", "--project", "demo", "--environment", "dev", "--service", "s",
                "--secret-id", "box-key", "--host", "127.0.0.1", "--username", "deploy", "--host-key", self.host_key)
        self.ok("principal", "create", "--id", "agent-1")
        self.ok("principal", "create", "--id", "agent-2")
        http_grant = self.ok("grant", "create", "--principal", "agent-1", "--connection", "gh")["id"]
        ssh_grant = self.ok("grant", "create", "--principal", "agent-2", "--connection", "box")["id"]

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
                startup.append(payload)   # the serve startup line; command output passes through
            else:
                original_emit(payload)

        stop = threading.Event()
        emit_patch = patch.object(admin_cli, "_emit", emit)
        emit_patch.start()
        self.addCleanup(emit_patch.stop)
        with patch.object(admin_cli, "Context", CapturingContext):
            serve = threading.Thread(target=admin_cli.run_serve, args=(self.state, "127.0.0.1:0"),
                                     kwargs={"quiet": True, "stop_event": stop, "install_signals": False}, daemon=True)
            serve.start()
            self.addCleanup(serve.join, 30)
            self.addCleanup(stop.set)
            deadline = time.monotonic() + 30
            while not startup and time.monotonic() < deadline:
                time.sleep(0.05)
        self.assertTrue(startup, "serve did not start")
        serve_ctx = captured[0]

        def wait_for(predicate, what: str, timeout: float = 10.0) -> None:
            limit = time.monotonic() + timeout
            while time.monotonic() < limit:
                if predicate():
                    return
                time.sleep(0.05)
            self.fail_test(what)

        ready, finished = self.root / "ready", self.root / "finished"
        view = tools.exec(serve_ctx, "agent-1", "gh", ["30", str(ready), str(finished)])
        run = serve_ctx.runs.get(view["run_id"], "agent-1")
        wait_for(ready.exists, "the run never started")
        self.assertEqual(serve_ctx.runs.view(run)["state"], "running")
        binding = serve_ctx.signer_manager.bind("agent-2", "box", ssh_grant)
        self.assertTrue(Path(binding.socket_path).exists())

        self.ok("grant", "revoke", "--id", http_grant)   # another Policy instance: no in-process listener fires
        wait_for(lambda: serve_ctx.runs.view(run)["state"] == "cancelled", "run not cancelled after grant revoke")
        self.assertEqual(serve_ctx.runs.view(run)["reason"], "grant_revoked")
        self.assertFalse(finished.exists())
        self.assertIn(binding, serve_ctx.signer_manager.active_bindings())   # other principal's socket untouched

        self.ok("principal", "disable", "--id", "agent-2")
        wait_for(lambda: binding not in serve_ctx.signer_manager.active_bindings(), "signer binding not released")
        wait_for(lambda: not Path(binding.socket_path).exists(), "signer socket not removed")
        cancels = [(r["event"], r["reason"]) for r in self.ctx().audit.tail(500) if r["event"] == "run_cancel"]
        self.assertEqual(cancels, [("run_cancel", "grant_revoked")])

        # restore rotates the handle key; the running serve reloads it, so earlier handles stop verifying.
        self.ok("principal", "create", "--id", "agent-3")
        grant3 = self.ok("grant", "create", "--principal", "agent-3", "--connection", "gh")["id"]
        handle = serve_ctx.handles.issue("agent-3", "gh", grant3, 1, 600)
        serve_ctx.handles.verify(handle)
        archive = self.root / "serve-backup.json"
        self.ok("backup", "--out", str(archive))
        self.ok("restore", "--in", str(archive))

        def handle_dead() -> bool:
            try:
                serve_ctx.handles.verify(handle)
            except AuthFailedError:
                return True
            return False

        wait_for(handle_dead, "serve kept the pre-restore handle key")
        stop.set()
        serve.join(30)
        self.assertFalse(serve.is_alive())

    def fail_test(self, message: str) -> None:
        raise self.failureException(message)

    def test_cli_restore_keeps_revocations_and_used_approvals(self) -> None:
        """F10 / PL-3 through the administrator CLI."""
        self.seed_project()
        self.put_secret()
        self.create_http("gh")
        self.create_http("gh2")
        self.ok("principal", "create", "--id", "agent-1")
        self.ok("principal", "create", "--id", "agent-2")
        grant = self.ok("grant", "create", "--principal", "agent-1", "--connection", "gh")["id"]
        self.ok("grant", "create", "--principal", "agent-2", "--connection", "gh2")
        digest = P.approval_digest("agent-1", "gh", "DELETE", "/repos/demo", b"")
        self.ctx().policy.request_approval(digest, "agent-1", "gh", "DELETE", "/repos/demo")
        self.ok("approvals", "approve", "--digest", digest)
        archive = self.root / "backup.json"
        self.ok("backup", "--out", str(archive))
        self.assertTrue(self.ctx().policy.consume_approval(digest, "agent-1", "gh"))
        self.ok("principal", "disable", "--id", "agent-2")
        self.ok("connection", "disable", "--id", "gh2")
        (self.state / P.REVOCATIONS).unlink()   # the audit log alone must be enough
        restored = self.ok("restore", "--in", str(archive))
        self.assertEqual((restored["reapplied"]["principals"], restored["reapplied"]["connections"]), (1, 1))
        self.assertTrue(restored["handle_key_rotated"])
        self.assertIn("approvals", restored["next"])
        policy = self.ctx().policy
        self.assertEqual(policy.get_principal("agent-2").status, "disabled")
        self.assertEqual(policy.get_connection("gh2").status, "disabled")
        self.assertEqual(policy.list_approvals()[digest]["status"], "consumed")
        acked = self.ok("restore-ack")
        self.assertFalse(acked["restore_pending"])
        self.assertIn(grant, acked["active_grant_ids"])
        policy = self.ctx().policy
        self.assertFalse(policy.consume_approval(digest, "agent-1", "gh"))
        self.assertEqual(policy.evaluate("agent-2", "gh2", P.Action("http", "GET", "/repos")).reason, "principal_disabled")
        self.assertTrue(policy.evaluate("agent-1", "gh", P.Action("http", "GET", "/repos")).allowed)
        # The used approval stays in history once the same request asks again.
        policy.request_approval(digest, "agent-1", "gh", "DELETE", "/repos/demo")
        listing = self.ok("approvals", "list")
        self.assertEqual([(a["digest"], a["status"], a["cycle"]) for a in listing["approvals"]], [(digest, "pending", 2)])
        self.assertEqual([(h["digest"], h["status"]) for h in listing["history"]], [(digest, "consumed")])

    @staticmethod
    def _kill(proc: subprocess.Popen) -> None:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()

    # ---------------------------------------------- connection safety (F1 save-time, F5 opt-in)
    def democli(self) -> str:
        return str(Path(__file__).resolve().parent.parent / "examples" / "democli.py")

    def test_cli_env_holding_the_credential_is_refused_at_save_time(self) -> None:
        import base64

        self.seed_project()
        self.put_secret()
        for value in (SYNTHETIC, f"prefix-{SYNTHETIC}", base64.b64encode(SYNTHETIC.encode()).decode(),
                      SYNTHETIC.encode().hex()):
            with self.subTest(value=value[:12]):
                error = self.fail("connection", "create-http", "--id", "leaky", "--project", "demo",
                                  "--environment", "dev", "--service", "fake", "--secret-id", "gh-token",
                                  "--target", "http://127.0.0.1:8080", "--auth", "bearer",
                                  "--cli-program", self.democli(), "--cli-env", f"GH_TOKEN={value}")
                self.assertEqual((error["reason"], error.get("detail")), ("cli_env_contains_credential", "leaky"))
        connections = (self.state / "policy" / "connections.json")
        self.assertFalse(connections.exists() and SYNTHETIC in connections.read_text())
        self.assertEqual(self.ok("connection", "list")["connections"], [])
        denied = [r for r in self.ok("audit", "tail", "--limit", "20")["records"]
                  if r["event"] == "connection_create" and r["result"] == "denied"]
        self.assertEqual({r["reason"] for r in denied}, {"cli_env_contains_credential"})
        # A harmless value is accepted.
        created = self.ok("connection", "create-http", "--id", "clean", "--project", "demo", "--environment", "dev",
                          "--service", "fake", "--secret-id", "gh-token", "--target", "http://127.0.0.1:8080",
                          "--auth", "bearer", "--cli-program", self.democli(), "--cli-env", "DEMOCLI_COLOR=never")
        self.assertEqual(created["cli"]["extra_env"], {"DEMOCLI_COLOR": "never"})

    def test_new_secret_version_matching_existing_cli_env_is_refused(self) -> None:
        self.seed_project()
        self.put_secret()
        self.ok("connection", "create-http", "--id", "gh", "--project", "demo", "--environment", "dev",
                "--service", "fake", "--secret-id", "gh-token", "--target", "http://127.0.0.1:8080",
                "--auth", "bearer", "--cli-program", self.democli(), "--cli-env", "LABEL=zpw-label-that-later-becomes-a-value")
        error = self.fail("secret", "put", "--id", "gh-token", "--kind", "api_key", "--project", "demo",
                          "--environment", "dev", "--stdin", stdin_bytes=b"zpw-label-that-later-becomes-a-value\n")
        self.assertEqual((error["reason"], error.get("detail")), ("cli_env_contains_credential", "gh"))
        error = self.fail("rotation", "start", "--secret-id", "gh-token", "--stdin",
                          stdin_bytes=b"zpw-label-that-later-becomes-a-value\n")
        self.assertEqual(error["reason"], "cli_env_contains_credential")
        versions = self.ok("secret", "versions", "--id", "gh-token")
        self.assertEqual(len(versions["versions"]), 1)

    def test_cli_env_holding_any_vault_value_is_refused_at_save_time(self) -> None:
        """Every version (any status) of every secret, not only the connection's own active or staged ones."""
        self.seed_project()
        self.ok("project", "create", "prodproj", "--environments", "prod")
        other = "synthetic-prod-token-OTHERPROJECT-0123456789"
        self.ok("secret", "put", "--id", "prod-token", "--kind", "api_key", "--project", "prodproj",
                "--environment", "prod", "--stdin", stdin_bytes=other.encode())
        retired = "synthetic-retired-token-v1-abcdefghijkl"
        self.put_secret(retired)
        self.put_secret("synthetic-current-token-v2-mnopqrstuvwx")
        self.assertEqual([v["status"] for v in self.ok("secret", "versions", "--id", "gh-token")["versions"]],
                         ["retired", "active"])
        revoked = "synthetic-revoked-token-0123456789abc"
        self.put_secret(revoked, secret_id="gone")
        self.ok("secret", "revoke", "--id", "gone", "--version", "1")
        for label, assignment in (("other project", f"OTHER_TOKEN={other}"),
                                  ("retired version", f"OLD_TOKEN=Bearer {retired}"),
                                  ("revoked version", f"GONE_B64={base64.b64encode(revoked.encode()).decode()}")):
            with self.subTest(label):
                error = self.fail("connection", "create-http", "--id", "leaky", "--project", "demo",
                                  "--environment", "dev", "--service", "fake", "--secret-id", "gh-token",
                                  "--target", "http://127.0.0.1:8080", "--auth", "bearer",
                                  "--cli-program", self.democli(), "--cli-env", assignment)
                self.assertEqual((error["reason"], error.get("detail")), ("cli_env_contains_credential", "leaky"))
        connections = self.state / "policy" / "connections.json"
        text = connections.read_text() if connections.exists() else ""
        for value in (other, retired, revoked):
            self.assertNotIn(value, text)
        self.assertEqual(self.ok("connection", "list")["connections"], [])

    def test_new_secret_matching_any_connection_cli_env_is_refused(self) -> None:
        """A new secret (other id, other project) whose value is already configured as a CLI env value."""
        self.seed_project()
        self.ok("project", "create", "prodproj", "--environments", "prod")
        self.put_secret()
        label = "zpw-label-that-later-becomes-another-secret"
        self.ok("connection", "create-http", "--id", "gh", "--project", "demo", "--environment", "dev",
                "--service", "fake", "--secret-id", "gh-token", "--target", "http://127.0.0.1:8080",
                "--auth", "bearer", "--cli-program", self.democli(), "--cli-env", f"LATER_TOKEN={label}")
        error = self.fail("secret", "put", "--id", "later", "--kind", "api_key", "--project", "prodproj",
                          "--environment", "prod", "--stdin", stdin_bytes=label.encode())
        self.assertEqual((error["reason"], error.get("detail")), ("cli_env_contains_credential", "gh"))
        self.ok("secret", "put", "--id", "later", "--kind", "api_key", "--project", "prodproj",
                "--environment", "prod", "--stdin", stdin_bytes=b"zpw-unrelated-value-0123456789")
        error = self.fail("rotation", "start", "--secret-id", "later", "--stdin", stdin_bytes=label.encode())
        self.assertEqual((error["reason"], error.get("detail")), ("cli_env_contains_credential", "gh"))
        self.assertEqual(len(self.ok("secret", "versions", "--id", "later")["versions"]), 1)
        denied = [r for r in self.ctx().audit.tail(50) if r["result"] == "denied"]
        self.assertEqual({(r["event"], r["reason"], r.get("secret_id")) for r in denied},
                         {("secret_put", "cli_env_contains_credential", "later"),
                          ("rotation", "cli_env_contains_credential", "later")})

    def _race(self, patch_target: type, attribute: str, main_argv: list[str], other_argv: list[str]) -> tuple[int, int | None]:
        """Run ``other_argv`` with its own Context (as a second admin process would) while ``main_argv`` is
        between its save-time check and its write (``patch_target.attribute``).  Returns both exit codes."""
        codes: dict[str, int] = {}
        threads: list[threading.Thread] = []
        original = getattr(patch_target, attribute)

        def other() -> None:
            args = admin_cli.build_parser().parse_args(["--state-dir", str(self.state), *other_argv])
            try:
                args.handler(args)
                codes["other"] = 0
            except admin_cli.ZeroPWError:
                codes["other"] = 1

        def racing_write(*args: object, **kwargs: object) -> object:
            if not threads:
                thread = threading.Thread(target=other)
                threads.append(thread)
                thread.start()
                thread.join(1.0)   # an unguarded concurrent command finishes well within this
            return original(*args, **kwargs)

        with patch.object(patch_target, attribute, racing_write):
            main_code, _out, _err = self.run_cli(*main_argv)
        for thread in threads:
            thread.join(30)
        self.assertEqual(len(threads), 1, "the racing command never started")
        return main_code, codes.get("other")

    def test_save_time_check_and_write_are_one_critical_section(self) -> None:
        """Concurrent `connection create-http --cli-env X=V` and `secret put V` cannot both succeed."""
        from zeropw.vault import Vault

        self.seed_project()
        self.put_secret()
        for label, target, attribute in (("secret put during connection create", P.Policy, "create_connection"),
                                         ("connection create during secret put", Vault, "put_secret")):
            with self.subTest(label):
                value = f"zpw-raced-value-{attribute}-abcdefgh"   # a plain label until one side stores it as a secret
                value_file = self.root / f"raced-{attribute}"
                value_file.write_text(value)
                put = ["secret", "put", "--id", "gh-token", "--kind", "api_key", "--project", "demo",
                       "--environment", "dev", "--value-file", str(value_file)]
                create = ["connection", "create-http", "--id", f"c-{attribute}", "--project", "demo",
                          "--environment", "dev", "--service", "s", "--secret-id", "gh-token",
                          "--target", "http://127.0.0.1:9", "--auth", "bearer", "--cli-program", self.democli(),
                          "--cli-env", f"X={value}"]
                main_argv, other_argv = (create, put) if target is P.Policy else (put, create)
                codes = self._race(target, attribute, main_argv, other_argv)
                self.assertEqual(sorted(codes), [0, 1], f"exactly one racing command may succeed: {codes}")
                connections = self.state / "policy" / "connections.json"
                in_policy = connections.exists() and value in connections.read_text()
                in_vault = value.encode() in self.ctx().vault.values_for_trusted_scan()
                self.assertFalse(in_policy and in_vault, "the value is both a CLI env value and a vault value")

    def test_private_network_opt_in_flag(self) -> None:
        self.seed_project()
        self.put_secret()
        default = self.ok("connection", "create-http", "--id", "public", "--project", "demo", "--environment", "dev",
                          "--service", "fake", "--secret-id", "gh-token", "--target", "https://api.example.com",
                          "--auth", "bearer")
        self.assertFalse(default["http_target"]["allow_private_network"])
        internal = self.ok("connection", "create-http", "--id", "internal", "--project", "demo", "--environment", "dev",
                           "--service", "fake", "--secret-id", "gh-token", "--target", "https://git.corp.example",
                           "--auth", "bearer", "--allow-private-network")
        self.assertTrue(internal["http_target"]["allow_private_network"])
        for target, reason in (("http://169.254.169.254", "metadata_address_not_allowed"),
                               ("http://[fe80::1]:8080", "metadata_address_not_allowed"),
                               ("http://0.0.0.0:8080", "target_address_not_allowed")):
            with self.subTest(target=target):
                error = self.fail("connection", "create-http", "--id", "meta", "--project", "demo",
                                  "--environment", "dev", "--service", "fake", "--secret-id", "gh-token",
                                  "--target", target, "--auth", "bearer", "--allow-private-network")
                self.assertEqual(error["reason"], reason)


class TeamCliTestCase(AdminCliTestCase):
    """``team`` commands and shared-environment awareness in ``connection``/``secret``/``rotation``
    (docs/team-sync.md section 12; stage-3 test list in section 13): commit/fact output shape,
    value-free CLI output (json and yaml), and cross-process pickup (one ``Context`` driving the
    CLI, a second live ``TeamSync`` over the same state dir standing in for a running ``serve``).
    """

    def _share(self) -> str:
        self.seed_project()
        self.put_secret()
        self.create_http()
        from zeropw.team import membership as team_membership

        env_id = team_membership.share_environment(self.ctx(), None, "demo", "dev", "owner", ADMIN)["env_id"]
        return env_id

    def test_team_init_refuses_second_time(self) -> None:
        self.init()
        payload = self.ok("team", "init")
        self.assertIn("fingerprint", payload)
        self.fail("team", "init")

    def test_team_share_cli_reports_not_shared_connection(self) -> None:
        """H1 regression through the CLI: `team share` output surfaces a connection left behind
        because its secret was not carried over, instead of silently disabling it."""
        self.seed_project()
        self.put_secret()  # "gh-token", active
        self.create_http()  # "gh", references gh-token: the happy path
        self.put_secret(secret_id="dead-token", value="synthetic-dead-token-value")
        self.ok("connection", "create-http", "--id", "dead", "--project", "demo", "--environment", "dev",
               "--service", "deadsvc", "--secret-id", "dead-token", "--target", "https://dead.example.com",
               "--auth", "bearer")
        self.ok("secret", "revoke", "--id", "dead-token", "--version", "1")  # no active/staged version left

        payload = self.ok("team", "share", "--project", "demo", "--environment", "dev")
        self.assertEqual(payload["not_shared"], [{"connection": "dead", "reason": "secret_not_shared"}])
        still_local = self.ok("connection", "show", "--id", "dead")
        self.assertEqual(still_local["status"], "active")
        raw = self.ctx().state.read_json(P.CONNECTIONS, {}) or {}
        self.assertNotIn("shared_env", raw["dead"])
        self.assertEqual(raw["gh"].get("shared_env"), payload["env_id"])

    def test_team_share_status_members_log_show(self) -> None:
        env_id = self._share()
        status = self.ok("team", "status", "--env", "demo/dev")
        self.assertEqual(status["env_id"], env_id)
        self.assertGreaterEqual(status["commits_folded"], 1)
        self.assertEqual(status["rejected_commits"], 0)

        members = self.ok("team", "members", "--env", "demo/dev")
        self.assertEqual(len(members["members"]), 1)
        self.assertTrue(members["members"][0]["owner"])

        log = self.ok("team", "log", "--env", "demo/dev")
        self.assertTrue(any("env.init" in entry["ops"] for entry in log["log"]))

        show = self.ok("team", "show", "--env", "demo/dev")
        self.assertEqual(show["env_id"], env_id)
        blob = json.dumps(show)
        for forbidden in ("ciphertext", "nonce", "\"sig\"", "wraps", SYNTHETIC):
            self.assertNotIn(forbidden, blob)

    def test_team_show_yaml_has_no_ciphertext_or_wraps(self) -> None:
        self._share()
        code, out, err = self.run_cli("team", "show", "--env", "demo/dev", "--format", "yaml")
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        for forbidden in ("ciphertext", "nonce", "sig:", "wraps", SYNTHETIC):
            self.assertNotIn(forbidden, out)
        self.assertIn("env_id:", out)
        # NOT valid JSON: proves this really is the YAML writer, not json.dumps under another name.
        with self.assertRaises(ValueError):
            json.loads(out)

    def test_team_invite_warns_and_join_rejects_malformed_invite(self) -> None:
        self._share()
        payload = self.ok("team", "invite", "--env", "demo/dev", "--role", "user", "--name", "bob")
        self.assertIn("warning", payload)
        self.assertIn("invite", payload)
        error = self.fail("team", "join", "not-a-real-invite-string")
        self.assertEqual(error["reason"], "invite_malformed")

    def test_team_diff_between_two_commits(self) -> None:
        env_id = self._share()
        log = self.ok("team", "log", "--env", "demo/dev")
        self.assertGreaterEqual(len(log["log"]), 1)
        from zeropw.team import commit as team_commit_mod

        store = team_commit_mod.CommitStore(self.ctx().state, env_id)
        commits = team_commit_mod.sort_total_order(store.all_commits())
        left, right = commits[0].hash[:12], commits[-1].hash[:12]
        diff = self.ok("team", "diff", "--env", "demo/dev", left, right)
        self.assertIn("left", diff)
        self.assertIn("right", diff)
        blob = json.dumps(diff)
        for forbidden in ("ciphertext", "nonce", "\"sig\"", SYNTHETIC):
            self.assertNotIn(forbidden, blob)

    def test_team_peers_add_and_list(self) -> None:
        self._share()
        fake_fp = "b" * 26
        added = self.ok("team", "peers", "--env", "demo/dev", "--add", "127.0.0.1:9999", "--device", fake_fp)
        self.assertIn(fake_fp, added["peers"])
        self.assertIn("127.0.0.1:9999", added["peers"][fake_fp])

    def test_team_compact_no_op_when_too_young(self) -> None:
        self._share()
        payload = self.ok("team", "compact", "--env", "demo/dev")
        self.assertEqual(payload["removed"], 0)

    def test_team_set_role_and_transfer_owner_are_commits(self) -> None:
        self._share()
        fake_fp = "c" * 26
        role_payload = self.ok("team", "set-role", "--env", "demo/dev", "--device", fake_fp, "--role", "admin")
        self.assertIn("commit", role_payload)
        transfer_payload = self.ok("team", "transfer-owner", "--env", "demo/dev", "--device", fake_fp)
        self.assertIn("commit", transfer_payload)

    def test_connection_create_secret_put_are_commits_with_propagated_to(self) -> None:
        env_id = self._share()
        create_payload = self.ok("connection", "create-http", "--id", "gh2", "--project", "demo",
                                 "--environment", "dev", "--service", "svc2", "--secret-id", "gh-token",
                                 "--target", "https://api.github.com", "--auth", "bearer")
        self.assertIn("commit", create_payload)
        self.assertEqual(create_payload["propagated_to"], 0)  # this one-shot CLI holds no live session
        put_payload = self.ok("secret", "put", "--id", "gh-token", "--kind", "api_key", "--project", "demo",
                              "--environment", "dev", "--stdin", stdin_bytes=(SYNTHETIC_V2 + "\n").encode())
        self.assertIn("commit", put_payload)
        self.assertNotIn("version", put_payload)  # a shared secret is keyed by its version id, not a local int
        self.assertIn("version_id", put_payload)

    def test_connection_disable_and_secret_revoke_are_facts(self) -> None:
        self._share()
        disable_payload = self.ok("connection", "disable", "--id", "gh")
        self.assertIn("fact", disable_payload)
        self.assertNotIn("commit", disable_payload)
        revoke_payload = self.ok("secret", "revoke", "--id", "gh-token", "--version", "1")
        self.assertIn("fact", revoke_payload)
        self.assertNotIn("commit", revoke_payload)

    def test_cli_commits_and_facts_visible_on_second_node_after_poll(self) -> None:
        """docs/team-sync.md section 12: the admin CLI is a separate process from ``serve``.  A
        second, independent ``Context``/``TeamSync`` over the SAME state directory stands in for a
        separately-running ``serve --team-listen`` -- it must pick up, on its next ``poll()``, both
        a commit (``secret put``) and a fact (``connection disable``) the CLI wrote directly.
        """
        env_id = self._share()
        from zeropw.team.identity import DeviceKey
        from zeropw.team.sync import TeamSync
        from zeropw.team.transport import InProcessTransport

        serve_ctx = Context.open(self.state)
        device = DeviceKey.load_or_create(serve_ctx.state, serve_ctx.kms)
        serve_sync = TeamSync(serve_ctx, InProcessTransport(device), device)
        serve_sync.register_env(env_id)
        self.addCleanup(serve_sync.stop)

        put_payload = self.ok("secret", "put", "--id", "gh-token", "--kind", "api_key", "--project", "demo",
                              "--environment", "dev", "--stdin", stdin_bytes=(SYNTHETIC_V2 + "\n").encode())
        self.assertIn("commit", put_payload)
        update_payload = self.ok("connection", "update", "--id", "gh", "--methods", "GET,POST")
        self.assertIn("commit", update_payload)

        serve_sync.poll()
        doc = serve_sync.document(env_id)
        self.assertEqual(len(doc["secrets"]["gh-token"]["versions"]), 2)
        self.assertEqual(sorted(doc["connections"]["gh"]["http_scope"]["methods"]), ["GET", "POST"])

        disable_payload = self.ok("connection", "disable", "--id", "gh")
        self.assertIn("fact", disable_payload)
        serve_sync.poll()
        # A bare fact-only disable (no accompanying commit) retroactively skips "gh"'s own
        # connection.create in every full refold from now on (docs/team-sync.md section 5.3's
        # "never let a disabled id (re)exist" rule applied from the very start of the fold), so it
        # is entirely ABSENT from the raw folded document -- not present with status "disabled".
        # The derived local view is where "disabled" actually shows (fold.py's vanished-connection
        # handling retains a disabled marker there instead of deleting the entry).
        self.assertNotIn("gh", serve_sync.document(env_id)["connections"])
        self.assertEqual(self.ok("connection", "show", "--id", "gh")["status"], "disabled")


if __name__ == "__main__":
    unittest.main()
