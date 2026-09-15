"""agent_cli against a real ZeroPWServer: JSON in/out, exit codes, token hygiene."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import types
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest import mock

import zeropw
from zeropw import policy as P
from zeropw import tools
from zeropw.context import Config, Context
from zeropw.server import ZeroPWServer

ADMIN = "admin-passphrase-1"
RECOVERY = "recovery-passphrase-1"
SYNTHETIC = b"synthetic-token-0123456789abcdef"
REPO_ROOT = Path(__file__).resolve().parent.parent

ECHO_SCRIPT = """
import sys, time
print(" ".join(sys.argv[1:]))
if sys.argv[1:] and sys.argv[1] == "sleep":
    time.sleep(30)
"""


@dataclass
class FakeRelayResult:
    status: int
    headers: list[tuple[str, str]]
    body: bytes
    reason: str | None = None


def gateway_module() -> tuple[types.ModuleType, bool]:
    try:
        import importlib

        return importlib.import_module("zeropw.gateway"), False
    except ImportError:
        module = types.ModuleType("zeropw.gateway")
        module.RelayResult = FakeRelayResult  # type: ignore[attr-defined]
        module.relay_for_caller = lambda *a, **k: FakeRelayResult(501, [], b"", "stub")  # type: ignore[attr-defined]
        module.relay = lambda *a, **k: FakeRelayResult(501, [], b"", "stub")  # type: ignore[attr-defined]
        sys.modules["zeropw.gateway"] = module
        setattr(zeropw, "gateway", module)
        return module, True


class AgentCliTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ctx = Context.initialize(self.root / "state", ADMIN, RECOVERY, Config())
        self.ctx.projects.create("demo")
        self.ctx.vault.put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev")
        self.token = self.ctx.policy.create_principal("agent-1")
        program = self.root / "echo.py"
        program.write_text(f"#!{sys.executable}\n{ECHO_SCRIPT}")
        program.chmod(0o700)
        self.ctx.policy.create_connection(P.Connection(
            id="gh", project="demo", environment="dev", service="fake-github", kind="http", secret_id="gh-token",
            secret_version=None, description="demo", http_target=P.HttpTarget("http", "127.0.0.1", 8080),
            http_auth=P.HttpAuth("bearer"), http_scope=P.HttpScope(("GET", "POST"), ("/repos", "/me"), ()),
            ssh_target=None, cli=P.CliProfile(str(program), "http"), policy_version=0, status="active",
            created_at="", updated_at=""))
        self.grant = self.ctx.policy.create_grant("agent-1", "gh", 3600, None)
        self.registry = tools.install(self.ctx)
        self.server = ZeroPWServer(self.ctx).serve_in_thread()
        tools.set_public_url(self.ctx, self.server.url)
        self.gateway, self.gateway_is_stub = gateway_module()

    def tearDown(self) -> None:
        self.registry.shutdown()
        self.server.stop()
        if self.gateway_is_stub:
            sys.modules.pop("zeropw.gateway", None)
            if getattr(zeropw, "gateway", None) is self.gateway:
                delattr(zeropw, "gateway")
        self.tmp.cleanup()

    def cli(self, *args: str, token: str | None = None, url: str | None = None,
            env_override: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        env = {"PATH": os.environ.get("PATH", ""), "HOME": self.tmp.name,
               "ZEROPW_GATEWAY_URL": self.server.url if url is None else url,
               "ZEROPW_CALLER_TOKEN": self.token if token is None else token}
        if env_override is not None:
            env = env_override
        return subprocess.run([sys.executable, "-m", "zeropw.agent_cli", *args], capture_output=True, text=True,
                              cwd=str(REPO_ROOT), env=env, timeout=60)

    def ok(self, *args: str) -> dict[str, Any]:
        proc = self.cli(*args)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stderr, "")
        return json.loads(proc.stdout)

    def wait_state(self, run_id: str, timeout: float = 20) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            view = self.ok("status", "--run", run_id)
            if view["state"] not in ("queued", "running") or time.monotonic() > deadline:
                return view
            time.sleep(0.1)

    def test_list_connections(self) -> None:
        result = self.ok("list-connections")
        self.assertEqual([c["id"] for c in result["connections"]], ["gh"])
        self.assertEqual(result["connections"][0]["grant"]["status"], "active")
        self.assertNotIn(SYNTHETIC.decode(), json.dumps(result))
        self.assertNotIn("secret_id", json.dumps(result))

    def test_exec_status_cancel_roundtrip(self) -> None:
        started = self.ok("exec", "--connection", "gh", "--request-id", "req-1", "--", "hello", "--flag", "-x")
        self.assertTrue(started["run_id"].startswith("r-"))
        view = self.wait_state(started["run_id"])
        self.assertEqual(view["state"], "completed")
        self.assertEqual(view["exit_code"], 0)
        self.assertEqual(view["stdout"].strip(), "hello --flag -x")
        again = self.ok("exec", "--connection", "gh", "--request-id", "req-1", "--", "hello", "--flag", "-x")
        self.assertEqual(again["run_id"], started["run_id"])

        sleeper = self.ok("exec", "--connection", "gh", "--", "sleep")
        self.assertEqual(sleeper["state"], "running")
        cancelled = self.ok("cancel", "--run", sleeper["run_id"])
        self.assertEqual(cancelled["state"], "cancelled")
        self.assertEqual(self.ok("status", "--run", sleeper["run_id"])["state"], "cancelled")

    def test_request_through_gateway(self) -> None:
        seen: list[tuple] = []

        def relay(ctx, caller, connection_id, method, path, headers, body, request_id=None):
            seen.append((caller, connection_id, method, path, dict(headers), body, request_id))
            return FakeRelayResult(200, [("Content-Type", "application/json"), ("Set-Cookie", "x=1")],
                                   b'{"repos": []}', None)

        body_file = self.root / "body.json"
        body_file.write_text('{"title": "from file"}')
        with mock.patch.object(self.gateway, "relay_for_caller", side_effect=relay):
            result = self.ok("request", "--connection", "gh", "--method", "post", "--path", "/repos/demo/issues",
                             "--body-file", str(body_file), "--header", "Accept: application/json",
                             "--header", "X-Trace: abc", "--request-id", "r-9")
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["body"], '{"repos": []}')
        self.assertEqual(result["headers"], {"content-type": "application/json"})
        self.assertEqual(seen, [("agent-1", "gh", "POST", "/repos/demo/issues",
                                 {"Accept": "application/json", "X-Trace": "abc"}, b'{"title": "from file"}', "r-9")])
        with mock.patch.object(self.gateway, "relay_for_caller", side_effect=relay):
            result = self.ok("request", "--connection", "gh", "--method", "GET", "--path", "/me", "--body", "x")
        self.assertEqual(seen[-1][5], b"x")

    def test_errors_exit_1_with_json_and_never_print_token(self) -> None:
        proc = self.cli("status", "--run", "r-0000000000000000")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout, "")
        error = json.loads(proc.stderr)
        self.assertEqual((error["error"], error["reason"], error["status"]), ("NotFound", "run_not_found", 404))

        proc = self.cli("list-connections", token="zpwc_not-a-real-token")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stderr)["reason"], "caller_token_invalid")

        proc = self.cli("exec", "--connection", "ghost", "--", "x")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stderr)["reason"], "connection_unknown")

        proc = self.cli("list-connections", url="http://127.0.0.1:1")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stderr)["reason"], "gateway_unreachable")

        proc = self.cli("list-connections", env_override={"PATH": os.environ.get("PATH", ""), "HOME": self.tmp.name})
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stderr)["reason"], "gateway_url_unset")

        proc = self.cli("list-connections", env_override={"PATH": os.environ.get("PATH", ""), "HOME": self.tmp.name,
                                                          "ZEROPW_GATEWAY_URL": self.server.url})
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stderr)["reason"], "caller_token_unset")

        proc = self.cli("list-connections", url="file:///etc/passwd")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stderr)["reason"], "gateway_url_invalid")

        proc = self.cli("bogus-command")
        self.assertEqual(proc.returncode, 2)

        for output in (proc.stdout, proc.stderr):
            self.assertNotIn(self.token, output)
        self.assertNotIn(self.token, "".join(self.server.log_lines))

    def test_refused_blocked_or_unsupported_relays_exit_1_on_stderr(self) -> None:
        refusals = {
            "/unsupported": FakeRelayResult(501, [("Content-Type", "application/json")],
                                            b'{"error": "Unsupported", "reason": "credential_header_unsafe"}',
                                            "credential_header_unsafe"),
            "/blocked": FakeRelayResult(502, [], b'{"error": "Blocked", "reason": "response_credential_blocked"}',
                                        "response_credential_blocked"),
            "/me": FakeRelayResult(404, [("Content-Type", "application/json")], b'{"message": "Not Found"}', None),
        }

        def relay(ctx, caller, connection_id, method, path, headers, body, request_id=None):
            return refusals[path]

        with mock.patch.object(self.gateway, "relay_for_caller", side_effect=relay):
            for path, reason in (("/unsupported", "credential_header_unsafe"),
                                 ("/blocked", "response_credential_blocked")):
                proc = self.cli("request", "--connection", "gh", "--method", "GET", "--path", path)
                self.assertEqual(proc.returncode, 1, (path, proc.stdout))
                self.assertEqual(proc.stdout, "")
                self.assertEqual(json.loads(proc.stderr)["reason"], reason)
            # An upstream response relayed as-is (reason null) is a success whatever its HTTP status.
            relayed = self.ok("request", "--connection", "gh", "--method", "GET", "--path", "/me")
            self.assertEqual((relayed["status"], relayed["reason"]), (404, None))
            # Denials decided before the gateway (tools API returns a 403 relay envelope) are errors too.
            proc = self.cli("request", "--connection", "nope", "--method", "GET", "--path", "/me")
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertEqual(proc.stdout, "")
            self.assertEqual((json.loads(proc.stderr)["status"], json.loads(proc.stderr)["reason"]),
                             (403, "connection_unknown"))
        if not self.gateway_is_stub:
            # The real gateway's scope refusal (method outside the connection scope) exits 1 as well.
            proc = self.cli("request", "--connection", "gh", "--method", "DELETE", "--path", "/repos")
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertEqual(proc.stdout, "")
            error = json.loads(proc.stderr)
            self.assertEqual((error["status"], error["reason"]), (403, "method_not_allowed"))
        self.assertNotIn(self.token, "".join(self.server.log_lines))

    def test_server_maps_tool_errors_and_refuses_bad_json(self) -> None:
        import urllib.error
        import urllib.request

        request = urllib.request.Request(f"{self.server.url}/v1/tools/status", data=b"not json", method="POST",
                                         headers={"Authorization": f"Bearer {self.token}"})
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=10)
        self.assertEqual(caught.exception.code, 400)
        self.assertEqual(json.loads(caught.exception.read())["reason"], "invalid_json")
        request = urllib.request.Request(f"{self.server.url}/v1/tools/nope", data=b"{}", method="POST",
                                         headers={"Authorization": f"Bearer {self.token}"})
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=10)
        self.assertEqual(caught.exception.code, 404)
        self.assertEqual(json.loads(caught.exception.read())["reason"], "tool_not_found")


if __name__ == "__main__":
    unittest.main()
