"""Agent tools: payload validation, filtered responses, exec isolation, policy re-checks, democli end to end."""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import threading
import time
import types
import unittest
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest import mock

import zeropw
from zeropw import policy as P
from zeropw import tools
from zeropw.context import Config, Context
from zeropw.errors import AuditUnavailable, InvalidInput, NotFound, PolicyDenied, StateError, Unsupported

try:  # test helper next to this file
    from tests.leakcheck import find_secret, ssh_key_material
except ImportError:  # pragma: no cover - discovery from another working directory
    from leakcheck import find_secret, ssh_key_material  # type: ignore[no-redef]

ADMIN = "admin-passphrase-1"
RECOVERY = "recovery-passphrase-1"
SYNTHETIC = b"synthetic-token-0123456789abcdef"
REPO_ROOT = Path(__file__).resolve().parent.parent
DEMOCLI = REPO_ROOT / "examples" / "democli.py"
ALLOWED_HTTP_ENV = {"PATH", "HOME", "LANG", "TMPDIR", "ZEROPW_RUN_ID", "ZEROPW_API_BASE_URL"}
ALLOWED_SSH_ENV = {"PATH", "HOME", "LANG", "TMPDIR", "ZEROPW_RUN_ID", "SSH_AUTH_SOCK"}
HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA test-host"

# Writes what the child can see to the file named by its first argument; stdout stays free of the handle.
DUMP_SCRIPT = """
import json, os, sys
with open(sys.argv[1], "w") as fh:
    json.dump({"env": dict(os.environ), "argv": sys.argv, "cwd": os.getcwd()}, fh)
print("dumped")
"""

# A fake "ssh": records argv/env, the managed known_hosts file and every file in its working directory (hex),
# never connects anywhere.
FAKE_SSH_SCRIPT = """
import json, os, sys
argv = sys.argv
remote = argv[argv.index("--") + 1:] if "--" in argv else []
known_hosts = None
identity = None
for i, item in enumerate(argv):
    if item.startswith("UserKnownHostsFile="):
        known_hosts = open(item.split("=", 1)[1]).read()
    if item.startswith("IdentityFile="):
        path = item.split("=", 1)[1]
        identity = {"text": open(path).read(), "mode": os.stat(path).st_mode & 0o777}
entries = {}
for name in sorted(os.listdir(".")):
    entries[name] = open(name, "rb").read().hex() if os.path.isfile(name) else None
with open(remote[0], "w") as fh:
    json.dump({"env": dict(os.environ), "argv": argv, "cwd": os.getcwd(), "known_hosts": known_hosts,
               "identity": identity, "entries": entries}, fh)
print("ssh-ok")
"""

PRINT_ENV_SCRIPT = """
import os, sys
print(os.environ.get(sys.argv[1], "<unset>"))
"""

ECHO_SCRIPT = """
import sys
print(" ".join(sys.argv[1:]))
"""

# Sleeps; when a second argument is given, creates that file once it is running (test synchronisation).
SLEEP_SCRIPT = """
import sys, time
print("sleeping", flush=True)
if len(sys.argv) > 2:
    open(sys.argv[2], "w").write("ready")
time.sleep(float(sys.argv[1]) if len(sys.argv) > 1 else 30)
"""


def child_env_names(env: dict[str, str]) -> set[str]:
    # macOS CoreFoundation injects __CF_USER_TEXT_ENCODING into every new process; it is not inherited.
    return {name for name in env if not name.startswith("__CF_")}


def write_script(path: Path, body: str) -> str:
    path.write_text(f"#!{sys.executable}\n{body}")
    path.chmod(0o700)
    return str(path)


def http_connection(cid: str, program: str | None, secret_id: str = "gh-token", **overrides: Any) -> P.Connection:
    base: dict[str, Any] = dict(
        id=cid, project="demo", environment="dev", service="fake-github", kind="http", secret_id=secret_id,
        secret_version=None, description="demo connection",
        http_target=P.HttpTarget("http", "127.0.0.1", 8080), http_auth=P.HttpAuth("bearer"),
        http_scope=P.HttpScope(("GET", "POST"), ("/repos", "/me"), ("DELETE",)),
        ssh_target=None, cli=P.CliProfile(program, "http") if program else None,
        policy_version=0, status="active", created_at="", updated_at="",
    )
    base.update(overrides)
    return P.Connection(**base)


def ssh_connection(cid: str, program: str | None, port: int = 2222) -> P.Connection:
    return P.Connection(
        id=cid, project="demo", environment="dev", service="ssh-box", kind="ssh", secret_id="box-key",
        secret_version=None, description="", http_target=None, http_auth=None, http_scope=None,
        ssh_target=P.SshTarget("127.0.0.1", port, "deploy", (HOST_KEY,)),
        cli=P.CliProfile(program, "ssh") if program else None,
        policy_version=0, status="active", created_at="", updated_at="",
    )


@dataclass
class FakeRelayResult:
    status: int
    headers: list[tuple[str, str]]
    body: bytes
    reason: str | None = None


def gateway_module() -> tuple[types.ModuleType, bool]:
    """The real gateway if the sibling module exists, otherwise a stub registered as zeropw.gateway."""
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


class FakeBinding:
    def __init__(self, socket_path: Path, caller: str, connection_id: str, grant_id: str) -> None:
        self.socket_path = socket_path
        self.caller = caller
        self.connection_id = connection_id
        self.grant_id = grant_id
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakeSignerManager:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.bindings: list[FakeBinding] = []

    def bind(self, caller: str, connection_id: str, grant_id: str) -> FakeBinding:
        binding = FakeBinding(self.root / f"agent-{len(self.bindings)}.sock", caller, connection_id, grant_id)
        self.bindings.append(binding)
        return binding


class RecordingUpstream(ThreadingHTTPServer):
    """Stands in for the gateway endpoint a CLI talks to: records requests, answers JSON."""

    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), RecordingHandler)
        self.requests: list[dict[str, Any]] = []
        self.lock = threading.Lock()

    @property
    def url(self) -> str:
        host, port = self.server_address[:2]
        return f"http://{host}:{port}"


class RecordingHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _record(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        with self.server.lock:  # type: ignore[attr-defined]
            self.server.requests.append({  # type: ignore[attr-defined]
                "method": self.command, "path": self.path, "headers": dict(self.headers.items()), "body": body,
            })
        return body

    def _reply(self, status: int, payload: Any) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        self._record()
        if self.path.endswith("/repos"):
            self._reply(200, [{"name": "demo"}, {"name": "tools"}])
        elif self.path.endswith("/me"):
            self._reply(200, {"login": "demo-user"})
        else:
            self._reply(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        body = self._record()
        if "/issues" in self.path:
            self._reply(201, {"number": 1, "title": json.loads(body or b"{}").get("title")})
        else:
            self._reply(404, {"error": "not_found"})


class ToolsFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ctx = Context.initialize(self.root / "state", ADMIN, RECOVERY, Config())
        self.ctx.projects.create("demo")
        self.ctx.vault.put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev")
        self.scripts = self.root / "bin"
        self.scripts.mkdir()
        self.dump_program = write_script(self.scripts / "dump.py", DUMP_SCRIPT)
        self.token = self.ctx.policy.create_principal("agent-1")
        self.other_token = self.ctx.policy.create_principal("agent-2")
        self.ctx.policy.create_connection(http_connection("gh", self.dump_program))
        self.grant = self.ctx.policy.create_grant("agent-1", "gh", 3600, None)
        self.registry = tools.install(self.ctx)
        tools.set_public_url(self.ctx, "http://127.0.0.1:1")
        self.gateway, self.gateway_is_stub = gateway_module()

    def tearDown(self) -> None:
        self.registry.shutdown()
        if self.gateway_is_stub:
            sys.modules.pop("zeropw.gateway", None)
            if getattr(zeropw, "gateway", None) is self.gateway:
                delattr(zeropw, "gateway")
        self.tmp.cleanup()

    # helpers ---------------------------------------------------------------
    def script(self, name: str, body: str) -> str:
        return write_script(self.scripts / name, body)

    def events(self, name: str | None = None) -> list[dict[str, Any]]:
        return [r for r in self.ctx.audit.tail(1000) if name is None or r["event"] == name]

    def wait(self, run_id: str, timeout: float = 20) -> dict[str, Any]:
        run = self.registry.get(run_id, "agent-1")
        self.registry.wait(run, timeout)
        return tools.status(self.ctx, "agent-1", run_id)

    def exec_dump(self, connection: str = "gh", extra: list[str] | None = None, caller: str = "agent-1") -> tuple[dict, dict]:
        out = self.root / f"dump-{time.monotonic_ns()}.json"
        result = tools.exec(self.ctx, caller, connection, [str(out), *(extra or [])])
        run = self.registry.get(result["run_id"], caller)
        self.registry.wait(run, 20)
        view = self.registry.view(run)
        self.assertEqual(view["state"], "completed", view)
        return view, json.loads(out.read_text())

    def all_state_text(self) -> str:
        chunks = []
        for path in (self.root / "state").rglob("*"):
            if path.is_file():
                chunks.append(path.read_bytes().decode("utf-8", "replace"))
        return "\n".join(chunks)


class DispatchTestCase(ToolsFixture):
    def test_unknown_tool_and_payload_shapes(self) -> None:
        with self.assertRaises(NotFound) as caught:
            tools.dispatch(self.ctx, "reveal_secret", "agent-1", {})
        self.assertEqual(caught.exception.reason, "tool_not_found")
        with self.assertRaises(InvalidInput):
            tools.dispatch(self.ctx, "status", "agent-1", {"run_id": 12})
        with self.assertRaises(InvalidInput):
            tools.dispatch(self.ctx, "status", "agent-1", {})
        with self.assertRaises(InvalidInput):
            tools.dispatch(self.ctx, "status", "agent-1", {"run_id": "bad id!"})
        with self.assertRaises(InvalidInput):
            tools.dispatch(self.ctx, "exec", "agent-1", {"connection": "gh", "argv": "not-a-list"})
        with self.assertRaises(InvalidInput):
            tools.dispatch(self.ctx, "exec", "agent-1", {"connection": "gh", "argv": [1, 2]})
        with self.assertRaises(InvalidInput) as caught:
            tools.dispatch(self.ctx, "exec", "agent-1", {"connection": "gh", "argv": ["x"] * 257})
        self.assertEqual(caught.exception.reason, "argv_too_long")
        with self.assertRaises(InvalidInput) as caught:
            tools.dispatch(self.ctx, "exec", "agent-1", {"connection": "gh", "argv": ["y" * 4097]})
        self.assertEqual(caught.exception.reason, "argument_too_long")
        with self.assertRaises(InvalidInput):
            tools.dispatch(self.ctx, "exec", "agent-1", {"connection": "gh", "argv": ["a\x00b"]})
        with self.assertRaises(InvalidInput):
            tools.dispatch(self.ctx, "exec", "agent-1", {"connection": "../etc", "argv": []})
        with self.assertRaises(InvalidInput):
            tools.dispatch(self.ctx, "request", "agent-1", {"connection": "gh", "method": "TRACE", "path": "/repos"})
        with self.assertRaises(InvalidInput):
            tools.dispatch(self.ctx, "request", "agent-1", {"connection": "gh", "method": "GET", "path": "repos"})
        with self.assertRaises(InvalidInput):
            tools.dispatch(self.ctx, "request", "agent-1", {"connection": "gh", "method": "GET", "path": "/re pos"})
        with self.assertRaises(InvalidInput):
            tools.dispatch(self.ctx, "request", "agent-1", {"connection": "gh", "method": "GET", "path": "/x",
                                                            "headers": {"Bad Name": "v"}})
        with self.assertRaises(InvalidInput):
            tools.dispatch(self.ctx, "request", "agent-1", {"connection": "gh", "method": "GET", "path": "/x",
                                                            "headers": {"X-A": "line\r\nInjected: 1"}})
        with self.assertRaises(InvalidInput):
            tools.dispatch(self.ctx, "request", "agent-1", {"connection": "gh", "method": "GET", "path": "/x",
                                                            "body": "a", "body_base64": "YQ=="})
        with self.assertRaises(InvalidInput):
            tools.dispatch(self.ctx, "request", "agent-1", {"connection": "gh", "method": "GET", "path": "/x",
                                                            "body_base64": "not base64!"})
        with self.assertRaises(InvalidInput):
            tools.dispatch(self.ctx, "request", "agent-1", {"connection": "gh", "method": "GET", "path": "/x",
                                                            "request_id": "has space"})
        # unknown keys are ignored
        result = tools.dispatch(self.ctx, "list_connections", "agent-1", {"unexpected": {"nested": True}})
        self.assertEqual([c["id"] for c in result["connections"]], ["gh"])


class ListConnectionsTestCase(ToolsFixture):
    def test_filters_to_caller_and_hides_secret_material(self) -> None:
        self.ctx.policy.create_connection(http_connection("other", None))
        self.ctx.policy.create_grant("agent-2", "other", 3600, 5)
        mine = tools.list_connections(self.ctx, "agent-1")
        theirs = tools.list_connections(self.ctx, "agent-2")
        self.assertEqual([c["id"] for c in mine["connections"]], ["gh"])
        self.assertEqual([c["id"] for c in theirs["connections"]], ["other"])
        self.assertEqual(theirs["connections"][0]["grant"]["remaining_uses"], 5)
        self.assertEqual(mine["connections"][0]["cli"], {"program": self.dump_program})
        text = json.dumps(mine) + json.dumps(theirs)
        self.assertNotIn(SYNTHETIC.decode(), text)
        self.assertNotIn("secret_id", text)
        self.assertNotIn("gh-token", text)
        self.assertNotIn("zpw1.", text)
        self.assertEqual(tools.list_connections(self.ctx, "ghost"), {"connections": []})
        event = self.events("tools_list_connections")[0]
        self.assertEqual((event["caller"], event["count"]), ("agent-1", 1))

    def test_stop_and_revocation_empty_the_list(self) -> None:
        self.ctx.policy.stop_all()
        self.assertEqual(tools.list_connections(self.ctx, "agent-1"), {"connections": []})
        self.ctx.policy.resume()
        self.assertEqual(len(tools.list_connections(self.ctx, "agent-1")["connections"]), 1)
        self.ctx.policy.revoke_grant(self.grant.id)
        self.assertEqual(tools.list_connections(self.ctx, "agent-1"), {"connections": []})

    def test_audit_failure_refuses(self) -> None:
        with mock.patch.object(self.ctx.audit, "record", side_effect=AuditUnavailable("audit_write_failed")):
            with self.assertRaises(AuditUnavailable):
                tools.list_connections(self.ctx, "agent-1")


class RequestTestCase(ToolsFixture):
    def test_delegates_to_gateway_and_filters_response(self) -> None:
        calls: list[tuple] = []

        def relay(ctx, caller, connection_id, method, path, headers, body, request_id=None):
            self.assertEqual(self.events("tools_request")[-1]["result"], "ok")  # audited before the relay
            calls.append((caller, connection_id, method, path, dict(headers), body, request_id))
            return FakeRelayResult(200, [("Content-Type", "application/json"), ("Set-Cookie", "session=leak"),
                                         ("WWW-Authenticate", "Bearer"), ("X-Upstream", "yes"),
                                         ("Authorization", "Bearer " + SYNTHETIC.decode()),
                                         ("Transfer-Encoding", "chunked")],
                                   b'{"ok": true}', None)

        with mock.patch.object(self.gateway, "relay_for_caller", side_effect=relay):
            result = tools.dispatch(self.ctx, "request", "agent-1", {
                "connection": "gh", "method": "get", "path": "/repos?per_page=2",
                "headers": {"Accept": "application/json"}, "body": None, "request_id": "req-1"})
        self.assertEqual(calls, [("agent-1", "gh", "GET", "/repos?per_page=2", {"Accept": "application/json"},
                                  b"", "req-1")])
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["body"], '{"ok": true}')
        self.assertIsNone(result["body_base64"])
        self.assertIsNone(result["reason"])
        self.assertEqual(result["headers"], {"content-type": "application/json", "x-upstream": "yes"})
        self.assertNotIn(SYNTHETIC.decode(), json.dumps(result))
        event = self.events("tools_request")[-1]
        self.assertEqual((event["caller"], event["connection"], event["method"], event["path"], event["request_id"]),
                         ("agent-1", "gh", "GET", "/repos", "req-1"))
        self.assertNotIn("per_page", json.dumps(event))

    def test_method_is_normalised_and_bodies_round_trip(self) -> None:
        seen: list[tuple[str, bytes]] = []

        def relay(ctx, caller, connection_id, method, path, headers, body, request_id=None):
            seen.append((method, body))
            return FakeRelayResult(201, [("Content-Type", "application/octet-stream")], b"\xff\xfe\x00binary", None)

        with mock.patch.object(self.gateway, "relay_for_caller", side_effect=relay):
            result = tools.dispatch(self.ctx, "request", "agent-1", {
                "connection": "gh", "method": "POST", "path": "/repos/demo/issues", "body": '{"title": "x"}'})
            self.assertEqual(seen[-1], ("POST", b'{"title": "x"}'))
            self.assertIsNone(result["body"])
            self.assertEqual(base64.b64decode(result["body_base64"]), b"\xff\xfe\x00binary")
            tools.dispatch(self.ctx, "request", "agent-1", {
                "connection": "gh", "method": "POST", "path": "/repos/demo/issues",
                "body_base64": base64.b64encode(b"\x00\x01").decode()})
            self.assertEqual(seen[-1], ("POST", b"\x00\x01"))

    def test_denied_without_usable_grant_never_reaches_gateway(self) -> None:
        with mock.patch.object(self.gateway, "relay_for_caller") as relay:
            self.ctx.policy.revoke_grant(self.grant.id)
            result = tools.request(self.ctx, "agent-1", "gh", "GET", "/repos")
            self.assertEqual((result["status"], result["reason"]), (403, "grant_revoked"))
            self.assertEqual(tools.request(self.ctx, "agent-2", "gh", "GET", "/repos")["reason"], "no_grant")
            self.assertEqual(tools.request(self.ctx, "agent-1", "nope", "GET", "/repos")["reason"],
                             "connection_unknown")
            self.ctx.policy.stop_all()
            self.assertEqual(tools.request(self.ctx, "agent-1", "gh", "GET", "/repos")["reason"], "global_stop")
            self.ctx.policy.resume()
            self.ctx.policy.set_restore_pending(True)
            self.assertEqual(tools.request(self.ctx, "agent-1", "gh", "GET", "/repos")["reason"], "restore_pending")
            relay.assert_not_called()
        denied = [r for r in self.events("tools_request") if r["result"] == "denied"]
        self.assertEqual([r["reason"] for r in denied],
                         ["grant_revoked", "no_grant", "connection_unknown", "global_stop", "restore_pending"])
        self.assertTrue(any(a["alert"] == "revoked_use_attempt" for a in self.ctx.audit.alerts()))

    def test_ssh_connection_is_not_relayable(self) -> None:
        self.ctx.vault.put_secret("box-key", "ssh_private_key", _ssh_key_pem(), "demo", "dev")
        self.ctx.policy.create_connection(ssh_connection("box", None))
        self.ctx.policy.create_grant("agent-1", "box", 3600, None)
        with mock.patch.object(self.gateway, "relay_for_caller") as relay:
            result = tools.request(self.ctx, "agent-1", "box", "GET", "/")
            relay.assert_not_called()
        self.assertEqual((result["status"], result["reason"]), (403, "action_kind_mismatch"))

    def test_audit_failure_refuses_before_relay(self) -> None:
        with mock.patch.object(self.gateway, "relay_for_caller") as relay, \
                mock.patch.object(self.ctx.audit, "record", side_effect=AuditUnavailable("audit_write_failed")):
            with self.assertRaises(AuditUnavailable):
                tools.request(self.ctx, "agent-1", "gh", "GET", "/repos")
            relay.assert_not_called()


class ExecTestCase(ToolsFixture):
    def test_child_gets_minimal_env_handle_url_and_only_arguments(self) -> None:
        view, dump = self.exec_dump(extra=["alpha", "--beta", "gamma delta", "/bin/sh"])
        self.assertEqual(view["stdout"].strip(), "dumped")
        self.assertEqual(view["exit_code"], 0)
        env = dump["env"]
        self.assertEqual(child_env_names(env), ALLOWED_HTTP_ENV)
        self.assertTrue(env["ZEROPW_API_BASE_URL"].startswith("http://127.0.0.1:1/h/zpw1."))
        self.assertIn("/h/zpw1.", env["ZEROPW_API_BASE_URL"])
        self.assertEqual(env["LANG"], "C.UTF-8")
        self.assertEqual(env["PATH"], os.environ.get("PATH", "/usr/bin:/bin"))
        self.assertEqual(env["HOME"], dump["cwd"])
        self.assertEqual(env["TMPDIR"], dump["cwd"])
        self.assertEqual(env["ZEROPW_RUN_ID"], view["run_id"])
        run_dir = Path(dump["cwd"])
        self.assertEqual(run_dir.parent, Path(self.ctx.config.run_dir).resolve())
        self.assertFalse(run_dir.exists())  # cleaned up after the run
        self.assertEqual(dump["argv"][0], self.dump_program)
        self.assertEqual(dump["argv"][2:], ["alpha", "--beta", "gamma delta", "/bin/sh"])
        blob = json.dumps(dump)
        self.assertNotIn(SYNTHETIC.decode(), blob)
        self.assertNotIn(base64.b64encode(SYNTHETIC).decode(), blob)
        self.assertNotIn("gh-token", blob)
        # the handle in the URL verifies to this caller/connection/grant and nothing else
        handle = env["ZEROPW_API_BASE_URL"].split("/h/", 1)[1]
        parsed = self.ctx.handles.verify(handle)
        self.assertEqual((parsed.caller, parsed.connection, parsed.grant, parsed.policy_version),
                         ("agent-1", "gh", self.grant.id, 1))
        self.assertLessEqual(parsed.expires_at - parsed.issued_at, self.ctx.config.handle_ttl_seconds)
        names = [r["event"] for r in self.events()]
        first_exec = names.index("tools_exec")
        self.assertLess(first_exec, names.index("handle_issue"))
        self.assertLess(names.index("handle_issue"), names.index("run_start"))
        self.assertIn("run_finish", names)
        self.assertNotIn(SYNTHETIC.decode(), self.all_state_text())

    def test_run_dir_is_fresh_and_private(self) -> None:
        modes: list[int] = []
        original_mkdtemp = tempfile.mkdtemp

        def spy(*args: Any, **kwargs: Any) -> str:
            path = original_mkdtemp(*args, **kwargs)
            modes.append(os.stat(path).st_mode & 0o777)
            return path

        with mock.patch.object(tools.tempfile, "mkdtemp", side_effect=spy):
            _, first = self.exec_dump()
            _, second = self.exec_dump()
        self.assertEqual(modes, [0o700, 0o700])
        self.assertNotEqual(first["cwd"], second["cwd"])

    def test_requires_cli_profile_and_existing_executable_program(self) -> None:
        self.ctx.policy.create_connection(http_connection("nocli", None))
        self.ctx.policy.create_grant("agent-1", "nocli", 3600, None)
        with self.assertRaises(Unsupported) as caught:
            tools.exec(self.ctx, "agent-1", "nocli", ["list-repos"])
        self.assertEqual(caught.exception.reason, "cli_not_supported")

        self.ctx.policy.create_connection(http_connection("missing", str(self.scripts / "absent.py")))
        self.ctx.policy.create_grant("agent-1", "missing", 3600, None)
        with self.assertRaises(Unsupported) as caught:
            tools.exec(self.ctx, "agent-1", "missing", [])
        self.assertEqual(caught.exception.reason, "cli_program_missing")

        plain = self.scripts / "plain.py"
        plain.write_text("print('x')\n")
        plain.chmod(0o600)
        self.ctx.policy.create_connection(http_connection("notexec", str(plain)))
        self.ctx.policy.create_grant("agent-1", "notexec", 3600, None)
        with self.assertRaises(Unsupported) as caught:
            tools.exec(self.ctx, "agent-1", "notexec", [])
        self.assertEqual(caught.exception.reason, "cli_program_missing")

        self.ctx.policy.create_connection(http_connection("byname", "zeropw-no-such-program-xyz"))
        self.ctx.policy.create_grant("agent-1", "byname", 3600, None)
        with self.assertRaises(Unsupported):
            tools.exec(self.ctx, "agent-1", "byname", [])
        reasons = [r["reason"] for r in self.events("tools_exec") if r["result"] == "unsupported"]
        self.assertEqual(reasons, ["cli_not_supported", "cli_program_missing", "cli_program_missing",
                                   "cli_program_missing"])
        self.assertEqual(self.registry.active_runs(), [])

    def test_agent_cannot_choose_the_program(self) -> None:
        echo = self.script("echo.py", ECHO_SCRIPT)
        self.ctx.policy.create_connection(http_connection("echo", echo))
        self.ctx.policy.create_grant("agent-1", "echo", 3600, None)
        result = tools.exec(self.ctx, "agent-1", "echo", ["/bin/sh", "-c", "id"])
        view = self.wait(result["run_id"])
        self.assertEqual(view["state"], "completed")
        self.assertEqual(view["stdout"].strip(), "/bin/sh -c id")
        self.assertEqual(self.events("run_start")[-1]["program"], echo)

    def test_policy_denials_are_precise_and_audited(self) -> None:
        with self.assertRaises(PolicyDenied) as caught:
            tools.exec(self.ctx, "agent-2", "gh", [])
        self.assertEqual(caught.exception.reason, "no_grant")
        with self.assertRaises(PolicyDenied) as caught:
            tools.exec(self.ctx, "agent-1", "ghost", [])
        self.assertEqual(caught.exception.reason, "connection_unknown")
        self.ctx.policy.stop_all()
        with self.assertRaises(PolicyDenied) as caught:
            tools.exec(self.ctx, "agent-1", "gh", [])
        self.assertEqual(caught.exception.reason, "global_stop")
        self.ctx.policy.resume()
        self.ctx.policy.set_restore_pending(True)
        with self.assertRaises(PolicyDenied) as caught:
            tools.exec(self.ctx, "agent-1", "gh", [])
        self.assertEqual(caught.exception.reason, "restore_pending")
        self.ctx.policy.set_restore_pending(False)
        # widening the connection makes the grant stale: no inheritance of broader scope
        self.ctx.policy.update_connection("gh", http_scope=P.HttpScope(None, None, ()))
        with self.assertRaises(PolicyDenied) as caught:
            tools.exec(self.ctx, "agent-1", "gh", [])
        self.assertEqual(caught.exception.reason, "grant_stale")
        fresh = self.ctx.policy.regrant(self.grant.id)  # regrant revokes the stale grant
        self.ctx.policy.revoke_grant(fresh.id)
        with self.assertRaises(PolicyDenied) as caught:
            tools.exec(self.ctx, "agent-1", "gh", [])
        self.assertEqual(caught.exception.reason, "grant_revoked")
        # a principal with exactly one, exhausted grant (evaluate reports the state of the last grant it sees)
        self.ctx.policy.create_principal("agent-3")
        capped = self.ctx.policy.create_grant("agent-3", "gh", 3600, 1)
        self.ctx.policy.consume(capped.id)
        with self.assertRaises(PolicyDenied) as caught:
            tools.exec(self.ctx, "agent-3", "gh", [])
        self.assertEqual(caught.exception.reason, "grant_exhausted")
        self.ctx.policy.disable_principal("agent-1")
        with self.assertRaises(PolicyDenied) as caught:
            tools.exec(self.ctx, "agent-1", "gh", [])
        self.assertEqual(caught.exception.reason, "principal_disabled")
        denied = [r["reason"] for r in self.events("tools_exec") if r["result"] == "denied"]
        self.assertEqual(denied, ["no_grant", "connection_unknown", "global_stop", "restore_pending", "grant_stale",
                                  "grant_revoked", "grant_exhausted", "principal_disabled"])
        self.assertEqual(self.events("handle_issue"), [])
        self.assertEqual(self.registry.active_runs(), [])

    def test_expired_grant_is_refused(self) -> None:
        # agent-2 holds exactly one grant, so the reported reason is unambiguous
        self.ctx.policy.create_grant("agent-2", "gh", 1, None)
        self.assertEqual(tools.exec(self.ctx, "agent-2", "gh", [str(self.root / "x.json")])["state"], "running")
        time.sleep(1.1)
        with self.assertRaises(PolicyDenied) as caught:
            tools.exec(self.ctx, "agent-2", "gh", [])
        self.assertEqual(caught.exception.reason, "grant_expired")
        self.assertEqual(self.events("tools_exec")[-1]["reason"], "grant_expired")

    def test_public_url_must_be_set(self) -> None:
        self.ctx.config.extra.pop("public_url", None)
        with self.assertRaises(StateError) as caught:
            tools.exec(self.ctx, "agent-1", "gh", [])
        self.assertEqual(caught.exception.reason, "public_url_unset")
        with self.assertRaises(InvalidInput):
            tools.set_public_url(self.ctx, "ftp://127.0.0.1:1")
        self.assertEqual(tools.set_public_url(self.ctx, "http://127.0.0.1:1/"), "http://127.0.0.1:1")

    def test_audit_failure_refuses_exec_before_handle_issue(self) -> None:
        with mock.patch.object(self.ctx.audit, "record", side_effect=AuditUnavailable("audit_write_failed")):
            with self.assertRaises(AuditUnavailable):
                tools.exec(self.ctx, "agent-1", "gh", [])
        self.assertEqual(self.events("handle_issue"), [])
        self.assertEqual(self.registry.active_runs(), [])

    def test_output_containing_handle_or_credential_is_blocked(self) -> None:
        printer = self.script("printenv.py", PRINT_ENV_SCRIPT)
        self.ctx.policy.create_connection(http_connection("printer", printer))
        self.ctx.policy.create_grant("agent-1", "printer", 3600, None)
        result = tools.exec(self.ctx, "agent-1", "printer", ["ZEROPW_API_BASE_URL"])
        view = self.wait(result["run_id"])
        self.assertEqual(view["state"], "blocked")
        self.assertEqual(view["reason"], "output_credential_blocked")
        self.assertEqual(view["stdout"], "[blocked: output contained authentication material]")
        self.assertNotIn("zpw1.", json.dumps(view))
        harmless = tools.exec(self.ctx, "agent-1", "printer", ["ZEROPW_RUN_ID"])
        view = self.wait(harmless["run_id"])
        self.assertEqual(view["state"], "completed")
        self.assertEqual(view["stdout"].strip(), harmless["run_id"])

        echo = self.script("echo.py", ECHO_SCRIPT)
        self.ctx.policy.create_connection(http_connection("echo", echo))
        self.ctx.policy.create_grant("agent-1", "echo", 3600, None)
        # the child never has the value; simulate a leak by echoing what the test knows
        leak = tools.exec(self.ctx, "agent-1", "echo", ["token:" + SYNTHETIC.hex()])
        view = self.wait(leak["run_id"])
        self.assertEqual(view["state"], "blocked")
        self.assertNotIn(SYNTHETIC.hex(), json.dumps(view))
        finish = [r for r in self.events("run_finish") if r["result"] == "blocked"]
        self.assertEqual(len(finish), 2)
        self.assertTrue(all(r["reason"] == "output_credential_blocked" for r in finish))

    def test_revocation_and_stop_cancel_running_runs(self) -> None:
        sleeper = self.script("sleep.py", SLEEP_SCRIPT)
        self.ctx.policy.create_connection(http_connection("sleep", sleeper))
        grant = self.ctx.policy.create_grant("agent-1", "sleep", 3600, None)
        first = tools.exec(self.ctx, "agent-1", "sleep", ["30"])
        self.assertEqual(first["state"], "running")
        self.ctx.policy.revoke_grant(grant.id)
        view = self.wait(first["run_id"])
        self.assertEqual((view["state"], view["reason"]), ("cancelled", "grant_revoked"))
        regrant = self.ctx.policy.create_grant("agent-1", "sleep", 3600, None)
        self.assertTrue(regrant.id)
        running = tools.exec(self.ctx, "agent-1", "sleep", ["30"])
        self.ctx.policy.stop_all()
        view = self.wait(running["run_id"])
        self.assertEqual((view["state"], view["reason"]), ("cancelled", "global_stop"))
        self.ctx.policy.resume()
        running = tools.exec(self.ctx, "agent-1", "sleep", ["30"])
        self.ctx.policy.disable_connection("sleep")
        view = self.wait(running["run_id"])
        self.assertEqual(view["state"], "cancelled")
        self.assertIn(view["reason"], ("connection_changed", "grant_stale"))

    def test_exec_timeout(self) -> None:
        sleeper = self.script("sleep.py", SLEEP_SCRIPT)
        self.ctx.policy.create_connection(http_connection("sleep", sleeper))
        self.ctx.policy.create_grant("agent-1", "sleep", 3600, None)
        self.ctx.config.exec_timeout_seconds = 0.5
        result = tools.exec(self.ctx, "agent-1", "sleep", ["30"])
        view = self.wait(result["run_id"])
        self.assertEqual((view["state"], view["reason"]), ("failed", "timeout"))

    def test_status_and_cancel_are_owner_scoped(self) -> None:
        sleeper = self.script("sleep.py", SLEEP_SCRIPT)
        self.ctx.policy.create_connection(http_connection("sleep", sleeper))
        self.ctx.policy.create_grant("agent-1", "sleep", 3600, None)
        ready = self.root / "ready"
        result = tools.exec(self.ctx, "agent-1", "sleep", ["30", str(ready)])
        run_id = result["run_id"]
        deadline = time.monotonic() + 15
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(ready.exists())
        with self.assertRaises(NotFound) as caught:
            tools.status(self.ctx, "agent-2", run_id)
        self.assertEqual(caught.exception.reason, "run_not_found")
        with self.assertRaises(NotFound):
            tools.cancel(self.ctx, "agent-2", run_id)
        with self.assertRaises(NotFound):
            tools.status(self.ctx, "agent-1", "r-0000000000000000")
        self.assertEqual(tools.status(self.ctx, "agent-1", run_id)["state"], "running")
        cancelled = tools.cancel(self.ctx, "agent-1", run_id)
        self.assertEqual((cancelled["run_id"], cancelled["state"]), (run_id, "cancelled"))
        view = tools.status(self.ctx, "agent-1", run_id)
        self.assertEqual(view["state"], "cancelled")
        self.assertEqual(view["stdout"].strip(), "sleeping")
        denied = [r for r in self.events() if r["event"] in ("tools_status", "tools_cancel") and r["result"] == "denied"]
        self.assertEqual([r["reason"] for r in denied], ["run_not_found"] * 3)
        self.assertEqual(self.events("tools_cancel")[-1]["result"], "ok")
        self.assertEqual(len(self.events("run_cancel")), 1)

    def test_request_id_makes_exec_idempotent(self) -> None:
        echo = self.script("echo.py", ECHO_SCRIPT)
        self.ctx.policy.create_connection(http_connection("echo", echo))
        self.ctx.policy.create_grant("agent-1", "echo", 3600, None)
        first = tools.exec(self.ctx, "agent-1", "echo", ["a"], request_id="req-1")
        again = tools.exec(self.ctx, "agent-1", "echo", ["a"], request_id="req-1")
        self.assertEqual(first["run_id"], again["run_id"])
        with self.assertRaises(InvalidInput) as caught:
            tools.exec(self.ctx, "agent-1", "echo", ["b"], request_id="req-1")
        self.assertEqual(caught.exception.reason, "request_id_reused")
        self.assertEqual(len(self.events("run_start")), 1)
        self.wait(first["run_id"])

    def test_responses_never_contain_secret_material(self) -> None:
        view, _ = self.exec_dump()
        texts = [json.dumps(view), json.dumps(tools.list_connections(self.ctx, "agent-1")),
                 json.dumps(tools.status(self.ctx, "agent-1", view["run_id"])),
                 json.dumps(tools.cancel(self.ctx, "agent-1", view["run_id"]))]
        for text in texts:
            self.assertNotIn(SYNTHETIC.decode(), text)
            self.assertNotIn("zpw1.", text)
            self.assertNotIn("gh-token", text)
            self.assertNotIn(str(self.ctx.config.run_dir), text)
            # Also no encoded form (aligned/urlsafe base64, hex, percent) or decodable token carrying it.
            self.assertIsNone(find_secret(text, [SYNTHETIC]))
        # The administrator's audit view and every state file hold no decodable copy either.
        self.assertIsNone(find_secret(json.dumps(self.events()), [SYNTHETIC]))
        for path in (self.root / "state").rglob("*"):
            if path.is_file():
                self.assertIsNone(find_secret(path.read_bytes(), [SYNTHETIC]), str(path.relative_to(self.root)))


class SshExecTestCase(ToolsFixture):
    def setUp(self) -> None:
        super().setUp()
        self.ctx.vault.put_secret("box-key", "ssh_private_key", _ssh_key_pem(), "demo", "dev")
        self.fake_ssh = self.script("ssh.py", FAKE_SSH_SCRIPT)
        self.ctx.policy.create_connection(ssh_connection("box", self.fake_ssh))
        self.box_grant = self.ctx.policy.create_grant("agent-1", "box", 3600, None)
        self.manager = FakeSignerManager(self.root)

    def test_signer_required(self) -> None:
        self.ctx.signer_manager = None
        with self.assertRaises(Unsupported) as caught:
            tools.exec(self.ctx, "agent-1", "box", ["uptime"])
        self.assertEqual(caught.exception.reason, "ssh_signer_unavailable")
        self.assertEqual(self.events("tools_exec")[-1]["reason"], "ssh_signer_unavailable")

    def test_fixed_ssh_argv_socket_env_and_known_hosts(self) -> None:
        self.ctx.signer_manager = self.manager
        out = self.root / "ssh-dump.json"
        result = tools.exec(self.ctx, "agent-1", "box", [str(out), "uptime", "-o", "ProxyCommand=evil"])
        view = self.wait(result["run_id"])
        self.assertEqual(view["state"], "completed", view)
        dump = json.loads(out.read_text())
        binding = self.manager.bindings[0]
        self.assertEqual((binding.caller, binding.connection_id, binding.grant_id), ("agent-1", "box", self.box_grant.id))
        self.assertTrue(binding.closed)
        env = dump["env"]
        self.assertEqual(child_env_names(env), ALLOWED_SSH_ENV)
        self.assertEqual(env["SSH_AUTH_SOCK"], str(binding.socket_path))
        self.assertEqual(env["HOME"], dump["cwd"])
        argv = dump["argv"]
        known_hosts = f"{dump['cwd']}/known_hosts"
        self.assertEqual(argv, [
            self.fake_ssh,
            "-F", "/dev/null",
            "-o", "IdentitiesOnly=yes",
            "-o", f"IdentityFile={dump['cwd']}/id.pub",
            "-o", f"IdentityAgent={binding.socket_path}",
            "-o", "ForwardAgent=no",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-p", "2222",
            "deploy@127.0.0.1",
            "--", str(out), "uptime", "-o", "ProxyCommand=evil",
        ])
        self.assertEqual(dump["known_hosts"], f"[127.0.0.1]:2222 {HOST_KEY}\n")
        # IdentitiesOnly=yes needs a matching IdentityFile: only the public key line, never the private key.
        public_line = self.ctx.vault.get_meta("box-key").versions[0].public["public_key"]
        self.assertEqual(dump["identity"]["mode"], 0o600)
        self.assertEqual(len(dump["identity"]["text"].splitlines()), 1)
        # Same key type and blob as the vault's public key; the comment is ZeroPW's own label.
        self.assertEqual(dump["identity"]["text"].split()[:2], public_line.split()[:2])
        self.assertEqual(dump["identity"]["text"].split()[2:], ["zeropw:box"])
        self.assertTrue(dump["identity"]["text"].startswith("ssh-ed25519 "))
        blob = json.dumps(dump)
        self.assertNotIn("PRIVATE KEY", blob)
        self.assertNotIn("box-key", blob)
        # The run directory holds exactly the two managed files, and no file, env value or argument carries the
        # private key in any encoding (PEM text, decoded key blob, seed).
        self.assertEqual(set(dump["entries"]), {"id.pub", "known_hosts"})
        material = ssh_key_material(self.ctx.vault.secret_for_trusted_use("box-key"))
        for name, content in dump["entries"].items():
            self.assertIsNone(find_secret(bytes.fromhex(content), material), name)
        for name, value in env.items():
            self.assertIsNone(find_secret(value, material), name)
        for item in argv:
            self.assertIsNone(find_secret(item, material))
        self.assertIsNone(find_secret(json.dumps([view, self.events()]), material))
        self.assertFalse(Path(dump["cwd"]).exists())

    def test_default_port_known_hosts_format(self) -> None:
        self.ctx.signer_manager = self.manager
        self.ctx.policy.create_connection(ssh_connection("box22", self.fake_ssh, port=22))
        self.ctx.policy.create_grant("agent-1", "box22", 3600, None)
        out = self.root / "ssh22.json"
        result = tools.exec(self.ctx, "agent-1", "box22", [str(out)])
        self.wait(result["run_id"])
        dump = json.loads(out.read_text())
        self.assertEqual(dump["known_hosts"], f"127.0.0.1 {HOST_KEY}\n")
        self.assertIn("-p", dump["argv"])
        self.assertEqual(dump["argv"][dump["argv"].index("-p") + 1], "22")

    def test_binding_failure_cleans_up(self) -> None:
        class Broken:
            def bind(self, caller: str, connection_id: str, grant_id: str) -> Any:
                raise RuntimeError("signer down")

        self.ctx.signer_manager = Broken()
        with self.assertRaises(RuntimeError):
            tools.exec(self.ctx, "agent-1", "box", ["uptime"])
        self.assertEqual(self.registry.active_runs(), [])
        self.assertEqual(list(Path(self.ctx.config.run_dir).iterdir()), [])
        self.assertEqual(self.events("run_finish")[-1]["reason"], "exec_setup_failed")


class DemoCliTestCase(ToolsFixture):
    def setUp(self) -> None:
        super().setUp()
        self.upstream = RecordingUpstream()
        self.thread = threading.Thread(target=self.upstream.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        # The sample CLI itself is the fixed program; only its shebang is pointed at the test interpreter.
        source = DEMOCLI.read_text().split("\n", 1)[1]
        launcher = self.scripts / "democli"
        launcher.write_text(f"#!{sys.executable}\n{source}")
        launcher.chmod(0o700)
        self.ctx.policy.create_connection(http_connection("demo", str(launcher)))
        self.ctx.policy.create_grant("agent-1", "demo", 3600, None)
        tools.set_public_url(self.ctx, self.upstream.url)

    def tearDown(self) -> None:
        self.upstream.shutdown()
        self.upstream.server_close()
        self.thread.join(5)
        super().tearDown()

    def test_list_repos_and_create_issue_send_placeholder_only(self) -> None:
        result = tools.exec(self.ctx, "agent-1", "demo", ["list-repos"])
        view = self.wait(result["run_id"])
        self.assertEqual(view["state"], "completed", view)
        self.assertEqual(view["exit_code"], 0)
        output = json.loads(view["stdout"])
        self.assertEqual(output["status"], 200)
        self.assertEqual([r["name"] for r in output["body"]], ["demo", "tools"])

        result = tools.exec(self.ctx, "agent-1", "demo", ["create-issue", "demo", "Hello issue"])
        view = self.wait(result["run_id"])
        self.assertEqual(view["state"], "completed", view)
        output = json.loads(view["stdout"])
        self.assertEqual((output["status"], output["body"]["title"]), (201, "Hello issue"))

        self.assertEqual(len(self.upstream.requests), 2)
        listing, creating = self.upstream.requests
        self.assertEqual(listing["method"], "GET")
        self.assertTrue(listing["path"].startswith("/h/zpw1."), listing["path"])
        self.assertTrue(listing["path"].endswith("/repos"))
        self.assertEqual(creating["method"], "POST")
        self.assertTrue(creating["path"].endswith("/repos/demo/issues"))
        self.assertEqual(json.loads(creating["body"]), {"title": "Hello issue"})
        for recorded in (listing, creating):
            self.assertEqual(recorded["headers"].get("Authorization"), "Bearer democli-placeholder")
            blob = json.dumps(recorded["headers"]) + recorded["body"].decode("utf-8", "replace")
            self.assertNotIn(SYNTHETIC.decode(), blob)
            self.assertNotIn(base64.b64encode(SYNTHETIC).decode(), blob)
        handle = listing["path"][len("/h/"):].split("/", 1)[0]
        parsed = self.ctx.handles.verify(handle)
        self.assertEqual((parsed.caller, parsed.connection), ("agent-1", "demo"))

    def test_steal_finds_nothing(self) -> None:
        result = tools.exec(self.ctx, "agent-1", "demo", ["steal", "--please"])
        view = self.wait(result["run_id"])
        self.assertEqual(view["state"], "completed", view)
        report = json.loads(view["stdout"])
        self.assertEqual(child_env_names(dict.fromkeys(report["env_names"], "")), ALLOWED_HTTP_ENV)
        self.assertEqual(report["argv"], ["steal", "--please"])
        self.assertTrue(report["base_url"].endswith("/h/<opaque-handle-redacted>"))
        self.assertEqual(report["home_entries"], [])
        self.assertTrue(all(v == "missing" for v in report["probes"].values()), report["probes"])
        text = view["stdout"] + view["stderr"]
        self.assertNotIn(SYNTHETIC.decode(), text)
        self.assertNotIn("zpw1.", text)
        self.assertEqual(self.upstream.requests, [])

    def test_democli_runs_standalone_and_refuses_without_base_url(self) -> None:
        import subprocess

        proc = subprocess.run([sys.executable, str(DEMOCLI), "whoami"], capture_output=True, text=True,
                              env={"PATH": os.environ.get("PATH", ""), "HOME": self.tmp.name}, timeout=30)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(json.loads(proc.stdout)["error"], "base_url_unset")
        proc = subprocess.run([sys.executable, str(DEMOCLI)], capture_output=True, text=True,
                              env={"PATH": os.environ.get("PATH", ""), "HOME": self.tmp.name}, timeout=30)
        self.assertEqual(proc.returncode, 2)


def _ssh_key_pem() -> bytes:
    from zeropw import sshwire

    return sshwire.generate_ed25519_private_key("demo").to_openssh_private_key().encode()


COUNTER_SCRIPT = """
import sys, time
with open(sys.argv[1], "a") as fh:
    fh.write("ran\\n")
time.sleep(0.2)
"""


class ExecHardeningTestCase(ToolsFixture):
    """Isolation of agent-facing directories, spawn-time policy re-check, idempotency, response hygiene."""

    def state_path(self) -> str:
        return str((self.root / "state").resolve())

    def test_agent_facing_directories_live_outside_the_state_directory(self) -> None:
        state = self.state_path()
        for name in ("run_dir", "socket_dir"):
            configured = str(Path(getattr(self.ctx.config, name)).resolve())
            self.assertFalse(configured.startswith(state), (name, configured))
            self.assertEqual(Path(configured).stat().st_mode & 0o777, 0o700, name)
        _view, dump = self.exec_dump()
        for key in ("HOME", "TMPDIR"):
            self.assertFalse(str(Path(dump["env"][key]).resolve()).startswith(state), key)
        self.assertFalse(str(Path(dump["cwd"]).resolve()).startswith(state))
        for key, value in dump["env"].items():
            self.assertNotIn(state, value, key)
            self.assertNotIn(str(self.root / "state"), value, key)
        # An explicitly configured run_dir inside the state store is refused.
        with self.assertRaises(StateError) as caught:
            Context.open(self.root / "state", Config(run_dir=self.root / "state" / "runs"))
        self.assertEqual(caught.exception.reason, "run_dir_inside_state_dir")
        with self.assertRaises(StateError) as caught:
            Context.open(self.root / "state", Config(socket_dir=self.root / "state"))
        self.assertEqual(caught.exception.reason, "socket_dir_inside_state_dir")

    def test_signer_socket_path_is_outside_the_state_directory(self) -> None:
        from zeropw import signer, sshwire

        key = sshwire.generate_ed25519_private_key("iso")
        self.ctx.vault.put_secret("iso-key", "ssh_private_key", key.to_openssh_private_key().encode(), "demo", "dev")
        self.ctx.policy.create_connection(P.Connection(
            id="iso", project="demo", environment="dev", service="ssh", kind="ssh", secret_id="iso-key",
            secret_version=None, description="", http_target=None, http_auth=None, http_scope=None,
            ssh_target=P.SshTarget("127.0.0.1", 2222, "deploy", (HOST_KEY,)), cli=None,
            policy_version=0, status="active", created_at="", updated_at=""))
        grant = self.ctx.policy.create_grant("agent-1", "iso", 60, None)
        manager = signer.install(self.ctx)
        try:
            binding = manager.bind("agent-1", "iso", grant.id)
            self.assertFalse(str(Path(binding.socket_path).resolve()).startswith(self.state_path()))
        finally:
            manager.shutdown()

    def _limited_connection(self) -> P.Grant:
        self.ctx.policy.create_connection(http_connection("limited", self.dump_program))
        return self.ctx.policy.create_grant("agent-1", "limited", 3600, 1)

    def test_policy_change_between_registration_and_spawn_prevents_the_child(self) -> None:
        """A change that sends no revoke notification (usage exhaustion) is caught by the spawn-time re-check."""
        grant = self._limited_connection()
        out = self.root / "never-written.json"
        original = self.ctx.vault.secret_for_trusted_use

        def exhaust_then_fetch(*args: Any, **kwargs: Any) -> bytes:
            self.ctx.policy.consume(grant.id)  # the only use is spent after the first check passed
            return original(*args, **kwargs)

        with mock.patch.object(self.ctx.vault, "secret_for_trusted_use", side_effect=exhaust_then_fetch):
            result = tools.exec(self.ctx, "agent-1", "limited", [str(out)])
        self.assertEqual((result["state"], result["reason"]), ("cancelled", "grant_exhausted"))
        run = self.registry.get(result["run_id"], "agent-1")
        self.registry.wait(run, 5)
        time.sleep(0.3)
        self.assertFalse(out.exists(), "the child must never have been spawned")
        self.assertEqual(list(Path(self.ctx.config.run_dir).iterdir()), [])
        self.assertNotIn("run_start", [e["event"] for e in self.events() if e.get("run_id") == run.id])
        self.assertIn(("denied", "grant_exhausted"),
                      [(e["result"], e["reason"]) for e in self.events("tools_exec")])

    def test_revocation_between_registration_and_spawn_prevents_the_child(self) -> None:
        out = self.root / "never-written-revoked.json"
        original = self.ctx.vault.secret_for_trusted_use

        def revoke_then_fetch(*args: Any, **kwargs: Any) -> bytes:
            self.ctx.policy.revoke_grant(self.grant.id)
            return original(*args, **kwargs)

        with mock.patch.object(self.ctx.vault, "secret_for_trusted_use", side_effect=revoke_then_fetch):
            result = tools.exec(self.ctx, "agent-1", "gh", [str(out)])
        self.assertEqual(result["state"], "cancelled")
        self.assertIn(result["reason"], ("grant_revoked",))
        time.sleep(0.3)
        self.assertFalse(out.exists())
        with mock.patch.object(self.ctx.vault, "secret_for_trusted_use", side_effect=original):
            with self.assertRaises(PolicyDenied):
                tools.exec(self.ctx, "agent-1", "gh", [str(out)])

    def test_global_stop_between_registration_and_spawn_prevents_the_child(self) -> None:
        out = self.root / "never-written-stop.json"
        original = self.ctx.vault.secret_for_trusted_use

        def stop_then_fetch(*args: Any, **kwargs: Any) -> bytes:
            self.ctx.policy.stop_all()
            return original(*args, **kwargs)

        with mock.patch.object(self.ctx.vault, "secret_for_trusted_use", side_effect=stop_then_fetch):
            result = tools.exec(self.ctx, "agent-1", "gh", [str(out)])
        self.assertEqual((result["state"], result["reason"]), ("cancelled", "global_stop"))
        time.sleep(0.3)
        self.assertFalse(out.exists())
        self.ctx.policy.resume()

    def test_concurrent_duplicate_request_ids_run_exactly_once(self) -> None:
        counter_program = self.script("counter.py", COUNTER_SCRIPT)
        self.ctx.policy.create_connection(http_connection("counted", counter_program))
        self.ctx.policy.create_grant("agent-1", "counted", 3600, None)
        marks = self.root / "marks.txt"
        barrier = threading.Barrier(8)
        results: list[dict[str, Any]] = []
        errors: list[BaseException] = []
        lock = threading.Lock()

        def worker() -> None:
            try:
                barrier.wait(5)
                result = tools.exec(self.ctx, "agent-1", "counted", [str(marks)], request_id="req-same")
                with lock:
                    results.append(result)
            except BaseException as exc:  # pragma: no cover - reported below
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(20)
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 8)
        run_ids = {r["run_id"] for r in results}
        self.assertEqual(len(run_ids), 1, results)
        run = self.registry.get(run_ids.pop(), "agent-1")
        self.registry.wait(run, 20)
        self.assertEqual(marks.read_text().splitlines(), ["ran"])
        with self.assertRaises(InvalidInput) as caught:
            tools.exec(self.ctx, "agent-1", "counted", [str(marks), "different"], request_id="req-same")
        self.assertEqual(caught.exception.reason, "request_id_reused")
        # Another caller's identical request id is an independent slot.
        self.ctx.policy.create_grant("agent-2", "counted", 3600, None)
        other = tools.exec(self.ctx, "agent-2", "counted", [str(marks)], request_id="req-same")
        self.assertNotEqual(other["run_id"], run.id)
        self.registry.wait(self.registry.get(other["run_id"], "agent-2"), 20)
        self.assertEqual(marks.read_text().splitlines(), ["ran", "ran"])

    def test_exec_and_status_responses_carry_no_handle_path_or_environment(self) -> None:
        out = self.root / "hygiene.json"
        result = tools.exec(self.ctx, "agent-1", "gh", [str(out)])
        self.assertEqual(set(result), {"run_id", "state", "reason"})
        run = self.registry.get(result["run_id"], "agent-1")
        self.registry.wait(run, 20)
        dump = json.loads(out.read_text())
        status = tools.status(self.ctx, "agent-1", result["run_id"])
        blob = json.dumps([result, status])
        handle_url = dump["env"]["ZEROPW_API_BASE_URL"]
        handle = handle_url.rsplit("/h/", 1)[1]
        for needle in (handle, handle_url, dump["cwd"], dump["env"]["HOME"], str(self.ctx.config.run_dir),
                       str(self.ctx.config.socket_dir), self.state_path(), SYNTHETIC.decode()):
            self.assertNotIn(needle, blob, needle)
        self.assertNotIn("zpw1.", blob)
        self.assertEqual(status["stdout"].strip(), "dumped")
        cancelled = tools.cancel(self.ctx, "agent-1", result["run_id"])
        self.assertNotIn(handle, json.dumps(cancelled))


class ExecEnvAuditCancelTestCase(ToolsFixture):
    """Review regressions: credential in CLI env (F1), audit target/policy version (F9), cancel vs audit (PL-8)."""

    def _env_connection(self, cid: str, extra_env: dict[str, str], base_url_env: str = "ZEROPW_API_BASE_URL") -> None:
        self.ctx.policy.create_connection(http_connection(
            cid, None, cli=P.CliProfile(self.dump_program, "http", base_url_env=base_url_env, extra_env=extra_env)))
        self.ctx.policy.create_grant("agent-1", cid, 3600, None)

    def test_cli_env_carrying_the_credential_is_refused_before_any_artefact(self) -> None:
        secret = SYNTHETIC.decode()
        variants = {
            "raw": {"GH_TOKEN": secret},
            "embedded": {"AUTH_HEADER": "Bearer " + secret},
            "base64": {"GH_AUTH": "Basic " + base64.b64encode(SYNTHETIC).decode()},
            "hex": {"GH_HEX": SYNTHETIC.hex()},
            "urlencoded": {"GH_URL": "https://x/?t=" + secret.replace("-", "%2D")},
        }
        # Environment *names* are scanned as well: a credential that is a valid variable name.
        self.ctx.vault.put_secret("name-token", "api_key", b"GH_SYNTHETIC_TOKEN_0123456789", "demo", "dev")
        self.ctx.policy.create_connection(http_connection(
            "byname", None, secret_id="name-token",
            cli=P.CliProfile(self.dump_program, "http", extra_env={"GH_SYNTHETIC_TOKEN_0123456789": "1"})))
        self.ctx.policy.create_grant("agent-1", "byname", 3600, None)
        self.ctx.policy.create_connection(http_connection(
            "baseurl", None, secret_id="name-token",
            cli=P.CliProfile(self.dump_program, "http", base_url_env="GH_SYNTHETIC_TOKEN_0123456789")))
        self.ctx.policy.create_grant("agent-1", "baseurl", 3600, None)
        cids = ["byname", "baseurl"]
        for label, extra_env in variants.items():
            cid = f"env-{label}"
            self._env_connection(cid, extra_env)
            cids.append(cid)
        for cid in cids:
            out = self.root / f"{cid}.json"
            handles_before = len(self.events("handle_issue"))
            with self.assertRaises(Unsupported) as caught:
                tools.exec(self.ctx, "agent-1", cid, [str(out)])
            self.assertEqual(caught.exception.reason, "cli_env_contains_credential", cid)
            self.assertFalse(out.exists(), cid)  # the child never ran
            self.assertEqual(len(self.events("handle_issue")), handles_before, cid)  # no handle issued
            refusal = [r for r in self.events("tools_exec") if r["connection"] == cid][-1]
            self.assertEqual((refusal["result"], refusal["reason"]), ("unsupported", "cli_env_contains_credential"))
            finish = [r for r in self.events("run_finish") if r["connection"] == cid][-1]
            self.assertEqual((finish["result"], finish["reason"]), ("failed", "cli_env_contains_credential"))
        self.assertEqual(self.registry.active_runs(), [])
        self.assertEqual(list(Path(self.ctx.config.run_dir).iterdir()), [])
        self.assertEqual(self.events("run_start"), [])
        # A harmless value still reaches the child.
        self._env_connection("env-ok", {"DEMOCLI_COLOR": "never"})
        _view, dump = self.exec_dump("env-ok")
        self.assertEqual(dump["env"]["DEMOCLI_COLOR"], "never")

    def test_cli_env_carrying_any_other_vault_value_is_refused_at_exec(self) -> None:
        """Product rule: no vault value -- another project's secret, a retired version -- reaches the child env."""
        self.ctx.projects.create("prodproj")
        other = b"synthetic-prod-token-OTHERPROJECT-0123456789"
        self.ctx.vault.put_secret("prod-token", "api_key", other, "prodproj", "prod")
        retired = b"synthetic-retired-token-v1-abcdefghijkl"
        self.ctx.vault.put_secret("rotating", "api_key", retired, "demo", "dev")
        self.ctx.vault.put_secret("rotating", "api_key", b"synthetic-current-token-v2-mnopqrst", "demo", "dev")
        self.assertEqual([v.status for v in self.ctx.vault.get_meta("rotating").versions], ["retired", "active"])
        revoked = b"synthetic-revoked-token-zyxwvutsrqpo"
        self.ctx.vault.put_secret("gone", "api_key", revoked, "demo", "dev")
        self.ctx.vault.set_version_status("gone", 1, "revoked")
        # Every connection below uses the harmless "gh-token" secret; the env carries a *different* vault value.
        cases = {"env-other": {"OTHER_TOKEN": other.decode()},
                 "env-retired": {"OLD_TOKEN": "Bearer " + retired.decode()},
                 "env-revoked": {"GONE_HEX": revoked.hex().upper()}}
        for cid, extra_env in cases.items():
            self._env_connection(cid, extra_env)
            out = self.root / f"{cid}.json"
            with self.assertRaises(Unsupported) as caught:
                tools.exec(self.ctx, "agent-1", cid, [str(out)])
            self.assertEqual(caught.exception.reason, "cli_env_contains_credential", cid)
            self.assertFalse(out.exists(), cid)
        self.assertEqual(self.events("run_start"), [])
        self.assertEqual(list(Path(self.ctx.config.run_dir).iterdir()), [])

    def test_exec_request_and_run_audit_records_carry_target_and_policy_version(self) -> None:
        sleeper = self.script("sleep.py", SLEEP_SCRIPT)
        self.ctx.policy.create_connection(http_connection("sleep", sleeper))
        self.ctx.policy.create_grant("agent-1", "sleep", 3600, None)
        origin = "http://127.0.0.1:8080"
        view, _dump = self.exec_dump()
        running = tools.exec(self.ctx, "agent-1", "sleep", ["30"])
        tools.status(self.ctx, "agent-1", running["run_id"])
        tools.cancel(self.ctx, "agent-1", running["run_id"])
        self.wait(running["run_id"])
        with mock.patch.object(self.gateway, "relay_for_caller",
                               return_value=FakeRelayResult(200, [], b"{}", None)):
            tools.request(self.ctx, "agent-1", "gh", "GET", "/repos")
        expected = {"gh": self.ctx.policy.get_connection("gh").policy_version,
                    "sleep": self.ctx.policy.get_connection("sleep").policy_version}
        for event in ("tools_exec", "handle_issue", "run_start", "run_finish", "run_cancel", "tools_status",
                      "tools_cancel", "tools_request"):
            records = [r for r in self.events(event) if r["result"] != "denied"]
            self.assertTrue(records, event)
            for record in records:
                self.assertEqual(record["target"], origin, (event, record))
                self.assertIsNotNone(record["policy_version"], (event, record))
                self.assertEqual(record["policy_version"], expected[record["connection"]], (event, record))
        self.assertEqual(self.registry.get(view["run_id"], "agent-1").target, origin)
        # refusals that know the connection name its target too
        self.ctx.policy.create_connection(http_connection("nocli", None))
        self.ctx.policy.create_grant("agent-1", "nocli", 3600, None)
        with self.assertRaises(Unsupported):
            tools.exec(self.ctx, "agent-1", "nocli", [])
        refusal = self.events("tools_exec")[-1]
        self.assertEqual((refusal["reason"], refusal["target"]), ("cli_not_supported", origin))

    def test_ssh_run_audit_records_carry_host_port_target(self) -> None:
        self.ctx.vault.put_secret("box-key", "ssh_private_key", _ssh_key_pem(), "demo", "dev")
        fake_ssh = self.script("ssh.py", FAKE_SSH_SCRIPT)
        self.ctx.policy.create_connection(ssh_connection("box", fake_ssh))
        self.ctx.policy.create_grant("agent-1", "box", 3600, None)
        self.ctx.signer_manager = FakeSignerManager(self.root)
        out = self.root / "ssh-audit.json"
        result = tools.exec(self.ctx, "agent-1", "box", [str(out)])
        self.assertEqual(self.wait(result["run_id"])["state"], "completed")
        version = self.ctx.policy.get_connection("box").policy_version
        for event in ("tools_exec", "run_start", "run_finish"):
            record = [r for r in self.events(event) if r["connection"] == "box"][-1]
            self.assertEqual((record["target"], record["policy_version"]), ("127.0.0.1:2222", version), event)

    def test_cancel_stops_the_run_even_when_the_audit_log_is_unavailable(self) -> None:
        sleeper = self.script("sleep.py", SLEEP_SCRIPT)
        self.ctx.policy.create_connection(http_connection("sleep", sleeper))
        self.ctx.policy.create_grant("agent-1", "sleep", 3600, None)
        ready = self.root / "ready-audit"
        result = tools.exec(self.ctx, "agent-1", "sleep", ["30", str(ready)])
        deadline = time.monotonic() + 15
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(ready.exists())
        run = self.registry.get(result["run_id"], "agent-1")
        proc = run.proc
        self.assertIsNotNone(proc)
        with mock.patch.object(self.ctx.audit, "record", side_effect=AuditUnavailable("audit_write_failed")):
            with self.assertRaises(AuditUnavailable) as caught:  # the audit failure is still reported
                tools.cancel(self.ctx, "agent-1", result["run_id"])
            self.assertEqual(caught.exception.reason, "audit_write_failed")
            self.registry.wait(run, 20)
        assert proc is not None
        self.assertIsNotNone(proc.poll())  # the child is gone
        self.assertNotIn(run.state, ("queued", "running"))
        # unrecorded output never reaches the agent: run_finish could not be written either
        self.assertEqual((run.state, run.reason), ("failed", "audit_unavailable"))
        self.assertEqual(self.registry.active_runs(), [])

        # A queued run is cancelled too (never spawned) when the log is down.
        queued = self.registry.create("agent-1", "sleep", "g-x", "http", sleeper)
        with mock.patch.object(self.ctx.audit, "record", side_effect=AuditUnavailable("audit_write_failed")):
            with self.assertRaises(AuditUnavailable):
                tools.cancel(self.ctx, "agent-1", queued.id)
        self.assertNotIn(queued.state, ("queued", "running"))


if __name__ == "__main__":
    unittest.main()
