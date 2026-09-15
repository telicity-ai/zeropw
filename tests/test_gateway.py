"""HTTP authentication relay: one connection, many operations, no credential leaves the gateway.

Covers docs/security-design.md §7 rows for the HTTP path: placeholder replacement,
fixed target, path traversal, connection substitution, revocation/expiry/usage/
global stop/restore-pending/stale policy, reflection and redirect blocking,
buffering limits, upstream failures, approvals, the idempotency ledger, TLS
verification, and value-free audit records.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import http.client
import json
import random
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import types
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from zeropw import gateway
from zeropw import policy as P
from zeropw.context import Config, Context
from zeropw.fake_upstream import BASIC_LEAK_FORMS, ENCODED_LEAK_FORMS, FakeUpstream, LARGE_BODY_SIZE, STREAM_PARTS
from zeropw.errors import InvalidInput
from zeropw.gateway import RelayResult
from zeropw.server import ZeroPWHandler, ZeroPWServer

ADMIN = "admin-passphrase-1"
RECOVERY = "recovery-passphrase-1"
SECRET_A = "synthetic-token-alpha-0123456789ABCDEFGHIJ"
SECRET_B = "synthetic-token-bravo-ZYXWVUTSRQPONMLKJIHG"
# Contains reserved characters so that its percent-encoding differs from the raw value.
SECRET_RESERVED = "synthetic/token+reserved=chars:0123456789"
# Reserved URL characters, bytes whose base64 differs between the std and urlsafe alphabets,
# and characters JSON/HTML escape: every encoding the guard scans differs from the raw value.
SECRET_ENCODINGS = 'synthetic-token/enc+ode=chars:>>>?<&"\\x-0123456789'
PLACEHOLDER = "Bearer democli-placeholder"


class FakeClock:
    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


def http_connection(cid: str, fake: FakeUpstream, secret_id: str, auth: P.HttpAuth, scope: P.HttpScope,
                    ca_file: str | None = None) -> P.Connection:
    return P.Connection(
        id=cid, project="demo", environment="dev", service="fake-github", kind="http",
        secret_id=secret_id, secret_version=None, description="test connection",
        http_target=P.HttpTarget(fake.scheme, fake.host, fake.port, ca_file),
        http_auth=auth, http_scope=scope, ssh_target=None, cli=None,
        policy_version=0, status="active", created_at="", updated_at="",
    )


def all_encodings(secret: str) -> list[str]:
    return [p.decode("utf-8", "replace") for p in gateway.credential_patterns(secret.encode(), "synthetic-user")]


class GatewayBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.clock = FakeClock()
        self.ctx = Context.initialize(Path(self.tmp.name) / "state", ADMIN, RECOVERY,
                                      Config(upstream_timeout=3.0), self.clock)
        self.ctx.projects.create("demo")
        self.fake = FakeUpstream(SECRET_A).start()
        self.addCleanup(self.fake.stop)
        self.ctx.vault.put_secret("gh-token", "api_key", SECRET_A.encode(), "demo", "dev")
        self.ctx.policy.create_principal("agent-1")
        self.ctx.policy.create_connection(http_connection(
            "gh", self.fake, "gh-token", P.HttpAuth("bearer"), P.HttpScope(None, None, ("DELETE",))))
        self.grant = self.ctx.policy.create_grant("agent-1", "gh", 3600, None)
        self.handle = self.issue_handle()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # helpers ----------------------------------------------------------
    def issue_handle(self, caller: str = "agent-1", connection: str = "gh", grant: str | None = None,
                     policy_version: int | None = None, ttl: int = 300) -> str:
        if policy_version is None:
            policy_version = self.ctx.policy.get_connection(connection).policy_version
        return self.ctx.handles.issue(caller, connection, grant or self.grant.id, policy_version, ttl, now=self.clock())

    def relay(self, method: str, path: str, headers: dict[str, str] | None = None, body: bytes = b"",
              handle: str | None = None, request_id: str | None = None) -> RelayResult:
        token = self.handle if handle is None else handle
        return gateway.relay(self.ctx, token, method, path, headers or {}, body, request_id)

    def audit_records(self) -> list[dict]:
        return [r for r in self.ctx.audit.tail(10_000) if r["event"] == "http_relay"]

    def state_text(self, *names: str) -> str:
        chunks = []
        for name in names:
            path = self.ctx.state.path / name
            if path.exists():
                chunks.append(path.read_text())
        return "\n".join(chunks)

    def assert_credential_free(self, blob: str | bytes, secrets: tuple[str, ...] = (SECRET_A, SECRET_B)) -> None:
        text = blob.decode("utf-8", "replace") if isinstance(blob, bytes) else blob
        for secret in secrets:
            for encoding in all_encodings(secret):
                self.assertNotIn(encoding, text)

    def assert_result_credential_free(self, result: RelayResult) -> None:
        self.assert_credential_free(result.body)
        self.assert_credential_free(json.dumps(result.headers))
        self.assert_credential_free(result.reason or "")


# ---------------------------------------------------------------- normal flow
class RelayFlowTests(GatewayBase):
    def test_one_connection_two_operations_placeholder_replaced(self) -> None:
        client_headers = {"Authorization": PLACEHOLDER, "Cookie": "session=agent-cookie", "Host": "evil.invalid",
                          "X-ZeroPW-Handle": "stale", "Proxy-Authorization": "Basic xx", "Accept": "application/json",
                          "User-Agent": "democli/1", "Accept-Encoding": "gzip", "Connection": "keep-alive",
                          "Transfer-Encoding": "identity"}
        first = self.relay("GET", "/repos", client_headers)
        self.assertEqual((first.status, first.reason), (200, None))
        self.assertEqual(first.json(), [{"name": "demo"}, {"name": "tools"}])
        second = self.relay("POST", "/repos/demo/issues", {**client_headers, "Content-Type": "application/json"},
                            json.dumps({"title": "from agent"}).encode())
        self.assertEqual((second.status, second.reason), (201, None))
        self.assertEqual(second.json()["title"], "from agent")
        self.assertEqual(len(self.fake.requests), 2)
        for seen in self.fake.requests:
            headers = seen["headers"]
            self.assertEqual(headers["authorization"], f"Bearer {SECRET_A}")
            self.assertNotIn("democli-placeholder", json.dumps(headers))
            self.assertNotIn("cookie", headers)
            self.assertNotIn("proxy-authorization", headers)
            self.assertNotIn("x-zeropw-handle", headers)
            self.assertNotIn("transfer-encoding", headers)
            self.assertEqual(headers["host"], f"127.0.0.1:{self.fake.port}")
            self.assertEqual(headers["accept"], "application/json")
            self.assertEqual(headers["user-agent"], "democli/1")
            self.assertEqual(headers["accept-encoding"], "identity")
            self.assertEqual(headers["connection"], "close")
        self.assertEqual(self.fake.requests[1]["body"], json.dumps({"title": "from agent"}).encode())
        self.assertEqual(self.fake.requests[1]["headers"]["content-type"], "application/json")
        results = [(r["result"], r.get("status")) for r in self.audit_records()]
        self.assertEqual(results, [("attempt", None), ("ok", 200), ("attempt", None), ("ok", 201)])
        record = self.audit_records()[-1]
        self.assertEqual((record["caller"], record["connection"], record["action"], record["path"]),
                         ("agent-1", "gh", "POST", "/repos/demo/issues"))
        self.assertEqual(record["target"], f"http://127.0.0.1:{self.fake.port}")
        self.assertEqual(record["policy_version"], 1)
        self.assertEqual(record["grant"], self.grant.id)
        self.assertEqual(self.ctx.policy.get_grant(self.grant.id).uses, 2)

    def test_basic_mode(self) -> None:
        fake = FakeUpstream(SECRET_B, mode="basic", basic_username="synthetic-user").start()
        self.addCleanup(fake.stop)
        self.ctx.vault.put_secret("basic-pw", "password", SECRET_B.encode(), "demo", "dev")
        self.ctx.policy.create_connection(http_connection(
            "basic", fake, "basic-pw", P.HttpAuth("basic", basic_username="synthetic-user"), P.HttpScope()))
        grant = self.ctx.policy.create_grant("agent-1", "basic", 3600, None)
        handle = self.issue_handle(connection="basic", grant=grant.id)
        result = self.relay("GET", "/me", {"Authorization": PLACEHOLDER}, handle=handle)
        self.assertEqual((result.status, result.json()), (200, {"login": "synthetic-user"}))
        expected = "Basic " + base64.b64encode(f"synthetic-user:{SECRET_B}".encode()).decode()
        self.assertEqual(fake.requests[-1]["headers"]["authorization"], expected)
        # The Basic pair is itself a credential encoding: reflecting it is blocked.
        echoed = self.relay("GET", "/echo-headers", {}, handle=handle)
        self.assertEqual((echoed.status, echoed.reason), (502, "credential_reflection_blocked"))
        self.assertNotIn(expected.split(" ", 1)[1], echoed.body.decode())

    def test_header_mode(self) -> None:
        fake = FakeUpstream(SECRET_B, mode="header", header_name="X-Api-Key", value_prefix="Key ").start()
        self.addCleanup(fake.stop)
        self.ctx.vault.put_secret("api-key", "api_key", SECRET_B.encode(), "demo", "dev")
        self.ctx.policy.create_connection(http_connection(
            "keyed", fake, "api-key", P.HttpAuth("header", header_name="X-Api-Key", value_prefix="Key "), P.HttpScope()))
        grant = self.ctx.policy.create_grant("agent-1", "keyed", 3600, None)
        handle = self.issue_handle(connection="keyed", grant=grant.id)
        result = self.relay("GET", "/repos", {"X-Api-Key": "agent-guess", "Authorization": PLACEHOLDER}, handle=handle)
        self.assertEqual(result.status, 200)
        seen = fake.requests[-1]["headers"]
        self.assertEqual(seen["x-api-key"], f"Key {SECRET_B}")
        self.assertNotIn("authorization", seen)

    def test_relay_for_caller_without_handle(self) -> None:
        result = gateway.relay_for_caller(self.ctx, "agent-1", "gh", "GET", "/me", {"Authorization": PLACEHOLDER}, b"")
        self.assertEqual((result.status, result.json()), (200, {"login": "synthetic-user"}))
        self.assertEqual(self.fake.requests[-1]["headers"]["authorization"], f"Bearer {SECRET_A}")
        denied = gateway.relay_for_caller(self.ctx, "agent-1", "missing", "GET", "/me", {}, b"")
        self.assertEqual((denied.status, denied.reason), (403, "connection_unknown"))
        ghost = gateway.relay_for_caller(self.ctx, "ghost", "gh", "GET", "/me", {}, b"")
        self.assertEqual((ghost.status, ghost.reason), (403, "principal_unknown"))
        self.assertEqual(len(self.fake.requests), 1)

    def test_query_forwarded_untouched_but_never_audited(self) -> None:
        result = self.relay("GET", "/repos?page=2&token=agent-guess", {})
        self.assertEqual(result.status, 200)
        self.assertEqual(self.fake.requests[-1]["path"], "/repos?page=2&token=agent-guess")
        for record in self.audit_records():
            self.assertNotIn("?", record["path"])
            self.assertNotIn("agent-guess", json.dumps(record))
        self.assertNotIn("agent-guess", self.state_text("audit/audit.jsonl"))

    def test_head_and_no_content_responses(self) -> None:
        head = self.relay("HEAD", "/repos")
        self.assertEqual((head.status, head.body, head.reason), (200, b"", None))
        digest = self.relay("DELETE", "/repos/demo").json()["approval_digest"]
        self.ctx.policy.approve(digest)
        gone = self.relay("DELETE", "/repos/demo")
        self.assertEqual((gone.status, gone.body, gone.reason), (204, b"", None))

    def test_response_header_filter_and_upstream_401(self) -> None:
        ok = self.relay("GET", "/repos")
        names = {name.lower() for name, _ in ok.headers}
        self.assertIn("content-type", names)
        for dropped in ("server", "date", "connection", "content-length", "transfer-encoding"):
            self.assertNotIn(dropped, names)
        # A connection whose stored credential the upstream rejects: the 401
        # passes through as business data but WWW-Authenticate is dropped.
        self.ctx.vault.put_secret("wrong-token", "api_key", b"synthetic-token-not-accepted-upstream", "demo", "dev")
        self.ctx.policy.create_connection(http_connection("bad", self.fake, "wrong-token", P.HttpAuth("bearer"), P.HttpScope()))
        grant = self.ctx.policy.create_grant("agent-1", "bad", 3600, None)
        result = self.relay("GET", "/repos", handle=self.issue_handle(connection="bad", grant=grant.id))
        self.assertEqual((result.status, result.reason), (401, None))
        self.assertNotIn("www-authenticate", {n.lower() for n, _ in result.headers})
        self.assertEqual(result.json(), {"error": "unauthorized"})

    def test_usage_consumed_only_after_policy_pass(self) -> None:
        limited = self.ctx.policy.create_grant("agent-1", "gh", 3600, 1)
        handle = self.issue_handle(grant=limited.id)
        self.assertEqual(self.relay("GET", "/repos/../x", handle=handle).status, 400)
        self.assertEqual(self.relay("DELETE", "/repos/demo", handle=handle).status, 428)
        self.assertEqual(self.ctx.policy.get_grant(limited.id).uses, 0)
        self.assertEqual(self.fake.requests, [])
        self.assertEqual(self.relay("GET", "/repos", handle=handle).status, 200)
        self.assertEqual(self.ctx.policy.get_grant(limited.id).uses, 1)
        exhausted = self.relay("GET", "/repos", handle=handle)
        self.assertEqual((exhausted.status, exhausted.reason), (403, "grant_exhausted"))
        self.assertEqual(len(self.fake.requests), 1)

    def test_invalid_inputs_are_explicit(self) -> None:
        self.assertEqual(self.relay("GE T", "/repos").reason, "invalid_method")
        self.assertEqual(self.relay("TRACE", "/repos").reason, "method_not_allowed")
        self.assertEqual(self.relay("GET", "/repos", {"Accept": "a\r\nInjected: 1"}).reason, "invalid_header_value")
        self.assertEqual(self.relay("GET", "/repos", request_id="x" * 200).reason, "invalid_request_id")
        self.assertEqual(self.relay("GET", "/repos", request_id="bad id").reason, "invalid_request_id")
        self.assertEqual(gateway.relay(self.ctx, self.handle, "GET", "/repos", {}, 12).reason, "invalid_body")  # type: ignore[arg-type]
        self.assertEqual(self.fake.requests, [])


# -------------------------------------------------------------- target & path
class TargetAndPathTests(GatewayBase):
    def test_path_traversal_and_smuggling_rejected(self) -> None:
        bad = ["repos", "", "/repos/../admin", "/../", "/repos/..", "/repos//x", "//evil.invalid/x", "/repos/%2e%2e/admin",
               "/repos/%2E%2E/admin", "/repos%2f..%2fadmin", "/repos/%2f%2f", "/repos/%252e%252e/x", "/re\x00pos", "/re pos",
               "/repos\r\nX: 1", "/http://evil.invalid/", "/repos/./x", "/repos/%2e/x", "/repos\\x", "/repos#frag",
               "/re\u00e9pos", "/" + "a" * 9000]
        for path in bad:
            result = self.relay("GET", path)
            self.assertEqual((result.status, result.reason), (400, "invalid_path"), path)
        self.assertEqual(self.fake.requests, [])
        for record in self.audit_records():
            self.assertEqual(record["result"], "denied")
            self.assertNotIn("\x00", json.dumps(record))
        good = ["/", "/repos/", "/repos/demo%20x/issues", "/repos?q=a//b://c", "/repos/a%2fb"]
        for path in good:
            result = self.relay("GET", path)
            self.assertNotEqual(result.reason, "invalid_path", path)
        with self.assertRaises(Exception):
            gateway.normalize_path("/a/../b")
        self.assertEqual(gateway.normalize_path("/a/b?c=1"), ("/a/b", "/a/b?c=1"))

    def test_scope_method_and_path_denied_with_reason(self) -> None:
        self.ctx.policy.create_connection(http_connection(
            "scoped", self.fake, "gh-token", P.HttpAuth("bearer"), P.HttpScope(("GET", "POST"), ("/repos", "/me"))))
        grant = self.ctx.policy.create_grant("agent-1", "scoped", 3600, None)
        handle = self.issue_handle(connection="scoped", grant=grant.id)
        self.assertEqual(self.relay("GET", "/repos", handle=handle).status, 200)
        self.assertEqual(self.relay("GET", "/repos/x/y?z=1", handle=handle).status, 404)   # allowed, upstream 404
        for method, path, reason in (("PUT", "/repos", "method_not_allowed"), ("DELETE", "/repos/demo", "method_not_allowed"),
                                     ("GET", "/debug/token", "path_not_allowed"), ("GET", "/reposx", "path_not_allowed"),
                                     ("GET", "/repos%2fx", "path_not_allowed"), ("GET", "/m%65", "path_not_allowed")):
            result = self.relay(method, path, handle=handle)
            self.assertEqual((result.status, result.reason), (403, reason), (method, path))
            self.assertEqual(result.json()["reason"], reason)
        self.assertEqual(len(self.fake.requests), 2)
        self.assertEqual(self.audit_records()[-1]["reason"], "path_not_allowed")


# ------------------------------------------------------- connection substitution
class SubstitutionTests(GatewayBase):
    def setUp(self) -> None:
        super().setUp()
        self.fake_b = FakeUpstream(SECRET_B).start()
        self.addCleanup(self.fake_b.stop)
        self.ctx.vault.put_secret("b-token", "api_key", SECRET_B.encode(), "demo", "dev")
        self.ctx.policy.create_connection(http_connection("gh-b", self.fake_b, "b-token", P.HttpAuth("bearer"), P.HttpScope()))
        self.ctx.policy.create_principal("agent-2")
        self.grant_b = self.ctx.policy.create_grant("agent-2", "gh-b", 3600, None)

    def test_handle_is_bound_to_its_connection_caller_and_grant(self) -> None:
        # Each agent reaches only its own upstream; there is no way to name another one.
        self.assertEqual(self.relay("GET", "/me").status, 200)
        handle_b = self.issue_handle("agent-2", "gh-b", self.grant_b.id)
        self.assertEqual(self.relay("GET", "/me", handle=handle_b).status, 200)
        self.assertEqual(self.fake.requests[-1]["headers"]["authorization"], f"Bearer {SECRET_A}")
        self.assertEqual(self.fake_b.requests[-1]["headers"]["authorization"], f"Bearer {SECRET_B}")
        before = (len(self.fake.requests), len(self.fake_b.requests))
        # Handles minted with mismatched bindings: refused before any upstream contact.
        cross = [
            (self.issue_handle("agent-1", "gh-b", self.grant.id), "grant_mismatch"),     # my grant, their connection
            (self.issue_handle("agent-1", "gh-b", self.grant_b.id), "grant_mismatch"),   # their grant, my identity
            (self.issue_handle("agent-2", "gh", self.grant_b.id), "grant_mismatch"),     # their identity, my connection
            (self.issue_handle("agent-2", "gh", self.grant.id), "grant_mismatch"),
            (self.issue_handle("agent-1", "gh", "g-unknown"), "grant_unknown"),
        ]
        for handle, reason in cross:
            result = self.relay("GET", "/me", handle=handle)
            self.assertEqual((result.status, result.reason), (403, reason))
        # relay_for_caller: no grant on the other connection.
        result = gateway.relay_for_caller(self.ctx, "agent-1", "gh-b", "GET", "/me", {}, b"")
        self.assertEqual((result.status, result.reason), (403, "no_grant"))
        self.assertEqual((len(self.fake.requests), len(self.fake_b.requests)), before)

    def test_tampered_or_foreign_handles_are_unauthorized(self) -> None:
        head, payload, sig = self.handle.split(".")
        forged = payload[:-2] + ("AA" if payload[-2:] != "AA" else "BB")
        for token, reason in ((f"{head}.{forged}.{sig}", "handle_signature"), (f"{head}.{payload}.{sig[:-1]}x", "handle_signature"),
                              ("", "handle_malformed"), ("zpw1.abc", "handle_malformed"), ("Bearer " + SECRET_A, "handle_malformed")):
            result = self.relay("GET", "/me", handle=token)
            self.assertEqual((result.status, result.reason), (401, reason))
            self.assertEqual(result.json()["error"], "AuthFailed")
        from zeropw.handles import HandleIssuer

        foreign = HandleIssuer(HandleIssuer.generate_key()).issue("agent-1", "gh", self.grant.id, 1, 300, now=self.clock())
        self.assertEqual(self.relay("GET", "/me", handle=foreign).reason, "handle_signature")
        short = self.issue_handle(ttl=60)
        self.clock.now += 60
        expired = self.relay("GET", "/me", handle=short)
        self.assertEqual((expired.status, expired.reason), (401, "handle_expired"))
        self.assertEqual(self.fake.requests, [])
        denied = [r for r in self.audit_records() if r["result"] == "denied"]
        self.assertTrue(denied)
        self.assertTrue(all(r["caller"] is None for r in denied))


# ------------------------------------------------------------- policy state
class PolicyStateTests(GatewayBase):
    def assert_denied(self, reason: str, handle: str | None = None) -> None:
        before = len(self.fake.requests)
        result = self.relay("GET", "/repos", handle=handle)
        self.assertEqual((result.status, result.reason), (403, reason))
        self.assertEqual(result.json(), {"error": "PolicyDenied", "reason": reason})
        self.assertEqual(len(self.fake.requests), before)
        self.assertEqual(self.audit_records()[-1]["reason"], reason)
        self.assertEqual(self.audit_records()[-1]["result"], "denied")

    def test_revoked(self) -> None:
        self.assertEqual(self.relay("GET", "/repos").status, 200)
        self.ctx.policy.revoke_grant(self.grant.id)
        self.assert_denied("grant_revoked")
        self.assertIn("revoked_use_attempt", [a["alert"] for a in self.ctx.audit.alerts()])

    def test_expired(self) -> None:
        grant = self.ctx.policy.create_grant("agent-1", "gh", 100, None)
        handle = self.issue_handle(grant=grant.id, ttl=3600)
        self.assertEqual(self.relay("GET", "/repos", handle=handle).status, 200)
        self.clock.now += 100
        self.assert_denied("grant_expired", handle)

    def test_max_uses(self) -> None:
        grant = self.ctx.policy.create_grant("agent-1", "gh", 3600, 2)
        handle = self.issue_handle(grant=grant.id)
        self.assertEqual(self.relay("GET", "/repos", handle=handle).status, 200)
        self.assertEqual(self.relay("GET", "/me", handle=handle).status, 200)
        self.assert_denied("grant_exhausted", handle)

    def test_global_stop_and_resume(self) -> None:
        self.ctx.policy.stop_all()
        self.assert_denied("global_stop")
        self.assertEqual(gateway.relay_for_caller(self.ctx, "agent-1", "gh", "GET", "/me", {}, b"").reason, "global_stop")
        self.ctx.policy.resume()
        self.assertEqual(self.relay("GET", "/repos").status, 200)

    def test_restore_pending(self) -> None:
        self.ctx.policy.set_restore_pending(True)
        self.assert_denied("restore_pending")
        self.ctx.policy.set_restore_pending(False)
        self.assertEqual(self.relay("GET", "/repos").status, 200)

    def test_stale_policy_version_on_handle_after_narrowing_change(self) -> None:
        self.ctx.policy.update_connection("gh", description="renamed")   # not widening: grant re-evaluated in place
        self.assertEqual(self.ctx.policy.get_grant(self.grant.id).status, "active")
        self.assert_denied("grant_stale")   # handle carries policy version 1, connection is at 2
        fresh = self.issue_handle()
        self.assertEqual(self.relay("GET", "/repos", handle=fresh).status, 200)
        self.assertEqual(gateway.relay_for_caller(self.ctx, "agent-1", "gh", "GET", "/me", {}, b"").status, 200)

    def test_widening_change_makes_grant_stale_until_regrant(self) -> None:
        self.ctx.policy.create_connection(http_connection(
            "scoped", self.fake, "gh-token", P.HttpAuth("bearer"), P.HttpScope(("GET",), ("/repos",))))
        grant = self.ctx.policy.create_grant("agent-1", "scoped", 3600, None)
        handle = self.issue_handle(connection="scoped", grant=grant.id)
        self.assertEqual(self.relay("GET", "/repos", handle=handle).status, 200)
        _, widened = self.ctx.policy.update_connection("scoped", http_scope=P.HttpScope(("GET",), ("/repos", "/me")))
        self.assertTrue(widened)
        self.assert_denied("grant_stale", handle)
        denied = gateway.relay_for_caller(self.ctx, "agent-1", "scoped", "GET", "/me", {}, b"")
        self.assertEqual(denied.reason, "grant_stale")
        fresh = self.ctx.policy.regrant(grant.id)
        result = self.relay("GET", "/me", handle=self.issue_handle(connection="scoped", grant=fresh.id))
        self.assertEqual(result.status, 200)

    def test_principal_and_connection_disabled(self) -> None:
        self.ctx.policy.disable_connection("gh")
        self.assert_denied("connection_disabled")
        self.ctx.policy.disable_principal("agent-1")
        self.assert_denied("principal_disabled")


# ------------------------------------------------------ reflection & upstream
class ReflectionAndUpstreamTests(GatewayBase):
    def assert_blocked(self, path: str, reason: str = "credential_reflection_blocked") -> RelayResult:
        result = self.relay("GET", path)
        self.assertEqual((result.status, result.reason), (502, reason), path)
        self.assertEqual(result.json(), {"error": "UpstreamError", "reason": reason})
        self.assert_result_credential_free(result)
        self.assertEqual({n.lower() for n, _ in result.headers}, {"content-type"})
        record = self.audit_records()[-1]
        self.assertEqual((record["result"], record["reason"]), ("blocked", reason))
        return result

    def test_reflection_in_body_and_headers_is_blocked(self) -> None:
        for path in ("/echo-headers", "/debug/token", "/base64-leak", "/set-cookie"):
            self.assert_blocked(path)
        alerts = [a for a in self.ctx.audit.alerts() if a["alert"] == "credential_reflection"]
        self.assertEqual(len(alerts), 4)
        self.assert_credential_free(self.state_text("audit/audit.jsonl", "audit/alerts.jsonl"))

    def test_credential_patterns_cover_both_percent_encoding_casings(self) -> None:
        # RFC 3986 §2.1 allows upper- or lower-case hex in %XX triplets; quote() emits only upper.
        patterns = gateway.credential_patterns(b"AKIA/secret+Key 9=abc", None)
        for expected in (
            b"AKIA%2Fsecret%2BKey%209%3Dabc",   # quote(), upper-case hex
            b"AKIA%2fsecret%2bKey%209%3dabc",   # same, lower-case hex
            b"AKIA%2Fsecret%2BKey+9%3Dabc",     # quote_plus(), upper-case hex
            b"AKIA%2fsecret%2bKey+9%3dabc",     # same, lower-case hex
        ):
            self.assertIn(expected, patterns)
            self.assertTrue(gateway._contains_credential(b'{"echo":"' + expected + b'"}', patterns), expected)
        self.assertEqual(len(patterns), len(set(patterns)))
        # A credential without reserved characters gains no duplicate patterns.
        plain = gateway.credential_patterns(SECRET_A.encode(), None)
        self.assertEqual(len(plain), len(set(plain)))

    def test_lowercase_percent_encoded_reflection_is_blocked(self) -> None:
        fake = FakeUpstream(SECRET_RESERVED).start()
        self.addCleanup(fake.stop)
        self.ctx.vault.put_secret("reserved-token", "api_key", SECRET_RESERVED.encode(), "demo", "dev")
        self.ctx.policy.create_connection(http_connection(
            "gh-reserved", fake, "reserved-token", P.HttpAuth("bearer"), P.HttpScope(None, None, ("DELETE",))))
        grant = self.ctx.policy.create_grant("agent-1", "gh-reserved", 3600, None)
        handle = self.issue_handle(connection="gh-reserved", grant=grant.id)
        for path in ("/urlencoded-leak?case=lower", "/urlencoded-leak"):
            result = self.relay("GET", path, handle=handle)
            self.assertEqual((result.status, result.reason), (502, "credential_reflection_blocked"), path)
            self.assertEqual(result.json(), {"error": "UpstreamError", "reason": "credential_reflection_blocked"})
            self.assert_credential_free(result.body, (SECRET_RESERVED,))
            self.assertNotIn(b"%2f", result.body.lower())
            record = self.audit_records()[-1]
            self.assertEqual((record["result"], record["reason"]), ("blocked", "credential_reflection_blocked"))
        self.assertEqual(len(fake.requests), 2)
        self.assert_credential_free(self.state_text("audit/audit.jsonl", "audit/alerts.jsonl"), (SECRET_RESERVED,))

    def test_every_credential_encoding_in_upstream_body_is_blocked(self) -> None:
        # docs/security-design.md §4/§7 (변형·인코딩 유출): raw, base64 std/urlsafe padded or
        # not, percent-encoding in either hex case (quote and quote_plus), hex in either case,
        # JSON and HTML escapes and, for basic auth, base64(user:secret) are all caught inside
        # a real upstream body, and no upstream byte of a blocked response is returned.
        for mode in ("bearer", "basic"):
            username = "synthetic-user" if mode == "basic" else None
            fake = FakeUpstream(SECRET_ENCODINGS, mode=mode, basic_username=username).start()
            self.addCleanup(fake.stop)
            cid, secret_id = f"enc-{mode}", f"enc-{mode}-secret"
            self.ctx.vault.put_secret(secret_id, "password" if mode == "basic" else "api_key",
                                      SECRET_ENCODINGS.encode(), "demo", "dev")
            self.ctx.policy.create_connection(http_connection(
                cid, fake, secret_id, P.HttpAuth(mode, basic_username=username), P.HttpScope()))
            grant = self.ctx.policy.create_grant("agent-1", cid, 3600, None)
            handle = self.issue_handle(connection=cid, grant=grant.id)
            # Control: the credential is injected and an ordinary business response passes.
            result = self.relay("GET", "/me", {"Authorization": PLACEHOLDER}, handle=handle)
            self.assertEqual((result.status, result.json()), (200, {"login": "synthetic-user"}), mode)
            forms = ENCODED_LEAK_FORMS + (BASIC_LEAK_FORMS if mode == "basic" else ())
            for form in forms:
                with self.subTest(mode=mode, form=form):
                    result = self.relay("GET", f"/encoded-leak?form={form}", handle=handle)
                    self.assertEqual((result.status, result.reason), (502, "credential_reflection_blocked"))
                    self.assertEqual(result.json(), {"error": "UpstreamError", "reason": "credential_reflection_blocked"})
                    self.assertNotIn(b"leak=[", result.body)
                    self.assert_credential_free(result.body, (SECRET_ENCODINGS,))
                    self.assertEqual({n.lower() for n, _ in result.headers}, {"content-type"})
                    record = self.audit_records()[-1]
                    self.assertEqual((record["result"], record["reason"]), ("blocked", "credential_reflection_blocked"))
            # An unknown form is an ordinary credential-free upstream 400 and passes through:
            # the guard blocks reflections, not the endpoint.
            result = self.relay("GET", "/encoded-leak?form=nope", handle=handle)
            self.assertEqual((result.status, result.reason, result.json()), (400, None, {"error": "unknown_form"}))
            self.assertEqual(len(fake.requests), len(forms) + 2)
        self.assert_credential_free(self.state_text("audit/audit.jsonl", "audit/alerts.jsonl"), (SECRET_ENCODINGS,))

    def test_credential_embedded_in_base64_blob_is_blocked_at_every_alignment(self) -> None:
        # docs/security-design.md §4/§7: a "file content" style API returns base64 of a larger
        # document holding the credential.  Whichever 3-byte alignment the credential lands on,
        # and whether or not the blob is wrapped into lines, the whole response is blocked.
        for alphabet in ("std", "url"):
            for offset in range(3):
                for wrap in (0, 60):
                    with self.subTest(alphabet=alphabet, offset=offset, wrap=wrap):
                        self.assert_blocked(f"/base64-embedded-leak?offset={offset}&wrap={wrap}&alphabet={alphabet}")
        self.assertEqual(len(self.fake.requests), 12)
        self.assert_credential_free(self.state_text("audit/audit.jsonl", "audit/alerts.jsonl"))

    def test_redirects_are_not_followed_and_location_never_forwarded(self) -> None:
        for path in ("/redirect", "/redirect-external"):
            result = self.assert_blocked(path, "redirect_not_followed")
            self.assertNotIn("location", {n.lower() for n, _ in result.headers})
            self.assertNotIn("leak", result.body.decode())
            self.assertNotIn("evil.invalid", result.body.decode())
        self.assertEqual([r["path"] for r in self.fake.requests], ["/redirect", "/redirect-external"])
        self.assertEqual(self.audit_records()[-1]["status"], 302)

    def test_chunked_stream_is_buffered(self) -> None:
        result = self.relay("GET", "/stream")
        self.assertEqual((result.status, result.body), (200, b"".join(STREAM_PARTS)))
        self.assertNotIn("transfer-encoding", {n.lower() for n, _ in result.headers})

    def test_large_ok_and_huge_rejected(self) -> None:
        result = self.relay("GET", "/large")
        self.assertEqual((result.status, len(result.body)), (200, LARGE_BODY_SIZE))
        huge = self.assert_blocked("/huge", "response_too_large")
        self.assertNotIn(b"yyyy", huge.body)   # JSON error only, no partial upstream bytes
        self.ctx.config.max_response_bytes = 1024
        small = self.relay("GET", "/large")
        self.assertEqual(small.reason, "response_too_large")

    def test_upstream_down_and_timeout(self) -> None:
        self.ctx.config.upstream_timeout = 0.3
        slow = self.relay("GET", "/slow?seconds=1")
        self.assertEqual((slow.status, slow.reason), (502, "upstream_timeout"))
        self.assert_result_credential_free(slow)
        self.assertEqual(self.audit_records()[-1]["result"], "error")
        self.fake.stop()
        down = self.relay("GET", "/repos")
        self.assertEqual((down.status, down.reason), (502, "upstream_unreachable"))
        self.assert_result_credential_free(down)
        self.assertEqual(self.audit_records()[-1]["reason"], "upstream_unreachable")
        time.sleep(0.8)   # let the sleeping fake handler thread finish before teardown

    def test_unsupported_auth_mode_fails_closed(self) -> None:
        connection = self.ctx.policy.get_connection("gh")
        bad_auth = object.__new__(P.HttpAuth)
        for name, value in (("mode", "digest"), ("header_name", None), ("value_prefix", None), ("basic_username", None)):
            object.__setattr__(bad_auth, name, value)
        from dataclasses import replace

        broken = replace(connection, http_auth=bad_auth)
        decision = P.Decision(True, "allowed", self.ctx.policy.get_grant(self.grant.id), broken)
        with mock.patch.object(self.ctx.policy, "evaluate", return_value=decision):
            result = self.relay("GET", "/repos")
        self.assertEqual((result.status, result.reason), (501, "unsupported_auth_mode"))
        self.assertEqual(result.json()["error"], "Unsupported")
        self.assertEqual(self.fake.requests, [])
        self.assertEqual(self.audit_records()[-1]["reason"], "unsupported_auth_mode")
        # A credential that cannot travel in a header (control characters) is refused, never mangled.
        self.ctx.vault.put_secret("crlf", "api_key", b"synthetic\r\nX-Injected: 1", "demo", "dev")
        self.ctx.policy.create_connection(http_connection("crlf", self.fake, "crlf", P.HttpAuth("bearer"), P.HttpScope()))
        grant = self.ctx.policy.create_grant("agent-1", "crlf", 3600, None)
        result = self.relay("GET", "/repos", handle=self.issue_handle(connection="crlf", grant=grant.id))
        self.assertEqual((result.status, result.reason), (501, "credential_header_unsafe"))
        self.assertEqual(self.fake.requests, [])

    def test_missing_credential_is_explicit(self) -> None:
        self.ctx.vault.set_version_status("gh-token", 1, "retired")
        result = self.relay("GET", "/repos")
        self.assertEqual((result.status, result.reason), (503, "credential_unavailable"))
        self.assertEqual(self.fake.requests, [])

    def test_audit_unavailable_refuses_before_credential_use(self) -> None:
        original = self.ctx.state.append_line

        def broken(name: str, line: str) -> None:
            raise OSError("disk full")

        self.ctx.state.append_line = broken  # type: ignore[assignment]
        try:
            result = self.relay("GET", "/repos")
        finally:
            self.ctx.state.append_line = original  # type: ignore[assignment]
        self.assertEqual((result.status, result.reason), (503, "audit_unavailable"))
        self.assertEqual(self.fake.requests, [])
        self.assertEqual(self.ctx.policy.get_grant(self.grant.id).uses, 0)
        self.assertEqual(self.relay("GET", "/repos").status, 200)   # audit back: request proceeds

    def test_audit_and_alerts_are_value_free(self) -> None:
        for path in ("/repos", "/echo-headers", "/debug/token", "/redirect", "/repos?secret=agent-guess"):
            self.relay("GET", path, {"Authorization": PLACEHOLDER, "Cookie": "c=1"})
        self.ctx.policy.revoke_grant(self.grant.id)
        self.relay("GET", "/repos")
        blob = self.state_text("audit/audit.jsonl", "audit/alerts.jsonl", "gateway/requests.json")
        self.assert_credential_free(blob)
        self.assertNotIn("democli-placeholder", blob)
        self.assertNotIn("agent-guess", blob)
        self.assertNotIn(self.handle, blob)
        self.assertNotIn("c=1", blob)


# --------------------------------------------------------------- approvals
class ApprovalTests(GatewayBase):
    def test_delete_requires_one_shot_approval_bound_to_digest(self) -> None:
        first = self.relay("DELETE", "/repos/demo")
        self.assertEqual((first.status, first.reason), (428, "approval_required"))
        digest = first.json()["approval_digest"]
        # Bound to the server-resolved origin, full target, policy version and Content-Type too.
        subject = json.dumps({"content_type": None, "origin": f"http://127.0.0.1:{self.fake.port}",
                              "policy_version": 1, "target": "/repos/demo"}, sort_keys=True, separators=(",", ":"))
        self.assertEqual(digest, P.approval_digest("agent-1", "gh", "DELETE", subject, b""))
        self.assertEqual(self.fake.requests, [])
        self.assertEqual(self.ctx.policy.list_approvals()[digest]["status"], "pending")
        record = self.audit_records()[-1]
        self.assertEqual((record["result"], record["reason"], record["digest"]), ("denied", "approval_required", digest))
        self.ctx.policy.approve(digest)
        # A different body or path does not consume the approval.
        other = self.relay("DELETE", "/repos/other")
        self.assertEqual(other.status, 428)
        self.assertNotEqual(other.json()["approval_digest"], digest)
        self.assertEqual(self.fake.requests, [])
        done = self.relay("DELETE", "/repos/demo")
        self.assertEqual((done.status, done.reason), (204, None))
        self.assertEqual(self.fake.requests[-1]["method"], "DELETE")
        again = self.relay("DELETE", "/repos/demo")
        self.assertEqual((again.status, again.reason), (428, "approval_required"))
        self.assertEqual(len(self.fake.requests), 1)
        self.assertEqual(self.ctx.policy.get_grant(self.grant.id).uses, 1)

    def test_pending_approval_shows_what_the_digest_binds(self) -> None:
        # Two look-alike requests (same caller, connection, method, query-free path) must be
        # distinguishable to the approver: query, body digest/size/preview, Content-Type, origin.
        self.ctx.policy.create_connection(http_connection(
            "writes", self.fake, "gh-token", P.HttpAuth("bearer"), P.HttpScope(None, None, ("POST",))))
        grant = self.ctx.policy.create_grant("agent-1", "writes", 3600, None)
        handle = self.issue_handle(connection="writes", grant=grant.id)
        json_type = {"Content-Type": "application/json"}
        benign_body = json.dumps({"title": "typo fix"}).encode()
        evil_body = json.dumps({"title": "wipe everything"}).encode()
        benign = self.relay("POST", "/repos/demo/issues", json_type, benign_body, handle=handle)
        evil = self.relay("POST", "/repos/demo/issues?admin_override=1", json_type, evil_body, handle=handle)
        self.assertEqual((benign.reason, evil.reason), ("approval_required", "approval_required"))
        approvals = self.ctx.policy.list_approvals()
        benign_entry, evil_entry = approvals[benign.json()["approval_digest"]], approvals[evil.json()["approval_digest"]]
        origin = f"http://127.0.0.1:{self.fake.port}"
        self.assertEqual(
            {key: evil_entry[key] for key in ("caller", "connection", "method", "path", "origin", "query", "content_type",
                                              "body_bytes", "body_sha256", "body_preview", "body_preview_truncated",
                                              "policy_version", "status")},
            {"caller": "agent-1", "connection": "writes", "method": "POST", "path": "/repos/demo/issues",
             "origin": origin, "query": "admin_override=1", "content_type": "application/json",
             "body_bytes": len(evil_body), "body_sha256": hashlib.sha256(evil_body).hexdigest(),
             "body_preview": evil_body.decode(), "body_preview_truncated": False, "policy_version": 1,
             "status": "pending"})
        self.assertEqual((benign_entry["query"], benign_entry["body_preview"]), (None, benign_body.decode()))
        self.assertNotEqual(benign_entry["body_sha256"], evil_entry["body_sha256"])
        # The details live only in the admin-only approval record, never in the audit log.
        audit = self.state_text("audit/audit.jsonl")
        self.assertNotIn("admin_override", audit)
        self.assertNotIn("wipe everything", audit)
        # Approving the benign entry releases exactly the benign request.
        self.ctx.policy.approve(benign.json()["approval_digest"])
        self.assertEqual(self.relay("POST", "/repos/demo/issues?admin_override=1", json_type, evil_body,
                                    handle=handle).reason, "approval_required")
        done = self.relay("POST", "/repos/demo/issues", json_type, benign_body, handle=handle)
        self.assertEqual((done.status, done.reason), (201, None))
        self.assertEqual((self.fake.requests[-1]["path"], self.fake.requests[-1]["body"]),
                         ("/repos/demo/issues", benign_body))
        # Content-Type is bound as well: the approved bytes under another type need a new approval.
        self.ctx.policy.approve(evil.json()["approval_digest"])
        retyped = self.relay("POST", "/repos/demo/issues?admin_override=1", {"Content-Type": "text/plain"}, evil_body,
                             handle=handle)
        self.assertEqual(retyped.reason, "approval_required")
        self.assertEqual(self.ctx.policy.list_approvals()[retyped.json()["approval_digest"]]["content_type"], "text/plain")
        self.assertEqual(len(self.fake.requests), 1)
        # Long and binary bodies: bounded preview, or size and digest only.
        long_body = b'{"title":"' + b"x" * 1000 + b'"}'
        long_digest = self.relay("POST", "/repos/demo/issues", json_type, long_body, handle=handle).json()["approval_digest"]
        long_entry = self.ctx.policy.list_approvals()[long_digest]
        self.assertEqual((len(long_entry["body_preview"]), long_entry["body_preview_truncated"]),
                         (gateway.APPROVAL_PREVIEW_CHARS, True))
        binary_digest = self.relay("POST", "/repos/demo/issues", {}, b"\xff\xfe\x00binary",
                                   handle=handle).json()["approval_digest"]
        binary_entry = self.ctx.policy.list_approvals()[binary_digest]
        self.assertEqual((binary_entry["body_preview"], binary_entry["body_bytes"], binary_entry["content_type"]),
                         (None, 9, None))

    def test_approval_does_not_follow_a_changed_origin_or_policy_version(self) -> None:
        first = self.relay("DELETE", "/repos/demo")
        digest = first.json()["approval_digest"]
        self.ctx.policy.approve(digest)
        other = FakeUpstream(SECRET_A).start()
        self.addCleanup(other.stop)
        # Same connection id and policy version, but the server now resolves another origin.
        connection = self.ctx.policy.get_connection("gh")
        moved = replace(connection, http_target=P.HttpTarget("http", "127.0.0.1", other.port, None))
        decision = P.Decision(True, "allowed", self.ctx.policy.get_grant(self.grant.id), moved)
        with mock.patch.object(self.ctx.policy, "evaluate", return_value=decision):
            redirected = self.relay("DELETE", "/repos/demo")
        self.assertEqual((redirected.status, redirected.reason), (428, "approval_required"))
        self.assertNotEqual(redirected.json()["approval_digest"], digest)
        self.assertEqual(self.ctx.policy.list_approvals()[redirected.json()["approval_digest"]]["origin"], other.url)
        # The administrator really moves the target and regrants: the old approval does not apply.
        _, widened = self.ctx.policy.update_connection("gh", http_target=P.HttpTarget("http", "127.0.0.1", other.port, None))
        self.assertTrue(widened)
        fresh = self.ctx.policy.regrant(self.grant.id)
        after_move = self.relay("DELETE", "/repos/demo", handle=self.issue_handle(grant=fresh.id))
        self.assertEqual((after_move.status, after_move.reason), (428, "approval_required"))
        self.assertNotIn(after_move.json()["approval_digest"], (digest, redirected.json()["approval_digest"]))
        # A policy-version change alone (not widening) also needs a new approval.
        self.ctx.policy.approve(after_move.json()["approval_digest"])
        self.ctx.policy.update_connection("gh", description="renamed")
        renamed = gateway.relay_for_caller(self.ctx, "agent-1", "gh", "DELETE", "/repos/demo", {}, b"")
        self.assertEqual((renamed.status, renamed.reason), (428, "approval_required"))
        self.assertNotEqual(renamed.json()["approval_digest"], after_move.json()["approval_digest"])
        self.assertEqual((self.fake.requests, other.requests), ([], []))


# ---------------------------------------------------------------- ledger
class LedgerTests(GatewayBase):
    def issue(self, request_id: str, title: str = "same") -> RelayResult:
        return self.relay("POST", "/repos/demo/issues", {"Content-Type": "application/json"},
                          json.dumps({"title": title}).encode(), request_id=request_id)

    def test_completed_request_is_replayed_without_upstream_contact(self) -> None:
        first = self.issue("req-1")
        self.assertEqual(first.status, 201)
        replay = self.issue("req-1")
        self.assertEqual((replay.status, replay.body, replay.reason), (201, first.body, None))
        self.assertIn(("X-ZeroPW-Replay", "true"), replay.headers)
        self.assertEqual(len(self.fake.requests), 1)
        self.assertEqual(self.ctx.policy.get_grant(self.grant.id).uses, 1)
        self.assertEqual(self.audit_records()[-1]["reason"], "replayed")
        self.assertEqual(self.audit_records()[-1]["request_id"], "req-1")
        # The header form of the request id works too and is scoped per caller.
        via_header = self.relay("POST", "/repos/demo/issues", {"Content-Type": "application/json",
                                "X-ZeroPW-Request-Id": "req-1"}, json.dumps({"title": "same"}).encode())
        self.assertEqual(via_header.status, 201)
        self.assertEqual(len(self.fake.requests), 1)
        # Replays still go through policy: a revoked grant cannot replay.
        self.ctx.policy.revoke_grant(self.grant.id)
        self.assertEqual(self.issue("req-1").reason, "grant_revoked")

    def test_same_id_different_request_is_rejected(self) -> None:
        self.assertEqual(self.issue("req-2").status, 201)
        reused = self.issue("req-2", title="different")
        self.assertEqual((reused.status, reused.reason), (409, "request_id_reused"))
        self.assertEqual(len(self.fake.requests), 1)
        other_path = self.relay("GET", "/repos", request_id="req-2")
        self.assertEqual(other_path.reason, "request_id_reused")

    def test_in_flight_duplicate_is_rejected_then_replayed(self) -> None:
        results: list[RelayResult] = []
        worker = threading.Thread(target=lambda: results.append(self.relay("GET", "/slow?seconds=0.8", request_id="slow")))
        worker.start()
        deadline = time.time() + 3
        while not self.fake.requests and time.time() < deadline:
            time.sleep(0.01)
        duplicate = self.relay("GET", "/slow?seconds=0.8", request_id="slow")
        self.assertEqual((duplicate.status, duplicate.reason), (409, "request_in_flight"))
        worker.join(timeout=5)
        self.assertEqual(results[0].status, 200)
        replay = self.relay("GET", "/slow?seconds=0.8", request_id="slow")
        self.assertEqual((replay.status, replay.body), (200, results[0].body))
        self.assertEqual(len(self.fake.requests), 1)

    def test_uncertain_outcome_is_not_retried_blindly(self) -> None:
        self.ctx.config.upstream_timeout = 0.3
        first = self.issue("req-3")
        self.assertEqual((first.status, first.reason), (201, None))
        timed_out = self.relay("GET", "/slow?seconds=1", request_id="slow-2")
        self.assertEqual(timed_out.reason, "upstream_timeout")
        again = self.relay("GET", "/slow?seconds=1", request_id="slow-2")
        self.assertEqual((again.status, again.reason), (409, "outcome_uncertain"))
        self.assertEqual(len([r for r in self.fake.requests if r["path"].startswith("/slow")]), 1)
        time.sleep(0.8)

    def test_pre_transmission_failure_releases_claim(self) -> None:
        self.ctx.vault.set_version_status("gh-token", 1, "retired")
        failed = self.issue("req-4")
        self.assertEqual(failed.reason, "credential_unavailable")
        self.ctx.vault.set_version_status("gh-token", 1, "active")
        self.assertEqual(self.issue("req-4").status, 201)
        # Unreachable upstream: nothing was transmitted, so the claim is dropped and the id may retry.
        self.fake.stop()
        down = self.issue("req-5")
        self.assertEqual(down.reason, "upstream_unreachable")
        doc = self.ctx.state.read_json(gateway.LEDGER_DOC) or {}
        self.assertNotIn("req-5", doc.get("agent-1", {}))
        self.assertIn("req-4", doc.get("agent-1", {}))
        self.assertEqual(self.issue("req-5").reason, "upstream_unreachable")   # retried, still not "uncertain"

    def test_large_replay_body_is_not_stored(self) -> None:
        with mock.patch.object(gateway, "LEDGER_MAX_STORED_BODY", 16):
            first = self.relay("GET", "/repos", request_id="big")
            self.assertEqual(first.status, 200)
            replay = self.relay("GET", "/repos", request_id="big")
        self.assertEqual((replay.status, replay.reason), (200, "replay_body_unavailable"))
        self.assertEqual(replay.json()["reason"], "replay_body_unavailable")
        self.assertEqual(len(self.fake.requests), 1)

    def test_ledger_file_is_bounded_and_value_free(self) -> None:
        for index in range(3):
            self.assertEqual(self.relay("GET", "/repos", request_id=f"r{index}").status, 200)
        self.clock.now += gateway.LEDGER_TTL_SECONDS + 1
        # The handle and the hour-long grant expired with the clock jump, as did the ledger entries.
        durable = self.ctx.policy.create_grant("agent-1", "gh", None, None)
        fresh_handle = self.issue_handle(grant=durable.id)
        self.assertEqual(self.relay("GET", "/me", handle=fresh_handle, request_id="r0").status, 200)
        self.assertEqual(len(self.fake.requests), 4)
        doc = self.ctx.state.read_json(gateway.LEDGER_DOC)
        self.assertEqual(set(doc["agent-1"]), {"r0"})
        self.assert_credential_free(json.dumps(doc))


# ------------------------------------------------------------ server routes
class ServerRouteTests(GatewayBase):
    def setUp(self) -> None:
        super().setUp()
        self.server = ZeroPWServer(self.ctx, quiet=False).serve_in_thread()
        self.addCleanup(self.server.stop)
        self.host, self.port = self.server.server_address[:2]

    def http(self, method: str, path: str, headers: dict[str, str] | None = None,
             body: bytes | None = None) -> tuple[int, dict[str, str], bytes]:
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp.read()
        finally:
            conn.close()

    def raw(self, request: bytes) -> bytes:
        with socket.create_connection((self.host, self.port), timeout=5) as sock:
            sock.sendall(request)
            chunks = []
            while True:
                try:
                    piece = sock.recv(65536)
                except socket.timeout:
                    break
                if not piece:
                    break
                chunks.append(piece)
        return b"".join(chunks)

    def test_handle_in_url_route(self) -> None:
        status, headers, body = self.http("GET", f"/h/{self.handle}/repos?page=1",
                                          {"Authorization": PLACEHOLDER, "Host": "evil.invalid", "Cookie": "a=b"})
        self.assertEqual((status, json.loads(body)), (200, [{"name": "demo"}, {"name": "tools"}]))
        self.assertEqual(headers["content-type"], "application/json")
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertNotIn("set-cookie", headers)
        seen = self.fake.requests[-1]
        self.assertEqual(seen["path"], "/repos?page=1")
        self.assertEqual(seen["headers"]["authorization"], f"Bearer {SECRET_A}")
        self.assertEqual(seen["headers"]["host"], f"127.0.0.1:{self.fake.port}")
        self.assertNotIn("cookie", seen["headers"])
        payload = json.dumps({"title": "via server"}).encode()
        status, _, body = self.http("POST", f"/h/{self.handle}/repos/demo/issues",
                                    {"Authorization": PLACEHOLDER, "Content-Type": "application/json"}, payload)
        self.assertEqual((status, json.loads(body)["title"]), (201, "via server"))
        self.assertEqual(self.fake.requests[-1]["body"], payload)
        status, _, body = self.http("GET", f"/h/{self.handle}")
        self.assertEqual(status, 404)   # "/" is relayed; the fake has no root route
        self.assertEqual(self.fake.requests[-1]["path"], "/")

    def test_header_handle_route(self) -> None:
        status, _, body = self.http("GET", "/relay/me", {"X-ZeroPW-Handle": self.handle, "Authorization": PLACEHOLDER})
        self.assertEqual((status, json.loads(body)), (200, {"login": "synthetic-user"}))
        self.assertNotIn("x-zeropw-handle", self.fake.requests[-1]["headers"])
        status, _, body = self.http("GET", "/relay/me")
        self.assertEqual((status, json.loads(body)["reason"]), (401, "handle_malformed"))
        status, _, body = self.http("GET", "/relay/me", {"X-ZeroPW-Handle": self.handle[:-3] + "xyz"})
        self.assertEqual((status, json.loads(body)["reason"]), (401, "handle_signature"))
        status, _, body = self.http("GET", "/relay/../admin", {"X-ZeroPW-Handle": self.handle})
        self.assertEqual((status, json.loads(body)["reason"]), (400, "invalid_path"))
        status, _, body = self.http("GET", f"/h/{self.handle}/debug/token")
        self.assertEqual((status, json.loads(body)["reason"]), (502, "credential_reflection_blocked"))
        self.assert_credential_free(body)

    def test_client_cannot_change_target(self) -> None:
        response = self.raw(f"GET http://evil.invalid/repos HTTP/1.1\r\nHost: evil.invalid\r\n"
                            f"X-ZeroPW-Handle: {self.handle}\r\nConnection: close\r\n\r\n".encode())
        self.assertTrue(response.startswith(b"HTTP/1.1 400"))
        self.assertIn(b"absolute_uri_unsupported", response)
        response = self.raw(b"CONNECT evil.invalid:443 HTTP/1.1\r\nHost: evil.invalid:443\r\nConnection: close\r\n\r\n")
        self.assertTrue(response.startswith(b"HTTP/1.1 405"))
        self.assertIn(b"connect_tunnel_unsupported", response)
        response = self.raw(f"GET /h/{self.handle}/repos HTTP/1.1\r\nHost: evil.invalid:1\r\nConnection: close\r\n\r\n".encode())
        self.assertTrue(response.startswith(b"HTTP/1.1 200"))
        self.assertEqual(self.fake.requests[-1]["headers"]["host"], f"127.0.0.1:{self.fake.port}")
        self.assertEqual(len(self.fake.requests), 1)

    def test_ambiguous_request_framing_is_refused(self) -> None:
        # Request smuggling / body-drop: anything a proxy could frame differently is refused
        # before routing, with an explicit reason, and the connection is closed.
        h = self.handle.encode()
        smuggled = b"GET /h/%s/me HTTP/1.1\r\nHost: x\r\n\r\n" % h
        post = b"POST /h/%s/repos/demo/issues HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n" % h
        cases = [
            (post + b"Transfer-Encoding: gzip, chunked\r\n\r\nd\r\nHELLO-PAYLOAD\r\n0\r\n\r\n", "transfer_encoding_unsupported"),
            (post + b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n", "transfer_encoding_unsupported"),
            (post + b"Transfer-Encoding: chunked \r\n\r\n0\r\n\r\n", "transfer_encoding_unsupported"),
            (post + b"Transfer-Encoding: identity\r\nContent-Length: 2\r\n\r\n{}", "transfer_encoding_unsupported"),
            (post + b"Content-Length: 5\r\nContent-Length: %d\r\n\r\nAAAAA" % (5 + len(smuggled)) + smuggled,
             "invalid_content_length"),
            (post + b"Content-Length: 5, 5\r\n\r\nAAAAA", "invalid_content_length"),
            (post + b"Content-Length: +5\r\n\r\nAAAAA", "invalid_content_length"),
            (post + b"Content-Length: 1_0\r\n\r\nAAAAAAAAAA", "invalid_content_length"),
            (post + b"Content-Length: -1\r\n\r\n", "invalid_content_length"),
            (post + b"Transfer-Encoding : chunked\r\nContent-Length: 3\r\n\r\nabc", "malformed_header"),
            (post + b"X-A: 1\r\n Transfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}", "obsolete_line_folding"),
            (b"GET /h/%s/repos HTTP/1.1\nHost: x\nConnection: close\n\n" % h, "malformed_header"),
            (b"GET /h/%s/repos HTTP/1.1\nHost: x\r\nConnection: close\r\n\r\n" % h, "malformed_request_line"),
            (b"GET  /h/%s/repos HTTP/1.1\r\nHost: x\r\n\r\n" % h, "malformed_request_line"),
            (b"GET /h/%s/repos HTTP/1.1\r\nHost: x\r\nX-Nul: a\x00b\r\n\r\n" % h, "malformed_header"),
        ]
        for raw, reason in cases:
            with self.subTest(reason=reason, raw=raw[-60:]):
                response = self.raw(raw)
                self.assertTrue(response.startswith(b"HTTP/1.1 400"), response[:80])
                self.assertIn(b'"reason": "%s"' % reason.encode(), response)
                self.assertIn(b"\r\nConnection: close\r\n", response)
                self.assertEqual(response.count(b"HTTP/1.1 "), 1)
        self.assertEqual(self.fake.requests, [])
        self.assertEqual(self.ctx.policy.get_grant(self.grant.id).uses, 0)

    def test_keep_alive_works_and_unread_or_short_bodies_never_frame_a_request(self) -> None:
        h = self.handle.encode()
        pair = self.raw(b"GET /h/%s/repos HTTP/1.1\r\nHost: x\r\n\r\n"
                        b"GET /h/%s/me HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" % (h, h))
        self.assertEqual(pair.count(b"HTTP/1.1 200 OK"), 2)
        self.assertEqual([r["path"] for r in self.fake.requests], ["/repos", "/me"])
        # A tools call refused before its body is read closes the connection, so the body is
        # never parsed as a second (authenticated) request.
        smuggled = b"GET /h/%s/repos HTTP/1.1\r\nHost: x\r\n\r\n" % h
        refused = self.raw(b"POST /v1/tools/request HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer zpwc_wrong\r\n"
                           b"Content-Length: %d\r\n\r\n" % len(smuggled) + smuggled)
        self.assertEqual(refused.count(b"HTTP/1.1 "), 1)
        self.assertIn(b"caller_token_invalid", refused)
        self.assertIn(b"\r\nConnection: close\r\n", refused)
        # A body the client cuts short is never relayed as a truncated write.
        with socket.create_connection((self.host, self.port), timeout=5) as sock:
            sock.sendall(b"POST /h/%s/repos/demo/issues HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                         b"Content-Length: 100\r\n\r\n" % h + b'{"title":"cut"}')
            sock.shutdown(socket.SHUT_WR)
            self.assertEqual(sock.recv(65536), b"")
        self.assertEqual(len(self.fake.requests), 2)
        self.assertEqual(self.ctx.policy.get_grant(self.grant.id).uses, 2)

    def test_tools_caller_authentication_failures_are_audited_and_alerted(self) -> None:
        token = self.ctx.policy.create_principal("agent-2")

        def call(headers: dict[str, str], name: str = "list_connections") -> tuple[int, dict]:
            status, _, body = self.http("POST", f"/v1/tools/{name}", headers, b"{}")
            return status, json.loads(body)

        self.assertEqual(call({"Authorization": f"Bearer {token}"})[0], 200)
        self.ctx.policy.disable_principal("agent-2")
        cases = [({}, "caller_token_missing", None), ({"Authorization": "Basic c3ludGhldGlj"}, "caller_token_missing", None),
                 ({"Authorization": "Bearer zpwc_synthetic-not-issued"}, "caller_token_invalid", None),
                 ({"Authorization": f"Bearer {token}"}, "principal_disabled", "agent-2")]
        for headers, reason, caller in cases:
            status, payload = call(headers)
            self.assertEqual((status, payload), (401, {"error": "AuthFailed", "reason": reason}))
            record = [r for r in self.ctx.audit.tail(1000) if r["event"] == "auth_failed"][-1]
            self.assertEqual((record["caller"], record["action"], record["result"], record["reason"]),
                             (caller, "list_connections", "denied", reason))
        self.assertIn(("revoked_use_attempt", "agent-2"), [(a["alert"], a["caller"]) for a in self.ctx.audit.alerts()])
        # An agent-chosen tool name is not copied into the log.
        self.assertEqual(call({"Authorization": "Bearer zpwc_synthetic-not-issued"}, "free-text-name")[0], 401)
        self.assertIsNone([r for r in self.ctx.audit.tail(1000) if r["event"] == "auth_failed"][-1]["action"])
        blob = self.state_text("audit/audit.jsonl", "audit/alerts.jsonl")
        self.assertNotIn(token, blob)
        self.assertNotIn("zpwc_synthetic-not-issued", blob)
        self.assertNotIn("free-text-name", blob)
        # If the failure cannot be recorded, the answer is audit_unavailable, not a silent 401.
        with mock.patch.object(self.ctx.state, "append_line", side_effect=OSError("disk full")):
            self.assertEqual(call({"Authorization": f"Bearer {token}"}),
                             (503, {"error": "AuditUnavailable", "reason": "audit_unavailable"}))

    def test_server_logs_never_contain_handles_or_queries(self) -> None:
        self.http("GET", f"/h/{self.handle}/repos?token=agent-guess", {"Authorization": PLACEHOLDER})
        self.http("GET", "/relay/me?x=1", {"X-ZeroPW-Handle": self.handle})
        self.assertTrue(self.server.log_lines)
        for line in self.server.log_lines:
            self.assertNotIn(self.handle, line)
            self.assertNotIn(self.handle.split(".")[1][:20], line)
            self.assertNotIn("agent-guess", line)
            self.assertNotIn("?", line)
        self.assertIn("GET /h/<handle>/...", self.server.log_lines)
        self.assert_credential_free("\n".join(self.server.log_lines))


# ----------------------------------------------------------- self-reference
class SelfReferenceTests(GatewayBase):
    """docs/security-design.md §6: ZeroPW's own authority never goes into a business connection."""

    def setUp(self) -> None:
        super().setUp()
        self.server = ZeroPWServer(self.ctx, quiet=False).serve_in_thread()
        self.addCleanup(self.server.stop)
        self.host, self.port = self.server.server_address[:2]

    def connect(self, cid: str, host: str, port: int, secret_id: str = "gh-token") -> str:
        target = types.SimpleNamespace(scheme="http", host=host, port=port)
        self.ctx.policy.create_connection(http_connection(cid, target, secret_id, P.HttpAuth("bearer"), P.HttpScope()))  # type: ignore[arg-type]
        return self.ctx.policy.create_grant("agent-1", cid, 3600, None).id

    def test_target_that_is_zeropw_itself_is_refused_before_use(self) -> None:
        token = self.ctx.policy.create_principal("agent-2")
        self.ctx.vault.put_secret("zpw-self", "api_key", token.encode(), "demo", "dev")
        self.ctx.config.extra["public_url"] = "http://zeropw.invalid:8443"
        # An unspecified address (0.0.0.0 / ::) is never a valid credential target: refused at configuration.
        for unspecified in ("0.0.0.0", "::"):
            with self.assertRaises(InvalidInput) as caught:
                P.HttpTarget("http", unspecified, self.port)
            self.assertEqual(caught.exception.reason, "target_address_not_allowed")
        targets = [("literal", self.host, self.port, "zpw-self"), ("localhost", "localhost", self.port, "gh-token"),
                   ("public", "zeropw.invalid", 8443, "gh-token")]
        for cid, host, port, secret_id in targets:
            grant_id = self.connect(cid, host, port, secret_id)
            with self.subTest(target=cid):
                result = gateway.relay_for_caller(self.ctx, "agent-1", cid, "POST", "/v1/tools/list_connections",
                                                  {"Content-Type": "application/json"}, b"{}")
                self.assertEqual((result.status, result.reason), (501, "self_referential_target"))
                self.assertEqual(result.json()["error"], "Unsupported")
                self.assertEqual(self.ctx.policy.get_grant(grant_id).uses, 0)
                self.assertEqual((self.audit_records()[-1]["result"], self.audit_records()[-1]["reason"]),
                                 ("denied", "self_referential_target"))
        self.assertEqual(self.server.log_lines, [])     # ZeroPW's API was never contacted
        self.assertNotIn("tools_list_connections", [r["event"] for r in self.ctx.audit.tail(1000)])

    def test_peer_that_resolves_to_zeropw_is_refused_before_transmission(self) -> None:
        self.connect("alias", "127.0.0.1", self.port)
        with mock.patch.object(gateway, "_self_referential_target", return_value=False):
            result = gateway.relay_for_caller(self.ctx, "agent-1", "alias", "GET", "/healthz", {}, b"", request_id="r-alias")
        self.assertEqual((result.status, result.reason), (501, "self_referential_target"))
        self.assertEqual(self.server.log_lines, [])
        self.assertNotIn("r-alias", (self.ctx.state.read_json(gateway.LEDGER_DOC) or {}).get("agent-1", {}))

    def test_relayed_request_marker_is_refused_by_the_server(self) -> None:
        # Normal relays announce themselves to the upstream.
        self.assertEqual(self.relay("GET", "/me").status, 200)
        self.assertEqual(self.fake.requests[-1]["headers"]["via"], gateway.RELAY_VIA)
        # Even when neither address check recognises ZeroPW (another host, a proxy), the server refuses.
        self.connect("proxied", "127.0.0.1", self.port)
        with mock.patch.object(gateway, "_self_referential_target", return_value=False), \
                mock.patch.object(gateway, "_peer_is_local_listener", return_value=False):
            result = gateway.relay_for_caller(self.ctx, "agent-1", "proxied", "GET", "/healthz", {}, b"")
        self.assertEqual((result.status, result.json()), (501, {"error": "Unsupported", "reason": "self_referential_target"}))
        refused = [r for r in self.ctx.audit.tail(1000) if r["event"] == "unsupported"]
        self.assertEqual([(r["action"], r["reason"], r["result"]) for r in refused],
                         [("GET", "self_referential_target", "denied")])
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        try:
            for via, status in (("1.1 zeropw-relay", 501), ("1.0 edge, 1.1 ZEROPW-RELAY (x)", 501), ("1.1 proxy.example", 200)):
                conn.request("GET", "/healthz", headers={"Via": via})
                response = conn.getresponse()
                response.read()
                self.assertEqual(response.status, status, via)
                if response.getheader("Connection") == "close":
                    conn.close()
        finally:
            conn.close()

    def test_zeropw_authority_is_never_a_business_credential(self) -> None:
        token = self.ctx.policy.create_principal("agent-2")
        values = {"caller-token": token, "handle": self.handle, "bearer-caller-token": f"Bearer {token}"}
        for name, value in values.items():
            self.ctx.vault.put_secret(name, "api_key", value.encode(), "demo", "dev")
            self.connect(name, self.fake.host, self.fake.port, name)
            with self.subTest(credential=name):
                result = gateway.relay_for_caller(self.ctx, "agent-1", name, "GET", "/me", {}, b"")
                self.assertEqual((result.status, result.reason), (501, "self_referential_credential"))
        self.assertEqual(self.fake.requests, [])
        # A credential that merely contains the letters is not mistaken for ZeroPW authority.
        self.ctx.vault.put_secret("lookalike", "api_key", b"synthetic-token-xzpw1.abc-zpwc_def", "demo", "dev")
        self.connect("lookalike", self.fake.host, self.fake.port, "lookalike")
        result = gateway.relay_for_caller(self.ctx, "agent-1", "lookalike", "GET", "/me", {}, b"")
        self.assertEqual((result.status, result.reason), (401, None))   # reached the upstream, which rejects it
        self.assert_credential_free(self.state_text("audit/audit.jsonl"), (token,))

    def test_closed_listener_is_forgotten(self) -> None:
        other = ZeroPWServer(self.ctx)
        port = other.server_address[1]
        self.assertIn(port, [p for _, p in gateway._listener_addresses()])
        other.server_close()
        self.assertNotIn(port, [p for _, p in gateway._listener_addresses()])


# -------------------------------------------------------------- slow clients
class SlowClientTests(GatewayBase):
    def start(self, timeout: float, deadline: float, max_connections: int = 128) -> ZeroPWServer:
        server = ZeroPWServer(self.ctx)
        server.request_timeout, server.request_read_deadline, server.max_connections = timeout, deadline, max_connections
        server.serve_in_thread()
        self.addCleanup(server.stop)
        return server

    @staticmethod
    def seconds_until_closed(sock: socket.socket, limit: float = 5.0) -> float:
        started = time.monotonic()
        sock.settimeout(limit)
        try:
            while sock.recv(65536):
                pass
        except OSError:
            pass
        return time.monotonic() - started

    def test_idle_and_dribbling_clients_are_dropped(self) -> None:
        self.assertIsNotNone(ZeroPWHandler.timeout)
        server = self.start(timeout=0.3, deadline=0.8)
        address = server.server_address[:2]
        with socket.create_connection(address) as partial:
            partial.sendall(b"POST /h/%s/repos/demo/issues HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\nabc"
                            % self.handle.encode())
            self.assertLess(self.seconds_until_closed(partial), 3.0)
        with socket.create_connection(address) as dribbler:
            request = b"GET /h/%s/repos HTTP/1.1\r\nHost: x\r\nX-Slow: " % self.handle.encode() + b"a" * 200

            def dribble() -> None:
                try:
                    for byte in request:
                        dribbler.send(bytes([byte]))
                        time.sleep(0.05)
                except OSError:
                    pass

            worker = threading.Thread(target=dribble, daemon=True)
            worker.start()
            elapsed = self.seconds_until_closed(dribbler)
            self.assertGreater(elapsed, 0.6)
            self.assertLess(elapsed, 3.0)
        self.assertEqual(self.fake.requests, [])
        self.assertEqual(self.ctx.policy.get_grant(self.grant.id).uses, 0)
        with socket.create_connection(address, timeout=5) as ok:
            ok.sendall(b"GET /h/%s/repos HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" % self.handle.encode())
            self.assertTrue(ok.recv(65536).startswith(b"HTTP/1.1 200"))

    def test_concurrent_connections_are_capped(self) -> None:
        server = self.start(timeout=5.0, deadline=10.0, max_connections=2)
        address = server.server_address[:2]
        held = [socket.create_connection(address, timeout=5) for _ in range(2)]
        try:
            with socket.create_connection(address, timeout=5) as extra:
                response = extra.recv(65536)
            self.assertTrue(response.startswith(b"HTTP/1.1 503"), response[:40])
            self.assertIn(b'"reason": "too_many_connections"', response)
        finally:
            for sock in held:
                sock.close()
        deadline = time.monotonic() + 5
        while True:
            with socket.create_connection(address, timeout=5) as again:
                again.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                if again.recv(65536).startswith(b"HTTP/1.1 200") or time.monotonic() > deadline:
                    break
            time.sleep(0.05)
        self.assertLess(time.monotonic(), deadline)

    def test_request_cut_at_the_deadline_is_never_acted_on(self) -> None:
        server = ZeroPWServer(self.ctx)
        self.addCleanup(server.server_close)
        slow, busy = mock.Mock(), mock.Mock()
        server._connections.update({slow: None, busy: None})
        self.assertTrue(server.mark_reading(slow, True))
        self.assertTrue(server.mark_reading(busy, False))   # already processing: never reaped
        self.assertEqual(server.reap_slow_clients(now=time.monotonic() + server.request_read_deadline + 1), 1)
        slow.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        busy.shutdown.assert_not_called()
        # Even if the last body bytes were already buffered, the handler learns it was cut.
        self.assertFalse(server.mark_reading(slow, False))
        self.assertTrue(server.mark_reading(busy, False))

    def test_stop_does_not_wait_for_idle_keep_alive_clients(self) -> None:
        server = ZeroPWServer(self.ctx).serve_in_thread()
        with socket.create_connection(server.server_address[:2], timeout=5) as idle:
            idle.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
            self.assertTrue(idle.recv(65536).startswith(b"HTTP/1.1 200"))
            started = time.monotonic()
            server.stop()
            self.assertLess(time.monotonic() - started, 3.0)


# --------------------------------------------------------------------- TLS
@unittest.skipIf(shutil.which("openssl") is None, "openssl binary not available")
class TlsTests(GatewayBase):
    def make_cert(self, name: str, cn: str, san: str) -> tuple[Path, Path]:
        root = Path(self.tmp.name)
        cnf = root / f"{name}.cnf"
        cnf.write_text(f"[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = {cn}\n"
                       f"[ext]\nsubjectAltName = {san}\nbasicConstraints = CA:TRUE\n")
        key, cert = root / f"{name}.key", root / f"{name}.crt"
        try:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                            "-out", str(cert), "-days", "2", "-config", str(cnf), "-extensions", "ext"],
                           check=True, capture_output=True, timeout=60)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            self.skipTest(f"openssl could not generate a test certificate: {type(exc).__name__}")
        return cert, key

    def tls_fake(self, cert: Path, key: Path) -> FakeUpstream:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        fake = FakeUpstream(SECRET_B, ssl_context=context).start()
        self.addCleanup(fake.stop)
        return fake

    def tls_connection(self, cid: str, fake: FakeUpstream, ca_file: str | None) -> str:
        self.ctx.policy.create_connection(http_connection(cid, fake, "tls-token", P.HttpAuth("bearer"), P.HttpScope(), ca_file))
        grant = self.ctx.policy.create_grant("agent-1", cid, 3600, None)
        return self.issue_handle(connection=cid, grant=grant.id)

    def test_https_with_pinned_ca_succeeds_and_untrusted_or_wrong_name_fails(self) -> None:
        self.ctx.vault.put_secret("tls-token", "api_key", SECRET_B.encode(), "demo", "dev")
        cert, key = self.make_cert("good", "127.0.0.1", "IP:127.0.0.1")
        good = self.tls_fake(cert, key)
        self.assertTrue(good.url.startswith("https://"))
        trusted = self.relay("GET", "/me", handle=self.tls_connection("tls-good", good, str(cert)))
        self.assertEqual((trusted.status, trusted.json()), (200, {"login": "synthetic-user"}))
        self.assertEqual(good.requests[-1]["headers"]["authorization"], f"Bearer {SECRET_B}")

        untrusted = self.relay("GET", "/me", handle=self.tls_connection("tls-untrusted", good, None))
        self.assertEqual((untrusted.status, untrusted.reason), (502, "upstream_tls_failed"))
        self.assert_result_credential_free(untrusted)
        self.assertEqual(len(good.requests), 1)

        other_cert, other_key = self.make_cert("other", "other.invalid", "DNS:other.invalid")
        wrong_name = self.tls_fake(other_cert, other_key)
        mismatch = self.relay("GET", "/me", handle=self.tls_connection("tls-mismatch", wrong_name, str(other_cert)))
        self.assertEqual((mismatch.status, mismatch.reason), (502, "upstream_tls_failed"))
        self.assertEqual(wrong_name.requests, [])
        self.assertEqual(self.audit_records()[-1]["result"], "error")
        self.assert_credential_free(self.state_text("audit/audit.jsonl"))

        missing = self.relay("GET", "/me", handle=self.tls_connection("tls-missing-ca", good, str(cert) + ".missing"))
        self.assertEqual((missing.status, missing.reason), (502, "ca_file_unavailable"))


class CredentialPatternTestCase(unittest.TestCase):
    """Pure tests of the reflection pattern set (no servers)."""

    def test_space_in_password_covers_plus_and_percent20_forms(self) -> None:
        secret = b"synthetic pass word/+="
        patterns = gateway.credential_patterns(secret, basic_username="synthetic-user")
        plus_upper = b"synthetic+pass+word%2F%2B%3D"
        plus_lower = b"synthetic+pass+word%2f%2b%3d"
        pct_upper = b"synthetic%20pass%20word%2F%2B%3D"
        pct_lower = b"synthetic%20pass%20word%2f%2b%3d"
        for form in (secret, plus_upper, plus_lower, pct_upper, pct_lower,
                     base64.b64encode(b"synthetic-user:" + secret).rstrip(b"=")):
            self.assertIn(form, patterns, form)
            self.assertTrue(gateway._contains_credential(b"prefix " + form + b" suffix", patterns), form)

    def test_base64_patterns_find_the_credential_at_any_offset(self) -> None:
        rng = random.Random(20260914)
        for secret in (SECRET_A.encode(), SECRET_ENCODINGS.encode(), b"synthetic\x00\xff\xfe-binary-credential"):
            for username in (None, "synthetic-user"):
                patterns = gateway.credential_patterns(secret, username)
                values = [secret] + ([username.encode() + b":" + secret] if username else [])
                for value, offset, suffix in ((v, o, t) for v in values for o in range(6) for t in range(4)):
                    blob = rng.randbytes(offset) + value + rng.randbytes(suffix)
                    for encoder in (base64.b64encode, base64.urlsafe_b64encode):
                        encoded = encoder(blob)
                        with self.subTest(secret=secret[:12], username=username, offset=offset, suffix=suffix):
                            self.assertTrue(gateway._contains_credential(b'{"content":"' + encoded + b'"}', patterns))
                            self.assertTrue(gateway._contains_credential(encoded.rstrip(b"="), patterns))
                            wrapped = b"\\n".join(encoded[i:i + 16] for i in range(0, len(encoded), 16))
                            self.assertTrue(gateway._contains_credential(b'{"content":"' + wrapped + b'"}', patterns))
                            self.assertTrue(gateway._contains_credential(wrapped.replace(b"\\n", b"\r\n"), patterns))
        # Derived alignment patterns are never short enough to match unrelated output.
        self.assertEqual(gateway._base64_cores(b"abc"), [])
        self.assertTrue(all(len(core) >= gateway.MIN_ALIGNED_PATTERN_LENGTH
                            for core in gateway._base64_cores(b"synthetic-token")))
        patterns = gateway.credential_patterns(SECRET_A.encode(), "synthetic-user")
        unrelated = base64.b64encode(rng.randbytes(256 * 1024))
        self.assertFalse(gateway._contains_credential(unrelated, patterns))
        self.assertFalse(gateway._contains_credential(b'{"content":"' + unrelated[:4096] + b'\\n"}', patterns))

    def test_letters_of_the_credential_keep_their_case(self) -> None:
        secret = b"Synthetic/TOKEN"
        patterns = gateway.credential_patterns(secret)
        self.assertIn(b"Synthetic%2fTOKEN", patterns)
        self.assertNotIn(b"synthetic%2ftoken", patterns)
        self.assertIn(secret.hex().upper().encode(), patterns)
        self.assertFalse(gateway._contains_credential(b"an ordinary business response", patterns))


class ResolvedAddressTests(GatewayBase):
    """security-design §4: DNS changes must not route the credential to internal or metadata addresses."""

    NAME = "upstream.zeropw.test"

    def resolver(self, *addresses: str):
        calls: list[str] = []

        def fake_getaddrinfo(host: str, port: int, *args: object, **kwargs: object) -> list:
            calls.append(host)
            answers = []
            for address in addresses:
                family = socket.AF_INET6 if ":" in address else socket.AF_INET
                sockaddr = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
                answers.append((family, socket.SOCK_STREAM, 6, "", sockaddr))
            return answers

        return fake_getaddrinfo, calls

    @contextlib.contextmanager
    def dial_recorder(self, deliver_to_fake: bool = False):
        """Record every address the relay opens a TCP connection to.

        With ``deliver_to_fake`` the network is simulated: whatever public address was dialed, the connection
        reaches the local fake upstream (so a connection that refuses private answers can still be served).
        """
        dialed: list[str] = []
        real = socket.create_connection

        def recording(address, *args, **kwargs):
            dialed.append(address[0])
            if deliver_to_fake:
                address = ("127.0.0.1", address[1])
            return real(address, *args, **kwargs)

        with mock.patch.object(gateway.socket, "create_connection", recording):
            yield dialed

    @contextlib.contextmanager
    def os_resolver_trap(self):
        """Make the process-wide OS resolver answer the test names with a trap listener's address.

        ``gateway._getaddrinfo`` (the checked resolution) is patched separately by each test.  Anything that
        resolves a ``*.zeropw.test`` name again at connect time -- ``socket.create_connection`` uses
        ``socket.getaddrinfo`` -- is recorded in ``os_lookups`` and sent to the trap instead of the checked
        answer; ``connections`` counts what reached the trap.
        """
        trap = types.SimpleNamespace(dialed=[], os_lookups=[], connections=0)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        listener.settimeout(0.2)
        trap_port = listener.getsockname()[1]
        stop = threading.Event()

        def accept() -> None:
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except (socket.timeout, OSError):
                    continue
                trap.connections += 1
                conn.close()

        thread = threading.Thread(target=accept, daemon=True)
        thread.start()
        real_getaddrinfo = socket.getaddrinfo

        def os_getaddrinfo(host, port, *args, **kwargs):
            name = host.decode("ascii", "replace") if isinstance(host, bytes) else host
            if isinstance(name, str) and name.rstrip(".").endswith("zeropw.test"):
                trap.os_lookups.append(name)
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", trap_port))]
            return real_getaddrinfo(host, port, *args, **kwargs)

        try:
            with self.dial_recorder() as dialed, mock.patch.object(socket, "getaddrinfo", os_getaddrinfo):
                trap.dialed = dialed
                yield trap
        finally:
            stop.set()
            thread.join(2)
            listener.close()

    def named_connection(self, cid: str, host: str, allow_private: bool, scheme: str = "http",
                         port: int | None = None, ca_file: str | None = None, secret_id: str = "gh-token") -> str:
        self.ctx.policy.create_connection(P.Connection(
            id=cid, project="demo", environment="dev", service="named", kind="http", secret_id=secret_id,
            secret_version=None, description="", ssh_target=None, cli=None,
            http_target=P.HttpTarget(scheme, host, port or self.fake.port, ca_file, allow_private),
            http_auth=P.HttpAuth("bearer"), http_scope=P.HttpScope(), policy_version=0, status="active",
            created_at="", updated_at=""))
        grant = self.ctx.policy.create_grant("agent-1", cid, 3600, None)
        return self.issue_handle(connection=cid, grant=grant.id)

    def test_address_classes(self) -> None:
        import ipaddress

        table = {
            "8.8.8.8": (None, None),
            "2606:4700:4700::1111": (None, None),
            "127.0.0.1": ("target_address_not_allowed", None),
            "10.1.2.3": ("target_address_not_allowed", None),
            "172.16.0.1": ("target_address_not_allowed", None),
            "192.168.1.1": ("target_address_not_allowed", None),
            "100.64.0.1": ("target_address_not_allowed", None),
            "::1": ("target_address_not_allowed", None),
            "fc00::1": ("target_address_not_allowed", None),
            "::ffff:127.0.0.1": ("target_address_not_allowed", None),
            "0.0.0.0": ("target_address_not_allowed", "target_address_not_allowed"),
            "224.0.0.1": ("target_address_not_allowed", "target_address_not_allowed"),
            "169.254.169.254": ("metadata_address_not_allowed", "metadata_address_not_allowed"),
            "169.254.1.1": ("metadata_address_not_allowed", "metadata_address_not_allowed"),
            "::ffff:169.254.169.254": ("metadata_address_not_allowed", "metadata_address_not_allowed"),
            "fe80::1": ("metadata_address_not_allowed", "metadata_address_not_allowed"),
            "fd00:ec2::254": ("metadata_address_not_allowed", "metadata_address_not_allowed"),
            "100.100.100.200": ("metadata_address_not_allowed", "metadata_address_not_allowed"),
            "168.63.129.16": ("metadata_address_not_allowed", "metadata_address_not_allowed"),
            # IPv6 metadata / credential endpoints of other providers.
            "fd00:ec2::23": ("metadata_address_not_allowed", "metadata_address_not_allowed"),
            "fd20:ce::254": ("metadata_address_not_allowed", "metadata_address_not_allowed"),
            "fd00:c1::a9fe:a9fe": ("metadata_address_not_allowed", "metadata_address_not_allowed"),
            # IPv6 forms that a translator or tunnel delivers to the IPv4 address they carry.
            "64:ff9b::127.0.0.1": ("target_address_not_allowed", None),              # NAT64, RFC 6052
            "64:ff9b::10.0.0.1": ("target_address_not_allowed", None),
            "64:ff9b::169.254.169.254": ("metadata_address_not_allowed", "metadata_address_not_allowed"),
            "64:ff9b::8.8.8.8": (None, None),                                       # NAT64 to a public address
            "64:ff9b::0.0.0.0": ("target_address_not_allowed", "target_address_not_allowed"),
            "64:ff9b:1::a9fe:a9fe": ("metadata_address_not_allowed", "metadata_address_not_allowed"),  # RFC 8215
            "64:ff9b:1::a00:1": ("target_address_not_allowed", None),
            "::127.0.0.1": ("target_address_not_allowed", None),                     # IPv4-compatible
            "::10.0.0.1": ("target_address_not_allowed", None),
            "::169.254.169.254": ("metadata_address_not_allowed", "metadata_address_not_allowed"),
            "::8.8.8.8": ("target_address_not_allowed", None),                       # reserved IPv6 space
            "::ffff:0:127.0.0.1": ("target_address_not_allowed", None),              # SIIT
            "::ffff:0:10.0.0.1": ("target_address_not_allowed", None),
            "::ffff:0:169.254.169.254": ("metadata_address_not_allowed", "metadata_address_not_allowed"),
            "2002:a9fe:a9fe::1": ("metadata_address_not_allowed", "metadata_address_not_allowed"),     # 6to4
            "2002:a00:1::1": ("target_address_not_allowed", None),
            "2001:0:4136:e378:8000:63bf:5601:5601": ("metadata_address_not_allowed",                   # Teredo
                                                     "metadata_address_not_allowed"),
            "fec0::1": ("target_address_not_allowed", None),                         # site-local
        }
        for text, (public_only, private_allowed) in table.items():
            with self.subTest(address=text):
                address = ipaddress.ip_address(text)
                self.assertEqual(P.address_block_reason(address, False), public_only)
                self.assertEqual(P.address_block_reason(address, True), private_allowed)
        for literal in ("169.254.169.254", "fe80::1", "100.100.100.200", "fd00:ec2::254", "fd00:ec2::23",
                        "fd20:ce::254", "fd00:c1::a9fe:a9fe", "64:ff9b::169.254.169.254", "::169.254.169.254",
                        "::ffff:0:169.254.169.254", "2002:a9fe:a9fe::1"):
            with self.subTest(literal=literal):
                with self.assertRaises(InvalidInput) as caught:
                    P.HttpTarget("http", literal, 80)
                self.assertEqual(caught.exception.reason, "metadata_address_not_allowed")
        # A literal is an administrator choice: internal addresses, also NAT64-embedded ones, stay allowed.
        self.assertEqual(P.HttpTarget("http", "64:ff9b::10.0.0.1", 80).host, "64:ff9b::10.0.0.1")
        with self.assertRaises(InvalidInput):
            P.HttpTarget("http", "example.com", 80, None, "yes")  # type: ignore[arg-type]

    def test_hostname_resolving_to_loopback_is_refused_without_opt_in(self) -> None:
        handle = self.named_connection("named", self.NAME, allow_private=False)
        fake_getaddrinfo, calls = self.resolver("127.0.0.1")
        with mock.patch.object(gateway, "_getaddrinfo", fake_getaddrinfo):
            result = self.relay("GET", "/me", handle=handle)
        self.assertEqual((result.status, result.reason), (403, "target_address_not_allowed"))
        self.assertEqual(result.json(), {"error": "PolicyDenied", "reason": "target_address_not_allowed"})
        self.assertEqual(calls, [self.NAME])
        self.assertEqual(self.fake.requests, [])
        self.assert_result_credential_free(result)
        self.assertEqual(self.audit_records()[-1]["reason"], "target_address_not_allowed")
        self.assertIn("credential_exposure", [a["alert"] for a in self.ctx.audit.alerts(1000)])

    def test_mixed_answer_is_refused_as_a_whole(self) -> None:
        handle = self.named_connection("mixed", self.NAME, allow_private=False)
        fake_getaddrinfo, _calls = self.resolver("8.8.8.8", "127.0.0.1")
        with mock.patch.object(gateway, "_getaddrinfo", fake_getaddrinfo):
            result = self.relay("GET", "/me", handle=handle)
        self.assertEqual((result.status, result.reason), (403, "target_address_not_allowed"))
        self.assertEqual(self.fake.requests, [])

    def test_metadata_answer_is_refused_even_for_private_opt_in(self) -> None:
        handle = self.named_connection("meta", self.NAME, allow_private=True)
        for answer in ("169.254.169.254", "fd00:ec2::254", "::ffff:169.254.169.254", "fd00:ec2::23", "fd20:ce::254",
                       "fd00:c1::a9fe:a9fe", "64:ff9b::169.254.169.254", "::169.254.169.254", "168.63.129.16"):
            fake_getaddrinfo, _calls = self.resolver(answer)
            with self.subTest(answer=answer), mock.patch.object(gateway, "_getaddrinfo", fake_getaddrinfo):
                result = self.relay("GET", "/me", handle=handle)
                self.assertEqual((result.status, result.reason), (403, "metadata_address_not_allowed"))
        self.assertEqual(self.fake.requests, [])

    def test_ipv4_embedded_in_ipv6_answers_is_judged_by_the_ipv4_address(self) -> None:
        """A NAT64/IPv4-compatible/SIIT answer for an internal IPv4 address never gets the credential."""
        handle = self.named_connection("nat64", self.NAME, allow_private=False)
        for answer in ("64:ff9b::10.0.0.1", "64:ff9b::127.0.0.1", "::10.0.0.1", "::ffff:0:10.0.0.1", "fec0::1"):
            fake_getaddrinfo, _calls = self.resolver(answer)
            with self.subTest(answer=answer), self.dial_recorder() as dialed, \
                    mock.patch.object(gateway, "_getaddrinfo", fake_getaddrinfo):
                result = self.relay("GET", "/me", handle=handle)
                self.assertEqual((result.status, result.reason), (403, "target_address_not_allowed"))
                self.assertEqual(dialed, [])
        self.assertEqual(self.fake.requests, [])

    def test_address_refusal_spends_no_use_approval_or_credential(self) -> None:
        """A DNS answer the relay refuses cannot burn a capped grant, a granted approval or a secret decryption."""
        self.ctx.policy.create_connection(P.Connection(
            id="capped", project="demo", environment="dev", service="named", kind="http", secret_id="gh-token",
            secret_version=None, description="", ssh_target=None, cli=None,
            http_target=P.HttpTarget("http", self.NAME, self.fake.port, None, False), http_auth=P.HttpAuth("bearer"),
            http_scope=P.HttpScope(None, None, ("DELETE",)), policy_version=0, status="active",
            created_at="", updated_at=""))
        grant = self.ctx.policy.create_grant("agent-1", "capped", 3600, 2)
        handle = self.issue_handle(connection="capped", grant=grant.id)
        public, _ = self.resolver("8.8.8.8")
        with mock.patch.object(gateway, "_getaddrinfo", public), self.dial_recorder(deliver_to_fake=True):
            pending = self.relay("DELETE", "/repos/demo", handle=handle)
        self.assertEqual((pending.status, pending.reason), (428, "approval_required"))
        digest = pending.json()["approval_digest"]
        self.ctx.policy.approve(digest)
        rebound, _ = self.resolver("10.0.0.7")
        with mock.patch.object(gateway, "_getaddrinfo", rebound), \
                mock.patch.object(self.ctx.vault, "secret_for_trusted_use",
                                  side_effect=AssertionError("credential fetched")) as fetched:
            for method, path in (("GET", "/me"), ("GET", "/repos"), ("DELETE", "/repos/demo")):
                result = self.relay(method, path, handle=handle)
                self.assertEqual((result.status, result.reason), (403, "target_address_not_allowed"))
        fetched.assert_not_called()
        self.assertEqual(self.ctx.policy.get_grant(grant.id).uses, 0)
        approval = self.ctx.state.read_json(P.CONTROL)["approvals"][digest]
        self.assertEqual(approval["status"], "approved")
        self.assertNotIn("attempt", [r["result"] for r in self.audit_records() if r["connection"] == "capped"])
        # The approval and both uses are still there once DNS points back at the checked upstream.
        with mock.patch.object(gateway, "_getaddrinfo", public), self.dial_recorder(deliver_to_fake=True) as dialed:
            self.assertEqual(self.relay("DELETE", "/repos/demo", handle=handle).status, 204)
            self.assertEqual(self.relay("GET", "/me", handle=handle).status, 200)
        self.assertEqual(dialed, ["8.8.8.8", "8.8.8.8"])
        self.assertEqual(self.ctx.policy.get_grant(grant.id).uses, 2)

    def test_opt_in_connects_to_the_checked_address_and_resolves_once_per_request(self) -> None:
        handle = self.named_connection("internal", self.NAME, allow_private=True)
        fake_getaddrinfo, calls = self.resolver("127.0.0.1")
        with mock.patch.object(gateway, "_getaddrinfo", fake_getaddrinfo), self.os_resolver_trap() as trap:
            first = self.relay("GET", "/me", handle=handle)
            second = self.relay("GET", "/repos", handle=handle)
        self.assertEqual((first.status, second.status), (200, 200))
        self.assertEqual(calls, [self.NAME, self.NAME])   # one resolution per request
        # The connect step dials the checked answer and never asks the OS resolver again: the OS resolver would
        # have answered with a different address (the trap), and nothing reached it.
        self.assertEqual(trap.dialed, ["127.0.0.1", "127.0.0.1"])
        self.assertEqual(trap.os_lookups, [])
        self.assertEqual(trap.connections, 0)
        self.assertEqual(self.fake.requests[-1]["headers"]["host"], f"{self.NAME}:{self.fake.port}")
        self.assertEqual(self.fake.requests[-1]["headers"]["authorization"], f"Bearer {SECRET_A}")

    def test_stored_metadata_literal_loads_and_is_refused_at_use(self) -> None:
        """A record saved before its literal became forbidden can be listed and disabled; use is refused and audited."""
        from zeropw import tools

        self.named_connection("old-meta", self.NAME, allow_private=False)
        path = self.ctx.state.path / P.CONNECTIONS
        doc = json.loads(path.read_text())
        doc["old-meta"]["http_target"]["host"] = "169.254.169.254"
        del doc["old-meta"]["http_target"]["allow_private_network"]
        path.write_text(json.dumps(doc))
        grant = [g for g in self.ctx.policy.list_grants("agent-1") if g.connection == "old-meta"][0]

        self.assertEqual(self.ctx.policy.get_connection("old-meta").http_target.host, "169.254.169.254")
        self.assertIn("old-meta", [c.id for c in self.ctx.policy.list_connections()])
        listed = tools.list_connections(self.ctx, "agent-1")
        self.assertEqual(sorted(c["id"] for c in listed["connections"]), ["gh", "old-meta"])
        result = gateway.relay_for_caller(self.ctx, "agent-1", "old-meta", "GET", "/me", {}, b"")
        self.assertEqual((result.status, result.reason), (403, "metadata_address_not_allowed"))
        self.assertEqual((self.audit_records()[-1]["connection"], self.audit_records()[-1]["reason"]),
                         ("old-meta", "metadata_address_not_allowed"))
        self.assertEqual(self.ctx.policy.get_grant(grant.id).uses, 0)
        self.assertEqual(self.fake.requests, [])
        disabled = self.ctx.policy.disable_connection("old-meta")
        self.assertEqual(disabled.status, "disabled")
        # New input is still checked strictly, also when it bypasses the constructor check.
        lenient = P.HttpTarget("http", "fd20:ce::254", 80, check_address=False)
        with self.assertRaises(InvalidInput) as caught:
            self.ctx.policy.update_connection("old-meta", http_target=lenient)
        self.assertEqual(caught.exception.reason, "metadata_address_not_allowed")
        stored = self.ctx.policy.get_connection("old-meta")
        with self.assertRaises(InvalidInput) as caught:
            self.ctx.policy.create_connection(replace(stored, id="new-meta", http_target=lenient))
        self.assertEqual(caught.exception.reason, "metadata_address_not_allowed")

    def test_dns_change_between_requests_takes_effect_on_the_next_request(self) -> None:
        handle = self.named_connection("rebind", self.NAME, allow_private=True)
        good, _ = self.resolver("127.0.0.1")
        with mock.patch.object(gateway, "_getaddrinfo", good):
            self.assertEqual(self.relay("GET", "/me", handle=handle).status, 200)
        rebound, _ = self.resolver("169.254.169.254")
        with mock.patch.object(gateway, "_getaddrinfo", rebound):
            result = self.relay("GET", "/me", handle=handle)
        self.assertEqual((result.status, result.reason), (403, "metadata_address_not_allowed"))
        self.assertEqual(len(self.fake.requests), 1)

    def test_resolution_failure_is_explicit(self) -> None:
        handle = self.named_connection("nxdomain", self.NAME, allow_private=True)

        def failing(*args: object, **kwargs: object) -> list:
            raise socket.gaierror(socket.EAI_NONAME, "no such name")

        with mock.patch.object(gateway, "_getaddrinfo", failing):
            result = self.relay("GET", "/me", handle=handle)
        self.assertEqual((result.status, result.reason), (502, "upstream_unreachable"))
        self.assert_result_credential_free(result)

    def test_private_network_opt_in_is_a_widening_change(self) -> None:
        self.named_connection("widen", self.NAME, allow_private=False)
        before = self.ctx.policy.get_connection("widen")
        target = P.HttpTarget(before.http_target.scheme, before.http_target.host, before.http_target.port, None, True)
        _, widened = self.ctx.policy.update_connection("widen", http_target=target)
        self.assertTrue(widened)
        narrowed = P.HttpTarget(target.scheme, target.host, target.port, None, False)
        _, widened = self.ctx.policy.update_connection("widen", http_target=narrowed)
        self.assertFalse(widened)

    @unittest.skipIf(shutil.which("openssl") is None, "openssl binary not available")
    def test_tls_is_verified_against_the_configured_name_not_the_pinned_address(self) -> None:
        root = Path(self.tmp.name)
        cnf = root / "named.cnf"
        cnf.write_text(f"[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = {self.NAME}\n"
                       f"[ext]\nsubjectAltName = DNS:{self.NAME}\nbasicConstraints = CA:TRUE\n")
        key, cert = root / "named.key", root / "named.crt"
        try:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                            "-out", str(cert), "-days", "2", "-config", str(cnf), "-extensions", "ext"],
                           check=True, capture_output=True, timeout=60)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            self.skipTest(f"openssl could not generate a test certificate: {type(exc).__name__}")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        fake = FakeUpstream(SECRET_B, ssl_context=context).start()
        self.addCleanup(fake.stop)
        self.ctx.vault.put_secret("tls-named", "api_key", SECRET_B.encode(), "demo", "dev")
        good = self.named_connection("tls-good", self.NAME, True, "https", fake.port, str(cert), "tls-named")
        wrong = self.named_connection("tls-wrong", "other.zeropw.test", True, "https", fake.port, str(cert), "tls-named")
        resolver, _ = self.resolver("127.0.0.1")
        with mock.patch.object(gateway, "_getaddrinfo", resolver), self.os_resolver_trap() as trap:
            ok = self.relay("GET", "/me", handle=good)
            bad = self.relay("GET", "/me", handle=wrong)
        self.assertEqual((ok.status, ok.reason), (200, None))
        self.assertEqual((bad.status, bad.reason), (502, "upstream_tls_failed"))
        self.assertEqual(len(fake.requests), 1)
        # TLS also dials the pinned address: the OS resolver is never asked and its (different) answer gets nothing.
        self.assertEqual(trap.dialed, ["127.0.0.1", "127.0.0.1"])
        self.assertEqual((trap.os_lookups, trap.connections), ([], 0))


if __name__ == "__main__":
    unittest.main()
