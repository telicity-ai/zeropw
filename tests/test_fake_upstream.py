"""The controlled fake upstream used by the gateway tests behaves as documented."""

from __future__ import annotations

import base64
import html
import http.client
import json
import re
import unittest
import urllib.parse

from zeropw.fake_upstream import (
    BASIC_LEAK_FORMS, ENCODED_LEAK_FORMS, FakeUpstream, LARGE_BODY_SIZE, STREAM_PARTS, encoded_credential,
)

SECRET = "synthetic-token-fake-upstream-0123456789"
# Reserved URL characters, bytes whose base64 differs between the std and urlsafe
# alphabets, and characters JSON/HTML escape: every named form is distinct.
SECRET_ENCODINGS = 'synthetic-token/enc+ode=chars:>>>?<&"\\x-0123456789'


def lower_percent_triplets(encoded: str) -> str:
    return re.sub(r"%[0-9A-F]{2}", lambda match: match.group(0).lower(), encoded)


class FakeUpstreamTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.fake = FakeUpstream(SECRET).start()
        self.addCleanup(self.fake.stop)

    def request(self, method: str, path: str, headers: dict[str, str] | None = None, body: bytes | None = None,
                fake: FakeUpstream | None = None) -> tuple[int, dict[str, str], bytes]:
        target = fake or self.fake
        conn = http.client.HTTPConnection(target.host, target.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data
        finally:
            conn.close()

    def auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {SECRET}"}

    def test_url_and_recording(self) -> None:
        self.assertTrue(self.fake.url.startswith("http://127.0.0.1:"))
        self.assertEqual(self.fake.host, "127.0.0.1")
        status, headers, body = self.request("GET", "/repos?page=2", {"Authorization": "Bearer wrong", "X-Test": "1"})
        self.assertEqual(status, 401)
        self.assertIn("www-authenticate", headers)
        self.assertEqual(json.loads(body), {"error": "unauthorized"})
        self.assertEqual(len(self.fake.requests), 1)
        seen = self.fake.requests[0]
        self.assertEqual((seen["method"], seen["path"], seen["body"]), ("GET", "/repos?page=2", b""))
        self.assertEqual(seen["headers"]["authorization"], "Bearer wrong")
        self.assertEqual(seen["headers"]["x-test"], "1")
        self.fake.reset()
        self.assertEqual(self.fake.requests, [])

    def test_business_endpoints(self) -> None:
        status, _, body = self.request("GET", "/repos", self.auth())
        self.assertEqual((status, json.loads(body)), (200, [{"name": "demo"}, {"name": "tools"}]))
        status, _, body = self.request("GET", "/me", self.auth())
        self.assertEqual((status, json.loads(body)), (200, {"login": "synthetic-user"}))
        payload = json.dumps({"title": "first"}).encode()
        status, _, body = self.request("POST", "/repos/demo/issues", {**self.auth(), "Content-Type": "application/json"}, payload)
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body), {"number": 1, "title": "first", "repo": "demo"})
        status, _, body = self.request("POST", "/repos/demo/issues", self.auth(), b"not json")
        self.assertEqual(status, 400)
        status, _, body = self.request("DELETE", "/repos/demo", self.auth())
        self.assertEqual((status, body), (204, b""))
        status, _, _ = self.request("GET", "/nope", self.auth())
        self.assertEqual(status, 404)
        status, _, _ = self.request("GET", "/repos")
        self.assertEqual(status, 401)

    def test_leak_endpoints_really_leak(self) -> None:
        status, _, body = self.request("GET", "/echo-headers", {**self.auth(), "X-Extra": "v"})
        self.assertEqual(status, 200)
        echoed = json.loads(body)["headers"]
        self.assertEqual(echoed["Authorization"], f"Bearer {SECRET}")
        status, headers, body = self.request("GET", "/redirect", self.auth())
        self.assertEqual(status, 302)
        self.assertIn(SECRET, headers["location"])
        self.assertIn(SECRET, body.decode())
        status, headers, _ = self.request("GET", "/redirect-external", self.auth())
        self.assertEqual((status, headers["location"]), (302, "http://evil.invalid/"))
        status, _, body = self.request("GET", "/debug/token", self.auth())
        self.assertEqual(json.loads(body), {"token": SECRET})
        status, _, body = self.request("GET", "/base64-leak", self.auth())
        self.assertEqual(json.loads(body)["blob"], base64.b64encode(SECRET.encode()).decode())
        status, headers, _ = self.request("GET", "/set-cookie", self.auth())
        self.assertIn(SECRET, headers["set-cookie"])
        status, _, body = self.request("GET", "/leak?auth=abc", self.auth())
        self.assertEqual(json.loads(body), {"leaked": "abc"})

    def test_urlencoded_leak_emits_both_hex_casings(self) -> None:
        reserved = "synthetic/token+reserved=chars:0123456789"
        fake = FakeUpstream(reserved).start()
        self.addCleanup(fake.stop)
        auth = {"Authorization": f"Bearer {reserved}"}
        status, _, body = self.request("GET", "/urlencoded-leak", auth, fake=fake)
        self.assertEqual((status, json.loads(body)),
                         (200, {"blob": "synthetic%2Ftoken%2Breserved%3Dchars%3A0123456789"}))
        status, _, body = self.request("GET", "/urlencoded-leak?case=lower", auth, fake=fake)
        self.assertEqual((status, json.loads(body)),
                         (200, {"blob": "synthetic%2ftoken%2breserved%3dchars%3a0123456789"}))
        # Without reserved characters the encoding is the credential itself, whichever case is asked for.
        status, _, body = self.request("GET", "/urlencoded-leak?case=lower", self.auth())
        self.assertEqual((status, json.loads(body)), (200, {"blob": SECRET}))

    def test_encoded_leak_emits_every_named_form(self) -> None:
        secret = SECRET_ENCODINGS
        raw = secret.encode("utf-8")
        percent, percent_plus = urllib.parse.quote(secret, safe=""), urllib.parse.quote_plus(secret, safe="")
        expected = {
            "raw": secret,
            "base64": base64.b64encode(raw).decode(),
            "base64-unpadded": base64.b64encode(raw).decode().rstrip("="),
            "base64url": base64.urlsafe_b64encode(raw).decode(),
            "base64url-unpadded": base64.urlsafe_b64encode(raw).decode().rstrip("="),
            "percent-upper": percent,
            "percent-lower": lower_percent_triplets(percent),
            "percent-plus-upper": percent_plus,
            "percent-plus-lower": lower_percent_triplets(percent_plus),
            "hex-lower": raw.hex(),
            "hex-upper": raw.hex().upper(),
            "json": json.dumps(secret),
            "json-unicode": json.dumps(secret, ensure_ascii=False),
            "html": html.escape(secret, quote=True),
        }
        self.assertEqual(set(expected), set(ENCODED_LEAK_FORMS))
        # The chosen secret really separates the casings and alphabets the gateway must tell apart.
        self.assertNotEqual(expected["percent-upper"], expected["percent-lower"])
        # quote() and quote_plus() differ only for spaces, which a bearer token does not contain;
        # the space case (basic passwords) is covered by the gateway's credential_patterns tests.
        self.assertEqual(expected["percent-upper"], expected["percent-plus-upper"])
        self.assertNotEqual(expected["base64"], expected["base64url"])
        self.assertNotEqual(expected["hex-lower"], expected["hex-upper"])
        self.assertNotEqual(expected["json"], '"' + secret + '"')
        self.assertNotEqual(expected["html"], secret)
        for form in ENCODED_LEAK_FORMS:
            if form != "raw":
                self.assertNotIn(secret, expected[form], form)  # a raw-only scan would miss every other form
        fake = FakeUpstream(secret).start()
        self.addCleanup(fake.stop)
        auth = {"Authorization": f"Bearer {secret}"}
        for form in ENCODED_LEAK_FORMS:
            with self.subTest(form=form):
                status, headers, body = self.request("GET", f"/encoded-leak?form={form}", auth, fake=fake)
                self.assertEqual((status, headers["content-type"]), (200, "text/plain"))
                self.assertEqual(body, f"leak=[{expected[form]}]\n".encode("utf-8"))
                self.assertEqual(encoded_credential(fake, form), expected[form])
        for path in ("/encoded-leak", "/encoded-leak?form=nope", "/encoded-leak?form=basic"):
            status, _, body = self.request("GET", path, auth, fake=fake)
            self.assertEqual((status, json.loads(body)), (400, {"error": "unknown_form"}), path)
        self.assertIsNone(encoded_credential(fake, "basic"))
        # basic mode adds base64(user:credential) in both alphabets, padded and not.
        basic = FakeUpstream(secret, mode="basic", basic_username="synthetic-user").start()
        self.addCleanup(basic.stop)
        pair = f"synthetic-user:{secret}".encode("utf-8")
        basic_auth = {"Authorization": "Basic " + base64.b64encode(pair).decode()}
        basic_expected = {
            "basic": base64.b64encode(pair).decode(),
            "basic-unpadded": base64.b64encode(pair).decode().rstrip("="),
            "basic-url": base64.urlsafe_b64encode(pair).decode(),
        }
        self.assertEqual(set(basic_expected), set(BASIC_LEAK_FORMS))
        for form in BASIC_LEAK_FORMS + ("raw", "hex-upper"):
            with self.subTest(form=form):
                status, _, body = self.request("GET", f"/encoded-leak?form={form}", basic_auth, fake=basic)
                value = basic_expected.get(form) or expected[form]
                self.assertEqual((status, body), (200, f"leak=[{value}]\n".encode("utf-8")))

    def test_stream_large_and_slow(self) -> None:
        conn = http.client.HTTPConnection(self.fake.host, self.fake.port, timeout=5)
        try:
            conn.request("GET", "/stream", headers=self.auth())
            resp = conn.getresponse()
            self.assertEqual(resp.getheader("Transfer-Encoding"), "chunked")
            self.assertEqual(resp.read(), b"".join(STREAM_PARTS))
        finally:
            conn.close()
        status, headers, body = self.request("GET", "/large", self.auth())
        self.assertEqual((status, len(body)), (200, LARGE_BODY_SIZE))
        self.assertEqual(headers["content-length"], str(LARGE_BODY_SIZE))
        status, _, body = self.request("GET", "/slow?seconds=0.05", self.auth())
        self.assertEqual((status, json.loads(body)), (200, {"slept": 0.05}))
        status, _, _ = self.request("HEAD", "/huge", self.auth())
        self.assertEqual(status, 200)

    def test_huge_streams_more_than_eight_mib(self) -> None:
        conn = http.client.HTTPConnection(self.fake.host, self.fake.port, timeout=5)
        try:
            conn.request("GET", "/huge", headers=self.auth())
            resp = conn.getresponse()
            self.assertGreater(int(resp.getheader("Content-Length")), 8 * 1024 * 1024)
            self.assertEqual(len(resp.read(1024)), 1024)   # then hang up early on purpose
        finally:
            conn.close()

    def test_basic_and_header_modes(self) -> None:
        basic = FakeUpstream(SECRET, mode="basic", basic_username="synthetic-user").start()
        self.addCleanup(basic.stop)
        pair = base64.b64encode(f"synthetic-user:{SECRET}".encode()).decode()
        status, _, _ = self.request("GET", "/me", {"Authorization": f"Basic {pair}"}, fake=basic)
        self.assertEqual(status, 200)
        status, headers, _ = self.request("GET", "/me", {"Authorization": f"Bearer {SECRET}"}, fake=basic)
        self.assertEqual(status, 401)
        self.assertTrue(headers["www-authenticate"].startswith("Basic "))
        custom = FakeUpstream(SECRET, mode="header", header_name="X-Api-Key", value_prefix="Key ").start()
        self.addCleanup(custom.stop)
        status, _, _ = self.request("GET", "/me", {"X-Api-Key": f"Key {SECRET}"}, fake=custom)
        self.assertEqual(status, 200)
        status, _, _ = self.request("GET", "/me", {"X-Api-Key": SECRET}, fake=custom)
        self.assertEqual(status, 401)
        with self.assertRaises(ValueError):
            FakeUpstream(SECRET, mode="digest")
        with self.assertRaises(ValueError):
            FakeUpstream(SECRET, mode="basic")

    def test_base64_embedded_leak_moves_the_credential_across_alignments(self) -> None:
        whole_groups = len(SECRET) - len(SECRET) % 3
        aligned = base64.b64encode(SECRET[:whole_groups].encode()).decode()
        for alphabet, decode in (("std", base64.b64decode), ("url", base64.urlsafe_b64decode)):
            for offset in range(3):
                for wrap in (0, 60):
                    with self.subTest(alphabet=alphabet, offset=offset, wrap=wrap):
                        status, headers, body = self.request(
                            "GET", f"/base64-embedded-leak?offset={offset}&wrap={wrap}&alphabet={alphabet}", self.auth())
                        self.assertEqual((status, headers["content-type"]), (200, "application/json"))
                        content = json.loads(body)["content"]
                        self.assertEqual("\n" in content, wrap > 0)
                        self.assertIn(SECRET.encode(), decode(content.replace("\n", "")))
                        self.assertNotIn(SECRET, body.decode())
        # The reflection is real at every alignment, but the credential's own base64
        # (its whole 3-byte groups) appears only when it starts on a group boundary.
        for offset in range(3):
            status, _, body = self.request("GET", f"/base64-embedded-leak?offset={offset}", self.auth())
            self.assertEqual(aligned in json.loads(body)["content"], offset == 0, offset)
        status, _, body = self.request("GET", "/base64-embedded-leak?offset=x", self.auth())
        self.assertEqual((status, json.loads(body)), (400, {"error": "invalid_query"}))
        status, _, _ = self.request("GET", "/base64-embedded-leak?offset=1")
        self.assertEqual(status, 401)

    def test_stop_is_idempotent_and_context_manager(self) -> None:
        with FakeUpstream(SECRET) as other:
            status, _, _ = self.request("GET", "/me", self.auth(), fake=other)
            self.assertEqual(status, 200)
        other.stop()
        with self.assertRaises(RuntimeError):
            _ = other.port


if __name__ == "__main__":
    unittest.main()
