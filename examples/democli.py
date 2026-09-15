#!/usr/bin/env python3
"""democli: a sample "supported CLI" for the ZeroPW prototype.

This program stands in for a service CLI that ZeroPW can drive.  It is run by
the ``exec`` tool inside a secret-free environment and demonstrates the only
things such a CLI needs:

* It reads its API base URL from ``ZEROPW_API_BASE_URL`` (a non-secret
  setting; the URL contains an opaque, short-lived handle that the gateway
  maps to a connection and re-checks against policy on every request).
* It sends a fixed placeholder ``Authorization: Bearer democli-placeholder``
  on every request.  The gateway strips it and injects the real credential
  towards the fixed upstream, which proves the CLI never needs the value.
* It never follows redirects, so a redirecting upstream cannot pull the
  request (or its headers) somewhere else.

Sub-commands: ``list-repos``, ``create-issue <repo> <title>``, ``whoami`` and
``steal``.  ``steal`` is the adversarial demo: it lists every environment
variable name, its own arguments, its home directory and the usual credential
file locations, and shows that nothing but the opaque base URL is present.
It never prints the base URL itself (the handle inside it is a bearer
capability; ZeroPW blocks output that contains it).

Security scope: this file runs in the agent's trust domain.  It is not a
trusted component and holds no secrets; it is intentionally compatible with
any Python 3 so it can be executed via ``/usr/bin/env python3``.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

PLACEHOLDER = "Bearer democli-placeholder"
BASE_URL_ENV = "ZEROPW_API_BASE_URL"
MAX_BODY = 1024 * 1024
TIMEOUT = 30.0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def base_url() -> str:
    value = os.environ.get(BASE_URL_ENV, "").strip()
    if not value:
        raise SystemExit(_fail("base_url_unset", "set %s to the ZeroPW base URL" % BASE_URL_ENV, 2))
    return value.rstrip("/")


def _fail(reason: str, detail: str = "", code: int = 1) -> int:
    payload = {"error": reason}
    if detail:
        payload["detail"] = detail
    print(json.dumps(payload, sort_keys=True))
    return code


def call(method: str, path: str, body=None) -> int:
    """Send one request; print ``{"status", "body"}``; return the process exit status."""
    url = base_url() + path
    data = None
    headers = {"Authorization": PLACEHOLDER, "Accept": "application/json", "User-Agent": "democli/1"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            status = int(response.status)
            raw = response.read(MAX_BODY)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        raw = exc.read(MAX_BODY)
    except urllib.error.URLError as exc:
        return _fail("unreachable", str(exc.reason)[:200])
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        parsed = raw.decode("utf-8", "replace")
    print(json.dumps({"status": status, "body": parsed}, sort_keys=True))
    return 0 if 200 <= status < 300 else 1


def cmd_list_repos() -> int:
    return call("GET", "/repos")


def cmd_create_issue(repo: str, title: str) -> int:
    if not repo or "/" in repo or ".." in repo:
        return _fail("invalid_repo")
    return call("POST", "/repos/%s/issues" % repo, {"title": title})


def cmd_whoami() -> int:
    return call("GET", "/me")


def _probe(path: str) -> str:
    try:
        with open(path, "rb") as stream:
            data = stream.read(4096)
    except FileNotFoundError:
        return "missing"
    except IsADirectoryError:
        return "directory"
    except OSError as exc:
        return "unreadable (%s)" % type(exc).__name__
    return "present (%d bytes read, not shown)" % len(data)


def cmd_steal() -> int:
    """Try every place a credential could be and show there is nothing to take."""
    home = os.environ.get("HOME", "")
    raw_base = os.environ.get(BASE_URL_ENV, "")
    origin, sep, _rest = raw_base.partition("/h/")
    report = {
        "env_names": sorted(os.environ),
        "argv": sys.argv[1:],
        "base_url": (origin + "/h/<opaque-handle-redacted>") if sep else ("<unset>" if not raw_base else "<opaque>"),
        "home": home,
        "home_entries": sorted(os.listdir(home)) if home and os.path.isdir(home) else [],
        "probes": {},
        "conclusion": "no credential in environment, arguments, home directory or credential files; "
                      "only an opaque base URL that the gateway re-checks against policy",
    }
    for candidate in (".zeropw", ".zeropw.json", ".netrc", ".ssh/id_ed25519", ".ssh/id_rsa", ".config/zeropw",
                      ".aws/credentials", ".git-credentials"):
        report["probes"][candidate] = _probe(os.path.join(home, candidate)) if home else "no home"
    print(json.dumps(report, sort_keys=True))
    return 0


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        return _fail("usage", "democli list-repos | create-issue <repo> <title> | whoami | steal", 2)
    command, rest = args[0], args[1:]
    if command == "list-repos":
        return cmd_list_repos()
    if command == "create-issue":
        if len(rest) != 2:
            return _fail("usage", "create-issue <repo> <title>", 2)
        return cmd_create_issue(rest[0], rest[1])
    if command == "whoami":
        return cmd_whoami()
    if command == "steal":
        return cmd_steal()
    return _fail("unknown_command", command[:64], 2)


if __name__ == "__main__":
    sys.exit(main())
