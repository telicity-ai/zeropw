"""Thin JSON command-line client for the ZeroPW tools API.

Usage::

    python3.12 -m zeropw.agent_cli list-connections
    python3.12 -m zeropw.agent_cli request --connection C --method M --path P
                                   [--body-file F | --body TEXT] [--header 'K: V' ...] [--request-id ID]
    python3.12 -m zeropw.agent_cli exec --connection C [--request-id ID] -- ARGS...
    python3.12 -m zeropw.agent_cli status --run ID
    python3.12 -m zeropw.agent_cli cancel --run ID

Environment: ``ZEROPW_GATEWAY_URL`` (the trusted server) and
``ZEROPW_CALLER_TOKEN`` (the agent's own identity token, ``zpwc_...``).

Security scope: this client runs in the agent's environment and therefore
holds nothing but the caller token, which identifies the agent and is not a
vault value.  It only talks to the URL given in the environment, never
follows redirects, never prints the token, and prints exactly the JSON the
server returned (stdout on success, stderr with exit status 1 on error).  For
``request`` a relay that the gateway refused, blocked, could not complete or
does not support (a non-null ``reason``, e.g. ``credential_header_unsafe`` or
``method_not_allowed``) is an error too: stderr, exit status 1.  A response
relayed from the upstream (``reason`` null) is a success whatever its HTTP
status.  It cannot reveal a secret because no tool returns one.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Sequence

ENV_URL = "ZEROPW_GATEWAY_URL"
ENV_TOKEN = "ZEROPW_CALLER_TOKEN"
TIMEOUT_SECONDS = 120.0
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
TOOL_BY_COMMAND = {
    "list-connections": "list_connections",
    "request": "request",
    "exec": "exec",
    "status": "status",
    "cancel": "cancel",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:  # type: ignore[override]
        return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zeropw-agent", description="ZeroPW agent tools client (JSON output)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list-connections", help="connections usable by this caller")

    req = sub.add_parser("request", help="relay one HTTP request through the gateway")
    req.add_argument("--connection", required=True)
    req.add_argument("--method", required=True)
    req.add_argument("--path", required=True)
    body = req.add_mutually_exclusive_group()
    body.add_argument("--body-file", help="file whose bytes form the request body")
    body.add_argument("--body", help="request body text (UTF-8)")
    req.add_argument("--header", action="append", default=[], metavar="'K: V'")
    req.add_argument("--request-id")

    run = sub.add_parser("exec", help="run the connection's supported CLI; arguments follow '--'")
    run.add_argument("--connection", required=True)
    run.add_argument("--request-id")

    st = sub.add_parser("status", help="state and captured output of one of your runs")
    st.add_argument("--run", required=True)

    ca = sub.add_parser("cancel", help="cancel one of your runs")
    ca.add_argument("--run", required=True)
    return parser


def _split_exec_args(argv: Sequence[str]) -> tuple[list[str], list[str]]:
    """Everything after the first ``--`` is passed verbatim as the CLI's arguments."""
    argv = list(argv)
    if "--" in argv:
        index = argv.index("--")
        return argv[:index], argv[index + 1:]
    return argv, []


def _parse_header(text: str) -> tuple[str, str]:
    name, sep, value = text.partition(":")
    if not sep or not name.strip():
        raise ValueError("header must be 'Name: value'")
    return name.strip(), value.strip()


def build_payload(args: argparse.Namespace, extra_argv: list[str]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if args.command == "request":
        payload = {"connection": args.connection, "method": args.method.upper(), "path": args.path}
        headers: dict[str, str] = {}
        for item in args.header:
            name, value = _parse_header(item)
            headers[name] = value
        if headers:
            payload["headers"] = headers
        if args.body_file is not None:
            with open(args.body_file, "rb") as stream:
                raw = stream.read()
            try:
                payload["body"] = raw.decode("utf-8")
            except UnicodeDecodeError:
                import base64

                payload["body_base64"] = base64.b64encode(raw).decode("ascii")
        elif args.body is not None:
            payload["body"] = args.body
        if args.request_id:
            payload["request_id"] = args.request_id
    elif args.command == "exec":
        payload = {"connection": args.connection, "argv": extra_argv}
        if args.request_id:
            payload["request_id"] = args.request_id
    elif args.command in ("status", "cancel"):
        payload = {"run_id": args.run}
    return payload


def call_tool(base_url: str, token: str, tool: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    url = f"{base_url.rstrip('/')}/v1/tools/{tool}"
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST", headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            status = int(response.status)
            raw = response.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        raw = exc.read(MAX_RESPONSE_BYTES)
    except urllib.error.URLError as exc:
        return 0, {"error": "ConnectionError", "reason": "gateway_unreachable", "detail": str(exc.reason)[:200]}
    except (OSError, ValueError) as exc:
        return 0, {"error": "ConnectionError", "reason": "gateway_unreachable", "detail": type(exc).__name__}
    try:
        body = json.loads(raw.decode("utf-8"))
        if not isinstance(body, dict):
            body = {"error": "ProtocolError", "reason": "non_object_response", "status": status}
    except (ValueError, UnicodeDecodeError):
        body = {"error": "ProtocolError", "reason": "non_json_response", "status": status}
    return status, body


def _emit(payload: dict[str, Any], stream: Any) -> None:
    stream.write(json.dumps(payload, sort_keys=True, indent=2) + "\n")
    stream.flush()


def main(argv: Sequence[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    extra_argv: list[str] = []
    if raw_argv and raw_argv[0] == "exec":
        raw_argv, extra_argv = _split_exec_args(raw_argv)
    parser = build_parser()
    args = parser.parse_args(raw_argv)

    base_url = os.environ.get(ENV_URL, "").strip()
    token = os.environ.get(ENV_TOKEN, "").strip()
    if not base_url:
        _emit({"error": "ConfigError", "reason": "gateway_url_unset", "detail": f"set {ENV_URL}"}, sys.stderr)
        return 1
    scheme = urllib.parse.urlsplit(base_url).scheme
    if scheme not in ("http", "https"):
        _emit({"error": "ConfigError", "reason": "gateway_url_invalid"}, sys.stderr)
        return 1
    if not token:
        _emit({"error": "ConfigError", "reason": "caller_token_unset", "detail": f"set {ENV_TOKEN}"}, sys.stderr)
        return 1
    try:
        payload = build_payload(args, extra_argv)
    except (OSError, ValueError) as exc:
        _emit({"error": "InvalidInput", "reason": "invalid_arguments", "detail": type(exc).__name__}, sys.stderr)
        return 1
    status, body = call_tool(base_url, token, TOOL_BY_COMMAND[args.command], payload)
    if status == 200:
        if args.command == "request" and body.get("reason") is not None:
            _emit(body, sys.stderr)  # refused/blocked/unsupported relay: never reported as success
            return 1
        _emit(body, sys.stdout)
        return 0
    if "status" not in body and status:
        body = {**body, "status": status}
    _emit(body, sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
