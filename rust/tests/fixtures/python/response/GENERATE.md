# Response fixtures generated from the Python prototype

Generated once on 2026-10-03 from the Python prototype (`zeropw/`, `tests/`)
at commit 942a963 with CPython 3.12.14 in the Linux parity VM. They are the
expected values of the response, intrusion-detector, notification and SMTP
tests in `rust/src/smtp.rs` and `rust/tests/{response_contract,
response_parity_gaps,astra_response_*}.rs`. All addresses, passwords and
incidents are synthetic.

| File | Content | Source |
| --- | --- | --- |
| `denial_rules.json` | every `(event, result, reason)` that `intrusion._match_denial_rule` matched, with rule and strength (all other combinations of the listed values matched nothing) | `gen.py rules` |
| `scope_emails.json` | `[incident.to_dict(), render_incident_email(...)]` for the principal, runtime and all scopes (`tests.test_notify.NotifyTestCase.build_incident`) | `gen.py scope_emails` |
| `incident_emails.json` | two loaded incident documents and their rendered email (`now=2023-11-14T22:13:21Z`) | Python oracle in `response_parity_gaps.rs` at 942a963 |
| `smtp_messages.json` | flattened messages (`EmailMessage` + `BytesGenerator(linesep="\r\n")`, `utf8` policy for internationalized envelopes; `null` = CPython 3.12.14 `HeaderWriteError`) for the 45 fixed header cases, 9 well-formed RFC 2047 cases (5 malformed encoded-word cases dropped), 11 group/domain-literal cases with their `getaddresses` envelopes, 13 bodies around the transfer-encoding thresholds, and 30 representative cases (8 refused, 11 internationalized, 11 ASCII) of the former 400-case pseudo-random corpus | Python oracles in `rust/src/smtp.rs` at 942a963 |
| `smtp_sessions.json` | per scripted-server scenario: `send_test_message` outcome, new audit records and the exact client transcript (EHLO argument masked) | Python oracle in `response_parity_gaps.rs` at 942a963 |
| `envelope_comments.json` | `quoteaddr` envelope mailbox for a comment at every position of representative addresses (`quoteaddr`); `MAIL FROM`/`RCPT TO` arguments sent for configured comment forms (`transport`, `interior`) | `smtp.rs` oracle at 942a963; `gen.py envelopes` |

The rows marked "Python oracle in ... at 942a963" were recorded by running
those tests once with each Python result printed as JSON (the Python code is
the `crate::oracle::python(...)`/`python3.12` snippet in that test at commit
942a963); the selection and conversion to these files was:

```
cargo test --offline --lib smtp:: -- --nocapture --test-threads=1   # prints EXPECT <name> <json>
cargo test --offline --test response_parity_gaps --test astra_response_review \
  --test astra_response_round2 --test astra_response_round3 -- --nocapture --test-threads=1
```

The other expected values written directly into `astra_response_review.rs`,
`astra_response_round2.rs`, `astra_response_round3.rs` and
`response_parity_gaps.rs` (SMTP outcome names, incident defaults,
assessments, detector reasons) came from the same runs.

`gen.py` (run from the repository root inside the VM:
`PYTHONPATH=$PWD python3.12 gen.py > out.json`; `admin_helpers` and
`detector_single` fed the explicit expectations in `rust/src/admin_cli.rs`
and `response_parity_gaps.rs`):

```python
"""One-off generator for rust/tests/fixtures/python/response (run once in the VM)."""
import json, pathlib, socket, sys, tempfile, threading


def rules():
    from zeropw.intrusion import _match_denial_rule
    events = ["tools_unknown", "http_relay", "ssh_agent_refused", "ssh_bind", "ssh_sign", "run_finish",
              "tools_request", "tools_exec", "tools_status", "unmatched"]
    results = ["ok", "denied", "blocked", "cancelled", ""]
    reasons = ["tool_not_found", "handle_signature", "handle_malformed", "handle_version", "handle_expired",
               "unsupported_agent_message", "unsupported_extension", "agent_forwarding_not_allowed",
               "not_userauth_request", "no_session_bind", "unsupported_sign_flags", "output_credential_blocked",
               "grant_revoked", "grant_stale", "principal_disabled", "method_not_allowed", "path_not_allowed",
               "approval_required", "no_grant", "grant_unknown", "connection_unknown", "global_stop",
               "restore_pending", "cancelled_by_caller", ""]
    out = {"events": events, "results": results, "reasons": reasons, "matches": []}
    for e in events:
        for r in results:
            for why in reasons:
                m = _match_denial_rule(e, r, why)
                if m is not None:
                    out["matches"].append([e, r, why, m[0], m[1]])
    return out


def scope_emails():
    from tests.test_notify import NotifyTestCase
    from zeropw.notify import render_incident_email
    out = []
    for scope in ("principal", "runtime", "all"):
        case = NotifyTestCase(); case.setUp()
        try:
            i = case.build_incident(scope=scope, incident_runtime="default" if scope == "runtime" else None)
            out.append([i.to_dict(), render_incident_email(i, now="2026-09-16T00:00:00Z")])
        finally:
            case.doCleanups()
    return out


def detector_single():
    from zeropw.errors import InvalidInput
    from zeropw.intrusion import DetectorConfig
    invalid = [("strong_thresholds", {"unknown_tool": "2"}), ("strong_thresholds", {"signer_misuse": 0}),
               ("weak_points", {"burst": 1.5}), ("weak_points", {"revoked_use": -1}), ("window_seconds", "120"),
               ("window_seconds", True), ("window_seconds", 0), ("weak_threshold", 2.0), ("weak_threshold", 0),
               ("enumeration_min", None), ("enumeration_min", 0), ("enumeration_ratio", [0.5]),
               ("enumeration_ratio", 1.5), ("burst_count", "60"), ("burst_count", -3)]
    out = []
    for key, value in invalid:
        try:
            DetectorConfig.from_mapping({key: value})
            out.append([key, value, None])
        except InvalidInput as e:
            out.append([key, value, e.reason])
    return out


def admin_helpers():
    import argparse
    from zeropw import admin_cli as A

    def run(fn, text):
        try:
            value = fn(text)
        except A.ZeroPWError as exc:
            return ["error", exc.reason, exc.detail]
        except argparse.ArgumentTypeError as exc:
            return ["type_error", str(exc)]
        return ["ok", list(value) if isinstance(value, tuple) else str(value)]
    ttl = ["1h", " 3M ", "30m", "2d", "86400", "0", "1w", "1.5h"]
    listen = ["127.0.0.1:80", " [::1]:65535 ", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:", "127.0.0.1",
              "0.0.0.0:80"]
    limit = ["50", " 7 ", "0", "-1", "x"]
    paths = {}
    import os, pwd
    user = pwd.getpwuid(os.getuid()).pw_name
    for p in ["~" + user, "~" + user + "//nested/./path/", "relative//nested/./path/", "/absolute//nested/./path/"]:
        paths[p] = str(pathlib.Path(p).expanduser())
    return {"ttl": [[t, run(A._parse_ttl, t)] for t in ttl],
            "listen": [[t, run(A._parse_listen, t)] for t in listen],
            "limit": [[t, run(A._positive_int, t)] for t in limit],
            "paths": paths, "home": os.path.expanduser("~" + user)}


def receiver(enforce=False):
    listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(1)
    port = listener.getsockname()[1]; commands = []

    def serve():
        with listener:
            wire, _ = listener.accept()
            with wire:
                wire.settimeout(3); reader = wire.makefile("rb"); wire.sendall(b"220 synthetic ready\r\n")
                while True:
                    line = reader.readline()
                    if not line:
                        break
                    commands.append(line.decode("utf-8").strip()); upper = line.upper()
                    if upper.startswith(b"EHLO"):
                        reply = b"250 synthetic\r\n"
                    elif enforce and upper.startswith(b"MAIL") and not upper.startswith(b"MAIL FROM:<SENDER@EXAMPLE.COM>"):
                        reply = b"501 invalid sender\r\n"
                    elif enforce and upper.startswith(b"RCPT") and not upper.startswith(b"RCPT TO:<RECIPIENT@EXAMPLE.COM>"):
                        reply = b"501 invalid recipient\r\n"
                    elif upper.startswith(b"DATA"):
                        wire.sendall(b"354 data\r\n")
                        while reader.readline() != b".\r\n":
                            pass
                        reply = b"250 accepted\r\n"
                    elif upper.startswith(b"QUIT"):
                        wire.sendall(b"221 bye\r\n"); break
                    else:
                        reply = b"250 ok\r\n"
                    wire.sendall(reply)
    thread = threading.Thread(target=serve, daemon=True); thread.start()
    return port, thread, commands


def envelopes():
    from zeropw.context import Context
    from zeropw.notify import send_test_message
    tmp = tempfile.mkdtemp()
    ctx = Context.initialize(pathlib.Path(tmp) / "state", "synthetic-admin", "synthetic-recovery")
    addresses = ["sender@(nested(inner)).com", "sender@(nested(inner))", "sender@exa.(nested(inner)).com",
                 "sender@exa.(nested(inner))", "sen(comment)der@example.com", '"lo cal"@(comment)example.com',
                 '"lo\\\\(cal"@(comment)example.com', "Display <sender@(comment)example.com>",
                 "sender(comment).foo@example.com", "sender.(comment)foo@example.com", "sender@exa(comment).com",
                 "sender@exa.(comment)com", "sender(comment)@example.com", "sender@(comment)example.com",
                 "sender@exa(comment)mple.com"]
    pairs = [(a, "recipient@example.com") for a in addresses] + [("sender@example.com", a) for a in addresses]
    pairs += [("sender@example.com", "recipient@exa(comment)mple.com"),
              ("sender@(comment)example.com", "recipient@(comment)example.com")]
    out = []
    for sender, recipient in pairs:
        port, thread, commands = receiver()
        ctx.state.write_json("notify.json", {"host": "127.0.0.1", "port": port, "mode": "plain", "sender": sender,
                                             "recipients": [recipient], "timeout_seconds": 1})
        result = send_test_message(ctx)
        thread.join(4)
        env = [c.split(":", 1)[1] for c in commands if c.upper().startswith(("MAIL", "RCPT"))]
        out.append({"sender": sender, "recipient": recipient, "result": result, "envelope": env})
    interior = []
    for sender, recipient in [("sender(Internal)@example.com", "recipient@example.com"),
                              ("sender@(Internal)example.com", "recipient@example.com"),
                              ("sender@example.com", "recipient(Internal)@example.com"),
                              ("sender@example.com", "recipient@(Internal)example.com"),
                              ("(Nested (inner)) sender@example.com", "recipient@example.com"),
                              ("sender@example.com(Nested (inner))", "recipient@example.com")]:
        port, thread, commands = receiver(True)
        ctx.state.write_json("notify.json", {"host": "127.0.0.1", "port": port, "mode": "plain", "sender": sender,
                                             "recipients": [recipient], "timeout_seconds": 1})
        result = send_test_message(ctx)
        thread.join(4)
        interior.append({"sender": sender, "recipient": recipient, "result": result})
    return {"envelopes": out, "interior": interior}


which = sys.argv[1:] or ["rules", "scope_emails", "detector_single", "admin_helpers", "envelopes"]
print(json.dumps({name: globals()[name]() for name in which}, ensure_ascii=False))
```
