#!/usr/bin/env python3
"""Real ZeroPW CLI -> real daemon -> ICE/QUIC/coturn -> real peer CLI.

Linux VM fixture only. Every value is synthetic. Captured secret-reveal output
stays in this test's memory; failures print operation labels and reason codes.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import pwd
import signal
import subprocess
import time


WORK = Path(os.environ["ZPE_WORK"])
PREFIX = os.environ["ZPE_PREFIX"]
USER = os.environ["ZPE_USER"]
BIN = WORK / "bin"
ADMIN = BIN / "zeropw-admin"
PASS = "synthetic-e2e-admin-passphrase-47"
RECOVERY = "synthetic-e2e-recovery-passphrase-81"
VALUES: list[bytes] = [PASS.encode(), RECOVERY.encode()]
PROCESSES: dict[str, subprocess.Popen] = {}
FILES = []
ASSERTIONS = []
ENVIRONMENT = "demo/dev"
SERVICE = "https://link.zpl.test"


def check(name: str, condition: bool, detail: str = "") -> None:
    result = "PASS" if condition else "FAIL"
    print(f"{result} {name}" + (f": {detail}" if detail else ""), flush=True)
    ASSERTIONS.append({"name": name, "result": result, "detail": detail})
    (WORK / "assertions.json").write_text(json.dumps(ASSERTIONS, indent=2) + "\n")
    if not condition:
        raise AssertionError(name)


def wait_for(label, predicate, timeout=55):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(0.3)
    raise AssertionError(f"timeout: {label}; last={last!r}")


def ns_command(node: str, args, *, unprivileged=True):
    network_node = "a" if node == "c" else node
    command = ["ip", "netns", "exec", f"{PREFIX}-p{network_node}"]
    if unprivileged:
        command += ["setpriv", f"--reuid={USER}", f"--regid={USER}", "--init-groups", "--"]
    return command + list(map(str, args))


def call(node, args, *, data=b"", authenticate=False, allow_error=False):
    environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(WORK / f"home-{node}")}
    if authenticate:
        environment.update(ZEROPW_ADMIN_PASSPHRASE=PASS, ZEROPW_RECOVERY_PASSPHRASE=RECOVERY)
    result = subprocess.run(ns_command(node, args), input=data, capture_output=True,
                            env=environment, timeout=90, check=False)
    # Never include argv (could contain an invite) or raw output in exceptions.
    # zeropw-link prints daemon failure JSON to stdout with exit 1;
    # zeropw-admin prints its failure JSON to stderr. Accept either explicit
    # JSON envelope, retaining the actual exit code as a separate assertion.
    decoded = None
    for candidate in (result.stdout, result.stderr):
        try:
            text = candidate.decode().strip()
            decoded = json.loads(text)
            break
        except ValueError:
            try:
                decoded = json.loads(text.splitlines()[-1])
                break
            except (ValueError, IndexError):
                continue
    if not isinstance(decoded, dict):
        raise AssertionError(f"non-JSON CLI result, exit={result.returncode}") from None
    if result.returncode and not allow_error:
        raise AssertionError(f"CLI {Path(args[0]).name}: exit={result.returncode} reason={decoded.get('reason', decoded.get('error'))}")
    allowed_stdout = "reveal" in args or any(x in args for x in ("invite", "link-token"))
    for value in VALUES:
        check_no_value(result.stderr, value, "CLI stderr")
        if not allowed_stdout:
            check_no_value(result.stdout, value, "CLI stdout")
    return decoded


def admin(node, *args, data=b"", allow_error=False):
    return call(node, [ADMIN, "--state-dir", WORK / f"home-{node}" / "state", *args],
                data=data, authenticate=True, allow_error=allow_error)


def link(node, *args, data=b"", allow_error=False):
    return call(node, [BIN / "zeropw-link", *args, "--state", WORK / node],
                data=data, allow_error=allow_error)


def spawn(key, command, *, environment=None):
    stop(key)
    path = WORK / "run" / f"{key}.out"
    offset = path.stat().st_size if path.exists() else 0
    log = open(path, "ab", buffering=0)
    FILES.append(log)
    PROCESSES[key] = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                     stdout=log, stderr=log,
                                     env=environment or {"PATH": "/usr/bin:/bin"})
    return offset


def stop(key):
    proc = PROCESSES.pop(key, None)
    if proc is not None:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)


def daemon(node, flags=(), *, enrolled=True):
    spawn(f"daemon-{node}", ns_command(node, [BIN / "zeropw-link", "daemon", "--state", WORK / node,
          "--service-ca", WORK / "pki/ca.pem", "--log-file", WORK / "run" / f"daemon-{node}.log", *flags]))
    wait_for(f"daemon {node} socket", lambda: (WORK / node / "link.sock").is_socket(), timeout=15)
    if enrolled:
        wait_for(f"daemon {node} online", lambda: link(node, "status").get("online"), timeout=30)


def serve(node):
    offset = spawn(f"serve-{node}", ns_command(node, [ADMIN, "--state-dir", WORK / f"home-{node}" / "state",
          "serve", "--listen", "127.0.0.1:0", "--link-socket", WORK / node / "link.sock", "--quiet"]))
    wait_for(f"serve {node}", lambda: PROCESSES[f"serve-{node}"].poll() is None and
             b'"link_socket"' in (WORK / "run" / f"serve-{node}.out").read_bytes()[offset:], timeout=15)


def switch(flags=()):
    for node in "ab":
        stop(f"serve-{node}")
        stop(f"daemon-{node}")
    for node in "ab":
        daemon(node, flags)
    for node in "ab":
        serve(node)


def vector(node):
    return admin(node, "team", "status", "--env", ENVIRONMENT)["vector"]


def synced():
    left, right = vector("a"), vector("b")
    sessions = [admin(node, "team", "sync-status", "--env", ENVIRONMENT)["peers"] for node in "ab"]
    connected = all(any(peer.get("session") for peer in peers) for peers in sessions)
    return left if left == right and connected else None


def converged(label):
    result = wait_for(label, synced, timeout=100)
    check(label, True, f"{sum(result.values())} durably stored commits")
    return result


def put(node, name, value, kind="api_key"):
    raw = value.encode()
    VALUES.append(raw)
    return admin(node, "secret", "put", "--id", name, "--kind", kind,
                 "--project", "demo", "--environment", "dev", "--stdin", data=raw)


def reveal(node, name, version=None):
    args = ["secret", "reveal", "--id", name]
    if version is not None:
        args += ["--version", str(version)]
    return admin(node, *args)["value"]


def operator_invite():
    result = subprocess.run(["ip", "netns", "exec", f"{PREFIX}-srv", str(BIN / "zeropw-linkd"),
        "invite", "create", "--db", str(WORK / "linkd/linkd.db"), "--pepper-file", str(WORK / "linkd/pepper"),
        "--uses", "1", "--ttl", "1m"], capture_output=True, check=True, timeout=10)
    invitation = json.loads(result.stdout)
    VALUES.append(invitation["invite_code"].encode())
    return invitation


def enrollment_boundaries(expiring, invitation):
    account = pwd.getpwnam(USER)
    for directory in (WORK / "c", WORK / "home-c"):
        directory.mkdir(mode=0o700)
        os.chown(directory, account.pw_uid, account.pw_gid)
    daemon("c", enrolled=False)
    fixture_path = WORK / "enrollment-fixture.json"
    consumed = json.loads(fixture_path.read_text())
    fixture_path.unlink()
    for field, want in (("invite_code", "invite_invalid"), ("link_token", "link_token_invalid")):
        VALUES.append(consumed[field].encode())
        failed = link("c", "enroll", data=json.dumps({"service": SERVICE, "name": "Mac C", field: consumed[field]}).encode(), allow_error=True)
        check(f"server-{field}-reuse-refused", failed.get("error") == want, str(failed.get("error")))
    remaining = max(0.0, expiring["expires_at"] + 1 - time.time())
    if remaining:
        print(f"WAIT real invite expiry: {remaining:.1f}s", flush=True)
        time.sleep(min(remaining, 62))
    failed = link("c", "enroll", data=json.dumps({"service": SERVICE, "name": "Mac C", "invite_code": expiring["invite_code"]}).encode(), allow_error=True)
    check("server-invite-real-expiry", failed.get("error") == "invite_invalid", str(failed.get("error")))
    token = link("a", "link-token")["link_token"]
    VALUES.append(token.encode())
    link("c", "enroll", data=json.dumps({"service": SERVICE, "name": "Mac C", "link_token": token}).encode())
    wait_for("C enrolled online", lambda: link("c", "status").get("online"))
    admin("c", "init")
    refused = admin("c", "team", "join", "--stdin", "--link-socket", str(WORK / "c/link.sock"),
                    "--project", "demo", "--environment", "dev", data=invitation.encode(), allow_error=True)
    check("service-enrollment-not-vault-membership", bool(refused.get("reason")) and "self_fingerprint" not in refused,
          str(refused.get("reason")))
    empty = admin("c", "secret", "list")["secrets"]
    check("unauthorized-device-has-no-secrets", empty == [])
    stop("daemon-c")


def malformed_requests():
    helper = ("import socket,sys; s=socket.socket(socket.AF_UNIX); s.settimeout(5); "
              "s.connect(sys.argv[1]); s.sendall(sys.stdin.buffer.read()); "
              "sys.stdout.buffer.write(s.recv(8192))")
    marker = b"synthetic-error-reflection-marker-3729"
    cases = [("invalid-json", b"{" + marker + b"}\n"),
             ("duplicate-key", b'{"op":"status","op":"status"}\n'),
             ("unknown-field", b'{"op":"status","extra":"' + marker + b'"}\n')]
    for name, payload in cases:
        response = subprocess.run(["setpriv", f"--reuid={USER}", f"--regid={USER}", "--init-groups", "--",
                    "python3", "-c", helper, str(WORK / "a/link.sock")], input=payload, capture_output=True,
                    timeout=8, check=True)
        decoded = json.loads(response.stdout)
        check(f"malformed-{name}-refused", decoded.get("ok") is False and decoded.get("error") == "invalid_request")
        check(f"malformed-{name}-not-reflected", marker not in response.stdout + response.stderr)


def check_no_value(raw, value, label):
    for encoded in (value, base64.b64encode(value), value.hex().encode()):
        if encoded in raw:
            raise AssertionError(f"synthetic vault value escaped into {label}")


def process_boundary_scan(label):
    """Sample only our synthetic daemon processes, never arbitrary processes."""
    scanned = 0
    for node in "ab":
        pid = PROCESSES[f"daemon-{node}"].pid
        proc = Path(f"/proc/{pid}")
        check(f"{label}-owned-process-{node}", (proc / "exe").resolve() == BIN / "zeropw-link")
        for name in ("environ", "cmdline"):
            raw = (proc / name).read_bytes()
            for value in VALUES:
                check_no_value(raw, value, f"daemon {name}")
        # Bounded chunks avoid retaining a heap copy in the test process. Read
        # writable readable mappings only; this is a point-in-time observation.
        with open(proc / "mem", "rb", buffering=0) as memory:
            for mapping in (proc / "maps").read_text().splitlines():
                address, permissions, *_ = mapping.split()
                if not permissions.startswith("rw"):
                    continue
                start, end = (int(x, 16) for x in address.split("-"))
                position = start
                overlap = b""
                while position < end:
                    try:
                        memory.seek(position)
                        chunk = memory.read(min(end - position, 1024 * 1024))
                    except OSError:
                        break
                    if not chunk:
                        break
                    scanned += len(chunk)
                    for value in VALUES:
                        check_no_value(overlap + chunk, value, "sampled daemon memory")
                    overlap = chunk[-4096:]
                    position += len(chunk)
    check(f"{label}-daemon-memory-environment-argv", scanned > 0, f"{scanned} writable mapped bytes sampled")


def path_is(want):
    labels = []
    for node in "ab":
        labels += [peer.get("path") for peer in link(node, "status").get("peers", [])]
    return want in labels


def blocked_udp(enable):
    operation = "-A" if enable else "-D"
    rules = [["OUTPUT", "-o", "lo", "-j", "ACCEPT"],
             ["OUTPUT", "-p", "udp", "-j", "DROP"], ["INPUT", "-p", "udp", "-j", "DROP"],
             ["OUTPUT", "-p", "tcp", "-d", "198.51.100.10", "-j", "ACCEPT"],
             ["OUTPUT", "-p", "tcp", "-j", "DROP"]]
    for node in "ab":
        for rule in rules:
            subprocess.run(ns_command(node, ["iptables", operation, *rule], unprivileged=False), check=True)


def initial_pairing():
    for node in "ab":
        home = WORK / f"home-{node}"
        home.mkdir()
        account = pwd.getpwnam(USER)
        os.chown(home, account.pw_uid, account.pw_gid)
        admin(node, "init")
    admin("a", "project", "create", "demo")
    put("a", "login", "synthetic-login-zero-7462", "env_var")
    put("a", "password", "synthetic-password-zero-3085", "password")
    put("a", "api", "synthetic-api-zero-5293")
    shared = admin("a", "team", "share", "--project", "demo", "--environment", "dev", "--name", "Mac A")
    check("shared-environment", bool(shared.get("env_id")))
    for node in "ab":
        daemon(node)
    serve("a")
    a_id = link("a", "status")["device_id"]
    invitation = admin("a", "team", "invite", "--env", ENVIRONMENT, "--role", "admin",
                       "--name", "Mac B", "--address", f"zpl:{a_id}", "--approval")["invite"]
    VALUES.append(invitation.encode())
    join_args = ["team", "join", "--stdin", "--link-socket", str(WORK / "b/link.sock"),
                 "--project", "demo", "--environment", "dev"]
    pending = admin("b", *join_args, data=invitation.encode(), allow_error=True)
    check("approval-required", pending.get("reason") == "join_pending_approval", str(pending.get("reason")))
    b_fp = pending["detail"]["self_fingerprint"]
    members = admin("a", "team", "members", "--env", ENVIRONMENT)["members"]
    check("pending-device-not-member", not any(m["fingerprint"] == b_fp for m in members))
    requests = admin("a", "team", "join-requests", "--env", ENVIRONMENT)["requests"]
    check("fingerprint-confirmation", requests[0]["fingerprint"] == b_fp)
    admin("a", "team", "approve-join", "--env", ENVIRONMENT, "--fingerprint", b_fp)
    joined = admin("b", *join_args, data=invitation.encode())
    check("approved-device-joined", joined.get("self_fingerprint") == b_fp)
    serve("b")
    converged("initial-signed-history")
    for name, value in (("login", "synthetic-login-zero-7462"), ("password", "synthetic-password-zero-3085"),
                        ("api", "synthetic-api-zero-5293")):
        check(f"initial-value-{name}", reveal("b", name) == value)
    wait_for("direct path", lambda: path_is("direct"))
    check("initial-direct-path", True)
    process_boundary_scan("initial")
    return b_fp, invitation, join_args


def later_versions():
    for name, kind in (("login", "env_var"), ("password", "password"), ("api", "api_key")):
        value = f"synthetic-{name}-one-624809"
        put("a", name, value, kind)
        converged(f"version-update-{name}")
        check(f"decrypted-update-{name}", reveal("b", name) == value)
    before = vector("a")
    stop("serve-b")
    stop("daemon-b")
    put("b", "password", "synthetic-password-offline-783291", "password")
    check("offline-edit-stays-local", vector("a") == before and vector("b") != before)
    daemon("b")
    serve("b")
    converged("offline-reconnect")
    check("offline-value-arrived", reveal("a", "password") == "synthetic-password-offline-783291")


def conflicting_edits():
    for node in "ab":
        stop(f"serve-{node}")
    before = admin("a", "secret", "versions", "--id", "api")
    left = put("a", "api", "synthetic-api-concurrent-left-1928")
    right = put("b", "api", "synthetic-api-concurrent-right-6410")
    for node in "ab":
        serve(node)
    converged("concurrent-edits-converge")
    a = admin("a", "secret", "versions", "--id", "api")
    b = admin("b", "secret", "versions", "--id", "api")
    check("concurrent-version-count", len(a["versions"]) == len(before["versions"]) + 2)
    # `created_at` is local import metadata (team/fold.rs::local_created_at),
    # deliberately not a replication identity. Compare identity/status and
    # the decrypted content of every retained version on both devices.
    semantic = lambda meta: [(v["version"], v["status"], v["public"]) for v in meta["versions"]]
    check("concurrent-versions-match", semantic(a) == semantic(b))
    contents = [{reveal(node, "api", v["version"]) for v in meta["versions"]}
                for node, meta in (("a", a), ("b", b))]
    check("both-concurrent-values-retained", contents[0] == contents[1] and
          {"synthetic-api-concurrent-left-1928", "synthetic-api-concurrent-right-6410"} <= contents[0])
    check("concurrent-active-value-converged", reveal("a", "api") == reveal("b", "api"))
    statuses = [admin(n, "team", "sync-status", "--env", ENVIRONMENT) for n in "ab"]
    check("conflict-alert-visible", any(s.get("conflicts", 0) > 0 for s in statuses))
    # A revocation is an irreversible fact: a stale offline peer cannot undo it.
    stop("serve-b")
    version = a["active_version"]
    admin("a", "secret", "revoke", "--id", "api", "--version", str(version))
    serve("b")
    # Revocations are signed facts, separate from the commit version vector.
    # Equal commit vectors alone do not demonstrate delivery of a new fact.
    def fact_arrived():
        meta = admin("b", "secret", "versions", "--id", "api")
        return meta if any(v["version"] == version and v["status"] == "revoked" for v in meta["versions"]) else None
    revoked = wait_for("revocation fact to stale peer", fact_arrived, timeout=100)
    converged("revocation-to-stale-peer")
    check("revoked-version-did-not-resurrect", revoked["active_version"] != version and
          any(v["version"] == version and v["status"] == "revoked" for v in revoked["versions"]))
    return left, right


def relay_modes():
    for label, flags, udp in (("relay-udp", ("--relay-only",), False),
                              ("relay-tls", ("--relay-only", "--turn-transports", "tls"), True)):
        if udp:
            blocked_udp(True)
        switch(flags)
        value = f"synthetic-{label}-remote-change-536928"
        put("a", "password", value, "password")
        converged(f"{label}-version-sync")
        wait_for(f"observed {label}", lambda: path_is(label))
        check(f"{label}-selected-path", True)
        check(f"{label}-decrypted-value", reveal("b", "password") == value)
        process_boundary_scan(label)
        if udp:
            # Keep TCP/TLS-only daemons alive across a simulated process pause.
            targets = [PROCESSES[k] for k in ("daemon-b", "serve-b")]
            for proc in targets:
                proc.send_signal(signal.SIGSTOP)
            time.sleep(2)
            for proc in targets:
                proc.send_signal(signal.SIGCONT)
            value = "synthetic-after-pause-change-783290"
            put("a", "login", value, "env_var")
            converged("pause-resume-over-tls")
            check("pause-resume-decrypted", reveal("b", "login") == value)
            pidfile = WORK / "turn.pid"
            old_pid = int(pidfile.read_text().strip())
            turnserver = os.environ.get("ZPD_TURNSERVER", "/opt/coturn/current/bin/turnserver")
            check("coturn-restart-owned-process", Path(f"/proc/{old_pid}/exe").resolve() == Path(turnserver).resolve())
            os.kill(old_pid, signal.SIGTERM)
            def coturn_exited():
                try:
                    return Path(f"/proc/{old_pid}/stat").read_text().rsplit(")", 1)[1].split()[0] == "Z"
                except FileNotFoundError:
                    return True
            wait_for("coturn exited", coturn_exited, timeout=10)
            # coturn leaves its pid file behind on normal shutdown.
            pidfile.unlink(missing_ok=True)
            spawn("coturn-restarted", ["ip", "netns", "exec", f"{PREFIX}-srv", turnserver,
                  "-c", WORK / "turnserver.conf", "--log-file", WORK / "turn.log", "--simple-log"])
            wait_for("coturn restarted", pidfile.exists, timeout=10)
            value = "synthetic-after-coturn-restart-645328"
            put("a", "password", value, "password")
            converged("coturn-restart-reconnect-over-tls")
            check("coturn-restart-decrypted", reveal("b", "password") == value)
            blocked_udp(False)


def restart_and_remove(b_fp, invitation, join_args):
    switch(("--relay-only", "--turn-transports", "tls"))
    converged("application-daemon-restart")
    stable = vector("a")
    time.sleep(2)
    check("restart-no-duplicate-commits", vector("a") == stable and vector("b") == stable)
    admin("a", "team", "remove", "--env", ENVIRONMENT, "--device", b_fp)
    put("a", "login", "synthetic-after-removal-849201", "env_var")
    time.sleep(8)
    members = admin("a", "team", "members", "--env", ENVIRONMENT)["members"]
    check("vault-device-removed", any(m["fingerprint"] == b_fp and m["status"] == "removed" for m in members))
    check("removed-device-no-new-value", reveal("b", "login") != "synthetic-after-removal-849201")
    b_id = link("b", "status")["device_id"]
    link("a", "revoke", b_id)
    wait_for("service-device-revoked", lambda: link("b", "status").get("revoked"), timeout=40)
    check("service-revocation-distinct", True)
    stop("serve-b")
    refused = admin("b", *join_args, data=invitation.encode(), allow_error=True)
    check("revoked-device-rejoin-refused", "self_fingerprint" not in refused and bool(refused.get("reason")), str(refused.get("reason")))


def leak_scan():
    capture = WORK / "run/wire.pcap"
    check("wire-capture-present", capture.is_file() and capture.stat().st_size > 24)
    paths = list((WORK / "run").glob("*")) + [WORK / "linkd.log", WORK / "turn.log"]
    for path in paths:
        if path.is_file():
            raw = path.read_bytes()
            for value in VALUES:
                check_no_value(raw, value, path.name)
    check("no-vault-values-in-runtime-logs-and-wire", True, f"{len(paths)} files; plaintext/base64/hex")


def main():
    expiring = operator_invite()
    b_fp, invitation, join_args = initial_pairing()
    later_versions()
    conflicting_edits()
    relay_modes()
    enrollment_boundaries(expiring, invitation)
    malformed_requests()
    restart_and_remove(b_fp, invitation, join_args)
    leak_scan()


if __name__ == "__main__":
    try:
        main()
    finally:
        for key in list(PROCESSES):
            stop(key)
        for handle in FILES:
            handle.close()
