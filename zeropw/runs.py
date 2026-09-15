"""Execution registry for secret-free CLI runs (``exec`` tool backend).

Security scope
--------------
* A run executes the program fixed by a connection's CLI profile inside a
  fresh working directory with the minimal environment that ``zeropw.tools``
  builds.  The registry never receives the vault value for use; it only gets
  byte patterns to look for in the captured output (defence in depth: the
  child never held the credential, so a match means something went wrong).
* Output capture is bounded (256 KiB per stream, marked ``truncated``).  After
  the child exits both streams are scanned for the credential in raw, base64,
  urlsafe-base64 (at every alignment), hex and URL-encoded forms, and for the
  opaque connection handle.  A match makes the run ``blocked`` and replaces
  both outputs with a fixed marker.  Transformations outside those encodings
  are not guaranteed to be caught; the structural guarantee is that the child
  never received the value in the first place.
* Only the owning caller can observe or cancel a run.  Any other caller gets
  ``NotFound`` (never "forbidden") so run ids cannot be enumerated.
* Revocation, global stop, restore-pending, connection changes and principal
  disablement cancel queued and running runs through ``on_revoke`` /
  ``cancel_all``.  Only grant revocations are targeted; the other kinds
  cancel every active run (fail-safe over-cancellation, see ``on_revoke``).
  Cancellation sends SIGTERM to the child's process group, then SIGKILL after
  a short grace period.  It cannot undo work the child has already performed
  remotely.
* ``find_or_create`` reserves a ``(caller, request_id)`` slot and creates the
  run in one critical section, so concurrent duplicate requests map to
  exactly one execution.  ``zeropw.tools`` registers the run *before* any
  slow setup work so a concurrent revoke/stop can find and cancel it while
  it is still queued.
* ``run_start`` is written to the audit log before the child is spawned and
  ``run_finish`` after it exits.  If ``run_start`` cannot be written the run is
  not started; if ``run_finish`` cannot be written the captured outputs are
  discarded and the run is reported as failed (fail closed, never silent).
* Audit records carry ids, states, exit codes and byte counts only; never
  output text, arguments, environment values or paths chosen by the agent.
  ``run_start`` / ``run_cancel`` / ``run_finish`` also carry the connection's
  target label (HTTP origin or ssh ``host:port``) and the policy version the
  run was admitted under, as given to ``create`` / ``find_or_create``.
"""

from __future__ import annotations

import base64
import binascii
import os
import secrets
import signal
import subprocess
import threading
import time
import urllib.parse
from typing import Any, Callable, Iterable, Mapping, Sequence

from .errors import AuditUnavailable, InvalidInput, NotFound
from .store import iso

CAPTURE_LIMIT = 256 * 1024
READ_CHUNK = 64 * 1024
TERMINATE_GRACE_SECONDS = 2.0
FINALIZE_WAIT_SECONDS = 10.0
BLOCKED_MARKER = "[blocked: output contained authentication material]"
MIN_PATTERN_LENGTH = 8
MAX_RETAINED_RUNS = 1000

QUEUED = "queued"
RUNNING = "running"
COMPLETED = "completed"
FAILED = "failed"
CANCELLED = "cancelled"
BLOCKED = "blocked"
STATES = (QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED, BLOCKED)
ACTIVE_STATES = frozenset({QUEUED, RUNNING})
TERMINAL_STATES = frozenset({COMPLETED, FAILED, CANCELLED, BLOCKED})

# Audit ``result`` per terminal state.
RESULT_BY_STATE = {COMPLETED: "ok", FAILED: "failed", CANCELLED: "cancelled", BLOCKED: "blocked"}

# Policy revocation kinds (see ``Policy._notify_revoke``) -> cancellation reason.
REVOKE_REASONS = {
    "grant": "grant_revoked",
    "all": "grant_revoked",
    "stop": "global_stop",
    "restore": "restore_pending",
    "connection": "connection_changed",
    "principal": "principal_disabled",
}


# ------------------------------------------------------------------ scanning
def credential_patterns(secret: bytes, minimum: int = MIN_PATTERN_LENGTH) -> list[bytes]:
    """Byte patterns whose presence in an output means ``secret`` leaked.

    Covers the raw value, standard and urlsafe base64 at all three byte
    alignments (partial edge groups stripped so the value is found inside a
    longer encoded blob), the padded exact encodings, hex (both cases) and
    URL encoding.  Derived patterns shorter than ``minimum`` are skipped to
    avoid matching unrelated output; the raw value is always included.
    """
    if not secret:
        return []
    patterns: list[bytes] = [bytes(secret)]

    def add(candidate: bytes) -> None:
        if len(candidate) >= minimum and candidate not in patterns:
            patterns.append(candidate)

    stripped = secret.strip()
    if stripped and stripped != secret:
        add(stripped)
    for encoder in (base64.b64encode, base64.urlsafe_b64encode):
        add(encoder(secret))
        add(encoder(secret).rstrip(b"="))
        for shift in range(3):
            encoded = encoder(b"\x00" * shift + secret).rstrip(b"=")
            head = 4 if shift else 0
            tail = {0: 0, 1: 2, 2: 3}[(shift + len(secret)) % 3]
            core = encoded[head:len(encoded) - tail] if tail else encoded[head:]
            add(core)
    hexed = binascii.hexlify(secret)
    add(hexed)
    add(hexed.upper())
    # URL encoding: the standard form (unreserved characters kept), the form aggressive encoders
    # produce (only alphanumerics kept) and the fully percent-encoded form, in both hex cases.
    add(urllib.parse.quote(secret, safe="").encode("ascii"))
    add(urllib.parse.quote_plus(secret, safe="").encode("ascii"))
    alnum_only = "".join(chr(b) if chr(b).isalnum() and b < 128 else f"%{b:02X}" for b in secret)
    add(alnum_only.encode("ascii"))
    add(alnum_only.lower().encode("ascii"))
    full = "".join(f"%{b:02X}" for b in secret)
    add(full.encode("ascii"))
    add(full.lower().encode("ascii"))
    return patterns


def contains_sensitive(data: bytes, patterns: Iterable[bytes]) -> bool:
    return any(pattern and pattern in data for pattern in patterns)


# ----------------------------------------------------------------------- run
class Run:
    """One execution.  Mutable; guarded by the registry lock."""

    def __init__(self, run_id: str, caller: str, connection: str, grant: str, kind: str, program: str,
                 request_id: str | None, input_digest: str, created_at: str, target: str | None = None,
                 policy_version: int | None = None) -> None:
        self.id = run_id
        self.caller = caller
        self.connection = connection
        self.grant = grant
        self.kind = kind
        self.program = program
        self.request_id = request_id
        self.input_digest = input_digest
        self.created_at = created_at
        self.target = target  # audit only: connection target label at admission
        self.policy_version = policy_version  # audit only: connection policy version at admission
        self.state = QUEUED
        self.reason: str | None = None
        self.exit_code: int | None = None
        self.started_at: str | None = None
        self.finished_at: str | None = None
        self.stdout = b""
        self.stderr = b""
        self.stdout_truncated = False
        self.stderr_truncated = False
        # internal
        self.proc: subprocess.Popen[bytes] | None = None
        self.thread: threading.Thread | None = None
        self.cancel_requested = False
        self.cancel_reason: str | None = None
        self.timed_out = False
        self.done = threading.Event()

    def public_view(self) -> dict[str, Any]:
        """What the owning caller may see.  No paths, no environment, no grant ids."""
        return {
            "run_id": self.id,
            "connection": self.connection,
            "state": self.state,
            "reason": self.reason,
            "exit_code": self.exit_code,
            "stdout": self.stdout.decode("utf-8", "replace"),
            "stderr": self.stderr.decode("utf-8", "replace"),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "truncated": bool(self.stdout_truncated or self.stderr_truncated),
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
        }


# ------------------------------------------------------------------ registry
class RunRegistry:
    def __init__(self, ctx: Any, capture_limit: int = CAPTURE_LIMIT,
                 grace_seconds: float = TERMINATE_GRACE_SECONDS) -> None:
        self.ctx = ctx
        self.capture_limit = int(capture_limit)
        self.grace_seconds = float(grace_seconds)
        self._runs: dict[str, Run] = {}
        self._by_request: dict[tuple[str, str], str] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------- creation
    def find_by_request(self, caller: str, request_id: str, input_digest: str) -> Run | None:
        """Idempotency: same caller + request id + same input -> the existing run.

        A different input under a reused request id is refused.
        """
        with self._lock:
            run_id = self._by_request.get((caller, request_id))
            run = self._runs.get(run_id) if run_id else None
        if run is None:
            return None
        if run.input_digest != input_digest:
            raise InvalidInput("request_id_reused")
        return run

    def create(self, caller: str, connection: str, grant: str, kind: str, program: str,
               request_id: str | None = None, input_digest: str = "", *, target: str | None = None,
               policy_version: int | None = None) -> Run:
        """Register a new queued run unconditionally (see ``find_or_create`` for request ids)."""
        with self._lock:
            return self._create_locked(caller, connection, grant, kind, program, request_id, input_digest,
                                       target, policy_version)

    def find_or_create(self, caller: str, connection: str, grant: str, kind: str, program: str,
                       request_id: str | None, input_digest: str, *, target: str | None = None,
                       policy_version: int | None = None) -> tuple[Run, bool]:
        """Atomic idempotent registration: ``(run, created)``.

        The lookup of the ``(caller, request_id)`` slot and the creation of the
        run happen in one critical section, so concurrent duplicates of the
        same request map to exactly one run (the losers get ``created=False``
        and the winner's run).  A different input digest under a reused
        request id raises ``InvalidInput("request_id_reused")``.  Without a
        request id a new run is always created.
        """
        with self._lock:
            if request_id is not None:
                existing_id = self._by_request.get((caller, request_id))
                existing = self._runs.get(existing_id) if existing_id else None
                if existing is not None:
                    if existing.input_digest != input_digest:
                        raise InvalidInput("request_id_reused")
                    return existing, False
            run = self._create_locked(caller, connection, grant, kind, program, request_id, input_digest,
                                      target, policy_version)
            return run, True

    def _create_locked(self, caller: str, connection: str, grant: str, kind: str, program: str,
                       request_id: str | None, input_digest: str, target: str | None = None,
                       policy_version: int | None = None) -> Run:
        run = Run("r-" + secrets.token_hex(8), caller, connection, grant, kind, program, request_id,
                  input_digest, iso(self.ctx.clock()), target, policy_version)
        self._runs[run.id] = run
        if request_id is not None:
            self._by_request[(caller, request_id)] = run.id
        self._evict_locked()
        return run

    def _evict_locked(self) -> None:
        if len(self._runs) <= MAX_RETAINED_RUNS:
            return
        for run_id, run in list(self._runs.items()):
            if len(self._runs) <= MAX_RETAINED_RUNS:
                break
            if run.state in TERMINAL_STATES:
                del self._runs[run_id]
                if run.request_id is not None:
                    self._by_request.pop((run.caller, run.request_id), None)

    # ---------------------------------------------------------------- start
    def start(self, run: Run, argv: Sequence[str], env: Mapping[str, str], cwd: str,
              sensitive: Iterable[bytes] = (), cleanup: Callable[[], None] | None = None,
              timeout: float | None = None) -> Run:
        """Audit ``run_start``, spawn the child, supervise it in a daemon thread.

        Once ``start`` is called the registry owns ``cleanup`` and invokes it
        exactly once (after the child exits, or immediately if the run was
        cancelled or could not be spawned).
        """
        patterns: list[bytes] = []
        for item in sensitive:
            patterns.extend(credential_patterns(bytes(item)))
        if timeout is None:
            timeout = float(getattr(self.ctx.config, "exec_timeout_seconds", 0) or 0)
        with self._lock:
            if run.state != QUEUED:
                self._run_cleanup(cleanup)
                return run
        try:
            self.ctx.audit.record("run_start", caller=run.caller, connection=run.connection, target=run.target,
                                  run_id=run.id, request_id=run.request_id, action="exec", result="ok",
                                  policy_version=run.policy_version,
                                  extra={"program": run.program, "kind": run.kind, "grant": run.grant})
        except AuditUnavailable:
            self._finalize(run, FAILED, "audit_unavailable", None, record=False)
            self._run_cleanup(cleanup)
            raise
        with self._lock:
            if run.state != QUEUED:  # cancelled between the audit record and the spawn
                self._run_cleanup(cleanup)
                return run
            try:
                proc = subprocess.Popen(  # noqa: S603 - program fixed by the connection profile
                    list(argv), cwd=cwd, env=dict(env), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, close_fds=True, start_new_session=True)
            except (OSError, ValueError):
                self._finalize(run, FAILED, "spawn_failed", None)
                self._run_cleanup(cleanup)
                return run
            run.proc = proc
            run.state = RUNNING
            run.started_at = iso(self.ctx.clock())
            thread = threading.Thread(target=self._supervise, args=(run, proc, timeout, patterns, cleanup),
                                      name=f"zeropw-run-{run.id}", daemon=True)
            run.thread = thread
            thread.start()
        return run

    def _pump(self, stream: Any, sink: dict[str, tuple[bytes, bool]], key: str) -> None:
        buffer = bytearray()
        truncated = False
        fd = stream.fileno()
        while True:
            try:
                chunk = os.read(fd, READ_CHUNK)
            except OSError:
                break
            if not chunk:
                break
            room = self.capture_limit - len(buffer)
            if room <= 0:
                truncated = True
                continue
            if len(chunk) > room:
                buffer += chunk[:room]
                truncated = True
            else:
                buffer += chunk
        sink[key] = (bytes(buffer), truncated)

    def _supervise(self, run: Run, proc: subprocess.Popen[bytes], timeout: float, patterns: list[bytes],
                   cleanup: Callable[[], None] | None) -> None:
        sink: dict[str, tuple[bytes, bool]] = {}
        pumps = [threading.Thread(target=self._pump, args=(proc.stdout, sink, "stdout"), daemon=True),
                 threading.Thread(target=self._pump, args=(proc.stderr, sink, "stderr"), daemon=True)]
        for pump in pumps:
            pump.start()
        state, reason = FAILED, "internal_error"
        exit_code: int | None = None
        stdout, stderr, out_trunc, err_trunc = b"", b"", False, False
        try:
            try:
                proc.wait(timeout=timeout if timeout > 0 else None)
            except subprocess.TimeoutExpired:
                with self._lock:
                    run.timed_out = True
                self._terminate([run])
                proc.wait()
            for pump in pumps:
                pump.join(FINALIZE_WAIT_SECONDS)
            stdout, out_trunc = sink.get("stdout", (b"", False))
            stderr, err_trunc = sink.get("stderr", (b"", False))
            exit_code = proc.returncode
            with self._lock:
                cancelled, cancel_reason, timed_out = run.cancel_requested, run.cancel_reason, run.timed_out
            if patterns and (contains_sensitive(stdout, patterns) or contains_sensitive(stderr, patterns)):
                state, reason = BLOCKED, "output_credential_blocked"
                stdout = stderr = BLOCKED_MARKER.encode("utf-8")
                out_trunc = err_trunc = False
            elif cancelled:
                state, reason = CANCELLED, cancel_reason or "cancelled"
            elif timed_out:
                state, reason = FAILED, "timeout"
            else:
                state, reason = COMPLETED, None
        finally:
            for stream in (proc.stdout, proc.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except OSError:
                    pass
            self._run_cleanup(cleanup)
            self._finalize(run, state, reason, exit_code, stdout, stderr, out_trunc, err_trunc)

    @staticmethod
    def _run_cleanup(cleanup: Callable[[], None] | None) -> None:
        if cleanup is None:
            return
        try:
            cleanup()
        except Exception:
            pass

    def _finalize(self, run: Run, state: str, reason: str | None, exit_code: int | None, stdout: bytes = b"",
                  stderr: bytes = b"", out_trunc: bool = False, err_trunc: bool = False, record: bool = True) -> None:
        with self._lock:
            if run.state in TERMINAL_STATES:
                run.done.set()
                return
            run.state = state
            run.reason = reason
            run.exit_code = exit_code
            run.stdout = stdout
            run.stderr = stderr
            run.stdout_truncated = out_trunc
            run.stderr_truncated = err_trunc
            run.finished_at = iso(self.ctx.clock())
            run.proc = None
        if record:
            try:
                self.ctx.audit.record("run_finish", caller=run.caller, connection=run.connection,
                                      target=run.target, run_id=run.id, request_id=run.request_id,
                                      action="exec", result=RESULT_BY_STATE[state], reason=reason,
                                      policy_version=run.policy_version,
                                      extra={"program": run.program, "exit_code": exit_code, "run_state": state,
                                             "bytes": len(stdout) + len(stderr)})
            except AuditUnavailable:
                with self._lock:  # unrecorded output never reaches the agent
                    run.state = FAILED
                    run.reason = "audit_unavailable"
                    run.stdout = b""
                    run.stderr = b""
                    run.stdout_truncated = run.stderr_truncated = False
        run.done.set()

    def fail(self, run: Run, reason: str) -> Run:
        """Mark a run that never started as failed (setup errors after ``create``)."""
        self._finalize(run, FAILED, reason, None)
        return run

    # ------------------------------------------------------------- queries
    def get(self, run_id: str, caller: str) -> Run:
        with self._lock:
            run = self._runs.get(run_id)
        if run is None or run.caller != caller:
            raise NotFound("run_not_found")
        return run

    def view(self, run: Run) -> dict[str, Any]:
        with self._lock:
            return run.public_view()

    def wait(self, run: Run, timeout: float | None = None) -> Run:
        run.done.wait(timeout)
        return run

    def active_runs(self) -> list[Run]:
        with self._lock:
            return [run for run in self._runs.values() if run.state in ACTIVE_STATES]

    # ------------------------------------------------------------ cancel
    def cancel(self, run_id: str, caller: str, reason: str = "cancelled_by_caller") -> Run:
        run = self.get(run_id, caller)
        self._cancel_runs([run], reason)
        return run

    def cancel_all(self, reason: str, grant_id: str | None = None) -> int:
        with self._lock:
            targets = [run for run in self._runs.values()
                       if run.state in ACTIVE_STATES and (grant_id is None or run.grant == grant_id)]
        self._cancel_runs(targets, reason)
        return len(targets)

    def on_revoke(self, kind: str, grant_id: str | None) -> None:
        """``Policy.on_revoke`` listener.

        A ``grant`` notification cancels only that grant's active runs.  Every
        other kind (``all``, ``stop``, ``restore``, ``connection``,
        ``principal``) cancels *all* active runs, including runs of unrelated
        principals and connections.  This over-cancellation is deliberate
        fail-safe behaviour: the notification does not carry the affected
        principal/connection id, and the runs' own policy re-evaluation only
        happens at spawn time, so cancelling everything is the only way to
        guarantee that no run keeps executing under a policy that may just
        have withdrawn its permission.  A cancelled run can simply be
        re-issued; a run that kept going under revoked policy cannot be
        undone.  Each cancellation is audited (``run_cancel`` and
        ``run_finish``) with the specific reason from ``REVOKE_REASONS``
        (``principal_disabled``, ``connection_changed``, ``restore_pending``,
        ``global_stop``, ``grant_revoked``) so the log names the policy change
        that caused it.
        """
        reason = REVOKE_REASONS.get(kind, "grant_revoked")
        if kind == "grant" and grant_id:
            self.cancel_all(reason, grant_id=grant_id)
        else:
            self.cancel_all(reason)

    def _record_cancel(self, run: Run, reason: str) -> None:
        # Best effort: a cancellation is never refused because the log is unavailable.
        try:
            self.ctx.audit.record("run_cancel", caller=run.caller, connection=run.connection, target=run.target,
                                  run_id=run.id, request_id=run.request_id, action="exec", result="ok",
                                  reason=reason, policy_version=run.policy_version,
                                  extra={"program": run.program, "run_state": run.state})
        except AuditUnavailable:
            pass

    def _cancel_runs(self, runs: Sequence[Run], reason: str) -> None:
        running: list[Run] = []
        for run in runs:
            with self._lock:
                if run.state == QUEUED:
                    run.cancel_requested = True
                    run.cancel_reason = reason
                    self._record_cancel(run, reason)
                    self._finalize(run, CANCELLED, reason, None)
                    continue
                if run.state != RUNNING:
                    continue
                if not run.cancel_requested:
                    run.cancel_requested = True
                    run.cancel_reason = reason
                    fresh = True
                else:
                    fresh = False
                running.append(run)
            if fresh:
                self._record_cancel(run, reason)
        if running:
            self._terminate(running)
            for run in running:
                run.done.wait(FINALIZE_WAIT_SECONDS)

    @staticmethod
    def _signal(proc: subprocess.Popen[bytes], sig: int) -> None:
        if proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, sig)  # start_new_session=True: the child leads its own group
        except ProcessLookupError:
            pass
        except PermissionError:
            try:
                proc.send_signal(sig)
            except ProcessLookupError:
                pass

    def _terminate(self, runs: Sequence[Run]) -> None:
        with self._lock:
            procs = [run.proc for run in runs if run.proc is not None]
        for proc in procs:
            self._signal(proc, signal.SIGTERM)
        deadline = time.monotonic() + self.grace_seconds
        for proc in procs:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                self._signal(proc, signal.SIGKILL)
        for proc in procs:
            try:
                proc.wait(timeout=FINALIZE_WAIT_SECONDS)
            except subprocess.TimeoutExpired:
                pass

    def shutdown(self, reason: str = "shutdown") -> None:
        self.cancel_all(reason)
        with self._lock:
            threads = [run.thread for run in self._runs.values() if run.thread is not None]
        for thread in threads:
            thread.join(FINALIZE_WAIT_SECONDS)
