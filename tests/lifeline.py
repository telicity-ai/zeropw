"""Test helper: start a long-running process (``serve``, ``sshd``) that dies with the test process.

``spawn(argv, cleanup_dir=...)`` runs ``argv`` under a small supervisor (this
file, run as a script) in a new session.  The supervisor holds the read end of
a pipe whose only write end belongs to the test process.  When the test
process exits for any reason -- normal exit, an exception that skips
``tearDown``, SIGINT, a job timeout's SIGTERM, even SIGKILL -- the pipe
reports EOF, and the supervisor terminates the command (SIGTERM, SIGKILL after
a grace period), removes ``cleanup_dir`` and SIGKILLs whatever is left in its
process group.

While the test process is alive the supervisor is transparent: the command
shares its stdout/stderr, ``Popen.terminate()`` on the returned object is
forwarded to the command as SIGTERM, and the supervisor exits with the
command's exit status.  ``kill(proc)`` SIGKILLs the whole process group.

Not a test module (no ``test_`` prefix); standard library only.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Sequence

GRACE_SECONDS = 5.0
_SUPERVISOR = str(Path(__file__).resolve())


def spawn(argv: Sequence[str], cleanup_dir: str | os.PathLike[str] | None = None, **popen_kwargs: Any) -> subprocess.Popen:
    """Start ``argv`` under a supervisor that stops it (and removes ``cleanup_dir``) once this process is gone."""
    read_end, write_end = os.pipe()          # non-inheritable: only the supervisor gets the read end
    command = [sys.executable, _SUPERVISOR, str(read_end)]
    command += [str(cleanup_dir)] if cleanup_dir is not None else [""]
    command += ["--", *argv]
    try:
        proc = subprocess.Popen(command, pass_fds=(read_end,), start_new_session=True,
                                stdin=subprocess.DEVNULL, **popen_kwargs)
    except BaseException:
        os.close(write_end)
        raise
    finally:
        os.close(read_end)
    proc._zeropw_lifeline = write_end  # type: ignore[attr-defined]  # closed by release()
    return proc


def kill(proc: subprocess.Popen) -> None:
    """SIGKILL the supervisor and everything left in its process group."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def release(proc: subprocess.Popen) -> None:
    """Close this process's end of the lifeline (call once the process has been stopped)."""
    write_end = getattr(proc, "_zeropw_lifeline", None)
    if write_end is not None:
        proc._zeropw_lifeline = None  # type: ignore[attr-defined]
        try:
            os.close(write_end)
        except OSError:
            pass


def _supervise(lifeline_fd: int, cleanup_dir: str, argv: list[str]) -> int:
    stop_requested = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):   # a stop before the child exists is kept
        signal.signal(signum, lambda *_: stop_requested.set())
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL)
    orphaned = threading.Event()

    def escalate() -> None:
        if child.poll() is None:
            try:
                child.kill()
            except OSError:
                pass

    def stop() -> None:
        if child.poll() is None:
            try:
                child.send_signal(signal.SIGTERM)
            except OSError:
                pass
            timer = threading.Timer(GRACE_SECONDS, escalate)
            timer.daemon = True
            timer.start()

    def watch_parent() -> None:
        try:
            while os.read(lifeline_fd, 1024):
                pass
        except OSError:
            pass
        orphaned.set()
        stop()

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, lambda *_: stop())
    if stop_requested.is_set():
        stop()
    threading.Thread(target=watch_parent, daemon=True).start()
    code = child.wait()
    if orphaned.is_set():
        if cleanup_dir:
            shutil.rmtree(cleanup_dir, ignore_errors=True)
        try:   # nobody is left to reap the rest of the group (e.g. sshd's per-connection processes)
            os.killpg(os.getpgid(0), signal.SIGKILL)
        except OSError:
            pass
    return code if code >= 0 else 128 - code


if __name__ == "__main__":
    fd, directory, separator, *command = sys.argv[1:]
    assert separator == "--" and command, "usage: lifeline.py FD CLEANUP_DIR -- command..."
    sys.exit(_supervise(int(fd), directory, command))
