"""Locked, atomic JSON state directory for the trusted ZeroPW process.

The state directory holds encrypted secrets, policy, audit records, and the
local KMS master key.  It belongs to the trusted control plane only.  Agent
processes never receive its path, and on a shared development host the only
isolation is the directory mode (0700) plus file modes (0600); the production
deployment boundary (separate identity, host, and network) is documented in
``docs/implementation.md``.

Concurrency: a single trusted process serves several threads (gateway, signer,
tools).  ``StateDir.lock()`` combines a re-entrant thread lock with an
``fcntl`` file lock so that a second administrative process (the admin CLI)
also serialises read-modify-write cycles.
"""

from __future__ import annotations

import fcntl
import json
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .errors import StateError

DIR_MODE = 0o700
FILE_MODE = 0o600


class StateDir:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._thread_lock = threading.RLock()
        self._local = threading.local()

    # ------------------------------------------------------------------ setup
    def create(self) -> None:
        if self.path.exists():
            raise StateError("state_exists", str(self.path))
        self.path.mkdir(mode=DIR_MODE, parents=True)
        os.chmod(self.path, DIR_MODE)

    def require(self) -> None:
        if not self.path.is_dir():
            raise StateError("state_missing", str(self.path))

    def subdir(self, name: str) -> Path:
        target = self.path / name
        target.mkdir(mode=DIR_MODE, exist_ok=True)
        return target

    # ------------------------------------------------------------------- lock
    @contextmanager
    def lock(self) -> Iterator[None]:
        """Exclusive re-entrant lock across threads and processes."""
        depth = getattr(self._local, "depth", 0)
        with self._thread_lock:
            if depth == 0:
                self.path.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
                fd = os.open(self.path / ".lock", os.O_RDWR | os.O_CREAT, FILE_MODE)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                except OSError:
                    os.close(fd)
                    raise
                self._local.fd = fd
            self._local.depth = depth + 1
            try:
                yield
            finally:
                self._local.depth = depth
                if depth == 0:
                    fd = self._local.fd
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    finally:
                        os.close(fd)
                        self._local.fd = None

    # ------------------------------------------------------------------- json
    def read_json(self, name: str, default: Any = None) -> Any:
        target = self.path / name
        if not target.exists():
            return default
        try:
            with open(target, "r", encoding="utf-8") as stream:
                return json.load(stream)
        except (OSError, ValueError) as exc:
            raise StateError("state_corrupt", name) from exc

    def write_json(self, name: str, value: Any) -> None:
        target = self.path / name
        target.parent.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
        tmp = target.with_name(f".{target.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(value, stream, sort_keys=True, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, target)
        except OSError as exc:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise StateError("state_write_failed", name) from exc

    def append_line(self, name: str, line: str) -> None:
        """Append one line and fsync.  Raises OSError to the caller on failure."""
        if "\n" in line:
            raise StateError("state_invalid_line", name)
        target = self.path / name
        target.parent.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, FILE_MODE)
        try:
            os.write(fd, (line + "\n").encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

    def read_lines(self, name: str, limit: int | None = None) -> list[str]:
        target = self.path / name
        if not target.exists():
            return []
        with open(target, "r", encoding="utf-8") as stream:
            lines = [line.rstrip("\n") for line in stream]
        if limit is not None:
            return lines[-limit:]
        return lines

    def write_bytes(self, name: str, data: bytes) -> None:
        target = self.path / name
        target.parent.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
        tmp = target.with_name(f".{target.name}.{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, target)
        except OSError as exc:
            raise StateError("state_write_failed", name) from exc

    def read_bytes(self, name: str) -> bytes:
        target = self.path / name
        try:
            return target.read_bytes()
        except OSError as exc:
            raise StateError("state_missing", name) from exc

    def exists(self, name: str) -> bool:
        return (self.path / name).exists()


def now() -> float:
    return time.time()


def iso(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts if ts is not None else time.time()))
