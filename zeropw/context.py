"""Trusted process context: state, KMS, vault, policy, audit, handles, config.

Directory layout rule: the state directory holds only trusted material (KMS
master key, vault, policy documents, handle key, admin credential, audit log).
The two directories that agent-controlled programs touch -- ``run_dir`` (the
exec child's cwd/HOME/TMPDIR) and ``socket_dir`` (per-run signer sockets) --
are never located inside, or derived from, the state directory: a child could
otherwise walk up from its working directory to ``kms/master.key`` and the
path itself would reveal where the trusted store lives.
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .audit import Audit
from .errors import StateError
from .handles import HandleIssuer
from .kms import LocalFileKms
from .policy import Policy
from .projects import Projects
from .store import StateDir
from .vault import AdminCredential, Vault

HANDLE_KEY = "policy/handle.key"
KMS_FILE = "kms/master.key"


@dataclass
class Config:
    """Runtime configuration.

    ``socket_dir`` / ``run_dir`` are handed to agent-controlled programs
    (signer socket path, child cwd/HOME/TMPDIR).  Leave them ``None`` to get
    fresh private temporary directories outside the state store; an explicit
    value inside the state directory is refused by ``Context``.
    """

    listen_host: str = "127.0.0.1"
    listen_port: int = 0
    socket_dir: Path | None = None
    run_dir: Path | None = None
    max_response_bytes: int = 8 * 1024 * 1024
    upstream_timeout: float = 30.0
    handle_ttl_seconds: int = 900
    max_request_body_bytes: int = 8 * 1024 * 1024
    exec_timeout_seconds: float = 600.0
    # Team sync (docs/team-sync.md section 6.6, section 14 item 1): ``None`` means "use the
    # folded environment document's own settings.sync_interval_seconds"; tests override it to a
    # short interval.  Session re-key age and dial backoff bounds are node-local operational
    # knobs, not shared state, so they live here rather than in the environment document.
    team_sync_interval_seconds: float | None = None
    team_session_max_age_seconds: float = 600.0
    team_dial_backoff: tuple[float, float] = (5.0, 300.0)
    # Section 9's incident outbox retry (``TeamSync._poll_incident_outbox``): same shape as
    # ``team_dial_backoff``, kept separate since redelivering a queued incident to an admin peer is
    # a different concern from reconnecting a dropped session and tests vary them independently.
    team_incident_retry_backoff: tuple[float, float] = (5.0, 300.0)
    # Overrides for zeropw.intrusion.DetectorConfig (docs/compromise-response.md §4.2): window
    # length, weak/strong thresholds, per-rule weak points, enumeration and burst parameters.
    # ``None`` (the default) means "use DetectorConfig's own defaults".
    intrusion: dict[str, Any] | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class Context:
    def __init__(self, state: StateDir, kms: LocalFileKms, vault: Vault, policy: Policy, audit: Audit,
                 handles: HandleIssuer, projects: Projects, admin: AdminCredential, config: Config,
                 clock: Callable[[], float]) -> None:
        self.state = state
        self.kms = kms
        self.vault = vault
        self.policy = policy
        self.audit = audit
        self.handles = handles
        self.projects = projects
        self.admin = admin
        self.config = config
        self.clock = clock
        # Set by the tools / signer / intrusion modules when a server is running.
        self.runs: Any = None
        self.signer_manager: Any = None
        self.intrusion: Any = None
        # Temporary directories this context created for run_dir / socket_dir (removed by close()).
        self._owned_dirs: list[Path] = []

    @classmethod
    def initialize(cls, state_dir: str | os.PathLike[str], admin_passphrase: str, recovery_passphrase: str,
                   config: Config | None = None, clock: Callable[[], float] | None = None) -> "Context":
        import time

        clock = clock or time.time
        state = StateDir(state_dir)
        state.create()
        for name in ("kms", "vault", "policy", "audit"):  # trusted material only; no run/socket dirs here
            state.subdir(name)
        kms = LocalFileKms.create(state.path / KMS_FILE)
        audit = Audit(state, clock)
        audit.require_writable()
        projects = Projects(state)
        vault = Vault.initialize(state, kms, audit, projects, recovery_passphrase)
        admin = AdminCredential(state)
        admin.initialize(admin_passphrase)
        state.write_bytes(HANDLE_KEY, HandleIssuer.generate_key())
        policy = Policy(state, clock)
        ctx = cls(state, kms, vault, policy, audit, HandleIssuer(state.read_bytes(HANDLE_KEY)), projects, admin,
                  config or Config(), clock)
        ctx._apply_config_defaults()
        audit.record("init", result="ok", extra={"kind": "state_initialized"})
        return ctx

    @classmethod
    def open(cls, state_dir: str | os.PathLike[str], config: Config | None = None,
             clock: Callable[[], float] | None = None) -> "Context":
        import time

        clock = clock or time.time
        state = StateDir(state_dir)
        state.require()
        kms = LocalFileKms.load(state.path / KMS_FILE)
        audit = Audit(state, clock)
        projects = Projects(state)
        vault = Vault.open(state, kms, audit, projects)
        admin = AdminCredential(state)
        if not state.exists(HANDLE_KEY):
            raise StateError("handle_key_missing")
        policy = Policy(state, clock)
        ctx = cls(state, kms, vault, policy, audit, HandleIssuer(state.read_bytes(HANDLE_KEY)), projects, admin,
                  config or Config(), clock)
        ctx._apply_config_defaults()
        return ctx

    def _apply_config_defaults(self) -> None:
        """Place the agent-facing directories OUTSIDE the state directory.

        The exec child runs with cwd/HOME/TMPDIR under ``run_dir`` and reaches
        the signer through a socket under ``socket_dir``.  Deriving either from
        the state path would hand an agent-chosen program a path into the
        trusted store and let it walk up to ``kms/master.key``, the vault, the
        handle key and the admin credential.  Unset values therefore become
        fresh private (0700) temporary directories that are remembered on the
        config; explicitly configured values must not lie inside the store.
        """
        if self.config.socket_dir is None:
            self.config.socket_dir = self._private_tempdir("zeropw-sockets-")
        if self.config.run_dir is None:
            self.config.run_dir = self._private_tempdir("zeropw-runs-")
        for name, path in (("socket_dir", self.config.socket_dir), ("run_dir", self.config.run_dir)):
            if self._inside_state(path):
                self.close()
                raise StateError(f"{name}_inside_state_dir")

    def _inside_state(self, path: Path | str) -> bool:
        try:
            resolved = Path(path).resolve()
            state = self.state.path.resolve()
        except OSError:
            return True  # fail closed: an unresolvable path is not acceptable either
        return resolved == state or resolved.is_relative_to(state)

    def _private_tempdir(self, prefix: str) -> Path:
        path = Path(tempfile.mkdtemp(prefix=prefix))
        os.chmod(path, 0o700)
        self._owned_dirs.append(path)
        atexit.register(shutil.rmtree, path, ignore_errors=True)  # never left behind by a CLI invocation
        return path

    def close(self) -> None:
        """Remove the temporary directories this context created (never user-supplied ones)."""
        while self._owned_dirs:
            shutil.rmtree(self._owned_dirs.pop(), ignore_errors=True)

    def rotate_handle_key(self) -> None:
        """Invalidate every outstanding handle (used by recovery)."""
        self.state.write_bytes(HANDLE_KEY, HandleIssuer.generate_key())
        self.handles = HandleIssuer(self.state.read_bytes(HANDLE_KEY))

    def recover(self, recovery_passphrase: str) -> int:
        """Disaster recovery: new KMS master key, re-wrapped DEK, all grants revoked, handles invalidated."""
        old = self.state.path / KMS_FILE
        rotated = self.state.path / "kms" / f"master.key.retired-{int(self.clock())}"
        os.replace(old, rotated)
        try:
            new_kms = LocalFileKms.create(old, key_id=f"local-dev-kms-{int(self.clock())}")
            self.vault = Vault.recover(self.state, new_kms, self.audit, self.projects, recovery_passphrase)
        except Exception:
            os.replace(rotated, old)
            raise
        self.kms = new_kms
        revoked = self.policy.revoke_all()
        self.rotate_handle_key()
        self.audit.record("recover", result="ok", extra={"count": revoked, "state": "grants_revoked_handles_rotated"})
        return revoked
