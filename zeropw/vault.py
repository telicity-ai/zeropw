"""Encrypted vault with versioned secrets, rotation, backup, restore, recovery.

Envelope: every secret version is encrypted with the vault data-encryption key
(DEK) using ChaCha20-Poly1305 (random nonce, AAD = secret id + version).  The
DEK is wrapped twice: by the KMS (normal operation) and by a key derived from
an independent recovery passphrase (disaster recovery).  Losing both the KMS
master key and the recovery passphrase makes the vault unrecoverable; the
product documentation states that no universal recovery is promised.

Value access:

* ``secret_for_trusted_use`` returns plaintext to *in-process* trusted
  components only (gateway, signer).  It is never exposed over the tools API.
* ``reveal`` is the administrator's single-secret read.  It requires a fresh
  administrator re-authentication and always writes an audit record first.
  There is no bulk plaintext export.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import Audit
from .crypto import chacha20poly1305 as aead
from .errors import AuthFailed, InvalidInput, NotFound, StateError
from .kms import Kms, WrappedKey
from .projects import Projects, validate_name
from .store import StateDir, iso

VAULT_DOC = "vault/secrets.json"
ADMIN_DOC = "admin.json"
SECRET_KINDS = ("api_key", "password", "env_var", "ssh_private_key")
VERSION_STATES = ("staged", "active", "retired", "revoked")
MAX_SECRET_BYTES = 64 * 1024
REAUTH_WINDOW_SECONDS = 60
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text)


def derive_key(passphrase: str, salt: bytes) -> bytes:
    if not isinstance(passphrase, str) or len(passphrase) < 8:
        raise InvalidInput("passphrase_too_short")
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)


# ------------------------------------------------------------------- admin auth
@dataclass(frozen=True)
class AdminAuth:
    """Proof of a recent administrator re-authentication."""

    verified_at: float

    def fresh(self, now: float | None = None) -> bool:
        current = now if now is not None else time.time()
        return 0 <= current - self.verified_at <= REAUTH_WINDOW_SECONDS


class AdminCredential:
    """Administrator passphrase (separate from any agent identity)."""

    def __init__(self, state: StateDir) -> None:
        self.state = state

    def initialize(self, passphrase: str) -> None:
        if self.state.exists(ADMIN_DOC):
            raise StateError("admin_exists")
        salt = secrets.token_bytes(16)
        key = derive_key(passphrase, salt)
        self.state.write_json(ADMIN_DOC, {"salt": _b64e(salt), "hash": _b64e(hashlib.sha256(key).digest()),
                                          "created_at": iso()})

    def verify(self, passphrase: str, now: float | None = None) -> AdminAuth:
        doc = self.state.read_json(ADMIN_DOC)
        if not doc:
            raise StateError("admin_missing")
        try:
            key = derive_key(passphrase, _b64d(doc["salt"]))
        except InvalidInput as exc:
            raise AuthFailed("admin_reauth_failed") from exc
        if not hmac.compare_digest(hashlib.sha256(key).digest(), _b64d(doc["hash"])):
            raise AuthFailed("admin_reauth_failed")
        return AdminAuth(now if now is not None else time.time())


# ------------------------------------------------------------------------ vault
@dataclass(frozen=True)
class VersionMeta:
    secret_id: str
    version: int
    status: str
    created_at: str
    public: dict[str, Any]


@dataclass(frozen=True)
class SecretMeta:
    id: str
    project: str
    environment: str
    kind: str
    active_version: int | None
    versions: tuple[VersionMeta, ...]


class Vault:
    def __init__(self, state: StateDir, kms: Kms, dek: bytes, audit: Audit, projects: Projects) -> None:
        self.state = state
        self.kms = kms
        self._dek = dek
        self.audit = audit
        self.projects = projects

    # lifecycle -----------------------------------------------------------
    @classmethod
    def initialize(cls, state: StateDir, kms: Kms, audit: Audit, projects: Projects,
                   recovery_passphrase: str) -> "Vault":
        if state.exists(VAULT_DOC):
            raise StateError("vault_exists")
        dek = secrets.token_bytes(aead.KEY_SIZE)
        salt = secrets.token_bytes(16)
        recovery_key = derive_key(recovery_passphrase, salt)
        nonce = secrets.token_bytes(aead.NONCE_SIZE)
        doc = {
            "dek": kms.wrap(dek).to_dict(),
            "recovery": {"salt": _b64e(salt), "nonce": _b64e(nonce),
                         "ciphertext": _b64e(aead.encrypt(recovery_key, nonce, dek, b"zeropw-recovery"))},
            "secrets": {},
            "created_at": iso(),
        }
        state.write_json(VAULT_DOC, doc)
        return cls(state, kms, dek, audit, projects)

    @classmethod
    def open(cls, state: StateDir, kms: Kms, audit: Audit, projects: Projects) -> "Vault":
        doc = state.read_json(VAULT_DOC)
        if not doc:
            raise StateError("vault_missing")
        dek = kms.unwrap(WrappedKey.from_dict(doc["dek"]))
        return cls(state, kms, dek, audit, projects)

    @classmethod
    def recover(cls, state: StateDir, new_kms: Kms, audit: Audit, projects: Projects,
                recovery_passphrase: str) -> "Vault":
        """Unwrap the DEK with the recovery passphrase and re-wrap it under a new KMS key."""
        doc = state.read_json(VAULT_DOC)
        if not doc:
            raise StateError("vault_missing")
        rec = doc["recovery"]
        key = derive_key(recovery_passphrase, _b64d(rec["salt"]))
        try:
            dek = aead.decrypt(key, _b64d(rec["nonce"]), _b64d(rec["ciphertext"]), b"zeropw-recovery")
        except aead.AuthenticationError as exc:
            raise AuthFailed("recovery_passphrase_invalid") from exc
        with state.lock():
            doc = state.read_json(VAULT_DOC)
            doc["dek"] = new_kms.wrap(dek).to_dict()
            state.write_json(VAULT_DOC, doc)
        return cls(state, new_kms, dek, audit, projects)

    # helpers -------------------------------------------------------------
    def _doc(self) -> dict[str, Any]:
        doc = self.state.read_json(VAULT_DOC)
        if not doc:
            raise StateError("vault_missing")
        return doc

    @staticmethod
    def _aad(secret_id: str, version: int) -> bytes:
        return f"zeropw-secret:{secret_id}:{version}".encode("utf-8")

    def _encrypt(self, secret_id: str, version: int, value: bytes) -> dict[str, str]:
        nonce = secrets.token_bytes(aead.NONCE_SIZE)
        return {"nonce": _b64e(nonce), "ciphertext": _b64e(aead.encrypt(self._dek, nonce, value, self._aad(secret_id, version)))}

    def _decrypt(self, secret_id: str, version: int, entry: dict[str, Any]) -> bytes:
        if entry.get("shared_env"):
            return self._decrypt_shared(secret_id, entry)
        try:
            return aead.decrypt(self._dek, _b64d(entry["nonce"]), _b64d(entry["ciphertext"]), self._aad(secret_id, version))
        except (aead.AuthenticationError, KeyError, ValueError) as exc:
            raise StateError("secret_corrupt", secret_id) from exc

    def _decrypt_shared(self, secret_id: str, entry: dict[str, Any]) -> bytes:
        """Decrypt a team-sync shared-environment secret version (docs/team-sync.md sections 4.2, 6.5).

        Shared secrets are encrypted under the environment DEK generation
        that was active when the version was written, not the local vault
        DEK.  The generation key was unwrapped once (``zeropw.team.fold``,
        ``_derive_dek_generations``) and re-wrapped under this node's own
        KMS at ``team/<env-id>/dek/<generation-id>.json``; it is looked up
        again here on every decrypt rather than cached.
        """
        from .team import envelope  # lazy: avoid an import cycle (team builds on vault, not the reverse)

        try:
            env_id = str(entry["shared_env"])
            generation_id = str(entry["generation"])
            version_id = str(entry["version_id"])
        except KeyError as exc:
            raise StateError("secret_corrupt", secret_id) from exc
        key = self._generation_key(env_id, generation_id)
        try:
            return envelope.decrypt_secret(key, env_id, secret_id, version_id, entry)
        except InvalidInput as exc:
            raise StateError("secret_corrupt", secret_id) from exc

    def _generation_key(self, env_id: str, generation_id: str) -> bytes:
        doc = self.state.read_json(f"team/{env_id}/dek/{generation_id}.json", None)
        if not doc:
            raise StateError("team_dek_generation_missing")
        return self.kms.unwrap(WrappedKey.from_dict(doc))

    @staticmethod
    def _public_metadata(kind: str, value: bytes) -> dict[str, Any]:
        """Non-secret metadata derived from the value (public key for SSH keys).

        Only an SSH key has genuinely public material.  For every other kind
        nothing derived from the value is stored: a hash prefix plus the exact
        length is an offline oracle for low-entropy secrets, and it would end
        up in listings and backup archives outside the audited ``reveal`` path.
        """
        if kind == "ssh_private_key":
            from . import sshwire  # lazy: pure-Python key parsing

            try:
                key = sshwire.parse_openssh_private_key(value)
            except sshwire.WireError as exc:
                raise InvalidInput("ssh_private_key_invalid", exc.__class__.__name__) from exc
            return {"public_key": key.public.to_authorized_key(key.comment), "fingerprint": key.public.fingerprint(),
                    "algorithm": "ssh-ed25519"}
        return {}

    # writes --------------------------------------------------------------
    def put_secret(self, secret_id: str, kind: str, value: bytes, project: str, environment: str,
                   activate: bool = True) -> int:
        validate_name(secret_id, "secret_id")
        if kind not in SECRET_KINDS:
            raise InvalidInput("invalid_secret_kind")
        if not isinstance(value, (bytes, bytearray)) or not value or len(value) > MAX_SECRET_BYTES:
            raise InvalidInput("invalid_secret_value")
        self.projects.require_environment(project, environment)
        public = self._public_metadata(kind, bytes(value))
        with self.state.lock():
            doc = self._doc()
            entry = doc["secrets"].get(secret_id)
            if entry is None:
                entry = {"project": project, "environment": environment, "kind": kind,
                         "created_at": iso(), "active_version": None, "versions": {}}
                doc["secrets"][secret_id] = entry
            elif (entry["project"], entry["environment"], entry["kind"]) != (project, environment, kind):
                raise InvalidInput("secret_identity_mismatch")
            version = max((int(v) for v in entry["versions"]), default=0) + 1
            record = self._encrypt(secret_id, version, bytes(value))
            record.update({"created_at": iso(), "status": "active" if activate else "staged", "public": public})
            entry["versions"][str(version)] = record
            if activate:
                previous = entry["active_version"]
                entry["active_version"] = version
                if previous is not None and entry["versions"][str(previous)]["status"] == "active":
                    entry["versions"][str(previous)]["status"] = "retired"
            self.state.write_json(VAULT_DOC, doc)
            rebound = self._rebind_connections(secret_id) if activate else []
        self.audit.record("secret_put", result="ok", extra={"secret_id": secret_id, "version": version, "kind": kind,
                                                           "project": project, "environment": environment})
        self._audit_rebound(secret_id, rebound)
        return version

    def _rebind_connections(self, secret_id: str) -> list[Any]:
        """Bind unpinned connections to the secret's new active version (call with the state lock held).

        Inside the same lock as the vault write, so no relay or signature can
        be counted between the version change and the policy-version bump.
        """
        from .policy import Policy  # lazy: policy reads vault metadata, never the other way round at import

        return Policy(self.state).credential_versions_changed(secret_id)

    def _audit_rebound(self, secret_id: str, connections: list[Any]) -> None:
        for connection in connections:
            self.audit.record("connection_update", connection=connection.id, result="ok",
                              policy_version=connection.policy_version,
                              extra={"detail": "credential_version", "secret_id": secret_id, "state": "reevaluated"})

    def set_version_status(self, secret_id: str, version: int, status: str) -> None:
        if status not in VERSION_STATES:
            raise InvalidInput("invalid_version_status")
        with self.state.lock():
            doc = self._doc()
            entry = doc["secrets"].get(secret_id)
            if entry is None or str(version) not in entry["versions"]:
                raise NotFound("secret_version_not_found")
            record = entry["versions"][str(version)]
            if record["status"] == "revoked" and status != "revoked":
                raise InvalidInput("version_revoked")
            if status == "revoked":
                from .policy import append_revocation

                append_revocation(self.state, "secret_version", secret_id=secret_id, version=int(version))
            record["status"] = status
            before_active = entry["active_version"]
            if status == "active":
                previous = entry["active_version"]
                entry["active_version"] = version
                if previous is not None and previous != version and entry["versions"][str(previous)]["status"] == "active":
                    entry["versions"][str(previous)]["status"] = "retired"
            elif entry["active_version"] == version:
                entry["active_version"] = None
            self.state.write_json(VAULT_DOC, doc)
            rebound = self._rebind_connections(secret_id) if entry["active_version"] != before_active else []
        event = {"retired": "secret_retire", "revoked": "secret_revoke"}.get(status, "rotation")
        self.audit.record(event, result="ok", extra={"secret_id": secret_id, "version": version, "state": status})
        self._audit_rebound(secret_id, rebound)

    # reads ---------------------------------------------------------------
    def list_secrets(self, project: str | None = None, environment: str | None = None) -> list[SecretMeta]:
        result = []
        for secret_id, entry in sorted(self._doc()["secrets"].items()):
            if project and entry["project"] != project:
                continue
            if environment and entry["environment"] != environment:
                continue
            versions = tuple(
                VersionMeta(secret_id, int(v), r["status"], r["created_at"], dict(r.get("public") or {}))
                for v, r in sorted(entry["versions"].items(), key=lambda item: int(item[0]))
            )
            result.append(SecretMeta(secret_id, entry["project"], entry["environment"], entry["kind"],
                                     entry["active_version"], versions))
        return result

    def get_meta(self, secret_id: str) -> SecretMeta:
        for meta in self.list_secrets():
            if meta.id == secret_id:
                return meta
        raise NotFound("secret_not_found")

    def resolve_version(self, secret_id: str, version: int | None) -> int:
        meta = self.get_meta(secret_id)
        if version is None:
            if meta.active_version is None:
                raise NotFound("secret_no_active_version")
            return meta.active_version
        for item in meta.versions:
            if item.version == version:
                return version
        raise NotFound("secret_version_not_found")

    def secret_for_trusted_use(self, secret_id: str, version: int | None = None) -> bytes:
        """Plaintext for in-process trusted components.  Never exposed to agents."""
        entry = self._doc()["secrets"].get(secret_id)
        if entry is None:
            raise NotFound("secret_not_found")
        resolved = self.resolve_version(secret_id, version)
        record = entry["versions"][str(resolved)]
        if record["status"] not in ("active", "staged"):
            raise NotFound("secret_version_unusable", record["status"])
        return self._decrypt(secret_id, resolved, record)

    def values_for_trusted_scan(self) -> list[bytes]:
        """Plaintext of every version of every secret (any status), for in-process leak comparisons only.

        Used to keep vault values out of CLI profile environments: a retired,
        revoked or other project's value is just as secret as the current one.
        Never returned to a caller outside the trusted process.
        """
        values: list[bytes] = []
        for secret_id, entry in sorted(self._doc()["secrets"].items()):
            for version, record in sorted(entry["versions"].items(), key=lambda item: int(item[0])):
                values.append(self._decrypt(secret_id, int(version), record))
        return values

    def reveal(self, secret_id: str, version: int | None, admin: AdminAuth, now: float | None = None) -> bytes:
        """Administrator single-secret read: fresh re-auth + audit first, then decrypt."""
        if not admin.fresh(now):
            self.audit.record("secret_reveal_denied", result="denied", reason="admin_reauth_stale",
                              extra={"secret_id": secret_id})
            raise AuthFailed("admin_reauth_stale")
        resolved = self.resolve_version(secret_id, version)
        self.audit.record("secret_reveal", result="ok", extra={"secret_id": secret_id, "version": resolved})
        entry = self._doc()["secrets"][secret_id]
        return self._decrypt(secret_id, resolved, entry["versions"][str(resolved)])

    # backup / restore ----------------------------------------------------
    BACKUP_DOCS = (VAULT_DOC, "projects.json", "policy/principals.json", "policy/connections.json",
                   "policy/grants.json", "policy/control.json")

    def backup(self, out_path: Path) -> dict[str, Any]:
        """Encrypted backup: ciphertexts plus the KMS- and recovery-wrapped DEK.

        The archive contains no plaintext.  Without the KMS master key or the
        recovery passphrase it cannot be decrypted.
        """
        documents: dict[str, Any] = {}
        with self.state.lock():
            for name in self.BACKUP_DOCS:
                documents[name] = self.state.read_json(name, None)
        payload = json.dumps(documents, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest = hashlib.sha256(payload).hexdigest()
        manifest = {"format": "zeropw-backup-v1", "created_at": iso(), "sha256": digest,
                    "kms_key_id": self.kms.key_id, "backup_id": secrets.token_hex(8)}
        archive = {"manifest": manifest, "documents": documents}
        out_path = Path(out_path)
        # A fresh O_EXCL|O_NOFOLLOW 0600 temp file with an unpredictable name in the
        # destination directory: a pre-planted file or symlink at a guessable
        # path can neither redirect the write nor keep a permissive mode.
        fd, tmp_name = tempfile.mkstemp(prefix=f".{out_path.name}.", suffix=".tmp", dir=out_path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(archive, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp_name, out_path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
        self.audit.record("backup", result="ok", extra={"backup_id": manifest["backup_id"], "digest": digest})
        return manifest

    @staticmethod
    def reapply_revocations(state: StateDir) -> dict[str, int]:
        """Re-apply every known revocation to the current state (idempotent).

        Sources are the revocation ledger (``policy/revocations.jsonl``, never
        part of a backup) and the audit log's revocation events.  Grants stay
        revoked, principals and connections stay disabled and secret versions
        stay revoked, whatever an archive says.  Returns the number of records
        that had to change, per kind.
        """
        from .audit import AUDIT_FILE
        from .policy import Policy, collect_revocations

        records: list[dict[str, Any]] = []
        for line in state.read_lines(AUDIT_FILE, None):
            try:
                record = json.loads(line) if line.strip() else None
            except ValueError:
                continue
            if isinstance(record, dict):
                records.append(record)
        revocations = collect_revocations(state, records)
        with state.lock():
            counts = Policy(state).reapply_revocations(revocations)
            doc = state.read_json(VAULT_DOC, None)
            changed = 0
            secrets_doc = doc.get("secrets") if isinstance(doc, dict) else None
            for secret_id, version in sorted(revocations.secret_versions):
                entry = secrets_doc.get(secret_id) if isinstance(secrets_doc, dict) else None
                record = entry.get("versions", {}).get(str(version)) if isinstance(entry, dict) else None
                if not isinstance(record, dict) or record.get("status") == "revoked":
                    continue
                record["status"] = "revoked"
                if entry.get("active_version") == version:
                    entry["active_version"] = None
                changed += 1
            if changed:
                state.write_json(VAULT_DOC, doc)
            counts["secret_versions"] = changed
        return counts

    @staticmethod
    def _merge_restored_approvals(current: Any, archived: Any) -> tuple[dict[str, Any], int]:
        """Approvals after a restore: the current entries win; the archive never reopens one.

        An approval that is approved (or pending) in the archive but consumed,
        invalidated or absent now could otherwise be used a second time, so
        open archive-only entries are dropped.  Closed archive-only entries are
        kept as history.
        """
        merged = {digest: entry for digest, entry in (current or {}).items()} if isinstance(current, dict) else {}
        dropped = 0
        for digest, entry in (archived.items() if isinstance(archived, dict) else ()):
            if digest in merged or not isinstance(entry, dict):
                continue
            if entry.get("status") in ("pending", "approved"):
                dropped += 1
                continue
            merged[digest] = entry
        return merged, dropped

    @staticmethod
    def restore(state: StateDir, in_path: Path, audit: Audit, kms: Kms | None = None) -> dict[str, Any]:
        """Restore documents and leave the system closed until ``restore_ack``.

        Executions stay refused (``restore_pending``) until the administrator
        acknowledges.  ``restore_pending`` is written to the *current* control
        document before any other document is overwritten.  A global stop that
        is set when the restore runs survives it: the archive's control
        document never lifts a stop issued after the backup was taken.

        The archive may pre-date revocations, so after the documents are
        written every known revocation is re-applied (``reapply_revocations``),
        approvals are merged so the archive can never reopen a used one, and
        the handle key is rotated so no handle issued before the restore
        (including a leaked one) works afterwards.

        With ``kms`` given, the archive's wrapped DEK must unwrap under that
        key *before* anything is written (``backup_kms_mismatch`` otherwise);
        a restore that the current KMS cannot open would leave a state
        directory that no command, including ``restore_ack``, can reopen.
        """
        try:
            archive = json.loads(in_path.read_text(encoding="utf-8"))
            manifest = archive["manifest"]
            documents = archive["documents"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise StateError("backup_malformed") from exc
        if not isinstance(manifest, dict) or not isinstance(documents, dict):
            raise StateError("backup_malformed")
        if manifest.get("format") != "zeropw-backup-v1":
            raise StateError("backup_format")
        payload = json.dumps(documents, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if not hmac.compare_digest(hashlib.sha256(payload).hexdigest(), str(manifest.get("sha256"))):
            raise StateError("backup_digest_mismatch")
        backup_id = str(manifest.get("backup_id"))
        vault_doc = documents.get(VAULT_DOC)
        if kms is not None and vault_doc is not None:
            dek = vault_doc.get("dek") if isinstance(vault_doc, dict) else None
            try:
                wrapped = WrappedKey.from_dict(dek) if isinstance(dek, dict) else None
            except StateError as exc:
                raise StateError("backup_malformed") from exc
            if wrapped is None:
                raise StateError("backup_malformed")
            try:
                kms.unwrap(wrapped)
            except StateError as exc:  # KmsError: another key id, or a foreign master key
                audit.record("restore", result="denied", reason="backup_kms_mismatch", extra={"backup_id": backup_id})
                raise StateError("backup_kms_mismatch") from exc
        from .context import HANDLE_KEY  # lazy: context imports this module
        from .handles import HandleIssuer

        control_doc = "policy/control.json"
        with state.lock():
            current = state.read_json(control_doc, None) or {}
            if not isinstance(current, dict):
                current = {}
            # Close execution first: nothing below may be observed with restore_pending unset.
            state.write_json(control_doc, {**current, "restore_pending": True})
            for name in Vault.BACKUP_DOCS:
                if name != control_doc and documents.get(name) is not None:
                    state.write_json(name, documents[name])
            archived_control = documents.get(control_doc)
            control = dict(archived_control) if isinstance(archived_control, dict) else {}
            if current.get("stopped"):
                control["stopped"] = True
                control["stopped_at"] = current.get("stopped_at")
            control["approvals"], dropped = Vault._merge_restored_approvals(current.get("approvals"),
                                                                            control.get("approvals"))
            control["approval_history"] = list(current.get("approval_history") or [])
            control["restore_pending"] = True
            control["restored_from"] = manifest.get("backup_id")
            control["restored_at"] = iso()
            state.write_json(control_doc, control)
            reapplied = Vault.reapply_revocations(state)
            reapplied["approvals_dropped"] = dropped
            control = state.read_json(control_doc, None) or {}
            control["restore_reapplied"] = reapplied
            state.write_json(control_doc, control)
            state.write_bytes(HANDLE_KEY, HandleIssuer.generate_key())
        audit.record("restore", result="ok", extra={"backup_id": backup_id, "state": "restore_pending",
                                                     "count": sum(reapplied.values())})
        return manifest
