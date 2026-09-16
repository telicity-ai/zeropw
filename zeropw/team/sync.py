"""Team sync: session management, message loop, and the commit/fact apply
pipeline for every shared environment a node has (docs/team-sync.md sections
6.3-6.6, 7.4).

``TeamSync`` is attached to a running ``Context`` as ``ctx.team``.  It owns:

* a per-environment ``CommitStore`` (reused from ``zeropw/team/commit.py``)
  and an in-memory ``Facts`` accumulator (``zeropw/team/fold.py``) rebuilt
  from ``team/<env_id>/facts.jsonl`` at startup;
* the address book (``team/<env_id>/peers.json``) and the live/backoff state
  of one outbound session per known active member, plus inbound sessions
  accepted from the listener;
* the ``VECTOR``/``COMMIT``/``FACT``/``PEERS``/``INCIDENT`` message loop
  (section 6.3) and the fold-and-derive apply step (section 6.5) that runs
  every time a commit is accepted or a fact is applied.

Nothing here decides *whether* to run a team listener -- that is
``zeropw/admin_cli.py``'s ``--team-listen`` flag.  A ``TeamSync`` with no
listener address still dials every known peer address and answers to
whatever ``Transport`` it was given (the in-process transport in tests never
needs a real socket).

Facts (section 7.4)
--------------------
Stage 1 (``zeropw/team/fold.py``) already defines ``Facts`` as an in-memory,
order-independent input to ``fold()``.  This module adds the wire format, the
signature, the append-only ``facts.jsonl`` persistence, and the role checks
at receipt time so a monotone fact keeps applying across restarts and
independently of which commits a node happens to have.  ``member_removed``
is the one exception to "the author must currently be an active member": two
admins removing each other at the same time must both take effect (section
7.4's worked example), so its role check reads the author's role from the
document's ``members`` entry (retained, with its role, even after the
member's status flips to ``removed``) rather than requiring the author still
be *active*.  ``incident`` is the other exception -- any presently active
member, admin or user, may author one, since the compromise-response
intrusion detector this hooks into (see below) runs on every node, not only
admin ones.  Every other fact kind requires the author to be a presently
active admin/owner.

Incident sharing (section 9)
-----------------------------
``send_incident``/``send_incident_for_all_envs`` (the latter aliased as
``on_incident_open``, the name the future caller hook is documented under)
are the sender side.  The summary is sanitized against
``INCIDENT_ALLOWED_KEYS`` -- unknown keys and out-of-shape values are
dropped, not merely rejected, since a caller building this from several
value-free sources should not have the whole report thrown away over one bad
field -- then signed as a ``Fact`` of kind ``"incident"`` so it is deduped
and durably persisted in ``facts.jsonl`` exactly like a disable/revoke/
removal fact (``_store_fact``).  Unlike those, it is never broadcast to the
whole mesh: section 3.1 shares incident summaries with admin nodes only, so
it is instead handed directly to every session whose peer is presently an
active admin, using the dedicated ``INCIDENT`` message (section 6.3) rather
than the general ``FACT`` gossip/relay path -- there is deliberately no
multi-hop relay for it, matching the spec's message table, which describes
``INCIDENT`` as node-to-admin-node only. Because a session-only send reaches
nobody who is not connected at that exact moment, with no catch-up
mechanism for a peer that connects later (unlike commits, facts have no
version-vector backfill), delivery alone is not enough for something this
security-sensitive: the signed fact is also queued in
``team/<env_id>/incident_outbox.jsonl`` and retried with exponential backoff
from ``poll()`` until at least one admin peer sends back an ``INCIDENT_ACK``
naming its hash. A receiving admin node persists the summary under
``team/<env_id>/incidents/<sender fingerprint>-<incident id>.json``, folds
its ``secret_ids_mandatory``/``secret_ids_recommended`` into
``team/<env_id>/rotation_flags.json`` as ``rotation_required``/
``rotation_recommended``, and raises a ``team_incident_received`` audit
alert; a non-admin node that happens to receive one (its role changed after
the message was already in flight) does nothing and sends no ack.

This module has no caller for ``on_incident_open`` yet: ``zeropw/incident.py``
and its ``open_incident`` live on ``feature/compromise-response-plan``, not
merged into this branch's base.  Once merged, ``open_incident`` should call
``ctx.team.send_incident_for_all_envs(summary_by_env)`` (guarded by
``getattr(ctx, "team", None) is not None``, since a node with no shared
environment attaches no ``TeamSync``) with one summary per shared
environment the compromise's exposure assessment touched.

Thread model
------------
One poll thread per ``TeamSync`` drives dialing, periodic ``VECTOR``
exchange, deferred-commit release and session re-keying (``poll()``, also
callable directly by ``zeropw/admin_cli.py``'s ``serve`` loop so both a
standalone ``TeamSync`` and one embedded in ``serve`` behave the same way).
Each open session gets its own daemon receive thread.  All on-disk state
mutation happens under ``ctx.state.lock()``; all in-memory bookkeeping
(sessions, address candidates, backoff timers) is under a separate
``threading.RLock`` so a slow dial or a fold never blocks the other.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field, replace
from typing import Any, Callable

from ..errors import AuditUnavailable, InvalidInput, NotFound, PolicyDenied
from ..store import iso
from ..crypto import ed25519
from . import commit as C
from . import envelope
from . import fold as F
from .commit import Hlc
from .identity import DeviceKey, DeviceRecord
from .transport import Session, SessionClosed

FACT_FORMAT = "zeropw-team-fact-v1"
FACT_KINDS = ("connection_disabled", "secret_version_revoked", "member_removed", "incident")
_SEEN_CAPACITY = 4096
_DISCOVERY_INTERVAL_SECONDS = 1.0
_RECV_POLL_SECONDS = 1.0
# Stage 3 (docs/team-sync.md section 7.3, section 14 item 1): a snapshot is saved every this-many
# newly-folded commits, in addition to whenever ``team compact`` explicitly asks for one.
SNAPSHOT_INTERVAL_COMMITS = 1000
# section 7.3's 30-day age floor for a commit to even be a compaction candidate.
COMPACT_MIN_AGE_MS = 30 * 24 * 3600 * 1000
# Ops that must never be deleted by compaction, regardless of age/coverage: membership and DEK
# history is small (bounded by team size, not by how many secrets/connections churn over time) and
# ``commit.receive_commit``'s device registry / this module's ``_relaxed_document`` both reconstruct
# device records by re-folding *raw* commits (snapshot-oblivious, by design -- a snapshot's own
# document has already had ``member_removed`` facts erase a removed member's ``member.add`` per
# ``_relaxed_document``'s docstring below), so keeping these files forever is what keeps signature
# verification working for old commits after everything else around them has been compacted away.
_PROTECTED_OPS = frozenset({"env.init", "member.add", "member.set_role", "member.remove", "owner.transfer",
                            "dek.rotate"})
ENVS_MAP_PATH = "team/envs.json"


def _commit_is_protected(commit_obj: C.Commit) -> bool:
    return any(op.get("op") in _PROTECTED_OPS for op in commit_obj.ops)


# ------------------------------------------------------------- env name mapping
def read_env_mapping(state: Any) -> dict[str, dict[str, str]]:
    """The node-local ``env_id -> {project, environment}`` map (docs/team-sync.md section 12's
    ``--env P/E`` resolution), written by ``zeropw.team.membership.share_environment``/``join``."""
    doc = state.read_json(ENVS_MAP_PATH, {})
    return doc if isinstance(doc, dict) else {}


def write_env_mapping(state: Any, env_id: str, project: str, environment: str) -> None:
    with state.lock():
        doc = read_env_mapping(state)
        doc[env_id] = {"project": project, "environment": environment}
        state.write_json(ENVS_MAP_PATH, doc)


def env_project_environment(state: Any, env_id: str) -> tuple[str | None, str | None]:
    entry = read_env_mapping(state).get(env_id)
    if not isinstance(entry, dict):
        return None, None
    return entry.get("project"), entry.get("environment")


def resolve_env_id(state: Any, project: str, environment: str) -> str | None:
    for env_id, entry in read_env_mapping(state).items():
        if isinstance(entry, dict) and entry.get("project") == project and entry.get("environment") == environment:
            return env_id
    return None

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_FINGERPRINT_RE = re.compile(r"^[a-z2-7]{26}$")
_TOKEN_RE = re.compile(r"^[0-9a-f]{16,64}$")


def _valid_id(value: Any, max_len: int = 64) -> bool:
    return isinstance(value, str) and 0 < len(value) <= max_len and not _CONTROL_RE.search(value)


def _valid_fingerprint(value: Any) -> bool:
    return isinstance(value, str) and bool(_FINGERPRINT_RE.fullmatch(value))


def _valid_token(value: Any) -> bool:
    return isinstance(value, str) and bool(_TOKEN_RE.fullmatch(value))


def _canon(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# -------------------------------------------------------------------- incidents
# Section 9's incident summary schema.  Deliberately split "mandatory" from "recommended" secret
# ids (rather than one list plus a severity tag) so the value shape stays "str/int/list-of-str
# only" per this stage's brief, with no nested objects to bound separately.
INCIDENT_ALLOWED_KEYS = frozenset({
    "incident_id", "ts", "scope", "rule", "secret_ids_mandatory", "secret_ids_recommended",
    "connection_ids", "first_used_at", "last_used_at", "uses",
})
_INCIDENT_STR_KEYS = frozenset({"incident_id", "ts", "scope", "rule", "first_used_at", "last_used_at"})
_INCIDENT_INT_KEYS = frozenset({"uses"})
_INCIDENT_LIST_KEYS = frozenset({"secret_ids_mandatory", "secret_ids_recommended", "connection_ids"})
MAX_INCIDENT_STR_LENGTH = 200
MAX_INCIDENT_LIST_ITEMS = 100
MAX_INCIDENT_UNIT = 2**31 - 1


def _valid_incident_str(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= MAX_INCIDENT_STR_LENGTH and not _CONTROL_RE.search(value)


def _valid_incident_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_INCIDENT_UNIT


def _valid_incident_list(value: Any) -> bool:
    return (isinstance(value, list) and len(value) <= MAX_INCIDENT_LIST_ITEMS
            and all(isinstance(v, str) and 0 < len(v) <= 64 and not _CONTROL_RE.search(v) for v in value))


def sanitize_incident_summary(summary: Any) -> dict[str, Any]:
    """Section 9/deliverable 1's sender-side sanitizer: keep only ``INCIDENT_ALLOWED_KEYS``, drop
    (never raise on) any key outside that set or any value that is not str/int/list-of-str within
    its bounds -- a caller assembling this from several value-free sources should not lose the
    whole report over one malformed field.  ``incident_id`` is the sole exception: it identifies
    the on-disk record and the outbox/ack entry, so a missing or malformed one is a hard error --
    and it is held to ``_valid_token``'s stricter hex-only shape (matching ``version_id``,
    ``generation_id``), not the looser ``_valid_id``, because it becomes a literal path component
    (``_incident_record_path``): a free-form string here would open a path-traversal hole no other
    id-shaped field in this module has to guard against.
    """
    if not isinstance(summary, dict) or not _valid_token(summary.get("incident_id")):
        raise InvalidInput("team_incident_summary_invalid")
    clean: dict[str, Any] = {"incident_id": summary["incident_id"]}
    for key, value in summary.items():
        if key == "incident_id" or key not in INCIDENT_ALLOWED_KEYS:
            continue
        if key in _INCIDENT_STR_KEYS and _valid_incident_str(value):
            clean[key] = value
        elif key in _INCIDENT_INT_KEYS and _valid_incident_int(value):
            clean[key] = value
        elif key in _INCIDENT_LIST_KEYS and _valid_incident_list(value):
            deduped = sorted(set(value))[:MAX_INCIDENT_LIST_ITEMS]
            if deduped:
                clean[key] = deduped
    return clean


# ---------------------------------------------------------------------- facts
def _validate_fact_target(kind: str, target: Any) -> None:
    if not isinstance(target, dict):
        raise InvalidInput("team_fact_target_invalid")
    if kind == "connection_disabled":
        if set(target) != {"connection_id"} or not _valid_id(target["connection_id"], 64):
            raise InvalidInput("team_fact_target_invalid")
    elif kind == "secret_version_revoked":
        if set(target) != {"secret_id", "version_id"} or not _valid_id(target["secret_id"], 64) \
                or not _valid_token(target["version_id"]):
            raise InvalidInput("team_fact_target_invalid")
    elif kind == "member_removed":
        if set(target) != {"fingerprint"} or not _valid_fingerprint(target["fingerprint"]):
            raise InvalidInput("team_fact_target_invalid")
    elif kind == "incident":
        # incident_id becomes a literal path component (_incident_record_path): hold it to
        # _valid_token's hex-only shape, not the looser _valid_id, to rule out path traversal.
        if not _valid_token(target.get("incident_id")) or not set(target).issubset(INCIDENT_ALLOWED_KEYS):
            raise InvalidInput("team_fact_target_invalid")
        for key, value in target.items():
            if key in _INCIDENT_STR_KEYS:
                ok = _valid_incident_str(value)
            elif key in _INCIDENT_INT_KEYS:
                ok = _valid_incident_int(value)
            elif key in _INCIDENT_LIST_KEYS:
                ok = _valid_incident_list(value)
            else:
                ok = False
            if not ok:
                raise InvalidInput("team_fact_target_invalid")
    else:
        raise InvalidInput("team_fact_kind_unknown")


@dataclass(frozen=True)
class Fact:
    """A signed, order-independent statement (docs/team-sync.md section 7.4)."""

    format: str
    env_id: str
    kind: str
    target: dict
    author: str
    hlc: str
    sig: str

    def _canonical(self, include_sig: bool) -> dict:
        data = {"format": self.format, "env_id": self.env_id, "kind": self.kind,
                "target": dict(sorted(self.target.items())), "author": self.author, "hlc": self.hlc}
        if include_sig:
            data["sig"] = self.sig
        return data

    def canonical_json(self, include_sig: bool) -> bytes:
        return _canon(self._canonical(include_sig))

    @property
    def hash(self) -> str:
        return hashlib.sha256(self.canonical_json(True)).hexdigest()

    def to_dict(self) -> dict:
        return self._canonical(True)

    @classmethod
    def from_dict(cls, data: Any) -> "Fact":
        if not isinstance(data, dict):
            raise InvalidInput("team_fact_malformed")
        try:
            target = {str(k): v for k, v in dict(data["target"]).items()}
            return cls(format=str(data["format"]), env_id=str(data["env_id"]), kind=str(data["kind"]),
                       target=target, author=str(data["author"]), hlc=str(data["hlc"]), sig=str(data["sig"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidInput("team_fact_malformed") from exc


def sign_fact(device: DeviceKey, env_id: str, kind: str, target: dict, hlc_value: str) -> Fact:
    _validate_fact_target(kind, target)
    unsigned = Fact(FACT_FORMAT, env_id, kind, dict(target), device.fingerprint, hlc_value, "")
    sig = base64.b64encode(device.sign(unsigned.canonical_json(False))).decode("ascii")
    return replace(unsigned, sig=sig)


def verify_fact(fact: Fact, author_record: DeviceRecord) -> bool:
    if fact.format != FACT_FORMAT or fact.author != author_record.fingerprint or fact.kind not in FACT_KINDS:
        return False
    try:
        _validate_fact_target(fact.kind, fact.target)
        Hlc.parse(fact.hlc)
        sig = base64.b64decode(fact.sig, validate=True)
    except (InvalidInput, ValueError, TypeError):
        return False
    return ed25519.verify(author_record.sign_pub, fact.canonical_json(False), sig)


def _apply_fact_to_facts(facts: F.Facts, fact: Fact) -> None:
    if fact.kind == "connection_disabled":
        facts.disabled_connections.add(fact.target["connection_id"])
    elif fact.kind == "secret_version_revoked":
        facts.revoked_versions.add((fact.target["secret_id"], fact.target["version_id"]))
    elif fact.kind == "member_removed":
        facts.removed_members.add(fact.target["fingerprint"])
    elif fact.kind == "incident":
        facts.incidents.append(dict(fact.target))


def _is_admin(doc: dict, fp: str) -> bool:
    member = doc.get("members", {}).get(fp)
    if not member or member.get("status") != "active":
        return False
    return fp == doc.get("owner") or member.get("role") == "admin"


def _fact_role_ok(doc: dict, kind: str, author_fp: str, target: dict) -> bool:
    """Section 7.4's role check, done at receipt time against the current folded document.

    ``member_removed`` alone is exempt from requiring the author still be
    *active*: two admins removing each other in the same instant must both
    take effect, so this checks the author's recorded ``role`` (retained
    after removal) rather than their current status.  ``incident`` is looser
    in the other direction: any presently active member (admin or user) may
    author one -- the intrusion detector it reports from runs on every node,
    not only admin ones (section 9 names no role restriction on the sender).
    """
    members = doc.get("members", {})
    if kind == "member_removed":
        target_fp = target.get("fingerprint")
        if target_fp == doc.get("owner"):
            return False  # the owner is never a removal target (docs/team-sync.md sections 4.4, 8)
        member = members.get(author_fp)
        privileged = author_fp == doc.get("owner") or (member is not None and member.get("role") == "admin")
        return privileged or author_fp == target_fp
    if kind == "incident":
        member = members.get(author_fp)
        return member is not None and member.get("status") == "active"
    return _is_admin(doc, author_fp)


# ------------------------------------------------------------------- discover
def load_facts(state: Any, env_id: str) -> tuple["F.Facts", set, dict]:
    """Rebuild ``Facts`` plus the raw hash set and ``member_removed`` authorship map from
    ``team/<env_id>/facts.jsonl`` (module-level so both ``TeamSync`` and
    ``zeropw.team.membership``'s node-local, no-live-``TeamSync`` command path can load the exact
    same monotone state without either one needing a live ``TeamSync`` instance)."""
    facts = F.Facts()
    hashes: set = set()
    removal_authors: dict[str, set] = {}
    for line in state.read_lines(f"team/{env_id}/facts.jsonl", None) or []:
        if not line:
            continue
        try:
            fact = Fact.from_dict(json.loads(line))
        except (ValueError, InvalidInput):
            continue
        if fact.hash in hashes:
            continue
        hashes.add(fact.hash)
        _apply_fact_to_facts(facts, fact)
        if fact.kind == "member_removed":
            removal_authors.setdefault(fact.target["fingerprint"], set()).add(fact.author)
    return facts, hashes, removal_authors


def discover_envs(state: Any) -> list[str]:
    root = state.path / "team"
    if not root.is_dir():
        return []
    found = []
    for child in sorted(root.iterdir()):
        if not child.is_dir() or not C.valid_env_id(child.name):
            continue
        if (child / "commits").is_dir() or (child / "snapshots").is_dir() or (child / "facts.jsonl").exists():
            found.append(child.name)
    return found


class _LruSet:
    """A bounded set used to dedupe rebroadcast of already-seen commit/fact hashes."""

    def __init__(self, capacity: int = _SEEN_CAPACITY) -> None:
        self._capacity = capacity
        self._data: "OrderedDict[str, None]" = OrderedDict()
        self._lock = threading.Lock()

    def add_if_new(self, key: str) -> bool:
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
                return False
            self._data[key] = None
            if len(self._data) > self._capacity:
                self._data.popitem(last=False)
            return True


@dataclass
class _EnvState:
    env_id: str
    store: C.CommitStore
    facts: F.Facts = field(default_factory=F.Facts)
    fact_hashes: set = field(default_factory=set)
    hlc: Hlc = field(default_factory=Hlc)
    document: dict = field(default_factory=dict)
    version_index: dict = field(default_factory=dict)
    sessions: dict = field(default_factory=dict)               # fingerprint -> Session
    candidate_addresses: dict = field(default_factory=dict)    # fingerprint -> set[str]
    backoff: dict = field(default_factory=dict)                # fingerprint -> seconds
    next_attempt: dict = field(default_factory=dict)           # fingerprint -> monotonic time
    last_vector_sent: dict = field(default_factory=dict)       # fingerprint -> monotonic time
    synced_at: float | None = None
    # target fingerprint -> set of fingerprints that authored a member_removed fact naming it.
    # Built from facts.jsonl at load time and kept live as new member_removed facts are stored;
    # used only to evaluate the precise section 7.4 mutual-removal exemption (see
    # ``_document_for_removal_author_check``), never to decide anything else.
    removal_authors: dict = field(default_factory=dict)
    # Stage 3 additions -----------------------------------------------------------------------
    # fingerprint -> the last VECTOR that peer sent us, persisted to peer_vectors.json; used only
    # by ``compact()`` to decide whether every active member is known to already have a commit.
    peer_vectors: dict = field(default_factory=dict)
    # The version vector as of the last time this env's on-disk CommitStore was inspected for
    # commits this process did not itself just accept via ``_handle_commit``/``submit_commit`` --
    # i.e. commits a *different* process (the admin CLI) wrote directly.  ``poll()`` compares the
    # current store vector against this to notice and broadcast them (section 12: "commits it
    # creates must be ... applied locally; the running serve's TeamSync must pick it up on next
    # poll() ... and broadcast them").
    last_known_vector: dict = field(default_factory=dict)
    # Number of facts.jsonl lines already processed, for the same reason as ``last_known_vector``
    # but for facts (a `connection disable`/`secret revoke` issued through the admin CLI on a
    # shared environment while a separate `serve` is running).
    known_fact_lines: int = 0
    # Total commits (sum of the vector) reflected in the last snapshot this process saved/loaded;
    # a new snapshot is saved once ``poll()``'s running total exceeds this by
    # ``SNAPSHOT_INTERVAL_COMMITS`` (section 7.3) or when ``compact()`` saves one explicitly.
    last_snapshot_total: int = 0
    # A cheap cache for ``_relaxed_document``: (sorted store-vector items, document) -- re-folding
    # every known commit on every inbound FACT/handshake is wasteful once the vector has not moved
    # since the last time it was computed.
    relaxed_cache: tuple | None = None
    # Stage 4 additions -----------------------------------------------------------------------
    # Section 9's outbox: fact hash -> the signed incident Fact, for every incident this node has
    # originated (or is relaying on behalf of a caller -- there is only one, this node itself,
    # since incidents are not relayed) that no admin peer has acknowledged yet.  Persisted to
    # ``team/<env_id>/incident_outbox.jsonl`` so it survives a restart; ``incident_backoff``/
    # ``incident_next_attempt`` are purely in-memory retry bookkeeping, mirroring ``backoff``/
    # ``next_attempt`` above.
    incident_outbox: dict = field(default_factory=dict)         # fact hash -> Fact
    incident_backoff: dict = field(default_factory=dict)        # fact hash -> seconds
    incident_next_attempt: dict = field(default_factory=dict)   # fact hash -> monotonic time
    # Section 7.2's "team_op_overridden" alert bookkeeping: signatures of (my overridden commit
    # hash, the commit hash that overrode it) already alerted on, so a repeat _refold (every poll
    # tick re-folds unconditionally) does not write the same alert over and over.  Persisted to
    # ``team/<env_id>/overridden_alerted.json``.
    alerted_overrides: set = field(default_factory=set)


class TeamSync:
    """Section 6/7.4's runtime, attached to a ``Context`` as ``ctx.team``.

    ``transport``'s ``membership`` and ``on_handshake_failed`` hooks are
    rebound to this instance's own methods here -- the transport is
    constructed first (so ``serve --team-listen`` can pick TCP vs. a test's
    in-process transport) but its handshake decisions always need this
    node's *current* view of membership across every shared environment, not
    a snapshot fixed at construction time.
    """

    def __init__(self, ctx: Any, transport: Any, device: DeviceKey) -> None:
        self.ctx = ctx
        self.transport = transport
        self.device = device
        transport.membership = self._membership
        transport.on_handshake_failed = self._on_handshake_failed
        transport.invite_check = self._invite_check
        self._envs: dict[str, _EnvState] = {}
        self._lock = threading.RLock()
        self._commit_seen = _LruSet()
        self._fact_seen = _LruSet()
        self._stop = threading.Event()
        self._poll_thread: threading.Thread | None = None
        self._session_threads: list[threading.Thread] = []
        self._listen_address: str | None = None
        self._tick_seconds = 0.05
        self._last_discovery = 0.0
        # env_id -> {joining device fingerprint -> {"role", "name"}}, populated by ``_invite_check``
        # (docs/team-sync.md section 6.2's msg3 invite proof, verified on the *responder* side) and
        # consumed by ``_maybe_admit_invited_member`` right after that same handshake completes and
        # the session is accepted, to author the ``member.add`` commit (section 4.3 step 3).
        self._pending_invite_grants: dict[str, dict[str, dict]] = {}

    # ------------------------------------------------------------- lifecycle
    def start(self, listen_address: str | None = None) -> None:
        with self._lock:
            self._discover_locked()
        if listen_address is not None:
            self.transport.listen(listen_address, self._on_inbound_session)
            self._listen_address = listen_address
        self._stop.clear()
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True, name="team-sync-poll")
        self._poll_thread.start()

    def _poll_loop(self) -> None:
        while not self._stop.wait(self._tick_seconds):
            try:
                self.poll()
            except Exception:
                pass  # a transient failure must never kill the sync loop; the next tick retries

    def stop(self) -> None:
        self._stop.set()
        thread, self._poll_thread = self._poll_thread, None
        if thread is not None:
            thread.join(timeout=5)
        close = getattr(self.transport, "close", None)
        if callable(close):
            close()
        else:
            unlisten = getattr(self.transport, "unlisten", None)
            if callable(unlisten):
                unlisten()
        with self._lock:
            all_sessions = []
            for env in self._envs.values():
                all_sessions.extend(env.sessions.values())
                env.sessions.clear()
        for session in all_sessions:
            session.close()
        threads, self._session_threads = self._session_threads, []
        for t in threads:
            t.join(timeout=5)

    def known_envs(self) -> list[str]:
        with self._lock:
            return sorted(self._envs.keys())

    # --------------------------------------------------------------- loading
    def _discover_locked(self) -> None:
        for env_id in discover_envs(self.ctx.state):
            if env_id not in self._envs:
                self._load_env_locked(env_id)

    def _load_env_locked(self, env_id: str) -> _EnvState:
        facts, hashes, removal_authors = self._read_facts(env_id)
        env = _EnvState(env_id=env_id, store=C.CommitStore(self.ctx.state, env_id), facts=facts, fact_hashes=hashes,
                        removal_authors=removal_authors)
        for fp, addrs in self._read_peers(env_id).items():
            if _valid_fingerprint(fp) and isinstance(addrs, list):
                env.candidate_addresses[fp] = {a for a in addrs if isinstance(a, str)}
        peer_vectors_doc = self.ctx.state.read_json(f"team/{env_id}/peer_vectors.json", {}) or {}
        for fp, vector in peer_vectors_doc.items():
            if _valid_fingerprint(fp) and isinstance(vector, dict):
                env.peer_vectors[fp] = {str(k): int(v) for k, v in vector.items()
                                        if isinstance(v, int) and not isinstance(v, bool)}
        env.known_fact_lines = len(self.ctx.state.read_lines(self._facts_path(env_id), None) or [])
        snapshot = F.load_latest_snapshot(self.ctx.state, env_id)
        if snapshot is not None:
            env.last_snapshot_total = sum((snapshot.get("vector") or {}).values())
        for line in self.ctx.state.read_lines(self._incident_outbox_path(env_id), None) or []:
            if not line:
                continue
            try:
                fact = Fact.from_dict(json.loads(line))
            except (ValueError, InvalidInput):
                continue
            if fact.env_id == env_id and fact.kind == "incident":
                env.incident_outbox[fact.hash] = fact
        alerted = self.ctx.state.read_json(self._overridden_alerted_path(env_id), []) or []
        env.alerted_overrides = {s for s in alerted if isinstance(s, str)}
        self._envs[env_id] = env
        self._refold(env_id)
        env.last_known_vector = dict(env.store.vector())
        return env

    def register_env(self, env_id: str) -> None:
        """Pick up a shared environment that appeared on disk after ``start()`` without waiting a tick."""
        with self._lock:
            if env_id not in self._envs:
                self._load_env_locked(env_id)

    # -------------------------------------------------------------- facts io
    def _facts_path(self, env_id: str) -> str:
        return f"team/{env_id}/facts.jsonl"

    def _incident_outbox_path(self, env_id: str) -> str:
        return f"team/{env_id}/incident_outbox.jsonl"

    def _overridden_alerted_path(self, env_id: str) -> str:
        return f"team/{env_id}/overridden_alerted.json"

    def _read_facts(self, env_id: str) -> tuple[F.Facts, set, dict]:
        return load_facts(self.ctx.state, env_id)

    def _read_peers(self, env_id: str) -> dict:
        return self.ctx.state.read_json(f"team/{env_id}/peers.json", {}) or {}

    def _persist_peer_address(self, env_id: str, fp: str, address: str) -> None:
        with self.ctx.state.lock():
            doc = self._read_peers(env_id)
            addrs = list(doc.get(fp, []))
            if address not in addrs:
                addrs.append(address)
            doc[fp] = addrs
            self.ctx.state.write_json(f"team/{env_id}/peers.json", doc)

    def _persist_peer_vectors(self, env_id: str) -> None:
        with self._lock:
            env = self._envs.get(env_id)
            snapshot = {fp: dict(v) for fp, v in env.peer_vectors.items()} if env is not None else {}
        self.ctx.state.write_json(f"team/{env_id}/peer_vectors.json", snapshot)

    def set_peer_address(self, env_id: str, fingerprint: str, address: str) -> None:
        """Explicit address-book management (``team peers --add``): trusted immediately, unlike a
        gossiped ``PEERS`` address, which is only a dial candidate until a handshake confirms it."""
        if not _valid_fingerprint(fingerprint) or not isinstance(address, str) or not address:
            raise InvalidInput("team_invalid_peer_address")
        with self._lock:
            env = self._envs.get(env_id)
            if env is None:
                raise InvalidInput("team_env_unknown")
            env.candidate_addresses.setdefault(fingerprint, set()).add(address)
        self._persist_peer_address(env_id, fingerprint, address)

    # ------------------------------------------------------------- fold/apply
    def _refold(self, env_id: str) -> None:
        env = self._envs[env_id]
        # The whole read-fold-derive-assign sequence is one atomic unit under the SAME lock:
        # ``ctx.state.lock()`` is a real cross-thread mutex (docs/store.py), so two concurrent
        # ``_refold`` calls (e.g. one node's own ``publish_fact`` racing its session-receiver
        # thread applying a peer's commit or fact) complete one at a time, in acquisition order.
        # Splitting the "compute" and "assign env.document" steps across two separate lock
        # acquisitions would let the slower of two concurrent folds overwrite ``env.document``
        # with a stale result completed after a faster, more-up-to-date one.
        with self.ctx.state.lock():
            commits = env.store.all_commits()
            result = F.fold_with_snapshot(env_id, commits, self.ctx.state, env.facts, audit=self.ctx.audit)
            project, environment = env_project_environment(self.ctx.state, env_id)
            version_index = F.derive_local(result, self.ctx.state, self.ctx.vault, self.ctx.policy, self.ctx.audit,
                                           device=self.device, project=project, environment=environment)
            with self._lock:
                env.document = result.document
                env.version_index = version_index
                env.relaxed_cache = None
            total = sum(result.vector.values())
            if total - env.last_snapshot_total >= SNAPSHOT_INTERVAL_COMMITS:
                F.save_snapshot(self.ctx.state, env_id, total, result)
                env.last_snapshot_total = total
        self._record_overrides(env_id, result.overridden)

    def _record_overrides(self, env_id: str, overridden: list[dict[str, Any]]) -> None:
        """Section 7.2's ``team_op_overridden`` alert: for every override ``fold()`` found where
        THIS device authored the losing op, alert exactly once (``alerted_overrides``, persisted,
        since every ``_refold`` recomputes the whole ``overridden`` list from scratch)."""
        self_fp = self.device.fingerprint
        newly_alerted: list[dict[str, Any]] = []
        with self._lock:
            env = self._envs.get(env_id)
            if env is None:
                return
            for entry in overridden:
                if entry["author"] != self_fp:
                    continue
                signature = f'{entry["hash"]}:{entry["by_hash"]}'
                if signature in env.alerted_overrides:
                    continue
                env.alerted_overrides.add(signature)
                newly_alerted.append(entry)
        if not newly_alerted:
            return
        with self._lock:
            env = self._envs.get(env_id)
            snapshot = sorted(env.alerted_overrides) if env is not None else []
        self.ctx.state.write_json(self._overridden_alerted_path(env_id), snapshot)
        for entry in newly_alerted:
            extra: dict[str, Any] = {"env_id": env_id, "author_seq": entry["author_seq"],
                                     "fingerprint": entry["by_author"]}
            connection_id = entry["target_id"] if entry["target_kind"] == "connection" else None
            if entry["target_kind"] == "secret_active":
                extra["secret_id"] = entry["target_id"]
            try:
                self.ctx.audit.record("team_op_overridden", result="ok", connection=connection_id, extra=extra)
            except AuditUnavailable:
                pass

    def _membership(self, env_id: str, fingerprint: str) -> DeviceRecord | None:
        with self._lock:
            env = self._envs.get(env_id)
            doc = env.document if env is not None else None
        if doc is None:
            return None
        member = doc.get("members", {}).get(fingerprint)
        if not member or member.get("status") != "active":
            return None
        try:
            record = DeviceRecord.from_dict(member["device"])
        except (KeyError, InvalidInput):
            return None
        return record if record.fingerprint == fingerprint else None

    def _relaxed_document(self, env_id: str) -> dict:
        """The folded document with ``removed_members``'s retroactive erasure of the member entry
        (section 7.2/7.4: an out-of-band, persisted fact is fed into every fold from its very
        start, so ``member.add``'s own "never let a removed fingerprint (re)exist" check --
        section 5.3 -- also skips the ORIGINAL add, not just a later re-add) turned off, so a
        removed member's device record stays resolvable for SIGNATURE VERIFICATION only.  Never
        use this for an authorization decision: it un-removes everyone, unconditionally.  The
        precise, authorization-safe version of "who may still act despite being removed" is
        ``_document_for_removal_author_check``.

        Cached by the store's version vector (stage 3): as long as no new commit has been accepted
        for this environment since the last call, the previous result is reused instead of
        re-folding the whole commit log again -- ``_known_device_record`` calls this once per
        inbound FACT and once per inbound handshake, so this matters under the
        ``TcpTransport.max_connections`` concurrency cap.  Deliberately snapshot-oblivious (always
        folds every *raw* commit, never a compacted snapshot's document): ``compact()`` never
        deletes a commit whose op could affect this fold (``sync._PROTECTED_OPS``), specifically so
        that this reconstruction keeps working after compaction.
        """
        env = self._envs[env_id]
        vector_key = tuple(sorted(env.store.vector().items()))
        cached = env.relaxed_cache
        if cached is not None and cached[0] == vector_key:
            return cached[1]
        relaxed_facts = env.facts.copy()
        relaxed_facts.removed_members = set()
        document = F.fold(env_id, env.store.all_commits(), relaxed_facts).document
        env.relaxed_cache = (vector_key, document)
        return document

    def _document_for_removal_author_check(self, env_id: str, author_fp: str, target_fp: str) -> dict:
        """The document to authorize "author_fp removes target_fp" against (section 7.4).

        Two admins removing each other in the same instant must both succeed: evaluating
        "author_fp removes target_fp" must not treat author_fp as disqualified-by-removal when
        the ONLY fact that removed author_fp was itself authored by target_fp.  This drops
        author_fp from ``removed_members`` for THIS check alone, and only under that exact
        condition -- an author removed by anyone ELSE (or by nobody) is unaffected: removal by a
        third party is never undone, so a fingerprint removed by Z can never go on to remove
        someone else by exploiting this exemption.
        """
        env = self._envs[env_id]
        removed_by = env.removal_authors.get(author_fp, ())
        if author_fp not in env.facts.removed_members or set(removed_by) != {target_fp}:
            return env.document  # removed by anyone other than the target (too): no exemption
        relaxed_facts = env.facts.copy()
        relaxed_facts.removed_members = set(relaxed_facts.removed_members) - {author_fp}
        return F.fold(env_id, env.store.all_commits(), relaxed_facts).document

    def _known_device_record(self, env_id: str, fingerprint: str) -> DeviceRecord | None:
        env = self._envs.get(env_id)
        if env is None:
            return None
        member = self._relaxed_document(env_id).get("members", {}).get(fingerprint)
        if member is None:
            return None
        try:
            record = DeviceRecord.from_dict(member["device"])
        except (KeyError, InvalidInput):
            return None
        return record if record.fingerprint == fingerprint else None

    def _active_member_fps(self, env_id: str) -> list[str]:
        doc = self._envs[env_id].document
        return [fp for fp, m in doc.get("members", {}).items() if m.get("status") == "active"]

    # -------------------------------------------------------------- sessions
    def _accept_or_replace_session(self, env_id: str, session: Session, *, inbound: bool) -> bool:
        """Resolve a same-peer session collision deterministically; returns whether ``session``
        becomes (or stays) the canonical one.

        Two nodes maintaining "one outbound session per known peer" (section
        6.4) while both also accept inbound sessions can each complete a
        connection to the other at almost the same moment.  Rather than
        coordinate that over the wire, both sides apply the same rule
        independently: the fingerprint that sorts lower keeps its own
        outbound dial; the higher one keeps the inbound connection accepted
        from the lower one.  A one-directional setup (this node only ever
        dials out, or only ever listens) never collides at all, so this is a
        no-op there.
        """
        fp = session.peer.fingerprint
        prefer_outbound = self.device.fingerprint < fp
        with self._lock:
            env = self._envs.get(env_id)
            if env is None:
                return False
            current = env.sessions.get(fp)
            if current is None or current is session:
                env.sessions[fp] = session
                return True
            keep_new = (not inbound) if prefer_outbound else inbound
            if keep_new:
                env.sessions[fp] = session
            losing = session if not keep_new else current
        losing.close()
        return keep_new

    def _on_inbound_session(self, session: Session) -> None:
        env_id = session.env_id
        with self._lock:
            env = self._envs.get(env_id)
            if env is None:
                session.close()
                return
        if not self._accept_or_replace_session(env_id, session, inbound=True):
            return
        self._maybe_admit_invited_member(env_id, session.peer)
        self._audit_session_open(env_id, session.peer.fingerprint)
        self._start_receiver(env_id, session)
        self._send_vector(env_id, session)
        self._send_peers(env_id, session)
        self._retry_pending_incidents_to(env_id, session)

    # ------------------------------------------------------------ invites (section 4.3)
    def _invite_check(self, env_id: str, initiator_record: DeviceRecord, transcript_hash: bytes,
                      proof: bytes) -> bool:
        """``transport.invite_check`` (section 6.2 msg3): verify a joining device's invite proof and,
        on success, remember its granted role/name for ``_maybe_admit_invited_member`` to turn into
        a ``member.add`` commit once the handshake finishes.  Never raises: any failure to look up
        or unwrap an invite is indistinguishable from "no matching invite" to the caller.
        """
        from . import membership as M  # lazy: membership builds on sync (TeamSync), not vice versa

        try:
            info = M.consume_invite(self.ctx, env_id, transcript_hash, proof)
        except Exception:
            return False
        if info is None:
            return False
        with self._lock:
            self._pending_invite_grants.setdefault(env_id, {})[initiator_record.fingerprint] = info
        return True

    def _maybe_admit_invited_member(self, env_id: str, record: DeviceRecord) -> None:
        with self._lock:
            pending = self._pending_invite_grants.get(env_id, {}).pop(record.fingerprint, None)
        if pending is None:
            return  # an ordinary reconnect from an already-known member, not a fresh join
        self._admit_member(env_id, record, pending["role"], pending["name"])

    def _admit_member(self, env_id: str, record: DeviceRecord, role: str, name: str) -> None:
        """Author and submit the ``member.add`` commit (section 4.3 step 3): the new device record,
        its invited name/role, and a wrap of every DEK generation this node can itself unwrap (so
        the new member can decrypt every existing shared secret version, not only future ones)."""
        from ..kms import WrappedKey  # lazy: sync.py otherwise has no need of the KMS wrapper type

        env = self._envs[env_id]
        wraps: dict[str, Any] = {}
        for gen_id in env.document.get("dek", {}).get("generations", {}):
            wrapped = self.ctx.state.read_json(f"team/{env_id}/dek/{gen_id}.json", None)
            if not wrapped:
                continue
            try:
                dek = self.ctx.kms.unwrap(WrappedKey.from_dict(wrapped))
            except Exception:
                continue
            wraps[gen_id] = envelope.wrap_dek(dek, env_id, gen_id, record)
        op: dict[str, Any] = {"op": "member.add", "device": record.to_dict(), "name": name, "role": role}
        if wraps:
            op["wraps"] = wraps
        with self._lock:
            seq = env.store.last_seq(self.device.fingerprint) + 1
            hlc_value = env.hlc.tick()
            vector = env.store.vector()
        commit_obj = C.sign_commit(self.device, env_id, seq, hlc_value, vector, [op])
        self.submit_commit(env_id, commit_obj)
        try:
            self.ctx.audit.record("team_member_add", result="ok",
                                  extra={"env_id": env_id, "fingerprint": record.fingerprint, "role": role})
        except AuditUnavailable:
            pass

    def _start_receiver(self, env_id: str, session: Session) -> None:
        def loop() -> None:
            try:
                while True:
                    try:
                        message = session.recv(_RECV_POLL_SECONDS)
                    except SessionClosed:
                        return
                    except Exception:
                        return
                    if message is None:
                        continue
                    try:
                        self._handle_message(env_id, session, message)
                    except Exception:
                        return
            finally:
                self._drop_session(env_id, session.peer.fingerprint, session)

        thread = threading.Thread(target=loop, daemon=True, name="team-session-recv")
        with self._lock:
            self._session_threads.append(thread)
        thread.start()

    def _drop_session(self, env_id: str, fp: str, session: Session | None = None) -> None:
        with self._lock:
            env = self._envs.get(env_id)
            if env is None:
                return
            current = env.sessions.get(fp)
            if current is None or (session is not None and current is not session):
                return
            env.sessions.pop(fp, None)
        current.close()
        self._audit_session_close(env_id, fp)

    def _close_session(self, env_id: str, fp: str) -> None:
        with self._lock:
            env = self._envs.get(env_id)
            session = env.sessions.pop(fp, None) if env is not None else None
        if session is not None:
            session.close()
            self._audit_session_close(env_id, fp)

    def _drop_member_sessions(self, env_id: str, fp: str) -> None:
        with self._lock:
            env = self._envs.get(env_id)
            session = env.sessions.pop(fp, None) if env is not None else None
            if env is not None:
                env.candidate_addresses.pop(fp, None)
                env.backoff.pop(fp, None)
                env.next_attempt.pop(fp, None)
        if session is not None:
            session.close()
            self._audit_session_close(env_id, fp)

    # ------------------------------------------------------------ messaging
    def _send_vector(self, env_id: str, session: Session) -> None:
        vector = self._envs[env_id].store.vector()
        try:
            session.send({"type": "VECTOR", "vector": vector})
        except (SessionClosed, InvalidInput):
            self._drop_session(env_id, session.peer.fingerprint, session)
            return
        with self._lock:
            env = self._envs.get(env_id)
            if env is not None:
                env.last_vector_sent[session.peer.fingerprint] = time.monotonic()
        self._mark_synced(env_id)

    def _send_peers(self, env_id: str, session: Session) -> None:
        peers_doc = self._read_peers(env_id)
        payload = {fp: sorted(a for a in addrs if isinstance(a, str)) for fp, addrs in peers_doc.items()
                  if isinstance(addrs, list)}
        try:
            session.send({"type": "PEERS", "peers": payload})
        except (SessionClosed, InvalidInput):
            self._drop_session(env_id, session.peer.fingerprint, session)

    def _broadcast(self, env_id: str, message: dict, exclude_fp: str | None = None) -> None:
        with self._lock:
            env = self._envs.get(env_id)
            if env is None:
                return
            sessions = [(fp, s) for fp, s in env.sessions.items() if fp != exclude_fp]
        for fp, session in sessions:
            try:
                session.send(message)
            except (SessionClosed, InvalidInput):
                self._drop_session(env_id, fp, session)

    def _mark_synced(self, env_id: str) -> None:
        with self._lock:
            env = self._envs.get(env_id)
            if env is not None:
                env.synced_at = self.ctx.clock()

    def _handle_message(self, env_id: str, session: Session, message: dict) -> None:
        mtype = message.get("type") if isinstance(message, dict) else None
        if mtype == "VECTOR":
            self._handle_vector(env_id, session, message)
        elif mtype == "COMMIT":
            self._handle_commit(env_id, session, message)
        elif mtype == "FACT":
            self._handle_fact(env_id, session, message)
        elif mtype == "PEERS":
            self._handle_peers(env_id, session, message)
        elif mtype == "INCIDENT":
            self._handle_incident(env_id, session, message)
        elif mtype == "INCIDENT_ACK":
            self._handle_incident_ack(env_id, session, message)
        # an unrecognised type is ignored, not a protocol error: forward compatibility.

    def _handle_vector(self, env_id: str, session: Session, message: dict) -> None:
        peer_vector = message.get("vector")
        if not isinstance(peer_vector, dict):
            return
        env = self._envs[env_id]
        clean_peer_vector = {k: v for k, v in peer_vector.items()
                             if isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool) and v >= 0}
        with self._lock:
            env.peer_vectors[session.peer.fingerprint] = clean_peer_vector
        self._persist_peer_vectors(env_id)
        local_vector = env.store.vector()
        to_send: list[C.Commit] = []
        for fp, last_seq in sorted(local_vector.items()):
            their_seq = peer_vector.get(fp, 0)
            if not isinstance(their_seq, int) or isinstance(their_seq, bool) or their_seq < 0:
                their_seq = 0
            for seq in range(their_seq + 1, last_seq + 1):
                found = env.store.get(fp, seq)
                if found is not None:
                    to_send.append(found)
        sent = 0
        for found in to_send:
            try:
                session.send({"type": "COMMIT", "commit": found.to_dict()})
                sent += 1
            except (SessionClosed, InvalidInput):
                self._drop_session(env_id, session.peer.fingerprint, session)
                break
        if sent:
            self._audit_vector(env_id, session.peer.fingerprint, sent)
        self._mark_synced(env_id)

    def _handle_commit(self, env_id: str, session: Session, message: dict) -> None:
        raw = message.get("commit")
        if not isinstance(raw, dict):
            return
        try:
            commit_obj = C.Commit.from_dict(raw)
        except InvalidInput:
            return
        if commit_obj.env_id != env_id:
            return
        env = self._envs[env_id]
        with self.ctx.state.lock():
            result = C.receive_commit(env.store, commit_obj, C.now_ms(), audit=self.ctx.audit)
        if result != "accepted":
            return
        self._refold(env_id)
        if self._commit_seen.add_if_new(commit_obj.hash):
            self._broadcast(env_id, {"type": "COMMIT", "commit": commit_obj.to_dict()},
                            exclude_fp=session.peer.fingerprint)

    def submit_commit(self, env_id: str, commit_obj: C.Commit) -> str:
        """Locally originate (or re-inject) one commit: validate, store, fold+derive, broadcast.

        This is the entry point docs/team-sync.md section 12's stage-3
        ``connection``/``secret``/``rotation`` commands will call once their
        target is a shared environment.  Returns ``receive_commit``'s
        outcome (``"accepted"``, ``"duplicate"``, ``"deferred"`` or
        ``"rejected"``) so a caller can report it back to whoever issued the
        command.
        """
        env = self._envs.get(env_id)
        if env is None:
            raise InvalidInput("team_env_unknown")
        with self.ctx.state.lock():
            result = C.receive_commit(env.store, commit_obj, C.now_ms(), audit=self.ctx.audit)
        if result == "accepted":
            self._refold(env_id)
            if self._commit_seen.add_if_new(commit_obj.hash):
                self._broadcast(env_id, {"type": "COMMIT", "commit": commit_obj.to_dict()})
        return result

    def _handle_fact(self, env_id: str, session: Session, message: dict) -> None:
        raw = message.get("fact")
        if not isinstance(raw, dict):
            return
        try:
            fact = Fact.from_dict(raw)
        except InvalidInput:
            return
        # An "incident" fact travels only as a direct, single-hop INCIDENT message (module
        # docstring, section 9): never accept or relay one that arrives wrapped as an ordinary
        # FACT, which would defeat the "admin nodes only, no mesh-wide relay" delivery model.
        if fact.env_id != env_id or fact.kind not in FACT_KINDS or fact.kind == "incident":
            return
        self._apply_remote_fact(env_id, fact, exclude_fp=session.peer.fingerprint)

    def _validate_incoming_fact(self, env_id: str, fact: Fact) -> bool:
        """Section 7.4's receipt checks, shared by an inbound wire ``FACT`` and one this process
        notices another local process (the admin CLI) already appended to ``facts.jsonl``."""
        env = self._envs[env_id]
        if fact.hash in env.fact_hashes:
            return False
        try:
            _validate_fact_target(fact.kind, fact.target)
        except InvalidInput:
            self._audit_fact_rejected(env_id, fact, "team_fact_target_invalid")
            return False
        author_record = self._known_device_record(env_id, fact.author)
        if author_record is None or not verify_fact(fact, author_record):
            self._audit_fact_rejected(env_id, fact, "team_fact_signature_invalid")
            return False
        if fact.kind == "member_removed":
            role_doc = self._document_for_removal_author_check(env_id, fact.author, fact.target["fingerprint"])
        else:
            role_doc = env.document
        if not _fact_role_ok(role_doc, fact.kind, fact.author, fact.target):
            self._audit_fact_rejected(env_id, fact, "team_fact_not_authorized")
            return False
        return True

    def _apply_remote_fact(self, env_id: str, fact: Fact, exclude_fp: str | None) -> None:
        if not self._validate_incoming_fact(env_id, fact):
            return
        # store_fact (mutates the shared, unlocked env.facts) and refold (reads it) must be one
        # atomic unit relative to another thread doing the same for a DIFFERENT, concurrently
        # arriving fact (this node's own two session-receiver threads, one per peer, are exactly
        # such a pair) -- otherwise a refold that started just before the other fact's mutation
        # lands can finish and overwrite env.document with a result that is missing it.
        with self.ctx.state.lock():
            self._store_fact(env_id, fact)
            self._refold(env_id)
        self._audit_fact_apply(env_id, fact)
        # Broadcast BEFORE dropping the removed member's own session: in a two-node mesh that
        # session may be the only path left to tell them (and to relay onward through them) that
        # they were removed, and closing it first would silently swallow the fact.
        self._broadcast(env_id, {"type": "FACT", "fact": fact.to_dict()}, exclude_fp=exclude_fp)
        if fact.kind == "member_removed":
            self._drop_member_sessions(env_id, fact.target["fingerprint"])

    def _remember_fact(self, env_id: str, fact: Fact) -> None:
        """Update this process's in-memory ``Facts``/dedup bookkeeping only -- no disk write.  Used
        for a fact already persisted by whoever wrote it (``_store_fact`` covers writing it too)."""
        env = self._envs[env_id]
        env.fact_hashes.add(fact.hash)
        _apply_fact_to_facts(env.facts, fact)
        if fact.kind == "member_removed":
            env.removal_authors.setdefault(fact.target["fingerprint"], set()).add(fact.author)

    def _store_fact(self, env_id: str, fact: Fact) -> None:
        with self.ctx.state.lock():
            self.ctx.state.append_line(self._facts_path(env_id), json.dumps(fact.to_dict(), sort_keys=True,
                                                                             separators=(",", ":")))
            env = self._envs[env_id]
            env.known_fact_lines += 1
        self._remember_fact(env_id, fact)

    def publish_fact(self, env_id: str, kind: str, **target: Any) -> dict:
        """Locally originate, sign, apply and broadcast one fact (the ``team ...`` CLI's future entry point)."""
        if kind not in FACT_KINDS:
            raise InvalidInput("team_fact_kind_unknown")
        with self._lock:
            env = self._envs.get(env_id)
            if env is None:
                raise InvalidInput("team_env_unknown")
            hlc_value = env.hlc.tick()
        if kind == "member_removed":
            try:
                _validate_fact_target(kind, target)
            except InvalidInput as exc:
                raise InvalidInput("team_fact_target_invalid") from exc
            role_doc = self._document_for_removal_author_check(env_id, self.device.fingerprint,
                                                                target["fingerprint"])
        else:
            role_doc = env.document
        if not _fact_role_ok(role_doc, kind, self.device.fingerprint, target):
            raise PolicyDenied("team_fact_not_authorized")
        fact = sign_fact(self.device, env_id, kind, dict(target), hlc_value)
        with self.ctx.state.lock():
            self._store_fact(env_id, fact)
            self._refold(env_id)
        self._audit_fact_apply(env_id, fact)
        self._broadcast(env_id, {"type": "FACT", "fact": fact.to_dict()})
        if kind == "member_removed":
            self._drop_member_sessions(env_id, target["fingerprint"])
        return fact.to_dict()

    def _handle_peers(self, env_id: str, session: Session, message: dict) -> None:
        peers = message.get("peers")
        if not isinstance(peers, dict):
            return
        env = self._envs[env_id]
        active_fps = set(self._active_member_fps(env_id))
        with self._lock:
            for fp, addrs in peers.items():
                if not isinstance(fp, str) or fp == self.device.fingerprint or fp not in active_fps:
                    continue
                if not isinstance(addrs, list):
                    continue
                bucket = env.candidate_addresses.setdefault(fp, set())
                for addr in addrs:
                    if isinstance(addr, str) and 0 < len(addr) <= 128:
                        bucket.add(addr)

    def _incident_record_path(self, env_id: str, sender_fp: str, incident_id: str) -> str:
        return f"team/{env_id}/incidents/{sender_fp}-{incident_id}.json"

    def _apply_incident_rotation_flags(self, env_id: str, target: dict) -> None:
        """Section 9's admin-side rotation marker: fold an incident's ``secret_ids_mandatory``/
        ``secret_ids_recommended`` into the SAME ``rotation_flags.json`` ``team remove``'s DEK
        rotation already writes to (``rotation_flags_path`` there), so ``team incidents`` has one
        place to read either source from.  ``rotation_required`` always outranks a later, weaker
        ``rotation_recommended`` for the same secret id; it is never downgraded."""
        from . import membership as M  # lazy: avoids a sync<->membership import cycle (see _invite_check)

        mandatory = target.get("secret_ids_mandatory") or []
        recommended = target.get("secret_ids_recommended") or []
        now = iso(self.ctx.clock())
        with self.ctx.state.lock():
            flags = self.ctx.state.read_json(M._rotation_flags_path(env_id), {}) or {}
            for secret_id in mandatory:
                if isinstance(secret_id, str):
                    flags[secret_id] = {"reason": "rotation_required", "flagged_at": now}
            for secret_id in recommended:
                if isinstance(secret_id, str) and flags.get(secret_id, {}).get("reason") != "rotation_required":
                    flags[secret_id] = {"reason": "rotation_recommended", "flagged_at": now}
            self.ctx.state.write_json(M._rotation_flags_path(env_id), flags)

    def _handle_incident(self, env_id: str, session: Session, message: dict) -> None:
        """Receiver side of section 9's ``INCIDENT`` message.  Verifies the embedded ``Fact`` (any
        active member may author one -- see ``_fact_role_ok``) exactly like an inbound ``FACT``
        would, but never relays it (there is no multi-hop path for incidents; see the module
        docstring) and only a currently-admin node stores it, flags rotation, and alerts -- a
        non-admin node does nothing and sends no ack, so a demoted-since-queued sender's outbox
        entry simply keeps retrying until it reaches an actual admin.
        """
        raw = message.get("fact")
        if not isinstance(raw, dict):
            return
        try:
            fact = Fact.from_dict(raw)
        except InvalidInput:
            return
        if fact.env_id != env_id or fact.kind != "incident" or fact.author != session.peer.fingerprint:
            return  # section 9/6.3: INCIDENT is a direct, single-hop message; never a relay
        author_record = self._known_device_record(env_id, fact.author)
        if author_record is None or not verify_fact(fact, author_record):
            self._audit_fact_rejected(env_id, fact, "team_fact_signature_invalid")
            return
        env = self._envs[env_id]
        if not _fact_role_ok(env.document, "incident", fact.author, fact.target):
            self._audit_fact_rejected(env_id, fact, "team_fact_not_authorized")
            return
        if _is_admin(env.document, self.device.fingerprint):
            incident_id = fact.target.get("incident_id")
            path = self._incident_record_path(env_id, fact.author, incident_id) if _valid_token(incident_id) else None
            if path is not None and not self.ctx.state.exists(path):
                if fact.hash not in env.fact_hashes:
                    self._store_fact(env_id, fact)
                record = dict(fact.target)
                record["received_from"] = fact.author
                record["received_at"] = iso(self.ctx.clock())
                self.ctx.state.write_json(path, record)
                self._apply_incident_rotation_flags(env_id, fact.target)
                try:
                    self.ctx.audit.record("team_incident_received", result="ok",
                                          extra={"env_id": env_id, "fingerprint": fact.author})
                except AuditUnavailable:
                    pass
            # An admin acks even a duplicate delivery (a retry that crossed with an earlier ack):
            # idempotent storage above means re-processing costs nothing, and the sender's outbox
            # entry must be able to clear on ANY ack, not only the first.
            try:
                session.send({"type": "INCIDENT_ACK", "hash": fact.hash})
            except (SessionClosed, InvalidInput):
                self._drop_session(env_id, session.peer.fingerprint, session)
        # else: section 9/3.1 -- a non-admin recipient ignores an incident summary entirely.

    def _handle_incident_ack(self, env_id: str, session: Session, message: dict) -> None:
        fact_hash = message.get("hash")
        if not isinstance(fact_hash, str):
            return
        with self._lock:
            env = self._envs.get(env_id)
            if env is None or fact_hash not in env.incident_outbox:
                return
            env.incident_outbox.pop(fact_hash, None)
            env.incident_backoff.pop(fact_hash, None)
            env.incident_next_attempt.pop(fact_hash, None)
        self._persist_incident_outbox(env_id)

    def _persist_incident_outbox(self, env_id: str) -> None:
        with self._lock:
            env = self._envs.get(env_id)
            pending = list(env.incident_outbox.values()) if env is not None else []
        lines = [json.dumps(fact.to_dict(), sort_keys=True, separators=(",", ":")) for fact in pending]
        blob = ("\n".join(lines) + "\n") if lines else ""
        self.ctx.state.write_bytes(self._incident_outbox_path(env_id), blob.encode("utf-8"))

    def _deliver_incident(self, env_id: str, fact: "Fact") -> int:
        """Send ``fact`` (an ``INCIDENT`` message) to every currently open session whose peer is an
        active admin member other than this device.  Returns how many sends succeeded -- never a
        promise of receipt; only an ``INCIDENT_ACK`` is that."""
        with self._lock:
            env = self._envs.get(env_id)
            if env is None:
                return 0
            targets = [(fp, s) for fp, s in env.sessions.items()
                      if fp != self.device.fingerprint and _is_admin(env.document, fp)]
        sent = 0
        for fp, session in targets:
            try:
                session.send({"type": "INCIDENT", "fact": fact.to_dict()})
                sent += 1
            except (SessionClosed, InvalidInput):
                self._drop_session(env_id, fp, session)
        return sent

    def send_incident(self, env_id: str, summary: dict) -> dict:
        """Sender side of section 9 (deliverable 1): sanitize, sign as a ``Fact`` of kind
        ``"incident"``, persist it exactly like any other fact, queue it for guaranteed admin
        delivery, and make a first delivery attempt to whichever admin sessions are open right now.
        Returns the signed fact (its ``hash`` is what an ``INCIDENT_ACK`` will name).
        """
        clean = sanitize_incident_summary(summary)
        with self._lock:
            env = self._envs.get(env_id)
            if env is None:
                raise InvalidInput("team_env_unknown")
            hlc_value = env.hlc.tick()
            doc = env.document
        if not _fact_role_ok(doc, "incident", self.device.fingerprint, clean):
            raise PolicyDenied("team_fact_not_authorized")
        fact = sign_fact(self.device, env_id, "incident", clean, hlc_value)
        with self.ctx.state.lock():
            self._store_fact(env_id, fact)
        with self._lock:
            env.incident_outbox[fact.hash] = fact
            env.incident_backoff.pop(fact.hash, None)
            env.incident_next_attempt.pop(fact.hash, None)
        self._persist_incident_outbox(env_id)
        self._deliver_incident(env_id, fact)
        result = fact.to_dict()
        result["hash"] = fact.hash  # convenience for a caller correlating this with an INCIDENT_ACK
        return result

    def send_incident_for_all_envs(self, summary_by_env: dict) -> dict:
        """The hook a future ``zeropw/incident.py``'s ``open_incident`` (``feature/compromise-
        response-plan``, not yet merged into this branch's base) is expected to call once per
        shared environment its exposure assessment touched: ``{env_id: summary}``.  Returns
        ``{env_id: "queued"}`` for each summary that was signed and queued, or
        ``{env_id: "error:<reason>"}`` for one this node could not send (unknown environment, or
        this device is not presently an active member of it).  Never raises: a caller iterating
        several environments should not lose the rest over one bad one."""
        results: dict[str, str] = {}
        for env_id, summary in summary_by_env.items():
            try:
                self.send_incident(env_id, summary)
                results[env_id] = "queued"
            except (InvalidInput, PolicyDenied, NotFound) as exc:
                results[env_id] = f"error:{getattr(exc, 'reason', type(exc).__name__)}"
        return results

    # Alias: docs/team-sync.md section 9 documents this call site under the name
    # ``on_incident_open``; the implementation is identical to ``send_incident_for_all_envs``.
    on_incident_open = send_incident_for_all_envs

    def _poll_incident_outbox(self, env_id: str, now: float) -> None:
        with self._lock:
            env = self._envs.get(env_id)
            if env is None or not env.incident_outbox:
                return
            due = [h for h in env.incident_outbox if now >= env.incident_next_attempt.get(h, 0.0)]
        if not due:
            return
        min_backoff, max_backoff = self.ctx.config.team_incident_retry_backoff
        for fact_hash in due:
            with self._lock:
                env = self._envs.get(env_id)
                fact = env.incident_outbox.get(fact_hash) if env is not None else None
            if fact is None:
                continue
            self._deliver_incident(env_id, fact)
            with self._lock:
                env = self._envs.get(env_id)
                if env is None or fact_hash not in env.incident_outbox:
                    continue
                current = env.incident_backoff.get(fact_hash)
                next_backoff = min_backoff if current is None else min(current * 2, max_backoff)
                env.incident_backoff[fact_hash] = next_backoff
                env.incident_next_attempt[fact_hash] = now + next_backoff

    # --------------------------------------------------------------- polling
    def poll(self) -> None:
        now = time.monotonic()
        if now - self._last_discovery > _DISCOVERY_INTERVAL_SECONDS or not self._envs:
            self._last_discovery = now
            with self._lock:
                self._discover_locked()
        now_ms_value = C.now_ms()
        with self._lock:
            env_ids = list(self._envs.keys())
        for env_id in env_ids:
            self._poll_env(env_id, now, now_ms_value)

    def _poll_env(self, env_id: str, now: float, now_ms_value: int) -> None:
        env = self._envs.get(env_id)
        if env is None:
            return
        self._pick_up_local_commits(env_id)
        self._pick_up_local_facts(env_id)
        self._poll_incident_outbox(env_id, now)
        released = env.store.release_deferred(now_ms_value)
        if released:
            self._refold(env_id)
            for released_commit in released:
                if self._commit_seen.add_if_new(released_commit.hash):
                    self._broadcast(env_id, {"type": "COMMIT", "commit": released_commit.to_dict()})
        with self._lock:
            dead = [fp for fp, s in env.sessions.items() if s.closed]
        for fp in dead:
            self._drop_session(env_id, fp)
        max_age = self.ctx.config.team_session_max_age_seconds
        with self._lock:
            aged = [fp for fp, s in env.sessions.items() if now - s.created_at > max_age]
        for fp in aged:
            self._close_session(env_id, fp)
        members = self._active_member_fps(env_id)
        self_fp = self.device.fingerprint
        with self._lock:
            need_dial = [fp for fp in members if fp != self_fp and fp not in env.sessions
                        and env.candidate_addresses.get(fp) and now >= env.next_attempt.get(fp, 0.0)]
        for fp in need_dial:
            self._dial_attempt(env_id, fp)
        interval = self._sync_interval(env_id)
        with self._lock:
            sessions = list(env.sessions.items())
        for fp, session in sessions:
            last = env.last_vector_sent.get(fp, 0.0)
            if now - last >= interval:
                self._send_vector(env_id, session)

    def _pick_up_local_commits(self, env_id: str) -> None:
        """Notice and broadcast commits a *different* process (the admin CLI, on a shared
        environment: docs/team-sync.md section 12) wrote directly to this env's ``CommitStore``
        since the last poll tick, by diffing the on-disk vector against ``last_known_vector``.
        """
        env = self._envs.get(env_id)
        if env is None:
            return
        current_vector = env.store.vector()
        with self._lock:
            baseline = dict(env.last_known_vector)
        new_commits: list[C.Commit] = []
        for fp, seq_hi in current_vector.items():
            seq_lo = baseline.get(fp, 0)
            if seq_hi <= seq_lo:
                continue
            for seq in range(seq_lo + 1, seq_hi + 1):
                found = env.store.get(fp, seq)
                if found is not None:
                    new_commits.append(found)
        if not new_commits:
            with self._lock:
                env.last_known_vector = current_vector
            return
        with self._lock:
            env.last_known_vector = current_vector
        self._refold(env_id)
        for found in new_commits:
            if self._commit_seen.add_if_new(found.hash):
                self._broadcast(env_id, {"type": "COMMIT", "commit": found.to_dict()})

    def _pick_up_local_facts(self, env_id: str) -> None:
        """The FACT-side twin of ``_pick_up_local_commits``: a ``connection disable``/``secret
        revoke`` issued through the admin CLI on a shared environment writes straight to
        ``facts.jsonl``; broadcast anything appended there since the last poll tick.
        """
        env = self._envs.get(env_id)
        if env is None:
            return
        lines = self.ctx.state.read_lines(self._facts_path(env_id), None) or []
        if len(lines) <= env.known_fact_lines:
            env.known_fact_lines = len(lines)
            return
        new_lines = lines[env.known_fact_lines:]
        env.known_fact_lines = len(lines)
        for line in new_lines:
            if not line:
                continue
            try:
                fact = Fact.from_dict(json.loads(line))
            except (ValueError, InvalidInput):
                continue
            if fact.env_id != env_id or fact.kind not in FACT_KINDS or fact.hash in env.fact_hashes:
                continue
            if fact.kind == "incident":
                # Written by this same process's own ``send_incident``/``_handle_incident``, which
                # already keep ``known_fact_lines`` in step -- never reached in practice, but an
                # "incident" line must never be broadcast mesh-wide as a FACT (see ``_handle_fact``).
                continue
            self._absorb_local_fact(env_id, fact)

    def _absorb_local_fact(self, env_id: str, fact: "Fact") -> None:
        """Apply (without re-appending -- it is already on disk) and broadcast a fact this process
        did not itself author, exactly like an inbound ``FACT`` message except for that."""
        if not self._validate_incoming_fact(env_id, fact):
            return
        with self.ctx.state.lock():
            self._remember_fact(env_id, fact)
            self._refold(env_id)
        self._audit_fact_apply(env_id, fact)
        self._broadcast(env_id, {"type": "FACT", "fact": fact.to_dict()})
        if fact.kind == "member_removed":
            self._drop_member_sessions(env_id, fact.target["fingerprint"])

    def _sync_interval(self, env_id: str) -> float:
        override = self.ctx.config.team_sync_interval_seconds
        if override is not None:
            return override
        settings = self._envs[env_id].document.get("settings", {})
        value = settings.get("sync_interval_seconds")
        return value if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0 \
            else F.DEFAULT_SYNC_INTERVAL_SECONDS

    def _dial_attempt(self, env_id: str, fp: str) -> None:
        with self._lock:
            env = self._envs.get(env_id)
            if env is None or fp in env.sessions:
                return
            addrs = sorted(env.candidate_addresses.get(fp, ()))
        if not addrs:
            return
        address = addrs[0]
        try:
            session = self.transport.dial(address, env_id)
        except Exception:
            self._record_dial_failure(env_id, fp)
            return
        if session.peer.fingerprint != fp:
            session.close()
            self._record_dial_failure(env_id, fp)
            return
        with self._lock:
            env.backoff.pop(fp, None)
            env.next_attempt.pop(fp, None)
        self._wire_dialed_session(env_id, fp, address, session)

    def _wire_dialed_session(self, env_id: str, fp: str, address: str, session: Session) -> None:
        """Common tail of every successful outbound dial: persist the address, resolve a same-peer
        collision against a concurrently accepted inbound session, then start gossiping."""
        self._persist_peer_address(env_id, fp, address)   # the address worked, regardless of the race below
        if not self._accept_or_replace_session(env_id, session, inbound=False):
            return
        self._audit_session_open(env_id, fp)
        self._start_receiver(env_id, session)
        self._send_vector(env_id, session)
        self._send_peers(env_id, session)
        self._retry_pending_incidents_to(env_id, session)

    def _retry_pending_incidents_to(self, env_id: str, session: Session) -> None:
        """Give a freshly-opened session to an admin peer an immediate shot at every outstanding
        incident, instead of waiting out that entry's backoff -- reconnection is exactly the event
        the outbox retry exists for."""
        with self._lock:
            env = self._envs.get(env_id)
            if env is None or not env.incident_outbox or not _is_admin(env.document, session.peer.fingerprint):
                return
            pending = list(env.incident_outbox.values())
        for fact in pending:
            try:
                session.send({"type": "INCIDENT", "fact": fact.to_dict()})
            except (SessionClosed, InvalidInput):
                self._drop_session(env_id, session.peer.fingerprint, session)
                return

    def adopt_outbound_session(self, env_id: str, session: Session, address: str) -> None:
        """Hand a session this caller dialed itself into the ordinary gossip machinery.

        ``zeropw.team.membership.join`` must dial with an ``invite_proof`` --  a parameter
        ``TeamSync``'s own periodic ``_dial_attempt`` never passes, since it only ever reconnects to
        an *already*-member peer -- so it cannot go through ``_dial_attempt`` itself.  This is the
        rest of that same tail (``_wire_dialed_session``), exposed for that one caller.
        """
        self._wire_dialed_session(env_id, session.peer.fingerprint, address, session)

    def is_active_member(self, env_id: str, fingerprint: str) -> bool:
        with self._lock:
            env = self._envs.get(env_id)
            if env is None:
                return False
            member = env.document.get("members", {}).get(fingerprint)
            return bool(member) and member.get("status") == "active"

    def document(self, env_id: str) -> dict:
        with self._lock:
            env = self._envs.get(env_id)
            if env is None:
                raise NotFound("team_env_unknown")
            return env.document

    def _record_dial_failure(self, env_id: str, fp: str) -> None:
        min_backoff, max_backoff = self.ctx.config.team_dial_backoff
        with self._lock:
            env = self._envs.get(env_id)
            if env is None:
                return
            current = env.backoff.get(fp)
            next_backoff = min_backoff if current is None else min(current * 2, max_backoff)
            env.backoff[fp] = next_backoff
            env.next_attempt[fp] = time.monotonic() + next_backoff

    # ------------------------------------------------------------- handshake
    def _on_handshake_failed(self, reason: str, fingerprint: str | None) -> None:
        try:
            extra = {"fingerprint": fingerprint} if fingerprint else None
            self.ctx.audit.record("team_handshake_failed", result="denied", reason=reason, extra=extra)
        except AuditUnavailable:
            pass

    # ---------------------------------------------------------------- status
    def status(self, env_id: str) -> dict:
        with self._lock:
            env = self._envs.get(env_id)
            if env is None:
                raise NotFound("team_env_unknown")
            return {
                "env_id": env_id,
                "vector": dict(env.store.vector()),
                "sessions": sorted(env.sessions.keys()),
                "synced_at": iso(env.synced_at) if env.synced_at is not None else None,
                "pending_deferred": len(env.store.deferred_commits()),
            }

    # -------------------------------------------------------------- compact
    def compact(self, env_id: str) -> dict:
        """``team compact`` (docs/team-sync.md section 7.3): delete commits older than
        ``COMPACT_MIN_AGE_MS`` once every active member's last-known ``VECTOR`` (``peer_vectors``,
        section 6.3) already covers them, saving a snapshot first so ``fold_with_snapshot`` still
        reconstructs the exact same document.  Never deletes a commit carrying a ``_PROTECTED_OPS``
        op (membership/DEK history), regardless of age or coverage, so signature verification of
        older commits and ``_relaxed_document`` keep working after compaction (see their
        docstrings).  Returns ``{"removed": N, "blocked_by": [...]}``; a non-empty ``blocked_by``
        means no commit was old *and* universally-covered enough, and names the lagging members.
        """
        with self._lock:
            env = self._envs.get(env_id)
        if env is None:
            raise NotFound("team_env_unknown")
        commits = env.store.all_commits()
        if not commits:
            return {"env_id": env_id, "removed": 0, "blocked_by": []}
        now_ms_value = C.now_ms()
        cutoff_index = -1
        for index, commit_obj in enumerate(commits):
            wall_ms, _ = Hlc.parse(commit_obj.hlc)
            if now_ms_value - wall_ms < COMPACT_MIN_AGE_MS:
                break
            cutoff_index = index
        if cutoff_index < 0:
            return {"env_id": env_id, "removed": 0, "blocked_by": [], "reason": "no_commit_old_enough"}
        candidate_vector: dict[str, int] = {}
        for commit_obj in commits[: cutoff_index + 1]:
            candidate_vector[commit_obj.author] = max(candidate_vector.get(commit_obj.author, 0), commit_obj.author_seq)
        with self._lock:
            peer_vectors = {fp: dict(v) for fp, v in env.peer_vectors.items()}
        blocked = sorted(
            fp for fp in self._active_member_fps(env_id)
            if fp != self.device.fingerprint
            and any(peer_vectors.get(fp, {}).get(author, 0) < seq for author, seq in candidate_vector.items())
        )
        if blocked:
            return {"env_id": env_id, "removed": 0, "blocked_by": blocked}
        snapshot_result = F.fold(env_id, commits[: cutoff_index + 1], env.facts, audit=self.ctx.audit)
        total = sum(candidate_vector.values())
        F.save_snapshot(self.ctx.state, env_id, total, snapshot_result)
        removed = 0
        with self.ctx.state.lock():
            for commit_obj in commits[: cutoff_index + 1]:
                if _commit_is_protected(commit_obj):
                    continue
                path = self.ctx.state.path / env.store._commit_path(commit_obj.author, commit_obj.author_seq)
                try:
                    path.unlink()
                    removed += 1
                except OSError:
                    pass
        with self._lock:
            env.last_snapshot_total = total
        self._refold(env_id)
        try:
            self.ctx.audit.record("team_compact", result="ok", extra={"env_id": env_id, "count": removed})
        except AuditUnavailable:
            pass
        return {"env_id": env_id, "removed": removed, "blocked_by": []}

    def synced_at(self, env_id: str) -> str | None:
        with self._lock:
            env = self._envs.get(env_id)
            return iso(env.synced_at) if env is not None and env.synced_at is not None else None

    # --------------------------------------------------------------- audit
    def _audit_session_open(self, env_id: str, fp: str) -> None:
        try:
            self.ctx.audit.record("team_session_open", result="ok", extra={"env_id": env_id, "fingerprint": fp})
        except AuditUnavailable:
            pass

    def _audit_session_close(self, env_id: str, fp: str) -> None:
        try:
            self.ctx.audit.record("team_session_close", result="ok", extra={"env_id": env_id, "fingerprint": fp})
        except AuditUnavailable:
            pass

    def _audit_vector(self, env_id: str, fp: str, count: int) -> None:
        try:
            self.ctx.audit.record("team_sync_vector", result="ok",
                                  extra={"env_id": env_id, "fingerprint": fp, "commits": count})
        except AuditUnavailable:
            pass

    def _audit_fact_apply(self, env_id: str, fact: Fact) -> None:
        try:
            self.ctx.audit.record("team_fact_apply", result="ok",
                                  extra={"env_id": env_id, "kind": fact.kind, "fingerprint": fact.author})
        except AuditUnavailable:
            pass

    def _audit_fact_rejected(self, env_id: str, fact: Fact, reason: str) -> None:
        try:
            self.ctx.audit.record("team_fact_rejected", result="denied", reason=reason,
                                  extra={"env_id": env_id, "kind": fact.kind, "fingerprint": fact.author})
        except AuditUnavailable:
            pass
