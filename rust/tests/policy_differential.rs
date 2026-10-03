//! Committed differential harness for work unit D (`policy.rs`), round 5.
//!
//! Five rounds of one-finding-at-a-time equivalence fixes for this module
//! have not converged (8, 9, 10, 8, 11 findings per round) -- the same
//! *class* of bug (a stored field's exact type/shape driving a different
//! decision than a coerced/narrowed Rust reading of it) kept recurring in
//! new fields and new operations. This harness builds one baseline policy
//! state directory, mutates one field at a time to an "odd" JSON shape
//! (wrong type, `null`, missing key, empty container, numeric string,
//! integral float, bool, an integer beyond `f64` range, a Unicode-digit
//! string, a non-ASCII string, a whitespace-padded string), and for each
//! mutated document runs the same battery of public `Policy` operations in
//! real `python3.12` and in this crate, comparing:
//!
//! - the outcome: success vs. failure, and for a failure, whether Python
//!   raised a proper `ZeroPWError` (exact class + reason must match) or an
//!   uncaught built-in exception (`TypeError`/`ValueError`/`KeyError`/...,
//!   which PORTING.md §3.5 allows Rust to map to *any* handled error, so
//!   only "did it fail" is compared for that case);
//! - for the mutating operations, the persisted bytes of every document and
//!   the revocation ledger (with the ledger's own non-deterministic `ts`
//!   field -- real wall-clock time, not the mocked `Clock` -- stripped
//!   before comparing).
//!
//! A handful of field/value combinations hit an *already recorded* §3
//! deviation (see `NAMED_EXCEPTIONS` below); those are asserted to take
//! exactly their documented shape, not silently skipped. Anything else that
//! disagrees fails the test with a full description of the case.
//!
//! Python does all the mutation-matrix bookkeeping (it is one process,
//! invoked once) and prints one JSON-lines manifest to stdout; this file
//! re-applies the exact same recorded mutation independently in Rust and
//! compares. No temp directory outlives this test: every `TempDir` this
//! file creates is dropped before the test returns, including on a panic
//! (Rust's `Drop` on `TempDir` runs even on unwind, and this test does not
//! use `std::mem::forget`/`ManuallyDrop` anywhere).

use std::collections::{BTreeMap, HashSet};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::Command;

use regex::Regex;
use serde_json::{Map, Value, json};
use tempfile::TempDir;
use zeropw::clock;
use zeropw::policy::{self, Action, ConnectionChanges, Policy, Revocations};
use zeropw::store::StateDir;

/// Same normalisation as the Python driver's `normalize_regrant_id`
/// (finding D-R7-3's harness gap: `regrant` is now in `WRITE_OPS`, and its
/// fresh grant gets a random id neither language can predict) -- replaces
/// any freshly generated `"g-" + 16 hex chars` id with a fixed placeholder
/// so the rest of the document is still byte-comparable. No baseline grant
/// id matches this pattern (they are all `"g-" + a name`, never 16 raw hex
/// characters), so this can never mis-normalise a real id.
fn normalize_regrant_id(text: &str) -> String {
    static PATTERN: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re = PATTERN.get_or_init(|| Regex::new(r"g-[0-9a-f]{16}").expect("valid regex"));
    re.replace_all(text, "g-REGRANT").into_owned()
}

/// Applies [`normalize_regrant_id`] to the `grants` document text and every
/// ledger line in a [`read_docs`] result, in place.
fn normalize_regrant_id_in_docs(docs: &mut Map<String, Value>) {
    if let Some(Value::String(s)) = docs.get("grants") {
        let normalized = normalize_regrant_id(s);
        docs.insert("grants".to_string(), Value::String(normalized));
    }
    if let Some(Value::Array(items)) = docs.get("ledger").cloned() {
        let normalized: Vec<Value> = items
            .into_iter()
            .map(|v| match v {
                Value::String(s) => Value::String(normalize_regrant_id(&s)),
                other => other,
            })
            .collect();
        docs.insert("ledger".to_string(), Value::Array(normalized));
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

/// Runs the embedded Python driver once and returns its stdout (the JSONL
/// manifest), one process for the whole matrix (not one per case).
fn run_driver(script_path: &Path) -> String {
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".to_string());
    let output = Command::new(interpreter)
        .arg(script_path)
        .env("PYTHONPATH", repo_root())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run python driver");
    assert!(
        output.status.success(),
        "python driver failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

// The Python driver is embedded as a string (not a sibling file) because
// this round's editable-file list is limited to `rust/src/policy.rs`,
// `rust/tests/policy_oracle.rs`, and this file.
const PY_DRIVER: &str = r#"
import copy
import json
import os
import tempfile

from zeropw.store import StateDir
from zeropw import policy as P

CLOCK = 1700000000.0


def clock():
    return CLOCK


def baseline():
    principals = {
        "agent-1": {
            "token_hash": P.hash_token("zpwc_abc"),
            "status": "active",
            "created_at": "",
            "runtime": "default",
        },
    }

    def http_conn(id_, auth, secret_id="gh-token", cli=None):
        return {
            "id": id_, "project": "demo", "environment": "dev", "service": "svc", "kind": "http",
            "secret_id": secret_id, "secret_version": None, "description": "demo",
            "http_target": {"scheme": "http", "host": "127.0.0.1", "port": 8080, "ca_file": None, "allow_private_network": False},
            "http_auth": auth,
            "http_scope": {"methods": ["GET", "POST"], "path_prefixes": ["/repos", "/me"], "confirm_methods": []},
            "ssh_target": None, "cli": cli, "policy_version": 1, "status": "active", "created_at": "", "updated_at": "",
        }

    connections = {
        # round 7 (harness gap named by the D-R7 review): a CLI-bearing
        # connection -- the previous baseline had none, so every
        # `cli.*`-mutating case was unreachable.
        "gh-bearer": http_conn(
            "gh-bearer", {"mode": "bearer", "header_name": None, "value_prefix": None, "basic_username": None},
            cli={"program": "ghcli", "kind": "http", "base_url_env": "ZEROPW_API_BASE_URL", "extra_env": {}},
        ),
        "gh-header": http_conn("gh-header", {"mode": "header", "header_name": "X-Token", "value_prefix": None, "basic_username": None}),
        "gh-basic": http_conn("gh-basic", {"mode": "basic", "header_name": None, "value_prefix": None, "basic_username": "svc"}),
        "box-ssh": {
            "id": "box-ssh", "project": "demo", "environment": "dev", "service": "svc", "kind": "ssh",
            "secret_id": "box-key", "secret_version": None, "description": "demo",
            "http_target": None, "http_auth": None, "http_scope": None,
            "ssh_target": {
                "host": "127.0.0.1", "port": 22, "username": "deploy",
                "host_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA host"],
            },
            "cli": None, "policy_version": 1, "status": "active", "created_at": "", "updated_at": "",
        },
    }

    def grant(id_, conn_id, credential_version=None):
        return {
            "id": id_, "principal": "agent-1", "connection": conn_id, "policy_version": 1,
            "expires_at": None, "max_uses": None, "uses": 0, "status": "active",
            "created_at": "", "revoked_at": None, "credential_version": credential_version,
        }

    grants = {
        "g-gh-bearer": grant("g-gh-bearer", "gh-bearer", 1),
        "g-gh-header": grant("g-gh-header", "gh-header"),
        "g-gh-basic": grant("g-gh-basic", "gh-basic"),
        "g-box-ssh": grant("g-box-ssh", "box-ssh"),
    }

    control = {
        "stopped": False, "restore_pending": False, "incident_open": None,
        "approvals": {
            "dg1": {
                "caller": "agent-1", "connection": "gh-bearer", "method": "GET", "path": "/repos",
                "status": "pending", "created_at": "", "expires_at": CLOCK + 300.0,
                "grant": "g-gh-bearer", "policy_version": 1, "cycle": 1,
            },
            # round 7 (harness gap named by the D-R7 review): an *approved*
            # approval -- the previous baseline had only a pending one, so
            # `approve`/`consume_approval`'s approved-status branches were
            # unreachable.
            "dg2": {
                "caller": "agent-1", "connection": "gh-bearer", "method": "GET", "path": "/me",
                "status": "approved", "created_at": "", "approved_at": "",
                "expires_at": CLOCK + 300.0,
                "grant": "g-gh-bearer", "policy_version": 1, "cycle": 1,
            },
        },
        "approval_history": [],
    }
    vault_secrets = {"secrets": {"gh-token": {"active_version": 1}}}
    return {
        "principals": principals, "connections": connections, "grants": grants,
        "control": control, "vault_secrets": vault_secrets,
    }


FIELD_PATHS = [
    ("connections", ["gh-bearer", "policy_version"]),
    ("connections", ["box-ssh", "policy_version"]),
    ("connections", ["gh-basic", "policy_version"]),
    ("connections", ["gh-header", "status"]),
    ("connections", ["gh-header", "http_auth", "header_name"]),
    ("connections", ["gh-basic", "http_auth", "basic_username"]),
    ("connections", ["box-ssh", "ssh_target", "host_keys"]),
    ("connections", ["gh-bearer", "secret_version"]),
    ("grants", ["g-gh-bearer", "policy_version"]),
    ("grants", ["g-gh-bearer", "max_uses"]),
    ("grants", ["g-gh-bearer", "uses"]),
    ("grants", ["g-gh-bearer", "credential_version"]),
    ("grants", ["g-gh-bearer", "status"]),
    ("grants", ["g-gh-bearer", "expires_at"]),
    ("grants", ["g-gh-bearer", "revoked_at"]),
    ("grants", ["g-box-ssh", "status"]),
    ("control", ["stopped"]),
    ("control", ["restore_pending"]),
    ("control", ["incident_open"]),
    ("control", ["approvals", "dg1", "status"]),
    ("control", ["approvals", "dg1", "expires_at"]),
    ("control", ["approvals", "dg1", "connection"]),
    ("control", ["approvals", "dg1", "caller"]),
    ("control", ["approvals", "dg1", "grant"]),
    ("control", ["approvals"]),
    ("control", ["approval_history"]),
    ("principals", ["agent-1", "token_hash"]),
    ("vault_secrets", ["secrets", "gh-token", "active_version"]),
    # Round 7 additions (harness gaps named by the D-R7 review): nested
    # http_target/http_scope/cli paths, plus top-level connection/grant/
    # principal/approval fields the committed harness never mutated at all.
    ("connections", ["gh-bearer", "http_target", "scheme"]),
    ("connections", ["gh-bearer", "http_target", "host"]),
    ("connections", ["gh-bearer", "http_target", "port"]),
    ("connections", ["gh-bearer", "http_target", "ca_file"]),
    ("connections", ["gh-bearer", "http_target", "allow_private_network"]),
    ("connections", ["gh-bearer", "http_scope", "methods"]),
    ("connections", ["gh-bearer", "http_scope", "path_prefixes"]),
    ("connections", ["gh-bearer", "http_scope", "confirm_methods"]),
    ("connections", ["gh-bearer", "cli", "program"]),
    ("connections", ["gh-bearer", "cli", "kind"]),
    ("connections", ["gh-bearer", "cli", "base_url_env"]),
    ("connections", ["gh-bearer", "cli", "extra_env"]),
    ("connections", ["gh-bearer", "kind"]),
    ("connections", ["gh-bearer", "secret_id"]),
    ("connections", ["gh-bearer", "id"]),
    ("grants", ["g-gh-bearer", "principal"]),
    ("grants", ["g-gh-bearer", "connection"]),
    ("principals", ["agent-1", "status"]),
    ("principals", ["agent-1", "runtime"]),
    ("control", ["approvals", "dg1", "policy_version"]),
    ("control", ["approvals", "dg1", "cycle"]),
    # `dg2` (the *approved* baseline approval) specifically, not `dg1`
    # (pending): `consume_approval` only ever targets `dg2` in this
    # harness's `WRITE_OPS`, so this is the field path that actually
    # exercises finding D-R7-4's unhashable-`grant`-lookup bug through the
    # matrix (mutating `dg1.grant` is irrelevant to `consume_approval`,
    # which never reads `dg1`).
    ("control", ["approvals", "dg2", "grant"]),
]

HUGE_INT = 10 ** 30
I64_MAX = 2 ** 63 - 1
I64_MIN = -(2 ** 63)
TWO_POW_53_PLUS_1 = 2 ** 53 + 1
ODD_VALUES = [
    ("null", None),
    ("empty_array", []),
    ("empty_object", {}),
    ("empty_string", ""),
    ("numeric_string", "3"),
    ("integral_float", 3.0),
    ("bool_true", True),
    ("huge_int", HUGE_INT),
    ("unicode_digit_string", "٣"),
    ("non_ascii_string", "café"),
    ("whitespace_padded", "  3  "),
    ("missing", "__MISSING__"),
    # Round 7 additions (harness gaps the D-R7 review named explicitly):
    # truthy *containers* -- the exact class of the D-R5-1/D-R4-1 fail-open
    # bugs, and (combined with the cross-field mutation mode below) of
    # D-R7-6's two-array `grant_num_ge` gap -- plus the `i64` arithmetic
    # boundary (D-R7-1) and the `f64` 53-bit exactness boundary (D-R7-3).
    ("truthy_array", [1]),
    ("truthy_object", {"a": 1}),
    ("negative_one", -1),
    ("i64_max", I64_MAX),
    ("i64_min", I64_MIN),
    ("two_pow_53_plus_1", TWO_POW_53_PLUS_1),
]

# Runtime control (round 6, extended round 7): the full `FIELD_PATHS x
# ODD_VALUES` cross product exercises every (field, odd-value) combination,
# but most fields only ever see *type* confusion, not *content* confusion --
# once a value is "some non-matching string", `value_eq_str`/`GrantNum::Str`/
# `numeric_value_as_f64`/`Option::as_str` all treat "3", "٣", "café" and
# "  3  " identically (none of them route through `python_int_coerce`'s
# Unicode-digit/whitespace-stripping grammar). The exception is
# `Connection.policy_version`, whose `int(data["policy_version"])` *does*
# parse a numeric string (including a Unicode-digit or whitespace-padded
# one) -- that's the one place the full string variety changes the
# accept/reject outcome, so it keeps the complete `ODD_VALUES` list. Every
# other field runs a smaller, still-representative `CORE_VALUES` set: one
# falsy string (`empty_string`), one truthy non-numeric string
# (`numeric_string`), both empty containers, both truthy-numeric shapes
# (`bool_true`, `integral_float`), the exact-precision boundary
# (`huge_int`), the no-default/missing-key case, and (round 7) the two
# truthy containers and the three integer-boundary values above. This keeps
# the case_count (and so total runtime) from exploding even as this round
# adds many more field paths -- fixed, not randomly sampled, so it is
# exactly reproducible and never silently drops the specific (field, label)
# pairs any round's fixes are pinned against.
FULL_ODD_VALUE_PATHS = {
    ("connections", ("gh-bearer", "policy_version")),
    ("connections", ("box-ssh", "policy_version")),
    ("connections", ("gh-basic", "policy_version")),
    # Round 7: the fields D-R7-1/D-R7-3's arithmetic actually touches get
    # the complete value set too, not just the reduced `CORE_VALUES`.
    ("grants", ("g-gh-bearer", "max_uses")),
    ("grants", ("g-gh-bearer", "uses")),
    ("grants", ("g-gh-bearer", "expires_at")),
    ("control", ("approvals", "dg1", "cycle")),
}
CORE_VALUES = [
    v for v in ODD_VALUES
    if v[0] in ("null", "empty_array", "empty_object", "empty_string",
                "numeric_string", "integral_float", "bool_true", "huge_int",
                "missing", "truthy_array", "truthy_object", "i64_max",
                "i64_min", "two_pow_53_plus_1")
]


def set_path(doc, path, value):
    d = doc
    for k in path[:-1]:
        d = d[k]
    d[path[-1]] = value


def del_path(doc, path):
    d = doc
    for k in path[:-1]:
        d = d[k]
    del d[path[-1]]


def apply_mutation(base, doc_name, path, label, value):
    docs = {k: copy.deepcopy(v) for k, v in base.items()}
    if label == "missing":
        del_path(docs[doc_name], path)
    else:
        set_path(docs[doc_name], path, value)
    return docs


def write_docs(state, docs):
    state.write_json(P.PRINCIPALS, docs["principals"])
    state.write_json(P.CONNECTIONS, docs["connections"])
    state.write_json(P.GRANTS, docs["grants"])
    state.write_json(P.CONTROL, docs["control"])
    state.write_json(P.VAULT_SECRETS, docs["vault_secrets"])


def err_tuple(e):
    return {"err": [type(e).__name__, getattr(e, "reason", "")]}


def ok(v):
    return {"ok": v}


def run_read_ops(pol):
    out = {}
    try:
        p = pol.authenticate("zpwc_abc")
        out["authenticate"] = ok({"id": p.id, "status": p.status})
    except Exception as e:
        out["authenticate"] = err_tuple(e)
    try:
        c = pol.get_connection("gh-bearer")
        out["get_connection"] = ok(c.public_view())
    except Exception as e:
        out["get_connection"] = err_tuple(e)
    try:
        cs = pol.list_connections()
        out["list_connections"] = ok([c.public_view() for c in sorted(cs, key=lambda c: c.id)])
    except Exception as e:
        out["list_connections"] = err_tuple(e)
    try:
        g = pol.get_grant("g-gh-bearer")
        out["get_grant"] = ok(g.public_view())
    except Exception as e:
        out["get_grant"] = err_tuple(e)
    try:
        gs = pol.list_grants("agent-1")
        out["list_grants"] = ok([g.public_view() for g in sorted(gs, key=lambda g: g.id)])
    except Exception as e:
        out["list_grants"] = err_tuple(e)
    try:
        d = pol.evaluate("agent-1", "gh-bearer", P.Action("http", "GET", "/repos"), "g-gh-bearer")
        out["evaluate"] = ok({"allowed": d.allowed, "reason": d.reason})
    except Exception as e:
        out["evaluate"] = err_tuple(e)
    try:
        d = pol.check_grant("agent-1", "gh-bearer", "g-gh-bearer")
        out["check_grant"] = ok({"allowed": d.allowed, "reason": d.reason})
    except Exception as e:
        out["check_grant"] = err_tuple(e)
    try:
        uc = pol.usable_connections("agent-1")
        out["usable_connections"] = ok(sorted([c.id, g.id] for c, g in uc))
    except Exception as e:
        out["usable_connections"] = err_tuple(e)
    try:
        out["is_stopped"] = ok(pol.is_stopped())
    except Exception as e:
        out["is_stopped"] = err_tuple(e)
    try:
        out["restore_pending"] = ok(pol.restore_pending())
    except Exception as e:
        out["restore_pending"] = err_tuple(e)
    try:
        out["list_approvals"] = ok(pol.list_approvals())
    except Exception as e:
        out["list_approvals"] = err_tuple(e)
    try:
        out["approval_history"] = ok(pol.approval_history())
    except Exception as e:
        out["approval_history"] = err_tuple(e)
    return out


def doc_text(state_path, name):
    p = os.path.join(state_path, name)
    return open(p, "r", encoding="utf-8").read()


def ledger_lines_normalized(state_path):
    p = os.path.join(state_path, P.REVOCATIONS)
    if not os.path.exists(p):
        return []
    out = []
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            obj = json.loads(line)
            obj.pop("ts", None)
            out.append(json.dumps(obj, sort_keys=True, separators=(",", ":")))
    return out


WRITE_OPS = [
    "resume", "request_approval", "revoke_grant", "revoke_all", "reapply_revocations",
    "credential_versions_changed", "update_connection", "disable_principal",
    "disable_connection", "consume",
    # Round 7 additions (harness gap named by the D-R7 review): a third of
    # the public write API -- including `regrant`, the one operation
    # finding D-R7-3's `max_uses` exactness bug lives in -- was absent.
    "regrant", "approve", "consume_approval", "revoke_grants_of", "stop_all",
]

# `regrant` (round 7) creates a fresh grant with a random id
# (`"g-" + uuid4().hex[:16]`), so its own persisted `grants.json` and its
# `public_view()["id"]` can never byte-match Rust's independently-random id.
# Neither language's *decision* depends on the id's actual value, only on it
# being fresh, so normalising it to a fixed placeholder (the same way the
# ledger's real-wall-clock `ts` is stripped above) makes the rest of the
# document still comparable. Only a freshly generated id is touched -- every
# *baseline* grant id (`g-gh-bearer`, ...) is `"g-" + a name`, never 16 raw
# hex characters, so this can never mis-normalise a real, meaningful id.
_REGRANT_ID_RE = __import__("re").compile(r"g-[0-9a-f]{16}")


def normalize_regrant_id(text):
    return _REGRANT_ID_RE.sub("g-REGRANT", text)


def run_write_op(state_path, docs, name):
    state = StateDir(state_path)
    state.create()
    write_docs(state, docs)
    pol = P.Policy(state, clock=clock)
    try:
        if name == "resume":
            pol.resume()
            result = ok(None)
        elif name == "request_approval":
            entry = pol.request_approval("dg1", "agent-1", "gh-bearer", "GET", "/repos")
            result = ok(entry)
        elif name == "revoke_grant":
            g = pol.revoke_grant("g-gh-bearer")
            result = ok(g.public_view())
        elif name == "revoke_all":
            n = pol.revoke_all()
            result = ok(n)
        elif name == "reapply_revocations":
            revs = P.Revocations(
                grants={"g-gh-bearer"}, principals={"agent-1"},
                connections={"gh-bearer"}, secret_versions=set(),
            )
            counts = pol.reapply_revocations(revs)
            result = ok(counts)
        elif name == "credential_versions_changed":
            cvc = pol.credential_versions_changed("gh-token")
            result = ok(sorted(c.id for c in cvc))
        elif name == "update_connection":
            c, widened = pol.update_connection("gh-bearer", description="mutated")
            result = ok({"view": c.public_view(), "widened": widened})
        elif name == "disable_principal":
            pol.disable_principal("agent-1", notify=False)
            result = ok(None)
        elif name == "disable_connection":
            c = pol.disable_connection("gh-bearer")
            result = ok(c.public_view())
        elif name == "consume":
            g = pol.consume(
                "g-gh-bearer", caller="agent-1", connection_id="gh-bearer",
                action=P.Action("http", "GET", "/repos"), policy_version=None,
            )
            result = ok(g.public_view())
        elif name == "regrant":
            g = pol.regrant("g-gh-bearer")
            result = ok(g.public_view())
        elif name == "approve":
            entry = pol.approve("dg1")
            result = ok(entry)
        elif name == "consume_approval":
            # No `grant_id`/`policy_version` (finding D-R7-4): passing an
            # explicit `grant_id` that differs from a malformed stored
            # `grant` short-circuits `_approval_mismatch` via `!=` *before*
            # it ever reaches `self.get_grant(recorded_grant)` -- the
            # `dict.get()` call whose `TypeError` on an unhashable
            # `recorded_grant` is the actual bug. Omitting both (as no
            # preceding `evaluate()` call population would too) is what
            # actually exercises that path.
            ok_bool = pol.consume_approval("dg2", "agent-1", "gh-bearer")
            result = ok(ok_bool)
        elif name == "revoke_grants_of":
            n = pol.revoke_grants_of("agent-1")
            result = ok(n)
        elif name == "stop_all":
            pol.stop_all()
            result = ok(None)
        else:
            raise AssertionError(name)
    except Exception as e:
        result = err_tuple(e)
    if name == "regrant" and "ok" in result and isinstance(result["ok"], dict) and "id" in result["ok"]:
        result["ok"]["id"] = "g-REGRANT"
    docs_out = {
        "principals": doc_text(state_path, P.PRINCIPALS),
        "connections": doc_text(state_path, P.CONNECTIONS),
        "grants": doc_text(state_path, P.GRANTS),
        "control": doc_text(state_path, P.CONTROL),
        "vault_secrets": doc_text(state_path, P.VAULT_SECRETS),
        "ledger": ledger_lines_normalized(state_path),
    }
    if name == "regrant":
        docs_out["grants"] = normalize_regrant_id(docs_out["grants"])
        docs_out["ledger"] = [normalize_regrant_id(line) for line in docs_out["ledger"]]
    return {"outcome": result, "docs": docs_out}


def apply_mutations(base, mutations):
    """Like `apply_mutation`, but applies *several* (doc, path, label,
    value) mutations to the same document set at once (round 7, the
    cross-field mutation mode finding D-R7-6 needs: that bug only exists
    when *both* `uses` and `max_uses` are arrays at once, which a
    one-field-at-a-time mutation can never reach)."""
    docs = {k: copy.deepcopy(v) for k, v in base.items()}
    for doc_name, path, label, value in mutations:
        if label == "missing":
            del_path(docs[doc_name], path)
        else:
            set_path(docs[doc_name], path, value)
    return docs


# Round 7 (harness gap named by the D-R7 review, finding D-R7-6): the main
# matrix above only ever mutates one field at a time, so a bug that only
# manifests when *two* fields are simultaneously odd (exactly D-R7-6's
# `uses`/`max_uses` both-arrays case) is structurally unreachable there.
# `CROSS_FIELD_CASES` starts with that exact repro (a must-have, not left to
# chance), then adds a small, fixed (seeded, not exhaustive -- a full
# `FIELD_PATHS` x `FIELD_PATHS` x `CORE_VALUES` x `CORE_VALUES` cross
# product would explode the runtime for very little extra signal) sample of
# further two-field combinations drawn from a curated pool of fields real
# decisions actually read *together* (a connection and its own grant's
# fields, a grant and the approval bound to it, ...), so the sample is
# reproducible across runs rather than silently different every time.
CROSS_FIELD_CASES = [
    (("grants", ["g-gh-bearer", "uses"], "empty_array", []),
     ("grants", ["g-gh-bearer", "max_uses"], "truthy_array", [1])),
]


def _sample_cross_field_cases(seed, count):
    rng = __import__("random").Random(seed)
    pool_paths = [
        ("connections", ["gh-bearer", "policy_version"]),
        ("connections", ["gh-bearer", "secret_id"]),
        ("connections", ["gh-bearer", "status"]),
        ("connections", ["gh-bearer", "kind"]),
        ("grants", ["g-gh-bearer", "policy_version"]),
        ("grants", ["g-gh-bearer", "max_uses"]),
        ("grants", ["g-gh-bearer", "uses"]),
        ("grants", ["g-gh-bearer", "status"]),
        ("grants", ["g-gh-bearer", "expires_at"]),
        ("control", ["approvals", "dg1", "grant"]),
        ("control", ["approvals", "dg1", "policy_version"]),
        ("control", ["approvals", "dg2", "policy_version"]),
    ]
    sampled = []
    for _ in range(count):
        doc1, path1 = rng.choice(pool_paths)
        remaining = [p for p in pool_paths if p != (doc1, path1)]
        doc2, path2 = rng.choice(remaining)
        label1, value1 = rng.choice(CORE_VALUES)
        label2, value2 = rng.choice(CORE_VALUES)
        sampled.append((
            (doc1, path1, label1, value1),
            (doc2, path2, label2, value2),
        ))
    return sampled


CROSS_FIELD_CASES += _sample_cross_field_cases(seed=20260918, count=8)


def main():
    base = baseline()
    print(json.dumps({"baseline": base}, sort_keys=True))
    idx = 0
    for doc_name, path in FIELD_PATHS:
        odd_values = ODD_VALUES if (doc_name, tuple(path)) in FULL_ODD_VALUE_PATHS else CORE_VALUES
        for label, value in odd_values:
            idx += 1
            mutated = apply_mutation(base, doc_name, path, label, value)

            with tempfile.TemporaryDirectory() as d:
                state_path = os.path.join(d, "state")
                state = StateDir(state_path)
                state.create()
                write_docs(state, mutated)
                pol = P.Policy(state, clock=clock)
                reads = run_read_ops(pol)

            writes = {}
            for wname in WRITE_OPS:
                with tempfile.TemporaryDirectory() as d:
                    state_path = os.path.join(d, "state")
                    writes[wname] = run_write_op(state_path, mutated, wname)

            case_obj = {
                "case": idx, "doc": doc_name, "path": path, "label": label,
                "missing": label == "missing",
                "value": None if label == "missing" else value,
                "reads": reads, "writes": writes,
            }
            print(json.dumps(case_obj, sort_keys=True))

    for mutations in CROSS_FIELD_CASES:
        idx += 1
        mutated = apply_mutations(base, mutations)

        with tempfile.TemporaryDirectory() as d:
            state_path = os.path.join(d, "state")
            state = StateDir(state_path)
            state.create()
            write_docs(state, mutated)
            pol = P.Policy(state, clock=clock)
            reads = run_read_ops(pol)

        writes = {}
        for wname in WRITE_OPS:
            with tempfile.TemporaryDirectory() as d:
                state_path = os.path.join(d, "state")
                writes[wname] = run_write_op(state_path, mutated, wname)

        case_obj = {
            "case": idx, "cross_field": True,
            "fields": [
                [d, p, l, (None if l == "missing" else v)]
                for (d, p, l, v) in mutations
            ],
            "reads": reads, "writes": writes,
        }
        print(json.dumps(case_obj, sort_keys=True))


main()
"#;

// ------------------------------------------------------------- JSON helpers

fn set_path(doc: &mut Value, path: &[String], value: Value) {
    let mut cur = doc;
    for k in &path[..path.len() - 1] {
        cur = cur
            .as_object_mut()
            .unwrap_or_else(|| panic!("path segment {k:?} not an object"))
            .get_mut(k)
            .unwrap_or_else(|| panic!("missing path segment {k:?}"));
    }
    cur.as_object_mut()
        .expect("parent not an object")
        .insert(path[path.len() - 1].clone(), value);
}

fn del_path(doc: &mut Value, path: &[String]) {
    let mut cur = doc;
    for k in &path[..path.len() - 1] {
        cur = cur.as_object_mut().unwrap().get_mut(k).unwrap();
    }
    cur.as_object_mut().unwrap().remove(&path[path.len() - 1]);
}

fn apply_mutation(
    baseline: &Map<String, Value>,
    doc: &str,
    path: &[String],
    missing: bool,
    value: &Value,
) -> Map<String, Value> {
    let mut docs = baseline.clone();
    let target = docs.get_mut(doc).expect("doc name");
    if missing {
        del_path(target, path);
    } else {
        set_path(target, path, value.clone());
    }
    docs
}

/// Plural form of [`apply_mutation`] for the cross-field mutation mode
/// (finding D-R7-6): applies every `(doc, path, missing, value)` mutation
/// to the same document set at once.
fn apply_mutations(
    baseline: &Map<String, Value>,
    mutations: &[(String, Vec<String>, bool, Value)],
) -> Map<String, Value> {
    let mut docs = baseline.clone();
    for (doc, path, missing, value) in mutations {
        let target = docs.get_mut(doc.as_str()).expect("doc name");
        if *missing {
            del_path(target, path);
        } else {
            set_path(target, path, value.clone());
        }
    }
    docs
}

fn write_docs(state: &StateDir, docs: &Map<String, Value>) {
    state
        .write_json(policy::PRINCIPALS, &docs["principals"])
        .unwrap();
    state
        .write_json(policy::CONNECTIONS, &docs["connections"])
        .unwrap();
    state.write_json(policy::GRANTS, &docs["grants"]).unwrap();
    state.write_json(policy::CONTROL, &docs["control"]).unwrap();
    state
        .write_json(policy::VAULT_SECRETS, &docs["vault_secrets"])
        .unwrap();
}

// -------------------------------------------------------------- outcome ADT

/// One operation's outcome, in the same shape the Python driver emits so
/// the two can be compared directly.
#[derive(Debug, Clone, PartialEq)]
enum Outcome {
    Ok(Value),
    /// A proper `ZeroPWError`: exact class name + reason.
    ZeroPwErr(String, String),
    /// An uncaught Python built-in exception (no `.reason`) -- PORTING.md
    /// §3.5 allows Rust to map this to *any* handled error, so only
    /// "did it fail" is compared, not the specific class/reason.
    BuiltinErr,
    /// Round 7 (finding D-R7-1): the Rust side panicked (e.g. `attempt to
    /// add with overflow`), caught via `std::panic::catch_unwind` so the
    /// whole harness run reports it as an ordinary divergence instead of
    /// aborting -- Python never panics, so this variant only ever appears
    /// on the Rust side, and `matches`/`check_case`'s default fall-through
    /// already treats it as a real, unexplained divergence against every
    /// Python outcome (nothing should ever need a named exception for it).
    Panic(String),
}

impl Outcome {
    fn from_manifest(v: &Value) -> Outcome {
        if let Some(ok) = v.get("ok") {
            return Outcome::Ok(ok.clone());
        }
        let err = v.get("err").expect("ok or err").as_array().unwrap();
        let class = err[0].as_str().unwrap().to_string();
        let reason = err[1].as_str().unwrap_or("").to_string();
        if reason.is_empty() {
            Outcome::BuiltinErr
        } else {
            Outcome::ZeroPwErr(class, reason)
        }
    }

    fn from_rust_result(r: Result<Value, zeropw::errors::Error>) -> Outcome {
        match r {
            Ok(v) => Outcome::Ok(v),
            Err(e) => Outcome::ZeroPwErr(e.class.class_name().to_string(), e.reason.to_string()),
        }
    }

    /// Compares Python's recorded outcome against Rust's, honouring the
    /// `BuiltinErr` tolerance described on the enum itself.
    fn matches(&self, other: &Outcome) -> bool {
        match (self, other) {
            // A Rust panic never "matches" anything, including Python's own
            // `BuiltinErr` (which the `BuiltinErr` arm below would
            // otherwise treat as "any failure" and silently accept) --
            // Python never panics, so this is always a real divergence
            // (finding D-R7-1: this is exactly the case that would have
            // aborted the whole harness before `catch_unwind` was added).
            (Outcome::Panic(_), _) | (_, Outcome::Panic(_)) => false,
            (Outcome::Ok(a), Outcome::Ok(b)) => a == b,
            (Outcome::BuiltinErr, o) | (o, Outcome::BuiltinErr) => !matches!(o, Outcome::Ok(_)),
            (Outcome::ZeroPwErr(c1, r1), Outcome::ZeroPwErr(c2, r2)) => c1 == c2 && r1 == r2,
            _ => false,
        }
    }
}

// ----------------------------------------------------- named §3 exceptions

/// A mutation the harness expects to disagree, because it hits an already
/// recorded `DEVIATIONS.md` row, or a newly-discovered-but-not-yet-fixed gap
/// this same harness surfaced and this round documents rather than fixes
/// (both kinds are recorded in the `description`, and every one is also a
/// row in `DEVIATIONS.md` or called out in the final report) -- never a
/// silent "ignore this case". `judge` still has to confirm the disagreement
/// takes *exactly* its documented shape: if Python's or Rust's outcome ever
/// changes shape for a matching case, `judge` returns `false` and the
/// harness reports it as a real, unexplained divergence, not a skip.
struct NamedException {
    description: &'static str,
    /// Matches on (doc, path, missing, value-label, operation).
    applies: fn(&str, &[String], bool, &str, &str) -> bool,
    judge: fn(&Outcome, &Outcome) -> bool,
    /// If true, a write op's persisted-document comparison is also skipped
    /// for a matching case (the deviation is about what gets *written*, not
    /// just the outcome).
    skip_doc_compare: bool,
}

const NAMED_EXCEPTIONS: &[NamedException] = &[
    // This `huge_int`-only exception is listed *before* the (removed, round
    // 6) general Grant-field one used to sit so `matching_exception`'s
    // first-match lookup would reach it for `expires_at` at that specific
    // value; kept in this position since a future addition to this array
    // could reintroduce the same ordering hazard for any predicate that
    // doesn't exclude `label == "huge_int"`.
    NamedException {
        // Round-7 correction (finding D-R7-8): this exception's description
        // previously claimed the divergence was "newly discovered,
        // undocumented until this round's differential harness" -- false.
        // It is already recorded, and named `Grant.expires_at` explicitly,
        // in `DEVIATIONS.md`'s `store (iso, findings A-R4-2, A-R5-3)` row
        // (line 41): Python's `time.gmtime`/`time.strftime` raise for a
        // timestamp magnitude the platform C library can't represent (or a
        // non-finite `ts`), uncaught by `iso`, where this port's own `iso`
        // has no such bound (by design -- callers across the whole crate
        // depend on its `-> String` signature never failing) and renders a
        // physically meaningless but well-formed date instead.
        description: "Documented divergence: DEVIATIONS.md's `store (iso, \
            findings A-R4-2, A-R5-3)` row, which names `Grant.expires_at` \
            explicitly. Python's `iso()` raises an uncaught `OverflowError`/\
            `OSError` for a timestamp magnitude the platform C library \
            can't represent (e.g. `grant.expires_at` beyond what \
            `time.gmtime` accepts, reachable via Python's arbitrary- \
            precision `int`); this port's own ISO formatting has no such \
            bound and renders an absurd but well-formed date instead.",
        applies: |doc, path, missing, label, _op| {
            doc == "grants"
                && !missing
                // `i64_max`/`i64_min` (round 7's new boundary values) hit
                // the identical platform `gmtime`/`OSError` limit `python3.12`
                // confirms directly (`iso(2**63-1)`/`iso(-(2**63))` both
                // raise `OSError [Errno 84] Value too large...`);
                // `two_pow_53_plus_1` deliberately does NOT get this
                // exception -- `python3.12` confirms `iso(2**53+1)` returns
                // normally, and finding D-R7-3's fix makes this port match
                // it exactly (`exact_iso_seconds`), pinned by
                // `grant_public_view_expires_at_is_exact_past_f64_53_bit_precision`.
                && matches!(label, "huge_int" | "i64_max" | "i64_min")
                && path.last().map(String::as_str) == Some("expires_at")
        },
        // Round-7 correction (finding D-R7-8): `|_py, _rust| true` accepted
        // *any* pair of outcomes, including a future regression where Rust
        // starts disagreeing with Python in some entirely different way --
        // directly contradicting this harness's own contract that a judge
        // must "confirm the disagreement takes exactly its documented
        // shape ... never a silent 'ignore this case'". The real shape is:
        // Python raises the uncaught built-in error this row documents,
        // and Rust still succeeds.
        judge: |py, rust| matches!(py, Outcome::BuiltinErr) && matches!(rust, Outcome::Ok(_)),
        skip_doc_compare: true,
    },
];

fn matching_exception(
    doc: &str,
    path: &[String],
    missing: bool,
    label: &str,
    op: &str,
) -> Option<&'static NamedException> {
    NAMED_EXCEPTIONS
        .iter()
        .find(|e| (e.applies)(doc, path, missing, label, op))
}

// --------------------------------------------------------------- Rust ops

const READ_OPS: &[&str] = &[
    "authenticate",
    "get_connection",
    "list_connections",
    "get_grant",
    "list_grants",
    "evaluate",
    "check_grant",
    "usable_connections",
    "is_stopped",
    "restore_pending",
    "list_approvals",
    "approval_history",
];

const WRITE_OPS: &[&str] = &[
    "resume",
    "request_approval",
    "revoke_grant",
    "revoke_all",
    "reapply_revocations",
    "credential_versions_changed",
    "update_connection",
    "disable_principal",
    "disable_connection",
    "consume",
    // Round 7 additions (harness gap named by the D-R7 review).
    "regrant",
    "approve",
    "consume_approval",
    "revoke_grants_of",
    "stop_all",
];

fn run_rust_read_op(pol: &Policy, op: &str) -> Outcome {
    let r: Result<Value, zeropw::errors::Error> = match op {
        "authenticate" => pol
            .authenticate("zpwc_abc")
            .map(|p| json!({"id": p.id, "status": p.status})),
        "get_connection" => pol.get_connection("gh-bearer").map(|c| c.public_view()),
        "list_connections" => pol.list_connections().map(|mut cs| {
            cs.sort_by(|a, b| a.id.cmp(&b.id));
            Value::Array(cs.iter().map(|c| c.public_view()).collect())
        }),
        "get_grant" => pol.get_grant("g-gh-bearer").and_then(|g| g.public_view()),
        "list_grants" => (|| {
            let mut gs = pol.list_grants(Some("agent-1"))?;
            gs.sort_by(|a, b| a.id.cmp(&b.id));
            let mut out = Vec::with_capacity(gs.len());
            for g in &gs {
                out.push(g.public_view()?);
            }
            Ok(Value::Array(out))
        })(),
        "evaluate" => pol
            .evaluate(
                "agent-1",
                "gh-bearer",
                &Action::http("GET", "/repos"),
                Some("g-gh-bearer"),
            )
            .map(|d| json!({"allowed": d.allowed, "reason": d.reason})),
        "check_grant" => pol
            .check_grant("agent-1", "gh-bearer", "g-gh-bearer")
            .map(|d| json!({"allowed": d.allowed, "reason": d.reason})),
        "usable_connections" => pol.usable_connections("agent-1").map(|mut uc| {
            uc.sort_by(|a, b| {
                (a.0.id.as_str(), a.1.id.as_str()).cmp(&(b.0.id.as_str(), b.1.id.as_str()))
            });
            Value::Array(uc.iter().map(|(c, g)| json!([c.id, g.id])).collect())
        }),
        "is_stopped" => pol.is_stopped().map(|b| json!(b)),
        "restore_pending" => pol.restore_pending().map(|b| json!(b)),
        "list_approvals" => pol.list_approvals().map(Value::Object),
        "approval_history" => pol.approval_history().map(Value::Array),
        _ => unreachable!("unknown read op {op}"),
    };
    Outcome::from_rust_result(r)
}

fn run_rust_write_op(state: &StateDir, pol: &Policy, op: &str) -> Outcome {
    let r: Result<Value, zeropw::errors::Error> = match op {
        "resume" => pol.resume().map(|_| Value::Null),
        "request_approval" => pol.request_approval("dg1", "agent-1", "gh-bearer", "GET", "/repos"),
        "revoke_grant" => pol
            .revoke_grant("g-gh-bearer")
            .and_then(|g| g.public_view()),
        "revoke_all" => pol.revoke_all().map(|n| json!(n)),
        "reapply_revocations" => {
            let revocations = Revocations {
                grants: HashSet::from(["g-gh-bearer".to_string()]),
                principals: HashSet::from(["agent-1".to_string()]),
                connections: HashSet::from(["gh-bearer".to_string()]),
                secret_versions: HashSet::new(),
            };
            pol.reapply_revocations(&revocations).map(|counts| {
                let mut m: BTreeMap<&str, usize> = BTreeMap::new();
                for (k, v) in counts {
                    m.insert(k, v);
                }
                serde_json::to_value(m).unwrap()
            })
        }
        "credential_versions_changed" => {
            pol.credential_versions_changed("gh-token").map(|mut cs| {
                cs.sort_by(|a, b| a.id.cmp(&b.id));
                Value::Array(cs.iter().map(|c| json!(c.id)).collect())
            })
        }
        "update_connection" => pol
            .update_connection(
                "gh-bearer",
                ConnectionChanges::new().description("mutated".to_string()),
            )
            .map(|(c, widened)| json!({"view": c.public_view(), "widened": widened})),
        "disable_principal" => pol.disable_principal("agent-1", false).map(|_| Value::Null),
        "disable_connection" => pol.disable_connection("gh-bearer").map(|c| c.public_view()),
        "consume" => pol
            .consume(
                "g-gh-bearer",
                Some("agent-1"),
                Some("gh-bearer"),
                Some(Action::http("GET", "/repos")),
                None,
            )
            .and_then(|g| g.public_view()),
        "regrant" => pol.regrant("g-gh-bearer").and_then(|g| g.public_view()),
        "approve" => pol.approve("dg1"),
        // No `grant_id`/`policy_version` (finding D-R7-4): see the matching
        // comment in the Python driver's `consume_approval` branch.
        "consume_approval" => pol
            .consume_approval("dg2", "agent-1", "gh-bearer", None, None)
            .map(|b| json!(b)),
        "revoke_grants_of" => pol.revoke_grants_of("agent-1").map(|n| json!(n)),
        "stop_all" => pol.stop_all().map(|_| Value::Null),
        _ => unreachable!("unknown write op {op}"),
    };
    let _ = state; // state is written to by the ops above via `pol`
    Outcome::from_rust_result(r)
}

/// Extracts a human-readable message from a `catch_unwind` panic payload
/// (a `&str` or `String`, the two shapes `panic!`/`.expect`/an arithmetic
/// overflow's own panic message use; anything else falls back to a fixed
/// placeholder rather than failing to build a divergence message).
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

/// Finding D-R7-1: without this, a Rust panic (e.g. `attempt to add with
/// overflow`, exactly what the unchecked `+ 1` sites this finding fixed
/// used to do) would abort the whole `cargo test` process instead of being
/// reported as a divergence -- so reverting that fix would make the harness
/// itself stop running rather than fail with a clear diagnosis. Wrapping
/// every Rust operation call in `catch_unwind` turns a panic into an
/// ordinary [`Outcome::Panic`], which [`Outcome::matches`] never treats as
/// agreeing with any Python outcome.
fn run_rust_read_op_catching(pol: &Policy, op: &str) -> Outcome {
    match panic::catch_unwind(AssertUnwindSafe(|| run_rust_read_op(pol, op))) {
        Ok(outcome) => outcome,
        Err(payload) => Outcome::Panic(panic_message(payload.as_ref())),
    }
}

fn run_rust_write_op_catching(state: &StateDir, pol: &Policy, op: &str) -> Outcome {
    match panic::catch_unwind(AssertUnwindSafe(|| run_rust_write_op(state, pol, op))) {
        Ok(outcome) => outcome,
        Err(payload) => Outcome::Panic(panic_message(payload.as_ref())),
    }
}

/// The document text plus the revocation ledger (ts-stripped), read back
/// after a write op, for byte comparison against Python's recording.
fn read_docs(state: &StateDir, state_path: &Path) -> Map<String, Value> {
    let mut out = Map::new();
    for (key, name) in [
        ("principals", policy::PRINCIPALS),
        ("connections", policy::CONNECTIONS),
        ("grants", policy::GRANTS),
        ("control", policy::CONTROL),
        ("vault_secrets", policy::VAULT_SECRETS),
    ] {
        let text = std::fs::read_to_string(state_path.join(name)).unwrap();
        out.insert(key.to_string(), Value::String(text));
    }
    let ledger = state
        .read_lines(policy::REVOCATIONS, None)
        .unwrap_or_default();
    let normalized: Vec<Value> = ledger
        .iter()
        .map(|line| {
            let mut v: Value = serde_json::from_str(line).unwrap();
            if let Some(obj) = v.as_object_mut() {
                obj.remove("ts");
            }
            Value::String(serde_json::to_string(&v).unwrap())
        })
        .collect();
    out.insert("ledger".to_string(), Value::Array(normalized));
    out
}

// ------------------------------------------------------------------- test

#[test]
fn policy_differential_matrix_matches_python_across_mutations_and_operations() {
    let harness_dir = TempDir::new().expect("harness tempdir");
    let script_path = harness_dir.path().join("driver.py");
    std::fs::write(&script_path, PY_DRIVER).unwrap();

    let manifest = run_driver(&script_path);
    let mut lines = manifest.lines();

    let header: Value = serde_json::from_str(lines.next().expect("header line")).unwrap();
    let baseline: Map<String, Value> = header["baseline"].as_object().unwrap().clone();

    let mut case_count = 0usize;
    let mut op_count = 0usize;
    let mut divergences: Vec<String> = Vec::new();
    let mut exceptions_hit = 0usize;

    // Finding D-R7-1: a caught panic (see `run_rust_read_op_catching`/
    // `run_rust_write_op_catching`) still fires Rust's default panic hook,
    // which prints a full "thread panicked" message plus backtrace hint to
    // stderr for every single occurrence -- across the whole matrix that
    // can be thousands of lines of noise even though the harness now
    // handles it gracefully. Silenced only for the duration of this loop
    // and always restored afterward (`std::panic::set_hook` is a global,
    // process-wide setting).
    let previous_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let case: Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("bad case line: {e}: {line}"));
        case_count += 1;

        // ---------------- cross-field mutation mode (finding D-R7-6) ----------------
        if case
            .get("cross_field")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            let fields = case["fields"].as_array().unwrap();
            let mutations: Vec<(String, Vec<String>, bool, Value)> = fields
                .iter()
                .map(|f| {
                    let arr = f.as_array().unwrap();
                    let d = arr[0].as_str().unwrap().to_string();
                    let p: Vec<String> = arr[1]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap().to_string())
                        .collect();
                    let label = arr[2].as_str().unwrap();
                    (d, p, label == "missing", arr[3].clone())
                })
                .collect();
            // For `matching_exception` lookups: each field's own (doc,
            // path, missing, label), independent of the mutations vec
            // above (which drops the label string).
            let field_labels: Vec<(String, Vec<String>, bool, String)> = fields
                .iter()
                .map(|f| {
                    let arr = f.as_array().unwrap();
                    let d = arr[0].as_str().unwrap().to_string();
                    let p: Vec<String> = arr[1]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap().to_string())
                        .collect();
                    let label = arr[2].as_str().unwrap().to_string();
                    let missing = label == "missing";
                    (d, p, missing, label)
                })
                .collect();
            // A cross-field case's divergence can be fully explained by
            // *either* of its two individual field mutations independently
            // (e.g. the `connections.secret_id` exception below fires
            // regardless of what the other, unrelated field is doing) --
            // try each field's own single-field named exception in turn.
            let cross_field_exception = |op: &str| -> Option<&'static NamedException> {
                field_labels
                    .iter()
                    .find_map(|(d, p, m, l)| matching_exception(d, p, *m, l, op))
            };
            let case_desc = format!("cross_field={fields:?}");
            let mutated_docs = apply_mutations(&baseline, &mutations);

            // Cross-field cases compare outcomes only (not persisted-
            // document bytes): their purpose is proving the *decision* an
            // interacting pair of fields drives agrees (exactly D-R7-6's
            // `check_grant`/`consume` allow-vs-deny outcome), which the
            // main per-field loop below already covers byte-for-byte for
            // every single-field case.
            {
                let tmp = TempDir::new().unwrap();
                let state_path = tmp.path().join("state");
                let state = StateDir::new(&state_path);
                state.create().unwrap();
                write_docs(&state, &mutated_docs);
                let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));

                for op in READ_OPS {
                    op_count += 1;
                    let rust_outcome = run_rust_read_op_catching(&pol, op);
                    let py_outcome = Outcome::from_manifest(&case["reads"][op]);
                    check_case(
                        &case_desc,
                        op,
                        cross_field_exception(op),
                        &py_outcome,
                        &rust_outcome,
                        &mut divergences,
                        &mut exceptions_hit,
                    );
                }
            }
            for op in WRITE_OPS {
                op_count += 1;
                let tmp = TempDir::new().unwrap();
                let state_path = tmp.path().join("state");
                let state = StateDir::new(&state_path);
                state.create().unwrap();
                write_docs(&state, &mutated_docs);
                let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));

                let mut rust_outcome = run_rust_write_op_catching(&state, &pol, op);
                // Same `regrant` random-id normalisation as the main
                // per-field loop below (see its matching comment).
                if *op == "regrant"
                    && let Outcome::Ok(Value::Object(obj)) = &mut rust_outcome
                    && obj.contains_key("id")
                {
                    obj.insert("id".to_string(), json!("g-REGRANT"));
                }
                let py_outcome = Outcome::from_manifest(&case["writes"][op]["outcome"]);
                check_case(
                    &case_desc,
                    op,
                    cross_field_exception(op),
                    &py_outcome,
                    &rust_outcome,
                    &mut divergences,
                    &mut exceptions_hit,
                );
            }
            continue;
        }

        let doc = case["doc"].as_str().unwrap().to_string();
        let path: Vec<String> = case["path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let missing = case["missing"].as_bool().unwrap();
        let label = case["label"].as_str().unwrap().to_string();
        let value = case["value"].clone();
        let case_desc =
            format!("doc={doc} path={path:?} missing={missing} label={label} value={value}");

        let mutated_docs = apply_mutation(&baseline, &doc, &path, missing, &value);

        // ---- shared read-only state, all READ_OPS against it ----
        {
            let tmp = TempDir::new().unwrap();
            let state_path = tmp.path().join("state");
            let state = StateDir::new(&state_path);
            state.create().unwrap();
            write_docs(&state, &mutated_docs);
            let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));

            for op in READ_OPS {
                op_count += 1;
                let rust_outcome = run_rust_read_op_catching(&pol, op);
                let py_outcome = Outcome::from_manifest(&case["reads"][op]);
                let exception = matching_exception(&doc, &path, missing, &label, op);
                check_case(
                    &case_desc,
                    op,
                    exception,
                    &py_outcome,
                    &rust_outcome,
                    &mut divergences,
                    &mut exceptions_hit,
                );
            }
        }

        // ---- fresh state per WRITE_OPS, plus persisted-bytes comparison ----
        for op in WRITE_OPS {
            op_count += 1;
            let tmp = TempDir::new().unwrap();
            let state_path = tmp.path().join("state");
            let state = StateDir::new(&state_path);
            state.create().unwrap();
            write_docs(&state, &mutated_docs);
            let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));

            let mut rust_outcome = run_rust_write_op_catching(&state, &pol, op);
            // `regrant` (finding D-R7-3's harness gap) creates a fresh
            // grant with a random id neither language can predict --
            // normalise it the same way the Python driver already
            // normalises its own recording (see `normalize_regrant_id`),
            // so the rest of the outcome/document is still comparable.
            if *op == "regrant"
                && let Outcome::Ok(Value::Object(obj)) = &mut rust_outcome
                && obj.contains_key("id")
            {
                obj.insert("id".to_string(), json!("g-REGRANT"));
            }
            let py_outcome = Outcome::from_manifest(&case["writes"][op]["outcome"]);
            let exception = matching_exception(&doc, &path, missing, &label, op);
            let matched = check_case(
                &case_desc,
                op,
                exception,
                &py_outcome,
                &rust_outcome,
                &mut divergences,
                &mut exceptions_hit,
            );

            let skip_docs = exception.is_some_and(|e| e.skip_doc_compare);
            if matched && !skip_docs {
                let mut rust_docs = read_docs(&state, &state_path);
                if *op == "regrant" {
                    normalize_regrant_id_in_docs(&mut rust_docs);
                }
                let py_docs = case["writes"][op]["docs"].as_object().unwrap();
                for key in [
                    "principals",
                    "connections",
                    "grants",
                    "control",
                    "vault_secrets",
                ] {
                    // `regrant`'s fresh grant's *original* random id (before
                    // `normalize_regrant_id` relabels it to the fixed
                    // `"g-REGRANT"` placeholder) still decided where
                    // `write_json`'s `sort_keys=True` placed that entry in
                    // the document -- Python's and Rust's independently
                    // generated random ids sort into different positions,
                    // so a raw byte/text comparison of the *relabelled*
                    // text would spuriously "differ" on key order alone,
                    // not on any real content difference. Only for
                    // `grants` under `regrant`, compare structurally
                    // (`serde_json::Value`'s `PartialEq`, which -- built on
                    // `indexmap`'s own map equality -- is order-independent)
                    // instead of by raw text.
                    let differs = if key == "grants" && *op == "regrant" {
                        let py_val: Value = serde_json::from_str(py_docs[key].as_str().unwrap())
                            .expect("python grants doc is valid json");
                        let rust_val: Value =
                            serde_json::from_str(rust_docs[key].as_str().unwrap())
                                .expect("rust grants doc is valid json");
                        py_val != rust_val
                    } else {
                        rust_docs[key] != py_docs[key]
                    };
                    if differs {
                        divergences.push(format!(
                            "{case_desc} op={op}: document {key} bytes differ\n  python: {}\n  rust:   {}",
                            py_docs[key], rust_docs[key]
                        ));
                    }
                }
                if rust_docs["ledger"] != py_docs["ledger"] {
                    divergences.push(format!(
                        "{case_desc} op={op}: revocation ledger differs\n  python: {}\n  rust:   {}",
                        py_docs["ledger"], rust_docs["ledger"]
                    ));
                }
            }
        }
    }

    panic::set_hook(previous_hook);

    eprintln!(
        "policy_differential: {case_count} mutation cases x ~{} ops = {op_count} checks, {exceptions_hit} named-exception hits",
        READ_OPS.len() + WRITE_OPS.len()
    );

    if !divergences.is_empty() {
        panic!(
            "{} unexplained divergence(s) between python3.12 and rust:\n\n{}",
            divergences.len(),
            divergences.join("\n\n")
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn check_case(
    case_desc: &str,
    op: &str,
    exception: Option<&NamedException>,
    py: &Outcome,
    rust: &Outcome,
    divergences: &mut Vec<String>,
    exceptions_hit: &mut usize,
) -> bool {
    if py.matches(rust) {
        return true;
    }
    if let Some(exc) = exception {
        if (exc.judge)(py, rust) {
            *exceptions_hit += 1;
            return true;
        }
        divergences.push(format!(
            "{case_desc} op={op}: named exception {:?} did not take its documented shape (python={py:?} rust={rust:?})",
            exc.description
        ));
        return false;
    }
    divergences.push(format!("{case_desc} op={op}: python={py:?} rust={rust:?}"));
    false
}
