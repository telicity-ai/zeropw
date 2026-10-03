//! Scope parity for the built-in exceptions CPython lets escape from
//! `zeropw/team/commit.py`'s op validation (`_build_http_scope`'s
//! `prefix.startswith`, `HttpAuth.__post_init__`'s `re.match`/`in`,
//! `_build_cli_profile`'s `dict(...)` `ValueError`) and from
//! canonicalizing a commit whose op holds a non-string key.
//!
//! PORTING.md §3.5 allows a different error identity only at the SAME scope
//! (§3d). Python's exception escapes `receive_commit` before `_reject`
//! (no `rejected/` record, no `team_commit_rejected` audit), escapes
//! `fold()` (no partial result) and ends `TeamSync`'s receive loop (the
//! session is dropped). These tests measure each against CPython 3.12 and
//! check the Rust port fails at the same scope, while a documented
//! `InvalidInput` in the same position is still an ordinary rejection/skip.
use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use tempfile::TempDir;
use zeropw::errors::ErrorClass;
use zeropw::pybase64;
use zeropw::pyint::PyInt;
use zeropw::pyjson::{self, DumpOptions};
use zeropw::store::StateDir;
use zeropw::team::commit::{self as C, Commit};
use zeropw::team::fold as F;
use zeropw::team::identity::DeviceKey;

fn python(script: &str) -> Value {
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".into());
    let mut child = Command::new(interpreter)
        .arg("-")
        .env("PYTHONPATH", format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

fn device(seed: u8) -> DeviceKey {
    DeviceKey {
        sign_seed: zeropw::secret::SecretBytes::from_slice(&[seed; 32]),
        agree_private: zeropw::secret::SecretBytes::from_slice(&[seed ^ 0x5a; 32]),
    }
}

/// A commit signed over its canonical bytes WITHOUT `sign_commit`'s
/// `validate_ops` (a peer's own signer need not run it).
fn signed(owner: &DeviceKey, env_id: &str, seq: i64, hlc: &str, ops: Vec<Value>) -> Commit {
    let mut commit = Commit {
        format: C::COMMIT_FORMAT.into(),
        env_id: env_id.into(),
        author: owner.fingerprint().unwrap(),
        author_seq: PyInt::from(seq),
        hlc: hlc.into(),
        seen: BTreeMap::new(),
        ops,
        sig: String::new(),
    };
    let sig = owner.sign(&commit.canonical_json(false).unwrap()).unwrap();
    commit.sig = pybase64::b64encode(&sig);
    commit
}

fn genesis(owner: &DeviceKey) -> (String, Commit) {
    let record = owner.record().unwrap();
    let env_id = C::new_env_id(&record.fingerprint()).unwrap();
    let gen0 = "0".repeat(16);
    let op = json!({"op": "env.init", "owner_device": record.to_dict(), "owner_name": "alice",
        "generation_id": gen0,
        "wraps": {record.fingerprint(): {"eph_pub": "AAAA", "nonce": "AAAA", "ciphertext": "AAAA"}}});
    let c1 = C::sign_commit(owner, &env_id, 1, "1000-0000", &BTreeMap::new(), vec![op]).unwrap();
    (env_id, c1)
}

fn connection_create(http_scope: Value, http_auth: Value, cli: Value) -> Value {
    json!({"op": "connection.create", "id": "gh", "project": "demo", "environment": "dev",
        "service": "github", "kind": "http", "secret_id": "gh-token", "secret_version": null,
        "description": "", "http_target": {"scheme": "https", "host": "api.github.com", "port": 443},
        "http_auth": http_auth, "http_scope": http_scope, "cli": cli})
}

/// `(case name, op)`: every escaping shape plus documented-reason controls.
fn cases() -> Vec<(&'static str, Value)> {
    let scope = |prefixes: Value| json!({"methods": ["GET"], "path_prefixes": prefixes});
    let bearer = json!({"mode": "bearer"});
    let get = json!({"methods": ["GET"]});
    let cli = |extra: Value| json!({"program": "gh", "kind": "http", "extra_env": extra});
    vec![
        (
            "prefix_int",
            connection_create(scope(json!([5])), bearer.clone(), Value::Null),
        ),
        (
            "prefix_after_valid",
            connection_create(scope(json!(["/ok", true])), bearer.clone(), Value::Null),
        ),
        (
            "prefix_invalid_first",
            connection_create(scope(json!(["bad", 5])), bearer.clone(), Value::Null),
        ),
        (
            "header_int",
            connection_create(
                get.clone(),
                json!({"mode": "header", "header_name": 5}),
                Value::Null,
            ),
        ),
        (
            "header_list",
            connection_create(
                get.clone(),
                json!({"mode": "header", "header_name": ["X-Foo"]}),
                Value::Null,
            ),
        ),
        (
            "header_falsy",
            connection_create(
                get.clone(),
                json!({"mode": "header", "header_name": 0}),
                Value::Null,
            ),
        ),
        (
            "basic_int",
            connection_create(
                get.clone(),
                json!({"mode": "basic", "basic_username": 7}),
                Value::Null,
            ),
        ),
        (
            "basic_true",
            connection_create(
                get.clone(),
                json!({"mode": "basic", "basic_username": true}),
                Value::Null,
            ),
        ),
        (
            "extra_env_string",
            connection_create(get.clone(), bearer.clone(), cli(json!("ab"))),
        ),
        (
            "extra_env_long_item",
            connection_create(get.clone(), bearer.clone(), cli(json!(["AB", "abc"]))),
        ),
        (
            "extra_env_scalar_item",
            connection_create(get.clone(), bearer.clone(), cli(json!([5, "abc"]))),
        ),
        (
            "extra_env_unhashable_first",
            connection_create(get.clone(), bearer.clone(), cli(json!([[[1], "x"], "abc"]))),
        ),
        (
            "extra_env_ok",
            connection_create(get, bearer, cli(json!([["A", "x"]]))),
        ),
    ]
}

const PY_SCOPE: &str = r#"
import json, sys, tempfile
from pathlib import Path
from zeropw.store import StateDir
from zeropw.team import commit as C, fold as F
data = json.loads(sys.stdin.readline())
c1 = C.Commit.from_dict(data["c1"])
out = {}
for name, raw in data["cases"].items():
    c2 = C.Commit.from_dict(raw)
    with tempfile.TemporaryDirectory() as tmp:
        state = StateDir(Path(tmp) / "state")
        state.create()
        store = C.CommitStore(state, data["env_id"])
        assert C.receive_commit(store, c1, 1_000_000) == "accepted"
        try:
            receive = C.receive_commit(store, c2, 1_000_000)
        except Exception as exc:
            receive = "RAISE " + type(exc).__name__
        rejected_dir = state.path / "team" / data["env_id"] / "rejected"
        rejected = list(rejected_dir.glob("*.json")) if rejected_dir.is_dir() else []
    try:
        folded = F.fold(data["env_id"], [c1, c2])
        fold = [s[2] for s in folded.skipped]
    except Exception as exc:
        fold = "RAISE " + type(exc).__name__
    out[name] = {"receive": receive, "rejected": len(rejected), "fold": fold}
print(json.dumps(out))
"#;

fn rust_outcomes(env_id: &str, c1: &Commit, c2: &Commit) -> Value {
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let store = C::CommitStore::new(&state, env_id);
    assert_eq!(
        C::receive_commit(&store, c1, 1_000_000, None).unwrap(),
        "accepted"
    );
    let receive = match C::receive_commit(&store, c2, 1_000_000, None) {
        Ok(outcome) => json!(outcome),
        Err(error) => {
            assert!(!error.is(ErrorClass::InvalidInput));
            assert_eq!(error.reason, "team_uncaught_exception");
            json!(format!("RAISE {}", error.detail))
        }
    };
    let rejected_dir = state.path.join("team").join(env_id).join("rejected");
    let rejected = std::fs::read_dir(&rejected_dir)
        .map(|entries| entries.count())
        .unwrap_or(0);
    let fold = match F::fold(env_id, vec![c1.clone(), c2.clone()], None, None, None, None) {
        Ok(result) => json!(
            result
                .skipped
                .iter()
                .map(|s| s.2.clone())
                .collect::<Vec<_>>()
        ),
        Err(error) => {
            assert_eq!(error.reason, "team_uncaught_exception");
            json!(format!("RAISE {}", error.detail))
        }
    };
    json!({"receive": receive, "rejected": rejected, "fold": fold})
}

/// `receive_commit` and `fold` for each escaping op shape (and its
/// documented-reason controls): the Python exception type, the absence of a
/// rejected record and the aborted fold are matched exactly; a commit that
/// merely fails a documented check is still rejected/skipped with Python's
/// reason. Python's own uncaught exception names are asserted as measured.
#[test]
fn escaping_validation_exceptions_match_python_scope() {
    let owner = device(0x31);
    let (env_id, c1) = genesis(&owner);
    let mut commits = serde_json::Map::new();
    let mut rust = serde_json::Map::new();
    for (name, op) in cases() {
        // The secret exists first, so the fold reaches the connection
        // builder instead of skipping with `secret_not_found`.
        let put = json!({"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
            "generation_id": "0".repeat(16), "version_id": "00112233445566778899aabbccddeeff",
            "ciphertext": {"nonce": "AAAA", "ciphertext": "AAAA"}, "public": {}});
        let c2 = signed(&owner, &env_id, 2, "2000-0000", vec![put, op]);
        rust.insert(name.into(), rust_outcomes(&env_id, &c1, &c2));
        commits.insert(name.into(), c2.to_dict());
    }
    let input = json!({"env_id": env_id, "c1": c1.to_dict(), "cases": commits});
    let line = pyjson::dumps(&input, DumpOptions::compact_sorted()).unwrap();
    let python = python(&format!(
        "import io, sys\nsys.stdin = io.StringIO({})\n{PY_SCOPE}",
        zeropw::pystr::repr_str(&line)
    ));
    assert_eq!(Value::Object(rust), python);
    let expect = |name: &str, receive: &str| {
        assert_eq!(python[name]["receive"], json!(receive), "{name}");
    };
    expect("prefix_int", "RAISE AttributeError");
    expect("prefix_after_valid", "RAISE AttributeError");
    expect("prefix_invalid_first", "rejected");
    expect("header_int", "RAISE TypeError");
    expect("header_list", "RAISE TypeError");
    expect("header_falsy", "rejected");
    expect("basic_int", "RAISE TypeError");
    expect("basic_true", "RAISE TypeError");
    expect("extra_env_string", "RAISE ValueError");
    expect("extra_env_long_item", "RAISE ValueError");
    expect("extra_env_scalar_item", "rejected");
    expect("extra_env_unhashable_first", "rejected");
    expect("extra_env_ok", "accepted");
    assert_eq!(python["prefix_int"]["rejected"], json!(0));
    assert_eq!(python["prefix_int"]["fold"], json!("RAISE AttributeError"));
    assert_eq!(python["prefix_invalid_first"]["rejected"], json!(1));
    assert_eq!(
        python["prefix_invalid_first"]["fold"],
        json!(["invalid_path_prefix"])
    );
}

/// A commit whose op holds a non-string key: Python's `Commit.from_dict`
/// accepts it and `receive_commit` then raises `TypeError` from
/// canonicalization before recording anything.
#[test]
fn non_string_op_key_commit_raises_in_receive_commit_like_python() {
    let owner = device(0x32);
    let (env_id, c1) = genesis(&owner);
    let mut raw = c1.to_dict();
    raw["author_seq"] = json!(2);
    raw["hlc"] = json!("2000-0000");
    raw["ops"] = json!([[
        ["op", "settings.update"],
        ["sync_interval_seconds", 5],
        [1, "x"]
    ]]);
    let input = json!({"env_id": env_id, "c1": c1.to_dict(), "raw": raw});
    let line = pyjson::dumps(&input, DumpOptions::compact_sorted()).unwrap();
    let python = python(&format!(
        r#"
import io, json, tempfile
from pathlib import Path
from zeropw.store import StateDir
from zeropw.team import commit as C
data = json.loads({line})
c1 = C.Commit.from_dict(data["c1"])
c2 = C.Commit.from_dict(data["raw"])
with tempfile.TemporaryDirectory() as tmp:
    state = StateDir(Path(tmp) / "state")
    state.create()
    store = C.CommitStore(state, data["env_id"])
    assert C.receive_commit(store, c1, 1_000_000) == "accepted"
    try:
        out = C.receive_commit(store, c2, 1_000_000)
    except Exception as exc:
        out = "RAISE " + type(exc).__name__
    print(json.dumps({{"receive": out, "rejected": (state.path / "team" / data["env_id"] / "rejected").is_dir()}}))
"#,
        line = zeropw::pystr::repr_str(&line)
    ));
    assert_eq!(
        python,
        json!({"receive": "RAISE TypeError", "rejected": false})
    );
    let error = Commit::from_dict(&raw).unwrap_err();
    assert!(!error.is(ErrorClass::InvalidInput));
    assert_eq!(
        (error.reason.as_ref(), error.detail.as_str()),
        ("team_uncaught_exception", "TypeError")
    );
}
