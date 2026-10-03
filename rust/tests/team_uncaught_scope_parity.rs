//! Scope of the failures for peer input the Python prototype let escape as
//! uncaught built-in exceptions from `zeropw/team/commit.py`'s op validation
//! (`_build_http_scope`'s `prefix.startswith`, `HttpAuth.__post_init__`'s
//! `re.match`/`in`, `_build_cli_profile`'s `dict(...)` `ValueError`) and
//! from canonicalizing a commit whose op holds a non-string key.
//!
//! Such a commit must fail closed at the same scope: `receive_commit`
//! errors before recording a rejection (no `rejected/` record, no
//! `team_commit_rejected` audit), `fold()` aborts (no partial result) and
//! `TeamSync`'s receive loop drops the session, while a documented
//! `InvalidInput` in the same position is still an ordinary rejection/skip.
//! The outcomes were measured against CPython 3.12 and are pinned here.
use std::collections::BTreeMap;

use serde_json::{Value, json};
use tempfile::TempDir;
use zeropw::errors::ErrorClass;
use zeropw::pybase64;
use zeropw::pyint::PyInt;
use zeropw::store::StateDir;
use zeropw::team::commit::{self as C, Commit};
use zeropw::team::fold as F;
use zeropw::team::identity::DeviceKey;

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
/// documented-reason controls): the error (named after the Python exception
/// that escaped), the absence of a rejected record and the aborted fold; a
/// commit that merely fails a documented check is still rejected/skipped
/// with Python's reason.
#[test]
fn escaping_validation_exceptions_fail_at_python_scope() {
    let owner = device(0x31);
    let (env_id, c1) = genesis(&owner);
    let mut rust = serde_json::Map::new();
    for (name, op) in cases() {
        // The secret exists first, so the fold reaches the connection
        // builder instead of skipping with `secret_not_found`.
        let put = json!({"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
            "generation_id": "0".repeat(16), "version_id": "00112233445566778899aabbccddeeff",
            "ciphertext": {"nonce": "AAAA", "ciphertext": "AAAA"}, "public": {}});
        let c2 = signed(&owner, &env_id, 2, "2000-0000", vec![put, op]);
        rust.insert(name.into(), rust_outcomes(&env_id, &c1, &c2));
    }
    let raise = |name: &str| json!({"receive": format!("RAISE {name}"), "rejected": 0,
        "fold": format!("RAISE {name}")});
    let rejected = |reason: &str| json!({"receive": "rejected", "rejected": 1, "fold": [reason]});
    assert_eq!(
        Value::Object(rust),
        json!({
            "basic_int": raise("TypeError"),
            "basic_true": raise("TypeError"),
            "extra_env_long_item": raise("ValueError"),
            "extra_env_ok": {"receive": "accepted", "rejected": 0, "fold": []},
            "extra_env_scalar_item": rejected("invalid_cli_profile"),
            "extra_env_string": raise("ValueError"),
            "extra_env_unhashable_first": rejected("invalid_cli_profile"),
            "header_falsy": rejected("invalid_header_name"),
            "header_int": raise("TypeError"),
            "header_list": raise("TypeError"),
            "prefix_after_valid": raise("AttributeError"),
            "prefix_int": raise("AttributeError"),
            "prefix_invalid_first": rejected("invalid_path_prefix"),
        })
    );
}

/// A commit whose op holds a non-string key: Python's `Commit.from_dict`
/// accepted it and `receive_commit` then raised `TypeError` from
/// canonicalization before recording anything (no `rejected/` directory).
/// Here parsing reports the same uncaught error, never `InvalidInput`.
#[test]
fn non_string_op_key_commit_raises_in_receive_commit_like_python() {
    let owner = device(0x32);
    let (_env_id, c1) = genesis(&owner);
    let mut raw = c1.to_dict();
    raw["author_seq"] = json!(2);
    raw["hlc"] = json!("2000-0000");
    raw["ops"] = json!([[
        ["op", "settings.update"],
        ["sync_interval_seconds", 5],
        [1, "x"]
    ]]);
    let error = Commit::from_dict(&raw).unwrap_err();
    assert!(!error.is(ErrorClass::InvalidInput));
    assert_eq!(
        (error.reason.as_ref(), error.detail.as_str()),
        ("team_uncaught_exception", "TypeError")
    );
}

// ------------------------------------------------------------- session scope

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::team::identity::DeviceRecord;
use zeropw::team::transport::{InProcessTransport, MembershipCheck, Session, SessionClosed};
use zeropw::team::{membership, sync};

/// A session fed by the test: frames pushed on the channel are received.
struct Scripted {
    peer: DeviceRecord,
    env_id: String,
    inbox: Mutex<mpsc::Receiver<Value>>,
    closed: AtomicBool,
    created: Instant,
}
impl Session for Scripted {
    fn peer(&self) -> DeviceRecord {
        self.peer.clone()
    }
    fn env_id(&self) -> &str {
        &self.env_id
    }
    fn send(&self, _message: &Value) -> zeropw::errors::Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(zeropw::errors::Error::state("session_closed"));
        }
        Ok(())
    }
    fn recv(&self, timeout: Duration) -> std::result::Result<Option<Value>, SessionClosed> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SessionClosed("session_closed"));
        }
        match self.inbox.lock().unwrap().recv_timeout(timeout) {
            Ok(message) => Ok(Some(message)),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(SessionClosed("peer_closed")),
        }
    }
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
    fn created_at(&self) -> Instant {
        self.created
    }
}

const ADMIN: &str = "synthetic-admin";

fn rust_session_case(name: &str) -> Value {
    let root = TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            root.path().join("a"),
            ADMIN,
            "synthetic-recovery",
            Config {
                team_sync_interval_seconds: Some(3600.0),
                ..Config::default()
            },
            clock::system(),
        )
        .unwrap(),
    );
    ctx.projects.create("demo", &["dev"]).unwrap();
    let env_id = membership::share_environment(&ctx, None, "demo", "dev", "owner", ADMIN).unwrap()
        ["env_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let key = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let members: MembershipCheck = Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None });
    let transport = Arc::new(InProcessTransport::new(key.clone(), members));
    let team = sync::TeamSync::new(ctx.clone(), transport, key.clone());
    team.register_env(&env_id).unwrap();
    let store = C::CommitStore::new(ctx.state, &env_id);
    let last = store.last_seq(&key.fingerprint().unwrap()).unwrap();
    let op = if name == "escaping_validation" {
        json!({"op": "connection.create", "id": "gh", "project": "demo", "environment": "dev",
            "service": "github", "kind": "http", "secret_id": "s", "description": "",
            "http_target": {"scheme": "https", "host": "api.github.com", "port": 443},
            "http_auth": {"mode": "bearer"}, "http_scope": {"methods": ["GET"], "path_prefixes": [5]}})
    } else {
        json!({"op": "settings.update", "sync_interval_seconds": 5})
    };
    let mut c = Commit {
        format: C::COMMIT_FORMAT.into(),
        env_id: env_id.clone(),
        author: key.fingerprint().unwrap(),
        author_seq: &last + 1,
        hlc: format!("{}-0000", C::now_ms()),
        seen: BTreeMap::new(),
        ops: vec![op],
        sig: String::new(),
    };
    c.sig = pybase64::b64encode(&key.sign(&c.canonical_json(false).unwrap()).unwrap());
    let mut raw = c.to_dict();
    if name == "non_string_key" || name == "other_env" {
        raw["ops"] = json!([[
            ["op", "settings.update"],
            ["sync_interval_seconds", 5],
            [1, "x"]
        ]]);
    }
    if name == "other_env" {
        raw["env_id"] = json!("elsewhere");
    }
    if name == "malformed" {
        raw.as_object_mut().unwrap().remove("sig");
    }
    if name == "overflow_other_env" {
        raw["author_seq"] = serde_json::from_str("1e400").unwrap();
        raw["env_id"] = json!("elsewhere");
    }
    if name == "empty_ops_dict" {
        raw["ops"] = json!({});
    }
    let (tx, rx) = mpsc::channel();
    let peer = DeviceKey::generate().record().unwrap();
    let fp = peer.fingerprint();
    let session = Arc::new(Scripted {
        peer,
        env_id: env_id.clone(),
        inbox: Mutex::new(rx),
        closed: AtomicBool::new(false),
        created: Instant::now(),
    });
    team.adopt_outbound_session(&env_id, session.clone(), "scripted");
    tx.send(json!({"type": "COMMIT", "commit": raw})).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let open = |team: &sync::TeamSync| {
        team.status(&env_id).unwrap()["sessions"]
            .as_array()
            .unwrap()
            .contains(&json!(fp))
    };
    while Instant::now() < deadline && open(&team) {
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(1500));
    let rejected = ctx.state.path.join("team").join(&env_id).join("rejected");
    let result = json!({
        "session_open": open(&team),
        "rejected": std::fs::read_dir(&rejected).map(|mut d| d.next().is_some()).unwrap_or(false),
        "audited": ctx.audit.tail(200).unwrap().iter().any(|r| r["event"] == "team_commit_rejected"),
    });
    team.stop();
    drop(tx);
    result
}

/// `TeamSync._handle_commit` over a live session: a commit whose
/// canonicalization or validation raises a built-in exception ends the
/// receive loop (session dropped, nothing recorded), while a malformed
/// (`InvalidInput`) commit or another environment's commit is ignored and
/// the session stays open -- as measured against CPython's `TeamSync`.
#[test]
fn escaping_receive_exceptions_drop_the_session_like_python() {
    let dropped = json!({"session_open": false, "rejected": false, "audited": false});
    let ignored = json!({"session_open": true, "rejected": false, "audited": false});
    for (name, expected) in [
        ("non_string_key", dropped.clone()),
        ("escaping_validation", dropped.clone()),
        ("malformed", ignored.clone()),
        ("other_env", ignored),
        ("overflow_other_env", dropped),
        (
            "empty_ops_dict",
            json!({"session_open": true, "rejected": true, "audited": true}),
        ),
    ] {
        assert_eq!(rust_session_case(name), expected, "{name}");
    }
}
