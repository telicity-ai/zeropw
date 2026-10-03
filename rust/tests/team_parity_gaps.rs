//! Parity regressions for team sync/membership behaviour that previously
//! differed from the Python specification (`zeropw/team/sync.py`,
//! `zeropw/team/membership.py`). Synthetic keys and in-process sessions only.
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::TempDir;
use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::errors::{Error, Result};
use zeropw::team::commit::{self, Commit, CommitStore, Hlc};
use zeropw::team::identity::{DeviceKey, DeviceRecord};
use zeropw::team::transport::{
    InProcessTransport, MembershipCheck, Session, SessionClosed, Transport,
};
use zeropw::team::{membership, sync};

const ADMIN: &str = "synthetic-admin";

fn python(script: &str) -> Value {
    let mut child = Command::new("python3.12")
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

/// A session driven by the test: frames pushed on `inbox` are what the node
/// receives; everything the node sends is recorded in `sent`.
struct Scripted {
    peer: DeviceRecord,
    env_id: String,
    inbox: Mutex<mpsc::Receiver<Value>>,
    sent: Mutex<Vec<Value>>,
    closed: AtomicBool,
    created: Instant,
    /// When set, `recv` ignores its timeout and `close` and blocks this long.
    stuck_for: Option<Duration>,
    /// When set, `send` fails although the session is still open.
    fail_sends: AtomicBool,
}
impl Scripted {
    fn new(
        peer: DeviceRecord,
        env_id: &str,
        stuck_for: Option<Duration>,
    ) -> (Arc<Self>, mpsc::Sender<Value>) {
        let (tx, rx) = mpsc::channel();
        (
            Arc::new(Self {
                peer,
                env_id: env_id.to_owned(),
                inbox: Mutex::new(rx),
                sent: Mutex::new(Vec::new()),
                closed: AtomicBool::new(false),
                created: Instant::now(),
                stuck_for,
                fail_sends: AtomicBool::new(false),
            }),
            tx,
        )
    }
    fn frames(&self, kind: &str) -> Vec<Value> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m["type"] == kind)
            .cloned()
            .collect()
    }
    fn commit_count(&self, commit: &Commit) -> usize {
        self.frames("COMMIT")
            .iter()
            .filter(|m| m["commit"] == commit.to_dict())
            .count()
    }
}
impl Session for Scripted {
    fn peer(&self) -> DeviceRecord {
        self.peer.clone()
    }
    fn env_id(&self) -> &str {
        &self.env_id
    }
    fn send(&self, message: &Value) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) || self.fail_sends.load(Ordering::SeqCst) {
            return Err(Error::state("session_closed"));
        }
        self.sent.lock().unwrap().push(message.clone());
        Ok(())
    }
    fn recv(&self, timeout: Duration) -> std::result::Result<Option<Value>, SessionClosed> {
        if let Some(stuck) = self.stuck_for {
            std::thread::sleep(stuck);
            return Ok(None);
        }
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

fn no_members() -> MembershipCheck {
    Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None })
}

fn context(root: &TempDir, name: &str) -> Arc<Context> {
    Arc::new(
        Context::initialize(
            root.path().join(name),
            ADMIN,
            "synthetic-recovery",
            Config {
                // No periodic VECTOR frames during a test: only the frames a
                // test provokes are recorded.
                team_sync_interval_seconds: Some(3600.0),
                ..Config::default()
            },
            clock::system(),
        )
        .unwrap(),
    )
}

// `share_environment` compares JSON-decoded Python numeric values with
// integer version keys. This differential uses Python to prepare identical
// encrypted states so large synthetic version keys have matching AAD in the
// Rust half too.
#[test]
fn share_environment_numeric_version_identity_matches_python() {
    let root = TempDir::new().unwrap();
    let rust_states: Vec<_> = (0..5)
        .map(|index| root.path().join(format!("rust-numeric-{index}")))
        .collect();
    let python_states: Vec<_> = (0..5)
        .map(|index| root.path().join(format!("python-numeric-{index}")))
        .collect();
    let rust_paths = serde_json::to_string(&rust_states).unwrap();
    let python_paths = serde_json::to_string(&python_states).unwrap();
    let script = format!(
        r#"
import json
from pathlib import Path
from zeropw import policy as P
from zeropw.context import Config, Context
from zeropw.store import iso
from zeropw.team import membership as M

cases = [
    ("bool", 1, True, True),
    ("float", 1, 1.0, 1.0),
    ("large_exact", 9007199254740993, 9007199254740993, 9007199254740993),
    ("integer_mismatch", 9007199254740992, 9007199254740993, 9007199254740993),
    ("rounded_float", 9007199254740992, 9007199254740993.0, 9007199254740993.0),
]

def prepare(path, key, active, connection_version):
    ctx = Context.initialize(Path(path), "synthetic-admin", "synthetic-recovery", Config())
    ctx.projects.create("demo", ["dev"])
    ctx.vault.put_secret("secret", "api_key", b"synthetic-seed", "demo", "dev")
    doc = ctx.state.read_json("vault/secrets.json")
    record = ctx.vault._encrypt("secret", key, b"synthetic-wide")
    record.update({{"created_at": iso(), "status": "active", "public": {{}}}})
    entry = doc["secrets"]["secret"]
    entry["versions"] = {{str(key): record}}
    entry["active_version"] = active
    ctx.state.write_json("vault/secrets.json", doc)
    ctx.policy.create_connection(P.Connection(
        id="connection", project="demo", environment="dev", service="synthetic", kind="http",
        secret_id="secret", secret_version=None, description="",
        http_target=P.HttpTarget("https", "example.com", 443), http_auth=P.HttpAuth("bearer"),
        http_scope=P.HttpScope(), ssh_target=None, cli=None, policy_version=0, status="active",
        created_at="", updated_at=""))
    connections = ctx.state.read_json(P.CONNECTIONS)
    connections["connection"]["secret_version"] = connection_version
    ctx.state.write_json(P.CONNECTIONS, connections)
    return ctx

def summary(ctx, env_id):
    doc = M.load_environment(ctx, env_id).document
    secret = doc["secrets"]["secret"]
    connection = doc["connections"]["connection"]
    active = secret["active_version"]
    pinned = connection["secret_version"]
    return {{"active": active is not None, "pinned": pinned is not None,
             "pin_is_active": pinned is not None and pinned == active}}

rust_paths = {rust_paths}
python_paths = {python_paths}
out = []
for (case, key, active, connection_version), rust_path, python_path in zip(cases, rust_paths, python_paths):
    prepare(rust_path, key, active, connection_version).close()
    ctx = prepare(python_path, key, active, connection_version)
    env_id = M.share_environment(ctx, None, "demo", "dev", "owner", "synthetic-admin")["env_id"]
    out.append({{"case": case, **summary(ctx, env_id)}})
print(json.dumps(out, sort_keys=True))
"#,
    );
    let expected = python(&script);
    let mut actual = Vec::new();
    for (index, state) in rust_states.iter().enumerate() {
        let ctx = Context::open(state, Config::default(), clock::system()).unwrap();
        let env_id = membership::share_environment(&ctx, None, "demo", "dev", "owner", ADMIN)
            .unwrap()["env_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let doc = membership::load_environment(&ctx, &env_id)
            .unwrap()
            .document;
        let active = &doc["secrets"]["secret"]["active_version"];
        let pinned = &doc["connections"]["connection"]["secret_version"];
        actual.push(json!({
            "case": expected[index]["case"],
            "active": !active.is_null(),
            "pinned": !pinned.is_null(),
            "pin_is_active": !pinned.is_null() && pinned == active,
        }));
    }
    assert_eq!(json!(actual), expected);
    assert_eq!(expected[0]["active"], true);
    assert_eq!(expected[1]["active"], true);
    assert_eq!(expected[2]["active"], true);
    assert_eq!(expected[3]["active"], false);
    assert_eq!(expected[3]["pinned"], false);
    assert_eq!(expected[4]["active"], true);
}

#[test]
fn share_environment_invalid_retired_version_key_fails_before_mutation_like_python() {
    let root = TempDir::new().unwrap();
    let rust_state = root.path().join("rust-invalid-key");
    let python_state = root.path().join("python-invalid-key");
    let script = format!(
        r#"
import json
from pathlib import Path
from zeropw.context import Config, Context
from zeropw.team import membership as M

def prepare(path):
    ctx = Context.initialize(Path(path), "synthetic-admin", "synthetic-recovery", Config())
    ctx.projects.create("demo", ["dev"])
    ctx.vault.put_secret("secret", "api_key", b"synthetic-seed", "demo", "dev")
    doc = ctx.state.read_json("vault/secrets.json")
    doc["secrets"]["secret"]["versions"]["invalid"] = {{"status": "retired"}}
    ctx.state.write_json("vault/secrets.json", doc)
    return ctx

prepare({rust_state}).close()
ctx = prepare({python_state})
try:
    M.share_environment(ctx, None, "demo", "dev", "owner", "synthetic-admin")
    result = "ok"
except Exception as exc:
    result = type(exc).__name__
doc = ctx.state.read_json("vault/secrets.json")
print(json.dumps({{"result": result, "shared_env": doc["secrets"]["secret"].get("shared_env")}}))
"#,
        rust_state = serde_json::to_string(&rust_state).unwrap(),
        python_state = serde_json::to_string(&python_state).unwrap(),
    );
    let expected = python(&script);
    let ctx = Context::open(&rust_state, Config::default(), clock::system()).unwrap();
    let error =
        membership::share_environment(&ctx, None, "demo", "dev", "owner", ADMIN).unwrap_err();
    let doc = ctx
        .state
        .read_json(zeropw::vault::VAULT_DOC, json!({}))
        .unwrap();
    assert_eq!(expected["result"], "ValueError");
    assert_eq!(expected["shared_env"], Value::Null);
    assert_eq!(error.reason, "state_corrupt");
    assert_eq!(doc["secrets"]["secret"]["shared_env"], Value::Null);
}

#[test]
fn share_environment_rejects_unhashable_connection_versions_before_mutation() {
    let root = TempDir::new().unwrap();
    for (index, raw) in [json!([]), json!({})].into_iter().enumerate() {
        let rust_state = root.path().join(format!("rust-unhashable-{index}"));
        let python_state = root.path().join(format!("python-unhashable-{index}"));
        let script = format!(
            r#"
import json
from pathlib import Path
from zeropw import policy as P
from zeropw.context import Config, Context
from zeropw.team import membership as M

def prepare(path):
    ctx = Context.initialize(Path(path), "synthetic-admin", "synthetic-recovery", Config())
    ctx.projects.create("demo", ["dev"])
    ctx.vault.put_secret("secret", "api_key", b"synthetic-seed", "demo", "dev")
    ctx.policy.create_connection(P.Connection(
        id="connection", project="demo", environment="dev", service="synthetic", kind="http",
        secret_id="secret", secret_version=None, description="",
        http_target=P.HttpTarget("https", "example.com", 443), http_auth=P.HttpAuth("bearer"),
        http_scope=P.HttpScope(), ssh_target=None, cli=None, policy_version=0, status="active",
        created_at="", updated_at=""))
    connections = ctx.state.read_json(P.CONNECTIONS)
    connections["connection"]["secret_version"] = {raw}
    ctx.state.write_json(P.CONNECTIONS, connections)
    return ctx

prepare({rust_state}).close()
ctx = prepare({python_state})
try:
    M.share_environment(ctx, None, "demo", "dev", "owner", "synthetic-admin")
    result = "ok"
except Exception as exc:
    result = type(exc).__name__
vault = ctx.state.read_json("vault/secrets.json")
connections = ctx.state.read_json(P.CONNECTIONS)
print(json.dumps({{"result": result,
                  "secret_shared": vault["secrets"]["secret"].get("shared_env"),
                  "connection_shared": connections["connection"].get("shared_env")}}))
"#,
            raw = raw,
            rust_state = serde_json::to_string(&rust_state).unwrap(),
            python_state = serde_json::to_string(&python_state).unwrap(),
        );
        let expected = python(&script);
        let ctx = Context::open(&rust_state, Config::default(), clock::system()).unwrap();
        let error =
            membership::share_environment(&ctx, None, "demo", "dev", "owner", ADMIN).unwrap_err();
        let vault = ctx
            .state
            .read_json(zeropw::vault::VAULT_DOC, json!({}))
            .unwrap();
        let connections = ctx
            .state
            .read_json(zeropw::policy::CONNECTIONS, json!({}))
            .unwrap();
        assert_eq!(expected["result"], "TypeError");
        assert_eq!(expected["secret_shared"], Value::Null);
        assert_eq!(expected["connection_shared"], Value::Null);
        assert_eq!(error.reason, "state_corrupt");
        assert_eq!(vault["secrets"]["secret"]["shared_env"], Value::Null);
        assert_eq!(connections["connection"]["shared_env"], Value::Null);
    }
}

/// An owner node with one shared environment and a (not started) TeamSync.
struct Node {
    ctx: Arc<Context>,
    key: DeviceKey,
    env: String,
    team: Arc<sync::TeamSync>,
}
impl Node {
    fn new(root: &TempDir, name: &str) -> Self {
        let ctx = context(root, name);
        ctx.projects.create("demo", &["dev"]).unwrap();
        let env = membership::share_environment(&ctx, None, "demo", "dev", "owner", ADMIN).unwrap()
            ["env_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let key = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        let transport = Arc::new(InProcessTransport::new(key.clone(), no_members()));
        let team = sync::TeamSync::new(ctx.clone(), transport, key.clone());
        team.register_env(&env).unwrap();
        Self {
            ctx,
            key,
            env,
            team,
        }
    }
    fn scripted(&self, address: &str) -> (Arc<Scripted>, mpsc::Sender<Value>) {
        let (session, inbox) =
            Scripted::new(DeviceKey::generate().record().unwrap(), &self.env, None);
        self.team
            .adopt_outbound_session(&self.env, session.clone(), address);
        (session, inbox)
    }
    /// The next commit by this node's own device, signed but not stored.
    fn next_commit(&self, ops: Vec<Value>) -> Commit {
        let store = CommitStore::new(self.ctx.state, &self.env);
        let fp = self.key.fingerprint().unwrap();
        let last = store.last_seq(&fp).unwrap();
        let mut hlc = Hlc::new(0, 0);
        hlc.observe(&store.get(&fp, &last).unwrap().unwrap().hlc)
            .unwrap();
        commit::sign_commit(
            &self.key,
            &self.env,
            &last + 1,
            &hlc.tick(None),
            &store.vector().unwrap(),
            ops,
        )
        .unwrap()
    }
    fn audit(&self, event: &str) -> Vec<Value> {
        self.ctx
            .audit
            .tail(500)
            .unwrap()
            .into_iter()
            .filter(|r| r["event"] == event)
            .collect()
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        self.team.stop();
    }
}

fn wait(stage: &str, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if check() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("condition not reached: {stage}");
}

fn settings(interval: i64) -> Vec<Value> {
    vec![json!({"op":"settings.update","sync_interval_seconds":interval})]
}

// ---------------------------------------------------------------- local-commit pickup (gap 2)

/// sync.py `_handle_commit`/`_pick_up_local_commits`: receiving a commit
/// never moves the pickup baseline, so a commit another local process (the
/// admin CLI) wrote just before is still broadcast on the next poll, and the
/// `_commit_seen` set keeps the received commit from being sent twice.
#[test]
fn cli_commit_written_before_a_received_commit_is_still_picked_up_once() {
    let root = TempDir::new().unwrap();
    let node = Node::new(&root, "a");
    let (injector, inbox) = node.scripted("gap-injector");
    let (observer, _observer_inbox) = node.scripted("gap-observer");
    let cli = membership::author_commit(&node.ctx, None, &node.env, settings(7)).unwrap();
    let received = node.next_commit(settings(9));
    inbox
        .send(json!({"type":"COMMIT","commit":received.to_dict()}))
        .unwrap();
    // The receive path has finished once it rebroadcast to the other session.
    wait("received commit rebroadcast", || {
        observer.commit_count(&received) == 1
    });
    node.team.poll().unwrap();
    node.team.poll().unwrap();
    assert_eq!(
        observer.commit_count(&cli),
        1,
        "CLI commit was never picked up"
    );
    assert_eq!(injector.commit_count(&cli), 1);
    assert_eq!(observer.commit_count(&received), 1);
    // Python's `_broadcast(exclude_fp=sender)` plus `_commit_seen`: the sender
    // never gets its own commit back, not even from the later pickup.
    assert_eq!(injector.commit_count(&received), 0);
}

/// sync.py `submit_commit`: same baseline/dedup semantics on the local
/// origination path.
#[test]
fn cli_commit_written_before_a_submitted_commit_is_still_picked_up_once() {
    let root = TempDir::new().unwrap();
    let node = Node::new(&root, "a");
    let (observer, _inbox) = node.scripted("gap-observer");
    let cli = membership::author_commit(&node.ctx, None, &node.env, settings(7)).unwrap();
    let submitted =
        membership::author_commit(&node.ctx, Some(&node.team), &node.env, settings(9)).unwrap();
    assert_eq!(observer.commit_count(&submitted), 1);
    node.team.poll().unwrap();
    node.team.poll().unwrap();
    assert_eq!(
        observer.commit_count(&cli),
        1,
        "CLI commit was never picked up"
    );
    assert_eq!(observer.commit_count(&submitted), 1);
    // The in-memory document reflects the picked-up commit too.
    assert_eq!(
        node.team.document(&node.env).unwrap()["settings"]["sync_interval_seconds"],
        json!(9)
    );
}

/// sync.py `_poll_env`: a released deferred commit is broadcast once; the
/// following pickup tick sees it as a new store commit but `_commit_seen`
/// suppresses the second broadcast.
#[test]
fn released_deferred_commit_is_broadcast_once_across_polls() {
    let root = TempDir::new().unwrap();
    let node = Node::new(&root, "a");
    let (observer, _inbox) = node.scripted("gap-observer");
    let deferred = node.next_commit(settings(11));
    CommitStore::new(node.ctx.state, &node.env)
        .defer(&deferred)
        .unwrap();
    node.team.poll().unwrap();
    assert_eq!(
        CommitStore::new(node.ctx.state, &node.env)
            .last_seq(&node.key.fingerprint().unwrap())
            .unwrap(),
        deferred.author_seq
    );
    node.team.poll().unwrap();
    node.team.poll().unwrap();
    assert_eq!(observer.commit_count(&deferred), 1);
}

// ------------------------------------------------------------ INCIDENT from unknown author (gap 3)

const PY_UNKNOWN_INCIDENT: &str = r#"
import json, tempfile, pathlib, time
from zeropw.context import Config, Context
from zeropw.team import membership as M, sync as S, transport as T
from zeropw.team.identity import DeviceKey

root = pathlib.Path(tempfile.mkdtemp())
ctx = Context.initialize(root / "a", "synthetic-admin", "synthetic-recovery", Config())
ctx.projects.create("demo", ["dev"])
env_id = M.share_environment(ctx, None, "demo", "dev", "owner", "synthetic-admin")["env_id"]
device = DeviceKey.load_or_create(ctx.state, ctx.kms)
team = S.TeamSync(ctx, T.InProcessTransport(device), device)
team.register_env(env_id)
stranger = DeviceKey.generate()

class Fake:
    def __init__(self, peer):
        self.peer, self.env_id, self.sent, self.closed = peer, env_id, [], False
        self.created_at = time.monotonic()
    def send(self, m): self.sent.append(m)
    def recv(self, timeout): return None
    def close(self): self.closed = True

session = Fake(stranger.record)
fact = S.sign_fact(stranger, env_id, "incident", {"incident_id": "0123456789abcdef"}, "1000-0000")
team._handle_message(env_id, session, {"type": "INCIDENT", "fact": fact.to_dict()})
rejected = [r for r in ctx.audit.tail(50) if r["event"] == "team_fact_rejected"]
for r in rejected:
    r.pop("ts")
    assert r.pop("env_id") == env_id and r.pop("fingerprint") == stranger.fingerprint
print(json.dumps({"rejected": rejected, "sent": session.sent}))
"#;

#[test]
fn incident_from_unknown_author_is_audited_like_python() {
    let expected = python(PY_UNKNOWN_INCIDENT);
    let root = TempDir::new().unwrap();
    let node = Node::new(&root, "a");
    let stranger = DeviceKey::generate();
    let (session, inbox) = Scripted::new(stranger.record().unwrap(), &node.env, None);
    node.team
        .adopt_outbound_session(&node.env, session.clone(), "gap-stranger");
    let fact = sync::sign_fact(
        &stranger,
        &node.env,
        "incident",
        json!({"incident_id":"0123456789abcdef"}),
        "1000-0000",
    )
    .unwrap();
    inbox
        .send(json!({"type":"INCIDENT","fact":fact.to_dict()}))
        .unwrap();
    wait("incident rejection audited", || {
        !node.audit("team_fact_rejected").is_empty()
    });
    let rejected: Vec<Value> = node
        .audit("team_fact_rejected")
        .into_iter()
        .map(|mut r| {
            let obj = r.as_object_mut().unwrap();
            obj.remove("ts");
            assert_eq!(obj.remove("env_id").unwrap(), json!(node.env));
            assert_eq!(
                obj.remove("fingerprint").unwrap(),
                json!(stranger.fingerprint().unwrap())
            );
            r
        })
        .collect();
    assert_eq!(json!(rejected), expected["rejected"]);
    assert_eq!(expected["sent"], json!([]));
    assert!(session.frames("INCIDENT_ACK").is_empty());
}

// ---------------------------------------------------------------- team_member_add audit (gap 4)

/// sync.py `_admit_member`: `extra={"env_id", "fingerprint", "role"}`.
#[test]
fn member_add_audit_records_role_like_python() {
    let root = TempDir::new().unwrap();
    let a = context(&root, "a");
    a.projects.create("demo", &["dev"]).unwrap();
    let env =
        membership::share_environment(&a, None, "demo", "dev", "owner", ADMIN).unwrap()["env_id"]
            .as_str()
            .unwrap()
            .to_owned();
    let a_key = DeviceKey::load_or_create(a.state, a.kms).unwrap();
    let a_transport = Arc::new(InProcessTransport::new(a_key.clone(), no_members()));
    let a_team = sync::TeamSync::new(a.clone(), a_transport, a_key);
    let address = "gap-member-add-inviter";
    a_team.start(Some(address)).unwrap();
    let invite =
        membership::create_invite(&a, &env, "user", "synthetic-b", 3600, &[address.into()])
            .unwrap();
    let b = context(&root, "b");
    let b_key = DeviceKey::load_or_create(b.state, b.kms).unwrap();
    let b_transport = Arc::new(InProcessTransport::new(b_key.clone(), no_members()));
    let b_team = sync::TeamSync::new(b.clone(), b_transport.clone(), b_key.clone());
    b_team.start(None).unwrap();
    membership::join(
        &b,
        &invite,
        b_transport.as_ref() as &dyn Transport,
        &b_team,
        Some("demo"),
        Some("dev"),
        5.0,
    )
    .unwrap();
    let records: Vec<Value> = a
        .audit
        .tail(500)
        .unwrap()
        .into_iter()
        .filter(|r| r["event"] == "team_member_add")
        .collect();
    b_team.stop();
    a_team.stop();
    assert_eq!(records.len(), 1);
    let mut record = records[0].clone();
    record.as_object_mut().unwrap().remove("ts");
    assert_eq!(
        record,
        json!({
            "event": "team_member_add", "caller": null, "connection": null, "target": null,
            "action": null, "result": "ok", "reason": null, "policy_version": null,
            "run_id": null, "request_id": null,
            "env_id": env, "fingerprint": b_key.fingerprint().unwrap(), "role": "user",
        })
    );
}

// ---------------------------------------------------------------- PEERS payload (gap 5)

/// sync.py `_send_peers`: `{fp: sorted(a for a in addrs if isinstance(a, str))
/// for fp, addrs in peers_doc.items() if isinstance(addrs, list)}`, read after
/// `_persist_peer_address` stored the dialed address (`list(doc.get(fp, []))`).
#[test]
fn peers_frame_is_filtered_and_sorted_like_python() {
    let root = TempDir::new().unwrap();
    let node = Node::new(&root, "a");
    let peer = DeviceKey::generate().record().unwrap();
    let peer_fp = peer.fingerprint();
    let path = format!("team/{}/peers.json", node.env);
    let listed = "aaaaaaaaaaaaaaaaaaaaaaaaaa";
    node.ctx
        .state
        .write_json(
            &path,
            &json!({
                listed: ["zeta", "alpha", 1, null, "alpha", "\u{e9}t\u{e9}", {"x": 1}, ["n"], "Beta"],
                "bbbbbbbbbbbbbbbbbbbbbbbbbb": "not-a-list",
                "cccccccccccccccccccccccccc": {"k": ["v"]},
                "free-form-key": [],
                // The dialed peer's own entry: `list("zy")` is ["z", "y"].
                (peer_fp.clone()): "zy",
            }),
        )
        .unwrap();
    let (session, _inbox) = Scripted::new(peer, &node.env, None);
    node.team
        .adopt_outbound_session(&node.env, session.clone(), "gap-peers");
    let persisted = node.ctx.state.read_json(&path, json!({})).unwrap();
    assert_eq!(persisted[&peer_fp], json!(["z", "y", "gap-peers"]));
    let expected = python(&format!(
        "import json\ndoc = json.loads({:?})\nprint(json.dumps({{fp: sorted(a for a in addrs if isinstance(a, str)) for fp, addrs in doc.items() if isinstance(addrs, list)}}))",
        persisted.to_string()
    ));
    let frames = session.frames("PEERS");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0]["peers"], expected);
    assert_eq!(
        frames[0]["peers"],
        json!({
            listed: ["Beta", "alpha", "alpha", "zeta", "\u{e9}t\u{e9}"],
            "free-form-key": [],
            (peer_fp): ["gap-peers", "y", "z"],
        })
    );
}

/// `read_json(...) or {}`: a falsy peers document is an empty dict to Python;
/// it must not panic the dial path.
#[test]
fn falsy_peers_document_is_an_empty_dict() {
    let root = TempDir::new().unwrap();
    let node = Node::new(&root, "a");
    let path = format!("team/{}/peers.json", node.env);
    node.ctx.state.write_json(&path, &json!([])).unwrap();
    let peer = DeviceKey::generate().record().unwrap();
    let peer_fp = peer.fingerprint();
    let (session, _inbox) = Scripted::new(peer, &node.env, None);
    node.team
        .adopt_outbound_session(&node.env, session.clone(), "gap-falsy");
    assert_eq!(
        node.ctx.state.read_json(&path, json!(null)).unwrap(),
        json!({(peer_fp.clone()): ["gap-falsy"]})
    );
    assert_eq!(
        session.frames("PEERS"),
        vec![json!({"type":"PEERS","peers":{(peer_fp): ["gap-falsy"]}})]
    );
}

const PY_NON_DICT_PEERS: &str = r#"
import json, tempfile, pathlib, time
from zeropw.context import Config, Context
from zeropw.team import membership as M, sync as S, transport as T
from zeropw.team.identity import DeviceKey

root = pathlib.Path(tempfile.mkdtemp())
ctx = Context.initialize(root / "a", "synthetic-admin", "synthetic-recovery", Config())
ctx.projects.create("demo", ["dev"])
env_id = M.share_environment(ctx, None, "demo", "dev", "owner", "synthetic-admin")["env_id"]
device = DeviceKey.load_or_create(ctx.state, ctx.kms)
path = f"team/{env_id}/peers.json"
load = {}
for doc in (["x"], "x", 5, True, [], 0, "", None, {}):
    ctx.state.write_json(path, doc)
    try:
        S.TeamSync(ctx, T.InProcessTransport(device), device).register_env(env_id)
        load[json.dumps(doc)] = "ok"
    except Exception as exc:
        load[json.dumps(doc)] = type(exc).__name__

class Fake:
    def __init__(self, peer):
        self.peer, self.env_id, self.sent, self.closed = peer, env_id, [], False
        self.created_at = time.monotonic()
    def send(self, m): self.sent.append(m)
    def recv(self, timeout): return None
    def close(self): self.closed = True

ctx.state.write_json(path, {})
team = S.TeamSync(ctx, T.InProcessTransport(device), device)
team.register_env(env_id)
ctx.state.write_json(path, ["synthetic-raw-entry"])
session = Fake(DeviceKey.generate().record)
try:
    team.adopt_outbound_session(env_id, session, "gap-non-dict")
    wired = "ok"
except Exception as exc:
    wired = type(exc).__name__
peers_after = ctx.state.read_json(path, None)
other = Fake(DeviceKey.generate().record)
ctx.state.write_json(path, {other.peer.fingerprint: 5})
try:
    team.adopt_outbound_session(env_id, other, "gap-non-list")
    entry = "ok"
except Exception as exc:
    entry = type(exc).__name__
print(json.dumps({"load": load, "wired": wired, "sent": session.sent, "peers": peers_after, "entry": entry,
                  "entry_sent": other.sent, "sessions": sorted(team._envs[env_id].sessions)}))
"#;

/// A truthy non-dict peers document makes Python raise `AttributeError`
/// (`_read_peers(...).items()` loading the environment, `doc.get` in
/// `_persist_peer_address` before a dialed session is accepted). Rust fails
/// closed at the same steps with `state_corrupt` (PORTING.md §3.5) instead of
/// panicking, wiring the session anyway or relaying the raw document.
#[test]
fn non_dict_peers_document_is_never_sent() {
    let python = python(PY_NON_DICT_PEERS);
    let root = TempDir::new().unwrap();
    let node = Node::new(&root, "a");
    let path = format!("team/{}/peers.json", node.env);
    for (doc, expected) in python["load"].as_object().unwrap() {
        node.ctx
            .state
            .write_json(&path, &serde_json::from_str::<Value>(doc).unwrap())
            .unwrap();
        let fresh = sync::TeamSync::new(
            node.ctx.clone(),
            Arc::new(InProcessTransport::new(node.key.clone(), no_members())),
            node.key.clone(),
        );
        match fresh.register_env(&node.env) {
            Ok(()) => assert_eq!(expected, "ok", "{doc}"),
            Err(error) => {
                assert_eq!(expected, "AttributeError", "{doc}");
                assert_eq!(error.reason, "state_corrupt", "{doc}");
            }
        }
    }
    assert_eq!(python["load"]["[\"x\"]"], "AttributeError");
    // `Node::new` registered its environment while the document was valid.
    node.ctx
        .state
        .write_json(&path, &json!(["synthetic-raw-entry"]))
        .unwrap();
    let (session, _inbox) = Scripted::new(DeviceKey::generate().record().unwrap(), &node.env, None);
    node.team
        .adopt_outbound_session(&node.env, session.clone(), "gap-non-dict");
    assert_eq!(python["wired"], "AttributeError");
    assert_eq!(python["sent"], json!([]));
    assert!(session.sent.lock().unwrap().is_empty());
    assert_eq!(python["sessions"], json!([]));
    assert_eq!(node.team.status(&node.env).unwrap()["sessions"], json!([]));
    assert!(
        session.is_closed(),
        "an unwired dialed session is not leaked"
    );
    assert_eq!(python["peers"], json!(["synthetic-raw-entry"]));
    assert_eq!(
        node.ctx.state.read_json(&path, json!(null)).unwrap(),
        json!(["synthetic-raw-entry"])
    );
    // `list(doc.get(fp, []))` over a non-iterable entry: `TypeError`.
    let (other, _other_inbox) =
        Scripted::new(DeviceKey::generate().record().unwrap(), &node.env, None);
    let entry = json!({(other.peer.fingerprint()): 5});
    node.ctx.state.write_json(&path, &entry).unwrap();
    node.team
        .adopt_outbound_session(&node.env, other.clone(), "gap-non-list");
    assert_eq!(python["entry"], "TypeError");
    assert_eq!(python["entry_sent"], json!([]));
    assert!(other.sent.lock().unwrap().is_empty());
    assert!(other.is_closed());
    assert_eq!(node.team.status(&node.env).unwrap()["sessions"], json!([]));
    assert_eq!(node.ctx.state.read_json(&path, json!(null)).unwrap(), entry);
}

/// `join` with a corrupt local peers document: Python's `register_env`
/// raises before any dial, so the inviter's one-time invite is not consumed.
#[test]
fn join_with_non_dict_peers_document_fails_before_dialing() {
    let root = TempDir::new().unwrap();
    let a = context(&root, "a");
    a.projects.create("demo", &["dev"]).unwrap();
    let env =
        membership::share_environment(&a, None, "demo", "dev", "owner", ADMIN).unwrap()["env_id"]
            .as_str()
            .unwrap()
            .to_owned();
    let a_key = DeviceKey::load_or_create(a.state, a.kms).unwrap();
    let a_team = sync::TeamSync::new(
        a.clone(),
        Arc::new(InProcessTransport::new(a_key.clone(), no_members())),
        a_key,
    );
    let address = "gap-join-corrupt-peers";
    a_team.start(Some(address)).unwrap();
    let invite =
        membership::create_invite(&a, &env, "user", "synthetic-b", 3600, &[address.into()])
            .unwrap();
    let b = context(&root, "b");
    b.state
        .write_json(&format!("team/{env}/peers.json"), &json!(["x"]))
        .unwrap();
    let b_key = DeviceKey::load_or_create(b.state, b.kms).unwrap();
    let b_transport = Arc::new(InProcessTransport::new(b_key.clone(), no_members()));
    let b_team = sync::TeamSync::new(b.clone(), b_transport.clone(), b_key);
    let error = membership::join(
        &b,
        &invite,
        b_transport.as_ref() as &dyn Transport,
        &b_team,
        Some("demo"),
        Some("dev"),
        5.0,
    )
    .unwrap_err();
    b_team.stop();
    a_team.stop();
    assert_eq!(error.reason, "state_corrupt");
    let invites = a
        .state
        .read_json(&format!("team/{env}/invites.json"), json!({}))
        .unwrap();
    let entries = invites.as_object().unwrap();
    assert_eq!(entries.len(), 1);
    assert!(entries.values().all(|entry| entry["used"] == false));
    assert!(
        a.audit
            .tail(500)
            .unwrap()
            .iter()
            .all(|r| r["event"] != "team_member_add")
    );
}

// ------------------------------------------------------- failed broadcast send

const PY_BROADCAST_DROP: &str = r#"
import json, tempfile, pathlib, time
from zeropw.context import Config, Context
from zeropw.team import membership as M, sync as S, transport as T
from zeropw.team.identity import DeviceKey

root = pathlib.Path(tempfile.mkdtemp())
ctx = Context.initialize(root / "a", "synthetic-admin", "synthetic-recovery", Config())
ctx.projects.create("demo", ["dev"])
env_id = M.share_environment(ctx, None, "demo", "dev", "owner", "synthetic-admin")["env_id"]
device = DeviceKey.load_or_create(ctx.state, ctx.kms)
team = S.TeamSync(ctx, T.InProcessTransport(device), device)
team.register_env(env_id)
peer = DeviceKey.generate()

class Failing:
    def __init__(self, peer):
        self.peer, self.env_id, self.closed = peer, env_id, False
        self.created_at = time.monotonic()
    def send(self, m): raise T.SessionClosed("synthetic_send_failure")
    def recv(self, timeout): return None
    def close(self): self.closed = True

session = Failing(peer.record)
assert team._accept_or_replace_session(env_id, session, inbound=False)
team.publish_fact(env_id, "connection_disabled", connection_id="gh")
closes = [r for r in ctx.audit.tail(200) if r["event"] == "team_session_close"]
for r in closes:
    r.pop("ts")
    assert r.pop("env_id") == env_id and r.pop("fingerprint") == peer.fingerprint
print(json.dumps({"closes": closes, "sessions": sorted(team._envs[env_id].sessions),
                  "closed": session.closed}))
"#;

/// sync.py `_broadcast`: a send failure calls `_drop_session` right away --
/// the session leaves the table, is closed, and `team_session_close` is
/// audited before the broadcasting call returns (not at the next poll).
#[test]
fn failed_broadcast_send_drops_the_session_immediately() {
    let python = python(PY_BROADCAST_DROP);
    let root = TempDir::new().unwrap();
    let node = Node::new(&root, "a");
    // A receive loop that never notices `close`, so only the broadcast path
    // can drop the session.
    let (session, _inbox) = Scripted::new(
        DeviceKey::generate().record().unwrap(),
        &node.env,
        Some(Duration::from_millis(200)),
    );
    let fp = session.peer.fingerprint();
    node.team
        .adopt_outbound_session(&node.env, session.clone(), "gap-broadcast");
    assert_eq!(
        node.team.status(&node.env).unwrap()["sessions"],
        json!([fp])
    );
    session.fail_sends.store(true, Ordering::SeqCst);
    node.team
        .publish_fact(
            &node.env,
            "connection_disabled",
            json!({"connection_id":"gh"}),
        )
        .unwrap();
    let closes = |node: &Node| -> Vec<Value> {
        node.audit("team_session_close")
            .into_iter()
            .map(|mut r| {
                let obj = r.as_object_mut().unwrap();
                obj.remove("ts");
                assert_eq!(obj.remove("env_id").unwrap(), json!(node.env));
                assert_eq!(obj.remove("fingerprint").unwrap(), json!(fp));
                r
            })
            .collect()
    };
    assert_eq!(json!(closes(&node)), python["closes"]);
    assert_eq!(python["closes"].as_array().unwrap().len(), 1);
    assert_eq!(node.team.status(&node.env).unwrap()["sessions"], json!([]));
    assert_eq!(python["sessions"], json!([]));
    assert!(session.is_closed());
    assert_eq!(python["closed"], json!(true));
    // The receive thread's own exit later finds nothing left to drop.
    node.team.stop();
    assert_eq!(closes(&node).len(), 1);
}

// ------------------------------------------------------- receive thread ownership (gap 8)

/// sync.py `_wire_dialed_session` starts `self._start_receiver`, whatever
/// object the context currently has attached as `ctx.team`.
#[test]
fn outbound_receiver_belongs_to_the_adopting_instance() {
    let root = TempDir::new().unwrap();
    let node = Node::new(&root, "a");
    // Another instance registers itself on the same context and goes away.
    let other = sync::TeamSync::new(
        node.ctx.clone(),
        Arc::new(InProcessTransport::new(node.key.clone(), no_members())),
        node.key.clone(),
    );
    drop(other);
    assert!(sync::attached(&node.ctx).is_none());
    let (session, inbox) = node.scripted("gap-self");
    inbox.send(json!({"type":"VECTOR","vector":{}})).unwrap();
    let local = CommitStore::new(node.ctx.state, &node.env)
        .all_commits()
        .unwrap()
        .len();
    wait("VECTOR answered by the adopting instance", || {
        session.frames("COMMIT").len() == local
    });
}

// ------------------------------------------------------------- stop() joins receivers (gap 9)

/// sync.py `stop`: `for t in threads: t.join(timeout=5)` -- after `stop()`
/// returns, receive threads have finished (the thread's session reference is
/// released).
#[test]
fn stop_joins_receiver_threads() {
    let root = TempDir::new().unwrap();
    let node = Node::new(&root, "a");
    let (session, _inbox) = node.scripted("gap-join");
    // Let the receiver block in its 1 s recv.
    std::thread::sleep(Duration::from_millis(100));
    node.team.stop();
    assert_eq!(
        Arc::strong_count(&session),
        1,
        "a receive thread still holds the session after stop()"
    );
}

/// ...and the wait is bounded like Python's `join(timeout=5)`: a receive
/// thread stuck in a blocking read does not hang `stop()` forever.
#[test]
fn stop_join_is_bounded_like_python() {
    let root = TempDir::new().unwrap();
    let node = Node::new(&root, "a");
    let (session, _inbox) = Scripted::new(
        DeviceKey::generate().record().unwrap(),
        &node.env,
        Some(Duration::from_secs(9)),
    );
    node.team
        .adopt_outbound_session(&node.env, session.clone(), "gap-stuck");
    std::thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    node.team.stop();
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(4500),
        "stop() did not wait for the receive thread: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(8000),
        "stop() waited past the 5 s bound: {elapsed:?}"
    );
}

// ------------------------------------------------------------------ parse_invite (gap 6)

const PY_INVITES: &str = r#"
import base64, json
from zeropw.team.membership import parse_invite, INVITE_FORMAT
base = {"format": INVITE_FORMAT, "env_id": "aaaaaaaaaaaaaaaaaaaaaaaaaa-0123456789abcdef0123456789abcdef",
        "inviter": "x", "addresses": ["a:1"], "invite_secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "expires_at": "2099-01-01T00:00:00Z", "role": "user", "name": "synthetic"}
DROP = object()
variants = [
    {}, {"addresses": DROP}, {"addresses": None}, {"addresses": "ab"}, {"addresses": {"k1": 1, "k2": [2]}},
    {"addresses": 5}, {"addresses": True}, {"addresses": [1, 1.5, -0.0, 1e20, 12345678901234567890, None, True,
     False, [1, "a", None], {"a": [1.5]}, "s", "é\x01"]},
    {"inviter": 12}, {"inviter": None}, {"inviter": [1, "x"]}, {"inviter": {"k": "é\x7f"}}, {"inviter": 2.5},
    {"inviter": DROP}, {"name": 42}, {"name": True}, {"name": None}, {"name": 1e-7}, {"name": ["x" * 100, "y" * 100]},
    {"name": ""}, {"name": DROP}, {"expires_at": 1.5}, {"expires_at": 4102444800}, {"expires_at": None},
    {"expires_at": DROP}, {"invite_secret": [1]}, {"invite_secret": None}, {"invite_secret": 5},
    {"invite_secret": "AAAA"}, {"invite_secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
    {"invite_secret": "AA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}, {"role": True}, {"role": "admin"},
    {"role": "owner"}, {"role": DROP}, {"env_id": 5}, {"env_id": DROP}, {"format": DROP}, {"format": "other"},
]
texts = []
for over in variants:
    payload = dict(base)
    for k, v in over.items():
        if v is DROP:
            payload.pop(k)
        else:
            payload[k] = v
    texts.append(base64.b32encode(json.dumps(payload).encode()).decode().rstrip("=").lower())
plain = texts[0]
texts += [plain + "\x1c", "\x1f" + plain, " " + plain + "　", plain.upper(),
          plain.replace("s", "ſ"), plain.replace("i", "ı"), plain + "é", plain + "=",
          base64.b32encode(json.dumps(base).encode()).decode(), plain[:-1], "", "!!",
          base64.b32encode(b"[1, 2]").decode(), base64.b32encode(b"\xff\xfe").decode(),
          base64.b32encode(json.dumps(dict(base, extra=[1])).encode()).decode()]
out = []
for text in texts:
    try:
        r = parse_invite(text)
        r["invite_secret"] = base64.b64encode(r["invite_secret"]).decode()
        out.append({"text": text, "ok": r})
    except Exception as e:
        out.append({"text": text, "err": [type(e).__name__, getattr(e, "reason", None)]})
upper = {}
for cp in range(0x80, 0x110000):
    if 0xD800 <= cp <= 0xDFFF:
        continue
    u = chr(cp).upper()
    if u.isascii():
        upper[str(cp)] = u
print(json.dumps({"cases": out, "upper_to_ascii": upper}))
"#;

/// membership.py `parse_invite`: `str()` coercion of every field, a missing
/// `addresses` defaulting to `[]`, Python iteration of `addresses`, and
/// `_b32d`'s `strip().upper()` -- compared case by case with CPython.
#[test]
fn parse_invite_accepts_every_shape_python_accepts() {
    let oracle = python(PY_INVITES);
    let cases = oracle["cases"].as_array().unwrap();
    assert!(cases.len() > 50);
    let mut accepted = 0;
    for case in cases {
        let text = case["text"].as_str().unwrap();
        match membership::parse_invite(text) {
            Ok(invite) => {
                accepted += 1;
                let got = json!({
                    "env_id": invite.env_id, "inviter": invite.inviter,
                    "addresses": invite.addresses,
                    "invite_secret": zeropw::pybase64::b64encode(invite.invite_secret.expose()),
                    "expires_at": invite.expires_at, "role": invite.role, "name": invite.name,
                });
                assert_eq!(Some(&got), case.get("ok"), "{text:?}");
            }
            Err(e) => {
                assert_eq!(
                    case["err"],
                    json!(["InvalidInput", e.reason]),
                    "{text:?} rejected by Rust but Python gave {case}"
                );
            }
        }
    }
    assert!(accepted >= 25, "only {accepted} accepted");
    // `_b32d`'s `str.upper()`: every non-ASCII code point whose uppercase is
    // ASCII (and so decodes) maps identically in Rust.
    let upper = oracle["upper_to_ascii"].as_object().unwrap();
    let mut rust_upper = serde_json::Map::new();
    for cp in 0x80u32..0x11_0000 {
        let Some(c) = char::from_u32(cp) else {
            continue;
        };
        let u = c.to_uppercase().collect::<String>();
        if u.is_ascii() {
            rust_upper.insert(cp.to_string(), json!(u));
        }
    }
    assert_eq!(&rust_upper, upper);
}
