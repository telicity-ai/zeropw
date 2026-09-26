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
        if self.closed.load(Ordering::SeqCst) {
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
        hlc.observe(&store.get(&fp, last).unwrap().unwrap().hlc)
            .unwrap();
        commit::sign_commit(
            &self.key,
            &self.env,
            last + 1,
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

/// A truthy non-dict peers document makes Python raise (AttributeError) in
/// `_persist_peer_address`/`_send_peers`; Rust fails closed (§3.5) instead of
/// panicking or relaying the raw document.
#[test]
fn non_dict_peers_document_is_never_sent() {
    let root = TempDir::new().unwrap();
    let node = Node::new(&root, "a");
    let path = format!("team/{}/peers.json", node.env);
    node.ctx
        .state
        .write_json(&path, &json!(["synthetic-raw-entry"]))
        .unwrap();
    let (session, _inbox) = Scripted::new(DeviceKey::generate().record().unwrap(), &node.env, None);
    node.team
        .adopt_outbound_session(&node.env, session.clone(), "gap-non-dict");
    assert!(session.frames("PEERS").is_empty());
    assert!(
        !json!(*session.sent.lock().unwrap())
            .to_string()
            .contains("synthetic-raw-entry")
    );
    assert_eq!(
        node.ctx.state.read_json(&path, json!(null)).unwrap(),
        json!(["synthetic-raw-entry"])
    );
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
