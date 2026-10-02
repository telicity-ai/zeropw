//! Finite duplicate-delivery diagnostic; real receive threads with controlled Session adapters.
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use tempfile::TempDir;
use zeropw::{
    clock,
    context::{Config, Context},
    team::{
        commit::{self, Commit, CommitStore},
        envelope,
        identity::{DeviceKey, DeviceRecord},
        sync::{self, TeamSync},
        transport::{InProcessTransport, MembershipCheck, Session, SessionClosed},
    },
};

struct Node {
    ctx: Arc<Context>,
    key: DeviceKey,
    team: Arc<TeamSync>,
}
impl Node {
    fn new(root: &TempDir, name: &str) -> Self {
        let ctx = Arc::new(
            Context::initialize(
                root.path().join(name),
                "synthetic-admin",
                "synthetic-recovery",
                Config {
                    team_removed_drain_seconds: 0.8,
                    team_sync_interval_seconds: Some(0.1),
                    ..Default::default()
                },
                clock::system(),
            )
            .unwrap(),
        );
        let key = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        let empty: MembershipCheck = Arc::new(|_, _| None);
        let transport = Arc::new(InProcessTransport::new(key.clone(), empty));
        let team = TeamSync::new(ctx.clone(), transport, key.clone());
        Self { ctx, key, team }
    }
    fn fp(&self) -> String {
        self.key.fingerprint().unwrap()
    }
    fn seed(&self, env: &str, commits: &[Commit]) {
        for c in commits {
            CommitStore::new(self.ctx.state, env).append(c).unwrap();
        }
        self.team.register_env(env).unwrap();
    }
    fn session(&self, env: &str, peer: &Node) -> Arc<QueueSession> {
        let session = QueueSession::new(env, peer.key.record().unwrap());
        self.team
            .adopt_outbound_session(env, session.clone(), "synthetic-unused-address");
        session.sent.lock().unwrap().clear();
        session
    }
    fn audit(&self, event: &str) -> Vec<Value> {
        self.ctx
            .audit
            .tail(1000)
            .unwrap()
            .into_iter()
            .filter(|v| v["event"] == event)
            .collect()
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        self.team.stop();
    }
}
struct QueueSession {
    env: String,
    peer: DeviceRecord,
    tx: mpsc::Sender<Value>,
    rx: Mutex<mpsc::Receiver<Value>>,
    sent: Mutex<Vec<Value>>,
    closed: AtomicBool,
    created: Instant,
}
impl QueueSession {
    fn new(env: &str, peer: DeviceRecord) -> Arc<Self> {
        let (tx, rx) = mpsc::channel();
        Arc::new(Self {
            env: env.into(),
            peer,
            tx,
            rx: Mutex::new(rx),
            sent: Mutex::new(vec![]),
            closed: AtomicBool::new(false),
            created: Instant::now(),
        })
    }
    fn push(&self, message: Value) {
        self.tx.send(message).unwrap();
    }
}
impl Session for QueueSession {
    fn peer(&self) -> DeviceRecord {
        self.peer.clone()
    }
    fn env_id(&self) -> &str {
        &self.env
    }
    fn send(&self, message: &Value) -> zeropw::errors::Result<()> {
        self.sent.lock().unwrap().push(message.clone());
        Ok(())
    }
    fn recv(&self, timeout: Duration) -> std::result::Result<Option<Value>, SessionClosed> {
        if self.is_closed() {
            return Err(SessionClosed("closed"));
        }
        match self
            .rx
            .lock()
            .unwrap()
            .recv_timeout(timeout.min(Duration::from_millis(20)))
        {
            Ok(v) => Ok(Some(v)),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(_) => Err(SessionClosed("closed")),
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
fn wait(mut predicate: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(8);
    while Instant::now() < end {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("bounded team condition did not complete");
}
fn signed(key: &DeviceKey, env: &str, seq: i128, hlc: &str, ops: Vec<Value>) -> Commit {
    commit::sign_commit(key, env, seq, hlc, &BTreeMap::new(), ops).unwrap()
}
fn genesis(owner: &Node, env: &str, hlc: &str) -> Commit {
    let generation = "0000000000000000";
    let dek = [7u8; 32];
    let wrap = envelope::wrap_dek(&dek, env, generation, &owner.key.record().unwrap()).unwrap();
    let ct = envelope::encrypt_secret(
        &dek,
        env,
        "shared-secret",
        "0011223344556677",
        b"synthetic-team-review-secret-0123456789",
    )
    .unwrap();
    signed(
        &owner.key,
        env,
        1,
        hlc,
        vec![
            json!({"op":"env.init","owner_device":owner.key.record().unwrap().to_dict(),"owner_name":"owner","generation_id":generation,"wraps":{owner.fp():wrap}}),
            json!({"op":"secret.put_version","secret_id":"shared-secret","kind":"api_key","generation_id":generation,"version_id":"0011223344556677","ciphertext":ct,"public":{}}),
        ],
    )
}
fn member(owner: &Node, env: &str, seq: i128, hlc: &str, other: &Node, role: &str) -> Commit {
    signed(
        &owner.key,
        env,
        seq,
        hlc,
        vec![
            json!({"op":"member.add","device":other.key.record().unwrap().to_dict(),"name":"synthetic-member","role":role}),
        ],
    )
}
fn fact(author: &Node, env: &str, kind: &str, target: Value, hlc: &str) -> sync::Fact {
    sync::sign_fact(&author.key, env, kind, target, hlc).unwrap()
}
fn inject(session: &QueueSession, f: &sync::Fact) {
    session.push(json!({"type":"FACT","fact":f.to_dict()}));
}

#[test]
fn simultaneous_duplicate_fact_has_one_application_audit() {
    let root = TempDir::new().unwrap();
    let a = Node::new(&root, "a");
    let b = Node::new(&root, "b");
    let c = Node::new(&root, "c");
    let env = commit::new_env_id(&a.fp()).unwrap();
    a.seed(
        &env,
        &[
            genesis(&a, &env, "1000-0000"),
            member(&a, &env, 2, "2000-0000", &b, "admin"),
            member(&a, &env, 3, "3000-0000", &c, "admin"),
        ],
    );
    let ab = a.session(&env, &b);
    let ac = a.session(&env, &c);
    for n in 0..20 {
        let f = fact(
            &b,
            &env,
            "connection_disabled",
            json!({"connection_id":format!("synthetic-duplicate-{n}")}),
            &format!("{}-0000", 4000 + n),
        );
        inject(&ab, &f);
        inject(&ac, &f);
    }
    wait(|| sync::load_facts(a.ctx.state, &env).unwrap().1.len() == 20);
    // Receiver barrier: each queue processes its earlier FACTs before answering VECTOR.
    ab.sent.lock().unwrap().clear();
    ac.sent.lock().unwrap().clear();
    ab.push(json!({"type":"VECTOR","vector":{}}));
    ac.push(json!({"type":"VECTOR","vector":{}}));
    wait(|| {
        ab.sent
            .lock()
            .unwrap()
            .iter()
            .any(|v| v["type"] == "COMMIT")
            && ac
                .sent
                .lock()
                .unwrap()
                .iter()
                .any(|v| v["type"] == "COMMIT")
    });
    let rows = a
        .ctx
        .state
        .read_lines(&format!("team/{env}/facts.jsonl"), None)
        .unwrap()
        .len();
    let applied = a.audit("team_fact_apply").len();
    eprintln!("unique=20 ledger_rows={rows} application_audits={applied}");
    assert_eq!(rows, 20);
    assert_eq!(
        applied, 20,
        "duplicate application audit after concurrent receipt"
    );
}
