//! Partial gpt-6-astra test artifact; coordinator-corrected restart fixtures.
//! No completed independent round-three acceptance verdict was returned.
//! Session fixtures drive real receive threads and signed messages; no product hooks changed.
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
        envelope, fold,
        identity::{DeviceKey, DeviceRecord},
        membership,
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
    fn restart(&mut self, env: &str) {
        self.team.stop();
        let transport = Arc::new(InProcessTransport::new(
            self.key.clone(),
            Arc::new(|_, _| None),
        ));
        self.team = TeamSync::new(self.ctx.clone(), transport, self.key.clone());
        self.team.register_env(env).unwrap();
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
#[track_caller]
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
fn has_fact(node: &Node, env: &str, f: &sync::Fact) -> bool {
    sync::load_facts(&node.ctx, env).is_ok_and(|(_, hashes, _)| hashes.contains(&f.hash().unwrap()))
}

#[test]
fn removed_peer_drain_is_receive_only_and_accepts_self_removal() {
    let root = TempDir::new().unwrap();
    let a = Node::new(&root, "a");
    let b = Node::new(&root, "b");
    let env = commit::new_env_id(&a.fp()).unwrap();
    a.seed(
        &env,
        &[
            genesis(&a, &env, "1000-0000"),
            member(&a, &env, 2, "2000-0000", &b, "admin"),
        ],
    );
    let session = a.session(&env, &b);
    a.team
        .publish_fact(&env, "member_removed", json!({"fingerprint":b.fp()}))
        .unwrap();
    assert!(
        !session.is_closed(),
        "must drain rather than close immediately"
    );
    assert!(
        session
            .sent
            .lock()
            .unwrap()
            .iter()
            .any(|v| v["type"] == "FACT" && v["fact"]["kind"] == "member_removed")
    );
    session.sent.lock().unwrap().clear();
    let stray = signed(
        &a.key,
        &env,
        3,
        "3000-0000",
        vec![json!({"op":"settings.update","sync_interval_seconds":42})],
    );
    session.push(json!({"type":"COMMIT","commit":stray.to_dict()}));
    session.push(json!({"type":"VECTOR","vector":{}}));
    let self_removal = fact(
        &b,
        &env,
        "member_removed",
        json!({"fingerprint":b.fp()}),
        "4000-0000",
    );
    inject(&session, &self_removal);
    wait(|| has_fact(&a, &env, &self_removal));
    assert!(
        CommitStore::new(a.ctx.state, &env)
            .get(&a.fp(), 3)
            .unwrap()
            .is_none()
    );
    a.team.poll().unwrap();
    assert!(
        session.sent.lock().unwrap().is_empty(),
        "draining peer received a reply/broadcast"
    );
    wait(|| {
        a.team.poll().unwrap();
        session.is_closed()
    });
    assert!(
        !a.team.status(&env).unwrap()["sessions"]
            .as_array()
            .unwrap()
            .contains(&json!(b.fp()))
    );
}

#[test]
fn removed_by_third_party_cannot_remove_an_unrelated_admin() {
    let root = TempDir::new().unwrap();
    let a = Node::new(&root, "a");
    let x = Node::new(&root, "x");
    let z = Node::new(&root, "z");
    let w = Node::new(&root, "w");
    let env = commit::new_env_id(&a.fp()).unwrap();
    let commits = vec![
        genesis(&a, &env, "1000-0000"),
        member(&a, &env, 2, "2000-0000", &x, "admin"),
        member(&a, &env, 3, "3000-0000", &z, "admin"),
        member(&a, &env, 4, "4000-0000", &w, "admin"),
    ];
    a.seed(&env, &commits);
    x.seed(&env, &commits);
    let to_a = a.session(&env, &x);
    let to_x = x.session(&env, &z);
    let removed = fact(
        &z,
        &env,
        "member_removed",
        json!({"fingerprint":x.fp()}),
        "5000-0000",
    );
    inject(&to_a, &removed);
    inject(&to_x, &removed);
    wait(|| !a.team.is_active_member(&env, &x.fp()) && !x.team.is_active_member(&env, &x.fp()));
    assert!(
        x.team
            .publish_fact(&env, "member_removed", json!({"fingerprint":w.fp()}))
            .is_err()
    );
    let forged = fact(
        &x,
        &env,
        "member_removed",
        json!({"fingerprint":w.fp()}),
        "6000-0000",
    );
    inject(&to_a, &forged);
    wait(|| {
        a.audit("team_fact_rejected")
            .iter()
            .any(|v| v["reason"] == "team_fact_not_authorized")
    });
    assert!(a.team.is_active_member(&env, &w.fp()));
    assert!(!has_fact(&a, &env, &forged));
}

#[test]
fn mutual_removal_converges_when_second_fact_arrives_on_draining_peer() {
    let root = TempDir::new().unwrap();
    let a = Node::new(&root, "a");
    let b = Node::new(&root, "b");
    let c = Node::new(&root, "c");
    let env = commit::new_env_id(&a.fp()).unwrap();
    let commits = vec![
        genesis(&a, &env, "1000-0000"),
        member(&a, &env, 2, "2000-0000", &b, "admin"),
        member(&a, &env, 3, "3000-0000", &c, "admin"),
    ];
    for n in [&a, &b, &c] {
        n.seed(&env, &commits);
    }
    let at_a_b = a.session(&env, &b);
    let at_a_c = a.session(&env, &c);
    let at_b = b.session(&env, &a);
    let at_c = c.session(&env, &a);
    let b_removes_c = fact(
        &b,
        &env,
        "member_removed",
        json!({"fingerprint":c.fp()}),
        "4000-0000",
    );
    let c_removes_b = fact(
        &c,
        &env,
        "member_removed",
        json!({"fingerprint":b.fp()}),
        "4000-0001",
    );
    inject(&at_a_b, &b_removes_c);
    wait(|| !a.team.is_active_member(&env, &c.fp()));
    assert!(!at_a_c.is_closed());
    inject(&at_a_c, &c_removes_b);
    for s in [&at_b, &at_c] {
        inject(s, &b_removes_c);
        inject(s, &c_removes_b);
    }
    for n in [&a, &b, &c] {
        wait(|| !n.team.is_active_member(&env, &b.fp()) && !n.team.is_active_member(&env, &c.fp()));
        assert!(n.team.is_active_member(&env, &a.fp()));
    }
    assert_eq!(
        a.team.document(&env).unwrap(),
        b.team.document(&env).unwrap()
    );
    assert_eq!(
        b.team.document(&env).unwrap(),
        c.team.document(&env).unwrap()
    );
}

#[test]
fn incident_mandatory_rotation_is_monotone_and_nonadmin_never_acks() {
    let root = TempDir::new().unwrap();
    let a = Node::new(&root, "a");
    let b = Node::new(&root, "b");
    let user = Node::new(&root, "user");
    let env = commit::new_env_id(&a.fp()).unwrap();
    let commits = vec![
        genesis(&a, &env, "1000-0000"),
        member(&a, &env, 2, "2000-0000", &b, "admin"),
        member(&a, &env, 3, "3000-0000", &user, "user"),
    ];
    a.seed(&env, &commits);
    user.seed(&env, &commits);
    let admin_session = a.session(&env, &b);
    let user_session = user.session(&env, &b);
    for (id, mandatory, recommended) in [
        ("1111111111111111", vec!["shared-secret"], vec![]),
        ("2222222222222222", vec![], vec!["shared-secret"]),
    ] {
        let incident = fact(
            &b,
            &env,
            "incident",
            json!({"incident_id":id,"secret_ids_mandatory":mandatory,"secret_ids_recommended":recommended}),
            "5000-0000",
        );
        admin_session.push(json!({"type":"INCIDENT","fact":incident.to_dict()}));
        user_session.push(json!({"type":"INCIDENT","fact":incident.to_dict()}));
        wait(|| {
            admin_session
                .sent
                .lock()
                .unwrap()
                .iter()
                .any(|v| v["type"] == "INCIDENT_ACK" && v["hash"] == incident.hash().unwrap())
        });
    }
    let barrier = fact(
        &b,
        &env,
        "connection_disabled",
        json!({"connection_id":"processed-barrier"}),
        "6000-0000",
    );
    inject(&user_session, &barrier);
    wait(|| has_fact(&user, &env, &barrier));
    assert_eq!(
        a.ctx
            .state
            .read_json(&format!("team/{env}/rotation_flags.json"), json!({}))
            .unwrap()["shared-secret"]["reason"],
        "rotation_required"
    );
    assert!(
        !user_session
            .sent
            .lock()
            .unwrap()
            .iter()
            .any(|v| v["type"] == "INCIDENT_ACK")
    );
    for id in ["1111111111111111", "2222222222222222"] {
        assert!(
            !user
                .ctx
                .state
                .exists(&format!("team/{env}/incidents/{}-{id}.json", b.fp()))
        );
    }
}

#[test]
fn snapshots_refuse_lagging_member_preserve_history_and_allow_gap_append() {
    let root = TempDir::new().unwrap();
    let mut a = Node::new(&root, "a");
    let b = Node::new(&root, "b");
    let env = commit::new_env_id(&a.fp()).unwrap();
    let old = commit::now_ms() - 40 * 24 * 3600 * 1000;
    let mut commits = vec![
        genesis(&a, &env, &format!("{old}-0000")),
        member(&a, &env, 2, &format!("{}-0000", old + 1), &b, "admin"),
    ];
    for seq in 3..8 {
        commits.push(signed(
            &a.key,
            &env,
            seq,
            &format!("{}-0000", old + seq as i64),
            vec![json!({"op":"settings.update","sync_interval_seconds":seq})],
        ));
    }
    commits.push(signed(
        &a.key,
        &env,
        8,
        &format!("{}-0000", commit::now_ms()),
        vec![json!({"op":"settings.update","sync_interval_seconds":8})],
    ));
    a.ctx
        .state
        .write_json(
            &format!("team/{env}/peer_vectors.json"),
            &json!({b.fp():{a.fp():3}}),
        )
        .unwrap();
    a.seed(&env, &commits);
    let before = a.team.document(&env).unwrap();
    let blocked = a.team.compact(&env).unwrap();
    assert_eq!(blocked["removed"], 0);
    assert_eq!(blocked["blocked_by"], json!([b.fp()]));
    assert_eq!(
        CommitStore::new(a.ctx.state, &env)
            .all_commits()
            .unwrap()
            .len(),
        8
    );
    a.ctx
        .state
        .write_json(
            &format!("team/{env}/peer_vectors.json"),
            &json!({b.fp():{a.fp():8}}),
        )
        .unwrap();
    a.restart(&env);
    let result = a.team.compact(&env).unwrap();
    assert_eq!(result["blocked_by"], json!([]));
    assert_eq!(result["removed"], 5);
    let store = CommitStore::new(a.ctx.state, &env);
    for seq in [1, 2, 8] {
        assert!(store.get(&a.fp(), seq).unwrap().is_some());
    }
    assert!(store.get(&a.fp(), 3).unwrap().is_none());
    assert!(
        fold::load_latest_snapshot(a.ctx.state, &env)
            .unwrap()
            .is_some()
    );
    assert_eq!(a.team.document(&env).unwrap(), before);
    let next = signed(
        &a.key,
        &env,
        9,
        &format!("{}-0001", commit::now_ms()),
        vec![json!({"op":"settings.update","sync_interval_seconds":42})],
    );
    store.append(&next).unwrap();
    assert_eq!(store.last_seq(&a.fp()).unwrap(), 9);
    a.team.poll().unwrap();
    assert_eq!(
        a.team.document(&env).unwrap()["settings"]["sync_interval_seconds"],
        42
    );
}

#[test]
fn snapshot_is_created_at_production_threshold_and_not_before() {
    let root = TempDir::new().unwrap();
    let a = Node::new(&root, "a");
    let env = commit::new_env_id(&a.fp()).unwrap();
    let store = CommitStore::new(a.ctx.state, &env);
    store.append(&genesis(&a, &env, "1000-0000")).unwrap();
    for seq in 2..sync::SNAPSHOT_INTERVAL_COMMITS {
        store
            .append(&signed(
                &a.key,
                &env,
                seq,
                &format!("{}-0000", seq * 1000),
                vec![json!({"op":"settings.update","sync_interval_seconds":seq})],
            ))
            .unwrap();
    }
    a.team.register_env(&env).unwrap();
    assert!(
        fold::load_latest_snapshot(a.ctx.state, &env)
            .unwrap()
            .is_none()
    );
    let threshold = sync::SNAPSHOT_INTERVAL_COMMITS;
    let crossing = signed(
        &a.key,
        &env,
        threshold,
        &format!("{}-0000", threshold * 1000),
        vec![json!({"op":"settings.update","sync_interval_seconds":42})],
    );
    assert_eq!(a.team.submit_commit(&env, &crossing).unwrap(), "accepted");
    let snapshot = fold::load_latest_snapshot(a.ctx.state, &env)
        .unwrap()
        .unwrap();
    assert_eq!(snapshot["vector"][a.fp()], json!(threshold));
}

#[test]
fn facts_replay_deduplicates_and_restore_cannot_undo_later_revocation() {
    use zeropw::policy::{Connection, HttpAuth, HttpScope, HttpTarget};
    let root = TempDir::new().unwrap();
    let mut a = Node::new(&root, "a");
    a.ctx.projects.create("demo", &["dev"]).unwrap();
    a.ctx
        .vault
        .put_secret(
            "shared-secret",
            "api_key",
            b"synthetic-team-restore-secret-0123456789",
            "demo",
            "dev",
            true,
        )
        .unwrap();
    a.ctx
        .policy
        .create_connection(
            Connection::new(
                "shared-connection",
                "demo",
                "dev",
                "synthetic",
                "http",
                "shared-secret",
                None,
                "",
                Some(HttpTarget::new("https", "example.com", 443, None, false).unwrap()),
                Some(HttpAuth::bearer()),
                Some(HttpScope::new(None, None, vec![]).unwrap()),
                None,
                None,
                0,
                "active",
                "",
                "",
            )
            .unwrap(),
        )
        .unwrap();
    let shared =
        membership::share_environment(&a.ctx, None, "demo", "dev", "owner", "synthetic-admin")
            .unwrap();
    let env = shared["env_id"].as_str().unwrap();
    a.team.register_env(env).unwrap();
    a.team
        .publish_fact(
            env,
            "connection_disabled",
            json!({"connection_id":"shared-connection"}),
        )
        .unwrap();
    let factpath = format!("team/{env}/facts.jsonl");
    let original = a.ctx.state.read_bytes(&factpath).unwrap();
    let mut replay = original.clone();
    replay.extend(&original);
    a.ctx.state.write_bytes(&factpath, &replay).unwrap();
    let (facts, hashes, _) = sync::load_facts(&a.ctx, env).unwrap();
    assert_eq!(hashes.len(), 1);
    assert!(facts.disabled_connections.contains("shared-connection"));
    let backup = root.path().join("backup.json");
    a.ctx.vault.backup(&backup).unwrap();
    let archive = std::fs::read_to_string(&backup).unwrap();
    assert!(!archive.contains("facts.jsonl"));
    assert!(!archive.contains("team/"));
    let meta = a
        .ctx
        .state
        .read_json(zeropw::vault::VAULT_DOC, json!({}))
        .unwrap();
    let version = meta["secrets"]["shared-secret"]["versions"]["1"]["version_id"].clone();
    a.team
        .publish_fact(
            env,
            "secret_version_revoked",
            json!({"secret_id":"shared-secret","version_id":version}),
        )
        .unwrap();
    assert_eq!(
        a.ctx.vault.get_meta("shared-secret").unwrap().versions[0].status,
        "revoked"
    );
    zeropw::vault::Vault::restore(a.ctx.state, &backup, a.ctx.audit, Some(a.ctx.kms)).unwrap();
    assert_eq!(
        a.ctx.vault.get_meta("shared-secret").unwrap().versions[0].status,
        "active"
    );
    a.restart(env);
    assert_eq!(
        a.ctx.vault.get_meta("shared-secret").unwrap().versions[0].status,
        "revoked"
    );
    assert_eq!(
        a.ctx
            .policy
            .get_connection("shared-connection")
            .unwrap()
            .status,
        "disabled"
    );
    assert_eq!(sync::load_facts(&a.ctx, env).unwrap().1.len(), 2);
}

#[test]
fn conflict_override_alert_is_exactly_once_and_only_on_loser_including_restart() {
    let root = TempDir::new().unwrap();
    let mut a = Node::new(&root, "a");
    let mut b = Node::new(&root, "b");
    let env = commit::new_env_id(&a.fp()).unwrap();
    let create = signed(
        &a.key,
        &env,
        3,
        "3000-0000",
        vec![
            json!({"op":"connection.create","id":"gh","project":"demo","environment":"dev","service":"synthetic","kind":"http","secret_id":"shared-secret","secret_version":null,"description":"","http_target":{"scheme":"https","host":"example.com","port":443},"http_auth":{"mode":"bearer"},"http_scope":{"methods":["GET"],"path_prefixes":null}}),
        ],
    );
    let commits = vec![
        genesis(&a, &env, "1000-0000"),
        member(&a, &env, 2, "2000-0000", &b, "admin"),
        create,
    ];
    for n in [&a, &b] {
        n.seed(&env, &commits);
    }
    let losing = signed(
        &a.key,
        &env,
        4,
        "4000-0000",
        vec![
            json!({"op":"connection.update","id":"gh","http_scope":{"methods":["GET","POST"],"path_prefixes":null}}),
        ],
    );
    let winning = signed(
        &b.key,
        &env,
        1,
        "5000-0000",
        vec![
            json!({"op":"connection.update","id":"gh","http_scope":{"methods":null,"path_prefixes":["/repos"]}}),
        ],
    );
    for n in [&a, &b] {
        assert_eq!(n.team.submit_commit(&env, &losing).unwrap(), "accepted");
        assert_eq!(n.team.submit_commit(&env, &winning).unwrap(), "accepted");
        for _ in 0..3 {
            n.team.poll().unwrap();
            n.team.register_env(&env).unwrap();
        }
    }
    a.restart(&env);
    b.restart(&env);
    assert_eq!(a.audit("team_op_overridden").len(), 1);
    assert!(b.audit("team_op_overridden").is_empty());
    assert_eq!(
        a.ctx
            .audit
            .alerts(1000)
            .unwrap()
            .iter()
            .filter(|v| v["alert"] == "team_op_overridden")
            .count(),
        1
    );
    assert_eq!(
        a.team.document(&env).unwrap(),
        b.team.document(&env).unwrap()
    );
}

#[test]
fn concurrent_third_party_removals_are_visible_and_reconciled_by_active_owner() {
    let root = TempDir::new().unwrap();
    let a = Node::new(&root, "order-a");
    let b = Node::new(&root, "order-b");
    let x = Node::new(&root, "author-x");
    let z = Node::new(&root, "remover-z");
    let w = Node::new(&root, "target-w");
    let env = commit::new_env_id(&a.fp()).unwrap();
    let commits = vec![
        genesis(&a, &env, "1000-0000"),
        member(&a, &env, 2, "2000-0000", &b, "admin"),
        member(&a, &env, 3, "3000-0000", &x, "admin"),
        member(&a, &env, 4, "4000-0000", &z, "admin"),
        member(&a, &env, 5, "5000-0000", &w, "user"),
    ];
    a.seed(&env, &commits);
    b.seed(&env, &commits);
    let ax = a.session(&env, &x);
    let az = a.session(&env, &z);
    let bx = b.session(&env, &x);
    let bz = b.session(&env, &z);
    let ba = b.session(&env, &a);
    let remove_w = fact(
        &x,
        &env,
        "member_removed",
        json!({"fingerprint":w.fp()}),
        "6000-0000",
    );
    let remove_x = fact(
        &z,
        &env,
        "member_removed",
        json!({"fingerprint":x.fp()}),
        "7000-0000",
    );
    inject(&ax, &remove_w);
    wait(|| has_fact(&a, &env, &remove_w));
    inject(&az, &remove_x);
    wait(|| has_fact(&a, &env, &remove_x));
    inject(&bz, &remove_x);
    wait(|| has_fact(&b, &env, &remove_x));
    inject(&bx, &remove_w);
    wait(|| {
        !b.team.status(&env).unwrap()["rejected_removals"]
            .as_array()
            .unwrap()
            .is_empty()
    });
    assert!(!a.team.is_active_member(&env, &w.fp()));
    assert!(b.team.is_active_member(&env, &w.fp()));
    assert_eq!(
        b.team.status(&env).unwrap()["rejected_removals"][0]["target"],
        w.fp()
    );
    let reconciliation = a
        .team
        .publish_fact(&env, "member_removed", json!({"fingerprint":w.fp()}))
        .unwrap();
    ba.push(json!({"type":"FACT","fact":reconciliation}));
    wait(|| !b.team.is_active_member(&env, &w.fp()));
    assert!(
        b.team.status(&env).unwrap()["rejected_removals"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(!a.team.is_active_member(&env, &w.fp()));
}
