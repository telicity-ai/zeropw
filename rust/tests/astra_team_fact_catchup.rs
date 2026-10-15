//! Independent desired behavior for ASTRA-TEAM-T6: persisted emergency fact catch-up.
use serde_json::json;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tempfile::TempDir;
use zeropw::{
    clock,
    context::{Config, Context},
    team::{
        commit::CommitStore,
        identity::DeviceKey,
        membership,
        sync::{self, TeamSync},
        transport::TcpTransport,
    },
};

struct Node {
    ctx: Arc<Context>,
    key: DeviceKey,
    transport: Arc<TcpTransport>,
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
                    team_sync_interval_seconds: Some(0.1),
                    team_dial_backoff: (0.05, 0.2),
                    ..Config::default()
                },
                clock::system(),
            )
            .unwrap(),
        );
        let key = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        Self::from_context(ctx, key)
    }
    fn from_context(ctx: Arc<Context>, key: DeviceKey) -> Self {
        let transport = TcpTransport::new(key.clone(), Arc::new(|_, _| None), 4);
        let team = TeamSync::new(ctx.clone(), Arc::new(transport.clone()), key.clone());
        Self {
            ctx,
            key,
            transport,
            team,
        }
    }
    fn fp(&self) -> String {
        self.key.fingerprint().unwrap()
    }
    fn connected(&self, env: &str, fp: &str) -> bool {
        self.team.status(env).unwrap()["sessions"]
            .as_array()
            .unwrap()
            .contains(&json!(fp))
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        self.team.stop();
        self.transport.shutdown();
    }
}
fn wait(stage: &str, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("catch-up stage failed: {stage}");
}

#[test]
fn offline_fact_reaches_authenticated_replacement_and_remains_monotone() {
    let root = TempDir::new().unwrap();
    let a = Node::new(&root, "a");
    let b = Node::new(&root, "b");
    a.ctx.projects.create("demo", &["dev"]).unwrap();
    let env =
        membership::share_environment(&a.ctx, None, "demo", "dev", "owner", "synthetic-admin")
            .unwrap()["env_id"]
            .as_str()
            .unwrap()
            .to_owned();
    a.team.start(Some("127.0.0.1:0")).unwrap();
    b.team.start(Some("127.0.0.1:0")).unwrap();
    let a_address = a.transport.bound_address().unwrap();
    let b_address = b.transport.bound_address().unwrap();
    let invite =
        membership::create_invite(&a.ctx, &env, "admin", "synthetic-b", 3600, &[a_address])
            .unwrap();
    membership::join(
        &b.ctx,
        &invite,
        &b.transport,
        &b.team,
        Some("demo"),
        Some("dev"),
        5.0,
    )
    .unwrap();
    a.team.set_peer_address(&env, &b.fp(), &b_address).unwrap();
    wait("initial authenticated peer", || a.connected(&env, &b.fp()));
    b.team.stop();
    b.transport.shutdown();
    wait("old peer disconnected", || !a.connected(&env, &b.fp()));
    let lost = a
        .team
        .publish_fact(
            &env,
            "connection_disabled",
            json!({"connection_id":"synthetic-offline-target"}),
        )
        .unwrap();
    let lost_hash = sync::Fact::from_dict(&lost).unwrap().hash().unwrap();
    assert!(
        sync::load_facts(&a.ctx, &env)
            .unwrap()
            .1
            .contains(&lost_hash)
    );
    assert!(
        !sync::load_facts(&b.ctx, &env)
            .unwrap()
            .1
            .contains(&lost_hash)
    );
    let fresh_b = Node::from_context(b.ctx.clone(), b.key.clone());
    fresh_b.team.start(Some(&b_address)).unwrap();
    wait("replacement authenticated A peer", || {
        a.connected(&env, &fresh_b.fp())
    });
    wait("replacement authenticated B peer", || {
        fresh_b.connected(&env, &a.fp())
    });
    let barrier = membership::author_commit(
        &a.ctx,
        Some(&a.team),
        &env,
        vec![json!({"op":"settings.update","sync_interval_seconds":7})],
    )
    .unwrap();
    wait("new commit reaches replacement B", || {
        CommitStore::new(fresh_b.ctx.state, &env)
            .last_seq(&a.fp())
            .unwrap()
            >= barrier.author_seq
    });
    wait(
        "offline fact is caught up after authenticated reconnect",
        || {
            sync::load_facts(&fresh_b.ctx, &env)
                .unwrap()
                .1
                .contains(&lost_hash)
        },
    );
    assert!(
        sync::load_facts(&fresh_b.ctx, &env)
            .unwrap()
            .0
            .disabled_connections
            .contains("synthetic-offline-target")
    );
    let delivered = a
        .team
        .publish_fact(
            &env,
            "connection_disabled",
            json!({"connection_id":"synthetic-connected-target"}),
        )
        .unwrap();
    let delivered_hash = sync::Fact::from_dict(&delivered).unwrap().hash().unwrap();
    wait("connected fact arrives", || {
        sync::load_facts(&fresh_b.ctx, &env)
            .unwrap()
            .1
            .contains(&delivered_hash)
    });
    // A later refold must not undo the recovered monotone fact.
    let after = membership::author_commit(
        &a.ctx,
        Some(&a.team),
        &env,
        vec![json!({"op":"settings.update","sync_interval_seconds":3})],
    )
    .unwrap();
    wait("later refold reaches replacement", || {
        CommitStore::new(fresh_b.ctx.state, &env)
            .last_seq(&a.fp())
            .unwrap()
            >= after.author_seq
    });
    let facts = sync::load_facts(&fresh_b.ctx, &env).unwrap();
    assert!(facts.1.contains(&lost_hash));
    assert!(facts.1.contains(&delivered_hash));
    assert!(
        facts
            .0
            .disabled_connections
            .contains("synthetic-offline-target")
    );
}
