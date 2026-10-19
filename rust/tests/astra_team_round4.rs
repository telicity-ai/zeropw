//! Independent gpt-6-astra supplements for exact original membership assertions.
//! Synthetic state and authenticated in-process peers; no product test hooks.
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tempfile::TempDir;
use zeropw::{
    clock,
    context::{Config, Context},
    team::{identity::DeviceKey, membership, sync::TeamSync, transport::InProcessTransport},
};

struct Node {
    ctx: Arc<Context>,
    transport: Arc<InProcessTransport>,
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
                    team_sync_interval_seconds: Some(0.05),
                    team_dial_backoff: (0.02, 0.1),
                    ..Config::default()
                },
                clock::system(),
            )
            .unwrap(),
        );
        let key = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        let transport = Arc::new(InProcessTransport::new(key.clone(), Arc::new(|_, _| None)));
        let team = TeamSync::new(ctx.clone(), transport.clone(), key);
        Self {
            ctx,
            transport,
            team,
        }
    }
    fn fp(&self) -> String {
        self.team.device.fingerprint().unwrap()
    }
    fn owner(&self, address: &str) -> String {
        self.ctx.projects.create("demo", &["dev"]).unwrap();
        let env = membership::share_environment(
            &self.ctx,
            None,
            "demo",
            "dev",
            "owner",
            "synthetic-admin",
        )
        .unwrap()["env_id"]
            .as_str()
            .unwrap()
            .to_owned();
        self.team.start(Some(address)).unwrap();
        env
    }
    fn join(&self, owner: &Node, env: &str, address: &str, role: &str) {
        self.team.start(None).unwrap();
        let invite = membership::create_invite(
            &owner.ctx,
            env,
            role,
            "synthetic-member",
            3600,
            &[address.into()],
        )
        .unwrap();
        membership::join(
            &self.ctx,
            &invite,
            self.transport.as_ref(),
            &self.team,
            Some("demo"),
            Some("dev"),
            5.0,
        )
        .unwrap();
        wait(|| owner.team.is_active_member(env, &self.fp()));
        assert_eq!(
            self.team.document(env).unwrap()["members"][self.fp()]["role"],
            role
        );
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        self.team.stop();
    }
}
fn wait(mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if check() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("bounded synthetic team convergence failed");
}

#[test]
fn original_user_role_self_removal_is_authored_and_propagated() {
    let root = TempDir::new().unwrap();
    let owner = Node::new(&root, "owner");
    let user = Node::new(&root, "user");
    let address = "astra-team-round4-self-owner:47001";
    let env = owner.owner(address);
    user.join(&owner, &env, address, "user");
    let fp = user.fp();
    let denied = user
        .team
        .publish_fact(
            &env,
            "connection_disabled",
            json!({"connection_id":"synthetic"}),
        )
        .unwrap_err();
    assert_eq!(denied.reason, "team_fact_not_authorized");
    let fact = user
        .team
        .publish_fact(&env, "member_removed", json!({"fingerprint":fp}))
        .unwrap();
    assert_eq!(fact["kind"], "member_removed");
    wait(|| !owner.team.is_active_member(&env, &fp));
    assert!(
        owner.team.document(&env).unwrap()["members"]
            .get(&fp)
            .is_none()
    );
    assert!(owner.team.is_active_member(&env, &owner.fp()));
}

#[test]
fn original_local_mutual_removal_rotates_only_before_author_is_removed() {
    let root = TempDir::new().unwrap();
    let owner = Node::new(&root, "owner");
    let bob = Node::new(&root, "bob");
    let carol = Node::new(&root, "carol");
    let address = "astra-team-round4-mutual-owner:47001";
    let env = owner.owner(address);
    bob.join(&owner, &env, address, "admin");
    carol.join(&owner, &env, address, "admin");
    wait(|| bob.team.is_active_member(&env, &carol.fp()));
    for node in [&owner, &bob, &carol] {
        node.team.stop();
    }
    let result_b = membership::remove_member(&bob.ctx, None, &env, &carol.fp()).unwrap();
    assert_eq!(result_b["dek_rotated"], true);
    let path = format!("team/{env}/facts.jsonl");
    let line = bob
        .ctx
        .state
        .read_lines(&path, None)
        .unwrap()
        .pop()
        .unwrap();
    let raw: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(raw["author"], bob.fp());
    assert_eq!(raw["target"]["fingerprint"], carol.fp());
    carol.ctx.state.append_line(&path, &line).unwrap();
    let result_c = membership::remove_member(&carol.ctx, None, &env, &bob.fp()).unwrap();
    assert_eq!(result_c["dek_rotated"], false);
    let doc = membership::load_environment(&carol.ctx, &env)
        .unwrap()
        .document;
    // Removed members stay listed as removed (issues #18 and #27).
    assert_eq!(doc["members"][bob.fp()]["status"], "removed");
    assert_eq!(doc["members"][carol.fp()]["status"], "removed");
    assert_eq!(doc["members"][owner.fp()]["status"], "active");
}
