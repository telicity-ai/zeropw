//! docs/remote-sync.md §3.1: team sync carried by the zeropw-link daemon.
//!
//! Every test runs real ZeroPW nodes (`TeamSync` over `LinkTransport`, or
//! the `zeropw-admin` binary) against the fake daemons of
//! `tests/link_daemon`, which splice a `dial` at one daemon with an `accept`
//! waiting at another. Covered: replication of commits and facts over `zpl:`
//! addresses only, joining through a `zpl:` invite address, learning a
//! peer's `zpl:` address from its inbound session, rotation between an
//! unreachable `HOST:PORT` and a working `zpl:` address in both directions,
//! a daemon that is absent, killed or restarted, malformed, oversized,
//! partial and unanswered daemon replies, a bounded `accept` pool that backs
//! off from a refusing daemon, one inbound cap for TCP and link,
//! and that neither the wire capture nor the daemon ever sees plaintext.
//! Synthetic credentials only.
mod link_daemon;
mod native_e2e;

use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use link_daemon::{Daemon, Fault, LinkNet};
use serde_json::{Value, json};
use tempfile::TempDir;
use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::team::commit::CommitStore;
use zeropw::team::identity::{DeviceKey, DeviceRecord};
use zeropw::team::link::{LinkConfig, LinkTransport};
use zeropw::team::membership;
use zeropw::team::sync::{self, TeamSync};
use zeropw::team::sync_status;
use zeropw::team::transport::{MembershipCheck, Session, SessionClosed, Transport};

const SECRET: &[u8] = b"synthetic-link-transport-secret-0123456789";
const ADMIN: &str = "synthetic-link-admin";

fn context(root: &Path, name: &str) -> Arc<Context> {
    Arc::new(
        Context::initialize(
            root.join(name),
            ADMIN,
            "synthetic-link-recovery",
            Config {
                team_sync_interval_seconds: Some(0.1),
                team_dial_backoff: (0.05, 0.3),
                ..Config::default()
            },
            clock::system(),
        )
        .unwrap(),
    )
}

fn fast_link() -> LinkConfig {
    LinkConfig {
        accept_workers: 2,
        accept_backoff: (Duration::from_millis(20), Duration::from_millis(200)),
        dial_timeout: Duration::from_secs(2),
    }
}

fn nobody() -> MembershipCheck {
    Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None })
}

struct Node {
    ctx: Arc<Context>,
    key: DeviceKey,
    transport: Arc<LinkTransport>,
    team: Arc<TeamSync>,
}

impl Node {
    fn new(ctx: Arc<Context>, daemon: Option<&Daemon>) -> Node {
        let key = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        let transport = Arc::new(
            LinkTransport::with_config(
                key.clone(),
                nobody(),
                8,
                daemon.map(|d| d.socket.clone()),
                fast_link(),
            )
            .unwrap(),
        );
        let team = TeamSync::new(ctx.clone(), transport.clone(), key.clone());
        Node {
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
    fn peers(&self, env: &str) -> Value {
        self.ctx
            .state
            .read_json(&format!("team/{env}/peers.json"), json!({}))
            .unwrap()
    }
    fn join(&self, invite: &str) -> zeropw::errors::Result<Value> {
        membership::join(
            &self.ctx,
            invite,
            self.transport.as_ref() as &dyn Transport,
            &self.team,
            Some("shared-demo"),
            Some("dev"),
            10.0,
        )
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.team.stop();
    }
}

fn wait(stage: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("stage did not complete: {stage}");
}

/// A node at `root/name` holding `gh-token` = [`SECRET`] in demo/dev, shared.
fn owner(root: &Path, name: &str, daemon: Option<&Daemon>) -> (Node, String) {
    let ctx = context(root, name);
    ctx.projects.create("demo", &["dev"]).unwrap();
    ctx.vault
        .put_secret("gh-token", "api_key", SECRET, "demo", "dev", true)
        .unwrap();
    let env =
        membership::share_environment(&ctx, None, "demo", "dev", "alice", ADMIN).unwrap()["env_id"]
            .as_str()
            .unwrap()
            .to_owned();
    (Node::new(ctx, daemon), env)
}

fn invite_to(owner: &Node, env: &str, addresses: &[String]) -> String {
    membership::create_invite(&owner.ctx, env, "admin", "bob", 3600, addresses).unwrap()
}

fn settings_commit(node: &Node, env: &str, seconds: i64) -> zeropw::pyint::PyInt {
    membership::author_commit(
        &node.ctx,
        Some(&node.team),
        env,
        vec![json!({"op":"settings.update","sync_interval_seconds":seconds})],
    )
    .unwrap()
    .author_seq
}

fn has_commit(node: &Node, env: &str, author: &str, seq: &zeropw::pyint::PyInt) -> bool {
    CommitStore::new(node.ctx.state, env)
        .last_seq(author)
        .unwrap()
        .0
        >= seq.0
}

fn has_fact(node: &Node, env: &str, fact: &Value) -> bool {
    let hash = sync::Fact::from_dict(fact).unwrap().hash().unwrap();
    sync::load_facts(&node.ctx, env).unwrap().1.contains(&hash)
}

fn unused_tcp_address() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    drop(listener);
    address
}

/// Two nodes that know each other only as `zpl:` peers replicate the
/// shared history, live commits and facts both ways; no TCP socket is
/// opened, and the joiner reached the inviter through a `zpl:` invite.
#[test]
fn two_nodes_replicate_commits_and_facts_over_link_addresses_only() {
    let root = TempDir::new().unwrap();
    let net = LinkNet::new();
    let (da, db) = (net.daemon("a"), net.daemon("b"));
    let (a, env) = owner(root.path(), "a", Some(&da));
    a.team.start(Some("")).unwrap();
    let b = Node::new(context(root.path(), "b"), Some(&db));
    b.team.start(Some("")).unwrap();
    let invite = invite_to(&a, &env, &[da.address()]);
    let joined = b.join(&invite).unwrap();
    assert_eq!(joined["env_id"], json!(env));
    assert_eq!(joined["inviter_fingerprint"], json!(a.fp()));
    // The joiner received the signed history, secret included.
    assert_eq!(
        b.ctx
            .vault
            .secret_for_trusted_use("gh-token", None)
            .unwrap()
            .expose(),
        SECRET
    );
    // Neither node listens on TCP.
    assert_eq!(a.transport.tcp().bound_address(), None);
    assert_eq!(b.transport.tcp().bound_address(), None);
    wait("both see the session", || {
        a.connected(&env, &b.fp()) && b.connected(&env, &a.fp())
    });

    let seq = settings_commit(&a, &env, 7);
    wait("A's commit reaches B", || {
        has_commit(&b, &env, &a.fp(), &seq)
    });
    let seq = settings_commit(&b, &env, 9);
    wait("B's commit reaches A", || {
        has_commit(&a, &env, &b.fp(), &seq)
    });
    let fact = a
        .team
        .publish_fact(
            &env,
            "connection_disabled",
            json!({"connection_id":"synthetic-link-a"}),
        )
        .unwrap();
    wait("A's fact reaches B", || has_fact(&b, &env, &fact));
    let fact = b
        .team
        .publish_fact(
            &env,
            "connection_disabled",
            json!({"connection_id":"synthetic-link-b"}),
        )
        .unwrap();
    wait("B's fact reaches A", || has_fact(&a, &env, &fact));
    assert_eq!(
        CommitStore::new(a.ctx.state, &env).vector().unwrap(),
        CommitStore::new(b.ctx.state, &env).vector().unwrap()
    );
    // B dialed A at the invite address; A learned B's from the inbound session.
    assert_eq!(b.peers(&env)[a.fp()], json!([da.address()]));
    assert_eq!(a.peers(&env)[b.fp()], json!([db.address()]));
    // Only the link carried the session.
    assert!(!net.relayed().is_empty());
}

/// docs/remote-sync.md §3.1: after an inbound link session authenticates as
/// member F, `zpl:<link peer>` is an address of F, so the node that only
/// ever accepted can dial F itself.
#[test]
fn an_inbound_link_session_teaches_the_dial_back_address() {
    let root = TempDir::new().unwrap();
    let net = LinkNet::new();
    let (da, db) = (net.daemon("a"), net.daemon("b"));
    let (a, env) = owner(root.path(), "a", Some(&da));
    a.team.start(Some("")).unwrap();
    let b = Node::new(context(root.path(), "b"), Some(&db));
    b.team.start(Some("")).unwrap();
    b.join(&invite_to(&a, &env, &[da.address()])).unwrap();
    wait("A learned B's link address", || {
        a.peers(&env)[b.fp()] == json!([db.address()])
    });
    // B restarts without any address for A: only A can re-establish.
    let (b_ctx, b_key) = (b.ctx.clone(), b.key.clone());
    drop(b);
    wait("A saw B go", || {
        !a.connected(&env, &b_key.fingerprint().unwrap())
    });
    std::fs::remove_file(b_ctx.state.path.join(format!("team/{env}/peers.json"))).unwrap();
    let b = Node::new(b_ctx, Some(&db));
    b.team.start(Some("")).unwrap();
    wait("A dialed B back over the link", || {
        a.connected(&env, &b.fp()) && b.connected(&env, &a.fp())
    });
    let seq = settings_commit(&a, &env, 11);
    wait("A's commit reaches the restarted B", || {
        has_commit(&b, &env, &a.fp(), &seq)
    });
    // B learned A's address back from A's inbound session.
    assert_eq!(b.peers(&env)[a.fp()], json!([da.address()]));
}

/// docs/remote-sync.md §3.3 over the link: both ends of a link session
/// (the inviter accepted it, the joiner dialed it) report the transport as
/// `link`, not the local Unix stream's TCP-like framing, and a redial the
/// daemon refuses is reported with the adapter's fixed reason.
#[test]
fn sync_state_reports_link_sessions_and_link_dial_failures() {
    let root = TempDir::new().unwrap();
    let net = LinkNet::new();
    let (da, db) = (net.daemon("a"), net.daemon("b"));
    let (a, env) = owner(root.path(), "a", Some(&da));
    a.team.enable_sync_state();
    a.team.start(Some("")).unwrap();
    let b = Node::new(context(root.path(), "b"), Some(&db));
    b.team.enable_sync_state();
    b.team.start(Some("")).unwrap();
    b.join(&invite_to(&a, &env, &[da.address()])).unwrap();
    let (a_fp, b_fp) = (a.fp(), b.fp());
    let peer = |node: &Node, fp: &str| -> Value {
        sync_status::status(&node.ctx, &env).unwrap()["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["fingerprint"] == fp)
            .cloned()
            .unwrap_or(Value::Null)
    };
    wait("both ends report a link session", || {
        let (at_a, at_b) = (peer(&a, &b_fp), peer(&b, &a_fp));
        at_a["session"] == true
            && at_a["transport"] == "link"
            && at_b["session"] == true
            && at_b["transport"] == "link"
    });
    let file = |node: &Node| {
        node.ctx
            .state
            .read_json(&sync_status::path(&env), Value::Null)
            .unwrap()
    };
    assert_eq!(file(&a)["peers"][&b_fp]["transport"], "link");
    assert_eq!(file(&b)["peers"][&a_fp]["transport"], "link");

    // B's Mac goes away with its daemon: A redials B's learned `zpl:`
    // address, the daemon answers peer_offline, and that is the last error.
    drop(b);
    db.kill();
    wait("A retries B with the link's reason", || {
        let at_a = peer(&a, &b_fp);
        at_a["state"] == "retrying"
            && at_a["session"] == false
            && at_a["transport"].is_null()
            && at_a["last_error"] == "link_peer_offline"
    });
    assert!(file(&a)["peers"][&b_fp]["dial_failures"].as_u64().unwrap() >= 1);
}

/// A peer known at an unreachable `HOST:PORT` (sorted first) and a working
/// `zpl:` address is reached over the link; once the link is down and the
/// `HOST:PORT` answers, the redial moves on from the link address (the
/// cursor a successful dial kept) and wraps around to TCP.
#[test]
fn dials_rotate_between_tcp_and_link_addresses_in_both_directions() {
    let root = TempDir::new().unwrap();
    let net = LinkNet::new();
    let (da, db) = (net.daemon("a"), net.daemon("b"));
    let (a, env) = owner(root.path(), "a", Some(&da));
    a.team.start(Some("")).unwrap();
    let b = Node::new(context(root.path(), "b"), Some(&db));
    b.team.start(Some("")).unwrap();
    b.join(&invite_to(&a, &env, &[da.address()])).unwrap();
    let tcp = unused_tcp_address();
    assert!(tcp < da.address(), "the HOST:PORT must sort first");
    b.team.set_peer_address(&env, &a.fp(), &tcp).unwrap();
    // Drop the join session: B redials, first at the dead TCP address. A
    // forgets B's address, so the session that comes back is B's dial.
    let (a_ctx, a_key) = (a.ctx.clone(), a.key.clone());
    let a_peers = a_ctx.state.path.join(format!("team/{env}/peers.json"));
    drop(a);
    wait("B saw A go", || {
        !b.connected(&env, &a_key.fingerprint().unwrap())
    });
    std::fs::remove_file(&a_peers).unwrap();
    let a = Node::new(a_ctx.clone(), Some(&da));
    a.team.start(Some("")).unwrap();
    wait("B reached A over the link", || b.connected(&env, &a.fp()));
    let seq = settings_commit(&a, &env, 13);
    wait("commit over the link", || {
        has_commit(&b, &env, &a.fp(), &seq)
    });

    // A now listens on that TCP address and its link daemon dies.
    drop(a);
    wait("B saw A go again", || {
        !b.connected(&env, &a_key.fingerprint().unwrap())
    });
    da.kill();
    let _ = std::fs::remove_file(&a_peers);
    let a = Node::new(a_ctx, Some(&da));
    a.team.start(Some(&tcp)).unwrap();
    wait("B fell back to TCP", || b.connected(&env, &a.fp()));
    let seq = settings_commit(&a, &env, 15);
    wait("commit over TCP", || has_commit(&b, &env, &a.fp(), &seq));
    assert!(da.delivered.load(std::sync::atomic::Ordering::SeqCst) > 0);
    let peers = b.peers(&env);
    let known: std::collections::BTreeSet<&str> = peers[a.fp()]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(known, [tcp.as_str(), da.address().as_str()].into());
}

/// The daemon may be absent when `serve` starts, crash and come back: the
/// node starts anyway, joins fail with a fixed reason meanwhile, and the
/// accept workers and dials recover once it runs again.
#[test]
fn an_absent_killed_or_restarted_daemon_is_survived() {
    let root = TempDir::new().unwrap();
    let net = LinkNet::new();
    let da = net.stopped_daemon("a");
    let db = net.daemon("b");
    let (a, env) = owner(root.path(), "a", Some(&da));
    // Listening on a socket that does not exist yet is no error.
    a.team.start(Some("")).unwrap();
    let invite = invite_to(&a, &env, &[da.address()]);

    // The joiner's own daemon is missing.
    let lonely = net.stopped_daemon("c");
    let c = Node::new(context(root.path(), "c"), Some(&lonely));
    let error = c.join(&invite).unwrap_err();
    assert_eq!(
        (error.reason.as_ref(), error.detail.as_str()),
        ("team_join_failed", "link_unavailable")
    );
    // The joiner's daemon runs, the inviter's does not.
    let b = Node::new(context(root.path(), "b"), Some(&db));
    b.team.start(Some("")).unwrap();
    let error = b.join(&invite).unwrap_err();
    assert_eq!(
        (error.reason.as_ref(), error.detail.as_str()),
        ("team_join_failed", "link_peer_offline")
    );

    da.start();
    wait("A's accept workers reconnected", || {
        da.waiting_accepts() > 0
    });
    b.join(&invite).unwrap();
    wait("session up", || b.connected(&env, &a.fp()));

    // A crash ends the session on both sides.
    da.kill();
    wait("session down", || {
        !b.connected(&env, &a.fp()) && !a.connected(&env, &b.fp())
    });
    let seq = settings_commit(&a, &env, 17);
    da.start();
    wait("redialed after the restart", || {
        b.connected(&env, &a.fp()) && a.connected(&env, &b.fp())
    });
    wait("the offline commit arrives", || {
        has_commit(&b, &env, &a.fp(), &seq)
    });
    // The joiner's daemon restarts too.
    db.kill();
    wait("session down again", || !b.connected(&env, &a.fp()));
    db.start();
    wait("redialed after the joiner's daemon restarted", || {
        b.connected(&env, &a.fp())
    });
}

const LINK_REASONS: [&str; 15] = [
    "link_unavailable",
    "link_protocol_error",
    "link_timeout",
    "link_socket_required",
    "link_address_invalid",
    "link_failed",
    "link_not_enrolled",
    "link_peer_unknown",
    "link_peer_revoked",
    "link_peer_offline",
    "link_connect_failed",
    "link_service_unavailable",
    "link_rate_limited",
    "link_invalid_request",
    "handshake_channel_closed",
];

fn dial_reason(node: &Node, address: &str, env: &str) -> &'static str {
    match node.transport.dial(address, env, None) {
        Ok(session) => {
            session.close();
            "ok"
        }
        Err(SessionClosed(reason)) => reason,
    }
}

/// Every malformed, oversized, partial or missing daemon reply fails the
/// dial closed with one fixed reason (no daemon text), and bad `accept`
/// replies cost the listener nothing but a retry.
#[test]
fn malformed_daemon_replies_fail_closed() {
    let root = TempDir::new().unwrap();
    let net = LinkNet::new();
    let (da, db) = (net.daemon("a"), net.daemon("b"));
    let (a, env) = owner(root.path(), "a", Some(&da));
    a.team.start(Some("")).unwrap();
    let b = Node::new(context(root.path(), "b"), Some(&db));
    b.join(&invite_to(&a, &env, &[da.address()])).unwrap();
    b.team.stop();
    let target = da.address();
    let mut oversized = vec![b'{'; 9000];
    oversized.push(b'\n');
    let cases: Vec<(Fault, &str)> = vec![
        (Fault::Reply(b"not json\n".to_vec()), "link_protocol_error"),
        (Fault::Reply(b"[]\n".to_vec()), "link_protocol_error"),
        (
            Fault::Reply(b"{\"ok\":true}\n".to_vec()),
            "link_protocol_error",
        ),
        (
            Fault::Reply(b"{\"ok\":true,\"path\":\"warp\"}\n".to_vec()),
            "link_protocol_error",
        ),
        (
            Fault::Reply(b"{\"ok\":true,\"path\":\"direct\",\"x\":1}\n".to_vec()),
            "link_protocol_error",
        ),
        (
            Fault::Reply(b"{\"ok\":\"true\",\"path\":\"direct\"}\n".to_vec()),
            "link_protocol_error",
        ),
        (
            Fault::Reply(b"{\"ok\":true,\"path\":\"dir\xffect\"}\n".to_vec()),
            "link_protocol_error",
        ),
        (Fault::Reply(oversized), "link_protocol_error"),
        (
            Fault::Reply(b"{\"ok\":true,\"path\":\"dir".to_vec()),
            "link_protocol_error",
        ),
        (
            Fault::Reply(b"{\"ok\":false,\"error\":\"peer_offline\"}\n".to_vec()),
            "link_peer_offline",
        ),
        (
            Fault::Reply(b"{\"ok\":false,\"error\":\"peer_revoked\"}\n".to_vec()),
            "link_peer_revoked",
        ),
        (
            Fault::Reply(
                b"{\"ok\":false,\"error\":\"synthetic-token-ZPL-SECRET candidate:1\"}\n".to_vec(),
            ),
            "link_failed",
        ),
        (
            Fault::Reply(b"{\"ok\":false}\n".to_vec()),
            "link_protocol_error",
        ),
        (Fault::Close, "link_unavailable"),
        (Fault::Reply(Vec::new()), "link_unavailable"),
        // A successful reply, then a peer that is not a ZeroPW responder.
        (
            Fault::Reply(b"{\"ok\":true,\"path\":\"direct\"}\nnot a frame".to_vec()),
            "handshake_channel_closed",
        ),
    ];
    for (fault, expected) in cases {
        db.set_fault(Some(fault.clone()));
        let reason = dial_reason(&b, &target, &env);
        assert_eq!(reason, expected, "{fault:?}");
        assert!(LINK_REASONS.contains(&reason), "{reason}");
    }
    // No reply at all: the dial gives up at its deadline (2 s + margin).
    db.set_fault(Some(Fault::Hang));
    let started = Instant::now();
    assert_eq!(dial_reason(&b, &target, &env), "link_timeout");
    assert!(started.elapsed() < Duration::from_secs(15));
    db.kill();
    db.start();
    db.set_fault(None);
    // Addresses that never reach a daemon.
    assert_eq!(
        dial_reason(&b, "zpl:ABCDEFGHIJKLMNOPQRSTUVWXYZ", &env),
        "link_address_invalid"
    );
    assert_eq!(dial_reason(&b, "zpl:", &env), "link_address_invalid");
    let unlinked = Node::new(context(root.path(), "u"), None);
    assert_eq!(
        dial_reason(&unlinked, &target, &env),
        "link_socket_required"
    );

    // Bad `accept` replies at the inviter: its workers retry and keep
    // serving once the daemon behaves.
    for bad in [
        b"{\"ok\":true,\"path\":\"direct\",\"peer\":\"BAD\"}\n".to_vec(),
        b"{\"ok\":true,\"path\":\"direct\"}\n".to_vec(),
        b"{\"ok\":false,\"error\":\"not_enrolled\"}\n".to_vec(),
        b"garbage".to_vec(),
        vec![b'x'; 9000],
    ] {
        let accepts = || da.accept_requests.load(std::sync::atomic::Ordering::SeqCst);
        let before = accepts();
        da.set_fault(Some(Fault::Reply(bad)));
        da.kill();
        da.start();
        // Each worker is refused and comes back (two workers, backoff).
        wait("the workers retried against the faulty daemon", || {
            accepts() >= before + 4
        });
    }
    da.set_fault(None);
    wait("the workers are waiting again", || da.waiting_accepts() > 0);
    assert_eq!(dial_reason(&b, &target, &env), "ok");
}

/// The `accept` pool holds exactly its configured number of requests at the
/// daemon, retries a daemon that refuses every `accept` with the doubling
/// backoff rather than in a hot loop, and sends nothing once shut down. A
/// link-only listener needs a socket, and a transport listens once.
#[test]
fn the_accept_pool_is_bounded_backs_off_and_stops() {
    use std::sync::atomic::Ordering::SeqCst;
    let net = LinkNet::new();
    let da = net.daemon("a");
    let close_it = || -> zeropw::team::transport::OnSession {
        Arc::new(|session: Arc<dyn Session>| session.close())
    };

    let unlinked = LinkTransport::new(DeviceKey::generate(), nobody(), 8, None).unwrap();
    assert_eq!(
        unlinked.listen("", close_it()).unwrap_err().reason,
        "link_socket_required"
    );

    let transport = LinkTransport::with_config(
        DeviceKey::generate(),
        nobody(),
        8,
        Some(da.socket.clone()),
        fast_link(),
    )
    .unwrap();
    transport.listen("", close_it()).unwrap();
    assert_eq!(
        transport.listen("", close_it()).unwrap_err().reason,
        "team_already_listening"
    );
    wait("the workers wait at the daemon", || {
        da.waiting_accepts() == 2
    });
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(da.waiting_accepts(), 2);
    assert_eq!(da.accept_requests.load(SeqCst), 2);

    // Every `accept` is refused from now on.
    da.set_fault(Some(Fault::Reply(
        b"{\"ok\":false,\"error\":\"not_enrolled\"}\n".to_vec(),
    )));
    da.kill();
    da.start();
    let before = da.accept_requests.load(SeqCst);
    std::thread::sleep(Duration::from_secs(2));
    let retried = da.accept_requests.load(SeqCst) - before;
    // Two workers, 20 ms doubling to 200 ms: about 26 requests in 2 s; a
    // loop without backoff would make thousands.
    assert!((4..=60).contains(&retried), "{retried} accept retries");

    let started = Instant::now();
    transport.shutdown();
    assert!(started.elapsed() < Duration::from_secs(5));
    // A request written just before the shutdown may still be counted by
    // the daemon's handler thread; give it time before the baseline.
    std::thread::sleep(Duration::from_millis(200));
    let after = da.accept_requests.load(SeqCst);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(da.accept_requests.load(SeqCst), after);
}

/// TCP and link inbound streams share the one connection cap; outbound and
/// inbound link sessions name the link peer they run over, TCP ones none.
#[test]
fn tcp_and_link_inbound_share_one_connection_cap() {
    let net = LinkNet::new();
    let (da, db) = (net.daemon("a"), net.daemon("b"));
    let a = DeviceKey::generate();
    let b = DeviceKey::generate();
    let (ar, br) = (a.record().unwrap(), b.record().unwrap());
    let member_of_a: MembershipCheck =
        Arc::new(move |_, fp| (fp == br.fingerprint()).then(|| br.clone()));
    let member_of_b: MembershipCheck =
        Arc::new(move |_, fp| (fp == ar.fingerprint()).then(|| ar.clone()));
    let ta = LinkTransport::with_config(
        a.clone(),
        member_of_a,
        1,
        Some(da.socket.clone()),
        fast_link(),
    )
    .unwrap();
    let tb = LinkTransport::with_config(b, member_of_b, 4, Some(db.socket.clone()), fast_link())
        .unwrap();
    let (tx, rx) = mpsc::channel::<Arc<dyn Session>>();
    let tx = Mutex::new(tx);
    ta.listen(
        "127.0.0.1:0",
        Arc::new(move |s| {
            let _ = tx.lock().unwrap().send(s);
        }),
    )
    .unwrap();
    let tcp = ta.tcp().bound_address().unwrap();
    let env = zeropw::team::commit::new_env_id(&a.fingerprint().unwrap()).unwrap();
    wait("A's workers wait at the daemon", || {
        da.waiting_accepts() > 0
    });
    let outbound = tb.dial(&da.address(), &env, None).unwrap();
    let inbound = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(outbound.link_address(), Some(da.address()));
    assert_eq!(inbound.link_address(), Some(db.address()));
    outbound
        .send(&json!({"type":"VECTOR","vector":{}}))
        .unwrap();
    assert_eq!(
        inbound.recv(Duration::from_secs(5)).unwrap().unwrap()["type"],
        "VECTOR"
    );
    // The one slot is taken: neither a TCP nor a link stream gets a session.
    assert!(tb.dial(&tcp, &env, None).is_err());
    assert!(tb.dial(&da.address(), &env, None).is_err());
    assert!(rx.try_recv().is_err());
    inbound.close();
    outbound.close();
    let over_tcp = tb.dial(&tcp, &env, None).unwrap();
    let accepted = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(over_tcp.link_address(), None);
    assert_eq!(accepted.link_address(), None);
    over_tcp.close();
    accepted.close();
    wait("the slot is free for a link stream again", || {
        match tb.dial(&da.address(), &env, None) {
            Ok(session) => {
                session.close();
                true
            }
            Err(_) => false,
        }
    });
    ta.shutdown();
    tb.shutdown();
}

/// What the wire-capture child does: a share, a join through `zpl:` and a
/// later commit, all over the fake link; then it stores every byte the
/// daemons relayed for the parent to scan.
fn wire_case(relay_file: &Path) {
    let root = TempDir::new().unwrap();
    let net = LinkNet::new();
    let (da, db) = (net.daemon("a"), net.daemon("b"));
    let (a, env) = owner(root.path(), "a", Some(&da));
    a.team.start(Some("")).unwrap();
    let b = Node::new(context(root.path(), "b"), Some(&db));
    b.team.start(Some("")).unwrap();
    let invite = invite_to(&a, &env, &[da.address()]);
    b.join(&invite).unwrap();
    assert_eq!(
        b.ctx
            .vault
            .secret_for_trusted_use("gh-token", None)
            .unwrap()
            .expose(),
        SECRET
    );
    let seq = settings_commit(&a, &env, 19);
    wait("commit", || has_commit(&b, &env, &a.fp(), &seq));
    drop(b);
    drop(a);
    let secret = membership::parse_invite(&invite).unwrap().invite_secret;
    std::fs::write(relay_file.with_extension("invite"), secret.expose()).unwrap();
    std::fs::write(relay_file, net.relayed()).unwrap();
}

/// The bytes the transport wrote and read through the link channel
/// (`ZEROPW_TEAM_WIRE_CAPTURE`) and every byte the daemons relayed carry no
/// secret value, invite secret or administrator passphrase in any encoding;
/// and the captured frames are the relayed ones, so the capture really is
/// of link traffic.
#[test]
fn link_wire_and_daemon_bytes_carry_no_plaintext() {
    if let Some(relay) = std::env::var_os("ZEROPW_LINK_WIRE_TEST_RELAY") {
        wire_case(Path::new(&relay));
        return;
    }
    let root = TempDir::new().unwrap();
    let capture = root.path().join("wire.hex");
    let relay = root.path().join("relay.bin");
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "link_wire_and_daemon_bytes_carry_no_plaintext",
            "--nocapture",
        ])
        .env("ZEROPW_LINK_WIRE_TEST_RELAY", &relay)
        .env("ZEROPW_TEAM_WIRE_CAPTURE", &capture)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child link run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let frames: Vec<Vec<u8>> = std::fs::read_to_string(&capture)
        .unwrap()
        .lines()
        .map(|line| hex::decode(line.split_once(' ').unwrap().1).unwrap())
        .collect();
    let relayed = std::fs::read(&relay).unwrap();
    assert!(frames.len() > 6, "capture must contain real link frames");
    assert!(!relayed.is_empty(), "the daemons must have relayed bytes");
    for frame in &frames {
        let mut framed = (frame.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(frame);
        assert!(
            relayed
                .windows(framed.len())
                .any(|w| w == framed.as_slice()),
            "a captured frame did not cross the link"
        );
    }
    let invite_secret = std::fs::read(relay.with_extension("invite")).unwrap();
    assert_eq!(invite_secret.len(), 32);
    let needles = vec![SECRET.to_vec(), invite_secret, ADMIN.as_bytes().to_vec()];
    assert_eq!(native_e2e::find_secret(&frames.concat(), &needles), None);
    assert_eq!(native_e2e::find_secret(&relayed, &needles), None);
    let hex_capture = std::fs::read(&capture).unwrap();
    assert_eq!(native_e2e::find_secret(&hex_capture, &needles), None);
}

// ---------------------------------------------------------------- CLI

const CLI_SECRET: &str = "synthetic-link-cli-token-0123456789";
const CLI_SECRET_V2: &str = "synthetic-link-cli-token-v2-9876543210";

fn serve_env(admin: &native_e2e::Admin, capture: &Path) -> Vec<(String, String)> {
    vec![
        ("PATH".into(), native_e2e::path_env()),
        ("HOME".into(), admin.root.to_string_lossy().into_owned()),
        (
            "ZEROPW_ADMIN_PASSPHRASE".into(),
            native_e2e::ADMIN_PASSPHRASE.into(),
        ),
        (
            "ZEROPW_TEAM_WIRE_CAPTURE".into(),
            capture.to_string_lossy().into_owned(),
        ),
    ]
}

fn serve(admin: &native_e2e::Admin, extra: &[&str], capture: &Path) -> native_e2e::Serve {
    let env = serve_env(admin, capture);
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    native_e2e::Serve::start(&admin.state, extra, &env)
}

/// `serve --link-socket` (link-only inbound) and `team join --link-socket`
/// end to end with the native binary, plus the fixed failures of a missing
/// or relative socket and of a link-only invite without one.
#[test]
fn cli_serve_and_join_through_link_sockets() {
    let net = LinkNet::new();
    let (da, db) = (net.daemon("a"), net.daemon("b"));
    let root = tempfile::Builder::new()
        .prefix("zplc-")
        .tempdir_in("/tmp")
        .unwrap();
    let capture = root.path().join("wire.hex");
    let a = native_e2e::Admin::new(&root.path().join("a"));
    let b = native_e2e::Admin::new(&root.path().join("b"));
    let c = native_e2e::Admin::new(&root.path().join("c"));
    a.ok(&["init"]);
    a.ok(&["team", "init"]);
    a.ok(&["project", "create", "demo"]);
    let put = |admin: &native_e2e::Admin, value: &str| {
        admin
            .cmd(&[
                "secret",
                "put",
                "--id",
                "gh-token",
                "--kind",
                "api_key",
                "--project",
                "demo",
                "--environment",
                "dev",
                "--stdin",
            ])
            .stdin(value.as_bytes())
            .ok()
    };
    put(&a, CLI_SECRET);
    a.ok(&["team", "share", "--project", "demo", "--environment", "dev"]);
    let a_socket = da.socket.to_string_lossy().into_owned();
    let b_socket = db.socket.to_string_lossy().into_owned();
    // `--link-socket` must be absolute.
    let refused = a
        .cmd(&[
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--link-socket",
            "a.sock",
        ])
        .fail(1);
    assert_eq!(refused["reason"], "invalid_link_socket");
    let mut a_serve = serve(
        &a,
        &["--listen", "127.0.0.1:0", "--link-socket", &a_socket],
        &capture,
    );
    assert_eq!(a_serve.startup["link_socket"], json!(a_socket));
    assert_eq!(a_serve.startup["team_listen"], Value::Null);
    let created = a.ok(&[
        "team",
        "invite",
        "--env",
        "demo/dev",
        "--role",
        "admin",
        "--name",
        "bob",
        "--address",
        &da.address(),
    ]);
    let invite = created["invite"].as_str().unwrap().to_owned();
    let preview = a
        .cmd(&["team", "invite-info", "--stdin"])
        .state(&root.path().join("no-state"))
        .stdin(invite.as_bytes())
        .ok();
    assert_eq!(preview["addresses"], json!([da.address()]));
    let refused = a
        .cmd(&[
            "team",
            "invite",
            "--env",
            "demo/dev",
            "--role",
            "user",
            "--name",
            "eve",
            "--address",
            "zpl:NOT-A-DEVICE-ID",
        ])
        .fail(1);
    assert_eq!(refused["reason"], "invalid_address");

    for node in [&b, &c] {
        node.ok(&["init"]);
    }
    let capture_text = capture.to_string_lossy().into_owned();
    let join = |node: &native_e2e::Admin, extra: &[&str], code: i32| -> Value {
        let mut args = vec![
            "team",
            "join",
            invite.as_str(),
            "--project",
            "team-shared",
            "--environment",
            "dev",
        ];
        args.extend_from_slice(extra);
        let call = node
            .cmd(&args)
            .env("ZEROPW_TEAM_WIRE_CAPTURE", &capture_text);
        if code == 0 {
            call.ok()
        } else {
            call.fail(code)
        }
    };
    // A link-only invite needs the socket, and nothing is stored without it.
    let refused = join(&c, &[], 1);
    assert_eq!(refused["reason"], "link_socket_required");
    assert!(
        !c.state.join("team/envs.json").exists()
            || !std::fs::read_to_string(c.state.join("team/envs.json"))
                .unwrap()
                .contains("team-shared")
    );
    let refused = join(&c, &["--link-socket", "relative.sock"], 1);
    assert_eq!(refused["reason"], "invalid_link_socket");
    let missing = root.path().join("missing.sock");
    let refused = join(&c, &["--link-socket", &missing.to_string_lossy()], 1);
    assert_eq!(
        (refused["reason"].as_str(), refused["detail"].as_str()),
        (Some("team_join_failed"), Some("link_unavailable"))
    );

    let joined = join(&b, &["--link-socket", &b_socket], 0);
    let a_fp = joined["inviter_fingerprint"].as_str().unwrap().to_owned();
    let b_fp = joined["self_fingerprint"].as_str().unwrap().to_owned();
    // A learned B's link address from the joiner's inbound session.
    native_e2e::until(Duration::from_secs(30), || {
        let peers = a.ok(&["team", "peers", "--env", "demo/dev"]);
        (peers["peers"][&b_fp] == json!([db.address()])).then_some(())
    })
    .expect("A did not record B's link address");

    let mut b_serve = serve(
        &b,
        &["--listen", "127.0.0.1:0", "--link-socket", &b_socket],
        &capture,
    );
    put(&a, CLI_SECRET_V2);
    let vector = |admin: &native_e2e::Admin, env: &str| {
        admin.ok(&["team", "status", "--env", env])["vector"][&a_fp].clone()
    };
    native_e2e::until(Duration::from_secs(60), || {
        let target = vector(&a, "demo/dev");
        (vector(&b, "team-shared/dev") == target).then_some(())
    })
    .expect("A's new version did not reach B over the link");
    let shown = b.ok(&["team", "show", "--env", "team-shared/dev"]);
    let versions = &shown["secrets"]["gh-token"]["versions"];
    let count = versions
        .as_object()
        .map(|m| m.len())
        .or_else(|| versions.as_array().map(Vec::len));
    assert_eq!(count, Some(2), "{shown}");

    // Both serves run link-only (no --team-listen) and still write
    // sync_state.json: `team sync-status` sees the session, carried by the
    // link, on both Macs.
    let sync_peer = |admin: &native_e2e::Admin, env: &str, fp: &str| -> Value {
        let status = admin.ok(&["team", "sync-status", "--env", env]);
        if status["serve_updated_at"].is_null() {
            return Value::Null;
        }
        status["peers"]
            .as_array()
            .and_then(|peers| peers.iter().find(|p| p["fingerprint"] == fp))
            .cloned()
            .unwrap_or(Value::Null)
    };
    native_e2e::until(Duration::from_secs(30), || {
        let (at_a, at_b) = (
            sync_peer(&a, "demo/dev", &b_fp),
            sync_peer(&b, "team-shared/dev", &a_fp),
        );
        (at_a["session"] == true
            && at_a["transport"] == "link"
            && at_b["session"] == true
            && at_b["transport"] == "link")
            .then_some(())
    })
    .expect("a link-only serve did not report its link session");

    // `team peers --add` takes only well-formed link addresses.
    let refused = b
        .cmd(&[
            "team",
            "peers",
            "--env",
            "team-shared/dev",
            "--add",
            "zpl:short",
            "--device",
            &a_fp,
        ])
        .fail(1);
    assert_eq!(refused["reason"], "team_invalid_peer_address");
    let added = b.ok(&[
        "team",
        "peers",
        "--env",
        "team-shared/dev",
        "--add",
        &da.address(),
        "--device",
        &a_fp,
    ]);
    assert_eq!(added["peers"][&a_fp], json!([da.address()]));

    let (_, a_out) = a_serve.stop();
    let (_, b_out) = b_serve.stop();
    let needles = vec![
        CLI_SECRET.as_bytes().to_vec(),
        CLI_SECRET_V2.as_bytes().to_vec(),
        native_e2e::ADMIN_PASSPHRASE.as_bytes().to_vec(),
    ];
    for (who, text) in [("A serve", a_out), ("B serve", b_out)] {
        assert_eq!(
            native_e2e::find_secret(text.as_bytes(), &needles),
            None,
            "{who}"
        );
    }
    let wire = std::fs::read(&capture).unwrap();
    assert!(
        !wire.is_empty(),
        "the serve and join processes captured no frames"
    );
    assert_eq!(native_e2e::find_secret(&wire, &needles), None);
    let relayed = net.relayed();
    assert!(!relayed.is_empty());
    assert_eq!(native_e2e::find_secret(&relayed, &needles), None);
    for admin in [&a, &b, &c] {
        assert_eq!(
            native_e2e::find_secret_in_tree(&admin.state, &needles[..2]),
            None
        );
    }
}
