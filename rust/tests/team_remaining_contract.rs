//! Native counterparts of still-unmapped original team contracts. All values and
//! endpoints are synthetic. No Python product implementation is used here.
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tempfile::TempDir;
use zeropw::team::transport::TcpTransport;
use zeropw::{
    clock,
    context::{Config, Context},
    policy::{self, Connection, HttpAuth, HttpScope, HttpTarget},
    team::{
        commit::{self, CommitStore},
        envelope,
        identity::DeviceKey,
        membership,
        sync::TeamSync,
        transport::{InProcessTransport, MembershipCheck, Transport},
    },
};

const SECRET: &[u8] = b"synthetic-team-share-secret-0123456789";
type PeerTransportPair = (
    Arc<dyn Transport>,
    Arc<dyn Transport>,
    Option<Arc<TcpTransport>>,
    Option<Arc<TcpTransport>>,
);

fn context(root: &TempDir) -> Arc<Context> {
    Arc::new(
        Context::initialize(
            root.path().join("state"),
            "synthetic-admin-pass",
            "synthetic-recovery-pass",
            Config::default(),
            clock::system(),
        )
        .unwrap(),
    )
}

fn connection(id: &str, secret_id: &str) -> Connection {
    Connection::new(
        id,
        "demo",
        "dev",
        "synthetic",
        "http",
        secret_id,
        None,
        "",
        Some(HttpTarget::new("https", format!("{id}.example.com"), 443, None, false).unwrap()),
        Some(HttpAuth::bearer()),
        Some(
            HttpScope::new(
                Some(vec!["GET".into()]),
                Some(vec!["/repos".into()]),
                vec![],
            )
            .unwrap(),
        ),
        None,
        None,
        0,
        "active",
        "",
        "",
    )
    .unwrap()
}

fn setup() -> (TempDir, Arc<Context>, String) {
    let root = TempDir::new().unwrap();
    let ctx = context(&root);
    ctx.projects.create("demo", &["dev"]).unwrap();
    ctx.vault
        .put_secret("gh-token", "api_key", SECRET, "demo", "dev", true)
        .unwrap();
    ctx.policy
        .create_connection(connection("gh", "gh-token"))
        .unwrap();
    ctx.policy.create_principal("agent-1", "default").unwrap();
    let grant = ctx
        .policy
        .create_grant("agent-1", "gh", Some(3600), None)
        .unwrap();
    (root, ctx, grant.id)
}

fn share(ctx: &Context) -> Value {
    membership::share_environment(ctx, None, "demo", "dev", "owner", "synthetic-admin-pass")
        .unwrap()
}

#[test]
fn share_converts_existing_connection_and_stales_its_grant() {
    let (_root, ctx, grant_id) = setup();
    let before = ctx.policy.get_connection("gh").unwrap().policy_version;
    let result = share(&ctx);
    let env_id = result["env_id"].as_str().unwrap();
    let after = ctx.policy.get_connection("gh").unwrap();
    let raw = ctx.state.read_json(policy::CONNECTIONS, json!({})).unwrap();
    assert_eq!(raw["gh"]["shared_env"], env_id);
    assert!(after.policy_version > before);
    let grants = ctx.policy.list_grants(None).unwrap();
    assert_eq!(
        grants.iter().find(|g| g.id == grant_id).unwrap().status,
        "stale"
    );
    assert_eq!(
        ctx.vault
            .secret_for_trusted_use("gh-token", None)
            .unwrap()
            .expose(),
        SECRET
    );
    assert_eq!(after.http_target.unwrap().host, "gh.example.com");
}

#[test]
fn share_leaves_revoked_and_cross_project_secret_connections_local() {
    let (_root, ctx, _grant_id) = setup();
    ctx.vault
        .put_secret(
            "dead-token",
            "api_key",
            b"synthetic-dead-token",
            "demo",
            "dev",
            true,
        )
        .unwrap();
    ctx.vault
        .set_version_status("dead-token", &1.into(), "revoked")
        .unwrap();
    ctx.policy
        .create_connection(connection("dead", "dead-token"))
        .unwrap();
    let dead_grant = ctx
        .policy
        .create_grant("agent-1", "dead", Some(3600), None)
        .unwrap();
    ctx.projects.create("other", &["otherenv"]).unwrap();
    ctx.vault
        .put_secret(
            "other-token",
            "api_key",
            b"synthetic-other-token",
            "other",
            "otherenv",
            true,
        )
        .unwrap();
    ctx.policy
        .create_connection(connection("cross", "other-token"))
        .unwrap();

    let result = share(&ctx);
    let env_id = result["env_id"].as_str().unwrap();
    let not_shared = result["not_shared"].as_array().unwrap();
    assert_eq!(not_shared.len(), 2);
    for id in ["dead", "cross"] {
        assert!(
            not_shared
                .iter()
                .any(|entry| entry["connection"] == id && entry["reason"] == "secret_not_shared")
        );
    }
    let raw = ctx.state.read_json(policy::CONNECTIONS, json!({})).unwrap();
    for id in ["dead", "cross"] {
        assert!(raw[id].get("shared_env").is_none());
        assert_eq!(raw[id]["status"], "active");
        assert_eq!(ctx.policy.get_connection(id).unwrap().policy_version, 1);
    }
    assert_eq!(
        ctx.policy
            .list_grants(None)
            .unwrap()
            .iter()
            .find(|g| g.id == dead_grant.id)
            .unwrap()
            .status,
        "active"
    );
    assert_eq!(raw["gh"]["shared_env"], env_id);
    let document = membership::load_environment(&ctx, env_id).unwrap().document;
    for id in ["dead-token", "other-token"] {
        assert!(document["secrets"].get(id).is_none());
    }
    for id in ["dead", "cross"] {
        assert!(document["connections"].get(id).is_none());
    }
    assert!(document["secrets"].get("gh-token").is_some());
    assert!(document["connections"].get("gh").is_some());
}

#[test]
fn share_refuses_duplicate_and_wrong_admin_passphrase() {
    let (_root, ctx, _) = setup();
    let wrong =
        membership::share_environment(&ctx, None, "demo", "dev", "owner", "wrong-passphrase")
            .unwrap_err();
    assert_eq!(wrong.name, "AuthFailed");
    share(&ctx);
    let duplicate =
        membership::share_environment(&ctx, None, "demo", "dev", "owner", "synthetic-admin-pass")
            .unwrap_err();
    assert_eq!(duplicate.name, "InvalidInput");
    assert_eq!(duplicate.reason, "team_env_already_shared");
}

fn admin(state: &std::path::Path, args: &[&str], stdin: &[u8]) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_zeropw-admin"))
        .args(["--state-dir", state.to_str().unwrap()])
        .args(args)
        .env("ZEROPW_ADMIN_PASSPHRASE", "synthetic-admin-pass")
        .env("ZEROPW_RECOVERY_PASSPHRASE", "synthetic-recovery-pass")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "native admin failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.stdout.windows(SECRET.len()).any(|v| v == SECRET));
    assert!(!output.stderr.windows(SECRET.len()).any(|v| v == SECRET));
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn shared_admin_fact_commands_do_not_author_commits_or_emit_secret_fields() {
    for case in ["connection", "secret"] {
        let (_root, ctx, _) = setup();
        let env = share(&ctx)["env_id"].as_str().unwrap().to_owned();
        let before = CommitStore::new(ctx.state, &env)
            .all_commits()
            .unwrap()
            .len();
        let payload = if case == "connection" {
            admin(
                &ctx.state.path,
                &["connection", "disable", "--id", "gh"],
                b"",
            )
        } else {
            admin(
                &ctx.state.path,
                &["secret", "revoke", "--id", "gh-token", "--version", "1"],
                b"",
            )
        };
        assert!(payload.get("fact").is_some());
        assert!(payload.get("commit").is_none());
        assert_eq!(
            CommitStore::new(ctx.state, &env)
                .all_commits()
                .unwrap()
                .len(),
            before
        );
        for forbidden in ["nonce", "ciphertext", "sig", "wraps"] {
            assert!(!payload.to_string().contains(forbidden));
        }
        if case == "connection" {
            assert_eq!(payload["status"], "disabled");
            assert_eq!(ctx.policy.get_connection("gh").unwrap().status, "disabled");
        } else {
            assert_eq!(
                ctx.vault.get_meta("gh-token").unwrap().versions[0].status,
                "revoked"
            );
        }
    }
}

#[test]
fn shared_admin_secret_put_and_connection_update_author_commits() {
    let (_root, ctx, _) = setup();
    let env = share(&ctx)["env_id"].as_str().unwrap().to_owned();
    let store = CommitStore::new(ctx.state, &env);
    let before = store.all_commits().unwrap().len();
    let put = admin(
        &ctx.state.path,
        &[
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
        ],
        b"synthetic-team-facts-v2\n",
    );
    assert!(put["commit"]["author_seq"].as_i64().is_some());
    assert!(put["commit"]["hlc"].as_str().is_some());
    let middle = store.all_commits().unwrap().len();
    assert!(middle > before);
    let update = admin(
        &ctx.state.path,
        &[
            "connection",
            "update",
            "--id",
            "gh",
            "--methods",
            "GET,POST",
        ],
        b"",
    );
    assert!(update.get("commit").is_some());
    assert!(store.all_commits().unwrap().len() > middle);
}

#[test]
fn old_session_is_closed_then_replaced_by_a_new_authenticated_session() {
    let root = TempDir::new().unwrap();
    let cfg = Config {
        team_sync_interval_seconds: Some(0.1),
        team_dial_backoff: (0.05, 0.2),
        team_session_max_age_seconds: 0.3,
        ..Config::default()
    };
    let make = |name: &str| {
        Arc::new(
            Context::initialize(
                root.path().join(name),
                "synthetic-admin-pass",
                "synthetic-recovery-pass",
                cfg.clone(),
                clock::system(),
            )
            .unwrap(),
        )
    };
    let a = make("a");
    let b = make("b");
    let ka = DeviceKey::load_or_create(a.state, a.kms).unwrap();
    let kb = DeviceKey::load_or_create(b.state, b.kms).unwrap();
    let fa = ka.fingerprint().unwrap();
    let fb = kb.fingerprint().unwrap();
    let env = commit::new_env_id(&fa).unwrap();
    let generation = "0000000000000000";
    let dek = [7u8; 32];
    let wrap = envelope::wrap_dek(&dek, &env, generation, &ka.record().unwrap()).unwrap();
    let init = commit::sign_commit(&ka, &env, 1, "1000-0000", &BTreeMap::new(), vec![json!({"op":"env.init","owner_device":ka.record().unwrap().to_dict(),"owner_name":"alice","generation_id":generation,"wraps":{fa.clone():wrap}})]).unwrap();
    let add = commit::sign_commit(&ka, &env, 2, "2000-0000", &BTreeMap::new(), vec![json!({"op":"member.add","device":kb.record().unwrap().to_dict(),"name":"bob","role":"admin"})]).unwrap();
    for ctx in [&a, &b] {
        let store = CommitStore::new(ctx.state, &env);
        store.append(&init).unwrap();
        store.append(&add).unwrap();
    }
    let empty: MembershipCheck = Arc::new(|_, _| None);
    let ta = Arc::new(InProcessTransport::new(ka.clone(), empty.clone()));
    let tb = Arc::new(InProcessTransport::new(kb.clone(), empty));
    let sa = TeamSync::new(a, ta.clone(), ka);
    let sb = TeamSync::new(b, tb, kb);
    sa.start(Some("remaining-session-a")).unwrap();
    sb.start(Some("remaining-session-b")).unwrap();
    struct Stop<'a>(&'a TeamSync, &'a TeamSync);
    impl Drop for Stop<'_> {
        fn drop(&mut self) {
            self.0.stop();
            self.1.stop();
        }
    }
    let _stop = Stop(&sa, &sb);
    let first = ta.dial("remaining-session-b", &env, None).unwrap();
    sa.adopt_outbound_session(&env, first.clone(), "remaining-session-b");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !first.is_closed() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(first.is_closed(), "aged original session was not closed");
    while !sa.status(&env).unwrap()["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == &fb)
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        sa.status(&env).unwrap()["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == &fb),
        "no replacement session after expiration"
    );
}

fn connection_create(id: &str) -> Value {
    json!({"op":"connection.create","id":id,"project":"demo","environment":"dev","service":"synthetic","kind":"http","secret_id":"key","secret_version":null,"description":"","http_target":{"scheme":"http","host":"127.0.0.1","port":8080},"http_auth":{"mode":"bearer"},"http_scope":{"methods":["GET"],"path_prefixes":["/repos"]}})
}

fn two_node_convergence(tcp: bool) {
    let root = TempDir::new().unwrap();
    let config = Config {
        team_sync_interval_seconds: Some(0.1),
        team_dial_backoff: (0.05, 0.2),
        ..Config::default()
    };
    let create = |name: &str| {
        Arc::new(
            Context::initialize(
                root.path().join(name),
                "synthetic-admin",
                "synthetic-recovery",
                config.clone(),
                clock::system(),
            )
            .unwrap(),
        )
    };
    let a = create("a");
    let b = create("b");
    let ka = DeviceKey::load_or_create(a.state, a.kms).unwrap();
    let kb = DeviceKey::load_or_create(b.state, b.kms).unwrap();
    let fa = ka.fingerprint().unwrap();
    let fb = kb.fingerprint().unwrap();
    let env = commit::new_env_id(&fa).unwrap();
    let generation = "0000000000000000";
    let dek = [7u8; 32];
    let wraps = json!({fa.clone():envelope::wrap_dek(&dek, &env, generation, &ka.record().unwrap()).unwrap(), fb.clone():envelope::wrap_dek(&dek, &env, generation, &kb.record().unwrap()).unwrap()});
    let ct = envelope::encrypt_secret(&dek, &env, "key", "0011223344556677", SECRET).unwrap();
    let c1 = commit::sign_commit(&ka, &env, 1, "1000-0000", &BTreeMap::new(), vec![json!({"op":"env.init","owner_device":ka.record().unwrap().to_dict(),"owner_name":"alice","generation_id":generation,"wraps":wraps}), json!({"op":"secret.put_version","secret_id":"key","kind":"api_key","generation_id":generation,"version_id":"0011223344556677","ciphertext":ct,"public":{}})]).unwrap();
    let c2 = commit::sign_commit(&ka, &env, 2, "2000-0000", &BTreeMap::new(), vec![json!({"op":"member.add","device":kb.record().unwrap().to_dict(),"name":"bob","role":"admin"})]).unwrap();
    for ctx in [&a, &b] {
        let store = CommitStore::new(ctx.state, &env);
        store.append(&c1).unwrap();
        store.append(&c2).unwrap();
    }
    let empty: MembershipCheck = Arc::new(|_, _| None);
    let (transport_a, transport_b, tcp_a, tcp_b): PeerTransportPair = if tcp {
        let ta = TcpTransport::new(ka.clone(), empty.clone(), 4);
        let tb = TcpTransport::new(kb.clone(), empty, 4);
        (
            Arc::new(ta.clone()),
            Arc::new(tb.clone()),
            Some(ta),
            Some(tb),
        )
    } else {
        (
            Arc::new(InProcessTransport::new(ka.clone(), empty.clone())),
            Arc::new(InProcessTransport::new(kb.clone(), empty)),
            None,
            None,
        )
    };
    let sa = TeamSync::new(a.clone(), transport_a, ka.clone());
    let sb = TeamSync::new(b.clone(), transport_b, kb.clone());
    let addr_a = if tcp {
        "127.0.0.1:0"
    } else {
        "native-convergence-a"
    };
    let addr_b = if tcp {
        "127.0.0.1:0"
    } else {
        "native-convergence-b"
    };
    sa.start(Some(addr_a)).unwrap();
    sb.start(Some(addr_b)).unwrap();
    struct Stop(Arc<TeamSync>, Arc<TeamSync>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.stop();
            self.1.stop();
        }
    }
    let _stop = Stop(sa.clone(), sb.clone());
    let address_a = tcp_a
        .as_ref()
        .and_then(|v| v.bound_address())
        .unwrap_or_else(|| addr_a.to_owned());
    let address_b = tcp_b
        .as_ref()
        .and_then(|v| v.bound_address())
        .unwrap_or_else(|| addr_b.to_owned());
    sa.set_peer_address(&env, &fb, &address_b).unwrap();
    sb.set_peer_address(&env, &fa, &address_a).unwrap();
    let wait = |check: &dyn Fn() -> bool| {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if check() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("two-node convergence condition failed (tcp={tcp})");
    };
    wait(&|| {
        sa.status(&env).unwrap()["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == &fb)
    });
    wait(&|| {
        sb.status(&env).unwrap()["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == &fa)
    });
    let ca = commit::sign_commit(
        &ka,
        &env,
        3,
        "3000-0000",
        &BTreeMap::new(),
        vec![connection_create("gh-a")],
    )
    .unwrap();
    let cb = commit::sign_commit(
        &kb,
        &env,
        1,
        "3500-0000",
        &BTreeMap::new(),
        vec![connection_create("gh-b")],
    )
    .unwrap();
    assert_eq!(sa.submit_commit(&env, &ca).unwrap(), "accepted");
    assert_eq!(sb.submit_commit(&env, &cb).unwrap(), "accepted");
    wait(&|| CommitStore::new(a.state, &env).last_seq(&fb).unwrap() >= 1);
    wait(&|| CommitStore::new(b.state, &env).last_seq(&fa).unwrap() >= 3);
    wait(&|| {
        ["gh-a", "gh-b"]
            .iter()
            .all(|id| sa.document(&env).unwrap()["connections"].get(id).is_some())
    });
    wait(&|| {
        ["gh-a", "gh-b"]
            .iter()
            .all(|id| sb.document(&env).unwrap()["connections"].get(id).is_some())
    });
    let doc_a = sa.document(&env).unwrap();
    let doc_b = sb.document(&env).unwrap();
    assert_eq!(doc_a, doc_b);
    for id in ["gh-a", "gh-b"] {
        assert!(doc_a["connections"].get(id).is_some());
    }
    wait(&|| !sa.status(&env).unwrap()["synced_at"].is_null());
    wait(&|| !sb.status(&env).unwrap()["synced_at"].is_null());
}

#[test]
fn original_two_node_convergence_inprocess() {
    two_node_convergence(false);
}

#[test]
fn original_two_node_convergence_tcp() {
    two_node_convergence(true);
}

#[test]
fn explicit_empty_membership_refuses_inprocess_and_tcp_handshakes() {
    // Rust requires an explicit MembershipCheck argument; unlike Python it
    // exposes no zero-argument constructor/default callback. This closure is
    // the measured fail-closed equivalent of Python's absent membership.
    for tcp in [false, true] {
        let a = DeviceKey::generate();
        let b = DeviceKey::generate();
        let fa = a.fingerprint().unwrap();
        let env = commit::new_env_id(&fa).unwrap();
        let empty: MembershipCheck = Arc::new(|_, _| None);
        let accepted = Arc::new(AtomicBool::new(false));
        let failures = Arc::new(Mutex::new(Vec::new()));
        if tcp {
            let ta = TcpTransport::new(a, empty.clone(), 4);
            let tb = TcpTransport::new(b, empty, 4);
            let accepted_cb = accepted.clone();
            let failed_cb = failures.clone();
            tb.set_handshake_failed(Some(Arc::new(move |reason, fp| {
                failed_cb
                    .lock()
                    .unwrap()
                    .push((reason.to_owned(), fp.map(str::to_owned)));
            })));
            tb.listen_arc(
                "127.0.0.1:0",
                Arc::new(move |_| accepted_cb.store(true, Ordering::Release)),
            )
            .unwrap();
            assert!(
                ta.dial_session(&tb.bound_address().unwrap(), &env, None)
                    .is_err()
            );
            let deadline = Instant::now() + Duration::from_secs(3);
            while failures.lock().unwrap().is_empty() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            ta.shutdown();
            tb.shutdown();
        } else {
            let ta = InProcessTransport::new(a, empty.clone());
            let tb = InProcessTransport::new(b, empty);
            let accepted_cb = accepted.clone();
            let failed_cb = failures.clone();
            tb.set_handshake_failed(Some(Arc::new(move |reason, fp| {
                failed_cb
                    .lock()
                    .unwrap()
                    .push((reason.to_owned(), fp.map(str::to_owned)));
            })));
            tb.listen(
                "native-empty-membership",
                Arc::new(move |_| accepted_cb.store(true, Ordering::Release)),
            )
            .unwrap();
            assert!(ta.dial("native-empty-membership", &env, None).is_err());
            // The responder closes its queue before invoking this hook, so
            // dial can return its refusal while the callback is still queued
            // on the responder thread.
            let deadline = Instant::now() + Duration::from_secs(3);
            while failures.lock().unwrap().is_empty() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            tb.close();
        }
        assert!(!accepted.load(Ordering::Acquire));
        assert_eq!(
            failures.lock().unwrap().as_slice(),
            &[("not_member".to_owned(), Some(fa))],
            "missing or wrong responder rejection hook for tcp={tcp}"
        );
    }
}

#[test]
fn inprocess_refusal_can_return_before_responder_hook_finishes() {
    use std::sync::mpsc;

    let a = DeviceKey::generate();
    let b = DeviceKey::generate();
    let fa = a.fingerprint().unwrap();
    let env = commit::new_env_id(&fa).unwrap();
    let empty: MembershipCheck = Arc::new(|_, _| None);
    let ta = Arc::new(InProcessTransport::new(a, empty.clone()));
    let tb = InProcessTransport::new(b, empty);
    let (hook_started_tx, hook_started_rx) = mpsc::channel();
    let (hook_release_tx, hook_release_rx) = mpsc::channel();
    let hook_release_rx = Mutex::new(hook_release_rx);
    let (hook_completed_tx, hook_completed_rx) = mpsc::channel();
    tb.set_handshake_failed(Some(Arc::new(move |reason, fp| {
        let _ = hook_started_tx.send(());
        let released = hook_release_rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(10))
            .is_ok();
        let _ = hook_completed_tx.send((released, reason.to_owned(), fp.map(str::to_owned)));
    })));
    let accepted = Arc::new(AtomicBool::new(false));
    let accepted_cb = accepted.clone();
    tb.listen(
        "native-empty-membership-hook-channel",
        Arc::new(move |_| accepted_cb.store(true, Ordering::Release)),
    )
    .unwrap();
    let (dial_tx, dial_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let refused = ta
            .dial("native-empty-membership-hook-channel", &env, None)
            .is_err();
        let _ = dial_tx.send(refused);
    });
    let dial_result = dial_rx.recv_timeout(Duration::from_secs(3));
    let hook_started = hook_started_rx.recv_timeout(Duration::from_secs(3));
    let completion_before_release = hook_completed_rx.try_recv();
    // Release even when an assertion is about to fail: no diagnostic thread
    // should be left waiting for a main-thread barrier or an unbounded join.
    let _ = hook_release_tx.send(());
    assert!(
        dial_result.expect("in-process dial did not finish within 3 seconds"),
        "empty membership must refuse the handshake before hook completion"
    );
    hook_started.expect("responder hook did not start within 3 seconds");
    assert!(matches!(
        completion_before_release,
        Err(mpsc::TryRecvError::Empty)
    ));
    assert!(!accepted.load(Ordering::Acquire));
    let (released, reason, fingerprint) = hook_completed_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("responder hook did not complete within 3 seconds");
    assert!(released, "responder hook timed out before release");
    assert_eq!((reason, fingerprint), ("not_member".to_owned(), Some(fa)));
    tb.close();
}

fn wire_case() {
    let a = DeviceKey::generate();
    let b = DeviceKey::generate();
    let ar = a.record().unwrap();
    let br = b.record().unwrap();
    let env = commit::new_env_id(&a.fingerprint().unwrap()).unwrap();
    let dek = *b"synthetic-dek-0123456789-ABCDEF!";
    let secret = b"synthetic-wire-capture-secret-0123456789";
    let ct = envelope::encrypt_secret(&dek, &env, "gh-token", "0011223344556677", secret).unwrap();
    let wrap = envelope::wrap_dek(&dek, &env, "0000000000000000", &br).unwrap();
    let member_a: MembershipCheck =
        Arc::new(move |_, fp| (fp == br.fingerprint()).then(|| br.clone()));
    let member_b: MembershipCheck =
        Arc::new(move |_, fp| (fp == ar.fingerprint()).then(|| ar.clone()));
    let ta = TcpTransport::new(a, member_a, 4);
    let tb = TcpTransport::new(b, member_b, 4);
    let (tx, rx) = std::sync::mpsc::channel();
    tb.listen_arc(
        "127.0.0.1:0",
        Arc::new(move |s| {
            tx.send(s).unwrap();
        }),
    )
    .unwrap();
    let outbound = ta
        .dial_session(&tb.bound_address().unwrap(), &env, None)
        .unwrap();
    let inbound = rx.recv_timeout(Duration::from_secs(3)).unwrap();
    outbound
        .send(&json!({"type":"COMMIT","payload":{"ciphertext":ct,"wrap":wrap}}))
        .unwrap();
    assert_eq!(
        inbound.recv(Duration::from_secs(3)).unwrap().unwrap()["type"],
        "COMMIT"
    );
    inbound
        .send(&json!({"type":"VECTOR","vector":{"synthetic":1}}))
        .unwrap();
    assert_eq!(
        outbound.recv(Duration::from_secs(3)).unwrap().unwrap()["type"],
        "VECTOR"
    );
    outbound.close();
    inbound.close();
    ta.shutdown();
    tb.shutdown();
}

#[test]
fn actual_tcp_capture_contains_neither_secret_nor_unwrapped_dek() {
    if std::env::var_os("ZEROPW_TEAM_WIRE_CAPTURE_CHILD").is_some() {
        wire_case();
        return;
    }
    let root = TempDir::new().unwrap();
    let capture = root.path().join("wire.hex");
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "actual_tcp_capture_contains_neither_secret_nor_unwrapped_dek",
            "--nocapture",
        ])
        .env("ZEROPW_TEAM_WIRE_CAPTURE_CHILD", "1")
        .env("ZEROPW_TEAM_WIRE_CAPTURE", &capture)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child TCP run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let frames: Vec<Vec<u8>> = fs::read_to_string(&capture)
        .unwrap()
        .lines()
        .map(|line| hex::decode(line.split_once(' ').unwrap().1).unwrap())
        .collect();
    assert!(!frames.is_empty(), "capture must contain real TCP frames");
    let joined: Vec<u8> = frames.concat();
    for (label, needle) in [
        (
            "vault value",
            b"synthetic-wire-capture-secret-0123456789".as_slice(),
        ),
        (
            "unwrapped DEK",
            b"synthetic-dek-0123456789-ABCDEF!".as_slice(),
        ),
    ] {
        assert!(
            !joined.windows(needle.len()).any(|w| w == needle),
            "{label} appeared in captured TCP bytes"
        );
        let encoded = hex::encode(needle);
        assert!(
            !joined
                .windows(encoded.len())
                .any(|w| w == encoded.as_bytes()),
            "hex {label} appeared in captured TCP bytes"
        );
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(needle);
        assert!(
            !joined
                .windows(encoded.len())
                .any(|w| w == encoded.as_bytes()),
            "base64 {label} appeared in captured TCP bytes"
        );
    }
}

#[test]
fn full_team_sync_tcp_wire_uses_original_encoding_leak_scanner() {
    // Capture at an independent TCP relay, not the transport's concurrent
    // debug-file hook (whose writes can interleave under two sync threads).
    let f = RemoteFixture::new_with_relay(connection_create("gh"), "api_key", SECRET, json!({}));
    let next = commit::sign_commit(
        &f.ka,
        &f.env,
        4,
        "4000-0000",
        &BTreeMap::new(),
        vec![connection_create("gh-new")],
    )
    .unwrap();
    assert_eq!(f.sa.submit_commit(&f.env, &next).unwrap(), "accepted");
    f.wait(|| {
        f.sb.document(&f.env).unwrap()["connections"]
            .get("gh-new")
            .is_some()
    });
    std::thread::sleep(Duration::from_millis(200));
    let streams = f.relay.as_ref().unwrap().captured.lock().unwrap().clone();
    assert!(
        streams.iter().all(|stream| !stream.is_empty()),
        "both real TCP directions must be captured"
    );
    assert!(
        streams.iter().any(|stream| stream.len() > 500),
        "capture must include more than an empty handshake"
    );
    let needles: [&[u8]; 2] = [b"synthetic-team-share-secret-0123456789", &[7u8; 32]];
    let joined = streams.concat();
    for stream in streams.iter().chain(std::iter::once(&joined)) {
        assert_eq!(
            find_secret(stream, &needles),
            None,
            "leak scanner found a captured encoding"
        );
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Port of the retired Python test helper `tests/leakcheck.py::find_secret`:
/// where (which encoding) one of `secrets` occurs in `data`, or `None`.
/// Looks for every pattern `runs::credential_patterns` derives (raw,
/// standard/urlsafe base64 at every alignment with and without padding, hex
/// in both cases, percent-encoding), then decodes percent-encoded, base64
/// and hex tokens found in the data and searches the decoded bytes for any
/// secret of at least 16 bytes. Only a description is returned, never the
/// value.
fn find_secret(data: &[u8], secrets: &[&[u8]]) -> Option<String> {
    for (index, secret) in secrets.iter().enumerate() {
        for pattern in zeropw::runs::credential_patterns(secret) {
            if contains(data, &pattern) {
                return Some(format!("secret #{index} in a directly scanned encoding"));
            }
        }
    }
    let raw: Vec<(usize, &[u8])> = secrets
        .iter()
        .enumerate()
        .filter(|(_, secret)| secret.len() >= 16)
        .map(|(index, secret)| (index, *secret))
        .collect();
    if raw.is_empty() {
        return None;
    }
    let decoded_hit = |decoded: &[u8], how: &str| {
        raw.iter()
            .find(|(_, secret)| contains(decoded, secret))
            .map(|(index, _)| format!("secret #{index} inside decoded {how}"))
    };
    // `urllib.parse.unquote_to_bytes(blob.replace(b"+", b" "))`
    let plus: Vec<u8> = data
        .iter()
        .map(|&b| if b == b'+' { b' ' } else { b })
        .collect();
    let unquoted: Vec<u8> = percent_encoding::percent_decode(&plus).collect();
    if unquoted != data
        && let Some(hit) = decoded_hit(&unquoted, "percent-encoding")
    {
        return Some(hit);
    }
    let base64_token = regex::bytes::Regex::new(r"[A-Za-z0-9+/_-]{16,}={0,2}").unwrap();
    for token in base64_token.find_iter(data) {
        let body = token.as_bytes();
        let end = body.iter().rposition(|&b| b != b'=').map_or(0, |i| i + 1);
        let body = &body[..end];
        // The token may start in the middle of an encoded group.
        for offset in 0..4 {
            let Some(chunk) = body.get(offset..) else {
                break;
            };
            if chunk.len() < 8 {
                break;
            }
            let mut padded = chunk.to_vec();
            padded.resize(chunk.len().div_ceil(4) * 4, b'=');
            for decoded in [
                zeropw::pybase64::b64decode_bytes(&padded),
                zeropw::pybase64::urlsafe_b64decode_bytes(&padded),
            ]
            .into_iter()
            .flatten()
            {
                if let Some(hit) = decoded_hit(&decoded, "base64") {
                    return Some(hit);
                }
            }
        }
    }
    let hex_token = regex::bytes::Regex::new(r"[0-9A-Fa-f]{16,}").unwrap();
    for token in hex_token.find_iter(data) {
        for offset in 0..2 {
            let chunk = &token.as_bytes()[offset..];
            let chunk = &chunk[..chunk.len() - chunk.len() % 2];
            if let Ok(decoded) = hex::decode(chunk)
                && let Some(hit) = decoded_hit(&decoded, "hex")
            {
                return Some(hit);
            }
        }
    }
    None
}

#[test]
fn leak_scanner_finds_encoded_and_embedded_secrets() {
    let secret: &[u8] = b"synthetic-team-share-secret-0123456789";
    let needles = [secret];
    assert_eq!(find_secret(b"nothing to see here", &needles), None);
    let mut shifted = b"x".to_vec();
    shifted.extend_from_slice(secret);
    for data in [
        secret.to_vec(),
        format!("prefix {} suffix", zeropw::pybase64::b64encode(secret)).into_bytes(),
        format!("[{}]", zeropw::pybase64::b64encode(&shifted)).into_bytes(),
        hex::encode_upper(secret).into_bytes(),
        format!("k={}", hex::encode(&shifted)).into_bytes(),
        percent_encoding::percent_encode(secret, percent_encoding::NON_ALPHANUMERIC)
            .to_string()
            .into_bytes(),
    ] {
        assert!(
            find_secret(&data, &needles).is_some(),
            "{}",
            String::from_utf8_lossy(&data)
        );
    }
}

fn reserve_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn native_serve(team: bool) {
    let root = TempDir::new().unwrap();
    let ctx = context(&root);
    let state = ctx.state.path.to_path_buf();
    drop(ctx);
    let port = reserve_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_zeropw-admin"))
        .args([
            "--state-dir",
            state.to_str().unwrap(),
            "serve",
            "--listen",
            "127.0.0.1:0",
        ])
        .args(if team {
            vec!["--team-listen".to_string(), format!("127.0.0.1:{port}")]
        } else {
            vec![]
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let line = BufReader::new(child.stdout.take().unwrap())
        .lines()
        .next()
        .unwrap()
        .unwrap();
    let startup: Value = serde_json::from_str(&line).unwrap();
    if team {
        assert_eq!(startup["team_listen"], format!("127.0.0.1:{port}"));
        TcpStream::connect(("127.0.0.1", port))
            .expect("native serve did not open team TCP listener");
    } else {
        assert!(startup["team_listen"].is_null());
        assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    }
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn native_serve_with_team_listen_accepts_tcp() {
    native_serve(true);
}

#[test]
fn native_serve_without_team_listen_does_not_start_team_tcp() {
    native_serve(false);
}

fn api(port: u16, token: &str, name: &str, payload: Value) -> Value {
    let body = payload.to_string();
    let request = format!(
        "POST /v1/tools/{name} HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    socket.read_to_end(&mut response).unwrap();
    let text = String::from_utf8(response).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "native serve returned {head}: {body}"
    );
    serde_json::from_str(body).unwrap()
}

struct ServeGuard {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<zeropw::errors::Result<Value>>>,
}
impl Drop for ServeGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap().unwrap();
        }
    }
}

struct RemoteFixture {
    _root: TempDir,
    b: Arc<Context>,
    ka: DeviceKey,
    env: String,
    sa: Arc<TeamSync>,
    sb: Arc<TeamSync>,
    ta: Arc<TcpTransport>,
    tb: Arc<TcpTransport>,
    relay: Option<TcpRelay>,
}

struct TcpRelay {
    address: String,
    captured: Arc<Mutex<[Vec<u8>; 2]>>,
    stop: Arc<AtomicBool>,
    accept: Option<std::thread::JoinHandle<()>>,
    forwarders: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
}

impl TcpRelay {
    fn new(target: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let captured = Arc::new(Mutex::new([Vec::new(), Vec::new()]));
        let stop = Arc::new(AtomicBool::new(false));
        let forwarders = Arc::new(Mutex::new(Vec::new()));
        let (cap, signal, workers) = (captured.clone(), stop.clone(), forwarders.clone());
        let accept = std::thread::spawn(move || {
            while !signal.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((client, _)) => {
                        client.set_nonblocking(false).unwrap();
                        let server = TcpStream::connect(&target).unwrap();
                        for (from, to, direction) in [
                            (client.try_clone().unwrap(), server.try_clone().unwrap(), 0),
                            (server, client, 1),
                        ] {
                            let capture = cap.clone();
                            workers.lock().unwrap().push(std::thread::spawn(move || {
                                let mut from = from;
                                let mut to = to;
                                let mut buffer = [0u8; 16384];
                                while let Ok(n) = from.read(&mut buffer) {
                                    if n == 0 {
                                        break;
                                    }
                                    capture.lock().unwrap()[direction]
                                        .extend_from_slice(&buffer[..n]);
                                    if to.write_all(&buffer[..n]).is_err() {
                                        break;
                                    }
                                }
                                let _ = to.shutdown(Shutdown::Write);
                            }));
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            captured,
            stop,
            accept: Some(accept),
            forwarders,
        }
    }
}

impl Drop for TcpRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.accept.take() {
            handle.join().unwrap();
        }
        for handle in self.forwarders.lock().unwrap().drain(..) {
            handle.join().unwrap();
        }
    }
}

impl RemoteFixture {
    fn new(connection_op: Value, secret_kind: &str, secret_value: &[u8], public: Value) -> Self {
        Self::build(connection_op, secret_kind, secret_value, public, false)
    }

    fn new_with_relay(
        connection_op: Value,
        secret_kind: &str,
        secret_value: &[u8],
        public: Value,
    ) -> Self {
        Self::build(connection_op, secret_kind, secret_value, public, true)
    }

    fn build(
        mut connection_op: Value,
        secret_kind: &str,
        secret_value: &[u8],
        public: Value,
        capture: bool,
    ) -> Self {
        let root = TempDir::new().unwrap();
        fs::create_dir(root.path().join("runs")).unwrap();
        if connection_op["cli"]["program"] == "__SYNTHETIC_SLEEP_CLI__" {
            let script = root.path().join("synthetic-ssh-cli");
            fs::write(&script, b"#!/bin/sh\nfor arg in \"$@\"; do marker=$arg; done\nprintf '%s' \"$SSH_AUTH_SOCK\" > \"$marker.tmp\"\nmv \"$marker.tmp\" \"$marker\"\nsleep 30\n").unwrap();
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
            connection_op["cli"]["program"] = json!(script.to_string_lossy());
        }
        let cfg = Config {
            team_sync_interval_seconds: Some(0.1),
            team_dial_backoff: (0.05, 0.2),
            run_dir: Some(root.path().join("runs")),
            ..Config::default()
        };
        let make = |name: &str| {
            Arc::new(
                Context::initialize(
                    root.path().join(name),
                    "synthetic-admin-pass",
                    "synthetic-recovery-pass",
                    cfg.clone(),
                    clock::system(),
                )
                .unwrap(),
            )
        };
        let a = make("a");
        let b = make("b");
        let ka = DeviceKey::load_or_create(a.state, a.kms).unwrap();
        let kb = DeviceKey::load_or_create(b.state, b.kms).unwrap();
        let fa = ka.fingerprint().unwrap();
        let fb = kb.fingerprint().unwrap();
        let env = commit::new_env_id(&fa).unwrap();
        let generation = "0000000000000000";
        let dek = [7u8; 32];
        let mut wraps = serde_json::Map::new();
        wraps.insert(
            fa.clone(),
            json!(envelope::wrap_dek(&dek, &env, generation, &ka.record().unwrap()).unwrap()),
        );
        wraps.insert(
            fb.clone(),
            json!(envelope::wrap_dek(&dek, &env, generation, &kb.record().unwrap()).unwrap()),
        );
        let ct =
            envelope::encrypt_secret(&dek, &env, "key", "0011223344556677", secret_value).unwrap();
        let signed = |seq, hlc: &str, ops| {
            commit::sign_commit(&ka, &env, seq, hlc, &BTreeMap::new(), ops).unwrap()
        };
        let c1 = signed(
            1,
            "1000-0000",
            vec![
                json!({"op":"env.init","owner_device":ka.record().unwrap().to_dict(),"owner_name":"alice","generation_id":generation,"wraps":wraps}),
                json!({"op":"secret.put_version","secret_id":"key","kind":secret_kind,"generation_id":generation,"version_id":"0011223344556677","ciphertext":ct,"public":public}),
                json!({"op":"secret.activate","secret_id":"key","version_id":"0011223344556677"}),
            ],
        );
        let c2 = signed(
            2,
            "2000-0000",
            vec![
                json!({"op":"member.add","device":kb.record().unwrap().to_dict(),"name":"bob","role":"admin"}),
            ],
        );
        let c3 = signed(3, "3000-0000", vec![connection_op]);
        for ctx in [&a, &b] {
            let store = CommitStore::new(ctx.state, &env);
            for c in [&c1, &c2, &c3] {
                store.append(c).unwrap();
            }
        }
        let empty: MembershipCheck = Arc::new(|_, _| None);
        let ta = TcpTransport::new(ka.clone(), empty.clone(), 4);
        let tb = TcpTransport::new(kb.clone(), empty, 4);
        let sa = TeamSync::new(a.clone(), Arc::new(ta.clone()), ka.clone());
        let sb = TeamSync::new(b.clone(), Arc::new(tb.clone()), kb);
        sa.start(if capture { None } else { Some("127.0.0.1:0") })
            .unwrap();
        sb.start(Some("127.0.0.1:0")).unwrap();
        let relay = capture.then(|| TcpRelay::new(tb.bound_address().unwrap()));
        let peer_address = relay
            .as_ref()
            .map_or_else(|| tb.bound_address().unwrap(), |r| r.address.clone());
        sa.set_peer_address(&env, &fb, &peer_address).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if sa.status(&env).unwrap()["sessions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == &fb)
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            sa.status(&env).unwrap()["sessions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == &fb),
            "real remote TCP session never formed"
        );
        Self {
            _root: root,
            b,
            ka,
            env,
            sa,
            sb,
            ta,
            tb,
            relay,
        }
    }

    fn wait(&self, mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if condition() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("remote live runtime condition did not occur");
    }

    fn wait_stage(&self, stage: &str, mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if condition() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!(
            "remote signer stage {stage} did not occur; A sessions={:?}; B connection={:?}",
            self.sa.status(&self.env).unwrap()["sessions"],
            self.b.policy.get_connection("box").map(|c| c.status)
        );
    }
}

impl Drop for RemoteFixture {
    fn drop(&mut self) {
        self.sa.stop();
        self.sb.stop();
        self.ta.shutdown();
        self.tb.shutdown();
        self.relay.take();
    }
}

#[test]
fn user_member_cannot_publish_connection_disabled_fact_to_live_team() {
    let f = RemoteFixture::new(connection_create("gh"), "api_key", SECRET, json!({}));
    let c = Arc::new(
        Context::initialize(
            f._root.path().join("c"),
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
    let kc = DeviceKey::load_or_create(c.state, c.kms).unwrap();
    let fc = kc.fingerprint().unwrap();
    let add = commit::sign_commit(&f.ka, &f.env, 4, "4000-0000", &BTreeMap::new(), vec![json!({"op":"member.add","device":kc.record().unwrap().to_dict(),"name":"eve","role":"user"})]).unwrap();
    assert_eq!(f.sa.submit_commit(&f.env, &add).unwrap(), "accepted");
    f.wait(|| {
        CommitStore::new(f.b.state, &f.env)
            .last_seq(&f.ka.fingerprint().unwrap())
            .unwrap()
            >= 4
    });
    for item in CommitStore::new(f.sa.ctx.state, &f.env)
        .all_commits()
        .unwrap()
    {
        CommitStore::new(c.state, &f.env).append(&item).unwrap();
    }
    let tc = TcpTransport::new(kc.clone(), Arc::new(|_, _| None), 4);
    let sc = TeamSync::new(c, Arc::new(tc.clone()), kc);
    sc.start(Some("127.0.0.1:0")).unwrap();
    struct Stop(Arc<TeamSync>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.stop();
        }
    }
    let _stop = Stop(sc.clone());
    sc.set_peer_address(
        &f.env,
        &f.ka.fingerprint().unwrap(),
        &f.ta.bound_address().unwrap(),
    )
    .unwrap();
    f.wait(|| {
        sc.status(&f.env).unwrap()["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == &f.ka.fingerprint().unwrap())
    });
    let before =
        f.sa.ctx
            .state
            .read_lines(&format!("team/{}/facts.jsonl", f.env), None)
            .unwrap();
    let err = sc
        .publish_fact(&f.env, "connection_disabled", json!({"connection_id":"gh"}))
        .unwrap_err();
    assert_eq!(err.name, "PolicyDenied");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        f.sa.ctx
            .state
            .read_lines(&format!("team/{}/facts.jsonl", f.env), None)
            .unwrap(),
        before
    );
    assert!(
        f.sa.document(&f.env).unwrap()["connections"]
            .get("gh")
            .is_some()
    );
    assert!(f.sa.is_active_member(&f.env, &fc));
}

#[test]
fn removed_member_session_drains_then_fresh_tcp_dial_is_refused() {
    let f = RemoteFixture::new(connection_create("gh"), "api_key", SECRET, json!({}));
    let fb = f.sb.device.fingerprint().unwrap();
    f.sa.publish_fact(&f.env, "member_removed", json!({"fingerprint":fb}))
        .unwrap();
    f.wait(|| !f.sa.is_active_member(&f.env, &fb));
    f.wait(|| {
        !f.sa.status(&f.env).unwrap()["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == &fb)
    });
    let dial =
        f.tb.dial_session(&f.ta.bound_address().unwrap(), &f.env, None);
    match dial {
        Err(_) => {}
        Ok(session) => {
            let received = session.recv(Duration::from_secs(2));
            session.close();
            assert!(
                received.is_err(),
                "removed member's fresh dial remained usable"
            );
        }
    }
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !f.sa.status(&f.env).unwrap()["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == &fb)
    );
}

#[test]
fn removed_member_keeps_old_version_but_cannot_get_new_generation_version() {
    let f = RemoteFixture::new(connection_create("gh"), "api_key", SECRET, json!({}));
    let fb = f.sb.device.fingerprint().unwrap();
    let old_generation = f.sa.document(&f.env).unwrap()["dek"]["current"]
        .as_str()
        .unwrap()
        .to_owned();
    let removal = membership::remove_member(&f.sa.ctx, Some(&f.sa), &f.env, &fb).unwrap();
    assert_eq!(removal["dek_rotated"], true);
    let new_generation = removal["new_generation"].as_str().unwrap();
    assert_ne!(old_generation, new_generation);
    f.wait(|| {
        !f.sa.status(&f.env).unwrap()["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == &fb)
    });
    assert_eq!(
        f.b.vault
            .secret_for_trusted_use("key", None)
            .unwrap()
            .expose(),
        SECRET
    );
    let wrapped_new =
        f.sa.ctx
            .state
            .read_json(
                &format!("team/{}/dek/{new_generation}.json", f.env),
                Value::Null,
            )
            .unwrap();
    let new_dek =
        f.sa.ctx
            .kms
            .unwrap(&zeropw::kms::WrappedKey::from_dict(&wrapped_new).unwrap())
            .unwrap();
    let version_id = "deadbeefcafef00d";
    let ciphertext = envelope::encrypt_secret(
        new_dek.expose(),
        &f.env,
        "key",
        version_id,
        b"synthetic-new-version-after-removal",
    )
    .unwrap();
    membership::author_commit(&f.sa.ctx, Some(&f.sa), &f.env, vec![json!({"op":"secret.put_version","secret_id":"key","kind":"api_key","generation_id":new_generation,"version_id":version_id,"ciphertext":ciphertext,"public":{}})]).unwrap();
    let wrapped_old =
        f.b.state
            .read_json(
                &format!("team/{}/dek/{old_generation}.json", f.env),
                Value::Null,
            )
            .unwrap();
    let old_dek =
        f.b.kms
            .unwrap(&zeropw::kms::WrappedKey::from_dict(&wrapped_old).unwrap())
            .unwrap();
    assert!(
        envelope::decrypt_secret(old_dek.expose(), &f.env, "key", version_id, &ciphertext).is_err()
    );
    assert!(
        !f.b.state
            .exists(&format!("team/{}/dek/{new_generation}.json", f.env))
    );
    assert_eq!(
        f.b.vault
            .get_meta("key")
            .unwrap()
            .versions
            .iter()
            .map(|v| v.version.clone())
            .collect::<Vec<_>>(),
        vec![zeropw::pyint::PyInt::from(1_i64)]
    );
}

#[test]
fn remote_widening_commit_cancels_existing_http_run_with_grant_stale() {
    let op = json!({"op":"connection.create","id":"gh","project":"demo","environment":"dev","service":"synthetic","kind":"http","secret_id":"key","secret_version":null,"description":"","http_target":{"scheme":"http","host":"127.0.0.1","port":8080},"http_auth":{"mode":"bearer"},"http_scope":{"methods":["GET"],"path_prefixes":["/repos"]},"cli":{"program":"/bin/sh","kind":"http"}});
    let f = RemoteFixture::new(
        op,
        "api_key",
        b"synthetic-http-secret-0123456789",
        json!({}),
    );
    let token = f.b.policy.create_principal("agent-1", "default").unwrap();
    let grant =
        f.b.policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
    let team_addr = f.tb.bound_address().unwrap();
    f.sb.stop();
    f.tb.shutdown();
    let api_port = reserve_port();
    let stop = Arc::new(AtomicBool::new(false));
    let (state, stop_thread, listen, team_listen) = (
        f.b.state.path.to_string_lossy().to_string(),
        stop.clone(),
        format!("127.0.0.1:{api_port}"),
        team_addr.clone(),
    );
    let thread = std::thread::spawn(move || {
        zeropw::admin_cli::run_serve(&state, &listen, true, Some(&team_listen), stop_thread)
    });
    let _serve = ServeGuard {
        stop,
        thread: Some(thread),
    };
    f.wait(|| TcpStream::connect(("127.0.0.1", api_port)).is_ok());
    f.wait(|| {
        f.sa.status(&f.env).unwrap()["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == &f.sb.device.fingerprint().unwrap())
    });
    let view = api(
        api_port,
        &token,
        "exec",
        json!({"connection":"gh","argv":["-c","sleep 30"]}),
    );
    let run_id = view["run_id"].as_str().unwrap();
    f.wait(|| api(api_port, &token, "status", json!({"run_id":run_id}))["state"] == "running");
    let widen = commit::sign_commit(&f.ka, &f.env, 4, "4000-0000", &BTreeMap::new(), vec![json!({"op":"connection.update","id":"gh","http_scope":{"methods":null,"path_prefixes":null}})]).unwrap();
    assert_eq!(f.sa.submit_commit(&f.env, &widen).unwrap(), "accepted");
    f.wait(|| {
        CommitStore::new(f.b.state, &f.env)
            .last_seq(&f.ka.fingerprint().unwrap())
            .unwrap()
            >= 4
    });
    f.wait(|| api(api_port, &token, "status", json!({"run_id":run_id}))["state"] == "cancelled");
    let final_run = api(api_port, &token, "status", json!({"run_id":run_id}));
    assert_eq!(final_run["reason"], "grant_stale");
    assert_eq!(
        f.b.policy
            .list_grants(None)
            .unwrap()
            .iter()
            .find(|g| g.id == grant.id)
            .unwrap()
            .status,
        "stale"
    );
}

#[test]
fn remote_connection_disabled_fact_closes_existing_signer_socket() {
    let user_key = zeropw::sshwire::generate_ed25519_private_key("synthetic-user");
    let host_key = zeropw::sshwire::generate_ed25519_private_key("synthetic-host");
    let host_line = host_key.public.to_authorized_key("synthetic-host").unwrap();
    let op = json!({"op":"connection.create","id":"box","project":"demo","environment":"dev","service":"synthetic","kind":"ssh","secret_id":"key","secret_version":null,"description":"","ssh_target":{"host":"127.0.0.1","port":2222,"username":"deploy","host_keys":[host_line]},"cli":{"program":"__SYNTHETIC_SLEEP_CLI__","kind":"ssh"}});
    let public = json!({"public_key":user_key.public.to_authorized_key("synthetic-user").unwrap()});
    let f = RemoteFixture::new(
        op,
        "ssh_private_key",
        user_key.to_openssh_private_key().as_bytes(),
        public,
    );
    let token = f.b.policy.create_principal("agent-2", "default").unwrap();
    f.b.policy
        .create_grant("agent-2", "box", Some(3600), None)
        .unwrap();
    let team_addr = f.tb.bound_address().unwrap();
    f.sb.stop();
    f.tb.shutdown();
    let api_port = reserve_port();
    let stop = Arc::new(AtomicBool::new(false));
    let (state, stop_thread, listen) = (
        f.b.state.path.to_string_lossy().to_string(),
        stop.clone(),
        format!("127.0.0.1:{api_port}"),
    );
    let thread = std::thread::spawn(move || {
        zeropw::admin_cli::run_serve(&state, &listen, true, Some(&team_addr), stop_thread)
    });
    let _serve = ServeGuard {
        stop,
        thread: Some(thread),
    };
    f.wait_stage("serve-http-ready", || {
        TcpStream::connect(("127.0.0.1", api_port)).is_ok()
    });
    let marker = f._root.path().join("socket-marker");
    let view = api(
        api_port,
        &token,
        "exec",
        json!({"connection":"box","argv":[marker.to_string_lossy()]}),
    );
    let run_id = view["run_id"].as_str().unwrap();
    f.wait_stage("signer-child-marker", || marker.exists());
    let marker_content = fs::read_to_string(&marker).unwrap();
    let socket_path = std::path::PathBuf::from(&marker_content);
    if !socket_path.exists() {
        // Synthetic child output only; capture the actual run outcome if the
        // marker was written but the signer socket is already absent.
        let status =
            std::panic::catch_unwind(|| api(api_port, &token, "status", json!({"run_id":run_id})));
        panic!(
            "real signer socket never opened; marker_length={}; path={socket_path:?}; exec={view}; status={status:?}",
            marker_content.len()
        );
    }
    // `serve` HTTP readiness does not prove its replacement team session is
    // established. This case tests live FACT delivery over a confirmed new
    // session; the separate offline case covers FACT replay. A fresh harmless
    // commit reaching B proves this is not A's stale peer status.
    let a_fp = f.ka.fingerprint().unwrap();
    let b_fp = DeviceKey::load_or_create(f.b.state, f.b.kms)
        .unwrap()
        .fingerprint()
        .unwrap();
    let barrier = commit::sign_commit(
        &f.ka,
        &f.env,
        4,
        "4000-0000",
        &BTreeMap::new(),
        vec![json!({"op":"member.set_role","fingerprint":b_fp,"role":"admin"})],
    )
    .unwrap();
    assert_eq!(f.sa.submit_commit(&f.env, &barrier).unwrap(), "accepted");
    f.wait_stage("replacement-team-session-commit-delivered", || {
        CommitStore::new(f.b.state, &f.env).last_seq(&a_fp).unwrap() >= 4
    });
    assert!(
        socket_path.exists(),
        "signer socket closed before remote FACT"
    );
    f.sa.publish_fact(
        &f.env,
        "connection_disabled",
        json!({"connection_id":"box"}),
    )
    .unwrap();
    f.wait_stage("remote-fact-applied", || {
        f.b.policy.get_connection("box").unwrap().status == "disabled"
    });
    f.wait_stage("signer-socket-removed-and-run-cancelled", || {
        !socket_path.exists()
            && api(api_port, &token, "status", json!({"run_id":run_id}))["state"] == "cancelled"
    });
    assert!(!socket_path.exists());
    assert_eq!(
        api(api_port, &token, "status", json!({"run_id":run_id}))["state"],
        "cancelled"
    );
    assert_eq!(f.b.policy.get_connection("box").unwrap().status, "disabled");
}

#[test]
fn offline_fact_reconnect_cancels_live_native_signer_and_run() {
    let user_key = zeropw::sshwire::generate_ed25519_private_key("synthetic-user");
    let host_key = zeropw::sshwire::generate_ed25519_private_key("synthetic-host");
    let host_line = host_key.public.to_authorized_key("synthetic-host").unwrap();
    let op = json!({"op":"connection.create","id":"box","project":"demo","environment":"dev","service":"synthetic","kind":"ssh","secret_id":"key","secret_version":null,"description":"","ssh_target":{"host":"127.0.0.1","port":2222,"username":"deploy","host_keys":[host_line]},"cli":{"program":"__SYNTHETIC_SLEEP_CLI__","kind":"ssh"}});
    let public = json!({"public_key":user_key.public.to_authorized_key("synthetic-user").unwrap()});
    let f = RemoteFixture::new(
        op,
        "ssh_private_key",
        user_key.to_openssh_private_key().as_bytes(),
        public,
    );
    let token =
        f.b.policy
            .create_principal("agent-offline", "default")
            .unwrap();
    f.b.policy
        .create_grant("agent-offline", "box", Some(3600), None)
        .unwrap();
    let team_addr = f.tb.bound_address().unwrap();
    f.sb.stop();
    f.tb.shutdown();
    let api_port = reserve_port();
    let stop = Arc::new(AtomicBool::new(false));
    let (state, stop_thread, listen) = (
        f.b.state.path.to_string_lossy().to_string(),
        stop.clone(),
        format!("127.0.0.1:{api_port}"),
    );
    let team_listen = team_addr.clone();
    let thread = std::thread::spawn(move || {
        zeropw::admin_cli::run_serve(&state, &listen, true, Some(&team_listen), stop_thread)
    });
    let _serve = ServeGuard {
        stop,
        thread: Some(thread),
    };
    f.wait_stage("offline-serve-http-ready", || {
        TcpStream::connect(("127.0.0.1", api_port)).is_ok()
    });
    let a_fp = f.ka.fingerprint().unwrap();
    let b_fp = DeviceKey::load_or_create(f.b.state, f.b.kms)
        .unwrap()
        .fingerprint()
        .unwrap();
    let barrier = commit::sign_commit(
        &f.ka,
        &f.env,
        4,
        "4000-0000",
        &BTreeMap::new(),
        vec![json!({"op":"member.set_role","fingerprint":b_fp,"role":"admin"})],
    )
    .unwrap();
    assert_eq!(f.sa.submit_commit(&f.env, &barrier).unwrap(), "accepted");
    f.wait_stage("offline-serve-session-ready", || {
        CommitStore::new(f.b.state, &f.env).last_seq(&a_fp).unwrap() >= 4
    });
    let marker = f._root.path().join("offline-socket-marker");
    let view = api(
        api_port,
        &token,
        "exec",
        json!({"connection":"box","argv":[marker.to_string_lossy()]}),
    );
    let run_id = view["run_id"].as_str().unwrap();
    f.wait_stage("offline-signer-child-marker", || marker.exists());
    let socket_path = std::path::PathBuf::from(fs::read_to_string(&marker).unwrap());
    assert!(socket_path.exists(), "live signer socket was not created");
    f.wait_stage("offline-run-running", || {
        api(api_port, &token, "status", json!({"run_id":run_id}))["state"] == "running"
    });

    f.sa.stop();
    f.ta.shutdown();
    f.sa.publish_fact(
        &f.env,
        "connection_disabled",
        json!({"connection_id":"box"}),
    )
    .unwrap();
    assert_eq!(f.b.policy.get_connection("box").unwrap().status, "active");
    assert!(
        socket_path.exists(),
        "offline publication closed remote socket"
    );
    assert_eq!(
        api(api_port, &token, "status", json!({"run_id":run_id}))["state"],
        "running"
    );
    let empty: MembershipCheck = Arc::new(|_, _| None);
    let ta2 = TcpTransport::new(f.ka.clone(), empty, 4);
    let sa2 = TeamSync::new(f.sa.ctx.clone(), Arc::new(ta2.clone()), f.ka.clone());
    sa2.start(None).unwrap();
    struct StopSource(Arc<TeamSync>, Arc<TcpTransport>);
    impl Drop for StopSource {
        fn drop(&mut self) {
            self.0.stop();
            self.1.shutdown();
        }
    }
    let _source = StopSource(sa2.clone(), ta2);
    sa2.set_peer_address(&f.env, &b_fp, &team_addr).unwrap();
    f.wait_stage("offline-fact-applied-to-native-serve", || {
        f.b.policy.get_connection("box").unwrap().status == "disabled"
    });
    f.wait_stage("offline-signer-socket-removed", || !socket_path.exists());
    f.wait_stage("offline-run-cancelled", || {
        api(api_port, &token, "status", json!({"run_id":run_id}))["state"] == "cancelled"
    });
    assert_eq!(
        f.b.state
            .read_lines(&format!("team/{}/facts.jsonl", f.env), None)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn offline_facts_catch_up_after_sender_restart_in_bounded_batches() {
    let f = RemoteFixture::new(connection_create("gh"), "api_key", SECRET, json!({}));
    let a_fp = f.ka.fingerprint().unwrap();
    let kb = DeviceKey::load_or_create(f.b.state, f.b.kms).unwrap();
    let b_fp = kb.fingerprint().unwrap();
    f.sb.stop();
    f.tb.shutdown();
    let facts_path = format!("team/{}/facts.jsonl", f.env);
    let foreign_env = commit::new_env_id(&a_fp).unwrap();
    // Invalid local ledger entries occupy two whole replay batches. They may
    // not starve the valid tail or be forwarded as ordinary FACTs.
    for index in 0..128 {
        let line = match index % 4 {
            0 => "not-json".to_owned(),
            1 => zeropw::team::sync::sign_fact(
                &f.ka,
                &f.env,
                "incident",
                json!({"incident_id":"0123456789abcdef"}),
                &format!("{}-0000", 5000 + index),
            )
            .unwrap()
            .to_dict()
            .to_string(),
            2 => zeropw::team::sync::sign_fact(
                &f.ka,
                &foreign_env,
                "connection_disabled",
                json!({"connection_id":"gh"}),
                &format!("{}-0000", 5000 + index),
            )
            .unwrap()
            .to_dict()
            .to_string(),
            _ => {
                let mut tampered = zeropw::team::sync::sign_fact(
                    &f.ka,
                    &f.env,
                    "connection_disabled",
                    json!({"connection_id":"gh"}),
                    &format!("{}-0000", 5000 + index),
                )
                .unwrap()
                .to_dict();
                tampered["target"]["connection_id"] = json!("changed-after-signing");
                tampered.to_string()
            }
        };
        f.sa.ctx.state.append_line(&facts_path, &line).unwrap();
    }
    f.sa.publish_fact(&f.env, "connection_disabled", json!({"connection_id":"gh"}))
        .unwrap();
    assert_eq!(f.b.policy.get_connection("gh").unwrap().status, "active");
    f.sa.stop();
    f.ta.shutdown();

    let empty: MembershipCheck = Arc::new(|_, _| None);
    let ta = TcpTransport::new(f.ka.clone(), empty.clone(), 4);
    let sa = TeamSync::new(f.sa.ctx.clone(), Arc::new(ta.clone()), f.ka.clone());
    sa.start(None).unwrap();
    let tb = TcpTransport::new(kb.clone(), empty.clone(), 4);
    let sb = TeamSync::new(f.b.clone(), Arc::new(tb.clone()), kb.clone());
    sb.start(Some("127.0.0.1:0")).unwrap();
    struct StopReplay {
        sa: Arc<TeamSync>,
        sb: Arc<TeamSync>,
        ta: Arc<TcpTransport>,
        tb: Arc<TcpTransport>,
    }
    impl Drop for StopReplay {
        fn drop(&mut self) {
            self.sa.stop();
            self.sb.stop();
            self.ta.shutdown();
            self.tb.shutdown();
        }
    }
    let mut cleanup = StopReplay { sa, sb, ta, tb };
    let address = cleanup.tb.bound_address().unwrap();
    let session = cleanup.ta.dial(&address, &f.env, None).unwrap();
    cleanup.sa.adopt_outbound_session(&f.env, session, &address);
    f.wait_stage("offline-fact-replayed-after-restart", || {
        f.b.policy.get_connection("gh").unwrap().status == "disabled"
    });
    assert_eq!(
        f.b.state.read_lines(&facts_path, None).unwrap().len(),
        1,
        "only the signed same-env non-incident fact may reach B"
    );
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(f.b.state.read_lines(&facts_path, None).unwrap().len(), 1);

    // A second offline fact appears after the cursor has reached EOF. A new
    // authenticated session must replay it, without duplicating the first.
    cleanup.sb.stop();
    cleanup.tb.shutdown();
    let second = cleanup
        .sa
        .publish_fact(
            &f.env,
            "secret_version_revoked",
            json!({"secret_id":"key","version_id":"0011223344556677"}),
        )
        .unwrap();
    assert_eq!(second["kind"], "secret_version_revoked");
    assert_eq!(f.b.state.read_lines(&facts_path, None).unwrap().len(), 1);
    let tb2 = TcpTransport::new(kb.clone(), empty, 4);
    let sb2 = TeamSync::new(f.b.clone(), Arc::new(tb2.clone()), kb);
    sb2.start(Some("127.0.0.1:0")).unwrap();
    cleanup.sb = sb2;
    cleanup.tb = tb2;
    let address = cleanup.tb.bound_address().unwrap();
    let session = cleanup.ta.dial(&address, &f.env, None).unwrap();
    cleanup.sa.adopt_outbound_session(&f.env, session, &address);
    f.wait_stage(
        "appended-offline-fact-ledger-and-revocation-applied",
        || {
            f.b.state.read_lines(&facts_path, None).unwrap().len() == 2
                && f.b.vault.get_meta("key").is_ok_and(|meta| {
                    meta.versions
                        .first()
                        .is_some_and(|version| version.status == "revoked")
                })
        },
    );
    assert_eq!(f.b.state.read_lines(&facts_path, None).unwrap().len(), 2);
    assert_eq!(
        f.b.vault.get_meta("key").unwrap().versions[0].status,
        "revoked"
    );
    assert_eq!(
        cleanup.sa.status(&f.env).unwrap()["sessions"],
        json!([b_fp])
    );
}

#[test]
fn catchup_keeps_current_role_authorization_after_offline_demotion() {
    let f = RemoteFixture::new(connection_create("gh"), "api_key", SECRET, json!({}));
    let kb = DeviceKey::load_or_create(f.b.state, f.b.kms).unwrap();
    let b_fp = kb.fingerprint().unwrap();
    f.sb.stop();
    f.tb.shutdown();
    let demote = commit::sign_commit(
        &f.ka,
        &f.env,
        4,
        "4000-0000",
        &BTreeMap::new(),
        vec![json!({"op":"member.set_role","fingerprint":b_fp,"role":"user"})],
    )
    .unwrap();
    assert_eq!(f.sa.submit_commit(&f.env, &demote).unwrap(), "accepted");
    // B's offline replica has not learned its demotion, so it can originate a
    // signed fact. A must still evaluate B's role at receipt and reject it.
    f.sb.publish_fact(&f.env, "connection_disabled", json!({"connection_id":"gh"}))
        .unwrap();
    assert_eq!(
        f.sa.ctx.policy.get_connection("gh").unwrap().status,
        "active"
    );
    let rejects = Arc::new(Mutex::new(Vec::<Value>::new()));
    let captured = rejects.clone();
    f.sa.ctx.audit.subscribe(move |record| {
        if record.get("event") == Some(&json!("team_fact_rejected")) {
            captured.lock().unwrap().push(Value::Object(record.clone()));
        }
    });
    f.wait(|| {
        !f.sa.status(&f.env).unwrap()["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == &b_fp)
    });
    let empty: MembershipCheck = Arc::new(|_, _| None);
    let tb = TcpTransport::new(kb.clone(), empty, 4);
    let sb = TeamSync::new(f.b.clone(), Arc::new(tb.clone()), kb);
    sb.start(Some("127.0.0.1:0")).unwrap();
    let address = tb.bound_address().unwrap();
    let session = f.ta.dial(&address, &f.env, None).unwrap();
    f.sa.adopt_outbound_session(&f.env, session, &address);
    f.wait_stage("demoted-fact-rejected-on-catchup", || {
        rejects
            .lock()
            .unwrap()
            .iter()
            .any(|v| v["reason"] == "team_fact_not_authorized")
    });
    assert_eq!(
        f.sa.ctx.policy.get_connection("gh").unwrap().status,
        "active"
    );
    assert!(
        f.sa.ctx
            .state
            .read_lines(&format!("team/{}/facts.jsonl", f.env), None)
            .unwrap()
            .is_empty()
    );
    sb.stop();
    tb.shutdown();
}

#[test]
fn removed_offline_peer_gets_no_fact_replay_or_authenticated_session() {
    let f = RemoteFixture::new(connection_create("gh"), "api_key", SECRET, json!({}));
    let kb = DeviceKey::load_or_create(f.b.state, f.b.kms).unwrap();
    let b_fp = kb.fingerprint().unwrap();
    f.sb.stop();
    f.tb.shutdown();
    f.sa.publish_fact(&f.env, "connection_disabled", json!({"connection_id":"gh"}))
        .unwrap();
    f.sa.publish_fact(&f.env, "member_removed", json!({"fingerprint":b_fp}))
        .unwrap();
    let empty: MembershipCheck = Arc::new(|_, _| None);
    let tb = TcpTransport::new(kb.clone(), empty, 4);
    let sb = TeamSync::new(f.b.clone(), Arc::new(tb.clone()), kb);
    sb.start(Some("127.0.0.1:0")).unwrap();
    let address = tb.bound_address().unwrap();
    assert!(
        f.ta.dial(&address, &f.env, None).is_err(),
        "removed peer was allowed to authenticate for replay"
    );
    assert!(
        f.b.state
            .read_lines(&format!("team/{}/facts.jsonl", f.env), None)
            .unwrap()
            .is_empty(),
        "removed peer received a queued fact"
    );
    sb.stop();
    tb.shutdown();
}
