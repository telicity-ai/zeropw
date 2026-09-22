//! Native counterparts of still-unmapped original team contracts. All values and
//! endpoints are synthetic. No Python product implementation is used here.
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Stdio},
    sync::{
        Arc,
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
        .set_version_status("dead-token", 1, "revoked")
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
}

impl RemoteFixture {
    fn new(
        mut connection_op: Value,
        secret_kind: &str,
        secret_value: &[u8],
        public: Value,
    ) -> Self {
        let root = TempDir::new().unwrap();
        fs::create_dir(root.path().join("runs")).unwrap();
        if connection_op["cli"]["program"] == "__SYNTHETIC_SLEEP_CLI__" {
            let script = root.path().join("synthetic-ssh-cli");
            fs::write(&script, b"#!/bin/sh\nfor arg in \"$@\"; do marker=$arg; done\nprintf '%s' \"$SSH_AUTH_SOCK\" > \"$marker\"\nsleep 30\n").unwrap();
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
        sa.start(Some("127.0.0.1:0")).unwrap();
        sb.start(Some("127.0.0.1:0")).unwrap();
        sa.set_peer_address(&env, &fb, &tb.bound_address().unwrap())
            .unwrap();
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
}

impl Drop for RemoteFixture {
    fn drop(&mut self) {
        self.sa.stop();
        self.sb.stop();
        self.ta.shutdown();
        self.tb.shutdown();
    }
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
    f.wait(|| TcpStream::connect(("127.0.0.1", api_port)).is_ok());
    let marker = f._root.path().join("socket-marker");
    let view = api(
        api_port,
        &token,
        "exec",
        json!({"connection":"box","argv":[marker.to_string_lossy()]}),
    );
    let run_id = view["run_id"].as_str().unwrap();
    f.wait(|| marker.exists());
    let socket_path = std::path::PathBuf::from(fs::read_to_string(&marker).unwrap());
    assert!(socket_path.exists(), "real signer socket never opened");
    f.sa.publish_fact(
        &f.env,
        "connection_disabled",
        json!({"connection_id":"box"}),
    )
    .unwrap();
    f.wait(|| f.b.policy.get_connection("box").unwrap().status == "disabled");
    f.wait(|| !socket_path.exists());
    assert_eq!(
        api(api_port, &token, "status", json!({"run_id":run_id}))["state"],
        "cancelled"
    );
    assert_eq!(f.b.policy.get_connection("box").unwrap().status, "disabled");
}
