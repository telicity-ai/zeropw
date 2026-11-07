//! Remote sync between two Macs end to end against the real zeropw-admin (ignored by default):
//! two app data folders with their own vaults, and an in-process stand-in for the zeropw-link
//! service and the two Macs' daemons (zeropw-link protocol §5: status, enroll, link_token,
//! devices, revoke, dial, accept; a dial is joined to the other daemon's waiting accept and the
//! raw bytes are piped through). Needs `ZEROPW_BIN_DIR` with a zeropw-admin that has the pairing
//! approval and the `--link-socket` transport (docs/remote-sync.md §3.1-§3.3). Synthetic
//! passphrases, invite code and secret only; temp state directories.
//!
//! ```text
//! cargo build --manifest-path rust/Cargo.toml --bins
//! ZEROPW_BIN_DIR=$CARGO_TARGET_DIR/debug \
//!   cargo test --manifest-path desktop/Cargo.toml --test e2e_remote_pairing -- --ignored
//! ```

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use zeropw_desktop_core::commands::*;
use zeropw_desktop_core::{AppPaths, Core, CoreConfig, NoEvents, SecretString, Settings};

const PASS_A: &str = "velvet-ocean-27-quartz-lantern";
const PASS_B: &str = "amber-river-58-cobalt-meadow";
const INVITE_CODE: &str = "ZPL-SYNT-HETI-CSYN-THET-ICSY-NTHE-TI";
const SECRET: &str = "sk-synthetic-remote-pairing-0123456789";
const SERVICE: &str = "https://link.example.org";

fn bin_dir() -> PathBuf {
    let bin = PathBuf::from(std::env::var_os("ZEROPW_BIN_DIR").expect("set ZEROPW_BIN_DIR"));
    assert!(
        bin.join("zeropw-admin").is_file(),
        "no zeropw-admin in ZEROPW_BIN_DIR"
    );
    bin
}

/// Whether the zeropw-admin in `ZEROPW_BIN_DIR` has the pairing approval and the link
/// transport (`team invite --approval`, `team join --link-socket`). desktop/verify.sh runs the
/// ignored tests against the rust/ of the same checkout, which gains them only when the
/// remote-sync CLI work is merged; until then these tests say so and stop.
fn admin_has_remote_sync() -> bool {
    let help = |args: &[&str]| {
        std::process::Command::new(bin_dir().join("zeropw-admin"))
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout).into_owned()
                    + &String::from_utf8_lossy(&o.stderr)
            })
            .unwrap_or_default()
    };
    let ok = help(&["team", "invite", "--help"]).contains("--approval")
        && help(&["team", "join", "--help"]).contains("--link-socket");
    if !ok {
        eprintln!(
            "skipped: this zeropw-admin has no `team invite --approval` / `team join --link-socket` (remote sync CLI not merged)"
        );
    }
    ok
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

// ---------------------------------------------------------------------------------------------
// The link service and the daemons
// ---------------------------------------------------------------------------------------------

struct Device {
    account: String,
    name: String,
    created_at: u64,
    revoked: bool,
}

#[derive(Default)]
struct Service {
    devices: HashMap<String, Device>,
    tokens: HashMap<String, String>,
    accepts: HashMap<String, VecDeque<UnixStream>>,
    /// Every request line any daemon received, for the no-secret checks.
    lines: Vec<String>,
}

type Shared = Arc<Mutex<Service>>;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// One Mac's daemon: a socket in its app data folder, with a fixed link device ID.
struct Daemon {
    stop: Arc<AtomicBool>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn daemon(socket: &Path, device_id: &'static str, service: Shared) -> Daemon {
    let dir = socket.parent().unwrap();
    fs::create_dir_all(dir).unwrap();
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
    let _ = fs::remove_file(socket);
    let listener = UnixListener::bind(socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    thread::spawn(move || {
        while !s.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let service = service.clone();
                    thread::spawn(move || {
                        connection(blocking_stream(stream).unwrap(), device_id, service)
                    });
                }
                Err(_) => thread::sleep(Duration::from_millis(5)),
            }
        }
    });
    Daemon { stop }
}

// Accepted sockets can inherit the nonblocking listener mode on Darwin.
// The request parser and bridge below use blocking Read/io::copy semantics.
fn blocking_stream(stream: UnixStream) -> io::Result<UnixStream> {
    stream.set_nonblocking(false)?;
    Ok(stream)
}

#[test]
fn fake_daemon_stream_waits_for_a_request_instead_of_closing_on_would_block() {
    let (mut client, accepted) = UnixStream::pair().unwrap();
    // Force the Darwin inheritance case on both OSes.
    accepted.set_nonblocking(true).unwrap();
    let mut accepted = blocking_stream(accepted).unwrap();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let reader = thread::spawn(move || {
        ready_tx.send(()).unwrap();
        done_tx.send(request_line(&mut accepted)).unwrap();
    });
    ready_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    let premature = done_rx.recv_timeout(Duration::from_millis(50));
    // Always release the reader before asserting, also on a regression failure.
    let sent = client.write_all(b"{}\n");
    let result = if premature.is_ok() {
        premature.clone()
    } else {
        done_rx.recv_timeout(Duration::from_secs(1))
    };
    reader.join().unwrap();
    assert!(
        premature.is_err(),
        "bridge closed before any request arrived"
    );
    sent.unwrap();
    assert_eq!(result.unwrap().as_deref(), Some("{}"));
}

/// One request line, read byte by byte so nothing after it is consumed.
fn request_line(stream: &mut UnixStream) -> Option<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while line.len() <= 8 * 1024 {
        match stream.read(&mut byte) {
            Ok(1) if byte[0] == b'\n' => return String::from_utf8(line).ok(),
            Ok(1) => line.push(byte[0]),
            _ => return None,
        }
    }
    None
}

fn reply(stream: &mut UnixStream, value: &Value) -> io::Result<()> {
    let mut out = serde_json::to_vec(value).unwrap();
    out.push(b'\n');
    stream.write_all(&out)
}

/// A waiting accept whose client is still there: nothing to read yet, not closed (an accept
/// client writes nothing before its reply).
fn still_waiting(stream: &UnixStream) -> bool {
    let mut probe = [0u8; 1];
    if stream.set_nonblocking(true).is_err() {
        return false;
    }
    let waiting =
        matches!((&*stream).read(&mut probe), Err(e) if e.kind() == io::ErrorKind::WouldBlock);
    waiting && stream.set_nonblocking(false).is_ok()
}

fn pipe(mut from: UnixStream, mut to: UnixStream) {
    thread::spawn(move || {
        let _ = io::copy(&mut from, &mut to);
        let _ = to.shutdown(std::net::Shutdown::Write);
    });
}

static TOKENS: AtomicU64 = AtomicU64::new(1);

fn connection(mut stream: UnixStream, me: &'static str, service: Shared) {
    let Some(line) = request_line(&mut stream) else {
        return;
    };
    let request: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
    let mut svc = service.lock().unwrap();
    svc.lines.push(line.clone());
    let enrolled = svc
        .devices
        .get(me)
        .filter(|d| !d.revoked)
        .map(|d| d.account.clone());
    let answer = match request["op"].as_str().unwrap_or("") {
        "status" => {
            let peers: Vec<Value> = match &enrolled {
                Some(account) => svc
                    .devices
                    .iter()
                    .filter(|(id, d)| *id != me && d.account == *account)
                    .map(|(id, d)| json!({"device_id": id, "name": d.name, "online": !d.revoked,
                        "revoked": d.revoked, "path": if d.revoked { Value::Null } else { json!("direct") },
                        "rtt_ms": 3, "last_error": null}))
                    .collect(),
                None => Vec::new(),
            };
            json!({"ok": true, "enrolled": enrolled.is_some(), "revoked": false,
                   "service": if enrolled.is_some() { json!(SERVICE) } else { Value::Null },
                   "device_id": me, "account_id": enrolled, "online": enrolled.is_some(), "peers": peers})
        }
        "enroll" if enrolled.is_some() => json!({"ok": false, "error": "already_enrolled"}),
        "enroll" => {
            let account = if let Some(code) = request["invite_code"].as_str() {
                (code == INVITE_CODE).then(|| format!("acct-{me}"))
            } else {
                request["link_token"]
                    .as_str()
                    .and_then(|t| svc.tokens.remove(t))
            };
            match account {
                Some(account) => {
                    svc.devices.insert(
                        me.to_owned(),
                        Device {
                            account: account.clone(),
                            name: request["name"].as_str().unwrap_or("").to_owned(),
                            created_at: now(),
                            revoked: false,
                        },
                    );
                    json!({"ok": true, "device_id": me, "account_id": account})
                }
                None if request.get("invite_code").is_some() => {
                    json!({"ok": false, "error": "invite_invalid"})
                }
                None => json!({"ok": false, "error": "link_token_invalid"}),
            }
        }
        _ if enrolled.is_none() => json!({"ok": false, "error": "not_enrolled"}),
        "link_token" => {
            let token = format!("zplt_synthetic_{}", TOKENS.fetch_add(1, Ordering::SeqCst));
            svc.tokens.insert(token.clone(), enrolled.clone().unwrap());
            json!({"ok": true, "link_token": token, "expires_at": now() + 600, "device_id": me, "service": SERVICE})
        }
        "devices" => {
            let account = enrolled.clone().unwrap();
            let devices: Vec<Value> = svc
                .devices
                .iter()
                .filter(|(_, d)| d.account == account)
                .map(|(id, d)| json!({"device_id": id, "device_pub": "", "name": d.name, "created_at": d.created_at,
                    "last_seen_at": null, "online": !d.revoked, "revoked_at": if d.revoked { json!(now()) } else { Value::Null }}))
                .collect();
            json!({"ok": true, "account_id": account, "self": me, "devices": devices})
        }
        "revoke" => {
            let id = request["device_id"].as_str().unwrap_or("").to_owned();
            match svc.devices.get_mut(&id) {
                Some(d) if Some(&d.account) == enrolled.as_ref() => {
                    d.revoked = true;
                    json!({"ok": true})
                }
                _ => json!({"ok": false, "error": "peer_unknown"}),
            }
        }
        "accept" => {
            // answered when a dial arrives
            svc.accepts
                .entry(me.to_owned())
                .or_default()
                .push_back(stream);
            return;
        }
        "dial" => {
            let peer = request["peer"].as_str().unwrap_or("").to_owned();
            let same = svc
                .devices
                .get(&peer)
                .is_some_and(|d| !d.revoked && Some(&d.account) == enrolled.as_ref());
            if !same {
                json!({"ok": false, "error": "peer_unknown"})
            } else {
                drop(svc);
                let deadline = Instant::now() + Duration::from_secs(10);
                loop {
                    let waiting = {
                        let mut svc = service.lock().unwrap();
                        svc.accepts.get_mut(&peer).and_then(VecDeque::pop_front)
                    };
                    match waiting {
                        Some(mut accepted) if still_waiting(&accepted) => {
                            if reply(
                                &mut accepted,
                                &json!({"ok": true, "peer": me, "path": "direct"}),
                            )
                            .is_ok()
                                && reply(&mut stream, &json!({"ok": true, "path": "direct"}))
                                    .is_ok()
                            {
                                pipe(stream.try_clone().unwrap(), accepted.try_clone().unwrap());
                                pipe(accepted, stream);
                                return;
                            }
                        }
                        Some(_) => continue,
                        None if Instant::now() >= deadline => {
                            let _ =
                                reply(&mut stream, &json!({"ok": false, "error": "peer_offline"}));
                            return;
                        }
                        None => thread::sleep(Duration::from_millis(20)),
                    }
                }
            }
        }
        _ => json!({"ok": false, "error": "invalid_request"}),
    };
    drop(svc);
    let _ = reply(&mut stream, &answer);
}

// ---------------------------------------------------------------------------------------------

fn mac(root: &Path, name: &str) -> Core {
    let mut config = CoreConfig::new(AppPaths::new(root.join(name), bin_dir()));
    config.serve_stop_grace = Duration::from_secs(10);
    let core = Core::new(config, Arc::new(NoEvents));
    core.settings_set(Settings {
        gateway_port: free_port(),
        team_listen: None,
        link_service: None,
        language: None,
    })
    .unwrap();
    core
}

fn init(core: &Core, pass: &str) {
    let code = core.recovery_generate().unwrap();
    core.vault_init(VaultInitIn {
        admin_passphrase: pass.into(),
        recovery: RecoveryInput::Ref(code.reference),
    })
    .unwrap();
}

fn wait_for<T>(what: &str, timeout: Duration, mut check: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(found) = check() {
            return found;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(200));
    }
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(files_under(&path));
            } else {
                out.push(path);
            }
        }
    }
    out
}

#[test]
#[ignore = "needs ZEROPW_BIN_DIR with a zeropw-admin that has pairing approval and --link-socket"]
fn two_macs_pair_through_the_link_daemon_only_after_explicit_approval() {
    if !admin_has_remote_sync() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let service: Shared = Arc::default();
    let a = mac(dir.path(), "studio");
    let b = mac(dir.path(), "laptop");
    let a_paths = AppPaths::new(dir.path().join("studio"), bin_dir());
    let b_paths = AppPaths::new(dir.path().join("laptop"), bin_dir());
    let _daemon_a = daemon(
        &a_paths.link_socket(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaa",
        service.clone(),
    );
    let _daemon_b = daemon(
        &b_paths.link_socket(),
        "bbbbbbbbbbbbbbbbbbbbbbbbbb",
        service.clone(),
    );

    // Mac A: a vault with a key; Mac B: a new, empty vault
    init(&a, PASS_A);
    a.project_create(ProjectCreateIn {
        name: "demo".into(),
        environments: vec!["dev".into()],
    })
    .unwrap();
    a.secret_put(SecretPutIn {
        id: "api".into(),
        kind: SecretKind::ApiKey,
        project: "demo".into(),
        environment: "dev".into(),
        source: SecretSource::Typed(SECRET.into()),
    })
    .unwrap();
    init(&b, PASS_B);

    // A enrols once with the server invite code; serve now runs with the link socket
    let status = a
        .link_enroll(LinkEnrollIn {
            invite_code: INVITE_CODE.into(),
            service: Some(SERVICE.into()),
            name: Some("studio".into()),
        })
        .unwrap();
    assert!(status.enrolled && status.running);
    // the relay was restarted with the daemon's socket
    let serve: Value =
        serde_json::from_slice(&fs::read(a_paths.serve_pid_file()).unwrap()).unwrap();
    assert_eq!(
        serve["link_socket"].as_str().map(PathBuf::from),
        Some(a_paths.link_socket())
    );

    // A makes the pairing code: demo/dev is shared and gets one approval invitation for A's link device
    let made = a
        .pairing_create(PairingCreateIn {
            envs: None,
            name: Some("studio".into()),
            device_name: "laptop".into(),
            admin_passphrase: PASS_A.into(),
        })
        .unwrap();
    assert_eq!(made.peer, "aaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert_eq!(made.environments.len(), 1);
    assert_eq!(made.environments[0].env, "demo/dev");
    assert!(made.environments[0].shared_now);
    let code = a
        .onetime_show(RefIn {
            reference: made.reference.clone(),
        })
        .ok()
        .unwrap();
    assert!(code.expose().starts_with("zeropw://pair#"));
    // shown once
    assert!(
        a.onetime_show(RefIn {
            reference: made.reference
        })
        .is_err()
    );

    // B reads the code offline: A's name, fingerprint, one environment
    let preview = b
        .pairing_preview(PairingTextIn {
            text: SecretString::from(code.expose()),
        })
        .unwrap();
    assert_eq!(preview.preview.fingerprint, made.fingerprint);
    assert_eq!(preview.preview.name, "studio");
    assert_eq!(preview.preview.environments.len(), 1);

    // B asks: it enrols with the link token and waits for A's approval
    let first = b
        .pairing_join(RefIn {
            reference: preview.reference.clone(),
        })
        .unwrap();
    assert!(!first.done, "{first:?}");
    let pending = &first.environments[0];
    assert_eq!(pending.state, "pending", "{first:?}");
    assert_eq!(
        pending.inviter_fingerprint.as_deref(),
        Some(made.fingerprint.as_str())
    );
    let b_fp = pending.self_fingerprint.clone().unwrap();

    // A sees exactly B's request
    let requests = a
        .join_requests(EnvsIn {
            envs: vec!["demo/dev".into()],
        })
        .unwrap();
    assert!(requests.errors.is_empty(), "{requests:?}");
    assert_eq!(requests.requests.len(), 1);
    assert_eq!(requests.requests[0].fingerprint, b_fp);

    // asking again before approval still only waits
    let again = b
        .pairing_join(RefIn {
            reference: preview.reference.clone(),
        })
        .unwrap();
    assert_eq!(again.environments[0].state, "pending");

    // a wrong password approves nothing; the right one approves exactly B
    let wrong = a.approve_join(JoinDecisionIn {
        envs: vec!["demo/dev".into()],
        fingerprint: b_fp.clone(),
        admin_passphrase: "not-the-admin-passphrase-91".into(),
    });
    assert_eq!(wrong.unwrap_err().error, "AuthFailed");
    let approved = a
        .approve_join(JoinDecisionIn {
            envs: vec!["demo/dev".into()],
            fingerprint: b_fp.clone(),
            admin_passphrase: PASS_A.into(),
        })
        .unwrap();
    assert!(approved.envs[0].ok, "{approved:?}");
    assert_eq!(approved.envs[0].invites.len(), 1);

    // B joins and receives the history
    let joined = wait_for("B to join", Duration::from_secs(60), || {
        let out = b
            .pairing_join(RefIn {
                reference: preview.reference.clone(),
            })
            .unwrap();
        out.done.then_some(out)
    });
    assert_eq!(joined.environments[0].state, "joined");
    assert_eq!(joined.environments[0].project.as_deref(), Some("demo"));
    assert_eq!(joined.environments[0].environment.as_deref(), Some("dev"));
    let revealed = wait_for("the key on B", Duration::from_secs(30), || {
        b.secret_reveal(SecretRevealIn {
            id: "api".into(),
            version: None,
            admin_passphrase: PASS_B.into(),
        })
        .ok()
    });
    let shown = b
        .onetime_show(RefIn {
            reference: revealed.reference,
        })
        .ok()
        .unwrap();
    assert_eq!(shown.expose(), SECRET);

    // both Macs list each other in the devices view, with a sync state from the CLI
    let view_a = a.devices_overview().unwrap();
    let row = view_a
        .devices
        .iter()
        .find(|d| d.fingerprint == b_fp)
        .expect("B on A");
    assert_eq!(row.envs, ["demo/dev"]);
    assert_eq!(
        row.link_device_id.as_deref(),
        Some("bbbbbbbbbbbbbbbbbbbbbbbbbb")
    );
    let sync = view_a.envs[0].sync.as_ref().expect("team sync-status");
    let peer = sync["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["fingerprint"] == b_fp.as_str())
        .expect("B in sync-status");
    assert!(
        [
            "up_to_date",
            "syncing",
            "retrying",
            "offline",
            "never_connected"
        ]
        .contains(&peer["state"].as_str().unwrap()),
        "{peer}"
    );
    let view_b = b.devices_overview().unwrap();
    assert!(
        view_b
            .devices
            .iter()
            .any(|d| d.fingerprint == made.fingerprint
                && d.link_device_id.as_deref() == Some("aaaaaaaaaaaaaaaaaaaaaaaaaa"))
    );
    // Both relays run with the link socket and no team listen address. Each still writes its
    // sync state, and the two Macs' relays reach each other through the daemons: each reports
    // an open session carried by the link (docs/remote-sync.md §3.3).
    let link_session = |core: &Core, fp: &str| {
        let view = core.devices_overview().ok()?;
        let sync = view
            .envs
            .iter()
            .find(|e| e.env == "demo/dev")?
            .sync
            .clone()?;
        let peer = sync["peers"]
            .as_array()?
            .iter()
            .find(|p| p["fingerprint"] == fp)?
            .clone();
        (!sync["serve_updated_at"].is_null()
            && peer["session"] == true
            && peer["transport"] == "link")
            .then_some(peer)
    };
    for (who, core, fp) in [
        ("A", &a, b_fp.as_str()),
        ("B", &b, made.fingerprint.as_str()),
    ] {
        let peer = wait_for(
            &format!("{who}'s relay to report the link session"),
            Duration::from_secs(90),
            || link_session(core, fp),
        );
        assert!(
            ["up_to_date", "syncing"].contains(&peer["state"].as_str().unwrap_or("")),
            "{who}: {peer}"
        );
    }

    // removing B on A leaves the team and revokes B at the service
    let removed = a
        .device_remove(DeviceRemoveIn {
            fingerprint: Some(b_fp.clone()),
            link_device_id: None,
            admin_passphrase: Some(PASS_A.into()),
        })
        .unwrap();
    assert_eq!(removed.removed, ["demo/dev"]);
    assert!(removed.link_revoked, "{removed:?}");
    let members = a
        .team_members(EnvIn {
            env: "demo/dev".into(),
        })
        .unwrap();
    let b_member = members["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["fingerprint"] == b_fp.as_str())
        .cloned();
    assert_ne!(b_member.map(|m| m["status"].clone()), Some(json!("active")));
    assert!(
        service
            .lock()
            .unwrap()
            .devices
            .get("bbbbbbbbbbbbbbbbbbbbbbbbbb")
            .unwrap()
            .revoked
    );

    // the daemons only ever saw the invite code and link token in their own requests, never the
    // key, a passphrase or a team invitation; no app data file holds the key or the code
    let lines = service.lock().unwrap().lines.join("\n");
    for secret in [SECRET, PASS_A, PASS_B] {
        assert!(!lines.contains(secret), "a daemon request carried a secret");
    }
    for path in files_under(dir.path())
        .into_iter()
        .filter(|p| !p.starts_with(a_paths.state_dir()) && !p.starts_with(b_paths.state_dir()))
    {
        let text = fs::read(&path).unwrap_or_default();
        let text = String::from_utf8_lossy(&text);
        for secret in [SECRET, PASS_A, PASS_B, INVITE_CODE, code.expose()] {
            assert!(!text.contains(secret), "{} holds a secret", path.display());
        }
    }

    a.shutdown();
    b.shutdown();
}

/// A Mac whose request is refused never becomes a member, and its request is gone.
#[test]
#[ignore = "needs ZEROPW_BIN_DIR with a zeropw-admin that has pairing approval and --link-socket"]
fn a_refused_mac_never_joins() {
    if !admin_has_remote_sync() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let service: Shared = Arc::default();
    let a = mac(dir.path(), "studio");
    let b = mac(dir.path(), "laptop");
    let a_paths = AppPaths::new(dir.path().join("studio"), bin_dir());
    let b_paths = AppPaths::new(dir.path().join("laptop"), bin_dir());
    let _daemon_a = daemon(
        &a_paths.link_socket(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaa",
        service.clone(),
    );
    let _daemon_b = daemon(
        &b_paths.link_socket(),
        "bbbbbbbbbbbbbbbbbbbbbbbbbb",
        service.clone(),
    );
    init(&a, PASS_A);
    a.project_create(ProjectCreateIn {
        name: "demo".into(),
        environments: vec!["dev".into()],
    })
    .unwrap();
    init(&b, PASS_B);
    a.link_enroll(LinkEnrollIn {
        invite_code: INVITE_CODE.into(),
        service: Some(SERVICE.into()),
        name: None,
    })
    .unwrap();
    let made = a
        .pairing_create(PairingCreateIn {
            envs: Some(vec!["demo/dev".into()]),
            name: None,
            device_name: "laptop".into(),
            admin_passphrase: PASS_A.into(),
        })
        .unwrap();
    let code = a
        .onetime_show(RefIn {
            reference: made.reference,
        })
        .ok()
        .unwrap();
    let preview = b
        .pairing_preview(PairingTextIn {
            text: SecretString::from(code.expose()),
        })
        .unwrap();
    let first = b
        .pairing_join(RefIn {
            reference: preview.reference.clone(),
        })
        .unwrap();
    assert_eq!(first.environments[0].state, "pending", "{first:?}");
    let b_fp = first.environments[0].self_fingerprint.clone().unwrap();

    let denied = a
        .deny_join(JoinDecisionIn {
            envs: vec!["demo/dev".into()],
            fingerprint: b_fp.clone(),
            admin_passphrase: PASS_A.into(),
        })
        .unwrap();
    assert!(denied.envs[0].ok, "{denied:?}");
    assert_eq!(denied.envs[0].invites.len(), 1);
    assert!(
        a.join_requests(EnvsIn {
            envs: vec!["demo/dev".into()],
        })
        .unwrap()
        .requests
        .is_empty()
    );
    // B tries again: no membership, no new request, never "joined"
    let after = b
        .pairing_join(RefIn {
            reference: preview.reference,
        })
        .unwrap();
    assert!(!after.done);
    assert_ne!(after.environments[0].state, "joined", "{after:?}");
    let members = a
        .team_members(EnvIn {
            env: "demo/dev".into(),
        })
        .unwrap();
    assert!(
        !members["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["fingerprint"] == b_fp.as_str())
    );
    a.shutdown();
    b.shutdown();
}
