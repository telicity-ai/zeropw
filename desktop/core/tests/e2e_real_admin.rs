//! End to end against the real binaries (ignored by default). Needs `ZEROPW_BIN_DIR` pointing at
//! a build of `zeropw-admin` with the desktop CLI changes (docs/desktop-app.md §3:
//! `--input-envelope`, `status`). Synthetic passphrases and values only, temp state directory.
//!
//! ```text
//! cargo build --manifest-path rust/Cargo.toml --bins
//! ZEROPW_BIN_DIR=$CARGO_TARGET_DIR/debug \
//!   cargo test --manifest-path desktop/Cargo.toml --test e2e_real_admin -- --ignored
//! ```

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use zeropw_desktop_core::commands::*;
use zeropw_desktop_core::serve::{ServeConfig, ServeSupervisor, healthz};
use zeropw_desktop_core::{AppPaths, Core, CoreConfig, NoEvents, Settings};

fn bin_dir() -> PathBuf {
    let bin = PathBuf::from(std::env::var_os("ZEROPW_BIN_DIR").expect("set ZEROPW_BIN_DIR"));
    assert!(
        bin.join("zeropw-admin").is_file(),
        "no zeropw-admin in ZEROPW_BIN_DIR"
    );
    bin
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// The serve sidecar needs no input envelope, so this runs against today's CLI too. The state
/// directory is created the pre-envelope way (passphrases in the child's environment; test only,
/// synthetic values).
#[test]
#[ignore = "needs ZEROPW_BIN_DIR with zeropw-admin"]
fn real_serve_starts_attaches_and_stops() {
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::new(dir.path().join("app"), bin_dir());
    zeropw_desktop_core::paths::ensure_private_dir(&paths.app_data_dir).unwrap();
    let init = Command::new(paths.admin_bin())
        .arg(format!("--state-dir={}", paths.state_dir().display()))
        .arg("init")
        .env("ZEROPW_ADMIN_PASSPHRASE", "velvet-ocean-27-quartz-lantern")
        .env(
            "ZEROPW_RECOVERY_PASSPHRASE",
            "another-lantern-42-quartz-velvet",
        )
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );

    let port = free_port();
    let first = ServeSupervisor::new(&paths);
    let status = first
        .start(&ServeConfig {
            port,
            team_listen: None,
        })
        .unwrap();
    assert!(status.running);
    assert_eq!(status.url, Some(format!("http://127.0.0.1:{port}")));
    assert!(healthz(port, Duration::from_secs(2)).unwrap().is_zeropw());

    let second = ServeSupervisor::new(&paths);
    assert_eq!(second.attach().pid, status.pid);
    let started = Instant::now();
    assert!(!second.stop().running);
    assert!(
        started.elapsed() < Duration::from_secs(25),
        "SIGTERM was not honored"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while healthz(port, Duration::from_millis(500)).is_ok() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(healthz(port, Duration::from_millis(500)).is_err());
    assert!(!first.status().running);
    assert!(!paths.serve_pid_file().exists());
}

/// The real sidecar's own reason tells a taken gateway port from a team listener that cannot
/// open its address, and neither error carries the address.
#[test]
#[ignore = "needs ZEROPW_BIN_DIR with zeropw-admin"]
fn real_serve_says_which_address_it_could_not_open() {
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::new(dir.path().join("app"), bin_dir());
    zeropw_desktop_core::paths::ensure_private_dir(&paths.app_data_dir).unwrap();
    let init = Command::new(paths.admin_bin())
        .arg(format!("--state-dir={}", paths.state_dir().display()))
        .arg("init")
        .env("ZEROPW_ADMIN_PASSPHRASE", "velvet-ocean-27-quartz-lantern")
        .env(
            "ZEROPW_RECOVERY_PASSPHRASE",
            "another-lantern-42-quartz-velvet",
        )
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let sup = ServeSupervisor::new(&paths);

    let gateway = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = gateway.local_addr().unwrap().port();
    let e = sup
        .start(&ServeConfig {
            port,
            team_listen: None,
        })
        .unwrap_err();
    assert_eq!(
        (e.reason.as_str(), e.detail.as_deref()),
        ("listen_failed", Some("gateway_port")),
        "{e}"
    );

    let team = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let team_listen = team.local_addr().unwrap().to_string();
    let e = sup
        .start(&ServeConfig {
            port: free_port(),
            team_listen: Some(team_listen.clone()),
        })
        .unwrap_err();
    assert_eq!(
        (e.reason.as_str(), e.detail.as_deref()),
        ("team_invalid_listen_address", Some("team_listen")),
        "{e}"
    );
    assert!(!e.to_string().contains(&team_listen));
    assert!(!sup.status().running);
    assert!(!paths.serve_pid_file().exists());
    drop((gateway, team));
}

#[test]
#[ignore = "needs ZEROPW_BIN_DIR with a zeropw-admin that supports --input-envelope"]
fn init_project_secret_put_and_list_without_values() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = CoreConfig::new(AppPaths::new(dir.path().join("app"), bin_dir()));
    config.serve_stop_grace = Duration::from_secs(10);
    let core = Core::new(config, Arc::new(NoEvents));
    core.settings_set(Settings {
        gateway_port: free_port(),
        team_listen: None,
    })
    .unwrap();

    let code = core.recovery_generate().unwrap();
    let init = core
        .vault_init(VaultInitIn {
            admin_passphrase: "velvet-ocean-27-quartz-lantern".into(),
            recovery: RecoveryInput::Ref(code.reference),
        })
        .unwrap();
    assert!(!init.kms_key_id.is_empty());
    let status = core.app_status().unwrap();
    assert!(status.initialized);
    assert!(status.serve.running);
    assert_eq!(status.control.map(|c| c.stopped), Some(false));

    let project = core
        .project_create(ProjectCreateIn {
            name: "demo".into(),
            environments: vec!["dev".into()],
        })
        .unwrap();
    assert_eq!(project["name"], "demo");

    let value = "sk-synthetic-e2e-0123456789";
    core.secret_put(SecretPutIn {
        id: "api".into(),
        kind: SecretKind::ApiKey,
        project: "demo".into(),
        environment: "dev".into(),
        source: SecretSource::Typed(value.into()),
    })
    .unwrap();
    let list = core.secret_list(SecretListIn::default()).unwrap();
    let text = list.to_string();
    assert!(text.contains("\"api\""), "{text}");
    assert!(!text.contains(value), "secret list leaked the value");

    let revealed = core
        .secret_reveal(SecretRevealIn {
            id: "api".into(),
            version: None,
            admin_passphrase: "velvet-ocean-27-quartz-lantern".into(),
        })
        .unwrap();
    let shown = core
        .onetime_show(RefIn {
            reference: revealed.reference,
        })
        .ok()
        .unwrap();
    assert_eq!(shown.expose(), value);

    core.shutdown();
    assert!(!core.serve_status().running);
}

/// CORE-5 against the real CLI: `zeropw-admin init` keeps a code-shaped recovery passphrase
/// exactly as typed, so the app's canonical form fails once and the exact text then works.
/// A wrong code-shaped passphrase costs exactly two `auth_failed` records, never more.
#[test]
#[ignore = "needs ZEROPW_BIN_DIR with a zeropw-admin that supports --input-envelope"]
fn recover_reaches_a_vault_whose_code_was_typed_into_the_cli() {
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::new(dir.path().join("app"), bin_dir());
    zeropw_desktop_core::paths::ensure_private_dir(&paths.app_data_dir).unwrap();
    let typed = "abcd efgh ijkl mnop qrst uvw2";
    let init = Command::new(paths.admin_bin())
        .arg(format!("--state-dir={}", paths.state_dir().display()))
        .arg("init")
        .env("ZEROPW_ADMIN_PASSPHRASE", "velvet-ocean-27-quartz-lantern")
        .env("ZEROPW_RECOVERY_PASSPHRASE", typed)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let core = Core::new(CoreConfig::new(paths), Arc::new(NoEvents));
    let failures = |core: &Core| {
        core.audit_tail(LimitIn { limit: 1000 }).unwrap()["records"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["event"] == "auth_failed")
            .count()
    };

    let wrong = core
        .recover(RecoverIn {
            recovery_passphrase: "zzzz zzzz zzzz zzzz zzzz zzzz".into(),
        })
        .unwrap_err();
    assert_eq!(wrong.error, "AuthFailed");
    assert_eq!(failures(&core), 2);

    let out = core
        .recover(RecoverIn {
            recovery_passphrase: typed.into(),
        })
        .unwrap();
    assert!(out["kms_key_id"].is_string(), "{out}");
    assert_eq!(failures(&core), 3);
}

/// `sshd`, `ssh-keygen`: the SSH test below must fail, not silently pass, without them.
fn openssh_tools() -> (PathBuf, PathBuf) {
    let find = |name: &str, fallback: &str| {
        Command::new("sh")
            .args(["-c", &format!("command -v {name}")])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()))
            .or_else(|| Some(PathBuf::from(fallback)).filter(|p| p.is_file()))
            .unwrap_or_else(|| panic!("{name} not available: this test needs OpenSSH"))
    };
    (
        find("sshd", "/usr/sbin/sshd"),
        find("ssh-keygen", "/usr/bin/ssh-keygen"),
    )
}

/// A throwaway `sshd` on loopback, run as the current user, that accepts one public key.
struct Sshd {
    port: u16,
    host_key_line: String,
    child: std::process::Child,
}

impl Sshd {
    fn start(dir: &std::path::Path, authorized_key: &str) -> Sshd {
        use std::io::{BufRead, BufReader};
        use std::os::unix::fs::PermissionsExt;
        let (sshd, keygen) = openssh_tools();
        let dir = dir.join("sshd");
        std::fs::create_dir_all(&dir).unwrap();
        let host_key = dir.join("host_ed25519");
        let made = Command::new(keygen)
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&host_key)
            .status()
            .unwrap();
        assert!(made.success(), "ssh-keygen failed");
        let host_key_line = std::fs::read_to_string(dir.join("host_ed25519.pub"))
            .unwrap()
            .trim()
            .to_owned();
        let authorized = dir.join("authorized_keys");
        std::fs::write(&authorized, format!("{authorized_key}\n")).unwrap();
        std::fs::set_permissions(&authorized, std::fs::Permissions::from_mode(0o600)).unwrap();
        let config = dir.join("sshd_config");
        let port = free_port();
        std::fs::write(
            &config,
            format!(
                "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile none\n\
                 AuthorizedKeysFile {}\nPubkeyAuthentication yes\nPasswordAuthentication no\n\
                 KbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nLogLevel ERROR\n\
                 AllowAgentForwarding no\nAllowTcpForwarding no\nX11Forwarding no\n",
                host_key.display(),
                authorized.display()
            ),
        )
        .unwrap();
        let mut child = Command::new(sshd)
            .args(["-D", "-e", "-f"])
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let banner = std::net::TcpStream::connect(("127.0.0.1", port))
                .ok()
                .and_then(|s| {
                    s.set_read_timeout(Some(Duration::from_millis(500))).ok()?;
                    let mut line = String::new();
                    BufReader::new(s).read_line(&mut line).ok()?;
                    Some(line)
                })
                .unwrap_or_default();
            if banner.starts_with("SSH-2.0-OpenSSH") {
                break;
            }
            if child.try_wait().unwrap().is_some() || Instant::now() > deadline {
                let _ = child.kill();
                panic!("sshd did not start as the current user on 127.0.0.1:{port}");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Sshd {
            port,
            host_key_line,
            child,
        }
    }
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Stops the core's `serve` even when an assertion fails, so a failed run leaves no sidecar.
struct ShutdownOnDrop<'a>(&'a Core);

impl Drop for ShutdownOnDrop<'_> {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

/// `zeropw-agent` with only the caller token, the gateway URL, PATH and an empty HOME.
fn agent(home: &std::path::Path, url: &str, token: &str, args: &[&str]) -> serde_json::Value {
    let out = Command::new(bin_dir().join("zeropw-agent"))
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", home)
        .env("ZEROPW_GATEWAY_URL", url)
        .env("ZEROPW_CALLER_TOKEN", token)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "agent {args:?}: {text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("agent JSON ({e}): {text:?}"))
}

/// Desktop E2E finding F8: an SSH connection made the way the app's form makes it (generated
/// key, the form's default ssh) is one the agent can use. The core creates it, the core's own
/// `serve` signs, and `zeropw-agent exec` runs a command on a throwaway sshd. Before the fix
/// the connection had no ssh and exec answered `cli_not_supported` without reaching sshd.
#[test]
#[ignore = "needs ZEROPW_BIN_DIR with zeropw-admin and zeropw-agent, and OpenSSH sshd"]
fn app_made_ssh_connection_runs_agent_exec_on_a_real_sshd() {
    const PASS: &str = "velvet-ocean-27-quartz-lantern";
    // desktop/src/lib/dash.ts SSH_PROGRAM, what the connection form sends unless changed
    const FORM_SSH: &str = "/usr/bin/ssh";
    let dir = tempfile::tempdir().unwrap();
    let mut config = CoreConfig::new(AppPaths::new(dir.path().join("app"), bin_dir()));
    config.serve_stop_grace = Duration::from_secs(10);
    let core = Core::new(config, Arc::new(NoEvents));
    let _serve = ShutdownOnDrop(&core);
    core.settings_set(Settings {
        gateway_port: free_port(),
        team_listen: None,
    })
    .unwrap();
    let code = core.recovery_generate().unwrap();
    core.vault_init(VaultInitIn {
        admin_passphrase: PASS.into(),
        recovery: RecoveryInput::Ref(code.reference),
    })
    .unwrap();
    core.project_create(ProjectCreateIn {
        name: "demo".into(),
        environments: vec!["dev".into()],
    })
    .unwrap();
    let key = core
        .secret_put(SecretPutIn {
            id: "box".into(),
            kind: SecretKind::SshPrivateKey,
            project: "demo".into(),
            environment: "dev".into(),
            source: SecretSource::GenerateEd25519(true),
        })
        .unwrap();
    let sshd = Sshd::start(dir.path(), key["public_key"].as_str().unwrap());
    let user = Command::new("id").arg("-un").output().unwrap();
    let user = String::from_utf8_lossy(&user.stdout).trim().to_owned();

    let created = core
        .connection_create_ssh(SshConnectionIn {
            id: "box".into(),
            project: "demo".into(),
            environment: "dev".into(),
            service: "box".into(),
            secret_id: "box".into(),
            host: "127.0.0.1".into(),
            port: sshd.port,
            username: user.clone(),
            host_keys: vec![sshd.host_key_line.clone()],
            cli_program: FORM_SSH.into(),
            description: None,
            admin_passphrase: PASS.into(),
        })
        .unwrap();
    assert_eq!(
        (&created["cli"]["program"], &created["cli"]["kind"]),
        (&serde_json::json!(FORM_SSH), &serde_json::json!("ssh")),
        "{created}"
    );
    let listed = core.connection_list().unwrap();
    let stored = listed["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "box")
        .unwrap();
    assert_eq!(stored["cli"]["program"], FORM_SSH, "{stored}");

    let principal = core
        .principal_create(PrincipalCreateIn {
            id: "agent-1".into(),
            runtime: "default".into(),
        })
        .unwrap();
    let token = core
        .onetime_show(RefIn {
            reference: principal.token_ref,
        })
        .unwrap();
    core.grant_create(GrantCreateIn {
        principal: "agent-1".into(),
        connection: "box".into(),
        ttl: "1h".into(),
        max_uses: None,
        admin_passphrase: PASS.into(),
    })
    .unwrap();

    let url = core.serve_status().url.expect("serve is running");
    let home = dir.path().join("agent-home");
    std::fs::create_dir(&home).unwrap();
    let run = agent(
        &home,
        &url,
        token.expose(),
        &["exec", "--connection", "box", "--", "whoami"],
    );
    let run_id = run["run_id"].as_str().unwrap_or_else(|| panic!("{run}"));
    let deadline = Instant::now() + Duration::from_secs(60);
    let done = loop {
        let status = agent(&home, &url, token.expose(), &["status", "--run", run_id]);
        if !matches!(status["state"].as_str(), Some("queued" | "running")) {
            break status;
        }
        assert!(Instant::now() < deadline, "run did not finish: {status}");
        std::thread::sleep(Duration::from_millis(200));
    };
    assert_eq!(
        (
            done["state"].as_str(),
            done["exit_code"].as_i64(),
            done["stdout"].as_str().map(str::trim)
        ),
        (Some("completed"), Some(0), Some(user.as_str())),
        "{done}"
    );
}
