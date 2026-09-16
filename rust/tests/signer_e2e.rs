//! End-to-end SSH signing delegation against a real OpenSSH `sshd`
//! (non-root, loopback). Port of the `SshEndToEndTestCase` tests in
//! `tests/test_ssh_e2e.py`, for work unit G.
//!
//! The real `ssh` client authenticates with nothing but `SSH_AUTH_SOCK`
//! pointing at a `zeropw::signer` socket: the private key never leaves the
//! trusted process. Skipped (with a printed reason, never a silent pass)
//! when `sshd`/`ssh`/`ssh-keygen` are missing, or when `sshd` cannot start
//! as the current user in this environment.
//!
//! The exec-tool variant of the Python suite
//! (`ExecToolSshEndToEndTestCase`) is not ported: it drives `zeropw.tools`,
//! which is outside this half's scope (`rust/PORTING.md` §1 lists `tools`
//! under "Not in this half").
//!
//! Process supervision here is a simplified, Rust-test-scoped version of
//! `tests/lifeline.py`'s pipe-based orphan supervisor: a `Drop` guard
//! SIGKILLs `sshd` (which also runs `libtest`'s panic-triggered unwind on a
//! test failure), which is sufficient for a test process's lifetime -- the
//! full supervisor exists in Python to survive `SIGKILL`/hard crashes of
//! the *test* process itself, a case `cargo test`'s own process model does
//! not need defending against here.

use std::io::{BufRead, BufReader, Read};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::policy as P;
use zeropw::projects::DEFAULT_ENVIRONMENTS;
use zeropw::signer;
use zeropw::sshwire;

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

fn sshd_path() -> Option<PathBuf> {
    which("sshd").or_else(|| {
        let fallback = PathBuf::from("/usr/sbin/sshd");
        fallback.is_file().then_some(fallback)
    })
}

/// True when `sshd`, `ssh` and `ssh-keygen` are all on `PATH` (or, for
/// `sshd`, at the usual system path). Prints why a test is skipped instead
/// of silently passing, matching `tests/test_ssh_e2e.py`'s
/// `unittest.skipIf` (whose reason string appears in `-v` output).
fn tools_available() -> Option<(PathBuf, PathBuf, PathBuf)> {
    match (sshd_path(), which("ssh"), which("ssh-keygen")) {
        (Some(sshd), Some(ssh), Some(keygen)) => Some((sshd, ssh, keygen)),
        _ => {
            eprintln!("skipping: sshd, ssh, or ssh-keygen not available");
            None
        }
    }
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
    listener.local_addr().unwrap().port()
}

struct Sshd {
    root: PathBuf,
    port: u16,
    host_key: PathBuf,
    host_key_line: String,
    proc: Option<Child>,
}

impl Sshd {
    const START_ATTEMPTS: u32 = 3;

    fn new(sshd_bin: &Path, keygen: &Path, root: &Path, authorized_keys_line: &str) -> Self {
        let host_key = root.join("host_ed25519");
        let status = Command::new(keygen)
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&host_key)
            .status()
            .expect("run ssh-keygen");
        assert!(status.success(), "ssh-keygen failed to generate a host key");
        let host_key_line = std::fs::read_to_string(root.join("host_ed25519.pub"))
            .expect("read generated host public key")
            .trim()
            .to_string();
        let authorized = root.join("authorized_keys");
        std::fs::write(&authorized, format!("{authorized_keys_line}\n")).unwrap();
        std::fs::set_permissions(&authorized, std::fs::Permissions::from_mode(0o600)).unwrap();

        let mut sshd = Sshd {
            root: root.to_path_buf(),
            port: free_port(),
            host_key,
            host_key_line,
            proc: None,
        };
        let config_path = sshd.config_path();
        write_config(&config_path, sshd.port, &sshd.host_key, &authorized);

        for _attempt in 0..Self::START_ATTEMPTS {
            let mut child = Command::new(sshd_bin)
                .args(["-D", "-e", "-f"])
                .arg(&config_path)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn sshd");
            match Self::wait_until_serving(&mut child, sshd.port) {
                ServeResult::Serving => {
                    sshd.proc = Some(child);
                    return sshd;
                }
                ServeResult::PortInUse => {
                    kill_child(&mut child);
                    sshd.port = free_port();
                    write_config(&config_path, sshd.port, &sshd.host_key, &authorized);
                }
                ServeResult::Failed => {
                    kill_child(&mut child);
                    break;
                }
            }
        }
        sshd
    }

    fn config_path(&self) -> PathBuf {
        self.root.join("sshd_config")
    }

    fn started(&self) -> bool {
        self.proc.is_some()
    }

    fn wait_until_serving(child: &mut Child, port: u16) -> ServeResult {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(Some(_status)) = child.try_wait() {
                let mut stderr = String::new();
                if let Some(mut s) = child.stderr.take() {
                    let _ = s.read_to_string(&mut stderr);
                }
                let port_in_use =
                    stderr.contains("Address already in use") || stderr.contains("Cannot bind");
                return if port_in_use {
                    ServeResult::PortInUse
                } else {
                    ServeResult::Failed
                };
            }
            if banner(port).starts_with("SSH-2.0-OpenSSH") {
                std::thread::sleep(Duration::from_millis(200)); // a squatter can answer before sshd itself fails to bind
                return if child.try_wait().ok().flatten().is_none() {
                    ServeResult::Serving
                } else {
                    ServeResult::PortInUse
                };
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        ServeResult::Failed
    }

    #[allow(clippy::too_many_arguments)]
    fn run_ssh(
        &self,
        ssh_bin: &Path,
        socket_path: &Path,
        known_host_line: &str,
        run_dir: &Path,
        username: &str,
        user_public_key: &str,
        remote: &[&str],
    ) -> std::process::Output {
        std::fs::create_dir_all(run_dir).unwrap();
        let known = run_dir.join("known_hosts");
        std::fs::write(
            &known,
            format!("[127.0.0.1]:{} {known_host_line}\n", self.port),
        )
        .unwrap();
        let pub_path = run_dir.join("id.pub");
        std::fs::write(&pub_path, format!("{user_public_key}\n")).unwrap();
        let mut cmd = Command::new(ssh_bin);
        cmd.args(["-F", "/dev/null", "-o", "IdentitiesOnly=yes"])
            .arg("-o")
            .arg(format!("IdentityFile={}", pub_path.display()))
            .arg("-o")
            .arg(format!("IdentityAgent={}", socket_path.display()))
            .args(["-o", "ForwardAgent=no", "-o", "StrictHostKeyChecking=yes"])
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", known.display()))
            .args([
                "-o",
                "BatchMode=yes",
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "KbdInteractiveAuthentication=no",
                "-o",
                "ConnectTimeout=10",
                "-p",
            ])
            .arg(self.port.to_string())
            .arg(format!("{username}@127.0.0.1"))
            .arg("--")
            .args(remote)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", run_dir)
            .env("SSH_AUTH_SOCK", socket_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd.output().expect("run ssh")
    }
}

fn write_config(config_path: &Path, port: u16, host_key: &Path, authorized: &Path) {
    std::fs::write(
        config_path,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {host_key}\nPidFile none\n\
             AuthorizedKeysFile {authorized}\nPubkeyAuthentication yes\nPasswordAuthentication no\n\
             KbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nLogLevel ERROR\n\
             AllowAgentForwarding no\nAllowTcpForwarding no\nX11Forwarding no\nPermitUserEnvironment no\n",
            host_key = host_key.display(),
            authorized = authorized.display(),
        ),
    )
    .unwrap();
}

enum ServeResult {
    Serving,
    PortInUse,
    Failed,
}

fn banner(port: u16) -> String {
    match TcpStream::connect(("127.0.0.1", port)) {
        Ok(sock) => {
            let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
            let mut reader = BufReader::new(sock);
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            line
        }
        Err(_) => String::new(),
    }
}

fn kill_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

impl Drop for Sshd {
    fn drop(&mut self) {
        if let Some(mut proc) = self.proc.take() {
            kill_child(&mut proc);
        }
    }
}

use std::os::unix::fs::PermissionsExt;

// --------------------------------------------------------------- fixture

struct Fixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    ctx: &'static Context,
    manager: std::sync::Arc<signer::SignerManager>,
    user_key: sshwire::Ed25519PrivateKey,
    sshd: Sshd,
    username: String,
    ssh_bin: PathBuf,
}

fn build_fixture() -> Option<Fixture> {
    let (sshd_bin, ssh_bin, keygen_bin) = tools_available()?;
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().to_path_buf();
    let ctx: &'static Context = Box::leak(Box::new(
        Context::initialize(
            root.join("state"),
            "admin-passphrase-1",
            "recovery-passphrase-1",
            Config::default(),
            clock::system(),
        )
        .unwrap(),
    ));
    ctx.projects.create("demo", DEFAULT_ENVIRONMENTS).unwrap();
    let user_key = sshwire::generate_ed25519_private_key("agent");
    ctx.vault
        .put_secret(
            "box-key",
            "ssh_private_key",
            user_key.to_openssh_private_key().as_bytes(),
            "demo",
            "dev",
            true,
        )
        .unwrap();
    ctx.policy.create_principal("agent-1", "default").unwrap();
    let username = whoami();
    let sshd = Sshd::new(
        &sshd_bin,
        &keygen_bin,
        &root,
        &user_key.public.to_authorized_key("agent").unwrap(),
    );
    if !sshd.started() {
        eprintln!("skipping: sshd could not start as a non-root user in this environment");
        return None;
    }
    let manager = signer::install(ctx, None).unwrap();
    Some(Fixture {
        _tmp: tmp,
        root,
        ctx,
        manager,
        user_key,
        sshd,
        username,
        ssh_bin,
    })
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| {
            let out = Command::new("id").arg("-un").output().expect("run id -un");
            String::from_utf8(out.stdout).unwrap().trim().to_string()
        })
}

impl Fixture {
    fn connection(&self, host_key_line: &str) -> P::Connection {
        self.ctx
            .policy
            .create_connection(
                P::Connection::new(
                    "box",
                    "demo",
                    "dev",
                    "ssh-box",
                    "ssh",
                    "box-key",
                    None,
                    "",
                    None,
                    None,
                    None,
                    Some(
                        P::SshTarget::new(
                            "127.0.0.1",
                            self.sshd.port as i64,
                            &self.username,
                            vec![host_key_line.to_string()],
                        )
                        .unwrap(),
                    ),
                    None,
                    0,
                    "active",
                    "",
                    "",
                )
                .unwrap(),
            )
            .unwrap()
    }

    fn ssh_audit(&self) -> Vec<(String, String, Option<String>)> {
        self.ctx
            .audit
            .tail(200)
            .unwrap()
            .into_iter()
            .filter(|r| r["event"].as_str().is_some_and(|e| e.starts_with("ssh")))
            .map(|r| {
                (
                    r["event"].as_str().unwrap().to_string(),
                    r["result"].as_str().unwrap().to_string(),
                    r.get("reason").and_then(|v| v.as_str()).map(str::to_string),
                )
            })
            .collect()
    }
}

// ----------------------------------------------------------------- tests

// Port of SshEndToEndTestCase::test_real_ssh_client_authenticates_through_signer_without_private_key
#[test]
fn real_ssh_client_authenticates_through_signer_without_private_key() {
    let Some(f) = build_fixture() else { return };
    f.connection(&f.sshd.host_key_line);
    let grant = f
        .ctx
        .policy
        .create_grant("agent-1", "box", Some(3600), None)
        .unwrap();
    let binding = f.manager.bind("agent-1", "box", &grant.id).unwrap();
    let run_dir = f.root.join("run");
    let user_pub = f.user_key.public.to_authorized_key("agent").unwrap();

    let first = f.sshd.run_ssh(
        &f.ssh_bin,
        &binding.socket_path,
        &f.sshd.host_key_line,
        &run_dir,
        &f.username,
        &user_pub,
        &["echo", "hello-from-sshd"],
    );
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&first.stdout).trim(),
        "hello-from-sshd"
    );

    // Same connection, a different remote command: no per-operation registration.
    let second = f.sshd.run_ssh(
        &f.ssh_bin,
        &binding.socket_path,
        &f.sshd.host_key_line,
        &run_dir,
        &f.username,
        &user_pub,
        &["printf", "second-%s", "command"],
    );
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&second.stdout).trim(),
        "second-command"
    );

    let audit = f.ssh_audit();
    assert!(audit.contains(&("ssh_bind".to_string(), "ok".to_string(), None)));
    assert_eq!(
        audit
            .iter()
            .filter(|e| e == &&("ssh_sign".to_string(), "ok".to_string(), None))
            .count(),
        2
    );
    assert_eq!(f.ctx.policy.get_grant(&grant.id).unwrap().uses, 2);

    // The execution environment never held the private key.
    for entry in walk(&run_dir) {
        if entry.is_file() {
            let content = std::fs::read_to_string(&entry).unwrap_or_default();
            assert!(!content.contains("PRIVATE KEY"), "{}", entry.display());
        }
    }
    binding.close();
}

// Port of SshEndToEndTestCase::test_wrong_destination_host_key_is_refused
#[test]
fn wrong_destination_host_key_is_refused() {
    let Some(f) = build_fixture() else { return };
    let impostor = sshwire::generate_ed25519_private_key("impostor");
    f.connection(&impostor.public.to_authorized_key("impostor").unwrap());
    let grant = f
        .ctx
        .policy
        .create_grant("agent-1", "box", Some(3600), None)
        .unwrap();
    let binding = f.manager.bind("agent-1", "box", &grant.id).unwrap();
    let run_dir = f.root.join("run2");
    let user_pub = f.user_key.public.to_authorized_key("agent").unwrap();

    // The client trusts the real server key, but the signer only signs for
    // the configured destination.
    let result = f.sshd.run_ssh(
        &f.ssh_bin,
        &binding.socket_path,
        &f.sshd.host_key_line,
        &run_dir,
        &f.username,
        &user_pub,
        &["echo", "should-not-run"],
    );
    assert!(!result.status.success());
    assert!(!String::from_utf8_lossy(&result.stdout).contains("should-not-run"));
    let audit = f.ssh_audit();
    assert!(audit.contains(&(
        "ssh_bind".to_string(),
        "denied".to_string(),
        Some("host_key_not_allowed".to_string())
    )));
    assert!(audit.contains(&(
        "ssh_sign".to_string(),
        "denied".to_string(),
        Some("no_session_bind".to_string())
    )));
    assert_eq!(f.ctx.policy.get_grant(&grant.id).unwrap().uses, 0);
}

// Port of SshEndToEndTestCase::test_revoked_grant_cannot_authenticate
#[test]
fn revoked_grant_cannot_authenticate() {
    let Some(f) = build_fixture() else { return };
    f.connection(&f.sshd.host_key_line);
    let grant = f
        .ctx
        .policy
        .create_grant("agent-1", "box", Some(3600), None)
        .unwrap();
    let binding = f.manager.bind("agent-1", "box", &grant.id).unwrap();
    f.ctx.policy.revoke_grant(&grant.id).unwrap();
    let run_dir = f.root.join("run3");
    let user_pub = f.user_key.public.to_authorized_key("agent").unwrap();
    let result = f.sshd.run_ssh(
        &f.ssh_bin,
        &binding.socket_path,
        &f.sshd.host_key_line,
        &run_dir,
        &f.username,
        &user_pub,
        &["echo", "should-not-run"],
    );
    assert!(!result.status.success());
    assert!(!String::from_utf8_lossy(&result.stdout).contains("should-not-run"));
    assert!(!binding.socket_path.exists());
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}
