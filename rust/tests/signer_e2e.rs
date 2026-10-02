//! End-to-end SSH signing delegation against a real OpenSSH `sshd`
//! (non-root, loopback). Port of the `SshEndToEndTestCase` tests in
//! `tests/test_ssh_e2e.py`, for work unit G.
//!
//! The real `ssh` client authenticates with nothing but `SSH_AUTH_SOCK`
//! pointing at a `zeropw::signer` socket: the private key never leaves the
//! trusted process. Python's `SshEndToEndTestCase` uses a real
//! `unittest.skipIf` for missing tooling, which `unittest`/CI report as
//! "skipped", never "ok". `libtest` has no equivalent status for an
//! ordinary `#[test]` run without `--ignored`, and printing a message then
//! returning early is silently reported as "ok" -- a false green (finding
//! G-5). So this suite instead **fails** the test (a clear panic message,
//! never a silent early return) when `sshd`/`ssh`/`ssh-keygen` are missing,
//! or when `sshd` cannot start as the current user in this environment: a
//! host that cannot actually run this coverage cannot report green either.
//!
//! The exec-tool variant of the Python suite (`ExecToolSshEndToEndTestCase`)
//! is ported at the end of this file (`exec_tool_*`): `zeropw::tools::exec`
//! runs an inspector-wrapped real `ssh` through the signer to the real
//! `sshd`, under the same availability rule.
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

/// `sshd`, `ssh` and `ssh-keygen`, all on `PATH` (or, for `sshd`, at the
/// usual system path). Panics with a clear reason instead of silently
/// skipping: unlike `tests/test_ssh_e2e.py`'s `unittest.skipIf` (reported as
/// "skipped"), a `libtest` test that prints a message and returns early is
/// reported as "ok", a false pass this project's rule for the SSH e2e
/// coverage forbids (finding G-5).
fn tools_available() -> (PathBuf, PathBuf, PathBuf) {
    match (sshd_path(), which("ssh"), which("ssh-keygen")) {
        (Some(sshd), Some(ssh), Some(keygen)) => (sshd, ssh, keygen),
        _ => panic!(
            "sshd, ssh, or ssh-keygen not available on PATH: this end-to-end SSH test \
             requires real OpenSSH tooling and must fail, not silently pass, when it is missing"
        ),
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
    ctx: std::sync::Arc<Context>,
    manager: std::sync::Arc<signer::SignerManager>,
    user_key: sshwire::Ed25519PrivateKey,
    sshd: Sshd,
    username: String,
    ssh_bin: PathBuf,
}

fn build_fixture() -> Fixture {
    let (sshd_bin, ssh_bin, keygen_bin) = tools_available();
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().to_path_buf();
    // Explicit `socket_dir`/`run_dir`, both under `root`: otherwise
    // `Context::initialize` would default them to fresh private temp dirs
    // under the *system* temp dir (`private_tempdir`, prefixes
    // "zeropw-sockets-"/"zeropw-runs-") -- harmless now that `ctx` is a
    // properly-dropped `Arc<Context>` (finding E-R7-1), but still worth
    // keeping self-contained under `root`.
    let config = Config {
        socket_dir: Some(root.join("ctx-sockets")),
        run_dir: Some(root.join("ctx-run")),
        ..Config::default()
    };
    let ctx: std::sync::Arc<Context> = std::sync::Arc::new(
        Context::initialize(
            root.join("state"),
            "admin-passphrase-1",
            "recovery-passphrase-1",
            config,
            clock::system(),
        )
        .unwrap(),
    );
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
        panic!(
            "sshd could not start as a non-root user in this environment: this end-to-end \
             SSH test must fail, not silently pass, when it cannot actually run"
        );
    }
    let manager = signer::install(std::sync::Arc::clone(&ctx), None).unwrap();
    Fixture {
        _tmp: tmp,
        root,
        ctx,
        manager,
        user_key,
        sshd,
        username,
        ssh_bin,
    }
}

/// Port of `tests/test_ssh_e2e.py`'s `SshEndToEndTestCase.setUp`, which
/// registers `addCleanup(self.manager.shutdown)` so every case exercises
/// `shutdown()` -> `release_for_grant(None)` -> `close()` on every socket it
/// bound, even ones a test never explicitly closed itself (finding G-R3-4:
/// this crate's fixture used to call neither `shutdown()` nor anything else,
/// so none of that teardown path was exercised at all).
///
/// This does not call `Context::close()` explicitly: `ctx` is an `Arc<Context>`
/// (finding E-R7-1 -- `signer::install` takes an owned `Arc<Context>`, not
/// `&'static Context`/`Box::leak`), so once `shutdown()` above has dropped every
/// `BindingServer`'s own clone, the only clones left are this `Fixture`'s `ctx`
/// field and `manager`'s internal one; both go when `Fixture`'s fields drop after
/// this impl's body runs, which runs `Context::drop`/`close()` for real.
/// `build_fixture` also gives `Context` explicit `socket_dir`/`run_dir` under
/// `_tmp`, so it never allocates anything outside `_tmp` in the first place;
/// `_tmp`'s own ordinary `Drop` -- which runs after this impl's body, since
/// fields drop after a type's own `Drop::drop` -- removes the state dir,
/// `ctx-sockets`/`ctx-run`, and every socket the signer created under
/// `ctx-sockets`.
impl Drop for Fixture {
    fn drop(&mut self) {
        self.manager.shutdown();
    }
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
    let f = build_fixture();
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
    let f = build_fixture();
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
    let f = build_fixture();
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

// Regression test for finding G-R3-4: this file's `Fixture` used to call
// neither `manager.shutdown()` nor anything else at teardown, so none of
// `SshEndToEndTestCase.setUp`'s `addCleanup(self.manager.shutdown)` path was
// ever exercised, and every leftover socket/socket_dir was left for the OS
// to eventually reclaim. `Fixture::drop` (added for this finding) now runs
// `manager.shutdown()` before `_tmp`'s own `Drop` removes the directory tree
// -- this asserts both effects are real once the `Fixture` is gone. (The
// listener-fd half of "no listening socket" needs access to
// `BindingServer`'s private state to check directly and is pinned instead by
// `signer.rs`'s `close_releases_the_listener_even_with_a_client_thread_wedged_on_the_state_lock`.)
#[test]
fn teardown_leaves_no_socket_file_or_signer_created_directory() {
    let socket_path;
    let socket_dir;
    let tmp_root;
    {
        let f = build_fixture();
        f.connection(&f.sshd.host_key_line);
        let grant = f
            .ctx
            .policy
            .create_grant("agent-1", "box", Some(3600), None)
            .unwrap();
        let binding = f.manager.bind("agent-1", "box", &grant.id).unwrap();
        socket_path = binding.socket_path.clone();
        socket_dir = f.manager.socket_dir().to_path_buf();
        tmp_root = f.root.clone();
        assert!(
            socket_path.exists(),
            "sanity: socket should exist while bound"
        );
        assert!(
            socket_dir.exists(),
            "sanity: socket_dir should exist while bound"
        );
        // `f` (and therefore `binding`, whose `Drop` is a no-op -- only
        // `SignerBinding::close`/`BindingServer::close` release anything) is
        // dropped at the end of this block, running `Fixture::drop` ->
        // `manager.shutdown()` -> every `BindingServer::close()` -> then
        // `_tmp`'s own ordinary `Drop` removing the whole directory tree.
    }
    assert!(
        !socket_path.exists(),
        "socket file must not survive Fixture teardown"
    );
    assert!(
        !socket_dir.exists(),
        "signer-created socket_dir must not survive Fixture teardown"
    );
    // Finding G-R4-3: the socket-file/socket_dir checks above miss a
    // detached client thread left wedged past close()'s join deadline (e.g.
    // `signer.rs`'s state-lock wedge regression tests) -- once unblocked, it
    // can resume and write under this fixture's root after the fixture is
    // supposed to be gone. Assert the whole TempDir root is gone too.
    assert!(
        !tmp_root.exists(),
        "the fixture's whole TempDir root must not survive teardown"
    );
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

// ------------------------------------------------------------ exec tool
//
// Port of `ExecToolSshEndToEndTestCase`: the agent-native exec tool drives
// the real ssh client through the signer to a real sshd. Same availability
// rule as above: when sshd cannot start, `build_fixture` fails the test.

/// `INSPECTOR_TEMPLATE`: wraps the real ssh client as the connection's CLI
/// program, records what the exec child can see, then becomes ssh.
const INSPECTOR_TEMPLATE: &str = r#"#!{python}
import json, os, sys, time
entries = {}
for name in sorted(os.listdir(".")):
    if os.path.isfile(name):
        with open(name, "rb") as fh:
            entries[name] = fh.read().hex()
    else:
        entries[name] = None
report = {"argv": sys.argv, "cwd": os.getcwd(), "env": dict(os.environ), "entries": entries}
with open(os.path.join({reports}, "%d-%d.json" % (time.time_ns(), os.getpid())), "w") as fh:
    json.dump(report, fh)
os.execv({ssh}, [{ssh}, *sys.argv[1:]])
"#;

/// The Python test oracle (its `tests.leakcheck` helpers are used for the
/// key-material search).
fn python_interpreter() -> PathBuf {
    std::env::var_os("ZEROPW_PYTHON")
        .map(PathBuf::from)
        .or_else(|| which("python3.12"))
        .expect("python3.12 test oracle")
}

/// `assert_exec_children_held_no_key`, plus `find_secret(blob, material)`
/// for the tool results and audit trail, run by `tests/leakcheck.py`.
const PY_HELD_NO_KEY: &str = r#"
import json, sys
from pathlib import Path
from tests.leakcheck import find_secret, ssh_key_material
reports, pem, blob, minimum = Path(sys.argv[1]), Path(sys.argv[2]).read_text(), Path(sys.argv[3]).read_text(), int(sys.argv[4])
material = ssh_key_material(pem)
assert find_secret(blob, material) is None, "tool results or audit"
files = sorted(reports.glob("*.json"))
assert len(files) >= minimum, "the inspector never ran"
for path in files:
    report = json.loads(path.read_text())
    assert set(report["entries"]) == {"id.pub", "known_hosts"}, sorted(report["entries"])
    for name, content in report["entries"].items():
        assert find_secret(bytes.fromhex(content), material) is None, "run directory file " + name
    env = report["env"]
    names = {name for name in env if not name.startswith("__CF_")}
    assert names == {"PATH", "HOME", "LANG", "TMPDIR", "ZEROPW_RUN_ID", "SSH_AUTH_SOCK"}, sorted(names)
    for name, value in env.items():
        assert find_secret(value, material) is None, "environment variable " + name
    for item in report["argv"]:
        assert find_secret(item, material) is None, "exec child argument"
print(len(files))
"#;

struct ExecFixture {
    f: Fixture,
    registry: std::sync::Arc<zeropw::runs::RunRegistry>,
    grant: String,
    reports: PathBuf,
    private_pem: String,
}

fn build_exec_fixture() -> Fixture2 {
    let f = build_fixture();
    let private_pem = f.user_key.to_openssh_private_key();
    let (_, ssh_bin, _) = tools_available();
    // The connection's CLI program records what the exec child sees, then
    // becomes the real ssh.
    let bin_dir = f.root.join("inspector-bin");
    let reports = f.root.join("inspector-reports");
    // `build_fixture` names an explicit `run_dir` (Python's test leaves it
    // to `Context`, which makes a private one); exec runs are made in it.
    let run_dir = f.root.join("ctx-run");
    for dir in [&bin_dir, &reports, &run_dir] {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let inspector = bin_dir.join("ssh-inspector");
    let py_str = |p: &Path| serde_json::to_string(&p.display().to_string()).unwrap();
    std::fs::write(
        &inspector,
        INSPECTOR_TEMPLATE
            .replace("{python}", &python_interpreter().display().to_string())
            .replace("{reports}", &py_str(&reports))
            .replace("{ssh}", &py_str(&ssh_bin)),
    )
    .unwrap();
    std::fs::set_permissions(&inspector, std::fs::Permissions::from_mode(0o700)).unwrap();
    f.ctx
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
                        i64::from(f.sshd.port),
                        &f.username,
                        vec![f.sshd.host_key_line.clone()],
                    )
                    .unwrap(),
                ),
                Some(
                    P::CliProfile::new(
                        inspector.display().to_string(),
                        "ssh",
                        None,
                        std::collections::BTreeMap::new(),
                    )
                    .unwrap(),
                ),
                0,
                "active",
                "",
                "",
            )
            .unwrap(),
        )
        .unwrap();
    let grant = f
        .ctx
        .policy
        .create_grant("agent-1", "box", Some(3600), None)
        .unwrap()
        .id;
    let registry = zeropw::tools::install(std::sync::Arc::clone(&f.ctx));
    Fixture2(ExecFixture {
        f,
        registry,
        grant,
        reports,
        private_pem,
    })
}

/// `addCleanup(registry.shutdown)` then `addCleanup(manager.shutdown)`:
/// cleanups run LIFO, so the signer shuts down first.
struct Fixture2(ExecFixture);

impl Drop for Fixture2 {
    fn drop(&mut self) {
        self.0.f.manager.shutdown();
        self.0.registry.shutdown("shutdown");
    }
}

impl std::ops::Deref for Fixture2 {
    type Target = ExecFixture;
    fn deref(&self) -> &ExecFixture {
        &self.0
    }
}

impl ExecFixture {
    fn run_exec(&self, remote: &[&str]) -> serde_json::Value {
        let argv: Vec<String> = remote.iter().map(|s| s.to_string()).collect();
        let result = zeropw::tools::exec(&self.f.ctx, "agent-1", "box", &argv, None).unwrap();
        let run_id = result["run_id"].as_str().unwrap();
        let run = self.registry.get(run_id, "agent-1").unwrap();
        self.registry.wait(&run, Some(60.0));
        zeropw::tools::status(&self.f.ctx, "agent-1", run_id).unwrap()
    }
}

// Port of ExecToolSshEndToEndTestCase::test_exec_tool_runs_two_remote_commands_on_one_connection
#[test]
fn exec_tool_runs_two_remote_commands_on_one_connection() {
    let x = build_exec_fixture();
    let first = x.run_exec(&["echo", "exec-tool-first"]);
    assert_eq!(
        (first["state"].as_str(), first["exit_code"].as_i64()),
        (Some("completed"), Some(0)),
        "{first}"
    );
    assert_eq!(first["stdout"].as_str().unwrap().trim(), "exec-tool-first");
    let second = x.run_exec(&["printf", "exec-%s", "second"]);
    assert_eq!(
        (second["state"].as_str(), second["exit_code"].as_i64()),
        (Some("completed"), Some(0)),
        "{second}"
    );
    assert_eq!(second["stdout"].as_str().unwrap().trim(), "exec-second");
    let signs =
        x.f.ctx
            .audit
            .tail(200)
            .unwrap()
            .into_iter()
            .filter(|r| r["event"] == "ssh_sign" && r["result"] == "ok")
            .count();
    assert_eq!(signs, 2);
    // Per-run sockets are closed afterwards.
    assert!(x.f.manager.active_bindings().is_empty());
    let blob = serde_json::json!([
        first,
        second,
        zeropw::tools::list_connections(&x.f.ctx, "agent-1").unwrap(),
        x.f.ctx.audit.tail(500).unwrap(),
    ])
    .to_string();
    assert!(!blob.contains(&x.f.root.join("state").display().to_string()));
    // What both exec children could see: their run directory, its files and
    // their environment; and the results and audit trail above.
    let pem_path = x.f.root.join("private.pem.check");
    let blob_path = x.f.root.join("blob.check");
    std::fs::write(&pem_path, &x.private_pem).unwrap();
    std::fs::write(&blob_path, &blob).unwrap();
    let output = Command::new(python_interpreter())
        .arg("-c")
        .arg(PY_HELD_NO_KEY)
        .arg(&x.reports)
        .arg(&pem_path)
        .arg(&blob_path)
        .arg("2")
        .env(
            "PYTHONPATH",
            Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap(),
        )
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .unwrap();
    std::fs::remove_file(&pem_path).unwrap();
    assert!(
        output.status.success(),
        "exec children or results held key material:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// Port of ExecToolSshEndToEndTestCase::test_exec_tool_after_revocation_is_denied_before_ssh_starts
#[test]
fn exec_tool_after_revocation_is_denied_before_ssh_starts() {
    let x = build_exec_fixture();
    x.f.ctx.policy.revoke_grant(&x.grant).unwrap();
    let error = zeropw::tools::exec(
        &x.f.ctx,
        "agent-1",
        "box",
        &["echo".to_string(), "should-not-run".to_string()],
        None,
    )
    .unwrap_err();
    assert_eq!(
        (error.name.as_ref(), error.reason.as_ref()),
        ("PolicyDenied", "grant_revoked")
    );
    assert_eq!(std::fs::read_dir(&x.reports).unwrap().count(), 0);
}
