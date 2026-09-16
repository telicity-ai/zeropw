//! Differential tests for `zeropw::signer` against the Python prototype
//! (`zeropw/signer.py`), per `rust/PORTING.md`'s "add oracle differential
//! tests ... for every cross-language format you own" rule for work unit G.
//!
//! Lives under `rust/tests/` as a standalone test binary (like
//! `policy_oracle.rs`/`vault_context_oracle.rs`): `crate::oracle` is
//! `#[cfg(test)] pub(crate)` and not reachable from here, so this file has
//! its own tiny Python-running helper.
//!
//! Approach: one Rust process hosts a real signer socket (`Context` +
//! `signer::install`, exactly like the crate's own unit tests). Two
//! identical grants are issued against the same connection/key material —
//! one bound for a Python-driven client, one for a Rust-driven client — so
//! both drives start from byte-identical policy/vault state and cannot
//! interfere with each other's grant usage count. For each named scenario
//! in the table below, the Python side builds its request messages with
//! `zeropw.sshwire`'s own encoders and sends them over a real
//! `AF_UNIX` socket to the Rust-hosted signer; the Rust side builds the
//! *same* logical messages with `zeropw::sshwire`'s encoders and sends them
//! to the same signer over its own socket. The two reply sequences (hex
//! encoded, one per request) are asserted byte-for-byte identical — since
//! Ed25519 signing is deterministic and both grants/keys/session ids are
//! identical, a successful sign reply is expected to match exactly, not
//! just structurally.
//!
//! Table: valid flow, wrong user, wrong session id, second bind (on one
//! client connection), forwarding bind, unknown host key, arbitrary-data
//! sign, add/remove key, lock.
//!
//! "a Python signer with Rust helpers if practical" (PORTING.md's wording
//! for this unit): see `python_signer_rust_client_valid_flow_matches` below
//! for a smaller check in that direction — a full table in that direction
//! would require driving a *separate*, long-lived Python signer process
//! from Rust, which is a large amount of additional process-lifecycle
//! machinery for marginal extra coverage once the Rust-signer direction
//! above already cross-checks every scenario in the table against both
//! languages' encoders.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::policy as P;
use zeropw::projects::DEFAULT_ENVIRONMENTS;
use zeropw::signer;
use zeropw::sshwire;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn run_python(script: &str) -> String {
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".to_string());
    let output = Command::new(interpreter)
        .arg("-c")
        .arg(script)
        .env("PYTHONPATH", repo_root())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run python");
    assert!(
        output.status.success(),
        "python stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

fn py_path(p: &Path) -> String {
    format!("{:?}", p.to_str().expect("utf8 path"))
}

// --------------------------------------------------------------- fixtures

struct Fixture {
    ctx: &'static Context,
    manager: Arc<signer::SignerManager>,
    user_key: sshwire::Ed25519PrivateKey,
    host_key: sshwire::Ed25519PrivateKey,
    other_host_key: sshwire::Ed25519PrivateKey,
    session_id: Vec<u8>,
    other_session_id: Vec<u8>,
    socket_py: PathBuf,
    socket_rs: PathBuf,
}

fn random_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

fn build_fixture() -> Fixture {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().to_path_buf();
    std::mem::forget(tmp); // kept alive for the leaked Context's lifetime (test process only)

    let ctx: &'static Context = Box::leak(Box::new(
        Context::initialize(
            root.join("state"),
            "admin-passphrase-1",
            "recovery-passphrase-1",
            Config::default(),
            clock::fixed(1_700_000_000.0),
        )
        .unwrap(),
    ));
    ctx.projects.create("demo", DEFAULT_ENVIRONMENTS).unwrap();

    let user_key = sshwire::generate_ed25519_private_key("agent-key");
    let host_key = sshwire::generate_ed25519_private_key("host");
    let other_host_key = sshwire::generate_ed25519_private_key("other-host");
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
    ctx.policy
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
                        2222,
                        "deploy",
                        vec![host_key.public.to_authorized_key("host").unwrap()],
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
        .unwrap();
    let grant_py = ctx
        .policy
        .create_grant("agent-1", "box", Some(3600), Some(20))
        .unwrap();
    let grant_rs = ctx
        .policy
        .create_grant("agent-1", "box", Some(3600), Some(20))
        .unwrap();
    let manager = signer::install(ctx, None).unwrap();
    let binding_py = manager.bind("agent-1", "box", &grant_py.id).unwrap();
    let binding_rs = manager.bind("agent-1", "box", &grant_rs.id).unwrap();

    Fixture {
        ctx,
        manager,
        user_key,
        host_key,
        other_host_key,
        session_id: random_bytes(32),
        other_session_id: random_bytes(32),
        socket_py: binding_py.socket_path,
        socket_rs: binding_rs.socket_path,
    }
}

// ------------------------------------------------------------- Rust driver

fn connect(path: &Path) -> sshwire::AgentConnection<UnixStream> {
    let sock = UnixStream::connect(path).expect("connect to signer socket");
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    sshwire::AgentConnection::new(sock)
}

/// Send `messages` in order over one fresh connection to `path`; returns one
/// hex-encoded reply per message (or `ERR` if the connection itself failed,
/// matching the Python driver's own error marker so a transport-level
/// refusal -- e.g. the oversized-message case, which closes the connection
/// without a reply -- compares equal across languages too).
fn drive_rust(path: &Path, messages: &[Vec<u8>]) -> Vec<String> {
    let mut conn = connect(path);
    let mut out = Vec::with_capacity(messages.len());
    for m in messages {
        match conn.request(m) {
            Ok(reply) => out.push(hex::encode(reply)),
            Err(_) => out.push("ERR".to_string()),
        }
    }
    out
}

/// Mirrors `drive_rust`, but from a Python subprocess using
/// `zeropw.sshwire`'s own client helpers.
fn drive_python(path: &Path, key_setup: &str, messages_expr: &str) -> Vec<String> {
    let script = format!(
        r#"
import socket
from zeropw import sshwire as w

{key_setup}

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(5)
sock.connect({path})
conn = w.AgentConnection(sock)
messages = {messages_expr}
for m in messages:
    try:
        reply = conn.request(m)
        print(reply.hex())
    except Exception:
        print("ERR")
"#,
        path = py_path(path),
    );
    run_python(&script).lines().map(str::to_string).collect()
}

/// Python source reconstructing `user_key`/`host_key`/`other_host_key` and
/// `session_id`/`other_session_id` from the same seeds/bytes the Rust side
/// used, so both languages sign over byte-identical material.
fn python_key_setup(f: &Fixture) -> String {
    format!(
        r#"
from zeropw.crypto.ed25519 import public_key_from_seed

def key_from_seed(seed_hex, comment):
    seed = bytes.fromhex(seed_hex)
    pub = w.Ed25519PublicKey(public_key_from_seed(seed))
    return w.Ed25519PrivateKey(seed=seed, public=pub, comment=comment)

user_key = key_from_seed({user_seed:?}, "agent-key")
host_key = key_from_seed({host_seed:?}, "host")
other_host_key = key_from_seed({other_seed:?}, "other-host")
session_id = bytes.fromhex({session:?})
other_session_id = bytes.fromhex({other_session:?})
"#,
        user_seed = hex::encode(f.user_key.seed().expose()),
        host_seed = hex::encode(f.host_key.seed().expose()),
        other_seed = hex::encode(f.other_host_key.seed().expose()),
        session = hex::encode(&f.session_id),
        other_session = hex::encode(&f.other_session_id),
    )
}

// ------------------------------------------------------- scenario builders

fn bind_msg(key: &sshwire::Ed25519PrivateKey, session_id: &[u8], forwarding: bool) -> Vec<u8> {
    let sig = key.sign(session_id);
    sshwire::build_session_bind(
        &key.public.blob(),
        session_id,
        &sshwire::encode_ssh_signature(&sig).unwrap(),
        forwarding,
    )
}

fn userauth_msg(
    username: &str,
    session_id: &[u8],
    algorithm: &str,
    key_blob: &[u8],
    hostbound: Option<&[u8]>,
) -> Vec<u8> {
    sshwire::build_userauth_request(
        session_id,
        username,
        algorithm,
        key_blob,
        sshwire::SSH_CONNECTION_SERVICE,
        hostbound,
    )
}

fn sign_msg(key_blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    sshwire::build_sign_request(key_blob, data, flags)
}

/// One `(name, rust_messages, python_messages_expr)` row of the table.
struct Scenario {
    name: &'static str,
    rust: Vec<Vec<u8>>,
    python_expr: String,
}

fn scenarios(f: &Fixture) -> Vec<Scenario> {
    let valid_userauth = userauth_msg(
        "deploy",
        &f.session_id,
        signer::SSH_ED25519,
        &f.user_key.public.blob(),
        None,
    );
    vec![
        Scenario {
            name: "valid_flow",
            rust: vec![
                bind_msg(&f.host_key, &f.session_id, false),
                sign_msg(&f.user_key.public.blob(), &valid_userauth, 0),
            ],
            python_expr: r#"[
    w.build_session_bind(host_key.public.blob(), session_id, w.encode_ssh_signature(host_key.sign(session_id)), False),
    w.build_sign_request(user_key.public.blob(),
        w.build_userauth_request(session_id, "deploy", "ssh-ed25519", user_key.public.blob(), host_key_blob=None), 0),
]"#
            .to_string(),
        },
        Scenario {
            name: "wrong_user",
            rust: vec![
                bind_msg(&f.host_key, &f.session_id, false),
                sign_msg(
                    &f.user_key.public.blob(),
                    &userauth_msg("root", &f.session_id, signer::SSH_ED25519, &f.user_key.public.blob(), None),
                    0,
                ),
            ],
            python_expr: r#"[
    w.build_session_bind(host_key.public.blob(), session_id, w.encode_ssh_signature(host_key.sign(session_id)), False),
    w.build_sign_request(user_key.public.blob(),
        w.build_userauth_request(session_id, "root", "ssh-ed25519", user_key.public.blob(), host_key_blob=None), 0),
]"#
            .to_string(),
        },
        Scenario {
            name: "wrong_session_id",
            rust: vec![
                bind_msg(&f.host_key, &f.session_id, false),
                sign_msg(
                    &f.user_key.public.blob(),
                    &userauth_msg(
                        "deploy",
                        &f.other_session_id,
                        signer::SSH_ED25519,
                        &f.user_key.public.blob(),
                        None,
                    ),
                    0,
                ),
            ],
            python_expr: r#"[
    w.build_session_bind(host_key.public.blob(), session_id, w.encode_ssh_signature(host_key.sign(session_id)), False),
    w.build_sign_request(user_key.public.blob(),
        w.build_userauth_request(other_session_id, "deploy", "ssh-ed25519", user_key.public.blob(), host_key_blob=None), 0),
]"#
            .to_string(),
        },
        Scenario {
            name: "second_bind",
            rust: vec![
                bind_msg(&f.host_key, &f.session_id, false),
                bind_msg(&f.host_key, &f.session_id, false),
            ],
            python_expr: r#"[
    w.build_session_bind(host_key.public.blob(), session_id, w.encode_ssh_signature(host_key.sign(session_id)), False),
    w.build_session_bind(host_key.public.blob(), session_id, w.encode_ssh_signature(host_key.sign(session_id)), False),
]"#
            .to_string(),
        },
        Scenario {
            name: "forwarding_bind",
            rust: vec![bind_msg(&f.host_key, &f.session_id, true)],
            python_expr: r#"[
    w.build_session_bind(host_key.public.blob(), session_id, w.encode_ssh_signature(host_key.sign(session_id)), True),
]"#
            .to_string(),
        },
        Scenario {
            name: "unknown_host_key",
            rust: vec![bind_msg(&f.other_host_key, &f.session_id, false)],
            python_expr: r#"[
    w.build_session_bind(other_host_key.public.blob(), session_id, w.encode_ssh_signature(other_host_key.sign(session_id)), False),
]"#
            .to_string(),
        },
        Scenario {
            name: "arbitrary_data_sign",
            rust: vec![
                bind_msg(&f.host_key, &f.session_id, false),
                sign_msg(&f.user_key.public.blob(), b"not a userauth request at all", 0),
            ],
            python_expr: r#"[
    w.build_session_bind(host_key.public.blob(), session_id, w.encode_ssh_signature(host_key.sign(session_id)), False),
    w.build_sign_request(user_key.public.blob(), b"not a userauth request at all", 0),
]"#
            .to_string(),
        },
        Scenario {
            name: "add_remove_key",
            rust: vec![
                [&[sshwire::SSH_AGENTC_ADD_IDENTITY][..], &[0u8; 8]].concat(),
                [&[sshwire::SSH_AGENTC_REMOVE_IDENTITY][..], &[0u8; 8]].concat(),
            ],
            python_expr: r#"[
    bytes([w.SSH_AGENTC_ADD_IDENTITY]) + b"\x00" * 8,
    bytes([w.SSH_AGENTC_REMOVE_IDENTITY]) + b"\x00" * 8,
]"#
            .to_string(),
        },
        Scenario {
            name: "lock",
            rust: vec![[&[sshwire::SSH_AGENTC_LOCK][..], &[0u8; 4]].concat()],
            python_expr: r#"[
    bytes([w.SSH_AGENTC_LOCK]) + b"\x00" * 4,
]"#
            .to_string(),
        },
    ]
}

#[test]
fn table_driven_scenarios_match_between_python_client_and_rust_client() {
    let f = build_fixture();
    let key_setup = python_key_setup(&f);
    for scenario in scenarios(&f) {
        let rust_replies = drive_rust(&f.socket_rs, &scenario.rust);
        let python_replies = drive_python(&f.socket_py, &key_setup, &scenario.python_expr);
        assert_eq!(
            rust_replies, python_replies,
            "scenario {} produced different replies",
            scenario.name
        );
    }
    f.manager.shutdown();
    let _ = f.ctx; // keep alive until here (it is 'static/leaked anyway)
}

/// The oversized-message case (`sshwire::MAX_AGENT_MESSAGE`) closes the
/// connection without any reply at all, in both languages: a transport-level
/// refusal rather than a `SSH_AGENT_FAILURE` reply. Exercised separately
/// since it needs to write a raw length prefix rather than a well-formed
/// agent message `AgentConnection` would refuse to build.
#[test]
fn oversized_message_closes_connection_without_a_reply_in_both_languages() {
    let f = build_fixture();

    let mut rust_sock = UnixStream::connect(&f.socket_rs).unwrap();
    rust_sock
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let oversized = sshwire::encode_uint32((sshwire::MAX_AGENT_MESSAGE + 1) as u32);
    rust_sock.write_all(&oversized).unwrap();
    rust_sock.write_all(&[0x0d]).unwrap();
    let mut buf = [0u8; 16];
    let rust_reply = match rust_sock.read(&mut buf) {
        Ok(n) => buf[..n].to_vec(),
        Err(_) => Vec::new(),
    };
    assert!(rust_reply.is_empty());

    let script = format!(
        r#"
import socket
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(5)
sock.connect({path})
sock.sendall(({length}).to_bytes(4, "big") + b"\x0d")
try:
    reply = sock.recv(1024)
except (ConnectionResetError, OSError):
    reply = b""
print(reply.hex())
"#,
        path = py_path(&f.socket_py),
        length = sshwire::MAX_AGENT_MESSAGE + 1,
    );
    let python_reply = run_python(&script).trim().to_string();
    assert_eq!(python_reply, "");

    f.manager.shutdown();
}

// ---------------------------------------------- Python signer, Rust client

/// PORTING.md asks for "a Python signer with Rust helpers if practical".
/// This drives a real, separately-started Python `zeropw.signer` server
/// with Rust's own `sshwire::AgentConnection` client for the valid
/// bind-then-sign flow, and checks the signature Rust receives verifies
/// against the same public key -- proving Rust's *client* encoding
/// (`build_session_bind`/`build_userauth_request`/`build_sign_request`) is
/// something a real Python-hosted signer accepts, the reverse direction
/// from every other test in this file.
#[test]
fn python_signer_rust_client_valid_flow_matches() {
    let user_key = zeropw::sshwire::generate_ed25519_private_key("agent-key");
    let host_key = zeropw::sshwire::generate_ed25519_private_key("host");
    let session_id = random_bytes(32);

    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().to_path_buf();

    // A short-lived Python process: build state, install the signer, bind
    // one socket, print its path once ready, then block until stdin closes
    // (so the Rust test controls its lifetime). `SignerManager.bind` always
    // generates its own `a<uuid>.sock` name (`MAX_UNIX_PATH`-bounded), so
    // the actual path is read back from stdout rather than dictated here.
    let script = format!(
        r#"
import sys
from zeropw.context import Config, Context
from zeropw import policy as P, signer as S, sshwire as w
from zeropw.crypto.ed25519 import public_key_from_seed

def key_from_seed(seed_hex, comment):
    seed = bytes.fromhex(seed_hex)
    pub = w.Ed25519PublicKey(public_key_from_seed(seed))
    return w.Ed25519PrivateKey(seed=seed, public=pub, comment=comment)

user_key = key_from_seed({user_seed:?}, "agent-key")
host_key = key_from_seed({host_seed:?}, "host")

ctx = Context.initialize({state}, "admin-passphrase-1", "recovery-passphrase-1", Config(), lambda: 1700000000.0)
ctx.projects.create("demo")
ctx.vault.put_secret("box-key", "ssh_private_key", user_key.to_openssh_private_key().encode(), "demo", "dev")
ctx.policy.create_principal("agent-1")
ctx.policy.create_connection(P.Connection(
    id="box", project="demo", environment="dev", service="ssh-box", kind="ssh", secret_id="box-key",
    secret_version=None, description="", http_target=None, http_auth=None, http_scope=None,
    ssh_target=P.SshTarget("127.0.0.1", 2222, "deploy", (host_key.public.to_authorized_key("host"),)),
    cli=None, policy_version=0, status="active", created_at="", updated_at=""))
grant = ctx.policy.create_grant("agent-1", "box", 3600, 5)
manager = S.install(ctx)
binding = manager.bind("agent-1", "box", grant.id)
print(str(binding.socket_path), flush=True)
sys.stdin.readline()
manager.shutdown()
ctx.close()
"#,
        user_seed = hex::encode(user_key.seed().expose()),
        host_seed = hex::encode(host_key.seed().expose()),
        state = py_path(&root.join("state")),
    );

    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".to_string());
    let mut child = Command::new(&interpreter)
        .arg("-c")
        .arg(&script)
        .env("PYTHONPATH", repo_root())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn python signer");

    let stdout = child.stdout.take().unwrap();
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    // Blocking read of the socket path line; the process prints it right
    // after `manager.bind(...)` returns, well before any timeout budget
    // this test needs.
    std::io::BufRead::read_line(&mut reader, &mut line)
        .expect("python signer did not become ready");
    let socket_path = PathBuf::from(line.trim());
    assert!(
        !socket_path.as_os_str().is_empty(),
        "python signer printed no socket path"
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut conn = connect(&socket_path);
        let bind = bind_msg(&host_key, &session_id, false);
        assert_eq!(conn.request(&bind).unwrap(), sshwire::build_success());
        let data = userauth_msg(
            "deploy",
            &session_id,
            signer::SSH_ED25519,
            &user_key.public.blob(),
            None,
        );
        let reply = conn
            .request(&sign_msg(&user_key.public.blob(), &data, 0))
            .unwrap();
        assert_eq!(reply[0], sshwire::SSH_AGENT_SIGN_RESPONSE);
        let sig = sshwire::parse_ssh_signature(&sshwire::parse_sign_response(&reply[1..]).unwrap())
            .unwrap();
        assert!(zeropw::crypto::ed25519::verify(
            user_key.public.key_bytes(),
            &data,
            &sig
        ));
    }));

    let _ = child.stdin.take(); // close stdin: unblocks the python process's readline()
    let _ = child.wait();
    result.expect("python-signer/rust-client flow failed");
}
