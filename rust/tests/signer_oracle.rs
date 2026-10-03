//! SSH agent wire tests for `zeropw::signer` against a golden fixture the
//! Python prototype's signer produced once
//! (`tests/fixtures/python/signer/GENERATE.md`). The SSH agent protocol is a
//! wire format another party parses (`PORTING.md` §0 boundary 2).
//!
//! The fixture holds, for fixed key seeds and session identifiers, every
//! request message of a scenario table as built by `zeropw.sshwire`'s
//! encoders, and the replies the prototype's `zeropw.signer` sent back. Two
//! checks follow: Rust's encoders build byte-identical request messages, and
//! the Rust signer -- bound to the same connection, key and host keys --
//! answers every message with byte-identical replies (Ed25519 signing is
//! deterministic, so a successful sign reply matches exactly, and its
//! signature verifies).
//!
//! Table: valid flow, wrong user, wrong session id, second bind (on one
//! client connection), forwarding bind, unknown host key, arbitrary-data
//! sign, add/remove key, lock, identities.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::policy as P;
use zeropw::projects::DEFAULT_ENVIRONMENTS;
use zeropw::signer;
use zeropw::sshwire;

const AGENT_REPLIES: &str = include_str!("fixtures/python/signer/agent_replies.json");

fn fixture_json() -> Value {
    serde_json::from_str(AGENT_REPLIES).unwrap()
}

fn fixture_bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

// --------------------------------------------------------------- fixtures

struct Fixture {
    _tmp: tempfile::TempDir,
    manager: Arc<signer::SignerManager>,
    user_key: sshwire::Ed25519PrivateKey,
    host_key: sshwire::Ed25519PrivateKey,
    other_host_key: sshwire::Ed25519PrivateKey,
    session_id: Vec<u8>,
    other_session_id: Vec<u8>,
    socket: PathBuf,
}

/// `shutdown()` on every case, like the prototype's `tearDown`.
impl Drop for Fixture {
    fn drop(&mut self) {
        self.manager.shutdown();
    }
}

fn build_fixture() -> Fixture {
    let data = fixture_json();
    let key = |field: &str, comment: &str| {
        sshwire::Ed25519PrivateKey::from_seed(&fixture_bytes(&data[field]), comment).unwrap()
    };
    let user_key = key("user_seed", "agent-key");
    let host_key = key("host_seed", "host");
    let other_host_key = key("other_host_seed", "other-host");

    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().to_path_buf();
    // Explicit `socket_dir`/`run_dir` under `root`, kept alive as `_tmp`.
    let config = Config {
        socket_dir: Some(root.join("ctx-sockets")),
        run_dir: Some(root.join("ctx-run")),
        ..Config::default()
    };
    let ctx: Arc<Context> = Arc::new(
        Context::initialize(
            root.join("state"),
            "admin-passphrase-1",
            "recovery-passphrase-1",
            config,
            clock::fixed(1_700_000_000.0),
        )
        .unwrap(),
    );
    ctx.projects.create("demo", DEFAULT_ENVIRONMENTS).unwrap();
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
                        data["username"].as_str().unwrap(),
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
    let grant = ctx
        .policy
        .create_grant("agent-1", "box", Some(3600), Some(20))
        .unwrap();
    let manager = signer::install(ctx, None).unwrap();
    let binding = manager.bind("agent-1", "box", &grant.id).unwrap();

    Fixture {
        _tmp: tmp,
        manager,
        user_key,
        host_key,
        other_host_key,
        session_id: fixture_bytes(&data["session_id"]),
        other_session_id: fixture_bytes(&data["other_session_id"]),
        socket: binding.socket_path,
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
/// the generator's own marker).
fn drive(path: &Path, messages: &[Vec<u8>]) -> Vec<String> {
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

fn userauth_msg(username: &str, session_id: &[u8], key_blob: &[u8]) -> Vec<u8> {
    sshwire::build_userauth_request(
        session_id,
        username,
        signer::SSH_ED25519,
        key_blob,
        sshwire::SSH_CONNECTION_SERVICE,
        None,
    )
}

fn sign_msg(key_blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    sshwire::build_sign_request(key_blob, data, flags)
}

/// The scenario table, built with Rust's own encoders, in fixture order.
fn scenarios(f: &Fixture) -> Vec<(&'static str, Vec<Vec<u8>>)> {
    let user_blob = f.user_key.public.blob();
    let bind = bind_msg(&f.host_key, &f.session_id, false);
    vec![
        (
            "valid_flow",
            vec![
                bind.clone(),
                sign_msg(
                    &user_blob,
                    &userauth_msg("deploy", &f.session_id, &user_blob),
                    0,
                ),
            ],
        ),
        (
            "wrong_user",
            vec![
                bind.clone(),
                sign_msg(
                    &user_blob,
                    &userauth_msg("root", &f.session_id, &user_blob),
                    0,
                ),
            ],
        ),
        (
            "wrong_session_id",
            vec![
                bind.clone(),
                sign_msg(
                    &user_blob,
                    &userauth_msg("deploy", &f.other_session_id, &user_blob),
                    0,
                ),
            ],
        ),
        ("second_bind", vec![bind.clone(), bind.clone()]),
        (
            "forwarding_bind",
            vec![bind_msg(&f.host_key, &f.session_id, true)],
        ),
        (
            "unknown_host_key",
            vec![bind_msg(&f.other_host_key, &f.session_id, false)],
        ),
        (
            "arbitrary_data_sign",
            vec![
                bind,
                sign_msg(&user_blob, b"not a userauth request at all", 0),
            ],
        ),
        (
            "add_remove_key",
            vec![
                [&[sshwire::SSH_AGENTC_ADD_IDENTITY][..], &[0u8; 8]].concat(),
                [&[sshwire::SSH_AGENTC_REMOVE_IDENTITY][..], &[0u8; 8]].concat(),
            ],
        ),
        (
            "lock",
            vec![[&[sshwire::SSH_AGENTC_LOCK][..], &[0u8; 4]].concat()],
        ),
        (
            "request_identities",
            vec![vec![sshwire::SSH_AGENTC_REQUEST_IDENTITIES]],
        ),
    ]
}

#[test]
fn rust_encoders_build_the_python_request_messages() {
    let f = build_fixture();
    let data = fixture_json();
    let expected = data["scenarios"].as_array().unwrap();
    let actual = scenarios(&f);
    assert_eq!(actual.len(), expected.len());
    for ((name, messages), want) in actual.iter().zip(expected) {
        assert_eq!(want["name"], *name);
        let hex: Vec<String> = messages.iter().map(hex::encode).collect();
        assert_eq!(
            Value::from(hex),
            want["messages"],
            "scenario {name}: request bytes"
        );
    }
}

#[test]
fn signer_replies_match_the_python_signer() {
    let f = build_fixture();
    let data = fixture_json();
    for scenario in data["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let messages: Vec<Vec<u8>> = scenario["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(fixture_bytes)
            .collect();
        let replies = drive(&f.socket, &messages);
        assert_eq!(
            Value::from(replies),
            scenario["replies"],
            "scenario {name} produced different replies"
        );
    }
    // The fixture's valid-flow signature verifies against the bound key.
    let valid = &data["scenarios"][0];
    assert_eq!(valid["name"], "valid_flow");
    let reply = fixture_bytes(&valid["replies"][1]);
    assert_eq!(reply[0], sshwire::SSH_AGENT_SIGN_RESPONSE);
    let sig =
        sshwire::parse_ssh_signature(&sshwire::parse_sign_response(&reply[1..]).unwrap()).unwrap();
    let data_signed = userauth_msg("deploy", &f.session_id, &f.user_key.public.blob());
    assert!(zeropw::crypto::ed25519::verify(
        f.user_key.public.key_bytes(),
        &data_signed,
        &sig
    ));
    f.manager.shutdown();
}

/// An oversized message (`sshwire::MAX_AGENT_MESSAGE` + 1) closes the
/// connection without any reply at all, as the prototype's signer did: a
/// transport-level refusal rather than a `SSH_AGENT_FAILURE` reply.
#[test]
fn oversized_message_closes_connection_without_a_reply() {
    let f = build_fixture();
    let data = fixture_json();
    assert_eq!(
        data["max_agent_message"].as_u64().unwrap(),
        sshwire::MAX_AGENT_MESSAGE as u64
    );
    assert_eq!(data["oversized_reply"], "");

    let mut sock = UnixStream::connect(&f.socket).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let oversized = sshwire::encode_uint32((sshwire::MAX_AGENT_MESSAGE + 1) as u32);
    sock.write_all(&oversized).unwrap();
    sock.write_all(&[0x0d]).unwrap();
    let mut buf = [0u8; 16];
    let reply = match sock.read(&mut buf) {
        Ok(n) => buf[..n].to_vec(),
        Err(_) => Vec::new(),
    };
    assert!(reply.is_empty());
    f.manager.shutdown();
}

// ------------------------------------------------ non-ASCII socket_dir (G-R2-3)

/// Regression test for finding G-R2-3: `SignerManager::bind`/`choose_socket_dir`
/// used to measure UTF-8 *bytes* (`.to_string_lossy().len()`) where Python
/// measures Unicode *characters* (`len(str(path))`). A `socket_dir` built
/// from multi-byte characters diverges at exactly the characters that make
/// the two counts differ: this candidate is 75 characters (comfortably under
/// `MAX_UNIX_PATH` = 100) but 145 UTF-8 bytes (over it), so the old
/// byte-counting code silently replaced it with a private fallback temp dir
/// and then refused to bind inside it at all (`socket_path_too_long`), while
/// Python (and this crate, after the fix) use the configured directory
/// directly.
#[test]
fn non_ascii_socket_dir_length_is_measured_in_characters() {
    let tmp = tempfile::TempDir::new().unwrap();
    // A short, literal `/tmp`-rooted base (unlike `tempfile::TempDir`, whose
    // own directory can itself already be a long per-process path, e.g. on
    // macOS -- see `signer.rs`'s `choose_socket_dir_sets_leaf_mode_0700_...`
    // test for the same concern), so the character budget below is spent on
    // the non-ASCII component being tested, not consumed by the platform's
    // own temp-dir naming.
    let base = PathBuf::from("/tmp").join(format!("zpws-oracle-{}", std::process::id()));
    std::fs::create_dir_all(&base).unwrap();
    let base_chars = base.to_string_lossy().chars().count();
    // `choose_socket_dir` probes with a 24-character placeholder name (see
    // `signer.rs`), a wider margin than the real ~18-character socket
    // filename `bind` uses -- budget against the probe's 24 so the
    // directory is actually accepted as configured (not silently replaced
    // by a fallback temp dir). Fill the remainder with 2-byte-per-character
    // "é"s, so the total is comfortably within the character limit but well
    // over it in UTF-8 bytes -- exactly the gap finding G-R2-3 closed.
    // `choose_socket_dir`'s own probe is
    // `candidate.join("s" * 24)`, i.e. `base_chars + 1 (sep) + non_ascii_chars
    // + 1 (sep) + 24` characters, which must stay at or under 100.
    let non_ascii_chars = 100usize.saturating_sub(base_chars + 26).min(70);
    assert!(
        non_ascii_chars >= 20,
        "base path {base:?} ({base_chars} chars) leaves too little budget for this test"
    );
    let candidate = base.join("é".repeat(non_ascii_chars));
    let total_chars = candidate.to_string_lossy().chars().count();
    let total_bytes = candidate.to_string_lossy().len();
    assert!(
        total_chars <= 100,
        "candidate must fit MAX_UNIX_PATH in characters: {total_chars}"
    );
    assert!(
        total_bytes > 100,
        "candidate must exceed MAX_UNIX_PATH in bytes for this test to be meaningful: {total_bytes}"
    );

    // Explicit `socket_dir`/`run_dir` under `tmp` (unrelated to `candidate`,
    // which is what this test actually exercises via `signer::install`'s own
    // override below): otherwise `Context::initialize` would default them to
    // fresh private temp dirs under the *system* temp dir -- harmless now that
    // `ctx` is a properly-dropped `Arc<Context>` (finding E-R7-1), but still
    // worth keeping self-contained under `tmp`.
    let ctx: Arc<Context> = Arc::new(
        Context::initialize(
            tmp.path().join("state"),
            "admin-passphrase-1",
            "recovery-passphrase-1",
            Config {
                socket_dir: Some(tmp.path().join("ctx-sockets")),
                run_dir: Some(tmp.path().join("ctx-run")),
                ..Config::default()
            },
            clock::fixed(1_700_000_000.0),
        )
        .unwrap(),
    );
    ctx.projects.create("demo", DEFAULT_ENVIRONMENTS).unwrap();
    let user_key = sshwire::generate_ed25519_private_key("agent-key");
    let host_key = sshwire::generate_ed25519_private_key("host");
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
    let grant = ctx
        .policy
        .create_grant("agent-1", "box", Some(3600), Some(5))
        .unwrap();

    // Rust: the configured directory must be used as-is (no silent fallback
    // to a private temp dir) -- `choose_socket_dir`'s `mkdir` has no socket
    // byte-length limit at all, so this is a clean, platform-independent
    // check of the character-vs-byte counting fix.
    let manager = signer::install(ctx, Some(candidate.clone())).unwrap();
    assert_eq!(
        manager.socket_dir(),
        candidate.as_path(),
        "Rust must use the configured non-ASCII socket_dir directly, not fall back"
    );
    // `bind`'s own pre-`socket()` length check must accept this path (it
    // fits `MAX_UNIX_PATH + 3` *characters*), i.e. must never fail with
    // `Unsupported("socket_path_too_long")` here. Whether the *subsequent*
    // real `bind(2)` syscall itself then succeeds is a separate question:
    // this candidate's full socket path is long enough in UTF-8 *bytes*
    // (each "é" is 2 bytes) that it can independently exceed the kernel's
    // own `sockaddr_un` byte limit (~104 bytes on macOS) -- a real
    // both-languages-shared limitation this crate's `MAX_UNIX_PATH`
    // constant is deliberately calibrated close to, and not what finding
    // G-R2-3 is about.
    match manager.bind("agent-1", "box", &grant.id) {
        Ok(binding) => assert!(binding.socket_path.exists()),
        Err(e) => {
            assert!(
                !(e.is(zeropw::errors::ErrorClass::Unsupported)
                    && e.reason == "socket_path_too_long"),
                "bind() rejected a path that fits MAX_UNIX_PATH + 3 *characters* as \
                 too long -- it must be measuring UTF-8 bytes instead (finding \
                 G-R2-3): {e:?}"
            );
        }
    }

    manager.shutdown();
    let _ = std::fs::remove_dir_all(&base);
    let _ = tmp; // kept alive until here
}
