//! Independent gpt-6-astra boundary review of f7d160bd927f008c3b87974331f861c62d87b3e1.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Barrier, mpsc};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use zeropw::context::{Config, Context};
use zeropw::crypto::{chacha20poly1305 as aead, x25519};
use zeropw::kms::WrappedKey;
use zeropw::pybase64::{b64decode, b64encode};
use zeropw::pyjson::{self, DumpOptions};
use zeropw::team::identity::DeviceKey;
use zeropw::team::transport::{
    self as t, InProcessTransport, MembershipCheck, Session, TcpTransport, Transport,
};
use zeropw::team::{commit, envelope, membership, sync};

fn canon(value: &Value) -> Vec<u8> {
    pyjson::dumps(value, DumpOptions::compact_sorted())
        .unwrap()
        .into_bytes()
}
fn send_frame(stream: &mut TcpStream, bytes: &[u8]) {
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(bytes).unwrap();
}
fn recv_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).unwrap();
    let len = u32::from_be_bytes(header) as usize;
    assert!(len <= t::MAX_FRAME_BYTES);
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes).unwrap();
    bytes
}
fn raw_connect(server: &TcpTransport) -> TcpStream {
    let stream = TcpStream::connect(server.bound_address().unwrap()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
}
fn member_check(env: &str, key: &DeviceKey) -> MembershipCheck {
    let env = env.to_owned();
    let record = key.record().unwrap();
    Arc::new(move |e, fp| (e == env && fp == record.fingerprint()).then(|| record.clone()))
}
fn hello(key: &DeviceKey, env: &str, ephemeral: &[u8]) -> Vec<u8> {
    canon(&json!({"version":1,"env_id":env,"ea":b64encode(ephemeral),
        "device":key.record().unwrap().to_dict(),"nonce":b64encode(&[3;32])}))
}
fn listener(
    key: DeviceKey,
    members: MembershipCheck,
    cap: usize,
) -> (
    Arc<TcpTransport>,
    mpsc::Receiver<Arc<dyn Session>>,
    mpsc::Receiver<String>,
) {
    let server = TcpTransport::new(key, members, cap);
    let (accepted_tx, accepted_rx) = mpsc::channel();
    let (failed_tx, failed_rx) = mpsc::channel();
    server.set_handshake_failed(Some(Arc::new(move |reason, _| {
        let _ = failed_tx.send(reason.to_owned());
    })));
    server
        .listen_arc(
            "127.0.0.1:0",
            Arc::new(move |s| {
                accepted_tx.send(s).unwrap();
            }),
        )
        .unwrap();
    (server, accepted_rx, failed_rx)
}

#[test]
fn raw_tcp_rejects_nonmember_wrong_env_invalid_env_and_low_order_without_response() {
    let a = DeviceKey::generate();
    let b = DeviceKey::generate();
    let stranger = DeviceKey::generate();
    let env = commit::new_env_id(&a.fingerprint().unwrap()).unwrap();
    let other_env = commit::new_env_id(&a.fingerprint().unwrap()).unwrap();
    let (server, sessions, failures) = listener(b, member_check(&env, &a), 4);
    let private = x25519::generate_private();
    let public = x25519::public_key(private.expose()).unwrap();
    for (who, candidate_env, point, reason) in [
        (&stranger, env.as_str(), public.as_slice(), "not_member"),
        (&a, other_env.as_str(), public.as_slice(), "not_member"),
        (&a, "invalid", public.as_slice(), "invalid_env_id"),
        (&a, env.as_str(), &[0u8; 32][..], "low_order_point"),
    ] {
        let mut stream = raw_connect(&server);
        send_frame(&mut stream, &hello(who, candidate_env, point));
        assert_eq!(
            stream.read(&mut [0u8; 1]).unwrap(),
            0,
            "rejected peer got data"
        );
        assert_eq!(
            failures.recv_timeout(Duration::from_secs(3)).unwrap(),
            reason
        );
    }
    assert!(sessions.try_recv().is_err());
    server.shutdown();
}

#[test]
fn raw_tcp_wrong_role_signature_is_rejected() {
    let a = DeviceKey::generate();
    let env = commit::new_env_id(&a.fingerprint().unwrap()).unwrap();
    let (server, sessions, failures) = listener(DeviceKey::generate(), member_check(&env, &a), 4);
    let private = x25519::generate_private();
    let mut stream = raw_connect(&server);
    let first = hello(&a, &env, &x25519::public_key(private.expose()).unwrap());
    send_frame(&mut stream, &first);
    let second: Value =
        pyjson::loads(std::str::from_utf8(&recv_frame(&mut stream)).unwrap()).unwrap();
    let mut transcript = first;
    transcript.extend(b64decode(second["eb"].as_str().unwrap()).unwrap());
    transcript.extend(canon(&second["device"]));
    let mut wrong_role = t::HANDSHAKE_RESPONDER_CONTEXT.to_vec();
    wrong_role.extend(transcript);
    send_frame(
        &mut stream,
        &canon(&json!({"sig":b64encode(&a.sign(&wrong_role).unwrap())})),
    );
    assert_eq!(stream.read(&mut [0u8; 1]).unwrap(), 0);
    assert_eq!(
        failures.recv_timeout(Duration::from_secs(3)).unwrap(),
        "signature_invalid"
    );
    assert!(sessions.try_recv().is_err());
    server.shutdown();
}

#[test]
fn raw_tcp_replayed_responder_message_is_rejected_in_new_session() {
    let a = DeviceKey::generate();
    let b = DeviceKey::generate();
    let env = commit::new_env_id(&a.fingerprint().unwrap()).unwrap();
    let client = TcpTransport::new(a.clone(), member_check(&env, &b), 2);
    let (server, _, _) = listener(b, member_check(&env, &a), 2);
    let private = x25519::generate_private();
    let mut stream = raw_connect(&server);
    send_frame(
        &mut stream,
        &hello(&a, &env, &x25519::public_key(private.expose()).unwrap()),
    );
    let old_response = recv_frame(&mut stream);
    drop(stream);
    let replay = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = replay.local_addr().unwrap().to_string();
    let responder = std::thread::spawn(move || {
        let (mut socket, _) = replay.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let _ = recv_frame(&mut socket);
        send_frame(&mut socket, &old_response);
    });
    let result = client.dial_session(&address, &env, None);
    assert!(matches!(result, Err(t::SessionClosed("signature_invalid"))));
    responder.join().unwrap();
    server.shutdown();
}

/// `sanitize_incident_summary` and `Fact::from_dict` over a boundary corpus
/// of peer-supplied values. Expected outcomes were measured against the
/// Python prototype's `sanitize_incident_summary`/`Fact.from_dict`: a
/// summary keeps only a valid `incident_id` plus in-bounds `uses` (a
/// non-negative int32), `scope` (printable text up to 200 characters) and
/// `connection_ids` (up to 100 de-duplicated strings of up to 64
/// characters); anything else is dropped.
#[test]
fn incident_sanitizer_and_fact_conversion_boundary_corpus_match_python() {
    for invalid in [
        Value::Null,
        json!([]),
        json!({}),
        json!({"incident_id":"../escape"}),
    ] {
        assert_eq!(
            sync::sanitize_incident_summary(&invalid)
                .unwrap_err()
                .reason,
            "team_incident_summary_invalid",
            "{invalid}"
        );
    }
    let id = || json!({"incident_id": "0123456789abcdef"});
    let with = |key: &str, value: Value| {
        let mut summary = id();
        summary[key] = value;
        summary
    };
    let cases = [
        (Value::Null, id()),
        (json!(true), id()),
        (json!(1.0), id()),
        (json!(-1), id()),
        (json!(0), with("uses", json!(0))),
        (json!(2147483647_i64), with("uses", json!(2147483647_i64))),
        (json!(2147483648_i64), id()),
        (json!("x"), with("scope", json!("x"))),
        (
            json!("\u{e9}".repeat(200)),
            with("scope", json!("\u{e9}".repeat(200))),
        ),
        (json!("\u{e9}".repeat(201)), id()),
        (json!("control\u{007f}"), id()),
        (json!([]), id()),
        (
            json!(["a", "b", "a"]),
            with("connection_ids", json!(["a", "b"])),
        ),
        (json!(["a", false]), id()),
        (
            json!(["\u{e9}".repeat(64)]),
            with("connection_ids", json!(["\u{e9}".repeat(64)])),
        ),
        (json!(["\u{e9}".repeat(65)]), id()),
        (json!(vec!["a"; 101]), id()),
    ];
    for (value, expected) in cases {
        let case = json!({"incident_id":"0123456789abcdef","uses":value,"scope":value,"connection_ids":value,"unknown":"drop"});
        assert_eq!(
            sync::sanitize_incident_summary(&case).unwrap(),
            expected,
            "{case}"
        );
    }
    let fact = |target: Value| json!({"format":sync::FACT_FORMAT,"env_id":"e","kind":"incident","author":"a","hlc":"1-0","sig":"","target":target});
    for (target, expected) in [
        (json!({}), json!({})),
        (json!(["ab", "cd"]), json!({"a": "b", "c": "d"})),
        // Colliding keys keep the FIRST key's text and the LAST value.
        (
            json!([[1, "one"], [true, "true"], [1.0, "float"]]),
            json!({"1": "float"}),
        ),
        (json!([[null, 1], ["None", 2]]), json!({"None": 2})),
        (json!([["\u{e9}", "value"]]), json!({"\u{e9}": "value"})),
        (json!([]), json!({})),
    ] {
        let mut want = fact(target.clone());
        want["target"] = expected;
        assert_eq!(
            sync::Fact::from_dict(&fact(target)).unwrap().to_dict(),
            want
        );
    }
}

#[test]
fn raw_tcp_canonical_deep_json_and_frame_tamper_boundaries() {
    let a = DeviceKey::generate();
    let env = commit::new_env_id(&a.fingerprint().unwrap()).unwrap();
    let (server, sessions, _) = listener(DeviceKey::generate(), member_check(&env, &a), 4);
    let private = x25519::generate_private();
    let mut stream = raw_connect(&server);
    let first = hello(&a, &env, &x25519::public_key(private.expose()).unwrap());
    send_frame(&mut stream, &first);
    let second: Value =
        pyjson::loads(std::str::from_utf8(&recv_frame(&mut stream)).unwrap()).unwrap();
    let ephemeral = b64decode(second["eb"].as_str().unwrap()).unwrap();
    let mut transcript = first;
    transcript.extend(&ephemeral);
    transcript.extend(canon(&second["device"]));
    let digest = Sha256::digest(&transcript);
    let mut signing = t::HANDSHAKE_INITIATOR_CONTEXT.to_vec();
    signing.extend(transcript);
    send_frame(
        &mut stream,
        &canon(&json!({"sig":b64encode(&a.sign(&signing).unwrap())})),
    );
    let incoming = sessions.recv_timeout(Duration::from_secs(3)).unwrap();
    let shared = x25519::shared_secret(private.expose(), &ephemeral).unwrap();
    let mut info = t::SESSION_INFO.to_vec();
    info.extend(b"i2r");
    let key = envelope::hkdf(&digest, &shared, &info, 32).unwrap();
    let text = format!(
        "{{\"number\":123456789012345678901234567890,\"deep\":{}0{}}}",
        "[".repeat(150),
        "]".repeat(150)
    );
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(b"I2R\0");
    send_frame(
        &mut stream,
        &aead::encrypt(&key, &nonce, text.as_bytes(), b"").unwrap(),
    );
    assert_eq!(
        incoming.recv(Duration::from_secs(3)).unwrap().unwrap(),
        pyjson::loads(&text).unwrap()
    );
    nonce[11] = 1;
    let mut tampered = aead::encrypt(&key, &nonce, b"{\"ok\":true}", b"").unwrap();
    *tampered.last_mut().unwrap() ^= 1;
    send_frame(&mut stream, &tampered);
    assert_eq!(
        incoming.recv(Duration::from_secs(3)).unwrap_err().0,
        "frame_authentication_failed"
    );
    assert!(incoming.is_closed());
    server.shutdown();
}

#[test]
fn tcp_connection_cap_is_released_after_session_close() {
    let a = DeviceKey::generate();
    let b = DeviceKey::generate();
    let env = commit::new_env_id(&a.fingerprint().unwrap()).unwrap();
    let client = TcpTransport::new(a.clone(), member_check(&env, &b), 4);
    let (server, sessions, _) = listener(b, member_check(&env, &a), 1);
    let first = client
        .dial_session(&server.bound_address().unwrap(), &env, None)
        .unwrap();
    let accepted = sessions.recv_timeout(Duration::from_secs(3)).unwrap();
    let mut refused = raw_connect(&server);
    assert_eq!(refused.read(&mut [0u8; 1]).unwrap(), 0);
    accepted.close();
    first.close();
    let next = client
        .dial_session(&server.bound_address().unwrap(), &env, None)
        .unwrap();
    sessions
        .recv_timeout(Duration::from_secs(3))
        .unwrap()
        .close();
    next.close();
    server.shutdown();
}

fn context(root: &TempDir, name: &str) -> Arc<Context> {
    Arc::new(
        Context::initialize(
            root.path().join(name),
            "admin-passphrase",
            "recovery-passphrase",
            Config {
                team_sync_interval_seconds: Some(0.05),
                team_dial_backoff: (0.02, 0.1),
                ..Config::default()
            },
            zeropw::clock::system(),
        )
        .unwrap(),
    )
}
fn proof(secret: &[u8], hash: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(hash);
    mac.finalize().into_bytes().to_vec()
}
#[test]
fn invite_expiry_transcript_and_concurrent_single_consumption() {
    let root = TempDir::new().unwrap();
    let ctx = context(&root, "invites");
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let env = commit::new_env_id(&device.fingerprint().unwrap()).unwrap();
    let secret = [42u8; 32];
    let hash = [7u8; 32];
    let signature = proof(&secret, &hash);
    let path = format!("team/{env}/invites.json");
    for expiry in [
        json!(0),
        json!("2000-01-01T00:00:00Z"),
        json!("2099-02-30T00:00:00Z"),
        Value::Null,
    ] {
        ctx.state.write_json(&path, &json!({"fixture":{"wrapped_secret":ctx.kms.wrap(&secret).unwrap().to_dict(),"role":"user","name":"fixture","used":false,"expires_at":expiry}})).unwrap();
        assert!(
            membership::consume_invite(&ctx, &env, &hash, &signature)
                .unwrap()
                .is_none()
        );
    }
    ctx.state.write_json(&path, &json!({"fixture":{"wrapped_secret":ctx.kms.wrap(&secret).unwrap().to_dict(),"role":"user","name":"fixture","used":false,"expires_at":"2099-01-01T00:00:00Z"}})).unwrap();
    assert!(
        membership::consume_invite(&ctx, &env, &[8u8; 32], &signature)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        ctx.state.read_json(&path, Value::Null).unwrap()["fixture"]["used"],
        false
    );
    let barrier = Arc::new(Barrier::new(5));
    let workers = (0..4)
        .map(|_| {
            let (ctx, env, signature, barrier) =
                (ctx.clone(), env.clone(), signature.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                membership::consume_invite(&ctx, &env, &hash, &signature)
                    .unwrap()
                    .is_some()
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    assert_eq!(
        workers
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum::<usize>(),
        1
    );
}

fn wait(mut predicate: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(6);
    while Instant::now() < until {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("synthetic team state did not converge");
}

#[test]
fn user_authority_incident_retry_restart_and_admin_removal_dek_isolation() {
    let root = TempDir::new().unwrap();
    let a = context(&root, "a");
    let b = context(&root, "b");
    a.projects.create("demo", &["dev"]).unwrap();
    const OLD: &[u8] = b"synthetic-old-shared-secret-round2";
    a.vault
        .put_secret("token", "api_key", OLD, "demo", "dev", true)
        .unwrap();
    let env = membership::share_environment(&a, None, "demo", "dev", "alice", "admin-passphrase")
        .unwrap()["env_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let ad = DeviceKey::load_or_create(a.state, a.kms).unwrap();
    let bd = DeviceKey::load_or_create(b.state, b.kms).unwrap();
    let at = Arc::new(InProcessTransport::new(ad.clone(), Arc::new(|_, _| None)));
    let bt = Arc::new(InProcessTransport::new(bd.clone(), Arc::new(|_, _| None)));
    let team_a = sync::TeamSync::new(a.clone(), at.clone(), ad.clone());
    let team_b = sync::TeamSync::new(b.clone(), bt.clone(), bd.clone());
    team_a.start(Some("astra-round2-removal-a:47001")).unwrap();
    team_b.start(None).unwrap();
    let invite = membership::create_invite(
        &a,
        &env,
        "user",
        "bob",
        3600,
        &["astra-round2-removal-a:47001".into()],
    )
    .unwrap();
    membership::join(
        &b,
        &invite,
        bt.as_ref(),
        &team_b,
        Some("shared"),
        Some("dev"),
        5.0,
    )
    .unwrap();
    assert_eq!(
        b.vault
            .secret_for_trusted_use("token", None)
            .unwrap()
            .expose(),
        OLD
    );
    let old_gen = team_a.document(&env).unwrap()["dek"]["current"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        team_b
            .publish_fact(
                &env,
                "connection_disabled",
                json!({"connection_id":"example"})
            )
            .unwrap_err()
            .reason,
        "team_fact_not_authorized"
    );
    assert_eq!(
        membership::create_invite(&b, &env, "admin", "evil", 10, &[])
            .unwrap_err()
            .reason,
        "not_admin"
    );
    team_a.stop();
    team_b.stop();
    // Fresh sender has no route; persisted incident must survive another object restart.
    let offline_transport = Arc::new(InProcessTransport::new(bd.clone(), Arc::new(|_, _| None)));
    let offline = sync::TeamSync::new(b.clone(), offline_transport, bd.clone());
    offline.register_env(&env).unwrap();
    let pending = offline.send_incident(&env,&json!({"incident_id":"abababababababab","secret_ids_mandatory":["token"],"unknown":"discard"})).unwrap();
    assert!(
        b.state
            .read_lines(&format!("team/{env}/incident_outbox.jsonl"), None)
            .unwrap()
            .iter()
            .any(|s| s.contains("abababababababab"))
    );
    drop(offline);
    let at = Arc::new(InProcessTransport::new(ad.clone(), Arc::new(|_, _| None)));
    let bt = Arc::new(InProcessTransport::new(bd.clone(), Arc::new(|_, _| None)));
    let team_a = sync::TeamSync::new(a.clone(), at.clone(), ad);
    let team_b = sync::TeamSync::new(b.clone(), bt.clone(), bd.clone());
    team_a.start(Some("astra-round2-removal-a:47001")).unwrap();
    team_b.start(None).unwrap();
    team_b
        .set_peer_address(
            &env,
            &team_a.device.fingerprint().unwrap(),
            "astra-round2-removal-a:47001",
        )
        .unwrap();
    wait(|| {
        b.state
            .read_bytes(&format!("team/{env}/incident_outbox.jsonl"))
            .is_ok_and(|v| v.is_empty())
    });
    let received = a
        .state
        .read_json(
            &format!(
                "team/{env}/incidents/{}-abababababababab.json",
                bd.fingerprint().unwrap()
            ),
            Value::Null,
        )
        .unwrap();
    assert_eq!(received["incident_id"], pending["target"]["incident_id"]);
    assert!(received.get("unknown").is_none());
    assert_eq!(
        a.state
            .read_json(&format!("team/{env}/rotation_flags.json"), Value::Null)
            .unwrap()["token"]["reason"],
        "rotation_required"
    );
    let removal =
        membership::remove_member(&a, Some(&team_a), &env, &bd.fingerprint().unwrap()).unwrap();
    assert_eq!(removal["dek_rotated"], true);
    let new_gen = removal["new_generation"].as_str().unwrap();
    assert_ne!(old_gen, new_gen);
    let document = team_a.document(&env).unwrap();
    assert!(
        document["dek"]["generations"][new_gen]["wraps"]
            .get(bd.fingerprint().unwrap())
            .is_none()
    );
    let new_dek = a
        .kms
        .unwrap(
            &WrappedKey::from_dict(
                &a.state
                    .read_json(&format!("team/{env}/dek/{new_gen}.json"), Value::Null)
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let old_dek = b
        .kms
        .unwrap(
            &WrappedKey::from_dict(
                &b.state
                    .read_json(&format!("team/{env}/dek/{old_gen}.json"), Value::Null)
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let ciphertext = envelope::encrypt_secret(
        new_dek.expose(),
        &env,
        "token",
        "1234567890abcdef",
        b"synthetic-new-secret-round2",
    )
    .unwrap();
    assert!(
        envelope::decrypt_secret(
            old_dek.expose(),
            &env,
            "token",
            "1234567890abcdef",
            &ciphertext
        )
        .is_err()
    );
    assert!(!b.state.exists(&format!("team/{env}/dek/{new_gen}.json")));
    let refused = bt.dial("astra-round2-removal-a:47001", &env, None).unwrap();
    assert!(refused.recv(Duration::from_secs(3)).is_err());
    assert_eq!(
        b.vault
            .secret_for_trusted_use("token", None)
            .unwrap()
            .expose(),
        OLD
    );
    team_b.stop();
    team_a.stop();
}
