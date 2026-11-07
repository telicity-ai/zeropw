//! Explicit pairing approval (docs/remote-sync.md §3.2): approval-required
//! invitations, join requests, JOIN_PENDING, `team join-requests`,
//! `team approve-join` and `team deny-join`. Synthetic credentials only.
mod native_e2e;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use native_e2e::{ADMIN_PASSPHRASE, Admin, free_port};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use zeropw::context::{Config, Context};
use zeropw::team::identity::DeviceKey;
use zeropw::team::membership::{self, CreatedInvite, InviteOutcome};
use zeropw::team::transport::{
    InProcessTransport, InviteProof, MembershipCheck, TcpTransport, Transport,
};
use zeropw::team::{pairing, sync};

const SECRET: &[u8] = b"synthetic-pairing-secret-value-0123456789";

struct TestClock(Arc<AtomicU64>);
impl TestClock {
    fn set(&self, ts: f64) {
        self.0.store(ts.to_bits(), Ordering::SeqCst);
    }
}

fn now() -> f64 {
    zeropw::clock::now().floor()
}

fn context_at(root: &TempDir, name: &str, start: f64) -> (Arc<Context>, TestClock) {
    let cell = Arc::new(AtomicU64::new(start.to_bits()));
    let read = cell.clone();
    let ctx = Context::initialize(
        root.path().join(name),
        "admin-passphrase",
        "recovery-passphrase",
        Config {
            team_sync_interval_seconds: Some(0.05),
            team_dial_backoff: (0.02, 0.1),
            ..Config::default()
        },
        Arc::new(move || f64::from_bits(read.load(Ordering::SeqCst))),
    )
    .unwrap();
    (Arc::new(ctx), TestClock(cell))
}

/// A context sharing `demo/dev` (holding one synthetic secret).
fn shared(root: &TempDir, name: &str) -> (Arc<Context>, TestClock, String) {
    let (ctx, clock) = context_at(root, name, now());
    ctx.projects.create("demo", &["dev"]).unwrap();
    ctx.vault
        .put_secret("gh-token", "api_key", SECRET, "demo", "dev", true)
        .unwrap();
    let shared =
        membership::share_environment(&ctx, None, "demo", "dev", "owner", "admin-passphrase")
            .unwrap();
    let env = shared["env_id"].as_str().unwrap().to_owned();
    (ctx, clock, env)
}

fn none() -> MembershipCheck {
    Arc::new(|_, _| None)
}

/// A running inviter node on an in-process address.
fn inviter_node(ctx: &Arc<Context>, address: &str) -> Arc<sync::TeamSync> {
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let transport = Arc::new(InProcessTransport::new(device.clone(), none()));
    let node = sync::TeamSync::new(ctx.clone(), transport, device);
    node.start(Some(address)).unwrap();
    node
}

fn approval_invite(ctx: &Context, env: &str, address: &str) -> CreatedInvite {
    membership::create_invite_opts(
        ctx,
        env,
        "user",
        "second-mac",
        3600,
        &[address.to_owned()],
        false,
        true,
    )
    .unwrap()
}

/// One `team join` attempt from `ctx`'s device, as a fresh process would
/// run it; the joiner's node is stopped afterwards unless `keep`.
fn join_attempt(ctx: &Arc<Context>, invite: &str, timeout: f64) -> zeropw::errors::Result<Value> {
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let transport = Arc::new(InProcessTransport::new(device.clone(), none()));
    let team = sync::TeamSync::new(ctx.clone(), transport.clone(), device);
    team.start(None).unwrap();
    let result = membership::join(
        ctx,
        invite,
        transport.as_ref() as &dyn Transport,
        &team,
        Some("paired"),
        Some("dev"),
        timeout,
    );
    team.stop();
    result
}

fn fingerprint(ctx: &Context) -> String {
    DeviceKey::load_or_create(ctx.state, ctx.kms)
        .unwrap()
        .fingerprint()
        .unwrap()
}

fn invites_file(ctx: &Context, env: &str) -> Value {
    ctx.state
        .read_json(&format!("team/{env}/invites.json"), json!({}))
        .unwrap()
}

fn requests_file(ctx: &Context, env: &str) -> Value {
    ctx.state
        .read_json(&format!("team/{env}/join_requests.json"), Value::Null)
        .unwrap()
}

fn requests(ctx: &Context, env: &str) -> Vec<Value> {
    pairing::list_requests(ctx, env).unwrap()["requests"]
        .as_array()
        .unwrap()
        .clone()
}

fn member_status(ctx: &Context, env: &str, fp: &str) -> Value {
    membership::load_environment(ctx, env).unwrap().document["members"][fp]["status"].clone()
}

fn audit_events(ctx: &Context, event: &str) -> Vec<Value> {
    ctx.audit
        .iter_records()
        .unwrap()
        .into_iter()
        .filter(|record| record["event"] == event)
        .collect()
}

fn proof(secret: &[u8], hash: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(hash);
    mac.finalize().into_bytes().to_vec()
}

fn secret_of(invite: &str) -> Vec<u8> {
    membership::parse_invite_or_link(invite)
        .unwrap()
        .invite_secret
        .expose()
        .to_vec()
}

/// A synthetic device fingerprint (26 base32 characters), distinct per `n`.
fn synthetic_fp(n: usize) -> String {
    let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = Vec::new();
    let mut v = n;
    while out.len() < 26 {
        out.push(alphabet[v % 32]);
        v /= 32;
    }
    String::from_utf8(out).unwrap()
}

fn assert_pending(result: zeropw::errors::Result<Value>, joiner: &str, inviter: &str) {
    let error = result.expect_err("join should wait for approval");
    assert_eq!(error.reason, "join_pending_approval", "{error:?}");
    let dict = error.to_dict();
    assert_eq!(
        dict["detail"],
        json!({"self_fingerprint": joiner, "inviter_fingerprint": inviter})
    );
}

#[test]
fn approval_flow_end_to_end() {
    let root = TempDir::new().unwrap();
    let (a, _clock, env) = shared(&root, "a");
    let a_fp = fingerprint(&a);
    let address = "pairing-e2e.test:47001";
    let node = inviter_node(&a, address);
    let created = approval_invite(&a, &env, address);
    assert!(created.approval);
    assert_eq!(
        invites_file(&a, &env)[&created.invite_id]["approval"],
        "required"
    );
    let (b, _) = context_at(&root, "b", now());
    let b_fp = fingerprint(&b);

    // First attempt: pending, and the invitation is not consumed.
    let started = Instant::now();
    assert_pending(join_attempt(&b, &created.invite, 10.0), &b_fp, &a_fp);
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "JOIN_PENDING must end the join at once, not by timeout"
    );
    let entry = &invites_file(&a, &env)[&created.invite_id];
    assert_eq!(entry["used"], false);
    assert!(entry.get("wrapped_secret").is_some());
    let listed = requests(&a, &env);
    assert_eq!(listed.len(), 1, "{listed:?}");
    let request = &listed[0];
    assert_eq!(request["invite_id"], created.invite_id);
    assert_eq!(request["fingerprint"], b_fp);
    assert_eq!(request["attempts"], 1);
    assert_eq!(request["request_id"].as_str().unwrap().len(), 32);
    assert!(request["first_seen_at"].is_string());
    let mut keys: Vec<&String> = request.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "attempts",
            "fingerprint",
            "first_seen_at",
            "invite_id",
            "last_seen_at",
            "request_id"
        ]
    );
    // The handshake never enrolled B, nor did the inviter keep a session.
    assert!(member_status(&a, &env, &b_fp).is_null());
    assert!(node.status(&env).unwrap()["sessions"] == json!([]));

    // A second attempt refreshes the same request.
    assert_pending(join_attempt(&b, &created.invite, 10.0), &b_fp, &a_fp);
    let again = requests(&a, &env);
    assert_eq!(again.len(), 1);
    assert_eq!(again[0]["request_id"], request["request_id"]);
    assert_eq!(again[0]["attempts"], 2);

    // Approve exactly B; the request is no longer waiting.
    let approved = pairing::approve_join(&a, &env, &b_fp, None).unwrap();
    assert_eq!(
        approved,
        json!({"env_id": env, "fingerprint": b_fp, "approved_invites": [created.invite_id]})
    );
    assert_eq!(
        invites_file(&a, &env)[&created.invite_id]["approved_fingerprint"],
        b_fp
    );
    assert!(requests(&a, &env).is_empty());

    // Now B's join consumes the invitation exactly as a normal one does.
    let joined = join_attempt(&b, &created.invite, 10.0).unwrap();
    assert_eq!(joined["env_id"], env);
    assert_eq!(joined["self_fingerprint"], b_fp);
    let entry = &invites_file(&a, &env)[&created.invite_id];
    assert_eq!(entry["used"], true);
    assert_eq!(entry["used_by"], b_fp);
    assert!(entry.get("wrapped_secret").is_none(), "{entry}");
    // member.add (with wraps) is folded on both sides.
    assert_eq!(member_status(&a, &env, &b_fp), "active");
    assert_eq!(member_status(&b, &env, &b_fp), "active");
    let doc = membership::load_environment(&b, &env).unwrap().document;
    assert_eq!(doc["members"][&b_fp]["role"], "user");
    assert_eq!(
        b.vault
            .secret_for_trusted_use("gh-token", None)
            .unwrap()
            .expose(),
        SECRET
    );
    // Single use: approving again is refused with the existing reason.
    let error = pairing::approve_join(&a, &env, &b_fp, None).unwrap_err();
    assert_eq!(error.reason, "invite_already_used");

    // Audit: one rate-limited request record, the approval, no handshake
    // failure for the pending attempts, and nothing secret.
    let recorded = audit_events(&a, "team_join_request");
    assert_eq!(recorded.len(), 1, "{recorded:?}");
    assert_eq!(recorded[0]["fingerprint"], b_fp);
    assert_eq!(recorded[0]["detail"], created.invite_id);
    assert_eq!(recorded[0]["result"], "ok");
    assert_eq!(recorded[0]["reason"], "join_request_recorded");
    assert_eq!(recorded[0]["count"], 1);
    let approvals = audit_events(&a, "team_join_approved");
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0]["caller"], "admin");
    assert_eq!(approvals[0]["env_id"], env);
    assert_eq!(approvals[0]["fingerprint"], b_fp);
    assert_eq!(approvals[0]["detail"], created.invite_id);
    assert!(
        audit_events(&a, "team_handshake_failed")
            .iter()
            .all(|r| r["reason"] != "join_pending")
    );
    let log = std::fs::read_to_string(a.state.path.join("audit/audit.jsonl")).unwrap();
    let secret_b64 = zeropw::pybase64::b64encode(&secret_of(&created.invite));
    assert!(!log.contains(&created.invite));
    assert!(!log.contains(&secret_b64));
    let stored =
        std::fs::read_to_string(a.state.path.join(format!("team/{env}/join_requests.json")))
            .unwrap();
    assert!(!stored.contains(&secret_b64) && !stored.contains(&created.invite));
    node.stop();
}

#[test]
fn another_device_stays_pending_after_approval() {
    let root = TempDir::new().unwrap();
    let (a, _clock, env) = shared(&root, "a");
    let a_fp = fingerprint(&a);
    let address = "pairing-other.test:47001";
    let node = inviter_node(&a, address);
    let created = approval_invite(&a, &env, address);
    let (b, _) = context_at(&root, "b", now());
    let (c, _) = context_at(&root, "c", now());
    let (b_fp, c_fp) = (fingerprint(&b), fingerprint(&c));
    assert_pending(join_attempt(&b, &created.invite, 10.0), &b_fp, &a_fp);
    pairing::approve_join(&a, &env, &b_fp, None).unwrap();
    // C holds the same code but is not the approved device.
    assert_pending(join_attempt(&c, &created.invite, 10.0), &c_fp, &a_fp);
    assert!(member_status(&a, &env, &c_fp).is_null());
    let waiting = requests(&a, &env);
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0]["fingerprint"], c_fp);
    assert_eq!(
        invites_file(&a, &env)[&created.invite_id]["approved_fingerprint"],
        b_fp
    );
    // B still consumes it; afterwards C gets nothing at all.
    join_attempt(&b, &created.invite, 10.0).unwrap();
    let after = join_attempt(&c, &created.invite, 1.0).unwrap_err();
    assert_ne!(after.reason, "join_pending_approval");
    assert!(member_status(&a, &env, &c_fp).is_null());
    assert!(requests(&a, &env).is_empty());
    node.stop();
}

#[test]
fn deny_revokes_the_invitation() {
    let root = TempDir::new().unwrap();
    let (a, _clock, env) = shared(&root, "a");
    let a_fp = fingerprint(&a);
    let address = "pairing-deny.test:47001";
    let node = inviter_node(&a, address);
    let created = approval_invite(&a, &env, address);
    let (b, _) = context_at(&root, "b", now());
    let b_fp = fingerprint(&b);
    assert_pending(join_attempt(&b, &created.invite, 10.0), &b_fp, &a_fp);
    let denied = pairing::deny_join(&a, &env, &b_fp).unwrap();
    assert_eq!(
        denied,
        json!({"env_id": env, "fingerprint": b_fp, "revoked_invites": [created.invite_id]})
    );
    let entry = &invites_file(&a, &env)[&created.invite_id];
    assert!(entry["revoked_at"].is_number());
    assert!(entry.get("wrapped_secret").is_none());
    assert!(requests(&a, &env).is_empty());
    let listed = membership::list_invites(&a, &env).unwrap();
    assert_eq!(listed["invites"][0]["status"], "revoked");
    assert_eq!(listed["invites"][0]["approval"], "required");
    // Denying again is idempotent; approving now is refused.
    pairing::deny_join(&a, &env, &b_fp).unwrap();
    let error = pairing::approve_join(&a, &env, &b_fp, None).unwrap_err();
    assert_eq!(error.reason, "invite_revoked");
    // The revoked invitation matches nothing: no JOIN_PENDING, no new request.
    let before = requests_file(&a, &env);
    let refused = join_attempt(&b, &created.invite, 1.0).unwrap_err();
    assert_ne!(refused.reason, "join_pending_approval");
    assert_eq!(requests_file(&a, &env), before);
    let denials = audit_events(&a, "team_join_denied");
    assert_eq!(denials.len(), 2);
    assert!(denials.iter().all(|r| r["caller"] == "admin"
        && r["fingerprint"] == b_fp
        && r["detail"] == created.invite_id));
    // One revocation, recorded as `team revoke-invite` records it.
    let revoked = audit_events(&a, "team_invite_revoke");
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0]["role"], "user");
    assert_eq!(revoked[0]["detail"], created.invite_id);
    node.stop();
}

#[test]
fn approval_needs_a_request_and_a_usable_invitation() {
    let root = TempDir::new().unwrap();
    let (a, clock, env) = shared(&root, "a");
    let start = now();
    let created = approval_invite(&a, &env, "pairing-errors.test:47001");
    let b_fp = synthetic_fp(1);
    // Malformed fingerprints fail before anything is read.
    let upper = b_fp.to_uppercase();
    let long = format!("{b_fp}a");
    for bad in [
        "",
        "short",
        upper.as_str(),
        long.as_str(),
        "../../../../etc/pass",
    ] {
        assert_eq!(
            pairing::approve_join(&a, &env, bad, None)
                .unwrap_err()
                .reason,
            "invalid_fingerprint"
        );
        assert_eq!(
            pairing::deny_join(&a, &env, bad).unwrap_err().reason,
            "invalid_fingerprint"
        );
    }
    assert_eq!(
        pairing::approve_join(&a, &env, &b_fp, None)
            .unwrap_err()
            .reason,
        "join_request_not_found"
    );
    assert_eq!(
        pairing::deny_join(&a, &env, &b_fp).unwrap_err().reason,
        "join_request_not_found"
    );
    // A valid proof records a request (through the handshake's check).
    let hash = Sha256::digest(b"synthetic transcript").to_vec();
    let good = proof(&secret_of(&created.invite), &hash);
    let outcome = membership::check_invite(&a, &env, &hash, &good, &b_fp).unwrap();
    assert!(
        matches!(outcome, InviteOutcome::Pending { ref invite_id, new_request: true, attempts: 1 } if *invite_id == created.invite_id),
        "{outcome:?}"
    );
    assert_eq!(
        pairing::approve_join(&a, &env, &b_fp, Some(&"0".repeat(32)))
            .unwrap_err()
            .reason,
        "invite_not_found"
    );
    // An approval-free invitation never has a request from this device.
    let plain = membership::create_invite(&a, &env, "user", "plain", 3600, &[]).unwrap();
    let plain_id = membership::invite_id(&secret_of(&plain));
    assert_eq!(
        pairing::approve_join(&a, &env, &b_fp, Some(&plain_id))
            .unwrap_err()
            .reason,
        "join_request_not_found"
    );
    // Past its expiry the invitation cannot be approved.
    clock.set(start + 7200.0);
    assert_eq!(
        pairing::approve_join(&a, &env, &b_fp, Some(&created.invite_id))
            .unwrap_err()
            .reason,
        "invite_expired"
    );
    assert!(
        requests(&a, &env).is_empty(),
        "an expired invite waits for nothing"
    );
    clock.set(start);
    let approved = pairing::approve_join(&a, &env, &b_fp, Some(&created.invite_id)).unwrap();
    assert_eq!(approved["approved_invites"], json!([created.invite_id]));
    // The approved device consumes it; the same proof then matches nothing.
    let consumed = membership::check_invite(&a, &env, &hash, &good, &b_fp).unwrap();
    assert_eq!(
        consumed,
        InviteOutcome::Consumed {
            role: "user".into(),
            name: "second-mac".into()
        }
    );
    assert_eq!(
        membership::check_invite(&a, &env, &hash, &good, &b_fp).unwrap(),
        InviteOutcome::NoMatch
    );
    assert_eq!(
        pairing::deny_join(&a, &env, &b_fp).unwrap_err().reason,
        "invite_already_used"
    );
}

#[test]
fn invalid_proofs_record_nothing() {
    let root = TempDir::new().unwrap();
    let (a, _clock, env) = shared(&root, "a");
    let created = approval_invite(&a, &env, "pairing-invalid.test:47001");
    let hash = Sha256::digest(b"synthetic transcript").to_vec();
    let secret = secret_of(&created.invite);
    let fp = synthetic_fp(2);
    let mut wrong_secret = secret.clone();
    wrong_secret[0] ^= 1;
    let other_hash = Sha256::digest(b"another transcript").to_vec();
    for bad in [
        vec![],
        vec![0u8; 32],
        proof(&wrong_secret, &hash),
        proof(&secret, &other_hash),
        proof(&secret, &hash)[..31].to_vec(),
    ] {
        assert_eq!(
            membership::check_invite(&a, &env, &hash, &bad, &fp).unwrap(),
            InviteOutcome::NoMatch
        );
    }
    assert!(
        requests_file(&a, &env).is_null(),
        "no request file is written"
    );
    // The library's consume path never records a request either.
    let good = proof(&secret, &hash);
    assert_eq!(
        membership::consume_invite_by(&a, &env, &hash, &good, Some(&fp)).unwrap(),
        None
    );
    assert_eq!(
        membership::consume_invite(&a, &env, &hash, &good).unwrap(),
        None
    );
    assert!(requests_file(&a, &env).is_null());
    assert_eq!(invites_file(&a, &env)[&created.invite_id]["used"], false);
}

#[test]
fn requests_are_bounded_per_invitation_newest_kept() {
    let root = TempDir::new().unwrap();
    let (a, clock, env) = shared(&root, "a");
    let start = now();
    let created = approval_invite(&a, &env, "pairing-bounded.test:47001");
    let other = approval_invite(&a, &env, "pairing-bounded.test:47001");
    let hash = Sha256::digest(b"synthetic transcript").to_vec();
    let good = proof(&secret_of(&created.invite), &hash);
    let other_good = proof(&secret_of(&other.invite), &hash);
    // One request on the other invitation is never evicted by this one's.
    clock.set(start);
    membership::check_invite(&a, &env, &hash, &other_good, &synthetic_fp(99)).unwrap();
    for n in 0..12 {
        clock.set(start + 1.0 + n as f64);
        membership::check_invite(&a, &env, &hash, &good, &synthetic_fp(n)).unwrap();
        // Device 0 keeps retrying, so it stays among the newest.
        if n > 0 {
            membership::check_invite(&a, &env, &hash, &good, &synthetic_fp(0)).unwrap();
        }
    }
    let stored = requests_file(&a, &env);
    let stored = stored.as_object().unwrap();
    let on_created: Vec<&Value> = stored
        .values()
        .filter(|r| r["invite_id"] == created.invite_id)
        .collect();
    assert_eq!(on_created.len(), pairing::MAX_REQUESTS_PER_INVITE);
    let kept: Vec<String> = on_created
        .iter()
        .map(|r| r["fingerprint"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        kept.contains(&synthetic_fp(0)),
        "the retrying device is kept"
    );
    for n in 5..12 {
        assert!(kept.contains(&synthetic_fp(n)), "newest {n} kept");
    }
    for n in 1..5 {
        assert!(!kept.contains(&synthetic_fp(n)), "oldest {n} dropped");
    }
    let zero = on_created
        .iter()
        .find(|r| r["fingerprint"] == synthetic_fp(0))
        .unwrap();
    assert_eq!(zero["attempts"], 12);
    assert!(
        stored
            .values()
            .any(|r| r["invite_id"] == other.invite_id && r["fingerprint"] == synthetic_fp(99))
    );
    assert_eq!(stored.len(), pairing::MAX_REQUESTS_PER_INVITE + 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(a.state.path.join(format!("team/{env}/join_requests.json")))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn corrupt_request_files_fail_closed() {
    let root = TempDir::new().unwrap();
    let (a, _clock, env) = shared(&root, "a");
    let created = approval_invite(&a, &env, "pairing-corrupt.test:47001");
    let hash = Sha256::digest(b"synthetic transcript").to_vec();
    let good = proof(&secret_of(&created.invite), &hash);
    let path = format!("team/{env}/join_requests.json");
    let fp = synthetic_fp(3);
    let valid = json!({"invite_id": created.invite_id, "fingerprint": fp,
        "first_seen_at": 1.0, "last_seen_at": 2.0, "attempts": 1});
    let id = "ab".repeat(16);
    for bad in [
        json!([]),
        json!({"not-hex": valid.clone()}),
        json!({ &id: {"invite_id": "x", "fingerprint": fp, "first_seen_at": 1.0, "last_seen_at": 2.0, "attempts": 1}}),
        json!({ &id: {"invite_id": created.invite_id, "fingerprint": "NOPE", "first_seen_at": 1.0, "last_seen_at": 2.0, "attempts": 1}}),
        json!({ &id: {"invite_id": created.invite_id, "fingerprint": fp, "first_seen_at": "x", "last_seen_at": 2.0, "attempts": 1}}),
        json!({ &id: {"invite_id": created.invite_id, "fingerprint": fp, "first_seen_at": 1.0, "last_seen_at": 2.0, "attempts": 0}}),
        json!({ &id: {"invite_id": created.invite_id, "fingerprint": fp, "first_seen_at": 1e300, "last_seen_at": 2.0, "attempts": 1}}),
    ] {
        a.state.write_json(&path, &bad).unwrap();
        let error = pairing::list_requests(&a, &env).unwrap_err();
        assert_eq!(
            (error.reason.as_ref(), error.detail.as_str()),
            ("state_corrupt", path.as_str()),
            "{bad}"
        );
        assert_eq!(
            pairing::approve_join(&a, &env, &fp, None)
                .unwrap_err()
                .reason,
            "state_corrupt"
        );
        // The handshake fails closed too: no consumption, no JOIN_PENDING.
        assert!(membership::check_invite(&a, &env, &hash, &good, &fp).is_err());
        assert_eq!(a.state.read_json(&path, Value::Null).unwrap(), bad);
    }
    a.state.write_json(&path, &json!({ &id: valid })).unwrap();
    assert_eq!(requests(&a, &env).len(), 1);
}

#[test]
fn join_pending_reaches_only_invitation_holders() {
    let root = TempDir::new().unwrap();
    let (a, _clock, env) = shared(&root, "a");
    let device = DeviceKey::load_or_create(a.state, a.kms).unwrap();
    let transport = TcpTransport::new(device.clone(), none(), 8);
    let node = sync::TeamSync::new(a.clone(), Arc::new(transport), device);
    let address = format!("127.0.0.1:{}", free_port());
    node.start(Some(&address)).unwrap();
    let created = approval_invite(&a, &env, &address);
    let secret = secret_of(&created.invite);
    let inviter_record = DeviceKey::load_or_create(a.state, a.kms)
        .unwrap()
        .record()
        .unwrap();
    let dial = |secret: Option<Vec<u8>>| {
        let (ctx, _) = context_at(&root, &format!("dialer-{}", rand_name()), now());
        let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        // Without a proof the dialer must take the inviter for a member, or
        // it stops at message two itself and the inviter is never asked.
        let record = inviter_record.clone();
        let believes: MembershipCheck = Arc::new(move |_, _| Some(record.clone()));
        let transport = TcpTransport::new(device, believes, 8);
        let make: Option<InviteProof> =
            secret.map(|secret| Arc::new(move |hash: &[u8]| proof(&secret, hash)) as InviteProof);
        let session = transport.dial_session(&address, &env, make).unwrap();
        // Frames the joiner sends at once, before the inviter answers:
        // the inviter's close must not reset the connection over them.
        for _ in 0..3 {
            let _ = session.send(&json!({"type": "PEERS", "peers": {}}));
        }
        let mut frames = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            match session.recv(Duration::from_millis(500)) {
                Ok(Some(frame)) => frames.push(frame),
                Ok(None) => {}
                Err(_) => break,
            }
            if !frames.is_empty() {
                break;
            }
        }
        session.close();
        frames
    };
    // The holder of the invitation secret gets exactly one JOIN_PENDING.
    assert_eq!(
        dial(Some(secret.clone())),
        [json!({"type": "JOIN_PENDING"})]
    );
    // A wrong secret, or no proof at all, gets no frame and records nothing.
    let mut wrong = secret.clone();
    wrong[5] ^= 0x40;
    assert!(dial(Some(wrong)).is_empty());
    let recorded = requests_file(&a, &env);
    assert_eq!(recorded.as_object().unwrap().len(), 1);
    // A non-member sending no proof gets nothing either.
    assert!(dial(None).is_empty());
    assert_eq!(requests_file(&a, &env), recorded);
    node.stop();
}

fn rand_name() -> String {
    use std::sync::atomic::AtomicUsize;
    static N: AtomicUsize = AtomicUsize::new(0);
    N.fetch_add(1, Ordering::SeqCst).to_string()
}

#[test]
fn normal_invitations_are_unchanged() {
    let root = TempDir::new().unwrap();
    let (a, _clock, env) = shared(&root, "a");
    let address = "pairing-normal.test:47001";
    let node = inviter_node(&a, address);
    let created = membership::create_invite_with(
        &a,
        &env,
        "user",
        "plain",
        3600,
        &[address.to_owned()],
        false,
    )
    .unwrap();
    assert!(!created.approval);
    let entry = &invites_file(&a, &env)[&created.invite_id];
    assert!(entry.get("approval").is_none());
    assert!(entry.get("approved_fingerprint").is_none());
    let listed = membership::list_invites(&a, &env).unwrap();
    assert!(listed["invites"][0].get("approval").is_none());
    let (b, _) = context_at(&root, "b", now());
    let joined = join_attempt(&b, &created.invite, 10.0).unwrap();
    assert_eq!(joined["self_fingerprint"], fingerprint(&b));
    assert_eq!(invites_file(&a, &env)[&created.invite_id]["used"], true);
    assert!(requests_file(&a, &env).is_null());
    assert!(audit_events(&a, "team_join_request").is_empty());
    node.stop();
}

#[test]
fn requests_and_approvals_survive_restarts() {
    let root = TempDir::new().unwrap();
    let (a, _clock, env) = shared(&root, "a");
    let a_fp = fingerprint(&a);
    let address = "pairing-restart.test:47001";
    let node = inviter_node(&a, address);
    let created = approval_invite(&a, &env, address);
    let (b, _) = context_at(&root, "b", now());
    let b_fp = fingerprint(&b);
    assert_pending(join_attempt(&b, &created.invite, 10.0), &b_fp, &a_fp);
    node.stop();
    drop(node);
    // Another process (the administrator CLI) reads the same state.
    let reopened =
        Context::open(&a.state.path, Config::default(), zeropw::clock::system()).unwrap();
    let listed = pairing::list_requests(&reopened, &env).unwrap();
    assert_eq!(listed["requests"][0]["fingerprint"], b_fp);
    pairing::approve_join(&reopened, &env, &b_fp, None).unwrap();
    drop(reopened);
    // A restarted inviter node honours the stored approval.
    let node = inviter_node(&a, address);
    let joined = join_attempt(&b, &created.invite, 10.0).unwrap();
    assert_eq!(joined["self_fingerprint"], b_fp);
    assert_eq!(member_status(&a, &env, &b_fp), "active");
    node.stop();
}

// ---------------------------------------------------------------- CLI

fn cli_shared(root: &std::path::Path) -> Admin {
    let admin = Admin::new(root);
    admin.ok(&["init"]);
    admin.ok(&["project", "create", "demo"]);
    let ctx = Context::open(&admin.state, Config::default(), zeropw::clock::system()).unwrap();
    membership::share_environment(&ctx, None, "demo", "dev", "owner", ADMIN_PASSPHRASE).unwrap();
    admin
}

fn sorted_keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    keys
}

#[test]
fn cli_pairing_commands_end_to_end() {
    let tmp = TempDir::new().unwrap();
    let inviter = cli_shared(&tmp.path().join("inviter"));
    // The inviter's running node (what `serve --team-listen` hosts).
    let ctx = Arc::new(
        Context::open(&inviter.state, Config::default(), zeropw::clock::system()).unwrap(),
    );
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let inviter_fp = device.fingerprint().unwrap();
    let transport = TcpTransport::new(device.clone(), none(), 8);
    let node = sync::TeamSync::new(ctx.clone(), Arc::new(transport), device);
    let address = format!("127.0.0.1:{}", free_port());
    node.start(Some(&address)).unwrap();

    let invite = |extra: &[&str]| {
        let mut args: Vec<&str> = vec![
            "team",
            "invite",
            "--env",
            "demo/dev",
            "--role",
            "user",
            "--name",
            "laptop",
            "--address",
            &address,
        ];
        args.extend_from_slice(extra);
        inviter.ok(&args)
    };
    let plain = invite(&[]);
    assert!(plain.get("approval").is_none());
    let created = invite(&["--approval"]);
    assert_eq!(created["approval"], "required");
    assert_eq!(
        sorted_keys(&created),
        ["approval", "env_id", "invite", "name", "role", "warning"]
    );
    let linked = invite(&["--approval", "--link"]);
    assert_eq!(linked["approval"], "required");
    assert!(
        linked["link"]
            .as_str()
            .unwrap()
            .starts_with("zeropw://join#")
    );

    let empty = inviter.ok(&["team", "join-requests", "--env", "demo/dev"]);
    assert_eq!(empty, json!({"env_id": created["env_id"], "requests": []}));

    let joiner = Admin::new(&tmp.path().join("joiner"));
    joiner.ok(&["init"]);
    let invite_text = created["invite"].as_str().unwrap().to_owned();
    let pending = joiner.fail(&["team", "join", &invite_text]);
    assert_eq!(pending["reason"], "join_pending_approval");
    let joiner_fp = pending["detail"]["self_fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(pending["detail"]["inviter_fingerprint"], inviter_fp);
    assert_eq!(
        sorted_keys(&pending["detail"]),
        ["inviter_fingerprint", "self_fingerprint"]
    );

    let listed = inviter.ok(&["team", "join-requests", "--env", "demo/dev"]);
    assert_eq!(listed["requests"].as_array().unwrap().len(), 1);
    assert_eq!(listed["requests"][0]["fingerprint"], joiner_fp);
    let invite_id = listed["requests"][0]["invite_id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Error reasons, values never echoed.
    let bad = inviter.fail(&[
        "team",
        "approve-join",
        "--env",
        "demo/dev",
        "--fingerprint",
        "NOT-A-FINGERPRINT",
    ]);
    assert_eq!(bad["reason"], "invalid_fingerprint");
    assert!(!bad.to_string().contains("NOT-A-FINGERPRINT"));
    let unknown = synthetic_fp(7);
    for action in ["approve-join", "deny-join"] {
        let missing = inviter.fail(&[
            "team",
            action,
            "--env",
            "demo/dev",
            "--fingerprint",
            &unknown,
        ]);
        assert_eq!(missing["reason"], "join_request_not_found");
    }
    let wrong_id = inviter.fail(&[
        "team",
        "approve-join",
        "--env",
        "demo/dev",
        "--fingerprint",
        &joiner_fp,
        "--invite-id",
        &"0".repeat(32),
    ]);
    assert_eq!(wrong_id["reason"], "invite_not_found");
    let no_env = inviter.fail(&["team", "join-requests", "--env", "demo/nope"]);
    assert_eq!(no_env["reason"], "team_env_not_found");

    let approved = inviter.ok(&[
        "team",
        "approve-join",
        "--env",
        "demo/dev",
        "--fingerprint",
        &joiner_fp,
        "--invite-id",
        &invite_id,
    ]);
    assert_eq!(
        approved,
        json!({"env_id": created["env_id"], "fingerprint": joiner_fp, "approved_invites": [invite_id]})
    );
    let joined = joiner.ok(&["team", "join", &invite_text]);
    assert_eq!(joined["self_fingerprint"], joiner_fp);
    assert_eq!(joined["inviter_fingerprint"], inviter_fp);
    let members = inviter.ok(&["team", "members", "--env", "demo/dev"]);
    assert!(
        members["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["fingerprint"] == joiner_fp && m["status"] == "active")
    );

    // deny-join on another device's request revokes the link invitation.
    let other = Admin::new(&tmp.path().join("other"));
    other.ok(&["init"]);
    let linked_text = linked["link"].as_str().unwrap().to_owned();
    let pending = other.fail(&["team", "join", &linked_text]);
    assert_eq!(pending["reason"], "join_pending_approval");
    let other_fp = pending["detail"]["self_fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
    let denied = inviter.ok(&[
        "team",
        "deny-join",
        "--env",
        "demo/dev",
        "--fingerprint",
        &other_fp,
    ]);
    assert_eq!(
        sorted_keys(&denied),
        ["env_id", "fingerprint", "revoked_invites"]
    );
    assert_eq!(denied["revoked_invites"].as_array().unwrap().len(), 1);
    let invites = inviter.ok(&["team", "invites", "--env", "demo/dev"]);
    let statuses: Vec<(Value, Value)> = invites["invites"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            (
                i["status"].clone(),
                i.get("approval").cloned().unwrap_or(Value::Null),
            )
        })
        .collect();
    assert_eq!(
        statuses,
        [
            (json!("pending"), Value::Null),
            (json!("used"), json!("required")),
            (json!("revoked"), json!("required")),
        ]
    );
    // No CLI output carries the invitation string except `team invite`'s.
    for recorded in inviter.outputs.lock().unwrap().iter() {
        if recorded.argv.iter().any(|a| a == "invite") {
            continue;
        }
        assert!(!recorded.stdout.contains(&invite_text));
        assert!(!recorded.stderr.contains(&invite_text));
    }
    for recorded in joiner.outputs.lock().unwrap().iter() {
        assert!(!recorded.stdout.contains(&invite_text) && !recorded.stderr.contains(&invite_text));
    }
    node.stop();
}
