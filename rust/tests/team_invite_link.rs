//! One-day invite links, the invite list and revocation
//! (docs/desktop-app.md §3.2): the library contract in `team::membership`
//! and the `zeropw-admin team invite --link | invites | revoke-invite |
//! invite-info | join --stdin` command line. Synthetic credentials only.
mod native_e2e;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use hmac::{Hmac, Mac};
use native_e2e::{ADMIN_PASSPHRASE, Admin, free_port};
use serde_json::{Value, json};
use sha2::Sha256;
use tempfile::TempDir;
use zeropw::context::{Config, Context};
use zeropw::team::identity::DeviceKey;
use zeropw::team::membership::{self, CreatedInvite};
use zeropw::team::sync;
use zeropw::team::transport::{InProcessTransport, MembershipCheck, TcpTransport, Transport};

const DAY: f64 = 86_400.0;

/// A clock the test moves by hand.
struct TestClock(Arc<AtomicU64>);

impl TestClock {
    fn set(&self, ts: f64) {
        self.0.store(ts.to_bits(), Ordering::SeqCst);
    }
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

/// A context holding one shared environment; returns its env id.
fn shared(root: &TempDir, name: &str, start: f64) -> (Arc<Context>, TestClock, String) {
    let (ctx, clock) = context_at(root, name, start);
    ctx.projects.create("demo", &["dev"]).unwrap();
    let shared =
        membership::share_environment(&ctx, None, "demo", "dev", "owner", "admin-passphrase")
            .unwrap();
    let env = shared["env_id"].as_str().unwrap().to_owned();
    (ctx, clock, env)
}

fn now() -> f64 {
    zeropw::clock::now().floor()
}

fn link_invite(ctx: &Context, env: &str, name: &str, address: &str) -> CreatedInvite {
    membership::create_invite_with(
        ctx,
        env,
        "user",
        name,
        membership::INVITE_LINK_TTL_SECONDS,
        &[address.to_owned()],
        true,
    )
    .unwrap()
}

fn proof(secret: &[u8], hash: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(hash);
    mac.finalize().into_bytes().to_vec()
}

/// The handshake proof a joiner holding `invite` would send for `hash`.
fn proof_for(invite: &str, hash: &[u8]) -> Vec<u8> {
    let parsed = membership::parse_invite_or_link(invite).unwrap();
    proof(parsed.invite_secret.expose(), hash)
}

fn invites_file(ctx: &Context, env: &str) -> Value {
    ctx.state
        .read_json(&format!("team/{env}/invites.json"), json!({}))
        .unwrap()
}

fn listed(ctx: &Context, env: &str, id: &str) -> Value {
    membership::list_invites(ctx, env).unwrap()["invites"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["invite_id"] == id)
        .cloned()
        .unwrap_or_else(|| panic!("invite {id} not listed"))
}

/// RFC 4648 base32, lower case and unpadded, as the invite encoder writes.
fn b32(raw: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let (mut bits, mut held, mut out) = (0u32, 0u32, String::new());
    for byte in raw {
        bits = (bits << 8) | u32::from(*byte);
        held += 8;
        while held >= 5 {
            held -= 5;
            out.push(ALPHABET[((bits >> held) & 31) as usize] as char);
        }
    }
    if held > 0 {
        out.push(ALPHABET[((bits << (5 - held)) & 31) as usize] as char);
    }
    out
}

/// A hand-made invite string with `changes` applied to a valid payload.
fn crafted(changes: Value) -> String {
    let mut payload = json!({
        "format": membership::INVITE_FORMAT,
        "env_id": "aaaaaaaaaaaaaaaaaaaaaaaaaa-0123456789abcdef0123456789abcdef",
        "inviter": "aaaaaaaaaaaaaaaaaaaaaaaaaa",
        "addresses": ["192.0.2.10:47001"],
        "invite_secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "expires_at": "2099-01-01T00:00:00Z",
        "role": "user",
        "name": "synthetic-crafted",
    });
    for (key, value) in changes.as_object().unwrap() {
        payload[key] = value.clone();
    }
    b32(serde_json::to_string(&payload).unwrap().as_bytes())
}

fn assert_rejected_without_echo(text: &str, secret_part: &str) {
    match membership::parse_invite_or_link(text) {
        Ok(_) => panic!("accepted {text:?}"),
        Err(error) => {
            assert_eq!(error.reason, "invite_malformed", "{text:?}");
            let rendered = error.to_dict().to_string();
            if !secret_part.is_empty() {
                assert!(!rendered.contains(secret_part), "echoed: {rendered}");
            }
        }
    }
}

#[test]
fn link_and_invite_string_round_trip() {
    let root = TempDir::new().unwrap();
    let start = now();
    let (ctx, _clock, env) = shared(&root, "a", start);
    let addresses = vec![
        "192.0.2.10:47001".to_owned(),
        "[fd00::1]:47001".to_owned(),
        "node-a.example.test:47001".to_owned(),
    ];
    let created =
        membership::create_invite_with(&ctx, &env, "admin", "bob", 86_400, &addresses, true)
            .unwrap();
    let link = created.link.clone().unwrap();
    assert_eq!(link, format!("zeropw://join#{}", created.invite));
    assert_eq!(
        membership::parse_invite_link(&link).unwrap(),
        created.invite
    );
    assert!(link.len() <= membership::MAX_INVITE_LINK_BYTES);
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let upper = format!("ZeroPW://JOIN/#{}", created.invite);
    for text in [link.as_str(), created.invite.as_str(), upper.as_str()] {
        let invite = membership::parse_invite_or_link(text).unwrap();
        assert_eq!(invite.env_id, env);
        assert_eq!(invite.inviter, device.fingerprint().unwrap());
        assert_eq!(invite.addresses, addresses);
        assert_eq!(invite.role, "admin");
        assert_eq!(invite.name, "bob");
        let preview = membership::invite_preview(&invite, start);
        assert_eq!(
            preview,
            json!({"env_id": env, "inviter": invite.inviter, "addresses": addresses,
                "role": "admin", "name": "bob", "expires_at": created.expires_at,
                "expired": false, "invite_id": created.invite_id})
        );
    }
    assert_eq!(
        created.expires_at,
        zeropw::store::iso(Some(start + DAY)),
        "a link invite lasts exactly one day"
    );
    let entry = &invites_file(&ctx, &env)[&created.invite_id];
    assert_eq!(entry["link"], true);
    assert_eq!(entry["created_at"].as_f64(), Some(start));
    assert_eq!(entry["used"], false);
    // Without `link`, the stored entry and the invite stay as before.
    let plain =
        membership::create_invite_with(&ctx, &env, "user", "carol", 3600, &[], false).unwrap();
    assert!(plain.link.is_none());
    assert!(
        invites_file(&ctx, &env)[&plain.invite_id]
            .get("link")
            .is_none()
    );
}

#[test]
fn link_creation_rules() {
    let root = TempDir::new().unwrap();
    let (ctx, _clock, env) = shared(&root, "a", now());
    let reason = |ttl: i64, addresses: &[&str], name: &str| {
        let addresses: Vec<String> = addresses.iter().map(|a| (*a).to_owned()).collect();
        membership::create_invite_with(&ctx, &env, "user", name, ttl, &addresses, true)
            .err()
            .map(|e| e.reason.to_string())
    };
    assert_eq!(
        reason(3600, &[], "bob").as_deref(),
        Some("invite_link_ttl_fixed")
    );
    assert_eq!(
        reason(2 * 86_400, &[], "bob").as_deref(),
        Some("invite_link_ttl_fixed")
    );
    for bad in [
        "node-a",
        "node-a:0",
        "node-a:70000",
        "node a:1",
        ":1",
        "[::1:1",
    ] {
        assert_eq!(
            reason(86_400, &[bad], "bob").as_deref(),
            Some("invalid_address"),
            "{bad:?}"
        );
    }
    // 16 maximal addresses and a long non-ASCII name do not fit in 4096 bytes.
    let long = format!("{}.test:47001", "a".repeat(116));
    let many: Vec<&str> = std::iter::repeat_n(long.as_str(), 16).collect();
    let name = "\u{d55c}".repeat(200);
    assert_eq!(
        reason(86_400, &many, &name).as_deref(),
        Some("invite_link_too_long")
    );
    // None of the refusals stored anything.
    assert_eq!(invites_file(&ctx, &env), json!({}));
    assert_eq!(reason(86_400, &[], "bob"), None);
}

#[test]
fn malformed_links_are_rejected_without_echo() {
    let root = TempDir::new().unwrap();
    let (ctx, _clock, env) = shared(&root, "a", now());
    let created = link_invite(&ctx, &env, "bob", "192.0.2.10:47001");
    let invite = created.invite.as_str();
    let cases = [
        format!("zeropw://join?x=1#{invite}"),
        format!("zeropw://join/?x=1#{invite}"),
        format!("zeropw://user@join#{invite}"),
        format!("zeropw://join:443#{invite}"),
        format!("zeropw://join/extra#{invite}"),
        format!("zeropw://join//#{invite}"),
        format!("zeropw://join#%61{invite}"),
        format!("zeropw://join#{invite}%3D"),
        format!("zeropw://join# {invite}"),
        format!("zeropw://join#{invite} "),
        format!(" zeropw://join#{invite}"),
        format!("zeropw://join#{invite}\n"),
        format!("zeropw://join#{invite}#{invite}"),
        format!("zeropw://join#{invite}?x=1"),
        format!("zeropw:join#{invite}"),
        format!("zeropw:/join#{invite}"),
        format!("https://join#{invite}"),
        format!("zeropw://joins#{invite}"),
        format!("zeropw://j\u{f6}in#{invite}"),
        format!("zeropw://join#{invite}\u{e9}"),
        format!("zeropw://join{invite}"),
        "zeropw://join#".to_owned(),
        "zeropw://join#====".to_owned(),
        "zeropw://join".to_owned(),
        format!(
            "zeropw://join#{}",
            "a".repeat(membership::MAX_INVITE_LINK_BYTES)
        ),
        "a".repeat(membership::MAX_INVITE_TEXT_BYTES + 1),
    ];
    for text in &cases {
        assert_rejected_without_echo(text, invite);
    }
    // A link whose fragment decodes to something else is not an invite.
    assert_rejected_without_echo("zeropw://join#mzxw6", "");
    // Deterministic random input: never accepted, never echoed, never a panic.
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for round in 0..3000 {
        let len = (next() % 600) as usize;
        let mut bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        if round % 3 == 0 {
            let mut prefixed = b"zeropw://join#".to_vec();
            prefixed.extend(bytes);
            bytes = prefixed;
        }
        let text = String::from_utf8_lossy(&bytes).into_owned();
        if let Err(error) = membership::parse_invite_or_link(&text) {
            let rendered = error.to_dict().to_string();
            if text.len() >= 8 {
                assert!(!rendered.contains(&text), "echoed random input");
            }
        } else {
            panic!("random input accepted: {text:?}");
        }
    }
    // Single-character mutations of a valid link never panic or echo.
    let link = created.link.unwrap();
    for index in 0..link.len() {
        for replacement in ['#', '%', ' ', 'A', '1', ':', '/', '?', '@'] {
            let mut mutated = link.clone().into_bytes();
            mutated[index] = replacement as u8;
            let text = String::from_utf8(mutated).unwrap();
            if let Err(error) = membership::parse_invite_or_link(&text) {
                assert!(!error.to_dict().to_string().contains(invite));
            }
        }
    }
}

#[test]
fn untrusted_invite_fields_are_bounded() {
    // The lenient library parser keeps accepting what the prototype did; the
    // preview/join parser does not.
    let cases = [
        json!({"inviter": "aaaaaaa\u{e9}"}),
        json!({"inviter": "AAAAAAAAAAAAAAAAAAAAAAAAAA"}),
        json!({"inviter": "aaaaaaaaaaaaaaaaaaaaaaaaa"}),
        json!({"addresses": vec!["192.0.2.10:47001"; 17]}),
        json!({"addresses": [format!("{}.test:1", "a".repeat(122))]}),
        json!({"addresses": ["192.0.2.10"]}),
        json!({"addresses": ["192.0.2.10:0"]}),
        json!({"addresses": ["192.0.2.10:65536"]}),
        json!({"addresses": ["192.0.2.10:1 extra"]}),
        json!({"addresses": ["192.0.2.10:+1"]}),
        json!({"addresses": "192.0.2.10:1"}),
        json!({"addresses": [""]}),
        json!({"expires_at": "soon"}),
        json!({"expires_at": 4_070_908_800_u64}),
    ];
    for changes in cases {
        let text = crafted(changes.clone());
        membership::parse_invite(&text).unwrap_or_else(|e| panic!("{changes}: {e}"));
        assert_rejected_without_echo(&text, "synthetic-crafted");
        assert_rejected_without_echo(&format!("zeropw://join#{text}"), "synthetic-crafted");
    }
    let sixteen = crafted(json!({"addresses": vec!["192.0.2.10:47001"; 16]}));
    assert!(membership::parse_invite_or_link(&sixteen).is_ok());
    let limit = format!("{}.test:47001", "a".repeat(117));
    assert_eq!(limit.len(), 128);
    assert!(membership::parse_invite_or_link(&crafted(json!({"addresses": [limit]}))).is_ok());
}

#[test]
fn link_invite_is_single_use_and_records_the_joiner() {
    let root = TempDir::new().unwrap();
    let (a, _clock, env) = shared(&root, "a", now());
    let a_device = DeviceKey::load_or_create(a.state, a.kms).unwrap();
    let none: MembershipCheck = Arc::new(|_, _| None);
    let a_transport = Arc::new(InProcessTransport::new(a_device.clone(), none.clone()));
    let a_sync = sync::TeamSync::new(a.clone(), a_transport, a_device);
    let address = "invite-link-single-use.test:47001";
    a_sync.start(Some(address)).unwrap();
    let created = link_invite(&a, &env, "bob", address);
    let link = created.link.clone().unwrap();
    let join = |name: &str, timeout: f64| {
        let (ctx, _) = context_at(&root, name, now());
        let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        let transport = Arc::new(InProcessTransport::new(device.clone(), none.clone()));
        let team = sync::TeamSync::new(ctx.clone(), transport.clone(), device.clone());
        team.start(None).unwrap();
        let result = membership::join(
            &ctx,
            membership::invite_string_of(&link).unwrap(),
            transport.as_ref() as &dyn Transport,
            &team,
            Some("shared"),
            Some("dev"),
            timeout,
        );
        team.stop();
        (result, device.fingerprint().unwrap())
    };
    let (joined, b_fp) = join("b", 5.0);
    let joined = joined.unwrap();
    assert_eq!(joined["env_id"], env);
    let entry = &invites_file(&a, &env)[&created.invite_id];
    assert_eq!(entry["used"], true);
    assert_eq!(entry["used_by"], json!(b_fp));
    assert!(entry["used_at"].is_number());
    assert!(entry.get("wrapped_secret").is_none(), "{entry}");
    let item = listed(&a, &env, &created.invite_id);
    assert_eq!(item["status"], "used");
    assert_eq!(item["used_by"], json!(b_fp));
    assert!(item["used_at"].is_string());
    // The same link a second time: refused by the inviter.
    let (again, _) = join("c", 0.5);
    assert!(again.is_err());
    assert_eq!(listed(&a, &env, &created.invite_id)["used_by"], json!(b_fp));
    // Revoking a used invite is refused and changes nothing.
    let error = membership::revoke_invite(&a, &env, &created.invite_id).unwrap_err();
    assert_eq!(error.reason, "invite_already_used");
    assert_eq!(listed(&a, &env, &created.invite_id)["status"], "used");
    a_sync.stop();
}

#[test]
fn link_invite_expires_exactly_one_day_after_creation() {
    let root = TempDir::new().unwrap();
    let start = now();
    let (ctx, clock, env) = shared(&root, "a", start);
    let hash = [7u8; 32];
    let on_time = link_invite(&ctx, &env, "on-time", "192.0.2.10:47001");
    let late = link_invite(&ctx, &env, "late", "192.0.2.10:47001");
    clock.set(start + DAY);
    assert_eq!(listed(&ctx, &env, &late.invite_id)["status"], "pending");
    assert_eq!(
        membership::consume_invite_by(
            &ctx,
            &env,
            &hash,
            &proof_for(&on_time.invite, &hash),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaa"),
        )
        .unwrap(),
        Some(("user".to_owned(), "on-time".to_owned()))
    );
    clock.set(start + DAY + 0.001);
    assert_eq!(listed(&ctx, &env, &late.invite_id)["status"], "expired");
    assert_eq!(
        membership::consume_invite_by(&ctx, &env, &hash, &proof_for(&late.invite, &hash), None)
            .unwrap(),
        None
    );
    assert_eq!(invites_file(&ctx, &env)[&late.invite_id]["used"], false);
    // The joiner's local check allows five minutes of clock drift.
    let parsed = membership::parse_invite_or_link(late.link.as_deref().unwrap()).unwrap();
    assert!(!membership::invite_expired(&parsed, start + DAY));
    assert!(!membership::invite_expired(&parsed, start + DAY + 300.0));
    assert!(membership::invite_expired(&parsed, start + DAY + 300.5));
    assert_eq!(
        membership::invite_preview(&parsed, start + DAY + 301.0)["expired"],
        true
    );
}

#[test]
fn revoked_invite_is_refused_and_revoking_is_idempotent() {
    let root = TempDir::new().unwrap();
    let start = now();
    let (ctx, clock, env) = shared(&root, "a", start);
    let created = link_invite(&ctx, &env, "bob", "192.0.2.10:47001");
    clock.set(start + 60.0);
    let revoked = membership::revoke_invite(&ctx, &env, &created.invite_id).unwrap();
    assert_eq!(
        revoked,
        json!({"env_id": env, "invite_id": created.invite_id, "status": "revoked",
            "revoked_at": zeropw::store::iso(Some(start + 60.0)), "already_revoked": false})
    );
    let entry = &invites_file(&ctx, &env)[&created.invite_id];
    assert!(entry.get("wrapped_secret").is_none(), "{entry}");
    assert_eq!(entry["revoked_at"].as_f64(), Some(start + 60.0));
    let hash = [9u8; 32];
    assert_eq!(
        membership::consume_invite_by(&ctx, &env, &hash, &proof_for(&created.invite, &hash), None)
            .unwrap(),
        None
    );
    clock.set(start + 120.0);
    let again = membership::revoke_invite(&ctx, &env, &created.invite_id).unwrap();
    assert_eq!(again["already_revoked"], true);
    assert_eq!(again["revoked_at"], revoked["revoked_at"]);
    let item = listed(&ctx, &env, &created.invite_id);
    assert_eq!(item["status"], "revoked");
    assert_eq!(item["revoked_at"], revoked["revoked_at"]);
    let missing =
        membership::revoke_invite(&ctx, &env, "00000000000000000000000000000000").unwrap_err();
    assert_eq!(missing.reason, "invite_not_found");
    assert_eq!(missing.to_dict()["error"], "NotFound");
    let records = ctx.audit.tail(500).unwrap();
    let revokes: Vec<&Value> = records
        .iter()
        .filter(|r| r["event"] == "team_invite_revoke")
        .collect();
    assert_eq!(revokes.len(), 1, "only the first revocation is audited");
    assert_eq!(revokes[0]["detail"], json!(created.invite_id));
    assert_eq!(revokes[0]["env_id"], json!(env));
}

#[test]
fn revoke_and_consume_race_has_exactly_one_winner() {
    let root = TempDir::new().unwrap();
    let (ctx, _clock, env) = shared(&root, "a", now());
    let hash = [5u8; 32];
    let (mut revoked_wins, mut consumed_wins) = (0, 0);
    for round in 0..24 {
        let created = link_invite(&ctx, &env, &format!("racer-{round}"), "192.0.2.10:47001");
        let signature = proof_for(&created.invite, &hash);
        let barrier = Arc::new(Barrier::new(2));
        let revoker = {
            let (ctx, env, id, barrier) = (
                ctx.clone(),
                env.clone(),
                created.invite_id.clone(),
                barrier.clone(),
            );
            std::thread::spawn(move || {
                barrier.wait();
                membership::revoke_invite(&ctx, &env, &id)
            })
        };
        barrier.wait();
        let consumed = membership::consume_invite_by(
            &ctx,
            &env,
            &hash,
            &signature,
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaa"),
        )
        .unwrap();
        let revoked = revoker.join().unwrap();
        let status = listed(&ctx, &env, &created.invite_id)["status"].clone();
        match (consumed, revoked) {
            (Some(_), Err(error)) => {
                assert_eq!(error.reason, "invite_already_used");
                assert_eq!(status, "used");
                consumed_wins += 1;
            }
            (None, Ok(result)) => {
                assert_eq!(result["already_revoked"], false);
                assert_eq!(status, "revoked");
                revoked_wins += 1;
            }
            (consumed, revoked) => {
                panic!("round {round}: consumed={consumed:?} revoked={revoked:?}")
            }
        }
        assert!(
            invites_file(&ctx, &env)[&created.invite_id]
                .get("wrapped_secret")
                .is_none()
        );
    }
    assert_eq!(revoked_wins + consumed_wins, 24);
}

#[test]
fn invite_list_never_exposes_secrets() {
    let root = TempDir::new().unwrap();
    let start = now();
    let (ctx, clock, env) = shared(&root, "a", start);
    let link = link_invite(&ctx, &env, "bob", "192.0.2.10:47001");
    clock.set(start + 1.0);
    let plain =
        membership::create_invite_with(&ctx, &env, "admin", "carol", 3600, &[], false).unwrap();
    let listing = membership::list_invites(&ctx, &env).unwrap();
    let text = listing.to_string();
    for needle in [
        link.invite.as_str(),
        link.link.as_deref().unwrap(),
        plain.invite.as_str(),
        "wrapped_secret",
        "ciphertext",
        "invite_secret",
    ] {
        assert!(!text.contains(needle), "the listing exposes {needle:.24}");
    }
    for created in [&link, &plain] {
        let secret = membership::parse_invite_or_link(&created.invite)
            .unwrap()
            .invite_secret;
        let needles = [secret.expose().to_vec()];
        assert_eq!(native_e2e::find_secret(text.as_bytes(), &needles), None);
    }
    let items = listing["invites"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    for item in items {
        let mut keys: Vec<&str> = item
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "created_at",
                "expires_at",
                "invite_id",
                "link",
                "name",
                "revoked_at",
                "role",
                "status",
                "used_at",
                "used_by"
            ]
        );
    }
    // Oldest first, whatever the (random) invite ids.
    assert_eq!(items[0]["invite_id"], json!(link.invite_id));
    assert_eq!(items[1]["invite_id"], json!(plain.invite_id));
    let linked = listed(&ctx, &env, &link.invite_id);
    assert_eq!(linked["link"], true);
    assert_eq!(linked["status"], "pending");
    assert_eq!(linked["expires_at"], json!(link.expires_at));
    assert_eq!(listed(&ctx, &env, &plain.invite_id)["link"], false);
}

#[test]
fn legacy_invite_entries_list_and_are_consumed() {
    let root = TempDir::new().unwrap();
    let (ctx, _clock, env) = shared(&root, "a", now());
    let secret = [42u8; 32];
    let id = membership::invite_id(&secret);
    let path = format!("team/{env}/invites.json");
    ctx.state
        .write_json(
            &path,
            &json!({
                id.clone(): {"wrapped_secret": ctx.kms.wrap(&secret).unwrap().to_dict(),
                    "role": "user", "name": "legacy", "used": false,
                    "expires_at": "2099-01-01T00:00:00Z"},
                "fixture": {"role": "admin", "name": "old", "used": true, "expires_at": 0},
            }),
        )
        .unwrap();
    let item = listed(&ctx, &env, &id);
    assert_eq!(
        item,
        json!({"invite_id": id, "role": "user", "name": "legacy", "link": false,
            "created_at": null, "expires_at": "2099-01-01T00:00:00Z", "status": "pending",
            "used_at": null, "used_by": null, "revoked_at": null})
    );
    assert_eq!(listed(&ctx, &env, "fixture")["status"], "used");
    let hash = [3u8; 32];
    assert_eq!(
        membership::consume_invite_by(
            &ctx,
            &env,
            &hash,
            &proof(&secret, &hash),
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbb")
        )
        .unwrap(),
        Some(("user".to_owned(), "legacy".to_owned()))
    );
    let item = listed(&ctx, &env, &id);
    assert_eq!(item["status"], "used");
    assert_eq!(item["used_by"], "bbbbbbbbbbbbbbbbbbbbbbbbbb");
    let entry = &invites_file(&ctx, &env)[&id];
    assert!(entry.get("wrapped_secret").is_none());
    assert_eq!(entry["name"], "legacy");
    // The legacy entry that was already used cannot be revoked either.
    assert_eq!(
        membership::revoke_invite(&ctx, &env, "fixture")
            .unwrap_err()
            .reason,
        "invite_already_used"
    );
}

// ---------------------------------------------------------------- CLI

/// An initialized CLI state with `demo/dev` shared by the library.
fn cli_shared(root: &std::path::Path) -> Admin {
    let admin = Admin::new(root);
    admin.ok(&["init"]);
    admin.ok(&["project", "create", "demo"]);
    let ctx = Context::open(&admin.state, Config::default(), zeropw::clock::system()).unwrap();
    membership::share_environment(&ctx, None, "demo", "dev", "owner", ADMIN_PASSPHRASE).unwrap();
    admin
}

fn keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    keys
}

#[test]
fn cli_invite_link_list_revoke_and_preview() {
    let tmp = TempDir::new().unwrap();
    let admin = cli_shared(tmp.path());
    let invite = |extra: &[&str]| {
        let mut args = vec![
            "team",
            "invite",
            "--env",
            "demo/dev",
            "--role",
            "user",
            "--name",
            "bob",
            "--address",
            "127.0.0.1:47001",
        ];
        args.extend_from_slice(extra);
        admin.cmd(&args)
    };
    let plain = invite(&[]).ok();
    assert_eq!(
        keys(&plain),
        ["env_id", "invite", "name", "role", "warning"]
    );
    let linked = invite(&["--link"]).ok();
    assert_eq!(
        keys(&linked),
        [
            "env_id",
            "expires_at",
            "invite",
            "invite_id",
            "link",
            "name",
            "role",
            "warning"
        ]
    );
    let link = linked["link"].as_str().unwrap().to_owned();
    assert_eq!(
        link,
        format!("zeropw://join#{}", linked["invite"].as_str().unwrap())
    );
    let invite_id = linked["invite_id"].as_str().unwrap().to_owned();
    assert_eq!(invite_id.len(), 32);
    invite(&["--link", "--ttl", "24h"]).ok();
    let fixed = invite(&["--link", "--ttl", "1h"]).fail(1);
    assert_eq!(fixed["reason"], "invite_link_ttl_fixed");
    let bad_address = admin
        .cmd(&[
            "team",
            "invite",
            "--env",
            "demo/dev",
            "--role",
            "user",
            "--name",
            "bob",
            "--address",
            "not-an-address",
            "--link",
        ])
        .fail(1);
    assert_eq!(bad_address["reason"], "invalid_address");

    // Preview: raw stdin (one trailing newline), the envelope, and without
    // any state directory at all.
    let preview = admin
        .cmd(&["team", "invite-info", "--stdin"])
        .stdin(format!("{link}\n").as_bytes())
        .ok();
    assert_eq!(
        keys(&preview),
        [
            "addresses",
            "env_id",
            "expired",
            "expires_at",
            "invite_id",
            "inviter",
            "name",
            "role"
        ]
    );
    assert_eq!(preview["invite_id"], json!(invite_id));
    assert_eq!(preview["expires_at"], linked["expires_at"]);
    assert_eq!(preview["expired"], false);
    assert_eq!(preview["addresses"], json!(["127.0.0.1:47001"]));
    let enveloped = admin
        .cmd(&["--input-envelope", "team", "invite-info", "--stdin"])
        .stdin(json!({"invite": link}).to_string().as_bytes())
        .state(&tmp.path().join("not-created-yet"))
        .ok();
    assert_eq!(enveloped, preview);
    assert!(!tmp.path().join("not-created-yet").exists());
    let no_source = admin.cmd(&["team", "invite-info"]).fail(1);
    assert_eq!(no_source["reason"], "invite_source_required");
    let empty_envelope = admin
        .cmd(&["--input-envelope", "team", "invite-info", "--stdin"])
        .stdin(b"{}")
        .fail(1);
    assert_eq!(empty_envelope["reason"], "invite_source_required");
    let marker = "zz-not-an-invite-marker";
    let (code, out, err) = admin
        .cmd(&["team", "invite-info", "--stdin"])
        .stdin(format!("zeropw://join?{marker}#abc").as_bytes())
        .run();
    assert_eq!((code, out.as_str()), (1, ""));
    assert!(
        err.contains("invite_malformed") && !err.contains(marker),
        "{err}"
    );

    // The list, revocation and the list again.
    let listing = admin.ok(&["team", "invites", "--env", "demo/dev"]);
    let items = listing["invites"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    assert!(items.iter().all(|item| item["status"] == "pending"));
    let text = listing.to_string();
    assert!(!text.contains(linked["invite"].as_str().unwrap()));
    assert!(!text.contains(plain["invite"].as_str().unwrap()));
    let revoked = admin.ok(&[
        "team",
        "revoke-invite",
        "--env",
        "demo/dev",
        "--id",
        &invite_id,
    ]);
    assert_eq!(revoked["status"], "revoked");
    assert_eq!(revoked["already_revoked"], false);
    let again = admin.ok(&[
        "team",
        "revoke-invite",
        "--env",
        "demo/dev",
        "--id",
        &invite_id,
    ]);
    assert_eq!(again["already_revoked"], true);
    let unknown = admin.fail(&[
        "team",
        "revoke-invite",
        "--env",
        "demo/dev",
        "--id",
        "00000000000000000000000000000000",
    ]);
    assert_eq!(unknown["reason"], "invite_not_found");
    let listing = admin.ok(&["team", "invites", "--env", "demo/dev"]);
    let item = listing["invites"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["invite_id"] == json!(invite_id))
        .unwrap()
        .clone();
    assert_eq!(item["status"], "revoked");
    assert_eq!(item["link"], true);
    assert!(native_e2e::events(&admin.state).contains(&"team_invite_revoke".to_owned()));
}

#[test]
fn cli_join_reads_the_invite_from_stdin_and_checks_it_first() {
    let tmp = TempDir::new().unwrap();
    let joiner = Admin::new(&tmp.path().join("joiner"));
    joiner.ok(&["init"]);
    let join = |args: &[&str]| {
        let mut argv = vec!["team", "join"];
        argv.extend_from_slice(args);
        joiner.cmd(&argv)
    };
    let expired = crafted(json!({"expires_at": "2000-01-01T00:00:00Z"}));
    let refused = join(&["--stdin"])
        .stdin(format!("zeropw://join#{expired}").as_bytes())
        .fail(1);
    assert_eq!(refused["reason"], "invite_expired");
    let refused = joiner
        .cmd(&["--input-envelope", "team", "join", "--stdin"])
        .stdin(json!({"invite": expired}).to_string().as_bytes())
        .fail(1);
    assert_eq!(refused["reason"], "invite_expired");
    assert_eq!(join(&[&expired]).fail(1)["reason"], "invite_expired");
    // Bounded fields are checked before anything is dialed.
    let unbounded = crafted(json!({"addresses": ["192.0.2.10"]}));
    assert_eq!(join(&[&unbounded]).fail(1)["reason"], "invite_malformed");
    assert_eq!(join(&[]).fail(1)["reason"], "invite_source_required");
    let conflict = join(&[&expired, "--stdin"]).stdin(b"x").fail(1);
    assert_eq!(conflict["reason"], "invite_source_conflict");
    let (code, out, err) = join(&["--stdin"])
        .stdin(b"zeropw://join#abc def-synthetic-marker")
        .run();
    assert_eq!((code, out.as_str()), (1, ""));
    assert!(err.contains("invite_malformed"), "{err}");
    // No team state was written for any refused invite.
    assert!(!joiner.state.join("team").join("env_map.json").exists());
    assert!(
        !native_e2e::events(&joiner.state)
            .iter()
            .any(|event| event.starts_with("team_"))
    );
}

#[test]
fn cli_join_through_an_enveloped_link_records_the_joiner() {
    let tmp = TempDir::new().unwrap();
    let inviter = cli_shared(&tmp.path().join("inviter"));
    // The inviter's running node (what `serve --team-listen` hosts).
    let ctx = Arc::new(
        Context::open(&inviter.state, Config::default(), zeropw::clock::system()).unwrap(),
    );
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let transport = TcpTransport::new(device.clone(), Arc::new(|_, _| None), 8);
    let node = sync::TeamSync::new(ctx.clone(), Arc::new(transport), device);
    let address = format!("127.0.0.1:{}", free_port());
    node.start(Some(&address)).unwrap();
    let linked = inviter.ok(&[
        "team",
        "invite",
        "--env",
        "demo/dev",
        "--role",
        "user",
        "--name",
        "bob",
        "--address",
        &address,
        "--link",
    ]);
    let link = linked["link"].as_str().unwrap().to_owned();
    let joiner = Admin::new(&tmp.path().join("joiner"));
    joiner.ok(&["init"]);
    let joined = joiner
        .cmd(&[
            "--input-envelope",
            "team",
            "join",
            "--stdin",
            "--project",
            "shared",
            "--environment",
            "dev",
        ])
        .stdin(json!({"invite": link}).to_string().as_bytes())
        .ok();
    assert_eq!(joined["env_id"], linked["env_id"]);
    assert_eq!(joined["project"], "shared");
    let listing = inviter.ok(&["team", "invites", "--env", "demo/dev"]);
    let item = &listing["invites"][0];
    assert_eq!(item["status"], "used");
    assert_eq!(item["used_by"], joined["self_fingerprint"]);
    // Single use of the same link is covered by
    // `link_invite_is_single_use_and_records_the_joiner` (a refused joiner
    // waits out the join timeout).
    node.stop();
}
