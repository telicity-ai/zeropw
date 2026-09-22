//! Independent Astra review regressions for 06cf76f665937da557bf7a0272dbbc2d07735569.
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;

use serde_json::{Value, json};
use tempfile::TempDir;
use zeropw::context::{Config, Context};
use zeropw::team::identity::DeviceKey;
use zeropw::team::transport::{InProcessTransport, MembershipCheck};
use zeropw::team::{commit, membership, sync};

fn python(script: &str, input: &Value) -> Value {
    let mut child = Command::new("python3.12")
        .args(["-c", script])
        .env("PYTHONPATH", format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

fn ctx(tmp: &TempDir) -> Arc<Context> {
    Arc::new(
        Context::initialize(
            tmp.path().join("state"),
            "admin-passphrase",
            "recovery-passphrase",
            Config::default(),
            zeropw::clock::system(),
        )
        .unwrap(),
    )
}

fn invite_payload(inviter: &str) -> Value {
    json!({"format":membership::INVITE_FORMAT,"env_id":"aaaaaaaaaaaaaaaaaaaaaaaaaa-0123456789abcdef0123456789abcdef",
        "inviter":inviter,"addresses":[],"invite_secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "expires_at":"2099-01-01T00:00:00Z","role":"user","name":"synthetic"})
}

#[test]
fn astra_t1_untrusted_unicode_inviter_cannot_panic_join() {
    let input = invite_payload("aaaaaaaé");
    let encoded = python(
        "import json,base64,sys\np=json.load(sys.stdin)\ns=base64.b32encode(json.dumps(p).encode()).decode().rstrip('=')\nfrom zeropw.team.membership import parse_invite\nassert parse_invite(s)['inviter'] == p['inviter']\nprint(json.dumps(s))",
        &input,
    );
    let tmp = TempDir::new().unwrap();
    let ctx = ctx(&tmp);
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let members: MembershipCheck = Arc::new(|_, _| None);
    let transport = Arc::new(InProcessTransport::new(device.clone(), members));
    let team = sync::TeamSync::new(ctx.clone(), transport.clone(), device);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        membership::join(
            &ctx,
            encoded.as_str().unwrap(),
            transport.as_ref(),
            &team,
            None,
            None,
            0.01,
        )
    }));
    assert!(
        result.is_ok(),
        "untrusted invite panicked instead of returning team_join_failed"
    );
    assert_eq!(result.unwrap().unwrap_err().reason, "team_join_failed");
}

#[test]
fn astra_t2_live_fact_publication_records_apply_audit() {
    let tmp = TempDir::new().unwrap();
    let ctx = ctx(&tmp);
    ctx.projects.create("demo", &["dev"]).unwrap();
    let shared =
        membership::share_environment(&ctx, None, "demo", "dev", "synthetic", "admin-passphrase")
            .unwrap();
    let env = shared["env_id"].as_str().unwrap();
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let members: MembershipCheck = Arc::new(|_, _| None);
    let transport = Arc::new(InProcessTransport::new(device.clone(), members));
    let team = sync::TeamSync::new(ctx.clone(), transport, device);
    team.register_env(env).unwrap();
    team.publish_fact(
        env,
        "connection_disabled",
        json!({"connection_id":"synthetic-connection"}),
    )
    .unwrap();
    let events = ctx
        .state
        .read_lines(zeropw::audit::AUDIT_FILE, None)
        .unwrap();
    let count = events
        .iter()
        .filter_map(|s| serde_json::from_str::<Value>(s).ok())
        .filter(|v| v["event"] == "team_fact_apply")
        .count();
    assert_eq!(
        count, 1,
        "locally originated live emergency fact needs the Python audit event"
    );
}

#[test]
fn astra_t3_padded_base32_invites_match_python() {
    let mut input = invite_payload("aaaaaaaaaaaaaaaaaaaaaaaaaa");
    // Choose a payload whose standard base32 representation needs padding.
    input["name"] = json!("synthetic padded invite");
    let encoded = python(
        "import json,base64,sys\np=json.load(sys.stdin)\np['name'] += 'x'\ns=base64.b32encode(json.dumps(p).encode()).decode()\nfrom zeropw.team.membership import parse_invite\nassert parse_invite(s)['name'] == p['name']\nassert '=' in s\nprint(json.dumps(s))",
        &input,
    );
    assert!(
        membership::parse_invite(encoded.as_str().unwrap()).is_ok(),
        "Python accepts standard padded base32 invites"
    );
}

#[test]
fn astra_t4_fact_target_dict_string_pairs_match_python() {
    let input = json!({"format":sync::FACT_FORMAT,"env_id":"env","kind":"incident",
        "target":["ab","cd"],"author":"author","hlc":"1-0","sig":""});
    let expected = python(
        "import json,sys\nfrom zeropw.team.sync import Fact\nprint(json.dumps(Fact.from_dict(json.load(sys.stdin)).to_dict()))",
        &input,
    );
    assert_eq!(sync::Fact::from_dict(&input).unwrap().to_dict(), expected);
}

#[test]
fn astra_t5_iso_expiry_invite_state_matches_python() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let tmp = TempDir::new().unwrap();
    let ctx = ctx(&tmp);
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let env = commit::new_env_id(&device.fingerprint().unwrap()).unwrap();
    let secret = [42u8; 32];
    let hash = [7u8; 32];
    let mut mac = Hmac::<Sha256>::new_from_slice(&secret).unwrap();
    mac.update(&hash);
    let proof = mac.finalize().into_bytes();
    ctx.state
        .write_json(
            &format!("team/{env}/invites.json"),
            &json!({"synthetic":{
        "wrapped_secret":ctx.kms.wrap(&secret).unwrap().to_dict(), "role":"user","name":"synthetic",
        "used":false,"expires_at":"2099-01-01T00:00:00Z"}}),
        )
        .unwrap();
    let expected = python(
        "import json,sys\nfrom zeropw.team.membership import _parse_expiry\nprint(json.dumps(_parse_expiry(json.load(sys.stdin)) > 0))",
        &json!("2099-01-01T00:00:00Z"),
    );
    assert_eq!(expected, true);
    assert_eq!(
        membership::consume_invite(&ctx, &env, &hash, &proof).unwrap(),
        Some(("user".into(), "synthetic".into()))
    );
}
