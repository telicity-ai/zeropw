//! Independent Astra review regressions for 06cf76f665937da557bf7a0272dbbc2d07735569.
use std::sync::Arc;

use serde_json::{Value, json};
use tempfile::TempDir;
use zeropw::context::{Config, Context};
use zeropw::team::identity::DeviceKey;
use zeropw::team::transport::{InProcessTransport, MembershipCheck};
use zeropw::team::{commit, membership, sync};

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
    // `invite_payload("aaaaaaa\u{e9}")` as the Python prototype encoded it:
    // `base64.b32encode(json.dumps(p).encode()).decode().rstrip("=")`.
    let encoded = json!(
        "PMRGM33SNVQXIIR2EARHUZLSN5YHOLLUMVQW2LLJNZ3GS5DFFV3DCIRMEARGK3TWL5UWIIR2EARGCYLBMFQWCYLBMFQWCYLBMFQWCYLBMFQWCYLBMFQWCLJQGEZDGNBVGY3TQOLBMJRWIZLGGAYTEMZUGU3DOOBZMFRGGZDFMYRCYIBCNFXHM2LUMVZCEORAEJQWCYLBMFQWCXDVGAYGKOJCFQQCEYLEMRZGK43TMVZSEORALNOSYIBCNFXHM2LUMVPXGZLDOJSXIIR2EARECQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBHURCYIBCMV4HA2LSMVZV6YLUEI5CAIRSGA4TSLJQGEWTAMKUGAYDUMBQHIYDAWRCFQQCE4TPNRSSEORAEJ2XGZLSEIWCAITOMFWWKIR2EARHG6LOORUGK5DJMMRH2"
    );
    let payload = invite_payload("aaaaaaa\u{e9}");
    let invite = membership::parse_invite(encoded.as_str().unwrap()).unwrap();
    assert_eq!(json!(invite.inviter), payload["inviter"]);
    assert_eq!(json!(invite.env_id), payload["env_id"]);
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
    // `invite_payload("aaaaaaaaaaaaaaaaaaaaaaaaaa")` named "synthetic padded
    // invitex", as the Python prototype encoded it with standard padding:
    // `base64.b32encode(json.dumps(p).encode()).decode()`.
    let encoded = "PMRGM33SNVQXIIR2EARHUZLSN5YHOLLUMVQW2LLJNZ3GS5DFFV3DCIRMEARGK3TWL5UWIIR2EARGCYLBMFQWCYLBMFQWCYLBMFQWCYLBMFQWCYLBMFQWCLJQGEZDGNBVGY3TQOLBMJRWIZLGGAYTEMZUGU3DOOBZMFRGGZDFMYRCYIBCNFXHM2LUMVZCEORAEJQWCYLBMFQWCYLBMFQWCYLBMFQWCYLBMFQWCYLBMFQSELBAEJQWIZDSMVZXGZLTEI5CAW25FQQCE2LOOZUXIZK7ONSWG4TFOQRDUIBCIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCPJCFQQCEZLYOBUXEZLTL5QXIIR2EARDEMBZHEWTAMJNGAYVIMBQHIYDAORQGBNCELBAEJZG63DFEI5CAITVONSXEIRMEARG4YLNMURDUIBCON4W45DIMV2GSYZAOBQWIZDFMQQGS3TWNF2GK6BCPU======";
    assert!(encoded.ends_with('='));
    let invite = membership::parse_invite(encoded)
        .expect("Python accepts standard padded base32 invites");
    let payload = invite_payload("aaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert_eq!(invite.name, "synthetic padded invitex");
    assert_eq!(json!(invite.inviter), payload["inviter"]);
    assert_eq!(json!(invite.expires_at), payload["expires_at"]);
}

#[test]
fn astra_t4_fact_target_dict_string_pairs_match_python() {
    let input = json!({"format":sync::FACT_FORMAT,"env_id":"env","kind":"incident",
        "target":["ab","cd"],"author":"author","hlc":"1-0","sig":""});
    // What the Python prototype's `Fact.from_dict(...).to_dict()` gave:
    // `dict(["ab", "cd"])` pairs each string's two characters.
    assert_eq!(
        sync::Fact::from_dict(&input).unwrap().to_dict(),
        json!({"format": sync::FACT_FORMAT, "env_id": "env", "kind": "incident",
            "target": {"a": "b", "c": "d"}, "author": "author", "hlc": "1-0", "sig": ""})
    );
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
    assert_eq!(
        membership::consume_invite(&ctx, &env, &hash, &proof).unwrap(),
        Some(("user".into(), "synthetic".into()))
    );
}
