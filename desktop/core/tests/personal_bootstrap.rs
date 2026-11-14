//! Synthetic CLI/daemon boundary tests. Encrypted runtime is exercised in Rust.
mod common;
use common::{FakeLink, Fixture, health_server};
use serde_json::{Value, json};
use std::{fs, sync::Arc, time::Duration};
use zeropw_desktop_core::{
    Core, CoreConfig, NoEvents, SecretString, Settings,
    commands::*,
    pairing::{PairInvite, PairingCode},
};
const A: &str = "faaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "fbbbbbbbbbbbbbbbbbbbbbbbbb";
const OWN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbb";
const PEER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaa";
const PASSWORD: &str = "synthetic-personal-bootstrap-password";
struct OwnedCore(Core);
impl std::ops::Deref for OwnedCore {
    type Target = Core;
    fn deref(&self) -> &Core {
        &self.0
    }
}
impl Drop for OwnedCore {
    fn drop(&mut self) {
        // The new fixture owns any sidecar it starts, including on assertion failure.
        self.0.shutdown();
    }
}
fn core(fx: &Fixture) -> OwnedCore {
    fs::create_dir_all(fx.paths.state_dir()).unwrap();
    fs::write(fx.paths.state_dir().join("admin.json"), b"{}").unwrap();
    let mut config = CoreConfig::new(fx.paths.clone());
    config.serve_stop_grace = Duration::from_secs(3);
    let core = Core::new(config, Arc::new(NoEvents));
    core.settings_set(Settings {
        gateway_port: health_server(),
        team_listen: None,
        link_service: None,
        language: None,
    })
    .unwrap();
    OwnedCore(core)
}
fn decision(binding: &str) -> PersonalJoinDecisionIn {
    PersonalJoinDecisionIn {
        envs: vec!["personal/vault".into()],
        fingerprint: B.into(),
        requests: vec![PersonalJoinRequestIn {
            env: "personal/vault".into(),
            request_id: "1".repeat(32),
            record_binding: binding.into(),
        }],
        admin_passphrase: SecretString::from(PASSWORD),
    }
}

#[test]
fn personal_bootstrap_full_record_approval_is_exact_reauthenticated_and_never_legacy_fallback() {
    let fx = Fixture::new();
    let core = core(&fx);
    let binding = "a".repeat(64);
    let mut empty = decision(&binding);
    empty.admin_passphrase = "".into();
    assert!(core.decide_personal_join(empty, true).is_err());
    assert_eq!(fx.count("team_approve-join"), 0);
    fx.respond(
        "team_approve-join",
        &json!({"approved_invites":["2".repeat(32)]}).to_string(),
    );
    let out = core.decide_personal_join(decision(&binding), true).unwrap();
    assert!(out.envs[0].ok);
    let call = fx.last("team_approve-join");
    assert!(call.requires_admin());
    assert!(
        call.args()
            .contains(&format!("--record-binding={binding}").as_str())
    );
    assert!(
        call.args()
            .contains(&format!("--bootstrap-request={}", "1".repeat(32)).as_str())
    );
    assert_eq!(call.stdin_json()["admin_passphrase"], PASSWORD);
    assert!(!call.argv.iter().any(|value| value.contains(PASSWORD)));
    assert!(!call.env.iter().any(|(_, value)| value.contains(PASSWORD)));
    fx.respond_error(
        "team_approve-join",
        r#"{"error":"StateError","reason":"team_bootstrap_approval_changed"}"#,
        1,
    );
    let changed = core
        .decide_personal_join(decision(&"b".repeat(64)), true)
        .unwrap();
    assert!(!changed.envs[0].ok);
    assert_eq!(
        changed.envs[0].reason.as_deref(),
        Some("team_bootstrap_approval_changed")
    );
    assert_eq!(fx.count("team_approve-join"), 2);
    let tagged = json!({"envs":["personal/vault"],"fingerprint":B,"requests":[{"env":"personal/vault","request_id":"1".repeat(32),"record_binding":binding}],"admin_passphrase":PASSWORD});
    assert!(matches!(
        serde_json::from_value::<JoinApprovalInput>(tagged).unwrap(),
        JoinApprovalInput::Personal(_)
    ));
    let mut invalid = decision(&"a".repeat(64));
    invalid.envs = vec!["work/dev".into()];
    assert!(core.decide_personal_join(invalid, true).is_err());
    assert_eq!(fx.count("team_approve-join"), 2);
}

#[test]
fn personal_bootstrap_desktop_join_waits_for_durable_activation_and_retains_pending_code() {
    let fx = Fixture::new();
    let core = core(&fx);
    let _daemon = FakeLink::start(&fx.paths.link_socket(), |request| {
        Some(match request["op"].as_str().unwrap_or("") {
            "status" => {
                json!({"ok":true,"enrolled":true,"service":"https://link.example.org","device_id":OWN,"account_id":"synthetic","online":true,"peers":[]})
            }
            "devices" => {
                json!({"ok":true,"self":OWN,"devices":[{"device_id":PEER,"name":"original Mac","revoked_at":null}]})
            }
            _ => json!({"ok":false,"error":"invalid_request"}),
        })
    });
    let invitation = "syntheticinviteaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    fx.respond("team_invite-info",&json!({"addresses":[format!("zpl:{PEER}")],"env_id":"envsynthetic","expired":false,"expires_at":"2099-01-01T00:00:00Z","invite_id":"1".repeat(32),"inviter":A,"name":"fresh Mac","role":"admin","approval":"required"}).to_string());
    let code = PairingCode {
        service: "https://link.example.org".into(),
        link_token: "zplt_synthetic".into(),
        peer: PEER.into(),
        name: "original Mac".into(),
        invites: vec![PairInvite {
            env: "personal/vault".into(),
            invite: invitation.into(),
        }],
    }
    .encode()
    .unwrap();
    let preview = core.pairing_preview(PairingTextIn { text: code }).unwrap();
    for state in [
        "approval_pending",
        "transferring",
        "verifying",
        "installing",
    ] {
        fx.respond("team_join",&json!({"state":state,"env_id":"envsynthetic","project":"personal","environment":"vault","self_fingerprint":B,"inviter_fingerprint":A,"self_record_binding":"b".repeat(64),"inviter_record_binding":"a".repeat(64),"local_approval_complete":state!="approval_pending"}).to_string());
        let out = core
            .pairing_join(RefIn {
                reference: preview.reference.clone(),
            })
            .unwrap();
        assert!(!out.done);
        assert_eq!(out.environments[0].state, "pending");
        assert_eq!(out.environments[0].bootstrap_state.as_deref(), Some(state));
        if fx.paths.devices_file().exists() {
            let file: Value =
                serde_json::from_slice(&fs::read(fx.paths.devices_file()).unwrap()).unwrap();
            assert_eq!(file["devices"], json!([]));
        }
    }
    fx.respond("team_join",&json!({"state":"installed_syncing","env_id":"envsynthetic","project":"personal","environment":"vault","self_fingerprint":B,"inviter_fingerprint":A,"local_approval_complete":true}).to_string());
    let out = core
        .pairing_join(RefIn {
            reference: preview.reference.clone(),
        })
        .unwrap();
    assert!(out.done);
    assert_eq!(out.environments[0].state, "joined");
    assert_eq!(
        core.pairing_join(RefIn {
            reference: preview.reference
        })
        .unwrap_err()
        .reason,
        "onetime_ref_unknown"
    );
    let devices: Value =
        serde_json::from_slice(&fs::read(fx.paths.devices_file()).unwrap()).unwrap();
    assert_eq!(devices["devices"][0]["fingerprint"], A);
    assert_eq!(devices["devices"][0]["envs"], json!(["personal/vault"]));
}

#[test]
fn personal_bootstrap_desktop_invite_routes_owner_metadata_to_authenticated_probe() {
    for (members, selected) in [
        (
            json!([{"fingerprint":A,"owner":true,"role":"admin","status":"active"}]),
            true,
        ),
        (
            json!([{"fingerprint":A,"owner":true,"role":"admin","status":"active"}, {"fingerprint":B,"owner":false,"role":"admin","status":"active"}]),
            false,
        ),
        (
            json!([{"fingerprint":A,"owner":false,"role":"admin","status":"active"}]),
            false,
        ),
        (
            json!([{"fingerprint":A,"owner":true,"role":"admin","status":"removed"}]),
            false,
        ),
    ] {
        let fx = Fixture::new();
        let core = core(&fx);
        let _daemon = FakeLink::start(&fx.paths.link_socket(), |request| {
            Some(match request["op"].as_str().unwrap_or("") {
                "status" => {
                    json!({"ok":true,"enrolled":true,"service":"https://link.example.org","device_id":OWN,"account_id":"synthetic","online":true,"peers":[]})
                }
                "link_token" => {
                    json!({"ok":true,"link_token":"zplt_synthetic","expires_at":4102444000u64,"device_id":OWN,"service":"https://link.example.org"})
                }
                _ => json!({"ok":false,"error":"invalid_request"}),
            })
        });
        fx.respond(
            "team_members",
            &json!({"env_id":"envsynthetic","members":members}).to_string(),
        );
        fx.respond("team_invite", &json!({"invite":"syntheticinviteaaaaaaaaaaaaaaaaaaaaaaaaaaaa","invite_id":"1".repeat(32),"approval":"required","record_binding":if selected {json!("a".repeat(64))} else {Value::Null}}).to_string());
        fx.respond("team_invite-info", &json!({"addresses":[format!("zpl:{OWN}")],"env_id":"envsynthetic","expired":false,"expires_at":"2099-01-01T00:00:00Z","invite_id":"1".repeat(32),"inviter":A,"name":"fresh Mac","role":"admin","approval":"required"}).to_string());
        let out = core
            .pairing_create(PairingCreateIn {
                envs: Some(vec!["renamed/place".into()]),
                name: Some("original Mac".into()),
                device_name: "fresh Mac".into(),
                admin_passphrase: PASSWORD.into(),
            })
            .unwrap();
        assert_eq!(
            fx.last("team_invite")
                .args()
                .contains(&"--personal-bootstrap"),
            selected
        );
        assert_eq!(out.record_binding.is_some(), selected);
        assert!(fx.last("team_invite").requires_admin());
        assert_eq!(
            fx.last("team_invite").stdin_json()["admin_passphrase"],
            PASSWORD
        );
    }
}
