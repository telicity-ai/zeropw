//! Remote sync in the core (docs/remote-sync.md §4) against the fake zeropw-admin and a fake
//! zeropw-link socket: invite codes and link tokens only in the socket request body, team
//! invitations only in the input envelope, approval-required invitations, re-authentication of
//! approve/deny, pairing codes as one-time values, offline previews that check every
//! invitation, pending joins retried until approved, the paired-Mac file, device removal, and
//! serve started with `--link-socket` once the daemon answers. Synthetic values only.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{FakeLink, Fixture, err, health_server, ok};
use serde_json::{Value, json};
use zeropw_desktop_core::commands::*;
use zeropw_desktop_core::link::LinkClient;
use zeropw_desktop_core::pairing::{PairInvite, PairingCode};
use zeropw_desktop_core::{Core, CoreConfig, NoEvents, SecretString, Settings};

const ADMIN_PASS: &str = "velvet-ocean-27-quartz-lantern";
const OWN_LINK: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaa";
const PEER_LINK: &str = "pppppppppppppppppppppppppp";
const FP_A: &str = "faaaaaaaaaaaaaaaaaaaaaaaaa";
const FP_B: &str = "fbbbbbbbbbbbbbbbbbbbbbbbbb";
const SERVICE: &str = "https://link.example.org";
const INVITE_CODE: &str = "ZPL-SYNT-HETI-CSYN-THET-ICSY-NTHE-TI";
const LINK_TOKEN: &str = "zplt_synthetic_link_token_4f2a";
const INVITE_1: &str = "syntheticinviteaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const INVITE_2: &str = "syntheticinvitebbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn pass() -> SecretString {
    SecretString::from(ADMIN_PASS)
}

fn core(fx: &Fixture) -> Core {
    let mut config = CoreConfig::new(fx.paths.clone());
    config.serve_stop_grace = Duration::from_secs(3);
    config.serve_start_timeout = Duration::from_secs(10);
    config.link_start_timeout = Duration::from_secs(3);
    let core = Core::new(config, Arc::new(NoEvents));
    core.settings_set(Settings {
        gateway_port: health_server(),
        team_listen: None,
    })
    .unwrap();
    core
}

fn initialized(fx: &Fixture) {
    fs::create_dir_all(fx.paths.state_dir()).unwrap();
    fs::write(fx.paths.state_dir().join("admin.json"), b"{}").unwrap();
}

/// No zeropw-admin call carried any of `secrets` in argv, environment or envelope.
fn assert_admin_never_saw(fx: &Fixture, secrets: &[&str]) {
    for call in fx.calls() {
        for secret in secrets {
            for arg in &call.argv {
                assert!(!arg.contains(secret), "secret in argv of {}", call.key);
            }
            for (_, value) in &call.env {
                assert!(!value.contains(secret), "secret in env of {}", call.key);
            }
            if let Some(stdin) = &call.stdin {
                assert!(
                    !stdin.contains(secret),
                    "secret in envelope of {}",
                    call.key
                );
            }
        }
    }
}

/// A daemon state the fake socket answers from.
#[derive(Clone)]
struct Daemon {
    enrolled: Arc<AtomicBool>,
    device_id: &'static str,
    devices: Arc<Mutex<Vec<Value>>>,
}

impl Daemon {
    fn new(enrolled: bool, device_id: &'static str) -> Self {
        Self {
            enrolled: Arc::new(AtomicBool::new(enrolled)),
            device_id,
            devices: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn serve(&self, fx: &Fixture) -> FakeLink {
        let d = self.clone();
        FakeLink::start(&fx.paths.link_socket(), move |req| {
            let enrolled = d.enrolled.load(Ordering::SeqCst);
            Some(match req["op"].as_str().unwrap_or("") {
                "status" => json!({
                    "ok": true, "enrolled": enrolled,
                    "service": if enrolled { json!(SERVICE) } else { Value::Null },
                    "device_id": if enrolled { json!(d.device_id) } else { Value::Null },
                    "account_id": "acct_1", "online": enrolled,
                    "peers": [{"device_id": PEER_LINK, "name": "studio", "online": true,
                               "revoked": false, "path": "relay-tls", "rtt_ms": 31, "last_error": null}]
                }),
                "enroll" if enrolled => json!({"ok": false, "error": "already_enrolled"}),
                "enroll" => {
                    d.enrolled.store(true, Ordering::SeqCst);
                    // a link token adds this device to the account of the Mac that issued it
                    if req.get("link_token").is_some() {
                        d.devices.lock().unwrap().push(
                            json!({"device_id": PEER_LINK, "name": "studio", "revoked_at": null}),
                        );
                    }
                    json!({"ok": true, "device_id": d.device_id, "account_id": "acct_1"})
                }
                "link_token" => {
                    json!({"ok": true, "link_token": LINK_TOKEN, "expires_at": 4_102_444_000u64,
                                       "device_id": d.device_id, "service": SERVICE})
                }
                "devices" => {
                    json!({"ok": true, "self": d.device_id, "devices": d.devices.lock().unwrap().clone()})
                }
                "revoke" => json!({"ok": true}),
                _ => json!({"ok": false, "error": "invalid_request"}),
            })
        })
    }
}

fn invite_info(inviter: &str, address: &str) -> String {
    json!({"addresses": [address], "env_id": "envsynthetic", "expired": false,
           "expires_at": "2099-01-01T00:00:00Z", "invite_id": "00112233445566778899aabbccddeeff",
           "inviter": inviter, "name": "new mac", "role": "admin", "approval": "required"})
    .to_string()
}

fn pairing_text(invites: &[(&str, &str)]) -> String {
    PairingCode {
        service: SERVICE.into(),
        link_token: LINK_TOKEN.into(),
        peer: PEER_LINK.into(),
        name: "studio".into(),
        invites: invites
            .iter()
            .map(|(env, invite)| PairInvite {
                env: (*env).into(),
                invite: (*invite).into(),
            })
            .collect(),
    }
    .encode()
    .unwrap()
    .expose()
    .to_owned()
}

// ---------------------------------------------------------------------------------------------

#[test]
fn the_socket_client_reads_one_line_and_maps_daemon_errors_without_their_text() {
    let fx = Fixture::new();
    let answers = Arc::new(Mutex::new(vec![
        Some(json!({"ok": false, "error": "not_enrolled", "detail": "zplt_synthetic leaked?"})),
        Some(json!({"no": "ok field"})),
        Some(json!({"ok": false, "error": "a code with spaces"})),
        None,
    ]));
    let a = answers.clone();
    let _link = FakeLink::start(&fx.paths.link_socket(), move |_| {
        let mut a = a.lock().unwrap();
        if a.is_empty() { None } else { a.remove(0) }
    });
    let client = LinkClient::new(fx.paths.link_socket())
        .with_timeouts(Duration::from_millis(400), Duration::from_millis(400));
    let e = client.status().unwrap_err();
    assert_eq!(
        (e.error.as_str(), e.reason.as_str()),
        ("StateError", "link_not_enrolled")
    );
    assert!(e.detail.is_none() && !e.to_string().contains("zplt"));
    assert_eq!(client.status().unwrap_err().reason, "link_output_invalid");
    assert_eq!(client.status().unwrap_err().reason, "link_failed");
    assert_eq!(client.status().unwrap_err().reason, "link_timeout");
    assert_eq!(
        client.revoke("NOT-AN-ID").unwrap_err().detail.as_deref(),
        Some("device_id")
    );

    let gone = LinkClient::new(fx.dir.path().join("nothing.sock"));
    assert_eq!(gone.status().unwrap_err().reason, "link_unavailable");
    let long = LinkClient::new(fx.dir.path().join("x".repeat(120)));
    assert_eq!(
        long.status().unwrap_err().reason,
        "link_socket_path_too_long"
    );
}

#[test]
fn enrolment_sends_the_invite_code_only_in_the_socket_request() {
    let fx = Fixture::new();
    let core = core(&fx);
    let daemon = Daemon::new(false, OWN_LINK);
    let link = daemon.serve(&fx);

    let e = err(core.link_enroll(LinkEnrollIn {
        invite_code: "ZPL-not-a-code synthetic".into(),
        service: None,
        name: None,
    }));
    assert_eq!(e.reason, "link_invite_malformed");
    assert!(!e.to_string().contains("synthetic"));
    let e = err(core.link_enroll(LinkEnrollIn {
        invite_code: INVITE_CODE.into(),
        service: Some("http://link.example.org".into()),
        name: None,
    }));
    assert_eq!(e.reason, "link_service_invalid");
    assert!(!link.ops().contains(&"enroll".to_owned()));

    let out = ok(core.link_enroll(LinkEnrollIn {
        invite_code: format!("  {INVITE_CODE} ").into(),
        service: Some(format!("{SERVICE}/")),
        name: Some("work laptop".into()),
    }));
    assert!(out.enrolled && out.running);
    assert_eq!(out.device_id.as_deref(), Some(OWN_LINK));
    assert_eq!(out.service_host, "link.example.org");
    let enroll = link
        .requests()
        .into_iter()
        .find(|r| r["op"] == "enroll")
        .unwrap();
    assert_eq!(
        enroll,
        json!({"op": "enroll", "service": SERVICE, "name": "work laptop", "invite_code": INVITE_CODE})
    );
    assert_admin_never_saw(&fx, &[INVITE_CODE]);
    // once is enough
    let e = err(core.link_enroll(LinkEnrollIn {
        invite_code: INVITE_CODE.into(),
        service: None,
        name: None,
    }));
    assert_eq!(e.reason, "link_already_enrolled");
}

#[test]
fn link_status_says_why_remote_sync_is_unavailable() {
    let fx = Fixture::new();
    let core = core(&fx);
    let status = core.link_status().unwrap();
    assert!(!status.available && !status.running && !status.enrolled);
    assert_eq!(status.problem.as_deref(), Some("link_binary_missing"));
    assert_eq!(status.service, status.default_service);
    common::install_fake_link_daemon(&fx);
    let status = core.link_status().unwrap();
    assert!(status.available && !status.running);
    assert_eq!(status.problem.as_deref(), Some("link_unavailable"));
}

#[test]
fn pairing_create_makes_approval_invitations_for_this_mac_and_stores_the_code_once() {
    let fx = Fixture::new();
    let core = core(&fx);
    let _link = Daemon::new(true, OWN_LINK).serve(&fx);
    fx.respond(
        "project_list",
        r#"{"projects":[{"name":"demo","environments":["dev","prod"],"created_at":"2026-11-06T00:00:00Z"}]}"#,
    );
    // demo/dev is not shared yet, demo/prod is
    fx.respond_error_nth(
        "team_members",
        1,
        r#"{"error":"NotFound","reason":"team_env_not_found"}"#,
        1,
    );
    fx.respond("team_members", r#"{"env_id":"envsynthetic","members":[]}"#);
    fx.respond(
        "team_share",
        r#"{"env_id":"envsynthetic","project":"demo","environment":"dev","not_shared":[]}"#,
    );
    for (n, invite) in [(1, INVITE_1), (2, INVITE_2)] {
        fx.respond_nth(
            "team_invite",
            n,
            &json!({"env_id": "envsynthetic", "invite": invite, "link": format!("zeropw://join#{invite}"),
                    "invite_id": format!("0011223344556677889900000000000{n}"), "expires_at": "2026-11-07T00:00:00Z",
                    "name": "new mac", "role": "admin", "approval": "required"})
            .to_string(),
        );
    }
    fx.respond(
        "team_invite-info",
        &invite_info(FP_A, &format!("zpl:{OWN_LINK}")),
    );

    let out = ok(core.pairing_create(PairingCreateIn {
        envs: None,
        name: Some("studio".into()),
        device_name: "new mac".into(),
        admin_passphrase: pass(),
    }));
    assert_eq!(out.peer, OWN_LINK);
    assert_eq!(out.fingerprint, FP_A);
    assert_eq!(
        out.environments,
        [
            PairingEnvOut {
                env: "demo/dev".into(),
                invite_id: "00112233445566778899000000000001".into(),
                shared_now: true
            },
            PairingEnvOut {
                env: "demo/prod".into(),
                invite_id: "00112233445566778899000000000002".into(),
                shared_now: false
            },
        ]
    );

    let share = fx.last("team_share");
    assert_eq!(
        share.args(),
        [
            "team",
            "share",
            "--project=demo",
            "--environment=dev",
            "--name=studio"
        ]
    );
    assert_eq!(share.stdin_json(), json!({"admin_passphrase": ADMIN_PASS}));
    let invites: Vec<_> = fx
        .calls()
        .into_iter()
        .filter(|c| c.key == "team_invite")
        .collect();
    assert_eq!(invites.len(), 2);
    for (call, env) in invites.iter().zip(["demo/dev", "demo/prod"]) {
        assert!(call.requires_admin());
        assert_eq!(
            call.args(),
            [
                "team",
                "invite",
                &format!("--env={env}"),
                "--role=admin",
                "--name=new mac",
                &format!("--address=zpl:{OWN_LINK}"),
                "--approval",
                "--link",
            ]
        );
        assert_eq!(call.stdin_json(), json!({"admin_passphrase": ADMIN_PASS}));
    }
    // serve runs with the link socket so the other Mac can reach this one
    let serve = fx.last("serve");
    let socket_arg = format!("--link-socket={}", fx.paths.link_socket().display());
    assert!(
        serve.args().contains(&socket_arg.as_str()),
        "{:?}",
        serve.args()
    );
    // the link token never went to zeropw-admin; invitations only to invite-info's envelope
    assert_admin_never_saw(&fx, &[LINK_TOKEN]);
    for call in fx.calls() {
        for arg in &call.argv {
            assert!(
                !arg.contains(INVITE_1) && !arg.contains(INVITE_2),
                "invite in argv of {}",
                call.key
            );
        }
    }

    // the code is shown once and carries exactly what the other Mac needs
    let shown = core
        .onetime_show(RefIn {
            reference: out.reference.clone(),
        })
        .unwrap();
    let code = PairingCode::decode(shown.expose()).unwrap();
    assert_eq!(
        (
            code.service.as_str(),
            code.peer.as_str(),
            code.name.as_str()
        ),
        (SERVICE, OWN_LINK, "studio")
    );
    assert_eq!(code.link_token.expose(), LINK_TOKEN);
    let pairs: Vec<(String, String)> = code
        .invites
        .iter()
        .map(|i| (i.env.clone(), i.invite.expose().to_owned()))
        .collect();
    assert_eq!(
        pairs,
        [
            ("demo/dev".into(), INVITE_1.into()),
            ("demo/prod".into(), INVITE_2.into())
        ]
    );
    assert_eq!(
        err(core.onetime_show(RefIn {
            reference: out.reference
        }))
        .reason,
        "onetime_ref_unknown"
    );

    // the paired-Mac file notes the pairing and this Mac's fingerprint, nothing secret
    let file = fs::read_to_string(fx.paths.devices_file()).unwrap();
    assert!(file.contains(FP_A) && file.contains("new mac"));
    for secret in [LINK_TOKEN, INVITE_1, INVITE_2, ADMIN_PASS] {
        assert!(!file.contains(secret));
    }
    assert_eq!(
        fs::metadata(fx.paths.devices_file())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn pairing_create_never_hands_out_an_invitation_without_approval() {
    let fx = Fixture::new();
    let core = core(&fx);
    let link = Daemon::new(true, OWN_LINK).serve(&fx);
    fx.respond("team_members", r#"{"env_id":"envsynthetic","members":[]}"#);
    fx.respond(
        "team_invite",
        &json!({"env_id": "envsynthetic", "invite": INVITE_1, "link": format!("zeropw://join#{INVITE_1}"),
                "invite_id": "00112233445566778899aabbccddeeff", "expires_at": "2026-11-07T00:00:00Z",
                "name": "new mac", "role": "admin"})
        .to_string(),
    );
    let e = err(core.pairing_create(PairingCreateIn {
        envs: Some(vec!["demo/dev".into()]),
        name: None,
        device_name: "new mac".into(),
        admin_passphrase: pass(),
    }));
    assert_eq!(e.reason, "pairing_approval_unsupported");
    let revoke = fx.last("team_revoke-invite");
    assert_eq!(
        revoke.args(),
        [
            "team",
            "revoke-invite",
            "--env=demo/dev",
            "--id=00112233445566778899aabbccddeeff"
        ]
    );
    assert!(!link.ops().contains(&"link_token".to_owned()));

    // not enrolled: nothing is shared or invited
    let fx = Fixture::new();
    let core = self::core(&fx);
    let _link = Daemon::new(false, OWN_LINK).serve(&fx);
    let e = err(core.pairing_create(PairingCreateIn {
        envs: Some(vec!["demo/dev".into()]),
        name: None,
        device_name: "new mac".into(),
        admin_passphrase: pass(),
    }));
    assert_eq!(e.reason, "link_not_enrolled");
    assert_eq!(fx.count("team_share") + fx.count("team_invite"), 0);
    // nor without a passphrase or with a bad environment list
    for (envs, reason) in [
        (Some(vec!["--env=x".into()]), "invalid_argument"),
        (Some(vec![]), "invalid_argument"),
    ] {
        let e = err(core.pairing_create(PairingCreateIn {
            envs,
            name: None,
            device_name: "m".into(),
            admin_passphrase: pass(),
        }));
        assert_eq!(e.reason, reason);
    }
    let e = err(core.pairing_create(PairingCreateIn {
        envs: None,
        name: None,
        device_name: "m".into(),
        admin_passphrase: "".into(),
    }));
    assert_eq!(e.reason, "passphrase_missing");
}

#[test]
fn a_pasted_code_is_previewed_offline_and_each_invitation_is_checked() {
    let fx = Fixture::new();
    let core = core(&fx);
    let link = Daemon::new(false, OWN_LINK).serve(&fx);
    let text = pairing_text(&[("demo/dev", INVITE_1), ("demo/prod", INVITE_2)]);
    fx.respond(
        "team_invite-info",
        &invite_info(FP_A, &format!("zpl:{PEER_LINK}")),
    );
    let out = ok(core.pairing_preview(PairingTextIn {
        text: text.as_str().into(),
    }));
    let p = &out.preview;
    assert_eq!(
        (p.name.as_str(), p.peer.as_str(), p.fingerprint.as_str()),
        ("studio", PEER_LINK, FP_A)
    );
    assert_eq!(p.environments.len(), 2);
    assert_eq!(p.service_host, "link.example.org");
    assert_eq!(p.expires_at, "2099-01-01T00:00:00Z");
    // offline: the daemon was not asked anything, and each invitation went in an envelope
    assert!(link.ops().is_empty());
    let infos: Vec<_> = fx
        .calls()
        .into_iter()
        .filter(|c| c.key == "team_invite-info")
        .collect();
    assert_eq!(infos.len(), 2);
    assert_eq!(infos[0].stdin_json(), json!({"invite": INVITE_1}));
    assert_admin_never_saw(&fx, &[LINK_TOKEN]);
    // the pasted code stays in Rust
    assert_eq!(
        err(core.onetime_show(RefIn {
            reference: out.reference
        }))
        .reason,
        "onetime_ref_unknown"
    );

    // an invitation that names another address, another inviter, or has expired is refused
    fx.respond("team_invite-info", &invite_info(FP_A, "192.168.1.20:47390"));
    assert_eq!(
        err(core.pairing_preview(PairingTextIn {
            text: text.as_str().into()
        }))
        .reason,
        "pairing_address_mismatch"
    );
    fx.clear_response("team_invite-info");
    let base = fx.count("team_invite-info");
    fx.respond_nth(
        "team_invite-info",
        base + 1,
        &invite_info(FP_A, &format!("zpl:{PEER_LINK}")),
    );
    fx.respond_nth(
        "team_invite-info",
        base + 2,
        &invite_info(FP_B, &format!("zpl:{PEER_LINK}")),
    );
    assert_eq!(
        err(core.pairing_preview(PairingTextIn {
            text: text.as_str().into()
        }))
        .reason,
        "pairing_inviter_mismatch"
    );
    fx.respond(
        "team_invite-info",
        &invite_info(FP_A, &format!("zpl:{PEER_LINK}"))
            .replace("\"expired\":false", "\"expired\":true"),
    );
    assert_eq!(
        err(core.pairing_preview(PairingTextIn {
            text: text.as_str().into()
        }))
        .reason,
        "pairing_expired"
    );
    // and a code that is not one never reaches the CLI
    let before = fx.calls().len();
    for bad in [
        "",
        "zeropw://join#abc",
        "zeropw://pair#!!!",
        &text[..text.len() - 3],
    ] {
        let e = err(core.pairing_preview(PairingTextIn { text: bad.into() }));
        assert!(e.reason.starts_with("pairing_code_"), "{bad}: {}", e.reason);
        assert!(e.detail.is_none());
    }
    assert_eq!(fx.calls().len(), before);
}

#[test]
fn pairing_join_enrols_with_the_token_and_retries_pending_joins_until_approved() {
    let fx = Fixture::new();
    let core = core(&fx);
    initialized(&fx);
    let link = Daemon::new(false, OWN_LINK).serve(&fx);
    let text = pairing_text(&[("demo/dev", INVITE_1), ("demo/prod", INVITE_2)]);
    fx.respond(
        "team_invite-info",
        &invite_info(FP_A, &format!("zpl:{PEER_LINK}")),
    );
    let preview = ok(core.pairing_preview(PairingTextIn {
        text: text.as_str().into(),
    }));
    let pending = r#"{"error":"StateError","reason":"join_pending_approval","detail":{"self_fingerprint":"fbbbbbbbbbbbbbbbbbbbbbbbbb","inviter_fingerprint":"faaaaaaaaaaaaaaaaaaaaaaaaa"}}"#;
    fx.respond_error("team_join", pending, 1);

    let first = ok(core.pairing_join(RefIn {
        reference: preview.reference.clone(),
    }));
    assert!(!first.done);
    assert_eq!(first.peer, PEER_LINK);
    for env in &first.environments {
        assert_eq!(env.state, "pending");
        assert_eq!(env.self_fingerprint.as_deref(), Some(FP_B));
        assert_eq!(env.inviter_fingerprint.as_deref(), Some(FP_A));
    }
    let enroll = link
        .requests()
        .into_iter()
        .find(|r| r["op"] == "enroll")
        .unwrap();
    assert_eq!(enroll["link_token"], LINK_TOKEN);
    assert_eq!(enroll["service"], SERVICE);
    assert!(enroll.get("invite_code").is_none());
    let joins: Vec<_> = fx
        .calls()
        .into_iter()
        .filter(|c| c.key == "team_join")
        .collect();
    assert_eq!(joins.len(), 2);
    let socket_arg = format!("--link-socket={}", fx.paths.link_socket().display());
    assert_eq!(
        joins[0].args(),
        [
            "team",
            "join",
            "--stdin",
            socket_arg.as_str(),
            "--project=demo",
            "--environment=dev"
        ]
    );
    assert_eq!(joins[1].stdin_json(), json!({"invite": INVITE_2}));
    assert_admin_never_saw(&fx, &[LINK_TOKEN]);

    // the other Mac approves demo/dev first: only the pending one is tried again
    fx.clear_response("team_join");
    fx.respond_nth(
        "team_join",
        3,
        r#"{"env_id":"envsynthetic","environment":"dev","inviter_fingerprint":"faaaaaaaaaaaaaaaaaaaaaaaaa","project":"demo","self_fingerprint":"fbbbbbbbbbbbbbbbbbbbbbbbbb"}"#,
    );
    fx.respond_error_nth("team_join", 4, pending, 1);
    let second = ok(core.pairing_join(RefIn {
        reference: preview.reference.clone(),
    }));
    assert_eq!(
        second
            .environments
            .iter()
            .map(|e| e.state)
            .collect::<Vec<_>>(),
        ["joined", "pending"]
    );
    fx.respond_nth(
        "team_join",
        5,
        r#"{"env_id":"envother","environment":"prod","inviter_fingerprint":"faaaaaaaaaaaaaaaaaaaaaaaaa","project":"demo","self_fingerprint":"fbbbbbbbbbbbbbbbbbbbbbbbbb"}"#,
    );
    let third = ok(core.pairing_join(RefIn {
        reference: preview.reference.clone(),
    }));
    assert!(third.done);
    assert_eq!(
        fx.count("team_join"),
        5,
        "a joined environment is not joined again"
    );
    // once every environment joined, the code is gone
    assert_eq!(
        err(core.pairing_join(RefIn {
            reference: preview.reference
        }))
        .reason,
        "onetime_ref_unknown"
    );
    // only one enrolment, with the token
    assert_eq!(link.ops().iter().filter(|o| *o == "enroll").count(), 1);

    let devices = fs::read_to_string(fx.paths.devices_file()).unwrap();
    let devices: Value = serde_json::from_str(&devices).unwrap();
    assert_eq!(devices["self"], FP_B);
    assert_eq!(devices["devices"][0]["fingerprint"], FP_A);
    assert_eq!(devices["devices"][0]["link_device_id"], PEER_LINK);
    assert_eq!(
        devices["devices"][0]["envs"],
        json!(["demo/dev", "demo/prod"])
    );
}

#[test]
fn pairing_join_from_another_account_or_service_is_refused_before_any_join() {
    let fx = Fixture::new();
    let core = core(&fx);
    let daemon = Daemon::new(true, OWN_LINK);
    let _link = daemon.serve(&fx);
    fx.respond(
        "team_invite-info",
        &invite_info(FP_A, &format!("zpl:{PEER_LINK}")),
    );
    let text = pairing_text(&[("demo/dev", INVITE_1)]);
    let preview = ok(core.pairing_preview(PairingTextIn {
        text: text.as_str().into(),
    }));
    // enrolled already, but the code's Mac is not in this account
    let e = err(core.pairing_join(RefIn {
        reference: preview.reference.clone(),
    }));
    assert_eq!(e.reason, "link_other_account");
    assert_eq!(fx.count("team_join"), 0);
    // in the account: the join goes ahead without enrolling again
    daemon
        .devices
        .lock()
        .unwrap()
        .push(json!({"device_id": PEER_LINK, "name": "studio", "revoked_at": null}));
    fx.respond("team_join", r#"{"env_id":"e","environment":"dev","inviter_fingerprint":"faaaaaaaaaaaaaaaaaaaaaaaaa","project":"demo","self_fingerprint":"fbbbbbbbbbbbbbbbbbbbbbbbbb"}"#);
    assert!(
        ok(core.pairing_join(RefIn {
            reference: preview.reference
        }))
        .done
    );
}

#[test]
fn approve_and_deny_are_re_authenticated_and_stop_at_a_wrong_passphrase() {
    let fx = Fixture::new();
    let core = core(&fx);
    fx.respond("team_approve-join", r#"{"env_id":"e","fingerprint":"fbbbbbbbbbbbbbbbbbbbbbbbbb","approved_invites":["00112233445566778899aabbccddeeff"]}"#);
    let out = core
        .approve_join(JoinDecisionIn {
            envs: vec!["demo/dev".into(), "demo/prod".into()],
            fingerprint: FP_B.into(),
            admin_passphrase: pass(),
        })
        .unwrap();
    assert!(
        out.envs
            .iter()
            .all(|e| e.ok && e.invites == ["00112233445566778899aabbccddeeff"])
    );
    let calls: Vec<_> = fx
        .calls()
        .into_iter()
        .filter(|c| c.key == "team_approve-join")
        .collect();
    assert_eq!(calls.len(), 2);
    assert!(calls[0].requires_admin());
    assert_eq!(
        calls[0].args(),
        [
            "team",
            "approve-join",
            "--env=demo/dev",
            &format!("--fingerprint={FP_B}")
        ]
    );
    assert_eq!(
        calls[0].stdin_json(),
        json!({"admin_passphrase": ADMIN_PASS})
    );
    let devices: Value =
        serde_json::from_str(&fs::read_to_string(fx.paths.devices_file()).unwrap()).unwrap();
    assert_eq!(devices["devices"][0]["fingerprint"], FP_B);

    fx.respond_error(
        "team_deny-join",
        r#"{"error":"AuthFailed","reason":"admin_reauth_failed"}"#,
        1,
    );
    let e = core
        .deny_join(JoinDecisionIn {
            envs: vec!["demo/dev".into(), "demo/prod".into()],
            fingerprint: FP_B.into(),
            admin_passphrase: "wrong".into(),
        })
        .unwrap_err();
    assert_eq!(e.reason, "admin_reauth_failed");
    assert_eq!(
        fx.count("team_deny-join"),
        1,
        "stops at the first wrong passphrase"
    );
    assert!(fx.last("team_deny-join").requires_admin());
    // inputs are checked before anything runs
    for (fingerprint, pass) in [("not-a-fingerprint", ADMIN_PASS), (FP_B, "")] {
        let before = fx.calls().len();
        let e = core
            .approve_join(JoinDecisionIn {
                envs: vec!["demo/dev".into()],
                fingerprint: fingerprint.into(),
                admin_passphrase: pass.into(),
            })
            .unwrap_err();
        assert!(matches!(
            e.reason.as_str(),
            "invalid_argument" | "passphrase_missing"
        ));
        assert_eq!(fx.calls().len(), before);
    }
}

#[test]
fn join_requests_keep_well_formed_requests_and_name_unreadable_environments() {
    let fx = Fixture::new();
    let core = core(&fx);
    fx.respond_nth(
        "team_join-requests",
        1,
        &json!({"env_id": "e", "requests": [
            {"request_id": "r1", "invite_id": "00112233445566778899aabbccddeeff", "fingerprint": FP_B,
             "first_seen_at": "2026-11-06T00:00:00Z", "last_seen_at": "2026-11-06T00:01:00Z", "attempts": 3},
            {"request_id": "r2", "invite_id": "x", "fingerprint": "NOT A FINGERPRINT", "attempts": 1}
        ]})
        .to_string(),
    );
    fx.respond_error_nth(
        "team_join-requests",
        2,
        r#"{"error":"NotFound","reason":"team_env_not_found"}"#,
        1,
    );
    let out = core
        .join_requests(EnvsIn {
            envs: vec!["demo/dev".into(), "demo/prod".into()],
        })
        .unwrap();
    assert_eq!(out.requests.len(), 1);
    assert_eq!(out.requests[0].fingerprint, FP_B);
    assert_eq!(out.requests[0].attempts, 3);
    assert_eq!(out.requests[0].env, "demo/dev");
    assert_eq!(
        out.errors,
        [EnvError {
            env: "demo/prod".into(),
            reason: "team_env_not_found".into()
        }]
    );
    assert!(!fx.last("team_join-requests").requires_admin());
}

#[test]
fn removing_a_mac_leaves_its_teams_first_and_revokes_the_link_device_only_then() {
    let fx = Fixture::new();
    let core = core(&fx);
    let link = Daemon::new(true, OWN_LINK).serve(&fx);
    fs::create_dir_all(&fx.paths.app_data_dir).unwrap();
    fs::write(
        fx.paths.devices_file(),
        json!({"v": 1, "self": FP_A, "devices": [
            {"fingerprint": FP_B, "link_device_id": PEER_LINK, "name": "laptop", "envs": ["demo/dev", "demo/prod"], "added_at": 1}
        ]})
        .to_string(),
    )
    .unwrap();
    // a removal that fails in one environment keeps the link device
    fx.respond_error_nth(
        "team_remove",
        2,
        r#"{"error":"PolicyDenied","reason":"not_admin"}"#,
        1,
    );
    let out = core
        .device_remove(DeviceRemoveIn {
            fingerprint: Some(FP_B.into()),
            link_device_id: None,
            admin_passphrase: Some(pass()),
        })
        .unwrap();
    assert_eq!(out.removed, ["demo/dev"]);
    assert_eq!(
        out.failed,
        [EnvError {
            env: "demo/prod".into(),
            reason: "not_admin".into()
        }]
    );
    assert!(!out.link_revoked);
    assert_eq!(out.link_error.as_deref(), Some("link_kept"));
    assert!(!link.ops().contains(&"revoke".to_owned()));
    let removes: Vec<_> = fx
        .calls()
        .into_iter()
        .filter(|c| c.key == "team_remove")
        .collect();
    assert!(removes.iter().all(|c| c.requires_admin()));
    assert_eq!(
        removes[0].args(),
        [
            "team",
            "remove",
            "--env=demo/dev",
            &format!("--device={FP_B}")
        ]
    );

    // retried: the rest goes, then the link device
    let out = core
        .device_remove(DeviceRemoveIn {
            fingerprint: Some(FP_B.into()),
            link_device_id: None,
            admin_passphrase: Some(pass()),
        })
        .unwrap();
    assert_eq!(out.removed, ["demo/prod"]);
    assert!(out.link_revoked);
    let revoke = link
        .requests()
        .into_iter()
        .find(|r| r["op"] == "revoke")
        .unwrap();
    assert_eq!(revoke, json!({"op": "revoke", "device_id": PEER_LINK}));
    let devices: Value =
        serde_json::from_str(&fs::read_to_string(fx.paths.devices_file()).unwrap()).unwrap();
    assert_eq!(devices["devices"], json!([]));

    // never this Mac, and a team removal needs the passphrase
    let e = core
        .device_remove(DeviceRemoveIn {
            fingerprint: Some(FP_A.into()),
            link_device_id: None,
            admin_passphrase: Some(pass()),
        })
        .unwrap_err();
    assert_eq!(e.reason, "cannot_remove_self");
    let e = core
        .device_remove(DeviceRemoveIn {
            fingerprint: None,
            link_device_id: Some(OWN_LINK.into()),
            admin_passphrase: None,
        })
        .unwrap_err();
    assert_eq!(e.reason, "cannot_remove_self");
    // a link-only device is revoked there
    let out = core
        .device_remove(DeviceRemoveIn {
            fingerprint: None,
            link_device_id: Some(PEER_LINK.into()),
            admin_passphrase: None,
        })
        .unwrap();
    assert!(out.link_revoked && out.removed.is_empty());
}

#[test]
fn the_devices_overview_brings_members_sync_state_and_link_peers_together() {
    let fx = Fixture::new();
    let core = core(&fx);
    let daemon = Daemon::new(true, OWN_LINK);
    let _link = daemon.serve(&fx);
    fs::create_dir_all(&fx.paths.app_data_dir).unwrap();
    fs::write(
        fx.paths.devices_file(),
        json!({"v": 1, "self": FP_A, "devices": [{"fingerprint": FP_B, "name": "laptop", "envs": ["demo/dev"], "added_at": 1}],
               "pairings": [{"created_at": 1_000, "envs": ["demo/dev"], "device_name": "laptop"}]})
        .to_string(),
    )
    .unwrap();
    daemon.devices.lock().unwrap().extend([
        json!({"device_id": OWN_LINK, "name": "studio", "created_at": 10, "revoked_at": null}),
        json!({"device_id": PEER_LINK, "name": "laptop", "created_at": 1_100, "revoked_at": null}),
    ]);
    fx.respond("team_members", &json!({"env_id": "e", "members": [
        {"fingerprint": FP_A, "name": "studio", "role": "admin", "status": "active", "owner": true},
        {"fingerprint": FP_B, "name": "laptop", "role": "admin", "status": "active", "owner": false}]}).to_string());
    fx.respond("team_sync-status", &json!({"env_id": "e", "self": FP_A, "serve_updated_at": "2026-11-06T00:00:00Z",
        "conflicts": 1, "peers": [{"fingerprint": FP_B, "name": "laptop", "state": "syncing", "session": true,
        "transport": "link", "last_contact_at": "2026-11-06T00:00:00Z", "next_attempt_at": null, "last_error": null}]}).to_string());
    let out = core.devices_overview().unwrap();
    assert_eq!(out.self_fingerprint.as_deref(), Some(FP_A));
    assert!(out.link.enrolled);
    assert_eq!(out.link.peers[0].path.as_deref(), Some("relay-tls"));
    assert_eq!(out.envs.len(), 1);
    assert_eq!(out.envs[0].sync.as_ref().unwrap()["conflicts"], 1);
    // the one new device of the account went to the one paired Mac without a link ID
    assert_eq!(out.devices[0].link_device_id.as_deref(), Some(PEER_LINK));
    assert_eq!(
        fx.last("team_sync-status").args(),
        ["team", "sync-status", "--env=demo/dev"]
    );
}

#[test]
fn serve_gets_the_link_socket_once_the_daemon_answers() {
    let fx = Fixture::new();
    let core = core(&fx);
    initialized(&fx);
    // no daemon yet: serve starts without the socket
    core.serve_start().unwrap();
    assert!(
        !fx.last("serve")
            .args()
            .iter()
            .any(|a| a.starts_with("--link-socket"))
    );
    // the daemon turns up: the next status restarts serve with it, once
    let _link = Daemon::new(true, OWN_LINK).serve(&fx);
    core.link_status().unwrap();
    assert_eq!(fx.count("serve"), 2);
    let socket_arg = format!("--link-socket={}", fx.paths.link_socket().display());
    assert!(fx.last("serve").args().contains(&socket_arg.as_str()));
    core.link_status().unwrap();
    assert_eq!(fx.count("serve"), 2);
    // a stopped serve stays stopped
    core.serve_stop();
    core.link_status().unwrap();
    assert_eq!(fx.count("serve"), 2);
    core.shutdown();
}

#[test]
fn pairing_joins_one_at_a_time() {
    // two overlapping polls of the same code never run `team join` for one environment twice
    let fx = Fixture::new();
    let core = Arc::new(core(&fx));
    let daemon = Daemon::new(true, OWN_LINK);
    daemon
        .devices
        .lock()
        .unwrap()
        .push(json!({"device_id": PEER_LINK, "name": "studio", "revoked_at": null}));
    let _link = daemon.serve(&fx);
    fx.respond(
        "team_invite-info",
        &invite_info(FP_A, &format!("zpl:{PEER_LINK}")),
    );
    let text = pairing_text(&[("demo/dev", INVITE_1)]);
    let preview = ok(core.pairing_preview(PairingTextIn {
        text: text.as_str().into(),
    }));
    fx.respond("team_join", r#"{"env_id":"e","environment":"dev","inviter_fingerprint":"faaaaaaaaaaaaaaaaaaaaaaaaa","project":"demo","self_fingerprint":"fbbbbbbbbbbbbbbbbbbbbbbbbb"}"#);
    fx.respond_sleep("team_join", 1);
    let results: Vec<_> = (0..2)
        .map(|_| {
            let (core, reference) = (core.clone(), preview.reference.clone());
            std::thread::spawn(move || core.pairing_join(RefIn { reference }).map(|o| o.done))
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    assert_eq!(fx.count("team_join"), 1);
    // one joined; the other found the code already used up
    assert_eq!(results.iter().filter(|r| matches!(r, Ok(true))).count(), 1);
    assert!(
        results
            .iter()
            .any(|r| matches!(r, Err(e) if e.reason == "onetime_ref_unknown"))
    );
}

#[test]
fn a_local_environment_of_the_same_name_is_not_joined_and_a_dial_failure_says_why() {
    let fx = Fixture::new();
    let core = core(&fx);
    let daemon = Daemon::new(true, OWN_LINK);
    daemon
        .devices
        .lock()
        .unwrap()
        .push(json!({"device_id": PEER_LINK, "name": "studio", "revoked_at": null}));
    let _link = daemon.serve(&fx);
    fx.respond(
        "team_invite-info",
        &invite_info(FP_A, &format!("zpl:{PEER_LINK}")),
    );
    let text = pairing_text(&[("demo/dev", INVITE_1), ("demo/prod", INVITE_2)]);
    let preview = ok(core.pairing_preview(PairingTextIn {
        text: text.as_str().into(),
    }));
    // this Mac has its own demo/dev and demo/prod: dev already is the same team environment
    // (an earlier pairing), prod is a local environment that has nothing to do with the code
    fx.respond(
        "project_list",
        r#"{"projects":[{"name":"demo","environments":["dev","prod"],"created_at":""}]}"#,
    );
    fx.respond_nth(
        "team_members",
        1,
        r#"{"env_id":"envsynthetic","members":[]}"#,
    );
    fx.respond_error_nth(
        "team_members",
        2,
        r#"{"error":"NotFound","reason":"team_env_not_found"}"#,
        1,
    );
    // the other Mac is not reachable: the CLI's detail names why, as a code
    fx.respond_error(
        "team_join",
        r#"{"error":"StateError","reason":"team_join_failed","detail":"link_peer_offline"}"#,
        1,
    );
    let out = ok(core.pairing_join(RefIn {
        reference: preview.reference.clone(),
    }));
    assert!(!out.done);
    let dev = &out.environments[0];
    assert_eq!(
        (dev.state, dev.reason.as_deref(), dev.detail.as_deref()),
        (
            "failed",
            Some("team_join_failed"),
            Some("link_peer_offline")
        )
    );
    let prod = &out.environments[1];
    assert_eq!(
        (prod.state, prod.reason.as_deref(), prod.detail.as_deref()),
        ("failed", Some("pairing_env_exists"), None)
    );
    // only demo/dev was tried: nothing is joined into the unrelated local environment
    let joins: Vec<_> = fx
        .calls()
        .into_iter()
        .filter(|c| c.key == "team_join")
        .collect();
    assert_eq!(joins.len(), 1);
    assert!(joins[0].args().contains(&"--environment=dev"));

    // a detail that is not a code (free text from the CLI) is not passed on
    fx.respond_nth(
        "team_members",
        3,
        r#"{"env_id":"envsynthetic","members":[]}"#,
    );
    fx.respond_error(
        "team_join",
        r#"{"error":"StateError","reason":"team_join_failed","detail":"could not reach 192.0.2.7 for synthetic"}"#,
        1,
    );
    let again = ok(core.pairing_join(RefIn {
        reference: preview.reference,
    }));
    assert_eq!(
        again.environments[0].reason.as_deref(),
        Some("team_join_failed")
    );
    assert_eq!(again.environments[0].detail, None);
}

#[test]
fn link_status_reports_a_mac_removed_at_the_service() {
    let fx = Fixture::new();
    let core = core(&fx);
    let _link = FakeLink::start(&fx.paths.link_socket(), |req| {
        Some(match req["op"].as_str() {
            Some("status") => {
                json!({"ok": true, "enrolled": true, "revoked": true, "service": SERVICE,
                                     "device_id": OWN_LINK, "account_id": "acct_1", "online": false, "peers": []})
            }
            _ => json!({"ok": false, "error": "device_revoked"}),
        })
    });
    let status = ok(core.link_status());
    assert!(status.running && status.enrolled && status.revoked && !status.online);
    let e = err(core.link_enroll(LinkEnrollIn {
        invite_code: INVITE_CODE.into(),
        service: None,
        name: None,
    }));
    // enrolled already (and removed): no second enrolment is tried
    assert_eq!(e.reason, "link_already_enrolled");
}
