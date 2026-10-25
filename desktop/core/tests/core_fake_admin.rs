//! `Core` against the fake zeropw-admin: argv shape (`--flag=value`, no secret in argv), the
//! input envelope, the child environment, error parsing without echo, timeouts, and the
//! one-time store wiring of tokens, links and revealed values.

mod common;

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use common::{FakeClipboard, Fixture, arc_events, err, health_server, ok, wait_until};
use serde_json::json;
use zeropw_desktop_core::commands::*;
use zeropw_desktop_core::{Core, CoreConfig, FilePurpose, NoEvents, SecretString, Settings};

const ADMIN_PASS: &str = "velvet-ocean-27-quartz-lantern";

fn core(fx: &Fixture) -> Core {
    let mut config = CoreConfig::new(fx.paths.clone());
    config.serve_stop_grace = Duration::from_secs(3);
    config.serve_start_timeout = Duration::from_secs(10);
    Core::new(config, Arc::new(NoEvents))
}

fn pass() -> SecretString {
    SecretString::from(ADMIN_PASS)
}

/// No argv element contains any of `secrets`.
fn assert_argv_clean(fx: &Fixture, secrets: &[&str]) {
    for call in fx.calls() {
        for arg in &call.argv {
            for secret in secrets {
                assert!(
                    !arg.contains(secret),
                    "secret in argv of {}: {arg}",
                    call.key
                );
            }
        }
    }
}

#[test]
fn vault_init_passes_passphrases_only_in_the_envelope_then_starts_serve() {
    let fx = Fixture::new();
    let core = core(&fx);
    let port = health_server();
    core.settings_set(Settings {
        gateway_port: port,
        team_listen: None,
    })
    .unwrap();

    let code = core.recovery_generate().unwrap();
    assert_eq!(code.groups.len(), 6);
    let recovery_text = code.groups.join("-");
    let out = core
        .vault_init(VaultInitIn {
            admin_passphrase: pass(),
            recovery: RecoveryInput::Ref(code.reference.clone()),
        })
        .unwrap();
    assert_eq!(out.kms_key_id, "kms-synthetic");

    let init = fx.last("init");
    assert_eq!(
        init.argv,
        [fx.state_dir_arg().as_str(), "--input-envelope", "init"]
    );
    assert_eq!(
        init.stdin_json(),
        json!({"admin_passphrase": ADMIN_PASS, "recovery_passphrase": recovery_text})
    );
    // Cleared environment: only the fixed variables (plus what sh itself sets).
    // (PWD, SHLVL, _ and OLDPWD come from sh itself; macOS adds __CF_USER_TEXT_ENCODING.)
    for (key, _) in &init.env {
        assert!(
            [
                "PATH",
                "HOME",
                "LANG",
                "TMPDIR",
                "PWD",
                "SHLVL",
                "_",
                "OLDPWD",
                "__CF_USER_TEXT_ENCODING"
            ]
            .contains(&key.as_str()),
            "unexpected env var {key}"
        );
    }
    assert_eq!(init.env_var("PATH"), Some("/usr/bin:/bin"));
    assert_eq!(init.env_var("LANG"), Some("C.UTF-8"));
    assert!(init.env_var("HOME").is_some());

    let serve = fx.last("serve");
    assert_eq!(
        serve.args(),
        ["serve", &format!("--listen=127.0.0.1:{port}"), "--quiet"]
    );
    assert!(serve.stdin.is_none());
    let status = core.serve_status();
    assert!(status.running);
    assert_eq!(status.url, Some(format!("http://127.0.0.1:{port}")));

    assert_argv_clean(&fx, &[ADMIN_PASS, &recovery_text]);
    // The generated code was used up by the successful init.
    assert_eq!(
        err(core.onetime_show(RefIn {
            reference: code.reference
        }))
        .reason,
        "onetime_ref_unknown"
    );

    let app = core.app_status().unwrap();
    assert!(app.initialized);
    assert_eq!(app.control.map(|c| c.stopped), Some(false));
    assert!(app.serve.running);
    assert!(!core.serve_stop().running);
}

#[test]
fn vault_init_checks_passphrases_before_running_anything() {
    let fx = Fixture::new();
    let core = core(&fx);
    let weak = core
        .vault_init(VaultInitIn {
            admin_passphrase: "password1".into(),
            recovery: RecoveryInput::Typed("another-velvet-lantern-42-quartz".into()),
        })
        .unwrap_err();
    assert_eq!(
        (weak.reason.as_str(), weak.detail.as_deref()),
        ("passphrase_weak", Some("admin"))
    );
    let short = core
        .vault_init(VaultInitIn {
            admin_passphrase: "x7#Qa9!".into(),
            recovery: RecoveryInput::Typed("another-velvet-lantern-42-quartz".into()),
        })
        .unwrap_err();
    assert_eq!(short.reason, "passphrase_too_short");
    let same = core
        .vault_init(VaultInitIn {
            admin_passphrase: pass(),
            recovery: RecoveryInput::Typed(format!(" {} ", ADMIN_PASS.to_uppercase()).into()),
        })
        .unwrap_err();
    assert_eq!(same.reason, "passphrases_identical");
    let weak_recovery = core
        .vault_init(VaultInitIn {
            admin_passphrase: pass(),
            recovery: RecoveryInput::Typed("password123".into()),
        })
        .unwrap_err();
    assert_eq!(
        (
            weak_recovery.reason.as_str(),
            weak_recovery.detail.as_deref()
        ),
        ("passphrase_weak", Some("recovery"))
    );
    let bad_ref = core
        .vault_init(VaultInitIn {
            admin_passphrase: pass(),
            recovery: RecoveryInput::Ref("00000000000000000000000000000000".into()),
        })
        .unwrap_err();
    assert_eq!(bad_ref.reason, "onetime_ref_unknown");
    for e in [&weak, &short, &same, &weak_recovery] {
        let text = serde_json::to_string(e).unwrap();
        assert!(
            !text.contains("password") && !text.contains("velvet"),
            "{text}"
        );
    }
    assert!(fx.calls().is_empty());
}

#[test]
fn failed_init_keeps_the_generated_code_for_a_retry() {
    let fx = Fixture::new();
    let core = core(&fx);
    fx.respond_error(
        "init",
        r#"{"error":"StateError","reason":"state_exists","detail":"/x/state"}"#,
        1,
    );
    let code = core.recovery_generate().unwrap();
    let e = core
        .vault_init(VaultInitIn {
            admin_passphrase: pass(),
            recovery: RecoveryInput::Ref(code.reference.clone()),
        })
        .unwrap_err();
    assert_eq!(
        (e.error.as_str(), e.reason.as_str()),
        ("StateError", "state_exists")
    );
    // Still redeemable by the next attempt.
    fx.clear_response("init");
    fx.respond("init", r#"{"kms_key_id":"k","state_dir":"/s"}"#);
    fx.respond_error(
        "serve",
        r#"{"error":"StateError","reason":"state_missing"}"#,
        1,
    );
    let e = core
        .vault_init(VaultInitIn {
            admin_passphrase: pass(),
            recovery: RecoveryInput::Ref(code.reference.clone()),
        })
        .unwrap_err();
    // init succeeded (code consumed), the sidecar did not start.
    assert_eq!(e.reason, "state_missing");
    assert_eq!(fx.count("init"), 2);
    assert!(
        err(core.onetime_show(RefIn {
            reference: code.reference
        }))
        .reason
            == "onetime_ref_unknown"
    );
}

#[test]
fn secret_put_typed_value_travels_as_value_b64() {
    let fx = Fixture::new();
    let core = core(&fx);
    let value = "sk-synthetic-0123456789";
    let out = core
        .secret_put(SecretPutIn {
            id: "api".into(),
            kind: SecretKind::ApiKey,
            project: "demo".into(),
            environment: "dev".into(),
            source: SecretSource::Typed(value.into()),
        })
        .unwrap();
    assert_eq!(out["version"], 1);
    let call = fx.last("secret_put");
    assert_eq!(
        call.args(),
        [
            "secret",
            "put",
            "--id=api",
            "--kind=api_key",
            "--project=demo",
            "--environment=dev",
            "--stdin"
        ]
    );
    assert_eq!(
        call.stdin_json(),
        json!({"value_b64": base64::engine::general_purpose::STANDARD.encode(value)})
    );
    assert_argv_clean(&fx, &[value]);
}

#[test]
fn secret_put_generated_ssh_key_returns_only_public_parts() {
    let fx = Fixture::new();
    let core = core(&fx);
    let out = core
        .secret_put(SecretPutIn {
            id: "deploy".into(),
            kind: SecretKind::SshPrivateKey,
            project: "demo".into(),
            environment: "dev".into(),
            source: SecretSource::GenerateEd25519(true),
        })
        .unwrap();
    let public = out["public_key"].as_str().unwrap();
    assert!(public.starts_with("ssh-ed25519 AAAA"));
    assert!(public.ends_with(" zeropw-deploy"));
    assert!(out["fingerprint"].as_str().unwrap().starts_with("SHA256:"));
    let text = out.to_string();
    assert!(!text.contains("PRIVATE KEY"));

    let envelope = fx.last("secret_put").stdin_json();
    let pem = base64::engine::general_purpose::STANDARD
        .decode(envelope["value_b64"].as_str().unwrap())
        .unwrap();
    let pem = String::from_utf8(pem).unwrap();
    assert!(pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
    assert!(!text.contains(pem.lines().nth(1).unwrap()));
    assert_argv_clean(&fx, &["PRIVATE KEY", pem.lines().nth(1).unwrap()]);

    let mismatch = core
        .secret_put(SecretPutIn {
            id: "deploy".into(),
            kind: SecretKind::ApiKey,
            project: "demo".into(),
            environment: "dev".into(),
            source: SecretSource::GenerateEd25519(true),
        })
        .unwrap_err();
    assert_eq!(mismatch.reason, "source_kind_mismatch");
}

#[test]
fn secret_put_from_a_picked_file_uses_a_single_use_token() {
    let fx = Fixture::new();
    let core = core(&fx);
    let file = fx.dir.path().join("synthetic.key");
    fs::write(&file, b"synthetic-file-secret\n").unwrap();
    let pick = core.files().register(FilePurpose::Secret, &file).unwrap();
    assert_eq!(pick.name, "synthetic.key");
    let put = |token: &str| {
        core.secret_put(SecretPutIn {
            id: "file".into(),
            kind: SecretKind::Password,
            project: "demo".into(),
            environment: "dev".into(),
            source: SecretSource::FileToken(token.into()),
        })
    };
    put(&pick.file_token).unwrap();
    let envelope = fx.last("secret_put").stdin_json();
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(envelope["value_b64"].as_str().unwrap())
            .unwrap(),
        b"synthetic-file-secret\n"
    );
    assert_eq!(
        put(&pick.file_token).unwrap_err().reason,
        "file_token_unknown"
    );
    assert_argv_clean(&fx, &["synthetic-file-secret", file.to_str().unwrap()]);
}

#[test]
fn secret_reveal_returns_a_reference_shown_once() {
    let fx = Fixture::new();
    let core = core(&fx);
    let out = core
        .secret_reveal(SecretRevealIn {
            id: "api".into(),
            version: Some("1".into()),
            admin_passphrase: pass(),
        })
        .unwrap();
    assert_eq!((out.id.as_str(), out.version.as_str()), ("api", "1"));
    let serialized = serde_json::to_string(&out).unwrap();
    assert!(!serialized.contains("synthetic-revealed-value"));
    let call = fx.last("secret_reveal");
    assert_eq!(call.args(), ["secret", "reveal", "--id=api", "--version=1"]);
    assert_eq!(call.stdin_json(), json!({"admin_passphrase": ADMIN_PASS}));
    let shown = core
        .onetime_show(RefIn {
            reference: out.reference.clone(),
        })
        .ok()
        .unwrap();
    assert_eq!(shown.expose(), "synthetic-revealed-value");
    assert!(
        core.onetime_show(RefIn {
            reference: out.reference
        })
        .is_err()
    );
    assert_argv_clean(&fx, &[ADMIN_PASS]);

    let missing = core
        .secret_reveal(SecretRevealIn {
            id: "api".into(),
            version: None,
            admin_passphrase: "".into(),
        })
        .unwrap_err();
    assert_eq!(missing.reason, "passphrase_missing");
    let bad_version = core
        .secret_reveal(SecretRevealIn {
            id: "api".into(),
            version: Some("1; rm".into()),
            admin_passphrase: pass(),
        })
        .unwrap_err();
    assert_eq!(bad_version.detail.as_deref(), Some("version"));
}

#[test]
fn cli_errors_are_parsed_and_never_echo_secrets() {
    let fx = Fixture::new();
    let core = core(&fx);
    fx.respond_error(
        "secret_reveal",
        &format!(
            "usage: zeropw-admin [-h] --state-dir DIR\n{{\"detail\":\"passphrase {ADMIN_PASS} rejected\",\"error\":\"AuthFailed\",\"reason\":\"bad_passphrase\"}}\n"
        ),
        1,
    );
    let e = core
        .secret_reveal(SecretRevealIn {
            id: "api".into(),
            version: None,
            admin_passphrase: pass(),
        })
        .unwrap_err();
    assert_eq!(
        (e.error.as_str(), e.reason.as_str()),
        ("AuthFailed", "bad_passphrase")
    );
    assert_eq!(e.detail, None);
    assert!(!serde_json::to_string(&e).unwrap().contains(ADMIN_PASS));

    fx.respond_error(
        "secret_put",
        "{\"detail\":\"value c3ludGhldGlj was refused\",\"error\":\"InvalidInput\",\"reason\":\"x\"}",
        1,
    );
    let e = core
        .secret_put(SecretPutIn {
            id: "api".into(),
            kind: SecretKind::ApiKey,
            project: "demo".into(),
            environment: "dev".into(),
            source: SecretSource::Typed("synthetic".into()),
        })
        .unwrap_err();
    assert_eq!(e.detail, None, "detail carried the value's base64");

    fx.respond_error("project_list", "Traceback: something broke\n", 3);
    let e = core.project_list().unwrap_err();
    assert_eq!(
        (e.error.as_str(), e.reason.as_str(), e.detail.as_deref()),
        ("InternalError", "admin_failed", Some("exit status 3"))
    );

    fx.clear_response("project_list");
    fx.respond("project_list", "not json");
    assert_eq!(
        core.project_list().unwrap_err().reason,
        "admin_output_invalid"
    );
}

#[test]
fn a_hung_cli_call_is_killed_at_the_timeout() {
    let fx = Fixture::new();
    let mut config = CoreConfig::new(fx.paths.clone());
    config.admin_timeout = Duration::from_secs(1);
    let core = Core::new(config, Arc::new(NoEvents));
    fx.respond_sleep("status", 30);
    let started = Instant::now();
    let e = core.control_get().unwrap_err();
    assert_eq!(
        (e.error.as_str(), e.reason.as_str()),
        ("Timeout", "admin_timeout")
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn project_create_checks_the_positional_name() {
    let fx = Fixture::new();
    let core = core(&fx);
    for bad in ["-rf", "--help", "Demo", "a b", ""] {
        let e = core
            .project_create(ProjectCreateIn {
                name: bad.into(),
                environments: vec!["dev".into()],
            })
            .unwrap_err();
        assert_eq!(e.detail.as_deref(), Some("name"));
    }
    let e = core
        .project_create(ProjectCreateIn {
            name: "demo".into(),
            environments: vec!["dev".into(), "-x".into()],
        })
        .unwrap_err();
    assert_eq!(e.detail.as_deref(), Some("environments"));
    assert!(fx.calls().is_empty());
    core.project_create(ProjectCreateIn {
        name: "demo".into(),
        environments: vec!["dev".into(), "prod".into()],
    })
    .unwrap();
    assert_eq!(
        fx.last("project_create").args(),
        ["project", "create", "demo", "--environments=dev,prod"]
    );
}

#[test]
fn principal_token_goes_to_the_store_only() {
    let fx = Fixture::new();
    let core = core(&fx);
    let out = core
        .principal_create(PrincipalCreateIn {
            id: "agent-1".into(),
            runtime: "".into(),
        })
        .unwrap();
    assert_eq!(
        fx.last("principal_create").args(),
        ["principal", "create", "--id=agent-1"]
    );
    assert!(
        !serde_json::to_string(&out)
            .unwrap()
            .contains("zpw_synthetic_caller_token")
    );
    let token = core
        .onetime_show(RefIn {
            reference: out.token_ref,
        })
        .ok()
        .unwrap();
    assert_eq!(token.expose(), "zpw_synthetic_caller_token");
}

#[test]
fn invite_link_is_stored_and_the_raw_invite_dropped() {
    let fx = Fixture::new();
    let core = core(&fx);
    // An output without `inviter` makes the core ask `team invite-info` with the link.
    fx.respond(
        "team_invite",
        r#"{"env_id":"e","expires_at":"2026-10-16T00:00:00Z","invite":"SYNTHETICINVITE","invite_id":"aa","link":"zeropw://join#SYNTHETICINVITE"}"#,
    );
    let out = core
        .team_invite_create(TeamInviteCreateIn {
            env: "demo/dev".into(),
            role: TeamRole::User,
            name: "bob".into(),
            address: "192.168.1.20:47390".into(),
            admin_passphrase: pass(),
        })
        .unwrap();
    assert_eq!(out.inviter, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    assert!(
        !serde_json::to_string(&out)
            .unwrap()
            .contains("SYNTHETICINVITE")
    );
    let call = fx.last("team_invite");
    assert_eq!(
        call.args(),
        [
            "team",
            "invite",
            "--env=demo/dev",
            "--role=user",
            "--name=bob",
            "--address=192.168.1.20:47390",
            "--link"
        ]
    );
    assert_eq!(call.stdin_json(), json!({"admin_passphrase": ADMIN_PASS}));
    let info = fx.last("team_invite-info");
    assert_eq!(info.args(), ["team", "invite-info", "--stdin"]);
    assert_eq!(
        info.stdin_json(),
        json!({"invite": "zeropw://join#SYNTHETICINVITE"})
    );
    let link = core
        .onetime_show(RefIn {
            reference: out.link_ref,
        })
        .ok()
        .unwrap();
    assert_eq!(link.expose(), "zeropw://join#SYNTHETICINVITE");
    assert_argv_clean(&fx, &["SYNTHETICINVITE", ADMIN_PASS]);
}

#[test]
fn preview_then_join_keep_the_invite_out_of_argv_and_the_webview() {
    let fx = Fixture::new();
    let core = core(&fx);
    let preview = core
        .team_invite_preview(TeamInvitePreviewIn {
            text: "  zeropw://join#SYNTHETICINVITE\n".into(),
        })
        .unwrap();
    assert_eq!(preview.preview.role, "user");
    assert_eq!(preview.preview.addresses, ["192.168.1.20:47390"]);
    assert_eq!(
        fx.last("team_invite-info").stdin_json(),
        json!({"invite": "zeropw://join#SYNTHETICINVITE"})
    );
    // The pasted invite is not showable back to the webview.
    assert!(
        core.onetime_show(RefIn {
            reference: preview.reference.clone()
        })
        .is_err()
    );
    let joined = core
        .team_join(TeamJoinIn {
            reference: preview.reference.clone(),
            project: Some("demo".into()),
            environment: None,
        })
        .unwrap();
    assert_eq!(joined["env_id"], "env-synthetic");
    let call = fx.last("team_join");
    assert_eq!(call.args(), ["team", "join", "--stdin", "--project=demo"]);
    assert_eq!(
        call.stdin_json(),
        json!({"invite": "zeropw://join#SYNTHETICINVITE"})
    );
    // Used up by the successful join.
    assert_eq!(
        core.team_join(TeamJoinIn {
            reference: preview.reference,
            project: None,
            environment: None,
        })
        .unwrap_err()
        .reason,
        "onetime_ref_unknown"
    );
    assert_argv_clean(&fx, &["SYNTHETICINVITE"]);
}

#[test]
fn deep_links_only_preview_and_emit_an_event() {
    let fx = Fixture::new();
    let events = arc_events();
    let core = Core::new(CoreConfig::new(fx.paths.clone()), events.clone());
    for bad in [
        "https://evil.example/join#X",
        "zeropw://joi",
        "javascript:alert(1)",
    ] {
        assert_eq!(
            core.open_deep_link(bad).unwrap_err().reason,
            "deep_link_invalid"
        );
    }
    assert!(fx.calls().is_empty());
    let out = core
        .open_deep_link("ZeroPW://join#SYNTHETICINVITE")
        .unwrap();
    let emitted = events.named("invite://preview");
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0]["ref"], out.reference);
    assert_eq!(
        emitted[0]["preview"]["inviter"],
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    );
    assert!(!emitted[0].to_string().contains("SYNTHETICINVITE"));
    assert_eq!(fx.count("team_join"), 0);
}

#[test]
fn invite_lists_never_forward_link_strings() {
    let fx = Fixture::new();
    let core = core(&fx);
    fx.respond(
        "team_invites",
        r#"{"env_id":"e1","invites":[{"invite_id":"aa","role":"user","name":"bob","link":"zeropw://join#SYNTHETICINVITE","wrapped_secret":"c2VjcmV0","created_at":null,"expires_at":"t","status":"pending","used_at":null,"used_by":null,"revoked_at":null},{"invite_id":"bb","role":"admin","name":"amy","link":false,"expires_at":"t","status":"used"}]}"#,
    );
    let out = core
        .team_invites(EnvIn {
            env: "demo/dev".into(),
        })
        .unwrap();
    let text = out.to_string();
    assert!(
        !text.contains("SYNTHETICINVITE") && !text.contains("wrapped_secret"),
        "{text}"
    );
    assert_eq!(out["invites"][0]["link"], true);
    assert_eq!(out["invites"][1]["link"], false);
    assert_eq!(out["invites"][1]["used_at"], serde_json::Value::Null);
    assert_eq!(out["env_id"], "e1");
}

#[test]
fn control_commands_reduce_the_incident_id_and_emit_events() {
    let fx = Fixture::new();
    let events = arc_events();
    let core = Core::new(CoreConfig::new(fx.paths.clone()), events.clone());
    fx.respond(
        "stop-all",
        r#"{"incident_open":"inc-1","restore_pending":false,"stopped":true}"#,
    );
    let control = core.stop_all().unwrap();
    assert!(control.stopped && control.incident_open);
    assert_eq!(
        events.named("control://changed"),
        [json!({"stopped": true, "restore_pending": false, "incident_open": true})]
    );
    assert_eq!(
        core.resume(PassphraseIn {
            admin_passphrase: "".into()
        })
        .unwrap_err()
        .reason,
        "passphrase_missing"
    );
    core.resume(PassphraseIn {
        admin_passphrase: pass(),
    })
    .unwrap();
    assert_eq!(
        fx.last("resume").stdin_json(),
        json!({"admin_passphrase": ADMIN_PASS})
    );
    assert_eq!(fx.last("resume").args(), ["resume"]);
    assert_eq!(events.named("control://changed").len(), 2);
}

#[test]
fn http_connection_argv_and_ca_file_token() {
    let fx = Fixture::new();
    let core = core(&fx);
    let ca = fx.dir.path().join("ca.pem");
    fs::write(&ca, "synthetic ca").unwrap();
    let pick = core.files().register(FilePurpose::Ca, &ca).unwrap();
    core.connection_create_http(HttpConnectionIn {
        id: "gh".into(),
        project: "demo".into(),
        environment: "dev".into(),
        service: "github".into(),
        secret_id: "api".into(),
        target: "https://api.github.com".into(),
        auth: HttpAuth::Header,
        header_name: Some("Authorization".into()),
        value_prefix: Some("token ".into()),
        basic_username: None,
        methods: vec!["GET".into(), "POST".into()],
        confirm_methods: vec!["DELETE".into()],
        path_prefixes: vec!["/repos".into()],
        allow_private_network: false,
        cli_program: None,
        ca_file_token: Some(pick.file_token),
        description: Some("synthetic".into()),
        admin_passphrase: pass(),
    })
    .unwrap();
    let call = fx.last("connection_create-http");
    assert_eq!(
        call.args(),
        [
            "connection",
            "create-http",
            "--id=gh",
            "--project=demo",
            "--environment=dev",
            "--service=github",
            "--secret-id=api",
            "--target=https://api.github.com",
            "--auth=header",
            "--header-name=Authorization",
            "--value-prefix=token ",
            "--methods=GET,POST",
            "--confirm-methods=DELETE",
            "--path-prefixes=/repos",
            "--description=synthetic",
            &format!("--ca-file={}", ca.display()),
        ]
    );
    assert_eq!(call.stdin_json(), json!({"admin_passphrase": ADMIN_PASS}));
}

fn ssh_input(cli_program: &str) -> SshConnectionIn {
    SshConnectionIn {
        id: "prod".into(),
        project: "demo".into(),
        environment: "prod".into(),
        service: "ssh".into(),
        secret_id: "deploy".into(),
        host: "10.0.0.5".into(),
        port: 2222,
        username: "deploy".into(),
        host_keys: vec!["ssh-ed25519 AAAAone".into(), "ssh-ed25519 AAAAtwo".into()],
        cli_program: cli_program.into(),
        description: None,
        admin_passphrase: pass(),
    }
}

#[test]
fn ssh_connection_repeats_host_keys_and_names_its_ssh() {
    let fx = Fixture::new();
    let core = core(&fx);
    core.connection_create_ssh(ssh_input("/usr/bin/ssh"))
        .unwrap();
    assert_eq!(
        fx.last("connection_create-ssh").args(),
        [
            "connection",
            "create-ssh",
            "--id=prod",
            "--project=demo",
            "--environment=prod",
            "--service=ssh",
            "--secret-id=deploy",
            "--host=10.0.0.5",
            "--port=2222",
            "--username=deploy",
            "--host-key=ssh-ed25519 AAAAone",
            "--host-key=ssh-ed25519 AAAAtwo",
            "--cli-program=/usr/bin/ssh",
        ]
    );
}

/// An SSH connection without its ssh is one the agent's `exec` refuses (`cli_not_supported`,
/// desktop E2E finding F8), so the core never creates one: a payload without `cli_program` is
/// not accepted and an empty one is refused before the CLI runs.
#[test]
fn ssh_connection_without_its_ssh_is_refused_before_the_cli() {
    let payload = json!({
        "id": "prod", "project": "demo", "environment": "prod", "service": "ssh",
        "secret_id": "deploy", "host": "10.0.0.5", "port": 22, "username": "deploy",
        "host_keys": ["ssh-ed25519 AAAAone"], "admin_passphrase": ADMIN_PASS,
    });
    assert!(serde_json::from_value::<SshConnectionIn>(payload.clone()).is_err());
    let mut with_cli = payload;
    with_cli["cli_program"] = json!("/usr/bin/ssh");
    assert!(serde_json::from_value::<SshConnectionIn>(with_cli).is_ok());

    let fx = Fixture::new();
    let core = core(&fx);
    let e = core.connection_create_ssh(ssh_input("")).unwrap_err();
    assert_eq!(
        (e.error.as_str(), e.reason.as_str()),
        ("InvalidInput", "cli_program_required")
    );
    assert_eq!(fx.count("connection_create-ssh"), 0);
}

/// F8 repair: `connection_set_cli_program` is `connection update --cli-program` behind the
/// admin password. An empty path or a missing password never reaches the CLI; which connection
/// can take one is the CLI's rule, and its refusal comes back as it is.
#[test]
fn ssh_program_is_given_through_connection_update_behind_the_admin_password() {
    let fx = Fixture::new();
    let core = core(&fx);
    let input = |program: &str| CliProgramIn {
        id: "prod".into(),
        cli_program: program.into(),
        admin_passphrase: pass(),
    };
    core.connection_set_cli_program(input("/usr/bin/ssh"))
        .unwrap();
    let call = fx.last("connection_update");
    assert!(call.requires_admin());
    assert_eq!(
        call.args(),
        [
            "connection",
            "update",
            "--id=prod",
            "--cli-program=/usr/bin/ssh"
        ]
    );
    assert_eq!(call.stdin_json(), json!({"admin_passphrase": ADMIN_PASS}));

    let e = core.connection_set_cli_program(input("")).unwrap_err();
    assert_eq!(
        (e.error.as_str(), e.reason.as_str()),
        ("InvalidInput", "cli_program_required")
    );
    let e = core
        .connection_set_cli_program(CliProgramIn {
            admin_passphrase: SecretString::from(""),
            ..input("/usr/bin/ssh")
        })
        .unwrap_err();
    assert_eq!(
        (e.error.as_str(), e.reason.as_str()),
        ("AuthFailed", "passphrase_missing")
    );
    assert_eq!(fx.count("connection_update"), 1);
    for payload in [
        json!({"id": "prod", "admin_passphrase": ADMIN_PASS}),
        json!({"id": "prod", "cli_program": "/usr/bin/ssh", "admin_passphrase": ADMIN_PASS,
               "methods": "GET"}),
    ] {
        assert!(serde_json::from_value::<CliProgramIn>(payload).is_err());
    }

    fx.respond_error(
        "connection_update",
        r#"{"error":"InvalidInput","reason":"cli_already_set","detail":"disable the connection and create a new one to change its ssh program"}"#,
        1,
    );
    let e = core
        .connection_set_cli_program(input("/bin/sh"))
        .unwrap_err();
    assert_eq!(
        (e.error.as_str(), e.reason.as_str()),
        ("InvalidInput", "cli_already_set")
    );
    assert_argv_clean(&fx, &[ADMIN_PASS]);
}

/// The ssh path cannot be changed once given, so one that is not an absolute path to an
/// executable file on this machine is refused before the CLI runs, by both the create and the
/// fill (`cli_program_not_found`). The refusal does not repeat the path.
#[test]
fn an_ssh_path_that_names_no_executable_here_is_refused_before_the_cli() {
    use std::os::unix::fs::PermissionsExt;

    let fx = Fixture::new();
    let core = core(&fx);
    let plain = fx.dir.path().join("plain-file");
    fs::write(&plain, "synthetic").unwrap();
    fs::set_permissions(&plain, fs::Permissions::from_mode(0o644)).unwrap();
    let plain = plain.to_string_lossy().into_owned();
    let fill = |program: &str| CliProgramIn {
        id: "prod".into(),
        cli_program: program.into(),
        admin_passphrase: pass(),
    };
    for bad in [
        "/usr/bin/sshh",
        "ssh",
        "usr/bin/ssh",
        "/usr/bin",
        "/bin/sh/",
        plain.as_str(),
    ] {
        for e in [
            core.connection_create_ssh(ssh_input(bad)).unwrap_err(),
            core.connection_set_cli_program(fill(bad)).unwrap_err(),
        ] {
            assert_eq!(
                (e.error.as_str(), e.reason.as_str(), e.detail.as_deref()),
                ("InvalidInput", "cli_program_not_found", None),
                "{bad}"
            );
        }
    }
    assert_eq!(fx.count("connection_create-ssh"), 0);
    assert_eq!(fx.count("connection_update"), 0);

    // A real executable passes, also through a symlink, and reaches the CLI unchanged.
    let link = fx.dir.path().join("ssh-link");
    std::os::unix::fs::symlink("/bin/sh", &link).unwrap();
    let link = link.to_string_lossy().into_owned();
    for good in ["/bin/sh", link.as_str()] {
        core.connection_create_ssh(ssh_input(good)).unwrap();
        let create = fx.last("connection_create-ssh");
        assert!(
            create
                .args()
                .contains(&format!("--cli-program={good}").as_str())
        );
        core.connection_set_cli_program(fill(good)).unwrap();
        let update = fx.last("connection_update");
        assert_eq!(update.args()[3], format!("--cli-program={good}"));
    }
}

/// The envelopes of the `recover` calls after the first `skip`.
fn recover_envelopes(fx: &Fixture, skip: usize) -> Vec<serde_json::Value> {
    fx.calls()
        .into_iter()
        .filter(|c| c.key == "recover")
        .skip(skip)
        .map(|c| c.stdin_json()["recovery_passphrase"].clone())
        .collect()
}

#[test]
fn recover_tries_the_canonical_code_then_the_exact_text_and_no_more() {
    let fx = Fixture::new();
    let core = core(&fx);
    let typed = "abcd efgh ijkl mnop qrst uvw2";
    let canonical = "ABCD-EFGH-IJKL-MNOP-QRST-UVW2";
    let recover = |text: &str| {
        core.recover(RecoverIn {
            recovery_passphrase: text.into(),
        })
    };

    // A code the app made: the canonical form works at once, one call.
    recover(typed).unwrap();
    assert_eq!(fx.last("recover").args(), ["recover"]);
    assert_eq!(recover_envelopes(&fx, 0), [json!(canonical)]);

    // A vault whose recovery passphrase was given to `zeropw-admin init` as typed: the
    // canonical form fails authentication, then the exact text is tried once. Never more
    // than two attempts (two auth_failed records) for one request.
    fx.respond_error(
        "recover",
        r#"{"error":"AuthFailed","reason":"recovery_failed"}"#,
        1,
    );
    let e = recover(typed).unwrap_err();
    assert_eq!(
        (e.error.as_str(), e.reason.as_str()),
        ("AuthFailed", "recovery_failed")
    );
    assert_eq!(recover_envelopes(&fx, 1), [json!(canonical), json!(typed)]);

    // Already canonical, or not shaped like a code: one attempt only.
    for text in [canonical, "my own Recovery phrase 9"] {
        let before = fx.count("recover");
        assert!(recover(text).is_err());
        assert_eq!(recover_envelopes(&fx, before), [json!(text)]);
    }

    // Any other failure is not retried.
    fx.respond_error(
        "recover",
        r#"{"error":"StateError","reason":"state_corrupt"}"#,
        1,
    );
    let before = fx.count("recover");
    assert_eq!(recover(typed).unwrap_err().reason, "state_corrupt");
    assert_eq!(recover_envelopes(&fx, before), [json!(canonical)]);
    assert_argv_clean(&fx, &["ABCD", "abcd", "phrase"]);
}

/// Issue #59: a running sidecar, which holds the KMS key in memory, is stopped while
/// `recover` runs and started again after it, whether the recovery succeeds or fails; a
/// start asked for meanwhile, as the app's startup thread or relay button can, waits for the
/// recovery to end; a stopped sidecar stays stopped.
#[test]
fn recover_stops_a_running_serve_and_starts_it_again() {
    let fx = Fixture::new();
    let core = core(&fx);
    let port = health_server();
    core.settings_set(Settings {
        gateway_port: port,
        team_listen: None,
    })
    .unwrap();
    let recover = || {
        core.recover(RecoverIn {
            recovery_passphrase: "my own Recovery phrase 9".into(),
        })
    };

    recover().unwrap();
    assert_eq!(fx.count("serve"), 0);
    assert!(!core.serve_status().running);

    let mut pid = core.serve_start().unwrap().pid;
    let failed = r#"{"error":"AuthFailed","reason":"recovery_failed"}"#;
    // The start asked for meanwhile gets a round of its own: it would also start the
    // sidecar once the recovery ends, so in another round it could hide a recovery that does
    // not.
    for (failure, start_meanwhile) in [(None, false), (Some(failed), false), (None, true)] {
        let round = format!("failure {failure:?}, start meanwhile {start_meanwhile}");
        fx.clear_response("recover");
        // `recover` takes two seconds, so the sidecar can be seen stopped while it runs.
        fx.respond_sleep("recover", 2);
        if let Some(stderr) = failure {
            fx.respond_error("recover", stderr, 1);
        }
        let (serves, recovers) = (fx.count("serve"), fx.count("recover"));
        let result = std::thread::scope(|s| {
            let run = s.spawn(recover);
            assert!(wait_until(Duration::from_secs(5), || fx.count("recover") > recovers));
            assert!(!core.serve_status().running, "{round}");
            if !start_meanwhile {
                return run.join().unwrap();
            }
            let start = s.spawn(|| core.serve_start());
            assert!(
                !wait_until(Duration::from_millis(1200), || fx.count("serve") > serves),
                "a sidecar started during the recovery: {round}"
            );
            let result = run.join().unwrap();
            assert!(start.join().unwrap().unwrap().running, "{round}");
            result
        });
        assert_eq!(result.is_err(), failure.is_some(), "{round}");
        assert_eq!(fx.count("serve"), serves + 1, "{round}");
        let status = core.serve_status();
        assert!(status.running, "{round}");
        assert_ne!(status.pid, pid, "{round}");
        pid = status.pid;
    }
    assert!(!core.serve_stop().running);
}

#[test]
fn incident_all_scope_needs_the_passphrase() {
    let fx = Fixture::new();
    let core = core(&fx);
    let e = core
        .incident_declare(IncidentDeclareIn {
            scope: IncidentScope::All,
            principal: None,
            runtime: None,
            reason: None,
            admin_passphrase: None,
        })
        .unwrap_err();
    assert_eq!(e.reason, "passphrase_missing");
    core.incident_declare(IncidentDeclareIn {
        scope: IncidentScope::Principal,
        principal: Some("agent-1".into()),
        runtime: None,
        reason: Some("leaked log".into()),
        admin_passphrase: None,
    })
    .unwrap();
    let call = fx.last("incident_declare");
    assert_eq!(
        call.args(),
        [
            "incident",
            "declare",
            "--scope=principal",
            "--principal=agent-1",
            "--reason=leaked log"
        ]
    );
    assert_eq!(call.stdin_json(), json!({}));
}

#[test]
fn onetime_copy_clears_the_clipboard_only_if_unchanged() {
    let fx = Fixture::new();
    let mut config = CoreConfig::new(fx.paths.clone());
    config.clipboard_clear_after = Duration::from_millis(200);
    let core = Core::new(config, Arc::new(NoEvents));
    let clipboard = Arc::new(FakeClipboard::default());

    let first = core
        .principal_create(PrincipalCreateIn {
            id: "a".into(),
            runtime: "default".into(),
        })
        .unwrap();
    let out = core
        .onetime_copy(
            RefIn {
                reference: first.token_ref.clone(),
            },
            clipboard.clone(),
        )
        .unwrap();
    assert_eq!((out.copied, out.clears_in_s), (true, 0));
    assert_eq!(
        clipboard.0.lock().unwrap().as_deref(),
        Some("zpw_synthetic_caller_token")
    );
    assert!(
        core.onetime_show(RefIn {
            reference: first.token_ref
        })
        .is_err()
    );
    assert!(wait_until(Duration::from_secs(3), || clipboard
        .0
        .lock()
        .unwrap()
        .is_none()));

    let second = core
        .principal_create(PrincipalCreateIn {
            id: "b".into(),
            runtime: "default".into(),
        })
        .unwrap();
    core.onetime_copy(
        RefIn {
            reference: second.token_ref,
        },
        clipboard.clone(),
    )
    .unwrap();
    *clipboard.0.lock().unwrap() = Some("something the user copied".into());
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(
        clipboard.0.lock().unwrap().as_deref(),
        Some("something the user copied")
    );
}

#[test]
fn quitting_clears_a_copied_value_still_on_the_clipboard() {
    let fx = Fixture::new();
    let core_with_long_clear = || {
        let mut config = CoreConfig::new(fx.paths.clone());
        config.clipboard_clear_after = Duration::from_secs(3600);
        Core::new(config, Arc::new(NoEvents))
    };
    let copy = |core: &Core, clipboard: &Arc<FakeClipboard>| {
        let created = core
            .principal_create(PrincipalCreateIn {
                id: "a".into(),
                runtime: "default".into(),
            })
            .unwrap();
        core.onetime_copy(
            RefIn {
                reference: created.token_ref,
            },
            clipboard.clone(),
        )
        .unwrap();
        assert_eq!(
            clipboard.0.lock().unwrap().as_deref(),
            Some("zpw_synthetic_caller_token")
        );
    };

    // Quit long before the 60 s clear: the token does not stay behind.
    let core = core_with_long_clear();
    let clipboard = Arc::new(FakeClipboard::default());
    copy(&core, &clipboard);
    core.shutdown();
    assert_eq!(clipboard.0.lock().unwrap().as_deref(), None);

    // Something the user copied since is left alone.
    let core = core_with_long_clear();
    let clipboard = Arc::new(FakeClipboard::default());
    copy(&core, &clipboard);
    *clipboard.0.lock().unwrap() = Some("something the user copied".into());
    core.shutdown();
    assert_eq!(
        clipboard.0.lock().unwrap().as_deref(),
        Some("something the user copied")
    );
}

#[test]
fn a_full_one_time_store_refuses_before_the_cli_changes_anything() {
    let fx = Fixture::new();
    let core = core(&fx);
    // Fill the store with values that need no CLI call.
    for _ in 0..zeropw_desktop_core::onetime::MAX_ENTRIES {
        core.recovery_generate().unwrap();
    }
    let e = err(core.principal_create(PrincipalCreateIn {
        id: "agent-1".into(),
        runtime: "default".into(),
    }));
    assert_eq!(e.reason, "onetime_store_full");
    let e = err(core.team_invite_create(TeamInviteCreateIn {
        env: "demo/dev".into(),
        role: TeamRole::User,
        name: "bob".into(),
        address: "192.168.1.20:47390".into(),
        admin_passphrase: pass(),
    }));
    assert_eq!(e.reason, "onetime_store_full");
    let e = err(core.secret_reveal(SecretRevealIn {
        id: "api".into(),
        version: None,
        admin_passphrase: pass(),
    }));
    assert_eq!(e.reason, "onetime_store_full");
    // No principal was created, no invite issued, no reveal audited.
    for key in ["principal_create", "team_invite", "secret_reveal"] {
        assert_eq!(fx.count(key), 0, "{key} ran");
    }
}

#[test]
fn deep_links_cannot_fill_the_one_time_store() {
    let fx = Fixture::new();
    let core = core(&fx);
    let opened: Vec<String> = (0..zeropw_desktop_core::onetime::MAX_INVITE_TEXTS + 8)
        .map(|_| {
            core.open_deep_link("zeropw://join#SYNTHETICINVITE")
                .unwrap()
                .reference
        })
        .collect();
    // The newest previews are kept, the oldest gave way.
    assert!(!core.invite_pending(&opened[0]));
    assert!(core.invite_pending(opened.last().unwrap()));
    // Everything the app itself makes still fits.
    for _ in 0..zeropw_desktop_core::onetime::MAX_ENTRIES - 1 {
        core.recovery_generate().unwrap();
    }
    let created = core
        .principal_create(PrincipalCreateIn {
            id: "agent-1".into(),
            runtime: "default".into(),
        })
        .unwrap();
    assert_eq!(created.token_ref.len(), 32);
}

/// WEB-2: `secret_list`/`secret_versions` pass the CLI's output through, and the CLI prints a
/// secret's versions as JSON numbers (strings are accepted too). Feeding
/// those values straight back into the version commands must work, unchanged.
#[test]
fn versions_go_back_to_the_cli_as_it_printed_them() {
    let fx = Fixture::new();
    let core = core(&fx);
    fx.respond(
        "secret_versions",
        r#"{"active_version":2,"environment":"dev","id":"api","kind":"api_key","project":"demo","versions":[{"created_at":"2026-10-15T00:00:00Z","public":{},"status":"retired","version":1},{"created_at":"2026-10-15T00:00:00Z","public":{},"status":"active","version":2}]}"#,
    );
    let listed = core.secret_versions(IdIn { id: "api".into() }).unwrap();
    let versions: Vec<serde_json::Value> = listed["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["version"].clone())
        .collect();
    assert_eq!(versions, [json!(1), json!(2)]);

    // The webview sends back exactly what it got (deserialized like the IPC layer does).
    let revoke: SecretVersionIn =
        serde_json::from_value(json!({"id": "api", "version": versions[0]})).unwrap();
    core.secret_revoke(revoke).unwrap();
    assert_eq!(
        fx.last("secret_revoke").args(),
        ["secret", "revoke", "--id=api", "--version=1"]
    );
    let retire: SecretVersionIn =
        serde_json::from_value(json!({"id": "api", "version": "9f86d081884c7d65"})).unwrap();
    core.secret_retire(retire).unwrap();
    assert_eq!(
        fx.last("secret_retire").args(),
        ["secret", "retire", "--id=api", "--version=9f86d081884c7d65"]
    );
    let reveal: SecretRevealIn = serde_json::from_value(json!({
        "id": "api", "version": listed["active_version"], "admin_passphrase": ADMIN_PASS
    }))
    .unwrap();
    core.secret_reveal(reveal).unwrap();
    assert_eq!(
        fx.last("secret_reveal").args(),
        ["secret", "reveal", "--id=api", "--version=2"]
    );
}

#[test]
fn terminal_needs_a_caller_token_reference_and_a_running_gateway() {
    let fx = Fixture::new();
    let core = core(&fx);
    let revealed = core
        .secret_reveal(SecretRevealIn {
            id: "api".into(),
            version: None,
            admin_passphrase: pass(),
        })
        .unwrap();
    struct Null;
    impl zeropw_desktop_core::TerminalSink for Null {
        fn data(&mut self, _: &str) {}
        fn exit(&mut self, _: Option<u32>) {}
    }
    // A revealed secret's reference cannot be used as a terminal token.
    let e = err(core.terminal_open(
        TerminalOpenIn {
            token_ref: revealed.reference,
            as_user: None,
        },
        Box::new(Null),
    ));
    assert_eq!(e.reason, "onetime_ref_unknown");
    let token = core
        .principal_create(PrincipalCreateIn {
            id: "a".into(),
            runtime: "default".into(),
        })
        .unwrap();
    let e = err(core.terminal_open(
        TerminalOpenIn {
            token_ref: token.token_ref.clone(),
            as_user: None,
        },
        Box::new(Null),
    ));
    assert_eq!(e.reason, "serve_not_running");
    let e = err(core.terminal_open(
        TerminalOpenIn {
            token_ref: token.token_ref,
            as_user: Some("bad user".into()),
        },
        Box::new(Null),
    ));
    assert_eq!(e.reason, "invalid_account");
}

#[test]
fn list_commands_use_flag_equals_value() {
    let fx = Fixture::new();
    let core = core(&fx);
    core.secret_list(SecretListIn {
        project: Some("demo".into()),
        environment: Some("".into()),
    })
    .unwrap();
    assert_eq!(
        fx.last("secret_list").args(),
        ["secret", "list", "--project=demo"]
    );
    core.audit_tail(LimitIn { limit: 20 }).unwrap();
    assert_eq!(
        fx.last("audit_tail").args(),
        ["audit", "tail", "--limit=20"]
    );
    assert_eq!(
        core.alerts(LimitIn { limit: 0 })
            .unwrap_err()
            .detail
            .as_deref(),
        Some("limit")
    );
    core.grant_create(GrantCreateIn {
        principal: "agent-1".into(),
        connection: "gh".into(),
        ttl: "30m".into(),
        max_uses: Some("5".into()),
        admin_passphrase: pass(),
    })
    .unwrap();
    assert_eq!(
        fx.last("grant_create").args(),
        [
            "grant",
            "create",
            "--principal=agent-1",
            "--connection=gh",
            "--ttl=30m",
            "--max-uses=5"
        ]
    );
    core.backup_create(Path::new("/tmp/zeropw-backup.zpw"))
        .unwrap();
    assert_eq!(
        fx.last("backup").args(),
        ["backup", "--out=/tmp/zeropw-backup.zpw"]
    );
    assert!(core.backup_create(Path::new("relative.zpw")).is_err());
    core.team_revoke_invite(TeamRevokeInviteIn {
        env: "demo/dev".into(),
        invite_id: "aa".into(),
    })
    .unwrap();
    assert_eq!(
        fx.last("team_revoke-invite").args(),
        ["team", "revoke-invite", "--env=demo/dev", "--id=aa"]
    );
    // An option value that looks like an option stays a value.
    core.secret_versions(IdIn {
        id: "--help".into(),
    })
    .unwrap();
    assert_eq!(
        fx.last("secret_versions").args(),
        ["secret", "versions", "--id=--help"]
    );
    let e = core
        .secret_versions(IdIn { id: "a\nb".into() })
        .unwrap_err();
    assert_eq!(e.detail.as_deref(), Some("--id"));
}

#[test]
fn terminal_open_injects_the_principal_token_from_the_store() {
    use std::sync::Mutex;
    use std::sync::mpsc;
    use zeropw_desktop_core::{TerminalProgram, TerminalSink};

    struct Collect(Arc<Mutex<String>>, mpsc::Sender<Option<u32>>);
    impl TerminalSink for Collect {
        fn data(&mut self, chunk: &str) {
            self.0.lock().unwrap().push_str(chunk);
        }
        fn exit(&mut self, code: Option<u32>) {
            let _ = self.1.send(code);
        }
    }

    let fx = Fixture::new();
    let mut config = CoreConfig::new(fx.paths.clone());
    config.serve_stop_grace = Duration::from_secs(3);
    config.terminal_program = TerminalProgram::Program {
        path: "/bin/sh".into(),
        args: vec![
            "-c".into(),
            r#"echo "len=${#ZEROPW_CALLER_TOKEN} url=$ZEROPW_GATEWAY_URL""#.into(),
        ],
    };
    let core = Core::new(config, Arc::new(NoEvents));
    let port = health_server();
    core.settings_set(Settings {
        gateway_port: port,
        team_listen: None,
    })
    .unwrap();
    core.serve_start().unwrap();
    let principal = core
        .principal_create(PrincipalCreateIn {
            id: "agent-1".into(),
            runtime: "default".into(),
        })
        .unwrap();
    let out = Arc::new(Mutex::new(String::new()));
    let (tx, rx) = mpsc::channel();
    let opened = core
        .terminal_open(
            TerminalOpenIn {
                token_ref: principal.token_ref.clone(),
                as_user: Some("agent".into()),
            },
            Box::new(Collect(out.clone(), tx)),
        )
        .unwrap();
    assert_eq!(
        opened.suggestions,
        [
            "sudo --preserve-env=ZEROPW_GATEWAY_URL,ZEROPW_CALLER_TOKEN,no_proxy -u agent -i"
                .to_owned(),
            format!(
                "{}/zeropw-agent list-connections",
                fx.paths.bin_dir.display()
            ),
        ]
    );
    assert_eq!(rx.recv_timeout(Duration::from_secs(10)).unwrap(), Some(0));
    let text = out.lock().unwrap().clone();
    let token = "zpw_synthetic_caller_token";
    assert!(
        text.contains(&format!("len={} url=http://127.0.0.1:{port}", token.len())),
        "{text}"
    );
    assert!(!text.contains(token));
    // The terminal did not use up the token: it can still be shown once.
    let shown = core
        .onetime_show(RefIn {
            reference: principal.token_ref,
        })
        .ok()
        .unwrap();
    assert_eq!(shown.expose(), token);
    core.shutdown();
    assert!(!core.serve_status().running);
}

/// Desktop E2E F18: a damaged settings.json is never reset quietly, so `settings_get` and
/// `serve_start` refuse it with `settings_corrupt`. The settings screen repairs it by saving
/// the defaults with `settings_set`, which replaces the file without reading it (0600 again);
/// `settings_get` then returns what was saved.
#[test]
fn settings_set_replaces_a_damaged_settings_file() {
    use std::os::unix::fs::PermissionsExt;

    let oversized = vec![b' '; 70 * 1024];
    for damaged in [
        &br#"{"gateway_port": 80}"#[..],
        br#"{"gateway_port": 47380, "team_listen": "0.0.0.0:47390"}"#,
        b"{not json",
        &oversized,
    ] {
        let fx = Fixture::new();
        let core = core(&fx);
        let file = fx.paths.settings_file();
        fs::create_dir_all(&fx.paths.app_data_dir).unwrap();
        fs::write(&file, damaged).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        let reason = |e: zeropw_desktop_core::AppError| (e.error, e.reason);
        let corrupt = ("StateError".to_owned(), "settings_corrupt".to_owned());
        assert_eq!(reason(core.settings_get().unwrap_err()), corrupt);
        assert_eq!(reason(core.serve_start().unwrap_err()), corrupt);

        let defaults = Settings {
            gateway_port: 47380,
            team_listen: None,
        };
        assert_eq!(defaults, Settings::default());
        assert_eq!(core.settings_set(defaults.clone()).unwrap(), defaults);
        assert_eq!(core.settings_get().unwrap(), defaults);
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fx.count("serve"), 0);
    }
}

#[test]
fn app_status_before_init_does_not_run_the_cli() {
    let fx = Fixture::new();
    let core = core(&fx);
    let status = core.app_status().unwrap();
    assert!(!status.initialized);
    assert_eq!(status.control, None);
    assert!(!status.serve.running);
    assert_eq!(status.state_dir, fx.paths.state_dir().display().to_string());
    assert!(fx.calls().is_empty());
    let _ = ok(core.recovery_generate());
}
