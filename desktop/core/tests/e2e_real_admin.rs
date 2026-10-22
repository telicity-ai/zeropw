//! End to end against the real binaries (ignored by default). Needs `ZEROPW_BIN_DIR` pointing at
//! a build of `zeropw-admin` with the desktop CLI changes (docs/desktop-app.md §3:
//! `--input-envelope`, `status`). Synthetic passphrases and values only, temp state directory.
//!
//! ```text
//! cargo build --manifest-path rust/Cargo.toml --bins
//! ZEROPW_BIN_DIR=$CARGO_TARGET_DIR/debug \
//!   cargo test --manifest-path desktop/Cargo.toml --test e2e_real_admin -- --ignored
//! ```

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use zeropw_desktop_core::commands::*;
use zeropw_desktop_core::serve::{ServeConfig, ServeSupervisor, healthz};
use zeropw_desktop_core::{AppPaths, Core, CoreConfig, NoEvents, Settings};

fn bin_dir() -> PathBuf {
    let bin = PathBuf::from(std::env::var_os("ZEROPW_BIN_DIR").expect("set ZEROPW_BIN_DIR"));
    assert!(
        bin.join("zeropw-admin").is_file(),
        "no zeropw-admin in ZEROPW_BIN_DIR"
    );
    bin
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// The serve sidecar needs no input envelope, so this runs against today's CLI too. The state
/// directory is created the pre-envelope way (passphrases in the child's environment; test only,
/// synthetic values).
#[test]
#[ignore = "needs ZEROPW_BIN_DIR with zeropw-admin"]
fn real_serve_starts_attaches_and_stops() {
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::new(dir.path().join("app"), bin_dir());
    zeropw_desktop_core::paths::ensure_private_dir(&paths.app_data_dir).unwrap();
    let init = Command::new(paths.admin_bin())
        .arg(format!("--state-dir={}", paths.state_dir().display()))
        .arg("init")
        .env("ZEROPW_ADMIN_PASSPHRASE", "velvet-ocean-27-quartz-lantern")
        .env(
            "ZEROPW_RECOVERY_PASSPHRASE",
            "another-lantern-42-quartz-velvet",
        )
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );

    let port = free_port();
    let first = ServeSupervisor::new(&paths);
    let status = first
        .start(&ServeConfig {
            port,
            team_listen: None,
        })
        .unwrap();
    assert!(status.running);
    assert_eq!(status.url, Some(format!("http://127.0.0.1:{port}")));
    assert!(healthz(port, Duration::from_secs(2)).unwrap().is_zeropw());

    let second = ServeSupervisor::new(&paths);
    assert_eq!(second.attach().pid, status.pid);
    let started = Instant::now();
    assert!(!second.stop().running);
    assert!(
        started.elapsed() < Duration::from_secs(25),
        "SIGTERM was not honored"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while healthz(port, Duration::from_millis(500)).is_ok() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(healthz(port, Duration::from_millis(500)).is_err());
    assert!(!first.status().running);
    assert!(!paths.serve_pid_file().exists());
}

/// The real sidecar's own reason tells a taken gateway port from a team listener that cannot
/// open its address, and neither error carries the address.
#[test]
#[ignore = "needs ZEROPW_BIN_DIR with zeropw-admin"]
fn real_serve_says_which_address_it_could_not_open() {
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::new(dir.path().join("app"), bin_dir());
    zeropw_desktop_core::paths::ensure_private_dir(&paths.app_data_dir).unwrap();
    let init = Command::new(paths.admin_bin())
        .arg(format!("--state-dir={}", paths.state_dir().display()))
        .arg("init")
        .env("ZEROPW_ADMIN_PASSPHRASE", "velvet-ocean-27-quartz-lantern")
        .env(
            "ZEROPW_RECOVERY_PASSPHRASE",
            "another-lantern-42-quartz-velvet",
        )
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let sup = ServeSupervisor::new(&paths);

    let gateway = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = gateway.local_addr().unwrap().port();
    let e = sup
        .start(&ServeConfig {
            port,
            team_listen: None,
        })
        .unwrap_err();
    assert_eq!(
        (e.reason.as_str(), e.detail.as_deref()),
        ("listen_failed", Some("gateway_port")),
        "{e}"
    );

    let team = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let team_listen = team.local_addr().unwrap().to_string();
    let e = sup
        .start(&ServeConfig {
            port: free_port(),
            team_listen: Some(team_listen.clone()),
        })
        .unwrap_err();
    assert_eq!(
        (e.reason.as_str(), e.detail.as_deref()),
        ("team_invalid_listen_address", Some("team_listen")),
        "{e}"
    );
    assert!(!e.to_string().contains(&team_listen));
    assert!(!sup.status().running);
    assert!(!paths.serve_pid_file().exists());
    drop((gateway, team));
}

#[test]
#[ignore = "needs ZEROPW_BIN_DIR with a zeropw-admin that supports --input-envelope"]
fn init_project_secret_put_and_list_without_values() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = CoreConfig::new(AppPaths::new(dir.path().join("app"), bin_dir()));
    config.serve_stop_grace = Duration::from_secs(10);
    let core = Core::new(config, Arc::new(NoEvents));
    core.settings_set(Settings {
        gateway_port: free_port(),
        team_listen: None,
    })
    .unwrap();

    let code = core.recovery_generate().unwrap();
    let init = core
        .vault_init(VaultInitIn {
            admin_passphrase: "velvet-ocean-27-quartz-lantern".into(),
            recovery: RecoveryInput::Ref(code.reference),
        })
        .unwrap();
    assert!(!init.kms_key_id.is_empty());
    let status = core.app_status().unwrap();
    assert!(status.initialized);
    assert!(status.serve.running);
    assert_eq!(status.control.map(|c| c.stopped), Some(false));

    let project = core
        .project_create(ProjectCreateIn {
            name: "demo".into(),
            environments: vec!["dev".into()],
        })
        .unwrap();
    assert_eq!(project["name"], "demo");

    let value = "sk-synthetic-e2e-0123456789";
    core.secret_put(SecretPutIn {
        id: "api".into(),
        kind: SecretKind::ApiKey,
        project: "demo".into(),
        environment: "dev".into(),
        source: SecretSource::Typed(value.into()),
    })
    .unwrap();
    let list = core.secret_list(SecretListIn::default()).unwrap();
    let text = list.to_string();
    assert!(text.contains("\"api\""), "{text}");
    assert!(!text.contains(value), "secret list leaked the value");

    let revealed = core
        .secret_reveal(SecretRevealIn {
            id: "api".into(),
            version: None,
            admin_passphrase: "velvet-ocean-27-quartz-lantern".into(),
        })
        .unwrap();
    let shown = core
        .onetime_show(RefIn {
            reference: revealed.reference,
        })
        .ok()
        .unwrap();
    assert_eq!(shown.expose(), value);

    core.shutdown();
    assert!(!core.serve_status().running);
}

/// CORE-5 against the real CLI: `zeropw-admin init` keeps a code-shaped recovery passphrase
/// exactly as typed, so the app's canonical form fails once and the exact text then works.
/// A wrong code-shaped passphrase costs exactly two `auth_failed` records, never more.
#[test]
#[ignore = "needs ZEROPW_BIN_DIR with a zeropw-admin that supports --input-envelope"]
fn recover_reaches_a_vault_whose_code_was_typed_into_the_cli() {
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::new(dir.path().join("app"), bin_dir());
    zeropw_desktop_core::paths::ensure_private_dir(&paths.app_data_dir).unwrap();
    let typed = "abcd efgh ijkl mnop qrst uvw2";
    let init = Command::new(paths.admin_bin())
        .arg(format!("--state-dir={}", paths.state_dir().display()))
        .arg("init")
        .env("ZEROPW_ADMIN_PASSPHRASE", "velvet-ocean-27-quartz-lantern")
        .env("ZEROPW_RECOVERY_PASSPHRASE", typed)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let core = Core::new(CoreConfig::new(paths), Arc::new(NoEvents));
    let failures = |core: &Core| {
        core.audit_tail(LimitIn { limit: 1000 }).unwrap()["records"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["event"] == "auth_failed")
            .count()
    };

    let wrong = core
        .recover(RecoverIn {
            recovery_passphrase: "zzzz zzzz zzzz zzzz zzzz zzzz".into(),
        })
        .unwrap_err();
    assert_eq!(wrong.error, "AuthFailed");
    assert_eq!(failures(&core), 2);

    let out = core
        .recover(RecoverIn {
            recovery_passphrase: typed.into(),
        })
        .unwrap();
    assert!(out["kms_key_id"].is_string(), "{out}");
    assert_eq!(failures(&core), 3);
}

/// What the app sees of an open incident (2026-10-22 desktop run, F10 and F15): a declaration
/// the open incident takes in comes back marked `existing` and not `widened`, and contains no
/// one, while a wider one widens the same incident; a backup from before the incident, restored
/// while it is open, leaves resume refused.
#[test]
#[ignore = "needs ZEROPW_BIN_DIR with a zeropw-admin that supports --input-envelope"]
fn an_open_incident_takes_in_a_narrower_declaration_and_survives_a_restore() {
    const ADMIN: &str = "velvet-ocean-27-quartz-lantern";
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::new(dir.path().join("app"), bin_dir());
    zeropw_desktop_core::paths::ensure_private_dir(&paths.app_data_dir).unwrap();
    let init = Command::new(paths.admin_bin())
        .arg(format!("--state-dir={}", paths.state_dir().display()))
        .arg("init")
        .env("ZEROPW_ADMIN_PASSPHRASE", ADMIN)
        .env(
            "ZEROPW_RECOVERY_PASSPHRASE",
            "another-lantern-42-quartz-velvet",
        )
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let core = Core::new(CoreConfig::new(paths), Arc::new(NoEvents));
    for (id, runtime) in [("agent-a", "rt-a"), ("agent-b", "rt-b")] {
        core.principal_create(PrincipalCreateIn {
            id: id.into(),
            runtime: runtime.into(),
        })
        .unwrap();
    }
    let status = |id: &str| {
        core.principal_list().unwrap()["principals"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == id)
            .unwrap()["status"]
            .clone()
    };
    let archive = dir.path().join("before-incident.zpw");
    core.backup_create(&archive).unwrap();

    let declare = |scope, principal: Option<&str>, runtime: Option<&str>, pass: Option<&str>| {
        core.incident_declare(IncidentDeclareIn {
            scope,
            principal: principal.map(str::to_owned),
            runtime: runtime.map(str::to_owned),
            reason: None,
            admin_passphrase: pass.map(Into::into),
        })
        .unwrap()
    };
    let first = declare(IncidentScope::Runtime, None, Some("rt-a"), None);
    assert!(first.get("existing").is_none(), "{first}");
    let taken_in = declare(IncidentScope::Principal, Some("agent-b"), None, None);
    assert_eq!(
        (
            &taken_in["id"],
            &taken_in["scope"],
            &taken_in["existing"],
            &taken_in["widened"]
        ),
        (&first["id"], &"runtime".into(), &true.into(), &false.into()),
        "{taken_in}"
    );
    assert_eq!(status("agent-b"), "active");

    core.backup_restore(
        &archive,
        PassphraseIn {
            admin_passphrase: ADMIN.into(),
        },
    )
    .unwrap();
    core.restore_ack(PassphraseIn {
        admin_passphrase: ADMIN.into(),
    })
    .unwrap();
    assert!(core.control_get().unwrap().incident_open);
    assert_eq!(status("agent-a"), "disabled");
    let refused = core
        .resume(PassphraseIn {
            admin_passphrase: ADMIN.into(),
        })
        .unwrap_err();
    assert_eq!(
        (refused.error.as_str(), refused.reason.as_str()),
        ("InvalidInput", "incident_open")
    );

    let wider = declare(IncidentScope::All, None, None, Some(ADMIN));
    assert_eq!(
        (
            &wider["id"],
            &wider["scope"],
            &wider["existing"],
            &wider["widened"]
        ),
        (&first["id"], &"all".into(), &true.into(), &true.into()),
        "{wider}"
    );
    assert_eq!(status("agent-b"), "disabled");
}
