//! `.env` import through the core against the real binaries (docs/env-import.md §8; ignored
//! by default, `desktop/verify.sh` runs it): a file dropped on the window or picked natively
//! is read into the one-time store, previewed with names and key IDs only, imported with the
//! user's selection and then forgotten. Synthetic values only, temp state directory.
//!
//! ```text
//! cargo build --manifest-path rust/Cargo.toml --bins
//! ZEROPW_BIN_DIR=$CARGO_TARGET_DIR/debug \
//!   cargo test --manifest-path desktop/Cargo.toml --test e2e_env_import -- --ignored
//! ```
mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{Events, err};
use serde_json::Value;
use zeropw_desktop_core::commands::*;
use zeropw_desktop_core::{AppPaths, Core, CoreConfig, FilePurpose, Settings};

const OPENAI: &str = "sk-synthetic-import-openai-0123456789";
const OPENAI_V2: &str = "sk-synthetic-import-openai-rotated-01234";
const DB_PW: &str = "synthetic-import-db-pw-0123";

fn bin_dir() -> PathBuf {
    let bin = PathBuf::from(std::env::var_os("ZEROPW_BIN_DIR").expect("set ZEROPW_BIN_DIR"));
    assert!(
        bin.join("zeropw-admin").is_file(),
        "no zeropw-admin in ZEROPW_BIN_DIR"
    );
    bin
}

fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path
}

fn dropped(events: &Events) -> Value {
    events
        .named("envfile://dropped")
        .pop()
        .expect("no envfile://dropped event")
}

fn no_values(text: &str) {
    for value in [OPENAI, OPENAI_V2, DB_PW] {
        assert!(!text.contains(value), "a value reached the webview: {text}");
    }
}

fn preview(
    core: &Core,
    import_ref: &str,
    environment: &str,
) -> Result<ImportReport, zeropw_desktop_core::AppError> {
    core.secret_import_preview(SecretImportPreviewIn {
        import_ref: import_ref.into(),
        project: "demo".into(),
        environment: environment.into(),
        id_prefix: None,
    })
}

fn import(
    core: &Core,
    import_ref: &str,
    selected: &[&str],
    update: bool,
) -> Result<ImportReport, zeropw_desktop_core::AppError> {
    core.secret_import(SecretImportIn {
        import_ref: import_ref.into(),
        project: "demo".into(),
        environment: "dev".into(),
        id_prefix: None,
        selected: selected.iter().map(|s| (*s).to_owned()).collect(),
        update,
    })
}

fn action<'a>(report: &'a ImportReport, name: &str) -> &'a str {
    &report
        .entries
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("no entry {name}"))
        .action
}

#[test]
#[ignore = "needs ZEROPW_BIN_DIR with a zeropw-admin that has secret import"]
fn a_dropped_or_picked_env_file_is_previewed_and_imported_without_values_leaving_rust() {
    let dir = tempfile::tempdir().unwrap();
    let files = dir.path().join("files");
    std::fs::create_dir(&files).unwrap();
    let events = std::sync::Arc::new(Events::default());
    let mut config = CoreConfig::new(AppPaths::new(dir.path().join("app"), bin_dir()));
    config.serve_stop_grace = Duration::from_secs(10);
    let core = Core::new(config, events.clone());
    let env = write(
        &files,
        ".env",
        &format!(
            "# app\nexport OPENAI_API_KEY={OPENAI}\nPORT=3000\nNODE_ENV=development\nDATABASE_URL='postgres://app:{DB_PW}@db.example/app'\nEMPTY=\n"
        ),
    );

    // nothing is read before a vault exists
    core.env_file_drop(std::slice::from_ref(&env));
    assert_eq!(dropped(&events)["error"], "vault_missing");

    core.settings_set(Settings {
        gateway_port: common::free_port(),
        team_listen: None,
    })
    .unwrap();
    let code = core.recovery_generate().unwrap();
    core.vault_init(VaultInitIn {
        admin_passphrase: "velvet-ocean-27-quartz-lantern".into(),
        recovery: RecoveryInput::Ref(code.reference),
    })
    .unwrap();
    core.project_create(ProjectCreateIn {
        name: "demo".into(),
        environments: vec!["dev".into(), "prod".into()],
    })
    .unwrap();

    // a drop: the event carries a reference and the base name only
    core.env_file_drop(std::slice::from_ref(&env));
    let event = dropped(&events);
    no_values(&event.to_string());
    assert_eq!(event["name"], ".env");
    let import_ref = event["import_ref"].as_str().unwrap().to_owned();
    assert!(event.get("error").is_none());
    // the file never leaves through the one-time commands
    let shown = core.onetime_show(RefIn {
        reference: import_ref.clone(),
    });
    assert_eq!(err(shown).reason, "onetime_ref_unknown");

    let report = preview(&core, &import_ref, "dev").unwrap();
    no_values(&serde_json::to_string(&report).unwrap());
    assert!(!report.shared && report.dry_run);
    assert_eq!(report.empty_lines, vec![6]);
    let names: Vec<(&str, bool, &str)> = report
        .entries
        .iter()
        .map(|e| (e.name.as_str(), e.selected, e.why.as_str()))
        .collect();
    assert_eq!(
        names,
        [
            ("OPENAI_API_KEY", true, "secret_name"),
            ("PORT", false, "plain_value"),
            ("NODE_ENV", false, "no_hint"),
            ("DATABASE_URL", true, "url_password"),
        ]
    );
    assert!(report.entries.iter().all(|e| e.state == "new"));

    // the user's selection: PORT added, DATABASE_URL left out
    let out = import(&core, &import_ref, &["OPENAI_API_KEY", "PORT"], false).unwrap();
    no_values(&serde_json::to_string(&out).unwrap());
    assert!(!out.dry_run);
    assert_eq!(action(&out, "OPENAI_API_KEY"), "created");
    assert_eq!(action(&out, "PORT"), "created");
    assert!(out.entries.iter().any(|e| e.name == "PORT" && e.forced));
    assert_eq!(action(&out, "DATABASE_URL"), "skipped");
    let listed = core.secret_list(SecretListIn::default()).unwrap();
    let ids: Vec<&str> = listed["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["openai_api_key", "port"]);
    no_values(&listed.to_string());
    // an import forgets the file
    assert_eq!(
        err(preview(&core, &import_ref, "dev")).reason,
        "onetime_ref_unknown"
    );
    // and the file itself is left where it was
    assert!(env.exists());

    // a picked file: the token is single use and bound to its purpose
    let changed = write(&files, "next.env", &format!("OPENAI_API_KEY={OPENAI_V2}\n"));
    let other = core
        .files()
        .register(FilePurpose::Secret, &changed)
        .unwrap();
    let refused = core.env_file_load(FileTokenIn {
        file_token: other.file_token,
    });
    assert_eq!(err(refused).reason, "file_token_unknown");
    let pick = core
        .files()
        .register(FilePurpose::EnvFile, &changed)
        .unwrap();
    let loaded = core
        .env_file_load(FileTokenIn {
            file_token: pick.file_token.clone(),
        })
        .unwrap();
    assert_eq!(loaded.name, "next.env");
    let again = core.env_file_load(FileTokenIn {
        file_token: pick.file_token,
    });
    assert_eq!(err(again).reason, "file_token_unknown");

    // another value for an existing key: a conflict until update, then a new version
    let conflict = preview(&core, &loaded.import_ref, "dev").unwrap();
    assert_eq!(conflict.entries[0].state, "different");
    assert_eq!(
        err(import(
            &core,
            &loaded.import_ref,
            &["OPENAI_API_KEY"],
            false
        ))
        .reason,
        "import_conflict"
    );
    let elsewhere = preview(&core, &loaded.import_ref, "prod").unwrap();
    assert_eq!(elsewhere.entries[0].state, "elsewhere");
    let updated = import(&core, &loaded.import_ref, &["OPENAI_API_KEY"], true).unwrap();
    assert_eq!(action(&updated, "OPENAI_API_KEY"), "new_version");
    let versions = core
        .secret_versions(IdIn {
            id: "openai_api_key".into(),
        })
        .unwrap();
    assert_eq!(versions["active_version"], 2);

    // a selection naming something that is not an entry is refused before the CLI runs
    let third = write(&files, "third.env", &format!("NEW_TOKEN={OPENAI}-third\n"));
    core.env_file_drop(&[third]);
    let third_ref = dropped(&events)["import_ref"].as_str().unwrap().to_owned();
    assert_eq!(
        err(import(&core, &third_ref, &["NOT_IN_FILE"], false)).reason,
        "invalid_selection"
    );
    assert_eq!(
        err(import(&core, &third_ref, &["bad name"], false)).reason,
        "invalid_selection"
    );

    // drops the core does not read
    core.env_file_drop(&[env.clone(), changed.clone()]);
    assert_eq!(dropped(&events)["error"], "drop_one_file");
    core.env_file_drop(std::slice::from_ref(&files));
    assert_eq!(dropped(&events)["error"], "file_not_regular");
    let big = write(&files, "big.env", &"#".repeat(64 * 1024 + 1));
    core.env_file_drop(&[big]);
    assert_eq!(dropped(&events)["error"], "env_file_too_large");
    let empty = write(&files, "empty.env", "");
    core.env_file_drop(&[empty]);
    assert_eq!(dropped(&events)["error"], "env_file_empty");
    let latin = files.join("latin.env");
    std::fs::write(&latin, b"A=\xff\xfe\n").unwrap();
    core.env_file_drop(&[latin]);
    assert_eq!(dropped(&events)["error"], "env_file_not_utf8");

    // lines the parser refuses: line numbers and reasons, never the text
    let broken = write(&files, "broken.env", &format!("{OPENAI}\nKEY=a#b\n"));
    core.env_file_drop(&[broken]);
    let broken_ref = dropped(&events)["import_ref"].as_str().unwrap().to_owned();
    let invalid = err(preview(&core, &broken_ref, "dev"));
    assert_eq!(invalid.reason, "env_file_invalid");
    assert_eq!(
        invalid.detail.as_deref(),
        Some("1:not_assignment,2:unquoted_hash")
    );
    no_values(&serde_json::to_string(&invalid).unwrap());

    for (_, payload) in events.0.lock().unwrap().iter() {
        no_values(&payload.to_string());
    }
    core.shutdown();
}
