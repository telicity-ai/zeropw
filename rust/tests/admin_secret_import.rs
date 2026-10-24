//! `zeropw-admin secret import` in a personal environment
//! (docs/env-import.md §5–§7, stage 2 of §10): what a `.env` file creates,
//! leaves unchanged or refuses, all or nothing, with no value in any output,
//! error, audit record or state file.
mod native_e2e;

use std::path::Path;

use native_e2e::{Admin, events, find_secret, find_secret_in_tree};
use serde_json::{Value, json};

const OPENAI: &str = "synthetic-openai-0123456789";
const OPENAI_V2: &str = "synthetic-openai-rotated-0123456789";
const DB_PASSWORD: &str = "synthetic-db-pw-0123456789";
const CONN_KEY: &str = "synthetic-conn-key-0123456789";
/// A CLI setting the profile prints, so not `synthetic-…` (the sweep pattern).
const CLI_SHARED: &str = "cli-setting-value-0001";

struct Case {
    _tmp: tempfile::TempDir,
    admin: Admin,
}

impl Case {
    fn new() -> Case {
        let tmp = tempfile::TempDir::new().unwrap();
        let admin = Admin::new(tmp.path());
        admin.ok(&["init"]);
        admin.ok(&["project", "create", "demo"]);
        Case { _tmp: tmp, admin }
    }

    fn write_env(&self, name: &str, text: &str) -> String {
        let path = self.admin.root.join(name);
        std::fs::write(&path, text).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn import(&self, file: &str, extra: &[&str]) -> Value {
        let mut args = vec![
            "secret",
            "import",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--file",
            file,
        ];
        args.extend_from_slice(extra);
        self.admin.ok(&args)
    }

    fn import_fails(&self, file: &str, extra: &[&str]) -> Value {
        let mut args = vec![
            "secret",
            "import",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--file",
            file,
        ];
        args.extend_from_slice(extra);
        self.admin.fail(&args)
    }

    fn vault_doc(&self) -> Vec<u8> {
        std::fs::read(self.admin.state.join("vault/secrets.json")).unwrap()
    }

    fn reveal(&self, id: &str) -> String {
        self.admin.ok(&["secret", "reveal", "--id", id])["value"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn count(&self, event: &str) -> usize {
        events(&self.admin.state)
            .iter()
            .filter(|e| *e == event)
            .count()
    }
}

fn entry<'a>(out: &'a Value, name: &str) -> &'a Value {
    out["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == name)
        .unwrap_or_else(|| panic!("no entry {name}: {out}"))
}

fn strs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

fn env_text() -> String {
    format!(
        "# app settings\n\
         export OPENAI_API_KEY={OPENAI}\n\
         PORT=3000\n\
         NODE_ENV=development\n\
         DATABASE_URL='postgres://app:{DB_PASSWORD}@db.example:5432/app'\n\
         EMPTY=\n"
    )
}

/// No synthetic value in the state directory's plaintext files.
fn assert_state_clean(state: &Path) {
    let needles: Vec<Vec<u8>> = [OPENAI, OPENAI_V2, DB_PASSWORD, CONN_KEY]
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();
    assert_eq!(find_secret_in_tree(state, &needles), None);
}

#[test]
fn preview_then_import_creates_only_the_keys() {
    let case = Case::new();
    let file = case.write_env(".env", &env_text());
    let before = case.vault_doc();

    let preview = case.import(&file, &["--dry-run"]);
    assert_eq!(preview["dry_run"], true);
    assert_eq!(preview["shared"], false);
    assert_eq!(preview["empty_lines"], json!([6]));
    assert_eq!(preview["source_left_in_place"], true);
    let openai = entry(&preview, "OPENAI_API_KEY");
    assert_eq!(
        (openai["line"].clone(), openai["id"].clone()),
        (json!(2), json!("openai_api_key"))
    );
    assert_eq!(
        (openai["selected"].clone(), openai["why"].clone()),
        (json!(true), json!("secret_name"))
    );
    assert_eq!(openai["action"], "create");
    assert_eq!(openai["kind"], "env_var");
    assert_eq!(entry(&preview, "PORT")["why"], "plain_value");
    assert_eq!(entry(&preview, "PORT")["action"], "skip");
    // what turning it on would do
    assert_eq!(entry(&preview, "PORT")["state"], "new");
    assert_eq!(entry(&preview, "NODE_ENV")["why"], "no_hint");
    assert_eq!(entry(&preview, "DATABASE_URL")["why"], "url_password");
    // a preview writes nothing, not even an audit record
    assert_eq!(case.vault_doc(), before);
    assert_eq!(case.count("secret_import"), 0);

    let out = case.import(&file, &["--kind", "api_key"]);
    assert_eq!(out["dry_run"], false);
    assert_eq!(entry(&out, "OPENAI_API_KEY")["action"], "created");
    assert_eq!(entry(&out, "OPENAI_API_KEY")["version"], 1);
    assert_eq!(entry(&out, "DATABASE_URL")["action"], "created");
    assert_eq!(entry(&out, "PORT")["action"], "skipped");
    assert_eq!(entry(&out, "NODE_ENV")["action"], "skipped");
    let text = out.to_string();
    assert!(!text.contains("development") && !text.contains("3000"));
    assert_eq!(case.reveal("openai_api_key"), OPENAI);
    assert_eq!(
        case.reveal("database_url"),
        format!("postgres://app:{DB_PASSWORD}@db.example:5432/app")
    );
    let listed = case.admin.ok(&[
        "secret",
        "list",
        "--project",
        "demo",
        "--environment",
        "dev",
    ]);
    let ids: Vec<&str> = listed["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["database_url", "openai_api_key"]);
    assert_eq!(listed["secrets"][0]["kind"], "api_key");
    assert_eq!(case.count("secret_put"), 2);
    assert_eq!(case.count("secret_import"), 1);
    // the original file is left where it was
    assert!(Path::new(&file).exists());

    // a second run finds both unchanged and writes nothing
    let doc = case.vault_doc();
    let again = case.import(&file, &[]);
    assert_eq!(entry(&again, "OPENAI_API_KEY")["action"], "unchanged");
    assert_eq!(entry(&again, "DATABASE_URL")["action"], "unchanged");
    assert_eq!(case.vault_doc(), doc);
    assert_eq!(case.count("secret_put"), 2);
    assert_state_clean(&case.admin.state);
}

#[test]
fn a_changed_value_stops_the_import_until_update() {
    let case = Case::new();
    let file = case.write_env(".env", &env_text());
    case.import(&file, &[]);
    let changed = case.write_env(
        ".env.next",
        &format!("OPENAI_API_KEY={OPENAI_V2}\nNEW_TOKEN={DB_PASSWORD}-new\n"),
    );
    let doc = case.vault_doc();
    let puts = case.count("secret_put");

    let preview = case.import(&changed, &["--dry-run"]);
    assert_eq!(entry(&preview, "OPENAI_API_KEY")["action"], "conflict");
    assert_eq!(entry(&preview, "OPENAI_API_KEY")["state"], "different");
    let original = case.import(&file, &["--dry-run"]);
    assert_eq!(entry(&original, "OPENAI_API_KEY")["state"], "same");
    assert_eq!(entry(&preview, "NEW_TOKEN")["action"], "create");
    assert_eq!(
        case.import(&changed, &["--dry-run", "--update"])["entries"][0]["action"],
        "new_version"
    );

    let error = case.import_fails(&changed, &[]);
    assert_eq!(error["reason"], "import_conflict");
    assert_eq!(error["detail"], "openai_api_key");
    // all or nothing: the new key was not written either
    assert_eq!(case.vault_doc(), doc);
    assert_eq!(case.count("secret_put"), puts);

    let out = case.import(&changed, &["--update"]);
    assert_eq!(entry(&out, "OPENAI_API_KEY")["action"], "new_version");
    assert_eq!(entry(&out, "OPENAI_API_KEY")["version"], 2);
    assert_eq!(entry(&out, "NEW_TOKEN")["action"], "created");
    assert_eq!(case.reveal("openai_api_key"), OPENAI_V2);
    let versions = case
        .admin
        .ok(&["secret", "versions", "--id", "openai_api_key"]);
    assert_eq!(versions["active_version"], 2);
    assert_eq!(versions["versions"][0]["status"], "retired");
    // the key keeps the kind it was created with
    assert_eq!(versions["kind"], "env_var");
    assert_state_clean(&case.admin.state);
}

#[test]
fn ids_elsewhere_collisions_and_prefixes() {
    let case = Case::new();
    let file = case.write_env(".env", &format!("OPENAI_API_KEY={OPENAI}\n"));
    case.import(&file, &[]);
    let staging = |extra: &[&str]| -> Vec<String> {
        let mut args = vec![
            "secret",
            "import",
            "--project",
            "demo",
            "--environment",
            "staging",
            "--file",
            &file,
        ];
        args.extend_from_slice(extra);
        args.iter().map(|s| (*s).to_owned()).collect()
    };

    let preview = case.admin.ok(&strs(&staging(&["--dry-run"])));
    assert_eq!(preview["entries"][0]["action"], "id_taken");
    assert_eq!(preview["entries"][0]["state"], "elsewhere");
    let doc = case.vault_doc();
    let error = case.admin.fail(&strs(&staging(&[])));
    assert_eq!(error["reason"], "secret_identity_mismatch");
    assert_eq!(error["detail"], "openai_api_key");
    assert_eq!(case.vault_doc(), doc);

    let out = case.admin.ok(&strs(&staging(&["--id-prefix", "staging."])));
    assert_eq!(out["entries"][0]["id"], "staging.openai_api_key");
    assert_eq!(out["entries"][0]["action"], "created");
    assert_eq!(case.reveal("staging.openai_api_key"), OPENAI);
    let error = case.admin.fail(&strs(&staging(&["--id-prefix", "Bad"])));
    assert_eq!(error["reason"], "invalid_id_prefix");

    let both = case.write_env(
        ".env.case",
        &format!("Api_Token={OPENAI}\nAPI_TOKEN={DB_PASSWORD}\n"),
    );
    let error = case.import_fails(&both, &["--dry-run"]);
    assert_eq!(
        (error["reason"].clone(), error["detail"].clone()),
        (json!("id_collision"), json!("api_token"))
    );
}

#[test]
fn include_exclude_and_forced_entries() {
    let case = Case::new();
    let file = case.write_env(".env", &env_text());

    let error = case.import_fails(&file, &["--include", "PORT", "--exclude", "PORT"]);
    assert_eq!(error["reason"], "import_selection_conflict");
    let error = case.import_fails(&file, &["--include", "MISSING,EMPTY"]);
    assert_eq!(error["reason"], "import_name_unknown");
    assert_eq!(error["detail"], "2 name(s) are not entries with a value");

    let out = case.import(
        &file,
        &[
            "--include",
            "PORT",
            "--exclude",
            "OPENAI_API_KEY,DATABASE_URL",
        ],
    );
    assert_eq!(entry(&out, "PORT")["action"], "created");
    assert_eq!(entry(&out, "PORT")["forced"], true);
    assert_eq!(entry(&out, "OPENAI_API_KEY")["action"], "skipped");
    assert!(entry(&out, "OPENAI_API_KEY").get("forced").is_none());
    assert_eq!(case.reveal("port"), "3000");

    let none = case.write_env(".env.none", "NODE_ENV=development\nEMPTY=\n");
    let error = case.import_fails(&none, &[]);
    assert_eq!(error["reason"], "import_nothing_selected");
}

#[test]
fn a_cli_profile_carrying_a_value_refuses_the_whole_import() {
    let case = Case::new();
    case.admin
        .cmd(&[
            "secret",
            "put",
            "--id",
            "conn-key",
            "--kind",
            "api_key",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--stdin",
        ])
        .stdin(CONN_KEY.as_bytes())
        .ok();
    let setting = format!("prefix-{CLI_SHARED}-suffix");
    let cli_env = format!("SETTING={setting}");
    case.admin.ok(&[
        "connection",
        "create-http",
        "--id",
        "api",
        "--project",
        "demo",
        "--environment",
        "dev",
        "--service",
        "example",
        "--secret-id",
        "conn-key",
        "--target",
        "https://api.example.com",
        "--auth",
        "bearer",
        "--cli-program",
        "/bin/true",
        "--cli-env",
        &cli_env,
    ]);
    let file = case.write_env(
        ".env",
        &format!("OPENAI_API_KEY={OPENAI}\nOTHER_TOKEN={CLI_SHARED}\n"),
    );
    let preview = case.import(&file, &["--dry-run"]);
    assert_eq!(entry(&preview, "OTHER_TOKEN")["blocked_by"], "api");
    assert!(
        entry(&preview, "OPENAI_API_KEY")
            .get("blocked_by")
            .is_none()
    );

    let doc = case.vault_doc();
    let puts = case.count("secret_put");
    let error = case.import_fails(&file, &[]);
    assert_eq!(error["reason"], "cli_env_contains_credential");
    assert_eq!(error["detail"], "api:OTHER_TOKEN");
    assert_eq!(case.vault_doc(), doc);
    assert_eq!(case.count("secret_put"), puts);
    assert_eq!(case.count("secret_import"), 1);

    // leaving that entry out lets the rest through
    let out = case.import(&file, &["--exclude", "OTHER_TOKEN"]);
    assert_eq!(entry(&out, "OPENAI_API_KEY")["action"], "created");
    assert_eq!(case.count("secret_import"), 2);
}

#[test]
fn the_input_envelope_and_parse_errors_carry_no_value() {
    use base64::Engine;
    let case = Case::new();
    let text = format!("OPENAI_API_KEY={OPENAI}\n");
    let envelope = json!({
        "value_b64": base64::engine::general_purpose::STANDARD.encode(text.as_bytes()),
    });
    let out = case
        .admin
        .cmd(&[
            "--input-envelope",
            "secret",
            "import",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--stdin",
        ])
        .stdin(envelope.to_string().as_bytes())
        .ok();
    assert_eq!(out["entries"][0]["action"], "created");
    assert!(out.get("source_left_in_place").is_none());
    assert_eq!(case.reveal("openai_api_key"), OPENAI);

    // a token pasted without `=`, a `$`, an attached `#`: line numbers only
    let broken = format!("{DB_PASSWORD}\nTOKEN=${{{DB_PASSWORD}}}\nKEY={DB_PASSWORD}#x\n");
    let (code, stdout, stderr) = case
        .admin
        .cmd(&[
            "secret",
            "import",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--stdin",
        ])
        .stdin(broken.as_bytes())
        .run();
    assert_eq!(code, 1);
    assert_eq!(stdout, "");
    let error: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(error["reason"], "env_file_invalid");
    assert_eq!(
        error["detail"],
        "1:not_assignment,2:dollar_needs_single_quotes,3:unquoted_hash"
    );
    let needles = [DB_PASSWORD.as_bytes().to_vec()];
    assert_eq!(find_secret(stderr.as_bytes(), &needles), None);

    let big = "#".repeat(64 * 1024 + 1);
    let error = case
        .admin
        .cmd(&[
            "secret",
            "import",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--stdin",
        ])
        .stdin(big.as_bytes())
        .fail(1);
    assert_eq!(error["reason"], "env_file_too_large");
    let audit = std::fs::read(case.admin.state.join("audit/audit.jsonl")).unwrap();
    let needles = [OPENAI.as_bytes().to_vec(), DB_PASSWORD.as_bytes().to_vec()];
    assert_eq!(find_secret(&audit, &needles), None);
    assert_state_clean(&case.admin.state);
}
