//! The native administrator CLI (`zeropw-admin`) as a separate process:
//! port of the second half of `tests/test_admin_cli.py`'s
//! `AdminCliTestCase` (audit output, the admin-round-0 verification
//! findings, serve listen validation and smoke, restore and the save-time
//! CLI environment checks), formerly run against the native binary through
//! `rust/tests/native_cli_e2e.py` (`native_admin_contract`).
//!
//! Every test keeps the original scenario and assertions. State the Python
//! test read or changed in-process is read or changed through the Rust
//! library (`zeropw::context::Context`). Every command's output is swept on
//! drop: no synthetic value, private-key line or PEM marker may appear
//! anywhere except on `secret reveal` stdout. Hand-edited, semantically
//! corrupt state and non-ASCII TTL digits only have to fail closed; the
//! CPython exception names the original reported as detail are not kept.
mod native_e2e;

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use native_e2e::{ADMIN_PASSPHRASE, Admin, DEMOCLI_BIN, RECOVERY_PASSPHRASE, Serve};
use serde_json::{Value, json};
use zeropw::context::{Config, Context};
use zeropw::policy::{Action, approval_digest};
use zeropw::sshwire::{Ed25519PrivateKey, generate_ed25519_private_key, parse_authorized_key};

const SYNTHETIC: &str = "synthetic-token-0123456789";
const SYNTHETIC_V2: &str = "synthetic-token-rotated-v2";

/// The `AdminCliTestCase` fixture: a temporary root with `state/`, the
/// administrator CLI recording every output, and a fresh SSH user key plus a
/// host key line.
struct Case {
    admin: Admin,
    ssh_key: Ed25519PrivateKey,
    ssh_pem: String,
    host_key: String,
    _tmp: tempfile::TempDir,
}

impl Case {
    fn new() -> Case {
        let tmp = tempfile::TempDir::new().unwrap();
        let admin = Admin::new(tmp.path());
        let ssh_key = generate_ed25519_private_key("demo");
        let ssh_pem = ssh_key.to_openssh_private_key();
        let host_key = generate_ed25519_private_key("host")
            .public
            .to_authorized_key("host")
            .unwrap();
        let case = Case {
            admin,
            ssh_key,
            ssh_pem,
            host_key,
            _tmp: tmp,
        };
        case.admin.add_needle(&case.private_line());
        case
    }

    fn root(&self) -> &Path {
        &self.admin.root
    }

    fn state(&self) -> &Path {
        &self.admin.state
    }

    /// The second line of the PEM (the first line of key material).
    fn private_line(&self) -> String {
        self.ssh_pem.lines().nth(1).unwrap().to_owned()
    }

    fn ok(&self, args: &[&str]) -> Value {
        self.admin.ok(args)
    }

    fn ok_stdin(&self, args: &[&str], stdin: &[u8]) -> Value {
        self.admin.cmd(args).stdin(stdin).ok()
    }

    fn fail(&self, args: &[&str]) -> Value {
        self.admin.fail(args)
    }

    fn fail_code(&self, args: &[&str], code: i32) -> Value {
        self.admin.cmd(args).fail(code)
    }

    fn fail_stdin(&self, args: &[&str], stdin: &[u8], code: i32) -> Value {
        self.admin.cmd(args).stdin(stdin).fail(code)
    }

    fn init(&self) -> Value {
        self.ok(&["init"])
    }

    fn seed_project(&self) {
        self.init();
        self.ok(&["project", "create", "demo"]);
    }

    fn put_secret_as(&self, value: &str, secret_id: &str, environment: &str) -> Value {
        self.ok_stdin(
            &[
                "secret",
                "put",
                "--id",
                secret_id,
                "--kind",
                "api_key",
                "--project",
                "demo",
                "--environment",
                environment,
                "--stdin",
            ],
            format!("{value}\n").as_bytes(),
        )
    }

    fn put_secret(&self) -> Value {
        self.put_secret_as(SYNTHETIC, "gh-token", "dev")
    }

    fn put_ssh_key(&self, staged: bool) -> Value {
        let mut args = vec![
            "secret",
            "put",
            "--id",
            "box-key",
            "--kind",
            "ssh_private_key",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--stdin",
        ];
        if staged {
            args.push("--staged");
        }
        self.ok_stdin(&args, self.ssh_pem.as_bytes())
    }

    fn create_http(&self, cid: &str, extra: &[&str]) -> Value {
        let mut args = vec![
            "connection",
            "create-http",
            "--id",
            cid,
            "--project",
            "demo",
            "--environment",
            "dev",
            "--service",
            "fake-github",
            "--secret-id",
            "gh-token",
            "--target",
            "http://127.0.0.1:8080",
            "--auth",
            "bearer",
            "--methods",
            "GET,POST",
            "--path-prefixes",
            "/repos,/me",
            "--confirm-methods",
            "DELETE",
        ];
        args.extend_from_slice(extra);
        self.ok(&args)
    }

    fn ctx(&self) -> Context {
        open_ctx(self.state())
    }

    fn events(&self) -> Vec<String> {
        native_e2e::events(self.state())
    }

    fn path_arg(path: &Path) -> String {
        path.to_string_lossy().into_owned()
    }
}

fn open_ctx(state: &Path) -> Context {
    Context::open(state, Config::default(), zeropw::clock::system()).unwrap()
}

fn get_http(path: &str) -> Action {
    Action::http("GET", path)
}

fn array(value: &Value) -> &Vec<Value> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("not an array: {value}"))
}

fn keys(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("not an object: {value}"))
        .keys()
        .cloned()
        .collect()
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

/// Every regular file under `root`.
fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                files.push(entry.path());
            }
        }
    }
    files
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ------------------------------------------------------------ audit output

#[test]
fn audit_tail_and_alerts_are_json() {
    let t = Case::new();
    t.seed_project();
    t.put_secret();
    let tail = t.ok(&["audit", "tail", "--limit", "2"])["records"].clone();
    let tail = array(&tail);
    assert_eq!(tail.len(), 2);
    let last = tail.last().unwrap();
    assert_eq!(last["event"], "secret_put");
    let fields = keys(last);
    for field in ["ts", "event", "caller", "result"] {
        assert!(fields.contains(field), "{field} missing from {last}");
    }
    assert_eq!(t.ok(&["alerts", "--limit", "5"])["alerts"], json!([]));
    t.ok(&["secret", "reveal", "--id", "gh-token"]);
    let alerts = t.ok(&["alerts"])["alerts"].clone();
    assert_eq!(array(&alerts).last().unwrap()["alert"], "secret_reveal");
}

// ------------------------------------- verification findings (admin round 0)

/// admin-argv-abbrev-echo / ADM-8: `--value` is not an abbreviation of
/// `--value-file`, and no value given on argv is ever echoed.
#[test]
fn secret_value_on_argv_is_a_usage_error_and_never_echoed() {
    let t = Case::new();
    t.seed_project();
    t.put_secret();
    let base = [
        "secret",
        "put",
        "--id",
        "x",
        "--kind",
        "api_key",
        "--project",
        "demo",
        "--environment",
        "dev",
    ];
    let value_eq = format!("--value={SYNTHETIC}");
    let dash = format!("-{SYNTHETIC}");
    let double_dash = format!("--{SYNTHETIC}=1");
    let cases: Vec<Vec<&str>> = vec![
        vec!["--value", SYNTHETIC],
        vec!["--val", SYNTHETIC],
        vec![value_eq.as_str()],
        vec!["--stdin", "--value", SYNTHETIC],
        vec!["--stdin", value_eq.as_str()],
        vec!["--stdin", "--value", dash.as_str()], // a value that itself looks like a flag
        vec!["--stdin", "--value", double_dash.as_str()],
        vec!["--stdin", "--bogus", SYNTHETIC],
        vec!["--stdin", SYNTHETIC],
    ];
    for extra in &cases {
        let argv = [base.as_slice(), extra.as_slice()].concat();
        let error = t.fail_stdin(&argv, b"synthetic-other\n", 2);
        assert_eq!(
            (error["error"].as_str(), error["reason"].as_str()),
            (Some("UsageError"), Some("usage")),
            "{extra:?}"
        );
        assert!(!error.to_string().contains(SYNTHETIC), "{extra:?}");
    }
    // The mistyped option is named; the stray value never is, even when it
    // starts with "-".
    for extra in [
        vec!["--stdin", "--value", SYNTHETIC],
        vec!["--stdin", "--value", dash.as_str()],
        vec!["--stdin", "--value", double_dash.as_str()],
    ] {
        let argv = [base.as_slice(), extra.as_slice()].concat();
        let error = t.fail_stdin(&argv, b"synthetic-other\n", 2);
        assert_eq!(
            error["detail"],
            "unrecognized arguments: 2 (not accepted: --value); values are not echoed",
            "{extra:?}"
        );
    }
    let argv = [base.as_slice(), &["--stdin", "--bogus", SYNTHETIC]].concat();
    let error = t.fail_stdin(&argv, b"synthetic-other\n", 2);
    assert_eq!(
        error["detail"],
        "unrecognized arguments: 2; values are not echoed"
    );
    // An option of another subcommand.
    let error = t.fail_code(&["project", "list", "--id", SYNTHETIC], 2);
    assert_eq!(
        error["detail"],
        "unrecognized arguments: 2 (not accepted: --id); values are not echoed"
    );
    assert_eq!(
        t.fail_code(
            &[
                "rotation",
                "start",
                "--secret-id",
                "gh-token",
                "--value",
                SYNTHETIC
            ],
            2
        )["reason"],
        "usage"
    );
    assert_eq!(
        t.fail_stdin(
            &[
                "rotation",
                "start",
                "--secret-id",
                "gh-token",
                "--stdin",
                "--val",
                &dash
            ],
            b"synthetic-other\n",
            2
        )["detail"],
        "unrecognized arguments: 2 (not accepted: --val); values are not echoed"
    );
    // Nothing reached the vault from any of those attempts.
    let versions = t.ok(&["secret", "versions", "--id", "gh-token"])["versions"].clone();
    let numbers: Vec<&Value> = array(&versions).iter().map(|v| &v["version"]).collect();
    assert_eq!(numbers, [&json!(1)]);
    assert_eq!(
        t.fail(&["secret", "versions", "--id", "x"])["reason"],
        "secret_not_found"
    );
    // A missing --value-file is reported without the path: it could be a
    // value typed by mistake.
    let missing = Case::path_arg(&t.root().join(SYNTHETIC));
    let argv = [base.as_slice(), &["--value-file", missing.as_str()]].concat();
    assert_eq!(
        t.fail(&argv),
        json!({"error": "FileNotFoundError", "reason": "file_not_found"})
    );
    assert_eq!(
        t.fail(&[
            "rotation",
            "start",
            "--secret-id",
            "gh-token",
            "--value-file",
            &missing
        ]),
        json!({"error": "FileNotFoundError", "reason": "file_not_found"})
    );
    // (The original's introspection of argparse's `allow_abbrev` flags is
    // Python-internal; the `--val` cases above check the behaviour.) The
    // drop sweep checks every captured stdout/stderr for the values.
}

/// secret-listing-hash-length-oracle: non-SSH kinds expose `public == {}`,
/// on the CLI and on disk.
#[test]
fn secret_listings_carry_no_value_derived_metadata() {
    let t = Case::new();
    t.seed_project();
    for (secret_id, kind, value) in [
        ("gh-token", "api_key", SYNTHETIC),
        ("db-pass", "password", "synthetic-pw"),
        ("env", "env_var", "synthetic-env"),
    ] {
        t.ok_stdin(
            &[
                "secret",
                "put",
                "--id",
                secret_id,
                "--kind",
                kind,
                "--project",
                "demo",
                "--environment",
                "dev",
                "--stdin",
            ],
            value.as_bytes(),
        );
    }
    t.ok_stdin(
        &["rotation", "start", "--secret-id", "gh-token", "--stdin"],
        SYNTHETIC_V2.as_bytes(),
    );
    let listing = t.ok(&["secret", "list"]);
    let ids: Vec<&str> = array(&listing["secrets"])
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["db-pass", "env", "gh-token"]);
    for secret in array(&listing["secrets"]) {
        for version in array(&secret["versions"]) {
            assert_eq!(version["public"], json!({}), "{}", secret["id"]);
        }
    }
    let versions = t.ok(&["secret", "versions", "--id", "gh-token"]);
    let publics: Vec<&Value> = array(&versions["versions"])
        .iter()
        .map(|v| &v["public"])
        .collect();
    assert_eq!(publics, [&json!({}), &json!({})]);
    for text in [listing.to_string(), versions.to_string()] {
        for needle in ["sha256_prefix", "length", "sha256", "ciphertext", "nonce"] {
            assert!(!text.contains(needle), "{needle} in {text}");
        }
    }
    // Nothing derived from a value is persisted either (it would end up in
    // every backup archive).
    let doc: Value = serde_json::from_str(
        &std::fs::read_to_string(t.state().join("vault/secrets.json")).unwrap(),
    )
    .unwrap();
    for entry in doc["secrets"].as_object().unwrap().values() {
        for record in entry["versions"].as_object().unwrap().values() {
            assert_eq!(record["public"], json!({}));
        }
    }
    let archive = t.root().join("backup.json");
    t.ok(&["backup", "--out", &Case::path_arg(&archive)]);
    assert!(
        !std::fs::read_to_string(&archive)
            .unwrap()
            .contains("sha256_prefix")
    );
    // SSH keys keep their genuinely public material and nothing else.
    t.put_ssh_key(false);
    let versions = t.ok(&["secret", "versions", "--id", "box-key"]);
    let ssh = &versions["versions"][0]["public"];
    assert_eq!(
        keys(ssh),
        BTreeSet::from(["public_key", "fingerprint", "algorithm"].map(String::from))
    );
    assert_eq!(ssh["fingerprint"], t.ssh_key.public.fingerprint());
    assert_eq!(
        ssh["public_key"],
        t.ssh_key.public.to_authorized_key("demo").unwrap()
    );
}

/// ADM-2: a pinned version must be active/staged; an unpinned connection
/// needs an active version.
#[test]
fn connection_create_requires_a_usable_secret_version() {
    let t = Case::new();
    t.seed_project();
    t.put_secret();
    let put_staged = [
        "secret",
        "put",
        "--id",
        "gh-token",
        "--kind",
        "api_key",
        "--project",
        "demo",
        "--environment",
        "dev",
        "--stdin",
        "--staged",
    ];
    t.ok_stdin(&put_staged, SYNTHETIC_V2.as_bytes());
    t.ok(&["secret", "retire", "--id", "gh-token", "--version", "2"]);
    let base = [
        "connection",
        "create-http",
        "--project",
        "demo",
        "--environment",
        "dev",
        "--service",
        "svc",
        "--secret-id",
        "gh-token",
        "--target",
        "http://127.0.0.1:1",
        "--auth",
        "bearer",
    ];
    let with = |extra: &[&'static str]| -> Vec<&'static str> { [base.as_slice(), extra].concat() };
    let error = t.fail(&with(&["--id", "pin-retired", "--secret-version", "2"]));
    assert_eq!(
        (&error["error"], &error["reason"], &error["detail"]),
        (
            &json!("InvalidInput"),
            &json!("secret_version_unusable"),
            &json!("retired")
        )
    );
    // The active version: active_version -> None.
    t.ok(&["secret", "revoke", "--id", "gh-token", "--version", "1"]);
    let error = t.fail(&with(&["--id", "pin-revoked", "--secret-version", "1"]));
    assert_eq!(
        (&error["reason"], &error["detail"]),
        (&json!("secret_version_unusable"), &json!("revoked"))
    );
    let error = t.fail(&with(&["--id", "unpinned"]));
    assert_eq!(
        (&error["error"], &error["reason"]),
        (&json!("NotFound"), &json!("secret_no_active_version"))
    );
    assert_eq!(
        t.fail(&with(&["--id", "pin-missing", "--secret-version", "9"]))["reason"],
        "secret_version_not_found"
    );
    assert_eq!(t.ok(&["connection", "list"])["connections"], json!([]));
    assert!(!t.events().iter().any(|e| e == "connection_create"));
    // A staged version is usable when pinned (rotation), an active one when
    // unpinned.
    t.ok_stdin(&put_staged, b"synthetic-v3");
    assert_eq!(
        t.ok(&with(&["--id", "pin-staged", "--secret-version", "3"]))["secret_version"],
        3
    );
    assert_eq!(
        t.fail(&with(&["--id", "still-unpinned"]))["reason"],
        "secret_no_active_version"
    );
    t.ok_stdin(&put_staged[..11], b"synthetic-v4");
    assert!(t.ok(&with(&["--id", "unpinned"]))["secret_version"].is_null());
    // SSH connections go through the same check.
    t.put_ssh_key(true);
    let ssh = [
        "connection",
        "create-ssh",
        "--project",
        "demo",
        "--environment",
        "dev",
        "--service",
        "s",
        "--secret-id",
        "box-key",
        "--host",
        "127.0.0.1",
        "--username",
        "deploy",
        "--host-key",
        t.host_key.as_str(),
    ];
    assert_eq!(
        t.fail(&[ssh.as_slice(), &["--id", "box"]].concat())["reason"],
        "secret_no_active_version"
    );
    assert_eq!(
        t.ok(&[ssh.as_slice(), &["--id", "box", "--secret-version", "1"]].concat())["secret_version"],
        1
    );
}

/// ADM-3: malformed bracketed hosts are a fixed reason code, not
/// internal_error.
#[test]
fn connection_target_malformed_bracket_hosts_are_invalid_host() {
    let t = Case::new();
    t.seed_project();
    t.put_secret();
    let base = [
        "connection",
        "create-http",
        "--id",
        "a",
        "--project",
        "demo",
        "--environment",
        "dev",
        "--service",
        "svc",
        "--secret-id",
        "gh-token",
        "--auth",
        "bearer",
        "--target",
    ];
    let with =
        |target: &'static str| -> Vec<&'static str> { [base.as_slice(), &[target]].concat() };
    for target in [
        "http://[::1",
        "http://[evil]:80",
        "http://[evil]",
        "http://[",
        "http://][",
        "http://",
        "http:",
    ] {
        let error = t.fail(&with(target));
        assert_eq!(
            (&error["error"], &error["reason"]),
            (&json!("InvalidInput"), &json!("invalid_host")),
            "{target}"
        );
    }
    for target in [
        "http://127.0.0.1:99999",
        "http://127.0.0.1:0x50",
        "http://127.0.0.1:-1",
    ] {
        let error = t.fail(&with(target));
        assert_eq!(
            (&error["error"], &error["reason"]),
            (&json!("InvalidInput"), &json!("invalid_port")),
            "{target}"
        );
    }
    assert_eq!(
        t.fail(&with("http://user:pw@127.0.0.1"))["reason"],
        "target_must_be_origin"
    );
    assert_eq!(t.ok(&["connection", "list"])["connections"], json!([]));
    // A well-formed IPv6 literal is a valid target.
    let created = t.ok(&with("http://[::1]:8080"));
    assert_eq!(
        (
            &created["http_target"]["host"],
            &created["http_target"]["port"]
        ),
        (&json!("::1"), &json!(8080))
    );
}

/// ADM-4: only ASCII digits form a TTL; Unicode digit-class characters are
/// invalid. The original's direct `_parse_ttl` calls are checked through
/// `grant create` and the stored expiry.
#[test]
fn grant_ttl_rejects_non_ascii_digits() {
    let t = Case::new();
    t.seed_project();
    t.put_secret();
    t.create_http("gh", &[]);
    t.ok(&["principal", "create", "--id", "agent-1"]);
    for ttl in [
        "²", "٣٠m", "①h", "1³m", "１０m", "", " ", "30 m", "1.5h", "+30m", "0", "0m", "1x", "m",
    ] {
        let error = t.fail(&[
            "grant",
            "create",
            "--principal",
            "agent-1",
            "--connection",
            "gh",
            "--ttl",
            ttl,
        ]);
        assert_eq!(
            (&error["error"], &error["reason"]),
            (&json!("InvalidInput"), &json!("invalid_ttl")),
            "{ttl:?}"
        );
    }
    assert_eq!(t.ok(&["grant", "list"])["grants"], json!([]));
    for (ttl, seconds) in [(" 45S ", 45.0), ("2d", 172_800.0), ("90", 90.0)] {
        let before = now();
        let grant = t.ok(&[
            "grant",
            "create",
            "--principal",
            "agent-1",
            "--connection",
            "gh",
            "--ttl",
            ttl,
        ]);
        let after = now();
        let stored = t
            .ctx()
            .policy
            .get_grant(grant["id"].as_str().unwrap())
            .unwrap();
        let expires = stored.expires_at.unwrap();
        assert!(
            before + seconds - 1.0 <= expires && expires <= after + seconds + 1.0,
            "{ttl:?}: expires_at {expires} not {seconds}s after [{before}, {after}]"
        );
    }
}

/// ADM-5: tab-separated, padded or options-prefixed authorized_keys lines
/// are normalised.
#[test]
fn ssh_host_keys_are_stored_in_canonical_form() {
    let t = Case::new();
    t.seed_project();
    t.put_ssh_key(false);
    let public = generate_ed25519_private_key("h").public;
    let bare = public.to_authorized_key("").unwrap();
    let b64 = bare.split_whitespace().nth(1).unwrap().to_owned();
    let canonical = public.to_authorized_key("myhost").unwrap();
    let lines = [
        format!("ssh-ed25519\t{b64}\tmyhost"),
        format!("no-port-forwarding,command=\"/bin/true\" ssh-ed25519 {b64} myhost"),
        format!("  ssh-ed25519  {b64}   myhost  "),
        format!("ssh-ed25519 {b64}"),
    ];
    let mut argv = vec![
        "connection",
        "create-ssh",
        "--project",
        "demo",
        "--environment",
        "dev",
        "--service",
        "s",
        "--secret-id",
        "box-key",
        "--host",
        "127.0.0.1",
        "--port",
        "2222",
        "--username",
        "deploy",
    ];
    for line in &lines {
        argv.extend(["--host-key", line.as_str()]);
    }
    let created = t.ok(&[argv.as_slice(), &["--id", "box"]].concat());
    assert_eq!(
        created["ssh_target"]["host_keys"],
        json!([canonical, canonical, canonical, bare])
    );
    let connection = t.ctx().policy.get_connection("box").unwrap();
    for stored in &connection.ssh_target.as_ref().unwrap().host_keys {
        assert!(stored.starts_with("ssh-ed25519 "), "{stored}");
        assert!(!stored.contains('\t'), "{stored}");
        assert_eq!(
            parse_authorized_key(stored).unwrap().key_bytes(),
            public.key_bytes()
        );
    }
    // known_hosts markers are not host keys, and a comment line is not a key.
    for bad in [
        format!("@revoked ssh-ed25519 {b64}"),
        format!("@cert-authority ssh-ed25519 {b64}"),
        format!("# ssh-ed25519 {b64}"),
    ] {
        let args = [
            argv.as_slice(),
            &["--id", "bad", "--host-key", bad.as_str()],
        ]
        .concat();
        assert_eq!(t.fail(&args)["reason"], "invalid_host_key", "{bad}");
    }
    let ids: Vec<Value> = array(&t.ok(&["connection", "list"])["connections"])
        .iter()
        .map(|c| c["id"].clone())
        .collect();
    assert_eq!(ids, [json!("box")]);
}

/// ADM-6: --limit must be >= 1 (usage error) and one bad line does not hide
/// the log.
#[test]
fn audit_limit_validation_and_unparseable_lines() {
    let t = Case::new();
    t.seed_project();
    t.put_secret();
    for argv in [
        ["audit", "tail", "--limit", "0"].as_slice(),
        &["audit", "tail", "--limit", "-1"],
        &["alerts", "--limit", "0"],
        &["alerts", "--limit", "-5"],
        &["audit", "tail", "--limit", "x"],
        &["audit", "tail", "--limit", "1.5"],
    ] {
        assert_eq!(t.fail_code(argv, 2)["reason"], "usage", "{argv:?}");
    }
    let before = t.ok(&["audit", "tail", "--limit", "500"]);
    assert_eq!(before["unparseable_lines"], 0);
    let total = array(&before["records"]).len();
    assert_eq!(
        array(&t.ok(&["audit", "tail", "--limit", "1"])["records"]).len(),
        1
    );
    let mut stream = std::fs::OpenOptions::new()
        .append(true)
        .open(t.state().join("audit/audit.jsonl"))
        .unwrap();
    stream
        .write_all(b"{\"event\": \"secret_put\", \"truncated\n[1, 2, 3]\n")
        .unwrap();
    drop(stream);
    let tail = t.ok(&["audit", "tail", "--limit", "2"]);
    assert_eq!(array(&tail["records"]).len(), 2);
    assert_eq!(
        array(&tail["records"]).last().unwrap()["event"],
        "secret_put"
    );
    assert_eq!(tail["unparseable_lines"], 2);
    assert_eq!(
        array(&t.ok(&["audit", "tail", "--limit", "500"])["records"]).len(),
        total
    );
    std::fs::write(t.state().join("audit/alerts.jsonl"), "not json\n").unwrap();
    assert_eq!(
        t.ok(&["alerts"]),
        json!({"alerts": [], "unparseable_lines": 1})
    );
}

/// ADM-7: the server is IPv4 only, so IPv6 loopback is an explicit
/// unsupported error.
#[test]
fn serve_refuses_ipv6_loopback_explicitly() {
    let t = Case::new();
    t.init();
    for listen in ["[::1]:0", "::1:0", "[0:0:0:0:0:0:0:1]:0"] {
        let error = t.fail(&["serve", "--listen", listen]);
        assert_eq!(
            (&error["error"], &error["reason"]),
            (&json!("Unsupported"), &json!("listen_ipv6_unsupported")),
            "{listen}"
        );
    }
    assert_eq!(
        t.fail(&["serve", "--listen", "[::]:0"])["reason"],
        "listen_not_loopback"
    );
    assert_eq!(
        t.fail(&["serve", "--listen", "[fe80::1]:0"])["reason"],
        "listen_not_loopback"
    );
}

/// ADM-9: valid JSON with missing or mistyped fields fails closed with a
/// `state_corrupt` StateError, never an internal error or a value. (The
/// original also pinned the CPython exception class name in `detail`; that
/// is interpreter detail, not kept.)
#[test]
fn semantically_corrupt_state_reports_state_corrupt() {
    let t = Case::new();
    t.seed_project();
    t.put_secret();
    t.create_http("gh", &[]);
    t.ok(&["principal", "create", "--id", "agent-1"]);
    let grant = t.ok(&[
        "grant",
        "create",
        "--principal",
        "agent-1",
        "--connection",
        "gh",
    ]);
    let grant_id = grant["id"].as_str().unwrap().to_owned();
    t.ok(&["stop-all"]);
    t.ok(&["resume"]); // materialises policy/control.json
    let secrets: Value = serde_json::from_str(
        &std::fs::read_to_string(t.state().join("vault/secrets.json")).unwrap(),
    )
    .unwrap();
    let dek = secrets["dek"].clone();
    let cases: Vec<(&str, Value, Vec<&str>)> = vec![
        (
            "policy/grants.json",
            json!({"g-bogus": {"foo": "bar"}}),
            vec!["grant", "list"],
        ),
        (
            "policy/grants.json",
            json!({grant_id.clone(): {"id": grant_id.clone()}}),
            vec!["grant", "revoke", "--id", grant_id.as_str()],
        ),
        (
            "policy/grants.json",
            json!({grant_id.clone(): "not-a-dict"}),
            vec!["grant", "list"],
        ),
        (
            "policy/connections.json",
            json!({"gh": {"id": "gh", "kind": "http"}}),
            vec!["connection", "show", "--id", "gh"],
        ),
        (
            "policy/connections.json",
            json!({"gh": "not-a-dict"}),
            vec!["connection", "list"],
        ),
        (
            "policy/connections.json",
            json!({"gh": {"id": "gh", "kind": "http"}}),
            vec![
                "grant",
                "create",
                "--principal",
                "agent-1",
                "--connection",
                "gh",
            ],
        ),
        (
            "policy/principals.json",
            json!({"agent-1": {"status": "active"}}),
            vec!["principal", "list"],
        ),
        (
            "policy/principals.json",
            json!({"agent-1": 5}),
            vec!["principal", "list"],
        ),
        (
            "policy/control.json",
            json!({"stopped": false, "restore_pending": false, "approvals": "nope"}),
            vec!["approvals", "list"],
        ),
        ("policy/control.json", json!([1, 2]), vec!["stop-all"]),
        (
            "vault/secrets.json",
            json!({"dek": dek, "secrets": {"gh-token": {"project": "demo"}}}),
            vec!["secret", "list"],
        ),
        (
            "vault/secrets.json",
            json!({"dek": dek, "secrets": {"gh-token": {
                "project": "demo", "environment": "dev", "kind": "api_key", "active_version": 1,
                "versions": {"1": {"status": "active"}}}}}),
            vec!["secret", "versions", "--id", "gh-token"],
        ),
        (
            "vault/secrets.json",
            json!({"dek": dek, "secrets": "x"}),
            vec!["secret", "list"],
        ),
        (
            "vault/secrets.json",
            json!({"secrets": {}}),
            vec!["secret", "list"],
        ),
        (
            "projects.json",
            json!({"demo": "oops"}),
            vec!["project", "list"],
        ),
        (
            "projects.json",
            json!({"demo": {"name": "demo"}}),
            vec!["project", "list"],
        ),
        (
            "admin.json",
            json!({"salt": "AAAA"}),
            vec!["secret", "reveal", "--id", "gh-token"],
        ),
    ];
    for (name, doc, argv) in &cases {
        let path = t.state().join(name);
        let good = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, doc.to_string()).unwrap();
        let (code, out, err) = t.admin.cmd(argv).run();
        std::fs::write(&path, good).unwrap();
        assert_eq!(code, 1, "{name} {argv:?}: out={out:?} err={err:?}");
        assert_eq!(out, "", "{name} {argv:?}");
        let last = err
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("");
        let error: Value = serde_json::from_str(last)
            .unwrap_or_else(|e| panic!("{name} {argv:?}: not JSON ({e}): {err:?}"));
        assert_eq!(
            (&error["error"], &error["reason"]),
            (&json!("StateError"), &json!("state_corrupt")),
            "{name} {argv:?}"
        );
        assert_eq!(
            keys(&error),
            BTreeSet::from(["error", "reason", "detail"].map(String::from)),
            "{name} {argv:?}"
        );
    }
    // Malformed JSON is the store's own state_corrupt (naming the document);
    // a malformed wrapped DEK keeps its specific code. The state is intact
    // after all of the above.
    let path = t.state().join("policy/grants.json");
    let good = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, "{not json").unwrap();
    assert_eq!(
        t.fail(&["grant", "list"]),
        json!({"error": "StateError", "reason": "state_corrupt", "detail": "policy/grants.json"})
    );
    std::fs::write(&path, good).unwrap();
    let path = t.state().join("vault/secrets.json");
    let good = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, json!({"dek": "x", "secrets": {}}).to_string()).unwrap();
    assert_eq!(
        t.fail(&["secret", "list"])["reason"],
        "wrapped_key_malformed"
    );
    std::fs::write(&path, good).unwrap();
    let ids: Vec<Value> = array(&t.ok(&["grant", "list"])["grants"])
        .iter()
        .map(|g| g["id"].clone())
        .collect();
    assert_eq!(ids, [json!(grant_id)]);
    assert_eq!(
        t.ok(&["secret", "reveal", "--id", "gh-token"])["value"],
        SYNTHETIC
    );
}

/// backup-tmp-symlink-mode-bypass: the temp file is never a predictable
/// name, a planted symlink is not followed, and the archive is 0600.
#[test]
fn backup_ignores_planted_tmp_symlink_and_keeps_0600() {
    let t = Case::new();
    t.seed_project();
    t.put_secret();
    let outdir = t.root().join("backups");
    std::fs::create_dir(&outdir).unwrap();
    let victim = t.root().join("victim.txt");
    std::fs::write(&victim, "victim-content").unwrap();
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = outdir.join("backup.json");
    symlink(&victim, outdir.join("backup.json.tmp")).unwrap(); // the old predictable temp name
    symlink(&victim, &out).unwrap(); // and the destination itself
    let result = t.ok(&["backup", "--out", &Case::path_arg(&out)]);
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "victim-content");
    assert_eq!(
        std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
        0o644
    );
    let out_meta = std::fs::symlink_metadata(&out).unwrap();
    assert!(!out_meta.file_type().is_symlink());
    assert_eq!(out_meta.permissions().mode() & 0o777, 0o600);
    // Untouched: never used as a temp name.
    assert!(
        std::fs::symlink_metadata(outdir.join("backup.json.tmp"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    let mut names: Vec<String> = std::fs::read_dir(&outdir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["backup.json", "backup.json.tmp"]);
    let text = std::fs::read_to_string(&out).unwrap();
    let archive: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(archive["manifest"], result["manifest"]);
    assert!(!text.contains(SYNTHETIC));
    // A failed write leaves no temp file behind.
    let nodir = t.root().join("nodir");
    assert_eq!(
        t.fail(&["backup", "--out", &Case::path_arg(&nodir.join("b.json"))])["reason"],
        "file_not_found"
    );
    assert!(!nodir.exists());
}

/// restore-reverts-global-stop: an archive taken while running never lifts a
/// later stop-all.
#[test]
fn restore_keeps_a_global_stop_and_restore_ack_does_not_lift_it() {
    let t = Case::new();
    t.seed_project();
    t.put_secret();
    t.create_http("gh", &[]);
    t.ok(&["principal", "create", "--id", "agent-1"]);
    t.ok(&[
        "grant",
        "create",
        "--principal",
        "agent-1",
        "--connection",
        "gh",
    ]);
    let archive = t.root().join("backup.json");
    let archive_arg = Case::path_arg(&archive);
    t.ok(&["backup", "--out", &archive_arg]);
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&archive).unwrap()).unwrap();
    let control = &doc["documents"]["policy/control.json"];
    assert!(!control["stopped"].as_bool().unwrap_or(false), "{control}");
    t.ok(&["stop-all"]);
    let restored = t.ok(&["restore", "--in", &archive_arg]);
    assert_eq!(
        (&restored["stopped"], &restored["restore_pending"]),
        (&json!(true), &json!(true))
    );
    assert!(
        restored["next"]
            .as_str()
            .unwrap()
            .contains("global stop stays set until resume")
    );
    {
        let ctx = t.ctx();
        let policy = &ctx.policy;
        assert!(policy.is_stopped().unwrap());
        // Both flags deny; restore_pending is reported first because it is
        // checked first.
        assert_eq!(
            policy
                .evaluate("agent-1", "gh", &get_http("/repos"), None)
                .unwrap()
                .reason,
            "restore_pending"
        );
        assert!(policy.usable_connections("agent-1").unwrap().is_empty());
    }
    let acked = t.ok(&["restore-ack"]);
    assert_eq!(
        (&acked["stopped"], &acked["restore_pending"]),
        (&json!(true), &json!(false))
    );
    assert!(
        acked["note"]
            .as_str()
            .unwrap()
            .contains("global stop is still set")
    );
    {
        let ctx = t.ctx();
        let policy = &ctx.policy;
        assert!(policy.is_stopped().unwrap());
        assert!(!policy.restore_pending().unwrap());
        assert_eq!(
            policy
                .evaluate("agent-1", "gh", &get_http("/repos"), None)
                .unwrap()
                .reason,
            "global_stop"
        );
        assert!(policy.usable_connections("agent-1").unwrap().is_empty());
    }
    assert_eq!(
        t.ok(&["resume"]),
        json!({"stopped": false, "restore_pending": false, "incident_open": null})
    );
    assert!(
        t.ctx()
            .policy
            .evaluate("agent-1", "gh", &get_http("/repos"), None)
            .unwrap()
            .allowed
    );
    // resume before restore-ack lifts only the stop; restore_pending still
    // closes execution.
    t.ok(&["stop-all"]);
    t.ok(&["restore", "--in", &archive_arg]);
    let resumed = t.ok(&["resume"]);
    assert_eq!(
        (&resumed["stopped"], &resumed["restore_pending"]),
        (&json!(false), &json!(true))
    );
    assert!(resumed["note"].as_str().unwrap().contains("restore-ack"));
    assert_eq!(
        t.ctx()
            .policy
            .evaluate("agent-1", "gh", &get_http("/repos"), None)
            .unwrap()
            .reason,
        "restore_pending"
    );
    let acked = t.ok(&["restore-ack"]);
    assert_eq!(
        (&acked["stopped"], &acked["restore_pending"]),
        (&json!(false), &json!(false))
    );
    assert!(
        acked["note"]
            .as_str()
            .unwrap()
            .contains("execution is open")
    );
}

/// restore-kms-mismatch-bricks-reopen / ADM-1: nothing is written and the
/// state still opens.
#[test]
fn restore_refuses_an_archive_the_current_kms_cannot_open() {
    let t = Case::new();
    t.seed_project();
    t.put_secret();
    t.create_http("gh", &[]);
    let archive = Case::path_arg(&t.root().join("pre-recover.json"));
    t.ok(&["backup", "--out", &archive]);
    // Rotates the KMS key: the archive's DEK is wrapped under the old one.
    let recovered = t.ok(&["recover"]);
    let key_id = recovered["kms_key_id"].as_str().unwrap().to_owned();
    assert_ne!(key_id, "local-dev-kms-1");
    // Post-recover state that must survive.
    t.ok(&[
        "connection",
        "update-scope",
        "--id",
        "gh",
        "--methods",
        "GET",
    ]);
    assert_eq!(
        t.fail(&["restore", "--in", &archive]),
        json!({"error": "StateError", "reason": "backup_kms_mismatch"})
    );
    {
        let ctx = t.ctx(); // still opens
        assert_eq!(ctx.kms.key_id(), key_id);
        let connection = ctx.policy.get_connection("gh").unwrap();
        assert_eq!(
            connection.http_scope.as_ref().unwrap().methods,
            Some(vec!["GET".to_owned()])
        );
        assert!(!ctx.policy.restore_pending().unwrap());
        assert_eq!(
            ctx.vault
                .secret_for_trusted_use("gh-token", None)
                .unwrap()
                .expose(),
            SYNTHETIC.as_bytes()
        );
    }
    assert_eq!(
        t.ok(&["secret", "reveal", "--id", "gh-token"])["value"],
        SYNTHETIC
    );
    let restores: Vec<(Value, Value)> = t
        .ctx()
        .audit
        .tail(500)
        .unwrap()
        .into_iter()
        .filter(|r| r["event"] == "restore")
        .map(|r| (r["result"].clone(), r["reason"].clone()))
        .collect();
    assert_eq!(restores, [(json!("denied"), json!("backup_kms_mismatch"))]);
    // A backup of another state directory (same key id, different master
    // key) is refused the same way.
    let other = t.root().join("other");
    let fresh = t.root().join("fresh");
    t.admin.cmd(&["init"]).state(&other).ok();
    let foreign = t.root().join("foreign.json");
    let foreign_arg = Case::path_arg(&foreign);
    t.admin
        .cmd(&["backup", "--out", &foreign_arg])
        .state(&other)
        .ok();
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&foreign).unwrap()).unwrap();
    assert_eq!(doc["manifest"]["kms_key_id"], "local-dev-kms-1");
    t.admin.cmd(&["init"]).state(&fresh).ok();
    assert_eq!(
        t.admin
            .cmd(&["restore", "--in", &foreign_arg])
            .state(&fresh)
            .fail(1)["reason"],
        "backup_kms_mismatch"
    );
    assert_eq!(
        t.admin.cmd(&["project", "list"]).state(&fresh).ok()["projects"],
        json!([])
    );
    assert!(!open_ctx(&fresh).policy.restore_pending().unwrap());
    // An archive the current key can open restores normally.
    let current = Case::path_arg(&t.root().join("current.json"));
    t.ok(&["backup", "--out", &current]);
    assert_eq!(
        t.ok(&["restore", "--in", &current])["restore_pending"],
        true
    );
    assert_eq!(t.ok(&["restore-ack"])["restore_pending"], false);
}

/// Every command family runs once; exactly the `secret reveal` outputs carry
/// a value, and no state file holds one.
#[test]
fn only_reveal_prints_a_secret_value_across_the_command_surface() {
    let t = Case::new();
    t.seed_project();
    t.put_secret();
    t.put_ssh_key(false);
    t.ok(&["secret", "list"]);
    t.ok(&["secret", "versions", "--id", "gh-token"]);
    t.create_http("gh", &[]);
    t.ok(&[
        "connection",
        "create-ssh",
        "--id",
        "box",
        "--project",
        "demo",
        "--environment",
        "dev",
        "--service",
        "s",
        "--secret-id",
        "box-key",
        "--host",
        "127.0.0.1",
        "--username",
        "deploy",
        "--host-key",
        t.host_key.as_str(),
    ]);
    t.ok(&["connection", "list"]);
    t.ok(&["connection", "show", "--id", "gh"]);
    t.ok(&[
        "connection",
        "update-scope",
        "--id",
        "gh",
        "--methods",
        "GET",
    ]);
    t.ok(&["principal", "create", "--id", "agent-1"]);
    t.ok(&["principal", "list"]);
    let grant = t.ok(&[
        "grant",
        "create",
        "--principal",
        "agent-1",
        "--connection",
        "gh",
    ]);
    t.ok(&["grant", "list"]);
    t.ok_stdin(
        &["rotation", "start", "--secret-id", "gh-token", "--stdin"],
        SYNTHETIC_V2.as_bytes(),
    );
    t.ok(&[
        "rotation",
        "activate",
        "--connection",
        "gh",
        "--version",
        "2",
    ]);
    t.ok(&[
        "rotation",
        "finish",
        "--secret-id",
        "gh-token",
        "--version",
        "1",
    ]);
    t.ok_stdin(
        &[
            "secret",
            "put",
            "--id",
            "gh-token",
            "--kind",
            "api_key",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--stdin",
            "--staged",
        ],
        b"synthetic-v3",
    );
    t.ok(&[
        "connection",
        "switch-credential",
        "--id",
        "gh",
        "--version",
        "3",
    ]);
    t.ok(&[
        "connection",
        "switch-credential",
        "--id",
        "gh",
        "--version",
        "2",
    ]);
    t.ok(&["secret", "retire", "--id", "gh-token", "--version", "3"]);
    t.ok(&["secret", "revoke", "--id", "gh-token", "--version", "3"]);
    t.ok(&["stop-all"]);
    t.ok(&["resume"]);
    let digest = approval_digest("agent-1", "gh", "DELETE", "/repos/demo", b"");
    t.ctx()
        .policy
        .request_approval(&digest, "agent-1", "gh", "DELETE", "/repos/demo")
        .unwrap();
    t.ok(&["approvals", "list"]);
    t.ok(&["approvals", "approve", "--digest", &digest]);
    let archive = Case::path_arg(&t.root().join("backup.json"));
    t.ok(&["backup", "--out", &archive]);
    t.ok(&["restore", "--in", &archive]);
    t.ok(&["restore-ack"]);
    // Widening -> stale.
    t.ok(&[
        "connection",
        "update-scope",
        "--id",
        "gh",
        "--methods",
        "GET,POST",
    ]);
    let fresh = t.ok(&["grant", "regrant", "--id", grant["id"].as_str().unwrap()]);
    t.ok(&["grant", "revoke", "--id", fresh["id"].as_str().unwrap()]);
    t.ok(&["connection", "disable", "--id", "box"]);
    t.ok(&["principal", "disable", "--id", "agent-1"]);
    t.ok(&["recover"]);
    t.ok(&["audit", "tail", "--limit", "500"]);
    t.ok(&["alerts"]);
    t.fail(&["serve", "--listen", "0.0.0.0:1"]);
    assert_eq!(
        t.ok(&["secret", "reveal", "--id", "gh-token", "--version", "2"])["value"],
        SYNTHETIC_V2
    );
    assert_eq!(
        t.ok(&["secret", "reveal", "--id", "gh-token", "--version", "1"])["value"],
        SYNTHETIC
    );
    let synthetic = regex::Regex::new(r"synthetic-[A-Za-z0-9_.-]+").unwrap();
    let private_line = t.private_line();
    {
        let outputs = t.admin.outputs.lock().unwrap();
        assert!(outputs.len() >= 40, "only {} commands ran", outputs.len());
        // argv[2..4]: after `--state-dir <state>`.
        let printed: Vec<String> = outputs
            .iter()
            .filter(|r| synthetic.is_match(&r.stdout))
            .map(|r| r.argv[2..4].join(" "))
            .collect();
        assert_eq!(printed, ["secret reveal", "secret reveal"]);
        let stderr_hits: Vec<&Vec<String>> = outputs
            .iter()
            .filter(|r| synthetic.is_match(&r.stderr))
            .map(|r| &r.argv)
            .collect();
        assert!(stderr_hits.is_empty(), "{stderr_hits:?}");
        let key_hits: Vec<&Vec<String>> = outputs
            .iter()
            .filter(|r| r.stdout.contains(&private_line) || r.stderr.contains(&private_line))
            .map(|r| &r.argv)
            .collect();
        assert!(key_hits.is_empty(), "{key_hits:?}");
    }
    for path in files_under(t.state()) {
        let data = std::fs::read(&path).unwrap();
        for needle in [
            SYNTHETIC,
            SYNTHETIC_V2,
            "synthetic-v3",
            private_line.as_str(),
        ] {
            assert!(
                !contains_bytes(&data, needle.as_bytes()),
                "{} holds a value",
                path.display()
            );
        }
    }
}

// ------------------------------------------------------------------ serve

#[test]
fn serve_refuses_non_loopback_and_bad_listen() {
    let t = Case::new();
    t.init();
    assert_eq!(
        t.fail(&["serve", "--listen", "0.0.0.0:0"])["reason"],
        "listen_not_loopback"
    );
    assert_eq!(
        t.fail(&["serve", "--listen", "127.0.0.1"])["reason"],
        "invalid_listen"
    );
    assert_eq!(
        t.fail(&["serve", "--listen", "127.0.0.1:99999"])["reason"],
        "invalid_listen"
    );
}

/// `GET <url><path>` over a plain loopback connection: (status, body).
fn http_get(url: &str, path: &str) -> (u16, Vec<u8>) {
    let authority = url.strip_prefix("http://").unwrap().trim_end_matches('/');
    let mut stream = TcpStream::connect(authority).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("complete response head");
    let head = String::from_utf8_lossy(&response[..split]).into_owned();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("bad status line: {head:?}"));
    let mut body = response[split + 4..].to_vec();
    if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        body = dechunk(&body);
    }
    (status, body)
}

fn dechunk(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let line_end = data.windows(2).position(|w| w == b"\r\n").unwrap();
        let size_text = String::from_utf8_lossy(&data[..line_end]).into_owned();
        let size = usize::from_str_radix(size_text.split(';').next().unwrap().trim(), 16).unwrap();
        data = &data[line_end + 2..];
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

#[test]
fn serve_subprocess_smoke() {
    let t = Case::new();
    t.init();
    let path = native_e2e::path_env();
    let home = Case::path_arg(t.root());
    let mut serve = Serve::start(
        t.state(),
        &["--listen", "127.0.0.1:0"],
        &[
            ("PATH", path.as_str()),
            ("HOME", home.as_str()),
            ("ZEROPW_ADMIN_PASSPHRASE", ADMIN_PASSPHRASE),
            ("ZEROPW_RECOVERY_PASSPHRASE", RECOVERY_PASSPHRASE),
        ],
    );
    let startup = serve.startup.clone();
    assert!(startup.get("url").is_some(), "{startup}");
    assert_eq!(startup["pid"], serve.pid());
    let signer = startup["ssh_signer"].as_str().unwrap();
    assert!(matches!(signer, "available" | "unavailable"), "{signer}");
    let (status, body) = http_get(&serve.url, "/healthz");
    assert_eq!(status, 200);
    let health: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(health["status"], "ok");
    let (code, output) = serve.stop();
    assert_eq!(code, 0, "{output}");
    for needle in [SYNTHETIC, SYNTHETIC_V2, "BEGIN OPENSSH PRIVATE KEY"] {
        assert!(!output.contains(needle));
    }
}

/// F10 / PL-3 through the administrator CLI: restore re-applies later
/// revocations (from the audit log alone) and keeps used approvals used.
#[test]
fn cli_restore_keeps_revocations_and_used_approvals() {
    let t = Case::new();
    t.seed_project();
    t.put_secret();
    t.create_http("gh", &[]);
    t.create_http("gh2", &[]);
    t.ok(&["principal", "create", "--id", "agent-1"]);
    t.ok(&["principal", "create", "--id", "agent-2"]);
    let grant = t.ok(&[
        "grant",
        "create",
        "--principal",
        "agent-1",
        "--connection",
        "gh",
    ])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    t.ok(&[
        "grant",
        "create",
        "--principal",
        "agent-2",
        "--connection",
        "gh2",
    ]);
    let digest = approval_digest("agent-1", "gh", "DELETE", "/repos/demo", b"");
    t.ctx()
        .policy
        .request_approval(&digest, "agent-1", "gh", "DELETE", "/repos/demo")
        .unwrap();
    t.ok(&["approvals", "approve", "--digest", &digest]);
    let archive = Case::path_arg(&t.root().join("backup.json"));
    t.ok(&["backup", "--out", &archive]);
    assert!(
        t.ctx()
            .policy
            .consume_approval(&digest, "agent-1", "gh", None, None)
            .unwrap()
    );
    t.ok(&["principal", "disable", "--id", "agent-2"]);
    t.ok(&["connection", "disable", "--id", "gh2"]);
    // The audit log alone must be enough.
    std::fs::remove_file(t.state().join(zeropw::policy::REVOCATIONS)).unwrap();
    let restored = t.ok(&["restore", "--in", &archive]);
    assert_eq!(
        (
            &restored["reapplied"]["principals"],
            &restored["reapplied"]["connections"]
        ),
        (&json!(1), &json!(1))
    );
    assert_eq!(restored["handle_key_rotated"], true);
    assert!(restored["next"].as_str().unwrap().contains("approvals"));
    {
        let ctx = t.ctx();
        let policy = &ctx.policy;
        assert_eq!(policy.get_principal("agent-2").unwrap().status, "disabled");
        assert_eq!(policy.get_connection("gh2").unwrap().status, "disabled");
        assert_eq!(
            policy.list_approvals().unwrap()[&digest]["status"],
            "consumed"
        );
    }
    let acked = t.ok(&["restore-ack"]);
    assert_eq!(acked["restore_pending"], false);
    assert!(
        array(&acked["active_grant_ids"]).contains(&json!(grant)),
        "{acked}"
    );
    {
        let ctx = t.ctx();
        let policy = &ctx.policy;
        assert!(
            !policy
                .consume_approval(&digest, "agent-1", "gh", None, None)
                .unwrap()
        );
        assert_eq!(
            policy
                .evaluate("agent-2", "gh2", &get_http("/repos"), None)
                .unwrap()
                .reason,
            "principal_disabled"
        );
        assert!(
            policy
                .evaluate("agent-1", "gh", &get_http("/repos"), None)
                .unwrap()
                .allowed
        );
        // The used approval stays in history once the same request asks
        // again.
        policy
            .request_approval(&digest, "agent-1", "gh", "DELETE", "/repos/demo")
            .unwrap();
    }
    let listing = t.ok(&["approvals", "list"]);
    let approvals: Vec<(Value, Value, Value)> = array(&listing["approvals"])
        .iter()
        .map(|a| (a["digest"].clone(), a["status"].clone(), a["cycle"].clone()))
        .collect();
    assert_eq!(approvals, [(json!(digest), json!("pending"), json!(2))]);
    let history: Vec<(Value, Value)> = array(&listing["history"])
        .iter()
        .map(|h| (h["digest"].clone(), h["status"].clone()))
        .collect();
    assert_eq!(history, [(json!(digest), json!("consumed"))]);
}

// ---------------------------------------------- connection safety (F1 save-time, F5 opt-in)

/// `connection create-http` with the native democli as the CLI program (the
/// original used `examples/democli.py`) and one `--cli-env` assignment.
fn create_with_cli_env<'a>(id: &'a str, assignment: &'a str) -> Vec<&'a str> {
    vec![
        "connection",
        "create-http",
        "--id",
        id,
        "--project",
        "demo",
        "--environment",
        "dev",
        "--service",
        "fake",
        "--secret-id",
        "gh-token",
        "--target",
        "http://127.0.0.1:8080",
        "--auth",
        "bearer",
        "--cli-program",
        DEMOCLI_BIN,
        "--cli-env",
        assignment,
    ]
}

#[test]
fn cli_env_holding_the_credential_is_refused_at_save_time() {
    let t = Case::new();
    t.seed_project();
    t.put_secret();
    for value in [
        SYNTHETIC.to_owned(),
        format!("prefix-{SYNTHETIC}"),
        base64::engine::general_purpose::STANDARD.encode(SYNTHETIC),
        hex::encode(SYNTHETIC),
    ] {
        let assignment = format!("GH_TOKEN={value}");
        let args = create_with_cli_env("leaky", &assignment);
        let error = t.fail(&args);
        assert_eq!(
            (&error["reason"], &error["detail"]),
            (&json!("cli_env_contains_credential"), &json!("leaky")),
            "{}",
            &value[..12]
        );
    }
    let connections = t.state().join("policy/connections.json");
    assert!(
        !(connections.exists()
            && std::fs::read_to_string(&connections)
                .unwrap()
                .contains(SYNTHETIC))
    );
    assert_eq!(t.ok(&["connection", "list"])["connections"], json!([]));
    let tail = t.ok(&["audit", "tail", "--limit", "20"]);
    let denied: BTreeSet<String> = array(&tail["records"])
        .iter()
        .filter(|r| r["event"] == "connection_create" && r["result"] == "denied")
        .map(|r| r["reason"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        denied,
        BTreeSet::from(["cli_env_contains_credential".to_owned()])
    );
    // A harmless value is accepted.
    let args = create_with_cli_env("clean", "DEMOCLI_COLOR=never");
    let created = t.ok(&args);
    assert_eq!(
        created["cli"]["extra_env"],
        json!({"DEMOCLI_COLOR": "never"})
    );
}

#[test]
fn new_secret_version_matching_existing_cli_env_is_refused() {
    let t = Case::new();
    t.seed_project();
    t.put_secret();
    let args = create_with_cli_env("gh", "LABEL=zpw-label-that-later-becomes-a-value");
    t.ok(&args);
    let error = t.fail_stdin(
        &[
            "secret",
            "put",
            "--id",
            "gh-token",
            "--kind",
            "api_key",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--stdin",
        ],
        b"zpw-label-that-later-becomes-a-value\n",
        1,
    );
    assert_eq!(
        (&error["reason"], &error["detail"]),
        (&json!("cli_env_contains_credential"), &json!("gh"))
    );
    let error = t.fail_stdin(
        &["rotation", "start", "--secret-id", "gh-token", "--stdin"],
        b"zpw-label-that-later-becomes-a-value\n",
        1,
    );
    assert_eq!(error["reason"], "cli_env_contains_credential");
    let versions = t.ok(&["secret", "versions", "--id", "gh-token"]);
    assert_eq!(array(&versions["versions"]).len(), 1);
}

/// Every version (any status) of every secret, not only the connection's own
/// active or staged ones.
#[test]
fn cli_env_holding_any_vault_value_is_refused_at_save_time() {
    let t = Case::new();
    t.seed_project();
    t.ok(&["project", "create", "prodproj", "--environments", "prod"]);
    let other = "synthetic-prod-token-OTHERPROJECT-0123456789";
    t.ok_stdin(
        &[
            "secret",
            "put",
            "--id",
            "prod-token",
            "--kind",
            "api_key",
            "--project",
            "prodproj",
            "--environment",
            "prod",
            "--stdin",
        ],
        other.as_bytes(),
    );
    let retired = "synthetic-retired-token-v1-abcdefghijkl";
    t.put_secret_as(retired, "gh-token", "dev");
    t.put_secret_as("synthetic-current-token-v2-mnopqrstuvwx", "gh-token", "dev");
    let statuses: Vec<Value> =
        array(&t.ok(&["secret", "versions", "--id", "gh-token"])["versions"])
            .iter()
            .map(|v| v["status"].clone())
            .collect();
    assert_eq!(statuses, [json!("retired"), json!("active")]);
    let revoked = "synthetic-revoked-token-0123456789abc";
    t.put_secret_as(revoked, "gone", "dev");
    t.ok(&["secret", "revoke", "--id", "gone", "--version", "1"]);
    for (label, assignment) in [
        ("other project", format!("OTHER_TOKEN={other}")),
        ("retired version", format!("OLD_TOKEN=Bearer {retired}")),
        (
            "revoked version",
            format!(
                "GONE_B64={}",
                base64::engine::general_purpose::STANDARD.encode(revoked)
            ),
        ),
    ] {
        let args = create_with_cli_env("leaky", &assignment);
        let error = t.fail(&args);
        assert_eq!(
            (&error["reason"], &error["detail"]),
            (&json!("cli_env_contains_credential"), &json!("leaky")),
            "{label}"
        );
    }
    let connections = t.state().join("policy/connections.json");
    let text = std::fs::read_to_string(&connections).unwrap_or_default();
    for value in [other, retired, revoked] {
        assert!(!text.contains(value));
    }
    assert_eq!(t.ok(&["connection", "list"])["connections"], json!([]));
}

/// A new secret (other id, other project) whose value is already configured
/// as a CLI env value.
#[test]
fn new_secret_matching_any_connection_cli_env_is_refused() {
    let t = Case::new();
    t.seed_project();
    t.ok(&["project", "create", "prodproj", "--environments", "prod"]);
    t.put_secret();
    let label = "zpw-label-that-later-becomes-another-secret";
    let assignment = format!("LATER_TOKEN={label}");
    let args = create_with_cli_env("gh", &assignment);
    t.ok(&args);
    let put_later = [
        "secret",
        "put",
        "--id",
        "later",
        "--kind",
        "api_key",
        "--project",
        "prodproj",
        "--environment",
        "prod",
        "--stdin",
    ];
    let error = t.fail_stdin(&put_later, label.as_bytes(), 1);
    assert_eq!(
        (&error["reason"], &error["detail"]),
        (&json!("cli_env_contains_credential"), &json!("gh"))
    );
    t.ok_stdin(&put_later, b"zpw-unrelated-value-0123456789");
    let error = t.fail_stdin(
        &["rotation", "start", "--secret-id", "later", "--stdin"],
        label.as_bytes(),
        1,
    );
    assert_eq!(
        (&error["reason"], &error["detail"]),
        (&json!("cli_env_contains_credential"), &json!("gh"))
    );
    assert_eq!(
        array(&t.ok(&["secret", "versions", "--id", "later"])["versions"]).len(),
        1
    );
    // (event, reason, secret_id) as JSON text; a missing secret_id is null.
    let denied: BTreeSet<String> = t
        .ctx()
        .audit
        .tail(50)
        .unwrap()
        .into_iter()
        .filter(|r| r["result"] == "denied")
        .map(|r| json!([r["event"], r["reason"], r.get("secret_id")]).to_string())
        .collect();
    let expected = BTreeSet::from([
        json!(["secret_put", "cli_env_contains_credential", "later"]).to_string(),
        json!(["rotation", "cli_env_contains_credential", "later"]).to_string(),
    ]);
    assert_eq!(denied, expected);
}

#[test]
fn private_network_opt_in_flag() {
    let t = Case::new();
    t.seed_project();
    t.put_secret();
    let base = |id: &'static str, target: &'static str| -> Vec<&'static str> {
        vec![
            "connection",
            "create-http",
            "--id",
            id,
            "--project",
            "demo",
            "--environment",
            "dev",
            "--service",
            "fake",
            "--secret-id",
            "gh-token",
            "--target",
            target,
            "--auth",
            "bearer",
        ]
    };
    let default = t.ok(&base("public", "https://api.example.com"));
    assert_eq!(default["http_target"]["allow_private_network"], false);
    let internal = t.ok(&[
        base("internal", "https://git.corp.example").as_slice(),
        &["--allow-private-network"],
    ]
    .concat());
    assert_eq!(internal["http_target"]["allow_private_network"], true);
    for (target, reason) in [
        ("http://169.254.169.254", "metadata_address_not_allowed"),
        ("http://[fe80::1]:8080", "metadata_address_not_allowed"),
        ("http://0.0.0.0:8080", "target_address_not_allowed"),
    ] {
        let error = t.fail(
            &[
                base("meta", target).as_slice(),
                &["--allow-private-network"],
            ]
            .concat(),
        );
        assert_eq!(error["reason"], reason, "{target}");
    }
}
