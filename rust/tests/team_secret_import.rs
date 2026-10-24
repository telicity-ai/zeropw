//! `zeropw-admin secret import` into a shared environment
//! (docs/env-import.md §7, stage 3 of §10), across three devices with their
//! own state directories and `serve --team-listen` processes: the owner's
//! import is one commit that reaches an admin and a user device, a user
//! device cannot import, and no value appears in any output, state
//! directory or the raw team-sync wire capture.
mod native_e2e;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use native_e2e::{
    ADMIN_BIN, Serve, cli_json, find_secret, find_secret_in_tree, free_port, path_env,
};
use serde_json::Value;

const OPENAI: &str = "synthetic-team-import-openai-0123456789";
const STRIPE: &str = "synthetic-team-import-stripe-0123456789";
const STRIPE_V2: &str = "synthetic-team-import-stripe-rotated-01234";
const CONVERGE: Duration = Duration::from_secs(60);

struct Node {
    name: &'static str,
    root: PathBuf,
    state: PathBuf,
    team_listen: String,
    serve: Option<Serve>,
    outputs: Vec<String>,
}

impl Node {
    fn new(root: &Path, name: &'static str) -> Node {
        let root = root.join(name);
        std::fs::create_dir_all(&root).unwrap();
        Node {
            name,
            state: root.join("state"),
            root,
            team_listen: format!("127.0.0.1:{}", free_port()),
            serve: None,
            outputs: Vec::new(),
        }
    }

    fn env(&self) -> Vec<(String, String)> {
        vec![
            ("PATH".into(), path_env()),
            ("HOME".into(), self.root.to_string_lossy().into_owned()),
            (
                "ZEROPW_ADMIN_PASSPHRASE".into(),
                format!("admin-{}-pass-import", self.name),
            ),
            (
                "ZEROPW_RECOVERY_PASSPHRASE".into(),
                format!("recovery-{}-pass-import", self.name),
            ),
        ]
    }

    fn admin(&mut self, args: &[&str], stdin: &[u8], expect: i32) -> Value {
        use std::io::Write;
        let mut child = Command::new(ADMIN_BIN)
            .arg("--state-dir")
            .arg(&self.state)
            .args(args)
            .env_clear()
            .envs(self.env())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        let output = child.wait_with_output().unwrap();
        let out = String::from_utf8_lossy(&output.stdout).into_owned();
        let err = String::from_utf8_lossy(&output.stderr).into_owned();
        let code = output.status.code().unwrap();
        // invite strings are credentials of their own; keep them out of the sweep
        if !args.contains(&"invite") && !args.contains(&"join") {
            self.outputs.push(format!("{out}{err}"));
        }
        assert_eq!(code, expect, "{} {args:?}: {err}", self.name);
        cli_json(code, &out, &err)
    }

    fn start_serve(&mut self, wire: &Path) {
        let mut env = self.env();
        env.push((
            "ZEROPW_TEAM_WIRE_CAPTURE".into(),
            wire.to_string_lossy().into_owned(),
        ));
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        self.serve = Some(Serve::start(
            &self.state,
            &[
                "--listen",
                "127.0.0.1:0",
                "--team-listen",
                &self.team_listen,
            ],
            &env,
        ));
    }

    fn import(&mut self, env: &str, text: &str, extra: &[&str], expect: i32) -> Value {
        let (project, environment) = env.split_once('/').unwrap();
        let mut args = vec![
            "secret",
            "import",
            "--project",
            project,
            "--environment",
            environment,
            "--stdin",
        ];
        args.extend_from_slice(extra);
        self.admin(&args, text.as_bytes(), expect)
    }

    fn secret_ids(&mut self) -> Vec<String> {
        let listed = self.admin(&["secret", "list"], b"", 0);
        let mut ids: Vec<String> = listed["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["id"].as_str().unwrap().to_owned())
            .collect();
        ids.sort();
        ids
    }

    fn active_version_id(&mut self, id: &str) -> Option<String> {
        let doc = std::fs::read(self.state.join("vault/secrets.json")).ok()?;
        let doc: Value = serde_json::from_slice(&doc).ok()?;
        let entry = &doc["secrets"][id];
        let active = entry["active_version"].to_string();
        entry["versions"][active.trim_matches('"')]["version_id"]
            .as_str()
            .map(str::to_owned)
    }

    fn commits(&mut self, env: &str) -> usize {
        self.admin(&["team", "log", "--env", env], b"", 0)["log"]
            .as_array()
            .unwrap()
            .len()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(mut serve) = self.serve.take() {
            serve.stop();
        }
    }
}

fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + CONVERGE;
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("timed out: {what}");
}

fn join(owner: &mut Node, node: &mut Node, role: &str, wire: &Path) -> String {
    let listen = owner.team_listen.clone();
    let invite = owner.admin(
        &[
            "team",
            "invite",
            "--env",
            "demo/dev",
            "--role",
            role,
            "--name",
            node.name,
            "--address",
            &listen,
        ],
        b"",
        0,
    )["invite"]
        .as_str()
        .unwrap()
        .to_owned();
    node.admin(&["init"], b"", 0);
    let joined = node.admin(
        &[
            "team",
            "join",
            &invite,
            "--project",
            "team-shared",
            "--environment",
            "dev",
        ],
        b"",
        0,
    );
    node.start_serve(wire);
    format!(
        "{}/{}",
        joined["project"].as_str().unwrap(),
        joined["environment"].as_str().unwrap()
    )
}

#[test]
fn an_import_into_a_shared_environment_is_one_commit_every_device_receives() {
    let tmp = tempfile::Builder::new().prefix("zpwti-").tempdir().unwrap();
    let wire = tmp.path().join("wire.log");
    let mut a = Node::new(tmp.path(), "a");
    let mut b = Node::new(tmp.path(), "b");
    let mut c = Node::new(tmp.path(), "c");

    a.admin(&["init"], b"", 0);
    a.admin(&["team", "init"], b"", 0);
    a.admin(&["project", "create", "demo"], b"", 0);
    a.admin(
        &["team", "share", "--project", "demo", "--environment", "dev"],
        b"",
        0,
    );
    a.start_serve(&wire);
    let env_b = join(&mut a, &mut b, "admin", &wire);
    let env_c = join(&mut a, &mut c, "user", &wire);

    let text = format!("OPENAI_API_KEY={OPENAI}\nSTRIPE_SECRET_KEY='{STRIPE}'\nLOG_LEVEL=debug\n");
    let preview = a.import("demo/dev", &text, &["--dry-run"], 0);
    assert_eq!(preview["shared"], true);
    assert_eq!(preview["entries"][0]["action"], "create");
    let before = a.commits("demo/dev");
    let out = a.import("demo/dev", &text, &[], 0);
    assert_eq!(out["shared"], true);
    assert!(out["commit"]["author_seq"].is_number(), "{out}");
    assert_eq!(out["entries"][0]["action"], "created");
    assert!(out["entries"][0]["version_id"].is_string());
    assert_eq!(out["entries"][2]["action"], "skipped");
    // put_version and activate of both keys in a single commit
    assert_eq!(a.commits("demo/dev"), before + 1);
    let ids = vec!["openai_api_key".to_owned(), "stripe_secret_key".to_owned()];
    assert_eq!(a.secret_ids(), ids);

    // the running serves carry it to the admin and the user device
    wait_until("B derives the imported keys", || b.secret_ids() == ids);
    wait_until("C derives the imported keys", || c.secret_ids() == ids);
    let version = out["entries"][1]["version_id"].as_str().unwrap().to_owned();
    assert_eq!(c.active_version_id("stripe_secret_key"), Some(version));

    // a user device cannot import: refused before anything is authored
    let c_commits = c.commits(&env_c);
    let error = c.import(
        &env_c,
        &format!("STRIPE_SECRET_KEY={STRIPE_V2}\n"),
        &["--update"],
        1,
    );
    assert_eq!(error["reason"], "not_admin");
    assert_eq!(c.commits(&env_c), c_commits);

    // an admin device can, and the owner receives the new version
    let rotated = b.import(
        &env_b,
        &format!("STRIPE_SECRET_KEY={STRIPE_V2}\n"),
        &["--update"],
        0,
    );
    assert_eq!(rotated["entries"][0]["action"], "new_version");
    let new_version = rotated["entries"][0]["version_id"]
        .as_str()
        .unwrap()
        .to_owned();
    wait_until("A activates B's new version", || {
        a.active_version_id("stripe_secret_key").as_deref() == Some(new_version.as_str())
    });
    let revealed = a.admin(&["secret", "reveal", "--id", "stripe_secret_key"], b"", 0);
    assert_eq!(revealed["value"], STRIPE_V2);
    a.outputs.pop(); // the one output allowed to hold a value

    let needles: Vec<Vec<u8>> = [OPENAI, STRIPE, STRIPE_V2]
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();
    for node in [&a, &b, &c] {
        for text in &node.outputs {
            assert_eq!(
                find_secret(text.as_bytes(), &needles),
                None,
                "{} output",
                node.name
            );
        }
        assert_eq!(
            find_secret_in_tree(&node.state, &needles),
            None,
            "{} state directory",
            node.name
        );
    }
    let captured = std::fs::read(&wire).unwrap_or_default();
    assert!(!captured.is_empty(), "no wire capture");
    assert_eq!(find_secret(&captured, &needles), None, "wire capture");
}
