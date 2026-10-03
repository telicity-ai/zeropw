//! Native port of `tests/test_team_e2e.py` (`TeamEndToEndTestCase`): team
//! sync end to end across three simulated devices, each with its own state
//! directory and its own `zeropw-admin serve --team-listen` OS process, plus
//! one-shot `zeropw-admin` and `zeropw-agent` processes (docs/team-sync.md
//! section 1's whole narrative; stage 4's test list in section 13).
//!
//! Node A shares a project environment, invites B (admin) and C (user); C's
//! own node relays an HTTP call using the shared credential its agent never
//! sees; B narrows the connection's scope from its own node and C's next call
//! on the now-excluded path is refused, ending an already-running exec on C
//! that keeps calling back into the same path; A and B are then partitioned
//! (B's `serve` stopped), both edit the same connection while apart, B's
//! `serve` restarts, and all three nodes converge on one identical value-free
//! document with the losing edit's author alerted; finally A removes C (a
//! fact) and a secret version A puts afterwards is never decryptable by C's
//! node. A final sweep scans every node's state directory, every process's
//! captured output and the raw team-sync wire capture for the synthetic
//! values, in every encoding `tests/leakcheck.py` knows.
//!
//! Every product process is a native binary; the driver is this test. The
//! exec'd business CLI (formerly a Python urllib loop) is a `/bin/sh` loop
//! around the native `zeropw-democli whoami` (GET `/me` with a placeholder
//! bearer, redirects not followed). Each node's team port is chosen up front
//! because `serve --team-listen`'s startup line does not report it.
mod native_e2e;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use native_e2e::{
    ADMIN_BIN, AGENT_BIN, DEMOCLI_BIN, Serve, cli_json, find_secret, find_secret_in_tree,
    free_port, path_env,
};
use serde_json::{Value, json};
use zeropw::fake_upstream::FakeUpstream;

const SYNTHETIC: &str = "synthetic-token-team-e2e-0123456789";
const SYNTHETIC_V2: &str = "synthetic-token-team-e2e-post-removal-9876543210";
/// Generous polling deadline for cross-node convergence (the Python test
/// used 20 s; the VM may be slower).
const CONVERGE: Duration = Duration::from_secs(60);
/// Deadline for one admin/agent process (Python's `timeout=60`).
const PROCESS_TIMEOUT: Duration = Duration::from_secs(120);

/// The long-running exec'd CLI: create the ready file, then call GET `/me`
/// through the gateway every 0.2 s, appending each status to the heartbeat
/// file; on the first non-200 status write it to the refused file and exit 1
/// (exit 2 when the deadline passes first). A status of 0 means the gateway
/// was unreachable.
fn http_loop_script() -> String {
    format!(
        "#!/bin/sh\n\
         ready=\"$1\"; refused=\"$2\"; heartbeat=\"$3\"\n\
         : > \"$ready\"\n\
         end=$(( $(date +%s) + 90 ))\n\
         while [ \"$(date +%s)\" -lt \"$end\" ]; do\n\
         \x20 out=$('{democli}' whoami 2>/dev/null)\n\
         \x20 status=$(printf '%s\\n' \"$out\" | sed -n 's/.*\"status\": *\\([0-9][0-9]*\\)}}$/\\1/p')\n\
         \x20 [ -n \"$status\" ] || status=0\n\
         \x20 printf '%s\\n' \"$status\" >> \"$heartbeat\"\n\
         \x20 if [ \"$status\" != 200 ]; then printf '%s' \"$status\" > \"$refused\"; exit 1; fi\n\
         \x20 sleep 0.2\n\
         done\n\
         exit 2\n",
        democli = DEMOCLI_BIN
    )
}

/// Run `program args` with exactly `env`, `stdin` bytes (empty when none),
/// killing it after [`PROCESS_TIMEOUT`]; returns (exit code, stdout, stderr).
fn run(program: &str, args: &[&str], env: &[(&str, &str)], stdin: &[u8]) -> (i32, String, String) {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {program}: {e}"));
    let pid = child.id();
    let input = stdin.to_vec();
    let mut pipe = child.stdin.take().unwrap();
    let writer = thread::spawn(move || {
        let _ = pipe.write_all(&input);
    });
    let (tx, rx) = mpsc::channel();
    let waiter = thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    let output = match rx.recv_timeout(PROCESS_TIMEOUT) {
        Ok(output) => output.unwrap(),
        Err(_) => {
            // SAFETY: SIGKILL to the child we spawned and have not reaped.
            unsafe { libc::kill(pid as i32, libc::SIGKILL) };
            let _ = waiter.join();
            panic!("{program} {args:?} did not finish within {PROCESS_TIMEOUT:?}");
        }
    };
    let _ = waiter.join();
    let _ = writer.join();
    let code = output
        .status
        .code()
        .unwrap_or_else(|| panic!("{program} {args:?} killed: {:?}", output.status));
    (
        code,
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Every captured output, by who produced it.
type Transcript = Mutex<Vec<(String, String)>>;

/// One simulated team member device: its own state directory, admin/agent
/// process environments, and (once started) its own `serve --team-listen`.
struct Node {
    name: String,
    root: PathBuf,
    state: PathBuf,
    agent_home: PathBuf,
    admin_pass: String,
    recovery_pass: String,
    team_listen: String,
    serve: Option<Serve>,
    token: String,
    url: String,
}

impl Node {
    fn new(root: &Path, name: &str) -> Node {
        let root = root.join(name);
        let agent_home = root.join("agent-home");
        std::fs::create_dir_all(&agent_home).unwrap();
        std::fs::set_permissions(&agent_home, std::fs::Permissions::from_mode(0o700)).unwrap();
        Node {
            name: name.to_owned(),
            state: root.join("state"),
            root,
            agent_home,
            admin_pass: format!("admin-{name}-pass-team-e2e"),
            recovery_pass: format!("recovery-{name}-pass-team-e2e"),
            team_listen: format!("127.0.0.1:{}", free_port()),
            serve: None,
            token: String::new(),
            url: String::new(),
        }
    }

    /// One-shot admin CLI process; require exit `expect`; return its JSON.
    fn admin_in(&self, log: &Transcript, args: &[&str], stdin: &[u8], expect: i32) -> Value {
        let mut argv = vec!["--state-dir", self.state.to_str().unwrap()];
        argv.extend_from_slice(args);
        let path = path_env();
        let home = self.root.to_string_lossy().into_owned();
        let (code, out, err) = run(
            ADMIN_BIN,
            &argv,
            &[
                ("PATH", path.as_str()),
                ("HOME", home.as_str()),
                ("ZEROPW_ADMIN_PASSPHRASE", self.admin_pass.as_str()),
                ("ZEROPW_RECOVERY_PASSPHRASE", self.recovery_pass.as_str()),
            ],
            stdin,
        );
        // Invite strings/join output carry no values, but keep them quiet.
        if !args.contains(&"join") && !args.contains(&"invite") {
            let who = format!(
                "{} admin {}",
                self.name,
                args[..args.len().min(2)].join(" ")
            );
            log.lock().unwrap().push((who, format!("{out}{err}")));
        }
        assert_eq!(code, expect, "{} admin {args:?}: {err}", self.name);
        cli_json(code, &out, &err)
    }

    /// One-shot agent CLI process with only the gateway URL and the caller
    /// token; require exit `expect` when given.
    fn agent_in(&self, log: &Transcript, args: &[&str], expect: Option<i32>) -> (i32, Value) {
        let path = path_env();
        let home = self.agent_home.to_string_lossy().into_owned();
        let (code, out, err) = run(
            AGENT_BIN,
            args,
            &[
                ("PATH", path.as_str()),
                ("HOME", home.as_str()),
                ("ZEROPW_GATEWAY_URL", self.url.as_str()),
                ("ZEROPW_CALLER_TOKEN", self.token.as_str()),
            ],
            b"",
        );
        let who = format!(
            "{} agent {}",
            self.name,
            args[..args.len().min(3)].join(" ")
        );
        log.lock().unwrap().push((who, format!("{out}{err}")));
        if let Some(expect) = expect {
            assert_eq!(
                code, expect,
                "{} agent {args:?}: out={out} err={err}",
                self.name
            );
        }
        let payload = if out.trim().is_empty() { &err } else { &out };
        let value = if payload.trim().is_empty() {
            json!({})
        } else {
            serde_json::from_str(payload)
                .unwrap_or_else(|e| panic!("{} agent JSON ({e}): {payload:?}", self.name))
        };
        (code, value)
    }

    fn start_serve(&mut self, log: &Transcript, wire_capture: &Path) {
        let path = path_env();
        let home = self.root.to_string_lossy().into_owned();
        let capture = wire_capture.to_string_lossy().into_owned();
        let serve = Serve::start(
            &self.state,
            &[
                "--listen",
                "127.0.0.1:0",
                "--team-listen",
                &self.team_listen,
            ],
            &[
                ("PATH", path.as_str()),
                ("HOME", home.as_str()),
                ("ZEROPW_ADMIN_PASSPHRASE", self.admin_pass.as_str()),
                ("ZEROPW_TEAM_WIRE_CAPTURE", capture.as_str()),
            ],
        );
        log.lock().unwrap().push((
            format!("{} serve startup", self.name),
            serve.startup.to_string(),
        ));
        self.url = serve.url.clone();
        self.serve = Some(serve);
    }

    fn stop_serve(&mut self, log: &Transcript) {
        if let Some(mut serve) = self.serve.take() {
            let (_code, output) = serve.stop();
            log.lock()
                .unwrap()
                .push((format!("{} serve exit", self.name), output));
        }
    }
}

struct Team {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    transcript: Transcript,
    wire_capture: PathBuf,
    upstream: FakeUpstream,
    a: Node,
    b: Node,
    c: Node,
}

impl Team {
    fn new() -> Team {
        let tmp = tempfile::Builder::new().prefix("zpwte-").tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        Team {
            wire_capture: root.join("wire.log"),
            upstream: FakeUpstream::new(SYNTHETIC).start(),
            a: Node::new(&root, "a"),
            b: Node::new(&root, "b"),
            c: Node::new(&root, "c"),
            transcript: Mutex::new(Vec::new()),
            root,
            _tmp: tmp,
        }
    }

    /// No synthetic value in any captured output, any node's state
    /// directory or the raw team-sync wire capture; no agent wrote to its
    /// home directory.
    fn assert_no_secret_anywhere(&self) {
        let needles = [
            SYNTHETIC.as_bytes().to_vec(),
            SYNTHETIC_V2.as_bytes().to_vec(),
        ];
        for (who, text) in self.transcript.lock().unwrap().iter() {
            assert_eq!(
                find_secret(text.as_bytes(), &needles),
                None,
                "{who} output carried a secret value"
            );
        }
        for node in [&self.a, &self.b, &self.c] {
            assert_eq!(
                find_secret_in_tree(&node.state, &needles),
                None,
                "{}'s state directory carried a secret value",
                node.name
            );
        }
        let wire = std::fs::read(&self.wire_capture).unwrap_or_default();
        let wire = String::from_utf8_lossy(&wire);
        assert_eq!(
            find_secret(wire.as_bytes(), &needles),
            None,
            "the raw team-sync wire capture carried a secret value"
        );
        for node in [&self.a, &self.b, &self.c] {
            assert!(
                std::fs::read_dir(&node.agent_home)
                    .unwrap()
                    .next()
                    .is_none(),
                "{}'s agent side wrote something to its home directory",
                node.name
            );
        }
    }
}

impl Drop for Team {
    fn drop(&mut self) {
        for node in [&mut self.a, &mut self.b, &mut self.c] {
            if let Some(mut serve) = node.serve.take() {
                serve.stop();
            }
        }
        self.upstream.stop();
    }
}

/// Poll `predicate` until it returns `Some`, else fail with `msg`.
fn wait_until<T>(timeout: Duration, msg: &str, predicate: impl FnMut() -> Option<T>) -> T {
    native_e2e::until(timeout, predicate).unwrap_or_else(|| panic!("{msg}"))
}

/// Python truthiness of a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// `str(value)` of a JSON scalar as Python formats it into a path.
fn scalar_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[test]
fn full_team_lifecycle() {
    let mut team = Team::new();
    let log = &team.transcript;
    let wire = team.wire_capture.clone();

    // ------------------------------------------------ A: share an environment
    let http_loop = team.root.join("http_loop.sh");
    std::fs::write(&http_loop, http_loop_script()).unwrap();
    std::fs::set_permissions(&http_loop, std::fs::Permissions::from_mode(0o700)).unwrap();
    let upstream_target = format!("http://127.0.0.1:{}", team.upstream.port());

    let a = &mut team.a;
    a.admin_in(log, &["init"], b"", 0);
    a.admin_in(log, &["team", "init"], b"", 0);
    a.admin_in(log, &["project", "create", "demo"], b"", 0);
    a.admin_in(
        log,
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
        SYNTHETIC.as_bytes(),
        0,
    );
    a.admin_in(
        log,
        &[
            "connection",
            "create-http",
            "--id",
            "gh",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--service",
            "fake-code-host",
            "--secret-id",
            "gh-token",
            "--target",
            &upstream_target,
            "--auth",
            "bearer",
            "--methods",
            "GET,POST",
            "--path-prefixes",
            "/repos,/me",
            "--cli-program",
            http_loop.to_str().unwrap(),
        ],
        b"",
        0,
    );
    a.admin_in(
        log,
        &["team", "share", "--project", "demo", "--environment", "dev"],
        b"",
        0,
    );
    let env_a = "demo/dev";
    a.start_serve(log, &wire);

    // ------------------------------------------------------ invite + join B
    let a_listen = team.a.team_listen.clone();
    let invite_b = team.a.admin_in(
        log,
        &[
            "team",
            "invite",
            "--env",
            env_a,
            "--role",
            "admin",
            "--name",
            "bob",
            "--address",
            &a_listen,
        ],
        b"",
        0,
    )["invite"]
        .as_str()
        .unwrap()
        .to_owned();
    team.b.admin_in(log, &["init"], b"", 0);
    let join_b = team.b.admin_in(
        log,
        &[
            "team",
            "join",
            &invite_b,
            "--project",
            "team-shared",
            "--environment",
            "dev",
        ],
        b"",
        0,
    );
    let env_b = format!(
        "{}/{}",
        join_b["project"].as_str().unwrap(),
        join_b["environment"].as_str().unwrap()
    );
    team.b.start_serve(log, &wire);
    // Belt-and-suspenders (docs/team-sync.md section 12): B's own address
    // book already has A's address from the invite payload itself, but
    // register it explicitly too.
    team.b.admin_in(
        log,
        &[
            "team",
            "peers",
            "--env",
            &env_b,
            "--add",
            &a_listen,
            "--device",
            join_b["inviter_fingerprint"].as_str().unwrap(),
        ],
        b"",
        0,
    );

    // ------------------------------------------------------ invite + join C
    let invite_c = team.a.admin_in(
        log,
        &[
            "team",
            "invite",
            "--env",
            env_a,
            "--role",
            "user",
            "--name",
            "carol",
            "--address",
            &a_listen,
        ],
        b"",
        0,
    )["invite"]
        .as_str()
        .unwrap()
        .to_owned();
    team.c.admin_in(log, &["init"], b"", 0);
    let join_c = team.c.admin_in(
        log,
        &[
            "team",
            "join",
            &invite_c,
            "--project",
            "team-shared",
            "--environment",
            "dev",
        ],
        b"",
        0,
    );
    let env_c = format!(
        "{}/{}",
        join_c["project"].as_str().unwrap(),
        join_c["environment"].as_str().unwrap()
    );
    team.c.start_serve(log, &wire);

    // C creates its own principal + grant on the shared connection, and its
    // agent CLI request succeeds against the fake upstream through C's OWN
    // node's gateway: the shared credential is relayed by C's node, and C's
    // agent never sees it (proven at the end by the leak sweep).
    let c = &mut team.c;
    wait_until(
        CONVERGE,
        "C never derived the shared connection after joining",
        || {
            let listed = c.admin_in(log, &["connection", "list"], b"", 0);
            truthy(&listed["connections"]).then_some(())
        },
    );
    let principal_c = c.admin_in(log, &["principal", "create", "--id", "agent-c"], b"", 0);
    c.token = principal_c["token"].as_str().unwrap().to_owned();
    c.admin_in(
        log,
        &[
            "grant",
            "create",
            "--principal",
            "agent-c",
            "--connection",
            "gh",
            "--ttl",
            "1h",
        ],
        b"",
        0,
    );

    let (_code, repos) = c.agent_in(
        log,
        &[
            "request",
            "--connection",
            "gh",
            "--method",
            "GET",
            "--path",
            "/repos",
        ],
        Some(0),
    );
    let body: Value = serde_json::from_str(repos["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        (repos["status"].clone(), body),
        (json!(200), json!([{"name": "demo"}, {"name": "tools"}]))
    );
    let bearer = format!("Bearer {SYNTHETIC}");
    assert!(
        team.upstream
            .requests()
            .iter()
            .any(|r| r.headers.get("authorization") == Some(&bearer)),
        "the upstream never saw the relayed credential"
    );

    // ---------------------------------------------- long-running exec on C
    let ready = team.root.join("c-ready");
    let refused = team.root.join("c-refused");
    let heartbeat = team.root.join("c-heartbeat");
    let c = &team.c;
    let (_code, run) = c.agent_in(
        log,
        &[
            "exec",
            "--connection",
            "gh",
            "--",
            ready.to_str().unwrap(),
            refused.to_str().unwrap(),
            heartbeat.to_str().unwrap(),
        ],
        Some(0),
    );
    let run_id = run["run_id"].as_str().unwrap().to_owned();
    wait_until(CONVERGE, "C's long-running exec never started", || {
        ready.exists().then_some(())
    });
    wait_until(
        CONVERGE,
        "C's long-running exec never made a single successful call",
        || {
            std::fs::read_to_string(&heartbeat)
                .is_ok_and(|text| text.contains("200"))
                .then_some(())
        },
    );

    // ------------------------------------------ B narrows the connection scope
    team.b.admin_in(
        log,
        &[
            "connection",
            "update",
            "--id",
            "gh",
            "--methods",
            "GET",
            "--path-prefixes",
            "/repos",
        ],
        b"",
        0,
    );

    let deadline = Instant::now() + CONVERGE;
    let (mut final_code, mut final_reason) = (0, Value::Null);
    while Instant::now() < deadline {
        let (code, denied) = c.agent_in(
            log,
            &[
                "request",
                "--connection",
                "gh",
                "--method",
                "GET",
                "--path",
                "/me",
            ],
            None,
        );
        final_code = code;
        final_reason = denied["reason"].clone();
        if final_code != 0 {
            break;
        }
        thread::sleep(Duration::from_millis(300));
    }
    assert_ne!(
        final_code, 0,
        "C's request on the narrowed-out path was never refused"
    );
    assert_eq!(final_reason, "path_not_allowed");

    // The already-running exec's own next call on the same path is refused
    // too, ending it -- docs/team-sync.md section 6.5: a narrowing re-judges
    // an in-flight execution at its next relay call rather than cancelling it
    // outright (only a WIDENING stales the grant directly).
    wait_until(
        CONVERGE,
        "C's long-running exec never noticed the narrowed scope",
        || refused.exists().then_some(()),
    );
    let final_run = {
        let deadline = Instant::now() + CONVERGE;
        loop {
            let (_code, status) = c.agent_in(log, &["status", "--run", &run_id], Some(0));
            let state = status["state"].as_str().unwrap_or_default();
            if state != "queued" && state != "running" {
                break status;
            }
            assert!(
                Instant::now() <= deadline,
                "c: run {run_id} did not finish: {status}"
            );
            thread::sleep(Duration::from_millis(200));
        }
    };
    assert_eq!(final_run["state"], "completed", "{final_run}");
    assert_ne!(final_run["exit_code"], json!(0), "{final_run}");

    // ------------------------------------ A and B partitioned, then edit + rejoin
    // `connection update` has no `--description` flag; edit the same field
    // (path-prefixes) with two different values instead -- still "the same
    // target, concurrently" for section 7.2's override detection regardless
    // of which value ends up winning.
    team.b.stop_serve(log);
    team.a.admin_in(
        log,
        &[
            "connection",
            "update",
            "--id",
            "gh",
            "--path-prefixes",
            "/repos,/orgs",
        ],
        b"",
        0,
    );
    team.b.admin_in(
        log,
        &[
            "connection",
            "update",
            "--id",
            "gh",
            "--path-prefixes",
            "/repos,/issues",
        ],
        b"",
        0,
    );
    team.b.start_serve(log, &wire);

    let (a, b, c) = (&team.a, &team.b, &team.c);
    wait_until(
        CONVERGE,
        "A, B and C never converged to the identical document after B rejoined",
        || {
            let show_a = a.admin_in(log, &["team", "show", "--env", env_a], b"", 0);
            let show_b = b.admin_in(log, &["team", "show", "--env", &env_b], b"", 0);
            let show_c = c.admin_in(log, &["team", "show", "--env", &env_c], b"", 0);
            (show_a == show_b && show_b == show_c).then_some(())
        },
    );
    let final_view = a.admin_in(log, &["team", "show", "--env", env_a], b"", 0);
    let mut winner_paths: Vec<&str> =
        final_view["connections"]["gh"]["http_scope"]["path_prefixes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap())
            .collect();
    winner_paths.sort_unstable();
    winner_paths.dedup();
    assert!(
        winner_paths == ["/orgs", "/repos"] || winner_paths == ["/issues", "/repos"],
        "{winner_paths:?}"
    );
    let loser = if winner_paths == ["/orgs", "/repos"] {
        b
    } else {
        a
    };
    wait_until(
        CONVERGE,
        &format!(
            "{} (the loser of the concurrent edit) was never alerted",
            loser.name
        ),
        || {
            let alerts = loser.admin_in(log, &["alerts", "--limit", "200"], b"", 0);
            alerts["alerts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|alert| alert["alert"] == "team_op_overridden")
                .then_some(())
        },
    );

    // ---------------------------------------------------------- A removes C
    let c_fp = join_c["self_fingerprint"].as_str().unwrap();
    a.admin_in(
        log,
        &["team", "remove", "--env", env_a, "--device", c_fp],
        b"",
        0,
    );
    wait_until(CONVERGE, "C's node was never cut off after removal", || {
        let (code, _res) = c.agent_in(
            log,
            &[
                "request",
                "--connection",
                "gh",
                "--method",
                "GET",
                "--path",
                "/repos",
            ],
            None,
        );
        (code != 0).then_some(())
    });

    // A new secret version put on A after the removal must never be
    // decryptable by C: C's state directory has no generation-key file for
    // the new generation at all.
    a.admin_in(
        log,
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
        SYNTHETIC_V2.as_bytes(),
        0,
    );
    let new_gen = wait_until(
        CONVERGE,
        "A never rotated to a new DEK generation after removing C",
        || {
            let doc = a.admin_in(log, &["team", "show", "--env", env_a], b"", 0);
            let current = doc["dek"]["current"].clone();
            truthy(&current).then_some(current)
        },
    );
    let status = a.admin_in(log, &["team", "status", "--env", env_a], b"", 0);
    let env_id = status["env_id"].as_str().unwrap();
    assert!(
        !c.state
            .join("team")
            .join(env_id)
            .join("dek")
            .join(format!("{}.json", scalar_text(&new_gen)))
            .exists(),
        "C's state directory holds a key for a DEK generation created after its removal"
    );

    // ---------------------------------------------------------- final sweep
    // Touch every node once more before scanning.
    for node in [a, b, c] {
        node.admin_in(log, &["audit", "tail", "--limit", "1"], b"", 0);
    }
    team.assert_no_secret_anywhere();
}
