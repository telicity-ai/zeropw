//! Native ports of the multi-process end-to-end tests of
//! `tests/test_cli_e2e.py` (`CliEndToEndTestCase` and
//! `CompromiseResponseEndToEndTestCase`).
//!
//! Every ZeroPW component is its own OS process: the native administrator
//! (`zeropw-admin`) configures state, the trusted process is
//! `zeropw-admin ... serve`, and the agent side only runs `zeropw-agent` with
//! a gateway URL and its caller token in a minimal environment. The HTTP
//! connection's CLI program is the native `zeropw-democli`. The external
//! service is a controlled fake API in this test process, the SSH
//! destination is a real `sshd` started as the current user, and the
//! replacement-guidance email goes to a loopback SMTP receiver. The attacker
//! of the compromise-response flow is an HTTP client in this test process
//! that holds only the gateway URL and the caller token.
//!
//! Cancelling an SSH run stops the local `ssh` client only: a command
//! already running on the server keeps running (docs/security-design.md §5).
//! The test observes that through a heartbeat file and stops the remote
//! loops itself.
mod native_e2e;

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use native_e2e::{
    DEMOCLI_BIN, FakeSmtp, Processes, SMTP_PASSWORD, Sshd, assert_exec_children_held_no_key,
    find_secret, find_secret_in_tree, inspector_reports, parse_message, pid_alive, until, username,
    write_notify_config, write_ssh_inspector,
};
use serde_json::{Value, json};

const SYNTHETIC: &str = "synthetic-token-cli-e2e-0123456789";
const ADMIN: &str = "admin-passphrase-cli-e2e";
const RECOVERY: &str = "recovery-passphrase-cli-e2e";

const RUN_TIMEOUT: Duration = Duration::from_secs(60);

fn processes() -> Processes {
    Processes::new(SYNTHETIC, ADMIN, RECOVERY)
}

fn reason(value: &Value) -> &str {
    value["reason"].as_str().unwrap_or_default()
}

fn id_of(value: &Value) -> String {
    value["id"].as_str().expect("id").to_owned()
}

/// `admin_base`: init, the `demo` project and principal `agent-1`, whose
/// caller token becomes the agent's.
fn admin_base(p: &mut Processes) {
    let init = p.admin(&["init"], None, 0);
    let keys: BTreeSet<&str> = init
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, BTreeSet::from(["state_dir", "kms_key_id"]));
    p.admin(&["project", "create", "demo"], None, 0);
    let principal = p.admin(&["principal", "create", "--id", "agent-1"], None, 0);
    p.token = principal["token"].as_str().unwrap().to_owned();
    assert!(p.token.starts_with("zpwc_"));
}

// ------------------------------------------------------------------ HTTP

#[test]
fn test_http_connection_through_admin_serve_and_agent_processes() {
    let mut p = processes();
    admin_base(&mut p);
    p.admin(
        &[
            "secret",
            "put",
            "--id",
            "gh",
            "--kind",
            "api_key",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--stdin",
        ],
        Some(SYNTHETIC.as_bytes()),
        0,
    );
    let target = format!("http://127.0.0.1:{}", p.upstream.port());
    p.admin(
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
            "gh",
            "--target",
            &target,
            "--auth",
            "bearer",
            "--methods",
            "GET,POST",
            "--path-prefixes",
            "/repos,/me,/echo-headers",
            "--cli-program",
            DEMOCLI_BIN,
        ],
        None,
        0,
    );
    let grant = p.admin(
        &[
            "grant",
            "create",
            "--principal",
            "agent-1",
            "--connection",
            "gh",
            "--ttl",
            "1h",
            "--max-uses",
            "50",
        ],
        None,
        0,
    );
    p.start_serve();

    // One connection, several different operations, no registration.
    let (_code, listed) = p.agent(&["list-connections"], Some(0));
    let ids: Vec<&str> = listed["connections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["gh"]);
    assert!(!listed.to_string().contains("secret_id"));
    let (_code, repos) = p.agent(
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
    let repos_body: Value = serde_json::from_str(repos["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        (repos["status"].clone(), repos_body),
        (json!(200), json!([{"name": "demo"}, {"name": "tools"}]))
    );
    let (_code, issue) = p.agent(
        &[
            "request",
            "--connection",
            "gh",
            "--method",
            "POST",
            "--path",
            "/repos/demo/issues",
            "--header",
            "Content-Type: application/json",
            "--body",
            r#"{"title": "from agent"}"#,
        ],
        Some(0),
    );
    let issue_body: Value = serde_json::from_str(issue["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        (issue["status"].clone(), issue_body["title"].clone()),
        (json!(201), json!("from agent"))
    );
    let (_code, run) = p.agent(&["exec", "--connection", "gh", "--", "whoami"], Some(0));
    let whoami = p.wait_run(run["run_id"].as_str().unwrap(), RUN_TIMEOUT);
    assert_eq!(
        (whoami["state"].clone(), whoami["exit_code"].clone()),
        (json!("completed"), json!(0)),
        "{whoami}"
    );
    let whoami_stdout: Value = serde_json::from_str(whoami["stdout"].as_str().unwrap()).unwrap();
    assert_eq!(whoami_stdout["body"], json!({"login": "synthetic-user"}));

    // The CLI child holds nothing but the opaque base URL.
    let (_code, run) = p.agent(&["exec", "--connection", "gh", "--", "steal"], Some(0));
    let steal = p.wait_run(run["run_id"].as_str().unwrap(), RUN_TIMEOUT);
    assert_eq!(steal["state"], "completed", "{steal}");
    let report: Value = serde_json::from_str(steal["stdout"].as_str().unwrap()).unwrap();
    // __CF_USER_TEXT_ENCODING is added by macOS CoreFoundation inside the
    // process, not by ZeroPW.
    let mut env_names: Vec<&str> = report["env_names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap())
        .filter(|n| *n != "__CF_USER_TEXT_ENCODING")
        .collect();
    env_names.sort_unstable();
    assert_eq!(
        env_names,
        [
            "HOME",
            "LANG",
            "PATH",
            "TMPDIR",
            "ZEROPW_API_BASE_URL",
            "ZEROPW_RUN_ID"
        ]
    );
    assert_eq!(
        report["home_entries"],
        json!([]),
        "the exec run directory (HOME) must be empty for an HTTP CLI"
    );
    let probes = report["probes"].as_object().unwrap();
    assert!(
        probes.values().all(|v| v == "missing"),
        "{}",
        report["probes"]
    );
    assert_eq!(probes.len(), 8);
    assert!(!report.to_string().contains(&*p.state.to_string_lossy()));

    // The upstream saw the real synthetic credential every time, never the
    // CLI placeholder.
    let auth: BTreeSet<Option<String>> = p
        .upstream
        .requests()
        .iter()
        .map(|r| r.headers.get("authorization").cloned())
        .collect();
    assert_eq!(auth, BTreeSet::from([Some(format!("Bearer {SYNTHETIC}"))]));
    assert_eq!(p.upstream.requests().len(), 3);

    // Reflection is refused and the agent CLI exits non-zero with the
    // reason; so is a path outside the scope.
    let (code, reflected) = p.agent(
        &[
            "request",
            "--connection",
            "gh",
            "--method",
            "GET",
            "--path",
            "/echo-headers",
        ],
        None,
    );
    assert_eq!(
        (code != 0, reason(&reflected)),
        (true, "credential_reflection_blocked")
    );
    let (code, denied) = p.agent(
        &[
            "request",
            "--connection",
            "gh",
            "--method",
            "GET",
            "--path",
            "/debug/token",
        ],
        None,
    );
    assert_eq!((code != 0, reason(&denied)), (true, "path_not_allowed"));

    // Revocation by a separate admin process while serve is running.
    p.admin(&["grant", "revoke", "--id", &id_of(&grant)], None, 0);
    let (code, revoked) = p.agent(
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
    assert_eq!((code != 0, reason(&revoked)), (true, "grant_revoked"));
    let (code, refused) = p.agent(&["exec", "--connection", "gh", "--", "whoami"], None);
    assert_eq!((code != 0, reason(&refused)), (true, "grant_revoked"));
    // Only the blocked /echo-headers call was added.
    assert_eq!(p.upstream.requests().len(), 4);

    // Global stop and resume from the admin process.
    p.admin(
        &[
            "grant",
            "create",
            "--principal",
            "agent-1",
            "--connection",
            "gh",
            "--ttl",
            "1h",
        ],
        None,
        0,
    );
    p.admin(&["stop-all"], None, 0);
    let (_code, stopped) = p.agent(&["list-connections"], Some(0));
    assert_eq!(stopped["connections"], json!([]));
    let (code, refused) = p.agent(
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
    assert_eq!((code != 0, reason(&refused)), (true, "global_stop"));
    p.admin(&["resume"], None, 0);
    let (_code, back) = p.agent(
        &[
            "request",
            "--connection",
            "gh",
            "--method",
            "GET",
            "--path",
            "/me",
        ],
        Some(0),
    );
    assert_eq!(back["status"], 200);

    // Value-free audit records and alerts for the administrator.
    let tail = p.admin(&["audit", "tail", "--limit", "500"], None, 0);
    let events: BTreeSet<&str> = tail["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["event"].as_str().unwrap())
        .collect();
    for expected in [
        "http_relay",
        "tools_request",
        "tools_exec",
        "run_start",
        "run_finish",
        "grant_revoke",
        "stop_all",
        "resume",
    ] {
        assert!(events.contains(expected), "{expected} not audited");
    }
    let alerts = p.admin(&["alerts", "--limit", "100"], None, 0);
    let alerts: BTreeSet<&str> = alerts["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["alert"].as_str().unwrap())
        .collect();
    assert!(alerts.contains("credential_reflection"));

    let (code, serve_output) = p.stop_serve();
    assert_eq!(code, 0, "{serve_output}");
    p.assert_no_secret_anywhere(SYNTHETIC, None);
    assert!(
        p.agent_home_is_empty(),
        "the agent side wrote nothing to its home directory"
    );
}

// ------------------------------------------------------------------- SSH

fn beats(heartbeat: &Path) -> usize {
    std::fs::read(heartbeat)
        .map(|bytes| {
            bytes
                .split(|&b| b == b'\n')
                .filter(|l| !l.is_empty())
                .count()
        })
        .unwrap_or(0)
}

/// Stop every heartbeat loop still running on sshd (each checks the stop
/// file between beats).
fn stop_remote_loops(root: &Path) {
    let stop = root.join("remote-stop");
    if std::fs::write(&stop, b"").is_err() {
        return; // the directory is gone; the loops end on their next failed append
    }
    let mut beating: Vec<PathBuf> = std::fs::read_dir(root)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("heartbeat-"))
                })
                .collect()
        })
        .unwrap_or_default();
    beating.sort();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut counts: Vec<usize> = beating.iter().map(PathBuf::as_path).map(beats).collect();
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
        let now: Vec<usize> = beating.iter().map(PathBuf::as_path).map(beats).collect();
        if now == counts {
            break;
        }
        counts = now;
    }
    let _ = std::fs::remove_file(&stop);
}

/// Runs [`stop_remote_loops`] on drop, before `sshd` is killed (declared
/// after it), whether the test passed or not.
struct RemoteLoops(PathBuf);

impl Drop for RemoteLoops {
    fn drop(&mut self) {
        stop_remote_loops(&self.0);
    }
}

fn assert_long_run_cancelled_by(p: &Processes, reports: &Path, admin_argv: &[&str], why: &str) {
    let heartbeat = p.root.join(format!("heartbeat-{why}"));
    let stop = p.root.join("remote-stop");
    // One argument: ssh hands it to the remote login shell. The loop ends by
    // itself after ~60 s, when the stop file appears, or when the test
    // directory is gone (the append fails).
    let remote = format!(
        "i=0; while [ $i -lt 600 ] && [ ! -e '{}' ] && echo beat >> '{}'; do i=$((i+1)); sleep 0.1; done",
        stop.display(),
        heartbeat.display()
    );
    let known: BTreeSet<i32> = inspector_reports(reports).iter().map(|r| r.pid).collect();
    let (_code, run) = p.agent(&["exec", "--connection", "box", "--", &remote], Some(0));
    let run_id = run["run_id"].as_str().unwrap().to_owned();
    let started = Instant::now();
    assert!(
        until(Duration::from_secs(20), || (beats(&heartbeat) > 0)
            .then_some(()))
        .is_some(),
        "the long remote command never started on sshd"
    );
    // The inspector names its report after its pid, which the real ssh
    // client keeps (exec).
    let fresh: Vec<i32> = inspector_reports(reports)
        .iter()
        .map(|r| r.pid)
        .filter(|pid| !known.contains(pid))
        .collect();
    assert_eq!(fresh.len(), 1, "new inspector reports: {fresh:?}");
    let client_pid = fresh[0];
    assert!(pid_alive(client_pid));
    p.admin(admin_argv, None, 0);
    let last = p.wait_run(&run_id, Duration::from_secs(30));
    assert_eq!(
        (last["state"].as_str(), last["reason"].as_str()),
        (Some("cancelled"), Some(why)),
        "{last}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "cancellation must not wait for the remote command"
    );
    // What cancellation does stop: the local ssh client process.
    assert!(
        until(Duration::from_secs(10), || (!pid_alive(client_pid))
            .then_some(()))
        .is_some(),
        "the local ssh client still runs after its run was cancelled"
    );
    // Documented limit (docs/security-design.md §5, docs/implementation.md
    // §6/§8): cancelling kills the local ssh client; the command already
    // running on the server is not ended by ZeroPW.
    let at_cancel = beats(&heartbeat);
    assert!(
        until(Duration::from_secs(10), || (beats(&heartbeat)
            > at_cancel + 3)
            .then_some(()))
        .is_some(),
        "the remote command stopped: update the documented SSH cancellation limit"
    );
    stop_remote_loops(&p.root);
}

#[test]
fn test_ssh_connection_through_admin_serve_agent_processes_and_real_sshd() {
    // Fails (never silently passes) when sshd/ssh/ssh-keygen are missing.
    native_e2e::ssh_tools();
    let mut p = processes();
    admin_base(&mut p);
    let user_key = zeropw::sshwire::generate_ed25519_private_key("cli-e2e");
    let private_pem = user_key.to_openssh_private_key();
    let sshd = Sshd::start(
        &p.root,
        &user_key.public.to_authorized_key("cli-e2e").unwrap(),
    );
    // Dropped before sshd (reverse declaration order).
    let _remote_loops = RemoteLoops(p.root.clone());
    // Records what each exec child sees, then runs ssh.
    let (inspector, reports) = write_ssh_inspector(&p.root);
    let key_dir = p.root.join("admin-only");
    std::fs::create_dir(&key_dir).unwrap();
    std::fs::set_permissions(&key_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let key_file = key_dir.join("id_ed25519");
    std::fs::write(&key_file, &private_pem).unwrap();
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    p.admin(
        &[
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
            "--value-file",
            &key_file.to_string_lossy(),
        ],
        None,
        0,
    );
    // The only plaintext copy lived in the administrator's own directory.
    std::fs::remove_file(&key_file).unwrap();
    let port = sshd.port.to_string();
    let user = username();
    p.admin(
        &[
            "connection",
            "create-ssh",
            "--id",
            "box",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--service",
            "ssh-box",
            "--secret-id",
            "box-key",
            "--host",
            "127.0.0.1",
            "--port",
            &port,
            "--username",
            &user,
            "--host-key",
            &sshd.host_key_line,
            "--cli-program",
            &inspector.to_string_lossy(),
        ],
        None,
        0,
    );
    let grant = p.admin(
        &[
            "grant",
            "create",
            "--principal",
            "agent-1",
            "--connection",
            "box",
            "--ttl",
            "1h",
        ],
        None,
        0,
    );
    p.start_serve();
    assert_eq!(p.serve.as_ref().unwrap().startup["ssh_signer"], "available");

    // Two different remote commands on one connection.
    let (_code, run) = p.agent(
        &[
            "exec",
            "--connection",
            "box",
            "--",
            "echo",
            "cli-e2e-ssh-first",
        ],
        Some(0),
    );
    let first = p.wait_run(run["run_id"].as_str().unwrap(), RUN_TIMEOUT);
    assert_eq!(
        (
            first["state"].as_str(),
            first["exit_code"].as_i64(),
            first["stdout"].as_str().map(str::trim)
        ),
        (Some("completed"), Some(0), Some("cli-e2e-ssh-first")),
        "{first}"
    );
    let (_code, run) = p.agent(
        &[
            "exec",
            "--connection",
            "box",
            "--",
            "printf",
            "second-%s",
            "command",
        ],
        Some(0),
    );
    let second = p.wait_run(run["run_id"].as_str().unwrap(), RUN_TIMEOUT);
    assert_eq!(
        (
            second["state"].as_str(),
            second["stdout"].as_str().map(str::trim)
        ),
        (Some("completed"), Some("second-command")),
        "{second}"
    );

    // A long remote command's run is cancelled when a separate admin
    // process stops everything.
    assert_long_run_cancelled_by(&p, &reports, &["stop-all"], "global_stop");
    let (code, refused) = p.agent(
        &["exec", "--connection", "box", "--", "echo", "must-not-run"],
        None,
    );
    assert_eq!((code != 0, reason(&refused)), (true, "global_stop"));
    p.admin(&["resume"], None, 0);

    // Revoking the grant from the admin process cancels the in-flight run
    // (the local ssh client); the next exec is refused.
    let grant_id = id_of(&grant);
    assert_long_run_cancelled_by(
        &p,
        &reports,
        &["grant", "revoke", "--id", &grant_id],
        "grant_revoked",
    );
    let (code, refused) = p.agent(
        &["exec", "--connection", "box", "--", "echo", "must-not-run"],
        None,
    );
    assert_eq!((code != 0, reason(&refused)), (true, "grant_revoked"));

    // Disabling the connection from the admin process cancels the in-flight
    // run as well (local client only).
    p.admin(
        &[
            "grant",
            "create",
            "--principal",
            "agent-1",
            "--connection",
            "box",
            "--ttl",
            "1h",
        ],
        None,
        0,
    );
    assert_long_run_cancelled_by(
        &p,
        &reports,
        &["connection", "disable", "--id", "box"],
        "connection_disabled",
    );
    let (code, refused) = p.agent(
        &["exec", "--connection", "box", "--", "echo", "must-not-run"],
        None,
    );
    assert_eq!((code != 0, reason(&refused)), (true, "connection_disabled"));

    let tail = p.admin(&["audit", "tail", "--limit", "500"], None, 0);
    let records = tail["records"].as_array().unwrap();
    let signs: Vec<&Value> = records
        .iter()
        .filter(|r| r["event"] == "ssh_sign" && r["result"] == "ok")
        .collect();
    assert!(signs.len() >= 3, "{} ssh_sign ok records", signs.len());
    assert!(
        signs
            .iter()
            .all(|r| r.get("policy_version").is_some_and(|v| !v.is_null()))
    );
    let cancels: BTreeSet<(String, String)> = records
        .iter()
        .map(|r| {
            (
                r["event"].as_str().unwrap_or_default().to_owned(),
                r["reason"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    for expected in ["global_stop", "grant_revoked", "connection_disabled"] {
        assert!(
            cancels.contains(&("run_cancel".to_owned(), expected.to_owned())),
            "no run_cancel audited for {expected}"
        );
    }

    let (code, serve_output) = p.stop_serve();
    assert_eq!(code, 0, "{serve_output}");
    p.assert_no_secret_anywhere(SYNTHETIC, Some(&private_pem));
    // Every exec child (two commands and three cancelled loops): run
    // directory and environment hold no key.
    assert_exec_children_held_no_key(&reports, &private_pem, 5);
    assert!(
        p.agent_home_is_empty(),
        "the agent side wrote nothing to its home directory"
    );
}

// ------------------------------------------------------ compromise response

/// One `POST <gateway>/v1/tools/reveal_secret` with the caller token; any
/// HTTP status is accepted, a transport failure is not. Returns the raw
/// response.
fn post_unknown_tool(gateway_url: &str, token: &str) -> String {
    let rest = gateway_url
        .strip_prefix("http://")
        .unwrap_or_else(|| panic!("gateway URL is not http: {gateway_url}"));
    let (authority, base_path) = rest.split_once('/').unwrap_or((rest, ""));
    let base_path = base_path.trim_end_matches('/');
    let path = if base_path.is_empty() {
        "/v1/tools/reveal_secret".to_owned()
    } else {
        format!("/{base_path}/v1/tools/reveal_secret")
    };
    let mut stream = TcpStream::connect(authority).expect("attacker connects to the gateway");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut reader = BufReader::new(stream);
    let mut head = String::new();
    let mut length: Option<usize> = None;
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .expect("attacker reads the response head");
        assert!(
            n > 0,
            "gateway closed before the response head ended: {head:?}"
        );
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().ok();
        }
        let end = line == "\r\n" || line == "\n";
        head.push_str(&line);
        if end {
            break;
        }
    }
    assert!(
        head.starts_with("HTTP/1."),
        "not an HTTP response: {head:?}"
    );
    let mut body = Vec::new();
    match length {
        Some(length) => {
            body.resize(length, 0);
            reader
                .read_exact(&mut body)
                .expect("attacker reads the body");
        }
        None => {
            reader
                .read_to_end(&mut body)
                .expect("attacker reads the body");
        }
    }
    format!("{head}{}", String::from_utf8_lossy(&body))
}

/// docs/compromise-response.md §9 stage 5: the attacker gets only what the
/// compromised agent runtime itself holds -- the gateway URL and its own
/// caller token. Two calls to a tool ZeroPW never registered trip the
/// detector's `unknown_tool` strong rule at its threshold of 2.
fn run_attacker(p: &Processes) {
    let mut transcript = String::new();
    for _ in 0..2 {
        transcript.push_str(&post_unknown_tool(&p.url, &p.token));
    }
    p.record("attacker", &transcript);
}

fn notification_sent(p: &Processes, incident_id: &str) -> Value {
    until(Duration::from_secs(20), || {
        let shown = p.admin(&["incident", "show", "--id", incident_id], None, 0);
        (shown["notification"]["status"] == "sent").then_some(shown)
    })
    .expect("incident notification never reached status=sent")
}

#[test]
fn test_auto_lockdown_exposure_assessment_email_and_recovery() {
    let mut p = processes();
    let mut smtp = FakeSmtp::new();
    smtp.start();

    let init = p.admin(&["init"], None, 0);
    let keys: BTreeSet<&str> = init
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, BTreeSet::from(["state_dir", "kms_key_id"]));
    p.admin(&["project", "create", "demo"], None, 0);
    // A dedicated runtime id, as docs/compromise-response.md §4.3 and §9
    // require (`principal create --runtime <id>`).
    let principal = p.admin(
        &[
            "principal",
            "create",
            "--id",
            "agent-1b",
            "--runtime",
            "box-1",
        ],
        None,
        0,
    );
    p.token = principal["token"].as_str().unwrap().to_owned();
    assert!(p.token.starts_with("zpwc_"));

    let target = format!("http://127.0.0.1:{}", p.upstream.port());
    p.admin(
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
        Some(SYNTHETIC.as_bytes()),
        0,
    );
    p.admin(
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
            &target,
            "--auth",
            "bearer",
            "--methods",
            "GET",
            "--path-prefixes",
            "/repos",
        ],
        None,
        0,
    );
    p.admin(
        &[
            "grant",
            "create",
            "--principal",
            "agent-1b",
            "--connection",
            "gh",
            "--ttl",
            "1h",
            "--max-uses",
            "50",
        ],
        None,
        0,
    );

    let jira_secret_value = "synthetic-jira-unused-0123456789";
    p.admin(
        &[
            "secret",
            "put",
            "--id",
            "jira-token",
            "--kind",
            "api_key",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--stdin",
        ],
        Some(jira_secret_value.as_bytes()),
        0,
    );
    p.admin(
        &[
            "connection",
            "create-http",
            "--id",
            "jira",
            "--project",
            "demo",
            "--environment",
            "dev",
            "--service",
            "fake-jira",
            "--secret-id",
            "jira-token",
            "--target",
            &target,
            "--auth",
            "bearer",
            "--methods",
            "GET",
            "--path-prefixes",
            "/repos",
        ],
        None,
        0,
    );
    // Granted but never used: the exposure assessment must call this one
    // "recommended", not "mandatory".
    p.admin(
        &[
            "grant",
            "create",
            "--principal",
            "agent-1b",
            "--connection",
            "jira",
            "--ttl",
            "1h",
        ],
        None,
        0,
    );

    write_notify_config(&p.state, &p.root, &smtp);
    p.start_serve();

    // Normal agent use before the attack: one list, one request on the
    // connection that will come out "mandatory" once the incident opens.
    let (_code, listed) = p.agent(&["list-connections"], Some(0));
    let mut ids: Vec<&str> = listed["connections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, ["gh", "jira"]);
    let (_code, repos) = p.agent(
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
    assert_eq!(repos["status"], 200);

    // The attack: two unknown-tool calls from a separate client holding only
    // the gateway URL and this same caller token. The detector runs
    // synchronously inside serve, so by the time this returns the incident,
    // lockdown and email delivery attempt are complete.
    run_attacker(&p);

    let incidents = p.admin(&["incident", "list"], None, 0);
    let open: Vec<&Value> = incidents["incidents"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["status"] == "open")
        .collect();
    assert_eq!(open.len(), 1, "{incidents}");
    let incident = open[0];
    assert_eq!(incident["scope"], "principal");
    assert_eq!(incident["rule"], "unknown_tool");
    assert_eq!(incident["trigger"], "auto");
    assert_eq!(incident["principals"], json!(["agent-1b"]));
    let incident_id = id_of(incident);

    // The agent's own, otherwise-legitimate next calls are now refused: the
    // token was disabled, not just the one grant.
    let (code, refused) = p.agent(&["list-connections"], None);
    assert_eq!((code != 0, reason(&refused)), (true, "principal_disabled"));
    let (code, refused) = p.agent(
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
    assert_eq!((code != 0, reason(&refused)), (true, "principal_disabled"));

    // resume is refused while the incident is open.
    let resumed = p.admin(&["resume"], None, 1);
    assert_eq!(resumed["reason"], "incident_open");

    // The administrator sees the intrusion alert.
    let alerts = p.admin(&["alerts", "--limit", "100"], None, 0);
    assert!(
        alerts["alerts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["alert"] == "intrusion")
    );

    // The replacement-guidance email: exactly one message, sent through the
    // configured (loopback, plain-mode) SMTP path.
    let shown = notification_sent(&p, &incident_id);
    assert_eq!(shown["notification"]["status"], "sent");
    let messages = smtp.messages();
    assert_eq!(messages.len(), 1);
    let (subject, body) = parse_message(&messages[0].data);
    assert!(subject.contains(&incident_id), "{subject}");
    assert!(body.contains(&incident_id));

    let (mandatory_block, recommended_block) = body
        .split_once("4. Recommended rotation")
        .expect("the email has a recommended-replacement section");
    assert!(mandatory_block.contains("gh-token"));
    assert!(!recommended_block.contains("gh-token"));
    assert!(recommended_block.contains("jira-token"));
    assert!(!mandatory_block.contains("jira-token"));

    assert!(body.contains("6. Recovery commands"));
    assert!(body.contains(&format!("incident show --id {incident_id}")));
    assert!(body.contains(&format!("incident close --id {incident_id}")));
    assert!(body.contains("principal create --runtime"));
    assert!(body.contains("grant create"));
    assert!(body.contains("resume"));

    for text in [&subject, &body] {
        assert!(!text.contains("http://"));
        assert!(!text.contains("https://"));
    }

    let mut secret_patterns: Vec<Vec<u8>> = Vec::new();
    for value in [
        SYNTHETIC,
        jira_secret_value,
        p.token.as_str(),
        SMTP_PASSWORD,
    ] {
        secret_patterns.extend(zeropw::runs::credential_patterns(value.as_bytes()));
    }
    assert!(!zeropw::runs::contains_sensitive(
        format!("{subject}\n{body}").as_bytes(),
        &secret_patterns
    ));

    let smtp_password_bytes = vec![SMTP_PASSWORD.as_bytes().to_vec()];
    let audit_path = p.state.join("audit").join("audit.jsonl");
    assert_eq!(
        find_secret(&std::fs::read(&audit_path).unwrap(), &smtp_password_bytes),
        None
    );
    let alerts_path = p.state.join("audit").join("alerts.jsonl");
    if alerts_path.exists() {
        assert_eq!(
            find_secret(&std::fs::read(&alerts_path).unwrap(), &smtp_password_bytes),
            None
        );
    }
    let incident_path = p
        .state
        .join("incidents")
        .join(format!("{incident_id}.json"));
    assert_eq!(
        find_secret(
            &std::fs::read(&incident_path).unwrap(),
            &smtp_password_bytes
        ),
        None
    );

    // Recovery (§7): close the incident (admin passphrase from the
    // environment), create a fresh principal, resume.
    let closed = p.admin(&["incident", "close", "--id", &incident_id], None, 0);
    assert_eq!(closed["status"], "closed");

    let new_principal = p.admin(
        &[
            "principal",
            "create",
            "--id",
            "agent-2",
            "--runtime",
            "box-1",
        ],
        None,
        0,
    );
    let new_token = new_principal["token"].as_str().unwrap().to_owned();
    p.admin(
        &[
            "grant",
            "create",
            "--principal",
            "agent-2",
            "--connection",
            "gh",
            "--ttl",
            "1h",
        ],
        None,
        0,
    );

    let resumed_ok = p.admin(&["resume"], None, 0);
    assert!(
        resumed_ok.get("incident_open").is_some_and(Value::is_null),
        "{resumed_ok}"
    );
    assert_eq!(resumed_ok["stopped"], false);

    let old_token = std::mem::replace(&mut p.token, new_token);
    let (_code, ok_request) = p.agent(
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
    assert_eq!(ok_request["status"], 200);

    let (code, still_refused) = p.agent_as(
        &old_token,
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
    assert_eq!(
        (code != 0, reason(&still_refused)),
        (true, "principal_disabled")
    );

    let (code, serve_output) = p.stop_serve();
    assert_eq!(code, 0, "{serve_output}");
    assert_eq!(
        find_secret(serve_output.as_bytes(), &smtp_password_bytes),
        None
    );
    p.assert_no_secret_anywhere(SYNTHETIC, None);
    assert_eq!(find_secret_in_tree(&p.state, &smtp_password_bytes), None);
}
