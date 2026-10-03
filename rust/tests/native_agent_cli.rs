//! The native agent CLI against a real in-process `ZeroPWServer` and the
//! real gateway (port of `tests/test_agent_cli.py`, formerly run against the
//! Python server with a mocked relay): JSON in/out, exit codes and caller
//! token hygiene. The upstream is the synthetic fake API.
mod native_e2e;

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use zeropw::context::{Config, Context};
use zeropw::fake_upstream::FakeUpstream;
use zeropw::policy::{CliProfile, Connection, HttpAuth, HttpScope, HttpTarget};
use zeropw::server::ZeroPWServer;

const SYNTHETIC: &str = "synthetic-token-0123456789abcdef";

/// Prints its arguments; `sleep` keeps it running.
const ECHO_SCRIPT: &str = "#!/bin/sh\necho \"$*\"\nif [ \"$1\" = sleep ]; then exec sleep 30; fi\n";

struct Fixture {
    tmp: tempfile::TempDir,
    root: PathBuf,
    ctx: Arc<Context>,
    token: String,
    server: ZeroPWServer,
    upstream: FakeUpstream,
    registry: Arc<zeropw::runs::RunRegistry>,
}

impl Fixture {
    fn new() -> Fixture {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().to_path_buf();
        let ctx = Arc::new(
            Context::initialize(
                root.join("state"),
                native_e2e::ADMIN_PASSPHRASE,
                native_e2e::RECOVERY_PASSPHRASE,
                Config::default(),
                zeropw::clock::system(),
            )
            .unwrap(),
        );
        ctx.projects
            .create("demo", zeropw::projects::DEFAULT_ENVIRONMENTS)
            .unwrap();
        ctx.vault
            .put_secret(
                "gh-token",
                "api_key",
                SYNTHETIC.as_bytes(),
                "demo",
                "dev",
                true,
            )
            .unwrap();
        let token = ctx.policy.create_principal("agent-1", "default").unwrap();
        let program = root.join("echo.sh");
        std::fs::write(&program, ECHO_SCRIPT).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let upstream = FakeUpstream::new(SYNTHETIC).start();
        ctx.policy
            .create_connection(
                Connection::new(
                    "gh",
                    "demo",
                    "dev",
                    "fake-github",
                    "http",
                    "gh-token",
                    None,
                    "demo",
                    Some(
                        HttpTarget::new(
                            "http",
                            "127.0.0.1",
                            i64::from(upstream.port()),
                            None,
                            false,
                        )
                        .unwrap(),
                    ),
                    Some(HttpAuth::bearer()),
                    Some(
                        HttpScope::new(
                            Some(vec!["GET".into(), "POST".into()]),
                            Some(vec!["/repos".into(), "/me".into(), "/echo-headers".into()]),
                            Vec::new(),
                        )
                        .unwrap(),
                    ),
                    None,
                    Some(
                        CliProfile::new(program.to_string_lossy(), "http", None, BTreeMap::new())
                            .unwrap(),
                    ),
                    0,
                    "active",
                    "",
                    "",
                )
                .unwrap(),
            )
            .unwrap();
        ctx.policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        let registry = zeropw::tools::install(Arc::clone(&ctx));
        let server = ZeroPWServer::new(Arc::clone(&ctx), None, None).unwrap();
        server.serve_in_thread().unwrap();
        zeropw::tools::set_public_url(&ctx, &server.url()).unwrap();
        Fixture {
            tmp,
            root,
            ctx,
            token,
            server,
            upstream,
            registry,
        }
    }

    fn env(&self) -> Vec<(&'static str, String)> {
        vec![
            ("PATH", native_e2e::path_env()),
            ("HOME", self.tmp.path().to_string_lossy().into_owned()),
            ("ZEROPW_GATEWAY_URL", self.server.url()),
            ("ZEROPW_CALLER_TOKEN", self.token.clone()),
        ]
    }

    fn cli_env(&self, args: &[&str], env: &[(&'static str, String)]) -> Output {
        Command::new(native_e2e::AGENT_BIN)
            .args(args)
            .env_clear()
            .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
            .current_dir(&self.root)
            .output()
            .unwrap()
    }

    fn cli(&self, args: &[&str]) -> Output {
        self.cli_env(args, &self.env())
    }

    fn with(&self, name: &'static str, value: &str) -> Vec<(&'static str, String)> {
        let mut env = self.env();
        env.retain(|(k, _)| *k != name);
        env.push((name, value.to_owned()));
        env
    }

    fn ok(&self, args: &[&str]) -> Value {
        let output = self.cli(args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{args:?}: {stderr}");
        assert_eq!(stderr, "", "{args:?}");
        serde_json::from_slice(&output.stdout).unwrap()
    }

    /// Exit 1, nothing on stdout, the JSON error from stderr.
    fn error(&self, output: &Output) -> Value {
        assert_eq!(
            output.status.code(),
            Some(1),
            "stdout={}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(output.stdout.is_empty());
        serde_json::from_slice(&output.stderr).unwrap()
    }

    fn wait_state(&self, run_id: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let view = self.ok(&["status", "--run", run_id]);
            let state = view["state"].as_str().unwrap();
            if (state != "queued" && state != "running") || Instant::now() > deadline {
                return view;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn assert_token_never_logged(&self) {
        assert!(!self.server.log_lines().join("").contains(&self.token));
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.registry.shutdown("shutdown");
        self.server.stop();
        self.upstream.stop();
    }
}

#[test]
fn list_connections() {
    let f = Fixture::new();
    let result = f.ok(&["list-connections"]);
    let ids: Vec<&str> = result["connections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["gh"]);
    assert_eq!(result["connections"][0]["grant"]["status"], "active");
    let text = result.to_string();
    assert!(!text.contains(SYNTHETIC));
    assert!(!text.contains("secret_id"));
}

#[test]
fn exec_status_cancel_roundtrip() {
    let f = Fixture::new();
    let started = f.ok(&[
        "exec",
        "--connection",
        "gh",
        "--request-id",
        "req-1",
        "--",
        "hello",
        "--flag",
        "-x",
    ]);
    let run_id = started["run_id"].as_str().unwrap().to_owned();
    assert!(run_id.starts_with("r-"), "{run_id}");
    let view = f.wait_state(&run_id);
    assert_eq!(view["state"], "completed", "{view}");
    assert_eq!(view["exit_code"], 0);
    assert_eq!(view["stdout"].as_str().unwrap().trim(), "hello --flag -x");
    // The same request id is idempotent.
    let again = f.ok(&[
        "exec",
        "--connection",
        "gh",
        "--request-id",
        "req-1",
        "--",
        "hello",
        "--flag",
        "-x",
    ]);
    assert_eq!(again["run_id"], run_id.as_str());

    let sleeper = f.ok(&["exec", "--connection", "gh", "--", "sleep"]);
    assert_eq!(sleeper["state"], "running");
    let sleeper_id = sleeper["run_id"].as_str().unwrap();
    let cancelled = f.ok(&["cancel", "--run", sleeper_id]);
    assert_eq!(cancelled["state"], "cancelled");
    assert_eq!(f.ok(&["status", "--run", sleeper_id])["state"], "cancelled");
}

#[test]
fn request_through_gateway() {
    let f = Fixture::new();
    let body_file = f.root.join("body.json");
    std::fs::write(&body_file, r#"{"title": "from file"}"#).unwrap();
    let result = f.ok(&[
        "request",
        "--connection",
        "gh",
        "--method",
        "post",
        "--path",
        "/repos/demo/issues",
        "--body-file",
        body_file.to_str().unwrap(),
        "--header",
        "Accept: application/json",
        "--header",
        "X-Trace: abc",
        "--request-id",
        "r-9",
    ]);
    assert_eq!(result["status"], 201, "{result}");
    assert_eq!(result["reason"], Value::Null);
    let body: Value = serde_json::from_str(result["body"].as_str().unwrap()).unwrap();
    assert_eq!(body["title"], "from file");
    // Only the filtered response headers reach the agent.
    assert_eq!(
        result["headers"],
        json!({"content-type": "application/json"})
    );
    let requests = f.upstream.requests();
    assert_eq!(requests.len(), 1);
    let seen = &requests[0];
    assert_eq!(
        (seen.method.as_str(), seen.path.as_str()),
        ("POST", "/repos/demo/issues")
    );
    assert_eq!(seen.body, br#"{"title": "from file"}"#);
    let headers: HashMap<String, String> = seen
        .headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();
    assert_eq!(
        headers.get("accept").map(String::as_str),
        Some("application/json")
    );
    // The gateway injected the real credential; the agent never held it.
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some(format!("Bearer {SYNTHETIC}").as_str())
    );

    // Each --header reaches the tools API, which validates it.
    let output = f.cli(&[
        "request",
        "--connection",
        "gh",
        "--method",
        "GET",
        "--path",
        "/me",
        "--header",
        "X_Bad: 1",
    ]);
    assert_eq!(f.error(&output)["reason"], "invalid_header_name");

    // A literal --body is sent as is.
    let me = f.ok(&[
        "request",
        "--connection",
        "gh",
        "--method",
        "GET",
        "--path",
        "/me",
        "--body",
        "x",
    ]);
    assert_eq!(me["status"], 200);
    assert_eq!(f.upstream.requests().last().unwrap().body, b"x");
}

#[test]
fn errors_exit_1_with_json_and_never_print_token() {
    let f = Fixture::new();
    let mut outputs = Vec::new();
    let output = f.cli(&["status", "--run", "r-0000000000000000"]);
    let error = f.error(&output);
    assert_eq!(
        (&error["error"], &error["reason"], &error["status"]),
        (&json!("NotFound"), &json!("run_not_found"), &json!(404))
    );
    outputs.push(output);

    let output = f.cli_env(
        &["list-connections"],
        &f.with("ZEROPW_CALLER_TOKEN", "zpwc_not-a-real-token"),
    );
    assert_eq!(f.error(&output)["reason"], "caller_token_invalid");
    outputs.push(output);

    let output = f.cli(&["exec", "--connection", "ghost", "--", "x"]);
    assert_eq!(f.error(&output)["reason"], "connection_unknown");
    outputs.push(output);

    let output = f.cli_env(
        &["list-connections"],
        &f.with("ZEROPW_GATEWAY_URL", "http://127.0.0.1:1"),
    );
    assert_eq!(f.error(&output)["reason"], "gateway_unreachable");
    outputs.push(output);

    let home = f.tmp.path().to_string_lossy().into_owned();
    let output = f.cli_env(
        &["list-connections"],
        &[("PATH", native_e2e::path_env()), ("HOME", home.clone())],
    );
    assert_eq!(f.error(&output)["reason"], "gateway_url_unset");
    outputs.push(output);

    let output = f.cli_env(
        &["list-connections"],
        &[
            ("PATH", native_e2e::path_env()),
            ("HOME", home),
            ("ZEROPW_GATEWAY_URL", f.server.url()),
        ],
    );
    assert_eq!(f.error(&output)["reason"], "caller_token_unset");
    outputs.push(output);

    let output = f.cli_env(
        &["list-connections"],
        &f.with("ZEROPW_GATEWAY_URL", "file:///etc/passwd"),
    );
    assert_eq!(f.error(&output)["reason"], "gateway_url_invalid");
    outputs.push(output);

    let output = f.cli(&["bogus-command"]);
    assert_eq!(output.status.code(), Some(2));
    outputs.push(output);

    for output in &outputs {
        for stream in [&output.stdout, &output.stderr] {
            assert!(!String::from_utf8_lossy(stream).contains(&f.token));
        }
    }
    f.assert_token_never_logged();
}

#[test]
fn refused_blocked_or_unsupported_relays_exit_1_on_stderr() {
    let f = Fixture::new();
    // A connection whose target is ZeroPW itself: the gateway refuses it as
    // unsupported (501) before any use.
    let url = f.server.url();
    let (host, port) = url.trim_start_matches("http://").rsplit_once(':').unwrap();
    f.ctx
        .policy
        .create_connection(
            Connection::new(
                "self",
                "demo",
                "dev",
                "api",
                "http",
                "gh-token",
                None,
                "",
                Some(HttpTarget::new("http", host, port.parse().unwrap(), None, false).unwrap()),
                Some(HttpAuth::bearer()),
                Some(HttpScope::new(None, None, Vec::new()).unwrap()),
                None,
                None,
                0,
                "active",
                "",
                "",
            )
            .unwrap(),
        )
        .unwrap();
    f.ctx
        .policy
        .create_grant("agent-1", "self", Some(3600), None)
        .unwrap();
    for (connection, path, status, reason) in [
        ("self", "/me", 501, "self_referential_target"),
        ("gh", "/echo-headers", 502, "credential_reflection_blocked"),
    ] {
        let output = f.cli(&[
            "request",
            "--connection",
            connection,
            "--method",
            "GET",
            "--path",
            path,
        ]);
        let error = f.error(&output);
        assert_eq!(error["reason"], reason, "{path}: {error}");
        assert_eq!(error["status"], status, "{path}: {error}");
        assert!(!String::from_utf8_lossy(&output.stderr).contains(SYNTHETIC));
    }
    // An upstream response relayed as is (reason null) is a success whatever
    // its HTTP status.
    let relayed = f.ok(&[
        "request",
        "--connection",
        "gh",
        "--method",
        "GET",
        "--path",
        "/repos/missing/nothing",
    ]);
    assert_eq!(
        (&relayed["status"], &relayed["reason"]),
        (&json!(404), &Value::Null)
    );
    // Denials decided before the gateway are errors too.
    let output = f.cli(&[
        "request",
        "--connection",
        "nope",
        "--method",
        "GET",
        "--path",
        "/me",
    ]);
    let error = f.error(&output);
    assert_eq!(
        (&error["status"], &error["reason"]),
        (&json!(403), &json!("connection_unknown"))
    );
    // The real gateway's scope refusal exits 1 as well.
    let output = f.cli(&[
        "request",
        "--connection",
        "gh",
        "--method",
        "DELETE",
        "--path",
        "/repos",
    ]);
    let error = f.error(&output);
    assert_eq!(
        (&error["status"], &error["reason"]),
        (&json!(403), &json!("method_not_allowed"))
    );
    f.assert_token_never_logged();
}

fn post(url: &str, path: &str, token: &str, body: &[u8]) -> (u16, Value) {
    let address = url.trim_start_matches("http://");
    let mut stream = std::net::TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {token}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let text = String::from_utf8_lossy(&response);
    let status = text.split(' ').nth(1).unwrap().parse().unwrap();
    let (_, body) = text.split_once("\r\n\r\n").unwrap();
    (status, serde_json::from_str(body).unwrap())
}

#[test]
fn server_maps_tool_errors_and_refuses_bad_json() {
    let f = Fixture::new();
    let (status, body) = post(&f.server.url(), "/v1/tools/status", &f.token, b"not json");
    assert_eq!((status, &body["reason"]), (400, &json!("invalid_json")));
    let (status, body) = post(&f.server.url(), "/v1/tools/nope", &f.token, b"{}");
    assert_eq!((status, &body["reason"]), (404, &json!("tool_not_found")));
}
