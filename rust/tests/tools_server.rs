use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
    time::{Duration, Instant},
};
use tempfile::TempDir;
use zeropw::{
    context::{Config, Context},
    fake_upstream::FakeUpstream,
    policy::{
        CliProfile, Connection, ConnectionChanges, HttpAuth, HttpScope, HttpTarget, SshTarget,
    },
    server::ZeroPWServer,
    tools,
};
const SECRET: &str = "synthetic-tools-secret-0123456789";
struct Fixture {
    temp: TempDir,
    ctx: Arc<Context>,
    fake: FakeUpstream,
    server: ZeroPWServer,
    token: String,
    grant: String,
}
impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let ctx = Arc::new(
            Context::initialize(
                temp.path().join("state"),
                "test-admin-passphrase",
                "test-recovery-passphrase",
                Config {
                    upstream_timeout: 2.0,
                    exec_timeout_seconds: 3.0,
                    ..Config::default()
                },
                zeropw::clock::system(),
            )
            .unwrap(),
        );
        ctx.projects
            .create("demo", zeropw::projects::DEFAULT_ENVIRONMENTS)
            .unwrap();
        ctx.vault
            .put_secret("key", "api_key", SECRET.as_bytes(), "demo", "dev", true)
            .unwrap();
        let fake = FakeUpstream::new(SECRET).start();
        let token = ctx.policy.create_principal("alice", "cli").unwrap();
        let c = Connection::new(
            "service",
            "demo",
            "dev",
            "test-api",
            "http",
            "key",
            None,
            "business API",
            Some(
                HttpTarget::new("http", fake.host(), i64::from(fake.port()), None, false).unwrap(),
            ),
            Some(HttpAuth::bearer()),
            Some(
                HttpScope::new(
                    Some(vec!["GET".into(), "POST".into()]),
                    Some(vec!["/".into()]),
                    Vec::new(),
                )
                .unwrap(),
            ),
            None,
            Some(CliProfile::new("/bin/sh", "http", None, BTreeMap::new()).unwrap()),
            0,
            "active",
            "",
            "",
        )
        .unwrap();
        ctx.policy.create_connection(c).unwrap();
        let grant = ctx
            .policy
            .create_grant("alice", "service", Some(3600), None)
            .unwrap()
            .id;
        let server = ZeroPWServer::new(ctx.clone(), None, None).unwrap();
        server.serve_in_thread().unwrap();
        Self {
            temp,
            ctx,
            fake,
            server,
            token,
            grant,
        }
    }
    fn raw(&self, request: &[u8]) -> Vec<u8> {
        let mut socket =
            TcpStream::connect(self.server.url().trim_start_matches("http://")).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket.write_all(request).unwrap();
        let mut out = Vec::new();
        if let Err(error) = socket.read_to_end(&mut out) {
            // Admission refusal closes without consuming client data. A peer
            // reset after the complete error response is valid on macOS.
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
            assert!(out.windows(4).any(|w| w == b"\r\n\r\n"));
        }
        out
    }
    fn call(&self, name: &str, payload: Value) -> (u16, Value) {
        let body = serde_json::to_string(&payload).unwrap();
        let raw=self.raw(format!("POST /v1/tools/{name} HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",self.token,body.len()).as_bytes());
        decode(&raw)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.stop();
        self.fake.stop();
    }
}
fn decode(raw: &[u8]) -> (u16, Value) {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text.split_once("\r\n\r\n").expect("response headers");
    let code = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (code, serde_json::from_str(body).unwrap())
}
#[test]
fn one_connection_supports_multiple_api_operations_without_registration() {
    let f = Fixture::new();
    let (code, list) = f.call("list_connections", json!({}));
    assert_eq!(code, 200);
    assert_eq!(list["connections"].as_array().unwrap().len(), 1);
    let text = list.to_string();
    assert!(!text.contains(SECRET));
    assert!(!text.contains("secret_id"));
    for path in ["/me", "/repos"] {
        let (code, out) = f.call(
            "request",
            json!({"connection":"service","method":"GET","path":path}),
        );
        assert_eq!(code, 200);
        assert_eq!(out["status"], 200, "{out}");
        assert!(!out.to_string().contains(SECRET));
    }
    assert_eq!(f.fake.requests().len(), 2);
}
#[test]
fn native_exec_isolated_environment_output_status_and_replay() {
    let f = Fixture::new();
    let captured = f.temp.path().join("child-env");
    let payload = json!({"connection":"service","argv":["-c","env > \"$1\"; printf business-result","sh",captured],"request_id":"job-1"});
    let (code, run) = f.call("exec", payload.clone());
    assert_eq!(code, 200, "{run}");
    let id = run["run_id"].as_str().unwrap();
    let r = zeropw::runs::registry(&f.ctx).unwrap();
    let done = r.wait(&r.get(id, "alice").unwrap(), Some(5.0));
    assert_eq!(done.state, "completed");
    assert_eq!(done.stdout, b"business-result");
    let env = std::fs::read_to_string(captured).unwrap();
    assert!(!env.contains(SECRET));
    assert!(!env.contains(&f.ctx.state.path.to_string_lossy().to_string()));
    assert!(env.contains("ZEROPW_API_BASE_URL=http://"));
    let home = env.lines().find_map(|s| s.strip_prefix("HOME=")).unwrap();
    assert!(
        !std::path::Path::new(home).exists(),
        "run directory cleaned"
    );
    assert_eq!(f.call("exec", payload).1["run_id"], id);
    assert_eq!(
        f.call("status", json!({"run_id":id})).1["stdout"],
        "business-result"
    );
    assert_eq!(
        f.call(
            "exec",
            json!({"connection":"service","argv":["-c","echo different"],"request_id":"job-1"})
        )
        .1["reason"],
        "request_id_reused"
    );
}
#[test]
fn handle_output_is_blocked_and_revocation_denies_new_work() {
    let f = Fixture::new();
    let (_, run) = f.call(
        "exec",
        json!({"connection":"service","argv":["-c","printf %s \"$ZEROPW_API_BASE_URL\""]}),
    );
    let r = zeropw::runs::registry(&f.ctx).unwrap();
    let id = run["run_id"].as_str().unwrap();
    let done = r.wait(&r.get(id, "alice").unwrap(), Some(4.0));
    assert_eq!(done.state, "blocked");
    f.ctx.policy.revoke_grant(&f.grant).unwrap();
    let (_, denied) = f.call(
        "request",
        json!({"connection":"service","method":"GET","path":"/me"}),
    );
    assert_eq!(denied["status"], 403);
    assert_eq!(f.fake.requests().len(), 0);
}
#[test]
fn strict_framing_rejects_smuggling_variants() {
    let f = Fixture::new();
    let cases: [(&[u8], &str); 7] = [
        (
            b"GET /healthz HTTP/1.1\nHost: x\r\n\r\n",
            "malformed_request_line",
        ),
        (
            b"GET /healthz HTTP/1.1\r\nHost: x\n\r\n",
            "malformed_header",
        ),
        (
            b"GET /healthz HTTP/1.1\r\nHost: x\r\n folded\r\n\r\n",
            "obsolete_line_folding",
        ),
        (
            b"GET /healthz HTTP/1.1\r\nContent-Length : 0\r\n\r\n",
            "malformed_header",
        ),
        (
            b"GET /healthz HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
            "invalid_content_length",
        ),
        (
            b"GET /healthz HTTP/1.1\r\nContent-Length: +0\r\n\r\n",
            "invalid_content_length",
        ),
        (
            b"GET /healthz HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "transfer_encoding_unsupported",
        ),
    ];
    for (raw, reason) in cases {
        let (code, body) = decode(&f.raw(raw));
        assert_eq!(code, 400);
        assert_eq!(body["reason"], reason);
    }
}
#[test]
fn auth_failures_are_audited_and_unread_body_closes() {
    let f = Fixture::new();
    let raw=f.raw(b"POST /v1/tools/list_connections HTTP/1.1\r\nHost: x\r\nContent-Length: 999\r\n\r\nGET /healthz HTTP/1.1\r\n\r\n");
    let (code, body) = decode(&raw);
    assert_eq!(code, 401);
    assert_eq!(body["reason"], "caller_token_missing");
    assert_eq!(String::from_utf8_lossy(&raw).matches("HTTP/1.1").count(), 1);
    let lines = f.ctx.audit.tail(10).unwrap();
    assert!(
        lines
            .iter()
            .any(|v| v["event"] == "auth_failed" && v["reason"] == "caller_token_missing")
    );
}
#[test]
fn proxy_tunnels_absolute_targets_and_self_reference_are_refused() {
    let f = Fixture::new();
    for (raw, status, reason) in [
        (
            "CONNECT example.com:443 HTTP/1.1\r\nConnection: close\r\n\r\n",
            405,
            "connect_tunnel_unsupported",
        ),
        (
            "GET http://example.com/ HTTP/1.1\r\nConnection: close\r\n\r\n",
            400,
            "absolute_uri_unsupported",
        ),
        (
            "GET /healthz HTTP/1.1\r\nVia: 1.1 ZEROPW-RELAY\r\nConnection: close\r\n\r\n",
            501,
            "self_referential_target",
        ),
    ] {
        let (code, body) = decode(&f.raw(raw.as_bytes()));
        assert_eq!(code, status);
        assert_eq!(body["reason"], reason);
    }
}
#[test]
fn keepalive_frames_multiple_responses_and_head_suppresses_body() {
    let f = Fixture::new();
    let raw=f.raw(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\nGET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert_eq!(
        String::from_utf8_lossy(&raw)
            .matches("HTTP/1.1 200")
            .count(),
        2
    );
    let head = f.raw(b"HEAD /healthz HTTP/1.1\r\nConnection: close\r\n\r\n");
    assert!(head.ends_with(b"\r\n\r\n"));
    assert!(!String::from_utf8_lossy(&head).contains("{\"status\""));
}
#[test]
fn slow_clients_have_an_absolute_read_deadline() {
    let f = Fixture::new();
    f.server
        .set_limits(4, Duration::from_millis(200), Duration::from_millis(100));
    let mut s = TcpStream::connect(f.server.url().trim_start_matches("http://")).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    s.write_all(b"GET /healthz HTTP/1.1\r\nHost: ").unwrap();
    let began = Instant::now();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    assert!(began.elapsed() >= Duration::from_millis(80));
    assert!(began.elapsed() < Duration::from_secs(1));
    assert!(out.is_empty());
}
#[test]
fn connection_limit_refuses_extra_client_without_spawning_work() {
    let f = Fixture::new();
    f.server
        .set_limits(1, Duration::from_secs(1), Duration::from_secs(1));
    let mut first = TcpStream::connect(f.server.url().trim_start_matches("http://")).unwrap();
    first.write_all(b"GET /healthz HTTP/1.1\r\nHost:").unwrap();
    std::thread::sleep(Duration::from_millis(30));
    let (code, body) = decode(&f.raw(b"GET /healthz HTTP/1.1\r\nConnection: close\r\n\r\n"));
    assert_eq!(code, 503);
    assert_eq!(body["reason"], "too_many_connections");
}
#[test]
fn dispatch_validation_refuses_wrong_shapes_before_business_work() {
    let f = Fixture::new();
    for (payload, reason) in [
        (json!({}), "missing_connection"),
        (
            json!({"connection":"service","method":"TRACE","path":"/"}),
            "invalid_method",
        ),
        (
            json!({"connection":"service","method":"GET","path":"http://other"}),
            "invalid_path",
        ),
        (
            json!({"connection":"service","method":"GET","path":"/","headers":{"X-Test":"bad\r\nheader"}}),
            "invalid_header_value",
        ),
        (
            json!({"connection":"service","method":"GET","path":"/","body_base64":"AA==garbage"}),
            "invalid_body_base64",
        ),
    ] {
        let error = tools::dispatch(&f.ctx, "request", "alice", &payload).unwrap_err();
        assert_eq!(error.reason, reason);
    }
    assert_eq!(f.fake.requests().len(), 0);
    assert_eq!(f.call("unknown-vault-export", json!({})).0, 404);
}
#[test]
fn strict_base64_matches_python_validate_true() {
    let cases = [
        "", "AA==", "AB==", "AAA=", "AAB=", "AAAA", "AAAA=", "AAAA====", "=", "=AAA", "A=AA",
        "AA=", "AA===", "AAA==", "AA==AA==", "AA A", "é",
    ];
    let script = format!(
        "import base64,json\nout=[]\nfor s in {}:\n try: out.append(list(base64.b64decode(s,validate=True)))\n except (ValueError,TypeError): out.append(None)\nprint(json.dumps(out))",
        serde_json::to_string(&cases).unwrap()
    );
    let out = std::process::Command::new("python3.12")
        .arg("-c")
        .arg(script)
        .output()
        .unwrap();
    assert!(out.status.success());
    let expected: Vec<Option<Vec<u8>>> = serde_json::from_slice(&out.stdout).unwrap();
    for (s, want) in cases.iter().zip(expected) {
        assert_eq!(zeropw::pybase64::b64decode_strict(s).ok(), want, "{s:?}");
    }
}

#[test]
fn queued_work_rechecks_revocation_stop_and_exhaustion_before_spawn() {
    for action in ["revoke", "stop", "exhaust"] {
        let f = Fixture::new();
        f.ctx.policy.revoke_grant(&f.grant).unwrap();
        let grant = f
            .ctx
            .policy
            .create_grant("alice", "service", Some(3600), Some(1))
            .unwrap()
            .id;
        let weak = Arc::downgrade(&f.ctx);
        f.ctx.audit.subscribe(move |record| {
            if record.get("event") == Some(&json!("tools_exec"))
                && record.get("result") == Some(&json!("ok"))
            {
                let ctx = weak.upgrade().unwrap();
                match action {
                    "revoke" => {
                        ctx.policy.revoke_grant(&grant).unwrap();
                    }
                    "stop" => ctx.policy.stop_all().unwrap(),
                    _ => {
                        ctx.policy.consume(&grant, None, None, None, None).unwrap();
                    }
                }
            }
        });
        let marker = f.temp.path().join("must-not-run");
        let result = tools::exec(
            &f.ctx,
            "alice",
            "service",
            &[
                "-c".into(),
                "touch \"$1\"".into(),
                "sh".into(),
                marker.to_string_lossy().into_owned(),
            ],
            None,
        )
        .unwrap();
        assert_eq!(result["state"], "cancelled", "{action}: {result}");
        assert_eq!(
            result["reason"],
            match action {
                "revoke" => "grant_revoked",
                "stop" => "global_stop",
                _ => "grant_exhausted",
            }
        );
        assert!(!marker.exists());
        assert_eq!(
            std::fs::read_dir(f.ctx.config.run_dir.as_ref().unwrap())
                .unwrap()
                .count(),
            0
        );
        assert!(
            !f.ctx
                .audit
                .tail(30)
                .unwrap()
                .iter()
                .any(|r| r["event"] == "run_start")
        );
    }
}

#[test]
fn corrupt_policy_during_setup_fails_the_registered_run_and_cleans_resources() {
    let f = Fixture::new();
    let weak = Arc::downgrade(&f.ctx);
    f.ctx.audit.subscribe(move |record| {
        if record.get("event") == Some(&json!("handle_issue")) {
            std::fs::write(
                weak.upgrade()
                    .unwrap()
                    .state
                    .path
                    .join("policy/control.json"),
                b"{",
            )
            .unwrap();
        }
    });
    let error = tools::exec(
        &f.ctx,
        "alice",
        "service",
        &["-c".into(), "echo should-not-run".into()],
        None,
    )
    .unwrap_err();
    assert_eq!(error.reason, "state_corrupt");
    assert!(
        zeropw::runs::registry(&f.ctx)
            .unwrap()
            .active_runs()
            .is_empty()
    );
    assert_eq!(
        std::fs::read_dir(f.ctx.config.run_dir.as_ref().unwrap())
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn any_vault_value_in_profile_is_refused_before_handle_or_child() {
    let f = Fixture::new();
    let other = b"synthetic-unrelated-secret-7654321";
    f.ctx
        .vault
        .put_secret("other", "api_key", other, "demo", "dev", true)
        .unwrap();
    for value in [
        String::from_utf8(other.to_vec()).unwrap(),
        zeropw::pybase64::b64encode(other),
        hex::encode(other),
    ] {
        f.ctx
            .policy
            .update_connection(
                "service",
                ConnectionChanges::new().cli(Some(
                    CliProfile::new(
                        "/bin/sh",
                        "http",
                        None,
                        BTreeMap::from([("PUBLIC_LABEL".into(), value)]),
                    )
                    .unwrap(),
                )),
            )
            .unwrap();
        f.ctx
            .policy
            .create_grant("alice", "service", Some(3600), None)
            .unwrap();
        let error = tools::exec(&f.ctx, "alice", "service", &[], None).unwrap_err();
        assert_eq!(error.reason, "cli_env_contains_credential");
        assert!(
            !f.ctx
                .audit
                .tail(100)
                .unwrap()
                .iter()
                .any(|r| r["event"] == "handle_issue" || r["event"] == "run_start")
        );
        assert!(
            zeropw::runs::registry(&f.ctx)
                .unwrap()
                .active_runs()
                .is_empty()
        );
        assert_eq!(
            std::fs::read_dir(f.ctx.config.run_dir.as_ref().unwrap())
                .unwrap()
                .count(),
            0
        );
    }
}

#[test]
fn tools_owner_scope_and_cancellation_survive_audit_failure() {
    let f = Fixture::new();
    f.ctx.policy.create_principal("bob", "cli").unwrap();
    let result = tools::exec(
        &f.ctx,
        "alice",
        "service",
        &["-c".into(), "sleep 20".into()],
        None,
    )
    .unwrap();
    let id = result["run_id"].as_str().unwrap();
    assert_eq!(
        tools::status(&f.ctx, "bob", id).unwrap_err().reason,
        "run_not_found"
    );
    assert_eq!(
        tools::cancel(&f.ctx, "bob", id).unwrap_err().reason,
        "run_not_found"
    );
    let audit = f.ctx.state.path.join("audit/audit.jsonl");
    std::fs::rename(&audit, audit.with_extension("saved")).unwrap();
    std::fs::create_dir(&audit).unwrap();
    assert!(tools::cancel(&f.ctx, "alice", id).is_err());
    let registry = zeropw::runs::registry(&f.ctx).unwrap();
    let done = registry.wait(&registry.get(id, "alice").unwrap(), Some(5.0));
    assert!(!zeropw::runs::ACTIVE_STATES.contains(&done.state.as_str()));
    assert!(done.stdout.is_empty() && done.stderr.is_empty());
    assert_eq!(
        std::fs::read_dir(f.ctx.config.run_dir.as_ref().unwrap())
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn duplicate_concurrent_tool_exec_runs_the_fixed_program_once() {
    let f = Fixture::new();
    let mark = f.temp.path().join("marks");
    let args = vec![
        "-c".into(),
        "echo ran >> \"$1\"".into(),
        "sh".into(),
        mark.to_string_lossy().into_owned(),
    ];
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let ctx = f.ctx.clone();
            let args = args.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                tools::exec(&ctx, "alice", "service", &args, Some("same-request")).unwrap()
            })
        })
        .collect();
    let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    assert!(results.iter().all(|v| v["run_id"] == results[0]["run_id"]));
    let registry = zeropw::runs::registry(&f.ctx).unwrap();
    let done = registry.wait(
        &registry
            .get(results[0]["run_id"].as_str().unwrap(), "alice")
            .unwrap(),
        Some(5.0),
    );
    assert_eq!(done.state, "completed");
    assert_eq!(std::fs::read_to_string(mark).unwrap(), "ran\n");
}

#[test]
fn ssh_cli_keeps_private_key_in_signer_and_fixes_local_ssh_options() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let key = zeropw::sshwire::generate_ed25519_private_key("synthetic-client");
    let private = key.to_openssh_private_key();
    let host = zeropw::sshwire::generate_ed25519_private_key("synthetic-host")
        .public
        .to_authorized_key("")
        .unwrap();
    f.ctx
        .vault
        .put_secret(
            "ssh-key",
            "ssh_private_key",
            private.as_bytes(),
            "demo",
            "dev",
            true,
        )
        .unwrap();
    let program = f.temp.path().join("capture-ssh");
    std::fs::write(&program, b"#!/bin/sh\nfor arg in \"$@\"; do if [ \"$take_next\" = yes ]; then out=$arg; break; fi; if [ \"$arg\" = -- ]; then take_next=yes; fi; done\nprintf '%s\\n' \"$@\" > \"$out.args\"\nenv > \"$out.env\"\ncat known_hosts > \"$out.hosts\"\ncat id.pub > \"$out.public\"\nls -a > \"$out.entries\"\nprintf ssh-business-output\n").unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
    for port in [22, 2222] {
        let id = format!("box{port}");
        let connection = Connection::new(
            &id,
            "demo",
            "dev",
            "ssh",
            "ssh",
            "ssh-key",
            None,
            "",
            None,
            None,
            None,
            Some(SshTarget::new("127.0.0.1", port, "deploy", vec![host.clone()]).unwrap()),
            Some(CliProfile::new(program.to_string_lossy(), "ssh", None, BTreeMap::new()).unwrap()),
            0,
            "active",
            "",
            "",
        )
        .unwrap();
        f.ctx.policy.create_connection(connection).unwrap();
        f.ctx
            .policy
            .create_grant("alice", &id, Some(3600), None)
            .unwrap();
        let out = f.temp.path().join(format!("capture-{port}"));
        let result = tools::exec(
            &f.ctx,
            "alice",
            &id,
            &[
                out.to_string_lossy().into_owned(),
                "uptime".into(),
                "-o".into(),
                "ProxyCommand=must-stay-remote-argument".into(),
            ],
            None,
        )
        .unwrap();
        let registry = zeropw::runs::registry(&f.ctx).unwrap();
        let done = registry.wait(
            &registry
                .get(result["run_id"].as_str().unwrap(), "alice")
                .unwrap(),
            Some(5.0),
        );
        assert_eq!(done.state, "completed");
        assert_eq!(done.stdout, b"ssh-business-output");
        let read = |suffix: &str| std::fs::read_to_string(out.with_extension(suffix)).unwrap();
        let env = read("env");
        let home = env.lines().find_map(|s| s.strip_prefix("HOME=")).unwrap();
        let sock = env
            .lines()
            .find_map(|s| s.strip_prefix("SSH_AUTH_SOCK="))
            .unwrap();
        assert!(!std::path::Path::new(home).exists());
        assert!(!std::path::Path::new(sock).exists());
        assert!(!home.starts_with(f.ctx.state.path.to_str().unwrap()));
        assert_eq!(
            read("hosts"),
            format!(
                "{} {host}\n",
                if port == 22 {
                    "127.0.0.1".into()
                } else {
                    format!("[127.0.0.1]:{port}")
                }
            )
        );
        assert_eq!(
            read("public"),
            format!(
                "{}\n",
                key.public
                    .to_authorized_key(&format!("zeropw:{id}"))
                    .unwrap()
            )
        );
        let args = read("args");
        assert!(args.starts_with("-F\n/dev/null\n-o\nIdentitiesOnly=yes\n"));
        assert!(args.contains("-o\nForwardAgent=no\n-o\nStrictHostKeyChecking=yes\n"));
        assert!(args.ends_with(&format!("-p\n{port}\ndeploy@127.0.0.1\n--\n{}\nuptime\n-o\nProxyCommand=must-stay-remote-argument\n", out.display())));
        let entries = read("entries");
        assert_eq!(
            entries
                .lines()
                .filter(|s| ![".", ".."].contains(s))
                .collect::<Vec<_>>(),
            vec!["id.pub", "known_hosts"]
        );
        for text in [
            env,
            args,
            read("hosts"),
            read("public"),
            registry.view(&done).to_string(),
            serde_json::to_string(&f.ctx.audit.tail(100).unwrap()).unwrap(),
        ] {
            assert!(!text.contains("PRIVATE KEY"));
            assert!(!text.contains(&private));
            assert!(!text.contains(&hex::encode(key.seed().expose())));
        }
    }
}

// Direct ports of the remaining public-tool preflight cases in
// tests/test_tools.py. These exercise the native API, not a Python backend.
#[test]
fn original_dispatch_shape_limits_are_enforced() {
    let f = Fixture::new();
    for (name, payload) in [
        ("status", json!({"run_id":12})),
        ("status", json!({})),
        ("status", json!({"run_id":"bad id!"})),
        ("exec", json!({"connection":"service","argv":"not-a-list"})),
        ("exec", json!({"connection":"service","argv":[1,2]})),
        ("exec", json!({"connection":"service","argv":["a\u{0}b"]})),
        ("exec", json!({"connection":"../etc","argv":[]})),
        (
            "request",
            json!({"connection":"service","method":"GET","path":"repos"}),
        ),
        (
            "request",
            json!({"connection":"service","method":"GET","path":"/re pos"}),
        ),
        (
            "request",
            json!({"connection":"service","method":"GET","path":"/","headers":{"Bad Name":"v"}}),
        ),
        (
            "request",
            json!({"connection":"service","method":"GET","path":"/","body":"a","body_base64":"YQ=="}),
        ),
        (
            "request",
            json!({"connection":"service","method":"GET","path":"/","request_id":"has space"}),
        ),
    ] {
        assert_eq!(
            tools::dispatch(&f.ctx, name, "alice", &payload)
                .unwrap_err()
                .class,
            zeropw::errors::ErrorClass::InvalidInput,
            "{name}: {payload}"
        );
    }
    for (argv, reason) in [
        (json!(vec!["x"; 257]), "argv_too_long"),
        (json!(["y".repeat(4097)]), "argument_too_long"),
    ] {
        assert_eq!(
            tools::dispatch(
                &f.ctx,
                "exec",
                "alice",
                &json!({"connection":"service","argv":argv})
            )
            .unwrap_err()
            .reason,
            reason
        );
    }
    assert_eq!(
        tools::dispatch(
            &f.ctx,
            "list_connections",
            "alice",
            &json!({"unexpected":{"nested":true}})
        )
        .unwrap()["connections"][0]["id"],
        "service"
    );
    assert!(f.fake.requests().is_empty());
}

#[test]
fn original_list_ownership_stop_and_revocation_contract() {
    let f = Fixture::new();
    f.ctx.policy.create_principal("bob", "cli").unwrap();
    let mut other = f.ctx.policy.get_connection("service").unwrap();
    other.id = "other".into();
    other.cli = None;
    f.ctx.policy.create_connection(other).unwrap();
    f.ctx
        .policy
        .create_grant("bob", "other", Some(3600), Some(5))
        .unwrap();
    for (caller, id) in [("alice", "service"), ("bob", "other")] {
        let view = tools::list_connections(&f.ctx, caller).unwrap();
        assert_eq!(view["connections"].as_array().unwrap().len(), 1);
        assert_eq!(view["connections"][0]["id"], id);
        if caller == "bob" {
            assert_eq!(view["connections"][0]["grant"]["remaining_uses"], 5);
        }
        for forbidden in [SECRET, "secret_id", "zpw1."] {
            assert!(!view.to_string().contains(forbidden));
        }
    }
    assert_eq!(
        tools::list_connections(&f.ctx, "ghost").unwrap(),
        json!({"connections":[]})
    );
    f.ctx.policy.stop_all().unwrap();
    assert_eq!(
        tools::list_connections(&f.ctx, "alice").unwrap(),
        json!({"connections":[]})
    );
    f.ctx.policy.resume().unwrap();
    assert_eq!(
        tools::list_connections(&f.ctx, "alice").unwrap()["connections"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    f.ctx.policy.revoke_grant(&f.grant).unwrap();
    assert_eq!(
        tools::list_connections(&f.ctx, "alice").unwrap(),
        json!({"connections":[]})
    );
}

#[test]
fn original_cli_preflight_missing_profiles_and_programs_never_spawn() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let plain = f.temp.path().join("not-executable");
    std::fs::write(&plain, b"#!/bin/sh\necho must-not-run\n").unwrap();
    std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o600)).unwrap();
    for (id, program, reason) in [
        ("nocli", None, "cli_not_supported"),
        (
            "missing",
            Some(f.temp.path().join("absent").to_string_lossy().into_owned()),
            "cli_program_missing",
        ),
        (
            "notexec",
            Some(plain.to_string_lossy().into_owned()),
            "cli_program_missing",
        ),
        (
            "byname",
            Some("zeropw-no-such-program-xyz".into()),
            "cli_program_missing",
        ),
    ] {
        let mut connection = f.ctx.policy.get_connection("service").unwrap();
        connection.id = id.into();
        connection.cli =
            program.map(|p| CliProfile::new(p, "http", None, BTreeMap::new()).unwrap());
        f.ctx.policy.create_connection(connection).unwrap();
        f.ctx
            .policy
            .create_grant("alice", id, Some(3600), None)
            .unwrap();
        let error = tools::exec(&f.ctx, "alice", id, &[], None).unwrap_err();
        assert_eq!(error.class, zeropw::errors::ErrorClass::Unsupported);
        assert_eq!(error.reason, reason);
    }
    let events = f.ctx.audit.tail(100).unwrap();
    let reasons: Vec<_> = events
        .iter()
        .filter(|v| v["event"] == "tools_exec")
        .map(|v| v["reason"].clone())
        .collect();
    assert_eq!(
        reasons,
        json!([
            "cli_not_supported",
            "cli_program_missing",
            "cli_program_missing",
            "cli_program_missing"
        ])
        .as_array()
        .unwrap()
        .clone()
    );
    assert!(
        !events
            .iter()
            .any(|v| v["event"] == "run_start" || v["event"] == "handle_issue")
    );
    assert!(
        zeropw::runs::registry(&f.ctx)
            .unwrap()
            .active_runs()
            .is_empty()
    );
}

#[test]
fn original_exec_policy_denials_are_precise_and_audited() {
    let f = Fixture::new();
    f.ctx.policy.create_principal("bob", "cli").unwrap();
    let refused = |caller: &str, id: &str, reason: &str| {
        let error = tools::exec(&f.ctx, caller, id, &[], None).unwrap_err();
        assert_eq!(error.class, zeropw::errors::ErrorClass::PolicyDenied);
        assert_eq!(error.reason, reason);
    };
    refused("bob", "service", "no_grant");
    refused("alice", "ghost", "connection_unknown");
    f.ctx.policy.stop_all().unwrap();
    refused("alice", "service", "global_stop");
    f.ctx.policy.resume().unwrap();
    f.ctx.policy.set_restore_pending(true).unwrap();
    refused("alice", "service", "restore_pending");
    f.ctx.policy.set_restore_pending(false).unwrap();
    f.ctx
        .policy
        .update_connection(
            "service",
            ConnectionChanges::new().http_scope(Some(HttpScope::new(None, None, vec![]).unwrap())),
        )
        .unwrap();
    refused("alice", "service", "grant_stale");
    let fresh = f.ctx.policy.regrant(&f.grant).unwrap();
    f.ctx.policy.revoke_grant(&fresh.id).unwrap();
    refused("alice", "service", "grant_revoked");
    let capped = f
        .ctx
        .policy
        .create_grant("bob", "service", Some(3600), Some(1))
        .unwrap();
    f.ctx
        .policy
        .consume(&capped.id, None, None, None, None)
        .unwrap();
    refused("bob", "service", "grant_exhausted");
    f.ctx.policy.disable_principal("alice", true).unwrap();
    refused("alice", "service", "principal_disabled");
    let events = f.ctx.audit.tail(100).unwrap();
    let reasons: Vec<_> = events
        .iter()
        .filter(|v| v["event"] == "tools_exec" && v["result"] == "denied")
        .map(|v| v["reason"].clone())
        .collect();
    assert_eq!(
        reasons,
        json!([
            "no_grant",
            "connection_unknown",
            "global_stop",
            "restore_pending",
            "grant_stale",
            "grant_revoked",
            "grant_exhausted",
            "principal_disabled"
        ])
        .as_array()
        .unwrap()
        .clone()
    );
    assert!(!events.iter().any(|v| v["event"] == "handle_issue"));
    assert!(
        zeropw::runs::registry(&f.ctx)
            .unwrap()
            .active_runs()
            .is_empty()
    );
}

#[test]
fn original_audit_failure_refuses_each_tool_before_side_effects() {
    let f = Fixture::new();
    let audit = f.ctx.state.path.join("audit/audit.jsonl");
    let saved = audit.with_extension("saved");
    std::fs::rename(&audit, &saved).unwrap();
    std::fs::create_dir(&audit).unwrap();
    for error in [
        tools::list_connections(&f.ctx, "alice").unwrap_err(),
        tools::request(
            &f.ctx,
            "alice",
            "service",
            "GET",
            "/me",
            &Vec::new(),
            b"",
            None,
        )
        .unwrap_err(),
        tools::exec(&f.ctx, "alice", "service", &[], None).unwrap_err(),
    ] {
        assert_eq!(error.class, zeropw::errors::ErrorClass::AuditUnavailable);
    }
    assert!(f.fake.requests().is_empty());
    assert!(
        zeropw::runs::registry(&f.ctx)
            .unwrap()
            .active_runs()
            .is_empty()
    );
    let text = std::fs::read_to_string(saved).unwrap();
    assert!(!text.contains("handle_issue") && !text.contains("run_start"));
    assert_eq!(
        std::fs::read_dir(f.ctx.config.run_dir.as_ref().unwrap())
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn original_public_url_and_expired_grant_contract() {
    let f = Fixture::new();
    *f.ctx.public_url.write().unwrap() = None;
    assert_eq!(
        tools::exec(&f.ctx, "alice", "service", &[], None)
            .unwrap_err()
            .reason,
        "public_url_unset"
    );
    assert_eq!(
        tools::set_public_url(&f.ctx, "ftp://127.0.0.1:1")
            .unwrap_err()
            .class,
        zeropw::errors::ErrorClass::InvalidInput
    );
    assert_eq!(
        tools::set_public_url(&f.ctx, "http://127.0.0.1:1/").unwrap(),
        "http://127.0.0.1:1"
    );
    f.ctx.policy.create_principal("bob", "cli").unwrap();
    f.ctx
        .policy
        .create_grant("bob", "service", Some(1), None)
        .unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    assert_eq!(
        tools::exec(&f.ctx, "bob", "service", &[], None)
            .unwrap_err()
            .reason,
        "grant_expired"
    );
    assert_eq!(f.ctx.audit.tail(1).unwrap()[0]["reason"], "grant_expired");
}

#[test]
fn original_request_normalization_binary_body_and_header_filter_contract() {
    use std::net::TcpListener;
    let f = Fixture::new();
    let receiver = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = receiver.local_addr().unwrap().port();
    f.ctx
        .policy
        .update_connection(
            "service",
            ConnectionChanges::new().http_target(Some(
                HttpTarget::new("http", "127.0.0.1", i64::from(port), None, false).unwrap(),
            )),
        )
        .unwrap();
    f.ctx
        .policy
        .create_grant("alice", "service", Some(3600), None)
        .unwrap();
    let receiver = std::thread::spawn(move || {
        let mut received = Vec::new();
        for index in 0..2 {
            let (mut stream, _) = receiver.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let headers = String::from_utf8(request).unwrap();
            let size = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                        .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            let mut body = vec![0; size];
            stream.read_exact(&mut body).unwrap();
            received.push((headers.lines().next().unwrap().to_string(), body));
            let payload: &[u8] = if index == 0 {
                b"business-json"
            } else {
                b"\xff\xfe\0binary"
            };
            write!(stream,"HTTP/1.1 201 Created\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nSet-Cookie: synthetic-session\r\nWWW-Authenticate: Bearer\r\nX-Request-Id: req-upstream\r\nConnection: close\r\n\r\n",payload.len()).unwrap();
            stream.write_all(payload).unwrap();
        }
        received
    });
    let first = tools::dispatch(&f.ctx,"request","alice",&json!({"connection":"service","method":"post","path":"/repos?per_page=2","body":"{\"title\":\"x\"}","request_id":"req-1"})).unwrap();
    assert_eq!(first["status"], 201);
    assert_eq!(first["body"], "business-json");
    assert!(first["body_base64"].is_null());
    assert_eq!(first["headers"]["x-request-id"], "req-upstream");
    for name in [
        "set-cookie",
        "www-authenticate",
        "connection",
        "authorization",
    ] {
        assert!(first["headers"].get(name).is_none());
    }
    let second = tools::dispatch(
        &f.ctx,
        "request",
        "alice",
        &json!({"connection":"service","method":"POST","path":"/repos","body_base64":"AAE="}),
    )
    .unwrap();
    assert_eq!(second["status"], 201);
    assert!(second["body"].is_null());
    assert_eq!(
        zeropw::pybase64::b64decode_strict(second["body_base64"].as_str().unwrap()).unwrap(),
        b"\xff\xfe\0binary"
    );
    assert_eq!(
        receiver.join().unwrap(),
        vec![
            (
                "POST /repos?per_page=2 HTTP/1.1".into(),
                b"{\"title\":\"x\"}".to_vec()
            ),
            ("POST /repos HTTP/1.1".into(), vec![0, 1])
        ]
    );
    let events = f.ctx.audit.tail(100).unwrap();
    let request = events
        .iter()
        .find(|v| v["event"] == "tools_request" && v["request_id"] == "req-1")
        .unwrap();
    assert_eq!(request["path"], "/repos");
    assert_eq!(request["method"], "POST");
    assert!(!request.to_string().contains("per_page"));
}

#[test]
fn original_fixed_program_and_fresh_private_run_directories() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let mut connection = f.ctx.policy.get_connection("service").unwrap();
    connection.id = "echo".into();
    connection.cli = Some(CliProfile::new("/bin/echo", "http", None, BTreeMap::new()).unwrap());
    f.ctx.policy.create_connection(connection).unwrap();
    f.ctx
        .policy
        .create_grant("alice", "echo", Some(3600), None)
        .unwrap();
    let run = tools::exec(
        &f.ctx,
        "alice",
        "echo",
        &["/bin/sh".into(), "-c".into(), "id".into()],
        None,
    )
    .unwrap();
    let registry = zeropw::runs::registry(&f.ctx).unwrap();
    let done = registry.wait(
        &registry
            .get(run["run_id"].as_str().unwrap(), "alice")
            .unwrap(),
        Some(5.0),
    );
    assert_eq!(done.stdout, b"/bin/sh -c id\n");
    let mut paths = Vec::new();
    for index in 0..2 {
        let marker = f.temp.path().join(format!("cwd-{index}"));
        let run = tools::exec(
            &f.ctx,
            "alice",
            "service",
            &[
                "-c".into(),
                "printf '%s' \"$HOME\" > \"$1\"; exec /bin/sleep 20".into(),
                "sh".into(),
                marker.to_string_lossy().into_owned(),
            ],
            None,
        )
        .unwrap();
        let end = Instant::now() + Duration::from_secs(5);
        while std::fs::metadata(&marker).map_or(true, |m| m.len() == 0) && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(10));
        }
        let path = std::path::PathBuf::from(std::fs::read_to_string(marker).unwrap());
        assert!(!path.starts_with(&f.ctx.state.path));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        tools::cancel(&f.ctx, "alice", run["run_id"].as_str().unwrap()).unwrap();
        assert!(!path.exists());
        paths.push(path);
    }
    assert_ne!(paths[0], paths[1]);
}
