//! One-command, synthetic-only demonstration (`zeropw/demo.py`).
//!
//! `zeropw-demo` builds a throw-away state directory, starts a controlled fake
//! upstream API and the trusted ZeroPW process (gateway + tools + SSH signer),
//! configures one HTTP connection and one SSH connection, and then acts as an
//! agent that only holds a caller token. It runs the same phases, checks and
//! output text as the Python demo: one connection used for several operations,
//! extraction/reflection/bypass attempts, SSH signing bound to a destination,
//! revocation and global stop, a leak sweep, and automatic intrusion response
//! followed by recovery. Everything runs on 127.0.0.1 and is deleted
//! afterwards. Exit status 0 means every check passed; this is a demonstration
//! of the prototype's behaviour, not a security certification.
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::context::{Config, Context};
use crate::errors::Error;
use crate::fake_upstream::FakeUpstream;
use crate::policy::{CliProfile, Connection, HttpAuth, HttpScope, HttpTarget, SshTarget};
use crate::server::ZeroPWServer;
use crate::{agent_cli, incident, intrusion, notify, pybase64, pystr, sshwire, store};

const ADMIN_PASSPHRASE: &str = "demo-admin-passphrase";
const RECOVERY_PASSPHRASE: &str = "demo-recovery-passphrase";

/// Python `repr()` of a list of strings, e.g. `['box', 'gh']`.
fn repr_list<S: AsRef<str>>(items: &[S]) -> String {
    pystr::repr_value(&Value::Array(
        items
            .iter()
            .map(|s| Value::String(s.as_ref().to_owned()))
            .collect(),
    ))
}

/// `urllib.parse.quote(value, safe="")`.
fn url_quote(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"_.-~".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

struct Demo {
    failures: Vec<String>,
    checks: usize,
    /// Everything the "agent" side ever saw.
    visible: Vec<String>,
    url: String,
    caller_token: String,
}

impl Demo {
    fn say(&self, text: &str) {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{text}");
        let _ = out.flush();
    }

    fn check(&mut self, condition: bool, label: &str) -> bool {
        self.checks += 1;
        let mark = if condition { "PASS" } else { "FAIL" };
        self.say(&format!("  [{mark}] {label}"));
        if !condition {
            self.failures.push(label.to_owned());
        }
        condition
    }

    fn seen(&mut self, payload: &Value) {
        self.visible.push(payload.to_string());
    }

    fn call(&mut self, tool: &str, payload: Value) -> (u16, Value) {
        let (status, body) = agent_cli::call_tool(&self.url, &self.caller_token, tool, &payload);
        self.seen(&json!({"tool": tool, "status": status, "body": body}));
        (status, body)
    }

    fn wait_run(&mut self, run_id: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let (_, body) = self.call("status", json!({"run_id": run_id}));
            let state = body["state"].as_str().unwrap_or("");
            if ["completed", "failed", "cancelled", "blocked"].contains(&state)
                || Instant::now() > deadline
            {
                return body;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn exec_and_wait(&mut self, argv: Value) -> Value {
        let (_, body) = self.call("exec", json!({"connection": "gh", "argv": argv}));
        let run = self.wait_run(body["run_id"].as_str().unwrap_or(""));
        self.seen(&run);
        run
    }
}

/// Resources that `teardown` releases whichever phase fails.
struct Running {
    ctx: Arc<Context>,
    server: ZeroPWServer,
    upstream: FakeUpstream,
    synthetic: String,
    user_key: sshwire::Ed25519PrivateKey,
    host_key: sshwire::Ed25519PrivateKey,
    http_grant: String,
    ssh_grant: String,
}

fn setup(d: &mut Demo, root: &Path) -> Result<Running, Error> {
    d.say(&format!(
        "[1] 상태 디렉터리와 신뢰 프로세스 준비: {}",
        root.display()
    ));
    let ctx = Arc::new(Context::initialize(
        root.join("state"),
        ADMIN_PASSPHRASE,
        RECOVERY_PASSPHRASE,
        Config {
            handle_ttl_seconds: 300,
            ..Config::default()
        },
        crate::clock::system(),
    )?);
    ctx.projects
        .create("demo", crate::projects::DEFAULT_ENVIRONMENTS)?;
    let mut token_bytes = [0u8; 12];
    getrandom::getrandom(&mut token_bytes).map_err(|_| Error::state("demo_random_failed"))?;
    let synthetic = format!("synthetic-token-{}", hex::encode(token_bytes));
    ctx.vault.put_secret(
        "gh-token",
        "api_key",
        synthetic.as_bytes(),
        "demo",
        "dev",
        true,
    )?;

    let mut upstream = FakeUpstream::new(synthetic.clone()).start();
    d.say(&format!(
        "    시험용 외부 API: {} (합성 토큰만 인증)",
        upstream.url()
    ));

    // The native sample CLI ships beside this executable (`cargo build --bins`).
    let program = std::env::current_exe()
        .map_err(|_| Error::state("demo_program_missing"))?
        .with_file_name("zeropw-democli");
    if !program.is_file() {
        upstream.stop();
        return Err(Error::state("demo_program_missing"));
    }
    ctx.policy.create_connection(Connection::new(
        "gh",
        "demo",
        "dev",
        "fake-code-host",
        "http",
        "gh-token",
        None,
        "데모 코드 호스팅 API 연결",
        Some(HttpTarget::new(
            "http",
            "127.0.0.1",
            i64::from(upstream.port()),
            None,
            false,
        )?),
        Some(HttpAuth::bearer()),
        Some(HttpScope::new(
            Some(vec!["GET".into(), "POST".into(), "DELETE".into()]),
            None,
            vec!["DELETE".into()],
        )?),
        None,
        Some(CliProfile::new(
            program.to_string_lossy().to_string(),
            "http",
            None,
            Default::default(),
        )?),
        0,
        "active",
        "",
        "",
    )?)?;

    let user_key = sshwire::generate_ed25519_private_key("demo-agent");
    let host_key = sshwire::generate_ed25519_private_key("demo-box");
    ctx.vault.put_secret(
        "box-key",
        "ssh_private_key",
        user_key.to_openssh_private_key().as_bytes(),
        "demo",
        "dev",
        true,
    )?;
    let host_line = host_key
        .public
        .to_authorized_key("demo-box")
        .map_err(|_| Error::state("demo_ssh_failed"))?;
    ctx.policy.create_connection(Connection::new(
        "box",
        "demo",
        "dev",
        "ssh-box",
        "ssh",
        "box-key",
        None,
        "데모 SSH 목적지",
        None,
        None,
        None,
        Some(SshTarget::new(
            "demo-box.internal",
            22,
            "deploy",
            vec![host_line],
        )?),
        None,
        0,
        "active",
        "",
        "",
    )?)?;

    let caller_token = ctx.policy.create_principal("agent-1", "default")?;
    let http_grant = ctx
        .policy
        .create_grant("agent-1", "gh", Some(600), Some(50))?;
    let ssh_grant = ctx
        .policy
        .create_grant("agent-1", "box", Some(600), Some(10))?;

    // The server installs the run registry, the SSH signer and the public URL.
    let server = ZeroPWServer::new(ctx.clone(), None, None)?;
    server.serve_in_thread()?;
    d.url = server.url();
    d.caller_token = caller_token;
    d.say(&format!("    게이트웨이·도구 API: {}", d.url));
    d.say("    에이전트가 받는 것: 게이트웨이 URL과 호출 토큰(zpwc_...)뿐. 금고 값은 없음.");
    Ok(Running {
        ctx,
        server,
        upstream,
        synthetic,
        user_key,
        host_key,
        http_grant: http_grant.id,
        ssh_grant: ssh_grant.id,
    })
}

fn normal_flow(d: &mut Demo, r: &Running) {
    d.say("[2] 연결 한 번으로 여러 작업 (개별 등록 없음)");
    let (status, body) = d.call("list_connections", json!({}));
    let mut ids: Vec<String> = body["connections"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|c| c["id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    ids.sort();
    d.check(
        status == 200 && ids == ["box", "gh"],
        &format!("list_connections -> {}", repr_list(&ids)),
    );
    d.check(
        !body.to_string().contains("secret_id"),
        "연결 목록에 비밀 참조·값 없음",
    );

    let (status, body) = d.call(
        "request",
        json!({"connection": "gh", "method": "GET", "path": "/repos"}),
    );
    d.check(
        status == 200
            && body["status"] == 200
            && body["body"].as_str().unwrap_or("").contains("demo"),
        "request GET /repos -> 200",
    );
    let (status, body) = d.call(
        "request",
        json!({"connection": "gh", "method": "POST", "path": "/repos/demo/issues",
               "body": "{\"title\": \"hello from agent\"}"}),
    );
    d.check(
        status == 200 && body["status"] == 201,
        "request POST /repos/demo/issues -> 201",
    );

    // The native democli prints compact JSON (`"status":200`); Python's prints
    // `"status": 200`. Both are the business status reported by the CLI.
    let completed_with = |run: &Value, status: u16| {
        let stdout = run["stdout"].as_str().unwrap_or("");
        run["state"] == "completed"
            && (stdout.contains(&format!("\"status\": {status}"))
                || stdout.contains(&format!("\"status\":{status}")))
    };
    let run = d.exec_and_wait(json!(["list-repos"]));
    d.check(completed_with(&run, 200), "exec democli list-repos -> 200");
    let run = d.exec_and_wait(json!(["create-issue", "demo", "issue via cli"]));
    d.check(
        completed_with(&run, 201),
        "exec democli create-issue -> 201",
    );

    let expected = format!("Bearer {}", r.synthetic);
    let recorded = r.upstream.requests();
    d.check(
        recorded
            .iter()
            .all(|q| q.headers.get("authorization") == Some(&expected))
            && recorded.len() >= 4,
        "업스트림은 매번 실제 합성 토큰만 받음 (자리표시자 democli-placeholder 없음)",
    );
}

/// Send one raw HTTP/1.1 request to the local server and return its status line.
fn raw_status_line(port: u16, request: &str) -> String {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return String::new();
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    if stream.write_all(request.as_bytes()).is_err() {
        return String::new();
    }
    let mut reply = Vec::new();
    let mut chunk = [0u8; 1024];
    while !reply.windows(2).any(|w| w == b"\r\n") {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => reply.extend_from_slice(&chunk[..n]),
        }
    }
    let line = reply.split(|b| *b == b'\n').next().unwrap_or(&[]);
    String::from_utf8_lossy(line).trim_end().to_owned()
}

fn attacks(d: &mut Demo, r: &Running) -> Result<(), Error> {
    d.say("[3] 추출·반사·우회 시도");
    let run = d.exec_and_wait(json!(["steal"]));
    let stdout = run["stdout"].as_str().unwrap_or("").to_owned();
    d.check(
        run["state"] == "completed" && !stdout.contains(&r.synthetic) && !stdout.contains("zpw1."),
        "democli steal: 환경·인자·홈 디렉터리에 비밀 없음 (핸들도 가려짐)",
    );
    let env_names: Vec<String> = if stdout.starts_with('{') {
        serde_json::from_str::<Value>(&stdout)
            .ok()
            .and_then(|v| v["env_names"].as_array().cloned())
            .map(|a| {
                a.iter()
                    .filter_map(|n| n.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    d.check(
        env_names.iter().any(|n| n == "ZEROPW_API_BASE_URL")
            && !env_names.iter().any(|n| n.starts_with("ZEROPW_STATE")),
        &format!("자식 환경변수: {}", repr_list(&env_names)),
    );

    let cases = [
        (
            "GET",
            "/echo-headers",
            "credential_reflection_blocked",
            "헤더 반사 응답 차단",
        ),
        (
            "GET",
            "/debug/token",
            "credential_reflection_blocked",
            "토큰 조회 엔드포인트 응답 차단",
        ),
        (
            "GET",
            "/base64-leak",
            "credential_reflection_blocked",
            "base64 인코딩 반사 차단",
        ),
        (
            "GET",
            "/set-cookie",
            "credential_reflection_blocked",
            "Set-Cookie 반사 차단",
        ),
        (
            "GET",
            "/redirect",
            "redirect_not_followed",
            "리다이렉트 미추적 (Location 미전달)",
        ),
        (
            "PUT",
            "/repos",
            "method_not_allowed",
            "허용 범위 밖 메서드 거부",
        ),
    ];
    for (method, path, reason, label) in cases {
        let (_, body) = d.call(
            "request",
            json!({"connection": "gh", "method": method, "path": path}),
        );
        d.check(
            body["reason"] == reason && !body.to_string().contains(&r.synthetic),
            &format!("{method} {path} -> {reason}: {label}"),
        );
    }

    let (_, body) = d.call(
        "request",
        json!({"connection": "gh", "method": "DELETE", "path": "/repos/demo"}),
    );
    let digest = body["approval_digest"]
        .as_str()
        .map(str::to_owned)
        .or_else(|| {
            body["body"]
                .as_str()
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
                .and_then(|v| v["approval_digest"].as_str().map(str::to_owned))
        });
    d.check(
        body["status"] == 428 && digest.as_deref().is_some_and(|s| !s.is_empty()),
        "DELETE /repos/demo -> 428 승인 필요 (digest 발급)",
    );
    if let Some(digest) = digest.filter(|s| !s.is_empty()) {
        r.ctx.policy.approve(&digest)?;
        d.say("    관리자가 digest에 묶인 일회성 승인을 부여");
        let (_, body) = d.call(
            "request",
            json!({"connection": "gh", "method": "DELETE", "path": "/repos/demo"}),
        );
        d.check(body["status"] == 204, "승인 후 같은 입력의 DELETE -> 204");
        let (_, body) = d.call(
            "request",
            json!({"connection": "gh", "method": "DELETE", "path": "/repos/demo"}),
        );
        d.check(body["status"] == 428, "승인은 일회성: 재시도 -> 428");
    }

    // A stolen handle cannot be pointed at another target; the connection fixes the target.
    let port = r
        .server
        .url()
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .ok_or_else(|| Error::state("demo_server_url"))?;
    let policy_version = r.ctx.policy.get_connection("gh")?.policy_version;
    let handle = r
        .ctx
        .handles
        .issue("agent-1", "gh", &r.http_grant, policy_version, 60, None)?;
    let status = raw_status_line(
        port,
        &format!(
            "GET /h/{handle}/repos HTTP/1.1\r\nHost: evil.invalid\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
        ),
    );
    d.check(
        status.split(' ').nth(1) == Some("200"),
        "Host 헤더 변조는 무시되고 고정 대상으로만 전달",
    );
    let status = raw_status_line(
        port,
        "CONNECT evil.invalid:443 HTTP/1.1\r\nHost: evil.invalid:443\r\n\r\n",
    );
    d.check(format!("{status} ").contains(" 405 "), "CONNECT 터널 거부");
    Ok(())
}

fn failed<E>(_: E) -> Error {
    Error::state("demo_ssh_failed")
}

/// The agent answered `SSH_AGENT_FAILURE`.
fn refused<E>(reply: Result<Vec<u8>, E>) -> bool {
    reply.ok().as_deref() == Some(sshwire::build_failure().as_slice())
}

fn ssh_demo(d: &mut Demo, r: &Running) -> Result<(), Error> {
    d.say("[4] SSH 서명 위임 (스크립트 클라이언트, sshd 없이)");
    let manager =
        crate::tools::signer_manager(&r.ctx).ok_or_else(|| Error::state("demo_signer_missing"))?;
    let binding = manager.bind("agent-1", "box", &r.ssh_grant)?;
    let mut session_id = [0u8; 32];
    getrandom::getrandom(&mut session_id).map_err(|_| Error::state("demo_random_failed"))?;
    let connect = || -> Result<sshwire::AgentConnection<UnixStream>, Error> {
        let stream = UnixStream::connect(&binding.socket_path).map_err(failed)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(failed)?;
        Ok(sshwire::AgentConnection::new(stream))
    };
    let bind_msg = |host: &sshwire::Ed25519PrivateKey,
                    forwarding: bool|
     -> Result<Vec<u8>, Error> {
        let signature = sshwire::encode_ssh_signature(&host.sign(&session_id)).map_err(failed)?;
        Ok(sshwire::build_session_bind(
            &host.public.blob(),
            &session_id,
            &signature,
            forwarding,
        ))
    };
    let user_blob = r.user_key.public.blob();
    let userauth = sshwire::build_userauth_request(
        &session_id,
        "deploy",
        "ssh-ed25519",
        &user_blob,
        "ssh-connection",
        None,
    );

    let mut conn = connect()?;
    let reply = conn
        .request(&[sshwire::SSH_AGENTC_REQUEST_IDENTITIES])
        .map_err(failed)?;
    let keys = sshwire::parse_identities_answer(reply.get(1..).unwrap_or(&[])).map_err(failed)?;
    d.check(
        keys.len() == 1 && keys[0].0 == user_blob,
        "identities: 연결에 묶인 공개키 하나만 노출",
    );
    d.check(
        refused(conn.request(&sshwire::build_sign_request(&user_blob, &userauth, 0))),
        "세션 결합 전 서명 요청 거부",
    );
    d.check(
        conn.request(&bind_msg(&r.host_key, false)?).ok().as_deref()
            == Some(sshwire::build_success().as_slice()),
        "session-bind: 허용된 목적지 호스트 키 + 유효 서명",
    );
    let reply = conn
        .request(&sshwire::build_sign_request(&user_blob, &userauth, 0))
        .map_err(failed)?;
    let signature = reply
        .get(1..)
        .and_then(|b| sshwire::parse_sign_response(b).ok())
        .and_then(|b| sshwire::parse_ssh_signature(&b).ok());
    d.check(
        reply.first() == Some(&sshwire::SSH_AGENT_SIGN_RESPONSE)
            && signature
                .as_ref()
                .is_some_and(|s| r.user_key.public.verify(&userauth, s)),
        "결합된 세션의 userauth 요청 서명 -> 유효",
    );
    d.check(
        refused(conn.request(&sshwire::build_sign_request(
            &user_blob,
            b"arbitrary bytes",
            0,
        ))),
        "임의 데이터 서명 거부",
    );
    let other_user = sshwire::build_userauth_request(
        &session_id,
        "root",
        "ssh-ed25519",
        &user_blob,
        "ssh-connection",
        None,
    );
    d.check(
        refused(conn.request(&sshwire::build_sign_request(&user_blob, &other_user, 0))),
        "다른 사용자 이름(root) 서명 거부",
    );
    d.check(
        refused(conn.request(&[sshwire::SSH_AGENTC_REMOVE_ALL_IDENTITIES])),
        "키 삭제 메시지 거부",
    );
    drop(conn);

    let impostor = sshwire::generate_ed25519_private_key("impostor");
    let mut conn = connect()?;
    d.check(
        refused(conn.request(&bind_msg(&impostor, false)?)),
        "다른 호스트 키로 session-bind 거부",
    );
    d.check(
        refused(conn.request(&bind_msg(&r.host_key, true)?)),
        "agent forwarding 결합 거부",
    );
    drop(conn);
    binding.close();
    d.say("    실제 sshd·ssh 종단 시험은 tests/test_ssh_e2e.py 참고");
    Ok(())
}

fn revocation(d: &mut Demo, r: &Running) -> Result<(), Error> {
    d.say("[5] 회수와 전체 정지");
    r.ctx.policy.revoke_grant(&r.http_grant)?;
    let (_, body) = d.call(
        "request",
        json!({"connection": "gh", "method": "GET", "path": "/repos"}),
    );
    d.check(
        body["reason"] == "grant_revoked",
        "권한 회수 직후 request -> grant_revoked",
    );
    r.ctx.policy.stop_all()?;
    let (_, body) = d.call("list_connections", json!({}));
    d.check(
        body["connections"] == json!([]),
        "전체 정지 중 list_connections -> 빈 목록",
    );
    r.ctx.policy.resume()?;
    let (_, body) = d.call("list_connections", json!({}));
    let ids: Vec<&str> = body["connections"]
        .as_array()
        .map(|a| a.iter().filter_map(|c| c["id"].as_str()).collect())
        .unwrap_or_default();
    d.check(ids == ["box"], "재개 후 남은 권한(box)만 보임");
    Ok(())
}

fn read_state_text(path: &Path, out: &mut String) {
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                read_state_text(&path, out);
            } else if let Ok(bytes) = fs::read(&path) {
                out.push_str(&String::from_utf8_lossy(&bytes));
                out.push('\n');
            }
        }
    }
}

fn sweep(d: &mut Demo, r: &Running, root: &Path) -> Result<(), Error> {
    d.say("[6] 유출 검사");
    let encodings = [
        r.synthetic.clone(),
        pybase64::b64encode(r.synthetic.as_bytes()),
        hex::encode(r.synthetic.as_bytes()),
        url_quote(&r.synthetic),
    ];
    let visible = d.visible.join("\n");
    d.check(
        !encodings.iter().any(|e| visible.contains(e.as_str())),
        "에이전트가 본 모든 도구 응답·실행 출력에 토큰 없음",
    );
    let mut state_text = String::new();
    read_state_text(&root.join("state"), &mut state_text);
    d.check(
        !encodings.iter().any(|e| state_text.contains(e.as_str())),
        "상태 디렉터리 파일(감사 기록 포함)에 평문 토큰 없음",
    );
    d.check(
        !r.server
            .log_lines()
            .iter()
            .any(|line| line.contains("zpw1.")),
        "서버 로그에 핸들 없음",
    );
    let raw_audit = fs::read(root.join("state").join("audit").join("audit.jsonl"))
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .map_err(|_| Error::state("demo_audit_missing"))?;
    d.check(
        !raw_audit.contains("PRIVATE KEY")
            && !raw_audit.contains(&hex::encode(r.user_key.seed().expose())),
        "감사 기록에 SSH 개인키 없음",
    );
    d.say("    최근 감사 기록 (값 없음):");
    let text = |v: &Value| match v {
        Value::String(s) if !s.is_empty() => s.clone(),
        _ => String::new(),
    };
    for record in r.ctx.audit.tail(12)? {
        d.say(&format!(
            "      {} {:<22} {:<8} {}",
            text(&record["ts"]),
            text(&record["event"]),
            text(&record["result"]),
            text(&record["reason"])
        ));
    }
    let alerts = r.ctx.audit.alerts(50)?;
    let mut kinds: Vec<String> = alerts
        .iter()
        .filter_map(|a| a["alert"].as_str().map(str::to_owned))
        .collect();
    kinds.sort();
    kinds.dedup();
    d.say(&format!(
        "    알림 {}건: {}",
        alerts.len(),
        repr_list(&kinds)
    ));
    Ok(())
}

fn intrusion_demo(d: &mut Demo, r: &Running) -> Result<(), Error> {
    d.say("[7] 침입 시뮬레이션: 미제공 도구 반복 호출 -> 자동 봉쇄");
    // The detector is installed only for this phase, so the weak signals from
    // [2]-[6] (pending approvals, revocations) do not mix with the two
    // unknown-tool calls that reach the strong-signal threshold of two.
    let _detector = intrusion::install(r.ctx.clone(), None)?;

    let (status, body) = d.call("reveal_secret", json!({}));
    d.check(
        status == 404 && body["reason"] == "tool_not_found",
        "미제공 도구 1차 호출 -> tool_not_found",
    );
    d.check(
        r.ctx.policy.open_incident_id()?.is_none(),
        "1차 호출만으로는 아직 봉쇄되지 않음 (강한 신호 임계 2회)",
    );
    let (status, body) = d.call("reveal_secret", json!({}));
    d.check(
        status == 404 && body["reason"] == "tool_not_found",
        "미제공 도구 2차 호출 -> tool_not_found",
    );

    let incident_id = r.ctx.policy.open_incident_id()?;
    d.check(
        incident_id.is_some(),
        "2차 호출로 사건 자동 개설 (같은 호출 안에서 봉쇄까지 완료)",
    );
    let found = match &incident_id {
        Some(id) => Some(incident::get_incident(&r.ctx, id)?),
        None => None,
    };
    let rule = |i: &incident::Incident| i.rule.clone().unwrap_or_else(|| "None".into());
    if let Some(i) = &found {
        d.check(i.scope == "principal", &format!("봉쇄 범위: {}", i.scope));
        d.check(
            i.rule.as_deref() == Some("unknown_tool"),
            &format!("판정 규칙: {}", rule(i)),
        );
        d.say(&format!(
            "    사건 {}: 범위={} 규칙={} 판정 방식={}",
            i.id,
            i.scope,
            rule(i),
            i.trigger
        ));
    }

    let (status, body) = d.call("list_connections", json!({}));
    d.check(
        status == 401 && body["reason"] == "principal_disabled",
        "봉쇄 뒤 같은 호출 주체의 다음 호출 -> principal_disabled",
    );
    let intrusion_alerts = r
        .ctx
        .audit
        .alerts(50)?
        .iter()
        .filter(|a| a["alert"] == "intrusion")
        .count();
    d.check(
        intrusion_alerts >= 1,
        &format!("침입 알림 {intrusion_alerts}건"),
    );

    if let Some(i) = found {
        d.check(
            i.notification["status"] == "not_configured",
            "notify.json을 설정하지 않은 데모: notification=not_configured (이메일 없이도 봉쇄는 완전함)",
        );
        let now = store::iso(Some((r.ctx.clock)()));
        let (subject, body_text) = notify::render_incident_email(&i, &now);
        d.say("    렌더링된 교체 안내 이메일 (notify.json 미설정이라 실제로 발송하지는 않음):");
        d.say(&format!("    제목: {subject}"));
        for line in body_text.lines() {
            d.say(&format!("      {line}"));
        }

        d.say("[8] 복구: 사건을 닫고 새 호출 주체로 재개");
        incident::close_incident(&r.ctx, &i.id)?;
        let new_token = r.ctx.policy.create_principal("agent-2", "default")?;
        r.ctx
            .policy
            .create_grant("agent-2", "gh", Some(600), Some(10))?;
        r.ctx.policy.resume()?;
        let old_token = std::mem::replace(&mut d.caller_token, new_token);
        let (status, body) = d.call(
            "request",
            json!({"connection": "gh", "method": "GET", "path": "/repos"}),
        );
        d.check(
            status == 200 && body["status"] == 200,
            "사건을 닫고 새 호출 주체로 재개한 뒤 request 다시 성공",
        );
        d.caller_token = old_token;
        let (status, body) = d.call("list_connections", json!({}));
        d.check(
            status == 401 && body["reason"] == "principal_disabled",
            "비활성화된 예전 호출 주체는 그대로 거부됨",
        );
    }
    Ok(())
}

fn phases(d: &mut Demo, r: &Running, root: &Path) -> Result<(), Error> {
    normal_flow(d, r);
    attacks(d, r)?;
    ssh_demo(d, r)?;
    revocation(d, r)?;
    sweep(d, r, root)?;
    intrusion_demo(d, r)
}

fn teardown(r: Running) {
    // `stop` also shuts down the run registry and the SSH signer manager.
    r.server.stop();
    let mut upstream = r.upstream;
    upstream.stop();
}

fn make_root() -> Result<PathBuf, Error> {
    tempfile::Builder::new()
        .prefix("zeropw-demo-")
        .tempdir()
        .map(tempfile::TempDir::keep)
        .map_err(|_| Error::state("demo_temp_failed"))
}

/// Run all synthetic demonstrations; returns 0 only when every check passes.
pub fn main() -> i32 {
    let mut d = Demo {
        failures: Vec::new(),
        checks: 0,
        visible: Vec::new(),
        url: String::new(),
        caller_token: String::new(),
    };
    let root = match make_root() {
        Ok(root) => root,
        Err(e) => {
            eprintln!("demo setup failed: {e}");
            return 1;
        }
    };
    let outcome = match setup(&mut d, &root) {
        Ok(running) => {
            let outcome = phases(&mut d, &running, &root);
            teardown(running);
            outcome
        }
        Err(e) => Err(e),
    };
    let _ = fs::remove_dir_all(&root);
    if let Err(e) = outcome {
        // Python lets the exception escape with a traceback; the native demo
        // reports the value-free error and fails.
        eprintln!("demo aborted: {e}");
        return 1;
    }
    if !d.failures.is_empty() {
        d.say(&format!(
            "\n{}개 확인 실패 / 총 {}개:",
            d.failures.len(),
            d.checks
        ));
        for label in &d.failures {
            d.say(&format!("  - {label}"));
        }
        return 1;
    }
    d.say(&format!(
        "\n모든 확인 통과 ({}개). 합성 자격증명은 신뢰 프로세스 밖으로 나가지 않았다.",
        d.checks
    ));
    0
}
