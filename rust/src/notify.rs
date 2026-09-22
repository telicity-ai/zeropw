//! Replacement guidance email, port of `zeropw/notify.py`.
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use serde_json::{Value, json};

use crate::audit::RecordArgs;
use crate::context::Context;
use crate::errors::{Error, Result};
use crate::incident::{self, Incident};
use crate::store::iso;

pub const NOTIFY_FILE: &str = "notify.json";
pub const DEFAULT_TIMEOUT_SECONDS: f64 = 20.0;
pub const MAX_BACKOFF_SECONDS: f64 = 300.0;

#[derive(Clone, Debug, PartialEq)]
pub struct NotifyConfig {
    pub host: String,
    pub port: u16,
    pub mode: String,
    pub sender: String,
    pub recipients: Vec<String>,
    pub username: Option<String>,
    pub password_file: Option<PathBuf>,
    pub timeout_seconds: f64,
}

fn secure_file(path: &Path) -> Result<()> {
    let m = path
        .metadata()
        .map_err(|_| Error::invalid_input("notify_config_insecure"))?;
    if m.permissions().mode() & 0o777 != 0o600 || m.uid() != unsafe_free_uid() {
        return Err(Error::invalid_input("notify_config_insecure"));
    }
    Ok(())
}
fn unsafe_free_uid() -> u32 {
    std::process::Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(u32::MAX)
}
fn loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}
impl NotifyConfig {
    pub fn load(ctx: &Context) -> Result<Option<Self>> {
        let path = ctx.state.path.join(NOTIFY_FILE);
        if !path.exists() {
            return Ok(None);
        }
        secure_file(&path)?;
        let data: Value = serde_json::from_slice(
            &fs::read(path).map_err(|_| Error::invalid_input("notify_config_corrupt"))?,
        )
        .map_err(|_| Error::invalid_input("notify_config_corrupt"))?;
        let obj = data
            .as_object()
            .ok_or_else(|| Error::invalid_input("notify_config_corrupt"))?;
        let field = |k: &str| -> Result<String> {
            obj.get(k)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| Error::invalid_input("notify_config_invalid"))
        };
        let host = field("host")?;
        let port =
            obj.get("port")
                .and_then(Value::as_u64)
                .filter(|n| (1..=65535).contains(n))
                .ok_or_else(|| Error::invalid_input("notify_config_invalid"))? as u16;
        let mode = field("mode")?;
        if !["plain", "starttls", "smtps"].contains(&mode.as_str()) {
            return Err(Error::invalid_input("notify_config_invalid"));
        }
        let sender = field("sender")?;
        let recipients = obj
            .get("recipients")
            .and_then(Value::as_array)
            .filter(|a| !a.is_empty())
            .ok_or_else(|| Error::invalid_input("notify_config_invalid"))?
            .iter()
            .map(|r| {
                r.as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| Error::invalid_input("notify_config_invalid"))
            })
            .collect::<Result<Vec<_>>>()?;
        let username = match obj.get("username") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
            _ => return Err(Error::invalid_input("notify_config_invalid")),
        };
        let password_file = match obj.get("password_file") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if !s.is_empty() => {
                let p = PathBuf::from(s);
                secure_file(&p)?;
                Some(p)
            }
            _ => return Err(Error::invalid_input("notify_config_invalid")),
        };
        let timeout_seconds = match obj.get("timeout_seconds") {
            None => DEFAULT_TIMEOUT_SECONDS,
            Some(v) => v
                .as_f64()
                .filter(|f| *f > 0.0)
                .ok_or_else(|| Error::invalid_input("notify_config_invalid"))?,
        };
        if mode == "plain" && !loopback(&host) {
            return Err(Error::invalid_input("notify_plain_requires_loopback"));
        }
        Ok(Some(Self {
            host,
            port,
            mode,
            sender,
            recipients,
            username,
            password_file,
            timeout_seconds,
        }))
    }
}

fn display(v: &Value) -> String {
    v.as_str().map(str::to_owned).unwrap_or_else(|| {
        if v.is_null() {
            "None".into()
        } else {
            crate::pystr::repr_value(v)
        }
    })
}
fn get<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or(&Value::Null)
}
fn fallback(v: &Value) -> String {
    if v.is_null() || v == "" {
        "알 수 없음".into()
    } else {
        display(v)
    }
}
fn secret_block(s: &Value, mandatory: bool) -> Vec<String> {
    let mut lines = vec![
        format!(
            "* 비밀 ID: {}  (종류: {}, 서비스: {})",
            display(get(s, "secret_id")),
            display(get(s, "kind")),
            fallback(get(s, "service"))
        ),
        format!(
            "  프로젝트/환경: {}/{}  현재 활성 버전: {}",
            display(get(s, "project")),
            display(get(s, "environment")),
            display(get(s, "active_version"))
        ),
    ];
    if let Some(cs) = s["connections"].as_array().filter(|a| !a.is_empty()) {
        lines.push(format!(
            "  연결: {}",
            cs.iter().map(display).collect::<Vec<_>>().join(", ")
        ));
    }
    let labels: Vec<_> = s["targets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|t| {
            let host = t.get("host")?.as_str()?;
            let mut label = if let Some(port) = t.get("port").filter(|v| !v.is_null()) {
                format!("{host}:{}", display(port))
            } else {
                host.to_owned()
            };
            if let Some(user) = t
                .get("username")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                label = format!("{user}@{label}");
            }
            Some(label)
        })
        .collect();
    if !labels.is_empty() {
        lines.push(format!("  대상: {}", labels.join(", ")));
    }
    if mandatory {
        lines.push(format!(
            "  첫 사용: {}  마지막 사용: {}  사용 횟수: {}",
            if s["first_used"].is_null() {
                "없음".into()
            } else {
                display(&s["first_used"])
            },
            if s["last_used"].is_null() {
                "없음".into()
            } else {
                display(&s["last_used"])
            },
            s["use_count"].as_u64().unwrap_or(0)
        ));
    }
    let steps: &[&str] = match s["kind"].as_str().unwrap_or("") {
        "api_key" | "env_var" => &[
            "공급자 콘솔에서 이 자격증명을 폐기하고 재발급하십시오.",
            "`rotation start` -> `rotation activate` -> `rotation finish` 순서로 금고의 값을 교체하십시오.",
            "공급자 감사 로그에서 토큰 생성 시각 이후의 행위를 검토하십시오.",
        ],
        "password" => &[
            "서비스에서 비밀번호를 변경하십시오.",
            "`rotation start` -> `rotation activate` -> `rotation finish` 순서로 금고의 값을 교체하십시오.",
            "해당 서비스의 활성 세션을 종료하십시오.",
        ],
        "ssh_private_key" => &[
            "새 키를 생성하십시오.",
            "대상 서버마다 authorized_keys에서 지문 {fingerprint}인 키를 제거하고 새 키로 교체하십시오.",
            "대상 서버에서 활성 세션을 확인하고 종료하십시오 (who, ss -tnp).",
            "`rotation start` -> `rotation activate` -> `rotation finish` 순서로 금고의 값을 교체하십시오.",
        ],
        _ => &["공급자와 협의해 이 자격증명을 교체하십시오."],
    };
    let fingerprint = fallback(get(s, "fingerprint"));
    for (n, step) in steps.iter().enumerate() {
        lines.push(format!(
            "  {}. {}",
            n + 1,
            step.replace("{fingerprint}", &fingerprint)
        ));
    }
    lines
}

pub fn render_incident_email(i: &Incident, now: &str) -> (String, String) {
    let subject = format!(
        "[ZeroPW] 침입 감지 — 서비스 정지, 자격증명 교체 필요 (사건 {})",
        i.id
    );
    let secrets = i.assessment["secrets"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mandatory: Vec<_> = secrets
        .iter()
        .filter(|s| s["tier"] == "mandatory")
        .collect();
    let recommended: Vec<_> = secrets
        .iter()
        .filter(|s| s["tier"] == "recommended")
        .collect();
    let mut l = vec![
        format!("안내 생성 시각: {now}"),
        String::new(),
        "1. 무슨 일이 있었나".into(),
        format!("사건 ID: {}", i.id),
        format!("사건 시각: {}  (판정 방식: {})", i.opened_at, i.trigger),
    ];
    let scope = match i.scope.as_str() {
        "principal" => "호출 주체",
        "runtime" => "실행 환경",
        "all" => "전체",
        s => s,
    };
    l.push(format!(
        "봉쇄 범위: {scope}{}",
        i.runtime
            .as_ref()
            .map(|r| format!(" (실행 환경: {r})"))
            .unwrap_or_default()
    ));
    if let Some(rule) = &i.rule {
        l.push(format!("판정 규칙: {rule}"));
    }
    l.push("침해된 호출 주체:".into());
    let mut views: Vec<String> = i.assessment["principals"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| {
            v["id"]
                .as_str()
                .map(|pid| format!("  - {pid} (토큰 생성: {})", fallback(&v["created_at"])))
        })
        .collect();
    if views.is_empty() {
        views = i.principals.iter().map(|p| format!("  - {p}")).collect();
    }
    l.extend(views);
    l.extend([
        String::new(),
        "2. ZeroPW가 이미 한 것".into(),
        format!(
            "전체 정지: {}",
            if i.actions["stopped"] == true {
                "예"
            } else {
                "아니오"
            }
        ),
        format!(
            "비활성화된 호출 주체 수: {}",
            i.actions["principals_disabled"].as_u64().unwrap_or(0)
        ),
        format!(
            "회수한 권한 수: {}",
            i.actions["grants_revoked"].as_u64().unwrap_or(0)
        ),
        format!(
            "핸들 키 교체: {}",
            if i.actions["handle_key_rotated"] == true {
                "예"
            } else {
                "아니오"
            }
        ),
        format!(
            "취소한 실행 수: {}",
            i.actions["runs_cancelled"].as_u64().unwrap_or(0)
        ),
        format!(
            "닫은 서명기 소켓 수: {}",
            i.actions["sockets_closed"].as_u64().unwrap_or(0)
        ),
        String::new(),
        "3. 지금 해야 할 것 — 필수 교체".into(),
    ]);
    if mandatory.is_empty() {
        l.push("필수 교체 대상이 없습니다.".into());
        l.push(String::new());
    } else {
        for s in mandatory {
            l.extend(secret_block(s, true));
            l.push(String::new());
        }
    }
    l.push("4. 권장 교체".into());
    if recommended.is_empty() {
        l.push("권장 교체 대상이 없습니다.".into());
        l.push(String::new());
    } else {
        for s in recommended {
            l.push(format!(
                "* 비밀 ID: {}  (종류: {}) - 사용 기록 없이 권한만 보유",
                display(get(s, "secret_id")),
                display(get(s, "kind"))
            ));
        }
        l.push(String::new());
    }
    l.push("5. 실행 환경".into());
    if i.scope == "runtime" || i.scope == "all" {
        l.push("침해된 실행 환경(호스트)을 폐기하고 새로 구축하십시오. 기존 호출 주체의 토큰은 되살아나지 않습니다.".into());
    } else {
        l.push("실행 환경 자체의 침해를 배제할 수 없다면, 같은 실행 환경에 새 호출 주체를 만들기 전에 그 실행 환경을 재구축하고 다음 명령으로 범위를 넓히십시오:".into());
        l.push(format!(
            "  incident escalate --id {} --scope runtime|all",
            i.id
        ));
        l.push("기존 호출 주체의 토큰은 되살아나지 않습니다.".into());
    }
    l.extend([
        String::new(),
        "6. 복구 명령".into(),
        format!("  incident show --id {}", i.id),
        "  (위 필수 교체를 모두 완료한 뒤)".into(),
        format!("  incident close --id {}", i.id),
        "  principal create --runtime <실행 환경 ID>".into(),
        "  grant create --principal <새 호출 주체 ID> --connection <연결 ID>".into(),
        "  resume".into(),
    ]);
    if i.scope == "all" || i.assessment["recover_required"] == true {
        l.extend([
            String::new(),
            "이 사건은 금고 전체 노출로 판정되었습니다. `incident close` 전에 다음을 수행하십시오:"
                .into(),
            "  recover   (새 KMS 키, 권한 전부 회수, 핸들 키 교체)".into(),
            "  관리자 패스프레이즈와 복구 패스프레이즈를 모두 변경하십시오.".into(),
        ]);
    }
    (subject, l.join("\n") + "\n")
}

fn audit_notify(ctx: &Context, i: &mut Incident, result: &str, reason: &str) {
    if ctx
        .audit
        .record(
            "incident_notify",
            RecordArgs {
                result: Some(result),
                reason: Some(reason),
                extra: vec![
                    ("incident_id", json!(i.id)),
                    ("scope", json!(i.scope)),
                    ("runtime", json!(i.runtime)),
                ],
                ..Default::default()
            },
        )
        .is_err()
    {
        let failed = &mut i.actions["failed_steps"];
        if let Some(arr) = failed.as_array_mut() {
            if !arr.contains(&json!("audit_incident_notify")) {
                arr.push(json!("audit_incident_notify"));
            }
        }
    }
}
fn pending(ctx: &Context, i: &mut Incident, reason: &str) -> Result<()> {
    let attempts = i.notification["attempts"].as_u64().unwrap_or(0);
    let delay = 2f64.powi(attempts.min(30) as i32).min(MAX_BACKOFF_SECONDS);
    i.notification = json!({"status":"pending","attempts":attempts+1,"last_error":reason,"next_attempt_at":(ctx.clock)()+delay});
    audit_notify(ctx, i, "denied", reason);
    incident::save_incident(ctx, i)
}
fn failed(ctx: &Context, i: &mut Incident, reason: &str) -> Result<()> {
    let attempts = i.notification["attempts"].as_u64().unwrap_or(0);
    i.notification = json!({"status":"failed","reason":reason,"attempts":attempts});
    audit_notify(ctx, i, "denied", reason);
    incident::save_incident(ctx, i)
}

pub fn deliver(ctx: &Arc<Context>, i: &mut Incident) -> Result<()> {
    let config = match NotifyConfig::load(ctx) {
        Ok(v) => v,
        Err(e) => {
            pending(ctx, i, &e.reason)?;
            return Ok(());
        }
    };
    let Some(config) = config else {
        let attempts = i.notification["attempts"].as_u64().unwrap_or(0);
        i.notification = json!({"status":"not_configured","attempts":attempts});
        audit_notify(ctx, i, "ok", "not_configured");
        incident::save_incident(ctx, i)?;
        return Ok(());
    };
    let (subject, body) = render_incident_email(i, &iso(Some((ctx.clock)())));
    if incident::value_leak(ctx, format!("{subject}\n{body}").as_bytes()) {
        failed(ctx, i, "rendered_value_detected")?;
        return Ok(());
    }
    if let Err(kind) = send(&config, &subject, &body) {
        pending(ctx, i, &kind)?;
        return Ok(());
    }
    let attempts = i.notification["attempts"].as_u64().unwrap_or(0);
    i.notification =
        json!({"status":"sent","attempts":attempts+1,"sent_at":iso(Some((ctx.clock)()))});
    audit_notify(ctx, i, "ok", "sent");
    incident::save_incident(ctx, i)
}
pub fn retry_pending(ctx: &Arc<Context>, now: f64) -> Result<usize> {
    let Some(id) = ctx.policy.open_incident_id()? else {
        return Ok(0);
    };
    let Ok(mut i) = incident::get_incident(ctx, &id) else {
        return Ok(0);
    };
    if i.status != "open"
        || i.notification["status"] != "pending"
        || i.notification["next_attempt_at"]
            .as_f64()
            .is_none_or(|t| t > now)
    {
        return Ok(0);
    }
    deliver(ctx, &mut i)?;
    Ok(1)
}
pub fn send_test_message(ctx: &Arc<Context>) -> Result<Value> {
    let config = match NotifyConfig::load(ctx) {
        Ok(v) => v,
        Err(e) => {
            audit_test(ctx, "denied", &e.reason);
            return Ok(json!({"status":"config_invalid","reason":e.reason}));
        }
    };
    let Some(config) = config else {
        audit_test(ctx, "ok", "not_configured");
        return Ok(json!({"status":"not_configured"}));
    };
    let result = send(
        &config,
        "[ZeroPW] 알림 설정 시험 메시지",
        "ZeroPW 알림 설정을 확인하기 위한 시험 메시지입니다.\n실제 침입 사건이 아닙니다. 이 메시지가 도착했다면 SMTP 설정이 올바르게 동작합니다.\n",
    );
    match result {
        Ok(()) => {
            audit_test(ctx, "ok", "sent");
            Ok(json!({"status":"sent"}))
        }
        Err(kind) => {
            audit_test(ctx, "denied", &kind);
            Ok(json!({"status":"failed","error":kind}))
        }
    }
}
fn audit_test(ctx: &Context, result: &str, reason: &str) {
    let _ = ctx.audit.record(
        "incident_notify",
        RecordArgs {
            result: Some(result),
            reason: Some(reason),
            extra: vec![("kind", json!("notify_test"))],
            ..Default::default()
        },
    );
}

// SMTP transport uses a verified TLS stream for STARTTLS/SMTPS. No credentials are retained.
type Wire = Box<dyn ReadWrite>;
trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}
fn smtp_error() -> String {
    "SMTPException".into()
}
fn io_error() -> String {
    "OSError".into()
}
fn io_error_kind(e: std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::ConnectionRefused => "ConnectionRefusedError",
        std::io::ErrorKind::ConnectionReset => "ConnectionResetError",
        std::io::ErrorKind::BrokenPipe => "BrokenPipeError",
        std::io::ErrorKind::TimedOut => "TimeoutError",
        std::io::ErrorKind::NotFound => "FileNotFoundError",
        _ => "OSError",
    }
    .into()
}
fn send(config: &NotifyConfig, subject: &str, body: &str) -> std::result::Result<(), String> {
    let timeout = Duration::from_secs_f64(config.timeout_seconds.min(86400.0));
    let addr = (config.host.as_str(), config.port)
        .to_socket_addrs()
        .map_err(|_| io_error())?
        .next()
        .ok_or_else(io_error)?;
    let tcp = TcpStream::connect_timeout(&addr, timeout).map_err(io_error_kind)?;
    tcp.set_read_timeout(Some(timeout))
        .map_err(|_| io_error())?;
    tcp.set_write_timeout(Some(timeout))
        .map_err(|_| io_error())?;
    let mut wire: Wire = if config.mode == "smtps" {
        tls(config, tcp.try_clone().map_err(|_| io_error())?)?
    } else {
        Box::new(tcp.try_clone().map_err(|_| io_error())?)
    };
    response(&mut wire, 220)?;
    command(&mut wire, "EHLO localhost\r\n", 250)?;
    if config.mode == "starttls" {
        command(&mut wire, "STARTTLS\r\n", 220)?;
        drop(wire);
        let mut secure = tls(config, tcp)?;
        command(&mut secure, "EHLO localhost\r\n", 250)?;
        return send_after_greeting(&mut secure, config, subject, body);
    }
    send_after_greeting(&mut wire, config, subject, body)
}
fn send_after_greeting(
    wire: &mut Wire,
    config: &NotifyConfig,
    subject: &str,
    body: &str,
) -> std::result::Result<(), String> {
    if let Some(user) = &config.username {
        command(wire, "AUTH LOGIN\r\n", 334)?;
        let user = base64::engine::general_purpose::STANDARD.encode(user);
        command(wire, &format!("{user}\r\n"), 334)?;
        let password = config
            .password_file
            .as_ref()
            .map(|p| fs::read_to_string(p).map(|s| s.trim().to_owned()))
            .transpose()
            .map_err(|_| io_error())?
            .unwrap_or_default();
        let pw = base64::engine::general_purpose::STANDARD.encode(password);
        command(wire, &format!("{pw}\r\n"), 235)?;
    }
    command(wire, &format!("MAIL FROM:<{}>\r\n", config.sender), 250)?;
    for recipient in &config.recipients {
        command(wire, &format!("RCPT TO:<{recipient}>\r\n"), 250)?;
    }
    command(wire, "DATA\r\n", 354)?;
    let content = base64::engine::general_purpose::STANDARD.encode(body);
    let mut msg = format!(
        "Subject: =?utf-8?b?{}?=\r\nFrom: {}\r\nTo: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"utf-8\"\r\nContent-Transfer-Encoding: base64\r\n\r\n",
        base64::engine::general_purpose::STANDARD.encode(subject),
        config.sender,
        config.recipients.join(", ")
    );
    for chunk in content.as_bytes().chunks(76) {
        msg.push_str(std::str::from_utf8(chunk).map_err(|_| smtp_error())?);
        msg.push_str("\r\n");
    }
    msg.push_str(".\r\n");
    wire.write_all(msg.as_bytes()).map_err(|_| io_error())?;
    wire.flush().map_err(|_| io_error())?;
    response(wire, 250)?;
    let _ = command(wire, "QUIT\r\n", 221);
    Ok(())
}
fn command(wire: &mut Wire, cmd: &str, expected: u16) -> std::result::Result<(), String> {
    wire.write_all(cmd.as_bytes()).map_err(|_| io_error())?;
    wire.flush().map_err(|_| io_error())?;
    response(wire, expected)
}
fn response(wire: &mut Wire, expected: u16) -> std::result::Result<(), String> {
    let mut reader = BufReader::new(wire);
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|_| io_error())?;
        if line.len() < 4 {
            return Err(smtp_error());
        }
        let code = line[..3].parse::<u16>().map_err(|_| smtp_error())?;
        if code != expected {
            return Err(smtp_error());
        }
        if line.as_bytes()[3] != b'-' {
            return Ok(());
        }
    }
}
fn tls(config: &NotifyConfig, tcp: TcpStream) -> std::result::Result<Wire, String> {
    let mut roots = rustls::RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs();
    for cert in certs.certs {
        let _ = roots.add(cert);
    }
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name =
        rustls::pki_types::ServerName::try_from(config.host.clone()).map_err(|_| smtp_error())?;
    let conn = rustls::ClientConnection::new(Arc::new(cfg), name).map_err(|_| smtp_error())?;
    Ok(Box::new(rustls::StreamOwned::new(conn, tcp)))
}
