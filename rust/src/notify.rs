//! Replacement guidance email, port of `zeropw/notify.py`.
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Value, json};

use crate::audit::RecordArgs;
use crate::context::Context;
use crate::errors::{Error, ErrorClass, Result};
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
    // `st.st_uid != os.getuid()`: the *real* user id of this process, read
    // directly (no helper process, so an environment without `id` or
    // unable to spawn cannot turn every file into "insecure").
    if m.permissions().mode() & 0o7777 != 0o600 || m.uid() != rustix::process::getuid().as_raw() {
        return Err(Error::invalid_input("notify_config_insecure"));
    }
    Ok(())
}
fn loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}
fn header_safe(value: &str) -> bool {
    !value.chars().any(|c| c.is_control())
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
                .filter(|s| !s.is_empty() && header_safe(s))
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
                    .filter(|s| !s.is_empty() && header_safe(s))
                    .map(str::to_owned)
                    .ok_or_else(|| Error::invalid_input("notify_config_invalid"))
            })
            .collect::<Result<Vec<_>>>()?;
        let username = match obj.get("username") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if !s.is_empty() && header_safe(s) => Some(s.clone()),
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
        if let Some(arr) = failed.as_array_mut()
            && !arr.contains(&json!("audit_incident_notify"))
        {
            arr.push(json!("audit_incident_notify"));
        }
    }
}
fn python_int_or_zero(v: &Value) -> crate::pyint::PyInt {
    crate::pyint::PyInt::from_python_int(v).unwrap_or_else(|| 0_i64.into())
}
fn next_attempt(attempts: &crate::pyint::PyInt) -> Value {
    crate::pyint::PyInt(&attempts.0 + num_bigint::BigInt::from(1_u8)).value()
}
fn next_success_attempt(value: &Value) -> Value {
    if let Some(integer) = crate::pyint::PyInt::from_python_int(value) {
        return next_attempt(&integer);
    }
    // Unlike the pending/failure paths, Python's successful-send expression
    // adds one directly to a previously persisted floating count.
    value
        .as_f64()
        .map(|number| json!(number + 1.0))
        .unwrap_or_else(|| json!(1))
}
fn retry_delay(attempts: &crate::pyint::PyInt) -> f64 {
    if attempts.0 >= num_bigint::BigInt::from(9_u8) {
        return MAX_BACKOFF_SECONDS;
    }
    // Very negative accepted Python integers underflow to zero. Avoid
    // converting the arbitrary-precision exponent through a narrow integer.
    if attempts.0 < num_bigint::BigInt::from(-1074_i32) {
        return 0.0;
    }
    2f64.powi(
        attempts
            .0
            .to_string()
            .parse::<i32>()
            .expect("bounded exponent"),
    )
}
fn python_number(v: &Value) -> Option<f64> {
    match v {
        Value::Bool(true) => Some(1.0),
        Value::Bool(false) => Some(0.0),
        _ => v.as_f64(),
    }
}
fn pending(ctx: &Context, i: &mut Incident, reason: &str) -> Result<()> {
    let attempts = python_int_or_zero(&i.notification["attempts"]);
    let delay = retry_delay(&attempts);
    i.notification = json!({"status":"pending","attempts":next_attempt(&attempts),"last_error":reason,"next_attempt_at":(ctx.clock)()+delay});
    audit_notify(ctx, i, "denied", reason);
    incident::save_incident(ctx, i)
}
fn failed(ctx: &Context, i: &mut Incident, reason: &str) -> Result<()> {
    let attempts = python_int_or_zero(&i.notification["attempts"]);
    i.notification = json!({"status":"failed","reason":reason,"attempts":attempts.value()});
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
        let attempts = i.notification.get("attempts").cloned().unwrap_or(json!(0));
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
    if let Err(kind) = crate::smtp::send(&config, &subject, &body) {
        pending(ctx, i, &kind)?;
        return Ok(());
    }
    let attempts = next_success_attempt(&i.notification["attempts"]);
    i.notification =
        json!({"status":"sent","attempts":attempts,"sent_at":iso(Some((ctx.clock)()))});
    audit_notify(ctx, i, "ok", "sent");
    incident::save_incident(ctx, i)
}
pub fn retry_pending(ctx: &Arc<Context>, now: f64) -> Result<usize> {
    let Some(id) = ctx.policy.open_incident_id()? else {
        return Ok(0);
    };
    let mut i = match incident::get_incident(ctx, &id) {
        Ok(i) => i,
        Err(e) if e.is(ErrorClass::NotFound) => return Ok(0),
        Err(e) => return Err(e),
    };
    if i.status != "open"
        || i.notification["status"] != "pending"
        || python_number(&i.notification["next_attempt_at"]).is_none_or(|t| t > now)
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
    let result = crate::smtp::send(
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

#[cfg(test)]
mod uid_tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;

    const CHILD_ENV: &str = "ZEROPW_NOTIFY_SECURE_FILE_CHILD";
    const TEST: &str =
        "notify::uid_tests::secure_file_owner_is_compared_with_the_real_uid_without_spawning";

    /// `_require_secure_file` compares `st_uid` with `os.getuid()` (the real
    /// uid) and never starts a process. Run the Rust check in a process that
    /// cannot start one (non-root: `RLIMIT_NPROC` 0) or whose real and
    /// effective uids differ (root: `setreuid`), and compare it with Python's
    /// verdict measured in that same process state before `exec`.
    #[test]
    fn secure_file_owner_is_compared_with_the_real_uid_without_spawning() {
        if let Ok(path) = std::env::var(CHILD_ENV) {
            println!(
                "RUST_VERDICT={}",
                super::secure_file(Path::new(&path)).is_ok()
            );
            return;
        }
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("notify.json");
        std::fs::write(&file, b"{}").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let script = r#"
import os, resource, sys
from pathlib import Path
from zeropw.errors import InvalidInput
from zeropw.notify import _require_secure_file
path, exe, test, child_env = sys.argv[1:5]
if os.geteuid() == 0:
    os.chown(path, 4242, -1)
    os.setreuid(4242, 0)
else:
    resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))
try:
    _require_secure_file(Path(path))
    verdict = True
except InvalidInput:
    verdict = False
print(f"PY_VERDICT={str(verdict).lower()}", flush=True)
os.execve(exe, [exe, test, "--exact", "--nocapture", "--test-threads=1"],
          dict(os.environ, **{child_env: path}))
"#;
        let interpreter =
            std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".to_string());
        let output = Command::new(interpreter)
            .arg("-c")
            .arg(script)
            .arg(&file)
            .arg(std::env::current_exe().unwrap())
            .arg(TEST)
            .arg(CHILD_ENV)
            .env("PYTHONPATH", crate::oracle::repo_root())
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(stdout.contains("PY_VERDICT=true"), "{stdout}");
        assert!(stdout.contains("RUST_VERDICT=true"), "{stdout}");
    }
}
