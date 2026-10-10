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
use crate::smtp::SendError;
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
/// `value or default` inside an f-string: any falsy value (`None`, `""`,
/// `0`, `False`, `[]`, `{}`) selects `default`.
fn or_default(v: &Value, default: &str) -> String {
    if incident::python_truthy(v) {
        display(v)
    } else {
        default.into()
    }
}
fn fallback(v: &Value) -> String {
    or_default(v, "unknown")
}
/// `mapping.get(key, 0)` inside an f-string.
fn get_or_zero(v: &Value, key: &str) -> String {
    v.get(key).map_or_else(|| "0".into(), display)
}
/// Python iteration of `value or []` for the value kinds it can iterate:
/// list items, string characters, dict keys.
fn python_items(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(items) => items.clone(),
        Value::String(text) => text.chars().map(|c| json!(c.to_string())).collect(),
        Value::Object(map) => map.keys().map(|k| json!(k)).collect(),
        _ => vec![],
    }
}
fn secret_block(s: &Value, mandatory: bool) -> Vec<String> {
    let mut lines = vec![
        format!(
            "* Secret ID: {}  (kind: {}, service: {})",
            display(get(s, "secret_id")),
            display(get(s, "kind")),
            fallback(get(s, "service"))
        ),
        format!(
            "  Project/environment: {}/{}  Active version: {}",
            display(get(s, "project")),
            display(get(s, "environment")),
            display(get(s, "active_version"))
        ),
    ];
    let connections = python_items(&s["connections"]);
    if !connections.is_empty() {
        lines.push(format!(
            "  Connections: {}",
            connections
                .iter()
                .map(display)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let labels: Vec<_> = s["targets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|t| {
            let host = display(t.get("host").filter(|v| !v.is_null())?);
            let mut label = if let Some(port) = t.get("port").filter(|v| !v.is_null()) {
                format!("{host}:{}", display(port))
            } else {
                host
            };
            if let Some(user) = t.get("username").filter(|v| incident::python_truthy(v)) {
                label = format!("{}@{label}", display(user));
            }
            Some(label)
        })
        .collect();
    if !labels.is_empty() {
        lines.push(format!("  Targets: {}", labels.join(", ")));
    }
    if mandatory {
        lines.push(format!(
            "  First use: {}  Last use: {}  Use count: {}",
            or_default(&s["first_used"], "none"),
            or_default(&s["last_used"], "none"),
            get_or_zero(s, "use_count")
        ));
    }
    let steps: &[&str] = match s["kind"].as_str().unwrap_or("") {
        "api_key" | "env_var" => &[
            "Revoke and reissue this credential in the provider console.",
            "Replace the vault value with `rotation start` -> `rotation activate` -> `rotation finish`.",
            "Review provider audit logs for activity since token creation.",
        ],
        "password" => &[
            "Change the password at the service.",
            "Replace the vault value with `rotation start` -> `rotation activate` -> `rotation finish`.",
            "Terminate active sessions at the service.",
        ],
        "ssh_private_key" => &[
            "Generate a new key.",
            "On each target server, remove the key with fingerprint {fingerprint} from authorized_keys and replace it with the new key.",
            "Inspect and terminate active sessions on target servers (who, ss -tnp).",
            "Replace the vault value with `rotation start` -> `rotation activate` -> `rotation finish`.",
        ],
        _ => &["Coordinate with the provider to replace this credential."],
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
        "[ZeroPW] Intrusion detected: service stopped, credential rotation required (incident {})",
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
        format!("Report generated: {now}"),
        String::new(),
        "1. What happened".into(),
        format!("Incident ID: {}", i.id),
        format!("Incident time: {}  (trigger: {})", i.opened_at, i.trigger),
    ];
    let scope = i.scope.as_str();
    // `incident.runtime`/`incident.rule` as loaded (any JSON value), each
    // rendered only when truthy.
    let raw = i.to_dict();
    l.push(format!(
        "Containment scope: {scope}{}",
        if incident::python_truthy(&raw["runtime"]) {
            format!(" (runtime: {})", display(&raw["runtime"]))
        } else {
            String::new()
        }
    ));
    if incident::python_truthy(&raw["rule"]) {
        l.push(format!("Detection rule: {}", display(&raw["rule"])));
    }
    l.push("Compromised principals:".into());
    let mut views: Vec<String> = i.assessment["principals"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| {
            v["id"]
                .as_str()
                .map(|pid| format!("  - {pid} (token created: {})", fallback(&v["created_at"])))
        })
        .collect();
    if views.is_empty() {
        views = i.principals.iter().map(|p| format!("  - {p}")).collect();
    }
    l.extend(views);
    l.extend([
        String::new(),
        "2. Actions already taken by ZeroPW".into(),
        format!(
            "Global stop: {}",
            if incident::python_truthy(&i.actions["stopped"]) {
                "yes"
            } else {
                "no"
            }
        ),
        format!(
            "Disabled principals: {}",
            get_or_zero(&i.actions, "principals_disabled")
        ),
        format!(
            "Revoked grants: {}",
            get_or_zero(&i.actions, "grants_revoked")
        ),
        format!(
            "Handle key rotated: {}",
            if incident::python_truthy(&i.actions["handle_key_rotated"]) {
                "yes"
            } else {
                "no"
            }
        ),
        format!(
            "Cancelled runs: {}",
            get_or_zero(&i.actions, "runs_cancelled")
        ),
        format!(
            "Closed signer sockets: {}",
            get_or_zero(&i.actions, "sockets_closed")
        ),
        String::new(),
        "3. Required credential rotation".into(),
    ]);
    if mandatory.is_empty() {
        l.push("No mandatory rotation targets.".into());
        l.push(String::new());
    } else {
        for s in mandatory {
            l.extend(secret_block(s, true));
            l.push(String::new());
        }
    }
    l.push("4. Recommended rotation".into());
    if recommended.is_empty() {
        l.push("No recommended rotation targets.".into());
        l.push(String::new());
    } else {
        for s in recommended {
            l.push(format!(
                "* Secret ID: {}  (kind: {}) - granted authority without recorded use",
                display(get(s, "secret_id")),
                display(get(s, "kind"))
            ));
        }
        l.push(String::new());
    }
    l.push("5. Runtime".into());
    if i.scope == "runtime" || i.scope == "all" {
        l.push("Discard and rebuild the compromised runtime (host). Tokens for existing principals remain invalid.".into());
    } else {
        l.push("If runtime compromise cannot be ruled out, rebuild it before creating new principals there and escalate the incident with:".into());
        l.push(format!(
            "  incident escalate --id {} --scope runtime|all",
            i.id
        ));
        l.push("Tokens for existing principals remain invalid.".into());
    }
    l.extend([
        String::new(),
        "6. Recovery commands".into(),
        format!("  incident show --id {}", i.id),
        "  (after completing all required rotations above)".into(),
        format!("  incident close --id {}", i.id),
        "  principal create --runtime <RUNTIME_ID>".into(),
        "  grant create --principal <NEW_PRINCIPAL_ID> --connection <CONNECTION_ID>".into(),
        "  resume".into(),
    ]);
    if i.scope == "all" || incident::python_truthy(&i.assessment["recover_required"]) {
        l.extend([
            String::new(),
            "This incident is assessed as full vault exposure. Before `incident close`:".into(),
            "  recover   (new KMS key, revoke all grants, rotate handle key)".into(),
            "  Change both administrator and recovery passphrases.".into(),
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
        && let Some(failed) = incident::failed_steps(i)
        && !failed.contains(&json!("audit_incident_notify"))
    {
        failed.push(json!("audit_incident_notify"));
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
    match crate::smtp::send(&config, &subject, &body) {
        Ok(()) => {}
        // `except (OSError, smtplib.SMTPException) as exc`.
        Err(SendError::Caught(kind)) => {
            pending(ctx, i, &kind)?;
            return Ok(());
        }
        // Any other exception leaves `deliver` untouched by it; the incident
        // records `notify` in `failed_steps`.
        Err(SendError::Escaped(error)) => return Err(error),
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
        "[ZeroPW] Notification configuration test",
        "ZeroPW notification configuration test.\nThis is not a real intrusion incident. Receipt confirms the SMTP setup works.\n",
    );
    match result {
        Ok(()) => {
            audit_test(ctx, "ok", "sent");
            Ok(json!({"status":"sent"}))
        }
        Err(SendError::Caught(kind)) => {
            audit_test(ctx, "denied", &kind);
            Ok(json!({"status":"failed","error":kind}))
        }
        Err(SendError::Escaped(error)) => Err(error),
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
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::Command;

    const CHILD_ENV: &str = "ZEROPW_NOTIFY_SECURE_FILE_CHILD";
    const TEST: &str =
        "notify::uid_tests::secure_file_owner_is_compared_with_the_real_uid_without_spawning";

    /// `_require_secure_file` compares `st_uid` with the real uid and never
    /// starts a process. Run the check in a re-executed test process that
    /// cannot start one (non-root: `RLIMIT_NPROC` 0) or whose real and
    /// effective uids differ (root: the file belongs to the real uid 4242
    /// while the effective uid stays 0); the original accepted the file.
    /// Only the test needs `pre_exec` to set up that process state.
    #[test]
    #[allow(unsafe_code)]
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
        // SAFETY: geteuid has no preconditions.
        let root = unsafe { libc::geteuid() } == 0;
        if root {
            std::os::unix::fs::chown(&file, Some(4242), None).unwrap();
        }
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, &file);
        // SAFETY: only async-signal-safe system calls between fork and exec.
        unsafe {
            command.pre_exec(move || {
                if root {
                    if libc::setreuid(4242, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                } else {
                    let none = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    if libc::setrlimit(libc::RLIMIT_NPROC, &none) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let output = command.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(stdout.contains("RUST_VERDICT=true"), "{stdout}");
    }
}
