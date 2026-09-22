//! Agent-native tools, equivalent to `zeropw.tools`.
use crate::{
    audit::RecordArgs,
    context::Context,
    errors::{Error, ErrorClass},
    gateway,
    policy::{Action, Connection, Grant},
    pyjson::{self, DumpOptions},
    runs::{self, Run, RunRegistry},
    signer::{SignerBinding, SignerManager},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Weak};
use zeroize::Zeroize;

pub const TOOL_NAMES: &[&str] = &["list_connections", "request", "exec", "status", "cancel"];
pub const MAX_ARGV_ITEMS: usize = 256;
pub const MAX_ARG_LENGTH: usize = 4096;
pub const MAX_PATH_LENGTH: usize = 4096;
pub const MAX_HEADERS: usize = 64;
pub const MAX_HEADER_VALUE: usize = 8192;
pub const DEFAULT_PATH: &str = "/usr/bin:/bin";
const DROP_RESPONSE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "proxy-authenticate",
    "www-authenticate",
    "set-cookie",
    "set-cookie2",
    "cookie",
    "x-zeropw-handle",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
];
static PUBLIC_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^https?://[A-Za-z0-9.\-\[\]:_]+(?:/[\x21-\x7e]*)?$").unwrap());
static HEADER_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$").unwrap());
static REQUEST_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9._:-]{1,128}$").unwrap());
static RUN_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,64}$").unwrap());

pub fn install(ctx: Arc<Context>) -> Arc<RunRegistry> {
    runs::install(ctx)
}
pub fn set_public_url(ctx: &Context, url: &str) -> Result<String, Error> {
    if !PUBLIC_URL.is_match(url) {
        return Err(Error::invalid_input("invalid_public_url"));
    }
    let clean = url.trim_end_matches('/').to_string();
    *ctx.public_url.write().unwrap() = Some(clean.clone());
    Ok(clean)
}
fn registry(ctx: &Context) -> Result<Arc<RunRegistry>, Error> {
    runs::registry(ctx).ok_or_else(|| Error::state("runs_not_installed"))
}
pub fn signer_manager(ctx: &Context) -> Option<Arc<SignerManager>> {
    ctx.signer_manager
        .lock()
        .unwrap()
        .as_ref()?
        .downcast_ref::<Weak<SignerManager>>()?
        .upgrade()
}
fn string<'a>(
    payload: &'a Map<String, Value>,
    key: &str,
    required: bool,
    max: usize,
) -> Result<Option<&'a str>, Error> {
    match payload.get(key) {
        None | Some(Value::Null) => {
            if required {
                Err(Error::invalid_input(format!("missing_{key}")))
            } else {
                Ok(None)
            }
        }
        Some(Value::String(s)) if s.chars().count() <= max && !s.contains('\0') => Ok(Some(s)),
        _ => Err(Error::invalid_input(format!("invalid_{key}"))),
    }
}
fn required<'a>(p: &'a Map<String, Value>, key: &str, max: usize) -> Result<&'a str, Error> {
    string(p, key, true, max)?.ok_or_else(|| Error::invalid_input(format!("missing_{key}")))
}
pub fn dispatch(
    ctx: &Arc<Context>,
    name: &str,
    caller: &str,
    payload: &Value,
) -> Result<Value, Error> {
    if !TOOL_NAMES.contains(&name) {
        if !caller.is_empty() {
            ctx.audit.record(
                "tools_unknown",
                RecordArgs {
                    caller: Some(caller),
                    result: Some("denied"),
                    reason: Some("tool_not_found"),
                    ..Default::default()
                },
            )?;
        }
        return Err(Error::not_found("tool_not_found"));
    }
    let p = payload
        .as_object()
        .ok_or_else(|| Error::invalid_input("invalid_payload"))?;
    if caller.is_empty() {
        return Err(Error::invalid_input("invalid_caller"));
    }
    match name {
        "list_connections" => list_connections(ctx, caller),
        "request" | "exec" => {
            let connection = required(p, "connection", 4096)?;
            crate::projects::validate_name(connection, "connection")?;
            if name == "exec" {
                let argv = match p.get("argv") {
                    None | Some(Value::Null) => Vec::new(),
                    Some(Value::Array(a)) => {
                        if a.len() > MAX_ARGV_ITEMS {
                            return Err(Error::invalid_input("argv_too_long"));
                        }
                        a.iter()
                            .map(|v| {
                                let s = v
                                    .as_str()
                                    .ok_or_else(|| Error::invalid_input("invalid_argv"))?;
                                if s.chars().count() > MAX_ARG_LENGTH {
                                    return Err(Error::invalid_input("argument_too_long"));
                                }
                                if s.contains('\0') {
                                    return Err(Error::invalid_input("invalid_argv"));
                                }
                                Ok(s.to_string())
                            })
                            .collect::<Result<Vec<_>, Error>>()?
                    }
                    _ => return Err(Error::invalid_input("invalid_argv")),
                };
                exec(ctx, caller, connection, &argv, request_id(p)?)
            } else {
                let method = required(p, "method", 16)?.to_uppercase();
                if !["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
                    .contains(&method.as_str())
                {
                    return Err(Error::invalid_input("invalid_method"));
                }
                let path = required(p, "path", MAX_PATH_LENGTH)?;
                if !path.starts_with('/')
                    || path.bytes().any(|b| !(0x21..=0x7e).contains(&b))
                    || path.contains("://")
                {
                    return Err(Error::invalid_input("invalid_path"));
                }
                let mut headers = Vec::new();
                match p.get("headers") {
                    None | Some(Value::Null) => (),
                    Some(Value::Object(h)) if h.len() <= MAX_HEADERS => {
                        for (name, value) in h {
                            if !HEADER_NAME.is_match(name) {
                                return Err(Error::invalid_input("invalid_header_name"));
                            }
                            let v = value
                                .as_str()
                                .ok_or_else(|| Error::invalid_input("invalid_header_value"))?;
                            if v.chars().count() > MAX_HEADER_VALUE
                                || v.chars().any(|c| {
                                    c <= '\u{8}'
                                        || ('\u{a}'..='\u{1f}').contains(&c)
                                        || c == '\u{7f}'
                                })
                            {
                                return Err(Error::invalid_input("invalid_header_value"));
                            }
                            headers.push((name.clone(), v.into()));
                        }
                    }
                    _ => return Err(Error::invalid_input("invalid_headers")),
                }
                let body = body(p, ctx.config.max_request_body_bytes)?;
                request(
                    ctx,
                    caller,
                    connection,
                    &method,
                    path,
                    &headers,
                    &body,
                    request_id(p)?,
                )
            }
        }
        _ => {
            let id = required(p, "run_id", 64)?;
            if !RUN_ID.is_match(id) {
                return Err(Error::invalid_input("invalid_run_id"));
            }
            if name == "status" {
                status(ctx, caller, id)
            } else {
                cancel(ctx, caller, id)
            }
        }
    }
}
fn request_id(p: &Map<String, Value>) -> Result<Option<&str>, Error> {
    let id = string(p, "request_id", false, 128)?;
    if id.is_some_and(|v| !REQUEST_ID.is_match(v)) {
        return Err(Error::invalid_input("invalid_request_id"));
    }
    Ok(id)
}
fn body(p: &Map<String, Value>, limit: i64) -> Result<Vec<u8>, Error> {
    let text = p.get("body").filter(|v| !v.is_null());
    let encoded = p.get("body_base64").filter(|v| !v.is_null());
    if text.is_some() && encoded.is_some() {
        return Err(Error::invalid_input("invalid_body"));
    }
    let bytes = if let Some(v) = text {
        v.as_str()
            .ok_or_else(|| Error::invalid_input("invalid_body"))?
            .as_bytes()
            .to_vec()
    } else if let Some(v) = encoded {
        crate::pybase64::b64decode_strict(
            v.as_str()
                .ok_or_else(|| Error::invalid_input("invalid_body"))?,
        )
        .map_err(|_| Error::invalid_input("invalid_body_base64"))?
    } else {
        Vec::new()
    };
    if limit < 0 || bytes.len() as u64 > limit as u64 {
        return Err(Error::invalid_input("request_body_too_large"));
    }
    Ok(bytes)
}
pub fn target_label(connection: &Connection) -> Option<String> {
    if connection.kind == "http" {
        connection.http_target.as_ref().map(|t| t.origin())
    } else {
        connection
            .ssh_target
            .as_ref()
            .map(|t| format!("{}:{}", t.host, t.port))
    }
}
fn usable(
    ctx: &Context,
    caller: &str,
    id: &str,
) -> Result<(Option<(Connection, Grant)>, String), Error> {
    for (c, g) in ctx.policy.usable_connections(caller)? {
        if c.id == id {
            return Ok((Some((c, g)), "allowed".into()));
        }
    }
    let action = match ctx.policy.get_connection(id) {
        Ok(c) if c.kind == "ssh" => c
            .ssh_target
            .as_ref()
            .map(|t| Action::ssh(t.username.clone()))
            .unwrap_or_else(|| Action::http("GET", "/")),
        Ok(_) => Action::http("GET", "/"),
        Err(e) if e.class == ErrorClass::NotFound => Action::http("GET", "/"),
        Err(e) => return Err(e),
    };
    let d = ctx.policy.evaluate(caller, id, &action, None)?;
    Ok((
        None,
        if d.allowed {
            "policy_denied".into()
        } else {
            d.reason.to_string()
        },
    ))
}
pub fn list_connections(ctx: &Context, caller: &str) -> Result<Value, Error> {
    let usable = ctx.policy.usable_connections(caller)?;
    ctx.audit.record(
        "tools_list_connections",
        RecordArgs {
            caller: Some(caller),
            action: Some("list"),
            result: Some("ok"),
            extra: vec![("count", json!(usable.len()))],
            ..Default::default()
        },
    )?;
    let raw = ctx.state.read_json(crate::policy::CONNECTIONS, json!({}))?;
    let mut entries = Vec::new();
    for (c, g) in usable {
        let mut entry = c.public_view();
        entry["grant"] = g.public_view()?;
        if let Some(env_id) = raw
            .get(&c.id)
            .and_then(|v| v.get("shared_env"))
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
        {
            entry["synced_at"] =
                json!(crate::team::sync::attached(ctx).and_then(|team| team.synced_at(env_id)));
        }
        entries.push(entry);
    }
    Ok(json!({"connections":entries}))
}
#[allow(clippy::too_many_arguments)]
pub fn request(
    ctx: &Context,
    caller: &str,
    connection: &str,
    method: &str,
    path: &str,
    headers: &gateway::Headers,
    body: &[u8],
    request_id: Option<&str>,
) -> Result<Value, Error> {
    let (known, reason) = usable(ctx, caller, connection)?;
    let Some((known, _)) = known else {
        ctx.audit.record(
            "tools_request",
            RecordArgs {
                caller: Some(caller),
                connection: Some(connection),
                action: Some(method),
                result: Some("denied"),
                reason: Some(&reason),
                request_id,
                extra: vec![("method", json!(method)), ("path", json!(path))],
                ..Default::default()
            },
        )?;
        return Ok(denied_relay(&reason));
    };
    let target = target_label(&known);
    let mismatch = known.kind != "http";
    ctx.audit.record(
        "tools_request",
        RecordArgs {
            caller: Some(caller),
            connection: Some(connection),
            target: target.as_deref(),
            action: Some(method),
            result: Some(if mismatch { "denied" } else { "ok" }),
            reason: if mismatch {
                Some("action_kind_mismatch")
            } else {
                None
            },
            request_id,
            policy_version: Some(known.policy_version),
            extra: if mismatch {
                vec![("method", json!(method)), ("path", json!(path))]
            } else {
                vec![
                    ("method", json!(method)),
                    ("path", json!(path)),
                    ("bytes", json!(body.len())),
                ]
            },
            ..Default::default()
        },
    )?;
    if mismatch {
        return Ok(denied_relay("action_kind_mismatch"));
    }
    let result = gateway::relay_for_caller(
        ctx, caller, connection, method, path, headers, body, request_id,
    );
    let (text, encoded) = match String::from_utf8(result.body.clone()) {
        Ok(s) => (Some(s), None),
        Err(_) => (None, Some(STANDARD.encode(&result.body))),
    };
    let mut filtered = Map::new();
    for (name, value) in result.headers {
        let name = name.to_lowercase();
        if DROP_RESPONSE_HEADERS.contains(&name.as_str()) {
            continue;
        }
        let value = filtered
            .get(&name)
            .and_then(Value::as_str)
            .map_or(value.clone(), |old| format!("{old}, {value}"));
        filtered.insert(name, Value::String(value));
    }
    Ok(
        json!({"status":result.status,"headers":filtered,"body":text,"body_base64":encoded,"reason":result.reason}),
    )
}
fn denied_relay(reason: &str) -> Value {
    json!({"status":403,"headers":{},"body":null,"body_base64":null,"reason":reason})
}
pub fn profile_env_carries_credential(c: &Connection, credential: &[u8]) -> bool {
    let Some(cli) = &c.cli else { return false };
    let mut patterns = runs::credential_patterns(credential);
    let found = std::iter::once(&cli.base_url_env)
        .chain(cli.extra_env.keys())
        .chain(cli.extra_env.values())
        .any(|s| runs::contains_sensitive(s.as_bytes(), &patterns));
    patterns.zeroize();
    found
}
pub fn profile_env_carries_vault_value(ctx: &Context, c: &Connection) -> Result<bool, Error> {
    if c.cli.is_none() {
        return Ok(false);
    }
    let values = ctx
        .vault
        .values_for_trusted_scan()
        .map_err(|_| Error::state("credential_unavailable"))?;
    Ok(values
        .iter()
        .any(|v| profile_env_carries_credential(c, v.expose())))
}
pub fn resolve_program(program: &str) -> Option<PathBuf> {
    let candidates: Vec<_> = if program.contains('/') {
        vec![PathBuf::from(program)]
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_else(|| DEFAULT_PATH.into()))
            .map(|p| p.join(program))
            .collect()
    };
    candidates
        .into_iter()
        .find(|p| p.is_file() && rustix::fs::access(p, rustix::fs::Access::EXEC_OK).is_ok())
        .and_then(|p| std::path::absolute(p).ok())
}
fn child_env(
    dir: &Path,
    id: &str,
    specific: HashMap<String, String>,
    extra: &std::collections::BTreeMap<String, String>,
) -> Result<HashMap<String, String>, Error> {
    let mut env = HashMap::from([
        (
            "PATH".into(),
            std::env::var("PATH").unwrap_or_else(|_| DEFAULT_PATH.into()),
        ),
        ("HOME".into(), dir.to_string_lossy().into_owned()),
        ("LANG".into(), "C.UTF-8".into()),
        ("TMPDIR".into(), dir.to_string_lossy().into_owned()),
        ("ZEROPW_RUN_ID".into(), id.into()),
    ]);
    env.extend(specific);
    for (k, v) in extra {
        if env.contains_key(k) {
            return Err(Error::unsupported("cli_env_conflict"));
        }
        env.insert(k.clone(), v.clone());
    }
    Ok(env)
}
pub fn probe_action(c: &Connection) -> Action {
    if let Some(t) = &c.ssh_target
        && c.kind == "ssh"
    {
        return Action::ssh(t.username.clone());
    }
    let method = c
        .http_scope
        .as_ref()
        .and_then(|s| s.methods.as_ref()?.first())
        .map(String::as_str)
        .unwrap_or("GET");
    let path = c
        .http_scope
        .as_ref()
        .and_then(|s| s.path_prefixes.as_ref()?.first())
        .map(String::as_str)
        .unwrap_or("/");
    Action::http(method, path)
}
pub fn recheck(
    ctx: &Context,
    caller: &str,
    c: &Connection,
    g: &Grant,
) -> Result<Option<String>, Error> {
    if ctx.policy.restore_pending()? {
        return Ok(Some("restore_pending".into()));
    }
    if ctx.policy.is_stopped()? {
        return Ok(Some("global_stop".into()));
    }
    let d = ctx
        .policy
        .evaluate(caller, &c.id, &probe_action(c), Some(&g.id))?;
    Ok((!d.allowed).then_some(d.reason.to_string()))
}
#[allow(clippy::too_many_arguments)]
fn refuse_exec(
    ctx: &Context,
    caller: &str,
    id: &str,
    req: Option<&str>,
    result: &str,
    reason: &str,
    c: Option<&Connection>,
) -> Result<(), Error> {
    let target = c.and_then(target_label);
    ctx.audit.record(
        "tools_exec",
        RecordArgs {
            caller: Some(caller),
            connection: Some(id),
            target: target.as_deref(),
            action: Some("exec"),
            result: Some(result),
            reason: Some(reason),
            request_id: req,
            policy_version: c.map(|c| c.policy_version),
            ..Default::default()
        },
    )?;
    Ok(())
}
fn exec_view(registry: &RunRegistry, run: &Run) -> Value {
    let view = registry.view(run);
    json!({"run_id":view["run_id"],"state":view["state"],"reason":view["reason"]})
}
#[derive(Default)]
struct Resources {
    binding: Option<SignerBinding>,
    dir: Option<tempfile::TempDir>,
}
impl Drop for Resources {
    fn drop(&mut self) {
        if let Some(binding) = self.binding.take() {
            binding.close();
        }
    }
}
fn write_private(path: &Path, text: &str) -> Result<File, Error> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| Error::state("exec_setup_failed"))?;
    f.write_all(text.as_bytes())
        .map_err(|_| Error::state("exec_setup_failed"))?;
    Ok(f)
}
pub fn exec(
    ctx: &Arc<Context>,
    caller: &str,
    id: &str,
    argv: &[String],
    req: Option<&str>,
) -> Result<Value, Error> {
    let registry = registry(ctx)?;
    let digest = hex::encode(Sha256::digest(
        pyjson::dumps(&json!([id, argv]), DumpOptions::compact_sorted())?.as_bytes(),
    ));
    if let Some(req) = req
        && let Some(run) = registry.find_by_request(caller, req, &digest)?
    {
        return Ok(exec_view(&registry, &run));
    }
    let (known, reason) = usable(ctx, caller, id)?;
    let Some((known, grant)) = known else {
        refuse_exec(ctx, caller, id, req, "denied", &reason, None)?;
        return Err(Error::policy_denied(reason));
    };
    let Some(cli) = &known.cli else {
        refuse_exec(
            ctx,
            caller,
            id,
            req,
            "unsupported",
            "cli_not_supported",
            Some(&known),
        )?;
        return Err(Error::unsupported("cli_not_supported"));
    };
    let program =
        resolve_program(&cli.program).ok_or_else(|| Error::unsupported("cli_program_missing"));
    let program = match program {
        Ok(p) => p,
        Err(e) => {
            refuse_exec(ctx, caller, id, req, "unsupported", &e.reason, Some(&known))?;
            return Err(e);
        }
    };
    let public_url = ctx.public_url.read().unwrap().clone();
    let manager = signer_manager(ctx);
    let preflight = match known.kind.as_str() {
        "http" if public_url.as_ref().is_none_or(|s| s.is_empty()) => {
            Some(("failed", Error::state("public_url_unset")))
        }
        "ssh" if manager.is_none() || known.ssh_target.is_none() => {
            Some(("unsupported", Error::unsupported("ssh_signer_unavailable")))
        }
        "http" | "ssh" => None,
        _ => Some(("unsupported", Error::unsupported("cli_kind_unsupported"))),
    };
    if let Some((result, e)) = preflight {
        refuse_exec(ctx, caller, id, req, result, &e.reason, Some(&known))?;
        return Err(e);
    }
    let run_root = ctx
        .config
        .run_dir
        .as_ref()
        .ok_or_else(|| Error::state("run_dir_unset"))?;
    let target = target_label(&known);
    let program_text = program.to_string_lossy();
    let (run, created) = registry.find_or_create(
        caller,
        id,
        &grant.id,
        &known.kind,
        &program_text,
        req,
        &digest,
        target.as_deref(),
        Some(known.policy_version),
    )?;
    if !created {
        return Ok(exec_view(&registry, &run));
    }
    let mut resources = Resources::default();
    let mut sensitive = Vec::new();
    type PreparedProcess = (Vec<String>, HashMap<String, String>, PathBuf);
    let setup = (|| -> Result<PreparedProcess, Error> {
        ctx.audit.record(
            "tools_exec",
            RecordArgs {
                caller: Some(caller),
                connection: Some(id),
                target: target.as_deref(),
                action: Some("exec"),
                result: Some("ok"),
                request_id: req,
                policy_version: Some(known.policy_version),
                extra: vec![
                    ("program", json!(program_text)),
                    ("kind", json!(known.kind)),
                    ("grant", json!(grant.id)),
                    ("count", json!(argv.len())),
                ],
                ..Default::default()
            },
        )?;
        let credential = ctx
            .vault
            .secret_for_trusted_use(&known.secret_id, known.secret_version)
            .map_err(|_| Error::state("credential_unavailable"))?;
        if profile_env_carries_vault_value(ctx, &known)? {
            refuse_exec(
                ctx,
                caller,
                id,
                req,
                "unsupported",
                "cli_env_contains_credential",
                Some(&known),
            )?;
            return Err(Error::unsupported("cli_env_contains_credential"));
        }
        let dir = tempfile::Builder::new()
            .prefix(&format!("{}-", run.id))
            .tempdir_in(run_root)
            .map_err(|_| Error::state("exec_setup_failed"))?;
        let path = dir
            .path()
            .canonicalize()
            .map_err(|_| Error::state("exec_setup_failed"))?;
        resources.dir = Some(dir);
        sensitive.push(credential.expose().to_vec());
        if known.kind == "http" {
            let ttl = ctx.config.handle_ttl_seconds;
            ctx.audit.record(
                "handle_issue",
                RecordArgs {
                    caller: Some(caller),
                    connection: Some(id),
                    target: target.as_deref(),
                    run_id: Some(&run.id),
                    request_id: req,
                    policy_version: Some(known.policy_version),
                    result: Some("ok"),
                    extra: vec![
                        ("grant", json!(grant.id)),
                        (
                            "expires_at",
                            json!(crate::store::iso(Some((ctx.clock)() + ttl as f64))),
                        ),
                    ],
                    ..Default::default()
                },
            )?;
            let handle =
                ctx.handles
                    .issue(caller, id, &grant.id, known.policy_version, ttl, None)?;
            sensitive.push(handle.as_bytes().to_vec());
            let env = child_env(
                &path,
                &run.id,
                HashMap::from([(
                    cli.base_url_env.clone(),
                    format!(
                        "{}/h/{handle}",
                        public_url.as_deref().unwrap_or("").trim_end_matches('/')
                    ),
                )]),
                &cli.extra_env,
            )?;
            let args = std::iter::once(program_text.to_string())
                .chain(argv.iter().cloned())
                .collect();
            Ok((args, env, path))
        } else {
            let ssh = known
                .ssh_target
                .as_ref()
                .ok_or_else(|| Error::unsupported("ssh_signer_unavailable"))?;
            let version = ctx
                .vault
                .resolve_version(&known.secret_id, known.secret_version)
                .map_err(|_| Error::state("credential_unavailable"))?;
            let metadata = ctx
                .vault
                .get_meta(&known.secret_id)
                .map_err(|_| Error::state("credential_unavailable"))?;
            let line = metadata
                .versions
                .iter()
                .find(|v| v.version == version)
                .and_then(|v| v.public.get("public_key"))
                .and_then(Value::as_str)
                .ok_or_else(|| Error::unsupported("ssh_public_key_unavailable"))?;
            let public = crate::sshwire::parse_authorized_key(line)
                .and_then(|k| k.to_authorized_key(&format!("zeropw:{id}")))
                .map_err(|_| Error::unsupported("ssh_public_key_unavailable"))?;
            let binding = manager
                .as_ref()
                .ok_or_else(|| Error::unsupported("ssh_signer_unavailable"))?
                .bind(caller, id, &grant.id)?;
            let socket = binding.socket_path.to_string_lossy().into_owned();
            resources.binding = Some(binding);
            let prefix = if ssh.port == 22 {
                ssh.host.clone()
            } else {
                format!("[{}]:{}", ssh.host, ssh.port)
            };
            let hosts = ssh
                .host_keys
                .iter()
                .map(|key| format!("{prefix} {}\n", key.trim()))
                .collect::<String>();
            let known_hosts = path.join("known_hosts");
            let identity = path.join("id.pub");
            write_private(&known_hosts, &hosts)?;
            write_private(&identity, &format!("{public}\n"))?;
            let env = child_env(
                &path,
                &run.id,
                HashMap::from([("SSH_AUTH_SOCK".into(), socket.clone())]),
                &cli.extra_env,
            )?;
            let mut args = vec![
                program_text.to_string(),
                "-F".into(),
                "/dev/null".into(),
                "-o".into(),
                "IdentitiesOnly=yes".into(),
                "-o".into(),
                format!("IdentityFile={}", identity.display()),
                "-o".into(),
                format!("IdentityAgent={socket}"),
                "-o".into(),
                "ForwardAgent=no".into(),
                "-o".into(),
                "StrictHostKeyChecking=yes".into(),
                "-o".into(),
                format!("UserKnownHostsFile={}", known_hosts.display()),
                "-o".into(),
                "BatchMode=yes".into(),
                "-o".into(),
                "PasswordAuthentication=no".into(),
                "-o".into(),
                "KbdInteractiveAuthentication=no".into(),
                "-p".into(),
                ssh.port.to_string(),
                format!("{}@{}", ssh.username, ssh.host),
                "--".into(),
            ];
            args.extend_from_slice(argv);
            Ok((args, env, path))
        }
    })();
    let (args, env, path) = match setup {
        Ok(v) => v,
        Err(e) => {
            sensitive.zeroize();
            drop(resources);
            let reason = if [
                ErrorClass::AuditUnavailable,
                ErrorClass::StateError,
                ErrorClass::Unsupported,
            ]
            .contains(&e.class)
            {
                e.reason.as_ref()
            } else {
                "exec_setup_failed"
            };
            registry.fail(&run, reason);
            return Err(e);
        }
    };
    if let Some(reason) = recheck(ctx, caller, &known, &grant)? {
        sensitive.zeroize();
        drop(resources);
        registry.cancel(&run.id, caller, &reason)?;
        refuse_exec(ctx, caller, id, req, "denied", &reason, Some(&known))?;
        return Ok(exec_view(&registry, &run));
    }
    let result = registry.start(
        &run,
        &args,
        &env,
        &path,
        &sensitive,
        Some(Box::new(move || drop(resources))),
        None,
    );
    sensitive.zeroize();
    result?;
    Ok(exec_view(&registry, &run))
}
pub fn status(ctx: &Context, caller: &str, id: &str) -> Result<Value, Error> {
    let r = registry(ctx)?;
    let run = lookup_audited(ctx, &r, caller, id, "tools_status", "status")?;
    let target = run.target.as_deref();
    ctx.audit.record(
        "tools_status",
        RecordArgs {
            caller: Some(caller),
            connection: Some(&run.connection),
            target,
            run_id: Some(id),
            action: Some("status"),
            result: Some("ok"),
            policy_version: run.policy_version,
            extra: vec![("run_state", json!(run.state))],
            ..Default::default()
        },
    )?;
    Ok(r.view(&run))
}
pub fn cancel(ctx: &Context, caller: &str, id: &str) -> Result<Value, Error> {
    let r = registry(ctx)?;
    let run = lookup_audited(ctx, &r, caller, id, "tools_cancel", "cancel")?;
    let audit = ctx.audit.record(
        "tools_cancel",
        RecordArgs {
            caller: Some(caller),
            connection: Some(&run.connection),
            target: run.target.as_deref(),
            run_id: Some(id),
            action: Some("cancel"),
            result: Some("ok"),
            policy_version: run.policy_version,
            extra: vec![("run_state", json!(run.state))],
            ..Default::default()
        },
    );
    r.cancel(id, caller, "cancelled_by_caller")?;
    audit?;
    Ok(exec_view(&r, &run))
}
fn lookup_audited(
    ctx: &Context,
    r: &RunRegistry,
    caller: &str,
    id: &str,
    event: &str,
    action: &str,
) -> Result<Run, Error> {
    match r.get(id, caller) {
        Ok(run) => Ok(run),
        Err(e) => {
            ctx.audit.record(
                event,
                RecordArgs {
                    caller: Some(caller),
                    run_id: Some(id),
                    action: Some(action),
                    result: Some("denied"),
                    reason: Some("run_not_found"),
                    ..Default::default()
                },
            )?;
            Err(e)
        }
    }
}
