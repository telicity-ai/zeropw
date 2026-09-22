//! Trusted administrator CLI. Never invoke this module from an agent process.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

use crate::audit::RecordArgs;
use crate::context::{Config, Context};
use crate::errors::Error;
use crate::policy::{
    CliProfile, Connection, ConnectionChanges, HttpAuth, HttpScope, HttpTarget, SshTarget,
};
use crate::pybase64;
use crate::pyjson::{self, DumpOptions};
use crate::store::iso;
use crate::vault::{MAX_SECRET_BYTES, SecretMeta, Vault};

const PROVIDER_REMINDER: &str = "Retiring a vault version does not revoke the credential at the provider. Revoke the old credential in the provider's console or API now.";

#[derive(Default)]
struct Args {
    state_dir: String,
    command: String,
    action: String,
    options: BTreeMap<String, Vec<String>>,
    positional: Vec<String>,
}

impl Args {
    fn get(&self, key: &str) -> Option<&str> {
        self.options
            .get(key)
            .and_then(|v| v.last())
            .map(String::as_str)
    }
    fn has(&self, key: &str) -> bool {
        self.options.contains_key(key)
    }
    fn req(&self, key: &str) -> &str {
        self.get(key).unwrap_or("")
    }
    fn integer(&self, key: &str) -> Result<Option<i64>, Error> {
        self.get(key)
            .map(|s| {
                s.parse::<i64>()
                    .map_err(|_| Error::invalid_input("invalid_arguments"))
            })
            .transpose()
    }
    fn list(&self, key: &str) -> Vec<String> {
        self.options.get(key).cloned().unwrap_or_default()
    }
}

fn spec(command: &str, action: &str) -> Option<(&'static str, &'static str, &'static str, usize)> {
    // Required-value options, optional-value options, flags, positional count.
    let spec = match (command, action) {
        ("init", "") => ("", "", "", 0),
        ("project", "create") => ("", "environments", "", 1),
        ("project", "list") => ("", "", "", 0),
        ("secret", "put") => (
            "id kind project environment",
            "value-file",
            "stdin staged",
            0,
        ),
        ("secret", "list") => ("", "project environment", "", 0),
        ("secret", "versions") => ("id", "", "", 0),
        ("secret", "reveal") => ("id", "version", "", 0),
        ("secret", "retire" | "revoke") => ("id version", "", "", 0),
        ("connection", "create-http") => (
            "id project environment service secret-id target auth",
            "secret-version header-name value-prefix basic-username methods path-prefixes confirm-methods ca-file cli-program cli-env description",
            "allow-private-network",
            0,
        ),
        ("connection", "create-ssh") => (
            "id project environment service secret-id host username host-key",
            "secret-version port cli-program description",
            "",
            0,
        ),
        ("connection", "list") => ("", "", "", 0),
        ("connection", "show" | "disable") => ("id", "", "", 0),
        ("connection", "update" | "update-scope") => {
            ("id", "methods path-prefixes confirm-methods", "", 0)
        }
        ("connection", "switch-credential") => ("id version", "", "", 0),
        ("principal", "create") => ("id", "runtime", "", 0),
        ("principal", "list") => ("", "", "", 0),
        ("principal", "disable") => ("id", "", "", 0),
        ("grant", "create") => ("principal connection", "ttl max-uses", "", 0),
        ("grant", "list") => ("", "principal", "", 0),
        ("grant", "revoke" | "regrant") => ("id", "", "", 0),
        ("stop-all" | "resume" | "restore-ack" | "recover", "") => ("", "", "", 0),
        ("approvals", "list") => ("", "", "", 0),
        ("approvals", "approve") => ("digest", "", "", 0),
        ("rotation", "start") => ("secret-id", "value-file", "stdin", 0),
        ("rotation", "activate") => ("connection version", "", "", 0),
        ("rotation", "finish") => ("secret-id version", "", "", 0),
        ("backup", "") => ("out", "", "", 0),
        ("restore", "") => ("in", "", "", 0),
        ("incident", "declare") => ("scope", "principal runtime reason", "", 0),
        ("incident", "escalate") => ("id scope", "runtime", "", 0),
        ("incident", "list" | "notify-test") => ("", "", "", 0),
        ("incident", "show" | "close") => ("id", "", "", 0),
        ("audit", "tail") | ("alerts", "") => ("", "limit", "", 0),
        ("team", "init") => ("", "", "", 0),
        ("team", "share") => ("project environment", "name", "", 0),
        ("team", "invite") => ("env role name", "ttl address", "", 0),
        ("team", "join") => ("", "project environment", "", 1),
        ("team", "members" | "status" | "log" | "compact" | "incidents") => ("env", "", "", 0),
        ("team", "show") => ("env", "format", "", 0),
        ("team", "diff") => ("env", "", "", 2),
        ("team", "peers") => ("env", "add device", "", 0),
        ("team", "remove" | "transfer-owner") => ("env device", "", "", 0),
        ("team", "set-role") => ("env device role", "", "", 0),
        ("serve", "") => ("", "listen team-listen", "quiet", 0),
        _ => return None,
    };
    Some(spec)
}

fn parse(argv: &[String]) -> Result<Args, String> {
    let mut a = Args::default();
    let mut i = 0;
    if argv.get(i).map(String::as_str) != Some("--state-dir") {
        return Err("the following arguments are required: --state-dir".into());
    }
    i += 1;
    a.state_dir = argv
        .get(i)
        .cloned()
        .ok_or("argument --state-dir: expected one argument")?;
    i += 1;
    a.command = argv
        .get(i)
        .cloned()
        .ok_or("the following arguments are required: COMMAND")?;
    i += 1;
    if [
        "project",
        "secret",
        "connection",
        "principal",
        "grant",
        "approvals",
        "rotation",
        "incident",
        "audit",
        "team",
    ]
    .contains(&a.command.as_str())
    {
        a.action = argv
            .get(i)
            .cloned()
            .ok_or("the following arguments are required: SUBCOMMAND")?;
        i += 1;
    }
    let (required, optional, flags, positional) =
        spec(&a.command, &a.action).ok_or("invalid choice")?;
    let valid: BTreeSet<&str> = required
        .split_whitespace()
        .chain(optional.split_whitespace())
        .chain(flags.split_whitespace())
        .collect();
    let known_options = [
        "state-dir",
        "id",
        "kind",
        "project",
        "environment",
        "value-file",
        "stdin",
        "version",
        "secret-id",
        "connection",
        "principal",
        "ttl",
        "methods",
        "path-prefixes",
        "confirm-methods",
        "target",
        "auth",
        "host",
        "host-key",
        "listen",
        "env",
        "scope",
        "digest",
        "out",
        "in",
    ];
    let mut extras = Vec::new();
    while i < argv.len() {
        let token = &argv[i];
        if let Some(key) = token.strip_prefix("--") {
            if !valid.contains(key) {
                extras.push(token.clone());
                i += 1;
                continue;
            }
            if flags.split_whitespace().any(|f| f == key) {
                a.options
                    .entry(key.to_owned())
                    .or_default()
                    .push("true".into());
                i += 1;
                continue;
            }
            i += 1;
            let value = argv
                .get(i)
                .ok_or_else(|| format!("argument --{key}: expected one argument"))?;
            if value.starts_with("--") {
                return Err(format!("argument --{key}: expected one argument"));
            }
            if key != "host-key" && key != "cli-env" && key != "address" && a.has(key) {
                return Err(format!(
                    "argument --{key}: not allowed with previous argument"
                ));
            }
            a.options
                .entry(key.to_owned())
                .or_default()
                .push(value.clone());
        } else {
            a.positional.push(token.clone());
        }
        i += 1;
    }
    if !extras.is_empty() || a.positional.len() > positional {
        let names: BTreeSet<String> = extras
            .iter()
            .filter_map(|item| item.strip_prefix("--"))
            .filter_map(|name| name.split('=').next())
            .filter(|name| {
                !name.is_empty() && known_options.iter().any(|known| known.starts_with(name))
            })
            .map(|name| format!("--{name}"))
            .collect();
        let count = extras.len() + a.positional.len().saturating_sub(positional);
        let detail = if names.is_empty() {
            String::new()
        } else {
            format!(
                " (not accepted: {})",
                names.into_iter().collect::<Vec<_>>().join(" ")
            )
        };
        return Err(format!(
            "unrecognized arguments: {count}{detail}; values are not echoed"
        ));
    }
    let missing: Vec<String> = required
        .split_whitespace()
        .filter(|key| !a.has(key))
        .map(|key| format!("--{key}"))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "the following arguments are required: {}",
            missing.join(", ")
        ));
    }
    if a.positional.len() != positional {
        return Err(format!(
            "unrecognized arguments: {}; values are not echoed",
            a.positional.len().abs_diff(positional)
        ));
    }
    if ((a.command == "secret" && a.action == "put")
        || (a.command == "rotation" && a.action == "start"))
        && a.has("stdin") == a.has("value-file")
    {
        return Err("one of the arguments --value-file --stdin is required".into());
    }
    for key in ["version", "secret-version", "port", "max-uses", "limit"] {
        if let Some(value) = a.get(key) {
            let number = value
                .parse::<i64>()
                .map_err(|_| format!("argument --{key}: invalid int value"))?;
            if key == "limit" && number < 1 {
                return Err("argument --limit: must be a positive integer".into());
            }
        }
    }
    if a.command == "secret"
        && a.action == "put"
        && !crate::vault::SECRET_KINDS.contains(&a.req("kind"))
    {
        return Err("argument --kind: invalid choice".into());
    }
    if a.command == "connection"
        && a.action == "create-http"
        && !crate::policy::AUTH_MODES.contains(&a.req("auth"))
    {
        return Err("argument --auth: invalid choice".into());
    }
    if a.command == "incident"
        && a.action == "declare"
        && !["principal", "runtime", "all"].contains(&a.req("scope"))
    {
        return Err("argument --scope: invalid choice".into());
    }
    if a.command == "incident"
        && a.action == "escalate"
        && !["runtime", "all"].contains(&a.req("scope"))
    {
        return Err("argument --scope: invalid choice".into());
    }
    if a.command == "team"
        && ["invite", "set-role"].contains(&a.action.as_str())
        && !["admin", "user"].contains(&a.req("role"))
    {
        return Err("argument --role: invalid choice".into());
    }
    Ok(a)
}

fn output(v: &Value, stderr: bool) {
    let text = pyjson::dumps(
        v,
        if stderr {
            DumpOptions::default_sorted()
        } else {
            DumpOptions::pretty_sorted()
        },
    )
    .unwrap_or_else(|_| "{}".into());
    if stderr {
        eprintln!("{text}");
    } else {
        println!("{text}");
    }
}

fn admin_record(ctx: &Context, event: &str, extra: Vec<(&str, Value)>) -> Result<(), Error> {
    ctx.audit.record(
        event,
        RecordArgs {
            caller: Some("admin"),
            result: Some("ok"),
            extra,
            ..Default::default()
        },
    )?;
    Ok(())
}

fn open(a: &Args, mutating: bool) -> Result<Context, Error> {
    let ctx = Context::open(&a.state_dir, Config::default(), crate::clock::system())?;
    if mutating {
        ctx.audit.require_writable()?;
    }
    Ok(ctx)
}

fn passphrase(name: &str) -> Result<String, Error> {
    let value = env::var(name).unwrap_or_default();
    if value.is_empty() {
        Err(Error::auth_failed("passphrase_missing")
            .with_detail(format!("set {name} or run on a terminal")))
    } else {
        Ok(value)
    }
}

fn read_secret(a: &Args, kind: &str) -> Result<Vec<u8>, Error> {
    let mut data = if let Some(path) = a.get("value-file") {
        let file = fs::File::open(path).map_err(|_| Error::invalid_input("file_not_found"))?;
        let mut data = Vec::new();
        file.take((MAX_SECRET_BYTES + 1) as u64)
            .read_to_end(&mut data)
            .map_err(|_| Error::invalid_input("io_error"))?;
        data
    } else if a.has("stdin") {
        let mut data = Vec::new();
        io::stdin()
            .take((MAX_SECRET_BYTES + 1) as u64)
            .read_to_end(&mut data)
            .map_err(|_| Error::invalid_input("io_error"))?;
        data
    } else {
        return Err(Error::invalid_input("secret_source_required")
            .with_detail("use --value-file or --stdin"));
    };
    if kind != "ssh_private_key" {
        if data.ends_with(b"\r\n") {
            data.truncate(data.len() - 2);
        } else if data.ends_with(b"\n") {
            data.truncate(data.len() - 1);
        }
    }
    if data.is_empty() {
        return Err(Error::invalid_input("empty_secret_value"));
    }
    Ok(data)
}

fn secret_view(m: SecretMeta) -> Value {
    json!({"id":m.id,"project":m.project,"environment":m.environment,"kind":m.kind,
        "active_version":m.active_version,"versions":m.versions.iter().map(|v| {
            let mut public = serde_json::Map::new();
            for key in ["public_key","fingerprint","algorithm"] { if let Some(value) = v.public.get(key) { public.insert(key.into(), value.clone()); } }
            json!({"version":v.version,"status":v.status,"created_at":v.created_at,"public":public})
        }).collect::<Vec<_>>()})
}

fn csv(v: Option<&str>) -> Vec<String> {
    v.unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}
fn methods(v: Option<&str>, default: Option<Vec<String>>) -> Result<Option<Vec<String>>, Error> {
    let Some(v) = v else {
        return Ok(default);
    };
    if v.trim().eq_ignore_ascii_case("all") {
        return Ok(None);
    }
    let items: Vec<String> = csv(Some(v)).into_iter().map(|s| s.to_uppercase()).collect();
    if items.is_empty() {
        return Err(Error::invalid_input("invalid_method").with_detail("empty method list"));
    }
    Ok(Some(items))
}
fn paths(v: Option<&str>, default: Option<Vec<String>>) -> Result<Option<Vec<String>>, Error> {
    let Some(v) = v else {
        return Ok(default);
    };
    if v.trim().eq_ignore_ascii_case("all") {
        return Ok(None);
    }
    let items = csv(Some(v));
    if items.is_empty() {
        return Err(Error::invalid_input("invalid_path_prefix").with_detail("empty prefix list"));
    }
    Ok(Some(items))
}
fn confirmations(v: Option<&str>, default: Vec<String>) -> Vec<String> {
    let Some(v) = v else {
        return default;
    };
    if v.trim().is_empty() || v.trim().eq_ignore_ascii_case("none") {
        return Vec::new();
    }
    csv(Some(v)).into_iter().map(|s| s.to_uppercase()).collect()
}
fn ttl(v: &str) -> Result<i64, Error> {
    let s = v.trim().to_ascii_lowercase();
    let (digits, unit) = s
        .trim_end_matches(|c: char| c.is_ascii_alphabetic())
        .split_at(s.trim_end_matches(|c: char| c.is_ascii_alphabetic()).len());
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::invalid_input("invalid_ttl"));
    }
    let factor: i64 = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err(Error::invalid_input("invalid_ttl")),
    };
    let seconds = digits
        .parse::<i64>()
        .ok()
        .and_then(|n| n.checked_mul(factor))
        .ok_or_else(|| Error::invalid_input("invalid_ttl"))?;
    if seconds <= 0 {
        return Err(Error::invalid_input("invalid_ttl"));
    }
    Ok(seconds)
}

fn target(v: &str) -> Result<(String, String, i64), Error> {
    let (scheme, rest) = v.trim().split_once("://").ok_or_else(|| {
        Error::invalid_input("invalid_scheme")
            .with_detail("target must start with http:// or https://")
    })?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(Error::invalid_input("invalid_scheme")
            .with_detail("target must start with http:// or https://"));
    }
    if rest.contains('@')
        || rest.contains('?')
        || rest.contains('#')
        || rest.find('/').is_some_and(|i| &rest[i..] != "/")
    {
        return Err(Error::invalid_input("target_must_be_origin")
            .with_detail("target is scheme://host[:port] only"));
    }
    let host_port = rest.trim_end_matches('/');
    let (host, port) = if host_port.starts_with('[') {
        let end = host_port
            .find(']')
            .ok_or_else(|| Error::invalid_input("invalid_host"))?;
        let host = &host_port[1..end];
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(Error::invalid_input("invalid_host"));
        }
        let rem = &host_port[end + 1..];
        let port = if rem.is_empty() {
            if scheme == "https" { 443 } else { 80 }
        } else {
            rem.strip_prefix(':')
                .ok_or_else(|| Error::invalid_input("invalid_port"))?
                .parse::<i64>()
                .map_err(|_| Error::invalid_input("invalid_port"))?
        };
        (host.to_owned(), port)
    } else if let Some((host, port)) = host_port.rsplit_once(':') {
        (
            host.to_owned(),
            port.parse::<i64>()
                .map_err(|_| Error::invalid_input("invalid_port"))?,
        )
    } else {
        (
            host_port.to_owned(),
            if scheme == "https" { 443 } else { 80 },
        )
    };
    if host.is_empty() {
        return Err(Error::invalid_input("invalid_host"));
    }
    Ok((scheme, host, port))
}

fn control(ctx: &Context) -> Result<Value, Error> {
    Ok(
        json!({"stopped":ctx.policy.is_stopped()?,"restore_pending":ctx.policy.restore_pending()?,"incident_open":ctx.policy.open_incident_id()?}),
    )
}

fn grant_view(grant: &crate::policy::Grant) -> Value {
    json!({"id":grant.id,"principal":grant.principal,"connection":grant.connection,
        "policy_version":grant.policy_version,"expires_at":grant.expires_at.map(|t| iso(Some(t))),
        "max_uses":grant.max_uses,"uses":grant.uses,"status":grant.status,
        "created_at":grant.created_at,"revoked_at":grant.revoked_at,
        "credential_version":grant.credential_version})
}

fn verify_admin(ctx: &Context) -> Result<(), Error> {
    let pass = passphrase("ZEROPW_ADMIN_PASSPHRASE")?;
    ctx.admin.verify(&pass, None)?;
    Ok(())
}

fn check_secret_connection(ctx: &Context, connection: &Connection) -> Result<(), Error> {
    ctx.projects
        .require_environment(&connection.project, &connection.environment)?;
    let meta = ctx.vault.get_meta(&connection.secret_id)?;
    if meta.project != connection.project || meta.environment != connection.environment {
        return Err(Error::invalid_input("secret_scope_mismatch")
            .with_detail("secret belongs to another project/environment"));
    }
    let kinds = if connection.kind == "http" {
        &["api_key", "password", "env_var"][..]
    } else {
        &["ssh_private_key"][..]
    };
    if !kinds.contains(&meta.kind.as_str()) {
        return Err(Error::invalid_input("secret_kind_mismatch"));
    }
    let ver = ctx
        .vault
        .resolve_version(&connection.secret_id, connection.secret_version)?;
    if !meta
        .versions
        .iter()
        .any(|v| v.version == ver && (v.status == "active" || v.status == "staged"))
    {
        return Err(Error::invalid_input("secret_version_unusable"));
    }
    if crate::tools::profile_env_carries_vault_value(ctx, connection)? {
        return Err(Error::invalid_input("cli_env_contains_credential").with_detail(&connection.id));
    }
    Ok(())
}

fn create_connection(
    ctx: &Context,
    connection: Connection,
    target: &str,
) -> Result<Connection, Error> {
    // The credential scan and persisted CLI profile must be one state transaction.
    let _lock = ctx.state.lock()?;
    check_secret_connection(ctx, &connection)?;
    let stamped = ctx.policy.create_connection(connection)?;
    ctx.audit.record(
        "connection_create",
        RecordArgs {
            caller: Some("admin"),
            connection: Some(&stamped.id),
            target: Some(target),
            result: Some("ok"),
            policy_version: Some(stamped.policy_version),
            extra: vec![
                ("kind", json!(stamped.kind)),
                ("service", json!(stamped.service)),
                ("project", json!(stamped.project)),
                ("environment", json!(stamped.environment)),
                ("secret_id", json!(stamped.secret_id)),
            ],
            ..Default::default()
        },
    )?;
    Ok(stamped)
}

fn local_command(a: &Args) -> Result<Value, Error> {
    if a.command == "init" {
        let admin = passphrase("ZEROPW_ADMIN_PASSPHRASE")?;
        let recovery = passphrase("ZEROPW_RECOVERY_PASSPHRASE")?;
        if admin.chars().count() < 8 {
            return Err(Error::invalid_input("passphrase_too_short")
                .with_detail("administrator passphrase needs at least 8 characters"));
        }
        if recovery.chars().count() < 8 {
            return Err(Error::invalid_input("passphrase_too_short")
                .with_detail("recovery passphrase needs at least 8 characters"));
        }
        if admin == recovery {
            return Err(Error::invalid_input("passphrases_identical")
                .with_detail("the recovery passphrase must be independent of the admin one"));
        }
        let ctx = Context::initialize(
            &a.state_dir,
            &admin,
            &recovery,
            Config::default(),
            crate::clock::system(),
        )?;
        return Ok(
            json!({"state_dir":ctx.state.path.to_string_lossy(),"kms_key_id":ctx.kms.key_id()}),
        );
    }
    let mutating = !matches!(
        (a.command.as_str(), a.action.as_str()),
        ("project", "list")
            | ("secret", "list" | "versions" | "reveal")
            | ("connection", "list" | "show")
            | ("principal", "list")
            | ("grant", "list")
            | ("approvals", "list")
            | ("incident", "list" | "show")
            | ("audit", "tail")
            | ("alerts", "")
            | (
                "team",
                "members" | "status" | "log" | "show" | "diff" | "incidents"
            )
    );
    let mut ctx = open(a, mutating)?;
    match (a.command.as_str(), a.action.as_str()) {
        ("project", "create") => {
            let envs = if let Some(v) = a.get("environments") {
                csv(Some(v))
            } else {
                vec!["dev".into(), "staging".into(), "prod".into()]
            };
            let p = ctx.projects.create(
                &a.positional[0],
                &envs.iter().map(String::as_str).collect::<Vec<_>>(),
            )?;
            admin_record(
                &ctx,
                "project_create",
                vec![
                    ("project", json!(p.name)),
                    ("count", json!(p.environments.len())),
                ],
            )?;
            Ok(json!({"name":p.name,"environments":p.environments,"created_at":p.created_at}))
        }
        ("project", "list") => Ok(
            json!({"projects":ctx.projects.list()?.into_iter().map(|p| json!({"name":p.name,"environments":p.environments,"created_at":p.created_at})).collect::<Vec<_>>()}),
        ),
        ("secret", "put") => {
            let value = read_secret(a, a.req("kind"))?;
            if let Some(env_id) = project_shared_env(&ctx, a.req("project"), a.req("environment"))?
            {
                return shared_put(
                    &ctx,
                    &env_id,
                    a.req("id"),
                    a.req("kind"),
                    &value,
                    (a.req("project"), a.req("environment")),
                    a.has("staged"),
                );
            }
            let _lock = ctx.state.lock()?;
            // Reject credentials embedded in any saved CLI environment before committing the new version.
            for conn in ctx.policy.list_connections()? {
                if crate::tools::profile_env_carries_credential(&conn, &value) {
                    return Err(
                        Error::invalid_input("cli_env_contains_credential").with_detail(conn.id)
                    );
                }
            }
            let version = ctx.vault.put_secret(
                a.req("id"),
                a.req("kind"),
                &value,
                a.req("project"),
                a.req("environment"),
                !a.has("staged"),
            )?;
            Ok(
                json!({"id":a.req("id"),"version":version,"status":if a.has("staged") {"staged"} else {"active"},"kind":a.req("kind"),"project":a.req("project"),"environment":a.req("environment")}),
            )
        }
        ("secret", "list") => Ok(
            json!({"secrets":ctx.vault.list_secrets(a.get("project"),a.get("environment"))?.into_iter().map(secret_view).collect::<Vec<_>>()}),
        ),
        ("secret", "versions") => Ok(secret_view(ctx.vault.get_meta(a.req("id"))?)),
        ("secret", "reveal") => {
            let auth = ctx
                .admin
                .verify(&passphrase("ZEROPW_ADMIN_PASSPHRASE")?, None)?;
            let version = a.integer("version")?;
            let value = ctx.vault.reveal(a.req("id"), version, &auth, None)?;
            let resolved = ctx.vault.resolve_version(a.req("id"), version)?;
            let mut out = json!({"id":a.req("id"),"version":resolved});
            if let Ok(text) = std::str::from_utf8(value.expose()) {
                out["value"] = json!(text);
            } else {
                out["value_base64"] = json!(pybase64::b64encode(value.expose()));
                out["encoding"] = json!("base64");
            }
            Ok(out)
        }
        ("secret", "retire" | "revoke") | ("rotation", "finish") => {
            let id = if a.command == "secret" {
                a.req("id")
            } else {
                a.req("secret-id")
            };
            let version = a
                .integer("version")?
                .ok_or_else(|| Error::invalid_input("invalid_arguments"))?;
            if let Some(env_id) = secret_shared_env(&ctx, id)? {
                let version_id = shared_version_id(&ctx, id, version)?;
                let is_retire = a.action == "retire" || a.command == "rotation";
                let result = if is_retire {
                    team_commit(
                        &ctx,
                        &env_id,
                        vec![
                            json!({"op":"secret.set_status","secret_id":id,"version_id":version_id,"status":"retired"}),
                        ],
                    )?
                } else {
                    team_fact(
                        &ctx,
                        &env_id,
                        "secret_version_revoked",
                        json!({"secret_id":id,"version_id":version_id}),
                    )?
                };
                let mut out = json!({"secret_id":id,"version":version,"status":if is_retire{"retired"}else{"revoked"},"propagated_to":0});
                if let Some(commit) = result.get("commit") {
                    out["commit"] = commit.clone();
                }
                if let Some(fact) = result.get("fact") {
                    out["fact"] = fact.clone();
                }
                if !is_retire || a.command == "rotation" {
                    out["provider_revocation_required"] = json!(true);
                    out["reminder"] = json!(PROVIDER_REMINDER);
                }
                return Ok(out);
            }
            let meta = ctx.vault.get_meta(id)?;
            let is_retire = a.action == "retire" || a.command == "rotation";
            if is_retire && meta.active_version == Some(version) {
                return Err(Error::invalid_input("version_is_active")
                    .with_detail("activate another version first (rotation activate)"));
            }
            let using = ctx.policy.list_connections()?;
            let pinned: Vec<String> = using
                .iter()
                .filter(|c| {
                    c.secret_id == id && c.secret_version == Some(version) && c.status == "active"
                })
                .map(|c| c.id.clone())
                .collect();
            if is_retire && !pinned.is_empty() {
                return Err(Error::invalid_input("version_in_use")
                    .with_detail(format!("pinned by connections: {}", pinned.join(","))));
            }
            let mut affected = pinned;
            if !is_retire && meta.active_version == Some(version) {
                for c in &using {
                    if c.secret_id == id
                        && c.secret_version.is_none()
                        && c.status == "active"
                        && !affected.contains(&c.id)
                    {
                        affected.push(c.id.clone());
                    }
                }
                affected.sort();
            }
            ctx.vault.set_version_status(
                id,
                version,
                if is_retire { "retired" } else { "revoked" },
            )?;
            let mut out = json!({"secret_id":id,"version":version,"status":if is_retire {"retired"} else {"revoked"}});
            if !is_retire {
                out["affected_connections"] = json!(affected);
            }
            if !is_retire || a.command == "rotation" {
                out["provider_revocation_required"] = json!(true);
                out["reminder"] = json!(PROVIDER_REMINDER);
            }
            Ok(out)
        }
        ("connection", "create-http") => {
            let (scheme, host, port) = target(a.req("target"))?;
            let ca = if let Some(p) = a.get("ca-file") {
                let path = Path::new(p);
                if !path.is_file() {
                    return Err(Error::invalid_input("ca_file_missing").with_detail(p));
                }
                Some(
                    path.canonicalize()
                        .unwrap_or_else(|_| path.to_path_buf())
                        .to_string_lossy()
                        .to_string(),
                )
            } else {
                None
            };
            let http_target =
                HttpTarget::new(&scheme, &host, port, ca, a.has("allow-private-network"))?;
            let http_auth = HttpAuth::new(
                a.req("auth"),
                a.get("header-name").map(str::to_owned),
                a.get("value-prefix").map(str::to_owned),
                a.get("basic-username").map(str::to_owned),
            )?;
            let scope = HttpScope::new(
                methods(a.get("methods"), Some(vec!["GET".into(), "HEAD".into()]))?,
                paths(a.get("path-prefixes"), None)?,
                confirmations(a.get("confirm-methods"), Vec::new()),
            )?;
            let cli = if let Some(program) = a.get("cli-program") {
                let mut extra = BTreeMap::new();
                for item in a.list("cli-env") {
                    let (key, val) = item.split_once('=').ok_or_else(|| {
                        Error::invalid_input("invalid_cli_env").with_detail("use KEY=VALUE")
                    })?;
                    if key.is_empty() {
                        return Err(
                            Error::invalid_input("invalid_cli_env").with_detail("use KEY=VALUE")
                        );
                    }
                    extra.insert(key.to_owned(), val.to_owned());
                }
                Some(CliProfile::new(program, "http", None, extra)?)
            } else {
                None
            };
            let connection = Connection::new(
                a.req("id"),
                a.req("project"),
                a.req("environment"),
                a.req("service"),
                "http",
                a.req("secret-id"),
                a.integer("secret-version")?,
                a.get("description").unwrap_or(""),
                Some(http_target),
                Some(http_auth),
                Some(scope),
                None,
                cli,
                0,
                "active",
                "",
                "",
            )?;
            if let Some(env_id) = project_shared_env(&ctx, a.req("project"), a.req("environment"))?
            {
                let version_id = a
                    .integer("secret-version")?
                    .map(|v| shared_version_id(&ctx, a.req("secret-id"), v))
                    .transpose()?;
                let result = team_commit(
                    &ctx,
                    &env_id,
                    vec![shared_connection_op(&connection, version_id)],
                )?;
                let mut out = ctx.policy.get_connection(a.req("id"))?.to_value();
                out["commit"] = result["commit"].clone();
                out["propagated_to"] = json!(0);
                return Ok(out);
            }
            Ok(
                create_connection(&ctx, connection, &format!("{scheme}://{host}:{port}"))?
                    .to_value(),
            )
        }
        ("connection", "create-ssh") => {
            let port = a.integer("port")?.unwrap_or(22);
            let ssh = SshTarget::new(a.req("host"), port, a.req("username"), a.list("host-key"))?;
            let cli = a
                .get("cli-program")
                .map(|p| CliProfile::new(p, "ssh", None, BTreeMap::new()))
                .transpose()?;
            let connection = Connection::new(
                a.req("id"),
                a.req("project"),
                a.req("environment"),
                a.req("service"),
                "ssh",
                a.req("secret-id"),
                a.integer("secret-version")?,
                a.get("description").unwrap_or(""),
                None,
                None,
                None,
                Some(ssh),
                cli,
                0,
                "active",
                "",
                "",
            )?;
            let shared = project_shared_env(&ctx, a.req("project"), a.req("environment"))?;
            let result = if let Some(env_id) = &shared {
                let version_id = a
                    .integer("secret-version")?
                    .map(|v| shared_version_id(&ctx, a.req("secret-id"), v))
                    .transpose()?;
                Some(team_commit(
                    &ctx,
                    env_id,
                    vec![shared_connection_op(&connection, version_id)],
                )?)
            } else {
                None
            };
            let stamped = if shared.is_some() {
                ctx.policy.get_connection(a.req("id"))?
            } else {
                create_connection(&ctx, connection, &format!("{}:{port}", a.req("host")))?
            };
            let mut out = stamped.to_value();
            if let Some(result) = result {
                out["commit"] = result["commit"].clone();
                out["propagated_to"] = json!(0);
            }
            let meta = ctx.vault.get_meta(&stamped.secret_id)?;
            let resolved = ctx
                .vault
                .resolve_version(&stamped.secret_id, stamped.secret_version)
                .ok();
            if let Some(v) = meta.versions.iter().find(|v| Some(v.version) == resolved) {
                out["public_key"] = v.public.get("public_key").cloned().unwrap_or(Value::Null);
                out["fingerprint"] = v.public.get("fingerprint").cloned().unwrap_or(Value::Null);
            }
            Ok(out)
        }
        ("connection", "list") => Ok(
            json!({"connections":ctx.policy.list_connections()?.into_iter().map(|c| c.to_value()).collect::<Vec<_>>()}),
        ),
        ("connection", "show") => Ok(ctx.policy.get_connection(a.req("id"))?.to_value()),
        ("connection", "update" | "update-scope") => {
            let before = ctx.policy.get_connection(a.req("id"))?;
            let prev = before.http_scope.as_ref().ok_or_else(|| {
                Error::invalid_input("scope_requires_http")
                    .with_detail("only HTTP connections carry a method/path scope")
            })?;
            if !a.has("methods") && !a.has("path-prefixes") && !a.has("confirm-methods") {
                return Err(Error::invalid_input("no_scope_changes")
                    .with_detail("give --methods, --path-prefixes or --confirm-methods"));
            }
            let scope = HttpScope::new(
                methods(a.get("methods"), prev.methods.clone())?,
                paths(a.get("path-prefixes"), prev.path_prefixes.clone())?,
                confirmations(a.get("confirm-methods"), prev.confirm_methods.clone()),
            )?;
            if let Some(env_id) = connection_shared_env(&ctx, a.req("id"))? {
                let result = team_commit(
                    &ctx,
                    &env_id,
                    vec![
                        json!({"op":"connection.update","id":a.req("id"),"http_scope":{"methods":scope.methods,"path_prefixes":scope.path_prefixes,"confirm_methods":scope.confirm_methods}}),
                    ],
                )?;
                let after = ctx.policy.get_connection(a.req("id"))?;
                return Ok(
                    json!({"id":after.id,"policy_version":after.policy_version,"scope":after.public_view().get("scope"),"commit":result["commit"],"propagated_to":0}),
                );
            }
            let (after, widened) = ctx.policy.update_connection(
                a.req("id"),
                ConnectionChanges::new().http_scope(Some(scope)),
            )?;
            admin_record(
                &ctx,
                "connection_update",
                vec![
                    ("detail", json!("scope")),
                    ("state", json!(if widened { "widened" } else { "narrowed" })),
                ],
            )?;
            Ok(
                json!({"id":after.id,"widened":widened,"policy_version":after.policy_version,"scope":after.public_view().get("scope"),"note":if widened {"existing grants are stale and need regrant"} else {"existing grants re-evaluated in place"}}),
            )
        }
        ("connection", "switch-credential") => {
            let ver = a
                .integer("version")?
                .ok_or_else(|| Error::invalid_input("invalid_arguments"))?;
            let before = ctx.policy.get_connection(a.req("id"))?;
            if let Some(env_id) = connection_shared_env(&ctx, a.req("id"))? {
                let version_id = shared_version_id(&ctx, &before.secret_id, ver)?;
                let result = team_commit(
                    &ctx,
                    &env_id,
                    vec![
                        json!({"op":"connection.switch_credential","id":a.req("id"),"secret_id":before.secret_id,"secret_version":version_id}),
                    ],
                )?;
                let after = ctx.policy.get_connection(a.req("id"))?;
                return Ok(
                    json!({"id":after.id,"secret_id":after.secret_id,"secret_version":after.secret_version,"policy_version":after.policy_version,"commit":result["commit"],"propagated_to":0}),
                );
            }
            let meta = ctx.vault.get_meta(&before.secret_id)?;
            let status = meta
                .versions
                .iter()
                .find(|v| v.version == ver)
                .map(|v| v.status.as_str())
                .ok_or_else(|| Error::not_found("secret_version_not_found"))?;
            if status != "active" && status != "staged" {
                return Err(Error::invalid_input("secret_version_unusable").with_detail(status));
            }
            let after = ctx.policy.switch_credential(a.req("id"), Some(ver))?;
            admin_record(
                &ctx,
                "connection_switch_credential",
                vec![
                    ("secret_id", json!(after.secret_id)),
                    ("version", json!(ver)),
                ],
            )?;
            Ok(
                json!({"id":after.id,"secret_id":after.secret_id,"secret_version":after.secret_version,"policy_version":after.policy_version}),
            )
        }
        ("connection", "disable") => {
            if let Some(env_id) = connection_shared_env(&ctx, a.req("id"))? {
                let result = team_fact(
                    &ctx,
                    &env_id,
                    "connection_disabled",
                    json!({"connection_id":a.req("id")}),
                )?;
                let after = ctx.policy.get_connection(a.req("id"))?;
                return Ok(
                    json!({"id":after.id,"status":after.status,"policy_version":after.policy_version,"fact":result["fact"],"propagated_to":0}),
                );
            }
            let c = ctx.policy.disable_connection(a.req("id"))?;
            admin_record(&ctx, "connection_disable", vec![])?;
            Ok(json!({"id":c.id,"status":c.status,"policy_version":c.policy_version}))
        }
        ("principal", "create") => {
            let runtime = a.get("runtime").unwrap_or("default");
            let token = ctx.policy.create_principal(a.req("id"), runtime)?;
            admin_record(
                &ctx,
                "principal_create",
                vec![
                    ("principal", json!(a.req("id"))),
                    ("runtime", json!(runtime)),
                ],
            )?;
            Ok(
                json!({"id":a.req("id"),"runtime":runtime,"token":token,"note":"shown once; only its hash is stored. Give it to the agent runtime, never to a vault."}),
            )
        }
        ("principal", "list") => Ok(
            json!({"principals":ctx.policy.list_principals()?.into_iter().map(|p|json!({"id":p.id,"status":p.status,"created_at":p.created_at,"runtime":p.runtime})).collect::<Vec<_>>()}),
        ),
        ("principal", "disable") => {
            ctx.policy.disable_principal(a.req("id"), true)?;
            admin_record(
                &ctx,
                "principal_disable",
                vec![("principal", json!(a.req("id")))],
            )?;
            Ok(json!({"id":a.req("id"),"status":"disabled"}))
        }
        ("grant", "create") => {
            let seconds = ttl(a.get("ttl").unwrap_or("1h"))?;
            let max_uses = a.integer("max-uses")?;
            let grant = ctx.policy.create_grant(
                a.req("principal"),
                a.req("connection"),
                Some(seconds),
                max_uses,
            )?;
            admin_record(
                &ctx,
                "grant_create",
                vec![
                    ("grant", json!(grant.id)),
                    ("principal", json!(grant.principal)),
                    ("max_uses", json!(grant.max_uses)),
                    ("expires_at", json!(grant.expires_at.map(|t| iso(Some(t))))),
                ],
            )?;
            Ok(grant_view(&grant))
        }
        ("grant", "list") => Ok(
            json!({"grants":ctx.policy.list_grants(a.get("principal"))?.iter().map(grant_view).collect::<Vec<_>>()}),
        ),
        ("grant", "revoke") => {
            let g = ctx.policy.revoke_grant(a.req("id"))?;
            admin_record(
                &ctx,
                "grant_revoke",
                vec![("grant", json!(g.id)), ("principal", json!(g.principal))],
            )?;
            Ok(grant_view(&g))
        }
        ("grant", "regrant") => {
            let g = ctx.policy.regrant(a.req("id"))?;
            admin_record(
                &ctx,
                "grant_regrant",
                vec![
                    ("grant", json!(g.id)),
                    ("principal", json!(g.principal)),
                    ("detail", json!(a.req("id"))),
                ],
            )?;
            let mut v = grant_view(&g);
            v["replaces"] = json!(a.req("id"));
            Ok(v)
        }
        ("stop-all", "") => {
            ctx.policy.stop_all()?;
            admin_record(&ctx, "stop_all", vec![])?;
            control(&ctx)
        }
        ("resume", "") => {
            ctx.policy.resume()?;
            admin_record(&ctx, "resume", vec![])?;
            let mut v = control(&ctx)?;
            if v["restore_pending"] == true {
                v["note"] = json!(
                    "restore_pending is still set; run restore-ack after re-applying revocations"
                );
            }
            Ok(v)
        }
        ("approvals", "list") => {
            let approvals = ctx.policy.list_approvals()?;
            let mut entries: Vec<Value> = approvals
                .into_iter()
                .map(|(digest, value)| {
                    let mut v = json!({"digest":digest});
                    if let Some(obj) = value.as_object() {
                        for (k, val) in obj {
                            v[k] = val.clone();
                        }
                    }
                    v
                })
                .collect();
            entries.sort_by(|a, b| a["digest"].as_str().cmp(&b["digest"].as_str()));
            Ok(json!({"approvals":entries,"history":ctx.policy.approval_history()?}))
        }
        ("approvals", "approve") => {
            let entry = ctx.policy.approve(a.req("digest"))?;
            admin_record(
                &ctx,
                "approval_grant",
                vec![
                    ("digest", json!(a.req("digest"))),
                    (
                        "principal",
                        entry.get("caller").cloned().unwrap_or(Value::Null),
                    ),
                    (
                        "method",
                        entry.get("method").cloned().unwrap_or(Value::Null),
                    ),
                    ("path", entry.get("path").cloned().unwrap_or(Value::Null)),
                ],
            )?;
            let mut out = json!({"digest":a.req("digest")});
            if let Some(obj) = entry.as_object() {
                for (k, v) in obj {
                    out[k] = v.clone();
                }
            }
            Ok(out)
        }
        ("rotation", "start") => {
            let meta = ctx.vault.get_meta(a.req("secret-id"))?;
            let value = read_secret(a, &meta.kind)?;
            if let Some(env_id) = secret_shared_env(&ctx, &meta.id)? {
                let result = shared_put(
                    &ctx,
                    &env_id,
                    &meta.id,
                    &meta.kind,
                    &value,
                    (&meta.project, &meta.environment),
                    true,
                )?;
                let version_id = result["version_id"].as_str().unwrap_or("");
                let doc = ctx.state.read_json(crate::vault::VAULT_DOC, json!({}))?;
                let version = doc["secrets"][&meta.id]["versions"]
                    .as_object()
                    .and_then(|m| m.iter().find(|(_, v)| v["version_id"] == version_id))
                    .and_then(|(k, _)| k.parse::<i64>().ok());
                let next_version = version
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| version_id.to_owned());
                return Ok(
                    json!({"secret_id":meta.id,"version_id":version_id,"version":version,"status":"staged","previous_active":meta.active_version,"next":format!("rotation activate --connection <id> --version {next_version}"),"commit":result["commit"],"propagated_to":0}),
                );
            }
            let _lock = ctx.state.lock()?;
            for conn in ctx.policy.list_connections()? {
                if crate::tools::profile_env_carries_credential(&conn, &value) {
                    return Err(
                        Error::invalid_input("cli_env_contains_credential").with_detail(conn.id)
                    );
                }
            }
            let version = ctx.vault.put_secret(
                &meta.id,
                &meta.kind,
                &value,
                &meta.project,
                &meta.environment,
                false,
            )?;
            admin_record(
                &ctx,
                "rotation",
                vec![
                    ("secret_id", json!(meta.id)),
                    ("version", json!(version)),
                    ("state", json!("staged")),
                ],
            )?;
            Ok(
                json!({"secret_id":meta.id,"version":version,"status":"staged","previous_active":meta.active_version,"next":format!("rotation activate --connection <id> --version {version}")}),
            )
        }
        ("rotation", "activate") => {
            let version = a
                .integer("version")?
                .ok_or_else(|| Error::invalid_input("invalid_arguments"))?;
            let before = ctx.policy.get_connection(a.req("connection"))?;
            let previous = ctx.vault.get_meta(&before.secret_id)?.active_version;
            if let Some(env_id) = connection_shared_env(&ctx, &before.id)? {
                let version_id = shared_version_id(&ctx, &before.secret_id, version)?;
                team_commit(
                    &ctx,
                    &env_id,
                    vec![
                        json!({"op":"connection.switch_credential","id":before.id,"secret_id":before.secret_id,"secret_version":version_id}),
                    ],
                )?;
                let result = team_commit(
                    &ctx,
                    &env_id,
                    vec![
                        json!({"op":"secret.activate","secret_id":before.secret_id,"version_id":version_id}),
                    ],
                )?;
                let after = ctx.policy.get_connection(&before.id)?;
                let others = ctx
                    .policy
                    .list_connections()?
                    .into_iter()
                    .filter(|c| {
                        c.secret_id == before.secret_id && c.status == "active" && c.id != after.id
                    })
                    .map(|c| c.id)
                    .collect::<Vec<_>>();
                return Ok(
                    json!({"connection":after.id,"secret_id":after.secret_id,"version":version,"previous_active":previous,"policy_version":after.policy_version,"other_connections":others,"next":format!("verify the new credential works, then: rotation finish --secret-id {} --version {}",after.secret_id,previous.map(|v|v.to_string()).unwrap_or("<old>".into())),"commit":result["commit"],"propagated_to":0}),
                );
            }
            let after = ctx.policy.switch_credential(&before.id, Some(version))?;
            ctx.vault
                .set_version_status(&before.secret_id, version, "active")?;
            let after = ctx.policy.get_connection(&after.id)?;
            let others = ctx
                .policy
                .list_connections()?
                .into_iter()
                .filter(|c| {
                    c.secret_id == before.secret_id && c.status == "active" && c.id != after.id
                })
                .map(|c| c.id)
                .collect::<Vec<_>>();
            Ok(
                json!({"connection":after.id,"secret_id":after.secret_id,"version":version,"previous_active":previous,"policy_version":after.policy_version,"other_connections":others,"next":format!("verify the new credential works, then: rotation finish --secret-id {} --version {}",after.secret_id,previous.map(|n|n.to_string()).unwrap_or("<old>".into()))}),
            )
        }
        ("backup", "") => {
            let path = PathBuf::from(a.req("out"));
            let manifest = ctx.vault.backup(&path)?;
            Ok(
                json!({"out":path.to_string_lossy(),"manifest":manifest,"note":"encrypted archive; needs the KMS key or recovery passphrase"}),
            )
        }
        ("restore", "") => {
            let manifest =
                Vault::restore(ctx.state, Path::new(a.req("in")), ctx.audit, Some(ctx.kms))?;
            let mut v = control(&ctx)?;
            v["manifest"] = manifest;
            v["reapplied"] = ctx
                .state
                .read_json(crate::policy::CONTROL, Value::Null)?
                .get("restore_reapplied")
                .cloned()
                .unwrap_or(Value::Null);
            v["handle_key_rotated"] = json!(true);
            v["next"] = json!(
                "revocations recorded after the backup (grant revoke/regrant, principal disable, connection disable, secret revoke) were re-applied and the handle key was rotated; approvals keep their current state (open approvals that exist only in the archive were dropped; re-approve if needed). Redo non-revocation changes made after the backup (scope, rotation), review grant list, then restore-ack (a global stop stays set until resume)"
            );
            Ok(v)
        }
        ("restore-ack", "") => {
            verify_admin(&ctx)?;
            let reapplied = Vault::reapply_revocations(ctx.state)?;
            ctx.policy.set_restore_pending(false)?;
            let active = ctx
                .policy
                .list_grants(None)?
                .into_iter()
                .filter(|g| g.status == "active")
                .map(|g| g.id)
                .collect::<Vec<_>>();
            admin_record(
                &ctx,
                "restore_ack",
                vec![
                    ("count", json!(active.len())),
                    ("state", json!("restore_pending_cleared")),
                ],
            )?;
            let mut v = control(&ctx)?;
            v["active_grants"] = json!(active.len());
            v["active_grant_ids"] = json!(active);
            v["reapplied"] = json!(reapplied);
            v["note"] = json!(if v["stopped"] == true {
                "restore_pending cleared; the global stop is still set (run resume to lift it)"
            } else {
                "restore_pending cleared; execution is open under the restored grants"
            });
            Ok(v)
        }
        ("recover", "") => {
            let count = ctx.recover(&passphrase("ZEROPW_RECOVERY_PASSPHRASE")?)?;
            Ok(
                json!({"kms_key_id":ctx.kms.key_id(),"grants_revoked":count,"handles_invalidated":true}),
            )
        }
        ("audit", "tail") | ("alerts", "") => {
            let limit = a.integer("limit")?.unwrap_or(50);
            if limit < 1 {
                return Err(Error::invalid_input("invalid_arguments"));
            }
            let name = if a.command == "audit" {
                crate::audit::AUDIT_FILE
            } else {
                crate::audit::ALERT_FILE
            };
            let mut entries = Vec::new();
            let mut unparseable = 0;
            for line in ctx.state.read_lines(name, None)? {
                if line.trim().is_empty() {
                    continue;
                }
                match pyjson::loads(&line) {
                    Ok(v) if v.is_object() => entries.push(v),
                    _ => unparseable += 1,
                }
            }
            let start = entries.len().saturating_sub(limit as usize);
            Ok(
                json!({if a.command=="audit" {"records"} else {"alerts"}:entries[start..],"unparseable_lines":unparseable}),
            )
        }
        _ => Err(Error::unsupported("command_not_implemented")),
    }
}

fn incident_command(a: &Args) -> Result<Value, Error> {
    let mutating = !matches!(a.action.as_str(), "list" | "show");
    let ctx = Arc::new(open(a, mutating)?);
    match a.action.as_str() {
        "declare" => {
            if a.req("scope") == "all" {
                verify_admin(&ctx)?;
            }
            let principals = a.get("principal").map(|p| vec![p.to_owned()]);
            let existing_id = ctx.policy.open_incident_id()?;
            let existing_scope = existing_id
                .as_ref()
                .and_then(|id| crate::incident::get_incident(&ctx, id).ok())
                .map(|i| i.scope);
            let incident = crate::incident::open_incident(
                &ctx,
                a.req("scope"),
                principals.as_deref(),
                a.get("runtime"),
                "manual",
                None,
                a.get("reason"),
            )?;
            let mut view = incident.to_dict();
            if existing_scope.is_some() {
                view["existing"] = json!(true);
                view["widened"] = json!(Some(&incident.scope) != existing_scope.as_ref());
            }
            Ok(view)
        }
        "escalate" => {
            if a.req("scope") == "all" {
                verify_admin(&ctx)?;
            }
            Ok(crate::incident::widen_incident(
                &ctx,
                a.req("id"),
                a.req("scope"),
                a.get("runtime"),
                None,
                None,
            )?
            .to_dict())
        }
        "list" => Ok(
            json!({"incidents":crate::incident::list_incidents(&ctx)?.iter().map(crate::incident::Incident::to_dict).collect::<Vec<_>>()}),
        ),
        "show" => Ok(crate::incident::get_incident(&ctx, a.req("id"))?.to_dict()),
        "close" => {
            verify_admin(&ctx)?;
            Ok(crate::incident::close_incident(&ctx, a.req("id"))?.to_dict())
        }
        "notify-test" => crate::notify::send_test_message(&ctx),
        _ => Err(Error::invalid_input("invalid_arguments")),
    }
}

fn team_env_id(ctx: &Context, reference: &str) -> Result<String, Error> {
    let (project, environment) = reference.split_once('/').ok_or_else(|| {
        Error::invalid_input("invalid_env_ref").with_detail("use PROJECT/ENVIRONMENT")
    })?;
    if project.is_empty() || environment.is_empty() {
        return Err(Error::invalid_input("invalid_env_ref").with_detail("use PROJECT/ENVIRONMENT"));
    }
    crate::team::sync::resolve_env_id(ctx.state, project, environment)?
        .ok_or_else(|| Error::not_found("team_env_not_found"))
}

fn offline_team(ctx: Arc<Context>) -> Result<Arc<crate::team::sync::TeamSync>, Error> {
    use crate::team::identity::DeviceKey;
    use crate::team::transport::InProcessTransport;
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms)?;
    let transport = Arc::new(InProcessTransport::new(
        device.clone(),
        Arc::new(|_, _| None),
    ));
    Ok(crate::team::sync::TeamSync::new(ctx, transport, device))
}

fn commit_view(commit: &crate::team::commit::Commit) -> Value {
    json!({"author_seq":commit.author_seq,"hlc":commit.hlc})
}
fn team_commit(ctx: &Context, env_id: &str, ops: Vec<Value>) -> Result<Value, Error> {
    let commit = crate::team::membership::author_commit(ctx, None, env_id, ops)?;
    Ok(json!({"commit":commit_view(&commit),"propagated_to":0}))
}
fn team_fact(ctx: &Context, env_id: &str, kind: &str, target: Value) -> Result<Value, Error> {
    use sha2::{Digest, Sha256};
    let fact = crate::team::membership::author_fact(ctx, None, env_id, kind, target)?;
    let bytes = pyjson::dumps(&fact, DumpOptions::compact_sorted())?;
    Ok(json!({"fact":{"hash":hex::encode(Sha256::digest(bytes.as_bytes()))},"propagated_to":0}))
}

fn project_shared_env(
    ctx: &Context,
    project: &str,
    environment: &str,
) -> Result<Option<String>, Error> {
    crate::team::sync::resolve_env_id(ctx.state, project, environment)
}
fn secret_shared_env(ctx: &Context, secret_id: &str) -> Result<Option<String>, Error> {
    let doc = ctx.state.read_json(crate::vault::VAULT_DOC, json!({}))?;
    Ok(doc["secrets"][secret_id]["shared_env"]
        .as_str()
        .map(str::to_owned))
}
fn connection_shared_env(ctx: &Context, connection_id: &str) -> Result<Option<String>, Error> {
    let doc = ctx.state.read_json(crate::policy::CONNECTIONS, json!({}))?;
    Ok(doc[connection_id]["shared_env"].as_str().map(str::to_owned))
}
fn shared_version_id(ctx: &Context, secret_id: &str, version: i64) -> Result<String, Error> {
    let doc = ctx.state.read_json(crate::vault::VAULT_DOC, json!({}))?;
    doc["secrets"][secret_id]["versions"][version.to_string()]["version_id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::not_found("secret_version_not_found"))
}
fn current_dek(ctx: &Context, env_id: &str) -> Result<(String, crate::secret::SecretBytes), Error> {
    let doc = crate::team::membership::load_environment(ctx, env_id)?.document;
    let generation = doc["dek"]["current"]
        .as_str()
        .ok_or_else(|| Error::invalid_input("team_env_no_generation"))?
        .to_owned();
    let wrapped = ctx
        .state
        .read_json(&format!("team/{env_id}/dek/{generation}.json"), Value::Null)?;
    if wrapped.is_null() {
        return Err(Error::invalid_input("team_dek_generation_missing"));
    }
    let key = ctx
        .kms
        .unwrap(&crate::kms::WrappedKey::from_dict(&wrapped)?)?;
    Ok((generation, key))
}
fn random_version_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
fn shared_put(
    ctx: &Context,
    env_id: &str,
    id: &str,
    kind: &str,
    value: &[u8],
    location: (&str, &str),
    staged: bool,
) -> Result<Value, Error> {
    let (generation, dek) = current_dek(ctx, env_id)?;
    let version_id = random_version_id();
    let ciphertext =
        crate::team::envelope::encrypt_secret(dek.expose(), env_id, id, &version_id, value)?;
    let public = Vault::public_metadata(kind, value)?;
    let mut result = team_commit(
        ctx,
        env_id,
        vec![
            json!({"op":"secret.put_version","secret_id":id,"kind":kind,"generation_id":generation,"version_id":version_id,"ciphertext":ciphertext,"public":public}),
        ],
    )?;
    if !staged {
        result = team_commit(
            ctx,
            env_id,
            vec![json!({"op":"secret.activate","secret_id":id,"version_id":version_id})],
        )?;
    }
    Ok(
        json!({"id":id,"version_id":version_id,"status":if staged{"staged"}else{"active"},"kind":kind,"project":location.0,"environment":location.1,"commit":result["commit"],"propagated_to":0}),
    )
}
fn shared_connection_op(connection: &Connection, secret_version_id: Option<String>) -> Value {
    let mut data = connection.to_value();
    if let Some(obj) = data.as_object_mut() {
        for key in ["id", "policy_version", "status", "created_at", "updated_at"] {
            obj.shift_remove(key);
        }
        obj.insert("secret_version".into(), json!(secret_version_id));
        obj.insert("op".into(), json!("connection.create"));
        obj.insert("id".into(), json!(connection.id));
    }
    data
}

fn team_command(a: &Args) -> Result<Option<Value>, Error> {
    use crate::team::{
        commit::{CommitStore, sort_total_order},
        identity::DeviceKey,
        membership as M, sync,
    };
    let mutating = !matches!(
        a.action.as_str(),
        "members" | "status" | "log" | "show" | "diff" | "incidents"
    ) && !(a.action == "peers" && !a.has("add"));
    let ctx = open(a, mutating)?;
    if a.action == "init" {
        let key = DeviceKey::create(ctx.state, ctx.kms)?;
        return Ok(Some(json!({"fingerprint":key.fingerprint()?})));
    }
    if a.action == "share" {
        let result = M::share_environment(
            &ctx,
            None,
            a.req("project"),
            a.req("environment"),
            a.get("name").unwrap_or("owner"),
            &passphrase("ZEROPW_ADMIN_PASSPHRASE")?,
        )?;
        return Ok(Some(
            json!({"env_id":result["env_id"],"project":a.req("project"),"environment":a.req("environment"),"not_shared":result["not_shared"]}),
        ));
    }
    if a.action == "join" {
        use crate::team::transport::TcpTransport;
        let device = DeviceKey::load_or_create(ctx.state, ctx.kms)?;
        let transport = TcpTransport::new(device.clone(), Arc::new(|_, _| None), 32);
        let team = sync::TeamSync::new(Arc::new(ctx), Arc::new(transport.clone()), device);
        team.start(None)?;
        let result = M::join(
            &team.ctx,
            &a.positional[0],
            &transport,
            &team,
            a.get("project"),
            a.get("environment"),
            30.0,
        );
        team.stop();
        return result.map(Some);
    }
    let env_id = team_env_id(&ctx, a.req("env"))?;
    let out = match a.action.as_str() {
        "invite" => {
            let ttl = ttl(a.get("ttl").unwrap_or("24h"))?;
            let invite = M::create_invite(
                &ctx,
                &env_id,
                a.req("role"),
                a.req("name"),
                ttl,
                &a.list("address"),
            )?;
            json!({"env_id":env_id,"invite":invite,"role":a.req("role"),"name":a.req("name"),"warning":"this string is a secret: never paste it into chat, issues, tickets, or logs"})
        }
        "members" => {
            let doc = M::load_environment(&ctx, &env_id)?.document;
            let mut members = Vec::new();
            if let Some(map) = doc["members"].as_object() {
                let mut keys = map.keys().collect::<Vec<_>>();
                keys.sort();
                for fp in keys {
                    let m = &map[fp];
                    members.push(json!({"fingerprint":fp,"name":m.get("name"),"role":m.get("role"),"status":m.get("status"),"owner":doc["owner"]==*fp}));
                }
            }
            json!({"env_id":env_id,"members":members})
        }
        "remove" => M::remove_member(&ctx, None, &env_id, a.req("device"))?,
        "set-role" => {
            let commit = M::author_commit(
                &ctx,
                None,
                &env_id,
                vec![
                    json!({"op":"member.set_role","fingerprint":a.req("device"),"role":a.req("role")}),
                ],
            )?;
            json!({"env_id":env_id,"fingerprint":a.req("device"),"role":a.req("role"),"commit":commit_view(&commit)})
        }
        "transfer-owner" => {
            let commit = M::author_commit(
                &ctx,
                None,
                &env_id,
                vec![json!({"op":"owner.transfer","fingerprint":a.req("device")})],
            )?;
            json!({"env_id":env_id,"new_owner":a.req("device"),"commit":commit_view(&commit)})
        }
        "status" => {
            let store = CommitStore::new(ctx.state, &env_id);
            let vector = store.vector()?;
            let folded = M::load_environment(&ctx, &env_id)?;
            let reject_dir = ctx.state.path.join("team").join(&env_id).join("rejected");
            let rejected = fs::read_dir(reject_dir)
                .ok()
                .map(|iter| {
                    iter.filter_map(Result::ok)
                        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
                        .count()
                })
                .unwrap_or(0);
            json!({"env_id":env_id,"vector":vector,"commits_folded":vector.values().sum::<i128>(),"skipped_ops":folded.skipped.len(),"rejected_commits":rejected,"pending_deferred":store.deferred_commits()?.len(),"note":"sessions/synced_at reflect a running `serve --team-listen`; this one-shot CLI holds none"})
        }
        "log" => {
            let store = CommitStore::new(ctx.state, &env_id);
            let commits = sort_total_order(store.all_commits()?)?;
            let folded = M::load_environment(&ctx, &env_id)?;
            let mut skips: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for (hash, _, reason) in folded.skipped {
                skips.entry(hash).or_default().push(reason);
            }
            let entries=commits.into_iter().map(|c|{let hash=c.hash().unwrap_or_default();json!({"author":c.author,"author_seq":c.author_seq,"hlc":c.hlc,"ops":c.ops.iter().map(|v|v.get("op").cloned().unwrap_or(Value::Null)).collect::<Vec<_>>(),"skipped":skips.get(&hash).cloned().unwrap_or_default()})}).collect::<Vec<_>>();
            json!({"env_id":env_id,"log":entries})
        }
        "show" => {
            let folded = M::load_environment(&ctx, &env_id)?;
            let view = crate::team::humanview::strip_document(&folded.document);
            if a.get("format") == Some("yaml") {
                print!(
                    "{}",
                    crate::team::humanview::to_yaml(&view, &folded.fresh_connections)
                );
                return Ok(None);
            }
            view
        }
        "diff" => {
            let store = CommitStore::new(ctx.state, &env_id);
            let commits = sort_total_order(store.all_commits()?)?;
            let (facts, _, _) = sync::load_facts(ctx.state, &env_id)?;
            let find = |prefix: &str| -> Result<usize, Error> {
                let matches = commits
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| c.hash().is_ok_and(|h| h.starts_with(prefix)))
                    .map(|(i, _)| i)
                    .collect::<Vec<_>>();
                if matches.is_empty() {
                    Err(Error::not_found("commit_hash_not_found"))
                } else if matches.len() > 1 {
                    Err(Error::invalid_input("commit_hash_ambiguous"))
                } else {
                    Ok(matches[0])
                }
            };
            let left = find(&a.positional[0])?;
            let right = find(&a.positional[1])?;
            let view = |index: usize| -> Result<Value, Error> {
                let folded = crate::team::fold::fold(
                    &env_id,
                    commits[..=index].to_vec(),
                    Some(&facts),
                    None,
                    None,
                    None,
                )?;
                Ok(crate::team::humanview::strip_document(&folded.document))
            };
            json!({"env_id":env_id,"left":{"hash":commits[left].hash()?,"view":view(left)?},"right":{"hash":commits[right].hash()?,"view":view(right)?}})
        }
        "peers" => {
            if let Some(add) = a.get("add") {
                let device = a.get("device").ok_or_else(|| {
                    Error::invalid_input("peer_add_needs_device")
                        .with_detail("use --device FP with --add")
                })?;
                let team = offline_team(Arc::new(open(a, true)?))?;
                team.register_env(&env_id)?;
                team.set_peer_address(&env_id, device, add)?;
            }
            json!({"env_id":env_id,"peers":ctx.state.read_json(&format!("team/{env_id}/peers.json"),json!({}))?})
        }
        "compact" => {
            let team = offline_team(Arc::new(open(a, true)?))?;
            team.register_env(&env_id)?;
            team.compact(&env_id)?
        }
        "incidents" => {
            let dir = ctx.state.path.join("team").join(&env_id).join("incidents");
            let mut incidents = Vec::new();
            if let Ok(entries) = fs::read_dir(dir) {
                let mut paths = entries
                    .filter_map(Result::ok)
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|e| e == "json"))
                    .collect::<Vec<_>>();
                paths.sort();
                for path in paths {
                    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                        let record = ctx
                            .state
                            .read_json(&format!("team/{env_id}/incidents/{name}"), Value::Null)?;
                        if let Some(obj) = record.as_object() {
                            let mut view = json!({"id":path.file_stem().and_then(|s|s.to_str()).unwrap_or("")});
                            for (k, v) in obj {
                                view[k] = v.clone();
                            }
                            incidents.push(view);
                        }
                    }
                }
            }
            json!({"env_id":env_id,"incidents":incidents,"rotation_flags":ctx.state.read_json(&format!("team/{env_id}/rotation_flags.json"),json!({}))?})
        }
        _ => return Err(Error::invalid_input("invalid_arguments")),
    };
    Ok(Some(out))
}

fn parse_listen(raw: &str) -> Result<(String, u16), Error> {
    let (host, port) = raw
        .trim()
        .rsplit_once(':')
        .ok_or_else(|| Error::invalid_input("invalid_listen").with_detail("use HOST:PORT"))?;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::invalid_input("invalid_listen").with_detail("port must be 0-65535"));
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| Error::invalid_input("invalid_listen").with_detail("port must be 0-65535"))?;
    Ok((host.trim_matches(['[', ']']).to_owned(), port))
}
fn require_loopback(host: &str) -> Result<String, Error> {
    if host == "localhost" {
        return Ok("127.0.0.1".into());
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) if ip.is_loopback() => Ok(host.to_owned()),
        Ok(std::net::IpAddr::V6(ip)) if ip.is_loopback() => {
            Err(Error::unsupported("listen_ipv6_unsupported")
                .with_detail("the trusted process binds IPv4 loopback only"))
        }
        _ => Err(Error::unsupported("listen_not_loopback")
            .with_detail("the trusted process binds loopback addresses only")),
    }
}
const WITHDRAWN: &[&str] = &[
    "restore_pending",
    "global_stop",
    "principal_unknown",
    "principal_disabled",
    "connection_unknown",
    "connection_disabled",
    "grant_unknown",
    "grant_mismatch",
    "grant_revoked",
    "grant_stale",
    "grant_inactive",
];
fn withdrawn(ctx: &Context, caller: &str, connection: &str, grant: &str) -> Option<String> {
    ctx.policy
        .check_grant(caller, connection, grant)
        .ok()
        .and_then(|d| (!d.allowed && WITHDRAWN.contains(&d.reason)).then(|| d.reason.to_owned()))
}
fn enforce_withdrawn(ctx: &Context, quiet: bool) {
    if let Some(runs) = crate::runs::registry(ctx) {
        for run in runs.active_runs() {
            if run.cancel_requested {
                continue;
            }
            if let Some(reason) = withdrawn(ctx, &run.caller, &run.connection, &run.grant)
                && runs.cancel(&run.id, &run.caller, &reason).is_err()
                && !quiet
            {
                eprintln!("run revocation check failed: Error");
            }
        }
    }
    if let Some(manager) = crate::tools::signer_manager(ctx) {
        for binding in manager.active_bindings() {
            if withdrawn(
                ctx,
                &binding.caller,
                &binding.connection_id,
                &binding.grant_id,
            )
            .is_some()
            {
                manager.release(&binding);
            }
        }
    }
}

/// Serve the trusted API until `stop` is set. Prints one compact startup payload before polling.
pub fn run_serve(
    state_dir: &str,
    listen: &str,
    quiet: bool,
    team_listen: Option<&str>,
    stop: Arc<AtomicBool>,
) -> Result<Value, Error> {
    use std::io::Write;
    let (host, port) = parse_listen(listen)?;
    let host = require_loopback(&host)?;
    if let Some(address) = team_listen {
        parse_listen(address)?;
    }
    let config = Config {
        listen_host: host.clone(),
        listen_port: i64::from(port),
        ..Config::default()
    };
    let ctx = Arc::new(Context::open(state_dir, config, crate::clock::system())?);
    ctx.audit.require_writable()?;
    let _detector = crate::intrusion::install(ctx.clone(), None)?;
    let team = if let Some(address) = team_listen {
        use crate::team::{identity::DeviceKey, sync::TeamSync, transport::TcpTransport};
        let device = DeviceKey::load_or_create(ctx.state, ctx.kms)?;
        let transport = TcpTransport::new(device.clone(), Arc::new(|_, _| None), 64);
        let team = TeamSync::new(ctx.clone(), Arc::new(transport), device);
        team.start(Some(address))?;
        Some(team)
    } else {
        None
    };
    let server = crate::server::ZeroPWServer::new(ctx.clone(), Some(&host), Some(port))?;
    server.serve_in_thread()?;
    let mut payload = json!({"url":server.url(),"pid":std::process::id(),"ssh_signer":"available","state_dir":ctx.state.path.to_string_lossy(),"team_listen":team_listen});
    if let Some(obj) = control(&ctx)?.as_object() {
        for (k, v) in obj {
            payload[k] = v.clone();
        }
    }
    let text = pyjson::dumps(&payload, DumpOptions::compact_sorted())?;
    println!("{text}");
    let _ = io::stdout().flush();
    let mut was_stopped = payload["stopped"] == true;
    let mut was_pending = payload["restore_pending"] == true;
    while !stop.load(Ordering::Acquire) {
        thread::sleep(Duration::from_millis(250));
        server.service_actions();
        let _ = ctx.reload_handle_key();
        if let (Ok(now_stopped), Ok(now_pending)) =
            (ctx.policy.is_stopped(), ctx.policy.restore_pending())
        {
            if let Some(runs) = crate::runs::registry(&ctx) {
                if now_stopped && !was_stopped {
                    runs.cancel_all("global_stop", None);
                }
                if now_pending && !was_pending {
                    runs.cancel_all("restore_pending", None);
                }
            }
            was_stopped = now_stopped;
            was_pending = now_pending;
            enforce_withdrawn(&ctx, quiet);
        }
        if crate::notify::retry_pending(&ctx, (ctx.clock)()).is_err() && !quiet {
            eprintln!("notification retry failed: Error");
        }
    }
    if let Some(team) = team {
        team.stop();
    }
    server.stop();
    Ok(payload)
}

/// Process entry point for the trusted administrator CLI.
pub fn main(argv: &[String]) -> i32 {
    if argv.iter().any(|v| v == "--help" || v == "-h") {
        println!(
            "usage: zeropw-admin --state-dir DIR COMMAND ...\n\nZeroPW administrator CLI (trusted; JSON output).\n\ncommands: init, project, secret, connection, principal, grant, stop-all, resume, approvals, rotation, backup, restore, restore-ack, recover, incident, audit, alerts, team, serve"
        );
        return 0;
    }
    let args = match parse(argv) {
        Ok(a) => a,
        Err(detail) => {
            eprintln!("usage: zeropw-admin --state-dir DIR COMMAND ...");
            output(
                &json!({"error":"UsageError","reason":"usage","detail":detail}),
                true,
            );
            return 2;
        }
    };
    if args.command == "serve" {
        let stop = Arc::new(AtomicBool::new(false));
        for signal in [
            signal_hook::consts::signal::SIGINT,
            signal_hook::consts::signal::SIGTERM,
        ] {
            if signal_hook::flag::register(signal, stop.clone()).is_err() {
                output(&Error::state("signal_handler_unavailable").to_dict(), true);
                return 1;
            }
        }
        return match run_serve(
            &args.state_dir,
            args.get("listen").unwrap_or("127.0.0.1:0"),
            args.has("quiet"),
            args.get("team-listen"),
            stop,
        ) {
            Ok(_) => 0,
            Err(error) => {
                output(&error.to_dict(), true);
                1
            }
        };
    }
    let result = if args.command == "incident" {
        incident_command(&args).map(Some)
    } else if args.command == "team" {
        team_command(&args)
    } else {
        local_command(&args).map(Some)
    };
    match result {
        Ok(Some(value)) => {
            output(&value, false);
            0
        }
        Ok(None) => 0,
        Err(error) => {
            if error.reason == "file_not_found" {
                output(
                    &json!({"error":"FileNotFoundError","reason":"file_not_found"}),
                    true,
                );
            } else {
                output(&error.to_dict(), true);
            }
            1
        }
    }
}
