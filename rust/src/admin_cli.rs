//! Trusted administrator CLI. Never invoke this module from an agent process.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
    if scheme != "http" && scheme != "https" {
        return Err(Error::invalid_input("invalid_scheme")
            .with_detail("target must start with http:// or https://"));
    }
    if rest.contains('@')
        || rest.contains('?')
        || rest.contains('#')
        || (rest.contains('/') && !rest.ends_with('/'))
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
    Ok((scheme.to_owned(), host, port))
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
    if let Some(cli) = &connection.cli {
        for value in ctx.vault.values_for_trusted_scan()? {
            if profile_env_carries_credential(cli, value.expose()) {
                return Err(
                    Error::invalid_input("cli_env_contains_credential").with_detail(&connection.id)
                );
            }
        }
    }
    Ok(())
}

fn profile_env_carries_credential(cli: &CliProfile, credential: &[u8]) -> bool {
    let patterns = crate::runs::credential_patterns(credential);
    if patterns.is_empty() {
        return false;
    }
    std::iter::once(cli.base_url_env.as_str())
        .chain(cli.extra_env.keys().map(String::as_str))
        .chain(cli.extra_env.values().map(String::as_str))
        .any(|item| crate::runs::contains_sensitive(item.as_bytes(), &patterns))
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
            let _lock = ctx.state.lock()?;
            // Reject credentials embedded in any saved CLI environment before committing the new version.
            for conn in ctx.policy.list_connections()? {
                if let Some(cli) = &conn.cli
                    && profile_env_carries_credential(cli, &value)
                {
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
            let stamped =
                create_connection(&ctx, connection, &format!("{}:{port}", a.req("host")))?;
            let mut out = stamped.to_value();
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
            let _lock = ctx.state.lock()?;
            for conn in ctx.policy.list_connections()? {
                if let Some(cli) = &conn.cli
                    && profile_env_carries_credential(cli, &value)
                {
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
    let result = if args.command == "incident" {
        incident_command(&args)
    } else {
        local_command(&args)
    };
    match result {
        Ok(value) => {
            output(&value, false);
            0
        }
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
