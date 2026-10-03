//! Trusted administrator CLI. Never invoke this module from an agent process.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

use crate::argparse::{Arg, INT, Outcome, Parser, TypeFn, Val};
use crate::audit::RecordArgs;
use crate::context::{Config, Context, OwnedTempDirRegistry};
use crate::errors::Error;
use crate::policy::{
    CliProfile, Connection, ConnectionChanges, HttpAuth, HttpScope, HttpTarget, SshTarget,
};
use crate::pybase64;
use crate::pyint::PyInt;
use crate::pyjson::{self, DumpOptions};
use crate::store::iso;
use crate::vault::{MAX_SECRET_BYTES, SecretMeta, Vault};

const DEFAULT_GRANT_TTL: &str = "1h";
const DEFAULT_LISTEN: &str = "127.0.0.1:0";
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
    /// An argparse `type=int` value narrowed to `i64` by saturation: a
    /// port or bounded operational limit beyond the range behaves like the (never
    /// existing / always exceeding) value Python's arbitrary-precision int
    /// would have been.
    fn integer(&self, key: &str) -> Result<Option<i64>, Error> {
        self.get(key)
            .map(|s| {
                s.parse::<i128>()
                    .map(|n| n.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64)
                    .map_err(|_| Error::invalid_input("invalid_arguments"))
            })
            .transpose()
    }
    fn version(&self, key: &str) -> Result<Option<PyInt>, Error> {
        self.get(key)
            .map(|value| {
                value
                    .parse::<serde_json::Number>()
                    .ok()
                    .and_then(|number| PyInt::from_json_integer(&Value::Number(number)))
                    .ok_or_else(|| Error::invalid_input("invalid_arguments"))
            })
            .transpose()
    }
    fn exact_integer(&self, key: &str) -> Result<Option<Value>, Error> {
        self.get(key)
            .map(|s| {
                s.parse::<serde_json::Number>()
                    .map(Value::Number)
                    .map_err(|_| Error::invalid_input("invalid_arguments"))
            })
            .transpose()
    }
    fn list(&self, key: &str) -> Vec<String> {
        self.options.get(key).cloned().unwrap_or_default()
    }
}

/// `_positive_int`.
const POSITIVE_INT: TypeFn = TypeFn {
    name: "_positive_int",
    convert: |text| match crate::pystr::int_from_str(text) {
        Some(value) if value >= 1 => Ok(Val::Int(value)),
        _ => Err(Some("must be a positive integer".into())),
    },
};

fn exact_int_arg(text: &str) -> Result<Val, Option<String>> {
    let value = crate::pystr::int_from_str_decimal_limited(text).ok_or(None)?;
    Ok(Val::Str(value))
}

/// `argparse`'s `type=int` grammar without narrowing the resulting Python
/// integer. The canonical decimal string stays in the namespace until the
/// grant policy stores it as an arbitrary-precision JSON number.
const EXACT_INT: TypeFn = TypeFn {
    name: "int",
    convert: exact_int_arg,
};

const ENV_METAVAR: &str = "PROJECT/ENVIRONMENT";

/// `_add`: a subcommand whose help and description are the same text.
fn add<'a>(parent: &'a mut Parser, name: &str, help: &str) -> &'a mut Parser {
    parent.add_parser(name, Some(help), Some(help))
}

/// `_group`: a subcommand holding its own required `SUBCOMMAND`.
fn group<'a>(parent: &'a mut Parser, name: &str, help: &str) -> &'a mut Parser {
    let group = parent.add_parser(name, Some(help), Some(help));
    group.subparsers(&format!("{name}_command"), Some("SUBCOMMAND"));
    group
}

/// `_value_source`.
fn value_source(p: &mut Parser) {
    p.exclusive(
        true,
        vec![
            Arg::opt("--value-file")
                .metavar("PATH")
                .help("read the secret value from this file (delete it afterwards)"),
            Arg::opt("--stdin")
                .flag()
                .help("read the secret value from standard input"),
        ],
    );
}

fn env_arg() -> Arg {
    Arg::opt("--env").required().metavar(ENV_METAVAR)
}

/// `build_parser()`: the same tree, options, help text and choices as
/// `zeropw/admin_cli.py`, with abbreviation off for every (sub)parser.
fn build_parser() -> Parser {
    let mut parser = Parser::new(
        "zeropw-admin",
        Some("ZeroPW administrator CLI (trusted; JSON output)."),
        false,
    );
    parser.arg(
        Arg::opt("--state-dir")
            .required()
            .metavar("DIR")
            .help("trusted state directory (0700)"),
    );
    parser.subparsers("command", Some("COMMAND"));
    let sub = &mut parser;
    add(
        sub,
        "init",
        "create a new state directory (passphrases from env or prompt)",
    );

    let project = group(sub, "project", "projects and environments");
    add(project, "create", "create a project")
        .arg(Arg::positional("name"))
        .arg(
            Arg::opt("--environments")
                .metavar("A,B")
                .help("default: dev,staging,prod"),
        );
    add(project, "list", "list projects");

    let secret = group(
        sub,
        "secret",
        "vault secrets (metadata only, except reveal)",
    );
    let p = add(
        secret,
        "put",
        "store a new secret version; value via --value-file or --stdin only",
    );
    p.arg(Arg::opt("--id").required())
        .arg(
            Arg::opt("--kind")
                .required()
                .choices(crate::vault::SECRET_KINDS),
        )
        .arg(Arg::opt("--project").required())
        .arg(Arg::opt("--environment").required())
        .arg(Arg::opt("--staged").flag().help("store without activating"));
    value_source(p);
    add(secret, "list", "list secrets (metadata only)")
        .arg(Arg::opt("--project"))
        .arg(Arg::opt("--environment"));
    add(
        secret,
        "versions",
        "list the versions of one secret (metadata only)",
    )
    .arg(Arg::opt("--id").required());
    add(
        secret,
        "reveal",
        "reveal ONE secret version (admin re-auth; audited and alerted)",
    )
    .arg(Arg::opt("--id").required())
    .arg(Arg::opt("--version").ty(EXACT_INT));
    add(secret, "retire", "retire a non-active version")
        .arg(Arg::opt("--id").required())
        .arg(Arg::opt("--version").ty(EXACT_INT).required());
    add(
        secret,
        "revoke",
        "revoke a version (connections using it fail closed)",
    )
    .arg(Arg::opt("--id").required())
    .arg(Arg::opt("--version").ty(EXACT_INT).required());

    let connection = group(sub, "connection", "service connections");
    add(
        connection,
        "create-http",
        "create an HTTP connection (gateway-injected auth)",
    )
    .arg(Arg::opt("--id").required())
    .arg(Arg::opt("--project").required())
    .arg(Arg::opt("--environment").required())
    .arg(Arg::opt("--service").required())
    .arg(Arg::opt("--secret-id").required())
    .arg(
        Arg::opt("--secret-version")
            .ty(EXACT_INT)
            .help("pin a version (default: follow the active version)"),
    )
    .arg(
        Arg::opt("--target")
            .required()
            .metavar("URL")
            .help("scheme://host[:port]; port defaults to 80/443"),
    )
    .arg(
        Arg::opt("--auth")
            .required()
            .choices(crate::policy::AUTH_MODES),
    )
    .arg(Arg::opt("--header-name").help("header for --auth header"))
    .arg(Arg::opt("--value-prefix").help("e.g. \"token \" placed before the credential"))
    .arg(
        Arg::opt("--basic-username")
            .help("username for --auth basic (the vault value is the password)"),
    )
    .arg(
        Arg::opt("--methods")
            .metavar("GET,POST|all")
            .help("default: GET,HEAD"),
    )
    .arg(
        Arg::opt("--path-prefixes")
            .metavar("/a,/b|all")
            .help("default: all"),
    )
    .arg(
        Arg::opt("--confirm-methods")
            .metavar("DELETE")
            .help("methods needing a one-shot approval"),
    )
    .arg(Arg::opt("--ca-file").help("CA bundle for TLS verification (tests)"))
    .arg(Arg::opt("--allow-private-network").flag().help(
        "allow a host-name target to resolve to loopback/private addresses (internal services); \
         metadata and link-local addresses stay refused",
    ))
    .arg(
        Arg::opt("--cli-program")
            .metavar("PATH")
            .help("supported CLI executable for exec"),
    )
    .arg(
        Arg::opt("--cli-env")
            .append()
            .metavar("K=V")
            .help("non-secret env for the CLI (repeatable)"),
    )
    .arg(Arg::opt("--description"));
    add(
        connection,
        "create-ssh",
        "create an SSH connection (signer-delegated auth)",
    )
    .arg(Arg::opt("--id").required())
    .arg(Arg::opt("--project").required())
    .arg(Arg::opt("--environment").required())
    .arg(Arg::opt("--service").required())
    .arg(Arg::opt("--secret-id").required())
    .arg(Arg::opt("--secret-version").ty(EXACT_INT))
    .arg(Arg::opt("--host").required())
    .arg(Arg::opt("--port").ty(INT).default(Val::Int(22)))
    .arg(Arg::opt("--username").required())
    .arg(
        Arg::opt("--host-key")
            .append()
            .required()
            .metavar("\"ssh-ed25519 AAAA...\"")
            .help("expected host key (repeatable)"),
    )
    .arg(
        Arg::opt("--cli-program")
            .metavar("PATH")
            .help("ssh executable (default: none registered)"),
    )
    .arg(Arg::opt("--description"));
    add(connection, "list", "list connections");
    add(connection, "show", "show one connection").arg(Arg::opt("--id").required());
    // "update" is the primary name (docs/team-sync.md section 12); "update-scope" is kept as an alias.
    for name in ["update", "update-scope"] {
        add(
            connection,
            name,
            "change the HTTP scope (widening stales grants)",
        )
        .arg(Arg::opt("--id").required())
        .arg(Arg::opt("--methods").metavar("GET,POST|all"))
        .arg(Arg::opt("--path-prefixes").metavar("/a,/b|all"))
        .arg(Arg::opt("--confirm-methods").metavar("DELETE|none"));
    }
    add(
        connection,
        "switch-credential",
        "pin the connection to a secret version",
    )
    .arg(Arg::opt("--id").required())
    .arg(Arg::opt("--version").ty(EXACT_INT).required());
    add(connection, "disable", "disable a connection").arg(Arg::opt("--id").required());

    let principal = group(sub, "principal", "agent identities");
    add(
        principal,
        "create",
        "create a principal; prints its caller token once",
    )
    .arg(Arg::opt("--id").required())
    .arg(
        Arg::opt("--runtime")
            .default(Val::Str("default".into()))
            .help(
                "execution runtime this principal is bound to (default: default); a compromise-response \
                 'runtime' incident disables every principal sharing one",
            ),
    );
    add(principal, "list", "list principals (no tokens, no hashes)");
    add(principal, "disable", "disable a principal").arg(Arg::opt("--id").required());

    let grant = group(
        sub,
        "grant",
        "grants (principal x connection, expiry, usage)",
    );
    add(grant, "create", "grant a principal use of a connection")
        .arg(Arg::opt("--principal").required())
        .arg(Arg::opt("--connection").required())
        .arg(
            Arg::opt("--ttl")
                .default(Val::Str(DEFAULT_GRANT_TTL.into()))
                .help("30m, 1h, 3600s, 86400 (default: 1h; max 30d)"),
        )
        .arg(Arg::opt("--max-uses").ty(EXACT_INT));
    add(grant, "list", "list grants").arg(Arg::opt("--principal"));
    add(grant, "revoke", "revoke a grant immediately").arg(Arg::opt("--id").required());
    add(
        grant,
        "regrant",
        "re-issue a stale grant at the current policy version",
    )
    .arg(Arg::opt("--id").required());

    add(
        sub,
        "stop-all",
        "refuse every relay, signature and execution until resume",
    );
    add(sub, "resume", "lift the global stop");

    let approvals = group(sub, "approvals", "one-shot approvals for risky methods");
    add(approvals, "list", "list approval requests");
    add(approvals, "approve", "approve a pending request by digest")
        .arg(Arg::opt("--digest").required());

    let rotation = group(
        sub,
        "rotation",
        "credential rotation: start -> activate -> finish",
    );
    let p = add(rotation, "start", "stage a new version of a secret");
    p.arg(Arg::opt("--secret-id").required());
    value_source(p);
    add(
        rotation,
        "activate",
        "activate a version and switch a connection to it",
    )
    .arg(Arg::opt("--connection").required())
    .arg(Arg::opt("--version").ty(EXACT_INT).required());
    add(
        rotation,
        "finish",
        "retire the old version (provider revocation is separate)",
    )
    .arg(Arg::opt("--secret-id").required())
    .arg(
        Arg::opt("--version")
            .ty(INT)
            .required()
            .help("the OLD version to retire"),
    );

    add(sub, "backup", "write an encrypted backup archive")
        .arg(Arg::opt("--out").required().metavar("FILE"));
    add(
        sub,
        "restore",
        "restore an archive; leaves restore_pending set",
    )
    .arg(Arg::opt("--in").dest("input").required().metavar("FILE"));
    add(
        sub,
        "restore-ack",
        "clear restore_pending after re-applying revocations (admin re-auth)",
    );
    add(
        sub,
        "recover",
        "disaster recovery: new KMS key, grants revoked, handles rotated",
    );

    let inc = group(
        sub,
        "incident",
        "compromise-response incidents: lockdown and exposure assessment",
    );
    add(
        inc,
        "declare",
        "open an incident: lock down the given scope (docs/compromise-response.md \u{a7}4)",
    )
    .arg(
        Arg::opt("--scope")
            .required()
            .choices(crate::incident::SCOPES),
    )
    .arg(Arg::opt("--principal").help("required for --scope principal"))
    .arg(Arg::opt("--runtime").help("required for --scope runtime"))
    .arg(Arg::opt("--reason").help("admin note stored on the incident (bounded to 200 chars)"));
    add(
        inc,
        "escalate",
        "widen an open incident's scope (never narrows)",
    )
    .arg(Arg::opt("--id").required())
    .arg(Arg::opt("--scope").required().choices(&["runtime", "all"]))
    .arg(Arg::opt("--runtime").help("required when widening to --scope runtime"));
    add(inc, "list", "list incidents, newest last");
    add(
        inc,
        "show",
        "show one incident, including its exposure assessment",
    )
    .arg(Arg::opt("--id").required());
    add(
        inc,
        "close",
        "close an incident (admin re-auth; does not resume)",
    )
    .arg(Arg::opt("--id").required());
    add(
        inc,
        "notify-test",
        "send a short test message through the configured SMTP path (docs/compromise-response.md \u{a7}6.1)",
    );

    let audit = group(sub, "audit", "audit log (administrator only)");
    add(audit, "tail", "print the last records").arg(
        Arg::opt("--limit")
            .ty(POSITIVE_INT)
            .default(Val::Int(50))
            .metavar("N")
            .help("last N records (default 50)"),
    );
    add(sub, "alerts", "print the last alerts").arg(
        Arg::opt("--limit")
            .ty(POSITIVE_INT)
            .default(Val::Int(50))
            .metavar("N")
            .help("last N alerts (default 50)"),
    );

    let team = group(
        sub,
        "team",
        "team sync: environment sharing between teammate nodes (docs/team-sync.md)",
    );
    add(
        team,
        "init",
        "create this node's device key; refuses if one already exists",
    );
    add(
        team,
        "share",
        "promote a local project/environment to a shared one (admin re-auth)",
    )
    .arg(Arg::opt("--project").required())
    .arg(Arg::opt("--environment").required())
    .arg(Arg::opt("--name").help("this node's displayed member name (default: owner)"));
    add(
        team,
        "invite",
        "print a one-time invite string (never paste it into chat/issues)",
    )
    .arg(env_arg())
    .arg(Arg::opt("--role").required().choices(&["admin", "user"]))
    .arg(
        Arg::opt("--name")
            .required()
            .help("display name for the invited member"),
    )
    .arg(Arg::opt("--ttl").help("30m, 1h, 3600s, 86400 (default: 24h)"))
    .arg(
        Arg::opt("--address")
            .append()
            .metavar("HOST:PORT")
            .help("this node's reachable address (repeatable)"),
    );
    add(team, "join", "dial the inviter, prove the invite, and join")
        .arg(Arg::positional("invite"))
        .arg(Arg::opt("--project").help("local project name (default: derived from the inviter)"))
        .arg(Arg::opt("--environment").help("local environment name (default: shared)"));
    add(team, "members", "list team members").arg(env_arg());
    add(
        team,
        "remove",
        "remove a team member (fact) and rotate the DEK if applicable",
    )
    .arg(env_arg())
    .arg(Arg::opt("--device").required().metavar("FINGERPRINT"));
    add(team, "set-role", "change a member's role")
        .arg(env_arg())
        .arg(Arg::opt("--device").required().metavar("FINGERPRINT"))
        .arg(Arg::opt("--role").required().choices(&["admin", "user"]));
    add(
        team,
        "transfer-owner",
        "transfer ownership to another active admin/member",
    )
    .arg(env_arg())
    .arg(Arg::opt("--device").required().metavar("FINGERPRINT"));
    add(
        team,
        "status",
        "version vector, folded/skipped/rejected/pending counts",
    )
    .arg(env_arg());
    add(
        team,
        "log",
        "commits in fold order, with skip reasons (no values)",
    )
    .arg(env_arg());
    add(
        team,
        "show",
        "render the environment document (no ciphertext/wraps/signatures)",
    )
    .arg(env_arg())
    .arg(
        Arg::opt("--format")
            .choices(&["json", "yaml"])
            .default(Val::Str("json".into())),
    );
    add(
        team,
        "diff",
        "compare the folded view at two commit hashes (prefixes accepted)",
    )
    .arg(env_arg())
    .arg(Arg::positional("left").metavar("COMMIT-HASH-PREFIX"))
    .arg(Arg::positional("right").metavar("COMMIT-HASH-PREFIX"));
    add(
        team,
        "peers",
        "list, or (with --device) add, a peer's known address",
    )
    .arg(env_arg())
    .arg(Arg::opt("--add").metavar("HOST:PORT"))
    .arg(
        Arg::opt("--device")
            .metavar("FINGERPRINT")
            .help("required with --add"),
    );
    add(
        team,
        "compact",
        "delete commits every active member's vector already covers",
    )
    .arg(env_arg());
    add(
        team,
        "incidents",
        "list received incident summaries and rotation flags",
    )
    .arg(env_arg());

    add(
        sub,
        "serve",
        "run the trusted server (tools API, relay, signer) until SIGINT/SIGTERM",
    )
    .arg(
        Arg::opt("--listen")
            .default(Val::Str(DEFAULT_LISTEN.into()))
            .metavar("HOST:PORT")
            .help("IPv4 loopback only (127.0.0.1 or localhost); port 0 = ephemeral"),
    )
    .arg(
        Arg::opt("--team-listen")
            .metavar("HOST:PORT")
            .help("start team sync on a separate LAN/VPN-facing socket (default: team sync off)"),
    )
    .arg(
        Arg::opt("--quiet")
            .flag()
            .help("no request log lines on stderr"),
    );
    parser
}

/// Why argv did not produce [`Args`]: argparse printed help (exit 0), or a
/// usage error (`_Parser.error`: usage, then the JSON error, exit 2).
#[derive(Debug)]
enum ParseFail {
    Help(String),
    Usage { usage: String, detail: String },
}

/// `_Parser._unrecognized_detail`: a count, plus only those tokens that are
/// (or abbreviate) an option registered somewhere in the tree.
fn unrecognized_detail(parser: &Parser, extras: &[String]) -> String {
    let registered = parser.registered_options();
    let names: BTreeSet<&str> = extras
        .iter()
        .map(|item| item.split('=').next().unwrap_or(""))
        .filter(|name| {
            name.starts_with("--")
                && name.chars().count() > 2
                && registered.iter().any(|option| option.starts_with(name))
        })
        .collect();
    let mut detail = format!("unrecognized arguments: {}", extras.len());
    if !names.is_empty() {
        detail.push_str(&format!(
            " (not accepted: {})",
            names.into_iter().collect::<Vec<_>>().join(" ")
        ));
    }
    detail + "; values are not echoed"
}

/// `build_parser().parse_args(argv)` with `_Parser`'s error reporting,
/// converted to the option map the command handlers read.
fn parse(argv: &[String]) -> Result<Args, ParseFail> {
    let parser = build_parser();
    let (namespace, extras) = match parser.parse_known_args(argv) {
        Outcome::Parsed(namespace, extras) => (namespace, extras),
        Outcome::Help(text) => return Err(ParseFail::Help(text)),
        Outcome::Error { usage, message, .. } => {
            return Err(ParseFail::Usage {
                usage,
                detail: message,
            });
        }
    };
    if !extras.is_empty() {
        return Err(ParseFail::Usage {
            usage: parser.format_usage(),
            detail: unrecognized_detail(&parser, &extras),
        });
    }
    let text = |key: &str| {
        namespace
            .get(key)
            .and_then(Val::as_str)
            .unwrap_or("")
            .to_owned()
    };
    let mut a = Args {
        state_dir: text("state_dir"),
        command: text("command"),
        ..Args::default()
    };
    a.action = text(&format!("{}_command", a.command));
    let positionals: &[&str] = match (a.command.as_str(), a.action.as_str()) {
        ("project", "create") => &["name"],
        ("team", "join") => &["invite"],
        ("team", "diff") => &["left", "right"],
        _ => &[],
    };
    for positional in positionals {
        a.positional.push(text(positional));
    }
    for (dest, value) in &namespace {
        if dest == "state_dir" || dest.ends_with("command") || positionals.contains(&dest.as_str())
        {
            continue;
        }
        let key = if dest == "input" {
            "in".to_owned()
        } else {
            dest.replace('_', "-")
        };
        let values = match value {
            Val::Str(s) => vec![s.clone()],
            Val::Int(int) => vec![int.to_string()],
            Val::Bool(true) => vec!["true".to_owned()],
            Val::List(items) => items.clone(),
            Val::None | Val::Bool(false) => continue,
        };
        a.options.insert(key, values);
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

/// `_admin_record(ctx, event, connection=..., policy_version=..., extra=...)`.
fn admin_record_for(
    ctx: &Context,
    event: &str,
    connection: Option<&str>,
    policy_version: Option<i64>,
    extra: Vec<(&str, Value)>,
) -> Result<(), Error> {
    ctx.audit.record(
        event,
        RecordArgs {
            caller: Some("admin"),
            connection,
            result: Some("ok"),
            policy_version,
            extra,
            ..Default::default()
        },
    )?;
    Ok(())
}

fn record_auth_failure(ctx: &Context, reason: &str, extra: Vec<(&str, Value)>) {
    let _ = ctx.audit.record(
        "auth_failed",
        RecordArgs {
            caller: Some("admin"),
            result: Some("denied"),
            reason: Some(reason),
            extra,
            ..Default::default()
        },
    );
}

fn refuse_cli_env<T>(
    ctx: &Context,
    connection: &str,
    secret_id: Option<&str>,
    event: &str,
) -> Result<T, Error> {
    ctx.audit.record(
        event,
        RecordArgs {
            caller: Some("admin"),
            connection: Some(connection),
            result: Some("denied"),
            reason: Some("cli_env_contains_credential"),
            extra: secret_id
                .map(|id| vec![("secret_id", json!(id))])
                .unwrap_or_default(),
            ..Default::default()
        },
    )?;
    Err(Error::invalid_input("cli_env_contains_credential").with_detail(connection))
}

/// Built-in exceptions that a module ports as `StateError("state_corrupt",
/// <class name>)` because Python lets them escape (PORTING.md §3.5); the CLI
/// prints that class name as Python's handler does.
const ESCAPED_BUILTIN_ERRORS: [&str; 8] = [
    "KeyError",
    "TypeError",
    "AttributeError",
    "ValueError",
    "UnicodeDecodeError",
    "UnicodeEncodeError",
    "JSONDecodeError",
    "Error",
];

/// `type(exc).__name__` for an error that reached a CLI handler.
fn python_exception_name(error: &Error) -> String {
    if error.reason == "state_corrupt" && ESCAPED_BUILTIN_ERRORS.contains(&error.detail.as_str()) {
        error.detail.clone()
    } else {
        error.name.to_string()
    }
}

/// Python truthiness of a JSON value.
fn python_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `str(pathlib.PurePosixPath(path))`: repeated and trailing separators and
/// `.` components dropped (a leading `//` is kept, as POSIX allows).
fn pathlib_str(path: &str) -> String {
    let (root, rel) = if !path.starts_with('/') {
        ("", path)
    } else if path[1..].starts_with('/') && !path[2..].starts_with('/') {
        ("//", &path[2..])
    } else {
        ("/", &path[1..])
    };
    let tail: Vec<&str> = rel
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    let text = format!("{root}{}", tail.join("/"));
    if text.is_empty() {
        ".".to_owned()
    } else {
        text
    }
}

/// The home directory `pwd` reports for `user` (or the current uid), resolved
/// through the system's NSS path (`getpwnam`/`getpwuid`).
fn passwd_home(user: Option<&str>) -> Option<String> {
    let record = match user {
        Some(name) => nix::unistd::User::from_name(name),
        None => nix::unistd::User::from_uid(nix::unistd::Uid::current()),
    }
    .ok()
    .flatten()?;
    Some(record.dir.to_string_lossy().into_owned())
}

/// `str(pathlib.Path(path).expanduser())`; `pathlib` raises
/// `RuntimeError("Could not determine home directory.")` when `~` or `~user`
/// cannot be resolved, which the CLI reports as an internal error.
fn user_path(path: &str) -> Result<String, Error> {
    let normalized = pathlib_str(path);
    let (first, rest) = match normalized.split_once('/') {
        Some((first, rest)) => (first, Some(rest)),
        None => (normalized.as_str(), None),
    };
    if normalized.starts_with('/') || !first.starts_with('~') {
        return Ok(normalized);
    }
    let home = if first == "~" {
        match env::var_os("HOME") {
            Some(home) => Some(home.to_string_lossy().into_owned()),
            None => passwd_home(None),
        }
    } else {
        passwd_home(Some(&first[1..]))
    };
    let Some(home) = home else {
        return Err(Error::subclass(
            crate::errors::ErrorClass::ZeroPW,
            "RuntimeError",
            "internal_error",
            "",
        ));
    };
    let home = home.trim_end_matches('/');
    let home = if home.is_empty() { "/" } else { home };
    Ok(pathlib_str(&match rest {
        Some(rest) => format!("{home}/{rest}"),
        None => home.to_owned(),
    }))
}

/// The CLI's `except OSError` mapping for a file named on the command line:
/// `FileNotFoundError` is reported without detail, any other error by its
/// `OSError` subclass name and `strerror`.
fn os_error(error: &io::Error) -> Error {
    if error.raw_os_error() == Some(libc::ENOENT) {
        return Error::invalid_input("file_not_found");
    }
    Error::subclass(
        crate::errors::ErrorClass::ZeroPW,
        crate::pystr::os_error_class(error),
        "io_error",
        crate::pystr::os_error_strerror(error).unwrap_or_default(),
    )
}

fn open(a: &Args, mutating: bool) -> Result<Context, Error> {
    let ctx = Context::open_with_tempdir_cleanup(
        user_path(&a.state_dir)?,
        Config::default(),
        crate::clock::system(),
        admin_owned_dir_registry(),
    )?;
    if mutating {
        ctx.audit.require_writable()?;
    }
    Ok(ctx)
}

// Only ordinary administrator Contexts opt into this registry. Its entries
// are the exact private paths they create, never supplied/adopted paths.
static ADMIN_OWNED_DIRS: OnceLock<Arc<OwnedTempDirRegistry>> = OnceLock::new();

fn admin_owned_dir_registry() -> Arc<OwnedTempDirRegistry> {
    Arc::clone(ADMIN_OWNED_DIRS.get_or_init(|| Arc::new(OwnedTempDirRegistry::default())))
}

fn shutdown_admin_owned_dirs() {
    admin_owned_dir_registry().shutdown_and_cleanup();
}

struct AdminOwnedDirCleanup;

impl Drop for AdminOwnedDirCleanup {
    fn drop(&mut self) {
        admin_owned_dir_registry().cleanup();
    }
}

struct RestoreTerminalEcho {
    terminal: fs::File,
    original: rustix::termios::Termios,
    signals: signal_hook::iterator::Handle,
    watcher: Option<thread::JoinHandle<()>>,
    default_signal_action: Arc<AtomicBool>,
}
impl Drop for RestoreTerminalEcho {
    fn drop(&mut self) {
        let mut active = PROMPT_TERMINAL.lock().unwrap_or_else(|e| e.into_inner());
        let _ = rustix::termios::tcsetattr(
            &self.terminal,
            rustix::termios::OptionalActions::Now,
            &self.original,
        );
        *active = None;
        drop(active);
        // signal-hook unregisters callbacks but does not restore the OS's
        // previous disposition. Re-arm SIGTERM's conditional default action
        // outside the prompt; SIGINT stays on the process-lifetime watcher.
        self.default_signal_action.store(true, Ordering::SeqCst);
        self.signals.close();
        if let Some(watcher) = self.watcher.take() {
            let _ = watcher.join();
        }
    }
}

static PROMPT_LOCK: Mutex<()> = Mutex::new(());
struct PromptTerminal {
    terminal: fs::File,
    original: rustix::termios::Termios,
}
static PROMPT_TERMINAL: Mutex<Option<PromptTerminal>> = Mutex::new(None);
static PROMPT_DEFAULT_SIGNALS: OnceLock<Result<Arc<AtomicBool>, String>> = OnceLock::new();

fn exit_after_prompt_signal(signal: i32) -> ! {
    // Keep this lock through process termination: a concurrently executing
    // prompt cannot disable echo again after restoration but before exit.
    let active = PROMPT_TERMINAL.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(prompt) = active.as_ref() {
        let _ = rustix::termios::tcsetattr(
            &prompt.terminal,
            rustix::termios::OptionalActions::Now,
            &prompt.original,
        );
    }
    if signal == signal_hook::consts::signal::SIGINT {
        shutdown_admin_owned_dirs();
        std::process::exit(130);
    }
    let _ = signal_hook::low_level::emulate_default_handler(signal);
    std::process::exit(128 + signal);
}

fn prompt_default_signal_action() -> io::Result<Arc<AtomicBool>> {
    PROMPT_DEFAULT_SIGNALS
        .get_or_init(|| {
            let armed = Arc::new(AtomicBool::new(true));
            // Signal callbacks only wake this thread. Filesystem cleanup is
            // performed here, never in the asynchronous signal handler.
            let mut interrupts =
                signal_hook::iterator::Signals::new([signal_hook::consts::signal::SIGINT])
                    .map_err(|e| e.to_string())?;
            thread::Builder::new()
                .name("zeropw-admin-sigint".into())
                .spawn(move || {
                    if interrupts.forever().next().is_some() {
                        exit_after_prompt_signal(signal_hook::consts::signal::SIGINT);
                    }
                })
                .map_err(|e| e.to_string())?;
            signal_hook::flag::register_conditional_default(
                signal_hook::consts::signal::SIGTERM,
                armed.clone(),
            )
            .map_err(|e| e.to_string())?;
            Ok(armed)
        })
        .as_ref()
        .map(Arc::clone)
        .map_err(|e| io::Error::other(e.clone()))
}

fn prompt_password_without_echo_race(prompt: &str) -> io::Result<String> {
    let _prompt_lock = PROMPT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut terminal = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")?;
    let original = rustix::termios::tcgetattr(&terminal)?;
    let default_signal_action = prompt_default_signal_action()?;
    // The process-lifetime SIGINT watcher restores active terminal state.
    // This prompt-local watcher handles SIGTERM while echo is disabled.
    let mut signals = signal_hook::iterator::Signals::new([signal_hook::consts::signal::SIGTERM])?;
    let handle = signals.handle();
    let restore_terminal = terminal.try_clone()?;
    let watcher = thread::Builder::new().spawn(move || {
        if let Some(signal) = signals.forever().next() {
            exit_after_prompt_signal(signal);
        }
    })?;
    let restore = RestoreTerminalEcho {
        terminal: restore_terminal,
        original: original.clone(),
        signals: handle,
        watcher: Some(watcher),
        default_signal_action: default_signal_action.clone(),
    };
    default_signal_action.store(false, Ordering::SeqCst);
    let mut hidden = original.clone();
    hidden
        .local_modes
        .remove(rustix::termios::LocalModes::ECHO | rustix::termios::LocalModes::ECHONL);
    {
        let mut active = PROMPT_TERMINAL.lock().unwrap_or_else(|e| e.into_inner());
        *active = Some(PromptTerminal {
            terminal: terminal.try_clone()?,
            original: original.clone(),
        });
        rustix::termios::tcsetattr(&terminal, rustix::termios::OptionalActions::Now, &hidden)?;
    }
    terminal.write_all(prompt.as_bytes())?;
    terminal.flush()?;
    // Canonical TTY input retains the usual backspace and line-kill editing.
    // Avoid a second password reader that changes termios and can restore
    // no-echo settings immediately before a signal terminates the process.
    // Read one byte at a time so a pasted second line remains in the TTY for
    // the recovery prompt instead of being prefetched into a dropped buffer.
    let mut password = String::new();
    if io::BufReader::with_capacity(1, &terminal).read_line(&mut password)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "terminal password input ended",
        ));
    }
    terminal.write_all(b"\n")?;
    if password.ends_with('\n') {
        password.pop();
    }
    if password.ends_with('\r') {
        password.pop();
    }
    drop(restore);
    Ok(password)
}

fn passphrase(name: &str) -> Result<String, Error> {
    let value = env::var(name).unwrap_or_default();
    if !value.is_empty() {
        return Ok(value);
    }
    if io::stdin().is_terminal() {
        let prompt = if name == "ZEROPW_RECOVERY_PASSPHRASE" {
            "Recovery passphrase: "
        } else {
            "Administrator passphrase: "
        };
        return prompt_password_without_echo_race(prompt).map_err(|_| {
            Error::auth_failed("passphrase_missing")
                .with_detail(format!("set {name} or run on a terminal"))
        });
    }
    Err(Error::auth_failed("passphrase_missing")
        .with_detail(format!("set {name} or run on a terminal")))
}

fn read_secret(a: &Args, kind: &str) -> Result<Vec<u8>, Error> {
    let mut data = if let Some(path) = a.get("value-file").filter(|p| !p.is_empty()) {
        let file = fs::File::open(path).map_err(|e| os_error(&e))?;
        let mut data = Vec::new();
        file.take((MAX_SECRET_BYTES + 1) as u64)
            .read_to_end(&mut data)
            .map_err(|e| os_error(&e))?;
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
    let digits_end = s.bytes().take_while(u8::is_ascii_digit).count();
    let (digits, unit) = s.split_at(digits_end);
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

/// `_parse_target`: `scheme://host[:port]` with no path, query, fragment or
/// userinfo, parsed by `urllib.parse.urlsplit` semantics.
fn target(v: &str) -> Result<(String, String, i64), Error> {
    let origin_only = || {
        Error::invalid_input("target_must_be_origin")
            .with_detail("target is scheme://host[:port] only")
    };
    let parts = crate::pystr::urlsplit(v.trim_matches(crate::pystr::is_space))
        .map_err(|_| Error::invalid_input("invalid_host"))?;
    let host = parts.hostname();
    if parts.scheme != "http" && parts.scheme != "https" {
        return Err(Error::invalid_input("invalid_scheme")
            .with_detail("target must start with http:// or https://"));
    }
    let (username, password) = parts.userinfo();
    if !(parts.path.is_empty() || parts.path == "/")
        || !parts.query.is_empty()
        || !parts.fragment.is_empty()
        || username.is_some_and(|u| !u.is_empty())
        || password.is_some_and(|p| !p.is_empty())
    {
        return Err(origin_only());
    }
    let port = parts
        .port()
        .map_err(|_| Error::invalid_input("invalid_port"))?;
    let host = host.ok_or_else(|| Error::invalid_input("invalid_host"))?;
    let port = match port {
        Some(port) => i64::from(port),
        None if parts.scheme == "https" => 443,
        None => 80,
    };
    Ok((parts.scheme, host, port))
}

fn control(ctx: &Context) -> Result<Value, Error> {
    Ok(
        json!({"stopped":ctx.policy.is_stopped()?,"restore_pending":ctx.policy.restore_pending()?,"incident_open":ctx.policy.open_incident_id()?}),
    )
}

fn grant_view(grant: &crate::policy::Grant) -> Value {
    json!({"id":grant.id,"principal":grant.principal,"connection":grant.connection,
        "policy_version":grant.policy_version,"expires_at":grant.expires_at.map(|t| iso(Some(t))),
        "max_uses":grant.max_uses_value(),"uses":grant.uses,"status":grant.status,
        "created_at":grant.created_at,"revoked_at":grant.revoked_at,
        "credential_version":grant.credential_version})
}

fn check_admin_document(ctx: &Context) -> Result<(), Error> {
    let doc = ctx.state.read_json(crate::vault::ADMIN_DOC, Value::Null)?;
    if doc.is_null() {
        return Ok(()); // Preserve AdminCredential's own admin_missing reason.
    }
    let object = doc
        .as_object()
        .ok_or_else(|| Error::state("state_corrupt").with_detail("TypeError"))?;
    for key in ["salt", "hash"] {
        if !object.contains_key(key) {
            return Err(Error::state("state_corrupt").with_detail("KeyError"));
        }
        if !object[key].is_string() {
            return Err(Error::state("state_corrupt").with_detail("TypeError"));
        }
    }
    Ok(())
}

fn verify_admin(ctx: &Context, state: &str) -> Result<(), Error> {
    check_admin_document(ctx)?;
    let pass = passphrase("ZEROPW_ADMIN_PASSPHRASE")?;
    if let Err(error) = ctx.admin.verify(&pass, None) {
        record_auth_failure(ctx, &error.reason, vec![("state", json!(state))]);
        return Err(error);
    }
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
        .resolve_version(&connection.secret_id, connection.secret_version.clone())?;
    if let Some(version) = meta
        .versions
        .iter()
        .find(|v| ver.equals_integer(&v.version))
        && version.status != "active"
        && version.status != "staged"
    {
        return Err(Error::invalid_input("secret_version_unusable").with_detail(&version.status));
    }
    if crate::tools::profile_env_carries_vault_value(ctx, connection)? {
        return refuse_cli_env(ctx, &connection.id, None, "connection_create");
    }
    Ok(())
}

/// `_create_connection`: the state-locked credential scan and write, then
/// the `connection_create` record with the kind-specific `extra` fields.
fn create_connection(
    ctx: &Context,
    connection: Connection,
    target: &str,
    extra: Vec<(&str, Value)>,
) -> Result<Connection, Error> {
    let stamped = {
        // The credential scan and persisted CLI profile must be one state transaction.
        let _lock = ctx.state.lock()?;
        check_secret_connection(ctx, &connection)?;
        ctx.policy.create_connection(connection)?
    };
    let mut fields = vec![
        ("kind", json!(stamped.kind)),
        ("service", json!(stamped.service)),
        ("project", json!(stamped.project)),
        ("environment", json!(stamped.environment)),
        ("secret_id", json!(stamped.secret_id)),
        ("version", json!(stamped.secret_version)),
    ];
    fields.extend(extra);
    ctx.audit.record(
        "connection_create",
        RecordArgs {
            caller: Some("admin"),
            connection: Some(&stamped.id),
            target: Some(target),
            result: Some("ok"),
            policy_version: Some(stamped.policy_version),
            extra: fields,
            ..Default::default()
        },
    )?;
    Ok(stamped)
}

/// `_switch_credential`: pin a local connection to one usable version of its
/// secret. The version is checked before the connection changes, so a
/// missing, retired or revoked version leaves the connection untouched.
fn switch_credential(
    ctx: &Context,
    connection_id: &str,
    version: PyInt,
) -> Result<Connection, Error> {
    let before = ctx.policy.get_connection(connection_id)?;
    let meta = ctx.vault.get_meta(&before.secret_id)?;
    let status = meta
        .versions
        .iter()
        .find(|v| v.version == version)
        .map(|v| v.status.clone())
        .ok_or_else(|| Error::not_found("secret_version_not_found"))?;
    if status != "active" && status != "staged" {
        return Err(Error::invalid_input("secret_version_unusable").with_detail(status));
    }
    let after = ctx
        .policy
        .switch_credential(connection_id, Some(version.clone()))?;
    ctx.audit.record(
        "connection_switch_credential",
        RecordArgs {
            caller: Some("admin"),
            connection: Some(&after.id),
            result: Some("ok"),
            policy_version: Some(after.policy_version),
            extra: vec![
                ("secret_id", json!(after.secret_id)),
                ("version", json!(version)),
            ],
            ..Default::default()
        },
    )?;
    Ok(after)
}

fn local_command(a: &Args) -> Result<Value, Error> {
    if a.command == "init" {
        // `_check_passphrase_strength` runs on each passphrase as soon as it is read.
        let admin = passphrase("ZEROPW_ADMIN_PASSPHRASE")?;
        if admin.chars().count() < 8 {
            return Err(Error::invalid_input("passphrase_too_short")
                .with_detail("administrator passphrase needs at least 8 characters"));
        }
        let recovery = passphrase("ZEROPW_RECOVERY_PASSPHRASE")?;
        if recovery.chars().count() < 8 {
            return Err(Error::invalid_input("passphrase_too_short")
                .with_detail("recovery passphrase needs at least 8 characters"));
        }
        if admin == recovery {
            return Err(Error::invalid_input("passphrases_identical")
                .with_detail("the recovery passphrase must be independent of the admin one"));
        }
        let ctx = Context::initialize_with_tempdir_cleanup(
            user_path(&a.state_dir)?,
            &admin,
            &recovery,
            Config::default(),
            crate::clock::system(),
            admin_owned_dir_registry(),
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
            // `tuple(_csv(args.environments)) if args.environments else DEFAULT_ENVIRONMENTS`.
            let envs = if let Some(v) = a.get("environments").filter(|v| !v.is_empty()) {
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
                    return refuse_cli_env(&ctx, &conn.id, Some(a.req("id")), "secret_put");
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
            check_admin_document(&ctx)?;
            let pass = passphrase("ZEROPW_ADMIN_PASSPHRASE")?;
            let auth = match ctx.admin.verify(&pass, None) {
                Ok(auth) => auth,
                Err(error) => {
                    record_auth_failure(
                        &ctx,
                        &error.reason,
                        vec![("secret_id", json!(a.req("id")))],
                    );
                    return Err(error);
                }
            };
            let version = a.version("version")?;
            let value = ctx
                .vault
                .reveal(a.req("id"), version.clone(), &auth, None)?;
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
                .version("version")?
                .ok_or_else(|| Error::invalid_input("invalid_arguments"))?;
            if let Some(env_id) = secret_shared_env(&ctx, id)? {
                let version_id = shared_version_id(&ctx, id, version.clone())?;
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
            if is_retire
                && meta
                    .active_version
                    .as_ref()
                    .is_some_and(|active| active.equals_integer(&version))
            {
                return Err(Error::invalid_input("version_is_active")
                    .with_detail("activate another version first (rotation activate)"));
            }
            let using = ctx.policy.list_connections()?;
            let pinned: Vec<String> = using
                .iter()
                .filter(|c| {
                    c.secret_id == id
                        && c.secret_version.as_ref() == Some(&version)
                        && c.status == "active"
                })
                .map(|c| c.id.clone())
                .collect();
            if is_retire && !pinned.is_empty() {
                return Err(Error::invalid_input("version_in_use")
                    .with_detail(format!("pinned by connections: {}", pinned.join(","))));
            }
            let mut affected = pinned;
            if !is_retire
                && meta
                    .active_version
                    .as_ref()
                    .is_some_and(|active| active.equals_integer(&version))
            {
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
                &version,
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
            let ca = if let Some(p) = a.get("ca-file").filter(|p| !p.is_empty()) {
                let expanded = user_path(p)?;
                let path = Path::new(&expanded);
                if !path.is_file() {
                    return Err(Error::invalid_input("ca_file_missing").with_detail(&expanded));
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
            let cli = if let Some(program) = a.get("cli-program").filter(|p| !p.is_empty()) {
                // `_parse_env_assignments`: a dict, so a repeated key keeps its
                // first position with the last value, and `CliProfile`
                // validates entries in that insertion order.
                let mut extra: Vec<(String, String)> = Vec::new();
                for item in a.list("cli-env") {
                    let (key, val) = item.split_once('=').ok_or_else(|| {
                        Error::invalid_input("invalid_cli_env").with_detail("use KEY=VALUE")
                    })?;
                    if key.is_empty() {
                        return Err(
                            Error::invalid_input("invalid_cli_env").with_detail("use KEY=VALUE")
                        );
                    }
                    match extra.iter_mut().find(|(k, _)| k == key) {
                        Some(entry) => entry.1 = val.to_owned(),
                        None => extra.push((key.to_owned(), val.to_owned())),
                    }
                }
                Some(CliProfile::new_ordered(program, "http", None, extra)?)
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
                a.version("secret-version")?,
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
                    .version("secret-version")?
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
            let origin = connection
                .http_target
                .as_ref()
                .map(HttpTarget::origin)
                .unwrap_or_default();
            let (host, port) = connection
                .http_target
                .as_ref()
                .map(|t| (t.host.clone(), t.port))
                .unwrap_or_default();
            Ok(create_connection(
                &ctx,
                connection,
                &origin,
                vec![
                    ("scheme", json!(scheme)),
                    ("host", json!(host)),
                    ("port", json!(port)),
                    ("method", json!(a.req("auth"))),
                ],
            )?
            .to_value())
        }
        ("connection", "create-ssh") => {
            let port = a.integer("port")?.unwrap_or(22);
            let host_keys = a
                .list("host-key")
                .iter()
                .map(|line| {
                    let entry = crate::sshwire::parse_authorized_key_entry(line)
                        .map_err(|_| Error::invalid_input("invalid_host_key"))?;
                    if entry.options.starts_with('@') {
                        return Err(Error::invalid_input("invalid_host_key")
                            .with_detail("known_hosts_marker"));
                    }
                    entry
                        .key
                        .to_authorized_key(&entry.comment)
                        .map_err(|_| Error::invalid_input("invalid_host_key"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let ssh = SshTarget::new(a.req("host"), port, a.req("username"), host_keys)?;
            let cli = a
                .get("cli-program")
                .filter(|p| !p.is_empty())
                .map(|p| CliProfile::new(p, "ssh", None, BTreeMap::new()))
                .transpose()?;
            let connection = Connection::new(
                a.req("id"),
                a.req("project"),
                a.req("environment"),
                a.req("service"),
                "ssh",
                a.req("secret-id"),
                a.version("secret-version")?,
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
                    .version("secret-version")?
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
                let (host, port, username) = connection
                    .ssh_target
                    .as_ref()
                    .map(|t| (t.host.clone(), t.port, t.username.clone()))
                    .unwrap_or_default();
                create_connection(
                    &ctx,
                    connection,
                    &format!("{host}:{port}"),
                    vec![
                        ("host", json!(host)),
                        ("port", json!(port)),
                        ("username", json!(username)),
                    ],
                )?
            };
            let mut out = stamped.to_value();
            if let Some(result) = result {
                out["commit"] = result["commit"].clone();
                out["propagated_to"] = json!(0);
            }
            let meta = ctx.vault.get_meta(&stamped.secret_id)?;
            let resolved = ctx
                .vault
                .resolve_version(&stamped.secret_id, stamped.secret_version.clone())
                .ok();
            if let Some(v) = meta.versions.iter().find(|v| {
                resolved
                    .as_ref()
                    .is_some_and(|r| r.equals_integer(&v.version))
            }) {
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
            admin_record_for(
                &ctx,
                "connection_update",
                Some(&after.id),
                Some(after.policy_version),
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
                .version("version")?
                .ok_or_else(|| Error::invalid_input("invalid_arguments"))?;
            let before = ctx.policy.get_connection(a.req("id"))?;
            if let Some(env_id) = connection_shared_env(&ctx, a.req("id"))? {
                let version_id = shared_version_id(&ctx, &before.secret_id, ver.clone())?;
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
            let after = switch_credential(&ctx, a.req("id"), ver)?;
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
            ctx.audit.record(
                "connection_disable",
                RecordArgs {
                    caller: Some("admin"),
                    connection: Some(&c.id),
                    result: Some("ok"),
                    policy_version: Some(c.policy_version),
                    ..Default::default()
                },
            )?;
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
            let max_uses = a.exact_integer("max-uses")?;
            let grant = ctx.policy.create_grant_with_exact_max_uses(
                a.req("principal"),
                a.req("connection"),
                Some(seconds),
                max_uses,
            )?;
            admin_record_for(
                &ctx,
                "grant_create",
                Some(&grant.connection),
                Some(grant.policy_version),
                vec![
                    ("grant", json!(grant.id)),
                    ("principal", json!(grant.principal)),
                    ("max_uses", grant.max_uses_value()),
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
            admin_record_for(
                &ctx,
                "grant_revoke",
                Some(&g.connection),
                None,
                vec![("grant", json!(g.id)), ("principal", json!(g.principal))],
            )?;
            Ok(grant_view(&g))
        }
        ("grant", "regrant") => {
            let g = ctx.policy.regrant(a.req("id"))?;
            admin_record_for(
                &ctx,
                "grant_regrant",
                Some(&g.connection),
                Some(g.policy_version),
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
            admin_record_for(
                &ctx,
                "approval_grant",
                entry.get("connection").and_then(Value::as_str),
                None,
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
                    return refuse_cli_env(&ctx, &conn.id, Some(&meta.id), "rotation");
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
                .version("version")?
                .ok_or_else(|| Error::invalid_input("invalid_arguments"))?;
            let before = ctx.policy.get_connection(a.req("connection"))?;
            let previous = ctx.vault.get_meta(&before.secret_id)?.active_version;
            if let Some(env_id) = connection_shared_env(&ctx, &before.id)? {
                let version_id = shared_version_id(&ctx, &before.secret_id, version.clone())?;
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
                    json!({"connection":after.id,"secret_id":after.secret_id,"version":version,"previous_active":previous,"policy_version":after.policy_version,"other_connections":others,"next":format!("verify the new credential works, then: rotation finish --secret-id {} --version {}",after.secret_id,previous.map(|v|format!("{v}")).unwrap_or("<old>".into())),"commit":result["commit"],"propagated_to":0}),
                );
            }
            // Pin first (one policy-version bump for this connection), then activate:
            // activating re-binds only the other unpinned connections that follow the secret.
            let after = switch_credential(&ctx, &before.id, version.clone())?;
            ctx.vault
                .set_version_status(&before.secret_id, &version, "active")?;
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
                json!({"connection":after.id,"secret_id":after.secret_id,"version":version,"previous_active":previous,"policy_version":after.policy_version,"other_connections":others,"next":format!("verify the new credential works, then: rotation finish --secret-id {} --version {}",after.secret_id,previous.map(|n|format!("{n}")).unwrap_or("<old>".into()))}),
            )
        }
        ("backup", "") => {
            let path = PathBuf::from(user_path(a.req("out"))?);
            if path
                .parent()
                .is_some_and(|parent| !parent.as_os_str().is_empty() && !parent.exists())
            {
                return Err(Error::invalid_input("file_not_found"));
            }
            let manifest = ctx.vault.backup(&path)?;
            Ok(
                json!({"out":path.to_string_lossy(),"manifest":manifest,"note":"encrypted archive; needs the KMS key or recovery passphrase"}),
            )
        }
        ("restore", "") => {
            let manifest = Vault::restore(
                ctx.state,
                Path::new(&user_path(a.req("in"))?),
                ctx.audit,
                Some(ctx.kms),
            )?;
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
            verify_admin(&ctx, "restore_pending")?;
            // The latest revocation state is applied again under the lock before execution reopens.
            let reapplied = {
                let _lock = ctx.state.lock()?;
                let reapplied = Vault::reapply_revocations(ctx.state)?;
                ctx.policy.set_restore_pending(false)?;
                reapplied
            };
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
            let pass = passphrase("ZEROPW_RECOVERY_PASSPHRASE")?;
            let count = match ctx.recover(&pass) {
                Ok(count) => count,
                Err(error) => {
                    if error.class == crate::errors::ErrorClass::AuthFailed {
                        record_auth_failure(&ctx, &error.reason, vec![("state", json!("recover"))]);
                    }
                    return Err(error);
                }
            };
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
                verify_admin(&ctx, "incident_declare")?;
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
                verify_admin(&ctx, "incident_escalate")?;
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
            verify_admin(&ctx, "incident_close")?;
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
fn shared_version_id(ctx: &Context, secret_id: &str, version: PyInt) -> Result<String, Error> {
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
    ) && (a.action != "peers" || a.get("add").is_some_and(|v| !v.is_empty()));
    let ctx = open(a, mutating)?;
    if a.action == "init" {
        let key = DeviceKey::create(ctx.state, ctx.kms)?;
        return Ok(Some(json!({"fingerprint":key.fingerprint()?})));
    }
    if a.action == "share" {
        let admin = passphrase("ZEROPW_ADMIN_PASSPHRASE")?;
        let result = M::share_environment(
            &ctx,
            None,
            a.req("project"),
            a.req("environment"),
            a.get("name").filter(|n| !n.is_empty()).unwrap_or("owner"),
            &admin,
        )
        .inspect_err(|error| {
            if error.is(crate::errors::ErrorClass::AuthFailed) {
                record_auth_failure(
                    &ctx,
                    &error.reason,
                    vec![
                        ("project", json!(a.req("project"))),
                        ("environment", json!(a.req("environment"))),
                    ],
                );
            }
        })?;
        return Ok(Some(
            json!({"env_id":result["env_id"],"project":a.req("project"),"environment":a.req("environment"),"not_shared":result["not_shared"]}),
        ));
    }
    if a.action == "join" {
        use crate::team::transport::TcpTransport;
        let device = DeviceKey::load_or_create(ctx.state, ctx.kms)?;
        let transport = TcpTransport::new(
            device.clone(),
            Arc::new(|_, _| None),
            crate::team::transport::DEFAULT_MAX_CONNECTIONS,
        );
        let team = sync::TeamSync::new(Arc::new(ctx), Arc::new(transport.clone()), device);
        team.start(None)?;
        let result = M::join(
            &team.ctx,
            &a.positional[0],
            &transport,
            &team,
            a.get("project"),
            a.get("environment"),
            M::JOIN_TIMEOUT_SECONDS,
        );
        team.stop();
        return result.map(Some);
    }
    let env_id = team_env_id(&ctx, a.req("env"))?;
    let out = match a.action.as_str() {
        "invite" => {
            // `_parse_ttl(args.ttl) if args.ttl else DEFAULT_INVITE_TTL_SECONDS`.
            let ttl = match a.get("ttl").filter(|t| !t.is_empty()) {
                Some(text) => ttl(text)?,
                None => M::DEFAULT_INVITE_TTL_SECONDS,
            };
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
            json!({"env_id":env_id,"vector":vector,"commits_folded":vector.values().fold(crate::pyint::PyInt::zero(),|acc,v|crate::pyint::PyInt(acc.0+&v.0)),"skipped_ops":folded.skipped.len(),"rejected_commits":rejected,"pending_deferred":store.deferred_commits()?.len(),"note":"sessions/synced_at reflect a running `serve --team-listen`; this one-shot CLI holds none"})
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
            if let Some(add) = a.get("add").filter(|v| !v.is_empty()) {
                let device = a.get("device").filter(|d| !d.is_empty()).ok_or_else(|| {
                    Error::invalid_input("peer_add_needs_device")
                        .with_detail("use --device FP with --add")
                })?;
                let team = offline_team(Arc::new(open(a, true)?))?;
                team.register_env(&env_id)?;
                team.set_peer_address(&env_id, device, add)?;
            }
            // `read_json(...) or {}`: a falsy document prints as `{}`.
            let doc = ctx
                .state
                .read_json(&format!("team/{env_id}/peers.json"), json!({}))?;
            let doc = if python_truthy(&doc) { doc } else { json!({}) };
            json!({"env_id":env_id,"peers":doc})
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
    let ctx = Arc::new(Context::open(
        user_path(state_dir)?,
        config,
        crate::clock::system(),
    )?);
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
    let server =
        crate::server::ZeroPWServer::new_with_quiet(ctx.clone(), Some(&host), Some(port), quiet)?;
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
        // The server records only "METHOD query-free-path" lines; handles are already masked.
        if !quiet {
            for line in server.take_log_lines() {
                eprintln!("{line}");
            }
        }
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
        // `_notice(f"notification retry failed: {type(exc).__name__}")`.
        if let Err(error) = crate::notify::retry_pending(&ctx, (ctx.clock)())
            && !quiet
        {
            eprintln!(
                "notification retry failed: {}",
                python_exception_name(&error)
            );
        }
    }
    if let Some(team) = team {
        team.stop();
    }
    server.stop();
    Ok(payload)
}

/// Process entry point taking the raw OS arguments. Python decodes a
/// non-UTF-8 argument with `surrogateescape`; a Rust `String` cannot hold
/// the resulting lone surrogates (PORTING.md §3.6), so such an argument is a
/// usage error -- and, like every unrecognized token, it is never echoed.
pub fn main_os(argv: Vec<std::ffi::OsString>) -> i32 {
    match argv
        .into_iter()
        .map(std::ffi::OsString::into_string)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(argv) => main(&argv),
        Err(_) => {
            eprint!("{}", build_parser().format_usage());
            output(
                &json!({"error":"UsageError","reason":"usage","detail":"argument is not valid UTF-8; values are not echoed"}),
                true,
            );
            2
        }
    }
}

/// Process entry point for the trusted administrator CLI.
pub fn main(argv: &[String]) -> i32 {
    let args = match parse(argv) {
        Ok(a) => a,
        Err(ParseFail::Help(text)) => {
            print!("{text}");
            let _ = io::stdout().flush();
            return 0;
        }
        Err(ParseFail::Usage { usage, detail }) => {
            eprint!("{usage}");
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
    // Unlike `serve`, ordinary commands return Python's caught
    // KeyboardInterrupt status even when an environment passphrase bypasses
    // the terminal prompt (or no passphrase is needed at all).
    if prompt_default_signal_action().is_err() {
        output(&Error::state("signal_handler_unavailable").to_dict(), true);
        return 1;
    }
    let _owned_dir_cleanup = AdminOwnedDirCleanup;
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
            } else if error.reason == "state_corrupt"
                && !ESCAPED_BUILTIN_ERRORS.contains(&error.detail.as_str())
                && (!error.detail.ends_with(".json")
                    || [
                        "admin.json",
                        "projects.json",
                        "policy/grants.json",
                        "policy/connections.json",
                        "policy/principals.json",
                        "policy/control.json",
                        "vault/secrets.json",
                    ]
                    .contains(&error.detail.as_str())
                        && fs::read_to_string(
                            Path::new(&user_path(&args.state_dir).unwrap_or_default())
                                .join(&error.detail),
                        )
                        .ok()
                        .is_some_and(|text| pyjson::loads(&text).is_ok()))
            {
                // Python's CLI reports only the built-in exception class for
                // semantically broken JSON; internal model labels are not public.
                output(
                    &json!({"error":"StateError","reason":"state_corrupt","detail":"KeyError"}),
                    true,
                );
            } else {
                output(&error.to_dict(), true);
            }
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn user_path_matches_pathlib_expanduser_through_system_nss() {
        let current = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .expect("current-user NSS lookup failed")
            .expect("current uid has no NSS user");
        let named = format!("~{}", current.name);
        let named_child = format!("~{}//nested/./path/", current.name);
        let unknown = format!(
            "~zeropw-user-that-must-not-exist-{}/path",
            std::process::id()
        );
        let paths = [
            named.as_str(),
            named_child.as_str(),
            unknown.as_str(),
            "relative//nested/./path/",
            "/absolute//nested/./path/",
        ];
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&paths).unwrap());
        let script = format!(
            r#"
import base64, json, pathlib
for path in json.loads(base64.b64decode({encoded:?})):
    try:
        print(json.dumps({{"ok": str(pathlib.Path(path).expanduser())}}, sort_keys=True))
    except Exception as error:
        print(json.dumps({{"error": type(error).__name__}}, sort_keys=True))
"#
        );
        let expected: Vec<Value> = crate::oracle::python(&script)
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let actual: Vec<Value> = paths
            .iter()
            .map(|path| match user_path(path) {
                Ok(path) => json!({"ok": path}),
                Err(error) => json!({"error": error.name}),
            })
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(actual[2], json!({"error": "RuntimeError"}));
    }

    #[test]
    fn parser_accepts_equals_repeated_values_and_positional_terminator() {
        let args = parse(
            &[
                "--state-dir=state",
                "project",
                "create",
                "--environments=dev,prod",
                "--",
                "--literal-name",
            ]
            .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(args.state_dir, "state");
        assert_eq!(args.positional, ["--literal-name"]);
        assert_eq!(args.get("environments"), Some("dev,prod"));

        let args = parse(
            &[
                "--state-dir",
                "state",
                "team",
                "invite",
                "--env=demo/dev",
                "--role=user",
                "--name=peer",
                "--address=127.0.0.1:1",
                "--address=127.0.0.1:2",
            ]
            .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(args.list("address"), ["127.0.0.1:1", "127.0.0.1:2"]);
        assert!(
            parse(
                &[
                    "--state-dir",
                    "state",
                    "team",
                    "show",
                    "--env=demo/dev",
                    "--format=xml",
                ]
                .map(str::to_owned)
            )
            .is_err()
        );
        assert!(
            parse(
                &[
                    "--state-dir",
                    "state",
                    "secret",
                    "put",
                    "--id=x",
                    "--kind=api_key",
                    "--project=p",
                    "--environment=e",
                    "--stdin=true",
                ]
                .map(str::to_owned)
            )
            .is_err()
        );
    }

    #[test]
    fn ttl_matches_python_units_and_rejects_bad_or_overflowing_forms() {
        for (text, expected) in [
            ("30m", 1800),
            ("1h", 3600),
            ("3600s", 3600),
            ("86400", 86400),
            ("24h", 86400),
            ("2d", 172800),
            (" 3M ", 180),
        ] {
            assert_eq!(ttl(text).unwrap(), expected, "{text}");
        }
        for text in [
            "",
            "0",
            "0h",
            "-1h",
            "+1h",
            "1w",
            "1hour",
            "1.5h",
            "٣h",
            "²h",
            "1é",
            "999999999999999999999999999999d",
        ] {
            assert_eq!(ttl(text).unwrap_err().reason, "invalid_ttl", "{text}");
        }
    }
}
