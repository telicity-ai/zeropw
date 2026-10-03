//! Port of `tests/test_team_fold.py`'s `derive_local`-driving cases (`Context`
//! plumbing: `Vault`/`Policy`/`Audit` all exercised together, not just
//! `fold()` in isolation -- those pure-`fold()` cases live in
//! `zeropw::team::fold`'s own `#[cfg(test)] mod tests` instead, per
//! `rust/PORTING.md`'s "unit tests in the module or `rust/tests/*.rs`").
//!
//! Lives under `rust/tests/` (a standalone integration-test binary) because
//! it needs `Context::initialize`, matching `vault_context.rs`'s pattern.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use serde_json::{Map, Value, json};
use tempfile::TempDir;

use zeropw::context::{Config, Context};
use zeropw::errors::ErrorClass;
use zeropw::policy::{CONNECTIONS, Connection, HttpAuth, HttpScope, HttpTarget};
use zeropw::projects;
use zeropw::team::commit::{self as C, Commit};
use zeropw::team::envelope;
use zeropw::team::fold::{self as F};
use zeropw::team::identity::DeviceKey;
use zeropw::vault::VAULT_DOC;
use zeropw::{clock, pyjson};

/// Runs `script` with `python3.12` (override with `ZEROPW_PYTHON`) and the
/// repository root on `PYTHONPATH`. Mirrors `team_oracle.rs`'s own helper --
/// this is a separate standalone test binary, so `crate::oracle` (this
/// crate's own `#[cfg(test)]` helper) is not reachable from here either.
fn run_python(script: &str) -> String {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf();
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".to_string());
    let output = Command::new(&interpreter)
        .arg("-c")
        .arg(script)
        .env("PYTHONPATH", &repo_root)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .unwrap_or_else(|e| panic!("cannot run {interpreter}: {e}"));
    if !output.status.success() {
        panic!(
            "python oracle failed ({}):\n--- script ---\n{script}\n--- stderr ---\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout).expect("oracle stdout is UTF-8")
}

const ADMIN: &str = "admin-pass-1";
const RECOVERY: &str = "recovery-pass-1";
const GEN0: &str = "0000000000000000";
const BOOTSTRAP_SECRET_VALUE: &[u8] = b"synthetic-bootstrap-placeholder-secret";
const SYNTHETIC_SECRET: &[u8] = b"synthetic-shared-secret-0123456789";

fn setup() -> (TempDir, Context) {
    let tmp = TempDir::new().expect("tempdir");
    let ctx = Context::initialize(
        tmp.path().join("state"),
        ADMIN,
        RECOVERY,
        Config::default(),
        clock::system(),
    )
    .expect("Context::initialize");
    ctx.projects
        .create("demo", projects::DEFAULT_ENVIRONMENTS)
        .expect("create demo project");
    (tmp, ctx)
}

fn random_hex(n: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

fn env_init_commit(
    env_id: &str,
    owner: &DeviceKey,
    dek: &[u8],
    hlc: &str,
    bootstrap_secret_id: Option<&str>,
) -> Commit {
    let record = owner.record().unwrap();
    let wrap = envelope::wrap_dek(dek, env_id, GEN0, &record).unwrap();
    let mut wraps = Map::new();
    wraps.insert(owner.fingerprint().unwrap(), wrap);
    let op_init = json!({"op": "env.init", "owner_device": record.to_dict(), "owner_name": "alice",
                        "generation_id": GEN0, "wraps": wraps});
    let mut ops = vec![op_init];
    if let Some(secret_id) = bootstrap_secret_id {
        let version_id = random_hex(8);
        let ct =
            envelope::encrypt_secret(dek, env_id, secret_id, &version_id, BOOTSTRAP_SECRET_VALUE)
                .unwrap();
        ops.push(json!({"op": "secret.put_version", "secret_id": secret_id, "kind": "api_key",
                        "generation_id": GEN0, "version_id": version_id, "ciphertext": ct, "public": {}}));
    }
    C::sign_commit(owner, env_id, 1, hlc, &BTreeMap::new(), ops).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn connection_create_commit(
    env_id: &str,
    author: &DeviceKey,
    seq: i128,
    hlc: &str,
    conn_id: &str,
    methods: Option<&[&str]>,
    paths: Option<&[&str]>,
    secret_id: &str,
) -> Commit {
    let scope = json!({
        "methods": methods.map(|m| m.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
        "path_prefixes": paths.map(|p| p.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
    });
    let op = json!({"op": "connection.create", "id": conn_id, "project": "demo", "environment": "dev",
                    "service": "github", "kind": "http", "secret_id": secret_id, "secret_version": null,
                    "description": "", "http_target": {"scheme": "https", "host": "api.github.com", "port": 443},
                    "http_auth": {"mode": "bearer"}, "http_scope": scope});
    C::sign_commit(author, env_id, seq, hlc, &BTreeMap::new(), vec![op]).unwrap()
}

fn simple_connection_create(
    env_id: &str,
    author: &DeviceKey,
    seq: i128,
    hlc: &str,
    conn_id: &str,
) -> Commit {
    connection_create_commit(
        env_id,
        author,
        seq,
        hlc,
        conn_id,
        Some(&["GET"]),
        Some(&["/repos"]),
        "gh-token",
    )
}

fn new_env(bootstrap_secret_id: Option<&str>) -> (DeviceKey, String, Vec<u8>, Commit) {
    let owner = DeviceKey::generate();
    let env_id = C::new_env_id(&owner.fingerprint().unwrap()).unwrap();
    let dek: Vec<u8> = (0..32u8).collect();
    let c1 = env_init_commit(&env_id, &owner, &dek, "1000-0000", bootstrap_secret_id);
    (owner, env_id, dek, c1)
}

fn derive(ctx: &Context, owner: &DeviceKey, commits: Vec<Commit>) -> F::FoldResult {
    let env_id = commits[0].env_id.clone();
    let result = F::fold(&env_id, commits, None, None, None, None).unwrap();
    F::derive_local(
        &result,
        ctx.state,
        &ctx.policy,
        Some(ctx.audit),
        Some(owner),
        Some(ctx.kms),
        None,
        None,
    )
    .unwrap();
    result
}

// --------------------------------------------------------------- LateArrival
#[test]
fn late_insert_monotonic_policy_version() {
    let (_tmp, ctx) = setup();
    let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
    let c2 = simple_connection_create(&env_id, &owner, 2, "2000-0000", "gh");
    derive(&ctx, &owner, vec![c1.clone(), c2.clone()]);
    let connections = ctx
        .state
        .read_json("policy/connections.json", Value::Null)
        .unwrap();
    let pv1 = connections["gh"]["policy_version"].as_i64().unwrap();

    let widen = C::sign_commit(
        &owner,
        &env_id,
        3,
        "3000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "connection.update", "id": "gh",
                    "http_scope": {"methods": null, "path_prefixes": null}})],
    )
    .unwrap();
    derive(&ctx, &owner, vec![c1.clone(), c2.clone(), widen.clone()]);
    let connections = ctx
        .state
        .read_json("policy/connections.json", Value::Null)
        .unwrap();
    let pv2 = connections["gh"]["policy_version"].as_i64().unwrap();
    assert!(pv2 > pv1);

    derive(&ctx, &owner, vec![c1, c2, widen]);
    let connections = ctx
        .state
        .read_json("policy/connections.json", Value::Null)
        .unwrap();
    let pv3 = connections["gh"]["policy_version"].as_i64().unwrap();
    assert_eq!(pv3, pv2);
}

// --------------------------------------------------------------- WidenNarrow
#[test]
fn widen_marks_grants_stale() {
    let (_tmp, ctx) = setup();
    let token = ctx.policy.create_principal("agent-1", "default").unwrap();
    let _ = token;
    let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
    let c2 = simple_connection_create(&env_id, &owner, 2, "2000-0000", "gh");
    derive(&ctx, &owner, vec![c1.clone(), c2.clone()]);
    let grant = ctx
        .policy
        .create_grant("agent-1", "gh", Some(3600), None)
        .unwrap();
    let c3 = C::sign_commit(
        &owner,
        &env_id,
        3,
        "3000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "connection.update", "id": "gh",
                    "http_scope": {"methods": null, "path_prefixes": null}})],
    )
    .unwrap();
    derive(&ctx, &owner, vec![c1, c2, c3]);
    assert_eq!(ctx.policy.get_grant(&grant.id).unwrap().status, "stale");
}

#[test]
fn narrow_reevaluates_in_place() {
    let (_tmp, ctx) = setup();
    ctx.policy.create_principal("agent-1", "default").unwrap();
    let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
    let c2 = connection_create_commit(
        &env_id,
        &owner,
        2,
        "2000-0000",
        "gh",
        None,
        None,
        "gh-token",
    );
    derive(&ctx, &owner, vec![c1.clone(), c2.clone()]);
    let grant = ctx
        .policy
        .create_grant("agent-1", "gh", Some(3600), None)
        .unwrap();
    let c3 = C::sign_commit(
        &owner,
        &env_id,
        3,
        "3000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "connection.update", "id": "gh",
                    "http_scope": {"methods": ["GET"], "path_prefixes": ["/repos"]}})],
    )
    .unwrap();
    derive(&ctx, &owner, vec![c1, c2, c3]);
    assert_eq!(ctx.policy.get_grant(&grant.id).unwrap().status, "active");
}

#[test]
fn disable_invalidates_grants() {
    let (_tmp, ctx) = setup();
    ctx.policy.create_principal("agent-1", "default").unwrap();
    let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
    let c2 = simple_connection_create(&env_id, &owner, 2, "2000-0000", "gh");
    derive(&ctx, &owner, vec![c1.clone(), c2.clone()]);
    let grant = ctx
        .policy
        .create_grant("agent-1", "gh", Some(3600), None)
        .unwrap();
    let c3 = C::sign_commit(
        &owner,
        &env_id,
        3,
        "3000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "connection.disable", "id": "gh"})],
    )
    .unwrap();
    derive(&ctx, &owner, vec![c1, c2, c3]);
    assert_eq!(ctx.policy.get_connection("gh").unwrap().status, "disabled");
    assert_eq!(ctx.policy.get_grant(&grant.id).unwrap().status, "stale");
}

// ---------------------------------------------------------- GenerationAvail.
#[test]
fn unknown_generation_id_skipped_at_fold_time() {
    let (owner, env_id, _dek, c1) = new_env(None);
    let bogus_ct = json!({"nonce": "AAAA", "ciphertext": "AAAA"});
    let c2 = C::sign_commit(
        &owner,
        &env_id,
        2,
        "2000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
                    "generation_id": "f".repeat(16), "version_id": "1".repeat(16), "ciphertext": bogus_ct,
                    "public": {}})],
    )
    .unwrap();
    let result = F::fold(&env_id, vec![c1, c2], None, None, None, None).unwrap();
    let doc = result.document.as_object().unwrap();
    assert!(!doc["secrets"].as_object().unwrap().contains_key("gh-token"));
    assert!(
        result
            .skipped
            .iter()
            .any(|(_, _, r)| r == "generation_unknown")
    );
}

#[test]
fn unwrappable_generation_excluded_and_does_not_break_scan_or_exec() {
    let (_tmp, ctx) = setup();
    let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
    let other = DeviceKey::generate();
    let gen1 = "1".repeat(16);
    let other_dek: Vec<u8> = (0..32u8).rev().collect();
    let rotate_wrap =
        envelope::wrap_dek(&other_dek, &env_id, &gen1, &other.record().unwrap()).unwrap();
    let mut wraps = Map::new();
    wraps.insert(other.fingerprint().unwrap(), rotate_wrap);
    let rotate_op = json!({"op": "dek.rotate", "generation_id": gen1, "wraps": wraps});
    let c2 = C::sign_commit(
        &owner,
        &env_id,
        2,
        "2000-0000",
        &BTreeMap::new(),
        vec![rotate_op],
    )
    .unwrap();
    let version_id = "2".repeat(16);
    let ct = envelope::encrypt_secret(
        &other_dek,
        &env_id,
        "gh-token",
        &version_id,
        SYNTHETIC_SECRET,
    )
    .unwrap();
    let c3 = C::sign_commit(
        &owner,
        &env_id,
        3,
        "3000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
                    "generation_id": gen1, "version_id": version_id, "ciphertext": ct, "public": {}})],
    )
    .unwrap();
    let c4 = C::sign_commit(
        &owner,
        &env_id,
        4,
        "4000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "secret.activate", "secret_id": "gh-token", "version_id": version_id})],
    )
    .unwrap();

    ctx.vault
        .put_secret(
            "local-secret",
            "api_key",
            b"synthetic-local-value",
            "demo",
            "dev",
            true,
        )
        .unwrap();

    let result = F::fold(&env_id, vec![c1, c2, c3, c4], None, None, None, None).unwrap();
    F::derive_local(
        &result,
        ctx.state,
        &ctx.policy,
        Some(ctx.audit),
        Some(&owner),
        Some(ctx.kms),
        None,
        None,
    )
    .unwrap();

    let doc = ctx
        .state
        .read_json("vault/secrets.json", Value::Null)
        .unwrap();
    assert!(
        !doc["secrets"]["gh-token"]["versions"]
            .as_object()
            .unwrap()
            .contains_key("2")
    );
    assert!(doc["secrets"]["gh-token"]["active_version"].is_null());

    let values = ctx.vault.values_for_trusted_scan().unwrap();
    assert!(
        values
            .iter()
            .any(|v| v.expose() == b"synthetic-local-value")
    );

    let err = ctx
        .vault
        .secret_for_trusted_use("gh-token", None)
        .unwrap_err();
    assert!(err.is(ErrorClass::NotFound));
}

// ---------------------------------------------------------- LocalIdConflict
#[test]
fn connection_create_referencing_undeclared_secret_skipped() {
    let (owner, env_id, _dek, c1) = new_env(None);
    let c2 = simple_connection_create(&env_id, &owner, 2, "2000-0000", "gh");
    let result = F::fold(&env_id, vec![c1, c2], None, None, None, None).unwrap();
    let doc = result.document.as_object().unwrap();
    assert!(!doc["connections"].as_object().unwrap().contains_key("gh"));
    assert!(
        result
            .skipped
            .iter()
            .any(|(_, _, r)| r == "secret_not_found")
    );
}

#[test]
fn local_connection_survives_colliding_shared_id() {
    let (_tmp, ctx) = setup();
    let target = HttpTarget::new("https", "private.example.com", 443, None, false).unwrap();
    let local = Connection::new(
        "gh",
        "demo",
        "dev",
        "my-private-github",
        "http",
        "local-secret",
        None,
        "",
        Some(target),
        Some(HttpAuth::bearer()),
        Some(HttpScope::new(Some(vec!["GET".into()]), Some(vec!["/".into()]), vec![]).unwrap()),
        None,
        None,
        0,
        "active",
        "",
        "",
    )
    .unwrap();
    ctx.policy.create_connection(local).unwrap();

    let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
    let c2 = simple_connection_create(&env_id, &owner, 2, "2000-0000", "gh");
    let result = F::fold(&env_id, vec![c1, c2], None, None, None, None).unwrap();
    F::derive_local(
        &result,
        ctx.state,
        &ctx.policy,
        Some(ctx.audit),
        Some(&owner),
        Some(ctx.kms),
        None,
        None,
    )
    .unwrap();

    let local = ctx.policy.get_connection("gh").unwrap();
    assert_eq!(local.service, "my-private-github");
    assert_eq!(local.http_target.unwrap().host, "private.example.com");
    let raw = ctx
        .state
        .read_json("policy/connections.json", Value::Null)
        .unwrap();
    assert!(raw["gh"].as_object().unwrap().get("shared_env").is_none());
}

#[test]
fn local_secret_survives_colliding_shared_secret_id() {
    let (_tmp, ctx) = setup();
    ctx.vault
        .put_secret(
            "gh-token",
            "api_key",
            b"synthetic-local-value",
            "demo",
            "dev",
            true,
        )
        .unwrap();
    let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
    let result = F::fold(&env_id, vec![c1], None, None, None, None).unwrap();
    F::derive_local(
        &result,
        ctx.state,
        &ctx.policy,
        Some(ctx.audit),
        Some(&owner),
        Some(ctx.kms),
        None,
        None,
    )
    .unwrap();
    let meta = ctx.vault.get_meta("gh-token").unwrap();
    assert_eq!(meta.project, "demo");
    let value = ctx.vault.secret_for_trusted_use("gh-token", None).unwrap();
    assert_eq!(value.expose(), b"synthetic-local-value");
}

// ------------------------------------------------------- DerivedDocOverwrite
#[test]
fn hand_edit_is_overwritten_on_next_fold() {
    let (_tmp, ctx) = setup();
    let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
    let c2 = simple_connection_create(&env_id, &owner, 2, "2000-0000", "gh");
    let result = derive(&ctx, &owner, vec![c1, c2]);

    let mut doc = ctx
        .state
        .read_json("policy/connections.json", Value::Null)
        .unwrap();
    doc["gh"]["service"] = json!("hand-edited-service");
    doc["gh"]["http_scope"]["methods"] = Value::Null;
    ctx.state
        .write_json("policy/connections.json", &doc)
        .unwrap();

    F::derive_local(
        &result,
        ctx.state,
        &ctx.policy,
        Some(ctx.audit),
        Some(&owner),
        Some(ctx.kms),
        None,
        None,
    )
    .unwrap();
    let restored = ctx
        .state
        .read_json("policy/connections.json", Value::Null)
        .unwrap();
    assert_eq!(restored["gh"]["service"], json!("github"));
    assert_eq!(restored["gh"]["http_scope"]["methods"], json!(["GET"]));
}

// ------------------------------------------------------- AuditCommitApplyCount
#[test]
fn count_is_commits_folded_not_ops_skipped() {
    let (_tmp, ctx) = setup();
    let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
    let user = DeviceKey::generate();
    let c2 = C::sign_commit(
        &owner,
        &env_id,
        2,
        "2000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "member.add", "device": user.record().unwrap().to_dict(), "name": "bob", "role": "user"})],
    )
    .unwrap();
    let bad = C::sign_commit(
        &user,
        &env_id,
        1,
        "3000-0000",
        &BTreeMap::new(),
        vec![
            json!({"op": "connection.disable", "id": "gh"}),
            json!({"op": "settings.update", "sync_interval_seconds": 5}),
        ],
    )
    .unwrap();
    let result = F::fold(&env_id, vec![c1, c2, bad], None, None, None, None).unwrap();
    assert_eq!(result.skipped.len(), 2);
    let total: i128 = result.vector.values().sum();
    assert_eq!(total, 3);
    F::derive_local(
        &result,
        ctx.state,
        &ctx.policy,
        Some(ctx.audit),
        Some(&owner),
        Some(ctx.kms),
        None,
        None,
    )
    .unwrap();
    let applies: Vec<Value> = ctx
        .audit
        .tail(50)
        .unwrap()
        .into_iter()
        .filter(|r| r.get("event").and_then(Value::as_str) == Some("team_commit_apply"))
        .collect();
    assert_eq!(applies.last().unwrap()["count"], json!(3));
}

// ------------------------------------------------------- DerivedProjectName
#[test]
fn placeholder_names_are_valid_and_listable() {
    let (_tmp, ctx) = setup();
    let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
    let result = F::fold(&env_id, vec![c1], None, None, None, None).unwrap();
    F::derive_local(
        &result,
        ctx.state,
        &ctx.policy,
        Some(ctx.audit),
        Some(&owner),
        Some(ctx.kms),
        None,
        None,
    )
    .unwrap();
    let meta = ctx.vault.get_meta("gh-token").unwrap();
    let (project, environment) = (
        meta.project.as_str().unwrap(),
        meta.environment.as_str().unwrap(),
    );
    projects::validate_name(project, "project").unwrap();
    projects::validate_name(environment, "environment").unwrap();
    assert!(!project.contains(':'));
    let listed = ctx
        .vault
        .list_secrets(Some(project), Some(environment))
        .unwrap();
    assert!(listed.iter().any(|m| m.id == "gh-token"));
}

// ----------------------------------------------- SharedSecretGenerationKey
#[test]
fn generation_key_decrypts_local_dek_does_not() {
    let (_tmp, ctx) = setup();
    let (owner, env_id, dek, c1) = new_env(None);
    let version_id = "1".repeat(16);
    let ct =
        envelope::encrypt_secret(&dek, &env_id, "gh-token", &version_id, SYNTHETIC_SECRET).unwrap();
    let c2 = C::sign_commit(
        &owner,
        &env_id,
        2,
        "2000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
                    "generation_id": GEN0, "version_id": version_id, "ciphertext": ct, "public": {}})],
    )
    .unwrap();
    let c3 = C::sign_commit(
        &owner,
        &env_id,
        3,
        "3000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "secret.activate", "secret_id": "gh-token", "version_id": version_id})],
    )
    .unwrap();
    let result = F::fold(&env_id, vec![c1, c2, c3], None, None, None, None).unwrap();
    F::derive_local(
        &result,
        ctx.state,
        &ctx.policy,
        Some(ctx.audit),
        Some(&owner),
        Some(ctx.kms),
        None,
        None,
    )
    .unwrap();
    let value = ctx.vault.secret_for_trusted_use("gh-token", None).unwrap();
    assert_eq!(value.expose(), SYNTHETIC_SECRET);
}

#[test]
fn values_for_trusted_scan_includes_shared_secret() {
    let (_tmp, ctx) = setup();
    let (owner, env_id, dek, c1) = new_env(None);
    let version_id = "1".repeat(16);
    let ct =
        envelope::encrypt_secret(&dek, &env_id, "gh-token", &version_id, SYNTHETIC_SECRET).unwrap();
    let c2 = C::sign_commit(
        &owner,
        &env_id,
        2,
        "2000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
                    "generation_id": GEN0, "version_id": version_id, "ciphertext": ct, "public": {}})],
    )
    .unwrap();
    let c3 = C::sign_commit(
        &owner,
        &env_id,
        3,
        "3000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "secret.activate", "secret_id": "gh-token", "version_id": version_id})],
    )
    .unwrap();
    let result = F::fold(&env_id, vec![c1, c2, c3], None, None, None, None).unwrap();
    F::derive_local(
        &result,
        ctx.state,
        &ctx.policy,
        Some(ctx.audit),
        Some(&owner),
        Some(ctx.kms),
        None,
        None,
    )
    .unwrap();
    let values = ctx.vault.values_for_trusted_scan().unwrap();
    assert!(values.iter().any(|v| v.expose() == SYNTHETIC_SECRET));
}

// --------------------------------------------------------------- NoLeakage
fn find_secret(haystack: &str, secrets: &[&[u8]]) -> Option<&'static str> {
    for secret in secrets {
        if let Ok(text) = std::str::from_utf8(secret)
            && haystack.contains(text)
        {
            return Some("plaintext");
        }
        if haystack.contains(&hex::encode(secret)) {
            return Some("hex");
        }
        if haystack.contains(&zeropw::pybase64::b64encode(secret)) {
            return Some("base64");
        }
    }
    None
}

fn find_secret_in_tree(dir: &Path, secrets: &[&[u8]]) -> Option<&'static str> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        let entries = match std::fs::read_dir(&path) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(bytes) = std::fs::read(&p)
                && let Ok(text) = std::str::from_utf8(&bytes)
                && let Some(hit) = find_secret(text, secrets)
            {
                return Some(hit);
            }
        }
    }
    None
}

#[test]
fn no_leak_across_commits_documents_snapshots_state() {
    let (_tmp, ctx) = setup();
    let (owner, env_id, dek, c1) = new_env(Some("gh-token"));
    let version_id = "9".repeat(16);
    let ct = envelope::encrypt_secret(&dek, &env_id, "gh-token-2", &version_id, SYNTHETIC_SECRET)
        .unwrap();
    let c2 = C::sign_commit(
        &owner,
        &env_id,
        2,
        "2000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "secret.put_version", "secret_id": "gh-token-2", "kind": "api_key",
                    "generation_id": GEN0, "version_id": version_id, "ciphertext": ct, "public": {}})],
    )
    .unwrap();
    let c3 = simple_connection_create(&env_id, &owner, 3, "3000-0000", "gh");
    let commits = vec![c1, c2, c3];

    let result = F::fold(&env_id, commits.clone(), None, None, None, None).unwrap();
    F::save_snapshot(ctx.state, &env_id, 1, &result).unwrap();
    F::derive_local(
        &result,
        ctx.state,
        &ctx.policy,
        Some(ctx.audit),
        Some(&owner),
        Some(ctx.kms),
        None,
        None,
    )
    .unwrap();

    let secrets_to_check: Vec<&[u8]> = vec![
        SYNTHETIC_SECRET,
        BOOTSTRAP_SECRET_VALUE,
        &dek,
        owner.sign_seed.expose(),
        owner.agree_private.expose(),
    ];
    for commit in &commits {
        let text = pyjson::dumps(&commit.to_dict(), pyjson::DumpOptions::plain()).unwrap();
        assert!(
            find_secret(&text, &secrets_to_check).is_none(),
            "leak in commit"
        );
    }
    let doc_text = pyjson::dumps(&result.document, pyjson::DumpOptions::compact_sorted()).unwrap();
    assert!(
        find_secret(&doc_text, &secrets_to_check).is_none(),
        "leak in document"
    );
    assert!(
        find_secret_in_tree(&ctx.state.path, &secrets_to_check).is_none(),
        "leak in state directory"
    );
}

// --------------------------------------------------------- H-7: seq gap
/// Port of `tests/test_team_fold.py::SignatureSeqEnvMismatchTestCase::
/// test_seq_gap_rejected` (finding H-7): a validly-signed commit whose
/// `author_seq` skips ahead of the store's contiguous sequence must be
/// rejected by `receive_commit` -- not merely by `CommitStore::append` in
/// isolation -- with a `rejected/` record on disk and a
/// `team_commit_rejected` audit entry carrying reason `team_seq_gap`.
/// Nothing exercised this path through `receive_commit` before.
#[test]
fn seq_gap_rejected_through_receive_commit() {
    let (_tmp, ctx) = setup();
    let (owner, env_id, _dek, c1) = new_env(None);
    let store = C::CommitStore::new(ctx.state, env_id.clone());
    assert_eq!(
        C::receive_commit(&store, &c1, 1_000_000, Some(ctx.audit)).unwrap(),
        "accepted"
    );

    // author_seq jumps from 1 straight to 5: a gap, not a duplicate.
    let skip_ahead = simple_connection_create(&env_id, &owner, 5, "2000-0000", "gh");
    assert_eq!(
        C::receive_commit(&store, &skip_ahead, 1_000_100, Some(ctx.audit)).unwrap(),
        "rejected"
    );

    // A `rejected/` record was written for the gapped commit.
    let rejected_dir = ctx.state.path.join(format!("team/{env_id}/rejected"));
    let rejected_files: Vec<_> = std::fs::read_dir(&rejected_dir)
        .expect("rejected dir exists")
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(rejected_files.len(), 1, "exactly one rejected record");
    let rejected_doc: Value =
        pyjson::loads(&std::fs::read_to_string(rejected_files[0].path()).unwrap()).unwrap();
    assert_eq!(rejected_doc["rejected_reason"], json!("team_seq_gap"));

    // The audit carries the same reason.
    let rejections: Vec<Value> = ctx
        .audit
        .tail(50)
        .unwrap()
        .into_iter()
        .filter(|r| r.get("event").and_then(Value::as_str) == Some("team_commit_rejected"))
        .collect();
    assert_eq!(rejections.len(), 1);
    assert_eq!(rejections[0]["reason"], json!("team_seq_gap"));
    assert_eq!(rejections[0]["result"], json!("denied"));
}

// ------------------------------------------------------------------ H-R2-6
/// Finding H-R2-6 (round 2): `derive_local`'s `count: i64 =
/// fold_result.vector.values().sum()` PANICKED (`attempt to add with
/// overflow`) once `FoldResult::vector` (widened to `i128` for
/// `commit.author_seq`) held two authors whose combined `author_seq` total
/// exceeded `i64::MAX` -- a panic on file-supplied data (`author_seq` is
/// read straight off a stored commit file by `all_commits()`), which
/// `rust/PORTING.md` forbids regardless of how it's reached. `count` was
/// widened to `i128` to fix it.
///
/// **Round-3 correction (finding H-R3-7):** the round-2 fix and this very
/// test only ever probed `i64::MAX`-sized values, which fit comfortably
/// inside `i128` and never actually exercised an `i128` overflow -- the
/// round-2 DEVIATIONS.md row's claim that this was "fixed" was therefore
/// premature: `.sum()`'s plain `+` still panicked for the REAL boundary,
/// two authors each at `author_seq == i128::MAX` (reachable from two real
/// commit files, since `author_seq` is read verbatim at `i128` width).
/// `derive_local` now accumulates with `saturating_add` instead of
/// `.sum()`, which cannot panic at any width; this test now pins the actual
/// `i128::MAX` boundary, not merely the previously-fixed `i64::MAX` one
/// (still exercised below too, since it remains a valid, smaller case).
#[test]
fn derive_local_does_not_panic_with_two_large_author_seq_totals() {
    let (_tmp, ctx) = setup();
    let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
    let mut result = F::fold(&env_id, vec![c1], None, None, None, None).unwrap();
    // Two authors, each holding an `author_seq` that alone fits `i64` but
    // whose SUM does not -- the round-2 fix's own shape, still valid.
    result
        .vector
        .insert("author-a".to_string(), i64::MAX as i128);
    result
        .vector
        .insert("author-b".to_string(), i64::MAX as i128);
    // Must not panic (the actual assertion): a plain `.unwrap()` propagates
    // any real error as a normal test failure, but a panic inside
    // `derive_local` would abort the test process instead.
    F::derive_local(
        &result,
        ctx.state,
        &ctx.policy,
        Some(ctx.audit),
        Some(&owner),
        Some(ctx.kms),
        None,
        None,
    )
    .unwrap();
    let applies: Vec<Value> = ctx
        .audit
        .tail(50)
        .unwrap()
        .into_iter()
        .filter(|r| r.get("event").and_then(Value::as_str) == Some("team_commit_apply"))
        .collect();
    assert_eq!(applies.len(), 1);
    // `result.vector` already carries the real owner's entry from folding
    // `c1` (`author_seq == 1`) alongside the two synthetic huge entries.
    let expected: i128 = 1 + 2 * (i64::MAX as i128);
    assert_eq!(
        applies[0]["count"],
        json!(expected),
        "count must carry the full i128 sum, not a clamped/overflowed i64"
    );
}

/// Finding H-R3-7's actual reachable boundary: two authors EACH at
/// `author_seq == i128::MAX` -- unlike the sibling test above (`i64::MAX`,
/// which fits comfortably inside `i128` and never overflows when summed),
/// adding two `i128::MAX` values together overflows `i128` itself. This is
/// exactly the case the round-2 DEVIATIONS.md row wrongly claimed was
/// already fixed. Must not panic, and the audited `count` must saturate at
/// `i128::MAX` (the closest representable value to the true,
/// arbitrary-precision Python sum) rather than wrapping or panicking.
#[test]
fn derive_local_saturates_instead_of_panicking_at_the_real_i128_max_boundary() {
    let (_tmp, ctx) = setup();
    let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
    let mut result = F::fold(&env_id, vec![c1], None, None, None, None).unwrap();
    result.vector.insert("author-a".to_string(), i128::MAX);
    result.vector.insert("author-b".to_string(), i128::MAX);
    F::derive_local(
        &result,
        ctx.state,
        &ctx.policy,
        Some(ctx.audit),
        Some(&owner),
        Some(ctx.kms),
        None,
        None,
    )
    .unwrap();
    let applies: Vec<Value> = ctx
        .audit
        .tail(50)
        .unwrap()
        .into_iter()
        .filter(|r| r.get("event").and_then(Value::as_str) == Some("team_commit_apply"))
        .collect();
    assert_eq!(applies.len(), 1);
    assert_eq!(
        applies[0]["count"],
        json!(i128::MAX),
        "count must saturate at i128::MAX rather than panic or wrap"
    );
}

// -------------------------------------------------------- DeriveVaultCorrupt
/// Finding H-R4-8: `_derive_vault`'s `secrets_doc = doc.setdefault("secrets",
/// {})` only installs `{}` when the key is ABSENT -- a PRESENT but non-dict
/// `vault/secrets.json["secrets"]` (a corrupt local vault) is returned
/// AS-IS, and the very next line's `secrets_doc.get(secret_id)` then raises
/// an uncaught `AttributeError`, confirmed here directly against real
/// `python3.12`, BEFORE `_derive_vault` ever reaches its own
/// `state.write_json(VAULT_DOC, doc)` call at the end -- the corrupt vault
/// file is left completely untouched. This used to silently substitute an
/// empty `Map` for the non-dict "secrets" field and then OVERWRITE it with a
/// fresh object built from only this fold's own secrets, destroying
/// whatever the field held. Confirms both that `derive_local` (the public
/// entry point `_derive_vault` is reached through) now fails closed with
/// `state_corrupt`, and that the on-disk vault file is byte-for-byte
/// unchanged afterwards.
#[test]
fn derive_vault_non_object_secrets_field_fails_closed_without_overwriting() {
    let (_tmp, ctx) = setup();
    let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
    let result = F::fold(&env_id, vec![c1], None, None, None, None).unwrap();

    let corrupt_vault = json!({"secrets": "not-an-object"});
    ctx.state.write_json(VAULT_DOC, &corrupt_vault).unwrap();

    let err = F::derive_local(
        &result,
        ctx.state,
        &ctx.policy,
        Some(ctx.audit),
        Some(&owner),
        Some(ctx.kms),
        None,
        None,
    )
    .expect_err("a non-object vault secrets field must fail closed, not overwrite it");
    assert!(err.is(ErrorClass::StateError));
    assert_eq!(err.reason, "state_corrupt");

    let after = ctx.state.read_json(VAULT_DOC, Value::Null).unwrap();
    assert_eq!(
        after, corrupt_vault,
        "the corrupt vault file must be left byte-for-byte unchanged, not overwritten"
    );

    // Cross-check directly against real python3.12's own `_derive_vault`:
    // same corrupt vault file, same document shape (one secret with at
    // least one version, so the loop that crashes actually runs), same
    // "left untouched" assertion.
    let document_text =
        pyjson::dumps(&result.document, pyjson::DumpOptions::compact_sorted()).unwrap();
    let corrupt_vault_text =
        pyjson::dumps(&corrupt_vault, pyjson::DumpOptions::compact_sorted()).unwrap();
    let script = format!(
        r#"
import json, tempfile
from pathlib import Path
from zeropw.store import StateDir
from zeropw.team import fold as F

with tempfile.TemporaryDirectory() as tmp:
    state = StateDir(Path(tmp) / "state")
    state.create()
    state.write_json("vault/secrets.json", json.loads({corrupt_vault_text:?}))
    document = json.loads({document_text:?})
    try:
        F._derive_vault(document, state, {env_id:?}, {{}}, None, project=None, environment=None)
        print("OK")
    except Exception as e:
        print(f"ERR {{type(e).__name__}}")
    print(json.dumps(state.read_json("vault/secrets.json", None), sort_keys=True))
"#,
    );
    let out = run_python(&script);
    let mut lines = out.lines();
    assert_eq!(
        lines.next().unwrap(),
        "ERR AttributeError",
        "real python3.12 must raise an uncaught AttributeError"
    );
    let py_vault_after: Value = pyjson::loads(lines.next().unwrap()).unwrap();
    assert_eq!(
        py_vault_after, corrupt_vault,
        "python3.12's own vault file must also be left untouched"
    );
}

// ----------------------------------------------------------- H-R6-1 ca_file
/// H-R6-1 (peer-reachable denial of sync): `HttpTarget.ca_file` has no
/// `__post_init__` check in Python at all -- confirmed directly against
/// real `python3.12` below, for a number, bool, list, dict and (as a
/// control) a string and `null`: `fold()` and `derive_local()` BOTH always
/// succeed, for every shape, and keep the value byte-identical in both the
/// folded environment document and the locally derived
/// `policy/connections.json`.
///
/// A real peer's signed `connection.create` op can therefore put a
/// non-string `ca_file` into a synced document. Both the folded document and
/// locally derived connection must retain every JSON shape byte-identically.
#[test]
fn derive_connections_preserves_every_ca_file_shape_like_python() {
    let shapes: [(&str, Value); 6] = [
        ("number", json!(5)),
        ("bool", json!(true)),
        ("list", json!(["not", "a", "path"])),
        ("dict", json!({"nested": "object"})),
        ("string", json!("/etc/ssl/certs/ca.pem")),
        ("null", Value::Null),
    ];
    for (label, ca_file) in shapes {
        let (_tmp, ctx) = setup();
        let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
        let bad_op = json!({"op": "connection.create", "id": "bad", "project": "demo", "environment": "dev",
                            "service": "api", "kind": "http", "secret_id": "gh-token", "secret_version": null,
                            "description": "", "http_target": {"scheme": "https", "host": "api.example.com",
                                                                "port": 443, "ca_file": ca_file},
                            "http_auth": {"mode": "bearer"},
                            "http_scope": {"methods": ["GET"], "path_prefixes": ["/x"]}});
        let c2 = C::sign_commit(
            &owner,
            &env_id,
            2,
            "2000-0000",
            &BTreeMap::new(),
            vec![bad_op],
        )
        .unwrap();
        let c3 = simple_connection_create(&env_id, &owner, 3, "3000-0000", "good");
        let commits = vec![c1.clone(), c2.clone(), c3.clone()];

        let result = F::fold(&env_id, commits.clone(), None, None, None, None).unwrap();
        assert_eq!(
            result.skipped,
            Vec::<(String, usize, String)>::new(),
            "{label}: fold() must not skip either op -- Python never rejects any ca_file shape"
        );
        assert_eq!(
            result.document["connections"]["bad"]["http_target"]["ca_file"], ca_file,
            "{label}: folded document must keep ca_file byte-identical (team/commit.rs's raw_ca_file passthrough)"
        );

        let derive_result = F::derive_local(
            &result,
            ctx.state,
            &ctx.policy,
            Some(ctx.audit),
            Some(&owner),
            Some(ctx.kms),
            None,
            None,
        );
        assert!(
            derive_result.is_ok(),
            "{label}: derive_local must succeed for every ca_file shape, matching Python -- got {derive_result:?}"
        );

        let local = ctx.state.read_json(CONNECTIONS, Value::Null).unwrap();
        assert!(
            local["good"].is_object(),
            "{label}: the sibling well-formed connection must still derive locally"
        );
        assert_eq!(
            local["bad"]["http_target"]["ca_file"], ca_file,
            "{label}: local derivation must keep ca_file byte-identical"
        );
        let reloaded = ctx.policy.get_connection("bad").unwrap().to_value();
        assert_eq!(
            reloaded["http_target"]["ca_file"], ca_file,
            "{label}: policy load/save must preserve ca_file byte-identically"
        );

        // Cross-check fold()+derive_local() against real python3.12: both
        // must succeed and keep ca_file byte-identical for EVERY shape,
        // including non-string values.
        let commits_json: Vec<Value> = commits.iter().map(Commit::to_dict).collect();
        let commits_text =
            pyjson::dumps(&json!(commits_json), pyjson::DumpOptions::compact_sorted()).unwrap();
        let script = format!(
            r#"
import json, tempfile
from pathlib import Path
from zeropw.context import Config, Context
from zeropw.team import commit as C
from zeropw.team import fold as F

raw = json.loads({commits_text:?})
commits = [C.Commit.from_dict(c) for c in raw]
env_id = {env_id:?}
result = F.fold(env_id, commits)
assert result.skipped == [], result.skipped
with tempfile.TemporaryDirectory() as tmp:
    ctx = Context.initialize(Path(tmp) / "state", "admin-pass-1", "recovery-pass-1", Config())
    ctx.projects.create("demo")
    F.derive_local(result, ctx.state, ctx.vault, ctx.policy, ctx.audit)
    connections = ctx.state.read_json("policy/connections.json")
print(json.dumps({{
    "document_ca_file": result.document["connections"]["bad"]["http_target"]["ca_file"],
    "local_bad_ca_file": connections.get("bad", {{}}).get("http_target", {{}}).get("ca_file", "__ABSENT__"),
    "local_good_present": "good" in connections,
}}, sort_keys=True))
"#,
        );
        let out = run_python(&script);
        let py: Value = pyjson::loads(out.trim()).unwrap();
        assert_eq!(
            py["document_ca_file"], ca_file,
            "{label}: python's own folded document must keep ca_file byte-identical too"
        );
        assert_eq!(
            py["local_good_present"],
            json!(true),
            "{label}: python's derive_local must also derive the sibling connection"
        );
        assert_eq!(
            py["local_bad_ca_file"], ca_file,
            "{label}: Python must derive the connection locally with ca_file byte-identical"
        );
    }
}

/// A minimal, non-quoting Python string literal for a temp-dir path. Every
/// path this test builds comes from `tempfile::TempDir`, never from
/// untrusted input, so this does not need `state_dir_cross_language.rs`'s
/// full `py_str_literal` escaping -- just enough to survive normal path
/// characters.
fn py_path_literal(p: &std::path::Path) -> String {
    format!(
        "'{}'",
        p.to_str()
            .expect("utf8 path")
            .replace('\\', "\\\\")
            .replace('\'', "\\'")
    )
}

/// Finding X-3 (HIGH): `pyjson::MAX_JSON_DEPTH` used to be 500, lowered from
/// 1,000 purely for `dumps`'s own stack safety -- but `loads` shares the
/// same bound, and Python's own `validate_op` places no depth limit at all
/// on a `secret.put_version` op's `public` field (`isinstance(public, dict)`
/// is the only check). A real Python node happily accepts, signs, folds and
/// derives such a commit -- `derive_local` -> `_derive_vault` ->
/// `StateDir.write_json` all succeed for `public` nested far deeper than
/// 500 -- and the resulting `vault/secrets.json` used to be completely
/// unreadable by this port (`StateError(state_corrupt)`), taking the WHOLE
/// node down (vault, policy, gateway, signer all key off the same
/// `Context::open`), not just the one deep secret. This is the real-world
/// shape PORTING.md's own invariant names explicitly: "A state directory
/// written by Python must load in Rust and vice versa".
///
/// Builds the state directory the same way a real peer would -- entirely in
/// Python, through the real API this finding's own repro used
/// (`validate_op`, `sign_commit`, `CommitStore.append`, `fold`,
/// `derive_local`), with `public` nested 600 deep (the finding's own
/// reported depth: comfortably past the OLD 500 cap this port used to
/// reject at, comfortably under the NEW cap this fix raises it to) -- then
/// confirms this port's `Context::open` + `Vault::list_secrets` +
/// `CommitStore::all_commits` all succeed against that same directory, with
/// no Rust code involved in writing it at all. Before this fix (`cargo test
/// --offline` on the pre-fix `MAX_JSON_DEPTH = 500`), `Context::open`
/// itself already failed with `state_corrupt` -- this test would not even
/// reach the `list_secrets`/`all_commits` assertions.
#[test]
fn python_written_state_dir_with_deeply_nested_secret_public_field_opens_in_rust() {
    let tmp = TempDir::new().expect("tempdir");
    let state_dir = tmp.path().join("state");

    let script = format!(
        r#"
import secrets
from zeropw.context import Config, Context
from zeropw.team import commit as C
from zeropw.team import envelope
from zeropw.team import fold as F
from zeropw.team.identity import DeviceKey

GEN0 = "0" * 16

def nested_public(depth):
    obj = {{}}
    for _ in range(depth):
        obj = {{"a": obj}}
    return obj

ctx = Context.initialize({state_dir}, {admin:?}, {recovery:?}, Config())
ctx.projects.create("demo")
owner = DeviceKey.create(ctx.state, ctx.kms)
env_id = C.new_env_id(owner.fingerprint)
dek = bytes(range(32))
wraps = {{owner.fingerprint: envelope.wrap_dek(dek, env_id, GEN0, owner.record)}}
op_init = {{"op": "env.init", "owner_device": owner.record.to_dict(), "owner_name": "alice",
           "generation_id": GEN0, "wraps": wraps}}
c1 = C.sign_commit(owner, env_id, 1, "1000-0000", {{}}, [op_init])

public = nested_public({depth})
version_id = secrets.token_hex(8)
ct = envelope.encrypt_secret(dek, env_id, "gh-token", version_id, b"secretvalue012345")
op2 = {{"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
       "generation_id": GEN0, "version_id": version_id, "ciphertext": ct, "public": public}}
C.validate_op(op2)  # the finding: no depth check at all on `public`
c2 = C.sign_commit(owner, env_id, 2, "2000-0000", {{}}, [op2])

store = C.CommitStore(ctx.state, env_id)
store.append(c1)
store.append(c2)

result = F.fold(env_id, store.all_commits())
assert result.skipped == [], result.skipped
F.derive_local(result, ctx.state, ctx.vault, ctx.policy, ctx.audit, device=owner)

import os
print(env_id)
print(os.path.getsize({state_dir} + "/vault/secrets.json"))
"#,
        state_dir = py_path_literal(&state_dir),
        admin = ADMIN,
        recovery = RECOVERY,
        depth = 600,
    );
    let out = run_python(&script);
    let mut lines = out.lines();
    let env_id = lines.next().expect("python printed env_id").to_string();
    let secrets_json_size: u64 = lines
        .next()
        .expect("python printed vault/secrets.json size")
        .parse()
        .expect("size is a number");
    assert!(
        secrets_json_size > 500_000,
        "sanity check: the deeply-nested public field should make vault/secrets.json large, got {secrets_json_size} bytes"
    );

    // No Rust code wrote any of this -- open it exactly the way a real node
    // resuming from disk would.
    let ctx = Context::open(&state_dir, Config::default(), clock::system())
        .expect("a state directory python's own real API wrote must open in rust (PORTING.md #2)");

    let secrets = ctx
        .vault
        .list_secrets(None, None)
        .expect("list_secrets must succeed against the python-written vault document");
    let gh_token = secrets
        .iter()
        .find(|s| s.id == "gh-token")
        .expect("the deeply-nested secret must be visible");
    assert_eq!(
        gh_token.versions.len(),
        1,
        "the one deeply-nested-public version must be derived locally, not silently dropped"
    );

    let store = C::CommitStore::new(ctx.state, env_id);
    let commits = store
        .all_commits()
        .expect("all_commits must see the peer's deep commit, not fall behind");
    assert_eq!(
        commits.len(),
        2,
        "both commits (env.init, secret.put_version with the deep public field) must be visible"
    );
}

// ---------------------------------------------------------------- X-2 value_prefix
/// Cross-unit finding X-2: unlike `ca_file` (which `HttpTarget::from_value`
/// still cannot represent, the documented H-R6-1 residual just above),
/// `HttpAuth::from_value`'s `value_prefix`/`basic_username` (for a
/// non-"basic" mode) now carry the real value through `raw_value_prefix`/
/// `raw_basic_username` -- so unlike `ca_file`, this shape does NOT get
/// skipped at all: both the "odd"-shaped connection and its well-formed
/// sibling derive locally, matching Python's `Connection.from_dict`, which
/// never fails on either field for these shapes.
///
/// Before this fix, `HttpAuth::from_value`'s `opt_str("value_prefix",
/// false)` rejected ANY non-string, non-null `value_prefix` regardless of
/// mode as `state_corrupt` -- and, measured directly (temporarily reverting
/// just this fix and re-running this exact test): `document_connection_
/// object`'s existing `Err(_) => continue` (the SAME per-item catch the
/// `ca_file` test above exercises, from H-R6-1) already limited the damage
/// to the one connection even before this fix -- the `local["good"]`
/// assertion below passed against the unfixed code too, only the
/// `local["odd"]` one failed. So, for this exact "two fresh connections in
/// one fold" shape, "NEITHER connection is derived" does not reproduce;
/// what actually reproduces is the SAME "unrepresentable connection
/// silently absent from the local derive" residual the `ca_file` test
/// documents. This test pins the STRONGER, correct outcome finding X-2
/// asks for regardless: `derive_local` must derive BOTH connections,
/// matching Python exactly, not silently drop the representable one.
#[test]
fn derive_connections_represents_container_value_prefix_for_every_mode_and_derives_both_connections()
 {
    let (_tmp, ctx) = setup();
    let (owner, env_id, _dek, c1) = new_env(Some("gh-token"));
    let odd_op = json!({"op": "connection.create", "id": "odd", "project": "demo", "environment": "dev",
                        "service": "api", "kind": "http", "secret_id": "gh-token", "secret_version": null,
                        "description": "", "http_target": {"scheme": "https", "host": "api.example.com", "port": 443},
                        "http_auth": {"mode": "bearer", "value_prefix": ["pre"]},
                        "http_scope": {"methods": ["GET"], "path_prefixes": ["/x"]}});
    let c2 = C::sign_commit(
        &owner,
        &env_id,
        2,
        "2000-0000",
        &BTreeMap::new(),
        vec![odd_op],
    )
    .unwrap();
    let c3 = simple_connection_create(&env_id, &owner, 3, "3000-0000", "good");
    let commits = vec![c1.clone(), c2.clone(), c3.clone()];

    let result = F::fold(&env_id, commits.clone(), None, None, None, None).unwrap();
    assert_eq!(
        result.skipped,
        Vec::<(String, usize, String)>::new(),
        "fold() must not skip either op -- Python never rejects value_prefix for any mode"
    );
    assert_eq!(
        result.document["connections"]["odd"]["http_auth"]["value_prefix"],
        json!(["pre"]),
        "folded document must keep value_prefix byte-identical (team/commit.rs's raw_value_prefix passthrough)"
    );

    F::derive_local(
        &result,
        ctx.state,
        &ctx.policy,
        Some(ctx.audit),
        Some(&owner),
        Some(ctx.kms),
        None,
        None,
    )
    .expect("derive_local must succeed -- neither connection's shape is rejected by Python");

    let local = ctx.state.read_json(CONNECTIONS, Value::Null).unwrap();
    assert!(
        local["good"].is_object(),
        "the sibling well-formed connection must derive locally"
    );
    // Finding X-2's original point (the same raw-passthrough shape as the
    // now-resolved ca_file case above):
    // "odd" is NOT a documented-absent residual -- it must derive too, with
    // the real value.
    assert_eq!(
        local["odd"]["http_auth"]["value_prefix"],
        json!(["pre"]),
        "the container value_prefix connection must ALSO derive locally, byte-identical to the fold document"
    );

    // Cross-check against real python3.12: both connections derive, and
    // value_prefix stays byte-identical throughout.
    let commits_json: Vec<Value> = commits.iter().map(Commit::to_dict).collect();
    let commits_text =
        pyjson::dumps(&json!(commits_json), pyjson::DumpOptions::compact_sorted()).unwrap();
    let script = format!(
        r#"
import json, tempfile
from pathlib import Path
from zeropw.context import Config, Context
from zeropw.team import commit as C
from zeropw.team import fold as F

raw = json.loads({commits_text:?})
commits = [C.Commit.from_dict(c) for c in raw]
env_id = {env_id:?}
result = F.fold(env_id, commits)
assert result.skipped == [], result.skipped
with tempfile.TemporaryDirectory() as tmp:
    ctx = Context.initialize(Path(tmp) / "state", "admin-pass-1", "recovery-pass-1", Config())
    ctx.projects.create("demo")
    F.derive_local(result, ctx.state, ctx.vault, ctx.policy, ctx.audit)
    connections = ctx.state.read_json("policy/connections.json")
print(json.dumps({{
    "document_value_prefix": result.document["connections"]["odd"]["http_auth"]["value_prefix"],
    "local_odd_value_prefix": connections.get("odd", {{}}).get("http_auth", {{}}).get("value_prefix", "__ABSENT__"),
    "local_good_present": "good" in connections,
    "local_odd_present": "odd" in connections,
}}, sort_keys=True))
"#,
    );
    let out = run_python(&script);
    let py: Value = pyjson::loads(out.trim()).unwrap();
    assert_eq!(py["document_value_prefix"], json!(["pre"]));
    assert_eq!(py["local_good_present"], json!(true));
    assert_eq!(
        py["local_odd_present"],
        json!(true),
        "python must derive BOTH connections -- confirming rust must too, not skip one"
    );
    assert_eq!(py["local_odd_value_prefix"], json!(["pre"]));
}
