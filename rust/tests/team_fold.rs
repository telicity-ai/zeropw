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

use serde_json::{Map, Value, json};
use tempfile::TempDir;

use zeropw::context::{Config, Context};
use zeropw::errors::ErrorClass;
use zeropw::policy::{Connection, HttpAuth, HttpScope, HttpTarget};
use zeropw::projects;
use zeropw::team::commit::{self as C, Commit};
use zeropw::team::envelope;
use zeropw::team::fold::{self as F};
use zeropw::team::identity::DeviceKey;
use zeropw::{clock, pyjson};

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
    projects::validate_name(&meta.project, "project").unwrap();
    projects::validate_name(&meta.environment, "environment").unwrap();
    assert!(!meta.project.contains(':'));
    let listed = ctx
        .vault
        .list_secrets(Some(&meta.project), Some(&meta.environment))
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
