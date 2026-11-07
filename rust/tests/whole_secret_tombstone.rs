//! M1 acceptance: synthetic credentials and local signed history only.
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tempfile::TempDir;
use zeropw::{
    clock,
    context::{Config, Context},
    policy::{Connection, HttpAuth, HttpScope, HttpTarget},
    team::{
        commit::{self, CommitStore},
        fold,
        identity::DeviceKey,
        membership, sync,
    },
    tombstone,
    vault::Vault,
};
const PASS: &str = "synthetic-administrator-pass";
const VALUE: &[u8] = b"synthetic-tombstone-credential-012345";
fn setup() -> (TempDir, Context) {
    let tmp = TempDir::new().unwrap();
    let ctx = Context::initialize(
        tmp.path().join("state"),
        PASS,
        "synthetic-independent-recovery",
        Config::default(),
        clock::system(),
    )
    .unwrap();
    ctx.projects.create("demo", &["dev"]).unwrap();
    for id in ["gone", "keep"] {
        ctx.vault
            .put_secret(id, "api_key", VALUE, "demo", "dev", true)
            .unwrap();
    }
    (tmp, ctx)
}
fn connection(id: &str, secret: &str) -> Connection {
    Connection::new(
        id,
        "demo",
        "dev",
        "synthetic",
        "http",
        secret,
        None,
        "",
        Some(HttpTarget::new("https", "controlled.example", 443, None, false).unwrap()),
        Some(HttpAuth::bearer()),
        Some(HttpScope::new(Some(vec!["GET".into()]), Some(vec!["/data".into()]), vec![]).unwrap()),
        None,
        None,
        0,
        "active",
        "",
        "",
    )
    .unwrap()
}
#[test]
fn private_delete_blocks_all_versions_reuse_and_stale_backup_across_restart() {
    let (tmp, ctx) = setup();
    ctx.vault
        .put_secret(
            "gone",
            "api_key",
            b"synthetic-second-version",
            "demo",
            "dev",
            false,
        )
        .unwrap();
    ctx.policy.create_principal("agent", "default").unwrap();
    for (id, secret) in [("dead", "gone"), ("live", "keep")] {
        ctx.policy
            .create_connection(connection(id, secret))
            .unwrap();
        ctx.policy
            .create_grant("agent", id, Some(3600), None)
            .unwrap();
    }
    let grants = ctx.policy.list_grants(None).unwrap();
    let backup = tmp.path().join("before.json");
    ctx.vault.backup(&backup).unwrap();
    assert!(ctx.admin.verify("wrong", None).is_err());
    let auth = ctx.admin.verify(PASS, None).unwrap();
    assert!(ctx.vault.delete_secret("gone", &auth).unwrap());
    assert!(!ctx.vault.delete_secret("gone", &auth).unwrap());
    for version in [None, Some(1.into()), Some(2.into())] {
        assert_eq!(
            ctx.vault
                .secret_for_trusted_use("gone", version)
                .err()
                .unwrap()
                .reason,
            "secret_deleted"
        );
    }
    assert_eq!(
        ctx.vault
            .put_secret("gone", "api_key", VALUE, "demo", "dev", true)
            .unwrap_err()
            .reason,
        "secret_deleted"
    );
    assert_eq!(
        ctx.vault
            .set_version_status("gone", &1.into(), "active")
            .unwrap_err()
            .reason,
        "secret_deleted"
    );
    for g in &grants {
        let d = ctx
            .policy
            .check_grant("agent", &g.connection, &g.id)
            .unwrap();
        assert_eq!(d.allowed, g.connection == "live");
    }
    let after = tmp.path().join("after.json");
    ctx.vault.backup(&after).unwrap();
    let archive = zeropw::pyjson::loads(&std::fs::read_to_string(&after).unwrap()).unwrap();
    assert!(archive["documents"].get(tombstone::PATH).is_some());
    Vault::restore(ctx.state, &backup, ctx.audit, Some(ctx.kms)).unwrap();
    assert!(ctx.policy.restore_pending().unwrap());
    for grant in &grants {
        assert_eq!(
            ctx.policy
                .check_grant("agent", &grant.connection, &grant.id)
                .unwrap()
                .reason,
            "restore_pending"
        );
    }
    // Even after the restore barrier is cleared, a restored old grant cannot
    // authenticate the deleted identity; the current deny ledger wins.
    ctx.policy.set_restore_pending(false).unwrap();
    for grant in &grants {
        assert_eq!(
            ctx.policy
                .check_grant("agent", &grant.connection, &grant.id)
                .unwrap()
                .allowed,
            grant.connection == "live"
        );
    }

    assert_eq!(
        ctx.vault
            .secret_for_trusted_use("gone", Some(1.into()))
            .err()
            .unwrap()
            .reason,
        "secret_deleted"
    );
    assert_eq!(
        ctx.vault
            .secret_for_trusted_use("keep", None)
            .unwrap()
            .expose(),
        VALUE
    );
    let reopened =
        Context::open(ctx.state.path.clone(), Config::default(), clock::system()).unwrap();
    assert_eq!(
        reopened
            .vault
            .secret_for_trusted_use("gone", None)
            .err()
            .unwrap()
            .reason,
        "secret_deleted"
    );
    reopened
        .vault
        .put_secret("recreated", "api_key", VALUE, "demo", "dev", true)
        .unwrap();
    assert_eq!(
        reopened
            .vault
            .secret_for_trusted_use("recreated", None)
            .unwrap()
            .expose(),
        VALUE
    );
}
#[test]
fn deletion_survives_share_compacted_prefix_late_put_and_fact_log_loss() {
    let (tmp, ctx) = setup();
    let env =
        membership::share_environment(&ctx, None, "demo", "dev", "owner", PASS).unwrap()["env_id"]
            .as_str()
            .unwrap()
            .to_owned();
    let before = membership::load_environment(&ctx, &env).unwrap();
    let total = before
        .vector
        .values()
        .fold(zeropw::pyint::PyInt::zero(), |a, b| {
            zeropw::pyint::PyInt(a.0 + &b.0)
        });
    fold::save_snapshot(ctx.state, &env, &total, &before).unwrap();
    let commits = CommitStore::new(ctx.state, &env).all_commits().unwrap();
    fold::save_snapshot_record(
        ctx.state,
        &env,
        &total,
        &fold::snapshot_record(None, &commits),
    )
    .unwrap();
    let fact = membership::author_fact(
        &ctx,
        None,
        &env,
        "secret_deleted",
        json!({"secret_id":"gone"}),
    )
    .unwrap();
    let parsed = sync::Fact::from_dict(&fact).unwrap();
    let (facts, _, _) = sync::load_facts(&ctx, &env).unwrap();
    assert_eq!(facts.tombstone_facts.len(), 1);
    let device = DeviceKey::load(ctx.state, ctx.kms).unwrap();
    let doc = membership::load_environment(&ctx, &env).unwrap().document;
    let generation = doc["dek"]["current"].as_str().unwrap();
    let wrapped = ctx
        .state
        .read_json(&format!("team/{env}/dek/{generation}.json"), Value::Null)
        .unwrap();
    let dek = ctx
        .kms
        .unwrap(&zeropw::kms::WrappedKey::from_dict(&wrapped).unwrap())
        .unwrap();
    let vid = "abababababababab";
    let ct = zeropw::team::envelope::encrypt_secret(
        dek.expose(),
        &env,
        "gone",
        vid,
        b"synthetic-late-offline-edit",
    )
    .unwrap();
    let seq =
        CommitStore::new(ctx.state, &env).vector().unwrap()[&device.fingerprint().unwrap()].clone();
    let late=commit::sign_commit(&device,&env,&seq+1,&format!("{}-0000",commit::now_ms()+10),&BTreeMap::new(),vec![json!({"op":"secret.put_version","secret_id":"gone","kind":"api_key","generation_id":generation,"version_id":vid,"ciphertext":ct,"public":{}}),json!({"op":"secret.activate","secret_id":"gone","version_id":vid})]).unwrap();
    let folded = fold::fold_with_snapshot(
        &env,
        commits.iter().cloned().chain([late.clone()]).collect(),
        ctx.state,
        Some(&facts),
        None,
    )
    .unwrap();
    assert!(folded.document["secrets"]["gone"]["active_version"].is_null());
    assert_eq!(
        folded.document["secrets"]["gone"]["versions"][vid]["status"],
        "revoked"
    );
    assert!(folded.skipped.iter().any(|(_, _, r)| r == "secret_deleted"));
    // Remove only ordinary prefix commits as compaction does; retained identity and
    // generation history still authorize facts. Old snapshot cannot resurrect.
    for c in &commits {
        if !c.ops.iter().any(|op| {
            ["env.init", "member.add", "dek.rotate"].contains(&op["op"].as_str().unwrap_or(""))
        }) {
            std::fs::remove_file(ctx.state.path.join(format!(
                "team/{env}/commits/{}/{}.json",
                c.author, c.author_seq
            )))
            .unwrap();
        }
    }
    std::fs::remove_file(ctx.state.path.join(format!("team/{env}/facts.jsonl"))).unwrap();
    let (reloaded, _, _) = sync::load_facts(&ctx, &env).unwrap();
    assert_eq!(reloaded.tombstone_facts.len(), 1);
    assert!(
        reloaded
            .tombstone_facts
            .contains_key(&parsed.hash().unwrap())
    );
    let result = fold::fold_with_snapshot(
        &env,
        CommitStore::new(ctx.state, &env).all_commits().unwrap(),
        ctx.state,
        Some(&reloaded),
        None,
    )
    .unwrap();
    assert!(result.document["secrets"]["gone"]["active_version"].is_null());
    assert_eq!(
        ctx.vault
            .secret_for_trusted_use("gone", Some(1.into()))
            .err()
            .unwrap()
            .reason,
        "secret_deleted"
    );
    assert_eq!(
        ctx.vault
            .secret_for_trusted_use("keep", None)
            .unwrap()
            .expose(),
        VALUE
    );
    let backup = tmp.path().join("shared.json");
    ctx.vault.backup(&backup).unwrap();
    assert!(sync::verify_fact(&parsed, &device.record().unwrap()));
}
#[test]
fn deleted_private_identity_is_transferred_when_environment_is_shared() {
    let (_tmp, ctx) = setup();
    ctx.vault
        .delete_secret("gone", &ctx.admin.verify(PASS, None).unwrap())
        .unwrap();
    let env =
        membership::share_environment(&ctx, None, "demo", "dev", "owner", PASS).unwrap()["env_id"]
            .as_str()
            .unwrap()
            .to_owned();
    let (facts, _, _) = sync::load_facts(&ctx, &env).unwrap();
    assert!(facts.deleted_secrets.contains("gone"));
    assert_eq!(
        ctx.vault
            .secret_for_trusted_use("gone", Some(1.into()))
            .err()
            .unwrap()
            .reason,
        "secret_deleted"
    );
}

#[test]
fn shared_tombstone_does_not_damage_a_colliding_unmarked_local_identity() {
    let (_tmp, ctx) = setup();
    ctx.projects.create("other", &["dev"]).unwrap();
    let env =
        membership::share_environment(&ctx, None, "other", "dev", "owner", PASS).unwrap()["env_id"]
            .as_str()
            .unwrap()
            .to_owned();
    let doc = membership::load_environment(&ctx, &env).unwrap().document;
    let gid = doc["dek"]["current"].as_str().unwrap();
    let wrapped = ctx
        .state
        .read_json(&format!("team/{env}/dek/{gid}.json"), Value::Null)
        .unwrap();
    let dek = ctx
        .kms
        .unwrap(&zeropw::kms::WrappedKey::from_dict(&wrapped).unwrap())
        .unwrap();
    let vid = "abababababababab";
    let ct = zeropw::team::envelope::encrypt_secret(
        dek.expose(),
        &env,
        "gone",
        vid,
        b"synthetic-remote-collision",
    )
    .unwrap();
    membership::author_commit(&ctx,None,&env,vec![json!({"op":"secret.put_version","secret_id":"gone","kind":"api_key","generation_id":gid,"version_id":vid,"ciphertext":ct,"public":{}}),json!({"op":"secret.activate","secret_id":"gone","version_id":vid})]).unwrap();
    membership::author_fact(
        &ctx,
        None,
        &env,
        "secret_deleted",
        json!({"secret_id":"gone"}),
    )
    .unwrap();
    assert_eq!(
        ctx.vault
            .secret_for_trusted_use("gone", None)
            .unwrap()
            .expose(),
        VALUE
    );
    assert!(
        ctx.state
            .read_json(zeropw::vault::VAULT_DOC, Value::Null)
            .unwrap()["secrets"]["gone"]["shared_env"]
            .is_null()
    );
}

#[test]
fn corrupted_deletion_ledger_fails_closed_before_authentication() {
    let (_tmp, ctx) = setup();
    let env =
        membership::share_environment(&ctx, None, "demo", "dev", "owner", PASS).unwrap()["env_id"]
            .as_str()
            .unwrap()
            .to_owned();
    membership::author_fact(
        &ctx,
        None,
        &env,
        "secret_deleted",
        json!({"secret_id":"gone"}),
    )
    .unwrap();
    let mut ledger = ctx.state.read_json(tombstone::PATH, Value::Null).unwrap();
    let fact = ledger["shared"][&env]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap();
    fact["target"]["secret_id"] = json!("keep");
    ctx.state.write_json(tombstone::PATH, &ledger).unwrap();
    assert_eq!(
        ctx.vault
            .secret_for_trusted_use("gone", Some(1.into()))
            .err()
            .unwrap()
            .reason,
        "state_corrupt"
    );
}

#[test]
fn missing_compatibility_metadata_cannot_downgrade_admitted_deletions() {
    let (_tmp, ctx) = setup();
    let env =
        membership::share_environment(&ctx, None, "demo", "dev", "owner", PASS).unwrap()["env_id"]
            .as_str()
            .unwrap()
            .to_owned();
    membership::author_fact(
        &ctx,
        None,
        &env,
        "secret_deleted",
        json!({"secret_id":"gone"}),
    )
    .unwrap();
    std::fs::remove_file(ctx.state.path.join(tombstone::PATH)).unwrap();
    let (facts, _, _) = sync::load_facts(&ctx, &env).unwrap();
    assert_eq!(facts.tombstone_facts.len(), 1);
    assert!(tombstone::support_required(ctx.state, &env).unwrap());
    assert_eq!(
        ctx.vault
            .secret_for_trusted_use("gone", Some(1.into()))
            .err()
            .unwrap()
            .reason,
        "secret_deleted"
    );
}

#[test]
fn backup_from_before_sharing_cannot_reclassify_deleted_identity_as_private() {
    let (tmp, ctx) = setup();
    ctx.policy.create_principal("agent", "default").unwrap();
    ctx.policy
        .create_connection(connection("restored", "gone"))
        .unwrap();
    let grant = ctx
        .policy
        .create_grant("agent", "restored", Some(3600), None)
        .unwrap();
    let backup = tmp.path().join("before-share.json");
    ctx.vault.backup(&backup).unwrap();
    let env =
        membership::share_environment(&ctx, None, "demo", "dev", "owner", PASS).unwrap()["env_id"]
            .as_str()
            .unwrap()
            .to_owned();
    membership::author_fact(
        &ctx,
        None,
        &env,
        "secret_deleted",
        json!({"secret_id":"gone"}),
    )
    .unwrap();
    Vault::restore(ctx.state, &backup, ctx.audit, Some(ctx.kms)).unwrap();
    assert_eq!(
        ctx.state
            .read_json(zeropw::vault::VAULT_DOC, Value::Null)
            .unwrap()["secrets"]["gone"]["shared_env"],
        env
    );
    // Loss of the derived marker alone cannot clear previously admitted
    // identity provenance retained independently with the tombstone.
    let mut unmarked = ctx
        .state
        .read_json(zeropw::vault::VAULT_DOC, Value::Null)
        .unwrap();
    unmarked["secrets"]["gone"]
        .as_object_mut()
        .unwrap()
        .remove("shared_env");
    ctx.state
        .write_json(zeropw::vault::VAULT_DOC, &unmarked)
        .unwrap();
    let folded = membership::load_environment(&ctx, &env).unwrap();
    let device = DeviceKey::load(ctx.state, ctx.kms).unwrap();
    fold::derive_local(
        &folded,
        ctx.state,
        &ctx.policy,
        Some(ctx.audit),
        Some(&device),
        Some(ctx.kms),
        Some("demo"),
        Some("dev"),
    )
    .unwrap();
    ctx.policy.set_restore_pending(false).unwrap();
    assert_eq!(
        ctx.policy
            .check_grant("agent", "restored", &grant.id)
            .unwrap()
            .reason,
        "secret_deleted"
    );
    assert_eq!(
        ctx.vault
            .secret_for_trusted_use("gone", Some(1.into()))
            .err()
            .unwrap()
            .reason,
        "secret_deleted"
    );
    assert_eq!(
        ctx.vault
            .secret_for_trusted_use("keep", None)
            .unwrap()
            .expose(),
        VALUE
    );
    let mut vault = ctx
        .state
        .read_json(zeropw::vault::VAULT_DOC, Value::Null)
        .unwrap();
    vault["secrets"].as_object_mut().unwrap().remove("gone");
    ctx.state
        .write_json(zeropw::vault::VAULT_DOC, &vault)
        .unwrap();
    assert_eq!(
        ctx.vault
            .put_secret("gone", "api_key", VALUE, "demo", "dev", true)
            .unwrap_err()
            .reason,
        "secret_deleted"
    );
}

#[test]
fn unmarked_local_collision_in_same_project_is_preserved() {
    let (_tmp, ctx) = setup();
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let fp = device.fingerprint().unwrap();
    let env = commit::new_env_id(&fp).unwrap();
    let gid = "0000000000000000";
    let dek = [7u8; 32];
    let wrap =
        zeropw::team::envelope::wrap_dek(&dek, &env, gid, &device.record().unwrap()).unwrap();
    let init=commit::sign_commit(&device,&env,1,"1000-0000",&BTreeMap::new(),vec![json!({"op":"env.init","owner_device":device.record().unwrap().to_dict(),"owner_name":"owner","generation_id":gid,"wraps":{fp:wrap}})]).unwrap();
    CommitStore::new(ctx.state, &env).append(&init).unwrap();
    sync::write_env_mapping(ctx.state, &env, "demo", "dev").unwrap();
    let vid = "abababababababab";
    let ct = zeropw::team::envelope::encrypt_secret(
        &dek,
        &env,
        "gone",
        vid,
        b"synthetic-remote-colliding-key",
    )
    .unwrap();
    membership::author_commit(&ctx,None,&env,vec![json!({"op":"secret.put_version","secret_id":"gone","kind":"api_key","generation_id":gid,"version_id":vid,"ciphertext":ct,"public":{}}),json!({"op":"secret.activate","secret_id":"gone","version_id":vid})]).unwrap();
    membership::author_commit(&ctx,None,&env,vec![json!({"op":"connection.create","id":"shared-connection","project":"demo","environment":"dev","service":"synthetic","kind":"http","secret_id":"gone","secret_version":null,"http_target":{"scheme":"https","host":"controlled.example","port":443},"http_auth":{"mode":"bearer"},"http_scope":{"methods":["GET"],"path_prefixes":["/data"]}})]).unwrap();
    ctx.policy.create_principal("agent", "default").unwrap();
    ctx.policy
        .create_connection(connection("private-connection", "gone"))
        .unwrap();
    let private = ctx
        .policy
        .create_grant("agent", "private-connection", Some(3600), None)
        .unwrap();
    let shared = ctx
        .policy
        .create_grant("agent", "shared-connection", Some(3600), None)
        .unwrap();
    membership::author_fact(
        &ctx,
        None,
        &env,
        "secret_deleted",
        json!({"secret_id":"gone"}),
    )
    .unwrap();
    assert!(
        ctx.policy
            .check_grant("agent", "private-connection", &private.id)
            .unwrap()
            .allowed
    );
    assert_eq!(
        ctx.policy
            .check_grant("agent", "shared-connection", &shared.id)
            .unwrap()
            .reason,
        "secret_deleted"
    );
    assert_eq!(
        ctx.vault
            .secret_for_trusted_use("gone", None)
            .unwrap()
            .expose(),
        VALUE
    );
    assert!(
        ctx.state
            .read_json(zeropw::vault::VAULT_DOC, Value::Null)
            .unwrap()["secrets"]["gone"]["shared_env"]
            .is_null()
    );
}

#[test]
fn restore_before_remote_delete_preserves_known_shared_ownership() {
    let (tmp, ctx) = setup();
    let backup = tmp.path().join("old-private.json");
    ctx.vault.backup(&backup).unwrap();
    let env =
        membership::share_environment(&ctx, None, "demo", "dev", "owner", PASS).unwrap()["env_id"]
            .as_str()
            .unwrap()
            .to_owned();
    Vault::restore(ctx.state, &backup, ctx.audit, Some(ctx.kms)).unwrap();
    assert_eq!(
        ctx.state
            .read_json(zeropw::vault::VAULT_DOC, Value::Null)
            .unwrap()["secrets"]["gone"]["shared_env"],
        env
    );
    membership::author_fact(
        &ctx,
        None,
        &env,
        "secret_deleted",
        json!({"secret_id":"gone"}),
    )
    .unwrap();
    ctx.policy.set_restore_pending(false).unwrap();
    assert_eq!(
        ctx.vault
            .secret_for_trusted_use("gone", Some(1.into()))
            .err()
            .unwrap()
            .reason,
        "secret_deleted"
    );
}
