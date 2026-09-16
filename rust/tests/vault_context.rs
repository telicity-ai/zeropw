//! Port of `tests/test_core_vault.py`: vault, KMS, admin re-authentication,
//! backup/restore and recovery, exercised through `Context` exactly like the
//! Python test suite (`Context.initialize`/`Context.open`, `FakeClock`).
//!
//! Kms cases already covered by `rust/src/kms.rs`'s own unit tests (per
//! `PORTING.md`'s "skip only what belongs to unit B's kms tests already
//! ported" instruction) are not re-ported here, except
//! `test_kms_unwrap_rejects_other_master_key`, which is really a `Vault`
//! integration case (it goes through `Context`/`Vault` document storage, not
//! just `LocalFileKms` in isolation).

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use tempfile::TempDir;

use zeropw::audit::RecordArgs;
use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::errors::ErrorClass;
use zeropw::kms::{Kms, LocalFileKms, WrappedKey};
use zeropw::policy::{self, Action, Connection, Grant, HttpAuth, HttpScope, HttpTarget};
use zeropw::projects;
use zeropw::vault::{self, AdminAuth, Vault};

const ADMIN: &str = "admin-passphrase-1";
const RECOVERY: &str = "recovery-passphrase-1";
const SYNTHETIC: &[u8] = b"synthetic-token-0123456789";
const FIXED_NOW: f64 = 1_700_000_000.0;

fn setup() -> (TempDir, Context) {
    let tmp = TempDir::new().expect("tempdir");
    let ctx = Context::initialize(
        tmp.path().join("state"),
        ADMIN,
        RECOVERY,
        Config::default(),
        clock::fixed(FIXED_NOW),
    )
    .expect("Context::initialize");
    ctx.projects
        .create("demo", projects::DEFAULT_ENVIRONMENTS)
        .expect("create demo project");
    (tmp, ctx)
}

fn walk_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read_dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            walk_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn all_state_text(state_dir: &Path) -> String {
    let mut files = Vec::new();
    walk_files(state_dir, &mut files);
    let mut out = String::new();
    for path in files {
        out.push_str(&String::from_utf8_lossy(
            &fs::read(&path).expect("read file"),
        ));
        out.push('\n');
    }
    out
}

fn plain_http_connection(id: &str, secret_version: Option<i64>) -> Connection {
    Connection::new(
        id,
        "demo",
        "dev",
        "fake",
        "http",
        "gh-token",
        secret_version,
        "",
        Some(HttpTarget::new("http", "127.0.0.1", 1, None, false).unwrap()),
        Some(HttpAuth::bearer()),
        Some(HttpScope::new(None, None, vec!["DELETE".to_string()]).unwrap()),
        None,
        None,
        0,
        "active",
        "",
        "",
    )
    .expect("valid connection")
}

/// Port of `VaultTestCase.http_setup`.
fn http_setup(ctx: &Context, cid: &str, secret_version: Option<i64>) -> Grant {
    if ctx.vault.list_secrets(None, None).unwrap().is_empty() {
        ctx.vault
            .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
            .unwrap();
    }
    if ctx.policy.get_principal("agent-1").is_err() {
        ctx.policy.create_principal("agent-1", "default").unwrap();
    }
    ctx.policy
        .create_connection(plain_http_connection(cid, secret_version))
        .unwrap();
    ctx.policy
        .create_grant("agent-1", cid, Some(3600), None)
        .unwrap()
}

#[test]
fn state_directory_permissions() {
    let (tmp, _ctx) = setup();
    let state = tmp.path().join("state");
    assert_eq!(
        fs::metadata(&state).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let mut files = Vec::new();
    walk_files(&state, &mut files);
    for path in files {
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o077,
            0,
            "{path:?}"
        );
    }
}

#[test]
fn put_and_trusted_use_never_persists_plaintext() {
    let (tmp, ctx) = setup();
    let version = ctx
        .vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    assert_eq!(version, 1);
    assert_eq!(
        ctx.vault.secret_for_trusted_use("gh-token", None).unwrap(),
        SYNTHETIC
    );
    assert!(
        !all_state_text(&tmp.path().join("state"))
            .contains(std::str::from_utf8(SYNTHETIC).unwrap())
    );
    let meta = ctx.vault.get_meta("gh-token").unwrap();
    assert_eq!(meta.active_version, Some(1));
    assert_eq!(meta.versions[0].status, "active");
    assert_eq!(meta.versions[0].public, json!({}));
}

#[test]
fn non_ssh_kinds_store_no_value_derived_metadata() {
    let (tmp, ctx) = setup();
    let low_entropy = b"synthetic-pw";
    for (secret_id, kind) in [("api", "api_key"), ("pw", "password"), ("env", "env_var")] {
        ctx.vault
            .put_secret(secret_id, kind, low_entropy, "demo", "dev", true)
            .unwrap();
        assert_eq!(
            ctx.vault.get_meta(secret_id).unwrap().versions[0].public,
            json!({})
        );
        assert_eq!(
            Vault::public_metadata(kind, low_entropy).unwrap(),
            json!({})
        );
    }
    let doc = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    let secrets = doc["secrets"].as_object().unwrap().clone();
    for entry in secrets.values() {
        for record in entry["versions"].as_object().unwrap().values() {
            assert_eq!(record["public"], json!({}));
            let keys: std::collections::BTreeSet<&str> = record
                .as_object()
                .unwrap()
                .keys()
                .map(|s| s.as_str())
                .collect();
            let expected: std::collections::BTreeSet<&str> =
                ["nonce", "ciphertext", "created_at", "status", "public"]
                    .into_iter()
                    .collect();
            assert_eq!(keys, expected);
        }
    }
    use sha2::{Digest, Sha256};
    let sha_hex = hex::encode(Sha256::digest(low_entropy));
    let secrets_json = serde_json::to_string(&Value::Object(secrets.clone())).unwrap();
    for needle in ["sha256_prefix", "\"length\"", &sha_hex[..8]] {
        assert!(
            !secrets_json.contains(needle),
            "unexpected {needle} in {secrets_json}"
        );
    }
    for entry in secrets.values() {
        for record in entry["versions"].as_object().unwrap().values() {
            for v in record.as_object().unwrap().values() {
                if let Some(n) = v.as_i64() {
                    assert_ne!(n, low_entropy.len() as i64);
                }
                if let Some(s) = v.as_str() {
                    assert_ne!(s, low_entropy.len().to_string());
                }
            }
        }
    }
    let text = all_state_text(&tmp.path().join("state"));
    assert!(!text.contains("sha256_prefix"));
    let backup = tmp.path().join("backup.json");
    ctx.vault.backup(&backup).unwrap();
    assert!(
        !fs::read_to_string(&backup)
            .unwrap()
            .contains("sha256_prefix")
    );
}

#[test]
fn versioning_and_status_transitions() {
    let (_tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", b"v1-synthetic", "demo", "dev", true)
        .unwrap();
    ctx.vault
        .put_secret("gh-token", "api_key", b"v2-synthetic", "demo", "dev", false)
        .unwrap();
    let meta = ctx.vault.get_meta("gh-token").unwrap();
    assert_eq!(meta.active_version, Some(1));
    assert_eq!(
        meta.versions
            .iter()
            .map(|v| v.status.as_str())
            .collect::<Vec<_>>(),
        vec!["active", "staged"]
    );
    assert_eq!(
        ctx.vault.secret_for_trusted_use("gh-token", None).unwrap(),
        b"v1-synthetic"
    );
    assert_eq!(
        ctx.vault
            .secret_for_trusted_use("gh-token", Some(2))
            .unwrap(),
        b"v2-synthetic"
    );
    ctx.vault
        .set_version_status("gh-token", 2, "active")
        .unwrap();
    let meta = ctx.vault.get_meta("gh-token").unwrap();
    assert_eq!(meta.active_version, Some(2));
    assert_eq!(
        meta.versions
            .iter()
            .map(|v| v.status.as_str())
            .collect::<Vec<_>>(),
        vec!["retired", "active"]
    );
    let err = ctx
        .vault
        .secret_for_trusted_use("gh-token", Some(1))
        .unwrap_err();
    assert!(err.is(ErrorClass::NotFound));
    ctx.vault
        .set_version_status("gh-token", 1, "revoked")
        .unwrap();
    let err = ctx
        .vault
        .set_version_status("gh-token", 1, "active")
        .unwrap_err();
    assert!(err.is(ErrorClass::InvalidInput));
    let err = ctx
        .vault
        .put_secret("gh-token", "password", b"x", "demo", "dev", true)
        .unwrap_err();
    assert!(err.is(ErrorClass::InvalidInput));
    let err = ctx
        .vault
        .put_secret("other", "api_key", b"x", "demo", "qa", true)
        .unwrap_err();
    assert!(err.is(ErrorClass::NotFound));
}

#[test]
fn reveal_requires_fresh_reauth_and_is_audited() {
    let (tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let err = ctx.admin.verify("wrong-passphrase", None).unwrap_err();
    assert!(err.is(ErrorClass::AuthFailed));
    let auth = ctx.admin.verify(ADMIN, Some((ctx.clock)())).unwrap();
    assert_eq!(
        ctx.vault
            .reveal("gh-token", None, &auth, Some((ctx.clock)()))
            .unwrap(),
        SYNTHETIC
    );
    let events: Vec<String> = ctx
        .audit
        .tail(100)
        .unwrap()
        .iter()
        .map(|r| r["event"].as_str().unwrap().to_string())
        .collect();
    assert!(events.contains(&"secret_reveal".to_string()));
    assert!(
        !all_state_text(&tmp.path().join("state"))
            .contains(std::str::from_utf8(SYNTHETIC).unwrap())
    );
    let stale = AdminAuth::new((ctx.clock)() - 120.0);
    let err = ctx
        .vault
        .reveal("gh-token", None, &stale, Some((ctx.clock)()))
        .unwrap_err();
    assert!(err.is(ErrorClass::AuthFailed));
    let events: Vec<String> = ctx
        .audit
        .tail(100)
        .unwrap()
        .iter()
        .map(|r| r["event"].as_str().unwrap().to_string())
        .collect();
    assert!(events.contains(&"secret_reveal_denied".to_string()));
    assert!(
        ctx.audit
            .alerts(1000)
            .unwrap()
            .iter()
            .any(|a| a["alert"] == "secret_reveal")
    );
}

#[test]
fn ssh_private_key_public_metadata_only() {
    let (tmp, ctx) = setup();
    let key = zeropw::sshwire::generate_ed25519_private_key("demo");
    let pem = key.to_openssh_private_key();
    ctx.vault
        .put_secret(
            "box-key",
            "ssh_private_key",
            pem.as_bytes(),
            "demo",
            "dev",
            true,
        )
        .unwrap();
    let meta = ctx.vault.get_meta("box-key").unwrap();
    assert_eq!(
        meta.versions[0].public["fingerprint"],
        json!(key.public.fingerprint())
    );
    assert!(
        meta.versions[0].public["public_key"]
            .as_str()
            .unwrap()
            .starts_with("ssh-ed25519 ")
    );
    let text = all_state_text(&tmp.path().join("state")).replace("BEGIN OPENSSH PRIVATE KEY", "");
    assert!(!text.contains("PRIVATE"));
    let err = ctx
        .vault
        .put_secret(
            "bad-key",
            "ssh_private_key",
            b"not a key",
            "demo",
            "dev",
            true,
        )
        .unwrap_err();
    assert!(err.is(ErrorClass::InvalidInput));
}

#[test]
fn kms_unwrap_rejects_other_master_key() {
    let (tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let other = LocalFileKms::create(&tmp.path().join("other.key"), "local-dev-kms-1").unwrap();
    let doc = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    let wrapped = WrappedKey::from_dict(&doc["dek"]).unwrap();
    let err = other.unwrap(&wrapped).unwrap_err();
    assert_eq!(err.name, "KmsError");
}

#[test]
fn backup_restore_blocks_until_ack_and_recovery_rewraps() {
    let (tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let token = ctx.policy.create_principal("agent-1", "default").unwrap();
    assert!(!token.is_empty());
    ctx.policy
        .create_connection(plain_http_connection("gh", None))
        .unwrap();
    let grant = ctx
        .policy
        .create_grant("agent-1", "gh", Some(3600), None)
        .unwrap();
    let backup = tmp.path().join("backup.json");
    let manifest = ctx.vault.backup(&backup).unwrap();
    assert!(
        !fs::read_to_string(&backup)
            .unwrap()
            .contains(std::str::from_utf8(SYNTHETIC).unwrap())
    );
    assert_eq!(
        fs::metadata(&backup).unwrap().permissions().mode() & 0o077,
        0
    );

    ctx.policy.revoke_grant(&grant.id).unwrap();
    Vault::restore(ctx.state, &backup, ctx.audit, None).unwrap();
    assert!(ctx.policy.restore_pending().unwrap());
    assert_eq!(
        ctx.policy
            .evaluate("agent-1", "gh", &Action::http("GET", "/"), None)
            .unwrap()
            .reason,
        "restore_pending"
    );
    assert_eq!(ctx.policy.get_grant(&grant.id).unwrap().status, "revoked");
    ctx.policy.set_restore_pending(false).unwrap();
    assert_eq!(
        ctx.policy
            .evaluate("agent-1", "gh", &Action::http("GET", "/"), None)
            .unwrap()
            .reason,
        "grant_revoked"
    );

    let tampered = tmp.path().join("tampered.json");
    let mut archive: Value = serde_json::from_str(&fs::read_to_string(&backup).unwrap()).unwrap();
    archive["documents"]["policy/grants.json"][grant.id.as_str()]["max_uses"] = Value::Null;
    archive["documents"]["policy/grants.json"][grant.id.as_str()]["expires_at"] = Value::Null;
    archive["documents"]["policy/grants.json"][grant.id.as_str()]["status"] =
        json!("tampered-active");
    fs::write(&tampered, serde_json::to_string(&archive).unwrap()).unwrap();
    let err = Vault::restore(ctx.state, &tampered, ctx.audit, None).unwrap_err();
    assert!(err.is(ErrorClass::StateError));

    let reopened = Context::open(
        tmp.path().join("state"),
        Config::default(),
        clock::fixed(FIXED_NOW),
    )
    .unwrap();
    assert_eq!(
        reopened
            .vault
            .secret_for_trusted_use("gh-token", None)
            .unwrap(),
        SYNTHETIC
    );
    assert_eq!(manifest["format"], json!("zeropw-backup-v1"));
}

#[test]
fn recover_rotates_kms_revokes_grants_and_handles() {
    let (tmp, mut ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    ctx.policy.create_principal("agent-1", "default").unwrap();
    ctx.policy
        .create_connection(plain_http_connection("gh", None))
        .unwrap();
    let grant = ctx
        .policy
        .create_grant("agent-1", "gh", Some(3600), None)
        .unwrap();
    let handle = ctx
        .handles
        .issue("agent-1", "gh", &grant.id, 1, 60, Some((ctx.clock)()))
        .unwrap();
    let old_key_id = ctx.kms.key_id().to_string();
    let err = ctx.recover("wrong-recovery-passphrase").unwrap_err();
    assert!(err.is(ErrorClass::AuthFailed));
    assert_eq!(
        ctx.vault.secret_for_trusted_use("gh-token", None).unwrap(),
        SYNTHETIC
    );
    let revoked = ctx.recover(RECOVERY).unwrap();
    assert_eq!(revoked, 1);
    assert_ne!(ctx.kms.key_id(), old_key_id);
    assert_eq!(
        ctx.vault.secret_for_trusted_use("gh-token", None).unwrap(),
        SYNTHETIC
    );
    assert_eq!(ctx.policy.get_grant(&grant.id).unwrap().status, "revoked");
    let err = ctx
        .handles
        .verify(&handle, Some((ctx.clock)()))
        .unwrap_err();
    assert!(err.is(ErrorClass::AuthFailed));
    let reopened = Context::open(
        tmp.path().join("state"),
        Config::default(),
        clock::fixed(FIXED_NOW),
    )
    .unwrap();
    assert_eq!(
        reopened
            .vault
            .secret_for_trusted_use("gh-token", None)
            .unwrap(),
        SYNTHETIC
    );
}

#[test]
fn new_active_version_rebinds_unpinned_connections_and_invalidates_handles() {
    let (_tmp, ctx) = setup();
    let grant = http_setup(&ctx, "gh", None);
    http_setup(&ctx, "pinned", Some(1));
    assert_eq!(grant.credential_version, Some(1));
    let before = ctx.policy.get_connection("gh").unwrap().policy_version;
    ctx.vault
        .put_secret(
            "gh-token",
            "api_key",
            b"synthetic-token-v2",
            "demo",
            "dev",
            true,
        )
        .unwrap();
    let after = ctx.policy.get_connection("gh").unwrap();
    assert_eq!(after.policy_version, before + 1);
    assert_eq!(
        ctx.policy.get_connection("pinned").unwrap().policy_version,
        1
    );
    let refreshed = ctx.policy.get_grant(&grant.id).unwrap();
    assert_eq!(refreshed.status, "active");
    assert_eq!(refreshed.policy_version, after.policy_version);
    assert_eq!(refreshed.credential_version, Some(2));
    let rebound: Vec<Value> = ctx
        .audit
        .tail(50)
        .unwrap()
        .into_iter()
        .filter(|r| r["event"] == "connection_update")
        .collect();
    assert_eq!(rebound.len(), 1);
    assert_eq!(rebound[0]["connection"], json!("gh"));
    assert_eq!(rebound[0]["policy_version"], json!(after.policy_version));
    assert_eq!(rebound[0]["detail"], json!("credential_version"));

    // A staged version, or a retire that leaves no active version, uses no
    // other credential: no bump.
    ctx.vault
        .put_secret(
            "gh-token",
            "api_key",
            b"synthetic-token-v3",
            "demo",
            "dev",
            false,
        )
        .unwrap();
    ctx.vault
        .set_version_status("gh-token", 2, "retired")
        .unwrap();
    assert_eq!(
        ctx.policy.get_connection("gh").unwrap().policy_version,
        after.policy_version
    );
    ctx.vault
        .set_version_status("gh-token", 3, "active")
        .unwrap();
    assert_eq!(
        ctx.policy.get_connection("gh").unwrap().policy_version,
        after.policy_version + 1
    );
    assert_eq!(
        ctx.policy.get_grant(&grant.id).unwrap().credential_version,
        Some(3)
    );
}

#[test]
fn restore_reapplies_revocations_rotates_handle_key_and_never_reopens_approvals() {
    let (tmp, ctx) = setup();
    let grant = http_setup(&ctx, "gh", None);
    let used = policy::approval_digest("agent-1", "gh", "DELETE", "/repos/used", b"");
    let archive_only =
        policy::approval_digest("agent-1", "gh", "DELETE", "/repos/archive-only", b"");
    for (digest, path) in [
        (&used, "/repos/used"),
        (&archive_only, "/repos/archive-only"),
    ] {
        ctx.policy
            .request_approval(digest, "agent-1", "gh", "DELETE", path)
            .unwrap();
        ctx.policy.approve(digest).unwrap();
    }
    let handle = ctx
        .handles
        .issue("agent-1", "gh", &grant.id, 1, 600, Some((ctx.clock)()))
        .unwrap();
    let backup = tmp.path().join("backup.json");
    ctx.vault.backup(&backup).unwrap();
    // After the backup: the approval is used, then everything is revoked
    // through the core API (not audited).
    assert!(
        ctx.policy
            .consume_approval(&used, "agent-1", "gh", None, None)
            .unwrap()
    );
    let mut control = ctx.state.read_json(policy::CONTROL, Value::Null).unwrap();
    control["approvals"]
        .as_object_mut()
        .unwrap()
        .remove(&archive_only);
    ctx.state.write_json(policy::CONTROL, &control).unwrap();
    ctx.policy.revoke_grant(&grant.id).unwrap();
    ctx.policy.disable_connection("gh").unwrap();
    ctx.policy.disable_principal("agent-1", true).unwrap();
    ctx.vault
        .set_version_status("gh-token", 1, "revoked")
        .unwrap();

    Vault::restore(ctx.state, &backup, ctx.audit, Some(ctx.kms)).unwrap();

    assert_eq!(ctx.policy.get_grant(&grant.id).unwrap().status, "revoked");
    assert_eq!(ctx.policy.get_connection("gh").unwrap().status, "disabled");
    assert_eq!(
        ctx.policy.get_principal("agent-1").unwrap().status,
        "disabled"
    );
    assert_eq!(
        ctx.vault.get_meta("gh-token").unwrap().versions[0].status,
        "revoked"
    );
    assert_eq!(ctx.vault.get_meta("gh-token").unwrap().active_version, None);
    let approvals = ctx.policy.list_approvals().unwrap();
    assert_eq!(approvals.get(&used).unwrap()["status"], json!("consumed"));
    assert!(!approvals.contains_key(&archive_only));
    let reapplied =
        ctx.state.read_json(policy::CONTROL, Value::Null).unwrap()["restore_reapplied"].clone();
    assert_eq!(
        reapplied,
        json!({"grants": 1, "principals": 1, "connections": 1, "secret_versions": 1, "approvals_dropped": 1})
    );
    ctx.policy.set_restore_pending(false).unwrap();
    assert!(
        !ctx.policy
            .consume_approval(&used, "agent-1", "gh", None, None)
            .unwrap()
    );
    // A new process reads the rotated handle key: a handle issued (or
    // leaked) before the restore is dead.
    let reopened = Context::open(
        tmp.path().join("state"),
        Config::default(),
        clock::fixed(FIXED_NOW),
    )
    .unwrap();
    let err = reopened
        .handles
        .verify(&handle, Some((ctx.clock)()))
        .unwrap_err();
    assert!(err.is(ErrorClass::AuthFailed));
    assert_eq!(
        Vault::reapply_revocations(ctx.state).unwrap(),
        HashMap::from([
            ("grants", 0),
            ("principals", 0),
            ("connections", 0),
            ("secret_versions", 0)
        ])
    );
}

/// Substitutes for the Python test's `state.write_json` monkeypatch (not
/// expressible on a Rust struct): forces the *second* document write inside
/// `Vault::restore`'s locked section to fail (by occupying
/// `policy/principals.json`'s path with a directory) and checks that the
/// control document's `restore_pending` -- written first, unconditionally --
/// already reached disk before the failure. This is the same invariant the
/// Python test names in its own comment ("restore_pending reaches the
/// current control document before any other document is overwritten").
#[test]
fn restore_writes_control_restore_pending_before_other_documents_even_on_failure() {
    let (tmp, ctx) = setup();
    http_setup(&ctx, "gh", None);
    let backup = tmp.path().join("backup.json");
    ctx.vault.backup(&backup).unwrap();
    let principals_path = tmp.path().join("state/policy/principals.json");
    fs::remove_file(&principals_path).unwrap();
    fs::create_dir(&principals_path).unwrap();
    let err = Vault::restore(ctx.state, &backup, ctx.audit, None).unwrap_err();
    assert!(err.is(ErrorClass::StateError));
    let control = ctx.state.read_json(policy::CONTROL, Value::Null).unwrap();
    assert_eq!(control["restore_pending"], json!(true));
}

#[test]
fn restore_replays_audit_revocations_when_the_ledger_is_missing() {
    let (tmp, ctx) = setup();
    let grant = http_setup(&ctx, "gh", None);
    let backup = tmp.path().join("backup.json");
    ctx.vault.backup(&backup).unwrap();
    ctx.policy.revoke_grant(&grant.id).unwrap();
    ctx.audit
        .record(
            "grant_revoke",
            RecordArgs {
                caller: Some("admin"),
                connection: Some("gh"),
                result: Some("ok"),
                extra: vec![("grant", json!(grant.id))],
                ..Default::default()
            },
        )
        .unwrap();
    fs::remove_file(tmp.path().join("state").join(policy::REVOCATIONS)).unwrap();
    Vault::restore(ctx.state, &backup, ctx.audit, Some(ctx.kms)).unwrap();
    assert_eq!(ctx.policy.get_grant(&grant.id).unwrap().status, "revoked");
}

#[test]
fn open_requires_existing_state() {
    let (tmp, _ctx) = setup();
    let err = Context::open(
        tmp.path().join("missing"),
        Config::default(),
        clock::system(),
    )
    .err()
    .unwrap();
    assert!(err.is(ErrorClass::StateError));
    let err = Context::initialize(
        tmp.path().join("state"),
        ADMIN,
        RECOVERY,
        Config::default(),
        clock::system(),
    )
    .err()
    .unwrap();
    assert!(err.is(ErrorClass::StateError));
}

#[test]
fn secret_value_limits() {
    let (_tmp, ctx) = setup();
    let err = ctx
        .vault
        .put_secret("x", "api_key", b"", "demo", "dev", true)
        .unwrap_err();
    assert!(err.is(ErrorClass::InvalidInput));
    let big = vec![b'a'; 64 * 1024 + 1];
    let err = ctx
        .vault
        .put_secret("x", "api_key", &big, "demo", "dev", true)
        .unwrap_err();
    assert!(err.is(ErrorClass::InvalidInput));
    let err = ctx
        .vault
        .put_secret("x", "card", b"a", "demo", "dev", true)
        .unwrap_err();
    assert!(err.is(ErrorClass::InvalidInput));
    let err = ctx
        .vault
        .put_secret("Bad Id", "api_key", b"a", "demo", "dev", true)
        .unwrap_err();
    assert!(err.is(ErrorClass::InvalidInput));
}
