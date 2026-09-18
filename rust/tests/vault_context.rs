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

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
    // Explicit `socket_dir`/`run_dir` under this test's own `TempDir` (unit G's fixtures already
    // do this, e.g. `signer_oracle.rs`'s `build_fixture`): `Config::default()` leaves both `None`,
    // which `Context::initialize` fills in with fresh private directories under the *system* temp
    // dir instead of this test's own, disposable one.
    let config = Config {
        socket_dir: Some(tmp.path().join("ctx-sockets")),
        run_dir: Some(tmp.path().join("ctx-run")),
        ..Config::default()
    };
    let ctx = Context::initialize(
        tmp.path().join("state"),
        ADMIN,
        RECOVERY,
        config,
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
        ctx.vault
            .secret_for_trusted_use("gh-token", None)
            .unwrap()
            .expose(),
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

/// Finding E-3: `secret_for_trusted_use`/`reveal`/`values_for_trusted_scan`
/// must return `SecretBytes` (zeroised on drop, redacted `Debug`, no
/// `Serialize`), not a bare `Vec<u8>` -- the highest-value secret material in
/// the system should never be printable or JSON-serializable by accident.
#[test]
fn secret_for_trusted_use_and_reveal_return_redacted_secret_bytes() {
    let (_tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let secret = ctx.vault.secret_for_trusted_use("gh-token", None).unwrap();
    let debug = format!("{secret:?}");
    let plaintext = std::str::from_utf8(SYNTHETIC).unwrap();
    assert!(
        !debug.contains(plaintext),
        "Debug output must not contain the plaintext secret: {debug}"
    );
    assert!(debug.contains("redacted"), "Debug output was: {debug}");
    assert_eq!(secret.expose(), SYNTHETIC);

    let auth = ctx.admin.verify(ADMIN, Some((ctx.clock)())).unwrap();
    let revealed = ctx
        .vault
        .reveal("gh-token", None, &auth, Some((ctx.clock)()))
        .unwrap();
    assert!(!format!("{revealed:?}").contains(plaintext));

    let scanned = ctx.vault.values_for_trusted_scan().unwrap();
    assert_eq!(scanned.len(), 1);
    assert!(!format!("{:?}", scanned[0]).contains(plaintext));
    assert_eq!(scanned[0].expose(), SYNTHETIC);
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
        ctx.vault
            .secret_for_trusted_use("gh-token", None)
            .unwrap()
            .expose(),
        b"v1-synthetic"
    );
    assert_eq!(
        ctx.vault
            .secret_for_trusted_use("gh-token", Some(2))
            .unwrap()
            .expose(),
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
            .unwrap()
            .expose(),
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
            .unwrap()
            .expose(),
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
        ctx.vault
            .secret_for_trusted_use("gh-token", None)
            .unwrap()
            .expose(),
        SYNTHETIC
    );
    let revoked = ctx.recover(RECOVERY).unwrap();
    assert_eq!(revoked, 1);
    assert_ne!(ctx.kms.key_id(), old_key_id);
    assert_eq!(
        ctx.vault
            .secret_for_trusted_use("gh-token", None)
            .unwrap()
            .expose(),
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
            .unwrap()
            .expose(),
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
        vec![
            ("grants", 0),
            ("principals", 0),
            ("connections", 0),
            ("secret_versions", 0)
        ]
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

/// Finding E-R2-4a: `doc["secrets"].get(secret_id)` in Python returns `None`
/// both when the key is absent *and* when it maps to a JSON `null` (`dict.get`
/// doesn't distinguish the two), so `secret_for_trusted_use` must raise the
/// documented `NotFound("secret_not_found")` for `"secrets": {"ghost": null}`,
/// not fall through to the generic `state_corrupt` the version-record lookups
/// use for a genuinely malformed (non-null, non-dict) entry.
#[test]
fn secret_for_trusted_use_treats_explicit_null_secret_entry_as_absent() {
    let (_tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let mut doc = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    doc["secrets"]
        .as_object_mut()
        .unwrap()
        .insert("ghost".to_string(), Value::Null);
    ctx.state.write_json(vault::VAULT_DOC, &doc).unwrap();

    // `secret_for_trusted_use`'s own up-front `doc["secrets"].get(secret_id)` check must treat
    // the null entry as absent *before* `resolve_version`/`get_meta`/`list_secrets` ever run --
    // those iterate every secret id and would themselves hit the null entry (`as_obj` failing on
    // `Value::Null`), surfacing `state_corrupt` instead. This matches Python's own `list_secrets`,
    // which raises an uncaught `TypeError` for the same null entry when asked about *any* secret
    // id (DEVIATIONS.md row 51, unaffected by this fix) -- only the up-front existence check on
    // `secret_id` itself is fixed here.
    let err = ctx.vault.secret_for_trusted_use("ghost", None).unwrap_err();
    assert!(err.is(ErrorClass::NotFound));
    assert_eq!(err.reason.to_string(), "secret_not_found");
}

/// Finding E-R2-4b: `Vault._decrypt_shared`'s `env_id = str(entry["shared_env"])`,
/// `generation_id = str(entry["generation"])`, `version_id = str(entry["version_id"])`
/// coerce a *present* field of any JSON type with Python's `str(...)` -- only a
/// missing key is `secret_corrupt`. A well-typed-but-non-string field (e.g. the
/// JSON number `5`) must therefore still decrypt successfully, not be rejected.
#[test]
fn decrypt_shared_coerces_non_string_scalar_fields_like_pythons_str() {
    let (_tmp, ctx) = setup();
    let dek = [7u8; 32];
    let wrapped = ctx.kms.wrap(&dek).unwrap();
    ctx.state
        .write_json("team/5/dek/7.json", &wrapped.to_dict())
        .unwrap();

    let mut version_record =
        zeropw::team::envelope::encrypt_secret(&dek, "5", "gh-token", "3", SYNTHETIC).unwrap();
    version_record.insert("status".into(), json!("active"));
    version_record.insert("created_at".into(), json!("2024-01-01T00:00:00Z"));
    version_record.insert("public".into(), json!({}));
    // Numbers, not strings -- Python's `str(entry["shared_env"])` etc. still
    // coerce these to "5"/"7"/"3", matching the path just written above.
    version_record.insert("shared_env".into(), json!(5));
    version_record.insert("generation".into(), json!(7));
    version_record.insert("version_id".into(), json!(3));

    let mut doc = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    doc["secrets"].as_object_mut().unwrap().insert(
        "gh-token".to_string(),
        json!({
            "project": "demo",
            "environment": "dev",
            "kind": "env_var",
            "active_version": 1,
            "versions": {"1": version_record},
        }),
    );
    ctx.state.write_json(vault::VAULT_DOC, &doc).unwrap();

    let value = ctx.vault.secret_for_trusted_use("gh-token", None).unwrap();
    assert_eq!(value.expose(), SYNTHETIC);
}

/// Finding E-R3-2: a `create_private_dir` random suffix 8 characters longer
/// than Python's own `tempfile.mkdtemp` suffix silently defeated the
/// signer's `choose_socket_dir` probe (`candidate.join("s" * 24)` must fit
/// under `MAX_UNIX_PATH` = 100): on this machine, the over-long Rust
/// basename made that probe 105 bytes (Python's equivalent probe is 97),
/// so `choose_socket_dir` discarded `ctx.config.socket_dir` entirely and
/// fell back to an unrelated `zpws-` temp dir that `Context` neither owns
/// nor removes. With the suffix length fixed to match Python, the signer
/// must actually use the configured directory under this machine's default
/// `TMPDIR`, not silently fall back.
#[test]
fn signer_socket_dir_matches_configured_directory_under_this_machines_default_tmpdir() {
    let tmp = TempDir::new().expect("tempdir");
    // Deliberately `Config::default()` (not an explicit `socket_dir`/`run_dir` under `tmp`, unlike
    // every other fixture in this crate): the whole point of this test is to exercise
    // `Context::apply_config_defaults`'s *default* private-tempdir codepath (the one that creates
    // `zeropw-sockets-*`/`zeropw-runs-*` under the real system temp dir) and confirm the signer
    // actually binds in the directory `Context` created rather than silently falling back. `ctx` is
    // an owned `Arc<Context>` (finding E-R7-1: `signer::install` no longer requires
    // `&'static Context`/`Box::leak`), so when `ctx` and `manager` both go out of scope at the end
    // of this test, the last `Arc<Context>` clone drops and `Context::close()` removes those two
    // default directories for real -- unlike the `Box::leak` this test used to reach for just to
    // satisfy `install`'s old `'static` bound, which left both directories on disk forever.
    let ctx: Arc<Context> = Arc::new(
        Context::initialize(
            tmp.path().join("state"),
            ADMIN,
            RECOVERY,
            Config::default(),
            clock::fixed(FIXED_NOW),
        )
        .expect("Context::initialize"),
    );
    let configured = ctx
        .config
        .socket_dir
        .clone()
        .expect("apply_config_defaults always sets socket_dir");
    let manager = zeropw::signer::install(Arc::clone(&ctx), None).expect("signer::install");
    assert_eq!(
        manager.socket_dir(),
        configured.as_path(),
        "signer must bind in the Context-owned socket_dir, not fall back to an unrelated temp dir"
    );
}

// ------------------------------------------------------- round-5 findings (E-R5-*)

/// A JSON value nested `depth` array levels deep (each level adds exactly 1
/// to `pyjson::value_depth_within`'s count), used by the `E-R5-8` tests
/// below to probe the archive's extra two levels of wrapping.
fn nested_array(depth: usize) -> Value {
    let mut v = Value::Null;
    for _ in 0..depth {
        v = Value::Array(vec![v]);
    }
    v
}

/// Finding E-R5-1: `put_secret`'s `doc["secrets"].get(secret_id)` first
/// indexes `doc["secrets"]` itself, direct indexing -- a missing or
/// wrong-typed `secrets` field raises an uncaught `KeyError`/`TypeError`
/// (state_corrupt) and commits nothing. A previous version of this port's
/// `.entry("secrets").or_insert_with(|| json!({}))` silently created the
/// missing key and wrote a brand-new secret into it instead.
#[test]
fn put_secret_missing_secrets_key_is_state_corrupt_not_silently_created() {
    let (_tmp, ctx) = setup();
    let mut doc = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    doc.as_object_mut().unwrap().remove("secrets");
    ctx.state.write_json(vault::VAULT_DOC, &doc).unwrap();

    let err = ctx
        .vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap_err();
    assert!(err.is(ErrorClass::StateError));
    assert_eq!(err.reason.to_string(), "state_corrupt");

    // Nothing committed: `secrets` is still missing, not silently created with the new secret in
    // it.
    let doc_after = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    assert!(doc_after.get("secrets").is_none());
}

/// Same finding, the wrong-type (rather than missing-key) half: a present
/// `secrets` field of the wrong JSON type is also `state_corrupt`, not a
/// silently-created fresh object either.
#[test]
fn put_secret_secrets_field_of_wrong_type_is_state_corrupt() {
    let (_tmp, ctx) = setup();
    let mut doc = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    doc["secrets"] = json!("not-an-object");
    ctx.state.write_json(vault::VAULT_DOC, &doc).unwrap();

    let err = ctx
        .vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap_err();
    assert!(err.is(ErrorClass::StateError));
    assert_eq!(err.reason.to_string(), "state_corrupt");
}

/// Finding E-R5-2: `reapply_revocations`'s `entry.get("versions", {}).get(
/// str(version))` has no `.get` method at all once `versions` is present but
/// not a dict -- Python's own `.get(...)` call raises an uncaught
/// `AttributeError`, aborting the whole call (and therefore `Vault::restore`)
/// rather than silently leaving the revoked secret version un-revoked.
#[test]
fn reapply_revocations_aborts_when_versions_field_is_not_an_object() {
    let (_tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    ctx.vault
        .set_version_status("gh-token", 1, "revoked")
        .unwrap();

    let mut doc = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    doc["secrets"]["gh-token"]["versions"] = json!(["not", "an", "object"]);
    ctx.state.write_json(vault::VAULT_DOC, &doc).unwrap();

    let err = Vault::reapply_revocations(ctx.state).unwrap_err();
    assert!(err.is(ErrorClass::StateError));
    assert_eq!(err.reason.to_string(), "state_corrupt");
}

/// Same finding, the *missing*-key half (which must keep skipping, not
/// error): Python's `.get("versions", {})` falls back to `{}` for an absent
/// key, whose own `.get(...)` is simply `None` -- no exception, no change.
#[test]
fn reapply_revocations_skips_silently_when_versions_key_is_entirely_missing() {
    let (_tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    ctx.vault
        .set_version_status("gh-token", 1, "revoked")
        .unwrap();

    let mut doc = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    doc["secrets"]["gh-token"]
        .as_object_mut()
        .unwrap()
        .remove("versions");
    ctx.state.write_json(vault::VAULT_DOC, &doc).unwrap();

    let counts = Vault::reapply_revocations(ctx.state).unwrap();
    assert_eq!(
        counts
            .iter()
            .find(|(k, _)| *k == "secret_versions")
            .map(|(_, v)| *v),
        Some(0)
    );
}

/// Finding E-R5-4: `set_version_status`'s activate branch compares a stored
/// `active_version` against the version being activated with Python's
/// numeric `==` (`True == 1`), not JSON-shape equality. Re-activating the
/// same version that is already (numerically) active must be a no-op
/// success, not a `state_corrupt` from trying to "retire" a `versions["True"]`
/// key that doesn't exist.
#[test]
fn set_version_status_reactivating_bool_true_active_version_as_one_succeeds() {
    let (_tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let mut doc = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    doc["secrets"]["gh-token"]["active_version"] = json!(true);
    ctx.state.write_json(vault::VAULT_DOC, &doc).unwrap();

    ctx.vault
        .set_version_status("gh-token", 1, "active")
        .expect(
            "Python: `previous != version` (`True != 1`) is False, retire is skipped, call succeeds",
        );

    let doc_after = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    assert_eq!(doc_after["secrets"]["gh-token"]["active_version"], json!(1));
    assert_eq!(
        doc_after["secrets"]["gh-token"]["versions"]["1"]["status"],
        json!("active")
    );
}

/// Same finding, the retire-clears-to-null direction: an `active_version`
/// stored as the integral float `1.0` must still be recognised as "version
/// 1 is active" and cleared to `null` when that version is explicitly
/// retired.
#[test]
fn set_version_status_retiring_clears_active_version_stored_as_integral_float() {
    let (_tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let mut doc = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    doc["secrets"]["gh-token"]["active_version"] = json!(1.0);
    ctx.state.write_json(vault::VAULT_DOC, &doc).unwrap();

    ctx.vault
        .set_version_status("gh-token", 1, "retired")
        .unwrap();

    let doc_after = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    assert!(doc_after["secrets"]["gh-token"]["active_version"].is_null());
}

/// X-16 (equivalence review, round 8): `active_version_values_equal` used
/// to compare both sides as `f64`, and `9007199254740992` (`2**53`) and
/// `9007199254740993` (`2**53 + 1`) are numerically distinct `i64`s that
/// collide once both are cast to `f64` (`9007199254740993.0f64 ==
/// 9007199254740992.0f64`). CPython's `int.__eq__` never routes through
/// `float` at all, so `entry["active_version"] == version` is measured
/// `False` here (`python3.12`: `9007199254740993 == 9007199254740992` is
/// `False`) and the retire step must leave `active_version` untouched --
/// before the fix, this cleared it to `null` instead.
#[test]
fn set_version_status_retire_does_not_clear_active_version_on_f64_collision() {
    let (_tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let mut doc = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    {
        let entry = &mut doc["secrets"]["gh-token"];
        entry["active_version"] = json!(9007199254740993i64);
        entry["versions"]["9007199254740992"] = json!({"status": "retired_candidate"});
    }
    ctx.state.write_json(vault::VAULT_DOC, &doc).unwrap();

    ctx.vault
        .set_version_status("gh-token", 9007199254740992, "retired")
        .unwrap();

    let doc_after = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    assert_eq!(
        doc_after["secrets"]["gh-token"]["active_version"],
        json!(9007199254740993i64),
        "a version that only collides with the active one in f64 must not clear it"
    );
}

/// X-16, the other direction: before the fix, re-activating
/// `9007199254740992` while `9007199254740993` (the colliding `f64`
/// neighbour) was active wrongly read as "no change" via the same `f64`
/// equality bug and *silently skipped* retiring the previous version,
/// leaving both versions marked `"active"` -- a fail-open. CPython's own
/// `previous != version` is measured `True` here
/// (`9007199254740993 != 9007199254740992`), takes the retire branch, and
/// then raises an uncaught `KeyError` indexing
/// `entry["versions"][str(previous)]` (no such key in this reproduction --
/// see PORTING.md §3.5), mapped to this crate's `StateError("state_corrupt")`,
/// committing nothing at all.
#[test]
fn set_version_status_activate_does_not_silently_skip_retire_on_f64_collision() {
    let (_tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let mut doc = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    {
        let entry = &mut doc["secrets"]["gh-token"];
        entry["active_version"] = json!(9007199254740993i64);
        entry["versions"]["9007199254740992"] = json!({"status": "retired"});
        // Deliberately no "9007199254740993" versions entry: reproduces
        // the shape X-16 measured -- an `active_version` that collides
        // with a *different* real version in `f64` but has no version
        // record of its own.
    }
    ctx.state.write_json(vault::VAULT_DOC, &doc).unwrap();
    let before = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();

    let err = ctx
        .vault
        .set_version_status("gh-token", 9007199254740992, "active")
        .expect_err("Python raises KeyError here, mapped to state_corrupt");
    assert!(err.is(ErrorClass::StateError), "{err:?}");
    assert_eq!(err.reason.to_string(), "state_corrupt");

    let after = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    assert_eq!(
        before, after,
        "a failed set_version_status must commit nothing, matching Python's uncaught KeyError"
    );
}

/// Same finding, `reapply_revocations`'s own `entry.get("active_version") ==
/// version` comparison: a stored `active_version` of the bool `true` must
/// still be cleared for the matching revoked version 1, not left dangling
/// (a fail-open gap on a revocation-adjacent path).
#[test]
fn reapply_revocations_clears_active_version_stored_as_bool_true() {
    let (_tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let mut doc = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    doc["secrets"]["gh-token"]["active_version"] = json!(true);
    ctx.state.write_json(vault::VAULT_DOC, &doc).unwrap();

    let mut fields = serde_json::Map::new();
    fields.insert("secret_id".into(), json!("gh-token"));
    fields.insert("version".into(), json!(1));
    zeropw::policy::append_revocation(ctx.state, "secret_version", fields);

    let counts = Vault::reapply_revocations(ctx.state).unwrap();
    assert_eq!(
        counts
            .iter()
            .find(|(k, _)| *k == "secret_versions")
            .map(|(_, v)| *v),
        Some(1)
    );

    let doc_after = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    assert_eq!(
        doc_after["secrets"]["gh-token"]["versions"]["1"]["status"],
        json!("revoked")
    );
    assert!(
        doc_after["secrets"]["gh-token"]["active_version"].is_null(),
        "active_version stored as `true` must still be cleared for the matching revoked version 1"
    );
}

/// Finding E-R5-5: `python_int_from_str`'s padding predicate must be
/// CPython `int()`'s own (which excludes U+001C..U+001F), not the full
/// `str.isspace()` set `str.strip()` uses -- a `versions` key of
/// `"\u{1c}1"` is `state_corrupt` (Python: `int("\x1c1")` raises
/// `ValueError`), not silently accepted as version 1.
#[test]
fn versions_key_with_information_separator_padding_is_state_corrupt() {
    let (_tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let mut doc = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    let versions = doc["secrets"]["gh-token"]["versions"]
        .as_object_mut()
        .unwrap();
    let v1 = versions.remove("1").unwrap();
    versions.insert("\u{1c}1".to_string(), v1);
    ctx.state.write_json(vault::VAULT_DOC, &doc).unwrap();

    let err = ctx.vault.list_secrets(None, None).unwrap_err();
    assert!(err.is(ErrorClass::StateError));
    assert_eq!(err.reason.to_string(), "state_corrupt");
}

/// The same padding predicate must still accept an ordinary ASCII space,
/// which both `str.isspace()` and CPython's `int()` treat as valid padding.
#[test]
fn versions_key_with_ordinary_space_padding_still_parses() {
    let (_tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let mut doc = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    let versions = doc["secrets"]["gh-token"]["versions"]
        .as_object_mut()
        .unwrap();
    let v1 = versions.remove("1").unwrap();
    versions.insert(" 1 ".to_string(), v1);
    ctx.state.write_json(vault::VAULT_DOC, &doc).unwrap();

    let meta = ctx.vault.get_meta("gh-token").unwrap();
    assert_eq!(meta.versions[0].version, 1);
}

/// Finding E-R5-6: `NotFound("secret_version_unusable", status)` must
/// suppress a *falsy* `status` detail exactly like `ZeroPWError.__init__`
/// (`str(exc)` is bare, `to_dict()` omits `detail`) -- a status of the JSON
/// number `0` produces no visible detail at all, not the literal string
/// `"0"`.
#[test]
fn secret_version_unusable_suppresses_falsy_status_detail() {
    let (_tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let mut doc = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    doc["secrets"]["gh-token"]["versions"]["1"]["status"] = json!(0);
    ctx.state.write_json(vault::VAULT_DOC, &doc).unwrap();

    let err = ctx
        .vault
        .secret_for_trusted_use("gh-token", Some(1))
        .unwrap_err();
    assert!(err.is(ErrorClass::NotFound));
    assert_eq!(err.reason.to_string(), "secret_version_unusable");
    assert_eq!(err.detail, "");
    assert!(err.to_dict().get("detail").is_none());
}

/// Same finding, the truthy-string counter-case: a status of the *string*
/// `"0"` is truthy in Python (a non-empty string), so its detail must still
/// render, unlike the falsy JSON number `0` above.
#[test]
fn secret_version_unusable_keeps_truthy_string_status_detail() {
    let (_tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let mut doc = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    doc["secrets"]["gh-token"]["versions"]["1"]["status"] = json!("0");
    ctx.state.write_json(vault::VAULT_DOC, &doc).unwrap();

    let err = ctx
        .vault
        .secret_for_trusted_use("gh-token", Some(1))
        .unwrap_err();
    assert!(err.is(ErrorClass::NotFound));
    assert_eq!(err.reason.to_string(), "secret_version_unusable");
    assert_eq!(err.detail, "0");
    assert_eq!(err.to_dict()["detail"], "0");
}

/// Finding E-R5-7: `set_version_status`'s `str(version) not in
/// entry["versions"]` is an ordinary Python `in` membership test -- an empty
/// array `versions` simply doesn't contain the key (documented
/// `NotFound`), it is not `state_corrupt` the way a non-iterable `versions`
/// (`null`/a number/a bool) or a missing key would be.
#[test]
fn set_version_status_versions_as_empty_array_is_not_found() {
    let (_tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let mut doc = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    doc["secrets"]["gh-token"]["versions"] = json!([]);
    ctx.state.write_json(vault::VAULT_DOC, &doc).unwrap();

    let err = ctx
        .vault
        .set_version_status("gh-token", 1, "retired")
        .unwrap_err();
    assert!(err.is(ErrorClass::NotFound));
    assert_eq!(err.reason.to_string(), "secret_version_not_found");
}

/// Same finding: an array `versions` that *does* contain the key (as a
/// string element) passes the membership test, but the next line's
/// `entry["versions"][str(version)]` indexing then fails (a list has no
/// string-keyed indexing) -- `state_corrupt`, not `NotFound`.
#[test]
fn set_version_status_versions_as_array_containing_the_key_is_state_corrupt() {
    let (_tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let mut doc = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    doc["secrets"]["gh-token"]["versions"] = json!(["1"]);
    ctx.state.write_json(vault::VAULT_DOC, &doc).unwrap();

    let err = ctx
        .vault
        .set_version_status("gh-token", 1, "retired")
        .unwrap_err();
    assert!(err.is(ErrorClass::StateError));
    assert_eq!(err.reason.to_string(), "state_corrupt");
}

/// Same finding, the `str` case: Python's `in` checks *substring*
/// containment for a string `versions`.
#[test]
fn set_version_status_versions_as_string_uses_substring_membership() {
    let (_tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();

    let mut doc = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    doc["secrets"]["gh-token"]["versions"] = json!("abc");
    ctx.state.write_json(vault::VAULT_DOC, &doc).unwrap();
    let err = ctx
        .vault
        .set_version_status("gh-token", 1, "retired")
        .unwrap_err();
    assert!(err.is(ErrorClass::NotFound));
    assert_eq!(err.reason.to_string(), "secret_version_not_found");

    let mut doc2 = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    doc2["secrets"]["gh-token"]["versions"] = json!("a1c");
    ctx.state.write_json(vault::VAULT_DOC, &doc2).unwrap();
    let err2 = ctx
        .vault
        .set_version_status("gh-token", 1, "retired")
        .unwrap_err();
    assert!(err2.is(ErrorClass::StateError));
    assert_eq!(err2.reason.to_string(), "state_corrupt");
}

/// Same finding, the missing-key case (Python's uncaught `KeyError`
/// evaluating `entry["versions"]` at all): still `state_corrupt`.
#[test]
fn set_version_status_versions_missing_key_is_state_corrupt() {
    let (_tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let mut doc = ctx.state.read_json(vault::VAULT_DOC, Value::Null).unwrap();
    doc["secrets"]["gh-token"]
        .as_object_mut()
        .unwrap()
        .remove("versions");
    ctx.state.write_json(vault::VAULT_DOC, &doc).unwrap();

    let err = ctx
        .vault
        .set_version_status("gh-token", 1, "retired")
        .unwrap_err();
    assert!(err.is(ErrorClass::StateError));
    assert_eq!(err.reason.to_string(), "state_corrupt");
}

/// Finding E-R5-8: `backup`'s two `pyjson::dumps` calls (the digest payload,
/// then the full `{"manifest":...,"documents":{...}}` archive) each add a
/// level of nesting beyond what `StateDir::write_json` already accepted, so
/// the real per-document budget inside `backup` is `MAX_JSON_DEPTH - 2`,
/// not the full `MAX_JSON_DEPTH` itself (finding X-3 raised `MAX_JSON_DEPTH`
/// from 500 to 990, which moves this budget too -- computed from the
/// constant below rather than hand-written, so it never goes stale like
/// this comment's old literal numbers did). Exactly at that budget,
/// `backup` must still succeed.
#[test]
fn backup_succeeds_when_document_leaves_two_levels_of_headroom() {
    let (tmp, ctx) = setup();
    ctx.state
        .write_json(
            policy::CONTROL,
            &nested_array(zeropw::pyjson::MAX_JSON_DEPTH - 2),
        )
        .unwrap();
    let out = tmp.path().join("backup.json");
    ctx.vault
        .backup(&out)
        .expect("a document with 2 levels of headroom must still back up");
}

/// Same finding: one level past that per-document budget, `backup` must
/// fail *closed* with the same `StateError` class every other `backup`
/// failure already uses, not the `InvalidInput("pyjson_max_depth_exceeded")`
/// class `pyjson::dumps` itself raises for the archive's own extra
/// wrapping -- a class no caller of `backup` otherwise ever sees from it.
#[test]
fn backup_fails_closed_instead_of_an_unexpected_error_class_past_the_headroom() {
    let (tmp, ctx) = setup();
    ctx.state
        .write_json(
            policy::CONTROL,
            &nested_array(zeropw::pyjson::MAX_JSON_DEPTH - 1),
        )
        .unwrap();
    let out = tmp.path().join("backup.json");
    let err = ctx.vault.backup(&out).unwrap_err();
    assert!(err.is(ErrorClass::StateError));
    assert_eq!(err.reason.to_string(), "backup_too_deep");
}

/// Same finding, the other binding constraint: a document at `StateDir`'s
/// own writable max depth (`MAX_JSON_DEPTH`) already exceeds `backup`'s
/// *first* `dumps` call (the digest payload, one level of wrapping) before
/// the archive is even assembled -- still `StateError("backup_too_deep")`,
/// not an escaping `InvalidInput`.
#[test]
fn backup_fails_closed_for_a_document_at_the_writable_max_depth() {
    let (tmp, ctx) = setup();
    ctx.state
        .write_json(
            policy::CONTROL,
            &nested_array(zeropw::pyjson::MAX_JSON_DEPTH),
        )
        .unwrap();
    let out = tmp.path().join("backup.json");
    let err = ctx.vault.backup(&out).unwrap_err();
    assert!(err.is(ErrorClass::StateError));
    assert_eq!(err.reason.to_string(), "backup_too_deep");
}

/// Same finding, `restore`'s side: a real Python-written archive (Python's
/// `json` has no depth limit at all) can legitimately carry a document
/// right at `StateDir`'s own writable max depth, wrapped two levels deeper
/// by the archive itself -- past this port's own parse-time cap. `restore`
/// must fail *closed* with the ordinary, already-handled
/// `StateError("backup_malformed")` (the same class every other unparseable
/// archive already gets), not panic or succeed with truncated data. Built
/// with plain `serde_json` (not `pyjson`, which enforces the very cap this
/// test is probing) to stand in for output Python could really produce.
#[test]
fn restore_rejects_a_python_built_archive_whose_document_is_at_the_writable_max_depth() {
    let (tmp, ctx) = setup();
    let deep_doc = nested_array(zeropw::pyjson::MAX_JSON_DEPTH);
    let archive = json!({
        "manifest": {"format": "zeropw-backup-v1", "sha256": "0", "backup_id": "test"},
        "documents": {policy::CONTROL: deep_doc},
    });
    let text = serde_json::to_string(&archive).unwrap();
    let path = tmp.path().join("deep-backup.json");
    fs::write(&path, text).unwrap();

    let err = Vault::restore(ctx.state, &path, ctx.audit, None).unwrap_err();
    assert!(err.is(ErrorClass::StateError));
    assert_eq!(err.reason.to_string(), "backup_malformed");
}

/// Finding E-R5-9: `restore`'s `list(current.get("approval_history") or
/// [])` iterates a truthy non-list value instead of discarding it -- a
/// string yields its characters, a dict yields its keys.
#[test]
fn restore_approval_history_iterates_a_truthy_string_into_characters() {
    let (tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let out = tmp.path().join("backup.json");
    ctx.vault.backup(&out).unwrap();

    let mut control = ctx
        .state
        .read_json(policy::CONTROL, Value::Null)
        .unwrap_or_else(|_| json!({}));
    if !control.is_object() {
        control = json!({});
    }
    control["approval_history"] = json!("ab");
    ctx.state.write_json(policy::CONTROL, &control).unwrap();

    Vault::restore(ctx.state, &out, ctx.audit, None).unwrap();
    let after = ctx.state.read_json(policy::CONTROL, Value::Null).unwrap();
    assert_eq!(after["approval_history"], json!(["a", "b"]));
}

/// Same finding, the dict-yields-keys case.
#[test]
fn restore_approval_history_iterates_a_truthy_object_into_its_keys() {
    let (tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let out = tmp.path().join("backup.json");
    ctx.vault.backup(&out).unwrap();

    let mut control = ctx
        .state
        .read_json(policy::CONTROL, Value::Null)
        .unwrap_or_else(|_| json!({}));
    if !control.is_object() {
        control = json!({});
    }
    control["approval_history"] = json!({"x": 1, "y": 2});
    ctx.state.write_json(policy::CONTROL, &control).unwrap();

    Vault::restore(ctx.state, &out, ctx.audit, None).unwrap();
    let after = ctx.state.read_json(policy::CONTROL, Value::Null).unwrap();
    assert_eq!(after["approval_history"], json!(["x", "y"]));
}

/// Same finding, the truthy-non-iterable-scalar case: `list(5)` raises an
/// uncaught `TypeError` in Python -- `state_corrupt` here, not a silent
/// `[]` substitution.
#[test]
fn restore_approval_history_truthy_scalar_is_state_corrupt() {
    let (tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let out = tmp.path().join("backup.json");
    ctx.vault.backup(&out).unwrap();

    let mut control = ctx
        .state
        .read_json(policy::CONTROL, Value::Null)
        .unwrap_or_else(|_| json!({}));
    if !control.is_object() {
        control = json!({});
    }
    control["approval_history"] = json!(5);
    ctx.state.write_json(policy::CONTROL, &control).unwrap();

    let err = Vault::restore(ctx.state, &out, ctx.audit, None).unwrap_err();
    assert!(err.is(ErrorClass::StateError));
    assert_eq!(err.reason.to_string(), "state_corrupt");
}

/// Same finding: a *falsy* `approval_history` (missing, `0`, `false`, `[]`,
/// `{}`) is simply replaced with `[]`, same as before this fix.
#[test]
fn restore_approval_history_falsy_value_becomes_empty_list() {
    let (tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let out = tmp.path().join("backup.json");
    ctx.vault.backup(&out).unwrap();

    let mut control = ctx
        .state
        .read_json(policy::CONTROL, Value::Null)
        .unwrap_or_else(|_| json!({}));
    if !control.is_object() {
        control = json!({});
    }
    control["approval_history"] = json!(0);
    ctx.state.write_json(policy::CONTROL, &control).unwrap();

    Vault::restore(ctx.state, &out, ctx.audit, None).unwrap();
    let after = ctx.state.read_json(policy::CONTROL, Value::Null).unwrap();
    assert_eq!(after["approval_history"], json!([]));
}

/// Rewrites one document inside an on-disk backup archive and recomputes
/// the manifest's `sha256` digest to match, the same way `Vault::backup`
/// itself computes it (`pyjson::dumps(&documents,
/// DumpOptions::compact_sorted())`, then `sha256` hex) -- otherwise the
/// corrupted archive would be rejected as `backup_digest_mismatch` before
/// `Vault::restore` ever reaches the document this helper is meant to
/// exercise.
fn corrupt_document_in_backup(path: &Path, doc_name: &str, new_value: Value) {
    let text = fs::read_to_string(path).unwrap();
    let mut archive: Value = serde_json::from_str(&text).unwrap();
    archive["documents"][doc_name] = new_value;
    let documents = archive["documents"].clone();
    let payload =
        zeropw::pyjson::dumps(&documents, zeropw::pyjson::DumpOptions::compact_sorted()).unwrap();
    let digest = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(payload.as_bytes()))
    };
    archive["manifest"]["sha256"] = json!(digest);
    fs::write(path, serde_json::to_string(&archive).unwrap()).unwrap();
}

/// E-R6-2 (correcting the coordinator's own drafting error in the
/// `#[ignore]`d placeholder this replaces): Python's `Vault.restore` is
/// strictly sequential (`reapply_revocations` at vault.py:573 runs *before*
/// the `write_bytes(HANDLE_KEY, ...)`-equivalent handle-key rotation at
/// vault.py:578, both inside the same `with state.lock():` block, with no
/// enclosing `try`/`except` around either), so there is no Python execution
/// where `restore` fails partway through and the handle key still rotates
/// -- a failure and a rotation are mutually exclusive outcomes of the same
/// call, not independent. `Policy::reapply_revocations` itself only reads
/// `policy/connections.json` (via `self.connections()?`) when there is at
/// least one pending connection revocation to look up (unit D's round-6
/// lazy-read fix, `policy.rs`) -- mirroring Python's own
/// `connections.get(connection_id)` only running inside a `for` loop over
/// `revocations.connections`. So a `policy/connections.json` that is a
/// truthy non-dict (e.g. a JSON string) must not by itself fail a restore:
/// only a *pending* connection revocation forces the read that discovers
/// the corruption. This is the "no pending revocation" half: `restore`
/// must succeed, write `restore_reapplied`, and rotate `context::HANDLE_KEY`
/// exactly as Python does. Verified against real `python3.12` by
/// `vault_context_oracle.rs`'s
/// `restore_reapply_revocations_connections_doc_corruption_matches_python`.
#[test]
fn restore_succeeds_and_rotates_handle_key_when_corrupt_connections_doc_has_no_pending_revocation()
{
    let (tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let out = tmp.path().join("backup.json");
    ctx.vault.backup(&out).unwrap();
    corrupt_document_in_backup(&out, policy::CONNECTIONS, json!("not-a-dict"));

    let key_before = ctx.state.read_bytes(zeropw::context::HANDLE_KEY).unwrap();

    Vault::restore(ctx.state, &out, ctx.audit, None)
        .expect("no pending connection revocation: restore must succeed like Python does");

    let connections_after = ctx
        .state
        .read_json(policy::CONNECTIONS, Value::Null)
        .unwrap();
    assert_eq!(
        connections_after,
        json!("not-a-dict"),
        "the corrupted document itself is written through verbatim, same as any other archived document"
    );
    let control_after = ctx.state.read_json(policy::CONTROL, Value::Null).unwrap();
    assert!(
        control_after.get("restore_reapplied").is_some(),
        "restore_reapplied must be written on a successful restore"
    );
    let key_after = ctx.state.read_bytes(zeropw::context::HANDLE_KEY).unwrap();
    assert_ne!(
        key_before, key_after,
        "the handle key must be rotated on a successful restore"
    );
}

/// E-R6-2's companion case: the same corrupted `policy/connections.json`,
/// but *with* a pending connection revocation. Python's
/// `Policy.reapply_revocations` for-loop now actually runs
/// `connections.get(connection_id)` against the corrupted (non-dict) value,
/// raising an uncaught `AttributeError` that propagates out of
/// `Vault.restore` entirely -- so the whole restore fails and, per this
/// finding's own reasoning above, the handle key must be left untouched
/// (never reaching the rotation a few lines below the failed
/// `reapply_revocations` call). Verified against real `python3.12` by
/// `vault_context_oracle.rs`'s
/// `restore_reapply_revocations_connections_doc_corruption_matches_python`.
#[test]
fn restore_fails_and_leaves_handle_key_untouched_when_corrupt_connections_doc_has_a_pending_revocation()
 {
    let (tmp, ctx) = setup();
    ctx.vault
        .put_secret("gh-token", "api_key", SYNTHETIC, "demo", "dev", true)
        .unwrap();
    let out = tmp.path().join("backup.json");
    ctx.vault.backup(&out).unwrap();
    corrupt_document_in_backup(&out, policy::CONNECTIONS, json!("not-a-dict"));

    let mut fields = serde_json::Map::new();
    fields.insert("id".into(), json!("conn-pending-revocation"));
    policy::append_revocation(ctx.state, "connection", fields);

    let key_before = ctx.state.read_bytes(zeropw::context::HANDLE_KEY).unwrap();

    let err = Vault::restore(ctx.state, &out, ctx.audit, None)
        .expect_err("a pending connection revocation forces the corrupted read: restore must fail like Python's uncaught AttributeError does");
    assert!(err.is(ErrorClass::StateError));
    assert_eq!(err.reason.to_string(), "state_corrupt");

    let key_after = ctx.state.read_bytes(zeropw::context::HANDLE_KEY).unwrap();
    assert_eq!(
        key_before, key_after,
        "a failed restore must never rotate the handle key"
    );
}
