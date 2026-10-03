//! Vault and context boundary tests that used to run the Python prototype.
//!
//! The persisted-state boundary is checked against a state directory, a
//! backup archive and a handle generated once by the prototype
//! (`tests/fixtures/python/vault/GENERATE.md`): they must open, decrypt,
//! restore, authenticate and verify in Rust, and what Rust writes for the
//! same operations must have the same files and document layout. The
//! remaining tests assert Rust's own fail-closed outcome for malformed state
//! and the `socket_dir` containment rule.
//!
//! Secret values are only ever compared through a sha256 digest.

mod python_fixtures;

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::errors::ErrorClass;
use zeropw::projects;
use zeropw::pyjson::{self, DumpOptions};

const FIXED_NOW: f64 = 1_700_000_000.0;

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Copies the prototype-written state directory into `tmp` and returns it.
fn python_state(tmp: &TempDir) -> PathBuf {
    let state = tmp.path().join("state");
    python_fixtures::copy_state("vault/state", &state);
    state
}

fn fixture_meta() -> Value {
    python_fixtures::json("vault/meta.json")
}

/// Asserts `ours` has the same files as the prototype-written fixture
/// directory `fixture` and that every JSON document (and every audit line)
/// has the same layout; values (random keys, ids, timestamps) may differ.
fn assert_same_layout(ours: &Path, fixture: &Path) {
    assert_eq!(
        python_fixtures::relative_files(ours),
        python_fixtures::relative_files(fixture),
        "file set"
    );
    for name in python_fixtures::relative_files(fixture) {
        let text = |root: &Path| fs::read_to_string(root.join(&name)).unwrap();
        if name.ends_with(".json") {
            let (a, b) = (text(ours), text(fixture));
            let a: Value = serde_json::from_str(&a).unwrap();
            let b: Value = serde_json::from_str(&b).unwrap();
            assert_eq!(
                python_fixtures::shape(&a),
                python_fixtures::shape(&b),
                "{name}"
            );
        } else if name.ends_with(".jsonl") {
            let (a, b) = (text(ours), text(fixture));
            let shapes = |text: &str| -> Vec<Value> {
                text.lines()
                    .map(|l| {
                        // `Audit::require_writable` appends an empty line.
                        if l.is_empty() {
                            return Value::String("<empty line>".into());
                        }
                        let v: Value = serde_json::from_str(l)
                            .unwrap_or_else(|e| panic!("{name}: {l:?}: {e}\n{text}"));
                        python_fixtures::shape(&v)
                    })
                    .collect()
            };
            let (a, b) = (shapes(&a), shapes(&b));
            assert_eq!(a, b, "{name}");
        } else if name == "kms/master.key" {
            let (a, b) = (text(ours), text(fixture));
            let (a, b): (Vec<&str>, Vec<&str>) = (a.lines().collect(), b.lines().collect());
            assert_eq!(a.len(), 2, "{name}");
            assert_eq!(a[0], b[0], "{name}: key id");
            assert_eq!(a[1].len(), b[1].len(), "{name}: base64 master key");
        } else {
            assert_eq!(
                fs::metadata(ours.join(&name)).unwrap().len(),
                fs::metadata(fixture.join(&name)).unwrap().len(),
                "{name}"
            );
        }
    }
}

/// The operations the fixture generator ran, through the Rust API.
fn rust_state_like_the_fixture(state: &Path, backup: &Path) -> (String, String) {
    let ctx = Context::initialize(
        state,
        "admin-passphrase-1",
        "recovery-passphrase-1",
        Config::default(),
        clock::fixed(FIXED_NOW),
    )
    .unwrap();
    ctx.projects
        .create("demo", projects::DEFAULT_ENVIRONMENTS)
        .unwrap();
    ctx.vault
        .put_secret(
            "gh-token",
            "api_key",
            b"cross-lang-secret-rust",
            "demo",
            "dev",
            true,
        )
        .unwrap();
    ctx.policy.create_principal("agent-1", "default").unwrap();
    let target = zeropw::policy::HttpTarget::new("http", "127.0.0.1", 1, None, false).unwrap();
    let scope = zeropw::policy::HttpScope::new(None, None, vec![]).unwrap();
    let connection = zeropw::policy::Connection::new(
        "gh",
        "demo",
        "dev",
        "fake",
        "http",
        "gh-token",
        None,
        "",
        Some(target),
        Some(zeropw::policy::HttpAuth::bearer()),
        Some(scope),
        None,
        None,
        0,
        "active",
        "",
        "",
    )
    .unwrap();
    ctx.policy.create_connection(connection).unwrap();
    let grant = ctx
        .policy
        .create_grant("agent-1", "gh", Some(3600), None)
        .unwrap();
    let handle = ctx
        .handles
        .issue(
            "agent-1",
            "gh",
            &grant.id,
            grant.policy_version.to_i64().unwrap(),
            300,
            Some(FIXED_NOW),
        )
        .unwrap();
    ctx.vault.backup(backup).unwrap();
    (handle, grant.id)
}

// ------------------------------------------------------- state dir round trip
#[test]
fn python_initialized_state_opens_in_rust_and_reads_the_same_secret() {
    let tmp = TempDir::new().unwrap();
    let state = python_state(&tmp);
    let meta = fixture_meta();

    let ctx = Context::open(&state, Config::default(), clock::fixed(FIXED_NOW)).unwrap();
    let got = ctx.vault.secret_for_trusted_use("gh-token", None).unwrap();
    assert_eq!(
        sha256_hex(got.expose()),
        sha256_hex(meta["secret_value"].as_str().unwrap().as_bytes())
    );
    let names: Vec<String> = ctx
        .projects
        .list()
        .unwrap()
        .into_iter()
        .map(|p| p.name)
        .collect();
    assert_eq!(names, vec!["demo"]);
    let grant_id = meta["grant_id"].as_str().unwrap();
    assert_eq!(ctx.policy.get_grant(grant_id).unwrap().principal, "agent-1");
}

#[test]
fn rust_initialized_state_has_the_python_layout_and_reads_the_same_secret() {
    let tmp = TempDir::new().unwrap();
    let state = tmp.path().join("state");
    let backup = tmp.path().join("backup.json");
    rust_state_like_the_fixture(&state, &backup);

    assert_same_layout(&state, &python_fixtures::path("vault/state"));

    let ctx = Context::open(&state, Config::default(), clock::fixed(FIXED_NOW)).unwrap();
    let got = ctx.vault.secret_for_trusted_use("gh-token", None).unwrap();
    assert_eq!(
        sha256_hex(got.expose()),
        sha256_hex(b"cross-lang-secret-rust")
    );
}

// --------------------------------------------------------- backup / restore
#[test]
fn backup_made_by_python_restores_through_rust() {
    let tmp = TempDir::new().unwrap();
    let state = python_state(&tmp);
    let backup = python_fixtures::path("vault/backup.json");
    let meta = fixture_meta();

    let ctx = Context::open(&state, Config::default(), clock::fixed(FIXED_NOW)).unwrap();
    zeropw::vault::Vault::restore(ctx.state, &backup, ctx.audit, Some(ctx.kms)).unwrap();
    let got = ctx.vault.secret_for_trusted_use("gh-token", None).unwrap();
    assert_eq!(
        sha256_hex(got.expose()),
        sha256_hex(meta["secret_value"].as_str().unwrap().as_bytes())
    );
}

#[test]
fn backup_made_by_rust_has_the_python_archive_layout_and_restores() {
    let tmp = TempDir::new().unwrap();
    let state = tmp.path().join("state");
    let backup = tmp.path().join("backup.json");
    rust_state_like_the_fixture(&state, &backup);

    let ours: Value = serde_json::from_str(&fs::read_to_string(&backup).unwrap()).unwrap();
    let theirs = python_fixtures::json("vault/backup.json");
    assert_eq!(
        python_fixtures::shape(&ours),
        python_fixtures::shape(&theirs)
    );
    assert_eq!(ours["manifest"]["format"], theirs["manifest"]["format"]);

    let ctx = Context::open(&state, Config::default(), clock::fixed(FIXED_NOW)).unwrap();
    zeropw::vault::Vault::restore(ctx.state, &backup, ctx.audit, Some(ctx.kms)).unwrap();
    let got = ctx.vault.secret_for_trusted_use("gh-token", None).unwrap();
    assert_eq!(
        sha256_hex(got.expose()),
        sha256_hex(b"cross-lang-secret-rust")
    );
}

// ---------------------------------------------- restore reapply_revocations
// (finding E-R6-2: corrects the coordinator's own drafting error about
// which end state is correct here -- see `vault_context.rs`'s replacement
// tests for the full reasoning)

/// A minimal, digest-valid backup archive whose only document is
/// `policy/connections.json`, set to a truthy non-dict (`"not-a-dict"`).
fn connections_corruption_archive() -> Value {
    let mut documents = serde_json::Map::new();
    documents.insert(zeropw::policy::CONNECTIONS.to_string(), json!("not-a-dict"));
    let documents = Value::Object(documents);
    let payload = pyjson::dumps(&documents, DumpOptions::compact_sorted()).unwrap();
    let digest = hex::encode(Sha256::digest(payload.as_bytes()));
    json!({
        "manifest": {
            "format": "zeropw-backup-v1",
            "created_at": "2024-01-01T00:00:00Z",
            "sha256": digest,
            "kms_key_id": "irrelevant-for-this-probe",
            "backup_id": "e6-2-probe",
        },
        "documents": documents,
    })
}

/// Runs `Vault::restore` over [`connections_corruption_archive`] on a freshly
/// initialized state directory, optionally with a pending `"connection"`
/// revocation appended to the ledger first. Returns `(restore_ok,
/// handle_key_rotated)`.
fn probe_connections_corruption(with_pending_revocation: bool) -> (bool, bool) {
    let tmp = TempDir::new().unwrap();
    let archive = connections_corruption_archive();
    let archive_path = tmp.path().join("archive.json");
    fs::write(&archive_path, serde_json::to_string(&archive).unwrap()).unwrap();

    let rust_state = tmp.path().join("state-rust");
    let (rust_ok, rust_key_rotated) = {
        let ctx = Context::initialize(
            &rust_state,
            "admin-passphrase-1",
            "recovery-passphrase-1",
            Config::default(),
            clock::fixed(FIXED_NOW),
        )
        .unwrap();
        if with_pending_revocation {
            let mut fields = serde_json::Map::new();
            fields.insert("id".into(), json!("conn-pending-revocation"));
            zeropw::policy::append_revocation(ctx.state, "connection", fields);
        }
        let key_before = ctx.state.read_bytes(zeropw::context::HANDLE_KEY).unwrap();
        let ok = zeropw::vault::Vault::restore(ctx.state, &archive_path, ctx.audit, None).is_ok();
        let key_after = ctx.state.read_bytes(zeropw::context::HANDLE_KEY).unwrap();
        (ok, key_before != key_after)
    };
    (rust_ok, rust_key_rotated)
}

/// No pending connection revocation: `Policy::reapply_revocations`'s lazy
/// read of `policy/connections.json` never runs, so the corrupted document
/// is never even looked at -- `restore` succeeds and rotates the handle key
/// in both languages.
#[test]
fn restore_reapply_revocations_connections_doc_corruption_matches_python_without_pending_revocation()
 {
    let rust = probe_connections_corruption(false);
    assert_eq!(
        rust,
        (true, true),
        "rust: restore must succeed and rotate the handle key"
    );
}

/// A pending connection revocation forces the read: Python's
/// `connections.get(connection_id)` raises an uncaught `AttributeError` on
/// the corrupted (non-dict) document, aborting `Vault.restore` entirely
/// before the handle-key rotation a few lines later ever runs; Rust must
/// fail the same way (`StateError("state_corrupt")`) and also leave the
/// handle key untouched.
#[test]
fn restore_reapply_revocations_connections_doc_corruption_matches_python_with_pending_revocation() {
    let rust = probe_connections_corruption(true);
    assert_eq!(
        rust,
        (false, false),
        "rust: restore must fail and leave the handle key untouched"
    );
}

// -------------------------------------------------- inside_state (finding E-1)
/// Builds one on-disk state directory (via a throwaway `Context::initialize`
/// with default config, so `socket_dir`/`run_dir` land outside `tmp`
/// entirely and cannot interfere with the probe), then asks `Context::open`
/// whether it accepts or refuses the candidate as `socket_dir`, returning
/// `(accepted, reason_if_refused)`.
fn probe_inside_state(build_candidate: impl FnOnce(&TempDir, &Path) -> PathBuf) -> (bool, String) {
    let tmp = TempDir::new().unwrap();
    let state = tmp.path().join("state");
    Context::initialize(
        &state,
        "admin-passphrase-1",
        "recovery-passphrase-1",
        Config::default(),
        clock::fixed(FIXED_NOW),
    )
    .unwrap();
    let candidate = build_candidate(&tmp, &state);

    match Context::open(
        &state,
        Config {
            socket_dir: Some(candidate.clone()),
            ..Config::default()
        },
        clock::fixed(FIXED_NOW),
    ) {
        Ok(_) => (true, String::new()),
        Err(e) => (false, e.reason.to_string()),
    }
}

/// Reviewer probe 1: a non-existent leaf directly under the state dir.
#[test]
fn inside_state_matches_python_for_nonexistent_leaf() {
    let rust = probe_inside_state(|_tmp, state| state.join("sockets"));
    assert!(!rust.0, "must be refused: {rust:?}");
    assert_eq!(rust.1, "socket_dir_inside_state_dir");
}

/// Reviewer probe 2: an *existing* leaf directly under the state dir.
#[test]
fn inside_state_matches_python_for_existing_leaf() {
    let rust = probe_inside_state(|_tmp, state| {
        let candidate = state.join("sockets2");
        fs::create_dir_all(&candidate).unwrap();
        candidate
    });
    assert!(!rust.0, "must be refused: {rust:?}");
    assert_eq!(rust.1, "socket_dir_inside_state_dir");
}

/// Reviewer probe 3: a non-existent leaf reached through a lexical `..` that
/// cancels back into the state dir (`state/vault/../runs`; `state/vault`
/// already exists -- `Context::initialize` creates it).
#[test]
fn inside_state_matches_python_for_dotdot_back_into_state() {
    let rust = probe_inside_state(|_tmp, state| state.join("vault").join("..").join("runs"));
    assert!(!rust.0, "must be refused: {rust:?}");
    assert_eq!(rust.1, "socket_dir_inside_state_dir");
}

/// Reviewer probe 4: a non-existent leaf reached through a symlink whose
/// target is the state dir (`root/link/runs`, `root/link -> state`).
#[test]
fn inside_state_matches_python_for_symlink_to_state() {
    let rust = probe_inside_state(|tmp, state| {
        let root = tmp.path().join("root");
        fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(state, root.join("link")).unwrap();
        root.join("link").join("runs")
    });
    assert!(!rust.0, "must be refused: {rust:?}");
    assert_eq!(rust.1, "socket_dir_inside_state_dir");
}

/// Reviewer probe 5: the state dir itself.
#[test]
fn inside_state_matches_python_for_state_dir_itself() {
    let rust = probe_inside_state(|_tmp, state| state.to_path_buf());
    assert!(!rust.0, "must be refused: {rust:?}");
    assert_eq!(rust.1, "socket_dir_inside_state_dir");
}

// ------------------------------------------ restore null vault_doc (finding E-4)
/// Builds a minimal backup archive whose `documents` map is exactly
/// `{"vault/secrets.json": vault_doc}` (or, when `vault_doc` is `None`, an
/// empty `documents` map -- the key is entirely absent), with a correct
/// `sha256`/`format` in the manifest so only the `vault_doc` handling itself
/// is under test.
fn minimal_backup_archive(vault_doc: Option<Value>) -> Value {
    let mut documents = serde_json::Map::new();
    if let Some(v) = vault_doc {
        documents.insert("vault/secrets.json".to_string(), v);
    }
    let documents = Value::Object(documents);
    let payload = pyjson::dumps(&documents, DumpOptions::compact_sorted()).unwrap();
    let digest = hex::encode(Sha256::digest(payload.as_bytes()));
    json!({
        "manifest": {
            "format": "zeropw-backup-v1",
            "created_at": "2024-01-01T00:00:00Z",
            "sha256": digest,
            "kms_key_id": "irrelevant-for-this-probe",
            "backup_id": "e4-probe",
        },
        "documents": documents,
    })
}

/// Runs `Vault::restore(kms=Some(...))` against the given archive on a
/// freshly initialized state directory, returning `Ok(())` or `Err(reason)`.
fn probe_restore_vault_doc(archive: &Value) -> Result<(), String> {
    let tmp = TempDir::new().unwrap();
    let archive_path = tmp.path().join("archive.json");
    fs::write(&archive_path, serde_json::to_string(archive).unwrap()).unwrap();

    let rust_state = tmp.path().join("state-rust");
    let ctx = Context::initialize(
        &rust_state,
        "admin-passphrase-1",
        "recovery-passphrase-1",
        Config::default(),
        clock::fixed(FIXED_NOW),
    )
    .unwrap();
    match zeropw::vault::Vault::restore(ctx.state, &archive_path, ctx.audit, Some(ctx.kms)) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.reason.to_string()),
    }
}

/// Reviewer case: `vault_doc` present with a non-dict `dek` -- must still be
/// `backup_malformed` in both languages (unaffected by the E-4 fix).
#[test]
fn restore_rejects_vault_doc_with_non_dict_dek_in_both_languages() {
    let archive = minimal_backup_archive(Some(json!({"dek": "not-a-dict"})));
    let rust = probe_restore_vault_doc(&archive);
    assert_eq!(rust, Err("backup_malformed".to_string()));
}

// ------------------------------------ vault version-key parsing (finding E-R3-4)
/// Overwrites the sole version key of `secret_id`'s `versions` object in the
/// on-disk `vault/secrets.json` with `new_key`, leaving the encrypted
/// record itself untouched. Safe for probes that only read *metadata*
/// (`list_secrets`/`get_meta`) -- they never decrypt anything, so a renamed
/// key does not need to match the AAD `version` baked into the ciphertext
/// at encryption time.
fn rename_sole_version_key(ctx: &Context, secret_id: &str, new_key: &str) {
    let mut doc = ctx
        .state
        .read_json(zeropw::vault::VAULT_DOC, Value::Null)
        .unwrap();
    let versions = doc["secrets"][secret_id]["versions"]
        .as_object_mut()
        .expect("versions object");
    let old_key = versions.keys().next().cloned().expect("one version key");
    let record = versions.remove(&old_key).expect("record");
    versions.insert(new_key.to_string(), record);
    ctx.state
        .write_json(zeropw::vault::VAULT_DOC, &doc)
        .unwrap();
}

fn setup_single_secret_context(tmp: &TempDir) -> Context {
    let state = tmp.path().join("state");
    // Explicit `socket_dir`/`run_dir` under this test's own `TempDir` (unit G's fixtures already
    // do this): `Config::default()` leaves both `None`, which `Context::initialize` fills in with
    // fresh private directories under the *system* temp dir instead of this test's own.
    let config = Config {
        socket_dir: Some(tmp.path().join("ctx-sockets")),
        run_dir: Some(tmp.path().join("ctx-run")),
        ..Config::default()
    };
    let ctx = Context::initialize(
        &state,
        "admin-passphrase-1",
        "recovery-passphrase-1",
        config,
        clock::fixed(FIXED_NOW),
    )
    .unwrap();
    ctx.projects
        .create("demo", projects::DEFAULT_ENVIRONMENTS)
        .unwrap();
    ctx.vault
        .put_secret(
            "gh-token",
            "api_key",
            b"synthetic-token-0123456789",
            "demo",
            "dev",
            true,
        )
        .unwrap();
    ctx
}

/// Reviewer requirement: a version key `int()` cannot parse at all (e.g.
/// `"x"`) raises an uncaught `ValueError` in Python (`vault.py` never
/// guards `int(v)` with a `try`/`except`); Rust must fail closed with the
/// `StateError("state_corrupt")` this module's own DEVIATIONS row already
/// documents for exactly this class of corrupted state, not silently drop
/// the version the way the previous `.parse::<i64>().ok()` inside a
/// `filter_map` did.
#[test]
fn list_secrets_non_integer_version_key_is_state_corrupt_not_silently_dropped() {
    let tmp = TempDir::new().unwrap();
    let ctx = setup_single_secret_context(&tmp);
    rename_sole_version_key(&ctx, "gh-token", "x");

    let err = ctx.vault.list_secrets(None, None).unwrap_err();
    assert_eq!(err.reason.to_string(), "state_corrupt");
}

/// Reviewer requirement: `put_secret`'s next-version computation must also
/// account for a non-canonical version key, not compute a next-version
/// number that could overwrite an existing version. After renaming the
/// existing `"1"` key to `"01"` (still parses to version 1), putting a new
/// value must land on version 2, exactly as if the key had never been
/// renamed. `activate: false` here: `setup_single_secret_context` leaves
/// `active_version = 1` (a plain JSON integer) from the first `put_secret`
/// call, so renaming the *version* key to `"01"` (without also touching
/// `active_version`) leaves the two inconsistent -- with `activate: true`,
/// `entry["versions"][str(previous)]` (`str(1) == "1"`) would no longer
/// find a `"1"` key at all, and *this* function's own finding (E-R4-4)
/// requires that to fail closed. Confirmed directly against `python3.12`:
/// the same on-disk corruption raises `KeyError: '1'` there too (real
/// Python, not just this port) when `activate=True`; passing `False`
/// skips that whole branch in both languages (`vault.py`: the retire
/// logic sits entirely inside `if activate:`), isolating this test back
/// down to the next-version computation it's actually about. See
/// `put_secret_retire_step_fails_closed_for_a_version_key_active_version_disagrees_with`
/// below for the `activate: true` / E-R4-4 case itself.
#[test]
fn put_secret_next_version_accounts_for_non_canonical_version_keys() {
    let tmp = TempDir::new().unwrap();
    let ctx = setup_single_secret_context(&tmp);
    rename_sole_version_key(&ctx, "gh-token", "01");

    let version = ctx
        .vault
        .put_secret(
            "gh-token",
            "api_key",
            b"another-synthetic-token-012345",
            "demo",
            "dev",
            false,
        )
        .unwrap();
    assert_eq!(version, 2, "must not overwrite version 1");
}

// ------------------------------------------------ put_secret retire step (finding E-R4-4)
/// Reviewer requirement (finding E-R4-4): `put_secret`'s retire step
/// (`entry["versions"][str(previous)]["status"]`, run only when
/// `activate=True`) is unguarded in Python -- if `active_version` names a
/// version that doesn't exist as a key (renamed away, exactly like the test
/// above but *with* `activate: true`), Python raises an uncaught `KeyError`
/// and commits nothing (`self.state.write_json` never runs). Cross-checked
/// against real `python3.12` on the same on-disk state directory: both
/// languages must reject the write and leave `vault/secrets.json`
/// byte-for-byte unchanged.
#[test]
fn put_secret_retire_step_fails_closed_for_a_version_key_active_version_disagrees_with() {
    let tmp = TempDir::new().unwrap();
    let ctx = setup_single_secret_context(&tmp);
    rename_sole_version_key(&ctx, "gh-token", "01");
    let before = ctx
        .state
        .read_json(zeropw::vault::VAULT_DOC, Value::Null)
        .unwrap();

    let err = ctx
        .vault
        .put_secret(
            "gh-token",
            "api_key",
            b"another-synthetic-token-012345",
            "demo",
            "dev",
            true,
        )
        .unwrap_err();
    assert_eq!(err.reason.to_string(), "state_corrupt");
    let after = ctx
        .state
        .read_json(zeropw::vault::VAULT_DOC, Value::Null)
        .unwrap();
    assert_eq!(before, after, "a failed put_secret must not write anything");
}

// ------------------------------------------------- put_secret sweep findings (round 4)
/// Sweep finding (round 4): `put_secret`'s existing-entry identity check
/// (`entry["project"]`/`entry["environment"]`/`entry["kind"]`, direct indexing in Python) must
/// fail closed with `state_corrupt` for a *missing* field, not silently treat it as an identity
/// mismatch (`InvalidInput("secret_identity_mismatch")`, the previous behaviour whenever
/// `.and_then(Value::as_str) == Some(...)` saw `None`, whether from a missing key or a present
/// wrong-typed one).
#[test]
fn put_secret_existing_entry_missing_project_field_is_state_corrupt_matching_python() {
    let tmp = TempDir::new().unwrap();
    let ctx = setup_single_secret_context(&tmp);
    overwrite_entry_field_removing(&ctx, "gh-token", "project");

    let err = ctx
        .vault
        .put_secret(
            "gh-token",
            "api_key",
            b"another-synthetic-token-012345",
            "demo",
            "dev",
            true,
        )
        .unwrap_err();
    assert_eq!(err.reason.to_string(), "state_corrupt");
}

/// Sweep finding (round 4): `entry["versions"]` is direct indexing in Python too -- a missing
/// `versions` field must fail closed with `state_corrupt`, not silently reset to `{}` (the
/// previous `.unwrap_or_default()`), which would have computed `next_version = 1` and overwritten
/// whatever the field actually held.
fn overwrite_entry_field_removing(ctx: &Context, secret_id: &str, key: &str) {
    let mut doc = ctx
        .state
        .read_json(zeropw::vault::VAULT_DOC, Value::Null)
        .unwrap();
    doc["secrets"][secret_id]
        .as_object_mut()
        .expect("entry object")
        .remove(key);
    ctx.state
        .write_json(zeropw::vault::VAULT_DOC, &doc)
        .unwrap();
}

#[test]
fn put_secret_missing_versions_field_is_state_corrupt_matching_python() {
    let tmp = TempDir::new().unwrap();
    let ctx = setup_single_secret_context(&tmp);
    overwrite_entry_field_removing(&ctx, "gh-token", "versions");

    let err = ctx
        .vault
        .put_secret(
            "gh-token",
            "api_key",
            b"another-synthetic-token-012345",
            "demo",
            "dev",
            true,
        )
        .unwrap_err();
    assert_eq!(err.reason.to_string(), "state_corrupt");
}

/// Overwrites a field of `secret_id`'s sole version record (`status`, `public`, ...).
fn overwrite_sole_version_field(ctx: &Context, secret_id: &str, key: &str, value: Value) {
    let mut doc = ctx
        .state
        .read_json(zeropw::vault::VAULT_DOC, Value::Null)
        .unwrap();
    let versions = doc["secrets"][secret_id]["versions"]
        .as_object_mut()
        .expect("versions object");
    let k = versions.keys().next().cloned().expect("one version key");
    versions
        .get_mut(&k)
        .and_then(Value::as_object_mut)
        .expect("version record")
        .insert(key.to_string(), value);
    ctx.state
        .write_json(zeropw::vault::VAULT_DOC, &doc)
        .unwrap();
}

/// Reviewer case: the active version's `status` field is the JSON number `5`, not a string.
/// Python's `record["status"] not in ("active", "staged")` is simply `True` (no error), and the
/// raised `NotFound("secret_version_unusable", record["status"])` carries the raw int `5` as
/// `detail`. `secret_for_trusted_use` isn't storing this into a typed struct field, so this port
/// matches Python's return-a-value behaviour exactly (via `python_str_scalar`) instead of folding
/// it into `state_corrupt`.
#[test]
fn secret_for_trusted_use_carries_wrong_type_status_into_notfound_detail_matching_python() {
    let tmp = TempDir::new().unwrap();
    let ctx = setup_single_secret_context(&tmp);
    overwrite_sole_version_field(&ctx, "gh-token", "status", json!(5));

    let err = ctx
        .vault
        .secret_for_trusted_use("gh-token", None)
        .unwrap_err();
    assert_eq!(err.reason.to_string(), "secret_version_unusable");
    assert_eq!(err.detail, "5");
}

/// Reviewer case: `public` is `"ab"`, a two-character string. Unlike the pair-sequence array
/// above, Python's `dict("ab")` genuinely raises an uncaught `ValueError` here (each character is
/// a length-1 "pair", not length-2) -- both languages must reject this record.
#[test]
fn list_secrets_public_non_pair_string_is_state_corrupt_in_both_languages() {
    let tmp = TempDir::new().unwrap();
    let ctx = setup_single_secret_context(&tmp);
    overwrite_sole_version_field(&ctx, "gh-token", "public", json!("ab"));

    let err = ctx.vault.list_secrets(None, None).unwrap_err();
    assert_eq!(err.reason.to_string(), "state_corrupt");
}

// ----------------------------------------------------- admin passphrase auth
#[test]
fn admin_passphrase_set_by_python_authenticates_in_rust() {
    let tmp = TempDir::new().unwrap();
    let state = python_state(&tmp);
    let meta = fixture_meta();

    let ctx = Context::open(&state, Config::default(), clock::fixed(FIXED_NOW)).unwrap();
    let auth = ctx
        .admin
        .verify(meta["admin_passphrase"].as_str().unwrap(), Some(FIXED_NOW))
        .unwrap();
    assert!(auth.fresh(Some(FIXED_NOW)));
    let err = ctx.admin.verify("wrong-one", Some(FIXED_NOW)).unwrap_err();
    assert!(err.is(ErrorClass::AuthFailed));
}

#[test]
fn admin_passphrase_set_by_rust_has_the_python_layout_and_authenticates() {
    let tmp = TempDir::new().unwrap();
    let state = tmp.path().join("state");
    let ctx = Context::initialize(
        &state,
        "cross-admin-pw-rust",
        "recovery-passphrase-1",
        Config::default(),
        clock::fixed(FIXED_NOW),
    )
    .unwrap();

    let ours: Value =
        serde_json::from_str(&fs::read_to_string(state.join("admin.json")).unwrap()).unwrap();
    let theirs = python_fixtures::json("vault/state/admin.json");
    assert_eq!(
        python_fixtures::shape(&ours),
        python_fixtures::shape(&theirs)
    );
    for field in ["hash", "salt"] {
        let decode = |v: &Value| {
            base64::engine::general_purpose::STANDARD
                .decode(v[field].as_str().unwrap())
                .unwrap()
                .len()
        };
        assert_eq!(decode(&ours), decode(&theirs), "{field} length");
    }

    ctx.admin
        .verify("cross-admin-pw-rust", Some(FIXED_NOW))
        .unwrap();
    let err = ctx.admin.verify("wrong-one", Some(FIXED_NOW)).unwrap_err();
    assert!(err.is(ErrorClass::AuthFailed));
}

// ------------------------------------------------------------------ handles
#[test]
fn handle_issued_by_python_verifies_in_rust() {
    let tmp = TempDir::new().unwrap();
    let state = python_state(&tmp);
    let meta = fixture_meta();

    let ctx = Context::open(&state, Config::default(), clock::fixed(FIXED_NOW)).unwrap();
    let verified = ctx
        .handles
        .verify(meta["handle"].as_str().unwrap(), Some(FIXED_NOW + 10.0))
        .unwrap();
    assert_eq!(verified.caller, "agent-1");
    assert_eq!(verified.connection, "gh");
    assert_eq!(verified.grant, meta["grant_id"].as_str().unwrap());
    // `Policy::create_connection` always stamps a freshly created connection
    // to policy version 1, regardless of what the constructor was given.
    assert_eq!(verified.policy_version, 1);
}

#[test]
fn handle_issued_by_rust_has_the_python_payload_layout_and_verifies() {
    let tmp = TempDir::new().unwrap();
    let state = tmp.path().join("state");
    let backup = tmp.path().join("backup.json");
    let (handle, grant_id) = rust_state_like_the_fixture(&state, &backup);

    // `zpw1.<base64url payload>.<signature>`: same prefix and payload keys.
    let payload = |token: &str| -> Value {
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "{token}");
        assert_eq!(parts[0], "zpw1");
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        serde_json::from_slice(&raw).unwrap()
    };
    let fixture_handle = fixture_meta()["handle"].as_str().unwrap().to_string();
    assert_eq!(
        python_fixtures::shape(&payload(&handle)),
        python_fixtures::shape(&payload(&fixture_handle))
    );

    let ctx = Context::open(&state, Config::default(), clock::fixed(FIXED_NOW)).unwrap();
    let verified = ctx.handles.verify(&handle, Some(FIXED_NOW + 10.0)).unwrap();
    assert_eq!(verified.caller, "agent-1");
    assert_eq!(verified.connection, "gh");
    assert_eq!(verified.grant, grant_id);
    assert_eq!(verified.policy_version, 1);
}

// ------------------------------------ resolve_components long chains (finding E-R2-1)
/// Builds a symlink chain `root/k0 -> k1 -> ... -> k{hops-1} -> real_dir` (`hops` links total)
/// under `root`, returning the head (`root/k0`).
fn build_symlink_chain(root: &Path, real_dir: &Path, hops: usize) -> PathBuf {
    fs::create_dir_all(root).unwrap();
    let mut target = real_dir.to_path_buf();
    for i in (0..hops).rev() {
        let link = root.join(format!("k{i}"));
        std::os::unix::fs::symlink(&target, &link).unwrap();
        target = link;
    }
    target
}

/// Reviewer probe (finding E-R2-1): a 51-hop *acyclic* symlink chain resolving to a real
/// directory outside the state dir. CPython's `posixpath._joinrealpath` has no hop-count limit
/// (`maxlinks = None`) -- only an actual cycle is special-cased via its `seen` map -- so Python
/// resolves the whole chain and accepts it as `socket_dir`. The previous Rust implementation
/// bounded symlink-chain recursion at a fixed depth of 40 and turned *any* deeper chain into
/// `StateError("socket_dir_inside_state_dir")`, fail-closed for a path that was never inside the
/// state dir at all.
#[test]
fn inside_state_matches_python_for_51_hop_symlink_chain_to_existing_dir() {
    let rust = probe_inside_state(|tmp, _state| {
        let root = tmp.path().join("rl");
        let real = tmp.path().join("realdir");
        fs::create_dir_all(&real).unwrap();
        build_symlink_chain(&root, &real, 51)
    });
    assert!(
        rust.0,
        "a 51-hop acyclic symlink chain must resolve and be accepted, like Python: {rust:?}"
    );
}

/// Same 51-hop chain, but with a trailing leaf appended after the chain's head that does not
/// exist on disk (the common real-world shape: the chain's target directory exists, but the
/// specific leaf under it does not yet) -- combines the E-R2-1 long-chain fix with the existing
/// E-1 nonexistent-leaf handling.
#[test]
fn inside_state_matches_python_for_51_hop_symlink_chain_with_nonexistent_leaf() {
    let rust = probe_inside_state(|tmp, _state| {
        let root = tmp.path().join("rl2");
        let real = tmp.path().join("realdir2");
        fs::create_dir_all(&real).unwrap();
        let head = build_symlink_chain(&root, &real, 51);
        head.join("does-not-exist-leaf")
    });
    assert!(
        rust.0,
        "a 51-hop chain with a nonexistent trailing leaf must still be accepted: {rust:?}"
    );
}

// ------------------------------------ loop + .. + symlink cycle short-circuit (finding E-R3-1)
/// Reviewer probe: unlike the self-loop-only case above, this shape has real components
/// *after* the cycle, so it actually exercises the fail-*open* gap in round-2's cycle handling
/// (finding E-R3-1) -- the self-loop test alone never reached it because nothing followed the
/// loop. `tmp/L` is a self-loop symlink; `tmp/M` is a symlink to a real, unrelated directory
/// outside the state dir (`tmp/other/deep`); the candidate is
/// `tmp/L/../M/../state/x`. CPython's `posixpath._joinrealpath` stops resolving the instant it
/// hits the `L` cycle and appends every remaining component (`../M/../state/x`) *literally*,
/// never even looking `M` up on the filesystem -- a plain lexical `normpath` then collapses
/// `L/..` and `M/..` away, landing on the *real* trusted `state` directory's own `x`, which
/// `Context._inside_state` correctly refuses. Round-2's Rust code kept resolving past the
/// cycle instead: it popped back out of the loop, then *actually* followed the `M` symlink
/// to `tmp/other/deep`, then appended a literal (nonexistent) `state/x` under *that* --
/// landing far outside the real state dir and wrongly **accepting** a socket_dir that is, in
/// truth, inside the trusted store.
#[test]
fn inside_state_matches_python_for_loop_then_dotdot_then_symlink() {
    let rust = probe_inside_state(|tmp, _state| {
        let loop_path = tmp.path().join("L");
        std::os::unix::fs::symlink(&loop_path, &loop_path).unwrap();
        let other_deep = tmp.path().join("other").join("deep");
        fs::create_dir_all(&other_deep).unwrap();
        let m_path = tmp.path().join("M");
        std::os::unix::fs::symlink(&other_deep, &m_path).unwrap();
        tmp.path()
            .join("L")
            .join("..")
            .join("M")
            .join("..")
            .join("state")
            .join("x")
    });
    assert!(
        !rust.0,
        "must be refused as inside the state dir, like Python: {rust:?}"
    );
    assert_eq!(rust.1, "socket_dir_inside_state_dir");
}

// ------------------------------------ symlink loop escape (finding E-R2-2a)
/// Reviewer case: a **self-referential** symlink as the candidate `socket_dir`. CPython's
/// non-strict `os.path.realpath` does not raise for this by itself (it leaves the loop
/// unresolved and returns a literal path), but `pathlib.Path.resolve(strict=False)` then
/// `stat()`s that result and turns the resulting `OSError(ELOOP)` into an uncaught
/// `RuntimeError("Symlink loop from ...")` -- `Context._inside_state`'s `except OSError` does not
/// catch a `RuntimeError`, so it escapes `Context.open` entirely, not as a `StateError`. Rust has
/// no exception to let escape the same way; `resolve_lenient` reproduces the same `stat()`-based
/// loop detection and folds it into the fail-closed `StateError("socket_dir_inside_state_dir")`
/// `Context::open` already uses for every other "not acceptable" candidate (DEVIATIONS.md,
/// finding E-R2-2a; PORTING.md §3.5).
#[test]
fn inside_state_matches_python_for_self_symlink_loop() {
    let tmp = TempDir::new().unwrap();
    let state = tmp.path().join("state");
    Context::initialize(
        &state,
        "admin-passphrase-1",
        "recovery-passphrase-1",
        Config::default(),
        clock::fixed(FIXED_NOW),
    )
    .unwrap();
    let root = tmp.path().join("loop-root");
    fs::create_dir_all(&root).unwrap();
    let loop_path = root.join("loop");
    std::os::unix::fs::symlink(&loop_path, &loop_path).unwrap();

    let rust_result = Context::open(
        &state,
        Config {
            socket_dir: Some(loop_path.clone()),
            ..Config::default()
        },
        clock::fixed(FIXED_NOW),
    );
    let rust_err = match rust_result {
        Ok(_) => panic!("expected a self symlink loop to be refused"),
        Err(e) => e,
    };
    assert_eq!(rust_err.reason.to_string(), "socket_dir_inside_state_dir");
}

// ------------------------------------ restore non-ASCII manifest sha256 (finding E-R2-2b)
/// Reviewer case: `manifest["sha256"]` is a non-ASCII string. Python's `hmac.compare_digest`
/// only accepts bytes-like objects or *ASCII-only* strings; comparing the (always-ASCII-hex)
/// computed digest against a non-ASCII string raises an uncaught `TypeError`, escaping
/// `Vault.restore` entirely (not a `StateError`); the administrator CLI then prints
/// `StateError`/`state_corrupt`/`TypeError`. `Vault::restore` reproduces that escaped
/// built-in instead of reporting `backup_digest_mismatch` (finding E-R2-2b).
#[test]
fn restore_non_ascii_manifest_sha256_raises_the_python_typeerror() {
    let tmp = TempDir::new().unwrap();
    let archive_path = tmp.path().join("archive.json");
    let archive = json!({
        "manifest": {
            "format": "zeropw-backup-v1",
            "created_at": "2024-01-01T00:00:00Z",
            "sha256": "abcé",
            "kms_key_id": "irrelevant-for-this-probe",
            "backup_id": "e-r2-2b-probe",
        },
        "documents": {},
    });
    fs::write(&archive_path, serde_json::to_string(&archive).unwrap()).unwrap();

    let rust_state = tmp.path().join("state-rust");
    let ctx = Context::initialize(
        &rust_state,
        "admin-passphrase-1",
        "recovery-passphrase-1",
        Config::default(),
        clock::fixed(FIXED_NOW),
    )
    .unwrap();
    let rust_err =
        zeropw::vault::Vault::restore(ctx.state, &archive_path, ctx.audit, Some(ctx.kms))
            .unwrap_err();
    // The escaped `TypeError`, in the shape the administrator CLI prints.
    assert_eq!(
        rust_err.to_dict(),
        json!({"error": "StateError", "reason": "state_corrupt", "detail": "TypeError"})
    );
}

// ------------------------------------ Config sharing divergence (finding E-R2-3)
/// Python's `Config` is a mutable dataclass passed by reference: `Context._apply_config_defaults`
/// writes the fresh `socket_dir`/`run_dir` back onto the caller's own `Config` object, so two
/// `Context`s built from the *same* `Config` instance end up sharing one `socket_dir` and one
/// `run_dir`, owned (removed on `close()`) only by whichever built it first --
/// `tests/test_team_sync.py`'s `RemoteWideningCancelsRunningExecTestCase.setUp` and
/// `SessionRekeyTestCase.test_old_session_is_closed_and_replaced` both rely on exactly this to
/// simulate two nodes. `Context::initialize`/`Context::open` here take `Config` by value, so this
/// crate cannot reproduce that sharing (see `Config`'s doc comment in `context.rs` and
/// `DEVIATIONS.md`, finding E-R2-3): two Rust `Context`s from independently-constructed `Config`s
/// never share a temp dir, unlike Python's two `Context`s from one shared `cfg` object.
#[test]
fn two_contexts_from_separate_configs_never_share_temp_dirs_unlike_pythons_shared_config() {
    let tmp = TempDir::new().unwrap();
    let rust_state_a = tmp.path().join("rust-state-a");
    let rust_state_b = tmp.path().join("rust-state-b");

    let ctx_a = Context::initialize(
        &rust_state_a,
        "admin-passphrase-a",
        "recovery-passphrase-a",
        Config::default(),
        clock::fixed(FIXED_NOW),
    )
    .unwrap();
    let ctx_b = Context::initialize(
        &rust_state_b,
        "admin-passphrase-b",
        "recovery-passphrase-b",
        Config::default(),
        clock::fixed(FIXED_NOW),
    )
    .unwrap();
    assert_ne!(
        ctx_a.config.socket_dir, ctx_b.config.socket_dir,
        "Rust contexts must never share an owned temp dir"
    );
    assert_ne!(ctx_a.config.run_dir, ctx_b.config.run_dir);
}

// ------------------------------------ restore overflowing numeric literal (finding E-R4-5)
/// Reviewer case: the manifest's `backup_id` field is the bare numeric literal `1e999`, which
/// overflows `float` -- CPython's `float()` parses it to `inf` with no exception, so
/// `Vault.restore` proceeds normally and returns successfully. The *raw* float `inf` propagates
/// into `policy/control.json`'s `restored_from` field (`control["restored_from"] =
/// manifest.get("backup_id")`, an unconverted assignment -- serialized as the bare `Infinity`
/// token, since `json.dump`'s default `allow_nan=True` writes a non-finite float verbatim), while
/// a *separate* `str(manifest.get("backup_id"))` computed once up front for the `restore` audit
/// record's own `backup_id` field is the distinct *string* `"inf"` -- the two are not the same
/// value taking two paths, they are two different Python expressions over the same source field
/// (a previous version of this comment conflated them, claiming both ended up as the string
/// `"inf"`). `manifest` is not covered by the archive's digest (only `documents` is), so this
/// field is attacker/caller controlled in an otherwise digest-valid archive. `pyjson::loads` --
/// the module-wide, existing convention for any numeric literal that would overflow to a
/// non-finite `f64` -- rejects the *whole* archive as malformed before `Vault::restore` ever
/// inspects `manifest`, which is the deliberate, fail-closed choice recorded in `DEVIATIONS.md`
/// (finding E-R4-5) rather than an attempt to reproduce either of Python's two `inf`-derived
/// values.
#[test]
fn restore_rejects_overflowing_numeric_literal_in_manifest_python_parses_to_inf() {
    let tmp = TempDir::new().unwrap();
    let documents = json!({});
    let payload = pyjson::dumps(&documents, DumpOptions::compact_sorted()).unwrap();
    let digest = hex::encode(Sha256::digest(payload.as_bytes()));
    // Built by hand (not via `serde_json::Value`, which cannot represent an overflowing numeric
    // literal at all) so the raw `1e999` token reaches `pyjson::loads` unmodified.
    let archive_text = format!(
        r#"{{"manifest":{{"format":"zeropw-backup-v1","created_at":"2024-01-01T00:00:00Z","sha256":"{digest}","kms_key_id":"irrelevant-for-this-probe","backup_id":1e999}},"documents":{payload}}}"#,
    );
    let archive_path = tmp.path().join("archive.json");
    fs::write(&archive_path, &archive_text).unwrap();

    let rust_state = tmp.path().join("state-rust");
    let config = Config {
        socket_dir: Some(tmp.path().join("ctx-sockets")),
        run_dir: Some(tmp.path().join("ctx-run")),
        ..Config::default()
    };
    let ctx = Context::initialize(
        &rust_state,
        "admin-passphrase-1",
        "recovery-passphrase-1",
        config,
        clock::fixed(FIXED_NOW),
    )
    .unwrap();
    let err = zeropw::vault::Vault::restore(ctx.state, &archive_path, ctx.audit, Some(ctx.kms))
        .unwrap_err();
    assert_eq!(err.reason.to_string(), "backup_malformed");
}

// ------------------------------------ versions-key int() padding predicate (finding E-R5-5)
/// Ground truth against real `python3.12`: `int()` strips ordinary whitespace but *not*
/// U+001C-U+001F (`str.isspace()` is `True` for them, `int()` still raises `ValueError`).
/// Confirms the exact padding predicate `python_int_from_str` must use in `vault.rs`, then
/// checks the same divergence shows up through the real `Vault` API: a `versions` key with a
/// leading U+001C must be `state_corrupt`, not silently parsed as version 1.
#[test]
fn versions_key_int_padding_matches_pythons_int_not_str_isspace() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        socket_dir: Some(tmp.path().join("ctx-sockets")),
        run_dir: Some(tmp.path().join("ctx-run")),
        ..Config::default()
    };
    let ctx = Context::initialize(
        tmp.path().join("state"),
        "admin-passphrase-1",
        "recovery-passphrase-1",
        config,
        clock::fixed(FIXED_NOW),
    )
    .unwrap();
    ctx.projects
        .create("demo", projects::DEFAULT_ENVIRONMENTS)
        .unwrap();
    ctx.vault
        .put_secret(
            "gh-token",
            "api_key",
            b"synthetic-token-0123456789",
            "demo",
            "dev",
            true,
        )
        .unwrap();
    let mut doc = ctx
        .state
        .read_json(zeropw::vault::VAULT_DOC, Value::Null)
        .unwrap();
    let versions = doc["secrets"]["gh-token"]["versions"]
        .as_object_mut()
        .unwrap();
    let v1 = versions.remove("1").unwrap();
    versions.insert("\u{1c}1".to_string(), v1);
    ctx.state
        .write_json(zeropw::vault::VAULT_DOC, &doc)
        .unwrap();

    let err = ctx.vault.list_secrets(None, None).unwrap_err();
    assert_eq!(err.reason.to_string(), "state_corrupt");
}

// ------------------------------------------- Context::recover's int(clock())
/// Disaster recovery of the prototype-written state: the retired master key
/// and the new KMS key id are named from `int(clock())` exactly as the
/// prototype named them for the same clock (recorded by the fixture
/// generator), and the recovered state still decrypts.
#[test]
fn recover_of_a_python_state_names_files_like_python() {
    let tmp = TempDir::new().unwrap();
    let state = python_state(&tmp);
    let expected = &fixture_meta()["recover"];
    let clock_value = expected["clock"].as_f64().unwrap();

    let mut ctx = Context::open(&state, Config::default(), clock::fixed(clock_value)).unwrap();
    let revoked = ctx.recover("recovery-passphrase-1").unwrap();
    drop(ctx);
    assert_eq!(json!(revoked), expected["revoked"]);
    let mut names: Vec<String> = fs::read_dir(state.join("kms"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(json!(names), expected["kms_files"]);
    let key_id = fs::read_to_string(state.join("kms/master.key"))
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_string();
    assert_eq!(json!(key_id), expected["kms_key_id"]);

    // The recovered state still decrypts the prototype's secret.
    let ctx = Context::open(&state, Config::default(), clock::fixed(clock_value)).unwrap();
    let got = ctx.vault.secret_for_trusted_use("gh-token", None).unwrap();
    assert_eq!(
        sha256_hex(got.expose()),
        sha256_hex(fixture_meta()["secret_value"].as_str().unwrap().as_bytes())
    );
}
