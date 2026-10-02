//! Cross-language differential tests for `zeropw::vault`/`zeropw::context`
//! against the Python prototype (`zeropw/vault.py`, `zeropw/context.py`), per
//! `rust/PORTING.md`'s "add oracle differential tests ... for every
//! cross-language format you own ... state directory round trips in both
//! directions" rule for work unit E.
//!
//! Lives under `rust/tests/` as a standalone test binary (like
//! `policy_oracle.rs`/`state_dir_cross_language.rs`): `crate::oracle` is
//! `#[cfg(test)] pub(crate)` and not reachable from here, so this file has
//! its own tiny Python-running helper.
//!
//! Covers:
//! - A state directory initialized by Python opens in Rust and Rust reads
//!   the same secret value (compared via a sha256 digest, never printed or
//!   compared as plaintext), and vice versa.
//! - A backup archive produced by Python restores correctly through Rust's
//!   `Vault::restore` (onto the same state directory, so the KMS-wrapped DEK
//!   the archive carries still unwraps), and vice versa.
//! - An admin passphrase set by `Context::initialize` in one language
//!   authenticates via `AdminCredential::verify` in the other.
//! - A handle issued by Python's `Context.handles.issue` verifies through
//!   Rust's `HandleIssuer::verify` on the same state directory (matching
//!   caller/connection/grant/policy_version), and vice versa.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::errors::ErrorClass;
use zeropw::projects;
use zeropw::pyjson::{self, DumpOptions};

const FIXED_NOW: f64 = 1_700_000_000.0;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn run_python(script: &str) -> String {
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".to_string());
    let output = Command::new(interpreter)
        .arg("-c")
        .arg(script)
        .env("PYTHONPATH", repo_root())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run python");
    assert!(
        output.status.success(),
        "python stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

fn py_str(p: &Path) -> String {
    let s = p.to_str().expect("utf8 path");
    format!("{s:?}")
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// A Python byte-string literal for an ASCII test value (every value this
/// file embeds is plain ASCII, so Rust's `{:?}` string escaping already
/// produces valid Python source).
fn py_bytes(data: &[u8]) -> String {
    format!(
        "b{:?}",
        std::str::from_utf8(data).expect("ascii test value")
    )
}

// ------------------------------------------------------- state dir round trip
#[test]
fn python_initialized_state_opens_in_rust_and_reads_the_same_secret() {
    let tmp = TempDir::new().unwrap();
    let state = tmp.path().join("state");
    let value = b"cross-lang-secret-py-to-rust";
    let script = format!(
        r#"
from zeropw.context import Context, Config
ctx = Context.initialize({state}, "admin-passphrase-1", "recovery-passphrase-1", Config(), lambda: {now})
ctx.projects.create("demo")
ctx.vault.put_secret("gh-token", "api_key", {value}, "demo", "dev")
print("ok")
"#,
        state = py_str(&state),
        now = FIXED_NOW,
        value = py_bytes(value),
    );
    run_python(&script);

    let ctx = Context::open(&state, Config::default(), clock::fixed(FIXED_NOW)).unwrap();
    let got = ctx.vault.secret_for_trusted_use("gh-token", None).unwrap();
    assert_eq!(sha256_hex(got.expose()), sha256_hex(value));
}

#[test]
fn rust_initialized_state_opens_in_python_and_reads_the_same_secret() {
    let tmp = TempDir::new().unwrap();
    let state = tmp.path().join("state");
    let value = b"cross-lang-secret-rust-to-py";
    {
        let ctx = Context::initialize(
            &state,
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
            .put_secret("gh-token", "api_key", value, "demo", "dev", true)
            .unwrap();
    }

    let script = format!(
        r#"
import hashlib
from zeropw.context import Context, Config
ctx = Context.open({state}, Config(), lambda: {now})
value = ctx.vault.secret_for_trusted_use("gh-token")
print(hashlib.sha256(value).hexdigest())
"#,
        state = py_str(&state),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    assert_eq!(out.trim(), sha256_hex(value));
}

#[test]
fn oversized_stored_version_matches_python_across_vault_and_admin_cli() {
    let tmp = TempDir::new().unwrap();
    let python_state = tmp.path().join("state-python");
    let rust_state = tmp.path().join("state-rust");
    let script = format!(
        r#"
import json
import os
import shutil
import subprocess
import sys
from zeropw.context import Context, Config
from zeropw.store import iso

state = {python_state}
rust_state = {rust_state}
version = 10 ** 80
ctx = Context.initialize(state, "admin-passphrase-1", "recovery-passphrase-1", Config(), lambda: {now})
ctx.projects.create("demo")
ctx.vault.put_secret("wide", "api_key", b"synthetic-seed", "demo", "dev")
doc = ctx.state.read_json("vault/secrets.json")
entry = doc["secrets"]["wide"]
record = ctx.vault._encrypt("wide", version, b"synthetic-wide")
record.update({{"created_at": iso(), "status": "active", "public": {{}}}})
entry["versions"] = {{str(version): record}}
entry["active_version"] = version
ctx.state.write_json("vault/secrets.json", doc)
ctx.close()
shutil.copytree(state, rust_state)

env = dict(os.environ, ZEROPW_ADMIN_PASSPHRASE="admin-passphrase-1")
base = [sys.executable, "-m", "zeropw.admin_cli", "--state-dir", str(state)]
revealed = subprocess.run(base + ["secret", "reveal", "--id", "wide", "--version", str(version)], env=env, check=True, capture_output=True, text=True)
reveal_doc = json.loads(revealed.stdout)
revoked = subprocess.run(base + ["secret", "revoke", "--id", "wide", "--version", str(version)], env=env, check=True, capture_output=True, text=True)
revoke_doc = json.loads(revoked.stdout)

ctx = Context.open(state, Config(), lambda: {now})
next_version = ctx.vault.put_secret("wide", "api_key", b"synthetic-next", "demo", "dev")
meta = ctx.vault.get_meta("wide")
print(json.dumps({{
    "revealed_version": str(reveal_doc["version"]),
    "revealed_value_matches": reveal_doc["value"] == "synthetic-wide",
    "revoked_version": str(revoke_doc["version"]),
    "next_version": str(next_version),
    "active_version": str(meta.active_version),
    "versions": [str(item.version) for item in meta.versions],
    "statuses": {{str(item.version): item.status for item in meta.versions}},
    "next_value_matches": ctx.vault.secret_for_trusted_use("wide") == b"synthetic-next",
}}, sort_keys=True))
"#,
        python_state = py_str(&python_state),
        rust_state = py_str(&rust_state),
        now = FIXED_NOW,
    );
    let python: Value = serde_json::from_str(run_python(&script).trim()).unwrap();
    let wide = format!("1{}", "0".repeat(80));
    let next = format!("1{}1", "0".repeat(79));

    let run_rust_admin = |args: &[&str]| -> Value {
        let output = Command::new(env!("CARGO_BIN_EXE_zeropw-admin"))
            .args(["--state-dir", rust_state.to_str().unwrap()])
            .args(args)
            .env("ZEROPW_ADMIN_PASSPHRASE", "admin-passphrase-1")
            .output()
            .expect("run Rust administrator CLI");
        assert!(
            output.status.success(),
            "Rust administrator stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("Rust administrator JSON")
    };
    let rust_reveal = run_rust_admin(&["secret", "reveal", "--id", "wide", "--version", &wide]);
    let rust_revoke = run_rust_admin(&["secret", "revoke", "--id", "wide", "--version", &wide]);
    let rust_ctx = Context::open(&rust_state, Config::default(), clock::fixed(FIXED_NOW)).unwrap();
    let rust_next = rust_ctx
        .vault
        .put_secret("wide", "api_key", b"synthetic-next", "demo", "dev", true)
        .unwrap();
    let rust_meta = rust_ctx.vault.get_meta("wide").unwrap();
    let rust = json!({
        "revealed_version": rust_reveal["version"].to_string(),
        "revealed_value_matches": rust_reveal["value"] == "synthetic-wide",
        "revoked_version": rust_revoke["version"].to_string(),
        "next_version": rust_next.to_string(),
        "active_version": rust_meta.active_version.as_ref().unwrap().to_string(),
        "versions": rust_meta.versions.iter().map(|item| item.version.to_string()).collect::<Vec<_>>(),
        "statuses": rust_meta.versions.iter().map(|item| (item.version.to_string(), item.status.clone())).collect::<std::collections::BTreeMap<_, _>>(),
        "next_value_matches": rust_ctx.vault.secret_for_trusted_use("wide", None).unwrap().expose() == b"synthetic-next",
    });

    assert_eq!(python["revealed_version"], wide);
    assert_eq!(python["revoked_version"], wide);
    assert_eq!(python["next_version"], next);
    assert_eq!(python["active_version"], next);
    assert_eq!(python["versions"], json!([wide, next]));
    assert_eq!(python["statuses"][wide.as_str()], "revoked");
    assert_eq!(python["statuses"][next.as_str()], "active");
    assert_eq!(python["revealed_value_matches"], true);
    assert_eq!(python["next_value_matches"], true);
    assert_eq!(rust, python);
}

// --------------------------------------------------------- backup / restore
#[test]
fn backup_made_by_python_restores_through_rust() {
    let tmp = TempDir::new().unwrap();
    let state = tmp.path().join("state");
    let backup = tmp.path().join("backup.json");
    let value = b"cross-lang-backup-py-to-rust";
    let script = format!(
        r#"
from pathlib import Path
from zeropw.context import Context, Config
ctx = Context.initialize({state}, "admin-passphrase-1", "recovery-passphrase-1", Config(), lambda: {now})
ctx.projects.create("demo")
ctx.vault.put_secret("gh-token", "api_key", {value}, "demo", "dev")
ctx.vault.backup(Path({backup}))
print("ok")
"#,
        state = py_str(&state),
        backup = py_str(&backup),
        now = FIXED_NOW,
        value = py_bytes(value),
    );
    run_python(&script);

    let ctx = Context::open(&state, Config::default(), clock::fixed(FIXED_NOW)).unwrap();
    zeropw::vault::Vault::restore(ctx.state, &backup, ctx.audit, Some(ctx.kms)).unwrap();
    let got = ctx.vault.secret_for_trusted_use("gh-token", None).unwrap();
    assert_eq!(sha256_hex(got.expose()), sha256_hex(value));
}

#[test]
fn backup_made_by_rust_restores_through_python() {
    let tmp = TempDir::new().unwrap();
    let state = tmp.path().join("state");
    let backup = tmp.path().join("backup.json");
    let value = b"cross-lang-backup-rust-to-py";
    {
        let ctx = Context::initialize(
            &state,
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
            .put_secret("gh-token", "api_key", value, "demo", "dev", true)
            .unwrap();
        ctx.vault.backup(&backup).unwrap();
    }

    let script = format!(
        r#"
import hashlib
from pathlib import Path
from zeropw.context import Context, Config
from zeropw.vault import Vault
ctx = Context.open({state}, Config(), lambda: {now})
Vault.restore(ctx.state, Path({backup}), ctx.audit, kms=ctx.kms)
value = ctx.vault.secret_for_trusted_use("gh-token")
print(hashlib.sha256(value).hexdigest())
"#,
        state = py_str(&state),
        backup = py_str(&backup),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    assert_eq!(out.trim(), sha256_hex(value));
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

/// Runs `Vault::restore`/`Vault.restore` over [`connections_corruption_archive`]
/// on two freshly (and identically) initialized state directories, one per
/// language, optionally with a pending `"connection"` revocation appended to
/// the ledger first (`policy::append_revocation`/`zeropw.policy.append_revocation`,
/// same `kind`/`id` shape in both). Returns `((rust_ok, rust_key_rotated),
/// (py_ok, py_key_rotated))`.
fn probe_connections_corruption(with_pending_revocation: bool) -> ((bool, bool), (bool, bool)) {
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

    let py_state = tmp.path().join("state-py");
    let revoke_line = if with_pending_revocation {
        r#"from zeropw.policy import append_revocation
append_revocation(ctx.state, "connection", id="conn-pending-revocation")"#
    } else {
        ""
    };
    let script = format!(
        r#"
from pathlib import Path
from zeropw.context import Context, Config, HANDLE_KEY
from zeropw.vault import Vault
ctx = Context.initialize({state}, "admin-passphrase-1", "recovery-passphrase-1", Config(), lambda: {now})
{revoke_line}
key_before = ctx.state.read_bytes(HANDLE_KEY)
try:
    Vault.restore(ctx.state, Path({archive}), ctx.audit)
    ok = True
except AttributeError:
    ok = False
except Exception as exc:
    print(f"unexpected:{{type(exc).__name__}}:{{exc}}")
    raise SystemExit(1)
key_after = ctx.state.read_bytes(HANDLE_KEY)
print("ok" if ok else "err", int(key_before != key_after))
"#,
        state = py_str(&py_state),
        archive = py_str(&archive_path),
        now = FIXED_NOW,
        revoke_line = revoke_line,
    );
    let out = run_python(&script);
    let mut parts = out.split_whitespace();
    let py_ok = parts.next().unwrap() == "ok";
    let py_key_rotated: u8 = parts.next().unwrap().parse().unwrap();
    let py_key_rotated = py_key_rotated != 0;
    ((rust_ok, rust_key_rotated), (py_ok, py_key_rotated))
}

/// No pending connection revocation: `Policy::reapply_revocations`'s lazy
/// read of `policy/connections.json` never runs, so the corrupted document
/// is never even looked at -- `restore` succeeds and rotates the handle key
/// in both languages.
#[test]
fn restore_reapply_revocations_connections_doc_corruption_matches_python_without_pending_revocation()
 {
    let (rust, py) = probe_connections_corruption(false);
    assert_eq!(
        rust,
        (true, true),
        "rust: restore must succeed and rotate the handle key"
    );
    assert_eq!(
        py,
        (true, true),
        "python: restore must succeed and rotate the handle key"
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
    let (rust, py) = probe_connections_corruption(true);
    assert_eq!(
        rust,
        (false, false),
        "rust: restore must fail and leave the handle key untouched"
    );
    assert_eq!(
        py,
        (false, false),
        "python: restore must fail (AttributeError) and leave the handle key untouched"
    );
}

// -------------------------------------------------- inside_state (finding E-1)
/// Builds one on-disk state directory (via a throwaway `Context::initialize`
/// with default config, so `socket_dir`/`run_dir` land outside `tmp`
/// entirely and cannot interfere with the probe), then asks Python's
/// `Context.open` and Rust's `Context::open` -- on that *same* state
/// directory and candidate path -- whether each accepts or refuses the
/// candidate as `socket_dir`, returning `(accepted, reason_if_refused)` for
/// each language so the caller can assert both the cross-language agreement
/// and the expected outcome.
fn probe_inside_state(
    build_candidate: impl FnOnce(&TempDir, &Path) -> PathBuf,
) -> ((bool, String), (bool, String)) {
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

    let rust_outcome = match Context::open(
        &state,
        Config {
            socket_dir: Some(candidate.clone()),
            ..Config::default()
        },
        clock::fixed(FIXED_NOW),
    ) {
        Ok(_) => (true, String::new()),
        Err(e) => (false, e.reason.to_string()),
    };

    let script = format!(
        r#"
from zeropw.context import Context, Config
from zeropw.errors import StateError
try:
    Context.open({state}, Config(socket_dir={candidate}), lambda: {now})
    print("ok")
except StateError as exc:
    print(f"err:{{exc.reason}}")
"#,
        state = py_str(&state),
        candidate = py_str(&candidate),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    let trimmed = out.trim();
    let py_outcome = if trimmed == "ok" {
        (true, String::new())
    } else {
        (
            false,
            trimmed.strip_prefix("err:").unwrap_or(trimmed).to_string(),
        )
    };
    (rust_outcome, py_outcome)
}

/// Reviewer probe 1: a non-existent leaf directly under the state dir.
#[test]
fn inside_state_matches_python_for_nonexistent_leaf() {
    let (rust, py) = probe_inside_state(|_tmp, state| state.join("sockets"));
    assert_eq!(rust, py);
    assert!(!rust.0, "must be refused: {rust:?}");
    assert_eq!(rust.1, "socket_dir_inside_state_dir");
}

/// Reviewer probe 2: an *existing* leaf directly under the state dir.
#[test]
fn inside_state_matches_python_for_existing_leaf() {
    let (rust, py) = probe_inside_state(|_tmp, state| {
        let candidate = state.join("sockets2");
        fs::create_dir_all(&candidate).unwrap();
        candidate
    });
    assert_eq!(rust, py);
    assert!(!rust.0, "must be refused: {rust:?}");
    assert_eq!(rust.1, "socket_dir_inside_state_dir");
}

/// Reviewer probe 3: a non-existent leaf reached through a lexical `..` that
/// cancels back into the state dir (`state/vault/../runs`; `state/vault`
/// already exists -- `Context::initialize` creates it).
#[test]
fn inside_state_matches_python_for_dotdot_back_into_state() {
    let (rust, py) = probe_inside_state(|_tmp, state| state.join("vault").join("..").join("runs"));
    assert_eq!(rust, py);
    assert!(!rust.0, "must be refused: {rust:?}");
    assert_eq!(rust.1, "socket_dir_inside_state_dir");
}

/// Reviewer probe 4: a non-existent leaf reached through a symlink whose
/// target is the state dir (`root/link/runs`, `root/link -> state`).
#[test]
fn inside_state_matches_python_for_symlink_to_state() {
    let (rust, py) = probe_inside_state(|tmp, state| {
        let root = tmp.path().join("root");
        fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(state, root.join("link")).unwrap();
        root.join("link").join("runs")
    });
    assert_eq!(rust, py);
    assert!(!rust.0, "must be refused: {rust:?}");
    assert_eq!(rust.1, "socket_dir_inside_state_dir");
}

/// Reviewer probe 5: the state dir itself.
#[test]
fn inside_state_matches_python_for_state_dir_itself() {
    let (rust, py) = probe_inside_state(|_tmp, state| state.to_path_buf());
    assert_eq!(rust, py);
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

/// Runs `Vault::restore(kms=Some(...))` (Rust) and `Vault.restore(kms=...)`
/// (Python) against the given archive, each on its own freshly initialized
/// state directory (restore's `vault_doc` handling here never touches
/// crypto -- the KMS pre-check is skipped entirely whenever `vault_doc` is
/// absent/`null` -- so two independently-initialized states are equivalent
/// probes). Returns `(rust_outcome, python_outcome)` as `Ok(())` or
/// `Err(reason)`.
fn probe_restore_vault_doc(archive: &Value) -> (Result<(), String>, Result<(), String>) {
    let tmp = TempDir::new().unwrap();
    let archive_path = tmp.path().join("archive.json");
    fs::write(&archive_path, serde_json::to_string(archive).unwrap()).unwrap();

    let rust_state = tmp.path().join("state-rust");
    let rust_outcome = {
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
    };

    let py_state = tmp.path().join("state-py");
    let script = format!(
        r#"
from pathlib import Path
from zeropw.context import Context, Config
from zeropw.vault import Vault
from zeropw.errors import StateError
ctx = Context.initialize({state}, "admin-passphrase-1", "recovery-passphrase-1", Config(), lambda: {now})
try:
    Vault.restore(ctx.state, Path({archive}), ctx.audit, kms=ctx.kms)
    print("ok")
except StateError as exc:
    print(f"err:{{exc.reason}}")
"#,
        state = py_str(&py_state),
        archive = py_str(&archive_path),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    let trimmed = out.trim();
    let py_outcome = if trimmed == "ok" {
        Ok(())
    } else {
        Err(trimmed.strip_prefix("err:").unwrap_or(trimmed).to_string())
    };
    (rust_outcome, py_outcome)
}

/// Reviewer case: `"vault/secrets.json": null` -- Python's `documents.get(...)`
/// treats a JSON `null` the same as a missing key, so the KMS pre-check is
/// skipped and the restore succeeds.
#[test]
fn restore_treats_explicit_null_vault_doc_as_absent_like_python() {
    let archive = minimal_backup_archive(Some(Value::Null));
    let (rust, py) = probe_restore_vault_doc(&archive);
    assert!(rust.is_ok(), "rust: {rust:?}");
    assert!(py.is_ok(), "python: {py:?}");
}

/// Reviewer case: the `vault/secrets.json` key is absent entirely.
#[test]
fn restore_treats_missing_vault_doc_key_as_absent_like_python() {
    let archive = minimal_backup_archive(None);
    let (rust, py) = probe_restore_vault_doc(&archive);
    assert!(rust.is_ok(), "rust: {rust:?}");
    assert!(py.is_ok(), "python: {py:?}");
}

/// Reviewer case: `vault_doc` present with a non-dict `dek` -- must still be
/// `backup_malformed` in both languages (unaffected by the E-4 fix).
#[test]
fn restore_rejects_vault_doc_with_non_dict_dek_in_both_languages() {
    let archive = minimal_backup_archive(Some(json!({"dek": "not-a-dict"})));
    let (rust, py) = probe_restore_vault_doc(&archive);
    assert_eq!(rust, Err("backup_malformed".to_string()));
    assert_eq!(py, Err("backup_malformed".to_string()));
}

// ---------------------------------- restore manifest backup_id repr (finding E-R3-3)
/// Builds a minimal, digest-valid backup archive (empty `documents`, so no
/// `vault_doc`/KMS interaction at all) whose `manifest.backup_id` is
/// `backup_id` verbatim -- the manifest is otherwise unauthenticated (the
/// digest only ever covers `documents`), so an attacker who can hand the
/// admin a backup file to restore controls this field completely, including
/// giving it a non-scalar JSON shape.
fn backup_id_manifest_archive(backup_id: Value) -> Value {
    let documents = json!({});
    let payload = pyjson::dumps(&documents, DumpOptions::compact_sorted()).unwrap();
    let digest = hex::encode(Sha256::digest(payload.as_bytes()));
    json!({
        "manifest": {
            "format": "zeropw-backup-v1",
            "created_at": "2024-01-01T00:00:00Z",
            "sha256": digest,
            "kms_key_id": "irrelevant-for-this-probe",
            "backup_id": backup_id,
        },
        "documents": documents,
    })
}

/// Runs `Vault::restore` (Rust) and `Vault.restore` (Python) against the same
/// `backup_id`-carrying archive, each on its own freshly initialized state
/// directory, and returns the `backup_id` field of the `restore` audit
/// record's `extra` each language actually wrote (`vault.py`: `backup_id =
/// str(manifest.get("backup_id"))`, stored into the audit record verbatim).
fn probe_restore_backup_id_repr(backup_id: &Value) -> (String, String) {
    let tmp = TempDir::new().unwrap();
    let archive = backup_id_manifest_archive(backup_id.clone());
    let archive_path = tmp.path().join("archive.json");
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
    zeropw::vault::Vault::restore(ctx.state, &archive_path, ctx.audit, None).unwrap();
    let records = ctx.audit.tail(1).unwrap();
    let rust_backup_id = records[0]
        .get("backup_id")
        .and_then(Value::as_str)
        .expect("restore audit record has a string backup_id field")
        .to_string();

    let py_state = tmp.path().join("state-py");
    let script = format!(
        r#"
from pathlib import Path
from zeropw.context import Context, Config
from zeropw.vault import Vault
ctx = Context.initialize({state}, "admin-passphrase-1", "recovery-passphrase-1", Config(), lambda: {now})
Vault.restore(ctx.state, Path({archive}), ctx.audit, kms=None)
records = ctx.audit.tail(1)
print(records[0]["backup_id"])
"#,
        state = py_str(&py_state),
        archive = py_str(&archive_path),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    (rust_backup_id, out.trim_end_matches('\n').to_string())
}

/// Reviewer case: `manifest.backup_id` is a JSON object. Python's `str(dict)`
/// falls back to `repr(dict)` (`"{'a': 1}"`), not a compact JSON rendering
/// (`{"a":1}` -- what the previous, buggy `python_str_scalar` catch-all
/// produced via `Value::to_string()`).
#[test]
fn restore_audit_backup_id_object_matches_python_repr() {
    let (rust, py) = probe_restore_backup_id_repr(&json!({"a": 1}));
    assert_eq!(py, "{'a': 1}", "python oracle sanity check");
    assert_eq!(rust, py);
}

/// Reviewer case: `manifest.backup_id` is a JSON array. Python's `str(list)`
/// falls back to `repr(list)` (`"[1, 2]"`).
#[test]
fn restore_audit_backup_id_array_matches_python_repr() {
    let (rust, py) = probe_restore_backup_id_repr(&json!([1, 2]));
    assert_eq!(py, "[1, 2]", "python oracle sanity check");
    assert_eq!(rust, py);
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

/// Reviewer requirement (finding E-R3-4): `int(v)` over a `versions` key
/// must match Python's `int()` exactly, not silently drop a key Python
/// accepts. Each of these forms is one Python's `int()` accepts but is not
/// a plain ASCII integer literal: leading/trailing whitespace, an
/// underscore digit-group separator, a fullwidth (non-ASCII) Unicode
/// decimal digit, a leading zero, and an explicit `+` sign. Cross-checked
/// against real `python3.12`'s own `list_secrets()` on the *same* on-disk
/// state directory (sequential opens, not concurrent -- `Vault::doc`/
/// `Vault._doc` both re-read the JSON file fresh on every call, so no
/// reopen is needed between the Rust write and the Rust read, and the
/// Python open happens strictly after both).
#[test]
fn list_secrets_version_key_parsing_matches_pythons_int_for_non_canonical_forms() {
    let cases: &[(&str, i64)] = &[
        (" 1", 1),
        ("1_0", 10),
        ("\u{ff11}", 1), // fullwidth digit one
        ("01", 1),
        ("+1", 1),
    ];
    for (key, expected) in cases {
        let tmp = TempDir::new().unwrap();
        let ctx = setup_single_secret_context(&tmp);
        let state = tmp.path().join("state");
        rename_sole_version_key(&ctx, "gh-token", key);

        let metas = ctx.vault.list_secrets(None, None).expect("list_secrets");
        assert_eq!(metas.len(), 1, "key={key:?}");
        assert_eq!(metas[0].versions.len(), 1, "key={key:?}");
        assert_eq!(metas[0].versions[0].version, *expected, "key={key:?}");

        let script = format!(
            r#"
from zeropw.context import Context, Config
ctx = Context.open({state}, Config(), lambda: {now})
metas = ctx.vault.list_secrets()
print(metas[0].versions[0].version)
"#,
            state = py_str(&state),
            now = FIXED_NOW,
        );
        let out = run_python(&script);
        let py_version: i64 = out
            .trim()
            .parse()
            .expect("python prints an integer version");
        assert_eq!(py_version, *expected, "key={key:?}");
    }
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
    let state = tmp.path().join("state");
    rename_sole_version_key(&ctx, "gh-token", "x");

    let err = ctx.vault.list_secrets(None, None).unwrap_err();
    assert_eq!(err.reason.to_string(), "state_corrupt");

    let script = format!(
        r#"
from zeropw.context import Context, Config
ctx = Context.open({state}, Config(), lambda: {now})
try:
    ctx.vault.list_secrets()
    print("ok")
except ValueError as exc:
    print(f"valueerror:{{exc}}")
except Exception as exc:
    print(f"othererror:{{type(exc).__name__}}:{{exc}}")
"#,
        state = py_str(&state),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    assert!(
        out.trim().starts_with("valueerror:"),
        "python must raise an uncaught ValueError for int(\"x\"), got: {out}"
    );
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
    let state = tmp.path().join("state");
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

    let script = format!(
        r#"
from zeropw.context import Context, Config
ctx = Context.open({state}, Config(), lambda: {now})
try:
    ctx.vault.put_secret("gh-token", "api_key", b"another-synthetic-token-012345", "demo", "dev", True)
    print("ok")
except KeyError as exc:
    print(f"keyerror:{{exc}}")
except Exception as exc:
    print(f"othererror:{{type(exc).__name__}}:{{exc}}")
"#,
        state = py_str(&state),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    assert!(
        out.trim().starts_with("keyerror:"),
        "python must raise an uncaught KeyError here, got: {out}"
    );
}

// ------------------------------------------ version key magnitude (finding E-R4-1)
/// Reviewer requirement (finding E-R4-1): `python_int_from_str` must accept `i64::MIN` (its
/// magnitude, one past `i64::MAX`, was previously rejected by a same-width unsigned-then-negate
/// parse step), and version keys wider than `i64` remain exact like Python's
/// unbounded `int()`.
#[test]
fn list_secrets_version_key_i64_min_matches_python() {
    let tmp = TempDir::new().unwrap();
    let ctx = setup_single_secret_context(&tmp);
    let state = tmp.path().join("state");
    rename_sole_version_key(&ctx, "gh-token", "-9223372036854775808");

    let metas = ctx.vault.list_secrets(None, None).expect("list_secrets");
    assert_eq!(metas[0].versions[0].version, i64::MIN);

    let script = format!(
        r#"
from zeropw.context import Context, Config
ctx = Context.open({state}, Config(), lambda: {now})
metas = ctx.vault.list_secrets()
print(metas[0].versions[0].version)
"#,
        state = py_str(&state),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    assert_eq!(out.trim(), i64::MIN.to_string());
}

/// A `versions` key outside `i64` remains exact in both metadata APIs.
#[test]
fn list_secrets_version_key_magnitude_outside_i64_matches_python() {
    let tmp = TempDir::new().unwrap();
    let ctx = setup_single_secret_context(&tmp);
    let state = tmp.path().join("state");
    rename_sole_version_key(&ctx, "gh-token", "100000000000000000000");

    let rust_version = &ctx.vault.list_secrets(None, None).unwrap()[0].versions[0].version;
    assert_eq!(rust_version.to_string(), "100000000000000000000");

    let script = format!(
        r#"
from zeropw.context import Context, Config
ctx = Context.open({state}, Config(), lambda: {now})
metas = ctx.vault.list_secrets()
print(metas[0].versions[0].version)
"#,
        state = py_str(&state),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    assert_eq!(
        out.trim(),
        "100000000000000000000",
        "python oracle sanity check: real python must still parse this key"
    );
}

/// `put_secret` computes `max(existing keys) + 1` with Python's arbitrary
/// precision. Both implementations must write and return `2**63` after an
/// `i64::MAX` key rather than rejecting, panicking, or wrapping.
#[test]
fn put_secret_next_version_at_i64_max_matches_python_two_pow_63() {
    let tmp = TempDir::new().unwrap();
    let ctx = setup_single_secret_context(&tmp);
    rename_sole_version_key(&ctx, "gh-token", "9223372036854775807");

    // `activate=false`: `rename_sole_version_key` only renames the `versions` object's key, not
    // `entry["active_version"]` (still `1` from `setup_single_secret_context`'s original
    // `put_secret`), and this test's whole point is the next-version arithmetic, not activation --
    // `activate=true`'s `entry["versions"][str(previous)]` would look up the now-renamed "1" key
    // and raise its own unrelated `KeyError` in Python before ever reaching the overflow this test
    // pins. `next_version`'s computation (and therefore the overflow) happens unconditionally
    // before the `activate` branch in both languages, so `false` still exercises the finding.
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
    assert_eq!(version.to_string(), "9223372036854775808");

    let py_state = tmp.path().join("state-py");
    let script = format!(
        r#"
from zeropw.context import Context, Config
ctx = Context.initialize({state}, "admin-passphrase-1", "recovery-passphrase-1", Config(), lambda: {now})
ctx.projects.create("demo")
ctx.vault.put_secret("gh-token", "api_key", b"synthetic-token-0123456789", "demo", "dev")
doc = ctx.state.read_json("vault/secrets.json")
versions = doc["secrets"]["gh-token"]["versions"]
versions["9223372036854775807"] = versions.pop("1")
ctx.state.write_json("vault/secrets.json", doc)
v = ctx.vault.put_secret("gh-token", "api_key", b"another-synthetic-token-012345", "demo", "dev", False)
print(v, type(v).__name__)
"#,
        state = py_str(&py_state),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    assert_eq!(
        out.trim(),
        "9223372036854775808 int",
        "python oracle sanity check: real python must return 2**63 and succeed here"
    );
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
    let state = tmp.path().join("state");
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

    let script = format!(
        r#"
from zeropw.context import Context, Config
ctx = Context.open({state}, Config(), lambda: {now})
try:
    ctx.vault.put_secret("gh-token", "api_key", b"another-synthetic-token-012345", "demo", "dev", True)
    print("ok")
except KeyError as exc:
    print(f"keyerror:{{exc}}")
except Exception as exc:
    print(f"othererror:{{type(exc).__name__}}:{{exc}}")
"#,
        state = py_str(&state),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    assert!(
        out.trim().starts_with("keyerror:"),
        "python must raise an uncaught KeyError for entry[\"project\"], got: {out}"
    );
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
    let state = tmp.path().join("state");
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

    let script = format!(
        r#"
from zeropw.context import Context, Config
ctx = Context.open({state}, Config(), lambda: {now})
try:
    ctx.vault.put_secret("gh-token", "api_key", b"another-synthetic-token-012345", "demo", "dev", True)
    print("ok")
except KeyError as exc:
    print(f"keyerror:{{exc}}")
except Exception as exc:
    print(f"othererror:{{type(exc).__name__}}:{{exc}}")
"#,
        state = py_str(&state),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    assert!(
        out.trim().starts_with("keyerror:"),
        "python must raise an uncaught KeyError for entry[\"versions\"], got: {out}"
    );
}

// ------------------------------------------ null secret entry (finding E-R4-2)
/// `secrets_obj.get(secret_id)` conflates a missing key with an explicit JSON `null`
/// (`dict.get` semantics) -- already fixed for `secret_for_trusted_use` in round 2 (E-R2-4a).
/// Round 4 found the same gap in `put_secret` (must create a fresh entry, returning version 1,
/// exactly like a genuinely absent secret id) and `set_version_status` (must raise the documented
/// `NotFound("secret_version_not_found")`), pinned here against real `python3.12` on matching
/// on-disk state directories.
fn init_context_with_null_ghost_entry(state: &Path) -> Context {
    // Explicit `socket_dir`/`run_dir` as siblings of `state` (both under the caller's own
    // `TempDir`), same reasoning as `setup_single_secret_context` above.
    let parent = state.parent().expect("state has a parent directory");
    let config = Config {
        socket_dir: Some(parent.join("ctx-sockets")),
        run_dir: Some(parent.join("ctx-run")),
        ..Config::default()
    };
    let ctx = Context::initialize(
        state,
        "admin-passphrase-1",
        "recovery-passphrase-1",
        config,
        clock::fixed(FIXED_NOW),
    )
    .unwrap();
    ctx.projects
        .create("demo", projects::DEFAULT_ENVIRONMENTS)
        .unwrap();
    let mut doc = ctx
        .state
        .read_json(zeropw::vault::VAULT_DOC, Value::Null)
        .unwrap();
    doc["secrets"]
        .as_object_mut()
        .unwrap()
        .insert("ghost".to_string(), Value::Null);
    ctx.state
        .write_json(zeropw::vault::VAULT_DOC, &doc)
        .unwrap();
    ctx
}

#[test]
fn put_secret_treats_explicit_null_secret_entry_as_absent_like_python() {
    let tmp = TempDir::new().unwrap();
    let rust_state = tmp.path().join("state-rust");
    let ctx = init_context_with_null_ghost_entry(&rust_state);
    let version = ctx
        .vault
        .put_secret(
            "ghost",
            "api_key",
            b"synthetic-token-0123456789",
            "demo",
            "dev",
            true,
        )
        .unwrap();
    assert_eq!(
        version, 1,
        "a null entry must be treated as absent, not corrupt"
    );

    let py_state = tmp.path().join("state-py");
    let script = format!(
        r#"
from zeropw.context import Context, Config
ctx = Context.initialize({state}, "admin-passphrase-1", "recovery-passphrase-1", Config(), lambda: {now})
ctx.projects.create("demo")
doc = ctx.state.read_json("vault/secrets.json")
doc["secrets"]["ghost"] = None
ctx.state.write_json("vault/secrets.json", doc)
version = ctx.vault.put_secret("ghost", "api_key", b"synthetic-token-0123456789", "demo", "dev", True)
print(version)
"#,
        state = py_str(&py_state),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    assert_eq!(out.trim(), "1");
}

#[test]
fn set_version_status_treats_explicit_null_secret_entry_as_absent_like_python() {
    let tmp = TempDir::new().unwrap();
    let rust_state = tmp.path().join("state-rust");
    let ctx = init_context_with_null_ghost_entry(&rust_state);
    let err = ctx
        .vault
        .set_version_status("ghost", &1.into(), "revoked")
        .unwrap_err();
    assert!(err.is(ErrorClass::NotFound));
    assert_eq!(err.reason.to_string(), "secret_version_not_found");

    let py_state = tmp.path().join("state-py");
    let script = format!(
        r#"
from zeropw.context import Context, Config
from zeropw.errors import NotFound
ctx = Context.initialize({state}, "admin-passphrase-1", "recovery-passphrase-1", Config(), lambda: {now})
ctx.projects.create("demo")
doc = ctx.state.read_json("vault/secrets.json")
doc["secrets"]["ghost"] = None
ctx.state.write_json("vault/secrets.json", doc)
try:
    ctx.vault.set_version_status("ghost", 1, "revoked")
    print("ok")
except NotFound as exc:
    print(f"notfound:{{exc.reason}}")
"#,
        state = py_str(&py_state),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    assert_eq!(out.trim(), "notfound:secret_version_not_found");
}

// ------------------------------------------ scalar field typing (finding E-R4-3)
/// Overwrites a top-level field of `secret_id`'s vault entry (`project`, `active_version`, ...).
fn overwrite_entry_field(ctx: &Context, secret_id: &str, key: &str, value: Value) {
    let mut doc = ctx
        .state
        .read_json(zeropw::vault::VAULT_DOC, Value::Null)
        .unwrap();
    doc["secrets"][secret_id]
        .as_object_mut()
        .expect("entry object")
        .insert(key.to_string(), value);
    ctx.state
        .write_json(zeropw::vault::VAULT_DOC, &doc)
        .unwrap();
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

/// A raw string active version survives metadata serialization and follows
/// Python's later `str(version)` record lookup and AAD construction.
#[test]
fn raw_string_active_version_round_trips_and_resolves_like_python() {
    let tmp = TempDir::new().unwrap();
    let ctx = setup_single_secret_context(&tmp);
    let state = tmp.path().join("state");
    overwrite_entry_field(&ctx, "gh-token", "active_version", json!("1"));

    let meta = ctx.vault.get_meta("gh-token").unwrap();
    assert_eq!(json!(meta.active_version), json!("1"));
    let resolved = ctx.vault.resolve_version("gh-token", None).unwrap();
    assert_eq!(resolved.value(), json!("1"));
    let rust_value = ctx.vault.secret_for_trusted_use("gh-token", None).unwrap();

    let script = format!(
        r#"
import hashlib
import json
from zeropw.context import Context, Config
ctx = Context.open({state}, Config(), lambda: {now})
value = ctx.vault.secret_for_trusted_use("gh-token")
meta = ctx.vault.get_meta("gh-token")
print(json.dumps({{"active": meta.active_version, "digest": hashlib.sha256(value).hexdigest()}}))
"#,
        state = py_str(&state),
        now = FIXED_NOW,
    );
    let out: Value = serde_json::from_str(run_python(&script).trim()).unwrap();
    assert_eq!(out["active"], json!("1"));
    assert_eq!(
        out["digest"],
        sha256_hex(rust_value.expose()),
        "both implementations must use the raw string for lookup and AAD"
    );
}

#[test]
fn raw_active_version_metadata_shapes_round_trip_like_python() {
    for raw in [
        json!(true),
        json!(false),
        json!(1.0),
        json!(0),
        json!("raw"),
        json!([]),
        json!({}),
        Value::Null,
    ] {
        let tmp = TempDir::new().unwrap();
        let ctx = setup_single_secret_context(&tmp);
        let state = tmp.path().join("state");
        overwrite_entry_field(&ctx, "gh-token", "active_version", raw.clone());
        let meta = ctx.vault.get_meta("gh-token").unwrap();
        assert_eq!(json!(meta.active_version), raw);
        let script = format!(
            r#"
import json
from zeropw.context import Context, Config
ctx = Context.open({state}, Config(), lambda: {now})
print(json.dumps(ctx.vault.get_meta("gh-token").active_version))
"#,
            state = py_str(&state),
            now = FIXED_NOW,
        );
        let python: Value = serde_json::from_str(run_python(&script).trim()).unwrap();
        assert_eq!(python, raw);
        if raw.is_null() {
            assert_eq!(
                ctx.vault
                    .resolve_version("gh-token", None)
                    .unwrap_err()
                    .reason,
                "secret_no_active_version"
            );
        } else {
            assert_eq!(
                ctx.vault.resolve_version("gh-token", None).unwrap().value(),
                raw
            );
        }
        assert_eq!(
            sha256_hex(
                ctx.vault
                    .secret_for_trusted_use("gh-token", Some(1.into()))
                    .unwrap()
                    .expose()
            ),
            sha256_hex(b"synthetic-token-0123456789")
        );
    }
}

#[test]
fn bool_active_version_uses_python_true_key_and_fails_when_absent() {
    let tmp = TempDir::new().unwrap();
    let ctx = setup_single_secret_context(&tmp);
    let state = tmp.path().join("state");
    overwrite_entry_field(&ctx, "gh-token", "active_version", json!(true));
    let rust = ctx
        .vault
        .secret_for_trusted_use("gh-token", None)
        .unwrap_err();
    assert_eq!(rust.reason, "state_corrupt");
    let script = format!(
        r#"
from zeropw.context import Context, Config
ctx = Context.open({state}, Config(), lambda: {now})
try:
    ctx.vault.secret_for_trusted_use("gh-token")
    print("ok")
except KeyError:
    print("KeyError")
"#,
        state = py_str(&state),
        now = FIXED_NOW,
    );
    assert_eq!(run_python(&script).trim(), "KeyError");
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
    let state = tmp.path().join("state");
    overwrite_sole_version_field(&ctx, "gh-token", "status", json!(5));

    let err = ctx
        .vault
        .secret_for_trusted_use("gh-token", None)
        .unwrap_err();
    assert_eq!(err.reason.to_string(), "secret_version_unusable");
    assert_eq!(err.detail, "5");

    let script = format!(
        r#"
from zeropw.context import Context, Config
from zeropw.errors import NotFound
ctx = Context.open({state}, Config(), lambda: {now})
try:
    ctx.vault.secret_for_trusted_use("gh-token")
    print("ok")
except NotFound as exc:
    print(f"notfound:{{exc.reason}}:{{exc.detail}}")
"#,
        state = py_str(&state),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    assert_eq!(out.trim(), "notfound:secret_version_unusable:5");
}

/// `public` is `[["a", 1]]`, a JSON array. Python's
/// `dict(r.get("public") or {})` coerces it to `{"a": 1}`; Rust must return
/// the same public metadata while retaining the malformed non-pair rejection below.
#[test]
fn list_secrets_public_pair_sequence_matches_python_dict_coercion() {
    let tmp = TempDir::new().unwrap();
    let ctx = setup_single_secret_context(&tmp);
    let state = tmp.path().join("state");
    overwrite_sole_version_field(&ctx, "gh-token", "public", json!([["a", 1]]));

    let rust_public = ctx.vault.list_secrets(None, None).unwrap()[0].versions[0]
        .public
        .clone();
    assert_eq!(rust_public, json!({"a": 1}));

    let script = format!(
        r#"
from zeropw.context import Context, Config
ctx = Context.open({state}, Config(), lambda: {now})
metas = ctx.vault.list_secrets()
print(metas[0].versions[0].public)
"#,
        state = py_str(&state),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    assert_eq!(
        out.trim(),
        "{'a': 1}",
        "python oracle sanity check: dict() really does coerce a pair sequence"
    );
}

/// Reviewer case: `public` is `"ab"`, a two-character string. Unlike the pair-sequence array
/// above, Python's `dict("ab")` genuinely raises an uncaught `ValueError` here (each character is
/// a length-1 "pair", not length-2) -- both languages must reject this record.
#[test]
fn list_secrets_public_non_pair_string_is_state_corrupt_in_both_languages() {
    let tmp = TempDir::new().unwrap();
    let ctx = setup_single_secret_context(&tmp);
    let state = tmp.path().join("state");
    overwrite_sole_version_field(&ctx, "gh-token", "public", json!("ab"));

    let err = ctx.vault.list_secrets(None, None).unwrap_err();
    assert_eq!(err.reason.to_string(), "state_corrupt");

    let script = format!(
        r#"
from zeropw.context import Context, Config
ctx = Context.open({state}, Config(), lambda: {now})
try:
    ctx.vault.list_secrets()
    print("ok")
except ValueError as exc:
    print(f"valueerror:{{exc}}")
except Exception as exc:
    print(f"othererror:{{type(exc).__name__}}:{{exc}}")
"#,
        state = py_str(&state),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    assert!(
        out.trim().starts_with("valueerror:"),
        "python must raise an uncaught ValueError for dict(\"ab\"), got: {out}"
    );
}

// ----------------------------------------------------- admin passphrase auth
#[test]
fn admin_passphrase_set_by_python_authenticates_in_rust() {
    let tmp = TempDir::new().unwrap();
    let state = tmp.path().join("state");
    let script = format!(
        r#"
from zeropw.context import Context, Config
Context.initialize({state}, "cross-admin-pw-py", "recovery-passphrase-1", Config(), lambda: {now})
print("ok")
"#,
        state = py_str(&state),
        now = FIXED_NOW,
    );
    run_python(&script);

    let ctx = Context::open(&state, Config::default(), clock::fixed(FIXED_NOW)).unwrap();
    let auth = ctx
        .admin
        .verify("cross-admin-pw-py", Some(FIXED_NOW))
        .unwrap();
    assert!(auth.fresh(Some(FIXED_NOW)));
    let err = ctx.admin.verify("wrong-one", Some(FIXED_NOW)).unwrap_err();
    assert!(err.is(ErrorClass::AuthFailed));
}

#[test]
fn admin_passphrase_set_by_rust_authenticates_in_python() {
    let tmp = TempDir::new().unwrap();
    let state = tmp.path().join("state");
    Context::initialize(
        &state,
        "cross-admin-pw-rust",
        "recovery-passphrase-1",
        Config::default(),
        clock::fixed(FIXED_NOW),
    )
    .unwrap();

    let script = format!(
        r#"
from zeropw.context import Context, Config
from zeropw.errors import AuthFailed
ctx = Context.open({state}, Config(), lambda: {now})
ctx.admin.verify("cross-admin-pw-rust", now={now})
try:
    ctx.admin.verify("wrong-one", now={now})
    print("UNEXPECTED_SUCCESS")
except AuthFailed:
    print("ok")
"#,
        state = py_str(&state),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    assert_eq!(out.trim(), "ok");
}

// ------------------------------------------------------------------ handles
#[test]
fn handle_issued_by_python_verifies_in_rust() {
    let tmp = TempDir::new().unwrap();
    let state = tmp.path().join("state");
    let script = format!(
        r#"
from zeropw import policy as P
from zeropw.context import Context, Config
ctx = Context.initialize({state}, "admin-passphrase-1", "recovery-passphrase-1", Config(), lambda: {now})
ctx.projects.create("demo")
ctx.vault.put_secret("gh-token", "api_key", b"cross-lang-handle-secret", "demo", "dev")
ctx.policy.create_principal("agent-1")
ctx.policy.create_connection(P.Connection(
    id="gh", project="demo", environment="dev", service="fake", kind="http", secret_id="gh-token",
    secret_version=None, description="", http_target=P.HttpTarget("http", "127.0.0.1", 1),
    http_auth=P.HttpAuth("bearer"), http_scope=P.HttpScope(), ssh_target=None, cli=None,
    policy_version=0, status="active", created_at="", updated_at=""))
grant = ctx.policy.create_grant("agent-1", "gh", 3600, None)
handle = ctx.handles.issue("agent-1", "gh", grant.id, grant.policy_version, 300, now={now})
print(handle)
print(grant.id)
"#,
        state = py_str(&state),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    let mut lines = out.lines();
    let handle = lines.next().unwrap().to_string();
    let grant_id = lines.next().unwrap().to_string();

    let ctx = Context::open(&state, Config::default(), clock::fixed(FIXED_NOW)).unwrap();
    let verified = ctx.handles.verify(&handle, Some(FIXED_NOW + 10.0)).unwrap();
    assert_eq!(verified.caller, "agent-1");
    assert_eq!(verified.connection, "gh");
    assert_eq!(verified.grant, grant_id);
    // `Policy::create_connection` always stamps a freshly created connection
    // to policy version 1, regardless of what the constructor was given.
    assert_eq!(verified.policy_version, 1);
}

#[test]
fn handle_issued_by_rust_verifies_in_python() {
    let tmp = TempDir::new().unwrap();
    let state = tmp.path().join("state");
    let (handle, grant_id) = {
        let ctx = Context::initialize(
            &state,
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
                b"cross-lang-handle-secret",
                "demo",
                "dev",
                true,
            )
            .unwrap();
        ctx.policy.create_principal("agent-1", "default").unwrap();
        let target = zeropw::policy::HttpTarget::new("http", "127.0.0.1", 1, None, false).unwrap();
        let auth = zeropw::policy::HttpAuth::bearer();
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
            Some(auth),
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
                grant.policy_version,
                300,
                Some(FIXED_NOW),
            )
            .unwrap();
        (handle, grant.id)
    };

    let handle_lit = format!("{handle:?}");
    let grant_id_lit = format!("{grant_id:?}");
    let script = format!(
        r#"
from zeropw.context import Context, Config
ctx = Context.open({state}, Config(), lambda: {now})
handle = ctx.handles.verify({handle}, now={now} + 10)
assert handle.caller == "agent-1"
assert handle.connection == "gh"
assert handle.grant == {grant_id}
assert handle.policy_version == 1
print("ok")
"#,
        state = py_str(&state),
        now = FIXED_NOW,
        handle = handle_lit,
        grant_id = grant_id_lit,
    );
    let out = run_python(&script);
    assert_eq!(out.trim(), "ok");
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
    let (rust, py) = probe_inside_state(|tmp, _state| {
        let root = tmp.path().join("rl");
        let real = tmp.path().join("realdir");
        fs::create_dir_all(&real).unwrap();
        build_symlink_chain(&root, &real, 51)
    });
    assert_eq!(rust, py);
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
    let (rust, py) = probe_inside_state(|tmp, _state| {
        let root = tmp.path().join("rl2");
        let real = tmp.path().join("realdir2");
        fs::create_dir_all(&real).unwrap();
        let head = build_symlink_chain(&root, &real, 51);
        head.join("does-not-exist-leaf")
    });
    assert_eq!(rust, py);
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
    let (rust, py) = probe_inside_state(|tmp, _state| {
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
    assert_eq!(rust, py);
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

    let script = format!(
        r#"
from zeropw.context import Context, Config
from zeropw.errors import StateError
try:
    Context.open({state}, Config(socket_dir={candidate}), lambda: {now})
    print("ok")
except StateError as exc:
    print(f"err:{{exc.reason}}")
except RuntimeError as exc:
    print(f"runtimeerror:{{exc}}")
"#,
        state = py_str(&state),
        candidate = py_str(&loop_path),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    assert!(
        out.trim().starts_with("runtimeerror:"),
        "python must raise an uncaught RuntimeError for a symlink loop, got: {out}"
    );
}

// ------------------------------------ restore non-ASCII manifest sha256 (finding E-R2-2b)
/// Reviewer case: `manifest["sha256"]` is a non-ASCII string. Python's `hmac.compare_digest`
/// only accepts bytes-like objects or *ASCII-only* strings; comparing the (always-ASCII-hex)
/// computed digest against a non-ASCII string raises an uncaught `TypeError`, escaping
/// `Vault.restore` entirely (not a `StateError`). Rust's `constant_time_eq` is a plain
/// constant-time byte comparison with no such restriction: the digests simply don't match, so
/// `Vault::restore` returns the ordinary `StateError("backup_digest_mismatch")` (DEVIATIONS.md,
/// finding E-R2-2b; PORTING.md §3.5).
#[test]
fn restore_rejects_non_ascii_manifest_sha256_python_raises_typeerror_rust_fails_closed() {
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
    assert_eq!(rust_err.reason.to_string(), "backup_digest_mismatch");

    let py_state = tmp.path().join("state-py");
    let script = format!(
        r#"
from pathlib import Path
from zeropw.context import Context, Config
from zeropw.vault import Vault
ctx = Context.initialize({state}, "admin-passphrase-1", "recovery-passphrase-1", Config(), lambda: {now})
try:
    Vault.restore(ctx.state, Path({archive}), ctx.audit, kms=ctx.kms)
    print("ok")
except TypeError as exc:
    print(f"typeerror:{{exc}}")
except Exception as exc:
    print(f"othererror:{{type(exc).__name__}}:{{exc}}")
"#,
        state = py_str(&py_state),
        archive = py_str(&archive_path),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    assert!(
        out.trim().starts_with("typeerror:"),
        "python must raise an uncaught TypeError comparing a non-ASCII sha256, got: {out}"
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

    let py_state_a = tmp.path().join("py-state-a");
    let py_state_b = tmp.path().join("py-state-b");
    let script = format!(
        r#"
from zeropw.context import Context, Config
cfg = Config()
a = Context.initialize({state_a}, "admin-passphrase-a", "recovery-passphrase-a", cfg, lambda: {now})
b = Context.initialize({state_b}, "admin-passphrase-b", "recovery-passphrase-b", cfg, lambda: {now})
print(a.config.socket_dir == b.config.socket_dir)
print(len(b._owned_dirs))
a.close()
b.close()
"#,
        state_a = py_str(&py_state_a),
        state_b = py_str(&py_state_b),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    let mut lines = out.lines();
    assert_eq!(
        lines.next().unwrap(),
        "True",
        "python's shared Config makes both contexts share one socket_dir"
    );
    assert_eq!(
        lines.next().unwrap(),
        "0",
        "python's second context does not own (and will not remove) the shared dir"
    );
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

    let py_state = tmp.path().join("state-py");
    let script = format!(
        r#"
import json
from pathlib import Path
from zeropw.context import Context, Config
from zeropw.vault import Vault
ctx = Context.initialize({state}, "admin-passphrase-1", "recovery-passphrase-1", Config(), lambda: {now})
manifest = Vault.restore(ctx.state, Path({archive}), ctx.audit, kms=None)
print(manifest["backup_id"])
control_raw = (Path({state}) / "policy" / "control.json").read_text()
control = json.loads(control_raw)
print(type(control["restored_from"]).__name__, control["restored_from"])
print("Infinity" in control_raw)
audit_lines = (Path({state}) / "audit" / "audit.jsonl").read_text().strip().splitlines()
last = json.loads(audit_lines[-1])
print(last["event"], type(last["backup_id"]).__name__, repr(last["backup_id"]))
"#,
        state = py_str(&py_state),
        archive = py_str(&archive_path),
        now = FIXED_NOW,
    );
    let out = run_python(&script);
    let mut lines = out.lines();
    assert_eq!(
        lines.next().unwrap().trim(),
        "inf",
        "python oracle sanity check: python must parse 1e999 to inf and restore successfully"
    );
    assert_eq!(
        lines.next().unwrap().trim(),
        "float inf",
        "control.json's `restored_from` must hold the *raw* float `inf`, not a string"
    );
    assert_eq!(
        lines.next().unwrap().trim(),
        "True",
        "the raw float must serialize as the bare `Infinity` token (json.dump's allow_nan=True)"
    );
    assert_eq!(
        lines.next().unwrap().trim(),
        "restore str 'inf'",
        "the restore audit record's `backup_id` must be the separately-computed *string* \"inf\", \
         not the same raw float `control.json` holds"
    );
}

// ------------------------------------ versions-key int() padding predicate (finding E-R5-5)
/// Ground truth against real `python3.12`: `int()` strips ordinary whitespace but *not*
/// U+001C-U+001F (`str.isspace()` is `True` for them, `int()` still raises `ValueError`).
/// Confirms the exact padding predicate `python_int_from_str` must use in `vault.rs`, then
/// checks the same divergence shows up through the real `Vault` API: a `versions` key with a
/// leading U+001C must be `state_corrupt`, not silently parsed as version 1.
#[test]
fn versions_key_int_padding_matches_pythons_int_not_str_isspace() {
    let script = r#"
ok = int(" 1\t")
try:
    int("\x1c1")
    bad_accepted = True
except ValueError:
    bad_accepted = False
print(ok, bad_accepted, "\x1c".isspace())
"#;
    let out = run_python(script);
    assert_eq!(
        out.trim(),
        "1 False True",
        "python3.12 ground truth: int() accepts ordinary whitespace but rejects U+001C even \
         though str.isspace() is True for it"
    );

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

// ------------------------------------ falsy NotFound detail suppression (finding E-R5-6)
/// Ground truth against real `python3.12`: `ZeroPWError.__init__`/`to_dict` suppress a *falsy*
/// `detail` (`0`, `False`, `None`, `[]`, `{}`) entirely, but keep a *truthy* one even when its
/// string form looks falsy (`"0"`, `"False"` are non-empty strings). This is the exact rule
/// `secret_for_trusted_use`'s `NotFound("secret_version_unusable", record["status"])` must
/// reproduce (finding E-R5-6); the Rust-side behaviour for both cases is pinned separately by
/// `vault_context.rs`'s `secret_version_unusable_suppresses_falsy_status_detail`/
/// `secret_version_unusable_keeps_truthy_string_status_detail`.
#[test]
fn zeropw_error_falsy_detail_suppression_ground_truth() {
    let script = r#"
from zeropw.errors import NotFound
for status in (0, False, None, [], {}, "0", "False"):
    exc = NotFound("secret_version_unusable", status)
    d = exc.to_dict()
    print(repr(status), "detail" in d, d.get("detail"))
"#;
    let out = run_python(script);
    let expected = "0 False None\n\
False False None\n\
None False None\n\
[] False None\n\
{} False None\n\
'0' True 0\n\
'False' True False";
    assert_eq!(out.trim(), expected);
}

// ------------------------------------ versions membership test shapes (finding E-R5-7)
/// Ground truth against real `python3.12`, reproducing `set_version_status`'s exact two
/// statements (`str(version) not in entry["versions"]` as a membership test, then the separate
/// `entry["versions"][str(version)]` indexing) over every non-dict `versions` shape this port
/// must handle identically.
#[test]
fn set_version_status_membership_test_matches_python_for_non_dict_versions_shapes() {
    let script = r#"
def probe(versions):
    entry = {"versions": versions}
    version = 1
    if str(version) not in entry["versions"]:
        return "not_found"
    try:
        entry["versions"][str(version)]
        return "indexed_ok"
    except TypeError:
        return "index_typeerror"

print(probe([]))
print(probe(["1"]))
print(probe("abc"))
print(probe("a1c"))
try:
    probe(None)
    print("none_ok")
except TypeError:
    print("none_typeerror")
try:
    probe(5)
    print("number_ok")
except TypeError:
    print("number_typeerror")
"#;
    let out = run_python(script);
    let lines: Vec<&str> = out.lines().map(str::trim).collect();
    assert_eq!(
        lines,
        vec![
            "not_found",        // []: membership test finds nothing, documented NotFound
            "index_typeerror",  // ["1"]: membership finds "1", but list[str] indexing then fails
            "not_found",        // "abc": substring membership finds nothing
            "index_typeerror",  // "a1c": substring membership finds "1", but str[str] then fails
            "none_typeerror",   // missing/None: `in` itself raises (not iterable)
            "number_typeerror", // a number: `in` itself raises (not iterable)
        ]
    );
}
