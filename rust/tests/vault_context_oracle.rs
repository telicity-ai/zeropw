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

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use tempfile::TempDir;

use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::errors::ErrorClass;
use zeropw::projects;

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
    assert_eq!(sha256_hex(&got), sha256_hex(value));
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
    assert_eq!(sha256_hex(&got), sha256_hex(value));
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
