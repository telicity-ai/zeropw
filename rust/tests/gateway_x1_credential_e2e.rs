//! End-to-end pinning test for cross-unit finding X-1: a peer-signed
//! `connection.create` op with a truthy, colon-free CONTAINER
//! `http_auth.basic_username` (e.g. `["curl"]`) folds and derives
//! successfully (finding H-R5-3 -- Python's `"in"` membership test on
//! `basic_username` never raises for a list), but must never let the
//! resulting `raw_basic_username` placeholder reach an outgoing
//! `Authorization` header when the connection is actually relayed through
//! (finding X-1): Python's own `_auth_header`, given that same connection,
//! raises an uncaught `AttributeError` (`'list' object has no attribute
//! 'encode'`) that nothing up to `relay` catches, so NO upstream request is
//! ever made and no credential leaves the process.
//!
//! Drives the full pipeline this finding's fix note calls for: a signed
//! commit -> `team::fold::fold` -> `team::fold::derive_local` (writing the
//! real `policy/connections.json` this node's `Policy` reads) ->
//! `gateway::relay` -- and asserts what (if anything) reaches a real
//! `FakeUpstream` listener.
//!
//! Lives under `rust/tests/` (a standalone integration-test binary) for the
//! same reason `team_fold.rs` does: it needs `Context::initialize` wired
//! together with `team::fold`'s `derive_local`, matching that file's
//! `derive()` helper pattern (mirrored here rather than imported, since
//! that helper is private to `team_fold.rs`).

use std::collections::BTreeMap;

use serde_json::{Map, json};
use tempfile::TempDir;

use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::fake_upstream::FakeUpstream;
use zeropw::gateway::{self, Headers};
use zeropw::projects;
use zeropw::team::commit::{self as C, Commit};
use zeropw::team::envelope;
use zeropw::team::fold::{self as F};
use zeropw::team::identity::DeviceKey;

const ADMIN: &str = "admin-pass-x1";
const RECOVERY: &str = "recovery-pass-x1";
const GEN0: &str = "0000000000000000";
const BOOTSTRAP_SECRET_VALUE: &[u8] = b"synthetic-bootstrap-real-credential-0123456789";

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
    secret_id: &str,
) -> (Commit, String) {
    let record = owner.record().unwrap();
    let wrap = envelope::wrap_dek(dek, env_id, GEN0, &record).unwrap();
    let mut wraps = Map::new();
    wraps.insert(owner.fingerprint().unwrap(), wrap);
    let op_init = json!({"op": "env.init", "owner_device": record.to_dict(), "owner_name": "alice",
                        "generation_id": GEN0, "wraps": wraps});
    let version_id = random_hex(8);
    let ct = envelope::encrypt_secret(dek, env_id, secret_id, &version_id, BOOTSTRAP_SECRET_VALUE)
        .unwrap();
    let op_secret = json!({"op": "secret.put_version", "secret_id": secret_id, "kind": "api_key",
                          "generation_id": GEN0, "version_id": version_id, "ciphertext": ct, "public": {}});
    let commit = C::sign_commit(
        owner,
        env_id,
        1,
        hlc,
        &BTreeMap::new(),
        vec![op_init, op_secret],
    )
    .unwrap();
    (commit, version_id)
}

/// A `connection.create` op whose `http_auth` is exactly the shape finding
/// H-R5-3/X-1 concerns: `mode: "basic"`, a truthy, colon-free list
/// `basic_username` -- accepted verbatim by Python's `"in"` membership
/// check (`HttpAuth(mode="basic", basic_username=["curl"])` constructs
/// fine, confirmed against real `python3.12`).
#[allow(clippy::too_many_arguments)]
fn connection_create_basic_container_commit(
    env_id: &str,
    author: &DeviceKey,
    seq: i128,
    hlc: &str,
    conn_id: &str,
    fake: &FakeUpstream,
    secret_id: &str,
    secret_version: &str,
) -> Commit {
    let op = json!({"op": "connection.create", "id": conn_id, "project": "demo", "environment": "dev",
                    "service": "github", "kind": "http", "secret_id": secret_id, "secret_version": secret_version,
                    "description": "", "http_target": {"scheme": fake.scheme(), "host": fake.host(), "port": fake.port()},
                    "http_auth": {"mode": "basic", "basic_username": ["curl"]},
                    "http_scope": {"methods": ["GET"], "path_prefixes": ["/repos"]}});
    C::sign_commit(author, env_id, seq, hlc, &BTreeMap::new(), vec![op]).unwrap()
}

#[test]
fn peer_op_basic_container_username_folds_derives_and_refuses_to_relay_without_touching_upstream() {
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

    // A real listener standing in for the upstream API: if `relay` ever
    // sends a byte to it, `fake.requests()` below will be non-empty.
    let fake = FakeUpstream::new("unused-fake-upstream-secret").start();

    let owner = DeviceKey::generate();
    let env_id = C::new_env_id(&owner.fingerprint().unwrap()).unwrap();
    let dek: Vec<u8> = (0..32u8).collect();
    let secret_id = "gh-token";
    let (c1, secret_version) = env_init_commit(&env_id, &owner, &dek, "1000-0000", secret_id);
    let c2 = connection_create_basic_container_commit(
        &env_id,
        &owner,
        2,
        "2000-0000",
        "gh",
        &fake,
        secret_id,
        &secret_version,
    );

    let fold_result = F::fold(&env_id, vec![c1, c2], None, None, None, None).expect(
        "fold succeeds: connection.create with a container basic_username is a REAL, \
                 Python-accepted document shape (H-R5-3), not something fold() should reject",
    );
    F::derive_local(
        &fold_result,
        ctx.state,
        &ctx.policy,
        Some(ctx.audit),
        Some(&owner),
        Some(ctx.kms),
        None,
        None,
    )
    .expect(
        "derive_local succeeds and derives the connection despite the representational gap \
         (finding X-2's sibling fix -- HttpAuth::from_value now accepts the container via \
         raw_basic_username instead of aborting the whole environment's derivation)",
    );

    // Sanity check: the derived, LOADED connection really does carry the
    // real container in `raw_basic_username`, not a lost/dropped value --
    // otherwise this test would not actually be exercising X-1's wire path.
    let connection = ctx.policy.get_connection("gh").expect("connection derived");
    let auth = connection
        .http_auth
        .as_ref()
        .expect("http connection has auth");
    assert_eq!(auth.mode, "basic");
    assert_eq!(
        auth.raw_basic_username,
        Some(json!(["curl"])),
        "the real basic_username container must survive fold -> derive_local -> Policy reload"
    );

    // Wire up a caller who can actually relay through this connection.
    ctx.policy.create_principal("agent-1", "cli").unwrap();
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
            connection.policy_version.to_i64().unwrap(),
            300,
            None,
        )
        .unwrap();

    let result = gateway::relay(&ctx, &handle, "GET", "/repos", &Headers::new(), b"", None);

    // Finding X-1: Python's `_auth_header` raises an uncaught
    // `AttributeError` here (confirmed against real `python3.12`,
    // `HttpAuth(mode="basic", basic_username=["curl"])` then
    // `gateway._auth_header(conn, secret)` -> `AttributeError: 'list'
    // object has no attribute 'encode'`), which nothing up to `relay`
    // catches -- so the relay is refused, not merely "blocked after
    // sending". `auth_header`'s `unsupported_auth_mode` is the closest
    // handled reason this path already uses (PORTING.md §3.5).
    assert_eq!(result.status, 501);
    assert_eq!(result.reason.as_deref(), Some("unsupported_auth_mode"));

    // The actual assertion this finding is about: nothing was ever sent to
    // the upstream. Before the fix, this relay would have sent
    // `Authorization: Basic <base64("\u{1}:" + the real secret)>` to
    // `fake` and consumed the grant use for a request Python never makes.
    assert_eq!(
        fake.requests().len(),
        0,
        "X-1: no upstream request may be made when basic_username is an unusable placeholder"
    );

    // The real credential never appears anywhere in the refusal either.
    let body = String::from_utf8_lossy(&result.body);
    assert!(!body.contains(&String::from_utf8_lossy(BOOTSTRAP_SECRET_VALUE).into_owned()));
}
