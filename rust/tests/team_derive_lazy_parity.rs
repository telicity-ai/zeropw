//! `derive_local` (`derive_dek_generations`, `derive_vault`,
//! `derive_connections`) over a well-formed folded document and malformed
//! variants of the document and of both local documents. The Python
//! prototype subscripted these documents directly, so an uncaught built-in
//! exception aborted it at that point; the port fails closed with an error
//! at the same points. The per-case outcome (error or success) and the
//! well-formed case's resulting state (vault and connections documents with
//! wall-clock timestamps normalized, DEK files, audit records) were measured
//! against CPython 3.12 and are pinned here. The port derives only a version
//! that decrypts under its generation (issue #57), which Python did not
//! check, so the version is sealed under the key the template wraps for its
//! generation; Python copied `nonce` and `ciphertext` as given.
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;

use serde_json::{Value, json};
use tempfile::TempDir;
use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::team::envelope;
use zeropw::team::fold::{self as F, FoldResult};
use zeropw::team::identity::DeviceKey;

const ENV: &str = "envaaaaaaaaaaaaaaaaaaaaaaaaa-0123456789abcdef0123456789abcdef";
const GEN: &str = "00000000000000aa";
const V1: &str = "aaaaaaaaaaaaaaaa";
const FIXED_TS: &str = "2026-01-01T00:00:00Z";
/// `GEN`'s key, which the template wraps under its KMS.
const GENERATION_KEY: [u8; 32] = [7; 32];

/// `V1`'s `nonce` and `ciphertext`: a synthetic value sealed under `GEN`.
static SEALED_V1: LazyLock<serde_json::Map<String, Value>> = LazyLock::new(|| {
    envelope::encrypt_secret(&GENERATION_KEY, ENV, "s1", V1, b"synthetic-parity-value").unwrap()
});

fn connection(id: &str) -> Value {
    json!({"id": id, "project": "demo", "environment": "dev", "service": "github",
        "kind": "http", "secret_id": "s1", "secret_version": V1, "description": "",
        "http_target": {"scheme": "https", "host": "api.github.com", "port": 443,
            "ca_file": null, "allow_private_network": false},
        "http_auth": {"mode": "bearer", "header_name": null, "value_prefix": null,
            "basic_username": null},
        "http_scope": {"methods": ["GET"], "path_prefixes": null, "confirm_methods": []},
        "ssh_target": null, "cli": null, "status": "active",
        "created_at": FIXED_TS, "updated_at": FIXED_TS})
}

fn stored_connection(id: &str, env: &str) -> Value {
    let mut c = connection(id);
    c["policy_version"] = json!(1);
    c["secret_version"] = json!(1);
    c["shared_env"] = json!(env);
    c
}

fn base_document() -> Value {
    json!({
        "env_id": ENV,
        "dek": {"current": GEN, "generations": {GEN: {"wraps": {"zzzzzzzzzzzzzzzzzzzzzzzzzz": {"eph_pub": "AAAA"}}}}},
        "connections": {"gh": connection("gh")},
        "secrets": {"s1": {"kind": "api_key", "active_version": V1, "versions": {
            V1: {"status": "active", "generation": GEN, "nonce": SEALED_V1["nonce"],
                "ciphertext": SEALED_V1["ciphertext"], "public": {"label": "x"}}}}},
    })
}

/// `(name, document, version_order, vault document, connections document)`;
/// `None` leaves the local document as the template wrote it.
type Case = (String, Value, Value, Option<Value>, Option<Value>);

fn set(doc: &Value, path: &[&str], value: Option<Value>) -> Value {
    let mut doc = doc.clone();
    let mut cursor = &mut doc;
    for key in &path[..path.len() - 1] {
        cursor = cursor.get_mut(*key).unwrap();
    }
    let map = cursor.as_object_mut().unwrap();
    match value {
        Some(v) => {
            map.insert(path[path.len() - 1].into(), v);
        }
        None => {
            map.remove(path[path.len() - 1]);
        }
    }
    doc
}

fn cases() -> Vec<Case> {
    let base = base_document();
    let order = json!({"s1": [V1]});
    let mut out: Vec<Case> = Vec::new();
    let mut doc_case = |name: &str, path: &[&str], value: Option<Value>| {
        out.push((
            name.into(),
            set(&base, path, value),
            order.clone(),
            None,
            None,
        ));
    };
    doc_case("base", &["env_id"], Some(json!(ENV)));
    doc_case("no_env_id", &["env_id"], None);
    doc_case("no_dek", &["dek"], None);
    doc_case(
        "generations_list",
        &["dek", "generations"],
        Some(json!([GEN])),
    );
    doc_case(
        "generation_int",
        &["dek", "generations", GEN],
        Some(json!(5)),
    );
    doc_case(
        "generation_null",
        &["dek", "generations", GEN],
        Some(Value::Null),
    );
    doc_case(
        "generation_empty",
        &["dek", "generations", GEN],
        Some(json!({})),
    );
    doc_case(
        "wraps_int",
        &["dek", "generations", GEN, "wraps"],
        Some(json!(5)),
    );
    doc_case(
        "wraps_null",
        &["dek", "generations", GEN, "wraps"],
        Some(Value::Null),
    );
    doc_case("no_secrets", &["secrets"], None);
    doc_case("secrets_list", &["secrets"], Some(json!(["s1"])));
    doc_case("secret_int", &["secrets", "s1"], Some(json!(5)));
    doc_case("secret_empty", &["secrets", "s1"], Some(json!({})));
    doc_case(
        "versions_list",
        &["secrets", "s1", "versions"],
        Some(json!([V1])),
    );
    doc_case(
        "record_int",
        &["secrets", "s1", "versions", V1],
        Some(json!(5)),
    );
    doc_case(
        "unindexed_record_int",
        &["secrets", "s1", "versions", "bbbbbbbbbbbbbbbb"],
        Some(json!(5)),
    );
    doc_case(
        "no_generation",
        &["secrets", "s1", "versions", V1, "generation"],
        None,
    );
    doc_case(
        "generation_number",
        &["secrets", "s1", "versions", V1, "generation"],
        Some(json!(5)),
    );
    doc_case(
        "no_nonce",
        &["secrets", "s1", "versions", V1, "nonce"],
        None,
    );
    doc_case(
        "no_status",
        &["secrets", "s1", "versions", V1, "status"],
        None,
    );
    doc_case(
        "public_pairs",
        &["secrets", "s1", "versions", V1, "public"],
        Some(json!([["a", "b"]])),
    );
    doc_case(
        "public_string",
        &["secrets", "s1", "versions", V1, "public"],
        Some(json!("ab")),
    );
    doc_case(
        "public_int",
        &["secrets", "s1", "versions", V1, "public"],
        Some(json!(5)),
    );
    doc_case(
        "public_falsy",
        &["secrets", "s1", "versions", V1, "public"],
        Some(json!(0)),
    );
    doc_case(
        "active_list",
        &["secrets", "s1", "active_version"],
        Some(json!([V1])),
    );
    doc_case(
        "active_int",
        &["secrets", "s1", "active_version"],
        Some(json!(5)),
    );
    doc_case("no_kind", &["secrets", "s1", "kind"], None);
    doc_case("no_connections", &["connections"], None);
    doc_case("connections_list", &["connections"], Some(json!(["gh"])));
    doc_case("connection_int", &["connections", "gh"], Some(json!(5)));
    doc_case(
        "connection_no_secret_id",
        &["connections", "gh", "secret_id"],
        None,
    );
    doc_case(
        "connection_list_secret_id",
        &["connections", "gh", "secret_id"],
        Some(json!(["s1"])),
    );
    doc_case(
        "connection_list_version",
        &["connections", "gh", "secret_version"],
        Some(json!([V1])),
    );
    doc_case(
        "connection_unknown_version",
        &["connections", "gh", "secret_version"],
        Some(json!("cccccccccccccccc")),
    );
    let vault =
        |name: &str, v: Value| (name.to_string(), base.clone(), order.clone(), Some(v), None);
    out.push(vault("vault_falsy_list", json!([])));
    out.push(vault("vault_truthy_list", json!([1])));
    out.push(vault("vault_secrets_list", json!({"secrets": ["s1"]})));
    out.push(vault("vault_existing_int", json!({"secrets": {"s1": 5}})));
    out.push(vault("vault_existing_zero", json!({"secrets": {"s1": 0}})));
    out.push(vault(
        "vault_existing_other_env",
        json!({"secrets": {"s1": {"shared_env": "other"}}}),
    ));
    out.push(vault(
        "vault_existing_versions_int",
        json!({"secrets": {"s1": {"shared_env": ENV, "versions": 5}}}),
    ));
    out.push(vault(
        "vault_existing_version_int",
        json!({"secrets": {"s1": {"shared_env": ENV, "versions": {"1": 5}}}}),
    ));
    out.push(vault(
        "vault_existing_created_at",
        json!({"secrets": {"s1": {"shared_env": ENV, "created_at": 7,
            "versions": {"1": {"created_at": ["kept"]}}}}}),
    ));
    let conns =
        |name: &str, v: Value| (name.to_string(), base.clone(), order.clone(), None, Some(v));
    out.push(conns("connections_truthy_list", json!([1])));
    out.push(conns("connections_existing_int", json!({"gh": 5})));
    out.push(conns("connections_unrelated_int", json!({"other": 5})));
    out.push(conns(
        "connections_other_env",
        json!({"gh": {"shared_env": "other"}}),
    ));
    out.push(conns(
        "connections_stale_then_int",
        json!({"stale": stored_connection("stale", ENV), "zz": 5}),
    ));
    out.push(conns(
        "connections_existing_same",
        json!({"gh": stored_connection("gh", ENV)}),
    ));
    out
}

/// Strings that are wall-clock timestamps written during the run.
fn normalize(value: &Value) -> Value {
    match value {
        Value::String(s)
            if s != FIXED_TS
                && s.len() == 20
                && s.as_bytes()[4] == b'-'
                && s.as_bytes()[10] == b'T'
                && s.ends_with('Z') =>
        {
            json!("<now>")
        }
        Value::Array(items) => Value::Array(items.iter().map(normalize).collect()),
        Value::Object(map) => {
            Value::Object(map.iter().map(|(k, v)| (k.clone(), normalize(v))).collect())
        }
        other => other.clone(),
    }
}

/// The vault's own key material differs per state; only its `secrets` map
/// is written by derive.
fn vault_view(doc: Value) -> Value {
    match doc {
        Value::Object(map) => map.get("secrets").cloned().unwrap_or(Value::Null),
        other => other,
    }
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

#[test]
fn derive_local_fails_closed_exactly_where_python_raised() {
    let cases = cases();
    let expected_outcomes: BTreeMap<&str, &str> = [
        ("base", "OK"),
        ("no_env_id", "ERR"),
        ("no_dek", "ERR"),
        ("generations_list", "ERR"),
        ("generation_int", "ERR"),
        ("generation_null", "ERR"),
        ("generation_empty", "OK"),
        ("wraps_int", "ERR"),
        ("wraps_null", "ERR"),
        ("no_secrets", "ERR"),
        ("secrets_list", "ERR"),
        ("secret_int", "ERR"),
        ("secret_empty", "ERR"),
        ("versions_list", "ERR"),
        ("record_int", "ERR"),
        ("unindexed_record_int", "OK"),
        ("no_generation", "ERR"),
        ("generation_number", "OK"),
        ("no_nonce", "ERR"),
        ("no_status", "ERR"),
        ("public_pairs", "OK"),
        ("public_string", "ERR"),
        ("public_int", "ERR"),
        ("public_falsy", "OK"),
        ("active_list", "ERR"),
        ("active_int", "OK"),
        ("no_kind", "ERR"),
        ("no_connections", "ERR"),
        ("connections_list", "ERR"),
        ("connection_int", "ERR"),
        ("connection_no_secret_id", "ERR"),
        ("connection_list_secret_id", "ERR"),
        ("connection_list_version", "ERR"),
        ("connection_unknown_version", "OK"),
        ("vault_falsy_list", "OK"),
        ("vault_truthy_list", "ERR"),
        ("vault_secrets_list", "ERR"),
        ("vault_existing_int", "ERR"),
        ("vault_existing_zero", "ERR"),
        ("vault_existing_other_env", "OK"),
        ("vault_existing_versions_int", "ERR"),
        ("vault_existing_version_int", "ERR"),
        ("vault_existing_created_at", "OK"),
        ("connections_truthy_list", "ERR"),
        ("connections_existing_int", "ERR"),
        ("connections_unrelated_int", "ERR"),
        ("connections_other_env", "OK"),
        ("connections_stale_then_int", "ERR"),
        ("connections_existing_same", "OK"),
    ]
    .into_iter()
    .collect();
    assert_eq!(expected_outcomes.len(), cases.len());

    let root = TempDir::new().unwrap();
    let template = root.path().join("template");
    {
        let ctx = Context::initialize(
            &template,
            "synthetic-admin",
            "synthetic-recovery",
            Config::default(),
            clock::system(),
        )
        .unwrap();
        DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        ctx.state
            .write_json(
                &format!("team/{ENV}/dek/{GEN}.json"),
                &ctx.kms.wrap(&GENERATION_KEY).unwrap().to_dict(),
            )
            .unwrap();
    }
    for (i, (name, document, order, vault_doc, connections_doc)) in cases.iter().enumerate() {
        let target = root.path().join(format!("c{i}"));
        copy_dir(&template, &target);
        let ctx = Context::open(&target, Config::default(), clock::system()).unwrap();
        if let Some(v) = vault_doc {
            ctx.state.write_json(zeropw::vault::VAULT_DOC, v).unwrap();
        }
        if let Some(c) = connections_doc {
            ctx.state
                .write_json(zeropw::policy::CONNECTIONS, c)
                .unwrap();
        }
        let before = ctx.audit.tail(1000).unwrap().len();
        let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        let result = FoldResult {
            document: document.clone(),
            skipped: Vec::new(),
            version_order: order.clone(),
            vector: Default::default(),
            overridden: Vec::new(),
            fresh_connections: Default::default(),
        };
        let outcome = match F::derive_local(
            &result,
            ctx.state,
            &ctx.policy,
            Some(ctx.audit),
            Some(&device),
            Some(ctx.kms),
            None,
            None,
        ) {
            Ok(_) => "OK".to_string(),
            Err(_) => "ERR".to_string(),
        };
        let audit: Vec<Value> = ctx.audit.tail(1000).unwrap()[before..]
            .iter()
            .cloned()
            .map(|mut r| {
                r.as_object_mut().unwrap().remove("ts");
                r
            })
            .collect();
        let dek_dir = ctx.state.path.join("team").join(ENV).join("dek");
        let mut dek: Vec<String> = std::fs::read_dir(&dek_dir)
            .map(|d| {
                d.map(|e| e.unwrap().file_name().into_string().unwrap())
                    .collect()
            })
            .unwrap_or_default();
        dek.sort();
        let rust = json!({
            "outcome": outcome,
            "vault": vault_view(ctx.state.read_json(zeropw::vault::VAULT_DOC, Value::Null).unwrap()),
            "connections": ctx.state.read_json(zeropw::policy::CONNECTIONS, Value::Null).unwrap(),
            "dek": dek,
            "audit": audit,
        });
        assert_eq!(
            json!(outcome),
            json!(expected_outcomes[name.as_str()]),
            "{name}: {}",
            normalize(&rust)
        );
        if name == "base" {
            assert_eq!(normalize(&rust), base_expected(), "base");
        }
    }
    // Both outcomes are exercised.
    assert!(
        expected_outcomes
            .values()
            .filter(|outcome| **outcome == "ERR")
            .count()
            > 20
    );
}

/// The well-formed case's state as the Python prototype derived it (vault
/// `secrets` map, connections document, DEK files, audit records).
fn base_expected() -> Value {
    json!({
     "audit": [
      {
       "action": null,
       "caller": null,
       "connection": null,
       "count": 0,
       "env_id": ENV,
       "event": "team_commit_apply",
       "policy_version": null,
       "reason": null,
       "request_id": null,
       "result": "ok",
       "run_id": null,
       "target": null
      }
     ],
     "connections": {
      "gh": {
       "cli": null,
       "created_at": FIXED_TS,
       "description": "",
       "environment": "dev",
       "http_auth": {
        "basic_username": null,
        "header_name": null,
        "mode": "bearer",
        "value_prefix": null
       },
       "http_scope": {
        "confirm_methods": [],
        "methods": [
         "GET"
        ],
        "path_prefixes": null
       },
       "http_target": {
        "allow_private_network": false,
        "ca_file": null,
        "host": "api.github.com",
        "port": 443,
        "scheme": "https"
       },
       "id": "gh",
       "kind": "http",
       "policy_version": 1,
       "project": "demo",
       "secret_id": "s1",
       "secret_version": 1,
       "service": "github",
       "shared_env": ENV,
       "ssh_target": null,
       "status": "active",
       "updated_at": "<now>"
      }
     },
     "dek": [
      format!("{GEN}.json")
     ],
     "outcome": "OK",
     "vault": {
      "s1": {
       "active_version": 1,
       "created_at": "<now>",
       "environment": "shared",
       "kind": "api_key",
       "project": "shared-01234567",
       "shared_env": ENV,
       "versions": {
        "1": {
         "ciphertext": SEALED_V1["ciphertext"],
         "created_at": "<now>",
         "generation": GEN,
         "nonce": SEALED_V1["nonce"],
         "public": {
          "label": "x"
         },
         "shared_env": ENV,
         "status": "active",
         "version_id": V1
        }
       }
      }
     }
    })
}
