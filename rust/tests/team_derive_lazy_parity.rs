//! `zeropw/team/fold.py`'s `derive_local` (`_derive_dek_generations`,
//! `_derive_vault`, `_derive_connections`) subscripts the folded document,
//! the local vault document and the local connections document directly;
//! an uncaught built-in exception aborts it at that point, after whatever
//! it already wrote. This differential runs CPython 3.12's and the port's
//! `derive_local` over a well-formed document and malformed variants of the
//! document and of both local documents, and compares the outcome (error or
//! success) and the resulting state (vault and connections documents with
//! wall-clock timestamps normalized, DEK files, audit records).
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{Map, Value, json};
use tempfile::TempDir;
use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::pyjson::{self, DumpOptions};
use zeropw::team::fold::{self as F, FoldResult};
use zeropw::team::identity::DeviceKey;

const ENV: &str = "envaaaaaaaaaaaaaaaaaaaaaaaaa-0123456789abcdef0123456789abcdef";
const GEN: &str = "00000000000000aa";
const V1: &str = "aaaaaaaaaaaaaaaa";
const FIXED_TS: &str = "2026-01-01T00:00:00Z";

fn python(script: &str) -> Value {
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".into());
    let mut child = Command::new(interpreter)
        .arg("-")
        .env("PYTHONPATH", format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

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
            V1: {"status": "active", "generation": GEN, "nonce": "AAAA", "ciphertext": "AAAA",
                "public": {"label": "x"}}}}},
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

const PY_DERIVE: &str = r#"
import json, os, shutil, sys, tempfile, pathlib
from zeropw.context import Config, Context
from zeropw.team import fold as F
from zeropw.team.identity import DeviceKey
from zeropw import policy as P
from zeropw.vault import VAULT_DOC

data = json.loads(sys.stdin.read())
root = pathlib.Path(tempfile.mkdtemp())
template = root / "template"
ctx = Context.initialize(template, "synthetic-admin", "synthetic-recovery", Config())
DeviceKey.load_or_create(ctx.state, ctx.kms)
ctx.state.write_json(f"team/{data['env']}/dek/{data['gen']}.json", {})
def vault_view(doc):
    # The vault's own key material differs per state; only its secrets map
    # is written by derive.
    return doc.get("secrets") if isinstance(doc, dict) else doc

out = {}
for i, (name, document, order, vault_doc, connections_doc) in enumerate(data["cases"]):
    target = root / f"c{i}"
    shutil.copytree(template, target)
    c = Context.open(target, Config())
    if vault_doc is not None:
        c.state.write_json(VAULT_DOC, vault_doc)
    if connections_doc is not None:
        c.state.write_json(P.CONNECTIONS, connections_doc)
    before = len(c.audit.tail(1000))
    device = DeviceKey.load_or_create(c.state, c.kms)
    result = F.FoldResult(document=document, skipped=[], version_order=order, vector={})
    try:
        F.derive_local(result, c.state, c.vault, c.policy, c.audit, device=device)
        outcome = "OK"
    except Exception as exc:
        outcome = "ERR " + type(exc).__name__
    audit = c.audit.tail(1000)[before:]
    for record in audit:
        record.pop("ts", None)
    dek_dir = c.state.path / "team" / data["env"] / "dek"
    out[name] = {"outcome": outcome,
                 "vault": vault_view(c.state.read_json(VAULT_DOC, None)),
                 "connections": c.state.read_json(P.CONNECTIONS, None),
                 "dek": sorted(p.name for p in dek_dir.iterdir()) if dek_dir.is_dir() else [],
                 "audit": audit}
print(json.dumps(out))
"#;

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
fn derive_local_fails_and_writes_exactly_like_python() {
    let cases = cases();
    let input = json!({"env": ENV, "gen": GEN, "cases": cases.iter().map(|(n, d, o, v, c)| json!([n, d, o, v, c])).collect::<Vec<_>>()});
    let script = format!(
        "import io, sys\nsys.stdin = io.StringIO({})\n{PY_DERIVE}",
        zeropw::pystr::repr_str(&pyjson::dumps(&input, DumpOptions::compact_sorted()).unwrap())
    );
    let python = python(&script);

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
            .write_json(&format!("team/{ENV}/dek/{GEN}.json"), &json!({}))
            .unwrap();
    }
    let mut mismatches = Vec::new();
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
        let mut expected = python[name.as_str()].clone();
        if expected["outcome"].as_str().unwrap().starts_with("ERR") {
            expected["outcome"] = json!("ERR");
        }
        if normalize(&rust) != normalize(&expected) {
            mismatches.push(format!(
                "{name}:\n  rust   {}\n  python {}",
                normalize(&rust),
                normalize(&expected)
            ));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    let outcomes: Map<String, Value> = python
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v["outcome"].clone()))
        .collect();
    // Both outcomes are exercised.
    assert_eq!(outcomes["base"], json!("OK"));
    assert!(outcomes.values().filter(|o| o != &&json!("OK")).count() > 20);
}
