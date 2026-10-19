//! `fold()` performs no up-front document validation (the Python
//! prototype's `fold.py` deep-copied `base_document` and each op handler
//! subscripted only what it touched). This folds every op kind over a
//! well-formed base document and over ~100 malformed variants of it
//! (missing keys, wrong container types, falsy and truthy non-dict entries,
//! stray `_version_order`, ...), with and without facts: the well-formed
//! document folds for every op, and every malformed variant either folds or
//! fails closed with an error -- never a panic. (The exact per-variant
//! outcomes were once compared one-for-one with CPython 3.12.)
use serde_json::{Value, json};
use zeropw::pyint::PyInt;
use zeropw::secret::SecretBytes;
use zeropw::team::commit::{self as C, Commit};
use zeropw::team::fold::{self as F, Facts};
use zeropw::team::identity::DeviceKey;

fn device(seed: u8) -> DeviceKey {
    DeviceKey {
        sign_seed: SecretBytes::from_slice(&[seed; 32]),
        agree_private: SecretBytes::from_slice(&[seed.wrapping_add(0x40); 32]),
    }
}

const GEN: &str = "00000000000000aa";
const V1: &str = "aaaaaaaaaaaaaaaa";

fn commit(author: &DeviceKey, env_id: &str, seq: i64, hlc: &str, op: Value) -> Commit {
    Commit {
        format: C::COMMIT_FORMAT.into(),
        env_id: env_id.into(),
        author: author.fingerprint().unwrap(),
        author_seq: PyInt::from(seq),
        hlc: hlc.into(),
        seen: Default::default(),
        ops: vec![op],
        sig: "c2ln".into(),
    }
}

fn connection_entry() -> Value {
    json!({"id": "gh", "project": "demo", "environment": "dev", "service": "github",
        "kind": "http", "secret_id": "s1", "secret_version": null, "description": "",
        "http_target": {"scheme": "https", "host": "api.github.com", "port": 443,
            "ca_file": null, "allow_private_network": false},
        "http_auth": {"mode": "bearer", "header_name": null, "value_prefix": null,
            "basic_username": null},
        "http_scope": {"methods": ["GET"], "path_prefixes": null, "confirm_methods": []},
        "ssh_target": null, "cli": null, "status": "active",
        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"})
}

/// `(path, replacement)`; `None` deletes the key.
type Mutation = (Vec<String>, Option<Value>);

fn mutations(owner: &str, m2: &str) -> Vec<Mutation> {
    let mut out: Vec<Mutation> = Vec::new();
    let mut put = |path: &[&str], values: Vec<Option<Value>>| {
        for v in values {
            out.push((path.iter().map(|s| s.to_string()).collect(), v));
        }
    };
    let falsy_and_shapes = || {
        vec![
            None,
            Some(Value::Null),
            Some(json!(0)),
            Some(json!(5)),
            Some(json!("")),
            Some(json!("x")),
            Some(json!([])),
            Some(json!(["x"])),
            Some(json!({})),
            Some(json!(true)),
        ]
    };
    put(
        &["owner"],
        vec![None, Some(Value::Null), Some(json!(5)), Some(json!(m2))],
    );
    put(&["members"], falsy_and_shapes());
    put(&["members", owner], falsy_and_shapes());
    put(
        &["members", owner, "status"],
        vec![None, Some(json!(5)), Some(json!("removed"))],
    );
    put(
        &["members", owner, "role"],
        vec![None, Some(json!(5)), Some(json!("user"))],
    );
    put(
        &["members", m2],
        vec![None, Some(json!(7)), Some(json!({}))],
    );
    put(
        &["members", m2, "status"],
        vec![None, Some(json!("removed"))],
    );
    put(&["connections"], falsy_and_shapes());
    put(
        &["connections"],
        vec![Some(json!(["gh"])), Some(json!("ghx"))],
    );
    put(&["connections", "gh"], falsy_and_shapes());
    put(
        &["connections", "gh", "status"],
        vec![None, Some(json!("disabled")), Some(json!(5))],
    );
    put(
        &["connections", "gh", "created_at"],
        vec![None, Some(json!("")), Some(json!(5))],
    );
    put(
        &["connections", "gh", "secret_id"],
        vec![None, Some(json!(5)), Some(json!(["s1"]))],
    );
    put(
        &["connections", "gh", "http_scope"],
        vec![
            Some(json!({"methods": ["GET"], "path_prefixes": [5]})),
            Some(json!({"methods": ["GET"], "path_prefixes": ["bad"]})),
        ],
    );
    put(&["secrets"], falsy_and_shapes());
    put(&["secrets"], vec![Some(json!(["s1"])), Some(json!("s1"))]);
    put(&["secrets", "s1"], falsy_and_shapes());
    put(
        &["secrets", "s1", "kind"],
        vec![None, Some(json!(5)), Some(json!("password"))],
    );
    put(
        &["secrets", "s1", "active_version"],
        vec![
            None,
            Some(json!([V1])),
            Some(json!(5)),
            Some(json!(V1)),
            Some(json!("zz")),
        ],
    );
    put(&["secrets", "s1", "versions"], falsy_and_shapes());
    put(
        &["secrets", "s1", "versions"],
        vec![Some(json!([V1])), Some(json!(V1))],
    );
    put(&["secrets", "s1", "versions", V1], falsy_and_shapes());
    put(
        &["secrets", "s1", "versions", V1, "status"],
        vec![None, Some(json!("revoked")), Some(json!("active"))],
    );
    put(&["dek"], falsy_and_shapes());
    put(&["dek", "generations"], falsy_and_shapes());
    put(
        &["dek", "generations"],
        vec![Some(json!([GEN])), Some(json!(GEN))],
    );
    put(&["dek", "generations", GEN], falsy_and_shapes());
    put(&["dek", "generations", GEN, "wraps"], falsy_and_shapes());
    put(&["dek", "current"], vec![None]);
    put(&["settings"], falsy_and_shapes());
    put(
        &["_version_order"],
        vec![
            Some(json!({"s1": 5})),
            Some(json!(5)),
            Some(json!({"s1": ["x", 1]})),
            Some(json!({"s1": "ab"})),
            Some(json!({"s1": {"k": 1}})),
            Some(json!([])),
            Some(Value::Null),
        ],
    );
    out
}

fn apply(doc: &Value, (path, value): &Mutation) -> Option<Value> {
    let mut doc = doc.clone();
    let mut cursor = &mut doc;
    for key in &path[..path.len() - 1] {
        cursor = cursor.as_object_mut()?.get_mut(key)?;
    }
    let map = cursor.as_object_mut()?;
    let last = path.last()?;
    match value {
        Some(v) => {
            map.insert(last.clone(), v.clone());
        }
        None => {
            map.remove(last);
        }
    }
    Some(doc)
}

/// `true` when the fold succeeded; a panic fails the test.
fn folds(env_id: &str, commits: &[Commit], doc: &Value, facts: Option<&Facts>) -> bool {
    F::fold(
        env_id,
        commits.to_vec(),
        facts,
        Some(doc.clone()),
        None,
        None,
    )
    .is_ok()
}

#[test]
fn fold_over_malformed_documents_fails_closed_without_panicking() {
    let owner = device(0x21);
    let member2 = device(0x22);
    let newcomer = device(0x23);
    let owner_fp = owner.fingerprint().unwrap();
    let m2_fp = member2.fingerprint().unwrap();
    let env_id = C::new_env_id(&owner_fp).unwrap();
    let base = json!({
        "env_id": env_id, "format": F::ENV_FORMAT, "owner": owner_fp,
        "members": {
            owner_fp.clone(): {"name": "alice", "role": "admin", "status": "active",
                "device": owner.record().unwrap().to_dict()},
            m2_fp.clone(): {"name": "bob", "role": "admin", "status": "active",
                "device": member2.record().unwrap().to_dict()},
        },
        "dek": {"current": GEN, "generations": {GEN: {"wraps": {owner_fp.clone(): {"eph_pub": "AAAA"}}}}},
        "connections": {"gh": connection_entry()},
        "secrets": {"s1": {"kind": "api_key", "active_version": null, "versions": {
            V1: {"status": "staged", "generation": GEN, "nonce": "AAAA", "ciphertext": "AAAA", "public": {}}}}},
        "settings": {"sync_interval_seconds": 10},
    });
    let wrap = json!({"eph_pub": "AAAA", "nonce": "AAAA", "ciphertext": "AAAA"});
    let create = {
        let mut entry = connection_entry();
        let obj = entry.as_object_mut().unwrap();
        for key in ["status", "created_at", "updated_at"] {
            obj.remove(key);
        }
        obj.insert("op".into(), json!("connection.create"));
        obj.insert("id".into(), json!("gh2"));
        entry
    };
    let ops: Vec<(&str, i64, Value)> = vec![
        (
            "env.init",
            1,
            json!({"op": "env.init", "owner_device": owner.record().unwrap().to_dict(),
                "owner_name": "alice", "generation_id": "00000000000000bb", "wraps": {owner_fp.clone(): wrap.clone()}}),
        ),
        ("connection.create", 2, create),
        (
            "connection.update",
            2,
            json!({"op": "connection.update", "id": "gh", "description": "new"}),
        ),
        (
            "connection.switch_credential",
            2,
            json!({"op": "connection.switch_credential", "id": "gh", "secret_id": "s1", "secret_version": V1}),
        ),
        (
            "connection.switch_credential.default",
            2,
            json!({"op": "connection.switch_credential", "id": "gh"}),
        ),
        (
            "connection.disable",
            2,
            json!({"op": "connection.disable", "id": "gh"}),
        ),
        (
            "secret.put_version",
            2,
            json!({"op": "secret.put_version", "secret_id": "s1", "kind": "api_key", "generation_id": GEN,
                "version_id": "bbbbbbbbbbbbbbbb", "ciphertext": {"nonce": "AAAA", "ciphertext": "AAAA"}, "public": {"a": 1}}),
        ),
        (
            "secret.put_version.new",
            2,
            json!({"op": "secret.put_version", "secret_id": "s2", "kind": "api_key", "generation_id": GEN,
                "version_id": "cccccccccccccccc", "ciphertext": {"nonce": "AAAA", "ciphertext": "AAAA"}}),
        ),
        (
            "secret.set_status",
            2,
            json!({"op": "secret.set_status", "secret_id": "s1", "version_id": V1, "status": "retired"}),
        ),
        (
            "secret.activate",
            2,
            json!({"op": "secret.activate", "secret_id": "s1", "version_id": V1}),
        ),
        (
            "member.add",
            2,
            json!({"op": "member.add", "device": newcomer.record().unwrap().to_dict(), "name": "carol",
                "role": "user", "wraps": {GEN: wrap.clone(), "00000000000000cc": wrap.clone()}}),
        ),
        (
            "member.set_role",
            2,
            json!({"op": "member.set_role", "fingerprint": m2_fp, "role": "user"}),
        ),
        (
            "member.remove",
            2,
            json!({"op": "member.remove", "fingerprint": m2_fp}),
        ),
        (
            "owner.transfer",
            2,
            json!({"op": "owner.transfer", "fingerprint": m2_fp}),
        ),
        (
            "dek.rotate",
            2,
            json!({"op": "dek.rotate", "generation_id": "00000000000000dd", "wraps": {owner_fp.clone(): wrap.clone()}}),
        ),
        (
            "settings.update",
            2,
            json!({"op": "settings.update", "sync_interval_seconds": 30}),
        ),
        ("unknown", 2, json!({"op": "nope"})),
    ];
    let mut rust_commits: Vec<(String, Vec<Commit>)> = Vec::new();
    for (name, seq, op) in &ops {
        let c = commit(
            &owner,
            &env_id,
            *seq,
            &format!("{}-0000", 1000 * seq),
            op.clone(),
        );
        rust_commits.push(((*name).into(), vec![c]));
    }
    // A member's self-removal and a non-admin author.
    let self_remove = commit(
        &member2,
        &env_id,
        1,
        "3000-0000",
        json!({"op": "member.remove", "fingerprint": m2_fp}),
    );
    rust_commits.push(("member.remove.self".into(), vec![self_remove]));
    // Every op in one fold, in total order.
    let all: Vec<Commit> = rust_commits
        .iter()
        .flat_map(|(_, c)| c.clone())
        .enumerate()
        .map(|(i, mut c)| {
            c.hlc = format!("{}-{:04}", 5000 + i, 0);
            c
        })
        .collect();
    rust_commits.push(("all".into(), all));

    let mut docs = vec![base.clone(), json!([]), json!(5), json!("doc")];
    for m in mutations(&owner_fp, &m2_fp) {
        if let Some(doc) = apply(&base, &m) {
            docs.push(doc);
        }
    }
    let facts = Facts {
        disabled_connections: ["gh".to_string()].into_iter().collect(),
        revoked_versions: [("s1".to_string(), V1.to_string())].into_iter().collect(),
        removed_members: [m2_fp.clone()].into_iter().collect(),
        incidents: Vec::new(),
        ..Default::default()
    };
    let mut errors = 0;
    let mut successes = 0;
    for (doc_index, doc) in docs.iter().enumerate() {
        for (name, commit_list) in &rust_commits {
            for facts in [None, Some(&facts)] {
                if folds(&env_id, commit_list, doc, facts) {
                    successes += 1;
                } else {
                    errors += 1;
                    assert_ne!(
                        doc_index,
                        0,
                        "op {name} facts={} must fold over the well-formed base document",
                        facts.is_some()
                    );
                }
            }
        }
    }
    // The sweep exercises both outcomes heavily.
    assert!(
        errors > 200 && successes > 1000,
        "{errors} errors, {successes} successes"
    );
}
