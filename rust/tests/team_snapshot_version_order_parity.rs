//! Snapshot `version_order` coercion and preservation of non-string
//! entries, and snapshot categories validated only when an operation reaches
//! them. Saved snapshot bytes are compared with the Python prototype's
//! (`tests/fixtures/python/team/snapshots/`); the other outcomes were
//! measured against it and are pinned explicitly.

use std::collections::BTreeMap;
use std::fs;

use serde_json::{Value, json};
use tempfile::TempDir;

use zeropw::secret::SecretBytes;
use zeropw::store::StateDir;
use zeropw::team::commit;
use zeropw::team::fold;
use zeropw::team::identity::DeviceKey;

fn signer() -> DeviceKey {
    DeviceKey {
        sign_seed: SecretBytes::from_slice(&[0x5e; 32]),
        agree_private: SecretBytes::from_slice(&[0x5f; 32]),
    }
}

#[test]
fn snapshot_version_order_successes_and_saved_bytes_match_python() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/python/team/snapshots/cases.json"
    );
    let cases: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let cases = cases.as_array().unwrap();
    // `null` documents with list/string/object orders, an existing document
    // key winning over the separately supplied map (popped and returned
    // unchanged with no ops), and a deliberately incomplete document no op
    // touches (returned unchanged instead of eagerly validated).
    assert_eq!(cases.len(), 5);
    for (index, case) in cases.iter().enumerate() {
        let tmp = TempDir::new().unwrap();
        let state_path = tmp.path().join("rust");
        let state = StateDir::new(&state_path);
        state.create().unwrap();
        state
            .write_json("team/env/snapshots/1.json", &case["snapshot"])
            .unwrap();
        let result = fold::fold_with_snapshot("env", vec![], &state, None, None).unwrap();
        fold::save_snapshot(&state, "env", &zeropw::pyint::PyInt::from(2), &result).unwrap();
        assert_eq!(
            serde_json::to_value(&result.version_order).unwrap(),
            case["version_order"],
            "case {index}"
        );
        assert_eq!(
            fs::read_to_string(state_path.join("team/env/snapshots/2.json")).unwrap(),
            case["saved"].as_str().unwrap(),
            "saved snapshot bytes, case {index}"
        );
    }
}

#[test]
fn snapshot_categories_are_validated_only_when_an_operation_reaches_them() {
    let fingerprint = signer().fingerprint().unwrap();
    // (label, document, op, skip reason, expected settings value)
    let cases = vec![
        (
            "unknown",
            json!({"opaque": {"connections": 5}, "settings": ["untouched"]}),
            json!({"op": "future.unknown", "id": "x"}),
            Some("unknown_op"),
            None,
        ),
        (
            "not_admin",
            json!({
                "env_id": "env",
                "owner": null,
                "members": {},
                "connections": 5,
                "secrets": ["untouched"],
                "dek": "untouched",
                "settings": 7,
            }),
            json!({"op": "settings.update", "sync_interval_seconds": 3}),
            Some("not_admin"),
            None,
        ),
        (
            "settings_only",
            json!({
                "owner": fingerprint,
                "members": {(fingerprint.clone()): {"status": "active", "role": "admin"}},
                "connections": 5,
                "secrets": ["untouched"],
                "dek": "untouched",
                "settings": {"sync_interval_seconds": 1},
            }),
            json!({"op": "settings.update", "sync_interval_seconds": 3}),
            None,
            Some(json!(3)),
        ),
    ];
    for (label, document, op, skip_reason, expected_setting) in cases {
        // Public fold accepts already-loaded commits. Construct this directly
        // so the deliberately unknown operation reaches fold instead of being
        // rejected by sign_commit's local authoring validation.
        let commit = commit::Commit {
            format: commit::COMMIT_FORMAT.to_owned(),
            env_id: "env".to_owned(),
            author: fingerprint.clone(),
            author_seq: zeropw::pyint::PyInt::from(1),
            hlc: "1000-0000".to_owned(),
            seen: BTreeMap::new(),
            ops: vec![op],
            sig: String::new(),
        };
        let snapshot = json!({"document": document, "vector": {}, "version_order": {}});
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("rust"));
        state.create().unwrap();
        state
            .write_json("team/env/snapshots/1.json", &snapshot)
            .unwrap();
        let rust =
            fold::fold_with_snapshot("env", vec![commit.clone()], &state, None, None).unwrap();

        // What the Python prototype's `fold_with_snapshot` produced: the
        // document untouched except by an applied op.
        let mut expected_document = snapshot["document"].clone();
        if let Some(setting) = expected_setting {
            expected_document["settings"]["sync_interval_seconds"] = setting;
        }
        let expected_skipped = match skip_reason {
            Some(reason) => json!([[commit.hash().unwrap(), 0, reason]]),
            None => json!([]),
        };
        assert_eq!(
            json!({
                "document": rust.document,
                "skipped": rust.skipped,
                "version_order": rust.version_order,
            }),
            json!({"document": expected_document, "skipped": expected_skipped, "version_order": {}}),
            "{label}"
        );
    }
}

#[test]
fn raw_version_order_valid_target_appends_without_touching_bad_sibling() {
    let signer = signer();
    let fingerprint = signer.fingerprint().unwrap();
    let document = json!({
        "env_id": "env",
        "owner": fingerprint,
        "members": {(fingerprint.clone()): {"status": "active", "role": "admin"}},
        "connections": {},
        "secrets": {},
        "dek": {"current": "0000000000000000", "generations": {"0000000000000000": {"wraps": {}}}},
        "settings": {},
        "_version_order": {"bad-unrelated": 5, "existing": ["v0"]},
    });
    let op = json!({
        "op": "secret.put_version", "secret_id": "new", "kind": "api_key",
        "generation_id": "0000000000000000", "version_id": "1111111111111111",
        "ciphertext": {"nonce": "AA==", "ciphertext": "AA=="}, "public": {},
    });
    let commit =
        commit::sign_commit(&signer, "env", 1, "1000-0000", &BTreeMap::new(), vec![op]).unwrap();
    let snapshot = json!({"document": document, "vector": {}, "version_order": {"ignored": []}});
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("rust"));
    state.create().unwrap();
    state
        .write_json("team/env/snapshots/1.json", &snapshot)
        .unwrap();
    let rust = fold::fold_with_snapshot("env", vec![commit], &state, None, None).unwrap();

    // The result the Python prototype's `fold_with_snapshot` produced.
    assert_eq!(
        json!({"document": rust.document, "version_order": rust.version_order}),
        json!({
            "document": {
                "connections": {},
                "dek": {"current": "0000000000000000",
                        "generations": {"0000000000000000": {"wraps": {}}}},
                "env_id": "env",
                "members": {(fingerprint.clone()): {"role": "admin", "status": "active"}},
                "owner": fingerprint,
                "secrets": {"new": {"active_version": null, "kind": "api_key", "versions": {
                    "1111111111111111": {"ciphertext": "AA==", "generation": "0000000000000000",
                                         "nonce": "AA==", "public": {}, "status": "staged"}}}},
                "settings": {},
            },
            "version_order": {"bad-unrelated": 5, "existing": ["v0"], "new": ["1111111111111111"]},
        })
    );
}
