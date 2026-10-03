//! Cross-language compatibility tests for `zeropw::team` against golden
//! output of the retired Python prototype (`zeropw/team/`), stored under
//! `tests/fixtures/python/team/oracle/` (see its `GENERATE.md`).
//!
//! Covers the persisted-state and wire boundaries:
//! - Device identity: the SAME fixed seed pair derives byte-identical
//!   `DeviceRecord` fields (`sign_pub`, `agree_pub`, `sig`, fingerprint), and
//!   the Python-made record verifies here.
//! - `envelope.unwrap_dek`: a DEK wrapped by Python unwraps here.
//! - `commit.sign_commit`: the same device/env id/seq/hlc/seen/ops sign to
//!   byte-identical `Commit.to_dict()` (hash included) -- Ed25519 is
//!   deterministic and the canonical JSON encoder is byte-identical.
//! - `fold()`: a fixed commit history signed by Python folds to a
//!   byte-identical environment document, under several arrival orders.
//! - A commit store and snapshot written by Python load and fold here, and
//!   the same files written here are byte-identical.
//! - `humanview.to_yaml`/`strip_document`: byte-identical rendering.
//!
//! The remaining tests pin peer-input handling (lenient decoding, documented
//! rejection reasons, fail-closed outcomes) that was first measured against
//! the prototype; their expected values are now explicit.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};
use tempfile::TempDir;

use zeropw::pyint::PyInt;
use zeropw::pyjson::{self, DumpOptions};
use zeropw::secret::SecretBytes;
use zeropw::store::StateDir;
use zeropw::team::commit::{self as C, Commit};
use zeropw::team::envelope;
use zeropw::team::fold as F;
use zeropw::team::humanview;
use zeropw::team::identity::{DeviceKey, DeviceRecord};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/python/team/oracle")
}

/// `oracle.json`: every value the generator measured.
fn fixture() -> Value {
    let text = std::fs::read_to_string(fixture_dir().join("oracle.json")).expect("oracle fixture");
    serde_json::from_str(&text).expect("oracle fixture is JSON")
}

fn text(value: &Value) -> &str {
    value.as_str().expect("fixture string")
}

/// A Python `Commit.to_dict()` stored as its compact, key-sorted JSON text.
fn python_commit(value: &Value) -> Commit {
    Commit::from_dict(&pyjson::loads(text(value)).expect("fixture commit JSON"))
        .expect("python commit parses")
}

fn compact(value: &Value) -> String {
    pyjson::dumps(value, DumpOptions::compact_sorted()).unwrap()
}

fn fixed_device(seed_byte: u8, scalar_byte: u8) -> DeviceKey {
    DeviceKey {
        sign_seed: SecretBytes::from_slice(&[seed_byte; 32]),
        agree_private: SecretBytes::from_slice(&[scalar_byte; 32]),
    }
}

// ------------------------------------------------------------------ identity
#[test]
fn device_record_matches_python_for_a_fixed_seed_pair() {
    let fx = &fixture()["device_record"];
    let device = fixed_device(0x11, 0x22);
    let record = device.record().expect("record");
    assert_eq!(
        compact(&record.to_dict()),
        text(&fx["record"]),
        "DeviceRecord.to_dict() must match byte-for-byte"
    );
    assert_eq!(record.fingerprint(), text(&fx["fingerprint"]));
    assert!(record.verify());

    // The Python-produced record decodes and verifies here.
    let python_record =
        DeviceRecord::from_dict(&pyjson::loads(text(&fx["record"])).unwrap()).unwrap();
    assert!(python_record.verify());
    assert_eq!(python_record, record);
}

// ------------------------------------------------------------------ envelope
#[test]
fn wrap_in_python_unwrap_in_rust() {
    let fx = &fixture()["envelope"];
    let recipient = fixed_device(0x55, 0x66);
    let recovered = envelope::unwrap_dek(
        &fx["wrap"],
        text(&fx["env_id"]),
        text(&fx["generation_id"]),
        &recipient,
    )
    .unwrap();
    assert_eq!(hex::encode(recovered), text(&fx["dek_hex"]));
    // Bound to the env id and generation it was wrapped for.
    assert!(
        envelope::unwrap_dek(
            &fx["wrap"],
            text(&fx["env_id"]),
            "0000000000000000",
            &recipient
        )
        .is_err()
    );
}

/// A Rust wrap has the Python wrap's shape (same fields, same encoded
/// lengths) and round-trips.
#[test]
fn wrap_in_rust_has_the_python_shape_and_round_trips() {
    let python_wrap = fixture()["envelope"]["wrap"].clone();
    let recipient = fixed_device(0x33, 0x44);
    let record = recipient.record().unwrap();
    let dek: Vec<u8> = (0..32u8).collect();
    let env_id = "0123456789abcdef0123456789abcdef";
    let generation_id = "deadbeefcafef00d";
    let wrap = envelope::wrap_dek(&dek, env_id, generation_id, &record).unwrap();
    let keys = |v: &Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
    let mut rust_keys = keys(&wrap);
    let mut python_keys = keys(&python_wrap);
    rust_keys.sort();
    python_keys.sort();
    assert_eq!(rust_keys, python_keys);
    for field in &python_keys {
        assert_eq!(
            text(&wrap[field]).len(),
            text(&python_wrap[field]).len(),
            "{field}"
        );
    }
    let recovered = envelope::unwrap_dek(&wrap, env_id, generation_id, &recipient).unwrap();
    assert_eq!(recovered, dek);
}

// -------------------------------------------------------------------- commit
fn env_init_op(owner_record: &DeviceRecord, name: &str, generation_id: &str) -> Value {
    let mut wraps = Map::new();
    wraps.insert(
        owner_record.fingerprint(),
        json!({"eph_pub": "AAAA", "nonce": "AAAA", "ciphertext": "AAAA"}),
    );
    json!({"op": "env.init", "owner_device": owner_record.to_dict(), "owner_name": name,
          "generation_id": generation_id, "wraps": wraps})
}

#[test]
fn sign_commit_matches_python_byte_for_byte() {
    let fx = &fixture()["sign_commit"];
    let owner = fixed_device(0x77, 0x88);
    let record = owner.record().unwrap();
    let env_id = text(&fx["env_id"]);
    assert_eq!(
        C::env_owner_fingerprint(env_id).unwrap(),
        record.fingerprint()
    );
    let op = env_init_op(&record, "alice-laptop", &"0".repeat(16));
    let c1 = C::sign_commit(&owner, env_id, 1, "1000-0000", &BTreeMap::new(), vec![op]).unwrap();
    assert_eq!(
        compact(&c1.to_dict()),
        text(&fx["commit"]),
        "Commit.to_dict() must match byte-for-byte"
    );
    assert_eq!(c1.hash().unwrap(), text(&fx["hash"]));
    assert!(C::verify_commit(&c1, &record));

    // The Python-signed commit, parsed and verified here.
    let restored = python_commit(&fx["commit"]);
    assert_eq!(restored.hash().unwrap(), text(&fx["hash"]));
    assert!(C::verify_commit(&restored, &record));
}

// ---------------------------------------------------------------------- fold
/// The env id the fixture history was signed under (`<owner fp>-<fixed hex>`).
fn history_env_id() -> String {
    text(&fixture()["history"]["env_id"]).to_owned()
}

/// A small, fixed commit history (env.init, member.add, a secret, two
/// connection.create, a disable, a settings.update) signed with fixed-seed
/// device keys -- the same history the Python generator signed.
fn build_history() -> (String, Vec<Commit>, DeviceRecord, DeviceRecord) {
    let owner = fixed_device(0x10, 0x20);
    let second = fixed_device(0x30, 0x40);
    let owner_record = owner.record().unwrap();
    let second_record = second.record().unwrap();
    let env_id = history_env_id();
    assert_eq!(
        C::env_owner_fingerprint(&env_id).unwrap(),
        owner_record.fingerprint()
    );

    let gen0 = "0".repeat(16);
    let c1 = C::sign_commit(
        &owner,
        &env_id,
        1,
        "1000-0000",
        &BTreeMap::new(),
        vec![env_init_op(&owner_record, "alice", &gen0)],
    )
    .unwrap();
    let c2 = C::sign_commit(
        &owner,
        &env_id,
        2,
        "2000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "member.add", "device": second_record.to_dict(), "name": "bob", "role": "admin"})],
    )
    .unwrap();
    // Finding H-1: without a `secret.put_version` for "gh-token", both
    // `connection.create` ops below are skipped at fold time
    // (`secret_not_found`), so the whole connection path -- including the
    // `http_scope`/`ssh_target` tuple-rendering `to_yaml` bug -- went
    // untested.
    let c3 = C::sign_commit(
        &owner,
        &env_id,
        3,
        "2500-0000",
        &BTreeMap::new(),
        vec![
            json!({"op": "secret.put_version", "secret_id": "gh-token", "kind": "api_key",
                  "generation_id": gen0, "version_id": "1".repeat(16),
                  "ciphertext": {"nonce": "AAAA", "ciphertext": "BBBB"}, "public": {}}),
        ],
    )
    .unwrap();
    let conn_op = |conn_id: &str| {
        json!({"op": "connection.create", "id": conn_id, "project": "demo", "environment": "dev",
              "service": "github", "kind": "http", "secret_id": "gh-token", "secret_version": null,
              "description": "", "http_target": {"scheme": "https", "host": "api.github.com", "port": 443},
              "http_auth": {"mode": "bearer"}, "http_scope": {"methods": ["GET"], "path_prefixes": ["/repos"]}})
    };
    let c4 = C::sign_commit(
        &owner,
        &env_id,
        4,
        "3000-0000",
        &BTreeMap::new(),
        vec![conn_op("gh")],
    )
    .unwrap();
    let c5 = C::sign_commit(
        &second,
        &env_id,
        1,
        "3000-0000",
        &BTreeMap::new(),
        vec![conn_op("gitlab")],
    )
    .unwrap();
    let c6 = C::sign_commit(
        &owner,
        &env_id,
        5,
        "4000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "connection.disable", "id": "gh"})],
    )
    .unwrap();
    let c7 = C::sign_commit(
        &second,
        &env_id,
        2,
        "5000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "settings.update", "sync_interval_seconds": 42})],
    )
    .unwrap();
    (
        env_id,
        vec![c1, c2, c3, c4, c5, c6, c7],
        owner_record,
        second_record,
    )
}

fn python_history() -> Vec<Commit> {
    fixture()["history"]["commits"]
        .as_array()
        .unwrap()
        .iter()
        .map(python_commit)
        .collect()
}

#[test]
fn history_signs_byte_identically_to_python() {
    let (_env_id, commits, _owner, _second) = build_history();
    let fx = fixture();
    let python: Vec<&str> = fx["history"]["commits"]
        .as_array()
        .unwrap()
        .iter()
        .map(text)
        .collect();
    let rust: Vec<String> = commits.iter().map(|c| compact(&c.to_dict())).collect();
    assert_eq!(rust, python);
}

#[test]
fn fold_matches_python_for_a_fixed_commit_history() {
    let env_id = history_env_id();
    let fx = fixture();
    let py_doc_text = text(&fx["history"]["document"]);
    let commits = python_history();
    let rust_result = F::fold(&env_id, commits.clone(), None, None, None, None).unwrap();
    assert!(rust_result.skipped.is_empty());
    assert_eq!(
        compact(&rust_result.document),
        py_doc_text,
        "fold() must produce a byte-identical document"
    );

    // Order independence: fold the same history under fixed-seed shuffles.
    let mut seeds = [0x9u64, 0x99, 0x999, 0x9999];
    for seed in seeds.iter_mut() {
        let mut shuffled = commits.clone();
        for i in (1..shuffled.len()).rev() {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            let j = (*seed as usize) % (i + 1);
            shuffled.swap(i, j);
        }
        let result = F::fold(&env_id, shuffled, None, None, None, None).unwrap();
        assert_eq!(
            compact(&result.document),
            py_doc_text,
            "a shuffled arrival order diverged from the python document"
        );
    }
}

// ----------------------------------------------------------------- humanview
#[test]
fn humanview_matches_python_for_the_folded_history() {
    let env_id = history_env_id();
    let fx = fixture();
    let rust_result = F::fold(&env_id, python_history(), None, None, None, None).unwrap();
    let stripped = humanview::strip_document(&rust_result.document);
    // Every connection in the history is created within this single
    // `fold()` call, so all of them are "fresh" (finding H-R2-7).
    let rust_yaml = humanview::to_yaml(&stripped, &rust_result.fresh_connections);

    assert_eq!(
        compact(&stripped),
        text(&fx["history"]["stripped"]),
        "strip_document() must match byte-for-byte"
    );
    assert_eq!(
        rust_yaml,
        text(&fx["history"]["yaml"]),
        "to_yaml() must match byte-for-byte"
    );

    // Finding H-1: `dataclasses.asdict(Connection(...))` kept
    // `HttpScope.methods`/`path_prefixes`/`confirm_methods` as Python
    // tuples, which `to_yaml` renders as `str(tuple)`. Assert the concrete
    // shape too, so a fixture regenerated with the connections skipped
    // fails loudly here.
    assert!(
        rust_yaml.contains("methods: ('GET',)"),
        "http_scope.methods must render as a Python tuple repr:\n{rust_yaml}"
    );
    assert!(
        rust_yaml.contains("path_prefixes: ('/repos',)"),
        "http_scope.path_prefixes must render as a Python tuple repr:\n{rust_yaml}"
    );
    assert!(
        rust_yaml.contains("confirm_methods: ()"),
        "http_scope.confirm_methods must render as an empty Python tuple repr:\n{rust_yaml}"
    );
}

/// Copies the Python-written `team/<env>/...` tree into a fresh state dir.
fn python_state() -> (TempDir, StateDir) {
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let fx = fixture();
    for rel in fx["snapshot_seeded"]["files"].as_array().unwrap() {
        let rel = text(rel);
        let bytes = std::fs::read(fixture_dir().join("state").join(rel)).unwrap();
        let value = pyjson::loads(std::str::from_utf8(&bytes).unwrap()).unwrap();
        state.write_json(rel, &value).unwrap();
        // `write_json` reproduces Python's own bytes exactly.
        assert_eq!(
            std::fs::read(state.path.join(rel)).unwrap(),
            bytes,
            "{rel}: rust-written JSON differs from the python-written file"
        );
    }
    (tmp, state)
}

/// Finding H-R2-7: a connection's `http_scope`/`ssh_target` tuple-vs-list
/// rendering depends on whether THAT connection was (re)built by the fold
/// call that produced the document, not on the key name. The Python
/// generator stored the history plus one more commit (updating only
/// "gitlab") in its own commit store, saved snapshot 1 after the first
/// seven commits, and rendered `fold_with_snapshot`'s document: "gitlab" as
/// a tuple (rebuilt this fold), "gh" as a plain YAML list (carried over
/// from the snapshot). That Python-written state must load and render
/// byte-identically here.
#[test]
fn humanview_tuple_vs_list_matches_python_across_a_snapshot_seeded_fold() {
    let env_id = history_env_id();
    let fx = fixture();
    let (_tmp, state) = python_state();
    let store = C::CommitStore::new(&state, env_id.clone());
    let all_commits = store.all_commits().unwrap();
    assert_eq!(all_commits.len(), 8);

    let result2 = F::fold_with_snapshot(&env_id, all_commits, &state, None, None).unwrap();
    assert_eq!(
        result2.fresh_connections,
        std::collections::BTreeSet::from(["gitlab".to_string()]),
        "only the connection touched by the new commit is fresh this fold"
    );
    let stripped2 = humanview::strip_document(&result2.document);
    let rust_yaml2 = humanview::to_yaml(&stripped2, &result2.fresh_connections);
    assert_eq!(
        rust_yaml2,
        text(&fx["snapshot_seeded"]["yaml"]),
        "to_yaml() after a snapshot-seeded second fold must match byte-for-byte"
    );
    assert_eq!(
        rust_yaml2.matches("methods: ('GET',)").count(),
        1,
        "exactly the rebuilt connection (gitlab) renders http_scope.methods as a tuple:\n{rust_yaml2}"
    );
    assert_eq!(
        rust_yaml2.matches("path_prefixes: ('/repos',)").count(),
        1,
        "exactly the rebuilt connection (gitlab) renders http_scope.path_prefixes as a tuple:\n{rust_yaml2}"
    );
    assert!(
        rust_yaml2.contains("methods:\n      - GET"),
        "the untouched connection (gh) must render http_scope.methods as a YAML list, not a tuple:\n{rust_yaml2}"
    );
}

/// The same commit store and snapshot, written by this port from the same
/// commits, is byte-identical to the Python-written files.
#[test]
fn commit_store_and_snapshot_files_match_python_bytes() {
    let (env_id, mut commits, _owner, _second) = build_history();
    let fx = fixture();
    let owner = fixed_device(0x10, 0x20);
    let c8 = C::sign_commit(
        &owner,
        &env_id,
        6,
        "6000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "connection.update", "id": "gitlab", "description": "updated"})],
    )
    .unwrap();
    assert_eq!(
        compact(&c8.to_dict()),
        text(&fx["snapshot_seeded"]["commit"])
    );

    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let store = C::CommitStore::new(&state, env_id.clone());
    let result1 = F::fold(&env_id, commits.clone(), None, None, None, None).unwrap();
    commits.push(c8);
    for commit in &commits {
        store.append(commit).unwrap();
    }
    F::save_snapshot(&state, &env_id, &PyInt::from(1), &result1).unwrap();
    let files = fx["snapshot_seeded"]["files"].as_array().unwrap();
    assert_eq!(files.len(), 9);
    for rel in files {
        let rel = text(rel);
        assert_eq!(
            std::fs::read(state.path.join(rel)).unwrap(),
            std::fs::read(fixture_dir().join("state").join(rel)).unwrap(),
            "{rel}"
        );
    }
}

/// Finding H-R3-6: the tuple-rendering special case used to trigger for a
/// key literally named `"connections"` at ANY depth, not just the
/// document's own top-level `connections` map -- but a `secret.put_version`
/// op's `public` metadata is arbitrary peer-controlled JSON that never
/// passes through `build_connection_fields`/`dataclasses.asdict`, so its
/// array values are always plain lists, no matter what key they sit under.
/// The history's "gh" connection is genuinely fresh-built by a real
/// `connection.create` op, and one more commit's `public` metadata nests a
/// `"connections"` key with an id that deliberately COLLIDES with "gh". The
/// Python prototype rendered the top-level "gh" as a tuple repr but the
/// nested, colliding one as an ordinary list; this port must match
/// byte-for-byte.
#[test]
fn humanview_nested_connections_key_off_root_matches_python() {
    let (env_id, mut commits, _owner_record, _second_record) = build_history();
    let fx = fixture();
    let owner = fixed_device(0x10, 0x20);
    let gen0 = "0".repeat(16);
    let trap_public = json!({"connections": {"gh": {"http_scope": {"methods": ["GET"]}}}});
    let c8 = C::sign_commit(
        &owner,
        &env_id,
        6,
        "6000-0000",
        &BTreeMap::new(),
        vec![
            json!({"op": "secret.put_version", "secret_id": "s-trap", "kind": "api_key",
              "generation_id": gen0, "version_id": "2".repeat(16),
              "ciphertext": {"nonce": "AAAA", "ciphertext": "BBBB"}, "public": trap_public}),
        ],
    )
    .unwrap();
    assert_eq!(
        compact(&c8.to_dict()),
        text(&fx["nested_connections"]["commit"])
    );
    commits.push(c8);

    let rust_result = F::fold(&env_id, commits, None, None, None, None).unwrap();
    let stripped = humanview::strip_document(&rust_result.document);
    let rust_yaml = humanview::to_yaml(&stripped, &rust_result.fresh_connections);
    assert_eq!(
        rust_yaml,
        text(&fx["nested_connections"]["yaml"]),
        "to_yaml() must match python byte-for-byte for a colliding nested connections key"
    );
    // Both "gh" and "gitlab" are genuinely fresh-built this fold, so each
    // renders `http_scope.methods` as a tuple repr -- exactly 2
    // occurrences, not 3.
    assert_eq!(
        rust_yaml.matches("methods: ('GET',)").count(),
        2,
        "exactly the two real top-level connections may render as a tuple:\n{rust_yaml}"
    );
    assert!(
        rust_yaml.contains("public:\n          connections:\n            gh:\n              http_scope:\n                methods:\n                - GET"),
        "the nested, colliding connections key must render as an ordinary YAML list:\n{rust_yaml}"
    );
}

// ------------------------------------------------------------------ H-R2-6
/// Finding H-R2-6 (probe 1, "the 10^30 commit body"): `FoldResult::vector`
/// used to be filled with `i64::try_from(commit.author_seq).unwrap_or(i64::MAX)`,
/// silently clamping a real, huge `author_seq` (read straight off a commit
/// file by `all_commits()`, not merely a snapshot artifact) to `i64::MAX`
/// instead of keeping the true value the way Python's arbitrary-precision
/// `vector[commit.author] = max(..., commit.author_seq)` does.
#[test]
fn fold_vector_preserves_author_seq_beyond_i64_like_python() {
    let owner = fixed_device(0x71, 0x72);
    let record = owner.record().unwrap();
    let env_id = C::new_env_id(&record.fingerprint()).unwrap();
    let gen0 = "0".repeat(16);
    // 10**60: beyond i64 and i128 alike.
    let huge = PyInt(format!("1{}", "0".repeat(60)).parse().unwrap());
    let c1 = C::sign_commit(
        &owner,
        &env_id,
        1,
        "1000-0000",
        &BTreeMap::new(),
        vec![env_init_op(&record, "alice", &gen0)],
    )
    .unwrap();
    let c2 = C::sign_commit(
        &owner,
        &env_id,
        &huge,
        "2000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "settings.update", "sync_interval_seconds": 1})],
    )
    .unwrap();
    let rust_result = F::fold(
        &env_id,
        vec![c1.clone(), c2.clone()],
        None,
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(rust_result.vector.get(&record.fingerprint()), Some(&huge));
}

/// Finding H-R2-6 (probe 2, "the 10^30 snapshot vector"): `snapshot_floor`
/// used to parse each snapshot `vector` entry with `Number::as_i64`,
/// silently DROPPING (not clamping) any entry outside `i64` -- so a
/// hand-crafted/bit-rotted snapshot claiming `vector = {fp: 10**30}` was
/// read back as if that author had never committed anything
/// (`last_seq == 0`), letting a REPLAYED `author_seq=1` commit from that
/// author be accepted again by `CommitStore::append` (`team_seq_duplicate`
/// should fire instead). Probed directly at the `CommitStore::append`
/// level (not through `receive_commit`, which also calls `all_commits()` --
/// looping `1..=last` for a `10**30` floor is as impractical in Python as
/// in Rust and is not what this finding is about).
#[test]
fn snapshot_floor_beyond_i64_still_refuses_a_replayed_commit() {
    let owner = fixed_device(0x73, 0x74);
    let record = owner.record().unwrap();
    let env_id = C::new_env_id(&record.fingerprint()).unwrap();
    let huge: i128 = 1_000_000_000_000_000_000_000_000_000_000; // 10**30
    let replayed = C::sign_commit(
        &owner,
        &env_id,
        1,
        "1000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "settings.update", "sync_interval_seconds": 1})],
    )
    .unwrap();

    // --- Rust side: hand-write a snapshot claiming a 10**30 floor, then
    // try to append the replayed seq=1 commit through CommitStore.
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let snapshot_doc = json!({
        "document": {"env_id": env_id, "format": "zeropw-team-env-v1", "owner": record.fingerprint(),
                     "members": {}, "connections": {}, "secrets": {}, "settings": {},
                     "dek": {"current": null, "generations": {}}},
        "version_order": {},
        "vector": {record.fingerprint(): huge},
    });
    state
        .write_json(&format!("team/{env_id}/snapshots/1.json"), &snapshot_doc)
        .unwrap();
    let store = C::CommitStore::new(&state, env_id.clone());
    assert_eq!(
        store.last_seq(&record.fingerprint()).unwrap(),
        huge,
        "the floor must be retained, not dropped"
    );
    let rust_err = store.append(&replayed).unwrap_err();
    assert_eq!(rust_err.reason, "team_seq_duplicate");
}

/// Finding H-R3-9: `CommitStore.vector`/`_snapshot_floor` (Python) filter
/// commit/snapshot filenames with `Path.stem.isdigit()` then parse with
/// `int(stem)` -- NOT the ASCII-only grammar this port's `digit_stems` used
/// to filter on. A commit file named `٣.json` (U+0663, ARABIC-INDIC DIGIT
/// THREE -- an `Nd` code point `int()` DOES accept) used to be silently
/// IGNORED here (`vector()` missing that entry, `last_seq() == 0`) where
/// Python reads it as `author_seq = 3` -- which would let a REPLAYED
/// `author_seq = 1..3` commit Python refuses (`team_seq_duplicate`) be
/// silently re-accepted by this port instead. (The Python prototype read
/// that exact filename as `3`.)
#[test]
fn commit_store_vector_reads_non_ascii_nd_digit_filename_like_python() {
    let owner = fixed_device(0x91, 0x92);
    let record = owner.record().unwrap();
    let env_id = C::new_env_id(&record.fingerprint()).unwrap();
    let fp = record.fingerprint();

    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    // U+0663 ARABIC-INDIC DIGIT THREE: `"\u{0663}".isdigit()` is `True` and
    // `int("\u{0663}") == 3` in real python3.12, but it is not an ASCII
    // digit at all.
    state
        .write_json(
            &format!("team/{env_id}/commits/{fp}/\u{0663}.json"),
            &json!({}),
        )
        .unwrap();
    let store = C::CommitStore::new(&state, env_id.clone());
    assert_eq!(
        store.last_seq(&fp).unwrap(),
        3,
        "a non-ASCII Nd digit filename must still be read as author_seq 3"
    );
}

/// Finding H-R3-9's other reachable shape: a stem `str.isdigit()` accepts
/// but `int()` cannot parse -- `"\u{b2}"` (superscript two, `Numeric_Type=
/// Digit`, not `Decimal`) -- raises an uncaught `ValueError` from Python's
/// own `[int(p.stem) for p in ... if p.stem.isdigit()]` list comprehension,
/// aborting `CommitStore.vector`/`_snapshot_floor` entirely, where the
/// previous ASCII-only filter here just silently ignored the file (as if
/// it had never matched `isdigit()` at all). Fixed to fail closed
/// (`state_corrupt`) instead, matching "every real caller lets this
/// exception escape uncaught" (PORTING.md §3.5).
#[test]
fn commit_store_vector_fails_closed_on_isdigit_but_unparsable_filename() {
    let owner = fixed_device(0x93, 0x94);
    let record = owner.record().unwrap();
    let env_id = C::new_env_id(&record.fingerprint()).unwrap();
    let fp = record.fingerprint();

    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    state
        .write_json(
            &format!("team/{env_id}/commits/{fp}/\u{b2}.json"),
            &json!({}),
        )
        .unwrap();
    let store = C::CommitStore::new(&state, env_id.clone());
    let err = store
        .last_seq(&fp)
        .expect_err("an isdigit()-but-unparsable stem must fail closed, not silently skip");
    assert_eq!(err.reason, "state_corrupt");
}

// ------------------------------------------------------------------ H-2/H-3/H-4/H-5/H-6
// Round-1 equivalence-review fixes for work unit H (team data layer). Each
// test below feeds a genuinely-signed commit (or op) to `receive_commit`/
// `validate_op`/`fold` and asserts the outcome the Python prototype
// produced for the same input (measured when these tests were written
// against it).

fn fresh_state() -> (TempDir, StateDir) {
    let tmp = TempDir::new().expect("tempdir");
    let state = StateDir::new(tmp.path().join("state"));
    state.create().expect("create state dir");
    (tmp, state)
}

/// Finding H-2 (`Hlc::parse` vs `zeropw/team/commit.py`'s `Hlc.parse`):
/// CPython's `int(str)` accepts surrounding whitespace, a leading `+`,
/// `_` digit separators and Unicode decimal digits, with arbitrary
/// precision. Each probe below is a genuinely-signed commit (the hlc string
/// is just a field in the signed bytes, so `sign_commit` happily produces a
/// valid signature over any string); `receive_commit`'s outcome must match
/// Python's exactly, including the out-of-`i64` value that Python defers
/// (clock-skew branch) rather than treating as malformed.
#[test]
fn hlc_parse_leniency_matches_python_receive_commit_outcome() {
    let owner = fixed_device(0xE1, 0xE2);
    let record = owner.record().unwrap();
    let env_id = C::new_env_id(&record.fingerprint()).unwrap();
    let gen0 = "0".repeat(16);
    let c1 = C::sign_commit(
        &owner,
        &env_id,
        1,
        "1000-0000",
        &BTreeMap::new(),
        vec![env_init_op(&record, "alice", &gen0)],
    )
    .unwrap();

    let probes: [(&str, &str); 5] = [
        (" 1000-0001", "accepted"),
        ("1000-0001 ", "accepted"),
        ("1_000-0001", "accepted"),
        ("١٠٠٠-0001", "accepted"),
        ("99999999999999999999999999-0000", "deferred"),
    ];
    for (hlc, expected) in probes {
        let c2 = C::sign_commit(
            &owner,
            &env_id,
            2,
            hlc,
            &BTreeMap::new(),
            vec![json!({"op": "settings.update", "sync_interval_seconds": 42})],
        )
        .unwrap();

        let (_tmp, state) = fresh_state();
        let store = C::CommitStore::new(&state, env_id.clone());
        assert_eq!(
            C::receive_commit(&store, &c1, 1_000_000, None).unwrap(),
            "accepted"
        );
        let rust_result = C::receive_commit(&store, &c2, 1_000_000, None).unwrap();
        assert_eq!(
            rust_result, expected,
            "rust receive_commit outcome for hlc={hlc:?}"
        );
    }
}

/// Finding H-3 (`validate_settings_update` vs `zeropw/team/commit.py`'s
/// `_validate_settings_update`): Python accepts any positive `int`
/// (`isinstance(int)`, not `bool`), including one far outside `i64`
/// (`10**30`). The old `as_i64()`-bounded Rust check rejected the whole
/// commit even though `fold()` itself handles the value fine -- a node
/// divergence (accept vs reject).
#[test]
fn settings_update_accepts_arbitrary_precision_positive_int() {
    let cases: [(Value, &str); 4] = [
        (
            json!(1_000_000_000_000_000_000_000_000_000_000_i128),
            "accepted",
        ),
        (json!(true), "invalid_settings"),
        (json!(0), "invalid_settings"),
        (json!(-1), "invalid_settings"),
    ];
    for (value, expected) in cases {
        let op = json!({"op": "settings.update", "sync_interval_seconds": value});
        let rust_result = match C::validate_op(&op) {
            Ok(()) => "accepted".to_string(),
            Err(e) => e.reason.to_string(),
        };
        assert_eq!(rust_result, expected, "rust reason for {value}");
    }
    // 1.5 is a float, not an int shape at all -- rejected on both sides too,
    // checked separately since it needs a float JSON literal.
    let op = json!({"op": "settings.update", "sync_interval_seconds": 1.5});
    assert_eq!(C::validate_op(&op).unwrap_err().reason, "invalid_settings");
}

/// Finding H-4 (`ca_file`/`value_prefix` vs `zeropw/team/commit.py`'s
/// `_build_http_target`/`_build_http_auth`): Python's `HttpTarget.ca_file`/
/// `HttpAuth.value_prefix` have no `isinstance` check, so a non-string
/// value validates and is stored verbatim in the folded document. Both
/// sides used to accept the commit but produce byte-different documents
/// (Rust silently dropped the field to `null`); this compares the folded
/// document with the Python fixture byte-for-byte.
#[test]
fn ca_file_and_value_prefix_pass_through_verbatim_in_folded_document() {
    let fx = fixture();
    let owner = fixed_device(0xF1, 0xF2);
    let record = owner.record().unwrap();
    let env_id = text(&fx["ca_file"]["env_id"]).to_owned();
    let gen0 = "0".repeat(16);
    let c1 = C::sign_commit(
        &owner,
        &env_id,
        1,
        "1000-0000",
        &BTreeMap::new(),
        vec![env_init_op(&record, "alice", &gen0)],
    )
    .unwrap();
    let c2 = C::sign_commit(
        &owner,
        &env_id,
        2,
        "2000-0000",
        &BTreeMap::new(),
        vec![
            json!({"op": "secret.put_version", "secret_id": "tok", "kind": "api_key",
                  "generation_id": gen0, "version_id": "2".repeat(16),
                  "ciphertext": {"nonce": "AAAA", "ciphertext": "BBBB"}, "public": {}}),
        ],
    )
    .unwrap();
    let c3 = C::sign_commit(
        &owner,
        &env_id,
        3,
        "3000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "connection.create", "id": "svc", "project": "demo", "environment": "dev",
              "service": "api", "kind": "http", "secret_id": "tok", "secret_version": null,
              "description": "", "http_target": {"scheme": "https", "host": "api.example.com", "port": 443, "ca_file": 5},
              "http_auth": {"mode": "bearer", "value_prefix": 7}, "http_scope": {"methods": ["GET"]}})],
    )
    .unwrap();
    let commits = vec![c1, c2, c3];
    let rust_result = F::fold(&env_id, commits.clone(), None, None, None, None).unwrap();
    let rust_doc_text =
        pyjson::dumps(&rust_result.document, DumpOptions::compact_sorted()).unwrap();
    // The raw JSON values (not strings) must survive verbatim.
    assert_eq!(
        rust_result.document["connections"]["svc"]["http_target"]["ca_file"],
        json!(5)
    );
    assert_eq!(
        rust_result.document["connections"]["svc"]["http_auth"]["value_prefix"],
        json!(7)
    );

    let python_commits: Vec<&str> = fx["ca_file"]["commits"]
        .as_array()
        .unwrap()
        .iter()
        .map(text)
        .collect();
    let rust_commits: Vec<String> = commits.iter().map(|c| compact(&c.to_dict())).collect();
    assert_eq!(rust_commits, python_commits);
    assert_eq!(
        rust_doc_text,
        text(&fx["ca_file"]["document"]),
        "folded document must be byte-identical, including ca_file/value_prefix"
    );
}

/// Finding H-5 (five validation-reason mismatches vs the policy dataclasses'
/// own check order): each case below is a `connection.create` op that
/// differs from a known-good baseline in exactly one way, run through
/// `validate_op`/`zeropw.team.commit.validate_op` and compared reason for
/// reason.
#[test]
fn op_validation_reason_sweep_matches_python() {
    let http_base = || {
        json!({"op": "connection.create", "id": "gh", "project": "demo", "environment": "dev",
              "service": "github", "kind": "http", "secret_id": "gh-token", "secret_version": null,
              "description": "", "http_target": {"scheme": "https", "host": "api.github.com", "port": 443},
              "http_auth": {"mode": "bearer"}, "http_scope": {"methods": ["GET"], "path_prefixes": ["/repos"]}})
    };
    let ssh_base = || {
        json!({"op": "connection.create", "id": "box", "project": "demo", "environment": "dev",
              "service": "ssh-box", "kind": "ssh", "secret_id": "box-key", "secret_version": null,
              "description": "", "ssh_target": {"host": "127.0.0.1", "port": 22, "username": "deploy",
              "host_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA host"]}})
    };
    let cli_base = || {
        json!({"op": "connection.create", "id": "gh", "project": "demo", "environment": "dev",
              "service": "github", "kind": "http", "secret_id": "gh-token", "secret_version": null,
              "description": "", "http_target": {"scheme": "https", "host": "api.github.com", "port": 443},
              "http_auth": {"mode": "bearer"}, "http_scope": {"methods": ["GET"]},
              "cli": {"program": "gh", "kind": "http"}})
    };

    let mut cases: Vec<(&str, Value, &str)> = Vec::new();
    cases.push(("http baseline accepted", http_base(), "accepted"));

    // H-5 case 1: bad scheme *and* a non-bool allow_private_network must
    // surface Python's scheme check (checked first), not Rust's old
    // allow_private_network-first check.
    let mut op = http_base();
    op["http_target"]["scheme"] = json!("ftp");
    op["http_target"]["allow_private_network"] = json!(5);
    cases.push((
        "bad scheme + non-bool allow_private_network",
        op,
        "invalid_scheme",
    ));

    let mut op = http_base();
    op["http_target"]["allow_private_network"] = json!(5);
    cases.push((
        "non-bool allow_private_network alone",
        op,
        "invalid_allow_private_network",
    ));

    // H-R2-3: `value.get("allow_private_network", False)` only defaults an
    // *absent* key; a *present* `null` reaches `HttpTarget.__post_init__`'s
    // `isinstance(..., bool)` check and is rejected -- not silently treated
    // as `false` the way the round-1 fix did.
    let mut op = http_base();
    op["http_target"]["allow_private_network"] = Value::Null;
    cases.push((
        "explicit null allow_private_network",
        op,
        "invalid_allow_private_network",
    ));

    let mut op = http_base();
    op["http_target"]
        .as_object_mut()
        .unwrap()
        .remove("allow_private_network");
    cases.push((
        "absent allow_private_network still defaults to false",
        op,
        "accepted",
    ));

    let mut op = http_base();
    op["http_target"]["host"] = json!("not a host!!");
    cases.push(("bad host (sanity, unaffected)", op, "invalid_host"));

    let mut op = http_base();
    op["http_target"]["port"] = json!(70000);
    cases.push(("bad port (sanity, unaffected)", op, "invalid_port"));

    // H-5 case 2: methods as a string.
    let mut op = http_base();
    op["http_scope"]["methods"] = json!("GET");
    cases.push(("http_scope.methods a string", op, "invalid_method"));

    let mut op = http_base();
    op["http_scope"]["methods"] = json!(5);
    cases.push((
        "http_scope.methods a number (non-iterable)",
        op,
        "invalid_http_scope",
    ));

    // H-5 case 3: path_prefixes as a string.
    let mut op = http_base();
    op["http_scope"]["path_prefixes"] = json!("/repos");
    cases.push((
        "http_scope.path_prefixes a string",
        op,
        "invalid_path_prefix",
    ));

    let mut op = http_base();
    op["http_scope"]["path_prefixes"] = json!([]);
    cases.push((
        "http_scope.path_prefixes empty array (sanity, unaffected)",
        op,
        "empty_path_prefixes",
    ));

    let mut op = http_base();
    op["http_scope"]["confirm_methods"] = json!(0);
    cases.push((
        "http_scope.confirm_methods falsy int (sanity, no error)",
        op,
        "accepted",
    ));

    let mut op = http_base();
    op["http_scope"]["confirm_methods"] = json!(5);
    cases.push((
        "http_scope.confirm_methods truthy non-iterable int",
        op,
        "invalid_http_scope",
    ));

    let mut op = http_base();
    op["http_scope"]["confirm_methods"] = json!("XY");
    cases.push((
        "http_scope.confirm_methods a 2-char string",
        op,
        "invalid_method",
    ));

    cases.push(("ssh baseline accepted", ssh_base(), "accepted"));

    // H-5 case 4: ssh_target.host_keys as a string.
    let mut op = ssh_base();
    op["ssh_target"]["host_keys"] = json!("not-a-key");
    cases.push((
        "ssh_target.host_keys a non-empty string",
        op,
        "unsupported_host_key",
    ));

    let mut op = ssh_base();
    op["ssh_target"]["host_keys"] = json!("");
    cases.push((
        "ssh_target.host_keys an empty string",
        op,
        "ssh_host_keys_required",
    ));

    let mut op = ssh_base();
    op["ssh_target"]["host_keys"] = json!(5);
    cases.push((
        "ssh_target.host_keys a number (non-iterable)",
        op,
        "invalid_ssh_target",
    ));

    let mut op = ssh_base();
    op["ssh_target"]["host_keys"] = json!({"nonsense": null});
    cases.push((
        "ssh_target.host_keys an object (iterated as keys)",
        op,
        "unsupported_host_key",
    ));

    cases.push(("cli baseline accepted", cli_base(), "accepted"));

    // H-5 case 5: cli.base_url_env non-string.
    let mut op = cli_base();
    op["cli"]["base_url_env"] = json!(5);
    cases.push(("cli.base_url_env a non-string", op, "invalid_cli_profile"));

    let mut op = cli_base();
    op["cli"]["base_url_env"] = Value::Null;
    cases.push(("cli.base_url_env explicit null", op, "invalid_cli_profile"));

    let mut op = cli_base();
    op["cli"]["base_url_env"] = json!("not-upper-case");
    cases.push((
        "cli.base_url_env wrong pattern (sanity, unaffected)",
        op,
        "invalid_env_name",
    ));

    // H-R2-4: `extra_env=dict(value.get("extra_env") or {})` -- any falsy
    // JSON shape (not just `null`) is equivalent to an absent `extra_env`,
    // and a truthy array of two-element pairs is accepted just like a JSON
    // object would be.
    for falsy in [json!(0), json!(false), json!(""), json!([]), json!({})] {
        let mut op = cli_base();
        op["cli"]["extra_env"] = falsy.clone();
        cases.push((
            "cli.extra_env falsy non-null (sanity, no error)",
            op,
            "accepted",
        ));
    }
    let mut op = cli_base();
    op["cli"]["extra_env"] = json!([["A_B", "value"]]);
    cases.push(("cli.extra_env as an array of pairs", op, "accepted"));

    let mut op = cli_base();
    op["cli"]["extra_env"] = json!([[1, "value"]]);
    cases.push((
        "cli.extra_env pair with a non-string key",
        op,
        "invalid_cli_profile",
    ));

    let mut op = cli_base();
    op["cli"]["extra_env"] = json!(5);
    cases.push((
        "cli.extra_env a truthy non-iterable number",
        op,
        "invalid_cli_profile",
    ));

    let mut op = cli_base();
    op["cli"]["extra_env"] = json!(true);
    cases.push((
        "cli.extra_env a truthy non-iterable bool",
        op,
        "invalid_cli_profile",
    ));

    // H-R2-9(c) (a truthy plain *string* `extra_env`, Python's uncaught
    // `dict("ab")` ValueError) is NOT included in this sweep -- Python's own
    // `validate_op` lets that exception escape uncaught rather than
    // returning a reason string, so it cannot go through this loop's
    // "both sides print a reason" harness. See
    // `extra_env_truthy_string_is_pythons_uncaught_valueerror` below.

    // H-R2-8: `if not self.program or "\x00" in self.program: raise
    // invalid_cli_program` -- a FALSY non-string `program` (0, false, "",
    // [], {}) hits the documented reason, but a TRUTHY non-string reaches
    // an uncaught `TypeError` from the `in` test, wrapped as
    // `invalid_cli_profile` instead.
    for falsy in [json!(0), json!(false), json!(""), json!([]), json!({})] {
        let mut op = cli_base();
        op["cli"]["program"] = falsy.clone();
        cases.push(("cli.program falsy non-string", op, "invalid_cli_program"));
    }
    let mut op = cli_base();
    op["cli"]["program"] = json!(5);
    cases.push((
        "cli.program truthy non-string number",
        op,
        "invalid_cli_profile",
    ));
    let mut op = cli_base();
    op["cli"]["program"] = json!(true);
    cases.push((
        "cli.program truthy non-string bool",
        op,
        "invalid_cli_profile",
    ));

    for (label, op, expected) in &cases {
        let rust_result = match C::validate_op(op) {
            Ok(()) => "accepted".to_string(),
            Err(e) => e.reason.to_string(),
        };
        assert_eq!(&rust_result, expected, "rust reason for case {label:?}");
    }
}

/// Finding H-R3-5: `CliProfile.__post_init__` validates each `extra_env`
/// entry's KEY before its VALUE, one entry at a time, in the dict's
/// insertion/document order -- `{"b": "x", "A": 5}` raises
/// `invalid_env_name` (`"b"`, checked first, fails the name pattern) not
/// `invalid_env_value` (from `"A"`'s non-string value, never reached). The
/// sweep test above (`op_validation_reason_sweep_matches_python`) serialises
/// every op with `pyjson::dumps(..., DumpOptions::compact_sorted())` before
/// sending it to the Python subprocess -- which recursively KEY-SORTS the
/// JSON text, so by the time Python's `json.loads` reconstructs the dict,
/// `"A"` already sorts before `"b"` and the bug is invisible. This test
/// builds the raw JSON text BY HAND instead, with `extra_env`'s keys
/// deliberately left in `b`-before-`A` order, and feeds that exact text to
/// both `serde_json::from_str` (preserving the document order it parses,
/// same as `zeropw::team::commit::validate_op`'s own `Map` -- `preserve_
/// order` is enabled crate-wide) and Python's `json.loads` (which always
/// preserves the source text's key order).
#[test]
fn extra_env_key_before_value_order_matches_python_when_not_key_sorted() {
    let raw_json = r#"{"op": "connection.create", "id": "gh", "project": "demo", "environment": "dev",
        "service": "github", "kind": "http", "secret_id": "gh-token", "secret_version": null,
        "description": "", "http_target": {"scheme": "https", "host": "api.github.com", "port": 443},
        "http_auth": {"mode": "bearer"}, "http_scope": {"methods": ["GET"]},
        "cli": {"program": "gh", "kind": "http", "extra_env": {"b": "x", "A": 5}}}"#;

    let op: Value = serde_json::from_str(raw_json).expect("parse raw json");
    let rust_result = match C::validate_op(&op) {
        Ok(()) => "accepted".to_string(),
        Err(e) => e.reason.to_string(),
    };
    assert_eq!(
        rust_result, "invalid_env_name",
        "'b' (checked first in document order) must fail the name pattern before 'A's bad value is ever inspected"
    );
}

/// Finding H-R4-3 (`build_cli_profile` vs `zeropw/team/commit.py`
/// `_build_cli_profile`): a 2,925-case sweep found 1,507 cases where the
/// round-3 version of this function picked a different `InvalidInput`
/// reason than Python for the same malformed `cli` shape, because it
/// checked fields in a different order than Python's two phases (phase 1:
/// `KeyError`/`dict(extra_env)` `TypeError`, pre-empting everything; phase
/// 2, `CliProfile.__post_init__`: kind -> program -> base_url_env ->
/// entries). Every op's JSON text here is hand-built (like the test above),
/// NOT round-tripped through `pyjson::dumps(..., DumpOptions::
/// compact_sorted())`, which would key-sort `extra_env` *object* shapes and
/// hide any order-dependent bug the same way the test above's own doc
/// comment explains -- irrelevant for most cases below (`extra_env` as an
/// ARRAY of pairs keeps its element order under key-sorting regardless,
/// since only object *keys* get reordered) but kept consistent throughout
/// for a single, uniformly trustworthy harness. Every reason below was
/// measured against the Python prototype, not asserted from memory.
#[test]
fn build_cli_profile_check_order_matches_python_over_a_sweep() {
    fn cli_op(cli_json: &str) -> String {
        format!(
            r#"{{"op": "connection.create", "id": "gh", "project": "demo", "environment": "dev",
            "service": "github", "kind": "http", "secret_id": "gh-token", "secret_version": null,
            "description": "", "http_target": {{"scheme": "https", "host": "api.github.com", "port": 443}},
            "http_auth": {{"mode": "bearer"}}, "http_scope": {{"methods": ["GET"]}},
            "cli": {cli_json}}}"#
        )
    }

    let cases: &[(&str, &str)] = &[
        // Kind is checked BEFORE program (finding H-R4-3's first example):
        // an empty `program` would independently be `invalid_cli_program`,
        // but `kind="ftp"` is checked first and wins.
        (r#"{"program":"","kind":"ftp"}"#, "invalid_cli_kind"),
        // Kind is checked BEFORE the extra_env entries loop even when that
        // loop would otherwise fail on a non-string key (finding H-R4-3's
        // second example): `dict([[1,"x"]])` succeeds in phase 1 (1 is a
        // valid dict key), so `__post_init__` runs and fails at `kind`
        // before the entries loop is ever reached.
        (
            r#"{"program":"prog","kind":"ftp","extra_env":[[1,"x"]]}"#,
            "invalid_cli_kind",
        ),
        // Same shape, but kind now valid: phase 1 still succeeds (`dict()`
        // doesn't care about key types), `__post_init__` passes kind,
        // program and base_url_env, and only then reaches the entries
        // loop's own non-string-key `TypeError`.
        (
            r#"{"program":"prog","kind":"http","extra_env":[[1,"x"],["A","y"]]}"#,
            "invalid_cli_profile",
        ),
        // A valid entry before the non-string-key one must still let
        // Python (and this fix) reach and check it first, in order.
        (
            r#"{"program":"prog","kind":"http","extra_env":[["A","x"],[1,"y"]]}"#,
            "invalid_cli_profile",
        ),
        // ... but a valid-shaped, invalid-VALUE entry before the
        // non-string key must win instead, since Python stops at the
        // first failing entry regardless of why the later one would also
        // fail.
        (
            r#"{"program":"prog","kind":"http","extra_env":[["zz","x"],[1,"y"]]}"#,
            "invalid_env_name",
        ),
        // Missing "program"/"kind" keys: phase 1's `KeyError`, pre-empting
        // phase 2 entirely (so a valid `kind`/`program` present on one but
        // not the other still can't paper over the missing one).
        (r#"{"kind":"http"}"#, "invalid_cli_profile"),
        (r#"{"program":"p"}"#, "invalid_cli_profile"),
        // A non-string `kind` fails the plain membership check with the
        // same reason a wrong-but-string `kind` gets -- no `TypeError`
        // risk at all, unlike `program`/`base_url_env` below.
        (r#"{"program":"p","kind":5}"#, "invalid_cli_kind"),
        // A TRUTHY non-string `program` reaches `"\x00" in self.program`,
        // Python's own uncaught `TypeError` -- but only once `kind` (here
        // valid) has already passed.
        (r#"{"program":5,"kind":"http"}"#, "invalid_cli_profile"),
        (r#"{"program":true,"kind":"http"}"#, "invalid_cli_profile"),
        // A FALSY non-string `program` short-circuits to the documented
        // reason instead, without ever risking that `TypeError`.
        (r#"{"program":0,"kind":"http"}"#, "invalid_cli_program"),
        // `base_url_env` has no falsy/truthy distinction at all -- ANY
        // non-string value is Python's uncaught `TypeError` (from
        // `re.match`), unconditionally, reached only once kind/program
        // (both valid here) already passed.
        (
            r#"{"program":"p","kind":"http","base_url_env":null}"#,
            "invalid_cli_profile",
        ),
        (
            r#"{"program":"p","kind":"http","base_url_env":5}"#,
            "invalid_cli_profile",
        ),
        (
            r#"{"program":"p","kind":"http","base_url_env":"bad-name"}"#,
            "invalid_env_name",
        ),
        // Phase 1's `dict(extra_env)` conversion succeeding or failing is
        // independent of kind/program: a truthy non-pairable `extra_env`
        // pre-empts a bad `kind` just the same as a good one.
        (
            r#"{"program":"p","kind":"http","extra_env":5}"#,
            "invalid_cli_profile",
        ),
        (
            r#"{"program":"p","kind":"ftp","extra_env":5}"#,
            "invalid_cli_profile",
        ),
        (
            r#"{"program":"p","kind":"http","extra_env":null}"#,
            "accepted",
        ),
        (r#"{"program":"p","kind":"http","extra_env":0}"#, "accepted"),
        // Sanity: the already-fixed key-before-value-in-order behaviour
        // (finding H-R3-5) must still hold after this round's rewrite.
        (
            r#"{"program":"p","kind":"http","extra_env":{"b":"x","A":5}}"#,
            "invalid_env_name",
        ),
        (
            r#"{"program":"p","kind":"http","extra_env":{"SSH_AUTH_SOCK":"x"}}"#,
            "invalid_env_name",
        ),
    ];

    for (cli_json, expected) in cases {
        let raw = cli_op(cli_json);
        let op: Value = serde_json::from_str(&raw).expect("parse raw json");
        let rust_result = match C::validate_op(&op) {
            Ok(()) => "accepted".to_string(),
            Err(e) => e.reason.to_string(),
        };
        assert_eq!(&rust_result, expected, "rust reason for cli={cli_json:?}");
    }
}

fn connection_create_args(cli_json: &str, http_auth_json: &str) -> String {
    format!(
        r#"{{"project": "demo", "environment": "dev", "service": "github", "kind": "http",
        "secret_id": "gh-token", "secret_version": null, "description": "",
        "http_target": {{"scheme": "https", "host": "api.github.com", "port": 443}},
        "http_auth": {http_auth_json}, "http_scope": {{"methods": ["GET"]}},
        "cli": {cli_json}}}"#
    )
}

/// Finding H-R5-2 (`build_cli_profile`'s `program` check vs
/// `zeropw/policy.py` `CliProfile.__post_init__`'s `if not self.program or
/// "\x00" in self.program`): a TRUTHY list/dict `program` does not raise in
/// Python -- `"\x00" in value` is a plain membership test on any container,
/// not a type check -- so it is folded into the connection's `cli` field
/// VERBATIM. Confirmed against real `python3.12`:
/// `build_connection_fields({"cli": {"program": ["curl"], ...}, ...})`
/// succeeds and keeps `program == ["curl"]`; the previous Rust code
/// rejected ANY non-string `program` outright (`invalid_cli_profile`), even
/// a well-formed list with no `"\x00"` in it. A container that DOES contain
/// the literal `"\x00"` (as a list element or dict key) still fails with
/// the documented `invalid_cli_program` -- the same reason a falsy `program`
/// gets, matching Python exactly.
#[test]
fn cli_profile_truthy_container_program_matches_python() {
    let accept_args = connection_create_args(
        r#"{"program": ["curl", "--silent"], "kind": "http"}"#,
        r#"{"mode": "bearer"}"#,
    );
    let accept_op: Map<String, Value> = serde_json::from_str(&accept_args).unwrap();
    let rust_fields = C::build_connection_fields(&accept_op)
        .expect("rust must accept a truthy, nul-free list program, matching python");
    assert_eq!(
        rust_fields.get("cli").unwrap().get("program").unwrap(),
        &json!(["curl", "--silent"]),
        "the list program must be folded VERBATIM into the document"
    );

    // A dict `program` containing the literal NUL as a KEY must still be
    // rejected the documented way.
    let reject_args = connection_create_args(
        "{\"program\": {\"\\u0000\": 1}, \"kind\": \"http\"}",
        r#"{"mode": "bearer"}"#,
    );
    let reject_op: Map<String, Value> = serde_json::from_str(&reject_args).unwrap();
    let rust_err = C::build_connection_fields(&reject_op)
        .expect_err("a dict program containing a literal NUL key must be rejected");
    assert_eq!(rust_err.reason, "invalid_cli_program");
}

/// Finding H-R5-4 (`build_cli_profile`'s check ORDER vs
/// `CliProfile.__post_init__`'s exact `kind` -> `program` -> `base_url_env`
/// -> entries sequence): with `kind` already valid, a FALSY `program`
/// (`""`) must raise `invalid_cli_program` even when `base_url_env` is ALSO
/// malformed (a non-string value, which on its own would fail with a
/// different substituted reason) -- Python's `__post_init__` never reaches
/// `base_url_env` at all once `program` has already failed. Before this
/// fix, the `program` check was deferred into `CliProfile::new_ordered`'s
/// own check at the very end of `build_cli_profile`, so `base_url_env`'s
/// check ran FIRST and its reason won instead.
#[test]
fn cli_profile_program_checked_before_base_url_env_matches_python() {
    let args_text = connection_create_args(
        r#"{"program": "", "kind": "http", "base_url_env": 5}"#,
        r#"{"mode": "bearer"}"#,
    );
    let op: Map<String, Value> = serde_json::from_str(&args_text).unwrap();
    let rust_err = C::build_connection_fields(&op)
        .expect_err("a falsy program must be rejected even with a malformed base_url_env");
    assert_eq!(
        rust_err.reason, "invalid_cli_program",
        "rust must report the PROGRAM failure, not whatever base_url_env's own reason is"
    );
}

/// Finding H-6 (the two `Commit::from_dict` DEVIATIONS.md rows, the second
/// covering `str(data["format"])`/`str(data["env_id"])`/`str(data["author"])`/
/// `str(data["hlc"])`/`str(data["sig"])`): Python's `str(x)` coerces *any*
/// JSON value into text rather than requiring it already be a string, and
/// under the peer-key ruling that gap is a real, fixable divergence (not a
/// trusted-input-shaped one) -- `Commit::from_dict` now goes through
/// `python_str_coerce` for these five fields instead of requiring
/// `Value::as_str`.
#[test]
fn commit_from_dict_coerces_non_string_scalar_fields_like_python_str() {
    let raw = json!({
        "format": "zeropw-team-commit-v1",
        "env_id": 12345,
        "author": true,
        "author_seq": 1,
        "hlc": 1000,
        "seen": {},
        "ops": [{"op": "settings.update", "sync_interval_seconds": 1}],
        "sig": null,
    });
    let rust_commit = Commit::from_dict(&raw).expect("must parse despite non-string fields");
    let rust_text = pyjson::dumps(&rust_commit.to_dict(), DumpOptions::compact_sorted()).unwrap();

    // What the Python prototype's `Commit.from_dict(...).to_dict()` gave.
    assert_eq!(
        rust_text,
        r#"{"author":"True","author_seq":1,"env_id":"12345","format":"zeropw-team-commit-v1","hlc":"1000","ops":[{"op":"settings.update","sync_interval_seconds":1}],"seen":{},"sig":"None"}"#
    );
}

/// Finding H-R4-1 (`DeviceRecord::from_dict` vs `zeropw/team/identity.py`
/// `DeviceRecord.from_dict`): Python applies `str(...)` to `sign_pub`/
/// `agree_pub`/`sig` before its lenient `base64.b64decode`, so a peer op
/// whose `device.sign_pub` is a ONE-ELEMENT ARRAY holding the base64 text
/// (`["<b64>"]`) still decodes to the correct 32 bytes: `str(["<b64>"])`
/// yields `"['<b64>']"`, and the lenient decoder discards the brackets and
/// quotes as non-alphabet characters. Before this fix, Rust required
/// `sign_pub` to already be a JSON string and rejected the whole
/// `member.add` commit as `team_op_format_invalid_device_record`, which then
/// made every LATER commit from the same author fail as `team_seq_gap`
/// forever (a rejected commit is never stored, so the author's sequence
/// never advances) -- a permanent, peer-reachable divergence: Python
/// accepts all three commits below and the member joins; Rust rejected two
/// of three and the member never joined.
#[test]
fn member_add_device_record_with_array_wrapped_field_matches_python_receive_commit() {
    let owner = fixed_device(0x71, 0x72);
    let new_device = fixed_device(0x73, 0x74);
    let owner_record = owner.record().unwrap();
    let new_record = new_device.record().unwrap();
    let env_id = C::new_env_id(&owner_record.fingerprint()).unwrap();
    let gen0 = "0".repeat(16);

    let c1 = C::sign_commit(
        &owner,
        &env_id,
        1,
        "1000-0000",
        &BTreeMap::new(),
        vec![env_init_op(&owner_record, "alice", &gen0)],
    )
    .unwrap();

    // Reshape `device.sign_pub` as a one-element array of the base64 text --
    // exactly the peer-op shape from the finding.
    let mut malformed_device = new_record.to_dict();
    let sign_pub_b64 = malformed_device
        .as_object()
        .unwrap()
        .get("sign_pub")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    malformed_device
        .as_object_mut()
        .unwrap()
        .insert("sign_pub".to_string(), json!([sign_pub_b64]));

    let c2 = C::sign_commit(
        &owner,
        &env_id,
        2,
        "2000-0000",
        &BTreeMap::new(),
        vec![
            json!({"op": "member.add", "device": malformed_device, "name": "bob", "role": "user"}),
        ],
    )
    .unwrap();
    let c3 = C::sign_commit(
        &owner,
        &env_id,
        3,
        "3000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "settings.update", "sync_interval_seconds": 42})],
    )
    .unwrap();

    let (_tmp, state) = fresh_state();
    let store = C::CommitStore::new(&state, env_id.clone());
    let rust_results: Vec<&str> = [&c1, &c2, &c3]
        .iter()
        .map(|c| C::receive_commit(&store, c, 1_000_000, None).unwrap())
        .collect();
    assert_eq!(
        rust_results,
        vec!["accepted", "accepted", "accepted"],
        "rust receive_commit outcomes"
    );

    // The commit store, folded, must show both members joined, like Python.
    let all_commits = store.all_commits().unwrap();
    let rust_fold = F::fold(&env_id, all_commits, None, None, None, None).unwrap();
    let members = rust_fold.document["members"].as_object().unwrap();
    assert_eq!(members.len(), 2, "owner + new member must both be present");
}

/// Finding H-R5-1: `DeviceRecord::from_dict`'s `str(...)` coercion for
/// `sign_pub`/`agree_pub`/`sig` (`crate::team::commit::python_str_coerce`,
/// PORTING.md §3b's canonical coercion, now backed by
/// `crate::pystr::repr_value` for the `Array`/`Object` cases) against
/// `zeropw/team/identity.py`'s `_b64d(str(data[key]))`. Two shapes from
/// the reviewer's own probes, run directly against
/// `DeviceRecord::from_dict`/`DeviceRecord.from_dict` (no signing/receiving
/// needed -- this is purely a decode-correctness question, not an
/// accept/reject-of-a-commit one):
///
/// (a) A dict-ordered `agree_pub` (`{"!": "<first 20 chars>", " ": "<rest>"}`)
///     decodes to the REAL 32-byte key in Python, because `str(dict)`
///     preserves INSERTION order (matching the JSON document's own key
///     order) and the lenient base64 decoder discards the non-alphabet
///     `{`/`}`/`'`/`:`/`,`/space characters wherever they fall. Before this
///     fix, `python_str_coerce` rendered this as compact, SORTED JSON
///     (`{" ":"...","!":"..."}`, keys reordered) instead of CPython's
///     `repr()` text (`{'!': '...', ' ': '...'}`, insertion order) -- the
///     reordering shuffled which base64 characters landed where, decoding
///     to the WRONG 17 bytes instead of the real key.
/// (b) An array-wrapped `agree_pub` with a literal NON-ASCII element
///     alongside the real base64 text (`["<b64>", "é"]`) is REJECTED
///     by Python: `str(["<b64>", "é"])` contains the literal `é` (`repr()`
///     never escapes a printable non-ASCII codepoint), and
///     `base64.b64decode` on a `str` containing any non-ASCII character
///     raises `ValueError` before the lenient scan even runs. Before this
///     fix, `python_str_coerce` rendered this as compact JSON with
///     `ensure_ascii`-style escaping (`["<b64>","é"]`, still pure
///     ASCII), which the lenient decoder then silently accepted --
///     decoding to the CORRECT 32 bytes -- so Rust wrongly ACCEPTED a
///     device Python rejects. `pybase64::b64decode`'s existing ASCII
///     precheck (`require_ascii`, unchanged by this fix) is what turns the
///     corrected `repr()` text into the matching rejection automatically
///     once the literal `é` is no longer escaped away.
#[test]
fn device_record_from_dict_container_field_coercion_matches_python() {
    let new_device = fixed_device(0x81, 0x82);
    let record = new_device.record().unwrap();
    let agree_pub_b64 = record
        .to_dict()
        .as_object()
        .unwrap()
        .get("agree_pub")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

    // (a) dict-ordered, non-alphabetically-sorted keys: must be ACCEPTED
    // and decode to the real key, matching Python.
    let (first, rest) = agree_pub_b64.split_at(20);
    let mut reordered = Map::new();
    reordered.insert("!".to_string(), json!(first));
    reordered.insert(" ".to_string(), json!(rest));
    let mut dict_order_device = record.to_dict();
    dict_order_device
        .as_object_mut()
        .unwrap()
        .insert("agree_pub".to_string(), Value::Object(reordered));

    let rust_result = DeviceRecord::from_dict(&dict_order_device);
    assert!(
        rust_result.is_ok(),
        "rust must accept the dict-ordered agree_pub, matching python: {rust_result:?}"
    );
    assert_eq!(
        rust_result.unwrap(),
        record,
        "the decoded record must match the real one -- the dict-ordered field must decode to the \
         SAME bytes as the plain string form"
    );

    // (b) array-wrapped with a literal non-ASCII element: must be REJECTED,
    // matching Python.
    let mut array_nonascii_device = record.to_dict();
    array_nonascii_device.as_object_mut().unwrap().insert(
        "agree_pub".to_string(),
        json!([agree_pub_b64.clone(), "\u{00e9}"]),
    );
    let rust_result = DeviceRecord::from_dict(&array_nonascii_device);
    assert!(
        rust_result.is_err(),
        "rust must reject the non-ASCII-containing array agree_pub, matching python"
    );
}

/// Finding H-R2-5 (`Commit::from_dict`'s `ops` arm vs `zeropw/team/commit.py`
/// `Commit.from_dict`): Python's `tuple(dict(op) for op in data["ops"])`
/// normalises each op element through `dict()`, which accepts a mapping OR
/// an iterable of two-element pairs -- not just a JSON object. An on-disk
/// commit whose `ops[0]` is reshaped as `[["op", "settings.update"],
/// ["sync_interval_seconds", 7]]` must still parse and process exactly like
/// the equivalent JSON object would (the signature was computed over the
/// *reconstructed* dict either way, so a lenient parser sees no difference).
/// Before this fix, `Commit::from_dict` required every `ops` element to
/// already be a JSON object, so this single reshaped op made the entire
/// commit -- and therefore `CommitStore::all_commits()`'s whole fold input,
/// since it calls `Commit::from_dict` for every stored file -- fail to load.
#[test]
fn commit_ops_element_accepts_pair_list_like_python_dict_op() {
    let owner = fixed_device(0x61, 0x62);
    let record = owner.record().unwrap();
    let env_id = C::new_env_id(&record.fingerprint()).unwrap();
    let gen0 = "0".repeat(16);
    let c1 = C::sign_commit(
        &owner,
        &env_id,
        1,
        "1000-0000",
        &BTreeMap::new(),
        vec![env_init_op(&record, "alice", &gen0)],
    )
    .unwrap();
    let c2 = C::sign_commit(
        &owner,
        &env_id,
        2,
        "2000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "settings.update", "sync_interval_seconds": 7})],
    )
    .unwrap();
    let mut c2_reshaped = c2.to_dict();
    let op_obj = c2_reshaped["ops"][0].as_object().unwrap().clone();
    let pairs: Vec<Value> = op_obj.into_iter().map(|(k, v)| json!([k, v])).collect();
    c2_reshaped["ops"][0] = json!(pairs);

    let (_tmp, state) = fresh_state();
    let store = C::CommitStore::new(&state, env_id.clone());
    assert_eq!(
        C::receive_commit(&store, &c1, 1_000_000, None).unwrap(),
        "accepted"
    );
    let rust_c2 = Commit::from_dict(&c2_reshaped).expect("pair-list op must parse");
    assert_eq!(rust_c2.ops[0].get("sync_interval_seconds"), Some(&json!(7)));
    let rust_result = C::receive_commit(&store, &rust_c2, 1_000_000, None).unwrap();
    assert_eq!(rust_result, "accepted");
    // `all_commits()` reads every stored commit file back through
    // `Commit::from_dict` -- must not fail now that c2 was actually
    // appended with a pair-list op.
    let all = store.all_commits().unwrap();
    assert_eq!(all.len(), 2);
}

/// Finding H-R3-3 (correcting H-R2-5's own reasoning): a pair-list `ops`
/// element whose KEY isn't a JSON string, e.g.
/// `[["op", "settings.update"], [1, "x"]]`, is not actually inert in
/// Python just because no op handler looks it up by name -- `dict()` keeps
/// the `1` key like any other, and `Commit.canonical_json`'s
/// `json.dumps(..., sort_keys=True)` (the exact bytes signed and hashed)
/// then raises an uncaught `TypeError` trying to sort `1` against `"op"`.
/// The round-2 fix silently dropped the bad-keyed pair and kept the rest of
/// the op, so this port ACCEPTED and FOLDED a commit shape Python can never
/// even hash, let alone sign or verify -- confirmed here against real
/// `python3.12`: `Commit.from_dict` succeeds, but `canonical_json` (and
/// therefore `hash`/`sign_commit`/`receive_commit`) always raises for this
/// exact shape. `Commit::from_dict` must instead reject the whole commit as
/// malformed, matching "every real caller's canonicalization step raises".
#[test]
fn commit_ops_element_with_non_string_pair_key_is_pythons_uncaught_typeerror() {
    let data = json!({
        "format": "zeropw-team-commit-v1", "env_id": "e", "author": "a", "author_seq": 1,
        "hlc": "1000-0000", "seen": {}, "sig": "",
        "ops": [[["op", "settings.update"], [1, "x"]]],
    });

    // Python's `Commit.from_dict` itself succeeds; the uncaught
    // `TypeError` comes from canonicalization. Rust reports that later
    // failure as the non-`InvalidInput` uncaught-builtin error, so callers
    // do not treat it as an ordinary malformed (ignored) message.
    let err = Commit::from_dict(&data).expect_err("Rust cannot hold a non-string op key");
    assert!(!err.is(zeropw::errors::ErrorClass::InvalidInput));
    assert_eq!(err.reason, "team_uncaught_exception");
    assert_eq!(err.detail, "TypeError");
}

/// Finding H-6 (`Commit::from_dict`'s `seen` arm vs `zeropw/team/commit.py`
/// `Commit.from_dict`): Python's `dict(data.get("seen") or {})` accepts any
/// iterable of key/value pairs (e.g. a wire `seen` of `[["<fp>", 3]]`,
/// which parses to the same dict a normal `{"<fp>": 3}` would and the
/// commit is still validly signed, since `canonical_json()` re-derives the
/// exact same signed bytes from either wire shape); it also accepts
/// `author_seq`/`seen` magnitudes far outside `i64`.
#[test]
fn commit_from_dict_accepts_seen_pairs_and_large_author_seq() {
    let owner = fixed_device(0x51, 0x52);
    let record = owner.record().unwrap();
    let env_id = C::new_env_id(&record.fingerprint()).unwrap();
    let gen0 = "0".repeat(16);
    let c1 = C::sign_commit(
        &owner,
        &env_id,
        1,
        "1000-0000",
        &BTreeMap::new(),
        vec![env_init_op(&record, "alice", &gen0)],
    )
    .unwrap();

    // --- seen as an array of pairs: reshape an already-signed commit's
    // wire JSON, keeping `sig` untouched -- the signature only has to
    // match the *reconstructed* canonical bytes (always an object for
    // `seen`), not the wire shape, so this is transparent to a lenient
    // parser and must be ACCEPTED, not `commit_malformed`.
    let mut seen_map = BTreeMap::new();
    seen_map.insert(record.fingerprint(), PyInt::from(3));
    let c2 = C::sign_commit(
        &owner,
        &env_id,
        2,
        "2000-0000",
        &seen_map,
        vec![json!({"op": "settings.update", "sync_interval_seconds": 1})],
    )
    .unwrap();
    let mut c2_reshaped = c2.to_dict();
    c2_reshaped["seen"] = json!([[record.fingerprint(), 3]]);

    {
        let (_tmp, state) = fresh_state();
        let store = C::CommitStore::new(&state, env_id.clone());
        assert_eq!(
            C::receive_commit(&store, &c1, 1_000_000, None).unwrap(),
            "accepted"
        );
        let rust_c2 = Commit::from_dict(&c2_reshaped).expect("seen-as-pairs must parse");
        assert_eq!(
            rust_c2.seen.get(&record.fingerprint()),
            Some(&PyInt::from(3))
        );
        let rust_result = C::receive_commit(&store, &rust_c2, 1_000_000, None).unwrap();
        assert_eq!(rust_result, "accepted");
    }

    // --- a large author_seq: signed directly (this port's own signer
    // natively supports `i128`), so no reshaping trick is needed. A fresh
    // store has `last_seq == 1` after the bootstrap, so `10**30` is a
    // massive gap -- both languages must reject with the same reason
    // (`team_seq_gap`), not diverge because one side rejected the commit
    // outright as malformed before ever checking the sequence.
    {
        let (_tmp, state) = fresh_state();
        let store = C::CommitStore::new(&state, env_id.clone());
        assert_eq!(
            C::receive_commit(&store, &c1, 1_000_000, None).unwrap(),
            "accepted"
        );
        let huge = C::sign_commit(
            &owner,
            &env_id,
            1_000_000_000_000_000_000_000_000_000_000_i128,
            "2000-0000",
            &BTreeMap::new(),
            vec![json!({"op": "settings.update", "sync_interval_seconds": 1})],
        )
        .unwrap();
        let rust_result = C::receive_commit(&store, &huge, 1_000_000, None).unwrap();
        assert_eq!(rust_result, "rejected");
    }
}

/// Finding H-R5-5 (`Commit::from_dict`'s `seen` building vs
/// `zeropw/team/commit.py`'s `seen={str(k): int(v) for k, v in
/// dict(data.get("seen") or {}).items()}`): Python's `dict(pairs)` runs
/// FIRST, entirely on its own, before `str(k)`/`int(v)` ever touch
/// anything. A `list`/`dict` PAIR KEY is Python's own UNHASHABLE type, an
/// uncaught `TypeError` from `dict()` itself -- caught by
/// `Commit.from_dict`'s own `except (KeyError, TypeError, ValueError)` and
/// reported as the documented `commit_malformed`, confirmed against real
/// `python3.12`. A HASHABLE key collides with any other Python-equal one:
/// `bool`/`int`/`float` all compare and hash by pure NUMERIC value, so
/// `dict([(True, 1), (1, 2)])` has exactly ONE entry (`{True: 2}` -- the
/// FIRST key's representation, the LAST value written for it), confirmed
/// against real `python3.12`. Before this fix, `Commit::from_dict` coerced
/// EVERY pair's key to a STRING (via `python_str_coerce`) and inserted
/// directly into a `BTreeMap<String, i128>`, before ever considering
/// whether two JSON-distinct keys were the same Python dict key -- so
/// `True`/`1` never collided here the way they do in Python, a `list`/
/// `dict` key was silently coerced to text instead of rejected, and a
/// discarded pair's VALUE could spuriously fail `int()` validation even
/// though Python's real `dict()`-first order never evaluates `int()` on a
/// value that gets overwritten before ever being read.
#[test]
fn commit_from_dict_seen_pair_key_hashability_and_collisions_match_python() {
    fn from_dict_seen(seen: Value) -> String {
        let data = json!({
            "format": "zeropw-team-commit-v1", "env_id": "env", "author": "auth",
            "author_seq": 1, "hlc": "1000-0000", "seen": seen,
            "ops": [{"op": "settings.update", "sync_interval_seconds": 1}], "sig": "",
        });
        match Commit::from_dict(&data) {
            Ok(c) => {
                let mut entries: Vec<(String, PyInt)> = c.seen.into_iter().collect();
                entries.sort();
                format!(
                    "OK {}",
                    entries
                        .iter()
                        .map(|(k, v)| format!("{k:?}:{v}"))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            }
            Err(e) => format!("ERR {}", e.reason),
        }
    }

    // Outcomes measured against the Python prototype (`ERR` for an
    // unhashable pair key; colliding keys keep the FIRST key's text and the
    // LAST value).
    let cases: &[(&str, &str, &str)] = &[
        // Unhashable pair keys: a list, then a dict.
        (r#"[[["x"], 5]]"#, "list key", "ERR commit_malformed"),
        (r#"[[{"a": 1}, 5]]"#, "dict key", "ERR commit_malformed"),
        // bool/int collide: ONE entry, first key's repr, last value.
        (
            r#"[[true, 1], [1, 2]]"#,
            "bool/int collision",
            r#"OK "True":2"#,
        ),
        // bool/float/int collide, mixed with an ordinary string key.
        (
            r#"[["fp", 1], [1.0, 2], [true, 3]]"#,
            "fp plus float/bool/int collision",
            r#"OK "1.0":3,"fp":1"#,
        ),
        // false/0 collide too.
        (
            r#"[[false, 1], [0, 2], [0.0, 3]]"#,
            "false/0/0.0 collision",
            r#"OK "False":3"#,
        ),
        // A later pair's key collides with and overwrites an earlier one
        // whose VALUE would otherwise fail int() validation -- Python's
        // dict()-first order never evaluates int() on the discarded value.
        (
            r#"[[1, "not-an-int"], [1, 5]]"#,
            "overwritten bad value never validated",
            r#"OK "1":5"#,
        ),
        (
            r#"[[9007199254740992, 1], [9007199254740993, 2]]"#,
            "distinct integer keys above binary64 precision",
            r#"OK "9007199254740992":1,"9007199254740993":2"#,
        ),
        (
            r#"[[9007199254740992.0, 1], [9007199254740993, 2]]"#,
            "float and next integer stay distinct",
            r#"OK "9007199254740992.0":1,"9007199254740993":2"#,
        ),
        (
            r#"[{"a": 0, "2": 1}]"#,
            "two-key mapping as pair iterable",
            r#"OK "a":2"#,
        ),
    ];

    for (seen_json, label, expected) in cases {
        let seen_value: Value = serde_json::from_str(seen_json).unwrap();
        assert_eq!(
            from_dict_seen(seen_value),
            *expected,
            "case {label:?} ({seen_json})"
        );
    }
}

// ------------------------------------------------------------------ H-R2-9
// Round-2 equivalence-review finding H-R2-9: several §3.5-shaped mappings
// (Rust substitutes a documented reason for something Python does NOT
// handle the same way) were real but unrecorded in `rust/DEVIATIONS.md`.
// Each test below pins BOTH sides: Python's real, concrete behaviour for
// the case, and Rust's substituted reason -- see `rust/DEVIATIONS.md`'s
// new rows for the write-up.

/// Finding H-R2-9(a): `_build_http_scope`'s `path_prefixes` loop calls
/// `prefix.startswith("/")` with no `isinstance` guard, so a non-string
/// element is a genuinely uncaught `AttributeError` -- not even caught by
/// `_build_http_scope`'s own `except (KeyError, TypeError)`, since
/// `AttributeError` isn't in that tuple. `json_strings_lossy`'s sentinel
/// (a value no real path prefix can equal) makes Rust reach the documented
/// `invalid_path_prefix` instead.
#[test]
fn path_prefixes_non_string_element_is_pythons_uncaught_attributeerror() {
    // Reached via the public `validate_op` (`_build_http_scope`'s Rust
    // port is private), same connection.create baseline as the H-5 reason
    // sweep.
    for elem in [json!(5), json!(true)] {
        let op = json!({"op": "connection.create", "id": "gh", "project": "demo", "environment": "dev",
              "service": "github", "kind": "http", "secret_id": "gh-token", "secret_version": null,
              "description": "", "http_target": {"scheme": "https", "host": "api.github.com", "port": 443},
              "http_auth": {"mode": "bearer"}, "http_scope": {"methods": ["GET"], "path_prefixes": [elem]}});
        let err = C::validate_op(&op).unwrap_err();
        assert!(!err.is(zeropw::errors::ErrorClass::InvalidInput));
        assert_eq!(err.reason, "team_uncaught_exception");
        assert_eq!(err.detail, "AttributeError");
    }
}

/// Finding H-R2-9(b), corrected by finding H-R5-3: `HttpAuth.__post_init__`'s
/// `HEADER_NAME_RE.match(self.header_name)` (mode `"header"`) has no
/// `isinstance` guard either; a TRUTHY non-string value there is an
/// uncaught `TypeError` that `_build_http_auth`'s own `except KeyError`
/// (KeyError only, not TypeError) does not catch. This row's ORIGINAL
/// claim was that `":" in self.basic_username` (mode `"basic"`) behaves the
/// SAME way for a truthy non-string value -- that is only true for a
/// truthy non-ITERABLE scalar (`int`/`float`/`bool`, this test's own `5`/
/// `true` cases: `"in"` on a non-iterable raises `TypeError` too). It is
/// FALSE for a truthy list/dict: `"in"` is a plain membership test that
/// works on any iterable and does not raise at all for one, so Python
/// accepts and keeps it verbatim (see
/// `http_auth_truthy_container_basic_username_matches_python`, right
/// below). For the scalar case this test covers, `opt_string`/
/// `basic_username_decision` (post-H-R5-3) still collapse the value to
/// `None`, so Rust still reaches the documented
/// `invalid_header_name`/`invalid_basic_username` a FALSY value would also
/// get.
#[test]
fn header_name_and_basic_username_truthy_non_string_is_pythons_uncaught_typeerror() {
    let http_auth_base = |auth: Value| {
        json!({"op": "connection.create", "id": "gh", "project": "demo", "environment": "dev",
              "service": "github", "kind": "http", "secret_id": "gh-token", "secret_version": null,
              "description": "", "http_target": {"scheme": "https", "host": "api.github.com", "port": 443},
              "http_auth": auth, "http_scope": {"methods": ["GET"]}})
    };
    for auth in [
        json!({"mode": "header", "header_name": 5}),
        json!({"mode": "header", "header_name": true}),
        json!({"mode": "header", "header_name": ["X-Foo"]}),
        json!({"mode": "basic", "basic_username": 5}),
        json!({"mode": "basic", "basic_username": true}),
    ] {
        let err = C::validate_op(&http_auth_base(auth)).unwrap_err();
        assert!(!err.is(zeropw::errors::ErrorClass::InvalidInput));
        assert_eq!(err.reason, "team_uncaught_exception");
        assert_eq!(err.detail, "TypeError");
    }
}

/// Finding H-R5-3 (`build_http_auth`'s `basic_username` check vs
/// `zeropw/policy.py` `HttpAuth.__post_init__`'s `if self.mode == "basic"
/// and (not self.basic_username or ":" in self.basic_username)`): the
/// DEVIATIONS.md H-R2-9b row's claim that a truthy non-string value here is
/// always Python's uncaught `TypeError` is only true for `header_name`
/// (`re.match` requires an actual `str`/`bytes` argument); `basic_username`
/// uses plain `"in"` membership, which works on any iterable, so a truthy
/// list/dict does NOT raise at all -- confirmed against real `python3.12`:
/// `build_connection_fields({"http_auth": {"mode": "basic",
/// "basic_username": ["curl", "user"]}, ...})` succeeds and keeps
/// `basic_username == ["curl", "user"]` verbatim. A container that DOES
/// contain the literal `":"` (as an element or key) still fails with the
/// documented `invalid_basic_username`, matching a colon-containing STRING
/// exactly.
#[test]
fn http_auth_truthy_container_basic_username_matches_python() {
    let accept_args = connection_create_args(
        r#"{"program": "gh", "kind": "http"}"#,
        r#"{"mode": "basic", "basic_username": ["curl", "user"]}"#,
    );
    let accept_op: Map<String, Value> = serde_json::from_str(&accept_args).unwrap();
    let rust_fields = C::build_connection_fields(&accept_op)
        .expect("rust must accept a truthy, colon-free list basic_username, matching python");
    assert_eq!(
        rust_fields
            .get("http_auth")
            .unwrap()
            .get("basic_username")
            .unwrap(),
        &json!(["curl", "user"]),
        "the list basic_username must be folded VERBATIM into the document"
    );

    // A list `basic_username` containing the literal ":" as an ELEMENT
    // must still be rejected the documented way.
    let reject_args = connection_create_args(
        r#"{"program": "gh", "kind": "http"}"#,
        r#"{"mode": "basic", "basic_username": ["a", ":"]}"#,
    );
    let reject_op: Map<String, Value> = serde_json::from_str(&reject_args).unwrap();
    let rust_err = C::build_connection_fields(&reject_op)
        .expect_err("a list basic_username containing the literal ':' must be rejected");
    assert_eq!(rust_err.reason, "invalid_basic_username");
}

/// Finding X-4: `HttpAuth.__post_init__` only inspects `header_name` when
/// `mode == "header"` (`if self.mode == "header": ...`) -- for every other
/// mode, Python validates it not at all and keeps whatever value it was
/// given verbatim. Confirmed against real `python3.12`:
/// `build_connection_fields({"http_auth": {"mode": "bearer", "header_name":
/// ["X-Foo"]}, ...})` returns `header_name: ["X-Foo"]`, `value_prefix: None`,
/// `basic_username: None`. Before this fix, `http_auth_value` (`team/
/// commit.rs`) rendered `a.header_name` -- which `build_http_auth`'s local
/// `opt_string` had already collapsed to `None` regardless of mode -- into
/// the folded document, silently losing the real value (`"header_name":
/// null` instead of `["X-Foo"]`): a Python node and a Rust node folding the
/// same commit chain would produce different documents.
#[test]
fn http_auth_container_header_name_matches_python_for_non_header_mode() {
    let args = connection_create_args("null", r#"{"mode": "bearer", "header_name": ["X-Foo"]}"#);
    let op: Map<String, Value> = serde_json::from_str(&args).unwrap();
    let rust_fields =
        C::build_connection_fields(&op).expect("rust must accept an unchecked header_name");
    assert_eq!(
        rust_fields.get("http_auth").unwrap(),
        &json!({"mode": "bearer", "header_name": ["X-Foo"], "value_prefix": null, "basic_username": null}),
        "the header_name container must be folded VERBATIM into the document, not dropped to null"
    );
}

/// Finding H-R2-9(c): a truthy plain *string* `extra_env` (e.g. `"ab"`) is
/// Python's uncaught `dict("ab")` `ValueError` (each character has length
/// 1, not the length-2 pair `dict()` needs) -- `_build_cli_profile`'s
/// `except (KeyError, TypeError)` does not catch `ValueError` either.
/// `python_dict_pairs` returns `None` for a top-level JSON string (the same
/// as any other shape it can't turn into pairs), which
/// `build_cli_profile`'s caller folds into `invalid_cli_profile`.
#[test]
fn extra_env_truthy_string_is_pythons_uncaught_valueerror() {
    let full_op = json!({"op": "connection.create", "id": "gh", "project": "demo", "environment": "dev",
          "service": "github", "kind": "http", "secret_id": "gh-token", "secret_version": null,
          "description": "", "http_target": {"scheme": "https", "host": "api.github.com", "port": 443},
          "http_auth": {"mode": "bearer"}, "http_scope": {"methods": ["GET"]},
          "cli": {"program": "gh", "kind": "http", "extra_env": "ab"}});
    let err = C::validate_op(&full_op).unwrap_err();
    assert!(!err.is(zeropw::errors::ErrorClass::InvalidInput));
    assert_eq!(err.reason, "team_uncaught_exception");
    assert_eq!(err.detail, "ValueError");
}

/// Regression for finding H-R2-9(d): `unwrap_dek`/`decrypt_secret` build each of
/// `eph_pub`/`nonce`/`ciphertext` with `str(wrap[key])`, so a *present*
/// `null` becomes the text `"None"` -- 4 base64-alphabet characters -- which
/// decodes cleanly to 3 bytes and reaches the real AEAD call, failing
/// there with the SAME documented reason a genuinely-wrong-but-well-formed
/// wrap would get (`dek_wrap_malformed` only if the resulting byte length
/// is wrong, e.g. `eph_pub`; `dek_unwrap_failed`/`secret_ciphertext_invalid`
/// for `nonce`/`ciphertext`, which reach `aead.decrypt` at any length and
/// fail authentication there instead). The port applies the same `str(...)`
/// coercion before decoding, so the documented reason agrees for every
/// field.
#[test]
fn envelope_null_field_matches_python_reason() {
    let owner = DeviceKey::generate();
    let record = owner.record().unwrap();
    let dek: Vec<u8> = (0..32u8).collect();
    let env_id = "0123456789abcdef0123456789abcdef";
    let generation_id = "deadbeefcafef00d";
    let wrap = envelope::wrap_dek(&dek, env_id, generation_id, &record).unwrap();

    for field in ["eph_pub", "nonce", "ciphertext"] {
        let mut w = wrap.clone();
        w[field] = Value::Null;
        let rust_reason = envelope::unwrap_dek(&w, env_id, generation_id, &owner)
            .unwrap_err()
            .reason
            .to_string();

        let expected = if field == "eph_pub" {
            "dek_wrap_malformed"
        } else {
            "dek_unwrap_failed"
        };
        assert_eq!(rust_reason, expected, "{field}=null");
    }
}
