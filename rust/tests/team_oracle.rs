//! Differential tests for `zeropw::team` against the Python prototype
//! (`zeropw/team/`), per `rust/PORTING.md`'s "add oracle differential
//! tests ... for every cross-language format you own" rule for work unit H.
//!
//! Lives under `rust/tests/` as a standalone test binary (like
//! `policy_oracle.rs`/`state_dir_cross_language.rs`): `crate::oracle` is
//! `#[cfg(test)] pub(crate)` and not reachable from here, so this file has
//! its own tiny Python-running helper.
//!
//! Covers:
//! - Device identity: the SAME fixed seed pair derives byte-identical
//!   `DeviceRecord` fields (`sign_pub`, `agree_pub`, `sig`, fingerprint) in
//!   both languages, and each language's signature verifies under the
//!   other's decode.
//! - `envelope.wrap_dek`/`unwrap_dek`: a DEK wrapped in one language unwraps
//!   correctly in the other, in both directions.
//! - `commit.sign_commit`: the same device/env id/seq/hlc/seen/ops sign to
//!   byte-identical `Commit.to_dict()` (hash included) in both languages --
//!   Ed25519 is deterministic and the canonical JSON encoder is
//!   byte-identical, so this is not just "both succeed" but "both produce
//!   the exact same bytes".
//! - `fold()`: a fixed commit history, signed once in Rust and handed to
//!   Python as JSON, folds to a byte-identical environment document in
//!   both languages -- including under a handful of fixed-seed shuffles of
//!   arrival order on each side.
//! - `humanview.to_yaml`/`strip_document`: byte-identical rendering of the
//!   same folded document.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Map, Value, json};
use tempfile::NamedTempFile;

use zeropw::pyjson::{self, DumpOptions};
use zeropw::secret::SecretBytes;
use zeropw::team::commit::{self as C, Commit};
use zeropw::team::envelope;
use zeropw::team::fold as F;
use zeropw::team::humanview;
use zeropw::team::identity::{DeviceKey, DeviceRecord};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

/// Runs `script` with `python3.12` (override with `ZEROPW_PYTHON`) and the
/// repository root on `PYTHONPATH`. Panics with stderr on a non-zero exit.
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

/// Writes `data` to a fresh temp `.json` file and returns it (kept alive by
/// the caller for the duration of the Python subprocess).
fn write_json_temp(data: &Value) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("temp file");
    let text = pyjson::dumps(data, DumpOptions::compact_sorted()).expect("dumps");
    f.write_all(text.as_bytes()).expect("write temp json");
    f.flush().expect("flush");
    f
}

/// A valid single-quoted Python string literal for `s` (backslash/quote/
/// newline escaped), for splicing arbitrary Rust-computed text (JSON,
/// paths, hex) into a generated Python script -- Rust's own `format!` has
/// no `!r`-style repr formatting, so this does the escaping by hand.
fn py_str_literal(s: &str) -> String {
    let mut out = String::from("'");
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    out.push('\'');
    out
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
    let device = fixed_device(0x11, 0x22);
    let record = device.record().expect("record");
    let rust_dict = record.to_dict();
    let rust_dict_text = pyjson::dumps(&rust_dict, DumpOptions::compact_sorted()).unwrap();

    let script = r#"
import json
from zeropw.team.identity import DeviceKey
device = DeviceKey(bytes([0x11]) * 32, bytes([0x22]) * 32)
record = device.record
print(json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":")))
print(record.fingerprint)
print(record.verify())
"#;
    let out = run_python(script);
    let mut lines = out.lines();
    let py_dict_text = lines.next().unwrap();
    let py_fingerprint = lines.next().unwrap();
    let py_verify = lines.next().unwrap();

    assert_eq!(
        rust_dict_text, py_dict_text,
        "DeviceRecord.to_dict() must match byte-for-byte"
    );
    assert_eq!(record.fingerprint(), py_fingerprint);
    assert_eq!(py_verify, "True");
    assert!(record.verify());

    // The Rust-produced record, fed back through Python's own decoder, must
    // verify there too (round-trip through the wire encoding, not just
    // matching field values).
    let script2 = format!(
        r#"
import json
from zeropw.team.identity import DeviceRecord
record = DeviceRecord.from_dict(json.loads({text}))
print(record.verify())
"#,
        text = py_str_literal(&rust_dict_text),
    );
    let out2 = run_python(&script2);
    assert_eq!(out2.trim(), "True");
}

// ------------------------------------------------------------------ envelope
#[test]
fn wrap_in_rust_unwrap_in_python() {
    let recipient = fixed_device(0x33, 0x44);
    let record = recipient.record().unwrap();
    let dek: Vec<u8> = (0..32u8).collect();
    let env_id = "0123456789abcdef0123456789abcdef";
    let generation_id = "deadbeefcafef00d";
    let wrap = envelope::wrap_dek(&dek, env_id, generation_id, &record).unwrap();
    let wrap_text = pyjson::dumps(&wrap, DumpOptions::compact_sorted()).unwrap();

    let script = format!(
        r#"
import json
from zeropw.team import envelope
from zeropw.team.identity import DeviceKey
device = DeviceKey(bytes([0x33]) * 32, bytes([0x44]) * 32)
wrap = json.loads({wrap})
recovered = envelope.unwrap_dek(wrap, {env_id}, {generation_id}, device)
print(recovered.hex())
"#,
        wrap = py_str_literal(&wrap_text),
        env_id = py_str_literal(env_id),
        generation_id = py_str_literal(generation_id),
    );
    let out = run_python(&script);
    assert_eq!(out.trim(), hex::encode(&dek));
}

#[test]
fn wrap_in_python_unwrap_in_rust() {
    let recipient = fixed_device(0x55, 0x66);
    let dek_hex = "aa".repeat(32);
    let env_id = "0123456789abcdef0123456789abcdef";
    let generation_id = "deadbeefcafef00d";

    let script = format!(
        r#"
import json
from zeropw.team import envelope
from zeropw.team.identity import DeviceKey
device = DeviceKey(bytes([0x55]) * 32, bytes([0x66]) * 32)
record = device.record
wrap = envelope.wrap_dek(bytes.fromhex({dek_hex}), {env_id}, {generation_id}, record)
print(json.dumps(wrap, sort_keys=True, separators=(",", ":")))
"#,
        dek_hex = py_str_literal(&dek_hex),
        env_id = py_str_literal(env_id),
        generation_id = py_str_literal(generation_id),
    );
    let out = run_python(&script);
    let wrap: Value = pyjson::loads(out.trim()).unwrap();
    let recovered = envelope::unwrap_dek(&wrap, env_id, generation_id, &recipient).unwrap();
    assert_eq!(hex::encode(recovered), dek_hex);
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
    let owner = fixed_device(0x77, 0x88);
    let record = owner.record().unwrap();
    let env_id = C::new_env_id(&record.fingerprint()).unwrap();
    let op = env_init_op(&record, "alice-laptop", &"0".repeat(16));
    let c1 = C::sign_commit(
        &owner,
        &env_id,
        1,
        "1000-0000",
        &BTreeMap::new(),
        vec![op.clone()],
    )
    .unwrap();
    let rust_dict_text = pyjson::dumps(&c1.to_dict(), DumpOptions::compact_sorted()).unwrap();
    let rust_hash = c1.hash().unwrap();

    let script = format!(
        r#"
import json
from zeropw.team import commit as C
from zeropw.team.identity import DeviceKey
device = DeviceKey(bytes([0x77]) * 32, bytes([0x88]) * 32)
op = json.loads({op})
c1 = C.sign_commit(device, {env_id}, 1, "1000-0000", {{}}, [op])
print(json.dumps(c1.to_dict(), sort_keys=True, separators=(",", ":")))
print(c1.hash)
print(C.verify_commit(c1, device.record))
"#,
        op = py_str_literal(&pyjson::dumps(&op, DumpOptions::compact_sorted()).unwrap()),
        env_id = py_str_literal(&env_id),
    );
    let out = run_python(&script);
    let mut lines = out.lines();
    let py_dict_text = lines.next().unwrap();
    let py_hash = lines.next().unwrap();
    let py_verify = lines.next().unwrap();

    assert_eq!(
        rust_dict_text, py_dict_text,
        "Commit.to_dict() must match byte-for-byte"
    );
    assert_eq!(rust_hash, py_hash);
    assert_eq!(py_verify, "True");
    assert!(C::verify_commit(&c1, &record));

    // The Python-signed commit's own JSON, re-parsed and re-verified on the
    // Rust side.
    let py_commit_value: Value = pyjson::loads(py_dict_text).unwrap();
    let restored = Commit::from_dict(&py_commit_value).unwrap();
    assert_eq!(restored.hash().unwrap(), rust_hash);
    assert!(C::verify_commit(&restored, &record));
}

// ---------------------------------------------------------------------- fold
/// A small, fixed commit history (env.init, member.add, two
/// connection.create, a disable, a settings.update) signed once in Rust
/// with fixed-seed device keys, used by both the fold and humanview oracle
/// tests below.
fn build_history() -> (String, Vec<Commit>, DeviceRecord, DeviceRecord) {
    let owner = fixed_device(0x10, 0x20);
    let second = fixed_device(0x30, 0x40);
    let owner_record = owner.record().unwrap();
    let second_record = second.record().unwrap();
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
    let c2 = C::sign_commit(
        &owner,
        &env_id,
        2,
        "2000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "member.add", "device": second_record.to_dict(), "name": "bob", "role": "admin"})],
    )
    .unwrap();
    let conn_op = |conn_id: &str| {
        json!({"op": "connection.create", "id": conn_id, "project": "demo", "environment": "dev",
              "service": "github", "kind": "http", "secret_id": "gh-token", "secret_version": null,
              "description": "", "http_target": {"scheme": "https", "host": "api.github.com", "port": 443},
              "http_auth": {"mode": "bearer"}, "http_scope": {"methods": ["GET"], "path_prefixes": ["/repos"]}})
    };
    let c3 = C::sign_commit(
        &owner,
        &env_id,
        3,
        "3000-0000",
        &BTreeMap::new(),
        vec![conn_op("gh")],
    )
    .unwrap();
    let c4 = C::sign_commit(
        &second,
        &env_id,
        1,
        "3000-0000",
        &BTreeMap::new(),
        vec![conn_op("gitlab")],
    )
    .unwrap();
    let c5 = C::sign_commit(
        &owner,
        &env_id,
        4,
        "4000-0000",
        &BTreeMap::new(),
        vec![json!({"op": "connection.disable", "id": "gh"})],
    )
    .unwrap();
    let c6 = C::sign_commit(
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
        vec![c1, c2, c3, c4, c5, c6],
        owner_record,
        second_record,
    )
}

#[test]
fn fold_matches_python_for_a_fixed_commit_history() {
    let (env_id, commits, _owner_record, _second_record) = build_history();
    let rust_result = F::fold(&env_id, commits.clone(), None, None, None, None).unwrap();
    let rust_doc_text =
        pyjson::dumps(&rust_result.document, DumpOptions::compact_sorted()).unwrap();

    let commits_json: Vec<Value> = commits.iter().map(Commit::to_dict).collect();
    let temp = write_json_temp(&json!(commits_json));
    let script = format!(
        r#"
import json
import random
from zeropw.team import commit as C
from zeropw.team import fold as F
with open({path}) as f:
    raw = json.load(f)
commits = [C.Commit.from_dict(c) for c in raw]
canonical = None
for seed in range(4):
    rnd = random.Random(seed)
    shuffled = commits[:]
    rnd.shuffle(shuffled)
    result = F.fold({env_id}, shuffled)
    as_json = json.dumps(result.document, sort_keys=True, separators=(",", ":"))
    if canonical is None:
        canonical = as_json
    assert as_json == canonical, f"python-side shuffle {{seed}} diverged"
print(canonical)
"#,
        path = py_str_literal(temp.path().to_str().unwrap()),
        env_id = py_str_literal(&env_id),
    );
    let out = run_python(&script);
    let py_doc_text = out.trim();
    assert_eq!(
        rust_doc_text, py_doc_text,
        "fold() must produce a byte-identical document"
    );

    // And the reverse direction: fold the same history under a handful of
    // fixed-seed Rust-side shuffles too (order-independence on this side).
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
        let text = pyjson::dumps(&result.document, DumpOptions::compact_sorted()).unwrap();
        assert_eq!(
            text, py_doc_text,
            "rust-side shuffle diverged from the python oracle"
        );
    }
}

// ----------------------------------------------------------------- humanview
#[test]
fn humanview_matches_python_for_the_folded_history() {
    let (env_id, commits, _owner_record, _second_record) = build_history();
    let rust_result = F::fold(&env_id, commits.clone(), None, None, None, None).unwrap();
    let stripped = humanview::strip_document(&rust_result.document);
    let rust_yaml = humanview::to_yaml(&stripped);
    let rust_stripped_json = pyjson::dumps(&stripped, DumpOptions::compact_sorted()).unwrap();

    let commits_json: Vec<Value> = commits.iter().map(Commit::to_dict).collect();
    let temp = write_json_temp(&json!(commits_json));
    let script = format!(
        r#"
import json
from zeropw.team import commit as C
from zeropw.team import fold as F
from zeropw.team import humanview as H
with open({path}) as f:
    raw = json.load(f)
commits = [C.Commit.from_dict(c) for c in raw]
result = F.fold({env_id}, commits)
stripped = H.strip_document(result.document)
print(json.dumps(stripped, sort_keys=True, separators=(",", ":")))
print("---SPLIT---")
print(H.to_yaml(stripped), end="")
"#,
        path = py_str_literal(temp.path().to_str().unwrap()),
        env_id = py_str_literal(&env_id),
    );
    let out = run_python(&script);
    let mut parts = out.splitn(2, "---SPLIT---\n");
    let py_stripped_json = parts.next().unwrap().trim_end_matches('\n');
    let py_yaml = parts.next().unwrap();

    assert_eq!(
        rust_stripped_json, py_stripped_json,
        "strip_document() must match byte-for-byte"
    );
    assert_eq!(rust_yaml, py_yaml, "to_yaml() must match byte-for-byte");
}
