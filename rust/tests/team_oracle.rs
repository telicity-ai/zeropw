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
use tempfile::{NamedTempFile, TempDir};

use zeropw::pyjson::{self, DumpOptions};
use zeropw::secret::SecretBytes;
use zeropw::store::StateDir;
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
    // Finding H-1: without a `secret.put_version` for "gh-token", both
    // `connection.create` ops below are skipped at fold time
    // (`secret_not_found`), so the whole connection path -- including the
    // `http_scope`/`ssh_target` tuple-rendering `to_yaml` bug -- went
    // untested. `secret.put_version` needs a generation id the document
    // already knows about (`gen0`, from `c1`'s `env.init`).
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

    // Finding H-1: `dataclasses.asdict(Connection(...))` keeps
    // `HttpScope.methods`/`path_prefixes`/`confirm_methods` as Python
    // tuples, which `to_yaml` renders as `str(tuple)` -- a single inline
    // scalar like `methods: ('GET',)`, never the multi-line `-` list form
    // `to_yaml` uses for a JSON array. Byte-equality with the oracle above
    // already proves this, but assert the concrete shape too so a future
    // change that happens to make both sides agree on the *wrong* thing
    // (e.g. by reverting `build_history()`'s secret so connections are
    // skipped again) fails loudly here instead of silently.
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

// ------------------------------------------------------------------ H-2/H-3/H-4/H-5/H-6
// Round-1 equivalence-review fixes for work unit H (team data layer). Each
// test below is oracle-backed: the same genuinely-signed commit (or op) is
// fed to both languages' `receive_commit`/`validate_op`/`fold`, and their
// outcomes are asserted equal -- both to each other and, where the finding
// spells one out, to the specific string the review recorded.

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
    let c1_text = pyjson::dumps(&c1.to_dict(), DumpOptions::compact_sorted()).unwrap();

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
        let c2_text = pyjson::dumps(&c2.to_dict(), DumpOptions::compact_sorted()).unwrap();

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

        let script = format!(
            r#"
import json, tempfile
from pathlib import Path
from zeropw.store import StateDir
from zeropw.team import commit as C
with tempfile.TemporaryDirectory() as tmp:
    state = StateDir(Path(tmp) / "state")
    state.create()
    store = C.CommitStore(state, {env_id})
    c1 = C.Commit.from_dict(json.loads({c1}))
    c2 = C.Commit.from_dict(json.loads({c2}))
    print(C.receive_commit(store, c1, 1_000_000))
    print(C.receive_commit(store, c2, 1_000_000))
"#,
            env_id = py_str_literal(&env_id),
            c1 = py_str_literal(&c1_text),
            c2 = py_str_literal(&c2_text),
        );
        let out = run_python(&script);
        let mut lines = out.lines();
        assert_eq!(lines.next().unwrap(), "accepted", "python bootstrap");
        let py_result = lines.next().unwrap();
        assert_eq!(
            py_result, expected,
            "python receive_commit outcome for hlc={hlc:?}"
        );
        assert_eq!(
            rust_result, py_result,
            "rust and python must agree for hlc={hlc:?}"
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

        let op_text = pyjson::dumps(&op, DumpOptions::compact_sorted()).unwrap();
        let script = format!(
            r#"
import json
from zeropw.team import commit as C
from zeropw.errors import InvalidInput
op = json.loads({op})
try:
    C.validate_op(op)
    print("accepted")
except InvalidInput as exc:
    print(exc.reason)
"#,
            op = py_str_literal(&op_text),
        );
        let py_result = run_python(&script);
        assert_eq!(py_result.trim(), expected, "python reason for {value}");
        assert_eq!(rust_result, py_result.trim());
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
/// document byte-for-byte.
#[test]
fn ca_file_and_value_prefix_pass_through_verbatim_in_folded_document() {
    let owner = fixed_device(0xF1, 0xF2);
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

    let commits_json: Vec<Value> = commits.iter().map(Commit::to_dict).collect();
    let temp = write_json_temp(&json!(commits_json));
    let script = format!(
        r#"
import json
from zeropw.team import commit as C
from zeropw.team import fold as F
with open({path}) as f:
    raw = json.load(f)
commits = [C.Commit.from_dict(c) for c in raw]
result = F.fold({env_id}, commits)
print(json.dumps(result.document, sort_keys=True, separators=(",", ":")))
"#,
        path = py_str_literal(temp.path().to_str().unwrap()),
        env_id = py_str_literal(&env_id),
    );
    let py_doc_text = run_python(&script);
    assert_eq!(
        rust_doc_text,
        py_doc_text.trim(),
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

    for (label, op, expected) in &cases {
        let rust_result = match C::validate_op(op) {
            Ok(()) => "accepted".to_string(),
            Err(e) => e.reason.to_string(),
        };
        assert_eq!(&rust_result, expected, "rust reason for case {label:?}");

        let op_text = pyjson::dumps(op, DumpOptions::compact_sorted()).unwrap();
        let script = format!(
            r#"
import json
from zeropw.team import commit as C
from zeropw.errors import InvalidInput
op = json.loads({op})
try:
    C.validate_op(op)
    print("accepted")
except InvalidInput as exc:
    print(exc.reason)
"#,
            op = py_str_literal(&op_text),
        );
        let py_result = run_python(&script);
        let py_result = py_result.trim();
        assert_eq!(py_result, *expected, "python reason for case {label:?}");
        assert_eq!(
            rust_result, py_result,
            "rust/python reason must agree for case {label:?}"
        );
    }
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

    let raw_text = pyjson::dumps(&raw, DumpOptions::compact_sorted()).unwrap();
    let script = format!(
        r#"
import json
from zeropw.team import commit as C
data = json.loads({raw})
c = C.Commit.from_dict(data)
print(json.dumps(c.to_dict(), sort_keys=True, separators=(",", ":")))
"#,
        raw = py_str_literal(&raw_text),
    );
    let py_text = run_python(&script);
    assert_eq!(rust_text, py_text.trim());
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
    let c1_text = pyjson::dumps(&c1.to_dict(), DumpOptions::compact_sorted()).unwrap();

    // --- seen as an array of pairs: reshape an already-signed commit's
    // wire JSON, keeping `sig` untouched -- the signature only has to
    // match the *reconstructed* canonical bytes (always an object for
    // `seen`), not the wire shape, so this is transparent to a lenient
    // parser and must be ACCEPTED, not `commit_malformed`.
    let mut seen_map = BTreeMap::new();
    seen_map.insert(record.fingerprint(), 3i128);
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
    let c2_text = pyjson::dumps(&c2_reshaped, DumpOptions::compact_sorted()).unwrap();

    {
        let (_tmp, state) = fresh_state();
        let store = C::CommitStore::new(&state, env_id.clone());
        assert_eq!(
            C::receive_commit(&store, &c1, 1_000_000, None).unwrap(),
            "accepted"
        );
        let rust_c2 = Commit::from_dict(&c2_reshaped).expect("seen-as-pairs must parse");
        assert_eq!(rust_c2.seen.get(&record.fingerprint()), Some(&3));
        let rust_result = C::receive_commit(&store, &rust_c2, 1_000_000, None).unwrap();
        assert_eq!(rust_result, "accepted");

        let script = format!(
            r#"
import json, tempfile
from pathlib import Path
from zeropw.store import StateDir
from zeropw.team import commit as C
with tempfile.TemporaryDirectory() as tmp:
    state = StateDir(Path(tmp) / "state")
    state.create()
    store = C.CommitStore(state, {env_id})
    c1 = C.Commit.from_dict(json.loads({c1}))
    c2 = C.Commit.from_dict(json.loads({c2}))
    print(C.receive_commit(store, c1, 1_000_000))
    print(C.receive_commit(store, c2, 1_000_000))
"#,
            env_id = py_str_literal(&env_id),
            c1 = py_str_literal(&c1_text),
            c2 = py_str_literal(&c2_text),
        );
        let out = run_python(&script);
        let mut lines = out.lines();
        assert_eq!(lines.next().unwrap(), "accepted");
        assert_eq!(
            lines.next().unwrap(),
            "accepted",
            "python must also accept seen-as-pairs"
        );
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
        let huge_text = pyjson::dumps(&huge.to_dict(), DumpOptions::compact_sorted()).unwrap();
        let rust_result = C::receive_commit(&store, &huge, 1_000_000, None).unwrap();
        assert_eq!(rust_result, "rejected");

        let script = format!(
            r#"
import json, tempfile
from pathlib import Path
from zeropw.store import StateDir
from zeropw.team import commit as C
with tempfile.TemporaryDirectory() as tmp:
    state = StateDir(Path(tmp) / "state")
    state.create()
    store = C.CommitStore(state, {env_id})
    c1 = C.Commit.from_dict(json.loads({c1}))
    huge = C.Commit.from_dict(json.loads({huge}))
    print(C.receive_commit(store, c1, 1_000_000))
    print(C.receive_commit(store, huge, 1_000_000))
"#,
            env_id = py_str_literal(&env_id),
            c1 = py_str_literal(&c1_text),
            huge = py_str_literal(&huge_text),
        );
        let out = run_python(&script);
        let mut lines = out.lines();
        assert_eq!(lines.next().unwrap(), "accepted");
        assert_eq!(
            lines.next().unwrap(),
            "rejected",
            "python must also reject the huge-seq commit"
        );
    }
}
