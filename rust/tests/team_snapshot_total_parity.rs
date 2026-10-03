//! Exact Python numbers for team snapshot totals and scheduling.
//!
//! `zeropw/team/sync.py` keeps `last_snapshot_total = sum((snapshot.get(
//! "vector") or {}).values())` from the newest snapshot and saves a new one
//! when `sum(result.vector.values()) - last_snapshot_total >= 1000`. Both
//! sums are Python's built-in `sum()` over unbounded ints (and, for a
//! hand-written snapshot vector, floats and bools), so the scheduling
//! decision and the saved file name must follow CPython exactly. These
//! tests compare `zeropw::pyint::python_sum` / `PyInt::to_f64` against
//! CPython 3.12 and the whole `register_env` -> refold -> snapshot decision
//! against Python's `TeamSync`.
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;

use num_bigint::BigInt;
use serde_json::{Value, json};
use tempfile::TempDir;
use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::pyint::{PyInt, PyNumber, python_sum};
use zeropw::pyjson::{self, DumpOptions};
use zeropw::team::identity::{DeviceKey, DeviceRecord};
use zeropw::team::transport::{InProcessTransport, MembershipCheck};
use zeropw::team::{membership, sync};

const ADMIN: &str = "synthetic-admin";

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

fn literal(value: &Value) -> String {
    zeropw::pystr::repr_str(&pyjson::dumps(value, DumpOptions::compact_sorted()).unwrap())
}

/// A deterministic pseudo-random sequence (no seeding API needed).
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 11
    }
}

fn big(text: &str) -> BigInt {
    text.parse().unwrap()
}

/// `float(int)` (round-half-even, `OverflowError` at 2**1024) for edge and
/// random magnitudes, compared bit-for-bit with CPython.
#[test]
fn int_to_float_conversion_matches_python() {
    let mut values: Vec<BigInt> = Vec::new();
    for bits in [52u32, 53, 54, 63, 64, 100, 1022, 1023, 1024, 1025] {
        let base = BigInt::from(1) << bits as usize;
        for delta in [-3i64, -1, 0, 1, 3] {
            values.push(&base + delta);
            values.push(-(&base + delta));
        }
    }
    // Halfway cases just above 2**53 and just below 2**1024.
    values.push((BigInt::from(1) << 53usize) + 1);
    values.push((BigInt::from(1) << 53usize) + 3);
    values.push((BigInt::from(1) << 1024usize) - (BigInt::from(1) << 970usize));
    values.push((BigInt::from(1) << 1024usize) - (BigInt::from(1) << 971usize));
    let mut rng = Lcg(7);
    for _ in 0..400 {
        let digits = 1 + rng.next() % 330;
        let text: String = (0..digits)
            .map(|i| {
                let d = rng.next() % 10;
                char::from(b'0' + if i == 0 { 1 + (d % 9) as u8 } else { d as u8 })
            })
            .collect();
        values.push(big(&text));
    }
    let texts: Vec<String> = values.iter().map(BigInt::to_string).collect();
    let script = format!(
        "import json, struct\nout = []\nfor t in json.loads({}):\n    try:\n        out.append(struct.unpack('<Q', struct.pack('<d', float(int(t))))[0])\n    except OverflowError:\n        out.append(None)\nprint(json.dumps(out))\n",
        literal(&json!(texts))
    );
    let python = python(&script);
    for (value, expected) in values.iter().zip(python.as_array().unwrap()) {
        let rust = PyInt(value.clone()).to_f64().map(f64::to_bits);
        assert_eq!(json!(rust), *expected, "float({value})");
    }
}

fn number_json(result: Option<PyNumber>) -> Value {
    match result {
        None => json!("ERR"),
        Some(PyNumber::Int(i)) => json!(["int", i.to_string()]),
        Some(PyNumber::Float(f)) => json!(["float", f.to_bits()]),
    }
}

/// CPython 3.12's `sum()` -- integer fast path, Neumaier-compensated float
/// path, generic fallback -- over random mixes of small/huge ints, floats
/// and bools (and non-numbers, which raise), compared exactly.
#[test]
fn builtin_sum_matches_python_over_random_json_values() {
    let mut rng = Lcg(11);
    let mut cases: Vec<Vec<Value>> = vec![
        vec![],
        vec![json!(1), json!(2)],
        vec![json!(0.1), json!(0.2), json!(0.3)],
        vec![json!(1e16), json!(1.0), json!(-1e16)],
        vec![json!(-0.0)],
        vec![json!(true), json!(false), json!(2.5)],
        vec![json!(i64::MAX), json!(1), json!(0.5)],
        vec![json!(0.5), json!(i64::MAX), json!(1)],
        vec![
            json!(0.5),
            PyInt(big("18446744073709551616")).value(),
            json!(0.25),
        ],
        vec![json!(1.5), PyInt(BigInt::from(1) << 1100usize).value()],
        vec![json!(1), json!("a")],
        vec![json!(1.0), Value::Null],
        vec![json!(1e308), json!(1e308), json!(-1e308)],
    ];
    for _ in 0..300 {
        let len = rng.next() % 8;
        let items = (0..len)
            .map(|_| match rng.next() % 7 {
                0 => json!((rng.next() % 2000) as i64 - 1000),
                1 => json!((rng.next() as f64) / 3.0e9 - 1000.0),
                2 => json!(rng.next().is_multiple_of(2)),
                3 => PyInt(BigInt::from(rng.next()) << (rng.next() % 90) as usize).value(),
                4 => json!(((rng.next() % 100000) as f64) * 1e-3),
                5 => json!(-((rng.next() as f64) * 1e10)),
                _ => json!(i64::MAX - (rng.next() % 3) as i64),
            })
            .collect();
        cases.push(items);
    }
    let script = format!(
        r#"
import json, struct
out = []
for items in json.loads({}):
    try:
        r = sum(items)
    except (TypeError, OverflowError):
        out.append("ERR")
        continue
    if isinstance(r, float):
        out.append(["float", struct.unpack('<Q', struct.pack('<d', r))[0]])
    else:
        out.append(["int", str(r)])
print(json.dumps(out))
"#,
        literal(&json!(cases))
    );
    let python = python(&script);
    for (items, expected) in cases.iter().zip(python.as_array().unwrap()) {
        assert_eq!(
            number_json(python_sum(items.iter())),
            *expected,
            "sum({items:?})"
        );
    }
}

const PY_SCHEDULE: &str = r#"
import json, sys, tempfile, pathlib
from zeropw.context import Config, Context
from zeropw.team import membership as M, sync as S, transport as T
from zeropw.team.identity import DeviceKey

out = {}
for name, raw in json.loads(CASES).items():
    root = pathlib.Path(tempfile.mkdtemp())
    ctx = Context.initialize(root / "a", "synthetic-admin", "synthetic-recovery", Config())
    ctx.projects.create("demo", ["dev"])
    env_id = M.share_environment(ctx, None, "demo", "dev", "owner", "synthetic-admin")["env_id"]
    snapshots = ctx.state.path / "team" / env_id / "snapshots"
    snapshots.mkdir(parents=True, exist_ok=True)
    (snapshots / "0.json").write_text(raw, encoding="utf-8")
    device = DeviceKey.load_or_create(ctx.state, ctx.kms)
    team = S.TeamSync(ctx, T.InProcessTransport(device), device)
    try:
        team.register_env(env_id)
        result = sorted(p.name for p in snapshots.iterdir())
    except Exception as exc:
        result = "RAISE " + type(exc).__name__
    out[name] = result
print(json.dumps(out))
"#;

fn no_members() -> MembershipCheck {
    Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None })
}

fn rust_schedule(raw: &str) -> Value {
    let root = TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            root.path().join("a"),
            ADMIN,
            "synthetic-recovery",
            Config {
                team_sync_interval_seconds: Some(3600.0),
                ..Config::default()
            },
            clock::system(),
        )
        .unwrap(),
    );
    ctx.projects.create("demo", &["dev"]).unwrap();
    let env_id = membership::share_environment(&ctx, None, "demo", "dev", "owner", ADMIN).unwrap()
        ["env_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let snapshots = ctx.state.path.join("team").join(&env_id).join("snapshots");
    std::fs::create_dir_all(&snapshots).unwrap();
    std::fs::write(snapshots.join("0.json"), raw).unwrap();
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let transport = Arc::new(InProcessTransport::new(device.clone(), no_members()));
    let team = sync::TeamSync::new(ctx.clone(), transport, device);
    let result = match team.register_env(&env_id) {
        Ok(()) => {
            let mut names: Vec<String> = std::fs::read_dir(&snapshots)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            json!(names)
        }
        Err(_) => json!("RAISE"),
    };
    team.stop();
    result
}

/// `_load_env_locked`'s `sum(...)` of a hand-written snapshot vector and
/// `_refold`'s `total - last_snapshot_total >= SNAPSHOT_INTERVAL_COMMITS`:
/// float, bool, huge and negative entries change whether (and under which
/// exact name) the next snapshot is saved; non-numbers, an int too large
/// for its float neighbour, and non-dict shapes make `register_env` raise.
#[test]
fn snapshot_scheduling_follows_python_numbers() {
    let doc = |vector: &str| {
        format!(r#"{{"document": null, "version_order": {{}}, "vector": {vector}}}"#)
    };
    let huge = format!("1{}", "0".repeat(30));
    let enormous = format!("1{}", "0".repeat(400));
    let cases: Vec<(&str, String)> = vec![
        ("float_floor", doc(r#"{"x": -1500.5}"#)),
        ("negative_huge", doc(&format!(r#"{{"x": -{huge}}}"#))),
        ("bool_and_float", doc(r#"{"x": true, "y": 2.5}"#)),
        // A positive integer floor would make `all_commits` iterate
        // `range(1, floor + 1)` in both languages; only negative ones here.
        ("near_boundary_int", doc(r#"{"x": -999}"#)),
        ("near_boundary_float", doc(r#"{"x": -999.0}"#)),
        (
            "u64_plus_float",
            doc(r#"{"x": -18446744073709551616, "y": 0.5}"#),
        ),
        ("string_value", doc(r#"{"x": "a"}"#)),
        ("null_value", doc(r#"{"x": null}"#)),
        (
            "int_too_large_for_float",
            doc(&format!(r#"{{"x": 0.5, "y": -{enormous}}}"#)),
        ),
        ("falsy_list_vector", doc("[]")),
        ("truthy_list_vector", doc("[1]")),
        ("null_snapshot", "null".to_string()),
        ("zero_snapshot", "0".to_string()),
    ];
    let mut rust = serde_json::Map::new();
    let mut raw = serde_json::Map::new();
    for (name, text) in &cases {
        rust.insert((*name).into(), rust_schedule(text));
        raw.insert((*name).into(), json!(text));
    }
    let python = python(&PY_SCHEDULE.replace("CASES", &literal(&Value::Object(raw))));
    for (name, _) in &cases {
        let expected = match &python[*name] {
            Value::String(s) if s.starts_with("RAISE ") => json!("RAISE"),
            other => other.clone(),
        };
        assert_eq!(rust[*name], expected, "{name}: python {}", python[*name]);
    }
    // The measured Python outcomes these cases exist for.
    assert_eq!(python["float_floor"], json!(["0.json", "1.json"]));
    assert_eq!(python["negative_huge"], json!(["0.json", "1.json"]));
    assert_eq!(python["string_value"], json!("RAISE TypeError"));
    assert_eq!(
        python["int_too_large_for_float"],
        json!("RAISE OverflowError")
    );
    assert_eq!(python["truthy_list_vector"], json!("RAISE AttributeError"));
    assert_eq!(python["zero_snapshot"], json!("RAISE AttributeError"));
}
