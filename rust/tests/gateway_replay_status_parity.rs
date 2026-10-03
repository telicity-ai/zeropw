use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr as _;

use serde_json::{Value, json};
use zeropw::gateway::RequestLedger;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn run_python(script: &str) -> String {
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".into());
    let output = Command::new(interpreter)
        .arg("-c")
        .arg(script)
        .env("PYTHONPATH", repo_root())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run Python replay oracle");
    assert!(
        output.status.success(),
        "python stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 python stdout")
}

#[test]
fn persisted_replay_status_matches_pythons_unbounded_int() {
    let cases = json!([
        65736,
        65536,
        1000000,
        1e300,
        "18446744073709551816",
        " 65736_0 ",
        "１２３４５６７８９０１２３４５６７８９０",
        -1,
        true,
        200.9,
        5e-324,
        -5e-324
    ]);
    let cases_literal = serde_json::to_string(&cases.to_string()).unwrap();
    let script = format!(
        r#"
import json
from zeropw.gateway import RequestLedger
for value in json.loads({cases}):
    result = RequestLedger.replay({{"response": {{
        "status": value, "headers": [], "reason": None,
        "body_b64": "", "body_stored": True,
    }}}})
    print(str(result.status))
"#,
        cases = cases_literal,
    );
    let python_output = run_python(&script);
    let python: Vec<&str> = python_output.lines().collect();

    let rust: Vec<String> = cases
        .as_array()
        .unwrap()
        .iter()
        .map(|status| {
            let entry = json!({"response": {
                "status": status, "headers": [], "reason": null,
                "body_b64": "", "body_stored": true,
            }});
            let replay = RequestLedger::replay(&entry).unwrap();
            assert_eq!(replay.status.value().to_string(), replay.status.to_string());
            replay.status.to_string()
        })
        .collect();
    assert_eq!(rust, python);
}

#[test]
fn malformed_replay_status_raises_the_same_builtin_as_python() {
    // `int(response.get("status", 502))` raises a CPython built-in that
    // escapes `relay`; the Rust error is the matching escaped built-in
    // (`zeropw.server` answers it with `500 internal_error`), named after
    // the exact Python exception class.
    let too_many_digits = "1".repeat(4301);
    let positive_infinity = Value::Number(serde_json::Number::from_str("1e400").unwrap());
    let negative_infinity = Value::Number(serde_json::Number::from_str("-1e400").unwrap());
    let mut rust = Vec::new();
    for status in [
        Value::Null,
        json!([]),
        json!({}),
        json!("not-an-int"),
        json!("_1"),
        json!("1_"),
        json!("1__0"),
        json!("+-1"),
        json!("\u{1c}1"),
        json!(too_many_digits),
        positive_infinity,
        negative_infinity,
    ] {
        let entry = json!({"response": {
            "status": status, "headers": [], "reason": null,
            "body_b64": "", "body_stored": true,
        }});
        let error = RequestLedger::replay(&entry).unwrap_err();
        assert_eq!(error.reason, "internal_error");
        assert!(zeropw::gateway::is_escaped_builtin(&error));
        rust.push(error.name.to_string());
    }

    let python = run_python(
        r#"
from zeropw.gateway import RequestLedger
values = [None, [], {}, "not-an-int", "_1", "1_", "1__0", "+-1", "\x1c1", "1" * 4301,
          float("inf"), float("-inf")]
for value in values:
    try:
        RequestLedger.replay({"response": {"status": value, "body_stored": True}})
        print("ok")
    except Exception as exc:
        print(type(exc).__name__)
"#,
    );
    assert_eq!(python.lines().collect::<Vec<_>>(), rust);
}
