//! Persisted `RequestLedger.updated_at` strings follow Python's exact
//! `float(str)` grammar when a claim causes `_save` to sweep the ledger.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;

use serde_json::{Value, json};
use tempfile::TempDir;
use zeropw::context::{Config, Context};
use zeropw::gateway::{LEDGER_DOC, RequestLedger};

const NOW: f64 = 100_000.0;

fn python_float_oracle(cases: &[&str]) -> Vec<Value> {
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".into());
    let script = r#"
import json, os
from zeropw.gateway import LEDGER_TTL_SECONDS

out = []
for text in json.loads(os.environ["CASES"]):
    try:
        value = float(text)
    except (TypeError, ValueError):
        out.append({"accepted": False})
    else:
        out.append({"accepted": True, "retained": 100000.0 - value <= LEDGER_TTL_SECONDS})
print(json.dumps(out))
"#;
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repository root");
    let mut child = Command::new(&interpreter)
        .arg("-")
        .env("PYTHONPATH", repo_root)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("CASES", serde_json::to_string(cases).unwrap())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("cannot run {interpreter}: {error}"));
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "Python float oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn persisted_updated_at_string_float_grammar_matches_python() {
    let cases = [
        "1_2.5_0",
        "1_0e+2_0",
        " \t1_2.5\n",
        "\u{2003}1_2\u{2003}",
        "١_٢.٥",
        "inf",
        "-Infinity",
        "+NaN",
        "1e309",
        "-1e309",
        "1__2",
        "_12",
        "12_",
        "1_.2",
        "1._2",
        "1e_2",
        "1_e2",
        "in_f",
        "nan_",
        "1 2",
    ];
    let expected = python_float_oracle(&cases);

    let temp = TempDir::new().unwrap();
    let clock: zeropw::clock::Clock = Arc::new(|| NOW);
    let ctx = Context::initialize(
        temp.path().join("state"),
        "synthetic-admin-passphrase",
        "synthetic-recovery-passphrase",
        Config::default(),
        clock,
    )
    .unwrap();
    let ledger = RequestLedger::new(&ctx);

    for (index, (text, oracle)) in cases.iter().zip(&expected).enumerate() {
        ctx.state
            .write_json(
                LEDGER_DOC,
                &json!({
                    "other": {
                        "probe": {
                            "updated_at": text,
                            "state": "completed"
                        }
                    }
                }),
            )
            .unwrap();

        let result = ledger.claim(
            "caller",
            &format!("request-{index}"),
            "digest",
            "connection",
        );
        let accepted = oracle["accepted"].as_bool().unwrap();
        assert_eq!(result.is_ok(), accepted, "float({text:?}) acceptance");
        if !accepted {
            continue;
        }
        assert_eq!(result.unwrap().0, "new", "float({text:?}) claim result");
        let stored = ctx.state.read_json(LEDGER_DOC, json!({})).unwrap();
        let retained = stored["other"].get("probe").is_some();
        assert_eq!(
            retained,
            oracle["retained"].as_bool().unwrap(),
            "float({text:?}) TTL behavior"
        );
    }
}
