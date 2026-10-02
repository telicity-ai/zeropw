//! Persisted project values that Python successfully returns remain visible
//! through the native administrator CLI, not merely the library loader.
use std::process::Command;

use serde_json::{Value, json};
use zeropw::context::{Config, Context};
use zeropw::projects::{DOC, Projects};

#[test]
fn persisted_iterables_and_created_at_values_match_python_and_native_cli() {
    let temp = tempfile::TempDir::new().unwrap();
    let state_path = temp.path().join("state");
    let ctx = Context::initialize(
        &state_path,
        "synthetic-admin",
        "synthetic-recovery",
        Config::default(),
        zeropw::clock::system(),
    )
    .unwrap();
    let doc = json!({
        "array": {"environments": ["dev", 7, false, null], "created_at": {"note": "synthetic"}},
        "dict": {"environments": {"staging": 1, "dev": 2}, "created_at": [1, "synthetic"]},
        "string": {"environments": "dev", "created_at": null}
    });
    ctx.state.write_json(DOC, &doc).unwrap();

    let script = r#"
import json,sys
from zeropw.projects import Projects
from zeropw.store import StateDir
p=Projects(StateDir(sys.argv[1]))
print(json.dumps({'projects':[{'name':x.name,'environments':list(x.environments),'created_at':x.created_at} for x in p.list()]}))
print(json.dumps([p.require_environment('string', e) is None for e in ('d','e','v')]))
"#;
    let python = Command::new("python3.12")
        .args(["-c", script])
        .arg(&state_path)
        .env("PYTHONPATH", format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .output()
        .unwrap();
    assert!(
        python.status.success(),
        "{}",
        String::from_utf8_lossy(&python.stderr)
    );
    let expected: Value =
        serde_json::from_slice(python.stdout.split(|&b| b == b'\n').next().unwrap()).unwrap();

    let native = Command::new(env!("CARGO_BIN_EXE_zeropw-admin"))
        .args(["--state-dir"])
        .arg(&state_path)
        .args(["project", "list"])
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    let actual: Value = serde_json::from_slice(&native.stdout).unwrap();
    assert_eq!(actual, expected);
    let projects = Projects::new(ctx.state);
    for env in ["d", "e", "v"] {
        projects.require_environment("string", env).unwrap();
    }
    assert_eq!(
        projects.get("array").unwrap().environments,
        vec![json!("dev"), json!(7), json!(false), Value::Null]
    );
    assert_eq!(
        projects.get("array").unwrap().created_at,
        json!({"note": "synthetic"})
    );
}
