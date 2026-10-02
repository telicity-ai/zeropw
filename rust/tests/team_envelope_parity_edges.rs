//! Edge parity for Python's `str(value)` coercion before envelope base64
//! decoding. All values and keys are synthetic.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Map, Value, json};
use zeropw::errors::ErrorClass;
use zeropw::pyjson::{self, DumpOptions};
use zeropw::team::envelope;
use zeropw::team::identity::DeviceKey;

const ENV_ID: &str = "0123456789abcdef0123456789abcdef";
const GENERATION_ID: &str = "deadbeefcafef00d";
const SECRET_ID: &str = "synthetic-token";
const VERSION_ID: &str = "abc123ef00112233";

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
        .expect("run python3.12 envelope oracle");
    assert!(
        output.status.success(),
        "python stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 python stdout")
}

fn error_pair(error: zeropw::Error) -> Value {
    assert_eq!(error.class, ErrorClass::InvalidInput);
    json!([error.name, error.reason])
}

fn edge_values() -> Vec<(&'static str, Value)> {
    vec![
        ("null", Value::Null),
        ("true", Value::Bool(true)),
        ("false", Value::Bool(false)),
        ("integer_decodes", json!(1111)),
        ("integer_malformed", json!(0)),
        // Python receives real bytes below. `str(b"AAAA")` is exactly this
        // string, which is the text Rust must hand to the base64 decoder.
        ("bytes", Value::String("b'AAAA'".into())),
    ]
}

#[test]
fn non_string_base64_fields_match_python_error_class_and_reason() {
    let dek: Vec<u8> = (0..32u8).collect();
    let device = DeviceKey::generate();
    let wrap = envelope::wrap_dek(&dek, ENV_ID, GENERATION_ID, &device.record().unwrap()).unwrap();
    let secret = envelope::encrypt_secret(
        &dek,
        ENV_ID,
        SECRET_ID,
        VERSION_ID,
        b"synthetic-secret-value",
    )
    .unwrap();

    let mut rust = Map::new();
    for (case, value) in edge_values() {
        for field in ["eph_pub", "nonce", "ciphertext"] {
            let mut changed_wrap = wrap.clone();
            changed_wrap[field] = value.clone();
            let error = envelope::unwrap_dek(&changed_wrap, ENV_ID, GENERATION_ID, &device)
                .expect_err("edge value must not authenticate");
            rust.insert(format!("unwrap:{field}:{case}"), error_pair(error));

            if field == "eph_pub" {
                continue;
            }
            let mut changed_secret = secret.clone();
            changed_secret.insert(field.into(), value.clone());
            let error =
                envelope::decrypt_secret(&dek, ENV_ID, SECRET_ID, VERSION_ID, &changed_secret)
                    .expect_err("edge value must not authenticate");
            rust.insert(format!("decrypt:{field}:{case}"), error_pair(error));
        }
    }

    let wrap_json = pyjson::dumps(&wrap, DumpOptions::compact_sorted()).unwrap();
    let secret_json = pyjson::dumps(&Value::Object(secret), DumpOptions::compact_sorted()).unwrap();
    let sign_seed = device
        .sign_seed
        .expose()
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let agree_private = device
        .agree_private
        .expose()
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let sign_seed = format!("[{sign_seed}]");
    let agree_private = format!("[{agree_private}]");
    let script = format!(
        r#"
import json
from zeropw.errors import InvalidInput
from zeropw.team import envelope
from zeropw.team.identity import DeviceKey

base_wrap = json.loads({wrap_json})
base_secret = json.loads({secret_json})
device = DeviceKey(bytes({sign_seed}), bytes({agree_private}))
dek = bytes(range(32))
values = [
    ("null", None),
    ("true", True),
    ("false", False),
    ("integer_decodes", 1111),
    ("integer_malformed", 0),
    ("bytes", b"AAAA"),
]
out = {{}}
for case, value in values:
    for field in ("eph_pub", "nonce", "ciphertext"):
        changed = dict(base_wrap)
        changed[field] = value
        try:
            envelope.unwrap_dek(changed, {env_id}, {generation_id}, device)
            out[f"unwrap:{{field}}:{{case}}"] = ["ok", "ok"]
        except InvalidInput as exc:
            out[f"unwrap:{{field}}:{{case}}"] = [type(exc).__name__, exc.reason]

        if field == "eph_pub":
            continue
        changed = dict(base_secret)
        changed[field] = value
        try:
            envelope.decrypt_secret(dek, {env_id}, {secret_id}, {version_id}, changed)
            out[f"decrypt:{{field}}:{{case}}"] = ["ok", "ok"]
        except InvalidInput as exc:
            out[f"decrypt:{{field}}:{{case}}"] = [type(exc).__name__, exc.reason]
print(json.dumps(out, sort_keys=True))
"#,
        wrap_json = serde_json::to_string(&wrap_json).unwrap(),
        secret_json = serde_json::to_string(&secret_json).unwrap(),
        sign_seed = sign_seed,
        agree_private = agree_private,
        env_id = serde_json::to_string(ENV_ID).unwrap(),
        generation_id = serde_json::to_string(GENERATION_ID).unwrap(),
        secret_id = serde_json::to_string(SECRET_ID).unwrap(),
        version_id = serde_json::to_string(VERSION_ID).unwrap(),
    );
    let python: Value = serde_json::from_str(run_python(&script).trim()).unwrap();
    assert_eq!(Value::Object(rust), python);
}
