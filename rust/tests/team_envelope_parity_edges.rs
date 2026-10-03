//! Python's `str(value)` coercion before envelope base64 decoding: a
//! non-string field never authenticates and fails with the documented
//! reason the Python prototype gave (measured once, pinned here). All values
//! and keys are synthetic.

use serde_json::{Map, Value, json};
use zeropw::errors::ErrorClass;
use zeropw::team::envelope;
use zeropw::team::identity::DeviceKey;

const ENV_ID: &str = "0123456789abcdef0123456789abcdef";
const GENERATION_ID: &str = "deadbeefcafef00d";
const SECRET_ID: &str = "synthetic-token";
const VERSION_ID: &str = "abc123ef00112233";

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
        // The Python prototype was given real bytes here. `str(b"AAAA")` is
        // exactly this string, the text Rust must hand to the decoder.
        ("bytes", Value::String("b'AAAA'".into())),
    ]
}

#[test]
fn non_string_base64_fields_fail_with_the_documented_reason() {
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

    // `str(value)` of `null`/`true`/`1111` decodes to bytes that reach the
    // AEAD and fail authentication; `false`, `0` and `b'AAAA'` are not
    // valid base64 at the right length.
    let mut expected = Map::new();
    for (case, decodes) in [
        ("null", true),
        ("true", true),
        ("false", false),
        ("integer_decodes", true),
        ("integer_malformed", false),
        ("bytes", false),
    ] {
        for field in ["eph_pub", "nonce", "ciphertext"] {
            let unwrap = if decodes && field != "eph_pub" {
                "dek_unwrap_failed"
            } else {
                "dek_wrap_malformed"
            };
            expected.insert(
                format!("unwrap:{field}:{case}"),
                json!(["InvalidInput", unwrap]),
            );
            if field == "eph_pub" {
                continue;
            }
            let decrypt = if decodes {
                "secret_ciphertext_invalid"
            } else {
                "secret_ciphertext_malformed"
            };
            expected.insert(
                format!("decrypt:{field}:{case}"),
                json!(["InvalidInput", decrypt]),
            );
        }
    }
    assert_eq!(Value::Object(rust), Value::Object(expected));
}
