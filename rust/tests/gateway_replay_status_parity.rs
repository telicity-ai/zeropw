//! `RequestLedger::replay` of a stored response status. The prototype only
//! ever persisted the integer status an upstream answered, which must replay
//! unchanged (`PORTING.md` §0 boundary 1). A hand-edited status that is not
//! an integer fails closed: the error escapes `relay` and the server answers
//! its fixed `500 internal_error`.

use std::str::FromStr as _;

use serde_json::{Value, json};
use zeropw::gateway::RequestLedger;

fn entry(status: Value) -> Value {
    json!({"response": {
        "status": status, "headers": [["Content-Type", "application/json"]], "reason": null,
        "body_b64": "e30=", "body_stored": true,
    }})
}

#[test]
fn persisted_integer_status_replays_unchanged() {
    for status in [200, 201, 204, 301, 404, 409, 429, 500, 502, 503] {
        let replay = RequestLedger::replay(&entry(json!(status))).unwrap();
        assert_eq!(replay.status, status, "{status}");
        assert_eq!(replay.reason, None);
        assert_eq!(replay.body, b"{}");
        assert!(
            replay
                .headers
                .iter()
                .any(|(name, value)| name == "X-ZeroPW-Replay" && value == "true")
        );
    }
}

#[test]
fn malformed_replay_status_fails_closed() {
    let too_many_digits = "1".repeat(4301);
    let positive_infinity = Value::Number(serde_json::Number::from_str("1e400").unwrap());
    let negative_infinity = Value::Number(serde_json::Number::from_str("-1e400").unwrap());
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
        let error = RequestLedger::replay(&entry(status.clone())).unwrap_err();
        assert_eq!(error.reason, "internal_error", "{status}");
        assert!(zeropw::gateway::is_escaped_builtin(&error), "{status}");
    }
}
