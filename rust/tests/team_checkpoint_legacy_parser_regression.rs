//! These are the TWO unchanged legacy oracles, not the new parser oracle.
//! In particular Number-reserved objects must keep their old coercions/errors.
use serde_json::{Value, json};
use zeropw::pyjson::{self, DumpOptions};

fn outcome(result: serde_json::Result<Value>) -> Value {
    match result {
        Ok(value) => {
            let kind = match &value {
                Value::Null => "null",
                Value::Bool(_) => "bool",
                Value::Number(_) => "number",
                Value::String(_) => "string",
                Value::Array(_) => "array",
                Value::Object(_) => "object",
            };
            let canonical = match pyjson::dumps(&value, DumpOptions::compact_sorted()) {
                Ok(text) => json!({"ok":true,"text":text}),
                Err(error) => json!({"ok":false,"error":error.to_string()}),
            };
            json!({"ok":true,"kind":kind,"debug":format!("{value:?}"),
                "serialized":serde_json::to_string(&value).unwrap(),"canonical":canonical})
        }
        Err(error) => json!({"ok":false,"error":error.to_string(),
            "category":format!("{:?}",error.classify()),"line":error.line(),"column":error.column()}),
    }
}

#[test]
fn all_36_complete_baseline_outcomes_for_both_legacy_paths() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../docs/evidence/2026-11-07-m2a-raw-value-feature-probe/comparison.json"
    ))
    .unwrap();
    let rows = corpus["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 36);
    for row in rows {
        // Decode the corpus string to the ORIGINAL JSON TEXT, not its object.
        let input = row["input"].as_str().unwrap();
        assert_eq!(
            outcome(pyjson::loads(input)),
            row["baseline"]["pyjson"],
            "pyjson {}",
            row["id"]
        );
        assert_eq!(
            outcome(serde_json::from_str::<Value>(input)),
            row["baseline"]["serde_value"],
            "Value {}",
            row["id"]
        );
    }
}
