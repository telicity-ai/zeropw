//! Port of `zeropw/team/humanview.py`: human-readable rendering of a folded
//! environment document (docs/team-sync.md section 5.5).
//!
//! [`strip_document`] produces the view `team show`/`team log`/`team diff`
//! render: every ciphertext, DEK wrap, nonce and signature is removed.
//! [`to_yaml`] is an output-only YAML subset writer (dicts, lists, and
//! quoted-when-needed scalars) -- there is no YAML input anywhere in ZeroPW
//! (docs/team-sync.md section 11), so this never needs to parse anything
//! back.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};

use crate::pyjson;

/// `zeropw.team.humanview._YAML_NEEDS_QUOTING`.
static YAML_NEEDS_QUOTING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^\s|\s$|^$|^[-?:,\[\]{}#&*!|>'"%@`]|[:#]\s|[\n\t]"#).expect("valid regex")
});

/// `zeropw.team.humanview._YAML_RESERVED`.
const YAML_RESERVED: &[&str] = &["true", "false", "null", "yes", "no", "~"];

/// `zeropw.team.humanview.strip_document`: the value-free view -- no
/// ciphertext, no DEK wraps, no device-record signatures/public keys.
pub fn strip_document(doc: &Value) -> Value {
    let root = doc.as_object();
    let get_obj = |key: &str| root.and_then(|o| o.get(key)).and_then(Value::as_object);
    let get_field = |key: &str| {
        root.and_then(|o| o.get(key))
            .cloned()
            .unwrap_or(Value::Null)
    };

    let mut members = Map::new();
    if let Some(m) = get_obj("members") {
        for (fp, member) in m {
            let member_obj = member.as_object();
            let field = |k: &str| {
                member_obj
                    .and_then(|o| o.get(k))
                    .cloned()
                    .unwrap_or(Value::Null)
            };
            members.insert(
                fp.clone(),
                json!({"name": field("name"), "role": field("role"), "status": field("status")}),
            );
        }
    }

    let dek = get_obj("dek");
    let dek_current = dek
        .and_then(|d| d.get("current"))
        .cloned()
        .unwrap_or(Value::Null);
    let mut dek_generations: Vec<String> = dek
        .and_then(|d| d.get("generations"))
        .and_then(Value::as_object)
        .map(|g| g.keys().cloned().collect())
        .unwrap_or_default();
    dek_generations.sort();

    let mut secrets_view = Map::new();
    if let Some(secrets) = get_obj("secrets") {
        for (secret_id, entry) in secrets {
            let entry_obj = entry.as_object();
            let mut versions = Map::new();
            if let Some(vs) = entry_obj
                .and_then(|e| e.get("versions"))
                .and_then(Value::as_object)
            {
                for (version_id, record) in vs {
                    let record_obj = record.as_object();
                    let status = record_obj
                        .and_then(|r| r.get("status"))
                        .cloned()
                        .unwrap_or(Value::Null);
                    let generation = record_obj
                        .and_then(|r| r.get("generation"))
                        .cloned()
                        .unwrap_or(Value::Null);
                    let public = record_obj
                        .and_then(|r| r.get("public"))
                        .and_then(Value::as_object)
                        .cloned()
                        .unwrap_or_default();
                    versions.insert(
                        version_id.clone(),
                        json!({"status": status, "generation": generation, "public": Value::Object(public)}),
                    );
                }
            }
            let kind = entry_obj
                .and_then(|e| e.get("kind"))
                .cloned()
                .unwrap_or(Value::Null);
            let active_version = entry_obj
                .and_then(|e| e.get("active_version"))
                .cloned()
                .unwrap_or(Value::Null);
            secrets_view.insert(
                secret_id.clone(),
                json!({"kind": kind, "active_version": active_version, "versions": Value::Object(versions)}),
            );
        }
    }

    let connections = get_obj("connections")
        .map(|c| Value::Object(c.clone()))
        .unwrap_or_else(|| json!({}));
    let settings = get_obj("settings")
        .map(|s| Value::Object(s.clone()))
        .unwrap_or_else(|| json!({}));

    json!({
        "env_id": get_field("env_id"),
        "format": get_field("format"),
        "owner": get_field("owner"),
        "members": Value::Object(members),
        "dek": {"current": dek_current, "generations": dek_generations},
        "connections": connections,
        "secrets": Value::Object(secrets_view),
        "settings": settings,
    })
}

/// `str(int|float)` for a parsed JSON number -- Python's `str()`/`repr()`
/// agree for both. Classified the same way `pyjson`/`kms.rs` already do:
/// a `.`/`e`/`E` in the raw literal means `float` syntax.
fn number_display(n: &serde_json::Number) -> String {
    let raw = n.as_str();
    if raw.contains(['.', 'e', 'E']) {
        raw.parse::<f64>()
            .map(pyjson::python_float_repr)
            .unwrap_or_else(|_| raw.to_string())
    } else {
        raw.to_string()
    }
}

/// `zeropw.team.humanview._yaml_scalar`.
fn yaml_scalar(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(n) => number_display(n),
        Value::String(s) => {
            if YAML_RESERVED.contains(&s.to_lowercase().as_str()) || YAML_NEEDS_QUOTING.is_match(s)
            {
                // A double-quoted YAML scalar follows JSON string escaping rules.
                pyjson::encode_str(s, true)
            } else {
                s.clone()
            }
        }
        // `_yaml_lines` never routes a container value here (both branches
        // that could -- a dict/list under a key, or a dict/list list item --
        // recurse into `_yaml_lines` instead); kept as a safe, non-panicking
        // fallback rather than relying on that invariant.
        Value::Array(_) | Value::Object(_) => String::new(),
    }
}

fn yaml_scalar_or_empty(item: &Value) -> String {
    match item {
        Value::Object(_) => "{}".to_string(),
        Value::Array(_) => "[]".to_string(),
        other => yaml_scalar(other),
    }
}

fn yaml_lines(value: &Value, indent: usize) -> Vec<String> {
    let pad = "  ".repeat(indent);
    let mut lines = Vec::new();
    match value {
        Value::Object(map) => {
            if map.is_empty() {
                return vec![format!("{pad}{{}}")];
            }
            for (key, item) in map {
                let key_text = yaml_scalar(&Value::String(key.clone()));
                match item {
                    Value::Object(m) if !m.is_empty() => {
                        lines.push(format!("{pad}{key_text}:"));
                        lines.extend(yaml_lines(item, indent + 1));
                    }
                    Value::Array(a) if !a.is_empty() => {
                        lines.push(format!("{pad}{key_text}:"));
                        lines.extend(yaml_lines(item, indent));
                    }
                    _ => lines.push(format!("{pad}{key_text}: {}", yaml_scalar_or_empty(item))),
                }
            }
        }
        Value::Array(items) => {
            if items.is_empty() {
                return vec![format!("{pad}[]")];
            }
            for item in items {
                let nonempty_container = match item {
                    Value::Object(m) => !m.is_empty(),
                    Value::Array(a) => !a.is_empty(),
                    _ => false,
                };
                if nonempty_container {
                    let sub = yaml_lines(item, indent + 1);
                    lines.push(format!("{pad}-"));
                    lines.extend(sub);
                } else {
                    lines.push(format!("{pad}- {}", yaml_scalar_or_empty(item)));
                }
            }
        }
        other => lines.push(format!("{pad}{}", yaml_scalar(other))),
    }
    lines
}

/// `zeropw.team.humanview.to_yaml`.
pub fn to_yaml(value: &Value) -> String {
    let lines = yaml_lines(value, 0);
    format!("{}\n", lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_document_removes_secrets_and_keeps_shape() {
        let doc = json!({
            "env_id": "e1", "format": "zeropw-team-env-v1", "owner": "fp1",
            "members": {"fp1": {"name": "alice", "role": "admin", "status": "active", "device": {"sign_pub": "x"}}},
            "dek": {"current": "g0", "generations": {"g0": {"wraps": {"fp1": {"eph_pub": "x"}}}}},
            "connections": {"gh": {"id": "gh", "status": "active"}},
            "secrets": {"s1": {"kind": "api_key", "active_version": "v1",
                               "versions": {"v1": {"status": "active", "generation": "g0",
                                                   "nonce": "N", "ciphertext": "C", "public": {}}}}},
            "settings": {"sync_interval_seconds": 10},
        });
        let stripped = strip_document(&doc);
        assert_eq!(stripped["owner"], json!("fp1"));
        assert_eq!(stripped["members"]["fp1"]["name"], json!("alice"));
        assert!(stripped["members"]["fp1"].get("device").is_none());
        assert_eq!(stripped["dek"]["current"], json!("g0"));
        assert_eq!(stripped["dek"]["generations"], json!(["g0"]));
        let version = &stripped["secrets"]["s1"]["versions"]["v1"];
        assert_eq!(version["status"], json!("active"));
        assert!(version.get("nonce").is_none());
        assert!(version.get("ciphertext").is_none());
    }

    #[test]
    fn to_yaml_scalars_and_quoting() {
        assert_eq!(to_yaml(&json!(null)), "null\n");
        assert_eq!(to_yaml(&json!(true)), "true\n");
        assert_eq!(to_yaml(&json!(5)), "5\n");
        assert_eq!(to_yaml(&json!("plain")), "plain\n");
        // A value equal (case-insensitively) to a YAML reserved word must be quoted.
        assert_eq!(to_yaml(&json!("true")), "\"true\"\n");
        assert_eq!(to_yaml(&json!("Yes")), "\"Yes\"\n");
        // Leading/trailing whitespace and empty strings need quoting.
        assert_eq!(to_yaml(&json!(" x")), "\" x\"\n");
        assert_eq!(to_yaml(&json!("")), "\"\"\n");
    }

    #[test]
    fn to_yaml_nested_structures() {
        let value = json!({"a": {"b": 1}, "c": [], "d": {}, "e": [1, 2], "f": [{"g": 1}]});
        let out = to_yaml(&value);
        assert_eq!(
            out,
            "a:\n  b: 1\nc: []\nd: {}\ne:\n- 1\n- 2\nf:\n-\n  g: 1\n"
        );
    }
}
