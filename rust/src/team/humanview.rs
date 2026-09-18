//! Port of `zeropw/team/humanview.py`: human-readable rendering of a folded
//! environment document (docs/team-sync.md section 5.5).
//!
//! [`strip_document`] produces the view `team show`/`team log`/`team diff`
//! render: every ciphertext, DEK wrap, nonce and signature is removed.
//! [`to_yaml`] is an output-only YAML subset writer (dicts, lists, and
//! quoted-when-needed scalars) -- there is no YAML input anywhere in ZeroPW
//! (docs/team-sync.md section 11), so this never needs to parse anything
//! back.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};

use crate::pyjson;
use crate::pystr;

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

/// Quote `text` as a double-quoted YAML scalar (JSON string escaping rules)
/// when it needs it -- a YAML-reserved word (case-insensitively) or a match
/// of [`YAML_NEEDS_QUOTING`] -- else return it verbatim. Shared by
/// [`yaml_scalar`]'s `Value::String` case and [`python_tuple_repr`]'s
/// composed `str(tuple(...))` text (finding H-1).
fn quote_yaml_text(text: &str) -> String {
    if YAML_RESERVED.contains(&text.to_lowercase().as_str()) || YAML_NEEDS_QUOTING.is_match(text) {
        pyjson::encode_str(text, true)
    } else {
        text.to_string()
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
        Value::String(s) => quote_yaml_text(s),
        // `_yaml_lines` never routes a container value here (both branches
        // that could -- a dict/list under a key, or a dict/list list item --
        // recurse into `_yaml_lines` instead); kept as a safe, non-panicking
        // fallback rather than relying on that invariant.
        Value::Array(_) | Value::Object(_) => String::new(),
    }
}

/// `str(tuple(items))` for a JSON array Python holds as a `tuple` at this
/// exact point in the document (finding H-1): `build_connection_fields`
/// (`zeropw/team/commit.py`) returns `dataclasses.asdict(Connection(...))`,
/// and `HttpScope.methods`/`path_prefixes`/`confirm_methods` and
/// `SshTarget.host_keys` are dataclass fields typed as `tuple[str, ...]` --
/// `asdict` recurses into a tuple field but keeps it a tuple, so a folded
/// connection's `to_yaml()` rendering hits `_yaml_lines`' final `else`
/// branch (neither `isinstance(..., dict)` nor `isinstance(..., list)` is
/// true for a tuple) and falls through to `_yaml_scalar(the_tuple)` ->
/// `str(the_tuple)`, always as a single inline scalar (never the multi-line
/// `-` list form, and never `[]` for an empty one -- `()` instead).
/// `str()` of a Python tuple is `(repr(e0), repr(e1), ...)`, with a
/// trailing comma before the closing paren for exactly one element
/// (`('x',)`) and none for zero or two-or-more (`()`, `('x', 'y')`).
/// Every element here is validated to already be a `str` by
/// `HttpScope::new`/`SshTarget::new`, so [`pystr::repr_str`] (this crate's
/// `repr(str)`) is exact; a non-string element (unreachable through this
/// port's own validated builders) falls back to [`yaml_scalar`] rather than
/// panicking.
///
/// Whether a *given* connection's `http_scope`/`ssh_target` fields are
/// really Python tuples at this point is NOT determined by the key name
/// alone (finding H-R2-7, correcting the round-1 fix's assumption): a
/// connection `connection.create`/`connection.update` (re)built during THIS
/// fold call always gets fresh tuples via `build_connection_fields`, but a
/// connection carried over untouched from a `fold_with_snapshot` seed
/// (round-tripped through `json.dump`/`json.load`) holds plain `list`s in
/// those same fields and renders as an ordinary multi-line YAML sequence
/// instead. Callers pass `fold::FoldResult::fresh_connections` (the set of
/// connection ids actually (re)built this fold call) through to
/// [`to_yaml`], which only applies this tuple rendering for ids in that
/// set.
fn python_tuple_repr(items: &[Value]) -> String {
    let reprs: Vec<String> = items
        .iter()
        .map(|v| match v {
            Value::String(s) => pystr::repr_str(s),
            other => yaml_scalar(other),
        })
        .collect();
    match reprs.len() {
        0 => "()".to_string(),
        1 => format!("({},)", reprs[0]),
        _ => format!("({})", reprs.join(", ")),
    }
}

/// Render a `http_scope`/`ssh_target` dict's own fields, treating
/// `tuple_fields` (an array value, even empty) as a Python tuple -- see
/// [`python_tuple_repr`] -- and every other field generically, matching
/// `_yaml_lines`'s per-key dispatch (finding H-1). Only called for a
/// connection [`yaml_lines_connection`] has determined is "fresh" this fold
/// (finding H-R2-7) -- callers elsewhere fall through to plain [`yaml_lines`]
/// instead, which renders these same array fields as ordinary YAML
/// sequences.
fn yaml_lines_tuple_dict(
    map: &Map<String, Value>,
    indent: usize,
    tuple_fields: &[&str],
    fresh_connections: &BTreeSet<String>,
) -> Vec<String> {
    let pad = "  ".repeat(indent);
    let mut lines = Vec::new();
    for (key, item) in map {
        let key_text = yaml_scalar(&Value::String(key.clone()));
        if tuple_fields.contains(&key.as_str())
            && let Value::Array(items) = item
        {
            let text = python_tuple_repr(items);
            lines.push(format!("{pad}{key_text}: {}", quote_yaml_text(&text)));
            continue;
        }
        match item {
            Value::Object(m) if !m.is_empty() => {
                lines.push(format!("{pad}{key_text}:"));
                lines.extend(yaml_lines(item, indent + 1, fresh_connections, false));
            }
            Value::Array(a) if !a.is_empty() => {
                lines.push(format!("{pad}{key_text}:"));
                lines.extend(yaml_lines(item, indent, fresh_connections, false));
            }
            _ => lines.push(format!("{pad}{key_text}: {}", yaml_scalar_or_empty(item))),
        }
    }
    lines
}

fn yaml_scalar_or_empty(item: &Value) -> String {
    match item {
        Value::Object(_) => "{}".to_string(),
        Value::Array(_) => "[]".to_string(),
        other => yaml_scalar(other),
    }
}

/// Render one connection's own fields: `http_scope`/`ssh_target` go through
/// [`yaml_lines_tuple_dict`] (Python-tuple rendering) only when `is_fresh`
/// is `true` -- i.e. this connection id is in
/// `fold::FoldResult::fresh_connections`, meaning `connection.create`/
/// `connection.update` (re)built it during the fold call that produced this
/// document (finding H-R2-7). Otherwise every field, including
/// `http_scope`/`ssh_target`, renders through the ordinary generic path
/// (plain YAML lists for their array sub-fields), matching Python holding
/// those as `list`s when they were carried over untouched from a
/// snapshot-seeded `base_document`.
fn yaml_lines_connection(
    map: &Map<String, Value>,
    indent: usize,
    is_fresh: bool,
    fresh_connections: &BTreeSet<String>,
) -> Vec<String> {
    let pad = "  ".repeat(indent);
    let mut lines = Vec::new();
    for (key, item) in map {
        let key_text = yaml_scalar(&Value::String(key.clone()));
        if is_fresh
            && key == "http_scope"
            && let Value::Object(m) = item
            && !m.is_empty()
        {
            lines.push(format!("{pad}{key_text}:"));
            lines.extend(yaml_lines_tuple_dict(
                m,
                indent + 1,
                &["methods", "path_prefixes", "confirm_methods"],
                fresh_connections,
            ));
            continue;
        }
        if is_fresh
            && key == "ssh_target"
            && let Value::Object(m) = item
            && !m.is_empty()
        {
            lines.push(format!("{pad}{key_text}:"));
            lines.extend(yaml_lines_tuple_dict(
                m,
                indent + 1,
                &["host_keys"],
                fresh_connections,
            ));
            continue;
        }
        match item {
            Value::Object(m) if !m.is_empty() => {
                lines.push(format!("{pad}{key_text}:"));
                lines.extend(yaml_lines(item, indent + 1, fresh_connections, false));
            }
            Value::Array(a) if !a.is_empty() => {
                lines.push(format!("{pad}{key_text}:"));
                lines.extend(yaml_lines(item, indent, fresh_connections, false));
            }
            _ => lines.push(format!("{pad}{key_text}: {}", yaml_scalar_or_empty(item))),
        }
    }
    lines
}

/// `is_root`: true only for the single top-level call `to_yaml` itself
/// makes -- every recursive call (a nested dict/list value, a list item, ...)
/// passes `false`. Finding H-R3-6: the "connections" special-case below
/// used to trigger for a key literally named `"connections"` at ANY depth,
/// not just the actual environment document's own top-level `connections`
/// map -- but Python's real rendering has NO key-name-based special case at
/// all (see the module doc comment on [`python_tuple_repr`]): whether an
/// array renders as a YAML list or a Python tuple's `str()` depends
/// entirely on whether that specific JSON VALUE, in Python, is really a
/// `list` or a `tuple` object at that exact tree position, which for a real
/// document can only ever be true at the document's OWN `connections`
/// field. Peer-controlled JSON reachable through this renderer (e.g. a
/// `secret.put_version` op's arbitrary `public` metadata) can freely nest a
/// key named `"connections"` at any depth without ever containing a Python
/// tuple, so a `public = {"connections": {"<id>": {"http_scope":
/// {"methods": ["GET"]}}}}` value must render `methods` as an ordinary YAML
/// list, matching Python -- not as `('GET',)` just because some nested dict
/// happens to be named `connections` and some inner id happens to collide
/// with (or merely coincide in shape with) a real fresh connection id.
fn yaml_lines(
    value: &Value,
    indent: usize,
    fresh_connections: &BTreeSet<String>,
    is_root: bool,
) -> Vec<String> {
    let pad = "  ".repeat(indent);
    let mut lines = Vec::new();
    match value {
        Value::Object(map) => {
            if map.is_empty() {
                return vec![format!("{pad}{{}}")];
            }
            for (key, item) in map {
                let key_text = yaml_scalar(&Value::String(key.clone()));
                // `connections` is a dict keyed by connection id (finding
                // H-R2-7): each entry's own tuple-vs-list rendering depends
                // on THAT connection's freshness, not on the "connections"
                // key itself, so it gets its own per-id dispatch here
                // rather than falling into the generic `Value::Object`
                // branch below (which has no notion of "current connection
                // id") -- but ONLY at the document root (`is_root`, finding
                // H-R3-6): see this function's own doc comment.
                if is_root
                    && key == "connections"
                    && let Value::Object(conns) = item
                {
                    if conns.is_empty() {
                        lines.push(format!("{pad}{key_text}: {{}}"));
                        continue;
                    }
                    lines.push(format!("{pad}{key_text}:"));
                    let conn_pad = "  ".repeat(indent + 1);
                    for (conn_id, conn_value) in conns {
                        let conn_key_text = yaml_scalar(&Value::String(conn_id.clone()));
                        match conn_value {
                            Value::Object(cm) if !cm.is_empty() => {
                                lines.push(format!("{conn_pad}{conn_key_text}:"));
                                lines.extend(yaml_lines_connection(
                                    cm,
                                    indent + 2,
                                    fresh_connections.contains(conn_id),
                                    fresh_connections,
                                ));
                            }
                            _ => lines.push(format!(
                                "{conn_pad}{conn_key_text}: {}",
                                yaml_scalar_or_empty(conn_value)
                            )),
                        }
                    }
                    continue;
                }
                match item {
                    Value::Object(m) if !m.is_empty() => {
                        lines.push(format!("{pad}{key_text}:"));
                        lines.extend(yaml_lines(item, indent + 1, fresh_connections, false));
                    }
                    Value::Array(a) if !a.is_empty() => {
                        lines.push(format!("{pad}{key_text}:"));
                        lines.extend(yaml_lines(item, indent, fresh_connections, false));
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
                    let sub = yaml_lines(item, indent + 1, fresh_connections, false);
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
///
/// `fresh_connections` (finding H-R2-7) is `fold::FoldResult::fresh_connections`
/// -- the set of connection ids `connection.create`/`connection.update`
/// (re)built during the fold call that produced `value`'s document. Pass
/// `&BTreeSet::new()` for a document (or fragment) with no connections, or
/// one where every connection came from a snapshot seed untouched this
/// fold.
pub fn to_yaml(value: &Value, fresh_connections: &BTreeSet<String>) -> String {
    let lines = yaml_lines(value, 0, fresh_connections, true);
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

    fn no_fresh_connections() -> BTreeSet<String> {
        BTreeSet::new()
    }

    #[test]
    fn to_yaml_scalars_and_quoting() {
        let fresh = no_fresh_connections();
        assert_eq!(to_yaml(&json!(null), &fresh), "null\n");
        assert_eq!(to_yaml(&json!(true), &fresh), "true\n");
        assert_eq!(to_yaml(&json!(5), &fresh), "5\n");
        assert_eq!(to_yaml(&json!("plain"), &fresh), "plain\n");
        // A value equal (case-insensitively) to a YAML reserved word must be quoted.
        assert_eq!(to_yaml(&json!("true"), &fresh), "\"true\"\n");
        assert_eq!(to_yaml(&json!("Yes"), &fresh), "\"Yes\"\n");
        // Leading/trailing whitespace and empty strings need quoting.
        assert_eq!(to_yaml(&json!(" x"), &fresh), "\" x\"\n");
        assert_eq!(to_yaml(&json!(""), &fresh), "\"\"\n");
    }

    #[test]
    fn to_yaml_nested_structures() {
        let value = json!({"a": {"b": 1}, "c": [], "d": {}, "e": [1, 2], "f": [{"g": 1}]});
        let out = to_yaml(&value, &no_fresh_connections());
        assert_eq!(
            out,
            "a:\n  b: 1\nc: []\nd: {}\ne:\n- 1\n- 2\nf:\n-\n  g: 1\n"
        );
    }

    /// Finding H-R2-7: a connection's `http_scope` must render as a Python
    /// tuple only when its id is in `fresh_connections`; otherwise its
    /// array fields render as plain YAML lists, even though the document
    /// shape is identical either way.
    #[test]
    fn to_yaml_connection_tuple_rendering_depends_on_freshness() {
        let doc = json!({"connections": {"gh": {"http_scope": {"methods": ["GET"]}}}});
        let mut fresh = BTreeSet::new();
        fresh.insert("gh".to_string());
        let fresh_out = to_yaml(&doc, &fresh);
        assert!(
            fresh_out.contains("methods: ('GET',)"),
            "fresh connection must render http_scope.methods as a tuple repr:\n{fresh_out}"
        );

        let stale_out = to_yaml(&doc, &BTreeSet::new());
        assert!(
            stale_out.contains("- GET") && !stale_out.contains("methods: ("),
            "non-fresh connection must render http_scope.methods as a YAML list, not a tuple repr:\n{stale_out}"
        );
        assert_ne!(fresh_out, stale_out);
    }

    /// Finding H-R3-6: a key literally named `"connections"` at ANY depth
    /// used to trigger the tuple-rendering special case, not just the
    /// document's own top-level `connections` map. A `secret.put_version`
    /// op's `public` metadata is arbitrary peer-controlled JSON (never
    /// passes through `build_connection_fields`/`dataclasses.asdict`, so
    /// its array values are always plain Python `list`s, never `tuple`s):
    /// nesting a `"connections"` key inside it, whose "id" happens to
    /// collide with a REAL fresh connection id, must still render as an
    /// ordinary YAML list, not `('GET',)`, since Python's real rendering
    /// has no key-name-based special case at all -- only the document
    /// POSITION (top-level `connections`) ever holds a real Python tuple.
    #[test]
    fn nested_connections_key_off_document_root_never_renders_as_a_tuple() {
        let mut fresh = BTreeSet::new();
        fresh.insert("gh".to_string()); // a REAL fresh connection id
        let doc = json!({
            "connections": {"gh": {"http_scope": {"methods": ["GET"]}}},
            "secrets": {"s1": {"versions": {"v1": {"public": {
                "connections": {"gh": {"http_scope": {"methods": ["GET"]}}}
            }}}}},
        });
        let out = to_yaml(&doc, &fresh);
        // The REAL top-level connection ("gh", genuinely fresh) still
        // renders as a tuple repr...
        assert!(
            out.contains("methods: ('GET',)"),
            "the document's own top-level connections must still render as a tuple:\n{out}"
        );
        // ...but the nested one inside `public`, despite the identical
        // shape and a colliding id, must render as a plain YAML list --
        // i.e. there must be exactly ONE tuple-repr occurrence, not two.
        assert_eq!(
            out.matches("methods: ('GET',)").count(),
            1,
            "only the document's own top-level connections may render as a tuple:\n{out}"
        );
        assert!(
            out.contains("- GET"),
            "the nested public.connections.gh.http_scope.methods must render as an ordinary YAML list:\n{out}"
        );
    }
}
