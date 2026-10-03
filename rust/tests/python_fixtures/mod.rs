//! Golden fixtures generated once from the retired Python prototype.
//!
//! Each area under `tests/fixtures/python/<area>/` carries a `GENERATE.md`
//! with the exact script and command that produced it. The files are
//! synthetic (no real credentials) and are the persisted-state and
//! wire-format boundary the Rust crate must keep loading (PORTING.md §0).
#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::Value;

/// Absolute path of `tests/fixtures/python/<rel>`.
pub fn path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/python")
        .join(rel)
}

pub fn read(rel: &str) -> String {
    fs::read_to_string(path(rel)).unwrap_or_else(|e| panic!("fixture {rel}: {e}"))
}

pub fn json(rel: &str) -> Value {
    serde_json::from_str(&read(rel)).unwrap_or_else(|e| panic!("fixture {rel}: {e}"))
}

/// Copies a fixture state directory to `dst` (which must not exist yet),
/// restoring the modes the prototype created it with (0700 directories,
/// 0600 files) -- git keeps neither.
pub fn copy_state(rel: &str, dst: &Path) {
    copy_tree(&path(rel), dst);
}

fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir(dst).unwrap_or_else(|e| panic!("mkdir {}: {e}", dst.display()));
    fs::set_permissions(dst, fs::Permissions::from_mode(0o700)).unwrap();
    let mut entries: Vec<_> = fs::read_dir(src).unwrap().map(|e| e.unwrap()).collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let target = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
}

/// Every regular file under `root`, as sorted `/`-separated relative paths.
pub fn relative_files(root: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                walk(root, &entry.path(), out);
            } else {
                let rel = entry.path().strip_prefix(root).unwrap().to_path_buf();
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

/// The JSON "shape" of a document: objects keep their keys (recursively),
/// arrays keep their element shapes, scalars collapse to their JSON type
/// name. Two documents written by the two implementations with different
/// random ids, salts or timestamps still have the same shape.
pub fn shape(value: &Value) -> Value {
    match value {
        Value::Null => Value::String("null".into()),
        Value::Bool(_) => Value::String("bool".into()),
        Value::Number(_) => Value::String("number".into()),
        Value::String(_) => Value::String("string".into()),
        Value::Array(items) => Value::Array(items.iter().map(shape).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (normalize_key(k), shape(v)))
                .collect(),
        ),
    }
}

/// Grant ids (`g-<16 hex>`) are random; normalize them so map keys compare.
fn normalize_key(key: &str) -> String {
    if key.len() == 18 && key.starts_with("g-") && key[2..].bytes().all(|b| b.is_ascii_hexdigit()) {
        "g-<id>".to_string()
    } else {
        key.to_string()
    }
}
