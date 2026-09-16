//! Port of `zeropw/team/` (data layer only in the first half).
//!
//! Stage 1 only (docs/team-sync.md section 13, "단계 1"): device identity,
//! DEK envelopes, signed commits, deterministic fold, human-readable
//! rendering. No networking: `zeropw/team/transport.py` and `sync.py` (and
//! `membership.py`) are later stages, out of this half's scope
//! (`rust/PORTING.md` section 1). Where an in-scope module here lazily
//! imports one of those in Python, this port leaves a `// SECOND-HALF:` note
//! at the seam instead of inventing the missing module.

pub mod commit;
pub mod envelope;
pub mod fold;
pub mod humanview;
pub mod identity;

use serde_json::Value;

/// Python truthiness of a parsed JSON value (`if not doc:` /
/// `entry.get("shared_env")` used as a condition, throughout `zeropw/team/`
/// and the modules it builds on): `None`, `false`, `0`/`0.0`, `""`, `[]`,
/// `{}` are all falsy. Mirrors `vault.rs`'s private `json_falsy` (not
/// reachable from here), duplicated because it is such a small, self
/// contained predicate that a cross-module `pub(crate)` seam would be more
/// machinery than the thing itself.
pub(crate) fn json_falsy(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_f64().map(|f| f == 0.0).unwrap_or(false),
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
    }
}
