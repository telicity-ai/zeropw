//! Port of `zeropw/team/`: the complete team-sharing stack.
//!
//! Data layer (docs/team-sync.md section 13, stage 1): device identity
//! (`identity`), DEK envelopes (`envelope`), signed commits (`commit`),
//! deterministic fold and local derivation (`fold`), human-readable rendering
//! (`humanview`). Networking and membership (later stages): the authenticated
//! session transport (`transport`, in-process and TCP), the replication /
//! monotone-fact runtime attached to a running context (`sync`), and
//! share/invite/join/remove flows (`membership`). Python behaviour is the
//! specification; recorded differences live in `rust/DEVIATIONS.md`.

pub mod commit;
pub mod envelope;
pub mod fold;
pub mod humanview;
pub mod identity;
pub mod membership;
pub mod sync;
pub mod transport;

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
