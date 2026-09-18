//! Port of `zeropw/policy.py`: connections, principals, grants, approvals and
//! global stop. Default deny.
//!
//! Model (`docs/security-design.md` §3, §5):
//!
//! * A *principal* is an agent identity. It authenticates to the tools API
//!   with its own random token (never a vault value).
//! * A *connection* binds a service, a vault credential (id + optional
//!   pinned version), a fixed target, the authentication profile the gateway
//!   or signer applies, and the scope the user allows (methods / path
//!   prefixes for HTTP, username for SSH). Scope is configured once per
//!   connection; individual operations are never registered.
//! * A *grant* gives one principal use of one connection with expiry and an
//!   optional usage cap. It records the connection's policy version at grant
//!   time. Changes that could widen what the connection allows (target, auth
//!   mode, broader scope) make existing grants `stale` so nothing inherits a
//!   broader permission automatically; narrowing changes and credential
//!   rotation re-evaluate grants in place. A grant also records the
//!   credential version it resolves to; when a different vault version
//!   becomes the one an unpinned connection uses, the connection's policy
//!   version is bumped (so earlier handles stop working) and its grants are
//!   re-evaluated in place.
//! * [`Policy::stop_all`] refuses every new relay, signature and execution
//!   until [`Policy::resume`]. `restore_pending` does the same after a
//!   backup restore until the administrator acknowledges the latest
//!   revocation state.
//! * [`Policy::consume`] is the authoritative last-moment decision: under the
//!   state lock it re-checks restore-pending, global stop, principal,
//!   connection, grant, the operation's scope and that the policy version is
//!   still the one the caller evaluated, then counts one use.
//! * Every revocation (grant revoke, principal/connection disable, secret
//!   version revoke) is also appended to `policy/revocations.jsonl`, which is
//!   not part of a backup, so a restore can re-apply it.
//! * Risky methods can require a one-shot approval bound to a digest of the
//!   caller, connection, method, path and body, and to the grant and
//!   connection policy version in use. Approvals expire, are invalidated by
//!   revocation or policy changes, and a used or dead approval starts a new
//!   cycle instead of blocking the request forever.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, LazyLock, Mutex};
use std::thread::{self, ThreadId};

use base64::Engine as _;
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::clock::Clock;
use crate::errors::{Error, ErrorClass};
use crate::projects::validate_name;
use crate::pyjson::{self, DumpOptions};
use crate::store::{StateDir, iso};

pub const PRINCIPALS: &str = "policy/principals.json";
pub const CONNECTIONS: &str = "policy/connections.json";
pub const GRANTS: &str = "policy/grants.json";
pub const CONTROL: &str = "policy/control.json";
pub const REVOCATIONS: &str = "policy/revocations.jsonl";
/// Read for version metadata only (no ciphertext is touched).
pub const VAULT_SECRETS: &str = "vault/secrets.json";
pub const APPROVAL_TTL_SECONDS: f64 = 15.0 * 60.0;
pub const APPROVAL_HISTORY_LIMIT: usize = 256;
const EVALUATED_MEMO_LIMIT: usize = 64;

pub const HTTP_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
pub const AUTH_MODES: &[&str] = &["bearer", "basic", "header"];
pub const CONNECTION_KINDS: &[&str] = &["http", "ssh"];
pub const MAX_GRANT_TTL: i64 = 30 * 86400;

static FORBIDDEN_CUSTOM_HEADERS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "cookie",
        "proxy-authorization",
        "location",
    ]
    .into_iter()
    .collect()
});

// `^[A-Za-z0-9-]{1,64}$` (no lookaround needed).
pub static HEADER_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9-]{1,64}$").unwrap());
// Python: `^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`.
// The `regex` crate has no lookaround; the `(?=.{1,253}$)` length gate is
// applied separately in `matches_host_re` below, on the label pattern alone.
static HOST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
        .unwrap()
});
static SSH_USERNAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[a-z_][a-z0-9_.-]{0,31}").unwrap());
static CONTROL_CHARS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[\x00-\x1f\x7f]").unwrap());
static ENV_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Z][A-Z0-9_]{0,63}$").unwrap());

/// `pattern.fullmatch(s)`: the whole string must match, not merely a prefix.
/// The `regex` crate's `^`/`$` anchors already stop at the true end of the
/// haystack (unlike Python's `$`, which also accepts a single trailing
/// `"\n"` in `.match()`/`.search()` -- see [`matches_with_trailing_newline`]
/// for the call sites that need that quirk reproduced).
fn fullmatch(re: &Regex, s: &str) -> bool {
    re.find(s)
        .is_some_and(|m| m.start() == 0 && m.end() == s.len())
}

/// `pattern.match(s)` for a pattern of the form `^...$` (no other use of
/// `$`, no `re.MULTILINE`, and a body that cannot itself match `"\n"` --
/// true of every pattern this is used with). CPython's `$` in that mode
/// matches at the true end of the string *or* immediately before a single
/// trailing `"\n"`; `.match()` only anchors the start, so the whole pattern
/// ends up accepting one trailing newline that `fullmatch` (and the `regex`
/// crate's own `$`) would reject. Used for `HEADER_NAME_RE`/`ENV_NAME_RE`,
/// which are matched with `.match()` in Python with no preceding `.strip()`;
/// `HOST_RE` and the SSH username pattern don't need this (the former is
/// only ever matched after `.strip()` removes a trailing newline, the latter
/// is matched with `.fullmatch()` in Python already).
fn matches_with_trailing_newline(re: &Regex, s: &str) -> bool {
    if fullmatch(re, s) {
        return true;
    }
    match s.strip_suffix('\n') {
        Some(rest) => fullmatch(re, rest),
        None => false,
    }
}

/// `policy.HEADER_NAME_RE.match(name)`, including its CPython trailing-newline
/// quirk (see [`matches_with_trailing_newline`]). Exposed for reuse by the
/// header-name checks in this module and by a future port of `tools.py`,
/// which calls `HEADER_NAME_RE.match` directly on caller-supplied header names.
pub fn header_name_matches(name: &str) -> bool {
    matches_with_trailing_newline(&HEADER_NAME_RE, name)
}

/// `re.match(r"^[A-Z][A-Z0-9_]{0,63}$", name)` as used by `CliProfile`'s
/// `base_url_env`/`extra_env` validation (`policy.py:361,364`), including the
/// same trailing-newline quirk.
fn env_name_matches(name: &str) -> bool {
    matches_with_trailing_newline(&ENV_NAME_RE, name)
}

fn matches_host_re(s: &str) -> bool {
    (1..=253).contains(&s.len()) && fullmatch(&HOST_RE, s)
}

/// Python truthiness of a control-flag read as `dict.get(key)` (`None` when
/// the key is absent), e.g. `if control.get("stopped")` /
/// `if control.get("restore_pending")` in `zeropw/policy.py`. Falsy:
/// missing/`null`, `false`, any numeric zero (`0`, `0.0`), `""`, `[]`, `{}`.
/// Truthy: everything else, including non-zero numbers (`1`, `-1`, `0.5`),
/// non-empty strings (`"true"`), and non-empty arrays/objects (`[1]`) -- a
/// stored control document is never generated with those shapes by this
/// crate itself, but a hand-edited or foreign-written one must still be
/// judged the way Python's `if` statement would.
///
/// The number arm decides truthiness from the JSON literal's own text
/// rather than `Number::as_f64` (finding D-R5-1, third recurrence of this
/// fail-open class): with `arbitrary_precision`, `as_f64` parses the
/// literal via `f64::from_str`, which overflows to `+`/`-infinity` for a
/// magnitude beyond `f64::MAX` and is then filtered back to `None` by
/// `Number::as_f64` itself (it only returns finite values) -- so a huge
/// integer (`10**400`, which `read_json` accepts in both languages) was
/// read as *falsy* here, where CPython's `int` is always truthy for any
/// non-zero value regardless of magnitude. `is_stopped()`/`resume()`/the
/// `global_stop`/`restore_pending` gate in `decide` all route through this
/// function, so that false reading was fail-open: a `stopped`/
/// `restore_pending`/`incident_open` control document holding such a huge
/// integer denied nothing and let `resume()` silently clear the stop.
fn json_truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => !number_literal_is_zero(n),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// Whether a JSON number's literal source text denotes the value zero
/// (`0`, `-0`, `0.0`, `0e5`, `-0.000`, ...): true iff every digit in the
/// mantissa (the part before any `e`/`E` exponent -- an exponent can never
/// turn a zero mantissa non-zero, or vice versa) is `0`. Used by
/// [`json_truthy`] so a magnitude that overflows `f64` (any huge non-zero
/// integer) is still correctly truthy instead of falling through a
/// `None`-from-`as_f64` case.
fn number_literal_is_zero(n: &serde_json::Number) -> bool {
    let text = n.to_string();
    let mantissa = text.split(['e', 'E']).next().unwrap_or(&text);
    !mantissa.bytes().any(|b| b.is_ascii_digit() && b != b'0')
}

/// Whether a JSON number's literal source text is negative (`-` prefix),
/// used by [`Policy::approval_expired`] to decide the sign of a magnitude
/// too large for `f64` (see [`number_literal_is_zero`] for the same
/// literal-text approach for a different question).
fn number_literal_is_negative(n: &serde_json::Number) -> bool {
    n.to_string().starts_with('-')
}

// ------------------------------------------------ stored-field JSON validation
//
// `Connection.from_dict` (and the nested-model `build()` closure inside it)
// reconstructs each dataclass by calling its normal constructor, so a
// malformed *value* for a field Python still validates raises the same
// documented `InvalidInput` reason a bad value passed to the public
// constructor would; only a field Python's own code never `isinstance`- or
// pattern-checks (so a bad *type* reaches a built-in operation that raises
// uncaught, or a required key is simply absent) falls back to
// `state_corrupt` (PORTING.md §3.5). The helpers below take the raw
// `serde_json::Value` for one field -- not the already-narrowed Rust type --
// so they can reproduce Python's `isinstance` checks exactly instead of
// bailing out with a generic `state_corrupt` before that check ever runs.

/// `_validate_host(host)` when `host` may not even be a JSON string:
/// Python's own first line is `if not isinstance(host, str): raise
/// InvalidInput("invalid_host")`.
fn validate_host_value(v: &Value) -> Result<String, Error> {
    match v.as_str() {
        Some(s) => validate_host(s),
        None => Err(Error::invalid_input("invalid_host")),
    }
}

/// Whether a JSON number's literal source text has integer form (no `.`,
/// `e`/`E`) -- i.e. whether CPython's `json` module would have produced an
/// `int` rather than a `float` for it. `serde_json`'s `arbitrary_precision`
/// feature (enabled by this crate) preserves the exact source text via
/// `Number`'s `Display`, which is what this inspects; verified directly
/// (`cargo test number_is_python_int_matches_json_literal_form`) against
/// `"8080"` (integer), `"8080.0"` (float) and an out-of-`i64`-range integer
/// literal (still integer form, just not representable by `as_i64`).
fn number_is_python_int(n: &serde_json::Number) -> bool {
    !n.to_string().contains(['.', 'e', 'E'])
}

/// `isinstance(x, int)` for a JSON value, as used by
/// `_collect_revocations`'s `isinstance(entry.get("version"), int)` guards
/// (finding D-R2-4). CPython's `bool` is an `int` subclass, so a JSON `true`/
/// `false` counts too (`True == 1`, `False == 0`) -- unlike
/// `python_int_coerce`, a *float*-shaped JSON number (even `3.0`) is not an
/// `int` in Python and must return `None` here, matching
/// `isinstance(3.0, int) is False`.
fn json_isinstance_int(v: &Value) -> Option<i64> {
    match v {
        Value::Bool(b) => Some(i64::from(*b)),
        Value::Number(n) if number_is_python_int(n) => n.as_i64(),
        _ => None,
    }
}

/// `_validate_port(port)`: `isinstance(port, bool) or not isinstance(port,
/// int) or not 1 <= port <= 65535` -- every one of those disjuncts raises
/// the same `invalid_port`, so *any* JSON shape other than an in-range
/// integer (never a JSON bool, even though `bool` is an `int` subclass in
/// Python -- that is exactly what the first disjunct excludes) is rejected
/// the same way, with no separate uncaught-exception case.
fn validate_port_value(v: &Value) -> Result<i64, Error> {
    let bad = || Error::invalid_input("invalid_port");
    match v {
        Value::Number(n) if number_is_python_int(n) => match n.as_i64() {
            Some(i) if (1..=65535).contains(&i) => Ok(i),
            _ => Err(bad()),
        },
        _ => Err(bad()),
    }
}

/// `HttpTarget.__post_init__`'s `if not isinstance(self.allow_private_network,
/// bool): raise InvalidInput(...)`. Unlike `port`/`host`, a *missing* key
/// here is not an error: `HttpTarget(**value, check_address=False)` simply
/// falls back to the dataclass default (`False`, itself a valid `bool`) when
/// the kwarg is absent, whereas an explicit JSON `null` *is* passed through
/// and fails `isinstance(None, bool)`.
fn validate_allow_private_network_value(v: Option<&Value>) -> Result<bool, Error> {
    match v {
        None => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(Error::invalid_input("invalid_allow_private_network")),
    }
}

/// `SshTarget.__post_init__`'s `if not isinstance(self.username, str) or not
/// _SSH_USERNAME_RE.fullmatch(self.username): raise
/// InvalidInput("invalid_ssh_username")` -- a non-string username is
/// rejected with the same reason as a badly-formed one.
fn validate_ssh_username_value(v: &Value) -> Result<String, Error> {
    match v.as_str() {
        Some(s) if fullmatch(&SSH_USERNAME_RE, s) => Ok(s.to_string()),
        _ => Err(Error::invalid_input("invalid_ssh_username")),
    }
}

/// One raw `host_keys` element, canonicalised exactly like
/// `_canonical_host_key(line)`: `if not isinstance(line, str) or not
/// line.startswith(...)` rejects a non-string element with
/// `unsupported_host_key`, the same reason a wrong-type-but-string value
/// gets, before `canonical_host_key` itself ever runs.
fn host_keys_from_elements<'a>(
    items: impl Iterator<Item = &'a Value>,
) -> Result<Vec<String>, Error> {
    let mut out = Vec::new();
    for item in items {
        let line = item
            .as_str()
            .ok_or_else(|| Error::invalid_input("unsupported_host_key"))?;
        out.push(canonical_host_key(line)?);
    }
    if out.is_empty() {
        return Err(Error::invalid_input("ssh_host_keys_required"));
    }
    Ok(out)
}

/// `tuple(value["host_keys"])` followed by `SshTarget.__post_init__`'s
/// `isinstance(..., (str, bytes)) or not host_keys` check and per-element
/// `_canonical_host_key`, exactly as `Connection.from_dict`'s nested
/// `build()` constructs it. Python's `tuple(x)` iterates whatever `x` is:
///
/// * a JSON string yields its individual *characters* as one-character
///   `str`s; every one is far too short to start with `"ssh-ed25519 "`, so a
///   non-empty string host_keys deterministically fails on the first
///   character with `unsupported_host_key` -- **not** `ssh_host_keys_required`
///   -- and only an *empty* string (`tuple("") == ()`) is falsy enough for
///   that reason. Verified directly against `python3.12`
///   (`SshTarget("h", 22, "u", tuple("somestring"))` raises
///   `unsupported_host_key`; `tuple("")` raises `ssh_host_keys_required`).
/// * a JSON array is iterated element by element (the existing, expected
///   case).
/// * a JSON object is iterated over its *keys* (Python `dict` iteration),
///   each already a JSON string, so it reduces to the array case.
/// * anything else (`null`, a number, a bool) is not iterable at all in
///   Python, raising an uncaught `TypeError` (`state_corrupt`, PORTING.md
///   §3.5).
fn ssh_host_keys_from_value(v: &Value) -> Result<Vec<String>, Error> {
    match v {
        Value::String(s) if s.is_empty() => Err(Error::invalid_input("ssh_host_keys_required")),
        // Any non-empty string: every "character" is a one-codepoint `str`,
        // which can never start with a 12-codepoint prefix, so Python's
        // generator raises on the very first element.
        Value::String(_) => Err(Error::invalid_input("unsupported_host_key")),
        Value::Array(items) => host_keys_from_elements(items.iter()),
        Value::Object(map) => {
            let keys: Vec<Value> = map.keys().cloned().map(Value::String).collect();
            host_keys_from_elements(keys.iter())
        }
        _ => Err(Error::state("state_corrupt").with_detail("ssh_target")),
    }
}

/// `tuple(x)`'s iterable cases, shared by every place `Connection.from_dict`
/// applies Python's `tuple(...)` to a stored field
/// ([`ssh_host_keys_from_value`] above ports the same semantics by hand for
/// `host_keys`; `HttpScope::from_value` below uses this shared helper for
/// `methods`/`path_prefixes`/`confirm_methods`): a JSON array is iterated
/// element by element, a JSON string yields its individual characters, and
/// a JSON object is iterated over its keys -- all three succeed. A
/// non-iterable JSON value (a bare number or bool; `null` is excluded by
/// every caller's own guard before this is ever called) raises an uncaught
/// `TypeError` in Python; `on_not_iterable` supplies the caller-specific
/// `state_corrupt` detail for that case (PORTING.md §3.5, finding D-R3-4).
fn python_tuple_iter(v: &Value, on_not_iterable: impl Fn() -> Error) -> Result<Vec<Value>, Error> {
    match v {
        Value::String(s) => Ok(s.chars().map(|c| Value::String(c.to_string())).collect()),
        Value::Array(items) => Ok(items.clone()),
        Value::Object(map) => Ok(map.keys().cloned().map(Value::String).collect()),
        _ => Err(on_not_iterable()),
    }
}

/// `dict(x)` where the caller only reaches here for a *truthy* `x`
/// (`extra_env`'s `... or {}` guard already excludes a falsy/absent value,
/// and a JSON object is handled by the caller before ever reaching here).
/// This covers the remaining iterable cases `dict()` accepts: an array
/// whose elements are each a two-item iterable (a two-element JSON array,
/// or a two-character JSON string whose two characters become the key and
/// the value) becomes one entry per element, a later element overwriting
/// an earlier one with the same key (ordinary `dict` construction
/// semantics -- last value wins, but the key keeps its *first* insertion
/// position, exactly like [`python_dict_coerce`]'s `serde_json::Map` does);
/// a plain (non-empty) string is iterated by individual character, each of
/// length 1, so it always fails; anything else (a bare number/bool, an
/// array holding a non-pair element) is a genuinely uncaught
/// `TypeError`/`ValueError` in Python (PORTING.md §3.5, finding D-R3-5).
///
/// The de-duplication matters beyond just the returned shape (finding
/// D-R4-5): `dict(...)` collapses duplicate keys to their last value
/// *before* `CliProfile.__post_init__`'s per-entry `extra_env` validation
/// ever runs, so only the surviving value is checked. `extra_env =
/// [["AA", 5], ["AA", "x"]]` validates and loads in Python (the collapsed
/// `{"AA": "x"}` is a valid string value) even though the first, discarded
/// pair's value (`5`) is not a string -- returning every pair verbatim, as
/// this function previously did, made the caller validate `5` too and
/// reject the whole document.
fn python_dict_from_pairs(
    v: &Value,
    bad: impl Fn() -> Error,
) -> Result<Vec<(Value, Value)>, Error> {
    let Value::Array(items) = v else {
        return Err(bad());
    };
    let mut pairs: Vec<(Value, Value)> = Vec::with_capacity(items.len());
    for item in items {
        let (key, val) = match item {
            Value::Array(p) if p.len() == 2 => (p[0].clone(), p[1].clone()),
            Value::String(s) if s.chars().count() == 2 => {
                let mut chars = s.chars();
                let k = chars.next().expect("checked count == 2").to_string();
                let val = chars.next().expect("checked count == 2").to_string();
                (Value::String(k), Value::String(val))
            }
            // `dict([{"a": 1, "b": 2}]) == {"a": "b"}`: `dict()` treats
            // each element as any length-2 *iterable*, not just a
            // sequence, and iterating a `dict` yields its keys in
            // insertion order -- a 1- or 3-key object instead raises
            // Python's own `ValueError` ("... has length N; 2 is
            // required"), reaching the `_ => Err(bad())` arm below the
            // same way an array of the wrong length already does (finding
            // D-R5-10). `serde_json::Map`'s `preserve_order` keeps
            // iteration order equal to the source JSON text, matching
            // Python's dict (itself built from the same source order by
            // `json.loads`).
            Value::Object(o) if o.len() == 2 => {
                let mut keys = o.keys();
                let k = keys.next().expect("checked len == 2").clone();
                let val = keys.next().expect("checked len == 2").clone();
                (Value::String(k), Value::String(val))
            }
            _ => return Err(bad()),
        };
        match pairs.iter_mut().find(|(k, _)| *k == key) {
            Some(existing) => existing.1 = val,
            None => pairs.push((key, val)),
        }
    }
    Ok(pairs)
}

// Note on `CliProfile.base_url_env`: unlike `_validate_host`/`_validate_port`/
// the SSH username check, `re.match(r"^[A-Z][A-Z0-9_]{0,63}$", value)` has no
// preceding `isinstance` guard in Python, so a non-string, present
// `base_url_env` reaches `re.match` directly and raises an uncaught
// `TypeError` (verified against python3.12: `CliProfile("git", "http", 5,
// {})` raises `TypeError`, not `InvalidInput`) -- `state_corrupt`, PORTING.md
// §3.5, exactly what `CliProfile::from_value`'s `Some(_) => return
// Err(bad())` arm for `base_url_env` already does. Every `extra_env` *key*
// is a JSON object key and therefore always a string, so this never applies
// there.

/// `int(x)` (`Connection.from_dict`'s `policy_version=int(data["policy_version"])`),
/// covering every JSON shape CPython's `int()` builtin accepts without
/// raising: an integer (unchanged), a float (truncated toward zero --
/// `int(3.7) == 3`), a bool (`int(True) == 1`, `int(False) == 0`, since
/// `bool` is an `int` subclass), or a string `int()` itself parses (optional
/// sign, ASCII digits, single underscores between digits, surrounding
/// `str.isspace()` whitespace). Anything else -- `null`, a list, a dict, a
/// non-numeric string -- raises `TypeError`/`ValueError` in Python, uncaught
/// (PORTING.md §3.5). A magnitude Python's arbitrary-precision `int` can
/// hold but Rust's `i64` cannot (from a huge literal, numeric string, or
/// float) is also `None` here; see `rust/DEVIATIONS.md`.
fn python_int_coerce(v: &Value) -> Option<i64> {
    match v {
        Value::Bool(b) => Some(i64::from(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(i)
            } else if number_is_python_int(n) {
                None // integer-shaped but outside i64 range
            } else {
                // `int(float)` truncates toward zero. The previous filter
                // (`f.abs() < 9.223_372_036_854_775e18`) used a *rounded*
                // threshold with a strict `<`, so it rejected the real,
                // representable boundary itself (finding D-R5-4c):
                // `int(9.223372036854775e18) == 9223372036854774784` in
                // Python (well within `i64`), but that literal's `f64`
                // value equals the threshold exactly, failing `< `. Using
                // the true `i64` range after truncation (`i64::MIN` is
                // exactly representable as `f64`; `i64::MAX + 1 == 2**63`
                // is the tight exclusive upper bound, since `i64::MAX`
                // itself is not exactly representable) accepts every
                // magnitude `as i64` can hold and none it can't.
                n.as_f64()
                    .map(f64::trunc)
                    .filter(|f| {
                        f.is_finite() && (I64_MIN_AS_F64..I64_MAX_EXCLUSIVE_AS_F64).contains(f)
                    })
                    .map(|f| f as i64)
            }
        }
        Value::String(s) => python_int_from_str(s),
        _ => None,
    }
}

/// `i64::MIN` as `f64`: exact (a power of two), so this is an inclusive
/// lower bound for "truncates to a representable `i64`".
const I64_MIN_AS_F64: f64 = -9_223_372_036_854_775_808.0;
/// `2**63`, one past `i64::MAX` (`i64::MAX` itself, `2**63 - 1`, is not
/// exactly representable as `f64`): an exclusive upper bound for
/// "truncates to a representable `i64`".
const I64_MAX_EXCLUSIVE_AS_F64: f64 = 9_223_372_036_854_775_808.0;

/// The numeric-literal grammar CPython's `int(str)` accepts -- padding,
/// sign, PEP 515 underscores, any Unicode decimal digit (not just ASCII
/// `0`-`9`) -- is `crate::pystr::int_from_str`, the one canonical home for
/// CPython's `int(str)` semantics (PORTING.md §3b; a former private copy of
/// this grammar lived here, finding D-R5-4). This function's only remaining
/// job is narrowing that `i128` result to this module's `i64` (`None` for a
/// magnitude that doesn't fit, unlike `team/commit.rs`'s
/// `python_int_parse_i128`, this module's fields never need more).
fn python_int_from_str(s: &str) -> Option<i64> {
    crate::pystr::int_from_str(s).and_then(|v| i64::try_from(v).ok())
}

/// Python `str()` of a parsed JSON value, used only to format an
/// `InvalidInput` `detail` that Python built from a raw stored value rather
/// than a fixed string (`resume`'s `InvalidInput("incident_open",
/// open_incident)`, finding D-R4-1). Scalars: a string passes through
/// unchanged (Python's `str()` of a `str` has no quoting); `true`/`false` as
/// `"True"`/`"False"`; `null` as `"None"`; an integer-shaped number via its
/// JSON literal text (CPython's arbitrary-precision `int.__str__` prints
/// exactly the canonical decimal digits the JSON literal already is); a
/// genuinely float-shaped number via [`crate::pyjson::python_float_repr`],
/// PORTING.md §3b's canonical home for CPython's `repr(float)`/`str(float)`
/// (`str`/`repr` are identical for `float` in Python 3).
///
/// **Round-7 correction (finding D-PO-1):** this function's previous doc
/// comment claimed the plain-JSON-literal-text rendering was "adequate ...
/// since no field this crate formats this way is ever a float" -- false,
/// and measured false. `resume`'s `control.get("incident_open")` reads
/// `policy/control.json` (`zeropw/policy.py:1037-1039`), a document this
/// crate does not itself ever write a float into, but a hand-edited or
/// bit-rotted one can hold any JSON shape (the same class of gap
/// `DEVIATIONS.md`'s row 95 documents for other fields) -- including a
/// float. `python3.12` confirms `str(1e-07) == "1e-07"` while the raw JSON
/// source text for that same value can be `"1e-7"` (no leading zero on the
/// exponent) -- a different string. A near-identical bypass of this same
/// canonical helper was just confirmed in `gateway.rs` (finding F-R4-5);
/// this is a repeat of that class, not a new one.
fn python_str_for_error(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Null => "None".to_string(),
        Value::Number(n) if number_is_python_int(n) => n.to_string(),
        Value::Number(n) => n
            .as_f64()
            .map(crate::pyjson::python_float_repr)
            .unwrap_or_else(|| n.to_string()),
        Value::Array(_) | Value::Object(_) => python_repr_for_error(value),
    }
}

/// `repr()` half of [`python_str_for_error`]: a string is quoted, everything
/// else falls back to the same rules `str()` uses.
fn python_repr_for_error(value: &Value) -> String {
    match value {
        Value::String(s) => crate::pystr::repr_str(s),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(python_repr_for_error).collect();
            format!("[{}]", parts.join(", "))
        }
        Value::Object(map) => {
            let parts: Vec<String> = map
                .iter()
                .map(|(k, v)| {
                    format!(
                        "{}: {}",
                        crate::pystr::repr_str(k),
                        python_repr_for_error(v)
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
        other => python_str_for_error(other),
    }
}

// --------------------------------------------------------------------- models

/// Python `str.isspace()`.
fn is_python_whitespace(c: char) -> bool {
    crate::pystr::is_space(c)
}

/// `str.strip()` with CPython's exact `str.isspace()` predicate (see
/// [`is_python_whitespace`]), not Rust's narrower `char::is_whitespace()`.
fn python_strip(s: &str) -> &str {
    s.trim_matches(is_python_whitespace)
}

/// `policy._validate_host`.
fn validate_host(host: &str) -> Result<String, Error> {
    let lowered = python_strip(host).to_lowercase();
    if parse_ip_literal(&lowered).is_some() {
        return Ok(lowered);
    }
    if !matches_host_re(&lowered) {
        return Err(Error::invalid_input("invalid_host"));
    }
    Ok(lowered)
}

/// `policy._validate_port`. `port` is any JSON/Rust integer; Python also
/// rejects `bool` (a `bool` is an `int` subclass in Python) -- moot here
/// since the type is a plain integer, never a `bool`.
fn validate_port(port: i64) -> Result<i64, Error> {
    if !(1..=65535).contains(&port) {
        return Err(Error::invalid_input("invalid_port"));
    }
    Ok(port)
}

/// Parses `s` as a literal IPv4/IPv6 address exactly like Python's
/// `ipaddress.ip_address(s)`, including the RFC 4007 `%<zone>` suffix on an
/// IPv6 literal (`std::net::IpAddr`'s parser does not accept that suffix, so
/// it is peeled off and validated separately, matching
/// `IPv6Address._split_scope_id`: the zone id must be non-empty and contain
/// no second `%`). The zone id itself is not validated further (Python
/// accepts any non-empty string there) and is not retained: callers that
/// need the address for classification use the zone-stripped value, which is
/// correct because scope id never affects network membership.
fn parse_ip_literal(s: &str) -> Option<IpAddr> {
    if let Ok(addr) = s.parse::<IpAddr>() {
        return Some(addr);
    }
    let (addr_part, zone) = s.split_once('%')?;
    if zone.is_empty() || zone.contains('%') {
        return None;
    }
    addr_part.parse::<Ipv6Addr>().ok().map(IpAddr::V6)
}

// ---- ipaddress semantics (CPython 3.12 `ipaddress.py`) ---------------------
// Ported by hand: the `regex`/`std::net` ecosystem has no direct equivalent
// of Python's `is_private`/`is_global`/`is_reserved`/`is_site_local` address
// classification, and getting it byte-for-byte right (rather than "close")
// is the actual security property `address_block_reason` provides. Every
// network below is transcribed from `_IPv4Constants`/`_IPv6Constants` in
// CPython's `ipaddress.py`; `rust/tests/policy_oracle.rs` cross-checks a
// large address table against the real `ipaddress` module.

fn ipv4_in(addr: Ipv4Addr, network: Ipv4Addr, prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(addr) & mask) == (u32::from(network) & mask)
}

fn ipv6_in(addr: Ipv6Addr, network: Ipv6Addr, prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(addr) & mask) == (u128::from(network) & mask)
}

const IPV4_PRIVATE_NETWORKS: &[(Ipv4Addr, u32)] = &[
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 0, 0, 0), 24),
    (Ipv4Addr::new(192, 0, 0, 170), 31),
    (Ipv4Addr::new(192, 0, 2, 0), 24),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(198, 18, 0, 0), 15),
    (Ipv4Addr::new(198, 51, 100, 0), 24),
    (Ipv4Addr::new(203, 0, 113, 0), 24),
    (Ipv4Addr::new(240, 0, 0, 0), 4),
    (Ipv4Addr::new(255, 255, 255, 255), 32),
];
const IPV4_PRIVATE_EXCEPTIONS: &[(Ipv4Addr, u32)] = &[
    (Ipv4Addr::new(192, 0, 0, 9), 32),
    (Ipv4Addr::new(192, 0, 0, 10), 32),
];
const IPV4_PUBLIC_NETWORK: (Ipv4Addr, u32) = (Ipv4Addr::new(100, 64, 0, 0), 10); // CGNAT, RFC 6598
const IPV4_RESERVED_NETWORK: (Ipv4Addr, u32) = (Ipv4Addr::new(240, 0, 0, 0), 4);

fn ipv4_is_private(a: Ipv4Addr) -> bool {
    IPV4_PRIVATE_NETWORKS.iter().any(|&(n, p)| ipv4_in(a, n, p))
        && IPV4_PRIVATE_EXCEPTIONS
            .iter()
            .all(|&(n, p)| !ipv4_in(a, n, p))
}

/// `IPv4Address.is_global`: `self not in _public_network and not self.is_private`.
fn ipv4_is_global(a: Ipv4Addr) -> bool {
    !ipv4_in(a, IPV4_PUBLIC_NETWORK.0, IPV4_PUBLIC_NETWORK.1) && !ipv4_is_private(a)
}

fn ipv4_is_reserved(a: Ipv4Addr) -> bool {
    ipv4_in(a, IPV4_RESERVED_NETWORK.0, IPV4_RESERVED_NETWORK.1)
}

const IPV6_PRIVATE_NETWORKS: &[(&str, u32)] = &[
    ("::1", 128),
    ("::", 128),
    ("::ffff:0:0", 96),
    ("64:ff9b:1::", 48),
    ("100::", 64),
    ("2001::", 23),
    ("2001:db8::", 32),
    ("2002::", 16),
    ("3fff::", 20),
    ("fc00::", 7),
    ("fe80::", 10),
];
const IPV6_PRIVATE_EXCEPTIONS: &[(&str, u32)] = &[
    ("2001:1::1", 128),
    ("2001:1::2", 128),
    ("2001:3::", 32),
    ("2001:4:112::", 48),
    ("2001:20::", 28),
    ("2001:30::", 28),
];
const IPV6_RESERVED_NETWORKS: &[(&str, u32)] = &[
    ("::", 8),
    ("100::", 8),
    ("200::", 7),
    ("400::", 6),
    ("800::", 5),
    ("1000::", 4),
    ("4000::", 3),
    ("6000::", 3),
    ("8000::", 3),
    ("a000::", 3),
    ("c000::", 3),
    ("e000::", 4),
    ("f000::", 5),
    ("f800::", 6),
    ("fe00::", 9),
];
const IPV6_SITE_LOCAL_NETWORK: (&str, u32) = ("fec0::", 10);

fn v6(s: &str) -> Ipv6Addr {
    s.parse().expect("hard-coded IPv6 literal")
}

fn ipv6_is_private(a: Ipv6Addr) -> bool {
    IPV6_PRIVATE_NETWORKS
        .iter()
        .any(|&(n, p)| ipv6_in(a, v6(n), p))
        && IPV6_PRIVATE_EXCEPTIONS
            .iter()
            .all(|&(n, p)| !ipv6_in(a, v6(n), p))
}

fn ipv6_is_global(a: Ipv6Addr) -> bool {
    !ipv6_is_private(a)
}

fn ipv6_is_reserved(a: Ipv6Addr) -> bool {
    IPV6_RESERVED_NETWORKS
        .iter()
        .any(|&(n, p)| ipv6_in(a, v6(n), p))
}

fn ipv6_is_site_local(a: Ipv6Addr) -> bool {
    ipv6_in(a, v6(IPV6_SITE_LOCAL_NETWORK.0), IPV6_SITE_LOCAL_NETWORK.1)
}

/// One IP address as it flows through [`address_block_reason`]: either side
/// of the `_Address = IPv4Address | IPv6Address` union in Python, with the
/// same `is_global` / `is_reserved` / `is_unspecified` / `is_multicast`
/// classification. IPv4-mapped IPv6 is normalised to plain `V4` before this
/// type is used (`_normalized_address`), so `V6` here is always a genuine
/// (non-mapped) IPv6 address, matching Python's guarantee that none of the
/// `IPv6Address` properties below ever take their `ipv4_mapped` branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Addr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl Addr {
    fn is_global(self) -> bool {
        match self {
            Addr::V4(a) => ipv4_is_global(a),
            Addr::V6(a) => ipv6_is_global(a),
        }
    }
    fn is_reserved(self) -> bool {
        match self {
            Addr::V4(a) => ipv4_is_reserved(a),
            Addr::V6(a) => ipv6_is_reserved(a),
        }
    }
    fn is_site_local(self) -> bool {
        match self {
            Addr::V4(_) => false, // `getattr(address, "is_site_local", False)`: IPv4 has no such attribute.
            Addr::V6(a) => ipv6_is_site_local(a),
        }
    }
    fn is_unspecified(self) -> bool {
        match self {
            Addr::V4(a) => a.is_unspecified(),
            Addr::V6(a) => a.segments() == [0; 8],
        }
    }
    fn is_multicast(self) -> bool {
        match self {
            Addr::V4(a) => a.is_multicast(),
            Addr::V6(a) => a.is_multicast(),
        }
    }
}

fn normalized_address(address: Addr) -> Addr {
    match address {
        Addr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => Addr::V4(v4),
            None => Addr::V6(a),
        },
        v4 => v4,
    }
}

/// `NEVER_TARGET_NETWORKS`: link-local ranges (where cloud instance metadata
/// services live) and the metadata/credential endpoints some providers
/// expose outside link-local space.
fn in_never_target_networks(a: Addr) -> bool {
    match a {
        Addr::V4(v) => {
            ipv4_in(v, Ipv4Addr::new(169, 254, 0, 0), 16)
                || v == Ipv4Addr::new(100, 100, 100, 200) // Alibaba Cloud metadata
                || v == Ipv4Addr::new(168, 63, 129, 16) // Azure WireServer
        }
        Addr::V6(v) => {
            ipv6_in(v, v6("fe80::"), 10)
                || ipv6_in(v, v6("fd00:ec2::"), 64) // AWS IPv6 services (IMDS ::254, EKS Pod Identity ::23, ...)
                || v == v6("fd20:ce::254") // Google Cloud metadata over IPv6
                || v == v6("fd00:c1::a9fe:a9fe") // Oracle Cloud IMDS over IPv6
        }
    }
}

const NAT64_WELL_KNOWN: (&str, u32) = ("64:ff9b::", 96); // RFC 6052
const NAT64_LOCAL_USE: (&str, u32) = ("64:ff9b:1::", 48); // RFC 8215
const IPV4_COMPATIBLE: (&str, u32) = ("::", 96); // RFC 4291 (deprecated)
const IPV4_TRANSLATED: (&str, u32) = ("::ffff:0:0:0", 96); // SIIT, RFC 2765

fn in_nat64_well_known(v: Ipv6Addr) -> bool {
    ipv6_in(v, v6(NAT64_WELL_KNOWN.0), NAT64_WELL_KNOWN.1)
}

/// `_embedded_ipv4`: IPv4 addresses a translator or tunnel delivers a packet
/// for `address` to. `exact` addresses are fixed by the IPv6 form (the
/// well-known NAT64 prefix, IPv4-compatible/SIIT, 6to4, Teredo); `possible`
/// lists every RFC 6052 layout of the local-use NAT64 prefix, whose prefix
/// length only the operator knows.
fn embedded_ipv4(address: Addr) -> (Vec<Ipv4Addr>, Vec<Ipv4Addr>) {
    let Addr::V6(v) = address else {
        return (Vec::new(), Vec::new());
    };
    let value = u128::from(v);
    let low32 = Ipv4Addr::from((value & 0xFFFF_FFFF) as u32);
    let mut exact = Vec::new();
    let in_ipv4_translated = ipv6_in(v, v6(IPV4_TRANSLATED.0), IPV4_TRANSLATED.1);
    let in_ipv4_compatible = ipv6_in(v, v6(IPV4_COMPATIBLE.0), IPV4_COMPATIBLE.1);
    if in_nat64_well_known(v) || in_ipv4_translated || (in_ipv4_compatible && value > 1) {
        exact.push(low32);
    }
    // `sixtofour`: starts with 2002::/16 -> bits [79:48] are the embedded /32.
    if (value >> 112) == 0x2002 {
        exact.push(Ipv4Addr::from(((value >> 80) & 0xFFFF_FFFF) as u32));
    }
    // `teredo`: starts with 2001::/32 -> server = bits[95:64], client = ~low32.
    if (value >> 96) == 0x2001_0000 {
        exact.push(Ipv4Addr::from(((value >> 64) & 0xFFFF_FFFF) as u32));
        exact.push(Ipv4Addr::from((!value & 0xFFFF_FFFF) as u32));
    }
    let mut possible = Vec::new();
    if ipv6_in(v, v6(NAT64_LOCAL_USE.0), NAT64_LOCAL_USE.1) {
        possible.push(Ipv4Addr::from(
            (((value >> 64) & 0xFFFF) << 16 | ((value >> 40) & 0xFFFF)) as u32,
        )); // /48
        possible.push(Ipv4Addr::from(
            (((value >> 64) & 0xFF) << 24 | ((value >> 32) & 0xFF_FFFF)) as u32,
        )); // /56
        possible.push(Ipv4Addr::from(((value >> 24) & 0xFFFF_FFFF) as u32)); // /64
        possible.push(low32); // /96
    }
    (exact, possible)
}

/// `policy.address_block_reason`: why a relayed credential must not be sent
/// to `address`, or `None`.
///
/// Metadata and link-local addresses are always refused. Every other
/// non-public address (loopback, RFC 1918, unique-local, site-local,
/// carrier-grade NAT, reserved, documentation, unspecified, multicast) is
/// refused unless the connection explicitly allows private networks.
///
/// An IPv6 address that carries an IPv4 address (NAT64, IPv4-compatible,
/// SIIT, 6to4, Teredo) is judged by that IPv4 address as well, so a DNS
/// answer such as `64:ff9b::169.254.169.254` cannot reach metadata or
/// internal IPv4 space through a translator. The well-known NAT64 prefix is
/// reserved IPv6 space that reaches whatever public IPv4 address it embeds,
/// so only its embedded address decides there.
pub fn address_block_reason(address: IpAddr, allow_private_network: bool) -> Option<&'static str> {
    let address = normalized_address(match address {
        IpAddr::V4(a) => Addr::V4(a),
        IpAddr::V6(a) => Addr::V6(a),
    });
    let (exact, possible) = embedded_ipv4(address);
    let exact_addrs: Vec<Addr> = exact.iter().map(|&a| Addr::V4(a)).collect();
    let possible_addrs: Vec<Addr> = possible.iter().map(|&a| Addr::V4(a)).collect();

    for candidate in std::iter::once(address)
        .chain(exact_addrs.iter().copied())
        .chain(possible_addrs.iter().copied())
    {
        if in_never_target_networks(candidate) {
            return Some("metadata_address_not_allowed");
        }
    }
    if std::iter::once(address)
        .chain(exact_addrs.iter().copied())
        .any(|c| c.is_unspecified() || c.is_multicast())
    {
        return Some("target_address_not_allowed");
    }
    if !allow_private_network {
        let special = address.is_reserved() || address.is_site_local();
        let addr_in_nat64_well_known = matches!(address, Addr::V6(v) if in_nat64_well_known(v));
        if !address.is_global() || (special && !addr_in_nat64_well_known) {
            return Some("target_address_not_allowed");
        }
        if exact_addrs
            .iter()
            .any(|&c| !c.is_global() || c.is_reserved())
        {
            return Some("target_address_not_allowed");
        }
    }
    None
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpTarget {
    pub scheme: String,
    pub host: String,
    pub port: i64,
    pub ca_file: Option<String>,
    pub allow_private_network: bool,
}

impl HttpTarget {
    /// `HttpTarget(...)` with `check_address=True` (the default): refuses a
    /// forbidden IP literal immediately.
    pub fn new(
        scheme: impl Into<String>,
        host: impl Into<String>,
        port: i64,
        ca_file: Option<String>,
        allow_private_network: bool,
    ) -> Result<Self, Error> {
        Self::build(scheme, host, port, ca_file, allow_private_network, true)
    }

    /// `HttpTarget(..., check_address=False)`: only for loading stored
    /// documents (a record saved before a literal became forbidden must
    /// still load, so the administrator can list and disable it).
    pub fn from_stored(
        scheme: impl Into<String>,
        host: impl Into<String>,
        port: i64,
        ca_file: Option<String>,
        allow_private_network: bool,
    ) -> Result<Self, Error> {
        Self::build(scheme, host, port, ca_file, allow_private_network, false)
    }

    fn build(
        scheme: impl Into<String>,
        host: impl Into<String>,
        port: i64,
        ca_file: Option<String>,
        allow_private_network: bool,
        check_address: bool,
    ) -> Result<Self, Error> {
        let scheme = scheme.into();
        if scheme != "http" && scheme != "https" {
            return Err(Error::invalid_input("invalid_scheme"));
        }
        let host = validate_host(&host.into())?;
        let port = validate_port(port)?;
        let target = HttpTarget {
            scheme,
            host,
            port,
            ca_file,
            allow_private_network,
        };
        if check_address {
            target.require_allowed_literal()?;
        }
        Ok(target)
    }

    /// Why this target's IP literal may never receive a credential, or
    /// `None` (also for host names).
    pub fn literal_block_reason(&self) -> Option<&'static str> {
        let literal = parse_ip_literal(&self.host)?;
        address_block_reason(literal, true)
    }

    pub fn require_allowed_literal(&self) -> Result<(), Error> {
        match self.literal_block_reason() {
            Some(reason) => Err(Error::invalid_input(reason)),
            None => Ok(()),
        }
    }

    pub fn origin(&self) -> String {
        format!("{}://{}:{}", self.scheme, self.host, self.port)
    }

    fn to_value(&self) -> Value {
        json!({
            "scheme": self.scheme, "host": self.host, "port": self.port,
            "ca_file": self.ca_file, "allow_private_network": self.allow_private_network,
        })
    }

    /// `HttpTarget(**value, check_address=False)` in `Connection.from_dict`.
    /// A field Python's `__post_init__` still validates (`scheme`, `host`,
    /// `port`, `allow_private_network`) raises the same documented
    /// `InvalidInput` reason for a wrong-type stored value that it would for
    /// a wrong *value*, not `state_corrupt`; only a missing required key
    /// (`scheme`/`host`/`port` have no dataclass default, so kwarg
    /// unpacking raises an uncaught `TypeError` for them) falls back to
    /// `state_corrupt` (PORTING.md §3.5). An *unknown* key in `value` --
    /// including `check_address`, which `Connection.from_dict` itself
    /// already passes -- makes the `**value` unpacking collide with (or add
    /// to) `HttpTarget`'s own keyword arguments, an uncaught `TypeError`
    /// (`__init__() got multiple/unexpected keyword argument(s)`), likewise
    /// `state_corrupt` (finding D-R2-6).
    fn from_value(v: &Value) -> Result<Self, Error> {
        let obj = v
            .as_object()
            .ok_or_else(|| Error::state("state_corrupt").with_detail("http_target"))?;
        let missing = || Error::state("state_corrupt").with_detail("http_target");
        const KNOWN_KEYS: &[&str] = &["scheme", "host", "port", "ca_file", "allow_private_network"];
        if obj.keys().any(|k| !KNOWN_KEYS.contains(&k.as_str())) {
            return Err(missing());
        }
        let scheme_v = obj.get("scheme").ok_or_else(missing)?;
        let scheme = match scheme_v.as_str() {
            // `self.scheme not in ("http", "https")`: a plain equality
            // check, no `isinstance` guard, so any non-matching type is
            // rejected the same documented way as a non-matching string.
            Some(s) if s == "http" || s == "https" => s.to_string(),
            _ => return Err(Error::invalid_input("invalid_scheme")),
        };
        let host = validate_host_value(obj.get("host").ok_or_else(missing)?)?;
        let port = validate_port_value(obj.get("port").ok_or_else(missing)?)?;
        // **Round-7 correction (finding D-R7-7):** `allow_private_network`
        // is checked *before* `ca_file` is narrowed, matching Python's own
        // `__post_init__` order (`scheme` -> `host` -> `port` ->
        // `allow_private_network`; `ca_file` is never checked by Python at
        // all -- see the comment on the representational-gap check below).
        // The previous order checked `ca_file` first, so a document with
        // both fields malformed raised this crate's `state_corrupt`
        // instead of the documented `InvalidInput` Python actually raises:
        // measured directly, `HttpTarget(scheme="http", host="1.2.3.4",
        // port=80, ca_file=5, allow_private_network="x",
        // check_address=False)` raises `InvalidInput
        // invalid_allow_private_network` in Python (it never even reaches a
        // `ca_file` check), where this crate previously gave
        // `state_corrupt "http_target"`. Deferring the `ca_file`
        // representational-gap rejection past every check Python actually
        // performs is the same pattern `Connection::from_value`'s `corrupt`
        // flag already uses for its own no-`isinstance`-guard fields.
        let allow_private_network =
            validate_allow_private_network_value(obj.get("allow_private_network"))?;
        let ca_file = match obj.get("ca_file") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            // Python's `ca_file: str | None = None` field has no
            // `__post_init__` check at all: a non-string, non-null stored
            // value loads successfully and is kept verbatim. Rust's typed
            // `Option<String>` cannot represent that value; rejecting it is
            // a genuine, documented residual (see DEVIATIONS.md),
            // unreachable via any writer in this crate or the matching
            // Python code path (both only ever store a string or null).
            Some(_) => return Err(Error::state("state_corrupt").with_detail("http_target")),
        };
        Self::from_stored(scheme, host, port, ca_file, allow_private_network)
    }
}

/// Python's `not self.basic_username or ":" in self.basic_username`
/// (`HttpAuth.__post_init__`, only evaluated when `mode == "basic"`),
/// resolved to a placeholder `String` that [`HttpAuth::new`]'s own
/// `!u.is_empty() && !u.contains(':')` check evaluates to the identical
/// accept/reject decision -- finding H-R5-3, correcting DEVIATIONS.md's
/// H-R2-9b row, which claimed a truthy non-string value always raises
/// Python's uncaught `TypeError` here. That is true for `header_name`
/// (`re.match` requires an actual `str`/`bytes` argument, so ANY
/// non-string -- scalar or container -- raises), but NOT for
/// `basic_username`: `"in"` is a membership test that works on any
/// iterable, so a truthy `list`/`dict` never raises at all. Confirmed
/// against real `python3.12`: `HttpAuth(mode="basic",
/// basic_username=["curl"])` succeeds and keeps the list verbatim;
/// `HttpAuth(mode="basic", basic_username=[":"])` raises the documented
/// `InvalidInput("invalid_basic_username")`; only a truthy *non-iterable*
/// scalar (`int`/`float`/`bool`) still hits the uncaught `TypeError`
/// (`"argument of type 'int' is not iterable"`), which keeps its existing
/// substitution onto the same `invalid_basic_username` reason the falsy
/// case already uses (round-2 finding H-R2-9b, unchanged for this shape).
///
/// Returns `None` for anything [`HttpAuth::new`] should reject via its
/// existing "missing" branch: a falsy value (`None`, `false`, `0`, `""`,
/// `[]`, `{}`) or a truthy non-iterable scalar (the substituted
/// `TypeError` case). Returns `Some(s.clone())` for a real string
/// (unchanged). Returns `Some(":")` for a truthy list/dict that contains
/// the literal `":"` as an element (list) or key (dict) -- deliberately
/// colon-bearing so [`HttpAuth::new`]'s own check rejects it with the
/// correct reason -- or a fixed colon-free sentinel for one that does not,
/// so the same check accepts it.
///
/// This only resolves the accept/reject *decision*; it cannot make
/// [`HttpAuth::new`]'s typed `Option<String>` field hold the real
/// list/dict (PORTING.md §3b/§4's typed-field limit, the same one
/// `HttpTarget.ca_file`/`HttpAuth.value_prefix` already have residual rows
/// for). A caller that also needs the byte-exact value in an emitted
/// document (`team::commit::build_http_auth`, receiving a peer-signed op)
/// carries the raw `serde_json::Value` through separately, the same
/// raw-passthrough pattern `ca_file`/`value_prefix` already use.
pub(crate) fn basic_username_decision(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) => Some(s.clone()),
        v @ Value::Array(items) if json_truthy(Some(v)) => {
            let has_colon = items.iter().any(|item| item.as_str() == Some(":"));
            Some(if has_colon {
                ":".to_string()
            } else {
                "\u{1}".to_string()
            })
        }
        v @ Value::Object(map) if json_truthy(Some(v)) => {
            let has_colon = map.keys().any(|k| k == ":");
            Some(if has_colon {
                ":".to_string()
            } else {
                "\u{1}".to_string()
            })
        }
        _ => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpAuth {
    pub mode: String,
    pub header_name: Option<String>,
    pub value_prefix: Option<String>,
    pub basic_username: Option<String>,
    /// The original JSON value for `basic_username` when it is a truthy,
    /// colon-free list/dict that [`basic_username_decision`] accepts
    /// without raising (finding H-R5-3's sibling gap on this STATE-
    /// DOCUMENT loading path, `HttpAuth::from_value`). `basic_username`
    /// (typed `Option<String>`, PORTING.md §3b/§4's typed-field limit)
    /// cannot hold a list/dict, so it is set to a colon-free placeholder in
    /// that case and this field holds `Some(<the real container>)` instead
    /// -- `None` whenever `basic_username` itself is already faithful (an
    /// ordinary string, or genuinely absent/falsy).
    ///
    /// Cross-unit finding (round 8), the same one [`CliProfile::raw_program`]
    /// documents: [`HttpAuth::to_value`] (the persisted document, read by
    /// `Connection::to_value` and written by
    /// `create_connection`/`update_connection`/`disable_connection` and
    /// `team::fold`'s connection derivation) must render from this field
    /// whenever it is `Some`, never from `basic_username` itself, which
    /// only ever holds a placeholder in that case. (`public_view` never
    /// renders `basic_username` at all, so unlike `CliProfile.program` this
    /// field has no agent-facing view exposure -- only the persisted
    /// document.)
    pub raw_basic_username: Option<Value>,
}

impl HttpAuth {
    pub fn new(
        mode: impl Into<String>,
        header_name: Option<String>,
        value_prefix: Option<String>,
        basic_username: Option<String>,
    ) -> Result<Self, Error> {
        let mode = mode.into();
        if !AUTH_MODES.contains(&mode.as_str()) {
            return Err(Error::invalid_input("unsupported_auth_mode"));
        }
        if mode == "header" {
            let ok_name = header_name
                .as_deref()
                .is_some_and(|n| !n.is_empty() && header_name_matches(n));
            if !ok_name {
                return Err(Error::invalid_input("invalid_header_name"));
            }
            if FORBIDDEN_CUSTOM_HEADERS
                .contains(header_name.as_deref().unwrap().to_lowercase().as_str())
            {
                return Err(Error::invalid_input("invalid_header_name"));
            }
        }
        if mode == "basic" {
            let ok = basic_username
                .as_deref()
                .is_some_and(|u| !u.is_empty() && !u.contains(':'));
            if !ok {
                return Err(Error::invalid_input("invalid_basic_username"));
            }
        }
        Ok(HttpAuth {
            mode,
            header_name,
            value_prefix,
            basic_username,
            raw_basic_username: None,
        })
    }

    /// Convenience for `HttpAuth("bearer")` (the common case in tests).
    pub fn bearer() -> Self {
        HttpAuth {
            mode: "bearer".into(),
            header_name: None,
            value_prefix: None,
            basic_username: None,
            raw_basic_username: None,
        }
    }

    fn to_value(&self) -> Value {
        let basic_username =
            self.raw_basic_username
                .clone()
                .unwrap_or_else(|| match &self.basic_username {
                    Some(s) => Value::String(s.clone()),
                    None => Value::Null,
                });
        json!({
            "mode": self.mode, "header_name": self.header_name,
            "value_prefix": self.value_prefix, "basic_username": basic_username,
        })
    }

    /// `HttpAuth(**value)`. Like `HttpTarget`'s `scheme`, `self.mode not in
    /// AUTH_MODES` is a plain equality check with no `isinstance` guard, so
    /// a non-string, present `mode` gets the same documented
    /// `unsupported_auth_mode` a wrong-string mode would, not
    /// `state_corrupt`. `header_name`/`value_prefix`/`basic_username`
    /// remain `state_corrupt` for any present non-string/non-null value:
    /// see the `policy` row in `DEVIATIONS.md` for the residual this still
    /// leaves (Python's own checks on those fields are considerably more
    /// irregular -- see the `DEVIATIONS.md` row for exactly which shapes
    /// that covers). An unknown key in `value` makes the `**value`
    /// unpacking raise an uncaught `TypeError` (`__init__() got an
    /// unexpected keyword argument ...`), likewise `state_corrupt`
    /// (finding D-R2-6).
    fn from_value(v: &Value) -> Result<Self, Error> {
        let obj = v
            .as_object()
            .ok_or_else(|| Error::state("state_corrupt").with_detail("http_auth"))?;
        let bad = || Error::state("state_corrupt").with_detail("http_auth");
        const KNOWN_KEYS: &[&str] = &["mode", "header_name", "value_prefix", "basic_username"];
        if obj.keys().any(|k| !KNOWN_KEYS.contains(&k.as_str())) {
            return Err(bad());
        }
        let mode_v = obj.get("mode").ok_or_else(bad)?;
        let mode = match mode_v.as_str() {
            Some(s) if AUTH_MODES.contains(&s) => s.to_string(),
            _ => return Err(Error::invalid_input("unsupported_auth_mode")),
        };
        // `header_name`/`basic_username` are only validated by Python at all
        // when `mode` requires them (`if self.mode == "header": ...`); when
        // it does, `if not self.header_name or not HEADER_NAME_RE.match(...)`
        // (`self.basic_username` similarly) short-circuits on a *falsy*
        // value before ever reaching `isinstance`/the regex, so a present
        // but falsy non-string value (`0`, `false`, `[]`, `{}`) still gets
        // the documented `invalid_header_name`/`invalid_basic_username`
        // reason in Python, not an uncaught `TypeError` -- coercing it to
        // `None` here reproduces that (`HttpAuth::new` treats a `None`
        // `header_name`/`basic_username` the same falsy way). A *truthy*
        // non-string `header_name` when the field applies still reaches
        // Python's `re.match` and is an uncaught `TypeError` there in every
        // case this crate's own tests exercise (`state_corrupt`, PORTING.md
        // §3.5); a truthy non-string `basic_username` does NOT, per
        // [`basic_username_decision`]'s doc comment (finding H-R5-3,
        // correcting this row's previous blanket claim) -- handled
        // separately below instead of through this closure. When a field
        // does not apply to this `mode` at all, Python validates it not at
        // all, which Rust's typed `Option<String>` still cannot represent
        // for a non-string value -- a real, narrower residual (see
        // `DEVIATIONS.md`).
        let opt_str = |key: &str, applies_for_mode: bool| -> Result<Option<String>, Error> {
            match obj.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) => Ok(Some(s.clone())),
                Some(v) if applies_for_mode && !json_truthy(Some(v)) => Ok(None),
                _ => Err(bad()),
            }
        };
        // Finding H-R5-3: when `mode == "basic"`, resolve through
        // [`basic_username_decision`] instead of `opt_str` so a truthy,
        // colon-free list/dict is accepted (matching Python) rather than
        // rejected as `state_corrupt` -- a state file this crate's own
        // `team::commit::build_http_auth` can now legitimately write, since
        // it folds a peer's `connection.create`/`connection.update` op the
        // same way Python does. When `mode != "basic"` the field is
        // unchecked in Python either way, so `opt_str`'s existing
        // (documented, narrower) residual for that case is unchanged.
        let basic_username_raw = obj.get("basic_username");
        // Cross-unit finding (round 8): whether `basic_username_decision`
        // is about to return the accepted, colon-free CONTAINER placeholder
        // (`"\u{1}"`) rather than a faithful string -- computed the same
        // way [`basic_username_decision`] itself decides a truthy container
        // is in play, so this can only be `true` exactly when the
        // constructed `HttpAuth` below is going to need
        // `raw_basic_username` to round-trip the real value.
        let basic_username_is_container = mode == "basic"
            && json_truthy(basic_username_raw)
            && matches!(basic_username_raw, Some(Value::Array(_) | Value::Object(_)));
        let basic_username = if mode == "basic" {
            basic_username_decision(basic_username_raw)
        } else {
            opt_str("basic_username", false)?
        };
        let mut auth = HttpAuth::new(
            mode.clone(),
            opt_str("header_name", mode == "header")?,
            opt_str("value_prefix", false)?,
            basic_username,
        )?;
        if basic_username_is_container {
            auth.raw_basic_username = basic_username_raw.cloned();
        }
        Ok(auth)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpScope {
    /// `None` = every method.
    pub methods: Option<Vec<String>>,
    /// `None` = every path.
    pub path_prefixes: Option<Vec<String>>,
    /// Risky methods needing one-shot approval.
    pub confirm_methods: Vec<String>,
}

impl HttpScope {
    pub fn new(
        methods: Option<Vec<String>>,
        path_prefixes: Option<Vec<String>>,
        confirm_methods: Vec<String>,
    ) -> Result<Self, Error> {
        for g in [&methods, &Some(confirm_methods.clone())]
            .into_iter()
            .flatten()
        {
            for m in g {
                if !HTTP_METHODS.contains(&m.as_str()) {
                    return Err(Error::invalid_input("invalid_method"));
                }
            }
        }
        if let Some(prefixes) = &path_prefixes {
            if prefixes.is_empty() {
                return Err(Error::invalid_input("empty_path_prefixes"));
            }
            for p in prefixes {
                if !p.starts_with('/') || p.contains("..") || p.contains('?') {
                    return Err(Error::invalid_input("invalid_path_prefix"));
                }
            }
        }
        Ok(HttpScope {
            methods,
            path_prefixes,
            confirm_methods,
        })
    }

    pub fn allows_method(&self, method: &str) -> bool {
        self.methods
            .as_ref()
            .is_none_or(|m| m.iter().any(|x| x == method))
    }

    pub fn allows_path(&self, path: &str) -> bool {
        let Some(prefixes) = &self.path_prefixes else {
            return true;
        };
        prefixes.iter().any(|p| {
            path == p
                || path.starts_with(&format!("{}/", p.trim_end_matches('/')))
                || (p.ends_with('/') && path.starts_with(p.as_str()))
        })
    }

    /// True when `other` allows something this scope did not.
    pub fn widens(&self, other: &HttpScope) -> bool {
        match (&self.methods, &other.methods) {
            (Some(_), None) => return true,
            (Some(a), Some(b)) => {
                let a: HashSet<&str> = a.iter().map(String::as_str).collect();
                let b: HashSet<&str> = b.iter().map(String::as_str).collect();
                if b.difference(&a).next().is_some() {
                    return true;
                }
            }
            (None, _) => {}
        }
        match (&self.path_prefixes, &other.path_prefixes) {
            (Some(_), None) => return true,
            (Some(_), Some(other_prefixes)) => {
                for prefix in other_prefixes {
                    if !self.allows_path(prefix) {
                        return true;
                    }
                }
            }
            (None, _) => {}
        }
        let confirm_self: HashSet<&str> = self.confirm_methods.iter().map(String::as_str).collect();
        let confirm_other: HashSet<&str> =
            other.confirm_methods.iter().map(String::as_str).collect();
        confirm_self.difference(&confirm_other).next().is_some()
    }

    fn to_value(&self) -> Value {
        json!({
            "methods": self.methods, "path_prefixes": self.path_prefixes,
            "confirm_methods": self.confirm_methods,
        })
    }

    /// Port of the `HttpScope` branch of `Connection.from_dict`'s nested
    /// `build()` closure: `HttpScope(tuple(value["methods"]) if
    /// value.get("methods") is not None else None, tuple(value["path_prefixes"])
    /// if value.get("path_prefixes") is not None else None,
    /// tuple(value.get("confirm_methods") or ()))`.
    ///
    /// `methods`/`path_prefixes` use an explicit `is not None` guard (a
    /// present `false`/`0`/`[]` still reaches `tuple(...)`), while
    /// `confirm_methods` uses Python's `or` -- a *falsy* check, so any
    /// falsy stored value (`[]`, `""`, `0`, `false`, `{}`, `null`, or an
    /// absent key) short-circuits to `()` without ever calling `tuple`.
    /// `tuple(x)` itself iterates whatever `x` is: a JSON array element by
    /// element, a JSON string into its individual characters, a JSON
    /// object over its keys (all three succeed); a non-iterable JSON value
    /// (a bare number or bool) raises an uncaught `TypeError`
    /// (`state_corrupt`, PORTING.md §3.5) -- exactly the same iterable
    /// cases [`ssh_host_keys_from_value`] already reproduces for
    /// `host_keys` (finding D-R3-4).
    fn from_value(v: &Value) -> Result<Self, Error> {
        let bad = || Error::state("state_corrupt").with_detail("http_scope");
        let obj = v.as_object().ok_or_else(bad)?;
        // `methods`/`confirm_methods`: each element then only has to
        // survive `HttpScope::new`'s own `method not in HTTP_METHODS`
        // membership test, which -- like Python's `in` operator -- accepts
        // any element type and simply never matches a non-string one; a
        // non-string element is mapped to a placeholder (`""`) that can
        // never equal a real HTTP method, so it still reaches that same
        // documented `invalid_method` rejection.
        let method_group = |v: &Value| -> Result<Vec<String>, Error> {
            Ok(python_tuple_iter(v, bad)?
                .iter()
                .map(|i| i.as_str().unwrap_or("").to_string())
                .collect())
        };
        let methods = match obj.get("methods") {
            None | Some(Value::Null) => None,
            Some(v) => Some(method_group(v)?),
        };
        // `path_prefixes`: unlike `methods`, Python's per-element check is
        // `prefix.startswith("/")`, which raises an uncaught
        // `AttributeError` for a non-string element (state_corrupt,
        // PORTING.md §3.5) -- it cannot tolerate one the way the
        // membership test above does.
        let path_prefixes = match obj.get("path_prefixes") {
            None | Some(Value::Null) => None,
            Some(v) => {
                let mut out = Vec::new();
                for item in python_tuple_iter(v, bad)? {
                    out.push(item.as_str().map(str::to_string).ok_or_else(bad)?);
                }
                Some(out)
            }
        };
        let confirm_raw = obj.get("confirm_methods");
        let confirm_methods = if json_truthy(confirm_raw) {
            method_group(confirm_raw.expect("truthy implies present"))?
        } else {
            Vec::new()
        };
        HttpScope::new(methods, path_prefixes, confirm_methods)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshTarget {
    pub host: String,
    pub port: i64,
    pub username: String,
    pub host_keys: Vec<String>,
}

impl SshTarget {
    pub fn new(
        host: impl Into<String>,
        port: i64,
        username: impl Into<String>,
        host_keys: Vec<String>,
    ) -> Result<Self, Error> {
        let host = validate_host(&host.into())?;
        let port = validate_port(port)?;
        let username = username.into();
        // `fullmatch`, not `^...$`: Python's `$` also matches before a
        // trailing newline ("deploy\n"), which must be rejected.
        if !fullmatch(&SSH_USERNAME_RE, &username) {
            return Err(Error::invalid_input("invalid_ssh_username"));
        }
        if host_keys.is_empty() {
            return Err(Error::invalid_input("ssh_host_keys_required"));
        }
        let host_keys = host_keys
            .iter()
            .map(|line| canonical_host_key(line))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SshTarget {
            host,
            port,
            username,
            host_keys,
        })
    }

    fn to_value(&self) -> Value {
        json!({
            "host": self.host, "port": self.port, "username": self.username,
            "host_keys": self.host_keys,
        })
    }

    /// `SshTarget(value["host"], value["port"], value["username"],
    /// tuple(value["host_keys"]))` in `Connection.from_dict`. Every field is
    /// indexed directly (no `.get()` default), so a missing key is an
    /// uncaught Python `KeyError` (`state_corrupt`, PORTING.md §3.5); a
    /// present-but-wrong-type value instead reaches the same
    /// `__post_init__` checks a bad *value* would, and gets the same
    /// documented `InvalidInput` reason (see [`validate_host_value`],
    /// [`validate_port_value`], [`validate_ssh_username_value`],
    /// [`ssh_host_keys_from_value`]).
    fn from_value(v: &Value) -> Result<Self, Error> {
        let obj = v
            .as_object()
            .ok_or_else(|| Error::state("state_corrupt").with_detail("ssh_target"))?;
        let missing = || Error::state("state_corrupt").with_detail("ssh_target");
        let host = validate_host_value(obj.get("host").ok_or_else(missing)?)?;
        let port = validate_port_value(obj.get("port").ok_or_else(missing)?)?;
        let username = validate_ssh_username_value(obj.get("username").ok_or_else(missing)?)?;
        let host_keys = ssh_host_keys_from_value(obj.get("host_keys").ok_or_else(missing)?)?;
        SshTarget::new(host, port, username, host_keys)
    }
}

/// `policy._canonical_host_key` (`zeropw/policy.py`): the line must start
/// with `"ssh-ed25519 "` and contain no ASCII control character
/// (`\x00`-`\x1f`, `\x7f`), then parses via `crate::sshwire`'s
/// general-purpose `authorized_keys` parser and re-serialises canonically.
/// Python wraps the parse/serialise step in `except (sshwire.WireError,
/// ValueError)`; since `sshwire.WireError` is itself a `ValueError`
/// subclass, that catches every error either call can raise, tagged or not
/// (`crate::sshwire::WireError`'s three-way `kind` -- see its doc comment --
/// so `is_wire_error()`/`is_unsupported()` distinguish those cases for
/// *other* callers, but `_canonical_host_key` itself does not care which
/// kind it got).
fn canonical_host_key(line: &str) -> Result<String, Error> {
    if !line.starts_with("ssh-ed25519 ") {
        return Err(Error::invalid_input("unsupported_host_key"));
    }
    if CONTROL_CHARS_RE.is_match(line) {
        return Err(Error::invalid_input("invalid_host_key"));
    }
    let bad = || Error::invalid_input("invalid_host_key");
    let entry = crate::sshwire::parse_authorized_key_entry(line).map_err(|_| bad())?;
    if !entry.options.is_empty() {
        return Err(bad());
    }
    entry
        .key
        .to_authorized_key(&entry.comment)
        .map_err(|_| bad())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliProfile {
    pub program: String,
    pub kind: String,
    pub base_url_env: String,
    pub extra_env: std::collections::BTreeMap<String, String>,
    /// The original JSON value for `program` when it is a truthy list/dict
    /// that Python's `"\x00" in self.program` membership test does not
    /// reject and keeps verbatim (finding H-R5-2's sibling gap on this
    /// STATE-DOCUMENT loading path, `CliProfile::from_value`). `program`
    /// (typed `String`, PORTING.md §3b/§4's typed-field limit) cannot hold
    /// a list/dict, so it is set to the placeholder
    /// `"\u{1}container-program"` in that case and this field holds
    /// `Some(<the real container>)` instead -- `None` for an ordinary
    /// string `program`, where `program` itself is already the faithful
    /// value and no substitution ever happened.
    ///
    /// Cross-unit finding (round 8): every renderer that turns a
    /// `CliProfile` back into JSON -- [`CliProfile::to_value`] (the
    /// persisted document, read by [`Connection::to_value`] and written by
    /// `create_connection`/`update_connection`/`disable_connection` and
    /// `team::fold`'s connection derivation) and [`Connection::public_view`]
    /// (the agent-facing `get_connection`/`list_connections`/
    /// `update_connection`/`disable_connection` response) -- must render
    /// from this field whenever it is `Some`, never from `program` itself:
    /// `program` only holds a placeholder in that case, not a faithful
    /// round-trip, and DEVIATIONS.md's previous claim that nothing in this
    /// half's scope reads `CliProfile.program` back out of a loaded
    /// `Connection` was false -- `Connection::public_view` (`policy.rs`)
    /// always has, in every version of this file since `CliProfile` first
    /// gained a `program` field.
    pub raw_program: Option<Value>,
}

impl CliProfile {
    /// The JSON value `program` should render as: the original container
    /// from [`Self::raw_program`] when set, otherwise the (faithful, for an
    /// ordinary string `program`) typed field itself.
    fn program_value(&self) -> Value {
        self.raw_program
            .clone()
            .unwrap_or_else(|| Value::String(self.program.clone()))
    }

    pub fn new(
        program: impl Into<String>,
        kind: impl Into<String>,
        base_url_env: Option<String>,
        extra_env: std::collections::BTreeMap<String, String>,
    ) -> Result<Self, Error> {
        let program = program.into();
        let kind = kind.into();
        let base_url_env = base_url_env.unwrap_or_else(|| "ZEROPW_API_BASE_URL".to_string());
        if !CONNECTION_KINDS.contains(&kind.as_str()) {
            return Err(Error::invalid_input("invalid_cli_kind"));
        }
        if program.is_empty() || program.contains('\0') {
            return Err(Error::invalid_input("invalid_cli_program"));
        }
        if !env_name_matches(&base_url_env) {
            return Err(Error::invalid_input("invalid_env_name"));
        }
        for (key, value) in &extra_env {
            if !env_name_matches(key) || key == "SSH_AUTH_SOCK" || key == &base_url_env {
                return Err(Error::invalid_input("invalid_env_name"));
            }
            if value.contains('\0') {
                return Err(Error::invalid_input("invalid_env_value"));
            }
        }
        Ok(CliProfile {
            program,
            kind,
            base_url_env,
            extra_env,
            raw_program: None,
        })
    }

    /// Order-preserving counterpart of [`CliProfile::new`] (finding
    /// D-R4-8). `CliProfile.__post_init__`'s `for key, value in self.
    /// extra_env.items(): ...` iterates in the dataclass field's *insertion*
    /// order and raises on the first entry that fails, so which reason a
    /// malformed `extra_env` gets depends on that order: `{"zz": "x", "AA":
    /// "\x00"}` raises `invalid_env_name` in Python (`"zz"` checked first),
    /// but `new`'s `BTreeMap<String, String>` parameter always iterates in
    /// *key-sorted* order, so the same map there checks `"AA"` first and
    /// raises `invalid_env_value` instead.
    ///
    /// `CliProfile::from_value` is unaffected -- round 2 already made it
    /// validate its own document-ordered pairs before ever calling `new`,
    /// so by the time `new` re-checks them every entry already passed. This
    /// only matters for a caller that constructs a `CliProfile` directly
    /// with an `extra_env` whose original document order it still has and
    /// wants to reproduce; `team::commit::build_cli_profile` (the crate's
    /// only current caller of `new`) builds its `extra_env` from a
    /// `serde_json::Map` from a JSON object without preserving that as a
    /// separate ordered list, so it keeps calling `new` -- changing `new`'s
    /// signature would break that call site, which is owned by another
    /// engineer's concurrent work. See `rust/DEVIATIONS.md`.
    pub fn new_ordered(
        program: impl Into<String>,
        kind: impl Into<String>,
        base_url_env: Option<String>,
        extra_env: Vec<(String, String)>,
    ) -> Result<Self, Error> {
        let program = program.into();
        let kind = kind.into();
        let base_url_env = base_url_env.unwrap_or_else(|| "ZEROPW_API_BASE_URL".to_string());
        if !CONNECTION_KINDS.contains(&kind.as_str()) {
            return Err(Error::invalid_input("invalid_cli_kind"));
        }
        if program.is_empty() || program.contains('\0') {
            return Err(Error::invalid_input("invalid_cli_program"));
        }
        if !env_name_matches(&base_url_env) {
            return Err(Error::invalid_input("invalid_env_name"));
        }
        for (key, value) in &extra_env {
            if !env_name_matches(key) || key == "SSH_AUTH_SOCK" || key == &base_url_env {
                return Err(Error::invalid_input("invalid_env_name"));
            }
            if value.contains('\0') {
                return Err(Error::invalid_input("invalid_env_value"));
            }
        }
        Ok(CliProfile {
            program,
            kind,
            base_url_env,
            extra_env: extra_env.into_iter().collect(),
            raw_program: None,
        })
    }

    fn to_value(&self) -> Value {
        json!({
            "program": self.program_value(), "kind": self.kind, "base_url_env": self.base_url_env,
            "extra_env": self.extra_env,
        })
    }

    /// `CliProfile(value["program"], value["kind"], value.get("base_url_env",
    /// "ZEROPW_API_BASE_URL"), dict(value.get("extra_env") or {}))` in
    /// `Connection.from_dict`, followed by `CliProfile.__post_init__`.
    ///
    /// Two distinct phases, in this exact order (findings D-R3-5, D-R3-6):
    ///
    /// 1. Constructor-argument evaluation, left to right: `value["program"]`/
    ///    `value["kind"]` (a missing key is an uncaught `KeyError`,
    ///    `state_corrupt`), `value.get("base_url_env", ...)` (never raises),
    ///    then `dict(value.get("extra_env") or {})` -- Python's `or` is a
    ///    *falsy* check (an absent key or a falsy stored value
    ///    short-circuits to `{}` without ever calling `dict`), and a truthy
    ///    value's `dict(x)` coercion can itself raise a
    ///    `TypeError`/`ValueError` for a fundamentally non-dict-shaped `x` --
    ///    *before* `__post_init__` (phase 2) ever runs, so this can pre-empt
    ///    even an invalid `kind`/`program` (verified against `python3.12`:
    ///    `kind="ftp", extra_env=5` raises the `TypeError` from `dict(5)`,
    ///    not `invalid_cli_kind`).
    /// 2. `__post_init__`, only once phase 1 has fully succeeded: `kind`
    ///    membership, then `program` (falsy-or-null-byte), then
    ///    `base_url_env` (`re.match`, an uncaught `TypeError` for *any*
    ///    non-string value -- no membership-style tolerance the way
    ///    `kind`/`program`/`status` have), then the already-dict-shaped
    ///    `extra_env`'s per-entry name-then-value checks in document order
    ///    (finding D-R2-5). Probes confirm this order: `kind="ftp",
    ///    extra_env={"zz":"x"}` -> `invalid_cli_kind` (checked before the
    ///    extra_env per-entry loop even though the shape itself is already
    ///    valid); `program="", extra_env={"AA":5}` -> `invalid_cli_program`.
    ///    `CliProfile::new` is still called at the end as the single source
    ///    of truth for constructing the value; by then every check above
    ///    already passed, so its own (key-sorted) re-checks can only ever
    ///    re-confirm success.
    fn from_value(v: &Value) -> Result<Self, Error> {
        let bad = || Error::state("state_corrupt").with_detail("cli");
        let obj = v.as_object().ok_or_else(bad)?;

        // Phase 1.
        let program_raw = obj.get("program").ok_or_else(bad)?.clone();
        let kind_raw = obj.get("kind").ok_or_else(bad)?.clone();
        let base_url_env_raw = obj.get("base_url_env").cloned();
        let extra_env_raw = obj.get("extra_env");
        let pairs: Vec<(Value, Value)> = if !json_truthy(extra_env_raw) {
            Vec::new()
        } else {
            match extra_env_raw.expect("truthy implies present") {
                Value::Object(m) => m
                    .iter()
                    .map(|(k, val)| (Value::String(k.clone()), val.clone()))
                    .collect(),
                other => python_dict_from_pairs(other, bad)?,
            }
        };

        // Phase 2, in Python's exact order.
        // `self.kind not in CONNECTION_KINDS`: a plain membership check, no
        // `isinstance` guard, so a non-string `kind` (placeholder `""`)
        // simply never matches and gets the same documented reason.
        let kind = kind_raw.as_str().unwrap_or("").to_string();
        if !CONNECTION_KINDS.contains(&kind.as_str()) {
            return Err(Error::invalid_input("invalid_cli_kind"));
        }
        // `if not self.program or "\x00" in self.program`: Python's `or`
        // short-circuits on *any* falsy value (not just an empty string),
        // so a present falsy non-string (`null`/`0`/`false`/`[]`/`{}`) gets
        // this documented reason too; only a *truthy* non-string reaches
        // `"\x00" in self.program`, a genuinely uncaught `TypeError` for a
        // non-iterable (a number/bool) -- `state_corrupt` for that case,
        // since there is no documented reason to substitute a scalar with.
        //
        // A truthy `list`/`dict` does NOT raise (finding H-R5-2's sibling
        // gap on this loading path: `"\x00" in self.program` is a plain
        // membership test, true only when an element/key literally equals
        // `"\x00"`), and Python loads it successfully, keeping the
        // list/dict verbatim -- `team::commit::build_cli_profile` can now
        // legitimately write exactly that shape into a document (it folds
        // a peer's `connection.create`/`connection.update` op the same way
        // Python does), so this must accept it too rather than fail the
        // whole document with `state_corrupt`. `CliProfile.program` is
        // typed `String` here and cannot hold the real list/dict (PORTING.md
        // §3b's typed-field limit, same as `ca_file`); the value substituted
        // below is a placeholder guaranteed to pass the checks after it, not
        // a faithful round-trip of the original container through the typed
        // field itself -- but [`CliProfile::raw_program`] (populated below)
        // carries the real container through unchanged, and every renderer
        // (`to_value`, `Connection::public_view`) reads that instead of
        // `program` whenever it is set, so the public view and the
        // persisted document are still byte-identical to Python's (cross-
        // unit finding, round 8: DEVIATIONS.md previously and wrongly
        // claimed this placeholder was never read back by anything in this
        // half's scope).
        let program_contains_nul = match &program_raw {
            Value::String(s) => s.contains('\0'),
            Value::Array(items) => items.iter().any(|v| v.as_str() == Some("\u{0}")),
            Value::Object(map) => map.keys().any(|k| k == "\u{0}"),
            Value::Number(_) | Value::Bool(_) | Value::Null => false,
        };
        if !json_truthy(Some(&program_raw)) || program_contains_nul {
            return Err(Error::invalid_input("invalid_cli_program"));
        }
        let program_is_container = matches!(&program_raw, Value::Array(_) | Value::Object(_));
        let program = match program_raw.as_str() {
            Some(s) => s.to_string(),
            None if program_is_container => "\u{1}container-program".to_string(),
            None => return Err(bad()),
        };
        // `re.match(pattern, self.base_url_env)`: no `isinstance` guard at
        // all, so a present non-string value raises an uncaught `TypeError`
        // here, unconditionally.
        let base_url_env = match &base_url_env_raw {
            None => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => return Err(bad()),
        };
        let resolved_base_url_env = base_url_env
            .clone()
            .unwrap_or_else(|| "ZEROPW_API_BASE_URL".to_string());
        if !env_name_matches(&resolved_base_url_env) {
            return Err(Error::invalid_input("invalid_env_name"));
        }
        // `for key, value in self.extra_env.items()`, in the document order
        // `pairs` already preserves (finding D-R2-5).
        let mut extra_env = std::collections::BTreeMap::new();
        for (key, val) in &pairs {
            // `re.match(pattern, key)`: a non-string key (only reachable
            // via the array-of-pairs shape) raises the same uncaught
            // `TypeError` `base_url_env` does above.
            let key_str = key.as_str().ok_or_else(bad)?;
            if !env_name_matches(key_str)
                || key_str == "SSH_AUTH_SOCK"
                || key_str == resolved_base_url_env
            {
                return Err(Error::invalid_input("invalid_env_name"));
            }
            let val_str = val
                .as_str()
                .ok_or_else(|| Error::invalid_input("invalid_env_value"))?;
            if val_str.contains('\0') {
                return Err(Error::invalid_input("invalid_env_value"));
            }
            extra_env.insert(key_str.to_string(), val_str.to_string());
        }
        let mut profile = CliProfile::new(program, kind, base_url_env, extra_env)?;
        if program_is_container {
            profile.raw_program = Some(program_raw.clone());
        }
        Ok(profile)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Connection {
    pub id: String,
    pub project: String,
    pub environment: String,
    pub service: String,
    /// `"http"` or `"ssh"`.
    pub kind: String,
    pub secret_id: String,
    pub secret_version: Option<i64>,
    pub description: String,
    pub http_target: Option<HttpTarget>,
    pub http_auth: Option<HttpAuth>,
    pub http_scope: Option<HttpScope>,
    pub ssh_target: Option<SshTarget>,
    pub cli: Option<CliProfile>,
    pub policy_version: i64,
    /// `"active"` or `"disabled"`.
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

/// The subset of `Connection`'s fields `Policy::update_connection` may
/// change (`replace(before, **changes)` in Python). Every field is an
/// `Option`: `None` means "leave as-is"; the nullable ones (`http_target`
/// etc.) are `Option<Option<T>>` so a change can also *set* the field to
/// `None`. Python validates the kwarg names at runtime
/// (`connection_field_not_updatable`); Rust's typed builder makes an unknown
/// field a compile error instead, so that check has no Rust equivalent to
/// port (not a behaviour difference for any valid caller).
#[derive(Default)]
pub struct ConnectionChanges {
    pub description: Option<String>,
    pub http_target: Option<Option<HttpTarget>>,
    pub http_auth: Option<Option<HttpAuth>>,
    pub http_scope: Option<Option<HttpScope>>,
    pub ssh_target: Option<Option<SshTarget>>,
    pub cli: Option<Option<CliProfile>>,
    pub secret_id: Option<String>,
    pub secret_version: Option<Option<i64>>,
    pub status: Option<String>,
}

impl ConnectionChanges {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn description(mut self, v: impl Into<String>) -> Self {
        self.description = Some(v.into());
        self
    }
    pub fn http_target(mut self, v: Option<HttpTarget>) -> Self {
        self.http_target = Some(v);
        self
    }
    pub fn http_auth(mut self, v: Option<HttpAuth>) -> Self {
        self.http_auth = Some(v);
        self
    }
    pub fn http_scope(mut self, v: Option<HttpScope>) -> Self {
        self.http_scope = Some(v);
        self
    }
    pub fn ssh_target(mut self, v: Option<SshTarget>) -> Self {
        self.ssh_target = Some(v);
        self
    }
    pub fn cli(mut self, v: Option<CliProfile>) -> Self {
        self.cli = Some(v);
        self
    }
    pub fn secret_id(mut self, v: impl Into<String>) -> Self {
        self.secret_id = Some(v.into());
        self
    }
    pub fn secret_version(mut self, v: Option<i64>) -> Self {
        self.secret_version = Some(v);
        self
    }
    pub fn status(mut self, v: impl Into<String>) -> Self {
        self.status = Some(v.into());
        self
    }
}

impl Connection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        project: impl Into<String>,
        environment: impl Into<String>,
        service: impl Into<String>,
        kind: impl Into<String>,
        secret_id: impl Into<String>,
        secret_version: Option<i64>,
        description: impl Into<String>,
        http_target: Option<HttpTarget>,
        http_auth: Option<HttpAuth>,
        http_scope: Option<HttpScope>,
        ssh_target: Option<SshTarget>,
        cli: Option<CliProfile>,
        policy_version: i64,
        status: impl Into<String>,
        created_at: impl Into<String>,
        updated_at: impl Into<String>,
    ) -> Result<Self, Error> {
        let id = validate_name(&id.into(), "connection_id")?;
        let kind = kind.into();
        let status = status.into();
        if !CONNECTION_KINDS.contains(&kind.as_str()) {
            return Err(Error::invalid_input("invalid_connection_kind"));
        }
        if kind == "http" && !(http_target.is_some() && http_auth.is_some() && http_scope.is_some())
        {
            return Err(Error::invalid_input("http_connection_incomplete"));
        }
        if kind == "ssh" && ssh_target.is_none() {
            return Err(Error::invalid_input("ssh_connection_incomplete"));
        }
        if let Some(c) = &cli
            && c.kind != kind
        {
            return Err(Error::invalid_input("cli_kind_mismatch"));
        }
        if status != "active" && status != "disabled" {
            return Err(Error::invalid_input("invalid_status"));
        }
        Ok(Connection {
            id,
            project: project.into(),
            environment: environment.into(),
            service: service.into(),
            kind,
            secret_id: secret_id.into(),
            secret_version,
            description: description.into(),
            http_target,
            http_auth,
            http_scope,
            ssh_target,
            cli,
            policy_version,
            status,
            created_at: created_at.into(),
            updated_at: updated_at.into(),
        })
    }

    /// `replace(before, **changes)` then re-run `__post_init__` (Python's
    /// frozen-dataclass `replace` re-validates through the constructor).
    fn with_changes(&self, changes: &ConnectionChanges) -> Result<Connection, Error> {
        Connection::new(
            self.id.clone(),
            self.project.clone(),
            self.environment.clone(),
            self.service.clone(),
            self.kind.clone(),
            changes
                .secret_id
                .clone()
                .unwrap_or_else(|| self.secret_id.clone()),
            changes.secret_version.unwrap_or(self.secret_version),
            changes
                .description
                .clone()
                .unwrap_or_else(|| self.description.clone()),
            changes
                .http_target
                .clone()
                .unwrap_or_else(|| self.http_target.clone()),
            changes
                .http_auth
                .clone()
                .unwrap_or_else(|| self.http_auth.clone()),
            changes
                .http_scope
                .clone()
                .unwrap_or_else(|| self.http_scope.clone()),
            changes
                .ssh_target
                .clone()
                .unwrap_or_else(|| self.ssh_target.clone()),
            changes.cli.clone().unwrap_or_else(|| self.cli.clone()),
            self.policy_version,
            changes
                .status
                .clone()
                .unwrap_or_else(|| self.status.clone()),
            self.created_at.clone(),
            self.updated_at.clone(),
        )
    }

    /// `Connection.to_dict` (`dataclasses.asdict`).
    pub fn to_value(&self) -> Value {
        json!({
            "id": self.id, "project": self.project, "environment": self.environment,
            "service": self.service, "kind": self.kind, "secret_id": self.secret_id,
            "secret_version": self.secret_version, "description": self.description,
            "http_target": self.http_target.as_ref().map(HttpTarget::to_value),
            "http_auth": self.http_auth.as_ref().map(HttpAuth::to_value),
            "http_scope": self.http_scope.as_ref().map(HttpScope::to_value),
            "ssh_target": self.ssh_target.as_ref().map(SshTarget::to_value),
            "cli": self.cli.as_ref().map(CliProfile::to_value),
            "policy_version": self.policy_version, "status": self.status,
            "created_at": self.created_at, "updated_at": self.updated_at,
        })
    }

    /// `Connection.from_dict`. A stored `http_target` loads with
    /// `check_address=False` (Python: "a record saved before a literal
    /// became forbidden must still load").
    /// Port of `Connection.from_dict`.
    ///
    /// Python evaluates `Connection(id=data["id"], project=data["project"],
    /// ...)` strictly in the order these keyword arguments are written
    /// (policy.py:429-440): each raw `data[key]` access raises an uncaught
    /// `KeyError` (state_corrupt, PORTING.md §3.5) exactly where it is
    /// missing, and the nested `build()` calls for
    /// http_target/http_auth/http_scope/ssh_target/cli run their own real
    /// `__post_init__` validation right there, in between -- all of this
    /// happens *before* `Connection.__post_init__` itself runs (which then
    /// checks `id` via `validate_name`, then `kind`'s membership, then
    /// completeness/cli/status). Getting this order right matters: a
    /// malformed `id`/`kind`/`status`, or one of the untyped fields below,
    /// must not pre-empt a nested build's own documented error (finding
    /// D-R3-3; probe: `id=5` with a bad `http_target.scheme` -> Python's
    /// `invalid_scheme`, not `invalid_connection_id`; `id=5, kind=5` ->
    /// Python's `invalid_connection_id`, since `validate_name(id)` in
    /// `__post_init__` runs before the `kind` membership check).
    ///
    /// `project`/`environment`/`service`/`secret_id`/`secret_version`/
    /// `description`/`created_at`/`updated_at` are never type-checked by
    /// Python at all (see the `policy` row in `DEVIATIONS.md`) -- a present
    /// non-string value there is stored completely verbatim by Python (a
    /// real success, e.g. a stored `project: 5` alone loads fine), so
    /// unlike `id`/`kind`/`status` there is no Python checkpoint to line
    /// this crate's own representational gap up against. To make sure it
    /// never masks a genuine Python-mirrored error, every such gap is
    /// collected in `corrupt` and only surfaced once every check below that
    /// *does* have a real Python counterpart has already succeeded.
    pub fn from_value(v: &Value) -> Result<Self, Error> {
        let bad = || Error::state("state_corrupt").with_detail("connection");
        let obj = v.as_object().ok_or_else(bad)?;
        let mut corrupt = false;
        let required_str = |key: &str, corrupt: &mut bool| -> Result<String, Error> {
            match obj.get(key) {
                None => Err(bad()),
                Some(Value::String(s)) => Ok(s.clone()),
                Some(_) => {
                    *corrupt = true;
                    Ok(String::new())
                }
            }
        };

        // Kwarg order 1-4: id, project, environment, service.
        let id_raw = obj.get("id").ok_or_else(bad)?.clone();
        let project = required_str("project", &mut corrupt)?;
        let environment = required_str("environment", &mut corrupt)?;
        let service = required_str("service", &mut corrupt)?;
        // Kwarg order 5-6: kind, secret_id.
        let kind_raw = obj.get("kind").ok_or_else(bad)?.clone();
        let secret_id = required_str("secret_id", &mut corrupt)?;
        // Kwarg order 7-8: secret_version, description (both untyped in
        // Python -- see the doc comment above).
        let secret_version = match obj.get("secret_version") {
            None | Some(Value::Null) => None,
            Some(v) => match v.as_i64() {
                Some(n) => Some(n),
                None => {
                    corrupt = true;
                    None
                }
            },
        };
        let description = match obj.get("description") {
            None => String::new(),
            Some(Value::String(s)) => s.clone(),
            Some(_) => {
                corrupt = true;
                String::new()
            }
        };
        // Kwarg order 9-13: the nested `build()` calls, each with its own
        // real Python validation.
        let opt_val = |key: &str| -> Option<&Value> {
            match obj.get(key) {
                Some(Value::Null) | None => None,
                Some(v) => Some(v),
            }
        };
        let http_target = opt_val("http_target")
            .map(HttpTarget::from_value)
            .transpose()?;
        let http_auth = opt_val("http_auth").map(HttpAuth::from_value).transpose()?;
        let http_scope = opt_val("http_scope")
            .map(HttpScope::from_value)
            .transpose()?;
        let ssh_target = opt_val("ssh_target")
            .map(SshTarget::from_value)
            .transpose()?;
        let cli = opt_val("cli").map(CliProfile::from_value).transpose()?;
        // Kwarg order 14: `policy_version=int(data["policy_version"])`. A
        // missing key is an uncaught `KeyError`, and any shape `int()`
        // itself would raise on is an uncaught `TypeError`/`ValueError` --
        // both §3.5, `state_corrupt` either way. [`python_int_coerce`]
        // reproduces exactly the shapes `int()` *does* accept.
        let policy_version = obj
            .get("policy_version")
            .and_then(python_int_coerce)
            .ok_or_else(bad)?;
        // Kwarg order 15-17: status, created_at, updated_at.
        let status_raw = obj.get("status").ok_or_else(bad)?.clone();
        let created_at = required_str("created_at", &mut corrupt)?;
        let updated_at = required_str("updated_at", &mut corrupt)?;

        // `Connection.__post_init__` runs only now, on the fully
        // constructed instance, via `Connection::new`: `validate_name(id)`
        // first, then `kind`'s membership check, then completeness/cli/
        // status. A present non-string `id`/`kind`/`status` is passed
        // through as `""`, which never matches `validate_name`'s regex,
        // `CONNECTION_KINDS`, or the status tuple -- exactly like Python's
        // own non-string value, it always fails that check with the same
        // documented reason a real mismatched string would.
        let id = id_raw.as_str().unwrap_or("").to_string();
        let kind = kind_raw.as_str().unwrap_or("").to_string();
        let status = status_raw.as_str().unwrap_or("").to_string();
        let connection = Connection::new(
            id,
            project,
            environment,
            service,
            kind,
            secret_id,
            secret_version,
            description,
            http_target,
            http_auth,
            http_scope,
            ssh_target,
            cli,
            policy_version,
            status,
            created_at,
            updated_at,
        )?;
        if corrupt {
            return Err(bad());
        }
        Ok(connection)
    }

    /// What an agent may see: no secret ids, no internal file paths.
    pub fn public_view(&self) -> Value {
        let mut view = Map::new();
        view.insert("id".into(), json!(self.id));
        view.insert("project".into(), json!(self.project));
        view.insert("environment".into(), json!(self.environment));
        view.insert("service".into(), json!(self.service));
        view.insert("kind".into(), json!(self.kind));
        view.insert("description".into(), json!(self.description));
        view.insert("policy_version".into(), json!(self.policy_version));
        view.insert(
            "cli".into(),
            match &self.cli {
                Some(c) => json!({"program": c.program_value()}),
                None => Value::Null,
            },
        );
        if self.kind == "http"
            && let (Some(target), Some(scope), Some(auth)) =
                (&self.http_target, &self.http_scope, &self.http_auth)
        {
            view.insert(
                "target".into(),
                json!({"scheme": target.scheme, "host": target.host, "port": target.port}),
            );
            view.insert("auth_mode".into(), json!(auth.mode));
            view.insert(
                "scope".into(),
                json!({
                    // Python: `list(...) if self.http_scope.methods else "all"`
                    // -- falsy, not `is None`: an explicitly empty
                    // `methods`/`path_prefixes` (legal for `methods`; only
                    // reachable for `path_prefixes` via a hand-corrupted
                    // stored document, since `HttpScope.__post_init__`
                    // rejects an empty `path_prefixes`) also displays as
                    // `"all"`.
                    "methods": match &scope.methods { Some(m) if !m.is_empty() => Value::from(m.clone()), _ => Value::String("all".into()) },
                    "path_prefixes": match &scope.path_prefixes { Some(p) if !p.is_empty() => Value::from(p.clone()), _ => Value::String("all".into()) },
                    "confirm_methods": scope.confirm_methods,
                }),
            );
        }
        if self.kind == "ssh"
            && let Some(target) = &self.ssh_target
        {
            view.insert(
                "target".into(),
                json!({"host": target.host, "port": target.port, "username": target.username}),
            );
            view.insert("auth_mode".into(), json!("ssh-ed25519-signature"));
        }
        Value::Object(view)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub id: String,
    pub token_hash: String,
    pub status: String,
    pub created_at: String,
    pub runtime: String,
}

/// Runtime shape of a `Grant` field Python's `Grant` dataclass applies
/// **no** `int()`/`isinstance` conversion to at all (`policy_version`,
/// `max_uses`, `uses`, `credential_version`) -- the dataclass keeps
/// whatever JSON-shaped value `Grant(**entry)` was handed, and every use
/// site compares it with CPython's plain `==`/`!=`/ordering/arithmetic
/// operators, which resolve numerically across `int`/`float`/`bool` but
/// raise an uncaught `TypeError` for a numeric-vs-`str` pair. Correcting
/// round 4's D-R4-7 fix (finding D-R5-2), which routed these fields
/// through [`python_int_coerce`] -- accepting a numeric *string* and
/// silently parsing it to an `i64`. That flips real authorization
/// outcomes both ways: a stored `policy_version: "1"` never equals an
/// `int` connection version in Python (`str != int` is always `True`), so
/// it is always `grant_stale`, where the coerced `i64` could match and
/// allow; two stored strings for `max_uses`/`uses` compare
/// *lexicographically* in Python (`"2" >= "10"` is `True`, `"10" >= "9"`
/// is `False`), the opposite of their coerced-`i64` numeric comparison.
/// See [`grant_num_ne_i64`]/[`grant_num_ge`]/[`grant_num_sub`]/
/// [`grant_num_add_one`] for the specific operations these fields are put
/// through, each reproducing Python's exact cross-type behaviour
/// (including raising the closest handled error, `state_corrupt`, for a
/// numeric-vs-`str` operand pair Python itself cannot compare).
#[derive(Clone, Debug, PartialEq)]
pub enum GrantNum {
    Int(i64),
    /// An integer-shaped JSON literal (no `.`/`e`/`E`) outside `i64` range
    /// but within `i128` -- Python's `int` is arbitrary-precision, so a
    /// value like `10**30` stays *exact* there; representing it as
    /// [`GrantNum::Float`] (the previous behaviour, round-5/round-6
    /// differential-harness finding) made every arithmetic operation and
    /// every persisted byte only an `f64` approximation of it (`remaining_uses`,
    /// `consume`'s `uses + 1`, ...). `i128` covers every magnitude this
    /// harness or any real deployment writes exactly; a literal beyond even
    /// `i128` (astronomically larger than anything this crate or
    /// `zeropw/policy.py` itself ever produces) falls back to
    /// [`GrantNum::Other`], which still preserves the exact JSON text for
    /// round-tripping but -- like `Str`/`Other` generally -- no longer
    /// participates in arithmetic without raising the closest handled
    /// error.
    BigInt(i128),
    Float(f64),
    Bool(bool),
    Str(String),
    /// `null`, an array or an object: Python's `Grant` dataclass applies no
    /// `isinstance` check at all, so these load exactly as successfully as
    /// any other shape (differential-harness finding, round 5: an earlier
    /// version of this enum had no variant for them, so `Grant::from_value`
    /// aborted the *entire* grant load -- `state_corrupt` -- for a `null`/
    /// array/object `uses`/`max_uses`/`policy_version`/`credential_version`
    /// where Python succeeds unconditionally). Behaves exactly like
    /// [`GrantNum::Str`] in every operation: never equal to an `int`, and
    /// raises the closest handled error for ordering/arithmetic, matching
    /// Python's own `TypeError` for e.g. `None >= 5` or `[] + 1`.
    Other(Value),
}

impl GrantNum {
    fn from_value(v: &Value) -> Self {
        match v {
            Value::Bool(b) => GrantNum::Bool(*b),
            Value::String(s) => GrantNum::Str(s.clone()),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    GrantNum::Int(i)
                } else if number_is_python_int(n) {
                    // Integer-shaped but outside `i64` -- keep it exact via
                    // `i128` when possible (see the variant's own doc
                    // comment) instead of silently approximating via `f64`.
                    match n.to_string().parse::<i128>() {
                        Ok(i) => GrantNum::BigInt(i),
                        Err(_) => GrantNum::Other(v.clone()),
                    }
                } else if let Some(f) = n.as_f64() {
                    GrantNum::Float(f)
                } else {
                    GrantNum::Other(v.clone())
                }
            }
            other => GrantNum::Other(other.clone()),
        }
    }

    fn to_value(&self) -> Value {
        match self {
            GrantNum::Int(i) => json!(i),
            GrantNum::BigInt(i) => json!(*i),
            GrantNum::Float(f) => json!(f),
            GrantNum::Bool(b) => json!(b),
            GrantNum::Str(s) => json!(s),
            GrantNum::Other(v) => v.clone(),
        }
    }

    /// `None` for [`GrantNum::Str`]/[`GrantNum::Other`]; every numeric
    /// variant converts (an exact [`GrantNum::BigInt`] is approximated here
    /// only for the *ordering* fallback in [`grant_num_ge`] -- exact
    /// arithmetic goes through [`GrantNum::as_i128`] first).
    fn as_f64(&self) -> Option<f64> {
        match self {
            GrantNum::Int(i) => Some(*i as f64),
            GrantNum::BigInt(i) => Some(*i as f64),
            GrantNum::Float(f) => Some(*f),
            GrantNum::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            GrantNum::Str(_) | GrantNum::Other(_) => None,
        }
    }

    /// Exact `i128` value for every integer-or-bool-shaped variant
    /// (`Int`/`BigInt`/`Bool`); `None` for `Float`/`Str`/`Other` (a float is
    /// never promoted to an exact integer here, even when integral, since
    /// Python's own `int - int` vs. `float - float` distinction depends on
    /// the stored *type*, not the value).
    fn as_i128(&self) -> Option<i128> {
        match self {
            GrantNum::Int(i) => Some(*i as i128),
            GrantNum::BigInt(i) => Some(*i),
            GrantNum::Bool(b) => Some(i128::from(*b)),
            GrantNum::Float(_) | GrantNum::Str(_) | GrantNum::Other(_) => None,
        }
    }

    /// Whether this is one of the two shapes ([`GrantNum::Str`],
    /// [`GrantNum::Other`]) that never participates in a numeric
    /// comparison/operation without raising.
    fn is_non_numeric(&self) -> bool {
        matches!(self, GrantNum::Str(_) | GrantNum::Other(_))
    }
}

/// `f == i` compared exactly (no precision loss for `i` near the `i64`
/// boundary): `f` must be an integer-valued `f64` within the exact `i64`
/// range (see [`I64_MIN_AS_F64`]/[`I64_MAX_EXCLUSIVE_AS_F64`]) whose
/// truncation equals `i`.
fn float_eq_i64_exact(f: f64, i: i64) -> bool {
    f.fract() == 0.0 && (I64_MIN_AS_F64..I64_MAX_EXCLUSIVE_AS_F64).contains(&f) && (f as i64) == i
}

/// `grant.policy_version != connection.policy_version` (`_grant_state`):
/// `connection.policy_version` is always a plain, already-`int()`-coerced
/// `i64` (`Connection::from_value` routes it through `python_int_coerce`),
/// so this only needs the other side's shape. A `str` never equals an
/// `int` in Python (`!=` is `True` unconditionally, never raises); a bool
/// compares via `int(bool)`; a float compares exactly, not by casting both
/// sides to `f64` (see [`float_eq_i64_exact`]).
fn grant_num_ne_i64(a: &GrantNum, b: i64) -> bool {
    match a {
        GrantNum::Str(_) | GrantNum::Other(_) => true,
        GrantNum::Bool(x) => i64::from(*x) != b,
        GrantNum::Int(x) => *x != b,
        // Constructed only for a magnitude outside `i64` range, so this is
        // never equal to any representable `i64` -- exact, not an
        // approximation.
        GrantNum::BigInt(_) => true,
        GrantNum::Float(f) => !float_eq_i64_exact(*f, b),
    }
}

/// `grant.uses >= grant.max_uses` (`_grant_state`'s exhaustion check):
/// numeric-vs-numeric resolves by value; two `str` values compare
/// lexicographically (Python `str.__ge__`, which Rust's `&str: Ord` already
/// matches -- both order by Unicode scalar value / UTF-8 byte order); a
/// numeric-vs-`str` pair raises an uncaught `TypeError` in Python, which
/// `_grant_state` does not catch -- `state_corrupt` is the closest error a
/// caller of `_grant_state` (`evaluate`/`consume`/`check_grant`/
/// `usable_connections`/`_approval_mismatch`) already handles (PORTING.md
/// §3.5).
///
/// **Round-7 correction (finding D-R7-6):** two JSON *arrays* also support
/// `>=` in Python -- lists have real, working ordering -- but the previous
/// `a.is_non_numeric() || b.is_non_numeric()` guard treated `GrantNum::Other`
/// (which an array falls into, alongside `null` and an object) as
/// unconditionally non-comparable, so both `uses`/`max_uses` being arrays
/// gave `state_corrupt` where Python decides. Measured: `[] >= [1]` is
/// `False`, `[] >= []` is `True`; with `uses: []`, `max_uses: [1]`,
/// `check_grant` returns `(True, "allowed")` in Python (this crate gave
/// `state_corrupt`); with `uses: []`, `max_uses: []` it returns `(False,
/// "grant_exhausted")`. `dict >= dict` genuinely *is* an uncaught
/// `TypeError` in Python (`'>=' not supported between instances of 'dict'
/// and 'dict'`), so an object (or any other non-array `Other`, or a mixed
/// pair) still falls through to the existing `state_corrupt` case below.
fn grant_num_ge(a: &GrantNum, b: &GrantNum) -> Result<bool, Error> {
    match (a, b) {
        (GrantNum::Str(x), GrantNum::Str(y)) => Ok(x.as_str() >= y.as_str()),
        (GrantNum::Other(Value::Array(x)), GrantNum::Other(Value::Array(y))) => {
            python_list_ge(x, y)
        }
        _ if a.is_non_numeric() || b.is_non_numeric() => {
            Err(Error::state("state_corrupt").with_detail("grant"))
        }
        // Exact integer-vs-integer ordering (covers a `BigInt` beyond `i64`
        // range) before falling back to the lossy `f64` comparison used for
        // any pair involving a genuine `Float`.
        _ if a.as_i128().is_some() && b.as_i128().is_some() => {
            Ok(a.as_i128().expect("checked above") >= b.as_i128().expect("checked above"))
        }
        _ => Ok(a.as_f64().expect("checked numeric above")
            >= b.as_f64().expect("checked numeric above")),
    }
}

/// Python `==` for a pair of JSON values of *any* shape -- used by list
/// ordering's own element-by-element walk (`python_list_ge`/
/// `python_value_gt`, finding D-R7-6), which (like CPython's real list
/// comparison) tries `==` on each pair of elements before ever needing
/// `<`/`>`, and never raises doing so: mismatched types are just unequal
/// (`5 == "5"` is `False`, no exception), unlike ordering. Numeric
/// cross-type equality (`int`/`float`/`bool`) delegates to
/// [`python_numeric_eq_value`] (exact above 2**53, like every other numeric
/// comparison in this module); arrays/objects compare structurally,
/// recursively, the same way Python's own `list.__eq__`/`dict.__eq__` do
/// (an object's key order never affects equality, matching Python `dict`).
fn python_value_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| python_value_eq(p, q))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|v2| python_value_eq(v, v2)))
        }
        (Value::Number(_) | Value::Bool(_), Value::Number(_) | Value::Bool(_)) => {
            python_numeric_eq_value(Some(a), b)
        }
        _ => false,
    }
}

/// Python `x > y` for a pair of JSON values of any shape, used once
/// `python_value_eq` has already established the pair is *not* equal
/// (finding D-R7-6): a string pair compares lexicographically (same
/// reasoning as `grant_num_ge`'s `Str` arm); an array pair recurses via
/// [`python_list_gt`]; a numeric-or-bool pair compares by value (exact
/// above 2**53 when both sides are integer-shaped, via [`GrantNum`]'s own
/// `as_i128`, falling back to `f64` only for a genuine float, mirroring
/// `grant_num_ge`); anything else (a `null`/object operand, or a pair of
/// mismatched non-numeric shapes, e.g. a string against a number) is a
/// genuinely uncaught `TypeError` in Python (`'>' not supported between
/// instances of ...`), `state_corrupt` here (PORTING.md §3.5).
fn python_value_gt(a: &Value, b: &Value) -> Result<bool, Error> {
    match (a, b) {
        (Value::String(x), Value::String(y)) => Ok(x > y),
        (Value::Array(x), Value::Array(y)) => python_list_gt(x, y),
        (Value::Number(_) | Value::Bool(_), Value::Number(_) | Value::Bool(_)) => {
            let (ga, gb) = (GrantNum::from_value(a), GrantNum::from_value(b));
            if let (Some(x), Some(y)) = (ga.as_i128(), gb.as_i128()) {
                Ok(x > y)
            } else {
                Ok(ga.as_f64().expect("numeric") > gb.as_f64().expect("numeric"))
            }
        }
        _ => Err(Error::state("state_corrupt").with_detail("grant")),
    }
}

/// Python's list `>` (lexicographic): the first pair of elements that
/// differ (by `==`) decides the whole comparison via [`python_value_gt`];
/// if every paired element is equal, the longer list is greater (Python's
/// `list.__gt__`/`__ge__`/`__lt__`/`__le__` all reduce to this same
/// "compare elements, then length" algorithm, standard lexicographic
/// tuple/sequence ordering).
fn python_list_gt(x: &[Value], y: &[Value]) -> Result<bool, Error> {
    for (p, q) in x.iter().zip(y.iter()) {
        if python_value_eq(p, q) {
            continue;
        }
        return python_value_gt(p, q);
    }
    Ok(x.len() > y.len())
}

/// Python's list `>=` (finding D-R7-6's `uses`/`max_uses` array case): same
/// element-then-length algorithm as [`python_list_gt`], differing only in
/// the length tie-break (`>=` on equal-length, all-equal-elements lists is
/// `True`, matching `[] >= []`).
fn python_list_ge(x: &[Value], y: &[Value]) -> Result<bool, Error> {
    for (p, q) in x.iter().zip(y.iter()) {
        if python_value_eq(p, q) {
            continue;
        }
        return python_value_gt(p, q);
    }
    Ok(x.len() >= y.len())
}

/// `max_uses - uses` (`Grant.public_view`'s `remaining_uses`,
/// `Policy.regrant`'s `remaining_uses`): numeric-vs-numeric subtracts
/// (kept as an exact `i64` when both sides are int/bool-shaped, matching
/// Python's own `int - int -> int`); a `str` operand on either side raises
/// an uncaught `TypeError`, `state_corrupt` here (PORTING.md §3.5).
fn grant_num_sub(a: &GrantNum, b: &GrantNum) -> Result<Value, Error> {
    if a.is_non_numeric() || b.is_non_numeric() {
        return Err(Error::state("state_corrupt").with_detail("grant"));
    }
    // Exact integer subtraction (covers `Int`/`BigInt`/`Bool` in any
    // combination, including a `BigInt` beyond `i64` range) before falling
    // back to `f64` for a pair involving a genuine `Float` -- matching
    // Python's own `int - int -> int` vs. `float`-involved `-> float`.
    //
    // `checked_sub` (finding D-R7-1, the `i128` boundary): both operands
    // individually fit `i128` (`GrantNum::BigInt` is only ever constructed
    // for a magnitude that does, `GrantNum::from_value`), but their
    // difference can still overflow `i128` at its extreme edge (e.g. `x`
    // near `i128::MAX`, `y` near `i128::MIN`) where Python's
    // arbitrary-precision `int` never would. Nothing this crate or
    // `zeropw/policy.py` itself ever writes approaches `i128::MAX`
    // (~1.7e38) in the first place -- the same practical ceiling
    // `DEVIATIONS.md`'s `GrantNum::BigInt` row already documents for a
    // literal beyond even `i128` -- so failing closed here with the error
    // every caller of `grant_num_sub` already handles is the same "closest
    // handled error" choice as that row, not a new class of approximation.
    if let (Some(x), Some(y)) = (a.as_i128(), b.as_i128()) {
        return x
            .checked_sub(y)
            .map(i128_to_value)
            .ok_or_else(|| Error::state("state_corrupt").with_detail("grant"));
    }
    Ok(json!(
        a.as_f64().expect("checked numeric above") - b.as_f64().expect("checked numeric above")
    ))
}

/// An exact `i128` as a JSON number, preserving full precision via
/// `serde_json`'s `arbitrary_precision` feature (this crate's own writers
/// never produce a plain `i64`-fitting result here that this would render
/// any differently from `json!`).
fn i128_to_value(i: i128) -> Value {
    Value::Number(serde_json::Number::from(i))
}

/// Python's `max(diff, 0)` (`Policy::regrant`'s `remaining_uses`, finding
/// D-R7-3), keeping `diff`'s exact JSON shape (an integer-shaped literal of
/// any magnitude, or a genuine float) when it is already `>= 0` -- the only
/// case that ever reaches [`Policy::create_grant_exact`], since a result of
/// exactly `0` is checked (and rejected as `grant_exhausted`) separately,
/// immediately after, by [`grant_num_value_is_zero`]. `diff` is always
/// [`grant_num_sub`]'s own output here (an exact-integer `Value` or a
/// `json!(f64)`), so an exact sign check on its canonical form is enough --
/// no precision is at stake in a sign comparison against `0`.
fn grant_num_max_with_zero(diff: Value) -> Value {
    let is_negative = match &diff {
        Value::Number(n) if number_is_python_int(n) => n.to_string().starts_with('-'),
        Value::Number(n) => n.as_f64().is_some_and(|f| f < 0.0),
        _ => false,
    };
    if is_negative { json!(0) } else { diff }
}

/// `remaining_uses == 0` (`Policy::regrant`'s exhaustion check) for a value
/// already known to be `grant_num_sub`'s exact output (an integer-shaped
/// `Value` of any magnitude, or a `json!(f64)`): exact for both shapes (an
/// arbitrarily large integer literal is never `"0"`; a float compares to
/// `0.0` exactly, no precision loss possible right at zero).
fn grant_num_value_is_zero(v: &Value) -> bool {
    match v {
        Value::Number(n) if number_is_python_int(n) => n.to_string() == "0",
        Value::Number(n) => n.as_f64() == Some(0.0),
        _ => false,
    }
}

/// `grant.uses + 1` (`Policy::consume`'s use-counting): a `str` operand
/// raises an uncaught `TypeError`, `state_corrupt` here (PORTING.md §3.5).
///
/// **Round-7 fix (finding D-R7-1):** `Int(x) => x + 1` used to panic in
/// debug (`attempt to add with overflow`) and silently wrap to `i64::MIN`
/// in release (`Cargo.toml` has no `overflow-checks` override) once `x ==
/// i64::MAX`, where Python's arbitrary-precision `int` just keeps counting
/// -- measured: `consume` on a grant with `uses: 2**63-1` succeeds and
/// writes `"uses": 9223372036854775808`. Unlike the plain-`i64`
/// `policy_version`/`cycle` counters elsewhere in this module (which are
/// relied on as `i64` outside this file and so fail closed instead), this
/// value only ever flows back into `raw_uses`/the persisted document
/// (`Grant::to_value`, `Grant::from_value`) -- the same exact,
/// arbitrary-shaped storage `GrantNum::BigInt` already exists for -- so
/// widening the addition to `i128` reproduces Python's actual success
/// instead of substituting an error for it. `x` is always `i64`-range
/// (`GrantNum::Int`'s own invariant), so `x as i128 + 1` can never itself
/// overflow `i128`.
fn grant_num_add_one(a: &GrantNum) -> Result<Value, Error> {
    match a {
        GrantNum::Str(_) | GrantNum::Other(_) => {
            Err(Error::state("state_corrupt").with_detail("grant"))
        }
        GrantNum::Int(x) => Ok(i128_to_value(*x as i128 + 1)),
        // `x` is `i128`-range by construction (`GrantNum::BigInt` is only
        // ever built for a magnitude `as_i128`/the source literal fits),
        // but `x + 1` can still overflow `i128` at its extreme edge (`x ==
        // i128::MAX`) -- see `grant_num_sub`'s matching comment for why
        // `checked_add` failing closed there is the right "closest handled
        // error" choice rather than a new approximation.
        GrantNum::BigInt(x) => x
            .checked_add(1)
            .map(i128_to_value)
            .ok_or_else(|| Error::state("state_corrupt").with_detail("grant")),
        // `bool` is `0`/`1`; `+ 1` is `1`/`2` and can never overflow `i64`.
        GrantNum::Bool(x) => Ok(json!(i64::from(*x) + 1)),
        // Float arithmetic saturates to `f64::INFINITY` rather than
        // panicking or wrapping, so there is no overflow hazard here --
        // matching Python's own IEEE-754 `float + float`.
        GrantNum::Float(f) => Ok(json!(f + 1.0)),
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Grant {
    pub id: String,
    pub principal: String,
    pub connection: String,
    pub policy_version: i64,
    pub expires_at: Option<f64>,
    pub max_uses: Option<i64>,
    pub uses: i64,
    /// `"active"`, `"stale"` or `"revoked"`.
    pub status: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
    /// The vault version the connection resolved to when last evaluated.
    pub credential_version: Option<i64>,
    // The four fields above stay plain `i64`/`Option<i64>` -- this
    // struct's public shape is relied on outside this file (gateway,
    // signer, vault/context, and their tests, none of which are this
    // round's files to edit) -- but Python applies **no** conversion to
    // them at all, so a stored non-numeric-shaped value (most notably a
    // numeric *string*, finding D-R5-2) cannot be reproduced by an `i64`
    // alone: the public fields above hold a best-effort numeric reading
    // (via [`python_int_coerce`], unchanged from round 4, so every
    // existing caller's behaviour for a normally-shaped grant -- the only
    // shape any writer in this crate or `zeropw/policy.py` ever produces
    // -- is byte-for-byte identical to before this fix) for display/
    // embedding use (`to_value` round-tripping, `HandleIssuer::issue`,
    // ...), while the raw fields below carry the *exact* JSON shape Python
    // itself kept, used only by this module's own authorization decisions
    // ([`Policy::grant_state`], `Grant::public_view`, `Policy::consume`'s
    // use-counting, `Policy::regrant`'s remaining-uses calculation) so
    // those match Python's real outcome for a corrupted/hand-edited grant
    // exactly (`policy_version: "1"` is always `grant_stale`; two stored
    // strings for `max_uses`/`uses` compare lexicographically, not
    // numerically) instead of silently authorizing (or wrongly denying)
    // through a lossy `i64` coercion.
    raw_policy_version: GrantNum,
    raw_max_uses: Option<GrantNum>,
    raw_uses: GrantNum,
    raw_credential_version: Option<GrantNum>,
    // `status`/`revoked_at`/`expires_at` above are likewise best-effort
    // (`String`/`Option<String>`/`Option<f64>`, `state_corrupt`-on-load-
    // failure would be wrong the same way it was for the four `GrantNum`
    // fields): Python's `Grant` dataclass applies **no** `int()`/
    // `isinstance` conversion to any of these three either (differential-
    // harness finding, round 6). `raw_status`/`raw_revoked_at` carry the
    // exact JSON value Python's dataclass kept (`Value::Null` when the
    // field is absent-with-default/explicit `null`); `raw_expires_at` is
    // `None` for Python `None` (no dataclass default, so a *missing* key
    // is still a hard load-time error, matching `TypeError`) and
    // `Some(value)` for every other JSON shape, since `expires_at`'s two
    // real Python call sites (`_grant_state`'s `is not None` guard,
    // `public_view`'s truthiness guard) tell `None` apart from every other
    // value differently from one another (see `Policy::grant_state`/
    // `Grant::public_view`).
    raw_status: Value,
    raw_revoked_at: Value,
    raw_expires_at: Option<Value>,
}

/// Python's `==`/`!=` against a string literal for a value of any JSON
/// shape: `True` only when `v` is itself a JSON string equal to `s`, `False`
/// for every other shape (never raises -- `==` across mismatched types is
/// always just unequal in Python).
fn value_eq_str(v: &Value, s: &str) -> bool {
    matches!(v, Value::String(x) if x == s)
}

/// `x if x is not None else None`-style numeric read for a raw JSON value:
/// `Some(f64)` for `bool`/any-magnitude `int`/`float` (Python's numeric
/// tower), `None` for anything else (a value ordering/arithmetic can't
/// touch without Python raising an uncaught `TypeError`). An integer-shaped
/// literal outside `f64`'s 53-bit exact range is approximated here.
///
/// **Round-7 correction (finding D-R7-3):** this function's previous doc
/// comment justified that approximation by pointing at the harness's
/// `expires_at`-`huge_int` named exception -- that was wrong, and measured
/// wrong: that exception covers `iso()` *raising* on an out-of-range
/// timestamp (`DEVIATIONS.md`'s `store (iso)` row), not this function's
/// precision loss. `python3.12` confirms the two are unrelated: `iso(2**53
/// + 1)` returns `"285428751-11-12T07:36:33Z"`, one second after `iso(2**53)`
/// -- no exception either way. Callers that need exactness above 2**53 (the
/// [`Grant::public_view`] `expires_at` field, and `_grant_state`'s expiry
/// comparison) now use [`iso_for_raw_value`] / [`now_at_least_exact`]
/// instead of this function; this one remains for the cases that are
/// genuinely fine to approximate (a real `Float`, or a magnitude beyond even
/// `i128`, which nothing this crate or `zeropw/policy.py` itself ever
///   writes).
fn numeric_value_as_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Value::Number(n) => n.as_f64(),
        _ => None,
    }
}

/// Exact seconds-to-civil-date formatting for an integer number of seconds
/// (any magnitude that fits `i128`), matching `store::iso`'s
/// `%Y-%m-%dT%H:%M:%SZ` output exactly for every timestamp `store::iso`
/// itself can represent, and extending it (finding D-R7-3) to magnitudes
/// beyond `f64`'s 53-bit exact-integer range, where converting through
/// `f64` first (as `numeric_value_as_f64` does) rounds and can render the
/// wrong second.
///
/// This duplicates `store::civil_from_unix`'s Howard Hinnant
/// `civil_from_days` algorithm (public domain), widened from `i64` to
/// `i128`, because that function is private to `store.rs`, which this work
/// unit may not edit (`PORTING.md`'s per-work-unit file list). Pinned
/// byte-identical against `store::iso` for every timestamp that fits `f64`
/// exactly, and against real `python3.12` `time.strftime`/`time.gmtime`
/// beyond it, by
/// `policy_exact_iso_seconds_matches_store_iso_within_f64_range` and
/// `policy_exact_iso_seconds_matches_python_beyond_f64_precision`.
fn exact_iso_seconds(secs: i128) -> String {
    let mut days = secs.div_euclid(86400);
    let mut rem = secs.rem_euclid(86400);
    let h = (rem / 3600) as u32;
    rem -= (h as i128) * 3600;
    let mi = (rem / 60) as u32;
    let s = (rem - (mi as i128) * 60) as u32;

    days += 719_468; // shift epoch from 1970-01-01 to 0000-03-01
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let doe = days - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// `iso()` for a raw JSON value already known to be Python-truthy
/// (`Grant::public_view`'s `iso(self.expires_at) if self.expires_at else
/// None`, finding D-R7-3): an integer-shaped literal is formatted exactly
/// via [`exact_iso_seconds`] (`time.gmtime` floors a fractional timestamp
/// to whole seconds, and an already-integer value has nothing to floor),
/// bypassing the precision loss `numeric_value_as_f64` would incur above
/// 2**53; a genuine float, or an integer literal too large even for
/// `i128` (nothing this crate or `zeropw/policy.py` itself ever writes),
/// falls back to the existing `f64` path through `store::iso`. `None`
/// only for a non-numeric truthy value (`iso()`'s own uncaught
/// `TypeError` in Python, PORTING.md §3.5, handled by the caller).
fn iso_for_raw_value(v: &Value) -> Option<String> {
    if let Value::Number(n) = v
        && number_is_python_int(n)
        && let Ok(secs) = n.to_string().parse::<i128>()
    {
        return Some(exact_iso_seconds(secs));
    }
    numeric_value_as_f64(v).map(|f| iso(Some(f)))
}

/// `self.clock() >= grant.expires_at` (`_grant_state`'s expiry check,
/// finding D-R7-3): CPython's mixed int/float rich comparison
/// (`float.__ge__` against an `int`) is exact -- it never rounds the `int`
/// through `f64` the way arithmetic (`-`/`+`) does, unlike
/// `numeric_value_as_f64`'s cast. For an integer-shaped `exp`, `now >= exp`
/// (as real numbers) is exactly `floor(now) >= exp`: for any real `x` and
/// integer `n`, `x >= n` iff `floor(x) >= n` (if `floor(x) >= n` then `x >=
/// floor(x) >= n`; if `floor(x) < n` then `floor(x) <= n - 1`, so `x <
/// floor(x) + 1 <= n`). `now` is always a small, ordinary wall-clock
/// reading, so `now.floor()` fits `i128` exactly with nothing to lose on
/// that side. Anything else (a genuine float `exp`, or an integer literal
/// beyond `i128`) falls back to the existing `f64` comparison. `None` only
/// for a non-numeric `exp` (the caller's existing `state_corrupt`).
fn now_at_least_exact(now: f64, exp: &Value) -> Option<bool> {
    if let Value::Number(n) = exp
        && number_is_python_int(n)
        && let Ok(exp_i128) = n.to_string().parse::<i128>()
    {
        return Some(now.floor() as i128 >= exp_i128);
    }
    numeric_value_as_f64(exp).map(|f| now >= f)
}

impl Grant {
    /// Python `==`/`!=` for `self.status` against a literal: see
    /// [`value_eq_str`].
    fn status_is(&self, s: &str) -> bool {
        value_eq_str(&self.raw_status, s)
    }

    pub fn public_view(&self) -> Result<Value, Error> {
        let remaining_uses = match &self.raw_max_uses {
            Some(m) => grant_num_sub(m, &self.raw_uses)?,
            None => Value::Null,
        };
        // `iso(self.expires_at) if self.expires_at else None`: Python
        // truthiness of *any* JSON shape (falsy: `None`, `0`/`0.0`, `False`,
        // `""`, `[]`, `{}`) skips `iso()` entirely and yields `None`; a
        // truthy value reaches `iso()`, which requires a real number
        // (`bool`/`int`/`float`) -- a truthy non-numeric value (a non-empty
        // string, `True` is numeric so it's fine, a non-empty list/object)
        // raises `iso()`'s own uncaught `TypeError`, the closest handled
        // error here (PORTING.md §3.5).
        let expires_at = match &self.raw_expires_at {
            Some(v) if json_truthy(Some(v)) => match iso_for_raw_value(v) {
                Some(s) => Value::String(s),
                None => return Err(Error::state("state_corrupt").with_detail("grant")),
            },
            _ => Value::Null,
        };
        Ok(json!({
            "id": self.id, "connection": self.connection, "status": self.raw_status,
            "expires_at": expires_at,
            "remaining_uses": remaining_uses,
        }))
    }

    /// Serializes the *raw* forms (finding D-R5-2, extended round 6 to
    /// `status`/`revoked_at`/`expires_at`), not the best-effort public
    /// fields, so a grant that round-trips through this (currently only
    /// fresh grants from `create_grant`, always plain well-typed values
    /// either way) keeps the exact JSON shape it was loaded with.
    fn to_value(&self) -> Value {
        json!({
            "id": self.id, "principal": self.principal, "connection": self.connection,
            "policy_version": self.raw_policy_version.to_value(),
            "expires_at": self.raw_expires_at.clone().unwrap_or(Value::Null),
            "max_uses": self.raw_max_uses.as_ref().map(GrantNum::to_value),
            "uses": self.raw_uses.to_value(), "status": self.raw_status,
            "created_at": self.created_at, "revoked_at": self.raw_revoked_at,
            "credential_version": self.raw_credential_version.as_ref().map(GrantNum::to_value),
        })
    }

    /// `Grant(**entry)` in `get_grant`/`list_grants`/`revoke_grant`/`consume`.
    /// An unrecognised key in `entry` makes the `**entry` unpacking add an
    /// unexpected keyword argument, an uncaught `TypeError` -- the same
    /// `**value`-unpacking shape `HttpTarget::from_value`/`HttpAuth::from_value`
    /// already reject (finding D-R2-6), extended here to `Grant` (finding
    /// D-R3-7).
    ///
    /// `expires_at`/`max_uses` have **no** dataclass default in Python
    /// (unlike `revoked_at`/`credential_version`, which do) -- an absent key
    /// makes `Grant(**entry)` raise `TypeError: missing 1 required
    /// positional argument`, the same as a missing `uses`. A present `null`
    /// is a genuine value for these two `T | None` fields, not an absence,
    /// so it still loads as `None` (finding D-R4-4: the previous `None |
    /// Some(Value::Null) => None` conflated "absent" with "present and
    /// null", silently loading an unlimited grant where Python fails
    /// closed).
    ///
    /// `policy_version`/`max_uses`/`uses`/`credential_version` are read
    /// here with no `int()`/`isinstance` conversion at all in Python -- see
    /// [`GrantNum`]'s own doc comment (finding D-R5-2, correcting round 4's
    /// D-R4-7 fix, which coerced a numeric string here to an `i64` and
    /// flipped real authorization outcomes). Any other JSON shape (`null`,
    /// an array, an object) is still not one of `int`/`float`/`bool`/`str`
    /// -- Python would still hit an uncaught `TypeError`/`ValueError` at
    /// whatever operation first touches it -- `state_corrupt` at load time,
    /// PORTING.md §3.5.
    ///
    /// Each of these four fields is stored twice: once as a best-effort
    /// `i64`/`Option<i64>` via [`python_int_coerce`] (the struct's public
    /// fields, unchanged from round 4 for a normally-shaped grant -- every
    /// existing caller outside this module, and every grant this crate or
    /// `zeropw/policy.py` itself ever writes, sees the exact same value as
    /// before), and once as the exact [`GrantNum`] shape Python kept (the
    /// private `raw_*` fields), which is what this module's own
    /// authorization decisions (`grant_state`, `public_view`, `consume`,
    /// `regrant`) actually compare against.
    fn from_value(v: &Value) -> Result<Self, Error> {
        let bad = || Error::state("state_corrupt").with_detail("grant");
        let obj = v.as_object().ok_or_else(bad)?;
        const KNOWN_KEYS: &[&str] = &[
            "id",
            "principal",
            "connection",
            "policy_version",
            "expires_at",
            "max_uses",
            "uses",
            "status",
            "created_at",
            "revoked_at",
            "credential_version",
        ];
        if obj.keys().any(|k| !KNOWN_KEYS.contains(&k.as_str())) {
            return Err(bad());
        }
        let str_field = |key: &str| -> Result<String, Error> {
            obj.get(key)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(bad)
        };
        // The public `i64` field is a *best-effort* reading (see the
        // struct's own doc comment): it must never be the reason the whole
        // grant fails to load, since Python's dataclass never validates
        // these four fields at all. Round 5's differential harness found
        // the previous `.ok_or_else(bad)?` here defeated that intent for
        // any value `python_int_coerce` doesn't accept (`null`, an array,
        // an object, a non-numeric string, an out-of-`i64` integer/huge
        // magnitude) -- exactly the shapes Python tolerates unconditionally
        // -- aborting the entire `Grant::from_value` where Python succeeds.
        // `0` is an arbitrary, safe placeholder; only `raw_field`'s
        // [`GrantNum`] (which never fails to represent a JSON value, see
        // `GrantNum::Other`) drives this module's own authorization
        // decisions.
        let int_field =
            |key: &str| -> i64 { obj.get(key).and_then(python_int_coerce).unwrap_or(0) };
        // Presence is still required for `policy_version`/`uses` (no
        // dataclass default in Python -- a missing key is an uncaught
        // `TypeError`); `GrantNum::from_value` itself never fails once the
        // key is known present.
        let raw_field = |key: &str| -> Result<GrantNum, Error> {
            obj.get(key).map(GrantNum::from_value).ok_or_else(bad)
        };
        // `expires_at` has **no** dataclass default in Python (a missing
        // key is still an uncaught `TypeError`, unchanged from before), but
        // once the key is present, Python applies no `int()`/`isinstance`
        // check to its value at all -- any JSON shape loads (differential-
        // harness finding, round 6, the same pattern as the four `GrantNum`
        // fields above). `raw_expires_at` keeps the exact shape (`None` only
        // for an explicit `null`, i.e. Python `None`); the best-effort
        // public `f64` field is `None` whenever the raw value isn't
        // numeric, never the reason the whole grant fails to load.
        let expires_at_value = obj.get("expires_at").cloned().ok_or_else(bad)?;
        let raw_expires_at = match &expires_at_value {
            Value::Null => None,
            other => Some(other.clone()),
        };
        let expires_at = raw_expires_at.as_ref().and_then(numeric_value_as_f64);
        let max_uses_value = match obj.get("max_uses") {
            None => return Err(bad()),
            Some(Value::Null) => None,
            Some(v) => Some(v),
        };
        let max_uses = max_uses_value.map(|v| python_int_coerce(v).unwrap_or(0));
        let raw_max_uses = max_uses_value.map(GrantNum::from_value);
        let credential_version_value = match obj.get("credential_version") {
            None | Some(Value::Null) => None,
            Some(v) => Some(v),
        };
        let credential_version =
            credential_version_value.map(|v| python_int_coerce(v).unwrap_or(0));
        let raw_credential_version = credential_version_value.map(GrantNum::from_value);
        // `status: str` has **no** dataclass default either -- a missing
        // key is still a hard load-time error -- but a present non-string
        // value is never validated by Python (round 6): kept exactly in
        // `raw_status`, with the best-effort public `String` field falling
        // back to `""` (never read for a corrupted grant; every real
        // decision goes through `raw_status`/[`Grant::status_is`]).
        let raw_status = obj.get("status").cloned().ok_or_else(bad)?;
        let status = raw_status.as_str().map(str::to_string).unwrap_or_default();
        // `revoked_at: str | None = None` -- an *absent* key falls back to
        // the dataclass default (`None`), matching the existing behaviour;
        // a present non-string, non-null value is (round 6) no longer a
        // load-time error, kept exactly in `raw_revoked_at`.
        let raw_revoked_at = obj.get("revoked_at").cloned().unwrap_or(Value::Null);
        let revoked_at = match &raw_revoked_at {
            Value::String(s) => Some(s.clone()),
            _ => None,
        };
        Ok(Grant {
            id: str_field("id")?,
            principal: str_field("principal")?,
            connection: str_field("connection")?,
            policy_version: int_field("policy_version"),
            expires_at,
            max_uses,
            uses: int_field("uses"),
            status,
            created_at: str_field("created_at")?,
            revoked_at,
            credential_version,
            raw_policy_version: raw_field("policy_version")?,
            raw_max_uses,
            raw_uses: raw_field("uses")?,
            raw_credential_version,
            raw_status,
            raw_revoked_at,
            raw_expires_at,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Action {
    /// `"http"` or `"ssh"`.
    pub kind: String,
    pub method: Option<String>,
    pub path: Option<String>,
    pub username: Option<String>,
}

impl Action {
    pub fn http(method: impl Into<String>, path: impl Into<String>) -> Self {
        Action {
            kind: "http".into(),
            method: Some(method.into()),
            path: Some(path.into()),
            username: None,
        }
    }
    pub fn ssh(username: impl Into<String>) -> Self {
        Action {
            kind: "ssh".into(),
            method: None,
            path: None,
            username: Some(username.into()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Decision {
    pub allowed: bool,
    pub reason: &'static str,
    pub grant: Option<Grant>,
    pub connection: Option<Connection>,
}

impl Decision {
    fn new(
        allowed: bool,
        reason: &'static str,
        grant: Option<Grant>,
        connection: Option<Connection>,
    ) -> Self {
        Decision {
            allowed,
            reason,
            grant,
            connection,
        }
    }
    fn denied(reason: &'static str) -> Self {
        Decision::new(false, reason, None, None)
    }
    fn denied_with_connection(reason: &'static str, connection: Connection) -> Self {
        Decision::new(false, reason, None, Some(connection))
    }

    pub fn policy_version(&self) -> Option<i64> {
        self.connection.as_ref().map(|c| c.policy_version)
    }

    pub fn require(self) -> Result<Decision, Error> {
        if !self.allowed {
            return Err(Error::policy_denied(self.reason));
        }
        Ok(self)
    }
}

/// `policy.hash_token`.
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// `policy.approval_digest`.
pub fn approval_digest(
    caller: &str,
    connection: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> String {
    let body_digest = hex::encode(Sha256::digest(body));
    let canonical = [
        "zeropw-approval-v1",
        caller,
        connection,
        method,
        path,
        &body_digest,
    ]
    .join("\n");
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

/// Every revocation known from the revocation ledger and the audit log
/// (monotone: never undone).
#[derive(Default, Debug, Clone)]
pub struct Revocations {
    pub grants: HashSet<String>,
    pub principals: HashSet<String>,
    pub connections: HashSet<String>,
    pub secret_versions: HashSet<(String, i64)>,
}

/// Append one line to the revocation ledger (outside the backup set).
///
/// Best effort by design: a revocation is never blocked because this line
/// could not be written; the audit log is replayed as a second source.
pub fn append_revocation(state: &StateDir, kind: &str, fields: Map<String, Value>) {
    let mut entry = Map::new();
    entry.insert("kind".into(), json!(kind));
    entry.insert("ts".into(), json!(iso(None)));
    for (k, v) in fields {
        entry.insert(k, v);
    }
    if let Ok(line) = pyjson::dumps(&Value::Object(entry), DumpOptions::compact_sorted()) {
        let _ = state.append_line(REVOCATIONS, &line);
    }
}

/// Reads the revocation ledger plus revocation events from the audit log.
///
/// Ledger lines are processed in order because the core API can re-enable a
/// connection; for the ledger only a connection whose last event is a
/// disable counts. Audit events are the administrator CLI's records
/// (`grant_revoke`, `grant_regrant`, `principal_disable`,
/// `connection_disable`, `secret_revoke`); they cover states written before
/// the ledger existed and always count (the CLI has no re-enable).
/// Identifiers are not reused by design: a principal or connection id that
/// was disabled stays disabled across restores, so a re-created one needs a
/// new id.
pub fn collect_revocations<'a>(
    state: &StateDir,
    audit_records: impl IntoIterator<Item = &'a Value>,
) -> Revocations {
    let mut found = Revocations::default();
    let lines = state.read_lines(REVOCATIONS, None).unwrap_or_default();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(entry) = pyjson::loads(&line) else {
            continue;
        };
        let Some(obj) = entry.as_object() else {
            continue;
        };
        let kind = obj.get("kind").and_then(Value::as_str);
        let id = obj.get("id").and_then(Value::as_str);
        match kind {
            Some("grant") => {
                if let Some(id) = id {
                    found.grants.insert(id.to_string());
                }
            }
            Some("principal") => {
                if let Some(id) = id {
                    found.principals.insert(id.to_string());
                }
            }
            Some("connection") => {
                if let Some(id) = id {
                    found.connections.insert(id.to_string());
                }
            }
            Some("connection_enable") => {
                if let Some(id) = id {
                    found.connections.remove(id);
                }
            }
            Some("secret_version") => {
                let secret_id = obj.get("secret_id").and_then(Value::as_str);
                let version = obj.get("version").and_then(json_isinstance_int);
                if let (Some(secret_id), Some(version)) = (secret_id, version) {
                    found
                        .secret_versions
                        .insert((secret_id.to_string(), version));
                }
            }
            _ => {}
        }
    }
    for record in audit_records {
        let Some(obj) = record.as_object() else {
            continue;
        };
        if obj.get("result").and_then(Value::as_str) != Some("ok") {
            continue;
        }
        match obj.get("event").and_then(Value::as_str) {
            Some("grant_revoke") => {
                if let Some(id) = obj.get("grant").and_then(Value::as_str) {
                    found.grants.insert(id.to_string());
                }
            }
            Some("grant_regrant") => {
                // The replaced (old) grant id.
                if let Some(id) = obj.get("detail").and_then(Value::as_str) {
                    found.grants.insert(id.to_string());
                }
            }
            Some("principal_disable") => {
                if let Some(id) = obj.get("principal").and_then(Value::as_str) {
                    found.principals.insert(id.to_string());
                }
            }
            Some("connection_disable") => {
                if let Some(id) = obj.get("connection").and_then(Value::as_str) {
                    found.connections.insert(id.to_string());
                }
            }
            Some("secret_revoke") => {
                let secret_id = obj.get("secret_id").and_then(Value::as_str);
                let version = obj.get("version").and_then(json_isinstance_int);
                if let (Some(secret_id), Some(version)) = (secret_id, version) {
                    found
                        .secret_versions
                        .insert((secret_id.to_string(), version));
                }
            }
            _ => {}
        }
    }
    found
}

fn as_obj(v: &Value) -> Result<&Map<String, Value>, Error> {
    v.as_object()
        .ok_or_else(|| Error::state("state_corrupt").with_detail("policy_document"))
}

/// `raw != resolved` where `raw` is a *stored* JSON value compared against a
/// resolved Rust `i64` (`g.get("credential_version") != resolved` in
/// `credential_versions_changed`, `entry.get("policy_version") !=
/// connection.policy_version` in `_approval_mismatch`): Python compares
/// using ordinary numeric equality across types -- a stored float (`2.0`)
/// or bool (`True`/`False`, via `int(bool)`) compares equal to an
/// equal-valued int, so nothing changes. `Value::as_i64` alone would treat
/// a float-shaped number (even one with no fractional part) as a mismatch,
/// silently bumping the connection's policy version / reporting a spurious
/// `policy_changed` for no real change (finding D-R3-9). Any non-numeric
/// stored value (a string, array, object, `null`) never compares equal to
/// an int in Python either.
///
/// The `n.as_i64() == Some(resolved) || n.as_f64() == Some(resolved as
/// f64)` form previously used here compared *both* sides through the `||`,
/// so even when the exact `as_i64` comparison already correctly found two
/// distinct integers unequal, the `f64` fallback still ran and could
/// report them equal anyway: two distinct `i64`s whose magnitude exceeds
/// 2**53 (`9007199254740993` and `9007199254740992`, say) both round to
/// the *same* `f64`, so the fallback alone would call them equal (finding
/// D-R5-7) -- silently missing a real credential-version change (no policy
/// version bump, so a handle for the old credential keeps working) or a
/// real approval `policy_version` change (an approval that should have
/// been invalidated stays open). Fixed by using the `f64` path only for a
/// stored value that is *genuinely* float-shaped in the JSON source
/// (`number_is_python_int` false, i.e. it has a `.`/`e`/`E`); an
/// integer-shaped literal is compared exactly via `as_i64`, and one
/// outside `i64` range (`as_i64` is `None`) is correctly unequal to any
/// representable `resolved`.
fn python_numeric_eq(stored: Option<&Value>, resolved: i64) -> bool {
    match stored {
        Some(Value::Bool(b)) => i64::from(*b) == resolved,
        Some(Value::Number(n)) => {
            if number_is_python_int(n) {
                n.as_i64() == Some(resolved)
            } else {
                n.as_f64() == Some(resolved as f64)
            }
        }
        _ => false,
    }
}

/// Same cross-type numeric equality as [`python_numeric_eq`], but for a
/// `resolved` value that may itself be an integer-shaped literal beyond
/// `i64` range (`credential_versions_changed`'s `resolved_credential_version`,
/// round 6, once a vault secret's `active_version` is kept exact rather
/// than collapsing to `None` past `i64`): two integer-shaped values of any
/// magnitude compare exactly via their canonical decimal digits (a valid
/// JSON integer literal has no leading zero or `+` sign, so its source text
/// already canonically identifies the value -- no need to parse into a
/// fixed-width integer type at all); a pair involving a genuinely
/// float-shaped value falls back to `f64`, same as `python_numeric_eq`.
fn python_numeric_eq_value(stored: Option<&Value>, resolved: &Value) -> bool {
    fn canonical_int(v: &Value) -> Option<String> {
        match v {
            Value::Bool(b) => Some(if *b { "1" } else { "0" }.to_string()),
            Value::Number(n) if number_is_python_int(n) => Some(n.to_string()),
            _ => None,
        }
    }
    fn numeric_f64(v: &Value) -> Option<f64> {
        match v {
            Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            Value::Number(n) => n.as_f64(),
            _ => None,
        }
    }
    let Some(stored) = stored else { return false };
    if let (Some(a), Some(b)) = (canonical_int(stored), canonical_int(resolved)) {
        return a == b;
    }
    matches!((numeric_f64(stored), numeric_f64(resolved)), (Some(a), Some(b)) if a == b)
}

/// `x in <a set of strings>` for a raw stored value of any JSON shape
/// (`credential_versions_changed`'s `e.get("connection") in ids`,
/// `reapply_revocations`'s equivalent three-way check against
/// `revocations.{grants,principals,connections}`): every hashable Python
/// value (`None`, a `bool`, a number, a string) can be tested against a
/// `set[str]` without raising -- only a string can actually be a member, so
/// anything else just isn't `in` it -- but a list or a dict is unhashable,
/// an uncaught `TypeError` in Python (`_invalidate_approvals` catches
/// nothing), the closest handled error here (PORTING.md §3.5). Verified
/// against `python3.12` by `rust/tests/policy_oracle.rs` and exercised by
/// `rust/tests/policy_differential.rs`'s mutation matrix.
fn value_in_str_set(v: Option<&Value>, set: &HashSet<String>) -> Result<bool, Error> {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(_)) | Some(Value::Number(_)) => Ok(false),
        Some(Value::String(s)) => Ok(set.contains(s)),
        Some(Value::Array(_)) | Some(Value::Object(_)) => {
            Err(Error::state("state_corrupt").with_detail(CONTROL))
        }
    }
}

/// What an allowed `evaluate` decided, remembered per thread for the
/// matching `consume`. Port of `policy._Evaluated`.
#[derive(Clone, Debug)]
struct Evaluated {
    caller: String,
    connection: String,
    grant: String,
    action: Action,
    policy_version: i64,
}

/// One thread's remembered evaluations for one [`Policy`] instance. Mirrors
/// a Python `dict[str, _Evaluated]` used as an ordered map: `remember`
/// moves a re-inserted key to the end (like `dict.pop` + reassignment), and
/// hitting [`EVALUATED_MEMO_LIMIT`] wipes the whole memo before inserting
/// the new entry (not a real LRU -- this is what Python's `_remember` does).
#[derive(Default)]
struct EvaluatedMemo {
    entries: Vec<(String, Evaluated)>,
}

impl EvaluatedMemo {
    fn remember(&mut self, grant_id: String, ev: Evaluated) {
        if self.entries.len() >= EVALUATED_MEMO_LIMIT {
            self.entries.clear();
        }
        self.entries.retain(|(k, _)| k != &grant_id);
        self.entries.push((grant_id, ev));
    }
    /// Port of `Policy._recall(grant_id, pop=False)`; unused in this half
    /// too (Python's own `_recall` is only ever called with `pop=True`, in
    /// `consume`), kept for API parity with the Python method.
    #[allow(dead_code)]
    fn get(&self, grant_id: &str) -> Option<&Evaluated> {
        self.entries
            .iter()
            .find(|(k, _)| k == grant_id)
            .map(|(_, v)| v)
    }
    fn pop(&mut self, grant_id: &str) -> Option<Evaluated> {
        let pos = self.entries.iter().position(|(k, _)| k == grant_id)?;
        Some(self.entries.remove(pos).1)
    }
    /// `reversed(list(memo.values()))`, first match.
    fn pair(&self, caller: &str, connection: &str) -> Option<&Evaluated> {
        self.entries
            .iter()
            .rev()
            .map(|(_, v)| v)
            .find(|e| e.caller == caller && e.connection == connection)
    }
}

/// One `Policy::on_revoke` listener.
type RevokeListener = Arc<dyn Fn(&str, Option<&str>) + Send + Sync>;

/// Port of `policy.Policy`.
///
/// Python gives every `Policy()` instance its own `threading.local()`; a
/// second `Policy` on the same [`StateDir`] (as the admin CLI and this
/// crate's tests' `other_process()` helper construct) has an independently
/// empty memo even on the same thread. [`Policy::evaluated`] reproduces that
/// per-instance-per-thread scoping with a `Mutex<HashMap<ThreadId, _>>`
/// instead of true TLS (which in Rust is scoped per *type*, not per value).
pub struct Policy<'a> {
    state: &'a StateDir,
    clock: Clock,
    revoke_listeners: Mutex<Vec<RevokeListener>>,
    evaluated: Mutex<HashMap<ThreadId, EvaluatedMemo>>,
}

impl<'a> Policy<'a> {
    pub fn new(state: &'a StateDir, clock: Clock) -> Self {
        Policy {
            state,
            clock,
            revoke_listeners: Mutex::new(Vec::new()),
            evaluated: Mutex::new(HashMap::new()),
        }
    }

    fn now(&self) -> f64 {
        (self.clock)()
    }

    // ------------------------------------------------------- persistence
    /// `self.state.read_json(name, {}) or {}`: same falsy/truthy split as
    /// `control()` below (finding D-R3-1). Python's `or` only falls back to
    /// `{}` for a *falsy* read (missing file -> the `{}` default itself, or a
    /// stored falsy value: `{}`, `[]`, `null`, `0`, `""`, `false`); a
    /// *truthy* non-dict read (`[1]`, `"x"`, `5`, ...) is returned as-is, and
    /// every caller's subsequent `.get`/`in`/`[...]` raises an uncaught
    /// `TypeError`/`AttributeError` -- fail closed (PORTING.md §3.5) instead
    /// of the empty map every caller here already propagates with `?`.
    fn read_doc(&self, name: &str) -> Result<Map<String, Value>, Error> {
        let value = self.state.read_json(name, json!({}))?;
        Self::shape_doc(value, name)
    }

    /// The `json_truthy`/object-shape half of [`Policy::read_doc`], split
    /// out so a caller that needs Python's own laziness precisely (finding
    /// D-R7-2: [`Policy::reapply_revocations`], whose `self._grants()`
    /// call -- and thus any *parse* failure inside `read_json` -- runs
    /// unconditionally in Python, while the shape check only bites once a
    /// caller actually calls `.get()` on the result) can perform the raw
    /// `state.read_json` unconditionally and defer only this shape check
    /// to the point Python's own laziness would reach it.
    fn shape_doc(value: Value, name: &str) -> Result<Map<String, Value>, Error> {
        if !json_truthy(Some(&value)) {
            return Ok(Map::new());
        }
        match value {
            Value::Object(m) => Ok(m),
            _ => Err(Error::state("state_corrupt").with_detail(name)),
        }
    }
    fn principals(&self) -> Result<Map<String, Value>, Error> {
        self.read_doc(PRINCIPALS)
    }
    fn connections(&self) -> Result<Map<String, Value>, Error> {
        self.read_doc(CONNECTIONS)
    }
    fn grants(&self) -> Result<Map<String, Value>, Error> {
        self.read_doc(GRANTS)
    }
    /// `self.state.read_json(CONTROL, None) or {...defaults...}`: Python's
    /// `or` falls back to the default dict for *any* falsy read (missing
    /// file -> `None`, or a stored `{}`), not just a missing file. A
    /// *truthy* non-dict read (`[1]`, `"x"`, `5`) is returned as-is by
    /// Python's `or`, and every caller's subsequent `control.get(...)` then
    /// raises an uncaught `AttributeError` -- fail closed (PORTING.md §3.5,
    /// finding D-R2-1): the closest handled error every caller of
    /// `control()` (`decide`, `is_stopped`, `restore_pending`,
    /// `usable_connections`, ...) already propagates with `?`.
    fn control(&self) -> Result<Map<String, Value>, Error> {
        let value = self.state.read_json(CONTROL, Value::Null)?;
        if !json_truthy(Some(&value)) {
            return Ok(default_control());
        }
        match value {
            Value::Object(m) => Ok(m),
            _ => Err(Error::state("state_corrupt").with_detail(CONTROL)),
        }
    }

    pub fn on_revoke(&self, listener: impl Fn(&str, Option<&str>) + Send + Sync + 'static) {
        self.revoke_listeners
            .lock()
            .unwrap()
            .push(Arc::new(listener));
    }

    fn notify_revoke(&self, kind: &str, grant_id: Option<&str>) {
        let snapshot: Vec<_> = self.revoke_listeners.lock().unwrap().clone();
        for listener in snapshot {
            listener(kind, grant_id);
        }
    }

    // ------------------------------------- per-thread evaluated-grant memo
    fn remember(&self, caller: &str, action: &Action, decision: &Decision) {
        if !decision.allowed {
            return;
        }
        let (Some(grant), Some(connection)) = (&decision.grant, &decision.connection) else {
            return;
        };
        let tid = thread::current().id();
        let mut map = self.evaluated.lock().unwrap();
        map.entry(tid).or_default().remember(
            grant.id.clone(),
            Evaluated {
                caller: caller.to_string(),
                connection: connection.id.clone(),
                grant: grant.id.clone(),
                action: action.clone(),
                policy_version: connection.policy_version,
            },
        );
    }
    /// Port of `Policy._recall(grant_id, pop=False)`; see the note on
    /// `EvaluatedMemo::get`.
    #[allow(dead_code)]
    fn recall(&self, grant_id: &str) -> Option<Evaluated> {
        let tid = thread::current().id();
        self.evaluated
            .lock()
            .unwrap()
            .get(&tid)
            .and_then(|m| m.get(grant_id))
            .cloned()
    }
    fn recall_pop(&self, grant_id: &str) -> Option<Evaluated> {
        let tid = thread::current().id();
        self.evaluated
            .lock()
            .unwrap()
            .get_mut(&tid)
            .and_then(|m| m.pop(grant_id))
    }
    fn recall_pair(&self, caller: &str, connection_id: &str) -> Option<Evaluated> {
        let tid = thread::current().id();
        self.evaluated
            .lock()
            .unwrap()
            .get(&tid)
            .and_then(|m| m.pair(caller, connection_id))
            .cloned()
    }

    // ------------------------------------------------- credential version
    /// `doc = self.state.read_json(VAULT_SECRETS, None); return doc if
    /// isinstance(doc, dict) else {}`. An unparseable `vault/secrets.json`
    /// makes `read_json` itself raise `StateError("state_corrupt", ...)`,
    /// uncaught by `_vault_doc` -- propagate that here too (finding
    /// D-R2-2); only a *successfully parsed* non-dict value (`[1]`, `"x"`,
    /// `null`, a missing file) is replaced with `{}`.
    fn vault_doc(&self) -> Result<Map<String, Value>, Error> {
        match self.state.read_json(VAULT_SECRETS, Value::Null)? {
            Value::Object(m) => Ok(m),
            _ => Ok(Map::new()),
        }
    }

    /// The vault version this connection uses now: the pinned one, else the
    /// secret's active version.
    ///
    /// `active if isinstance(active, int) and not isinstance(active, bool)
    /// else None`: any magnitude qualifies (Python's `int` is
    /// arbitrary-precision) -- returning a raw [`Value`] rather than an
    /// `i64` (round 6, differential-harness finding) keeps a huge
    /// `active_version` exact instead of resolving to `None` (an unpinned
    /// connection wrongly reading as "no active credential") the way a
    /// `Value::as_i64`-based reading did. A JSON bool is excluded (matching
    /// `not isinstance(active, bool)`) even though `Value::as_i64` already
    /// naturally never returns one.
    fn resolved_credential_version(
        &self,
        connection: &Connection,
        vault_doc: Option<&Map<String, Value>>,
    ) -> Result<Option<Value>, Error> {
        if let Some(v) = connection.secret_version {
            return Ok(Some(json!(v)));
        }
        let owned;
        let doc = match vault_doc {
            Some(d) => d,
            None => {
                owned = self.vault_doc()?;
                &owned
            }
        };
        let entry = doc
            .get("secrets")
            .and_then(Value::as_object)
            .and_then(|m| m.get(&connection.secret_id))
            .and_then(Value::as_object);
        Ok(entry
            .and_then(|e| e.get("active_version"))
            .filter(|v| matches!(v, Value::Number(n) if number_is_python_int(n)))
            .cloned())
    }

    /// Re-bind unpinned connections that follow `secret_id` to its current
    /// active version.
    ///
    /// Called by the vault after the active version of a secret changes.
    /// For every active, unpinned connection whose active grants were
    /// evaluated against another credential version, the policy version is
    /// bumped (so handles issued for the old version are refused as
    /// `grant_stale`), grants are re-evaluated in place with the new
    /// version, and approvals bound to the old policy version are
    /// invalidated. A secret that has no active version any more changes
    /// nothing: no credential can be used. Returns the updated connections.
    pub fn credential_versions_changed(&self, secret_id: &str) -> Result<Vec<Connection>, Error> {
        let mut changed: Vec<(Connection, Value)> = Vec::new();
        let _lock = self.state.lock()?;
        let mut doc = self.connections()?;
        let grants = self.grants()?;
        let vault_doc = self.vault_doc()?;
        let mut ids: Vec<String> = doc.keys().cloned().collect();
        ids.sort();
        for connection_id in ids {
            let entry = doc
                .get(&connection_id)
                .expect("key from doc.keys()")
                .clone();
            let entry_obj = as_obj(&entry)?;
            if entry_obj.get("secret_id").and_then(Value::as_str) != Some(secret_id) {
                continue;
            }
            if !matches!(entry_obj.get("secret_version"), None | Some(Value::Null)) {
                continue;
            }
            if entry_obj.get("status").and_then(Value::as_str) != Some("active") {
                continue;
            }
            let connection = Connection::from_value(&entry)?;
            let Some(resolved) = self.resolved_credential_version(&connection, Some(&vault_doc))?
            else {
                continue;
            };
            // `recorded = [g for g in grants.values() if g.get("connection")
            // == ... and g.get("status") == "active" and
            // "credential_version" in g]`: a full list comprehension --
            // every `.get()`/`in` call here is a dict method/operator, so a
            // grant entry that isn't an object at all raises an uncaught
            // `AttributeError`/`TypeError` while *building* `recorded`,
            // aborting the whole call, regardless of where that malformed
            // entry sits relative to any entry that would already satisfy
            // `any(...)`. `any(...)` only runs once the full list exists.
            //
            // Iterating `grants.values()` and `break`-ing on the first
            // mismatch (finding D-R5-9) stopped validating the shape of
            // every entry *after* that point, so a malformed later entry
            // was never noticed and the whole operation succeeded --
            // bumping the policy version, re-evaluating grants and
            // invalidating approvals -- where Python raises before any of
            // that happens. Materialising `recorded` first (validating
            // every entry's shape unconditionally) and only then testing
            // `any(...)` reproduces that ordering.
            let mut recorded: Vec<Option<&Value>> = Vec::new();
            for g in grants.values() {
                let g_obj = as_obj(g)?;
                if g_obj.get("connection").and_then(Value::as_str) != Some(connection_id.as_str()) {
                    continue;
                }
                if g_obj.get("status").and_then(Value::as_str) != Some("active") {
                    continue;
                }
                if !g_obj.contains_key("credential_version") {
                    continue;
                }
                recorded.push(g_obj.get("credential_version"));
            }
            // `g.get("credential_version") != resolved`: Python compares
            // the *raw* stored value against the resolved `int` (any
            // magnitude -- round 6) using ordinary numeric equality across
            // types (a stored float or bool can compare equal to an
            // equal-valued int) -- see [`python_numeric_eq_value`] (finding
            // D-R3-9, extended round 6 for an exact beyond-`i64` `resolved`).
            let any_active_recorded_mismatch = recorded
                .iter()
                .any(|cv| !python_numeric_eq_value(*cv, &resolved));
            if !any_active_recorded_mismatch {
                continue;
            }
            let after = Connection {
                // Finding D-R7-1: `connection.policy_version + 1` panics
                // (debug) / silently wraps to `i64::MIN` (release, since
                // `Cargo.toml` has no `overflow-checks` override) at the
                // `i64` boundary, where Python's arbitrary-precision `int`
                // just keeps counting (measured: `policy_version: 2**63-1`
                // succeeds and writes `9223372036854775808`). Rust's
                // `Connection::policy_version` is a plain `i64` relied on
                // by files outside this work unit (gateway, handles,
                // signer), so there is no exact-widening escape hatch the
                // way `GrantNum::BigInt` gives the grant fields; `checked_add`
                // fails closed with the error a caller of `update_connection`/
                // `credential_versions_changed` already handles instead of
                // panicking or corrupting the monotonic counter
                // `grant_num_ne_i64`'s `grant_stale` check depends on. See
                // `DEVIATIONS.md`'s `policy (policy_version/cycle i64
                // counter overflow, finding D-R7-1)` row.
                policy_version: connection
                    .policy_version
                    .checked_add(1)
                    .ok_or_else(|| Error::state("state_corrupt").with_detail(CONNECTIONS))?,
                updated_at: iso(Some(self.now())),
                ..connection
            };
            doc.insert(connection_id.clone(), after.to_value());
            changed.push((after, resolved));
        }
        if !changed.is_empty() {
            self.state.write_json(CONNECTIONS, &Value::Object(doc))?;
            for (after, resolved) in &changed {
                self.reevaluate_grants_value(
                    &after.id,
                    after.policy_version,
                    false,
                    Some(resolved.clone()),
                )?;
            }
            let ids: HashSet<String> = changed.iter().map(|(c, _)| c.id.clone()).collect();
            self.invalidate_approvals_fallible(
                |e| value_in_str_set(e.get("connection"), &ids),
                "policy_changed",
            )?;
        }
        Ok(changed.into_iter().map(|(c, _)| c).collect())
    }

    // ------------------------------------------------------------ principals
    pub fn create_principal(&self, principal_id: &str, runtime: &str) -> Result<String, Error> {
        let principal_id = validate_name(principal_id, "principal_id")?;
        let runtime = validate_name(runtime, "runtime")?;
        let token = format!("zpwc_{}", random_url_safe_token(32));
        let _lock = self.state.lock()?;
        let mut doc = self.principals()?;
        if doc.contains_key(&principal_id) {
            return Err(Error::invalid_input("principal_exists"));
        }
        doc.insert(
            principal_id,
            json!({
                "token_hash": hash_token(&token), "status": "active",
                "created_at": iso(Some(self.now())), "runtime": runtime,
            }),
        );
        self.state.write_json(PRINCIPALS, &Value::Object(doc))?;
        Ok(token)
    }

    /// Permanently invalidate a principal's token.
    ///
    /// `notify=false` skips the [`Policy::notify_revoke`] fan-out (which
    /// would cancel *every* active run/socket, not just this principal's --
    /// see `RunRegistry.on_revoke`). The compromise-response incident module
    /// uses this to disable a principal without over-cancelling other
    /// principals' work; it does its own precise per-principal cancellation.
    ///
    /// `doc[principal_id]["status"] = "disabled"`: a raw subscript
    /// *assignment*, not `.get()` -- if the stored entry is not a dict (a
    /// string, a list, ...), this raises an uncaught `TypeError` in Python
    /// (found by this round's exhaustive sweep of every raw index in
    /// `policy.py`, alongside the eight numbered findings), aborting before
    /// `principals.json` is ever written, though the best-effort revocation
    /// ledger line above it was already appended. The previous `if let
    /// Some(entry) = ... .and_then(Value::as_object_mut) { ... }` here
    /// silently skipped the assignment for a non-object entry instead and
    /// fell through to write the *unchanged* document and return `Ok(())`,
    /// so a corrupted principal entry could never actually be disabled.
    pub fn disable_principal(&self, principal_id: &str, notify: bool) -> Result<(), Error> {
        {
            let _lock = self.state.lock()?;
            let mut doc = self.principals()?;
            if !doc.contains_key(principal_id) {
                return Err(Error::not_found("principal_not_found"));
            }
            let mut fields = Map::new();
            fields.insert("id".into(), json!(principal_id));
            append_revocation(self.state, "principal", fields);
            let entry = doc
                .get_mut(principal_id)
                .and_then(Value::as_object_mut)
                .ok_or_else(|| Error::state("state_corrupt").with_detail("principal"))?;
            entry.insert("status".into(), json!("disabled"));
            self.state.write_json(PRINCIPALS, &Value::Object(doc))?;
            self.invalidate_approvals(
                |e| e.get("caller").and_then(Value::as_str) == Some(principal_id),
                "principal_disabled",
            )?;
        }
        if notify {
            self.notify_revoke("principal", None);
        }
        Ok(())
    }

    pub fn get_principal(&self, principal_id: &str) -> Result<Principal, Error> {
        let doc = self.principals()?;
        let entry = doc
            .get(principal_id)
            .ok_or_else(|| Error::not_found("principal_not_found"))?;
        principal_from_entry(principal_id, entry)
    }

    pub fn list_principals(&self) -> Result<Vec<Principal>, Error> {
        let doc = self.principals()?;
        let mut ids: Vec<&String> = doc.keys().collect();
        ids.sort();
        ids.into_iter()
            .map(|id| principal_from_entry(id, &doc[id]))
            .collect()
    }

    pub fn principals_in_runtime(&self, runtime: &str) -> Result<Vec<Principal>, Error> {
        Ok(self
            .list_principals()?
            .into_iter()
            .filter(|p| p.runtime == runtime)
            .collect())
    }

    /// `for pid, entry in self._principals().items(): if
    /// secrets.compare_digest(entry["token_hash"], digest): ...`
    ///
    /// Two things matter here for a corrupted `policy/principals.json`
    /// (finding D-R3-10): the iteration is in the document's own
    /// (insertion/file) order, not sorted -- this crate's `serde_json::Map`
    /// (built with `preserve_order`) already preserves that order for
    /// anything this crate itself wrote (always alphabetically sorted
    /// keys, matching Python's `sort_keys=True`), so this only changes
    /// anything for a hand-corrupted document; and `entry["token_hash"]`
    /// is a raw dict index (not `.get()`), so a malformed entry (missing
    /// or non-string `token_hash`, which also makes `secrets.compare_digest`
    /// raise `TypeError`) raises an uncaught `KeyError`/`TypeError` right
    /// where it is encountered, aborting the *whole* scan -- not silently
    /// skipping ahead to a later, well-formed entry the way treating it as
    /// `""` would.
    pub fn authenticate(&self, token: &str) -> Result<Principal, Error> {
        if !token.starts_with("zpwc_") || token.chars().count() > 256 {
            return Err(Error::auth_failed("caller_token_invalid"));
        }
        let digest = hash_token(token);
        let doc = self.principals()?;
        for (id, entry) in &doc {
            let obj = as_obj(entry)?;
            let stored_hash = obj
                .get("token_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::state("state_corrupt").with_detail("principal"))?;
            // `secrets.compare_digest(str, str)` raises an uncaught
            // `TypeError` ("comparing strings with non-ASCII characters is
            // not supported") the moment either argument has a non-ASCII
            // character; `digest` (a hex sha256) always is ASCII, so only
            // a non-ASCII *stored* `token_hash` can trigger it. Python's
            // `TypeError` aborts the whole scan right there, so no later
            // (even well-formed) principal can authenticate while such an
            // entry exists. Comparing raw bytes here never raises -- it
            // just fails to match and the loop moves on to the next
            // principal -- which let every other principal keep
            // authenticating where Python would refuse all of them
            // (finding D-R5-6).
            if !stored_hash.is_ascii() {
                return Err(Error::state("state_corrupt").with_detail("principal"));
            }
            if constant_time_eq(stored_hash.as_bytes(), digest.as_bytes()) {
                let principal = principal_from_entry(id, entry)?;
                if principal.status != "active" {
                    return Err(Error::auth_failed("principal_disabled"));
                }
                return Ok(principal);
            }
        }
        Err(Error::auth_failed("caller_token_invalid"))
    }
}

fn default_control() -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("stopped".into(), json!(false));
    m.insert("restore_pending".into(), json!(false));
    m.insert("approvals".into(), json!({}));
    m
}

fn principal_from_entry(id: &str, entry: &Value) -> Result<Principal, Error> {
    let obj = as_obj(entry)?;
    let bad = || Error::state("state_corrupt").with_detail("principal");
    Ok(Principal {
        id: id.to_string(),
        token_hash: obj
            .get("token_hash")
            .and_then(Value::as_str)
            .ok_or_else(bad)?
            .to_string(),
        status: obj
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(bad)?
            .to_string(),
        created_at: obj
            .get("created_at")
            .and_then(Value::as_str)
            .ok_or_else(bad)?
            .to_string(),
        // `entry.get("runtime", "default")`: defaults only when the key is
        // *absent*; a present value of any type (including `null`) is kept
        // verbatim, with no check anywhere -- `principals_in_runtime`
        // compares it by equality, so a stored non-string `runtime` would
        // never match any `str` runtime name in Python either. Silently
        // substituting `"default"` here would instead make a
        // corrupt-`runtime` principal match `principals_in_runtime("default")`,
        // which incident/intrusion scoping relies on; keep it consistent
        // with the sibling fields above (finding D-R2-7).
        runtime: match obj.get("runtime") {
            None => "default".to_string(),
            Some(Value::String(s)) => s.clone(),
            Some(_) => return Err(bad()),
        },
    })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// `secrets.token_urlsafe(n)`: `n` random bytes, base64url-encoded without
/// padding (Python strips the `=` padding `token_urlsafe` would otherwise
/// produce).
fn random_url_safe_token(n: usize) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

impl<'a> Policy<'a> {
    // ----------------------------------------------------------- connections
    pub fn create_connection(&self, connection: Connection) -> Result<Connection, Error> {
        if let Some(target) = &connection.http_target {
            target.require_allowed_literal()?;
        }
        let _lock = self.state.lock()?;
        let mut doc = self.connections()?;
        if doc.contains_key(&connection.id) {
            return Err(Error::invalid_input("connection_exists"));
        }
        let now = iso(Some(self.now()));
        let stamped = Connection {
            policy_version: 1,
            created_at: now.clone(),
            updated_at: now,
            ..connection
        };
        doc.insert(stamped.id.clone(), stamped.to_value());
        self.state.write_json(CONNECTIONS, &Value::Object(doc))?;
        Ok(stamped)
    }

    pub fn get_connection(&self, connection_id: &str) -> Result<Connection, Error> {
        let doc = self.connections()?;
        let entry = doc
            .get(connection_id)
            .ok_or_else(|| Error::not_found("connection_not_found"))?;
        Connection::from_value(entry)
    }

    pub fn list_connections(&self) -> Result<Vec<Connection>, Error> {
        let doc = self.connections()?;
        let mut ids: Vec<&String> = doc.keys().collect();
        ids.sort();
        ids.into_iter()
            .map(|id| Connection::from_value(&doc[id]))
            .collect()
    }

    /// Apply changes, bump the policy version, and re-evaluate grants.
    ///
    /// Returns `(connection, widened)`. Widening changes mark grants stale.
    pub fn update_connection(
        &self,
        connection_id: &str,
        changes: ConnectionChanges,
    ) -> Result<(Connection, bool), Error> {
        if let Some(Some(target)) = &changes.http_target {
            target.require_allowed_literal()?;
        }
        let (after, widened);
        {
            let _lock = self.state.lock()?;
            let mut doc = self.connections()?;
            let entry = doc
                .get(connection_id)
                .ok_or_else(|| Error::not_found("connection_not_found"))?
                .clone();
            let before = Connection::from_value(&entry)?;
            let updated = before.with_changes(&changes)?;
            widened = Policy::widens(&before, &updated);
            // Finding D-R7-1: see the matching comment on
            // `credential_versions_changed`'s policy-version bump --
            // `checked_add` fails closed instead of panicking (debug) or
            // wrapping to `i64::MIN` (release) at the `i64` boundary.
            let after_version = before
                .policy_version
                .checked_add(1)
                .ok_or_else(|| Error::state("state_corrupt").with_detail(CONNECTIONS))?;
            after = Connection {
                policy_version: after_version,
                updated_at: iso(Some(self.now())),
                ..updated
            };
            if after.status == "disabled" && before.status != "disabled" {
                let mut fields = Map::new();
                fields.insert("id".into(), json!(connection_id));
                append_revocation(self.state, "connection", fields);
            } else if after.status == "active" && before.status != "active" {
                let mut fields = Map::new();
                fields.insert("id".into(), json!(connection_id));
                append_revocation(self.state, "connection_enable", fields);
            }
            doc.insert(connection_id.to_string(), after.to_value());
            self.state.write_json(CONNECTIONS, &Value::Object(doc))?;
            let resolved = self.resolved_credential_version(&after, None)?;
            self.reevaluate_grants_value(connection_id, after.policy_version, widened, resolved)?;
            // Approvals are bound to the policy version they were requested under.
            let reason = if after.status == "disabled" {
                "connection_disabled"
            } else {
                "policy_changed"
            };
            self.invalidate_approvals(
                |e| e.get("connection").and_then(Value::as_str) == Some(connection_id),
                reason,
            )?;
        }
        if widened {
            self.notify_revoke("connection", None);
        }
        Ok((after, widened))
    }

    /// `Policy._widens` (a `@staticmethod` in Python, called directly by
    /// `zeropw/team/fold.py` as `P.Policy._widens(before, after)`; kept
    /// `pub(crate)` so that work unit's `team::fold` can do the same here).
    pub(crate) fn widens(before: &Connection, after: &Connection) -> bool {
        if before.kind != after.kind || (before.status != after.status && after.status == "active")
        {
            return true;
        }
        // Another secret is another credential (possibly with broader
        // rights); only a version switch within the same secret is
        // re-evaluated in place.
        if before.secret_id != after.secret_id {
            return true;
        }
        if before.kind == "http" {
            let (Some(bt), Some(at)) = (&before.http_target, &after.http_target) else {
                return true;
            };
            let (Some(bs), Some(aus)) = (&before.http_scope, &after.http_scope) else {
                return true;
            };
            let (Some(ba), Some(aa)) = (&before.http_auth, &after.http_auth) else {
                return true;
            };
            if (bt.scheme.as_str(), bt.host.as_str(), bt.port)
                != (at.scheme.as_str(), at.host.as_str(), at.port)
            {
                return true;
            }
            // A different TLS trust anchor (another CA file, or the system
            // store) can authenticate servers the old one did not.
            if bt.ca_file != at.ca_file {
                return true;
            }
            // Opening private networks lets the credential reach addresses
            // it could not before.
            if at.allow_private_network && !bt.allow_private_network {
                return true;
            }
            if ba != aa {
                return true;
            }
            if bs.widens(aus) {
                return true;
            }
        }
        if before.kind == "ssh" {
            let (Some(bt), Some(at)) = (&before.ssh_target, &after.ssh_target) else {
                return true;
            };
            if (bt.host.as_str(), bt.port, bt.username.as_str())
                != (at.host.as_str(), at.port, at.username.as_str())
            {
                return true;
            }
            let before_keys: HashSet<&str> = bt.host_keys.iter().map(String::as_str).collect();
            let after_keys: HashSet<&str> = at.host_keys.iter().map(String::as_str).collect();
            if after_keys.difference(&before_keys).next().is_some() {
                return true;
            }
        }
        if before.cli.is_some() != after.cli.is_some() {
            return true;
        }
        if let (Some(bc), Some(ac)) = (&before.cli, &after.cli)
            && bc != ac
        {
            return true;
        }
        false
    }

    /// `pub(crate)`: called directly by `zeropw/team/fold.py`'s
    /// `policy._reevaluate_grants` (and `team/membership.py`) once those
    /// modules land, exactly as `Policy::widens` above.
    ///
    /// `for gid, entry in grants.items(): if entry["connection"] !=
    /// connection_id or entry["status"] != "active": continue`: both are raw
    /// dict indices, evaluated for *every* entry in the document regardless
    /// of whether it belongs to this connection -- a non-object entry raises
    /// an uncaught `TypeError` and a missing `connection`/`status` key an
    /// uncaught `KeyError`, aborting `update_connection`/
    /// `credential_versions_changed` entirely (finding D-R4-2) after the
    /// connections document was already written. The previous `let Some(obj)
    /// = ... else { continue }` / `.and_then(Value::as_str)` here silently
    /// skipped exactly those malformed entries instead, leaving other grants
    /// re-evaluated (or not) from a partial pass Python would never reach.
    /// A present-but-wrong-*type* value for either key is not an error in
    /// Python (`!=` across types is just `True`, no exception), so only a
    /// non-object entry or an outright missing key fails closed here.
    /// Thin `i64` wrapper kept for existing callers outside this module
    /// (`team::fold`, `team::membership`) that only ever resolve a
    /// plain-`i64` credential version -- see
    /// [`Policy::reevaluate_grants_value`] for the exact-value form this
    /// module's own callers use (round 6, a vault secret's `active_version`
    /// beyond `i64` range).
    pub(crate) fn reevaluate_grants(
        &self,
        connection_id: &str,
        new_version: i64,
        widened: bool,
        credential_version: Option<i64>,
    ) -> Result<(), Error> {
        self.reevaluate_grants_value(
            connection_id,
            new_version,
            widened,
            credential_version.map(|v| json!(v)),
        )
    }

    pub(crate) fn reevaluate_grants_value(
        &self,
        connection_id: &str,
        new_version: i64,
        widened: bool,
        credential_version: Option<Value>,
    ) -> Result<(), Error> {
        let mut grants = self.grants()?;
        let mut changed = false;
        for (_, entry) in grants.iter_mut() {
            let obj = entry
                .as_object_mut()
                .ok_or_else(|| Error::state("state_corrupt").with_detail("grant"))?;
            // `entry["connection"] != connection_id or entry["status"] !=
            // "active"`: Python's `or` short-circuits, so `entry["status"]`
            // is never read at all for a grant of another connection --
            // only fetching `status` unconditionally (finding D-R5-3) made
            // an unrelated entry with no `status` key `state_corrupt` the
            // whole call, after `connections.json` had already been
            // written by the caller (`update_connection`/
            // `credential_versions_changed`).
            let connection_val = obj
                .get("connection")
                .ok_or_else(|| Error::state("state_corrupt").with_detail("grant"))?
                .clone();
            if connection_val.as_str() != Some(connection_id) {
                continue;
            }
            let status_val = obj
                .get("status")
                .ok_or_else(|| Error::state("state_corrupt").with_detail("grant"))?
                .clone();
            if status_val.as_str() != Some("active") {
                continue;
            }
            if widened {
                obj.insert("status".into(), json!("stale"));
            } else {
                obj.insert("policy_version".into(), json!(new_version));
                obj.insert(
                    "credential_version".into(),
                    credential_version.clone().unwrap_or(Value::Null),
                );
            }
            changed = true;
        }
        if changed {
            self.state.write_json(GRANTS, &Value::Object(grants))?;
        }
        Ok(())
    }

    pub fn switch_credential(
        &self,
        connection_id: &str,
        secret_version: Option<i64>,
    ) -> Result<Connection, Error> {
        let (connection, _) = self.update_connection(
            connection_id,
            ConnectionChanges::new().secret_version(secret_version),
        )?;
        Ok(connection)
    }

    pub fn disable_connection(&self, connection_id: &str) -> Result<Connection, Error> {
        let (connection, _) =
            self.update_connection(connection_id, ConnectionChanges::new().status("disabled"))?;
        self.notify_revoke("connection", None);
        Ok(connection)
    }
}

impl<'a> Policy<'a> {
    // ---------------------------------------------------------------- grants
    pub fn create_grant(
        &self,
        principal_id: &str,
        connection_id: &str,
        ttl_seconds: Option<i64>,
        max_uses: Option<i64>,
    ) -> Result<Grant, Error> {
        self.create_grant_exact(
            principal_id,
            connection_id,
            ttl_seconds,
            max_uses.map(|m| json!(m)),
        )
    }

    /// Shared grant-construction core for [`Policy::create_grant`] (always
    /// a plain `i64`-or-`None` `max_uses`) and [`Policy::regrant`] (finding
    /// D-R7-3): `regrant`'s `max_uses_raw` is [`grant_num_sub`]'s *exact*
    /// remaining-uses `Value`, which can exceed `i64` (`GrantNum::BigInt`,
    /// or even a `Float`) -- Python's `Grant.max_uses` applies no `int()`/
    /// `isinstance` conversion at all, so a regranted grant must keep the
    /// exact value `max(old.max_uses - old.uses, 0)` computed, not a lossy
    /// `f64`-then-`i64` collapse. [`Grant::to_value`] serializes it via
    /// `raw_max_uses` exactly, so the persisted document keeps full
    /// precision even when the best-effort public `max_uses: Option<i64>`
    /// field below can't.
    ///
    /// The `ttl_seconds <= 0 || > MAX_GRANT_TTL` / `max_uses <= 0` checks
    /// live *here*, not in the public `create_grant` wrapper above: Python's
    /// own `create_grant` applies both checks unconditionally, before ever
    /// acquiring the state lock, and `regrant` calls that same `create_grant`
    /// -- so `regrant`'s own `remaining_ttl`/`remaining_uses` must pass
    /// through the identical checks. Calling `create_grant_exact` directly
    /// from `regrant` (bypassing the public wrapper) had silently dropped
    /// this: measured with `grants["g-gh-bearer"]["expires_at"] =
    /// 2**63-1`, `regrant` computes a `remaining_ttl` far beyond
    /// `MAX_GRANT_TTL`, and Python's `create_grant` correctly rejects it
    /// with `InvalidInput("invalid_ttl")` -- this port's `regrant`
    /// previously created the grant anyway (`create_grant_exact` had no
    /// such check at all).
    fn create_grant_exact(
        &self,
        principal_id: &str,
        connection_id: &str,
        ttl_seconds: Option<i64>,
        max_uses_raw: Option<Value>,
    ) -> Result<Grant, Error> {
        if let Some(ttl) = ttl_seconds
            && (ttl <= 0 || ttl > MAX_GRANT_TTL)
        {
            return Err(Error::invalid_input("invalid_ttl"));
        }
        // `isinstance(max_uses, bool)` never applies here: neither caller
        // ever constructs a `Value::Bool` for this parameter (the public
        // wrapper always wraps a plain `i64`; `regrant`'s `grant_num_sub`
        // never produces a bool result). The numeric `<= 0` check uses the
        // same sign-only comparison `grant_num_max_with_zero` already
        // uses elsewhere -- exactness only matters near the `i64`/`f64`
        // boundary, never near zero.
        if let Some(m) = &max_uses_raw
            && numeric_value_as_f64(m).is_some_and(|f| f <= 0.0)
        {
            return Err(Error::invalid_input("invalid_max_uses"));
        }
        let _lock = self.state.lock()?;
        let principal = self.get_principal(principal_id)?;
        if principal.status != "active" {
            return Err(Error::invalid_input("principal_disabled"));
        }
        let connection = self.get_connection(connection_id)?;
        if connection.status != "active" {
            return Err(Error::invalid_input("connection_disabled"));
        }
        let now = self.now();
        let credential_version_raw = self.resolved_credential_version(&connection, None)?;
        // Best-effort `i64` reading (see `Grant`'s own doc comment): `None`
        // when the resolved version is exact but outside `i64` range (a
        // vault secret's `active_version` beyond `i64`, round 6) rather than
        // the reason grant creation fails -- the exact value still flows
        // through `raw_credential_version`.
        let credential_version = credential_version_raw.as_ref().and_then(Value::as_i64);
        let raw_credential_version = credential_version_raw.map(|v| GrantNum::from_value(&v));
        let max_uses = max_uses_raw.as_ref().and_then(python_int_coerce);
        let raw_max_uses = max_uses_raw.as_ref().map(GrantNum::from_value);
        let grant = Grant {
            id: format!("g-{}", &uuid::Uuid::new_v4().simple().to_string()[..16]),
            principal: principal_id.to_string(),
            connection: connection_id.to_string(),
            policy_version: connection.policy_version,
            expires_at: ttl_seconds.map(|t| now + t as f64),
            max_uses,
            uses: 0,
            status: "active".to_string(),
            created_at: iso(Some(now)),
            revoked_at: None,
            credential_version,
            raw_policy_version: GrantNum::Int(connection.policy_version),
            raw_max_uses,
            raw_uses: GrantNum::Int(0),
            raw_credential_version,
            raw_status: json!("active"),
            raw_revoked_at: Value::Null,
            raw_expires_at: ttl_seconds.map(|t| json!(now + t as f64)),
        };
        let mut doc = self.grants()?;
        doc.insert(grant.id.clone(), grant.to_value());
        self.state.write_json(GRANTS, &Value::Object(doc))?;
        Ok(grant)
    }

    pub fn get_grant(&self, grant_id: &str) -> Result<Grant, Error> {
        let doc = self.grants()?;
        let entry = doc
            .get(grant_id)
            .ok_or_else(|| Error::not_found("grant_not_found"))?;
        Grant::from_value(entry)
    }

    /// `[Grant(**e) for _, e in sorted(self._grants().items()) if
    /// principal_id is None or e["principal"] == principal_id]`. Python's
    /// `or` short-circuits: `e["principal"]` -- a raw dict index -- is only
    /// ever evaluated when `principal_id is not None`, but then it is
    /// evaluated for *every* entry in sorted-key order, eagerly, before the
    /// list comprehension moves on; a non-object entry (`TypeError`) or one
    /// missing `principal` (`KeyError`) aborts the whole call there, not a
    /// silent skip. That includes `decide`'s no-grant-id path and
    /// `usable_connections` (both call `list_grants(Some(caller))`), which
    /// must refuse to decide from a partial grant set the same way (finding
    /// D-R4-3). A present-but-non-string `principal` is not an error in
    /// Python (`5 == "caller"` is just `False`, no exception) -- only a
    /// non-object entry or an outright missing key fails closed here; the
    /// previous `.as_object().and_then(|o| o.get("principal"))
    /// .and_then(Value::as_str) == Some(p)` chain silently treated both of
    /// those shapes as "does not match" and moved on.
    pub fn list_grants(&self, principal_id: Option<&str>) -> Result<Vec<Grant>, Error> {
        let doc = self.grants()?;
        let mut ids: Vec<&String> = doc.keys().collect();
        ids.sort();
        let mut result = Vec::with_capacity(ids.len());
        for id in ids {
            let entry = &doc[id];
            if let Some(p) = principal_id {
                let obj = entry
                    .as_object()
                    .ok_or_else(|| Error::state("state_corrupt").with_detail("grant"))?;
                let principal = obj
                    .get("principal")
                    .ok_or_else(|| Error::state("state_corrupt").with_detail("grant"))?;
                if principal.as_str() != Some(p) {
                    continue;
                }
            }
            result.push(Grant::from_value(entry)?);
        }
        Ok(result)
    }

    /// Approvals recorded for this grant, or recorded without a grant for
    /// its caller and connection.
    ///
    /// `entry.get("caller") == grant.get("principal") and entry.get(
    /// "connection") == grant.get("connection")`: both are `.get()` calls on
    /// the *raw stored grant dict* (`grant` here is `revoke_grant`'s own
    /// `entry`/`regrant`'s `doc[grant_id]`, not the parsed `Grant`), so a
    /// missing `principal`/`connection` key on the grant compares as `None`,
    /// which *matches* an approval whose own `caller`/`connection` is
    /// likewise absent (`None == None` is `True` in Python) -- closing that
    /// approval. The previous `grant_principal: &str`/`grant_connection:
    /// &str` parameters collapsed "missing or non-string" to `""` at the two
    /// call sites (`.unwrap_or("")`), so `Some("")` never matched the
    /// approval's absent `caller`/`connection` (`None`), leaving a usable
    /// approved approval where Python invalidates it (finding D-R4-6, a
    /// fail-open state divergence). Taking `Option<&str>` here instead and
    /// comparing it directly against the approval's own
    /// `.and_then(Value::as_str)` (which is `None` for both "missing" and
    /// "present but non-string", exactly as `grant_principal`/
    /// `grant_connection` now are) reproduces the None-to-None match.
    /// (`regrant`'s call site is unaffected in practice -- `get_grant` runs
    /// first there and already requires `principal`/`connection` to be
    /// non-empty strings, so its `entry_snapshot` values are never actually
    /// missing/non-string by the time this runs; see `rust/DEVIATIONS.md`.)
    fn approval_matches_grant<'g>(
        grant_principal: Option<&'g str>,
        grant_connection: Option<&'g str>,
        grant_id: &'g str,
    ) -> impl Fn(&Map<String, Value>) -> bool + 'g {
        move |entry: &Map<String, Value>| match entry.get("grant") {
            Some(Value::Null) | None => {
                entry.get("caller").and_then(Value::as_str) == grant_principal
                    && entry.get("connection").and_then(Value::as_str) == grant_connection
            }
            Some(Value::String(g)) => g == grant_id,
            Some(_) => false,
        }
    }

    pub fn revoke_grant(&self, grant_id: &str) -> Result<Grant, Error> {
        let grant;
        {
            let _lock = self.state.lock()?;
            let mut doc = self.grants()?;
            if !doc.contains_key(grant_id) {
                return Err(Error::not_found("grant_not_found"));
            }
            // Python's `entry = doc.get(grant_id)` (just an existence
            // check -- `None` means not found) is followed immediately by
            // `append_revocation(...)`, and only *then* does `entry["status"]
            // = "revoked"` attempt to mutate `entry`, raising an uncaught
            // `TypeError` there if it isn't a dict. So the ledger line is
            // written before Python ever learns the entry is malformed:
            // the revocation survives on disk (the ledger sits outside the
            // backup set and is replayed by `collect_revocations`) even
            // though the call itself still fails. Shape-checking before
            // `append_revocation` (finding D-R5-8) lost that surviving
            // ledger line for a malformed grant entry.
            let mut fields = Map::new();
            fields.insert("id".into(), json!(grant_id));
            append_revocation(self.state, "grant", fields);
            let entry = doc
                .get_mut(grant_id)
                .and_then(Value::as_object_mut)
                .ok_or_else(|| Error::state("state_corrupt").with_detail("grant"))?;
            entry.insert("status".into(), json!("revoked"));
            entry.insert("revoked_at".into(), json!(iso(Some(self.now()))));
            let principal = entry
                .get("principal")
                .and_then(Value::as_str)
                .map(str::to_string);
            let connection = entry
                .get("connection")
                .and_then(Value::as_str)
                .map(str::to_string);
            self.state.write_json(GRANTS, &Value::Object(doc))?;
            self.invalidate_approvals(
                Self::approval_matches_grant(principal.as_deref(), connection.as_deref(), grant_id),
                "grant_revoked",
            )?;
            grant = self.get_grant(grant_id)?;
        }
        self.notify_revoke("grant", Some(grant_id));
        Ok(grant)
    }

    /// Revoke every active or stale grant and invalidate every open approval
    /// (used by recovery).
    /// `for grant_id, entry in doc.items(): if entry["status"] in
    /// ("active", "stale"): ...`
    ///
    /// `entry["status"]` is a raw dict index, not `.get()` -- a malformed
    /// entry (not an object at all, or missing `status`) raises an
    /// uncaught `KeyError`/`TypeError` in Python, aborting the *whole*
    /// operation before anything is written (finding D-R3-10). Unlike
    /// [`Policy::revoke_grants_of`] below (whose Python source legitimately
    /// uses `.get()` and keeps skipping), this must fail closed instead of
    /// silently ignoring the malformed entry and still writing every other
    /// revocation, reporting a partial count as if nothing were wrong.
    pub fn revoke_all(&self) -> Result<usize, Error> {
        let count;
        {
            let _lock = self.state.lock()?;
            let mut doc = self.grants()?;
            let mut n = 0usize;
            for (grant_id, entry) in doc.iter_mut() {
                let obj = entry
                    .as_object_mut()
                    .ok_or_else(|| Error::state("state_corrupt").with_detail("grant"))?;
                // `entry["status"] in ("active", "stale")`: a raw index
                // (missing key -> uncaught `KeyError`, `state_corrupt`),
                // but the membership test itself never raises for a
                // present *non-string* value -- it simply never matches,
                // same as any other value not in the tuple, and that grant
                // is skipped while every other one is still revoked.
                // Treating "present but not a string" the same as
                // "missing" (finding D-R5-5) made this recovery operation
                // refuse to revoke *anything* the moment one grant had a
                // non-string `status`.
                let status = obj
                    .get("status")
                    .ok_or_else(|| Error::state("state_corrupt").with_detail("grant"))?;
                let revocable = matches!(status, Value::String(s) if s == "active" || s == "stale");
                if revocable {
                    let mut fields = Map::new();
                    fields.insert("id".into(), json!(grant_id));
                    append_revocation(self.state, "grant", fields);
                    obj.insert("status".into(), json!("revoked"));
                    obj.insert("revoked_at".into(), json!(iso(Some(self.now()))));
                    n += 1;
                }
            }
            count = n;
            self.state.write_json(GRANTS, &Value::Object(doc))?;
            self.invalidate_approvals(|_| true, "grant_revoked")?;
        }
        self.notify_revoke("all", None);
        Ok(count)
    }

    /// Revoke every active/stale grant of one principal; notify per grant
    /// for precise cancellation.
    ///
    /// Used by the compromise-response incident module (`principal` scope):
    /// unlike [`Policy::revoke_all`], this only touches one principal's
    /// grants, and the per-grant `notify_revoke("grant", grant_id)` cancels
    /// exactly that grant's runs/signer sockets instead of every active one.
    pub fn revoke_grants_of(&self, principal_id: &str) -> Result<usize, Error> {
        let mut revoked_ids: Vec<String> = Vec::new();
        {
            let _lock = self.state.lock()?;
            let mut doc = self.grants()?;
            for (grant_id, entry) in doc.iter_mut() {
                // `entry.get("principal") == principal_id and entry.get("status")
                // in (...)`: both real `.get()` calls, so a well-formed
                // object entry missing either key is legitimately skipped
                // (`None` never equals `principal_id`/is never in the
                // tuple) -- but `.get()` itself is a dict method, so an
                // entry that isn't an object at all (a string, a number, an
                // array) raises an uncaught `AttributeError` in Python,
                // aborting the whole call, not a silent skip (finding
                // D-R3-10's sweep).
                let obj = entry
                    .as_object_mut()
                    .ok_or_else(|| Error::state("state_corrupt").with_detail("grant"))?;
                if obj.get("principal").and_then(Value::as_str) != Some(principal_id) {
                    continue;
                }
                let status = obj.get("status").and_then(Value::as_str).unwrap_or("");
                if status == "active" || status == "stale" {
                    let mut fields = Map::new();
                    fields.insert("id".into(), json!(grant_id));
                    append_revocation(self.state, "grant", fields);
                    obj.insert("status".into(), json!("revoked"));
                    obj.insert("revoked_at".into(), json!(iso(Some(self.now()))));
                    revoked_ids.push(grant_id.clone());
                }
            }
            if !revoked_ids.is_empty() {
                self.state.write_json(GRANTS, &Value::Object(doc))?;
                self.invalidate_approvals(
                    |e| e.get("caller").and_then(Value::as_str) == Some(principal_id),
                    "grant_revoked",
                )?;
            }
        }
        for grant_id in &revoked_ids {
            self.notify_revoke("grant", Some(grant_id));
        }
        Ok(revoked_ids.len())
    }

    /// Issue a fresh grant with the same limits at the current policy
    /// version.
    pub fn regrant(&self, grant_id: &str) -> Result<Grant, Error> {
        let _lock = self.state.lock()?;
        let old = self.get_grant(grant_id)?;
        if !old.status_is("stale") && !old.status_is("active") {
            return Err(Error::invalid_input("grant_not_regrantable"));
        }
        // `if old.expires_at is not None:` -- the guard is `is not None`,
        // not truthiness (see `Policy::grant_state`'s matching comment); a
        // non-`None`, non-numeric value raises the closest handled error.
        //
        // `remaining_ttl = int(old.expires_at - self.clock())`: unlike
        // *comparisons* (`now_at_least_exact`'s exactness), Python's mixed
        // int/float *subtraction* is not special-cased -- it converts the
        // `int` through an ordinary (potentially lossy) `float()` first,
        // same as `numeric_value_as_f64` here. Measured directly:
        // `(2**53 + 1) - 1000.5 == 9007199254739992.0` in `python3.12`, the
        // same value `f64` subtraction gives -- so this site is *not* part
        // of finding D-R7-3 despite being on the same call chain; it
        // already matches Python's own precision loss exactly.
        let remaining_ttl = match &old.raw_expires_at {
            Some(exp_val) => {
                let exp = numeric_value_as_f64(exp_val)
                    .ok_or_else(|| Error::state("state_corrupt").with_detail("grant"))?;
                let remaining = (exp - self.now()) as i64;
                if remaining <= 0 {
                    return Err(Error::invalid_input("grant_expired"));
                }
                Some(remaining)
            }
            None => None,
        };
        // `max(old.max_uses - old.uses, 0)`: the subtraction can raise the
        // same uncaught `TypeError` `grant_num_sub` already models for a
        // `str`-typed field (PORTING.md §3.5, propagated via `?`).
        //
        // **Round-7 correction (finding D-R7-3):** this used to collapse
        // `grant_num_sub`'s exact result through `.as_f64().unwrap_or(0.0)`
        // then `as i64` before handing it to `create_grant`, losing
        // precision above 2**53 (measured: `max_uses = 2**53 + 1` gave
        // `9007199254740992` instead of Python's `9007199254740993`) and
        // silently dropping a genuine float remainder (`max_uses = 5.5,
        // uses = 1.0` gave `4` instead of Python's `4.5`) or clamping a
        // huge value to `i64::MAX`. `grant_num_sub` already computes the
        // exact result (an exact integer of any magnitude `i128` can hold,
        // or a real `f64` for a genuinely float-shaped operand); the exact
        // `Value` now flows straight through [`Policy::create_grant_exact`]
        // to the fresh grant's `raw_max_uses`/persisted document instead.
        let remaining_uses_raw: Option<Value> = match &old.raw_max_uses {
            Some(max) => Some(grant_num_max_with_zero(grant_num_sub(max, &old.raw_uses)?)),
            None => None,
        };
        if remaining_uses_raw
            .as_ref()
            .is_some_and(grant_num_value_is_zero)
        {
            return Err(Error::invalid_input("grant_exhausted"));
        }
        let mut doc = self.grants()?;
        let mut fields = Map::new();
        fields.insert("id".into(), json!(grant_id));
        append_revocation(self.state, "grant", fields);
        let entry = doc
            .get_mut(grant_id)
            .and_then(Value::as_object_mut)
            .ok_or_else(|| Error::not_found("grant_not_found"))?;
        entry.insert("status".into(), json!("revoked"));
        entry.insert("revoked_at".into(), json!(iso(Some(self.now()))));
        let entry_snapshot = entry.clone();
        self.state.write_json(GRANTS, &Value::Object(doc))?;
        // `.unwrap_or("")` here (unlike `revoke_grant`'s equivalent, finding
        // D-R4-6) can never actually collapse a missing/non-string value:
        // `old = self.get_grant(grant_id)?` above already ran `Grant::from_
        // value` on this same entry and requires `principal`/`connection`
        // to be present, non-empty strings, so `entry_snapshot` is
        // guaranteed to have both as strings by the time we get here. Passed
        // through as `Option<&str>` only to match `approval_matches_grant`'s
        // signature.
        let principal = entry_snapshot.get("principal").and_then(Value::as_str);
        let connection = entry_snapshot.get("connection").and_then(Value::as_str);
        self.invalidate_approvals(
            Self::approval_matches_grant(principal, connection, grant_id),
            "grant_revoked",
        )?;
        self.create_grant_exact(
            &old.principal,
            &old.connection,
            remaining_ttl,
            remaining_uses_raw,
        )
    }
}

fn as_obj_mut(v: &mut Value) -> Result<&mut Map<String, Value>, Error> {
    v.as_object_mut()
        .ok_or_else(|| Error::state("state_corrupt").with_detail("policy_document"))
}

/// `control.setdefault("approvals", {})` / `control.setdefault(
/// "approval_history", [])`: Python's `setdefault` only inserts the given
/// default for an ABSENT key; a key that is *present* with the wrong shape
/// (a stray `"x"`/`5`/`[1]`) is returned by `setdefault` completely
/// unchanged, so the caller's subsequent `.get(...)`/`.append(...)` raises
/// an uncaught `AttributeError` and the whole operation aborts without
/// writing anything. Fail closed instead of silently replacing the corrupt
/// value with the default (finding D-R3-2).
fn setdefault_obj<'m>(
    control: &'m mut Map<String, Value>,
    key: &str,
) -> Result<&'m mut Map<String, Value>, Error> {
    if !control.contains_key(key) {
        control.insert(key.to_string(), json!({}));
    }
    as_obj_mut(control.get_mut(key).expect("just ensured"))
}

fn setdefault_arr<'m>(
    control: &'m mut Map<String, Value>,
    key: &str,
) -> Result<&'m mut Vec<Value>, Error> {
    if !control.contains_key(key) {
        control.insert(key.to_string(), json!([]));
    }
    control
        .get_mut(key)
        .expect("just ensured")
        .as_array_mut()
        .ok_or_else(|| Error::state("state_corrupt").with_detail(CONTROL))
}

/// `dict(self._control().get("approvals", {}))`: CPython's `dict(x)`
/// coercion, not the falsy/truthy split `control()` itself applies (finding
/// D-R3-2). Besides an already-dict value, `dict()` also succeeds for an
/// empty array or empty string (both give `{}`, same as the absent-key
/// default) and for an array of two-element `[key, value]` pairs (a later
/// pair overwrites an earlier one with an *equal* key, ordinary `dict`
/// construction); an array element that isn't a two-element pair, or a pair
/// whose first element is itself unhashable (a JSON array or object,
/// `list`/`dict` in Python) is a genuinely uncaught `TypeError`/
/// `ValueError` in Python (PORTING.md §3.5), so it fails closed as
/// `state_corrupt` here.
///
/// **Round-7 correction (finding D-R7-5):** a pair whose first element is a
/// hashable *non-string* (a JSON number, bool or `null`) used to be folded
/// into that same `state_corrupt` case, with a doc comment (since corrected
/// above) that called it "a genuinely uncaught TypeError/ValueError in
/// Python (§3.5)". That was false, and measured false: `python3.12`
/// confirms `dict([[1, "a"]]) == {1: 'a'}` -- CPython's `dict()` accepts
/// any hashable key, not just strings, and returns a value, it never
/// raises. This crate's `Map<String, Value>` genuinely cannot represent a
/// non-string key, though, and stringifying it (as `json.dumps` would if
/// the result were ever re-serialised, e.g. key `1` -> `"1"`) is not a safe
/// substitute: Python keeps `1` (`int`) and `"1"` (`str`) as two distinct
/// dict keys (`dict([[1, "a"], ["1", "b"]]) == {1: 'a', '1': 'b'}`), so
/// stringifying would silently collide two real, distinct entries into
/// one. This is therefore a genuine representational gap (the same shape
/// as the `ca_file`/`secret_version` rows in `DEVIATIONS.md`), not a
/// §3.5 uncaught-exception substitution -- recorded there under `policy
/// (python_dict_coerce non-string pair key, finding D-R7-5)`, with the
/// existing fail-closed `state_corrupt` kept deliberately (over a
/// collision-prone stringify) and pinned by
/// `list_approvals_with_non_string_pair_key_is_a_recorded_representational_gap`.
fn python_dict_coerce(value: Option<&Value>) -> Result<Map<String, Value>, Error> {
    let corrupt = || Error::state("state_corrupt").with_detail(CONTROL);
    match value {
        None => Ok(Map::new()),
        Some(Value::Object(m)) => Ok(m.clone()),
        Some(Value::Array(a)) => {
            let mut m = Map::new();
            for item in a {
                match item {
                    Value::Array(pair) if pair.len() == 2 => match &pair[0] {
                        Value::String(k) => {
                            m.insert(k.clone(), pair[1].clone());
                        }
                        _ => return Err(corrupt()),
                    },
                    _ => return Err(corrupt()),
                }
            }
            Ok(m)
        }
        Some(Value::String(s)) if s.is_empty() => Ok(Map::new()),
        Some(_) => Err(corrupt()),
    }
}

/// `list(self._control().get("approval_history", []))`: CPython's `list(x)`
/// coercion. An object becomes the list of its keys and a string becomes
/// the list of its individual characters -- both genuine Python successes,
/// not failures (finding D-R3-2); a bare number/bool/`null` is a genuinely
/// uncaught `TypeError` (PORTING.md §3.5), so it fails closed as
/// `state_corrupt` here.
fn python_list_coerce(value: Option<&Value>) -> Result<Vec<Value>, Error> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::Array(a)) => Ok(a.clone()),
        Some(Value::Object(m)) => Ok(m.keys().map(|k| Value::String(k.clone())).collect()),
        Some(Value::String(s)) => Ok(s.chars().map(|c| Value::String(c.to_string())).collect()),
        Some(_) => Err(Error::state("state_corrupt").with_detail(CONTROL)),
    }
}

/// Lifecycle of one digest: pending -> approved -> consumed, or -> expired /
/// invalidated. Only `pending` and `approved` are open. A digest whose
/// current entry is closed starts a new cycle on the next request; the
/// closed entry moves to `approval_history`.
const OPEN_APPROVAL_STATES: &[&str] = &["pending", "approved"];

impl<'a> Policy<'a> {
    // --------------------------------------------------------------- control
    pub fn stop_all(&self) -> Result<(), Error> {
        {
            let _lock = self.state.lock()?;
            let mut control = self.control()?;
            control.insert("stopped".into(), json!(true));
            control.insert("stopped_at".into(), json!(iso(Some(self.now()))));
            self.state.write_json(CONTROL, &Value::Object(control))?;
        }
        self.notify_revoke("stop", None);
        Ok(())
    }

    /// `open_incident = control.get("incident_open"); if open_incident: raise
    /// InvalidInput("incident_open", open_incident)`: Python's `if` is plain
    /// truthiness over *any* stored type, not an `isinstance(str)` narrowing
    /// -- unlike [`Policy::open_incident_id`] below, which deliberately does
    /// narrow with `isinstance(str)` and is unaffected. A stored
    /// `incident_open` of `5`, `["x"]` or `{"a": 1}` is truthy in Python and
    /// refuses the resume; the previous `.and_then(Value::as_str).filter(|s|
    /// !s.is_empty())` here only recognised a non-empty *string*, so those
    /// shapes silently cleared the global stop instead (finding D-R4-1, a
    /// fail-open lockdown-gate bug). `InvalidInput`'s `detail` passes the raw
    /// value in Python (formatted via `str()` wherever the exception is
    /// stringified/`to_dict()`-ed); `Error::detail` here is a plain `String`
    /// (PORTING.md has no primitive for an arbitrary JSON `detail`), so
    /// [`python_str_for_error`] reproduces that `str()` formatting -- see
    /// `rust/DEVIATIONS.md`.
    pub fn resume(&self) -> Result<(), Error> {
        let _lock = self.state.lock()?;
        let mut control = self.control()?;
        let open_incident = control.get("incident_open").cloned();
        if json_truthy(open_incident.as_ref()) {
            let open_incident = open_incident.expect("truthy implies present");
            return Err(Error::new(
                ErrorClass::InvalidInput,
                "incident_open",
                python_str_for_error(&open_incident),
            ));
        }
        control.insert("stopped".into(), json!(false));
        self.state.write_json(CONTROL, &Value::Object(control))
    }

    pub fn is_stopped(&self) -> Result<bool, Error> {
        Ok(json_truthy(self.control()?.get("stopped")))
    }

    // ------------------ compromise-response incidents (docs/compromise-response.md)
    /// The currently open incident's id, or `None` while `resume()` is
    /// allowed.
    pub fn open_incident_id(&self) -> Result<Option<String>, Error> {
        Ok(self
            .control()?
            .get("incident_open")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string))
    }

    /// Record (or clear) the open incident. While set, `resume` is refused.
    pub fn set_open_incident(&self, incident_id: Option<&str>) -> Result<(), Error> {
        let _lock = self.state.lock()?;
        let mut control = self.control()?;
        control.insert(
            "incident_open".into(),
            match incident_id {
                Some(s) => json!(s),
                None => Value::Null,
            },
        );
        self.state.write_json(CONTROL, &Value::Object(control))
    }

    pub fn set_restore_pending(&self, pending: bool) -> Result<(), Error> {
        {
            let _lock = self.state.lock()?;
            let mut control = self.control()?;
            control.insert("restore_pending".into(), json!(pending));
            self.state.write_json(CONTROL, &Value::Object(control))?;
        }
        if pending {
            self.notify_revoke("restore", None);
        }
        Ok(())
    }

    pub fn restore_pending(&self) -> Result<bool, Error> {
        Ok(json_truthy(self.control()?.get("restore_pending")))
    }

    // ------------------------------------------------------------ approvals
    fn approval_expired(entry: &Map<String, Value>, now: f64) -> bool {
        match entry.get("expires_at") {
            // `isinstance(expires, bool) or not isinstance(expires, (int, float))`:
            // any JSON number (int or float) is accepted; anything else
            // (including a JSON bool, which `as_f64` never returns a value
            // for) means "entries without an expiry (older state) are never
            // usable".
            Some(Value::Number(n)) => match n.as_f64() {
                Some(f) => now >= f,
                // `as_f64` is `None` for a literal whose magnitude
                // overflows `f64` (finding D-R5-1's other call site):
                // CPython's `isinstance(expires, (int, float))` still
                // accepts an out-of-`f64`-range `int` and compares it by
                // real value. `now` is always a small, finite timestamp,
                // so it can never reach a magnitude this large either way
                // -- a positive overflow (`expires` is enormous) is never
                // expired, a negative overflow (`expires` is enormously
                // negative) always is. The sign of the literal alone
                // (without parsing the magnitude) decides which.
                None => number_literal_is_negative(n),
            },
            _ => true,
        }
    }

    fn close_approval(
        entry: &mut Map<String, Value>,
        status: &str,
        reason: Option<&str>,
        now: f64,
    ) {
        entry.insert("status".into(), json!(status));
        entry.insert(format!("{status}_at"), json!(iso(Some(now))));
        if let Some(r) = reason {
            entry.insert("closed_reason".into(), json!(r));
        }
    }

    /// Close every open approval matching `predicate`. Call with the state
    /// lock held.
    ///
    /// `pub(crate)`: called directly by `zeropw/team/fold.py` and
    /// `zeropw/team/membership.py` as `ctx.policy._invalidate_approvals`.
    /// `predicate` may fail (round 6): `credential_versions_changed`'s and
    /// `reapply_revocations`'s own predicates do a raw Python `in <set>`
    /// test against a stored field that can be any JSON shape, which raises
    /// an uncaught `TypeError: unhashable type` for a list/object value --
    /// *after* this same call may already have closed and written earlier
    /// approvals in this same loop (Python's `for entry in
    /// approvals.values():` has no exception handling, so a later entry's
    /// unhashable field aborts mid-iteration, keeping every already-applied
    /// mutation to `control` **in memory**, but `self.state.write_json`
    /// only runs once, *after* the loop, in both languages -- so `control`
    /// on disk is untouched by this call either way, matching Python's own
    /// all-or-nothing write here (finding, round 6 differential harness).
    ///
    /// Thin infallible wrapper kept for existing callers outside this
    /// module (`team::fold`, `team::membership`) whose predicates only ever
    /// do a plain `==` comparison, which never raises in Python -- see
    /// [`Policy::invalidate_approvals_fallible`] for the `Result`-returning
    /// form this module's own `in <set>`-based predicates use (round 6).
    pub(crate) fn invalidate_approvals(
        &self,
        predicate: impl Fn(&Map<String, Value>) -> bool,
        reason: &str,
    ) -> Result<usize, Error> {
        self.invalidate_approvals_fallible(|e| Ok(predicate(e)), reason)
    }

    pub(crate) fn invalidate_approvals_fallible(
        &self,
        predicate: impl Fn(&Map<String, Value>) -> Result<bool, Error>,
        reason: &str,
    ) -> Result<usize, Error> {
        let mut control = self.control()?;
        let now = self.now();
        let mut count = 0usize;
        // `approvals = control.get("approvals") or {}`: Python's `or` falls
        // back to `{}` only for a *falsy* stored value (or an absent key);
        // a *truthy* non-dict value (`"x"`, `[1]`, `5`) is kept as-is, and
        // the subsequent `approvals.values()` raises an uncaught
        // `AttributeError` -- the same `control`-document corruption shape
        // `Policy::control` itself already fails closed on (finding
        // D-R3-2's sweep), not a silent no-op success.
        match control.get("approvals") {
            None => {}
            Some(v) if !json_truthy(Some(v)) => {}
            Some(Value::Object(_)) => {
                let approvals = control
                    .get_mut("approvals")
                    .and_then(Value::as_object_mut)
                    .expect("just matched Object");
                for entry in approvals.values_mut() {
                    let Some(obj) = entry.as_object_mut() else {
                        continue;
                    };
                    let status = obj.get("status").and_then(Value::as_str).unwrap_or("");
                    if OPEN_APPROVAL_STATES.contains(&status) && predicate(obj)? {
                        Self::close_approval(obj, "invalidated", Some(reason), now);
                        count += 1;
                    }
                }
            }
            Some(_) => return Err(Error::state("state_corrupt").with_detail(CONTROL)),
        }
        if count > 0 {
            self.state.write_json(CONTROL, &Value::Object(control))?;
        }
        Ok(count)
    }

    fn archive_approval(
        control: &mut Map<String, Value>,
        digest: &str,
        entry: &Map<String, Value>,
    ) -> Result<(), Error> {
        let arr = setdefault_arr(control, "approval_history")?;
        let mut item = Map::new();
        item.insert("digest".into(), json!(digest));
        for (k, v) in entry {
            item.insert(k.clone(), v.clone());
        }
        arr.push(Value::Object(item));
        if arr.len() > APPROVAL_HISTORY_LIMIT {
            let excess = arr.len() - APPROVAL_HISTORY_LIMIT;
            arr.drain(0..excess);
        }
        Ok(())
    }

    /// `_usable_grant_id`: unlike most of this module's internal helpers,
    /// Python's `_decide(...)` here is *not* wrapped in a `try`/`except` --
    /// an exception (e.g. `StateError` on corrupt state) propagates straight
    /// out of `_usable_grant_id` and out of `request_approval`, which writes
    /// nothing in that case. `.ok()?` previously swallowed every error the
    /// same way a caught-and-discarded exception would, which is wrong: it
    /// let `request_approval` silently write an approval with `"grant":
    /// null` instead of failing (matching Python's `AttributeError`-adjacent
    /// crash-and-write-nothing behaviour).
    fn usable_grant_id(&self, caller: &str, connection_id: &str) -> Result<Option<String>, Error> {
        let decision = self.decide(caller, connection_id, None, None)?;
        Ok(if decision.allowed {
            decision.grant.map(|g| g.id)
        } else {
            None
        })
    }

    /// Open (or return the open) approval for `digest`.
    ///
    /// The entry records the grant and connection policy version in use and
    /// expires after [`APPROVAL_TTL_SECONDS`]. A digest whose previous
    /// entry was consumed, expired or invalidated gets a new pending cycle,
    /// so a request that used up its approval without being sent can be
    /// approved again.
    pub fn request_approval(
        &self,
        digest: &str,
        caller: &str,
        connection: &str,
        method: &str,
        path: &str,
    ) -> Result<Value, Error> {
        let now = self.now();
        let _lock = self.state.lock()?;
        let mut control = self.control()?;
        setdefault_obj(&mut control, "approvals")?;
        let mut cycle: i64 = 1;
        let existing = control
            .get("approvals")
            .and_then(Value::as_object)
            .and_then(|a| a.get(digest))
            .cloned();
        if let Some(entry_val) = existing
            && let Some(entry_obj) = entry_val.as_object()
        {
            let status = entry_obj
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("");
            if OPEN_APPROVAL_STATES.contains(&status) && !Self::approval_expired(entry_obj, now) {
                return Ok(entry_val.clone());
            }
            let mut entry_mut = entry_obj.clone();
            if OPEN_APPROVAL_STATES.contains(&status) {
                Self::close_approval(&mut entry_mut, "expired", Some("approval_expired"), now);
            }
            Self::archive_approval(&mut control, digest, &entry_mut)?;
            // `cycle = int(entry.get("cycle") or 1) + 1`: Python's `or`
            // falls back to `1` for any *falsy* stored `cycle` (`0`,
            // `null`, `""`, missing), not just a missing one; a truthy
            // value still goes through `int()`'s full coercion (a numeric
            // string, a float truncated toward zero, a bool) rather than a
            // plain `as_i64` (finding D-R2-8). A truthy value `int()`
            // itself cannot coerce (`[1]`, `{"a":1}`, `"abc"`, ...) is a
            // genuinely uncaught `TypeError`/`ValueError` in Python
            // (§3.5) -- fail closed instead of silently substituting `1`
            // and completing the write (finding D-R3-8).
            let raw_cycle = entry_mut.get("cycle").cloned();
            let base = if json_truthy(raw_cycle.as_ref()) {
                python_int_coerce(raw_cycle.as_ref().expect("truthy implies present"))
                    .ok_or_else(|| Error::state("state_corrupt").with_detail(CONTROL))?
            } else {
                1
            };
            // Finding D-R7-1: `base + 1` panics (debug) / wraps (release)
            // at the `i64` boundary, where Python's arbitrary-precision
            // `int` succeeds (measured: `cycle: 2**63-1` writes `cycle:
            // 9223372036854775808`). `checked_add` fails closed instead.
            cycle = base
                .checked_add(1)
                .ok_or_else(|| Error::state("state_corrupt").with_detail(CONTROL))?;
        }
        let evaluated = self.recall_pair(caller, connection);
        let mut policy_version = match self.get_connection(connection) {
            Ok(c) => Some(c.policy_version),
            Err(e) if e.is(ErrorClass::NotFound) => None,
            Err(e) => return Err(e),
        };
        if let Some(ev) = &evaluated
            && Some(ev.policy_version) != policy_version
        {
            policy_version = Some(ev.policy_version);
        }
        let grant = match &evaluated {
            Some(ev) => Some(ev.grant.clone()),
            None => self.usable_grant_id(caller, connection)?,
        };
        let entry = json!({
            "caller": caller, "connection": connection, "method": method, "path": path,
            "status": "pending", "created_at": iso(Some(now)), "expires_at": now + APPROVAL_TTL_SECONDS,
            "grant": grant, "policy_version": policy_version, "cycle": cycle,
        });
        as_obj_mut(control.get_mut("approvals").expect("just ensured"))?
            .insert(digest.to_string(), entry.clone());
        self.state.write_json(CONTROL, &Value::Object(control))?;
        Ok(entry)
    }

    pub fn approve(&self, digest: &str) -> Result<Value, Error> {
        let now = self.now();
        let _lock = self.state.lock()?;
        let mut control = self.control()?;
        let result;
        {
            // `control.get("approvals", {}).get(digest)`: a read, not a
            // `setdefault` -- an absent key uses the `{}` default (never
            // written back), and a present non-object value raises the same
            // uncaught `AttributeError` any other `.get()` on it would
            // (finding D-R3-2), never silently replaced.
            let approvals_obj = match control.get_mut("approvals") {
                None => None,
                Some(v) => Some(as_obj_mut(v)?),
            };
            let entry = approvals_obj
                .and_then(|a| a.get_mut(digest))
                .ok_or_else(|| Error::not_found("approval_not_found"))?;
            let entry_obj = as_obj_mut(entry)?;
            if entry_obj.get("status").and_then(Value::as_str) != Some("pending") {
                return Err(Error::invalid_input("approval_not_pending"));
            }
            if Self::approval_expired(entry_obj, now) {
                Self::close_approval(entry_obj, "expired", Some("approval_expired"), now);
                self.state.write_json(CONTROL, &Value::Object(control))?;
                return Err(Error::invalid_input("approval_expired"));
            }
            entry_obj.insert("status".into(), json!("approved"));
            entry_obj.insert("approved_at".into(), json!(iso(Some(now))));
            entry_obj.insert("expires_at".into(), json!(now + APPROVAL_TTL_SECONDS));
            result = Value::Object(entry_obj.clone());
        }
        self.state.write_json(CONTROL, &Value::Object(control))?;
        Ok(result)
    }

    /// Use an approved, unexpired approval once.
    ///
    /// It must still match the grant and the connection policy version it
    /// was requested under. `grant_id`/`policy_version` name what the
    /// caller is about to use; when omitted, the last allowed `evaluate`
    /// for this caller and connection in the current thread supplies them.
    /// A mismatch or expiry closes the approval (the next request opens a
    /// new cycle).
    pub fn consume_approval(
        &self,
        digest: &str,
        caller: &str,
        connection: &str,
        grant_id: Option<&str>,
        policy_version: Option<i64>,
    ) -> Result<bool, Error> {
        let now = self.now();
        let _lock = self.state.lock()?;
        let mut control = self.control()?;
        // `control.get("approvals", {}).get(digest)`: an absent key uses the
        // `{}` default (found -> `False`, no write); a present non-object
        // value raises the same uncaught `AttributeError` any other
        // `.get()` on it would (finding D-R3-2), not a silent `false`.
        let approvals = match control.get_mut("approvals") {
            None => return Ok(false),
            Some(v) => as_obj_mut(v)?,
        };
        let Some(entry) = approvals.get_mut(digest) else {
            return Ok(false);
        };
        let Some(entry_obj) = entry.as_object_mut() else {
            return Ok(false);
        };
        if entry_obj.get("status").and_then(Value::as_str) != Some("approved") {
            return Ok(false);
        }
        if entry_obj.get("caller").and_then(Value::as_str) != Some(caller)
            || entry_obj.get("connection").and_then(Value::as_str) != Some(connection)
        {
            return Ok(false);
        }
        let evaluated = self.recall_pair(caller, connection);
        let in_use_grant: Option<String> = grant_id
            .map(str::to_string)
            .or_else(|| evaluated.as_ref().map(|e| e.grant.clone()));
        let in_use_version: Option<i64> =
            policy_version.or_else(|| evaluated.as_ref().map(|e| e.policy_version));
        let reason = self.approval_mismatch(
            entry_obj,
            caller,
            connection,
            in_use_grant.as_deref(),
            in_use_version,
            now,
        )?;
        if let Some(reason) = reason {
            let status = if reason == "approval_expired" {
                "expired"
            } else {
                "invalidated"
            };
            Self::close_approval(entry_obj, status, Some(reason), now);
            self.state.write_json(CONTROL, &Value::Object(control))?;
            return Ok(false);
        }
        entry_obj.insert("status".into(), json!("consumed"));
        entry_obj.insert("consumed_at".into(), json!(iso(Some(now))));
        if let Some(g) = &in_use_grant {
            entry_obj.insert("consumed_grant".into(), json!(g));
        }
        self.state.write_json(CONTROL, &Value::Object(control))?;
        Ok(true)
    }

    fn approval_mismatch(
        &self,
        entry: &Map<String, Value>,
        caller: &str,
        connection_id: &str,
        in_use_grant: Option<&str>,
        in_use_version: Option<i64>,
        now: f64,
    ) -> Result<Option<&'static str>, Error> {
        if Self::approval_expired(entry, now) {
            return Ok(Some("approval_expired"));
        }
        let connection = match self.get_connection(connection_id) {
            Ok(c) => c,
            Err(e) if e.is(ErrorClass::NotFound) => return Ok(Some("connection_unknown")),
            Err(e) => return Err(e),
        };
        // `recorded_version != connection.policy_version`: Python compares
        // the raw stored value using numeric equality (see
        // [`python_numeric_eq`]), not `as_i64` (finding D-R3-9's sweep) --
        // a stored float/bool `policy_version` that is numerically equal
        // must not be reported as a mismatch.
        if !python_numeric_eq(entry.get("policy_version"), connection.policy_version) {
            return Ok(Some("policy_changed"));
        }
        if let Some(v) = in_use_version
            && v != connection.policy_version
        {
            return Ok(Some("policy_changed"));
        }
        // `recorded_grant = entry.get("grant")`: Python checks `is not
        // None`, so a present *non-string* value (e.g. `5`) is not skipped
        // -- it reaches `self.get_grant(recorded_grant)` ->
        // `self._grants().get(recorded_grant)`, a `dict.get()` call.
        //
        // **Round-7 correction (finding D-R7-4):** the previous single
        // `Some(_) => return Ok(Some("grant_changed"))` arm treated every
        // non-string, non-null shape alike, but Python's `dict.get()`
        // behaves very differently depending on whether the value is
        // *hashable*. A hashable non-string (a JSON number or bool, `int`/
        // `bool` in Python) can be looked up like any other key: it is
        // never found (grant ids are strings), so `.get()` returns `None`,
        // `get_grant` raises the documented `NotFound`, and
        // `_approval_mismatch` maps that to `"grant_changed"` -- this
        // crate's existing behaviour for that shape is correct.  An
        // *unhashable* value (a JSON array or object, `list`/`dict` in
        // Python) makes `dict.get()` itself raise an uncaught `TypeError:
        // unhashable type`, propagating straight out of `consume_approval`
        // -- Python writes nothing. Measured directly: a stored `"grant":
        // [1]` gives `py=BuiltinErr` where this crate previously gave
        // `rust=Ok(Bool(false))` *and* persisted a closed
        // `invalidated`/`grant_changed` approval to `control.json` --
        // PORTING.md §3.5 permits mapping Python's uncaught `TypeError` to
        // a handled *error*, never to a successful `Ok(false)` plus a
        // state write. (`Policy::approval_matches_grant`, `rust/src/
        // policy.rs`'s other `entry.get("grant")` reader, is unaffected:
        // it compares with plain `==`, which never raises for any type in
        // Python, so its existing `Some(_) => false` arm was already
        // correct and needs no change.)
        match entry.get("grant") {
            None | Some(Value::Null) => {}
            Some(Value::String(recorded_grant)) => {
                if let Some(iug) = in_use_grant
                    && iug != recorded_grant
                {
                    return Ok(Some("grant_changed"));
                }
                let grant = match self.get_grant(recorded_grant) {
                    Ok(g) => g,
                    Err(e) if e.is(ErrorClass::NotFound) => return Ok(Some("grant_changed")),
                    Err(e) => return Err(e),
                };
                if grant.principal != caller || grant.connection != connection_id {
                    return Ok(Some("grant_changed"));
                }
                if let Some(state) = self.grant_state(&grant, &connection)? {
                    return Ok(Some(state));
                }
            }
            // Hashable, never found: `NotFound` -> `"grant_changed"`.
            Some(Value::Number(_)) | Some(Value::Bool(_)) => {
                return Ok(Some("grant_changed"));
            }
            // Unhashable: Python's `dict.get()` itself raises uncaught
            // `TypeError`, not caught anywhere between there and
            // `consume_approval`'s caller -- the closest handled error
            // (§3.5), propagated via `?` so nothing is written.
            Some(Value::Array(_)) | Some(Value::Object(_)) => {
                return Err(Error::state("state_corrupt").with_detail(CONTROL));
            }
        }
        Ok(None)
    }

    pub fn list_approvals(&self) -> Result<Map<String, Value>, Error> {
        let control = self.control()?;
        python_dict_coerce(control.get("approvals"))
    }

    pub fn approval_history(&self) -> Result<Vec<Value>, Error> {
        let control = self.control()?;
        python_list_coerce(control.get("approval_history"))
    }

    // -------------------------------------------------------------- restore
    /// Apply every known revocation to the current policy documents
    /// (idempotent).
    ///
    /// Used after a restore: the archive may pre-date revocations, and a
    /// restore must never bring a revoked grant, a disabled principal or a
    /// disabled connection back. Returns how many records had to change.
    pub fn reapply_revocations(
        &self,
        revocations: &Revocations,
    ) -> Result<HashMap<&'static str, usize>, Error> {
        let mut counts: HashMap<&'static str, usize> =
            HashMap::from([("grants", 0), ("principals", 0), ("connections", 0)]);
        let _lock = self.state.lock()?;
        let now = iso(Some(self.now()));
        // `grants = self._grants()` (`self.state.read_json(GRANTS, {}) or
        // {}`) runs unconditionally in Python -- `read_json` reads the file
        // and calls `json.loads` on it regardless of whether
        // `revocations.grants` has anything in it, so a genuinely
        // unparseable `policy/grants.json` raises there every time.
        // Python's own laziness is a *different*, narrower thing: `or {}`
        // never validates the parsed document's *shape*, so a truthy
        // non-dict read (e.g. the file holding a bare JSON string) is
        // returned exactly as read, and the `TypeError`/`AttributeError`
        // that shape would eventually cause only fires inside the `for
        // grant_id in revocations.grants: entry = grants.get(grant_id)`
        // loop's first `.get()` call -- which only runs at all when the set
        // is non-empty.
        //
        // **Round-7 correction (finding D-R7-2):** the previous fix here
        // (cross-unit finding E-R5-3, round 6) gated the *entire* read --
        // including the parse itself -- on `!revocations.grants.is_empty()`,
        // so an unparseable `grants.json` with an empty revocation set was
        // silently ignored where Python still raises. Measured directly:
        // `policy/grants.json = "{not json"` with every revocation set
        // empty raises `StateError state_corrupt policy/grants.json` in
        // Python; this port previously returned `Ok([("connections", 0),
        // ("grants", 0), ("principals", 0)])`. Reachable via
        // `Vault::restore` on a state directory with a truncated/corrupt
        // policy document: Python aborts the restore with `StateError`,
        // where this port reported "0 reapplied", rotated the handle key
        // and wrote a *successful* `restore` audit record.
        //
        // Fixed by splitting the read (`self.state.read_json` -- always,
        // propagating a parse failure via `?` regardless of the set) from
        // the shape check ([`Policy::shape_doc`] -- still only reached, as
        // in Python, once there is at least one id to look up), preserving
        // round 6's own laziness fix for the narrower shape-only case
        // (E-R5-3) while no longer swallowing a genuine parse failure.
        let grants_raw = self.state.read_json(GRANTS, json!({}))?;
        if !revocations.grants.is_empty() {
            let mut grants = Self::shape_doc(grants_raw, GRANTS)?;
            for grant_id in &revocations.grants {
                if let Some(entry) = grants.get_mut(grant_id).and_then(Value::as_object_mut)
                    && entry.get("status").and_then(Value::as_str) != Some("revoked")
                {
                    entry.insert("status".into(), json!("revoked"));
                    // `entry["revoked_at"] = entry.get("revoked_at") or now`:
                    // Python's `or` keeps *any* truthy stored value verbatim
                    // (even a non-string one), replacing only a falsy one
                    // (`None`, `""`, `0`, ...) with `now` (finding D-R2-9).
                    let existing_revoked_at = entry.get("revoked_at").cloned();
                    let revoked_at = if json_truthy(existing_revoked_at.as_ref()) {
                        existing_revoked_at.unwrap()
                    } else {
                        json!(now.clone())
                    };
                    entry.insert("revoked_at".into(), revoked_at);
                    *counts.get_mut("grants").unwrap() += 1;
                }
            }
            if counts["grants"] > 0 {
                self.state.write_json(GRANTS, &Value::Object(grants))?;
            }
        }
        // Finding D-R7-2, same fix as `grants` above: `self._principals()`
        // runs unconditionally in Python.
        let principals_raw = self.state.read_json(PRINCIPALS, json!({}))?;
        if !revocations.principals.is_empty() {
            let mut principals = Self::shape_doc(principals_raw, PRINCIPALS)?;
            for principal_id in &revocations.principals {
                if let Some(entry) = principals
                    .get_mut(principal_id)
                    .and_then(Value::as_object_mut)
                    && entry.get("status").and_then(Value::as_str) != Some("disabled")
                {
                    entry.insert("status".into(), json!("disabled"));
                    *counts.get_mut("principals").unwrap() += 1;
                }
            }
            if counts["principals"] > 0 {
                self.state
                    .write_json(PRINCIPALS, &Value::Object(principals))?;
            }
        }
        // Finding D-R7-2, same fix as `grants` above: `self._connections()`
        // runs unconditionally in Python.
        let connections_raw = self.state.read_json(CONNECTIONS, json!({}))?;
        if !revocations.connections.is_empty() {
            let mut connections = Self::shape_doc(connections_raw, CONNECTIONS)?;
            for connection_id in &revocations.connections {
                if let Some(entry) = connections
                    .get_mut(connection_id)
                    .and_then(Value::as_object_mut)
                    && entry.get("status").and_then(Value::as_str) != Some("disabled")
                {
                    entry.insert("status".into(), json!("disabled"));
                    // `int(entry.get("policy_version", 0)) + 1`: `int()`
                    // coerces a numeric string/float/bool the same way
                    // `python_int_coerce` does, not just a plain integer
                    // (finding D-R2-9). The `0` default only applies when the
                    // key is *absent* -- `.get(key, default)` only falls back
                    // for a missing key, not a present-but-uncoercible one
                    // (including an explicit `null`); §3.5 allows the closest
                    // handled error for a value `int()` itself would reject,
                    // not a silently substituted default that completes the
                    // write (finding D-R3-8).
                    // Finding D-R7-1: the trailing `+ 1` panics (debug) /
                    // wraps (release) at the `i64` boundary, where Python's
                    // arbitrary-precision `int` succeeds (measured:
                    // `policy_version: 2**63-1` -> `reapply` succeeds,
                    // writing `9223372036854775808`). `checked_add` fails
                    // closed instead.
                    let pv = match entry.get("policy_version") {
                        None => 0,
                        Some(v) => python_int_coerce(v).ok_or_else(|| {
                            Error::state("state_corrupt").with_detail("connection")
                        })?,
                    }
                    .checked_add(1)
                    .ok_or_else(|| Error::state("state_corrupt").with_detail("connection"))?;
                    entry.insert("policy_version".into(), json!(pv));
                    entry.insert("updated_at".into(), json!(now.clone()));
                    *counts.get_mut("connections").unwrap() += 1;
                }
            }
            if counts["connections"] > 0 {
                self.state
                    .write_json(CONNECTIONS, &Value::Object(connections))?;
            }
        }
        let revocations = revocations.clone();
        self.invalidate_approvals_fallible(
            move |e| {
                // `e.get("grant") in revocations.grants or e.get("caller") in
                // revocations.principals or e.get("connection") in
                // revocations.connections`: Python's `or` short-circuits, so
                // the second/third `in` test is never even reached once an
                // earlier one is `True` -- but each is still its own
                // unhashable-raising `in <set>` test (round 6), not a plain
                // `==`.
                Ok(value_in_str_set(e.get("grant"), &revocations.grants)?
                    || value_in_str_set(e.get("caller"), &revocations.principals)?
                    || value_in_str_set(e.get("connection"), &revocations.connections)?)
            },
            "revoked_before_restore",
        )?;
        Ok(counts)
    }

    // ----------------------------------------------------------- evaluation
    fn grant_state(
        &self,
        grant: &Grant,
        connection: &Connection,
    ) -> Result<Option<&'static str>, Error> {
        if grant.status_is("revoked") {
            return Ok(Some("grant_revoked"));
        }
        if grant.status_is("stale")
            || grant_num_ne_i64(&grant.raw_policy_version, connection.policy_version)
        {
            return Ok(Some("grant_stale"));
        }
        if !grant.status_is("active") {
            return Ok(Some("grant_inactive"));
        }
        // `grant.expires_at is not None and self.clock() >= grant.expires_at`:
        // the guard is `is not None`, not truthiness -- unlike
        // `public_view`'s `if self.expires_at`, a *falsy-but-not-`None`*
        // value (`""`, `[]`, `{}`, `0`) still reaches the `>=` comparison
        // here, which raises the closest handled error for a non-numeric
        // value (PORTING.md §3.5).
        if let Some(exp_val) = &grant.raw_expires_at {
            let exceeded = now_at_least_exact(self.now(), exp_val)
                .ok_or_else(|| Error::state("state_corrupt").with_detail("grant"))?;
            if exceeded {
                return Ok(Some("grant_expired"));
            }
        }
        if let Some(max) = &grant.raw_max_uses
            && grant_num_ge(&grant.raw_uses, max)?
        {
            return Ok(Some("grant_exhausted"));
        }
        Ok(None)
    }

    /// Full decision for one operation (lock-free read).
    ///
    /// An allowed decision is remembered for the current thread so that the
    /// matching [`Policy::consume`] re-applies the same operation scope and
    /// requires the same connection policy version under the state lock.
    pub fn evaluate(
        &self,
        caller: &str,
        connection_id: &str,
        action: &Action,
        grant_id: Option<&str>,
    ) -> Result<Decision, Error> {
        let decision = self.decide(caller, connection_id, Some(action), grant_id)?;
        self.remember(caller, action, &decision);
        Ok(decision)
    }

    /// Is this (caller, connection, grant) still usable at all, independent
    /// of any one operation?
    ///
    /// Checks restore-pending, global stop, principal, connection and grant
    /// state; no scope check. Used to find running executions and signer
    /// sockets whose permission was withdrawn by another process.
    pub fn check_grant(
        &self,
        caller: &str,
        connection_id: &str,
        grant_id: &str,
    ) -> Result<Decision, Error> {
        self.decide(caller, connection_id, None, Some(grant_id))
    }

    fn scope_reason(connection: &Connection, action: &Action) -> Option<&'static str> {
        if action.kind != connection.kind {
            return Some("action_kind_mismatch");
        }
        if connection.kind == "http" {
            let scope = connection
                .http_scope
                .as_ref()
                .expect("http connection always has http_scope");
            let Some(method) = action.method.as_deref() else {
                return Some("method_not_allowed");
            };
            if !HTTP_METHODS.contains(&method) {
                return Some("method_not_allowed");
            }
            if !scope.allows_method(method) {
                return Some("method_not_allowed");
            }
            let Some(path) = action.path.as_deref() else {
                return Some("path_not_allowed");
            };
            if !scope.allows_path(path) {
                return Some("path_not_allowed");
            }
            return None;
        }
        let target = connection
            .ssh_target
            .as_ref()
            .expect("ssh connection always has ssh_target");
        if action.username.as_deref() != Some(target.username.as_str()) {
            return Some("ssh_user_mismatch");
        }
        None
    }

    fn decide(
        &self,
        caller: &str,
        connection_id: &str,
        action: Option<&Action>,
        grant_id: Option<&str>,
    ) -> Result<Decision, Error> {
        let control = self.control()?;
        if json_truthy(control.get("restore_pending")) {
            return Ok(Decision::denied("restore_pending"));
        }
        if json_truthy(control.get("stopped")) {
            return Ok(Decision::denied("global_stop"));
        }
        let principal = match self.get_principal(caller) {
            Ok(p) => p,
            Err(e) if e.is(ErrorClass::NotFound) => {
                return Ok(Decision::denied("principal_unknown"));
            }
            Err(e) => return Err(e),
        };
        if principal.status != "active" {
            return Ok(Decision::denied("principal_disabled"));
        }
        let connection = match self.get_connection(connection_id) {
            Ok(c) => c,
            Err(e) if e.is(ErrorClass::NotFound) => {
                return Ok(Decision::denied("connection_unknown"));
            }
            Err(e) => return Err(e),
        };
        if connection.status != "active" {
            return Ok(Decision::denied_with_connection(
                "connection_disabled",
                connection,
            ));
        }
        if let Some(a) = action
            && a.kind != connection.kind
        {
            return Ok(Decision::denied_with_connection(
                "action_kind_mismatch",
                connection,
            ));
        }
        let candidates: Vec<Grant> = if let Some(gid) = grant_id {
            let grant = match self.get_grant(gid) {
                Ok(g) => g,
                Err(e) if e.is(ErrorClass::NotFound) => {
                    return Ok(Decision::denied_with_connection(
                        "grant_unknown",
                        connection,
                    ));
                }
                Err(e) => return Err(e),
            };
            if grant.principal != caller || grant.connection != connection_id {
                return Ok(Decision::denied_with_connection(
                    "grant_mismatch",
                    connection,
                ));
            }
            vec![grant]
        } else {
            let all = self.list_grants(Some(caller))?;
            let candidates: Vec<Grant> = all
                .into_iter()
                .filter(|g| g.connection == connection_id)
                .collect();
            if candidates.is_empty() {
                return Ok(Decision::denied_with_connection("no_grant", connection));
            }
            candidates
        };
        let mut failure: &'static str = "no_grant";
        let mut chosen: Option<Grant> = None;
        for grant in candidates {
            match self.grant_state(&grant, &connection)? {
                None => {
                    chosen = Some(grant);
                    break;
                }
                Some(state) => failure = state,
            }
        }
        let Some(chosen) = chosen else {
            return Ok(Decision::denied_with_connection(failure, connection));
        };
        if let Some(a) = action
            && let Some(reason) = Self::scope_reason(&connection, a)
        {
            return Ok(Decision::new(false, reason, Some(chosen), Some(connection)));
        }
        Ok(Decision::new(
            true,
            "allowed",
            Some(chosen),
            Some(connection),
        ))
    }

    /// The authoritative last-moment decision, then count one use (default
    /// deny).
    ///
    /// Everything is re-read under the state lock, so an administrator
    /// change committed by any process before this call is honoured:
    /// restore-pending, global stop, principal and connection status, grant
    /// state (revoked, stale, expired, exhausted), the operation's scope
    /// and the connection policy version. `action` and `policy_version`
    /// name the operation and the version the caller evaluated (for a
    /// handle: the handle's version). When omitted, the last allowed
    /// `evaluate` of this grant in the current thread supplies them, so the
    /// relay and the signer are held to exactly what they were allowed a
    /// moment earlier. A policy version that moved since then refuses with
    /// `grant_stale`: the caller's connection snapshot (target, credential
    /// version) is no longer current.
    pub fn consume(
        &self,
        grant_id: &str,
        caller: Option<&str>,
        connection_id: Option<&str>,
        action: Option<Action>,
        policy_version: Option<i64>,
    ) -> Result<Grant, Error> {
        let evaluated = self.recall_pop(grant_id);
        let mut action = action;
        let mut policy_version = policy_version;
        if let Some(ev) = &evaluated {
            if action.is_none() {
                action = Some(ev.action.clone());
            }
            if policy_version.is_none() {
                policy_version = Some(ev.policy_version);
            }
        }
        let _lock = self.state.lock()?;
        let mut doc = self.grants()?;
        let entry = doc
            .get(grant_id)
            .ok_or_else(|| Error::policy_denied("grant_unknown"))?;
        let grant = Grant::from_value(entry)?;
        if let Some(c) = caller
            && c != grant.principal
        {
            return Err(Error::policy_denied("grant_mismatch"));
        }
        if let Some(cid) = connection_id
            && cid != grant.connection
        {
            return Err(Error::policy_denied("grant_mismatch"));
        }
        let decision = self.decide(
            &grant.principal,
            &grant.connection,
            action.as_ref(),
            Some(grant_id),
        )?;
        if !decision.allowed {
            return Err(Error::policy_denied(decision.reason));
        }
        let connection = decision
            .connection
            .expect("allowed decision always carries a connection");
        if let Some(pv) = policy_version
            && pv != connection.policy_version
        {
            return Err(Error::policy_denied("grant_stale"));
        }
        let obj = doc
            .get_mut(grant_id)
            .and_then(Value::as_object_mut)
            .expect("checked above");
        obj.insert("uses".into(), grant_num_add_one(&grant.raw_uses)?);
        let updated_entry = Value::Object(obj.clone());
        self.state.write_json(GRANTS, &Value::Object(doc))?;
        Grant::from_value(&updated_entry)
    }

    /// Connections the caller may use right now, with the grant that allows
    /// each.
    pub fn usable_connections(&self, caller: &str) -> Result<Vec<(Connection, Grant)>, Error> {
        let control = self.control()?;
        if json_truthy(control.get("restore_pending")) || json_truthy(control.get("stopped")) {
            return Ok(Vec::new());
        }
        let mut result = Vec::new();
        for grant in self.list_grants(Some(caller))? {
            let connection = match self.get_connection(&grant.connection) {
                Ok(c) => c,
                Err(e) if e.is(ErrorClass::NotFound) => continue,
                Err(e) => return Err(e),
            };
            if connection.status != "active" || self.grant_state(&grant, &connection)?.is_some() {
                continue;
            }
            result.push((connection, grant));
        }
        Ok(result)
    }
}

/// Port of `tests/test_core_policy.py`.
#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    use tempfile::TempDir;

    use super::*;

    /// Documents the `serde_json` `arbitrary_precision` behaviour
    /// [`number_is_python_int`] and [`validate_port_value`]/
    /// [`python_int_coerce`] rely on: an integer-literal token (even one too
    /// large for `i64`) round-trips through `Number`'s exact source text,
    /// while a float-literal token (containing `.`/`e`/`E`) is
    /// distinguishable from it.
    #[test]
    fn number_is_python_int_matches_json_literal_form() {
        let int_tok: Value = serde_json::from_str("8080").unwrap();
        let float_tok: Value = serde_json::from_str("8080.0").unwrap();
        let huge_int_tok: Value = serde_json::from_str("1180591620717411303424").unwrap();
        assert!(number_is_python_int(int_tok.as_number().unwrap()));
        assert!(!number_is_python_int(float_tok.as_number().unwrap()));
        assert!(number_is_python_int(huge_int_tok.as_number().unwrap()));
        assert_eq!(huge_int_tok.as_i64(), None);
    }

    /// Round-6 de-duplication (PORTING.md §3b, finding E-R6-1): a former
    /// local copy of `int(str)`'s grammar in `python_int_from_str` built the
    /// unsigned magnitude directly in `i64` via `checked_mul`/`checked_add`,
    /// which cannot hold `i64::MIN`'s own magnitude
    /// (`9223372036854775808`, one past `i64::MAX`) even momentarily, so
    /// `int("-9223372036854775808")` was wrongly rejected even though
    /// `i64::MIN` itself is representable -- the same shape of bug
    /// `vault.rs`'s `python_int_from_str` was already fixed for at finding
    /// E-R4-1. Delegating to `crate::pystr::int_from_str` (which parses the
    /// magnitude via `i128` before narrowing) fixes this as a byproduct.
    #[test]
    fn python_int_from_str_accepts_i64_min() {
        assert_eq!(python_int_from_str("-9223372036854775808"), Some(i64::MIN));
        assert_eq!(python_int_from_str("9223372036854775807"), Some(i64::MAX));
        assert_eq!(python_int_from_str("-9223372036854775809"), None); // one past i64::MIN
        assert_eq!(python_int_from_str("9223372036854775808"), None); // one past i64::MAX
    }

    fn new_state_and_clock() -> (TempDir, StateDir, Arc<Mutex<f64>>) {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        (tmp, state, Arc::new(Mutex::new(1_700_000_000.0)))
    }

    fn make_clock(val: &Arc<Mutex<f64>>) -> Clock {
        let val = val.clone();
        Arc::new(move || *val.lock().unwrap())
    }

    /// `setUp`: a fresh state dir, a fake clock and one active `"gh"` http
    /// connection, plus the `"agent-1"` principal's token.
    fn setup() -> (TempDir, StateDir, Arc<Mutex<f64>>, String) {
        let (tmp, state, clock_val) = new_state_and_clock();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let token = policy.create_principal("agent-1", "default").unwrap();
        policy.create_connection(http_connection("gh")).unwrap();
        (tmp, state, clock_val, token)
    }

    /// `with self.assertRaises(InvalidInput): ...`: the class matters, not
    /// just that construction failed somehow.
    fn assert_invalid_input<T: std::fmt::Debug>(r: Result<T, Error>) {
        assert!(r.unwrap_err().is(ErrorClass::InvalidInput));
    }

    /// `assert_consume_denied` (`tests/test_core_policy.py`): `consume`
    /// must both raise `PolicyDenied` and carry the expected `reason` --
    /// not just fail somehow.
    #[allow(clippy::too_many_arguments)]
    fn assert_consume_denied(
        policy: &Policy,
        grant_id: &str,
        caller: Option<&str>,
        connection_id: Option<&str>,
        action: Option<Action>,
        policy_version: Option<i64>,
        reason: &str,
    ) {
        let err = policy
            .consume(grant_id, caller, connection_id, action, policy_version)
            .unwrap_err();
        assert!(err.is(ErrorClass::PolicyDenied), "{err:?}");
        assert_eq!(err.reason, reason);
    }

    /// `http_connection(cid="gh", **overrides)` for the common case (no
    /// overrides): id `"gh"`, `GET`/`POST` on `/repos`, `/me`, `DELETE`
    /// needs approval.
    fn http_connection(id: &str) -> Connection {
        Connection::new(
            id,
            "demo",
            "dev",
            "fake-github",
            "http",
            "gh-token",
            None,
            "demo connection",
            Some(HttpTarget::new("http", "127.0.0.1", 8080, None, false).unwrap()),
            Some(HttpAuth::bearer()),
            Some(
                HttpScope::new(
                    Some(vec!["GET".into(), "POST".into()]),
                    Some(vec!["/repos".into(), "/me".into()]),
                    vec!["DELETE".into()],
                )
                .unwrap(),
            ),
            None,
            None,
            0,
            "active",
            "",
            "",
        )
        .unwrap()
    }

    fn http_connection_with_secret_version(id: &str, version: i64) -> Connection {
        Connection::new(
            id,
            "demo",
            "dev",
            "fake-github",
            "http",
            "gh-token",
            Some(version),
            "demo connection",
            Some(HttpTarget::new("http", "127.0.0.1", 8080, None, false).unwrap()),
            Some(HttpAuth::bearer()),
            Some(
                HttpScope::new(
                    Some(vec!["GET".into(), "POST".into()]),
                    Some(vec!["/repos".into(), "/me".into()]),
                    vec!["DELETE".into()],
                )
                .unwrap(),
            ),
            None,
            None,
            0,
            "active",
            "",
            "",
        )
        .unwrap()
    }

    fn ssh_connection(id: &str) -> Connection {
        Connection::new(
            id,
            "demo",
            "dev",
            "ssh-box",
            "ssh",
            "box-key",
            None,
            "",
            None,
            None,
            None,
            Some(
                SshTarget::new(
                    "127.0.0.1",
                    22,
                    "deploy",
                    vec![
                        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA host"
                            .to_string(),
                    ],
                )
                .unwrap(),
            ),
            None,
            0,
            "active",
            "",
            "",
        )
        .unwrap()
    }

    fn approval_helper(policy: &Policy, path: &str) -> String {
        let digest = approval_digest("agent-1", "gh", "DELETE", path, b"");
        policy
            .request_approval(&digest, "agent-1", "gh", "DELETE", path)
            .unwrap();
        digest
    }

    // ---------------------------------------------------------- principals
    #[test]
    fn principal_token_authenticates_and_is_hashed() {
        let (_tmp, state, clock_val, token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let principal = policy.authenticate(&token).unwrap();
        assert_eq!(principal.id, "agent-1");
        let text =
            std::fs::read_to_string(state.path.join("policy").join("principals.json")).unwrap();
        assert!(!text.contains(&token));
        assert!(
            policy
                .authenticate(&format!("{token}x"))
                .unwrap_err()
                .is(ErrorClass::AuthFailed)
        );
        assert!(
            policy
                .authenticate(&format!("zpwc_{}", "a".repeat(43)))
                .unwrap_err()
                .is(ErrorClass::AuthFailed)
        );
        assert!(
            policy
                .authenticate("")
                .unwrap_err()
                .is(ErrorClass::AuthFailed)
        );
    }

    #[test]
    fn disabled_principal_cannot_authenticate_or_use() {
        let (_tmp, state, clock_val, token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        policy.disable_principal("agent-1", true).unwrap();
        assert!(
            policy
                .authenticate(&token)
                .unwrap_err()
                .is(ErrorClass::AuthFailed)
        );
        let decision = policy
            .evaluate("agent-1", "gh", &Action::http("GET", "/repos"), None)
            .unwrap();
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "principal_disabled");
    }

    // ------------------------------------------------------- default deny
    #[test]
    fn no_grant_is_denied() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let decision = policy
            .evaluate("agent-1", "gh", &Action::http("GET", "/repos"), None)
            .unwrap();
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "no_grant");
        assert!(decision.require().unwrap_err().is(ErrorClass::PolicyDenied));
    }

    #[test]
    fn unknown_caller_and_connection_denied() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        assert_eq!(
            policy
                .evaluate("ghost", "gh", &Action::http("GET", "/repos"), None)
                .unwrap()
                .reason,
            "principal_unknown"
        );
        assert_eq!(
            policy
                .evaluate("agent-1", "nope", &Action::http("GET", "/repos"), None)
                .unwrap()
                .reason,
            "connection_unknown"
        );
    }

    #[test]
    fn one_connection_many_operations_without_registration() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        for (method, path) in [
            ("GET", "/repos"),
            ("POST", "/repos/demo/issues"),
            ("GET", "/me"),
            ("GET", "/repos/x/y/z"),
        ] {
            let decision = policy
                .evaluate("agent-1", "gh", &Action::http(method, path), None)
                .unwrap();
            assert!(decision.allowed, "{method} {path}: {}", decision.reason);
        }
    }

    #[test]
    fn scope_method_and_path_enforced() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        assert_eq!(
            policy
                .evaluate("agent-1", "gh", &Action::http("PUT", "/repos"), None)
                .unwrap()
                .reason,
            "method_not_allowed"
        );
        assert_eq!(
            policy
                .evaluate("agent-1", "gh", &Action::http("GET", "/admin"), None)
                .unwrap()
                .reason,
            "path_not_allowed"
        );
        assert_eq!(
            policy
                .evaluate("agent-1", "gh", &Action::http("GET", "/reposx"), None)
                .unwrap()
                .reason,
            "path_not_allowed"
        );
        assert_eq!(
            policy
                .evaluate("agent-1", "gh", &Action::http("TRACE", "/repos"), None)
                .unwrap()
                .reason,
            "method_not_allowed"
        );
        assert_eq!(
            policy
                .evaluate("agent-1", "gh", &Action::ssh("deploy"), None)
                .unwrap()
                .reason,
            "action_kind_mismatch"
        );
    }

    #[test]
    fn grant_is_bound_to_caller_and_connection() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let other_token = policy.create_principal("agent-2", "default").unwrap();
        assert!(other_token.starts_with("zpwc_"));
        policy.create_connection(http_connection("gh2")).unwrap();
        let grant = policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        assert_eq!(
            policy
                .evaluate("agent-2", "gh", &Action::http("GET", "/repos"), None)
                .unwrap()
                .reason,
            "no_grant"
        );
        assert_eq!(
            policy
                .evaluate("agent-1", "gh2", &Action::http("GET", "/repos"), None)
                .unwrap()
                .reason,
            "no_grant"
        );
        assert_eq!(
            policy
                .evaluate(
                    "agent-1",
                    "gh2",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id)
                )
                .unwrap()
                .reason,
            "grant_mismatch"
        );
        assert_eq!(
            policy
                .evaluate(
                    "agent-2",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id)
                )
                .unwrap()
                .reason,
            "grant_mismatch"
        );
    }

    // -------------------------------------------------- expiry / usage / revoke
    #[test]
    fn expiry_is_enforced_at_evaluation_time() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        policy
            .create_grant("agent-1", "gh", Some(100), None)
            .unwrap();
        assert!(
            policy
                .evaluate("agent-1", "gh", &Action::http("GET", "/repos"), None)
                .unwrap()
                .allowed
        );
        *clock_val.lock().unwrap() += 100.0;
        assert_eq!(
            policy
                .evaluate("agent-1", "gh", &Action::http("GET", "/repos"), None)
                .unwrap()
                .reason,
            "grant_expired"
        );
    }

    #[test]
    fn usage_cap_consumed_atomically() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let grant = policy
            .create_grant("agent-1", "gh", Some(3600), Some(2))
            .unwrap();
        policy.consume(&grant.id, None, None, None, None).unwrap();
        policy.consume(&grant.id, None, None, None, None).unwrap();
        assert_consume_denied(
            &policy,
            &grant.id,
            None,
            None,
            None,
            None,
            "grant_exhausted",
        );
        assert_eq!(
            policy
                .evaluate("agent-1", "gh", &Action::http("GET", "/repos"), None)
                .unwrap()
                .reason,
            "grant_exhausted"
        );
    }

    #[test]
    fn revocation_applies_immediately_and_notifies() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        type Seen = Vec<(String, Option<String>)>;
        let seen: Arc<Mutex<Seen>> = Arc::new(Mutex::new(Vec::new()));
        {
            let seen = seen.clone();
            policy.on_revoke(move |kind, gid| {
                seen.lock()
                    .unwrap()
                    .push((kind.to_string(), gid.map(str::to_string)))
            });
        }
        let grant = policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        policy.revoke_grant(&grant.id).unwrap();
        assert_eq!(
            policy
                .evaluate("agent-1", "gh", &Action::http("GET", "/repos"), None)
                .unwrap()
                .reason,
            "grant_revoked"
        );
        assert!(
            policy
                .consume(&grant.id, None, None, None, None)
                .unwrap_err()
                .is(ErrorClass::PolicyDenied)
        );
        assert!(
            seen.lock()
                .unwrap()
                .contains(&("grant".to_string(), Some(grant.id.clone())))
        );
        assert!(
            policy
                .revoke_grant("g-missing")
                .unwrap_err()
                .is(ErrorClass::NotFound)
        );
    }

    #[test]
    fn global_stop_blocks_everything_until_resume() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let grant = policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        policy.stop_all().unwrap();
        assert!(policy.is_stopped().unwrap());
        assert_eq!(
            policy
                .evaluate("agent-1", "gh", &Action::http("GET", "/repos"), None)
                .unwrap()
                .reason,
            "global_stop"
        );
        assert!(policy.usable_connections("agent-1").unwrap().is_empty());
        policy.resume().unwrap();
        assert!(
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id)
                )
                .unwrap()
                .allowed
        );
    }

    #[test]
    fn restore_pending_blocks_until_acknowledged() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        policy.set_restore_pending(true).unwrap();
        assert_eq!(
            policy
                .evaluate("agent-1", "gh", &Action::http("GET", "/repos"), None)
                .unwrap()
                .reason,
            "restore_pending"
        );
        policy.set_restore_pending(false).unwrap();
        assert!(
            policy
                .evaluate("agent-1", "gh", &Action::http("GET", "/repos"), None)
                .unwrap()
                .allowed
        );
    }

    // ------------------------------------------------ policy version changes
    #[test]
    fn widening_change_makes_grants_stale_no_inheritance() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let grant = policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        let scope = HttpScope::new(
            None,
            Some(vec!["/repos".into(), "/me".into()]),
            vec!["DELETE".into()],
        )
        .unwrap();
        let (conn, widened) = policy
            .update_connection("gh", ConnectionChanges::new().http_scope(Some(scope)))
            .unwrap();
        assert!(widened);
        assert_eq!(conn.policy_version, 2);
        assert_eq!(
            policy
                .evaluate("agent-1", "gh", &Action::http("PUT", "/repos"), None)
                .unwrap()
                .reason,
            "grant_stale"
        );
        assert_eq!(policy.get_grant(&grant.id).unwrap().status, "stale");
        let fresh = policy.regrant(&grant.id).unwrap();
        assert_eq!(fresh.policy_version, 2);
        assert!(
            policy
                .evaluate("agent-1", "gh", &Action::http("PUT", "/repos"), None)
                .unwrap()
                .allowed
        );
        assert_eq!(policy.get_grant(&grant.id).unwrap().status, "revoked");
    }

    #[test]
    fn target_change_is_widening() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        let target = HttpTarget::new("http", "127.0.0.2", 8080, None, false).unwrap();
        let (_, widened) = policy
            .update_connection("gh", ConnectionChanges::new().http_target(Some(target)))
            .unwrap();
        assert!(widened);
        assert_eq!(
            policy
                .evaluate("agent-1", "gh", &Action::http("GET", "/repos"), None)
                .unwrap()
                .reason,
            "grant_stale"
        );
    }

    #[test]
    fn narrowing_or_rotation_reevaluates_in_place() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let grant = policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        let scope = HttpScope::new(
            Some(vec!["GET".into()]),
            Some(vec!["/repos".into()]),
            vec!["DELETE".into()],
        )
        .unwrap();
        let (conn, widened) = policy
            .update_connection("gh", ConnectionChanges::new().http_scope(Some(scope)))
            .unwrap();
        assert!(!widened);
        assert_eq!(conn.policy_version, 2);
        assert_eq!(policy.get_grant(&grant.id).unwrap().policy_version, 2);
        assert_eq!(
            policy
                .evaluate("agent-1", "gh", &Action::http("POST", "/repos"), None)
                .unwrap()
                .reason,
            "method_not_allowed"
        );
        assert!(
            policy
                .evaluate("agent-1", "gh", &Action::http("GET", "/repos"), None)
                .unwrap()
                .allowed
        );
        let conn = policy.switch_credential("gh", Some(2)).unwrap();
        assert_eq!(conn.secret_version, Some(2));
        assert!(
            policy
                .evaluate("agent-1", "gh", &Action::http("GET", "/repos"), None)
                .unwrap()
                .allowed
        );
    }

    #[test]
    fn disabled_connection_denied() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        policy.disable_connection("gh").unwrap();
        assert_eq!(
            policy
                .evaluate("agent-1", "gh", &Action::http("GET", "/repos"), None)
                .unwrap()
                .reason,
            "connection_disabled"
        );
        assert!(
            policy
                .create_grant("agent-1", "gh", Some(10), None)
                .unwrap_err()
                .is(ErrorClass::InvalidInput)
        );
    }

    // ------------------------------------------------------------- approvals
    #[test]
    fn approval_bound_to_digest_caller_connection_and_one_shot() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let digest = approval_digest("agent-1", "gh", "DELETE", "/repos/demo", b"");
        assert_ne!(
            digest,
            approval_digest("agent-1", "gh", "DELETE", "/repos/demo", b"{}")
        );
        assert_ne!(
            digest,
            approval_digest("agent-1", "gh", "DELETE", "/repos/other", b"")
        );
        policy
            .request_approval(&digest, "agent-1", "gh", "DELETE", "/repos/demo")
            .unwrap();
        assert!(
            !policy
                .consume_approval(&digest, "agent-1", "gh", None, None)
                .unwrap()
        );
        assert!(
            policy
                .approve(&"0".repeat(64))
                .unwrap_err()
                .is(ErrorClass::NotFound)
        );
        policy.approve(&digest).unwrap();
        assert!(
            policy
                .approve(&digest)
                .unwrap_err()
                .is(ErrorClass::InvalidInput)
        );
        assert!(
            !policy
                .consume_approval(&digest, "agent-2", "gh", None, None)
                .unwrap()
        );
        assert!(
            policy
                .consume_approval(&digest, "agent-1", "gh", None, None)
                .unwrap()
        );
        assert!(
            !policy
                .consume_approval(&digest, "agent-1", "gh", None, None)
                .unwrap()
        );
    }

    /// D-8: `_usable_grant_id`'s `_decide(...)` call is not wrapped in Python
    /// (unlike almost every other internal use of `_decide`/`decide`), so an
    /// exception propagates straight out of `request_approval`, which writes
    /// nothing. The Rust port previously used `.ok()?`, silently treating a
    /// corrupt-state error exactly like "no usable grant" and writing an
    /// approval with `"grant": null` anyway -- this pins the fix: a corrupt
    /// grant for the very caller/connection being approved must fail
    /// `request_approval` outright, and the approval must not appear in
    /// `control.json` afterwards.
    ///
    /// Round 6 correction: this test previously corrupted the grant's
    /// `status` field to a JSON number to reach `decide`'s `state_corrupt`
    /// path. Since round 6 fixed `Grant::from_value` to load `status` (like
    /// `revoked_at`/`expires_at`) with no `int()`/`isinstance` check at all,
    /// exactly matching Python's own zero-validation `Grant` dataclass, a
    /// non-string `status` no longer fails the load -- `5 != "active"` is
    /// simply `True` in Python, so that grant now loads fine and
    /// contributes `"grant_inactive"`, not an exception, the same as
    /// Python. Corrupting the *entry's shape* instead (a JSON string in
    /// place of the whole grant object) still reaches the same
    /// `state_corrupt` path this test is pinning: Python's `Grant(**entry)`
    /// raises an uncaught `TypeError` for a non-mapping `entry` (`**` may
    /// only unpack a mapping), confirmed directly against `python3.12`.
    #[test]
    fn request_approval_propagates_corrupt_state_instead_of_writing_a_grantless_approval() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let grant = policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        // Corrupt this grant's entry shape (a JSON string instead of an
        // object): `list_grants` -- called by `_decide`/`decide` when no
        // `grant_id` is given, exactly the path `_usable_grant_id` takes --
        // parses every grant belonging to this caller, so this makes
        // `decide` itself fail with `state_corrupt`, not merely
        // `NotFound`/`no_grant`.
        let mut doc = state.read_json(GRANTS, json!({})).unwrap();
        doc.as_object_mut().unwrap()[&grant.id] = json!("not-a-dict");
        state.write_json(GRANTS, &doc).unwrap();

        let digest = approval_digest("agent-1", "gh", "DELETE", "/repos/demo", b"");
        // No preceding `evaluate()`: `recall_pair` finds nothing remembered,
        // so `request_approval` must fall back to `usable_grant_id`, which is
        // exactly the path under test.
        let err = policy
            .request_approval(&digest, "agent-1", "gh", "DELETE", "/repos/demo")
            .unwrap_err();
        assert!(err.is(ErrorClass::StateError));
        let control = state.read_json(CONTROL, json!({})).unwrap();
        let approvals = control.get("approvals").and_then(Value::as_object);
        assert!(
            approvals.is_none_or(|a| !a.contains_key(&digest)),
            "no approval should have been written for a corrupt-state failure"
        );
    }

    // ------------------------------------------------------------ validation
    #[test]
    fn connection_validation_rejects_bad_targets() {
        assert_invalid_input(HttpTarget::new("ftp", "example.com", 21, None, false));
        assert_invalid_input(HttpTarget::new(
            "https",
            "http://example.com",
            443,
            None,
            false,
        ));
        assert_invalid_input(HttpTarget::new(
            "https",
            "example.com/path",
            443,
            None,
            false,
        ));
        assert_invalid_input(HttpTarget::new(
            "https",
            "user@example.com",
            443,
            None,
            false,
        ));
        assert_invalid_input(HttpTarget::new("https", "example.com", 0, None, false));
        assert_invalid_input(HttpAuth::new("query", None, None, None));
        assert_invalid_input(HttpAuth::new("header", Some("Host".into()), None, None));
        assert_invalid_input(HttpAuth::new("header", Some("X Bad".into()), None, None));
        assert_invalid_input(HttpAuth::new("basic", None, None, Some("a:b".into())));
        assert_invalid_input(HttpScope::new(
            Some(vec!["GET".into()]),
            Some(vec!["repos".into()]),
            vec![],
        ));
        assert_invalid_input(HttpScope::new(
            Some(vec!["GET".into()]),
            Some(vec!["/repos/../admin".into()]),
            vec![],
        ));
        assert_invalid_input(SshTarget::new(
            "host",
            22,
            "deploy",
            vec!["ssh-rsa AAAA".into()],
        ));
        assert_invalid_input(SshTarget::new(
            "host",
            22,
            "Deploy!",
            vec!["ssh-ed25519 AAAA".into()],
        ));
        let mut extra = std::collections::BTreeMap::new();
        extra.insert("SSH_AUTH_SOCK".to_string(), "/x".to_string());
        assert_invalid_input(CliProfile::new("prog", "http", None, extra));
        // `http_connection(http_target=None)`: build directly, omitting
        // `http_target`.
        assert_invalid_input(Connection::new(
            "gh",
            "demo",
            "dev",
            "fake-github",
            "http",
            "gh-token",
            None,
            "demo connection",
            None,
            Some(HttpAuth::bearer()),
            Some(
                HttpScope::new(
                    Some(vec!["GET".into(), "POST".into()]),
                    Some(vec!["/repos".into(), "/me".into()]),
                    vec!["DELETE".into()],
                )
                .unwrap(),
            ),
            None,
            None,
            0,
            "active",
            "",
            "",
        ));
    }

    #[test]
    fn public_view_hides_secret_reference_and_others() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        policy.create_connection(ssh_connection("box")).unwrap();
        let views: Vec<Value> = policy
            .usable_connections("agent-1")
            .unwrap()
            .into_iter()
            .map(|(c, _)| c.public_view())
            .collect();
        assert_eq!(
            views
                .iter()
                .map(|v| v["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["gh"]
        );
        assert!(views[0].get("secret_id").is_none());
        assert!(!views[0].to_string().contains("ca_file"));
        assert_eq!(
            views[0]["target"],
            json!({"scheme": "http", "host": "127.0.0.1", "port": 8080})
        );
        let ssh_view = ssh_connection("box").public_view();
        assert!(!ssh_view.to_string().contains("host_keys"));
        assert_eq!(ssh_view["target"]["username"], json!("deploy"));
    }

    #[test]
    fn ssh_action_requires_matching_username() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        policy.create_connection(ssh_connection("box")).unwrap();
        policy
            .create_grant("agent-1", "box", Some(3600), None)
            .unwrap();
        assert!(
            policy
                .evaluate("agent-1", "box", &Action::ssh("deploy"), None)
                .unwrap()
                .allowed
        );
        assert_eq!(
            policy
                .evaluate("agent-1", "box", &Action::ssh("root"), None)
                .unwrap()
                .reason,
            "ssh_user_mismatch"
        );
    }

    #[test]
    fn grant_limits_validated() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        assert_invalid_input(policy.create_grant("agent-1", "gh", Some(0), None));
        assert_invalid_input(policy.create_grant("agent-1", "gh", Some(3600), Some(0)));
        assert_invalid_input(policy.create_grant("agent-1", "gh", Some(MAX_GRANT_TTL + 1), None));
    }

    #[test]
    fn revoke_all_marks_everything() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        assert_eq!(policy.revoke_all().unwrap(), 2);
        assert!(policy.usable_connections("agent-1").unwrap().is_empty());
    }

    // ------------------------------------------ PL-1: consume is authoritative
    #[test]
    fn consume_rechecks_control_principal_and_connection_committed_after_evaluate() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let other = || Policy::new(&state, make_clock(&clock_val));
        let grant = policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();

        assert!(
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id)
                )
                .unwrap()
                .allowed
        );
        other().stop_all().unwrap();
        assert_consume_denied(&policy, &grant.id, None, None, None, None, "global_stop");
        other().resume().unwrap();

        assert!(
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id)
                )
                .unwrap()
                .allowed
        );
        other().set_restore_pending(true).unwrap();
        assert_consume_denied(
            &policy,
            &grant.id,
            None,
            None,
            None,
            None,
            "restore_pending",
        );
        other().set_restore_pending(false).unwrap();

        assert_eq!(policy.get_grant(&grant.id).unwrap().uses, 0);
        assert!(
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id)
                )
                .unwrap()
                .allowed
        );
        assert_eq!(
            policy
                .consume(&grant.id, None, None, None, None)
                .unwrap()
                .uses,
            1
        );

        assert!(
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id)
                )
                .unwrap()
                .allowed
        );
        other().disable_principal("agent-1", true).unwrap();
        assert_consume_denied(
            &policy,
            &grant.id,
            None,
            None,
            None,
            None,
            "principal_disabled",
        );

        policy.create_principal("agent-2", "default").unwrap();
        policy.create_connection(http_connection("gh2")).unwrap();
        let other_grant = policy
            .create_grant("agent-2", "gh2", Some(3600), None)
            .unwrap();
        assert!(
            policy
                .evaluate(
                    "agent-2",
                    "gh2",
                    &Action::http("GET", "/me"),
                    Some(&other_grant.id)
                )
                .unwrap()
                .allowed
        );
        other().disable_connection("gh2").unwrap();
        assert_consume_denied(
            &policy,
            &other_grant.id,
            None,
            None,
            None,
            None,
            "connection_disabled",
        );
        assert_eq!(policy.get_grant(&other_grant.id).unwrap().uses, 0);
    }

    #[test]
    fn consume_reapplies_the_evaluated_scope_and_policy_version() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let other = || Policy::new(&state, make_clock(&clock_val));
        let grant = policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        assert!(
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("POST", "/repos"),
                    Some(&grant.id)
                )
                .unwrap()
                .allowed
        );
        let scope = HttpScope::new(
            Some(vec!["GET".into()]),
            Some(vec!["/repos".into(), "/me".into()]),
            vec!["DELETE".into()],
        )
        .unwrap();
        other()
            .update_connection("gh", ConnectionChanges::new().http_scope(Some(scope)))
            .unwrap();
        assert_consume_denied(
            &policy,
            &grant.id,
            None,
            None,
            None,
            None,
            "method_not_allowed",
        );

        assert!(
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id)
                )
                .unwrap()
                .allowed
        );
        other()
            .update_connection("gh", ConnectionChanges::new().description("renamed"))
            .unwrap();
        assert_consume_denied(&policy, &grant.id, None, None, None, None, "grant_stale");

        assert_consume_denied(
            &policy,
            &grant.id,
            None,
            None,
            Some(Action::http("PUT", "/repos")),
            None,
            "method_not_allowed",
        );
        assert_consume_denied(
            &policy,
            &grant.id,
            None,
            None,
            Some(Action::http("GET", "/admin")),
            None,
            "path_not_allowed",
        );
        let current = policy.get_connection("gh").unwrap().policy_version;
        assert_consume_denied(
            &policy,
            &grant.id,
            None,
            None,
            None,
            Some(current - 1),
            "grant_stale",
        );
        assert_consume_denied(
            &policy,
            &grant.id,
            Some("agent-2"),
            None,
            None,
            None,
            "grant_mismatch",
        );
        assert_eq!(policy.get_grant(&grant.id).unwrap().uses, 0);
        assert_eq!(
            policy
                .consume(
                    &grant.id,
                    None,
                    None,
                    Some(Action::http("GET", "/me")),
                    Some(current)
                )
                .unwrap()
                .uses,
            1
        );
        assert!(
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id)
                )
                .unwrap()
                .allowed
        );
        assert_eq!(
            policy
                .consume(&grant.id, None, None, None, None)
                .unwrap()
                .uses,
            2
        );
        other()
            .update_connection("gh", ConnectionChanges::new().description("again"))
            .unwrap();
        assert_eq!(
            policy
                .consume(&grant.id, None, None, None, None)
                .unwrap()
                .uses,
            3
        );
    }

    #[test]
    fn consume_in_another_thread_still_rechecks_control() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let other = Policy::new(&state, make_clock(&clock_val));
        let grant = policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        assert!(
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id)
                )
                .unwrap()
                .allowed
        );
        other.stop_all().unwrap();
        let errors = std::thread::scope(|s| {
            let grant_id = grant.id.clone();
            let policy_ref = &policy;
            let handle =
                s.spawn(
                    move || match policy_ref.consume(&grant_id, None, None, None, None) {
                        Err(e) => vec![e.reason.to_string()],
                        Ok(_) => vec![],
                    },
                );
            handle.join().unwrap()
        });
        assert_eq!(errors, vec!["global_stop".to_string()]);
    }

    #[test]
    fn ssh_consume_rechecks_username_and_stop() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let other = || Policy::new(&state, make_clock(&clock_val));
        policy.create_connection(ssh_connection("box")).unwrap();
        let grant = policy
            .create_grant("agent-1", "box", Some(3600), None)
            .unwrap();
        assert!(
            policy
                .evaluate("agent-1", "box", &Action::ssh("deploy"), Some(&grant.id))
                .unwrap()
                .allowed
        );
        other().stop_all().unwrap();
        assert_consume_denied(&policy, &grant.id, None, None, None, None, "global_stop");
        other().resume().unwrap();
        assert_consume_denied(
            &policy,
            &grant.id,
            None,
            None,
            Some(Action::ssh("root")),
            None,
            "ssh_user_mismatch",
        );
    }

    // ------------------------------------------------ PL-6: widening changes
    #[test]
    fn trust_anchor_and_secret_changes_are_widening() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let grant = policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        let t1 = HttpTarget::new(
            "http",
            "127.0.0.1",
            8080,
            Some("/tmp/other-ca.pem".into()),
            false,
        )
        .unwrap();
        let (_, widened) = policy
            .update_connection("gh", ConnectionChanges::new().http_target(Some(t1)))
            .unwrap();
        assert!(widened);
        assert_eq!(policy.get_grant(&grant.id).unwrap().status, "stale");
        let mut fresh = policy.regrant(&grant.id).unwrap();
        let t2 = HttpTarget::new("http", "127.0.0.1", 8080, None, false).unwrap();
        let (_, widened) = policy
            .update_connection("gh", ConnectionChanges::new().http_target(Some(t2)))
            .unwrap();
        assert!(widened);
        assert_eq!(policy.get_grant(&fresh.id).unwrap().status, "stale");
        fresh = policy.regrant(&fresh.id).unwrap();
        let (_, widened) = policy
            .update_connection("gh", ConnectionChanges::new().secret_id("gh-admin-token"))
            .unwrap();
        assert!(widened);
        assert_eq!(
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&fresh.id)
                )
                .unwrap()
                .reason,
            "grant_stale"
        );
        fresh = policy.regrant(&fresh.id).unwrap();
        let (_, widened) = policy
            .update_connection("gh", ConnectionChanges::new().secret_version(Some(3)))
            .unwrap();
        assert!(!widened);
        assert_eq!(policy.get_grant(&fresh.id).unwrap().status, "active");
    }

    // --------------------------------------------- SSH-1 / SSH-2: validation
    #[test]
    fn ssh_target_rejects_multiline_host_keys_and_trailing_newline_usernames() {
        let good = ssh_connection("box").ssh_target.unwrap().host_keys[0].clone();
        let evil =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB evil";
        let bad_lines = vec![
            format!("{good}\n[victim.example.com]:22 {evil}"),
            format!("{good}\r\n{evil}"),
            format!("{good}\x00"),
            good.replace(" host", "\thost"),
            "ssh-ed25519 AAAA".to_string(),
            "ssh-ed25519 not-base64!".to_string(),
        ];
        for line in bad_lines {
            let err = SshTarget::new("127.0.0.1", 22, "deploy", vec![line.clone()]).unwrap_err();
            assert!(err.is(ErrorClass::InvalidInput), "line={line:?}");
            assert_eq!(err.reason, "invalid_host_key", "line={line:?}");
        }
        // Python also checks that passing a bare `str` instead of a tuple
        // for `host_keys` raises `ssh_host_keys_required`; Rust's typed
        // `Vec<String>` parameter rules that case out at compile time
        // (PORTING.md §3.4's "duck-typed -> concrete type" category), so
        // there is no Rust case to port for it.
        for username in ["deploy\n", "deploy\r", "deploy\x00", "\ndeploy"] {
            let err = SshTarget::new("127.0.0.1", 22, username, vec![good.clone()]).unwrap_err();
            assert!(err.is(ErrorClass::InvalidInput), "username={username:?}");
            assert_eq!(err.reason, "invalid_ssh_username", "username={username:?}");
        }
        let target = SshTarget::new("127.0.0.1", 22, "deploy", vec![format!("{good}  ")]).unwrap();
        assert_eq!(target.host_keys, vec![good.clone()]);
        assert!(target.host_keys.iter().all(|l| !l.contains('\n')));
    }

    // ------------------------------------------ PL-4 / PL-7: approval lifecycle
    #[test]
    fn approval_expires() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        let digest = approval_helper(&policy, "/repos/demo");
        *clock_val.lock().unwrap() += APPROVAL_TTL_SECONDS;
        let err = policy.approve(&digest).unwrap_err();
        assert!(err.is(ErrorClass::InvalidInput));
        assert_eq!(err.reason, "approval_expired");
        let digest = approval_helper(&policy, "/repos/demo");
        assert_eq!(policy.list_approvals().unwrap()[&digest]["cycle"], json!(2));
        policy.approve(&digest).unwrap();
        *clock_val.lock().unwrap() += APPROVAL_TTL_SECONDS;
        assert!(
            !policy
                .consume_approval(&digest, "agent-1", "gh", None, None)
                .unwrap()
        );
        assert_eq!(
            policy.list_approvals().unwrap()[&digest]["status"],
            json!("expired")
        );
    }

    #[test]
    fn approval_is_bound_to_grant_and_policy_version_and_dies_with_them() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let other = || Policy::new(&state, make_clock(&clock_val));
        let grant = policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        let digest = approval_helper(&policy, "/repos/demo");
        let entry = policy.list_approvals().unwrap()[&digest].clone();
        assert_eq!(entry["grant"], json!(grant.id));
        assert_eq!(entry["policy_version"], json!(1));
        assert_eq!(
            entry["expires_at"].as_f64(),
            Some(1_700_000_000.0 + APPROVAL_TTL_SECONDS)
        );
        policy.approve(&digest).unwrap();
        other().revoke_grant(&grant.id).unwrap();
        assert_eq!(
            policy.list_approvals().unwrap()[&digest]["status"],
            json!("invalidated")
        );
        let fresh = policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        assert!(
            !policy
                .consume_approval(&digest, "agent-1", "gh", Some(&fresh.id), None)
                .unwrap()
        );

        for i in 0..3 {
            let fresh = policy
                .create_grant("agent-1", "gh", Some(3600), None)
                .unwrap();
            let path = format!("/repos/{}", fresh.id);
            let digest = approval_helper(&policy, &path);
            policy.approve(&digest).unwrap();
            match i {
                0 => {
                    other().revoke_all().unwrap();
                }
                1 => {
                    other()
                        .update_connection("gh", ConnectionChanges::new().description("x"))
                        .unwrap();
                }
                _ => {
                    other().disable_principal("agent-1", true).unwrap();
                }
            }
            assert_eq!(
                policy.list_approvals().unwrap()[&digest]["status"],
                json!("invalidated")
            );
            assert!(
                !policy
                    .consume_approval(&digest, "agent-1", "gh", None, None)
                    .unwrap()
            );
        }
    }

    #[test]
    fn approval_refused_under_another_grant_or_version() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let g1 = policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap()
            .id;
        let g2 = policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap()
            .id;
        let grants: HashSet<String> = [g1, g2].into_iter().collect();
        let digest = approval_helper(&policy, "/repos/demo");
        policy.approve(&digest).unwrap();
        let recorded = policy.list_approvals().unwrap()[&digest]["grant"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(grants.contains(&recorded));
        let other_grant = grants.iter().find(|g| **g != recorded).unwrap().clone();
        assert!(
            !policy
                .consume_approval(&digest, "agent-2", "gh", None, None)
                .unwrap()
        );
        assert_eq!(
            policy.list_approvals().unwrap()[&digest]["status"],
            json!("approved")
        );
        assert!(
            !policy
                .consume_approval(&digest, "agent-1", "gh", Some(&other_grant), None)
                .unwrap()
        );
        assert_eq!(
            policy.list_approvals().unwrap()[&digest]["closed_reason"],
            json!("grant_changed")
        );

        let digest = approval_helper(&policy, "/repos/demo");
        policy.approve(&digest).unwrap();
        assert!(
            !policy
                .consume_approval(&digest, "agent-1", "gh", None, Some(7))
                .unwrap()
        );
        assert_eq!(
            policy.list_approvals().unwrap()[&digest]["closed_reason"],
            json!("policy_changed")
        );

        let digest = approval_helper(&policy, "/repos/demo");
        policy.approve(&digest).unwrap();
        assert_eq!(
            policy.list_approvals().unwrap()[&digest]["grant"],
            json!(recorded)
        );
        assert!(
            policy
                .consume_approval(&digest, "agent-1", "gh", Some(&recorded), Some(1))
                .unwrap()
        );
    }

    #[test]
    fn used_approval_starts_a_new_cycle_with_history() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        let digest = approval_helper(&policy, "/repos/demo");
        policy.approve(&digest).unwrap();
        assert!(
            policy
                .consume_approval(&digest, "agent-1", "gh", None, None)
                .unwrap()
        );
        let again = policy
            .request_approval(&digest, "agent-1", "gh", "DELETE", "/repos/demo")
            .unwrap();
        assert_eq!(again["status"], json!("pending"));
        assert_eq!(again["cycle"], json!(2));
        let history = policy.approval_history().unwrap();
        let mapped: Vec<(String, String, i64)> = history
            .iter()
            .map(|h| {
                (
                    h["digest"].as_str().unwrap().to_string(),
                    h["status"].as_str().unwrap().to_string(),
                    h["cycle"].as_i64().unwrap(),
                )
            })
            .collect();
        assert_eq!(mapped, vec![(digest.clone(), "consumed".to_string(), 1)]);
        assert!(
            !policy
                .consume_approval(&digest, "agent-1", "gh", None, None)
                .unwrap()
        );
        policy.approve(&digest).unwrap();
        assert!(
            policy
                .consume_approval(&digest, "agent-1", "gh", None, None)
                .unwrap()
        );
        let digest2 = approval_helper(&policy, "/repos/other");
        let req = policy
            .request_approval(&digest2, "agent-1", "gh", "DELETE", "/repos/other")
            .unwrap();
        assert_eq!(req["cycle"], json!(1));
    }

    // -------------------------------------- F10 / F12: ledger, credential version
    #[test]
    fn revocations_are_ledgered_and_reapplied() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        policy.create_principal("agent-2", "default").unwrap();
        policy.create_connection(http_connection("gh2")).unwrap();
        let grant = policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        let other = policy
            .create_grant("agent-2", "gh2", Some(3600), None)
            .unwrap();
        let stale = policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        let snapshot: Vec<(&str, Value)> = [GRANTS, PRINCIPALS, CONNECTIONS]
            .iter()
            .map(|&name| (name, state.read_json(name, Value::Null).unwrap()))
            .collect();
        policy.revoke_grant(&grant.id).unwrap();
        policy.disable_principal("agent-2", true).unwrap();
        policy.disable_connection("gh2").unwrap();
        let fresh = policy.regrant(&stale.id).unwrap();
        for (name, doc) in &snapshot {
            state.write_json(name, doc).unwrap();
        }
        let found = collect_revocations(&state, std::iter::empty());
        assert_eq!(
            found.grants,
            [grant.id.clone(), stale.id.clone()]
                .into_iter()
                .collect::<HashSet<_>>()
        );
        assert_eq!(
            found.principals,
            ["agent-2".to_string()].into_iter().collect::<HashSet<_>>()
        );
        assert_eq!(
            found.connections,
            ["gh2".to_string()].into_iter().collect::<HashSet<_>>()
        );
        let counts = policy.reapply_revocations(&found).unwrap();
        assert_eq!(counts["grants"], 2);
        assert_eq!(counts["principals"], 1);
        assert_eq!(counts["connections"], 1);
        assert_eq!(policy.get_grant(&grant.id).unwrap().status, "revoked");
        assert_eq!(policy.get_grant(&stale.id).unwrap().status, "revoked");
        assert_eq!(policy.get_principal("agent-2").unwrap().status, "disabled");
        assert_eq!(policy.get_connection("gh2").unwrap().status, "disabled");
        let counts2 = policy.reapply_revocations(&found).unwrap();
        assert_eq!(counts2["grants"], 0);
        assert_eq!(counts2["principals"], 0);
        assert_eq!(counts2["connections"], 0);
        assert!(!found.grants.contains(&fresh.id));
        policy
            .update_connection("gh2", ConnectionChanges::new().status("active"))
            .unwrap();
        assert!(
            !collect_revocations(&state, std::iter::empty())
                .connections
                .contains("gh2")
        );
        let audit = [
            json!({"event": "grant_revoke", "result": "ok", "grant": other.id}),
            json!({"event": "principal_disable", "result": "denied", "principal": "agent-1"}),
        ];
        let found2 = collect_revocations(&state, audit.iter());
        assert!(found2.grants.contains(&other.id));
        assert!(!found2.principals.contains("agent-1"));
    }

    #[test]
    fn grant_records_credential_version_and_activation_rebinds_unpinned_connections() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let vault = json!({"secrets": {"gh-token": {"active_version": 1, "versions": {}}}});
        state.write_json(VAULT_SECRETS, &vault).unwrap();
        policy
            .create_connection(http_connection_with_secret_version("pinned", 1))
            .unwrap();
        let grant = policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        let pinned = policy
            .create_grant("agent-1", "pinned", Some(3600), None)
            .unwrap();
        assert_eq!(grant.credential_version, Some(1));
        assert_eq!(pinned.credential_version, Some(1));
        assert!(
            policy
                .credential_versions_changed("gh-token")
                .unwrap()
                .is_empty()
        );
        let vault2 = json!({"secrets": {"gh-token": {"active_version": 2, "versions": {}}}});
        state.write_json(VAULT_SECRETS, &vault2).unwrap();
        let changed = policy.credential_versions_changed("gh-token").unwrap();
        assert_eq!(
            changed
                .iter()
                .map(|c| (c.id.as_str(), c.policy_version))
                .collect::<Vec<_>>(),
            vec![("gh", 2)]
        );
        let after = policy.get_grant(&grant.id).unwrap();
        assert_eq!(
            (
                after.status.as_str(),
                after.policy_version,
                after.credential_version
            ),
            ("active", 2, Some(2))
        );
        assert_eq!(policy.get_connection("pinned").unwrap().policy_version, 1);
        let vault3 = json!({"secrets": {"gh-token": {"active_version": null, "versions": {}}}});
        state.write_json(VAULT_SECRETS, &vault3).unwrap();
        assert!(
            policy
                .credential_versions_changed("gh-token")
                .unwrap()
                .is_empty()
        );
        assert_eq!(policy.get_connection("gh").unwrap().policy_version, 2);
    }

    /// Finding D-R7-9 / `DEVIATIONS.md`'s row-95 round-7 addendum: with
    /// `connections["gh"]["secret_id"] = [1]` and a populated `vault/
    /// secrets.json` (`{"secrets": {"sec1": {"active_version": 1}}}`, so
    /// `_resolved_credential_version`'s `.get(secret_id)` is actually
    /// reached -- without it Python's own `isinstance(doc.get("secrets"),
    /// dict)` guard short-circuits before ever touching `secret_id`, and
    /// no exception happens at all), `python3.12` confirms `Policy.
    /// update_connection("gh", status="disabled")` writes `connections.
    /// json`, appends a `connection`/`connection_enable` revocation-ledger
    /// line, and only *then* raises `TypeError: unhashable type: 'list'`
    /// (probed directly against `zeropw/policy.py`: `doc changed: True`,
    /// `ledger changed: True`, ledger line
    /// `{"id":"gh","kind":"connection", ...}`). Rust's `Connection::
    /// from_value` cannot produce a `Connection` at all for a non-string
    /// `secret_id` (a plain typed `String` field, not a raw-`Value`-
    /// carrying one), so its deferred `corrupt` flag rejects the record
    /// the moment `before` is loaded -- before any write. This test pins
    /// that Rust's own failure is atomic: unlike Python, neither
    /// `connections.json` nor the revocation ledger change at all.
    #[test]
    fn update_connection_on_unhashable_secret_id_fails_atomically_unlike_pythons_partial_write() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        state
            .write_json(
                VAULT_SECRETS,
                &json!({"secrets": {"sec1": {"active_version": 1}}}),
            )
            .unwrap();
        let mut doc = state.read_json(CONNECTIONS, json!({})).unwrap();
        doc.as_object_mut().unwrap()["gh"]["secret_id"] = json!([1]);
        state.write_json(CONNECTIONS, &doc).unwrap();
        let before_doc = state.read_json(CONNECTIONS, json!({})).unwrap();
        let before_ledger = state.read_lines(REVOCATIONS, None).unwrap_or_default();

        let err = policy
            .update_connection(
                "gh",
                ConnectionChanges::new().status("disabled".to_string()),
            )
            .unwrap_err();
        assert!(err.is(ErrorClass::StateError), "{err:?}");

        let after_doc = state.read_json(CONNECTIONS, json!({})).unwrap();
        let after_ledger = state.read_lines(REVOCATIONS, None).unwrap_or_default();
        assert_eq!(
            before_doc, after_doc,
            "Rust's failure must not partially write connections.json"
        );
        assert_eq!(
            before_ledger, after_ledger,
            "Rust's failure must not append a ledger line (Python's does)"
        );
    }

    /// Same shape as the `update_connection` test above (finding D-R7-9),
    /// for `disable_connection` -- which calls `update_connection`
    /// internally, so the same atomic-failure property holds.
    #[test]
    fn disable_connection_on_unhashable_secret_id_fails_atomically_unlike_pythons_partial_write() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        state
            .write_json(
                VAULT_SECRETS,
                &json!({"secrets": {"sec1": {"active_version": 1}}}),
            )
            .unwrap();
        let mut doc = state.read_json(CONNECTIONS, json!({})).unwrap();
        doc.as_object_mut().unwrap()["gh"]["secret_id"] = json!([1]);
        state.write_json(CONNECTIONS, &doc).unwrap();
        let before_doc = state.read_json(CONNECTIONS, json!({})).unwrap();
        let before_ledger = state.read_lines(REVOCATIONS, None).unwrap_or_default();

        let err = policy.disable_connection("gh").unwrap_err();
        assert!(err.is(ErrorClass::StateError), "{err:?}");

        let after_doc = state.read_json(CONNECTIONS, json!({})).unwrap();
        let after_ledger = state.read_lines(REVOCATIONS, None).unwrap_or_default();
        assert_eq!(before_doc, after_doc);
        assert_eq!(before_ledger, after_ledger);
    }

    /// Finding D-PO-1: `resume`'s `InvalidInput("incident_open",
    /// open_incident)` builds its `detail` from whatever raw value
    /// `control.json`'s `incident_open` field holds -- reachable as a
    /// float via a hand-edited/bit-rotted `control.json`, the same class
    /// of gap `DEVIATIONS.md` row 95 documents elsewhere in this module.
    /// `python3.12` confirms `str(1e-07) == "1e-07"` while the *JSON
    /// source text* for that exact value can be `"1e-7"` (no leading zero
    /// on the exponent) -- a different string.
    /// `python_str_for_error`'s previous doc comment claimed this
    /// rendering was "adequate ... since no field this crate formats this
    /// way is ever a float", which this reachable case disproves; it now
    /// routes a genuinely float-shaped number through the canonical
    /// `crate::pyjson::python_float_repr` (PORTING.md §3b) instead of the
    /// raw JSON literal text.
    #[test]
    fn resume_incident_open_float_detail_matches_pythons_str_not_json_literal_text() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let mut control = state.read_json(CONTROL, json!({})).unwrap();
        // JSON source text "1e-7" (no leading zero on the exponent) --
        // Python's `str()` of the equal-valued float is "1e-07".
        let raw: Value = serde_json::from_str("1e-7").unwrap();
        control
            .as_object_mut()
            .unwrap()
            .insert("incident_open".to_string(), raw);
        state.write_json(CONTROL, &control).unwrap();

        let err = policy.resume().unwrap_err();
        assert!(err.is(ErrorClass::InvalidInput), "{err:?}");
        assert_eq!(err.reason, "incident_open");
        assert_eq!(err.detail, "1e-07");
    }

    /// Finding D-R7-7: Python's `HttpTarget.__post_init__` checks `scheme`
    /// -> `host` -> `port` -> `allow_private_network`, in that order, and
    /// never checks `ca_file` at all (verified against `python3.12`:
    /// `HttpTarget(scheme="http", host="1.2.3.4", port=80, ca_file=5,
    /// allow_private_network="x", check_address=False)` raises
    /// `InvalidInput invalid_allow_private_network`, not anything about
    /// `ca_file`). `HttpTarget::from_value` previously checked `ca_file`
    /// *before* `allow_private_network`, so a document with both fields
    /// malformed gave `state_corrupt` instead of the documented
    /// `InvalidInput` -- the `ca_file` representational-gap check is now
    /// deferred past every real Python check, the same pattern
    /// `Connection::from_value`'s `corrupt` flag already uses.
    #[test]
    fn http_target_checks_allow_private_network_before_ca_file_like_python() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let mut doc = state.read_json(CONNECTIONS, json!({})).unwrap();
        let target = &mut doc.as_object_mut().unwrap()["gh"]["http_target"];
        target["ca_file"] = json!(5);
        target["allow_private_network"] = json!("x");
        state.write_json(CONNECTIONS, &doc).unwrap();

        let err = policy.get_connection("gh").unwrap_err();
        assert!(err.is(ErrorClass::InvalidInput), "{err:?}");
        assert_eq!(err.reason, "invalid_allow_private_network");
    }

    /// Regression this round's own refactor introduced and the extended
    /// harness caught (not one of the coordinator's named findings):
    /// `regrant` calling `create_grant_exact` directly (finding D-R7-3's
    /// exact-`max_uses` plumbing) bypassed the `ttl_seconds <= 0 || >
    /// MAX_GRANT_TTL` check the public `create_grant` wrapper used to
    /// apply. Python's own `regrant` computes `remaining_ttl` from a
    /// stored `expires_at` and passes it to the *same* `create_grant` its
    /// public API uses, so an astronomically large `remaining_ttl` is
    /// rejected there too (verified against `python3.12`:
    /// `expires_at = 2**63 - 1` -> `regrant` raises `InvalidInput
    /// invalid_ttl`). The check now lives in `create_grant_exact` itself
    /// so both callers get it.
    #[test]
    fn regrant_rejects_ttl_beyond_max_grant_ttl_like_pythons_create_grant() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let grant = policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        let mut doc = state.read_json(GRANTS, json!({})).unwrap();
        doc.as_object_mut().unwrap()[&grant.id]["expires_at"] = json!(i64::MAX);
        state.write_json(GRANTS, &doc).unwrap();

        let err = policy.regrant(&grant.id).unwrap_err();
        assert!(err.is(ErrorClass::InvalidInput), "{err:?}");
        assert_eq!(err.reason, "invalid_ttl");
    }

    /// Finding D-R7-3: `iso(2**53 + 1) == "285428751-11-12T07:36:33Z"` in
    /// `python3.12`, one second after `iso(2**53)` -- exact, since Python's
    /// `int` stays exact. `numeric_value_as_f64` rounds `2**53 + 1` down to
    /// `2**53` first, rendering the wrong (one second earlier) string;
    /// `Grant::public_view`'s `expires_at` field now goes through
    /// `iso_for_raw_value`'s exact `i128` path instead.
    #[test]
    fn grant_public_view_expires_at_is_exact_past_f64_53_bit_precision() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let grant = policy.create_grant("agent-1", "gh", None, None).unwrap();
        let mut doc = state.read_json(GRANTS, json!({})).unwrap();
        // 2**53 + 1
        doc.as_object_mut().unwrap()[&grant.id]["expires_at"] = json!(9_007_199_254_740_993i64);
        state.write_json(GRANTS, &doc).unwrap();

        let loaded = policy.get_grant(&grant.id).unwrap();
        let view = loaded.public_view().unwrap();
        assert_eq!(view["expires_at"], json!("285428751-11-12T07:36:33Z"));
    }

    /// Finding D-R7-3: Python's `Grant.max_uses` has no `int()`/
    /// `isinstance` conversion, so `regrant`'s `max(old.max_uses -
    /// old.uses, 0)` keeps full precision: with `max_uses: 2**53 + 1`,
    /// `uses: 0`, `python3.12`'s `regrant` creates `max_uses ==
    /// 9007199254740993`. The previous `.as_f64().unwrap_or(0.0)` then
    /// `as i64` collapse gave `9007199254740992` (one less) instead --
    /// `regrant` now carries `grant_num_sub`'s exact `Value` through
    /// `create_grant_exact` unchanged.
    #[test]
    fn regrant_remaining_uses_is_exact_past_f64_53_bit_precision() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let grant = policy
            .create_grant("agent-1", "gh", Some(3600), Some(1))
            .unwrap();
        let mut doc = state.read_json(GRANTS, json!({})).unwrap();
        // 2**53 + 1
        doc.as_object_mut().unwrap()[&grant.id]["max_uses"] = json!(9_007_199_254_740_993i64);
        doc.as_object_mut().unwrap()[&grant.id]["uses"] = json!(0);
        state.write_json(GRANTS, &doc).unwrap();

        let fresh = policy.regrant(&grant.id).unwrap();
        let raw = state.read_json(GRANTS, json!({})).unwrap();
        assert_eq!(raw[&fresh.id]["max_uses"], json!(9_007_199_254_740_993i64));
    }

    /// Finding D-R7-2: Python's `self._grants()` (`reapply_revocations`)
    /// runs unconditionally -- `read_json` parses the file regardless of
    /// whether `revocations.grants` has anything in it -- so a genuinely
    /// unparseable `policy/grants.json` raises `StateError state_corrupt`
    /// even with every revocation set empty (verified against
    /// `python3.12`). The previous fix (round 6, cross-unit finding
    /// E-R5-3) gated the *entire* read behind `if !revocations.grants.
    /// is_empty()`, so this same corrupt-file case silently reported "0
    /// reapplied" instead -- reachable via `Vault::restore` on a state
    /// directory with a truncated/corrupt policy document.
    #[test]
    fn reapply_revocations_on_unparseable_grants_file_fails_even_with_empty_revocation_set() {
        let (tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        // Hand-corrupt grants.json with unparseable text.
        std::fs::write(tmp.path().join("state").join(GRANTS), b"{not json").unwrap();

        let revocations = Revocations::default();
        assert!(revocations.grants.is_empty());
        assert!(revocations.principals.is_empty());
        assert!(revocations.connections.is_empty());

        let err = policy.reapply_revocations(&revocations).unwrap_err();
        assert!(err.is(ErrorClass::StateError), "{err:?}");
        assert_eq!(err.reason, "state_corrupt");
    }

    /// Finding D-R7-1: Python's arbitrary-precision `int` never overflows,
    /// so `consume` on a grant with `uses: 9223372036854775807` (`i64::MAX`)
    /// succeeds and writes `"uses": 9223372036854775808` (verified against
    /// `python3.12`). The previous `GrantNum::Int(x) => x + 1` panicked
    /// (`attempt to add with overflow`, debug profile) or silently wrapped
    /// to `i64::MIN` (release profile, since `Cargo.toml` has no
    /// `overflow-checks` override) right here, while holding the state
    /// lock. Widening the addition to `i128` (nothing this crate's own
    /// `GrantNum::BigInt`/`i128_to_value` machinery couldn't already
    /// represent exactly) reproduces Python's actual success instead of
    /// erroring or corrupting the counter.
    #[test]
    fn consume_at_i64_max_uses_widens_exactly_matching_pythons_success() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let grant = policy.create_grant("agent-1", "gh", None, None).unwrap();
        let mut doc = state.read_json(GRANTS, json!({})).unwrap();
        doc.as_object_mut().unwrap()[&grant.id]["uses"] = json!(i64::MAX);
        state.write_json(GRANTS, &doc).unwrap();

        policy
            .consume(&grant.id, None, None, None, None)
            .expect("Python succeeds here; this must not panic or error");

        let raw = state.read_json(GRANTS, json!({})).unwrap();
        // `i64::MAX as i128 + 1 == 9223372036854775808`, one past `i64::MAX`.
        assert_eq!(raw[&grant.id]["uses"], json!(9_223_372_036_854_775_808i128));
    }

    /// Finding D-R7-1: unlike `uses` above, `Connection::policy_version`
    /// stays a plain `i64` (relied on outside this work unit's files), so
    /// there is no exact-widening escape hatch here -- `checked_add`
    /// fails closed with `state_corrupt` instead of panicking (debug) or
    /// silently wrapping to `i64::MIN` and persisting it (release),
    /// which would have broken `grant_num_ne_i64`'s monotonicity
    /// assumption. This is a deliberate, documented divergence from
    /// Python's continued success at this astronomically unreachable
    /// boundary (`DEVIATIONS.md`'s `policy_version`/`cycle` i64-counter-
    /// overflow row) -- the pinned behaviour is "does not panic or
    /// corrupt state", not "matches Python's success".
    #[test]
    fn update_connection_at_i64_max_policy_version_fails_closed_without_panicking() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let mut doc = state.read_json(CONNECTIONS, json!({})).unwrap();
        doc.as_object_mut().unwrap()["gh"]["policy_version"] = json!(i64::MAX);
        state.write_json(CONNECTIONS, &doc).unwrap();

        let err = policy
            .update_connection("gh", ConnectionChanges::new().description("x".to_string()))
            .unwrap_err();
        assert!(err.is(ErrorClass::StateError), "{err:?}");
        assert_eq!(err.reason, "state_corrupt");
    }

    /// Same shape as `update_connection` above, for `request_approval`'s
    /// `cycle = base + 1` (finding D-R7-1).
    #[test]
    fn request_approval_at_i64_max_cycle_fails_closed_without_panicking() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let digest = approval_helper(&policy, "/repos/demo");
        let mut control = state.read_json(CONTROL, json!({})).unwrap();
        control.as_object_mut().unwrap()["approvals"][&digest]["status"] = json!("expired");
        control.as_object_mut().unwrap()["approvals"][&digest]["cycle"] = json!(i64::MAX);
        state.write_json(CONTROL, &control).unwrap();

        let err = policy
            .request_approval(&digest, "agent-1", "gh", "DELETE", "/repos/demo")
            .unwrap_err();
        assert!(err.is(ErrorClass::StateError), "{err:?}");
        assert_eq!(err.reason, "state_corrupt");
    }

    /// Finding D-R7-6: `[] >= [1]` is `False`, `[] >= []` is `True` in
    /// Python (verified directly against `python3.12`), so a grant with
    /// both `uses` and `max_uses` stored as JSON arrays is meaningfully
    /// decided, not an error -- `check_grant("agent-1", "gh", grant_id)`
    /// returns `(True, "allowed")` for `uses: []`, `max_uses: [1]`, and
    /// `(False, "grant_exhausted")` for `uses: []`, `max_uses: []`. This
    /// needs *both* fields malformed at once: mutating only one leaves the
    /// other a plain `i64`, which never reaches `grant_num_ge`'s new
    /// `(Other(Array), Other(Array))` arm at all (the previous single-field
    /// differential harness could never have found this).
    #[test]
    fn check_grant_compares_two_array_valued_uses_and_max_uses_like_python_list_ordering() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let grant = policy.create_grant("agent-1", "gh", None, None).unwrap();

        let mut doc = state.read_json(GRANTS, json!({})).unwrap();
        doc.as_object_mut().unwrap()[&grant.id]["uses"] = json!([]);
        doc.as_object_mut().unwrap()[&grant.id]["max_uses"] = json!([1]);
        state.write_json(GRANTS, &doc).unwrap();
        let decision = policy.check_grant("agent-1", "gh", &grant.id).unwrap();
        assert!(decision.allowed, "{decision:?}");
        assert_eq!(decision.reason, "allowed");

        let mut doc = state.read_json(GRANTS, json!({})).unwrap();
        doc.as_object_mut().unwrap()[&grant.id]["max_uses"] = json!([]);
        state.write_json(GRANTS, &doc).unwrap();
        let decision = policy.check_grant("agent-1", "gh", &grant.id).unwrap();
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "grant_exhausted");

        // An object (`dict`) still genuinely raises in Python (`dict >=
        // dict` is an uncaught `TypeError`), unlike the array case above --
        // this must stay `state_corrupt`, not silently start "deciding"
        // too.
        let mut doc = state.read_json(GRANTS, json!({})).unwrap();
        doc.as_object_mut().unwrap()[&grant.id]["uses"] = json!({"a": 1});
        doc.as_object_mut().unwrap()[&grant.id]["max_uses"] = json!({"b": 2});
        state.write_json(GRANTS, &doc).unwrap();
        let err = policy.check_grant("agent-1", "gh", &grant.id).unwrap_err();
        assert!(err.is(ErrorClass::StateError), "{err:?}");
        assert_eq!(err.reason, "state_corrupt");
    }

    /// Finding D-R7-4: Python's `_approval_mismatch` checks `entry.get(
    /// "grant") is not None`, not hashability, so a stored `grant: [1]`
    /// reaches `self.get_grant([1])` -> `self._grants().get([1])` -> an
    /// uncaught `TypeError: unhashable type: 'list'` (verified directly
    /// against `python3.12`: `consume_approval` raises, and
    /// `control.json` is byte-identical before and after -- Python writes
    /// nothing). Crucially, this only happens when the *caller* doesn't
    /// supply its own `grant_id` -- an explicit one that disagrees with
    /// the stored (malformed) value short-circuits via plain `!=` first,
    /// which never raises; the failing case needs `grant_id: None` (no
    /// preceding `evaluate()` either, so `recall_pair` also gives
    /// `None`). Rust's split arm returns `Err(state_corrupt)` for the two
    /// unhashable shapes (`Array`/`Object`) and keeps the previous
    /// `Ok(Some("grant_changed"))` behaviour for a hashable non-string
    /// (`Number`/`Bool`, which Python's `dict.get` simply never finds,
    /// `NotFound` -> `"grant_changed"`, no exception) -- both pinned here.
    #[test]
    fn consume_approval_on_unhashable_stored_grant_fails_atomically_unlike_hashable_non_string() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();

        // Unhashable (array): Python raises, writes nothing.
        let digest_array = approval_helper(&policy, "/repos/array");
        policy.approve(&digest_array).unwrap();
        let mut control = state.read_json(CONTROL, json!({})).unwrap();
        control.as_object_mut().unwrap()["approvals"][&digest_array]["grant"] = json!([1]);
        state.write_json(CONTROL, &control).unwrap();
        let before = state.read_json(CONTROL, json!({})).unwrap();
        let err = policy
            .consume_approval(&digest_array, "agent-1", "gh", None, None)
            .unwrap_err();
        assert!(err.is(ErrorClass::StateError), "{err:?}");
        assert_eq!(err.reason, "state_corrupt");
        let after = state.read_json(CONTROL, json!({})).unwrap();
        assert_eq!(before, after, "nothing should be written on this failure");

        // Unhashable (object): same shape.
        let digest_object = approval_helper(&policy, "/repos/object");
        policy.approve(&digest_object).unwrap();
        let mut control = state.read_json(CONTROL, json!({})).unwrap();
        control.as_object_mut().unwrap()["approvals"][&digest_object]["grant"] = json!({"a": 1});
        state.write_json(CONTROL, &control).unwrap();
        let err = policy
            .consume_approval(&digest_object, "agent-1", "gh", None, None)
            .unwrap_err();
        assert!(err.is(ErrorClass::StateError), "{err:?}");
        assert_eq!(err.reason, "state_corrupt");

        // Hashable non-string (a plain number): unchanged behaviour --
        // `Ok(false)`, closed as `grant_changed` (Python's `NotFound`,
        // never an exception, since `5` is a valid dict key that's simply
        // never found).
        let digest_number = approval_helper(&policy, "/repos/number");
        policy.approve(&digest_number).unwrap();
        let mut control = state.read_json(CONTROL, json!({})).unwrap();
        control.as_object_mut().unwrap()["approvals"][&digest_number]["grant"] = json!(5);
        state.write_json(CONTROL, &control).unwrap();
        let consumed = policy
            .consume_approval(&digest_number, "agent-1", "gh", None, None)
            .unwrap();
        assert!(!consumed);
        assert_eq!(
            policy.list_approvals().unwrap()[&digest_number]["closed_reason"],
            json!("grant_changed")
        );
    }

    /// Finding D-R7-5 / `DEVIATIONS.md`'s `python_dict_coerce` row: CPython's
    /// `dict([[1, "a"]])` is `{1: 'a'}` -- a *success*, not an exception --
    /// verified directly against `python3.12`. This crate's `Map<String,
    /// Value>` cannot represent the non-string key `1`, so `list_approvals`
    /// deliberately stays fail-closed (`state_corrupt`) here rather than
    /// risking a silent key collision from stringifying (`dict([[1, "a"],
    /// ["1", "b"]])` keeps `1` and `"1"` as two distinct entries in
    /// Python) -- a recorded representational gap, not a §3.5 uncaught-
    /// exception substitution (the doc comment on `python_dict_coerce`
    /// used to claim the latter, falsely).
    #[test]
    fn list_approvals_with_non_string_pair_key_is_a_recorded_representational_gap() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let mut control = state.read_json(CONTROL, json!({})).unwrap();
        control
            .as_object_mut()
            .unwrap()
            .insert("approvals".to_string(), json!([[1, "a"]]));
        state.write_json(CONTROL, &control).unwrap();
        let err = policy.list_approvals().unwrap_err();
        assert!(err.is(ErrorClass::StateError), "{err:?}");
        assert_eq!(err.reason, "state_corrupt");
    }
}
