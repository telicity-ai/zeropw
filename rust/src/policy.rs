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
fn json_truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
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
                n.as_f64()
                    .filter(|f| f.is_finite() && f.abs() < 9.223_372_036_854_775e18)
                    .map(|f| f.trunc() as i64)
            }
        }
        Value::String(s) => python_int_from_str(s),
        _ => None,
    }
}

/// The numeric-literal grammar CPython's `int(str)` accepts: optional
/// `str.isspace()` padding, an optional `+`/`-` sign, then one or more ASCII
/// digits with single, non-leading/trailing underscores allowed between them
/// (`"1_000"`, not `"_1"`/`"1_"`/`"1__0"`).
fn python_int_from_str(s: &str) -> Option<i64> {
    let trimmed = python_strip(s);
    let (negative, digits_part) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    if digits_part.is_empty() || digits_part.starts_with('_') || digits_part.ends_with('_') {
        return None;
    }
    let mut cleaned = String::with_capacity(digits_part.len());
    let mut prev_underscore = false;
    for c in digits_part.chars() {
        if c == '_' {
            if prev_underscore {
                return None;
            }
            prev_underscore = true;
            continue;
        }
        if !c.is_ascii_digit() {
            return None;
        }
        prev_underscore = false;
        cleaned.push(c);
    }
    let magnitude: i64 = cleaned.parse().ok()?;
    Some(if negative { -magnitude } else { magnitude })
}

// --------------------------------------------------------------------- models

// TODO(pystr): switch to `crate::pystr::is_space` once it lands (verified
// equal to Python `str.isspace()` over all code points: Rust's
// `char::is_whitespace()` -- the Unicode `White_Space` property -- already
// covers everything Python's `str.isspace()` does except the four
// bidirectional-class-`B`/`S` ASCII separators `\x1c`-`\x1f`, which Python
// also treats as whitespace).
fn is_python_whitespace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
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
    /// `state_corrupt` (PORTING.md §3.5).
    fn from_value(v: &Value) -> Result<Self, Error> {
        let obj = v
            .as_object()
            .ok_or_else(|| Error::state("state_corrupt").with_detail("http_target"))?;
        let missing = || Error::state("state_corrupt").with_detail("http_target");
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
        let allow_private_network =
            validate_allow_private_network_value(obj.get("allow_private_network"))?;
        Self::from_stored(scheme, host, port, ca_file, allow_private_network)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpAuth {
    pub mode: String,
    pub header_name: Option<String>,
    pub value_prefix: Option<String>,
    pub basic_username: Option<String>,
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
        })
    }

    /// Convenience for `HttpAuth("bearer")` (the common case in tests).
    pub fn bearer() -> Self {
        HttpAuth {
            mode: "bearer".into(),
            header_name: None,
            value_prefix: None,
            basic_username: None,
        }
    }

    fn to_value(&self) -> Value {
        json!({
            "mode": self.mode, "header_name": self.header_name,
            "value_prefix": self.value_prefix, "basic_username": self.basic_username,
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
    /// that covers).
    fn from_value(v: &Value) -> Result<Self, Error> {
        let obj = v
            .as_object()
            .ok_or_else(|| Error::state("state_corrupt").with_detail("http_auth"))?;
        let bad = || Error::state("state_corrupt").with_detail("http_auth");
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
        // non-string value when the field applies (a number, a non-empty
        // list/dict) still reaches Python's `re.match`/`in` and is an
        // uncaught `TypeError` there in every case this crate's own tests
        // exercise (`state_corrupt`, PORTING.md §3.5); when the field does
        // not apply to this `mode` at all, Python validates it not at all,
        // which Rust's typed `Option<String>` still cannot represent for a
        // non-string value -- a real, narrower residual (see
        // `DEVIATIONS.md`).
        let opt_str = |key: &str, applies_for_mode: bool| -> Result<Option<String>, Error> {
            match obj.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) => Ok(Some(s.clone())),
                Some(v) if applies_for_mode && !json_truthy(Some(v)) => Ok(None),
                _ => Err(bad()),
            }
        };
        HttpAuth::new(
            mode.clone(),
            opt_str("header_name", mode == "header")?,
            opt_str("value_prefix", false)?,
            opt_str("basic_username", mode == "basic")?,
        )
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

    fn from_value(v: &Value) -> Result<Self, Error> {
        let obj = v
            .as_object()
            .ok_or_else(|| Error::state("state_corrupt").with_detail("http_scope"))?;
        let bad = || Error::state("state_corrupt").with_detail("http_scope");
        let opt_strs = |key: &str| -> Result<Option<Vec<String>>, Error> {
            match obj.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|i| i.as_str().map(str::to_string).ok_or_else(bad))
                    .collect::<Result<Vec<_>, _>>()
                    .map(Some),
                _ => Err(bad()),
            }
        };
        let confirm_methods = match obj.get("confirm_methods") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|i| i.as_str().map(str::to_string).ok_or_else(bad))
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err(bad()),
        };
        HttpScope::new(
            opt_strs("methods")?,
            opt_strs("path_prefixes")?,
            confirm_methods,
        )
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
}

impl CliProfile {
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
        })
    }

    fn to_value(&self) -> Value {
        json!({
            "program": self.program, "kind": self.kind, "base_url_env": self.base_url_env,
            "extra_env": self.extra_env,
        })
    }

    /// `CliProfile(value["program"], value["kind"], value.get("base_url_env",
    /// "ZEROPW_API_BASE_URL"), dict(value.get("extra_env") or {}))` in
    /// `Connection.from_dict`. `base_url_env` reaches `re.match` with no
    /// preceding `isinstance` guard, so a non-string *present* value raises
    /// an uncaught `TypeError` in Python, same as a missing `program`/`kind`
    /// key does (`Value::as_str`/`ok_or_else` below already reproduces both
    /// as `state_corrupt`, PORTING.md §3.5); `extra_env`'s per-entry *value*
    /// does have a documented `isinstance(value, str)` check
    /// (`invalid_env_value`), and a falsy (not just missing) `extra_env`
    /// itself is replaced with `{}` by Python's `... or {}` before `dict()`
    /// ever runs.
    fn from_value(v: &Value) -> Result<Self, Error> {
        let obj = v
            .as_object()
            .ok_or_else(|| Error::state("state_corrupt").with_detail("cli"))?;
        let bad = || Error::state("state_corrupt").with_detail("cli");
        let program = obj.get("program").and_then(Value::as_str).ok_or_else(bad)?;
        // `self.kind not in CONNECTION_KINDS`: a plain equality check, no
        // `isinstance` guard (same shape as `HttpTarget.scheme` and
        // `HttpAuth.mode` above), so a non-string, present `kind` gets the
        // documented `invalid_cli_kind`, not `state_corrupt`; `CliProfile::new`
        // below still does the actual membership check.
        let kind = match obj.get("kind").ok_or_else(bad)?.as_str() {
            Some(s) => s.to_string(),
            None => return Err(Error::invalid_input("invalid_cli_kind")),
        };
        let base_url_env = match obj.get("base_url_env") {
            None => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => return Err(bad()),
        };
        let extra_env = match obj.get("extra_env") {
            None => std::collections::BTreeMap::new(),
            Some(Value::Object(m)) => m
                .iter()
                .map(|(k, val)| {
                    val.as_str()
                        .map(|s| (k.clone(), s.to_string()))
                        .ok_or_else(|| Error::invalid_input("invalid_env_value"))
                })
                .collect::<Result<_, _>>()?,
            Some(other) if !json_truthy(Some(other)) => std::collections::BTreeMap::new(),
            Some(_) => return Err(bad()),
        };
        CliProfile::new(program, kind, base_url_env, extra_env)
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
    pub fn from_value(v: &Value) -> Result<Self, Error> {
        let bad = || Error::state("state_corrupt").with_detail("connection");
        let obj = v.as_object().ok_or_else(bad)?;
        let str_field = |key: &str| -> Result<String, Error> {
            obj.get(key)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(bad)
        };
        // `self.kind not in CONNECTION_KINDS`: a plain equality check, no
        // `isinstance` guard (same shape as `HttpTarget.scheme`,
        // `HttpAuth.mode` and `CliProfile.kind` above), so a non-string,
        // present `kind` gets the documented `invalid_connection_kind`, not
        // `state_corrupt`; `Connection::new` below still does the actual
        // membership check.
        let kind = match obj.get("kind").ok_or_else(bad)?.as_str() {
            Some(s) => s.to_string(),
            None => return Err(Error::invalid_input("invalid_connection_kind")),
        };
        let opt_val = |key: &str| -> Option<&Value> {
            match obj.get(key) {
                Some(Value::Null) | None => None,
                Some(v) => Some(v),
            }
        };
        // `secret_version=data.get("secret_version")`: Python stores this
        // field completely untyped -- there is no `__post_init__` check on
        // it at all, so any JSON shape loads successfully and is kept
        // verbatim (a string, a list, a bool, a float, an out-of-`i64`-range
        // integer, ...). Every writer in this crate -- and the matching
        // Python write paths -- only ever stores an integer or `null`;
        // anything else here can only come from a hand-edited state file,
        // and Rust's typed `Option<i64>` (used throughout this module for
        // credential-version comparisons) cannot represent the untyped
        // Python value, so it is rejected as `state_corrupt` -- a real,
        // documented residual (see DEVIATIONS.md), not a §3.5 case (Python
        // itself raises nothing here).
        let secret_version = match obj.get("secret_version") {
            None | Some(Value::Null) => None,
            Some(v) => Some(v.as_i64().ok_or_else(bad)?),
        };
        // `policy_version=int(data["policy_version"])`: a missing key is an
        // uncaught `KeyError`, and any shape `int()` itself would raise on
        // (`None`, a list, a non-numeric string, a magnitude too large for
        // `i64`) is an uncaught `TypeError`/`ValueError` -- both §3.5,
        // `state_corrupt` either way. [`python_int_coerce`] reproduces
        // exactly the shapes `int()` *does* accept (see its doc comment).
        let policy_version = obj
            .get("policy_version")
            .and_then(python_int_coerce)
            .ok_or_else(bad)?;
        Connection::new(
            str_field("id")?,
            str_field("project")?,
            str_field("environment")?,
            str_field("service")?,
            kind,
            str_field("secret_id")?,
            secret_version,
            obj.get("description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            opt_val("http_target")
                .map(HttpTarget::from_value)
                .transpose()?,
            opt_val("http_auth").map(HttpAuth::from_value).transpose()?,
            opt_val("http_scope")
                .map(HttpScope::from_value)
                .transpose()?,
            opt_val("ssh_target")
                .map(SshTarget::from_value)
                .transpose()?,
            opt_val("cli").map(CliProfile::from_value).transpose()?,
            policy_version,
            // `self.status not in ("active", "disabled")`: another plain
            // equality check, same shape as `kind` above -- a non-string,
            // present `status` gets the documented `invalid_status`, not
            // `state_corrupt`; `Connection::new` still does the membership
            // check itself.
            match obj.get("status").ok_or_else(bad)?.as_str() {
                Some(s) => s.to_string(),
                None => return Err(Error::invalid_input("invalid_status")),
            },
            str_field("created_at")?,
            str_field("updated_at")?,
        )
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
                Some(c) => json!({"program": c.program}),
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
}

impl Grant {
    pub fn public_view(&self) -> Value {
        json!({
            "id": self.id, "connection": self.connection, "status": self.status,
            // `iso(self.expires_at) if self.expires_at else None`: Python
            // truthiness treats `0.0` the same as `None` here.
            "expires_at": match self.expires_at {
                Some(v) if v != 0.0 => Value::String(iso(Some(v))),
                _ => Value::Null,
            },
            "remaining_uses": match self.max_uses {
                Some(m) => Value::from(m - self.uses),
                None => Value::Null,
            },
        })
    }

    fn to_value(&self) -> Value {
        json!({
            "id": self.id, "principal": self.principal, "connection": self.connection,
            "policy_version": self.policy_version, "expires_at": self.expires_at,
            "max_uses": self.max_uses, "uses": self.uses, "status": self.status,
            "created_at": self.created_at, "revoked_at": self.revoked_at,
            "credential_version": self.credential_version,
        })
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        let bad = || Error::state("state_corrupt").with_detail("grant");
        let obj = v.as_object().ok_or_else(bad)?;
        let str_field = |key: &str| -> Result<String, Error> {
            obj.get(key)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(bad)
        };
        let expires_at = match obj.get("expires_at") {
            None | Some(Value::Null) => None,
            Some(v) => Some(v.as_f64().ok_or_else(bad)?),
        };
        let max_uses = match obj.get("max_uses") {
            None | Some(Value::Null) => None,
            Some(v) => Some(v.as_i64().ok_or_else(bad)?),
        };
        let credential_version = match obj.get("credential_version") {
            None | Some(Value::Null) => None,
            Some(v) => Some(v.as_i64().ok_or_else(bad)?),
        };
        let revoked_at = match obj.get("revoked_at") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            _ => return Err(bad()),
        };
        Ok(Grant {
            id: str_field("id")?,
            principal: str_field("principal")?,
            connection: str_field("connection")?,
            policy_version: obj
                .get("policy_version")
                .and_then(Value::as_i64)
                .ok_or_else(bad)?,
            expires_at,
            max_uses,
            uses: obj.get("uses").and_then(Value::as_i64).ok_or_else(bad)?,
            status: str_field("status")?,
            created_at: str_field("created_at")?,
            revoked_at,
            credential_version,
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
                let version = obj.get("version").and_then(Value::as_i64);
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
                let version = obj.get("version").and_then(Value::as_i64);
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
    fn read_doc(&self, name: &str) -> Result<Map<String, Value>, Error> {
        match self.state.read_json(name, json!({}))? {
            Value::Object(m) => Ok(m),
            _ => Ok(Map::new()),
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
    /// file -> `None`, or a stored `{}`), not just a missing file.
    fn control(&self) -> Result<Map<String, Value>, Error> {
        match self.state.read_json(CONTROL, Value::Null)? {
            Value::Object(m) if !m.is_empty() => Ok(m),
            _ => Ok(default_control()),
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
    fn vault_doc(&self) -> Map<String, Value> {
        match self.state.read_json(VAULT_SECRETS, Value::Null) {
            Ok(Value::Object(m)) => m,
            _ => Map::new(),
        }
    }

    /// The vault version this connection uses now: the pinned one, else the
    /// secret's active version.
    fn resolved_credential_version(
        &self,
        connection: &Connection,
        vault_doc: Option<&Map<String, Value>>,
    ) -> Option<i64> {
        if let Some(v) = connection.secret_version {
            return Some(v);
        }
        let owned;
        let doc = match vault_doc {
            Some(d) => d,
            None => {
                owned = self.vault_doc();
                &owned
            }
        };
        let entry = doc
            .get("secrets")?
            .as_object()?
            .get(&connection.secret_id)?
            .as_object()?;
        match entry.get("active_version") {
            Some(v) => v.as_i64(),
            None => None,
        }
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
        let mut changed: Vec<(Connection, i64)> = Vec::new();
        let _lock = self.state.lock()?;
        let mut doc = self.connections()?;
        let grants = self.grants()?;
        let vault_doc = self.vault_doc();
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
            let Some(resolved) = self.resolved_credential_version(&connection, Some(&vault_doc))
            else {
                continue;
            };
            let mut any_active_recorded_mismatch = false;
            for g in grants.values() {
                let Ok(g_obj) = as_obj(g) else { continue };
                if g_obj.get("connection").and_then(Value::as_str) != Some(connection_id.as_str()) {
                    continue;
                }
                if g_obj.get("status").and_then(Value::as_str) != Some("active") {
                    continue;
                }
                if !g_obj.contains_key("credential_version") {
                    continue;
                }
                if g_obj.get("credential_version").and_then(Value::as_i64) != Some(resolved) {
                    any_active_recorded_mismatch = true;
                    break;
                }
            }
            if !any_active_recorded_mismatch {
                continue;
            }
            let after = Connection {
                policy_version: connection.policy_version + 1,
                updated_at: iso(Some(self.now())),
                ..connection
            };
            doc.insert(connection_id.clone(), after.to_value());
            changed.push((after, resolved));
        }
        if !changed.is_empty() {
            self.state.write_json(CONNECTIONS, &Value::Object(doc))?;
            for (after, resolved) in &changed {
                self.reevaluate_grants(&after.id, after.policy_version, false, Some(*resolved))?;
            }
            let ids: HashSet<String> = changed.iter().map(|(c, _)| c.id.clone()).collect();
            self.invalidate_approvals(
                |e| {
                    e.get("connection")
                        .and_then(Value::as_str)
                        .is_some_and(|c| ids.contains(c))
                },
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
            if let Some(entry) = doc.get_mut(principal_id).and_then(Value::as_object_mut) {
                entry.insert("status".into(), json!("disabled"));
            }
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

    pub fn authenticate(&self, token: &str) -> Result<Principal, Error> {
        if !token.starts_with("zpwc_") || token.chars().count() > 256 {
            return Err(Error::auth_failed("caller_token_invalid"));
        }
        let digest = hash_token(token);
        let doc = self.principals()?;
        let mut ids: Vec<&String> = doc.keys().collect();
        ids.sort();
        for id in ids {
            let entry = as_obj(&doc[id])?;
            let stored_hash = entry
                .get("token_hash")
                .and_then(Value::as_str)
                .unwrap_or("");
            if constant_time_eq(stored_hash.as_bytes(), digest.as_bytes()) {
                let principal = principal_from_entry(id, &doc[id])?;
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
        runtime: obj
            .get("runtime")
            .and_then(Value::as_str)
            .unwrap_or("default")
            .to_string(),
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
            let after_version = before.policy_version + 1;
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
            let resolved = self.resolved_credential_version(&after, None);
            self.reevaluate_grants(connection_id, after.policy_version, widened, resolved)?;
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
    pub(crate) fn reevaluate_grants(
        &self,
        connection_id: &str,
        new_version: i64,
        widened: bool,
        credential_version: Option<i64>,
    ) -> Result<(), Error> {
        let mut grants = self.grants()?;
        let mut changed = false;
        for (_, entry) in grants.iter_mut() {
            let Some(obj) = entry.as_object_mut() else {
                continue;
            };
            if obj.get("connection").and_then(Value::as_str) != Some(connection_id) {
                continue;
            }
            if obj.get("status").and_then(Value::as_str) != Some("active") {
                continue;
            }
            if widened {
                obj.insert("status".into(), json!("stale"));
            } else {
                obj.insert("policy_version".into(), json!(new_version));
                obj.insert("credential_version".into(), json!(credential_version));
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
        if let Some(ttl) = ttl_seconds
            && (ttl <= 0 || ttl > MAX_GRANT_TTL)
        {
            return Err(Error::invalid_input("invalid_ttl"));
        }
        if let Some(m) = max_uses
            && m <= 0
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
            credential_version: self.resolved_credential_version(&connection, None),
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

    pub fn list_grants(&self, principal_id: Option<&str>) -> Result<Vec<Grant>, Error> {
        let doc = self.grants()?;
        let mut ids: Vec<&String> = doc.keys().collect();
        ids.sort();
        ids.into_iter()
            .filter(|id| {
                principal_id.is_none_or(|p| {
                    doc[*id]
                        .as_object()
                        .and_then(|o| o.get("principal"))
                        .and_then(Value::as_str)
                        == Some(p)
                })
            })
            .map(|id| Grant::from_value(&doc[id]))
            .collect()
    }

    /// Approvals recorded for this grant, or recorded without a grant for
    /// its caller and connection.
    fn approval_matches_grant<'g>(
        grant_principal: &'g str,
        grant_connection: &'g str,
        grant_id: &'g str,
    ) -> impl Fn(&Map<String, Value>) -> bool + 'g {
        move |entry: &Map<String, Value>| match entry.get("grant") {
            Some(Value::Null) | None => {
                entry.get("caller").and_then(Value::as_str) == Some(grant_principal)
                    && entry.get("connection").and_then(Value::as_str) == Some(grant_connection)
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
            let entry_obj = doc
                .get(grant_id)
                .ok_or_else(|| Error::not_found("grant_not_found"))
                .and_then(|v| as_obj(v).cloned())?;
            let mut fields = Map::new();
            fields.insert("id".into(), json!(grant_id));
            append_revocation(self.state, "grant", fields);
            let entry = doc
                .get_mut(grant_id)
                .and_then(Value::as_object_mut)
                .expect("checked above");
            entry.insert("status".into(), json!("revoked"));
            entry.insert("revoked_at".into(), json!(iso(Some(self.now()))));
            self.state.write_json(GRANTS, &Value::Object(doc))?;
            let principal = entry_obj
                .get("principal")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let connection = entry_obj
                .get("connection")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            self.invalidate_approvals(
                Self::approval_matches_grant(&principal, &connection, grant_id),
                "grant_revoked",
            )?;
            grant = self.get_grant(grant_id)?;
        }
        self.notify_revoke("grant", Some(grant_id));
        Ok(grant)
    }

    /// Revoke every active or stale grant and invalidate every open approval
    /// (used by recovery).
    pub fn revoke_all(&self) -> Result<usize, Error> {
        let count;
        {
            let _lock = self.state.lock()?;
            let mut doc = self.grants()?;
            let mut n = 0usize;
            for (grant_id, entry) in doc.iter_mut() {
                let Some(obj) = entry.as_object_mut() else {
                    continue;
                };
                let status = obj.get("status").and_then(Value::as_str).unwrap_or("");
                if status == "active" || status == "stale" {
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
                let Some(obj) = entry.as_object_mut() else {
                    continue;
                };
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
        if old.status != "stale" && old.status != "active" {
            return Err(Error::invalid_input("grant_not_regrantable"));
        }
        let remaining_ttl = match old.expires_at {
            Some(exp) => {
                let remaining = (exp - self.now()) as i64;
                if remaining <= 0 {
                    return Err(Error::invalid_input("grant_expired"));
                }
                Some(remaining)
            }
            None => None,
        };
        let remaining_uses = match old.max_uses {
            Some(max) => Some((max - old.uses).max(0)),
            None => None,
        };
        if remaining_uses == Some(0) {
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
        let principal = entry_snapshot
            .get("principal")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let connection = entry_snapshot
            .get("connection")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        self.invalidate_approvals(
            Self::approval_matches_grant(&principal, &connection, grant_id),
            "grant_revoked",
        )?;
        self.create_grant(
            &old.principal,
            &old.connection,
            remaining_ttl,
            remaining_uses,
        )
    }
}

fn as_obj_mut(v: &mut Value) -> Result<&mut Map<String, Value>, Error> {
    v.as_object_mut()
        .ok_or_else(|| Error::state("state_corrupt").with_detail("policy_document"))
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

    pub fn resume(&self) -> Result<(), Error> {
        let _lock = self.state.lock()?;
        let mut control = self.control()?;
        if let Some(open) = control
            .get("incident_open")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            // `InvalidInput("incident_open", open_incident)`: Python passes
            // the incident id as `detail`.
            return Err(Error::new(
                ErrorClass::InvalidInput,
                "incident_open",
                open.to_string(),
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
            Some(v) => match v.as_f64() {
                Some(f) => now >= f,
                None => true,
            },
            None => true,
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
    pub(crate) fn invalidate_approvals(
        &self,
        predicate: impl Fn(&Map<String, Value>) -> bool,
        reason: &str,
    ) -> Result<usize, Error> {
        let mut control = self.control()?;
        let now = self.now();
        let mut count = 0usize;
        if let Some(approvals) = control.get_mut("approvals").and_then(Value::as_object_mut) {
            for entry in approvals.values_mut() {
                let Some(obj) = entry.as_object_mut() else {
                    continue;
                };
                let status = obj.get("status").and_then(Value::as_str).unwrap_or("");
                if OPEN_APPROVAL_STATES.contains(&status) && predicate(obj) {
                    Self::close_approval(obj, "invalidated", Some(reason), now);
                    count += 1;
                }
            }
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
    ) {
        let history = control
            .entry("approval_history".to_string())
            .or_insert_with(|| json!([]));
        if !history.is_array() {
            *history = json!([]);
        }
        let arr = history.as_array_mut().expect("just ensured array");
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
        if !matches!(control.get("approvals"), Some(Value::Object(_))) {
            control.insert("approvals".into(), json!({}));
        }
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
            Self::archive_approval(&mut control, digest, &entry_mut);
            cycle = entry_mut.get("cycle").and_then(Value::as_i64).unwrap_or(1) + 1;
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
        if !matches!(control.get("approvals"), Some(Value::Object(_))) {
            control.insert("approvals".into(), json!({}));
        }
        let result;
        {
            let approvals_obj = as_obj_mut(control.get_mut("approvals").expect("just ensured"))?;
            let entry = approvals_obj
                .get_mut(digest)
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
        let Some(approvals) = control.get_mut("approvals").and_then(Value::as_object_mut) else {
            return Ok(false);
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
        let recorded_version = entry.get("policy_version").and_then(Value::as_i64);
        if recorded_version != Some(connection.policy_version) {
            return Ok(Some("policy_changed"));
        }
        if let Some(v) = in_use_version
            && v != connection.policy_version
        {
            return Ok(Some("policy_changed"));
        }
        if let Some(recorded_grant) = entry.get("grant").and_then(Value::as_str) {
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
            if let Some(state) = self.grant_state(&grant, &connection) {
                return Ok(Some(state));
            }
        }
        Ok(None)
    }

    pub fn list_approvals(&self) -> Result<Map<String, Value>, Error> {
        Ok(self
            .control()?
            .get("approvals")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default())
    }

    pub fn approval_history(&self) -> Result<Vec<Value>, Error> {
        Ok(self
            .control()?
            .get("approval_history")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
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
        let mut grants = self.grants()?;
        for grant_id in &revocations.grants {
            if let Some(entry) = grants.get_mut(grant_id).and_then(Value::as_object_mut)
                && entry.get("status").and_then(Value::as_str) != Some("revoked")
            {
                entry.insert("status".into(), json!("revoked"));
                let revoked_at = entry
                    .get("revoked_at")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| now.clone());
                entry.insert("revoked_at".into(), json!(revoked_at));
                *counts.get_mut("grants").unwrap() += 1;
            }
        }
        if counts["grants"] > 0 {
            self.state.write_json(GRANTS, &Value::Object(grants))?;
        }
        let mut principals = self.principals()?;
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
        let mut connections = self.connections()?;
        for connection_id in &revocations.connections {
            if let Some(entry) = connections
                .get_mut(connection_id)
                .and_then(Value::as_object_mut)
                && entry.get("status").and_then(Value::as_str) != Some("disabled")
            {
                entry.insert("status".into(), json!("disabled"));
                let pv = entry
                    .get("policy_version")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
                    + 1;
                entry.insert("policy_version".into(), json!(pv));
                entry.insert("updated_at".into(), json!(now.clone()));
                *counts.get_mut("connections").unwrap() += 1;
            }
        }
        if counts["connections"] > 0 {
            self.state
                .write_json(CONNECTIONS, &Value::Object(connections))?;
        }
        let revocations = revocations.clone();
        self.invalidate_approvals(
            move |e| {
                e.get("grant")
                    .and_then(Value::as_str)
                    .is_some_and(|g| revocations.grants.contains(g))
                    || e.get("caller")
                        .and_then(Value::as_str)
                        .is_some_and(|c| revocations.principals.contains(c))
                    || e.get("connection")
                        .and_then(Value::as_str)
                        .is_some_and(|c| revocations.connections.contains(c))
            },
            "revoked_before_restore",
        )?;
        Ok(counts)
    }

    // ----------------------------------------------------------- evaluation
    fn grant_state(&self, grant: &Grant, connection: &Connection) -> Option<&'static str> {
        if grant.status == "revoked" {
            return Some("grant_revoked");
        }
        if grant.status == "stale" || grant.policy_version != connection.policy_version {
            return Some("grant_stale");
        }
        if grant.status != "active" {
            return Some("grant_inactive");
        }
        if let Some(exp) = grant.expires_at
            && self.now() >= exp
        {
            return Some("grant_expired");
        }
        if let Some(max) = grant.max_uses
            && grant.uses >= max
        {
            return Some("grant_exhausted");
        }
        None
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
            match self.grant_state(&grant, &connection) {
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
        obj.insert("uses".into(), json!(grant.uses + 1));
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
            if connection.status != "active" || self.grant_state(&grant, &connection).is_some() {
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
    #[test]
    fn request_approval_propagates_corrupt_state_instead_of_writing_a_grantless_approval() {
        let (_tmp, state, clock_val, _token) = setup();
        let policy = Policy::new(&state, make_clock(&clock_val));
        let grant = policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .unwrap();
        // Corrupt this grant's `status` field (a JSON number instead of a
        // string): `list_grants` -- called by `_decide`/`decide` when no
        // `grant_id` is given, exactly the path `_usable_grant_id` takes --
        // parses every grant belonging to this caller, so this makes
        // `decide` itself fail with `state_corrupt`, not merely
        // `NotFound`/`no_grant`.
        let mut doc = state.read_json(GRANTS, json!({})).unwrap();
        doc.as_object_mut().unwrap()[&grant.id]["status"] = json!(5);
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
}
