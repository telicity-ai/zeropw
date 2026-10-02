# Plan: exact CPython non-finite JSON values

Status: source-audit proposal only. No product code, build, or test was run while
preparing this note. The implementation model used for this audit was
`gpt-6-sol`.

## Required behavior

CPython 3.12.14's default `json` behavior is deliberately outside strict JSON.
`JSONDecoder` maps the three bare tokens `NaN`, `Infinity`, and `-Infinity` to
binary64 values. Its default `parse_float` is `float`, so a syntactically normal
literal such as `1e400` also becomes positive infinity (and `-1e400` negative
infinity). `JSONEncoder` has `allow_nan=True` by default and writes these values
as `NaN`, `Infinity`, and `-Infinity`; it does not retain `1e400`'s input
spelling. The controlling sources are:

* [Lib/json/decoder.py at v3.12.14](https://github.com/python/cpython/blob/v3.12.14/Lib/json/decoder.py), especially `_CONSTANTS`, `JSONDecoder.__init__`, and the default `parse_constant`.
* [Lib/json/encoder.py at v3.12.14](https://github.com/python/cpython/blob/v3.12.14/Lib/json/encoder.py), especially `JSONEncoder.__init__` and `floatstr` in `iterencode`.
* [Modules/_json.c at v3.12.14](https://github.com/python/cpython/blob/v3.12.14/Modules/_json.c), the accelerator used by an ordinary CPython installation.

The local port intentionally does the opposite today. `loads` documents and
enforces rejection at `rust/src/pyjson.rs:542-560`; the recursive rejection is
at `rust/src/pyjson.rs:750-777`. `write_number` rejects an overflowing numeric
literal at `rust/src/pyjson.rs:940-960`. Unit and oracle tests currently pin the
divergence at `rust/src/pyjson.rs:1857-1883` and `rust/src/pyjson.rs:2354-2375`.
Those tests must be replaced with parity assertions, not deleted or weakened.

## Why this needs a value representation change

The public `serde_json::Value` type cannot losslessly represent the required
domain. `Number::from_f64` returns `None` for every non-finite value. With the
enabled `arbitrary_precision` feature, a valid numeric lexeme such as `1e400`
can survive internally as a `Number`, but its numeric accessors deliberately do
not expose a non-finite `f64`. More fundamentally, `NaN` and `Infinity` are not
valid `serde_json::Number` lexemes, and the crate's unchecked raw-number
constructor is private.

Substituting `null` is incorrect and risks changing authorization, replay, and
state decisions. A tagged object or string sentinel is also incorrect: users
can supply the same object/string, and Python type, equality, truthiness, and
serialization behavior would change. A path-indexed side table is not a sound
value model because indexing, mutation, clone, removal, and map reordering can
detach a marker from its leaf. Patching serde_json to admit invalid Number
lexemes would depend on private invariants, while its standard numeric methods
would still hide the values. None is an exact small fix.

The recommended representation is an owned Python-JSON tree in `pyjson`:

```rust
pub enum PyNumber {
    Integer(BigInt),
    FiniteFloat(f64),
    PosInfinity,
    NegInfinity,
    NaN,
}

pub enum PyValue {
    Null,
    Bool(bool),
    Number(PyNumber),
    String(String),
    Array(Vec<PyValue>),
    Object(indexmap::IndexMap<String, PyValue>),
}
```

The integer variant may instead retain the already-canonical raw decimal text
if that avoids a new allocation in common paths; it must still expose exact
`BigInt` conversion. Object storage must preserve insertion order because
`DumpOptions::plain()` depends on it. `loads` should return `PyValue`, and
`dumps` should accept it. Parsing `1e400` must create `PosInfinity`; dumping that
tree must write `Infinity`. Direct construction must use explicit
`PyNumber::from_f64`, which accepts all binary64 values. Code must not use
`serde_json::json!(f64::NAN/INFINITY)`: serde_json can turn such construction
into `null`, the exact silent corruption this change is intended to prevent.

Compatibility conversion should be explicit and fallible:

```rust
impl TryFrom<serde_json::Value> for PyValue;
impl TryFrom<PyValue> for serde_json::Value; // errors on every non-finite leaf
```

There must be no lossy adapter. Keeping `loads -> serde_json::Value` while only
changing `dumps` cannot work for nested values and would leave state reads
incorrect. A maintained serde_json fork is the only plausible lower-callsite
alternative, but it still requires auditing every numeric accessor and ties the
product to non-public Number behavior. The owned tree is therefore the smaller
long-term change even though its initial migration is substantial.

Do not derive Rust `Eq` for `PyNumber` or `PyValue`. Python float NaN is unequal
to itself in scalar numeric comparison, while Python containers also have
identity shortcuts (for example, a list compared with itself). Product code
must use operation-specific Python comparison helpers rather than Rust-derived
structural equality. Whether container identity must be modeled at any existing
call site remains an implementation-stage oracle question; decoded separate
trees and repeated NaN tokens must at least compare with Python's observed
results.

## Consumer migration inventory

This is a cross-cutting boundary change. A static search finds approximately
190 numeric accessor/classification occurrences in the relevant source set and
many `pyjson::loads`/`dumps` boundaries. Each must either migrate to `PyValue`
or prove that a typed conversion rejects at the same place and with the same
observable Python failure. The important groups are:

* `rust/src/store.rs:227-249`: `StateDir::read_json` and `write_json` are the
  central persistence boundary. They must carry `PyValue`; otherwise grants,
  control state, projects, and vault state still become `state_corrupt` or
  cannot be rewritten.
* `rust/src/audit.rs:600-634`: audit iteration currently skips a line when
  `loads` rejects it, while tail maps rejection to `state_corrupt`. Python
  accepts these records. Audit and alert append/dump paths must preserve the
  non-finite tokens without logging additional data.
* `rust/src/policy.rs`: grant `uses`, `max_uses`, `expires_at`, approvals,
  ordering, arithmetic, truthiness, and persisted public views all inspect
  numbers. Infinity comparisons must be ordered bounds; NaN comparisons are
  unordered; arithmetic and Python integer coercion need their native Python
  exception behavior. Existing exact integer/finite-float helpers should be
  extended, not bypassed.
* `rust/src/team/fold.rs:1655-1673`, plus `team/commit.rs`, `team/sync.rs`,
  `team/transport.rs`, `team/membership.rs`, and `team/humanview.rs`: snapshots,
  author sequence floors, commits, transport messages, and display all pass
  arbitrary decoded values. For example, `author_seq > Infinity` is false,
  `author_seq > -Infinity` is true, and comparison with NaN is false; the
  current accessor instead reaches the corruption branch.
* `rust/src/vault.rs:81-92` and `rust/src/vault.rs:191-212`: Python truthiness
  makes NaN and both infinities true. Active-version numeric equality needs
  exact infinity/NaN behavior. Backup/restore JSON at roughly
  `rust/src/vault.rs:1463-1652` is also a persistence boundary.
* `rust/src/handles.rs:137-218`: issued payloads and verified payloads pass
  through pyjson. Python `int(inf)` raises `OverflowError` and `int(nan)` raises
  `ValueError`; signed-token behavior and public error mapping need a direct
  oracle rather than treating parse rejection as equivalence.
* `rust/src/pyint.rs:24-80`: JSON-to-int coercion must distinguish NaN and
  infinity and reproduce those failure classes where the caller observes
  them. Exact integer parsing remains unchanged.
* `rust/src/gateway.rs`, `server.rs`, and `fake_upstream.rs`: request, response,
  and fake-upstream JSON are externally reachable. Status/updated-at numeric
  coercion and response serialization need parity; no authentication material
  may be added to diagnostics.
* `rust/src/notify.rs`, `intrusion.rs`, `incident.rs`, `projects.rs`, and
  `admin_cli.rs`: retry counts, timing, counters, truthiness, and CLI rendering
  use generic Values and numeric accessors.
* `rust/src/agent_cli.rs`, `tools.rs`, `kms.rs`, and the demo CLI contain dump,
  display, or fallback paths. Current `unwrap_or_else("{}")` fallbacks must not
  hide a representable non-finite result after migration.

This inventory is a required review checklist, not evidence that every branch
needs identical handling. Typed fields may raise later in Python; generic or
unknown fields often remain untouched and must round-trip successfully.

## Implementation sequence

1. Add `PyNumber`/`PyValue`, parser events for the three constants, and overflow
   classification for decimal/exponent literals. Preserve the existing depth,
   string-escape, duplicate-key, insertion-order, and arbitrary-size-integer
   behavior. Keep source lexemes only where Python keeps their semantic
   distinction; overflow lexemes normalize to infinity.
2. Teach the existing canonical writer all five numeric cases. Finite float
   formatting continues through `python_float_repr`; non-finite spellings are
   exactly `NaN`, `Infinity`, and `-Infinity`. Every `DumpOptions` combination,
   sort order, indentation, separators, ASCII escaping, and final newline must
   remain byte-identical to CPython.
3. Add shared helpers for Python truthiness, numeric equality, and partial
   ordering on `PyNumber`. Preserve NaN unordered behavior and signed
   infinities. Extend exact `BigInt`/binary64 comparison rather than converting
   huge integers to `f64`.
4. Migrate `StateDir` and audit first, then the policy/team/vault/handle
   consumers, then network and CLI/display boundaries. Remove compatibility
   adapters once no product state or input boundary exposes raw
   `serde_json::Value`.
5. Only after all callers are migrated, replace the existing rejection tests
   and remove the documented rejection branches. A partially migrated `loads`
   must not be merged because it would newly route attacker-controlled
   non-finite values into code that assumes `Number::as_f64()` succeeds.

## Remote-only oracle and regression matrix

All differential tests should invoke the pinned CPython 3.12.14 oracle in the
remote harness. They should exchange classifications and canonical bytes, not
credentials or live state.

1. Decode each of `NaN`, `Infinity`, `-Infinity`, `1e400`, `-1e400`,
   `1e-400`, and nested/repeated forms. Compare `math.isnan`, `math.isinf`,
   `math.copysign`, Python type, and array/object shape. Include leading/trailing
   whitespace and invalid near-misses such as `+Infinity`, `inf`, and
   lowercase spellings.
2. For every accepted input above, compare `json.dumps(json.loads(text), ... )`
   bytes for the option sets represented by every `DumpOptions` constructor.
   Assert specifically that `1e400` writes `Infinity`, never `1e400` and never
   `null`.
3. Construct each non-finite value through the Rust public constructor and
   compare dumps with Python `json.dumps(float(...))`. Add a hard regression
   assertion that no constructor or round trip changes any non-finite leaf to
   `Null`.
4. Compare truthiness, equality, and ordering across non-finite values, bools,
   finite fractions, `2**53` neighbors, huge integers, and both signs. Include
   separate NaN objects, repeated references in Python containers, and
   self-comparison to settle the container-identity question before defining
   any structural helper.
5. Round-trip synthetic state files through Python and Rust for
   grants/control, vault backup/restore, project state, snapshots/commits, and
   audit/alert JSONL. Include non-finite values in both accessed typed fields
   and untouched extension fields. Compare successful bytes or exact mapped
   errors at the operation that first accesses the value.
6. Add API oracles for grant exhaustion/expiry, snapshot `author_seq`, handle
   `iat`/`exp`/`pv`, notify attempts/timing, vault active-version equality,
   gateway status coercion, CLI truthiness/rendering, and audit tail/iteration.
   Each test must compare the actual original Python operation, including its
   exception class and the Rust public error mapping.
7. Fuzz a bounded grammar containing finite and overflowing exponent literals,
   constants, huge integers, arrays, and objects. Compare decode classification
   and re-encoded canonical bytes. Record only synthetic input and mismatch
   location.

## Security and unresolved design choices

The value type contains only the same decoded content already held by the
product. Errors should report a field/path and stable error code, never the
value text; accepting NaN must not cause its enclosing request or state record
to be dumped into logs. No unsafe code or native dependency is required.

Before implementation, the coordinator must decide:

* whether to approve the recommended `PyValue` migration or accept the ongoing
  maintenance and semantic risks of a serde_json fork;
* whether `BigInt` or canonical integer text backs `PyNumber::Integer`;
* which public APIs retain temporary fallible serde adapters during staged
  migration;
* the exact Python container identity behavior required for NaN at each
  existing equality call site; and
* how Python exception classes from typed non-finite fields map through the
  existing section 3.5 Rust error policy.

These are implementation decisions to resolve with oracle evidence. They are
not grounds to keep the current rejection as a documented deviation.
