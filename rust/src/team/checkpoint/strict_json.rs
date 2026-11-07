//! Original bytes and public typed Serde container callbacks advance together.
//! The framing pass is iterative; it never certifies JSON grammar. Containers
//! never pass through Value::deserialize or the legacy whole-object loader.

use std::collections::BTreeSet;
use std::fmt;
use std::ops::Range;

use serde::Deserialize;
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use crate::{pyint::PyInt, pyjson};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Json,
    Duplicate,
    Limit,
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub(super) struct Span<'a> {
    source: &'a [u8],
    range: Range<usize>,
    ancestors: usize,
}

impl Span<'_> {
    pub(super) fn bytes(&self) -> &[u8] {
        // Only the checked cursor publishes ranges; there is no peer offset API.
        &self.source[self.range.clone()]
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Any,
    UInt,
    Manifest,
    Counts,
    Vector,
    Heads,
    Head,
    Hlc,
    Descriptors,
    Descriptor,
    PayloadDescriptor,
    Chunks,
    Chunk,
    Payload,
    Components,
    Component(usize),
    Devices,
    Device,
    Snapshot,
    Document,
    Secrets,
    Secret,
    Versions,
    Version,
    Commits,
    CommitEntries,
    CommitEntry,
    Commit,
    Facts,
    FactEntries,
    FactEntry,
    Fact,
    Removals,
    Pending,
    PendingEntry,
    Wraps,
    WrapEntries,
    WrapEntry,
}

impl Role {
    fn field(self, key: &str) -> Self {
        use Role::*;
        match (self, key) {
            (Manifest, "v" | "authorization_expires_at_ms" | "created_at_ms" | "expires_at_ms")
            | (Counts | Vector | Hlc, _)
            | (Head, "author_seq")
            | (Descriptor, "byte_length" | "item_count")
            | (PayloadDescriptor, "byte_length")
            | (Chunk, "index" | "byte_length")
            | (Payload, "v")
            | (Commit, "author_seq")
            | (WrapEntry, "source_op_index") => UInt,
            (Manifest, "counts") => Counts,
            (Manifest | Snapshot, "vector") | (Commit, "seen") | (Removals, "bounds") => Vector,
            (Manifest, "heads") => Heads,
            (Head, "hlc") => Hlc,
            (Manifest, "components") => Descriptors,
            (Manifest, "payload") => PayloadDescriptor,
            (PayloadDescriptor, "chunks") => Chunks,
            (Payload, "components") => Components,
            (Component(0), "data") => Devices,
            (Component(1), "data") => Snapshot,
            (Component(2), "data") => Commits,
            (Component(3), "data") => Facts,
            (Component(4), "data") => Removals,
            (Component(5), "data") => Wraps,
            (Snapshot, "document") => Document,
            (Document, "secrets") => Secrets,
            (Secrets, _) => Secret,
            (Secret, "versions") => Versions,
            (Versions, _) => Version,
            (Commits, "records") => CommitEntries,
            (CommitEntry, "record") => Commit,
            (Facts, "records") => FactEntries,
            (FactEntry, "record") => Fact,
            (Removals, "pending") => Pending,
            (Wraps, "entries") => WrapEntries,
            _ => Any,
        }
    }

    fn element(self, index: usize) -> Self {
        use Role::*;
        match self {
            Heads => Head,
            Descriptors => Descriptor,
            Chunks => Chunk,
            Components => Component(index),
            Devices => Device,
            CommitEntries => CommitEntry,
            FactEntries => FactEntry,
            Pending => PendingEntry,
            PendingEntry if index < 2 => UInt,
            WrapEntries => WrapEntry,
            _ => Any,
        }
    }
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
struct Counts {
    devices: usize,
    chunks: usize,
    commits: usize,
    facts: usize,
    versions: usize,
    combined: usize,
}

fn increment(count: &mut usize, max: usize) -> Result<()> {
    if *count >= max {
        return Err(Error::Limit);
    }
    *count += 1;
    Ok(())
}

impl Counts {
    fn enter(&mut self, role: Role) -> Result<()> {
        match role {
            Role::Device => increment(&mut self.devices, 256)?,
            Role::Chunk | Role::Head | Role::Descriptor => {
                // Heads/descriptors have separate per-container limits below.
                if role == Role::Chunk {
                    increment(&mut self.chunks, 256)?;
                }
            }
            Role::CommitEntry | Role::FactEntry | Role::Version => {
                increment(&mut self.combined, 65_536)?;
                let counter = match role {
                    Role::CommitEntry => &mut self.commits,
                    Role::FactEntry => &mut self.facts,
                    _ => &mut self.versions,
                };
                *counter += 1;
            }
            _ => {}
        }
        Ok(())
    }
}

/// A witness stays tied to its immutable original bytes and ancestor depth.
/// The index is selective: six components and record envelopes, never a token tree.
struct Index<'a> {
    root: Span<'a>,
    components: [Option<Span<'a>>; 6],
    commits: Vec<Span<'a>>,
    facts: Vec<Span<'a>>,
    counts: Counts,
}

struct Frame {
    role: Role,
    start: usize,
    ancestors: usize,
    count: usize,
    keys: BTreeSet<String>,
    key: Option<String>,
    value: Option<Value>,
}

struct State<'a> {
    source: &'a [u8],
    pos: usize,
    end: usize,
    ancestors: usize,
    role: Role,
    build: bool,
    frames: Vec<Box<Frame>>,
    output: Option<Value>,
    index: Index<'a>,
    failure: Error,
    // Observability of early refusal without process-global test hooks.
    entries: usize,
    scalars: usize,
    max_frames: usize,
    #[cfg(test)]
    before_value: Option<fn(usize)>,
}

fn preflight(bytes: &[u8], cap: usize, ancestors: usize) -> Result<()> {
    if bytes.len() > cap {
        return Err(Error::Limit);
    }
    std::str::from_utf8(bytes).map_err(|_| Error::Json)?;
    let mut stack = [0_u8; 64];
    let mut depth = 0_usize;
    let mut pos = 0_usize;
    let mut quoted = false;
    while let Some(&byte) = bytes.get(pos) {
        if quoted {
            match byte {
                b'\\' => {
                    pos = pos.checked_add(1).ok_or(Error::Json)?;
                    if bytes.get(pos).is_none() {
                        return Err(Error::Json);
                    }
                }
                b'"' => quoted = false,
                _ => {}
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    if depth.checked_add(ancestors).ok_or(Error::Limit)? >= 64 {
                        return Err(Error::Limit);
                    }
                    *stack.get_mut(depth).ok_or(Error::Limit)? = byte;
                    depth += 1;
                }
                b'}' | b']' => {
                    depth = depth.checked_sub(1).ok_or(Error::Json)?;
                    let opening = *stack.get(depth).ok_or(Error::Json)?;
                    if (opening, byte) != (b'{', b'}') && (opening, byte) != (b'[', b']') {
                        return Err(Error::Json);
                    }
                }
                _ => {}
            }
        }
        pos = pos.checked_add(1).ok_or(Error::Json)?;
    }
    if quoted || depth != 0 {
        return Err(Error::Json);
    }
    Ok(())
}

fn uint_token(bytes: &[u8]) -> bool {
    bytes == b"0"
        || matches!(bytes.first(), Some(b'1'..=b'9'))
            && bytes
                .get(1..)
                .is_some_and(|rest| rest.iter().all(u8::is_ascii_digit))
}

impl<'a> State<'a> {
    fn byte(&self) -> Option<u8> {
        if self.pos >= self.end {
            None
        } else {
            self.source.get(self.pos).copied()
        }
    }

    fn ws(&mut self) {
        while matches!(self.byte(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.pos += 1;
        }
    }

    fn punctuation(&mut self, byte: u8) -> Result<()> {
        self.ws();
        if self.byte() != Some(byte) {
            return Err(Error::Json);
        }
        self.pos = self.pos.checked_add(1).ok_or(Error::Json)?;
        Ok(())
    }

    fn token_end(&self) -> Result<usize> {
        let mut pos = self.pos;
        if self.byte() == Some(b'"') {
            pos += 1;
            while pos < self.end {
                match self.source.get(pos) {
                    Some(b'"') => return pos.checked_add(1).ok_or(Error::Json),
                    Some(b'\\') => pos = pos.checked_add(2).ok_or(Error::Json)?,
                    Some(_) => pos += 1,
                    None => return Err(Error::Json),
                }
            }
            return Err(Error::Json);
        }
        if !matches!(self.byte(), Some(b'-' | b'0'..=b'9' | b't' | b'f' | b'n')) {
            return Err(Error::Json);
        }
        while pos < self.end {
            match self.source.get(pos) {
                Some(
                    b' ' | b'\t' | b'\r' | b'\n' | b'{' | b'}' | b'[' | b']' | b',' | b':' | b'"',
                ) => break,
                Some(_) => pos += 1,
                None => break,
            }
        }
        Ok(pos)
    }

    fn scalar(&self, end: usize) -> Result<Value> {
        let raw = self.source.get(self.pos..end).ok_or(Error::Json)?;
        let value = pyjson::loads(std::str::from_utf8(raw).map_err(|_| Error::Json)?)
            .map_err(|_| Error::Json)?;
        let correct = match self.byte() {
            Some(b'"') => value.is_string(),
            Some(b't' | b'f') => value.is_boolean(),
            Some(b'n') => value.is_null(),
            Some(b'-' | b'0'..=b'9') => value.is_number(),
            _ => false,
        };
        if !correct {
            return Err(Error::Json);
        }
        Ok(value)
    }

    fn frame(&mut self) -> Result<&mut Frame> {
        self.frames.last_mut().map(Box::as_mut).ok_or(Error::Json)
    }

    fn fail<E: de::Error>(&mut self, error: Error) -> E {
        self.failure = error;
        E::custom("checkpoint syntax refused")
    }

    fn start(&mut self) -> Result<()> {
        #[cfg(test)]
        if let Some(hook) = self.before_value {
            hook(self.entries);
        }
        // The quota is checked before even framing or decoding the child token.
        self.index.counts.enter(self.role)?;
        self.entries += 1;
        self.ws();
        self.frames.push(Box::new(Frame {
            role: self.role,
            start: self.pos,
            ancestors: self.ancestors + self.frames.len(),
            count: 0,
            keys: BTreeSet::new(),
            key: None,
            value: None,
        }));
        self.max_frames = self.max_frames.max(self.frames.len());
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        let frame = self.frames.pop().ok_or(Error::Json)?;
        let span = Span {
            source: self.source,
            range: frame.start..self.pos,
            ancestors: frame.ancestors,
        };
        let component = match frame.role {
            Role::Devices => Some(0),
            Role::Snapshot => Some(1),
            Role::Commits => Some(2),
            Role::Facts => Some(3),
            Role::Removals => Some(4),
            Role::Wraps => Some(5),
            _ => None,
        };
        if let Some(index) = component {
            *self.index.components.get_mut(index).ok_or(Error::Json)? = Some(span.clone());
        }
        match frame.role {
            Role::CommitEntry => self.index.commits.push(span.clone()),
            Role::FactEntry => self.index.facts.push(span.clone()),
            _ => {}
        }
        if let Some(parent) = self.frames.last_mut() {
            parent.count += 1;
            if let Some(value) = frame.value {
                match parent.value.as_mut() {
                    Some(Value::Object(map)) => {
                        map.insert(parent.key.take().ok_or(Error::Json)?, value);
                    }
                    Some(Value::Array(array)) => array.push(value),
                    _ => return Err(Error::Json),
                }
            } else {
                parent.key = None;
            }
        } else {
            self.index.root = span;
            self.output = frame.value;
        }
        Ok(())
    }
}

struct Seed<'s, 'a>(&'s mut State<'a>);
struct KeySeed<'s, 'a>(&'s mut State<'a>);
struct EndSeed;

impl<'de> DeserializeSeed<'de> for EndSeed {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, _: D) -> std::result::Result<(), D::Error> {
        Err(de::Error::custom("unexpected checkpoint child callback"))
    }
}

impl<'de> DeserializeSeed<'de> for KeySeed<'_, '_> {
    type Value = ();
    #[inline(never)]
    fn deserialize<D: de::Deserializer<'de>>(self, de: D) -> std::result::Result<(), D::Error> {
        let end = self.0.token_end().map_err(|e| self.0.fail(e))?;
        let scalar = self.0.scalar(end).map_err(|e| self.0.fail(e))?;
        let Value::String(key) = scalar else {
            return Err(self.0.fail(Error::Json));
        };
        let decoded = String::deserialize(de)?;
        if decoded != key {
            return Err(self.0.fail(Error::Json));
        }
        self.0.pos = end;
        self.0.frame().map_err(de::Error::custom)?.key = Some(key);
        Ok(())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Json => "team_checkpoint_json_invalid",
            Self::Duplicate => "team_checkpoint_duplicate_key",
            Self::Limit => "team_checkpoint_limit_exceeded",
        })
    }
}

impl<'de> DeserializeSeed<'de> for Seed<'_, '_> {
    type Value = ();
    #[inline(never)]
    fn deserialize<D: de::Deserializer<'de>>(self, de: D) -> std::result::Result<(), D::Error> {
        self.0.start().map_err(|e| self.0.fail(e))?;
        if self.0.role == Role::UInt && matches!(self.0.byte(), Some(b'{' | b'[')) {
            return Err(self.0.fail(Error::Json));
        }
        match self.0.byte() {
            Some(b'{') => object(self.0, de)?,
            Some(b'[') => array(self.0, de)?,
            _ => scalar(self.0, de)?,
        }
        self.0.finish().map_err(|e| self.0.fail(e))
    }
}

#[inline(never)]
fn scalar<'de, D: de::Deserializer<'de>>(
    state: &mut State<'_>,
    de: D,
) -> std::result::Result<(), D::Error> {
    let end = state.token_end().map_err(|e| state.fail(e))?;
    if state.frame().map_err(de::Error::custom)?.role == Role::UInt
        && !uint_token(
            state
                .source
                .get(state.pos..end)
                .ok_or_else(|| state.fail::<D::Error>(Error::Json))?,
        )
    {
        return Err(state.fail(Error::Json));
    }
    let value = state.scalar(end).map_err(|e| state.fail(e))?;
    if state.frame().map_err(de::Error::custom)?.role == Role::UInt
        && PyInt::from_json_integer(&value).is_none()
    {
        return Err(state.fail(Error::Json));
    }
    IgnoredAny::deserialize(de)?;
    state.pos = end;
    state.scalars += 1;
    if state.build {
        state.frame().map_err(de::Error::custom)?.value = Some(value);
    }
    Ok(())
}

#[inline(never)]
fn object<'de, D: de::Deserializer<'de>>(
    state: &mut State<'_>,
    de: D,
) -> std::result::Result<(), D::Error> {
    state.pos += 1;
    if state.build {
        state.frame().map_err(de::Error::custom)?.value = Some(Value::Object(Map::new()));
    }
    de.deserialize_map(ObjectVisitor(state))
}

#[inline(never)]
fn array<'de, D: de::Deserializer<'de>>(
    state: &mut State<'_>,
    de: D,
) -> std::result::Result<(), D::Error> {
    state.pos += 1;
    if state.build {
        state.frame().map_err(de::Error::custom)?.value = Some(Value::Array(Vec::new()));
    }
    de.deserialize_seq(ArrayVisitor(state))
}

struct ObjectVisitor<'s, 'a>(&'s mut State<'a>);
struct ArrayVisitor<'s, 'a>(&'s mut State<'a>);

impl<'de> Visitor<'de> for ObjectVisitor<'_, '_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("checkpoint object")
    }
    #[inline(never)]
    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> std::result::Result<(), A::Error> {
        loop {
            self.0.ws();
            if self.0.byte() == Some(b'}') {
                if access.next_key_seed(EndSeed)?.is_some() {
                    return Err(self.0.fail(Error::Json));
                }
                self.0.pos += 1;
                return Ok(());
            }
            if self.0.frame().map_err(de::Error::custom)?.count != 0 {
                self.0.punctuation(b',').map_err(|e| self.0.fail(e))?;
            }
            self.0.ws();
            if self.0.byte() != Some(b'"') {
                return Err(self.0.fail(Error::Json));
            }
            if access.next_key_seed(KeySeed(self.0))?.is_none() {
                return Err(self.0.fail(Error::Json));
            }
            let role = map_child(self.0).map_err(|e| self.0.fail(e))?;
            self.0.punctuation(b':').map_err(|e| self.0.fail(e))?;
            self.0.role = role;
            access.next_value_seed(Seed(self.0))?;
        }
    }
}

#[inline(never)]
fn map_child(state: &mut State<'_>) -> Result<Role> {
    let frame = state.frame()?;
    let key = frame.key.as_ref().ok_or(Error::Json)?;
    if !frame.keys.insert(key.clone()) {
        return Err(Error::Duplicate);
    }
    if frame.role == Role::Vector && frame.count >= 256 {
        return Err(Error::Limit);
    }
    Ok(frame.role.field(key))
}

impl<'de> Visitor<'de> for ArrayVisitor<'_, '_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("checkpoint array")
    }
    #[inline(never)]
    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> std::result::Result<(), A::Error> {
        loop {
            self.0.ws();
            if self.0.byte() == Some(b']') {
                if access.next_element_seed(EndSeed)?.is_some() {
                    return Err(self.0.fail(Error::Json));
                }
                self.0.pos += 1;
                return Ok(());
            }
            if self.0.frame().map_err(de::Error::custom)?.count != 0 {
                self.0.punctuation(b',').map_err(|e| self.0.fail(e))?;
            }
            let frame = self.0.frame().map_err(de::Error::custom)?;
            if matches!(
                frame.role,
                Role::Heads | Role::Descriptors | Role::Components | Role::Pending
            ) && frame.count
                >= match frame.role {
                    Role::Components | Role::Descriptors => 6,
                    _ => 256,
                }
            {
                return Err(self.0.fail(Error::Limit));
            }
            self.0.role = frame.role.element(frame.count);
            if access.next_element_seed(Seed(self.0))?.is_none() {
                return Err(self.0.fail(Error::Json));
            }
        }
    }
}

fn run<'a>(span: Span<'a>, role: Role, build: bool) -> Result<Box<State<'a>>> {
    preflight(span.bytes(), 16_777_216, span.ancestors)?;
    let mut state = new_state(span.clone(), role, build);
    traverse(&mut state, &span)?;
    Ok(state)
}

fn new_state<'a>(span: Span<'a>, role: Role, build: bool) -> Box<State<'a>> {
    Box::new(State {
        source: span.source,
        pos: span.range.start,
        end: span.range.end,
        ancestors: span.ancestors,
        role,
        build,
        frames: Vec::new(),
        output: None,
        index: Index {
            root: span.clone(),
            components: std::array::from_fn(|_| None),
            commits: Vec::new(),
            facts: Vec::new(),
            counts: Counts::default(),
        },
        failure: Error::Json,
        entries: 0,
        scalars: 0,
        max_frames: 0,
        #[cfg(test)]
        before_value: None,
    })
}

fn traverse(state: &mut State<'_>, span: &Span<'_>) -> Result<()> {
    let mut de = serde_json::Deserializer::from_slice(span.bytes());
    Seed(state)
        .deserialize(&mut de)
        .map_err(|_| state.failure)?;
    de.end().map_err(|_| Error::Json)?;
    state.ws();
    if state.pos != state.end || !state.frames.is_empty() {
        return Err(Error::Json);
    }
    Ok(())
}

fn root(bytes: &[u8]) -> Span<'_> {
    Span {
        source: bytes,
        range: 0..bytes.len(),
        ancestors: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(bytes: &[u8]) -> Result<Value> {
        run(root(bytes), Role::Any, true)?
            .output
            .take()
            .ok_or(Error::Json)
    }

    #[test]
    fn d64_on_small_stack() {
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| {
                let text = format!("{}0{}", "[".repeat(64), "]".repeat(64));
                let value = parse(text.as_bytes()).unwrap();
                assert_eq!(
                    pyjson::dumps(&value, pyjson::DumpOptions::compact_sorted()).unwrap(),
                    text
                );
                assert_eq!(value, value.clone());
                drop(value);
            })
            .unwrap()
            .join()
            .unwrap();
    }
}

#[cfg(test)]
mod gate_tests {
    use super::*;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    const HUGE: &str = "9007199254740993123456789012345678901234567890";
    const NUMBER: &str = "$serde_json::private::Number";
    const RAW: &str = "$serde_json::private::RawValue";
    fn parse(text: &[u8]) -> Result<Value> {
        run(root(text), Role::Any, true)?
            .output
            .take()
            .ok_or(Error::Json)
    }
    fn canon(value: &Value) -> String {
        pyjson::dumps(value, pyjson::DumpOptions::compact_sorted()).unwrap()
    }
    fn object(key: &str, value: Value) -> Value {
        Value::Object([(key.into(), value)].into_iter().collect())
    }
    fn reserved_expected(id: &str) -> Value {
        let key = if id.starts_with("number_") {
            NUMBER
        } else {
            RAW
        };
        let suffix = id.split_once('_').unwrap().1;
        let value = match suffix {
            "singleton_integer" | "multi_first" | "multi_last" | "escaped_key" => json!("123"),
            "singleton_huge" => json!(HUGE),
            "singleton_finite" => json!("1.25"),
            "singleton_object" => json!("{\"a\":1}"),
            "singleton_array" => json!("[1,{\"x\":2}]"),
            "singleton_null" => json!("null"),
            "singleton_invalid" => json!("not-json"),
            "singleton_nonstring" => json!(123),
            "nested" => return json!({"outer":[object(key,json!("{\"x\":7}"))]}),
            _ => panic!("missing explicit oracle for {id}"),
        };
        let mut value = object(key, value);
        if suffix.starts_with("multi_") {
            value
                .as_object_mut()
                .unwrap()
                .insert("extra".into(), json!(true));
        }
        value
    }

    #[test]
    fn all_36_new_object_preserving_oracles_and_legacy_record_equality() {
        let corpus: Value = serde_json::from_str(include_str!(
            "../../../../docs/evidence/2026-11-07-m2a-raw-value-feature-probe/comparison.json"
        ))
        .unwrap();
        let rows = corpus["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 36);
        for row in rows {
            let id = row["id"].as_str().unwrap();
            let input = row["input"].as_str().unwrap();
            let value = parse(input.as_bytes()).unwrap();
            let expected = match id {
                "ordinary" => "{\"a\":[true,null,{\"text\":\"public-metadata\"}],\"b\":2}".into(),
                "ordinary_escaped_key" => "{\"a\":1,\"z\":\"escaped\"}".into(),
                "huge_integer" => HUGE.into(),
                "negative_huge_integer" => format!("-{HUGE}"),
                "nested_numbers" => format!(
                    "{{\"finite\":[1.25,1.0,-0.0,5e-324,1.7976931348623157e+308],\"large\":{HUGE}}}"
                ),
                "finite_1.25" => "1.25".into(),
                "finite_1e0" => "1.0".into(),
                "finite_-0.0" => "-0.0".into(),
                "finite_5e-324" => "5e-324".into(),
                "finite_1.7976931348623157e308" => "1.7976931348623157e+308".into(),
                "both_reserved_number_first" => canon(&json!({NUMBER:"123",RAW:"456"})),
                "both_reserved_raw_first" => canon(&json!({NUMBER:"456",RAW:"123"})),
                _ => canon(&reserved_expected(id)),
            };
            assert_eq!(canon(&value), expected, "{id}");
            if id.contains("singleton")
                || id.contains("multi")
                || id.contains("escaped")
                || id.contains("reserved")
            {
                assert!(value.is_object(), "{id}");
            }
            // Explicit materialization is also the independent oracle for the
            // unchanged Commit/Fact constructors, not a whole-object loader.
            let commit = crate::team::commit::Commit {
                format: "zeropw-team-commit-v1".into(),
                env_id: "public-env".into(),
                author: "public-author".into(),
                author_seq: 1.into(),
                hlc: "0001-0000".into(),
                seen: Default::default(),
                ops: vec![object("legacy", value.clone())],
                sig: "synthetic-sig".into(),
            };
            let encoded = commit.canonical_json(true).unwrap();
            let decoded = parse(&encoded).unwrap();
            let reconstructed = crate::team::commit::Commit::from_dict(&decoded).unwrap();
            assert_eq!(reconstructed.canonical_json(true).unwrap(), encoded);
            assert_eq!(
                reconstructed.hash().unwrap(),
                hex::encode(Sha256::digest(&encoded))
            );
            let fact = crate::team::sync::Fact {
                format: "zeropw-team-fact-v1".into(),
                env_id: "public-env".into(),
                kind: "incident".into(),
                target: object("legacy", value.clone()),
                author: "public-author".into(),
                hlc: "0001-0000".into(),
                sig: "synthetic-sig".into(),
            };
            let encoded = fact.canonical_json(true).unwrap();
            let reconstructed =
                crate::team::sync::Fact::from_dict(&parse(&encoded).unwrap()).unwrap();
            assert_eq!(reconstructed.canonical_json(true).unwrap(), encoded);
            assert_eq!(
                reconstructed.hash().unwrap(),
                hex::encode(Sha256::digest(&encoded))
            );
            let snapshot = json!({"document":{"legacy":value}});
            assert_eq!(
                canon(&parse(canon(&snapshot).as_bytes()).unwrap()),
                canon(&snapshot)
            );
        }
    }

    #[test]
    fn syntax_unicode_and_grammar_mutations() {
        let invalid: &[&[u8]] = &[
            b"",
            b" ",
            b"{",
            b"[",
            b"{]",
            b"[}",
            b"[1,]",
            b"{\"a\":0,}",
            b"[,1]",
            b"{,\"a\":0}",
            b"[1 2]",
            b"{\"a\" 1}",
            b"{\"a\"::1}",
            b"{\"a\":1 \"b\":2}",
            b"1true",
            b"1 2",
            b"\"a\"\"b\"",
            b"01",
            b"+1",
            b"1.",
            b"1e",
            b"--1",
            b"truefalse",
            b"1e999999",
            b"nullx",
            b"//x\n1",
            b"/*x*/1",
            b"\xef\xbb\xbf{}",
            b"[\xc2\xa01]",
            b"[1\x0b]",
            b"[1\x0c]",
            b"\"\\x\"",
            b"\"\\u123\"",
            b"\"\\uZZZZ\"",
            b"\"\\ud800\"",
            b"\"\\udc00\"",
            b"{\"\\ud800\":0}",
            b"{\"x\":\"\xff\"}",
            b"\"abc\\",
            b"\"abc",
            b"\"a\nb\"",
        ];
        for input in invalid {
            assert!(parse(input).is_err(), "{:?}", input);
        }
        for text in [
            "null",
            "true",
            "false",
            "0",
            "-1",
            "-0",
            "1.0",
            "-0.0",
            "1e-7",
            "[ ]",
            "{ }",
            r#"{"é":"\ud83d\ude00","é":[],"x":"\\\"{}[]"}"#,
        ] {
            assert!(parse(text.as_bytes()).is_ok(), "{text}");
        }
        // Deterministic insertion/deletion/substitution coverage. Ordinary
        // grammar only: no duplicate collapse or reserved-key semantics oracle.
        for text in [
            r#"{"x":[1,true,null,"a\\\"b",{}]}"#,
            "[0,-1,1e2,[],{\"q\":false}]",
            r#"{"é":"\ud83d\ude00"}"#,
        ] {
            for position in 0..=text.len() {
                for byte in [
                    b' ', b',', b':', b'[', b']', b'{', b'}', b'"', b'\\', b'0', b't', b'/', 0xff,
                ] {
                    let mut mutated = text.as_bytes().to_vec();
                    mutated.insert(position, byte);
                    let old = std::str::from_utf8(&mutated)
                        .ok()
                        .and_then(|s| pyjson::loads(s).ok());
                    assert_eq!(
                        parse(&mutated).is_ok(),
                        old.is_some(),
                        "insert {position} {byte} {mutated:?}"
                    );
                    if position < text.len() {
                        let mut mutated = text.as_bytes().to_vec();
                        mutated[position] = byte;
                        let old = std::str::from_utf8(&mutated)
                            .ok()
                            .and_then(|s| pyjson::loads(s).ok());
                        assert_eq!(
                            parse(&mutated).is_ok(),
                            old.is_some(),
                            "replace {position} {byte} {mutated:?}"
                        );
                    }
                }
                if position < text.len() {
                    let mut mutated = text.as_bytes().to_vec();
                    mutated.remove(position);
                    let old = std::str::from_utf8(&mutated)
                        .ok()
                        .and_then(|s| pyjson::loads(s).ok());
                    assert_eq!(
                        parse(&mutated).is_ok(),
                        old.is_some(),
                        "delete {position} {mutated:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn duplicate_before_value_and_non_normalized_keys() {
        for text in [
            r#"{"x":0,"x":1}"#,
            r#"{"x":0,"\u0078":1}"#,
            r#"{"x":0,"y":1,"x":2}"#,
            r#"{"😀":0,"\ud83d\ude00":1}"#,
            r#"{"target":{"x":0,"x":1}}"#,
            r#"{"$serde_json::private::Number":0,"$serde_json::private::Numbe\u0072":1}"#,
            r#"{"$serde_json::private::RawValue":0,"$serde_json::private::RawValue":1}"#,
        ] {
            assert!(
                matches!(parse(text.as_bytes()), Err(Error::Duplicate)),
                "{text}"
            );
        }
        for suffix in [
            "invalid".into(),
            format!("\"{}\"", "s".repeat(1_000_000)),
            format!("{}0{}", "[".repeat(63), "]".repeat(63)),
        ] {
            let text = format!("{{\"x\":0,\"x\":{suffix}}}");
            // A scalar-only invalid second value still gives Duplicate: the
            // child seed would have returned Json had it actually been entered.
            assert!(matches!(parse(text.as_bytes()), Err(Error::Duplicate)));
        }
        assert_eq!(
            parse("{\"é\":0,\"é\":1}".as_bytes())
                .unwrap()
                .as_object()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn golden_component_spans_and_hash_scopes() {
        // Literal offsets, independently counted; not cursor-derived oracles.
        let text = b"{\"components\":[{\"data\": \t[ ] \r,\"name\":\"devices\"}]}";
        let state = run(root(text), Role::Payload, false).unwrap();
        let span = state.index.components[0].as_ref().unwrap();
        assert_eq!(span.range, 25..28);
        assert_eq!(span.bytes(), b"[ ]");
        assert_eq!(span.ancestors, 3);
        let inside = b"{\"components\":[{\"data\": \t[  ] \r,\"name\":\"devices\"}]}";
        let outside = b"{\"components\":[{\"data\":  \t[ ] \r,\"name\":\"devices\"}]}";
        let hash = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
        let b = run(root(inside), Role::Payload, false).unwrap();
        let c = run(root(outside), Role::Payload, false).unwrap();
        assert_ne!(hash(text), hash(inside));
        assert_ne!(hash(text), hash(outside));
        assert_ne!(
            hash(span.bytes()),
            hash(b.index.components[0].as_ref().unwrap().bytes())
        );
        assert_eq!(
            hash(span.bytes()),
            hash(c.index.components[0].as_ref().unwrap().bytes())
        );
        let complex = "{\"components\":[{\"data\": {\"x\":\"é\\\\\\\"[]{}\",\"p\":\"\\ud83d\\ude00\",\"z\":[{},[]]} ,\"name\":\"devices\"}]}";
        let state = run(root(complex.as_bytes()), Role::Payload, true).unwrap();
        let span = state.index.components[0].as_ref().unwrap();
        assert_eq!(span.range, 24..73);
        assert_eq!(
            span.bytes(),
            "{\"x\":\"é\\\\\\\"[]{}\",\"p\":\"\\ud83d\\ude00\",\"z\":[{},[]]}".as_bytes()
        );
        assert_eq!(
            run(span.clone(), Role::Any, true).unwrap().output,
            Some(state.output.as_ref().unwrap()["components"][0]["data"].clone())
        );
    }

    #[test]
    fn count_before_children_and_across_reordered_components() {
        for (role, limit) in [
            (Role::Devices, 256),
            (Role::Chunks, 256),
            (Role::CommitEntries, 65_536),
            (Role::FactEntries, 65_536),
        ] {
            let valid = format!("[{}]", vec!["{}"; limit].join(","));
            let state = run(root(valid.as_bytes()), role, false).unwrap();
            assert_eq!(state.entries, limit + 1);
            let invalid = format!("[{},invalid]", vec!["{}"; limit].join(","));
            assert!(matches!(
                run(root(invalid.as_bytes()), role, true),
                Err(Error::Limit)
            ));
        }
        let text = format!(
            "{{\"components\":[{{\"data\":[],\"name\":\"devices\"}},{{\"data\":{{\"document\":{{\"secrets\":{{\"s\":{{\"versions\":{{\"v\":{{}}}},\"legacy\":{{\"versions\":{{\"not-a-record\":null}}}}}}}}}}}},\"name\":\"snapshot\"}},{{\"data\":{{\"records\":[{}]}},\"name\":\"commits\"}},{{\"data\":{{\"records\":[{{}}]}},\"name\":\"facts\"}}]}}",
            vec!["{}"; 65_534].join(",")
        );
        let state = run(root(text.as_bytes()), Role::Payload, false).unwrap();
        assert_eq!(state.index.counts.combined, 65_536);
        assert_eq!(state.index.counts.versions, 1);
        let mut counts = state.index.counts.clone();
        assert_eq!(counts.enter(Role::Version), Err(Error::Limit));
        let one_more = text
            .replacen("\"facts\"", "\"facts\"", 1)
            .replace("\"records\":[{}]", "\"records\":[{},invalid]");
        assert!(matches!(
            run(root(one_more.as_bytes()), Role::Payload, true),
            Err(Error::Limit)
        ));
        // Independent private quota boundary; no wire-size artifact excuses it.
        let mut counts = Counts::default();
        for i in 0..65_536 {
            counts
                .enter([Role::CommitEntry, Role::FactEntry, Role::Version][i % 3])
                .unwrap();
        }
        assert_eq!(counts.enter(Role::FactEntry), Err(Error::Limit));
    }

    #[test]
    fn uint_source_tokens_exact_integers_and_finite_legacy_numbers() {
        for token in ["true", "\"1\"", "1.0", "1e0", "-1", "-0", "null"] {
            assert!(
                run(root(token.as_bytes()), Role::UInt, true).is_err(),
                "{token}"
            );
        }
        for token in [
            "0",
            "9007199254740993",
            "1844674407370955161600000000000000000001",
        ] {
            let state = run(root(token.as_bytes()), Role::UInt, true).unwrap();
            assert_eq!(canon(state.output.as_ref().unwrap()), token);
        }
        let legacy = b"[1.0,-0.0,1e-7,1e2,-1844674407370955161600000000000000000001]";
        assert_eq!(
            canon(&parse(legacy).unwrap()),
            "[1.0,-0.0,1e-07,100.0,-1844674407370955161600000000000000000001]"
        );
        assert!(run(root(b"{\"counts\":{\"devices\":-0}}"), Role::Manifest, true).is_err());
    }

    #[test]
    fn small_stack_alternating_wrapped_success_errors_and_drop() {
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| {
                for depth in [1, 32, 64] {
                    let mut text = "9007199254740993".to_owned();
                    for i in 0..depth {
                        text = if i % 2 == 0 {
                            format!("{{\"\\u0078\":{text}}}")
                        } else {
                            format!("[{text}]")
                        };
                    }
                    let state = run(root(text.as_bytes()), Role::Any, false).unwrap();
                    assert_eq!(state.max_frames, depth + 1);
                    let value = parse(text.as_bytes()).unwrap();
                    let canonical = canon(&value);
                    let digest = Sha256::digest(canonical.as_bytes());
                    assert_eq!(digest.len(), 32);
                    assert_eq!(value, value.clone());
                    drop(value);
                }
                for depth in [64, 65, 4096] {
                    let text = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
                    assert_eq!(parse(text.as_bytes()).is_ok(), depth == 64);
                }
                for inner in [
                    r#"{"x":0,"x":invalid}"#,
                    r#"{"x": [0,]}"#,
                    r#"{"x":"\ud800"}"#,
                ] {
                    let text = format!("{}{}{}", "[".repeat(63), inner, "]".repeat(63));
                    assert!(parse(text.as_bytes()).is_err());
                }
                let inner = format!("{}0{}", "[".repeat(62), "]".repeat(62));
                let wrapped = format!("{{\"legacy\":{{\"child\":{inner}}}}}");
                let state = run(root(wrapped.as_bytes()), Role::Any, true).unwrap();
                drop(state);
                let over = wrapped.replacen('0', "[0]", 1);
                assert!(matches!(parse(over.as_bytes()), Err(Error::Limit)));
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn measured_wide_input_and_long_numeric_work() {
        let start = std::time::Instant::now();
        let text = format!(
            "{{{}}}",
            (0..200_000)
                .map(|i| format!("\"k{i}\":0"))
                .collect::<Vec<_>>()
                .join(",")
        );
        let state = run(root(text.as_bytes()), Role::Any, false).unwrap();
        assert_eq!(state.entries, 200_001);
        assert_eq!(state.scalars, 200_000);
        println!(
            "wide bytes={} entries={} max_frames={} state_bytes={} frame_bytes={} elapsed_ms={}",
            text.len(),
            state.entries,
            state.max_frames,
            std::mem::size_of::<State<'_>>(),
            std::mem::size_of::<Frame>(),
            start.elapsed().as_millis()
        );
        // RSS includes allocator bookkeeping and other test process allocations;
        // it is measured, not an asserted per-transfer capacity guarantee.
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status
                .lines()
                .filter(|l| l.starts_with("VmHWM:") || l.starts_with("VmRSS:"))
            {
                println!("{line}");
            }
        }
        for digits in [10_000, 100_000] {
            let number = "9".repeat(digits);
            let start = std::time::Instant::now();
            let state = run(root(number.as_bytes()), Role::UInt, true).unwrap();
            assert_eq!(canon(state.output.as_ref().unwrap()), number);
            println!(
                "numeric digits={digits} elapsed_ms={}",
                start.elapsed().as_millis()
            );
        }
    }
}

#[cfg(test)]
mod callback_tests {
    use super::*;

    #[test]
    fn duplicate_never_invokes_a_second_value_seed_or_materializer() {
        for second in [
            "invalid".to_owned(),
            format!("\"{}\"", "s".repeat(1_000_000)),
            format!("{}0{}", "[".repeat(63), "]".repeat(63)),
        ] {
            let bytes = format!("{{\"x\":0,\"\\u0078\":{second}}}");
            preflight(bytes.as_bytes(), 16_777_216, 0).unwrap();
            let span = root(bytes.as_bytes());
            let mut state = new_state(span.clone(), Role::Any, true);
            state.before_value =
                Some(|entries| assert!(entries < 2, "duplicate child decoder invoked"));
            assert_eq!(traverse(&mut state, &span), Err(Error::Duplicate));
            assert_eq!(state.entries, 2);
            assert_eq!(state.scalars, 1);
        }
    }

    struct PrematureEnd;
    struct UnexpectedChild;
    impl<'de> MapAccess<'de> for PrematureEnd {
        type Error = de::value::Error;
        fn next_key_seed<K: DeserializeSeed<'de>>(
            &mut self,
            _: K,
        ) -> std::result::Result<Option<K::Value>, Self::Error> {
            Ok(None)
        }
        fn next_value_seed<V: DeserializeSeed<'de>>(
            &mut self,
            _: V,
        ) -> std::result::Result<V::Value, Self::Error> {
            panic!("value after false None")
        }
    }
    impl<'de> SeqAccess<'de> for PrematureEnd {
        type Error = de::value::Error;
        fn next_element_seed<T: DeserializeSeed<'de>>(
            &mut self,
            _: T,
        ) -> std::result::Result<Option<T::Value>, Self::Error> {
            Ok(None)
        }
    }
    impl<'de> MapAccess<'de> for UnexpectedChild {
        type Error = de::value::Error;
        fn next_key_seed<K: DeserializeSeed<'de>>(
            &mut self,
            seed: K,
        ) -> std::result::Result<Option<K::Value>, Self::Error> {
            seed.deserialize(de::value::UnitDeserializer::<Self::Error>::new())
                .map(Some)
        }
        fn next_value_seed<V: DeserializeSeed<'de>>(
            &mut self,
            _: V,
        ) -> std::result::Result<V::Value, Self::Error> {
            panic!("value after false Some")
        }
    }
    impl<'de> SeqAccess<'de> for UnexpectedChild {
        type Error = de::value::Error;
        fn next_element_seed<T: DeserializeSeed<'de>>(
            &mut self,
            seed: T,
        ) -> std::result::Result<Option<T::Value>, Self::Error> {
            seed.deserialize(de::value::UnitDeserializer::<Self::Error>::new())
                .map(Some)
        }
    }

    #[test]
    fn both_directions_of_some_none_callback_disagreement_refuse() {
        for (bytes, end) in [(b"{\"x\":0}".as_slice(), false), (b"{}", true)] {
            let mut state = new_state(root(bytes), Role::Any, false);
            state.start().unwrap();
            state.pos = 1;
            let refused = if end {
                ObjectVisitor(&mut state)
                    .visit_map(UnexpectedChild)
                    .is_err()
            } else {
                ObjectVisitor(&mut state).visit_map(PrematureEnd).is_err()
            };
            assert!(refused);
        }
        for (bytes, end) in [(b"[0]".as_slice(), false), (b"[]", true)] {
            let mut state = new_state(root(bytes), Role::Any, false);
            state.start().unwrap();
            state.pos = 1;
            let refused = if end {
                ArrayVisitor(&mut state).visit_seq(UnexpectedChild).is_err()
            } else {
                ArrayVisitor(&mut state).visit_seq(PrematureEnd).is_err()
            };
            assert!(refused);
        }
    }
}
