//! Bounds and original-byte controls, independent of the permissive v1 parser.
use super::bad;
use crate::{errors::Result, pyjson};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

pub(crate) const PAYLOAD_CAP: usize = 16 * 1024 * 1024;
pub(crate) const CHUNK_CAP: usize = 64 * 1024;
pub(crate) const TOTAL: Duration = Duration::from_secs(600);
pub(crate) const IDLE: Duration = Duration::from_secs(30);

fn malformed() -> crate::Error {
    bad("team_bootstrap_control_malformed")
}

fn string_end(raw: &[u8], start: usize) -> Result<usize> {
    let mut i = start.checked_add(1).ok_or_else(malformed)?;
    while let Some(b) = raw.get(i) {
        match b {
            b'"' => return Ok(i + 1),
            b'\\' => i = i.checked_add(1).ok_or_else(malformed)?,
            _ => {}
        }
        i = i.checked_add(1).ok_or_else(malformed)?;
    }
    Err(malformed())
}

fn decoded(raw: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(raw).map_err(|_| malformed())?;
    pyjson::loads(text)
        .map_err(|_| malformed())?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(malformed)
}

/// Locate only the top-level type before constructing any peer-controlled
/// object or expanding base64. Escaped spelling is decoded, not searched for.
pub(crate) fn kind(raw: &[u8]) -> Result<Option<String>> {
    let mut depth = 0usize;
    let mut i = 0usize;
    let mut key = true;
    let mut type_key = false;
    let mut result = None;
    while let Some(b) = raw.get(i) {
        match b {
            b'"' => {
                let end = string_end(raw, i)?;
                if depth == 1 {
                    if key {
                        type_key = decoded(&raw[i..end])? == "type";
                    } else if type_key {
                        let k = decoded(&raw[i..end])?;
                        if k.len() > 64 {
                            return Err(malformed());
                        }
                        result = Some(k);
                    }
                }
                i = end;
                continue;
            }
            b'{' | b'[' => {
                depth = depth.checked_add(1).ok_or_else(malformed)?;
                if depth > 512 {
                    return Err(malformed());
                }
                if depth == 1 {
                    key = true;
                }
            }
            b'}' | b']' => depth = depth.checked_sub(1).ok_or_else(malformed)?,
            b':' if depth == 1 => key = false,
            b',' if depth == 1 => {
                key = true;
                type_key = false;
            }
            _ => {}
        }
        i += 1;
    }
    Ok(result)
}

pub(crate) fn is_control(kind: &str) -> bool {
    kind.starts_with("BOOTSTRAP_")
}

struct Object {
    object: bool,
    key: bool,
    keys: BTreeSet<String>,
}

/// Duplicate and depth validation finish before the legacy byte-compatible
/// JSON helper materializes a tree. Existing v1 messages never use this path.
pub(crate) fn parse(raw: &[u8]) -> Result<Value> {
    if raw.len() > 131_072 {
        return Err(bad("team_bootstrap_limit_exceeded"));
    }
    let k = kind(raw)?.ok_or_else(malformed)?;
    let cap = match k.as_str() {
        "BOOTSTRAP_MANIFEST" | "BOOTSTRAP_ACK" => 65_536,
        "BOOTSTRAP_CHUNK" => 131_072,
        "SYNC_CAPS" => 1024,
        _ => 4096,
    };
    if raw.len() > cap {
        return Err(bad("team_bootstrap_limit_exceeded"));
    }
    let mut stack: Vec<Object> = Vec::new();
    let mut i = 0;
    while let Some(b) = raw.get(i) {
        match b {
            b'{' | b'[' => {
                if stack.len() >= 64 {
                    return Err(bad("team_bootstrap_limit_exceeded"));
                }
                stack.push(Object {
                    object: *b == b'{',
                    key: *b == b'{',
                    keys: BTreeSet::new(),
                });
            }
            b'}' | b']' => {
                let top = stack.pop().ok_or_else(malformed)?;
                if top.object != (*b == b'}') {
                    return Err(malformed());
                }
            }
            b'"' => {
                let end = string_end(raw, i)?;
                if let Some(top) = stack.last_mut()
                    && top.object
                    && top.key
                    && !top.keys.insert(decoded(&raw[i..end])?)
                {
                    return Err(bad("team_checkpoint_duplicate_key"));
                }
                i = end;
                continue;
            }
            b':' => {
                if let Some(top) = stack.last_mut() {
                    top.key = false;
                }
            }
            b',' => {
                if let Some(top) = stack.last_mut() {
                    top.key = top.object;
                }
            }
            _ => {}
        }
        i += 1;
    }
    if !stack.is_empty() {
        return Err(malformed());
    }
    let value = pyjson::loads(std::str::from_utf8(raw).map_err(|_| malformed())?)
        .map_err(|_| malformed())?;
    if !value.is_object() {
        return Err(malformed());
    }
    Ok(value)
}

pub(crate) fn fields(value: &Value, names: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or_else(malformed)?;
    if object.len() != names.len() || names.iter().any(|k| !object.contains_key(*k)) {
        return Err(malformed());
    }
    Ok(())
}

pub(crate) struct Deadline {
    start: Instant,
    last: Instant,
}
impl Deadline {
    pub(crate) fn new() -> Self {
        let now = Instant::now();
        Self {
            start: now,
            last: now,
        }
    }
    pub(crate) fn check(&self) -> Result<()> {
        if self.start.elapsed() >= TOTAL || self.last.elapsed() >= IDLE {
            Err(bad("team_bootstrap_timeout"))
        } else {
            Ok(())
        }
    }
    pub(crate) fn progress(&mut self) -> Result<()> {
        self.check()?;
        self.last = Instant::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_control_rejects_nested_duplicates_escaped_type_and_depth_before_materialization() {
        assert_eq!(
            kind(br#"{"type":"\u0042OOTSTRAP_READY"}"#)
                .unwrap()
                .as_deref(),
            Some("BOOTSTRAP_READY")
        );
        for raw in [
            br#"{"type":"BOOTSTRAP_READY","a":{"x":1,"x":2}}"#.as_slice(),
            br#"{"type":"BOOTSTRAP_READY","type":"BOOTSTRAP_ACK"}"#,
        ] {
            assert!(parse(raw).is_err());
        }
        let deep = format!(
            "{{\"type\":\"BOOTSTRAP_READY\",\"a\":{}0{}}}",
            "[".repeat(64),
            "]".repeat(64)
        );
        assert!(parse(deep.as_bytes()).is_err());
        let large = format!(
            "{{\"type\":\"BOOTSTRAP_REQUEST\",\"x\":\"{}\"}}",
            "a".repeat(4096)
        );
        assert!(parse(large.as_bytes()).is_err());
        assert!(parse(br#"{"type":"BOOTSTRAP_REQUEST","a":{"x":1},"b":{"x":2}}"#).is_ok());
    }
    #[test]
    fn personal_bootstrap_control_exact_caps_and_monotonic_deadlines() {
        for (kind, cap) in [
            ("SYNC_CAPS", 1024),
            ("BOOTSTRAP_REQUEST", 4096),
            ("BOOTSTRAP_READY", 4096),
            ("BOOTSTRAP_MANIFEST", 65_536),
            ("BOOTSTRAP_ACK", 65_536),
            ("BOOTSTRAP_CHUNK", 131_072),
        ] {
            let mut raw = format!("{{\"type\":\"{kind}\"}}").into_bytes();
            raw.resize(cap, b' ');
            assert!(parse(&raw).is_ok());
            raw.push(b' ');
            assert!(parse(&raw).is_err());
        }
        let depth64 = format!(
            "{{\"type\":\"BOOTSTRAP_REQUEST\",\"a\":{}0{}}}",
            "[".repeat(63),
            "]".repeat(63)
        );
        assert!(parse(depth64.as_bytes()).is_ok());
        assert!(parse(br#"{"type":"BOOTSTRAP_READY","a":{"x":1,"\u0078":2}}"#).is_err());
        let now = Instant::now();
        assert!(
            Deadline {
                start: now - TOTAL,
                last: now
            }
            .check()
            .is_err()
        );
        assert!(
            Deadline {
                start: now,
                last: now - IDLE
            }
            .progress()
            .is_err()
        );
        assert!(Deadline::new().progress().is_ok());
    }
}
