//! Session-only feature negotiation and exact durable deletion agreement.
use crate::{
    errors::{Error, Result},
    pyjson::{self, DumpOptions},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, time::Instant};
pub const FEATURE: &str = "secret_tombstone_v1";
pub const MAX_CONTROL_BYTES: usize = 1024;
pub const CAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
pub fn digest(facts: &BTreeMap<String, Value>) -> Result<String> {
    Ok(hex::encode(Sha256::digest(
        pyjson::dumps(
            &json!(facts.keys().collect::<Vec<_>>()),
            DumpOptions::compact_sorted(),
        )?
        .as_bytes(),
    )))
}
pub fn empty_digest() -> String {
    hex::encode(Sha256::digest(b"[]"))
}
pub fn is_control(kind: &str) -> bool {
    matches!(kind, "SYNC_CAPS" | "TOMBSTONE_STATE" | "TOMBSTONE_ACK")
}
fn hex_field(value: &Value, n: usize) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() == n
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
pub fn validate(message: &Value) -> Result<()> {
    let bad = || Error::invalid_input("team_sync_control_malformed");
    let obj = message.as_object().ok_or_else(bad)?;
    if pyjson::dumps(message, DumpOptions::compact_sorted())?.len() > MAX_CONTROL_BYTES {
        return Err(bad());
    }
    match message["type"].as_str() {
        Some("SYNC_CAPS")
            if obj.len() == 3 && obj.contains_key("v") && obj.contains_key("features") =>
        {
            if message["v"].as_u64() != Some(1)
                || message["v"]
                    .as_number()
                    .is_some_and(|n| pyjson::is_float_literal(n.as_str()))
            {
                return Err(bad());
            }
            let features = message["features"].as_array().ok_or_else(bad)?;
            let mut seen = std::collections::HashSet::new();
            if features.len() > 16
                || features.iter().any(|f| {
                    !f.as_str()
                        .is_some_and(|s| s.len() <= 64 && s.is_ascii() && seen.insert(s))
                })
            {
                return Err(bad());
            }
        }
        Some("TOMBSTONE_STATE" | "TOMBSTONE_ACK")
            if obj.len() == 3
                && hex_field(&message["digest"], 64)
                && hex_field(&message["request_id"], 32) => {}
        _ => return Err(bad()),
    }
    Ok(())
}
#[derive(Clone)]
pub struct Gate {
    pub started: Instant,
    pub caps_sent: bool,
    pub caps: Option<bool>,
    pub peer_state: Option<(String, String)>,
    pub current: Option<(String, String)>,
    pub acked: bool,
    pub announced: bool,
    pub last_state_send: Option<Instant>,
    pub ack_reply: Option<(String, String)>,
}
impl Default for Gate {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            caps_sent: false,
            caps: None,
            peer_state: None,
            current: None,
            acked: false,
            announced: false,
            last_state_send: None,
            ack_reply: None,
        }
    }
}
impl Gate {
    pub fn invalidate(&mut self) {
        self.current = None;
        self.acked = false;
        self.announced = false;
        self.ack_reply = None;
    }
    pub fn request(&mut self, digest: &str) -> Value {
        if self.current.as_ref().is_none_or(|(d, _)| d != digest) {
            use rand::RngCore;
            let mut bytes = [0; 16];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            self.current = Some((digest.into(), hex::encode(bytes)));
            self.acked = false;
            self.announced = false;
        }
        let request = self.current.as_ref().map(|(_, r)| r.as_str()).unwrap_or("");
        json!({"type":"TOMBSTONE_STATE","digest":digest,"request_id":request})
    }
    pub fn receive_state(&mut self, message: &Value) {
        let incoming = (
            message["digest"].as_str().unwrap_or("").into(),
            message["request_id"].as_str().unwrap_or("").into(),
        );
        if self
            .peer_state
            .as_ref()
            .is_some_and(|old| old.0 != incoming.0)
        {
            self.invalidate();
        }
        self.peer_state = Some(incoming);
        self.ack_reply = None;
    }
    pub fn receive_ack(&mut self, message: &Value, digest: &str) {
        if self.announced
            && self.current.as_ref().is_some_and(|(d, r)| {
                d == digest && message["digest"] == *d && message["request_id"] == *r
            })
        {
            self.acked = true;
        }
    }
    pub fn ready(&self, digest: &str, required: bool) -> bool {
        if !self.caps_sent {
            return false;
        }
        if self.caps != Some(true) {
            return !required;
        }
        self.announced
            && self.acked
            && self.current.as_ref().is_some_and(|(d, _)| d == digest)
            && self.peer_state.as_ref().is_some_and(|(d, _)| d == digest)
    }
    pub fn allows_data(&self, required: bool) -> bool {
        if !self.caps_sent {
            return false;
        }
        if self.caps == Some(true) {
            self.announced
        } else {
            !required
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn control_bounds_types_unknown_features_and_duplicate_keys() {
        assert!(validate(&json!({"type":"SYNC_CAPS","v":1,"features":["unrelated"]})).is_ok());
        for bad in [
            json!({"type":"SYNC_CAPS","v":true,"features":[]}),
            json!({"type":"SYNC_CAPS","v":1.0,"features":[]}),
            json!({"type":"SYNC_CAPS","v":2,"features":[]}),
            json!({"type":"SYNC_CAPS","v":1,"features":vec!["x";17]}),
            json!({"type":"SYNC_CAPS","v":1,"features":["x".repeat(65)]}),
            json!({"type":"SYNC_CAPS","v":1,"features":[1]}),
            json!({"type":"SYNC_CAPS","v":1,"features":[],"extra":true}),
            json!({"type":"TOMBSTONE_ACK","digest":"A".repeat(64),"request_id":"b".repeat(32)}),
            json!({"type":"TOMBSTONE_STATE","digest":"a".repeat(64),"request_id":"b".repeat(31)}),
        ] {
            assert!(validate(&bad).is_err(), "{bad}");
        }
        assert!(
            pyjson::loads_unique_object(r#"{"type":"SYNC_CAPS","v":1,"v":1,"features":[]}"#)
                .is_err()
        );
        let mut gate = Gate::default();
        assert!(!gate.ready(&empty_digest(), false));
        assert!(!gate.allows_data(false));
        gate.caps_sent = true;
        assert!(gate.ready(&empty_digest(), false));
        gate.caps = Some(true);
        assert!(!gate.ready(&empty_digest(), false));
        let old = gate.request(&empty_digest());
        gate.announced = true;
        gate.receive_state(&json!({"digest":empty_digest(),"request_id":"a".repeat(32)}));
        gate.receive_ack(
            &json!({"digest":old["digest"],"request_id":old["request_id"]}),
            &empty_digest(),
        );
        assert!(gate.ready(&empty_digest(), true));
        gate.receive_state(&json!({"digest":"f".repeat(64),"request_id":"b".repeat(32)}));
        assert!(!gate.ready(&empty_digest(), true));
    }
}
