//! Sync status for the UI (docs/remote-sync.md §3.3).
//!
//! A running `serve` writes `team/ENV_ID/sync_state.json` (0600, atomic
//! replace, at most every [`WRITE_INTERVAL`] and only when something
//! changed):
//!
//! ```text
//! {"updated_at", "self", "peers": {FP: {"session", "since", "peer_vector",
//!   "vector_received_at", "transport", "dial_failures", "next_attempt_at",
//!   "last_error", "last_contact_at"}}}
//! ```
//!
//! Values are metadata only: booleans, counts, ISO times, version vectors
//! (author fingerprint to sequence), the transport name and reason codes.
//! [`status`] (`team sync-status`) merges it with the local store and the
//! folded document.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use serde_json::{Map, Value, json};

use super::commit::CommitStore;
use super::identity::DeviceKey;
use crate::context::Context;
use crate::errors::{Error, Result};
use crate::pyint::PyInt;
use crate::store::iso;

/// The least time between two writes of `sync_state.json`.
pub const WRITE_INTERVAL: Duration = Duration::from_secs(2);

pub fn path(env_id: &str) -> String {
    format!("team/{env_id}/sync_state.json")
}

/// What `serve` knows about one peer of an environment.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PeerState {
    pub session: bool,
    pub tombstone_agreement: Option<Value>,
    /// When the current session was accepted.
    pub since: Option<f64>,
    /// The last VECTOR this peer sent, and when it arrived.
    pub peer_vector: Option<BTreeMap<String, PyInt>>,
    pub vector_received_at: Option<f64>,
    /// `"tcp"` or `"link"` while a session is open.
    pub transport: Option<&'static str>,
    /// Dials that failed since the peer last answered.
    pub dial_failures: u64,
    pub next_attempt_at: Option<f64>,
    /// The reason code of the last failed dial.
    pub last_error: Option<String>,
    /// The last time a handshake with this peer completed or a frame from it
    /// was handled.
    pub last_contact_at: Option<f64>,
}

fn time(ts: Option<f64>) -> Value {
    ts.filter(|ts| ts.is_finite() && *ts >= 0.0)
        .map_or(Value::Null, |ts| json!(iso(Some(ts))))
}

/// The `peers` object of `sync_state.json` (without `updated_at`, so two of
/// them compare equal exactly when nothing changed).
pub fn peers_value(peers: &BTreeMap<String, PeerState>) -> Value {
    let mut out = Map::new();
    for (fp, peer) in peers {
        let mut value = json!({
            "session": peer.session,
            "since": if peer.session { time(peer.since) } else { Value::Null },
            "peer_vector": peer.peer_vector.as_ref().map_or(Value::Null, |v| json!(v)),
            "vector_received_at": time(peer.vector_received_at),
            "transport": if peer.session { peer.transport.map_or(Value::Null, |t| json!(t)) } else { Value::Null },
            "dial_failures": peer.dial_failures,
            "next_attempt_at": if peer.dial_failures > 0 { time(peer.next_attempt_at) } else { Value::Null },
            "last_error": peer.last_error.as_ref().map_or(Value::Null, |e| json!(e)),
            "last_contact_at": time(peer.last_contact_at),
        });
        if let Some(agreement) = &peer.tombstone_agreement {
            value["tombstone_agreement"] = agreement.clone();
        }
        out.insert(fp.clone(), value);
    }
    Value::Object(out)
}

/// The whole `sync_state.json` document.
pub fn file_value(updated_at: f64, self_fp: &str, peers: &Value) -> Value {
    json!({"updated_at": iso(Some(updated_at)), "self": self_fp, "peers": peers})
}

/// The `last_contact_at` of each peer in an existing `sync_state.json`, so a
/// restarted `serve` keeps telling `offline` from `never_connected`. Anything
/// unreadable is ignored: `serve` replaces the file with its own view.
pub fn previous_contacts(ctx: &Context, env_id: &str) -> HashMap<String, f64> {
    let Ok(value) = ctx.state.read_json(&path(env_id), Value::Null) else {
        return HashMap::new();
    };
    value["peers"]
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(fp, _)| super::pairing::valid_fingerprint(fp))
        .filter_map(|(fp, peer)| {
            super::membership::parse_stored_time(&peer["last_contact_at"])
                .map(|ts| (fp.clone(), ts))
        })
        .collect()
}

/// `state_corrupt` naming the file (`team/ENV_ID/sync_state.json`), as a
/// state read that fails names it.
fn corrupt(env_id: &str) -> Error {
    Error::state("state_corrupt").with_detail(path(env_id))
}

/// An ISO time as this module writes it, or null.
fn checked_time(value: Option<&Value>, env_id: &str) -> Result<Value> {
    match value {
        None | Some(Value::Null) => Ok(Value::Null),
        Some(value @ Value::String(_)) => super::membership::parse_stored_time(value)
            .map(|_| value.clone())
            .ok_or_else(|| corrupt(env_id)),
        Some(_) => Err(corrupt(env_id)),
    }
}

fn valid_code(text: &str) -> bool {
    (1..=64).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// One peer of `sync_state.json`, checked field by field: the output repeats
/// only values of the shapes this module writes.
struct FilePeer {
    session: bool,
    transport: Value,
    last_contact_at: Value,
    next_attempt_at: Value,
    last_error: Value,
    dial_failures: u64,
    peer_vector: Option<BTreeMap<String, PyInt>>,
    /// The vector arrived while this serve ran (a vector reloaded from
    /// `peer_vectors.json` after a restart has no receive time).
    vector_received: bool,
    tombstone_agreement: Option<Value>,
}

fn file_peer(value: &Value, env_id: &str) -> Result<FilePeer> {
    let corrupt = || corrupt(env_id);
    let peer = value.as_object().ok_or_else(corrupt)?;
    let session = peer
        .get("session")
        .and_then(Value::as_bool)
        .ok_or_else(corrupt)?;
    let transport = match peer.get("transport") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(t)) if t == "tcp" || t == "link" => json!(t),
        Some(_) => return Err(corrupt()),
    };
    let last_error = match peer.get("last_error") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(code)) if valid_code(code) => json!(code),
        Some(_) => return Err(corrupt()),
    };
    let dial_failures = match peer.get("dial_failures") {
        None => 0,
        Some(n) => n.as_u64().ok_or_else(corrupt)?,
    };
    let peer_vector = match peer.get("peer_vector") {
        None | Some(Value::Null) => None,
        Some(Value::Object(vector)) => {
            let mut out = BTreeMap::new();
            for (author, seq) in vector {
                let seq = PyInt::from_json_integer(seq)
                    .filter(|n| n.0.sign() != num_bigint::Sign::Minus)
                    .ok_or_else(corrupt)?;
                out.insert(author.clone(), seq);
            }
            Some(out)
        }
        Some(_) => return Err(corrupt()),
    };
    checked_time(peer.get("since"), env_id)?;
    let vector_received = !checked_time(peer.get("vector_received_at"), env_id)?.is_null();
    Ok(FilePeer {
        session,
        transport,
        last_contact_at: checked_time(peer.get("last_contact_at"), env_id)?,
        next_attempt_at: checked_time(peer.get("next_attempt_at"), env_id)?,
        last_error,
        dial_failures,
        peer_vector,
        vector_received,
        tombstone_agreement: peer.get("tombstone_agreement").cloned(),
    })
}

/// A vector without zero entries, so `{}` and `{"A": 0}` compare equal.
fn nonzero(vector: &BTreeMap<String, PyInt>) -> BTreeMap<&str, &PyInt> {
    vector
        .iter()
        .filter(|(_, seq)| seq.0.sign() != num_bigint::Sign::NoSign)
        .map(|(author, seq)| (author.as_str(), seq))
        .collect()
}

pub(crate) fn vectors_equal(a: &BTreeMap<String, PyInt>, b: &BTreeMap<String, PyInt>) -> bool {
    nonzero(a) == nonzero(b)
}

/// The state of one peer (docs/remote-sync.md §3.3): with a session,
/// `up_to_date` when the peer's last reported vector, received while this
/// serve ran, equals the local store vector now (built from durably stored
/// commits; ours only grows, so an equal report covers our latest change),
/// else `syncing`; without one,
/// `retrying` while a failed dial has another scheduled, `offline` after any
/// contact, `never_connected` before.
fn derive_state(peer: Option<&FilePeer>, local: &BTreeMap<String, PyInt>) -> &'static str {
    let Some(peer) = peer else {
        return "never_connected";
    };
    if peer.session {
        return match &peer.peer_vector {
            Some(vector) if peer.vector_received && vectors_equal(vector, local) => "up_to_date",
            _ => "syncing",
        };
    }
    if peer.dial_failures > 0 && !peer.next_attempt_at.is_null() {
        return "retrying";
    }
    if !peer.last_contact_at.is_null() {
        return "offline";
    }
    "never_connected"
}

/// Unacknowledged `team_op_overridden` alerts of `env_id`: the override
/// signatures this node alerted on (`overridden_alerted.json`, one per
/// alert), read as `serve` reads them (the set of its strings). No command
/// acknowledges them yet, so every one counts.
fn conflicts(ctx: &Context, env_id: &str) -> Result<usize> {
    let alerted_path = format!("team/{env_id}/overridden_alerted.json");
    let alerted = ctx.state.read_json(&alerted_path, json!([]))?;
    if super::json_falsy(&alerted) {
        return Ok(0);
    }
    let list = super::sync::python_list(&alerted)
        .ok_or_else(|| Error::state("state_corrupt").with_detail(alerted_path))?;
    let signatures: std::collections::HashSet<&str> =
        list.iter().filter_map(Value::as_str).collect();
    Ok(signatures.len())
}

/// `team sync-status`: `{"env_id", "self", "serve_updated_at", "conflicts",
/// "peers": [{"fingerprint", "name", "state", "session", "transport",
/// "last_contact_at", "next_attempt_at", "last_error"}]}`. The peers are the
/// document's active members other than this device, by fingerprint; without
/// `sync_state.json` every one is `never_connected` and `serve_updated_at`
/// is null.
pub fn status(ctx: &Context, env_id: &str) -> Result<Value> {
    let _lock = ctx.state.lock()?;
    let mine = DeviceKey::load(ctx.state, ctx.kms)?.fingerprint()?;
    let document = super::membership::load_environment(ctx, env_id)?.document;
    let local = CommitStore::new(ctx.state, env_id).vector()?;
    let (facts, _, _) = super::sync::load_facts(ctx, env_id)?;
    let digest = super::tombstone_gate::digest(&facts.tombstone_facts)?;
    let required = crate::tombstone::support_required(ctx.state, env_id)?;
    let file = ctx.state.read_json(&path(env_id), Value::Null)?;
    let corrupt = || corrupt(env_id);
    let (serve_updated_at, file_peers) = if file.is_null() {
        (Value::Null, HashMap::new())
    } else {
        let object = file.as_object().ok_or_else(corrupt)?;
        let updated = checked_time(object.get("updated_at"), env_id)?;
        if updated.is_null() {
            return Err(corrupt());
        }
        let mut peers = HashMap::new();
        for (fp, peer) in object
            .get("peers")
            .and_then(Value::as_object)
            .ok_or_else(corrupt)?
        {
            if !super::pairing::valid_fingerprint(fp) {
                return Err(corrupt());
            }
            peers.insert(fp.clone(), file_peer(peer, env_id)?);
        }
        (updated, peers)
    };
    let mut members: Vec<(&String, &Value)> = document["members"]
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(fp, member)| **fp != mine && member["status"] == "active")
        .collect();
    members.sort_by(|a, b| a.0.cmp(b.0));
    let peers: Vec<Value> = members
        .into_iter()
        .map(|(fp, member)| {
            let peer = file_peers.get(fp);
            let field =
                |pick: fn(&FilePeer) -> &Value| peer.map_or(Value::Null, |p| pick(p).clone());
            let session = peer.is_some_and(|p| p.session);
            let agreement = peer.and_then(|p| p.tombstone_agreement.as_ref());
            let fresh = super::membership::parse_stored_time(&serve_updated_at)
                .is_some_and(|at| (0.0..=6.0).contains(&((ctx.clock)() - at)));
            let gate_ready = if required || agreement.is_some() {
                fresh && agreement.is_some_and(|a| a["ready"] == true && a["digest"] == digest)
            } else {
                true
            };
            let state = derive_state(peer, &local);
            let state = if state == "up_to_date" && !gate_ready {
                "syncing"
            } else {
                state
            };
            json!({
                "fingerprint": fp,
                "name": member["name"].as_str().map_or(Value::Null, |n| json!(n)),
                "state": state,
                "session": session,
                "transport": if session { field(|p| &p.transport) } else { Value::Null },
                "last_contact_at": field(|p| &p.last_contact_at),
                "next_attempt_at": field(|p| &p.next_attempt_at),
                "last_error": field(|p| &p.last_error),
            })
        })
        .collect();
    Ok(json!({
        "env_id": env_id,
        "self": mine,
        "serve_updated_at": serve_updated_at,
        "conflicts": conflicts(ctx, env_id)?,
        "peers": peers,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector(pairs: &[(&str, i64)]) -> BTreeMap<String, PyInt> {
        pairs
            .iter()
            .map(|(author, seq)| ((*author).to_owned(), PyInt::from(*seq)))
            .collect()
    }

    const ENV: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaa-0123456789abcdef0123456789abcdef";

    fn peer(value: Value) -> FilePeer {
        file_peer(&value, ENV).unwrap()
    }

    #[test]
    fn states_follow_the_table() {
        let local = vector(&[("a", 3), ("b", 1)]);
        let base = json!({"session": true, "peer_vector": {"a": 3, "b": 1, "c": 0},
            "vector_received_at": "2026-11-06T00:00:00Z",
            "transport": "tcp", "dial_failures": 0, "last_contact_at": "2026-11-06T00:00:00Z"});
        assert_eq!(
            derive_state(Some(&peer(base.clone())), &local),
            "up_to_date"
        );
        let mut behind = base.clone();
        behind["peer_vector"] = json!({"a": 2, "b": 1});
        assert_eq!(derive_state(Some(&peer(behind)), &local), "syncing");
        let mut ahead = base.clone();
        ahead["peer_vector"] = json!({"a": 3, "b": 1, "c": 1});
        assert_eq!(derive_state(Some(&peer(ahead)), &local), "syncing");
        let mut no_vector = base.clone();
        no_vector["peer_vector"] = Value::Null;
        assert_eq!(derive_state(Some(&peer(no_vector)), &local), "syncing");
        // Equal, but reloaded from before a restart: not yet confirmed.
        let mut reloaded = base.clone();
        reloaded["vector_received_at"] = Value::Null;
        assert_eq!(derive_state(Some(&peer(reloaded)), &local), "syncing");
        let retrying = json!({"session": false, "dial_failures": 2,
            "next_attempt_at": "2026-11-06T00:00:05Z", "last_error": "team_dial_failed"});
        assert_eq!(derive_state(Some(&peer(retrying)), &local), "retrying");
        let offline = json!({"session": false, "dial_failures": 0,
            "last_contact_at": "2026-11-06T00:00:00Z"});
        assert_eq!(derive_state(Some(&peer(offline)), &local), "offline");
        // A failed dial with nothing scheduled is no retry.
        let gave_up = json!({"session": false, "dial_failures": 1, "next_attempt_at": null,
            "last_contact_at": "2026-11-06T00:00:00Z"});
        assert_eq!(derive_state(Some(&peer(gave_up)), &local), "offline");
        let never = json!({"session": false, "dial_failures": 0});
        assert_eq!(derive_state(Some(&peer(never)), &local), "never_connected");
        assert_eq!(derive_state(None, &local), "never_connected");
    }

    #[test]
    fn malformed_peers_fail_closed() {
        for bad in [
            json!([]),
            json!({"session": "yes"}),
            json!({"session": true, "transport": "udp"}),
            json!({"session": false, "last_error": "Bad Code"}),
            json!({"session": false, "last_error": "x".repeat(65)}),
            json!({"session": false, "dial_failures": -1}),
            json!({"session": false, "peer_vector": {"a": -1}}),
            json!({"session": false, "peer_vector": {"a": "1"}}),
            json!({"session": false, "last_contact_at": "yesterday"}),
            json!({"session": false, "next_attempt_at": 5}),
        ] {
            let error = file_peer(&bad, ENV)
                .err()
                .unwrap_or_else(|| panic!("accepted {bad}"));
            assert_eq!(error.reason, "state_corrupt");
            assert_eq!(error.detail, format!("team/{ENV}/sync_state.json"));
        }
    }

    #[test]
    fn written_peers_hide_session_fields_without_a_session() {
        let mut peers = BTreeMap::new();
        peers.insert(
            "f".repeat(26),
            PeerState {
                session: false,
                since: Some(10.0),
                transport: Some("tcp"),
                dial_failures: 0,
                next_attempt_at: Some(20.0),
                ..PeerState::default()
            },
        );
        let value = peers_value(&peers);
        let peer = &value["f".repeat(26)];
        assert!(peer["since"].is_null());
        assert!(peer["transport"].is_null());
        assert!(peer["next_attempt_at"].is_null());
        assert_eq!(peer["dial_failures"], 0);
        // What serve writes, the reader accepts.
        assert!(file_peer(peer, ENV).is_ok());
    }
}
