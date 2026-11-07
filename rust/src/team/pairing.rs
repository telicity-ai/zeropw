//! Explicit pairing approval (docs/remote-sync.md §3.2).
//!
//! An invitation created with `team invite --approval` stores
//! `approval: "required"` in `team/ENV_ID/invites.json`. A device that proves
//! such an invitation in the handshake does not consume it: the inviter
//! records a join request in `team/ENV_ID/join_requests.json` (0600, written
//! under the state lock, at most [`MAX_REQUESTS_PER_INVITE`] per invitation,
//! newest kept), sends one encrypted `JOIN_PENDING` frame and closes. An
//! administrator approves the request for exactly that device fingerprint
//! (`approved_fingerprint` on the invitation); the next proof from that
//! device consumes the invitation as before. A different device still only
//! gets a request. Denying revokes the invitations.
//!
//! A request holds `{invite_id, fingerprint, first_seen_at, last_seen_at,
//! attempts}` keyed by a random `request_id`: identifiers and times only,
//! never the invitation secret or anything derived from the proof.

use serde_json::{Map, Value, json};

use crate::audit::RecordArgs;
use crate::context::Context;
use crate::errors::{Error, Result};
use crate::store::iso;

/// The `approval` value of an invitation that needs explicit approval.
pub const APPROVAL_REQUIRED: &str = "required";
/// Join requests kept per invitation; the least recently seen goes first.
pub const MAX_REQUESTS_PER_INVITE: usize = 8;
/// The latest timestamp a request may hold (9999-12-31T23:59:59Z).
const MAX_TIMESTAMP: f64 = 253_402_300_799.0;

fn requests_path(env_id: &str) -> String {
    format!("team/{env_id}/join_requests.json")
}
fn invites_path(env_id: &str) -> String {
    format!("team/{env_id}/invites.json")
}

/// A stored invitation entry that requires explicit approval.
pub fn is_approval_entry(entry: &Map<String, Value>) -> bool {
    entry.get("approval").and_then(Value::as_str) == Some(APPROVAL_REQUIRED)
}
/// [`is_approval_entry`] for an entry as a JSON value.
pub fn is_approval_entry_value(entry: &Value) -> bool {
    entry.as_object().is_some_and(is_approval_entry)
}

/// A device fingerprint: 26 characters of lowercase RFC 4648 base32.
pub fn valid_fingerprint(text: &str) -> bool {
    text.len() == 26
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}
fn valid_hex_id(text: &str) -> bool {
    text.len() == 32
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Clone, PartialEq)]
struct Request {
    request_id: String,
    invite_id: String,
    fingerprint: String,
    first_seen_at: f64,
    last_seen_at: f64,
    attempts: u64,
}

impl Request {
    fn stored(&self) -> Value {
        json!({
            "invite_id": self.invite_id,
            "fingerprint": self.fingerprint,
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
            "attempts": self.attempts,
        })
    }
    fn view(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "invite_id": self.invite_id,
            "fingerprint": self.fingerprint,
            "first_seen_at": iso(Some(self.first_seen_at)),
            "last_seen_at": iso(Some(self.last_seen_at)),
            "attempts": self.attempts,
        })
    }
}

/// `state_corrupt` naming the file, as a state read that fails names it.
fn corrupt(env_id: &str) -> Error {
    Error::state("state_corrupt").with_detail(requests_path(env_id))
}

fn timestamp(value: Option<&Value>) -> Option<f64> {
    value
        .filter(|v| v.is_number())
        .and_then(Value::as_f64)
        .filter(|ts| ts.is_finite() && (0.0..=MAX_TIMESTAMP).contains(ts))
}

/// Every stored request, oldest first; a file that is not exactly the
/// format this module writes is `state_corrupt` (fail closed).
fn load_requests(ctx: &Context, env_id: &str) -> Result<Vec<Request>> {
    let corrupt = || corrupt(env_id);
    let value = ctx.state.read_json(&requests_path(env_id), json!({}))?;
    let map = value.as_object().ok_or_else(corrupt)?;
    let mut out = Vec::with_capacity(map.len());
    for (request_id, entry) in map {
        let entry = entry.as_object().ok_or_else(corrupt)?;
        let text = |key: &str| entry.get(key).and_then(Value::as_str);
        let invite_id = text("invite_id").filter(|id| valid_hex_id(id));
        let fingerprint = text("fingerprint").filter(|fp| valid_fingerprint(fp));
        let first = timestamp(entry.get("first_seen_at"));
        let last = timestamp(entry.get("last_seen_at"));
        let attempts = entry
            .get("attempts")
            .and_then(Value::as_u64)
            .filter(|n| *n >= 1);
        let (
            true,
            Some(invite_id),
            Some(fingerprint),
            Some(first_seen_at),
            Some(last_seen_at),
            Some(attempts),
        ) = (
            valid_hex_id(request_id),
            invite_id,
            fingerprint,
            first,
            last,
            attempts,
        )
        else {
            return Err(corrupt());
        };
        out.push(Request {
            request_id: request_id.clone(),
            invite_id: invite_id.to_owned(),
            fingerprint: fingerprint.to_owned(),
            first_seen_at,
            last_seen_at,
            attempts,
        });
    }
    out.sort_by(|a, b| {
        a.first_seen_at
            .total_cmp(&b.first_seen_at)
            .then_with(|| a.request_id.cmp(&b.request_id))
    });
    Ok(out)
}

fn store_requests(ctx: &Context, env_id: &str, requests: &[Request]) -> Result<()> {
    let mut map = Map::new();
    for request in requests {
        map.insert(request.request_id.clone(), request.stored());
    }
    ctx.state
        .write_json(&requests_path(env_id), &Value::Object(map))
}

fn random_id() -> String {
    use rand::RngCore;
    let mut raw = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    hex::encode(raw)
}

/// Record or refresh `fingerprint`'s join request for approval invitation
/// `invite_id`. The caller holds the state lock and has verified the proof.
/// Returns whether the request is new and its attempt count.
pub(crate) fn record_request(
    ctx: &Context,
    env_id: &str,
    invite_id: &str,
    fingerprint: &str,
    now: f64,
) -> Result<(bool, u64)> {
    if !valid_hex_id(invite_id) || !valid_fingerprint(fingerprint) {
        return Err(Error::invalid_input("join_request_malformed"));
    }
    let now = if now.is_finite() {
        now.clamp(0.0, MAX_TIMESTAMP)
    } else {
        0.0
    };
    let mut requests = load_requests(ctx, env_id)?;
    if let Some(existing) = requests
        .iter_mut()
        .find(|r| r.invite_id == invite_id && r.fingerprint == fingerprint)
    {
        existing.last_seen_at = existing.last_seen_at.max(now);
        existing.attempts = existing.attempts.saturating_add(1);
        let attempts = existing.attempts;
        store_requests(ctx, env_id, &requests)?;
        return Ok((false, attempts));
    }
    // Newest kept: make room by dropping this invitation's least recently
    // seen requests.
    loop {
        let same: Vec<usize> = requests
            .iter()
            .enumerate()
            .filter(|(_, r)| r.invite_id == invite_id)
            .map(|(i, _)| i)
            .collect();
        if same.len() < MAX_REQUESTS_PER_INVITE {
            break;
        }
        let Some(oldest) = same.into_iter().min_by(|a, b| {
            requests[*a]
                .last_seen_at
                .total_cmp(&requests[*b].last_seen_at)
                .then_with(|| requests[*a].request_id.cmp(&requests[*b].request_id))
        }) else {
            break;
        };
        requests.remove(oldest);
    }
    let mut request_id = random_id();
    while requests.iter().any(|r| r.request_id == request_id) {
        request_id = random_id();
    }
    requests.push(Request {
        request_id,
        invite_id: invite_id.to_owned(),
        fingerprint: fingerprint.to_owned(),
        first_seen_at: now,
        last_seen_at: now,
        attempts: 1,
    });
    store_requests(ctx, env_id, &requests)?;
    Ok((true, 1))
}

/// Where an invitation stands, as `team invites` reports it.
fn invite_status(entry: &Map<String, Value>, now: f64) -> &'static str {
    if entry.get("revoked_at").is_some_and(|v| !v.is_null())
        || (!entry.contains_key("wrapped_secret") && entry.get("used") != Some(&Value::Bool(true)))
    {
        "revoked"
    } else if entry.get("used") == Some(&Value::Bool(true)) {
        "used"
    } else if entry
        .get("expires_at")
        .and_then(super::membership::parse_stored_time)
        .is_none_or(|expires| now > expires)
    {
        "expired"
    } else {
        "pending"
    }
}

fn status_error(status: &str) -> Error {
    match status {
        "used" => Error::invalid_input("invite_already_used"),
        "expired" => Error::invalid_input("invite_expired"),
        _ => Error::invalid_input("invite_revoked"),
    }
}

fn invalid_fingerprint() -> Error {
    Error::invalid_input("invalid_fingerprint")
        .with_detail("a device fingerprint is 26 characters of a-z and 2-7")
}

/// The fields of a `team_join_approved` / `team_join_denied` record:
/// identifiers only.
fn decision_fields(env_id: &str, fingerprint: &str, invite_id: &str) -> Vec<(&'static str, Value)> {
    vec![
        ("env_id", json!(env_id)),
        ("fingerprint", json!(fingerprint)),
        ("detail", json!(invite_id)),
    ]
}

/// `team join-requests`: the join requests still waiting for a decision --
/// on an approval invitation that is pending (not used, revoked or expired)
/// and not already approved for the requesting device -- oldest first.
pub fn list_requests(ctx: &Context, env_id: &str) -> Result<Value> {
    let now = (ctx.clock)();
    let invites = ctx.state.read_json(&invites_path(env_id), json!({}))?;
    let requests = load_requests(ctx, env_id)?;
    let listed: Vec<Value> = requests
        .iter()
        .filter(|request| {
            invites
                .get(&request.invite_id)
                .and_then(Value::as_object)
                .is_some_and(|entry| {
                    is_approval_entry(entry)
                        && invite_status(entry, now) == "pending"
                        && entry.get("approved_fingerprint").and_then(Value::as_str)
                            != Some(request.fingerprint.as_str())
                })
        })
        .map(Request::view)
        .collect();
    Ok(json!({"env_id": env_id, "requests": listed}))
}

/// The approval invitations `fingerprint` has a request on, optionally only
/// `invite_id`; unknown is `join_request_not_found` (`invite_not_found` for
/// an `invite_id` this node never issued).
fn requested_invites(
    requests: &[Request],
    invites: &Value,
    fingerprint: &str,
    invite_id: Option<&str>,
) -> Result<Vec<String>> {
    if let Some(id) = invite_id
        && invites.get(id).and_then(Value::as_object).is_none()
    {
        return Err(Error::not_found("invite_not_found"));
    }
    // Newest request first, so a refusal names the invitation last used.
    let mut ordered: Vec<&Request> = requests
        .iter()
        .filter(|r| r.fingerprint == fingerprint)
        .filter(|r| invite_id.is_none_or(|id| r.invite_id == id))
        .filter(|r| {
            invites
                .get(&r.invite_id)
                .is_some_and(is_approval_entry_value)
        })
        .collect();
    ordered.sort_by(|a, b| b.last_seen_at.total_cmp(&a.last_seen_at));
    let mut ids = Vec::new();
    for request in ordered {
        if !ids.contains(&request.invite_id) {
            ids.push(request.invite_id.clone());
        }
    }
    if ids.is_empty() {
        return Err(Error::not_found("join_request_not_found"));
    }
    Ok(ids)
}

/// `team approve-join`: approve every pending approval invitation of
/// `env_id` that has a request from `fingerprint` (or only `invite_id`) for
/// exactly that device. The next proof from it consumes the invitation.
/// Used, expired and revoked invitations are refused with their reasons when
/// none is left to approve.
pub fn approve_join(
    ctx: &Context,
    env_id: &str,
    fingerprint: &str,
    invite_id: Option<&str>,
) -> Result<Value> {
    if !valid_fingerprint(fingerprint) {
        return Err(invalid_fingerprint());
    }
    if invite_id.is_some_and(|id| !valid_hex_id(id)) {
        return Err(Error::not_found("invite_not_found"));
    }
    let approved = {
        let _lock = ctx.state.lock()?;
        let now = (ctx.clock)();
        let mut invites = ctx.state.read_json(&invites_path(env_id), json!({}))?;
        let requests = load_requests(ctx, env_id)?;
        let candidates = requested_invites(&requests, &invites, fingerprint, invite_id)?;
        let mut approved = Vec::new();
        let mut refusal = None;
        for id in &candidates {
            let Some(entry) = invites.get_mut(id).and_then(Value::as_object_mut) else {
                continue;
            };
            let status = invite_status(entry, now);
            if status != "pending" {
                refusal.get_or_insert(status);
                continue;
            }
            entry.insert("approved_fingerprint".into(), json!(fingerprint));
            entry.insert("approved_at".into(), json!(now));
            approved.push(id.clone());
        }
        if approved.is_empty() {
            return Err(status_error(refusal.unwrap_or("revoked")));
        }
        ctx.state.write_json(&invites_path(env_id), &invites)?;
        approved.sort();
        approved
    };
    for id in &approved {
        let _ = ctx.audit.record(
            "team_join_approved",
            RecordArgs {
                caller: Some("admin"),
                result: Some("ok"),
                extra: decision_fields(env_id, fingerprint, id),
                ..Default::default()
            },
        );
    }
    Ok(json!({"env_id": env_id, "fingerprint": fingerprint, "approved_invites": approved}))
}

/// `team deny-join`: revoke every invitation of `env_id` that has a request
/// from `fingerprint` and is not used yet (dropping its wrapped secret, as
/// `team revoke-invite` does). Denying again succeeds; when every such
/// invitation was used it is `invite_already_used`.
pub fn deny_join(ctx: &Context, env_id: &str, fingerprint: &str) -> Result<Value> {
    if !valid_fingerprint(fingerprint) {
        return Err(invalid_fingerprint());
    }
    let (revoked, newly) = {
        let _lock = ctx.state.lock()?;
        let now = (ctx.clock)();
        let mut invites = ctx.state.read_json(&invites_path(env_id), json!({}))?;
        let requests = load_requests(ctx, env_id)?;
        let candidates = requested_invites(&requests, &invites, fingerprint, None)?;
        let mut revoked = Vec::new();
        let mut newly = Vec::new();
        let mut changed = false;
        for id in &candidates {
            let Some(entry) = invites.get_mut(id).and_then(Value::as_object_mut) else {
                continue;
            };
            if entry.get("used") == Some(&Value::Bool(true)) {
                continue;
            }
            changed |= entry.remove("wrapped_secret").is_some();
            if entry.get("revoked_at").is_none_or(Value::is_null) {
                entry.insert("revoked_at".into(), json!(now));
                let role = entry.get("role").cloned().unwrap_or(Value::Null);
                newly.push((id.clone(), role));
                changed = true;
            }
            revoked.push(id.clone());
        }
        if revoked.is_empty() {
            return Err(Error::invalid_input("invite_already_used"));
        }
        if changed {
            ctx.state.write_json(&invites_path(env_id), &invites)?;
        }
        revoked.sort();
        (revoked, newly)
    };
    for id in &revoked {
        let _ = ctx.audit.record(
            "team_join_denied",
            RecordArgs {
                caller: Some("admin"),
                result: Some("ok"),
                extra: decision_fields(env_id, fingerprint, id),
                ..Default::default()
            },
        );
    }
    // The same record `team revoke-invite` writes for each one it stops.
    for (id, role) in newly {
        let _ = ctx.audit.record(
            "team_invite_revoke",
            RecordArgs {
                caller: Some("admin"),
                result: Some("ok"),
                extra: vec![
                    ("env_id", json!(env_id)),
                    ("role", role),
                    ("detail", json!(id)),
                ],
                ..Default::default()
            },
        );
    }
    Ok(json!({"env_id": env_id, "fingerprint": fingerprint, "revoked_invites": revoked}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_and_id_shapes() {
        assert!(valid_fingerprint("abcdefghijklmnopqrstuvwxyz"));
        assert!(valid_fingerprint("a234567a234567a234567a2345"));
        assert!(!valid_fingerprint("abcdefghijklmnopqrstuvwxy"));
        assert!(!valid_fingerprint("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
        assert!(!valid_fingerprint("abcdefghijklmnopqrstuvwxy1"));
        assert!(!valid_fingerprint("abcdefghijklmnopqrstuvwxy/"));
        assert!(valid_hex_id(&"ab".repeat(16)));
        assert!(!valid_hex_id(&"AB".repeat(16)));
        assert!(!valid_hex_id("../../etc/passwd"));
    }

    #[test]
    fn invite_status_follows_the_listing_rules() {
        let now = 1_000.0;
        let entry = |v: Value| v.as_object().unwrap().clone();
        let pending = entry(json!({"wrapped_secret": {}, "used": false, "expires_at": 2000.0}));
        assert_eq!(invite_status(&pending, now), "pending");
        let expired = entry(json!({"wrapped_secret": {}, "used": false, "expires_at": 999.0}));
        assert_eq!(invite_status(&expired, now), "expired");
        let used = entry(json!({"used": true, "expires_at": 2000.0}));
        assert_eq!(invite_status(&used, now), "used");
        let revoked = entry(json!({"used": false, "revoked_at": 5.0, "expires_at": 2000.0}));
        assert_eq!(invite_status(&revoked, now), "revoked");
        // A secret dropped without a revocation time cannot be consumed.
        let dropped = entry(json!({"used": false, "expires_at": 2000.0}));
        assert_eq!(invite_status(&dropped, now), "revoked");
    }
}
