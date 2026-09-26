//! Team replication and monotone facts, port of `zeropw/team/sync.py`.
#![allow(clippy::collapsible_if)]
#![allow(clippy::type_complexity)]

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::commit::{self, Commit, CommitStore, Hlc};
use super::fold::{self, Facts, FoldResult};
use super::identity::{DeviceKey, DeviceRecord};
use super::transport::{InviteCheck, MembershipCheck, OnSession, Session, Transport};
use crate::audit::RecordArgs;
use crate::context::Context;
use crate::crypto::ed25519;
use crate::errors::{Error, Result};
use crate::pybase64;
use crate::pyjson::{self, DumpOptions};
use crate::store::{StateDir, iso};

pub const FACT_FORMAT: &str = "zeropw-team-fact-v1";
pub const FACT_KINDS: [&str; 4] = [
    "connection_disabled",
    "secret_version_revoked",
    "member_removed",
    "incident",
];
// Replay advances over at most this many persisted lines per VECTOR, including
// malformed lines. A full pass restarts so a rejected/out-of-order frame is
// retried after later commit catch-up, while receiver hashes deduplicate it.
const FACT_REPLAY_LINES_PER_VECTOR: usize = 64;
/// `sync._SEEN_CAPACITY`: bound of the rebroadcast-dedup set.
const SEEN_CAPACITY: usize = 4096;
/// `thread.join(timeout=5)` in `TeamSync.stop`.
const THREAD_JOIN_TIMEOUT: Duration = Duration::from_secs(5);
pub const ENVS_MAP_PATH: &str = "team/envs.json";
pub const SNAPSHOT_INTERVAL_COMMITS: i128 = 1000;
pub const COMPACT_MIN_AGE_MS: i64 = 30 * 24 * 3600 * 1000;
pub const MAX_INCIDENT_STR_LENGTH: usize = 200;
pub const MAX_INCIDENT_LIST_ITEMS: usize = 100;
pub const MAX_INCIDENT_UNIT: i64 = 2_147_483_647;

fn canon(value: &Value) -> Result<Vec<u8>> {
    Ok(pyjson::dumps(value, DumpOptions::compact_sorted())?.into_bytes())
}

#[cfg(test)]
mod retry_tests {
    use super::*;
    use crate::context::Config;
    use crate::team::transport::{
        HandshakeFailedHook, InviteCheck, InviteProof, MembershipCheck, OnSession, SessionClosed,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use tempfile::TempDir;

    struct StubSession {
        peer: DeviceRecord,
        closed: AtomicBool,
        created: Instant,
    }
    impl Session for StubSession {
        fn peer(&self) -> DeviceRecord {
            self.peer.clone()
        }
        fn env_id(&self) -> &str {
            "retry-env"
        }
        fn send(&self, _: &Value) -> Result<()> {
            Ok(())
        }
        fn recv(&self, _: Duration) -> std::result::Result<Option<Value>, SessionClosed> {
            Err(SessionClosed("peer_closed"))
        }
        fn close(&self) {
            self.closed.store(true, Ordering::SeqCst);
        }
        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }
        fn created_at(&self) -> Instant {
            self.created
        }
    }
    struct StubTransport {
        session: Arc<dyn Session>,
    }
    impl Transport for StubTransport {
        fn set_membership(&self, _: MembershipCheck) {}
        fn set_invite_check(&self, _: Option<InviteCheck>) {}
        fn set_handshake_failed(&self, _: Option<HandshakeFailedHook>) {}
        fn listen(&self, _: &str, _: OnSession) -> Result<()> {
            Ok(())
        }
        fn dial(
            &self,
            _: &str,
            _: &str,
            _: Option<InviteProof>,
        ) -> std::result::Result<Arc<dyn Session>, SessionClosed> {
            Ok(self.session.clone())
        }
        fn close(&self) {}
    }

    struct RecordingSession {
        peer: DeviceRecord,
        env_id: String,
        sent: Mutex<Vec<Value>>,
        on_first_send: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
        closed: AtomicBool,
        created: Instant,
    }
    impl Session for RecordingSession {
        fn peer(&self) -> DeviceRecord {
            self.peer.clone()
        }
        fn env_id(&self) -> &str {
            &self.env_id
        }
        fn send(&self, message: &Value) -> Result<()> {
            let first = {
                let mut sent = self.sent.lock().unwrap();
                sent.push(message.clone());
                sent.len() == 1
            };
            if first && let Some(callback) = self.on_first_send.lock().unwrap().take() {
                callback();
            }
            Ok(())
        }
        fn recv(&self, _: Duration) -> std::result::Result<Option<Value>, SessionClosed> {
            Err(SessionClosed("peer_closed"))
        }
        fn close(&self) {
            self.closed.store(true, Ordering::SeqCst);
        }
        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }
        fn created_at(&self) -> Instant {
            self.created
        }
    }

    #[test]
    fn fact_replay_stops_on_session_replacement_and_receive_only_drain() {
        let root = TempDir::new().unwrap();
        let ctx = Arc::new(
            Context::initialize(
                root.path().join("state"),
                "synthetic-admin",
                "synthetic-recovery",
                Config::default(),
                crate::clock::system(),
            )
            .unwrap(),
        );
        let mine = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        let peer_key = DeviceKey::generate();
        let peer = peer_key.record().unwrap();
        let mine_fp = mine.fingerprint().unwrap();
        let fp = peer.fingerprint();
        let env_id = commit::new_env_id(&mine_fp).unwrap();
        let generation = "0000000000000000";
        let wrap = crate::team::envelope::wrap_dek(
            &[7u8; 32],
            &env_id,
            generation,
            &mine.record().unwrap(),
        )
        .unwrap();
        let init = commit::sign_commit(
            &mine,
            &env_id,
            1,
            "1000-0000",
            &BTreeMap::new(),
            vec![json!({"op":"env.init","owner_device":mine.record().unwrap().to_dict(),"owner_name":"alice","generation_id":generation,"wraps":{mine_fp:wrap}})],
        )
        .unwrap();
        let add = commit::sign_commit(
            &mine,
            &env_id,
            2,
            "2000-0000",
            &BTreeMap::new(),
            vec![json!({"op":"member.add","device":peer.to_dict(),"name":"bob","role":"admin"})],
        )
        .unwrap();
        let store = CommitStore::new(ctx.state, &env_id);
        store.append(&init).unwrap();
        store.append(&add).unwrap();
        let make_recorder = || {
            Arc::new(RecordingSession {
                peer: peer.clone(),
                env_id: env_id.clone(),
                sent: Mutex::new(Vec::new()),
                on_first_send: Mutex::new(None),
                closed: AtomicBool::new(false),
                created: Instant::now(),
            })
        };
        let recorder = make_recorder();
        let session: Arc<dyn Session> = recorder.clone();
        let team = TeamSync::new(
            ctx.clone(),
            Arc::new(StubTransport {
                session: session.clone(),
            }),
            mine.clone(),
        );
        team.register_env(&env_id).unwrap();
        assert!(team.accept_session(&env_id, session.clone(), true));
        let foreign_env = commit::new_env_id(&mine.fingerprint().unwrap()).unwrap();
        // First and 65th lines are valid. Invalid, signed INCIDENT,
        // cross-environment, malformed-target and bad-signature rows between
        // them must never be sent.
        // Replacement during the first send reaches the old batch's cursor
        // update at line 64, which must not overwrite the new session's zero.
        for i in 0..=64 {
            let line = if i == 0 || i == 64 {
                sign_fact(
                    &mine,
                    &env_id,
                    "connection_disabled",
                    json!({"connection_id":"gh"}),
                    &format!("{}-0000", 3000 + i),
                )
                .unwrap()
                .to_dict()
                .to_string()
            } else {
                match i % 5 {
                    0 => "not-json".to_owned(),
                    1 => sign_fact(
                        &mine,
                        &env_id,
                        "incident",
                        json!({"incident_id":"0123456789abcdef"}),
                        &format!("{}-0000", 3000 + i),
                    )
                    .unwrap()
                    .to_dict()
                    .to_string(),
                    2 => sign_fact(
                        &mine,
                        &foreign_env,
                        "connection_disabled",
                        json!({"connection_id":"gh"}),
                        &format!("{}-0000", 3000 + i),
                    )
                    .unwrap()
                    .to_dict()
                    .to_string(),
                    3 => {
                        let mut tampered = sign_fact(
                            &mine,
                            &env_id,
                            "connection_disabled",
                            json!({"connection_id":"gh"}),
                            &format!("{}-0000", 3000 + i),
                        )
                        .unwrap()
                        .to_dict();
                        tampered["target"]["credential"] = json!("synthetic-do-not-send");
                        tampered.to_string()
                    }
                    _ => {
                        let mut tampered = sign_fact(
                            &mine,
                            &env_id,
                            "connection_disabled",
                            json!({"connection_id":"gh"}),
                            &format!("{}-0000", 3000 + i),
                        )
                        .unwrap()
                        .to_dict();
                        tampered["target"]["connection_id"] = json!("bad-signature");
                        tampered.to_string()
                    }
                }
            };
            ctx.state
                .append_line(&format!("team/{env_id}/facts.jsonl"), &line)
                .unwrap();
        }
        let replacement = make_recorder();
        let replacement_session: Arc<dyn Session> = replacement.clone();
        let keep_new_inbound = mine.fingerprint().unwrap() > fp;
        let weak = Arc::downgrade(&team);
        let callback_env = env_id.clone();
        *recorder.on_first_send.lock().unwrap() = Some(Box::new(move || {
            assert!(weak.upgrade().unwrap().accept_session(
                &callback_env,
                replacement_session.clone(),
                keep_new_inbound
            ));
        }));
        team.send_fact_catchup(&env_id, &session).unwrap();
        assert_eq!(recorder.sent.lock().unwrap().len(), 1);
        assert_eq!(
            team.envs.lock().unwrap()[&env_id].fact_replay_cursor[&fp],
            0
        );
        let replacement_session: Arc<dyn Session> = replacement.clone();
        team.send_fact_catchup(&env_id, &replacement_session)
            .unwrap();
        assert_eq!(replacement.sent.lock().unwrap().len(), 1);
        team.send_fact_catchup(&env_id, &replacement_session)
            .unwrap();
        assert_eq!(replacement.sent.lock().unwrap().len(), 2);
        let frames = replacement.sent.lock().unwrap().clone();
        assert!(frames.iter().all(|v| v["type"] == "FACT"));
        assert!(
            frames
                .iter()
                .all(|v| v["fact"]["kind"] == "connection_disabled")
        );
        assert!(
            frames
                .iter()
                .all(|v| v["fact"]["target"] == json!({"connection_id":"gh"}))
        );
        assert!(!json!(frames).to_string().contains("synthetic-do-not-send"));
        let appended = sign_fact(
            &mine,
            &env_id,
            "secret_version_revoked",
            json!({"secret_id":"key","version_id":"0011223344556677"}),
            "4000-0000",
        )
        .unwrap();
        ctx.state
            .append_line(
                &format!("team/{env_id}/facts.jsonl"),
                &appended.to_dict().to_string(),
            )
            .unwrap();
        // Same live session, after EOF had reset to zero: a later line still
        // arrives on the next bounded cycle. Earlier frames may repeat and
        // are deduplicated by the real receiving path.
        team.send_fact_catchup(&env_id, &replacement_session)
            .unwrap();
        team.send_fact_catchup(&env_id, &replacement_session)
            .unwrap();
        let frames = replacement.sent.lock().unwrap();
        assert_eq!(frames.len(), 5);
        assert_eq!(frames.last().unwrap()["fact"], appended.to_dict());
        drop(frames);

        let draining = make_recorder();
        let draining_session: Arc<dyn Session> = draining.clone();
        assert!(team.accept_session(&env_id, draining_session.clone(), keep_new_inbound));
        let weak = Arc::downgrade(&team);
        let callback_env = env_id.clone();
        let callback_fp = fp.clone();
        *draining.on_first_send.lock().unwrap() = Some(Box::new(move || {
            weak.upgrade()
                .unwrap()
                .drain_removed(&callback_env, &callback_fp);
        }));
        team.send_fact_catchup(&env_id, &draining_session).unwrap();
        // The next batch would reach valid line 64 if a drained session were
        // still eligible for outbound replay.
        team.send_fact_catchup(&env_id, &draining_session).unwrap();
        assert_eq!(draining.sent.lock().unwrap().len(), 1);
        assert!(
            team.envs.lock().unwrap()[&env_id]
                .draining
                .contains_key(&fp)
        );
    }

    #[test]
    fn concurrent_store_fact_has_exactly_one_insert_winner() {
        use std::sync::Barrier;

        let root = TempDir::new().unwrap();
        let ctx = Arc::new(
            Context::initialize(
                root.path().join("state"),
                "synthetic-admin",
                "synthetic-recovery",
                Config::default(),
                crate::clock::system(),
            )
            .unwrap(),
        );
        let mine = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        let peer = DeviceKey::generate().record().unwrap();
        let session: Arc<dyn Session> = Arc::new(StubSession {
            peer,
            closed: AtomicBool::new(false),
            created: Instant::now(),
        });
        let team = TeamSync::new(
            ctx.clone(),
            Arc::new(StubTransport { session }),
            mine.clone(),
        );
        let env_id = commit::new_env_id(&mine.fingerprint().unwrap()).unwrap();
        team.envs.lock().unwrap().insert(
            env_id.clone(),
            EnvState::new(Facts::default(), HashSet::new(), HashMap::new()),
        );
        let fact = sign_fact(
            &mine,
            &env_id,
            "connection_disabled",
            json!({"connection_id":"synthetic-connection"}),
            "3000-0000",
        )
        .unwrap();
        let barrier = Barrier::new(2);
        let inserted = thread::scope(|scope| {
            let first = scope.spawn(|| {
                barrier.wait();
                team.store_fact(&env_id, &fact).unwrap()
            });
            let second = scope.spawn(|| {
                barrier.wait();
                team.store_fact(&env_id, &fact).unwrap()
            });
            usize::from(first.join().unwrap()) + usize::from(second.join().unwrap())
        });
        assert_eq!(inserted, 1);
        assert_eq!(team.envs.lock().unwrap()[&env_id].fact_hashes.len(), 1);
        assert_eq!(
            ctx.state
                .read_lines(&format!("team/{env_id}/facts.jsonl"), None)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn successful_retry_resets_backoff_before_next_disconnect() {
        let root = TempDir::new().unwrap();
        let ctx = Arc::new(
            Context::initialize(
                root.path().join("state"),
                "admin-passphrase",
                "recovery-passphrase",
                Config::default(),
                crate::clock::system(),
            )
            .unwrap(),
        );
        let mine = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        let peer = DeviceKey::generate().record().unwrap();
        let fp = peer.fingerprint();
        let session: Arc<dyn Session> = Arc::new(StubSession {
            peer,
            closed: AtomicBool::new(false),
            created: Instant::now(),
        });
        let team = TeamSync::new(ctx, Arc::new(StubTransport { session }), mine);
        let mut state = EnvState::new(Facts::default(), HashSet::new(), HashMap::new());
        state
            .candidate_addresses
            .insert(fp.clone(), BTreeSet::from(["retry-address".to_owned()]));
        state.backoff.insert(fp.clone(), Duration::from_secs(8));
        state
            .next_attempt
            .insert(fp.clone(), Instant::now() + Duration::from_secs(8));
        team.envs.lock().unwrap().insert("retry-env".into(), state);
        team.dial_attempt("retry-env", &fp);
        let guard = team.envs.lock().unwrap();
        let state = guard.get("retry-env").unwrap();
        assert!(!state.backoff.contains_key(&fp));
        assert!(!state.next_attempt.contains_key(&fp));
    }
}
fn valid_id(s: &str, limit: usize) -> bool {
    !s.is_empty()
        && s.chars().count() <= limit
        && !s.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}')
}
fn valid_token(s: &str) -> bool {
    (16..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_fp(s: &str) -> bool {
    s.len() == 26
        && s.bytes()
            .all(|b: u8| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}
fn valid_incident_str(v: &Value) -> bool {
    v.as_str()
        .is_some_and(|s| valid_id(s, MAX_INCIDENT_STR_LENGTH))
}
fn valid_incident_int(v: &Value) -> bool {
    !v.is_boolean()
        && v.as_i64()
            .is_some_and(|n| (0..=MAX_INCIDENT_UNIT).contains(&n))
}
fn valid_incident_list(v: &Value) -> bool {
    v.as_array().is_some_and(|a| {
        a.len() <= MAX_INCIDENT_LIST_ITEMS
            && a.iter()
                .all(|v| v.as_str().is_some_and(|s| valid_id(s, 64)))
    })
}

pub fn sanitize_incident_summary(summary: &Value) -> Result<Value> {
    let source = summary
        .as_object()
        .ok_or_else(|| Error::invalid_input("team_incident_summary_invalid"))?;
    let id = source
        .get("incident_id")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::invalid_input("team_incident_summary_invalid"))?;
    if !valid_token(id) {
        return Err(Error::invalid_input("team_incident_summary_invalid"));
    }
    let mut clean = Map::new();
    clean.insert("incident_id".into(), json!(id));
    for (key, value) in source {
        if key == "incident_id" {
            continue;
        }
        if (["ts", "scope", "rule", "first_used_at", "last_used_at"].contains(&key.as_str())
            && valid_incident_str(value))
            || (key == "uses" && valid_incident_int(value))
        {
            clean.insert(key.clone(), value.clone());
        } else if [
            "secret_ids_mandatory",
            "secret_ids_recommended",
            "connection_ids",
        ]
        .contains(&key.as_str())
            && valid_incident_list(value)
        {
            let values: BTreeSet<&str> = value
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            if !values.is_empty() {
                clean.insert(key.clone(), json!(values));
            }
        }
    }
    Ok(Value::Object(clean))
}

fn validate_fact_target(kind: &str, target: &Value) -> Result<()> {
    let bad = || Error::invalid_input("team_fact_target_invalid");
    let obj = target.as_object().ok_or_else(bad)?;
    match kind {
        "connection_disabled"
            if obj.len() == 1
                && obj
                    .get("connection_id")
                    .and_then(Value::as_str)
                    .is_some_and(|s| valid_id(s, 64)) =>
        {
            Ok(())
        }
        "secret_version_revoked"
            if obj.len() == 2
                && obj
                    .get("secret_id")
                    .and_then(Value::as_str)
                    .is_some_and(|s| valid_id(s, 64))
                && obj
                    .get("version_id")
                    .and_then(Value::as_str)
                    .is_some_and(valid_token) =>
        {
            Ok(())
        }
        "member_removed"
            if obj.len() == 1
                && obj
                    .get("fingerprint")
                    .and_then(Value::as_str)
                    .is_some_and(valid_fp) =>
        {
            Ok(())
        }
        "incident" => {
            if !obj
                .get("incident_id")
                .and_then(Value::as_str)
                .is_some_and(valid_token)
            {
                return Err(bad());
            }
            for (key, value) in obj {
                let valid = match key.as_str() {
                    "incident_id" | "ts" | "scope" | "rule" | "first_used_at" | "last_used_at" => {
                        valid_incident_str(value)
                    }
                    "uses" => valid_incident_int(value),
                    "secret_ids_mandatory" | "secret_ids_recommended" | "connection_ids" => {
                        valid_incident_list(value)
                    }
                    _ => false,
                };
                if !valid {
                    return Err(bad());
                }
            }
            Ok(())
        }
        "connection_disabled" | "secret_version_revoked" | "member_removed" => Err(bad()),
        _ => Err(Error::invalid_input("team_fact_kind_unknown")),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fact {
    pub format: String,
    pub env_id: String,
    pub kind: String,
    pub target: Value,
    pub author: String,
    pub hlc: String,
    pub sig: String,
}
impl Fact {
    pub fn canonical_json(&self, include_sig: bool) -> Result<Vec<u8>> {
        canon(&self.canonical(include_sig))
    }
    fn canonical(&self, include_sig: bool) -> Value {
        let mut value = json!({"format":self.format,"env_id":self.env_id,"kind":self.kind,"target":self.target,"author":self.author,"hlc":self.hlc});
        if include_sig {
            value["sig"] = json!(self.sig);
        }
        value
    }
    pub fn hash(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(self.canonical_json(true)?)))
    }
    pub fn to_dict(&self) -> Value {
        self.canonical(true)
    }
    pub fn from_dict(data: &Value) -> Result<Self> {
        let bad = || Error::invalid_input("team_fact_malformed");
        let obj = data.as_object().ok_or_else(bad)?;
        let field = |key| obj.get(key).map(commit::python_str_coerce).ok_or_else(bad);
        // Python applies dict(target) before stringifying its keys. Reuse the
        // commit parser's sequence-of-pairs conversion and key equivalence.
        let pairs =
            commit::python_dict_pairs(obj.get("target").ok_or_else(bad)?).ok_or_else(bad)?;
        let mut merged: Vec<(Value, Value)> = Vec::new();
        for (key, value) in pairs {
            if !commit::dict_key_is_hashable(&key) {
                return Err(bad());
            }
            if let Some((_, prior_value)) = merged
                .iter_mut()
                .find(|(prior, _)| commit::dict_keys_equal(prior, &key))
            {
                *prior_value = value;
            } else {
                merged.push((key, value));
            }
        }
        let mut target = Map::new();
        for (key, value) in merged {
            target.insert(commit::python_str_coerce(&key), value);
        }
        Ok(Self {
            format: field("format")?,
            env_id: field("env_id")?,
            kind: field("kind")?,
            target: Value::Object(target),
            author: field("author")?,
            hlc: field("hlc")?,
            sig: field("sig")?,
        })
    }
}
pub fn sign_fact(
    device: &DeviceKey,
    env_id: &str,
    kind: &str,
    target: Value,
    hlc: &str,
) -> Result<Fact> {
    validate_fact_target(kind, &target)?;
    let mut fact = Fact {
        format: FACT_FORMAT.into(),
        env_id: env_id.into(),
        kind: kind.into(),
        target,
        author: device.fingerprint()?,
        hlc: hlc.into(),
        sig: String::new(),
    };
    fact.sig = pybase64::b64encode(&device.sign(&fact.canonical_json(false)?)?);
    Ok(fact)
}
pub fn verify_fact(fact: &Fact, author: &DeviceRecord) -> bool {
    if fact.format != FACT_FORMAT
        || fact.author != author.fingerprint()
        || !FACT_KINDS.contains(&fact.kind.as_str())
        || validate_fact_target(&fact.kind, &fact.target).is_err()
        || Hlc::parse(&fact.hlc).is_err()
    {
        return false;
    }
    let Ok(sig) = pybase64::b64decode_strict(&fact.sig) else {
        return false;
    };
    fact.canonical_json(false)
        .is_ok_and(|bytes| ed25519::verify(&author.sign_pub, &bytes, &sig))
}
fn apply_fact(facts: &mut Facts, fact: &Fact) {
    match fact.kind.as_str() {
        "connection_disabled" => {
            if let Some(id) = fact.target["connection_id"].as_str() {
                facts.disabled_connections.insert(id.into());
            }
        }
        "secret_version_revoked" => {
            if let (Some(sid), Some(vid)) = (
                fact.target["secret_id"].as_str(),
                fact.target["version_id"].as_str(),
            ) {
                facts.revoked_versions.insert((sid.into(), vid.into()));
            }
        }
        "member_removed" => {
            if let Some(fp) = fact.target["fingerprint"].as_str() {
                facts.removed_members.insert(fp.into());
            }
        }
        "incident" => facts.incidents.push(fact.target.clone()),
        _ => {}
    }
}
pub fn is_admin(doc: &Value, fp: &str) -> bool {
    let member = &doc["members"][fp];
    member["status"] == "active" && (doc["owner"] == fp || member["role"] == "admin")
}
pub fn fact_role_ok(doc: &Value, kind: &str, author: &str, target: &Value) -> bool {
    if kind == "member_removed" {
        let target_fp = target["fingerprint"].as_str().unwrap_or("");
        if doc["owner"] == target_fp {
            return false;
        }
        return doc["owner"] == author
            || doc["members"][author]["role"] == "admin"
            || author == target_fp;
    }
    if kind == "incident" {
        return doc["members"][author]["status"] == "active";
    }
    is_admin(doc, author)
}
pub fn load_facts(
    state: &StateDir,
    env_id: &str,
) -> Result<(Facts, HashSet<String>, HashMap<String, HashSet<String>>)> {
    let mut facts = Facts::default();
    let mut hashes = HashSet::new();
    let mut authors: HashMap<String, HashSet<String>> = HashMap::new();
    for line in state.read_lines(&format!("team/{env_id}/facts.jsonl"), None)? {
        if line.is_empty() {
            continue;
        }
        let Ok(value) = pyjson::loads(&line) else {
            continue;
        };
        let Ok(fact) = Fact::from_dict(&value) else {
            continue;
        };
        let Ok(hash) = fact.hash() else {
            continue;
        };
        if !hashes.insert(hash) {
            continue;
        }
        apply_fact(&mut facts, &fact);
        if fact.kind == "member_removed" {
            if let Some(fp) = fact.target["fingerprint"].as_str() {
                authors.entry(fp.into()).or_default().insert(fact.author);
            }
        }
    }
    Ok((facts, hashes, authors))
}
pub fn read_env_mapping(state: &StateDir) -> Result<Value> {
    let doc = state.read_json(ENVS_MAP_PATH, json!({}))?;
    Ok(if doc.is_object() { doc } else { json!({}) })
}
pub fn write_env_mapping(
    state: &StateDir,
    env_id: &str,
    project: &str,
    environment: &str,
) -> Result<()> {
    let _lock = state.lock()?;
    let mut doc = read_env_mapping(state)?;
    doc[env_id] = json!({"project":project,"environment":environment});
    state.write_json(ENVS_MAP_PATH, &doc)
}
pub fn env_project_environment(
    state: &StateDir,
    env_id: &str,
) -> Result<(Option<String>, Option<String>)> {
    let doc = read_env_mapping(state)?;
    let entry = &doc[env_id];
    Ok((
        entry["project"].as_str().map(str::to_owned),
        entry["environment"].as_str().map(str::to_owned),
    ))
}
pub fn resolve_env_id(
    state: &StateDir,
    project: &str,
    environment: &str,
) -> Result<Option<String>> {
    let doc = read_env_mapping(state)?;
    Ok(doc.as_object().and_then(|m| {
        m.iter()
            .find(|(_, entry)| entry["project"] == project && entry["environment"] == environment)
            .map(|(id, _)| id.clone())
    }))
}
pub fn discover_envs(state: &StateDir) -> Result<Vec<String>> {
    let root = state.path.join("team");
    if !root.is_dir() {
        return Ok(vec![]);
    }
    let mut found = Vec::new();
    for entry in std::fs::read_dir(root).map_err(|_| Error::state("state_corrupt"))? {
        let entry = entry.map_err(|_| Error::state("state_corrupt"))?;
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        if path.is_dir()
            && commit::valid_env_id(&name)
            && (path.join("commits").is_dir()
                || path.join("snapshots").is_dir()
                || path.join("facts.jsonl").exists())
        {
            found.push(name);
        }
    }
    found.sort();
    Ok(found)
}

/// Python `list(x)` / `for a in x` over a `json.load`ed value: a list yields
/// its elements, a str its characters, a dict its keys. `None`/`bool`/numbers
/// are not iterable (`TypeError` in Python), returned as `None` here.
pub(crate) fn python_list(value: &Value) -> Option<Vec<Value>> {
    match value {
        Value::Array(items) => Some(items.clone()),
        Value::String(s) => Some(s.chars().map(|c| Value::String(c.to_string())).collect()),
        Value::Object(map) => Some(map.keys().map(|k| Value::String(k.clone())).collect()),
        Value::Null | Value::Bool(_) | Value::Number(_) => None,
    }
}

/// `StateDir.read_json(path, {}) or {}` for a document Python then uses as a
/// `dict`: a falsy document becomes `{}`, and a truthy non-dict (on which
/// Python's `.get`/`.items`/item assignment raises an uncaught
/// `AttributeError`/`TypeError`) is `state_corrupt` (PORTING.md §3.5).
fn read_dict_or_empty(state: &StateDir, path: &str) -> Result<Map<String, Value>> {
    match state.read_json(path, json!({}))? {
        Value::Object(map) => Ok(map),
        other if super::json_falsy(&other) => Ok(Map::new()),
        _ => Err(Error::state("state_corrupt").with_detail(path)),
    }
}

/// Port of `sync._LruSet`: a bounded set deduplicating rebroadcast of
/// already-seen commit hashes. A hit refreshes the key's recency
/// (`move_to_end`); an insert past capacity evicts the least recent key.
struct LruSet {
    capacity: usize,
    tick: u64,
    by_key: HashMap<String, u64>,
    by_tick: BTreeMap<u64, String>,
}
impl LruSet {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            tick: 0,
            by_key: HashMap::new(),
            by_tick: BTreeMap::new(),
        }
    }
    fn add_if_new(&mut self, key: &str) -> bool {
        self.tick += 1;
        if let Some(previous) = self.by_key.get_mut(key) {
            self.by_tick.remove(previous);
            *previous = self.tick;
            self.by_tick.insert(self.tick, key.to_owned());
            return false;
        }
        self.by_key.insert(key.to_owned(), self.tick);
        self.by_tick.insert(self.tick, key.to_owned());
        if self.by_key.len() > self.capacity
            && let Some((_, oldest)) = self.by_tick.pop_first()
        {
            self.by_key.remove(&oldest);
        }
        true
    }
}

/// A spawned thread plus a channel that disconnects when its closure ends,
/// so `stop` can wait for it with Python's `join(timeout=5)` bound.
struct BoundedThread {
    handle: thread::JoinHandle<()>,
    done: mpsc::Receiver<()>,
}
impl BoundedThread {
    fn spawn(body: impl FnOnce() + Send + 'static) -> Self {
        let (done_tx, done) = mpsc::channel::<()>();
        let handle = thread::spawn(move || {
            // Dropped when the closure returns (or unwinds): disconnects `done`.
            let _done = done_tx;
            body();
        });
        Self { handle, done }
    }
    /// `thread.join(timeout=5)`: a thread still running after the bound is
    /// left detached, exactly like a timed-out Python join.
    fn join_bounded(self, timeout: Duration) {
        if self.handle.thread().id() == thread::current().id() {
            return;
        }
        match self.done.recv_timeout(timeout) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = self.handle.join();
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

struct EnvState {
    document: Value,
    facts: Facts,
    fact_hashes: HashSet<String>,
    removal_authors: HashMap<String, HashSet<String>>,
    sessions: HashMap<String, Arc<dyn Session>>,
    fact_replay_cursor: HashMap<String, usize>,
    candidate_addresses: HashMap<String, BTreeSet<String>>,
    draining: HashMap<String, Instant>,
    peer_vectors: HashMap<String, BTreeMap<String, i128>>,
    backoff: HashMap<String, Duration>,
    next_attempt: HashMap<String, Instant>,
    hlc: Hlc,
    last_known_vector: BTreeMap<String, i128>,
    known_fact_lines: usize,
    last_snapshot_total: i128,
    last_vector_sent: HashMap<String, Instant>,
    synced_at: Option<f64>,
    incident_outbox: HashMap<String, Fact>,
    incident_backoff: HashMap<String, Duration>,
    incident_next_attempt: HashMap<String, Instant>,
    pending_invites: HashMap<String, (String, String)>,
    alerted_overrides: HashSet<String>,
    /// `_EnvState.relaxed_cache`: (store vector, relaxed document).
    relaxed_cache: Option<(BTreeMap<String, i128>, Arc<Value>)>,
    /// Bumped wherever Python clears `relaxed_cache` (`_refold`), so a fold
    /// computed concurrently with that invalidation is never cached.
    relaxed_generation: u64,
}
impl EnvState {
    fn new(
        facts: Facts,
        hashes: HashSet<String>,
        authors: HashMap<String, HashSet<String>>,
    ) -> Self {
        Self {
            document: Value::Null,
            facts,
            fact_hashes: hashes,
            removal_authors: authors,
            sessions: HashMap::new(),
            fact_replay_cursor: HashMap::new(),
            candidate_addresses: HashMap::new(),
            draining: HashMap::new(),
            peer_vectors: HashMap::new(),
            backoff: HashMap::new(),
            next_attempt: HashMap::new(),
            hlc: Hlc::new(0, 0),
            last_known_vector: BTreeMap::new(),
            known_fact_lines: 0,
            last_snapshot_total: 0,
            last_vector_sent: HashMap::new(),
            synced_at: None,
            incident_outbox: HashMap::new(),
            incident_backoff: HashMap::new(),
            incident_next_attempt: HashMap::new(),
            pending_invites: HashMap::new(),
            alerted_overrides: HashSet::new(),
            relaxed_cache: None,
            relaxed_generation: 0,
        }
    }
}

pub struct TeamSync {
    pub ctx: Arc<Context>,
    pub transport: Arc<dyn Transport>,
    pub device: DeviceKey,
    envs: Mutex<HashMap<String, EnvState>>,
    stop: AtomicBool,
    poll_thread: Mutex<Option<BoundedThread>>,
    last_discovery: Mutex<Instant>,
    /// This instance, for the receive threads it starts (Python's `self`).
    this: Weak<TeamSync>,
    /// `TeamSync._commit_seen`.
    commit_seen: Mutex<LruSet>,
    /// `TeamSync._session_threads`.
    receivers: Mutex<Vec<BoundedThread>>,
    /// Test observability: how many relaxed-document folds actually ran.
    #[cfg(test)]
    relaxed_folds: std::sync::atomic::AtomicUsize,
}
pub fn attached(ctx: &Context) -> Option<Arc<TeamSync>> {
    let guard = ctx.team.lock().ok()?;
    guard.as_ref()?.downcast_ref::<Weak<TeamSync>>()?.upgrade()
}
impl TeamSync {
    pub fn new(ctx: Arc<Context>, transport: Arc<dyn Transport>, device: DeviceKey) -> Arc<Self> {
        let this = Arc::new_cyclic(|this| Self {
            ctx,
            transport,
            device,
            envs: Mutex::new(HashMap::new()),
            stop: AtomicBool::new(false),
            poll_thread: Mutex::new(None),
            last_discovery: Mutex::new(Instant::now() - Duration::from_secs(2)),
            this: this.clone(),
            commit_seen: Mutex::new(LruSet::new(SEEN_CAPACITY)),
            receivers: Mutex::new(Vec::new()),
            #[cfg(test)]
            relaxed_folds: std::sync::atomic::AtomicUsize::new(0),
        });
        let weak = Arc::downgrade(&this);
        let membership: MembershipCheck =
            Arc::new(move |env, fp| weak.upgrade().and_then(|s| s.membership(env, fp)));
        this.transport.set_membership(membership);
        let weak = Arc::downgrade(&this);
        let invite: InviteCheck = Arc::new(move |env, record, hash, proof| {
            weak.upgrade()
                .is_some_and(|s| s.invite_check(env, record, hash, proof))
        });
        this.transport.set_invite_check(Some(invite));
        let weak = Arc::downgrade(&this);
        this.transport
            .set_handshake_failed(Some(Arc::new(move |reason, fp| {
                if let Some(s) = weak.upgrade() {
                    s.audit_handshake_failed(reason, fp);
                }
            })));
        *this.ctx.team.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Box::new(Arc::downgrade(&this)));
        this
    }
    pub fn start(self: &Arc<Self>, listen_address: Option<&str>) -> Result<()> {
        self.discover()?;
        if let Some(address) = listen_address {
            let weak = Arc::downgrade(self);
            let callback: OnSession = Arc::new(move |session| {
                if let Some(s) = weak.upgrade() {
                    s.on_inbound_session(session);
                } else {
                    session.close();
                }
            });
            self.transport.listen(address, callback)?;
        }
        self.stop.store(false, Ordering::SeqCst);
        let weak = Arc::downgrade(self);
        *self.poll_thread.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(BoundedThread::spawn(move || {
                while let Some(s) = weak.upgrade() {
                    if s.stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let _ = s.poll();
                    thread::sleep(Duration::from_millis(50));
                }
            }));
        Ok(())
    }
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.transport.close();
        let poll_thread = self
            .poll_thread
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(t) = poll_thread {
            t.join_bounded(THREAD_JOIN_TIMEOUT);
        }
        let sessions = {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let mut all = Vec::new();
            for env in envs.values_mut() {
                all.extend(env.sessions.drain().map(|(_, session)| session));
                env.fact_replay_cursor.clear();
            }
            all
        };
        for session in sessions {
            session.close();
        }
        // Python: `threads, self._session_threads = self._session_threads, []`
        // then `t.join(timeout=5)` each, outside every lock (a receive
        // thread's own exit path takes `envs` via `drop_session`).
        let receivers =
            std::mem::take(&mut *self.receivers.lock().unwrap_or_else(|e| e.into_inner()));
        for t in receivers {
            t.join_bounded(THREAD_JOIN_TIMEOUT);
        }
    }
    pub fn known_envs(&self) -> Vec<String> {
        let mut ids: Vec<_> = self
            .envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect();
        ids.sort();
        ids
    }
    pub fn discover(&self) -> Result<()> {
        for id in discover_envs(self.ctx.state)? {
            self.register_env(&id)?;
        }
        Ok(())
    }
    pub fn register_env(&self, env_id: &str) -> Result<()> {
        if self
            .envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(env_id)
        {
            return Ok(());
        }
        let (facts, hashes, authors) = load_facts(self.ctx.state, env_id)?;
        let mut env = EnvState::new(facts, hashes, authors);
        let peers = self
            .ctx
            .state
            .read_json(&format!("team/{env_id}/peers.json"), json!({}))?;
        if let Some(peers) = peers.as_object() {
            for (fp, addrs) in peers {
                if valid_fp(fp) {
                    if let Some(addrs) = addrs.as_array() {
                        env.candidate_addresses.insert(
                            fp.clone(),
                            addrs
                                .iter()
                                .filter_map(Value::as_str)
                                .map(str::to_owned)
                                .collect(),
                        );
                    }
                }
            }
        }
        let peer_vectors = self
            .ctx
            .state
            .read_json(&format!("team/{env_id}/peer_vectors.json"), json!({}))?;
        if let Some(entries) = peer_vectors.as_object() {
            for (fp, vector) in entries {
                if !valid_fp(fp) {
                    continue;
                }
                if let Some(vector) = vector.as_object() {
                    env.peer_vectors.insert(
                        fp.clone(),
                        vector
                            .iter()
                            .filter_map(|(author, seq)| {
                                if seq.is_boolean() {
                                    None
                                } else {
                                    seq.as_number()
                                        .and_then(serde_json::Number::as_i128)
                                        .map(|n| (author.clone(), n))
                                }
                            })
                            .collect(),
                    );
                }
            }
        }
        env.known_fact_lines = self
            .ctx
            .state
            .read_lines(&format!("team/{env_id}/facts.jsonl"), None)?
            .len();
        env.last_known_vector = CommitStore::new(self.ctx.state, env_id).vector()?;
        if let Some(snapshot) = fold::load_latest_snapshot(self.ctx.state, env_id)? {
            env.last_snapshot_total = snapshot["vector"]
                .as_object()
                .map(|v| v.values().filter_map(Value::as_i64).map(i128::from).sum())
                .unwrap_or(0);
        }
        for line in self
            .ctx
            .state
            .read_lines(&format!("team/{env_id}/incident_outbox.jsonl"), None)?
        {
            if let Ok(value) = pyjson::loads(&line) {
                if let Ok(fact) = Fact::from_dict(&value) {
                    if fact.env_id == env_id && fact.kind == "incident" {
                        if let Ok(hash) = fact.hash() {
                            env.incident_outbox.insert(hash, fact);
                        }
                    }
                }
            }
        }
        let alerted = self
            .ctx
            .state
            .read_json(&format!("team/{env_id}/overridden_alerted.json"), json!([]))?;
        if let Some(values) = alerted.as_array() {
            env.alerted_overrides = values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
        }
        self.envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(env_id.into(), env);
        self.refold(env_id)?;
        Ok(())
    }
    fn refold(&self, env_id: &str) -> Result<FoldResult> {
        let _lock = self.ctx.state.lock()?;
        let facts = {
            self.envs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(env_id)
                .ok_or_else(|| Error::invalid_input("team_env_unknown"))?
                .facts
                .clone()
        };
        let commits = CommitStore::new(self.ctx.state, env_id).all_commits()?;
        let result = fold::fold_with_snapshot(
            env_id,
            commits,
            self.ctx.state,
            Some(&facts),
            Some(self.ctx.audit),
        )?;
        let (project, environment) = env_project_environment(self.ctx.state, env_id)?;
        fold::derive_local(
            &result,
            self.ctx.state,
            &self.ctx.policy,
            Some(self.ctx.audit),
            Some(&self.device),
            Some(self.ctx.kms),
            project.as_deref(),
            environment.as_deref(),
        )?;
        let total: i128 = result.vector.values().sum();
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        let env = envs
            .get_mut(env_id)
            .ok_or_else(|| Error::invalid_input("team_env_unknown"))?;
        env.document = result.document.clone();
        env.relaxed_cache = None;
        env.relaxed_generation = env.relaxed_generation.wrapping_add(1);
        if total - env.last_snapshot_total >= SNAPSHOT_INTERVAL_COMMITS {
            fold::save_snapshot(
                self.ctx.state,
                env_id,
                total.try_into().unwrap_or(i64::MAX),
                &result,
            )?;
            env.last_snapshot_total = total;
        }
        drop(envs);
        self.record_overrides(env_id, &result.overridden)?;
        Ok(result)
    }
    fn record_overrides(&self, env_id: &str, overridden: &[Value]) -> Result<()> {
        let mine = self.device.fingerprint()?;
        let mut new = Vec::new();
        let mut snapshot = None;
        {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let Some(env) = envs.get_mut(env_id) else {
                return Ok(());
            };
            for entry in overridden {
                if entry["author"] != mine {
                    continue;
                }
                let signature = format!(
                    "{}:{}",
                    entry["hash"].as_str().unwrap_or(""),
                    entry["by_hash"].as_str().unwrap_or("")
                );
                if env.alerted_overrides.insert(signature) {
                    new.push(entry.clone());
                }
            }
            if !new.is_empty() {
                let mut values: Vec<_> = env.alerted_overrides.iter().cloned().collect();
                values.sort();
                snapshot = Some(values);
            }
        }
        let Some(snapshot) = snapshot else {
            return Ok(());
        };
        self.ctx.state.write_json(
            &format!("team/{env_id}/overridden_alerted.json"),
            &json!(snapshot),
        )?;
        for entry in new {
            let kind = entry["target_kind"].as_str().unwrap_or("");
            let target = entry["target_id"].as_str();
            let mut extra = vec![
                ("env_id", json!(env_id)),
                ("author_seq", entry["author_seq"].clone()),
                ("fingerprint", entry["by_author"].clone()),
            ];
            if kind == "secret_active" {
                extra.push(("secret_id", entry["target_id"].clone()));
            }
            let _ = self.ctx.audit.record(
                "team_op_overridden",
                RecordArgs {
                    result: Some("ok"),
                    connection: if kind == "connection" { target } else { None },
                    extra,
                    ..Default::default()
                },
            );
        }
        Ok(())
    }
    fn membership(&self, env_id: &str, fp: &str) -> Option<DeviceRecord> {
        let envs = self.envs.lock().ok()?;
        let member = &envs.get(env_id)?.document["members"][fp];
        if member["status"] != "active" {
            return None;
        }
        let record = DeviceRecord::from_dict(&member["device"]).ok()?;
        (record.fingerprint() == fp).then_some(record)
    }
    fn audit_handshake_failed(&self, reason: &str, fp: Option<&str>) {
        let _ = self.ctx.audit.record(
            "team_handshake_failed",
            RecordArgs {
                result: Some("denied"),
                reason: Some(reason),
                extra: fp.map_or_else(Vec::new, |v| vec![("fingerprint", json!(v))]),
                ..Default::default()
            },
        );
    }
    fn invite_check(&self, env_id: &str, record: &DeviceRecord, hash: &[u8], proof: &[u8]) -> bool {
        let Ok(info) = super::membership::consume_invite(&self.ctx, env_id, hash, proof) else {
            return false;
        };
        let Some((role, name)) = info else {
            return false;
        };
        if let Ok(mut envs) = self.envs.lock() {
            if let Some(env) = envs.get_mut(env_id) {
                env.pending_invites
                    .insert(record.fingerprint(), (role, name));
                return true;
            }
        }
        false
    }
    pub fn document(&self, env_id: &str) -> Result<Value> {
        self.envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(env_id)
            .map(|e| e.document.clone())
            .ok_or_else(|| Error::not_found("team_env_unknown"))
    }
    pub fn is_active_member(&self, env_id: &str, fp: &str) -> bool {
        self.membership(env_id, fp).is_some()
    }
    pub fn set_peer_address(&self, env_id: &str, fp: &str, address: &str) -> Result<()> {
        if !valid_fp(fp) || address.is_empty() {
            return Err(Error::invalid_input("team_invalid_peer_address"));
        }
        {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let env = envs
                .get_mut(env_id)
                .ok_or_else(|| Error::invalid_input("team_env_unknown"))?;
            env.candidate_addresses
                .entry(fp.into())
                .or_default()
                .insert(address.into());
        }
        // `_persist_peer_address`: `doc = read_json(...) or {}`,
        // `addrs = list(doc.get(fp, []))`, append if absent, write back.
        let _lock = self.ctx.state.lock()?;
        let path = format!("team/{env_id}/peers.json");
        let mut peers = read_dict_or_empty(self.ctx.state, &path)?;
        let mut addrs = match peers.get(fp) {
            None => Vec::new(),
            Some(value) => python_list(value)
                .ok_or_else(|| Error::state("state_corrupt").with_detail(&path))?,
        };
        if !addrs.iter().any(|v| v == address) {
            addrs.push(json!(address));
        }
        peers.insert(fp.to_owned(), Value::Array(addrs));
        self.ctx.state.write_json(&path, &Value::Object(peers))
    }
    /// `self._commit_seen.add_if_new(commit.hash)`.
    fn commit_first_seen(&self, commit: &Commit) -> bool {
        // A commit that cannot be hashed cannot be deduplicated; keep the
        // broadcast rather than silently dropping it (unreachable for a
        // commit `receive_commit`/`CommitStore` already accepted).
        let Ok(hash) = commit.hash() else {
            return true;
        };
        self.commit_seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .add_if_new(&hash)
    }
    pub fn submit_commit(&self, env_id: &str, commit: &Commit) -> Result<&'static str> {
        if !self
            .envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(env_id)
        {
            return Err(Error::invalid_input("team_env_unknown"));
        }
        let result = {
            let _lock = self.ctx.state.lock()?;
            commit::receive_commit(
                &CommitStore::new(self.ctx.state, env_id),
                commit,
                commit::now_ms(),
                Some(self.ctx.audit),
            )?
        };
        if result == "accepted" {
            // The local-commit pickup baseline is moved only by
            // `pick_up_local_commits`, as in Python: resetting it here would
            // swallow a commit another process wrote meanwhile. The seen-set
            // keeps that pickup from broadcasting this commit a second time.
            self.refold(env_id)?;
            if self.commit_first_seen(commit) {
                self.broadcast(
                    env_id,
                    &json!({"type":"COMMIT","commit":commit.to_dict()}),
                    None,
                );
            }
        }
        Ok(result)
    }
    pub fn publish_fact(&self, env_id: &str, kind: &str, target: Value) -> Result<Value> {
        validate_fact_target(kind, &target)?;
        let fp = self.device.fingerprint()?;
        let doc = if kind == "member_removed" {
            self.role_document_for_removal(
                env_id,
                &fp,
                target["fingerprint"].as_str().unwrap_or(""),
            )?
        } else {
            self.document(env_id)?
        };
        if !fact_role_ok(&doc, kind, &fp, &target) {
            return Err(Error::policy_denied("team_fact_not_authorized"));
        }
        let hlc = {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            envs.get_mut(env_id)
                .ok_or_else(|| Error::invalid_input("team_env_unknown"))?
                .hlc
                .tick(None)
        };
        let fact = sign_fact(&self.device, env_id, kind, target, &hlc)?;
        if self.store_fact(env_id, &fact)? {
            self.refold(env_id)?;
            self.audit_fact_apply(env_id, &fact);
            self.broadcast(env_id, &json!({"type":"FACT","fact":fact.to_dict()}), None);
            if kind == "member_removed" {
                if let Some(fp) = fact.target["fingerprint"].as_str() {
                    self.drain_removed(env_id, fp);
                }
            }
        }
        Ok(fact.to_dict())
    }
    fn store_fact(&self, env_id: &str, fact: &Fact) -> Result<bool> {
        let hash = fact.hash()?;
        let _lock = self.ctx.state.lock()?;
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        let env = envs
            .get_mut(env_id)
            .ok_or_else(|| Error::invalid_input("team_env_unknown"))?;
        if env.fact_hashes.contains(&hash) {
            return Ok(false);
        }
        let line = pyjson::dumps(&fact.to_dict(), DumpOptions::compact_sorted())?;
        self.ctx
            .state
            .append_line(&format!("team/{env_id}/facts.jsonl"), &line)?;
        env.fact_hashes.insert(hash);
        apply_fact(&mut env.facts, fact);
        env.known_fact_lines += 1;
        if fact.kind == "member_removed" {
            if let Some(fp) = fact.target["fingerprint"].as_str() {
                env.removal_authors
                    .entry(fp.into())
                    .or_default()
                    .insert(fact.author.clone());
            }
        }
        Ok(true)
    }
    fn broadcast(&self, env_id: &str, message: &Value, exclude: Option<&str>) {
        let sessions = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            envs.get(env_id)
                .map(|e| {
                    e.sessions
                        .iter()
                        .filter(|(fp, _)| {
                            Some(fp.as_str()) != exclude && !e.draining.contains_key(*fp)
                        })
                        .map(|(_, s)| s.clone())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        for session in sessions {
            if session.send(message).is_err() {
                session.close();
            }
        }
    }
    fn drain_removed(&self, env_id: &str, fp: &str) {
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(env) = envs.get_mut(env_id) {
            // `_drop_member_sessions`: forget the removed peer as a dial
            // candidate entirely -- addresses and retry/backoff state.
            env.candidate_addresses.remove(fp);
            env.backoff.remove(fp);
            env.next_attempt.remove(fp);
            if env.sessions.contains_key(fp) {
                env.draining.insert(
                    fp.into(),
                    Instant::now()
                        + Duration::from_secs_f64(self.ctx.config.team_removed_drain_seconds),
                );
            }
        }
    }
    pub fn synced_at(&self, env_id: &str) -> Option<String> {
        self.envs
            .lock()
            .ok()?
            .get(env_id)?
            .synced_at
            .map(|ts| iso(Some(ts)))
    }

    fn accept_session(&self, env_id: &str, session: Arc<dyn Session>, inbound: bool) -> bool {
        let fp = session.peer().fingerprint();
        let mine = self.device.fingerprint().unwrap_or_default();
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        let Some(env) = envs.get_mut(env_id) else {
            session.close();
            return false;
        };
        if let Some(current) = env.sessions.get(&fp) {
            if Arc::ptr_eq(current, &session) {
                return true;
            }
            let keep_new = if mine < fp { !inbound } else { inbound };
            if !keep_new {
                session.close();
                return false;
            }
            current.close();
        }
        env.fact_replay_cursor.insert(fp.clone(), 0);
        env.sessions.insert(fp, session);
        true
    }
    fn on_inbound_session(self: &Arc<Self>, session: Arc<dyn Session>) {
        let env_id = session.env_id().to_owned();
        let fp = session.peer().fingerprint();
        if !self.accept_session(&env_id, session.clone(), true) {
            return;
        }
        let pending = {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            envs.get_mut(&env_id)
                .and_then(|env| env.pending_invites.remove(&fp))
        };
        if let Some((role, name)) = pending {
            let _ = self.admit_member(&env_id, &session.peer(), &role, &name);
        }
        self.audit_event("team_session_open", &env_id, Some(&fp), None, None);
        self.start_receiver(env_id.clone(), session.clone());
        self.send_vector(&env_id, &session);
        // Python lets `_send_peers`'s exception (corrupt/non-dict peers.json)
        // escape `_on_inbound_session`, skipping the remaining step.
        if self.send_peers(&env_id, &session).is_err() {
            return;
        }
        self.retry_pending_incidents_to(&env_id, &session);
    }
    fn admit_member(
        &self,
        env_id: &str,
        record: &DeviceRecord,
        role: &str,
        name: &str,
    ) -> Result<()> {
        use crate::kms::WrappedKey;
        let doc = self.document(env_id)?;
        let mut wraps = Map::new();
        if let Some(gens) = doc["dek"]["generations"].as_object() {
            for gen_id in gens.keys() {
                let value = self
                    .ctx
                    .state
                    .read_json(&format!("team/{env_id}/dek/{gen_id}.json"), Value::Null)?;
                if value.is_null() {
                    continue;
                }
                let Ok(wrapped) = WrappedKey::from_dict(&value) else {
                    continue;
                };
                let Ok(dek) = self.ctx.kms.unwrap(&wrapped) else {
                    continue;
                };
                wraps.insert(
                    gen_id.clone(),
                    super::envelope::wrap_dek(dek.expose(), env_id, gen_id, record)?,
                );
            }
        }
        let mut op = json!({"op":"member.add","device":record.to_dict(),"name":name,"role":role});
        if !wraps.is_empty() {
            op["wraps"] = Value::Object(wraps);
        }
        let store = CommitStore::new(self.ctx.state, env_id);
        let fp = self.device.fingerprint()?;
        let seq = store.last_seq(&fp)? + 1;
        let hlc = {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            envs.get_mut(env_id)
                .ok_or_else(|| Error::invalid_input("team_env_unknown"))?
                .hlc
                .tick(None)
        };
        let commit =
            commit::sign_commit(&self.device, env_id, seq, &hlc, &store.vector()?, vec![op])?;
        let outcome = self.submit_commit(env_id, &commit)?;
        if outcome != "accepted" {
            return Err(Error::state(format!("team_local_commit_{outcome}")));
        }
        // Python: extra={"env_id", "fingerprint", "role"} (the role is not a
        // fact/op `kind`).
        let _ = self.ctx.audit.record(
            "team_member_add",
            RecordArgs {
                result: Some("ok"),
                extra: vec![
                    ("env_id", json!(env_id)),
                    ("fingerprint", json!(record.fingerprint())),
                    ("role", json!(role)),
                ],
                ..Default::default()
            },
        );
        Ok(())
    }
    /// `_start_receiver`: always a receive thread of THIS instance (Python's
    /// `self`), registered for `stop`'s bounded join.
    fn start_receiver(&self, env_id: String, session: Arc<dyn Session>) {
        let weak: Weak<Self> = self.this.clone();
        let thread = BoundedThread::spawn(move || {
            loop {
                let Some(this) = weak.upgrade() else {
                    break;
                };
                if this.stop.load(Ordering::SeqCst) {
                    break;
                }
                match session.recv(Duration::from_secs(1)) {
                    Ok(Some(message)) => {
                        if this.handle_message(&env_id, &session, &message).is_err() {
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
            if let Some(this) = weak.upgrade() {
                this.drop_session(&env_id, &session.peer().fingerprint(), Some(&session));
            }
        });
        let mut receivers = self.receivers.lock().unwrap_or_else(|e| e.into_inner());
        // Joining an already-finished thread is immediate in Python; pruning
        // them here only bounds this list's growth.
        receivers.retain(|t| !t.handle.is_finished());
        receivers.push(thread);
    }
    fn drop_session(&self, env_id: &str, fp: &str, expected: Option<&Arc<dyn Session>>) {
        let removed = {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let Some(env) = envs.get_mut(env_id) else {
                return;
            };
            if expected.is_some_and(|wanted| {
                env.sessions
                    .get(fp)
                    .is_none_or(|current| !Arc::ptr_eq(current, wanted))
            }) {
                return;
            }
            env.draining.remove(fp);
            env.fact_replay_cursor.remove(fp);
            env.sessions.remove(fp)
        };
        if let Some(session) = removed {
            session.close();
            self.audit_event("team_session_close", env_id, Some(fp), None, None);
        }
    }
    fn send_vector(&self, env_id: &str, session: &Arc<dyn Session>) {
        let fp = session.peer().fingerprint();
        {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            if envs
                .get(env_id)
                .is_none_or(|e| e.draining.contains_key(&fp))
            {
                return;
            }
        }
        let Ok(vector) = CommitStore::new(self.ctx.state, env_id).vector() else {
            return;
        };
        if session
            .send(&json!({"type":"VECTOR","vector":vector}))
            .is_err()
        {
            self.drop_session(env_id, &fp, Some(session));
            return;
        }
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(env) = envs.get_mut(env_id) {
            env.last_vector_sent.insert(fp, Instant::now());
            env.synced_at = Some((self.ctx.clock)());
        }
    }
    /// `_send_peers`: only list-valued entries, each reduced to its sorted
    /// string addresses. A corrupt or non-dict `peers.json` is an error the
    /// caller stops on, as Python's escaping exception does.
    fn send_peers(&self, env_id: &str, session: &Arc<dyn Session>) -> Result<()> {
        let fp = session.peer().fingerprint();
        {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            if envs
                .get(env_id)
                .is_some_and(|e| e.draining.contains_key(&fp))
            {
                return Ok(());
            }
        }
        let peers_doc = read_dict_or_empty(self.ctx.state, &format!("team/{env_id}/peers.json"))?;
        let mut payload = Map::new();
        for (peer_fp, addrs) in peers_doc {
            let Value::Array(addrs) = addrs else {
                continue;
            };
            let mut strings: Vec<String> = addrs
                .into_iter()
                .filter_map(|a| match a {
                    Value::String(s) => Some(s),
                    _ => None,
                })
                .collect();
            // Python's `sorted()` on str orders by code point, which is
            // exactly UTF-8 byte order.
            strings.sort();
            payload.insert(peer_fp, json!(strings));
        }
        if session
            .send(&json!({"type":"PEERS","peers":payload}))
            .is_err()
        {
            self.drop_session(env_id, &fp, Some(session));
        }
        Ok(())
    }
    fn handle_message(
        &self,
        env_id: &str,
        session: &Arc<dyn Session>,
        message: &Value,
    ) -> Result<()> {
        let mtype = message["type"].as_str().unwrap_or("");
        let fp = session.peer().fingerprint();
        let draining = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            envs.get(env_id)
                .is_some_and(|e| e.draining.contains_key(&fp))
        };
        if draining {
            if mtype == "FACT" && message["fact"]["kind"] == "member_removed" {
                self.handle_fact(env_id, session, message)?;
            }
            return Ok(());
        }
        match mtype {
            "VECTOR" => self.handle_vector(env_id, session, message)?,
            "COMMIT" => self.handle_commit(env_id, session, message)?,
            "FACT" => self.handle_fact(env_id, session, message)?,
            "PEERS" => self.handle_peers(env_id, message),
            "INCIDENT" => self.handle_incident(env_id, session, message)?,
            "INCIDENT_ACK" => self.handle_incident_ack(env_id, message)?,
            _ => {}
        }
        Ok(())
    }
    fn handle_vector(
        &self,
        env_id: &str,
        session: &Arc<dyn Session>,
        message: &Value,
    ) -> Result<()> {
        let Some(vector) = message["vector"].as_object() else {
            return Ok(());
        };
        let fp = session.peer().fingerprint();
        let clean: BTreeMap<String, i128> = vector
            .iter()
            .filter_map(|(k, v)| {
                if !v.is_boolean() {
                    v.as_i64()
                        .filter(|n| *n >= 0)
                        .map(|n| (k.clone(), i128::from(n)))
                } else {
                    None
                }
            })
            .collect();
        {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(env) = envs.get_mut(env_id) {
                env.peer_vectors.insert(fp.clone(), clean);
            }
        }
        self.persist_peer_vectors(env_id)?;
        let store = CommitStore::new(self.ctx.state, env_id);
        let local = store.vector()?;
        let mut sent = 0;
        for (author, last) in local {
            let their = vector
                .get(&author)
                .and_then(Value::as_i64)
                .filter(|n| *n >= 0)
                .map(i128::from)
                .unwrap_or(0);
            for seq in their + 1..=last {
                if let Some(commit) = store.get(&author, seq)? {
                    if session
                        .send(&json!({"type":"COMMIT","commit":commit.to_dict()}))
                        .is_err()
                    {
                        self.drop_session(env_id, &fp, Some(session));
                        return Ok(());
                    }
                    sent += 1;
                }
            }
        }
        if sent > 0 {
            self.audit_event("team_sync_vector", env_id, Some(&fp), None, Some(sent));
        }
        // Ordinary facts have no sequence in the commit vector. Replay a
        // bounded slice after missing commits on this authenticated session;
        // otherwise an offline disable/revoke can be lost permanently.
        self.send_fact_catchup(env_id, session)?;
        if let Some(env) = self
            .envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(env_id)
        {
            env.synced_at = Some((self.ctx.clock)());
        }
        Ok(())
    }
    fn current_fact_session(&self, env_id: &str, fp: &str, session: &Arc<dyn Session>) -> bool {
        let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        envs.get(env_id).is_some_and(|env| {
            !env.draining.contains_key(fp)
                && env.document["members"][fp]["status"] == "active"
                && env
                    .sessions
                    .get(fp)
                    .is_some_and(|current| Arc::ptr_eq(current, session))
        })
    }
    fn send_fact_catchup(&self, env_id: &str, session: &Arc<dyn Session>) -> Result<()> {
        let fp = session.peer().fingerprint();
        if !self.current_fact_session(env_id, &fp, session) {
            return Ok(());
        }
        let lines = self
            .ctx
            .state
            .read_lines(&format!("team/{env_id}/facts.jsonl"), None)?;
        let start = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            envs.get(env_id)
                .and_then(|env| env.fact_replay_cursor.get(&fp))
                .copied()
                .unwrap_or(0)
                .min(lines.len())
        };
        let end = start
            .saturating_add(FACT_REPLAY_LINES_PER_VECTOR)
            .min(lines.len());
        for line in &lines[start..end] {
            let Ok(value) = pyjson::loads(line) else {
                continue;
            };
            let Ok(fact) = Fact::from_dict(&value) else {
                continue;
            };
            if fact.env_id != env_id || fact.kind == "incident" {
                continue;
            }
            let Some(author) = self.known_record(env_id, &fact.author) else {
                continue;
            };
            if !verify_fact(&fact, &author) {
                continue;
            }
            if !self.current_fact_session(env_id, &fp, session) {
                return Ok(());
            }
            if session
                .send(&json!({"type":"FACT","fact":fact.to_dict()}))
                .is_err()
            {
                self.drop_session(env_id, &fp, Some(session));
                return Ok(());
            }
        }
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(env) = envs.get_mut(env_id)
            && env
                .sessions
                .get(&fp)
                .is_some_and(|current| Arc::ptr_eq(current, session))
        {
            env.fact_replay_cursor
                .insert(fp, if end == lines.len() { 0 } else { end });
        }
        Ok(())
    }
    fn persist_peer_vectors(&self, env_id: &str) -> Result<()> {
        let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        let Some(env) = envs.get(env_id) else {
            return Ok(());
        };
        self.ctx.state.write_json(
            &format!("team/{env_id}/peer_vectors.json"),
            &json!(env.peer_vectors),
        )
    }
    fn handle_commit(
        &self,
        env_id: &str,
        session: &Arc<dyn Session>,
        message: &Value,
    ) -> Result<()> {
        let Ok(commit) = Commit::from_dict(&message["commit"]) else {
            return Ok(());
        };
        if commit.env_id != env_id {
            return Ok(());
        }
        let outcome = {
            let _lock = self.ctx.state.lock()?;
            commit::receive_commit(
                &CommitStore::new(self.ctx.state, env_id),
                &commit,
                commit::now_ms(),
                Some(self.ctx.audit),
            )?
        };
        if outcome == "accepted" {
            // As in `submit_commit`: the pickup baseline is left alone and the
            // seen-set gates the (single) rebroadcast.
            self.refold(env_id)?;
            if self.commit_first_seen(&commit) {
                self.broadcast(
                    env_id,
                    &json!({"type":"COMMIT","commit":commit.to_dict()}),
                    Some(&session.peer().fingerprint()),
                );
            }
        }
        Ok(())
    }
    /// `_relaxed_document`, including its store-vector-keyed cache: while no
    /// commit has changed the vector and no `_refold` has run since, the
    /// previous fold is reused instead of re-folding the whole commit log
    /// (one lookup per replayed/received fact and per incident).
    fn relaxed_document(&self, env_id: &str) -> Result<Arc<Value>> {
        let vector_key = CommitStore::new(self.ctx.state, env_id).vector()?;
        let (mut facts, generation) = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let env = envs
                .get(env_id)
                .ok_or_else(|| Error::invalid_input("team_env_unknown"))?;
            if let Some((cached_key, cached)) = &env.relaxed_cache
                && *cached_key == vector_key
            {
                return Ok(cached.clone());
            }
            (env.facts.clone(), env.relaxed_generation)
        };
        facts.removed_members.clear();
        #[cfg(test)]
        self.relaxed_folds.fetch_add(1, Ordering::SeqCst);
        let document = Arc::new(
            fold::fold(
                env_id,
                CommitStore::new(self.ctx.state, env_id).all_commits()?,
                Some(&facts),
                None,
                None,
                None,
            )?
            .document,
        );
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(env) = envs.get_mut(env_id)
            && env.relaxed_generation == generation
        {
            env.relaxed_cache = Some((vector_key, document.clone()));
        }
        Ok(document)
    }
    fn known_record(&self, env_id: &str, fp: &str) -> Option<DeviceRecord> {
        let doc = self.relaxed_document(env_id).ok()?;
        let record = DeviceRecord::from_dict(&doc["members"][fp]["device"]).ok()?;
        (record.fingerprint() == fp).then_some(record)
    }
    fn role_document_for_removal(&self, env_id: &str, author: &str, target: &str) -> Result<Value> {
        let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        let env = envs
            .get(env_id)
            .ok_or_else(|| Error::invalid_input("team_env_unknown"))?;
        if !env.facts.removed_members.contains(author)
            || env
                .removal_authors
                .get(author)
                .is_none_or(|set| set.len() != 1 || !set.contains(target))
        {
            return Ok(env.document.clone());
        }
        let mut facts = env.facts.clone();
        facts.removed_members.remove(author);
        drop(envs);
        Ok(fold::fold(
            env_id,
            CommitStore::new(self.ctx.state, env_id).all_commits()?,
            Some(&facts),
            None,
            None,
            None,
        )?
        .document)
    }
    fn validate_incoming_fact(&self, env_id: &str, fact: &Fact) -> Result<bool> {
        let hash = fact.hash()?;
        {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            if envs
                .get(env_id)
                .is_none_or(|e| e.fact_hashes.contains(&hash))
            {
                return Ok(false);
            }
        }
        if validate_fact_target(&fact.kind, &fact.target).is_err() {
            self.audit_fact_rejected(env_id, fact, "team_fact_target_invalid");
            return Ok(false);
        }
        let Some(record) = self.known_record(env_id, &fact.author) else {
            self.audit_fact_rejected(env_id, fact, "team_fact_signature_invalid");
            return Ok(false);
        };
        if !verify_fact(fact, &record) {
            self.audit_fact_rejected(env_id, fact, "team_fact_signature_invalid");
            return Ok(false);
        }
        let doc = if fact.kind == "member_removed" {
            self.role_document_for_removal(
                env_id,
                &fact.author,
                fact.target["fingerprint"].as_str().unwrap_or(""),
            )?
        } else {
            self.document(env_id)?
        };
        if !fact_role_ok(&doc, &fact.kind, &fact.author, &fact.target) {
            self.audit_fact_rejected(env_id, fact, "team_fact_not_authorized");
            return Ok(false);
        }
        Ok(true)
    }
    fn handle_fact(&self, env_id: &str, session: &Arc<dyn Session>, message: &Value) -> Result<()> {
        let Ok(fact) = Fact::from_dict(&message["fact"]) else {
            return Ok(());
        };
        if fact.env_id != env_id
            || fact.kind == "incident"
            || !FACT_KINDS.contains(&fact.kind.as_str())
        {
            return Ok(());
        }
        if self.validate_incoming_fact(env_id, &fact)? && self.store_fact(env_id, &fact)? {
            self.refold(env_id)?;
            self.audit_fact_apply(env_id, &fact);
            self.broadcast(
                env_id,
                &json!({"type":"FACT","fact":fact.to_dict()}),
                Some(&session.peer().fingerprint()),
            );
            if fact.kind == "member_removed" {
                if let Some(fp) = fact.target["fingerprint"].as_str() {
                    self.drain_removed(env_id, fp);
                }
            }
        }
        Ok(())
    }
    fn handle_peers(&self, env_id: &str, message: &Value) {
        let Some(peers) = message["peers"].as_object() else {
            return;
        };
        let mine = self.device.fingerprint().unwrap_or_default();
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        let Some(env) = envs.get_mut(env_id) else {
            return;
        };
        for (fp, addrs) in peers {
            if fp == &mine || env.document["members"][fp]["status"] != "active" {
                continue;
            }
            if let Some(addrs) = addrs.as_array() {
                let bucket = env.candidate_addresses.entry(fp.clone()).or_default();
                for addr in addrs {
                    if let Some(s) = addr.as_str() {
                        if !s.is_empty() && s.len() <= 128 {
                            bucket.insert(s.into());
                        }
                    }
                }
            }
        }
    }
    fn audit_event(
        &self,
        event: &str,
        env_id: &str,
        fp: Option<&str>,
        kind: Option<&str>,
        count: Option<usize>,
    ) {
        let mut extra = vec![("env_id", json!(env_id))];
        if let Some(fp) = fp {
            extra.push(("fingerprint", json!(fp)));
        }
        if let Some(kind) = kind {
            extra.push(("kind", json!(kind)));
        }
        if let Some(count) = count {
            extra.push(("commits", json!(count)));
        }
        let _ = self.ctx.audit.record(
            event,
            RecordArgs {
                result: Some("ok"),
                extra,
                ..Default::default()
            },
        );
    }
    fn audit_fact_apply(&self, env_id: &str, fact: &Fact) {
        self.audit_event(
            "team_fact_apply",
            env_id,
            Some(&fact.author),
            Some(&fact.kind),
            None,
        );
    }
    fn audit_fact_rejected(&self, env_id: &str, fact: &Fact, reason: &str) {
        let _ = self.ctx.audit.record(
            "team_fact_rejected",
            RecordArgs {
                result: Some("denied"),
                reason: Some(reason),
                extra: vec![
                    ("env_id", json!(env_id)),
                    ("kind", json!(fact.kind)),
                    ("fingerprint", json!(fact.author)),
                ],
                ..Default::default()
            },
        );
    }

    fn handle_incident(
        &self,
        env_id: &str,
        session: &Arc<dyn Session>,
        message: &Value,
    ) -> Result<()> {
        let Ok(fact) = Fact::from_dict(&message["fact"]) else {
            return Ok(());
        };
        if fact.env_id != env_id
            || fact.kind != "incident"
            || fact.author != session.peer().fingerprint()
        {
            return Ok(());
        }
        // `author_record is None or not verify_fact(...)`: an unknown author is
        // audited exactly like a bad signature.
        if !self
            .known_record(env_id, &fact.author)
            .is_some_and(|record| verify_fact(&fact, &record))
        {
            self.audit_fact_rejected(env_id, &fact, "team_fact_signature_invalid");
            return Ok(());
        }
        let doc = self.document(env_id)?;
        if !fact_role_ok(&doc, "incident", &fact.author, &fact.target) {
            self.audit_fact_rejected(env_id, &fact, "team_fact_not_authorized");
            return Ok(());
        }
        if !is_admin(&doc, &self.device.fingerprint()?) {
            return Ok(());
        }
        let id = fact.target["incident_id"].as_str().unwrap_or("");
        if !valid_token(id) {
            return Ok(());
        }
        let path = format!("team/{env_id}/incidents/{}-{id}.json", fact.author);
        if !self.ctx.state.exists(&path) {
            // A retry must reconstruct a missing incident record even when a
            // prior attempt already persisted the fact before failing here.
            let _newly_stored = self.store_fact(env_id, &fact)?;
            let mut rec = fact.target.clone();
            rec["received_from"] = json!(fact.author);
            rec["received_at"] = json!(iso(Some((self.ctx.clock)())));
            self.ctx.state.write_json(&path, &rec)?;
            self.apply_incident_rotation_flags(env_id, &fact.target)?;
            self.audit_event(
                "team_incident_received",
                env_id,
                Some(&fact.author),
                None,
                None,
            );
        }
        if session
            .send(&json!({"type":"INCIDENT_ACK","hash":fact.hash()?}))
            .is_err()
        {
            self.drop_session(env_id, &session.peer().fingerprint(), Some(session));
        }
        Ok(())
    }
    fn apply_incident_rotation_flags(&self, env_id: &str, target: &Value) -> Result<()> {
        let mandatory: Vec<&str> = target["secret_ids_mandatory"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let recommended: Vec<&str> = target["secret_ids_recommended"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let _lock = self.ctx.state.lock()?;
        let path = format!("team/{env_id}/rotation_flags.json");
        let corrupt = || Error::state("state_corrupt").with_detail(&path);
        // `flags = read_json(...) or {}`. On a truthy non-dict Python's item
        // assignment / `.get` raises uncaught (§3.5: `state_corrupt`), but
        // only once there is a secret id to flag; with none it writes the
        // document back unchanged.
        let mut flags = match self.ctx.state.read_json(&path, json!({}))? {
            Value::Object(map) => map,
            other if super::json_falsy(&other) => Map::new(),
            other if mandatory.is_empty() && recommended.is_empty() => {
                return self.ctx.state.write_json(&path, &other);
            }
            _ => return Err(corrupt()),
        };
        let now = iso(Some((self.ctx.clock)()));
        for id in mandatory {
            flags.insert(
                id.to_owned(),
                json!({"reason":"rotation_required","flagged_at":now}),
            );
        }
        for id in recommended {
            // `flags.get(id, {}).get("reason")`: a present non-dict entry
            // raises in Python.
            let required = match flags.get(id) {
                None => false,
                Some(Value::Object(entry)) => entry
                    .get("reason")
                    .is_some_and(|reason| reason == "rotation_required"),
                Some(_) => return Err(corrupt()),
            };
            if !required {
                flags.insert(
                    id.to_owned(),
                    json!({"reason":"rotation_recommended","flagged_at":now}),
                );
            }
        }
        self.ctx.state.write_json(&path, &Value::Object(flags))
    }
    fn handle_incident_ack(&self, env_id: &str, message: &Value) -> Result<()> {
        let Some(hash) = message["hash"].as_str() else {
            return Ok(());
        };
        let found = {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(env) = envs.get_mut(env_id) {
                env.incident_backoff.remove(hash);
                env.incident_next_attempt.remove(hash);
                env.incident_outbox.remove(hash).is_some()
            } else {
                false
            }
        };
        if found {
            self.persist_incident_outbox(env_id)?;
        }
        Ok(())
    }
    fn persist_incident_outbox(&self, env_id: &str) -> Result<()> {
        let facts = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            envs.get(env_id)
                .map(|e| e.incident_outbox.values().cloned().collect::<Vec<_>>())
                .unwrap_or_default()
        };
        let mut lines = Vec::new();
        for fact in facts {
            lines.push(pyjson::dumps(
                &fact.to_dict(),
                DumpOptions::compact_sorted(),
            )?);
        }
        let blob = if lines.is_empty() {
            String::new()
        } else {
            lines.join("\n") + "\n"
        };
        self.ctx.state.write_bytes(
            &format!("team/{env_id}/incident_outbox.jsonl"),
            blob.as_bytes(),
        )
    }
    fn deliver_incident(&self, env_id: &str, fact: &Fact) -> usize {
        let mine = self.device.fingerprint().unwrap_or_default();
        let sessions = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            envs.get(env_id)
                .map(|e| {
                    e.sessions
                        .iter()
                        .filter(|(fp, _)| {
                            *fp != &mine
                                && !e.draining.contains_key(*fp)
                                && is_admin(&e.document, fp)
                        })
                        .map(|(_, s)| s.clone())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        let mut sent = 0;
        for session in sessions {
            if session
                .send(&json!({"type":"INCIDENT","fact":fact.to_dict()}))
                .is_ok()
            {
                sent += 1;
            } else {
                self.drop_session(env_id, &session.peer().fingerprint(), Some(&session));
            }
        }
        sent
    }
    pub fn send_incident(&self, env_id: &str, summary: &Value) -> Result<Value> {
        let clean = sanitize_incident_summary(summary)?;
        let doc = self.document(env_id)?;
        if !fact_role_ok(&doc, "incident", &self.device.fingerprint()?, &clean) {
            return Err(Error::policy_denied("team_fact_not_authorized"));
        }
        let hlc = {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            envs.get_mut(env_id)
                .ok_or_else(|| Error::invalid_input("team_env_unknown"))?
                .hlc
                .tick(None)
        };
        let fact = sign_fact(&self.device, env_id, "incident", clean, &hlc)?;
        // An outbox entry still needs delivery/retry even if this signed fact
        // was already persisted by an earlier attempt.
        let _newly_stored = self.store_fact(env_id, &fact)?;
        let hash = fact.hash()?;
        {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let env = envs
                .get_mut(env_id)
                .ok_or_else(|| Error::invalid_input("team_env_unknown"))?;
            env.incident_outbox.insert(hash.clone(), fact.clone());
            env.incident_backoff.remove(&hash);
            env.incident_next_attempt.remove(&hash);
        }
        self.persist_incident_outbox(env_id)?;
        self.deliver_incident(env_id, &fact);
        let mut result = fact.to_dict();
        result["hash"] = json!(hash);
        Ok(result)
    }
    pub fn send_incident_for_all_envs(&self, summaries: &Value) -> Value {
        let mut result = Map::new();
        if let Some(entries) = summaries.as_object() {
            for (env, summary) in entries {
                let status = match self.send_incident(env, summary) {
                    Ok(_) => "queued".into(),
                    Err(e) => format!("error:{}", e.reason),
                };
                result.insert(env.clone(), json!(status));
            }
        }
        Value::Object(result)
    }
    pub fn on_incident_open(&self, summaries: &Value) -> Value {
        self.send_incident_for_all_envs(summaries)
    }
    fn retry_pending_incidents_to(&self, env_id: &str, session: &Arc<dyn Session>) {
        let fp = session.peer().fingerprint();
        let pending = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            envs.get(env_id)
                .filter(|e| !e.draining.contains_key(&fp) && is_admin(&e.document, &fp))
                .map(|e| e.incident_outbox.values().cloned().collect::<Vec<_>>())
                .unwrap_or_default()
        };
        for fact in pending {
            if session
                .send(&json!({"type":"INCIDENT","fact":fact.to_dict()}))
                .is_err()
            {
                self.drop_session(env_id, &fp, Some(session));
                break;
            }
        }
    }
    fn poll_incident_outbox(&self, env_id: &str, now: Instant) {
        let due = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            envs.get(env_id)
                .map(|e| {
                    e.incident_outbox
                        .iter()
                        .filter(|(h, _)| {
                            e.incident_next_attempt.get(*h).is_none_or(|at| now >= *at)
                        })
                        .map(|(h, f)| (h.clone(), f.clone()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        for (hash, fact) in due {
            self.deliver_incident(env_id, &fact);
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(env) = envs.get_mut(env_id) {
                if !env.incident_outbox.contains_key(&hash) {
                    continue;
                }
                let (min, max) = self.ctx.config.team_incident_retry_backoff;
                let next = env
                    .incident_backoff
                    .get(&hash)
                    .map_or(min, |d| (d.as_secs_f64() * 2.0).min(max));
                let dur = Duration::from_secs_f64(next);
                env.incident_backoff.insert(hash.clone(), dur);
                env.incident_next_attempt.insert(hash, now + dur);
            }
        }
    }

    pub fn poll(&self) -> Result<()> {
        let now = Instant::now();
        {
            let mut last = self
                .last_discovery
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if now.duration_since(*last) > Duration::from_secs(1) {
                *last = now;
                drop(last);
                self.discover()?;
            }
        }
        for id in self.known_envs() {
            self.poll_env(&id, now)?;
        }
        Ok(())
    }
    fn poll_env(&self, env_id: &str, now: Instant) -> Result<()> {
        self.pick_up_local_commits(env_id)?;
        self.pick_up_local_facts(env_id)?;
        self.poll_incident_outbox(env_id, now);
        let store = CommitStore::new(self.ctx.state, env_id);
        let released = store.release_deferred(commit::now_ms())?;
        if !released.is_empty() {
            self.refold(env_id)?;
            for commit in released {
                // The next pickup tick sees these as new store commits too;
                // the seen-set keeps that from broadcasting them again.
                if self.commit_first_seen(&commit) {
                    self.broadcast(
                        env_id,
                        &json!({"type":"COMMIT","commit":commit.to_dict()}),
                        None,
                    );
                }
            }
        }
        let (close, dial, send) = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let Some(env) = envs.get(env_id) else {
                return Ok(());
            };
            let max_age = Duration::from_secs_f64(self.ctx.config.team_session_max_age_seconds);
            let close = env
                .sessions
                .iter()
                .filter(|(fp, s)| {
                    s.is_closed()
                        || env
                            .draining
                            .get(*fp)
                            .is_some_and(|deadline| now >= *deadline)
                        || now.duration_since(s.created_at()) >= max_age
                })
                .map(|(fp, _)| fp.clone())
                .collect::<Vec<_>>();
            let mine = self.device.fingerprint()?;
            let dial = env.document["members"]
                .as_object()
                .into_iter()
                .flat_map(|m| m.iter())
                .filter(|(fp, m)| {
                    *fp != &mine
                        && m["status"] == "active"
                        && !env.sessions.contains_key(*fp)
                        && env
                            .candidate_addresses
                            .get(*fp)
                            .is_some_and(|a| !a.is_empty())
                        && env.next_attempt.get(*fp).is_none_or(|at| now >= *at)
                })
                .map(|(fp, _)| fp.clone())
                .collect::<Vec<_>>();
            let interval = self
                .ctx
                .config
                .team_sync_interval_seconds
                .unwrap_or_else(|| {
                    env.document["settings"]["sync_interval_seconds"]
                        .as_f64()
                        .filter(|v| *v > 0.0)
                        .unwrap_or(fold::DEFAULT_SYNC_INTERVAL_SECONDS as f64)
                });
            let send = env
                .sessions
                .iter()
                .filter(|(fp, _)| {
                    env.last_vector_sent
                        .get(*fp)
                        .is_none_or(|at| now.duration_since(*at).as_secs_f64() >= interval)
                })
                .map(|(_, s)| s.clone())
                .collect::<Vec<_>>();
            (close, dial, send)
        };
        for fp in close {
            self.drop_session(env_id, &fp, None);
        }
        for fp in dial {
            self.dial_attempt(env_id, &fp);
        }
        for session in send {
            self.send_vector(env_id, &session);
        }
        Ok(())
    }
    fn pick_up_local_commits(&self, env_id: &str) -> Result<()> {
        let store = CommitStore::new(self.ctx.state, env_id);
        let current = store.vector()?;
        let baseline = {
            self.envs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(env_id)
                .map(|e| e.last_known_vector.clone())
                .unwrap_or_default()
        };
        let mut added = Vec::new();
        for (fp, hi) in &current {
            let lo = baseline.get(fp).copied().unwrap_or(0);
            for seq in lo + 1..=*hi {
                if let Some(commit) = store.get(fp, seq)? {
                    added.push(commit);
                }
            }
        }
        if let Some(env) = self
            .envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(env_id)
        {
            env.last_known_vector = current;
        }
        if !added.is_empty() {
            self.refold(env_id)?;
            for commit in added {
                if self.commit_first_seen(&commit) {
                    self.broadcast(
                        env_id,
                        &json!({"type":"COMMIT","commit":commit.to_dict()}),
                        None,
                    );
                }
            }
        }
        Ok(())
    }
    fn pick_up_local_facts(&self, env_id: &str) -> Result<()> {
        let lines = self
            .ctx
            .state
            .read_lines(&format!("team/{env_id}/facts.jsonl"), None)?;
        let start = {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let env = envs
                .get_mut(env_id)
                .ok_or_else(|| Error::invalid_input("team_env_unknown"))?;
            let start = env.known_fact_lines;
            env.known_fact_lines = lines.len();
            start
        };
        for line in lines.iter().skip(start) {
            let Ok(value) = pyjson::loads(line) else {
                continue;
            };
            let Ok(fact) = Fact::from_dict(&value) else {
                continue;
            };
            if fact.env_id != env_id
                || fact.kind == "incident"
                || !FACT_KINDS.contains(&fact.kind.as_str())
                || !self.validate_incoming_fact(env_id, &fact)?
            {
                continue;
            }
            let inserted = {
                let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(env) = envs.get_mut(env_id) {
                    if env.fact_hashes.insert(fact.hash()?) {
                        apply_fact(&mut env.facts, &fact);
                        if fact.kind == "member_removed" {
                            if let Some(fp) = fact.target["fingerprint"].as_str() {
                                env.removal_authors
                                    .entry(fp.into())
                                    .or_default()
                                    .insert(fact.author.clone());
                            }
                        }
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            };
            if !inserted {
                continue;
            }
            self.refold(env_id)?;
            self.audit_fact_apply(env_id, &fact);
            self.broadcast(env_id, &json!({"type":"FACT","fact":fact.to_dict()}), None);
            if fact.kind == "member_removed" {
                if let Some(fp) = fact.target["fingerprint"].as_str() {
                    self.drain_removed(env_id, fp);
                }
            }
        }
        Ok(())
    }
    fn dial_attempt(&self, env_id: &str, fp: &str) {
        let address = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            envs.get(env_id)
                .and_then(|e| e.candidate_addresses.get(fp))
                .and_then(|a| a.iter().next().cloned())
        };
        let Some(address) = address else {
            return;
        };
        let Ok(session) = self.transport.dial(&address, env_id, None) else {
            self.record_dial_failure(env_id, fp);
            return;
        };
        if session.peer().fingerprint() != fp {
            session.close();
            self.record_dial_failure(env_id, fp);
            return;
        }
        if let Some(env) = self
            .envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(env_id)
        {
            env.backoff.remove(fp);
            env.next_attempt.remove(fp);
        }
        self.wire_dialed_session(env_id, fp, &address, session);
    }
    fn record_dial_failure(&self, env_id: &str, fp: &str) {
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(env) = envs.get_mut(env_id) {
            let (min, max) = self.ctx.config.team_dial_backoff;
            let next = env
                .backoff
                .get(fp)
                .map_or(min, |d| (d.as_secs_f64() * 2.0).min(max));
            let dur = Duration::from_secs_f64(next);
            env.backoff.insert(fp.into(), dur);
            env.next_attempt.insert(fp.into(), Instant::now() + dur);
        }
    }
    fn wire_dialed_session(
        &self,
        env_id: &str,
        fp: &str,
        address: &str,
        session: Arc<dyn Session>,
    ) {
        let _ = self.set_peer_address(env_id, fp, address);
        if !self.accept_session(env_id, session.clone(), false) {
            return;
        }
        self.audit_event("team_session_open", env_id, Some(fp), None, None);
        self.start_receiver(env_id.into(), session.clone());
        self.send_vector(env_id, &session);
        if self.send_peers(env_id, &session).is_err() {
            return;
        }
        self.retry_pending_incidents_to(env_id, &session);
    }
    pub fn adopt_outbound_session(&self, env_id: &str, session: Arc<dyn Session>, address: &str) {
        let fp = session.peer().fingerprint();
        self.wire_dialed_session(env_id, &fp, address, session);
    }
    pub fn status(&self, env_id: &str) -> Result<Value> {
        let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        let env = envs
            .get(env_id)
            .ok_or_else(|| Error::not_found("team_env_unknown"))?;
        let mut sessions: Vec<_> = env.sessions.keys().cloned().collect();
        sessions.sort();
        Ok(
            json!({"env_id":env_id,"vector":CommitStore::new(self.ctx.state,env_id).vector()?,"sessions":sessions,"synced_at":env.synced_at.map(|ts|iso(Some(ts))),"pending_deferred":CommitStore::new(self.ctx.state,env_id).deferred_commits()?.len()}),
        )
    }

    pub fn compact(&self, env_id: &str) -> Result<Value> {
        let (facts, peer_vectors, members) = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let env = envs
                .get(env_id)
                .ok_or_else(|| Error::not_found("team_env_unknown"))?;
            (
                env.facts.clone(),
                env.peer_vectors.clone(),
                env.document["members"].clone(),
            )
        };
        let store = CommitStore::new(self.ctx.state, env_id);
        let commits = store.all_commits()?;
        if commits.is_empty() {
            return Ok(json!({"env_id":env_id,"removed":0,"blocked_by":[]}));
        }
        let now = i128::from(commit::now_ms());
        let mut cutoff = None;
        for (i, entry) in commits.iter().enumerate() {
            let (wall, _) = Hlc::parse(&entry.hlc)?;
            if now - wall < i128::from(COMPACT_MIN_AGE_MS) {
                break;
            }
            cutoff = Some(i);
        }
        let Some(cutoff) = cutoff else {
            return Ok(
                json!({"env_id":env_id,"removed":0,"blocked_by":[],"reason":"no_commit_old_enough"}),
            );
        };
        let mut candidate = BTreeMap::<String, i128>::new();
        for entry in &commits[..=cutoff] {
            candidate
                .entry(entry.author.clone())
                .and_modify(|seq| *seq = (*seq).max(entry.author_seq))
                .or_insert(entry.author_seq);
        }
        let mine = self.device.fingerprint()?;
        let mut blocked = Vec::new();
        if let Some(members) = members.as_object() {
            for (fp, member) in members {
                if fp == &mine || member["status"] != "active" {
                    continue;
                }
                if candidate.iter().any(|(author, seq)| {
                    peer_vectors
                        .get(fp)
                        .and_then(|v| v.get(author))
                        .copied()
                        .unwrap_or(0)
                        < *seq
                }) {
                    blocked.push(fp.clone());
                }
            }
        }
        blocked.sort();
        if !blocked.is_empty() {
            return Ok(json!({"env_id":env_id,"removed":0,"blocked_by":blocked}));
        }
        let snapshot = fold::fold(
            env_id,
            commits[..=cutoff].to_vec(),
            Some(&facts),
            None,
            None,
            Some(self.ctx.audit),
        )?;
        let total: i128 = candidate.values().sum();
        fold::save_snapshot(
            self.ctx.state,
            env_id,
            total.try_into().unwrap_or(i64::MAX),
            &snapshot,
        )?;
        let mut removed = 0;
        {
            let _lock = self.ctx.state.lock()?;
            for entry in &commits[..=cutoff] {
                if entry.ops.iter().any(|op| {
                    [
                        "env.init",
                        "member.add",
                        "member.set_role",
                        "member.remove",
                        "owner.transfer",
                        "dek.rotate",
                    ]
                    .contains(&op["op"].as_str().unwrap_or(""))
                }) {
                    continue;
                }
                let path = self.ctx.state.path.join(format!(
                    "team/{env_id}/commits/{}/{}.json",
                    entry.author, entry.author_seq
                ));
                if std::fs::remove_file(path).is_ok() {
                    removed += 1;
                }
            }
        }
        if let Some(env) = self
            .envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(env_id)
        {
            env.last_snapshot_total = total;
        }
        self.refold(env_id)?;
        let _ = self.ctx.audit.record(
            "team_compact",
            RecordArgs {
                result: Some("ok"),
                extra: vec![("env_id", json!(env_id)), ("count", json!(removed))],
                ..Default::default()
            },
        );
        Ok(json!({"env_id":env_id,"removed":removed,"blocked_by":[]}))
    }
}
