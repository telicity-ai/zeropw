//! Team replication and monotone facts, port of `zeropw/team/sync.py`.
#![allow(clippy::collapsible_if)]
#![allow(clippy::type_complexity)]

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
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
pub const ENVS_MAP_PATH: &str = "team/envs.json";
pub const SNAPSHOT_INTERVAL_COMMITS: i128 = 1000;
pub const COMPACT_MIN_AGE_MS: i64 = 30 * 24 * 3600 * 1000;
pub const MAX_INCIDENT_STR_LENGTH: usize = 200;
pub const MAX_INCIDENT_LIST_ITEMS: usize = 100;
pub const MAX_INCIDENT_UNIT: i64 = 2_147_483_647;

fn canon(value: &Value) -> Result<Vec<u8>> {
    Ok(pyjson::dumps(value, DumpOptions::compact_sorted())?.into_bytes())
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
        let target = match obj.get("target").ok_or_else(bad)? {
            Value::Object(m) => m.clone(),
            Value::Array(pairs) => {
                let mut m = Map::new();
                for pair in pairs {
                    let (key, value) = match pair {
                        Value::Array(items) if items.len() == 2 => (&items[0], &items[1]),
                        _ => return Err(bad()),
                    };
                    if key.is_array() || key.is_object() {
                        return Err(bad());
                    }
                    m.insert(commit::python_str_coerce(key), value.clone());
                }
                m
            }
            _ => return Err(bad()),
        };
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
        let Ok(value) = serde_json::from_str(&line) else {
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

struct EnvState {
    document: Value,
    facts: Facts,
    fact_hashes: HashSet<String>,
    removal_authors: HashMap<String, HashSet<String>>,
    sessions: HashMap<String, Arc<dyn Session>>,
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
        }
    }
}

pub struct TeamSync {
    pub ctx: Arc<Context>,
    pub transport: Arc<dyn Transport>,
    pub device: DeviceKey,
    envs: Mutex<HashMap<String, EnvState>>,
    stop: AtomicBool,
    poll_thread: Mutex<Option<thread::JoinHandle<()>>>,
    last_discovery: Mutex<Instant>,
}
pub fn attached(ctx: &Context) -> Option<Arc<TeamSync>> {
    let guard = ctx.team.lock().ok()?;
    guard.as_ref()?.downcast_ref::<Weak<TeamSync>>()?.upgrade()
}
impl TeamSync {
    pub fn new(ctx: Arc<Context>, transport: Arc<dyn Transport>, device: DeviceKey) -> Arc<Self> {
        let this = Arc::new(Self {
            ctx,
            transport,
            device,
            envs: Mutex::new(HashMap::new()),
            stop: AtomicBool::new(false),
            poll_thread: Mutex::new(None),
            last_discovery: Mutex::new(Instant::now() - Duration::from_secs(2)),
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
            Some(thread::spawn(move || {
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
        if let Some(t) = self
            .poll_thread
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = t.join();
        }
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        for env in envs.values_mut() {
            for (_, session) in env.sessions.drain() {
                session.close();
            }
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
            if let Ok(value) = serde_json::from_str::<Value>(&line) {
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
        let _lock = self.ctx.state.lock()?;
        let path = format!("team/{env_id}/peers.json");
        let mut peers = self.ctx.state.read_json(&path, json!({}))?;
        let mut addrs = peers[fp].as_array().cloned().unwrap_or_default();
        if !addrs.iter().any(|v| v == address) {
            addrs.push(json!(address));
        }
        peers[fp] = Value::Array(addrs);
        self.ctx.state.write_json(&path, &peers)
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
            self.refold(env_id)?;
            if let Some(env) = self
                .envs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_mut(env_id)
            {
                env.last_known_vector = CommitStore::new(self.ctx.state, env_id).vector()?;
            }
            self.broadcast(
                env_id,
                &json!({"type":"COMMIT","commit":commit.to_dict()}),
                None,
            );
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
        self.store_fact(env_id, &fact)?;
        self.refold(env_id)?;
        if kind != "incident" {
            self.broadcast(env_id, &json!({"type":"FACT","fact":fact.to_dict()}), None);
        }
        if kind == "member_removed" {
            if let Some(fp) = fact.target["fingerprint"].as_str() {
                self.drain_removed(env_id, fp);
            }
        }
        Ok(fact.to_dict())
    }
    fn store_fact(&self, env_id: &str, fact: &Fact) -> Result<()> {
        let hash = fact.hash()?;
        let _lock = self.ctx.state.lock()?;
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        let env = envs
            .get_mut(env_id)
            .ok_or_else(|| Error::invalid_input("team_env_unknown"))?;
        if env.fact_hashes.contains(&hash) {
            return Ok(());
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
        Ok(())
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
            env.candidate_addresses.remove(fp);
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
        self.send_peers(&env_id, &session);
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
        self.audit_event(
            "team_member_add",
            env_id,
            Some(&record.fingerprint()),
            Some(role),
            None,
        );
        Ok(())
    }
    fn start_receiver(self: &Arc<Self>, env_id: String, session: Arc<dyn Session>) {
        let weak: Weak<Self> = Arc::downgrade(self);
        thread::spawn(move || {
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
    fn send_peers(&self, env_id: &str, session: &Arc<dyn Session>) {
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
        let peers = self
            .ctx
            .state
            .read_json(&format!("team/{env_id}/peers.json"), json!({}))
            .unwrap_or(json!({}));
        if session
            .send(&json!({"type":"PEERS","peers":peers}))
            .is_err()
        {
            self.drop_session(env_id, &fp, Some(session));
        }
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
            self.refold(env_id)?;
            if let Some(env) = self
                .envs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_mut(env_id)
            {
                env.last_known_vector = CommitStore::new(self.ctx.state, env_id).vector()?;
            }
            self.broadcast(
                env_id,
                &json!({"type":"COMMIT","commit":commit.to_dict()}),
                Some(&session.peer().fingerprint()),
            );
        }
        Ok(())
    }
    fn relaxed_document(&self, env_id: &str) -> Result<Value> {
        let mut facts = {
            self.envs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(env_id)
                .ok_or_else(|| Error::invalid_input("team_env_unknown"))?
                .facts
                .clone()
        };
        facts.removed_members.clear();
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
        if self.validate_incoming_fact(env_id, &fact)? {
            self.store_fact(env_id, &fact)?;
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
        let Some(record) = self.known_record(env_id, &fact.author) else {
            return Ok(());
        };
        if !verify_fact(&fact, &record) {
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
            self.store_fact(env_id, &fact)?;
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
        let _lock = self.ctx.state.lock()?;
        let path = format!("team/{env_id}/rotation_flags.json");
        let mut flags = self.ctx.state.read_json(&path, json!({}))?;
        let now = iso(Some((self.ctx.clock)()));
        for id in target["secret_ids_mandatory"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            flags[id] = json!({"reason":"rotation_required","flagged_at":now});
        }
        for id in target["secret_ids_recommended"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if flags[id]["reason"] != "rotation_required" {
                flags[id] = json!({"reason":"rotation_recommended","flagged_at":now});
            }
        }
        self.ctx.state.write_json(&path, &flags)
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
        self.store_fact(env_id, &fact)?;
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
                self.broadcast(
                    env_id,
                    &json!({"type":"COMMIT","commit":commit.to_dict()}),
                    None,
                );
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
                self.broadcast(
                    env_id,
                    &json!({"type":"COMMIT","commit":commit.to_dict()}),
                    None,
                );
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
            let Ok(value) = serde_json::from_str::<Value>(line) else {
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
            {
                let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(env) = envs.get_mut(env_id) {
                    env.fact_hashes.insert(fact.hash()?);
                    apply_fact(&mut env.facts, &fact);
                    if fact.kind == "member_removed" {
                        if let Some(fp) = fact.target["fingerprint"].as_str() {
                            env.removal_authors
                                .entry(fp.into())
                                .or_default()
                                .insert(fact.author.clone());
                        }
                    }
                }
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
        if let Some(this) = attached(&self.ctx) {
            this.start_receiver(env_id.into(), session.clone());
        }
        self.send_vector(env_id, &session);
        self.send_peers(env_id, &session);
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
