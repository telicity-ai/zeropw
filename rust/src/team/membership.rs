//! Team invitation, membership and sharing, port of `zeropw/team/membership.py`.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use rand::RngCore;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::commit::{self, Commit, CommitStore, Hlc};
use super::envelope;
use super::fold::{self, FoldResult};
use super::identity::{DeviceKey, DeviceRecord};
use super::sync::{self, TeamSync};
use super::transport::{InviteProof, SessionClosed, Transport};
use crate::audit::RecordArgs;
use crate::context::Context;
use crate::errors::{Error, Result};
use crate::kms::WrappedKey;
use crate::pybase64;
use crate::pyjson::{self, DumpOptions};
use crate::secret::SecretBytes;
use crate::store::iso;

pub const INVITE_FORMAT: &str = "zeropw-team-invite-v1";
pub const DEFAULT_INVITE_TTL_SECONDS: i64 = 24 * 3600;
pub const MAX_INVITE_TTL_SECONDS: i64 = 30 * 24 * 3600;
pub const MAX_ADDRESSES: usize = 16;
pub const JOIN_TIMEOUT_SECONDS: f64 = 20.0;
const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn b32e(raw: &[u8]) -> String {
    let mut out = String::new();
    let (mut bits, mut held) = (0u32, 0u32);
    for byte in raw {
        bits = (bits << 8) | u32::from(*byte);
        held += 8;
        while held >= 5 {
            held -= 5;
            out.push(B32[((bits >> held) & 31) as usize] as char);
        }
    }
    if held > 0 {
        out.push(B32[((bits << (5 - held)) & 31) as usize] as char);
    }
    out.to_ascii_lowercase()
}
fn b32d(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let (mut bits, mut held) = (0u32, 0u32);
    for c in text.trim().bytes() {
        let c = c.to_ascii_uppercase();
        let Some(v) = B32.iter().position(|b| *b == c) else {
            return Err(Error::invalid_input("invite_malformed"));
        };
        bits = (bits << 5) | v as u32;
        held += 5;
        if held >= 8 {
            held -= 8;
            out.push((bits >> held) as u8);
        }
    }
    if held > 0 && (bits & ((1 << held) - 1)) != 0 {
        return Err(Error::invalid_input("invite_malformed"));
    }
    Ok(out)
}
fn token(n: usize) -> String {
    let mut data = vec![0; n];
    rand::rngs::OsRng.fill_bytes(&mut data);
    hex::encode(data)
}
fn audit(ctx: &Context, event: &str, env_id: &str, extra: Vec<(&'static str, Value)>) {
    let mut fields = vec![("env_id", json!(env_id))];
    fields.extend(extra);
    let _ = ctx.audit.record(
        event,
        RecordArgs {
            caller: Some("admin"),
            result: Some("ok"),
            extra: fields,
            ..Default::default()
        },
    );
}

pub fn load_environment(ctx: &Context, env_id: &str) -> Result<FoldResult> {
    let store = CommitStore::new(ctx.state, env_id);
    let (facts, _, _) = sync::load_facts(ctx.state, env_id)?;
    fold::fold_with_snapshot(
        env_id,
        store.all_commits()?,
        ctx.state,
        Some(&facts),
        Some(ctx.audit),
    )
}
fn refold_and_derive(ctx: &Context, env_id: &str) -> Result<FoldResult> {
    let result = load_environment(ctx, env_id)?;
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms)?;
    let (project, environment) = sync::env_project_environment(ctx.state, env_id)?;
    fold::derive_local(
        &result,
        ctx.state,
        &ctx.policy,
        Some(ctx.audit),
        Some(&device),
        Some(ctx.kms),
        project.as_deref(),
        environment.as_deref(),
    )?;
    Ok(result)
}

pub fn author_commit(
    ctx: &Context,
    team: Option<&TeamSync>,
    env_id: &str,
    ops: Vec<Value>,
) -> Result<Commit> {
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms)?;
    let store = CommitStore::new(ctx.state, env_id);
    let _lock = ctx.state.lock()?;
    let mut hlc = Hlc::new(0, 0);
    let seq = store.last_seq(&device.fingerprint()?)? + 1;
    if seq > 1
        && let Some(previous) = store.get(&device.fingerprint()?, seq - 1)?
    {
        hlc.observe(&previous.hlc)?;
    }
    let commit = commit::sign_commit(&device, env_id, seq, &hlc.tick(None), &store.vector()?, ops)?;
    let outcome = if let Some(team) = team {
        team.submit_commit(env_id, &commit)?
    } else {
        commit::receive_commit(&store, &commit, commit::now_ms(), Some(ctx.audit))?
    };
    if outcome != "accepted" {
        return Err(Error::state(format!("team_local_commit_{outcome}")));
    }
    if team.is_none() {
        refold_and_derive(ctx, env_id)?;
    }
    Ok(commit)
}
pub fn author_fact(
    ctx: &Context,
    team: Option<&TeamSync>,
    env_id: &str,
    kind: &str,
    target: Value,
) -> Result<Value> {
    if let Some(team) = team {
        return team.publish_fact(env_id, kind, target);
    }
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms)?;
    let doc = load_environment(ctx, env_id)?.document;
    if !sync::fact_role_ok(&doc, kind, &device.fingerprint()?, &target) {
        return Err(Error::policy_denied("team_fact_not_authorized"));
    }
    let fact = sync::sign_fact(&device, env_id, kind, target, &Hlc::new(0, 0).tick(None))?;
    let _lock = ctx.state.lock()?;
    ctx.state.append_line(
        &format!("team/{env_id}/facts.jsonl"),
        &pyjson::dumps(&fact.to_dict(), DumpOptions::compact_sorted())?,
    )?;
    audit(ctx, "team_fact_apply", env_id, vec![("kind", json!(kind))]);
    refold_and_derive(ctx, env_id)?;
    Ok(fact.to_dict())
}

pub struct Invite {
    pub env_id: String,
    pub inviter: String,
    pub addresses: Vec<String>,
    pub invite_secret: SecretBytes,
    pub expires_at: String,
    pub role: String,
    pub name: String,
}
pub fn parse_invite(text: &str) -> Result<Invite> {
    let bytes = b32d(text)?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| Error::invalid_input("invite_malformed"))?;
    let bad = || Error::invalid_input("invite_malformed");
    if value["format"] != INVITE_FORMAT {
        return Err(bad());
    }
    let field = |key| value[key].as_str().map(str::to_owned).ok_or_else(bad);
    let env_id = field("env_id")?;
    if !commit::valid_env_id(&env_id) {
        return Err(bad());
    }
    let inviter = field("inviter")?;
    let addresses = value["addresses"]
        .as_array()
        .ok_or_else(bad)?
        .iter()
        .map(|v| v.as_str().map(str::to_owned).ok_or_else(bad))
        .collect::<Result<Vec<_>>>()?;
    let secret = pybase64::b64decode(&field("invite_secret")?).map_err(|_| bad())?;
    let expires_at = field("expires_at")?;
    let role = field("role")?;
    let name = field("name")?;
    if secret.len() != 32
        || !(role == "admin" || role == "user")
        || name.is_empty()
        || name.chars().count() > 200
    {
        return Err(bad());
    }
    Ok(Invite {
        env_id,
        inviter,
        addresses,
        invite_secret: SecretBytes::new(secret),
        expires_at,
        role,
        name,
    })
}
pub fn create_invite(
    ctx: &Context,
    env_id: &str,
    role: &str,
    name: &str,
    ttl_seconds: i64,
    addresses: &[String],
) -> Result<String> {
    if role != "admin" && role != "user" {
        return Err(Error::invalid_input("invalid_role"));
    }
    if name.is_empty() || name.chars().count() > 200 {
        return Err(Error::invalid_input("invalid_member_name"));
    }
    if ttl_seconds <= 0 || ttl_seconds > MAX_INVITE_TTL_SECONDS {
        return Err(Error::invalid_input("invalid_ttl"));
    }
    if addresses.len() > MAX_ADDRESSES {
        return Err(Error::invalid_input("too_many_addresses"));
    }
    for address in addresses {
        if address.is_empty() || address.chars().count() > 128 {
            return Err(Error::invalid_input("invalid_address"));
        }
    }
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms)?;
    let doc = load_environment(ctx, env_id)?.document;
    if doc["owner"].is_null() {
        return Err(Error::not_found("team_env_not_found"));
    }
    if !sync::is_admin(&doc, &device.fingerprint()?) {
        return Err(Error::policy_denied("not_admin"));
    }
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let id = hex::encode(&Sha256::digest(secret)[..16]);
    let expires = (ctx.clock)() + ttl_seconds as f64;
    let payload = json!({"format":INVITE_FORMAT,"env_id":env_id,"inviter":device.fingerprint()?,"addresses":addresses,"invite_secret":pybase64::b64encode(&secret),"expires_at":iso(Some(expires)),"role":role,"name":name});
    let invite = b32e(&pyjson::dumps(&payload, DumpOptions::compact_sorted())?.into_bytes());
    let _lock = ctx.state.lock()?;
    let path = format!("team/{env_id}/invites.json");
    let mut invites = ctx.state.read_json(&path, json!({}))?;
    invites[&id] = json!({"wrapped_secret":ctx.kms.wrap(&secret)?.to_dict(),"role":role,"name":name,"expires_at":expires,"used":false});
    ctx.state.write_json(&path, &invites)?;
    audit(
        ctx,
        "team_invite_create",
        env_id,
        vec![("role", json!(role))],
    );
    Ok(invite)
}
pub fn consume_invite(
    ctx: &Context,
    env_id: &str,
    transcript_hash: &[u8],
    proof: &[u8],
) -> Result<Option<(String, String)>> {
    if proof.is_empty() {
        return Ok(None);
    }
    let _lock = ctx.state.lock()?;
    let path = format!("team/{env_id}/invites.json");
    let mut invites = ctx.state.read_json(&path, json!({}))?;
    let Some(entries) = invites.as_object() else {
        return Ok(None);
    };
    let mut matched = None;
    for (id, entry) in entries {
        if entry["used"] == true {
            continue;
        }
        let Some(expires) = entry["expires_at"].as_f64() else {
            continue;
        };
        if (ctx.clock)() > expires {
            continue;
        }
        let Ok(wrapped) = WrappedKey::from_dict(&entry["wrapped_secret"]) else {
            continue;
        };
        let Ok(secret) = ctx.kms.unwrap(&wrapped) else {
            continue;
        };
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.expose())
            .map_err(|_| Error::state("invite_malformed"))?;
        mac.update(transcript_hash);
        let expected = mac.finalize().into_bytes();
        if bool::from(expected.ct_eq(proof)) {
            matched = Some((
                id.clone(),
                entry["role"].as_str().unwrap_or("").to_owned(),
                entry["name"].as_str().unwrap_or("").to_owned(),
            ));
            break;
        }
    }
    if let Some((id, role, name)) = matched {
        invites[&id]["used"] = json!(true);
        ctx.state.write_json(&path, &invites)?;
        return Ok(Some((role, name)));
    }
    Ok(None)
}

pub fn join(
    ctx: &Context,
    invite_text: &str,
    transport: &dyn Transport,
    team: &Arc<TeamSync>,
    project: Option<&str>,
    environment: Option<&str>,
    timeout: f64,
) -> Result<Value> {
    let invite = parse_invite(invite_text)?;
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms)?;
    let project = project
        .map(str::to_owned)
        .unwrap_or_else(|| format!("team-{}", &invite.inviter[..invite.inviter.len().min(8)]));
    let environment = environment.unwrap_or("shared");
    sync::write_env_mapping(ctx.state, &invite.env_id, &project, environment)?;
    team.register_env(&invite.env_id)?;
    let secret = invite.invite_secret.clone();
    let proof: InviteProof = Arc::new(move |hash| {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.expose()).expect("valid HMAC key");
        mac.update(hash);
        mac.finalize().into_bytes().to_vec()
    });
    let mut session = None;
    let mut address = String::new();
    let mut last_reason = "team_join_no_address";
    for candidate in &invite.addresses {
        match transport.dial(candidate, &invite.env_id, Some(proof.clone())) {
            Ok(s) => {
                session = Some(s);
                address = candidate.clone();
                break;
            }
            Err(SessionClosed(reason)) => last_reason = reason,
        }
    }
    let session =
        session.ok_or_else(|| Error::state("team_join_failed").with_detail(last_reason))?;
    if session.peer().fingerprint() != invite.inviter {
        session.close();
        return Err(Error::state("team_join_wrong_peer"));
    }
    team.adopt_outbound_session(&invite.env_id, session, &address);
    let deadline = Instant::now() + Duration::from_secs_f64(timeout);
    while Instant::now() < deadline {
        if team.is_active_member(&invite.env_id, &device.fingerprint()?) {
            audit(
                ctx,
                "team_join",
                &invite.env_id,
                vec![("fingerprint", json!(invite.inviter))],
            );
            return Ok(
                json!({"env_id":invite.env_id,"self_fingerprint":device.fingerprint()?,"inviter_fingerprint":invite.inviter,"project":project,"environment":environment}),
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(Error::state("team_join_timeout"))
}

pub fn remove_member(
    ctx: &Context,
    team: Option<&TeamSync>,
    env_id: &str,
    fingerprint: &str,
) -> Result<Value> {
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms)?;
    let doc = if let Some(team) = team {
        team.document(env_id)?
    } else {
        load_environment(ctx, env_id)?.document
    };
    if doc["owner"].is_null() {
        return Err(Error::not_found("team_env_not_found"));
    }
    let caller = device.fingerprint()?;
    let is_admin = sync::is_admin(&doc, &caller);
    let fact = author_fact(
        ctx,
        team,
        env_id,
        "member_removed",
        json!({"fingerprint":fingerprint}),
    )?;
    let mut rotated = None;
    if is_admin && caller != fingerprint {
        rotated = Some(rotate_dek(ctx, team, env_id)?);
        flag_rotation_recommended(ctx, team, env_id)?;
    }
    audit(
        ctx,
        "team_member_remove",
        env_id,
        vec![("fingerprint", json!(fingerprint))],
    );
    Ok(
        json!({"env_id":env_id,"fingerprint":fingerprint,"fact":fact,"dek_rotated":rotated.is_some(),"new_generation":rotated}),
    )
}
fn rotate_dek(ctx: &Context, team: Option<&TeamSync>, env_id: &str) -> Result<String> {
    let doc = if let Some(team) = team {
        team.document(env_id)?
    } else {
        load_environment(ctx, env_id)?.document
    };
    let mut dek = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut dek);
    let generation = token(16);
    let mut wraps = Map::new();
    if let Some(members) = doc["members"].as_object() {
        for (fp, member) in members {
            if member["status"] != "active" {
                continue;
            }
            let Ok(record) = DeviceRecord::from_dict(&member["device"]) else {
                continue;
            };
            wraps.insert(
                fp.clone(),
                envelope::wrap_dek(&dek, env_id, &generation, &record)?,
            );
        }
    }
    author_commit(
        ctx,
        team,
        env_id,
        vec![json!({"op":"dek.rotate","generation_id":generation,"wraps":wraps})],
    )?;
    audit(
        ctx,
        "team_dek_rotate",
        env_id,
        vec![("count", json!(wraps.len()))],
    );
    Ok(generation)
}
fn flag_rotation_recommended(ctx: &Context, team: Option<&TeamSync>, env_id: &str) -> Result<()> {
    let doc = if let Some(team) = team {
        team.document(env_id)?
    } else {
        load_environment(ctx, env_id)?.document
    };
    let path = format!("team/{env_id}/rotation_flags.json");
    let _lock = ctx.state.lock()?;
    let mut flags = ctx.state.read_json(&path, json!({}))?;
    let count = doc["secrets"].as_object().map_or(0, Map::len);
    if let Some(secrets) = doc["secrets"].as_object() {
        for sid in secrets.keys() {
            flags[sid] = json!({"reason":"member_removed_rotation_recommended","flagged_at":iso(Some((ctx.clock)()))});
        }
    }
    ctx.state.write_json(&path, &flags)?;
    let _ = ctx.audit.record(
        "team_dek_rotate",
        RecordArgs {
            caller: Some("admin"),
            result: Some("ok"),
            reason: Some("member_removed_rotation_recommended"),
            extra: vec![("env_id", json!(env_id)), ("count", json!(count))],
            ..Default::default()
        },
    );
    Ok(())
}

pub fn share_environment(
    ctx: &Context,
    team: Option<&TeamSync>,
    project: &str,
    environment: &str,
    owner_name: &str,
    admin_passphrase: &str,
) -> Result<Value> {
    ctx.admin.verify(admin_passphrase, None)?;
    ctx.projects.require_environment(project, environment)?;
    let mappings = sync::read_env_mapping(ctx.state)?;
    if mappings.as_object().is_some_and(|m| {
        m.values()
            .any(|e| e["project"] == project && e["environment"] == environment)
    }) {
        return Err(Error::invalid_input("team_env_already_shared"));
    }
    let vault_doc = ctx.state.read_json(crate::vault::VAULT_DOC, json!({}))?;
    let secrets_doc = vault_doc["secrets"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    if secrets_doc.values().any(|entry| {
        entry["project"] == project
            && entry["environment"] == environment
            && !entry["shared_env"].is_null()
    }) {
        return Err(Error::invalid_input("team_env_already_shared"));
    }
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms)?;
    let fp = device.fingerprint()?;
    let env_id = commit::new_env_id(&fp)?;
    let generation = token(16);
    let mut dek = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut dek);
    let mut wraps = Map::new();
    wraps.insert(
        fp.clone(),
        envelope::wrap_dek(&dek, &env_id, &generation, &device.record()?)?,
    );
    let init = json!({"op":"env.init","owner_device":device.record()?.to_dict(),"owner_name":owner_name,"generation_id":generation,"wraps":wraps});
    let mut shareable = Map::new();
    for (sid, entry) in &secrets_doc {
        if entry["project"] != project
            || entry["environment"] != environment
            || !entry["shared_env"].is_null()
        {
            continue;
        }
        if entry["versions"].as_object().is_some_and(|m| {
            m.values()
                .any(|v| v["status"] == "active" || v["status"] == "staged")
        }) {
            shareable.insert(sid.clone(), entry.clone());
        }
    }
    let mut version_ids: BTreeMap<String, BTreeMap<i64, String>> = BTreeMap::new();
    let mut secret_ops: Vec<Value> = Vec::new();
    for (sid, entry) in &shareable {
        let mut versions = entry["versions"]
            .as_object()
            .map(|m| m.iter().collect::<Vec<_>>())
            .unwrap_or_default();
        versions.sort_by_key(|(n, _)| n.parse::<i64>().unwrap_or(i64::MAX));
        for (number, v) in versions {
            if v["status"] != "active" && v["status"] != "staged" {
                continue;
            }
            let n = number
                .parse::<i64>()
                .map_err(|_| Error::state("state_corrupt"))?;
            let value = ctx.vault.secret_for_trusted_use(sid, Some(n))?;
            let version_id = token(8);
            let ciphertext =
                envelope::encrypt_secret(&dek, &env_id, sid, &version_id, value.expose())?;
            secret_ops.push(json!({"op":"secret.put_version","secret_id":sid,"kind":entry["kind"],"generation_id":generation,"version_id":version_id,"ciphertext":ciphertext,"public":entry["versions"][number]["public"].as_object().cloned().unwrap_or_default()}));
            version_ids
                .entry(sid.clone())
                .or_default()
                .insert(n, version_id.clone());
            if entry["active_version"].as_i64() == Some(n) {
                secret_ops
                    .push(json!({"op":"secret.activate","secret_id":sid,"version_id":version_id}));
            }
        }
    }
    let connections = ctx.state.read_json(crate::policy::CONNECTIONS, json!({}))?;
    let mut connection_ops = Vec::new();
    let mut converted = HashSet::new();
    let mut not_shared = Vec::new();
    if let Some(entries) = connections.as_object() {
        for (cid, entry) in entries {
            if entry["project"] != project
                || entry["environment"] != environment
                || !entry["shared_env"].is_null()
            {
                continue;
            }
            let Some(sid) = entry["secret_id"].as_str() else {
                not_shared.push(json!({"connection":cid,"reason":"secret_not_shared"}));
                continue;
            };
            if !shareable.contains_key(sid) {
                not_shared.push(json!({"connection":cid,"reason":"secret_not_shared"}));
                continue;
            }
            let mut op = Map::new();
            op.insert("op".into(), json!("connection.create"));
            op.insert("id".into(), json!(cid));
            if let Some(fields) = entry.as_object() {
                for (k, v) in fields {
                    if [
                        "id",
                        "policy_version",
                        "status",
                        "created_at",
                        "updated_at",
                        "shared_env",
                    ]
                    .contains(&k.as_str())
                    {
                        continue;
                    }
                    let value = if k == "secret_version" && !v.is_null() {
                        v.as_i64()
                            .and_then(|n| version_ids.get(sid).and_then(|m| m.get(&n)))
                            .map_or(Value::Null, |id| json!(id))
                    } else {
                        v.clone()
                    };
                    op.insert(k.clone(), value);
                }
            }
            connection_ops.push(Value::Object(op));
            converted.insert(cid.clone());
        }
    }
    // The pure computation above precedes all retag and commit writes.
    let _lock = ctx.state.lock()?;
    if !shareable.is_empty() {
        let mut doc = ctx.state.read_json(crate::vault::VAULT_DOC, json!({}))?;
        for sid in shareable.keys() {
            doc["secrets"][sid]["shared_env"] = json!(env_id);
        }
        ctx.state.write_json(crate::vault::VAULT_DOC, &doc)?;
    }
    if !converted.is_empty() {
        let mut doc = ctx.state.read_json(crate::policy::CONNECTIONS, json!({}))?;
        for cid in &converted {
            doc[cid]["shared_env"] = json!(env_id);
        }
        ctx.state.write_json(crate::policy::CONNECTIONS, &doc)?;
        for cid in &converted {
            let mut updated = ctx.state.read_json(crate::policy::CONNECTIONS, json!({}))?;
            let version = updated[cid]["policy_version"].as_i64().unwrap_or(0) + 1;
            updated[cid]["policy_version"] = json!(version);
            ctx.state.write_json(crate::policy::CONNECTIONS, &updated)?;
            ctx.policy.reevaluate_grants(cid, version, true, None)?;
            ctx.policy.invalidate_approvals(
                |e| e.get("connection").and_then(Value::as_str) == Some(cid),
                "policy_changed",
            )?;
        }
    }
    if let Some(team) = team {
        team.register_env(&env_id)?;
    }
    author_commit(ctx, team, &env_id, vec![init])?;
    for op in secret_ops {
        author_commit(ctx, team, &env_id, vec![op])?;
    }
    for op in connection_ops {
        author_commit(ctx, team, &env_id, vec![op])?;
    }
    sync::write_env_mapping(ctx.state, &env_id, project, environment)?;
    audit(
        ctx,
        "team_share",
        &env_id,
        vec![
            ("project", json!(project)),
            ("environment", json!(environment)),
            ("count", json!(not_shared.len())),
        ],
    );
    Ok(json!({"env_id":env_id,"not_shared":not_shared}))
}
