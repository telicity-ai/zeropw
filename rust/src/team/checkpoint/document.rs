//! Shape checks precede complete canonical equality. Opaque legacy values are
//! preserved; existing pure operation/policy validators define known semantics.
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::admission::{SemanticError as E, device_copy};
use super::manifest::{canonical, field, text};
use crate::team::{commit, fold, identity::DeviceRecord, sync};

type Result<T> = std::result::Result<T, E>;

#[derive(Default)]
pub(super) struct GenerationReferences {
    pub referenced: BTreeSet<String>,
    pub required: BTreeSet<String>,
}

fn valid_op(op: Value) -> Result<()> {
    commit::validate_op(&op).map_err(|_| E::SemanticMismatch)
}
fn object(value: &Value) -> Result<&serde_json::Map<String, Value>> {
    value.as_object().ok_or(E::SemanticMismatch)
}

pub(super) fn validate(
    document: &Value,
    order: &Value,
    env: &str,
    devices: &BTreeMap<String, DeviceRecord>,
    final_image: bool,
) -> Result<GenerationReferences> {
    validate_known(document, order, env, devices, final_image).map_err(|e| match e {
        E::AuthorityUnproven => E::AuthorityUnproven,
        _ => E::SemanticMismatch,
    })
}

fn validate_known(
    document: &Value,
    order: &Value,
    env: &str,
    devices: &BTreeMap<String, DeviceRecord>,
    final_image: bool,
) -> Result<GenerationReferences> {
    let doc = object(document)?;
    if doc.contains_key("_version_order")
        || text(document, "format")? != fold::ENV_FORMAT
        || text(document, "env_id")? != env
    {
        return Err(E::SemanticMismatch);
    }
    let members = object(field(document, "members")?)?;
    let owner = text(document, "owner")?;
    for (fp, member) in members {
        object(member)?;
        if device_copy(field(member, "device")?, devices)? != *fp {
            return Err(E::AuthorityUnproven);
        }
        if !matches!(text(member, "status")?, "active" | "removed") {
            return Err(E::SemanticMismatch);
        }
        valid_op(
            json!({"op":"member.add","device":field(member,"device")?,"name":field(member,"name")?,"role":field(member,"role")?,"wraps":{}}),
        )?;
    }
    if !sync::is_admin(document, owner) || document["members"][owner]["role"] != "admin" {
        return Err(E::AuthorityUnproven);
    }
    let dek = field(document, "dek")?;
    object(dek)?;
    let generations = object(field(dek, "generations")?)?;
    let current = text(dek, "current")?;
    if !generations.contains_key(current) {
        return Err(E::SemanticMismatch);
    }
    let mut refs = GenerationReferences::default();
    for (generation, entry) in generations {
        object(entry)?;
        let wraps = field(entry, "wraps")?;
        for fp in object(wraps)?.keys() {
            if !devices.contains_key(fp) {
                return Err(E::AuthorityUnproven);
            }
        }
        let mut op = json!({"op":"dek.rotate","generation_id":generation,"wraps":wraps});
        if let Some(hash) = entry.get("removal_fact_hash") {
            op["removal_fact_hash"] = hash.clone();
        }
        valid_op(op)?;
        refs.referenced.insert(generation.clone());
    }
    // Keep the entire arrays, including duplicates and absent historical IDs.
    // The shared derivation helper deliberately uses the last occurrence.
    for (sid, entries) in object(order)? {
        valid_op(json!({"op":"secret.activate","secret_id":sid,"version_id":"0000000000000000"}))?;
        for vid in entries.as_array().ok_or(E::SemanticMismatch)? {
            if !vid.is_string() {
                return Err(E::SemanticMismatch);
            }
            valid_op(json!({"op":"secret.activate","secret_id":sid,"version_id":vid}))?;
        }
    }
    let indices = fold::version_index_from_order(order).map_err(|_| E::SemanticMismatch)?;
    let secrets = object(field(document, "secrets")?)?;
    for (sid, secret) in secrets {
        object(secret)?;
        if !crate::vault::SECRET_KINDS.contains(&text(secret, "kind")?) {
            return Err(E::SemanticMismatch);
        }
        valid_op(json!({"op":"secret.activate","secret_id":sid,"version_id":"0000000000000000"}))?;
        let deleted = match secret.get("deleted") {
            None => false,
            Some(Value::Bool(v)) => *v,
            _ => return Err(E::SemanticMismatch),
        };
        let active = field(secret, "active_version")?;
        if !active.is_null() && !active.is_string() {
            return Err(E::SemanticMismatch);
        }
        let mut active_count = 0;
        for (vid, version) in object(field(secret, "versions")?)? {
            object(version)?;
            let status = text(version, "status")?;
            if !matches!(status, "staged" | "active" | "retired" | "revoked") {
                return Err(E::SemanticMismatch);
            }
            let generation = text(version, "generation")?;
            if !generations.contains_key(generation)
                || indices.get(sid).and_then(|m| m.get(vid)).is_none()
            {
                return Err(E::SemanticMismatch);
            }
            object(field(version, "public")?)?;
            // Reuse identity/kind/ciphertext validation without reconstructing
            // or reparsing an opaque nested public object at depth zero.
            valid_op(
                json!({"op":"secret.put_version","secret_id":sid,"version_id":vid,"kind":field(secret,"kind")?,"generation_id":generation,
                "ciphertext":{"nonce":field(version,"nonce")?,"ciphertext":field(version,"ciphertext")?}}),
            )?;
            if status == "active" {
                active_count += 1;
                if active.as_str() != Some(vid.as_str()) {
                    return Err(E::SemanticMismatch);
                }
            }
            if final_image && deleted && status != "revoked" {
                return Err(E::SemanticMismatch);
            }
            if !deleted && matches!(status, "active" | "staged") {
                refs.required.insert(generation.into());
            }
        }
        if (active.is_null() && active_count != 0)
            || (!active.is_null() && active_count != 1)
            || (final_image && deleted && !active.is_null())
        {
            return Err(E::SemanticMismatch);
        }
    }
    for (id, connection) in object(field(document, "connections")?)? {
        let entry = object(connection)?;
        if text(connection, "id")? != id
            || !matches!(text(connection, "status")?, "active" | "disabled")
            || !field(connection, "created_at")?.is_string()
            || !field(connection, "updated_at")?.is_string()
        {
            return Err(E::SemanticMismatch);
        }
        valid_op(json!({"op":"connection.disable","id":id}))?;
        let identity = json!({"op":"connection.create","id":id});
        if commit::creates_misnamed_connection(object(&identity)?) {
            return Err(E::SemanticMismatch);
        }
        let built = commit::build_connection_fields(entry).map_err(|_| E::SemanticMismatch)?;
        for (key, value) in built {
            if canonical(field(connection, &key)?)? != canonical(&value)? {
                return Err(E::SemanticMismatch);
            }
        }
        let sid = text(connection, "secret_id")?;
        let secret = secrets.get(sid).ok_or(E::SemanticMismatch)?;
        let pin = field(connection, "secret_version")?;
        if !pin.is_null() {
            let vid = pin.as_str().ok_or(E::SemanticMismatch)?;
            if secret["versions"].get(vid).is_none()
                || indices.get(sid).and_then(|m| m.get(vid)).is_none()
            {
                return Err(E::SemanticMismatch);
            }
        }
    }
    let settings = field(document, "settings")?;
    object(settings)?;
    valid_op(
        json!({"op":"settings.update","sync_interval_seconds":field(settings,"sync_interval_seconds")?}),
    )?;
    Ok(refs)
}

pub(super) fn check_puts(commits: &[crate::team::commit::Commit], document: &Value) -> Result<()> {
    let mut used = BTreeSet::new();
    for c in commits {
        for op in c.ops.iter().filter(|op| op["op"] == "secret.put_version") {
            let sid = text(op, "secret_id")?;
            let vid = text(op, "version_id")?;
            if !used.insert((sid.to_owned(), vid.to_owned())) {
                return Err(E::ScopeUnsupported);
            }
            let version = &document["secrets"][sid]["versions"][vid];
            if document["secrets"][sid]["kind"] != op["kind"] {
                return Err(E::SemanticMismatch);
            }
            for (result, source) in [
                ("generation", &op["generation_id"]),
                ("nonce", &op["ciphertext"]["nonce"]),
                ("ciphertext", &op["ciphertext"]["ciphertext"]),
            ] {
                if canonical(&version[result])? != canonical(source)? {
                    return Err(E::SemanticMismatch);
                }
            }
            let empty = json!({});
            if canonical(&version["public"])? != canonical(op.get("public").unwrap_or(&empty))? {
                return Err(E::SemanticMismatch);
            }
        }
    }
    Ok(())
}
