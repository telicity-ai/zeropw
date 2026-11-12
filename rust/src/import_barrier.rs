//! Durable import primitives. New records have their own strict private paths;
//! legacy StateDir byte formats and single-file writer behavior are unchanged.
use crate::{
    errors::{Error, Result},
    pyjson::{self, DumpOptions},
    store::StateDir,
};
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path},
};

pub(crate) const INDEX: &str = "vault/personal_imports.json";
pub(crate) const BACKUP: &str = "vault/personal_bootstrap_backup.json";
pub(crate) const LOCAL_REMOVAL_DENIAL: &str = "local-removal-denial.json";
fn denial_witness_present(state: &StateDir, env: &str, leaf: &str) -> Result<bool> {
    let path = state.path.join(crate::team::bootstrap::path(env, leaf)?);
    Ok(
        !matches!(fs::symlink_metadata(path),Err(error) if error.kind()==std::io::ErrorKind::NotFound),
    )
}

pub(crate) fn coherent_path(name: &str) -> bool {
    name.starts_with("team/")
        || [
            crate::vault::VAULT_DOC,
            crate::policy::CONNECTIONS,
            crate::projects::DOC,
            crate::tombstone::PATH,
        ]
        .contains(&name)
}
pub(crate) fn require_path(state: &StateDir, name: &str) -> Result<()> {
    let mut parts = name.split('/');
    if parts.next() == Some("team")
        && let Some(env) = parts.next()
        && crate::team::commit::valid_env_id(env)
        && parts.next() != Some("bootstrap")
    {
        require_env(state, env)?;
    }
    Ok(())
}

fn private_json(state: &StateDir, name: &str, limit: u64) -> Result<Option<Value>> {
    let p = state.path.join(name);
    match fs::symlink_metadata(&p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(failed()),
        Ok(m) if m.len() > limit => return Err(failed()),
        Ok(_) => {}
    }
    private_relative(state, name)?;
    let bytes = fs::read(p).map_err(|_| failed())?;
    if bytes.len() as u64 > limit {
        return Err(failed());
    }
    Ok(Some(
        pyjson::loads(std::str::from_utf8(&bytes).map_err(|_| failed())?).map_err(|_| failed())?,
    ))
}
fn authentic(state: &StateDir, record: &Value, env: &str, domain: &str) -> bool {
    (|| -> Result<bool> {
        let Some(identity) = state.import_identity() else {
            return Ok(false);
        };
        let mut unsigned = record.clone();
        let sig = unsigned
            .as_object_mut()
            .ok_or_else(failed)?
            .remove("sig")
            .ok_or_else(failed)?;
        let sig = crate::pybase64::b64decode_strict(sig.as_str().ok_or_else(failed)?)
            .map_err(|_| failed())?;
        Ok(unsigned["env_id"] == env
            && unsigned["domain"] == domain
            && crate::crypto::ed25519::verify(
                &identity.sign_pub,
                &crate::team::bootstrap::bytes(&unsigned)?,
                &sig,
            ))
    })()
    .unwrap_or(false)
}

pub(crate) fn index(state: &StateDir) -> Result<Value> {
    let loaded = private_json(state, INDEX, 1024 * 1024);
    let damaged = loaded.as_ref().is_err()
        || loaded
            .as_ref()
            .ok()
            .and_then(|v| v.as_ref())
            .is_some_and(|v| !v.is_object());
    let mut value = loaded
        .ok()
        .flatten()
        .filter(Value::is_object)
        .unwrap_or_else(|| serde_json::json!({}));
    if let Some(records) = value.as_object_mut() {
        for record in records.values_mut() {
            if !record.is_object() {
                *record = serde_json::json!({"state":"recovery_required"});
            }
        }
    }
    let mut witnessed = false;
    // A journal can only add a denial here. Neither a copied receipt nor a
    // damaged global index can publish an environment through this fallback.
    for env in crate::team::local_env_ids(state)? {
        let name = crate::team::bootstrap::path(&env, "journal.json")?;
        if matches!(fs::symlink_metadata(state.path.join(&name)),Err(e) if e.kind()==std::io::ErrorKind::NotFound)
        {
            continue;
        }
        witnessed = true;
        let journal = private_json(state, &name, 64 * 1024 * 1024)
            .ok()
            .flatten()
            .unwrap_or(Value::Null);
        let valid = authentic(state, &journal, &env, "zeropw-personal-import-journal-v1");
        if valid && journal["state"] == "PREPARED" && value.get(&env).is_none() && !damaged {
            continue;
        }
        if value.get(&env).is_none() {
            value[&env] = journal["visibility"]
                .as_object()
                .map(|_| journal["visibility"].clone())
                .unwrap_or_else(|| serde_json::json!({}));
            value[&env]["state"] = serde_json::json!("recovery_required");
        }
        if !valid || damaged {
            value[&env]["state"] = serde_json::json!("recovery_required");
        }
    }
    if damaged && !witnessed {
        return Err(failed());
    }
    if value
        .as_object()
        .is_none_or(|v| v.keys().any(|env| !crate::team::commit::valid_env_id(env)))
    {
        return Err(failed());
    }
    for (env, record) in value.as_object_mut().into_iter().flatten() {
        let mut valid = authentic(state, record, env, "zeropw-personal-import-visibility-v1")
            && matches!(record["state"].as_str(), Some("installing" | "committed"));
        if valid && record["state"] == "committed" {
            valid = (|| -> Result<bool> {
                let receipt = private_json(
                    state,
                    &crate::team::bootstrap::path(env, "receipt.json")?,
                    65_536,
                )?
                .ok_or_else(failed)?;
                Ok(
                    crate::team::bootstrap::digest(&receipt)? == record["receipt_sha256"]
                        && receipt["epoch"] == record["epoch"]
                        && immutable(state, env, record).is_ok(),
                )
            })()
            .unwrap_or(false);
        }
        if !valid {
            record["state"] = serde_json::json!("recovery_required");
        }
        if fs::symlink_metadata(
            state
                .path
                .join(crate::team::bootstrap::path(env, "history-required.json")?),
        )
        .is_ok()
        {
            record["state"] = serde_json::json!("recovery_required");
            record["reason"] = serde_json::json!("team_checkpoint_history_required");
        }
        if denial_witness_present(state, env, "member-removed.json")?
            || denial_witness_present(state, env, LOCAL_REMOVAL_DENIAL)?
        {
            record["local_member_removed"] = serde_json::json!(true);
        }
        if record["state"] != "committed" || record["local_member_removed"] == true {
            // Shared entries carry their environment independently of the
            // journal. These are denial hints only, including for cached IDs.
            for (doc, field, nested) in [
                (crate::vault::VAULT_DOC, "secret_ids", true),
                (crate::policy::CONNECTIONS, "connection_ids", false),
            ] {
                let raw = private_json(state, doc, 64 * 1024 * 1024)?.unwrap_or(Value::Null);
                let entries = if nested { &raw["secrets"] } else { &raw };
                let mut ids = record[field].as_array().cloned().unwrap_or_default();
                for (id, entry) in entries.as_object().into_iter().flatten() {
                    if entry["shared_env"] == *env && !ids.contains(&serde_json::json!(id)) {
                        ids.push(serde_json::json!(id));
                    }
                }
                record[field] = Value::Array(ids);
            }
            if record["project"].as_str().is_none() || record["environment"].as_str().is_none() {
                let mapping =
                    private_json(state, crate::team::sync::ENVS_MAP_PATH, 64 * 1024 * 1024)?
                        .unwrap_or(Value::Null);
                record["project"] = mapping[env]["project"].clone();
                record["environment"] = mapping[env]["environment"].clone();
            }
        }
    }
    Ok(value)
}

pub(crate) fn require_env(state: &StateDir, env: &str) -> Result<()> {
    let all = index(state)?;
    if let Some(v) = all.get(env)
        && v["state"] != "committed"
    {
        return Err(Error::state(
            if v["reason"] == "team_checkpoint_history_required" {
                "team_checkpoint_history_required"
            } else {
                "team_bootstrap_recovery_required"
            },
        ));
    }
    Ok(())
}

/// Authenticated metadata remains available after removal, while derived
/// credential copies must not be recreated or rebound behind the deny view.
pub(crate) fn credential_projection_denied(state: &StateDir, env: &str) -> Result<bool> {
    if !state.locked_by_current_thread() {
        return Err(failed());
    }
    let imports = index(state)?;
    let Some(record) = imports.get(env) else {
        return Ok(false);
    };
    if record["state"] != "committed" {
        return Err(Error::state("team_bootstrap_recovery_required"));
    }
    Ok(record["local_member_removed"] == true)
}

/// A single file's published projection. High-level credential operations
/// retain StateLock across authorization and decryption/signing start.
pub(crate) fn visible(state: &StateDir, name: &str, mut value: Value) -> Result<Value> {
    if name == crate::team::identity::DEVICE_KEY_FILE {
        return Ok(value);
    }
    let all = index(state)?;
    for (env, record) in all.as_object().into_iter().flatten() {
        if record["state"] == "committed" && record["local_member_removed"] != true {
            continue;
        }
        if record["state"] == "committed"
            && ![crate::vault::VAULT_DOC, crate::policy::CONNECTIONS].contains(&name)
        {
            continue;
        }
        if name.starts_with(&format!("team/{env}/"))
            && !name.starts_with(&format!("team/{env}/bootstrap/"))
        {
            return Err(Error::state("team_bootstrap_recovery_required"));
        }
        if name == crate::vault::VAULT_DOC {
            if let Some(map) = value.get_mut("secrets").and_then(Value::as_object_mut) {
                map.retain(|id, entry| {
                    entry["shared_env"] != *env
                        && !record["secret_ids"]
                            .as_array()
                            .is_some_and(|ids| ids.contains(&serde_json::json!(id)))
                });
            }
        } else if name == crate::policy::CONNECTIONS {
            if let Some(map) = value.as_object_mut() {
                map.retain(|id, entry| {
                    entry["shared_env"] != *env
                        && !record["connection_ids"]
                            .as_array()
                            .is_some_and(|ids| ids.contains(&serde_json::json!(id)))
                });
            }
        } else if name == "team/envs.json" {
            if let Some(map) = value.as_object_mut() {
                map.remove(env);
            }
        } else if name == crate::projects::DOC
            && let (Some(project), Some(environment)) =
                (record["project"].as_str(), record["environment"].as_str())
            && let Some(entries) = value
                .get_mut(project)
                .and_then(|v| v.get_mut("environments"))
                .and_then(Value::as_array_mut)
        {
            entries.retain(|v| v != environment);
        }
    }
    Ok(value)
}

pub(crate) fn require_secret(state: &StateDir, id: &str) -> Result<()> {
    for (env, v) in index(state)?.as_object().into_iter().flatten() {
        if v["secret_ids"]
            .as_array()
            .is_some_and(|ids| ids.contains(&serde_json::json!(id)))
        {
            if v["local_member_removed"] == true {
                return Err(Error::policy_denied("team_member_removed"));
            }
            if v["state"] != "committed" {
                return Err(Error::state("team_bootstrap_recovery_required"));
            }
            immutable(state, env, v)?;
        }
    }
    Ok(())
}

pub(crate) fn require_connection(state: &StateDir, id: &str) -> Result<()> {
    for (env, v) in index(state)?.as_object().into_iter().flatten() {
        if v["connection_ids"]
            .as_array()
            .is_some_and(|ids| ids.contains(&serde_json::json!(id)))
        {
            if v["local_member_removed"] == true {
                return Err(Error::policy_denied("team_member_removed"));
            }
            if v["state"] != "committed" {
                return Err(Error::policy_denied("team_bootstrap_recovery_required"));
            }
            immutable(state, env, v)?;
        }
    }
    Ok(())
}

/// Called only after the existing fact-authority decision. This durable
/// deny-only witness prevents a cached imported credential from surviving
/// this receiver's removal, even if subsequent derivation needs history.
pub(crate) fn admitted_fact(state: &StateDir, fact: &crate::team::sync::Fact) -> Result<()> {
    if fact.kind == "member_removed"
        && state
            .import_identity()
            .is_some_and(|r| fact.target["fingerprint"] == r.fingerprint())
        && index(state)?.get(&fact.env_id).is_some()
    {
        let _lock = state.lock()?;
        json(
            state,
            &crate::team::bootstrap::path(&fact.env_id, "member-removed.json")?,
            &fact.to_dict(),
        )?;
    }
    Ok(())
}

pub(crate) fn immutable(state: &StateDir, env: &str, record: &Value) -> Result<()> {
    use sha2::{Digest, Sha256};
    let load = |leaf: &str, limit: u64| -> Result<Vec<u8>> {
        let name = crate::team::bootstrap::path(env, leaf)?;
        private_relative(state, &name)?;
        let p = state.path.join(name);
        private(&p, false)?;
        if fs::metadata(&p).map_err(|_| failed())?.len() > limit {
            return Err(failed());
        }
        fs::read(p).map_err(|_| failed())
    };
    let receipt = load("receipt.json", 65_536)?;
    let receipt = pyjson::loads(std::str::from_utf8(&receipt).map_err(|_| failed())?)
        .map_err(|_| failed())?;
    let manifest = load("provenance/manifest.json", 65_536)?;
    let manifest = pyjson::loads(std::str::from_utf8(&manifest).map_err(|_| failed())?)
        .map_err(|_| failed())?;
    let payload = load("provenance/payload.json", 16 * 1024 * 1024)?;
    if record["receipt_sha256"] != crate::team::bootstrap::digest(&receipt)?
        || record["manifest_hash"] != crate::team::bootstrap::digest(&manifest)?
        || receipt["payload_sha256"] != hex::encode(Sha256::digest(&payload))
    {
        return Err(Error::state("team_bootstrap_recovery_required"));
    }
    Ok(())
}

pub(crate) fn personal_manifest(state: &StateDir, env: &str) -> Result<Option<Value>> {
    let index = index(state)?;
    let Some(record) = index.get(env) else {
        return Ok(None);
    };
    require_env(state, env)?;
    immutable(state, env, record)?;
    let raw = fs::read(state.path.join(crate::team::bootstrap::path(
        env,
        "provenance/manifest.json",
    )?))
    .map_err(|_| failed())?;
    Ok(Some(
        pyjson::loads(std::str::from_utf8(&raw).map_err(|_| failed())?).map_err(|_| failed())?,
    ))
}

pub(crate) fn history_required(state: &StateDir, env: &str, evidence: &Value) -> Result<Error> {
    let _lock = state.lock()?;
    let hash = crate::team::bootstrap::digest(evidence)?;
    json(
        state,
        &crate::team::bootstrap::path(env, &format!("history-required/{hash}.json"))?,
        evidence,
    )?;
    json(
        state,
        &crate::team::bootstrap::path(env, "history-required.json")?,
        &serde_json::json!({"reason":"team_checkpoint_history_required","evidence_sha256":hash}),
    )?;
    Ok(Error::state("team_checkpoint_history_required"))
}

pub(crate) fn backup_provenance(state: &StateDir) -> Result<Value> {
    let mut environments = serde_json::Map::new();
    for (env, record) in index(state)?.as_object().into_iter().flatten() {
        require_env(state, env)?;
        immutable(state, env, record)?;
        let mut files = serde_json::Map::new();
        let mut total_bytes = 0u64;
        for leaf in [
            "provenance/manifest.json",
            "provenance/payload.json",
            "provenance/basis.json",
            "receipt.json",
            "member-removed.json",
            LOCAL_REMOVAL_DENIAL,
        ] {
            let name = crate::team::bootstrap::path(env, leaf)?;
            let p = state.path.join(&name);
            let metadata = match fs::symlink_metadata(&p) {
                Ok(metadata) => metadata,
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        && matches!(leaf, "member-removed.json" | LOCAL_REMOVAL_DENIAL) =>
                {
                    continue;
                }
                Err(_) => return Err(failed()),
            };
            let cap = if matches!(leaf, "provenance/manifest.json" | "receipt.json") {
                65_536
            } else {
                16_777_216
            };
            if metadata.len() > cap {
                return Err(failed());
            }
            total_bytes = total_bytes
                .checked_add(metadata.len())
                .filter(|n| *n <= 67_108_864)
                .ok_or_else(failed)?;
            private_relative(state, &name)?;
            private(&p, false)?;
            let data = fs::read(p).map_err(|_| failed())?;
            if data.len() as u64 > cap {
                return Err(failed());
            }
            files.insert(
                leaf.into(),
                serde_json::json!(crate::pybase64::b64encode(&data)),
            );
        }
        environments.insert(
            env.clone(),
            serde_json::json!({"visibility":record,"original_files_b64":files}),
        );
    }
    if environments.is_empty() {
        return Ok(Value::Null);
    }
    Ok(
        serde_json::json!({"v":1,"local_record":state.import_identity().ok_or_else(failed)?.to_dict(),"environments":environments}),
    )
}

/// A backup preserves the attestation as original bytes. It confers no
/// replacement-device or repair authority: restore can only retain an intact
/// same-device epoch already present locally, never install a copied receipt.
pub(crate) fn check_restore_provenance(state: &StateDir, archived: &Value) -> Result<()> {
    if archived.is_null() {
        return Ok(());
    }
    let current = backup_provenance(state)?;
    if archived["v"] != 1
        || archived["local_record"] != current["local_record"]
        || archived["environments"]
            .as_object()
            .is_none_or(|m| m.is_empty())
    {
        return Err(Error::state("team_bootstrap_existing_state_unsupported"));
    }
    for (env, record) in current["environments"].as_object().into_iter().flatten() {
        if record["visibility"]["local_member_removed"] == true
            && archived["environments"].get(env).is_none()
        {
            return Err(Error::state("team_bootstrap_recovery_required"));
        }
    }
    for (env, value) in archived["environments"].as_object().into_iter().flatten() {
        if current["environments"].get(env) != Some(value) {
            return Err(Error::state("team_bootstrap_recovery_required"));
        }
    }
    Ok(())
}

/// Ordinary read/modify/write callers see a filtered view. Preserve reserved
/// unpublished entries when they save an unrelated edit, and refuse attempts
/// to write a reserved identity rather than overwriting the import projection.
pub(crate) fn preserve_hidden(state: &StateDir, name: &str, value: &Value) -> Result<Value> {
    let all = index(state)?;
    let mut result = value.clone();
    if !all
        .as_object()
        .into_iter()
        .flatten()
        .any(|(_, v)| v["state"] != "committed" || v["local_member_removed"] == true)
        || ![
            crate::vault::VAULT_DOC,
            crate::policy::CONNECTIONS,
            "team/envs.json",
            crate::projects::DOC,
        ]
        .contains(&name)
    {
        return Ok(result);
    }
    let target = state.path.join(name);
    let raw = if target.exists() {
        let b = fs::read(target).map_err(|_| failed())?;
        pyjson::loads(std::str::from_utf8(&b).map_err(|_| failed())?).map_err(|_| failed())?
    } else {
        Value::Null
    };
    for (env, rec) in all.as_object().into_iter().flatten() {
        if rec["state"] == "committed" && rec["local_member_removed"] != true {
            continue;
        }
        if name == "team/envs.json" {
            if result.get(env).is_some_and(|v| raw.get(env) != Some(v)) {
                return Err(Error::state("team_bootstrap_recovery_required"));
            }
            if let Some(v) = raw.get(env) {
                result
                    .as_object_mut()
                    .ok_or_else(failed)?
                    .insert(env.clone(), v.clone());
            }
            continue;
        }
        if name == crate::projects::DOC {
            let (Some(project), Some(environment)) =
                (rec["project"].as_str(), rec["environment"].as_str())
            else {
                continue;
            };
            if result[project]["environments"]
                .as_array()
                .is_some_and(|e| e.contains(&serde_json::json!(environment)))
                && !raw[project]["environments"]
                    .as_array()
                    .is_some_and(|e| e.contains(&serde_json::json!(environment)))
            {
                return Err(Error::state("team_bootstrap_recovery_required"));
            }
            if let Some(p) = raw.get(project)
                && p["environments"]
                    .as_array()
                    .is_some_and(|e| e.contains(&serde_json::json!(environment)))
            {
                let target = result
                    .as_object_mut()
                    .ok_or_else(failed)?
                    .entry(project)
                    .or_insert_with(|| p.clone());
                let entries = target
                    .get_mut("environments")
                    .and_then(Value::as_array_mut)
                    .ok_or_else(failed)?;
                if !entries.contains(&serde_json::json!(environment)) {
                    entries.push(serde_json::json!(environment));
                }
            }
            continue;
        }
        let (ids, nested) = if name == crate::vault::VAULT_DOC {
            (&rec["secret_ids"], true)
        } else {
            (&rec["connection_ids"], false)
        };
        let source = if nested { &raw["secrets"] } else { &raw };
        let destination = if nested {
            result.get_mut("secrets")
        } else {
            Some(&mut result)
        }
        .and_then(Value::as_object_mut)
        .ok_or_else(failed)?;
        for id in ids
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if destination
                .get(id)
                .is_some_and(|v| source.get(id) != Some(v))
            {
                return Err(Error::state("team_bootstrap_recovery_required"));
            }
            if let Some(v) = source.get(id) {
                destination.insert(id.to_owned(), v.clone());
            }
        }
    }
    Ok(result)
}

fn failed() -> Error {
    Error::state("team_bootstrap_storage_failed")
}
macro_rules! fault_edge {
    ($state:expr,$name:expr,$point:literal) => {{
        #[cfg(test)]
        {
            testing::hit($state, $name, $point)?;
        }
    }};
}
fn private(path: &Path, dir: bool) -> Result<()> {
    let m = fs::symlink_metadata(path).map_err(|_| failed())?;
    if (if dir { !m.is_dir() } else { !m.is_file() })
        || m.uid() != nix::unistd::geteuid().as_raw()
        || m.permissions().mode() & 0o777 != if dir { 0o700 } else { 0o600 }
        || (!dir && m.nlink() != 1)
    {
        return Err(failed());
    }
    #[cfg(target_os = "macos")]
    {
        // Refuse extended ACLs, including inherited ACLs. The trusted system
        // utility is fixed; no peer data selects a program or shell command.
        let out = std::process::Command::new("/bin/ls")
            .args(["-lde", "--"])
            .arg(path)
            .output()
            .map_err(|_| failed())?;
        if !out.status.success()
            || out
                .stdout
                .split(|b| *b == b'\n')
                .skip(1)
                .any(|line| !line.is_empty())
        {
            return Err(failed());
        }
    }
    Ok(())
}

pub(crate) fn private_relative(state: &StateDir, name: &str) -> Result<()> {
    let relative = Path::new(name);
    if relative
        .components()
        .any(|p| !matches!(p, Component::Normal(_)))
    {
        return Err(failed());
    }
    private(&state.path, true)?;
    let mut current = state.path.clone();
    let parts = relative.components().collect::<Vec<_>>();
    for (index, part) in parts.iter().enumerate() {
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(_) => private(&current, index + 1 < parts.len())?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(failed()),
        }
    }
    Ok(())
}

pub(crate) fn write(state: &StateDir, name: &str, data: &[u8]) -> Result<()> {
    if !state.locked_by_current_thread() {
        return Err(failed());
    }
    let relative = Path::new(name);
    if relative
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(failed());
    }
    private(&state.path, true)?;
    let parent = relative.parent().ok_or_else(failed)?;
    let mut current = state.path.clone();
    for component in parent.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(_) => private(&current, true)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fault_edge!(state, name, "directory-create-before");
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&current)
                    .map_err(|_| failed())?;
                fault_edge!(state, name, "directory-create-after");
                private(&current, true)?;
                fault_edge!(state, name, "ancestor-fsync-before");
                File::open(current.parent().ok_or_else(failed)?)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| failed())?;
                fault_edge!(state, name, "ancestor-fsync-after");
            }
            Err(_) => return Err(failed()),
        }
    }
    let target = state.path.join(relative);
    match fs::symlink_metadata(&target) {
        Ok(_) => private(&target, false)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(failed()),
    }
    let temp = current.join(format!(".pvboot-{}", super::team::bootstrap::random(16)));
    let result = (|| {
        fault_edge!(state, name, "file-open-before");
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)
            .map_err(|_| failed())?;
        fault_edge!(state, name, "file-open-after");
        fault_edge!(state, name, "file-write-before");
        f.write_all(data).map_err(|_| failed())?;
        fault_edge!(state, name, "file-write-after");
        fault_edge!(state, name, "file-fsync-before");
        f.sync_all().map_err(|_| failed())?;
        fault_edge!(state, name, "file-fsync-after");
        private(&temp, false)?;
        fault_edge!(state, name, "readback-before");
        if fs::read(&temp).map_err(|_| failed())? != data {
            return Err(failed());
        }
        fault_edge!(state, name, "readback-after");
        fault_edge!(state, name, "rename-before");
        fs::rename(&temp, &target).map_err(|_| failed())?;
        fault_edge!(state, name, "rename-after");
        fault_edge!(state, name, "parent-fsync-before");
        File::open(&current)
            .and_then(|f| f.sync_all())
            .map_err(|_| failed())?;
        fault_edge!(state, name, "parent-fsync-after");
        private(&target, false)?;
        fault_edge!(state, name, "final-readback-before");
        if fs::read(&target).map_err(|_| failed())? != data {
            return Err(failed());
        }
        fault_edge!(state, name, "final-readback-after");
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Exact-owned-state, in-process fault control. No environment variable,
/// IPC route, or non-test implementation exists.
// Selected publication uses descriptor-anchored parents and the same legacy
// pretty-sorted image. The original writer above remains unchanged.
pub(crate) fn write_with_history(
    history: &crate::team::commit::HistorySession<'_>,
    name: &str,
    data: &[u8],
) -> Result<()> {
    use rustix::fs::{
        AtFlags, Mode, OFlags, RenameFlags, fsync, mkdirat, open, openat, renameat_with, unlinkat,
    };
    use std::io::Read;
    let state = history.state();
    history.reserve_writer(name, data.len() as u64)?;
    let path = Path::new(name);
    let parts = path.components().collect::<Vec<_>>();
    if parts.is_empty()
        || parts
            .iter()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(failed());
    }
    let root = File::from(
        open(
            &state.path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| failed())?,
    );
    state.check_import_root_descriptor(&root)?;
    let mut directory: rustix::fd::OwnedFd = root.into();
    let mut current = state.path.clone();
    for part in &parts[..parts.len() - 1] {
        let Component::Normal(part) = part else {
            return Err(failed());
        };
        writer_edge(history, name, "directory-open-before")?;
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let child = match openat(&directory, *part, flags, Mode::empty()) {
            Ok(child) => child,
            Err(error) if error == rustix::io::Errno::NOENT => {
                writer_edge(history, name, "directory-create-before")?;
                history.invalidate()?;
                mkdirat(&directory, *part, Mode::from_raw_mode(0o700)).map_err(|_| failed())?;
                writer_edge(history, name, "directory-create-after")?;
                writer_edge(history, name, "ancestor-fsync-before")?;
                history.invalidate()?;
                fsync(&directory).map_err(|_| failed())?;
                writer_edge(history, name, "ancestor-fsync-after")?;
                openat(&directory, *part, flags, Mode::empty()).map_err(|_| failed())?
            }
            Err(_) => return Err(failed()),
        };
        current.push(part);
        private(&current, true)?;
        let opened = File::from(child);
        let metadata = opened.metadata().map_err(|_| failed())?;
        let named = fs::symlink_metadata(&current).map_err(|_| failed())?;
        if metadata.dev() != named.dev() || metadata.ino() != named.ino() {
            return Err(failed());
        }
        directory = opened.into();
        writer_edge(history, name, "directory-open-after")?;
    }
    let Component::Normal(leaf) = parts[parts.len() - 1] else {
        return Err(failed());
    };
    // NOREPLACE is supported by the pinned rustix on both Linux and Apple.
    // Existing records are handled by the independently validating guard.
    let temp = format!(".pvboot-{}", crate::team::bootstrap::random(16));
    let result = (|| {
        writer_edge(history, name, "file-open-before")?;
        history.invalidate()?;
        let mut file = File::from(
            openat(
                &directory,
                temp.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| failed())?,
        );
        writer_edge(history, name, "file-open-after")?;
        writer_edge(history, name, "file-write-before")?;
        history.invalidate()?;
        file.write_all(data).map_err(|_| failed())?;
        writer_edge(history, name, "file-write-after")?;
        writer_edge(history, name, "file-fsync-before")?;
        history.invalidate()?;
        file.sync_all().map_err(|_| failed())?;
        writer_edge(history, name, "file-fsync-after")?;
        let identity = file.metadata().map_err(|_| failed())?;
        let readback = |leaf: &std::ffi::OsStr| -> Result<()> {
            let opened = File::from(
                openat(
                    &directory,
                    leaf,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| failed())?,
            );
            let metadata = opened.metadata().map_err(|_| failed())?;
            if !metadata.is_file()
                || metadata.uid() != nix::unistd::geteuid().as_raw()
                || metadata.mode() & 0o077 != 0
                || metadata.nlink() != 1
                || metadata.dev() != identity.dev()
                || metadata.ino() != identity.ino()
                || metadata.len() != data.len() as u64
            {
                return Err(failed());
            }
            let mut bytes = Vec::new();
            (&opened)
                .take((data.len() as u64).checked_add(1).ok_or_else(failed)?)
                .read_to_end(&mut bytes)
                .map_err(|_| failed())?;
            if bytes != data {
                return Err(failed());
            }
            Ok(())
        };
        writer_edge(history, name, "readback-before")?;
        readback(std::ffi::OsStr::new(&temp))?;
        writer_edge(history, name, "readback-after")?;
        writer_edge(history, name, "rename-before")?;
        history.invalidate()?;
        renameat_with(
            &directory,
            temp.as_str(),
            &directory,
            leaf,
            RenameFlags::NOREPLACE,
        )
        .map_err(|_| failed())?;
        writer_edge(history, name, "rename-after")?;
        writer_edge(history, name, "parent-fsync-before")?;
        history.invalidate()?;
        fsync(&directory).map_err(|_| failed())?;
        writer_edge(history, name, "parent-fsync-after")?;
        writer_edge(history, name, "final-readback-before")?;
        readback(leaf)?;
        writer_edge(history, name, "final-readback-after")?;
        private(&current.join(leaf), false)?;
        history.check()
    })();
    if result.is_err() {
        let _ = history.invalidate();
        let _ = unlinkat(&directory, temp.as_str(), AtFlags::empty());
    }
    result
}
pub(crate) fn confirm_denial_durable(
    history: &crate::team::commit::HistorySession<'_>,
    name: &str,
) -> Result<()> {
    use rustix::fs::{Mode, OFlags, fsync, open, openat};
    use std::io::Read;
    let state = history.state();
    private_relative(state, name)?;
    let root = File::from(
        open(
            &state.path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| failed())?,
    );
    state.check_import_root_descriptor(&root)?;
    let mut directory: rustix::fd::OwnedFd = root.into();
    let parts = Path::new(name).components().collect::<Vec<_>>();
    if parts.is_empty()
        || parts
            .iter()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(failed());
    }
    for part in &parts[..parts.len() - 1] {
        let Component::Normal(part) = part else {
            return Err(failed());
        };
        history.check()?;
        directory = openat(
            &directory,
            *part,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| failed())?;
    }
    let Component::Normal(leaf) = parts[parts.len() - 1] else {
        return Err(failed());
    };
    let file = File::from(
        openat(
            &directory,
            leaf,
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| failed())?,
    );
    let metadata = file.metadata().map_err(|_| failed())?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > 16_777_216 {
        return Err(failed());
    }
    history.reserve_writer(name, metadata.len())?;
    let mut before = Vec::new();
    (&file)
        .take(metadata.len().checked_add(1).ok_or_else(failed)?)
        .read_to_end(&mut before)
        .map_err(|_| failed())?;
    writer_edge(history, name, "existing-file-fsync-before")?;
    history.invalidate()?;
    history.invalidate()?;
    file.sync_all().map_err(|_| failed())?;
    writer_edge(history, name, "existing-file-fsync-after")?;
    writer_edge(history, name, "existing-parent-fsync-before")?;
    history.invalidate()?;
    fsync(&directory).map_err(|_| failed())?;
    writer_edge(history, name, "existing-parent-fsync-after")?;
    let again = File::from(
        openat(
            &directory,
            leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| failed())?,
    );
    let actual = again.metadata().map_err(|_| failed())?;
    if actual.dev() != metadata.dev()
        || actual.ino() != metadata.ino()
        || actual.len() != metadata.len()
    {
        return Err(failed());
    }
    let mut after = Vec::new();
    (&again)
        .take(metadata.len().checked_add(1).ok_or_else(failed)?)
        .read_to_end(&mut after)
        .map_err(|_| failed())?;
    if before != after || before.len() as u64 != metadata.len() {
        return Err(failed());
    }
    history.check()
}
fn writer_edge(
    history: &crate::team::commit::HistorySession<'_>,
    name: &str,
    point: &str,
) -> Result<()> {
    history.check()?;
    history.charge(1, 0)?;
    #[cfg(test)]
    testing::hit(history.state(), name, point)?;
    #[cfg(not(test))]
    let _ = (name, point);
    history.check()
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::{
        collections::BTreeMap,
        path::PathBuf,
        sync::{Arc, Condvar, LazyLock, Mutex},
        time::Duration,
    };
    struct Spec {
        at: Option<usize>,
        named: Option<(String, String, usize)>,
        hits: Vec<(String, String)>,
        fired: bool,
        crash: bool,
        pause: Option<Arc<Pause>>,
    }
    pub(crate) struct Pause {
        state: Mutex<(bool, bool)>,
        changed: Condvar,
    }
    impl Pause {
        pub(crate) fn wait(&self) {
            let guard = self.state.lock().unwrap();
            let (guard, result) = self
                .changed
                .wait_timeout_while(guard, Duration::from_secs(10), |s| !s.0)
                .unwrap();
            assert!(
                guard.0 && !result.timed_out(),
                "owned reader did not reach pause"
            );
        }
        pub(crate) fn release(&self) {
            self.state.lock().unwrap().1 = true;
            self.changed.notify_all();
        }
    }
    static SPECS: LazyLock<Mutex<BTreeMap<PathBuf, Spec>>> =
        LazyLock::new(|| Mutex::new(BTreeMap::new()));
    pub(crate) struct Scope {
        root: PathBuf,
    }
    impl Scope {
        pub(crate) fn track(state: &StateDir, at: Option<usize>) -> Self {
            let root = state.path.clone();
            assert!(state.path.is_dir());
            assert!(
                SPECS
                    .lock()
                    .unwrap()
                    .insert(
                        root.clone(),
                        Spec {
                            at,
                            named: None,
                            hits: Vec::new(),
                            fired: false,
                            crash: false,
                            pause: None
                        }
                    )
                    .is_none()
            );
            Self { root }
        }
        pub(crate) fn pause(state: &StateDir, suffix: &str, point: &str) -> (Self, Arc<Pause>) {
            let scope = Self::named(state, suffix, point, 1);
            let pause = Arc::new(Pause {
                state: Mutex::new((false, false)),
                changed: Condvar::new(),
            });
            SPECS.lock().unwrap().get_mut(&scope.root).unwrap().pause = Some(pause.clone());
            (scope, pause)
        }
        pub(crate) fn crash(state: &StateDir, at: usize) -> Self {
            let scope = Self::track(state, Some(at));
            SPECS.lock().unwrap().get_mut(&scope.root).unwrap().crash = true;
            scope
        }
        pub(crate) fn named(state: &StateDir, suffix: &str, point: &str, nth: usize) -> Self {
            let value = Self::track(state, None);
            SPECS.lock().unwrap().get_mut(&value.root).unwrap().named =
                Some((suffix.into(), point.into(), nth));
            value
        }
        pub(crate) fn hits(&self) -> Vec<(String, String)> {
            SPECS.lock().unwrap()[&self.root].hits.clone()
        }
        pub(crate) fn fired(&self) -> bool {
            SPECS.lock().unwrap()[&self.root].fired
        }
    }
    impl Drop for Scope {
        fn drop(&mut self) {
            SPECS.lock().unwrap().remove(&self.root);
        }
    }
    pub(crate) fn reader_hit(state: &StateDir, name: &str, point: &str) -> Result<()> {
        let enabled = SPECS
            .lock()
            .unwrap()
            .get(&state.path)
            .is_some_and(|s| s.pause.is_some());
        if enabled {
            hit(state, name, point)
        } else {
            Ok(())
        }
    }
    pub(crate) fn hit(state: &StateDir, name: &str, point: &str) -> Result<()> {
        let mut specs = SPECS.lock().unwrap();
        let Some(spec) = specs.get_mut(&state.path) else {
            return Ok(());
        };
        let index = spec.hits.len();
        spec.hits.push((name.into(), point.into()));
        let named = spec.named.as_ref().is_some_and(|(suffix, p, nth)| {
            name.ends_with(suffix)
                && point == p
                && spec
                    .hits
                    .iter()
                    .filter(|(n, p)| n.ends_with(suffix) && p == point)
                    .count()
                    == *nth
        });
        if !spec.fired && (spec.at == Some(index) || named) {
            spec.fired = true;
            if spec.crash {
                std::process::exit(86);
            }
            if let Some(pause) = spec.pause.clone() {
                drop(specs);
                let mut guard = pause.state.lock().unwrap();
                guard.0 = true;
                pause.changed.notify_all();
                let (guard, result) = pause
                    .changed
                    .wait_timeout_while(guard, Duration::from_secs(10), |s| !s.1)
                    .unwrap();
                return if guard.1 && !result.timed_out() {
                    Ok(())
                } else {
                    Err(failed())
                };
            }
            return Err(failed());
        }
        Ok(())
    }
}

pub(crate) fn json(state: &StateDir, name: &str, value: &Value) -> Result<()> {
    encoded_len(value)?;
    write(
        state,
        name,
        pyjson::dumps(value, DumpOptions::pretty_sorted())?.as_bytes(),
    )
}

/// Count before allocating a pretty JSON image. All new import documents
/// use ASCII escaping, two-space indentation, and at most 64 containers.
pub(crate) fn encoded_len(value: &Value) -> Result<usize> {
    const CAP: usize = 64 * 1024 * 1024;
    fn add(a: usize, b: usize) -> Result<usize> {
        a.checked_add(b)
            .filter(|n| *n <= CAP)
            .ok_or_else(|| Error::state("team_bootstrap_limit_exceeded"))
    }
    fn string(s: &str) -> Result<usize> {
        let mut n = 2;
        for c in s.chars() {
            n = add(
                n,
                match c {
                    '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
                    ' '..='~' => 1,
                    c if (c as u32) <= 0xffff => 6,
                    _ => 12,
                },
            )?;
        }
        Ok(n)
    }
    fn count(v: &Value, depth: usize) -> Result<usize> {
        if depth > 64 {
            return Err(Error::state("team_bootstrap_limit_exceeded"));
        }
        match v {
            Value::Null => Ok(4),
            Value::Bool(b) => Ok(if *b { 4 } else { 5 }),
            Value::String(s) => string(s),
            Value::Number(_) => Ok(pyjson::dumps(v, DumpOptions::compact_sorted())?.len()),
            Value::Array(items) => {
                if items.is_empty() {
                    return Ok(2);
                }
                let mut n = add(3, 2 * depth)?;
                for item in items {
                    n = add(n, add(2 + 2 * (depth + 1), count(item, depth + 1)?)?)?;
                }
                Ok(n)
            }
            Value::Object(items) => {
                if items.is_empty() {
                    return Ok(2);
                }
                let mut n = add(3, 2 * depth)?;
                for (key, item) in items {
                    n = add(
                        n,
                        add(
                            4 + 2 * (depth + 1),
                            add(string(key)?, count(item, depth + 1)?)?,
                        )?,
                    )?;
                }
                Ok(n)
            }
        }
    }
    count(value, 0)
}

pub(crate) fn transfer_lease(state: &StateDir, env: &str) -> Result<File> {
    let _lock = state.lock()?;
    let marker = crate::team::bootstrap::path(env, "lease-marker")?;
    if !state.exists(&marker) {
        write(state, &marker, b"personal-bootstrap-lease-v1\n")?;
    }
    let name = crate::team::bootstrap::path(env, "transfer.lock")?;
    let p = state.path.join(&name);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)
        .map_err(|_| failed())?;
    private(&p, false)?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| Error::state("team_bootstrap_busy"))?;
    Ok(file)
}

pub(crate) fn validate_environment_tree(state: &StateDir, env: &str) -> Result<()> {
    if !crate::team::commit::valid_env_id(env) {
        return Err(failed());
    }
    private(&state.path, true)?;
    let team = state.path.join("team");
    private(&team, true)?;
    let root = team.join(env);
    if !root.exists() {
        return Ok(());
    }
    let mut directories = vec![root];
    let mut total = 0u64;
    let mut count = 0usize;
    while let Some(dir) = directories.pop() {
        private(&dir, true)?;
        for entry in fs::read_dir(dir).map_err(|_| failed())? {
            let entry = entry.map_err(|_| failed())?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(|_| failed())?;
            count = count.checked_add(1).ok_or_else(failed)?;
            if count > 65_536 {
                return Err(Error::state("team_bootstrap_limit_exceeded"));
            }
            if metadata.is_dir() {
                directories.push(entry.path());
            } else {
                private(&entry.path(), false)?;
                total = total.checked_add(metadata.len()).ok_or_else(failed)?;
                if total > 64 * 1024 * 1024 {
                    return Err(Error::state("team_bootstrap_limit_exceeded"));
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_inventory(state: &StateDir, env: &str) -> Result<()> {
    let mut total = 0u64;
    for name in [
        crate::vault::VAULT_DOC,
        crate::policy::CONNECTIONS,
        crate::projects::DOC,
        crate::tombstone::PATH,
        crate::team::sync::ENVS_MAP_PATH,
        crate::policy::CONTROL,
        &crate::team::bootstrap::path(env, "known-facts.json")?,
    ] {
        private_relative(state, name)?;
        match fs::symlink_metadata(state.path.join(name)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(failed()),
            Ok(m) => {
                total = total.checked_add(m.len()).ok_or_else(failed)?;
                if total > 64 * 1024 * 1024 {
                    return Err(Error::state("team_bootstrap_limit_exceeded"));
                }
            }
        }
    }
    Ok(())
}

/// Fixed private staging trees only. Inspect types, modes and ownership
/// before any file is opened, synced or removed; no archive or peer path.
fn staging_entries(state: &StateDir, env: &str) -> Result<Vec<(std::path::PathBuf, bool)>> {
    let root = state
        .path
        .join(crate::team::bootstrap::path(env, "staging")?);
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut pending = vec![root];
    let mut entries = Vec::new();
    let mut bytes = 0u64;
    while let Some(path) = pending.pop() {
        private(&path, true)?;
        entries.push((path.clone(), true));
        for entry in fs::read_dir(path).map_err(|_| failed())? {
            let path = entry.map_err(|_| failed())?.path();
            let metadata = fs::symlink_metadata(&path).map_err(|_| failed())?;
            if metadata.is_dir() {
                pending.push(path);
            } else {
                private(&path, false)?;
                bytes = bytes.checked_add(metadata.len()).ok_or_else(failed)?;
                entries.push((path, false));
            }
            if entries
                .len()
                .checked_add(pending.len())
                .is_none_or(|n| n > 65_536)
                || bytes > 64 * 1024 * 1024
            {
                return Err(Error::state("team_bootstrap_limit_exceeded"));
            }
        }
    }
    Ok(entries)
}
pub(crate) fn sync_staging(state: &StateDir, env: &str) -> Result<usize> {
    if !state.locked_by_current_thread() {
        return Err(failed());
    }
    let entries = staging_entries(state, env)?;
    let mut total = 0usize;
    for (path, dir) in entries.iter().rev() {
        let _name = path
            .strip_prefix(&state.path)
            .map_err(|_| failed())?
            .to_str()
            .ok_or_else(failed)?;
        if !dir {
            total = total
                .checked_add(
                    usize::try_from(fs::metadata(path).map_err(|_| failed())?.len())
                        .map_err(|_| failed())?,
                )
                .ok_or_else(failed)?;
        }
        fault_edge!(state, _name, "staging-fsync-before");
        File::open(path)
            .and_then(|f| f.sync_all())
            .map_err(|_| failed())?;
        fault_edge!(state, _name, "staging-fsync-after");
    }
    Ok(total)
}
pub(crate) fn discard_staging(state: &StateDir, env: &str) -> Result<()> {
    if !state.locked_by_current_thread() {
        return Err(failed());
    }
    for (path, dir) in staging_entries(state, env)?.into_iter().rev() {
        let _name = path
            .strip_prefix(&state.path)
            .map_err(|_| failed())?
            .to_str()
            .ok_or_else(failed)?;
        fault_edge!(state, _name, "staging-unlink-before");
        if dir {
            fs::remove_dir(&path)
        } else {
            fs::remove_file(&path)
        }
        .map_err(|_| failed())?;
        fault_edge!(state, _name, "staging-unlink-after");
        fault_edge!(state, _name, "staging-unlink-parent-fsync-before");
        File::open(path.parent().ok_or_else(failed)?)
            .and_then(|f| f.sync_all())
            .map_err(|_| failed())?;
        fault_edge!(state, _name, "staging-unlink-parent-fsync-after");
    }
    Ok(())
}

#[cfg(test)]
mod personal_reader_tests {
    use super::*;
    use crate::{
        context::Context,
        gateway,
        policy::{Connection, HttpAuth, HttpScope, HttpTarget},
        sshwire,
    };
    use std::{
        io::{BufRead, BufReader, Write},
        os::unix::net::UnixStream,
        process::{Child, Command, Stdio},
        sync::{Arc, mpsc},
        thread,
        time::Duration,
    };
    struct Writer(Option<Child>);
    impl Writer {
        fn join(&mut self) {
            assert!(self.0.take().unwrap().wait().unwrap().success());
        }
    }
    impl Drop for Writer {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    fn writer(
        state: &StateDir,
        env: &str,
    ) -> (Writer, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "import_barrier::personal_reader_tests::personal_bootstrap_guard_writer_child",
                "--nocapture",
            ])
            .env("PVBOOT_OWN_WRITER_STATE", &state.path)
            .env("PVBOOT_OWN_WRITER_ENV", env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let line = line.unwrap();
                if line.starts_with("PVBOOT_WRITER_") {
                    let _ = tx.send(line);
                }
            }
        });
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            "PVBOOT_WRITER_WAITING"
        );
        (Writer(Some(child)), rx, reader)
    }
    #[test]
    fn personal_bootstrap_guard_writer_child() {
        let Some(root) = std::env::var_os("PVBOOT_OWN_WRITER_STATE") else {
            return;
        };
        let env = std::env::var("PVBOOT_OWN_WRITER_ENV").unwrap();
        let state = StateDir::new(root);
        println!("\nPVBOOT_WRITER_WAITING");
        std::io::stdout().flush().unwrap();
        {
            let _lock = state.lock().unwrap();
            let name = crate::team::bootstrap::path(&env, "receipt.json").unwrap();
            fs::write(state.path.join(name), b"{}").unwrap();
        }
        println!("PVBOOT_WRITER_DONE");
        std::io::stdout().flush().unwrap();
    }
    fn ssh_client(path: &Path) -> sshwire::AgentConnection<UnixStream> {
        let socket = UnixStream::connect(path).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut client = sshwire::AgentConnection::new(socket);
        let host =
            sshwire::Ed25519PrivateKey::from_seed(&[9; 32], "synthetic-personal-host").unwrap();
        let signature = sshwire::encode_ssh_signature(&host.sign(&[3; 32])).unwrap();
        assert_eq!(
            client
                .request(&sshwire::build_session_bind(
                    &host.public.blob(),
                    &[3; 32],
                    &signature,
                    false
                ))
                .unwrap(),
            sshwire::build_success()
        );
        client
    }
    fn ssh_sign(mut client: sshwire::AgentConnection<UnixStream>) -> bool {
        let key =
            sshwire::Ed25519PrivateKey::from_seed(&[8; 32], "synthetic-personal-user").unwrap();
        let data = sshwire::build_userauth_request(
            &[3; 32],
            "deploy",
            "ssh-ed25519",
            &key.public.blob(),
            sshwire::SSH_CONNECTION_SERVICE,
            None,
        );
        client
            .request(&sshwire::build_sign_request(&key.public.blob(), &data, 0))
            .unwrap()
            .first()
            == Some(&sshwire::SSH_AGENT_SIGN_RESPONSE)
    }
    #[test]
    fn personal_bootstrap_paused_readers_gateway_and_signer_serialize_with_independent_writer() {
        let fixture = crate::team::bootstrap::install::tests::installed();
        let ctx = fixture.b.clone();
        let env = &fixture.env;
        let receipt_path = ctx
            .state
            .path
            .join(crate::team::bootstrap::path(env, "receipt.json").unwrap());
        let original = fs::read(&receipt_path).unwrap();
        let fake = crate::fake_upstream::FakeUpstream::new("synthetic-install-fault-value").start();
        ctx.policy
            .create_principal("epoch-reader", "synthetic")
            .unwrap();
        ctx.policy
            .create_connection(
                Connection::new(
                    "epoch-http",
                    "personal",
                    "vault",
                    "synthetic",
                    "http",
                    "alpha",
                    None,
                    "",
                    Some(
                        HttpTarget::new(fake.scheme(), fake.host(), fake.port() as i64, None, true)
                            .unwrap(),
                    ),
                    Some(HttpAuth::bearer()),
                    Some(
                        HttpScope::new(
                            Some(vec!["GET".into()]),
                            Some(vec!["/data".into()]),
                            vec![],
                        )
                        .unwrap(),
                    ),
                    None,
                    None,
                    0,
                    "active",
                    "",
                    "",
                )
                .unwrap(),
            )
            .unwrap();
        let grant = ctx
            .policy
            .create_grant("epoch-reader", "epoch-http", Some(3600), None)
            .unwrap();
        let http = ctx
            .handles
            .issue(
                "epoch-reader",
                "epoch-http",
                &grant.id,
                grant.policy_version,
                3600,
                None,
            )
            .unwrap();
        let grant = ctx
            .policy
            .create_grant("epoch-reader", "ssh", Some(3600), None)
            .unwrap();
        let manager = crate::signer::install(ctx.clone(), None).unwrap();
        let binding = manager.bind("epoch-reader", "ssh", &grant.id).unwrap();
        for (kind, name, point, held) in [
            (
                "vault",
                crate::vault::VAULT_DOC,
                "reader-check-before-read",
                true,
            ),
            (
                "vault",
                crate::vault::VAULT_DOC,
                "reader-file-read-before-view",
                true,
            ),
            (
                "policy",
                crate::policy::CONNECTIONS,
                "reader-file-read-before-view",
                true,
            ),
            ("http", "epoch-http", "gateway-consume-before", false),
            ("http", "epoch-http", "gateway-consume-before-decrypt", true),
            ("ssh", "ssh", "signer-consume-before", false),
            ("ssh", "ssh", "signer-consume-before-decrypt", true),
        ] {
            let client = (kind == "ssh").then(|| ssh_client(&binding.socket_path));
            let (scope, pause) = testing::Scope::pause(ctx.state, name, point);
            let reader_ctx = Arc::clone(&ctx);
            let handle = http.clone();
            let reader = thread::spawn(move || match kind {
                "vault" => reader_ctx
                    .vault
                    .list_secrets(None, None)
                    .unwrap()
                    .iter()
                    .any(|s| s.id == "alpha"),
                "policy" => reader_ctx.policy.get_connection("ssh").is_ok(),
                "http" => gateway::relay(
                    &reader_ctx,
                    &handle,
                    "GET",
                    "/data",
                    &gateway::Headers::new(),
                    b"",
                    None,
                )
                .relayed(),
                "ssh" => ssh_sign(client.unwrap()),
                _ => unreachable!(),
            });
            pause.wait();
            let (mut child, done, drain) = writer(ctx.state, env);
            if held {
                assert!(
                    matches!(
                        done.recv_timeout(Duration::from_millis(150)),
                        Err(mpsc::RecvTimeoutError::Timeout)
                    ),
                    "writer crossed a held epoch guard"
                );
                pause.release();
                assert!(
                    reader.join().unwrap(),
                    "coherent operation failed before writer started"
                );
                assert_eq!(
                    done.recv_timeout(Duration::from_secs(5)).unwrap(),
                    "PVBOOT_WRITER_DONE"
                );
            } else {
                assert_eq!(
                    done.recv_timeout(Duration::from_secs(5)).unwrap(),
                    "PVBOOT_WRITER_DONE"
                );
                pause.release();
                assert!(
                    !reader.join().unwrap(),
                    "cached operation crossed changed import epoch"
                );
            }
            child.join();
            drain.join().unwrap();
            drop(scope);
            assert!(ctx.vault.secret_for_trusted_use("alpha", None).is_err());
            assert!(ctx.vault.secret_for_trusted_use("unrelated", None).is_ok());
            {
                let _lock = ctx.state.lock().unwrap();
                fs::write(&receipt_path, &original).unwrap();
            }
            assert!(ctx.vault.secret_for_trusted_use("alpha", None).is_ok());
        }
        manager.shutdown();
        println!("PVBOOT_PAUSED_CROSS_PROCESS_READER_CASES=7");
    }
    fn removal_writer(
        state: &StateDir,
        env: &str,
    ) -> (Writer, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "import_barrier::personal_reader_tests::personal_bootstrap_removal_writer_child",
                "--nocapture",
            ])
            .env("PVBOOT_OWN_REMOVAL_STATE", &state.path)
            .env("PVBOOT_OWN_REMOVAL_ENV", env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let line = line.unwrap();
                if line.starts_with("PVBOOT_WRITER_") {
                    let _ = tx.send(line);
                }
            }
        });
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            "PVBOOT_WRITER_WAITING"
        );
        (Writer(Some(child)), rx, reader)
    }
    #[test]
    fn personal_bootstrap_removal_writer_child() {
        let Some(root) = std::env::var_os("PVBOOT_OWN_REMOVAL_STATE") else {
            return;
        };
        let env = std::env::var("PVBOOT_OWN_REMOVAL_ENV").unwrap();
        println!("\nPVBOOT_WRITER_WAITING");
        std::io::stdout().flush().unwrap();
        let ctx = Context::open(
            root,
            crate::context::Config::default(),
            crate::clock::system(),
        )
        .unwrap();
        let key = crate::team::identity::DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        let fp = key.fingerprint().unwrap();
        crate::team::membership::author_commit(
            &ctx,
            None,
            &env,
            vec![serde_json::json!({"op":"member.remove","fingerprint":fp})],
        )
        .unwrap();
        assert!(
            ctx.state
                .exists(&crate::team::bootstrap::path(&env, LOCAL_REMOVAL_DENIAL).unwrap())
        );
        assert!(
            !ctx.state
                .exists(&crate::team::bootstrap::path(&env, "member-removed.json").unwrap())
        );
        println!("PVBOOT_WRITER_DONE");
        std::io::stdout().flush().unwrap();
    }
    #[test]
    fn personal_bootstrap_real_removal_serializes_all_reader_lock_orders() {
        fn copy(source: &Path, target: &Path) {
            let metadata = fs::symlink_metadata(source).unwrap();
            assert!(metadata.is_dir());
            fs::DirBuilder::new()
                .mode(metadata.permissions().mode() & 0o777)
                .create(target)
                .unwrap();
            for entry in fs::read_dir(source).unwrap() {
                let entry = entry.unwrap();
                let metadata = fs::symlink_metadata(entry.path()).unwrap();
                let target = target.join(entry.file_name());
                if metadata.is_dir() {
                    copy(&entry.path(), &target);
                } else {
                    assert!(metadata.is_file());
                    fs::copy(entry.path(), &target).unwrap();
                    fs::set_permissions(target, metadata.permissions()).unwrap();
                }
            }
        }
        let fixture = crate::team::bootstrap::install::tests::installed();
        let env = &fixture.env;
        let fake = crate::fake_upstream::FakeUpstream::new("synthetic-install-fault-value").start();
        for (kind, name, point, held) in [
            (
                "vault",
                crate::vault::VAULT_DOC,
                "reader-check-before-read",
                true,
            ),
            (
                "vault",
                crate::vault::VAULT_DOC,
                "reader-file-read-before-view",
                true,
            ),
            (
                "trusted",
                crate::vault::VAULT_DOC,
                "reader-file-read-before-view",
                true,
            ),
            (
                "policy",
                crate::policy::CONNECTIONS,
                "reader-file-read-before-view",
                true,
            ),
            ("http", "epoch-http", "gateway-consume-before", false),
            ("http", "epoch-http", "gateway-consume-before-decrypt", true),
            ("ssh", "ssh", "signer-consume-before", false),
            ("ssh", "ssh", "signer-consume-before-decrypt", true),
        ] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("b");
            copy(&fixture.b.state.path, &path);
            let ctx = Arc::new(
                Context::open(
                    path,
                    crate::context::Config::default(),
                    crate::clock::system(),
                )
                .unwrap(),
            );
            ctx.policy
                .create_principal("epoch-reader", "synthetic")
                .unwrap();
            ctx.policy
                .create_connection(
                    Connection::new(
                        "epoch-http",
                        "personal",
                        "vault",
                        "synthetic",
                        "http",
                        "alpha",
                        None,
                        "",
                        Some(
                            HttpTarget::new(
                                fake.scheme(),
                                fake.host(),
                                fake.port() as i64,
                                None,
                                true,
                            )
                            .unwrap(),
                        ),
                        Some(HttpAuth::bearer()),
                        Some(
                            HttpScope::new(
                                Some(vec!["GET".into()]),
                                Some(vec!["/data".into()]),
                                vec![],
                            )
                            .unwrap(),
                        ),
                        None,
                        None,
                        0,
                        "active",
                        "",
                        "",
                    )
                    .unwrap(),
                )
                .unwrap();
            let grant = ctx
                .policy
                .create_grant("epoch-reader", "epoch-http", Some(3600), None)
                .unwrap();
            let http = ctx
                .handles
                .issue(
                    "epoch-reader",
                    "epoch-http",
                    &grant.id,
                    grant.policy_version,
                    3600,
                    None,
                )
                .unwrap();
            let grant = ctx
                .policy
                .create_grant("epoch-reader", "ssh", Some(3600), None)
                .unwrap();
            let manager = crate::signer::install(ctx.clone(), None).unwrap();
            let binding = manager.bind("epoch-reader", "ssh", &grant.id).unwrap();
            let client = (kind == "ssh").then(|| ssh_client(&binding.socket_path));
            let (scope, pause) = testing::Scope::pause(ctx.state, name, point);
            let reader_ctx = ctx.clone();
            let reader = thread::spawn(move || match kind {
                "vault" => reader_ctx
                    .vault
                    .list_secrets(None, None)
                    .unwrap()
                    .iter()
                    .any(|entry| entry.id == "alpha"),
                "trusted" => reader_ctx
                    .vault
                    .secret_for_trusted_use("alpha", None)
                    .is_ok(),
                "policy" => reader_ctx.policy.get_connection("ssh").is_ok(),
                "http" => gateway::relay(
                    &reader_ctx,
                    &http,
                    "GET",
                    "/data",
                    &gateway::Headers::new(),
                    b"",
                    None,
                )
                .relayed(),
                "ssh" => ssh_sign(client.unwrap()),
                _ => unreachable!(),
            });
            pause.wait();
            let (mut child, done, drain) = removal_writer(ctx.state, env);
            if held {
                assert!(matches!(
                    done.recv_timeout(Duration::from_millis(150)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ));
                pause.release();
                assert!(reader.join().unwrap(), "already linearized reader {kind}");
                assert_eq!(
                    done.recv_timeout(Duration::from_secs(5)).unwrap(),
                    "PVBOOT_WRITER_DONE"
                );
            } else {
                assert_eq!(
                    done.recv_timeout(Duration::from_secs(5)).unwrap(),
                    "PVBOOT_WRITER_DONE"
                );
                pause.release();
                assert!(!reader.join().unwrap(), "late reader {kind}");
            }
            child.join();
            drain.join().unwrap();
            drop(scope);
            assert!(ctx.vault.secret_for_trusted_use("alpha", None).is_err());
            assert!(ctx.vault.secret_for_trusted_use("unrelated", None).is_ok());
            if let Ok(grant) =
                ctx.policy
                    .create_grant("epoch-reader", "epoch-http", Some(3600), None)
            {
                let handle = ctx
                    .handles
                    .issue(
                        "epoch-reader",
                        "epoch-http",
                        &grant.id,
                        grant.policy_version,
                        3600,
                        None,
                    )
                    .unwrap();
                assert!(
                    !gateway::relay(
                        &ctx,
                        &handle,
                        "GET",
                        "/data",
                        &gateway::Headers::new(),
                        b"",
                        None
                    )
                    .relayed()
                );
            }
            if let Ok(binding) = manager.bind("epoch-reader", "ssh", &grant.id) {
                assert!(!ssh_sign(ssh_client(&binding.socket_path)));
            }
            manager.shutdown();
        }
        println!("PVBOOT_REAL_REMOVAL_READER_LOCK_ORDERS=8");
    }
}
