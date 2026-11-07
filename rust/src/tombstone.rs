//! Durable deny-only identity ledger. Absent for nondeleted v1 vaults. Signed
//! shared facts still go through team admission; this ledger never grants access.
use crate::{
    errors::{Error, Result},
    store::StateDir,
};
use serde_json::{Value, json};

pub const PATH: &str = "vault/tombstones.json";
fn bad() -> Error {
    Error::state("state_corrupt").with_detail(PATH)
}
pub fn load(state: &StateDir) -> Result<Value> {
    let value = state.read_json(PATH, json!({}))?;
    let obj = value.as_object().ok_or_else(bad)?;
    for (key, field) in obj {
        if !["local", "shared", "required", "bindings"].contains(&key.as_str())
            || !field.is_object()
        {
            return Err(bad());
        }
    }
    for (id, metadata) in value["local"].as_object().into_iter().flatten() {
        if crate::projects::validate_name(id, "secret_id").is_err()
            || !metadata.is_object()
            || !metadata["project"].is_string()
            || !metadata["environment"].is_string()
        {
            return Err(bad());
        }
    }
    for (env, entries) in value["shared"].as_object().into_iter().flatten() {
        for (hash, value) in entries.as_object().ok_or_else(bad)? {
            let fact = crate::team::sync::Fact::from_dict(value).map_err(|_| bad())?;
            let target = fact.target.as_object().ok_or_else(bad)?;
            if fact.format != crate::team::sync::FACT_FORMAT
                || fact.kind != "secret_deleted"
                || fact.env_id != *env
                || fact.hash().map_err(|_| bad())? != *hash
                || target.len() != 1
                || !target
                    .get("secret_id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| {
                        !id.is_empty()
                            && id.chars().count() <= 64
                            && !id.chars().any(|c| c.is_control())
                    })
            {
                return Err(bad());
            }
        }
    }
    for (_, identities) in value["bindings"].as_object().into_iter().flatten() {
        for (_, scopes) in identities.as_object().ok_or_else(bad)? {
            for scope in scopes.as_array().ok_or_else(bad)? {
                if scope.as_object().is_none_or(|m| m.len() != 2)
                    || !scope["project"].is_string()
                    || !scope["environment"].is_string()
                {
                    return Err(bad());
                }
            }
        }
    }
    if value["required"]
        .as_object()
        .into_iter()
        .flatten()
        .any(|(_, required)| required != &Value::Bool(true))
    {
        return Err(bad());
    }
    Ok(value)
}
pub fn shared_facts(state: &StateDir, env: &str) -> Result<Vec<Value>> {
    let ledger = load(state)?;
    match ledger["shared"].get(env) {
        None => Ok(vec![]),
        Some(value) => Ok(value
            .as_object()
            .ok_or_else(bad)?
            .values()
            .cloned()
            .collect()),
    }
}
fn add_binding(ledger: &mut Value, env: &str, id: &str, binding: Value) -> Result<()> {
    let scopes = ledger
        .as_object_mut()
        .ok_or_else(bad)?
        .entry("bindings")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(bad)?
        .entry(env)
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(bad)?
        .entry(id)
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(bad)?;
    if !scopes.contains(&binding) {
        scopes.push(binding);
    }
    Ok(())
}
pub fn retain_derived_binding(
    state: &StateDir,
    env: &str,
    id: &str,
    project: &str,
    environment: &str,
) -> Result<()> {
    let _lock = state.lock()?;
    let mut ledger = load(state)?;
    let known = ledger["shared"][env]
        .as_object()
        .is_some_and(|facts| facts.values().any(|fact| fact["target"]["secret_id"] == id));
    if !known {
        return Ok(());
    }
    add_binding(
        &mut ledger,
        env,
        id,
        json!({"project":project,"environment":environment}),
    )?;
    if ledger != load(state)? {
        state.write_json(PATH, &ledger)?;
    }
    Ok(())
}
pub fn retain_fact(state: &StateDir, fact: &crate::team::sync::Fact) -> Result<()> {
    if fact.kind != "secret_deleted" {
        return Ok(());
    }
    let _lock = state.lock()?;
    let mut ledger = load(state)?;
    let hash = fact.hash()?;
    ledger
        .as_object_mut()
        .ok_or_else(bad)?
        .entry("shared")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(bad)?
        .entry(&fact.env_id)
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(bad)?
        .insert(hash, fact.to_dict());
    let vault = state.read_json(crate::vault::VAULT_DOC, json!({}))?;
    let id = fact.target["secret_id"].as_str().ok_or_else(bad)?;
    let entry = &vault["secrets"][id];
    if entry["shared_env"] == fact.env_id {
        add_binding(
            &mut ledger,
            &fact.env_id,
            id,
            json!({"project":entry["project"],"environment":entry["environment"]}),
        )?;
        if let (Some(project), Some(environment)) =
            crate::team::sync::env_project_environment(state, &fact.env_id)?
        {
            add_binding(
                &mut ledger,
                &fact.env_id,
                id,
                json!({"project":project,"environment":environment}),
            )?;
        }
    }
    if ledger == load(state)? {
        return Ok(());
    }
    state.write_json(PATH, &ledger)
}
pub fn require_support(state: &StateDir, env: &str) -> Result<()> {
    let _lock = state.lock()?;
    let mut ledger = load(state)?;
    if ledger["required"][env] == true {
        return Ok(());
    }
    ledger
        .as_object_mut()
        .ok_or_else(bad)?
        .entry("required")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(bad)?
        .insert(env.into(), json!(true));
    state.write_json(PATH, &ledger)
}
pub fn support_required(state: &StateDir, env: &str) -> Result<bool> {
    let ledger = load(state)?;
    Ok(ledger["required"][env] == true
        || ledger["shared"]
            .get(env)
            .is_some_and(|v| v.as_object().is_none_or(|m| !m.is_empty())))
}
fn bound_scope(
    ledger: &Value,
    id: &str,
    project: &Value,
    environment: &Value,
) -> Result<Option<String>> {
    let mut found = None;
    for (env, identities) in ledger["bindings"].as_object().into_iter().flatten() {
        if identities
            .get(id)
            .and_then(Value::as_array)
            .is_some_and(|scopes| {
                scopes.iter().any(|scope| {
                    &scope["project"] == project && &scope["environment"] == environment
                })
            })
        {
            if found.as_ref().is_some_and(|prior| prior != env) {
                return Err(Error::policy_denied("secret_identity_ambiguous"));
            }
            found = Some(env.clone());
        }
    }
    Ok(found)
}
/// Local provenance survives a pre-sharing backup without claiming that every
/// unmarked colliding local entry belongs to the remote identity.
pub fn restored_scope(
    state: &StateDir,
    id: &str,
    project: &Value,
    environment: &Value,
) -> Result<Option<String>> {
    bound_scope(&load(state)?, id, project, environment)
}
pub fn is_deleted(state: &StateDir, id: &str, shared_env: Option<&str>) -> Result<bool> {
    let ledger = load(state)?;
    if ledger["local"].get(id).is_some() {
        return Ok(true);
    }
    let vault = state.read_json(crate::vault::VAULT_DOC, json!({}))?;
    let entry = &vault["secrets"][id];
    if bound_scope(&ledger, id, &entry["project"], &entry["environment"])?.is_some() {
        return Ok(true);
    }
    if let Some(env) = shared_env {
        for fact in shared_facts(state, env)? {
            if fact["target"]["secret_id"] == id {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
pub fn require_live_in_scope(
    state: &StateDir,
    id: &str,
    project: &Value,
    environment: &Value,
) -> Result<()> {
    require_live(state, id, None)?;
    let vault = state.read_json(crate::vault::VAULT_DOC, json!({}))?;
    if let Some(env) = vault["secrets"][id]["shared_env"].as_str() {
        require_live(state, id, Some(env))?;
    }
    if vault["secrets"].get(id).is_none()
        && let (Some(project), Some(environment)) = (project.as_str(), environment.as_str())
        && let Some(env) = crate::team::sync::resolve_env_id(state, project, environment)?
    {
        require_live(state, id, Some(&env))?;
    }
    Ok(())
}
pub fn require_live(state: &StateDir, id: &str, shared_env: Option<&str>) -> Result<()> {
    if is_deleted(state, id, shared_env)? {
        return Err(Error::policy_denied("secret_deleted"));
    }
    Ok(())
}
pub fn delete_local(state: &StateDir, id: &str, metadata: Value) -> Result<bool> {
    let _lock = state.lock()?;
    let mut ledger = load(state)?;
    let local = ledger
        .as_object_mut()
        .ok_or_else(bad)?
        .entry("local")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(bad)?;
    if local.contains_key(id) {
        return Ok(false);
    }
    local.insert(id.into(), metadata);
    state.write_json(PATH, &ledger)?;
    Ok(true)
}
/// Restore unions deny state; an old archive can never replace current facts.
pub fn merge_restore(state: &StateDir, archived: &Value) -> Result<()> {
    let _lock = state.lock()?;
    let mut current = load(state)?;
    let archived = archived.as_object().ok_or_else(bad)?;
    for (kind, entries) in archived {
        if !["local", "shared", "required", "bindings"].contains(&kind.as_str()) {
            return Err(bad());
        }
        let target = current
            .as_object_mut()
            .ok_or_else(bad)?
            .entry(kind)
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(bad)?;
        for (id, value) in entries.as_object().ok_or_else(bad)? {
            if kind == "bindings" {
                let identities = target
                    .entry(id)
                    .or_insert_with(|| json!({}))
                    .as_object_mut()
                    .ok_or_else(bad)?;
                for (sid, scopes) in value.as_object().ok_or_else(bad)? {
                    let all = identities
                        .entry(sid)
                        .or_insert_with(|| json!([]))
                        .as_array_mut()
                        .ok_or_else(bad)?;
                    for scope in scopes.as_array().ok_or_else(bad)? {
                        if !all.contains(scope) {
                            all.push(scope.clone());
                        }
                    }
                }
            } else if kind == "shared" {
                let env = target
                    .entry(id)
                    .or_insert_with(|| json!({}))
                    .as_object_mut()
                    .ok_or_else(bad)?;
                for (hash, fact) in value.as_object().ok_or_else(bad)? {
                    let parsed = crate::team::sync::Fact::from_dict(fact)?;
                    if parsed.env_id != *id
                        || parsed.kind != "secret_deleted"
                        || parsed.hash()? != *hash
                    {
                        return Err(bad());
                    }
                    env.entry(hash).or_insert_with(|| fact.clone());
                }
            } else {
                target.entry(id).or_insert_with(|| value.clone());
            }
        }
    }
    if !current.as_object().ok_or_else(bad)?.is_empty() {
        state.write_json(PATH, &current)?;
    }
    Ok(())
}
