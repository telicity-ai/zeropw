//! Signed, replayable install journal. Shared documents are patched at reserved
//! identities; recovery never replaces an unrelated document with an old image.
use super::{
    bad, bytes, digest, path,
    protocol::{self, Deadline},
    random, text,
};
use crate::{
    context::Context,
    errors::Result,
    import_barrier, pyjson,
    store::StateDir,
    team::{
        checkpoint::personal::Plan, commit::CommitStore, fold, identity::DeviceKey,
        transport::Session,
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;

fn raw(state: &StateDir, name: &str) -> Result<Option<Vec<u8>>> {
    import_barrier::private_relative(state, name)?;
    let p = state.path.join(name);
    match fs::symlink_metadata(&p) {
        Ok(m) if m.is_file() && m.len() <= 64 * 1024 * 1024 => Ok(Some(
            fs::read(p).map_err(|_| bad("team_bootstrap_storage_failed"))?,
        )),
        Ok(_) => Err(bad("team_bootstrap_storage_failed")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(bad("team_bootstrap_storage_failed")),
    }
}
fn raw_json(state: &StateDir, name: &str) -> Result<Value> {
    match raw(state, name)? {
        None => Ok(Value::Null),
        Some(b) => pyjson::loads(
            std::str::from_utf8(&b).map_err(|_| bad("team_bootstrap_storage_failed"))?,
        )
        .map_err(|_| bad("team_bootstrap_storage_failed")),
    }
}
fn hash(data: Option<&[u8]>) -> Value {
    data.map(|b| json!(hex::encode(Sha256::digest(b))))
        .unwrap_or(Value::Null)
}
fn targets_hash(ops: &[Value]) -> Result<String> {
    let value = json!(ops);
    import_barrier::encoded_len(&value)?;
    digest(&value)
}
fn signed(
    ctx: &Context,
    mut record: Value,
    history: &crate::team::commit::HistorySession<'_>,
) -> Result<Value> {
    record
        .as_object_mut()
        .ok_or_else(|| bad("team_bootstrap_state_invalid"))?
        .remove("sig");
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms)?;
    history.match_local_identity(&device.record()?)?;
    history.check()?;
    record["sig"] = json!(crate::pybase64::b64encode(&device.sign(&bytes(&record)?)?));
    history.check()?;
    Ok(record)
}
fn verified(ctx: &Context, record: &Value) -> Result<()> {
    let mut unsigned = record.clone();
    let signature = unsigned
        .as_object_mut()
        .ok_or_else(|| bad("team_bootstrap_recovery_required"))?
        .remove("sig")
        .ok_or_else(|| bad("team_bootstrap_recovery_required"))?;
    let signature = crate::pybase64::b64decode_strict(
        signature
            .as_str()
            .ok_or_else(|| bad("team_bootstrap_recovery_required"))?,
    )
    .map_err(|_| bad("team_bootstrap_recovery_required"))?;
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms)?.record()?;
    if !crate::crypto::ed25519::verify(&device.sign_pub, &bytes(&unsigned)?, &signature) {
        return Err(bad("team_bootstrap_recovery_required"));
    }
    Ok(())
}

fn file_op(state: &StateDir, name: String, data: Vec<u8>) -> Result<Value> {
    let before = raw(state, &name)?;
    if before.is_some() {
        return Err(bad("team_bootstrap_existing_state_unsupported"));
    }
    Ok(
        json!({"kind":"file","path":name,"before":hash(before.as_deref()),"after":hex::encode(Sha256::digest(&data)),"data_b64":crate::pybase64::b64encode(&data)}),
    )
}
fn json_op(state: &StateDir, name: &str, keys: Vec<String>, after: Value) -> Result<Value> {
    let mut before = &raw_json(state, name)?;
    for key in &keys {
        before = &before[key];
    }
    if !before.is_null() {
        return Err(bad("team_bootstrap_existing_state_unsupported"));
    }
    Ok(json!({"kind":"patch","path":name,"keys":keys,"before":before,"after":after}))
}

fn patched(mut document: Value, op: &Value) -> Result<Value> {
    let name = text(op, "path")?;
    if ![
        crate::vault::VAULT_DOC,
        crate::policy::CONNECTIONS,
        crate::projects::DOC,
        crate::team::sync::ENVS_MAP_PATH,
        crate::tombstone::PATH,
    ]
    .contains(&name)
    {
        return Err(bad("team_bootstrap_recovery_required"));
    }
    if document.is_null() {
        document = json!({});
    }
    if op["kind"] == "project_environment" {
        if name != crate::projects::DOC {
            return Err(bad("team_bootstrap_recovery_required"));
        }
        let project = text(op, "project")?;
        let environment = text(op, "environment")?;
        crate::projects::validate_name(project, "project")?;
        crate::projects::validate_name(environment, "environment")?;
        let entry = document
            .as_object_mut()
            .ok_or_else(|| bad("team_bootstrap_install_conflict"))?
            .entry(project)
            .or_insert_with(|| op["initial"].clone());
        let envs = entry["environments"]
            .as_array_mut()
            .ok_or_else(|| bad("team_bootstrap_install_conflict"))?;
        if !envs.contains(&json!(environment)) {
            envs.push(json!(environment));
        }
    } else if op["kind"] == "patch" {
        let keys = op["keys"]
            .as_array()
            .ok_or_else(|| bad("team_bootstrap_recovery_required"))?;
        if keys.is_empty() || keys.len() > 8 {
            return Err(bad("team_bootstrap_recovery_required"));
        }
        let mut target = &mut document;
        for key in keys.iter().take(keys.len() - 1) {
            let key = key
                .as_str()
                .ok_or_else(|| bad("team_bootstrap_recovery_required"))?;
            target = target
                .as_object_mut()
                .ok_or_else(|| bad("team_bootstrap_install_conflict"))?
                .entry(key)
                .or_insert_with(|| json!({}));
        }
        let key = keys
            .last()
            .and_then(Value::as_str)
            .ok_or_else(|| bad("team_bootstrap_recovery_required"))?;
        let object = target
            .as_object_mut()
            .ok_or_else(|| bad("team_bootstrap_install_conflict"))?;
        let current = object.get(key).unwrap_or(&Value::Null);
        if current != &op["after"] {
            if current != &op["before"] {
                return Err(bad("team_bootstrap_install_conflict"));
            }
            object.insert(key.into(), op["after"].clone());
        }
    } else {
        return Err(bad("team_bootstrap_recovery_required"));
    }
    Ok(document)
}
fn check_budget(ctx: &Context, env: &str, journal: &Value) -> Result<()> {
    let staged = import_barrier::sync_staging(ctx.state, env)?;
    let mut targets = 0usize;
    let mut largest = 0usize;
    let mut shared = std::collections::BTreeMap::<String, Value>::new();
    for op in journal["ops"]
        .as_array()
        .ok_or_else(|| bad("team_bootstrap_recovery_required"))?
    {
        if op["kind"] == "file" {
            let size = text(op, "data_b64")?
                .len()
                .checked_mul(3)
                .and_then(|n| n.checked_div(4))
                .ok_or_else(|| bad("team_bootstrap_limit_exceeded"))?;
            targets = targets
                .checked_add(size)
                .ok_or_else(|| bad("team_bootstrap_limit_exceeded"))?;
            largest = largest.max(size);
        } else {
            let name = text(op, "path")?;
            let document = match shared.remove(name) {
                Some(v) => v,
                None => raw_json(ctx.state, name)?,
            };
            shared.insert(name.into(), patched(document, op)?);
        }
    }
    for document in shared.values() {
        let size = import_barrier::encoded_len(document)?;
        targets = targets
            .checked_add(size)
            .ok_or_else(|| bad("team_bootstrap_limit_exceeded"))?;
        largest = largest.max(size);
    }
    let journal_size = import_barrier::encoded_len(journal)?;
    if journal_size
        .checked_add(512)
        .and_then(|n| n.checked_mul(2))
        .and_then(|n| n.checked_add(staged))
        .and_then(|n| n.checked_add(targets))
        .and_then(|n| n.checked_add(largest))
        .is_none_or(|n| n > 64 * 1024 * 1024)
    {
        return Err(bad("team_bootstrap_limit_exceeded"));
    }
    Ok(())
}
fn apply(state: &StateDir, op: &Value) -> Result<()> {
    let name = text(op, "path")?;
    if op["kind"] == "file" {
        let encoded = text(op, "data_b64")?;
        if encoded.len() > 64 * 1024 * 1024 {
            return Err(bad("team_bootstrap_limit_exceeded"));
        }
        let data = crate::pybase64::b64decode_strict(encoded)
            .map_err(|_| bad("team_bootstrap_recovery_required"))?;
        if hash(Some(&data)) != op["after"] {
            return Err(bad("team_bootstrap_recovery_required"));
        }
        let current = raw(state, name)?;
        if hash(current.as_deref()) == op["after"] {
            return Ok(());
        }
        if hash(current.as_deref()) != op["before"] {
            return Err(bad("team_bootstrap_install_conflict"));
        }
        import_barrier::write(state, name, &data)
    } else {
        let before = raw_json(state, name)?;
        let after = patched(before.clone(), op)?;
        if before == after {
            return Ok(());
        }
        import_barrier::json(state, name, &after)
    }
}

pub(crate) fn ready(
    ctx: &Context,
    plan: &Plan,
    session: &dyn Session,
    control: &Value,
    challenge: &str,
    deadline: &Deadline,
) -> Result<Value> {
    deadline.check()?;
    let history = plan.resume(ctx)?;
    plan.recheck(ctx)?;
    let manifest = plan.manifest();
    let env = text(manifest, "env_id")?;
    discard_prepared(ctx, env)?;
    protocol::fields(
        control,
        &[
            "type",
            "domain",
            "env_id",
            "signer",
            "recipient",
            "approval_id",
            "invite_id",
            "authorization_id",
            "transfer_id",
            "manifest_hash",
            "session_nonce",
            "onboarding_nonce",
            "challenge",
            "sig",
        ],
    )?;
    if session.is_closed()
        || session.env_id() != env
        || control["domain"] != "zeropw-team-bootstrap-ready-v1"
        || control["type"] != "BOOTSTRAP_READY"
        || control["challenge"] != challenge
        || control["manifest_hash"] != digest(manifest)?
    {
        return Err(bad("team_bootstrap_ready_invalid"));
    }
    for key in [
        "env_id",
        "signer",
        "recipient",
        "approval_id",
        "invite_id",
        "transfer_id",
        "session_nonce",
        "onboarding_nonce",
    ] {
        if control[key] != manifest[key] {
            return Err(bad("team_bootstrap_ready_invalid"));
        }
    }
    if control["authorization_id"] != manifest["recipient_authorization_id"] {
        return Err(bad("team_bootstrap_ready_invalid"));
    }
    let mut unsigned = control.clone();
    let signature = unsigned
        .as_object_mut()
        .ok_or_else(|| bad("team_bootstrap_ready_invalid"))?
        .remove("sig")
        .ok_or_else(|| bad("team_bootstrap_ready_invalid"))?;
    let signature = crate::pybase64::b64decode_strict(
        signature
            .as_str()
            .ok_or_else(|| bad("team_bootstrap_ready_invalid"))?,
    )
    .map_err(|_| bad("team_bootstrap_ready_invalid"))?;
    if !crate::crypto::ed25519::verify(&session.peer().sign_pub, &bytes(&unsigned)?, &signature) {
        return Err(bad("team_bootstrap_ready_invalid"));
    }
    let transfer = text(manifest, "transfer_id")?;
    let stage_path = path(env, &format!("staging/{transfer}/view"))?;
    let stage = StateDir::new(ctx.state.path.join(&stage_path));
    // The durable helper creates and validates every private ancestor before
    // any ordinary writer or derive helper touches this private view.
    import_barrier::write(
        ctx.state,
        &format!("{stage_path}/.prepared"),
        b"personal-bootstrap-v1\n",
    )?;
    {
        let _stage_lock = stage.lock()?;
        let mut vault = raw_json(ctx.state, crate::vault::VAULT_DOC)?;
        vault["secrets"] = json!({});
        import_barrier::json(&stage, crate::vault::VAULT_DOC, &vault)?;
        import_barrier::json(&stage, crate::policy::CONNECTIONS, &json!({}))?;
        for (generation, wrapped) in plan.wrapped() {
            import_barrier::json(
                &stage,
                &format!("team/{env}/dek/{generation}.json"),
                wrapped,
            )?;
        }
        for f in plan.facts() {
            crate::tombstone::retain_fact(&stage, f)?;
        }
    }
    let policy = crate::policy::Policy::new(&stage, ctx.clock.clone());
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms)?;
    fold::derive_local(
        plan.folded(),
        &stage,
        &policy,
        None,
        Some(&device),
        Some(ctx.kms),
        Some(&plan.mapping().project),
        Some(&plan.mapping().environment),
    )?;
    import_barrier::sync_staging(ctx.state, env)?;
    let mut ops = Vec::new();
    let (manifest_raw, payload_raw) = plan.originals();
    ops.push(file_op(
        ctx.state,
        path(env, "provenance/manifest.json")?,
        manifest_raw.to_vec(),
    )?);
    ops.push(file_op(
        ctx.state,
        path(env, "provenance/payload.json")?,
        payload_raw.to_vec(),
    )?);
    ops.push(file_op(ctx.state,path(env,"provenance/basis.json")?,bytes(&json!({"v":1,"trust_model":"administrator_attested","manifest_hash":digest(manifest)?,"payload_sha256":manifest["payload"]["sha256"],"approval_id":manifest["approval_id"],"ready":control}))?)?);
    let number = plan
        .folded()
        .vector
        .values()
        .fold(crate::pyint::PyInt::zero(), |n, v| {
            crate::pyint::PyInt(n.0 + &v.0)
        });
    ops.push(file_op(
        ctx.state,
        format!("team/{env}/snapshots/{number}.json"),
        bytes(plan.snapshot())?,
    )?);
    let mut effects = fold::Facts::default();
    for fact in plan.facts() {
        crate::team::sync::apply_fact(&mut effects, fact);
    }
    ops.push(file_op(
        ctx.state,
        format!("team/{env}/snapshot_records/{number}.json"),
        bytes(&fold::snapshot_record(Some(&effects), plan.commits()))?,
    )?);
    for c in plan.commits() {
        ops.push(file_op(
            ctx.state,
            format!("team/{env}/commits/{}/{}.json", c.author, c.author_seq),
            bytes(&c.to_dict())?,
        )?);
    }
    for (generation, wrapped) in plan.wrapped() {
        ops.push(file_op(
            ctx.state,
            format!("team/{env}/dek/{generation}.json"),
            bytes(wrapped)?,
        )?);
    }
    let mut fact_lines = Vec::new();
    let mut receipts = Vec::new();
    for fact in plan.facts() {
        let mut b = bytes(&fact.to_dict())?;
        b.push(b'\n');
        fact_lines.extend(b);
        let h = fact.hash()?;
        let sig = device.sign(&bytes(
            &json!({"domain":"zeropw-local-fact-admission-v1","env_id":env,"hash":h}),
        )?)?;
        let mut b = bytes(&json!({"hash":h,"sig":crate::pybase64::b64encode(&sig)}))?;
        b.push(b'\n');
        receipts.extend(b);
    }
    ops.push(file_op(
        ctx.state,
        format!("team/{env}/facts.jsonl"),
        fact_lines,
    )?);
    ops.push(file_op(
        ctx.state,
        format!("team/{env}/fact_admissions.jsonl"),
        receipts,
    )?);
    let derived = raw_json(&stage, crate::vault::VAULT_DOC)?;
    for (id, entry) in derived["secrets"].as_object().into_iter().flatten() {
        ops.push(json_op(
            ctx.state,
            crate::vault::VAULT_DOC,
            vec!["secrets".into(), id.clone()],
            entry.clone(),
        )?);
    }
    let connections = raw_json(&stage, crate::policy::CONNECTIONS)?;
    for (id, entry) in connections.as_object().into_iter().flatten() {
        let mut entry = entry.clone();
        entry["project"] = json!(plan.mapping().project);
        entry["environment"] = json!(plan.mapping().environment);
        ops.push(json_op(
            ctx.state,
            crate::policy::CONNECTIONS,
            vec![id.clone()],
            entry,
        )?);
    }
    let ledger = crate::tombstone::load(&stage)?;
    for (kind, groups) in ledger.as_object().into_iter().flatten() {
        for (id, value) in groups.as_object().into_iter().flatten() {
            let existing = raw_json(ctx.state, crate::tombstone::PATH)?;
            if !existing[kind][id].is_null() && existing[kind][id] != *value {
                return Err(bad("team_bootstrap_install_conflict"));
            }
            if existing[kind][id].is_null() {
                ops.push(json_op(
                    ctx.state,
                    crate::tombstone::PATH,
                    vec![kind.clone(), id.clone()],
                    value.clone(),
                )?);
            }
        }
    }
    let mapping =
        json!({"project":plan.mapping().project,"environment":plan.mapping().environment});
    if raw_json(ctx.state, crate::team::sync::ENVS_MAP_PATH)?[env] != mapping {
        ops.push(json_op(
            ctx.state,
            crate::team::sync::ENVS_MAP_PATH,
            vec![env.into()],
            mapping,
        )?);
    }
    ops.push(json!({"kind":"project_environment","path":crate::projects::DOC,"project":plan.mapping().project,"environment":plan.mapping().environment,"initial":{"created_at":crate::store::iso(Some((ctx.clock)())),"environments":[]}}));
    let epoch = random(16);
    let targets = targets_hash(&ops)?;
    let mut secret_ids = plan.folded().document["secrets"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(id, _)| id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let mut connection_ids = plan.folded().document["connections"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(id, _)| id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for fact in plan.facts() {
        if let Some(id) = fact.target["secret_id"].as_str() {
            secret_ids.insert(id.into());
        }
        if let Some(id) = fact.target["connection_id"].as_str() {
            connection_ids.insert(id.into());
        }
    }
    let receipt = signed(
        ctx,
        json!({"domain":"zeropw-team-bootstrap-receipt-v1","v":1,"env_id":env,"signer":manifest["signer"],"recipient":manifest["recipient"],"approval_id":manifest["approval_id"],"authorization_id":manifest["recipient_authorization_id"],"transfer_id":manifest["transfer_id"],"manifest_hash":digest(manifest)?,"payload_sha256":manifest["payload"]["sha256"],"vector":manifest["vector"],"tombstone_digest":manifest["tombstone_digest"],"trust_model":"administrator_attested","epoch":epoch,"ready_sha256":digest(control)?,"target_digests_sha256":targets}),
        &history,
    )?;
    ops.push(file_op(
        ctx.state,
        path(env, "receipt.json")?,
        bytes(&receipt)?,
    )?);
    let visibility = signed(
        ctx,
        json!({"domain":"zeropw-personal-import-visibility-v1","env_id":env,"state":"installing","epoch":epoch,"project":plan.mapping().project,"environment":plan.mapping().environment,"secret_ids":secret_ids,"connection_ids":connection_ids,"manifest_hash":digest(manifest)?}),
        &history,
    )?;
    let mut journal = json!({"domain":"zeropw-personal-import-journal-v1","v":1,"env_id":env,"state":"PREPARED","epoch":epoch,"manifest_hash":digest(manifest)?,"ready":control,"receipt":receipt,"visibility":visibility,"ops":ops});
    check_budget(ctx, env, &journal)?;
    journal = signed(ctx, journal, &history)?;
    import_barrier::json(ctx.state, &path(env, "journal.json")?, &journal)?;
    deadline.check()?;
    plan.recheck(ctx)?;
    if session.is_closed() {
        return Err(bad("team_bootstrap_peer_offline"));
    }
    let mut index = import_barrier::index(ctx.state)?;
    if index.get(env).is_some()
        || index
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(_, v)| v["state"] != "committed")
            .count()
            >= 2
    {
        return Err(bad("team_bootstrap_busy"));
    }
    ctx.state.bind_import_identity(device.record()?)?;
    index[env] = visibility;
    // Persist the barrier before the first ordinary target write. A PREPARED
    // journal is discardable; this durable INSTALLING intent is recoverable.
    history.check()?;
    import_barrier::json(ctx.state, import_barrier::INDEX, &index)?;
    journal["state"] = json!("INSTALLING");
    journal = signed(ctx, journal, &history)?;
    import_barrier::json(ctx.state, &path(env, "journal.json")?, &journal)?;
    let receipt = finish(ctx, env, &mut journal, &history)?;
    import_barrier::discard_staging(ctx.state, env)?;
    history.check()?;
    Ok(receipt)
}

pub(crate) fn discard_prepared(ctx: &Context, env: &str) -> Result<()> {
    let _lock = ctx.state.lock()?;
    if import_barrier::index(ctx.state)?.get(env).is_some() {
        return Ok(());
    }
    let p = path(env, "journal.json")?;
    if let Some(data) = raw(ctx.state, &p)? {
        let journal = pyjson::loads(
            std::str::from_utf8(&data).map_err(|_| bad("team_bootstrap_recovery_required"))?,
        )
        .map_err(|_| bad("team_bootstrap_recovery_required"))?;
        verified(ctx, &journal)?;
        if journal["state"] != "PREPARED"
            || journal["env_id"] != env
            || journal["domain"] != "zeropw-personal-import-journal-v1"
        {
            return Err(bad("team_bootstrap_recovery_required"));
        }
        fs::remove_file(ctx.state.path.join(&p))
            .map_err(|_| bad("team_bootstrap_storage_failed"))?;
        fs::File::open(
            ctx.state
                .path
                .join(&p)
                .parent()
                .ok_or_else(|| bad("team_bootstrap_storage_failed"))?,
        )
        .and_then(|f| f.sync_all())
        .map_err(|_| bad("team_bootstrap_storage_failed"))?;
    }
    import_barrier::discard_staging(ctx.state, env)
}

fn finish(
    ctx: &Context,
    env: &str,
    journal: &mut Value,
    history: &crate::team::commit::HistorySession<'_>,
) -> Result<Value> {
    verified(ctx, journal)?;
    check_budget(ctx, env, journal)?;
    let ops = journal["ops"]
        .as_array()
        .ok_or_else(|| bad("team_bootstrap_recovery_required"))?;
    let (receipt_op, targets) = ops
        .split_last()
        .ok_or_else(|| bad("team_bootstrap_recovery_required"))?;
    if receipt_op["path"] != path(env, "receipt.json")?
        || journal["receipt"]["target_digests_sha256"] != targets_hash(targets)?
    {
        return Err(bad("team_bootstrap_recovery_required"));
    }
    for op in journal["ops"]
        .as_array()
        .ok_or_else(|| bad("team_bootstrap_recovery_required"))?
    {
        history.check()?;
        apply(ctx.state, op)?;
        history.check()?;
    }
    #[cfg(test)]
    crate::import_barrier::testing::hit(ctx.state, env, "audit-before")?;
    ctx.audit.record(
        "team_join_approved",
        crate::audit::RecordArgs {
            result: Some("ok"),
            extra: vec![
                ("env_id", json!(env)),
                ("detail", journal["manifest_hash"].clone()),
                ("state", json!("bootstrap_activation_pending")),
            ],
            ..Default::default()
        },
    )?;
    #[cfg(test)]
    crate::import_barrier::testing::hit(ctx.state, env, "audit-after")?;
    for directory in [ctx.state.path.join("audit"), ctx.state.path.clone()] {
        #[cfg(test)]
        crate::import_barrier::testing::hit(ctx.state, env, "audit-parent-fsync-before")?;
        fs::File::open(directory)
            .and_then(|f| f.sync_all())
            .map_err(|_| bad("team_bootstrap_storage_failed"))?;
        #[cfg(test)]
        crate::import_barrier::testing::hit(ctx.state, env, "audit-parent-fsync-after")?;
    }
    let mut index = import_barrier::index(ctx.state)?;
    if index[env]["epoch"] != journal["epoch"] {
        return Err(bad("team_bootstrap_install_conflict"));
    }
    index[env]["state"] = json!("committed");
    index[env]["receipt_sha256"] = json!(digest(&journal["receipt"])?);
    index[env] = signed(ctx, index[env].clone(), history)?;
    history.check()?;
    import_barrier::json(ctx.state, import_barrier::INDEX, &index)?;
    journal["state"] = json!("COMMITTED");
    *journal = signed(ctx, journal.clone(), history)?;
    import_barrier::json(ctx.state, &path(env, "journal.json")?, journal)?;
    Ok(journal["receipt"].clone())
}

pub(crate) fn recover(ctx: &Context, env: &str) -> Result<()> {
    // An ordinary environment has no import journal or recovery work. Keep
    // that path lazy, including its absence of device-key creation.
    let journal_path = ctx
        .state
        .path
        .join(format!("team/{env}/bootstrap/journal.json"));
    if matches!(fs::symlink_metadata(&journal_path),Err(error) if error.kind()==std::io::ErrorKind::NotFound)
    {
        return Ok(());
    }
    let history = crate::team::commit::HistorySession::open_probe(
        ctx,
        env,
        crate::team::commit::ProbePurpose::Recipient,
    )?;
    recover_with_input(ctx, env, &history)
}
pub(crate) fn recover_with_input(
    ctx: &Context,
    env: &str,
    parent: &crate::team::commit::HistorySession<'_>,
) -> Result<()> {
    if matches!(fs::symlink_metadata(ctx.state.path.join(format!("team/{env}/bootstrap/journal.json"))),Err(error) if error.kind()==std::io::ErrorKind::NotFound)
    {
        return Ok(());
    }
    let history = parent.nested(ctx.state, env)?;
    let p = path(env, "journal.json")?;
    if !ctx.state.exists(&p) {
        return Ok(());
    }
    let mut journal = history.journal_record()?;
    verified(ctx, &journal)?;
    if journal["env_id"] != env || journal["domain"] != "zeropw-personal-import-journal-v1" {
        return Err(bad("team_bootstrap_recovery_required"));
    }
    // The visibility record is the commit point. A crash immediately after
    // it must never replay initial patches over ordinary post-cut edits.
    let visibility = import_barrier::index(ctx.state)?;
    if visibility[env]["state"] == "committed" {
        if visibility[env]["epoch"] != journal["epoch"]
            || receipt_evidence(ctx, env, &history)? != journal["receipt"]
        {
            return Err(bad("team_bootstrap_recovery_required"));
        }
        if journal["state"] != "COMMITTED" {
            journal["state"] = json!("COMMITTED");
            journal = signed(ctx, journal, &history)?;
            import_barrier::json(ctx.state, &p, &journal)?;
        }
        import_barrier::discard_staging(ctx.state, env)?;
        return Ok(());
    }
    match journal["state"].as_str() {
        Some("PREPARED") if import_barrier::index(ctx.state)?.get(env).is_none() => Ok(()),
        Some("PREPARED" | "INSTALLING") => {
            finish(ctx, env, &mut journal, &history)?;
            import_barrier::discard_staging(ctx.state, env)?;
            Ok(())
        }
        Some("COMMITTED") => {
            receipt_evidence(ctx, env, &history)?;
            Ok(())
        }
        _ => Err(bad("team_bootstrap_recovery_required")),
    }
}

pub(crate) fn receipt(ctx: &Context, env: &str) -> Result<Value> {
    let history = crate::team::commit::HistorySession::open_runtime(ctx.state, env)?;
    let value = receipt_evidence(ctx, env, &history)?;
    if import_barrier::index(ctx.state)?[env]["local_member_removed"] == true
        || ctx.policy.restore_pending()?
    {
        return Err(bad("team_bootstrap_recovery_required"));
    }
    Ok(value)
}
fn receipt_evidence(
    ctx: &Context,
    env: &str,
    parent: &crate::team::commit::HistorySession<'_>,
) -> Result<Value> {
    let history = parent.nested(ctx.state, env)?;
    history.preflight_inventory()?;
    let value = raw_json(ctx.state, &path(env, "receipt.json")?)?;
    verified(ctx, &value)?;
    let index = import_barrier::index(ctx.state)?;
    if index[env]["state"] != "committed"
        || index[env]["epoch"] != value["epoch"]
        || index[env]["receipt_sha256"] != digest(&value)?
    {
        return Err(bad("team_bootstrap_recovery_required"));
    }
    import_barrier::immutable(ctx.state, env, &index[env])?;
    let manifest = raw(ctx.state, &path(env, "provenance/manifest.json")?)?
        .ok_or_else(|| bad("team_bootstrap_recovery_required"))?;
    let manifest = pyjson::loads(
        std::str::from_utf8(&manifest).map_err(|_| bad("team_bootstrap_recovery_required"))?,
    )
    .map_err(|_| bad("team_bootstrap_recovery_required"))?;
    if digest(&manifest)? != text(&value, "manifest_hash")? {
        return Err(bad("team_bootstrap_recovery_required"));
    }
    let vector = CommitStore::new(ctx.state, env).vector()?;
    for (fp, seq) in value["vector"].as_object().into_iter().flatten() {
        let floor = crate::pyint::PyInt::from_json_integer(seq)
            .ok_or_else(|| bad("team_bootstrap_recovery_required"))?;
        if vector.get(fp).is_none_or(|n| n < &floor) {
            return Err(bad("team_bootstrap_recovery_required"));
        }
    }
    let journal = history.journal_record()?;
    verified(ctx, &journal)?;
    if journal["domain"] != "zeropw-personal-import-journal-v1"
        || journal["env_id"] != env
        || journal["epoch"] != value["epoch"]
        || journal["receipt"] != value
        || journal["manifest_hash"] != value["manifest_hash"]
        || !matches!(journal["state"].as_str(), Some("INSTALLING" | "COMMITTED"))
    {
        return Err(bad("team_bootstrap_recovery_required"));
    }
    history.check()?;
    Ok(value)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        clock,
        context::Config,
        team::{
            bootstrap::{self, approval},
            commit::{self, Commit},
            membership,
            sync::TeamSync,
            transport::TcpTransport,
        },
    };
    use std::{
        os::unix::fs::{DirBuilderExt, PermissionsExt},
        sync::Arc,
        time::{Duration, Instant},
    };
    const PASS: &str = "synthetic-install-fault-administrator";
    const VALUE: &[u8] = b"synthetic-install-fault-value";
    struct Stop(Vec<Arc<TeamSync>>);
    impl Drop for Stop {
        fn drop(&mut self) {
            for team in self.0.iter().rev() {
                team.stop();
            }
        }
    }
    fn context(root: &std::path::Path) -> Arc<Context> {
        Arc::new(
            Context::initialize(
                root,
                PASS,
                "synthetic-install-fault-recovery",
                Config::default(),
                clock::system(),
            )
            .unwrap(),
        )
    }
    fn append(ctx: &Context, key: &DeviceKey, env: &str, seq: i64, ops: Vec<Value>) -> Commit {
        let _lock = ctx.state.lock().unwrap();
        let store = CommitStore::new(ctx.state, env);
        let c = commit::sign_commit(
            key,
            env,
            seq,
            &format!("{}-0000", 1_000_000 + seq),
            &store.vector().unwrap(),
            ops,
        )
        .unwrap();
        store.append(&c).unwrap();
        c
    }
    fn copy_tree(source: &std::path::Path, target: &std::path::Path) {
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
                copy_tree(&entry.path(), &target);
            } else {
                assert!(metadata.is_file());
                fs::copy(entry.path(), &target).unwrap();
                fs::set_permissions(target, metadata.permissions()).unwrap();
            }
        }
    }

    pub(crate) struct Pending {
        pub(crate) root: tempfile::TempDir,
        pub(crate) a: Arc<Context>,
        pub(crate) b: Arc<Context>,
        pub(crate) env: String,
        pub(crate) pending: Value,
        pub(crate) invitation: membership::CreatedInvite,
        stop: Stop,
    }
    pub(crate) fn pending() -> Pending {
        let root = tempfile::tempdir().unwrap();
        let a = context(&root.path().join("a"));
        let b = context(&root.path().join("b"));
        a.projects.create("personal", &["vault"]).unwrap();
        b.projects.create("unrelated", &["dev"]).unwrap();
        b.vault
            .put_secret("unrelated", "api_key", VALUE, "unrelated", "dev", true)
            .unwrap();
        let ak = DeviceKey::load_or_create(a.state, a.kms).unwrap();
        let bk = DeviceKey::load_or_create(b.state, b.kms).unwrap();
        let fp = ak.fingerprint().unwrap();
        let env = format!("{fp}-0123456789abcdef0123456789abcdef");
        crate::team::sync::write_env_mapping(a.state, &env, "personal", "vault").unwrap();
        let generation = "0123456789abcdef";
        let wrap =
            crate::team::envelope::wrap_dek(&[7; 32], &env, generation, &ak.record().unwrap())
                .unwrap();
        append(
            &a,
            &ak,
            &env,
            1,
            vec![
                json!({"op":"env.init","owner_device":ak.record().unwrap().to_dict(),"owner_name":"original owner","generation_id":generation,"wraps":{fp.clone():wrap}}),
            ],
        );
        let cipher = crate::team::envelope::encrypt_secret(
            &[7; 32],
            &env,
            "alpha",
            "1111111111111111",
            VALUE,
        )
        .unwrap();
        let ssh = crate::sshwire::Ed25519PrivateKey::from_seed(&[8; 32], "synthetic-personal-user")
            .unwrap();
        let host =
            crate::sshwire::Ed25519PrivateKey::from_seed(&[9; 32], "synthetic-personal-host")
                .unwrap();
        append(
            &a,
            &ak,
            &env,
            2,
            vec![
                json!({"op":"secret.put_version","secret_id":"alpha","version_id":"1111111111111111","generation_id":generation,"kind":"api_key","ciphertext":cipher,"public":{}}),
                json!({"op":"secret.activate","secret_id":"alpha","version_id":"1111111111111111"}),
                json!({"op":"secret.put_version","secret_id":"ssh-key","version_id":"6666666666666666","generation_id":generation,"kind":"ssh_private_key","ciphertext":crate::team::envelope::encrypt_secret(&[7;32],&env,"ssh-key","6666666666666666",ssh.to_openssh_private_key().as_bytes()).unwrap(),"public":{"public_key":ssh.public.to_authorized_key("synthetic-personal-user").unwrap()}}),
                json!({"op":"secret.activate","secret_id":"ssh-key","version_id":"6666666666666666"}),
                json!({"op":"connection.create","id":"ssh","project":"personal","environment":"vault","service":"synthetic","kind":"ssh","secret_id":"ssh-key","secret_version":null,"description":"","ssh_target":{"host":"127.0.0.1","port":2222,"username":"deploy","host_keys":[host.public.to_authorized_key("synthetic-personal-host").unwrap()]}}),
            ],
        );
        let at = TcpTransport::new(ak.clone(), Arc::new(|_, _| None), 64);
        let ta = TeamSync::new(a.clone(), Arc::new(at.clone()), ak.clone());
        ta.start(Some("127.0.0.1:0")).unwrap();
        let mut stop = Stop(vec![ta.clone()]);
        ta.compact(&env).unwrap();
        append(
            &a,
            &ak,
            &env,
            3,
            vec![json!({"op":"settings.update","sync_interval_seconds":12})],
        );
        ta.compact(&env).unwrap();
        let invitation = membership::create_invite_opts(
            &a,
            &env,
            "admin",
            "fresh admin",
            600,
            &[at.bound_address().unwrap()],
            false,
            true,
        )
        .unwrap();
        approval::enable(&a, &env, &invitation.invite_id, None).unwrap();
        let bt = TcpTransport::new(bk.clone(), Arc::new(|_, _| None), 64);
        let tb = TeamSync::new(b.clone(), Arc::new(bt.clone()), bk.clone());
        tb.start(None).unwrap();
        stop.0.push(tb.clone());
        let pending = membership::join(
            &b,
            &invitation.invite,
            &bt,
            &tb,
            Some("personal"),
            Some("vault"),
            10.0,
        )
        .unwrap();
        let request = approval::list(&a, &env).unwrap().remove(0);
        approval::approve(
            &a,
            &env,
            text(&request, "request_id").unwrap(),
            text(&request, "record_binding").unwrap(),
            PASS,
        )
        .unwrap();
        Pending {
            root,
            a,
            b,
            env,
            pending,
            invitation,
            stop,
        }
    }

    pub(crate) fn installed() -> Pending {
        let fixture = pending();
        approval::approve_receiver(
            &fixture.b,
            &fixture.env,
            text(&fixture.pending, "inviter_record_binding").unwrap(),
            text(&fixture.pending, "self_record_binding").unwrap(),
            PASS,
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(35);
        while import_barrier::index(fixture.b.state).unwrap()[&fixture.env]["state"] != "committed"
        {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(20));
        }
        for team in fixture.stop.0.iter().rev() {
            team.stop();
        }
        fixture
    }

    #[test]
    fn personal_bootstrap_actual_ready_journal_recovers_every_install_io_edge_without_partial_visibility()
     {
        let Pending {
            root,
            a,
            b,
            env,
            pending,
            stop,
            ..
        } = pending();
        let bk = DeviceKey::load_or_create(b.state, b.kms).unwrap();
        // Stop only after an actual challenged READY and durable intent. The
        // captured journal was produced by the full encrypted runtime/validator.
        let fault = import_barrier::testing::Scope::named(
            b.state,
            "journal.json",
            "final-readback-after",
            2,
        );
        approval::approve_receiver(
            &b,
            &env,
            text(&pending, "inviter_record_binding").unwrap(),
            text(&pending, "self_record_binding").unwrap(),
            PASS,
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(35);
        while !fault.fired() {
            assert!(
                Instant::now() < deadline,
                "actual install intent not reached"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(stop);
        drop(fault);
        assert_eq!(
            raw_json(b.state, &path(&env, "journal.json").unwrap()).unwrap()["state"],
            "INSTALLING"
        );
        assert!(b.vault.secret_for_trusted_use("alpha", None).is_err());
        let auth = a
            .state
            .read_json(
                &bootstrap::path(
                    &env,
                    &format!("authorizations/{}.json", bk.fingerprint().unwrap()),
                )
                .unwrap(),
                Value::Null,
            )
            .unwrap();
        assert_ne!(auth["activated"], true);
        let baseline = root.path().join("baseline");
        copy_tree(&b.state.path, &baseline);
        let baseline = Context::open(&baseline, Config::default(), clock::system()).unwrap();
        let track = import_barrier::testing::Scope::track(baseline.state, None);
        recover(&baseline, &env).unwrap();
        let edges = track.hits();
        drop(track);
        assert!(edges.iter().any(|(_, edge)| edge == "rename-after"));
        assert!(
            edges
                .iter()
                .any(|(_, edge)| edge == "audit-parent-fsync-after")
        );
        for index in 0..edges.len() {
            let copy = root.path().join(format!("fault-{index}"));
            copy_tree(&b.state.path, &copy);
            let ctx = Context::open(&copy, Config::default(), clock::system()).unwrap();
            let fault = import_barrier::testing::Scope::track(ctx.state, Some(index));
            let result = recover(&ctx, &env);
            assert!(fault.fired(), "unreached I/O edge {index}");
            assert!(result.is_err());
            drop(fault);
            let visibility = import_barrier::index(ctx.state).unwrap();
            if visibility[&env]["state"] == "committed" {
                assert!(
                    ctx.vault
                        .secret_for_trusted_use("alpha", None)
                        .unwrap()
                        .ct_eq(VALUE)
                );
            } else {
                assert!(ctx.vault.secret_for_trusted_use("alpha", None).is_err());
                assert!(
                    !ctx.vault
                        .list_secrets(None, None)
                        .unwrap()
                        .iter()
                        .any(|s| s.id == "alpha")
                );
            }
            assert!(
                ctx.vault
                    .secret_for_trusted_use("unrelated", None)
                    .unwrap()
                    .ct_eq(VALUE)
            );
            if visibility[&env]["state"] != "committed" {
                let _lock = ctx.state.lock().unwrap();
                let mut projects = ctx
                    .state
                    .read_json(crate::projects::DOC, json!({}))
                    .unwrap();
                projects["personal"] =
                    json!({"created_at":"synthetic-unrelated-edit","environments":["other"]});
                ctx.state
                    .write_json(crate::projects::DOC, &projects)
                    .unwrap();
            }
            let reopened = Context::open(&copy, Config::default(), clock::system()).unwrap();
            recover(&reopened, &env).unwrap();
            let receipt = receipt(&reopened, &env).unwrap();
            recover(&reopened, &env).unwrap();
            assert_eq!(receipt, super::receipt(&reopened, &env).unwrap());
            assert!(
                reopened
                    .vault
                    .secret_for_trusted_use("alpha", None)
                    .unwrap()
                    .ct_eq(VALUE)
            );
            assert!(
                reopened
                    .vault
                    .secret_for_trusted_use("unrelated", None)
                    .unwrap()
                    .ct_eq(VALUE)
            );
            if visibility[&env]["state"] != "committed" {
                assert!(
                    reopened
                        .projects
                        .require_environment("personal", "other")
                        .is_ok()
                );
            }
        }
        println!("PVBOOT_INSTALL_FAULT_EDGES={}", edges.len());
        let selected = edges
            .iter()
            .enumerate()
            .filter(|(_, (_, point))| {
                [
                    "rename-before",
                    "rename-after",
                    "parent-fsync-before",
                    "parent-fsync-after",
                    "audit-before",
                    "audit-after",
                    "staging-unlink-before",
                    "staging-unlink-after",
                ]
                .contains(&point.as_str())
            })
            .fold(
                std::collections::BTreeMap::new(),
                |mut m, (index, (_, point))| {
                    m.entry(point).or_insert(index);
                    m
                },
            );
        for index in selected.values() {
            let copy = root.path().join(format!("process-crash-{index}"));
            copy_tree(&b.state.path, &copy);
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "team::bootstrap::install::tests::personal_bootstrap_recovery_crash_child",
                    "--nocapture",
                ])
                .env("PVBOOT_OWN_RECOVERY_STATE", &copy)
                .env("PVBOOT_OWN_RECOVERY_ENV", &env)
                .env("PVBOOT_OWN_RECOVERY_EDGE", index.to_string())
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(86),
                "independent child did not reach selected edge"
            );
            let reopened = Context::open(&copy, Config::default(), clock::system()).unwrap();
            if import_barrier::index(reopened.state).unwrap()[&env]["state"] != "committed" {
                assert!(
                    reopened
                        .vault
                        .secret_for_trusted_use("alpha", None)
                        .is_err()
                );
            }
            recover(&reopened, &env).unwrap();
            assert!(
                reopened
                    .vault
                    .secret_for_trusted_use("alpha", None)
                    .unwrap()
                    .ct_eq(VALUE)
            );
            assert_eq!(
                receipt(&reopened, &env).unwrap(),
                super::receipt(&baseline, &env).unwrap()
            );
        }
        println!("PVBOOT_INDEPENDENT_PROCESS_CRASH_EDGES={}", selected.len());
    }

    #[test]
    fn personal_bootstrap_recovery_crash_child() {
        let Some(root) = std::env::var_os("PVBOOT_OWN_RECOVERY_STATE") else {
            return;
        };
        let env = std::env::var("PVBOOT_OWN_RECOVERY_ENV").unwrap();
        let edge = std::env::var("PVBOOT_OWN_RECOVERY_EDGE")
            .unwrap()
            .parse()
            .unwrap();
        let ctx = Context::open(root, Config::default(), clock::system()).unwrap();
        let _crash = import_barrier::testing::Scope::crash(ctx.state, edge);
        recover(&ctx, &env).unwrap();
        panic!("unreached crash edge");
    }

    #[test]
    fn personal_bootstrap_admission_intent_recovers_every_io_edge_with_one_original() {
        use hmac::{Hmac, Mac};
        let Pending {
            root,
            a,
            b,
            env,
            invitation,
            stop,
            ..
        } = pending();
        drop(stop);
        let invite = membership::parse_invite(&invitation.invite).unwrap();
        let peer = DeviceKey::load_or_create(b.state, b.kms)
            .unwrap()
            .record()
            .unwrap();
        let transcript = b"synthetic-admission-recovery-transcript";
        let mut mac = Hmac::<Sha256>::new_from_slice(invite.invite_secret.expose()).unwrap();
        mac.update(transcript);
        let proof = mac.finalize().into_bytes();
        let baseline = root.path().join("admission-baseline");
        copy_tree(&a.state.path, &baseline);
        let ctx = Context::open(&baseline, Config::default(), clock::system()).unwrap();
        let track = import_barrier::testing::Scope::track(ctx.state, None);
        assert!(matches!(
            approval::check(&ctx, &env, &peer, transcript, &proof).unwrap(),
            Some(crate::team::transport::InviteDecision::Accept)
        ));
        let edges = track.hits();
        drop(track);
        for index in 0..edges.len() {
            let copy = root.path().join(format!("admission-fault-{index}"));
            copy_tree(&a.state.path, &copy);
            let ctx = Context::open(&copy, Config::default(), clock::system()).unwrap();
            let fault = import_barrier::testing::Scope::track(ctx.state, Some(index));
            assert!(approval::check(&ctx, &env, &peer, transcript, &proof).is_err());
            assert!(fault.fired());
            drop(fault);
            let auth_path =
                path(&env, &format!("authorizations/{}.json", peer.fingerprint())).unwrap();
            let captured = ctx.state.read_json(&auth_path, Value::Null).unwrap();
            let reopened = Context::open(&copy, Config::default(), clock::system()).unwrap();
            approval::recover_all(&reopened, &env).unwrap();
            let _ = approval::check(&reopened, &env, &peer, transcript, &proof).unwrap();
            approval::recover_all(&reopened, &env).unwrap();
            let auth = reopened.state.read_json(&auth_path, Value::Null).unwrap();
            let original = Commit::from_dict(&auth["admission"]).unwrap();
            if !captured.is_null() {
                assert_eq!(captured["admission"], auth["admission"]);
            }
            let commits = CommitStore::new(reopened.state, &env)
                .all_commits()
                .unwrap();
            assert_eq!(
                commits
                    .iter()
                    .filter(|c| c.ops.iter().any(|o| o["op"] == "member.add"))
                    .count(),
                1
            );
            assert!(commits.iter().any(|c| c.to_dict() == original.to_dict()));
            let invites = reopened
                .state
                .read_json(&format!("team/{env}/invites.json"), Value::Null)
                .unwrap();
            assert_eq!(invites[&invitation.invite_id]["used"], true);
            assert_eq!(
                invites[&invitation.invite_id]["used_by"],
                peer.fingerprint()
            );
        }
        println!("PVBOOT_ADMISSION_FAULT_EDGES={}", edges.len());
    }
    #[test]
    fn personal_bootstrap_attempt_label_cannot_publish_ready_without_committed_epoch() {
        let fixture = pending();
        let p = path(&fixture.env, "attempt.json").unwrap();
        {
            // Fixture corruption still obeys the writer's actual-lock rule.
            // The status call below must acquire its own fresh operation.
            let _lock = fixture.b.state.lock().unwrap();
            let mut attempt = fixture.b.state.read_json(&p, Value::Null).unwrap();
            attempt["state"] = json!("ready");
            import_barrier::json(fixture.b.state, &p, &attempt).unwrap();
        }
        let status = bootstrap::status(&fixture.b, &fixture.env).unwrap();
        assert_eq!(status["state"], "recovery_required");
        assert_eq!(status["reason"], "team_bootstrap_state_invalid");
        assert!(
            import_barrier::index(fixture.b.state)
                .unwrap()
                .get(&fixture.env)
                .is_none()
        );
        assert!(
            !fixture
                .b
                .state
                .exists(&path(&fixture.env, "receipt.json").unwrap())
        );
        assert!(
            fixture
                .b
                .vault
                .secret_for_trusted_use("alpha", None)
                .is_err()
        );
        assert!(
            fixture
                .b
                .vault
                .secret_for_trusted_use("unrelated", None)
                .unwrap()
                .ct_eq(VALUE)
        );
    }
    #[test]
    fn personal_bootstrap_cancel_before_intent_is_closed_and_retains_unrelated_state() {
        let fixture = pending();
        let ctx = &fixture.b;
        let env = &fixture.env;
        assert_eq!(
            bootstrap::cancel(ctx, env).unwrap()["reason"],
            "team_bootstrap_cancelled"
        );
        assert_eq!(
            approval::approve_receiver(
                ctx,
                env,
                text(&fixture.pending, "inviter_record_binding").unwrap(),
                text(&fixture.pending, "self_record_binding").unwrap(),
                PASS
            )
            .unwrap_err()
            .reason,
            "team_bootstrap_cancelled"
        );
        assert!(import_barrier::index(ctx.state).unwrap().get(env).is_none());
        assert!(!ctx.state.exists(&path(env, "receipt.json").unwrap()));
        assert!(
            ctx.vault
                .secret_for_trusted_use("unrelated", None)
                .unwrap()
                .ct_eq(VALUE)
        );
        let expires = Context::open(
            &ctx.state.path,
            Config::default(),
            Arc::new(|| clock::now() + 601.0),
        )
        .unwrap();
        assert!(matches!(
            bootstrap::status(&expires, env).unwrap()["state"].as_str(),
            Some("unsupported")
        ));
    }
}
