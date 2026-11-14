//! Signed, replayable install journal. Shared documents are patched at reserved
//! identities; recovery never replaces an unrelated document with an old image.
use super::{
    bad, bytes, digest, path,
    protocol::{self, Deadline},
    random, text,
};
#[cfg(test)]
use crate::team::{commit::CommitStore, identity::DeviceKey};
use crate::{
    context::Context,
    errors::Result,
    import_barrier, pyjson,
    store::StateDir,
    team::{checkpoint::personal::Plan, fold, transport::Session},
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
    history.reserve_import_signature(&record)?;
    record
        .as_object_mut()
        .ok_or_else(|| bad("team_bootstrap_state_invalid"))?
        .remove("sig");
    let device = history.load_device(ctx)?;
    history.match_local_identity(&device.record()?)?;
    history.check()?;
    record["sig"] = json!(crate::pybase64::b64encode(&device.sign(&bytes(&record)?)?));
    history.check()?;
    Ok(record)
}

fn compact_committed(
    ctx: &Context,
    env: &str,
    journal: &Value,
    full_raw: &[u8],
    history: &crate::team::commit::HistorySession<'_>,
) -> Result<Value> {
    use crate::team::{
        commit::{Commit, verify_commit},
        identity::DeviceRecord,
    };
    let io = history.import_io()?;
    let manifest_raw = io
        .read(&path(env, "provenance/manifest.json")?, 65_536)?
        .ok_or_else(|| bad("team_bootstrap_recovery_required"))?;
    let manifest = io.parse(&manifest_raw, 65_536)?;
    let receiver = io
        .json(&path(env, "receiver.json")?, 65_536)?
        .ok_or_else(|| bad("team_bootstrap_recovery_required"))?;
    verified(ctx, &receiver, history)?;
    let owner = DeviceRecord::from_dict(&receiver["signer_record"])?;
    let recipient = history.local_record()?;
    if receiver["recipient_record"] != recipient.to_dict()
        || receiver["env_id"] != env
        || !owner.verify_uncached()
        || crate::team::commit::env_owner_fingerprint(env)? != owner.fingerprint()
        || journal["state"] != "COMMITTED"
        || journal["env_id"] != env
        || journal["manifest_hash"] != digest(&manifest)?
        || receiver["approval_id"] != manifest["approval_id"]
    {
        return Err(bad("team_bootstrap_recovery_required"));
    }
    let mut genesis = None;
    let mut admission = false;
    for op in journal["ops"]
        .as_array()
        .ok_or_else(|| bad("team_bootstrap_recovery_required"))?
    {
        history.check()?;
        let name = text(op, "path")?;
        if !name.starts_with(&format!("team/{env}/commits/")) {
            continue;
        }
        let encoded = text(op, "data_b64")?;
        history.charge_import(encoded.len() as u64 * 4 + 4096, encoded.len() as u64 * 8)?;
        let raw = crate::pybase64::b64decode_strict(encoded)
            .map_err(|_| bad("team_bootstrap_recovery_required"))?;
        let value = io.parse(&raw, 16_777_216)?;
        let commit = Commit::from_dict(&value)?;
        if commit.env_id != env || !verify_commit(&commit, &owner) {
            return Err(bad("team_bootstrap_recovery_required"));
        }
        let hash = commit.hash()?;
        if commit.author_seq == 1
            && commit
                .ops
                .first()
                .is_some_and(|op| op["op"] == "env.init" && op["owner_device"] == owner.to_dict())
            && genesis.replace(hash.clone()).is_some()
        {
            return Err(bad("team_bootstrap_recovery_required"));
        }
        if hash == manifest["recipient_admission_commit_hash"] {
            if commit.ops.len() != 1
                || commit.ops[0]["op"] != "member.add"
                || commit.ops[0]["role"] != "admin"
                || commit.ops[0]["device"] != recipient.to_dict()
            {
                return Err(bad("team_bootstrap_recovery_required"));
            }
            admission = true;
        }
    }
    if !admission {
        return Err(bad("team_bootstrap_recovery_required"));
    }
    let compact = json!({"domain":"zeropw-personal-import-journal-v1","v":1,"layout":"compact_committed_v1","state":"COMMITTED","env_id":env,"epoch":journal["epoch"],"manifest_hash":journal["manifest_hash"],"ready":journal["ready"],"receipt":journal["receipt"],"visibility":journal["visibility"],"signer_record":owner.to_dict(),"recipient_record":recipient.to_dict(),"genesis_hash":genesis.ok_or_else(||bad("team_bootstrap_recovery_required"))?,"admission_hash":manifest["recipient_admission_commit_hash"],"manifest_raw_sha256":io.hash(&manifest_raw)?,"payload_sha256":manifest["payload"]["sha256"],"payload_length":manifest["payload"]["byte_length"],"cold_journal_sha256":io.hash(full_raw)?,"cold_journal_length":full_raw.len()});
    signed(ctx, compact, history)
}

fn publish_committed_metadata(
    ctx: &Context,
    env: &str,
    journal: &mut Value,
    history: &crate::team::commit::HistorySession<'_>,
    original_committed: Option<&[u8]>,
) -> Result<Value> {
    #[cfg(test)]
    import_barrier::testing::hit(ctx.state, env, "compact-plan-before")?;
    let journal_name = path(env, "journal.json")?;
    let archive_name = path(env, "provenance/install-journal.json")?;
    let full_raw = if let Some(original) = original_committed {
        if journal["state"] != "COMMITTED" {
            return Err(bad("team_bootstrap_recovery_required"));
        }
        history.charge_import(original.len() as u64, original.len() as u64)?;
        original.to_vec()
    } else {
        journal["state"] = json!("COMMITTED");
        *journal = signed(ctx, history.clone_import_record(journal)?, history)?;
        history.encode_import_record(journal)?
    };
    let io = history.import_io()?;
    let old_journal = io
        .read(&journal_name, 67_108_864)?
        .ok_or_else(|| bad("team_bootstrap_recovery_required"))?;
    let index_raw = io
        .read(import_barrier::INDEX, 1_048_576)?
        .ok_or_else(|| bad("team_bootstrap_recovery_required"))?;
    let mut index = io.parse(&index_raw, 1_048_576)?;
    verified(ctx, &index[env], history)?;
    if index[env]["epoch"] != journal["epoch"]
        || index[env]["manifest_hash"] != journal["manifest_hash"]
        || !matches!(
            index[env]["state"].as_str(),
            Some("installing" | "committed")
        )
    {
        return Err(bad("team_bootstrap_recovery_required"));
    }
    let compact = compact_committed(ctx, env, journal, &full_raw, history)?;
    #[cfg(test)]
    import_barrier::testing::hit(ctx.state, env, "compact-plan-after")?;
    let compact_raw = history.encode_import_record(&compact)?;
    if compact_raw.len() > 1_048_576 {
        return Err(bad("team_bootstrap_limit_exceeded"));
    }
    match io.read(&archive_name, 67_108_864)? {
        Some(existing) if existing == full_raw => {
            import_barrier::confirm_denial_durable(history, &archive_name)?
        }
        Some(_) => return Err(bad("team_bootstrap_recovery_required")),
        None => import_barrier::write_with_history(history, &archive_name, &full_raw)?,
    }
    #[cfg(test)]
    import_barrier::testing::hit(ctx.state, env, "archive-publication-after")?;
    // Immutable archive first; compact active journal next; index visibility
    // last. No committed recovery can replay the original target patches.
    if old_journal != compact_raw {
        import_barrier::replace_import_metadata(
            history,
            &journal_name,
            &old_journal,
            &compact_raw,
        )?;
    }
    #[cfg(test)]
    import_barrier::testing::hit(ctx.state, env, "compact-publication-after")?;
    index[env]["state"] = json!("committed");
    index[env]["receipt_sha256"] = json!(digest(&journal["receipt"])?);
    index[env]["commit_journal_sha256"] = json!(io.hash(&compact_raw)?);
    index[env] = signed(ctx, history.clone_import_record(&index[env])?, history)?;
    let new_index = history.encode_import_record(&index)?;
    history.check()?;
    import_barrier::replace_import_metadata(
        history,
        import_barrier::INDEX,
        &index_raw,
        &new_index,
    )?;
    #[cfg(test)]
    import_barrier::testing::hit(ctx.state, env, "committed-index-publication-after")?;
    Ok(journal["receipt"].clone())
}
fn verified(
    ctx: &Context,
    record: &Value,
    history: &crate::team::commit::HistorySession<'_>,
) -> Result<()> {
    history.reserve_import_signature(record)?;
    if !std::ptr::eq(ctx.state, history.state()) {
        return Err(bad("team_bootstrap_local_state_changed"));
    }
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
    let device = history.local_record()?;
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
    discard_prepared_with_input(ctx, env, &history)?;
    #[cfg(test)]
    import_barrier::opus_cost::note(ctx.state, env, "ready-initial-recheck-after");
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
    let device = history.load_device(ctx)?;
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
    #[cfg(test)]
    import_barrier::opus_cost::note(ctx.state, env, "stage-derived-after");
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
    #[cfg(test)]
    import_barrier::opus_cost::note(ctx.state, env, "journal-publication-after");
    deadline.check()?;
    plan.recheck(ctx)?;
    if session.is_closed() {
        return Err(bad("team_bootstrap_peer_offline"));
    }
    let mut index = import_barrier::raw_index_in(&history.import_io()?)?;
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
    // The same parent loaded/bound the actual recipient identity before Plan.
    history.match_local_identity(&device.record()?)?;
    index[env] = visibility;
    // Persist the barrier before the first ordinary target write. A PREPARED
    // journal is discardable; this durable INSTALLING intent is recoverable.
    history.check()?;
    import_barrier::json(ctx.state, import_barrier::INDEX, &index)?;
    #[cfg(test)]
    import_barrier::opus_cost::note(ctx.state, env, "installing-index-after");
    #[cfg(test)]
    import_barrier::testing::hit(ctx.state, env, "installing-index-after")?;
    journal["state"] = json!("INSTALLING");
    journal = signed(ctx, journal, &history)?;
    import_barrier::json(ctx.state, &path(env, "journal.json")?, &journal)?;
    #[cfg(test)]
    import_barrier::opus_cost::note(ctx.state, env, "journal-publication-after");
    let receipt = finish(ctx, env, &mut journal, &history)?;
    import_barrier::discard_staging(ctx.state, env)?;
    history.check()?;
    Ok(receipt)
}

pub(crate) fn prepared_without_publication(
    ctx: &Context,
    env: &str,
    history: &crate::team::commit::HistorySession<'_>,
) -> Result<bool> {
    let io = history.import_io()?;
    if import_barrier::raw_index_in(&io)?.get(env).is_some() {
        return Ok(false);
    }
    for leaf in [
        "receipt.json",
        "provenance",
        "member-removed.json",
        import_barrier::LOCAL_REMOVAL_DENIAL,
        "history-required.json",
    ] {
        io.charge(1 + leaf.len() as u64, 256)?;
        match fs::symlink_metadata(ctx.state.path.join(path(env, leaf)?)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Ok(false),
        }
    }
    let Some(raw) = io.read(&path(env, "journal.json")?, 67_108_864)? else {
        for directory in ["commits", "snapshots", "snapshot_records"] {
            let mut pending = vec![format!("team/{env}/{directory}")];
            let mut count = 0u64;
            while let Some(name) = pending.pop() {
                for leaf in io.list(&name)? {
                    count = count
                        .checked_add(1)
                        .filter(|n| *n <= 65_536)
                        .ok_or_else(|| bad("team_bootstrap_limit_exceeded"))?;
                    let name = format!("{name}/{leaf}");
                    io.charge(1 + name.len() as u64, 256)?;
                    let metadata = fs::symlink_metadata(ctx.state.path.join(&name))
                        .map_err(|_| bad("team_bootstrap_recovery_required"))?;
                    if metadata.is_dir() {
                        pending.push(name);
                    } else {
                        return Ok(false);
                    }
                }
            }
        }
        if io
            .read(&format!("team/{env}/facts.jsonl"), 67_108_864)?
            .is_some_and(|raw| raw.iter().any(|b| !b.is_ascii_whitespace()))
        {
            return Ok(false);
        }
        for (name, nested) in [
            (crate::vault::VAULT_DOC, true),
            (crate::policy::CONNECTIONS, false),
        ] {
            let value = io.json(name, 67_108_864)?.unwrap_or(Value::Null);
            let entries = if nested { &value["secrets"] } else { &value };
            if entries
                .as_object()
                .into_iter()
                .flatten()
                .any(|(_, v)| v["shared_env"] == env)
            {
                return Ok(false);
            }
        }
        return Ok(true);
    };
    let journal = io.parse(&raw, 67_108_864)?;
    verified(ctx, &journal, history)?;
    if journal["state"] != "PREPARED"
        || !journal["layout"].is_null()
        || journal["env_id"] != env
        || journal["domain"] != "zeropw-personal-import-journal-v1"
    {
        return Ok(false);
    }
    for op in journal["ops"]
        .as_array()
        .ok_or_else(|| bad("team_bootstrap_recovery_required"))?
    {
        let name = text(op, "path")?;
        if op["kind"] == "file" {
            let value = io.read(name, 16_777_216)?;
            let current = value
                .as_ref()
                .map(|raw| io.hash(raw).map(Value::String))
                .transpose()?
                .unwrap_or(Value::Null);
            if current != op["before"] {
                return Ok(false);
            }
        } else if op["kind"] == "patch" {
            let value = io.json(name, 67_108_864)?.unwrap_or(Value::Null);
            let mut current = &value;
            for key in op["keys"]
                .as_array()
                .ok_or_else(|| bad("team_bootstrap_recovery_required"))?
            {
                current = &current[key
                    .as_str()
                    .ok_or_else(|| bad("team_bootstrap_recovery_required"))?];
            }
            if current != &op["before"] {
                return Ok(false);
            }
        } else if op["kind"] == "project_environment" && name == crate::projects::DOC {
            let value = io.json(name, 67_108_864)?.unwrap_or(Value::Null);
            if value[text(op, "project")?]["environments"]
                .as_array()
                .is_some_and(|v| v.contains(&op["environment"]))
            {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }
    }
    history.check()?;
    Ok(true)
}

pub(crate) fn discard_prepared(ctx: &Context, env: &str) -> Result<()> {
    let history = crate::team::commit::HistorySession::open_probe(
        ctx,
        env,
        crate::team::commit::ProbePurpose::Recipient,
    )?;
    discard_prepared_with_input(ctx, env, &history)
}
pub(crate) fn discard_prepared_with_input(
    ctx: &Context,
    env: &str,
    history: &crate::team::commit::HistorySession<'_>,
) -> Result<()> {
    let io = history.import_io()?;
    if import_barrier::raw_index_in(&io)?.get(env).is_some() {
        return Ok(());
    }
    if !prepared_without_publication(ctx, env, history)? {
        return Err(bad("team_bootstrap_recovery_required"));
    }
    let name = path(env, "journal.json")?;
    if io.read(&name, 67_108_864)?.is_some() {
        history.charge_import(16 * (name.len() as u64 + 1), 16 * (name.len() as u64 + 1))?;
        history.invalidate()?;
        fs::remove_file(ctx.state.path.join(&name))
            .map_err(|_| bad("team_bootstrap_storage_failed"))?;
        history.check()?;
        history.invalidate()?;
        fs::File::open(
            ctx.state
                .path
                .join(&name)
                .parent()
                .ok_or_else(|| bad("team_bootstrap_storage_failed"))?,
        )
        .and_then(|file| file.sync_all())
        .map_err(|_| bad("team_bootstrap_storage_failed"))?;
    }
    history.check()?;
    import_barrier::discard_staging(ctx.state, env)?;
    history.check()
}

fn finish(
    ctx: &Context,
    env: &str,
    journal: &mut Value,
    history: &crate::team::commit::HistorySession<'_>,
) -> Result<Value> {
    verified(ctx, journal, history)?;
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
    publish_committed_metadata(ctx, env, journal, history, None)
}

// Compatibility entry for focused recovery callers; runtime borrows its Slot
// and existing parent through recover_with_input instead.
#[allow(dead_code)]
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
pub(crate) fn migrate_committed(ctx: &Context) -> Result<()> {
    // Conversion is deliberately unavailable to a bare StateDir. Only this
    // actual reopened Context and an owned Slot may extend legacy metadata.
    if matches!(fs::symlink_metadata(ctx.state.path.join(import_barrier::INDEX)), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        return Ok(());
    }
    let candidates = {
        let io = import_barrier::ImportIo::open(ctx.state)?;
        let index = import_barrier::raw_index_in(&io)?;
        if index.as_object().is_none_or(|m| m.len() > 256) {
            return Err(bad("team_bootstrap_limit_exceeded"));
        }
        index
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(_, record)| {
                record["state"] == "committed" && record["commit_journal_sha256"].is_null()
            })
            .map(|(env, _)| env.clone())
            .collect::<Vec<_>>()
    };
    for env in candidates {
        let slot = match super::Slot::take_registration(ctx, &env) {
            Ok(Some(slot)) => slot,
            Ok(None) => continue,
            Err(error) if error.reason == "team_bootstrap_busy" => continue,
            Err(error) => return Err(error),
        };
        slot.registration(ctx, &env)?.check(ctx, &env)?;
        let history = crate::team::commit::HistorySession::open_probe(
            ctx,
            &env,
            crate::team::commit::ProbePurpose::Recipient,
        )?;
        // An invalid environment remains denied; it cannot make an unrelated
        // ordinary environment unavailable merely by being opened.
        if let Err(error) = recover_with_input(ctx, &env, &history)
            && matches!(
                error.reason.as_ref(),
                "team_bootstrap_timeout" | "team_bootstrap_limit_exceeded"
            )
        {
            return Err(error);
        }
    }
    Ok(())
}
pub(crate) fn recover_with_input(
    ctx: &Context,
    env: &str,
    parent: &crate::team::commit::HistorySession<'_>,
) -> Result<()> {
    let history = parent.nested(ctx.state, env)?;
    let io = history.import_io()?;
    let name = path(env, "journal.json")?;
    let Some(raw) = io.read(&name, 67_108_864)? else {
        return Ok(());
    };
    let mut journal = history.journal_record(&raw)?;
    verified(ctx, &journal, &history)?;
    if journal["env_id"] != env || journal["domain"] != "zeropw-personal-import-journal-v1" {
        return Err(bad("team_bootstrap_recovery_required"));
    }
    let index = import_barrier::raw_index_in(&io)?;
    if index.get(env).is_none() {
        return if journal["state"] == "PREPARED" && journal["layout"].is_null() {
            Ok(())
        } else {
            Err(bad("team_bootstrap_recovery_required"))
        };
    }
    verified(ctx, &index[env], &history)?;
    if index[env]["epoch"] != journal["epoch"]
        || index[env]["manifest_hash"] != journal["manifest_hash"]
    {
        return Err(bad("team_bootstrap_recovery_required"));
    }
    if journal["layout"] == "compact_committed_v1" {
        if index[env]["state"] == "committed"
            && index[env]["commit_journal_sha256"] == io.hash(&raw)?
        {
            // Compact/index is the hot authenticated metadata route. The full
            // archive is consumed only when a cold completion needs its ops.
            receipt_evidence(ctx, env, &history)?;
            import_barrier::discard_staging(ctx.state, env)?;
            return Ok(());
        }
        let archive = io
            .read(&path(env, "provenance/install-journal.json")?, 67_108_864)?
            .ok_or_else(|| bad("team_bootstrap_recovery_required"))?;
        if journal["cold_journal_sha256"] != io.hash(&archive)?
            || journal["cold_journal_length"] != archive.len() as u64
        {
            return Err(bad("team_bootstrap_recovery_required"));
        }
        let full = io.parse(&archive, 67_108_864)?;
        verified(ctx, &full, &history)?;
        if full["state"] != "COMMITTED"
            || full["env_id"] != env
            || full["epoch"] != journal["epoch"]
            || full["receipt"] != journal["receipt"]
            || full["visibility"] != journal["visibility"]
            || full["ready"] != journal["ready"]
        {
            return Err(bad("team_bootstrap_recovery_required"));
        }
        if index[env]["state"] == "installing" {
            verify_installed_targets(ctx, &full, &history)?;
        } else if index[env]["state"] != "committed"
            || !index[env]["commit_journal_sha256"].is_null()
        {
            return Err(bad("team_bootstrap_recovery_required"));
        }
        // Interrupted legacy conversion requires BOTH original committed index
        // and the matching compact/archive. No target replay in either case.
        verify_immutable_install(ctx, env, &full, &history)?;
        let mut full = full;
        publish_committed_metadata(ctx, env, &mut full, &history, Some(&archive))?;
    } else if !journal["layout"].is_null() {
        return Err(bad("team_bootstrap_recovery_required"));
    } else if index[env]["state"] == "committed" {
        // Authentic legacy committed conversion is metadata-only, even when
        // ordinary post-cut edits have replaced the original target values.
        verify_immutable_install(ctx, env, &journal, &history)?;
        if index[env]["receipt_sha256"] != digest(&journal["receipt"])? {
            return Err(bad("team_bootstrap_recovery_required"));
        }
        publish_committed_metadata(ctx, env, &mut journal, &history, Some(&raw))?;
    } else if index[env]["state"] == "installing"
        && matches!(journal["state"].as_str(), Some("PREPARED" | "INSTALLING"))
    {
        finish(ctx, env, &mut journal, &history)?;
    } else {
        return Err(bad("team_bootstrap_recovery_required"));
    }
    import_barrier::discard_staging(ctx.state, env)?;
    history.check()
}

fn verify_immutable_install(
    ctx: &Context,
    env: &str,
    journal: &Value,
    history: &crate::team::commit::HistorySession<'_>,
) -> Result<()> {
    let io = history.import_io()?;
    let receipt = io
        .json(&path(env, "receipt.json")?, 65_536)?
        .ok_or_else(|| bad("team_bootstrap_recovery_required"))?;
    verified(ctx, &receipt, history)?;
    let raw_manifest = io
        .read(&path(env, "provenance/manifest.json")?, 65_536)?
        .ok_or_else(|| bad("team_bootstrap_recovery_required"))?;
    let manifest = io.parse(&raw_manifest, 65_536)?;
    let payload = io
        .read(&path(env, "provenance/payload.json")?, 16_777_216)?
        .ok_or_else(|| bad("team_bootstrap_recovery_required"))?;
    if receipt != journal["receipt"]
        || receipt["epoch"] != journal["epoch"]
        || receipt["env_id"] != env
        || receipt["manifest_hash"] != digest(&manifest)?
        || receipt["payload_sha256"] != io.hash(&payload)?
        || manifest["payload"]["byte_length"] != payload.len() as u64
        || receipt["ready_sha256"] != digest(&journal["ready"])?
    {
        return Err(bad("team_bootstrap_recovery_required"));
    }
    history.check()
}

fn verify_installed_targets(
    ctx: &Context,
    journal: &Value,
    history: &crate::team::commit::HistorySession<'_>,
) -> Result<()> {
    let io = history.import_io()?;
    for op in journal["ops"]
        .as_array()
        .ok_or_else(|| bad("team_bootstrap_recovery_required"))?
    {
        let name = text(op, "path")?;
        if op["kind"] == "file" {
            let raw = io
                .read(name, 16_777_216)?
                .ok_or_else(|| bad("team_bootstrap_recovery_required"))?;
            if io.hash(&raw)? != op["after"] {
                return Err(bad("team_bootstrap_recovery_required"));
            }
        } else {
            let value = io.json(name, 67_108_864)?.unwrap_or(Value::Null);
            if patched(value.clone(), op)? != value {
                return Err(bad("team_bootstrap_recovery_required"));
            }
        }
    }
    let _ = ctx;
    history.check()
}

pub(crate) fn receipt(ctx: &Context, env: &str) -> Result<Value> {
    let history = crate::team::commit::HistorySession::open_runtime(ctx.state, env)?;
    receipt_with_input(ctx, env, &history)
}
pub(crate) fn receipt_with_input(
    ctx: &Context,
    env: &str,
    parent: &crate::team::commit::HistorySession<'_>,
) -> Result<Value> {
    let history = parent.nested(ctx.state, env)?;
    let value = receipt_evidence(ctx, env, &history)?;
    if import_barrier::index_in(&history.import_io()?)?[env]["local_member_removed"] == true
        || ctx.policy.restore_pending()?
    {
        return Err(bad("team_bootstrap_recovery_required"));
    }
    history.check()?;
    Ok(value)
}
pub(crate) fn receipt_evidence(
    ctx: &Context,
    env: &str,
    parent: &crate::team::commit::HistorySession<'_>,
) -> Result<Value> {
    let history = parent.nested(ctx.state, env)?;
    let io = history.import_io()?;
    let index = import_barrier::index_in(&io)?;
    let value = io
        .json(&path(env, "receipt.json")?, 65_536)?
        .ok_or_else(|| bad("team_bootstrap_recovery_required"))?;
    verified(ctx, &value, &history)?;
    if index[env]["state"] != "committed"
        || index[env]["epoch"] != value["epoch"]
        || index[env]["receipt_sha256"] != digest(&value)?
    {
        return Err(bad("team_bootstrap_recovery_required"));
    }
    let input = history.acquire()?;
    let vector = input.vector()?;
    for (fp, seq) in value["vector"].as_object().into_iter().flatten() {
        let floor = crate::pyint::PyInt::from_json_integer(seq)
            .ok_or_else(|| bad("team_bootstrap_recovery_required"))?;
        if vector.get(fp).is_none_or(|n| n < &floor) {
            return Err(bad("team_bootstrap_recovery_required"));
        }
    }
    input.recheck()?;
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
    fn personal_bootstrap_pending_admission_refuses_another_peer_without_poisoning_owner() {
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
        let first_peer = DeviceKey::load_or_create(b.state, b.kms)
            .unwrap()
            .record()
            .unwrap();
        let other = context(&root.path().join("root03-other-peer"));
        let other_peer = DeviceKey::load_or_create(other.state, other.kms)
            .unwrap()
            .record()
            .unwrap();
        let second_invitation = membership::create_invite_opts(
            &a,
            &env,
            "admin",
            "second pending peer",
            600,
            &["127.0.0.1:9".to_owned()],
            false,
            true,
        )
        .unwrap();
        approval::enable(&a, &env, &second_invitation.invite_id, None).unwrap();
        let transcript = b"synthetic-root03-pending-admission";
        let parsed = membership::parse_invite(&invitation.invite).unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(parsed.invite_secret.expose()).unwrap();
        mac.update(transcript);
        let first_proof = mac.finalize().into_bytes();
        let parsed = membership::parse_invite(&second_invitation.invite).unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(parsed.invite_secret.expose()).unwrap();
        mac.update(transcript);
        let other_proof = mac.finalize().into_bytes();
        assert!(matches!(
            approval::check(&a, &env, &other_peer, transcript, &other_proof).unwrap(),
            Some(crate::team::transport::InviteDecision::PendingPersonal)
        ));
        let request = approval::list(&a, &env).unwrap().remove(0);
        assert_eq!(request["device_record"], other_peer.to_dict());
        let before_approval = root.path().join("root03-other-pending");
        copy_tree(&a.state.path, &before_approval);
        approval::approve(
            &a,
            &env,
            text(&request, "request_id").unwrap(),
            text(&request, "record_binding").unwrap(),
            PASS,
        )
        .unwrap();
        let already_approved = root.path().join("root03-other-approved");
        copy_tree(&a.state.path, &already_approved);

        for (copy, preapproved) in [(before_approval, false), (already_approved, true)] {
            let ctx = Context::open(&copy, Config::default(), clock::system()).unwrap();
            let failure = import_barrier::testing::Scope::named(
                ctx.state,
                &env,
                "admission-append-before",
                1,
            );
            assert!(approval::check(&ctx, &env, &first_peer, transcript, &first_proof).is_err());
            assert!(failure.fired());
            drop(failure);
            let first_path = path(
                &env,
                &format!("authorizations/{}.json", first_peer.fingerprint()),
            )
            .unwrap();
            let original_auth = ctx.state.read_json(&first_path, Value::Null).unwrap();
            let original = Commit::from_dict(&original_auth["admission"]).unwrap();
            assert!(
                CommitStore::new(ctx.state, &env)
                    .get(&original.author, original.author_seq.clone())
                    .unwrap()
                    .is_none()
            );
            let requests_path = path(&env, "requests.json").unwrap();
            let requests_before = fs::read(ctx.state.path.join(&requests_path)).unwrap();
            if !preapproved {
                assert_eq!(
                    approval::approve(
                        &ctx,
                        &env,
                        text(&request, "request_id").unwrap(),
                        text(&request, "record_binding").unwrap(),
                        PASS,
                    )
                    .unwrap_err()
                    .reason,
                    "team_bootstrap_semantic_scope_unsupported"
                );
            }
            assert_eq!(
                approval::check(&ctx, &env, &other_peer, transcript, &other_proof)
                    .unwrap_err()
                    .reason,
                "team_bootstrap_semantic_scope_unsupported"
            );
            assert_eq!(
                fs::read(ctx.state.path.join(&requests_path)).unwrap(),
                requests_before
            );
            assert_eq!(
                ctx.state.read_json(&first_path, Value::Null).unwrap(),
                original_auth
            );
            assert!(
                !ctx.state.exists(
                    &path(
                        &env,
                        &format!("authorizations/{}.json", other_peer.fingerprint()),
                    )
                    .unwrap()
                )
            );
            assert_eq!(
                fs::read_dir(ctx.state.path.join(path(&env, "authorizations").unwrap()))
                    .unwrap()
                    .count(),
                1
            );
            approval::recover_all(&ctx, &env).unwrap();
            assert_eq!(
                CommitStore::new(ctx.state, &env)
                    .get(&original.author, original.author_seq.clone())
                    .unwrap()
                    .unwrap()
                    .to_dict(),
                original.to_dict()
            );
            let document = membership::load_environment(&ctx, &env).unwrap().document;
            assert_eq!(
                document["members"][first_peer.fingerprint()]["status"],
                "active"
            );
            assert!(document["members"].get(other_peer.fingerprint()).is_none());
        }
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

#[cfg(test)]
mod opus_fix_tests {
    use super::*;

    fn installed_with_trace() -> tests::Pending {
        use std::time::{Duration, Instant};
        let fixture = tests::pending();
        let trace = import_barrier::testing::Scope::track(fixture.b.state, None);
        let costs = import_barrier::opus_cost::Scope::begin(fixture.b.state, &fixture.env);
        super::super::approval::approve_receiver(
            &fixture.b,
            &fixture.env,
            text(&fixture.pending, "inviter_record_binding").unwrap(),
            text(&fixture.pending, "self_record_binding").unwrap(),
            "synthetic-install-fault-administrator",
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(35);
        while import_barrier::index(fixture.b.state).unwrap()[&fixture.env]["state"] != "committed"
        {
            let attempt = raw_json(
                fixture.b.state,
                &path(&fixture.env, "attempt.json").unwrap(),
            )
            .unwrap();
            let terminal = matches!(
                attempt["state"].as_str(),
                Some("unsupported" | "recovery_required")
            );
            if terminal || Instant::now() >= deadline {
                let points = trace
                    .hits()
                    .into_iter()
                    .rev()
                    .take(24)
                    .map(|(_, point)| point)
                    .collect::<Vec<_>>();
                eprintln!("PVBOOT_COST_NOTES {:?}", costs.notes());
                eprintln!("PVBOOT_COST_METRICS {:?}", costs.metrics());
                panic!(
                    "real install did not commit: state={} reason={} recent_points={points:?}",
                    attempt["state"].as_str().unwrap_or("invalid"),
                    attempt["reason"].as_str().unwrap_or("none")
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        for ctx in [&fixture.b, &fixture.a] {
            crate::team::sync::attached(ctx).unwrap().stop();
        }
        drop(trace);
        fixture
    }

    #[test]
    fn compact_archive_real_install_reopens_without_replaying_targets() {
        let fixture = installed_with_trace();
        let ctx = &fixture.b;
        let env = &fixture.env;
        let compact_raw =
            fs::read(ctx.state.path.join(path(env, "journal.json").unwrap())).unwrap();
        let compact = pyjson::loads(std::str::from_utf8(&compact_raw).unwrap()).unwrap();
        assert_eq!(compact["layout"], "compact_committed_v1");
        assert!(compact.get("ops").is_none());
        let cold_raw = fs::read(
            ctx.state
                .path
                .join(path(env, "provenance/install-journal.json").unwrap()),
        )
        .unwrap();
        let cold = pyjson::loads(std::str::from_utf8(&cold_raw).unwrap()).unwrap();
        assert_eq!(cold["state"], "COMMITTED");
        assert!(cold["ops"].as_array().unwrap().len() > 5);
        assert_eq!(
            compact["cold_journal_sha256"],
            hex::encode(Sha256::digest(&cold_raw))
        );
        assert_eq!(compact["cold_journal_length"], cold_raw.len() as u64);
        assert_eq!(compact["receipt"], cold["receipt"]);
        let receipt = fs::read(ctx.state.path.join(path(env, "receipt.json").unwrap())).unwrap();
        let reopened = Context::open(
            &ctx.state.path,
            crate::context::Config::default(),
            crate::clock::system(),
        )
        .unwrap();
        recover(&reopened, env).unwrap();
        assert_eq!(
            fs::read(ctx.state.path.join(path(env, "receipt.json").unwrap())).unwrap(),
            receipt
        );
        assert_eq!(
            crate::team::sync::resolve_env_id(reopened.state, "personal", "vault")
                .unwrap()
                .as_deref(),
            Some(env.as_str())
        );
    }

    #[test]
    fn pending_mapping_survives_authenticated_context_reopen() {
        let fixture = tests::pending();
        let env = &fixture.env;
        let mapping_raw =
            fs::read(fixture.b.state.path.join(crate::team::sync::ENVS_MAP_PATH)).unwrap();
        let reopened = Context::open(
            &fixture.b.state.path,
            crate::context::Config::default(),
            crate::clock::system(),
        )
        .unwrap();
        assert_eq!(
            fs::read(fixture.b.state.path.join(crate::team::sync::ENVS_MAP_PATH)).unwrap(),
            mapping_raw
        );
        assert_eq!(
            crate::team::sync::resolve_env_id(reopened.state, "personal", "vault")
                .unwrap()
                .as_deref(),
            Some(env.as_str())
        );
    }
}

#[cfg(test)]
mod opus_process_death_tests {
    use super::*;
    use crate::team::{
        commit, membership,
        sync::{self, TeamSync},
        transport::TcpTransport,
    };
    use std::{
        io::{BufRead, BufReader, Write},
        process::{Child, Command, Stdio},
        sync::{Arc, mpsc},
        thread,
        time::{Duration, Instant},
    };
    const CHILD_TEST: &str =
        "team::bootstrap::install::opus_process_death_tests::owned_receiver_process";
    const DELTA: &[u8] = b"synthetic-personal-after-install-process-death";

    struct OwnedProcess {
        child: Child,
        lines: mpsc::Receiver<String>,
        reader: Option<thread::JoinHandle<()>>,
        receiver_root: std::path::PathBuf,
        owner_root: std::path::PathBuf,
        env: String,
        recipient: String,
        owner_team: Arc<TeamSync>,
    }
    impl OwnedProcess {
        fn spawn(ctx: &Context, owner: &Context, env: &str, mode: &str) -> Self {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"])
                .env("PVBOOT_OPUS_OWN_RECEIVER", &ctx.state.path)
                .env("PVBOOT_OPUS_OWN_ENV", env)
                .env("PVBOOT_OPUS_OWN_MODE", mode)
                .env("RUST_TEST_THREADS", "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("spawn exact owned receiver test process");
            eprintln!("PVBOOT_OPUS_CHILD_SPAWN pid={} mode={mode}", child.id());
            let stdout = child.stdout.take().unwrap();
            let (send, lines) = mpsc::channel();
            let reader = thread::spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    let line = line.expect("read owned child metadata");
                    if line.starts_with("PVBOOT_OPUS_") && send.send(line).is_err() {
                        break;
                    }
                }
            });
            Self {
                child,
                lines,
                reader: Some(reader),
                receiver_root: ctx.state.path.clone(),
                owner_root: owner.state.path.clone(),
                env: env.into(),
                recipient: ctx.state.import_identity().unwrap().fingerprint(),
                owner_team: sync::attached(owner).unwrap(),
            }
        }
        fn expect(&self, marker: &str, deadline: Instant) {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .expect("35-second child deadline elapsed");
            let observed = self.lines.recv_timeout(remaining);
            if observed.is_err() {
                self.diagnose();
            }
            assert_eq!(
                observed.expect("owned receiver did not report expected metadata"),
                marker
            );
            eprintln!("PVBOOT_OPUS_PARENT_OBSERVED {marker}");
        }
        fn diagnose(&self) {
            let mut result = serde_json::Map::new();
            for (side, root) in [("a", &self.owner_root), ("b", &self.receiver_root)] {
                let state = StateDir::new(root);
                let read = |name: String| raw_json(&state, &name).unwrap_or(Value::Null);
                let attempt = read(path(&self.env, "attempt.json").unwrap());
                let journal = read(path(&self.env, "journal.json").unwrap());
                let index = read(import_barrier::INDEX.into());
                let status = read(format!("team/{}/sync_state.json", self.env));
                let auth = read(
                    path(
                        &self.env,
                        &format!("authorizations/{}.json", self.recipient),
                    )
                    .unwrap(),
                );
                let sender = read(path(&self.env, "sender-status.json").unwrap());
                let peers = status["peers"].as_object().into_iter().flatten().take(2).map(|(peer,p)| (peer.clone(),json!({"session":p["session"],"peer_vector":p["peer_vector"],"vector_received_at":p["vector_received_at"],"transport":p["transport"],"dial_failures":p["dial_failures"],"last_error":p["last_error"],"tombstone_agreement":p["tombstone_agreement"]}))).collect::<serde_json::Map<_,_>>();
                result.insert(side.into(), json!({"attempt_state":attempt["state"],"attempt_reason":attempt["reason"],"failed_from":attempt["failed_from"],"journal_state":journal["state"],"layout":journal["layout"],"index_state":index[&self.env]["state"],"removed":index[&self.env]["local_member_removed"],"authorization_activated":auth["activated"],"sender_reason":sender["reason"],"peers":peers}));
            }
            result.insert(
                "owner_cached_recipient_active".into(),
                json!(self.owner_team.is_active_member(&self.env, &self.recipient)),
            );
            result.insert(
                "owner_import_guard_reason".into(),
                json!(
                    import_barrier::require_env(self.owner_team.ctx.state, &self.env)
                        .err()
                        .map(|error| error.reason.into_owned())
                ),
            );
            let fresh_membership = membership::load_environment(&self.owner_team.ctx, &self.env);
            result.insert("owner_fresh_membership".into(), match fresh_membership {
                Ok(folded) => json!({"recipient_status":folded.document["members"][&self.recipient]["status"],"recipient_record_present":folded.document["members"][&self.recipient]["device"].is_object(),"member_count":folded.document["members"].as_object().map(|members|members.len()),"vector":folded.vector}),
                Err(error) => json!({"reason":error.reason}),
            });
            let witnesses = [
                "receipt.json",
                "journal.json",
                "provenance",
                "history-required.json",
                "member-removed.json",
                import_barrier::LOCAL_REMOVAL_DENIAL,
            ]
            .into_iter()
            .map(|leaf| {
                (
                    leaf.to_owned(),
                    json!(
                        fs::symlink_metadata(self.owner_root.join(path(&self.env, leaf).unwrap()))
                            .is_ok()
                    ),
                )
            })
            .collect::<serde_json::Map<_, _>>();
            result.insert("owner_witness_presence".into(), Value::Object(witnesses));
            eprintln!("PVBOOT_OPUS_REOPEN_METADATA {}", Value::Object(result));
        }
        fn send(&mut self, command: Value) {
            let input = self.child.stdin.as_mut().unwrap();
            writeln!(
                input,
                "{}",
                pyjson::dumps(&command, pyjson::DumpOptions::compact_sorted()).unwrap()
            )
            .unwrap();
            input.flush().unwrap();
        }
        fn join_reader(&mut self) {
            if let Some(reader) = self.reader.take() {
                reader.join().unwrap();
            }
        }
        fn kill_wait(&mut self) {
            use std::os::unix::process::ExitStatusExt;
            self.child
                .kill()
                .expect("kill only the directly spawned receiver");
            let status = self.child.wait().expect("wait directly spawned receiver");
            assert_eq!(status.signal(), Some(libc::SIGKILL));
            eprintln!(
                "PVBOOT_OPUS_CHILD_WAIT pid={} signal={}",
                self.child.id(),
                libc::SIGKILL
            );
            self.join_reader();
        }
        fn finish(&mut self) {
            self.send(json!({"phase":"stop"}));
            assert!(self.child.wait().expect("wait owned receiver").success());
            eprintln!("PVBOOT_OPUS_CHILD_WAIT pid={} exit=0", self.child.id());
            self.join_reader();
        }
    }
    impl Drop for OwnedProcess {
        fn drop(&mut self) {
            if self.reader.is_none() {
                return;
            }
            if self.child.try_wait().ok().flatten().is_none() {
                let _ = self.child.kill();
            }
            use std::os::unix::process::ExitStatusExt;
            match self.child.wait() {
                Ok(status) => eprintln!(
                    "PVBOOT_OPUS_CHILD_UNWIND_WAIT pid={} exit={:?} signal={:?}",
                    self.child.id(),
                    status.code(),
                    status.signal()
                ),
                Err(error) => eprintln!(
                    "PVBOOT_OPUS_CHILD_UNWIND_WAIT_ERROR pid={} kind={:?}",
                    self.child.id(),
                    error.kind()
                ),
            }
            if let Some(reader) = self.reader.take() {
                let joined = reader.join().is_ok();
                eprintln!(
                    "PVBOOT_OPUS_CHILD_READER_JOIN pid={} joined={joined}",
                    self.child.id()
                );
            }
        }
    }
    fn emit(marker: &str) {
        println!("\n{marker}");
        std::io::stdout().flush().unwrap();
    }
    fn wait_until(mut predicate: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(35);
        while !predicate() {
            assert!(
                Instant::now() < deadline,
                "35-second personal agreement deadline"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn owned_receiver_process() {
        let Some(root) = std::env::var_os("PVBOOT_OPUS_OWN_RECEIVER") else {
            return;
        };
        let env = std::env::var("PVBOOT_OPUS_OWN_ENV").unwrap();
        let mode = std::env::var("PVBOOT_OPUS_OWN_MODE").unwrap();
        let ctx = Arc::new(
            Context::open(
                root,
                crate::context::Config::default(),
                crate::clock::system(),
            )
            .unwrap(),
        );
        let _protocol_trace = import_barrier::opus_cost::Scope::protocol_trace(ctx.state, &env);
        let owner = commit::env_owner_fingerprint(&env).unwrap();
        let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        let me = device.fingerprint().unwrap();
        let pause = if let Some(point) = mode.strip_prefix("pause:") {
            assert!(matches!(
                point,
                "installing-index-after" | "committed-index-publication-after"
            ));
            Some(import_barrier::testing::Scope::pause(
                ctx.state, &env, point,
            ))
        } else {
            assert_eq!(mode, "reopen");
            None
        };
        let transport = TcpTransport::new(device.clone(), Arc::new(|_, _| None), 64);
        let team = TeamSync::new(ctx.clone(), Arc::new(transport), device);
        assert!(
            team.synced_at(&env).is_none(),
            "new process must not inherit old readiness"
        );
        team.enable_sync_state();
        team.start(None).unwrap();
        if let Some((scope, pause)) = pause {
            let waited = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pause.wait()));
            if let Err(panic) = waited {
                let attempt = raw_json(ctx.state, &path(&env, "attempt.json").unwrap())
                    .unwrap_or(Value::Null);
                let index = raw_json(ctx.state, import_barrier::INDEX).unwrap_or(Value::Null);
                let journal = raw_json(ctx.state, &path(&env, "journal.json").unwrap())
                    .unwrap_or(Value::Null);
                let recent = scope
                    .hits()
                    .into_iter()
                    .rev()
                    .take(12)
                    .map(|(_, point)| point)
                    .collect::<Vec<_>>();
                eprintln!(
                    "PVBOOT_OPUS_BOUNDARY_DIAGNOSTIC {}",
                    json!({"attempt_state":attempt["state"],"reason":attempt["reason"],"failed_from":attempt["failed_from"],"index_state":index[&env]["state"],"journal_state":journal["state"],"recent_points":recent})
                );
                std::panic::resume_unwind(panic);
            }
            emit("PVBOOT_OPUS_DURABLE_INSTALL_BOUNDARY");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            panic!("parent must kill this exact child at the durable boundary");
        }
        wait_until(|| team.synced_at(&env).is_some());
        assert!(
            ctx.vault
                .secret_for_trusted_use("alpha", None)
                .unwrap()
                .ct_eq(b"synthetic-install-fault-value")
        );
        assert!(matches!(
            super::super::status(&ctx, &env).unwrap()["state"].as_str(),
            Some("ready" | "installed_syncing")
        ));
        emit("PVBOOT_OPUS_REOPEN_FRESH_AGREEMENT");
        for line in std::io::stdin().lock().lines() {
            let command = pyjson::loads(&line.unwrap()).unwrap();
            match command["phase"].as_str().unwrap() {
                "delta" => {
                    let sequence =
                        crate::pyint::PyInt::from_json_integer(&command["sequence"]).unwrap();
                    wait_until(|| {
                        CommitStore::new(ctx.state, &env)
                            .get(&owner, &sequence)
                            .ok()
                            .flatten()
                            .is_some_and(|commit| commit.hash().unwrap() == command["hash"])
                            && ctx
                                .vault
                                .secret_for_trusted_use("after-death", None)
                                .is_ok_and(|value| value.ct_eq(DELTA))
                    });
                    emit("PVBOOT_OPUS_ORDINARY_DELTA_AND_USE");
                }
                "removed" => {
                    let fact_hash = command["fact_hash"].as_str().unwrap();
                    let started = Instant::now();
                    let deadline = started + Duration::from_secs(35);
                    let mut diagnosed = false;
                    loop {
                        let facts = sync::load_facts(&ctx, &env);
                        let admitted = facts
                            .as_ref()
                            .is_ok_and(|(_, admitted, _)| admitted.contains(fact_hash));
                        let alpha_denied = ctx.vault.secret_for_trusted_use("alpha", None).is_err();
                        let delta_denied = ctx
                            .vault
                            .secret_for_trusted_use("after-death", None)
                            .is_err();
                        if admitted && alpha_denied && delta_denied {
                            break;
                        }
                        if !diagnosed && started.elapsed() >= Duration::from_secs(10) {
                            diagnosed = true;
                            let status =
                                raw_json(ctx.state, &format!("team/{env}/sync_state.json"))
                                    .unwrap_or(Value::Null);
                            let peers = status["peers"].as_object().into_iter().flatten().take(2).map(|(peer,p)| (peer.clone(),json!({"session":p["session"],"last_error":p["last_error"]}))).collect::<serde_json::Map<_,_>>();
                            eprintln!(
                                "PVBOOT_OPUS_REMOVAL_PREDICATES {}",
                                json!({"fact_admitted":admitted,"fact_reason":facts.as_ref().err().map(|e|e.reason.as_ref()),"alpha_denied":alpha_denied,"delta_denied":delta_denied,"peers":peers,"deny_witness":fs::symlink_metadata(ctx.state.path.join(path(&env,import_barrier::LOCAL_REMOVAL_DENIAL).unwrap())).is_ok(),"fact_witness":fs::symlink_metadata(ctx.state.path.join(path(&env,"member-removed.json").unwrap())).is_ok()})
                            );
                        }
                        assert!(
                            Instant::now() < deadline,
                            "35-second ordinary removal admission and credential denial deadline"
                        );
                        thread::sleep(Duration::from_millis(20));
                    }
                    assert!(
                        !ctx.vault
                            .list_secrets(None, None)
                            .unwrap()
                            .iter()
                            .any(|secret| matches!(secret.id.as_str(), "alpha" | "after-death"))
                    );
                    assert!(
                        ctx.vault
                            .secret_for_trusted_use("unrelated", None)
                            .unwrap()
                            .ct_eq(b"synthetic-install-fault-value")
                    );
                    let folded = membership::load_environment(&ctx, &env).unwrap();
                    assert_eq!(folded.document["members"][&me]["status"], "removed");
                    assert_eq!(
                        super::super::status(&ctx, &env).unwrap()["state"],
                        "recovery_required"
                    );
                    emit("PVBOOT_OPUS_ORDINARY_REMOVAL_DENIES_CACHED_USE");
                }
                "stop" => break,
                _ => panic!("unknown owned test command"),
            }
        }
        team.stop();
    }

    #[test]
    fn killed_install_reopens_challenges_activates_and_delivers_ordinary_revocation() {
        for point in [
            "installing-index-after",
            "committed-index-publication-after",
        ] {
            let fixture = tests::pending();
            sync::attached(&fixture.a).unwrap().enable_sync_state();
            sync::attached(&fixture.b).unwrap().stop();
            super::super::approval::approve_receiver(
                &fixture.b,
                &fixture.env,
                text(&fixture.pending, "inviter_record_binding").unwrap(),
                text(&fixture.pending, "self_record_binding").unwrap(),
                "synthetic-install-fault-administrator",
            )
            .unwrap();
            let bfp = DeviceKey::load_or_create(fixture.b.state, fixture.b.kms)
                .unwrap()
                .fingerprint()
                .unwrap();
            let auth_name = path(&fixture.env, &format!("authorizations/{bfp}.json")).unwrap();
            assert_ne!(
                raw_json(fixture.a.state, &auth_name).unwrap()["activated"],
                true
            );
            let mut killed = OwnedProcess::spawn(
                &fixture.b,
                &fixture.a,
                &fixture.env,
                &format!("pause:{point}"),
            );
            killed.expect(
                "PVBOOT_OPUS_DURABLE_INSTALL_BOUNDARY",
                Instant::now() + Duration::from_secs(35),
            );
            killed.kill_wait();
            let auth = raw_json(fixture.a.state, &auth_name).unwrap();
            let admission = commit::Commit::from_dict(&auth["admission"]).unwrap();
            let admission_hash = admission.hash().unwrap();
            assert_ne!(auth["activated"], true);
            let journal = raw_json(
                fixture.b.state,
                &path(&fixture.env, "journal.json").unwrap(),
            )
            .unwrap();
            let epoch = journal["epoch"].clone();
            if point == "committed-index-publication-after" {
                assert_eq!(journal["layout"], "compact_committed_v1");
            }
            let queries =
                import_barrier::opus_cost::Scope::protocol_trace(fixture.a.state, &fixture.env);
            let agreement_deadline = Instant::now() + Duration::from_secs(35);
            let mut reopened = OwnedProcess::spawn(&fixture.b, &fixture.a, &fixture.env, "reopen");
            reopened.expect("PVBOOT_OPUS_REOPEN_FRESH_AGREEMENT", agreement_deadline);
            let a = sync::attached(&fixture.a).unwrap();
            while raw_json(fixture.a.state, &auth_name).unwrap()["activated"] != true
                || a.synced_at(&fixture.env).is_none()
            {
                assert!(
                    Instant::now() < agreement_deadline,
                    "same 35-second fresh A/B agreement deadline"
                );
                thread::sleep(Duration::from_millis(20));
            }
            assert_eq!(queries.metrics().get("receipt_queries_sent"), Some(&1));
            let active = raw_json(fixture.a.state, &auth_name).unwrap();
            assert_eq!(active["admission"], auth["admission"]);
            let receipt = fs::read(
                fixture
                    .b
                    .state
                    .path
                    .join(path(&fixture.env, "receipt.json").unwrap()),
            )
            .unwrap();
            assert_eq!(
                raw_json(
                    fixture.b.state,
                    &path(&fixture.env, "journal.json").unwrap()
                )
                .unwrap()["epoch"],
                epoch
            );
            let cipher = crate::team::envelope::encrypt_secret(
                &[7; 32],
                &fixture.env,
                "after-death",
                "eeeeeeeeeeeeeeee",
                DELTA,
            )
            .unwrap();
            let delta = membership::author_commit(&fixture.a, Some(a.as_ref()), &fixture.env, vec![
                json!({"op":"secret.put_version","secret_id":"after-death","version_id":"eeeeeeeeeeeeeeee","generation_id":"0123456789abcdef","kind":"api_key","ciphertext":cipher,"public":{}}),
                json!({"op":"secret.activate","secret_id":"after-death","version_id":"eeeeeeeeeeeeeeee"}),
            ]).unwrap();
            reopened.send(json!({"phase":"delta","sequence":delta.author_seq.value(),"hash":delta.hash().unwrap()}));
            reopened.expect(
                "PVBOOT_OPUS_ORDINARY_DELTA_AND_USE",
                Instant::now() + Duration::from_secs(35),
            );
            let removed =
                membership::remove_member(&fixture.a, Some(a.as_ref()), &fixture.env, &bfp)
                    .unwrap();
            let fact = sync::Fact::from_dict(&removed["fact"]).unwrap();
            assert_eq!(fact.kind, "member_removed");
            assert_eq!(fact.target["fingerprint"], bfp);
            reopened.send(json!({"phase":"removed","fact_hash":fact.hash().unwrap()}));
            reopened.expect(
                "PVBOOT_OPUS_ORDINARY_REMOVAL_DENIES_CACHED_USE",
                Instant::now() + Duration::from_secs(35),
            );
            reopened.finish();
            let denied_reopen = Context::open(
                &fixture.b.state.path,
                crate::context::Config::default(),
                crate::clock::system(),
            )
            .unwrap();
            assert!(
                sync::load_facts(&denied_reopen, &fixture.env)
                    .unwrap()
                    .1
                    .contains(&fact.hash().unwrap())
            );
            assert!(
                denied_reopen
                    .vault
                    .secret_for_trusted_use("alpha", None)
                    .is_err()
            );
            assert!(
                denied_reopen
                    .vault
                    .secret_for_trusted_use("after-death", None)
                    .is_err()
            );
            assert!(
                !denied_reopen
                    .vault
                    .list_secrets(None, None)
                    .unwrap()
                    .iter()
                    .any(|secret| matches!(secret.id.as_str(), "alpha" | "after-death"))
            );
            assert!(
                denied_reopen
                    .vault
                    .secret_for_trusted_use("unrelated", None)
                    .unwrap()
                    .ct_eq(b"synthetic-install-fault-value")
            );
            assert_eq!(
                super::super::status(&denied_reopen, &fixture.env).unwrap()["state"],
                "recovery_required"
            );
            assert_eq!(
                fs::read(
                    fixture
                        .b
                        .state
                        .path
                        .join(path(&fixture.env, "receipt.json").unwrap())
                )
                .unwrap(),
                receipt
            );
            let commits = CommitStore::new(fixture.a.state, &fixture.env)
                .all_commits()
                .unwrap();
            assert_eq!(
                commits
                    .iter()
                    .filter(|commit| commit.hash().unwrap() == admission_hash)
                    .count(),
                1
            );
            assert_eq!(
                commits
                    .iter()
                    .flat_map(|commit| &commit.ops)
                    .filter(|op| op["op"] == "member.add" && op["device"] == auth["device_record"])
                    .count(),
                1
            );
            assert_eq!(queries.metrics().get("receipt_queries_sent"), Some(&1));
            eprintln!(
                "PVBOOT_OPUS_REAL_KILL_REOPEN_ACTIVATION point={point} one_admission=true fresh_queries=1 ordinary_delta=true ordinary_removal_denied=true denial_after_reopen=true"
            );
        }
    }
}
