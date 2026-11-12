//! Full-record approval and exactly-once Personal admission. Admission intent
//! precedes consuming the invitation; retries use its exact signed original.
use super::{bad, digest, path, random, text};
use crate::team::{
    commit::{self, Commit, CommitStore, Hlc},
    identity::{DeviceKey, DeviceRecord},
    membership,
    transport::InviteDecision,
};
use crate::{context::Context, errors::Result, import_barrier, kms::WrappedKey};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use std::collections::BTreeMap;
use subtle::ConstantTimeEq;

/// Created only by reading a locally signed, reauthenticated approval and
/// checking its entire pinned peer record against the live encrypted session.
pub(crate) struct ReceiverApproval {
    record: Value,
}
impl ReceiverApproval {
    pub(crate) fn record(&self) -> &Value {
        &self.record
    }
    pub(crate) fn load(ctx: &Context, env: &str, peer: &DeviceRecord) -> Result<Self> {
        let attempt = ctx
            .state
            .read_json(&path(env, "attempt.json")?, Value::Null)?;
        let installed = crate::import_barrier::index(ctx.state)?[env]["state"] == "committed";
        if !installed
            && matches!(
                attempt["state"].as_str(),
                Some("cancelled" | "unsupported" | "recovery_required")
            )
        {
            return Err(bad("team_bootstrap_cancelled"));
        }
        let record = ctx
            .state
            .read_json(&path(env, "receiver.json")?, Value::Null)?;
        let mut signed = record.clone();
        let signature = signed
            .as_object_mut()
            .ok_or_else(|| bad("team_bootstrap_approval_pending"))?
            .remove("sig")
            .ok_or_else(|| bad("team_bootstrap_approval_pending"))?;
        let device = DeviceKey::load_or_create(ctx.state, ctx.kms)?.record()?;
        if record["domain"] != "zeropw-personal-bootstrap-approval-v1"
            || record["signer_record"] != peer.to_dict()
            || record["recipient_record"] != device.to_dict()
            || record["env_id"] != env
            || record["recipient_role"] != "admin"
            || record["state"] != "approved"
        {
            return Err(bad("team_bootstrap_approval_pending"));
        }
        if !installed
            && record["invitation_expires_at_ms"]
                .as_u64()
                .is_none_or(|x| x <= ((ctx.clock)() * 1000.0) as u64)
        {
            return Err(bad("team_bootstrap_authorization_expired"));
        }
        let sig = crate::pybase64::b64decode_strict(
            signature
                .as_str()
                .ok_or_else(|| bad("team_bootstrap_approval_pending"))?,
        )
        .map_err(|_| bad("team_bootstrap_approval_pending"))?;
        if !crate::crypto::ed25519::verify(&device.sign_pub, &super::bytes(&signed)?, &sig) {
            return Err(bad("team_bootstrap_approval_pending"));
        }
        Ok(Self { record })
    }
    pub(crate) fn expected(
        &self,
        peer: &DeviceRecord,
        session_nonce: &str,
        onboarding_nonce: &str,
    ) -> Result<crate::team::checkpoint::ExpectedContext> {
        use crate::team::checkpoint::*;
        let v = &self.record;
        ExpectedContext::from_local_expectations(
            LocalApprovalDescription {
                approval_id: text(v, "approval_id")?.into(),
                env_id: text(v, "env_id")?.into(),
                signer: peer.fingerprint(),
                signer_record: peer.clone(),
                recipient: text(v, "recipient")?.into(),
                recipient_role: RecipientRole::Admin,
                invite_id: text(v, "invite_id")?.into(),
                invitation_expires_at_ms: v["invitation_expires_at_ms"]
                    .as_u64()
                    .ok_or_else(|| bad("team_bootstrap_state_invalid"))?,
            },
            AuthenticatedSessionExpectations {
                peer_record: peer.clone(),
                env_id: text(v, "env_id")?.into(),
                local_recipient: text(v, "recipient")?.into(),
                session_nonce: session_nonce.into(),
                onboarding_nonce: onboarding_nonce.into(),
            },
        )
        .map_err(|_| bad("team_bootstrap_approval_changed"))
    }
}

pub(crate) fn observe_peer(
    ctx: &Context,
    env: &str,
    invite: &membership::Invite,
    peer: &DeviceRecord,
    project: &str,
    environment: &str,
) -> Result<Value> {
    let _lock = ctx.state.lock()?;
    if peer.fingerprint() != invite.inviter || !peer.verify_uncached() {
        return Err(bad("team_bootstrap_approval_changed"));
    }
    let observed = json!({"env_id":env,"signer_record":peer.to_dict(),"record_binding":digest(&peer.to_dict())?,"invite_id":membership::invite_id(invite.invite_secret.expose()),"invitation_expires_at_ms":(membership::parse_stored_time(&json!(invite.expires_at)).ok_or_else(||bad("invite_expired"))?*1000.0) as u64,"project":project,"environment":environment});
    import_barrier::json(ctx.state, &path(env, "observed.json")?, &observed)?;
    Ok(observed)
}

pub(crate) fn approve_receiver(
    ctx: &Context,
    env: &str,
    binding: &str,
    self_binding: &str,
    passphrase: &str,
) -> Result<Value> {
    let _auth = ctx.admin.verify(passphrase, None)?;
    let _lock = ctx.state.lock()?;
    let mut record = ctx
        .state
        .read_json(&path(env, "observed.json")?, Value::Null)?;
    if record["record_binding"] != binding || digest(&record["signer_record"])? != binding {
        return Err(bad("team_bootstrap_approval_changed"));
    }
    if record["invitation_expires_at_ms"]
        .as_u64()
        .is_none_or(|x| x <= ((ctx.clock)() * 1000.0) as u64)
    {
        return Err(bad("team_bootstrap_authorization_expired"));
    }
    if crate::import_barrier::index(ctx.state)?.get(env).is_some() {
        return Err(bad("team_bootstrap_existing_state_unsupported"));
    }
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms)?;
    if digest(&device.record()?.to_dict())? != self_binding {
        return Err(bad("team_bootstrap_approval_changed"));
    }
    record["domain"] = json!("zeropw-personal-bootstrap-approval-v1");
    record["state"] = json!("approved");
    record["approval_id"] = json!(random(16));
    record["recipient"] = json!(device.fingerprint()?);
    record["recipient_record"] = device.record()?.to_dict();
    record["recipient_role"] = json!("admin");
    record["trust_model"] = json!("administrator_attested");
    record["sig"] = json!(crate::pybase64::b64encode(
        &device.sign(&super::bytes(&record)?)?
    ));
    let p = path(env, "attempt.json")?;
    let mut attempt = ctx.state.read_json(&p, Value::Null)?;
    if attempt["state"] == "cancelled" {
        return Err(bad("team_bootstrap_cancelled"));
    }
    if attempt["invite_id"] != record["invite_id"] {
        return Err(bad("team_bootstrap_approval_changed"));
    }
    import_barrier::json(ctx.state, &path(env, "receiver.json")?, &record)?;
    attempt["state"] = json!("approval_pending");
    attempt["reason"] = Value::Null;
    import_barrier::json(ctx.state, &p, &attempt)?;
    ctx.audit.record(
        "team_join_approved",
        crate::audit::RecordArgs {
            result: Some("ok"),
            extra: vec![("env_id", json!(env)), ("detail", json!(binding))],
            ..Default::default()
        },
    )?;
    Ok(json!({"env_id":env,"state":"approval_pending","approval_id":record["approval_id"]}))
}

fn requests(ctx: &Context, env: &str) -> Result<Value> {
    let v = ctx
        .state
        .read_json(&path(env, "requests.json")?, json!({}))?;
    if !v.is_object() {
        return Err(bad("team_bootstrap_state_invalid"));
    }
    Ok(v)
}

fn sole_pending_admission(ctx: &Context, env: &str) -> Result<Option<Commit>> {
    let directory = ctx.state.path.join(path(env, "authorizations")?);
    if !directory.exists() {
        return Ok(None);
    }
    let mut found = None;
    for entry in std::fs::read_dir(directory).map_err(|_| bad("team_bootstrap_state_invalid"))? {
        let entry = entry.map_err(|_| bad("team_bootstrap_state_invalid"))?;
        if !entry
            .file_type()
            .map_err(|_| bad("team_bootstrap_state_invalid"))?
            .is_file()
            || found.is_some()
        {
            return Err(bad("team_bootstrap_semantic_scope_unsupported"));
        }
        let value = ctx.state.read_json(
            &path(
                env,
                &format!(
                    "authorizations/{}",
                    entry
                        .file_name()
                        .to_str()
                        .ok_or_else(|| bad("team_bootstrap_state_invalid"))?
                ),
            )?,
            Value::Null,
        )?;
        if value["activated"] == true {
            return Err(bad("team_bootstrap_semantic_scope_unsupported"));
        }
        found = Some(Commit::from_dict(&value["admission"])?);
    }
    Ok(found)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn create_invite(
    ctx: &Context,
    env: &str,
    role: &str,
    name: &str,
    ttl: i64,
    addresses: &[String],
    link: bool,
    approval: bool,
) -> Result<membership::CreatedInvite> {
    let history = commit::HistorySession::open_probe(ctx, env, commit::ProbePurpose::Invite)?;
    let created = membership::create_invite_with_input(
        ctx,
        env,
        role,
        name,
        ttl,
        addresses,
        link,
        approval,
        Some(&history),
    )?;
    enable(ctx, env, &created.invite_id, Some(&history))?;
    Ok(created)
}
pub(crate) fn enable(
    ctx: &Context,
    env: &str,
    invite: &str,
    parent: Option<&commit::HistorySession<'_>>,
) -> Result<()> {
    if let Some(history) = parent {
        return enable_with_input(ctx, env, invite, history);
    }
    let history = commit::HistorySession::open_probe(ctx, env, commit::ProbePurpose::Invite)?;
    enable_with_input(ctx, env, invite, &history)
}
fn enable_with_input(
    ctx: &Context,
    env: &str,
    invite: &str,
    history: &commit::HistorySession<'_>,
) -> Result<()> {
    let input = history.acquire()?;
    let live = input.commits()?;
    let vector = input.vector()?;
    if vector
        .iter()
        .all(|(fp, n)| *n == live.iter().filter(|c| &c.author == fp).count())
    {
        return Ok(());
    }
    let existing = sole_pending_admission(ctx, env)?;
    profile_with_input(ctx, env, existing.as_ref(), history)?;
    let input = history.acquire()?;
    let v = input.read_json(&format!("team/{env}/invites.json"), Value::Null)?;
    if v[invite]["approval"] != "required" || v[invite]["role"] != "admin" {
        return Err(bad("team_bootstrap_semantic_scope_unsupported"));
    }
    let owner = DeviceKey::load_or_create(ctx.state, ctx.kms)?.record()?;
    let genesis = live
        .iter()
        .find(|c| c.author_seq == 1 && c.ops.first().is_some_and(|op| op["op"] == "env.init"))
        .ok_or_else(|| bad("team_bootstrap_authority_unproven"))?;
    let witness = json!({"v":1,"invite_id":invite,"owner_record":owner.to_dict(),"genesis_hash":genesis.hash()?,"initial_revision":input.revision()?});
    history.check()?;
    import_barrier::json(
        ctx.state,
        &path(env, &format!("invites/{invite}.json"))?,
        &witness,
    )
}

pub(crate) fn list(ctx: &Context, env: &str) -> Result<Vec<Value>> {
    let _lock = ctx.state.lock()?;
    let r = requests(ctx, env)?;
    Ok(r.as_object()
        .into_iter()
        .flatten()
        .filter(|(_, v)| v["state"] == "approval_pending")
        .map(|(id, v)| {
            let mut v = v.clone();
            v["request_id"] = json!(id);
            v
        })
        .collect())
}

pub(crate) fn approve(
    ctx: &Context,
    env: &str,
    request: &str,
    binding: &str,
    passphrase: &str,
) -> Result<Value> {
    let _auth = ctx.admin.verify(passphrase, None)?;
    let history = commit::HistorySession::open_probe(ctx, env, commit::ProbePurpose::Invite)?;
    let mut r = requests(ctx, env)?;
    let v = r
        .get_mut(request)
        .ok_or_else(|| bad("team_bootstrap_approval_changed"))?;
    if v["state"] != "approval_pending"
        || v["record_binding"] != binding
        || digest(&v["device_record"])? != binding
    {
        return Err(bad("team_bootstrap_approval_changed"));
    }
    let record = DeviceRecord::from_dict(&v["device_record"])?;
    if !record.verify_uncached() || record.fingerprint() != text(v, "fingerprint")? {
        return Err(bad("team_bootstrap_approval_changed"));
    }
    let existing = ctx.state.read_json(
        &path(
            env,
            &format!("authorizations/{}.json", record.fingerprint()),
        )?,
        Value::Null,
    )?;
    let admission = if existing.is_null() {
        None
    } else {
        if existing["device_record"] != record.to_dict() || existing["activated"] == true {
            return Err(bad("team_bootstrap_semantic_scope_unsupported"));
        }
        Some(Commit::from_dict(&existing["admission"])?)
    };
    profile_with_input(ctx, env, admission.as_ref(), &history)?;
    let invite = text(v, "invite_id")?.to_owned();
    let invites = ctx
        .state
        .read_json(&format!("team/{env}/invites.json"), Value::Null)?;
    let expires = membership::parse_stored_time(&invites[&invite]["expires_at"])
        .ok_or_else(|| bad("invite_expired"))?;
    if expires <= (ctx.clock)()
        || invites[&invite]["used"] == true
        || !invites[&invite]["revoked_at"].is_null()
    {
        return Err(bad("invite_expired"));
    }
    v["state"] = json!("approved");
    v["approved_at"] = json!((ctx.clock)());
    let wire_expiry = membership::parse_stored_time(&json!(crate::store::iso(Some(expires))))
        .ok_or_else(|| bad("invite_expired"))?;
    v["authorization_id"] = json!(random(16));
    v["expires_at_ms"] = json!((wire_expiry * 1000.0) as u64);
    import_barrier::json(ctx.state, &path(env, "requests.json")?, &r)?;
    ctx.audit.record(
        "team_join_approved",
        crate::audit::RecordArgs {
            result: Some("ok"),
            extra: vec![
                ("env_id", json!(env)),
                ("fingerprint", json!(record.fingerprint())),
                ("detail", json!(binding)),
            ],
            ..Default::default()
        },
    )?;
    Ok(json!({"env_id":env,"fingerprint":record.fingerprint(),"approved_invites":[invite]}))
}

pub(crate) fn deny(
    ctx: &Context,
    env: &str,
    request: &str,
    binding: &str,
    passphrase: &str,
) -> Result<Value> {
    let _auth = ctx.admin.verify(passphrase, None)?;
    let _lock = ctx.state.lock()?;
    let mut r = requests(ctx, env)?;
    let v = r
        .get_mut(request)
        .ok_or_else(|| bad("team_bootstrap_approval_changed"))?;
    if v["record_binding"] != binding
        || !matches!(v["state"].as_str(), Some("approval_pending" | "approved"))
    {
        return Err(bad("team_bootstrap_approval_changed"));
    }
    let invite = v["invite_id"].clone();
    let fp = v["fingerprint"].clone();
    v["state"] = json!("cancelled");
    import_barrier::json(ctx.state, &path(env, "requests.json")?, &r)?;
    let ap = path(
        env,
        &format!(
            "authorizations/{}.json",
            fp.as_str()
                .ok_or_else(|| bad("team_bootstrap_state_invalid"))?
        ),
    )?;
    let mut auth = ctx.state.read_json(&ap, Value::Null)?;
    if auth["request_id"] == request {
        auth["cancelled"] = json!(true);
        import_barrier::json(ctx.state, &ap, &auth)?;
    }
    Ok(json!({"env_id":env,"fingerprint":fp,"revoked_invites":[invite]}))
}

/// Returns None only when this is not a Personal invitation. A matching
/// Personal proof never falls through to the legacy fingerprint-only consumer.
pub(crate) fn check(
    ctx: &Context,
    env: &str,
    peer: &DeviceRecord,
    transcript: &[u8],
    proof: &[u8],
) -> Result<Option<InviteDecision>> {
    let history = commit::HistorySession::open_runtime(ctx.state, env)?;
    let ip = format!("team/{env}/invites.json");
    let mut invites = history.acquire()?.read_json(&ip, json!({}))?;
    let mut found = None;
    for (id, v) in invites.as_object().into_iter().flatten() {
        if !ctx.state.exists(&path(env, &format!("invites/{id}.json"))?)
            || v["used"] == true
            || !v["revoked_at"].is_null()
        {
            continue;
        }
        if membership::parse_stored_time(&v["expires_at"]).is_none_or(|t| t <= (ctx.clock)()) {
            continue;
        }
        let wrapped = WrappedKey::from_dict(&v["wrapped_secret"])?;
        let secret = ctx.kms.unwrap(&wrapped)?;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret.expose()).map_err(|_| bad("invite_malformed"))?;
        mac.update(transcript);
        if bool::from(mac.finalize().into_bytes().ct_eq(proof)) {
            found = Some(id.clone());
            break;
        }
    }
    let Some(invite) = found else {
        return Ok(None);
    };
    if !peer.verify_uncached() {
        return Err(bad("team_bootstrap_approval_changed"));
    }
    let binding = digest(&peer.to_dict())?;
    let ap = path(env, &format!("authorizations/{}.json", peer.fingerprint()))?;
    let previous = ctx.state.read_json(&ap, Value::Null)?;
    if !previous.is_null()
        && (previous["device_record"] != peer.to_dict() || previous["activated"] == true)
    {
        return Err(bad("team_bootstrap_semantic_scope_unsupported"));
    }
    let mut r = requests(ctx, env)?;
    let map = r
        .as_object_mut()
        .ok_or_else(|| bad("team_bootstrap_state_invalid"))?;
    let id = map
        .iter()
        .find(|(_, v)| v["invite_id"] == invite && v["record_binding"] == binding)
        .map(|(id, _)| id.clone());
    let id = if let Some(id) = id {
        id
    } else {
        if map.values().filter(|v| v["invite_id"] == invite).count() >= 8 {
            return Err(bad("team_bootstrap_limit_exceeded"));
        }
        let id = random(16);
        map.insert(id.clone(),json!({"env_id":env,"invite_id":invite,"fingerprint":peer.fingerprint(),"device_record":peer.to_dict(),"record_binding":binding,"state":"approval_pending","first_seen_at":(ctx.clock)(),"last_seen_at":(ctx.clock)(),"attempts":0}));
        id
    };
    let v = map
        .get_mut(&id)
        .ok_or_else(|| bad("team_bootstrap_state_invalid"))?;
    v["attempts"] = json!(v["attempts"].as_u64().unwrap_or(0).saturating_add(1));
    v["last_seen_at"] = json!((ctx.clock)());
    if v["state"] == "approval_pending" {
        import_barrier::json(ctx.state, &path(env, "requests.json")?, &r)?;
        return Ok(Some(InviteDecision::PendingPersonal));
    }
    if v["state"] != "approved" {
        return Err(bad("team_bootstrap_approval_changed"));
    }
    let prepared = if previous.is_null() {
        prepare(ctx, env, peer, &invites[&invite], &history)?
    } else {
        let c = Commit::from_dict(&previous["admission"])?;
        profile_with_input(ctx, env, Some(&c), &history)?;
        c
    };
    let mut intent = v.clone();
    intent["request_id"] = json!(id);
    intent["admission"] = prepared.to_dict();
    intent["state"] = json!("admission_intent");
    let ap = path(env, &format!("authorizations/{}.json", peer.fingerprint()))?;
    history.check()?;
    import_barrier::json(ctx.state, &ap, &intent)?;
    history.check()?;
    invites[&invite]["used"] = json!(true);
    invites[&invite]["used_by"] = json!(peer.fingerprint());
    invites[&invite]["used_at"] = json!((ctx.clock)());
    invites[&invite]
        .as_object_mut()
        .ok_or_else(|| bad("team_bootstrap_state_invalid"))?
        .remove("wrapped_secret");
    history.check()?;
    import_barrier::json(ctx.state, &ip, &invites)?;
    history.check()?;
    recover_admission(ctx, env, peer, &history)?;
    Ok(Some(InviteDecision::Accept))
}

fn prepare(
    ctx: &Context,
    env: &str,
    peer: &DeviceRecord,
    invite: &Value,
    parent: &commit::HistorySession<'_>,
) -> Result<Commit> {
    let history = parent.nested(ctx.state, env)?;
    profile_with_input(ctx, env, None, &history)?;
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms)?;
    history.match_local_identity(&device.record()?)?;
    let doc = membership::load_environment_with_input(ctx, env, &history)?.document;
    let mut wraps = serde_json::Map::new();
    for generation in doc["dek"]["generations"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(k, _)| k)
    {
        let value = ctx
            .state
            .read_json(&format!("team/{env}/dek/{generation}.json"), Value::Null)?;
        if value.is_null() {
            continue;
        }
        let key = ctx.kms.unwrap(&WrappedKey::from_dict(&value)?)?;
        wraps.insert(
            generation.clone(),
            crate::team::envelope::wrap_dek(key.expose(), env, generation, peer)?,
        );
    }
    let store = CommitStore::new(ctx.state, env);
    let live = history.acquire()?.commits()?;
    let mut hlc = Hlc::new(0, 0);
    for c in &live {
        hlc.observe(&c.hlc)?;
    }
    crate::team::compaction_heads::observe_cached_hlcs(&store, &live, &mut hlc)?;
    history.check()?;
    commit::sign_commit(
        &device,
        env,
        &store.last_seq(&device.fingerprint()?)? + 1,
        &hlc.tick(None),
        &store.vector()?,
        vec![
            json!({"op":"member.add","device":peer.to_dict(),"name":invite["name"],"role":"admin","wraps":wraps}),
        ],
    )
}

pub(crate) fn recover_admission(
    ctx: &Context,
    env: &str,
    peer: &DeviceRecord,
    parent: &commit::HistorySession<'_>,
) -> Result<Value> {
    let history = parent.nested(ctx.state, env)?;
    history.preflight_inventory()?;
    let ap = path(env, &format!("authorizations/{}.json", peer.fingerprint()))?;
    let mut auth = ctx.state.read_json(&ap, Value::Null)?;
    if auth["device_record"] != peer.to_dict() || auth["record_binding"] != digest(&peer.to_dict())?
    {
        return Err(bad("team_bootstrap_approval_changed"));
    }
    let c = Commit::from_dict(&auth["admission"])?;
    let store = CommitStore::new(ctx.state, env);
    match store.get(&c.author, c.author_seq.clone())? {
        Some(existing) if existing.to_dict() == c.to_dict() => {}
        Some(_) => return Err(bad("team_bootstrap_admission_conflict")),
        None => {
            let owner = DeviceKey::load_or_create(ctx.state, ctx.kms)?.record()?;
            #[cfg(test)]
            import_barrier::testing::hit(ctx.state, env, "admission-append-before")?;
            if !commit::verify_commit(&c, &owner)
                || commit::receive_runtime_with_input(
                    &store,
                    &c,
                    commit::now_ms(),
                    Some(ctx.audit),
                    true,
                    &history,
                    ctx,
                )? != "accepted"
            {
                return Err(bad("team_bootstrap_admission_conflict"));
            }
            #[cfg(test)]
            import_barrier::testing::hit(ctx.state, env, "admission-append-after")?;
        }
    }
    // If the process died before consumption, finish that exact intent before
    // making its durable membership usable. No second invitation is selected.
    let ip = format!("team/{env}/invites.json");
    let mut invites = ctx.state.read_json(&ip, Value::Null)?;
    let id = text(&auth, "invite_id")?.to_owned();
    if invites[&id]["used"] == true && invites[&id]["used_by"] != peer.fingerprint() {
        return Err(bad("team_bootstrap_admission_conflict"));
    }
    invites[&id]["used"] = json!(true);
    invites[&id]["used_by"] = json!(peer.fingerprint());
    invites[&id]
        .as_object_mut()
        .ok_or_else(|| bad("team_bootstrap_state_invalid"))?
        .remove("wrapped_secret");
    history.check()?;
    import_barrier::json(ctx.state, &ip, &invites)?;
    history.check()?;
    #[cfg(test)]
    import_barrier::testing::hit(ctx.state, env, "admission-derive-before")?;
    membership::refold_and_derive_with_input(ctx, env, &history)?;
    #[cfg(test)]
    import_barrier::testing::hit(ctx.state, env, "admission-derive-after")?;
    auth["state"] = json!("admitted");
    history.check()?;
    import_barrier::json(ctx.state, &ap, &auth)?;
    history.check()?;
    Ok(auth)
}

pub(crate) fn recover_all(ctx: &Context, env: &str) -> Result<()> {
    let history = commit::HistorySession::open_runtime(ctx.state, env)?;
    recover_all_with_input(ctx, env, &history)
}
pub(crate) fn recover_all_with_input(
    ctx: &Context,
    env: &str,
    parent: &commit::HistorySession<'_>,
) -> Result<()> {
    let candidate = ctx
        .state
        .path
        .join(format!("team/{env}/bootstrap/authorizations"));
    if matches!(std::fs::symlink_metadata(&candidate),Err(error) if error.kind()==std::io::ErrorKind::NotFound)
    {
        return Ok(());
    }
    let history = parent.nested(ctx.state, env)?;
    history.preflight_inventory()?;
    let directory = ctx.state.path.join(path(env, "authorizations")?);
    if !directory.exists() {
        return Ok(());
    }
    let _lock = ctx.state.lock()?;
    for entry in std::fs::read_dir(directory).map_err(|_| bad("team_bootstrap_state_invalid"))? {
        let entry = entry.map_err(|_| bad("team_bootstrap_state_invalid"))?;
        if !entry
            .file_type()
            .map_err(|_| bad("team_bootstrap_state_invalid"))?
            .is_file()
        {
            return Err(bad("team_bootstrap_state_invalid"));
        }
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| bad("team_bootstrap_state_invalid"))?;
        let auth = ctx
            .state
            .read_json(&path(env, &format!("authorizations/{name}"))?, Value::Null)?;
        if auth["state"] == "admission_intent" {
            let peer = DeviceRecord::from_dict(&auth["device_record"])?;
            recover_admission(ctx, env, &peer, &history)?;
        }
    }
    Ok(())
}

pub(crate) fn validate_invite_profile(
    ctx: &Context,
    env: &str,
    history: &commit::HistorySession<'_>,
) -> Result<()> {
    let admission = sole_pending_admission(ctx, env)?;
    profile_with_input(ctx, env, admission.as_ref(), history)
}
pub(crate) fn profile_with_input(
    ctx: &Context,
    env: &str,
    admission: Option<&Commit>,
    history: &commit::HistorySession<'_>,
) -> Result<()> {
    history.preflight_inventory()?;
    import_barrier::validate_environment_tree(ctx.state, env)?;
    import_barrier::validate_inventory(ctx.state, env)?;
    if ctx.policy.restore_pending()? {
        return Err(bad("team_bootstrap_semantic_scope_unsupported"));
    }
    let audit_path = ctx.state.path.join("audit/audit.jsonl");
    if audit_path
        .metadata()
        .map(|m| m.len() > 16 * 1024 * 1024)
        .unwrap_or(false)
    {
        return Err(bad("team_bootstrap_limit_exceeded"));
    }
    for line in ctx.state.read_lines("audit/audit.jsonl", None)? {
        // Audit::assert_writable durably appends an empty probe line.
        if line.is_empty() {
            continue;
        }
        let event = crate::pyjson::loads(&line)
            .map_err(|_| bad("team_bootstrap_semantic_scope_unsupported"))?;
        if event["event"] == "restore" || event["event"] == "recover" {
            return Err(bad("team_bootstrap_semantic_scope_unsupported"));
        }
    }
    let owner = DeviceKey::load_or_create(ctx.state, ctx.kms)?.record()?;
    let fp = owner.fingerprint();
    if commit::env_owner_fingerprint(env)? != fp {
        return Err(bad("team_bootstrap_semantic_scope_unsupported"));
    }
    let input = history.acquire()?;
    let commits = input.commits()?;
    let allowed = admission
        .and_then(|c| c.ops.first())
        .map(|o| DeviceRecord::from_dict(&o["device"]))
        .transpose()?;
    for dir in ["deferred", "rejected"] {
        let p = ctx.state.path.join(format!("team/{env}/{dir}"));
        if p.exists()
            && std::fs::read_dir(p)
                .map_err(|_| bad("team_bootstrap_state_invalid"))?
                .next()
                .is_some()
        {
            return Err(bad("team_bootstrap_semantic_scope_unsupported"));
        }
    }
    let vector = input.vector()?;
    if vector.iter().any(|(author, n)| author != &fp && *n > 0) {
        return Err(bad("team_bootstrap_semantic_scope_unsupported"));
    }
    let mut genesis = false;
    let mut additions = 0;
    for c in &commits {
        if c.author != fp || !commit::verify_commit(c, &owner) {
            return Err(bad("team_bootstrap_semantic_scope_unsupported"));
        }
        for op in &c.ops {
            match op["op"].as_str() {
                Some("env.init") => {
                    if genesis || c.author_seq != 1 || op["owner_device"] != owner.to_dict() {
                        return Err(bad("team_bootstrap_semantic_scope_unsupported"));
                    }
                    genesis = true;
                }
                Some("member.add") => {
                    additions += 1;
                    if additions != 1
                        || allowed.as_ref().is_none_or(|r| op["device"] != r.to_dict())
                        || op["role"] != "admin"
                        || admission.is_none_or(|a| a.to_dict() != c.to_dict())
                    {
                        return Err(bad("team_bootstrap_semantic_scope_unsupported"));
                    }
                }
                Some("member.set_role" | "member.remove" | "owner.transfer") => {
                    return Err(bad("team_bootstrap_semantic_scope_unsupported"));
                }
                Some("dek.rotate") if op.get("removal_fact_hash").is_some() => {
                    return Err(bad("team_bootstrap_semantic_scope_unsupported"));
                }
                _ => {}
            }
        }
    }
    if !genesis {
        return Err(bad("team_bootstrap_authority_unproven"));
    }
    let (facts, _, _) = crate::team::sync::load_facts_with_input(ctx, env, history)?;
    if !ctx
        .state
        .read_lines(&format!("team/{env}/rejected_facts.jsonl"), None)?
        .is_empty()
    {
        return Err(bad("team_bootstrap_semantic_scope_unsupported"));
    }
    if !facts.removed_members.is_empty() || !facts.removal_facts.is_empty() {
        return Err(bad("team_bootstrap_semantic_scope_unsupported"));
    }
    let doc = membership::load_environment_with_input(ctx, env, history)?.document;
    let expected = BTreeMap::from([(fp.clone(), owner.to_dict())])
        .into_iter()
        .chain(allowed.map(|r| (r.fingerprint(), r.to_dict())))
        .collect::<BTreeMap<_, _>>();
    let members = doc["members"]
        .as_object()
        .ok_or_else(|| bad("team_bootstrap_state_invalid"))?;
    if members.len() != expected.len()
        || members.iter().any(|(fp, m)| {
            m["status"] != "active"
                || m["role"] != "admin"
                || expected.get(fp) != Some(&m["device"])
        })
        || doc["owner"] != fp
    {
        return Err(bad("team_bootstrap_semantic_scope_unsupported"));
    }
    Ok(())
}
