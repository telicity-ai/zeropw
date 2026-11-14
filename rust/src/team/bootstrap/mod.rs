//! Personal first-pair onboarding. All authority originates in reauthenticated
//! local approval; transport enrollment and parser candidates confer none.
pub(crate) mod approval;
pub(crate) mod export;
pub(crate) mod install;
pub(crate) mod protocol;

use crate::{
    errors::{Error, Result},
    pyjson::{self, DumpOptions},
};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) const FEATURE: &str = "snapshot_bootstrap_v1";
pub(crate) fn bytes(value: &Value) -> Result<Vec<u8>> {
    Ok(pyjson::dumps(value, DumpOptions::compact_sorted())?.into_bytes())
}
pub(crate) fn digest(value: &Value) -> Result<String> {
    Ok(hex::encode(Sha256::digest(bytes(value)?)))
}
pub(crate) fn random(n: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}
pub(crate) fn bad(reason: &'static str) -> Error {
    Error::state(reason)
}
pub(crate) fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| bad("team_bootstrap_state_invalid"))
}
pub(crate) fn path(env: &str, leaf: &str) -> Result<String> {
    if !super::commit::valid_env_id(env)
        || leaf
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(bad("team_bootstrap_state_invalid"));
    }
    Ok(format!("team/{env}/bootstrap/{leaf}"))
}

use crate::{
    context::Context,
    import_barrier,
    kms::WrappedKey,
    secret::SecretBytes,
    team::{
        identity::DeviceKey,
        membership,
        sync::TeamSync,
        transport::{InviteProof, Session},
    },
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

static ACTIVE: LazyLock<Mutex<BTreeSet<(std::path::PathBuf, String)>>> =
    LazyLock::new(|| Mutex::new(BTreeSet::new()));
pub(super) struct Slot {
    key: (std::path::PathBuf, String),
    _lease: std::fs::File,
}
impl Slot {
    fn take(ctx: &Context, env: &str) -> Result<Self> {
        let lease = import_barrier::transfer_lease(ctx.state, env)?;
        let mut active = ACTIVE.lock().map_err(|_| bad("team_bootstrap_busy"))?;
        let key = (ctx.state.path.clone(), env.into());
        if active.len() >= 2 || !active.insert(key.clone()) {
            return Err(bad("team_bootstrap_busy"));
        }
        Ok(Self { key, _lease: lease })
    }
    pub(super) fn registration<'s>(
        &'s self,
        ctx: &Context,
        env: &str,
    ) -> Result<BootstrapRegistration<'s>> {
        if self.key != (ctx.state.path.clone(), env.to_owned()) {
            return Err(bad("team_bootstrap_local_state_changed"));
        }
        use std::os::unix::fs::MetadataExt;
        let held = self
            ._lease
            .metadata()
            .map_err(|_| bad("team_bootstrap_storage_failed"))?;
        let named = std::fs::symlink_metadata(ctx.state.path.join(path(env, "transfer.lock")?))
            .map_err(|_| bad("team_bootstrap_storage_failed"))?;
        if !named.is_file()
            || named.dev() != held.dev()
            || named.ino() != held.ino()
            || named.nlink() != 1
            || named.mode() & 0o777 != 0o600
        {
            return Err(bad("team_bootstrap_local_state_changed"));
        }
        Ok(BootstrapRegistration { slot: self })
    }
    pub(super) fn take_registration(ctx: &Context, env: &str) -> Result<Option<Self>> {
        let witness = ctx.state.path.join(path(env, "journal.json")?);
        match std::fs::symlink_metadata(witness) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            _ => Self::take(ctx, env).map(Some),
        }
    }
}
pub(crate) struct BootstrapRegistration<'s> {
    slot: &'s Slot,
}
impl BootstrapRegistration<'_> {
    pub(super) fn check(&self, ctx: &Context, env: &str) -> Result<()> {
        self.slot.registration(ctx, env).map(|_| ())
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        if let Ok(mut active) = ACTIVE.lock() {
            active.remove(&self.key);
        }
    }
}

pub(crate) fn begin(
    ctx: &Context,
    invite_text: &str,
    project: &str,
    environment: &str,
) -> Result<Value> {
    let invite = membership::parse_invite(invite_text)?;
    if invite.role != "admin" || membership::invite_expired(&invite, (ctx.clock)()) {
        return Err(bad("team_bootstrap_semantic_scope_unsupported"));
    }
    crate::projects::validate_name(project, "project")?;
    crate::projects::validate_name(environment, "environment")?;
    let history = super::commit::HistorySession::open_probe(
        ctx,
        &invite.env_id,
        super::commit::ProbePurpose::Recipient,
    )?;
    history.preflight_inventory()?;
    let p = path(&invite.env_id, "attempt.json")?;
    if ctx.state.exists(&p) {
        let old = ctx.state.read_json(&p, Value::Null)?;
        if old["project"] != project || old["environment"] != environment {
            return Err(bad("team_bootstrap_existing_state_unsupported"));
        }
        if old["invite_id"] == membership::invite_id(invite.invite_secret.expose()) {
            return status_with_input(ctx, &invite.env_id, &history);
        }
        if import_barrier::index(ctx.state)?
            .get(&invite.env_id)
            .is_some()
        {
            return Err(bad("team_bootstrap_existing_state_unsupported"));
        }
        let _lease = import_barrier::transfer_lease(ctx.state, &invite.env_id)?;
        history.invalidate()?;
        import_barrier::json(
            ctx.state,
            &path(
                &invite.env_id,
                &format!("attempts/{}.json", text(&old, "attempt_id")?),
            )?,
            &old,
        )?;
        history.check()?;
        for leaf in ["receiver.json", "observed.json"] {
            history.invalidate()?;
            import_barrier::json(ctx.state, &path(&invite.env_id, leaf)?, &Value::Null)?;
            history.check()?;
        }
    }
    history.invalidate()?;
    let wrapped = ctx.kms.wrap(invite_text.as_bytes())?;
    import_barrier::json(
        ctx.state,
        &p,
        &json!({"v":1,"attempt_id":random(16),"env_id":invite.env_id,"invite_id":membership::invite_id(invite.invite_secret.expose()),"invite":wrapped.to_dict(),"project":project,"environment":environment,"state":"approval_pending","created_at_ms":((ctx.clock)()*1000.0) as u64,"invitation_expires_at_ms":(membership::parse_stored_time(&json!(invite.expires_at)).ok_or_else(||bad("invite_expired"))?*1000.0) as u64}),
    )?;
    status_with_input(ctx, &invite.env_id, &history)
}

pub(crate) fn resume(
    ctx: &Context,
    invitation: &str,
    project: Option<&str>,
    environment: Option<&str>,
) -> Result<Value> {
    let invite = membership::parse_invite(invitation)?;
    let attempt = ctx
        .state
        .read_json(&path(&invite.env_id, "attempt.json")?, Value::Null)?;
    if attempt["invite_id"] == membership::invite_id(invite.invite_secret.expose()) {
        return status(ctx, &invite.env_id);
    }
    begin(
        ctx,
        invitation,
        project.unwrap_or(text(&attempt, "project")?),
        environment.unwrap_or(text(&attempt, "environment")?),
    )
}

pub(crate) fn status(ctx: &Context, env: &str) -> Result<Value> {
    let history = super::commit::HistorySession::open_recovery_entry(ctx, env)?;
    status_with_input(ctx, env, &history)
}
fn status_with_input(
    ctx: &Context,
    env: &str,
    parent: &super::commit::HistorySession<'_>,
) -> Result<Value> {
    let history = parent.nested(ctx.state, env)?;
    history.preflight_inventory()?;
    let io = history.import_io()?;
    let attempt = io
        .json(&path(env, "attempt.json")?, 65_536)?
        .unwrap_or(Value::Null);
    if attempt.is_null() {
        return Ok(
            json!({"env_id":env,"state":"unsupported","reason":"team_bootstrap_attempt_not_found"}),
        );
    }
    let observed = io
        .json(&path(env, "observed.json")?, 65_536)?
        .unwrap_or(Value::Null);
    let device = history.local_record()?;
    let mut state = attempt["state"].as_str().unwrap_or("recovery_required");
    let visibility = import_barrier::index_in(&io)?;
    let mut reason = attempt["reason"].clone();
    let known_state = matches!(
        state,
        "approval_pending"
            | "transferring"
            | "verifying"
            | "installing"
            | "installed_syncing"
            | "unsupported"
            | "recovery_required"
            | "cancelled"
    );
    if !known_state {
        state = "recovery_required";
        reason = json!("team_bootstrap_state_invalid");
    }
    if state == "cancelled" {
        state = "unsupported";
        reason = json!("team_bootstrap_cancelled");
    }
    if visibility.get(env).is_none()
        && attempt["invitation_expires_at_ms"]
            .as_u64()
            .is_some_and(|t| t <= ((ctx.clock)() * 1000.0) as u64)
    {
        state = "unsupported";
        reason = json!("team_bootstrap_authorization_expired");
    }
    if visibility[env]["local_member_removed"] == true {
        state = "recovery_required";
        reason = json!("team_member_removed");
    } else if visibility.get(env).is_some() && visibility[env]["state"] != "committed" {
        state = "recovery_required";
        reason = visibility[env]["reason"].clone();
    } else if visibility[env]["state"] == "committed" && ctx.policy.restore_pending()? {
        state = "recovery_required";
        reason = json!("team_bootstrap_recovery_required");
    } else if visibility[env]["state"] == "committed" {
        validate_receiver_continuation(ctx, env, &history, &attempt, &visibility)?;
        // Only a freshly authenticated committed runtime view can become
        // ready. The attempt label and an old receipt are DATA, not proof.
        let runtime = history.continue_runtime()?;
        state = "installed_syncing";
        if let Some(team) = crate::team::sync::attached(ctx)
            && team.synced_at_with_input(env, &runtime)?.is_some()
        {
            state = "ready";
        }
        let current = import_barrier::index_in(&runtime.import_io()?)?;
        if current[env]["local_member_removed"] == true {
            state = "recovery_required";
            reason = json!("team_member_removed");
        } else if current[env]["state"] != "committed" {
            state = "recovery_required";
            reason = json!("team_bootstrap_recovery_required");
        }
        runtime.check()?;
    } else if state == "installed_syncing" {
        state = "recovery_required";
        reason = json!("team_bootstrap_recovery_required");
    }
    let local_approval_complete =
        crate::team::identity::DeviceRecord::from_dict(&observed["signer_record"])
            .ok()
            .is_some_and(|peer| approval::ReceiverApproval::load(ctx, env, &peer).is_ok());
    history.check()?;
    Ok(
        json!({"env_id":env,"attempt_id":attempt["attempt_id"],"state":state,"reason":reason,"local_approval_complete":local_approval_complete,"failed_from":attempt["failed_from"],"self_fingerprint":device.fingerprint(),"self_record":device.to_dict(),"self_record_binding":digest(&device.to_dict())?,"inviter_fingerprint":observed["signer_record"].as_object().and_then(|_|crate::team::identity::DeviceRecord::from_dict(&observed["signer_record"]).ok()).map(|r|r.fingerprint()),"inviter_record":observed["signer_record"],"inviter_record_binding":observed["record_binding"],"project":attempt["project"],"environment":attempt["environment"]}),
    )
}

pub(crate) fn offer(
    ctx: &Context,
    env: &str,
    peer: &crate::team::identity::DeviceRecord,
) -> Result<()> {
    let _lock = ctx.state.lock()?;
    import_barrier::json(
        ctx.state,
        &path(env, "offer.json")?,
        &json!({"device_record":peer.to_dict()}),
    )
}

fn update(ctx: &Context, env: &str, state: &str, reason: Option<&str>) -> Result<()> {
    let _lock = ctx.state.lock()?;
    let p = path(env, "attempt.json")?;
    let mut attempt = ctx.state.read_json(&p, Value::Null)?;
    if attempt.is_null() {
        return Err(bad("team_bootstrap_attempt_not_found"));
    }
    if attempt["state"] == "cancelled" && state != "installed_syncing" {
        return Err(bad("team_bootstrap_cancelled"));
    }
    // An already-durable identical status is not a new transition. Avoid
    // replacing its inode while the current ordinary handler authenticates
    // its complete raw epoch. All real state/error changes still publish.
    if reason.is_none() && attempt["state"] == state && attempt.get("reason") == Some(&Value::Null)
    {
        #[cfg(test)]
        import_barrier::opus_cost::protocol_event(ctx.state, env, "attempt_update_noop");
        return Ok(());
    }
    if reason.is_some() {
        attempt["failed_from"] = attempt["state"].clone();
    }
    attempt["state"] = json!(state);
    attempt["reason"] = json!(reason);
    import_barrier::json(ctx.state, &p, &attempt)
}

fn update_with_input(
    ctx: &Context,
    env: &str,
    attempt_id: &Value,
    state: &str,
    reason: Option<&str>,
    history: &super::commit::HistorySession<'_>,
) -> Result<()> {
    let io = history.import_io()?;
    let name = path(env, "attempt.json")?;
    let mut attempt = io
        .json(&name, 65_536)?
        .ok_or_else(|| bad("team_bootstrap_attempt_not_found"))?;
    if &attempt["attempt_id"] != attempt_id {
        return Err(bad("team_bootstrap_local_state_changed"));
    }
    if attempt["state"] == "cancelled" && state != "installed_syncing" {
        return Err(bad("team_bootstrap_cancelled"));
    }
    // An already-durable identical status is not a new transition. Avoid
    // replacing its inode while the current ordinary handler authenticates
    // its complete raw epoch. All real state/error changes still publish.
    if reason.is_none() && attempt["state"] == state && attempt.get("reason") == Some(&Value::Null)
    {
        #[cfg(test)]
        import_barrier::opus_cost::protocol_event(ctx.state, env, "attempt_update_noop");
        return io.check();
    }
    if reason.is_some() {
        attempt["failed_from"] = attempt["state"].clone();
    }
    attempt["state"] = json!(state);
    attempt["reason"] = json!(reason);
    let raw = history.encode_import_record(&attempt)?;
    history.reserve_writer(&name, raw.len() as u64)?;
    io.invalidate()?;
    import_barrier::write(ctx.state, &name, &raw)?;
    io.check()
}

enum RestartDisposition {
    AwaitApproval,
    ContinueCommitted,
    ClosedInterrupted,
    Blocked,
}

fn validate_receiver_continuation(
    ctx: &Context,
    env: &str,
    history: &super::commit::HistorySession<'_>,
    attempt: &Value,
    imports: &Value,
) -> Result<()> {
    let io = history.import_io()?;
    let receipt = install::receipt_evidence(ctx, env, history)?;
    let receiver = io
        .json(&path(env, "receiver.json")?, 65_536)?
        .ok_or_else(|| bad("team_bootstrap_recovery_required"))?;
    let local = history.local_record()?;
    let compact = io
        .json(&path(env, "journal.json")?, 1_048_576)?
        .ok_or_else(|| bad("team_bootstrap_recovery_required"))?;
    verify_peer_signature(&receiver, local)?;
    let owner = super::identity::DeviceRecord::from_dict(&receiver["signer_record"])?;
    let invitation = ctx
        .kms
        .unwrap(&WrappedKey::from_dict(&attempt["invite"])?)?;
    let invite = membership::parse_invite(
        std::str::from_utf8(invitation.expose())
            .map_err(|_| bad("team_bootstrap_state_invalid"))?,
    )?;
    if receiver["domain"] != "zeropw-personal-bootstrap-approval-v1"
        || receiver["state"] != "approved"
        || receiver["signer_record"] != compact["signer_record"]
        || receiver["recipient_role"] != "admin"
        || receiver["recipient_record"] != local.to_dict()
        || receiver["env_id"] != env
        || receiver["approval_id"] != receipt["approval_id"]
        || receiver["invite_id"] != attempt["invite_id"]
        || receiver["project"] != imports[env]["project"]
        || receiver["environment"] != imports[env]["environment"]
        || attempt["project"] != imports[env]["project"]
        || attempt["environment"] != imports[env]["environment"]
        || invite.env_id != env
        || invite.inviter != owner.fingerprint()
        || membership::invite_id(invite.invite_secret.expose()) != attempt["invite_id"]
        || !owner.verify_uncached()
    {
        return Err(bad("team_bootstrap_recovery_required"));
    }
    history.check()?;
    Ok(())
}

fn reconcile_receiver(
    ctx: &Context,
    env: &str,
    slot: &Slot,
    history: &super::commit::HistorySession<'_>,
) -> Result<RestartDisposition> {
    slot.registration(ctx, env)?.check(ctx, env)?;
    install::recover_with_input(ctx, env, history)?;
    let io = history.import_io()?;
    let attempt = io
        .json(&path(env, "attempt.json")?, 65_536)?
        .ok_or_else(|| bad("team_bootstrap_attempt_not_found"))?;
    let imports = import_barrier::index_in(&io)?;
    if imports[env]["state"] == "committed" {
        // The label cannot select authority. Authenticate the full durable
        // continuation, exact original invite/approval/mapping and admission.
        validate_receiver_continuation(ctx, env, history, &attempt, &imports)?;
        let local = history.local_record()?;
        let continuation = history.continue_runtime()?;
        let folded = membership::load_environment_with_input(ctx, env, &continuation)?;
        if imports[env]["local_member_removed"] == true
            || folded.document["members"][local.fingerprint()]["status"] != "active"
            || ctx.policy.restore_pending()?
        {
            update_with_input(
                ctx,
                env,
                &attempt["attempt_id"],
                "recovery_required",
                Some("team_bootstrap_recovery_required"),
                history,
            )?;
            return Ok(RestartDisposition::Blocked);
        }
        update_with_input(
            ctx,
            env,
            &attempt["attempt_id"],
            "installed_syncing",
            None,
            history,
        )?;
        return Ok(RestartDisposition::ContinueCommitted);
    }
    if imports.get(env).is_some() && !install::prepared_without_publication(ctx, env, history)? {
        return Ok(RestartDisposition::Blocked);
    }
    match attempt["state"].as_str() {
        Some("approval_pending") => {
            if attempt["invitation_expires_at_ms"]
                .as_u64()
                .is_some_and(|expiry| expiry <= ((ctx.clock)() * 1000.0) as u64)
            {
                update_with_input(
                    ctx,
                    env,
                    &attempt["attempt_id"],
                    "unsupported",
                    Some("team_bootstrap_authorization_expired"),
                    history,
                )?;
                Ok(RestartDisposition::ClosedInterrupted)
            } else {
                Ok(RestartDisposition::AwaitApproval)
            }
        }
        Some("transferring" | "verifying" | "installing") => {
            install::discard_prepared_with_input(ctx, env, history)?;
            update_with_input(
                ctx,
                env,
                &attempt["attempt_id"],
                "unsupported",
                Some("team_bootstrap_transfer_interrupted"),
                history,
            )?;
            Ok(RestartDisposition::ClosedInterrupted)
        }
        Some("cancelled" | "unsupported") => Ok(RestartDisposition::ClosedInterrupted),
        _ => Ok(RestartDisposition::Blocked),
    }
}

pub(crate) fn cancel(ctx: &Context, env: &str) -> Result<Value> {
    let history = super::commit::HistorySession::open_recovery_entry(ctx, env)?;
    history.preflight_inventory()?;
    let mut attempt = ctx
        .state
        .read_json(&path(env, "attempt.json")?, Value::Null)?;
    if attempt.is_null() {
        return Err(bad("team_bootstrap_attempt_not_found"));
    }
    let index = import_barrier::index(ctx.state)?;
    attempt["state"] = json!(if index[env]["state"] == "committed" {
        "installed_syncing"
    } else if index.get(env).is_some() {
        "recovery_required"
    } else {
        "cancelled"
    });
    history.invalidate()?;
    import_barrier::json(ctx.state, &path(env, "attempt.json")?, &attempt)?;
    if index.get(env).is_none()
        && let Ok(_lease) = import_barrier::transfer_lease(ctx.state, env)
    {
        install::discard_prepared_with_input(ctx, env, &history)?;
    }
    status_with_input(ctx, env, &history)
}

fn send(session: &dyn Session, value: &Value) -> Result<()> {
    protocol::parse(&bytes(value)?)?;
    session.send(value).map_err(|error| {
        // A peer can close between authentication and CAPS (including while
        // its previous worker finishes). Match the receive-side offline
        // classification; a pending approval remains pending, never ready.
        if error.is(crate::errors::ErrorClass::StateError)
            && matches!(error.reason.as_ref(), "session_closed" | "send_failed")
        {
            bad("team_bootstrap_peer_offline")
        } else {
            error
        }
    })
}
fn recv(
    ctx: &Context,
    session: &dyn Session,
    deadline: &mut protocol::Deadline,
) -> Result<(Vec<u8>, Value)> {
    recv_protocol(ctx, session, deadline, false)
}

// Only a receiver with a verified committed receipt can select this narrow
// handoff after CAPS. A first ordinary M1 control is replayed into a fresh
// ordinary gate; it never stands in for READY or installation authority.
fn recv_protocol(
    ctx: &Context,
    session: &dyn Session,
    deadline: &mut protocol::Deadline,
    ordinary_handoff: bool,
) -> Result<(Vec<u8>, Value)> {
    loop {
        deadline.check()?;
        let attempt = ctx
            .state
            .read_json(&path(session.env_id(), "attempt.json")?, Value::Null)?;
        if attempt["state"] == "cancelled" {
            return Err(bad("team_bootstrap_cancelled"));
        }
        if attempt["invitation_expires_at_ms"]
            .as_u64()
            .is_some_and(|t| t <= ((ctx.clock)() * 1000.0) as u64)
            && import_barrier::index(ctx.state)?[session.env_id()]["state"] != "committed"
        {
            return Err(bad("team_bootstrap_authorization_expired"));
        }
        match session.recv_original(Duration::from_secs(1)) {
            Ok(Some(raw)) => {
                let value = protocol::parse(&raw)?;
                if value["type"] == "FACT" {
                    remember_restriction(ctx, session, &value)?;
                    deadline.progress()?;
                    continue;
                }
                if value["type"] == "BOOTSTRAP_REFUSAL" {
                    protocol::fields(&value, &["type", "env_id", "sender", "recipient", "reason"])?;
                    if value["env_id"] != session.env_id()
                        || value["sender"] != session.peer().fingerprint()
                        || value["recipient"]
                            != DeviceKey::load_or_create(ctx.state, ctx.kms)?.fingerprint()?
                    {
                        return Err(bad("team_bootstrap_binding_mismatch"));
                    }
                    return Err(bad(closed_reason(value["reason"].as_str().unwrap_or(""))));
                }
                let ordinary = ordinary_handoff
                    && (crate::team::tombstone_gate::is_control(
                        value["type"].as_str().unwrap_or(""),
                    ) || value["type"] == "VECTOR");
                if ordinary && value["type"] != "VECTOR" {
                    crate::team::tombstone_gate::validate(&value)?;
                }
                if !ordinary
                    && !protocol::is_control(value["type"].as_str().unwrap_or(""))
                    && !matches!(value["type"].as_str(), Some("SYNC_CAPS" | "JOIN_PENDING"))
                {
                    return Err(bad("team_bootstrap_control_malformed"));
                }
                deadline.progress()?;
                return Ok((raw, value));
            }
            Ok(None) => {}
            Err(error) => {
                return Err(bad(match error.0 {
                    "team_bootstrap_original_bytes_required" => {
                        "team_bootstrap_original_bytes_required"
                    }
                    "frame_too_large" => "team_bootstrap_limit_exceeded",
                    _ => "team_bootstrap_peer_offline",
                }));
            }
        }
    }
}

fn refusal(ctx: &Context, session: &dyn Session, reason: &str) -> Result<()> {
    let sender = DeviceKey::load_or_create(ctx.state, ctx.kms)?.fingerprint()?;
    send(
        session,
        &json!({"type":"BOOTSTRAP_REFUSAL","env_id":session.env_id(),"sender":sender,"recipient":session.peer().fingerprint(),"reason":closed_reason(reason)}),
    )
}
fn remember_restriction(ctx: &Context, session: &dyn Session, message: &Value) -> Result<()> {
    protocol::fields(message, &["type", "fact"])?;
    let env = session.env_id();
    let peer = session.peer();
    let _lock = ctx.state.lock()?;
    approval::ReceiverApproval::load(ctx, env, &peer)?;
    if crate::team::commit::env_owner_fingerprint(env)? != peer.fingerprint() {
        return Err(bad("team_bootstrap_semantic_scope_unsupported"));
    }
    let fact = crate::team::sync::Fact::from_dict(&message["fact"])?;
    crate::team::sync::validate_fact_target(&fact.kind, &fact.target)?;
    if fact.env_id != env
        || fact.author != peer.fingerprint()
        || !matches!(
            fact.kind.as_str(),
            "secret_deleted" | "secret_version_revoked" | "connection_disabled" | "member_removed"
        )
        || !crate::team::sync::verify_fact(&fact, &peer)
    {
        return Err(bad("team_bootstrap_authority_unproven"));
    }
    let p = path(env, "known-facts.json")?;
    let mut known = ctx.state.read_json(&p, json!({}))?;
    known
        .as_object_mut()
        .ok_or_else(|| bad("team_bootstrap_state_invalid"))?
        .insert(fact.hash()?, fact.to_dict());
    if known.as_object().is_none_or(|v| v.len() > 65_536)
        || bytes(&known)?.len() > protocol::PAYLOAD_CAP
    {
        return Err(bad("team_bootstrap_limit_exceeded"));
    }
    import_barrier::json(ctx.state, &p, &known)?;
    if fact.kind == "member_removed" {
        return Err(bad("team_bootstrap_semantic_scope_unsupported"));
    }
    Ok(())
}

fn closed_reason(reason: &str) -> &'static str {
    match reason {
        "team_bootstrap_admission_conflict" => "team_bootstrap_admission_conflict",
        "team_bootstrap_authority_unproven" => "team_bootstrap_authority_unproven",
        "team_bootstrap_existing_state_unsupported" => "team_bootstrap_existing_state_unsupported",
        "team_bootstrap_install_conflict" => "team_bootstrap_install_conflict",
        "team_bootstrap_local_state_changed" => "team_bootstrap_local_state_changed",
        "team_bootstrap_semantic_mismatch" => "team_bootstrap_semantic_mismatch",
        "team_bootstrap_session_changed" => "team_bootstrap_session_changed",
        "team_bootstrap_peer_offline" => "team_bootstrap_peer_offline",
        "team_bootstrap_binding_mismatch" => "team_bootstrap_binding_mismatch",
        "team_bootstrap_ready_invalid" => "team_bootstrap_ready_invalid",
        "team_bootstrap_receipt_invalid" => "team_bootstrap_receipt_invalid",
        "team_bootstrap_control_malformed" => "team_bootstrap_control_malformed",
        "team_bootstrap_chunk_order" => "team_bootstrap_chunk_order",
        "team_bootstrap_recovery_required" => "team_bootstrap_recovery_required",
        "team_bootstrap_state_invalid" => "team_bootstrap_state_invalid",
        "team_checkpoint_semantic_mismatch" => "team_checkpoint_semantic_mismatch",
        "team_bootstrap_semantic_scope_unsupported" => "team_bootstrap_semantic_scope_unsupported",
        "team_bootstrap_approval_changed" => "team_bootstrap_approval_changed",
        "team_bootstrap_original_bytes_required" => "team_bootstrap_original_bytes_required",
        "team_bootstrap_limit_exceeded" => "team_bootstrap_limit_exceeded",
        "team_peer_feature_unsupported" => "team_peer_feature_unsupported",
        "team_bootstrap_approval_pending" => "team_bootstrap_approval_pending",
        "team_bootstrap_cut_changed" => "team_bootstrap_cut_changed",
        "team_bootstrap_storage_failed" => "team_bootstrap_storage_failed",
        "team_bootstrap_busy" => "team_bootstrap_busy",
        "team_bootstrap_cancelled" => "team_bootstrap_cancelled",
        "team_bootstrap_timeout" => "team_bootstrap_timeout",
        "team_bootstrap_authorization_expired" => "team_bootstrap_authorization_expired",
        "team_checkpoint_history_required" => "team_checkpoint_history_required",
        "team_checkpoint_generation_unavailable" => "team_checkpoint_generation_unavailable",
        "team_checkpoint_json_invalid" => "team_checkpoint_json_invalid",
        "team_checkpoint_duplicate_key" => "team_checkpoint_duplicate_key",
        "team_checkpoint_limit_exceeded" => "team_checkpoint_limit_exceeded",
        "team_checkpoint_schema_unsupported" => "team_checkpoint_schema_unsupported",
        "team_checkpoint_binding_mismatch" => "team_checkpoint_binding_mismatch",
        "team_checkpoint_expired" => "team_checkpoint_expired",
        "team_checkpoint_signature_invalid" => "team_checkpoint_signature_invalid",
        "team_checkpoint_integrity_mismatch" => "team_checkpoint_integrity_mismatch",
        "team_checkpoint_structure_invalid" => "team_checkpoint_structure_invalid",
        _ => "team_bootstrap_peer_refused",
    }
}
fn caps(ctx: &Context, session: &dyn Session, deadline: &mut protocol::Deadline) -> Result<Value> {
    send(
        session,
        &json!({"type":"SYNC_CAPS","v":1,"features":["secret_tombstone_v1",FEATURE]}),
    )?;
    let (_, value) = recv(ctx, session, deadline)?;
    if value["type"] == "JOIN_PENDING" {
        return Err(bad("team_bootstrap_approval_pending"));
    }
    crate::team::tombstone_gate::validate(&value)?;
    if value["type"] != "SYNC_CAPS"
        || !value["features"].as_array().is_some_and(|f| {
            f.contains(&json!(FEATURE)) && f.contains(&json!("secret_tombstone_v1"))
        })
    {
        return Err(bad("team_peer_feature_unsupported"));
    }
    Ok(value)
}

// Actual completed local capability send on this exact authenticated socket.
// This private transient side-effect witness grants no membership or readiness.
pub(crate) struct SentCapabilities {
    session: std::sync::Weak<dyn Session>,
    peer: super::identity::DeviceRecord,
    env: String,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl SentCapabilities {
    pub(super) fn matches(&self, env: &str, session: &Arc<dyn Session>) -> bool {
        self.env == env
            && session.env_id() == env
            && self.peer == session.peer()
            && !session.is_closed()
            && self
                .session
                .upgrade()
                .is_some_and(|sent| Arc::ptr_eq(&sent, session))
    }
}
fn receiver_caps(
    ctx: &Context,
    session: &Arc<dyn Session>,
    deadline: &mut protocol::Deadline,
) -> Result<(Value, SentCapabilities)> {
    let peer_caps = caps(ctx, session.as_ref(), deadline)?;
    Ok((
        peer_caps,
        SentCapabilities {
            session: Arc::downgrade(session),
            peer: session.peer(),
            env: session.env_id().into(),
            _thread: std::marker::PhantomData,
        },
    ))
}

pub(crate) fn needs_serve(ctx: &Context, session: &dyn Session) -> Result<bool> {
    let p = path(
        session.env_id(),
        &format!("authorizations/{}.json", session.peer().fingerprint()),
    )?;
    let v = ctx.state.read_json(&p, Value::Null)?;
    if v.is_null() {
        return Ok(false);
    }
    if v["device_record"] != session.peer().to_dict() {
        return Err(bad("team_bootstrap_approval_changed"));
    }
    Ok(v["activated"] != true)
}

pub(crate) fn serve(ctx: &Context, session: &dyn Session) -> Result<()> {
    let env = session.env_id();
    let _slot = Slot::take(ctx, env)?;
    let mut deadline = protocol::Deadline::new();
    caps(ctx, session, &mut deadline)?;
    let session_nonce = random(32);
    send(
        session,
        &json!({"type":"BOOTSTRAP_HELLO","env_id":env,"session_nonce":session_nonce}),
    )?;
    let (_, request) = recv(ctx, session, &mut deadline)?;
    let ap = path(
        env,
        &format!("authorizations/{}.json", session.peer().fingerprint()),
    )?;
    if ctx.state.read_json(&ap, Value::Null)?["cancelled"] == true {
        return Err(bad("team_bootstrap_cancelled"));
    }
    let activation = if request["type"] == "BOOTSTRAP_INSTALLED" {
        protocol::fields(
            &request,
            &[
                "type",
                "env_id",
                "session_nonce",
                "signer",
                "recipient",
                "manifest_hash",
            ],
        )?;
        let history = super::commit::HistorySession::open_runtime(ctx.state, env)?;
        let auth = history.acquire()?.read_json(&ap, Value::Null)?;
        let continuation = history.into_resume()?;
        if request["env_id"] != env
            || request["session_nonce"] != session_nonce
            || request["signer"] != auth["last_manifest"]["signer"]
            || request["recipient"] != session.peer().fingerprint()
            || request["manifest_hash"] != auth["last_manifest_hash"]
        {
            return Err(bad("team_bootstrap_receipt_invalid"));
        }
        let challenge = random(32);
        continuation.check_unlocked()?;
        #[cfg(test)]
        import_barrier::opus_cost::metric(ctx.state, "receipt_queries_sent", 1);
        send(
            session,
            &json!({"type":"BOOTSTRAP_RECEIPT_QUERY","env_id":env,"session_nonce":session_nonce,"challenge":challenge,"manifest_hash":auth["last_manifest_hash"]}),
        )?;
        let (_, reply) = recv(ctx, session, &mut deadline)?;
        protocol::fields(
            &reply,
            &[
                "type",
                "domain",
                "env_id",
                "session_nonce",
                "challenge",
                "receipt",
                "sig",
            ],
        )?;
        if reply["type"] != "BOOTSTRAP_RECEIPT_REPLY"
            || reply["domain"] != "zeropw-team-bootstrap-receipt-query-v1"
            || reply["env_id"] != env
            || reply["session_nonce"] != session_nonce
            || reply["challenge"] != challenge
            || reply["receipt"]["manifest_hash"] != auth["last_manifest_hash"]
        {
            return Err(bad("team_bootstrap_receipt_invalid"));
        }
        verify_peer_signature(&reply, &session.peer())?;
        verify_receipt(&reply["receipt"], &auth, &session.peer())?;
        (auth, continuation)
    } else {
        protocol::fields(
            &request,
            &[
                "type",
                "env_id",
                "session_nonce",
                "onboarding_nonce",
                "approval",
                "renewal_proof",
            ],
        )?;
        if request["type"] != "BOOTSTRAP_REQUEST"
            || request["env_id"] != env
            || request["session_nonce"] != session_nonce
            || !hex_nonce(&request["onboarding_nonce"])
        {
            return Err(bad("team_bootstrap_binding_mismatch"));
        }
        let auth = ctx.state.read_json(&ap, Value::Null)?;
        if auth["invite_id"] != request["approval"]["invite_id"] {
            let transcript = bytes(
                &json!({"domain":"zeropw-personal-bootstrap-renewal-v1","env_id":env,"session_nonce":session_nonce,"recipient_record":session.peer().to_dict()}),
            )?;
            let proof = crate::pybase64::b64decode_strict(text(&request, "renewal_proof")?)
                .map_err(|_| bad("team_bootstrap_approval_changed"))?;
            match approval::check(ctx, env, &session.peer(), &transcript, &proof)? {
                Some(crate::team::transport::InviteDecision::Accept) => {}
                Some(crate::team::transport::InviteDecision::PendingPersonal) => {
                    return Err(bad("team_bootstrap_approval_pending"));
                }
                _ => return Err(bad("team_bootstrap_approval_changed")),
            }
        }
        let export = export::create(ctx, env, &session.peer(), &request, &session_nonce)?;
        let manifest_hash = digest(&export.manifest)?;
        send(session, &export.manifest)?;
        for (index, chunk) in export.payload.chunks(protocol::CHUNK_CAP).enumerate() {
            let frame = json!({"type":"BOOTSTRAP_CHUNK","v":1,"transfer_id":export.manifest["transfer_id"],"manifest_hash":manifest_hash,"index":index,"data_b64":crate::pybase64::b64encode(chunk)});
            loop {
                send(session, &frame)?;
                let (_, next) = recv(ctx, session, &mut deadline)?;
                protocol::fields(
                    &next,
                    &["type", "transfer_id", "manifest_hash", "next_index"],
                )?;
                if next["type"] != "BOOTSTRAP_NEXT"
                    || next["transfer_id"] != export.manifest["transfer_id"]
                    || next["manifest_hash"] != manifest_hash
                {
                    return Err(bad("team_bootstrap_chunk_order"));
                }
                match next["next_index"].as_u64() {
                    Some(n) if n == (index + 1) as u64 => break,
                    Some(n) if n == index as u64 => {}
                    _ => return Err(bad("team_bootstrap_chunk_order")),
                }
            }
        }
        let finalize = loop {
            let (_, value) = recv(ctx, session, &mut deadline)?;
            if value["type"] == "BOOTSTRAP_NEXT" {
                protocol::fields(
                    &value,
                    &["type", "transfer_id", "manifest_hash", "next_index"],
                )?;
                if value["transfer_id"] != export.manifest["transfer_id"]
                    || value["manifest_hash"] != manifest_hash
                    || value["next_index"].as_u64()
                        != Some(
                            export.manifest["payload"]["chunks"]
                                .as_array()
                                .ok_or_else(|| bad("team_bootstrap_state_invalid"))?
                                .len() as u64,
                        )
                {
                    return Err(bad("team_bootstrap_chunk_order"));
                }
                continue;
            }
            break value;
        };
        protocol::fields(
            &finalize,
            &["type", "transfer_id", "manifest_hash", "challenge"],
        )?;
        if finalize["type"] != "BOOTSTRAP_FINALIZE"
            || finalize["transfer_id"] != export.manifest["transfer_id"]
            || finalize["manifest_hash"] != manifest_hash
            || !hex_nonce(&finalize["challenge"])
        {
            return Err(bad("team_bootstrap_binding_mismatch"));
        }
        let ready = export.finalize(ctx, &session_nonce, text(&finalize, "challenge")?)?;
        {
            let _lock = ctx.state.lock()?;
            let mut auth = ctx.state.read_json(&ap, Value::Null)?;
            auth["last_ready"] = ready.clone();
            import_barrier::json(ctx.state, &ap, &auth)?;
        }
        let history = super::commit::HistorySession::open_runtime(ctx.state, env)?;
        let observed_auth = history.acquire()?.read_json(&ap, Value::Null)?;
        let continuation = history.into_resume()?;
        continuation.check_unlocked()?;
        send(session, &ready)?;
        let ack = loop {
            let (_, value) = recv(ctx, session, &mut deadline)?;
            if value["type"] == "BOOTSTRAP_NEXT" {
                protocol::fields(
                    &value,
                    &["type", "transfer_id", "manifest_hash", "next_index"],
                )?;
                if value["transfer_id"] != export.manifest["transfer_id"]
                    || value["manifest_hash"] != manifest_hash
                    || value["next_index"].as_u64()
                        != Some(
                            export.manifest["payload"]["chunks"]
                                .as_array()
                                .ok_or_else(|| bad("team_bootstrap_state_invalid"))?
                                .len() as u64,
                        )
                {
                    return Err(bad("team_bootstrap_chunk_order"));
                }
                continue;
            }
            break value;
        };
        protocol::fields(&ack, &["type", "receipt"])?;
        if ack["type"] != "BOOTSTRAP_ACK"
            || ack["receipt"]["manifest_hash"] != manifest_hash
            || ack["receipt"]["transfer_id"] != export.manifest["transfer_id"]
            || ack["receipt"]["vector"] != export.manifest["vector"]
            || ack["receipt"]["tombstone_digest"] != export.manifest["tombstone_digest"]
        {
            return Err(bad("team_bootstrap_receipt_invalid"));
        }
        verify_receipt(&ack["receipt"], &observed_auth, &session.peer())?;
        (observed_auth, continuation)
    };
    let (observed_auth, continuation) = activation;
    let history = continuation.resume()?;
    let mut auth = history.acquire()?.read_json(&ap, Value::Null)?;
    if auth != observed_auth || auth["device_record"] != session.peer().to_dict() {
        return Err(bad("team_bootstrap_approval_changed"));
    }
    let folded = membership::load_environment_with_input(ctx, env, &history)?;
    let local = history.local_record()?;
    let peer = session.peer();
    if folded.document["owner"] != local.fingerprint()
        || folded.document["members"][local.fingerprint()]["status"] != "active"
        || folded.document["members"][peer.fingerprint()]["status"] != "active"
        || folded.document["members"][peer.fingerprint()]["device"] != peer.to_dict()
    {
        return Err(bad("team_bootstrap_recovery_required"));
    }
    if auth["cancelled"] == true {
        return Err(bad("team_bootstrap_cancelled"));
    }
    auth["activated"] = json!(true);
    let raw = history.encode_import_record(&auth)?;
    history.reserve_writer(&ap, raw.len() as u64)?;
    history.acquire()?.recheck()?;
    history.invalidate()?;
    import_barrier::write(ctx.state, &ap, &raw)?;
    history.check()?;
    Ok(())
}

fn hex_nonce(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn verify_receipt(
    receipt: &Value,
    auth: &Value,
    peer: &crate::team::identity::DeviceRecord,
) -> Result<()> {
    protocol::fields(
        receipt,
        &[
            "domain",
            "v",
            "env_id",
            "signer",
            "recipient",
            "approval_id",
            "authorization_id",
            "transfer_id",
            "manifest_hash",
            "payload_sha256",
            "vector",
            "tombstone_digest",
            "trust_model",
            "epoch",
            "ready_sha256",
            "target_digests_sha256",
            "sig",
        ],
    )?;
    if !hex_nonce(&receipt["target_digests_sha256"]) {
        return Err(bad("team_bootstrap_receipt_invalid"));
    }
    let manifest = &auth["last_manifest"];
    for key in [
        "env_id",
        "signer",
        "recipient",
        "approval_id",
        "transfer_id",
        "vector",
        "tombstone_digest",
        "trust_model",
    ] {
        if receipt[key] != manifest[key] {
            return Err(bad("team_bootstrap_receipt_invalid"));
        }
    }
    if receipt["domain"] != "zeropw-team-bootstrap-receipt-v1"
        || receipt["v"] != 1
        || receipt["recipient"] != peer.fingerprint()
        || receipt["manifest_hash"] != digest(manifest)?
        || receipt["authorization_id"] != auth["authorization_id"]
        || receipt["payload_sha256"] != manifest["payload"]["sha256"]
        || receipt["ready_sha256"] != digest(&auth["last_ready"])?
        || !receipt["epoch"]
            .as_str()
            .is_some_and(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(bad("team_bootstrap_receipt_invalid"));
    }
    verify_peer_signature(receipt, peer)
}
fn verify_peer_signature(value: &Value, peer: &crate::team::identity::DeviceRecord) -> Result<()> {
    let mut unsigned = value.clone();
    let sig = unsigned
        .as_object_mut()
        .ok_or_else(|| bad("team_bootstrap_receipt_invalid"))?
        .remove("sig")
        .ok_or_else(|| bad("team_bootstrap_receipt_invalid"))?;
    let sig = crate::pybase64::b64decode_strict(
        sig.as_str()
            .ok_or_else(|| bad("team_bootstrap_receipt_invalid"))?,
    )
    .map_err(|_| bad("team_bootstrap_receipt_invalid"))?;
    if !crate::crypto::ed25519::verify(&peer.sign_pub, &bytes(&unsigned)?, &sig) {
        return Err(bad("team_bootstrap_receipt_invalid"));
    }
    Ok(())
}

fn receive(
    team: &Arc<TeamSync>,
    env: &str,
    slot: &Slot,
    stop: &AtomicBool,
    session_slot: &Mutex<Option<Arc<dyn Session>>>,
) -> Result<()> {
    let ctx = &team.ctx;
    let committed = {
        let history = super::commit::HistorySession::open_recovery_entry(ctx, env)?;
        match reconcile_receiver(ctx, env, slot, &history)? {
            RestartDisposition::ContinueCommitted => true,
            RestartDisposition::AwaitApproval => false,
            RestartDisposition::ClosedInterrupted | RestartDisposition::Blocked => return Ok(()),
        }
    };
    let attempt = ctx
        .state
        .read_json(&path(env, "attempt.json")?, Value::Null)?;
    let invitation = SecretBytes::new(
        ctx.kms
            .unwrap(&WrappedKey::from_dict(&attempt["invite"])?)?
            .expose()
            .to_vec(),
    );
    let invitation = std::str::from_utf8(invitation.expose())
        .map_err(|_| bad("team_bootstrap_state_invalid"))?;
    let invite = membership::parse_invite(invitation)?;
    let secret = invite.invite_secret.clone();
    let proof: InviteProof = Arc::new(move |transcript| {
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.expose())
            .expect("HMAC accepts any key length");
        mac.update(transcript);
        mac.finalize().into_bytes().to_vec()
    });
    let mut found = None;
    let mut address = String::new();
    let mut addresses = Vec::new();
    if committed {
        // Successful normal sync/discovery can learn a newer endpoint than
        // the immutable invitation. Hints never substitute for the full-key
        // approval and authenticated peer checks below.
        let peers = ctx
            .state
            .read_json(&format!("team/{env}/peers.json"), json!({}))?;
        for candidate in peers[&invite.inviter]
            .as_array()
            .into_iter()
            .flatten()
            .rev()
            .filter_map(Value::as_str)
            .filter(|s| membership::valid_invite_address(s))
            .take(16)
        {
            if !addresses.iter().any(|s| s == candidate) {
                addresses.push(candidate.to_owned());
            }
        }
    }
    for candidate in &invite.addresses {
        if addresses.len() >= 16 {
            break;
        }
        if !addresses.contains(candidate) {
            addresses.push(candidate.clone());
        }
    }
    let mut deadline = protocol::Deadline::new();
    for candidate in &addresses {
        deadline.check()?;
        if stop.load(Ordering::SeqCst) {
            return Err(bad("team_bootstrap_cancelled"));
        }
        if let Ok(session) = team.transport.dial(candidate, env, Some(proof.clone())) {
            deadline.progress()?;
            found = Some(session);
            address = candidate.clone();
            break;
        }
    }
    let session = found.ok_or_else(|| bad("team_bootstrap_peer_offline"))?;
    *session_slot
        .lock()
        .map_err(|_| bad("team_bootstrap_busy"))? = Some(session.clone());
    if session.peer().fingerprint() != invite.inviter {
        return Err(bad("team_bootstrap_approval_changed"));
    }
    approval::observe_peer(
        ctx,
        env,
        &invite,
        &session.peer(),
        text(&attempt, "project")?,
        text(&attempt, "environment")?,
    )?;
    let approval = approval::ReceiverApproval::load(ctx, env, &session.peer())?;
    let receipt = if committed {
        Some(install::receipt(ctx, env)?)
    } else {
        None
    };
    let (peer_caps, sent_capabilities) = receiver_caps(ctx, &session, &mut deadline)?;
    let (_, hello) = recv_protocol(ctx, session.as_ref(), &mut deadline, receipt.is_some())?;
    if receipt.is_some()
        && (crate::team::tombstone_gate::is_control(hello["type"].as_str().unwrap_or(""))
            || hello["type"] == "VECTOR")
    {
        // The inviter already durably accepted the earlier ACK. Its ordinary
        // protocol is authoritative for routing, never for import visibility
        // or readiness. Re-enter fresh ordinary vector/M1 agreement with both
        // already-received controls, before another reader owns the session.
        let handoff = (|| {
            team.personal_adopt_ordinary(
                env,
                session.clone(),
                &address,
                &peer_caps,
                &hello,
                &slot.registration(ctx, env)?,
                &sent_capabilities,
            )?;
            team.personal_handoff_complete(env, &session)
        })();
        // This verified committed receiver has selected the peer's ordinary
        // protocol. An adoption error must close only this attempt's socket;
        // receive_job must never inject a bootstrap refusal into that route.
        // Keep cancellation ownership until adoption returns, including on
        // error, and retain the original error and every ordinary guard.
        let released = session_slot
            .lock()
            .map(|mut current| *current = None)
            .map_err(|_| bad("team_bootstrap_busy"));
        if handoff.is_err() || released.is_err() {
            session.close();
        }
        handoff?;
        released?;
        return update(ctx, env, "installed_syncing", None);
    }
    protocol::fields(&hello, &["type", "env_id", "session_nonce"])?;
    if hello["type"] != "BOOTSTRAP_HELLO"
        || hello["env_id"] != env
        || !hex_nonce(&hello["session_nonce"])
    {
        return Err(bad("team_peer_feature_unsupported"));
    }
    let session_nonce = text(&hello, "session_nonce")?;
    if let Some(receipt) = receipt {
        let receipt_operation = {
            let history = super::commit::HistorySession::open_runtime(ctx.state, env)?;
            if install::receipt_with_input(ctx, env, &history)? != receipt {
                return Err(bad("team_bootstrap_receipt_invalid"));
            }
            history.into_resume()?
        };
        receipt_operation.check_unlocked()?;
        send(
            session.as_ref(),
            &json!({"type":"BOOTSTRAP_INSTALLED","env_id":env,"session_nonce":session_nonce,"signer":receipt["signer"],"recipient":receipt["recipient"],"manifest_hash":receipt["manifest_hash"]}),
        )?;
        let (_, query) = recv(ctx, session.as_ref(), &mut deadline)?;
        protocol::fields(
            &query,
            &[
                "type",
                "env_id",
                "session_nonce",
                "challenge",
                "manifest_hash",
            ],
        )?;
        if query["type"] != "BOOTSTRAP_RECEIPT_QUERY"
            || query["env_id"] != env
            || query["session_nonce"] != session_nonce
            || !hex_nonce(&query["challenge"])
            || query["manifest_hash"] != receipt["manifest_hash"]
        {
            return Err(bad("team_bootstrap_receipt_invalid"));
        }
        let reply = {
            let history = receipt_operation.resume()?;
            let fresh = install::receipt_with_input(ctx, env, &history)?;
            if fresh != receipt {
                return Err(bad("team_bootstrap_receipt_invalid"));
            }
            let mut reply = json!({"type":"BOOTSTRAP_RECEIPT_REPLY","domain":"zeropw-team-bootstrap-receipt-query-v1","env_id":env,"session_nonce":session_nonce,"challenge":query["challenge"],"receipt":fresh});
            history.reserve_import_signature(&reply)?;
            let device = DeviceKey::load_or_create(ctx.state, ctx.kms)?;
            history.match_local_identity(&device.record()?)?;
            let input = history.acquire()?;
            input.recheck()?;
            history.check()?;
            reply["sig"] = json!(crate::pybase64::b64encode(&device.sign(&bytes(&reply)?)?));
            input.recheck()?;
            history.check()?;
            reply
        };
        receipt_operation.check_unlocked()?;
        send(session.as_ref(), &reply)?;
    } else {
        let onboarding_nonce = random(32);
        update(ctx, env, "transferring", None)?;
        let renewal_proof = {
            use hmac::{Hmac, Mac};
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(invite.invite_secret.expose())
                .expect("HMAC accepts any key length");
            mac.update(&bytes(&json!({"domain":"zeropw-personal-bootstrap-renewal-v1","env_id":env,"session_nonce":session_nonce,"recipient_record":DeviceKey::load_or_create(ctx.state,ctx.kms)?.record()?.to_dict()}))?);
            crate::pybase64::b64encode(&mac.finalize().into_bytes())
        };
        send(
            session.as_ref(),
            &json!({"type":"BOOTSTRAP_REQUEST","env_id":env,"session_nonce":session_nonce,"onboarding_nonce":onboarding_nonce,"approval":approval.record(),"renewal_proof":renewal_proof}),
        )?;
        let (manifest_raw, manifest_value) = recv(ctx, session.as_ref(), &mut deadline)?;
        let expected = approval.expected(&session.peer(), session_nonce, &onboarding_nonce)?;
        let manifest = crate::team::checkpoint::verify_manifest_bytes(
            &manifest_raw,
            &expected,
            crate::team::checkpoint::VerificationWallTime::from_millis(
                ((ctx.clock)() * 1000.0) as u64,
            )
            .map_err(|e| bad(e.reason()))?,
        )
        .map_err(|e| bad(e.reason()))?;
        let mut payload = Vec::new();
        let length = manifest.signed_metadata()["payload"]["byte_length"]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| bad("team_bootstrap_limit_exceeded"))?;
        if length > protocol::PAYLOAD_CAP {
            return Err(bad("team_bootstrap_limit_exceeded"));
        }
        payload
            .try_reserve_exact(length)
            .map_err(|_| bad("team_bootstrap_limit_exceeded"))?;
        let mut accepted_raw = Vec::<[u8; 32]>::new();
        while accepted_raw.len() < manifest.chunks().len() {
            if stop.load(Ordering::SeqCst) {
                return Err(bad("team_bootstrap_cancelled"));
            }
            let (raw, _) = recv(ctx, session.as_ref(), &mut deadline)?;
            let chunk = crate::team::checkpoint::verify_chunk_frame_bytes(&manifest, &raw)
                .map_err(|e| bad(e.reason()))?;
            let hash: [u8; 32] = Sha256::digest(&raw).into();
            let index = accepted_raw.len();
            if chunk.index() == index {
                if payload
                    .len()
                    .checked_add(chunk.encrypted_bytes().len())
                    .is_none_or(|n| n > length)
                {
                    return Err(bad("team_bootstrap_limit_exceeded"));
                }
                payload.extend_from_slice(chunk.encrypted_bytes());
                accepted_raw.push(hash);
            } else if accepted_raw.get(chunk.index()) != Some(&hash) {
                return Err(bad("team_bootstrap_chunk_order"));
            }
            send(
                session.as_ref(),
                &json!({"type":"BOOTSTRAP_NEXT","transfer_id":manifest_value["transfer_id"],"manifest_hash":manifest.manifest_hash(),"next_index":accepted_raw.len()}),
            )?;
        }
        if payload.len() != length {
            return Err(bad("team_bootstrap_limit_exceeded"));
        }
        update(ctx, env, "verifying", None)?;
        let plan = crate::team::checkpoint::personal::validate(
            ctx,
            &manifest_raw,
            &payload,
            &approval,
            session.as_ref(),
            session_nonce,
            &onboarding_nonce,
        )?;
        let challenge = random(32);
        send(
            session.as_ref(),
            &json!({"type":"BOOTSTRAP_FINALIZE","transfer_id":manifest_value["transfer_id"],"manifest_hash":manifest.manifest_hash(),"challenge":challenge}),
        )?;
        let ready = loop {
            let (raw, value) = recv(ctx, session.as_ref(), &mut deadline)?;
            if value["type"] == "BOOTSTRAP_CHUNK" {
                let chunk = crate::team::checkpoint::verify_chunk_frame_bytes(&manifest, &raw)
                    .map_err(|e| bad(e.reason()))?;
                let hash: [u8; 32] = Sha256::digest(&raw).into();
                if accepted_raw.get(chunk.index()) != Some(&hash) {
                    return Err(bad("team_bootstrap_chunk_order"));
                }
                send(
                    session.as_ref(),
                    &json!({"type":"BOOTSTRAP_NEXT","transfer_id":manifest_value["transfer_id"],"manifest_hash":manifest.manifest_hash(),"next_index":accepted_raw.len()}),
                )?;
                continue;
            }
            break value;
        };
        update(ctx, env, "installing", None)?;
        let receipt = install::ready(ctx, &plan, session.as_ref(), &ready, &challenge, &deadline)?;
        update(ctx, env, "installed_syncing", None)?;
        send(
            session.as_ref(),
            &json!({"type":"BOOTSTRAP_ACK","receipt":receipt}),
        )?;
    }
    {
        let history = super::commit::HistorySession::open_recovery_entry(ctx, env)?;
        team.register_env_with_bootstrap_slot(env, &slot.registration(ctx, env)?, &history)?;
    }
    #[cfg(test)]
    import_barrier::opus_cost::protocol_event(
        ctx.state,
        env,
        "receiver_registered_before_ordinary_handoff",
    );
    let adopted = team.personal_adopt_outbound(env, session.clone(), &address);
    #[cfg(test)]
    if let Err(error) = &adopted {
        eprintln!(
            "PVBOOT_OPUS_ORDINARY_HANDOFF_REFUSED reason={}",
            closed_reason(&error.reason)
        );
    }
    let kept = adopted?;
    #[cfg(test)]
    import_barrier::opus_cost::protocol_event(ctx.state, env, "receiver_ordinary_handoff_returned");
    if !kept {
        #[cfg(test)]
        import_barrier::opus_cost::protocol_event(
            ctx.state,
            env,
            "losing_handoff_checks_current_winner",
        );
    }
    // The authenticated bootstrap exchange is complete. If the ordinary
    // tie-break rejected S0, only its actual live FULL-matching S1 may own
    // this handoff; personal_handoff_complete never records closed S0.
    team.personal_handoff_complete(env, &session)?;
    *session_slot
        .lock()
        .map_err(|_| bad("team_bootstrap_busy"))? = None;
    update(ctx, env, "installed_syncing", None)
}

struct Job {
    handle: thread::JoinHandle<()>,
    session: Arc<Mutex<Option<Arc<dyn Session>>>>,
}
struct OrdinaryOwnership {
    peer: super::identity::DeviceRecord,
    current: std::sync::Weak<dyn Session>,
}
// Scheduling only, borrowed for one current session's control handler. A
// replacement revokes this observation; dropping stale S0 cannot clear S1.
pub(super) struct OrdinaryReception<'a> {
    runtime: &'a Runtime,
    env: String,
    session: std::sync::Weak<dyn Session>,
}
struct ActiveControl {
    current: std::sync::Weak<dyn Session>,
    guards: usize,
}
impl Drop for OrdinaryReception<'_> {
    fn drop(&mut self) {
        if let Ok(mut controls) = self.runtime.active_controls.lock()
            && let Some(control) = controls.get_mut(&self.env)
            && std::sync::Weak::ptr_eq(&control.current, &self.session)
        {
            control.guards -= 1;
            if control.guards == 0 {
                controls.remove(&self.env);
            }
        }
    }
}
pub(crate) struct Runtime {
    jobs: Mutex<BTreeMap<String, Job>>,
    stop: Arc<AtomicBool>,
    last: Mutex<Instant>,
    // Protocol ownership only. Never used for membership, visibility or READY.
    ordinary_sessions: Mutex<BTreeMap<String, OrdinaryOwnership>>,
    // Ephemeral negative scheduling observation only. This separate map
    // cannot establish handoff lineage, membership, activation or readiness.
    active_controls: Mutex<BTreeMap<String, ActiveControl>>,
}
impl Default for Runtime {
    fn default() -> Self {
        Self {
            jobs: Mutex::new(BTreeMap::new()),
            stop: Arc::new(AtomicBool::new(false)),
            last: Mutex::new(Instant::now() - Duration::from_secs(3)),
            ordinary_sessions: Mutex::new(BTreeMap::new()),
            active_controls: Mutex::new(BTreeMap::new()),
        }
    }
}
impl Runtime {
    pub(crate) fn inbound(&self, team: Arc<TeamSync>, session: Arc<dyn Session>) -> Result<()> {
        let env = session.env_id().to_owned();
        let mut jobs = self.jobs.lock().map_err(|_| bad("team_bootstrap_busy"))?;
        if self.stop.load(Ordering::SeqCst) || jobs.contains_key(&env) || jobs.len() >= 2 {
            session.close();
            return Err(bad("team_bootstrap_busy"));
        }
        let shared = Arc::new(Mutex::new(Some(session.clone())));
        let slot = shared.clone();
        let handle = thread::spawn(move || {
            match serve(&team.ctx, session.as_ref()) {
                Ok(()) => {
                    #[cfg(test)]
                    import_barrier::opus_cost::protocol_event(
                        team.ctx.state,
                        session.env_id(),
                        "activation_serve_returned",
                    );
                    team.personal_adopt_inbound(session.clone());
                    #[cfg(test)]
                    import_barrier::opus_cost::protocol_event(
                        team.ctx.state,
                        session.env_id(),
                        "activation_ordinary_handoff_returned",
                    );
                }
                Err(error) => {
                    let reason = closed_reason(&error.reason);
                    #[cfg(test)]
                    {
                        use sha2::{Digest, Sha256};
                        println!(
                            "PVBOOT_SENDER_FAILURE {}",
                            json!({"reason":reason,"reason_sha256":hex::encode(Sha256::digest(error.reason.as_bytes()))})
                        );
                    }
                    let _ = refusal(&team.ctx, session.as_ref(), reason);
                    if let Ok(_lock) = team.ctx.state.lock()
                        && let Ok(p) = path(session.env_id(), "sender-status.json")
                    {
                        let _ = import_barrier::json(
                            team.ctx.state,
                            &p,
                            &json!({"state":"unsupported","reason":reason}),
                        );
                    }
                    session.close();
                }
            }
            if let Ok(mut value) = slot.lock() {
                *value = None;
            }
        });
        jobs.insert(
            env,
            Job {
                handle,
                session: shared,
            },
        );
        Ok(())
    }
    // Coordination observation only: no membership, receipt or use authority.
    pub(super) fn has_job(&self, env: &str) -> bool {
        self.jobs
            .lock()
            .map(|jobs| jobs.get(env).is_some_and(|job| !job.handle.is_finished()))
            .unwrap_or(true)
    }
    pub(super) fn handed_to_ordinary(&self, env: &str, session: &Arc<dyn Session>) -> Result<()> {
        let mut sessions = self
            .ordinary_sessions
            .lock()
            .map_err(|_| bad("team_bootstrap_busy"))?;
        sessions.retain(|_, owner| owner.current.upgrade().is_some_and(|s| !s.is_closed()));
        if sessions.get(env).is_some_and(|owner| {
            owner.peer == session.peer()
                && owner
                    .current
                    .upgrade()
                    .is_some_and(|current| Arc::ptr_eq(&current, session))
        }) {
            return Ok(());
        }
        if !sessions.contains_key(env) && sessions.len() >= 256 {
            return Err(bad("team_bootstrap_limit_exceeded"));
        }
        sessions.insert(
            env.into(),
            OrdinaryOwnership {
                peer: session.peer(),
                current: Arc::downgrade(session),
            },
        );
        Ok(())
    }
    // Called under the actual TeamSync environment mutex, after acceptance.
    // An ordinary socket cannot establish this Runtime's handoff lineage.
    pub(super) fn observe_ordinary_replacement(&self, env: &str, session: &Arc<dyn Session>) {
        if let Ok(mut sessions) = self.ordinary_sessions.lock()
            && let Some(owner) = sessions.get_mut(env)
            && owner.peer == session.peer()
        {
            owner.current = Arc::downgrade(session);
        }
    }
    pub(super) fn ordinary_control_started<'a>(
        &'a self,
        env: &str,
        session: &Arc<dyn Session>,
    ) -> Option<OrdinaryReception<'a>> {
        {
            let owners = self.ordinary_sessions.lock().ok()?;
            let owner = owners.get(env)?;
            if owner.peer != session.peer()
                || session.is_closed()
                || !owner
                    .current
                    .upgrade()
                    .is_some_and(|current| Arc::ptr_eq(&current, session))
            {
                return None;
            }
        }
        self.selected_control_started(env, session)
    }
    // TeamSync calls this only for a selected parent and its actual current
    // FULL recipient. Cold ordinary handlers can defer duplicate background
    // work without ever becoming authenticated bootstrap handoff owners.
    pub(super) fn selected_control_started<'a>(
        &'a self,
        env: &str,
        session: &Arc<dyn Session>,
    ) -> Option<OrdinaryReception<'a>> {
        let mut controls = self.active_controls.lock().ok()?;
        if session.is_closed() || (!controls.contains_key(env) && controls.len() >= 256) {
            return None;
        }
        let current = Arc::downgrade(session);
        let guards = controls
            .get(env)
            .filter(|control| std::sync::Weak::ptr_eq(&control.current, &current))
            .map_or(Some(1), |control| control.guards.checked_add(1))?;
        if guards > 64 {
            return None;
        }
        controls.insert(
            env.into(),
            ActiveControl {
                current: current.clone(),
                guards,
            },
        );
        Some(OrdinaryReception {
            runtime: self,
            env: env.into(),
            session: current,
        })
    }
    pub(super) fn ordinary_control_busy(&self, env: &str, current: &Arc<dyn Session>) -> bool {
        self.active_controls.lock().is_ok_and(|controls| {
            controls.get(env).is_some_and(|control| {
                control.guards != 0
                    && !current.is_closed()
                    && control.current.upgrade().is_some_and(|session| {
                        Arc::ptr_eq(&session, current) && session.peer() == current.peer()
                    })
            })
        })
    }
    pub(super) fn ordinary_owns_session(
        &self,
        env: &str,
        current: &Arc<dyn Session>,
    ) -> Result<bool> {
        let sessions = self
            .ordinary_sessions
            .lock()
            .map_err(|_| bad("team_bootstrap_busy"))?;
        Ok(sessions.get(env).is_some_and(|owner| {
            owner.peer == current.peer()
                && !current.is_closed()
                && owner
                    .current
                    .upgrade()
                    .is_some_and(|s| Arc::ptr_eq(&s, current))
        }))
    }
    pub(crate) fn poll(&self, team: Arc<TeamSync>) -> Result<()> {
        let mut last = self.last.lock().map_err(|_| bad("team_bootstrap_busy"))?;
        if last.elapsed() < Duration::from_secs(3) {
            return Ok(());
        }
        *last = Instant::now();
        drop(last);
        if self.stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        let finished = {
            let mut jobs = self.jobs.lock().map_err(|_| bad("team_bootstrap_busy"))?;
            let ids = jobs
                .iter()
                .filter(|(_, job)| job.handle.is_finished())
                .map(|(env, _)| env.clone())
                .collect::<Vec<_>>();
            ids.into_iter()
                .filter_map(|env| jobs.remove(&env))
                .collect::<Vec<_>>()
        };
        for job in finished {
            let _ = job.handle.join();
        }
        // Discovery is bounded routing DATA, not a continuation proof. Never
        // hold the jobs mutex over filesystem work or a worker's Slot/lock.
        let candidates = {
            let io = import_barrier::ImportIo::open(team.ctx.state)?;
            let index = io
                .json(import_barrier::INDEX, 1_048_576)?
                .unwrap_or(Value::Null);
            let mut names = io
                .list("team")?
                .into_iter()
                .filter(|env| super::commit::valid_env_id(env))
                .collect::<BTreeSet<_>>();
            names.extend(
                index
                    .as_object()
                    .into_iter()
                    .flatten()
                    .map(|(env, _)| env.clone()),
            );
            if names.len() > 256 {
                return Err(bad("team_bootstrap_limit_exceeded"));
            }
            let mut candidates = Vec::new();
            for env in names {
                if !super::commit::valid_env_id(&env) {
                    return Err(bad("team_bootstrap_state_invalid"));
                }
                let attempt = io
                    .json(&path(&env, "attempt.json")?, 65_536)?
                    .unwrap_or(Value::Null);
                io.charge(1, 256)?;
                let journal = !matches!(std::fs::symlink_metadata(team.ctx.state.path.join(path(&env, "journal.json")?)), Err(error) if error.kind() == std::io::ErrorKind::NotFound);
                let witnessed = journal || index.get(&env).is_some();
                if attempt.is_null() && !witnessed {
                    continue;
                }
                if !witnessed
                    && matches!(attempt["state"].as_str(), Some("cancelled" | "unsupported"))
                {
                    continue;
                }
                if !witnessed && attempt["state"] == "approval_pending" {
                    let observed = io
                        .json(&path(&env, "observed.json")?, 65_536)?
                        .unwrap_or(Value::Null);
                    let receiver = io
                        .json(&path(&env, "receiver.json")?, 65_536)?
                        .unwrap_or(Value::Null);
                    if !observed.is_null() && receiver.is_null() {
                        continue;
                    }
                }
                candidates.push(env);
            }
            io.check()?;
            candidates
        };
        for env in candidates {
            // Only this Runtime's completed protocol handoff owns a live
            // ordinary session. A cold process has no such handoff and must
            // reconcile its durable receipt regardless of the attempt label.
            // Temporary vector/M1 disagreement after a handoff belongs to
            // ordinary sync, which must retain the session to deliver changes
            // and removal notices. This is scheduling, never READY authority.
            if self.has_job(&env) || team.personal_ordinary_owns_session(&env)? {
                continue;
            }
            let mut jobs = self.jobs.lock().map_err(|_| bad("team_bootstrap_busy"))?;
            if self.stop.load(Ordering::SeqCst) || jobs.len() >= 2 || jobs.contains_key(&env) {
                continue;
            }
            let this = team.clone();
            let target = env.clone();
            let stop = self.stop.clone();
            let session = Arc::new(Mutex::new(None));
            let shared = session.clone();
            let handle = thread::spawn(move || receive_job(this, target, stop, shared));
            jobs.insert(env, Job { handle, session });
        }

        Ok(())
    }
    pub(crate) fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let jobs = std::mem::take(&mut *self.jobs.lock().unwrap_or_else(|e| e.into_inner()));
        for job in jobs.values() {
            if let Ok(slot) = job.session.lock()
                && let Some(session) = slot.as_ref()
            {
                session.close();
            }
        }
        for (_, job) in jobs {
            let _ = job.handle.join();
        }
    }
}

fn receive_job(
    this: Arc<TeamSync>,
    target: String,
    stop: Arc<AtomicBool>,
    shared: Arc<Mutex<Option<Arc<dyn Session>>>>,
) {
    // The lease covers the entire worker, including terminal status and
    // staging cleanup. A new human-approved attempt cannot replace its data
    // between receive returning and the old worker finishing publication.
    let (slot, failure) = match Slot::take(&this.ctx, &target) {
        Ok(slot) => (Some(slot), None),
        Err(error) if error.reason == "team_bootstrap_busy" => return,
        Err(error) => (None, Some(error)),
    };
    #[cfg(test)]
    let started_attempt = path(&target, "attempt.json")
        .and_then(|p| this.ctx.state.read_json(&p, Value::Null))
        .ok()
        .map(|v| v["attempt_id"].clone())
        .unwrap_or(Value::Null);
    let outcome = match (failure, slot.as_ref()) {
        (Some(error), _) => Err(error),
        (None, Some(slot)) => receive(&this, &target, slot, &stop, &shared),
        (None, None) => Err(bad("team_bootstrap_busy")),
    };
    if let Err(error) = outcome {
        #[cfg(test)]
        import_barrier::testing::reader_hit(
            this.ctx.state,
            &format!("team/{target}/bootstrap/attempt.json"),
            "receiver-error-returned",
        )
        .expect("owned receiver error pause");
        let attempt =
            path(&target, "attempt.json").and_then(|p| this.ctx.state.read_json(&p, Value::Null));
        let visibility = crate::import_barrier::index(this.ctx.state);
        let state_failed = attempt.is_err() || visibility.is_err();
        let attempt = attempt.unwrap_or(Value::Null);
        let visibility = visibility.unwrap_or(Value::Null);
        #[cfg(test)]
        println!(
            "PVBOOT_RECEIVER_FAILURE {}",
            json!({"same_attempt":started_attempt==attempt["attempt_id"],"reason":closed_reason(&error.reason),"state":attempt["state"].as_str().filter(|s|matches!(*s,"approval_pending"|"transferring"|"verifying"|"installing"|"installed_syncing"|"unsupported"|"recovery_required"|"cancelled")).unwrap_or("invalid")})
        );
        let installed = visibility[&target]["state"] == "committed";
        // An authenticated resource refusal is not an approval failure.
        // Retain only an existing pre-intent retryable label; every next job
        // still takes its own lease and revalidates the same approvals and
        // all durable evidence. Cancellation and import recovery stay closed.
        let busy_retry = (error.reason == "team_bootstrap_busy")
            .then_some(attempt["state"].as_str())
            .flatten()
            .filter(|state| matches!(*state, "approval_pending" | "transferring" | "verifying"));
        let pending = error.reason == "team_bootstrap_approval_pending"
            || (error.reason == "team_bootstrap_peer_offline"
                && attempt["state"] == "approval_pending");
        let reason = if state_failed {
            "team_bootstrap_storage_failed"
        } else if pending {
            "team_bootstrap_approval_pending"
        } else {
            closed_reason(&error.reason)
        };
        let state = if state_failed {
            "recovery_required"
        } else if installed {
            "installed_syncing"
        } else if visibility.get(&target).is_some() {
            "recovery_required"
        } else if let Some(prior) = busy_retry {
            prior
        } else if pending {
            "approval_pending"
        } else {
            "unsupported"
        };
        let _ = update(&this.ctx, &target, state, Some(reason));
        if let Ok(slot) = shared.lock()
            && let Some(session) = slot.as_ref()
        {
            let _ = refusal(&this.ctx, session.as_ref(), reason);
        }
        if slot.is_some()
            && !state_failed
            && visibility.get(&target).is_none()
            && install::discard_prepared(&this.ctx, &target).is_err()
        {
            let _ = update(
                &this.ctx,
                &target,
                "recovery_required",
                Some("team_bootstrap_storage_failed"),
            );
        }
    }
    if let Ok(mut slot) = shared.lock()
        && let Some(session) = slot.take()
    {
        session.close();
    }
    drop(slot);
}

#[cfg(test)]
mod attempt_lifecycle_tests {
    use super::*;
    #[test]
    fn personal_bootstrap_authenticated_remote_busy_recovers_with_same_approvals() {
        let f = super::install::tests::pending();
        let ta = crate::team::sync::attached(&f.a).unwrap();
        let tb = crate::team::sync::attached(&f.b).unwrap();
        struct Stop(Vec<Arc<TeamSync>>);
        impl Drop for Stop {
            fn drop(&mut self) {
                for team in self.0.iter().rev() {
                    team.stop();
                }
            }
        }
        let _stop = Stop(vec![ta.clone(), tb.clone()]);
        ta.enable_sync_state();
        tb.enable_sync_state();
        let deadline = Instant::now() + Duration::from_secs(35);
        let held = loop {
            match Slot::take(&f.a, &f.env) {
                Ok(slot) => break slot,
                Err(error) if error.reason == "team_bootstrap_busy" => {
                    assert!(
                        Instant::now() < deadline,
                        "owned sender lease did not settle"
                    );
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("owned sender lease refused: {}", error.reason),
            }
        };
        approval::approve_receiver(
            &f.b,
            &f.env,
            text(&f.pending, "inviter_record_binding").unwrap(),
            text(&f.pending, "self_record_binding").unwrap(),
            "synthetic-install-fault-administrator",
        )
        .unwrap();
        let approval_path = path(&f.env, "receiver.json").unwrap();
        let original_approval = f.b.state.read_bytes(&approval_path).unwrap();
        let attempt = loop {
            let attempt =
                f.b.state
                    .read_json(&path(&f.env, "attempt.json").unwrap(), Value::Null)
                    .unwrap();
            if attempt["reason"] == "team_bootstrap_busy" {
                break attempt;
            }
            assert!(
                Instant::now() < deadline,
                "authenticated busy was not observed"
            );
            thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(attempt["state"], "approval_pending");
        assert!(f.b.state.read_bytes(&approval_path).unwrap() == original_approval);
        assert!(
            import_barrier::index(f.b.state)
                .unwrap()
                .get(&f.env)
                .is_none()
        );
        assert!(f.b.vault.secret_for_trusted_use("alpha", None).is_err());
        drop(held);
        loop {
            let a_ready = ta.synced_at(&f.env).is_some();
            let b_ready = tb.synced_at(&f.env).is_some();
            if a_ready && b_ready {
                break;
            }
            if Instant::now() >= deadline {
                fn meta(ctx: &Context, env: &str, peer: &str) -> Value {
                    let closed = |value: &Value| {
                        value
                            .as_str()
                            .filter(|s| {
                                s.len() <= 64
                                    && s.bytes().all(|b| {
                                        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'
                                    })
                            })
                            .map(|s| json!(s))
                            .unwrap_or(Value::Null)
                    };
                    let read = |name: String| {
                        ctx.state
                            .read_json(&name, Value::Null)
                            .unwrap_or(Value::Null)
                    };
                    let attempt = read(path(env, "attempt.json").unwrap());
                    let auth = read(path(env, &format!("authorizations/{peer}.json")).unwrap());
                    let sender = read(path(env, "sender-status.json").unwrap());
                    let sync = read(format!("team/{env}/sync_state.json"));
                    let events = ctx.state.read_lines("audit/audit.jsonl",Some(16)).unwrap_or_default().iter()
                        .filter_map(|line|crate::pyjson::loads(line).ok())
                        .filter(|row|matches!(row["event"].as_str(),Some("team_handshake_failed"|"team_sync_poll")))
                        .take(8).map(|row|json!({"event":closed(&row["event"]),"reason":closed(&row["reason"])})).collect::<Vec<_>>();
                    json!({"attempt_state":closed(&attempt["state"]),"attempt_reason":closed(&attempt["reason"]),"authorization_activated":auth["activated"],"admission_present":auth["admission"].is_object(),"manifest_present":auth["last_manifest"].is_object(),"sender_state":closed(&sender["state"]),"sender_reason":closed(&sender["reason"]),"peer_session":sync["peers"][peer]["session"],"peer_error":closed(&sync["peers"][peer]["last_error"]),"gate_ready":sync["peers"][peer]["tombstone_agreement"]["ready"],"events":events})
                }
                let af = DeviceKey::load_or_create(f.a.state, f.a.kms)
                    .unwrap()
                    .fingerprint()
                    .unwrap();
                let bf = DeviceKey::load_or_create(f.b.state, f.b.kms)
                    .unwrap()
                    .fingerprint()
                    .unwrap();
                eprintln!(
                    "PVBOOT_REMOTE_BUSY_CLOSED_STATE {}",
                    json!({"a_ready":a_ready,"b_ready":b_ready,"a":meta(&f.a,&f.env,&bf),"b":meta(&f.b,&f.env,&af)})
                );
                panic!("unchanged35s busy recovery deadline");
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(f.b.state.read_bytes(&approval_path).unwrap() == original_approval);
        assert!(
            f.b.vault
                .secret_for_trusted_use("alpha", None)
                .unwrap()
                .ct_eq(b"synthetic-install-fault-value")
        );
        let peer = DeviceKey::load_or_create(f.b.state, f.b.kms)
            .unwrap()
            .fingerprint()
            .unwrap();
        let auth =
            f.a.state
                .read_json(
                    &path(&f.env, &format!("authorizations/{peer}.json")).unwrap(),
                    Value::Null,
                )
                .unwrap();
        assert_eq!(auth["activated"], true);
        let commits = crate::team::commit::CommitStore::new(f.a.state, &f.env)
            .all_commits()
            .unwrap();
        assert_eq!(
            commits
                .iter()
                .flat_map(|c| &c.ops)
                .filter(|op| op["op"] == "member.add")
                .count(),
            1
        );
        println!(
            "PVBOOT_REMOTE_BUSY_RECOVERY {{\"real_held_sender_lease\":true,\"same_signed_approval\":true,\"one_admission\":true,\"fresh_agreement\":true}}"
        );
    }
    #[test]
    fn personal_bootstrap_closed_encrypted_caps_send_is_offline() {
        let f = super::install::tests::pending();
        let key = DeviceKey::load_or_create(f.b.state, f.b.kms).unwrap();
        let transport = crate::team::transport::TcpTransport::new(key, Arc::new(|_, _| None), 8);
        let invite = membership::parse_invite(&f.invitation.invite).unwrap();
        let secret = invite.invite_secret.clone();
        let proof: InviteProof = Arc::new(move |transcript| {
            use hmac::{Hmac, Mac};
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.expose()).unwrap();
            mac.update(transcript);
            mac.finalize().into_bytes().to_vec()
        });
        let session = transport
            .dial_session(&invite.addresses[0], &f.env, Some(proof))
            .unwrap();
        session.close();
        let error = caps(&f.b, session.as_ref(), &mut protocol::Deadline::new()).unwrap_err();
        assert_eq!(error.reason, "team_bootstrap_peer_offline");
    }
    #[test]
    fn personal_bootstrap_receiver_failure_holds_attempt_lease_through_status_publication() {
        let f = super::install::tests::pending();
        let team = crate::team::sync::attached(&f.b).unwrap();
        team.stop();
        let old =
            f.b.state
                .read_json(&path(&f.env, "attempt.json").unwrap(), Value::Null)
                .unwrap()["attempt_id"]
                .clone();
        let addresses = membership::parse_invite(&f.invitation.invite)
            .unwrap()
            .addresses;
        let next = membership::create_invite_opts(
            &f.a,
            &f.env,
            "admin",
            "renewed-fresh-admin",
            600,
            &addresses,
            false,
            true,
        )
        .unwrap();
        approval::enable(&f.a, &f.env, &next.invite_id, None).unwrap();
        let (_scope, pause) = import_barrier::testing::Scope::pause(
            f.b.state,
            "attempt.json",
            "receiver-error-returned",
        );
        struct OwnedJob {
            pause: Arc<import_barrier::testing::Pause>,
            handle: Option<thread::JoinHandle<()>>,
        }
        impl Drop for OwnedJob {
            fn drop(&mut self) {
                self.pause.release();
                if let Some(handle) = self.handle.take() {
                    handle.join().unwrap();
                }
            }
        }
        let env = f.env.clone();
        let mut job = OwnedJob {
            pause: pause.clone(),
            handle: Some(thread::spawn(move || {
                receive_job(
                    team,
                    env,
                    Arc::new(AtomicBool::new(false)),
                    Arc::new(Mutex::new(None)),
                )
            })),
        };
        pause.wait();
        let replacement = begin(&f.b, &next.invite, "personal", "vault");
        pause.release();
        job.handle.take().unwrap().join().unwrap();
        assert!(
            matches!(replacement,Err(ref e) if e.reason=="team_bootstrap_busy"),
            "renewal began before previous receiver status publication completed"
        );
        assert!(
            f.b.state
                .read_json(&path(&f.env, "attempt.json").unwrap(), Value::Null)
                .unwrap()["attempt_id"]
                == old
        );
        let current = begin(&f.b, &next.invite, "personal", "vault").unwrap();
        assert_eq!(current["state"], "approval_pending");
        assert!(current["reason"].is_null());
        assert!(
            f.b.state
                .read_json(&path(&f.env, "attempt.json").unwrap(), Value::Null)
                .unwrap()["attempt_id"]
                != old
        );
        assert!(
            import_barrier::index(f.b.state)
                .unwrap()
                .get(&f.env)
                .is_none()
        );
        println!(
            "PVBOOT_RECEIVER_ATTEMPT_LIFETIME {{\"old_job_blocks_renewal\":true,\"new_attempt_untouched\":true,\"no_import_epoch\":true}}"
        );
    }
}
