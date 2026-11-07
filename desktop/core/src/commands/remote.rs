//! Remote sync between this user's Macs (docs/remote-sync.md §4): the link daemon's status and
//! enrolment, pairing codes, explicit pairing approval, the devices view and device removal.
//!
//! - Server invite codes, link tokens and team invitations never go into argv or the
//!   environment: invite codes and link tokens travel in the link socket's request body,
//!   invitations in the zeropw-admin input envelope (`team join --stdin`, `team invite-info
//!   --stdin`). A pairing code is a one-time value: shown or copied once on the Mac that made
//!   it (`PairingCode`, 10 minutes), kept in Rust on the Mac it was pasted on (`PairingText`).
//! - Approval is per device key: `team invite --approval` makes invitations that the inviting
//!   Mac must approve for exactly the joining Mac's fingerprint (`approve_join`). A code alone
//!   adds no device to a vault environment. `approve-join`, `deny-join` and `team invite` run
//!   with `--require-admin`.
//! - `serve` gets `--link-socket` whenever the daemon answers; a running serve started without
//!   it is restarted with it when the daemon turns up (link status, enrolment, pairing).

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Core, InvitePreview, RefIn, ServeStatus, lock, require_passphrase};
use crate::admin::{AdminArgs, Envelope};
use crate::devices::{self, DevicesFile, PairedDevice};
use crate::error::{AppError, is_code, is_fingerprint};
use crate::link::{
    Credential, DEFAULT_SERVICE_URL, LinkDevice, LinkPeer, check_display_name, check_service_url,
    clean_name, default_device_name, is_device_id, is_invite_code, service_host, time_unix,
};
use crate::onetime::OneTimeKind;
use crate::pairing::{self, PairInvite, PairingCode, split_env};
use crate::secret::SecretString;

/// How long a pairing code made here can be shown or copied (the link token in it lasts as
/// long; the one-time store keeps it 10 minutes).
pub const PAIRING_CODE_TTL: Duration = Duration::from_secs(10 * 60);
/// The CLI's reason for a join that waits for the inviting Mac's approval.
pub const JOIN_PENDING: &str = "join_pending_approval";

// ---------------------------------------------------------------------------------------------
// Contract types
// ---------------------------------------------------------------------------------------------

/// `link_status`: the daemon and this Mac's enrolment. `service` is the enrolled service, or the
/// default the app would enrol with; `problem` says why the daemon does not answer.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LinkStatusOut {
    pub available: bool,
    pub running: bool,
    pub enrolled: bool,
    /// This Mac was removed at the link service: remote sync cannot reach the other Macs.
    pub revoked: bool,
    pub device_id: Option<String>,
    pub online: bool,
    pub service: String,
    pub service_host: String,
    pub default_service: String,
    pub device_name: String,
    pub peers: Vec<LinkPeer>,
    pub problem: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkEnrollIn {
    pub invite_code: SecretString,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingCreateIn {
    /// `project/environment` names; absent: every environment of the local projects.
    #[serde(default)]
    pub envs: Option<Vec<String>>,
    /// This Mac's name as the other Mac shows it (default: the host name).
    #[serde(default)]
    pub name: Option<String>,
    /// The member name the invitations give the new Mac.
    pub device_name: String,
    pub admin_passphrase: SecretString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PairingEnvOut {
    pub env: String,
    pub invite_id: String,
    pub shared_now: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PairingCreateOut {
    #[serde(rename = "ref")]
    pub reference: String,
    pub expires_at: String,
    /// This Mac's link device ID.
    pub peer: String,
    /// This Mac's team fingerprint, as the joining Mac will show it.
    pub fingerprint: String,
    pub environments: Vec<PairingEnvOut>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingTextIn {
    pub text: SecretString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PairingPreviewEnv {
    pub env: String,
    pub env_id: String,
    pub role: String,
}

/// What a pasted code says, read offline. `name` and `env` come from the other Mac and are
/// untrusted text; `fingerprint` comes from the invitations themselves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PairingPreview {
    pub name: String,
    pub peer: String,
    pub fingerprint: String,
    pub environments: Vec<PairingPreviewEnv>,
    pub service: String,
    pub service_host: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PairingPreviewOut {
    #[serde(rename = "ref")]
    pub reference: String,
    pub preview: PairingPreview,
}

/// One environment of a pairing join: `joined`, `pending` (the other Mac has to approve this
/// Mac's fingerprint) or `failed` (`reason`, and for a dial that did not reach the other Mac
/// the CLI's code for why in `detail`, such as `link_peer_offline`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PairingJoinEnv {
    pub env: String,
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inviter_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
}

impl PairingJoinEnv {
    fn failed(env: &str, reason: &str, detail: Option<&str>) -> Self {
        Self {
            env: env.to_owned(),
            state: "failed",
            reason: Some(reason.to_owned()),
            detail: detail.map(str::to_owned),
            self_fingerprint: None,
            inviter_fingerprint: None,
            project: None,
            environment: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PairingJoinOut {
    /// Every environment joined; the code is forgotten.
    pub done: bool,
    pub peer: String,
    pub environments: Vec<PairingJoinEnv>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvsIn {
    pub envs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct JoinRequest {
    pub env: String,
    pub request_id: String,
    pub invite_id: String,
    pub fingerprint: String,
    pub first_seen_at: Value,
    pub last_seen_at: Value,
    pub attempts: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EnvError {
    pub env: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct JoinRequestsOut {
    pub requests: Vec<JoinRequest>,
    pub errors: Vec<EnvError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinDecisionIn {
    pub envs: Vec<String>,
    pub fingerprint: String,
    pub admin_passphrase: SecretString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct JoinDecisionEnv {
    pub env: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub invites: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct JoinDecisionOut {
    pub fingerprint: String,
    pub envs: Vec<JoinDecisionEnv>,
}

/// One paired environment for the devices view: its members and sync state as the CLI
/// printed them, or why they could not be read.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DeviceEnv {
    pub env: String,
    pub members: Option<Value>,
    pub sync: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DevicesOut {
    pub self_fingerprint: Option<String>,
    pub link: LinkStatusOut,
    pub link_devices: Vec<LinkDevice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_devices_error: Option<String>,
    pub devices: Vec<PairedDevice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub devices_error: Option<String>,
    pub envs: Vec<DeviceEnv>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRemoveIn {
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub link_device_id: Option<String>,
    #[serde(default)]
    pub admin_passphrase: Option<SecretString>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DeviceRemoveOut {
    pub removed: Vec<String>,
    pub failed: Vec<EnvError>,
    pub link_revoked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_error: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `YYYY-MM-DDTHH:MM:SSZ` for unix seconds (civil from days, Howard Hinnant).
pub fn iso_utc(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// A list of `project/environment` names: not empty, unique, at most a code's worth.
fn check_envs(envs: &[String]) -> Result<Vec<String>, AppError> {
    let mut seen = BTreeSet::new();
    if envs.is_empty() || envs.len() > pairing::MAX_INVITES {
        return Err(AppError::invalid_input("invalid_argument").with_detail("envs"));
    }
    for env in envs {
        if split_env(env).is_none() || !seen.insert(env.as_str()) {
            return Err(AppError::invalid_input("invalid_argument").with_detail("envs"));
        }
    }
    Ok(envs.to_vec())
}

fn check_fingerprint(fingerprint: &str) -> Result<(), AppError> {
    if is_fingerprint(fingerprint) {
        Ok(())
    } else {
        Err(AppError::invalid_input("invalid_argument").with_detail("fingerprint"))
    }
}

/// An identifier the CLI printed (request and invite IDs): a short code, else dropped.
fn id_text(value: &Value) -> Option<String> {
    value.as_str().filter(|s| is_code(s)).map(str::to_owned)
}

/// A reason code as the CLI prints them: lowercase letters, digits and `_`, at most 64.
fn is_reason_code(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// The fingerprints a pending join reports in its `detail` (see `AppError::from_admin_stderr`).
fn pending_fingerprints(error: &AppError) -> (Option<String>, Option<String>) {
    let detail: Option<Value> = error
        .detail
        .as_deref()
        .and_then(|d| serde_json::from_str(d).ok());
    let field = |key: &str| {
        detail
            .as_ref()
            .and_then(|d| d.get(key))
            .and_then(Value::as_str)
            .filter(|f| is_fingerprint(f))
            .map(str::to_owned)
    };
    (field("self_fingerprint"), field("inviter_fingerprint"))
}

impl Core {
    // -- link daemon --------------------------------------------------------------------------

    /// Start (or adopt) the link daemon at app start when a vault exists. Never fatal: without
    /// the daemon remote sync is unavailable and the rest of the app works as before.
    pub fn link_startup(&self) {
        if !self.initialized() || !self.link.available() {
            return;
        }
        if let Err(e) = self.link.start() {
            eprintln!(
                "zeropw: the link daemon did not start ({}: {})",
                e.error, e.reason
            );
        }
    }

    /// The daemon answers, starting it if needed (enrolment and pairing).
    fn ensure_link(&self) -> Result<(), AppError> {
        if self.link.ready() {
            return Ok(());
        }
        if !self.link.available() {
            return Err(AppError::unavailable("link_binary_missing"));
        }
        self.link.start().map(|_| ())
    }

    pub fn link_status(&self) -> Result<LinkStatusOut, AppError> {
        let out = self.link_view();
        if out.running {
            self.relink_serve();
        }
        Ok(out)
    }

    fn link_view(&self) -> LinkStatusOut {
        let process = self.link.process();
        let mut out = LinkStatusOut {
            available: process.available,
            running: false,
            enrolled: false,
            revoked: false,
            device_id: None,
            online: false,
            service: DEFAULT_SERVICE_URL.to_owned(),
            service_host: service_host(DEFAULT_SERVICE_URL),
            default_service: DEFAULT_SERVICE_URL.to_owned(),
            device_name: default_device_name(),
            peers: Vec::new(),
            problem: None,
        };
        match self.link.client().status() {
            Ok(status) => {
                out.running = true;
                out.enrolled = status.enrolled;
                out.revoked = status.revoked;
                out.device_id = status.device_id;
                out.online = status.online;
                if let Some(service) = status.service {
                    out.service_host = service_host(&service);
                    out.service = service;
                }
                out.peers = status.peers;
            }
            Err(_) if !process.available => out.problem = Some("link_binary_missing".into()),
            Err(e) => out.problem = process.problem.or(Some(e.reason)),
        }
        out
    }

    /// A running serve that was started without `--link-socket` is restarted with it once the
    /// daemon answers. A stopped serve is left stopped.
    pub fn relink_serve(&self) {
        if self.initialized()
            && matches!(self.serve.link_socket(), Some(None))
            && self.link.ready()
            && let Err(e) = self.restart_serve()
        {
            eprintln!(
                "zeropw: serve did not restart with the link socket ({}: {})",
                e.error, e.reason
            );
        }
    }

    /// Serve runs with `--link-socket` (started or restarted as needed), or why not.
    fn ensure_serve_link(&self) -> Result<ServeStatus, AppError> {
        match self.serve.link_socket() {
            Some(Some(_)) => Ok(self.serve.status()),
            Some(None) => self.restart_serve(),
            None => self.serve_start(),
        }
        .and_then(|status| {
            if status.running && matches!(self.serve.link_socket(), Some(Some(_))) {
                Ok(status)
            } else {
                Err(AppError::unavailable("serve_without_link"))
            }
        })
    }

    fn restart_serve(&self) -> Result<ServeStatus, AppError> {
        let _recovery = lock(&self.recovery_lock);
        self.serve.stop_reported(|status| self.show_serve(status));
        self.start_serve()
    }

    /// `link_enroll`: enrol this Mac with the link service using a server invite code. The
    /// code crosses IPC once (typed) and goes only into the socket request.
    pub fn link_enroll(&self, input: LinkEnrollIn) -> Result<LinkStatusOut, AppError> {
        if !is_invite_code(input.invite_code.expose()) {
            return Err(AppError::invalid_input("link_invite_malformed"));
        }
        let service = check_service_url(
            input
                .service
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(DEFAULT_SERVICE_URL),
        )?;
        let name = match input.name.as_deref().filter(|n| !n.trim().is_empty()) {
            Some(name) => check_display_name(name)?,
            None => default_device_name(),
        };
        self.ensure_link()?;
        let client = self.link.client();
        if client.status()?.enrolled {
            return Err(AppError::state("link_already_enrolled"));
        }
        client.enroll(&service, &name, Credential::InviteCode(&input.invite_code))?;
        self.relink_serve();
        Ok(self.link_view())
    }

    // -- pairing (the Mac with the vault) -------------------------------------------------------

    fn team_shared(&self, env: &str) -> Result<bool, AppError> {
        match self.team_members(super::EnvIn {
            env: env.to_owned(),
        }) {
            Ok(_) => Ok(true),
            Err(e) if e.reason == "team_env_not_found" => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Every `project/environment` of the local projects.
    fn local_envs(&self) -> Result<Vec<String>, AppError> {
        let list = self.project_list()?;
        let mut envs = Vec::new();
        for project in list
            .get("projects")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(name) = project.get("name").and_then(Value::as_str) else {
                continue;
            };
            for env in project
                .get("environments")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                let key = format!("{name}/{env}");
                if split_env(&key).is_some() {
                    envs.push(key);
                }
            }
        }
        Ok(envs)
    }

    /// `pairing_create`: share each chosen environment if needed (`team share`, which checks the
    /// passphrase), make one approval-required invitation per environment addressed to this
    /// Mac's link device (`team invite --approval --address zpl:<id>`, re-authenticated), get a
    /// one-time link token and put the code into the one-time store. A failure after some
    /// invitations were made revokes them (best effort); environments shared on the way stay
    /// shared and are reported by the error's detail only as a count.
    pub fn pairing_create(&self, input: PairingCreateIn) -> Result<PairingCreateOut, AppError> {
        require_passphrase(&input.admin_passphrase)?;
        let device_name = check_display_name(&input.device_name)?;
        let name = match input.name.as_deref().filter(|n| !n.trim().is_empty()) {
            Some(name) => check_display_name(name)?,
            None => default_device_name(),
        };
        let envs = match &input.envs {
            Some(envs) => check_envs(envs)?,
            None => self.local_envs()?,
        };
        if envs.is_empty() {
            return Err(AppError::invalid_input("pairing_no_environments"));
        }
        if envs.len() > pairing::MAX_INVITES {
            return Err(AppError::invalid_input("pairing_too_many_environments"));
        }
        self.ensure_link()?;
        let status = self.link.client().status()?;
        let (Some(own), Some(service), true) = (status.device_id, status.service, status.enrolled)
        else {
            return Err(AppError::state("link_not_enrolled"));
        };
        // the other Mac dials this one through serve's link socket
        self.ensure_serve_link()?;
        let slot = self.store.reserve(OneTimeKind::PairingCode)?;

        #[derive(Deserialize)]
        struct Created {
            #[serde(default)]
            invite: Option<SecretString>,
            #[serde(default)]
            link: Option<SecretString>,
            #[serde(default)]
            invite_id: Option<String>,
            #[serde(default)]
            approval: Option<String>,
        }
        let address = format!("zpl:{own}");
        let mut made: Vec<(String, String)> = Vec::new();
        let mut invites: Vec<PairInvite> = Vec::new();
        let mut out_envs = Vec::new();
        let mut fingerprint: Option<String> = None;
        let result = (|| -> Result<(), AppError> {
            for env in &envs {
                let (project, environment) =
                    split_env(env).ok_or_else(|| AppError::invalid_input("invalid_argument"))?;
                let shared_now = if self.team_shared(env)? {
                    false
                } else {
                    self.team_share(super::TeamShareIn {
                        project: project.to_owned(),
                        environment: environment.to_owned(),
                        name: Some(name.clone()),
                        admin_passphrase: input.admin_passphrase.duplicate(),
                    })?;
                    true
                };
                let created: Created = self.runner.run_parsed(
                    &AdminArgs::command(&["team", "invite"])
                        .require_admin()
                        .opt("env", env)?
                        .opt("role", "admin")?
                        .opt("name", &device_name)?
                        .opt("address", &address)?
                        .flag("approval")
                        .flag("link"),
                    &Envelope::new().admin_passphrase(&input.admin_passphrase),
                )?;
                let invite_id = created
                    .invite_id
                    .filter(|id| is_code(id))
                    .ok_or_else(|| AppError::internal("admin_output_invalid"))?;
                made.push((env.clone(), invite_id.clone()));
                // without approval anyone holding the code could join: never hand one out
                if created.approval.as_deref() != Some("required") {
                    return Err(AppError::internal("pairing_approval_unsupported"));
                }
                let invite = created
                    .invite
                    .or(created.link)
                    .ok_or_else(|| AppError::internal("admin_output_invalid"))?;
                if fingerprint.is_none() {
                    fingerprint = Some(self.invite_info(&invite)?.inviter);
                }
                invites.push(PairInvite {
                    env: env.clone(),
                    invite,
                });
                out_envs.push(PairingEnvOut {
                    env: env.clone(),
                    invite_id,
                    shared_now,
                });
            }
            Ok(())
        })();
        let token = result.and_then(|()| self.link.client().link_token());
        let token = match token {
            Ok(token) => token,
            Err(e) => {
                self.revoke_made(&made);
                return Err(e);
            }
        };
        let code = PairingCode {
            service,
            link_token: token.link_token,
            peer: own.clone(),
            name,
            invites,
        };
        let text = match code.encode() {
            Ok(text) => text,
            Err(e) => {
                self.revoke_made(&made);
                return Err(e);
            }
        };
        let now = now_unix();
        let expires = time_unix(&token.expires_at).map_or(now + PAIRING_CODE_TTL.as_secs(), |t| {
            t.min(now + PAIRING_CODE_TTL.as_secs())
        });
        let reference = slot.fill(text)?;
        let fingerprint = fingerprint.unwrap_or_default();
        let _ = self.devices_update(|file| {
            file.note_pairing(&envs, &device_name, now);
            if is_fingerprint(&fingerprint) {
                file.self_fingerprint = Some(fingerprint.clone());
            }
        });
        Ok(PairingCreateOut {
            reference,
            expires_at: iso_utc(expires),
            peer: own,
            fingerprint,
            environments: out_envs,
        })
    }

    fn revoke_made(&self, made: &[(String, String)]) {
        for (env, invite_id) in made {
            let _ = self.team_revoke_invite(super::TeamRevokeInviteIn {
                env: env.clone(),
                invite_id: invite_id.clone(),
            });
        }
    }

    /// `join_requests`: the pending approval requests of these environments (polled while the
    /// add-device sheet is open). An environment that cannot be read is listed in `errors`.
    pub fn join_requests(&self, input: EnvsIn) -> Result<JoinRequestsOut, AppError> {
        let envs = check_envs(&input.envs)?;
        let mut requests = Vec::new();
        let mut errors = Vec::new();
        for env in envs {
            match self.run_plain(AdminArgs::command(&["team", "join-requests"]).opt("env", &env)?) {
                Ok(out) => {
                    for r in out
                        .get("requests")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let Some(fingerprint) = r
                            .get("fingerprint")
                            .and_then(Value::as_str)
                            .filter(|f| is_fingerprint(f))
                        else {
                            continue;
                        };
                        requests.push(JoinRequest {
                            env: env.clone(),
                            request_id: r.get("request_id").and_then(id_text).unwrap_or_default(),
                            invite_id: r.get("invite_id").and_then(id_text).unwrap_or_default(),
                            fingerprint: fingerprint.to_owned(),
                            first_seen_at: r.get("first_seen_at").cloned().unwrap_or(Value::Null),
                            last_seen_at: r.get("last_seen_at").cloned().unwrap_or(Value::Null),
                            attempts: r.get("attempts").and_then(Value::as_u64).unwrap_or(0),
                        });
                    }
                }
                Err(e) => errors.push(EnvError {
                    env,
                    reason: e.reason,
                }),
            }
        }
        Ok(JoinRequestsOut { requests, errors })
    }

    pub fn approve_join(&self, input: JoinDecisionIn) -> Result<JoinDecisionOut, AppError> {
        self.decide_join(input, true)
    }

    pub fn deny_join(&self, input: JoinDecisionIn) -> Result<JoinDecisionOut, AppError> {
        self.decide_join(input, false)
    }

    /// `team approve-join`/`deny-join --env E --fingerprint FP` for each environment, with
    /// `--require-admin`. A wrong passphrase stops at once (the CLI changed nothing); any other
    /// failure is reported for its environment. An approval records the Mac as paired.
    fn decide_join(
        &self,
        input: JoinDecisionIn,
        approve: bool,
    ) -> Result<JoinDecisionOut, AppError> {
        require_passphrase(&input.admin_passphrase)?;
        let envs = check_envs(&input.envs)?;
        check_fingerprint(&input.fingerprint)?;
        let (words, key): (&[&'static str], &str) = if approve {
            (&["team", "approve-join"], "approved_invites")
        } else {
            (&["team", "deny-join"], "revoked_invites")
        };
        let mut results = Vec::new();
        for env in envs {
            let args = AdminArgs::command(words)
                .require_admin()
                .opt("env", &env)?
                .opt("fingerprint", &input.fingerprint)?;
            match self.run(
                args,
                Envelope::new().admin_passphrase(&input.admin_passphrase),
            ) {
                Ok(out) => results.push(JoinDecisionEnv {
                    env,
                    ok: true,
                    reason: None,
                    invites: out
                        .get(key)
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(id_text)
                        .collect(),
                }),
                Err(e) if e.error == "AuthFailed" => return Err(e),
                Err(e) => results.push(JoinDecisionEnv {
                    env,
                    ok: false,
                    reason: Some(e.reason),
                    invites: Vec::new(),
                }),
            }
        }
        if approve {
            let approved: Vec<String> = results
                .iter()
                .filter(|r| r.ok && !r.invites.is_empty())
                .map(|r| r.env.clone())
                .collect();
            if !approved.is_empty() {
                let fingerprint = input.fingerprint.clone();
                let _ = self.devices_update(|file| {
                    let name = approved
                        .iter()
                        .find_map(|env| file.pairing_name(env))
                        .unwrap_or_default()
                        .to_owned();
                    file.upsert(&fingerprint, None, &name, &approved, now_unix());
                });
            }
        }
        Ok(JoinDecisionOut {
            fingerprint: input.fingerprint,
            envs: results,
        })
    }

    // -- pairing (the joining Mac) ---------------------------------------------------------------

    /// `pairing_preview`: read a pasted code offline. Each invitation is read by `team
    /// invite-info` (no network): every one must name the code's link device as its only
    /// address, come from the same inviting fingerprint and not be expired. The code then
    /// waits in Rust (60 minutes) for `pairing_join`.
    pub fn pairing_preview(&self, input: PairingTextIn) -> Result<PairingPreviewOut, AppError> {
        let text = SecretString::new(input.text.expose().trim().to_owned());
        if text.is_empty() {
            return Err(AppError::invalid_input("pairing_code_missing"));
        }
        let code = PairingCode::decode(text.expose())?;
        let address = format!("zpl:{}", code.peer);
        let mut fingerprint: Option<String> = None;
        let mut expires: Option<(u64, String)> = None;
        let mut environments = Vec::new();
        for invite in &code.invites {
            let preview: InvitePreview = self.invite_info(&invite.invite)?;
            if preview.addresses.is_empty() || preview.addresses.iter().any(|a| *a != address) {
                return Err(AppError::invalid_input("pairing_address_mismatch"));
            }
            if preview.expired {
                return Err(AppError::invalid_input("pairing_expired"));
            }
            if !is_fingerprint(&preview.inviter) {
                return Err(AppError::internal("admin_output_invalid").with_detail("inviter"));
            }
            match &fingerprint {
                Some(f) if *f != preview.inviter => {
                    return Err(AppError::invalid_input("pairing_inviter_mismatch"));
                }
                Some(_) => {}
                None => fingerprint = Some(preview.inviter.clone()),
            }
            if let Some(at) = time_unix(&Value::String(preview.expires_at.clone()))
                && expires.as_ref().is_none_or(|(t, _)| at < *t)
            {
                expires = Some((at, preview.expires_at.clone()));
            }
            environments.push(PairingPreviewEnv {
                env: invite.env.clone(),
                env_id: preview.env_id,
                role: preview.role,
            });
        }
        let preview = PairingPreview {
            name: clean_name(&code.name),
            peer: code.peer.clone(),
            fingerprint: fingerprint.unwrap_or_default(),
            environments,
            service_host: service_host(&code.service),
            service: code.service.clone(),
            expires_at: expires.map(|(_, text)| text).unwrap_or_default(),
        };
        let reference = self.store.put(OneTimeKind::PairingText, text)?;
        Ok(PairingPreviewOut { reference, preview })
    }

    /// Whether the local `project/environment` already is the team environment `invite` is for
    /// (`team members` names its env id; `team invite-info` reads the invitation's offline).
    fn is_same_team_env(&self, env: &str, invite: &SecretString) -> Result<bool, AppError> {
        let members = match self.team_members(super::EnvIn {
            env: env.to_owned(),
        }) {
            Ok(members) => members,
            Err(e) if e.reason == "team_env_not_found" => return Ok(false),
            Err(e) => return Err(e),
        };
        let env_id = members.get("env_id").and_then(Value::as_str);
        Ok(env_id.is_some() && env_id == Some(self.invite_info(invite)?.env_id.as_str()))
    }

    /// `pairing_join`: enrol with the code's link token (or check that this Mac is already in
    /// the same account), then `team join --stdin --link-socket` for each environment not joined
    /// yet. An environment whose name is already a local environment other than this team
    /// environment is not joined (`pairing_env_exists`): its keys would mix with the other
    /// Mac's. The UI calls it again every few seconds while some environment is `pending`; once
    /// every environment joined the code is forgotten.
    pub fn pairing_join(&self, input: RefIn) -> Result<PairingJoinOut, AppError> {
        let _one_at_a_time = lock(&self.pairing_lock);
        let text = self
            .store
            .peek_kind(&input.reference, OneTimeKind::PairingText)?;
        let code = PairingCode::decode(text.expose())?;
        drop(text);
        self.ensure_link()?;
        let client = self.link.client();
        let status = client.status()?;
        if status.enrolled {
            if status.service.as_deref() != Some(code.service.as_str()) {
                return Err(AppError::state("link_other_service"));
            }
            if status.device_id.as_deref() == Some(code.peer.as_str()) {
                return Err(AppError::invalid_input("pairing_own_code"));
            }
            let devices = client.devices()?;
            if !devices
                .devices
                .iter()
                .any(|d| d.device_id == code.peer && d.active())
            {
                return Err(AppError::state("link_other_account"));
            }
        } else {
            client.enroll(
                &code.service,
                &default_device_name(),
                Credential::LinkToken(&code.link_token),
            )?;
        }
        // once joined, the other Mac reaches this one through serve's link socket
        self.relink_serve();
        let socket = self.paths.link_socket();
        let socket = socket
            .to_str()
            .ok_or_else(|| AppError::unavailable("link_socket_path_invalid"))?
            .to_owned();

        let cached: Vec<Option<PairingJoinEnv>> = {
            let mut progress = lock(&self.pairings);
            progress.retain(|reference, _| {
                self.store
                    .contains_kind(reference, OneTimeKind::PairingText)
            });
            progress
                .get(&input.reference)
                .cloned()
                .unwrap_or_else(|| vec![None; code.invites.len()])
        };
        // a local environment of the same name that is not this team environment would be
        // mixed with the other Mac's keys: refuse it rather than join into it
        let mut local: Option<BTreeSet<String>> = None;
        let mut results: Vec<PairingJoinEnv> = Vec::new();
        let mut joined_now: Vec<(String, String)> = Vec::new();
        let mut self_fp: Option<String> = None;
        for (index, invite) in code.invites.iter().enumerate() {
            if let Some(Some(done)) = cached.get(index) {
                results.push(done.clone());
                continue;
            }
            let (project, environment) = split_env(&invite.env)
                .ok_or_else(|| AppError::invalid_input("pairing_code_malformed"))?;
            if local.is_none() {
                local = Some(self.local_envs()?.into_iter().collect());
            }
            if local.as_ref().is_some_and(|l| l.contains(&invite.env))
                && !self.is_same_team_env(&invite.env, &invite.invite)?
            {
                results.push(PairingJoinEnv::failed(
                    &invite.env,
                    "pairing_env_exists",
                    None,
                ));
                continue;
            }
            let args = AdminArgs::command(&["team", "join"])
                .flag("stdin")
                .opt("link-socket", &socket)?
                .opt("project", project)?
                .opt("environment", environment)?
                .timeout(self.join_timeout);
            let result = self.run(args, Envelope::new().invite(&invite.invite));
            results.push(match result {
                Ok(out) => {
                    let text = |key: &str| out.get(key).and_then(Value::as_str).map(str::to_owned);
                    let local_project = text("project").unwrap_or_else(|| project.to_owned());
                    let local_env = text("environment").unwrap_or_else(|| environment.to_owned());
                    let inviter = text("inviter_fingerprint").filter(|f| is_fingerprint(f));
                    let me = text("self_fingerprint").filter(|f| is_fingerprint(f));
                    if me.is_some() {
                        self_fp.clone_from(&me);
                    }
                    if let Some(inviter) = &inviter {
                        joined_now.push((inviter.clone(), format!("{local_project}/{local_env}")));
                    }
                    PairingJoinEnv {
                        env: invite.env.clone(),
                        state: "joined",
                        reason: None,
                        detail: None,
                        self_fingerprint: me,
                        inviter_fingerprint: inviter,
                        project: Some(local_project),
                        environment: Some(local_env),
                    }
                }
                Err(e) if e.reason == JOIN_PENDING => {
                    let (me, inviter) = pending_fingerprints(&e);
                    if me.is_some() {
                        self_fp.clone_from(&me);
                    }
                    PairingJoinEnv {
                        env: invite.env.clone(),
                        state: "pending",
                        reason: None,
                        detail: None,
                        self_fingerprint: me,
                        inviter_fingerprint: inviter,
                        project: None,
                        environment: None,
                    }
                }
                // `team_join_failed` names in its detail why no address answered
                // (`link_peer_offline`, `link_unavailable`, …): kept only when it is a code
                Err(e) => {
                    let detail = e.detail.as_deref().filter(|d| is_reason_code(d));
                    PairingJoinEnv::failed(&invite.env, &e.reason, detail)
                }
            });
        }
        if !joined_now.is_empty() || self_fp.is_some() {
            let peer = code.peer.clone();
            let name = clean_name(&code.name);
            let _ = self.devices_update(|file| {
                if let Some(me) = &self_fp {
                    file.self_fingerprint = Some(me.clone());
                }
                for (inviter, env) in &joined_now {
                    file.upsert(
                        inviter,
                        Some(&peer),
                        &name,
                        std::slice::from_ref(env),
                        now_unix(),
                    );
                }
            });
        }
        let done = results.iter().all(|r| r.state == "joined");
        {
            let mut progress = lock(&self.pairings);
            if done {
                progress.remove(&input.reference);
            } else {
                progress.insert(
                    input.reference.clone(),
                    results
                        .iter()
                        .map(|r| (r.state == "joined").then(|| r.clone()))
                        .collect(),
                );
            }
        }
        if done {
            self.store.discard(&input.reference);
        }
        Ok(PairingJoinOut {
            done,
            peer: code.peer,
            environments: results,
        })
    }

    // -- devices view ----------------------------------------------------------------------------

    pub fn team_sync_status(&self, input: super::EnvIn) -> Result<Value, AppError> {
        self.run_plain(AdminArgs::command(&["team", "sync-status"]).opt("env", &input.env)?)
    }

    fn devices_update(&self, change: impl FnOnce(&mut DevicesFile)) -> Result<(), AppError> {
        let _guard = lock(&self.devices_lock);
        crate::paths::ensure_private_dir(&self.paths.app_data_dir)?;
        let path = self.paths.devices_file();
        let mut file = devices::load(&path)?;
        let before = file.clone();
        change(&mut file);
        if file != before {
            devices::save(&path, &file)?;
        }
        Ok(())
    }

    /// `devices_overview`: the paired Macs with their environments' members and sync state, the
    /// link daemon's view and the account's link devices, for the devices view to merge.
    pub fn devices_overview(&self) -> Result<DevicesOut, AppError> {
        let link = self.link_view();
        if link.running {
            self.relink_serve();
        }
        let (link_devices, link_devices_error) = if link.enrolled {
            match self.link.client().devices() {
                Ok(d) => (Some(d), None),
                Err(e) => (None, Some(e.reason)),
            }
        } else {
            (None, None)
        };
        let mut devices_error = None;
        let mut file = DevicesFile::default();
        let own = link.device_id.clone();
        if let Err(e) = self.devices_update(|f| {
            if let Some(d) = &link_devices {
                f.infer_link_ids(d, own.as_deref());
            }
            file = f.clone();
        }) {
            devices_error = Some(e.reason);
        }
        let envs: BTreeSet<String> = file.devices.iter().flat_map(|d| d.envs.clone()).collect();
        let envs = envs
            .into_iter()
            .map(|env| {
                let members = self.team_members(super::EnvIn { env: env.clone() });
                let sync = self.team_sync_status(super::EnvIn { env: env.clone() });
                let (members, members_error) = match members {
                    Ok(v) => (Some(v), None),
                    Err(e) => (None, Some(e.reason)),
                };
                let (sync, sync_error) = match sync {
                    Ok(v) => (Some(v), None),
                    Err(e) => (None, Some(e.reason)),
                };
                DeviceEnv {
                    env,
                    members,
                    sync,
                    members_error,
                    sync_error,
                }
            })
            .collect();
        Ok(DevicesOut {
            self_fingerprint: file.self_fingerprint.clone(),
            link,
            link_devices: link_devices.map(|d| d.devices).unwrap_or_default(),
            link_devices_error,
            devices: file.devices,
            devices_error,
            envs,
        })
    }

    /// `device_remove`: `team remove` (re-authenticated) in every environment paired with the
    /// Mac, then revoke its link device at the service. The link device is revoked only when
    /// every team removal went through, so a retry finds the same state. A Mac known only as a
    /// link device is revoked there without a passphrase (it holds no vault access through
    /// this Mac). This Mac cannot remove itself.
    pub fn device_remove(&self, input: DeviceRemoveIn) -> Result<DeviceRemoveOut, AppError> {
        let fingerprint = input.fingerprint.filter(|f| !f.is_empty());
        let link_id = input.link_device_id.filter(|l| !l.is_empty());
        if let Some(f) = &fingerprint {
            check_fingerprint(f)?;
        }
        if let Some(l) = &link_id
            && !is_device_id(l)
        {
            return Err(AppError::invalid_input("invalid_argument").with_detail("link_device_id"));
        }
        if fingerprint.is_none() && link_id.is_none() {
            return Err(AppError::invalid_input("invalid_argument").with_detail("device"));
        }
        let file = devices::load(&self.paths.devices_file())?;
        let record = fingerprint
            .as_deref()
            .and_then(|f| file.find(f))
            .or_else(|| link_id.as_deref().and_then(|l| file.find_link(l)))
            .cloned();
        let fingerprint = fingerprint.or_else(|| record.as_ref().map(|r| r.fingerprint.clone()));
        let link_id = link_id.or_else(|| record.as_ref().and_then(|r| r.link_device_id.clone()));
        let own_link = self.link.client().status().ok().and_then(|s| s.device_id);
        if (fingerprint.is_some() && fingerprint == file.self_fingerprint)
            || (link_id.is_some() && link_id == own_link)
        {
            return Err(AppError::invalid_input("cannot_remove_self"));
        }
        let envs = record.as_ref().map(|r| r.envs.clone()).unwrap_or_default();
        let mut removed = Vec::new();
        let mut failed = Vec::new();
        if let (Some(fp), false) = (&fingerprint, envs.is_empty()) {
            let pass = input
                .admin_passphrase
                .ok_or_else(|| AppError::auth_failed("passphrase_missing"))?;
            require_passphrase(&pass)?;
            for env in &envs {
                match self.team_remove(super::TeamRemoveIn {
                    env: env.clone(),
                    device: fp.clone(),
                    admin_passphrase: pass.duplicate(),
                }) {
                    Ok(_) => removed.push(env.clone()),
                    Err(e) if e.error == "AuthFailed" => return Err(e),
                    Err(e) => failed.push(EnvError {
                        env: env.clone(),
                        reason: e.reason,
                    }),
                }
            }
        }
        let (link_revoked, link_error) = match &link_id {
            Some(_) if !failed.is_empty() => (false, Some("link_kept".to_owned())),
            Some(id) => match self.link.client().revoke(id) {
                Ok(()) => (true, None),
                Err(e) => (false, Some(e.reason)),
            },
            None => (false, None),
        };
        let all_done = failed.is_empty() && (link_id.is_none() || link_revoked);
        let _ = self.devices_update(|file| {
            if all_done {
                file.remove(fingerprint.as_deref(), link_id.as_deref());
            } else if let Some(fp) = &fingerprint
                && let Some(d) = file.devices.iter_mut().find(|d| d.fingerprint == *fp)
            {
                d.envs.retain(|e| !removed.contains(e));
            }
        });
        Ok(DeviceRemoveOut {
            removed,
            failed,
            link_revoked,
            link_error,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_time_round_trips_with_the_parser() {
        for t in [0u64, 951_782_400, 1_793_966_400, 4_102_444_799] {
            let text = iso_utc(t);
            assert_eq!(time_unix(&Value::String(text.clone())), Some(t), "{text}");
        }
        assert_eq!(iso_utc(1_793_966_400), "2026-11-06T12:00:00Z");
    }

    #[test]
    fn env_lists_are_checked() {
        assert!(check_envs(&["demo/dev".into(), "demo/prod".into()]).is_ok());
        assert!(check_envs(&[]).is_err());
        assert!(check_envs(&["demo/dev".into(), "demo/dev".into()]).is_err());
        assert!(check_envs(&["--env=x/y".into()]).is_err());
        assert!(check_envs(&(0..17).map(|i| format!("demo/e{i}")).collect::<Vec<_>>()).is_err());
    }

    #[test]
    fn pending_detail_yields_both_fingerprints() {
        let e = AppError::new("StateError", JOIN_PENDING).with_detail(
            r#"{"inviter_fingerprint":"zyxwvutsrqponmlkjihgfedcba","self_fingerprint":"abcdefghijklmnopqrstuvwxyz"}"#,
        );
        assert_eq!(
            pending_fingerprints(&e),
            (
                Some("abcdefghijklmnopqrstuvwxyz".into()),
                Some("zyxwvutsrqponmlkjihgfedcba".into())
            )
        );
        assert_eq!(pending_fingerprints(&AppError::new("X", "y")), (None, None));
    }
}
