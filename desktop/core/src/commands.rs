//! [`Core`]: one method per IPC command in desktop/src/ipc/contract.ts (docs/desktop-app.md §5).
//!
//! Tauri-only pieces stay outside: `file_pick` opens a native dialog and registers the chosen
//! path with [`Core::files`]; `onetime_copy` receives a [`Clipboard`]; `terminal_open` and
//! `terminal_attach` receive a [`TerminalSink`] wrapping the output `Channel`; `secure_view`
//! receives a [`ScreenGuard`]; events go to an [`EventSink`]; the backup commands receive the
//! path the save/open dialog returned.
//!
//! Every method blocks (it may run a child process for up to 60–90 s), so the Tauri layer
//! should call them from async commands on a blocking thread.
//!
//! Commands whose CLI call changes state and prints a value once (`principal_create`,
//! `team_invite_create`, `secret_reveal`) reserve their one-time store slot before running
//! the CLI, so a full store refuses them up front instead of losing the token, link or value.
//!
//! "Re-auth" commands take the administrator passphrase and pass it to zeropw-admin in the
//! input envelope; the core refuses an empty one. `secret reveal`, `restore-ack`, `incident
//! close`, `incident declare --scope all` and `team share` verify it in the CLI itself. For
//! the commands the app re-authenticates but the CLI would run without a passphrase
//! (`resume`, `connection create-http`/`create-ssh`, `grant create`, `approvals approve`,
//! `team invite`, `team remove` and `restore`) the core adds the hidden global
//! `--require-admin` ([`REQUIRE_ADMIN_COMMANDS`]) so the CLI checks the envelope's passphrase
//! before it runs them.

use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::admin::{
    self, AdminArgs, AdminRunner, Envelope, JOIN_TIMEOUT, MAX_SECRET_BYTES, is_project_name,
};
use crate::error::AppError;
use crate::hooks::{Clipboard, CoreEvent, EventSink, FilePurpose, FileTokens, ScreenGuard};
use crate::netif::{self, NetInterface};
use crate::onetime::{OneTimeKind, OneTimeStore};
use crate::paths::{self, AppPaths};
use crate::recovery;
use crate::secret::SecretString;
use crate::serve::{self, ServeConfig, ServeStatus, ServeSupervisor};
use crate::settings::{self, Settings};
use crate::sshkey;
use crate::strength::{self, Strength};
use crate::terminal::{
    RING_BYTES, TerminalManager, TerminalProgram, TerminalRequest, TerminalSink, TerminalSummary,
};

/// How long a copied one-time value may stay on the clipboard (§8.7).
pub const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(60);
/// How long app quit waits for the clipboard while clearing a copied value.
const CLIPBOARD_SHUTDOWN_WAIT: Duration = Duration::from_secs(2);
/// Copies app quit remembers to clear; beyond this the oldest is forgotten (it can only still
/// be on the clipboard if every later copy failed). Its own 60 s timer still runs.
const MAX_PENDING_CLEARS: usize = 64;
const MAX_INVITE_CHARS: usize = 4096;
/// The longest version text the core passes on (the CLI prints integers).
const MAX_VERSION_CHARS: usize = 64;

/// zeropw-admin commands that run with `--require-admin` (docs/desktop-app.md §5: the app
/// re-authenticates them, the CLI alone would not).
pub const REQUIRE_ADMIN_COMMANDS: [&[&str]; 8] = [
    &["resume"],
    &["connection", "create-http"],
    &["connection", "create-ssh"],
    &["grant", "create"],
    &["approvals", "approve"],
    &["team", "invite"],
    &["team", "remove"],
    &["restore"],
];
const MAX_LIMIT: u32 = 10_000;

// ---------------------------------------------------------------------------------------------
// Contract types
// ---------------------------------------------------------------------------------------------

/// `Control`: `incident_open` is the CLI's open incident id reduced to a boolean.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Control {
    pub stopped: bool,
    pub restore_pending: bool,
    pub incident_open: bool,
}

impl Control {
    fn from_cli(value: &Value) -> Result<Self, AppError> {
        let flag = |key: &str| match value.get(key) {
            Some(Value::Bool(b)) => Ok(*b),
            _ => Err(AppError::internal("admin_output_invalid").with_detail(key.to_owned())),
        };
        let incident_open = match value.get("incident_open") {
            None | Some(Value::Null) | Some(Value::Bool(false)) => false,
            Some(Value::String(id)) => !id.is_empty(),
            Some(_) => true,
        };
        Ok(Self {
            stopped: flag("stopped")?,
            restore_pending: flag("restore_pending")?,
            incident_open,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AppStatus {
    pub initialized: bool,
    pub state_dir: String,
    pub serve: ServeStatus,
    pub control: Option<Control>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RecoveryOut {
    #[serde(rename = "ref")]
    pub reference: String,
    pub groups: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryInput {
    /// A code from `recovery_generate`, still in the one-time store.
    Ref(String),
    /// A passphrase the user chose instead.
    Typed(SecretString),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultInitIn {
    pub admin_passphrase: SecretString,
    pub recovery: RecoveryInput,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultInitOut {
    pub state_dir: String,
    pub kms_key_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PassphraseIn {
    pub admin_passphrase: SecretString,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectCreateIn {
    pub name: String,
    #[serde(default)]
    pub environments: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretListIn {
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdIn {
    pub id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ApiKey,
    Password,
    EnvVar,
    SshPrivateKey,
}

impl SecretKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SecretKind::ApiKey => "api_key",
            SecretKind::Password => "password",
            SecretKind::EnvVar => "env_var",
            SecretKind::SshPrivateKey => "ssh_private_key",
        }
    }
}

/// `SecretSource`: `{typed}` crosses IPC once, `{file_token}` names a natively picked file,
/// `{generate_ed25519: true}` makes a new SSH key in Rust.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretSource {
    Typed(SecretString),
    FileToken(String),
    GenerateEd25519(bool),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretPutIn {
    pub id: String,
    pub kind: SecretKind,
    pub project: String,
    pub environment: String,
    pub source: SecretSource,
}

/// A secret version exactly as the CLI printed it in `secret_list`/`secret_versions`: a JSON
/// number (what the CLI prints) or a string. It goes to the CLI unchanged as
/// `--version=<text>`; the CLI decides what it accepts. A number must be an integer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version(String);

impl Version {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Version {
    fn from(text: &str) -> Self {
        Self(text.to_owned())
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Text(String),
            Number(serde_json::Number),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Text(text) => Ok(Self(text)),
            Raw::Number(n) if n.is_u64() || n.is_i64() => Ok(Self(n.to_string())),
            Raw::Number(_) => Err(serde::de::Error::custom("version")),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRevealIn {
    pub id: String,
    #[serde(default)]
    pub version: Option<Version>,
    pub admin_passphrase: SecretString,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RevealOut {
    #[serde(rename = "ref")]
    pub reference: String,
    pub id: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretVersionIn {
    pub id: String,
    pub version: Version,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HttpAuth {
    Bearer,
    Basic,
    Header,
}

impl HttpAuth {
    fn as_str(self) -> &'static str {
        match self {
            HttpAuth::Bearer => "bearer",
            HttpAuth::Basic => "basic",
            HttpAuth::Header => "header",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpConnectionIn {
    pub id: String,
    pub project: String,
    pub environment: String,
    pub service: String,
    pub secret_id: String,
    pub target: String,
    pub auth: HttpAuth,
    #[serde(default)]
    pub header_name: Option<String>,
    #[serde(default)]
    pub value_prefix: Option<String>,
    #[serde(default)]
    pub basic_username: Option<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub confirm_methods: Vec<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    #[serde(default)]
    pub allow_private_network: bool,
    #[serde(default)]
    pub cli_program: Option<String>,
    #[serde(default)]
    pub ca_file_token: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    pub admin_passphrase: SecretString,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshConnectionIn {
    pub id: String,
    pub project: String,
    pub environment: String,
    pub service: String,
    pub secret_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub host_keys: Vec<String>,
    /// The ssh the agent's `exec` runs. Required: a connection without one is refused with
    /// `cli_not_supported` and never reaches the server.
    pub cli_program: String,
    #[serde(default)]
    pub description: Option<String>,
    pub admin_passphrase: SecretString,
}

/// Gives an SSH connection made without an ssh (before the app sent one) the ssh its agents run.
/// Which connections can take one is the CLI's rule (`connection update --cli-program`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliProgramIn {
    pub id: String,
    pub cli_program: String,
    pub admin_passphrase: SecretString,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalCreateIn {
    pub id: String,
    #[serde(default)]
    pub runtime: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PrincipalCreateOut {
    pub id: String,
    pub runtime: String,
    pub token_ref: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantListIn {
    #[serde(default)]
    pub principal: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantCreateIn {
    pub principal: String,
    pub connection: String,
    pub ttl: String,
    #[serde(default)]
    pub max_uses: Option<String>,
    pub admin_passphrase: SecretString,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalOpenIn {
    pub token_ref: String,
    #[serde(default)]
    pub as_user: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TerminalOpenOut {
    pub terminal_id: String,
    pub suggestions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TerminalListOut {
    pub terminals: Vec<TerminalSummary>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalIdIn {
    pub terminal_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecureViewIn {
    pub on: bool,
}

/// `secure_view` output: whether the content-protection request was applied to the window.
/// It is a best-effort request (macOS screen capture APIs may ignore it), not a guarantee;
/// `false` after `{on: true}` means the platform has no such request (Linux).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SecureViewOut {
    pub protected: bool,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitIn {
    pub limit: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveIn {
    pub digest: String,
    pub admin_passphrase: SecretString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentScope {
    Principal,
    Runtime,
    All,
}

impl IncidentScope {
    fn as_str(self) -> &'static str {
        match self {
            IncidentScope::Principal => "principal",
            IncidentScope::Runtime => "runtime",
            IncidentScope::All => "all",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentDeclareIn {
    pub scope: IncidentScope,
    #[serde(default)]
    pub principal: Option<String>,
    #[serde(default)]
    pub runtime: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub admin_passphrase: Option<SecretString>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentCloseIn {
    pub id: String,
    pub admin_passphrase: SecretString,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverIn {
    pub recovery_passphrase: SecretString,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamShareIn {
    pub project: String,
    pub environment: String,
    #[serde(default)]
    pub name: Option<String>,
    pub admin_passphrase: SecretString,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvIn {
    pub env: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamRemoveIn {
    pub env: String,
    pub device: String,
    pub admin_passphrase: SecretString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamRole {
    User,
    Admin,
}

impl TeamRole {
    fn as_str(self) -> &'static str {
        match self {
            TeamRole::User => "user",
            TeamRole::Admin => "admin",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamInviteCreateIn {
    pub env: String,
    pub role: TeamRole,
    pub name: String,
    pub address: String,
    pub admin_passphrase: SecretString,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TeamInviteCreateOut {
    pub invite_id: String,
    pub link_ref: String,
    pub expires_at: String,
    pub inviter: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamRevokeInviteIn {
    pub env: String,
    pub invite_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamInvitePreviewIn {
    pub text: SecretString,
}

/// `InvitePreview`: what `team invite-info` reveals before joining (no secret).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitePreview {
    pub env_id: String,
    pub inviter: String,
    pub addresses: Vec<String>,
    pub role: String,
    pub name: String,
    pub expires_at: String,
    pub expired: bool,
    pub invite_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InvitePreviewOut {
    #[serde(rename = "ref")]
    pub reference: String,
    pub preview: InvitePreview,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamJoinIn {
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefIn {
    #[serde(rename = "ref")]
    pub reference: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CopyOut {
    pub copied: bool,
    pub clears_in_s: u64,
}

// ---------------------------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------------------------

/// Construction parameters. `new` fills in the documented defaults.
pub struct CoreConfig {
    pub paths: AppPaths,
    pub admin_timeout: Duration,
    pub join_timeout: Duration,
    pub serve_start_timeout: Duration,
    pub serve_stop_grace: Duration,
    pub clipboard_clear_after: Duration,
    pub terminal_program: TerminalProgram,
    pub terminal_ring_bytes: usize,
}

impl CoreConfig {
    pub fn new(paths: AppPaths) -> Self {
        Self {
            paths,
            admin_timeout: admin::DEFAULT_TIMEOUT,
            join_timeout: JOIN_TIMEOUT,
            serve_start_timeout: serve::START_TIMEOUT,
            serve_stop_grace: serve::STOP_GRACE,
            clipboard_clear_after: CLIPBOARD_CLEAR_AFTER,
            terminal_program: TerminalProgram::LoginShell,
            terminal_ring_bytes: RING_BYTES,
        }
    }
}

/// A copied value whose 60 s clear has not run yet (app quit clears it early).
struct PendingClear {
    id: u64,
    digest: [u8; 32],
    clipboard: Arc<dyn Clipboard>,
}

#[derive(Default)]
struct PendingClears {
    next_id: u64,
    items: Vec<PendingClear>,
}

pub struct Core {
    paths: AppPaths,
    runner: AdminRunner,
    join_timeout: Duration,
    serve: ServeSupervisor,
    store: OneTimeStore,
    files: FileTokens,
    terminals: TerminalManager,
    events: Arc<dyn EventSink>,
    clipboard_clear_after: Duration,
    pending_clears: Arc<Mutex<PendingClears>>,
    settings_lock: Mutex<()>,
    /// Held by `recover` while the sidecar is down for it; `serve_start` waits on it.
    recovery_lock: Mutex<()>,
}

impl Core {
    pub fn new(config: CoreConfig, events: Arc<dyn EventSink>) -> Self {
        let paths = config.paths;
        Self {
            runner: AdminRunner::new(&paths.bin_dir, &paths.state_dir())
                .with_default_timeout(config.admin_timeout),
            join_timeout: config.join_timeout,
            serve: ServeSupervisor::new(&paths)
                .with_timeouts(config.serve_start_timeout, config.serve_stop_grace),
            store: OneTimeStore::new(),
            files: FileTokens::new(),
            terminals: TerminalManager::with_ring_bytes(
                config.terminal_program,
                config.terminal_ring_bytes,
            ),
            events,
            clipboard_clear_after: config.clipboard_clear_after,
            pending_clears: Arc::new(Mutex::new(PendingClears::default())),
            settings_lock: Mutex::new(()),
            recovery_lock: Mutex::new(()),
            paths,
        }
    }

    pub fn paths(&self) -> &AppPaths {
        &self.paths
    }

    /// Native file dialogs register their result here (`file_pick`).
    pub fn files(&self) -> &FileTokens {
        &self.files
    }

    /// App start: adopt a serve sidecar left running by an earlier app run.
    pub fn startup(&self) -> ServeStatus {
        let status = self.serve.attach();
        self.events.emit(CoreEvent::ServeStatus(status.clone()));
        status
    }

    /// App quit: clear the clipboard if it still holds a value copied in the last 60 s, forget
    /// one-time values, stop every terminal and what runs in it, SIGTERM the sidecar.
    pub fn shutdown(&self) {
        self.clear_pending_clipboard();
        self.store.clear();
        self.terminals.close_all();
        let status = self.serve.stop();
        self.events.emit(CoreEvent::ServeStatus(status));
    }

    /// The early run of every pending 60 s clear: the clipboard is emptied if it still holds
    /// any value the app copied. Waits at most [`CLIPBOARD_SHUTDOWN_WAIT`] for the clipboard.
    fn clear_pending_clipboard(&self) {
        let pending = std::mem::take(&mut lock(&self.pending_clears).items);
        let Some(clipboard) = pending.last().map(|p| p.clipboard.clone()) else {
            return;
        };
        let digests: Vec<[u8; 32]> = pending.iter().map(|p| p.digest).collect();
        drop(pending);
        let (done, wait) = std::sync::mpsc::channel();
        thread::spawn(move || {
            if clipboard
                .read_text()
                .is_some_and(|now| digests.contains(&digest(now.expose())))
            {
                let _ = clipboard.clear();
            }
            let _ = done.send(());
        });
        let _ = wait.recv_timeout(CLIPBOARD_SHUTDOWN_WAIT);
    }

    fn run(&self, args: AdminArgs, envelope: Envelope) -> Result<Value, AppError> {
        self.runner.run(&args, &envelope)
    }

    fn run_plain(&self, args: AdminArgs) -> Result<Value, AppError> {
        self.runner.run(&args, &Envelope::new())
    }

    // -- status and onboarding ------------------------------------------------------------

    /// Whether a vault exists in the state directory (no CLI call).
    pub fn initialized(&self) -> bool {
        self.paths.state_dir().join("admin.json").is_file()
    }

    pub fn app_status(&self) -> Result<AppStatus, AppError> {
        let state_dir = self.paths.state_dir();
        let initialized = self.initialized();
        let serve = self.serve.status();
        let control = if initialized {
            Some(self.control_get()?)
        } else {
            None
        };
        Ok(AppStatus {
            initialized,
            state_dir: state_dir.to_string_lossy().into_owned(),
            serve,
            control,
        })
    }

    pub fn password_strength(&self, value: &SecretString) -> Strength {
        strength::evaluate(value.expose(), &[])
    }

    pub fn recovery_generate(&self) -> Result<RecoveryOut, AppError> {
        let code = recovery::generate()?;
        let reference = self.store.put(OneTimeKind::RecoveryCode, code.passphrase)?;
        Ok(RecoveryOut {
            reference,
            groups: code.groups,
        })
    }

    /// `init` with both passphrases in the envelope, then start the sidecar. The admin
    /// passphrase and a typed recovery passphrase must pass the same strength rules the UI
    /// shows. A generated code stays in the store until `init` succeeds, so a retry after a
    /// failed `init` uses the code the user already wrote down. If `init` succeeds but the
    /// sidecar does not start, the sidecar's error is returned; `app_status` then reports
    /// `initialized: true` and `serve_start` can be retried.
    pub fn vault_init(&self, input: VaultInitIn) -> Result<VaultInitOut, AppError> {
        let admin = &input.admin_passphrase;
        check_passphrase(admin, "admin", &[], strength::ADMIN_MIN_SCORE)?;
        let (recovery, recovery_ref) = match &input.recovery {
            RecoveryInput::Ref(reference) => (
                self.store.peek_kind(reference, OneTimeKind::RecoveryCode)?,
                Some(reference.as_str()),
            ),
            RecoveryInput::Typed(typed) => {
                let canonical = recovery::canonical_passphrase(typed);
                if same_passphrase(canonical.expose(), admin.expose()) {
                    return Err(AppError::invalid_input("passphrases_identical"));
                }
                check_passphrase(
                    &canonical,
                    "recovery",
                    &[admin.expose()],
                    strength::RECOVERY_MIN_SCORE,
                )?;
                (canonical, None)
            }
        };
        if same_passphrase(recovery.expose(), admin.expose()) {
            return Err(AppError::invalid_input("passphrases_identical"));
        }
        paths::ensure_private_dir(&self.paths.app_data_dir)?;
        let out: VaultInitOut = self.runner.run_parsed(
            &AdminArgs::command(&["init"]),
            &Envelope::new()
                .admin_passphrase(admin)
                .recovery_passphrase(&recovery),
        )?;
        if let Some(reference) = recovery_ref {
            self.store.discard(reference);
        }
        self.serve_start()?;
        Ok(out)
    }

    // -- serve sidecar ------------------------------------------------------------------------

    /// A start asked for while `recover` runs (the app's startup thread, the relay button)
    /// waits for it to end, so no sidecar loads the KMS key the recovery retires.
    pub fn serve_start(&self) -> Result<ServeStatus, AppError> {
        let _recovery = lock(&self.recovery_lock);
        self.start_serve()
    }

    fn start_serve(&self) -> Result<ServeStatus, AppError> {
        let settings = self.settings_get()?;
        let status = self.serve.start(&ServeConfig {
            port: settings.gateway_port,
            team_listen: settings.team_listen,
        })?;
        self.events.emit(CoreEvent::ServeStatus(status.clone()));
        Ok(status)
    }

    pub fn serve_stop(&self) -> ServeStatus {
        let status = self.serve.stop();
        self.events.emit(CoreEvent::ServeStatus(status.clone()));
        status
    }

    pub fn serve_status(&self) -> ServeStatus {
        self.serve.status()
    }

    // -- global stop ----------------------------------------------------------------------------

    pub fn control_get(&self) -> Result<Control, AppError> {
        Control::from_cli(&self.run_plain(AdminArgs::command(&["status"]))?)
    }

    pub fn stop_all(&self) -> Result<Control, AppError> {
        let control = Control::from_cli(&self.run_plain(AdminArgs::command(&["stop-all"]))?)?;
        self.events.emit(CoreEvent::ControlChanged(control));
        Ok(control)
    }

    pub fn resume(&self, input: PassphraseIn) -> Result<Control, AppError> {
        require_passphrase(&input.admin_passphrase)?;
        let control = Control::from_cli(&self.run(
            AdminArgs::command(&["resume"]).require_admin(),
            Envelope::new().admin_passphrase(&input.admin_passphrase),
        )?)?;
        self.events.emit(CoreEvent::ControlChanged(control));
        Ok(control)
    }

    // -- projects -----------------------------------------------------------------------------

    pub fn project_list(&self) -> Result<Value, AppError> {
        self.run_plain(AdminArgs::command(&["project", "list"]))
    }

    pub fn project_create(&self, input: ProjectCreateIn) -> Result<Value, AppError> {
        let mut args = AdminArgs::command(&["project", "create"]).positional(
            "name",
            &input.name,
            is_project_name,
        )?;
        if !input.environments.is_empty() {
            if !input.environments.iter().all(|e| is_project_name(e)) {
                return Err(AppError::invalid_input("invalid_argument").with_detail("environments"));
            }
            args = args.opt("environments", &input.environments.join(","))?;
        }
        self.run_plain(args)
    }

    // -- secrets ------------------------------------------------------------------------------

    pub fn secret_list(&self, input: SecretListIn) -> Result<Value, AppError> {
        self.run_plain(
            AdminArgs::command(&["secret", "list"])
                .opt_nonempty("project", input.project.as_deref())?
                .opt_nonempty("environment", input.environment.as_deref())?,
        )
    }

    pub fn secret_versions(&self, input: IdIn) -> Result<Value, AppError> {
        self.run_plain(AdminArgs::command(&["secret", "versions"]).opt("id", &input.id)?)
    }

    /// `secret put --stdin` with the value in the envelope. A generated SSH key also returns
    /// its `public_key` line and `fingerprint` next to the CLI output.
    pub fn secret_put(&self, input: SecretPutIn) -> Result<Value, AppError> {
        let args = AdminArgs::command(&["secret", "put"])
            .opt("id", &input.id)?
            .opt("kind", input.kind.as_str())?
            .opt("project", &input.project)?
            .opt("environment", &input.environment)?
            .flag("stdin");
        let mut public = None;
        let envelope = match &input.source {
            SecretSource::Typed(value) => Envelope::new().value(value.expose().as_bytes())?,
            SecretSource::FileToken(token) => {
                let path = self
                    .files
                    .take(token, &[FilePurpose::Secret, FilePurpose::SshKey])?;
                Envelope::new().value(&read_secret_file(&path)?)?
            }
            SecretSource::GenerateEd25519(true) => {
                if input.kind != SecretKind::SshPrivateKey {
                    return Err(AppError::invalid_input("source_kind_mismatch"));
                }
                let key = sshkey::generate_ed25519(&input.id)?;
                public = Some((key.public_line.clone(), key.fingerprint.clone()));
                Envelope::new().value(key.private_pem.expose().as_bytes())?
            }
            SecretSource::GenerateEd25519(false) => {
                return Err(AppError::invalid_input("invalid_source"));
            }
        };
        let mut out = self.run(args, envelope)?;
        if let (Some((public_key, fingerprint)), Some(object)) = (public, out.as_object_mut()) {
            object.insert("public_key".into(), Value::String(public_key));
            object.insert("fingerprint".into(), Value::String(fingerprint));
        }
        Ok(out)
    }

    /// `secret reveal` (re-auth every time). The value goes into the one-time store for 60 s;
    /// only its reference is returned.
    pub fn secret_reveal(&self, input: SecretRevealIn) -> Result<RevealOut, AppError> {
        require_passphrase(&input.admin_passphrase)?;
        let mut args = AdminArgs::command(&["secret", "reveal"]).opt("id", &input.id)?;
        if let Some(version) = input.version.as_ref().filter(|v| !v.as_str().is_empty()) {
            args = args.opt("version", check_version(version)?)?;
        }
        let slot = self.store.reserve(OneTimeKind::RevealedSecret)?;
        #[derive(Deserialize)]
        struct Revealed {
            id: String,
            version: Value,
            #[serde(default)]
            value: Option<SecretString>,
            #[serde(default)]
            value_base64: Option<SecretString>,
        }
        let out: Revealed = self.runner.run_parsed(
            &args,
            &Envelope::new().admin_passphrase(&input.admin_passphrase),
        )?;
        let value = out
            .value
            .or(out.value_base64)
            .ok_or_else(|| AppError::internal("admin_output_invalid"))?;
        let reference = slot.fill(value)?;
        Ok(RevealOut {
            reference,
            id: out.id,
            version: scalar_text(&out.version),
        })
    }

    pub fn secret_retire(&self, input: SecretVersionIn) -> Result<Value, AppError> {
        self.secret_version_action("retire", input)
    }

    pub fn secret_revoke(&self, input: SecretVersionIn) -> Result<Value, AppError> {
        self.secret_version_action("revoke", input)
    }

    fn secret_version_action(
        &self,
        action: &'static str,
        input: SecretVersionIn,
    ) -> Result<Value, AppError> {
        self.run_plain(
            AdminArgs::command(&["secret", action])
                .opt("id", &input.id)?
                .opt("version", check_version(&input.version)?)?,
        )
    }

    // -- connections --------------------------------------------------------------------------

    pub fn connection_list(&self) -> Result<Value, AppError> {
        self.run_plain(AdminArgs::command(&["connection", "list"]))
    }

    pub fn connection_create_http(&self, input: HttpConnectionIn) -> Result<Value, AppError> {
        require_passphrase(&input.admin_passphrase)?;
        let mut args = AdminArgs::command(&["connection", "create-http"])
            .require_admin()
            .opt("id", &input.id)?
            .opt("project", &input.project)?
            .opt("environment", &input.environment)?
            .opt("service", &input.service)?
            .opt("secret-id", &input.secret_id)?
            .opt("target", &input.target)?
            .opt("auth", input.auth.as_str())?
            .opt_nonempty("header-name", input.header_name.as_deref())?
            .opt_nonempty("value-prefix", input.value_prefix.as_deref())?
            .opt_nonempty("basic-username", input.basic_username.as_deref())?
            .opt_nonempty(
                "methods",
                csv("methods", &input.methods, is_method)?.as_deref(),
            )?
            .opt_nonempty(
                "confirm-methods",
                csv("confirm_methods", &input.confirm_methods, is_method)?.as_deref(),
            )?
            .opt_nonempty(
                "path-prefixes",
                csv("path_prefixes", &input.path_prefixes, |p| !p.is_empty())?.as_deref(),
            )?
            .flag_if("allow-private-network", input.allow_private_network)
            .opt_nonempty("cli-program", input.cli_program.as_deref())?
            .opt_nonempty("description", input.description.as_deref())?;
        if let Some(token) = input.ca_file_token.as_deref().filter(|t| !t.is_empty()) {
            let path = self.files.take(token, &[FilePurpose::Ca])?;
            args = args.opt("ca-file", &path.to_string_lossy())?;
        }
        self.run(
            args,
            Envelope::new().admin_passphrase(&input.admin_passphrase),
        )
    }

    pub fn connection_create_ssh(&self, input: SshConnectionIn) -> Result<Value, AppError> {
        require_passphrase(&input.admin_passphrase)?;
        if input.host_keys.is_empty() {
            return Err(AppError::invalid_input("host_key_required"));
        }
        if input.cli_program.is_empty() {
            return Err(AppError::invalid_input("cli_program_required"));
        }
        let mut args = AdminArgs::command(&["connection", "create-ssh"])
            .require_admin()
            .opt("id", &input.id)?
            .opt("project", &input.project)?
            .opt("environment", &input.environment)?
            .opt("service", &input.service)?
            .opt("secret-id", &input.secret_id)?
            .opt("host", &input.host)?
            .opt("port", &input.port.to_string())?
            .opt("username", &input.username)?;
        for key in &input.host_keys {
            args = args.opt("host-key", key)?;
        }
        args = args
            .opt("cli-program", &input.cli_program)?
            .opt_nonempty("description", input.description.as_deref())?;
        self.run(
            args,
            Envelope::new().admin_passphrase(&input.admin_passphrase),
        )
    }

    /// `connection update --cli-program`: the CLI refuses a connection that is not SSH
    /// (`cli_requires_ssh`), is disabled (`connection_disabled`) or already has one
    /// (`cli_already_set`). A new program widens the connection, so its grants go stale.
    pub fn connection_set_cli_program(&self, input: CliProgramIn) -> Result<Value, AppError> {
        require_passphrase(&input.admin_passphrase)?;
        if input.cli_program.is_empty() {
            return Err(AppError::invalid_input("cli_program_required"));
        }
        let args = AdminArgs::command(&["connection", "update"])
            .require_admin()
            .opt("id", &input.id)?
            .opt("cli-program", &input.cli_program)?;
        self.run(
            args,
            Envelope::new().admin_passphrase(&input.admin_passphrase),
        )
    }

    pub fn connection_disable(&self, input: IdIn) -> Result<Value, AppError> {
        self.run_plain(AdminArgs::command(&["connection", "disable"]).opt("id", &input.id)?)
    }

    // -- agents and grants --------------------------------------------------------------------

    pub fn principal_list(&self) -> Result<Value, AppError> {
        self.run_plain(AdminArgs::command(&["principal", "list"]))
    }

    /// `principal create`; the caller token (printed once by the CLI) goes into the one-time
    /// store and only its reference is returned.
    pub fn principal_create(
        &self,
        input: PrincipalCreateIn,
    ) -> Result<PrincipalCreateOut, AppError> {
        #[derive(Deserialize)]
        struct Created {
            id: String,
            runtime: String,
            token: SecretString,
        }
        let args = AdminArgs::command(&["principal", "create"])
            .opt("id", &input.id)?
            .opt_nonempty("runtime", Some(input.runtime.as_str()))?;
        let slot = self.store.reserve(OneTimeKind::CallerToken)?;
        let out: Created = self.runner.run_parsed(&args, &Envelope::new())?;
        let token_ref = slot.fill_labeled(out.token, &out.id)?;
        Ok(PrincipalCreateOut {
            id: out.id,
            runtime: out.runtime,
            token_ref,
        })
    }

    pub fn principal_disable(&self, input: IdIn) -> Result<Value, AppError> {
        self.run_plain(AdminArgs::command(&["principal", "disable"]).opt("id", &input.id)?)
    }

    pub fn grant_list(&self, input: GrantListIn) -> Result<Value, AppError> {
        self.run_plain(
            AdminArgs::command(&["grant", "list"])
                .opt_nonempty("principal", input.principal.as_deref())?,
        )
    }

    pub fn grant_create(&self, input: GrantCreateIn) -> Result<Value, AppError> {
        require_passphrase(&input.admin_passphrase)?;
        let mut args = AdminArgs::command(&["grant", "create"])
            .require_admin()
            .opt("principal", &input.principal)?
            .opt("connection", &input.connection)?
            .opt_nonempty("ttl", Some(input.ttl.as_str()))?;
        if let Some(max) = input.max_uses.as_deref().filter(|m| !m.is_empty()) {
            args = args.opt("max-uses", check_integer("max_uses", max)?)?;
        }
        self.run(
            args,
            Envelope::new().admin_passphrase(&input.admin_passphrase),
        )
    }

    pub fn grant_revoke(&self, input: IdIn) -> Result<Value, AppError> {
        self.run_plain(AdminArgs::command(&["grant", "revoke"]).opt("id", &input.id)?)
    }

    // -- in-app terminal ----------------------------------------------------------------------

    /// Open a shell with the token from `token_ref` in its environment. The token entry is
    /// not consumed, so the "use in another terminal" menu can still show or copy it once.
    /// The terminal stays in the registry after the view that opened it goes away
    /// (`terminal_list`, `terminal_attach`) until `terminal_close` or app quit.
    pub fn terminal_open(
        &self,
        input: TerminalOpenIn,
        sink: Box<dyn TerminalSink>,
    ) -> Result<TerminalOpenOut, AppError> {
        let as_user = input.as_user.as_deref();
        let suggestions = crate::terminal::suggestions(&self.paths.bin_dir, as_user)?;
        let (token, principal) = self
            .store
            .peek_kind_labeled(&input.token_ref, OneTimeKind::CallerToken)?;
        let url = self
            .serve
            .url()
            .ok_or_else(|| AppError::unavailable("serve_not_running"))?;
        let terminal_id = self.terminals.open(
            &TerminalRequest {
                gateway_url: &url,
                token: &token,
                bin_dir: &self.paths.bin_dir,
                cols: 80,
                rows: 24,
                principal: principal.as_deref().unwrap_or_default(),
                as_user,
            },
            sink,
        )?;
        Ok(TerminalOpenOut {
            terminal_id,
            suggestions,
        })
    }

    /// Terminals in the registry, oldest first, value-free.
    pub fn terminal_list(&self) -> TerminalListOut {
        TerminalListOut {
            terminals: self.terminals.list(),
        }
    }

    /// Replay a terminal's buffered output into `sink`, then keep streaming to it (the
    /// previous view's sink is dropped). Returns the same suggestions `terminal_open` gave.
    pub fn terminal_attach(
        &self,
        input: TerminalIdIn,
        sink: Box<dyn TerminalSink>,
    ) -> Result<TerminalOpenOut, AppError> {
        let attached = self.terminals.attach(&input.terminal_id, sink)?;
        let suggestions =
            crate::terminal::suggestions(&self.paths.bin_dir, attached.as_user.as_deref())?;
        Ok(TerminalOpenOut {
            terminal_id: input.terminal_id,
            suggestions,
        })
    }

    pub fn terminal_write(&self, terminal_id: &str, data: &str) -> Result<(), AppError> {
        self.terminals.write(terminal_id, data)
    }

    pub fn terminal_resize(&self, terminal_id: &str, cols: u16, rows: u16) -> Result<(), AppError> {
        self.terminals.resize(terminal_id, cols, rows)
    }

    pub fn terminal_close(&self, terminal_id: &str) {
        self.terminals.close(terminal_id)
    }

    // -- screen capture -----------------------------------------------------------------------

    /// `secure_view`: ask the window system to keep the window out of screen capture while a
    /// one-time value is shown. Reports whether the request was applied (never on Linux); a
    /// capture tool may still ignore it, so nothing may claim the value cannot be captured.
    pub fn secure_view(
        &self,
        input: SecureViewIn,
        guard: &dyn ScreenGuard,
    ) -> Result<SecureViewOut, AppError> {
        let protected = guard.set_protected(input.on)?;
        Ok(SecureViewOut {
            protected: input.on && protected,
        })
    }

    // -- records ------------------------------------------------------------------------------

    pub fn audit_tail(&self, input: LimitIn) -> Result<Value, AppError> {
        self.run_plain(
            AdminArgs::command(&["audit", "tail"]).opt("limit", &check_limit(input.limit)?)?,
        )
    }

    pub fn alerts(&self, input: LimitIn) -> Result<Value, AppError> {
        self.run_plain(AdminArgs::command(&["alerts"]).opt("limit", &check_limit(input.limit)?)?)
    }

    pub fn approvals_list(&self) -> Result<Value, AppError> {
        self.run_plain(AdminArgs::command(&["approvals", "list"]))
    }

    pub fn approvals_approve(&self, input: ApproveIn) -> Result<Value, AppError> {
        require_passphrase(&input.admin_passphrase)?;
        self.run(
            AdminArgs::command(&["approvals", "approve"])
                .require_admin()
                .opt("digest", &input.digest)?,
            Envelope::new().admin_passphrase(&input.admin_passphrase),
        )
    }

    // -- incidents ----------------------------------------------------------------------------

    pub fn incident_list(&self) -> Result<Value, AppError> {
        self.run_plain(AdminArgs::command(&["incident", "list"]))
    }

    pub fn incident_show(&self, input: IdIn) -> Result<Value, AppError> {
        self.run_plain(AdminArgs::command(&["incident", "show"]).opt("id", &input.id)?)
    }

    /// `incident declare`; the `all` scope requires the admin passphrase.
    pub fn incident_declare(&self, input: IncidentDeclareIn) -> Result<Value, AppError> {
        let mut envelope = Envelope::new();
        match &input.admin_passphrase {
            Some(pass) if !pass.is_empty() => envelope = envelope.admin_passphrase(pass),
            _ if input.scope == IncidentScope::All => {
                return Err(AppError::auth_failed("passphrase_missing"));
            }
            _ => {}
        }
        self.run(
            AdminArgs::command(&["incident", "declare"])
                .opt("scope", input.scope.as_str())?
                .opt_nonempty("principal", input.principal.as_deref())?
                .opt_nonempty("runtime", input.runtime.as_deref())?
                .opt_nonempty("reason", input.reason.as_deref())?,
            envelope,
        )
    }

    pub fn incident_close(&self, input: IncidentCloseIn) -> Result<Value, AppError> {
        require_passphrase(&input.admin_passphrase)?;
        self.run(
            AdminArgs::command(&["incident", "close"]).opt("id", &input.id)?,
            Envelope::new().admin_passphrase(&input.admin_passphrase),
        )
    }

    // -- backup and recovery --------------------------------------------------------------------

    /// `backup --out=<path>`; `out` comes from the native save dialog.
    pub fn backup_create(&self, out: &Path) -> Result<Value, AppError> {
        self.run_plain(AdminArgs::command(&["backup"]).opt("out", &absolute(out)?)?)
    }

    /// `restore --in=<path>`; `input` comes from the native open dialog.
    pub fn backup_restore(&self, input: &Path, pass: PassphraseIn) -> Result<Value, AppError> {
        require_passphrase(&pass.admin_passphrase)?;
        self.run(
            AdminArgs::command(&["restore"])
                .require_admin()
                .opt("in", &absolute(input)?)?,
            Envelope::new().admin_passphrase(&pass.admin_passphrase),
        )
    }

    pub fn restore_ack(&self, input: PassphraseIn) -> Result<Value, AppError> {
        require_passphrase(&input.admin_passphrase)?;
        self.run(
            AdminArgs::command(&["restore-ack"]),
            Envelope::new().admin_passphrase(&input.admin_passphrase),
        )
    }

    /// `recover` with the recovery passphrase in the envelope. A typed recovery code may be
    /// in either of two forms: the canonical `XXXX-…` text `vault_init` stores for a code the
    /// app made (or a code typed at `vault_init`), or exactly what someone gave
    /// `zeropw-admin init` on the command line. When the input has a code's shape but is not
    /// already canonical, the canonical form is tried first and, only if the CLI answers
    /// `AuthFailed`, the input exactly as typed. So one attempt at most writes two
    /// `auth_failed` audit records; anything else is a single call.
    ///
    /// A running sidecar is stopped for the recovery and started again after it, whatever the
    /// outcome: it holds the KMS key in memory, so one left running would keep the key the
    /// recovery retired, could not read the team keys wrapped again under the new one, and
    /// could write new ones under the old key (issue #59). A start asked for meanwhile waits
    /// for the recovery to end. The recovery's result is returned whether or not the sidecar
    /// starts again; one that does not shows as stopped and can be started again.
    pub fn recover(&self, input: RecoverIn) -> Result<Value, AppError> {
        let typed = &input.recovery_passphrase;
        if typed.is_empty() {
            return Err(AppError::auth_failed("passphrase_missing"));
        }
        let attempt = |passphrase: &SecretString| {
            self.run(
                AdminArgs::command(&["recover"]),
                Envelope::new().recovery_passphrase(passphrase),
            )
        };
        let _recovery = lock(&self.recovery_lock);
        let running = self.serve_status().running;
        if running {
            self.serve_stop();
        }
        let out = match recovery::normalize(typed.expose()).filter(|c| c.expose() != typed.expose())
        {
            None => attempt(typed),
            Some(canonical) => match attempt(&canonical) {
                Err(e) if e.error == "AuthFailed" => attempt(typed),
                other => other,
            },
        };
        if running {
            let _ = self.start_serve();
        }
        out
    }

    // -- team ---------------------------------------------------------------------------------

    pub fn team_init(&self) -> Result<Value, AppError> {
        self.run_plain(AdminArgs::command(&["team", "init"]))
    }

    pub fn team_share(&self, input: TeamShareIn) -> Result<Value, AppError> {
        require_passphrase(&input.admin_passphrase)?;
        self.run(
            AdminArgs::command(&["team", "share"])
                .opt("project", &input.project)?
                .opt("environment", &input.environment)?
                .opt_nonempty("name", input.name.as_deref())?,
            Envelope::new().admin_passphrase(&input.admin_passphrase),
        )
    }

    pub fn team_members(&self, input: EnvIn) -> Result<Value, AppError> {
        self.run_plain(AdminArgs::command(&["team", "members"]).opt("env", &input.env)?)
    }

    pub fn team_remove(&self, input: TeamRemoveIn) -> Result<Value, AppError> {
        require_passphrase(&input.admin_passphrase)?;
        self.run(
            AdminArgs::command(&["team", "remove"])
                .require_admin()
                .opt("env", &input.env)?
                .opt("device", &input.device)?,
            Envelope::new().admin_passphrase(&input.admin_passphrase),
        )
    }

    /// `team invite --link`: the 24-hour link goes into the one-time store; the raw invite
    /// string the CLI also prints is wiped without leaving Rust.
    pub fn team_invite_create(
        &self,
        input: TeamInviteCreateIn,
    ) -> Result<TeamInviteCreateOut, AppError> {
        require_passphrase(&input.admin_passphrase)?;
        #[derive(Deserialize)]
        struct Created {
            #[serde(default)]
            link: Option<SecretString>,
            #[serde(default)]
            invite: Option<SecretString>,
            #[serde(default)]
            invite_id: Option<String>,
            #[serde(default)]
            expires_at: Option<String>,
            #[serde(default)]
            inviter: Option<String>,
        }
        let args = AdminArgs::command(&["team", "invite"])
            .require_admin()
            .opt("env", &input.env)?
            .opt("role", input.role.as_str())?
            .opt("name", &input.name)?
            .opt("address", &input.address)?
            .flag("link");
        let slot = self.store.reserve(OneTimeKind::InviteLink)?;
        let out: Created = self.runner.run_parsed(
            &args,
            &Envelope::new().admin_passphrase(&input.admin_passphrase),
        )?;
        drop(out.invite);
        let missing = || AppError::internal("admin_output_invalid");
        let link = out.link.ok_or_else(missing)?;
        let invite_id = out.invite_id.ok_or_else(missing)?;
        let expires_at = out.expires_at.ok_or_else(missing)?;
        let inviter = match out.inviter {
            Some(inviter) => inviter,
            None => self.invite_info(&link)?.inviter,
        };
        let link_ref = slot.fill(link)?;
        Ok(TeamInviteCreateOut {
            invite_id,
            link_ref,
            expires_at,
            inviter,
        })
    }

    /// `team invites`, reduced to the contract's fields; `link` is only ever a boolean.
    pub fn team_invites(&self, input: EnvIn) -> Result<Value, AppError> {
        let out =
            self.run_plain(AdminArgs::command(&["team", "invites"]).opt("env", &input.env)?)?;
        const KEYS: [&str; 9] = [
            "invite_id",
            "role",
            "name",
            "created_at",
            "expires_at",
            "status",
            "used_at",
            "used_by",
            "revoked_at",
        ];
        let invites: Vec<Value> = out
            .get("invites")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| {
                        let mut clean = Map::new();
                        for key in KEYS {
                            clean.insert(key.into(), item.get(key).cloned().unwrap_or(Value::Null));
                        }
                        let link = match item.get("link") {
                            Some(Value::Bool(b)) => *b,
                            Some(Value::String(s)) => !s.is_empty(),
                            _ => false,
                        };
                        clean.insert("link".into(), Value::Bool(link));
                        Value::Object(clean)
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(serde_json::json!({
            "env_id": out.get("env_id").cloned().unwrap_or(Value::Null),
            "invites": invites,
        }))
    }

    pub fn team_revoke_invite(&self, input: TeamRevokeInviteIn) -> Result<Value, AppError> {
        self.run_plain(
            AdminArgs::command(&["team", "revoke-invite"])
                .opt("env", &input.env)?
                .opt("id", &input.invite_id)?,
        )
    }

    /// `team invite-info --stdin`: preview a pasted invite without any network use. The text
    /// stays in Rust (one-time store, 60 minutes, so an invitee can make a vault before
    /// joining) for `team_join`, which removes it once the join succeeds. Previews have their
    /// own pool of 16 in the store; a new one drops the oldest, so links opened from outside
    /// the app cannot fill the store.
    pub fn team_invite_preview(
        &self,
        input: TeamInvitePreviewIn,
    ) -> Result<InvitePreviewOut, AppError> {
        let text = SecretString::new(input.text.expose().trim().to_owned());
        if text.is_empty() {
            return Err(AppError::invalid_input("invite_missing"));
        }
        if text.expose().chars().count() > MAX_INVITE_CHARS {
            return Err(AppError::invalid_input("invite_too_long"));
        }
        let preview = self.invite_info(&text)?;
        let reference = self.store.put(OneTimeKind::InviteText, text)?;
        Ok(InvitePreviewOut { reference, preview })
    }

    fn invite_info(&self, invite: &SecretString) -> Result<InvitePreview, AppError> {
        let preview: InvitePreview = self.runner.run_parsed(
            &AdminArgs::command(&["team", "invite-info"]).flag("stdin"),
            &Envelope::new().invite(invite),
        )?;
        if !matches!(preview.role.as_str(), "user" | "admin") {
            return Err(AppError::internal("admin_output_invalid").with_detail("role"));
        }
        Ok(preview)
    }

    /// A `zeropw://join#…` deep link: preview only, announced as `invite://preview`. Joining
    /// happens only when the user confirms (`team_join`).
    pub fn open_deep_link(&self, url: &str) -> Result<InvitePreviewOut, AppError> {
        let scheme_ok = url
            .get(..13)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("zeropw://join"));
        if !scheme_ok || url.len() > MAX_INVITE_CHARS {
            return Err(AppError::invalid_input("deep_link_invalid"));
        }
        let out = self.team_invite_preview(TeamInvitePreviewIn {
            text: SecretString::from(url),
        })?;
        self.events.emit(CoreEvent::InvitePreview(out.clone()));
        Ok(out)
    }

    /// Whether a preview reference from `team_invite_preview`/`open_deep_link` can still be
    /// joined (not yet used, discarded or expired).
    pub fn invite_pending(&self, reference: &str) -> bool {
        self.store.contains_kind(reference, OneTimeKind::InviteText)
    }

    /// `team join --stdin` with the previewed invite (90 s limit). The invite is forgotten
    /// once the join succeeds.
    pub fn team_join(&self, input: TeamJoinIn) -> Result<Value, AppError> {
        let invite = self
            .store
            .peek_kind(&input.reference, OneTimeKind::InviteText)?;
        let out = self.run(
            AdminArgs::command(&["team", "join"])
                .flag("stdin")
                .opt_nonempty("project", input.project.as_deref())?
                .opt_nonempty("environment", input.environment.as_deref())?
                .timeout(self.join_timeout),
            Envelope::new().invite(&invite),
        )?;
        self.store.discard(&input.reference);
        Ok(out)
    }

    // -- one-time values ----------------------------------------------------------------------

    /// `onetime_show`: the value, once. The caller sends `{text}` to the webview.
    pub fn onetime_show(&self, input: RefIn) -> Result<SecretString, AppError> {
        self.store
            .take_showable(&input.reference)
            .map(|(_, value)| value)
    }

    /// `onetime_copy`: write the value to the clipboard, then forget it, and clear the
    /// clipboard after 60 s if it still holds that value. A failed write keeps the value.
    /// The pending clear is recorded in the core, so app quit runs it early
    /// ([`Self::shutdown`]) instead of leaving the value behind.
    pub fn onetime_copy(
        &self,
        input: RefIn,
        clipboard: Arc<dyn Clipboard>,
    ) -> Result<CopyOut, AppError> {
        let value = self.store.peek_showable(&input.reference)?;
        clipboard.write_text(value.expose())?;
        self.store.discard(&input.reference);
        let copied = digest(value.expose());
        drop(value);
        let id = {
            let mut pending = lock(&self.pending_clears);
            pending.next_id += 1;
            let id = pending.next_id;
            pending.items.push(PendingClear {
                id,
                digest: copied,
                clipboard: clipboard.clone(),
            });
            if pending.items.len() > MAX_PENDING_CLEARS {
                pending.items.remove(0);
            }
            id
        };
        let after = self.clipboard_clear_after;
        let pending = self.pending_clears.clone();
        thread::spawn(move || {
            thread::sleep(after);
            {
                let mut pending = lock(&pending);
                pending.items.retain(|p| p.id != id);
            }
            if clipboard
                .read_text()
                .is_some_and(|now| digest(now.expose()) == copied)
            {
                let _ = clipboard.clear();
            }
        });
        Ok(CopyOut {
            copied: true,
            clears_in_s: after.as_secs(),
        })
    }

    pub fn onetime_discard(&self, input: RefIn) {
        self.store.discard(&input.reference);
    }

    // -- settings -----------------------------------------------------------------------------

    pub fn settings_get(&self) -> Result<Settings, AppError> {
        let _guard = self.settings_lock.lock().unwrap_or_else(|e| e.into_inner());
        settings::load(&self.paths.settings_file())
    }

    /// Save settings. A running sidecar keeps its port until it is restarted.
    pub fn settings_set(&self, input: Settings) -> Result<Settings, AppError> {
        let _guard = self.settings_lock.lock().unwrap_or_else(|e| e.into_inner());
        paths::ensure_private_dir(&self.paths.app_data_dir)?;
        settings::save(&self.paths.settings_file(), &input)?;
        Ok(input)
    }

    pub fn net_interfaces(&self) -> Result<Vec<NetInterface>, AppError> {
        netif::list()
    }
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

fn require_passphrase(pass: &SecretString) -> Result<(), AppError> {
    if pass.is_empty() {
        Err(AppError::auth_failed("passphrase_missing"))
    } else {
        Ok(())
    }
}

/// Length and strength rules for a passphrase chosen at `vault_init`.
fn check_passphrase(
    pass: &SecretString,
    which: &str,
    related: &[&str],
    min_score: u8,
) -> Result<(), AppError> {
    if pass.expose().chars().count() < strength::MIN_CHARS {
        return Err(AppError::invalid_input("passphrase_too_short").with_detail(which.to_owned()));
    }
    if strength::evaluate(pass.expose(), related).score < min_score {
        return Err(AppError::invalid_input("passphrase_weak").with_detail(which.to_owned()));
    }
    Ok(())
}

/// Equal ignoring surrounding whitespace and letter case: too close to keep both.
fn same_passphrase(a: &str, b: &str) -> bool {
    let a = Zeroizing::new(a.trim().to_lowercase());
    let b = Zeroizing::new(b.trim().to_lowercase());
    *a == *b
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn digest(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

/// A version as the webview got it from the CLI, passed on unchanged: letters, digits, `-`
/// and `_` only, starting with a letter or digit.
fn check_version(version: &Version) -> Result<&str, AppError> {
    let text = version.as_str();
    if text.len() <= MAX_VERSION_CHARS
        && text
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        Ok(text)
    } else {
        Err(AppError::invalid_input("invalid_argument").with_detail("version"))
    }
}

/// A non-negative decimal integer argument (max uses).
fn check_integer<'a>(what: &'static str, value: &'a str) -> Result<&'a str, AppError> {
    if !value.is_empty() && value.len() <= 20 && value.bytes().all(|b| b.is_ascii_digit()) {
        Ok(value)
    } else {
        Err(AppError::invalid_input("invalid_argument").with_detail(what))
    }
}

fn check_limit(limit: u32) -> Result<String, AppError> {
    if (1..=MAX_LIMIT).contains(&limit) {
        Ok(limit.to_string())
    } else {
        Err(AppError::invalid_input("invalid_argument").with_detail("limit"))
    }
}

fn is_method(method: &str) -> bool {
    !method.is_empty() && method.len() <= 16 && method.bytes().all(|b| b.is_ascii_alphabetic())
}

/// Join list items with commas for a `--flag=A,B` option; items must not contain commas.
fn csv(
    what: &'static str,
    items: &[String],
    valid: fn(&str) -> bool,
) -> Result<Option<String>, AppError> {
    if items.is_empty() {
        return Ok(None);
    }
    if items
        .iter()
        .any(|item| item.contains(',') || !valid(item.trim()))
    {
        return Err(AppError::invalid_input("invalid_argument").with_detail(what));
    }
    Ok(Some(
        items
            .iter()
            .map(|item| item.trim())
            .collect::<Vec<_>>()
            .join(","),
    ))
}

fn absolute(path: &Path) -> Result<String, AppError> {
    if !path.is_absolute() {
        return Err(AppError::invalid_input("file_path_invalid"));
    }
    Ok(path.to_string_lossy().into_owned())
}

fn scalar_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Read a natively picked secret file into a wiped buffer (at most the vault's 64 KiB).
fn read_secret_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, AppError> {
    let file = fs::File::open(path).map_err(|e| AppError::io("file_unreadable", &e))?;
    let meta = file
        .metadata()
        .map_err(|e| AppError::io("file_unreadable", &e))?;
    if !meta.is_file() {
        return Err(AppError::invalid_input("file_not_regular"));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_SECRET_BYTES + 1));
    file.take(MAX_SECRET_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| AppError::io("file_unreadable", &e))?;
    if bytes.len() > MAX_SECRET_BYTES {
        return Err(AppError::invalid_input("secret_too_large"));
    }
    if bytes.is_empty() {
        return Err(AppError::invalid_input("empty_secret_value"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_reduces_incident_id_to_bool() {
        let c = Control::from_cli(&serde_json::json!({
            "stopped": true, "restore_pending": false, "incident_open": "inc_123"
        }))
        .unwrap();
        assert_eq!(
            c,
            Control {
                stopped: true,
                restore_pending: false,
                incident_open: true
            }
        );
        let c = Control::from_cli(&serde_json::json!({
            "stopped": false, "restore_pending": false, "incident_open": null, "note": "x"
        }))
        .unwrap();
        assert!(!c.incident_open);
        assert!(Control::from_cli(&serde_json::json!({"stopped": "no"})).is_err());
    }

    #[test]
    fn contract_inputs_deserialize() {
        let v: VaultInitIn = serde_json::from_value(serde_json::json!({
            "admin_passphrase": "synthetic-pass-1",
            "recovery": {"ref": "0123456789abcdef0123456789abcdef"}
        }))
        .unwrap();
        assert!(matches!(v.recovery, RecoveryInput::Ref(_)));
        let v: VaultInitIn = serde_json::from_value(serde_json::json!({
            "admin_passphrase": "synthetic-pass-1",
            "recovery": {"typed": "synthetic recovery"}
        }))
        .unwrap();
        assert!(matches!(v.recovery, RecoveryInput::Typed(_)));
        for source in [
            serde_json::json!({"typed": "v"}),
            serde_json::json!({"file_token": "t"}),
            serde_json::json!({"generate_ed25519": true}),
        ] {
            let p: SecretPutIn = serde_json::from_value(serde_json::json!({
                "id": "a", "kind": "ssh_private_key", "project": "p", "environment": "dev",
                "source": source
            }))
            .unwrap();
            assert_eq!(p.kind, SecretKind::SshPrivateKey);
        }
        let j: TeamJoinIn = serde_json::from_value(serde_json::json!({"ref": "r"})).unwrap();
        assert_eq!(j.reference, "r");
        // Versions come back exactly as the CLI printed them: numbers or strings.
        for (version, text) in [
            (serde_json::json!(3), "3"),
            (serde_json::json!("3"), "3"),
            (serde_json::json!("9f86d081884c7d65"), "9f86d081884c7d65"),
        ] {
            let v: SecretVersionIn =
                serde_json::from_value(serde_json::json!({"id": "a", "version": version})).unwrap();
            assert_eq!(v.version.as_str(), text);
        }
        for bad in [
            serde_json::json!(1.5),
            serde_json::json!(true),
            serde_json::json!(null),
        ] {
            assert!(
                serde_json::from_value::<SecretVersionIn>(
                    serde_json::json!({"id": "a", "version": bad})
                )
                .is_err()
            );
        }
        let r: SecretRevealIn = serde_json::from_value(serde_json::json!({
            "id": "a", "version": 2, "admin_passphrase": "p"
        }))
        .unwrap();
        assert_eq!(r.version.map(|v| v.0), Some("2".to_owned()));
        let r: SecretRevealIn = serde_json::from_value(serde_json::json!({
            "id": "a", "version": null, "admin_passphrase": "p"
        }))
        .unwrap();
        assert!(r.version.is_none());
        assert!(
            serde_json::from_value::<IdIn>(serde_json::json!({"id": "a", "extra": 1})).is_err()
        );
        let s: Settings = serde_json::from_value(serde_json::json!({
            "gateway_port": 47380, "team_listen": null
        }))
        .unwrap();
        assert_eq!(s, Settings::default());
    }

    #[test]
    fn outputs_use_contract_names() {
        let v = serde_json::to_value(RevealOut {
            reference: "r".into(),
            id: "a".into(),
            version: "2".into(),
        })
        .unwrap();
        assert_eq!(
            v,
            serde_json::json!({"ref": "r", "id": "a", "version": "2"})
        );
        let v = serde_json::to_value(RecoveryOut {
            reference: "r".into(),
            groups: vec!["AAAA".into()],
        })
        .unwrap();
        assert_eq!(v["ref"], "r");
    }

    #[test]
    fn helpers() {
        assert!(same_passphrase(" Abc-Def ", "abc-def"));
        assert!(!same_passphrase("abc", "abd"));
        assert_eq!(check_integer("v", "12").unwrap(), "12");
        for bad in ["", "-1", "1.0", "1e3", &"9".repeat(21)] {
            assert!(check_integer("v", bad).is_err());
        }
        for good in ["1", "007", "18446744073709551616", "9f86d081884c7d65"] {
            assert_eq!(check_version(&Version::from(good)).unwrap(), good);
        }
        for bad in ["", "1; rm", "--help", "-1", "1 2", "1\n", &"9".repeat(65)] {
            assert_eq!(
                check_version(&Version::from(bad))
                    .unwrap_err()
                    .detail
                    .as_deref(),
                Some("version")
            );
        }
        assert_eq!(check_limit(50).unwrap(), "50");
        assert!(check_limit(0).is_err());
        assert!(check_limit(MAX_LIMIT + 1).is_err());
        assert_eq!(
            csv("m", &["GET".into(), " post ".into()], is_method).unwrap(),
            Some("GET,post".into())
        );
        assert!(csv("m", &["GET,POST".into()], is_method).is_err());
        assert!(csv("m", &["G T".into()], is_method).is_err());
        assert_eq!(csv("m", &[], is_method).unwrap(), None);
        assert_eq!(scalar_text(&serde_json::json!(3)), "3");
        assert!(absolute(Path::new("rel/x")).is_err());
    }
}
