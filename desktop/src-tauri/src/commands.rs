//! One Tauri command per entry of `Commands` in desktop/src/ipc/contract.ts (the source of
//! truth; docs/desktop-app.md §5). The webview sends the contract's input as the top-level
//! invoke payload with snake_case keys.
//!
//! - Inputs are parsed from the request body into the core's own input types, which reject
//!   unknown keys. A parse failure is `InvalidInput/invalid_payload` with no detail, because
//!   serde's messages can quote the offending value (a passphrase, a key).
//! - Every core call may block on a zeropw-admin child for up to 60–90 s, so each command
//!   runs it on the blocking pool and returns `AppError {error, reason, detail?}` on failure.
//! - Native pieces stay in Rust: `file_pick` and the backup commands open the dialog here
//!   (the webview only gets a token and a base name), `onetime_copy` writes the clipboard
//!   here, `secure_view` toggles the calling window's content protection and says whether the
//!   platform has it, and the terminal commands stream output through a `Channel<String>`.
//! - `build.rs` allowlists exactly these commands in the app manifest, and
//!   capabilities/default.json grants exactly their `allow-*` permissions to the main window;
//!   scripts/check-tauri.mjs checks the three lists against the contract.

use std::path::PathBuf;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::ipc::{Channel, InvokeBody, Request};
use tauri::{AppHandle, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;
use zeropw_desktop_core::commands::*;
use zeropw_desktop_core::netif::NetInterface;
use zeropw_desktop_core::strength::Strength;
use zeropw_desktop_core::{
    AppError, Core, FilePick, FilePurpose, SecretString, ServeStatus, Settings,
};

use crate::glue::{ChannelSink, WindowScreenGuard};
use crate::shell::Shell;

type Out<T> = Result<T, AppError>;

/// Parse the invoke payload into a contract input type. Never echoes the payload.
fn input<T: DeserializeOwned>(request: &Request<'_>) -> Out<T> {
    match request.body() {
        InvokeBody::Json(value) => {
            T::deserialize(value).map_err(|_| AppError::invalid_input("invalid_payload"))
        }
        InvokeBody::Raw(_) => Err(AppError::invalid_input("invalid_payload")),
    }
}

/// Run a blocking core call off the async runtime.
async fn blocking<T, F>(f: F) -> Out<T>
where
    T: Send + 'static,
    F: FnOnce() -> Out<T> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|_| AppError::internal("command_failed"))?
}

fn core(shell: &State<'_, Shell>) -> Arc<Core> {
    shell.core()
}

fn cancelled() -> AppError {
    AppError::new("Cancelled", "file_dialog_cancelled")
}

// -- shell-side input types (the core takes these as plain arguments) ------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValueIn {
    value: SecretString,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalWriteIn {
    terminal_id: String,
    data: Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalResizeIn {
    terminal_id: String,
    cols: u16,
    rows: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FilePickIn {
    purpose: FilePurpose,
}

/// `onetime_show` output. The value crosses IPC once, by design (§2).
#[derive(Serialize)]
pub struct ShownText {
    text: Zeroizing<String>,
}

// -- status and onboarding --------------------------------------------------------------------

#[tauri::command(rename_all = "snake_case")]
pub async fn app_status(shell: State<'_, Shell>) -> Out<AppStatus> {
    let core = core(&shell);
    blocking(move || core.app_status()).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn password_strength(shell: State<'_, Shell>, request: Request<'_>) -> Out<Strength> {
    let input: ValueIn = input(&request)?;
    let core = core(&shell);
    blocking(move || Ok(core.password_strength(&input.value))).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn recovery_generate(shell: State<'_, Shell>) -> Out<RecoveryOut> {
    let core = core(&shell);
    blocking(move || core.recovery_generate()).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn vault_init(shell: State<'_, Shell>, request: Request<'_>) -> Out<VaultInitOut> {
    let input: VaultInitIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.vault_init(input)).await
}

// -- serve sidecar ----------------------------------------------------------------------------

#[tauri::command(rename_all = "snake_case")]
pub async fn serve_start(shell: State<'_, Shell>) -> Out<ServeStatus> {
    let core = core(&shell);
    blocking(move || core.serve_start()).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn serve_stop(shell: State<'_, Shell>) -> Out<ServeStatus> {
    let core = core(&shell);
    blocking(move || Ok(core.serve_stop())).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn serve_status(shell: State<'_, Shell>) -> Out<ServeStatus> {
    let core = core(&shell);
    blocking(move || Ok(core.serve_status())).await
}

// -- global stop ------------------------------------------------------------------------------

#[tauri::command(rename_all = "snake_case")]
pub async fn control_get(shell: State<'_, Shell>) -> Out<Control> {
    let core = core(&shell);
    blocking(move || core.control_get()).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn stop_all(shell: State<'_, Shell>) -> Out<Control> {
    let core = core(&shell);
    blocking(move || core.stop_all()).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn resume(shell: State<'_, Shell>, request: Request<'_>) -> Out<Control> {
    let input: PassphraseIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.resume(input)).await
}

// -- projects ---------------------------------------------------------------------------------

#[tauri::command(rename_all = "snake_case")]
pub async fn project_list(shell: State<'_, Shell>) -> Out<Value> {
    let core = core(&shell);
    blocking(move || core.project_list()).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn project_create(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: ProjectCreateIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.project_create(input)).await
}

// -- secrets ----------------------------------------------------------------------------------

#[tauri::command(rename_all = "snake_case")]
pub async fn secret_list(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: SecretListIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.secret_list(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn secret_versions(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: IdIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.secret_versions(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn secret_put(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: SecretPutIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.secret_put(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn secret_reveal(shell: State<'_, Shell>, request: Request<'_>) -> Out<RevealOut> {
    let input: SecretRevealIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.secret_reveal(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn secret_retire(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: SecretVersionIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.secret_retire(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn secret_revoke(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: SecretVersionIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.secret_revoke(input)).await
}

// -- connections ------------------------------------------------------------------------------

#[tauri::command(rename_all = "snake_case")]
pub async fn connection_list(shell: State<'_, Shell>) -> Out<Value> {
    let core = core(&shell);
    blocking(move || core.connection_list()).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn connection_create_http(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: HttpConnectionIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.connection_create_http(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn connection_create_ssh(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: SshConnectionIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.connection_create_ssh(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn connection_set_cli_program(
    shell: State<'_, Shell>,
    request: Request<'_>,
) -> Out<Value> {
    let input: CliProgramIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.connection_set_cli_program(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn connection_disable(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: IdIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.connection_disable(input)).await
}

// -- agents and grants ------------------------------------------------------------------------

#[tauri::command(rename_all = "snake_case")]
pub async fn principal_list(shell: State<'_, Shell>) -> Out<Value> {
    let core = core(&shell);
    blocking(move || core.principal_list()).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn principal_create(
    shell: State<'_, Shell>,
    request: Request<'_>,
) -> Out<PrincipalCreateOut> {
    let input: PrincipalCreateIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.principal_create(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn principal_disable(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: IdIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.principal_disable(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn grant_list(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: GrantListIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.grant_list(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn grant_create(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: GrantCreateIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.grant_create(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn grant_revoke(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: IdIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.grant_revoke(input)).await
}

// -- in-app terminal --------------------------------------------------------------------------

/// The output channel is a top-level argument (`on_data`), so this command takes its fields
/// as arguments instead of parsing the body.
#[tauri::command(rename_all = "snake_case")]
pub async fn terminal_open(
    shell: State<'_, Shell>,
    token_ref: String,
    as_user: Option<String>,
    on_data: Channel<String>,
) -> Out<TerminalOpenOut> {
    let core = core(&shell);
    let input = TerminalOpenIn { token_ref, as_user };
    blocking(move || core.terminal_open(input, Box::new(ChannelSink::new(on_data)))).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn terminal_write(shell: State<'_, Shell>, request: Request<'_>) -> Out<()> {
    let input: TerminalWriteIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.terminal_write(&input.terminal_id, &input.data)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn terminal_resize(shell: State<'_, Shell>, request: Request<'_>) -> Out<()> {
    let input: TerminalResizeIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.terminal_resize(&input.terminal_id, input.cols, input.rows)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn terminal_close(shell: State<'_, Shell>, request: Request<'_>) -> Out<()> {
    let input: TerminalIdIn = input(&request)?;
    let core = core(&shell);
    blocking(move || {
        core.terminal_close(&input.terminal_id);
        Ok(())
    })
    .await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn terminal_list(shell: State<'_, Shell>) -> Out<TerminalListOut> {
    let core = core(&shell);
    blocking(move || Ok(core.terminal_list())).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn terminal_attach(
    shell: State<'_, Shell>,
    terminal_id: String,
    on_data: Channel<String>,
) -> Out<TerminalOpenOut> {
    let core = core(&shell);
    let input = TerminalIdIn { terminal_id };
    blocking(move || core.terminal_attach(input, Box::new(ChannelSink::new(on_data)))).await
}

/// The screen-capture exclusion request for the window that asked (the main window).
/// `{protected}` says whether the request was applied (never on Linux); it is best effort and
/// capture tools may ignore it.
#[tauri::command(rename_all = "snake_case")]
pub async fn secure_view(
    shell: State<'_, Shell>,
    window: WebviewWindow,
    request: Request<'_>,
) -> Out<SecureViewOut> {
    let input: SecureViewIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.secure_view(input, &WindowScreenGuard::new(window))).await
}

// -- records ----------------------------------------------------------------------------------

#[tauri::command(rename_all = "snake_case")]
pub async fn audit_tail(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: LimitIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.audit_tail(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn alerts(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: LimitIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.alerts(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn approvals_list(shell: State<'_, Shell>) -> Out<Value> {
    let core = core(&shell);
    blocking(move || core.approvals_list()).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn approvals_approve(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: ApproveIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.approvals_approve(input)).await
}

// -- incidents --------------------------------------------------------------------------------

#[tauri::command(rename_all = "snake_case")]
pub async fn incident_list(shell: State<'_, Shell>) -> Out<Value> {
    let core = core(&shell);
    blocking(move || core.incident_list()).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn incident_show(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: IdIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.incident_show(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn incident_declare(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: IncidentDeclareIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.incident_declare(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn incident_close(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: IncidentCloseIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.incident_close(input)).await
}

// -- backup and recovery ----------------------------------------------------------------------

/// The save dialog runs here; the webview never names a path.
#[tauri::command(rename_all = "snake_case")]
pub async fn backup_create(
    app: AppHandle,
    window: WebviewWindow,
    shell: State<'_, Shell>,
) -> Out<Value> {
    let core = core(&shell);
    blocking(move || {
        let path = app
            .dialog()
            .file()
            .set_parent(&window)
            .set_file_name("zeropw-backup.zpw")
            .set_can_create_directories(true)
            .blocking_save_file()
            .ok_or_else(cancelled)?;
        core.backup_create(&dialog_path(path)?)
    })
    .await
}

/// The open dialog runs here; the webview never names a path.
#[tauri::command(rename_all = "snake_case")]
pub async fn backup_restore(
    app: AppHandle,
    window: WebviewWindow,
    shell: State<'_, Shell>,
    request: Request<'_>,
) -> Out<Value> {
    let input: PassphraseIn = input(&request)?;
    let core = core(&shell);
    blocking(move || {
        let path = app
            .dialog()
            .file()
            .set_parent(&window)
            .blocking_pick_file()
            .ok_or_else(cancelled)?;
        core.backup_restore(&dialog_path(path)?, input)
    })
    .await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn restore_ack(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: PassphraseIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.restore_ack(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn recover(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: RecoverIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.recover(input)).await
}

// -- team -------------------------------------------------------------------------------------

#[tauri::command(rename_all = "snake_case")]
pub async fn team_init(shell: State<'_, Shell>) -> Out<Value> {
    let core = core(&shell);
    blocking(move || core.team_init()).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn team_share(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: TeamShareIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.team_share(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn team_members(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: EnvIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.team_members(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn team_remove(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: TeamRemoveIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.team_remove(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn team_invite_create(
    shell: State<'_, Shell>,
    request: Request<'_>,
) -> Out<TeamInviteCreateOut> {
    let input: TeamInviteCreateIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.team_invite_create(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn team_invites(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: EnvIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.team_invites(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn team_revoke_invite(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: TeamRevokeInviteIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.team_revoke_invite(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn team_invite_preview(
    shell: State<'_, Shell>,
    request: Request<'_>,
) -> Out<InvitePreviewOut> {
    let input: TeamInvitePreviewIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.team_invite_preview(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn team_join(shell: State<'_, Shell>, request: Request<'_>) -> Out<Value> {
    let input: TeamJoinIn = input(&request)?;
    let core = core(&shell);
    blocking(move || core.team_join(input)).await
}

// -- one-time values --------------------------------------------------------------------------

#[tauri::command(rename_all = "snake_case")]
pub async fn onetime_show(shell: State<'_, Shell>, request: Request<'_>) -> Out<ShownText> {
    let input: RefIn = input(&request)?;
    let core = core(&shell);
    blocking(move || {
        let value = core.onetime_show(input)?;
        Ok(ShownText {
            text: Zeroizing::new(value.expose().to_owned()),
        })
    })
    .await
}

/// The clipboard is written here, never by the webview, marked to stay out of clipboard
/// history, and cleared after 60 s (or at quit, if sooner) if it still holds the value.
#[tauri::command(rename_all = "snake_case")]
pub async fn onetime_copy(shell: State<'_, Shell>, request: Request<'_>) -> Out<CopyOut> {
    let input: RefIn = input(&request)?;
    let core = core(&shell);
    let clipboard = shell.clipboard();
    blocking(move || core.onetime_copy(input, clipboard)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn onetime_discard(shell: State<'_, Shell>, request: Request<'_>) -> Out<()> {
    let input: RefIn = input(&request)?;
    let core = core(&shell);
    blocking(move || {
        core.onetime_discard(input);
        Ok(())
    })
    .await
}

/// A native open dialog; the chosen path is registered with the core and only an opaque
/// token and the file's base name go back. `null` when the user cancels.
#[tauri::command(rename_all = "snake_case")]
pub async fn file_pick(
    app: AppHandle,
    window: WebviewWindow,
    shell: State<'_, Shell>,
    request: Request<'_>,
) -> Out<Option<FilePick>> {
    let input: FilePickIn = input(&request)?;
    let core = core(&shell);
    blocking(move || {
        let mut dialog = app.dialog().file().set_parent(&window);
        if input.purpose == FilePurpose::Ca {
            dialog = dialog.add_filter("Certificate", &["pem", "crt", "cer"]);
        }
        match dialog.blocking_pick_file() {
            None => Ok(None),
            Some(path) => core
                .files()
                .register(input.purpose, &dialog_path(path)?)
                .map(Some),
        }
    })
    .await
}

fn dialog_path(path: tauri_plugin_dialog::FilePath) -> Out<PathBuf> {
    path.into_path()
        .map_err(|_| AppError::invalid_input("file_path_invalid"))
}

// -- settings ---------------------------------------------------------------------------------

#[tauri::command(rename_all = "snake_case")]
pub async fn settings_get(shell: State<'_, Shell>) -> Out<Settings> {
    let core = core(&shell);
    blocking(move || core.settings_get()).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn settings_set(shell: State<'_, Shell>, request: Request<'_>) -> Out<Settings> {
    let input: Settings = input(&request)?;
    let core = core(&shell);
    blocking(move || core.settings_set(input)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn net_interfaces(shell: State<'_, Shell>) -> Out<Vec<NetInterface>> {
    let core = core(&shell);
    blocking(move || core.net_interfaces()).await
}

/// The invoke handler for exactly the contract's commands (same order as contract.ts).
pub fn handler() -> impl Fn(tauri::ipc::Invoke) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        app_status,
        password_strength,
        recovery_generate,
        vault_init,
        serve_start,
        serve_stop,
        serve_status,
        control_get,
        stop_all,
        resume,
        project_list,
        project_create,
        secret_list,
        secret_versions,
        secret_put,
        secret_reveal,
        secret_retire,
        secret_revoke,
        connection_list,
        connection_create_http,
        connection_create_ssh,
        connection_set_cli_program,
        connection_disable,
        principal_list,
        principal_create,
        principal_disable,
        grant_list,
        grant_create,
        grant_revoke,
        terminal_open,
        terminal_write,
        terminal_resize,
        terminal_close,
        terminal_list,
        terminal_attach,
        secure_view,
        audit_tail,
        alerts,
        approvals_list,
        approvals_approve,
        incident_list,
        incident_show,
        incident_declare,
        incident_close,
        backup_create,
        backup_restore,
        restore_ack,
        recover,
        team_init,
        team_share,
        team_members,
        team_remove,
        team_invite_create,
        team_invites,
        team_revoke_invite,
        team_invite_preview,
        team_join,
        onetime_show,
        onetime_copy,
        onetime_discard,
        file_pick,
        settings_get,
        settings_set,
        net_interfaces,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse<T: DeserializeOwned>(value: Value) -> Out<T> {
        T::deserialize(&value).map_err(|_| AppError::invalid_input("invalid_payload"))
    }

    #[test]
    fn shell_inputs_take_the_contract_keys_and_nothing_else() {
        let w: TerminalWriteIn = parse(json!({"terminal_id": "t", "data": "ls\r"})).unwrap();
        assert_eq!((w.terminal_id.as_str(), w.data.as_str()), ("t", "ls\r"));
        let r: TerminalResizeIn =
            parse(json!({"terminal_id": "t", "cols": 100, "rows": 30})).unwrap();
        assert_eq!((r.cols, r.rows), (100, 30));
        let f: FilePickIn = parse(json!({"purpose": "ssh_key"})).unwrap();
        assert_eq!(f.purpose, FilePurpose::SshKey);
        assert!(parse::<FilePickIn>(json!({"purpose": "anything"})).is_err());
        assert!(parse::<FilePickIn>(json!({"purpose": "ca", "path": "/etc/passwd"})).is_err());
        assert!(
            parse::<TerminalResizeIn>(json!({"terminal_id": "t", "cols": -1, "rows": 1})).is_err()
        );
        let v: ValueIn = parse(json!({"value": "synthetic"})).unwrap();
        assert_eq!(v.value.expose(), "synthetic");
    }

    #[test]
    fn a_rejected_payload_does_not_echo_its_values() {
        let e =
            parse::<PassphraseIn>(json!({"admin_passphrase": 12345, "extra": "synthetic-pass"}))
                .err()
                .unwrap();
        let text = serde_json::to_string(&e).unwrap();
        assert_eq!(
            text,
            r#"{"error":"InvalidInput","reason":"invalid_payload"}"#
        );
    }

    #[test]
    fn shown_text_serializes_as_the_contract_shape() {
        let v = serde_json::to_value(ShownText {
            text: Zeroizing::new("synthetic".into()),
        })
        .unwrap();
        assert_eq!(v, json!({"text": "synthetic"}));
    }
}
