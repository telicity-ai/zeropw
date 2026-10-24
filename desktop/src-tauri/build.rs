//! Build script: draw the app icons (nothing binary is committed; icons/ is gitignored), then
//! run tauri-build with an app manifest that allowlists exactly the IPC commands of
//! desktop/src/ipc/contract.ts. scripts/check-tauri.mjs checks this list, the invoke handler
//! in src/commands.rs and capabilities/default.json against the contract.

use std::fs;
use std::path::Path;

#[path = "build/png.rs"]
mod png;

/// Every contract command, in contract order. Each gets an `allow-<command>` permission
/// (with `-` for `_`); capabilities/default.json grants all of them to the main window.
const COMMANDS: &[&str] = &[
    "app_status",
    "password_strength",
    "recovery_generate",
    "vault_init",
    "serve_start",
    "serve_stop",
    "serve_status",
    "control_get",
    "stop_all",
    "resume",
    "project_list",
    "project_create",
    "secret_list",
    "secret_versions",
    "secret_put",
    "secret_reveal",
    "secret_retire",
    "secret_revoke",
    "connection_list",
    "connection_create_http",
    "connection_create_ssh",
    "connection_disable",
    "principal_list",
    "principal_create",
    "principal_disable",
    "grant_list",
    "grant_create",
    "grant_revoke",
    "terminal_open",
    "terminal_write",
    "terminal_resize",
    "terminal_close",
    "terminal_list",
    "terminal_attach",
    "secure_view",
    "audit_tail",
    "alerts",
    "approvals_list",
    "approvals_approve",
    "incident_list",
    "incident_show",
    "incident_declare",
    "incident_close",
    "backup_create",
    "backup_restore",
    "restore_ack",
    "recover",
    "team_init",
    "team_share",
    "team_members",
    "team_remove",
    "team_invite_create",
    "team_invites",
    "team_revoke_invite",
    "team_invite_preview",
    "team_join",
    "onetime_show",
    "onetime_copy",
    "onetime_discard",
    "file_pick",
    "env_file_load",
    "secret_import_preview",
    "secret_import",
    "settings_get",
    "settings_set",
    "net_interfaces",
];

/// The bundle icons named in tauri.conf.json, and their sizes.
const ICONS: [(&str, u32); 4] = [
    ("32x32.png", 32),
    ("128x128.png", 128),
    ("128x128@2x.png", 256),
    ("icon.png", 512),
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build/png.rs");

    let dir = Path::new("icons");
    fs::create_dir_all(dir).expect("create src-tauri/icons");
    for (name, size) in ICONS {
        let bytes = png::icon_png(size);
        let path = dir.join(name);
        // Rewrite only on change, so tauri-build's own rerun checks stay quiet.
        if fs::read(&path).ok().as_deref() != Some(bytes.as_slice()) {
            fs::write(&path, &bytes).expect("write an icon");
        }
    }

    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("tauri-build failed");
}
