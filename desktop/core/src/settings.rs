//! App settings (docs/desktop-app.md §4.5): `settings.json` (0600) in the app data folder, never
//! inside the state directory. Only the gateway port and the team-sync listen address live here.

use std::fs;
use std::io;
use std::net::SocketAddrV4;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::paths::write_private_atomic;

pub const DEFAULT_GATEWAY_PORT: u16 = 47380;
const MAX_SETTINGS_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    /// The fixed loopback port `serve --listen 127.0.0.1:<port>` binds.
    pub gateway_port: u16,
    /// `serve --team-listen IP:PORT`, or `null` for team sync off.
    #[serde(default)]
    pub team_listen: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            gateway_port: DEFAULT_GATEWAY_PORT,
            team_listen: None,
        }
    }
}

impl Settings {
    /// Unprivileged gateway port; team listen is one concrete IPv4 address and port (not
    /// `0.0.0.0`, not multicast or broadcast) so the picker's choice is what gets exposed.
    pub fn validate(&self) -> Result<(), AppError> {
        if self.gateway_port < 1024 {
            return Err(AppError::invalid_input("invalid_port").with_detail("gateway_port"));
        }
        if let Some(listen) = &self.team_listen {
            let addr: SocketAddrV4 = listen.parse().map_err(|_| {
                AppError::invalid_input("invalid_listen").with_detail("team_listen")
            })?;
            let ip = addr.ip();
            if addr.port() == 0 || ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
                return Err(AppError::invalid_input("invalid_listen").with_detail("team_listen"));
            }
        }
        Ok(())
    }
}

/// Read settings; a missing file means defaults. A corrupt file is an error rather than a
/// silent reset, so a changed port is never quietly forgotten.
pub fn load(path: &Path) -> Result<Settings, AppError> {
    let bytes = match fs::metadata(path) {
        Ok(meta) if meta.len() > MAX_SETTINGS_BYTES => {
            return Err(AppError::state("settings_corrupt"));
        }
        Ok(_) => fs::read(path).map_err(|e| AppError::io("settings_unreadable", &e))?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Settings::default()),
        Err(e) => return Err(AppError::io("settings_unreadable", &e)),
    };
    let settings: Settings =
        serde_json::from_slice(&bytes).map_err(|_| AppError::state("settings_corrupt"))?;
    settings
        .validate()
        .map_err(|_| AppError::state("settings_corrupt"))?;
    Ok(settings)
}

pub fn save(path: &Path, settings: &Settings) -> Result<(), AppError> {
    settings.validate()?;
    let mut bytes =
        serde_json::to_vec_pretty(settings).map_err(|_| AppError::internal("settings_encode"))?;
    bytes.push(b'\n');
    write_private_atomic(path, &bytes).map_err(|e| AppError::io("settings_unwritable", &e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn defaults_when_missing_and_round_trip_with_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        assert_eq!(load(&path).unwrap(), Settings::default());
        assert_eq!(Settings::default().gateway_port, 47380);
        let s = Settings {
            gateway_port: 48000,
            team_listen: Some("192.168.1.20:47390".into()),
        };
        save(&path, &s).unwrap();
        assert_eq!(load(&path).unwrap(), s);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let json: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"gateway_port": 48000, "team_listen": "192.168.1.20:47390"})
        );
    }

    #[test]
    fn invalid_values_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        for (port, listen) in [
            (80, None),
            (47380, Some("0.0.0.0:47390")),
            (47380, Some("192.168.1.20")),
            (47380, Some("192.168.1.20:0")),
            (47380, Some("[::1]:47390")),
            (47380, Some("example.com:47390")),
            (47380, Some("224.0.0.1:47390")),
        ] {
            let s = Settings {
                gateway_port: port,
                team_listen: listen.map(str::to_owned),
            };
            assert_eq!(save(&path, &s).unwrap_err().error, "InvalidInput");
        }
        assert!(!path.exists());
    }

    #[test]
    fn corrupt_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, b"{not json").unwrap();
        assert_eq!(load(&path).unwrap_err().reason, "settings_corrupt");
        fs::write(&path, br#"{"gateway_port": 80}"#).unwrap();
        assert_eq!(load(&path).unwrap_err().reason, "settings_corrupt");
        fs::write(&path, br#"{"gateway_port": 47381, "extra": 1}"#).unwrap();
        assert_eq!(load(&path).unwrap().gateway_port, 47381);
    }
}
