//! Paired Macs (`devices.json`, 0600, in the app data folder, never in the state directory):
//! which team member is which of this user's Macs, by team fingerprint and link device ID, and
//! the environments paired with it. It holds identifiers and names only, no secret; the team
//! state (membership, keys) stays in the CLI's state directory and decides everything that
//! matters. This file only lets the devices view put a member, its sync state and its link
//! peer on one row, and lets "연결 해제" find the environments and the link device to remove.
//!
//! The joining Mac learns both identifiers from the pairing code and the join result. The Mac
//! that made the code learns the fingerprint when it approves; the link device ID is inferred
//! when exactly one unmapped active device of the account appeared after a pairing code was
//! made and exactly one paired Mac still lacks one. Otherwise it stays unknown and that link
//! device is shown on its own row.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{AppError, is_fingerprint};
use crate::link::{LinkDevices, clean_name, is_device_id};
use crate::pairing::split_env;
use crate::paths::write_private_atomic;

const MAX_FILE_BYTES: u64 = 256 * 1024;
const MAX_DEVICES: usize = 64;
const MAX_NOTES: usize = 8;
/// A pairing code is good for 10 minutes; a note older than a day helps no inference.
const NOTE_LIFETIME_S: u64 = 24 * 3600;
/// Clock difference allowed between this Mac and the service when inferring.
const CLOCK_SLACK_S: u64 = 300;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedDevice {
    pub fingerprint: String,
    #[serde(default)]
    pub link_device_id: Option<String>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub envs: Vec<String>,
    #[serde(default)]
    pub added_at: u64,
}

/// A pairing code this Mac made: when, for which environments, and the member name its
/// invitations give the new Mac.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingNote {
    pub created_at: u64,
    #[serde(default)]
    pub envs: Vec<String>,
    #[serde(default)]
    pub device_name: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicesFile {
    #[serde(default)]
    pub v: u32,
    /// This Mac's team fingerprint, once known.
    #[serde(rename = "self", default)]
    pub self_fingerprint: Option<String>,
    #[serde(default)]
    pub devices: Vec<PairedDevice>,
    #[serde(default)]
    pub pairings: Vec<PairingNote>,
}

impl DevicesFile {
    /// Drop entries whose identifiers do not have their shapes (a hand-edited file).
    fn cleaned(mut self) -> Self {
        self.v = 1;
        self.self_fingerprint = self.self_fingerprint.filter(|f| is_fingerprint(f));
        self.devices.retain(|d| is_fingerprint(&d.fingerprint));
        for d in &mut self.devices {
            d.link_device_id = d.link_device_id.take().filter(|id| is_device_id(id));
            d.name = clean_name(&d.name);
            d.envs.retain(|e| split_env(e).is_some());
            d.envs.sort();
            d.envs.dedup();
        }
        self.devices.truncate(MAX_DEVICES);
        for n in &mut self.pairings {
            n.envs.retain(|e| split_env(e).is_some());
            n.device_name = clean_name(&n.device_name);
        }
        self
    }

    pub fn find(&self, fingerprint: &str) -> Option<&PairedDevice> {
        self.devices.iter().find(|d| d.fingerprint == fingerprint)
    }

    pub fn find_link(&self, link_device_id: &str) -> Option<&PairedDevice> {
        self.devices
            .iter()
            .find(|d| d.link_device_id.as_deref() == Some(link_device_id))
    }

    /// Add or extend a paired Mac. A known link device ID is never replaced by `None`, and an
    /// ID already given to another fingerprint moves to this one.
    pub fn upsert(
        &mut self,
        fingerprint: &str,
        link_device_id: Option<&str>,
        name: &str,
        envs: &[String],
        now: u64,
    ) {
        if !is_fingerprint(fingerprint) {
            return;
        }
        let link = link_device_id.filter(|id| is_device_id(id));
        if let Some(id) = link {
            for other in self
                .devices
                .iter_mut()
                .filter(|d| d.fingerprint != fingerprint)
            {
                if other.link_device_id.as_deref() == Some(id) {
                    other.link_device_id = None;
                }
            }
        }
        let index = match self
            .devices
            .iter()
            .position(|d| d.fingerprint == fingerprint)
        {
            Some(i) => i,
            None => {
                if self.devices.len() >= MAX_DEVICES {
                    return;
                }
                self.devices.push(PairedDevice {
                    fingerprint: fingerprint.to_owned(),
                    added_at: now,
                    ..PairedDevice::default()
                });
                self.devices.len() - 1
            }
        };
        let device = &mut self.devices[index];
        if let Some(id) = link {
            device.link_device_id = Some(id.to_owned());
        }
        let name = clean_name(name);
        if !name.is_empty() {
            device.name = name;
        }
        let mut all: BTreeSet<String> = device.envs.drain(..).collect();
        all.extend(envs.iter().filter(|e| split_env(e).is_some()).cloned());
        device.envs = all.into_iter().collect();
    }

    /// Remember a pairing code made now, for the inference above.
    pub fn note_pairing(&mut self, envs: &[String], device_name: &str, now: u64) {
        self.pairings
            .retain(|n| now.saturating_sub(n.created_at) < NOTE_LIFETIME_S);
        self.pairings.push(PairingNote {
            created_at: now,
            envs: envs.to_vec(),
            device_name: clean_name(device_name),
        });
        let extra = self.pairings.len().saturating_sub(MAX_NOTES);
        self.pairings.drain(..extra);
    }

    /// The member name a recent pairing gave the Mac that joins `env`.
    pub fn pairing_name(&self, env: &str) -> Option<&str> {
        self.pairings
            .iter()
            .rev()
            .find(|n| n.envs.iter().any(|e| e == env))
            .map(|n| n.device_name.as_str())
            .filter(|n| !n.is_empty())
    }

    /// Give the one paired Mac without a link device ID the one active, unmapped device of
    /// the account that enrolled after a pairing code was made. Returns whether anything
    /// changed.
    pub fn infer_link_ids(&mut self, link: &LinkDevices, own: Option<&str>) -> bool {
        let unmapped: Vec<usize> = (0..self.devices.len())
            .filter(|&i| self.devices[i].link_device_id.is_none())
            .collect();
        let [index] = unmapped.as_slice() else {
            return false;
        };
        let Some(first_note) = self.pairings.iter().map(|n| n.created_at).min() else {
            return false;
        };
        let since = first_note.saturating_sub(CLOCK_SLACK_S);
        let mapped: BTreeSet<&str> = self
            .devices
            .iter()
            .filter_map(|d| d.link_device_id.as_deref())
            .collect();
        let candidates: Vec<&str> = link
            .devices
            .iter()
            .filter(|d| d.active())
            .filter(|d| {
                Some(d.device_id.as_str()) != own && link.self_id.as_deref() != Some(&d.device_id)
            })
            .filter(|d| !mapped.contains(d.device_id.as_str()))
            .filter(|d| d.created_unix().is_some_and(|at| at >= since))
            .map(|d| d.device_id.as_str())
            .collect();
        let [only] = candidates.as_slice() else {
            return false;
        };
        self.devices[*index].link_device_id = Some((*only).to_owned());
        true
    }

    /// Forget a paired Mac (after it was removed everywhere).
    pub fn remove(&mut self, fingerprint: Option<&str>, link_device_id: Option<&str>) {
        self.devices.retain(|d| {
            !(fingerprint.is_some_and(|f| f == d.fingerprint)
                || link_device_id.is_some_and(|l| d.link_device_id.as_deref() == Some(l)))
        });
    }
}

/// Read the file; a missing file is empty. A damaged file is an error, never silently reset.
pub fn load(path: &Path) -> Result<DevicesFile, AppError> {
    let bytes = match fs::metadata(path) {
        Ok(meta) if meta.len() > MAX_FILE_BYTES => return Err(AppError::state("devices_corrupt")),
        Ok(_) => fs::read(path).map_err(|e| AppError::io("devices_unreadable", &e))?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(DevicesFile::default()),
        Err(e) => return Err(AppError::io("devices_unreadable", &e)),
    };
    let file: DevicesFile =
        serde_json::from_slice(&bytes).map_err(|_| AppError::state("devices_corrupt"))?;
    Ok(file.cleaned())
}

pub fn save(path: &Path, file: &DevicesFile) -> Result<(), AppError> {
    let mut bytes =
        serde_json::to_vec_pretty(file).map_err(|_| AppError::internal("devices_encode"))?;
    bytes.push(b'\n');
    write_private_atomic(path, &bytes).map_err(|e| AppError::io("devices_unwritable", &e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::LinkDevice;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbb";
    const L1: &str = "llllllllllllllllllllllllll";
    const L2: &str = "mmmmmmmmmmmmmmmmmmmmmmmmmm";
    const OWN: &str = "oooooooooooooooooooooooooo";

    fn link(devices: &[(&str, u64, bool)]) -> LinkDevices {
        LinkDevices {
            self_id: Some(OWN.into()),
            devices: devices
                .iter()
                .map(|(id, at, active)| LinkDevice {
                    device_id: (*id).into(),
                    name: "x".into(),
                    created_at: serde_json::json!(at),
                    last_seen_at: serde_json::Value::Null,
                    online: true,
                    revoked_at: if *active {
                        serde_json::Value::Null
                    } else {
                        serde_json::json!(1)
                    },
                })
                .collect(),
        }
    }

    #[test]
    fn upsert_merges_environments_and_keeps_a_known_link_id() {
        let mut f = DevicesFile::default();
        f.upsert(A, Some(L1), "studio", &["demo/dev".into()], 10);
        f.upsert(A, None, "", &["demo/prod".into(), "bad env".into()], 20);
        let d = f.find(A).unwrap();
        assert_eq!(d.link_device_id.as_deref(), Some(L1));
        assert_eq!(d.name, "studio");
        assert_eq!(d.envs, ["demo/dev", "demo/prod"]);
        assert_eq!(d.added_at, 10);
        // the same link device later turns out to be another member: it moves
        f.upsert(B, Some(L1), "laptop", &[], 30);
        assert_eq!(f.find(A).unwrap().link_device_id, None);
        assert_eq!(f.find_link(L1).unwrap().fingerprint, B);
        f.upsert("NOT-A-FINGERPRINT", Some(L2), "x", &[], 1);
        assert_eq!(f.devices.len(), 2);
        f.remove(None, Some(L1));
        assert!(f.find(B).is_none());
    }

    #[test]
    fn a_link_id_is_inferred_only_when_unambiguous() {
        let mut f = DevicesFile::default();
        f.note_pairing(&["demo/dev".into()], "new mac", 1_000);
        f.upsert(A, None, "new mac", &["demo/dev".into()], 1_100);
        // the device enrolled long before the pairing is not a candidate
        assert!(!f.infer_link_ids(&link(&[(L1, 100, true)]), Some(OWN)));
        // two candidates: ambiguous
        assert!(!f.infer_link_ids(&link(&[(L1, 1_050, true), (L2, 1_060, true)]), Some(OWN)));
        // a revoked one does not count, and neither does this Mac
        assert!(f.infer_link_ids(
            &link(&[(L1, 1_050, true), (L2, 1_060, false), (OWN, 1_070, true)]),
            Some(OWN)
        ));
        assert_eq!(f.find(A).unwrap().link_device_id.as_deref(), Some(L1));
        // nothing left to infer
        assert!(!f.infer_link_ids(&link(&[(L2, 1_060, true)]), Some(OWN)));
        // two Macs without an ID: ambiguous whichever device appeared
        let mut g = DevicesFile::default();
        g.note_pairing(&["demo/dev".into()], "", 1_000);
        g.upsert(A, None, "", &[], 1_000);
        g.upsert(B, None, "", &[], 1_000);
        assert!(!g.infer_link_ids(&link(&[(L1, 1_050, true)]), Some(OWN)));
        // without a pairing note there is nothing to go by
        let mut h = DevicesFile::default();
        h.upsert(A, None, "", &[], 1_000);
        assert!(!h.infer_link_ids(&link(&[(L1, 1_050, true)]), Some(OWN)));
    }

    #[test]
    fn notes_are_bounded_and_name_the_new_mac() {
        let mut f = DevicesFile::default();
        for i in 0..20u64 {
            f.note_pairing(&[format!("demo/e{i}")], &format!("mac {i}"), 1_000 + i);
        }
        assert_eq!(f.pairings.len(), MAX_NOTES);
        assert_eq!(f.pairing_name("demo/e19"), Some("mac 19"));
        assert_eq!(f.pairing_name("demo/e0"), None);
        f.note_pairing(&[], "", 1_000 + NOTE_LIFETIME_S + 100);
        assert_eq!(f.pairings.len(), 1);
    }

    #[test]
    fn the_file_is_private_and_a_damaged_one_is_an_error() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.json");
        assert_eq!(load(&path).unwrap(), DevicesFile::default());
        let mut f = DevicesFile {
            self_fingerprint: Some(B.into()),
            ..DevicesFile::default()
        };
        f.upsert(A, Some(L1), "studio", &["demo/dev".into()], 5);
        save(&path, &f).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let back = load(&path).unwrap();
        assert_eq!(back.find(A), f.find(A));
        assert_eq!(back.self_fingerprint.as_deref(), Some(B));
        fs::write(&path, b"{not json").unwrap();
        assert_eq!(load(&path).unwrap_err().reason, "devices_corrupt");
        fs::write(&path, br#"{"devices":"many"}"#).unwrap();
        assert_eq!(load(&path).unwrap_err().reason, "devices_corrupt");
        fs::write(&path, br#"{"devices":[{"fingerprint":"short","envs":[]}]}"#).unwrap();
        assert!(load(&path).unwrap().devices.is_empty());
    }
}
