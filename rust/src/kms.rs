//! Port of `zeropw/kms.py`: key-management abstraction with a local
//! development stand-in.
//!
//! The product design assumes a managed secret store and KMS. The prototype
//! keeps the same envelope structure: a random data-encryption key (DEK)
//! protects the vault, and the DEK is wrapped by a KMS. `LocalFileKms` stores
//! a master key in a 0600 file inside the trusted state directory. It is a
//! development stand-in only: it offers no hardware protection, no separate
//! KMS identity, and no cloud audit trail. Replace it with a managed KMS
//! wrapper before any real deployment; the `Kms` trait is the seam (Python's
//! `Kms` `Protocol`).

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Map, Value};

use crate::crypto::chacha20poly1305 as aead;
use crate::errors::{Error, ErrorClass, Result};
use crate::secret::SecretBytes;

/// `zeropw.kms.MASTER_KEY_SIZE`.
pub const MASTER_KEY_SIZE: usize = 32;

/// Default `key_id` used by `LocalFileKms::create` when the caller doesn't
/// give one, matching Python's `key_id: str = "local-dev-kms-1"` default.
pub const DEFAULT_KEY_ID: &str = "local-dev-kms-1";

/// Port of `zeropw.kms.WrappedKey`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedKey {
    pub key_id: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl WrappedKey {
    pub fn new(key_id: impl Into<String>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        WrappedKey {
            key_id: key_id.into(),
            nonce,
            ciphertext,
        }
    }

    /// Port of `WrappedKey.to_dict`.
    pub fn to_dict(&self) -> Value {
        let mut map = Map::new();
        map.insert("key_id".into(), Value::String(self.key_id.clone()));
        map.insert("nonce".into(), Value::String(BASE64.encode(&self.nonce)));
        map.insert(
            "ciphertext".into(),
            Value::String(BASE64.encode(&self.ciphertext)),
        );
        Value::Object(map)
    }

    /// Port of `WrappedKey.from_dict`. Any missing field, wrong type or
    /// invalid base64 becomes `StateError("wrapped_key_malformed")`, exactly
    /// as Python maps `KeyError | TypeError | ValueError` there.
    pub fn from_dict(value: &Value) -> Result<Self> {
        (|| -> Option<Self> {
            let obj = value.as_object()?;
            let key_id = obj.get("key_id")?.as_str()?.to_string();
            let nonce = BASE64.decode(obj.get("nonce")?.as_str()?).ok()?;
            let ciphertext = BASE64.decode(obj.get("ciphertext")?.as_str()?).ok()?;
            Some(WrappedKey {
                key_id,
                nonce,
                ciphertext,
            })
        })()
        .ok_or_else(|| Error::state("wrapped_key_malformed"))
    }
}

/// Port of `zeropw.kms.Kms` (a Python `Protocol`, i.e. structural interface).
pub trait Kms {
    fn key_id(&self) -> &str;
    fn wrap(&self, data_key: &[u8]) -> Result<WrappedKey>;
    /// Returns the unwrapped DEK as `SecretBytes` (PORTING.md §3.2: a DEK,
    /// like the seeds and master keys `secret.rs` names, is minted here and
    /// handed back already wrapped rather than as a naked `Vec<u8>`).
    fn unwrap(&self, wrapped: &WrappedKey) -> Result<SecretBytes>;
}

/// `KmsError(StateError)` in Python: same `ErrorClass::StateError`, but
/// `name` is `"KmsError"` rather than `"StateError"` (`type(exc).__name__`).
fn kms_error(reason: &'static str, detail: impl Into<String>) -> Error {
    Error::subclass(ErrorClass::StateError, "KmsError", reason, detail)
}

/// Port of `zeropw.kms.LocalFileKms`: development KMS with a master key in a
/// 0600 file. Not for production.
///
/// `Debug` is derived, not banned: `master`'s own `Debug` (`SecretBytes`) is
/// already redacted, so deriving here cannot leak the key (PORTING.md §3.2's
/// "no Debug leaks" is about not printing the raw bytes, not about banning
/// `Debug` on every struct that happens to hold a secret field).
#[derive(Debug)]
pub struct LocalFileKms {
    path: PathBuf,
    key_id: String,
    master: SecretBytes,
}

impl LocalFileKms {
    /// Port of `LocalFileKms.__init__`.
    pub fn new(
        path: impl Into<PathBuf>,
        key_id: impl Into<String>,
        master_key: SecretBytes,
    ) -> Result<Self> {
        if master_key.len() != MASTER_KEY_SIZE {
            return Err(kms_error("kms_master_key_size", ""));
        }
        Ok(LocalFileKms {
            path: path.into(),
            key_id: key_id.into(),
            master: master_key,
        })
    }

    /// Port of `LocalFileKms.create`, with `key_id` defaulting to
    /// `DEFAULT_KEY_ID` like Python's `key_id: str = "local-dev-kms-1"`.
    pub fn create(path: &Path, key_id: &str) -> Result<Self> {
        if path.exists() {
            return Err(kms_error("kms_exists", path.display().to_string()));
        }
        let mut master_bytes = [0u8; MASTER_KEY_SIZE];
        getrandom::getrandom(&mut master_bytes).expect("OS CSPRNG must be available");
        let master = SecretBytes::from_slice(&master_bytes);
        master_bytes.iter_mut().for_each(|b| *b = 0);

        ensure_dir_mode_0700(path.parent().unwrap_or_else(|| Path::new(".")))
            .map_err(|e| kms_error("kms_create_failed", e.to_string()))?;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| kms_error("kms_create_failed", e.to_string()))?;
        let mut contents = Vec::with_capacity(key_id.len() + 1 + 44 + 1);
        contents.extend_from_slice(key_id.as_bytes());
        contents.push(b'\n');
        contents.extend_from_slice(BASE64.encode(master.expose()).as_bytes());
        contents.push(b'\n');
        file.write_all(&contents)
            .map_err(|e| kms_error("kms_create_failed", e.to_string()))?;

        LocalFileKms::new(path.to_path_buf(), key_id.to_string(), master)
    }

    /// `LocalFileKms::create` with Python's default `key_id`.
    pub fn create_default(path: &Path) -> Result<Self> {
        LocalFileKms::create(path, DEFAULT_KEY_ID)
    }

    /// Port of `LocalFileKms.load`.
    pub fn load(path: &Path) -> Result<Self> {
        let raw =
            fs::read(path).map_err(|_| kms_error("kms_missing", path.display().to_string()))?;
        let mut parts = raw.splitn(3, |&b| b == b'\n');
        let key_id_line = parts
            .next()
            .ok_or_else(|| kms_error("kms_corrupt", path.display().to_string()))?;
        let master_line = parts
            .next()
            .ok_or_else(|| kms_error("kms_corrupt", path.display().to_string()))?;

        if !key_id_line.is_ascii() {
            return Err(kms_error("kms_corrupt", path.display().to_string()));
        }
        let key_id = String::from_utf8(key_id_line.to_vec())
            .map_err(|_| kms_error("kms_corrupt", path.display().to_string()))?;
        let master_bytes = BASE64
            .decode(master_line)
            .map_err(|_| kms_error("kms_corrupt", path.display().to_string()))?;

        LocalFileKms::new(path.to_path_buf(), key_id, SecretBytes::new(master_bytes))
    }
}

impl LocalFileKms {
    /// `LocalFileKms.path` (a public attribute in Python).
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Kms for LocalFileKms {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn wrap(&self, data_key: &[u8]) -> Result<WrappedKey> {
        let mut nonce = [0u8; aead::NONCE_SIZE];
        getrandom::getrandom(&mut nonce).expect("OS CSPRNG must be available");
        // Sizes are internally guaranteed (master validated at construction,
        // nonce always NONCE_SIZE), so encrypt cannot fail here in practice.
        let ciphertext = aead::encrypt(
            self.master.expose(),
            &nonce,
            data_key,
            self.key_id.as_bytes(),
        )
        .map_err(|e| kms_error("kms_wrap_failed", e.to_string()))?;
        Ok(WrappedKey::new(
            self.key_id.clone(),
            nonce.to_vec(),
            ciphertext,
        ))
    }

    fn unwrap(&self, wrapped: &WrappedKey) -> Result<SecretBytes> {
        if wrapped.key_id != self.key_id {
            return Err(kms_error("kms_key_id_mismatch", ""));
        }
        let plaintext = aead::decrypt(
            self.master.expose(),
            &wrapped.nonce,
            &wrapped.ciphertext,
            self.key_id.as_bytes(),
        )
        .map_err(|_| kms_error("kms_unwrap_failed", ""))?;
        Ok(SecretBytes::new(plaintext))
    }
}

/// `path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)`: Python's
/// pathlib applies `mode` only to the directory being created, not to any
/// missing ancestors created along the way (those get default permissions),
/// and does nothing (leaving existing permissions alone) if it already
/// exists. Mirrors that exactly rather than using a single recursive mkdir
/// with a uniform mode.
fn ensure_dir_mode_0700(dir: &Path) -> std::io::Result<()> {
    if dir.as_os_str().is_empty() || dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent()
        && !parent.as_os_str().is_empty()
        && !parent.is_dir()
    {
        fs::create_dir_all(parent)?;
    }
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && dir.is_dir() => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn to_dict_from_dict_round_trip() {
        let wrapped = WrappedKey::new("k1", vec![1, 2, 3], vec![4, 5, 6, 7]);
        let dict = wrapped.to_dict();
        assert_eq!(dict["key_id"], "k1");
        let back = WrappedKey::from_dict(&dict).unwrap();
        assert_eq!(back, wrapped);
    }

    #[test]
    fn from_dict_rejects_malformed() {
        assert!(WrappedKey::from_dict(&serde_json::json!({"key_id": "k1"})).is_err());
        assert!(
            WrappedKey::from_dict(
                &serde_json::json!({"key_id": "k1", "nonce": "not-base64!!", "ciphertext": "AA=="})
            )
            .is_err()
        );
        assert!(WrappedKey::from_dict(&serde_json::json!(null)).is_err());
    }

    #[test]
    fn create_then_load_round_trip() {
        let dir = tempdir();
        let path = dir.path().join("kms/master.key");
        let kms = LocalFileKms::create_default(&path).unwrap();
        assert_eq!(kms.key_id(), DEFAULT_KEY_ID);

        let loaded = LocalFileKms::load(&path).unwrap();
        assert_eq!(loaded.key_id(), DEFAULT_KEY_ID);

        let wrapped = kms.wrap(b"01234567890123456789012345678901").unwrap();
        let unwrapped = loaded.unwrap(&wrapped).unwrap();
        assert_eq!(unwrapped.expose(), b"01234567890123456789012345678901");
    }

    #[test]
    fn create_sets_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let path = dir.path().join("kms/master.key");
        LocalFileKms::create_default(&path).unwrap();
        let file_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
        let dir_mode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
    }

    #[test]
    fn create_rejects_existing_path() {
        let dir = tempdir();
        let path = dir.path().join("master.key");
        fs::write(&path, b"anything").unwrap();
        let err = LocalFileKms::create_default(&path).unwrap_err();
        assert_eq!(err.name, "KmsError");
        assert_eq!(err.reason, "kms_exists");
    }

    #[test]
    fn load_missing_file_is_kms_missing() {
        let dir = tempdir();
        let err = LocalFileKms::load(&dir.path().join("nope.key")).unwrap_err();
        assert_eq!(err.name, "KmsError");
        assert_eq!(err.reason, "kms_missing");
    }

    #[test]
    fn load_corrupt_file_is_kms_corrupt() {
        let dir = tempdir();
        let path = dir.path().join("bad.key");
        fs::write(&path, b"only-one-line-no-newline").unwrap();
        let err = LocalFileKms::load(&path).unwrap_err();
        assert_eq!(err.name, "KmsError");
        assert_eq!(err.reason, "kms_corrupt");

        fs::write(&path, b"key-id\nnot valid base64!!\n").unwrap();
        let err = LocalFileKms::load(&path).unwrap_err();
        assert_eq!(err.reason, "kms_corrupt");
    }

    #[test]
    fn new_rejects_wrong_master_key_size() {
        let err = LocalFileKms::new("x.key", "k1", SecretBytes::from_slice(b"short")).unwrap_err();
        assert_eq!(err.name, "KmsError");
        assert_eq!(err.reason, "kms_master_key_size");
    }

    #[test]
    fn unwrap_rejects_key_id_mismatch() {
        let dir = tempdir();
        let a = LocalFileKms::create(&dir.path().join("a.key"), "kms-a").unwrap();
        let b = LocalFileKms::create(&dir.path().join("b.key"), "kms-b").unwrap();
        let wrapped = a.wrap(b"data-key-32-bytes-aaaaaaaaaaaaaa").unwrap();
        let err = b.unwrap(&wrapped).unwrap_err();
        assert_eq!(err.name, "KmsError");
        assert_eq!(err.reason, "kms_key_id_mismatch");
    }

    /// Direct port of `test_kms_unwrap_rejects_other_master_key` in
    /// `tests/test_core_vault.py`: a KMS with the same `key_id` but a
    /// different (freshly generated) master key must still reject the
    /// wrapped DEK, since AEAD authentication -- not just the `key_id`
    /// field -- is what actually protects it.
    #[test]
    fn unwrap_rejects_other_master_key_with_same_key_id() {
        let dir = tempdir();
        let original = LocalFileKms::create(&dir.path().join("orig.key"), DEFAULT_KEY_ID).unwrap();
        let other = LocalFileKms::create(&dir.path().join("other.key"), DEFAULT_KEY_ID).unwrap();
        let wrapped = original.wrap(b"data-key-32-bytes-aaaaaaaaaaaaaa").unwrap();
        let err = other.unwrap(&wrapped).unwrap_err();
        assert_eq!(err.name, "KmsError");
        assert_eq!(err.reason, "kms_unwrap_failed");
    }

    #[test]
    fn key_id_used_as_associated_data() {
        // Swapping only the key_id on an otherwise-valid wrapped key must
        // break AEAD authentication (key_id is the AAD).
        let dir = tempdir();
        let kms = LocalFileKms::create(&dir.path().join("k.key"), "kms-a").unwrap();
        let mut wrapped = kms.wrap(b"data-key-32-bytes-aaaaaaaaaaaaaa").unwrap();
        wrapped.key_id = "kms-a-tampered".to_string();
        // key_id mismatch is checked first...
        assert_eq!(
            kms.unwrap(&wrapped).unwrap_err().reason,
            "kms_key_id_mismatch"
        );
    }

    #[test]
    fn python_created_kms_loads_and_unwraps_in_rust() {
        let dir = tempdir();
        let path = dir.path().join("py.key");
        let dek_hex = "30313233343536373839303132333435363738393031323334353637383930"; // "0123...90" 32 bytes
        let script = format!(
            "from pathlib import Path\n\
             from zeropw.kms import LocalFileKms\n\
             kms = LocalFileKms.create(Path({path:?}), key_id='oracle-kms')\n\
             wrapped = kms.wrap(bytes.fromhex('{dek}'))\n\
             import json\n\
             print(json.dumps(wrapped.to_dict()))",
            path = path,
            dek = dek_hex,
        );
        let out = crate::oracle::python(&script);
        let wrapped_json: Value = serde_json::from_str(out.trim()).unwrap();
        let wrapped = WrappedKey::from_dict(&wrapped_json).unwrap();

        let loaded = LocalFileKms::load(&path).unwrap();
        assert_eq!(loaded.key_id(), "oracle-kms");
        let dek = loaded.unwrap(&wrapped).unwrap();
        assert_eq!(hex::encode(dek.expose()), dek_hex);
    }

    #[test]
    fn rust_created_kms_loads_and_unwraps_in_python() {
        let dir = tempdir();
        let path = dir.path().join("rs.key");
        let kms = LocalFileKms::create(&path, "rust-oracle-kms").unwrap();
        let dek = b"rust-generated-dek-32-bytes-long";
        assert_eq!(dek.len(), 32);
        let wrapped = kms.wrap(dek).unwrap();
        let wrapped_dict = wrapped.to_dict();

        let script = format!(
            "from pathlib import Path\n\
             from zeropw.kms import LocalFileKms, WrappedKey\n\
             kms = LocalFileKms.load(Path({path:?}))\n\
             assert kms.key_id == 'rust-oracle-kms'\n\
             wrapped = WrappedKey.from_dict({dict})\n\
             print(kms.unwrap(wrapped).hex())",
            path = path,
            dict = python_dict_literal(&wrapped_dict),
        );
        let out = crate::oracle::python(&script);
        assert_eq!(out.trim(), hex::encode(dek));
    }

    fn python_dict_literal(value: &Value) -> String {
        // Minimal JSON -> Python literal: valid Python syntax for the plain
        // string-keyed, string-valued dict `to_dict()` produces.
        serde_json::to_string(value).expect("serialize")
    }
}
