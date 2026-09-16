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

use serde_json::{Map, Value};

use crate::crypto::chacha20poly1305 as aead;
use crate::errors::{Error, ErrorClass, Result};
use crate::pybase64;
use crate::pyjson::python_float_repr;
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
        map.insert(
            "nonce".into(),
            Value::String(pybase64::b64encode(&self.nonce)),
        );
        map.insert(
            "ciphertext".into(),
            Value::String(pybase64::b64encode(&self.ciphertext)),
        );
        Value::Object(map)
    }

    /// Port of `WrappedKey.from_dict`. Any missing field, wrong type or
    /// invalid base64 becomes `StateError("wrapped_key_malformed")`, exactly
    /// as Python maps `KeyError | TypeError | ValueError` there.
    ///
    /// `key_id` is coerced with Python's `str()`, not required to already be
    /// a JSON string: `str(123) == "123"`, `str(None) == "None"`,
    /// `str(1.5) == "1.5"`, `str(True) == "True"`. `nonce`/`ciphertext` are
    /// not coerced -- Python's `base64.b64decode` itself requires a `str` or
    /// bytes-like value (`TypeError` otherwise, caught the same way as a bad
    /// decode), so they must already be JSON strings. Base64 decoding uses
    /// [`pybase64::b64decode`], matching Python's lenient
    /// (`validate=False`) decoder (finding B-2): embedded whitespace,
    /// non-alphabet junk and irregular padding are tolerated rather than
    /// rejected.
    pub fn from_dict(value: &Value) -> Result<Self> {
        (|| -> Option<Self> {
            let obj = value.as_object()?;
            let key_id = python_str(obj.get("key_id")?);
            let nonce = pybase64::b64decode(obj.get("nonce")?.as_str()?).ok()?;
            let ciphertext = pybase64::b64decode(obj.get("ciphertext")?.as_str()?).ok()?;
            Some(WrappedKey {
                key_id,
                nonce,
                ciphertext,
            })
        })()
        .ok_or_else(|| Error::state("wrapped_key_malformed"))
    }
}

/// Port of Python's `str()` applied to a parsed JSON value, as
/// `WrappedKey.from_dict` does for `key_id` (`key_id=str(value["key_id"])`).
///
/// Scalars match Python exactly: a string passes through unchanged; an
/// integer's decimal digits (`Value::Number::as_str()` is already that,
/// since `pyjson` parses with `arbitrary_precision`); a float through
/// [`python_float_repr`] (`str(float)` and `repr(float)` are the same
/// function in Python); `true`/`false` as `"True"`/`"False"`; `null` as
/// `"None"`.
///
/// Arrays and objects fall back to [`python_repr`] (Python's `str()` of a
/// container is its `repr()`). See that function's doc comment for the two
/// known deviations recorded in `DEVIATIONS.md` (finding B-2): object key
/// order, and simplified string-escaping.
fn python_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Null => "None".to_string(),
        Value::Number(n) => {
            if n.is_f64() {
                python_float_repr(n.as_f64().unwrap_or(0.0))
            } else {
                n.as_str().to_string()
            }
        }
        Value::Array(_) | Value::Object(_) => python_repr(value),
    }
}

/// Python's `repr()` of a parsed JSON value, used by [`python_str`] for
/// arrays/objects (`str(list)`/`str(dict)` delegate to `repr`, and `repr` of
/// each element/value in turn).
///
/// Known deviations from CPython (finding B-2, `DEVIATIONS.md`): object keys
/// are emitted in sorted order rather than Python's insertion order (this
/// crate's `serde_json::Map` has no insertion-order feature available
/// offline -- the same limitation `pyjson.rs` already documents), and string
/// escaping only reproduces the common cases (backslash, the chosen quote
/// character, `\n`/`\r`/`\t`, and other C0 control bytes as `\xHH`) rather
/// than CPython's full `unicode_repr` (which also escapes non-printable
/// non-ASCII categories). Neither gap is reachable through this crate's own
/// `WrappedKey::to_dict`, which never emits `key_id` as anything but a
/// string.
fn python_repr(value: &Value) -> String {
    match value {
        Value::String(s) => python_str_repr(s),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(python_repr).collect();
            format!("[{}]", parts.join(", "))
        }
        Value::Object(map) => {
            let parts: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{}: {}", python_str_repr(k), python_repr(v)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
        other => python_str(other),
    }
}

/// `repr(str)`: single-quoted unless the string contains a `'` and no `"`,
/// in which case double-quoted (CPython's `unicode_repr` quote choice).
fn python_str_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
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

/// `key_id.encode("ascii")`, checked explicitly. Python performs this
/// implicitly at three call sites (`create`, `wrap`, `unwrap`) and lets a
/// non-ASCII `key_id` raise an *unwrapped* `UnicodeEncodeError` there (not a
/// `KmsError` -- see `DEVIATIONS.md` finding B-4 for the chosen `KmsError`
/// shape used here instead, and for `create`'s additional behavioural
/// difference: Python's failure happens after the file is already created
/// on disk (0 bytes, via `os.open(..., O_CREAT | O_EXCL)`), where this
/// checks first and writes nothing).
fn require_ascii_key_id(key_id: &str) -> Result<()> {
    if key_id.is_ascii() {
        Ok(())
    } else {
        Err(kms_error("kms_key_id_not_ascii", key_id.to_string()))
    }
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
        require_ascii_key_id(key_id)?;
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
        contents.extend_from_slice(pybase64::b64encode(master.expose()).as_bytes());
        contents.push(b'\n');
        file.write_all(&contents)
            .map_err(|e| kms_error("kms_create_failed", e.to_string()))?;

        LocalFileKms::new(path.to_path_buf(), key_id.to_string(), master)
    }

    /// `LocalFileKms::create` with Python's default `key_id`.
    pub fn create_default(path: &Path) -> Result<Self> {
        LocalFileKms::create(path, DEFAULT_KEY_ID)
    }

    /// Port of `LocalFileKms.load`. Python's `raw.split(b"\n")[:2]` splits on
    /// every `\n` in the file and keeps the first two pieces -- equivalent
    /// to taking the first two elements of a 3-way `splitn` here, including
    /// leaving a trailing `\r` (from a CRLF line ending) attached to
    /// whichever piece it was in, since only `\n` is a separator. Decoding
    /// uses [`pybase64::b64decode_bytes`] (finding B-3): Python's decode
    /// here runs on raw file `bytes`, not a `str`, so unlike
    /// [`WrappedKey::from_dict`] there is no ASCII precheck, and it is
    /// lenient the same way (a trailing `\r`, embedded whitespace or excess
    /// padding on the master-key line is tolerated rather than rejected).
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
        let master_bytes = pybase64::b64decode_bytes(master_line)
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
        require_ascii_key_id(&self.key_id)?;
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
        require_ascii_key_id(&self.key_id)?;
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

    // --- B-2: WrappedKey.from_dict key_id coercion & lenient base64 -------

    #[test]
    fn from_dict_coerces_scalar_key_id_like_python_str() {
        let base = |key_id: Value| serde_json::json!({"key_id": key_id, "nonce": "AAAA", "ciphertext": "AAAA"});
        assert_eq!(
            WrappedKey::from_dict(&base(serde_json::json!(123)))
                .unwrap()
                .key_id,
            "123"
        );
        assert_eq!(
            WrappedKey::from_dict(&base(Value::Null)).unwrap().key_id,
            "None"
        );
        assert_eq!(
            WrappedKey::from_dict(&base(serde_json::json!(true)))
                .unwrap()
                .key_id,
            "True"
        );
        assert_eq!(
            WrappedKey::from_dict(&base(serde_json::json!(false)))
                .unwrap()
                .key_id,
            "False"
        );
        assert_eq!(
            WrappedKey::from_dict(&base(serde_json::json!(1.5)))
                .unwrap()
                .key_id,
            "1.5"
        );
        assert_eq!(
            WrappedKey::from_dict(&base(serde_json::json!(["x"])))
                .unwrap()
                .key_id,
            "['x']"
        );
    }

    /// Cross-checks [`python_str`]'s scalar coercion against
    /// `str(value["key_id"])` in the Python prototype for a spread of JSON
    /// scalar types, matching finding B-2's examples (`123 -> "123"`,
    /// `None -> "None"`, `["x"] -> "['x']"`).
    #[test]
    fn oracle_key_id_coercion_matches_python() {
        let cases = [
            serde_json::json!(123),
            serde_json::json!(-7),
            serde_json::json!(0),
            Value::Null,
            serde_json::json!(true),
            serde_json::json!(false),
            serde_json::json!(1.5),
            serde_json::json!(-0.25),
            serde_json::json!("already-a-string"),
            serde_json::json!(["x"]),
            serde_json::json!(["a", 1, null, true]),
            serde_json::json!({"a": 1, "b": "two"}),
        ];
        for case in cases {
            let rust = python_str(&case);
            let script = format!(
                "value = {}\nprint(str(value))",
                json_to_python_literal(&case)
            );
            let python = crate::oracle::python(&script);
            assert_eq!(rust, python.trim_end_matches('\n'), "mismatch for {case:?}");
        }
    }

    /// JSON -> Python literal for arbitrary (not just plain string-keyed)
    /// values, unlike [`python_dict_literal`] (which only needs to handle
    /// `WrappedKey.to_dict()`'s always-string values, where JSON and Python
    /// literal syntax coincide). Used only to build oracle test scripts.
    fn json_to_python_literal(value: &Value) -> String {
        match value {
            Value::Null => "None".to_string(),
            Value::Bool(true) => "True".to_string(),
            Value::Bool(false) => "False".to_string(),
            Value::Number(n) => n.to_string(),
            Value::String(s) => format!("{s:?}"), // Rust's Debug quoting is valid Python too
            Value::Array(items) => {
                let parts: Vec<String> = items.iter().map(json_to_python_literal).collect();
                format!("[{}]", parts.join(", "))
            }
            Value::Object(map) => {
                let parts: Vec<String> = map
                    .iter()
                    .map(|(k, v)| format!("{k:?}: {}", json_to_python_literal(v)))
                    .collect();
                format!("{{{}}}", parts.join(", "))
            }
        }
    }

    #[test]
    fn from_dict_lenient_base64_matches_finding_b2_examples() {
        // "AB==" (non-canonical trailing bits) and embedded junk/whitespace
        // that `base64` (strict) would reject but Python's default decoder
        // accepts.
        for nonce in ["AB==", "AA AA", "\nAAAA\n"] {
            let value = serde_json::json!({"key_id": "k1", "nonce": nonce, "ciphertext": "AAAA"});
            assert!(
                WrappedKey::from_dict(&value).is_ok(),
                "expected lenient accept for nonce={nonce:?}"
            );
        }
    }

    // --- B-3: LocalFileKms.load lenient base64 / CRLF -----------------------

    #[test]
    fn load_accepts_lenient_base64_and_crlf_like_python() {
        let dir = tempdir();
        let path = dir.path().join("lenient.key");
        // A master line with embedded whitespace, which `base64` (strict)
        // rejects but Python's `base64.b64decode` (non-strict) accepts by
        // skipping it -- as long as the *decoded* bytes still amount to a
        // valid 32-byte master key.
        let master = [0x11u8; MASTER_KEY_SIZE];
        let mut encoded = pybase64::b64encode(&master);
        // Splice a space into the middle of the encoded master key; the
        // lenient decoder must skip it and recover the same bytes.
        let mid = encoded.len() / 2;
        encoded.insert(mid, ' ');
        fs::write(&path, format!("lenient-kms\n{encoded}\n")).unwrap();

        let loaded = LocalFileKms::load(&path).unwrap();
        assert_eq!(loaded.key_id(), "lenient-kms");
    }

    #[test]
    fn load_crlf_key_id_line_keeps_trailing_cr_like_python() {
        // Python's `raw.split(b"\n")[:2]` only splits on `\n`, so a CRLF
        // line ending leaves the `\r` attached to the key_id piece --
        // reproduced here byte-for-byte (see `LocalFileKms::load`'s doc
        // comment) rather than trimmed away.
        let dir = tempdir();
        let path = dir.path().join("crlf.key");
        let master = [0x22u8; MASTER_KEY_SIZE];
        let encoded = pybase64::b64encode(&master);
        fs::write(&path, format!("crlf-kms\r\n{encoded}\n")).unwrap();

        let loaded = LocalFileKms::load(&path).unwrap();
        assert_eq!(loaded.key_id(), "crlf-kms\r");
    }

    /// Oracle differential: a KMS file with a master line containing
    /// embedded whitespace and excess padding, written directly (not via
    /// `create`), must load identically in both implementations.
    #[test]
    fn oracle_load_lenient_base64_matches_python() {
        let dir = tempdir();
        let path = dir.path().join("oracle-lenient.key");
        let master = [0x33u8; MASTER_KEY_SIZE];
        let mut encoded = pybase64::b64encode(&master);
        encoded.push_str("=="); // excess padding, tolerated non-strictly
        fs::write(&path, format!("oracle-kms\n{encoded}\n")).unwrap();

        let loaded = LocalFileKms::load(&path).unwrap();
        assert_eq!(loaded.key_id(), "oracle-kms");

        let script = format!(
            "from pathlib import Path\n\
             from zeropw.kms import LocalFileKms\n\
             kms = LocalFileKms.load(Path({path:?}))\n\
             print(kms.key_id)\n\
             print(kms._master.hex())",
            path = path,
        );
        let out = crate::oracle::python(&script);
        let mut lines = out.lines();
        assert_eq!(lines.next().unwrap(), "oracle-kms");
        assert_eq!(lines.next().unwrap(), hex::encode(master));
    }

    // --- B-4: non-ASCII key_id rejected up front ---------------------------

    #[test]
    fn create_rejects_non_ascii_key_id_without_writing_anything() {
        let dir = tempdir();
        let path = dir.path().join("sub").join("master.key");
        let err = LocalFileKms::create(&path, "caf\u{e9}").unwrap_err();
        assert_eq!(err.name, "KmsError");
        assert_eq!(err.reason, "kms_key_id_not_ascii");
        assert!(!path.exists(), "no file should be written");
        assert!(
            !path.parent().unwrap().exists(),
            "no directory should be created"
        );
    }

    #[test]
    fn wrap_rejects_non_ascii_key_id() {
        // Bypass `create`'s own check to build a KMS with a non-ASCII
        // key_id directly, the way Python's `__init__` allows (it never
        // validates ASCII itself -- only `create`/`wrap`/`unwrap` do).
        let bad =
            LocalFileKms::new("x.key", "caf\u{e9}", SecretBytes::from_slice(&[0u8; 32])).unwrap();
        let err = bad.wrap(b"data-key-32-bytes-aaaaaaaaaaaaaa").unwrap_err();
        assert_eq!(err.name, "KmsError");
        assert_eq!(err.reason, "kms_key_id_not_ascii");
    }

    #[test]
    fn unwrap_rejects_non_ascii_key_id_after_key_id_match() {
        let dir = tempdir();
        let master = SecretBytes::from_slice(&[0u8; 32]);
        let bad = LocalFileKms::new(dir.path().join("x.key"), "caf\u{e9}", master.clone()).unwrap();
        let wrapped = WrappedKey::new("caf\u{e9}", vec![0u8; aead::NONCE_SIZE], vec![0u8; 16]);
        let err = bad.unwrap(&wrapped).unwrap_err();
        assert_eq!(err.name, "KmsError");
        assert_eq!(err.reason, "kms_key_id_not_ascii");
    }
}
