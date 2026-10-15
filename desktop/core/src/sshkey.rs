//! `SecretSource::generate_ed25519`: a new Ed25519 key in the unencrypted OpenSSH private key
//! format (`openssh-key-v1`, what `ssh-keygen -t ed25519 -N ''` writes), which is what the
//! vault's `ssh_private_key` kind parses. The private key goes straight into the input
//! envelope; only the public key line and its fingerprint leave the core.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::AppError;
use crate::secret::SecretString;

const MAGIC: &[u8] = b"openssh-key-v1\0";
const KEY_TYPE: &str = "ssh-ed25519";
const BLOCK: usize = 8;
const LINE: usize = 70;

pub struct GeneratedKey {
    /// PEM text for the vault (never returned to the webview).
    pub private_pem: SecretString,
    /// `ssh-ed25519 AAAA… comment`
    pub public_line: String,
    /// `SHA256:…` as `ssh-keygen -l` prints it.
    pub fingerprint: String,
}

/// Generate a key with a comment derived from `label` (unsafe characters become `_`).
pub fn generate_ed25519(label: &str) -> Result<GeneratedKey, AppError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut seed[..]).map_err(|_| AppError::unavailable("csprng_unavailable"))?;
    let mut check = [0u8; 4];
    getrandom::getrandom(&mut check).map_err(|_| AppError::unavailable("csprng_unavailable"))?;
    Ok(from_seed(
        &seed,
        u32::from_be_bytes(check),
        &comment_for(label),
    ))
}

fn comment_for(label: &str) -> String {
    let cleaned: String = label
        .chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "zeropw".to_owned()
    } else {
        format!("zeropw-{cleaned}")
    }
}

pub(crate) fn from_seed(seed: &[u8; 32], check: u32, comment: &str) -> GeneratedKey {
    let signing = SigningKey::from_bytes(seed);
    let public = signing.verifying_key().to_bytes();
    let blob = public_blob(&public);

    // Private section: checkint ×2, key type, public key, seed‖public, comment, padding.
    let mut section = Zeroizing::new(Vec::with_capacity(256));
    put_u32(&mut section, check);
    put_u32(&mut section, check);
    put_string(&mut section, KEY_TYPE.as_bytes());
    put_string(&mut section, &public);
    {
        let mut private = Zeroizing::new([0u8; 64]);
        private[..32].copy_from_slice(seed);
        private[32..].copy_from_slice(&public);
        put_string(&mut section, &private[..]);
    }
    put_string(&mut section, comment.as_bytes());
    let mut pad = 1u8;
    while section.len() % BLOCK != 0 {
        section.push(pad);
        pad += 1;
    }

    let mut container = Zeroizing::new(Vec::with_capacity(section.len() + blob.len() + 128));
    container.extend_from_slice(MAGIC);
    put_string(&mut container, b"none");
    put_string(&mut container, b"none");
    put_string(&mut container, b"");
    put_u32(&mut container, 1);
    put_string(&mut container, &blob);
    put_string(&mut container, &section);

    let mut encoded = Zeroizing::new(String::with_capacity(container.len().div_ceil(3) * 4));
    STANDARD.encode_string(&*container, &mut encoded);
    let mut pem = String::with_capacity(encoded.len() + encoded.len() / LINE + 80);
    pem.push_str("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for line in encoded.as_bytes().chunks(LINE) {
        pem.push_str(std::str::from_utf8(line).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----\n");

    GeneratedKey {
        private_pem: SecretString::new(pem),
        public_line: format!("{KEY_TYPE} {} {comment}", STANDARD.encode(&blob)),
        fingerprint: fingerprint(&blob),
    }
}

/// `string "ssh-ed25519" || string public_key`
pub fn public_blob(public: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(51);
    put_string(&mut blob, KEY_TYPE.as_bytes());
    put_string(&mut blob, public);
    blob
}

pub fn fingerprint(blob: &[u8]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob)))
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// RFC 8032 §7.1 test 1 secret key and its public key.
    const SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const PUBLIC: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    fn decode(pem: &str) -> Vec<u8> {
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        STANDARD.decode(body).unwrap()
    }

    #[test]
    fn container_layout_matches_openssh_key_v1() {
        let key = from_seed(&SEED, 0x0102_0304, "zeropw-test");
        let pem = key.private_pem.expose();
        assert!(pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        assert!(pem.ends_with("-----END OPENSSH PRIVATE KEY-----\n"));
        assert!(pem.lines().all(|l| l.len() <= LINE));
        let raw = decode(pem);
        assert!(raw.starts_with(MAGIC));
        let blob = public_blob(&PUBLIC);
        let section_start = MAGIC.len() + 8 + 8 + 4 + 4 + 4 + blob.len() + 4;
        assert_eq!(
            &raw[section_start - 4 - blob.len() - 4..section_start - 4][4..],
            &blob[..]
        );
        let section = &raw[section_start..];
        assert_eq!(section.len() % BLOCK, 0);
        assert_eq!(&section[..8], &[1, 2, 3, 4, 1, 2, 3, 4]);
        // seed‖public appears in the private section.
        let mut private = SEED.to_vec();
        private.extend_from_slice(&PUBLIC);
        assert!(section.windows(64).any(|w| w == private.as_slice()));
        assert_eq!(
            key.public_line,
            format!("ssh-ed25519 {} zeropw-test", STANDARD.encode(&blob))
        );
        assert!(key.fingerprint.starts_with("SHA256:"));
        assert_eq!(key.fingerprint.len(), 7 + 43);
    }

    #[test]
    fn generated_keys_differ_and_comments_are_sanitized() {
        let a = generate_ed25519("deploy key").unwrap();
        let b = generate_ed25519("deploy key").unwrap();
        assert_ne!(a.fingerprint, b.fingerprint);
        assert!(a.public_line.ends_with(" zeropw-deploy_key"));
        assert!(
            generate_ed25519("")
                .unwrap()
                .public_line
                .ends_with(" zeropw")
        );
        assert!(!a.public_line.contains(a.private_pem.expose()));
    }

    /// When OpenSSH is installed, `ssh-keygen` must derive the same public key and fingerprint.
    #[test]
    fn ssh_keygen_accepts_the_key_when_available() {
        if Command::new("ssh-keygen").arg("-?").output().is_err() {
            eprintln!("ssh-keygen not installed; skipping");
            return;
        }
        let key = generate_ed25519("interop").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id");
        crate::paths::write_private_atomic(&path, key.private_pem.expose().as_bytes()).unwrap();
        let public = Command::new("ssh-keygen")
            .arg("-y")
            .arg("-f")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            public.status.success(),
            "{}",
            String::from_utf8_lossy(&public.stderr)
        );
        let derived = String::from_utf8(public.stdout).unwrap();
        let ours: Vec<&str> = key.public_line.split(' ').take(2).collect();
        assert!(derived.starts_with(&ours.join(" ")), "{derived}");
        let fp = Command::new("ssh-keygen")
            .arg("-l")
            .arg("-f")
            .arg(&path)
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&fp.stdout).contains(&key.fingerprint));
    }
}
