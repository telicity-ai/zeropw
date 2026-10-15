//! Recovery codes (docs/desktop-app.md §7 step 3): 120 bits from the OS CSPRNG written as six
//! groups of four RFC 4648 base32 characters, `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`. That canonical
//! text is the recovery passphrase handed to `init`. Whatever the user types later (lowercase,
//! spaces, missing hyphens) is canonicalized the same way before `recover`, so a written-down
//! code always matches. A typed passphrase that does not have the code's shape is passed on
//! unchanged.

use zeroize::Zeroizing;

use crate::error::AppError;
use crate::secret::SecretString;

pub const GROUPS: usize = 6;
pub const GROUP_LEN: usize = 4;
pub const CODE_CHARS: usize = GROUPS * GROUP_LEN;
pub const CODE_BITS: usize = CODE_CHARS * 5;
const CODE_BYTES: usize = CODE_BITS / 8;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const _: () = assert!(CODE_BITS == 120 && CODE_BYTES == 15);

/// A fresh code: the canonical passphrase and its six groups for display.
pub struct RecoveryCode {
    pub passphrase: SecretString,
    pub groups: Vec<String>,
}

pub fn generate() -> Result<RecoveryCode, AppError> {
    let mut bytes = Zeroizing::new([0u8; CODE_BYTES]);
    getrandom::getrandom(&mut bytes[..])
        .map_err(|_| AppError::unavailable("csprng_unavailable"))?;
    let chars = base32(&bytes);
    let groups: Vec<String> = chars
        .chunks(GROUP_LEN)
        .map(|g| String::from_utf8_lossy(g).into_owned())
        .collect();
    Ok(RecoveryCode {
        passphrase: SecretString::new(groups.join("-")),
        groups,
    })
}

/// RFC 4648 base32 of exactly 15 bytes (120 bits, no padding).
fn base32(bytes: &[u8; CODE_BYTES]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(CODE_CHARS));
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &byte in bytes {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize]);
        }
        acc &= (1 << bits) - 1;
    }
    debug_assert_eq!(bits, 0);
    out
}

/// The canonical form of `input` when it has a recovery code's shape (24 base32 characters
/// once spaces and hyphens are removed, any case); `None` otherwise.
pub fn normalize(input: &str) -> Option<SecretString> {
    let mut chars = Zeroizing::new(String::with_capacity(CODE_CHARS + GROUPS));
    let mut count = 0;
    for c in input.chars() {
        if c == '-' || c.is_whitespace() {
            continue;
        }
        let upper = c.to_ascii_uppercase();
        if !upper.is_ascii() || !ALPHABET.contains(&(upper as u8)) {
            return None;
        }
        if count == CODE_CHARS {
            return None;
        }
        if count > 0 && count % GROUP_LEN == 0 {
            chars.push('-');
        }
        chars.push(upper);
        count += 1;
    }
    (count == CODE_CHARS).then(|| SecretString::new(std::mem::take(&mut *chars)))
}

/// The passphrase to hand to the CLI: a code-shaped input in canonical form, anything else
/// exactly as typed.
pub fn canonical_passphrase(input: &SecretString) -> SecretString {
    normalize(input.expose()).unwrap_or_else(|| input.duplicate())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_codes_have_six_groups_of_four_base32_chars() {
        let code = generate().unwrap();
        assert_eq!(code.groups.len(), GROUPS);
        for group in &code.groups {
            assert_eq!(group.len(), GROUP_LEN);
            assert!(group.bytes().all(|b| ALPHABET.contains(&b)));
        }
        assert_eq!(code.passphrase.expose(), code.groups.join("-"));
        assert_eq!(code.passphrase.len(), 29);
        assert_ne!(
            generate().unwrap().passphrase.expose(),
            code.passphrase.expose()
        );
    }

    #[test]
    fn base32_matches_rfc4648_vectors() {
        // RFC 4648 §10: BASE32("foobar") = "MZXW6YTBOI======"; 15 bytes encode without padding.
        let mut bytes = [0u8; 15];
        bytes[..6].copy_from_slice(b"foobar");
        let out = base32(&bytes);
        assert!(out.starts_with(b"MZXW6YTBOI"));
        assert_eq!(out.len(), 24);
        assert_eq!(&*base32(&[0xff; 15]), "7".repeat(24).as_bytes());
        assert_eq!(&*base32(&[0; 15]), "A".repeat(24).as_bytes());
    }

    #[test]
    fn normalize_accepts_what_a_person_types() {
        let canonical = "ABCD-EFGH-IJKL-MNOP-QRST-UVW2";
        for typed in [
            canonical,
            "abcd-efgh-ijkl-mnop-qrst-uvw2",
            "ABCDEFGHIJKLMNOPQRSTUVW2",
            " abcd efgh ijkl\tmnop qrst uvw2 ",
            "AB-CDEF-GHIJ-KLMN-OPQR-STUV-W2",
        ] {
            assert_eq!(normalize(typed).unwrap().expose(), canonical, "{typed}");
        }
        for not_a_code in [
            "ABCD-EFGH-IJKL-MNOP-QRST-UVW",
            "ABCD-EFGH-IJKL-MNOP-QRST-UVW2X",
            "ABCD-EFGH-IJKL-MNOP-QRST-UVW1",
            "correct horse battery staple",
            "ÄBCD-EFGH-IJKL-MNOP-QRST-UVW2",
        ] {
            assert!(normalize(not_a_code).is_none(), "{not_a_code}");
        }
        let typed: SecretString = "my own Recovery phrase 9".into();
        assert_eq!(
            canonical_passphrase(&typed).expose(),
            "my own Recovery phrase 9"
        );
        let code: SecretString = "abcdefghijklmnopqrstuvw2".into();
        assert_eq!(canonical_passphrase(&code).expose(), canonical);
    }
}
