//! CPython 3.12's built-in IDNA 2003 encoder.
//!
//! `encodings.idna` uses RFC 3490/3491, the RFC 3454 Unicode 3.2 tables,
//! `AllowUnassigned=true`, NFKC, and RFC 3492 Punycode.  This differs from
//! modern UTS #46/IDNA 2008 implementations for code points assigned after
//! Unicode 3.2, so SMTP host conversion uses this module rather than `idna`.

use stringprep::tables;
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UnicodeError;

/// Equivalent to `hostname.encode("idna").decode("ascii")`.
pub(crate) fn encode(hostname: &str) -> Result<String, UnicodeError> {
    if hostname.is_empty() {
        return Ok(String::new());
    }
    if hostname.is_ascii() {
        validate_labels(hostname)?;
        return Ok(hostname.to_owned());
    }

    let trailing_dot = hostname.chars().last().is_some_and(is_idna_dot);
    let mut labels: Vec<&str> = hostname.split(is_idna_dot).collect();
    if trailing_dot {
        labels.pop();
    }
    let mut output = String::new();
    for label in labels {
        if !output.is_empty() {
            output.push('.');
        }
        output.push_str(&to_ascii(label)?);
    }
    if trailing_dot {
        output.push('.');
    }
    Ok(output)
}

fn is_idna_dot(c: char) -> bool {
    matches!(c, '.' | '\u{3002}' | '\u{ff0e}' | '\u{ff61}')
}

fn validate_labels(hostname: &str) -> Result<(), UnicodeError> {
    let labels: Vec<_> = hostname.split('.').collect();
    if labels
        .iter()
        .take(labels.len().saturating_sub(1))
        .any(|label| label.is_empty() || label.len() >= 64)
        || labels.last().is_some_and(|label| label.len() >= 64)
    {
        return Err(UnicodeError);
    }
    Ok(())
}

fn to_ascii(label: &str) -> Result<String, UnicodeError> {
    if label.is_ascii() {
        return valid_label(label.to_owned());
    }
    let label = nameprep(label)?;
    if label.is_ascii() {
        return valid_label(label);
    }
    if label.starts_with("xn--") {
        return Err(UnicodeError);
    }
    let encoded = punycode::encode(&label).map_err(|_| UnicodeError)?;
    valid_label(format!("xn--{encoded}"))
}

fn valid_label(label: String) -> Result<String, UnicodeError> {
    if label.is_empty() || label.len() >= 64 {
        Err(UnicodeError)
    } else {
        Ok(label)
    }
}

fn nameprep(label: &str) -> Result<String, UnicodeError> {
    let mapped: Vec<char> = label
        .chars()
        .filter(|&c| !tables::commonly_mapped_to_nothing(c))
        .flat_map(tables::case_fold_for_nfkc)
        .collect();
    let normalized = nfkc_unicode_3_2_allow_unassigned(&mapped);

    if normalized.chars().any(prohibited) || prohibited_bidirectional_text(&normalized) {
        return Err(UnicodeError);
    }
    Ok(normalized)
}

/// Unicode normalization is stable for characters assigned in Unicode 3.2.
/// CPython's `AllowUnassigned=true` profile treats every RFC 3454 A.1 code
/// point as having no mapping and canonical-combining-class zero. Preserve
/// each such point and normalize the assigned runs on either side separately.
fn nfkc_unicode_3_2_allow_unassigned(mapped: &[char]) -> String {
    let mut output = String::new();
    let mut assigned = String::new();
    for &c in mapped {
        if tables::unassigned_code_point(c) {
            output.extend(assigned.nfkc());
            assigned.clear();
            output.push(c);
        } else {
            // Unicode Corrigendum #4 changed these five canonical
            // decompositions in 4.0. CPython's `ucd_3_2_0` intentionally
            // retains the original mappings, so pre-map them before using
            // the current normalization implementation.
            assigned.push(match c {
                '\u{2f868}' => '\u{2136a}',
                '\u{2f874}' => '\u{5f33}',
                '\u{2f91f}' => '\u{43ab}',
                '\u{2f95f}' => '\u{7aae}',
                '\u{2f9bf}' => '\u{4d57}',
                _ => c,
            });
        }
    }
    output.extend(assigned.nfkc());
    output
}

fn prohibited(c: char) -> bool {
    tables::non_ascii_space_character(c)
        || tables::non_ascii_control_character(c)
        || tables::private_use(c)
        || tables::non_character_code_point(c)
        || tables::surrogate_code(c)
        || tables::inappropriate_for_plain_text(c)
        || tables::inappropriate_for_canonical_representation(c)
        || tables::change_display_properties_or_deprecated(c)
        || tables::tagging_character(c)
}

fn prohibited_bidirectional_text(value: &str) -> bool {
    if !value.chars().any(bidi_r_or_al_3_2) {
        return false;
    }
    value.chars().any(bidi_l_3_2)
        || !value.chars().next().is_some_and(bidi_r_or_al_3_2)
        || !value.chars().next_back().is_some_and(bidi_r_or_al_3_2)
}

fn in_ranges(c: char, ranges: &[(u32, u32)]) -> bool {
    let c = c as u32;
    ranges
        .binary_search_by(|&(start, end)| {
            if end < c {
                std::cmp::Ordering::Less
            } else if start > c {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// RFC 3454 table D.1, fixed to Unicode 3.2.
fn bidi_r_or_al_3_2(c: char) -> bool {
    const D1: &[(u32, u32)] = &[
        (0x05be, 0x05be),
        (0x05c0, 0x05c0),
        (0x05c3, 0x05c3),
        (0x05d0, 0x05ea),
        (0x05f0, 0x05f4),
        (0x061b, 0x061b),
        (0x061f, 0x061f),
        (0x0621, 0x063a),
        (0x0640, 0x064a),
        (0x066d, 0x066f),
        (0x0671, 0x06d5),
        (0x06dd, 0x06dd),
        (0x06e5, 0x06e6),
        (0x06fa, 0x06fe),
        (0x0700, 0x070d),
        (0x0710, 0x0710),
        (0x0712, 0x072c),
        (0x0780, 0x07a5),
        (0x07b1, 0x07b1),
        (0x200f, 0x200f),
        (0xfb1d, 0xfb1d),
        (0xfb1f, 0xfb28),
        (0xfb2a, 0xfb36),
        (0xfb38, 0xfb3c),
        (0xfb3e, 0xfb3e),
        (0xfb40, 0xfb41),
        (0xfb43, 0xfb44),
        (0xfb46, 0xfbb1),
        (0xfbd3, 0xfd3d),
        (0xfd50, 0xfd8f),
        (0xfd92, 0xfdc7),
        (0xfdf0, 0xfdfc),
        (0xfe70, 0xfe74),
        (0xfe76, 0xfefc),
    ];
    in_ranges(c, D1)
}

/// RFC 3454 table D.2, fixed to Unicode 3.2.  The ranges are copied from
/// the RFC rather than derived from the build host's Unicode database.
fn bidi_l_3_2(c: char) -> bool {
    const D2: &[(u32, u32)] = &[
        (0x0041, 0x005a),
        (0x0061, 0x007a),
        (0x00aa, 0x00aa),
        (0x00b5, 0x00b5),
        (0x00ba, 0x00ba),
        (0x00c0, 0x00d6),
        (0x00d8, 0x00f6),
        (0x00f8, 0x0220),
        (0x0222, 0x0233),
        (0x0250, 0x02ad),
        (0x02b0, 0x02b8),
        (0x02bb, 0x02c1),
        (0x02d0, 0x02d1),
        (0x02e0, 0x02e4),
        (0x02ee, 0x02ee),
        (0x037a, 0x037a),
        (0x0386, 0x0386),
        (0x0388, 0x038a),
        (0x038c, 0x038c),
        (0x038e, 0x03a1),
        (0x03a3, 0x03ce),
        (0x03d0, 0x03f5),
        (0x0400, 0x0482),
        (0x048a, 0x04ce),
        (0x04d0, 0x04f5),
        (0x04f8, 0x04f9),
        (0x0500, 0x050f),
        (0x0531, 0x0556),
        (0x0559, 0x055f),
        (0x0561, 0x0587),
        (0x0589, 0x0589),
        (0x0903, 0x0903),
        (0x0905, 0x0939),
        (0x093d, 0x0940),
        (0x0949, 0x094c),
        (0x0950, 0x0950),
        (0x0958, 0x0961),
        (0x0964, 0x0970),
        (0x0982, 0x0983),
        (0x0985, 0x098c),
        (0x098f, 0x0990),
        (0x0993, 0x09a8),
        (0x09aa, 0x09b0),
        (0x09b2, 0x09b2),
        (0x09b6, 0x09b9),
        (0x09be, 0x09c0),
        (0x09c7, 0x09c8),
        (0x09cb, 0x09cc),
        (0x09d7, 0x09d7),
        (0x09dc, 0x09dd),
        (0x09df, 0x09e1),
        (0x09e6, 0x09f1),
        (0x09f4, 0x09fa),
        (0x0a05, 0x0a0a),
        (0x0a0f, 0x0a10),
        (0x0a13, 0x0a28),
        (0x0a2a, 0x0a30),
        (0x0a32, 0x0a33),
        (0x0a35, 0x0a36),
        (0x0a38, 0x0a39),
        (0x0a3e, 0x0a40),
        (0x0a59, 0x0a5c),
        (0x0a5e, 0x0a5e),
        (0x0a66, 0x0a6f),
        (0x0a72, 0x0a74),
        (0x0a83, 0x0a83),
        (0x0a85, 0x0a8b),
        (0x0a8d, 0x0a8d),
        (0x0a8f, 0x0a91),
        (0x0a93, 0x0aa8),
        (0x0aaa, 0x0ab0),
        (0x0ab2, 0x0ab3),
        (0x0ab5, 0x0ab9),
        (0x0abd, 0x0ac0),
        (0x0ac9, 0x0ac9),
        (0x0acb, 0x0acc),
        (0x0ad0, 0x0ad0),
        (0x0ae0, 0x0ae0),
        (0x0ae6, 0x0aef),
        (0x0b02, 0x0b03),
        (0x0b05, 0x0b0c),
        (0x0b0f, 0x0b10),
        (0x0b13, 0x0b28),
        (0x0b2a, 0x0b30),
        (0x0b32, 0x0b33),
        (0x0b36, 0x0b39),
        (0x0b3d, 0x0b3e),
        (0x0b40, 0x0b40),
        (0x0b47, 0x0b48),
        (0x0b4b, 0x0b4c),
        (0x0b57, 0x0b57),
        (0x0b5c, 0x0b5d),
        (0x0b5f, 0x0b61),
        (0x0b66, 0x0b70),
        (0x0b83, 0x0b83),
        (0x0b85, 0x0b8a),
        (0x0b8e, 0x0b90),
        (0x0b92, 0x0b95),
        (0x0b99, 0x0b9a),
        (0x0b9c, 0x0b9c),
        (0x0b9e, 0x0b9f),
        (0x0ba3, 0x0ba4),
        (0x0ba8, 0x0baa),
        (0x0bae, 0x0bb5),
        (0x0bb7, 0x0bb9),
        (0x0bbe, 0x0bbf),
        (0x0bc1, 0x0bc2),
        (0x0bc6, 0x0bc8),
        (0x0bca, 0x0bcc),
        (0x0bd7, 0x0bd7),
        (0x0be7, 0x0bf2),
        (0x0c01, 0x0c03),
        (0x0c05, 0x0c0c),
        (0x0c0e, 0x0c10),
        (0x0c12, 0x0c28),
        (0x0c2a, 0x0c33),
        (0x0c35, 0x0c39),
        (0x0c41, 0x0c44),
        (0x0c60, 0x0c61),
        (0x0c66, 0x0c6f),
        (0x0c82, 0x0c83),
        (0x0c85, 0x0c8c),
        (0x0c8e, 0x0c90),
        (0x0c92, 0x0ca8),
        (0x0caa, 0x0cb3),
        (0x0cb5, 0x0cb9),
        (0x0cbe, 0x0cbe),
        (0x0cc0, 0x0cc4),
        (0x0cc7, 0x0cc8),
        (0x0cca, 0x0ccb),
        (0x0cd5, 0x0cd6),
        (0x0cde, 0x0cde),
        (0x0ce0, 0x0ce1),
        (0x0ce6, 0x0cef),
        (0x0d02, 0x0d03),
        (0x0d05, 0x0d0c),
        (0x0d0e, 0x0d10),
        (0x0d12, 0x0d28),
        (0x0d2a, 0x0d39),
        (0x0d3e, 0x0d40),
        (0x0d46, 0x0d48),
        (0x0d4a, 0x0d4c),
        (0x0d57, 0x0d57),
        (0x0d60, 0x0d61),
        (0x0d66, 0x0d6f),
        (0x0d82, 0x0d83),
        (0x0d85, 0x0d96),
        (0x0d9a, 0x0db1),
        (0x0db3, 0x0dbb),
        (0x0dbd, 0x0dbd),
        (0x0dc0, 0x0dc6),
        (0x0dcf, 0x0dd1),
        (0x0dd8, 0x0ddf),
        (0x0df2, 0x0df4),
        (0x0e01, 0x0e30),
        (0x0e32, 0x0e33),
        (0x0e40, 0x0e46),
        (0x0e4f, 0x0e5b),
        (0x0e81, 0x0e82),
        (0x0e84, 0x0e84),
        (0x0e87, 0x0e88),
        (0x0e8a, 0x0e8a),
        (0x0e8d, 0x0e8d),
        (0x0e94, 0x0e97),
        (0x0e99, 0x0e9f),
        (0x0ea1, 0x0ea3),
        (0x0ea5, 0x0ea5),
        (0x0ea7, 0x0ea7),
        (0x0eaa, 0x0eab),
        (0x0ead, 0x0eb0),
        (0x0eb2, 0x0eb3),
        (0x0ebd, 0x0ebd),
        (0x0ec0, 0x0ec4),
        (0x0ec6, 0x0ec6),
        (0x0ed0, 0x0ed9),
        (0x0edc, 0x0edd),
        (0x0f00, 0x0f17),
        (0x0f1a, 0x0f34),
        (0x0f36, 0x0f36),
        (0x0f38, 0x0f38),
        (0x0f3e, 0x0f47),
        (0x0f49, 0x0f6a),
        (0x0f7f, 0x0f7f),
        (0x0f85, 0x0f85),
        (0x0f88, 0x0f8b),
        (0x0fbe, 0x0fc5),
        (0x0fc7, 0x0fcc),
        (0x0fcf, 0x0fcf),
        (0x1000, 0x1021),
        (0x1023, 0x1027),
        (0x1029, 0x102a),
        (0x102c, 0x102c),
        (0x1031, 0x1031),
        (0x1038, 0x1038),
        (0x1040, 0x1057),
        (0x10a0, 0x10c5),
        (0x10d0, 0x10f8),
        (0x10fb, 0x10fb),
        (0x1100, 0x1159),
        (0x115f, 0x11a2),
        (0x11a8, 0x11f9),
        (0x1200, 0x1206),
        (0x1208, 0x1246),
        (0x1248, 0x1248),
        (0x124a, 0x124d),
        (0x1250, 0x1256),
        (0x1258, 0x1258),
        (0x125a, 0x125d),
        (0x1260, 0x1286),
        (0x1288, 0x1288),
        (0x128a, 0x128d),
        (0x1290, 0x12ae),
        (0x12b0, 0x12b0),
        (0x12b2, 0x12b5),
        (0x12b8, 0x12be),
        (0x12c0, 0x12c0),
        (0x12c2, 0x12c5),
        (0x12c8, 0x12ce),
        (0x12d0, 0x12d6),
        (0x12d8, 0x12ee),
        (0x12f0, 0x130e),
        (0x1310, 0x1310),
        (0x1312, 0x1315),
        (0x1318, 0x131e),
        (0x1320, 0x1346),
        (0x1348, 0x135a),
        (0x1361, 0x137c),
        (0x13a0, 0x13f4),
        (0x1401, 0x1676),
        (0x1681, 0x169a),
        (0x16a0, 0x16f0),
        (0x1700, 0x170c),
        (0x170e, 0x1711),
        (0x1720, 0x1731),
        (0x1735, 0x1736),
        (0x1740, 0x1751),
        (0x1760, 0x176c),
        (0x176e, 0x1770),
        (0x1780, 0x17b6),
        (0x17be, 0x17c5),
        (0x17c7, 0x17c8),
        (0x17d4, 0x17da),
        (0x17dc, 0x17dc),
        (0x17e0, 0x17e9),
        (0x1810, 0x1819),
        (0x1820, 0x1877),
        (0x1880, 0x18a8),
        (0x1e00, 0x1e9b),
        (0x1ea0, 0x1ef9),
        (0x1f00, 0x1f15),
        (0x1f18, 0x1f1d),
        (0x1f20, 0x1f45),
        (0x1f48, 0x1f4d),
        (0x1f50, 0x1f57),
        (0x1f59, 0x1f59),
        (0x1f5b, 0x1f5b),
        (0x1f5d, 0x1f5d),
        (0x1f5f, 0x1f7d),
        (0x1f80, 0x1fb4),
        (0x1fb6, 0x1fbc),
        (0x1fbe, 0x1fbe),
        (0x1fc2, 0x1fc4),
        (0x1fc6, 0x1fcc),
        (0x1fd0, 0x1fd3),
        (0x1fd6, 0x1fdb),
        (0x1fe0, 0x1fec),
        (0x1ff2, 0x1ff4),
        (0x1ff6, 0x1ffc),
        (0x200e, 0x200e),
        (0x2071, 0x2071),
        (0x207f, 0x207f),
        (0x2102, 0x2102),
        (0x2107, 0x2107),
        (0x210a, 0x2113),
        (0x2115, 0x2115),
        (0x2119, 0x211d),
        (0x2124, 0x2124),
        (0x2126, 0x2126),
        (0x2128, 0x2128),
        (0x212a, 0x212d),
        (0x212f, 0x2131),
        (0x2133, 0x2139),
        (0x213d, 0x213f),
        (0x2145, 0x2149),
        (0x2160, 0x2183),
        (0x2336, 0x237a),
        (0x2395, 0x2395),
        (0x249c, 0x24e9),
        (0x3005, 0x3007),
        (0x3021, 0x3029),
        (0x3031, 0x3035),
        (0x3038, 0x303c),
        (0x3041, 0x3096),
        (0x309d, 0x309f),
        (0x30a1, 0x30fa),
        (0x30fc, 0x30ff),
        (0x3105, 0x312c),
        (0x3131, 0x318e),
        (0x3190, 0x31b7),
        (0x31f0, 0x321c),
        (0x3220, 0x3243),
        (0x3260, 0x327b),
        (0x327f, 0x32b0),
        (0x32c0, 0x32cb),
        (0x32d0, 0x32fe),
        (0x3300, 0x3376),
        (0x337b, 0x33dd),
        (0x33e0, 0x33fe),
        (0x3400, 0x4db5),
        (0x4e00, 0x9fa5),
        (0xa000, 0xa48c),
        (0xac00, 0xd7a3),
        (0xd800, 0xfa2d),
        (0xfa30, 0xfa6a),
        (0xfb00, 0xfb06),
        (0xfb13, 0xfb17),
        (0xff21, 0xff3a),
        (0xff41, 0xff5a),
        (0xff66, 0xffbe),
        (0xffc2, 0xffc7),
        (0xffca, 0xffcf),
        (0xffd2, 0xffd7),
        (0xffda, 0xffdc),
        (0x10300, 0x1031e),
        (0x10320, 0x10323),
        (0x10330, 0x1034a),
        (0x10400, 0x10425),
        (0x10428, 0x1044d),
        (0x1d000, 0x1d0f5),
        (0x1d100, 0x1d126),
        (0x1d12a, 0x1d166),
        (0x1d16a, 0x1d172),
        (0x1d183, 0x1d184),
        (0x1d18c, 0x1d1a9),
        (0x1d1ae, 0x1d1dd),
        (0x1d400, 0x1d454),
        (0x1d456, 0x1d49c),
        (0x1d49e, 0x1d49f),
        (0x1d4a2, 0x1d4a2),
        (0x1d4a5, 0x1d4a6),
        (0x1d4a9, 0x1d4ac),
        (0x1d4ae, 0x1d4b9),
        (0x1d4bb, 0x1d4bb),
        (0x1d4bd, 0x1d4c0),
        (0x1d4c2, 0x1d4c3),
        (0x1d4c5, 0x1d505),
        (0x1d507, 0x1d50a),
        (0x1d50d, 0x1d514),
        (0x1d516, 0x1d51c),
        (0x1d51e, 0x1d539),
        (0x1d53b, 0x1d53e),
        (0x1d540, 0x1d544),
        (0x1d546, 0x1d546),
        (0x1d54a, 0x1d550),
        (0x1d552, 0x1d6a3),
        (0x1d6a8, 0x1d7c9),
        (0x20000, 0x2a6d6),
        (0x2f800, 0x2fa1d),
        (0xf0000, 0xffffd),
        (0x100000, 0x10fffd),
    ];
    in_ranges(c, D2)
}

#[cfg(test)]
mod tests {
    use super::encode;

    #[test]
    fn matches_cpython_idna2003_boundaries() {
        let cases = [
            "under_score.example".to_owned(),
            "faß.example".to_owned(),
            "join\u{200c}er.example".to_owned(),
            "join\u{200d}er.example".to_owned(),
            "empty..example".to_owned(),
            "trailing.example.".to_owned(),
            "unicode\u{3002}dot.example".to_owned(),
            "\u{1e9e}.example".to_owned(),
            "\u{1f600}.example".to_owned(),
            "\u{2f868}.example".to_owned(),
            "\u{2f874}.example".to_owned(),
            "\u{2f91f}.example".to_owned(),
            "\u{2f95f}.example".to_owned(),
            "\u{2f9bf}.example".to_owned(),
            "A\u{030a}.example".to_owned(),
            "\u{0130}.example".to_owned(),
            "\u{1e9e}\u{0301}.example".to_owned(),
            "\u{2f868}\u{0301}.example".to_owned(),
            "a\u{3000}.example".to_owned(),
            "a\u{e000}.example".to_owned(),
            "aא.example".to_owned(),
            "אaא.example".to_owned(),
            "א1א.example".to_owned(),
            "א\u{1e9e}א.example".to_owned(),
            "a\u{1e900}.example".to_owned(),
            format!("{}.example", "a".repeat(63)),
            format!("{}.example", "a".repeat(64)),
            format!("{}.example", "ü".repeat(57)),
            format!("{}.example", "ü".repeat(58)),
        ];
        let input = serde_json::to_string(&cases).unwrap();
        let script = format!(
            "import json\nout=[]\nfor value in json.loads({input:?}):\n try: out.append(['ok', value.encode('idna').decode('ascii')])\n except UnicodeError: out.append(['error', 'UnicodeError'])\nprint(json.dumps(out))"
        );
        let expected: Vec<(String, String)> =
            serde_json::from_str(crate::oracle::python(&script).trim()).unwrap();
        let actual: Vec<(String, String)> = cases
            .iter()
            .map(|value| match encode(value) {
                Ok(value) => ("ok".to_owned(), value),
                Err(_) => ("error".to_owned(), "UnicodeError".to_owned()),
            })
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn every_unicode_scalar_matches_cpython_by_chunk_digest() {
        use sha2::{Digest, Sha256};

        const CHUNK: u32 = 4096;
        let script = r#"
import hashlib, json
out=[]
for start in range(0, 0x110000, 4096):
 h=hashlib.sha256()
 for cp in range(start, min(start+4096, 0x110000)):
  if 0xD800 <= cp <= 0xDFFF:
   continue
  try:
   value=chr(cp).encode('idna')
  except UnicodeError:
   h.update(b'E')
  else:
   h.update(b'O');h.update(len(value).to_bytes(4,'big'));h.update(value)
 out.append(h.hexdigest())
print(json.dumps(out))
"#;
        let expected: Vec<String> =
            serde_json::from_str(crate::oracle::python(script).trim()).unwrap();
        let actual: Vec<String> = (0..0x11_0000u32)
            .step_by(CHUNK as usize)
            .map(|start| {
                let mut digest = Sha256::new();
                for cp in start..(start + CHUNK).min(0x11_0000) {
                    let Some(value) = char::from_u32(cp) else {
                        continue;
                    };
                    match encode(&value.to_string()) {
                        Ok(value) => {
                            digest.update(b"O");
                            digest.update((value.len() as u32).to_be_bytes());
                            digest.update(value.as_bytes());
                        }
                        Err(_) => digest.update(b"E"),
                    }
                }
                hex::encode(digest.finalize())
            })
            .collect();
        assert_eq!(
            actual, expected,
            "first unequal index identifies a 4096-codepoint chunk"
        );
    }
}
