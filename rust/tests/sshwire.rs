//! Port of `tests/test_sshwire.py`.
//!
//! Every test here is a direct behavioural port of the corresponding Python
//! `unittest` case; comments note the Python test name. Oracle differential
//! tests (which need `crate::oracle::python`, only reachable from inside the
//! crate under `#[cfg(test)]`) live in `rust/src/sshwire.rs` instead; see
//! that file's `mod tests` for the encode/decode/sign/verify equivalence
//! checks and the malformed-input table cross-checked against Python.
//!
//! Unlike the Python suite, there is no "fake" Ed25519 backend to patch in:
//! `zeropw::sshwire`'s adapter always talks to the real `ed25519_dalek`
//! crate (see the `ADAPTER` comment in `src/sshwire.rs`), and the Python
//! test suite's `REAL_ED25519` is also available in this checkout, so
//! `PrivateKeyFormatTests::test_sign_delegates_to_backend` (which asserted
//! equality with the *fake* backend's deterministic hash-based "signature")
//! has no Rust equivalent here; the real-backend equivalent lives in the
//! oracle tests instead.

use std::io::{Cursor, Read, Write};
use std::os::unix::net::UnixStream;

use zeropw::sshwire as w;
use zeropw::sshwire::{
    AgentConnection, AgentError, Ed25519PrivateKey, Ed25519PublicKey, MpInt, Reader, SessionBind,
    SignRequest, UserAuthRequest, WireError,
};

// ---------------------------------------------------------------------------
// Wire primitives (EncodeTests)
// ---------------------------------------------------------------------------

#[test]
fn test_uint32() {
    assert_eq!(w::encode_uint32(0), [0, 0, 0, 0]);
    assert_eq!(w::encode_uint32(0xDEADBEEF), [0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(w::encode_uint32(0xFFFFFFFF), [0xff, 0xff, 0xff, 0xff]);
    // Python also checks that -1 and 2**32 raise ValueError; the `u32`
    // argument type makes both unrepresentable at compile time instead
    // (DEVIATIONS.md).
}

#[test]
fn test_string() {
    assert_eq!(w::encode_string(b"" as &[u8]).unwrap(), b"\x00\x00\x00\x00");
    assert_eq!(
        w::encode_string(b"abc" as &[u8]).unwrap(),
        b"\x00\x00\x00\x03abc"
    );
    assert_eq!(
        w::encode_string("ssh-ed25519").unwrap(),
        b"\x00\x00\x00\x0bssh-ed25519"
    );
    assert_eq!(
        w::encode_string(vec![b'x', b'y']).unwrap(),
        b"\x00\x00\x00\x02xy"
    );
    assert_eq!(w::encode_string("é").unwrap(), b"\x00\x00\x00\x02\xc3\xa9");
    // Python also checks that encode_string(5) raises TypeError; the
    // `AsRef<[u8]>` bound makes that a compile error instead.
}

#[test]
fn test_bool() {
    assert_eq!(w::encode_bool(true), [1]);
    assert_eq!(w::encode_bool(false), [0]);
}

#[test]
fn test_mpint_rfc4251_vectors() {
    let enc = |n: i64| w::encode_mpint(&MpInt::from_i64(n));
    assert_eq!(enc(0), hex::decode("00000000").unwrap());
    assert_eq!(
        enc(0x9A378F9B2E332A7),
        hex::decode("0000000809a378f9b2e332a7").unwrap()
    );
    assert_eq!(enc(0x80), hex::decode("000000020080").unwrap());
    assert_eq!(enc(0x7F), hex::decode("000000017f").unwrap());
    assert_eq!(enc(0x100), hex::decode("000000020100").unwrap());
    assert_eq!(enc(-0x1234), hex::decode("00000002edcc").unwrap());
    assert_eq!(
        enc(-0xDEADBEEFi64),
        hex::decode("00000005ff21524111").unwrap()
    );
}

#[test]
fn test_mpint_negative_minimal_encoding() {
    let enc = |n: i64| w::encode_mpint(&MpInt::from_i64(n));
    assert_eq!(enc(-1), hex::decode("00000001ff").unwrap());
    assert_eq!(enc(-0x7F), hex::decode("0000000181").unwrap());
    assert_eq!(enc(-0x80), hex::decode("0000000180").unwrap());
    assert_eq!(enc(-0x81), hex::decode("00000002ff7f").unwrap());
    assert_eq!(enc(-0x100), hex::decode("00000002ff00").unwrap());
    // -(2**255) and -(2**256) don't fit i64; covered by the oracle test
    // `mpint_round_trip_matches_python_for_large_values` in src/sshwire.rs.
}

#[test]
fn test_mpint_round_trip() {
    let values: Vec<i64> = vec![0, 1, 0x7F, 0x80, 0xFF, 0x100];
    let mut all = values.clone();
    all.extend(values.iter().map(|v| -v));
    all.extend([-0x80, -0x81]);
    for value in all {
        let encoded = w::encode_mpint(&MpInt::from_i64(value));
        let mut r = Reader::new(&encoded);
        let decoded = r.mpint().unwrap();
        assert_eq!(decoded, MpInt::from_i64(value), "value={value}");
    }
    for value in -600i64..600 {
        let encoded = w::encode_mpint(&MpInt::from_i64(value));
        let mut r = Reader::new(&encoded);
        assert_eq!(r.mpint().unwrap(), MpInt::from_i64(value));
    }
}

// ---------------------------------------------------------------------------
// ReaderTests
// ---------------------------------------------------------------------------

#[test]
fn test_sequential_reads_and_eof() {
    let mut buf = w::encode_string(b"hello" as &[u8]).unwrap();
    buf.extend(w::encode_uint32(7));
    buf.push(1);
    buf.push(0x2a);
    let mut r = Reader::new(&buf);
    assert_eq!(r.remaining(), buf.len());
    assert!(!r.eof());
    assert_eq!(r.string().unwrap(), b"hello");
    assert_eq!(r.uint32().unwrap(), 7);
    assert!(r.boolean().unwrap());
    assert_eq!(r.byte().unwrap(), 0x2A);
    assert!(r.eof());
    assert_eq!(r.remaining(), 0);
    r.expect_eof("message").unwrap();
    assert_eq!(r.rest(), Vec::<u8>::new());
}

#[test]
fn test_truncated_string_raises() {
    assert!(Reader::new(b"\x00\x00\x00\x05abc").string().is_err());
    assert!(Reader::new(b"\x00\x00\x00").string().is_err());
    assert!(Reader::new(b"").string().is_err());
}

#[test]
fn test_truncated_primitives_raise() {
    assert!(Reader::new(b"\x00\x00\x00").uint32().is_err());
    assert!(Reader::new(b"").byte().is_err());
    assert!(Reader::new(b"").boolean().is_err());
    assert!(Reader::new(b"ab").raw(3).is_err());
}

#[test]
fn test_trailing_bytes_detected() {
    let mut buf = w::encode_string(b"x" as &[u8]).unwrap();
    buf.extend_from_slice(b"junk");
    let mut r = Reader::new(&buf);
    r.string().unwrap();
    assert!(!r.eof());
    assert_eq!(r.remaining(), 4);
    assert!(r.expect_eof("thing").is_err());
    assert_eq!(r.rest(), b"junk");
    assert!(r.eof());
}

#[test]
fn test_boolean_is_strict() {
    assert!(!Reader::new(b"\x00").boolean().unwrap());
    assert!(Reader::new(b"\x01").boolean().unwrap());
    for value in [b"\x02" as &[u8], b"\xff"] {
        assert!(Reader::new(value).boolean().is_err());
    }
}

#[test]
fn test_text_requires_utf8() {
    assert_eq!(
        Reader::new(&w::encode_string("héllo").unwrap())
            .text()
            .unwrap(),
        "héllo"
    );
    assert!(
        Reader::new(&w::encode_string(b"\xff\xfe" as &[u8]).unwrap())
            .text()
            .is_err()
    );
    assert_eq!(
        Reader::new(&w::encode_string(b"caf\xe9" as &[u8]).unwrap())
            .text_lossy()
            .unwrap(),
        "caf\u{fffd}"
    );
}

#[test]
fn test_mpint_strictness() {
    assert_eq!(
        Reader::new(&hex::decode("00000000").unwrap())
            .mpint()
            .unwrap(),
        MpInt::from_i64(0)
    );
    assert_eq!(
        Reader::new(&hex::decode("000000020080").unwrap())
            .mpint()
            .unwrap(),
        MpInt::from_i64(0x80)
    );
    assert_eq!(
        Reader::new(&hex::decode("0000000180").unwrap())
            .mpint()
            .unwrap(),
        MpInt::from_i64(-0x80)
    );
    assert_eq!(
        Reader::new(&hex::decode("00000001ff").unwrap())
            .mpint()
            .unwrap(),
        MpInt::from_i64(-1)
    );
    assert_eq!(
        Reader::new(&hex::decode("00000002ff7f").unwrap())
            .mpint()
            .unwrap(),
        MpInt::from_i64(-0x81)
    );
    assert_eq!(
        Reader::new(&hex::decode("00000002edcc").unwrap())
            .mpint()
            .unwrap(),
        MpInt::from_i64(-0x1234)
    );
    assert_eq!(
        Reader::new(&hex::decode("00000005ff21524111").unwrap())
            .mpint()
            .unwrap(),
        MpInt::from_i64(-0xDEADBEEFi64)
    );
    assert!(Reader::new(&hex::decode("00000002ff80").unwrap())
        .mpint()
        .is_err());
    assert!(Reader::new(&hex::decode("00000002ffff").unwrap())
        .mpint()
        .is_err());
    assert!(Reader::new(&hex::decode("00000002007f").unwrap())
        .mpint()
        .is_err());
    assert!(Reader::new(&hex::decode("0000000100").unwrap())
        .mpint()
        .is_err());
    assert!(Reader::new(&hex::decode("0000000401").unwrap())
        .mpint()
        .is_err());
}

// (bytearray/memoryview don't apply: Rust's `Reader` always borrows `&[u8]`.)

// ---------------------------------------------------------------------------
// Public keys, authorized_keys, signature blobs
// ---------------------------------------------------------------------------

fn pub_bytes() -> Vec<u8> {
    (0u8..32).collect()
}

#[test]
fn test_blob_round_trip() {
    let key = Ed25519PublicKey::new(pub_bytes()).unwrap();
    let blob = key.blob();
    let mut expected = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20".to_vec();
    expected.extend(pub_bytes());
    assert_eq!(blob, expected);
    assert_eq!(w::parse_public_key_blob(&blob).unwrap(), key);
    assert_eq!(Ed25519PublicKey::from_blob(&blob).unwrap(), key);
}

#[test]
fn test_length_validation() {
    assert!(Ed25519PublicKey::new(vec![0u8; 31]).is_err());
    assert!(Ed25519PublicKey::new(vec![0u8; 33]).is_err());
}

#[test]
fn test_blob_parse_rejections() {
    let mut blob = w::encode_string("ssh-rsa").unwrap();
    blob.extend(w::encode_string(b"\x01" as &[u8]).unwrap());
    blob.extend(w::encode_string(b"\x02" as &[u8]).unwrap());
    let err = w::parse_public_key_blob(&blob).unwrap_err();
    assert!(err.is_unsupported());

    let mut blob = w::encode_string("ssh-ed25519-cert-v01@openssh.com").unwrap();
    blob.extend(w::encode_string(pub_bytes()).unwrap());
    assert!(w::parse_public_key_blob(&blob)
        .unwrap_err()
        .is_unsupported());

    let mut blob = w::encode_string("ssh-ed25519").unwrap();
    blob.extend(w::encode_string(&pub_bytes()[..31]).unwrap());
    assert!(w::parse_public_key_blob(&blob).is_err());

    let mut blob = w::encode_string("ssh-ed25519").unwrap();
    blob.extend(w::encode_string(pub_bytes()).unwrap());
    blob.push(0);
    assert!(w::parse_public_key_blob(&blob).is_err());

    assert!(w::parse_public_key_blob(&w::encode_string("ssh-ed25519").unwrap()).is_err());
    assert!(w::parse_public_key_blob(b"").is_err());
}

#[test]
fn test_fingerprint_format() {
    let key = Ed25519PublicKey::new(pub_bytes()).unwrap();
    let fp = key.fingerprint();
    assert!(fp.starts_with("SHA256:"));
    assert!(!fp.contains('='));
    use sha2::{Digest, Sha256};
    assert_eq!(fp.len(), "SHA256:".len() + 43);
    let digest = Sha256::digest(key.blob());
    use base64::Engine;
    let want = base64::engine::general_purpose::STANDARD.encode(digest);
    assert_eq!(format!("SHA256:{}", want.trim_end_matches('=')), fp);
}

#[test]
fn test_authorized_key_line() {
    let key = Ed25519PublicKey::new(pub_bytes()).unwrap();
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(key.blob());
    assert_eq!(
        key.to_authorized_key("").unwrap(),
        format!("ssh-ed25519 {b64}")
    );
    assert_eq!(
        key.to_authorized_key("me@host").unwrap(),
        format!("ssh-ed25519 {b64} me@host")
    );
    for bad in ["a\nb", "a\rb", "a\x00b"] {
        assert!(key.to_authorized_key(bad).is_err());
    }
}

#[test]
fn test_frozen_and_hashable() {
    use std::collections::HashSet;
    let key = Ed25519PublicKey::new(pub_bytes()).unwrap();
    let mut set = HashSet::new();
    set.insert(key.clone());
    set.insert(Ed25519PublicKey::new(pub_bytes()).unwrap());
    assert_eq!(set.len(), 1);
    // `Ed25519PublicKey` has no public setters, so "assigning key_bytes"
    // (Python's frozen-dataclass check) has no Rust equivalent to test:
    // it is simply not expressible.
}

fn make_entry_fixture() -> (Ed25519PublicKey, String) {
    let key = Ed25519PublicKey::new(pub_bytes()).unwrap();
    let line = key.to_authorized_key("user@example").unwrap();
    (key, line)
}

#[test]
fn test_plain_line() {
    let (key, line) = make_entry_fixture();
    assert_eq!(w::parse_authorized_key(&line).unwrap(), key);
    let entry = w::parse_authorized_key_entry(&line).unwrap();
    assert_eq!(entry.options, "");
    assert_eq!(entry.key, key);
    assert_eq!(entry.comment, "user@example");
}

#[test]
fn test_line_without_comment_and_with_whitespace() {
    let (key, line) = make_entry_fixture();
    assert_eq!(
        w::parse_authorized_key(&key.to_authorized_key("").unwrap()).unwrap(),
        key
    );
    assert_eq!(
        w::parse_authorized_key(&format!("  {line}  \n")).unwrap(),
        key
    );
    let entry = w::parse_authorized_key_entry(&format!("{}\n", key.to_authorized_key("").unwrap()))
        .unwrap();
    assert_eq!(entry.comment, "");
}

#[test]
fn test_comment_with_spaces() {
    let (key, _) = make_entry_fixture();
    let entry =
        w::parse_authorized_key_entry(&key.to_authorized_key("a comment with  spaces").unwrap())
            .unwrap();
    assert_eq!(entry.comment, "a comment with  spaces");
}

#[test]
fn test_options_prefix() {
    let (key, line) = make_entry_fixture();
    let opts = r#"command="echo ssh-ed25519 \"fake\" AAAA",no-pty,from="10.0.0.0/8""#;
    let entry = w::parse_authorized_key_entry(&format!("{opts} {line}")).unwrap();
    assert_eq!(entry.options, opts);
    assert_eq!(entry.key, key);
    assert_eq!(entry.comment, "user@example");

    let entry =
        w::parse_authorized_key_entry(&format!("restrict\t{}", key.to_authorized_key("").unwrap()))
            .unwrap();
    assert_eq!(entry.options, "restrict");
    assert_eq!(entry.comment, "");
}

#[test]
fn test_other_key_types_unsupported() {
    for key_type in [
        "ssh-rsa",
        "ssh-dss",
        "ecdsa-sha2-nistp256",
        "sk-ssh-ed25519@openssh.com",
        "ssh-ed25519-cert-v01@openssh.com",
        "rsa-sha2-512",
        "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
        "x509v3-ssh-rsa",
        "x509v3-ecdsa-sha2-nistp256",
    ] {
        let line = format!("{key_type} AAAAB3NzaC1yc2EAAAADAQABAAAAgQ== c");
        assert!(
            w::parse_authorized_key(&line).unwrap_err().is_unsupported(),
            "{key_type}"
        );
        let line = format!(r#"command="x" {key_type} AAAAB3NzaC1yc2EAAAADAQABAAAAgQ== c"#);
        assert!(
            w::parse_authorized_key(&line).unwrap_err().is_unsupported(),
            "{key_type}"
        );
    }
}

#[test]
fn test_unknown_key_type_followed_by_blob_is_unsupported() {
    use base64::Engine;
    let mut inner = w::encode_string("future-alg@example.com").unwrap();
    inner.extend(w::encode_string(b"\x01" as &[u8]).unwrap());
    let blob = base64::engine::general_purpose::STANDARD.encode(inner);
    for line in [
        format!("future-alg@example.com {blob}"),
        format!("future-alg@example.com {blob} a comment"),
        format!(r#"command="x",restrict future-alg@example.com {blob} c"#),
        format!("restrict\tfuture-alg@example.com {blob}"),
    ] {
        let err = w::parse_authorized_key(&line).unwrap_err();
        assert!(err.is_unsupported(), "{line}");
        assert!(err.message().contains("future-alg@example.com"), "{line}");
    }
    for line in [
        "future-alg@example.com AAAA",
        "future-alg@example.com not*base64*",
        "garbage more",
    ] {
        let err = w::parse_authorized_key(line).unwrap_err();
        assert!(!err.is_unsupported(), "{line}");
    }
}

#[test]
fn test_multi_line_input_rejected() {
    let (key, line) = make_entry_fixture();
    for text in [
        format!("{line}\n{line}"),
        format!("{line}\r\n{line}\n"),
        format!("{line}\n# trailing comment"),
        format!("ssh-ed25519\n{}", line.split(' ').nth(1).unwrap()),
        format!("{line}\x00"),
    ] {
        assert!(w::parse_authorized_key(&text).is_err(), "{text:.24}");
    }
    assert_eq!(
        w::parse_authorized_key(&format!("{line}\r\n")).unwrap(),
        key
    );
    let entry = w::parse_authorized_key_entry(&format!("\n{line}\n")).unwrap();
    assert_eq!(entry.key.to_authorized_key(&entry.comment).unwrap(), line);
}

fn exotic_whitespace() -> Vec<(&'static str, char)> {
    vec![
        ("NBSP", '\u{a0}'),
        ("VT", '\u{b}'),
        ("FF", '\u{c}'),
        ("NEL", '\u{85}'),
        ("FS", '\u{1c}'),
        ("LINE SEPARATOR", '\u{2028}'),
        ("IDEOGRAPHIC SPACE", '\u{3000}'),
    ]
}

const REFUSED_BY_OPENSSH: [&str; 4] = [
    "between type and blob",
    "between blob and comment",
    "leading",
    "after options",
];
const IGNORED_BY_OPENSSH: [&str; 3] = ["inside comment", "trailing", "inside quoted option"];

fn exotic_lines(key: &Ed25519PublicKey, ws: char) -> Vec<(&'static str, String)> {
    let plain = key.to_authorized_key("").unwrap();
    let (typ, b64) = plain.split_once(' ').unwrap();
    vec![
        ("between type and blob", format!("{typ}{ws}{b64} c")),
        ("between blob and comment", format!("{typ} {b64}{ws}c")),
        ("leading", format!("{ws}{typ} {b64}")),
        ("after options", format!("command=\"x\"{ws}{typ} {b64}")),
        ("inside comment", format!("{typ} {b64} a{ws}b")),
        ("trailing", format!("{typ} {b64} c{ws}")),
        (
            "inside quoted option",
            format!("command=\"x{ws}y\" {typ} {b64}"),
        ),
        (
            "inside blob",
            format!("{typ} {}{ws}{}", &b64[..10], &b64[10..]),
        ),
    ]
}

#[test]
fn test_only_ascii_space_and_tab_separate_fields() {
    let key = Ed25519PublicKey::new(pub_bytes()).unwrap();
    let plain = key.to_authorized_key("").unwrap();
    let (typ, b64) = plain.split_once(' ').unwrap();
    for (name, ws) in exotic_whitespace() {
        assert!(
            ws.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&ws),
            "{name}"
        );
        for (where_, text) in exotic_lines(&key, ws) {
            let err = w::parse_authorized_key_entry(&text);
            assert!(err.is_err(), "{name} {where_}: {text:?}");
            assert!(!err.unwrap_err().is_unsupported(), "{name} {where_}");
        }
    }
    for (text, options, comment) in [
        (format!("{typ}\t{b64}\tc"), "", "c"),
        (format!(" \t{typ} \t {b64}\t c d \t\r\n"), "", "c d"),
        (format!("restrict\t{typ}\t{b64}"), "restrict", ""),
        (
            format!("command=\"a\tb\" {typ} {b64}\t"),
            "command=\"a\tb\"",
            "",
        ),
    ] {
        let entry = w::parse_authorized_key_entry(&text).unwrap();
        assert_eq!(entry.options, options, "{text:?}");
        assert_eq!(entry.key, key);
        assert_eq!(entry.comment, comment, "{text:?}");
    }
}

#[test]
fn test_exotic_whitespace_handling_agrees_with_ssh_keygen() {
    use std::process::Command;
    if Command::new("ssh-keygen").arg("-h").output().is_err() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }
    let key = Ed25519PublicKey::new(pub_bytes()).unwrap();
    let plain = key.to_authorized_key("").unwrap();
    let (typ, b64) = plain.split_once(' ').unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("line.pub");

    let ssh_keygen_accepts = |text: &str| -> bool {
        std::fs::write(&path, format!("{text}\n")).unwrap();
        Command::new("ssh-keygen")
            .args(["-l", "-f"])
            .arg(&path)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };

    for control in [
        format!("{typ} {b64} c"),
        format!("{typ}\t{b64}\tc"),
        format!("restrict\t{typ}\t{b64}"),
    ] {
        assert!(ssh_keygen_accepts(&control), "{control}");
        assert_eq!(w::parse_authorized_key(&control).unwrap(), key);
    }
    for (name, ws) in exotic_whitespace() {
        for (where_, text) in exotic_lines(&key, ws) {
            assert!(
                w::parse_authorized_key_entry(&text).is_err(),
                "{name} {where_}"
            );
            if REFUSED_BY_OPENSSH.contains(&where_) {
                assert!(!ssh_keygen_accepts(&text), "{name} {where_}: {text:?}");
            } else if IGNORED_BY_OPENSSH.contains(&where_) {
                assert!(ssh_keygen_accepts(&text), "{name} {where_}: {text:?}");
            }
        }
    }
}

#[test]
fn test_type_mismatch_between_line_and_blob() {
    use base64::Engine;
    let mut rsa_blob = w::encode_string("ssh-rsa").unwrap();
    rsa_blob.extend(w::encode_string(b"\x01\x00\x01" as &[u8]).unwrap());
    rsa_blob.extend(w::encode_string(b"\x05" as &[u8]).unwrap());
    let line = format!(
        "ssh-ed25519 {}",
        base64::engine::general_purpose::STANDARD.encode(rsa_blob)
    );
    assert!(w::parse_authorized_key(&line).is_err());
}

#[test]
fn test_malformed_lines() {
    for bad in [
        "",
        "   ",
        "# comment line",
        "ssh-ed25519",
        "ssh-ed25519 not*base64* c",
        "ssh-ed25519 AAAA c",
        r#"command="unterminated ssh-ed25519 AAAA"#,
        "garbage",
        "garbage more",
        "restrict",
    ] {
        assert!(w::parse_authorized_key(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn test_signature_round_trip() {
    let sig: Vec<u8> = (0u8..64).collect();
    let blob = w::encode_ssh_signature(&sig).unwrap();
    let mut expected = w::encode_string("ssh-ed25519").unwrap();
    expected.extend(w::encode_string(&sig).unwrap());
    assert_eq!(blob, expected);
    assert_eq!(w::parse_ssh_signature(&blob).unwrap(), sig);
}

#[test]
fn test_signature_rejections() {
    assert!(w::encode_ssh_signature(&[0u8; 63]).is_err());
    let mut blob = w::encode_string("rsa-sha2-256").unwrap();
    blob.extend(w::encode_string([0u8; 64]).unwrap());
    assert!(w::parse_ssh_signature(&blob).is_err());

    let mut blob = w::encode_string("ssh-ed25519").unwrap();
    blob.extend(w::encode_string([0u8; 65]).unwrap());
    assert!(w::parse_ssh_signature(&blob).is_err());

    let mut blob = w::encode_string("ssh-ed25519").unwrap();
    blob.extend(w::encode_string([0u8; 64]).unwrap());
    blob.push(0);
    assert!(w::parse_ssh_signature(&blob).is_err());

    let mut blob = w::encode_string("ssh-ed25519").unwrap();
    let mut sig_enc = w::encode_string([0u8; 64]).unwrap();
    sig_enc.pop();
    blob.extend(sig_enc);
    assert!(w::parse_ssh_signature(&blob).is_err());
}

// ---------------------------------------------------------------------------
// OpenSSH private key format (PrivateKeyFormatTests)
// ---------------------------------------------------------------------------

const MAGIC: &[u8] = b"openssh-key-v1\x00";
const BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const END: &str = "-----END OPENSSH PRIVATE KEY-----";

fn pem(blob: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(blob);
    let mut lines = vec![BEGIN.to_string()];
    let chars: Vec<char> = b64.chars().collect();
    for chunk in chars.chunks(70) {
        lines.push(chunk.iter().collect());
    }
    lines.push(END.to_string());
    lines.join("\n") + "\n"
}

#[allow(clippy::too_many_arguments)]
fn section(
    pub_: &[u8],
    seed: &[u8],
    comment: &[u8],
    check1: u32,
    check2: Option<u32>,
    key_type: &str,
    priv_: Option<&[u8]>,
    padding: Option<&[u8]>,
) -> Vec<u8> {
    let mut body = w::encode_uint32(check1).to_vec();
    body.extend(w::encode_uint32(check2.unwrap_or(check1)));
    body.extend(w::encode_string(key_type).unwrap());
    body.extend(w::encode_string(pub_).unwrap());
    let priv_owned;
    let priv_field: &[u8] = match priv_ {
        Some(p) => p,
        None => {
            let mut v = seed.to_vec();
            v.extend_from_slice(pub_);
            priv_owned = v;
            &priv_owned
        }
    };
    body.extend(w::encode_string(priv_field).unwrap());
    body.extend(w::encode_string(comment).unwrap());
    let default_padding: Vec<u8>;
    let padding: &[u8] = match padding {
        Some(p) => p,
        None => {
            let pad_len = (8 - body.len() % 8) % 8;
            default_padding = (1..=pad_len as u8).collect();
            &default_padding
        }
    };
    body.extend_from_slice(padding);
    body
}

#[allow(clippy::too_many_arguments)]
fn container(
    pub_blob: &[u8],
    section: &[u8],
    cipher: &str,
    kdf: &str,
    kdfoptions: &[u8],
    nkeys: u32,
    magic: &[u8],
    trailing: &[u8],
) -> Vec<u8> {
    let mut out = magic.to_vec();
    out.extend(w::encode_string(cipher).unwrap());
    out.extend(w::encode_string(kdf).unwrap());
    out.extend(w::encode_string(kdfoptions).unwrap());
    out.extend(w::encode_uint32(nkeys));
    out.extend(w::encode_string(pub_blob).unwrap());
    out.extend(w::encode_string(section).unwrap());
    out.extend_from_slice(trailing);
    out
}

fn default_container(pub_blob: &[u8], section: &[u8]) -> Vec<u8> {
    container(pub_blob, section, "none", "none", b"", 1, MAGIC, b"")
}

fn fixture_seed() -> Vec<u8> {
    (32u8..64).collect()
}

#[test]
fn test_from_seed_and_generate() {
    let seed = fixture_seed();
    let key = Ed25519PrivateKey::from_seed(&seed, "test comment").unwrap();
    assert_eq!(key.comment, "test comment");
    let generated = w::generate_ed25519_private_key("gen");
    assert_eq!(generated.seed().expose().len(), 32);
    assert_eq!(generated.comment, "gen");
    assert_ne!(
        generated.seed().expose(),
        w::generate_ed25519_private_key("").seed().expose()
    );
}

#[test]
fn test_sign_and_verify_self_consistent() {
    // Python's test_sign_delegates_to_backend compares against the fake
    // backend's deterministic hash; we use the real backend (see the
    // module doc comment), so this checks internal consistency instead:
    // sign() produces SIGNATURE_SIZE bytes and verify() accepts them.
    let seed = fixture_seed();
    let key = Ed25519PrivateKey::from_seed(&seed, "test comment").unwrap();
    assert_eq!(key.sign(b"").len(), 64);
    let sig = key.sign(b"msg");
    assert_eq!(sig.len(), 64);
    assert!(key.public.verify(b"msg", &sig));
    assert!(!key.public.verify(b"other", &sig));
}

#[test]
fn test_repr_hides_seed() {
    let seed = fixture_seed();
    let key = Ed25519PrivateKey::from_seed(&seed, "test comment").unwrap();
    let text = format!("{key:?}");
    assert!(!text.contains(&hex::encode(&seed)));
    assert!(text.contains(&key.public.fingerprint()));
    assert!(text.contains("test comment"));
}

#[test]
fn test_validation() {
    use zeropw::secret::SecretBytes;
    let seed = fixture_seed();
    let key = Ed25519PrivateKey::from_seed(&seed, "").unwrap();
    assert!(Ed25519PrivateKey::new(
        SecretBytes::from_slice(&[0u8; 31]),
        key.public.clone(),
        String::new()
    )
    .is_err());
    assert!(Ed25519PrivateKey::from_seed(&[0u8; 33], "").is_err());
}

#[test]
fn test_pem_shape() {
    let seed = fixture_seed();
    let key = Ed25519PrivateKey::from_seed(&seed, "test comment").unwrap();
    let pem_text = key.to_openssh_private_key();
    let lines: Vec<&str> = pem_text.lines().collect();
    assert_eq!(lines[0], BEGIN);
    assert_eq!(*lines.last().unwrap(), END);
    assert!(pem_text.ends_with(&format!("{END}\n")));
    for line in &lines[1..lines.len() - 1] {
        assert!(line.len() <= 70);
    }
    for line in &lines[1..lines.len() - 2] {
        assert_eq!(line.len(), 70);
    }
    use base64::Engine;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(lines[1..lines.len() - 1].concat())
        .unwrap();
    let mut r = Reader::new(&blob);
    assert_eq!(r.raw(MAGIC.len()).unwrap(), MAGIC);
    assert_eq!(r.text().unwrap(), "none");
    assert_eq!(r.text().unwrap(), "none");
    assert_eq!(r.string().unwrap(), Vec::<u8>::new());
    assert_eq!(r.uint32().unwrap(), 1);
    assert_eq!(r.string().unwrap(), key.public.blob());
    let sect = r.string().unwrap();
    r.expect_eof("private key blob").unwrap();
    assert_eq!(sect.len() % 8, 0);
    let mut sr = Reader::new(&sect);
    let c1 = sr.uint32().unwrap();
    let c2 = sr.uint32().unwrap();
    assert_eq!(c1, c2);
    assert_eq!(sr.text().unwrap(), "ssh-ed25519");
    assert_eq!(sr.string().unwrap(), key.public.key_bytes());
    let mut expected_priv = seed.clone();
    expected_priv.extend_from_slice(key.public.key_bytes());
    assert_eq!(sr.string().unwrap(), expected_priv);
    assert_eq!(sr.text().unwrap(), "test comment");
    let padding = sr.rest();
    assert!(padding.len() < 8);
    let expected_padding: Vec<u8> = (1..=padding.len() as u8).collect();
    assert_eq!(padding, expected_padding);
}

#[test]
fn test_checkint_is_random() {
    use std::collections::HashSet;
    let seed = fixture_seed();
    let key = Ed25519PrivateKey::from_seed(&seed, "test comment").unwrap();
    let checkint = |pem_text: &str| -> u32 {
        use base64::Engine;
        let lines: Vec<&str> = pem_text.lines().collect();
        let blob = base64::engine::general_purpose::STANDARD
            .decode(lines[1..lines.len() - 1].concat())
            .unwrap();
        let mut r = Reader::new(&blob);
        r.raw(MAGIC.len()).unwrap();
        r.text().unwrap();
        r.text().unwrap();
        r.string().unwrap();
        r.uint32().unwrap();
        r.string().unwrap();
        let sect = r.string().unwrap();
        Reader::new(&sect).uint32().unwrap()
    };
    let values: HashSet<u32> = (0..8)
        .map(|_| checkint(&key.to_openssh_private_key()))
        .collect();
    assert!(values.len() > 1);
}

#[test]
fn test_round_trip() {
    let seed = fixture_seed();
    for comment in ["", "c", "a longer comment with spaces", "ünïcödé"] {
        let key = Ed25519PrivateKey::from_seed(&seed, comment).unwrap();
        let pem_text = key.to_openssh_private_key();
        let parsed = w::parse_openssh_private_key(pem_text.as_bytes()).unwrap();
        assert_eq!(parsed, key);
        assert_eq!(parsed.seed().expose(), key.seed().expose());
        assert_eq!(parsed.public, key.public);
        assert_eq!(parsed.comment, comment);
        assert_eq!(
            w::parse_openssh_private_key(pem_text.as_bytes()).unwrap(),
            key
        );
        assert_eq!(
            w::parse_openssh_private_key(pem_text.replace('\n', "\r\n").as_bytes()).unwrap(),
            key
        );
    }
}

#[test]
fn test_padding_lengths_all_accepted() {
    let seed = fixture_seed();
    for n in 0..16 {
        let key = Ed25519PrivateKey::from_seed(&seed, &"x".repeat(n)).unwrap();
        assert_eq!(
            w::parse_openssh_private_key(key.to_openssh_private_key().as_bytes()).unwrap(),
            key
        );
    }
}

#[test]
fn test_hand_built_container_parses() {
    let seed = fixture_seed();
    let key = Ed25519PrivateKey::from_seed(&seed, "").unwrap();
    let sect = section(
        key.public.key_bytes(),
        &seed,
        b"hand",
        0x01020304,
        None,
        "ssh-ed25519",
        None,
        None,
    );
    let pem_text = pem(&default_container(&key.public.blob(), &sect));
    let parsed = w::parse_openssh_private_key(pem_text.as_bytes()).unwrap();
    assert_eq!(parsed.seed().expose(), seed);
    assert_eq!(parsed.comment, "hand");
}

#[test]
fn test_encrypted_keys_unsupported() {
    let seed = fixture_seed();
    let key = Ed25519PrivateKey::from_seed(&seed, "").unwrap();
    let good = section(
        key.public.key_bytes(),
        &seed,
        b"c",
        0x01020304,
        None,
        "ssh-ed25519",
        None,
        None,
    );
    let pub_blob = key.public.blob();

    let c = container(
        &pub_blob,
        &good,
        "aes256-ctr",
        "bcrypt",
        &[0u8; 24],
        1,
        MAGIC,
        b"",
    );
    assert!(w::parse_openssh_private_key(pem(&c).as_bytes())
        .unwrap_err()
        .is_unsupported());

    let c = container(&pub_blob, &good, "aes256-ctr", "none", b"", 1, MAGIC, b"");
    assert!(w::parse_openssh_private_key(pem(&c).as_bytes())
        .unwrap_err()
        .is_unsupported());

    let c = container(&pub_blob, &good, "none", "bcrypt", b"", 1, MAGIC, b"");
    assert!(w::parse_openssh_private_key(pem(&c).as_bytes())
        .unwrap_err()
        .is_unsupported());
}

#[test]
fn test_other_pem_labels_unsupported() {
    let err = w::parse_openssh_private_key(
        b"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
    )
    .unwrap_err();
    assert!(err.is_unsupported());
    let err = w::parse_openssh_private_key(
        b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
    )
    .unwrap_err();
    assert!(err.is_unsupported());
}

#[test]
fn test_non_ed25519_key_unsupported() {
    let mut rsa_blob = w::encode_string("ssh-rsa").unwrap();
    rsa_blob.extend(w::encode_string(b"\x01\x00\x01" as &[u8]).unwrap());
    rsa_blob.extend(w::encode_string(b"\x05" as &[u8]).unwrap());
    let mut sect = w::encode_uint32(1).to_vec();
    sect.extend(w::encode_uint32(1));
    sect.extend(w::encode_string("ssh-rsa").unwrap());
    sect.extend(w::encode_string(b"\x05" as &[u8]).unwrap());
    sect.extend_from_slice(&[1, 2]);
    let pad_len = (8 - sect.len() % 8) % 8;
    sect.extend((1..=pad_len as u8).collect::<Vec<u8>>());
    let c = default_container(&rsa_blob, &sect);
    assert!(w::parse_openssh_private_key(pem(&c).as_bytes())
        .unwrap_err()
        .is_unsupported());
}

#[test]
fn test_malformed_containers() {
    let seed = fixture_seed();
    let key = Ed25519PrivateKey::from_seed(&seed, "").unwrap();
    let pub_blob = key.public.blob();
    let good = section(
        key.public.key_bytes(),
        &seed,
        b"c",
        0x01020304,
        None,
        "ssh-ed25519",
        None,
        None,
    );
    let other_seed: Vec<u8> = (64u8..96).collect();

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("bad magic", default_container(&pub_blob, &good).tap_magic()),
        (
            "kdfoptions present",
            container(&pub_blob, &good, "none", "none", b"\x00", 1, MAGIC, b""),
        ),
        (
            "zero keys",
            container(&pub_blob, &good, "none", "none", b"", 0, MAGIC, b""),
        ),
        (
            "trailing bytes",
            container(&pub_blob, &good, "none", "none", b"", 1, MAGIC, b"\x00"),
        ),
        (
            "checkint mismatch",
            default_container(
                &pub_blob,
                &section(
                    key.public.key_bytes(),
                    &seed,
                    b"c",
                    0x01020304,
                    Some(0x01020305),
                    "ssh-ed25519",
                    None,
                    None,
                ),
            ),
        ),
        (
            "section type mismatch",
            default_container(
                &pub_blob,
                &section(
                    key.public.key_bytes(),
                    &seed,
                    b"c",
                    0x01020304,
                    None,
                    "ssh-rsa",
                    None,
                    None,
                ),
            ),
        ),
        (
            "section pub mismatch",
            default_container(
                &pub_blob,
                &section(
                    &[0u8; 32],
                    &seed,
                    b"c",
                    0x01020304,
                    None,
                    "ssh-ed25519",
                    None,
                    None,
                ),
            ),
        ),
        (
            "priv wrong length",
            default_container(
                &pub_blob,
                &section(
                    key.public.key_bytes(),
                    &seed,
                    b"c",
                    0x01020304,
                    None,
                    "ssh-ed25519",
                    Some(&seed),
                    None,
                ),
            ),
        ),
        (
            "priv pub half mismatch",
            default_container(&pub_blob, &{
                let mut priv_ = seed.clone();
                priv_.extend_from_slice(&[0u8; 32]);
                section(
                    key.public.key_bytes(),
                    &seed,
                    b"c",
                    0x01020304,
                    None,
                    "ssh-ed25519",
                    Some(&priv_),
                    None,
                )
            }),
        ),
        (
            "seed does not derive pub",
            default_container(&pub_blob, &{
                let mut priv_ = other_seed.clone();
                priv_.extend_from_slice(key.public.key_bytes());
                section(
                    key.public.key_bytes(),
                    &other_seed,
                    b"c",
                    0x01020304,
                    None,
                    "ssh-ed25519",
                    Some(&priv_),
                    None,
                )
            }),
        ),
        (
            "bad padding values",
            default_container(
                &pub_blob,
                &section(
                    key.public.key_bytes(),
                    &seed,
                    b"",
                    0x01020304,
                    None,
                    "ssh-ed25519",
                    None,
                    Some(&[0u8; 5]),
                ),
            ),
        ),
        (
            "padding too long",
            default_container(&pub_blob, &{
                let padding: Vec<u8> = (1u8..14).collect();
                section(
                    key.public.key_bytes(),
                    &seed,
                    b"",
                    0x01020304,
                    None,
                    "ssh-ed25519",
                    None,
                    Some(&padding),
                )
            }),
        ),
        (
            "unaligned section",
            default_container(
                &pub_blob,
                &section(
                    key.public.key_bytes(),
                    &seed,
                    b"",
                    0x01020304,
                    None,
                    "ssh-ed25519",
                    None,
                    Some(&[1, 2]),
                ),
            ),
        ),
        (
            "truncated section",
            default_container(&pub_blob, &good[..good.len() - 9]),
        ),
        ("empty section", default_container(&pub_blob, b"")),
    ];
    for (name, blob) in cases {
        assert!(
            w::parse_openssh_private_key(pem(&blob).as_bytes()).is_err(),
            "{name}"
        );
    }
    let c = container(&pub_blob, &good, "none", "none", b"", 2, MAGIC, b"");
    assert!(w::parse_openssh_private_key(pem(&c).as_bytes())
        .unwrap_err()
        .is_unsupported());
}

trait TapMagic {
    fn tap_magic(self) -> Vec<u8>;
}
impl TapMagic for Vec<u8> {
    fn tap_magic(mut self) -> Vec<u8> {
        // Corrupt the trailing NUL of the 15-byte "openssh-key-v1" magic to
        // build the "bad magic" case without duplicating `container()`'s
        // signature just for a different `magic` argument.
        self[14] = b'2';
        self
    }
}

#[test]
fn test_non_utf8_comment_is_decoded_leniently() {
    let seed = fixture_seed();
    let key = Ed25519PrivateKey::from_seed(&seed, "").unwrap();
    for (raw, expected) in [
        (&b"caf\xe9"[..], "caf\u{fffd}"),
        (&b"\xff\xfe"[..], "\u{fffd}\u{fffd}"),
    ] {
        let sect = section(
            key.public.key_bytes(),
            &seed,
            raw,
            0x01020304,
            None,
            "ssh-ed25519",
            None,
            None,
        );
        let pem_text = pem(&default_container(&key.public.blob(), &sect));
        let parsed = w::parse_openssh_private_key(pem_text.as_bytes()).unwrap();
        assert_eq!(parsed.seed().expose(), seed);
        assert_eq!(parsed.public, key.public);
        assert_eq!(parsed.comment, expected);
        assert_eq!(
            w::parse_openssh_private_key(parsed.to_openssh_private_key().as_bytes()).unwrap(),
            parsed
        );
    }
}

#[test]
fn test_malformed_pem_wrapping() {
    let seed = fixture_seed();
    let key = Ed25519PrivateKey::from_seed(&seed, "").unwrap();
    let pem_text = key.to_openssh_private_key();
    let lines: Vec<&str> = pem_text.lines().collect();
    let cases: Vec<(&str, String)> = vec![
        ("empty", String::new()),
        ("no header", lines[1..].join("\n")),
        ("no footer", lines[..lines.len() - 1].join("\n")),
        (
            "bad base64",
            [lines[0], "!!!!", lines[lines.len() - 1]].join("\n"),
        ),
        (
            "truncated body",
            [
                &lines[..1],
                &lines[1..lines.len() - 2],
                &lines[lines.len() - 1..],
            ]
            .concat()
            .join("\n"),
        ),
        ("empty body", [lines[0], lines[lines.len() - 1]].join("\n")),
        ("garbage", "hello world".to_string()),
    ];
    for (name, text) in cases {
        assert!(
            w::parse_openssh_private_key(text.as_bytes()).is_err(),
            "{name}"
        );
    }
    let mut bad = pem_text.clone().into_bytes();
    bad.extend("é".as_bytes());
    assert!(w::parse_openssh_private_key(&bad).is_err());
}

// ---------------------------------------------------------------------------
// Interoperability with OpenSSH tooling (SshKeygenInteropTests)
// ---------------------------------------------------------------------------

fn ssh_keygen_available() -> bool {
    std::process::Command::new("ssh-keygen")
        .arg("-h")
        .output()
        .is_ok()
}

#[test]
fn test_parse_key_made_by_ssh_keygen() {
    if !ssh_keygen_available() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }
    use std::process::Command;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "c", "-f"])
        .arg(&path)
        .status()
        .unwrap();
    assert!(status.success());
    let pem_text = std::fs::read_to_string(&path).unwrap();
    let key = w::parse_openssh_private_key(pem_text.as_bytes()).unwrap();
    assert_eq!(key.comment, "c");
    let pub_line = std::fs::read_to_string(path.with_extension("pub"))
        .unwrap()
        .trim()
        .to_string();
    let entry = w::parse_authorized_key_entry(&pub_line).unwrap();
    assert_eq!(entry.key, key.public);
    assert_eq!(entry.comment, "c");
    assert_eq!(key.public.to_authorized_key("c").unwrap(), pub_line);
    let pem_bytes = std::fs::read(&path).unwrap();
    assert_eq!(w::parse_openssh_private_key(&pem_bytes).unwrap(), key);
}

#[test]
fn test_parse_key_made_by_ssh_keygen_with_non_utf8_comment() {
    if !ssh_keygen_available() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }
    use std::os::unix::ffi::OsStrExt;
    use std::process::Command;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nonutf8");
    // "caf\xe9" is not valid UTF-8; ssh-keygen -C copies argv bytes
    // verbatim, so pass it as a raw OsStr the way Python's test passes raw
    // bytes in argv.
    let comment = std::ffi::OsStr::from_bytes(b"caf\xe9");
    let out = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C"])
        .arg(comment)
        .arg("-f")
        .arg(&path)
        .output()
        .unwrap();
    if !out.status.success() {
        eprintln!(
            "skipping: ssh-keygen refused a non-UTF-8 comment: {:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    let key = w::parse_openssh_private_key(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(key.comment, "caf\u{fffd}");
    let pub_bytes = std::fs::read(path.with_extension("pub")).unwrap();
    let mut pub_fields = pub_bytes.split(|&b| b == b' ');
    assert_eq!(pub_fields.next().unwrap(), b"ssh-ed25519");
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(pub_fields.next().unwrap())
        .unwrap();
    assert_eq!(key.public, w::parse_public_key_blob(&decoded).unwrap());
    // ssh-keygen -y agrees on the public key for the very same file.
    let y_out = Command::new("ssh-keygen")
        .args(["-y", "-f"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        y_out.status.success(),
        "{}",
        String::from_utf8_lossy(&y_out.stderr)
    );
    let stdout_fields: Vec<&[u8]> = y_out.stdout.split(|&b| b == b' ').take(2).collect();
    let expected = key.public.to_authorized_key("").unwrap();
    let expected_fields: Vec<&[u8]> = expected.as_bytes().split(|&b| b == b' ').take(2).collect();
    assert_eq!(stdout_fields, expected_fields);
}

#[test]
fn test_fingerprint_matches_ssh_keygen() {
    if !ssh_keygen_available() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }
    use std::process::Command;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "fp-comment", "-f"])
        .arg(&path)
        .status()
        .unwrap();
    assert!(status.success());
    let key = w::parse_openssh_private_key(&std::fs::read(&path).unwrap()).unwrap();
    let out = Command::new("ssh-keygen")
        .args(["-l", "-E", "sha256", "-f"])
        .arg(path.with_extension("pub"))
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout
        .split_whitespace()
        .any(|tok| tok == key.public.fingerprint()));
}

#[test]
fn test_our_private_key_accepted_by_ssh_keygen_y() {
    if !ssh_keygen_available() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }
    use std::process::Command;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ours");
    let key = w::generate_ed25519_private_key("zeropw generated");
    std::fs::write(&path, key.to_openssh_private_key()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let out = Command::new("ssh-keygen")
        .args(["-y", "-f"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let fields: Vec<&str> = stdout.trim().splitn(3, ' ').collect();
    let expected_line = key.public.to_authorized_key("").unwrap();
    let expected: Vec<&str> = expected_line.split(' ').collect();
    assert_eq!(fields[..2], expected[..2]);
    if fields.len() == 3 {
        assert_eq!(fields[2], "zeropw generated");
    }
}

#[test]
fn test_reserialised_ssh_keygen_key_prints_same_public_line() {
    if !ssh_keygen_available() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }
    use std::process::Command;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "round trip", "-f"])
        .arg(&path)
        .status()
        .unwrap();
    assert!(status.success());
    let original = Command::new("ssh-keygen")
        .args(["-y", "-f"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        original.status.success(),
        "{}",
        String::from_utf8_lossy(&original.stderr)
    );
    let original = String::from_utf8(original.stdout)
        .unwrap()
        .trim()
        .to_string();
    let key = w::parse_openssh_private_key(&std::fs::read(&path).unwrap()).unwrap();
    let ours_path = dir.path().join("reserialised");
    std::fs::write(&ours_path, key.to_openssh_private_key()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ours_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let reserialised = Command::new("ssh-keygen")
        .args(["-y", "-f"])
        .arg(&ours_path)
        .output()
        .unwrap();
    assert!(
        reserialised.status.success(),
        "{}",
        String::from_utf8_lossy(&reserialised.stderr)
    );
    let reserialised = String::from_utf8(reserialised.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(reserialised, original);
    assert_eq!(
        w::parse_openssh_private_key(&std::fs::read(&ours_path).unwrap()).unwrap(),
        key
    );
}

#[test]
fn test_ssh_keygen_signs_and_verifies_with_our_key_file() {
    if !ssh_keygen_available() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }
    use std::process::Command;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sigkey");
    let key = w::generate_ed25519_private_key("signer");
    std::fs::write(&path, key.to_openssh_private_key()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let message_path = dir.path().join("message.txt");
    std::fs::write(&message_path, b"zeropw interop message\n").unwrap();
    let proc = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-f"])
        .arg(&path)
        .args(["-n", "zeropw-test"])
        .arg(&message_path)
        .output()
        .unwrap();
    if !proc.status.success()
        && String::from_utf8_lossy(&proc.stderr)
            .to_lowercase()
            .contains("unknown option")
    {
        eprintln!("skipping: ssh-keygen lacks -Y sign");
        return;
    }
    assert!(
        proc.status.success(),
        "{}",
        String::from_utf8_lossy(&proc.stderr)
    );
    let allowed = dir.path().join("allowed_signers");
    std::fs::write(
        &allowed,
        format!("tester {}\n", key.public.to_authorized_key("").unwrap()),
    )
    .unwrap();
    let sig_path = format!("{}.sig", message_path.display());
    let out = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(&allowed)
        .args(["-I", "tester", "-n", "zeropw-test", "-s", &sig_path])
        .stdin(std::fs::File::open(&message_path).unwrap())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let message = std::fs::read(&message_path).unwrap();
    let signature = key.sign(&message);
    assert!(key.public.verify(&message, &signature));
    let mut tampered = message.clone();
    tampered.push(b'x');
    assert!(!key.public.verify(&tampered, &signature));
}

// ---------------------------------------------------------------------------
// Agent protocol framing (AgentFramingTests)
// ---------------------------------------------------------------------------

struct RecordingRecv {
    data: Vec<u8>,
    pos: usize,
    requests: Vec<usize>,
    chunk: Option<usize>,
}

impl RecordingRecv {
    fn new(data: Vec<u8>, chunk: Option<usize>) -> Self {
        RecordingRecv {
            data,
            pos: 0,
            requests: Vec::new(),
            chunk,
        }
    }
}

impl Read for RecordingRecv {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.requests.push(buf.len());
        let want = self.chunk.map_or(buf.len(), |c| buf.len().min(c));
        let available = self.data.len() - self.pos;
        let n = want.min(available);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[test]
fn test_frame() {
    assert_eq!(
        w::frame_agent_message(b"\x0b").unwrap(),
        b"\x00\x00\x00\x01\x0b"
    );
    let mut payload = vec![0x0d];
    payload.extend(std::iter::repeat_n(b'x', 10));
    let mut expected = w::encode_uint32(11).to_vec();
    expected.extend(&payload);
    assert_eq!(w::frame_agent_message(&payload).unwrap(), expected);
    assert!(w::frame_agent_message(b"").is_err());
    assert!(w::frame_agent_message(&vec![0u8; w::MAX_AGENT_MESSAGE + 1]).is_err());
    assert_eq!(
        w::frame_agent_message(&vec![0u8; w::MAX_AGENT_MESSAGE])
            .unwrap()
            .len(),
        w::MAX_AGENT_MESSAGE + 4
    );
}

#[test]
fn test_read_round_trip_with_callable() {
    let mut data = w::frame_agent_message(b"\x0b").unwrap();
    let mut second = vec![0x0d];
    second.extend_from_slice(b"abc");
    data.extend(w::frame_agent_message(&second).unwrap());
    let mut cur = Cursor::new(data);
    assert_eq!(
        w::read_agent_message(&mut cur).unwrap(),
        Some(b"\x0b".to_vec())
    );
    assert_eq!(
        w::read_agent_message(&mut cur).unwrap(),
        Some(b"\x0dabc".to_vec())
    );
    assert_eq!(w::read_agent_message(&mut cur).unwrap(), None);
    assert_eq!(w::read_agent_message(&mut cur).unwrap(), None);
}

#[test]
fn test_read_with_short_recv_chunks() {
    let payload: Vec<u8> = (0..256u16)
        .flat_map(|i| vec![i as u8])
        .collect::<Vec<u8>>()
        .repeat(3);
    let framed = w::frame_agent_message(&payload).unwrap();
    let mut recv = RecordingRecv::new(framed, Some(7));
    assert_eq!(w::read_agent_message(&mut recv).unwrap(), Some(payload));
    assert_eq!(w::read_agent_message(&mut recv).unwrap(), None);
}

#[test]
fn test_read_with_object_having_recv() {
    let mut cur = Cursor::new(w::frame_agent_message(b"\x05").unwrap());
    assert_eq!(
        w::read_agent_message(&mut cur).unwrap(),
        Some(b"\x05".to_vec())
    );
    // Python also checks that a plain `object()` (no `.recv`) raises
    // TypeError; the `Read` trait bound makes that a compile error instead.
}

#[test]
fn test_truncated_length_prefix() {
    for prefix in [&b"\x00"[..], b"\x00\x00", b"\x00\x00\x00"] {
        let mut cur = Cursor::new(prefix.to_vec());
        assert!(w::read_agent_message(&mut cur).is_err());
    }
}

#[test]
fn test_truncated_payload() {
    let mut data = w::encode_uint32(10).to_vec();
    data.extend_from_slice(b"12345");
    let mut cur = Cursor::new(data);
    assert!(w::read_agent_message(&mut cur).is_err());
}

#[test]
fn test_zero_length_frame() {
    let mut data = w::encode_uint32(0).to_vec();
    data.push(5);
    let mut cur = Cursor::new(data);
    assert!(w::read_agent_message(&mut cur).is_err());
}

#[test]
fn test_oversize_rejected_before_reading_payload() {
    let mut data = w::encode_uint32(w::MAX_AGENT_MESSAGE as u32 + 1).to_vec();
    data.extend(vec![b'x'; 64]);
    let mut recv = RecordingRecv::new(data, None);
    assert!(w::read_agent_message(&mut recv).is_err());
    assert_eq!(recv.requests.iter().sum::<usize>(), 4);

    let mut recv = RecordingRecv::new(w::encode_uint32(0xFFFFFFFF).to_vec(), None);
    assert!(w::read_agent_message(&mut recv).is_err());
    assert_eq!(recv.requests.iter().sum::<usize>(), 4);
}

#[test]
fn test_max_size_accepted() {
    let mut payload = vec![0x0d];
    payload.extend(vec![0u8; w::MAX_AGENT_MESSAGE - 1]);
    let mut cur = Cursor::new(w::frame_agent_message(&payload).unwrap());
    assert_eq!(w::read_agent_message(&mut cur).unwrap(), Some(payload));
}

struct Greedy;
impl Read for Greedy {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Lies about how much it wrote, like Python's `greedy(n)` test
        // helper returning `n + 1` bytes.
        Ok(buf.len() + 1)
    }
}

#[test]
fn test_recv_returning_too_much_rejected() {
    let mut greedy = Greedy;
    assert!(w::read_agent_message(&mut greedy).is_err());
}

#[test]
fn test_write_with_callable_and_object() {
    let mut sent = Vec::new();
    w::write_agent_message(&mut sent, b"\x06").unwrap();
    assert_eq!(sent, b"\x00\x00\x00\x01\x06");

    let mut sent2: Vec<u8> = Vec::new();
    w::write_agent_message(&mut sent2, b"\x05").unwrap();
    assert_eq!(sent2, b"\x00\x00\x00\x01\x05");

    let mut sent3 = Vec::new();
    assert!(matches!(
        w::write_agent_message(&mut sent3, b""),
        Err(AgentError::Wire(_))
    ));
    // Python also checks writing to a plain `object()` raises TypeError;
    // the `Write` trait bound makes that a compile error instead.
}

#[test]
fn test_agent_connection_over_socketpair() {
    let (a, b) = UnixStream::pair().unwrap();
    // `AgentConnection` over `&UnixStream` (std provides `Read`/`Write` for
    // a shared reference to a connected socket) so we can also write on `b`
    // directly, the way Python's test calls `b.sendall(...)` even though
    // `server` also wraps the same socket object. Unlike `try_clone`, this
    // does not duplicate the underlying fd, so dropping `b` below actually
    // closes the connection instead of leaving a second open handle to it.
    let mut client = AgentConnection::new(&a);
    let mut server = AgentConnection::new(&b);

    client.write_message(&w::build_extension_query()).unwrap();
    let request = server.read_message().unwrap();
    assert_eq!(request, Some(w::build_extension_query()));
    server
        .write_message(&w::build_extension_query_response(&[
            "session-bind@openssh.com",
        ]))
        .unwrap();
    let reply = client.read_message().unwrap().unwrap();
    assert_eq!(reply[0], w::SSH_AGENT_SUCCESS);
    assert_eq!(
        w::parse_extension_query_response(&reply[1..]).unwrap(),
        vec!["session-bind@openssh.com".to_string()]
    );

    let payload = w::build_sign_request(b"blob", b"data", 0);
    (&b).write_all(&w::frame_agent_message(&w::build_failure()).unwrap())
        .unwrap();
    assert_eq!(client.request(&payload).unwrap(), w::build_failure());
    assert_eq!(server.read_message().unwrap(), Some(payload));

    // `server` borrows `b` and owns nothing to release; drop `b` itself to
    // actually close the socket, matching Python's `server.close()`.
    drop(b);
    // Peer closed cleanly: EOF at a message boundary reports None...
    assert_eq!(client.read_message().unwrap(), None);
    // ...and request() turns EOF-before-reply into an error.
    assert!(client.request(&w::build_extension_query()).is_err());
}

#[test]
fn test_agent_connection_truncated_peer_message() {
    let (a, b) = UnixStream::pair().unwrap();
    let mut client = AgentConnection::new(&a);
    let mut data = w::encode_uint32(100).to_vec();
    data.extend_from_slice(b"partial");
    (&b).write_all(&data).unwrap();
    drop(b);
    assert!(client.read_message().is_err());
}

// ---------------------------------------------------------------------------
// Agent messages (AgentMessageTests)
// ---------------------------------------------------------------------------

fn key_blob() -> Vec<u8> {
    Ed25519PublicKey::new(pub_bytes()).unwrap().blob()
}
fn host_key_blob() -> Vec<u8> {
    Ed25519PublicKey::new((100u8..132).collect())
        .unwrap()
        .blob()
}
fn session_id() -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(b"session").to_vec()
}
fn sig_blob() -> Vec<u8> {
    w::encode_ssh_signature(&(0u8..64).collect::<Vec<u8>>()).unwrap()
}

#[test]
fn test_constants() {
    assert_eq!(w::SSH_AGENT_FAILURE, 5);
    assert_eq!(w::SSH_AGENT_SUCCESS, 6);
    assert_eq!(w::SSH_AGENTC_REQUEST_IDENTITIES, 11);
    assert_eq!(w::SSH_AGENT_IDENTITIES_ANSWER, 12);
    assert_eq!(w::SSH_AGENTC_SIGN_REQUEST, 13);
    assert_eq!(w::SSH_AGENT_SIGN_RESPONSE, 14);
    assert_eq!(w::SSH_AGENTC_ADD_IDENTITY, 17);
    assert_eq!(w::SSH_AGENTC_REMOVE_IDENTITY, 18);
    assert_eq!(w::SSH_AGENTC_REMOVE_ALL_IDENTITIES, 19);
    assert_eq!(w::SSH_AGENTC_ADD_SMARTCARD_KEY, 20);
    assert_eq!(w::SSH_AGENTC_REMOVE_SMARTCARD_KEY, 21);
    assert_eq!(w::SSH_AGENTC_LOCK, 22);
    assert_eq!(w::SSH_AGENTC_UNLOCK, 23);
    assert_eq!(w::SSH_AGENTC_ADD_ID_CONSTRAINED, 25);
    assert_eq!(w::SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED, 26);
    assert_eq!(w::SSH_AGENTC_EXTENSION, 27);
    assert_eq!(w::SSH_AGENT_EXTENSION_FAILURE, 28);
    assert_eq!(w::MAX_AGENT_MESSAGE, 256 * 1024);
    assert_eq!(w::build_failure(), [5]);
    assert_eq!(w::build_success(), [6]);
}

#[test]
fn test_sign_request_round_trip() {
    let msg = w::build_sign_request(&key_blob(), b"to-sign", 0);
    assert_eq!(msg[0], w::SSH_AGENTC_SIGN_REQUEST);
    let mut expected = vec![0x0d];
    expected.extend(w::encode_string(key_blob()).unwrap());
    expected.extend(w::encode_string(b"to-sign" as &[u8]).unwrap());
    expected.extend(w::encode_uint32(0));
    assert_eq!(msg, expected);
    let req = w::parse_sign_request(&msg[1..]).unwrap();
    assert_eq!(
        req,
        SignRequest {
            key_blob: key_blob(),
            data: b"to-sign".to_vec(),
            flags: 0
        }
    );
    let msg2 = w::build_sign_request(&key_blob(), b"", 2);
    let req2 = w::parse_sign_request(&msg2[1..]).unwrap();
    assert_eq!(req2.flags, 2);
    assert_eq!(req2.data, Vec::<u8>::new());
}

#[test]
fn test_sign_request_rejections() {
    let body = w::build_sign_request(&key_blob(), b"d", 0)[1..].to_vec();
    let mut extra = body.clone();
    extra.push(0);
    assert!(w::parse_sign_request(&extra).is_err());
    for i in 0..body.len() {
        assert!(w::parse_sign_request(&body[..i]).is_err(), "cut={i}");
    }
}

#[test]
fn test_identities_answer_round_trip() {
    let keys = vec![
        (key_blob(), "first".to_string()),
        (host_key_blob(), String::new()),
    ];
    let msg = w::build_identities_answer(&keys);
    assert_eq!(msg[0], w::SSH_AGENT_IDENTITIES_ANSWER);
    assert_eq!(&msg[1..5], &w::encode_uint32(2));
    assert_eq!(w::parse_identities_answer(&msg[1..]).unwrap(), keys);
    let empty = w::build_identities_answer(&[]);
    assert_eq!(empty, b"\x0c\x00\x00\x00\x00");
    assert_eq!(w::parse_identities_answer(&empty[1..]).unwrap(), Vec::new());
}

#[test]
fn test_identities_answer_non_utf8_comment_is_decoded_leniently() {
    let mut body = w::encode_uint32(1).to_vec();
    body.extend(w::encode_string(key_blob()).unwrap());
    body.extend(w::encode_string(b"caf\xe9" as &[u8]).unwrap());
    assert_eq!(
        w::parse_identities_answer(&body).unwrap(),
        vec![(key_blob(), "caf\u{fffd}".to_string())]
    );
}

#[test]
fn test_identities_answer_rejections() {
    let body = w::build_identities_answer(&[(key_blob(), "c".to_string())])[1..].to_vec();
    let mut extra = body.clone();
    extra.push(0);
    assert!(w::parse_identities_answer(&extra).is_err());
    assert!(w::parse_identities_answer(&body[..body.len() - 1]).is_err());
    assert!(w::parse_identities_answer(&w::encode_uint32(0xFFFFFFFF)).is_err());
    let mut body2 = w::encode_uint32(2).to_vec();
    body2.extend(w::encode_string(key_blob()).unwrap());
    body2.extend(w::encode_string(b"c" as &[u8]).unwrap());
    assert!(w::parse_identities_answer(&body2).is_err());
}

#[test]
fn test_sign_response_round_trip() {
    let msg = w::build_sign_response(&sig_blob());
    let mut expected = vec![0x0e];
    expected.extend(w::encode_string(sig_blob()).unwrap());
    assert_eq!(msg, expected);
    assert_eq!(w::parse_sign_response(&msg[1..]).unwrap(), sig_blob());
    let inner = w::parse_sign_response(&msg[1..]).unwrap();
    assert_eq!(
        w::parse_ssh_signature(&inner).unwrap(),
        (0u8..64).collect::<Vec<u8>>()
    );
    let mut extra = msg[1..].to_vec();
    extra.push(0);
    assert!(w::parse_sign_response(&extra).is_err());
    assert!(w::parse_sign_response(&msg[1..msg.len() - 1]).is_err());
}

#[test]
fn test_extension_query() {
    let msg = w::build_extension_query();
    let mut expected = vec![0x1b];
    expected.extend(w::encode_string("query").unwrap());
    assert_eq!(msg, expected);
    let (name, rest) = w::parse_extension(&msg[1..]).unwrap();
    assert_eq!((name.as_str(), rest.as_slice()), ("query", &b""[..]));
    let reply = w::build_extension_query_response(&["session-bind@openssh.com", "other@example"]);
    assert_eq!(reply[0], w::SSH_AGENT_SUCCESS);
    let mut expected_reply = w::build_success().to_vec();
    expected_reply.extend(w::encode_string("session-bind@openssh.com").unwrap());
    expected_reply.extend(w::encode_string("other@example").unwrap());
    assert_eq!(reply, expected_reply);
    assert_ne!(reply[0], w::SSH_AGENT_SIGN_RESPONSE);
    assert_eq!(
        w::parse_extension_query_response(&reply[1..]).unwrap(),
        vec![
            "session-bind@openssh.com".to_string(),
            "other@example".to_string()
        ]
    );
    assert_eq!(
        w::parse_extension_query_response(b"").unwrap(),
        Vec::<String>::new()
    );
    assert!(w::parse_extension_query_response(b"\x00\x00\x00\x05abc").is_err());
}

#[test]
fn test_extension_parse() {
    let mut body = w::encode_string("some-ext@example").unwrap();
    body.extend_from_slice(&[1, 2, 3]);
    let (name, rest) = w::parse_extension(&body).unwrap();
    assert_eq!(
        (name.as_str(), rest.as_slice()),
        ("some-ext@example", &[1u8, 2, 3][..])
    );
    assert!(w::parse_extension(b"").is_err());
    assert!(w::parse_extension(&w::encode_string(b"" as &[u8]).unwrap()).is_err());
    assert!(w::parse_extension(&w::encode_string(b"\xff" as &[u8]).unwrap()).is_err());
    assert!(w::parse_extension(b"\x00\x00\x00\x09abc").is_err());
}

#[test]
fn test_session_bind_round_trip() {
    for forwarding in [false, true] {
        let msg = w::build_session_bind(&host_key_blob(), &session_id(), &sig_blob(), forwarding);
        assert_eq!(msg[0], w::SSH_AGENTC_EXTENSION);
        let (name, rest) = w::parse_extension(&msg[1..]).unwrap();
        assert_eq!(name, "session-bind@openssh.com");
        let bind = w::parse_session_bind(&rest).unwrap();
        assert_eq!(
            bind,
            SessionBind {
                host_key_blob: host_key_blob(),
                session_id: session_id(),
                signature: sig_blob(),
                is_forwarding: forwarding,
            }
        );
    }
}

#[test]
fn test_session_bind_rejections() {
    let (_, rest) = w::parse_extension(
        &w::build_session_bind(&host_key_blob(), &session_id(), &sig_blob(), false)[1..],
    )
    .unwrap();
    let mut extra = rest.clone();
    extra.push(0);
    assert!(w::parse_session_bind(&extra).is_err());
    let mut bad_bool = rest[..rest.len() - 1].to_vec();
    bad_bool.push(2);
    assert!(w::parse_session_bind(&bad_bool).is_err());
    for i in 0..rest.len() {
        assert!(w::parse_session_bind(&rest[..i]).is_err(), "cut={i}");
    }
    let empties: Vec<Vec<u8>> = vec![
        {
            let mut d = w::encode_string(b"" as &[u8]).unwrap();
            d.extend(w::encode_string(session_id()).unwrap());
            d.extend(w::encode_string(sig_blob()).unwrap());
            d.push(0);
            d
        },
        {
            let mut d = w::encode_string(host_key_blob()).unwrap();
            d.extend(w::encode_string(b"" as &[u8]).unwrap());
            d.extend(w::encode_string(sig_blob()).unwrap());
            d.push(0);
            d
        },
        {
            let mut d = w::encode_string(host_key_blob()).unwrap();
            d.extend(w::encode_string(session_id()).unwrap());
            d.extend(w::encode_string(b"" as &[u8]).unwrap());
            d.push(0);
            d
        },
    ];
    for data in empties {
        assert!(w::parse_session_bind(&data).is_err());
    }
}

// ---------------------------------------------------------------------------
// SSH_MSG_USERAUTH_REQUEST strictness (UserAuthRequestTests)
// ---------------------------------------------------------------------------

struct FieldsOverride<'a> {
    session_id: &'a [u8],
    msg: u8,
    username: &'a [u8],
    service: &'a [u8],
    method: &'a [u8],
    flag: &'a [u8],
    algorithm: &'a [u8],
    blob: &'a [u8],
    extra: &'a [u8],
}

impl<'a> Default for FieldsOverride<'a> {
    fn default() -> Self {
        FieldsOverride {
            session_id: &[],
            msg: 50,
            username: b"deploy",
            service: b"ssh-connection",
            method: b"publickey",
            flag: b"\x01",
            algorithm: b"ssh-ed25519",
            blob: &[],
            extra: b"",
        }
    }
}

fn fields(o: FieldsOverride) -> Vec<u8> {
    let sid = if o.session_id.is_empty() {
        session_id()
    } else {
        o.session_id.to_vec()
    };
    let blob = if o.blob.is_empty() {
        key_blob()
    } else {
        o.blob.to_vec()
    };
    let mut out = w::encode_string(&sid).unwrap();
    out.push(o.msg);
    out.extend(w::encode_string(o.username).unwrap());
    out.extend(w::encode_string(o.service).unwrap());
    out.extend(w::encode_string(o.method).unwrap());
    out.extend_from_slice(o.flag);
    out.extend(w::encode_string(o.algorithm).unwrap());
    out.extend(w::encode_string(&blob).unwrap());
    out.extend_from_slice(o.extra);
    out
}

#[test]
fn test_build_matches_layout() {
    let built = w::build_userauth_request(
        &session_id(),
        "deploy",
        "ssh-ed25519",
        &key_blob(),
        "ssh-connection",
        None,
    );
    assert_eq!(built, fields(FieldsOverride::default()));

    let hostbound = w::build_userauth_request(
        &session_id(),
        "deploy",
        "ssh-ed25519",
        &key_blob(),
        "ssh-connection",
        Some(&host_key_blob()),
    );
    let extra = w::encode_string(host_key_blob()).unwrap();
    let expected = fields(FieldsOverride {
        method: b"publickey-hostbound-v00@openssh.com",
        extra: &extra,
        ..Default::default()
    });
    assert_eq!(hostbound, expected);

    let custom = w::build_userauth_request(
        &session_id(),
        "u",
        "ssh-ed25519",
        &key_blob(),
        "other",
        None,
    );
    assert_eq!(
        custom,
        fields(FieldsOverride {
            username: b"u",
            service: b"other",
            ..Default::default()
        })
    );
}

#[test]
fn test_parse_plain() {
    let req = w::parse_userauth_request(&fields(FieldsOverride::default()), true).unwrap();
    assert_eq!(
        req,
        UserAuthRequest {
            session_id: session_id(),
            username: "deploy".to_string(),
            service: "ssh-connection".to_string(),
            method: "publickey".to_string(),
            has_signature: true,
            algorithm: "ssh-ed25519".to_string(),
            public_key_blob: key_blob(),
            host_key_blob: None,
        }
    );
}

#[test]
fn test_parse_hostbound() {
    let data = w::build_userauth_request(
        &session_id(),
        "deploy",
        "ssh-ed25519",
        &key_blob(),
        "ssh-connection",
        Some(&host_key_blob()),
    );
    let req = w::parse_userauth_request(&data, true).unwrap();
    assert_eq!(req.method, "publickey-hostbound-v00@openssh.com");
    assert_eq!(req.host_key_blob, Some(host_key_blob()));
    assert_eq!(req.public_key_blob, key_blob());
    assert_eq!(req.username, "deploy");
    assert_eq!(w::parse_userauth_request(&data, true).unwrap(), req);
    assert!(w::parse_userauth_request(&data, false).is_err());

    let plain = w::parse_userauth_request(&fields(FieldsOverride::default()), false).unwrap();
    assert_eq!(
        (plain.method.as_str(), plain.host_key_blob),
        ("publickey", None)
    );

    assert!(w::parse_userauth_request(
        &fields(FieldsOverride {
            method: b"publickey-hostbound-v00@openssh.com",
            ..Default::default()
        }),
        true
    )
    .is_err());

    let mut empty_host = w::encode_string(b"" as &[u8]).unwrap();
    assert!(w::parse_userauth_request(
        &fields(FieldsOverride {
            method: b"publickey-hostbound-v00@openssh.com",
            extra: &std::mem::take(&mut empty_host),
            ..Default::default()
        }),
        true
    )
    .is_err());

    let mut trailing = data.clone();
    trailing.push(0);
    assert!(w::parse_userauth_request(&trailing, true).is_err());

    let mut host_extra = w::encode_string(host_key_blob()).unwrap();
    assert!(w::parse_userauth_request(
        &fields(FieldsOverride {
            extra: &std::mem::take(&mut host_extra),
            ..Default::default()
        }),
        true
    )
    .is_err());
}

#[test]
fn test_each_field_wrong_is_rejected() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "empty session id",
            fields(FieldsOverride {
                session_id: b"\x00",
                ..Default::default()
            }),
        ), // placeholder, real empty below
        (
            "msg 51",
            fields(FieldsOverride {
                msg: 51,
                ..Default::default()
            }),
        ),
        (
            "msg 60",
            fields(FieldsOverride {
                msg: 60,
                ..Default::default()
            }),
        ),
        (
            "msg 0",
            fields(FieldsOverride {
                msg: 0,
                ..Default::default()
            }),
        ),
        (
            "empty username",
            fields(FieldsOverride {
                username: b"",
                ..Default::default()
            }),
        ),
        (
            "username invalid utf8",
            fields(FieldsOverride {
                username: b"\xff\xfe",
                ..Default::default()
            }),
        ),
        (
            "service ssh-userauth",
            fields(FieldsOverride {
                service: b"ssh-userauth",
                ..Default::default()
            }),
        ),
        (
            "service empty",
            fields(FieldsOverride {
                service: b"",
                ..Default::default()
            }),
        ),
        (
            "service case",
            fields(FieldsOverride {
                service: b"SSH-CONNECTION",
                ..Default::default()
            }),
        ),
        (
            "method password",
            fields(FieldsOverride {
                method: b"password",
                ..Default::default()
            }),
        ),
        (
            "method none",
            fields(FieldsOverride {
                method: b"none",
                ..Default::default()
            }),
        ),
        (
            "method empty",
            fields(FieldsOverride {
                method: b"",
                ..Default::default()
            }),
        ),
        (
            "method hostbased",
            fields(FieldsOverride {
                method: b"hostbased",
                ..Default::default()
            }),
        ),
        (
            "method publickey-ish",
            fields(FieldsOverride {
                method: b"publickey2",
                ..Default::default()
            }),
        ),
        (
            "flag FALSE",
            fields(FieldsOverride {
                flag: b"\x00",
                ..Default::default()
            }),
        ),
        (
            "flag non-canonical",
            fields(FieldsOverride {
                flag: b"\x02",
                ..Default::default()
            }),
        ),
        (
            "flag 0xff",
            fields(FieldsOverride {
                flag: b"\xff",
                ..Default::default()
            }),
        ),
        (
            "empty algorithm",
            fields(FieldsOverride {
                algorithm: b"",
                ..Default::default()
            }),
        ),
        (
            "algorithm invalid utf8",
            fields(FieldsOverride {
                algorithm: b"\xff",
                ..Default::default()
            }),
        ),
        (
            "empty blob",
            fields(FieldsOverride {
                blob: b"\x00\x00\x00\x00",
                ..Default::default()
            }),
        ), // encode_string(b"") below overrides
        (
            "trailing byte",
            fields(FieldsOverride {
                extra: b"\x00",
                ..Default::default()
            }),
        ),
        ("empty", Vec::new()),
    ];
    // Fix up the two cases that need a truly empty (not placeholder) field,
    // since `FieldsOverride` treats `&[]` as "use the default fixture".
    let mut real_cases = cases;
    real_cases[0] = ("empty session id", {
        let mut out = w::encode_string(b"" as &[u8]).unwrap();
        out.push(50);
        out.extend(w::encode_string(b"deploy" as &[u8]).unwrap());
        out.extend(w::encode_string(b"ssh-connection" as &[u8]).unwrap());
        out.extend(w::encode_string(b"publickey" as &[u8]).unwrap());
        out.push(1);
        out.extend(w::encode_string(b"ssh-ed25519" as &[u8]).unwrap());
        out.extend(w::encode_string(key_blob()).unwrap());
        out
    });
    real_cases[19] = ("empty blob", {
        let mut out = w::encode_string(session_id()).unwrap();
        out.push(50);
        out.extend(w::encode_string(b"deploy" as &[u8]).unwrap());
        out.extend(w::encode_string(b"ssh-connection" as &[u8]).unwrap());
        out.extend(w::encode_string(b"publickey" as &[u8]).unwrap());
        out.push(1);
        out.extend(w::encode_string(b"ssh-ed25519" as &[u8]).unwrap());
        out.extend(w::encode_string(b"" as &[u8]).unwrap());
        out
    });
    let trailing_string_case = {
        let mut d = fields(FieldsOverride::default());
        d.extend(w::encode_string(b"x" as &[u8]).unwrap());
        d
    };
    real_cases.push(("trailing string", trailing_string_case));

    for (name, data) in real_cases {
        assert!(w::parse_userauth_request(&data, true).is_err(), "{name}");
    }
}

#[test]
fn test_every_truncation_is_rejected() {
    let data = fields(FieldsOverride::default());
    for i in 0..data.len() {
        assert!(
            w::parse_userauth_request(&data[..i], true).is_err(),
            "cut={i}"
        );
    }
}

#[test]
fn test_arbitrary_data_is_rejected() {
    let mut token_bytes = vec![0u8; 64];
    getrandom::getrandom(&mut token_bytes).unwrap();
    let mut junk4 = w::encode_string(session_id()).unwrap();
    junk4.push(0x32);
    for junk in [b"hello world".to_vec(), token_bytes, vec![0u8; 40], junk4] {
        assert!(w::parse_userauth_request(&junk, true).is_err());
    }
}

#[test]
fn test_other_algorithms_parse_but_are_reported() {
    let mut rsa_blob = b"\x00\x00\x00\x07ssh-rsa".to_vec();
    let req = w::parse_userauth_request(
        &fields(FieldsOverride {
            algorithm: b"rsa-sha2-512",
            blob: &std::mem::take(&mut rsa_blob),
            ..Default::default()
        }),
        true,
    )
    .unwrap();
    assert_eq!(req.algorithm, "rsa-sha2-512");
}

// A couple of extra WireError-vs-UnsupportedKeyType sanity checks that map
// to Python's `assertNotIsInstance(cm.exception, w.UnsupportedKeyType)`
// idiom used throughout the authorized_keys tests above: WireError's
// `is_unsupported()` is exercised there directly.
#[test]
fn wire_error_is_a_std_error() {
    fn assert_is_error<E: std::error::Error>(_: &E) {}
    let err = WireError::new("x");
    assert_is_error(&err);
}
