use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=OPENSSL_DIR");
    println!("cargo:rerun-if-env-changed=OPENSSL_STATIC");
    if env::var_os("CARGO_FEATURE_BUNDLED_OPENSSL").is_none() {
        return;
    }
    assert_eq!(
        env::var("OPENSSL_STATIC").as_deref(),
        Ok("1"),
        "bundled-openssl requires the static SDK from scripts/build-release.py"
    );
    let sdk =
        PathBuf::from(env::var_os("OPENSSL_DIR").expect("set OPENSSL_DIR to the release SDK"));
    let header = sdk.join("include/openssl/opensslv.h");
    println!("cargo:rerun-if-changed={}", header.display());
    let text = fs::read_to_string(header).expect("release SDK version header missing");
    for (name, expected) in [
        ("OPENSSL_VERSION_MAJOR", "3"),
        ("OPENSSL_VERSION_MINOR", "5"),
        ("OPENSSL_VERSION_PATCH", "9"),
    ] {
        assert!(
            text.lines().any(|line| {
                line.trim_start().starts_with('#')
                    && line
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .windows(2)
                        .any(|parts| parts == [name, expected])
            }),
            "bundled-openssl requires the pinned OpenSSL 3.5.9 SDK"
        );
    }
    for library in ["libssl.a", "libcrypto.a"] {
        assert!(
            sdk.join("lib").join(library).is_file(),
            "release static library missing"
        );
    }
}
