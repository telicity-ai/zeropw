# Rust standard-library notice supplement

The Rust1.99.0 arm64 macOS standard library contains addr2line0.27.1, memchr2.8.3 and miniz_oxide0.9.1. That release's COPYRIGHT-library.html/COPYRIGHT.html omit those exact versions. The notice collector keeps the original catalogs and refuses unidentified dependencies; this supplement supplies only the missing exact-version notices.

Root downloaded the original published crates and verified their SHA256 against library/Cargo.lock at compiler commit b940084d7eb6a299eb4bfeb8e34901bc051e7ac4. The JSON records that lock's URL/hash, each original crate URL/hash and every unchanged notice-file hash. Files retain their upstream text, including the offered alternative licenses. This is a source notice inventory, not a legal opinion or a claim of an external licensing review.

The collector must match compiler release, full commit, target and observed dependency version before using a supplement. It prefers the toolchain's own matching catalog entry. Unknown or unversioned dependencies, changed notice bytes and unsafe paths still fail the build. No source or notice is downloaded during collection. A future toolchain requires its own recorded evidence; these entries cannot silently cover an upgrade.
