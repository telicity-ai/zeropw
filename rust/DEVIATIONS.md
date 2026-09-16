# Recorded deviations from the Python prototype

Only deviations allowed by `PORTING.md` §3 or explicitly justified here. One row per behaviour.

| Module | Python behaviour | Rust behaviour | Reason |
| --- | --- | --- | --- |
| crypto | Hand-written RFC 8439 / RFC 8032 in pure Python, not constant time | `chacha20poly1305`, `ed25519-dalek` crates | PORTING.md §3.1 |
| all | Secret `bytes` cannot be zeroised | `SecretBytes` zeroised on drop, redacted `Debug` | PORTING.md §3.2 |
| crypto/chacha20poly1305 | `chacha20_block`'s `counter: int` is runtime-checked (rejects negative, non-int, float, or `>= 2**32`, raising `TypeError`/`ValueError`) | `counter: u32`, so those cases are compile-time impossible; only the key/nonce size checks remain runtime errors | Rust's type system already enforces the RFC's 32-bit unsigned counter range; no runtime check can express something the type doesn't allow |
| crypto/chacha20poly1305, crypto/ed25519 | `decrypt`/`sign`/`verify`/`public_key_from_seed` accept `bytes \| bytearray \| memoryview` and raise `TypeError` (or, for `decrypt`, `AuthenticationError`) for a non-bytes-like value or a released `memoryview` | Functions take `&[u8]` directly; a caller cannot construct an "unusable buffer" value, so this whole error class does not exist | `&[u8]` is always a valid, live view; the Python cases exist only because `bytes`-like arguments are duck-typed and mutable buffers can be released after construction |
| kms | `LocalFileKms.create`: if `os.open(..., O_EXCL)` loses a TOCTOU race after the initial `path.exists()` check, or `path.parent.mkdir` fails for another OS reason, the raw `OSError`/`FileExistsError` propagates uncaught (not wrapped as `KmsError`) | Both cases are wrapped as `KmsError("kms_create_failed", <os error text>)` | `Result<T, crate::errors::Error>` has no "let anything else escape" case the way Python's unchecked exceptions do; wrapping keeps the return type uniform. Only the initial `path.exists()` check (`KmsError("kms_exists", ...)`) is reachable in the crate's own tests |
