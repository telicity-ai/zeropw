# Recorded deviations from the Python prototype

Only deviations allowed by `PORTING.md` §3 or explicitly justified here. One row per behaviour.

| Module | Python behaviour | Rust behaviour | Reason |
| --- | --- | --- | --- |
| crypto | Hand-written RFC 8439 / RFC 8032 in pure Python, not constant time | `chacha20poly1305`, `ed25519-dalek` crates | PORTING.md §3.1 |
| all | Secret `bytes` cannot be zeroised | `SecretBytes` zeroised on drop, redacted `Debug` | PORTING.md §3.2 |
