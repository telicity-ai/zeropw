# macOS validation evidence — final 260 source

The final UX-05 and N8/N9/N10 frontend changes pass **260/260 tests**, static checks, TypeScript, production frontend build, native embedding and deep/strict bundle signature verification. The temporary app is closed. **macOS visual E2E remains unavailable because CUA AX attachment timed out; this report does not claim a native UI PASS.**

Base: `8bd1d8340bc633067539df2b3b4e2ad35250486e` plus the frozen frontend patch. The copied input snapshot contains 552 files; its manifest SHA-256 is `18f670ad42aafaa2e87afe8fde98329fc9b6524c43761a6b4909424af8e50913`. The manifest describes the copied build snapshot before this report update. Product source was not edited by the macOS validator. The new hook is `desktop/src/ui/disclosure.ts`.

| Validation | Actual result |
|---|---|
| Frontend static, TypeScript, production build | PASS |
| Frontend unit/component tests | 260/260 PASS, 15 files |
| Embedded native Tauri build | PASS, debug/no-bundle, separate temporary bundle |
| Bundle signature verification | PASS, deep + strict ad-hoc signature |
| macOS visual E2E | Unavailable: CUA inventories the previous app but exact-ID/path AX attachment times out; final 260 bundle was not launched |
| Prior full rust/verify.sh | Exit 1; 97/97 steps exercised, 76 PASS / 21 FAIL; 1518 passing / 47 failing test executions |
| Rust fmt and strict Clippy | PASS |
| Rust integration targets | All 92 executed |
| Signer resource probes | 3 PASS / 1 FAIL; all 4 initially ignored probes executed |
| Rust binary unit supplement | All 5 targets PASS, 0 tests each |
| Rust doc tests | PASS, 0 tests |
| Prior desktop/verify.sh | npm/static/build/fmt/Clippy/product-bins PASS; initial focus-test failure was fixed; a core failure stops default Cargo fail-fast |
| Desktop Rust no-fail-fast supplement | All 10 targets executed; 125 PASS / 17 FAIL; native-shell unit tests 10/10 PASS; real-binary env-import E2E PASS |

Rust, `desktop/core` and `desktop/src-tauri` source hashes are identical to the earlier fully exercised snapshot. The UX-05/focus follow-ups changed TypeScript only, so these Rust matrices were reused without rerunning or relabeling failures. The original 47 failures group into 21 NSS/OpenSSH bootstrap failures, 12 PTY failures, 6 direct outside-task temp-path failures, 3 native-exec failures whose fixture clears TMPDIR (outside-temp cause inferred from source), 1 SystemConfiguration snapshot failure, 1 setuid-mode assertion, 1 setuid-ps CPU probe, and 2 timing/session failures that passed isolated retries. They are not presented as 47 new product regressions.

Targeted follow-ups preserve the original failures: 5 NSS-dependent library cases and expanduser integration pass, and sshwire passes 86/86. CLI parity matches 77/78 cases; `/tmp` produces PermissionError instead of expected IsADirectoryError under the sandbox. Runtime-session and HTTP content-length timing pass isolated retries. Corrected-NSS signer E2E remains 3 PASS / 3 FAIL: two real-sshd connection resets and one missing host-key-rejection audit. Desktop's 17 failures comprise 11 PTY-unavailable, 4 setuid-ps/serve-attachment, and 2 real-sshd resets. SSH remains unresolved under the restricted environment. A narrow public-sshd-helper allowance did not fix it and was removed.

The first UX-05 attempt passed 258 unit tests but exposed a TypeScript error in test fixtures missing `NetInterface.name`. Sol added synthetic names; the failure log and manifest are retained, and final 260 static/type/build/tests pass. No assertion was weakened by the macOS validator.

`logs/platform-limit-canary.log` confirms NSS lookup works under the revised test profile, os.openpty is EPERM, setuid `/bin/ps` cannot execute, requested 04600 becomes 0600, and the public coordinator README is EPERM. Build/runtime wrappers retain clean environments and synthetic HOME. The GUI profile adds narrow public IPC and synthetic ports only. No production vault, key, installed app or runtime was inspected or changed.

The earlier WebKit bootstrap fix used a temporary-bundle-only network.client entitlement for offline embedded pages. nsurlsessiond stays denied; the same-entitlement canary still denies external 192.0.2.1:443, forbidden localhost:9 and the coordinator README. Earlier AppKit/WebKit processes became stable, but no AX-specific denied service was observed, including Sol's independent read-only inspection. The sandbox was not broadened for speculative AX access. The final build was signed and left closed without another AX attempt.

Bundle: `/private/tmp/zeropw-codex-macos-r7zqb1go/ZeroPW UX Test.app`, identity `ai.telicity.zeropw.codexuxtest`. The trusted launcher always runs the product through `run-gui.sh` with synthetic HOME and gateway 48380. Final signed executable SHA-256: `41e01057bdf0302ce65361c345b879fb40cfe3c6b4fbf1d088519f6bdff8cfcd`. The existing installed app remains untouched.

The JSON summary contains exact hashes for the five final patch files, the manifest, signed binary, profiles and final logs. Primary evidence under `/private/tmp/zeropw-codex-macos-r7zqb1go`: `logs/frontend-final260.log`, `logs/native-build-final260.log`, `logs/app-bundle-verify-final260.log`, `logs/rust-verify.log`, `logs/desktop-verify-final.log`, `logs/desktop-rust-all-targets.log`, `rust-step-results.json`, `desktop-rust-target-results.json`, and focused retry/canary logs. The local rust-objcopy missing-libLLVM debug-stripping warning is preserved; builds exit successfully and toolchain files were not modified.
