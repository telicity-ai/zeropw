# Local macOS release verification — 2026-10-10

The user authorized local macOS and Homebrew verification instead of waiting for a self-hosted runner. The repository remains private. No release, deployment or public switch was performed.

## Source and environment

- Source: `03a989ff81eee0c16871278c438c17b48dbce826`.
- Product code is unchanged from `5d99a5e`; `03a989f` fixes the Homebrew verification script's local Git download strategy.
- The disposable local snapshot has the same Git tree, `857040ed694d70e85be71fe0ddf9f3590fcfe937`, as `03a989f`. Its synthetic Git commit identity is different from the source commit.
- Apple Silicon, macOS 26.5; native Cargo 1.98.1; Homebrew OpenSSL 3.6.5.
- Product checks use synthetic credentials and controlled endpoints. Native checks run with a clean environment and a Seatbelt profile denying home-directory data access except the source/toolchains. Cargo credential files and Keychain access are explicitly denied.
- Homebrew builds/tests use Homebrew's own sandbox, which denies home-directory reads. An outer Seatbelt sandbox cannot nest Homebrew's sandbox on this host; those failed setup attempts are not product-test failures.

## Confirmed checks

- Installation/publication tooling: 18 tests passed.
- Harness: 80 tests passed; Python compilation passed.
- Native release build passed.
- Native macOS archive with dependency notices: checksum installation, both CLI help commands and all 47 installed demo checks passed.
- `otool -L` confirms that the archive uses Homebrew OpenSSL dylibs. This does not establish curl-only installation on a Mac without those libraries.

## Permission-test environment boundary

`notify_secure_mode_includes_special_bits` fails inside Seatbelt because `chmod(04600)` is observed as `0600`. A synthetic file reproduces this behavior inside the sandbox; outside the sandbox its mode is `04600`. The unchanged test binary passed when run alone outside Seatbelt, with a clean environment and synthetic data, under the user's local-verification authorization. Do not present the sandbox matrix as an unqualified PASS or change the test assertion to bypass this boundary.

The first native setup attempt also omitted macOS `TMPDIR`, causing the Rust/Python temporary-directory comparison to differ. The matrix was restarted preserving the host's non-secret `TMPDIR`. This is an environment correction, not a product fix.

## Adversarial review

Claude Code 2.1.287 is installed and authenticated. The no-tools review used actual model `claude-opus-5-5`, medium effort, no MCP, hooks or session persistence. It reviewed the exact `03a989f` source supplied for installation, notifications and removal boundaries. Its verdict is **REVISE**, not repository acceptance.

The original findings and severity are preserved in [the review record](reviews/2026-10-10-open-source-opus.json). R1 is High; R2–R4 are Medium; R5–R9 are Low. They remain open pending bounded fixes and evidence. Known issues `OSS-TEAM-SELFREMOVE` and `OSS-INSTALL-OPENSSL` also remain open. No finding has been lowered or marked resolved by this validation note.

## Native matrix result

The complete 93-step native matrix exited 1 with four failed steps: `astra_response_review`, `native_cli_e2e`, `signer_e2e` and `signer-probes`. The other 89 steps passed, including formatting, strict Clippy and documentation checks.

The unchanged special-mode test passed separately as described above. Native CLI E2E (5 tests), signer E2E (6 tests), and all four ignored signer resource probes also passed separately outside Seatbelt with a clean environment and synthetic credentials. The sandbox run's real-sshd connections were reset, and its CPU probe could not execute `ps`; the supplemental results distinguish those environment restrictions from product failures. This combined evidence is not a single full unsandboxed-matrix PASS.

## Homebrew verification

The first actual Homebrew build succeeded. `brew test` passed both CLI help checks but the demo failed five child-execution assertions: its Unix runtime sockets were outside the directory that Homebrew's test sandbox permits. The failure is preserved; it was not converted into a PASS.

An attempted adjustment at `bd0cf7a91c5b12d5245b4ad60832ef25302115f9` set the formula test's `TMPDIR` to `testpath`. Its disposable snapshot matched tree `c6b011a1fc37c139db5bf7fc64e90003a38fd919`. The unchanged five demo checks still failed. Source inspection shows the exec launcher creates its ACK socket with `tempdir_in("/tmp")`, so it does not honor that override. The ineffective formula change was removed; no assertions or sandbox rules were relaxed.

Both real Homebrew build attempts passed; both `brew test` attempts exited 1. Record **OSS-HOMEBREW-ACK** as open: the launcher's short ACK socket path must work with the Homebrew test sandbox without dropping the child-execution assertions or weakening isolation. A bounded fix needs launcher/path-boundary tests, actual Homebrew revalidation and a new exact-head review. The final formula returns to the `03a989f` contents.

All native matrix, supplemental and archive checks have finished. This validation slice is complete, but release preparation remains incomplete: Homebrew tests and the preserved Opus findings block a readiness claim.
