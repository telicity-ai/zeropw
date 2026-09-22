# Astra SIGINT status recheck and owned-directory finding

Actual reviewer: `gpt-6-astra`, 2026-09-22. No Opus verdict claimed.
Product fix: `80c7eea201d7e7a5ad5bde70840b22aadd65815e` (Sol `c3801e9`).
Tested checkout: `019b92e1704a6b326cd04a0d23de5daa0c90d6e3`; the intervening
commit changes PTY test mechanics/reporting only, not product source.

Decision: **CHANGES REQUIRED** for new AR-CLI-06/P2 below. AR-CLI-05/P3 is
resolved for its measured exit-status criterion. AR-CLI-03 remains resolved
for termination and terminal restoration. No historical report is rewritten.

## AR-CLI-05 — P3 — resolved status behavior

The native SIGINT handler now exits 130; the active prompt watcher restores
terminal modes before exiting 130. Ordinary commands register handling even
when an environment passphrase bypasses prompting. `serve` retains its own
graceful stop path. Independently reran `admin_sigint_exit`: **3 passed**,
8.45 seconds, covering original Python/native active and completed prompts,
ordinary nonterminal FIFO input and graceful serve shutdown. SIGINT is 130 for
ordinary operations; SIGTERM retains signal termination; serve exits 0 for
both. Existing round-three/four/final prompt suites also passed immediately
before this review at the same product source.

This is exit-status/TTY evidence, not a claim that `std::process::exit` runs
Rust destructors or performs all the cleanup Python's handled interruption
does. The following direct measurement distinguishes those claims.

## AR-CLI-06 — P2 — SIGINT leaves Context-owned temporary directories behind

Locations: `admin_cli.rs` conditional-shutdown registration and active watcher
exit; `context.rs` `private_tempdir`, `owned_dirs`, and `Drop::drop`.

Python catches KeyboardInterrupt, returns 130 and runs registered atexit
cleanup. Native conditional shutdown exits from the signal path; the prompt
watcher's `std::process::exit(130)` similarly bypasses stack destructors.
Context removes its owned run/socket directories only through explicit close
or Drop. Thus status parity is achieved without its ordinary interruption
cleanup behavior.

New independent regression:
`astra_sigint_cleanup::ordinary_sigint_removes_context_owned_runtime_directories`.
It runs the actual original/native administrator `secret put --stdin` with a
synthetic environment passphrase and an anchored FIFO. Each child gets its
own empty TMPDIR. The test observes both owned Context directory prefixes
before sending SIGINT, then checks exit status and only that child's directory
contents. It does not scan shared system temp directories or delete by glob.

| Actual product | Exit | Owned directories before | Owned directories after |
| --- | --- | --- | --- |
| Original Python | 130 | `zeropw-runs-*`, `zeropw-sockets-*` | none |
| Native Rust | 130 | `zeropw-runs-*`, `zeropw-sockets-*` | both remain |

The preliminary probe and retained regression reproduce the same result.
Both products produce no stdout/stderr; no secret export, cross-UID access
or leaked authentication material is claimed. This is demonstrated resource
cleanup/behavioral parity failure. The test's enclosing synthetic TempDir
removes its own fixture contents after observation.

Fix criteria: after ordinary SIGINT, clean only Context-owned runtime
directories before exit 130, including prompt and nonprompt paths. Preserve
user-configured/unowned directories, TTY restoration, clean failure behavior,
SIGTERM semantics and graceful serve shutdown. Do not run filesystem work
directly inside an async signal handler or use prefix/glob cleanup over a
shared temporary root. A safe owner-scoped normal-thread cleanup path is
required; verify its negative ownership boundary as well as the unchanged
new reproduction. No full unwind or transactional rollback guarantee is
inferred from this bounded requirement.

Executed with clean inherited environment and explicit Cargo/Python paths:
new regression **0 passed, 1 failed**, 1.00 second; strict Clippy on the test
passes; `git diff --check` passes. All state/passphrases and child processes
are synthetic/local. Only this report and its new regression are added.
No product/old assertion/CI/harness/trusted-checkout edit, merge or deployment.
AR-CLI-06 remains open pending a fix and independent rerun; Linux final-head
verification and full acceptance remain separate coordinator gates.
