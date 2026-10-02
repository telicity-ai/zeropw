# Astra owned-directory cleanup recheck

Actual reviewer: `gpt-6-astra`, 2026-09-22. No Opus verdict claimed.
Product fix reviewed: `c71ec3d2589fae8e21a9131647ce771ef2a130db`
(actual Sol source `17c1995`). Final observed comparison:
`ec58f8d82b6c0e437c61b3bda2561bcafce6b0a7`; Context is identical and the
administrator source differs only in an explanatory SIGTERM comment.

Decision: **PASS for bounded AR-CLI-06/P2 cleanup remediation**. Its unchanged
independent original reproduction now passes: both original Python and native
administrator exit 130 and leave no Context-owned run/socket directories.
AR-CLI-05/P3 exit status and earlier prompt/runtime dispositions remain
resolved in their previously stated scope. No new product finding was
demonstrated. This does not approve whole-product integration or final Linux CI.

## Ownership and signal lifecycle

Ordinary administrator Context creation opts into a private registry. Generic
Context constructors and `serve` remain on their original ownership path.
Default-directory creation stays at its original point after state/key setup;
the new option does not pre-create temporary directories before validation.
The same mutex covers creation and exact-path registration. Closing an opted-in
Context removes and unregisters its owned paths. User-configured directory
paths never enter this registry. Shutdown marks the registry closed and drains
it under that mutex, so a concurrent later create cannot leave an unregistered
directory after shutdown has completed. Cleanup does not enumerate prefixes
or glob a shared temp root.

SIGINT's asynchronous callback wakes one process-lifetime normal thread;
filesystem cleanup is performed by that thread. It does not discard a queued
signal based on a later prompt-phase flag. The watcher holds the shared
terminal-state mutex while restoring any active prompt, cleaning owned paths
and exiting 130. Prompt setup and restoration use that same mutex, preventing
another thread from disabling echo after signal restoration but before exit.
The prompt-local watcher handles SIGTERM only; outside a prompt its conditional
default action remains armed. This review does not claim full Rust unwinding
or transactional rollback on SIGINT.

The new independent `astra_sigint_cleanup_final` verifies that two unowned
directories with matching runtime prefixes and their synthetic sentinel file
bytes survive while the actual Context-owned directories disappear. This is
tested for original Python and native processes. Its second case verifies
missing state and short initialization passphrases fail with their original
safe reasons, create no temporary directories and leave the absent state path
absent. The existing opted-in registry unit test separately proves actual
configured paths survive registry shutdown/Context close, and post-shutdown
creation is refused. No private seam was exposed merely for this review.

Existing worker tests independently rerun here cover ordinary success/error
cleanup, active-prompt cleanup with noecho and restored modes, exact SIGINT
130/SIGTERM termination, and graceful serve stop. Immutable prompt tests retain
their original assertions with only the separately approved launch-readiness
fixture corrections. EOF, invalid UTF-8 recovery input and repeated prompts
pass. The earlier fixture failures and original AR-CLI-06 report remain
immutable historical evidence.

## Fresh evidence

Offline Cargo, empty inherited environment with explicit Cargo/Python/system
PATH; all state, files, passphrases and processes are synthetic/local.

| Suite | Result |
| --- | --- |
| Immutable `astra_sigint_cleanup` | 1 passed |
| New `astra_sigint_cleanup_final` | 2 passed |
| `admin_sigint_cleanup_boundaries` | 2 passed |
| `admin_sigint_exit` | 3 passed |
| `astra_cli_runtime_round2` | 3 passed |
| `astra_cli_runtime_round3` | 3 passed |
| `astra_cli_runtime_round4` | 4 passed |
| `astra_runtime_final` | 1 passed |
| `agent_help` | 2 passed |
| Library `context::` | 5 passed |
| `runs` | 17 passed |
| `runtime_fix_boundaries` | 2 passed |
| Strict Clippy for the new independent test | passed |
| `git diff --check` | passed |

The unchanged run tests retain audit-failure output suppression, terminal
publication, ownership/idempotence, cleanup, spawn/session and process-group
cancellation checks. Broader tools/native E2E/full-suite execution belongs to
the coordinator's separate final-head run and is not counted here. No timing
threshold or failure assertion was relaxed. Arbitrary filesystem/kernel
failures and every possible scheduling interleaving are not exhaustively
injected.

Only this report and `rust/tests/astra_sigint_cleanup_final.rs` are added.
No product, earlier report/test, CI, harness, instruction or trusted-checkout
edit; no merge, push or deployment. Unresolved IDs in this bounded remediation:
none. Final-head Linux/platform and integrated acceptance remain separate.
