# Astra serve-signal fixture readiness correction

Actual reviewer: `gpt-6-astra`, 2026-09-22. This is a bounded fixture correction,
not a product change, changed graceful-exit assertion or whole-product PASS.

The coordinator reported CI run `35705000593` passing all 1,099 original Python
product tests and the harness tests, but failing the new worker-owned native
comparison `administrator_serve_keeps_its_graceful_signal_stop`: original Python
returned 130 for SIGINT while native returned 0; both returned 0 for SIGTERM.
The other two signal-status comparisons passed in that Linux run.

Source explains the invalid readiness assumption. Original Python
`admin_cli.run_serve` emits its startup payload before registering SIGINT and
SIGTERM handlers. Native `admin_cli::main` registers both stop flags before
calling `run_serve`, whose payload therefore follows registration. Reading the
Python banner alone does not establish readiness for graceful signal handling.

Independent deterministic measurement against the actual original Python
administrator used a test-only wrapper around `signal.signal`. The wrapper
delegated registration unchanged and exposed a dedicated pipe barrier:

| Signal delivery point | Original Python result |
| --- | --- |
| After banner, paused immediately before first handler registration | Exit 130; one startup payload line; no stderr |
| After actual SIGTERM registration, with installed SIGINT handler verified | Exit 0; one startup payload line; no stderr |

Neither probe uses a sleep to establish readiness. This reproduces the
observed outcome through the exact source ordering; it does not claim the
historical CI log recorded the precise scheduling interleaving.

The repaired worker fixture launches the original Python administrator through
a test-only wrapper that observes calls to the real `signal.signal`. After
actual SIGTERM registration, it verifies both installed handlers are the
observed callable objects, restores `signal.signal` itself, and writes a byte
to a dedicated inherited pipe. The parent requires that byte before sending
the tested signal. Original handlers, their saved previous handlers, command
arguments and output remain unchanged. Native still uses its valid startup
payload readiness point. Python remains a test oracle, never a native backend.

The original five-second startup budget now covers both payload and handler
readiness through one monotonic deadline. No timeout was increased. All four
Python/native SIGINT/SIGTERM cases still require exit 0 and empty stderr;
neither status 130 nor a skipped case is accepted. The other two worker signal
tests and all immutable Astra assertions remain unchanged.

Fresh macOS offline clean-environment verification: all **3 admin_sigint_exit
tests passed** (9.84 seconds); strict Clippy, file rustfmt check and
`git diff --check` passed. Tested checkout before this fixture commit was
`76050ca3df58fa79f656d4f7a20faa52e22521bd`. Final-head Linux CI is still required.

Only `rust/tests/admin_sigint_exit.rs` and this report changed. No product,
CI/harness, historical review or immutable assertion edit; no unrelated Linux
VM, production credentials, merge or deployment. This does not close the
separate AR-CLI-06 owned-directory cleanup finding.
