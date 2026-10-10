# Astra bounded Linux Python TTY-read readiness review

- Actual independent reviewer model: `gpt-6-astra`.
- Independently executed worker source: `c5c191a3a3822958a2fc2b006ce4034c1441da56`.
- Integration source: `cd17bf10e06ac0b02ed54831882a108e95b4cb57`. A direct diff confirmed identical product source, the three affected test files and CI workflows between these two revisions.
- **Accepted within source review and measured macOS fixture coverage; actual Linux observer execution remains pending.** This is not full product or Linux acceptance and does not establish the historical timeout's cause.

## Historical failure remains evidence

The independently retrieved log for Linux run `35720818752`, job `106723053700`, at `6becf5a2cda6fd07e80ec0456e75bd77dac4a686` records `astra_cli_runtime_round3`: **2 passed, 1 failed**, 8.18s, exit 101. The failure was the original-Python interrupt branch waiting eight seconds for its administrator child. It was not a demonstrated Rust terminal-restoration failure; that branch failed before the same test could proceed to Rust.

At timeout, child PID/process group 10383 matched terminal foreground group 10383; keeper PID/group was 10381. ISIG was enabled, ECHO disabled, VINTR was byte 0x03 and VEOF byte 0x04. Kernel pending/blocked signal fields were zero; SIGINT was caught, not ignored. `wchan` was `wait_woken`. Prewrite foreground and terminal flags agreed. These observations do not explain the precise signal/syscall interleaving and are not rewritten as a pass.

Separate bounded research found that a signal already delivered to CPython's C handler immediately before `_Py_read` can leave an interpreter-level pending signal while the subsequent read blocks. Local CPython **3.12.11**, not hosted 3.12.14, reproduced 5/5 pipe and 5/5 PTY cases with an intentional C shim; 5/5 already-blocked-read controls instead interrupted normally. The relevant source sequence was checked in 3.12.14. This establishes a possible mechanism, not natural getpass or hosted-CI causality. Reproducible driver, C source, primary-source links, bounds and limits are retained outside the checkout at `/tmp/astra-cpython-read-window.wmOuV0/`.

## Intentional test-phase correction

The Linux original-Python **interrupt** case now requires both the visible prompt and an observed positive-length read on its controlled terminal within the same original five-second startup deadline. This identifies the oracle's active-read phase instead of assuming prompt output proves that phase. The native immediate-prompt stimulus and EOF paths remain unchanged in this respect: no new PID pipe or blocking PID-readiness wait is used there.

The keeper explicitly reports its actual `Popen` child PID through a dedicated pipe, rather than inferring identity from the foreground group. The observer requires that PID to be its own process-group leader and current terminal foreground group. It checks Linux `SYS_read` supplied by Rust's target-specific `libc` constant, positive read length, a descriptor resolving to `/dev/tty` or the controlled slave terminal, ECHO off, ISIG on and VINTR byte 0x03. Generic `running` and short `-1 <sp> <pc>` syscall states remain not-ready; neither is parsed as a read. Missing ABI information, denied/unavailable process metadata or failure to reach readiness fails diagnostically, without fallback or skipped assertions. Raw buffer/register addresses, argv and environment are not logged by the observer.

The observer uses the existing startup deadline; it does not start a new five-second allowance. There is still one original PTY Ctrl-C byte, no replacement `kill(SIGINT)`, no resend or retry-until-pass, and no arbitrary fixed sleep before stimulus. The keeper's eight-second wait and existing terminal-mode comparison remain. Readiness failure cleanup targets only the explicitly reported child group when its foreground/session identity matches the fixture. No product, Python oracle implementation, harness, CI or job timeout was changed.

This reviewer identified an intermediate draft issue: PID metadata was awaited after the prompt for all modes, adding a new wait to native/EOF paths. The final `observe_read` condition confines pipe creation, relay and waiting to the Linux Python interrupt observer. No remaining concrete objection was found in the final scoped source review. The syscall snapshot is not atomic with the later input write; no universal race-elimination claim is made.

## Shared fixture consumers and controls

Both `include_str!` consumers were inspected: `astra_pty_portability.rs` forwards the target syscall constant while retaining its ignored/blocked SIGINT launch cases; `astra_runtime_final.rs` forwards the argument and retains its exact keeper-wait anchor, nonzero child-exit assertion, second-prompt boundary and terminal-mode checks. Its native EOF/invalid-input/interrupt scenarios do not enter the Linux Python observer. The self-derived negative controls use an explicit replacement anchor so they fail if fixture extraction/conditioning changes unexpectedly.

New controls cover missing syscall ABI, denied `/proc` access, and normal non-read `running`/`-1` states. Linux-only controls additionally require rejection of a prompt followed by `pause()` and a prompt followed by a read from an unrelated pipe, and acceptance of an actual positive-length read from `/dev/tty`. All preserve the actual stimulus/assertion path rather than treating any visible prompt or blocked process as ready.

## Independent execution

On macOS, at exact worker commit `c5c191a3a3822958a2fc2b006ce4034c1441da56`:

```text
env -i PATH=${HOME}/.local/bin:${HOME}/.cargo/bin:/usr/bin:/bin ${HOME}/.cargo/bin/cargo test --offline --test astra_cli_runtime_round3 --test astra_pty_portability --test astra_runtime_final
```

| Target | Independently observed result |
| --- | --- |
| `astra_cli_runtime_round3` | 4 passed, 5.21s |
| `astra_pty_portability` | 1 passed, 0.37s |
| `astra_runtime_final` | 1 passed, 0.14s |

**Six test functions passed.** The macOS run forced the observer branch for missing ABI, synthetic permission denial and injected `running`/`-1` states, verifying their explicit rejection paths. It did **not** execute Linux `/proc` observation or the Linux-only actual-read, pause and unrelated-pipe controls. Worker/root formatter and Clippy results are not substituted for independent execution here. The reviewer accidentally built a fresh default worker target; after the completed run its newly generated artifacts alone were removed with targeted `cargo clean`. Reusable validation caches and source were untouched.

The coordinator separately reported that its first affected run at `cd17bf1` had round3 **3 passed, 1 failed** in 9.54s: the unchanged runtime-07 output assertion observed empty final stdout. Python interrupt, EOF and observer rejection controls passed in that run. The coordinator's unchanged focused runtime-07 rerun passed in 2.56s and its unchanged three-target rerun passed 6/6 (5.19s/0.35s/0.14s). Those coordinator-reported results are distinct from this reviewer's execution above. The cause of that runtime observation remains unestablished and is not resolved by this observer review or by successful retries.

No new product finding or assertion waiver is recorded by this scoped observer review. Final Linux execution must establish that the real observer and its Linux-only controls work on the final candidate, followed by the complete required gates and disposition of the separate runtime observation. Only this unique review report was added by the reviewer; previous failure reports and evidence remain unchanged.
