# Astra PTY timeout diagnostic integrity review

- Actual independent reviewer: `gpt-6-astra`.
- Sol diagnostic commit: `ba7bb364164354d18d97ca2298ccab0901ff37ba`.
- Integrated revision: `d560488782eba343954ac133262ef83beb23baba`; the round-three fixture is identical to the reviewed worker file.
- **Accepted only as bounded diagnostic instrumentation. No original Linux cause, product fix, or overall acceptance is established.**

The change preserves the existing single Ctrl+C/EOF stimulus, eight-second child wait, failure result and exact terminal-restoration assertion (including its existing PENDIN treatment). It records a prewrite process-group/termios snapshot without introducing a wait or retransmission, and prints timeout metadata only when the original child wait raises TimeoutExpired, then rethrows. The original keeper wait bound also remains. Prewrite observation necessarily adds a small amount of work and can affect scheduling; a later passing run alone would not establish a fix.

Metadata is limited to child/keeper process IDs and groups, terminal foreground group, ISIG/ECHO/VINTR/VEOF, and on Linux selected child `/proc/status` fields (`State`, `SigPnd`, `ShdPnd`, `SigBlk`, `SigIgn`, `SigCgt`) plus `wchan`. No environment, command-line, input, credential, arbitrary process or application-state inspection is added. Diagnostic errors report exception type rather than arbitrary exception content. The pre-existing TimeoutExpired traceback still describes the synthetic test command/state path; this patch does not expand it to environment values.

## Independent forced-failure measurement

The reviewer extracted the proposed embedded Python driver into a disposable invocation without editing any fixture or product file. Immediately after its prewrite snapshot, the probe disabled ISIG on this synthetic PTY, then retained the original single Ctrl+C write. A synthetic environment sentinel was supplied solely to check that diagnostics did not expose it.

Observed on local macOS / Python 3.12.11: **exit 1 after 8.05 seconds**. The original `timed out after 8 seconds` failure remained. `PTY_TIMEOUT_DIAG` showed the child process group equal to the terminal foreground group, ISIG false and ECHO false; the earlier snapshot showed ISIG true. The synthetic environment marker was absent from stdout/stderr. This proves that the diagnostic path reports the controlled injected condition without converting failure to success. It is not reproduction of the hosted Linux mechanism.

The Linux-only `/proc` branch was reviewed in source, not executed locally. The worker separately reports round-three 3/3 and strict Clippy/fmt passing. Its first diagnostic draft used parent-side `tcgetpgrp(slave)`, which raised ENOTTY on macOS; the reviewed final version uses guarded `tcgetpgrp(master)` and retains slave termios inspection. This instrumentation correction is not a product or historical CI correction. No additional independent full-suite result is claimed here.

The earlier failure evidence in `astra-pty-linux-second-triage.md` remains unchanged. The next exact-head Linux run must either provide useful failing-state evidence or passing results with appropriately limited interpretation. Neither this review nor the forced probe justifies an arbitrary sleep, retry, skipped oracle, direct-signal substitution, longer assertion deadline or CI change.
