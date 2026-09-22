# Astra second Linux PTY failure triage

- Actual reviewer: `gpt-6-astra`.
- Inspected product/fixture: `8be0103f08556954e30fd9a651101607d2682bc8`.
- Linux run `35717335672`, Rust job `106711817003`.
- **Failure confirmed; exact hosted signal-loss mechanism remains unobserved. No product defect or fixture correction accepted by this report.** Earlier PTY findings, normalization evidence and successful runs remain unchanged.

## Observed hosted result

The job exits 101, not by its overall CI time limit. `astra_cli_runtime_round3` reports two passed and one failed in 8.21 seconds. The failure is `ar_cli_02_interrupt_restores_original_terminal_modes`, in the **original Python** branch. Captured PTY output contains `Administrator passphrase:` followed by the keeper's `subprocess.TimeoutExpired`: original Python initialization did not exit within its eight-second wait. The Rust branch of that individual comparison was not reached. EOF restoration and output-publication cases pass; preceding native signal/cleanup tests also pass. Those successes do not override this failed oracle comparison.

The failure log does not record the foreground process group, terminal signal flags/control characters, delivered/pending SIGINT, or blocked Python stack. It cannot distinguish those mechanisms. In particular, it is not evidence that the original Python process ignored a delivered signal, that Rust leaked terminal modes, or that eight seconds is too short for a normally delivered interrupt.

## Source inspection

The fixture already resets SIGINT to default and unblocks it in the foreground child's pre-exec setup; sets a separate child process group and makes it foreground; sends exactly one Ctrl+C byte after observing the prompt; and compares original/final termios, masking only macOS PENDIN. The keeper remains in the controlling session. These facts do not prove the runtime values on the failed Linux runner.

Original administrator `_passphrase` calls standard-library getpass; its main handler returns 130 for KeyboardInterrupt. Local CPython 3.12.11 getpass applies ECHO-off using TCSAFLUSH **before** `_raw_input` writes/flushes the prompt and calls readline. The coordinator independently verified the same relevant ordering in CPython 3.12.14. Therefore a claim that original getpass prints its prompt before disabling echo is unsupported. A signal/check/blocking-read interleaving is a possible hypothesis, not a demonstrated cause.

## Finite local measurement

Using Python 3.12.11 on macOS, this reviewer extracted the unchanged round-three embedded driver and ran its original-Python interrupt branch ten times against separate temporary state. The only instrumentation printed `os.tcgetpgrp(master)`, `ISIG`, and `VINTR` immediately before the existing Ctrl+C write. All **10/10 passed**, preserving the one-byte stimulus, eight-second child deadline, and terminal-restoration assertions. Each observed ISIG enabled, VINTR equal to Ctrl+C, and a nonzero foreground process group. Aggregate shell duration was 0.83 seconds.

This neither reproduces the Linux failure nor establishes correct foreground child identity on that runner. No retry-until-green acceptance is inferred. No product, existing fixture/assertion, harness or CI file was edited; this report is the sole artifact.

## Bounded next diagnostic

On a failing Linux execution, capture foreground/child process-group identities and termios ISIG/VINTR at the existing write point, and signal disposition/mask/pending state plus a child stack on timeout. A separately configured failure-only diagnostic signal can request a Python stack without substituting for the original interrupt assertion. Continue to fail on the original eight-second condition. Evidence should identify the mechanism before selecting a correction; an arbitrary sleep, another Ctrl+C, direct-signal substitution, skipped oracle or increased deadline is not justified by this investigation.

Final same-head Linux acceptance remains blocked. MacOS component/full-suite evidence remains valid only in its stated source/platform scope.
