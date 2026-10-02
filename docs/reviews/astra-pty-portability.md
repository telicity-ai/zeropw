# Astra controlling-PTY fixture portability

Actual reviewer: `gpt-6-astra`, 2026-09-22. Bounded test-fixture diagnosis;
no product fix, CI/harness change or new product acceptance verdict.

The coordinator reported Linux CI run `35703888623`, Rust job
`106668064498`, failing round-three active Ctrl-C restoration in the
**original Python** branch: the child remained at its administrator prompt
until the keeper's unchanged eight-second timeout. EOF and terminal output
publication passed. That historical CI failure remains recorded; it is not
relabeled as a native product defect or a passing run.

The fixture sets a foreground process group and resets SIGTTOU but originally
left SIGINT's inherited disposition and mask unchanged. Ignored dispositions
and blocked masks survive exec. Python preserves inherited SIG_IGN, so the
fixture cannot assume a Ctrl-C byte will generate an actionable interrupt.
Inspected local Python 3.12 `getpass.unix_getpass` clears ECHO but does not
clear ISIG; the tested fixture's issue can occur without a getpass change.

Independent macOS measurements used the exact embedded original Python
round-three script and actual `zeropw.admin_cli`, synthetic state and real
controlling PTYs:

| Controlled inherited launch state | Original fixture | Normalized child fixture |
| --- | --- | --- |
| Default SIGINT | Pass | Pass |
| SIGINT ignored | Same eight-second child timeout | Pass |
| SIGINT blocked | Same eight-second child timeout | Pass |

This proves a fixture dependency and reproduces the reported failure form;
it does **not** prove which disposition/mask the Linux runner used, because
the historical log did not record that information. Local Python is 3.12.11;
the coordinator reports CI Python 3.12.14. No unmeasured claim about their
getpass implementations being identical is needed for the controlled
inheritance reproduction. Linux validation requires the next actual CI run.

Approved fixture-only correction: in the controlled foreground child's
pre-exec setup, set tested signals to SIG_DFL and unblock them. Round three
normalizes SIGINT; round four normalizes SIGINT and SIGTERM because it tests
both. The keeper and caller are unchanged. The product's own handlers still
take effect after exec. No ignored signal is converted into a false success.

Preserved exactly: writing the actual Ctrl-C byte through the PTY, prompt
synchronization, process-group/controlling-terminal topology, all timeout
values, EOF input, and the original full terminal-state comparison (including
its preexisting macOS PENDIN exception). Original reports remain immutable.
The new `astra_pty_portability` regression injects SIG_IGN and blocked SIGINT
into each outer fixture invocation and requires both original Python and
native children to pass those unchanged assertions.

Fresh offline clean-environment macOS results: round three **3 passed**,
round four **4 passed**, new portability **1 passed** (four launches), final
recovery-prompt boundaries **1 passed**. Strict Clippy for the new test and
`git diff --check` pass. No unrelated Linux VM was used or changed; only its
availability was inventoried before the coordinator excluded it from scope.

This correction is not a relaxation of the AR-CLI-02 restoration assertion,
and it does not close the separately pending AR-CLI-05 exit-status finding.
Final-head Linux CI remains an acceptance gate.
