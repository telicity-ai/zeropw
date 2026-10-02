# Astra persisted-project acceptance and signal compatibility addendum

Actual reviewer: `gpt-6-astra`, 2026-09-22. No Opus verdict is claimed.
Projects fix reviewed: `cb8821580b45b889aabe7379d26c39c1b81662fc`
(actual Sol source `5734edf`). Final source comparison:
`3bfb7e8ac1d3113cb6b51128dc90e57da50b2981`; `projects.rs` is unchanged.
This report adds evidence without rewriting the PO checklist or earlier
runtime/finding reports. All test state and values are synthetic.

## A-R2-6(b): resolved in current full-port scope

Bounded verdict: **PASS for the persisted-project compatibility fix**.
`Project.environments` now retains JSON values and `created_at` retains its
original JSON value. Loading iterates strings by Unicode scalar character,
arrays by element, and dictionaries by insertion-order key, matching Python's
successful `tuple` conversion. `require_environment` compares the requested
string to an actual string element; it does not turn numbers, booleans, nulls
or containers into matching environment names. Normal create validation and
timestamp-string output remain intact.

New independent `astra_projects_final` measures actual Python `get`, `list`
and `require_environment` against native library results for six persisted
projects: mixed arrays (including nested empty containers), Unicode text,
deliberately unsorted dictionary keys and all three empty iterable kinds.
Creation-time values include null, false, number, string, object and nested
array. Project listing remains sorted by name while dictionary environment
keys retain on-disk order. Ten environment queries per project test success
and refusal without coercion. Actual original and native administrator
`project list` outputs match as parsed JSON. A normal newly created project
retains validated environments and a nonempty timestamp string on readback.

The independent negative test covers null, boolean, integer and float
environment fields plus either missing required field. Original Python
`get`/`list`/`require_environment` raise TypeError or KeyError; Rust fails closed
as `state_corrupt` under PORTING section 3.5. Native administrator listing
exits 1 with the safe `state_corrupt` reason. Each case leaves `projects.json`
byte-for-byte unchanged. No exact built-in error subclass equivalence is
claimed for that allowed error mapping.

The changed implementation-owned old strict-shape test is justified: its five
removed refusal expectations described successful Python cases and enforced
the now-obsolete first-half waiver. The remaining noniterable/missing-field
refusals remain tested, and the successful cases are covered by actual oracle
comparisons instead. The unchanged earlier Python edge-case oracle also
passes. The cross-language timestamp assertion merely accesses the retained
string through `Value::as_str`; its original length assertion is preserved.
No reviewer-owned historical assertion was changed.

Fresh offline, clean-environment checks:

| Suite | Result |
| --- | --- |
| New `astra_projects_final` | 2 passed |
| Worker `project_persisted_compat` | 1 passed |
| `state_dir_cross_language` | 6 passed |
| Library `projects::` | 17 passed |
| Clippy on new independent test, warnings denied | passed |
| `git diff --check` | passed |

These 26 selected passes close the checklist's persisted-project gate. They
do not constitute whole-product or Linux acceptance. Initial authoring errors
in the new review test (non-ASCII byte literal, then Cow/String collection)
were corrected before these successful runs; no product change was needed.

## AR-CLI-05 — P3: handled SIGINT exit status differs

This is a separate compatibility finding, not a reopening or severity change
of AR-CLI-03. AR-CLI-03's termination and restored-terminal criteria remain
resolved in their measured scope.

Evidence already measured in the immutable round-four controlling-PTY/FIFO
oracle at product `318386de404ccbff4cdd8c3e0a79dbb1a4aa25e0`: after successful
password input, original Python exits with code 130 and native Rust terminates
from signal 2 (`subprocess.Popen.returncode == -2`). Both restore terminal
modes. Python `admin_cli.py:1916–1917` explicitly catches KeyboardInterrupt and
returns 130; Rust's conditional default handler restores OS signal termination.

PO disposition: **fix required for full observable CLI parity**. Shells may
display status 130 for both, but subprocess supervisors distinguish normal
exit 130 from signal termination. A handled Python CLI outcome is not an
uncaught-exception case, and no existing allowed deviation covers this change.
The active-prompt restoration tests did not assert exact exit-code parity and
cannot establish it by passing alone.

Fix criteria: preserve exit 130 for ordinary administrator SIGINT, including
active and completed password prompts, while preserving terminal restoration,
noecho-before-prompt, EOF/error behavior, SIGTERM behavior and `serve`'s
deliberate signal-to-graceful-stop handling. A forthcoming signal fix must be
independently verified; this report does not approve unreviewed signal changes.

Only this report and `rust/tests/astra_projects_final.rs` are added. No product,
old report/test, CI, harness, working specification or trusted checkout edit;
no merge, push or deployment. Remaining local compatibility ID recorded here:
AR-CLI-05/P3, pending its separate fix/review.
