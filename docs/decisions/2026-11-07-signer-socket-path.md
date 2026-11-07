# Signer socket path and fallback ownership decision, 2026-11-07

Astra product/compatibility decision by actual `gpt-6-astra`: approve a narrow
correction to runtime socket-directory selection and fallback ownership. This is
not an implemented fix, passing test result or Opus review. The source inspected
is the parent `rust/src/signer.rs` and `rust/src/context.rs`; no worker checkout
or product execution was used.

The coordinator's static diagnosis is
`zeropw-mlp-evidence/macos/signer-path-static-diagnosis-20261107.md`.
It relates three retained native d942 signer/context failures to a long v2 TMPDIR.
Relevant source equals the earlier baseline; no saved evidence establishes the
baseline's exact TMPDIR string. Do not claim the original baseline reproduced
this path condition or change TMPDIR to hide the failures.

`choose_socket_dir` currently normalizes the preferred path and checks a
24-character probe against `MAX_UNIX_PATH` (100). `bind` generates
`a<12-hex>.sock` (18 characters) and separately rejects more than
`MAX_UNIX_PATH + 3` characters. The selection probe can therefore reject a
preferred directory even when its real socket pathname fits the existing
100-character selection budget. Fallback creates a fresh private `zpws-*`
directory, but `SignerManager` stores only its path; Context owns only its own
default directories, and fixture cleanup covers only its own subtree.

## Bounded behavior decision

- Replace the artificial 24-character selection probe with the actual generated
  basename length, derived from the same naming contract as `bind`. Retain the
  **100-character selection budget** and the separate existing bind-time guard;
  do not widen limits, shorten random identifiers or change socket names. Thus a
  normalized preferred path is selected when its actual generated socket path
  fits the selection budget. Exact cases formerly accepted remain accepted.
- Preserve pathlib-style normalization, character-count semantics, atomic 0700
  leaf creation, existing error behavior outside this narrow selection change,
  and the OS bind's own pathname/encoded-byte enforcement. This decision does not
  promise that every multibyte path under a character limit is OS-bindable.
- Represent fallback ownership explicitly. Only a directory freshly created by
  this manager's fallback is owned by it. Preferred/caller-supplied directories
  remain borrowed even if the helper creates their leaf; Context-owned defaults
  remain Context-owned. Never infer ownership from a `zpws-` prefix, location or
  existence, and never recursively remove a caller-owned directory or parent.
- Hold an ownership guard for the fallback through the manager's lifetime.
  `shutdown` must close/join its listener/client resources as before. Final
  manager teardown removes only its owned fallback after those resources stop;
  failed manager construction also cleans any owned fallback. Do not change
  shutdown into a terminal API or delete its directory while a still-live manager
  can bind again. Preserve existing weak-reference lifecycle and avoid new cycles.
  Test shutdown followed by final drop as the complete cleanup boundary.
- This is an intentional narrow runtime deviation from the legacy 24-character
  heuristic, to be documented with the implementation. No existing persisted
  vault/state, signed/wire/canonical bytes, crypto, CLI authentication boundary,
  SSH destination binding or prototype fixture meaning changes. No secret-file
  fallback or new plaintext delivery path is authorized.

## Required evidence before acceptance

Keep and rerun the three original failing signer/context tests unchanged. Add
behavioral tests for preferred paths where the real 18-character basename fits
but the old 24-character probe does not; exact selection-budget boundary and one
over; normalized repeated separators/dot components; unchanged multibyte counting
and OS refusal; and fallback selection for a genuinely overlong preferred path.
Use deterministic path lengths in isolated temporary roots, not the host's
incidental short TMPDIR. Preserve original mode and actual socket-path assertions.

Exercise actual bind/release/shutdown, then final manager and Context teardown:
owned fallback gone, sockets gone, caller directory and sentinel files preserved,
Context defaults cleaned by Context, multiple managers isolated, repeated shutdown
safe, and rebind on a live manager after shutdown retaining existing behavior.
Cover errors after fallback creation so construction cannot leak it. Confirm no
active listener/client uses a removed directory and no shared parent is deleted.
Cleanup on abrupt process kill is not promised by a destructor; do not relabel
that as tested orderly cleanup.

Run the unchanged original failures and focused boundaries in isolated macOS and
Linux, then unchanged full `rust/verify.sh` on both exact revised sources. Preserve
failed logs and report platform/runtime details. Passing selection tests alone
cannot close the native signer/context failures or establish two-Mac acceptance.
Root owns implementation and verification; this note authorizes no harness/CI
change and does not accept outstanding link REVISE findings.
