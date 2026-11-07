# Astra bounded signer acceptance, 2026-11-07

**Decision: the implementation matches the approved bounded design. Full
two-platform acceptance is not granted.** Actual assessor: `gpt-6-astra`.
This is source/design assessment and reconciliation of retained worker evidence,
not Opus review or an independent execution of the tests.

Assessed commit: `bd065fc4c66a79133a2b7f24f462200858080b60`, Rust tree
`2882ba592e2204eb62723d95e240525e75196f64`, against base
`410ce9b603ec956b5afeba84bbf4d30e87810f02`. Only `rust/src/signer.rs` and
`rust/DEVIATIONS.md` changed. Contract:
[signer path decision](../decisions/2026-11-07-signer-socket-path.md).

Read-only Git comparison confirms:

- Selection and binding share `a<12-hex>.sock` construction; selection retains
  the 100-character limit, bind retains its separate 103-character guard, and
  normalization, Unicode character counting, OS bind refusal, randomness and
  atomic 0700 creation remain in place.
- `SocketDirectory::Borrowed` never owns preferred leaves or Context defaults.
  A guard is armed only after a fresh fallback mkdir, before fallible abspath
  and chmod. Failed construction drops that guard.
- Shutdown still closes existing resources and permits rebind. Final manager
  drop calls shutdown before field cleanup; the owned guard removes only an
  empty leaf using `remove_dir`, without recursive deletion or prefix inference.
  Ownership adds no strong reference to Context or manager. Retained bindings
  or manager references must actually be released before final-drop cleanup.
- Eight new tests cover actual boundary sockets, one-over fallback, multibyte
  OS refusal, shutdown/rebind/last-owner and independent-manager lifetimes,
  caller/default ownership, post-mkdir failure and nonrecursive cleanup.
  The existing normalization test still asserts the exact selection boundary,
  now using the actual basename contract rather than the superseded heuristic.
- The three originally failing test bodies are independently byte-compared and
  unchanged: `teardown_leaves_no_socket_file_listener_or_signer_created_directory`,
  `teardown_leaves_no_socket_file_or_signer_created_directory`, and
  `signer_socket_dir_matches_configured_directory_under_this_machines_default_tmpdir`.
  Git objects for Context, `rust/verify.sh` and `rust/tests/fixtures` are unchanged.

No design mismatch requiring another signer change was found. Cleanup remains
orderly teardown only: unexpected nonempty contents or filesystem removal errors
can leave the owned leaf behind. This is preferable to recursively removing
unowned contents and is explicitly documented, not a universal no-leaks claim.

## Source-bound execution evidence and limit

Worker: actual `gpt-6.1-sol`. Evidence root:
`/Users/ys/Code/zeropw-mlp-evidence/signer-path-fix-20261107/`.
`REPORT.md`, `source-bindings.json`, `validation.json`, `source-expected.json`,
`SHA256SUMS`, and per-platform logs/manifests retain the execution record.
The assessor read the report and independently checked the source/test bindings;
no product code was executed for this assessment.

| Platform | Exact final-source result |
| --- | --- |
| Isolated macOS 26.6.2 arm64 Tart guest, SIP disabled | Full unchanged verification PASS: exit 0, all 100 steps, 1,634 passed, 0 failed, 4 ordinary ignored; all four signer probes explicitly passed |
| Isolated Ubuntu 24.04.4 arm64 VM | Full unchanged verification FAILED: exit 1, 99 successful steps and `test:tools_server` failed; 1,630 passed, 1 failed, 4 ordinary ignored; all four signer probes explicitly passed |
| Focused signer scope, both platforms | All eight new tests and three unchanged regressions passed, also passed within both full matrices |

Both final sources used private 57-character TMPDIR paths; the macOS path has
the same length as the failing native v2 path. This evidence does not rely on
shortening the tested temporary root to conceal the original failure. Separate
short roots in new boundary tests explicitly construct the requested path lengths.

Linux failed the unchanged `original_public_url_and_expired_grant_contract` at
`rust/tests/tools_server.rs:1242`: after a one-second grant and 1,100 ms sleep,
`tools::exec` returned a running result instead of `grant_expired`. Its root cause
is unresolved. Unchanged source and a macOS pass do not prove it is harmless or
flaky; preserve the failed run and investigate independently. The prior Linux
`945e6a6` PASS cannot be substituted for this commit's failed full verification.

The report records matching 634-file before/after manifests on both platforms.
It preserves other temporary residues and claims no broad cleanup success. The
native full Rust pass does not supply native desktop packaging, physical two-Mac
acceptance, deployment, M1/M2 acceptance or resolution of the link REVISE findings.
No original Opus report, finding severity or test assertion is changed by this
assessment. The coordinator may integrate the bounded signer implementation while
keeping full two-platform verification and release acceptance open.
