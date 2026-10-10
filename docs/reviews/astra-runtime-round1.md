# Astra runtime review, round 1

Date: 2026-09-22. Reviewer model: `gpt-6-astra`, independent runtime reviewer.
Decision: **REVISE**. This is an Astra review under the latest full-port user decision, not an Opus review or a complete-product acceptance.

Reviewed base: `b3d7384eaaa3072eb3b32ef2d7de9cef4bd864be`. During the review, concurrent CLI/team work advanced HEAD to `391efb4240088611420fdac5c98b1d72ed5c30fe`; `git diff b3d7384 HEAD -- rust/src/runs.rs rust/src/tools.rs rust/src/server.rs rust/src/context.rs` was empty. The final targeted tests below ran at that latter HEAD with the new independent review test uncommitted. This review does not approve the concurrently changed CLI/team code.

Scope: `rust/src/runs.rs`, `tools.rs`, `server.rs`, their Context attachment, compared to `zeropw/runs.py`, `tools.py`, `server.py` and the relevant Python tests. Product/security/implementation/harness documents and `rust/PORTING.md` were read. Only disposable synthetic state and loopback endpoints were used; test commands ran with an empty inherited environment and an explicit executable search path. No product source was edited.

## Findings

### AR-RUNTIME-01 — Medium — Installed run registry disappears when its return value is dropped

Location: `rust/src/runs.rs:188` (`install`), particularly the weak attachment at line 198; `rust/src/tools.rs:66` (`registry`). Python reference: `zeropw/tools.py:96`, `install`.

Python attaches the registry strongly to `ctx.runs`; callers can simply call `tools.install(ctx)` and then use the tools. Rust attaches only `Weak<RunRegistry>` and the revocation callback also retains only a Weak. `tools::install(ctx.clone());` therefore immediately leaves `runs::registry(&ctx)` as `None`. Subsequent `exec`, `status`, and `cancel` report `runs_not_installed`. Dropping the last external registry owner also discards finished-run history and the request-ID map while the Context remains alive. The HTTP server's extra strong owner masks this public installation defect in the existing tools/server tests.

Reproduction: `ar_runtime_01_installation_survives_discarded_return_value` fails. The corresponding Python probe printed `registry_survives: True`.

Fix criteria: keep installation and its run/idempotency state alive for the Context's lifetime, with explicit noncyclic ownership and cleanup. Cover discarded return values, repeated install, completed-run lookup/replay, revocation callbacks, and final Context cleanup.

### AR-RUNTIME-02 — Medium — Child spawning loses Python's separate-session boundary

Location: `rust/src/runs.rs:474`–`483`, especially `.process_group(0)` at line 482. Python reference: `zeropw/runs.py:306`–`308`, `start_new_session=True`.

Creating a process group does not create a new session. Rust children remain members of the coordinator's session; Python creates a session led by the child. This changes controlling-terminal and session/signal lifecycle behavior for programs run from an interactive server. It is a regression in the existing process boundary, not a claim that separate sessions alone provide the host isolation required for production deployment.

Reproduction: the synthetic child prints `os.getsid(0) == os.getpid()`. Rust prints `False`, and the corresponding Python registry probe prints `True` with state `completed`. `ar_runtime_02_child_leads_a_new_session` fails.

Fix criteria: spawn into a new session while preserving clean environment, closed unrelated descriptors, and group-directed cancellation. Keep the implementation compatible with the project's safe-spawn constraints; add session and controlling-terminal coverage plus cancellation regression checks.

### AR-RUNTIME-03 — Low — HEAD framing-error responses incorrectly carry a body

Location: `rust/src/server.rs:383`–`402`, hardcoded `"GET"` at lines 387 and 397. Python reference: `ZeroPWHandler._refuse_framing` and `_send` in `zeropw/server.py`.

When parsing rejects a request after reading its valid HEAD request line, the Rust error path loses the method and calls `send_json` as GET. A HEAD request containing `Transfer-Encoding: chunked` consequently receives the JSON error body. Python returns the same 400 status with zero response-body bytes. This breaks the HEAD wire contract even though normal HEAD responses are covered by the existing tests.

Reproduction: `ar_runtime_03_head_framing_error_has_no_response_body` fails with the `transfer_encoding_unsupported` JSON body; the equivalent Python socket probe returned `HTTP/1.1 400 Bad Request`, body `b''`.

Fix criteria: preserve the parsed method through framing/status errors and suppress bodies for HEAD. Cover malformed headers, duplicate/unsupported framing, and absolute-URI errors after a valid HEAD request line.

### AR-RUNTIME-04 — Low — Optional sanitized HTTP request logs were omitted

Location: `rust/src/server.rs:57`–`61` and the response path, which expose no equivalent of `quiet`/`log_lines`. Python reference: `zeropw/server.py:151`–`160`, `425`–`428`; original test `tests/test_gateway.py:1014`, `ServerRouteTests.test_server_logs_never_contain_handles_or_queries`.

Python offers `ZeroPWServer(ctx, quiet=False)` and records method plus query-free path, replacing handle-bearing routes with `/h/<handle>/...`. The Rust server has no configurable request log or retrievable log entries. Always suppressing logs avoids disclosure, but loses original observable functionality and cannot satisfy the original test's nonempty/redacted log assertions.

Evidence: direct public API and source comparison; no equivalent Rust API exists to call in a runtime regression yet. This is a functionality gap, not an observed secret leak.

Fix criteria: restore optional sanitized logging with quiet as the default, and port the original assertions for nonempty logs, fixed handle redaction, query removal, and credential absence. Do not introduce raw request/header/body/error logging.

## Verification and limits

Command from `rust/`:

```sh
env -i PATH=${HOME}/.local/bin:${HOME}/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin ${HOME}/.cargo/bin/cargo test --offline --test runs --test tools_server --test astra_runtime_review --no-fail-fast
```

- Existing `runs`: 13 passed.
- Existing `tools_server`: 17 passed.
- New independent `astra_runtime_review`: 2 passed, 3 failed. The failures reproduce AR-RUNTIME-01/02/03 and are intentionally left as acceptance regressions.
- Passing independent checks: idle keep-alive shutdown closes the client and listener promptly; a non-ASCII upstream ETag is filtered before server serialization. The latter disproves a preliminary UTF-8-versus-Latin-1 concern because the gateway's ASCII value gate prevents that path.
- Python probes independently establish durable installation, new-session spawning, and empty HEAD error bodies.
- Original Python `ServerRouteTests.test_server_logs_never_contain_handles_or_queries`: 1 passed (0.164s), confirming the logging behavior cited in AR-RUNTIME-04.

The existing passing suites exercise bounded capture, timeout/cancellation escalation, queued cancellation, owner scope, idempotency under concurrency, start/finish audit failures, known credential-output encodings, profile scanning against all vault values, pre-spawn policy rechecks (including setup-time corruption), fixed SSH arguments/public-key files, HTTP framing, authentication failure audit, admission caps and request read deadlines. The code comparison checked the corresponding return/audit/error paths; these statements describe measured coverage, not universal equivalence.

Not tested in this review: externally reaped-child/`try_wait` error injection; a server-stop race against an already-processing tool request; controlling-terminal attack behavior under a PTY; descriptor inheritance under every platform; every original Python case and malformed-input combination; deployment isolation; live service integrations. Source shows `try_wait` errors are discarded in supervision, but this review does not assign an additional finding without a bounded reproduction. The native HTTP/SSH/team process end-to-end suites are being handled independently by the coordinator and are not claimed here.

The number of Rust smoke cases is not evidence that every original Python behavioral assertion has been ported. In particular, optional server logging has a concrete original test with no Rust counterpart. Full functionality acceptance remains blocked on the findings and the coordinator's remaining whole-product coverage.

Changed files in this review: `rust/tests/astra_runtime_review.rs`, this report. Unresolved review IDs: AR-RUNTIME-01, AR-RUNTIME-02, AR-RUNTIME-03, AR-RUNTIME-04.
