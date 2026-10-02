# Astra team port review, round 1

- Actual reviewer model: `gpt-6-astra`. No Claude Opus review was performed or claimed.
- Reviewed product commit: `06cf76f665937da557bf7a0272dbbc2d07735569` in `/Users/ys/Code/zeropw-rust-team`.
- Review date: 2026-09-22.
- Scope: defensive code-quality and compatibility review of Rust `team/transport.rs`, `team/sync.rs`, and `team/membership.rs` against the Python modules and their existing tests. The full-port requirement supersedes the old first-half exclusion in `rust/PORTING.md`.
- Result: **NOT ACCEPTED; bounded review, incomplete coverage.** Five reproduced findings remain open. No product code was changed. The added regression file intentionally fails on the reviewed commit.
- Review artifacts: `rust/tests/astra_team_review.rs` and this report. These are working-tree additions on the product commit above, not claims about a later integrated commit.

## Reproduction

Run from `rust/`:

```text
/Users/ys/.cargo/bin/cargo test --offline --test astra_team_review -- --test-threads=1
```

Last run: compilation succeeded; **0 passed, 5 failed**, finished in 9.70 seconds, exit status 101. All credentials, keys, and state were synthetic and temporary. The tests do not contact external systems. Python probes use `python3.12` and the repository's own Python modules. `rustfmt --edition 2024 rust/tests/astra_team_review.rs` was then applied; it changes formatting only.

The first run's T3 fixture accidentally had a payload length requiring no base32 padding and failed its fixture assertion. That run was not evidence for T3. The corrected second run explicitly verifies Python accepts a padded representation and reaches the Rust acceptance assertion, which fails. The T3 evidence below is from that corrected run.

## Confirmed open findings

### ASTRA-TEAM-T1 — P2 / Medium — An accepted invite can panic the join operation

Location: `rust/src/team/membership.rs:362`; parser context at lines 204–240. Python counterpart: `zeropw/team/membership.py:join`, the default project expression using `payload['inviter'][:8]`.

`parse_invite` accepts an arbitrary string as the inviter. `join`, when no project override is supplied, slices that string at byte offset 8. An otherwise parseable synthetic invite with inviter `aaaaaaaé` causes a panic because offset 8 is inside the final UTF-8 character. Python slices characters and proceeds to its normal no-address error. This is an input-handling failure in an administrative operation, not evidence of remote code execution or a remotely reachable service crash.

Evidence: `astra_t1_untrusted_unicode_inviter_cannot_panic_join` first verifies the Python parser accepts the invite, then invokes Rust join within `catch_unwind`. Rust reports:

```text
panicked at src/team/membership.rs:362:62:
end byte index 8 is not a char boundary; it is inside 'é' (bytes 7..9 of string)
```

Fix criteria: implement character-based slicing consistent with Python, and return the existing documented error for malformed or undialable input without a panic. Keep the original severity and reproduction evidence. The regression must pass without requiring the caller to supply a project override.

### ASTRA-TEAM-T2 — P2 / Medium — Live local emergency facts lose their audit record

Location: `rust/src/team/sync.rs:917` through the return at line 928. Python counterpart: `TeamSync.publish_fact` calls `_audit_fact_apply` after persistence and refold.

Rust persists and applies a locally published emergency fact but never calls `audit_fact_apply`. The inbound path and the no-live-TeamSync membership path do record the event. Thus the audit result depends on which supported execution path the caller used, and the live path lacks the Python event identifying the author and fact kind.

Evidence: `astra_t2_live_fact_publication_records_apply_audit` initializes a synthetic environment, registers a live TeamSync object, successfully publishes `connection_disabled`, and counts `team_fact_apply` in `audit/audit.jsonl`. Actual count is **0**, expected **1**.

Fix criteria: emit the same event, fields, order, and failure handling as the Python live publication path. Check connection disabling, secret revocation, and member removal rather than fixing only the particular test target.

### ASTRA-TEAM-T3 — P2 / Medium — Standard padded base32 invitations are rejected

Location: `rust/src/team/membership.rs:51`–68. Python counterpart: `_b32d` accepts standard base32 padding using `base64.b32decode`.

The Rust decoder treats `=` as an invalid alphabet character. Python accepts both the application's unpadded output and a standard padded representation of the identical invite. This is an externally observable parsing incompatibility, not an allowed cryptographic implementation deviation.

Evidence: corrected `astra_t3_padded_base32_invites_match_python` generates standard padded base32 from a synthetic invite, verifies that padding exists and Python `parse_invite` accepts it, then receives a Rust error instead of success.

Fix criteria: reproduce Python's accepted padding and input normalization while still rejecting malformed encodings. Add malformed-padding checks alongside the padded and unpadded successful cases. Do not treat a DEVIATIONS entry as a waiver of the equivalence requirement.

### ASTRA-TEAM-T4 — P3 / Low — Fact conversion rejects Python's valid string-pair input

Location: `rust/src/team/sync.rs:218`–231. Python counterpart: `Fact.from_dict`, which calls `dict(data['target'])` before stringifying keys.

Python accepts a sequence of two-character strings as dictionary pairs: `['ab', 'cd']` becomes `{'a': 'b', 'c': 'd'}`. Rust only accepts arrays with two entries. This is a public conversion-contract difference. The demonstrated fact target does not pass incident schema verification; this finding does not claim an authorization bypass or acceptance of an invalid signed incident.

Evidence: `astra_t4_fact_target_dict_string_pairs_match_python` uses the actual Python `Fact.from_dict(...).to_dict()` as oracle. Python returns the object; Rust returns `InvalidInput(team_fact_malformed)`.

Fix criteria: use or extend the canonical Python mapping-conversion helper to cover valid Python values at the same scope, preserving later schema validation. Section 3.5 does not justify this rejection because Python returns a value rather than raising.

### ASTRA-TEAM-T5 — P2 / Medium — Saved invites with ISO expiry no longer work

Location: `rust/src/team/membership.rs:316`–318. Python counterpart: `consume_invite` invokes `_parse_expiry`, which accepts numeric timestamps and ISO UTC timestamp strings.

Rust only calls `as_f64` on the persisted expiry. A valid unused invite with an ISO UTC expiry is silently skipped, despite valid wrapped secret and transcript proof. Python explicitly supports this saved-state representation. The current create path normally writes numeric expiry; this finding concerns compatibility with the Python-supported stored representation, not a claim that current Python create always writes strings.

Evidence: `astra_t5_iso_expiry_invite_state_matches_python` creates temporary state containing a synthetic KMS-wrapped invite secret, a valid matching HMAC, and `expires_at='2099-01-01T00:00:00Z'`. The Python `_parse_expiry` probe succeeds. Rust `consume_invite` returns **None**, expected **Some(("user", "synthetic"))**. The Python `consume_invite` source calls that parser before checking expiry.

Fix criteria: support both Python expiry forms, preserving invalid/expired/used handling, transcript binding, and atomic one-time consumption. Exercise the complete consumption operation against the Python-supported state representation.

## Unfinished observations, not reproduced findings

These are follow-up review leads, not additional confirmed test results or acceptance evidence:

- `dial_attempt` at Rust sync lines 1990–2009 has no successful-dial removal of `backoff` and `next_attempt`; Python `_dial_attempt` clears both before wiring the session. A bounded deterministic retry regression is still needed.
- Rust socket reads use `read_exact` with socket timeouts, while Python `_recv_exact` recalculates the time remaining against an absolute deadline. Deadline equivalence requires a bounded local transport test. No slow-drip or external network testing was performed in this review.
- New direct `serde_json::from_slice/from_str` calls in team transport, membership, and fact-file loading require checking against the established canonical `pyjson` parser contract. No complete nesting/number/input-shape matrix was run.
- Full concurrent multi-peer receive, restart, fact reapplication, DEK rotation, removed-member drain, incident retry, and override-notification tests were not completed in this turn.

## Mapping and coverage limits

The Rust public operations exist for transport listen/dial/session lifecycle, environment discovery and mapping, signed facts, vector/commit/fact/peer processing, incident outbox/ack/retry, sharing, invitations, joining, member removal, DEK rotation, status, and compaction. Presence of these APIs is not evidence of behavioral equivalence.

| Python test source | Existing Python cases | Direct Rust coverage seen at reviewed commit | Remaining acceptance gap |
| --- | ---: | --- | --- |
| `test_team_transport.py` | 14 | 3 tests in `team_transport.rs`: in-process exchange, TCP exchange, nonmember rejection | Removed members, environment mismatch, low-order ephemeral input, replay, signature-role separation, frame tampering, connection cap, default refusal |
| `test_team_sync.py` | 26 | Parts of one combined membership/sync test | Two-way catch-up, three-node relay, offline conflict convergence, mutual removals, receive-only drain, exec/signer revocation effects, wire leak sweep, session renewal, sanitizer boundaries, retry persistence, override exactly-once |
| `test_team_membership.py` | 12 | Combined test covers join/decryption, invite reuse rejection, self-removal | Expiry, transcript mismatch, sharing/grant reevaluation boundaries, admin removal and new-generation confidentiality, concurrent removal |
| `test_team_facts.py` | 5 | Canonical fact bytes/hash and basic sign/verify plus live fact propagation | Full CLI fact-vs-commit behavior, ledger replay/dedup, backup/restore reapplication |
| `test_team_snapshot.py` | 4 | One compaction test preserves protected init and resulting document | Automatic snapshot threshold, lagging-member block, append after compaction gap |
| `test_team_e2e.py` | 1 | No new run by this reviewer | Root coordinator separately runs the original assertions against native binaries; its result must be reported independently |

These six files contain 62 Python test methods. The two direct Rust team networking integration files contain 7 test functions total; some combine several assertions, so counts alone do not establish one-to-one absence or coverage. Existing data-layer Rust tests were not counted as networking proof. Every applicable original case still needs a mapped Rust test or an equivalent native executable test run, including the original failure-boundary assertions.

The full suite was not completed by this reviewer. No previous PASS, DEVIATIONS entry, or successful compilation resolves the open IDs above. Fixes require a fresh review and tests bound to their exact new head SHA; root integration and native end-to-end results remain separate evidence.
