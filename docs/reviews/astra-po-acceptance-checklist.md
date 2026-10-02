# Astra PO acceptance inventory

Actual reviewer: `gpt-6-astra`, 2026-09-22. Inventory snapshot:
`34acd3e2f307d0854ef45f6c05c525526a2b165c`; latest SMTP product revision:
`55f95de0eec36d5261542fc6510c22be752eb726`. No Opus verdict is claimed.
This is a bounded source/evidence audit, not a new test run or blanket PASS.

**Acceptance remains pending.** The current SMTP envelope finding is open;
final integrated/macOS/resource checks and current-head Linux CI remain gates.
There is also a concrete outdated scope justification in the persisted-project
deviation that needs current-scope disposition below. An implementation commit
or a historical green PR check alone cannot close these gates.

## Feature inventory and wiring

| Existing Python feature group | Native implementation and evidence boundary |
| --- | --- |
| Store, projects, errors, audit, handles | Matching Rust modules are linked through `lib.rs`; canonical JSON/string/base64/integer helpers and differential tests support persistent/wire equivalence. Final integrated first-half rerun remains required. |
| Crypto, KMS, vault, backup/restore/recovery | Matching native modules plus `secret.rs`; SSH wire's adapter now calls `crate::crypto::ed25519`, and vault shared decryption calls the team envelope implementation. No remaining stub was found in these integration points. |
| Policy, gateway, signer, SSH wire | Native modules retain HTTP delegation and separate SSH signing; no universal CLI support is asserted. Real-sshd process evidence and signer resource tests are separate obligations from ordinary unit success. |
| Execution and five agent tools | `runs`, `tools`, `server`, `agent_cli` implement list-connections/request/exec/status/cancel. Native session helper is a required shipped binary, located beside the executable. Runtime review is bounded PASS at source `318386d`. |
| Incident, intrusion, notification | Native modules and internal `smtp`; serve installs the detector, polls control/revocation state and retries notifications. Response behavioral coverage is accepted within its mapped scope; envelope compatibility is still open. |
| Team data/networking/lifecycle | All eight original team modules have native counterparts. Optional team listener, authenticated sessions, membership, facts, snapshots, sync and containment have 62-method mapping plus independent supplements. Team review is bounded PASS. |
| Administrator, agent, demo/example CLI | Native admin/agent/demo entry points call Rust library functions directly; native demo business CLI is separate. Original black-box adapters retain assertions and count native launches. Dynamic Python module-removal fixtures are explicitly inapplicable to static linkage; native setup failures still must fail explicitly. |

Source scan found no `todo!` or `unimplemented!` product placeholders, and no
Python product backend. Python-spawning sites inspected are under test-only
modules (`oracle` itself is `cfg(test)`); production subprocess sites are the
native session helper, its requested fixed CLI, and `/usr/bin/id -u` for file
ownership checking. This is source evidence, not a runtime syscall trace.
Module presence is not treated as proof of every behavior.

Cross-unit source checks are coherent: `run_serve` opens Context, requires
writable audit, retains detector installation, starts TeamSync only when a
team listener is requested, constructs the native tools server, polls control
changes, enforces withdrawal and retries pending notifications. Team shutdown
and server shutdown are explicit. Runtime publication/ownership/audit checks
and native live-signer incident tests provide behavioral evidence for these
connections; this inventory did not repeat them.

## Current finding ledger

All original IDs/severities remain unchanged. This ledger covers the current
Rust completion reviews and coordinator CLI contract, not the superseded
September 12 design/Opus reports. Those historical documents remain preserved
and provide no new implementation approval.

Evidence keys identify actual committed reports and their tested source:

- **RT**: `astra-runtime-final.md`, report commit
  `7642b8e40dde6e7de9ea0b1e69e882137122af36`, product
  `318386de404ccbff4cdd8c3e0a79dbb1a4aa25e0`; 74 selected tests plus private-mode
  repeat and Clippy. Prior rounds remain immutable.
- **CLI**: `astra-cli-runtime-round2.md`, report commit
  `7e0452fa06febd551d3344656a5d61a782f3c1ee`, reviewed integration
  `7536e49647fe322e954f37d65a530d9cd2b5499f`; separates independent C1 rerun
  from source review plus coordinator original-suite evidence for C2–C10.
  Subsequent original native CLI runs supplement, not rewrite, that report.
- **RESP**: `astra-response-round4.md`, report commit
  `a6e3e9e0babb0e4c59c529a8e5c6677617b70a10`, tested integration
  `584ac71d1db4cbae19d2f13eba5ec8398ee4d487`, fix `4a526a2`. Later immutable
  `astra-response-final.md` retains its closures at product `318386d`.
- **MAIL**: `astra-response-final-recheck.md`, report commit
  `34acd3e2f307d0854ef45f6c05c525526a2b165c`, tested product
  `55f95de0eec36d5261542fc6510c22be752eb726`.
- **TEAM**: `astra-team-round4.md` and its additive supplement
  `astra-team-round4-addendum.md`, supplement report commit
  `4b504f04e718b863a5117f9ce8080aaba9c50f18`; unchanged team source from
  `a6e3e9e` through tested runtime product `318386d`; 104 native checks and
  original native three-process lifecycle. The interrupted round-three review
  remains partial historical evidence.

| IDs | Original severity | Current disposition / evidence |
| --- | --- | --- |
| AR-RUNTIME-01, AR-RUNTIME-02 | Medium | Resolved in bounded macOS scope, RT; descriptor completion also tracked by AR-RUNTIME-05. |
| AR-RUNTIME-03, AR-RUNTIME-04 | Low | Resolved, RT: HEAD errors and sanitized optional logs. |
| AR-RUNTIME-05 | P1 | Resolved in tested macOS descriptor boundary, RT; Linux verification pending. |
| AR-RUNTIME-06, AR-RUNTIME-07, AR-RUNTIME-08 | P2 | Resolved, RT: independent ACK location, atomic output publication, creation-time private modes. |
| AR-CLI-01, AR-CLI-02, AR-CLI-03 | P2 | Resolved, RT: noecho timing, active interruption restoration, post-prompt signals. |
| AR-CLI-04 | P3 | Resolved, RT: offline root/subcommand help and literal exec tail. |
| CLI-C1 | P1 | Resolved, CLI: audit-only restoration preserves revocation. |
| CLI-C2, CLI-C3, CLI-C4 | P2 | Resolved by the documented source/coordinator evidence, CLI: authentication/denial/rotation audit. |
| CLI-C5, CLI-C6, CLI-C7, CLI-C8, CLI-C9, CLI-C10 | P2 | Resolved by the documented source/coordinator evidence, CLI: version detail, SSH canonical keys, URL/error mapping, backup parent, safe corrupt-state detail and TTL. Final original CLI rerun remains integration evidence. |
| R-INTRUSION-LIFETIME, R-SMTP-PARSER | P1 | Resolved, RESP; closures retained in MAIL's unchanged original suites. |
| R-SMTP-CRAM, R-SMTP-AUTH, R-SMTP-RECIPIENT, R-SMTP-HELO, R-SMTP-ERRORS | P2 | Resolved for original findings, RESP/MAIL. |
| R-SMTP-ENVELOPE | P2 | **Open**, MAIL: sender/recipient `sen(comment)der@example.com` emit unquoted local-part whitespace rather than Python's quoted mailbox. Original domain fix passes; local-part regression fails. A forthcoming worker fix is not yet accepted. |
| R-INTRUSION-OVERFLOW, R-INCIDENT-CORRUPT, R-INCIDENT-SHAPE | P2 | Resolved for measured state/number cases, RESP/MAIL. |
| R-NOTIFY-MODE, R-SMTP-SECRET-LIFETIME | P2 | Resolved, RESP/MAIL; secret ownership includes source inspection, not a memory-dump proof. |
| R-RESPONSE-COVERAGE | P2 | Resolved for original behavioral map and missing live signer assertion, RESP; not universal coverage. |
| R-NOTIFY-COUNTER, R-INTRUSION-CONFIG | P2 | Resolved for accepted precision/configuration inputs, RESP/MAIL. |
| ASTRA-TEAM-T1, ASTRA-TEAM-T2, ASTRA-TEAM-T3, ASTRA-TEAM-T5 | P2 | Resolved, TEAM. |
| ASTRA-TEAM-T4 | P3 | Resolved, TEAM. |

## Accepted shape distinctions and outstanding specification debt

The two team constructor rows are valid native API-shape distinctions:
`InProcessTransport::new` and `TcpTransport::new` require an explicit typed
membership callback; supplying an empty callback is measured fail-closed.
Rust cannot express Python's omitted callback argument, but the protected
behavior remains. Likewise static module availability differs from Python
monkeypatching `sys.modules`; removal of an actual runtime feature would not
be justified by that distinction.

**Current-scope disposition needed: persisted project shapes.**
`projects.rs:253–267` and the `project_from_entry` row of `DEVIATIONS.md`
explicitly preserve rejection of Python-successful string/dict environments,
non-string environment entries and non-string creation times. Their stated
justification excludes administrator CLI from scope. That premise is now
false: native `admin_cli.rs:899` lists projects through this strict loader and
serializes its fields. The existing `python_oracle_confirms_load_get_create_edge_cases`
already measures Python success for these shapes. This is a concrete stale
scope justification and source-visible behavior difference, not a newly
executed CLI reproduction or a claim of ordinary well-formed project loss.
Unlike an unrepresentable constructor call, persisted JSON is representable
input. Do not count this row as an approved full-port exception without a
current-scope decision or correction. No new product finding severity is
invented by this inventory; the existing A-R2-6(b) reference is retained.

Other documentation debt is visible but does not establish missing code:
`DEVIATIONS.md` still describes a crypto stub and an unported vault although
the inspected modules and adapter are implemented. `RESPONSE_TEST_MAP.md`
labels its lower matrix historical; read its supplement and later RESP
dispositions before treating those old gap cells as current failures.
`docs/rust-completion.md` likewise predates the latest closures. Update the
working completion record after final evidence; preserve immutable reviews.
The recorded MIME serialization difference means no byte-identical MIME
claim is warranted; decoded content/authentication checks are the documented
response evidence, and that row cannot waive an envelope destination defect.

## Final gates

1. Close R-SMTP-ENVELOPE through actual Sol implementation and independent
   Astra rerun of every immutable mailbox reproduction plus the measured
   Python corpus; record source/report SHAs. Do not substitute a hardcoded
   expected corpus or discard successful Python outputs.
2. Resolve the persisted-project deviation's obsolete scope premise and
   document its current full-port disposition with evidence.
3. Finish the coordinator's integrated suite, original native CLI/API/real-sshd/
   team/response scenarios, long policy oracle, Clippy and explicit four
   ignored signer resource checks. The reported retry of default library
   tests (503 passed, four ignored) does not execute those resource checks.
   The earlier loaded-host latency failure remains recorded; an unchanged
   clean rerun supports diagnosis without relaxing its bound.
4. Bind final evidence to the final product head, accounting for later SMTP
   changes through unchanged-source comparison and fresh affected checks.
   The in-progress frozen-318 run cannot itself approve changed SMTP code.
5. Obtain Linux CI/platform checks on the same final head. PR 6's older
   `04a5634` green result is not current proof. Record real SSH exercise rather
   than treating a missing-sshd skip as success.
6. Publish a final factual acceptance record separating measured component
   passes, accepted shape differences, remaining deployment/host-isolation
   limits and full-product decision. Merge and deployment remain separate.

Only this checklist was added. No product, existing review/test, working
specification, CI, harness or trusted-checkout files were changed; no new broad
fuzzing, external service, production credential, merge or deployment was used.
