# Required-generation implementation and assigned native validation

Actual implementation model/settings: **gpt-6.1-sol / ultra**, T3 Code through the Codex harness. No subagents, workflows, model/provider substitution, Opus/Astra invocation, review/recheck/replacement or publishing action was used. This report is implementation/test evidence, not review or acceptance.

**Overall validation remains INCOMPLETE.** Linux was explicitly NOTASSIGNED / NOTRUN and was not queried or waived. An earlier valid wide-single-commit resource trial timed out at 1800 seconds and remains incomplete under its own exact source. The final allowed implementation and final native matrix are delivered separately from that residual. All M2/runtime/review/physical/Oracle/release gates remain OPEN.

## Source and inputs

HEAD remains base `8ca2cf0163bc7b3c9681d9a0df4e9f4b81e820e0`; no new commit exists. The tested result is the uncommitted artifact, not that base HEAD. Complete final source: 1328 regular files. Changes: 3 existing files, 4 new source/test files, 58 new fixture files, 65 total; every other baseline byte/blob/length/POSIX/executable mode stayed frozen. Desktop tree remains `2413844c89265a3e239be2372d34b1e6e1b2d4bb`.

Computed Git tree IDs (DATA computation, no object/ref/index write): full `a9670b198e985c98d0247be749d6e08d89748bdc`, Rust `4352ebbd0fa84bde0fb444c4d0902ef2510d0620`. The computation was checked against the known complete base tree.

| Input | Verified SHA256 |
| --- | --- |
| `/tmp/zeropw-required-generation-sol-20261108.md` | `b82706b1bf2fafc262ae93da047503eb21a1680d965fa4fd453ae90fc028ef39` |
| `/Users/ys/Code/zeropw-mlp-evidence/m2-required-generation-astra-20261108/decision.md` | `d4f80f910a3209b4d4399e302f8c63c65316ae78a06421f46043bacf9630b158` |
| `/Users/ys/Code/zeropw-mlp-evidence/m2-required-generation-astra-20261108/implementation-task.md` | `4d8990b5c6a38ff7c6224c7c1e734998a18b8416c579b211d9489663e40ed1c8` |
| `/Users/ys/Code/zeropw-mlp-evidence/required-generation-native-preparation-20261108/assignment.json` | `421b2659cd9005a2d032e50bde843a58ef332478a616119500ed344f35822115` |
| `/Users/ys/Code/zeropw-mlp-evidence/required-generation-native-preparation-20261108/setup-result.json` | `212e88712d4c4ec7b504f26b53ef321e8eb63dab7b3cbf2151920d4f2577ce7b` |
| `/Users/ys/Code/zeropw-mlp-evidence/required-generation-native-preparation-20261108/prestage-audit.stdout` | `d4a71e53a866435c749cef595bab6cd52cfbede165e15c83bb409e722d0d5e18` |

Both hash-bound actual Astra documents and the brief were read in full. Assignment/setup/audit receipts were read and hash-verified. All 1266 base files/blobs/bytes/modes matched before edits. The prepared source/cache audit is attributed preparation evidence; the worker independently rehashed all 172 public crate archives and 8194 extracted files against Cargo.lock/archive/metadata in phase 09 and again after validation, with identical results. Source/helper/dependency/fixture/formatter/build/test execution occurred only in the assigned fresh Mac501 job, UID501, fixed clean environment, offline/locked/jobs1/debug0/incremental0 and 57-byte TMPDIR. Host work was Git/stdlib DATA/text/control only. No production vault/model/deploy/recovery/administrator keys were requested or inspected.

## Implemented assurance

Added `verify_required_generations(&CompleteCutSemanticCandidate, &DeviceKey)` and opaque `RequiredGenerationCandidate`. The result borrows the exact immutable complete candidate and privately owns only required DEKs as SecretBytes plus aggregate counts. Its stage is `required_generation_ciphertexts_checked_not_admitted`, trust is `administrator_attested`; public observations are only the prescribed candidate bindings/revision and aggregate generation/ciphertext counts. No constructor, Clone/Default/Serde/Value/raw-byte conversion, key/plaintext/document getter, callback, install/use/receipt/Facts/provenance conversion or runtime caller was added. Debug is fixed redaction.

The function derives and compares the full recipient record, including sign_pub/agree_pub/sig, with the local binding and authenticated device table, and checks signed fingerprint. It inventories every final active/staged version of every nondeleted secret and checks exact equality with the private required summary. It indexes actual trace positions/selected spans, requires each exact original effective selector and final canonical wrap binding, and rejects required explicit unavailability. Compatible size preflight precedes unwrap. Every selected required historical/effective wrap must authenticate to 32 bytes and constant-time agree with the effective key. Every required ciphertext is authenticated with the existing exact AAD/helper; returned Vec allocations immediately enter SecretBytes, and each plaintext is dropped before the next blob. No partial result is returned. Nonrequired history remains unassessed and unchanged. Empty-required still checks recipient binding and performs zero unwrap/decrypt calls.

Envelope changes are ownership-only guards for named unwrap shared/key and HKDF MAC/PRK/block/output buffers, wiping replaced blocks and truncated tail before discard. Public signatures, crypto/wire/parsing/errors and original tests are unchanged. The entire legacy semantic verifier body and original envelope tests were byte-compared with baseline; public envelope signatures match. All old 145/149/97 fixture entries remain exact. No dependencies/features/raw_value/parsers/primitives/fold/runtime/UI/harness/CI/instructions/review files changed.

Cleanup assurance is scoped to new owned buffers and named envelope temporaries on normal completion/error/unwind. Crypto dependency internals, by-value/compiler/register/allocator/OS copies, swap/core dumps, abort/SIGTERM/power loss and physical erasure are not proved. Unit counters measure calls, not erased bytes. A Rust type is not process isolation; a future caller must run in a separately protected trusted backend, never with agent-submitted code. Borrowing a snapshot is not a freshness lock.

AEAD-valid empty/non-UTF8/malformed-SSH bytes may pass; all four stored kinds participate. Independent existing SSH parsing rejects the malformed SSH sample. This is authenticated retrieval-byte assurance, not provider/header/SSH signing readiness. Secret AAD still binds env/secret/version, not kind/generation; original signed wrap generation binding remains mandatory, and identical DEK bytes under distinct labels have that documented limit. SSH signing remains unchanged and core.

## Validation

Final unchanged native `rust/verify.sh`: **111 steps / 106 integration targets / 1819 passed / 0 failed / 5 ignored**, exit 0. Actual source-derived ordered begin/end markers match all 111 steps and 106 targets. Full-suite totals were parsed from this one final run only; overlapping focused phases are not summed. Exact final host/guest source bytes/modes match before/after this run. Formatting, strict Clippy, lib/bins, every discovered integration target, four ignored signer probes and docs are included.

| Phase | Exit | Seconds | Test summaries: passed/failed/ignored | Exact final source bytes |
| --- | --- | --- | --- | --- |
| `01-lib-check` | 0 | 39.020 | No completed test summary | False |
| `02-new-compile` | 101 | 40.720 | No completed test summary | False |
| `03-new-compile` | 0 | 14.618 | No completed test summary | False |
| `04-fixture-generation` | 101 | 13.618 | 0/1/0 | False |
| `05-fixture-generation` | 0 | 45.097 | 1/0/0 | False |
| `06-new-debug` | 0 | 379.648 | 5/0/1; 14/0/0 | False |
| `07-format` | 0 | 1.639 | No completed test summary | False |
| `08-fixture-final` | 0 | 51.227 | 1/0/0 | False |
| `09-cache-audit` | 0 | 4.272 | No completed test summary | False |
| `10-features-before` | 0 | 0.350 | No completed test summary | False |
| `11-clippy` | 0 | 32.332 | No completed test summary | False |
| `12-new-debug-final` | 0 | 392.643 | 6/0/1; 19/0/0 | False |
| `13-new-release-final` | -15 | 1800.348 | 6/0/1 | False |
| `14-envelope-debug` | 0 | 17.351 | 13/0/0 | False |
| `15-checkpoint-debug` | 0 | 17.480 | 15/0/0 | False |
| `16-checkpoint-release` | 0 | 81.375 | 15/0/0 | False |
| `17-old-semantics` | 0 | 297.020 | 1/0/0; 17/0/0 | False |
| `18-old-authority` | 0 | 19.834 | 17/0/0; 3/0/0 | False |
| `19-old-m2a` | 0 | 17.338 | 1/0/0; 10/0/0; 13/0/0; 4/0/0 | False |
| `20-m1-tombstone` | 0 | 31.126 | 9/0/0 | False |
| `21-compile-fail-docs` | 0 | 12.476 | 48/0/0 | False |
| `22-debug-exact-1` | 0 | 12.256 | 1/0/0 | False |
| `22-debug-exact-2` | 0 | 14.178 | 1/0/0 | False |
| `22-debug-exact-3` | 0 | 12.904 | 1/0/0 | False |
| `22-debug-exact-4` | 0 | 14.359 | 1/0/0 | False |
| `22-debug-exact-5` | 0 | 19.569 | 1/0/0 | False |
| `22-debug-exact-6` | 0 | 17.342 | 1/0/0 | False |
| `22-debug-exact-7` | 0 | 17.189 | 1/0/0 | False |
| `22-release-exact-1` | 0 | 66.602 | 1/0/0 | False |
| `22-release-exact-2` | 0 | 69.438 | 1/0/0 | False |
| `22-release-exact-3` | 0 | 81.429 | 1/0/0 | False |
| `22-release-exact-4` | 0 | 78.145 | 1/0/0 | False |
| `22-release-exact-5` | 0 | 7.315 | 1/0/0 | False |
| `22-release-exact-6` | 0 | 0.307 | 1/0/0 | False |
| `22-release-exact-7` | 0 | 0.443 | 1/0/0 | False |
| `23-resource-debug` | 0 | 313.355 | 1/0/0 | False |
| `23-resource-release` | 0 | 41.005 | 1/0/0 | False |
| `24-final-format` | 0 | 1.633 | No completed test summary | False |
| `25-final-clippy` | 0 | 24.291 | No completed test summary | True |
| `26-final-debug-compile` | 0 | 2.161 | No completed test summary | True |
| `27-final-release-compile` | 0 | 6.243 | No completed test summary | True |
| `28-debug-stress-1` | 0 | 1207.659 | 1/0/0 | True |
| `28-debug-stress-2` | 0 | 67.566 | 1/0/0 | True |
| `28-debug-stress-3` | 0 | 2.656 | 1/0/0 | True |
| `28-debug-stress-4` | 0 | 2.254 | 1/0/0 | True |
| `28-release-stress-1` | 0 | 509.992 | 1/0/0 | True |
| `28-release-stress-2` | 0 | 15.828 | 1/0/0 | True |
| `28-release-stress-3` | 0 | 0.531 | 1/0/0 | True |
| `28-release-stress-4` | 0 | 0.355 | 1/0/0 | True |
| `29-final-debug-exact-1` | 0 | 1.729 | 1/0/0 | True |
| `29-final-debug-exact-2` | 0 | 1.199 | 1/0/0 | True |
| `29-final-debug-exact-3` | 0 | 1.290 | 1/0/0 | True |
| `29-final-debug-exact-4` | 0 | 0.189 | 1/0/0 | True |
| `29-final-debug-exact-5` | 0 | 4.443 | 1/0/0 | True |
| `29-final-debug-exact-6` | 0 | 2.180 | 1/0/0 | True |
| `29-final-debug-exact-7` | 0 | 4.224 | 1/0/0 | True |
| `29-final-release-exact-1` | 0 | 2.803 | 1/0/0 | True |
| `29-final-release-exact-2` | 0 | 5.012 | 1/0/0 | True |
| `29-final-release-exact-3` | 0 | 0.194 | 1/0/0 | True |
| `29-final-release-exact-4` | 0 | 0.188 | 1/0/0 | True |
| `29-final-release-exact-5` | 0 | 0.394 | 1/0/0 | True |
| `29-final-release-exact-6` | 0 | 0.287 | 1/0/0 | True |
| `29-final-release-exact-7` | 0 | 0.424 | 1/0/0 | True |
| `29-new-release-final` | 0 | 537.165 | 6/0/1; 22/0/0 | True |
| `29-team-library-release-final` | 0 | 100.142 | 274/0/0 | True |
| `30-full-native` | 0 | 3608.199 | 704/0/4; 0/0/0; 0/0/0; 0/0/0; 0/0/0; 0/0/0; 1/0/0; 12/0/0; 9/0/0; 3/0/0; 4/0/0; 2/0/0; 4/0/0; 1/0/0; 4/0/0; 5/0/0; 5/0/0; 2/0/0; 2/0/0; 1/0/0; 1/0/0; 1/0/0; 6/0/0; 5/0/0; 3/0/0; 2/0/0; 1/0/0; 2/0/0; 6/0/0; 2/0/0; 3/0/0; 1/0/0; 1/0/0; 1/0/0; 5/0/0; 8/0/0; 9/0/0; 2/0/0; 5/0/0; 4/0/0; 12/0/0; 2/0/0; 1/0/0; 4/0/0; 2/0/0; 20/0/0; 149/0/0; 3/0/0; 2/0/0; 8/0/0; 1/0/0; 2/0/0; 26/0/0; 26/0/0; 8/0/0; 1/0/0; 6/0/0; 17/0/0; 20/0/0; 3/0/0; 26/0/0; 1/0/0; 1/0/0; 4/0/0; 32/0/0; 8/0/0; 2/0/0; 9/0/0; 21/0/0; 2/0/0; 15/0/0; 2/0/0; 1/0/0; 6/0/0; 4/0/0; 86/0/0; 6/0/0; 3/0/0; 2/0/0; 17/0/0; 3/0/0; 6/0/1; 1/0/0; 10/0/0; 13/0/0; 4/0/0; 1/0/0; 22/0/0; 17/0/0; 1/0/0; 1/0/0; 31/0/0; 1/0/0; 19/0/0; 12/0/0; 10/0/0; 35/0/0; 13/0/0; 16/0/0; 26/0/0; 3/0/0; 1/0/0; 1/0/0; 3/0/0; 8/0/0; 3/0/0; 3/0/0; 27/0/0; 46/0/0; 32/0/0; 1/0/0; 9/0/0; 4/0/0; 48/0/0 | True |
| `31-cache-after` | 0 | 3.450 | No completed test summary | True |
| `32-features-after` | 0 | 0.183 | No completed test summary | True |
| `33-final-metadata-cleanup` | 0 | 0.184 | No completed test summary | True |

Every phase receipt includes exact argv/fixed environment/UID, full source-before/after manifests, exit/timeout, own-child wait and raw stdout/stderr hashes. Each SSH transport has an end receipt. Earlier passing/failing/NOTRUN inputs keep their own source identities. Source layout/formatting changes are not silently rebound to earlier results.

| Final exact 256KiB selector | Profile | Actual selected tests | Exit |
| --- | --- | --- | --- |
| `team_checkpoint_payload::full_verifier_total_depth_64_65_and_post_parse_helpers_on_256_kib_stack` | debug | 1 | 0 |
| `team_checkpoint_admission::semantic_depth_64_success_error_drop_on_256_kib_stack_and_65_refusal` | debug | 1 | 0 |
| `team_checkpoint_semantic_cut::complete_candidate_depth64_success_late_error_repeat_drop_and_65_refusal_on_256_kib` | debug | 1 | 0 |
| `team_checkpoint_semantic_cut::complete_fold_depth64_on_actual_256_kib_stack` | debug | 1 | 0 |
| `team_checkpoint_required_generations::required_generation_depth64_success_late_error_repeat_drop_on_actual_256_kib` | debug | 1 | 0 |
| `team_checkpoint_required_generations::required_generation_depth65_refuses_before_crypto_on_actual_256_kib` | debug | 1 | 0 |
| `team_checkpoint_required_generations::required_wrap_depth64_success_error_repeat_drop_on_actual_256_kib` | debug | 1 | 0 |
| `team_checkpoint_payload::full_verifier_total_depth_64_65_and_post_parse_helpers_on_256_kib_stack` | release | 1 | 0 |
| `team_checkpoint_admission::semantic_depth_64_success_error_drop_on_256_kib_stack_and_65_refusal` | release | 1 | 0 |
| `team_checkpoint_semantic_cut::complete_candidate_depth64_success_late_error_repeat_drop_and_65_refusal_on_256_kib` | release | 1 | 0 |
| `team_checkpoint_semantic_cut::complete_fold_depth64_on_actual_256_kib_stack` | release | 1 | 0 |
| `team_checkpoint_required_generations::required_generation_depth64_success_late_error_repeat_drop_on_actual_256_kib` | release | 1 | 0 |
| `team_checkpoint_required_generations::required_generation_depth65_refuses_before_crypto_on_actual_256_kib` | release | 1 | 0 |
| `team_checkpoint_required_generations::required_wrap_depth64_success_error_repeat_drop_on_actual_256_kib` | release | 1 | 0 |

All final 14 selector commands use exact final source bytes and each actually runs exactly 1 test. Earlier 14 development selector runs remain separate. New actual small-stack tests include complete-candidate setup/use/drop, depth 64 legacy public/wrap data, required wrap/ciphertext success, late failure, repeat/drop, and depth 65 inherited-depth refusal before key checking. No stack/global-environment increase was used.

New frozen G01–G08 oracles triangulate hand-authored full final documents/order/status/required inventories and original source positions, known synthetic primitive wrap/decrypt bytes, signatures/canonical/component/chunk/manifest consistency, and ordinary complete folds. Negative families cover full record/key lengths/role, original selectors and applicability, missing effective/required/older wraps, all-selected consistency, malformed/low-order/AAD/tag/length cases, every required version including last unconnected staged values, status transitions/deletion/unavailable history, byte-kind limitations, late error/retry/drop/privacy, compile-fail boundaries and observed M1 restrictions with isolated removal. Existing limited/gapped/false-final/parser/removal/M1 regressions run unchanged.

## Resource trial, measurements and failures

Phase02 compiler refusal (attempted private helper use) and phase 04 invalid synthetic operation status are preserved. They were fixed inside the allowed new builder using existing ordinary M1 fact application and signed revocation facts. No frozen API/validator/test/fixture was changed.

Phase13 used a valid near-limit workload with 11,500 distinct required wraps/versions in one 23,000-operation original commit. It reached1800 seconds, TERM ended the own command, child wait and SSH transport joined, source/modes matched, and the result is **INCOMPLETE/TIMEOUT, not PASS**. Its exact 1328-file source is `13-wide-commit-source.tar.gz`, with full manifest and raw logs. The incomplete timeout ru_maxrss is not treated as a test-process capacity measurement. The frozen complete-fold trace hashes the entire commit for every operation; that inherited wide-commit cost remains a concrete limitation and was not fixed.

The final cardinality probe keeps 11,500 distinct keys, 11,504 checked ciphertexts and the same 14 MB..16 MiB byte assertions, distributed across 32 operations per original commit. It is a different signed input distribution, not a successful reclassification of phase 13. No threshold or runtime parser limit was lowered, no resource was increased, and the frozen fold remains untouched. DOS-1 remains HIGH/OPEN_NOT_FIXED_PARTIALLY_MITIGATED.

The controller initially rewrote identical source and forced rebuilds; v1/v2 logs and sources are retained. v3 skips identical byte writes/redundant modes while preserving all path/blob/byte/mode checks; phase receipts identify v3 by controller SHA256. Resource probes after precompile have no such source rewrite. `/usr/bin/time -l` and supervisor RSS are raw native measurements, not per-transfer reservations or Oracle capacity. They may include fixture/parser/prior-test state; compile-containing phases are identified by raw stderr. Raw DEK payload bound is at most 2 MiB for 65536 required versions, excluding map/index/string/allocator overhead. No enforced runtime memory/concurrency/deadline/cancel infrastructure is claimed. Historical 1,050,672 KiB fixture-process peak is retained as historical evidence only.

`06-new-debug`:

```text
MEASURE mode=near-payload bytes=15482747 records=6 wraps=3 setup_us=12379792 complete_us=12419088 key_us=612175 required=2 checked=4 key_payload_bytes=64 map_and_index_allocator_overhead=unmeasured
MEASURE mode=many-keys bytes=391131 records=262 wraps=259 setup_us=7018438 complete_us=4875930 key_us=269065 required=258 checked=260 key_payload_bytes=8256 map_and_index_allocator_overhead=unmeasured
MEASURE mode=many-versions bytes=2224480 records=4102 wraps=3 setup_us=4025613 complete_us=277398911 key_us=56451 required=2 checked=4100 key_payload_bytes=64 map_and_index_allocator_overhead=unmeasured
MEASURE mode=empty bytes=18847 records=6 wraps=3 setup_us=2057097 complete_us=26614 key_us=567 required=0 checked=0 key_payload_bytes=0 map_and_index_allocator_overhead=unmeasured
MEASURE mode=late-failure bytes=16227 records=6 wraps=3 setup_us=2105675 complete_us=23022 key_us=2861 required=0 checked=0 key_payload_bytes=0 map_and_index_allocator_overhead=unmeasured
```

`12-new-debug-final`:

```text
MEASURE mode=near-payload bytes=15482747 records=6 wraps=3 setup_us=12850234 complete_us=12478400 key_us=628825 required=2 checked=4 key_payload_bytes=64 map_and_index_allocator_overhead=unmeasured
MEASURE mode=many-keys bytes=391131 records=262 wraps=259 setup_us=6904155 complete_us=4760062 key_us=291728 required=258 checked=260 key_payload_bytes=8256 map_and_index_allocator_overhead=unmeasured
MEASURE mode=many-versions bytes=2224480 records=4102 wraps=3 setup_us=3994637 complete_us=289343337 key_us=73364 required=2 checked=4100 key_payload_bytes=64 map_and_index_allocator_overhead=unmeasured
MEASURE mode=empty bytes=18847 records=6 wraps=3 setup_us=2228360 complete_us=30686 key_us=857 required=0 checked=0 key_payload_bytes=0 map_and_index_allocator_overhead=unmeasured
MEASURE mode=late-failure bytes=16227 records=6 wraps=3 setup_us=1960891 complete_us=24967 key_us=3549 required=0 checked=0 key_payload_bytes=0 map_and_index_allocator_overhead=unmeasured
```

`13-new-release-final`:

```text
MEASURE mode=near-payload bytes=15482747 records=6 wraps=3 setup_us=1241274 complete_us=1796316 key_us=52195 required=2 checked=4 key_payload_bytes=64 map_and_index_allocator_overhead=unmeasured
MEASURE mode=many-keys bytes=391131 records=262 wraps=259 setup_us=1030837 complete_us=693559 key_us=31943 required=258 checked=260 key_payload_bytes=8256 map_and_index_allocator_overhead=unmeasured
MEASURE mode=many-versions bytes=2224480 records=4102 wraps=3 setup_us=449393 complete_us=46408693 key_us=3998 required=2 checked=4100 key_payload_bytes=64 map_and_index_allocator_overhead=unmeasured
MEASURE mode=empty bytes=18847 records=6 wraps=3 setup_us=174487 complete_us=3520 key_us=59 required=0 checked=0 key_payload_bytes=0 map_and_index_allocator_overhead=unmeasured
MEASURE mode=late-failure bytes=16227 records=6 wraps=3 setup_us=120165 complete_us=4756 key_us=515 required=0 checked=0 key_payload_bytes=0 map_and_index_allocator_overhead=unmeasured
STRESS label=original-records-near-byte-cap bytes=15769441 commits=31620 versions=6 selected_wraps=3 fixture_history_us=3307448 complete_us=5938268 key_stage_us=2148 required=2 checked=4 key_payload_bytes=64 allocator_overhead=not_a_quota
```

`17-old-semantics`:

```text
M2B2A_RESOURCE {"scope":"complete-original-records-near-byte-cap","platform":"macos","payload_bytes":15762410,"original_commits":31620,"original_facts":0,"operations":31620,"removal_witnesses":0,"semantic_microseconds":31963577,"process_vmhwm_before_kib":null,"process_vmhwm_after_kib":null}
M2B2A_RESOURCE {"scope":"wide-original-and-unflushed-snapshot-490000-public-entries","platform":"macos","payload_bytes":16669202,"original_commits":6,"original_facts":0,"operations":6,"removal_witnesses":0,"semantic_microseconds":18403671,"process_vmhwm_before_kib":null,"process_vmhwm_after_kib":null}
M2B2A_RESOURCE {"scope":"wide-late-semantic-error","semantic_microseconds":19959049,"process_vmhwm_kib":null,"payload_bytes":16669202}
M2B2A_RESOURCE {"scope":"5700-original-removals-and-5700-earliest-witnesses-one-target","platform":"macos","payload_bytes":16510770,"original_commits":5705,"original_facts":5700,"operations":5705,"removal_witnesses":5700,"semantic_microseconds":37906113,"process_vmhwm_before_kib":null,"process_vmhwm_after_kib":null}
```

`23-resource-debug`:

```text
MEASURE mode=near-payload bytes=15482747 records=6 wraps=3 setup_us=11527302 complete_us=11171571 key_us=540634 required=2 checked=4 key_payload_bytes=64 map_and_index_allocator_overhead=unmeasured
MEASURE mode=many-keys bytes=391131 records=262 wraps=259 setup_us=6354998 complete_us=4475316 key_us=252732 required=258 checked=260 key_payload_bytes=8256 map_and_index_allocator_overhead=unmeasured
MEASURE mode=many-versions bytes=2224480 records=4102 wraps=3 setup_us=3716345 complete_us=254666964 key_us=56776 required=2 checked=4100 key_payload_bytes=64 map_and_index_allocator_overhead=unmeasured
MEASURE mode=empty bytes=18847 records=6 wraps=3 setup_us=2097319 complete_us=48045 key_us=865 required=0 checked=0 key_payload_bytes=0 map_and_index_allocator_overhead=unmeasured
MEASURE mode=late-failure bytes=16227 records=6 wraps=3 setup_us=2125150 complete_us=41593 key_us=2463 required=0 checked=0 key_payload_bytes=0 map_and_index_allocator_overhead=unmeasured
```

`23-resource-release`:

```text
MEASURE mode=near-payload bytes=15482747 records=6 wraps=3 setup_us=1156117 complete_us=1629833 key_us=25679 required=2 checked=4 key_payload_bytes=64 map_and_index_allocator_overhead=unmeasured
MEASURE mode=many-keys bytes=391131 records=262 wraps=259 setup_us=694724 complete_us=527118 key_us=24865 required=258 checked=260 key_payload_bytes=8256 map_and_index_allocator_overhead=unmeasured
MEASURE mode=many-versions bytes=2224480 records=4102 wraps=3 setup_us=342634 complete_us=35770956 key_us=4007 required=2 checked=4100 key_payload_bytes=64 map_and_index_allocator_overhead=unmeasured
MEASURE mode=empty bytes=18847 records=6 wraps=3 setup_us=126954 complete_us=3030 key_us=59 required=0 checked=0 key_payload_bytes=0 map_and_index_allocator_overhead=unmeasured
MEASURE mode=late-failure bytes=16227 records=6 wraps=3 setup_us=91525 complete_us=3105 key_us=253 required=0 checked=0 key_payload_bytes=0 map_and_index_allocator_overhead=unmeasured
```

`28-debug-stress-1`:

```text
STRESS label=original-records-near-byte-cap bytes=15769441 commits=31620 versions=6 selected_wraps=3 fixture_history_us=24654601 fixture_package_us=1148191902 complete_us=33985343 key_stage_us=20820 required=2 checked=4 key_payload_bytes=64 allocator_overhead=not_a_quota
```

`28-debug-stress-2`:

```text
STRESS label=11500-distinct-required-original-wraps-in-bounded-commits-near-byte-cap bytes=15583919 commits=725 versions=11506 selected_wraps=11503 fixture_history_us=7685119 fixture_package_us=24360781 complete_us=23659714 key_stage_us=10766438 required=11502 checked=11504 key_payload_bytes=368064 allocator_overhead=not_a_quota
```

`28-release-stress-1`:

```text
STRESS label=original-records-near-byte-cap bytes=15769441 commits=31620 versions=6 selected_wraps=3 fixture_history_us=2690997 fixture_package_us=503942280 complete_us=4584659 key_stage_us=4205 required=2 checked=4 key_payload_bytes=64 allocator_overhead=not_a_quota
```

`28-release-stress-2`:

```text
STRESS label=11500-distinct-required-original-wraps-in-bounded-commits-near-byte-cap bytes=15583919 commits=725 versions=11506 selected_wraps=11503 fixture_history_us=783403 fixture_package_us=9741205 complete_us=3311409 key_stage_us=1142440 required=11502 checked=11504 key_payload_bytes=368064 allocator_overhead=not_a_quota
```

`29-new-release-final`:

```text
MEASURE mode=near-payload bytes=15482747 records=6 wraps=3 setup_us=1250945 complete_us=1685540 key_us=26387 required=2 checked=4 key_payload_bytes=64 map_and_index_allocator_overhead=unmeasured
MEASURE mode=many-keys bytes=391131 records=262 wraps=259 setup_us=847464 complete_us=688353 key_us=29340 required=258 checked=260 key_payload_bytes=8256 map_and_index_allocator_overhead=unmeasured
MEASURE mode=many-versions bytes=2224480 records=4102 wraps=3 setup_us=566694 complete_us=44420506 key_us=6523 required=2 checked=4100 key_payload_bytes=64 map_and_index_allocator_overhead=unmeasured
MEASURE mode=empty bytes=18847 records=6 wraps=3 setup_us=199880 complete_us=4115 key_us=59 required=0 checked=0 key_payload_bytes=0 map_and_index_allocator_overhead=unmeasured
MEASURE mode=late-failure bytes=16227 records=6 wraps=3 setup_us=112791 complete_us=3506 key_us=256 required=0 checked=0 key_payload_bytes=0 map_and_index_allocator_overhead=unmeasured
STRESS label=11500-distinct-required-original-wraps-in-bounded-commits-near-byte-cap bytes=15583919 commits=725 versions=11506 selected_wraps=11503 fixture_history_us=853023 fixture_package_us=7008710 complete_us=3847932 key_stage_us=1252418 required=11502 checked=11504 key_payload_bytes=368064 allocator_overhead=not_a_quota
STRESS label=original-records-near-byte-cap bytes=15769441 commits=31620 versions=6 selected_wraps=3 fixture_history_us=3511254 fixture_package_us=500848345 complete_us=4681211 key_stage_us=2588 required=2 checked=4 key_payload_bytes=64 allocator_overhead=not_a_quota
```

Resource lines, including Rust harness prefixes in exact single-test runs, are indexed with raw line numbers and raw-file hashes in `resource-measurements.json`. Earlier source identities remain separate.

## Artifacts and fixture integrity

| Artifact | SHA256 | Bytes |
| --- | --- | --- |
| [changed-paths.json](changed-paths.json) | `ff3842ad1be94516d135c1c24dffe25d466790acdf8240a63c0438f53177a3e9` | 6046 |
| [fixture-hashes-final.json](fixture-hashes-final.json) | `248515572ff0d725cc79203ce74817fd3c602ef2c620ee1308646ea30c69e6bc` | 121482 |
| [full-source.tar.gz](full-source.tar.gz) | `4835beb9e5889a20f2532ade0f5f27183937cb21fff3da9bba077a1e1d884e1c` | 7410148 |
| [source-final.json](source-final.json) | `81eef219b1adc03f1c450a4ffa7a5bf6a8f1c99f5c5c40235acefb177ed69018` | 354254 |
| [source-final.tsv](source-final.tsv) | `d1c34c1b46705ead84c6a3d719eb6c74487c55aef59f43cc3085a693a05d5235` | 238715 |
| [uncommitted.patch](uncommitted.patch) | `def8afb05cc9861774bc13eea192c312deebc28e9af97362c41b85bee429c200` | 422786 |

`uncommitted.patch` was parsed by Git in read-only numstat mode: 65 paths exactly match the allowlist. Full-source archive contains only the bound source files, no .git/target/cache/runtime DB/HOME/credential/TLS material. Intentional frozen synthetic fixture key/oracle material remains source DATA, not runtime export. Complete path/blob/SHA/byte/POSIX/executable inventories and changed-path catalog are included.

| Fixture family | Checksum entries | Catalog SHA256 |
| --- | --- | --- |
| `team_checkpoint_m2b2_v1` | 97 | `950e7bc521197d24dc9d86ae60438fba3beb5901c4627f34c70926887bae1fcf` |
| `team_checkpoint_required_generations_v1` | 57 | `76deb4be8ad0d9cca38cf623e8a98ee008302bc328d4b19bd6e28628bd0b8e19` |
| `team_checkpoint_semantics_v1` | 149 | `74877c9b8a930aa21a0c3a8fc5cf3519e11c97c6cd13ba1e3a6107235e19a199` |
| `team_checkpoint_v1` | 145 | `a5981856f26e687352a97836372816eaba0f98c285f8a8a41645678c8f8ebc88` |

New family has 58 regular 100644 files including SHA256SUMS, which binds 57 entries. Original 145/149/97 entries and catalog digests remain identical before/after. Dependencies: 172 archives/8194 source files MATCH lock/archive/metadata before/after; feature graph SHA256 `ffe8980d74b2303f5c9348b7eea29f5f1921704e4c64a9e065d97fbfe4fc810c`, raw_value ABSENT.

`privacy-scan.json` records bounded sentinel/DEK/full-synthetic-SSH and encoding-variant scans of collected stdout/stderr, with zero matches. Intentional source/fixture/oracle/archive DATA is excluded. This is not universal secrecy or coverage of every transformation/short/empty value. Public success Debug and early/late errors are tested for fixed redaction, and inputs remain immutable.

## Custody and unchanged holds

Execution used only `/Volumes/ZeroPWBuild/required-generations-r1-8ca2cf0`, UID501 and assigned fixed environment. No old jobs/driver/target/cache borrowing, VM/root/package/reset/resize/stop, production-key access or unassigned resources were used. All own native execution drivers/direct children/SSH transports ended and have wait/end receipts before native resource release. Assigned synthetic TMP was inspected by metadata only and cleaned to 0 entries; no keys/DB/TLS contents were read or exported. No whole-machine-idle or physical-erasure claim is made. Native resource state: **RELEASED**. The VM was not stopped.

Native release records 69 completed command phases and 122 joined SSH transports. Conservative elapsed native-task span: 11871.453 seconds against the 21600-second cap. See `native-resource-release.json`; no native call followed release.

Linux remains explicitly NOTASSIGNED/NOTRUN and validation INCOMPLETE. No Lima zeropw-parity, Docker/other VM/environment or Linux case12/service/root resource query occurred. Separate Go Linux case12 quarantine/lease remains UNRELEASED, AUTHORITY_NOTREADY/CANCELLATION_EVIDENCE_NOTREADY; no custody bypass.

Canonical ca01275 evidence/severities remain unchanged: DOS-1 HIGH/OPEN_NOT_FIXED_PARTIALLY_MITIGATED; OPUS-03 and 03-R1 OPEN; SEC-03 INSUFFICIENT_EVIDENCE; earlier resolved scenarios and new 04–10 LOW/11 JSON nit–Markdown NIT/LOW are not reclassified. Actual Opus 3eb remains interrupted without a completed accepted verdict. No reviewer was invoked or substituted.

All M2-G01–G10 remain OPEN, including full original/gapped/interacting-removal/compaction/continuation semantics; required-key/ciphertext integration and stronger credential assurance; durable two-sided approvals/live transfer/resources; fresh locked READY; journal/fsync/recovery/coherent epochs; committed provenance before receipt/ACK; exact-source Linux/macOS/crash/concurrency/physical two-Mac/direct/forced-TURN and actual reviews. Packaging, macOS ACL residuals, Oracle/deployment/capacity and product release remain separate OPEN gaps.

No commit/ref/index/PR/push/merge/deploy, repository permissions, coordinator checkout or coordinator runtime change was made. The controller collects this uncommitted artifact, publishes/reviews later, and binds any later readiness to its actual new head SHA. Completion of this bounded code/native work is not full M2, validation, review, runtime or release acceptance.
