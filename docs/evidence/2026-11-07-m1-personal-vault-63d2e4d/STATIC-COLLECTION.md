# M1 final source/evidence collection

Actual collector: **gpt-6.1-sol, inherited ultra reasoning**, native same-provider collection helper. This is static source/evidence collection only, not adversarial review, Opus disposition, runtime revalidation or Astra acceptance. No subagents, product/dependency/helper/build/test/formatter execution, VM access, credentials, source/ref/index changes or other-worker polling occurred. Git merge-tree created only ordinary prospective objects; no merge or checkout mutation occurred.

## Exact inspected inputs

- Completed worker: `63d2e4d8d1f0d6f2b834401767026da8fddb1b9c`, branch `t3/m1-personal-vault-integration`, clean worktree `/Users/ys/.t3/worktrees/zeropw/t3-70c85200`.
- Prepared worker base: `44e898db3ae0f48991a1fd821c4700e5d1a1eff5`.
- Current main: `9bf3e9071139302d96222d0f471ae6756992e658`.
- Worker full tree: `489d517b1cf0f75a3610b6c789a38257bae09f88`.
- Worker/tested Rust tree: `4b628201f8dc089c0579ebbe75ee768ae9861f6c`.
- Worker/tested Desktop tree: `2413844c89265a3e239be2372d34b1e6e1b2d4bb`.

The complete worker REPORT.md, seven-commit list, changed-file list, binding/protected/verification summaries and exact main/worker differences were read. All201 SHA256SUMS entries verified, with unique relative paths, no traversal, regular nonsymlink files, and matching SHA256. The 931-entry source manifest matches the worker Git exact set, each Git blob's bytes/SHA256 and executable mode, and the clean host worktree. The source archive was inspected as data without extraction or execution: all931 regular nonlink members match the exact set, byte hashes and executable bits. Linux and native before/after source JSON inventories each exactly equal that manifest's file list.

Primary evidence hashes:

- `REPORT.md`: `c539ee235e8bee4f4440d5f9a8b8a86fcf7eec1fcc307e74c15404bd6b367315`.
- `SHA256SUMS`: `9386ded5f2816ddc3e5c990cfb122835b3e2b77cf2936b620763e1bf2da42815`.
- `combined-source-expected.json`: `ba3ccb57008453859e078e1430b977f2dfdeb72678c9eead9767d2559b30a7db`.
- `combined-source.tar`: `77666c3e021797c29a7f89dfc5160fa193cb87e6245e4a6cfa007556921e45e7`.
- `combined-source.diff`: `4a0ed434a687b9929d19da89ca0478fdf28befa064adcb5bdfb19e88d2ee21c4`.
- `verification-summary.json`: `bb289d13d71ae6275455f52f6b038e709158e6c20b3be27ccdf20a3d910f4835`.

## Provenance and minimal collection

The worker's seven commits, in order:

1. `d93e9946104caf224a646105fcd70d13df58b970`: cumulative original M1 backend plus current Personal Vault delete/IPC/i18n and M1 documentation.
2. `143cf1b015a2c2d3395226d3e8f7ea4c4b02a885`: explicit failed-adoption handling, native fake-daemon blocking-stream correction and retained regressions/docs.
3. `290061380026f9b72b3a67362dd450083fbb441c`: deletion feature-table documentation.
4. `50f53af16b4960b5b0be375ad149aefd214d6475`: original M2a43723aec copy, already in main as5686afe.
5. `67c11dad1f3b13a21f4facca36ec27a2157d9570`: original M2a1aa5525 copy, already in main asb7d9252.
6. `5ae386b6300c193b02db698ee4ea06662f40ab61`: original M2a7bcecfd copy, already in main as74bb09a.
7. `63d2e4d8d1f0d6f2b834401767026da8fddb1b9c`: supervisor test-start preconditions and typed delete stubs.

These seven commits are provenance, not a series to blindly cherry-pick: main already contains the immutable M1 Rust union and all M2a source. No whole worker tree replacement is appropriate because it omits later coordinator documents.

`git merge-tree --write-tree <main> <worker>` completed with exit0 and no conflicts. The prospective tree is **`ecce458c22891ea7039c46f3412b5cc17854950e`**. It changes exactly26 paths relative to main:19 Desktop,2 Rust,5 M1 docs. There are no deleted paths. A coordinator source commit collecting those26 prospective blobs/modes provides the minimal nonduplicate source union; root alone owns that operation. Both entire rust/ and desktop/ trees in this prospective union are byte/blob/mode identical to the tested worker trees above. No fresh integrated-head runtime PASS is established by this static equality.

The26 paths are:

- `desktop/core/src/commands.rs`.
- `desktop/core/tests/core_fake_admin.rs`.
- `desktop/core/tests/e2e_remote_pairing.rs`.
- `desktop/core/tests/link_supervisor.rs`.
- `desktop/src-tauri/build.rs`.
- `desktop/src-tauri/capabilities/default.json`.
- `desktop/src-tauri/src/commands.rs`.
- `desktop/src/copy/backend.ts`.
- `desktop/src/copy/devices.ts`.
- `desktop/src/copy/vault.ts`.
- `desktop/src/ipc/contract.ts`.
- `desktop/src/ipc/mock.ts`.
- `desktop/src/lib/reasons.ts`.
- `desktop/src/lib/records.ts`.
- `desktop/src/screens/vault/ItemDetail.tsx`.
- `desktop/src/screens/vault/VaultPage.tsx`.
- `desktop/test/reasons.test.ts`.
- `desktop/test/records.test.ts`.
- `desktop/test/vault.test.ts`.
- `docs/desktop-app.md`.
- `docs/remote-sync-next-milestones.md`.
- `docs/remote-sync.md`.
- `docs/team-sync.md`.
- `docs/whole-secret-deletion.md`.
- `rust/src/team/sync.rs`.
- `rust/src/team/transport.rs`.

## Preservation choices

A direct main-to-worker diff misleadingly shows14 coordinator-only document deletions and stale status replacements. The prospective merge preserves all14 main-only paths, exactly by mode/type/blob, including actual Astra M2b decisions, interrupted-review output, M2a collection/evidence and original composition records. It preserves docs/remote-sync-validation-2026-11-07.md byte-identical to main. Its only milestone-page change is the11-line M1 integration paragraph; the main M2a implementation/status paragraph remains. All other main entries outside the26 paths remain byte/mode identical. AGENTS, .github and harness are unchanged, as are Cargo/dependency/fixture/verifier/sidecar boundaries carried by the product-tree comparison.

The worker delta from main within Rust is only sync.rs (checked adoption failure plus regression) and transport.rs (authenticated pending-frame regression). Existing whole-secret backend, signer/path changes and inert M2a files are identical otherwise. The Desktop delta connects the existing fresh-passphrase confirmation to permanent deletion and preserves the redesigned screens; no removed dashboard component is restored. This inventory is not a full semantic review.

## Reported execution and scheduling boundary

The hash-bound worker report/summary records exact-final-source normal completion: unchanged Rust verification105 steps with1709 Linux /1712 native tests; Desktop8 steps with343 frontend and198 core tests on each OS; separate release parser12 tests and256KiB-stack payload target1 test on each OS. All recorded phase/driver exits are0. These are the worker's source-bound execution results, not tests rerun by this collector. Original failed pairing/supervisor/type/setup logs remain in the201-entry evidence catalog.

The report literally states: **“Both owned verification drivers finished. Guest source, caches and raw evidence are left in place for collection; no other task was interrupted.”** The delegated task is completed. There is no separate literal VM-release token in the report; this collection did not query runtime state. Root may schedule a new exclusive macOS window according to that completed-task ownership record.

M1 external/Astra acceptance, actual authorized Opus review, full M2/M2b runtime, real-link-daemon deletion E2E, physical two-Mac/sleep-wake, native GUI walkthrough, signed/notarized packaging and deployment/OCI capacity remain open. Original ca01275 DOS-1 HIGH remains OPEN; no interrupted partial is a new verdict.
