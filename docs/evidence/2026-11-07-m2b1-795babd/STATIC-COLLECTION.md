# M2b.1 source and evidence collection

Actual model: **gpt-6.1-sol**, inherited ultra reasoning through Codex/T3 Code. Static data collection only, with no subagents. This is not a product/adversarial review, Opus disposition, test execution, acceptance or deployment.

## Exact inputs

Worker checkout: `/Users/ys/.t3/worktrees/zeropw/t3-f453296e`, clean at **795babd269e9c0ed0a6498a476c67c21894f875f**. Base: `9819c648640f401a54a42970fcb0515ac9654e9a`. Worker full tree: `f5b76658321b3e089cf0ca849c4815115bfba992`; Rust tree: `9c7d432b44ff7f7244dcd58f9a416c83b31e6c76`.

Original evidence directory: `/Users/ys/Code/zeropw-mlp-evidence/m2b1-authority-20261107/t3-f453296e/`. The read-only collection checked the final report, complete checksum catalogue/source manifest/archive, Git path/mode/blob data, final driver as text and data, summary/raw final log markers, exact scope allowlist and protected-file/diff comparisons. It did not read or adjudicate every new algorithm or test assertion.

## Independently checked data

- All **87** entries of `SHA256SUMS.evidence` matched regular non-symlink files and SHA256 values. Catalogue names are relative, unique, contain no `..`, and exactly inventory all87 files except the catalogue itself. No evidence was edited.
- All **1,098** final expected paths match the committed Git path set, Git blob SHA-1 including header, SHA256, working-copy regular types and executable bits. The source tar contains the same1,098 regular file entries with exact bytes and executable modes; no extra/missing/duplicate source files, link members or unsafe paths. Directory entries are ignored as archive structure.
- The final driver's embedded compressed source map independently decodes to the exact1,098 Git modes/blob IDs in the expected manifest. The raw final log has both before/after1,098-match reports, all12 declared phase exits zero and final driver failure flag0; these agree with the source-bound summary. I did not execute the driver or its audit script.
- Both fixture checksum catalogues verify independently: frozen M2a145 entries and new semantic149 entries. The helper, old fixture tree, strict_json.rs/manifest.rs/provenance.rs, Cargo files, verifier, AGENTS, CI and harness remain byte/mode identical to the supplied base.
- Exactly **158** paths change: **8 code/test files +150 new fixture/provenance files**. Every path is in the supplied M2b.1 allowance. No Desktop/source governing-doc/evidence edit exists in the worker delta.
- Worker `sync.rs` is exactly its original file with only `apply_fact` visibility changed to `pub(super)`; its body is unchanged. The original `fold.rs` diff has no deleted/replaced original line. These are scope-preservation checks, not proof that the new additive trace is semantically correct.

## Reconciliation with current M1/Personal Vault branch

Read-only `git merge-tree --write-tree` for frozen current **a4be71aca3cd611c83131bc9670965caa1b5a435** and worker **795babd269e9c0ed0a6498a476c67c21894f875f** succeeds with no conflicts:

- Prospective full tree: **c6799cd98f6d1e9e216175564dbb1d9509d24900**.
- Prospective Rust tree: **5d3acbd546c5dc3490e95635342572cb064007eb**.
- Prospective Desktop tree: **2413844c89265a3e239be2372d34b1e6e1b2d4bb**, exactly the current tested M1/Personal Vault tree.
- Exactly158 paths differ from current; all are the same allowed M2b.1 paths.
- Current `docs/`, `desktop/`, `harness/`, `.github/`, AGENTS and `rust/src/team/transport.rs` are byte/mode identical in the prospective tree, preserving all main-only evidence/status documents and current native pairing/supervisor corrections.
- Prospective `sync.rs` is exactly current `sync.rs` plus only the `pub(super)` visibility change. Thus the newer M1 checked-adoption correction and test remain present.

This is a clean source-preservation preflight, not an executed merge or runtime result. The prospective Rust tree differs from the worker-tested tree because it retains the newer M1 adoption/transport changes. **No runtime PASS binds to the prospective union through this collection.** The controller alone owns its checkout/index/ref and any actual integration.

## Test scope and retained gates

The checked worker summary/raw log records isolated **Linux107/107 verifier steps,102 integration targets,1,735 passed/0 failed**, with four explicit default-ignored signer probes and17 compile-fail doc tests. Focused admission/oracle and debug/release checkpoint/256KiB-stack/measurement phases all have recorded exit0. These are original worker execution records at795babd; I independently hashed/read their data, did not rerun them. **Native macOS: NOT ASSIGNED / NOT RUN.** The requested two-platform slice is incomplete. This Linux run does not certify Desktop or the prospective combined head.

All full-M2 gates remain open; the candidate is not a final overlay/generation/install/runtime onboarding result. The worker's blanket list of original IDs as unresolved is **not a canonical disposition** and must not reopen findings already resolved in the last completed ca01275 review. Preserve that review's exact individual statuses/severities and evidence; this collection supplies no new status for any finding. DOS-1 remains HIGH/open. Newer interrupted Opus output remains incomplete, without an accepted new verdict. Physical two-Mac/sleep-wake, native/full-combination, Opus/Astra acceptance, crash/runtime/packaging and deployment gates are not closed.

## Hashes and omissions

- Worker REPORT.md: `9d7ef3d0093ff1e4d5051727894943f4d7c9ebeae322bd9c658d13a6608a88d8`.
- Original SHA256SUMS.evidence: `e438a34cd62abbaaefb7860d3e783a929bb62abf9374fe1bf5cbeeffd45986d7`.
- Final source tar: `a719b42c9448a285e7601eedb130b942d9f186577ec3f8cf9bb1f118a11fb8f4`.
- Final validation summary: `8221bc8b8b8aaa3db17b35dbf896c3fed0d635bba40082c205217f99fbf7ee73`.

The companion `m2b1-static-collection-20261107.json` records machine-readable checks and tree bindings. All actions were static Git/standard-library data reads/hash/archive inspection plus these two collection outputs. No submitted source/helper/formatter/build/dependency/test execution/import, VM or credential access, worker polling, ref/index/source mutation, push, merge or deployment occurred. `merge-tree` may write ordinary Git tree objects; it does not change refs/index/worktree. An initial collection matcher used `Value` instead of the actual `Fact` parameter spelling; inspecting the actual two-line Git diff corrected that data-matcher assumption before the final successful checks. That was not a product failure.

No data-binding or allowed-scope blocker was found. No algorithmic security/authority/completeness verdict or acceptance follows from this collection.
