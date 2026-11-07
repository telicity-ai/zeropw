# Required-generation independent DATA collection

Actual collector: gpt-6.1-sol / ultra. This is static byte/hash/log/receipt collection; no submitted code was executed, no VM was queried, and no code-review or acceptance verdict is claimed.

Base `8ca2cf0163bc7b3c9681d9a0df4e9f4b81e820e0` contains1266 files. The1328-file source archive matches every byte, POSIX/Git mode, blob and length in source-final.json. Exactly3 allowed existing files,4 allowed new source/test files and58 allowed fixture files changed;1263 other base files remain exact. No deletions. Independent in-memory application of all65 patch paths reconstructs the archive. Independently computed full tree `a9670b198e985c98d0247be749d6e08d89748bdc`, Rust `4352ebbd0fa84bde0fb444c4d0902ef2510d0620`, Desktop `2413844c89265a3e239be2372d34b1e6e1b2d4bb`. Desktop and all nonallowed paths remain exact. Frozen fixture catalogues145/149/97 and the new57 entries all hash-match. All556 evidence catalogue files (72427419 bytes) match their recorded SHA256, length and mode.

The raw final full-native log independently gives111 ordered successful steps and106 integration targets derived from archived source:1819 passed,0 failed,5 ignored in114 test summaries. Four ignored library signer probes run explicitly and pass in the dedicated probe step. The fifth ignored test is the explicit synthetic fixture generator; generator development phases are preserved with their own earlier source, not counted as final product tests. All14 final exact256KiB commands actually select one passing test each and bind to the final1328-file source before/after. No overlapping focused counts were added to1819.

The69 native phase receipts and122 SSH transport receipts hash-match. Every direct child is recorded waited and every transport joined. The worker RELEASED receipt is timestamped `2026-11-07T23:20:26.110392+00:00` with zero known outstanding handles. This proves the recorded own-job lifecycle only; it is not a whole-machine-idle or physical-erasure assertion.

Phase13 remains TIMEOUT1800s, exit-15, child waited, exact source/archive preserved. Its source differs from final and is never relabelled PASS. Final distributed32-operation commits are a different workload from the original23000-operation commit. Development compiler and synthetic-status failures remain preserved.

Linux is NOTASSIGNED/NOTRUN: overall validation INCOMPLETE. DOS-1 HIGH, all M2/runtime/review/physical/Oracle/release gates and the separate Go case12 custody/cancellation hold remain unchanged. The collector made no implementation review or live cache/native-state assessment. Saved before/after cache audit DATA agree; the collector did not rehash live dependencies.

Detailed per-file/selector/artifact bindings are in collection.json.

The phase13→final new production module differs only in one private unit-test name (`does_no_private_crypto`→`does_no_unwrap_or_decrypt`); its production algorithm is byte-identical across those two archives. The integration test file separately tightens one parser error assertion, adds fixture packaging timing, distributes the wide23000-operation input into32-operation original commits, and adds an observed-M1-tombstone/removal regression. These are exact archive comparisons, not a semantic review verdict.

Five collector-only setup/parser corrections are recorded in collection.json: Git archive directory records, archive umask normalization, an interrupted inefficient tree calculation, Git no-newline marker handling, and an incorrect assumed changed-path expectation. No submitted evidence changed, no worker failure was reclassified, and all collector processes ended.
