# Real ZeroPW / link / coturn E2E — bd065fc Rust tree and 4af5ac link

Actual model: **gpt-6.1-sol**. This is independent functional verification,
not an Opus review or release acceptance.

The fresh isolated Linux run passed **all original 66 scenario assertions** and
the **separate scan of seven synthetic service secrets**, process exit 0.
Runtime: 2026-11-07T06:27:07Z through 2026-11-07T06:31:34Z. Raw log SHA-256:
`0dc6df3977098f5ea022d3a63b3266b64a9a223b51c3e8b011a880bf39df1101`.

| Input | Exact identity |
| --- | --- |
| ZeroPW source | `52e87b07380a2f752c127c5f89e5f8f76c38937f` |
| Rust tree (includes bd065fc) | `2882ba592e2204eb62723d95e240525e75196f64` |
| Link source | `4af5ac81b8e8e48ebc8e20f1ab382b12f8b685a2` |
| Fresh zeropw-admin | `d59ad679feb25586d136f6b61a8191aad0b084d14e2146f6333bd8e3e1665e80` |
| Fresh zeropw-link | `9e5b4dc6026c6d5b2b5b8284dd2f95b89daeafbebb7860e38aa6c7ebdf9cfe51` |
| Fresh zeropw-linkd | `f66a0f292cbfdae0e91c620f0731bde6576c21efe358476f361c378227dab61d` |
| Pinned cached coturn 4.18 | `d3e7cf6fd8446d11757f6969e75e1eb7d8ba1183ec33c27da67556f837052380` |

All **640 ZeroPW files and 162 link files** were checked by exact Git blobs,
SHA-256, modes and file sets before builds, after builds, immediately before
execution and after execution. Both original source archives were checked again
during collection. Four product executable digests match before/after runtime.
The original support helper sockxfer was built from the frozen link source and
its post-run digest is retained; the original fixture does not print its digest
before execution, and no pre-execution helper digest is invented.

The ORIGINAL run.sh, scenarios.py and link topology script remain byte-identical
to the earlier fixture: hashes51abd3effd5906ccc39cf01e9d5e90aad0e9ed58d8229f9b40ad337ca6e1d315,
5675f0d59fa7744f841e61fce0e7c5a2360418c0d26f392dbbff05c42e6e2539,
and8bbb6aef6a62e12dfaccac47d997bed306d2a6f6073c8c2f33a4f4185c70a080.
All 66 assertion names and order match the preserved earlier run. No assertion,
product check or source checkout was changed. The unexecuted candidate diff in
the collected records is explicitly not the invocation used for this run.

Passed cases cover approved fingerprint pairing, initial signed history and
three decrypted synthetic values, version updates, offline reconnect, concurrent
value retention/conflict alerts, irreversible version revocation, actual direct
and forced TURN UDP/TLS paths with both peers' UDP blocked for TLS, process pause,
coturn/application/daemon restart, one-use/real elapsed invite expiry,
unauthorized vault access rejection, malformed protocol refusal, separate
vault/service revocation, and runtime-log/wire/plaintext/base64/hex plus sampled
daemon-memory/environment/argv checks. Full assertions are in
`collected/assertions.json`.

## Preserved refusal and actual identity/path boundary

A new job beneath `/home/parity/jobs` was found to have an 0775 shared ancestor.
The fresh daemon, euid 2000, explicitly refused a state there with exit 1 and
“state is not private to this user: writable service CA path jobs
(mode drwxrwxr-x)”. `unsafe-parent-refusal.log` preserves the actual refusal.
No shared directory mode or product trust check was weakened.

The actual run used the original fresh `/tmp/zpe.x1x1TD` runtime work directory.
Its public CA chain is root-owned `/0755` -> root-owned sticky `/tmp01777` ->
root-owned W/pki 0755 -> public root CA 0644. This satisfies the existing trust
checks for each actual euid. A namespace-scoped snapshot confirmed both Go
daemons and Rust serves running as uid 2000; linkd/coturn ran as uid 0. Daemon
leaves were uid 2000/0700 and service state uid 0/0700. The snapshot read only known
fixture namespace PID status/exe and path metadata, never argv, environment,
secret files or unrelated processes. Exact records are retained in
`collected/evidence/runtime-identity.json`.

Builds used new frozen exports and own target/cache/module copies, Cargo j1,
incremental0, dev/test debug0, and Go-p1. No active M1 cache, prior frozen Rust
binary, native Mac, production authority, keychain or deployment endpoint was
used. The cached coturn binary was copied and explicitly checked against the
known digest; its source BUILDINFO pin is retained. All six owned namespaces and
the root-only build TMPDIR were removed. Generated fixture state/key/token files
were not copied into this evidence package.

## Limits

This Linux two-device simulation is not native macOS, physical two-Mac,
packaging or real sleep/wake validation. It does not close M1 whole-secret
deletion or M2 authenticated snapshot bootstrap: initial history and one-version
revocation are different cases. It does not replace the retained bd065fc Linux
full-matrix grant-expiry failure. No deliberate packet corruption/loss,
power-loss durability, long-duration renewal/capacity or actual OCI shape
measurement was performed. Memory samples are point-in-time writable mappings,
not RSS and not proof against every transient value or encoding. The original fixture disables IPv6; IPv6/mapped-peer denial policies were not
exercised here. Current coturn compilation was not retested. No Opus review, release readiness, deployment or
capacity acceptance is claimed.

`manifest.json` records exact commands, environment, sources, binary/script/log
hashes, preserved refusal, cleanup and remaining limitations.

This committed report mirrors the external evidence directory `/Users/ys/Code/zeropw-mlp-evidence/real-sync-bd-4af-20261107/`. The raw log, source archives and collection records remain there with SHA256SUMS; manifest paths refer to that evidence directory. Original reproduction scripts remain under `scripts/e2e-remote-sync/`.
