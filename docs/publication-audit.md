# Publication audit

The repository is public. This record began as the list of work to finish before the owner changed repository visibility; it now records what that change left open. `docs/releasing.md` has stated that the repository is public since the v0.1.0 release preparation (commit `989217a`, 2026-10-11), and v0.1.0's publication and public-download checks are recorded in its release verification asset. This record was not updated when visibility changed, and it does not record the exact time of the change. The repository was checked public again on 2026-10-16. This is not a completed audit or an authorization to publish.

## Information categories

- Original credentials, operational tokens, vault material and administrator/recovery authority: never include in a public tree or release. Audit current files and reachable history without printing matched values.
- Synthetic cryptographic fixtures: expected to contain test keys and encrypted state. Preserve bytes and document provenance; verify they are synthetic rather than treating every key-shaped file as a production secret.
- Personal local paths and development identities: current review records contain `/Users/…` paths and old repository/account references. Sanitize publication copies and review history exposure separately. Do not falsify original findings or their severity.
- Historical Korean records: preserve their meaning as dated evidence. Maintained product documentation and output should use English; historical fixtures and intentional Unicode test inputs need not be rewritten. The desktop app's interface is Korean only by owner decision (2026-10-16), and its specification and design rules are written in Korean (`docs/releasing.md`, gate 2).
- Third-party licenses: audit the locked dependency graph and include notices required for distributed binaries. The project's MIT license does not replace dependency terms.

## Work before and after publication

Before visibility changed, this record listed as outstanding: notification-output translation, remaining maintained-document translation, private-information scanning, a dependency-license inventory, validated release archives and Homebrew checks, current-commit E2E evidence, independent review, and a security reporting contact. The v0.1.0 release later recorded verified archives, macOS Homebrew installation, target-specific dependency notices, tracked-tree and reachable-history scans, and a final review for its own commit (`docs/releasing.md`, "v0.1.0 evidence and installation"). That evidence is bound to v0.1.0 and covers no later commit; each later release, including v0.2.0 with the desktop app, needs its own scan, notices and review. Whether every translation item was finished is not re-checked here.

Still open after publication:

- PUB-HISTORY-PATHS: the reachable history, including historical personal paths, was exposed when visibility changed. This record asked for an owner decision on that history (a sanitized history, a separate public snapshot, or exposing it as is) before the change. No such decision is recorded. The v0.1.0 evidence classifies historical personal paths as development evidence; that is a scan classification, not the owner decision. Rewriting history now would not withdraw copies already fetched. Do not force-rewrite the public repository without an explicit owner decision, and record the decision here when it is made.
- PUB-SECURITY-CONTACT: `SECURITY.md` still says a public reporting contact must be finalized; it has none.

## Concrete release findings

- OSS-INSTALL-OPENSSL: Source builds use OpenSSL. The Homebrew formula now declares openssl@3 and selects its prefix explicitly. Native Homebrew execution is still pending. Curl binary archives still need a checked portability policy for their OpenSSL linkage; success on a builder that already has system libraries does not prove a fresh machine can run them. Status at v0.1.0 (`docs/releasing.md`): the release archives link a static OpenSSL 3.5.9 SDK and passed linkage checks, an empty Linux runtime without shared OpenSSL passed the demo checks, and macOS Homebrew installation passed; Linux Homebrew installation remains unverified.
- OSS-TEAM-SELFREMOVE: `team/membership.rs::remove_member` rotates the generation only when an admin removes another device. User/admin self-removal publishes a removal fact but does not rotate DEK. Removal denies synchronization, but the existing generation remains available to the removed device; the general promise of new-generation secrecy needs a fix or explicit acceptance rather than a documentation-only PASS. This is a coordinator finding, not an Opus review or severity assessment.

## Tracked-tree path normalization

Publication copies of 18 historical review/fixture-generation Markdown files replace the original personal home prefix with `${HOME}`. Finding IDs, severity, source SHAs, assertions and conclusions are preserved. The original unsanitized reports remain in their recorded Git revisions; normalized current copies are not byte-identical review inputs and must not be used to revalidate an old input digest.

The remaining tracked-tree personal-path match is deliberately synthetic scanner-test input. Private-key markers are parser constants, scanner-test input and the documented synthetic OpenSSH fixture. `rust/tests/fixtures/python/sshwire/GENERATE.md` records the isolated, test-only generation of that fixture; no private-key bytes or original cryptographic fixture data were changed. Narrow pattern scanning does not prove absence of every credential format. The original unsanitized reports in history are public with the rest of the history; see PUB-HISTORY-PATHS.
