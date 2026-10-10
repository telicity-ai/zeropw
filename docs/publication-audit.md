# Publication audit

This record tracks work before the owner changes repository visibility. The repository is currently private. It is not a completed audit or an authorization to publish.

## Information categories

- Original credentials, operational tokens, vault material and administrator/recovery authority: never include in a public tree or release. Audit current files and reachable history without printing matched values.
- Synthetic cryptographic fixtures: expected to contain test keys and encrypted state. Preserve bytes and document provenance; verify they are synthetic rather than treating every key-shaped file as a production secret.
- Personal local paths and development identities: current review records contain `/Users/…` paths and old repository/account references. Sanitize publication copies and review history exposure separately. Do not falsify original findings or their severity.
- Historical Korean records: preserve their meaning as dated evidence. Maintained product documentation and output should use English; historical fixtures and intentional Unicode test inputs need not be rewritten.
- Third-party licenses: audit the locked dependency graph and include notices required for distributed binaries. The project's MIT license does not replace dependency terms.

## Outstanding work

The current tree still needs notification-output translation, remaining maintained-document translation, private-information scanning, dependency-license inventory, validated release archives and Homebrew checks, current-commit E2E evidence and independent review. The security reporting contact/channel must be finalized before launch.

Git history remains unchanged. Deleting a sensitive or personal file from the current tree does not remove it from history. If the audit finds content that should not be public, decide on a sanitized history or a separate public snapshot before changing visibility; do not force-rewrite the private repository without an explicit decision.

## Concrete release findings

- OSS-INSTALL-OPENSSL: Source builds use OpenSSL. The Homebrew formula now declares openssl@3 and selects its prefix explicitly. Native Homebrew execution is still pending. Curl binary archives still need a checked portability policy for their OpenSSL linkage; success on a builder that already has system libraries does not prove a fresh machine can run them.
- OSS-TEAM-SELFREMOVE: `team/membership.rs::remove_member` rotates the generation only when an admin removes another device. User/admin self-removal publishes a removal fact but does not rotate DEK. Removal denies synchronization, but the existing generation remains available to the removed device; the general promise of new-generation secrecy needs a fix or explicit acceptance rather than a documentation-only PASS. This is a coordinator finding, not an Opus review or severity assessment.

## Tracked-tree path normalization

Publication copies of 18 historical review/fixture-generation Markdown files replace the original personal home prefix with `${HOME}`. Finding IDs, severity, source SHAs, assertions and conclusions are preserved. The original unsanitized reports remain in their recorded Git revisions; normalized current copies are not byte-identical review inputs and must not be used to revalidate an old input digest.

The remaining tracked-tree personal-path match is deliberately synthetic scanner-test input. Private-key markers are parser constants, scanner-test input and the documented synthetic OpenSSH fixture. `rust/tests/fixtures/python/sshwire/GENERATE.md` records the isolated, test-only generation of that fixture; no private-key bytes or original cryptographic fixture data were changed. Narrow pattern scanning does not prove absence of every credential format. Historical personal paths still require an owner decision before exposing the existing history.
