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
