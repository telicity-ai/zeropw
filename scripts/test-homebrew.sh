#!/usr/bin/env bash
# Run only on a disposable macOS runner: builds code from the exact checkout.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
command -v brew >/dev/null
commit=$(git -C "$root" rev-parse HEAD)
brew tap-new zeropw-ci/readiness
trap 'brew uninstall --force zeropw-ci/readiness/zeropw >/dev/null 2>&1 || true; brew untap zeropw-ci/readiness >/dev/null 2>&1 || true' EXIT
tap=$(brew --repository zeropw-ci/readiness)
python3 "$root/scripts/homebrew-source.py" "$root" "$tap" "$commit"
HOMEBREW_NO_AUTO_UPDATE=1 brew install --HEAD zeropw-ci/readiness/zeropw
HOMEBREW_NO_AUTO_UPDATE=1 brew test zeropw-ci/readiness/zeropw
