#!/usr/bin/env bash
# Run only on a disposable macOS runner: builds code from the exact checkout.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
command -v brew >/dev/null
commit=$(git -C "$root" rev-parse HEAD)
brew tap-new zeropw-ci/readiness
trap 'brew uninstall --force zeropw-ci/readiness/zeropw >/dev/null 2>&1 || true; brew untap zeropw-ci/readiness >/dev/null 2>&1 || true' EXIT
tap=$(brew --repository zeropw-ci/readiness)
python3 - "$root" "$tap" "$commit" <<'PY'
import pathlib
import sys
root, tap, commit = sys.argv[1:]
formula = (pathlib.Path(root) / 'Formula/zeropw.rb').read_text()
# Local Git clone provides the exact source without a GitHub authentication token.
import json
formula = formula.replace('head "https://github.com/telicity-ai/zeropw.git", branch: "main"',
                          f'head {json.dumps(root)}, using: :git, revision: {json.dumps(commit)}')
(pathlib.Path(tap) / 'Formula/zeropw.rb').write_text(formula)
PY
HOMEBREW_NO_AUTO_UPDATE=1 brew install --HEAD zeropw-ci/readiness/zeropw
HOMEBREW_NO_AUTO_UPDATE=1 brew test zeropw-ci/readiness/zeropw
