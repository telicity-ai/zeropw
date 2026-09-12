#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required" >&2
  exit 1
fi

if ! command -v ssh >/dev/null 2>&1; then
  echo "error: ssh is required" >&2
  exit 1
fi

cd "$REPO_ROOT"
python3 -m compileall -q harness
python3 -m unittest discover -s harness -p 'test_*.py' -v

echo "ZeroPW harness smoke check passed."
