#!/usr/bin/env sh
# SessionStart hook for Claude Code (local and claude.ai/code cloud sessions).
# Lightweight runtime check only: no package installs, no test run, never blocks the session.
set -u

cd "${CLAUDE_PROJECT_DIR:-$(pwd)}" || exit 0

if ! command -v python3 >/dev/null 2>&1; then
  echo "session-start: python3 not found; harness commands will not work" >&2
  exit 0
fi

PYV=$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')
echo "ZeroPW session-start: python3 $PYV at $(command -v python3)"

if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "session-start: warning: harness expects Python >= 3.11 (CI uses 3.12)" >&2
fi

if [ -d harness ]; then
  if python3 -I -m compileall -q harness; then
    echo "session-start: harness compile check OK"
  else
    echo "session-start: harness compile check FAILED" >&2
  fi
  echo "session-start: harness tests -> python3 -m unittest discover -s harness -p 'test_*.py' -v"
fi

if [ -d tests ]; then
  echo "session-start: product tests -> python3 -m unittest discover -s tests -p 'test_*.py' -v"
fi

exit 0
