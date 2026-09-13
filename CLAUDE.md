# ZeroPW — Claude Code instructions

@AGENTS.md

## Claude Code working notes (local and claude.ai/code cloud)

- Read the sources listed in AGENTS.md before changing product behavior. `harness/README.md` describes the real development loop.
- The harness is Python standard library only. Nothing to install. Python >= 3.11 is required; CI runs 3.12.
- Validate every harness change with:

  ```sh
  python3 -m compileall -q harness
  python3 -m unittest discover -s harness -p 'test_*.py' -v
  ```

  Product code goes with its own tests in `tests/test_*.py`; the existing CI picks them up automatically.
- Operational control files are off-limits unless the user explicitly asks for a change to them: `.github/`, `harness/`, `AGENTS.md`, `docs/harness.md`, `docs/product-intent.md`, `docs/security-design.md`. The controller blocks automatic push of any diff touching them.
- Never read, print, or commit `.zeropw-harness/` or `.env*`. Never place real keys, tokens, or session credentials in the repo, prompts, hooks, or environment variables. Use synthetic credentials only.
- Do not merge, deploy, or change repository permissions. Open or update a PR and stop.

## Session setup

- `.claude/settings.json` runs `.claude/hooks/session-start.sh` on session start and resume. It only reports the Python version and runs the isolated-mode compile check for `harness/`. It never installs packages or runs tests.
- claude.ai/code environment for this repo: setup script `bash harness/cloud_setup.sh`, network access `Trusted` (default allowlist is enough; no extra domains needed), no environment variables and no secrets. Ubuntu 24.04 with Python 3.x, git, and gh is preinstalled.
