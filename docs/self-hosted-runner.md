# Mac mini verification runner

This workflow uses your own Apple Silicon Mac mini, not billable GitHub-hosted runners. It is manual-only: pull requests and forks cannot automatically start product execution on your machine.

## Prepare the runner

Use a dedicated disposable verification machine or equivalent isolation with no production credentials, vault state, signer keys, administrator/recovery material, deployment authority or coordinator session. Do not register the current trusted coordinator account as the verification runner. A clean environment does not remove credentials that remain accessible on disk; the machine boundary is the requirement.

Install a Rust toolchain supporting edition 2024, Python 3, Git, Homebrew, Homebrew `openssl@3`, Perl and OpenSSH client/server tooling. The real SSH E2E must be able to start `sshd` as the verification user. Install GitHub's official self-hosted runner from the repository's **Settings → Actions → Runners** page, in the dedicated verification environment. Enter registration material directly there; never paste it into agent chat or commit it.

Use the default `self-hosted`, `macOS`, and `ARM64` labels and add `zeropw-isolated`. Configure only this repository's trusted maintainers to dispatch it. Do not add automatic PR execution. An ephemeral runner is preferable because a test can change its execution environment; rebuild it before running another untrusted revision.

## Enable and run

GitHub Actions is currently disabled for this repository. Registering a runner is not enough: the owner must enable Actions when ready. The existing hosted `Harness CI` workflow is now manual-only, so pushes and PRs do not consume hosted minutes. Do not dispatch that hosted workflow if you want to avoid hosted charges. This preparation has not changed repository settings.

The workflow is `.github/workflows/self-hosted-verification.yml`. After the workflow exists on the default branch:

1. Open **Actions → Self-hosted release verification → Run workflow**.
2. Enter the full 40-character SHA of the reviewed preparation commit.
3. Confirm that the runner has no product or coordinator authority.
4. Dispatch and keep the runner online until completion.

It checks the exact checkout, installer boundary tests, harness tests/compilation, the complete Rust matrix, installed release binaries and the Homebrew source formula. A success summary names the verified commit. A queued job is not test success. Preserve failed checks and inspect their logs rather than treating a rerun as evidence that the original failure never happened.

This Mac runner proves Apple Silicon macOS behavior. Linux validation is separate; the existing isolated Linux VM can run `rust/verify.sh` under an unprivileged user with no host mounts or forwarded agent. Intel macOS and x86-64 Linux release packages need their own build/install evidence before advertising those downloads.
