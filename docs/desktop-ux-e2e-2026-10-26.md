# Desktop onboarding and team sharing follow-up — 2026-10-26

This is the historical record for the UX source committed as `35408eb` on base `8bd1d83`. The later integration with main `d6ecf0e` requires its own review and validation, bound to that candidate's exact source. The results below do not certify the later integration.

## Request and scope

The user requested independent desktop E2E testing based on the active Claude session, bug fixes, and simpler onboarding, sharing and joining teams. The user confirmed that the currently installed app contains synthetic test data only.

Implementation starts from `8bd1d83` (local `origin/main`, including the `.env` import work), in the separate `codex/desktop-e2e-onboarding` worktree. The coordinator checkout and Claude's active worktrees are not edited. The coordinator records `gpt-6.1-sol` for the implementation worker; the subagent API does not expose an independent served-model receipt. Actual Claude review-model receipts are recorded separately below. No prior Claude or Opus result is acceptance evidence for this change.

The earlier Claude E2E record covers installation, onboarding, home/relay, keys, HTTP/SSH connections, agents/grants, logs/incidents, team membership/synchronization, settings/recovery, process lifetime, and secret exposure. It reported 65 checks, 59 passing and six failing on its installed build (`fe3fc41`). That is historical, independently reported evidence, not a rerun by this change. Claude's remaining core/desktop-core/UI fixes are separate concurrent work.

## Observed problems and decisions

| ID | Evidence | Change |
| --- | --- | --- |
| UX-01 | Native app: enter a recipient and choose administrator, open Share, then return to Invite. Recipient becomes empty and role resets to user. | Keep the recipient, role and environment in one sheet. The explicit Share and create invite button performs sharing then invitation, retaining both core reauthentication checks. |
| UX-02 | Source: replacing valid invite A with valid invite B leaves A actionable until B's asynchronous preview completes. An older pasted preview can also replace a newer deep link. | Clear actionable ownership immediately; invalidate stale requests on replacement, deep link, close, back and submit; discard superseded core references. Add delayed/out-of-order regression tests. |
| UX-03 | First-run navigation requires visiting optional agent setup before completion. | Finish after the project step; agents remain available through dashboard quick actions and the Agents page. Four counted steps replace five. |
| UX-04 | Sharing exposes address/port controls and joining exposes a generated project/environment path before users need to customize them. | Show the selected address and generated local name; put editable details behind disclosure controls. Expand network details when selection is ambiguous or invalid. Preserve explicit enable, fingerprint verification and join confirmation. |
| UX-05 (Medium) | Modified native Linux app: after an invalid local name opens the details, editing the name clears the error and immediately collapses the input. The same error-derived `open` pattern exists in all four disclosure paths. | Keep explicit disclosure state. Validation opens it on every attempt; clearing an error preserves it. Async interface defaults apply only until the user interacts. Component regressions cover one-character repair, focus, repeated errors and delayed interface loading. |

Sharing remains irreversible for an environment. Every joined trusted device can decrypt its shared credentials regardless of role. Listener enable is explicit, and synchronization still needs the same LAN or a suitable VPN. These limits remain visible. No original secret retrieval path, plaintext fallback, protocol or persisted format is added.

Sharing and invitation are separate writes. A successful share remains recorded if invitation fails. An error with uncertain outcome offers a read-only sharing/invitation status recheck inside the same sheet. It reports an unshared environment, the current invitation count, or a read failure without repeating either write. Password state is cleared after completion or failure.

## Verification record

The checks below were executed against the recorded source snapshots. Platform limitations and failed attempts remain explicit; a mock IPC or unit test is not a native application E2E result.

- Existing native macOS app: independently reproduced UX-01; confirmed invalid pasted invite produces an inline error and no join. This installed build is distinct from the modified worktree.
- Linux isolation: `zeropw-parity` Lima VM, unprivileged `parity`, no host directory mounts, separate source and target directory. True `8bd1d83` frontend control: static checks, 223 tests and build passed.
- Final frontend snapshot, including UX-05 and the focus/error follow-ups: static checks, all **260 tests in 15 files**, TypeScript and Vite production build passed on both Linux and macOS. The suite includes **27 actual React component cases** with mocked IPC; these are not native E2E tests. Linux uses one test worker to avoid shared-VM CPU contention without changing the 5-second test timeout.
- Earlier failed runs are retained: Linux timed out in unrelated animation/terminal tests under CPU contention; macOS exposed a real delayed-autofocus race (247 passing, one failing). The timer race was fixed and a deterministic regression was added before the successful 249-test snapshot and subsequent final 260-test runs.
- macOS: the final temporary Tauri bundle builds and passes deep/strict signature verification, and is left closed. Earlier AppKit/WebKit child processes were live, but CUA accessibility attachment timed out; native macOS UI E2E remains unverified. The task-only network-client entitlement satisfies WebKit bootstrap; unchanged Seatbelt canaries still deny coordinator files, external connections and an unapproved localhost port. The URL-session broker stays denied.
- The Linux negative control removed only the new Sheet focus guard in a disposable copy. The deterministic focus regression failed as expected; the fixed snapshot passed. Neither test assertions nor timeouts were weakened.
- Linux `desktop/verify.sh` completed all eight steps on the 259-test snapshot: static/type/build, strict Rust formatting/Clippy, product binaries and **142/142 desktop Rust tests passed**. The final N10 change removes one TypeScript error-clear and adds one component regression; its separate 260-test frontend checks/build pass. All 279 Rust/core/native source files match the script-tested snapshot exactly. This is recorded as the 259 script plus final 260 frontend validation, not as a full-script invocation on 260.
- macOS `rust/verify.sh` ran all 97 steps and 92 integration targets: 76 steps passed and 21 failed, with 1518 passing and 47 failing test executions. The initial restrictive profile caused NSS/PTY/temp-path/process-inspection limitations; targeted corrected-NSS/timing/session reruns are recorded separately. Restricted SSH failures remain unresolved. Desktop Rust supplemental validation exercised all 10 targets: 125 passing and 17 failing tests (11 PTY, four process/sidecar attachment, two SSH resets). These are not green platform gates. [Detailed macOS evidence](reviews/2026-10-26-desktop-ux-macos-validation.md).
- Linux `rust/verify.sh` completed **97/97 steps and 92/92 integration targets**, with original exit 1: **96 steps passed, one failed; 1561 passing case invocations and one failing case**. The failure was `astra_cli_runtime_round2::ar_cli_01_terminal_prompts_hide_both_passphrases`, an unmet 15-second completion deadline. Two identical full-target follow-ups reproduced it; safe process-state samples showed active CPU work without establishing the cause. After the entire matrix and all task UI/build fixtures finished, the same unchanged full target passed **4/4 cases in 5.19 seconds**. Assertions, deadlines, flags and source were unchanged. Signer probes and doc tests passed. The original script is not relabeled PASS, and no further complete serial matrix was run. [Linux validation evidence](reviews/2026-10-26-desktop-linux-validation.json), [all 97 step records](reviews/2026-10-26-desktop-linux-full-rust-steps.json).

### Actual Linux desktop interaction

The following checks used the built Tauri application, WebKitGTK, real Rust IPC and task-only synthetic state. The app ran on a virtual display inside the isolated Linux VM; Codex operated it through the noVNC browser surface. These checks are independent of the mocked component suite. The initial 255-test native binary and source-manifest hashes are recorded in the [join and self-removal state cross-check](reviews/2026-10-26-desktop-native-linux-crosscheck.json).

| Flow | Observed result |
| --- | --- |
| Fresh onboarding | Four numbered steps; recovery challenge rejects missing answers; a real vault, relay and `codex-ux/dev` project are created. Completion goes directly to the dashboard without optional agent setup. |
| Sharing setup | A single detected interface is collapsed initially. Explicitly enabling a custom test port preserves the recipient and administrator role. |
| Share and invite | Wrong password shows an inline error and clears only the password. Correct retry shares the environment and creates exactly one pending invite; recipient and role are retained. |
| Invite copy | The initial build reports copy success. Native delivery was subsequently verified on the final build below; the noVNC clipboard bridge itself does not forward the sensitive-clipboard value. |
| Invalid invite | An invalid pasted link gives an inline error and no join. |
| Real team join | A controlled peer's invite previews its expected fingerprint/address, then explicit Join succeeds. Read-only CLI checks on both synthetic states confirm the same environment, both active members, and a consumed one-use invite. |
| Confirmation retry | Self-removal with a wrong password leaves a recoverable inline error. The second, correct attempt succeeds. Opening Join afterwards verifies that the parent busy guard was released. |
| Local-name validation | An invalid name with details collapsed reopens and focuses the input. Correction exposed UX-05, recorded before the fix. |
| Used invite | Reusing the consumed invite is rejected; the UI requests a fresh paste. |

Screenshots: [four-step onboarding](evidence/desktop-ux-2026-10-26/onboarding-four-steps.jpg), [invite password retry](evidence/desktop-ux-2026-10-26/invite-auth-retry.jpg), [created invite](evidence/desktop-ux-2026-10-26/invite-created.jpg), [joined team](evidence/desktop-ux-2026-10-26/team-joined.jpg), [confirmation retry](evidence/desktop-ux-2026-10-26/confirm-auth-retry.jpg), [invalid-name focus](evidence/desktop-ux-2026-10-26/join-error-focus.jpg), [UX-05 before fix](evidence/desktop-ux-2026-10-26/join-repair-collapse-before-fix.jpg), [used invite rejected](evidence/desktop-ux-2026-10-26/used-invite-rejected.jpg). All values belong to disposable synthetic fixtures.

The **final 260-test native build** was then launched against the same synthetic state. [Final UI evidence](reviews/2026-10-26-desktop-ux-linux-final-ui.json) binds its source manifest and binary hash to these observed checks:

- UX-05: invalid alias, collapsed details, submit, automatic reveal/error/focus, then an actual single `x` key. The error clears while the input remains open and focused. Repeating invalid submission also returns focus to the field. [After-fix screenshot](evidence/desktop-ux-2026-10-26/join-repair-open-after-fix.jpg).
- N8/N10: a consumed invite is rejected; opening details keeps focus on the summary. Editing the local name with a real key retains the link error, the open input and its focus. The expiry-specific case is covered by a component test; this native check uses a server rejection. [Retained-error screenshot](evidence/desktop-ux-2026-10-26/join-error-retained-after-edit.jpg).
- Home still offers agent setup after the shorter onboarding; its Add agent action opens the Agents connection sheet. [Shortcut screenshot](evidence/desktop-ux-2026-10-26/final-home-agent-shortcut.jpg).
- Native clipboard delivery: Home Invite teammate opens the sheet, an additional synthetic invite is created, Copy succeeds, and native Ctrl+V into Join produces the expected own-device fingerprint, user role and address. The noVNC clipboard was not touched between Copy and Paste. No Join was submitted. [Copy result](evidence/desktop-ux-2026-10-26/final-native-copy.jpg), [pasted preview](evidence/desktop-ux-2026-10-26/final-native-paste-preview.jpg).
- The additional clipboard-test invite is [revoked through the UI](evidence/desktop-ux-2026-10-26/final-clipboard-invite-revoked.jpg). A [read-only state cross-check](reviews/2026-10-26-desktop-native-linux-clipboard-fixture.json) confirms its revocation and that the original administrator invite remains the only pending invite. More than 60 seconds after Copy, the same native paste into a fresh focused field [leaves it empty](evidence/desktop-ux-2026-10-26/final-native-clipboard-cleared.jpg), consistent with the announced clipboard cleanup. The exact 60-second boundary was not measured.
- Keys, Connections, Records, Incidents and Settings render their expected state during navigation smoke checks. These checks do not claim key/connection CRUD or a complete rerun of Claude's 65 cases.

Tab/Space forwarding through the noVNC surface was unreliable, so keyboard-only traversal is not marked PASS. Actual one-character editing was checked only after native input focus was visibly established. The test clipboard was cleared and the temporary browser viewport restored after the checks.

No merge, deployment, replacement of the installed app, or release acceptance is implied by this record.

## Independent review and platform authorization

Tool-free Claude review was invoked from the coordinator with hooks, MCP, skills and session persistence disabled. Both the initialization and assistant response model were verified as `claude-opus-5-5` (requested alias `opus`, medium effort). [Round one](reviews/2026-10-26-desktop-ux-opus-round1.json) returned **REVISE** with nine original findings. Their original severity and evidence are retained. The review is static inspection, not native testing.

| Review ID | Original severity | Required follow-up |
| --- | --- | --- |
| F1 | Medium | Treat post-commit timeout, malformed response and unknown failure as uncertain; permit retry only for known rejection before mutation. |
| F2 | Medium | Defer incoming links while an operation is in progress; prevent an older completion from closing a newer sheet; discard late one-time references. |
| F3 | Medium | Disclose that sharing requires granting agent permissions again. |
| F4 | Medium | Preserve keyboard focus and move it after errors render and busy state clears. |
| F5 | Low | Verify lifecycle behavior and the actual StrictMode setting. The application entry point currently does not enable StrictMode. |
| F6 | Low | Update all four-step onboarding documentation and remove obsolete agent-step wiring. |
| F7 | Low | Distinguish unknown/loading sharing state from missing setup; offer recovery from load failure. |
| F8 | Low | Retain a user-customized local name while replacing a link. |
| F9 | Low | Exercise the real components, delayed operations and failure handling, then repeat final validation. |

[Round two](reviews/2026-10-26-desktop-ux-opus-round2.json) resolved F1–F8 and kept F9 open pending final validation. It returned **REVISE** with the following new findings; original severity is retained:

| Review ID | Original severity | Required follow-up |
| --- | --- | --- |
| N1 | High | Release both confirmation busy guards after success or failure, allowing wrong-password retry and subsequent page/deep-link actions. |
| N2 | Low | Keep uncertain sharing results in the sheet and offer read-only status recovery, including unshared and failed-read states. |
| N3 | Low | Preserve focused invitation fields during operations and focus rendered form-level errors. |

[Round three](reviews/2026-10-26-desktop-ux-opus-round3.json) returned **PASS for static source review**, resolving F1–F8 and N1–N3, while F9 remained open for platform/native validation. Its additional Low findings N4 (late join feedback and in-flight lifetime), N5 (queued reference replacement), and N6 (copy/documentation cleanup) were fixed. [Round four](reviews/2026-10-26-desktop-ux-opus-round4.json) returned **PASS for the bounded source fixes**. N7 is an optional Info-level copy refinement: an unreadable listener setting conservatively leads to explicit setup; it does not claim synchronization is working.

Native testing then found UX-05. [Round five](reviews/2026-10-26-desktop-ux-opus-round5.json) accepted the disclosure fix and identified Low N8 (stale join-error focus replay) and N9 (repeating an invalid submission while details are already open). [Round six](reviews/2026-10-26-desktop-ux-opus-round6.json) accepted their fixes and identified Low N10 (alias editing unnecessarily clearing an expired-link error). [Round seven](reviews/2026-10-26-desktop-ux-opus-round7.json) returned **PASS for the final bounded source fix**, preserving the previous fixes. Its N11-info is an optional test-strength suggestion, not a product defect. All original finding severities and evidence remain in the review files. No actionable source defect from these reviews remains open; F9 still tracks the platform/native limitations and is not a release PASS.

The [review receipt and product source manifest](reviews/2026-10-26-desktop-ux-review-manifest.json) records actual models, input/output hashes and source hashes. These static reviews do not replace executed tests.

An independent [source cross-check](reviews/2026-10-26-desktop-ux-source-crosscheck.json) compares all 22 changed desktop source/test/package files across the current worktree, review receipt, Linux final-build input and macOS final-build input: **22 match, zero mismatches**. The broader `rust/` and `desktop/` comparison also matches all **381 files** across both build inputs and the worktree. Documentation and evidence were finalized after those build snapshots.

The user explicitly authorized a task-specific exception for macOS verification on the coordinator host **inside a sandbox**. That authorization covers a separate temporary app and synthetic vault, with home-data/Keychain/coordinator-auth access restricted, and does not authorize replacing the installed app. The initial deny-default build profile verified that synthetic task files are accessible while the coordinator checkout and original Cargo directory are denied. UI-specific sandbox permissions and all platform limitations must be recorded with the execution results. This does not establish production host isolation.
