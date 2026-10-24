# .env import

Written 2026-10-25 as a design specification; implemented the same day (§10). Decisions are recorded in §9.

Read one `.env` file and put the keys in it into the vault at once. Imported into a shared environment, they reach other devices in one commit. The requirements of the [product](product-intent.md), [security boundary](security-design.md), [team sharing](team-sync.md) and [desktop app](desktop-app.md) do not change.

## 1. Why

Today every key needs its own `secret put --stdin`. For someone who already keeps several keys in a `.env`, that is the most tedious part of moving to ZeroPW or sharing with a team.

Importing does not conflict with the security boundary. Values enter only through the administrator input path and are stored as `secret put` stores them. The security design already says "Any environment-file import must parse data, never execute it" ([security-design.md](security-design.md), line 83). The opposite direction, exporting from the vault to a `.env` or into a process environment, is outside this document and will not be built (§8).

## 2. Flow

1. A human picks a `.env` file in the admin screens, drops it on the desktop app's window, or names it to `zeropw-admin`.
2. Preview: parse the file and show, per line, the variable name, the key ID it would create, and whether it would be imported and why. Values are not shown.
3. The human chooses the entries to import. The default selection follows the rules in §4.
4. Write the chosen entries at once. If any one fails, nothing is written.
5. Show the keys created, the keys left unchanged and the entries skipped, and say that the original file is still on disk.

## 3. Parsing rules

Tools (Node `dotenv`, `python-dotenv`, Docker Compose) read `.env` slightly differently. Storing a value other than the one the user's app actually read breaks it silently, so **accept only forms every tool reads the same way, and stop on an ambiguous line with an error.** Never execute shell syntax.

| Item | Rule |
| --- | --- |
| Size | File up to 64 KiB (`MAX_SECRET_BYTES`), at most 200 entries. UTF-8 only; a leading BOM is removed. A NUL byte is an error. |
| Lines | Accept `\n` and `\r\n`. A carriage return outside `\r\n` is an error (tools differ on whether it ends a line). Skip blank lines and lines starting with `#` (leading whitespace allowed). |
| Form | `[export ]NAME=VALUE`. Whitespace around `=` is removed. A line without `=` is an error. |
| Name | `[A-Za-z_][A-Za-z0-9_]*`. A name appearing twice is an error (tools differ on whether the first or the last wins). |
| Unquoted value | Trim surrounding spaces and tabs. A `#` after a space starts a comment. A `#` right after other text (`abc#def`) or a tab (`abc\t#x`: Compose keeps it) differs between tools and is an error, and so does a value that starts with `#` (`NAME=#x`, `NAME= #x`: Node reads an empty value, python-dotenv `#x`) or with `=` (`NAME==`; a padded base64 token on a line of its own would otherwise become a name). Other whitespace or a control character at either end (U+00A0, U+FEFF, `\v`, …) is an error, because the tools trim different sets. |
| Single-quoted value | Content is taken literally. Multiple lines are accepted. A `\` inside is an error (tools unescape it differently). |
| Double-quoted value | Multiple lines are accepted. Only `\n` and `\r` are unescaped; any other `\` sequence is an error. |
| Quoted line ends | A quoted value spanning a line that ends in `\r\n` is an error: Node and python-dotenv read `\n` there, Compose `\r\n`. |
| `$` | A `$` in an unquoted or double-quoted value is an error, because tools differ on variable expansion. Wrapped in single quotes it is taken literally. |
| Other | Backtick quotes, non-comment text after a closing quote and an unclosed quote are errors. |
| Empty value | `NAME=` and `NAME=""` are skipped, not errors. |

Collect all errors and report them together. Report **only the line number and a reason code**, never the line's text. Output a variable name only for an entry that parsed correctly and has a non-empty value. This keeps something like a token pasted without `=` out of the output.

Reason codes: `not_assignment`, `invalid_name`, `name_too_long`, `duplicate_name`, `unquoted_hash`, `dollar_needs_single_quotes`, `unsupported_escape`, `backslash_in_single_quotes`, `backtick_quote`, `unterminated_quote`, `trailing_text`, `nul_byte`, `lone_carriage_return`, `unusual_whitespace`, `crlf_in_quotes`. A NUL or a lone carriage return stops the file before its lines are read, so only those are reported then. The parser is `rust/src/envfile.rs`.

## 4. What to import

**Putting configuration values in the vault too blocks other features.** Every vault value feeds these checks:

- CLI profile check (`profile_env_carries_vault_value` in [tools.rs](../rust/src/tools.rs)): when a vault value appears in a saved CLI connection's environment variable names or values, that connection can be neither created nor run (`cli_env_contains_credential`).
- Incident record check (`value_leak` in [incident.rs](../rust/src/incident.rs)): when a vault value appears in an incident's JSON, its assessment is redacted, and the notification email is not sent (`rendered_value_detected`).

Since issue #60 both checks match by value length (`runs::vault_scan_patterns`, `tools::profile_env_carries_other_value`). A value of at least 8 bytes (`MIN_PATTERN_LENGTH`) matches even inside other text. So storing `NODE_ENV=development` refuses CLI connections that contain `development`, and redacts incident records in which it appears. A value shorter than 8 bytes is left out of the incident check, but the CLI profile check still matches it when an environment variable name or value equals it as a whole. So storing `PORT=3000` refuses CLI connections that set a variable to `3000`.

So each entry gets a default selection. The rules are deterministic, and the preview shows the result with its reason.

| Order | Condition | Default | Reason code |
| --- | --- | --- | --- |
| 1 | The value consists only of digits, `.` and `-`, or is `true/false/yes/no/on/off` (case-insensitive) | Skip | `plain_value` |
| 2 | The value is shorter than 8 bytes (`MIN_PATTERN_LENGTH`) | Skip | `short_value` |
| 3 | Splitting the name on `_` yields one of `KEY`, `APIKEY`, `SECRET`, `TOKEN`, `PASSWORD`, `PASSWD`, `PWD`, `PASS`, `PASSPHRASE`, `CREDENTIAL(S)`, `AUTH`, `PRIVATE`, `DSN`, `SIGNING`, `SALT`, `COOKIE`, `SESSION`, `WEBHOOK` | Import | `secret_name` |
| 4 | The value is a URL of the form `scheme://user:password@…` | Import | `url_password` |
| 5 | Anything else | Skip | `no_hint` |

Rules 1 and 2 are checked before rule 3, so that `AUTH_ENABLED=true` or `TOKEN_TTL=3600` does not become a key. A value shorter than 8 bytes is unlikely to be an API key, and storing it refuses CLI connections that use the same value. Rule 5 keeps out long configuration values such as `development` or an API address. Misclassification errs on the safe side: a missed key stays in the original file and its name appears in the result's skipped list, so it can be imported again.

A human can override the defaults. `--include NAME,…` imports entries that would be skipped and `--exclude NAME,…` drops entries that would be imported. Forcing in an entry skipped by default (rules 1, 2 and 5) marks it `forced: true` in the result, with a one-line note about the side effects above.

## 5. Key IDs and existing keys

The key ID rule (`validate_name` in [projects.rs](../rust/src/projects.rs)) is a lowercase letter or digit followed by `[a-z0-9._-]`, up to 64 characters. A key ID is unique across the whole vault, regardless of project and environment.

- The ID is the optional `--id-prefix` plus the lowercased name: `OPENAI_API_KEY` → `openai_api_key`.
- A result that breaks the rule (a name starting with `_`, more than 64 characters) is `invalid_name` or `name_too_long`.
- Two names differing only in case that map to the same ID stop with `id_collision`.
- When the ID already exists in a **different** project or environment, stop with `secret_identity_mismatch`; the preview suggests `--id-prefix`. Importing the same `.env` into both `dev` and `prod` is this case.
- When it already exists in the same project and environment, compare the value with the active version (inside the trusted process only).
  - Equal: `unchanged`, nothing is written.
  - Different: by default `conflict` stops the whole import. With `--update`, create a new version and make it active. Retiring the previous version, rebinding connections and moving connections pinned to the previous version (`moved_connections`) work as in `secret put`.
  - The existing key's kind is kept.
- A new key's kind is `--kind` (default `env_var`; `api_key` and `password` are also accepted). HTTP connections accept all three. `ssh_private_key` is not accepted.

The original variable name is not stored. It can be inferred from the ID, and the storage format stays unchanged (§9).

## 6. CLI

```
zeropw-admin secret import --project P --environment E (--file PATH | --stdin)
    [--dry-run] [--include A,B] [--exclude A,B] [--id-prefix X] [--kind K] [--update]
```

`secret import` is hidden from `secret`'s listing like `status`, because the recorded command-line contract pins that help text; `secret import -h` prints its own help. `--include` and `--exclude` may be repeated. A name in both is `import_selection_conflict`; a name that is not an entry with a value is `import_name_unknown` (the detail counts them and names none). An `--id-prefix` that cannot start a key ID is `invalid_id_prefix`.

- `--stdin` and the input envelope work as for `secret put`. With an envelope, `value_b64` carries the whole file. The envelope gains no new field. 64 KiB encoded as base64 still fits the envelope's 256 KiB limit.
- `--dry-run` writes nothing and only produces the preview. The app's preview uses it too, so parsing and classification live only in the CLI.
- Output (no values):

```json
{
  "project": "team-keys", "environment": "shared", "dry_run": false,
  "entries": [
    {"line": 3, "name": "OPENAI_API_KEY", "id": "openai_api_key", "kind": "env_var",
     "selected": true, "why": "secret_name", "action": "created", "state": "new", "version": 1},
    {"line": 5, "name": "PORT", "id": "port", "kind": "env_var",
     "selected": false, "why": "plain_value", "action": "skipped", "state": "new"}
  ],
  "shared": false, "empty_lines": [9],
  "commit": null, "propagated_to": 0,
  "source_left_in_place": true
}
```

  `selected` is the default selection and `why` its reason. `action` is `create|new_version|unchanged|conflict|id_taken|skip` in the preview (`id_taken`: the ID is used in another project or environment) and `created|new_version|unchanged|skipped` in a real run. `state` says what importing the entry meets whether or not it is selected: `new`, `same` (the active value is equal), `different` or `elsewhere`, so a screen can show what turning an entry on would do. `forced: true` marks an entry selected against the default, and `blocked_by` names a saved CLI connection whose profile carries the value (§7); the preview reports both and never stops on them, nor on `conflict` or `id_taken`. In a shared environment, `shared` is true, `commit` holds `{author_seq, hlc}` and versions appear as `version_id`; `moved_connections` lists connections moved to a new version. `source_left_in_place` appears with `--file` only. The `state` of an existing key tells whether a value in the file equals its active value, without a passphrase. Whoever can run `zeropw-admin` already learns as much from the CLI profile check (`cli_env_contains_credential`) and can read the vault with the local key file, so the preview adds no access.
- Parse errors stop with `env_file_invalid`; the detail holds only a `line:reason` list (at most 50). Other errors: `env_file_too_large`, `env_file_not_utf8`, `env_file_too_many_entries`, `import_nothing_selected`, `id_collision`, `secret_identity_mismatch`, `import_conflict`, `cli_env_contains_credential`.

## 7. Writing

**All or nothing.** Write only after parsing, ID computation, comparison with existing keys and the CLI profile check have all finished.

- Personal environment: add a batch write (`Vault::put_secrets`) that writes the vault document once while holding the state lock. Validation is the same as `put_secret_values`. After writing, rebind connections for each changed key. Audit each key with the same `secret_put` record as today, then add one summary `secret_import` record: project, environment, `count` and the source `file|stdin` in `detail`. No path and no names. An audit field holds no list, so the IDs are in the `secret_put` records (personal) or the commit (shared). A refused run (a file that does not parse, a conflict, an ID used elsewhere, a CLI profile, `not_admin`, …) records `secret_import` as `denied` with the reason; a preview records nothing.
- CLI profile check: check every chosen value against saved CLI connections with the same rule as `secret put` (`profile_env_carries_new_value`): connections that use that key at any length, the rest under the length rule in §4. A match stops the whole import and reports the connection ID and the entry name. Shared environments get the same check. Today `secret put` in a shared environment (`shared_put`) does not run this check; import blocks it from the start.
- Shared environment: put the chosen entries' `secret.put_version` and `secret.activate` (including the operations that move connections to the new version, as `shared_put` does) in **one commit**. Stopping with `team_rekey_pending` while a rekey is pending is the same as `secret put`. A non-admin device stops with `not_admin` before anything is authored, as every command does (`membership::author_commit` checks the author's standing first, issue #30). A running `serve` sends the commit to other devices on its next poll. The ciphertext of 200 entries fits the 4 MiB frame limit. An environment this device joined is mapped in the team state rather than `projects.json`, so the import resolves the shared environment before it checks the project.
- Values stay in `Zeroizing` buffers from start to finish, intermediate parse results included.

## 8. Desktop app

- The keys screen has ".env 가져오기" (".env import"). A `.env` file dropped anywhere on the window opens the same sheet at once, on the keys screen, with a shared environment chosen first: dropping a file is the quickest way to share its keys with the team.
- `file_pick {purpose: "env_file"}`: new purpose `FilePurpose::EnvFile`. A token picked for another purpose cannot be used for an import. The macOS open panel hides dot files; the button's tooltip says that Command+Shift+period shows them.
- `env_file_load {file_token}` → `{import_ref, name}`: the core reads the picked file (up to 64 KiB, UTF-8, not empty) into the one-time store for 10 minutes under a new kind, `EnvImport`, with a pool of its own (4 files, the oldest dropped first). That kind cannot be taken out with `onetime_show` or `onetime_copy`; only the two import commands read it. Only the file's base name reaches the webview.
- A drop: the window takes file drops (`dragDropEnabled`). The shell hands the dropped paths to the core, which reads exactly one regular file as `env_file_load` does and emits `envfile://dropped` with `{import_ref, name}`, or `{error}` (`drop_one_file`, `file_not_regular`, `env_file_too_large`, `env_file_empty`, `env_file_not_utf8`, `vault_missing`). `envfile://hover {over}` tells the page to show where to drop. The paths stay in Rust. Tauri also emits its own drag events with the paths, but only to page listeners for them, and the page registers none (`desktop/scripts/check-static.mjs` refuses them); with the `protocol-asset` feature off (`check-tauri.mjs`), the scope Tauri widens for a dropped path grants nothing.
- `secret_import_preview {import_ref, project, environment, id_prefix?}` → the report of `secret import --stdin --dry-run` (the file goes in the envelope's `value_b64`). The webview receives only names, IDs, kinds, selection, reasons, actions, states, `forced`, `blocked_by` and the empty lines; the core keeps no other field of the CLI output.
- `secret_import {import_ref, project, environment, id_prefix?, selected: [name…], update}`: the core previews again, turns the difference between `selected` and the default selection into `--include`/`--exclude` (split into arguments of at most 2,000 characters), runs the import and deletes the kept content on success. A selected name that is not an entry with a value is `invalid_selection` before the CLI runs. Like `secret_put`, it asks for no reauthentication.
- The sheet: each entry is a chip with its name, key ID (when a prefix changes it) and reason, and a tag for what importing it would do. Selecting an entry that is skipped by default shows the side effect of storing a setting; an entry whose value a CLI connection carries, another value without "새 값으로 바꾸기" (update), or an ID used elsewhere keeps the import button from running and says why. The prefix field appears when an ID is used elsewhere. A file the parser refuses shows its line numbers and reasons. The import button reads "N개 넣고 공유하기" in a shared environment.
- Screen copy (examples; the app's interface is Korean only): above the list, "키로 보이는 항목만 골라 뒀어요. 설정값은 넣지 않는 게 좋아요." ("Only the entries that look like keys are selected. Better not to store configuration values."). After the import, "원래 .env 파일은 그대로 있어요. 에이전트가 읽을 수 있는 곳이면 지워 주세요." ("The original .env file is still there. If an agent can read it where it is, delete it.").

Not provided:

- Exporting from the vault to a `.env`, putting values into a process environment, or executing shell syntax.
- Changing or deleting the original file. A key in a file an agent could already read stays exposed after import; where needed, issue a new key at the service.
- Variable expansion, other formats such as JSON or YAML, or searching the repository for `.env` files automatically.
- Importing through agent tools (`zeropw-agent`, MCP). Import happens only through the administrator input path.

## 9. Decisions

On 2026-10-25 the owner accepted all five proposals below. The body (§3–§8) follows these decisions.

| Item | Decision | Option not chosen |
| --- | --- | --- |
| Classification rules (§4) | Set the default selection by the name-fragment list in the table and the 8-byte threshold | Start with everything selected, without classification |
| Ambiguous syntax (`$`, attached `#`, `\`) | Stop with an error (§3) | Take the text literally and only warn |
| Storing the original variable name | Not stored (§5) | Put `env_name` in the version's `public` metadata and show it on teammates' screens too. Fold currently accepts any object as `public`, so 0.2.0 devices could still be mixed in. |
| Original file | Only a notice (§8) | A button in the app that moves it to the Trash (the core moves only the one picked file) |
| Existing key with a different value | Stop by default; `--update` creates a new version (§5) | Create a new version by default |

The options not chosen are kept for later reference. Changing a decision requires a new owner decision.

## 10. Implementation stages and tests

1. **Parsing and classification module** (`rust/src/envfile.rs`, unit tests): each rule and error code in §3, the classification table in §4, BOM, CRLF, multi-line values and limits. Error output carries no line content (synthetic values). A file containing `$(touch FILE)` or backticks does not create that file.
2. **CLI, personal environment** (`rust/tests/admin_secret_import.rs`): `secret import`, `Vault::put_secrets`. Creation, unchanged, conflict, `--update`, the same ID in another environment, case collisions, `--id-prefix`, CLI profile refusal, `--include`/`--exclude`, `forced`, the envelope path and parse errors. On failure the vault document is byte-for-byte unchanged and no `secret_put` record was added. Output, errors, the audit log and state files hold no synthetic value.
3. **Shared environment** (`rust/tests/team_secret_import.rs`): three devices with their own `serve --team-listen`. The owner's import is one commit that an admin and a user device both derive; the user device's import stops with `not_admin` before authoring anything; the admin device's `--update` reaches the owner. No synthetic value in any output, state directory or the wire capture. `team_rekey_pending` is the existing `author_commit` check, not exercised by these tests.
4. **Desktop**: `desktop/core/tests/e2e_env_import.rs` against the real binaries (a drop and a picked file, purpose-bound single-use tokens, `onetime_*` refused, no value in any event or report, the selection turned into include/exclude, conflict then update, refused drops, parse errors); unit tests for the one-time store pool and 10-minute expiry, the selection arithmetic and the inputs; `desktop/test/envimport.test.ts` for the sheet's rules and the mock.
5. **Documentation**: [implementation.md](implementation.md), the command table in [desktop-app.md](desktop-app.md), [GUIDE.md](../GUIDE.md) and the README. The team onboarding manuals describe the 0.2.0 release, which has no import; they change with the next release (their files are bound to validated cases).

Product changes run `rust/verify.sh` on Linux and macOS; app changes run `desktop/verify.sh`.
