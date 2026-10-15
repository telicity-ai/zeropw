// IPC contract between the webview and the Tauri core. Single source of truth for command
// names and payload shapes; the Rust handlers in desktop/src-tauri and desktop/core mirror it.
// See docs/desktop-app.md §5. Values that are secrets never come back from these calls except
// through onetime_show, and inputs are never echoed in errors.

export interface AppError {
  error: string;   // error class, e.g. "AuthFailed", "InvalidInput", "UsageError"
  reason: string;  // stable reason code, e.g. "passphrase_missing", "invite_expired"
  detail?: string; // value-free detail
}

export interface Control { stopped: boolean; restore_pending: boolean; incident_open: boolean }
export interface ServeStatus { running: boolean; url: string | null; pid: number | null; team_listen: string | null }
export interface AppStatus { initialized: boolean; state_dir: string; serve: ServeStatus; control: Control | null }

export interface Project { name: string; environments: string[]; created_at: string }
export type SecretKind = 'api_key' | 'password' | 'env_var' | 'ssh_private_key';
/** A secret version exactly as the CLI printed it (the CLI prints JSON numbers; a string is
 *  accepted too). The version commands take it back unchanged; do not convert it. */
export type VersionId = string | number;
export interface SecretVersion { version: VersionId; status: string; created_at: string; public?: { public_key: string; fingerprint: string; algorithm: string } | null }
export interface SecretView { id: string; project: string; environment: string; kind: SecretKind; active_version: VersionId | null; versions: SecretVersion[] }
/** Where a new secret value comes from. `typed` crosses IPC once; `file_token` refers to a file picked natively in Rust. */
export type SecretSource = { typed: string } | { file_token: string } | { generate_ed25519: true };

export interface HttpConnectionInput {
  id: string; project: string; environment: string; service: string; secret_id: string;
  target: string; auth: 'bearer' | 'basic' | 'header'; header_name?: string; value_prefix?: string; basic_username?: string;
  methods: string[]; confirm_methods: string[]; path_prefixes: string[];
  allow_private_network: boolean; cli_program?: string; ca_file_token?: string; description?: string;
}
export interface SshConnectionInput {
  id: string; project: string; environment: string; service: string; secret_id: string;
  host: string; port: number; username: string; host_keys: string[]; description?: string;
}
/** Connection::to_value as printed by the CLI; kept loose on purpose. */
export type ConnectionView = Record<string, unknown> & { id: string; project: string; environment: string; kind: string; status: string };

export interface Principal { id: string; status: string; created_at: string; runtime: string }
export interface Grant { id: string; principal: string; connection: string; expires_at: string; max_uses: string | null; uses: string; status: string }
export interface AuditRecord { [k: string]: unknown }
export interface Alert { ts: string; alert: string; caller?: string; connection?: string; event?: string; reason?: string; detail?: string }
export interface Incident { id: string; status: string; scope: string; opened_at: string; [k: string]: unknown }

export interface InvitePreview { env_id: string; inviter: string; addresses: string[]; role: 'user' | 'admin'; name: string; expires_at: string; expired: boolean; invite_id: string }
export interface InviteListItem { invite_id: string; role: string; name: string; link: boolean; created_at: string | null; expires_at: string; status: 'pending' | 'used' | 'expired' | 'revoked'; used_at: string | null; used_by: string | null; revoked_at: string | null }
export interface Member { fingerprint: string; name: string; role: string; status: string; owner: boolean }
export interface Settings { gateway_port: number; team_listen: string | null }
export interface NetInterface { name: string; ip: string; kind: 'vpn' | 'lan' | 'other' }

/** Command name → [input, output]. */
export interface Commands {
  app_status: [void, AppStatus];
  /** score: the zxcvbn score 0..4; reason: a code from desktop/core/src/strength.rs or null. */
  password_strength: [{ value: string }, { score: number; reason: string | null }];
  recovery_generate: [void, { ref: string; groups: string[] }];
  vault_init: [{ admin_passphrase: string; recovery: { ref: string } | { typed: string } }, { state_dir: string; kms_key_id: string }];
  /** A failed start carries the sidecar's own reason when it printed one (docs/desktop-app.md
   *  §5). A failure to open an address has detail 'gateway_port' (listen_failed) or
   *  'team_listen' (team_invalid_listen_address, team_listen_failed, invalid_listen). The
   *  start at the end of vault_init fails the same way. */
  serve_start: [void, ServeStatus];
  serve_stop: [void, ServeStatus];
  serve_status: [void, ServeStatus];
  control_get: [void, Control];
  stop_all: [void, Control];
  resume: [{ admin_passphrase: string }, Control];

  project_list: [void, { projects: Project[] }];
  project_create: [{ name: string; environments: string[] }, Project];

  secret_list: [{ project?: string; environment?: string }, { secrets: SecretView[] }];
  secret_versions: [{ id: string }, SecretView];
  secret_put: [{ id: string; kind: SecretKind; project: string; environment: string; source: SecretSource }, Record<string, unknown>];
  secret_reveal: [{ id: string; version?: VersionId; admin_passphrase: string }, { ref: string; id: string; version: VersionId }];
  secret_retire: [{ id: string; version: VersionId }, Record<string, unknown>];
  secret_revoke: [{ id: string; version: VersionId }, Record<string, unknown>];

  connection_list: [void, { connections: ConnectionView[] }];
  connection_create_http: [HttpConnectionInput & { admin_passphrase: string }, ConnectionView];
  connection_create_ssh: [SshConnectionInput & { admin_passphrase: string }, ConnectionView];
  connection_disable: [{ id: string }, Record<string, unknown>];

  principal_list: [void, { principals: Principal[] }];
  principal_create: [{ id: string; runtime: string }, { id: string; runtime: string; token_ref: string }];
  principal_disable: [{ id: string }, Record<string, unknown>];
  grant_list: [{ principal?: string }, { grants: Grant[] }];
  grant_create: [{ principal: string; connection: string; ttl: string; max_uses?: string; admin_passphrase: string }, Grant];
  grant_revoke: [{ id: string }, Grant];

  terminal_open: [{ token_ref: string; as_user?: string; on_data: unknown /* Channel<string> */ }, { terminal_id: string; suggestions: string[] }];
  /** Queued for the terminal's writer; Unavailable/terminal_busy while the program leaves 256 KiB unread. */
  terminal_write: [{ terminal_id: string; data: string }, void];
  terminal_resize: [{ terminal_id: string; cols: number; rows: number }, void];
  /** Stops the shell and every process started in it; returns when done (up to about 2 s). */
  terminal_close: [{ terminal_id: string }, void];
  /** Terminals stay alive after onboarding so the agent keeps running; the Agents page lists and reattaches. */
  terminal_list: [void, { terminals: { terminal_id: string; principal: string; as_user: string | null; alive: boolean }[] }];
  /** Replays the buffered output (bounded ring) into on_data, then keeps streaming. */
  terminal_attach: [{ terminal_id: string; on_data: unknown /* Channel<string> */ }, { terminal_id: string; suggestions: string[] }];
  /** Window content protection (screen-capture block) while a one-time value is visible.
   *  `protected` is false when the platform has none (Linux): the UI must not claim it then. */
  secure_view: [{ on: boolean }, { protected: boolean }];

  audit_tail: [{ limit: number }, { records: AuditRecord[]; unparseable_lines: number }];
  alerts: [{ limit: number }, { alerts: Alert[]; unparseable_lines: number }];
  approvals_list: [void, { approvals: Record<string, unknown>[]; history: Record<string, unknown>[] }];
  approvals_approve: [{ digest: string; admin_passphrase: string }, Record<string, unknown>];

  incident_list: [void, { incidents: Incident[] }];
  incident_show: [{ id: string }, Incident];
  incident_declare: [{ scope: 'principal' | 'runtime' | 'all'; principal?: string; runtime?: string; reason?: string; admin_passphrase?: string }, Incident];
  incident_close: [{ id: string; admin_passphrase: string }, Incident];

  backup_create: [void, Record<string, unknown>];
  backup_restore: [{ admin_passphrase: string }, Record<string, unknown>];
  restore_ack: [{ admin_passphrase: string }, Record<string, unknown>];
  recover: [{ recovery_passphrase: string }, Record<string, unknown>];

  team_init: [void, { fingerprint: string }];
  team_share: [{ project: string; environment: string; name?: string; admin_passphrase: string }, Record<string, unknown>];
  team_members: [{ env: string }, { env_id: string; members: Member[] }];
  team_remove: [{ env: string; device: string; admin_passphrase: string }, Record<string, unknown>];
  team_invite_create: [{ env: string; role: 'user' | 'admin'; name: string; address: string; admin_passphrase: string }, { invite_id: string; link_ref: string; expires_at: string; inviter: string }];
  team_invites: [{ env: string }, { env_id: string; invites: InviteListItem[] }];
  team_revoke_invite: [{ env: string; invite_id: string }, Record<string, unknown>];
  /** The core keeps the invite behind `ref` for team_join for 60 minutes (at most 16, the
   *  oldest dropped first) and forgets it once a join succeeds. */
  team_invite_preview: [{ text: string }, { ref: string; preview: InvitePreview }];
  team_join: [{ ref: string; project?: string; environment?: string }, { env_id: string; self_fingerprint: string; inviter_fingerprint: string; project: string; environment: string }];

  onetime_show: [{ ref: string }, { text: string }];
  onetime_copy: [{ ref: string }, { copied: boolean; clears_in_s: number }];
  onetime_discard: [{ ref: string }, void];
  file_pick: [{ purpose: 'secret' | 'ssh_key' | 'ca' }, { file_token: string; name: string } | null];

  settings_get: [void, Settings];
  settings_set: [Settings, Settings];
  net_interfaces: [void, NetInterface[]];
}

export type CommandName = keyof Commands;
/** Events the core emits. Payloads never contain secret values. */
export interface Events {
  'invite://preview': { ref: string; preview: InvitePreview };
  /** Reserved: the core does not emit it yet. The dashboard polls audit_tail instead. */
  'audit://records': { records: AuditRecord[] };
  'control://changed': Control;
  'serve://status': ServeStatus;
}
