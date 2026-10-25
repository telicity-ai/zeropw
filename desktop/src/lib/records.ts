// Usage records and alerts as the record lists show them (DESIGN.md §6.2: plain Korean, no
// internal names). The event, alert, result and reason codes the CLI writes map to short copy:
// every event in rust/src/audit.rs `EVENTS`, every alert `maybe_alert` writes, every result, and
// the reasons the relay, the SSH signer and an agent's commands record (denials, failed checks,
// near-exposures) with the most common others. The agent and connection
// names stay as they are; the caller `admin` is called the administrator only on a record the
// administrator's CLI writes, since an agent may be named `admin` too. Anything else (a code missing here, the CLI's English `detail`, the
// other fields) stays visible as the core wrote it, on a secondary `key=value` line. Records
// never contain values (rust/src/audit.rs); this reads no field the lists did not show before.

import { t, type CopyKey } from '../copy';
import type { AuditRecord } from '../ipc/contract';
import { valueText } from './dash';

const EVENT: Record<string, CopyKey> = {
  init: 'log.ev.init', principal_create: 'log.ev.principal_create', principal_disable: 'log.ev.principal_disable',
  project_create: 'log.ev.project_create', secret_put: 'log.ev.secret_put', secret_import: 'log.ev.secret_import',
  secret_retire: 'log.ev.secret_retire', secret_revoke: 'log.ev.secret_revoke', secret_reveal: 'log.ev.secret_reveal',
  secret_reveal_denied: 'log.ev.secret_reveal_denied', connection_create: 'log.ev.connection_create',
  connection_update: 'log.ev.connection_update', connection_disable: 'log.ev.connection_disable',
  connection_switch_credential: 'log.ev.connection_switch_credential', grant_create: 'log.ev.grant_create',
  grant_revoke: 'log.ev.grant_revoke', grant_regrant: 'log.ev.grant_regrant', grant_stale: 'log.ev.grant_stale',
  stop_all: 'log.ev.stop_all', resume: 'log.ev.resume', approval_request: 'log.ev.approval_request',
  approval_grant: 'log.ev.approval_grant', approval_consume: 'log.ev.approval_consume', handle_issue: 'log.ev.handle_issue',
  tools_list_connections: 'log.ev.tools_list_connections', tools_request: 'log.ev.tools_request', tools_exec: 'log.ev.tools_exec',
  tools_status: 'log.ev.tools_status', tools_cancel: 'log.ev.tools_cancel', tools_unknown: 'log.ev.tools_unknown',
  http_relay: 'log.ev.http_relay', ssh_bind: 'log.ev.ssh_bind', ssh_sign: 'log.ev.ssh_sign', ssh_agent_refused: 'log.ev.ssh_agent_refused',
  run_start: 'log.ev.run_start', run_finish: 'log.ev.run_finish', run_cancel: 'log.ev.run_cancel', backup: 'log.ev.backup',
  restore: 'log.ev.restore', restore_ack: 'log.ev.restore_ack', recover: 'log.ev.recover', rotation: 'log.ev.rotation',
  unsupported: 'log.ev.unsupported', auth_failed: 'log.ev.auth_failed', team_commit_apply: 'log.ev.team_commit_apply',
  team_commit_rejected: 'log.ev.team_commit_rejected', team_op_skipped: 'log.ev.team_op_skipped',
  team_op_overridden: 'log.ev.team_op_overridden', team_handshake_failed: 'log.ev.team_handshake_failed',
  team_session_open: 'log.ev.team_session_open', team_session_close: 'log.ev.team_session_close',
  team_fact_apply: 'log.ev.team_fact_apply', team_fact_rejected: 'log.ev.team_fact_rejected',
  team_sync_vector: 'log.ev.team_sync', team_sync_poll: 'log.ev.team_sync', team_share: 'log.ev.team_share',
  team_invite_create: 'log.ev.team_invite_create', team_invite_revoke: 'log.ev.team_invite_revoke', team_join: 'log.ev.team_join',
  team_member_add: 'log.ev.team_member_add', team_member_remove: 'log.ev.team_member_remove', team_dek_rotate: 'log.ev.team_dek_rotate',
  team_compact: 'log.ev.team_compact', team_incident_received: 'log.ev.team_incident_received', incident_open: 'log.ev.incident_open',
  incident_widen: 'log.ev.incident_widen', incident_close: 'log.ev.incident_close', incident_notify: 'log.ev.incident_notify',
};

const ALERT: Record<string, CopyKey> = {
  secret_reveal: 'log.al.secret_reveal', team_incident_received: 'log.al.team_incident_received',
  team_op_overridden: 'log.al.team_op_overridden', intrusion: 'log.al.intrusion', credential_reflection: 'log.al.credential_reflection',
  credential_exposure: 'log.al.credential_exposure', failure: 'log.al.failure', revoked_use_attempt: 'log.al.revoked_use_attempt',
  repeated_denials: 'log.al.repeated_denials',
};

/** `ok` says nothing a record does not already say; the other results are shown (rust/src/gateway.rs,
 *  rust/src/tools.rs, rust/src/runs.rs). */
const RESULT: Record<string, CopyKey | null> = {
  ok: null, denied: 'log.res.denied', failed: 'log.res.failed', skipped: 'log.res.skipped', attempt: 'log.res.attempt',
  error: 'log.res.error', blocked: 'log.res.blocked', cancelled: 'log.res.cancelled', unsupported: 'log.res.unsupported',
};

const REASON: Record<string, CopyKey | null> = {
  // the relay's policy (rust/src/policy.rs, rust/src/gateway.rs, rust/src/tools.rs)
  no_grant: 'log.why.no_grant', grant_expired: 'log.why.grant_expired', grant_exhausted: 'log.why.grant_exhausted',
  grant_revoked: 'log.why.grant_revoked', grant_stale: 'log.why.grant_stale', grant_inactive: 'log.why.grant_inactive',
  grant_unknown: 'log.why.grant_unknown', grant_mismatch: 'log.why.grant_mismatch', principal_disabled: 'log.why.principal_disabled',
  principal_unknown: 'log.why.principal_unknown', connection_unknown: 'log.why.connection_unknown',
  connection_disabled: 'log.why.connection_disabled', global_stop: 'log.why.global_stop', restore_pending: 'log.why.restore_pending',
  method_not_allowed: 'log.why.method_not_allowed', path_not_allowed: 'log.why.path_not_allowed',
  approval_required: 'log.why.approval_required', approval_expired: 'log.why.approval_expired',
  self_referential_target: 'log.why.self_referential_target', action_kind_mismatch: 'log.why.action_kind_mismatch',
  tool_not_found: 'log.why.tool_not_found', run_not_found: 'log.why.run_not_found',
  host_key_not_allowed: 'log.why.host_key_not_allowed', ssh_user_mismatch: 'log.why.ssh_user_mismatch',
  // near-exposures and failures of the authenticated path (rust/src/audit.rs)
  target_address_not_allowed: 'log.why.target_address_not_allowed', metadata_address_not_allowed: 'log.why.metadata_address_not_allowed',
  redirect_not_followed: 'log.why.redirect_not_followed', output_credential_blocked: 'log.why.output_credential_blocked',
  credential_reflection_blocked: 'log.why.credential_reflection_blocked', upstream_tls_failed: 'log.why.upstream_tls_failed',
  credential_unavailable: 'log.why.credential_unavailable', local_id_conflict: 'log.why.local_id_conflict',
  member_removed_rotation_recommended: 'log.why.member_removed_rotation_recommended',
  cli_env_contains_credential: 'log.why.cli_env_contains_credential',
  // the service behind an API connection and a repeated request (rust/src/gateway.rs)
  upstream_unreachable: 'log.why.upstream_unreachable', upstream_connection_lost: 'log.why.upstream_connection_lost',
  upstream_protocol_error: 'log.why.upstream_protocol_error', response_too_large: 'log.why.response_too_large',
  ca_file_unavailable: 'log.why.ca_file_unavailable', unsupported_auth_mode: 'log.why.unsupported_auth_mode',
  request_in_flight: 'log.why.request_in_flight', request_id_reused: 'log.why.request_id_reused',
  outcome_uncertain: 'log.why.outcome_uncertain', audit_unavailable: 'log.why.audit_unavailable',
  // a command an agent runs (rust/src/tools.rs `exec`, rust/src/runs.rs); a cancelled run's
  // reason repeats its result
  policy_denied: 'log.why.policy_denied', cli_not_supported: 'log.why.cli_not_supported',
  cli_program_missing: 'log.why.cli_program_missing', cli_kind_unsupported: 'log.why.cli_kind_unsupported',
  ssh_signer_unavailable: 'log.why.ssh_signer_unavailable', public_url_unset: 'log.why.public_url_unset',
  exec_setup_failed: 'log.why.exec_setup_failed', run_dir_unset: 'log.why.exec_setup_failed', runs_not_installed: 'log.why.exec_setup_failed',
  cli_env_conflict: 'log.why.cli_env_conflict', ssh_public_key_unavailable: 'log.why.ssh_public_key_unavailable',
  connection_changed: 'log.why.connection_changed', cancelled: null,
  // the SSH signer (rust/src/signer.rs): the agent protocol's own refusals
  agent_forwarding_not_allowed: 'log.why.agent_forwarding_not_allowed', host_key_unsupported: 'log.why.host_key_unsupported',
  host_signature_invalid: 'log.why.host_signature_invalid', host_signature_malformed: 'log.why.host_signature_invalid',
  session_already_bound: 'log.why.session_already_bound', no_session_bind: 'log.why.no_session_bind',
  session_mismatch: 'log.why.session_mismatch', hostbound_key_mismatch: 'log.why.session_mismatch',
  unknown_key: 'log.why.ssh_key_mismatch', userauth_key_mismatch: 'log.why.ssh_key_mismatch',
  key_metadata_mismatch: 'log.why.key_metadata_mismatch', key_unavailable: 'log.why.credential_unavailable',
  not_userauth_request: 'log.why.not_userauth_request', too_many_agent_clients: 'log.why.too_many_agent_clients',
  malformed_agent_message: 'log.why.malformed_request', malformed_extension: 'log.why.malformed_request',
  malformed_session_bind: 'log.why.malformed_request', malformed_sign_request: 'log.why.malformed_request',
  unsupported_agent_message: 'log.why.unsupported_request', unsupported_extension: 'log.why.unsupported_request',
  unsupported_sign_flags: 'log.why.unsupported_request',
  // who asked (rust/src/errors.rs `auth_failed`)
  admin_reauth_failed: 'log.why.admin_reauth_failed', admin_reauth_stale: 'log.why.admin_reauth_stale',
  passphrase_missing: 'log.why.passphrase_missing', bad_passphrase: 'log.why.admin_reauth_failed',
  caller_token_invalid: 'log.why.caller_token_invalid', caller_token_missing: 'log.why.caller_token_missing',
  handle_expired: 'log.why.handle_expired', handle_malformed: 'log.why.handle_invalid', handle_signature: 'log.why.handle_invalid',
  handle_version: 'log.why.handle_invalid', recovery_passphrase_invalid: 'log.why.recovery_passphrase_invalid',
  backup_kms_mismatch: 'log.why.backup_kms_mismatch',
  // team and incidents (rust/src/team, rust/src/incident.rs: an incident's trigger, `widen`)
  team_rekey_pending: 'log.why.team_rekey_pending', not_admin: 'log.why.not_admin', member_removed: 'log.why.member_removed',
  manual: 'log.why.manual', auto: 'log.why.auto', widen: null,
};

const SCOPE: Record<string, CopyKey> = { principal: 'inc.scope.principal', runtime: 'inc.scope.runtime', all: 'inc.scope.all' };

/** The events the administrator's CLI records with the caller `admin` (rust/src/admin_cli.rs,
 *  rust/src/team/membership.rs), and the reveal, which only the administrator can do. The relay,
 *  the SSH signer, an agent's commands and the server's token check write the agent's own id as
 *  the caller, and an agent may be named `admin` (rust/src/projects.rs `validate_name`), so on
 *  their events `admin` is a name. */
const ADMIN_EVENTS = new Set([
  'project_create', 'principal_create', 'principal_disable', 'secret_put', 'secret_import', 'secret_reveal',
  'connection_create', 'connection_update', 'connection_disable', 'connection_switch_credential',
  'grant_create', 'grant_revoke', 'grant_regrant', 'stop_all', 'resume', 'approval_grant', 'rotation', 'restore_ack',
  'auth_failed', 'team_share', 'team_invite_create', 'team_invite_revoke', 'team_join', 'team_member_remove',
  'team_dek_rotate', 'team_fact_apply',
]);
/** An `auth_failed` the administrator's password checks write; the server's token check writes
 *  one with a caller only for a disabled agent (`principal_disabled`, rust/src/server.rs). */
const ADMIN_AUTH = new Set(['admin_reauth_failed', 'admin_reauth_stale', 'passphrase_missing', 'recovery_passphrase_invalid']);

/** Whether the record says the administrator acted, not an agent named `admin`. */
const byAdmin = (rec: AuditRecord): boolean =>
  rec.caller === 'admin' && typeof rec.event === 'string' && ADMIN_EVENTS.has(rec.event)
  && (rec.event !== 'auth_failed' || (typeof rec.reason === 'string' && ADMIN_AUTH.has(rec.reason)));

/** The fixed English `detail` of the alerts rust/src/audit.rs writes: the alert and its reason
 *  already say it. */
const KNOWN_DETAIL = new Set([
  'administrator revealed a single secret version',
  'a shared environment received an incident summary; check rotation flags',
  "a later commit from another device overrode this node's change to the same target",
  'upstream response reflected the credential; blocked',
  'use attempted under a revoked, stale, or stopped grant',
  'execution output carried the credential or handle; output withheld',
  'upstream redirect was blocked; its Location may carry request or credential data',
  'credential delivery to a non-public address was refused (possible DNS change)',
  'credential delivery to a metadata or link-local address was refused',
  'upstream TLS server identity could not be verified; request refused',
  "the connection's credential is unavailable (revoked, retired or corrupt)",
  'a shared environment tried to derive a connection or secret id already used locally',
  "a team member was removed; this environment's active secrets should be rotated at the provider",
]);
const INCIDENT_OPENED = /^incident opened: scope=([a-z]+) reason=\S+$/;
const INCIDENT_WIDENED = /^incident widened to scope=([a-z]+)$/;
const DENIALS = /^(\d{1,4}) denials within (\d{1,6})s$/;

const own = <V>(table: Record<string, V>, code: unknown): V | undefined =>
  typeof code === 'string' && Object.prototype.hasOwnProperty.call(table, code) ? table[code] : undefined;

export interface RecordView {
  ts: string;
  /** What happened, in plain Korean; a generic word when the code is not known. */
  title: string;
  /** Plain parts for the detail line: who, through which connection, the result and the reason. */
  meta: string[];
  /** Everything not shown above, as the core wrote it (`key=value`), in the record's order. */
  raw: string[];
}

/** A usage record (`audit_tail`) or an alert (`alerts`) for the record lists. */
export function recordView(rec: AuditRecord, kind: 'audit' | 'alert'): RecordView {
  const meta: string[] = [];
  const raw: string[] = [];
  const shown = new Set(['ts', 'caller', 'connection']);
  const keep = (k: string) => {
    const text = valueText(rec[k]);
    if (text !== '') raw.push(`${valueText(k)}=${text}`);
  };
  /** A code shown through `table`: its copy (or nothing for a code that adds nothing), the code
   *  itself on the raw line when it is not known. */
  const code = (k: string, table: Record<string, CopyKey | null>): void => {
    shown.add(k);
    const key = own(table, rec[k]);
    if (key) meta.push(t(key));
    else if (key === undefined) keep(k);
  };

  let title: string;
  if (kind === 'audit') {
    shown.add('event');
    const key = own(EVENT, rec.event);
    title = key ? t(key) : t('log.event.other');
    if (!key) keep('event');
  } else {
    shown.add('alert');
    const alert = rec.alert;
    const key = alert === 'intrusion' && rec.event === 'incident_widen' ? 'log.al.intrusion.widen' : own(ALERT, alert);
    title = key ? t(key) : t('log.alert.other');
    if (!key) keep('alert');
  }

  const caller = valueText(rec.caller);
  if (caller) meta.push(byAdmin(rec) ? t('log.admin') : caller);
  const conn = valueText(rec.connection);
  if (conn) meta.push(conn);

  if (kind === 'alert') {
    // the event behind the alert, unless the alert already names it
    shown.add('event');
    if (rec.alert !== 'intrusion' && rec.event !== rec.alert) {
      const ev = own(EVENT, rec.event);
      if (ev) meta.push(t(ev));
      else keep('event');
    }
    // the fixed English detail is said by the alert, its reason and the scope; any other is kept
    shown.add('detail');
    const detail = typeof rec.detail === 'string' ? rec.detail : null;
    const scope = detail ? (INCIDENT_OPENED.exec(detail) ?? INCIDENT_WIDENED.exec(detail))?.[1] : undefined;
    const denials = detail ? DENIALS.exec(detail) : null;
    if (scope !== undefined && own(SCOPE, scope)) meta.push(t('log.scope', { scope: t(SCOPE[scope] as CopyKey) }));
    else if (denials) meta.push(t('log.denials', { n: denials[1] ?? '', s: denials[2] ?? '' }));
    else if (!detail || !KNOWN_DETAIL.has(detail)) keep('detail');
  } else if (own(SCOPE, rec.scope)) {
    shown.add('scope');
    meta.push(t('log.scope', { scope: t(SCOPE[rec.scope as string] as CopyKey) }));
  }

  code('result', RESULT);
  code('reason', REASON);
  for (const k of Object.keys(rec)) if (!shown.has(k)) keep(k);
  return { ts: valueText(rec.ts), title, meta, raw };
}
