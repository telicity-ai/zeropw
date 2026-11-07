// Value-free reading of a connection as the CLI printed it (Connection::to_value, kept loose in
// the contract) and the create form's error map. Nothing here touches a secret value.

import type { CopyKey } from '../../copy';
import type { ConnectionView, Grant } from '../../ipc/contract';
import { grantState } from '../../lib/dash';

const obj = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {});
const str = (v: unknown): string => (typeof v === 'string' ? v : typeof v === 'number' ? String(v) : '');
const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);

export interface HttpFacts {
  kind: 'http';
  origin: string; tls: boolean; privateAllowed: boolean; ca: boolean;
  auth: { mode: string; headerName: string; prefix: string; basicUser: string };
  methods: string[]; confirm: string[]; paths: string[];
  cli: string | null;
}
export interface SshFacts { kind: 'ssh'; host: string; port: string; user: string; hostKeys: string[]; cli: string | null }
export type ConnectionFacts = HttpFacts | SshFacts | { kind: 'other' };

/** The program a connection's CLI runs, or null when it has none. */
export function cliProgram(c: ConnectionView): string | null {
  if (c.cli === null || c.cli === undefined) return null;
  const p = str(obj(c.cli).program);
  return p || null;
}

export function connectionFacts(c: ConnectionView): ConnectionFacts {
  if (c.kind === 'http') {
    const tgt = obj(c.http_target), auth = obj(c.http_auth), scope = obj(c.http_scope);
    const scheme = str(tgt.scheme) || 'https', host = str(tgt.host), port = str(tgt.port);
    const def = (scheme === 'https' && port === '443') || (scheme === 'http' && port === '80') || !port;
    return {
      kind: 'http',
      origin: `${scheme}://${host}${def ? '' : `:${port}`}`,
      tls: scheme === 'https',
      privateAllowed: tgt.allow_private_network === true,
      ca: tgt.ca_file !== null && tgt.ca_file !== undefined && tgt.ca_file !== '',
      auth: { mode: str(auth.mode), headerName: str(auth.header_name), prefix: str(auth.value_prefix), basicUser: str(auth.basic_username) },
      methods: strs(scope.methods), confirm: strs(scope.confirm_methods), paths: strs(scope.path_prefixes),
      cli: cliProgram(c),
    };
  }
  if (c.kind === 'ssh') {
    const tgt = obj(c.ssh_target);
    return { kind: 'ssh', host: str(tgt.host), port: str(tgt.port) || '22', user: str(tgt.username), hostKeys: strs(tgt.host_keys), cli: cliProgram(c) };
  }
  return { kind: 'other' };
}

/** Grants that let an agent use this connection now (expiry and uses count, not the stored status). */
export function liveGrantsFor(grants: readonly Grant[], connection: string, now: number): Grant[] {
  return grants.filter((g) => g.connection === connection && grantState(g, now) === 'live');
}

export type ErrKey = 'env' | 'id' | 'target' | 'basic' | 'header' | 'prefix' | 'methods' | 'paths' | 'cli' | 'host' | 'port' | 'user' | 'hostKey' | 'sshCli' | 'key' | 'pass' | 'form';

/** Where a `connection_create_*` or `secret_put` refusal belongs on the form. The passphrase
 *  (AuthFailed) and team-write reasons are mapped by the caller first. */
export function createErrorField(reason: string, ssh: boolean): [ErrKey, CopyKey] | null {
  const map: Record<string, [ErrKey, CopyKey]> = {
    connection_exists: ['id', 'service.c.err.exists'], invalid_connection_id: ['id', 'service.c.err.name'],
    secret_identity_mismatch: ['id', 'service.c.err.keyExists'],
    invalid_scheme: ['target', 'service.c.url.err.format'], target_must_be_origin: ['target', 'service.c.url.err.format'],
    metadata_address_not_allowed: ['target', 'service.c.url.err.meta'], target_address_not_allowed: ['target', 'service.c.url.private'],
    invalid_host: ['host', 'service.c.ssh.host.err'], invalid_port: ['port', 'service.c.ssh.port.err'],
    invalid_ssh_username: ['user', 'service.c.ssh.user.err'],
    invalid_host_key: ['hostKey', 'service.c.ssh.hostKey.err'], unsupported_host_key: ['hostKey', 'service.c.ssh.hostKey.err'],
    ssh_host_keys_required: ['hostKey', 'service.c.ssh.hostKey.err'], host_key_required: ['hostKey', 'service.c.ssh.hostKey.err'],
    invalid_header_name: ['header', 'service.c.header.err'], invalid_basic_username: ['basic', 'service.c.basic.err'],
    invalid_secret_value: ['key', 'service.c.key.err.value'], file_token_unknown: ['key', 'service.c.key.err.value'],
    cli_program_required: ['sshCli', 'conn.cli.err'],
    invalid_cli_program: [ssh ? 'sshCli' : 'cli', 'conn.cli.err'],
    cli_program_not_found: [ssh ? 'sshCli' : 'cli', 'conn.cli.err.notFound'],
    secret_kind_mismatch: ['key', 'service.c.key.err.kind'], secret_scope_mismatch: ['key', 'service.c.key.err.pick'],
    secret_version_unusable: ['key', 'service.c.key.err.unusable'], secret_not_found: ['key', 'service.c.key.err.pick'],
  };
  return map[reason] ?? null;
}

/** The order the form checks its fields in; the first one with an error takes focus. */
export const ERR_ORDER: readonly ErrKey[] = ['env', 'id', 'target', 'basic', 'header', 'prefix', 'methods', 'paths', 'cli', 'host', 'port', 'user', 'hostKey', 'sshCli', 'key', 'pass'];
