import { call, toIpcError, type CommandInput } from '../ipc/client';
import { splitEnv } from '../lib/dash';

/** One explicit confirmation authorizes sharing and creating an invite. Each core command
 * reauthenticates independently. Report sharing immediately: invite failure must not undo or
 * hide that committed change, and a later explicit retry must not share again. Never retry an
 * invite automatically because its outcome may be uncertain. No password is retained here. */
export async function shareAndInvite(input: CommandInput<'team_invite_create'>, shared: boolean, onShared: () => void) {
  if (!shared) {
    const pair = splitEnv(input.env);
    if (!pair) throw { error: 'UsageError', reason: 'invalid_name' };
    await call('team_share', { ...pair, admin_passphrase: input.admin_passphrase });
    onShared();
  }
  return call('team_invite_create', input);
}

/** Only rejections known to precede a write permit retry. Slot reservation happens before
 * the CLI in Core::team_invite_create; all timeout/output/wait/storage errors stay uncertain. */
export function definiteInviteFailure(error: unknown): boolean {
  const e = toIpcError(error);
  if (e.error === 'AuthFailed') return true;
  return new Set(['invalid_name', 'invalid_argument', 'invalid_payload', 'passphrase_missing',
    'team_env_already_shared', 'onetime_store_full']).has(e.reason);
}
