// Stable reason codes from the core (and the zeropw-admin CLI behind it) mapped to copy keys.
// Codes the UI does not know fall back to a generic line; nothing here ever shows an input value.

import type { CopyKey, CopyVars } from '../copy';

/** `team_invite_preview` failures: a link that is not a valid invite (the CLI says
 *  `invite_malformed`; the core says `invite_missing` or `invite_too_long` before asking it) is
 *  "not an invite link"; anything else could not be checked. */
const INVITE_NOT_A_LINK = new Set(['invite_malformed', 'invite_invalid', 'invite_missing', 'invite_too_long', 'deep_link_invalid']);
export function invitePreviewErrorKey(reason: string): CopyKey {
  if (reason === 'invite_expired') return 'join.err.expired';
  return INVITE_NOT_A_LINK.has(reason) ? 'join.err' : 'join.err.check';
}

/** The previewed invite is gone from the core: it keeps a preview for 60 minutes. */
export const isStaleRef = (reason: string): boolean => reason === 'onetime_ref_unknown' || reason === 'onetime_ref_invalid';

/** `team_join` failures on the team page. */
export function joinErrorKey(reason: string): CopyKey {
  if (reason === 'invite_expired') return 'join.err.expired';
  if (isStaleRef(reason)) return 'join.err.reopen';
  return 'join.err.failed';
}

/** `team_join` failures at the end of the onboarding (the link itself is no longer on screen). */
export function finaleJoinErrorKey(reason: string): CopyKey {
  if (reason === 'invite_expired') return 'done.join.expired';
  if (isStaleRef(reason)) return 'done.join.reopen';
  return 'done.join.failed';
}

/** Why `backup_restore` was refused, when it was not the admin passphrase; null for anything
 *  else. An archive made under another device key (any backup made before the key was replaced
 *  with the recovery code) is refused with `backup_kms_mismatch` (rust/src/vault.rs). */
export function restoreErrorKey(reason: string): CopyKey | null {
  if (reason === 'file_dialog_cancelled') return 'set.restore.cancelled';
  if (reason === 'backup_kms_mismatch') return 'set.restore.mismatch';
  return null;
}

/** The sidecar could not open other-device access at the saved team address
 *  (rust/src/team/transport.rs). The gateway and the SSH signer run in the same process, so the
 *  whole relay stays off; the core passes the sidecar's reason on. */
const TEAM_LISTEN = new Set(['team_invalid_listen_address', 'team_listen_failed', 'team_address_in_use', 'team_already_listening']);
export const isTeamListenReason = (reason: string): boolean => TEAM_LISTEN.has(reason);

/** `serve_start` failures (desktop/core/src/serve.rs). `serve_exited` is the generic code for a
 *  sidecar that exited without saying why. When the sidecar could not open an address the core
 *  passes its reason on with `detail` naming the setting: `gateway_port` (`listen_failed`) or
 *  `team_listen`. Unknown codes are shown as they are. */
const RELAY: Record<string, CopyKey> = {
  serve_exited: 'relay.err.exited',
  listen_failed: 'relay.err.portBusy',
  serve_start_timeout: 'relay.err.timeout',
  admin_binary_missing: 'relay.err.missing',
  invalid_port: 'relay.err.port',
  invalid_listen: 'relay.err.listen',
};
export function relayError(reason: string, detail?: string): { key: CopyKey; reason: string } {
  const key = isTeamListenReason(reason) || detail === 'team_listen' ? 'relay.err.team' : RELAY[reason] ?? 'relay.err.other';
  return { key, reason: /^[a-z0-9_]{1,64}$/.test(reason) ? reason : 'unknown' };
}

/** Whether to offer turning other-device access off so the relay can start: only while the relay
 *  is off, no start is running, access is on and the last failure was the team address
 *  (`relay.err.team`). Never for a busy gateway port or any other reason, which turning access
 *  off would not fix and which would only stop team changes from arriving. */
export function offersListenOff(f: { running: boolean; busy: boolean; teamListen: string | null; problem: { key: CopyKey } | null }): boolean {
  return !f.running && !f.busy && f.teamListen !== null && f.problem?.key === 'relay.err.team';
}

/** What turning on other-device access did when the relay would not start with the new address
 *  (dashboard/relay.ts ListenError): what failed, then whether the previous setting and the relay
 *  are back. When the core names the gateway port (`detail` `gateway_port`) the relay port is
 *  named and the address is not. Otherwise the gateway port is never blamed: the address is named
 *  as the cause when the sidecar said so, or when the relay starts again without it; a relay that
 *  stays off either way (`serve_exited`, the generic code) shows its own reason next to the relay
 *  status. */
export function listenFailureLines(f: { address: string; reason: string; detail?: string; restored: boolean; relayBack: boolean }): Array<{ key: CopyKey; vars?: CopyVars }> {
  const vars = { address: f.address };
  const first: { key: CopyKey; vars?: CopyVars } =
    f.reason === 'admin_binary_missing' ? { key: 'relay.err.missing' }
      : f.detail === 'gateway_port' ? { key: 'listen.err.port' }
        : f.reason === 'invalid_listen' ? { key: 'set.listen.port.err' }
          : isTeamListenReason(f.reason) || f.detail === 'team_listen' || (f.restored && f.relayBack) ? { key: 'listen.err.open', vars }
            : { key: 'listen.err.start', vars };
  const second: CopyKey = !f.restored ? 'listen.err.kept' : f.relayBack ? 'listen.err.restored' : 'listen.err.relayOff';
  return [first, { key: second }];
}
