// Stable reason codes from the core (and the zeropw-admin CLI behind it) mapped to copy keys.
// Codes the UI does not know fall back to a generic line; nothing here ever shows an input value.

import type { CopyKey } from '../copy';

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

/** `serve_start` failures (desktop/core/src/serve.rs). Unknown codes are shown as they are. */
const RELAY: Record<string, CopyKey> = {
  serve_exited: 'relay.err.exited',
  serve_start_timeout: 'relay.err.timeout',
  admin_binary_missing: 'relay.err.missing',
  invalid_port: 'relay.err.port',
  invalid_listen: 'relay.err.listen',
};
export function relayError(reason: string): { key: CopyKey; reason: string } {
  return { key: RELAY[reason] ?? 'relay.err.other', reason: /^[a-z0-9_]{1,64}$/.test(reason) ? reason : 'unknown' };
}
