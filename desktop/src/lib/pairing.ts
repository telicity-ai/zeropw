// Pairing codes `zeropw://pair#<base64url(JSON)>` (docs/remote-sync.md §4). The core decodes and
// checks a pasted code (desktop/core/src/pairing.rs) and reads each invitation offline; the UI
// only decides whether pasted text looks like a code before asking it, and stops a pending join
// when the core says it cannot succeed. `decodePairingCode` mirrors the core's rules for the
// mock backend and the tests; the screens never decode a code.

import type { CopyKey } from '../copy';

export const PAIR_PREFIX = 'zeropw://pair#';
export const PAIR_CODE_MAX = 96 * 1024;
const MAX_INVITES = 16;
const PAIR_RE = /^zeropw:\/\/pair\/?#([A-Za-z0-9_-]{16,})$/i;
const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const DEVICE_ID_RE = /^[a-z2-7]{26}$/;

/** Pasted text that has the shape of a pairing code (the core checks the rest). */
export const isPairingCode = (v: string): boolean => {
  const s = v.trim();
  return s.length <= PAIR_CODE_MAX && PAIR_RE.test(s);
};

export interface PairingCodeData {
  v: 1; service: string; link_token: string; peer: string; name: string; invites: { env: string; invite: string }[];
}

function b64urlDecode(s: string): string | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null;
  const std = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
  try {
    const bin = atob(std);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

export function b64urlEncode(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const isServiceUrl = (s: string): boolean =>
  /^https:\/\/[a-z0-9.-]+(:\d{1,5})?$/.test(s) || /^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d{1,5})?$/.test(s);

/** The core's checks (exact keys, version 1, value shapes, bounds); null for anything else. */
export function decodePairingCode(text: string): PairingCodeData | null {
  const m = PAIR_RE.exec(text.trim());
  if (!m || text.trim().length > PAIR_CODE_MAX) return null;
  const json = b64urlDecode(m[1] ?? '');
  if (json === null) return null;
  let v: unknown;
  try { v = JSON.parse(json); } catch { return null; }
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o).sort().join(',');
  if (keys !== 'invites,link_token,name,peer,service,v' || o.v !== 1) return null;
  const { service, link_token, peer, name, invites } = o;
  if (typeof service !== 'string' || !isServiceUrl(service)) return null;
  if (typeof link_token !== 'string' || !/^[\x21-\x7e]{1,1024}$/.test(link_token)) return null;
  if (typeof peer !== 'string' || !DEVICE_ID_RE.test(peer)) return null;
  if (typeof name !== 'string' || !name.trim() || name !== name.trim() || new TextEncoder().encode(name).length > 64 || /[\x00-\x1f\x7f]/.test(name)) return null;
  if (!Array.isArray(invites) || invites.length === 0 || invites.length > MAX_INVITES) return null;
  const seen = new Set<string>();
  const out: { env: string; invite: string }[] = [];
  for (const i of invites) {
    if (!i || typeof i !== 'object' || Array.isArray(i)) return null;
    const e = i as Record<string, unknown>;
    if (Object.keys(e).sort().join(',') !== 'env,invite') return null;
    if (typeof e.env !== 'string' || typeof e.invite !== 'string') return null;
    const [p, env, extra] = e.env.split('/');
    if (extra !== undefined || !p || !env || !NAME_RE.test(p) || !NAME_RE.test(env) || seen.has(e.env)) return null;
    const body = e.invite.replace(/^zeropw:\/\/join#/i, '');
    if (!body || e.invite.length > 4096 || !/^[a-zA-Z2-7]+$/.test(body)) return null;
    seen.add(e.env);
    out.push({ env: e.env, invite: e.invite });
  }
  return { v: 1, service, link_token, peer, name, invites: out };
}

export function encodePairingCode(data: PairingCodeData): string {
  return PAIR_PREFIX + b64urlEncode(JSON.stringify(data));
}

/** Reasons after which trying a join again cannot succeed: the code or its invitations are gone,
 *  expired or refused, this Mac is in another account or was removed at the service, or the
 *  environment's name is already a local environment here. Codes are the core's and the CLI's
 *  (desktop/core/src/link.rs `link_error`, desktop/core/src/commands/remote.rs, rust/src/team).
 *  A refusal on the other Mac (deny) revokes its invitations; the joining Mac then only sees
 *  joins that fail or time out, like an unreachable Mac, so those keep being retried. */
const FINAL_REASONS = new Set([
  'onetime_ref_unknown', 'onetime_ref_invalid', 'pairing_code_malformed', 'pairing_code_version', 'pairing_expired', 'pairing_own_code',
  'pairing_env_exists', 'invite_expired', 'invite_malformed', 'link_other_account', 'link_other_service', 'link_token_invalid',
  'link_device_revoked', 'link_device_limit', 'link_socket_required', 'link_binary_missing',
]);
export const isFinalPairingReason = (reason: string): boolean => FINAL_REASONS.has(reason);

/** The reason a join result cannot get any further: every environment not joined yet failed for
 *  a final reason (null while one may still join). */
export function finalJoinReason(environments: readonly { state: string; reason?: string }[]): string | null {
  const open = environments.filter((e) => e.state !== 'joined');
  if (open.length === 0 || open.some((e) => e.state !== 'failed' || !e.reason || !isFinalPairingReason(e.reason))) return null;
  return open[0]?.reason ?? null;
}

// ---- reason codes to copy (the screens never show a code as text)

/** A pasted code the core would not preview. */
export function pairingPreviewErrorKey(reason: string): CopyKey {
  if (reason === 'pairing_expired') return 'pair.join.err.expired';
  if (reason === 'pairing_address_mismatch' || reason === 'pairing_inviter_mismatch') return 'pair.join.err.mismatch';
  if (reason.startsWith('pairing_code_')) return 'pair.join.err';
  return 'pair.join.err.check';
}

/** Why waiting for approval stopped. */
export function pairingStopKey(reason: string): CopyKey {
  switch (reason) {
    case 'link_other_account': return 'pair.failed.account';
    case 'link_other_service': return 'pair.failed.service';
    case 'pairing_own_code': return 'pair.failed.own';
    case 'pairing_env_exists': return 'pair.failed.exists';
    case 'link_device_revoked': return 'devices.revoked';
    case 'link_device_limit': return 'pair.failed.full';
    case 'pairing_expired': case 'invite_expired': case 'onetime_ref_unknown': case 'link_token_invalid': return 'pair.expired';
    default: return 'pair.failed';
  }
}

/** A failure that may pass while waiting (the other Mac asleep or closed, the network): said
 *  plainly, then tried again. `detail` is the CLI's code for why no address answered. */
export function pairingWaitHintKey(reason: string | undefined, detail?: string): CopyKey | null {
  if (!reason) return null;
  const why = `${reason} ${detail ?? ''}`;
  return /offline|connect_failed|timeout|unavailable|peer_|team_join_failed/.test(why) ? 'pair.failed.offline' : null;
}

/** Server enrolment errors. */
export function enrollErrorKey(reason: string): CopyKey {
  switch (reason) {
    case 'link_invite_malformed': return 'devices.enroll.err.code';
    case 'link_service_invalid': return 'devices.enroll.err.service';
    case 'link_invite_invalid': case 'link_device_revoked': return 'devices.enroll.err.refused';
    case 'link_device_limit': return 'pair.failed.full';
    case 'link_rate_limited': return 'devices.enroll.err.busy';
    case 'link_service_unavailable': case 'link_timeout': case 'link_connect_failed': case 'link_unavailable': return 'devices.enroll.err.offline';
    default: return 'error.generic';
  }
}
