// How a Mac's state reads on screen: the words and the tone of its status dot. A connection
// alone never reads as synced; only the peer's own `up_to_date` does (src/lib/devices.ts).

import type { CopyKey } from '../../copy';
import type { LinkStatus } from '../../ipc/contract';
import type { DeviceRow, DeviceState } from '../../lib/devices';
import type { Tone } from '../../ui/feedback';

/** A row state, plus `unsupported`: the other Mac's app does not know a feature this one sent. */
export type MacState = DeviceState | 'unsupported';

export const UNSUPPORTED_ERROR = 'team_peer_feature_unsupported';

export const STATE_COPY: Record<MacState, CopyKey> = {
  conflict: 'mac.st.conflict', retrying: 'mac.st.retrying', offline: 'mac.st.offline', syncing: 'mac.st.syncing',
  connected: 'mac.st.connected', up_to_date: 'mac.st.up_to_date', waiting: 'mac.st.waiting', unsupported: 'mac.st.unsupported',
};

export const STATE_TONE: Record<MacState, Tone> = {
  conflict: 'warn', retrying: 'warn', offline: 'neutral', syncing: 'info', connected: 'info', up_to_date: 'ok', waiting: 'neutral', unsupported: 'warn',
};

/** A conflict stays first; otherwise a refused feature says why changes are not arriving. */
export function macState(row: Pick<DeviceRow, 'state' | 'detail'>): MacState {
  if (row.state === 'conflict') return 'conflict';
  if (row.detail.lastError === UNSUPPORTED_ERROR) return 'unsupported';
  return row.state;
}

/** This Mac at the link service, from the most basic problem down. */
export type SelfState = 'unavailable' | 'down' | 'revoked' | 'unenrolled' | 'online' | 'offline';

export function selfState(link: LinkStatus): SelfState {
  if (!link.available) return 'unavailable';
  if (!link.running) return 'down';
  if (link.revoked) return 'revoked';
  if (!link.enrolled) return 'unenrolled';
  return link.online ? 'online' : 'offline';
}

export const SELF_COPY: Record<SelfState, CopyKey> = {
  unavailable: 'mac.self.unavailable', down: 'mac.self.down', revoked: 'mac.self.revoked', unenrolled: 'mac.self.unenrolled',
  online: 'mac.self.online', offline: 'mac.self.offline',
};

export const SELF_TONE: Record<SelfState, Tone> = {
  unavailable: 'neutral', down: 'warn', revoked: 'danger', unenrolled: 'neutral', online: 'ok', offline: 'neutral',
};

/** Whether this Mac can make pairing codes, and if not, why (copy). */
export function addBlocker(link: LinkStatus | null): CopyKey | null {
  if (!link) return 'state.loading';
  if (!link.available) return 'mac.unavailable';
  if (!link.running) return 'mac.down';
  if (link.revoked) return 'devices.revoked';
  if (!link.enrolled) return 'mac.needEnroll';
  return null;
}

/** Server invite code as typed: spaces and dashes removed, upper case. */
export const compactInvite = (v: string): string => v.replace(/[\s-]/g, '').toUpperCase();
export const isServerInvite = (v: string): boolean => /^ZPL[A-Z2-7]{26}$/.test(compactInvite(v));

/** A display name the core accepts: trimmed, 1–64 characters, no control characters. */
export const isDisplayName = (v: string): boolean => {
  const s = v.trim();
  return s.length > 0 && s.length <= 64 && !/[\x00-\x1f\x7f]/.test(s);
};
