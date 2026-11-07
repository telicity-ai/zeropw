// The devices view (docs/remote-sync.md §4): one row per paired Mac, merged from the paired-Mac
// records, the team members and `team sync-status` of the paired environments, and the link
// daemon's peers. Each row has one plain state; how it is connected (direct or relayed), the last
// error code and the last contact are only for the connection details disclosure (devices.detail).

import type { DevicesOverview, LinkPath, LinkPeer, SyncPeer, SyncState } from '../ipc/contract';

/** What a row says, from the most to the least urgent. */
export type DeviceState = 'conflict' | 'retrying' | 'offline' | 'syncing' | 'connected' | 'up_to_date' | 'waiting';

export const DEVICE_STATE_ORDER: readonly DeviceState[] = ['conflict', 'retrying', 'offline', 'syncing', 'connected', 'up_to_date', 'waiting'];

export interface DeviceDetail {
  /** Direct or relayed, from the link daemon's path label. */
  path: 'direct' | 'relay' | null;
  /** The daemon's own label (`relay-tls`, …), shown as is in the connection details. */
  pathLabel: LinkPath | null;
  /** A daemon or sync error code, shown as is in the connection details. */
  lastError: string | null;
  lastContact: string | null;
  rttMs: number | null;
  transport: 'link' | 'tcp' | null;
}

export interface DeviceRow {
  key: string;
  name: string;
  fingerprint: string | null;
  linkId: string | null;
  envs: string[];
  state: DeviceState;
  conflicts: number;
  /** Known to the link service only: no environment is paired with it yet (or any more). */
  linkOnly: boolean;
  detail: DeviceDetail;
}

/** One environment's sync state of a peer as a row state. */
export function syncRowState(peer: Pick<SyncPeer, 'state' | 'session'>): DeviceState {
  const s: SyncState = peer.state;
  if (s === 'up_to_date') return 'up_to_date';
  if (s === 'syncing') return 'syncing';
  if (peer.session) return 'connected';
  if (s === 'retrying') return 'retrying';
  if (s === 'offline') return 'offline';
  return 'waiting';
}

/** The most urgent of several states. */
export function worst(states: readonly DeviceState[]): DeviceState | null {
  let best: DeviceState | null = null;
  for (const s of states) {
    if (best === null || DEVICE_STATE_ORDER.indexOf(s) < DEVICE_STATE_ORDER.indexOf(best)) best = s;
  }
  return best;
}

const pathKind = (p: LinkPath | null): 'direct' | 'relay' | null => (p === null ? null : p === 'direct' ? 'direct' : 'relay');

const later = (a: string | null, b: string | null): string | null => {
  if (!a) return b;
  if (!b) return a;
  return Date.parse(b) > Date.parse(a) ? b : a;
};

/** Merge everything the overview holds into rows (this Mac excluded). */
export function deviceRows(o: DevicesOverview): DeviceRow[] {
  const self = o.self_fingerprint;
  const ownLink = o.link.device_id;
  const peers = new Map<string, LinkPeer>(o.link.peers.map((p) => [p.device_id, p]));
  const rows: DeviceRow[] = [];
  const mappedLinks = new Set<string>();

  for (const d of o.devices) {
    if (d.fingerprint === self) continue;
    if (d.link_device_id) mappedLinks.add(d.link_device_id);
    const peer = d.link_device_id ? peers.get(d.link_device_id) ?? null : null;
    const states: DeviceState[] = [];
    let conflicts = 0;
    let lastError: string | null = null;
    let lastContact: string | null = null;
    let transport: 'link' | 'tcp' | null = null;
    let session = false;
    let name = d.name;
    for (const envName of d.envs) {
      const env = o.envs.find((e) => e.env === envName);
      if (!env) continue;
      const member = env.members?.members.find((m) => m.fingerprint === d.fingerprint);
      if (member && member.status !== 'active') continue;   // removed from that team: not synced there
      if (!name && member?.name) name = String(member.name);
      if (!env.sync) continue;
      conflicts += Number.isFinite(env.sync.conflicts) ? env.sync.conflicts : 0;
      const sp = env.sync.peers.find((p) => p.fingerprint === d.fingerprint);
      if (!sp) continue;
      states.push(syncRowState(sp));
      session ||= sp.session;
      lastError ??= sp.last_error;
      lastContact = later(lastContact, sp.last_contact_at);
      transport ??= sp.transport;
    }
    let state = worst(states);
    // the link service knows whether the other Mac is reachable at all: a Mac that is off is
    // "off", not a failed connection
    if (peer && !peer.online && !session && (state === null || state === 'retrying' || state === 'waiting')) state = 'offline';
    if (state === null) state = peer ? (peer.online ? 'connected' : 'offline') : 'waiting';
    if (conflicts > 0) state = 'conflict';
    rows.push({
      key: d.fingerprint, name: name || d.fingerprint.slice(0, 8), fingerprint: d.fingerprint, linkId: d.link_device_id,
      envs: d.envs.slice(), state, conflicts, linkOnly: false,
      detail: {
        path: pathKind(peer?.path ?? null), pathLabel: peer?.path ?? null,
        lastError: lastError ?? peer?.last_error ?? null, lastContact, rttMs: peer?.rtt_ms ?? null, transport,
      },
    });
  }

  for (const ld of o.link_devices) {
    if (ld.device_id === ownLink || mappedLinks.has(ld.device_id) || ld.revoked_at !== null && ld.revoked_at !== undefined) continue;
    const peer = peers.get(ld.device_id) ?? null;
    if (peer?.revoked) continue;
    rows.push({
      key: 'link:' + ld.device_id, name: ld.name || peer?.name || ld.device_id.slice(0, 8), fingerprint: null, linkId: ld.device_id,
      envs: [], state: (peer?.online ?? ld.online) ? 'connected' : 'offline', conflicts: 0, linkOnly: true,
      detail: {
        path: pathKind(peer?.path ?? null), pathLabel: peer?.path ?? null, lastError: peer?.last_error ?? null,
        lastContact: null, rttMs: peer?.rtt_ms ?? null, transport: null,
      },
    });
  }
  return rows;
}

/** The environments to poll for join requests and to approve in: what the code was made for. */
export const pairingEnvs = (created: { environments: { env: string }[] }): string[] => created.environments.map((e) => e.env);

/** Join requests grouped by the requesting Mac's fingerprint, with the environments asked for. */
export function requestsByDevice(requests: readonly { env: string; fingerprint: string; attempts: number }[]): { fingerprint: string; envs: string[]; attempts: number }[] {
  const by = new Map<string, { fingerprint: string; envs: string[]; attempts: number }>();
  for (const r of requests) {
    const g = by.get(r.fingerprint) ?? { fingerprint: r.fingerprint, envs: [], attempts: 0 };
    if (!g.envs.includes(r.env)) g.envs.push(r.env);
    g.attempts += r.attempts;
    by.set(r.fingerprint, g);
  }
  return [...by.values()];
}
