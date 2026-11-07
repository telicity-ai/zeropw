// Remote sync between this user's Macs (docs/remote-sync.md §4): the devices view's row states,
// pairing code shapes and the reasons that stop or keep a pending join, and polling with its stop
// conditions. Synthetic identifiers only.
import { describe, expect, it } from 'vitest';
import type { DevicesOverview, LinkStatus, SyncPeer } from '../src/ipc/contract';
import { deviceRows, requestsByDevice, syncRowState, worst } from '../src/lib/devices';
import {
  decodePairingCode, encodePairingCode, enrollErrorKey, finalJoinReason, isFinalPairingReason, isPairingCode, pairingPreviewErrorKey,
  pairingStopKey, pairingWaitHintKey, PAIR_PREFIX, type PairingCodeData,
} from '../src/lib/pairing';
import { poll } from '../src/lib/poll';
import { hasCopy } from '../src/copy';

const SELF = 'saaaaaaaaaaaaaaaaaaaaaaaaa';
const MAC_B = 'fbbbbbbbbbbbbbbbbbbbbbbbbb';
const MAC_C = 'fccccccccccccccccccccccccc';
const OWN_LINK = 'oooooooooooooooooooooooooo';
const LINK_B = 'llllllllllllllllllllllllll';
const LINK_X = 'xxxxxxxxxxxxxxxxxxxxxxxxxx';

const link = (over: Partial<LinkStatus> = {}): LinkStatus => ({
  available: true, running: true, enrolled: true, revoked: false, device_id: OWN_LINK, online: true, service: 'https://link.example.org',
  service_host: 'link.example.org', default_service: 'https://link.zeropw.invalid', device_name: 'this mac', peers: [], problem: null, ...over,
});
const peer = (state: SyncPeer['state'], over: Partial<SyncPeer> = {}): SyncPeer => ({
  fingerprint: MAC_B, name: 'studio', state, session: state === 'up_to_date' || state === 'syncing', transport: null,
  last_contact_at: null, next_attempt_at: null, last_error: null, ...over,
});
function overview(peers: Record<string, SyncPeer[]>, over: Partial<DevicesOverview> = {}): DevicesOverview {
  const envs = Object.keys(peers);
  return {
    self_fingerprint: SELF, link: link(), link_devices: [],
    devices: [{ fingerprint: MAC_B, link_device_id: LINK_B, name: 'studio', envs, added_at: 1 }],
    envs: envs.map((env) => ({
      env, members: { env_id: 'e-' + env, members: [{ fingerprint: MAC_B, name: 'studio', role: 'admin', status: 'active', owner: false }] },
      sync: { env_id: 'e-' + env, self: SELF, serve_updated_at: '2026-11-07T00:00:00Z', conflicts: 0, peers: peers[env] ?? [] },
    })),
    ...over,
  };
}

describe('device rows', () => {
  it('maps each sync state to one plain row state', () => {
    expect(syncRowState({ state: 'up_to_date', session: true })).toBe('up_to_date');
    expect(syncRowState({ state: 'syncing', session: true })).toBe('syncing');
    expect(syncRowState({ state: 'retrying', session: false })).toBe('retrying');
    expect(syncRowState({ state: 'offline', session: false })).toBe('offline');
    expect(syncRowState({ state: 'never_connected', session: false })).toBe('waiting');
    // a session that is open but not yet compared counts as connected
    expect(syncRowState({ state: 'never_connected', session: true })).toBe('connected');
    expect(worst(['up_to_date', 'syncing', 'connected'])).toBe('syncing');
    expect(worst(['up_to_date', 'offline', 'retrying'])).toBe('retrying');
    expect(worst([])).toBeNull();
  });

  it('shows the most urgent state over the paired environments, conflicts first', () => {
    expect(deviceRows(overview({ 'demo/dev': [peer('up_to_date')], 'demo/prod': [peer('up_to_date')] }))[0]?.state).toBe('up_to_date');
    expect(deviceRows(overview({ 'demo/dev': [peer('up_to_date')], 'demo/prod': [peer('syncing')] }))[0]?.state).toBe('syncing');
    const retrying = overview({ 'demo/dev': [peer('retrying', { last_error: 'link_connect_failed', next_attempt_at: '2026-11-07T00:01:00Z' })] });
    retrying.link.peers = [{ device_id: LINK_B, name: 'studio', online: true, revoked: false, path: null, rtt_ms: null, last_error: 'connect_failed' }];
    const row = deviceRows(retrying)[0]!;
    expect(row.state).toBe('retrying');
    // the error code is only for the connection details
    expect(row.detail.lastError).toBe('link_connect_failed');
    const conflict = overview({ 'demo/dev': [peer('up_to_date')] });
    conflict.envs[0]!.sync!.conflicts = 2;
    expect(deviceRows(conflict)[0]).toMatchObject({ state: 'conflict', conflicts: 2 });
  });

  it('says a Mac the service sees as away is off, not failing', () => {
    const o = overview({ 'demo/dev': [peer('retrying')] });
    o.link.peers = [{ device_id: LINK_B, name: 'studio', online: false, revoked: false, path: null, rtt_ms: null, last_error: null }];
    expect(deviceRows(o)[0]?.state).toBe('offline');
    // without any sync data, the link service decides
    const bare = overview({});
    bare.devices[0]!.envs = [];
    bare.link.peers = [{ device_id: LINK_B, name: 'studio', online: true, revoked: false, path: 'relay-tls', rtt_ms: 40, last_error: null }];
    const row = deviceRows(bare)[0]!;
    expect(row.state).toBe('connected');
    expect(row.detail).toMatchObject({ path: 'relay', pathLabel: 'relay-tls', rttMs: 40 });
    bare.link.peers = [];
    expect(deviceRows(bare)[0]?.state).toBe('waiting');
  });

  it('leaves out this Mac, revoked link devices and teams the Mac was removed from', () => {
    const o = overview({ 'demo/dev': [peer('up_to_date')], 'demo/prod': [peer('retrying')] });
    o.envs[1]!.members!.members[0]!.status = 'removed';
    o.devices.push({ fingerprint: SELF, link_device_id: OWN_LINK, name: 'me', envs: ['demo/dev'], added_at: 1 });
    o.link_devices = [
      { device_id: OWN_LINK, name: 'this mac', created_at: 1, last_seen_at: null, online: true, revoked_at: null },
      { device_id: LINK_B, name: 'studio', created_at: 1, last_seen_at: null, online: true, revoked_at: null },
      { device_id: LINK_X, name: 'laptop', created_at: 1, last_seen_at: null, online: false, revoked_at: null },
      { device_id: 'rrrrrrrrrrrrrrrrrrrrrrrrrr', name: 'old', created_at: 1, last_seen_at: null, online: false, revoked_at: 5 },
    ];
    const rows = deviceRows(o);
    expect(rows.map((r) => r.key)).toEqual([MAC_B, 'link:' + LINK_X]);
    // the removed team does not count: only demo/dev decides
    expect(rows[0]?.state).toBe('up_to_date');
    expect(rows[1]).toMatchObject({ linkOnly: true, fingerprint: null, state: 'offline', envs: [] });
  });

  it('groups join requests by the requesting Mac', () => {
    const groups = requestsByDevice([
      { env: 'demo/dev', fingerprint: MAC_B, attempts: 2 },
      { env: 'demo/prod', fingerprint: MAC_B, attempts: 1 },
      { env: 'demo/dev', fingerprint: MAC_C, attempts: 1 },
    ]);
    expect(groups).toEqual([
      { fingerprint: MAC_B, envs: ['demo/dev', 'demo/prod'], attempts: 3 },
      { fingerprint: MAC_C, envs: ['demo/dev'], attempts: 1 },
    ]);
  });
});

const sample = (over: Partial<PairingCodeData> = {}): PairingCodeData => ({
  v: 1, service: 'https://link.example.org', link_token: 'zplt_synthetic_token', peer: LINK_B, name: 'studio mac',
  invites: [{ env: 'demo/dev', invite: 'syntheticinvitezzzzzzzz' }], ...over,
});
const raw = (value: unknown) => PAIR_PREFIX + btoa(JSON.stringify(value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

describe('pairing codes', () => {
  it('round-trips and accepts the slash form in any case', () => {
    const code = encodePairingCode(sample());
    expect(code.startsWith(PAIR_PREFIX)).toBe(true);
    expect(code).not.toContain('=');
    expect(isPairingCode(`  ${code}\n`)).toBe(true);
    expect(decodePairingCode(code)).toEqual(sample());
    expect(decodePairingCode(code.replace('zeropw://pair#', 'ZeroPW://PAIR/#'))).toEqual(sample());
  });

  it('refuses everything the core refuses', () => {
    const bad: unknown[] = [
      { ...sample(), extra: 1 }, { ...sample(), v: 2 }, sample({ service: 'http://link.example.org' }), sample({ service: 'https://link.example.org/x' }),
      sample({ peer: LINK_B.toUpperCase() }), sample({ name: '' }), sample({ name: 'a\u001bb' }), sample({ link_token: 'has space' }),
      sample({ invites: [] }), sample({ invites: [{ env: 'Demo/dev', invite: 'syntheticinvite' }] }), sample({ invites: [{ env: 'demo', invite: 'syntheticinvite' }] }),
      sample({ invites: [{ env: 'demo/dev', invite: 'not-base32!' }] }),
      sample({ invites: [{ env: 'demo/dev', invite: 'syntheticinvite' }, { env: 'demo/dev', invite: 'syntheticinviteb' }] }),
      sample({ invites: Array.from({ length: 17 }, (_, i) => ({ env: `demo/e${i}`, invite: 'syntheticinvite' })) }),
    ];
    for (const value of bad) expect(decodePairingCode(raw(value)), JSON.stringify(value)).toBeNull();
    for (const text of ['', 'zeropw://join#abcdef', 'zeropw://pair#', 'zeropw://pair?x#abcdefghijklmnopqrst', `${PAIR_PREFIX}not base64!`]) {
      expect(isPairingCode(text) && decodePairingCode(text) !== null, text).toBe(false);
    }
    expect(isPairingCode(PAIR_PREFIX + 'a'.repeat(96 * 1024))).toBe(false);
  });
});

describe('pairing reasons', () => {
  it('keeps waiting while an environment may still join, and stops when none can', () => {
    expect(finalJoinReason([{ state: 'joined' }, { state: 'pending' }])).toBeNull();
    // the other Mac is away: retried
    expect(finalJoinReason([{ state: 'failed', reason: 'team_join_failed' }])).toBeNull();
    expect(finalJoinReason([{ state: 'failed', reason: 'team_join_timeout' }])).toBeNull();
    expect(finalJoinReason([{ state: 'failed', reason: 'pairing_env_exists' }, { state: 'pending' }])).toBeNull();
    expect(finalJoinReason([{ state: 'joined' }, { state: 'failed', reason: 'pairing_env_exists' }])).toBe('pairing_env_exists');
    expect(finalJoinReason([{ state: 'failed', reason: 'invite_expired' }, { state: 'failed', reason: 'pairing_env_exists' }])).toBe('invite_expired');
    expect(finalJoinReason([{ state: 'joined' }])).toBeNull();
    for (const r of ['link_token_invalid', 'link_other_account', 'link_device_revoked', 'onetime_ref_unknown', 'pairing_own_code']) {
      expect(isFinalPairingReason(r), r).toBe(true);
    }
    for (const r of ['link_peer_offline', 'link_unavailable', 'link_timeout', 'team_join_failed', 'link_rate_limited']) {
      expect(isFinalPairingReason(r), r).toBe(false);
    }
  });

  it('turns codes into plain copy that exists', () => {
    const keys = [
      pairingStopKey('link_other_account'), pairingStopKey('pairing_env_exists'), pairingStopKey('link_token_invalid'), pairingStopKey('anything_else'),
      pairingStopKey('link_device_revoked'), pairingStopKey('link_device_limit'),
      pairingPreviewErrorKey('pairing_expired'), pairingPreviewErrorKey('pairing_code_malformed'), pairingPreviewErrorKey('pairing_inviter_mismatch'),
      pairingPreviewErrorKey('admin_output_invalid'), enrollErrorKey('link_invite_invalid'), enrollErrorKey('link_rate_limited'),
      enrollErrorKey('link_service_unavailable'), enrollErrorKey('link_device_limit'), enrollErrorKey('zzz'),
    ];
    for (const k of keys) expect(hasCopy(k), k).toBe(true);
    expect(pairingStopKey('link_token_invalid')).toBe('pair.expired');
    expect(pairingStopKey('pairing_env_exists')).toBe('pair.failed.exists');
    expect(enrollErrorKey('link_invite_invalid')).toBe('devices.enroll.err.refused');
    // a dial that did not reach the other Mac says so; the code itself is never the text
    expect(pairingWaitHintKey('team_join_failed', 'link_peer_offline')).toBe('pair.failed.offline');
    expect(pairingWaitHintKey('team_join_timeout')).toBe('pair.failed.offline');
    expect(pairingWaitHintKey('invite_malformed')).toBeNull();
    expect(pairingWaitHintKey(undefined)).toBeNull();
  });
});

describe('polling', () => {
  // a clock that only moves when the poller sleeps
  function clock() {
    let now = 0;
    const sleeps: number[] = [];
    return { now: () => now, sleep: async (ms: number) => { sleeps.push(ms); now += ms; }, sleeps, advance: (ms: number) => { now += ms; } };
  }

  it('stops when done, never overlapping attempts', async () => {
    const c = clock();
    let running = 0, max = 0, n = 0;
    const handle = poll({
      step: async () => { running++; max = Math.max(max, running); await Promise.resolve(); running--; return ++n; },
      done: (v) => v === 3, every: 3000, until: 60_000, now: c.now, sleep: c.sleep,
    });
    expect(await handle.result).toEqual({ kind: 'done', value: 3 });
    expect(max).toBe(1);
    expect(c.sleeps).toEqual([3000, 3000]);
  });

  it('expires at its deadline with the last value', async () => {
    const c = clock();
    const handle = poll({ step: async () => 'pending', done: () => false, every: 4000, until: 10_000, now: c.now, sleep: c.sleep });
    expect(await handle.result).toEqual({ kind: 'expired', value: 'pending' });
    // the last wait is cut to the deadline
    expect(c.sleeps).toEqual([4000, 4000, 2000]);
  });

  it('stops on a final result or a final error, and retries the others', async () => {
    const c = clock();
    const seen: unknown[] = [];
    let n = 0;
    const failing = poll({
      step: async () => { n++; if (n < 3) throw { reason: 'link_unavailable' }; throw { reason: 'link_token_invalid' }; },
      done: () => false, finalError: (e) => ((e as { reason: string }).reason === 'link_token_invalid' ? 'link_token_invalid' : null),
      onError: (e) => seen.push(e), every: 1000, until: 60_000, now: c.now, sleep: c.sleep,
    });
    expect(await failing.result).toEqual({ kind: 'failed', reason: 'link_token_invalid' });
    expect(seen).toHaveLength(2);
    const refused = poll({ step: async () => ({ ok: false }), done: () => false, final: () => 'pairing_env_exists', every: 1000, until: 60_000, now: c.now, sleep: c.sleep });
    expect(await refused.result).toEqual({ kind: 'failed', reason: 'pairing_env_exists' });
  });

  it('cancels at once, also in the middle of a wait', async () => {
    let calls = 0;
    const handle = poll({ step: async () => { calls++; return 0; }, done: () => false, every: 3_600_000, until: Date.now() + 7_200_000 });
    await new Promise((r) => setTimeout(r, 5));
    handle.cancel();
    expect(await handle.result).toEqual({ kind: 'cancelled' });
    expect(calls).toBe(1);
    // a result that arrives after cancel is dropped
    let release!: () => void;
    const slow = poll({ step: () => new Promise<number>((r) => { release = () => r(1); }), done: () => true, every: 10, until: Date.now() + 60_000 });
    await Promise.resolve();
    slow.cancel();
    release();
    expect(await slow.result).toEqual({ kind: 'cancelled' });
  });
});
