import { afterEach, describe, expect, it } from 'vitest';
import type { InvitePreview } from '../src/ipc/contract';
import { call, terminalOpen, useMockBackend } from '../src/ipc/client';
import { onInvitePreview, subscribe } from '../src/ipc/events';
import { createMockBackend, type MockBackend } from '../src/ipc/mock';

let backend: MockBackend | null = null;
function fresh(seed = {}) {
  backend?.dispose();
  backend = createMockBackend({ latency: 0, ...seed });
  useMockBackend(backend);
  return backend;
}
afterEach(() => { backend?.dispose(); backend = null; useMockBackend(null); });

const tick = () => new Promise((r) => setTimeout(r, 0));

const PREVIEW: InvitePreview = {
  env_id: 'ENVSYNTHETIC', inviter: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', addresses: ['100.64.1.7:47420'], role: 'user',
  name: 'teammate', expires_at: '2026-10-16T00:00:00Z', expired: false, invite_id: '00112233445566778899aabbccddeeff',
};

describe('event subscriptions', () => {
  it('delivers invite previews until unsubscribed', async () => {
    const b = fresh();
    const seen: string[] = [];
    const off = onInvitePreview((p) => seen.push(p.ref));
    await tick();
    b.emit('invite://preview', { ref: 'r1', preview: PREVIEW });
    off();
    b.emit('invite://preview', { ref: 'r2', preview: PREVIEW });
    expect(seen).toEqual(['r1']);
  });

  it('drops a listener whose subscription is cancelled before it resolves', async () => {
    const b = fresh();
    const seen: boolean[] = [];
    const off = subscribe('control://changed', (c) => seen.push(c.stopped));
    off(); // before `on` resolved
    await tick();
    b.emit('control://changed', { stopped: true, restore_pending: false, incident_open: false });
    expect(seen).toEqual([]);
  });
});

describe('terminal helpers outside Tauri', () => {
  it('open a terminal whose output reaches the callback', async () => {
    fresh({ initialized: true });
    const agent = await call('principal_create', { id: 'helper-agent', runtime: 'default' });
    let out = '';
    const term = await terminalOpen({ token_ref: agent.token_ref }, (d) => { out += d; });
    expect(term.terminal_id).toMatch(/^term_/);
    expect(out.length).toBeGreaterThan(0);
  });
});
