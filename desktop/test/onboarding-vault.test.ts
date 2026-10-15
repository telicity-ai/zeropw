import { afterEach, describe, expect, it } from 'vitest';
import { COPY } from '../src/copy';
import { call, toIpcError, useMockBackend, type IpcError } from '../src/ipc/client';
import { createMockBackend, type MockBackend, type MockSeed } from '../src/ipc/mock';
import { afterRelayFailure } from '../src/onboarding/flow';
import { createVault, initFailureOf, InitError, type InitFailure } from '../src/onboarding/vault';

// Vault creation during onboarding against the mock, which follows the core: `init` runs, then
// the relay starts, and a relay that does not start fails `vault_init` although the vault exists.

const ADMIN = 'Quiet-River-Lantern-82!';

let backend: MockBackend | null = null;
function fresh(seed: MockSeed = {}): MockBackend {
  backend?.dispose();
  backend = createMockBackend({ latency: 0, ...seed });
  useMockBackend(backend);
  return backend;
}
afterEach(() => { backend?.dispose(); backend = null; useMockBackend(null); });

async function failure(p: Promise<unknown>): Promise<InitFailure> {
  try { await p; } catch (e) { if (e instanceof InitError) return e.kind; throw e; }
  throw new Error('expected an InitError');
}
const initCalls = (b: MockBackend) => b.calls().filter((c) => c === 'vault_init').length;
async function rejection(p: Promise<unknown>): Promise<IpcError> {
  try { await p; } catch (e) { return toIpcError(e); }
  throw new Error('expected a rejection');
}

describe('creating the vault', () => {
  it('treats a vault whose relay failed to start as created, and never runs init again', async () => {
    const b = fresh({ relayFails: 1 });
    const rec = await call('recovery_generate');
    const attempts = { unsure: false };
    await createVault({ admin: ADMIN, recovery: { ref: rec.ref } }, attempts);   // vault_init failed with listen_failed
    expect((await call('app_status')).initialized).toBe(true);
    expect((await call('serve_status')).running).toBe(false);
    expect(initCalls(b)).toBe(1);
    // the relay is what the retry starts
    expect((await call('serve_start')).running).toBe(true);
  });

  it('lets the user go on when the relay port stays busy: the vault is made and the dashboard has the relay controls', async () => {
    const b = fresh({ relayFails: 3 });                          // another program keeps the gateway port
    const rec = await call('recovery_generate');
    await createVault({ admin: ADMIN, recovery: { ref: rec.ref } }, { unsure: false });
    const again = await rejection(call('serve_start'));          // the create step's retry fails again
    expect([again.reason, again.detail]).toEqual(['listen_failed', 'gateway_port']);
    // going on: no join opens the dashboard, which finds the vault and the relay off
    expect(afterRelayFailure(false)).toBe('dashboard');
    const status = await call('app_status');
    expect(status).toMatchObject({ initialized: true, serve: { running: false } });
    // the port can be changed there and the relay started on it
    await call('settings_set', { gateway_port: 48001, team_listen: null });
    await rejection(call('serve_start'));                        // the last injected failure
    expect(await call('serve_start')).toMatchObject({ running: true, url: 'http://127.0.0.1:48001' });
    expect(initCalls(b)).toBe(1);
    expect(COPY['create.relay.vaultOk']).toContain('대시보드');
  });

  it('still joins on the finale when the relay would not start during a join', async () => {
    fresh({ relayFails: 2 });
    const { ref } = await call('team_invite_preview', { text: 'zeropw://join#' + 'abcdefghijklmnopqrstuvwxyz234567'.repeat(8) });
    const rec = await call('recovery_generate');
    await createVault({ admin: ADMIN, recovery: { ref: rec.ref } }, { unsure: false });
    expect(afterRelayFailure(true)).toBe('done');
    expect((await call('team_join', { ref, project: 'team-x', environment: 'shared' })).project).toBe('team-x');
    expect((await call('serve_status')).running).toBe(false);
  });

  it('sends the user back for a new code when the generated one expired (and init never ran)', async () => {
    const b = fresh({ onetimeTtlMs: 1 });
    const rec = await call('recovery_generate');
    await new Promise((r) => setTimeout(r, 5));
    expect(await failure(createVault({ admin: ADMIN, recovery: { ref: rec.ref } }, { unsure: false }))).toBe('recovery_expired');
    expect(b.inspect().initialized).toBe(false);
    // missing secrets (the code was dropped) mean the same thing, not a dead-end retry
    expect(await failure(createVault({ admin: ADMIN, recovery: null }, { unsure: false }))).toBe('recovery_expired');
  });

  it('sends the user back when a chosen code contains the admin passphrase', async () => {
    fresh();
    expect(await failure(createVault({ admin: ADMIN, recovery: { typed: `${ADMIN}-spare-copy` } }, { unsure: false }))).toBe('recovery_weak');
    expect(await failure(createVault({ admin: ADMIN, recovery: { typed: ADMIN.toLowerCase() } }, { unsure: false }))).toBe('recovery_weak');
    expect((await call('app_status')).initialized).toBe(false);
  });

  it('offers only a retry when the core cannot say whether the vault exists, and the retry finds it', async () => {
    const b = fresh({ relayFails: 1 });
    const rec = await call('recovery_generate');
    const attempts = { unsure: false };
    b.failNext('app_status', { error: 'IoError', reason: 'status_unreadable' });
    expect(await failure(createVault({ admin: ADMIN, recovery: { ref: rec.ref } }, attempts))).toBe('unknown');
    expect(attempts.unsure).toBe(true);
    // retry with different secrets: the existing vault is found first, nothing is made again
    await createVault({ admin: 'Another-Passphrase-77!', recovery: { typed: 'some other long recovery phrase' } }, attempts);
    expect(initCalls(b)).toBe(1);
    expect(attempts.unsure).toBe(false);
  });

  it('reads the core reason only when the vault does not exist', () => {
    expect(initFailureOf('onetime_ref_unknown')).toBe('recovery_expired');
    expect(initFailureOf('onetime_ref_invalid')).toBe('recovery_expired');
    expect(initFailureOf('passphrase_weak', 'recovery')).toBe('recovery_weak');
    expect(initFailureOf('passphrase_too_short', 'recovery')).toBe('recovery_weak');
    expect(initFailureOf('passphrases_identical')).toBe('recovery_weak');
    expect(initFailureOf('passphrase_weak', 'admin')).toBe('failed');
    expect(initFailureOf('state_exists')).toBe('failed');
  });
});
