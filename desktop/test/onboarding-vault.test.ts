import { afterEach, describe, expect, it } from 'vitest';
import { call, useMockBackend } from '../src/ipc/client';
import { createMockBackend, type MockBackend, type MockSeed } from '../src/ipc/mock';
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

describe('creating the vault', () => {
  it('treats a vault whose relay failed to start as created, and never runs init again', async () => {
    const b = fresh({ relayFails: 1 });
    const rec = await call('recovery_generate');
    const attempts = { unsure: false };
    await createVault({ admin: ADMIN, recovery: { ref: rec.ref } }, attempts);   // vault_init failed with serve_exited
    expect((await call('app_status')).initialized).toBe(true);
    expect((await call('serve_status')).running).toBe(false);
    expect(initCalls(b)).toBe(1);
    // the relay is what the retry starts
    expect((await call('serve_start')).running).toBe(true);
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
