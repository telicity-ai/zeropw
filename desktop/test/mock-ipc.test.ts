import { afterEach, describe, expect, it } from 'vitest';
import { call, IpcError, outputChannel, toIpcError, useMockBackend } from '../src/ipc/client';
import { createMockBackend, mockStrength, type MockBackend } from '../src/ipc/mock';

const ADMIN = 'Quiet-River-Lantern-82!';
const LINK = 'zeropw://join#' + 'abcdefghijklmnopqrstuvwxyz234567'.repeat(8);
const EXPIRED = 'zeropw://join#zzzz' + 'abcdefghijklmnopqrstuvwxyz234567'.repeat(8);

async function rejection(p: Promise<unknown>): Promise<IpcError> {
  try { await p; } catch (e) { return toIpcError(e); }
  throw new Error('expected a rejection');
}

let backend: MockBackend | null = null;
function fresh(seed = {}) {
  backend?.dispose();
  backend = createMockBackend({ latency: 0, ...seed });
  useMockBackend(backend);
  return backend;
}
afterEach(() => { backend?.dispose(); backend = null; useMockBackend(null); });

describe('typed client outside Tauri', () => {
  it('routes calls to the mock backend', async () => {
    fresh();
    const s = await call('app_status');
    expect(s.initialized).toBe(false);
    expect(s.control).toBeNull();
  });

  it('normalises errors without echoing inputs', async () => {
    fresh();
    const e = await rejection(call('vault_init', { admin_passphrase: 'short', recovery: { typed: 'also-secret-value' } }));
    expect(e).toBeInstanceOf(IpcError);
    expect(e.reason).toBe('passphrase_too_short');
    expect(JSON.stringify({ ...e, message: e.message })).not.toContain('also-secret-value');
    const odd = toIpcError(new Error('contains a secret value'));
    expect(odd.reason).toBe('ipc_failed');
    expect(odd.message).not.toContain('secret value');
  });
});

describe('mock onboarding flow', () => {
  it('runs password → recovery → vault → relay → project → agent → terminal', async () => {
    const b = fresh();
    const weak = await call('password_strength', { value: 'password123' });
    expect(weak.reason).toBe('common');
    expect(weak.score).toBeLessThan(3);
    const strong = await call('password_strength', { value: ADMIN });
    expect(strong.score).toBeGreaterThanOrEqual(3);

    const rec = await call('recovery_generate');
    expect(rec.groups).toHaveLength(6);
    for (const g of rec.groups) expect(g).toMatch(/^[A-Z2-7]{4}$/);
    expect(b.inspect().onetime).toBe(1);

    expect((await rejection(call('project_create', { name: 'demo', environments: ['dev'] }))).reason).toBe('not_initialized');
    const init = await call('vault_init', { admin_passphrase: ADMIN, recovery: { ref: rec.ref } });
    expect(init.kms_key_id).toMatch(/^kms-dev-/);
    expect(b.inspect().onetime).toBe(0);                       // the recovery reference is used up
    expect((await rejection(call('vault_init', { admin_passphrase: ADMIN, recovery: { ref: rec.ref } }))).reason).toBe('already_initialized');

    const serve = await call('serve_status');
    expect(serve.running).toBe(true);
    expect(serve.url).toBe('http://127.0.0.1:47380');
    const status = await call('app_status');
    expect(status.initialized).toBe(true);
    expect(status.control).toEqual({ stopped: false, restore_pending: false, incident_open: false });

    const project = await call('project_create', { name: 'demo', environments: ['dev', 'staging', 'prod'] });
    expect(project.environments).toEqual(['dev', 'staging', 'prod']);
    expect((await rejection(call('project_create', { name: 'demo', environments: ['dev'] }))).reason).toBe('project_exists');
    expect((await rejection(call('project_create', { name: 'Demo', environments: ['dev'] }))).reason).toBe('invalid_name');

    const agent = await call('principal_create', { id: 'agent-1', runtime: 'user-agent' });
    expect(agent.token_ref).toMatch(/^ref_[0-9a-f]{32}$/);
    expect(JSON.stringify(agent)).not.toMatch(/zpwc_/);       // the token itself never comes back
    expect((await rejection(call('principal_create', { id: 'agent-1', runtime: 'default' }))).reason).toBe('principal_exists');

    let out = '';
    const term = await call('terminal_open', { token_ref: agent.token_ref, as_user: 'agent', on_data: outputChannel((d) => { out += d; }) });
    expect(term.suggestions).toHaveLength(2);
    expect(term.suggestions[0]).toBe('sudo --preserve-env=ZEROPW_GATEWAY_URL,ZEROPW_CALLER_TOKEN,no_proxy -u agent -i');
    expect(term.suggestions[1]).toMatch(/\/zeropw-agent list-connections$/);
    expect(out).toContain('me@mac');

    await call('terminal_write', { terminal_id: term.terminal_id, data: (term.suggestions[0] ?? '') + '\r' });
    expect(out).toContain('Password:');
    await call('terminal_write', { terminal_id: term.terminal_id, data: 'hunter2\r' });
    expect(out).not.toContain('hunter2');                      // the sudo password is not echoed
    expect(out).toContain('agent@mac');
    await call('terminal_write', { terminal_id: term.terminal_id, data: (term.suggestions[1] ?? '') + '\r' });
    expect(out).toContain('{"connections":[]}');
    expect(out).not.toMatch(/zpwc_/);
    await call('terminal_resize', { terminal_id: term.terminal_id, cols: 100, rows: 30 });
    await call('terminal_close', { terminal_id: term.terminal_id });
    expect(b.inspect().terminals).toBe(0);
    expect((await rejection(call('terminal_write', { terminal_id: term.terminal_id, data: 'x' }))).reason).toBe('terminal_unknown');
  });

  it('accepts a chosen recovery code but not the admin passphrase again', async () => {
    fresh();
    expect((await rejection(call('vault_init', { admin_passphrase: ADMIN, recovery: { typed: ` ${ADMIN.toLowerCase()} ` } }))).reason).toBe('recovery_same_as_admin');
    expect((await rejection(call('vault_init', { admin_passphrase: ADMIN, recovery: { ref: 'ref_unknown' } }))).reason).toBe('recovery_ref_unknown');
    await call('vault_init', { admin_passphrase: ADMIN, recovery: { typed: 'a different long recovery phrase' } });
    expect((await call('app_status')).initialized).toBe(true);
  });

  it('discards one-time references', async () => {
    const b = fresh();
    const rec = await call('recovery_generate');
    await call('onetime_discard', { ref: rec.ref });
    expect(b.inspect().onetime).toBe(0);
    expect((await rejection(call('vault_init', { admin_passphrase: ADMIN, recovery: { ref: rec.ref } }))).reason).toBe('recovery_ref_unknown');
  });
});

describe('mock join path', () => {
  it('previews without joining, then joins once after the vault exists', async () => {
    const b = fresh();
    expect((await rejection(call('team_invite_preview', { text: 'zeropw://join#short' }))).reason).toBe('invite_invalid');
    expect((await rejection(call('team_invite_preview', { text: 'https://example.com/#' + 'a'.repeat(100) }))).reason).toBe('invite_invalid');
    const { ref, preview } = await call('team_invite_preview', { text: LINK });
    expect(preview.expired).toBe(false);
    expect(preview.inviter).toMatch(/^[A-Z2-7]{26}$/);
    expect(b.inspect().projects).toEqual([]);                  // a preview changes nothing
    const again = await call('team_invite_preview', { text: LINK });
    expect(again.preview).toEqual(preview);                    // same link, same picture

    expect((await rejection(call('team_join', { ref }))).reason).toBe('not_initialized');
    const rec = await call('recovery_generate');
    await call('vault_init', { admin_passphrase: ADMIN, recovery: { ref: rec.ref } });
    const joined = await call('team_join', { ref, project: 'team-x', environment: 'shared' });
    expect(joined).toMatchObject({ project: 'team-x', environment: 'shared', inviter_fingerprint: preview.inviter });
    expect((await rejection(call('team_join', { ref }))).reason).toBe('invite_ref_unknown');
  });

  it('refuses an expired invite', async () => {
    fresh({ initialized: true });
    const { ref, preview } = await call('team_invite_preview', { text: EXPIRED });
    expect(preview.expired).toBe(true);
    expect((await rejection(call('team_join', { ref }))).reason).toBe('invite_expired');
  });
});

describe('mock dashboard shell', () => {
  it('stops everything and resumes only with the admin passphrase', async () => {
    const b = fresh({ initialized: true });
    const seen: boolean[] = [];
    const off = b.on('control://changed', (c) => seen.push(c.stopped));
    expect((await call('stop_all')).stopped).toBe(true);
    expect((await rejection(call('resume', { admin_passphrase: 'wrong passphrase' }))).error).toBe('AuthFailed');
    expect((await call('control_get')).stopped).toBe(true);
    expect((await call('resume', { admin_passphrase: 'mock-admin-pass' })).stopped).toBe(false);
    expect(seen).toEqual([true, false]);
    off();
    const alerts = await call('alerts', { limit: 5 });
    expect(alerts.alerts.length).toBeGreaterThan(0);
    expect((await call('audit_tail', { limit: 10 })).records.map((r) => r.event)).toEqual(['stop_all', 'resume']);
  });

  it('rejects commands it does not simulate with a stable reason', async () => {
    fresh({ initialized: true });
    expect((await rejection(call('backup_create'))).reason).toBe('mock_unsupported');
  });
});

describe('placeholder strength score', () => {
  it('reports zxcvbn-style integers with stable reason codes', () => {
    expect(mockStrength('')).toEqual({ score: 0, reason: null });
    expect(mockStrength('aaaaaaaaaaaa').reason).toBe('repeat');
    expect(mockStrength('Sunshine2024').reason).toBe('year');
    expect(mockStrength('Tr0ub4dor&3').reason).toBe('short');
    for (const v of ['x', 'password', ADMIN, 'correct horse battery staple']) expect(Number.isInteger(mockStrength(v).score)).toBe(true);
  });
});
