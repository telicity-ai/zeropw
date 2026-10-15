import { afterEach, describe, expect, it } from 'vitest';
import { call, IpcError, outputChannel, toIpcError, useMockBackend } from '../src/ipc/client';
import { createMockBackend, type MockBackend } from '../src/ipc/mock';
import { holdSecureView, secureViewHolders } from '../src/ui/secure';
import { grantState, liveGrants, pendingApprovals, runtimeStopsAll } from '../src/lib/dash';
import { relayError, restoreErrorKey } from '../src/lib/reasons';

// The browser mock stands in for the core while the dashboard is reviewed. These flows pin the
// rules the pages rely on: values never come back except through one-time references, the admin
// passphrase is asked again where the contract says so, and errors never echo inputs.

const PASS = 'mock-admin-pass';
const HOST_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl';

async function rejection(p: Promise<unknown>): Promise<IpcError> {
  try { await p; } catch (e) { return toIpcError(e); }
  throw new Error('expected a rejection');
}
const settle = async () => { for (let i = 0; i < 5; i++) await new Promise<void>((r) => setTimeout(r, 0)); };

let backend: MockBackend | null = null;
function ready(): MockBackend {
  backend?.dispose();
  backend = createMockBackend({ latency: 0, initialized: true });
  useMockBackend(backend);
  return backend;
}
afterEach(() => { backend?.dispose(); backend = null; useMockBackend(null); });

describe('keys', () => {
  it('lists without values and reveals one version once, after the admin passphrase', async () => {
    const b = ready();
    const value = 'sk_test_synthetic_value_1234';
    await call('secret_put', { id: 'my-key', kind: 'api_key', project: 'demo', environment: 'dev', source: { typed: value } });
    const list = await call('secret_list', {});
    expect(list.secrets.map((s) => s.id)).toContain('my-key');
    expect(JSON.stringify(list)).not.toContain(value);
    expect(JSON.stringify(list)).not.toMatch(/sk_test_mock_/);

    const before = b.inspect().onetime;
    const wrong = await rejection(call('secret_reveal', { id: 'my-key', admin_passphrase: 'wrong passphrase value' }));
    expect(wrong.error).toBe('AuthFailed');
    expect(JSON.stringify({ ...wrong, message: wrong.message })).not.toContain('wrong passphrase value');
    expect(b.inspect().onetime).toBe(before);
    expect((await rejection(call('secret_reveal', { id: 'my-key', admin_passphrase: '' }))).reason).toBe('passphrase_missing');

    const r = await call('secret_reveal', { id: 'my-key', admin_passphrase: PASS });
    expect(JSON.stringify(r)).not.toContain(value);
    expect((await call('onetime_show', { ref: r.ref })).text).toBe(value);
    expect((await rejection(call('onetime_show', { ref: r.ref }))).reason).toBe('onetime_ref_unknown');
  });

  it('replaces a value: the new version is active, the old one retired, and retiring the active one is refused', async () => {
    ready();
    await call('secret_put', { id: 'rot', kind: 'password', project: 'demo', environment: 'prod', source: { typed: 'first' } });
    await call('secret_put', { id: 'rot', kind: 'password', project: 'demo', environment: 'prod', source: { typed: 'second' } });
    const v = await call('secret_versions', { id: 'rot' });
    // versions are JSON numbers, as the CLI prints them
    expect(v.active_version as unknown).toBe(2);
    expect(v.versions.map((x) => [x.version, x.status])).toEqual([[1, 'retired'], [2, 'active']]);
    expect((await rejection(call('secret_retire', { id: 'rot', version: '2' }))).reason).toBe('version_is_active');
    expect((await rejection(call('secret_put', { id: 'rot', kind: 'api_key', project: 'demo', environment: 'prod', source: { typed: 'x' } }))).reason)
      .toBe('secret_identity_mismatch');
  });

  it('refuses to reveal a revoked version', async () => {
    ready();
    await call('secret_put', { id: 'gone', kind: 'env_var', project: 'demo', environment: 'staging', source: { typed: 'v' } });
    const out = await call('secret_revoke', { id: 'gone', version: '1' });
    expect(out).toMatchObject({ secret_id: 'gone', version: 1, status: 'revoked', provider_revocation_required: true });
    expect((await rejection(call('secret_reveal', { id: 'gone', version: '1', admin_passphrase: PASS }))).reason).toBe('version_revoked');
  });

  it('reads a picked file once and generates SSH keys only for SSH secrets', async () => {
    ready();
    const f = await call('file_pick', { purpose: 'secret' });
    if (!f) throw new Error('no file');
    await call('secret_put', { id: 'from-file', kind: 'api_key', project: 'demo', environment: 'dev', source: { file_token: f.file_token } });
    expect((await rejection(call('secret_put', { id: 'again', kind: 'api_key', project: 'demo', environment: 'dev', source: { file_token: f.file_token } }))).reason)
      .toBe('file_token_unknown');
    expect((await rejection(call('secret_put', { id: 'k', kind: 'api_key', project: 'demo', environment: 'dev', source: { generate_ed25519: true } }))).reason)
      .toBe('source_kind_mismatch');
    const out = await call('secret_put', { id: 'deploy', kind: 'ssh_private_key', project: 'demo', environment: 'dev', source: { generate_ed25519: true } });
    expect(String(out.public_key)).toMatch(/^ssh-ed25519 /);
    expect(String(out.fingerprint)).toMatch(/^SHA256:/);
    expect(JSON.stringify(out)).not.toMatch(/PRIVATE|mock-openssh-private-key/);
  });

  it('rejects names, kinds and environments the core would reject', async () => {
    ready();
    const put = (id: string, project = 'demo', environment = 'dev') => call('secret_put', { id, kind: 'api_key', project, environment, source: { typed: 'v' } });
    expect((await rejection(put('Bad Name'))).reason).toBe('invalid_secret_id');
    expect((await rejection(put('ok', 'nope'))).reason).toBe('project_unknown');
    expect((await rejection(put('ok', 'demo', 'qa'))).reason).toBe('environment_unknown');
  });
});

describe('connections', () => {
  const http = {
    id: 'svc', project: 'demo', environment: 'dev', service: 'svc', secret_id: 'svc', target: 'https://api.example.com', auth: 'bearer' as const,
    methods: ['GET'], confirm_methods: [], path_prefixes: [], allow_private_network: false,
  };

  it('needs the admin passphrase and a stored key, and blocks metadata and unapproved private addresses', async () => {
    const b = ready();
    expect((await rejection(call('connection_create_http', { ...http, admin_passphrase: PASS }))).reason).toBe('secret_not_found');
    await call('secret_put', { id: 'svc', kind: 'api_key', project: 'demo', environment: 'dev', source: { typed: 'k' } });
    expect((await rejection(call('connection_create_http', { ...http, admin_passphrase: 'nope' }))).error).toBe('AuthFailed');
    expect((await rejection(call('connection_create_http', { ...http, target: 'http://169.254.169.254', admin_passphrase: PASS }))).reason).toBe('metadata_address_not_allowed');
    expect((await rejection(call('connection_create_http', { ...http, target: 'http://10.0.0.8', admin_passphrase: PASS }))).reason).toBe('target_address_not_allowed');
    const c = await call('connection_create_http', { ...http, methods: ['GET', 'POST'], confirm_methods: ['POST'], admin_passphrase: PASS });
    expect(c.status).toBe('active');
    expect(JSON.stringify(c)).not.toContain('"k"');
    expect(b.inspect().connections).toContain('svc');
    expect((await rejection(call('connection_create_http', { ...http, admin_passphrase: PASS }))).reason).toBe('connection_exists');
    await call('connection_disable', { id: 'svc' });
    expect((await call('connection_list')).connections.find((x) => x.id === 'svc')?.status).toBe('disabled');
  });

  it('creates an SSH connection only with an Ed25519 host key and an SSH key', async () => {
    ready();
    await call('secret_put', { id: 'git', kind: 'ssh_private_key', project: 'demo', environment: 'dev', source: { generate_ed25519: true } });
    const ssh = { id: 'git', project: 'demo', environment: 'dev', service: 'git', secret_id: 'git', host: 'git.example.com', port: 22, username: 'git', admin_passphrase: PASS };
    expect((await rejection(call('connection_create_ssh', { ...ssh, host_keys: ['ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB'] }))).reason).toBe('unsupported_host_key');
    expect((await rejection(call('connection_create_ssh', { ...ssh, host_keys: [] }))).reason).toBe('host_key_required');
    const c = await call('connection_create_ssh', { ...ssh, host_keys: [HOST_KEY] });
    expect(c.kind).toBe('ssh');
  });
});

describe('agents, grants, terminals and approvals', () => {
  it('grants with the admin passphrase, shows the grant to the agent and revokes it', async () => {
    ready();
    const bad = await rejection(call('grant_create', { principal: 'agent-1', connection: 'example-api', ttl: '8h', admin_passphrase: 'x' }));
    expect(bad.error).toBe('AuthFailed');
    expect((await rejection(call('grant_create', { principal: 'agent-1', connection: 'example-api', ttl: '8h', max_uses: '0', admin_passphrase: PASS }))).reason)
      .toBe('invalid_argument');
    const g = await call('grant_create', { principal: 'agent-1', connection: 'example-api', ttl: '8h', max_uses: '5', admin_passphrase: PASS });
    expect(g).toMatchObject({ principal: 'agent-1', connection: 'example-api', max_uses: 5, uses: 0, status: 'active' });   // counts as JSON numbers
    expect(Date.parse(g.expires_at) - Date.now()).toBeGreaterThan(7.9 * 3600_000);
    expect((await call('grant_list', { principal: 'agent-1' })).grants.some((x) => x.id === g.id)).toBe(true);
    expect((await call('grant_revoke', { id: g.id })).status).toBe('revoked');
  });

  it('keeps a terminal running after its view goes away and replays it on attach', async () => {
    ready();
    const a = await call('principal_create', { id: 'agent-9', runtime: 'user-agent' });
    let first = '';
    const term = await call('terminal_open', { token_ref: a.token_ref, as_user: 'agent', on_data: outputChannel((d) => { first += d; }) });
    await call('terminal_write', { terminal_id: term.terminal_id, data: 'echo-me\r' });
    expect(first).toContain('command not found: echo-me');
    // the onboarding view is gone (no terminal_close): the shell is still listed
    const listed = (await call('terminal_list')).terminals.find((x) => x.terminal_id === term.terminal_id);
    expect(listed).toEqual({ terminal_id: term.terminal_id, principal: 'agent-9', as_user: 'agent', alive: true });
    let again = '';
    const att = await call('terminal_attach', { terminal_id: term.terminal_id, on_data: outputChannel((d) => { again += d; }) });
    expect(att.suggestions).toEqual(term.suggestions);
    expect(again).toContain('command not found: echo-me');
    expect(again).not.toMatch(/zpwc_/);
    const seen = first.length;
    await call('terminal_write', { terminal_id: term.terminal_id, data: 'second\r' });
    expect(again).toContain('second');
    expect(first.length).toBe(seen);                          // output now goes to the attached view only
    await call('terminal_close', { terminal_id: term.terminal_id });
    expect((await call('terminal_list')).terminals.some((x) => x.terminal_id === term.terminal_id)).toBe(false);
    expect((await rejection(call('terminal_attach', { terminal_id: term.terminal_id, on_data: outputChannel(() => undefined) }))).reason).toBe('terminal_not_found');
  });

  it('copies a token once; the core forgets it afterwards', async () => {
    ready();
    const a = await call('principal_create', { id: 'agent-c', runtime: 'default' });
    expect((await call('onetime_copy', { ref: a.token_ref })).copied).toBe(true);
    expect((await rejection(call('onetime_copy', { ref: a.token_ref }))).reason).toBe('onetime_ref_unknown');
    expect((await rejection(call('terminal_open', { token_ref: a.token_ref, on_data: outputChannel(() => undefined) }))).reason).toBe('onetime_ref_unknown');
  });

  it('approves a pending request once, with the admin passphrase', async () => {
    ready();
    const { approvals } = await call('approvals_list');
    const pending = approvals.find((x) => x.status === 'pending');
    expect(pending).toBeDefined();
    const digest = String(pending?.digest);
    expect((await rejection(call('approvals_approve', { digest, admin_passphrase: 'no' }))).error).toBe('AuthFailed');
    expect((await call('approvals_approve', { digest, admin_passphrase: PASS })).status).toBe('approved');
    expect((await rejection(call('approvals_approve', { digest, admin_passphrase: PASS }))).reason).toBe('approval_not_pending');
    expect((await call('audit_tail', { limit: 1 })).records[0]?.event).toBe('approval_grant');
  });

  it('disables an agent', async () => {
    ready();
    await call('principal_disable', { id: 'agent-1' });
    expect((await call('principal_list')).principals.find((p) => p.id === 'agent-1')?.status).toBe('disabled');
  });
});

describe('incidents, stop-all and recovery', () => {
  it('locks down a principal, needs the passphrase for the all scope and to close', async () => {
    const b = ready();
    const changes: boolean[] = [];
    b.on('control://changed', (c) => changes.push(c.incident_open));
    const inc = await call('incident_declare', { scope: 'principal', principal: 'agent-1', reason: 'token leaked in a log' });
    expect(inc.status).toBe('open');
    expect((await call('principal_list')).principals.find((p) => p.id === 'agent-1')?.status).toBe('disabled');
    expect((await call('grant_list', { principal: 'agent-1' })).grants.every((g) => g.status !== 'active')).toBe(true);
    expect((await call('control_get')).incident_open).toBe(true);
    expect((await rejection(call('incident_declare', { scope: 'all' }))).reason).toBe('passphrase_missing');
    expect((await rejection(call('incident_close', { id: inc.id, admin_passphrase: 'no' }))).error).toBe('AuthFailed');
    await call('incident_close', { id: inc.id, admin_passphrase: PASS });
    expect((await call('control_get')).incident_open).toBe(false);
    expect((await rejection(call('incident_close', { id: inc.id, admin_passphrase: PASS }))).reason).toBe('incident_already_closed');
    expect(changes).toEqual([true, false]);
  });

  it('stops everything when the all scope is declared', async () => {
    ready();
    await call('incident_declare', { scope: 'all', admin_passphrase: PASS });
    expect(await call('control_get')).toMatchObject({ stopped: true, incident_open: true });
  });

  it('holds relaying after a restore until it is acknowledged, and recovers with the recovery code', async () => {
    ready();
    await call('backup_create');
    expect((await rejection(call('backup_restore', { admin_passphrase: 'x' }))).error).toBe('AuthFailed');
    await call('backup_restore', { admin_passphrase: PASS });
    expect((await call('control_get')).restore_pending).toBe(true);
    await call('restore_ack', { admin_passphrase: PASS });
    expect((await call('control_get')).restore_pending).toBe(false);
    const wrong = await rejection(call('recover', { recovery_passphrase: 'AAAA-BBBB-CCCC-DDDD-EEEE-FFFF' }));
    expect(wrong.error).toBe('AuthFailed');
    expect(JSON.stringify({ ...wrong, message: wrong.message })).not.toContain('AAAA');
    await call('recover', { recovery_passphrase: 'abcd efgh ijkl mnop qrst uvwx' });   // typed casually, canonicalized
  });
});

describe('team', () => {
  it('shares with the admin passphrase; an unshared environment has no members', async () => {
    ready();
    expect((await rejection(call('team_members', { env: 'demo/dev' }))).reason).toBe('team_env_not_found');
    expect((await rejection(call('team_share', { project: 'demo', environment: 'dev', admin_passphrase: 'x' }))).error).toBe('AuthFailed');
    await call('team_share', { project: 'demo', environment: 'dev', admin_passphrase: PASS });
    const m = await call('team_members', { env: 'demo/dev' });
    expect(m.members).toHaveLength(1);
    expect(m.members[0]?.owner).toBe(true);
    expect((await rejection(call('team_share', { project: 'demo', environment: 'dev', admin_passphrase: PASS }))).reason).toBe('team_env_already_shared');
    expect((await rejection(call('team_remove', { env: 'demo/dev', device: m.members[0]?.fingerprint ?? '', admin_passphrase: PASS }))).reason).toBe('cannot_remove_owner');
  });

  it('creates a one-use link that leaves the core once and lists invites without secrets', async () => {
    const b = ready();
    await call('team_share', { project: 'demo', environment: 'dev', admin_passphrase: PASS });
    const inv = await call('team_invite_create', { env: 'demo/dev', role: 'user', name: 'laptop', address: '100.64.1.7:47420', admin_passphrase: PASS });
    expect(inv.inviter).toMatch(/^[A-Z2-7]{26}$/);
    expect(Date.parse(inv.expires_at) - Date.now()).toBeGreaterThan(23.9 * 3600_000);
    const shown = await call('onetime_show', { ref: inv.link_ref });
    expect(shown.text).toMatch(/^zeropw:\/\/join#[a-z2-7]{80,}$/);
    expect((await rejection(call('onetime_copy', { ref: inv.link_ref }))).reason).toBe('onetime_ref_unknown');
    const list = await call('team_invites', { env: 'demo/dev' });
    expect(list.invites).toHaveLength(1);
    expect(list.invites[0]).toMatchObject({ invite_id: inv.invite_id, status: 'pending', link: true });
    expect(JSON.stringify(list)).not.toContain(shown.text.slice(14, 40));
    await call('team_revoke_invite', { env: 'demo/dev', invite_id: inv.invite_id });
    await call('team_revoke_invite', { env: 'demo/dev', invite_id: inv.invite_id });   // idempotent
    expect((await call('team_invites', { env: 'demo/dev' })).invites[0]?.status).toBe('revoked');
    expect((await rejection(call('team_revoke_invite', { env: 'demo/dev', invite_id: 'nope' }))).reason).toBe('invite_not_found');
    expect(b.inspect().onetime).toBe(0);
  });

  it('joins only from a previewed reference and adds the shared environment', async () => {
    ready();
    const link = 'zeropw://join#' + 'abcdefghijklmnopqrstuvwxyz234567'.repeat(4);
    const { ref, preview } = await call('team_invite_preview', { text: link });
    expect((await rejection(call('onetime_show', { ref }))).reason).toBe('onetime_ref_unknown');   // a pasted invite stays in the core
    const joined = await call('team_join', { ref, project: 'team-x', environment: 'shared' });
    expect(joined.inviter_fingerprint).toBe(preview.inviter);
    expect((await call('team_members', { env: 'team-x/shared' })).members.map((m) => m.owner)).toEqual([true, false]);
  });
});

describe('settings and window protection', () => {
  it('validates ports and team addresses like the core and restarts the relay on the new port', async () => {
    ready();
    expect((await rejection(call('settings_set', { gateway_port: 80, team_listen: null }))).reason).toBe('invalid_port');
    expect((await rejection(call('settings_set', { gateway_port: 47380, team_listen: '0.0.0.0:47420' }))).reason).toBe('invalid_listen');
    expect((await rejection(call('settings_set', { gateway_port: 47380, team_listen: 'laptop:47420' }))).reason).toBe('invalid_listen');
    await call('settings_set', { gateway_port: 48000, team_listen: '100.64.1.7:47420' });
    await call('serve_stop');
    const s = await call('serve_start');
    expect(s).toMatchObject({ running: true, url: 'http://127.0.0.1:48000', team_listen: '100.64.1.7:47420' });
  });

  it('turns window protection on before a hold is ready and keeps it while any holder needs it', async () => {
    const b = ready();
    const h1 = holdSecureView(), h2 = holdSecureView();
    expect(b.inspect().secureView).toBe(false);                 // nothing is on yet: a value must wait
    await h1.ready;
    expect(b.inspect().secureView).toBe(true);                  // ready only once the core applied it
    h1.release(); h1.release();                                 // releasing twice counts once
    await settle();
    expect(b.inspect().secureView).toBe(true);
    h2.release();
    await settle();
    expect(b.inspect().secureView).toBe(false);
    expect(secureViewHolders()).toBe(0);
  });

  it('sends on and off in order, so a quick release and hold ends protected', async () => {
    const b = ready();
    const first = holdSecureView();
    await first.ready;
    first.release();                                            // queues "off"
    const second = holdSecureView();                            // queues "on" after it
    await second.ready;
    await settle();
    expect(b.inspect().secureView).toBe(true);
    second.release();
    await settle();
    expect(b.inspect().secureView).toBe(false);
  });
});

// ---- the shapes the real core sends (desktop/core passes the CLI's JSON through), fed back the
// way the pages feed them back

describe('versions as the CLI prints them', () => {
  it('reveals, retires and revokes with the version exactly as listed (a number)', async () => {
    ready();
    await call('secret_put', { id: 'cli-shape', kind: 'api_key', project: 'demo', environment: 'dev', source: { typed: 'first-synthetic' } });
    await call('secret_put', { id: 'cli-shape', kind: 'api_key', project: 'demo', environment: 'dev', source: { typed: 'second-synthetic' } });
    const listed = (await call('secret_list', {})).secrets.find((s) => s.id === 'cli-shape');
    expect(typeof listed?.active_version).toBe('number');
    const versions = (await call('secret_versions', { id: 'cli-shape' })).versions;
    for (const v of versions) expect(typeof v.version).toBe('number');
    const old = versions.find((v) => v.status === 'retired');
    if (!old) throw new Error('no retired version');
    // the Keys page passes `x.version` back unchanged
    const r = await call('secret_reveal', { id: 'cli-shape', version: old.version, admin_passphrase: PASS });
    expect((await call('onetime_show', { ref: r.ref })).text).toBe('first-synthetic');
    const revoked = await call('secret_revoke', { id: 'cli-shape', version: old.version });
    expect(revoked).toMatchObject({ secret_id: 'cli-shape', status: 'revoked', provider_revocation_required: true });
    expect(String(revoked.reminder)).toMatch(/provider/);
    expect((await rejection(call('secret_revoke', { id: 'cli-shape', version: 'v2' }))).reason).toBe('invalid_argument');
  });

  it('lists a generated SSH key with its public half, so it can be shown again later', async () => {
    ready();
    const out = await call('secret_put', { id: 'deploy-key', kind: 'ssh_private_key', project: 'demo', environment: 'dev', source: { generate_ed25519: true } });
    const v = (await call('secret_versions', { id: 'deploy-key' })).versions[0];
    expect(v?.public?.public_key).toBe(out.public_key);
    const plain = (await call('secret_versions', { id: 'example-api' })).versions[0];
    expect(plain?.public).toEqual({});                          // the CLI prints an empty object
  });

  it('creates a connection from a key stored on the Keys page, of any kind the connection takes', async () => {
    ready();
    await call('secret_put', { id: 'database-url', kind: 'env_var', project: 'demo', environment: 'staging', source: { typed: 'synthetic-dsn' } });
    const http = {
      id: 'db-api', project: 'demo', environment: 'staging', service: 'db-api', secret_id: 'database-url', target: 'https://db.example.com', auth: 'bearer' as const,
      methods: ['GET'], confirm_methods: [], path_prefixes: [], allow_private_network: false, admin_passphrase: PASS,
    };
    expect((await call('connection_create_http', http)).secret_id).toBe('database-url');
    expect((await rejection(call('connection_create_http', { ...http, id: 'x2', environment: 'dev' }))).reason).toBe('secret_scope_mismatch');
    const ssh = { id: 'git2', project: 'demo', environment: 'staging', service: 'git2', secret_id: 'database-url', host: 'git.example.com', port: 22, username: 'git', host_keys: [HOST_KEY], admin_passphrase: PASS };
    expect((await rejection(call('connection_create_ssh', ssh))).reason).toBe('secret_kind_mismatch');
  });
});

describe('grants as the CLI keeps them', () => {
  it('keeps an expired or used-up grant `active`; liveness is derived from time and uses', async () => {
    ready();
    const { grants } = await call('grant_list', { principal: 'agent-1' });
    expect(grants.every((g) => g.status === 'active')).toBe(true);
    const now = Date.now();
    expect(grants.map((g) => grantState(g, now)).sort()).toEqual(['expired', 'live', 'used']);
    expect(liveGrants(grants, 'agent-1', now)).toHaveLength(1);
    // the agent's own view (list-connections) matches: one live grant, one connection
    const term = (await call('terminal_list')).terminals[0];
    if (!term) throw new Error('no terminal');
    let out = '';
    await call('terminal_attach', { terminal_id: term.terminal_id, on_data: outputChannel((d) => { out += d; }) });
    out = '';
    await call('terminal_write', { terminal_id: term.terminal_id, data: '/x/zeropw-agent list-connections\r' });
    expect(out).toContain('{"connections":[{"id":"example-api"}]}');
  });
});

describe('approvals carry what the approval is bound to', () => {
  it('lists the query, the body and its hash next to the path', async () => {
    ready();
    const list = pendingApprovals((await call('approvals_list')).approvals);
    expect(list).toHaveLength(2);
    const long = list.find((a) => a.query !== null);
    expect(long?.target).toBe(`${long?.path}?force=true&dry_run=false`);
    expect(long?.path.length).toBeGreaterThan(160);             // shown whole, not clipped
    expect(long?.bodyTruncated).toBe(true);
    const json = list.find((a) => a.contentType === 'application/json');
    expect(json?.bodyPreview).toContain('synthetic item');
    expect(json?.bodyHash).toMatch(/^[0-9a-f]{4}( [0-9a-f]{4}){3}$/);
  });
});

describe('stop, incidents, restore and recovery as the CLI does them', () => {
  it('refuses to resume while an incident is open', async () => {
    ready();
    await call('stop_all');
    await call('incident_declare', { scope: 'principal', principal: 'agent-1' });
    const e = await rejection(call('resume', { admin_passphrase: PASS }));
    expect([e.error, e.reason]).toEqual(['InvalidInput', 'incident_open']);
  });

  it('stops everything when a runtime incident covers every active agent', async () => {
    ready();
    const principals = (await call('principal_list')).principals;
    expect(runtimeStopsAll(principals, 'user-agent')).toBe(true);
    await call('incident_declare', { scope: 'runtime', runtime: 'user-agent' });
    expect((await call('control_get')).stopped).toBe(true);
  });

  it('keeps a global stop after acknowledging a restore', async () => {
    ready();
    await call('stop_all');
    await call('backup_restore', { admin_passphrase: PASS });
    const out = await call('restore_ack', { admin_passphrase: PASS });
    expect(out.stopped).toBe(true);
    expect((await call('control_get')).stopped).toBe(true);
  });

  it('replaces the device key with the recovery code and revokes every grant', async () => {
    ready();
    const out = await call('recover', { recovery_passphrase: 'ABCD-EFGH-IJKL-MNOP-QRST-UVWX' });
    expect(out).toMatchObject({ grants_revoked: 3, handles_invalidated: true });
    expect((await call('grant_list', {})).grants.every((g) => g.status === 'revoked')).toBe(true);
  });

  it('refuses a backup made before the device key was replaced, and names why', async () => {
    ready();
    await call('backup_create');
    await call('recover', { recovery_passphrase: 'ABCD-EFGH-IJKL-MNOP-QRST-UVWX' });
    const e = await rejection(call('backup_restore', { admin_passphrase: PASS }));
    expect([e.error, e.reason]).toEqual(['StateError', 'backup_kms_mismatch']);
    expect(restoreErrorKey(e.reason)).toBe('set.restore.mismatch');
    expect((await call('control_get')).restore_pending).toBe(false);   // nothing was restored
    // a backup made afterwards, as the settings page asks for, restores
    await call('backup_create');
    expect(await call('backup_restore', { admin_passphrase: PASS })).toMatchObject({ restored: true });
    expect(restoreErrorKey('file_dialog_cancelled')).toBe('set.restore.cancelled');
    expect(restoreErrorKey('backup_digest_mismatch')).toBeNull();
  });
});

describe('relay start', () => {
  it('reports why the relay did not start and starts on a retry', async () => {
    backend?.dispose();
    backend = createMockBackend({ latency: 0, initialized: true, relayFails: 2 });
    useMockBackend(backend);
    expect((await call('serve_status')).running).toBe(false);   // the seeded start failed
    const e = await rejection(call('serve_start'));
    expect(e.reason).toBe('serve_exited');
    expect(relayError(e.reason).key).toBe('relay.err.exited');
    expect((await call('serve_start')).running).toBe(true);
  });
});
