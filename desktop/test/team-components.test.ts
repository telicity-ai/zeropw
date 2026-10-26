// @vitest-environment jsdom
import { act, createElement as h, useState, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { call } from '../src/ipc/client';
import type { InvitePreview } from '../src/ipc/contract';
import { Sheet } from '../src/dashboard/Sheet';
import { ConfirmSheet } from '../src/dashboard/Confirm';
import { ListenSetup } from '../src/dashboard/ListenSetup';
import { TeamPage } from '../src/dashboard/Team';
import { JoinStep } from '../src/onboarding/JoinStep';
import { AppContext, type AppApi } from '../src/ui/context';
import { DashContext, type DashApi, type Intent } from '../src/dashboard/context';
import { t } from '../src/copy';
import { TextField } from '../src/ui/fields';

vi.mock('../src/ipc/client', async (original) => ({ ...await original<typeof import('../src/ipc/client')>(), call: vi.fn() }));
const ipc = vi.mocked(call);
const future = () => new Date(Date.now() + 3600_000).toISOString();
const preview = (inviter = 'abcdefghijklmnopqrstuvwxyz'): InvitePreview => ({ inviter, env_id: 'environment', role: 'user', name: 'member', addresses: ['192.168.1.2:47420'], expires_at: future(), expired: false, invite_id: 'invite' });
const app = { field: { ripple: vi.fn(), set: vi.fn(), chipText: vi.fn() }, desktop: true, toast: vi.fn(), announce: vi.fn(), setPill: vi.fn() } as unknown as AppApi;
const dash = { tick: 0, go: vi.fn(), bump: vi.fn(), relay: { run: (fn: () => Promise<unknown>) => fn(), report: vi.fn() } } as unknown as DashApi;
let animationFrames: Map<number, FrameRequestCallback>, frameId: number;
let root: Root, host: HTMLDivElement, shared: boolean;
let requestIncoming: (ref: string, p?: InvitePreview) => void;
let leaveTeamForImport: () => void, returnToTeam: () => void;
function Driver() {
  const [intent, setIntent] = useState<Intent>();
  const [incoming, setIncoming] = useState<{ ref: string; preview: InvitePreview } | null>(null);
  const [showTeam, setShowTeam] = useState(true);
  leaveTeamForImport = () => { setShowTeam(false); setIntent('import'); };
  returnToTeam = () => { setShowTeam(true); setIntent(undefined); };
  requestIncoming = (ref, p = preview()) => { setIncoming({ ref, preview: p }); setIntent('join'); };
  if (!showTeam) return h('div', { id: 'import-page' });
  return h(TeamPage, { intent, onIntent: () => setIntent(undefined), incoming, onIncomingTaken: () => setIncoming(null) });
}
const providers = (child: ReactNode) => h(AppContext, { value: app }, h(DashContext, { value: dash }, child));
async function settle() {
  await act(async () => { await new Promise((r) => setTimeout(r, 10)); });
  // Commit effects first, then deliver the next animation frame deterministically. Real timer
  // scheduling under parallel test load must not decide whether post-render focus has run.
  await act(async () => {
    const pending = [...animationFrames.values()]; animationFrames.clear();
    for (const callback of pending) callback(0);
  });
}
async function render(child: ReactNode = h(Driver)) { await act(async () => root.render(providers(child))); await settle(); }
function button(text: string, within: ParentNode = host) {
  const found = [...within.querySelectorAll<HTMLButtonElement>('button')].find((b) => b.textContent?.trim().replace(/\s*→$/, '') === text);
  if (!found) throw new Error(`Missing button: ${text}`);
  return found;
}
async function click(el: HTMLElement) { await act(async () => el.click()); await settle(); }
async function input(id: string, value: string) {
  const el = host.querySelector<HTMLInputElement>(`#${id}`)!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await settle();
}
async function select(id: string, value: string) {
  const el = host.querySelector<HTMLSelectElement>(`#${id}`)!;
  await act(async () => { el.value = value; el.dispatchEvent(new Event('change', { bubbles: true })); });
  await settle();
}
function deferred<T>() { let resolve!: (v: T) => void, reject!: (e: unknown) => void; const promise = new Promise<T>((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; }
async function invite() {
  await click(button(t('inv.title')));
  await input('inv-name', 'custom member');
  await input('inv-pass', 'synthetic-only');
}
function defaultIpc(command: string): unknown {
  if (command === 'project_list') return { projects: [{ name: 'demo', environments: ['dev'], created_at: '' }] };
  if (command === 'settings_get') return { team_listen: '192.168.1.2:47420', gateway_port: 47380 };
  if (command === 'net_interfaces') return [{ ip: '192.168.1.2', kind: 'lan', name: 'en0' }];
  if (command === 'team_members') { if (!shared) throw { error: 'InvalidInput', reason: 'team_env_not_found' }; return { members: [], env_id: 'environment' }; }
  if (command === 'team_invites') return { invites: [], env_id: 'environment' };
  if (command === 'team_share') { shared = true; return {}; }
  if (command === 'team_invite_create') return { invite_id: 'i', link_ref: 'new-link', inviter: 'abcdefghijklmnopqrstuvwxyz', expires_at: future() };
  if (command === 'team_join') return { project: 'joined', environment: 'dev' };
  if (command === 'team_invite_preview') return { ref: 'preview', preview: preview() };
  return {};
}
beforeEach(() => {
  Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
  animationFrames = new Map(); frameId = 0;
  vi.stubGlobal('requestAnimationFrame', (fn: FrameRequestCallback) => { const id = ++frameId; animationFrames.set(id, fn); return id; });
  vi.stubGlobal('cancelAnimationFrame', (id: number) => animationFrames.delete(id));
  shared = false; dash.tick = 0;
  vi.clearAllMocks();
  ipc.mockImplementation(async (command) => defaultIpc(command) as never);
  host = document.createElement('div'); document.body.append(host); root = createRoot(host);
});
afterEach(async () => { await act(async () => root.unmount()); host.remove(); vi.unstubAllGlobals(); });

describe('invite component confirmation and failure recovery', () => {
  it.each([
    { error: 'Timeout', reason: 'admin_timeout' },
    { error: 'InternalError', reason: 'admin_output_invalid' },
    { error: 'InternalError', reason: 'admin_output_missing' },
    { error: 'IoError', reason: 'admin_wait_failed' },
    { error: 'Unavailable', reason: 'unknown' },
  ])('requires checking state after $reason and prevents repeat mutation', async (failure) => {
    ipc.mockImplementation(async (command) => { if (command === 'team_invite_create') throw failure; return defaultIpc(command) as never; });
    await render(); await invite();
    expect(host.textContent).toContain(t('inv.pre2.note'));
    await click(button(t('inv.shareCreate')));
    expect(host.textContent).toContain(t('inv.unknown'));
    expect(host.textContent).toContain(t('toast.share.done'));
    expect((host.querySelector('#inv-name') as HTMLInputElement).value).toBe('custom member');
    expect((host.querySelector('#inv-pass') as HTMLInputElement).value).toBe('');
    expect(document.activeElement?.getAttribute('role')).toBe('alert');
    expect((host.querySelector('#inv-name') as HTMLInputElement).disabled).toBe(false);
    expect((host.querySelector('#inv-env') as HTMLSelectElement).disabled).toBe(false);
    await click(button(t('inv.recheckState')));
    expect(host.textContent).toContain(t('inv.read.shared', { n: 0 }));
    expect(ipc.mock.calls.filter(([command]) => command === 'team_invite_create')).toHaveLength(1);
  });
  it('does not let delayed sheet autofocus overwrite newer validation focus', async () => {
    vi.useFakeTimers();
    try {
      await act(async () => root.render(providers(h(Sheet, { id: 'focus-race', open: true, title: 'Focus', onClose: vi.fn() },
        h('div', { id: 'early-error', role: 'alert', tabIndex: -1 }, 'Validation error')))));
      const error = host.querySelector<HTMLElement>('#early-error')!;
      error.focus();
      expect(document.activeElement).toBe(error);
      await act(async () => vi.advanceTimersByTimeAsync(60));
      expect(document.activeElement).toBe(error);
    } finally { vi.useRealTimers(); }
  });
  it('rechecks uncertain sharing read-only through read failure, unshared and shared states', async () => {
    let readFails = false;
    ipc.mockImplementation(async (command) => {
      if (command === 'team_share') throw { error: 'Timeout', reason: 'admin_timeout' };
      if (command === 'team_members' && readFails) throw { error: 'IoError', reason: 'state_unavailable' };
      return defaultIpc(command) as never;
    });
    await render(); await invite(); await click(button(t('inv.shareCreate')));
    readFails = true;
    await click(button(t('inv.recheckState')));
    expect(host.textContent).toContain(t('inv.read.failed'));
    readFails = false;
    await click(button(t('inv.recheckState')));
    expect(host.textContent).toContain(t('inv.read.unshared'));
    shared = true;
    await click(button(t('inv.recheckState')));
    expect(host.textContent).toContain(t('inv.read.shared', { n: 0 }));
    expect(ipc.mock.calls.filter(([command]) => command === 'team_share')).toHaveLength(1);
    expect(ipc.mock.calls.filter(([command]) => command === 'team_invite_create')).toHaveLength(0);
  });
  it('clears ConfirmSheet busy ownership after failed reauthentication and permits successful retry', async () => {
    const run = vi.fn().mockRejectedValueOnce({ error: 'AuthFailed', reason: 'admin_reauth_failed' }).mockResolvedValueOnce({});
    const onBusy = vi.fn();
    await render(h(ConfirmSheet, { id: 'confirm', open: true, title: 'Confirm', confirmLabel: 'Confirm', needPass: true, run, onBusy, onClose: vi.fn() }));
    await input('confirm-pass', 'synthetic-wrong');
    await click(button('Confirm'));
    expect(host.textContent).toContain(t('error.auth'));
    expect(onBusy.mock.calls).toEqual([[true], [false]]);
    await input('confirm-pass', 'synthetic-correct');
    await click(button('Confirm'));
    expect(run).toHaveBeenCalledTimes(2);
    expect(run).toHaveBeenLastCalledWith('synthetic-correct');
    expect(onBusy.mock.calls).toEqual([[true], [false], [true], [false]]);
  });
  it('releases team confirmation busy state so a pending link and later page buttons work', async () => {
    const pending = deferred<unknown>();
    ipc.mockImplementation(async (command) => {
      if (command === 'team_share') return pending.promise as never;
      return defaultIpc(command) as never;
    });
    await render(); await click(button(t('inv.pre2.btn')));
    await input('sheet-share-pass', 'synthetic-only');
    await click(button(t('inv.pre2.btn'), host.querySelector('#sheet-share')!));
    await act(async () => requestIncoming('after-share')); await settle();
    expect(host.querySelector('#sheet-join:not(.away)')).toBeNull();
    shared = true;
    await act(async () => pending.resolve({})); await settle();
    expect(host.querySelector('#sheet-join:not(.away)')).not.toBeNull();
    await click(button(t('common.cancel'), host.querySelector('#sheet-join')!));
    await click(button(t('inv.title')));
    expect(host.querySelector('#sheet-invite:not(.away)')).not.toBeNull();
    await click(button(t('common.cancel'), host.querySelector('#sheet-invite')!));
    await click(button(t('join.title')));
    expect(host.querySelector('#sheet-join:not(.away)')).not.toBeNull();
  });
  it('preserves name and role on share success then known invite rejection, and announces grant staleness', async () => {
    ipc.mockImplementation(async (command) => { if (command === 'team_invite_create') throw { error: 'AuthFailed', reason: 'admin_reauth_failed' }; return defaultIpc(command) as never; });
    await render(); await invite();
    const admin = host.querySelector<HTMLInputElement>('input[name="inv-role"][value="admin"]')!;
    await click(admin);
    await click(button(t('inv.shareCreate')));
    expect((host.querySelector('#inv-name') as HTMLInputElement).value).toBe('custom member');
    expect(admin.checked).toBe(true);
    expect(app.announce).toHaveBeenCalledWith(t('toast.share.done'));
    expect(host.textContent).toContain(t('toast.share.done'));
    expect(host.textContent).toContain(t('inv.failedShared'));
    expect(host.textContent).toContain(t('inv.pass.again'));
    expect(host.textContent).not.toContain(t('error.auth'));
    expect(button(t('inv.create'))).toBeTruthy();
  });
  it('defers a deep link during invite creation and guards two submissions in the same tick', async () => {
    const pending = deferred<unknown>();
    ipc.mockImplementation(async (command) => command === 'team_invite_create' ? pending.promise as never : defaultIpc(command) as never);
    await render(); await invite();
    const submit = button(t('inv.shareCreate'));
    await act(async () => { submit.click(); submit.click(); }); await settle();
    await act(async () => requestIncoming('next-team')); await settle();
    expect(host.querySelector('#sheet-invite:not(.away)')).not.toBeNull();
    expect(host.querySelector('#sheet-join:not(.away)')).toBeNull();
    await act(async () => pending.resolve(defaultIpc('team_invite_create'))); await settle();
    expect(host.querySelector('#sheet-invite:not(.away)')).not.toBeNull();
    expect(host.querySelector('#sheet-join:not(.away)')).toBeNull();
    expect(ipc).not.toHaveBeenCalledWith('onetime_discard', { ref: 'new-link' });
    await click(button(t('inv.done')));
    expect(host.querySelector('#sheet-join:not(.away)')).not.toBeNull();
    expect(ipc.mock.calls.filter(([command]) => command === 'team_invite_create')).toHaveLength(1);
  });
  it('surfaces a deferred incoming link after import navigation replaced the transient intent', async () => {
    await render(); await invite();
    await act(async () => requestIncoming('queued-before-import')); await settle();
    expect(host.querySelector('#sheet-join:not(.away)')).toBeNull();
    await act(async () => leaveTeamForImport()); await settle();
    expect(host.querySelector('#import-page')).not.toBeNull();
    await act(async () => returnToTeam()); await settle();
    expect(host.querySelector('#sheet-join:not(.away)')).not.toBeNull();
    expect(ipc).not.toHaveBeenCalledWith('onetime_discard', { ref: 'queued-before-import' });
    expect(ipc.mock.calls.filter(([command]) => command === 'team_join')).toHaveLength(0);
    await click(button(t('team.join.confirm')));
    expect(ipc).toHaveBeenCalledWith('team_join', expect.objectContaining({ ref: 'queued-before-import' }));
  });
  it('maps an already-shared rejection and reloads without silently creating an invite', async () => {
    ipc.mockImplementation(async (command) => {
      if (command === 'team_share') { shared = true; throw { error: 'InvalidInput', reason: 'team_env_already_shared' }; }
      return defaultIpc(command) as never;
    });
    await render(); await invite(); await click(button(t('inv.shareCreate')));
    expect(host.textContent).toContain(t('team.err.shared'));
    expect(host.textContent).not.toContain(t('error.generic'));
    expect((host.querySelector('#inv-name') as HTMLInputElement).value).toBe('custom member');
    expect(ipc.mock.calls.filter(([command]) => command === 'team_invite_create')).toHaveLength(0);
    await input('inv-pass', 'synthetic-again');
    await click(button(t('inv.create')));
    expect(ipc.mock.calls.filter(([command]) => command === 'team_share')).toHaveLength(1);
    expect(ipc.mock.calls.filter(([command]) => command === 'team_invite_create')).toHaveLength(1);
  });
  it('discards an invite link delivered after unmount', async () => {
    const pending = deferred<unknown>();
    ipc.mockImplementation(async (command) => command === 'team_invite_create' ? pending.promise as never : defaultIpc(command) as never);
    await render(); await invite(); await click(button(t('inv.shareCreate')));
    await act(async () => root.render(providers(h('div'))));
    await act(async () => pending.resolve(defaultIpc('team_invite_create'))); await settle();
    expect(ipc).toHaveBeenCalledWith('onetime_discard', { ref: 'new-link' });
    expect(app.toast).toHaveBeenCalledWith(t('inv.late', { env: 'demo/dev' }));
    expect(ipc.mock.calls.filter(([command]) => command === 'team_invite_create')).toHaveLength(1);
  });
  it('shows read failure and retries loading without authorizing an unknown share', async () => {
    let fail = true;
    ipc.mockImplementation(async (command) => { if (command === 'team_members' && fail) throw { error: 'IoError', reason: 'state_corrupt' }; return defaultIpc(command) as never; });
    await render(); await click(button(t('inv.title')));
    expect(host.textContent).toContain(t('error.load'));
    expect(button(t('inv.retryRead'))).toBeTruthy();
    fail = false;
    await click(button(t('inv.retryRead')));
    expect(button(t('inv.shareCreate'))).toBeTruthy();
    expect(ipc.mock.calls.filter(([command]) => command === 'team_share')).toHaveLength(0);
  });
});

describe('combined upstream recovery and UX behavior', () => {
  it('preserves child-field errorFor(false) and releases confirmation busy state for retry', async () => {
    const run = vi.fn().mockRejectedValueOnce({ error: 'InvalidInput', reason: 'cli_program_not_found' }).mockResolvedValueOnce({});
    const busy = vi.fn();
    function FieldErrorConfirm() {
      const [error, setError] = useState<string | null>(null);
      return h(ConfirmSheet, {
        id: 'child-confirm', open: true, title: 'Confirm', confirmLabel: 'Confirm', run, onBusy: busy, onClose: vi.fn(),
        errorFor: () => { setError(t('conn.cli.err.notFound')); return false; },
      }, h(TextField, { id: 'child-path', label: 'Path', value: '/synthetic/missing', onChange: vi.fn(), error }));
    }
    await render(h(FieldErrorConfirm));
    await click(button('Confirm'));
    expect(host.querySelector('#child-path-err')?.textContent).toBe(t('conn.cli.err.notFound'));
    expect(host.textContent).not.toContain(t('error.generic'));
    expect(busy.mock.calls).toEqual([[true], [false]]);
    await click(button('Confirm'));
    expect(run).toHaveBeenCalledTimes(2);
    expect(busy.mock.calls).toEqual([[true], [false], [true], [false]]);
  });
  it('keeps teams readable and settings reset guidance available when settings and team mapping are damaged', async () => {
    shared = true;
    ipc.mockImplementation(async (command) => {
      if (command === 'settings_get') throw { error: 'StateError', reason: 'settings_corrupt' };
      if (command === 'project_list') return { ...defaultIpc(command) as object, team_environments_error: 'team_state_corrupt' } as never;
      return defaultIpc(command) as never;
    });
    await render();
    expect((host.querySelector('#team-env') as HTMLSelectElement).value).toBe('demo/dev');
    expect(host.textContent).toContain(t('team.envs.err'));
    expect(host.textContent).toContain(t('team.members'));
    expect(host.textContent).toContain(t('listen.err.settings'));
    await click(button(t('listen.toSettings')));
    expect(dash.go).toHaveBeenCalledWith('settings');
    await invite();
    await click(button(t('inv.pre1.btn'), host.querySelector('#sheet-invite')!));
    expect(host.querySelector('#sheet-invite')?.textContent).toContain(t('listen.err.settings'));
    expect((host.querySelector('#inv-name') as HTMLInputElement).value).toBe('custom member');
    expect(ipc.mock.calls.filter(([command]) => command === 'settings_set' || command === 'team_invite_create')).toHaveLength(0);
  });
  it('routes a joined team with corrupt settings to reset instead of enabling access or misreporting join failure', async () => {
    let joined = false;
    ipc.mockImplementation(async (command) => {
      if (command === 'team_join') { joined = true; return { project: 'joined', environment: 'dev' } as never; }
      if (command === 'settings_get' && joined) throw { error: 'StateError', reason: 'settings_corrupt' };
      return defaultIpc(command) as never;
    });
    await render(); await act(async () => requestIncoming('corrupt-after-join')); await settle();
    await click(button(t('team.join.confirm')));
    const sheet = host.querySelector('#sheet-join')!;
    expect(sheet.textContent).toContain(t('listen.err.settings'));
    expect(sheet.querySelector('#join-listen-port')).toBeNull();
    await click(button(t('listen.toSettings'), sheet));
    expect(dash.go).toHaveBeenCalledWith('settings');
    expect(ipc.mock.calls.filter(([command]) => command === 'team_join')).toHaveLength(1);
    expect(ipc.mock.calls.filter(([command]) => command === 'settings_set')).toHaveLength(0);
  });
  it('loads the environment actually shown after a selected environment disappears during reload', async () => {
    let environments = ['dev', 'staging'];
    ipc.mockImplementation(async (command) => command === 'project_list'
      ? { projects: [{ name: 'demo', environments, created_at: '' }] } as never
      : defaultIpc(command) as never);
    await render();
    await select('team-env', 'demo/staging');
    expect(ipc).toHaveBeenCalledWith('team_members', { env: 'demo/staging' });
    environments = ['dev']; dash.tick++;
    await render();
    expect((host.querySelector('#team-env') as HTMLSelectElement).value).toBe('demo/dev');
    expect(ipc.mock.calls.filter(([command]) => command === 'team_members').at(-1)).toEqual(['team_members', { env: 'demo/dev' }]);
  });
  it.each(['success', 'uncertain'] as const)('keeps the submitted invite target after list fallback during a delayed %s outcome', async (outcome) => {
    const pending = deferred<unknown>();
    let mapped = true;
    shared = true;
    ipc.mockImplementation(async (command) => {
      if (command === 'project_list') return {
        projects: [{ name: 'demo', environments: ['dev'], created_at: '' }],
        team_environments: mapped ? [{ project: 'joined', environment: 'shared', env_id: 'team-A' }] : [],
        ...(mapped ? {} : { team_environments_error: 'mapping_unavailable' }),
      } as never;
      if (command === 'team_invite_create') return pending.promise as never;
      return defaultIpc(command) as never;
    });
    await render(); await select('team-env', 'joined/shared'); await invite();
    await click(button(t('inv.create')));
    mapped = false; dash.tick++;
    await render();
    expect((host.querySelector('#team-env') as HTMLSelectElement).value).toBe('demo/dev');
    const target = host.querySelector<HTMLSelectElement>('#inv-env')!;
    expect(target.value).toBe('joined/shared');
    expect(target.selectedOptions[0]?.textContent).toContain(t('set.listen.unlisted'));
    if (outcome === 'success') {
      await act(async () => pending.resolve(defaultIpc('team_invite_create'))); await settle();
      expect(target.value).toBe('joined/shared');
      await click(button(t('inv.revoke'), host.querySelector('#sheet-invite')!));
      expect(ipc).toHaveBeenCalledWith('team_revoke_invite', { env: 'joined/shared', invite_id: 'i' });
    } else {
      await act(async () => pending.reject({ error: 'Timeout', reason: 'admin_timeout' })); await settle();
      const before = ipc.mock.calls.length;
      await click(button(t('inv.recheckState')));
      const recheck = ipc.mock.calls.slice(before);
      expect(recheck).toContainEqual(['team_members', { env: 'joined/shared' }]);
      expect(recheck).toContainEqual(['team_invites', { env: 'joined/shared' }]);
      expect(target.value).toBe('joined/shared');
    }
    expect(ipc.mock.calls.filter(([command]) => command === 'team_invite_create')).toHaveLength(1);
    expect(ipc).toHaveBeenCalledWith('team_invite_create', expect.objectContaining({ env: 'joined/shared' }));
  });
  it('keeps an unlisted selected network address visible while disclosure repair stays open', async () => {
    const props = { id: 'unlisted', onDone: vi.fn() };
    await render(h(ListenSetup, { ...props, interfaces: [{ ip: '10.0.0.1', kind: 'vpn', name: 'utun0' }] }));
    const details = host.querySelector('#unlisted-if')!.closest('details')!;
    await click(details.querySelector('summary')!);
    await render(h(ListenSetup, { ...props, interfaces: [{ ip: '192.168.1.2', kind: 'lan', name: 'en0' }] }));
    const picker = host.querySelector<HTMLSelectElement>('#unlisted-if')!;
    expect(picker.value).toBe('10.0.0.1');
    expect([...picker.options].map((o) => o.value)).toEqual(['10.0.0.1', '192.168.1.2']);
    expect(picker.options[0]?.textContent).toContain(t('set.listen.unlisted'));
    expect(details.open).toBe(true);
    await select('unlisted-if', '192.168.1.2');
    expect(details.open).toBe(true);
  });
});

describe('progressive network details preserve repair and explicit expansion', () => {
  it('keeps invite network details open while correcting a port and reopens repeated validation errors', async () => {
    ipc.mockImplementation(async (command) => command === 'settings_get' ? { team_listen: null, gateway_port: 47380 } as never : defaultIpc(command) as never);
    await render(); await click(button(t('inv.title')));
    const details = host.querySelector('#inv-port')!.closest('details')!;
    expect(details.open).toBe(false);
    await click(details.querySelector('summary')!);
    expect(details.open).toBe(true);
    await input('inv-port', '0');
    await click(button(t('inv.pre1.btn'), host.querySelector('#sheet-invite')!));
    expect(document.activeElement?.id).toBe('inv-port');
    await click(details.querySelector('summary')!);
    expect(details.open).toBe(false);
    await click(button(t('inv.pre1.btn'), host.querySelector('#sheet-invite')!));
    expect(details.open).toBe(true);
    await input('inv-port', '1');
    expect(details.open).toBe(true);
    expect(document.activeElement?.id).toBe('inv-port');
    expect(ipc.mock.calls.filter(([command]) => command === 'settings_set')).toHaveLength(0);
  });
  it('keeps ListenSetup port repair visible after the error clears', async () => {
    await render(h(ListenSetup, { id: 'repair', interfaces: [{ ip: '192.168.1.2', kind: 'lan', name: 'en0' }], onDone: vi.fn() }));
    const details = host.querySelector('#repair-port')!.closest('details')!;
    expect(details.open).toBe(false);
    await click(details.querySelector('summary')!);
    await input('repair-port', '0');
    await click(button(t('inv.pre1.btn')));
    expect(document.activeElement?.id).toBe('repair-port');
    const retry = button(t('inv.pre1.btn'));
    retry.focus();
    await click(retry); // same invalid value, details already open: no state transition to drive focus
    expect(document.activeElement?.id).toBe('repair-port');
    await click(details.querySelector('summary')!);
    expect(details.open).toBe(false);
    await click(button(t('inv.pre1.btn')));
    expect(details.open).toBe(true);
    await input('repair-port', '1');
    expect(details.open).toBe(true);
    expect(document.activeElement?.id).toBe('repair-port');
  });
  it('applies async interface defaults only before the user chooses disclosure state', async () => {
    const props = { id: 'defaults', onDone: vi.fn() };
    await render(h(ListenSetup, { ...props, interfaces: [] }));
    const details = host.querySelector('#defaults-port')!.closest('details')!;
    expect(details.open).toBe(true);
    const one = [{ ip: '192.168.1.2', kind: 'lan' as const, name: 'en0' }];
    await render(h(ListenSetup, { ...props, interfaces: one }));
    expect(details.open).toBe(false);
    await click(details.querySelector('summary')!);
    expect(details.open).toBe(true);
    await render(h(ListenSetup, { ...props, interfaces: [...one, { ip: '10.0.0.1', kind: 'vpn', name: 'utun0' }] }));
    expect(details.open).toBe(true);
    await click(details.querySelector('summary')!);
    await render(h(ListenSetup, { ...props, interfaces: one }));
    expect(details.open).toBe(false);
    await render(h(ListenSetup, { ...props, key: 'editing', interfaces: [] }));
    await input('defaults-port', '1234'); // editing before interfaces load also owns the open state
    await render(h(ListenSetup, { ...props, key: 'editing', interfaces: one }));
    expect(host.querySelector('#defaults-port')!.closest('details')!.open).toBe(true);
  });
});

describe('join component ownership, busy intents and focus', () => {
  it('does not join the previous invite while its replacement preview is delayed', async () => {
    const pending = deferred<unknown>();
    await render(); await act(async () => requestIncoming('old')); await settle();
    ipc.mockImplementation(async (command) => command === 'team_invite_preview' ? pending.promise as never : defaultIpc(command) as never);
    await input('join-link', 'zeropw://join#' + 'a'.repeat(488));
    await click(button(t('team.join.confirm')));
    expect(ipc.mock.calls.filter(([command]) => command === 'team_join')).toHaveLength(0);
    await act(async () => pending.resolve({ ref: 'new', preview: preview() })); await settle();
    await click(button(t('team.join.confirm')));
    expect(ipc).toHaveBeenCalledWith('team_join', expect.objectContaining({ ref: 'new' }));
  });
  it('preserves a custom alias on replacement and focuses invalid alias after details opens', async () => {
    await render(); await act(async () => requestIncoming('old')); await settle();
    await input('join-local', 'custom/dev');
    await input('join-link', 'zeropw://join#' + 'a'.repeat(488));
    expect((host.querySelector('#join-local') as HTMLInputElement).value).toBe('custom/dev');
    await input('join-local', 'invalid');
    await click(button(t('team.join.confirm')));
    const details = host.querySelector('#join-local')!.closest('details')!;
    expect(details.open).toBe(true);
    expect(document.activeElement?.id).toBe('join-local');
    await click(details.querySelector('summary')!);
    expect(details.open).toBe(false);
    await click(button(t('team.join.confirm'))); // the same error must reopen it again
    expect(details.open).toBe(true);
    await input('join-local', 'invalidx'); // one repair character clears the error, not the disclosure
    expect(details.open).toBe(true);
    expect(document.activeElement?.id).toBe('join-local');
  });
  it('does not replay stale join-error focus while toggling or repairing an invalid alias', async () => {
    ipc.mockImplementation(async (command) => {
      if (command === 'team_join') throw { error: 'IoError', reason: 'connection_failed' };
      return defaultIpc(command) as never;
    });
    await render(); await act(async () => requestIncoming('retryable')); await settle();
    await click(button(t('team.join.confirm')));
    expect(document.activeElement?.id).toBe('join-link');
    const details = host.querySelector('#join-local')!.closest('details')!;
    const summary = details.querySelector('summary')!;
    summary.focus();
    await click(summary);
    expect(details.open).toBe(true);
    expect(document.activeElement).toBe(summary);
    await input('join-local', 'invalid');
    await click(button(t('team.join.confirm')));
    expect(document.activeElement?.id).toBe('join-local');
    await input('join-local', 'invalidx');
    expect(details.open).toBe(true);
    expect(document.activeElement?.id).toBe('join-local');
  });
  it('defers a new deep link while joining and does not let the old completion close it', async () => {
    const pending = deferred<unknown>();
    ipc.mockImplementation(async (command) => command === 'team_join' ? pending.promise as never : defaultIpc(command) as never);
    await render(); await act(async () => requestIncoming('old')); await settle();
    await click(button(t('team.join.confirm')));
    await act(async () => requestIncoming('new', preview('zyxwvutsrqponmlkjihgfedcba'))); await settle();
    expect(ipc).not.toHaveBeenCalledWith('onetime_discard', { ref: 'new' });
    await act(async () => pending.resolve({ project: 'joined', environment: 'dev' })); await settle();
    expect(host.querySelector('#sheet-join:not(.away)')).not.toBeNull();
    await click(button(t('team.join.confirm')));
    expect(ipc.mock.calls.filter(([command]) => command === 'team_join').at(-1)).toEqual(['team_join', expect.objectContaining({ ref: 'new' })]);
  });
  it('honors core-expired previews and returns error focus to the enabled link input after failed join', async () => {
    const p = preview(); p.expires_at = new Date(Date.now() - 301_000).toISOString(); p.expired = true;
    await render(); await act(async () => requestIncoming('expired', p)); await settle();
    await click(button(t('team.join.confirm')));
    expect(ipc.mock.calls.filter(([command]) => command === 'team_join')).toHaveLength(0);
    expect(document.activeElement?.id).toBe('join-link');
    await act(async () => requestIncoming('current')); await settle();
    ipc.mockImplementation(async (command) => { if (command === 'team_join') throw { error: 'IoError', reason: 'connection_failed' }; return defaultIpc(command) as never; });
    await click(button(t('team.join.confirm')));
    expect(document.activeElement?.id).toBe('join-link');
    expect((document.activeElement as HTMLInputElement).disabled).toBe(false);
  });
  it('retains a retryable link error and aria-invalid while editing the unrelated alias', async () => {
    ipc.mockImplementation(async (command) => {
      if (command === 'team_join') throw { error: 'IoError', reason: 'connection_failed' };
      return defaultIpc(command) as never;
    });
    await render(); await act(async () => requestIncoming('retryable-held')); await settle();
    await click(button(t('team.join.confirm')));
    const link = host.querySelector<HTMLInputElement>('#join-link')!;
    expect(link.getAttribute('aria-invalid')).toBe('true');
    expect(host.textContent).toContain(t('join.err.failed'));
    const local = host.querySelector<HTMLInputElement>('#join-local')!;
    await click(local.closest('details')!.querySelector('summary')!);
    local.focus();
    await input('join-local', 'custom/dev');
    expect(document.activeElement).toBe(local);
    expect(link.getAttribute('aria-invalid')).toBe('true');
    expect(host.textContent).toContain(t('join.err.failed'));
    expect(ipc.mock.calls.filter(([command]) => command === 'team_join')).toHaveLength(1);
  });
  it.each(['within-core-skew', 'browser-unparseable'] as const)('defers the %s expiry decision to core in both join paths', async (format) => {
    const p = preview();
    p.expires_at = format === 'within-core-skew' ? new Date(Date.now() - 120_000).toISOString() : 'core-only-timestamp';
    p.expired = false; // the trusted preview, not browser date parsing, owns this decision
    await render(); await act(async () => requestIncoming('core-authoritative', p)); await settle();
    await click(button(t('team.join.confirm')));
    expect(ipc).toHaveBeenCalledWith('team_join', expect.objectContaining({ ref: 'core-authoritative' }));
    const next = vi.fn();
    await render(h(JoinStep, { frame: { active: true, cls: 'in' as const }, sectionRef: null, incoming: { ref: 'onboarding-core', preview: p }, onBack: vi.fn(), onNext: next }));
    await click(button(t('join.next')));
    expect(next).toHaveBeenCalledWith(expect.objectContaining({ ref: 'onboarding-core' }));
  });
  it.each(['on', 'off', 'unavailable'] as const)('retains an in-flight ref across unmount and announces late success with listener %s', async (listener) => {
    const pending = deferred<unknown>();
    let completing = false;
    ipc.mockImplementation(async (command) => {
      if (command === 'team_join') return pending.promise as never;
      if (command === 'settings_get' && completing) {
        if (listener === 'unavailable') throw { error: 'IoError', reason: 'settings_unavailable' };
        return { team_listen: listener === 'on' ? '192.168.1.2:47420' : null, gateway_port: 47380 } as never;
      }
      return defaultIpc(command) as never;
    });
    await render(); await act(async () => requestIncoming('in-flight')); await settle();
    await click(button(t('team.join.confirm')));
    await act(async () => root.render(providers(h('div'))));
    expect(ipc).not.toHaveBeenCalledWith('onetime_discard', { ref: 'in-flight' });
    completing = true;
    await act(async () => pending.resolve({ project: 'joined', environment: 'dev' })); await settle();
    expect(app.toast).toHaveBeenCalledWith(t(listener === 'on' ? 'toast.join.done' : 'toast.join.needListen'));
    expect(ipc).not.toHaveBeenCalledWith('onetime_discard', { ref: 'in-flight' }); // success consumes it in core
  });
  it('reports late join failure and discards the retained ref only after the request settles', async () => {
    const pending = deferred<unknown>();
    ipc.mockImplementation(async (command) => command === 'team_join' ? pending.promise as never : defaultIpc(command) as never);
    await render(); await act(async () => requestIncoming('in-flight')); await settle();
    await click(button(t('team.join.confirm')));
    await act(async () => root.render(providers(h('div'))));
    expect(ipc).not.toHaveBeenCalledWith('onetime_discard', { ref: 'in-flight' });
    await act(async () => pending.reject({ error: 'IoError', reason: 'connection_failed' })); await settle();
    expect(app.toast).toHaveBeenCalledWith(t('join.err.failed'), 'warn');
    expect(ipc).toHaveBeenCalledWith('onetime_discard', { ref: 'in-flight' });
  });
  it('cleans pending preview after unmount in onboarding and focuses an invalid custom alias', async () => {
    const next = vi.fn();
    const props = { frame: { active: true, cls: 'in' as const }, sectionRef: null, incoming: { ref: 'first', preview: preview() }, onBack: vi.fn(), onNext: next };
    await render(h(JoinStep, props));
    await input('ob-join-local', 'bad');
    await click(button(t('join.next')));
    expect(document.activeElement?.id).toBe('ob-join-local');
    const retry = button(t('join.next'));
    retry.focus();
    await click(retry); // identical invalid alias while already open must still focus its field
    expect(document.activeElement?.id).toBe('ob-join-local');
    const details = host.querySelector('#ob-join-local')!.closest('details')!;
    await click(details.querySelector('summary')!);
    expect(details.open).toBe(false);
    await click(button(t('join.next')));
    expect(details.open).toBe(true);
    await input('ob-join-local', 'badx');
    expect(details.open).toBe(true);
    expect(document.activeElement?.id).toBe('ob-join-local');
    const pending = deferred<unknown>();
    ipc.mockImplementation(async (command) => command === 'team_invite_preview' ? pending.promise as never : defaultIpc(command) as never);
    await input('ob-join-link', 'zeropw://join#' + 'a'.repeat(488));
    await act(async () => root.render(providers(h('div'))));
    await act(async () => pending.resolve({ ref: 'late-preview', preview: preview() })); await settle();
    expect(ipc).toHaveBeenCalledWith('onetime_discard', { ref: 'late-preview' });
    expect(next).not.toHaveBeenCalled();
  });
});
