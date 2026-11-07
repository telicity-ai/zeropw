// @vitest-environment jsdom
// 내 Mac with a stubbed core: plain state words per Mac (conflict and unsupported included, a
// connection alone never reading as synced), server enrolment, making a pairing code that only
// leaves through onetime_* and approving the request it brings with a passphrase, and the
// joining Mac's paste, preview, wait and cancel. Synthetic values only.
import { act, createElement as h } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { t } from '../src/copy';
import { call } from '../src/ipc/client';
import type { DeviceEnvView, DevicesOverview, LinkStatus } from '../src/ipc/contract';
import { encodePairingCode } from '../src/lib/pairing';
import { ShellContext, type ShellApi } from '../src/app/shell';
import { AppContext, type AppApi } from '../src/ui/app';
import { DevicesPage } from '../src/screens/devices/DevicesPage';
import { PAIR_POLL_MS } from '../src/screens/devices/usePairJoin';
import { REQUESTS_POLL_MS } from '../src/screens/devices/AddMacDialog';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
vi.mock('../src/ipc/client', async (original) => ({ ...await original<typeof import('../src/ipc/client')>(), call: vi.fn(), on: vi.fn(async () => () => undefined) }));
const ipc = vi.mocked(call);

const SELF = 'saaaaaaaaaaaaaaaaaaaaaaaaa';
const MAC_B = 'fbbbbbbbbbbbbbbbbbbbbbbbbb';
const MAC_C = 'fccccccccccccccccccccccccc';
const MAC_D = 'fddddddddddddddddddddddddd';
const MAC_N = 'fnnnnnnnnnnnnnnnnnnnnnnnnn';
const OWN_LINK = 'oooooooooooooooooooooooooo';
const LINK_B = 'llllllllllllllllllllllllll';
const LINK_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaa';
const PASS = 'synthetic-admin-pass';
const CODE_TEXT_SECRET = 'zplt_synthetic_token';

const app: AppApi = { desktop: true, toast: vi.fn(), announce: vi.fn(), locale: 'ko', language: 'system', setLanguage: async () => undefined };
let shell: ShellApi;
let root: Root, host: HTMLDivElement;
let handlers: Record<string, (input: never) => unknown>;
const calls = (name: string) => ipc.mock.calls.filter(([c]) => c === name).map(([, input]) => input as Record<string, unknown>);

const linkStatus = (over: Partial<LinkStatus> = {}): LinkStatus => ({
  available: true, running: true, enrolled: true, revoked: false, device_id: OWN_LINK, online: true, service: 'https://link.example.org',
  service_host: 'link.example.org', default_service: 'https://link.example.org', device_name: 'this mac', problem: null,
  peers: [{ device_id: LINK_B, name: 'studio', online: true, revoked: false, path: 'relay-tls', rtt_ms: 31, last_error: null }], ...over,
});
const peer = (fingerprint: string, over: Record<string, unknown> = {}) => ({
  fingerprint, name: 'x', state: 'up_to_date', session: true, transport: 'link', last_contact_at: '2026-11-07T00:00:00Z', next_attempt_at: null, last_error: null, ...over,
});
const envView = (env: string, fp: string, conflicts: number, p: Record<string, unknown>): DeviceEnvView => ({
  env, members: { env_id: env, members: [{ fingerprint: fp, name: 'x', role: 'admin', status: 'active', owner: false }] },
  sync: { env_id: env, self: SELF, serve_updated_at: null, conflicts, peers: [peer(fp, p) as never] },
});
const overview = (over: Partial<DevicesOverview> = {}): DevicesOverview => ({
  self_fingerprint: SELF, link: linkStatus(), link_devices: [],
  devices: [
    { fingerprint: MAC_B, link_device_id: LINK_B, name: 'studio', envs: ['personal/main'], added_at: 1 },
    { fingerprint: MAC_C, link_device_id: null, name: 'laptop', envs: ['work/dev'], added_at: 2 },
    { fingerprint: MAC_D, link_device_id: null, name: 'old mini', envs: ['work/prod'], added_at: 3 },
    { fingerprint: MAC_N, link_device_id: null, name: 'linked only now', envs: ['work/stage'], added_at: 4 },
  ],
  envs: [
    envView('personal/main', MAC_B, 0, {}),
    envView('work/dev', MAC_C, 2, { state: 'syncing' }),
    envView('work/prod', MAC_D, 0, { state: 'retrying', session: false, last_error: 'team_peer_feature_unsupported' }),
    envView('work/stage', MAC_N, 0, { state: 'never_connected', session: true }),
  ],
  ...over,
});

async function flush(ms = 20) { await act(async () => { await vi.advanceTimersByTimeAsync(ms); }); }
async function render() {
  await act(async () => root.render(h(AppContext, { value: app }, h(ShellContext, { value: shell }, h(DevicesPage, {})))));
  await flush();
}
function button(text: string, within: ParentNode = document.body) {
  const found = [...within.querySelectorAll<HTMLButtonElement>('button')].find((b) => b.getAttribute('aria-label') === text || b.textContent?.trim() === text || b.querySelector('.mac-connect-text > span')?.textContent === text);
  if (!found) throw new Error(`Missing button: ${text}`);
  return found;
}
function field(label: string, within: ParentNode = document.body): HTMLInputElement {
  const l = [...within.querySelectorAll('label')].find((x) => x.textContent?.trim() === label);
  const el = l ? document.getElementById(l.htmlFor) : null;
  if (!el) throw new Error(`Missing field: ${label}`);
  return el as HTMLInputElement;
}
async function click(el: HTMLElement) { await act(async () => el.click()); await flush(); }
async function connectAction(label: string) {
  await click(button(t('mac.connect'), host));
  return button(label, host.querySelector<HTMLElement>('[role="menu"]')!);
}
async function type(el: HTMLInputElement, value: string) {
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await flush();
}
const dialog = (id: string) => document.getElementById(id)!;
const rowText = (name: string) => [...host.querySelectorAll('button[data-mac]')].find((r) => r.textContent?.includes(name))?.textContent ?? '';

beforeEach(() => {
  vi.useFakeTimers();
  host = document.createElement('div');
  document.body.append(host);
  root = createRoot(host);
  vi.clearAllMocks();
  handlers = {};
  shell = {
    route: { page: 'devices' }, go: vi.fn(), clearIntent: vi.fn(), tick: 0, activity: 0, bump: vi.fn(),
    control: { stopped: false, restore_pending: false, incident_open: false },
    serve: { running: true, url: 'http://127.0.0.1:47380', pid: 1, team_listen: null }, setControl: vi.fn(), setServe: vi.fn(),
    relay: { busy: false, problem: null, start: async () => true, run: (task) => task(), report: vi.fn(), teamListen: null, offerListenOff: false, confirmListenOff: vi.fn() },
    vault: { data: { secrets: [], listing: { projects: [{ name: 'personal', environments: ['main'], created_at: '' }, { name: 'work', environments: ['dev'], created_at: '' }] } }, error: null, loading: false, reload: vi.fn() },
    envFile: null, takeEnvFile: vi.fn(), invite: null, takeInvite: vi.fn(), lock: vi.fn(), narrow: { rail: false, single: false },
  };
  ipc.mockImplementation((async (name: string, inputValue?: unknown) => {
    const handler = handlers[name];
    if (handler) return handler(inputValue as never);
    if (name === 'devices_overview') return overview();
    if (name === 'secure_view') return { protected: false };
    if (name === 'onetime_discard') return undefined;
    throw { error: 'Internal', reason: 'unexpected_' + name };
  }) as never);
});
afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
  document.body.querySelectorAll('[data-dialog-layer]').forEach((d) => d.remove());
  vi.useRealTimers();
});

describe('Mac list', () => {
  it('says each state in plain words; a connection alone is not "synced"', async () => {
    await render();
    expect(rowText('studio')).toContain(t('mac.st.up_to_date'));
    expect(rowText('laptop')).toContain(t('mac.st.conflict'));
    expect(rowText('old mini')).toContain(t('mac.st.unsupported'));
    // a session with a peer that never synced reads as connecting, never as up to date
    expect(rowText('linked only now')).toContain(t('mac.st.connected'));
    expect(rowText('linked only now')).not.toContain(t('mac.st.up_to_date'));
    // conflicts point to the alerts
    await click(button(t('mac.conflict.go'), host));
    expect(shell.go).toHaveBeenCalledWith('activity', { view: 'alerts' });
  });

  it('keeps how a Mac is connected under the advanced diagnostics only', async () => {
    await render();
    const row = [...host.querySelectorAll<HTMLElement>('button[data-mac]')].find((r) => r.textContent?.includes('studio'))!;
    await click(row);
    const outsideBefore = host.cloneNode(true) as HTMLElement;
    outsideBefore.querySelectorAll('details').forEach((d) => d.remove());
    expect(outsideBefore.textContent).not.toMatch(/relay-/i);
    const details = [...host.querySelectorAll<HTMLDetailsElement>('details.more')].find((d) => d.querySelector('summary')?.textContent?.includes(t('mac.diag')))!;
    await act(async () => { details.open = true; details.dispatchEvent(new Event('toggle')); });
    expect(details.textContent).toContain('relay-tls');
    const outside = host.cloneNode(true) as HTMLElement;
    outside.querySelectorAll('details').forEach((d) => d.remove());
    expect(outside.textContent).not.toMatch(/ICE|TURN|STUN|allocation|candidate|relay-|zpl:|link_/i);
  });

  it('blocks adding a Mac until this Mac is enrolled, and enrols with the code only', async () => {
    handlers.devices_overview = () => overview({ link: linkStatus({ enrolled: false, device_id: null, online: false, peers: [] }), devices: [], envs: [] });
    handlers.link_enroll = () => linkStatus();
    await render();
    expect(host.textContent).toContain(t('mac.enroll.title'));
    const add = await connectAction(t('mac.add'));
    expect(add.getAttribute('aria-disabled')).toBe('true');
    await click(add);
    expect(document.getElementById('dlg-mac-add')).toBeNull();
    expect(calls('pairing_create')).toHaveLength(0);
    const code = field(t('mac.enroll.code'), host);
    await type(code, 'ZPL-not-a-code');
    await click(button(t('mac.enroll.go'), host));
    expect(host.textContent).toContain(t('devices.enroll.err.code'));
    expect(calls('link_enroll')).toHaveLength(0);
    const valid = 'ZPL-' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    await type(field(t('mac.enroll.code'), host), valid);
    await click(button(t('mac.enroll.go'), host));
    expect(calls('link_enroll')).toEqual([{ invite_code: valid, name: 'this mac' }]);
    expect(app.toast).toHaveBeenCalledWith(t('mac.toast.enrolled'), 'ok');
  });

  it('maps enrolment refusals to plain words and clears the code', async () => {
    handlers.devices_overview = () => overview({ link: linkStatus({ enrolled: false, device_id: null, peers: [] }), devices: [], envs: [] });
    handlers.link_enroll = () => { throw { error: 'Unavailable', reason: 'link_service_unavailable' }; };
    await render();
    await type(field(t('mac.enroll.code'), host), 'ZPL' + 'A'.repeat(26));
    await click(button(t('mac.enroll.go'), host));
    expect(host.textContent).toContain(t('devices.enroll.err.offline'));
    expect(field(t('mac.enroll.code'), host).value).toBe('');
  });
});

describe('adding a Mac', () => {
  it('makes a code that leaves only through onetime_*, and approves a request with the passphrase', async () => {
    handlers.pairing_create = () => ({ ref: 'ref-code', expires_at: new Date(Date.now() + 600_000).toISOString(), peer: OWN_LINK, fingerprint: SELF, environments: [{ env: 'personal/main', invite_id: 'i1', shared_now: true }] });
    let requests: unknown[] = [];
    handlers.join_requests = () => ({ requests, errors: [] });
    handlers.onetime_copy = () => ({ copied: true, clears_in_s: 60 });
    handlers.approve_join = () => ({ fingerprint: MAC_N, envs: [{ env: 'personal/main', ok: true, invites: ['i1'] }] });
    await render();
    await click(await connectAction(t('mac.add')));
    const dlg = dialog('dlg-mac-add');
    // essentials first: places (all by default) and the new Mac's name wait behind 더 보기
    expect([...dlg.querySelectorAll('label')].some((l) => l.textContent === t('mac.addDlg.name'))).toBe(false);
    expect(dlg.textContent).toContain(t('mac.addDlg.more', { n: 2 }));
    await click(button(t('mac.addDlg.create'), dlg));
    expect(dlg.textContent).toContain(t('pass.err.empty'));
    expect(calls('pairing_create')).toHaveLength(0);
    await type(field(t('pass.label'), dlg), PASS);
    await click(button(t('mac.addDlg.create'), dlg));
    expect(calls('pairing_create')).toEqual([{ envs: ['personal/main', 'work/dev'], device_name: t('mac.addDlg.name.default'), admin_passphrase: PASS, name: 'this mac' }]);
    expect(dlg.textContent).toContain(t('mac.code.masked'));
    expect(document.body.textContent).not.toContain(CODE_TEXT_SECRET);
    await click(button(t('act.copy'), dlg));
    expect(calls('onetime_copy')).toEqual([{ ref: 'ref-code' }]);
    expect(calls('onetime_show')).toHaveLength(0);

    requests = [{ env: 'personal/main', request_id: 'r1', invite_id: 'i1', fingerprint: MAC_N, first_seen_at: null, last_seen_at: null, attempts: 1 }];
    await flush(REQUESTS_POLL_MS + 10);
    const card = dlg.querySelector<HTMLElement>(`[data-fingerprint="${MAC_N}"]`)!;
    expect(card).not.toBeNull();
    await click(button(t('mac.req.approve'), card));
    expect(calls('approve_join')).toHaveLength(0);       // no passphrase yet
    await type(field(t('pass.label'), card), PASS);
    await click(button(t('mac.req.approve'), card));
    expect(calls('approve_join')).toEqual([{ envs: ['personal/main'], fingerprint: MAC_N, admin_passphrase: PASS }]);
    expect(dlg.textContent).toContain(t('mac.req.approved'));
    expect(dlg.querySelector(`[data-fingerprint="${MAC_N}"]`)).toBeNull();
  });

  it('discards a code nobody used when the dialog closes', async () => {
    handlers.pairing_create = () => ({ ref: 'ref-unused', expires_at: new Date(Date.now() + 600_000).toISOString(), peer: OWN_LINK, fingerprint: SELF, environments: [{ env: 'personal/main', invite_id: 'i1', shared_now: false }] });
    handlers.join_requests = () => ({ requests: [], errors: [] });
    await render();
    await click(await connectAction(t('mac.add')));
    const dlg = dialog('dlg-mac-add');
    await type(field(t('pass.label'), dlg), PASS);
    await click(button(t('mac.addDlg.create'), dlg));
    await click(button(t('act.done'), dlg));
    expect(calls('onetime_discard')).toContainEqual({ ref: 'ref-unused' });
  });
});

describe('joining another Mac', () => {
  const code = encodePairingCode({ v: 1, service: 'https://link.example.org', link_token: CODE_TEXT_SECRET, peer: LINK_A, name: 'studio', invites: [{ env: 'personal/main', invite: 'zeropw://join#' + 'a'.repeat(80) }] });
  const preview = { name: 'studio', peer: LINK_A, fingerprint: MAC_B, environments: [{ env: 'personal/main', env_id: 'e1', role: 'admin' }], service: 'https://link.example.org', service_host: 'link.example.org', expires_at: new Date(Date.now() + 600_000).toISOString() };

  it('previews, waits showing this Mac\'s code, then finishes', async () => {
    let polls = 0;
    handlers.pairing_preview = () => ({ ref: 'ref-pair', preview });
    handlers.pairing_join = () => {
      polls += 1;
      return polls < 2
        ? { done: false, peer: LINK_A, environments: [{ env: 'personal/main', state: 'pending', self_fingerprint: SELF }] }
        : { done: true, peer: LINK_A, environments: [{ env: 'personal/main', state: 'joined', self_fingerprint: SELF }] };
    };
    await render();
    await click(await connectAction(t('mac.join')));
    const dlg = dialog('dlg-mac-join');
    await type(field(t('mac.joinDlg.code'), dlg), 'not a code');
    expect(dlg.textContent).toContain(t('pair.join.err'));
    expect(calls('pairing_preview')).toHaveLength(0);
    await type(field(t('mac.joinDlg.code'), dlg), code);
    expect(calls('pairing_preview')).toEqual([{ text: code }]);
    expect(field(t('mac.joinDlg.code'), dlg).value).toBe('');       // the core holds the code now
    expect(dlg.textContent).toContain('studio');
    await click(button(t('mac.joinDlg.send'), dlg));
    expect(dlg.textContent).toContain(t('mac.wait.self'));
    expect(dlg.textContent).toContain(SELF.slice(0, 4));
    expect(dlg.textContent).toContain(t('mac.env.pending'));
    await flush(PAIR_POLL_MS + 10);
    expect(dlg.textContent).toContain(t('mac.done'));
    expect(shell.bump).toHaveBeenCalled();
    expect(calls('onetime_discard')).toHaveLength(0);
  });

  it('discards the held code when waiting is cancelled', async () => {
    handlers.pairing_preview = () => ({ ref: 'ref-cancel', preview });
    handlers.pairing_join = () => ({ done: false, peer: LINK_A, environments: [{ env: 'personal/main', state: 'pending', self_fingerprint: SELF }] });
    await render();
    await click(await connectAction(t('mac.join')));
    const dlg = dialog('dlg-mac-join');
    await type(field(t('mac.joinDlg.code'), dlg), code);
    await click(button(t('mac.joinDlg.send'), dlg));
    await click(button(t('mac.wait.cancel'), dlg));
    expect(calls('onetime_discard')).toEqual([{ ref: 'ref-cancel' }]);
    const before = calls('pairing_join').length;
    await flush(PAIR_POLL_MS * 2);
    expect(calls('pairing_join')).toHaveLength(before);
  });
});
