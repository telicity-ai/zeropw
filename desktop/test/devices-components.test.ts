// @vitest-environment jsdom
// The devices page (docs/remote-sync.md §4) with a stubbed core: plain row states with how a Mac
// is connected only under the connection details, server enrolment, making a pairing code and
// approving the request it brings per Mac and environment, and the joining Mac's paste, preview
// and wait for approval with its stop conditions. Synthetic values only.
import { act, createElement as h, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { call } from '../src/ipc/client';
import type { DevicesOverview, LinkStatus, PairingJoinResult, PairingPreview } from '../src/ipc/contract';
import { COPY, t } from '../src/copy';
import { DevicesPage } from '../src/dashboard/Devices';
import { PAIR_POLL_MS } from '../src/dashboard/pairJoin';
import { DashContext, type DashApi } from '../src/dashboard/context';
import { AppContext, type AppApi } from '../src/ui/context';
import { encodePairingCode } from '../src/lib/pairing';
import { formatFingerprint } from '../src/lib/validators';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
vi.mock('../src/ipc/client', async (original) => ({ ...await original<typeof import('../src/ipc/client')>(), call: vi.fn(), on: vi.fn(async () => () => undefined) }));
const ipc = vi.mocked(call);

const SELF = 'saaaaaaaaaaaaaaaaaaaaaaaaa';
const MAC_B = 'fbbbbbbbbbbbbbbbbbbbbbbbbb';
const MAC_A = 'faaaaaaaaaaaaaaaaaaaaaaaaa';
const OWN_LINK = 'oooooooooooooooooooooooooo';
const LINK_B = 'llllllllllllllllllllllllll';
const PASS = 'synthetic-admin-pass';

const app = { field: { ripple: vi.fn(), set: vi.fn(), chipText: vi.fn(), setMode: vi.fn(), setStopped: vi.fn() }, desktop: true, toast: vi.fn(), announce: vi.fn(), setPill: vi.fn() } as unknown as AppApi;
const dash = { tick: 0, go: vi.fn(), bump: vi.fn(), relay: { run: (fn: () => Promise<unknown>) => fn(), report: vi.fn() } } as unknown as DashApi;
let root: Root, host: HTMLDivElement;
let handlers: Record<string, (input: never) => unknown>;
const calls = (name: string) => ipc.mock.calls.filter(([c]) => c === name).map(([, input]) => input as Record<string, unknown>);

const linkStatus = (over: Partial<LinkStatus> = {}): LinkStatus => ({
  available: true, running: true, enrolled: true, revoked: false, device_id: OWN_LINK, online: true, service: 'https://link.example.org',
  service_host: 'link.example.org', default_service: 'https://link.zeropw.invalid', device_name: 'this mac', problem: null,
  peers: [{ device_id: LINK_B, name: 'studio', online: true, revoked: false, path: 'relay-tls', rtt_ms: 31, last_error: null }], ...over,
});
const overview = (over: Partial<DevicesOverview> = {}): DevicesOverview => ({
  self_fingerprint: SELF, link: linkStatus(), link_devices: [],
  devices: [{ fingerprint: MAC_B, link_device_id: LINK_B, name: 'studio', envs: ['demo/dev'], added_at: 1 }],
  envs: [{
    env: 'demo/dev', members: { env_id: 'e1', members: [{ fingerprint: MAC_B, name: 'studio', role: 'admin', status: 'active', owner: false }] },
    sync: { env_id: 'e1', self: SELF, serve_updated_at: '2026-11-07T00:00:00Z', conflicts: 0, peers: [{
      fingerprint: MAC_B, name: 'studio', state: 'up_to_date', session: true, transport: 'link', last_contact_at: '2026-11-07T00:00:00Z', next_attempt_at: null, last_error: null,
    }] },
  }],
  ...over,
});

async function flush(ms = 20) { await act(async () => { await vi.advanceTimersByTimeAsync(ms); }); }
async function render(child: ReactNode, d: DashApi = dash) {
  await act(async () => root.render(h(AppContext, { value: app }, h(DashContext, { value: d }, child))));
  await flush();
}
function button(text: string, within: ParentNode = host) {
  const found = [...within.querySelectorAll<HTMLButtonElement>('button')].find((b) => b.textContent?.trim().replace(/\s*→$/, '') === text);
  if (!found) throw new Error(`Missing button: ${text}`);
  return found;
}
async function click(el: HTMLElement) { await act(async () => el.click()); await flush(); }
async function input(id: string, value: string) {
  const el = host.querySelector<HTMLInputElement>(`#${id}`);
  if (!el) throw new Error(`Missing input: ${id}`);
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await flush();
}
const sheet = (id: string) => host.querySelector<HTMLElement>(`#${id}`)!;
/** What the page says outside the connection details disclosures. */
function plainText(within: HTMLElement = host): string {
  const copy = within.cloneNode(true) as HTMLElement;
  copy.querySelectorAll('details.device-detail').forEach((d) => d.remove());
  return copy.textContent ?? '';
}

beforeEach(() => {
  vi.useFakeTimers();
  host = document.createElement('div');
  document.body.append(host);
  root = createRoot(host);
  vi.clearAllMocks();
  handlers = {};
  ipc.mockImplementation((async (name: string, inputValue?: unknown) => {
    const handler = handlers[name];
    if (handler) return handler(inputValue as never);
    if (name === 'devices_overview') return overview();
    if (name === 'project_list') return { projects: [{ name: 'demo', environments: ['dev', 'prod'], created_at: '' }] };
    if (name === 'secure_view') return { protected: false };
    if (name === 'onetime_discard') return undefined;
    throw { error: 'Internal', reason: 'unexpected_' + name };
  }) as never);
});
afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
  vi.useRealTimers();
});

describe('devices page', () => {
  it('shows each paired Mac in plain words and how it is connected only under the details', async () => {
    await render(h(DevicesPage, { onIntent: () => undefined }));
    const row = [...host.querySelectorAll('li.list-row')].find((li) => li.textContent?.includes('studio'))!;
    expect(row.textContent).toContain(t('devices.st.up_to_date'));
    expect(row.textContent).toContain(formatFingerprint(MAC_B));
    const details = row.querySelector('details.device-detail')!;
    expect(details.querySelector('summary')?.textContent).toBe(t('devices.detail'));
    expect(details.textContent).toContain('relay-tls');
    expect(details.textContent).toContain(t('devices.path.relay'));
    // nothing about candidates, allocations, relays or link codes in the normal flow
    expect(plainText()).not.toMatch(/ICE|TURN|STUN|allocation|candidate|relay|direct|zpl:|link_|[a-z]+_[a-z]+/i);
    expect(button(t('devices.remove'), row).getAttribute('aria-label')).toBe(t('devices.remove.aria', { name: 'studio' }));
  });

  it('marks changes that need a look, and says when this Mac was removed at the server', async () => {
    const o = overview();
    o.envs[0]!.sync!.conflicts = 1;
    handlers.devices_overview = () => o;
    await render(h(DevicesPage, { onIntent: () => undefined }));
    expect(host.textContent).toContain(t('devices.st.conflict'));
    await click(button(t('devices.conflict.go')));
    expect(dash.go).toHaveBeenCalledWith('logs', 'alerts');

    // the next read (another page changed something: the dashboard's tick)
    handlers.devices_overview = () => overview({ link: linkStatus({ revoked: true, online: false }) });
    await render(h(DevicesPage, { onIntent: () => undefined }), { ...dash, tick: 1 } as DashApi);
    expect(host.textContent).toContain(t('devices.revoked'));
    expect(button(t('devices.add')).getAttribute('aria-disabled')).toBe('true');
  });

  it('enrols with a server invite code typed once, checked before it leaves', async () => {
    handlers.devices_overview = () => overview({ link: linkStatus({ enrolled: false, device_id: null, online: false, peers: [] }), devices: [], envs: [] });
    handlers.link_enroll = () => linkStatus();
    await render(h(DevicesPage, { onIntent: () => undefined }));
    await input('enroll-code', 'ZPL-not-a-code');
    await click(button(t('devices.enroll.btn')));
    expect(host.textContent).toContain(t('devices.enroll.err.code'));
    expect(calls('link_enroll')).toEqual([]);
    const code = 'zpl-abcd-efgh-ijkl-mnop-qrst-uvwx-yz';
    await input('enroll-code', code);
    await click(button(t('devices.enroll.btn')));
    // the default server is not sent: the core fills it in from its one constant
    expect(calls('link_enroll')).toEqual([{ invite_code: code, name: 'this mac' }]);
    expect(host.querySelector<HTMLInputElement>('#enroll-code')?.value ?? '').toBe('');
    expect(app.toast).toHaveBeenCalledWith(t('toast.devices.enrolled'));
  });

  it('refuses a code the server does not take, in plain words', async () => {
    handlers.devices_overview = () => overview({ link: linkStatus({ enrolled: false, device_id: null, peers: [] }), devices: [], envs: [] });
    handlers.link_enroll = () => { throw { error: 'PolicyDenied', reason: 'link_invite_invalid' }; };
    await render(h(DevicesPage, { onIntent: () => undefined }));
    await input('enroll-code', 'ZPL-ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ');
    await click(button(t('devices.enroll.btn')));
    expect(host.textContent).toContain(t('devices.enroll.err.refused'));
    expect(host.textContent).not.toContain('link_invite_invalid');
  });
});

describe('adding a Mac', () => {
  const created = { ref: 'ref-pair', expires_at: new Date(Date.now() + 600_000).toISOString(), peer: OWN_LINK, fingerprint: SELF,
    environments: [{ env: 'demo/dev', invite_id: 'i1', shared_now: true }, { env: 'demo/prod', invite_id: 'i2', shared_now: false }] };

  async function makeCode() {
    handlers.pairing_create = () => created;
    await render(h(DevicesPage, { onIntent: () => undefined }));
    await click(button(t('devices.add')));
    const s = sheet('sheet-pair-add');
    expect([...s.querySelectorAll('.chip')].map((c) => [c.textContent, c.getAttribute('aria-pressed')])).toEqual([['demo/dev', 'true'], ['demo/prod', 'true']]);
    await click(button(t('pair.add.create'), s));
    expect(calls('pairing_create')).toEqual([]);
    await input('pair-pass', PASS);
    await click(button(t('pair.add.create'), s));
    expect(calls('pairing_create')).toEqual([{ envs: ['demo/dev', 'demo/prod'], device_name: t('pair.add.name.default'), admin_passphrase: PASS, name: 'this mac' }]);
    return s;
  }

  it('makes one code, hands it out once, and drops a code nobody took when the sheet closes', async () => {
    handlers.join_requests = () => ({ requests: [], errors: [] });
    const s = await makeCode();
    // the code stays in the core until copied or shown, once
    expect(s.textContent).not.toContain('zeropw://pair#ey');
    expect(s.querySelector('.mask')).not.toBeNull();
    expect(s.querySelector<HTMLInputElement>('#pair-pass')).toBeNull();
    expect(s.textContent).toContain(t('pair.req.wait'));
    await click(button(t('common.done'), s));
    expect(calls('onetime_discard')).toEqual([{ ref: 'ref-pair' }]);
  });

  it('reads join requests while the code is out and approves each Mac per environment', async () => {
    let requests = [{ env: 'demo/dev', request_id: 'r1', invite_id: 'i1', fingerprint: MAC_B, first_seen_at: null, last_seen_at: null, attempts: 1 }];
    handlers.join_requests = () => ({ requests, errors: [] });
    handlers.onetime_copy = () => ({ copied: true, clears_in_s: 60 });
    handlers.approve_join = (i: { envs: string[]; fingerprint: string }) => ({ fingerprint: i.fingerprint, envs: i.envs.map((env) => ({ env, ok: true, invites: ['x'] })) });
    const s = await makeCode();
    await click(button(t('inv.copy'), s));
    expect(calls('onetime_copy')).toEqual([{ ref: 'ref-pair' }]);
    // once only
    expect([...s.querySelectorAll('button')].some((b) => b.textContent === t('inv.copy'))).toBe(false);
    // polled every few seconds while the sheet is open
    await flush(3_100);
    expect(calls('join_requests').at(-1)).toEqual({ envs: ['demo/dev', 'demo/prod'] });
    const card = s.querySelector<HTMLElement>('.request-card')!;
    expect(card.textContent).toContain(formatFingerprint(MAC_B));
    expect(card.textContent).toContain(t('pair.req.check'));
    const approve = button(t('pair.req.approve'), card);
    expect(approve.getAttribute('aria-label')).toBe(t('pair.req.approve.aria', { fp: formatFingerprint(MAC_B) }));
    // the admin password every time
    await click(approve);
    expect(calls('approve_join')).toEqual([]);
    expect(card.textContent).toContain(t('pass.err.empty'));
    await input(card.querySelector('input')!.id, PASS);
    await click(approve);
    expect(calls('approve_join')).toEqual([{ envs: ['demo/dev'], fingerprint: MAC_B, admin_passphrase: PASS }]);
    expect(s.querySelector('.request-card')).toBeNull();
    // the same Mac asks for the second environment later: it is asked about again
    requests = [...requests, { env: 'demo/prod', request_id: 'r2', invite_id: 'i2', fingerprint: MAC_B, first_seen_at: null, last_seen_at: null, attempts: 1 }];
    await flush(3_100);
    const again = s.querySelector<HTMLElement>('.request-card')!;
    expect(again).not.toBeNull();
    expect(again.textContent).toContain(t('devices.envs', { n: 1 }));
    // a copied code is not discarded when the sheet closes
    await click(button(t('common.done'), s));
    expect(calls('onetime_discard')).toEqual([]);
    const polls = calls('join_requests').length;
    await flush(10_000);
    expect(calls('join_requests').length).toBe(polls);
  });

  it('refuses a request with the password, and says a wrong password under the field', async () => {
    handlers.join_requests = () => ({ requests: [{ env: 'demo/dev', request_id: 'r1', invite_id: 'i1', fingerprint: MAC_B, first_seen_at: null, last_seen_at: null, attempts: 3 }], errors: [] });
    let wrong = true;
    handlers.deny_join = (i: { envs: string[]; fingerprint: string }) => {
      if (wrong) { wrong = false; throw { error: 'AuthFailed', reason: 'admin_reauth_failed' }; }
      return { fingerprint: i.fingerprint, envs: i.envs.map((env) => ({ env, ok: true, invites: ['x'] })) };
    };
    const s = await makeCode();
    await flush(3_100);
    const card = s.querySelector<HTMLElement>('.request-card')!;
    expect(card.textContent).toContain(t('pair.req.attempts', { n: 3 }));
    await input(card.querySelector('input')!.id, 'wrong-synthetic');
    await click(button(t('pair.req.deny'), card));
    expect(card.querySelector('input')!.value).toBe('');
    expect(card.querySelector('[aria-invalid="true"]')).not.toBeNull();
    await input(card.querySelector('input')!.id, PASS);
    await click(button(t('pair.req.deny'), card));
    expect(calls('deny_join').at(-1)).toEqual({ envs: ['demo/dev'], fingerprint: MAC_B, admin_passphrase: PASS });
    expect(app.toast).toHaveBeenCalledWith(t('toast.pair.denied'), 'warn');
  });
});

describe('joining another Mac', () => {
  const code = encodePairingCode({ v: 1, service: 'https://link.example.org', link_token: 'zplt_synthetic', peer: LINK_B, name: 'studio',
    invites: [{ env: 'demo/dev', invite: 'syntheticinviteaaaa' }, { env: 'demo/prod', invite: 'syntheticinvitebbbb' }] });
  const preview: PairingPreview = { name: 'studio', peer: LINK_B, fingerprint: MAC_A, service: 'https://link.example.org', service_host: 'link.example.org',
    expires_at: new Date(Date.now() + 600_000).toISOString(), environments: [{ env: 'demo/dev', env_id: 'e1', role: 'admin' }, { env: 'demo/prod', env_id: 'e2', role: 'admin' }] };
  const result = (states: Array<'joined' | 'pending' | 'failed'>, extra: Partial<PairingJoinResult['environments'][number]> = {}): PairingJoinResult => ({
    done: states.every((s) => s === 'joined'), peer: LINK_B,
    environments: states.map((state, i) => ({ env: ['demo/dev', 'demo/prod'][i]!, state, self_fingerprint: MAC_B, inviter_fingerprint: MAC_A, ...(state === 'failed' ? extra : {}) })),
  });

  async function paste() {
    handlers.pairing_preview = () => ({ ref: 'ref-text', preview });
    await render(h(DevicesPage, { onIntent: () => undefined }));
    await click(button(t('devices.join')));
    const s = sheet('sheet-pair-join');
    await input('pair-join-code', 'zeropw://join#notapairingcode');
    expect(s.textContent).toContain(t('pair.join.err'));
    expect(calls('pairing_preview')).toEqual([]);
    await input('pair-join-code', code);
    expect(calls('pairing_preview')).toEqual([{ text: code }]);
    // the core holds the code now; the field is empty
    expect(s.querySelector<HTMLInputElement>('#pair-join-code')!.value).toBe('');
    const region = s.querySelector('[role="region"]')!;
    expect(region.textContent).toContain('studio');
    expect(region.textContent).toContain(formatFingerprint(MAC_A));
    expect(region.textContent).toContain('link.example.org');
    return s;
  }

  it('asks to join, waits while the other Mac approves, and finishes when every environment joined', async () => {
    const answers = [result(['pending', 'pending']), result(['joined', 'pending']), result(['joined', 'joined'])];
    handlers.pairing_join = () => answers.shift() ?? result(['joined', 'joined']);
    const s = await paste();
    await click(button(t('pair.join.confirm'), s));
    expect(calls('pairing_join')).toEqual([{ ref: 'ref-text' }]);
    expect(s.querySelector('h2')?.textContent).toBe(t('pair.wait.title'));
    // both Macs' pictures and codes to compare
    expect(s.textContent).toContain(formatFingerprint(MAC_B));
    expect(s.textContent).toContain(formatFingerprint(MAC_A));
    expect([...s.querySelectorAll('.pair-env .st')].map((e) => e.textContent)).toEqual([t('pair.env.pending'), t('pair.env.pending')]);
    await flush(PAIR_POLL_MS + 50);
    expect([...s.querySelectorAll('.pair-env .st')].map((e) => e.textContent)).toEqual([t('pair.env.joined'), t('pair.env.pending')]);
    await flush(PAIR_POLL_MS + 50);
    expect(calls('pairing_join')).toHaveLength(3);
    expect(s.textContent).toContain(t('pair.done'));
    expect(app.toast).toHaveBeenCalledWith(t('toast.pair.done'));
    await flush(PAIR_POLL_MS * 3);
    expect(calls('pairing_join')).toHaveLength(3);
    // the core forgot the code itself once every environment joined
    expect(calls('onetime_discard')).toEqual([]);
  });

  it('keeps trying while the other Mac is away and says so plainly', async () => {
    handlers.pairing_join = () => result(['failed', 'pending'], { reason: 'team_join_failed', detail: 'link_peer_offline' });
    const s = await paste();
    await click(button(t('pair.join.confirm'), s));
    expect(s.textContent).toContain(t('pair.failed.offline'));
    expect(s.textContent).not.toContain('link_peer_offline');
    await flush(PAIR_POLL_MS + 50);
    expect(calls('pairing_join')).toHaveLength(2);
  });

  it('stops when the core says it cannot succeed, and forgets the code', async () => {
    handlers.pairing_join = () => { throw { error: 'StateError', reason: 'link_other_account' }; };
    const s = await paste();
    await click(button(t('pair.join.confirm'), s));
    expect(s.textContent).toContain(t('pair.failed.account'));
    expect(calls('onetime_discard')).toEqual([{ ref: 'ref-text' }]);
    await flush(PAIR_POLL_MS * 3);
    expect(calls('pairing_join')).toHaveLength(1);
  });

  it('ends a partial pairing when the rest cannot join, naming why', async () => {
    handlers.pairing_join = () => result(['joined', 'failed'], { reason: 'pairing_env_exists' });
    const s = await paste();
    await click(button(t('pair.join.confirm'), s));
    expect(s.textContent).toContain(t('pair.done'));
    expect(s.textContent).toContain(t('pair.failed.exists'));
    expect(calls('onetime_discard')).toEqual([{ ref: 'ref-text' }]);
  });

  it('stops waiting when the user stops', async () => {
    handlers.pairing_join = () => result(['pending', 'pending']);
    const s = await paste();
    await click(button(t('pair.join.confirm'), s));
    await click(button(t('pair.wait.cancel'), s));
    expect(calls('onetime_discard')).toEqual([{ ref: 'ref-text' }]);
    await flush(PAIR_POLL_MS * 3);
    expect(calls('pairing_join')).toHaveLength(1);
  });
});

describe('remote sync copy', () => {
  it('uses plain words without connection jargon or vault jargon', () => {
    const entries = Object.entries(COPY).filter(([k]) => /^(devices|pair|toast\.(devices|pair))\./.test(k) || k === 'nav.devices' || k === 'page.devices.sub' || k === 'proj.pair');
    expect(entries.length).toBeGreaterThan(80);
    for (const [k, v] of entries) {
      expect(v, k).not.toMatch(/ICE|TURN|STUN|NAT|allocation|candidate|QUIC|\brelay\b|zpl|link token|fingerprint/i);
      expect(v, k).not.toMatch(/패스프레이즈|금고/); // 패스프레이즈, 금고
    }
    // removal says what it does not do: keys the other Mac already had stay valid
    expect(COPY['devices.remove.warn']).toMatch(/서비스에서/); // 서비스에서
  });
});
