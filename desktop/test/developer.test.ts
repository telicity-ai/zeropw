// @vitest-environment jsdom
// The developer area against the in-memory mock core: agents and their one-time token, grants
// that need the administrator passphrase, approvals, invite links that never reach the page as
// text, and joining by link (pasted or opened from outside the app).
import { act, createElement as h, useCallback, useMemo, useState } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { t } from '../src/copy';
import { useMockBackend } from '../src/ipc/client';
import type { CommandName, InvitePreview } from '../src/ipc/contract';
import { createMockBackend, type MockBackend } from '../src/ipc/mock';
import { ShellContext, type Intent, type Route, type ShellApi } from '../src/app/shell';
import { AppContext, type AppApi } from '../src/ui/app';
import { DeveloperPage } from '../src/screens/developer/DeveloperPage';

// the terminal (xterm) is replaced: these tests check what the page hands it, not xterm itself
const terminals: Array<{ source: unknown; name: string }> = [];
vi.mock('../src/ui/Terminal', () => ({
  AppTerminal: (p: { source: unknown; name: string }) => { terminals.push({ source: p.source, name: p.name }); return h('div', { 'data-testid': 'terminal' }); },
  focusTerminalIn: () => undefined,
}));

const PASS = 'mock-admin-pass';
let backend: MockBackend;
let log: Array<[CommandName, unknown]>;
let root: Root, host: HTMLDivElement;
const toast = vi.fn();
const app: AppApi = { desktop: true, toast, announce: () => undefined, locale: 'ko', language: 'system', setLanguage: async () => undefined };
let takeInvite: ReturnType<typeof vi.fn<(ref: string) => void>>;
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

function Driver({ start, invite }: { start: Route; invite: { ref: string; preview: InvitePreview } | null }) {
  const [route, setRoute] = useState<Route>(start);
  const [held, setHeld] = useState(invite);
  const go = useCallback((page: Route['page'], opts?: Omit<Route, 'page'>) => setRoute({ page, ...opts }), []);
  const clearIntent = useCallback(() => setRoute((r) => ({ ...r, intent: undefined })), []);
  const shell = useMemo(() => ({
    route, go, clearIntent, tick: 0, activity: 0, bump: () => undefined,
    control: { stopped: false, restore_pending: false, incident_open: false },
    serve: { running: true, url: 'http://127.0.0.1:47380', pid: 1, team_listen: null },
    setControl: () => undefined, setServe: () => undefined,
    relay: { busy: false, problem: null, start: async () => true, run: <T,>(task: () => Promise<T>) => task(), report: () => undefined, teamListen: null, offerListenOff: false, confirmListenOff: () => undefined },
    vault: { data: null, error: null, loading: false, reload: () => undefined },
    envFile: null, takeEnvFile: () => undefined,
    invite: held, takeInvite: (ref: string) => { takeInvite(ref); setHeld((x) => (x?.ref === ref ? null : x)); },
    lock: () => undefined, narrow: { rail: false, single: false },
  }) as ShellApi, [route, go, clearIntent, held]);
  return h(ShellContext.Provider, { value: shell }, h(DeveloperPage, { intent: route.intent }));
}

async function settle(ms = 20) {
  for (let i = 0; i < 4; i++) await act(async () => { await new Promise((r) => setTimeout(r, ms)); });
}
async function render(start: Route, invite: { ref: string; preview: InvitePreview } | null = null) {
  await act(async () => root.render(h(AppContext.Provider, { value: app }, h(Driver, { start, invite }))));
  await settle();
}
const body = () => document.body;
function button(text: string, within: ParentNode = body()): HTMLButtonElement {
  const found = [...within.querySelectorAll<HTMLButtonElement>('button')].find((b) => b.textContent?.trim() === text || b.getAttribute('aria-label') === text);
  if (!found) throw new Error(`Missing button: ${text}`);
  return found;
}
const dialog = () => { const d = body().querySelector<HTMLElement>('[role="dialog"]'); if (!d) throw new Error('no dialog'); return d; };
async function click(el: HTMLElement) { await act(async () => el.click()); await settle(); }
function field(label: string, within: ParentNode = body()): HTMLInputElement {
  const l = [...within.querySelectorAll('label')].find((x) => x.textContent?.trim() === label);
  if (!l) throw new Error(`Missing field: ${label}`);
  return document.getElementById(l.htmlFor) as HTMLInputElement;
}
async function type(el: HTMLInputElement, value: string) {
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await settle();
}
async function submit(label: string) { await click(button(label, dialog())); }
const callsOf = (name: CommandName) => log.filter(([n]) => n === name).map(([, input]) => input as Record<string, unknown>);
const LINK = 'zeropw://join#' + 'abcdefghijklmnopqrstuvwxyz234567'.repeat(4);

beforeEach(() => {
  backend = createMockBackend({ initialized: true, latency: 0, teamListen: '100.64.1.7:47420' });
  log = [];
  const inner = backend;
  useMockBackend({ ...inner, call: (name, input) => { log.push([name, input]); return inner.call(name, input); } } as MockBackend);
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  terminals.length = 0;
  toast.mockClear();
  takeInvite = vi.fn<(ref: string) => void>();
});
afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
  document.body.innerHTML = '';
  backend.dispose();
  useMockBackend(null);
});

describe('agents', () => {
  it('creates an agent and copies its token only once', async () => {
    await render({ page: 'developer', intent: 'add-agent' as Intent });
    await type(field(t('agent.name'), dialog()), 'agent-x');
    await act(async () => { (dialog().querySelector('input[type="radio"][value="other"]') as HTMLInputElement).click(); });
    await submit(t('agent.create.confirm'));
    expect(callsOf('principal_create')).toEqual([{ id: 'agent-x', runtime: 'user-agent' }]);
    await click(button(t('agent.copyToken'), dialog()));
    expect(callsOf('onetime_copy')).toHaveLength(1);
    // used: no second copy, and the dialog only offers to finish
    expect(() => button(t('agent.copyToken'), dialog())).toThrow();
    await click(button(t('act.done'), dialog()));
    expect(callsOf('onetime_discard')).toHaveLength(0);
    expect(terminals).toHaveLength(0);
  });

  it('opens the terminal with the new token and never discards it', async () => {
    await render({ page: 'developer', intent: 'add-agent' as Intent });
    await act(async () => { (dialog().querySelector('input[type="radio"][value="same"]') as HTMLInputElement).click(); });
    expect(dialog().textContent).toContain(t('agent.where.warn'));
    await submit(t('agent.create.confirm'));
    expect(callsOf('principal_create')[0]).toMatchObject({ runtime: 'default' });
    await click(button(t('agent.openTerminal'), dialog()));
    expect(body().querySelector('[role="dialog"]')).toBeNull();
    const src = terminals.at(-1)?.source as { kind: string; tokenRef: string; asUser: string | null };
    expect(src.kind).toBe('open');
    expect(src.tokenRef).toMatch(/^[0-9a-f]{32}$/);
    expect(src.asUser).toBeNull();
    expect(callsOf('onetime_discard')).toHaveLength(0);
    expect(callsOf('onetime_copy')).toHaveLength(0);
  });

  it('discards a token nobody used when the dialog closes', async () => {
    await render({ page: 'developer', intent: 'add-agent' as Intent });
    await act(async () => { (dialog().querySelector('input[type="radio"][value="other"]') as HTMLInputElement).click(); });
    await submit(t('agent.create.confirm'));
    await click(button(t('act.close'), dialog().querySelector('footer')!));
    expect(callsOf('onetime_discard')).toHaveLength(1);
  });

  it('requires a choice of where the agent runs', async () => {
    await render({ page: 'developer', intent: 'add-agent' as Intent });
    await submit(t('agent.create.confirm'));
    expect(dialog().textContent).toContain(t('agent.where.required'));
    expect(callsOf('principal_create')).toHaveLength(0);
  });

  it('gives a permission only with the administrator passphrase', async () => {
    await render({ page: 'developer', intent: 'add-grant' as Intent });
    // essentials first: the duration and use limit wait behind 더 보기 with their defaults
    expect(dialog().textContent).not.toContain(t('grant.ttl.8h'));
    expect(dialog().textContent).toContain(t('grant.more', { ttl: t('grant.ttl.1h') }));
    await submit(t('grant.confirm'));
    expect(dialog().textContent).toContain(t('pass.err.empty'));
    expect(callsOf('grant_create')).toHaveLength(0);
    await type(field(t('pass.label'), dialog()), 'wrong-pass');
    await submit(t('grant.confirm'));
    expect(dialog().textContent).toContain(t('error.auth'));
    expect(field(t('pass.label'), dialog()).value).toBe('');
    await type(field(t('pass.label'), dialog()), PASS);
    await submit(t('grant.confirm'));
    const made = callsOf('grant_create');
    expect(made.at(-1)).toMatchObject({ principal: 'agent-1', connection: 'example-api', ttl: '1h', admin_passphrase: PASS });
    expect(body().querySelector('[role="dialog"]')).toBeNull();
    expect(toast).toHaveBeenCalledWith(t('grant.toast.created'), 'ok');
  });
});

describe('approvals', () => {
  it('approves one pending request with the passphrase', async () => {
    await render({ page: 'developer', view: 'approvals' });
    const approve = [...body().querySelectorAll<HTMLButtonElement>('button')].filter((b) => b.textContent === t('appr.approve'));
    expect(approve).toHaveLength(2);
    await click(approve[0]!);
    expect(dialog().textContent).toContain('/v1/');
    await type(field(t('pass.label'), dialog()), PASS);
    await submit(t('appr.confirm'));
    expect(callsOf('approvals_approve')).toHaveLength(1);
    expect(callsOf('approvals_approve')[0]).toMatchObject({ admin_passphrase: PASS });
    expect([...body().querySelectorAll('button')].filter((b) => b.textContent === t('appr.approve'))).toHaveLength(1);
  });
});

describe('sharing', () => {
  it('shares the place, then makes an invite whose link stays masked and is copied once', async () => {
    await render({ page: 'developer', view: 'sharing', intent: 'invite' as Intent });
    await type(field(t('share.name'), dialog()), 'synthetic friend');
    await type(field(t('pass.label'), dialog()), PASS);
    await submit(t('share.shareCreate'));
    expect(callsOf('team_share')).toHaveLength(1);
    const created = callsOf('team_invite_create');
    expect(created).toHaveLength(1);
    expect(created[0]).toMatchObject({ role: 'user', name: 'synthetic friend', address: '100.64.1.7:47420' });
    expect(dialog().textContent).toContain(t('share.link.mask'));
    expect(dialog().textContent).not.toMatch(/zeropw:\/\/join#[a-z2-7]{20}/i);
    await click(button(t('act.copy'), dialog()));
    expect(callsOf('onetime_copy')).toHaveLength(1);
    expect(callsOf('onetime_show')).toHaveLength(0);
    expect(() => button(t('act.copy'), dialog())).toThrow();
  });

  it('joins with a pasted link after the preview, keeping the link out of the page', async () => {
    await render({ page: 'developer', view: 'sharing', intent: 'join' as Intent });
    await type(field(t('share.join.field'), dialog()), LINK);
    expect(callsOf('team_invite_preview')).toHaveLength(1);
    expect(dialog().textContent).toContain(t('share.join.check'));
    await submit(t('share.join.confirm'));
    const joins = callsOf('team_join');
    expect(joins).toHaveLength(1);
    expect(joins[0]).toMatchObject({ project: expect.stringMatching(/^team-/), environment: 'shared' });
    expect(callsOf('onetime_discard')).toHaveLength(0);
  });

  it('adopts a link opened outside the app and joins with its reference', async () => {
    const opened = await backend.call('team_invite_preview', { text: LINK });
    await render({ page: 'developer', view: 'sharing', intent: 'join' as Intent }, opened);
    expect(takeInvite).toHaveBeenCalledWith(opened.ref);
    expect(dialog().textContent).toContain(t('share.join.fromLink'));
    await submit(t('share.join.confirm'));
    expect(callsOf('team_join')[0]).toMatchObject({ ref: opened.ref });
  });

  it('discards an adopted link when the dialog closes without joining', async () => {
    const opened = await backend.call('team_invite_preview', { text: LINK });
    await render({ page: 'developer', view: 'sharing' }, opened);
    await click(button(t('act.cancel'), dialog()));
    await settle();
    expect(callsOf('onetime_discard').map((x) => x.ref)).toContain(opened.ref);
    expect(callsOf('team_join')).toHaveLength(0);
  });
});
