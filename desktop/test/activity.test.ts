// @vitest-environment jsdom
// The activity screens against the browser mock backend: records and alerts in plain words, and
// declaring an incident (the passphrase only for the widest scope).
import { act, createElement as h, useState, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Page, Route, ShellApi } from '../src/app/shell';
import { NO_CONTROL, ShellContext } from '../src/app/shell';
import { t } from '../src/copy';
import { call, useMockBackend } from '../src/ipc/client';
import { createMockBackend, type MockBackend } from '../src/ipc/mock';
import { ActivityPage, shownRecords } from '../src/screens/activity/ActivityPage';
import { AppContext, type AppApi } from '../src/ui/app';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let root: Root, host: HTMLDivElement, backend: MockBackend;
const toast = vi.fn();
const go = vi.fn();
const app: AppApi = { desktop: true, toast, announce: vi.fn(), locale: 'ko', language: 'system', setLanguage: async () => undefined };

function Driver({ view }: { view: string }) {
  const [route, setRoute] = useState<Route>({ page: 'activity', view });
  const shell: ShellApi = {
    route, go: (page: Page, opts) => { go(page, opts); setRoute({ page, ...opts }); }, clearIntent: () => undefined, tick: 0, activity: 0, bump: () => undefined,
    control: NO_CONTROL, serve: { running: true, url: 'http://127.0.0.1:47380', pid: 1, team_listen: null }, setControl: () => undefined, setServe: () => undefined,
    relay: { busy: false, problem: null, start: async () => true, run: (fn) => fn(), report: vi.fn(), teamListen: null, offerListenOff: false, confirmListenOff: () => undefined },
    vault: { data: null, error: null, loading: false, reload: () => undefined }, envFile: null, takeEnvFile: () => undefined, invite: null,
    takeInvite: () => undefined, lock: vi.fn(), narrow: { rail: false, single: false },
  };
  return h(ShellContext, { value: shell }, h(ActivityPage, { intent: undefined }));
}
const providers = (child: ReactNode) => h(AppContext, { value: app }, child);
const settle = () => act(async () => { for (let i = 0; i < 4; i++) await new Promise((r) => setTimeout(r, 5)); });
async function render(view: string) { await act(async () => root.render(providers(h(Driver, { view })))); await settle(); }
function button(text: string, within: ParentNode = document.body) {
  const found = [...within.querySelectorAll<HTMLButtonElement>('button')].find((b) => b.textContent?.trim() === text);
  if (!found) throw new Error(`Missing button: ${text}`);
  return found;
}
async function click(el: HTMLElement) { await act(async () => el.click()); await settle(); }
const dialog = () => document.querySelector<HTMLElement>('[role="dialog"]');

beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  toast.mockClear(); go.mockClear();
  backend = createMockBackend({ initialized: true, activity: true });
  useMockBackend(backend);
});
afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
  document.body.innerHTML = '';
  backend.dispose();
  useMockBackend(null);
});

describe('records and alerts', () => {
  it('lists records newest first and switches to alerts', async () => {
    await render('records');
    const items = document.querySelectorAll('[role="table"] .log-row[role="row"]');
    expect(items.length).toBeGreaterThan(0);
    const tail = await call('audit_tail', { limit: 200 });
    const newest = shownRecords(tail.records, 'audit')[0]!;
    expect(items[0]!.querySelector('.log-title')!.textContent).toBe(newest.view.title);
    expect(document.querySelectorAll('[role="columnheader"]')).toHaveLength(4);
    await click([...document.querySelectorAll<HTMLButtonElement>('[role="radio"]')].find((b) => b.textContent === t('activity.tab.alerts'))!);
    expect(go).toHaveBeenCalledWith('activity', { view: 'alerts' });
    expect(document.querySelector('[role="radio"][aria-checked="true"]')!.textContent).toBe(t('activity.tab.alerts'));
  });

  it('marks an overridden change as a conflict to check', () => {
    const rows = shownRecords([{ ts: '2026-11-07T10:00:00Z', alert: 'team_op_overridden', event: 'team_op_overridden' }], 'alert');
    expect(rows[0]!.conflict).toBe(true);
  });
});

describe('incidents', () => {
  it('declares an incident for one agent without a passphrase', async () => {
    await render('incidents');
    await click(button(t('activity.inc.declare')));
    const d = dialog()!;
    expect(d.textContent).toContain(t('activity.inc.declare.warn'));
    expect(d.querySelector('input[type="password"]')).toBeNull();
    await click(button(t('activity.inc.declare.confirm'), d));
    expect(dialog()).toBeNull();
    expect(toast).toHaveBeenCalledWith(t('toast.activity.declared'), 'warn');
    expect(document.body.textContent).toContain(t('activity.inc.open'));
    expect((await call('control_get')).incident_open).toBe(true);
  });

  it('asks for the passphrase for the widest scope', async () => {
    await render('incidents');
    await click(button(t('activity.inc.declare')));
    await click([...dialog()!.querySelectorAll<HTMLButtonElement>('[role="radio"]')].find((b) => b.textContent === t('inc.scope.all'))!);
    expect(dialog()!.querySelector('input[type="password"]')).not.toBeNull();
    await click(button(t('activity.inc.declare.confirm'), dialog()!));
    expect(dialog()!.textContent).toContain(t('pass.err.empty'));
    expect((await call('control_get')).incident_open).toBe(false);
  });
});
