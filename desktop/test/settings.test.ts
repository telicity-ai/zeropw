// @vitest-environment jsdom
// The settings screens against the browser mock backend: the server address is saved without
// touching the other settings and never called operating, a damaged settings file is reset only
// after a confirmation, and a restore needs the administrator passphrase.
import { act, createElement as h, useState, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Page, Route, ShellApi } from '../src/app/shell';
import { NO_CONTROL, ShellContext } from '../src/app/shell';
import { call, useMockBackend } from '../src/ipc/client';
import type { Control } from '../src/ipc/contract';
import { createMockBackend, type MockBackend, type MockSeed } from '../src/ipc/mock';
import { PLANNED_SERVICE } from '../src/screens/settings/sections';
import { SettingsPage } from '../src/screens/settings/SettingsPage';
import { AppContext, type AppApi } from '../src/ui/app';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let root: Root, host: HTMLDivElement, backend: MockBackend;
const toast = vi.fn();
const app: AppApi = { desktop: true, toast, announce: vi.fn(), locale: 'ko', language: 'system', setLanguage: async () => undefined };
let control: Control = NO_CONTROL;

function Driver({ view }: { view: string }) {
  const [route, setRoute] = useState<Route>({ page: 'settings', view });
  const [ctl, setCtl] = useState<Control>(control);
  const shell: ShellApi = {
    route, go: (page: Page, opts) => setRoute({ page, ...opts }), clearIntent: () => undefined, tick: 0, activity: 0, bump: () => undefined,
    control: ctl, serve: { running: true, url: 'http://127.0.0.1:47380', pid: 42, team_listen: null }, setControl: setCtl, setServe: () => undefined,
    relay: { busy: false, problem: null, start: async () => true, run: (fn) => fn(), report: vi.fn(), teamListen: null, offerListenOff: false, confirmListenOff: () => undefined },
    vault: { data: null, error: null, loading: false, reload: () => undefined }, envFile: null, takeEnvFile: () => undefined, invite: null,
    takeInvite: () => undefined, lock: vi.fn(), narrow: { rail: false, single: false },
  };
  return h(ShellContext, { value: shell }, h(SettingsPage, { intent: undefined }));
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
async function type(el: HTMLInputElement, value: string) {
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
}
const dialog = () => document.querySelector<HTMLElement>('[role="dialog"]');
async function seed(s: MockSeed) {
  backend = createMockBackend({ initialized: true, ...s });
  useMockBackend(backend);
}

beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  toast.mockClear();
  control = NO_CONTROL;
});
afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
  document.body.innerHTML = '';
  backend?.dispose();
  useMockBackend(null);
});

describe('connection server', () => {
  it('saves the planned address without changing the other settings and never says the server operates', async () => {
    await seed({ teamListen: '192.168.1.20:47420' });
    await render('server');
    expect(document.body.textContent).toContain('아직 등록하지 않음');
    await click(button('배포 예정 주소 넣기'));
    const field = document.querySelector<HTMLInputElement>('input[placeholder="https://"]')!;
    expect(field.value).toBe(PLANNED_SERVICE);
    expect(document.body.textContent).toContain('배포 예정 주소예요');
    await click(button('저장'));
    const saved = await call('settings_get');
    expect(saved).toEqual({ gateway_port: 47380, team_listen: '192.168.1.20:47420', link_service: PLANNED_SERVICE });
    expect((await call('link_status')).default_service).toBe(PLANNED_SERVICE);
    expect(document.body.textContent).not.toMatch(/운영 ?중/);
  });

  it('refuses an address with a path and clears back to the built-in default', async () => {
    await seed({});
    await render('server');
    const field = document.querySelector<HTMLInputElement>('input[placeholder="https://"]')!;
    await type(field, 'https://zeropw-turn.telicity.ai/api');
    await click(button('저장'));
    expect(document.body.textContent).toContain('https://로 시작하는 서버 주소만');
    expect((await call('settings_get')).link_service).toBeUndefined();
    await type(field, PLANNED_SERVICE);
    await click(button('저장'));
    expect((await call('settings_get')).link_service).toBe(PLANNED_SERVICE);
    await type(field, '');
    await click(button('저장'));
    expect((await call('settings_get')).link_service).toBeUndefined();
  });
});

describe('damaged settings', () => {
  it('offers to write the defaults only after a confirmation', async () => {
    await seed({ settingsCorrupt: true });
    await render('developer');
    expect(document.body.textContent).toContain('설정 파일이 망가져서 읽지 못했어요');
    await expect(call('settings_get')).rejects.toMatchObject({ reason: 'settings_corrupt' });
    await click(button('기본값으로 되돌리기'));
    expect(dialog()?.textContent).toContain('47380');
    await click(button('기본값으로 되돌리기', dialog()!));
    expect(await call('settings_get')).toEqual({ gateway_port: 47380, team_listen: null });
    expect(toast).toHaveBeenCalledWith('기본값으로 되돌리고 로컬 서비스를 다시 켰어요', 'ok');
  });
});

describe('backup and restore', () => {
  it('asks for the administrator passphrase before restoring', async () => {
    await seed({});
    await render('backup');
    await click(button('백업 만들기…'));
    expect(toast).toHaveBeenCalledWith(expect.stringContaining('백업을 만들었어요'), 'ok');
    await click(button('백업에서 복원…'));
    const d = dialog()!;
    expect(d.textContent).toContain('지금 금고 내용이 백업 내용으로 바뀌어요');
    await click(button('파일 고르고 복원', d));
    expect(dialog()!.textContent).toContain('관리 비밀번호를 입력해 주세요');
    const pass = dialog()!.querySelector<HTMLInputElement>('input[type="password"]')!;
    await type(pass, 'wrong-pass');
    await click(button('파일 고르고 복원', dialog()!));
    expect(dialog()!.textContent).toContain('관리 비밀번호가 맞지 않아요');
    expect(pass.value).toBe('');
    await type(dialog()!.querySelector<HTMLInputElement>('input[type="password"]')!, 'mock-admin-pass');
    await click(button('파일 고르고 복원', dialog()!));
    expect(dialog()).toBeNull();
    expect((await call('control_get')).restore_pending).toBe(true);
  });
});

describe('diagnostics', () => {
  it('shows value-free state', async () => {
    await seed({ linkEnrolled: true });
    await render('about');
    // the summary stays short; addresses and paths are under 자세한 상태
    expect(document.body.textContent ?? '').not.toContain('127.0.0.1:47380');
    const more = document.querySelector<HTMLDetailsElement>('details.more')!;
    await act(async () => { more.open = true; more.dispatchEvent(new Event('toggle')); });
    await settle();
    const text = document.body.textContent ?? '';
    expect(text).toContain('127.0.0.1:47380');
    expect(text).not.toContain('mock-admin-pass');
  });
});
