// @vitest-environment jsdom
import { act, createElement } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { App, IDLE_LOCK_MIN } from '../src/app/App';
import { COPY } from '../src/copy';
import { useMockBackend } from '../src/ipc/client';
import { createMockBackend, type MockBackend, type MockSeed } from '../src/ipc/mock';

// The window's phases against the mock core: an existing vault opens locked, the lock screen
// checks the passphrase through vault_unlock and says nothing else on failure, the open vault
// shows the sidebar with the vault first, and ⌘L locks again.

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let backend: MockBackend | null = null;
let root: Root | null = null;
let host: HTMLDivElement;

function seed(s: MockSeed) {
  backend = createMockBackend({ latency: 0, ...s });
  useMockBackend(backend);
}
async function settle(n = 8) {
  for (let i = 0; i < n; i++) await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}
async function mount() {
  await act(async () => { root = createRoot(host); root.render(createElement(App)); });
  await settle();
}
function setInput(el: HTMLInputElement, value: string) {
  const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
  set.call(el, value);
  el.dispatchEvent(new Event('input', { bubbles: true }));
}
const text = () => document.body.textContent ?? '';

beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  window.matchMedia = ((q: string) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {} })) as unknown as typeof window.matchMedia;
});
afterEach(async () => {
  await act(async () => { root?.unmount(); });
  root = null;
  host.remove();
  backend?.dispose(); backend = null; useMockBackend(null);
});

describe('first run and lock', () => {
  it('starts the first run when there is no vault', async () => {
    seed({ initialized: false });
    await mount();
    expect(text()).not.toContain(COPY['lock.title']);
  });

  it('opens an existing vault locked, refuses a wrong passphrase and opens with the right one', async () => {
    seed({ initialized: true });
    await mount();
    expect(text()).toContain(COPY['lock.title']);
    expect(text()).toContain(COPY['lock.note']);
    const input = host.querySelector<HTMLInputElement>('.lock input[type="password"]')!;
    const form = host.querySelector<HTMLFormElement>('.lock form, form.lock-card')!;

    await act(async () => { form.requestSubmit(); });
    await settle();
    expect(text()).toContain(COPY['pass.err.empty']);

    await act(async () => { setInput(input, 'not-it'); });
    await act(async () => { form.requestSubmit(); });
    await settle();
    expect(text()).toContain(COPY['lock.err']);
    expect(input.value).toBe('');
    // the failed attempt is a record the user can see later, without the typed text
    const records = await backend!.call('audit_tail', { limit: 20 });
    expect(JSON.stringify(records)).toContain('auth_failed');
    expect(JSON.stringify(records)).not.toContain('not-it');

    await act(async () => { setInput(input, 'mock-admin-pass'); });
    await act(async () => { form.requestSubmit(); });
    await settle(12);
    expect(text()).not.toContain(COPY['lock.title']);
    const nav = host.querySelector('aside.sidebar')!;
    expect(nav.textContent).toContain(COPY['nav.all']);
    expect(nav.textContent).toContain(COPY['nav.devices']);
    // the vault comes first in the sidebar, settings last
    const labels = [...nav.querySelectorAll('.nav-item .nav-label')].map((n) => n.textContent);
    expect(labels[0]).toBe(COPY['nav.all']);
    expect(labels[labels.length - 1]).toBe(COPY['nav.settings']);

    // ⌘L locks again
    await act(async () => { window.dispatchEvent(new KeyboardEvent('keydown', { key: 'l', metaKey: true })); });
    await settle();
    expect(text()).toContain(COPY['lock.title']);
  });

  it('locks after the idle time', () => {
    expect(IDLE_LOCK_MIN).toBeGreaterThanOrEqual(5);
    expect(IDLE_LOCK_MIN).toBeLessThanOrEqual(30);
  });
});

describe('the local service in the sidebar', () => {
  it('shows a stop for every use, and resume asks for the passphrase', async () => {
    seed({ initialized: true });
    await mount();
    const input = host.querySelector<HTMLInputElement>('.lock input[type="password"]')!;
    await act(async () => { setInput(input, 'mock-admin-pass'); });
    await act(async () => { host.querySelector<HTMLFormElement>('form.lock-card')!.requestSubmit(); });
    await settle(12);
    const stop = [...host.querySelectorAll<HTMLButtonElement>('.sidebar-foot button')].find((b) => b.textContent === COPY['svc.stopAll'])!;
    expect(stop).toBeTruthy();
    await act(async () => { stop.click(); });
    await settle();
    const dialog = document.querySelector('[role="dialog"]')!;
    expect(dialog.textContent).toContain(COPY['stop.title']);
    await act(async () => { (dialog.querySelector('form') as HTMLFormElement).requestSubmit(); });
    await settle(12);
    expect((await backend!.call('control_get', undefined)).stopped).toBe(true);
    const resume = [...host.querySelectorAll<HTMLButtonElement>('.sidebar-foot button')].find((b) => b.textContent === COPY['svc.resume'])!;
    await act(async () => { resume.click(); });
    await settle();
    const d2 = document.querySelector('[role="dialog"]')!;
    expect(d2.querySelector('input[type="password"]')).toBeTruthy();
    await act(async () => { (d2.querySelector('form') as HTMLFormElement).requestSubmit(); });
    await settle();
    expect(d2.textContent).toContain(COPY['pass.err.empty']);
  });
});
