// @vitest-environment jsdom
// The first run against the mock backend, which follows the core: password strength gating,
// the generated recovery code confirmed by two groups, `vault_init` with the code's reference,
// the personal place, the local service, and where each final choice goes.
import { act, createElement as h } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Route } from '../src/app/shell';
import { t } from '../src/copy';
import { call, toIpcError, useMockBackend, type IpcError } from '../src/ipc/client';
import type { CommandName } from '../src/ipc/contract';
import { createMockBackend, type MockBackend, type MockSeed } from '../src/ipc/mock';
import { Onboarding } from '../src/screens/onboarding/Onboarding';
import { createVault, ensurePersonalPlace, initFailureOf, InitError, type InitFailure } from '../src/screens/onboarding/vault';
import { AppContext, type AppApi } from '../src/ui/app';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const ADMIN = 'Quiet-River-Lantern-82!';
const OWN_CODE = 'velvet harbor quartz meadow lantern 93';

let backend: MockBackend | null = null;
let log: Array<[CommandName, unknown]> = [];
function fresh(seed: MockSeed = {}): MockBackend {
  backend?.dispose();
  const b = createMockBackend({ latency: 0, ...seed });
  backend = b;
  log = [];
  useMockBackend({ ...b, call: (name, input) => { log.push([name, input]); return b.call(name, input); } });
  return b;
}
const inputsOf = (name: CommandName) => log.filter(([n]) => n === name).map(([, i]) => i);

let root: Root, host: HTMLDivElement;
const app: AppApi = { desktop: true, toast: vi.fn(), announce: vi.fn() };
let finished: Route[] = [];

beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  finished = [];
});
afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
  backend?.dispose(); backend = null; useMockBackend(null);
});

async function settle(ms = 15) {
  for (let i = 0; i < 4; i++) await act(async () => { await new Promise((r) => setTimeout(r, ms)); });
}
async function render(incoming: { ref: string; preview: never } | null = null) {
  await act(async () => root.render(h(AppContext, { value: app }, h(Onboarding, { incoming, onIncomingTaken: () => undefined, onFinish: (r: Route) => { finished.push(r); } }))));
  await settle();
}
function visible(el: Element): boolean {
  for (let e: Element | null = el; e; e = e.parentElement) if ((e as HTMLElement).hidden) return false;
  return true;
}
function button(text: string): HTMLButtonElement {
  const found = [...host.querySelectorAll<HTMLButtonElement>('button')].filter(visible).find((b) => b.textContent?.trim().startsWith(text));
  if (!found) throw new Error(`Missing button: ${text}`);
  return found;
}
function field(label: string): HTMLInputElement {
  const l = [...host.querySelectorAll('label')].filter(visible).find((x) => x.textContent?.trim() === label);
  const el = l && host.ownerDocument.getElementById(l.htmlFor);
  if (!el) throw new Error(`Missing field: ${label}`);
  return el as HTMLInputElement;
}
async function click(el: HTMLElement) { await act(async () => el.click()); await settle(); }
async function type(label: string, value: string) {
  const el = field(label);
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await settle();
}
async function submit() {
  const form = [...host.querySelectorAll('form')].find(visible)!;
  await act(async () => form.requestSubmit());
  await settle();
}
const step = () => [...host.querySelectorAll<HTMLElement>('[data-step]')].find(visible)?.dataset.step;

/** The creation lines all finished: go on from the create step. */
async function created() {
  expect(step()).toBe('create');
  expect(host.querySelectorAll('.mk-lines li[data-state="done"]')).toHaveLength(3);
  await click(button(t('act.continue')));
}
async function throughAdmin() {
  await type(t('setup.admin.field'), ADMIN);
  await type(t('setup.admin.confirm'), ADMIN);
  await submit();
}
async function confirmGenerated() {
  const groups = [...host.querySelectorAll('.rec-g')].map((g) => g.textContent ?? '');
  expect(groups).toHaveLength(6);
  expect(groups.every((g) => /^[A-Z2-7]{4}$/.test(g))).toBe(true);
  await click(field(t('setup.rec.ack')));
  // the code leaves the screen while it is being confirmed
  expect([...host.querySelectorAll('.rec-g')].every((g) => g.textContent === '••••')).toBe(true);
  const slots = [...host.querySelectorAll('label')].filter(visible).map((l) => l.textContent?.match(/^(\d)번째 묶음$/)?.[1]).filter(Boolean).map(Number);
  expect(slots).toHaveLength(2);
  for (const n of slots) await type(t('setup.rec.verify.slot', { n }), groups[n - 1]!);
  return groups;
}

describe('first run', () => {
  it('creates the vault with the generated code, the personal place and the service, then offers the first item', async () => {
    const b = fresh();
    await render();
    expect(step()).toBe('welcome');
    await click(button(t('setup.welcome.new')));
    expect(step()).toBe('admin');

    // a weak passphrase does not go on, a strong one does once both fields match
    await type(t('setup.admin.field'), 'short');
    await type(t('setup.admin.confirm'), 'short');
    await submit();
    expect(step()).toBe('admin');
    expect(inputsOf('password_strength').length).toBeGreaterThan(0);
    await throughAdmin();
    expect(step()).toBe('recovery');
    expect(b.inspect().secureView).toBe(true);

    // a wrong group keeps it here
    const groups = [...host.querySelectorAll('.rec-g')].map((g) => g.textContent ?? '');
    await click(field(t('setup.rec.ack')));
    const slots = [...host.querySelectorAll('label')].filter(visible).map((l) => l.textContent?.match(/^(\d)번째 묶음$/)?.[1]).filter(Boolean).map(Number);
    await type(t('setup.rec.verify.slot', { n: slots[0]! }), 'ZZZZ');
    await submit();
    expect(step()).toBe('recovery');
    expect(host.textContent).toContain(t('setup.rec.verify.need', { n: slots[1]! }));
    await type(t('setup.rec.verify.slot', { n: slots[0]! }), groups[slots[0]! - 1]!);
    await type(t('setup.rec.verify.slot', { n: slots[1]! }), groups[slots[1]! - 1]!);
    await submit();
    await settle();
    await created();

    expect(step()).toBe('done');
    const init = inputsOf('vault_init') as Array<{ admin_passphrase: string; recovery: { ref?: string } }>;
    expect(init).toHaveLength(1);
    const generated = inputsOf('recovery_generate');
    expect(generated).toHaveLength(1);
    expect(typeof init[0]!.recovery.ref).toBe('string');
    expect(init[0]!.admin_passphrase).toBe(ADMIN);
    expect(inputsOf('project_create')).toEqual([{ name: 'personal', environments: ['main'] }]);
    expect(b.inspect()).toMatchObject({ initialized: true, projects: ['personal'] });
    expect((await call('serve_status')).running).toBe(true);
    // the steps that held the secrets are gone
    expect(host.querySelector('[data-step="admin"]')).toBeNull();
    expect(host.querySelector('[data-step="recovery"]')).toBeNull();

    await click(button(t('setup.done.first')));
    expect(finished).toEqual([{ page: 'vault', view: 'all', intent: 'add' }]);
    await click(button(t('setup.done.addMac')));
    await click(button(t('setup.done.later')));
    expect(finished.slice(1)).toEqual([{ page: 'devices', intent: 'pair-add' }, { page: 'vault', view: 'all' }]);
  });

  it('on the connect path leads to joining with the other Mac first', async () => {
    fresh();
    await render();
    await click(button(t('setup.welcome.connect')));
    await throughAdmin();
    await confirmGenerated();
    await submit();
    await settle();
    await created();
    expect(step()).toBe('done');
    await click(button(t('setup.done.connect')));
    expect(finished).toEqual([{ page: 'devices', intent: 'pair-join' }]);
  });

  it('takes a chosen recovery code and refuses one that contains the passphrase', async () => {
    fresh();
    await render();
    await click(button(t('setup.welcome.new')));
    await throughAdmin();
    await click(button(t('setup.rec.own')));
    await type(t('setup.rec.own.field'), `${ADMIN}-copy`);
    expect(host.textContent).toContain(t('setup.rec.own.similar'));
    await type(t('setup.rec.own.field'), OWN_CODE);
    await type(t('setup.rec.own.confirm'), OWN_CODE);
    await click(field(t('setup.rec.ack')));
    await submit();
    await settle();
    await created();
    expect(step()).toBe('done');
    const init = inputsOf('vault_init') as Array<{ recovery: { typed?: string } }>;
    expect(init.map((i) => i.recovery)).toEqual([{ typed: OWN_CODE }]);
    // the generated code it did not use was discarded
    expect(inputsOf('onetime_discard').length).toBeGreaterThan(0);
  });

  it('lets the person finish when the local service does not start', async () => {
    const b = fresh({ relayFails: 2 });
    await render();
    await click(button(t('setup.welcome.new')));
    await throughAdmin();
    await confirmGenerated();
    await submit();
    await settle();
    expect(step()).toBe('create');
    expect(host.textContent).toContain(t('setup.create.err.service'));
    expect(host.textContent).toContain(t('setup.create.service.ok'));
    expect(b.inspect().initialized).toBe(true);
    expect(inputsOf('vault_init')).toHaveLength(1);
    await click(button(t('setup.create.later')));
    expect(step()).toBe('done');
    expect(host.textContent).toContain(t('setup.done.serviceOff'));
    await click(button(t('setup.done.first')));
    expect(finished).toEqual([{ page: 'vault', view: 'all', intent: 'add' }]);
  });

  it('mentions an invite link received during the first run without taking it', async () => {
    fresh();
    await render({ ref: 'r1', preview: {} as never });
    expect(host.textContent).toContain(t('setup.incoming'));
    await click(button(t('setup.welcome.new')));
    await throughAdmin();
    await confirmGenerated();
    await submit();
    await settle();
    await created();
    await click(button(t('setup.done.invite')));
    expect(finished).toEqual([{ page: 'developer', view: 'sharing', intent: 'join' }]);
  });
});

async function failure(p: Promise<unknown>): Promise<InitFailure> {
  try { await p; } catch (e) { if (e instanceof InitError) return e.kind; throw e; }
  throw new Error('expected an InitError');
}
async function rejection(p: Promise<unknown>): Promise<IpcError> {
  try { await p; } catch (e) { return toIpcError(e); }
  throw new Error('expected a rejection');
}
const initCalls = () => inputsOf('vault_init').length;

describe('creating the vault', () => {
  it('treats a vault whose service failed to start as created, and never runs init again', async () => {
    fresh({ relayFails: 1 });
    const rec = await call('recovery_generate');
    await createVault({ admin: ADMIN, recovery: { ref: rec.ref } }, { unsure: false });
    expect((await call('app_status')).initialized).toBe(true);
    expect((await call('serve_status')).running).toBe(false);
    expect(initCalls()).toBe(1);
    expect((await call('serve_start')).running).toBe(true);
  });

  it('sends the person back for a new code when the generated one expired', async () => {
    const b = fresh({ onetimeTtlMs: 1 });
    const rec = await call('recovery_generate');
    await new Promise((r) => setTimeout(r, 5));
    expect(await failure(createVault({ admin: ADMIN, recovery: { ref: rec.ref } }, { unsure: false }))).toBe('recovery_expired');
    expect(b.inspect().initialized).toBe(false);
    expect(await failure(createVault({ admin: ADMIN, recovery: null }, { unsure: false }))).toBe('recovery_expired');
  });

  it('sends the person back when a chosen code contains the passphrase', async () => {
    fresh();
    expect(await failure(createVault({ admin: ADMIN, recovery: { typed: `${ADMIN}-spare-copy` } }, { unsure: false }))).toBe('recovery_weak');
    expect((await call('app_status')).initialized).toBe(false);
  });

  it('offers only a retry when the core cannot say whether the vault exists, and the retry finds it', async () => {
    const b = fresh({ relayFails: 1 });
    const rec = await call('recovery_generate');
    const attempts = { unsure: false };
    b.failNext('app_status', { error: 'IoError', reason: 'status_unreadable' });
    expect(await failure(createVault({ admin: ADMIN, recovery: { ref: rec.ref } }, attempts))).toBe('unknown');
    expect(attempts.unsure).toBe(true);
    await createVault({ admin: 'Another-Passphrase-77!', recovery: { typed: 'some other long recovery phrase' } }, attempts);
    expect(initCalls()).toBe(1);
    expect(attempts.unsure).toBe(false);
  });

  it('counts a personal place that already exists as made', async () => {
    fresh();
    const rec = await call('recovery_generate');
    await createVault({ admin: ADMIN, recovery: { ref: rec.ref } }, { unsure: false });
    await ensurePersonalPlace();
    await ensurePersonalPlace();
    expect((await rejection(call('project_create', { name: 'personal', environments: ['main'] }))).reason).toBe('project_exists');
  });

  it('reads the core reason only when the vault does not exist', () => {
    expect(initFailureOf('onetime_ref_unknown')).toBe('recovery_expired');
    expect(initFailureOf('passphrase_weak', 'recovery')).toBe('recovery_weak');
    expect(initFailureOf('passphrases_identical')).toBe('recovery_weak');
    expect(initFailureOf('passphrase_weak', 'admin')).toBe('failed');
    expect(initFailureOf('state_exists')).toBe('failed');
  });
});
