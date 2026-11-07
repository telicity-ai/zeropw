// @vitest-environment jsdom
// The vault page against the in-memory mock backend: what the list shows for a view and a
// search, the empty states, adding an item, revealing a value behind the passphrase, revoking a
// version and permanently deleting an identity after fresh reauthentication.
import { act, createElement as h, useState } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NO_CONTROL, ShellContext, type Route, type ShellApi } from '../src/app/shell';
import { setLocale, t } from '../src/copy';
import { call, useMockBackend } from '../src/ipc/client';
import { createMockBackend, type MockBackend } from '../src/ipc/mock';
import { VaultPage } from '../src/screens/vault/VaultPage';
import { filterItems, parseView, sortItems } from '../src/screens/vault/logic';
import { AppContext, type AppApi } from '../src/ui/app';
import { useLoad } from '../src/ui/hooks';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const ADMIN = 'mock-admin-pass';
const toast = vi.fn();
const app: AppApi = { desktop: false, toast, announce: () => undefined, locale: 'ko', language: 'system', setLanguage: async () => undefined };
let root: Root, host: HTMLDivElement, backend: MockBackend, spy: ReturnType<typeof vi.fn>;

function Harness({ start }: { start: Route }) {
  const [r, setR] = useState<Route>(start);
  const [tick, setTick] = useState(0);
  const vault = useLoad(async () => {
    const [listing, s] = await Promise.all([call('project_list'), call('secret_list', {})]);
    return { listing, secrets: s.secrets };
  }, [tick]);
  const noop = () => undefined;
  const api: ShellApi = {
    route: r, go: (page, opts) => setR({ page, ...opts }), clearIntent: () => setR((x) => ({ ...x, intent: undefined })),
    tick, activity: 0, bump: () => setTick((k) => k + 1), control: NO_CONTROL,
    serve: { running: true, url: 'http://127.0.0.1:47380', pid: 1, team_listen: null }, setControl: noop, setServe: noop,
    relay: { busy: false, problem: null, start: async () => true, run: (task) => task(), report: noop, teamListen: null, offerListenOff: false, confirmListenOff: noop },
    vault, envFile: null, takeEnvFile: noop, invite: null, takeInvite: noop, lock: noop, narrow: { rail: false, single: false },
  };
  return h(AppContext.Provider, { value: app }, h(ShellContext.Provider, { value: api }, h(VaultPage, { intent: r.intent })));
}

async function settle(ms = 15) { await act(async () => { await new Promise((res) => setTimeout(res, ms)); }); }
async function render(start: Route = { page: 'vault', view: 'all' }) {
  await act(async () => root.render(h(Harness, { start })));
  await settle(); await settle();
}
const text = () => document.body.textContent ?? '';
function button(label: string, within: ParentNode = document.body): HTMLButtonElement {
  const found = [...within.querySelectorAll<HTMLButtonElement>('button')].find((b) => b.textContent?.trim() === label || b.getAttribute('aria-label') === label);
  if (!found) throw new Error(`Missing button: ${label}`);
  return found;
}
async function click(el: HTMLElement) { await act(async () => el.click()); await settle(); }
function field(label: string): HTMLInputElement {
  const l = [...document.querySelectorAll('label')].find((x) => x.textContent?.trim() === label);
  const el = l ? document.getElementById(l.htmlFor) : null;
  if (!el) throw new Error(`Missing field: ${label}`);
  return el as HTMLInputElement;
}
async function type(el: HTMLInputElement, value: string) {
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await settle();
}
async function submit() {
  const form = document.querySelector<HTMLFormElement>('.dialog form');
  await act(async () => { form!.requestSubmit(); });
  await settle(40);
}
const dialog = () => document.querySelector<HTMLElement>('.dialog');
const kindOption = (label: string) => [...document.querySelectorAll<HTMLButtonElement>('.dialog [role="radio"]')].find((b) => b.textContent?.includes(label))!;
const rows = () => [...host.querySelectorAll<HTMLElement>('.lrow .lrow-title')].map((x) => x.textContent);

beforeEach(() => {
  if (!(globalThis as { CSS?: unknown }).CSS) (globalThis as { CSS?: unknown }).CSS = { escape: (s: string) => s };
  if (!HTMLFormElement.prototype.requestSubmit) HTMLFormElement.prototype.requestSubmit = function () { this.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); };
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  toast.mockClear();
  setLocale('ko');
});
afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
  document.body.replaceChildren();
  backend?.dispose();
  useMockBackend(null);
  setLocale('ko');
});

function useBackend(b: MockBackend) {
  backend = b;
  spy = vi.fn(b.call.bind(b));
  useMockBackend({ ...b, call: spy as MockBackend['call'] });
}

describe('vault logic', () => {
  it('reads the route view and filters by kind, place and words', () => {
    expect(parseView('kind:password')).toEqual({ by: 'kind', kind: 'password' });
    expect(parseView('kind:nope')).toEqual({ by: 'all' });
    expect(parseView('place:demo/dev')).toEqual({ by: 'place', place: 'demo/dev' });
    const items = [
      { id: 'b-key', project: 'demo', environment: 'dev', kind: 'api_key' as const, active_version: 1, versions: [{ version: 1, status: 'active', created_at: '2026-01-02T00:00:00Z' }] },
      { id: 'a-pass', project: 'demo', environment: 'prod', kind: 'password' as const, active_version: 1, versions: [{ version: 1, status: 'active', created_at: '2026-01-01T00:00:00Z' }] },
    ];
    expect(filterItems(items, { by: 'kind', kind: 'password' }, '').map((s) => s.id)).toEqual(['a-pass']);
    expect(filterItems(items, { by: 'place', place: 'demo/dev' }, '').map((s) => s.id)).toEqual(['b-key']);
    expect(filterItems(items, { by: 'all' }, 'prod').map((s) => s.id)).toEqual(['a-pass']);
    expect(filterItems(items, { by: 'all' }, t('nav.kind.api_key')).map((s) => s.id)).toEqual(['b-key']);
    expect(sortItems(items, 'name').map((s) => s.id)).toEqual(['a-pass', 'b-key']);
    expect(sortItems(items, 'recent').map((s) => s.id)).toEqual(['b-key', 'a-pass']);
  });
});

describe('vault page', () => {
  it('lists the items of the view and narrows them with a search', async () => {
    useBackend(createMockBackend({ initialized: true, latency: 0 }));
    await render();
    expect(rows()).toEqual(['db-password', 'example-api', 'sentry-dsn']);
    // no value is ever on the page
    expect(text()).not.toMatch(/sk_test_mock_|mock-db-/);
    await type(host.querySelector<HTMLInputElement>('input[type="search"]')!, 'sentry');
    expect(rows()).toEqual(['sentry-dsn']);
    await type(host.querySelector<HTMLInputElement>('input[type="search"]')!, 'zzz-nothing');
    expect(rows()).toEqual([]);
    expect(text()).toContain(t('vault.empty.search.title'));
  });

  it('follows a kind filter, and tells an empty filter from an empty vault', async () => {
    useBackend(createMockBackend({ initialized: true, latency: 0 }));
    await render({ page: 'vault', view: 'kind:password' });
    expect(rows()).toEqual(['db-password']);
    await act(async () => root.unmount());
    root = createRoot(host);
    await render({ page: 'vault', view: 'kind:ssh_private_key' });
    expect(rows()).toEqual([]);
    expect(text()).toContain(t('vault.empty.filter.title'));
    expect(text()).not.toContain(t('vault.empty.title'));
  });

  it('shows a first-run empty vault apart from a filtered one', async () => {
    const b = createMockBackend({ latency: 0 });
    const code = await b.call('recovery_generate', undefined);
    await b.call('vault_init', { admin_passphrase: 'correct-horse-battery-staple-91', recovery: { ref: code.ref } });
    useBackend(b);
    await render();
    expect(text()).toContain(t('vault.empty.title'));
    expect(button(t('vault.empty.add'))).toBeTruthy();
    expect(button(t('vault.import'))).toBeTruthy();
  });

  it('adds an API key with a typed value through secret_put', async () => {
    useBackend(createMockBackend({ initialized: true, latency: 0 }));
    await render();
    await click(button(t('vault.add.aria')));
    expect(dialog()?.textContent).toContain(t('vault.add.title'));
    // the kind is one compact choice; the place and file options wait behind "더 보기"
    await click(kindOption(t('nav.kind.api_key')));
    expect(dialog()?.querySelector('details.more')?.hasAttribute('open')).toBe(false);
    expect(dialog()?.querySelector('select')).toBeNull();
    // nothing typed: the name and value are asked for, nothing is sent
    await submit();
    expect(spy.mock.calls.some((c) => c[0] === 'secret_put')).toBe(false);
    expect(dialog()?.textContent).toContain(t('vault.err.name'));
    await type(field(t('vault.add.name')), 'openai-api');
    await type(field(t('vault.add.value')), 'sk-synthetic-0123');
    await submit();
    const put = spy.mock.calls.find((c) => c[0] === 'secret_put');
    expect(put?.[1]).toMatchObject({ id: 'openai-api', kind: 'api_key', source: { typed: 'sk-synthetic-0123' } });
    expect(dialog()).toBeNull();
    expect(backend.inspect().secrets).toContain('openai-api');
    await settle();
    expect(rows()).toContain('openai-api');
    expect(text()).not.toContain('sk-synthetic-0123');
  });

  it('generates an SSH key in Rust and shows only its public half', async () => {
    useBackend(createMockBackend({ initialized: true, latency: 0 }));
    await render();
    await click(button(t('vault.add.aria')));
    await click(kindOption(t('nav.kind.ssh_private_key')));
    // a new key is made by default: no value to type
    await type(field(t('vault.add.name')), 'deploy-key');
    await submit();
    expect(spy.mock.calls.find((c) => c[0] === 'secret_put')?.[1]).toMatchObject({ kind: 'ssh_private_key', source: { generate_ed25519: true } });
    expect(dialog()?.textContent).toContain(t('vault.pub.title'));
    expect(dialog()?.querySelector('.vault-pub')?.textContent).toMatch(/^ssh-ed25519 /);
  });

  it('reveals a value only after the passphrase, then hides it', async () => {
    useBackend(createMockBackend({ initialized: true, latency: 0 }));
    await render({ page: 'vault', view: 'all', item: 'example-api' });
    await click(button(t('vault.act.reveal')));
    await submit();
    expect(dialog()?.textContent).toContain(t('pass.err.empty'));
    expect(spy.mock.calls.some((c) => c[0] === 'secret_reveal')).toBe(false);
    await type(field(t('pass.label')), 'wrong-pass');
    await submit();
    expect(dialog()?.textContent).toContain(t('error.auth'));
    expect(spy.mock.calls.some((c) => c[0] === 'onetime_show')).toBe(false);
    await type(field(t('pass.label')), ADMIN);
    await submit();
    await settle(60);
    const value = dialog()?.querySelector('.onetime-value')?.textContent ?? '';
    expect(value).toMatch(/^sk_test_mock_/);
    expect(dialog()?.textContent).toContain(t('onetime.left', { s: 30 }));
    await click(button(t('act.hide'), dialog()!));
    expect(dialog()?.querySelector('.onetime-value')?.textContent).toBe(t('onetime.hiddenMask'));
    expect(text()).not.toMatch(/sk_test_mock_/);
  });

  it('revokes a version after a danger confirmation that names the provider', async () => {
    useBackend(createMockBackend({ initialized: true, latency: 0 }));
    await render({ page: 'vault', view: 'all', item: 'example-api' });
    // version actions sit in the version's menu
    await click(button(t('vault.version.more.aria', { n: 1 })));
    await click(button(t('vault.version.revoke'), document.querySelector<HTMLElement>('[role="menu"]')!));
    expect(dialog()?.textContent).toContain(t('vault.provider.note'));
    await submit();
    expect(spy.mock.calls.find((c) => c[0] === 'secret_revoke')?.[1]).toEqual({ id: 'example-api', version: 1 });
    const s = await call('secret_versions', { id: 'example-api' });
    expect(s.versions.find((v) => String(v.version) === '1')?.status).toBe('revoked');
    expect(toast).toHaveBeenCalledWith(t('vault.toast.revoked'), 'warn');
  });

  it.each(['ko', 'en'] as const)('reauthenticates a permanent deletion and reports pending in %s', async (locale) => {
    setLocale(locale);
    useBackend(createMockBackend({ initialized: true, latency: 0 }));
    const original = spy.getMockImplementation()!;
    spy.mockImplementation(async (cmd, input) => cmd === 'secret_delete'
      ? { secret_id: input.id, status: 'deleted', permanent_id: true, provider_revocation_required: true, sync_status: 'pending' }
      : original(cmd, input));
    await render({ page: 'vault', view: 'all', item: 'example-api' });
    await click(button(t('vault.delete.action')));
    expect(dialog()?.textContent).toContain('example-api');
    expect(dialog()?.textContent).toContain(t('vault.delete.warn'));
    expect(dialog()?.textContent).toContain(t('vault.delete.provider'));
    await submit();
    expect(dialog()?.textContent).toContain(t('pass.err.empty'));
    expect(spy.mock.calls.filter((c) => c[0] === 'secret_delete')).toHaveLength(0);
    await type(field(t('pass.label')), ADMIN);
    const reloads = spy.mock.calls.filter((c) => c[0] === 'secret_list').length;
    await submit();
    expect(spy.mock.calls.filter((c) => c[0] === 'secret_delete').map((c) => c[1])).toEqual([{ id: 'example-api', admin_passphrase: ADMIN }]);
    expect(dialog()).toBeNull();
    expect(toast).toHaveBeenCalledWith(t('vault.toast.deleted.pending'), 'warn');
    expect(toast).not.toHaveBeenCalledWith(t('vault.toast.deleted.local'), 'warn');
    expect(spy.mock.calls.filter((c) => c[0] === 'secret_list').length).toBeGreaterThan(reloads);
    expect(text()).not.toContain(ADMIN);
    // Closing a completed dialog cannot carry the previous password into another delete.
    await click(button(t('vault.delete.action')));
    expect(field(t('pass.label')).value).toBe('');
  });

  it('reports local durability and reloads deleted metadata/history while blocking use', async () => {
    useBackend(createMockBackend({ initialized: true, latency: 0 }));
    const original = spy.getMockImplementation()!;
    let deleted = false;
    spy.mockImplementation(async (cmd, input) => {
      if (cmd === 'secret_delete') {
        deleted = true;
        return { secret_id: input.id, status: 'deleted', permanent_id: true, provider_revocation_required: true, sync_status: 'local' };
      }
      const out = await original(cmd, input);
      // Test-owned metadata fixture; the real mock intentionally has no durable deletion.
      if (cmd === 'secret_list' && deleted) return { ...out, secrets: out.secrets.map((s: { id: string }) => s.id === 'example-api' ? { ...s, deleted: true } : s) };
      return out;
    });
    await render({ page: 'vault', view: 'all', item: 'example-api' });
    await click(button(t('vault.delete.action')));
    await type(field(t('pass.label')), ADMIN);
    await submit();
    await settle();
    expect(toast).toHaveBeenCalledWith(t('vault.toast.deleted.local'), 'warn');
    expect(text()).toContain(t('vault.deleted.title'));
    expect(text()).toContain(t('vault.versions'));
    expect(text()).toContain(t('vault.version.n', { n: 1 }));
    expect(rows()).toContain('example-api');
    expect(rows()).toContain('db-password');
    const buttons = [...host.querySelectorAll('button')].map((b) => b.getAttribute('aria-label') ?? b.textContent?.trim());
    for (const label of [t('vault.act.reveal'), t('vault.act.copy'), t('vault.act.replace'), t('vault.delete.action'), t('vault.detail.more'), t('vault.version.more.aria', { n: 1 })]) expect(buttons).not.toContain(label);
  });

  it.each([
    ['AuthFailed', 'admin_reauth_failed', 'error.auth'],
    ['PolicyDenied', 'team_fact_not_authorized', 'team.err.adminOnly'],
    ['PolicyDenied', 'member_removed', 'team.err.adminOnly'],
    ['InternalError', 'storage_failed', 'error.generic'],
  ] as const)('retains the item/dialog after %s/%s and clears the password', async (error, reason, key) => {
    useBackend(createMockBackend({ initialized: true, latency: 0 }));
    const original = spy.getMockImplementation()!;
    spy.mockImplementation(async (cmd, input) => {
      if (cmd === 'secret_delete') throw { error, reason };
      return original(cmd, input);
    });
    await render({ page: 'vault', view: 'all', item: 'example-api' });
    await click(button(t('vault.delete.action')));
    await type(field(t('pass.label')), ADMIN);
    await submit();
    expect(dialog()?.textContent).toContain(t(key));
    expect(field(t('pass.label')).value).toBe('');
    expect(rows()).toContain('example-api');
    expect(text()).not.toContain(t('vault.deleted.title'));
    expect(toast).not.toHaveBeenCalled();
    await submit();
    expect(spy.mock.calls.filter((c) => c[0] === 'secret_delete')).toHaveLength(1);
    await type(field(t('pass.label')), 'cancelled-password');
    await click(button(t('act.cancel'), dialog()!));
    await click(button(t('vault.delete.action')));
    expect(field(t('pass.label')).value).toBe('');
  });

  it('guards duplicate submit and closure while deletion is busy', async () => {
    useBackend(createMockBackend({ initialized: true, latency: 0 }));
    const original = spy.getMockImplementation()!;
    let finish!: () => void;
    const pending = new Promise<void>((resolve) => { finish = resolve; });
    spy.mockImplementation(async (cmd, input) => {
      if (cmd !== 'secret_delete') return original(cmd, input);
      await pending;
      return { secret_id: input.id, status: 'deleted', permanent_id: true, provider_revocation_required: true, sync_status: 'pending' };
    });
    await render({ page: 'vault', view: 'all', item: 'example-api' });
    await click(button(t('vault.delete.action')));
    await type(field(t('pass.label')), ADMIN);
    await submit(); await submit();
    expect(spy.mock.calls.filter((c) => c[0] === 'secret_delete')).toHaveLength(1);
    expect(button(t('act.cancel'), dialog()!).getAttribute('aria-disabled')).toBe('true');
    await click(button(t('act.cancel'), dialog()!));
    expect(dialog()).not.toBeNull();
    await act(async () => document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true })));
    expect(dialog()).not.toBeNull();
    await act(async () => finish()); await settle();
    expect(dialog()).toBeNull();
  });

  it('keeps mock deletion explicitly unsupported', async () => {
    useBackend(createMockBackend({ initialized: true, latency: 0 }));
    await expect(call('secret_delete', { id: 'example-api', admin_passphrase: ADMIN })).rejects.toMatchObject({ reason: 'mock_unsupported' });
    expect(backend.inspect().secrets).toContain('example-api');
  });
});
