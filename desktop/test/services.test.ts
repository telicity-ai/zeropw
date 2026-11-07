// @vitest-environment jsdom
// The service connections page against the mock backend: what the list and detail show, the
// HTTP create flow (credential stored once, then the connection with the passphrase and the
// chosen methods), an error landing under its own field, and disabling with confirmation.

import { act, createElement as h } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ShellContext, type Route, type ShellApi, type VaultData } from '../src/app/shell';
import { t } from '../src/copy';
import { call, useMockBackend } from '../src/ipc/client';
import { createMockBackend, type MockBackend } from '../src/ipc/mock';
import { connectionFacts, createErrorField, liveGrantsFor } from '../src/screens/services/logic';
import { ServicesPage } from '../src/screens/services/ServicesPage';
import { AppContext, type AppApi } from '../src/ui/app';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const ADMIN = 'mock-admin-pass';
let backend: MockBackend;
let root: Root;
let host: HTMLDivElement;
const app: AppApi = { desktop: false, toast: vi.fn(), announce: vi.fn(), locale: 'ko', language: 'system', setLanguage: async () => undefined };

async function vaultData(): Promise<VaultData> {
  const [listing, secrets] = await Promise.all([call('project_list'), call('secret_list', {})]);
  return { listing, secrets: secrets.secrets };
}

async function shell(route: Route): Promise<ShellApi> {
  const data = await vaultData();
  return {
    route, go: vi.fn(), clearIntent: vi.fn(), tick: 0, activity: 0, bump: vi.fn(),
    control: { stopped: false, restore_pending: false, incident_open: false },
    serve: { running: true, url: 'http://127.0.0.1:47380', pid: 1, team_listen: null },
    setControl: vi.fn(), setServe: vi.fn(),
    relay: { busy: false, problem: null, start: async () => true, run: (task) => task(), report: vi.fn(), teamListen: null, offerListenOff: false, confirmListenOff: vi.fn() },
    vault: { data, error: null, loading: false, reload: vi.fn() },
    envFile: null, takeEnvFile: vi.fn(), invite: null, takeInvite: vi.fn(), lock: vi.fn(),
    narrow: { rail: false, single: false },
  };
}

async function settle(ms = 20) { await act(async () => { await new Promise((r) => setTimeout(r, ms)); }); }
async function render(route: Route = { page: 'services' }) {
  const value = await shell(route);
  await act(async () => { root.render(h(AppContext.Provider, { value: app }, h(ShellContext.Provider, { value }, h(ServicesPage, {})))); });
  await settle(40);
  return value;
}
function button(text: string, within: ParentNode = document.body): HTMLButtonElement {
  const found = [...within.querySelectorAll<HTMLButtonElement>('button')].find((b) => b.getAttribute('aria-label') === text || b.textContent?.trim() === text);
  if (!found) throw new Error(`Missing button: ${text}`);
  return found;
}
async function click(el: HTMLElement) { await act(async () => { el.click(); }); await settle(); }
async function type(name: string, value: string) {
  const el = document.querySelector<HTMLInputElement>(`[name="${name}"]`);
  if (!el) throw new Error(`Missing input ${name}`);
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
}
const dialog = () => document.querySelector<HTMLElement>('[role="dialog"]');
const fieldOf = (name: string) => document.querySelector(`[name="${name}"]`)?.closest('.field') ?? null;
async function openMore() {
  const more = dialog()!.querySelector<HTMLDetailsElement>('details.more')!;
  await act(async () => { more.open = true; more.dispatchEvent(new Event('toggle')); });
  await settle();
}
async function choose(name: string, value: string) {
  const el = document.querySelector<HTMLSelectElement>(`select[name="${name}"]`);
  if (!el) throw new Error(`Missing select ${name}`);
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')!.set!.call(el, value);
    el.dispatchEvent(new Event('change', { bubbles: true }));
  });
}
const menuButton = (label: string) => document.querySelector<HTMLButtonElement>(`button[aria-label="${label}"]`)!;

beforeEach(() => {
  backend = createMockBackend({ initialized: true, sshWithoutCli: true });
  useMockBackend(backend);
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root.unmount());
  host.remove();
  document.body.innerHTML = '';
  backend.dispose();
  useMockBackend(null);
});

describe('connection facts', () => {
  it('read the HTTP target, auth and scope, and the SSH target without its ssh', async () => {
    const { connections } = await call('connection_list');
    const http = connectionFacts(connections.find((c) => c.id === 'example-api')!);
    expect(http).toMatchObject({ kind: 'http', origin: 'https://api.example.com', tls: true, methods: ['GET', 'HEAD', 'POST'], confirm: ['POST'], cli: null });
    const ssh = connectionFacts(connections.find((c) => c.id === 'deploy-ssh')!);
    expect(ssh).toMatchObject({ kind: 'ssh', host: 'git.example.com', user: 'git', cli: null });
  });
  it('count only live grants of the connection', async () => {
    const { grants } = await call('grant_list', {});
    // one live, one expired, one used up on example-api (mock seed)
    expect(liveGrantsFor(grants, 'example-api', Date.now())).toHaveLength(1);
  });
  it('map path errors to the program field of the connection type', () => {
    expect(createErrorField('cli_program_not_found', true)).toEqual(['sshCli', 'conn.cli.err.notFound']);
    expect(createErrorField('cli_program_not_found', false)).toEqual(['cli', 'conn.cli.err.notFound']);
    expect(createErrorField('metadata_address_not_allowed', false)?.[0]).toBe('target');
    expect(createErrorField('something_else', false)).toBeNull();
  });
});

describe('services page', () => {
  it('lists both connections and offers an ssh path for the SSH one without it', async () => {
    await render({ page: 'services', item: 'deploy-ssh' });
    const rows = [...host.querySelectorAll('[role="option"]')].map((r) => r.getAttribute('data-id'));
    expect(rows).toEqual(expect.arrayContaining(['example-api', 'deploy-ssh']));
    expect(host.querySelector('[role="option"][data-id="deploy-ssh"]')?.textContent).toContain(t('service.state.nocli'));
    expect(host.textContent).toContain(t('service.d.nocli'));
    expect(host.querySelectorAll('button').length).toBeGreaterThan(0);
    button(t('service.sshcli'), host);
    // no value of any credential is on the page
    expect(host.textContent).not.toMatch(/sk_test_mock_|mock-ssh-key-/);
  });

  it('shows the HTTP scope with the confirm-each-time method marked and the live agent', async () => {
    await render({ page: 'services', item: 'example-api' });
    const detail = host.querySelector('.svc-detail')!;
    expect(detail.textContent).toContain('https://api.example.com');
    expect(detail.querySelector('.svc-methods-text')?.textContent).toContain(t('service.d.method.confirm', { m: 'POST' }));
    expect(detail.textContent).toContain('agent-1');
    expect(detail.textContent).toContain(t('service.scope.text'));
  });

  it('creates an HTTP connection: the key once, then the connection with the passphrase and methods', async () => {
    await render({ page: 'services', item: 'example-api' });
    await click(button(t('service.add'), host));
    expect(dialog()).not.toBeNull();
    // only the essentials show: the method chips wait behind "더 보기"
    expect(dialog()!.querySelector('.svc-method')).toBeNull();
    await type('conn-id', 'github-api');
    await type('conn-target', 'https://api.github.com');
    // an item already in the vault is offered first; this connection gets a new value
    await choose('conn-key-pick', '__new__');
    await settle();
    await openMore();
    // POST: off → confirm each time
    await click(dialog()!.querySelector<HTMLButtonElement>('.svc-method[aria-label^="POST"]')!);
    await type('conn-key', 'ghp_synthetic_value_0001');
    await type('conn-pass', 'not-the-passphrase');
    await click(button(t('service.c.submit'), dialog()!));
    // the wrong passphrase lands under the passphrase field; the key was stored already
    expect(fieldOf('conn-pass')?.textContent).toContain(t('error.auth'));
    expect(backend.calls().filter((c) => c === 'secret_put')).toHaveLength(1);
    expect(fieldOf('conn-key')?.textContent).toContain(t('service.c.key.stored'));
    await type('conn-pass', ADMIN);
    await click(button(t('service.c.submit'), dialog()!));
    await settle(40);
    expect(dialog()).toBeNull();
    const log = backend.calls();
    expect(log.filter((c) => c === 'secret_put')).toHaveLength(1);
    expect(log.indexOf('secret_put')).toBeLessThan(log.lastIndexOf('connection_create_http'));
    const made = (await call('connection_list')).connections.find((c) => c.id === 'github-api')!;
    expect(connectionFacts(made)).toMatchObject({ methods: ['GET', 'HEAD', 'POST'], confirm: ['POST'], origin: 'https://api.github.com' });
    expect(made.secret_id).toBe('github-api');
    // the dialog's typed value is gone from the page
    expect(document.body.textContent).not.toContain('ghp_synthetic_value_0001');
  });

  it('puts a client-side check under its field and focuses it', async () => {
    await render();
    await click(button(t('service.add'), host));
    await type('conn-id', 'example-api');
    await type('conn-target', 'http://169.254.169.254');
    await click(button(t('service.c.submit'), dialog()!));
    await settle(10);
    expect(fieldOf('conn-id')?.textContent).toContain(t('service.c.err.exists'));
    expect(fieldOf('conn-target')?.textContent).toContain(t('service.c.url.err.meta'));
    expect(document.activeElement?.getAttribute('name')).toBe('conn-id');
    expect(backend.calls()).not.toContain('secret_put');
  });

  it('shows only the SSH essentials and opens "더 보기" for an error inside it', async () => {
    await render();
    await click(button(t('service.add'), host));
    await click([...dialog()!.querySelectorAll<HTMLButtonElement>('[role="radio"]')].find((b) => b.textContent?.includes(t('service.c.type.ssh')))!);
    for (const n of ['conn-ssh-id', 'conn-ssh-user', 'conn-ssh-host', 'conn-ssh-hostkey', 'conn-pass']) expect(document.querySelector(`[name="${n}"]`), n).not.toBeNull();
    expect(document.querySelector('[name="conn-ssh-port"]')).toBeNull();
    await openMore();
    await type('conn-ssh-port', '99999');
    await act(async () => { const d = dialog()!.querySelector<HTMLDetailsElement>('details.more')!; d.open = false; d.dispatchEvent(new Event('toggle')); });
    await settle();
    expect(document.querySelector('[name="conn-ssh-port"]')).toBeNull();
    await click(button(t('service.c.submit'), dialog()!));
    await settle(80);
    expect(fieldOf('conn-ssh-port')?.textContent).toContain(t('service.c.ssh.port.err'));
    expect(backend.calls()).not.toContain('connection_create_ssh');
  });

  it('disables a connection only after confirming', async () => {
    await render({ page: 'services', item: 'example-api' });
    await click(menuButton(t('service.more.aria')));
    await click(button(t('service.disable'), document.querySelector<HTMLElement>('[role="menu"]')!));
    expect(dialog()?.textContent).toContain(t('service.disable.warn'));
    expect(backend.calls()).not.toContain('connection_disable');
    await click(button(t('service.disable.confirm'), dialog()!));
    await settle(40);
    expect(backend.calls()).toContain('connection_disable');
    const c = (await call('connection_list')).connections.find((x) => x.id === 'example-api')!;
    expect(c.status).toBe('disabled');
  });

  it('gives the SSH connection its ssh with the passphrase and says grants go stale', async () => {
    await render({ page: 'services', item: 'deploy-ssh' });
    await click(button(t('service.sshcli'), host));
    expect(dialog()?.textContent).toContain(t('service.sshcli.regrant'));
    await type('sshcli-path', '/usr/bin/nope');
    const pass = dialog()!.querySelector<HTMLInputElement>('input[type="password"]')!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(pass, ADMIN);
      pass.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await click(button(t('service.sshcli.confirm'), dialog()!));
    await settle(40);
    expect(fieldOf('sshcli-path')?.textContent).toContain(t('conn.cli.err.notFound'));
  });
});
