import { createElement, type ReactElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, describe, expect, it } from 'vitest';
import { CreateConnectionSheet } from '../src/dashboard/Connections';
import { DashContext, type DashApi } from '../src/dashboard/context';
import { AddKeySheet } from '../src/dashboard/Keys';
import { LogsPage } from '../src/dashboard/Logs';
import type { Field } from '../src/field/field';
import { call, useMockBackend } from '../src/ipc/client';
import { createMockBackend, type MockBackend } from '../src/ipc/mock';
import { teamEnvPairs } from '../src/lib/dash';
import { AppContext, type AppApi } from '../src/ui/context';

// Pages and sheets rendered once to static markup, as they first appear (effects and the core
// calls they start do not run here): what a page opens on, which choices a sheet offers.

const noop = (): void => undefined;
const app: AppApi = { field: { ripple: noop } as unknown as Field, desktop: false, motionOn: false, toast: noop, announce: noop, setPill: noop };
const dash: DashApi = {
  go: noop, tick: 0, activity: 0, bump: noop, setControl: noop, setServe: noop,
  control: { stopped: false, restore_pending: false, incident_open: false },
  serve: { running: true, url: 'http://127.0.0.1:47380', pid: 1, team_listen: null },
  relay: { busy: false, problem: null, start: async () => true, run: (task) => task(), report: noop, teamListen: null, offerListenOff: false, confirmListenOff: noop },
};

function render(el: ReactElement): string {
  return renderToStaticMarkup(createElement(AppContext.Provider, { value: app }, createElement(DashContext.Provider, { value: dash }, el)));
}

/** The option values of a <select>, by its id. */
function options(html: string, id: string): string[] {
  const from = html.indexOf(`<select id="${id}"`);
  if (from < 0) return [];
  const select = html.slice(from, html.indexOf('</select>', from));
  return [...select.matchAll(/<option value="([^"]*)"/g)].map((m) => m[1] ?? '');
}

let backend: MockBackend | null = null;
afterEach(() => { backend?.dispose(); backend = null; useMockBackend(null); });

/** The value of the checked radio in a group. */
function checked(html: string, name: string): string | null {
  const tag = (html.match(/<input [^>]*>/g) ?? []).find((x) => x.includes(`name="${name}"`) && x.includes('checked=""'));
  return tag ? /value="([^"]*)"/.exec(tag)?.[1] ?? null : null;
}

describe('records page', () => {
  // desktop E2E F2: the home's "모두 보기" under recent alerts opened the usage records
  it('opens on the alerts when the home sends the user to its alerts', () => {
    expect(checked(render(createElement(LogsPage, { intent: 'alerts', onIntent: noop })), 'logs-tab')).toBe('alerts');
    expect(checked(render(createElement(LogsPage, { onIntent: noop })), 'logs-tab')).toBe('audit');
    expect(checked(render(createElement(LogsPage, { intent: 'add-key', onIntent: noop })), 'logs-tab')).toBe('audit');
  });
});

describe('sheets that pick an environment', () => {
  // pr4-state-display-2: only the .env import offered an environment this device joined
  it('offer a team environment this device joined when adding a key or a connection', async () => {
    backend = createMockBackend({ latency: 0, initialized: true });
    useMockBackend(backend);
    const { ref } = await call('team_invite_preview', { text: 'zeropw://join#' + 'abcdefghijklmnopqrstuvwxyz234567'.repeat(8) });
    await call('team_join', { ref, project: 'team-x', environment: 'shared' });
    const listing = await call('project_list');
    expect(listing.projects.map((p) => p.name)).toEqual(['demo']);   // a joined environment is in no project
    const pairs = teamEnvPairs(listing);
    const key = render(createElement(AddKeySheet, { open: true, data: { kind: 'add' }, pairs, taken: [], onClose: noop, onSaved: noop }));
    expect(options(key, 'key-env')).toEqual(['demo/dev', 'demo/staging', 'demo/prod', 'team-x/shared']);
    const conn = render(createElement(CreateConnectionSheet, { open: true, pairs, connections: [], secrets: [], onClose: noop, onCreated: noop }));
    expect(options(conn, 'conn-env')).toEqual(['demo/dev', 'demo/staging', 'demo/prod', 'team-x/shared']);
  });
});
