import { createElement, type ReactElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { DashContext, type DashApi } from '../src/dashboard/context';
import { LogsPage } from '../src/dashboard/Logs';
import type { Field } from '../src/field/field';
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
