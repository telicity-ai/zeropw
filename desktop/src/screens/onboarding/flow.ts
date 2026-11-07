// The first run's steps and where each choice at the end goes. Both paths ("new vault" and
// "connect to another Mac's vault") create this Mac's own local vault first: pairing needs a
// vault on both Macs (docs/remote-sync.md §4).

import type { CopyKey } from '../../copy';
import type { Route } from '../../app/shell';

export type Step = 'welcome' | 'admin' | 'recovery' | 'create' | 'done';
export type Path = 'new' | 'connect';

/** The counted steps, in order. */
export const COUNTED: readonly Step[] = ['admin', 'recovery', 'create'];
export const FLOW: readonly Step[] = ['welcome', ...COUNTED, 'done'];

export const STEP_TITLE: Record<Exclude<Step, 'welcome' | 'done'>, CopyKey> = {
  admin: 'setup.step.admin',
  recovery: 'setup.step.recovery',
  create: 'setup.step.create',
};

/** Previous or next step. */
export function neighbour(s: Step, dir: -1 | 1): Step {
  const i = FLOW.indexOf(s);
  if (i < 0) return 'welcome';
  return FLOW[Math.min(FLOW.length - 1, Math.max(0, i + dir))] ?? 'welcome';
}

/** "n of total" for a counted step, or null for welcome and done. */
export function progressOf(s: Step): { index: number; total: number } | null {
  const i = COUNTED.indexOf(s);
  return i < 0 ? null : { index: i, total: COUNTED.length };
}

/** Going back is allowed until the vault exists (the secrets it uses must not change after). */
export const canGoBack = (s: Step, created: boolean): boolean => s !== 'welcome' && s !== 'done' && !created;

export interface DoneAction { key: CopyKey; route: Route; tone: 'primary' | 'secondary' | 'ghost' }

/** The choices at the end. The connect path leads to joining with the other Mac's code; a new
 *  vault leads to its first item, with adding another Mac as a second choice. An invite link the
 *  app received during the first run is offered too (the open vault holds it). */
export function doneActions(path: Path, hasInvite: boolean): DoneAction[] {
  const first: DoneAction = { key: 'setup.done.first', route: { page: 'vault', view: 'all', intent: 'add' }, tone: 'primary' };
  const out: DoneAction[] = path === 'connect'
    ? [{ key: 'setup.done.connect', route: { page: 'devices', intent: 'pair-join' }, tone: 'primary' }, { ...first, tone: 'secondary' }]
    : [first, { key: 'setup.done.addMac', route: { page: 'devices', intent: 'pair-add' }, tone: 'secondary' }];
  if (hasInvite) out.push({ key: 'setup.done.invite', route: { page: 'developer', view: 'sharing', intent: 'join' }, tone: 'secondary' });
  out.push({ key: 'setup.done.later', route: { page: 'vault', view: 'all' }, tone: 'ghost' });
  return out;
}
