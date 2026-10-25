import type { CopyKey } from '../copy';
import type { ModeTargets } from '../field/field';
import type { Pill } from '../ui/context';

// Onboarding v0.5 (DESIGN.md §5.2, docs/desktop-app.md §7): no service connection step.
export type Step = 'welcome' | 'admin' | 'recovery' | 'create' | 'project' | 'agent' | 'join' | 'done';
export type CardStep = Exclude<Step, 'welcome' | 'done'>;

export const FULL: readonly Step[] = ['admin', 'recovery', 'create', 'project', 'agent'];
export const JOIN_FLOW: readonly Step[] = ['admin', 'recovery', 'create'];

export const TITLE: Record<Exclude<Step, 'welcome'>, CopyKey> = {
  admin: 'admin.title',
  recovery: 'rec.title',
  create: 'create.title.run',
  project: 'proj.title',
  agent: 'agent.title',
  join: 'join.title',
  done: 'done.title',
};

export const counted = (joining: boolean): readonly Step[] => (joining ? JOIN_FLOW : FULL);
export const flow = (joining: boolean): Step[] => ['welcome', ...counted(joining), 'done'];
export const isCard = (s: Step): s is CardStep => s !== 'welcome' && s !== 'done';

/** Previous / next step in the current flow (join is reached only from welcome). */
export function neighbour(s: Step, joining: boolean, dir: -1 | 1): Step {
  const f = flow(joining), i = f.indexOf(s);
  if (i < 0) return 'welcome';
  return f[Math.min(f.length - 1, Math.max(0, i + dir))] ?? 'welcome';
}

/** Where the onboarding goes when the vault exists, the relay would not start and the user goes
 *  on without it: a join still happens on the finale; otherwise the dashboard, which has the
 *  relay's start button and the port setting (the agent step needs a running relay). */
export const afterRelayFailure = (joining: boolean): 'done' | 'dashboard' => (joining ? 'done' : 'dashboard');

/** The title bar's status during the onboarding: no vault until `vault_init` made one, then the
 *  relay off (also while a relay that would not start waits for a retry or for the user to go on
 *  without it), then the relay's address once it runs (desktop E2E F1). */
export function onboardingPill(vaultMade: boolean, relay: { addr: string | null } | null): Pill {
  if (relay) return { kind: 'live', addr: relay.addr };
  return vaultMade ? { kind: 'off' } : { kind: 'none' };
}

/** Progress label "n/total" for the live region, or null outside the counted steps. */
export function progressOf(s: Step, joining: boolean): { index: number; total: number } | null {
  const list = counted(joining), i = list.indexOf(s);
  return i < 0 ? null : { index: i, total: list.length };
}

/** Extra field targets per step; onboarding never has a service connection. */
export function fieldExtras(s: Step, ctx: { agent: boolean; joining: boolean }): ModeTargets | null {
  if (s === 'agent') return { svc: 0, mem: 0.35 };
  if (s === 'done') return { agent: ctx.agent ? 0.8 : 0, svc: 0, mem: 0.3, peer: ctx.joining ? 0.8 : 0 };
  return null;
}
