// Small pieces the developer tabs share.

import { useEffect, useRef } from 'react';
import { t } from '../../copy';
import type { Grant } from '../../ipc/contract';
import type { Intent } from '../../app/shell';
import { shortTime } from '../../lib/format';

export type DevTab = 'agents' | 'approvals' | 'sharing';
export const DEV_TABS: readonly DevTab[] = ['agents', 'approvals', 'sharing'];

export const asTab = (v: string | undefined): DevTab => (DEV_TABS.includes(v as DevTab) ? (v as DevTab) : 'agents');

/** The tab an intent belongs to. */
export function intentTab(i: Intent | undefined): DevTab | null {
  if (i === 'add-agent' || i === 'add-grant') return 'agents';
  if (i === 'invite' || i === 'join' || i === 'share') return 'sharing';
  return null;
}

/** `user-agent` → other account `agent`; `default` → this account. */
export function runtimeText(runtime: string): string {
  if (runtime === 'default') return t('agent.where.same.text');
  if (runtime.startsWith('user-')) return t('agent.where.other.text', { user: runtime.slice(5) });
  return runtime;
}

export function grantText(g: Grant): string {
  const uses = g.max_uses !== null && g.max_uses !== undefined
    ? t('grant.usesOf', { n: String(g.uses), max: String(g.max_uses) }) : t('grant.uses', { n: String(g.uses) });
  return `${t('grant.until', { time: shortTime(String(g.expires_at)) })} · ${uses}`;
}

export const roleText = (r: string): string => (r === 'admin' ? t('share.role.admin') : r === 'user' ? t('share.role.user') : r);

/** Run `handle` once for an intent; it returns true when it took the intent. */
export function useIntentOnce(intent: Intent | undefined, clear: () => void, handle: (i: Intent) => boolean, ready = true): void {
  const fn = useRef(handle);
  fn.current = handle;
  useEffect(() => {
    if (!intent || !ready) return;
    if (fn.current(intent)) clear();
  }, [intent, ready, clear]);
}
