// Pure helpers behind the vault page: which items a view and a search show, in which order, and
// how each item's state reads. Nothing here handles a value.

import { t, type CopyKey } from '../../copy';
import type { ConnectionView, SecretKind, SecretView, TeamEnvironment } from '../../ipc/contract';
import { envKey, type EnvPair } from '../../lib/dash';
import { placeLabel } from '../../lib/places';

export const KINDS: readonly SecretKind[] = ['password', 'api_key', 'env_var', 'ssh_private_key'];

export type VaultFilter = { by: 'all' } | { by: 'kind'; kind: SecretKind } | { by: 'place'; place: string };

/** The page's filter from the route view (`all`, `kind:<kind>`, `place:<project>/<env>`). */
export function parseView(view: string | undefined): VaultFilter {
  if (view?.startsWith('kind:')) {
    const k = view.slice(5) as SecretKind;
    if (KINDS.includes(k)) return { by: 'kind', kind: k };
  }
  if (view?.startsWith('place:') && view.length > 6) return { by: 'place', place: view.slice(6) };
  return { by: 'all' };
}

export const kindLabel = (k: string): string => (KINDS.includes(k as SecretKind) ? t(`vault.kind.${k}` as CopyKey) : k);
export const placeOf = (s: Pick<SecretView, 'project' | 'environment'>): string => envKey(String(s.project), String(s.environment));
export const placeText = (key: string): string => {
  const i = key.indexOf('/');
  return i < 0 ? key : placeLabel(key.slice(0, i), key.slice(i + 1));
};

/** When the item last changed: its newest version's creation time (0 when unknown). */
export function newestAt(s: Pick<SecretView, 'versions'>): number {
  let best = 0;
  for (const v of s.versions) {
    const ms = Date.parse(v.created_at);
    if (!Number.isNaN(ms) && ms > best) best = ms;
  }
  return best;
}

export const hasActive = (s: Pick<SecretView, 'active_version'>): boolean =>
  s.active_version !== null && s.active_version !== undefined && String(s.active_version) !== '';

export type ItemState = 'deleted' | 'active' | 'none';
export const itemState = (s: Pick<SecretView, 'active_version' | 'deleted'>): ItemState => (s.deleted ? 'deleted' : hasActive(s) ? 'active' : 'none');

/** Lowercased words a search matches: the id, the kind's name and the place. */
const haystack = (s: SecretView): string => `${s.id} ${kindLabel(s.kind)} ${placeOf(s)} ${placeText(placeOf(s))}`.toLowerCase();

export function filterItems(items: readonly SecretView[], filter: VaultFilter, query: string): SecretView[] {
  const q = query.trim().toLowerCase();
  return items.filter((s) => {
    if (filter.by === 'kind' && s.kind !== filter.kind) return false;
    if (filter.by === 'place' && placeOf(s) !== filter.place) return false;
    return !q || q.split(/\s+/).every((w) => haystack(s).includes(w));
  });
}

export type SortBy = 'name' | 'recent';
export function sortItems(items: readonly SecretView[], by: SortBy): SecretView[] {
  const byName = (a: SecretView, b: SecretView) => (a.id < b.id ? -1 : a.id > b.id ? 1 : placeOf(a) < placeOf(b) ? -1 : 1);
  return items.slice().sort(by === 'recent' ? (a, b) => newestAt(b) - newestAt(a) || byName(a, b) : byName);
}

/** Connections that authenticate with this item. */
export const connectionsUsing = (conns: readonly ConnectionView[], s: Pick<SecretView, 'id'>): ConnectionView[] =>
  conns.filter((c) => c.secret_id === s.id);

/** Whether a place is a team environment (shared from here or joined). */
export const isShared = (teamEnvs: readonly TeamEnvironment[] | undefined, place: string): boolean =>
  (teamEnvs ?? []).some((e) => envKey(e.project, e.environment) === place);

/** Where a new item goes: the place the list is filtered to, else the personal place, else the
 *  first one. */
export function defaultPlace(pairs: readonly EnvPair[], filter: VaultFilter): string {
  if (filter.by === 'place' && pairs.some((p) => p.key === filter.place)) return filter.place;
  return (pairs.find((p) => p.key === 'personal/main') ?? pairs[0])?.key ?? '';
}

/** A version as a stable key; the CLI prints versions as JSON numbers (sent back unchanged). */
export const versionText = (v: string | number): string => String(v);
