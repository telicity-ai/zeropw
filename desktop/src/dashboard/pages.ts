import type { CopyKey } from '../copy';

export type PageId = 'home' | 'keys' | 'connections' | 'agents' | 'logs' | 'team' | 'settings';

export interface PageMeta { id: PageId; label: CopyKey; sub: CopyKey; empty: CopyKey | null }

/** Sidebar order (DESIGN.md §5.3). Pages other than home are filled in by later slices. */
export const PAGES: readonly PageMeta[] = [
  { id: 'home', label: 'nav.home', sub: 'home.sub', empty: null },
  { id: 'keys', label: 'nav.keys', sub: 'page.keys.sub', empty: 'page.keys.empty' },
  { id: 'connections', label: 'nav.connections', sub: 'page.connections.sub', empty: 'page.connections.empty' },
  { id: 'agents', label: 'nav.agents', sub: 'page.agents.sub', empty: 'page.agents.empty' },
  { id: 'logs', label: 'nav.logs', sub: 'page.logs.sub', empty: 'page.logs.empty' },
  { id: 'team', label: 'nav.team', sub: 'page.team.sub', empty: 'page.team.empty' },
  { id: 'settings', label: 'nav.settings', sub: 'page.settings.sub', empty: 'page.settings.empty' },
];

export const pageMeta = (id: PageId): PageMeta => PAGES.find((p) => p.id === id) ?? (PAGES[0] as PageMeta);
