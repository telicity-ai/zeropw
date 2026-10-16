import type { CopyKey } from '../copy';

export type PageId = 'home' | 'keys' | 'connections' | 'agents' | 'logs' | 'team' | 'settings';

export interface PageMeta { id: PageId; label: CopyKey; sub: CopyKey }

/** Sidebar order (DESIGN.md §5.3). */
export const PAGES: readonly PageMeta[] = [
  { id: 'home', label: 'nav.home', sub: 'home.sub' },
  { id: 'keys', label: 'nav.keys', sub: 'page.keys.sub' },
  { id: 'connections', label: 'nav.connections', sub: 'page.connections.sub' },
  { id: 'agents', label: 'nav.agents', sub: 'page.agents.sub' },
  { id: 'logs', label: 'nav.logs', sub: 'page.logs.sub' },
  { id: 'team', label: 'nav.team', sub: 'page.team.sub' },
  { id: 'settings', label: 'nav.settings', sub: 'page.settings.sub' },
];

export const pageMeta = (id: PageId): PageMeta => PAGES.find((p) => p.id === id) ?? (PAGES[0] as PageMeta);
