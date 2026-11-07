// Pane building blocks shared by every screen: a pane header that is also the window's drag
// region, the list's search box, selectable list rows with arrow-key movement, static rows and
// kind tiles.

import { forwardRef, useCallback, type KeyboardEvent, type ReactNode, type Ref } from 'react';
import { t } from '../copy';
import type { SecretKind } from '../ipc/contract';
import { IconButton } from './controls';
import { Icon, type IconName } from './icons';

/** A pane's top bar. `title` is the page heading when `level` is 1 (focused after navigation). */
export function PaneHeader({ title, sub, actions, level = 1, onBack, titleRef }: {
  title: ReactNode; sub?: ReactNode; actions?: ReactNode; level?: 1 | 2; onBack?(): void; titleRef?: Ref<HTMLHeadingElement>;
}) {
  const H = level === 1 ? 'h1' : 'h2';
  return (
    <header className="pane-head" data-tauri-drag-region="">
      {onBack && <IconButton icon="chevron-left" label={t('nav.back')} size="sm" onClick={onBack} />}
      {title ? <H tabIndex={-1} ref={titleRef} data-page-title={level === 1 ? '' : undefined} data-tauri-drag-region="">
        {title}{sub && <> <span className="pane-head-sub">{sub}</span></>}
      </H> : <div className="grow" data-tauri-drag-region="" />}
      {actions && <div className="pane-actions">{actions}</div>}
    </header>
  );
}

export const SearchBox = forwardRef(function SearchBox({ value, onChange, placeholder, label, onKeyDown }: {
  value: string; onChange(v: string): void; placeholder: string; label: string; onKeyDown?(e: KeyboardEvent<HTMLInputElement>): void;
}, ref: Ref<HTMLInputElement>) {
  return (
    <div className="search" role="search">
      <Icon name="search" size={14} />
      <input ref={ref} type="search" value={value} placeholder={placeholder} aria-label={label} spellCheck={false} autoCorrect="off" autoCapitalize="off"
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Escape' && value) { e.preventDefault(); e.stopPropagation(); onChange(''); return; }
          onKeyDown?.(e);
        }} />
      {value && <IconButton icon="close" label={t('act.clear')} size="sm" onClick={() => onChange('')} />}
    </div>
  );
});

const KIND_ICON: Record<SecretKind, IconName> = { password: 'password', api_key: 'key', env_var: 'env', ssh_private_key: 'ssh' };
export const kindIcon = (k: SecretKind): IconName => KIND_ICON[k] ?? 'key';

export function KindTile({ kind, size }: { kind: SecretKind; size?: 'lg' }) {
  return <span className={`tile tile-${kind}` + (size ? ' tile-lg' : '')} aria-hidden="true"><Icon name={kindIcon(kind)} /></span>;
}

export function IconTile({ icon, tone = 'device', size }: { icon: IconName; tone?: 'device' | 'service'; size?: 'lg' }) {
  return <span className={`tile tile-${tone}` + (size ? ' tile-lg' : '')} aria-hidden="true"><Icon name={icon} /></span>;
}

/** Arrow keys, Home and End move the selection in a listbox of `.lrow` options. */
export function useListKeys(ids: readonly string[], selected: string | null, select: (id: string) => void, open?: (id: string) => void) {
  return useCallback((e: KeyboardEvent<HTMLElement>) => {
    if (e.nativeEvent.isComposing) return;
    if (!ids.length) return;
    const i = selected ? ids.indexOf(selected) : -1;
    let next: string | undefined;
    if (e.key === 'ArrowDown') next = ids[Math.min(ids.length - 1, i + 1)];
    else if (e.key === 'ArrowUp') next = ids[Math.max(0, i < 0 ? 0 : i - 1)];
    else if (e.key === 'Home') next = ids[0];
    else if (e.key === 'End') next = ids[ids.length - 1];
    else if (e.key === 'Enter' && selected && open) { e.preventDefault(); open(selected); return; }
    if (next === undefined) return;
    e.preventDefault();
    select(next);
    const host = e.currentTarget.closest('[role="listbox"]') ?? e.currentTarget;
    const el = host.querySelector<HTMLElement>(`[data-id="${CSS.escape(next)}"]`);
    el?.focus({ preventScroll: false });
    el?.scrollIntoView({ block: 'nearest' });
  }, [ids, selected, select, open]);
}

/** One option of a listbox: roving focus (only the selected row is in the tab order). */
export function ListRow({ id, selected, onSelect, lead, title, meta, end, onKeyDown, label }: {
  id: string; selected: boolean; onSelect(): void; lead?: ReactNode; title: ReactNode; meta?: ReactNode; end?: ReactNode;
  onKeyDown?(e: KeyboardEvent<HTMLElement>): void; label?: string;
}) {
  return (
    <div role="option" aria-selected={selected} tabIndex={selected ? 0 : -1} data-id={id} className="lrow" aria-label={label}
      onClick={onSelect} onKeyDown={onKeyDown} onFocus={() => { if (!selected) onSelect(); }}>
      {lead}
      <div className="lrow-main">
        <span className="lrow-title">{title}</span>
        {meta && <span className="lrow-meta">{meta}</span>}
      </div>
      {end && <div className="lrow-end">{end}</div>}
    </div>
  );
}

/** Meta pieces joined with a middle dot; empty pieces are left out. */
export function Meta({ parts }: { parts: readonly (ReactNode | null | undefined | false)[] }) {
  const shown = parts.filter((p) => p !== null && p !== undefined && p !== false && p !== '');
  return <>{shown.map((p, i) => <span key={i} className={i > 0 ? 'sep-before' : undefined}>{i > 0 && <span className="sep" aria-hidden="true" />}{p}</span>)}</>;
}

/** A static row in a bordered group (`.rows`). */
export function StaticRow({ lead, title, meta, end, onClick, label }: { lead?: ReactNode; title: ReactNode; meta?: ReactNode; end?: ReactNode; onClick?(): void; label?: string }) {
  const body = (
    <>
      {lead}
      <div className="srow-main">
        <span className="srow-title">{title}</span>
        {meta && <span className="srow-meta">{meta}</span>}
      </div>
      {end && <div className="srow-end">{end}</div>}
    </>
  );
  if (onClick) return <button type="button" className="srow is-button" onClick={onClick} aria-label={label}>{body}</button>;
  return <div className="srow">{body}</div>;
}
