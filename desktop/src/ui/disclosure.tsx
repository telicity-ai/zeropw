// Progressive disclosure: a form shows what is required first, and everything optional sits
// behind one quiet "더 보기" row (`More`). Secondary actions sit in a glass popover (`Menu`).

import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { t } from '../copy';
import { IconButton } from './controls';
import { Icon, type IconName } from './icons';

/** Optional fields. `open` forces it open (e.g. an error inside); the person can still toggle. */
export function More({ label, hint, open, children, onToggle }: {
  label?: ReactNode; hint?: ReactNode; open?: boolean; children: ReactNode; onToggle?(open: boolean): void;
}) {
  const [shown, setShown] = useState(!!open);
  useEffect(() => { if (open) setShown(true); }, [open]);
  return (
    <details className="more" open={shown} onToggle={(e) => { const o = (e.currentTarget as HTMLDetailsElement).open; setShown(o); onToggle?.(o); }}>
      <summary>
        <Icon name="chevron-right" size={13} />
        {label ?? t('act.more')}
        {hint && !shown && <span className="more-hint">{hint}</span>}
      </summary>
      {shown && <div className="more-body">{children}</div>}
    </details>
  );
}

export interface MenuEntry { label: string; icon?: IconName; onSelect(): void; danger?: boolean; checked?: boolean; disabled?: boolean; /** Accessible name when the label alone does not say what it acts on. */ aria?: string }

/** A glass popover menu opened from an icon button. Arrow keys move, Escape closes. */
export function Menu({ label, icon = 'more', items, align = 'end' }: { label: string; icon?: IconName; items: readonly (MenuEntry | 'sep')[]; align?: 'start' | 'end' }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false); };
    window.addEventListener('mousedown', close);
    setTimeout(() => box.current?.querySelector<HTMLButtonElement>('.menu-item:not([disabled])')?.focus(), 0);
    return () => window.removeEventListener('mousedown', close);
  }, [open]);
  return (
    <div className="menu-anchor" ref={box} style={{ position: 'relative' }}
      onKeyDown={(e) => {
        if (!open) return;
        if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); setOpen(false); box.current?.querySelector<HTMLButtonElement>('button')?.focus(); return; }
        if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
          e.preventDefault();
          const items = [...(box.current?.querySelectorAll<HTMLButtonElement>('.menu-item:not([disabled])') ?? [])];
          const i = items.indexOf(document.activeElement as HTMLButtonElement);
          items[(i + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length]?.focus();
        }
      }}>
      <IconButton icon={icon} label={label} size="sm" aria-haspopup="menu" aria-expanded={open} aria-controls={id} onClick={() => setOpen((o) => !o)} />
      {open && (
        <div id={id} role="menu" className="menu glass" style={align === 'end' ? { right: 0, top: 'calc(100% + 6px)' } : { left: 0, top: 'calc(100% + 6px)' }}>
          {items.map((it, i) => it === 'sep' ? <div key={i} className="menu-sep" role="separator" /> : (
            <button key={i} type="button" role="menuitem" className="menu-item" disabled={it.disabled} aria-label={it.aria} style={it.danger ? { color: 'var(--danger)' } : undefined}
              onClick={() => { setOpen(false); it.onSelect(); }}>
              {it.icon && <Icon name={it.icon} size={15} />}{it.label}
              {it.checked && <Icon name="check" size={13} className="menu-check" />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
