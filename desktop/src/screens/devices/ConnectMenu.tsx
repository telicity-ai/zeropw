// The one entry point for connecting Macs: a pull-down button with the two sides of pairing.
// "Show a code on this Mac" (add) needs this Mac registered with the server; while it is not,
// the item stays focusable and says why when chosen.

import { useEffect, useId, useRef, useState } from 'react';
import { t, type CopyKey } from '../../copy';
import { Button } from '../../ui/controls';
import { Icon, type IconName } from '../../ui/icons';

export function ConnectMenu({ blocker, onAdd, onJoin }: { blocker: CopyKey | null; onAdd(): void; onJoin(): void }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false); };
    window.addEventListener('mousedown', close);
    setTimeout(() => box.current?.querySelector<HTMLButtonElement>('.menu-item')?.focus(), 0);
    return () => window.removeEventListener('mousedown', close);
  }, [open]);
  const pick = (fn: () => void) => { setOpen(false); fn(); };
  const item = (icon: IconName, label: CopyKey, sub: CopyKey, fn: () => void, blocked?: boolean) => (
    <button type="button" role="menuitem" className="menu-item mac-connect-item" aria-disabled={blocked || undefined}
      onClick={() => pick(fn)}>
      <Icon name={icon} size={16} />
      <span className="mac-connect-text">
        <span>{t(label)}</span>
        <small>{blocked && blocker ? t(blocker) : t(sub)}</small>
      </span>
    </button>
  );
  return (
    <div className="menu-anchor" ref={box} style={{ position: 'relative' }}
      onKeyDown={(e) => {
        if (!open) return;
        if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); setOpen(false); box.current?.querySelector<HTMLButtonElement>('button')?.focus(); return; }
        if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
          e.preventDefault();
          const items = [...(box.current?.querySelectorAll<HTMLButtonElement>('.menu-item') ?? [])];
          const i = items.indexOf(document.activeElement as HTMLButtonElement);
          items[(i + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length]?.focus();
        }
      }}>
      <Button size="sm" tone="primary" iconEnd="chevron-down" aria-haspopup="menu" aria-expanded={open} aria-controls={id} onClick={() => setOpen((o) => !o)}>
        {t('mac.connect')}
      </Button>
      {open && (
        <div id={id} role="menu" aria-label={t('mac.connect')} className="menu glass mac-connect-menu" style={{ right: 0, top: 'calc(100% + 6px)' }}>
          {item('plus', 'mac.add', 'mac.add.sub', onAdd, blocker !== null)}
          {item('link', 'mac.join', 'mac.join.sub', onJoin)}
        </div>
      )}
    </div>
  );
}
