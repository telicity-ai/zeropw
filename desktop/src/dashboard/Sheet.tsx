import { useEffect, useRef, type ReactNode } from 'react';
import { t } from '../copy';

/** Right-hand sheet with the onboarding card's shape (DESIGN.md §5.3). Escape or the scrim closes
 *  it; focus moves in on open and back to the trigger on close. */
export function Sheet({ id, open, title, lead, children, primaryLabel, busy, onPrimary, onClose }: {
  id: string; open: boolean; title: string; lead?: string; children?: ReactNode;
  primaryLabel: string; busy?: boolean; onPrimary(): void; onClose(): void;
}) {
  const box = useRef<HTMLDivElement>(null);
  const opener = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    opener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const timer = setTimeout(() => {
      const el = box.current?.querySelector<HTMLElement>('.step-body input') ?? box.current?.querySelector<HTMLElement>('h2');
      el?.focus({ preventScroll: true });
    }, 60);
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') { e.preventDefault(); onClose(); } };
    document.addEventListener('keydown', onKey);
    return () => {
      clearTimeout(timer);
      document.removeEventListener('keydown', onKey);
      opener.current?.focus({ preventScroll: true });
    };
  }, [open, onClose]);

  return (
    <>
      {open && <div className="scrim on" onClick={onClose} aria-hidden="true" />}
      <div className={'sheet-wrap' + (open ? '' : ' away')} inert={!open} role="dialog" aria-modal="true" aria-labelledby={`${id}-title`} ref={box}>
        <div className="card">
          <form className="sheet" onSubmit={(e) => { e.preventDefault(); if (!busy) onPrimary(); }}>
            <div className="step-head">
              <h2 id={`${id}-title`} tabIndex={-1}>{title}</h2>
              {lead && <p className="lead">{lead}</p>}
            </div>
            <div className="step-body">{children}</div>
            <div className="nav">
              <button className="btn btn-text" type="button" onClick={onClose}>{t('common.cancel')}</button>
              <button className="btn btn-primary" type="submit" aria-busy={busy} aria-disabled={busy}>{primaryLabel}</button>
            </div>
          </form>
        </div>
      </div>
    </>
  );
}
