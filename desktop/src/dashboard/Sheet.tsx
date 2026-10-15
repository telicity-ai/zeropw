import { useContext, useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { t } from '../copy';
import { SheetHostContext } from './context';

const FOCUSABLE = '.step-body input:not([type=hidden]):not([disabled]), .step-body select:not([disabled]), .step-body textarea:not([disabled])';
const visible = (el: HTMLElement) => (typeof el.checkVisibility === 'function' ? el.checkVisibility() : !!el.offsetParent);
// the control outside any sheet that opened the current chain of sheets (a sheet opened from
// another sheet returns focus to where the first one came from)
let outsideOpener: HTMLElement | null = null;

/** Right-hand sheet with the onboarding card's shape (DESIGN.md §5.3). It renders into the
 *  dashboard's sheet host so the page under it can be made inert while the list stays visible.
 *  Escape or the scrim closes it; focus moves to `[data-autofocus]`, the first field or the title on
 *  open and back to the trigger on close. Content mounts on open and its DOM goes away after the
 *  closing animation. The component that renders the sheet stays mounted, though (useSheets keeps
 *  it until the same kind opens again), so a component that holds a passphrase, secret value or
 *  link in its own state clears it when `open` turns false (`useClearOnClose`). A primary button
 *  that is not ready keeps focus (`aria-disabled`) and calls `onBlocked` to point at what is missing. */
export function Sheet({ id, open, title, lead, children, primaryLabel, busy, ready = true, onPrimary, onBlocked, onClose, back, closeLabel, noCancel, cancelLabel }: {
  id: string; open: boolean; title: string; lead?: string; children?: ReactNode;
  primaryLabel?: string; busy?: boolean; ready?: boolean; onPrimary?(): void; onBlocked?(): void; onClose(): void;
  back?: { label: string; onClick(): void }; closeLabel?: string;
  /** Nothing left to cancel (the action already happened): only the primary button stays. */
  noCancel?: boolean;
  /** The secondary button's text when "cancel" would be wrong (the action already happened). */
  cancelLabel?: string;
}) {
  const host = useContext(SheetHostContext);
  const box = useRef<HTMLDivElement>(null);
  const opener = useRef<HTMLElement | null>(null);
  const [linger, setLinger] = useState(false);
  const wasOpen = useRef(open);
  const close = useRef(onClose);
  close.current = onClose;

  // keep the content for the closing animation, then drop it
  useEffect(() => {
    const was = wasOpen.current;
    wasOpen.current = open;
    if (!was || open) { setLinger(false); return; }
    setLinger(true);
    const tm = setTimeout(() => setLinger(false), 650);
    return () => clearTimeout(tm);
  }, [open]);

  useEffect(() => {
    if (!open || !host) return;
    host.hold(1);
    return () => host.hold(-1);
  }, [open, host]);

  useEffect(() => {
    if (!open) return;
    const active = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    if (active && !active.closest('.sheet-wrap') && active !== document.body) outsideOpener = active;
    opener.current = outsideOpener;
    const timer = setTimeout(() => {
      const root = box.current;
      if (!root) return;
      const auto = root.querySelector<HTMLElement>('[data-autofocus]');
      const first = [...root.querySelectorAll<HTMLElement>(FOCUSABLE)].find(visible);
      (auto ?? first ?? root.querySelector<HTMLElement>('h2'))?.focus({ preventScroll: true });
    }, 60);
    const onKey = (e: globalThis.KeyboardEvent) => { if (e.key === 'Escape' && !e.isComposing) { e.preventDefault(); close.current(); } };
    document.addEventListener('keydown', onKey);
    return () => {
      clearTimeout(timer);
      document.removeEventListener('keydown', onKey);
      const back = opener.current;
      // after the page under the sheet stops being inert, and only if no other sheet took over
      setTimeout(() => {
        if (document.querySelector('.sheet-wrap:not(.away)')) return;
        if (back && back.isConnected && !back.closest('[inert]')) back.focus({ preventScroll: true });
        else document.querySelector<HTMLElement>('.page-head h1')?.focus({ preventScroll: true });
      }, 30);
    };
  }, [open]);

  const submit = () => {
    if (busy || !onPrimary) return;
    if (!ready) { onBlocked?.(); return; }
    onPrimary();
  };
  // Enter that only finishes a Hangul composition must not submit
  const onKeyDown = (e: KeyboardEvent<HTMLFormElement>) => {
    if (e.key === 'Enter' && (e.nativeEvent.isComposing || e.keyCode === 229)) e.preventDefault();
  };

  const showContent = open || linger;
  const node = (
    <>
      {open && <div className="scrim on" onClick={onClose} aria-hidden="true" />}
      <div className={'sheet-wrap' + (open ? '' : ' away')} inert={!open} role="dialog" aria-modal="true" aria-labelledby={`${id}-title`}
        aria-describedby={lead ? `${id}-lead` : undefined} ref={box} id={id}>
        <div className="card">
          {showContent && (
            <form className="sheet" noValidate onKeyDown={onKeyDown} onSubmit={(e) => { e.preventDefault(); submit(); }}>
              <div className="step-head">
                <h2 id={`${id}-title`} tabIndex={-1}>{title}</h2>
                {lead && <p className="lead" id={`${id}-lead`}>{lead}</p>}
              </div>
              <div className="step-body">{children}</div>
              <div className="nav">
                {back
                  ? <button className="btn btn-text" type="button" onClick={back.onClick}><span aria-hidden="true">←</span> <span>{back.label}</span></button>
                  : primaryLabel && !noCancel
                    ? <button className="btn btn-text" type="button" onClick={onClose}>{cancelLabel ?? t('common.cancel')}</button>
                    : <span />}
                {primaryLabel
                  ? <button className="btn btn-primary" type="submit" aria-busy={busy || undefined} aria-disabled={busy || !ready || undefined}>{primaryLabel}</button>
                  : <button className="btn btn-ghost" type="button" onClick={onClose}>{closeLabel ?? t('common.close')}</button>}
              </div>
            </form>
          )}
        </div>
      </div>
    </>
  );
  return host?.el ? createPortal(node, host.el) : node;
}
