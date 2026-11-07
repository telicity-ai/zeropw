// Modal dialogs. One focus trap, Escape to close (never while an IME composes or while busy),
// focus back to the opener on close, and the rest of the window inert while a dialog is open.
// A dialog never closes from a click outside it: typed input is not thrown away by accident.

import { useEffect, useId, useLayoutEffect, useRef, useState, type FormEvent, type KeyboardEvent, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { t, type CopyKey } from '../copy';
import { toIpcError } from '../ipc/client';
import { Button, PassField, type ButtonTone } from './controls';
import { Banner } from './feedback';
import { IconButton } from './controls';

let openCount = 0;
function setInert(on: boolean) {
  const shell = typeof document !== 'undefined' ? document.getElementById('app-root') : null;
  openCount = Math.max(0, openCount + (on ? 1 : -1));
  if (shell) {
    if (openCount > 0) shell.setAttribute('inert', '');
    else shell.removeAttribute('inert');
  }
  if (typeof document !== 'undefined') {
    if (openCount > 0) document.body.setAttribute('data-dialog-open', '');
    else document.body.removeAttribute('data-dialog-open');
  }
}

const FOCUSABLE = 'button:not([disabled]), [href], input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export interface DialogProps {
  open: boolean;
  title: ReactNode;
  description?: ReactNode;
  onClose(): void;
  /** While true the dialog cannot be closed (a request is running). */
  busy?: boolean;
  size?: 'sm' | 'md' | 'lg';
  children?: ReactNode;
  /** The action row. With `onSubmit` the body is a form and Enter in a text field submits. */
  footer?: ReactNode;
  onSubmit?(): void;
  /** An extra quiet control at the start of the footer (e.g. "back"). */
  footerStart?: ReactNode;
  id?: string;
}

export function Dialog({ open, title, description, onClose, busy, size = 'md', children, footer, onSubmit, footerStart, id }: DialogProps) {
  const titleId = useId();
  const descId = useId();
  const box = useRef<HTMLDivElement>(null);
  const opener = useRef<HTMLElement | null>(null);
  const busyRef = useRef(busy);
  busyRef.current = busy;
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  useLayoutEffect(() => {
    if (!open) return;
    opener.current = document.activeElement as HTMLElement | null;
    setInert(true);
    return () => {
      setInert(false);
      const back = opener.current;
      opener.current = null;
      // the opener may have gone (a list re-rendered); then the page heading takes focus
      setTimeout(() => {
        if (back && back.isConnected && !document.querySelector('[data-dialog-open]')) back.focus({ preventScroll: true });
        else if (!document.querySelector('[data-dialog-open]')) document.querySelector<HTMLElement>('[data-page-title]')?.focus({ preventScroll: true });
      }, 0);
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const el = box.current;
    if (!el) return;
    const id = setTimeout(() => {
      if (el.contains(document.activeElement)) return;
      const target = el.querySelector<HTMLElement>('[data-autofocus]')
        ?? el.querySelector<HTMLElement>('.dialog-body input:not([type="hidden"]):not([disabled]), .dialog-body select, .dialog-body textarea')
        ?? el.querySelector<HTMLElement>('.dialog-title');
      target?.focus({ preventScroll: true });
    }, 30);
    return () => clearTimeout(id);
  }, [open]);

  if (!open) return null;

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.nativeEvent.isComposing || e.keyCode === 229) {
      // an Enter that only finishes a Hangul composition must not submit
      if (e.key === 'Enter') e.preventDefault();
      return;
    }
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      if (!busyRef.current) closeRef.current();
      return;
    }
    if (e.key === 'Tab') {
      const el = box.current;
      if (!el) return;
      const items = [...el.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((x) => x.offsetParent !== null || x === document.activeElement);
      if (!items.length) return;
      const first = items[0]!, last = items[items.length - 1]!;
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  };

  const submit = (e: FormEvent) => { e.preventDefault(); if (!busyRef.current) onSubmit?.(); };
  const Body = onSubmit ? 'form' : 'div';

  return createPortal(
    <div className="dialog-layer" data-dialog-layer="">
      <div className="dialog-scrim" aria-hidden="true" />
      <div ref={box} id={id} className={`dialog dialog-${size}`} role="dialog" aria-modal="true" aria-labelledby={titleId}
        aria-describedby={description ? descId : undefined} aria-busy={busy || undefined} onKeyDown={onKeyDown}>
        <Body className="dialog-form" onSubmit={onSubmit ? submit : undefined} noValidate={onSubmit ? true : undefined}>
          <header className="dialog-head">
            <div>
              <h2 className="dialog-title" id={titleId} tabIndex={-1}>{title}</h2>
              {description && <p className="dialog-desc" id={descId}>{description}</p>}
            </div>
            <IconButton icon="close" label={t('act.close')} size="sm" blocked={busy} onClick={onClose} />
          </header>
          {children !== undefined && <div className="dialog-body">{children}</div>}
          {(footer || footerStart) && (
            <footer className="dialog-foot">
              <div className="dialog-foot-start">{footerStart}</div>
              <div className="dialog-foot-end">{footer}</div>
            </footer>
          )}
        </Body>
      </div>
    </div>,
    document.body,
  );
}

/** What `errorFor` may answer: a copy key for the form line, `false` when the caller showed the
 *  error itself, `null` for the generic line. */
export type ErrorAnswer = CopyKey | false | null;

/** The error line for a failed re-authenticated call: a wrong or missing passphrase goes under
 *  the passphrase field, anything else to the form. */
export function passErrorKey(e: unknown): CopyKey {
  const err = toIpcError(e);
  if (err.error === 'AuthFailed' && err.reason === 'passphrase_missing') return 'pass.err.empty';
  if (err.error === 'AuthFailed' || err.reason === 'admin_reauth_failed') return 'error.auth';
  if (err.reason === 'passphrase_missing') return 'pass.err.empty';
  return 'error.generic';
}

export const isAuthError = (e: unknown): boolean => {
  const err = toIpcError(e);
  return err.error === 'AuthFailed' || err.reason === 'passphrase_missing' || err.reason === 'admin_reauth_failed';
};

export interface ConfirmProps {
  open: boolean;
  title: ReactNode;
  description?: ReactNode;
  confirmLabel: ReactNode;
  tone?: Extract<ButtonTone, 'primary' | 'danger'>;
  /** Ask for the administrator passphrase and pass it to `run`. */
  needPass?: boolean;
  /** Content above the notes (e.g. what is affected). */
  children?: ReactNode;
  warn?: ReactNode;
  info?: ReactNode;
  run(pass: string): Promise<void>;
  /** Map a failure to the form line; see ErrorAnswer. */
  errorFor?(e: unknown): ErrorAnswer;
  onClose(): void;
  /** A check before running; a copy key blocks with that line. */
  check?(): CopyKey | null;
  size?: 'sm' | 'md';
}

/** A confirmation, optionally re-authenticated. The passphrase is cleared after every attempt
 *  and when the dialog closes; a second click while one runs is ignored. */
export function ConfirmDialog({ open, title, description, confirmLabel, tone = 'primary', needPass, children, warn, info, run, errorFor, onClose, check, size = 'sm' }: ConfirmProps) {
  const [pass, setPass] = useState('');
  const [passErr, setPassErr] = useState<CopyKey | null>(null);
  const [formErr, setFormErr] = useState<CopyKey | null>(null);
  const [busy, setBusy] = useState(false);
  const running = useRef(false);
  const passRef = useRef<HTMLInputElement>(null);
  useEffect(() => { if (!open) { setPass(''); setPassErr(null); setFormErr(null); } }, [open]);

  const go = async () => {
    if (running.current) return;
    const blocked = check?.() ?? null;
    if (blocked) { setFormErr(blocked); return; }
    if (needPass && !pass) { setPassErr('pass.err.empty'); passRef.current?.focus(); return; }
    running.current = true; setBusy(true); setFormErr(null); setPassErr(null);
    try {
      await run(pass);
    } catch (e) {
      if (needPass && isAuthError(e)) { setPassErr(passErrorKey(e)); passRef.current?.focus(); }
      else {
        const k = errorFor ? errorFor(e) : null;
        if (k !== false) setFormErr(k ?? 'error.generic');
      }
    } finally {
      running.current = false; setBusy(false); setPass('');
    }
  };

  return (
    <Dialog open={open} title={title} description={description} onClose={onClose} busy={busy} size={size} onSubmit={() => void go()}
      footer={<>
        <Button tone="ghost" onClick={onClose} blocked={busy}>{t('act.cancel')}</Button>
        <Button tone={tone} type="submit" busy={busy}>{confirmLabel}</Button>
      </>}>
      {children}
      {warn && <Banner tone="warn">{warn}</Banner>}
      {info && <Banner tone="info">{info}</Banner>}
      {needPass && (
        <PassField value={pass} onChange={(v) => { setPass(v); setPassErr(null); }} inputRef={passRef}
          error={passErr ? t(passErr) : null} data-autofocus="" />
      )}
      {formErr && <Banner tone="danger">{t(formErr)}</Banner>}
    </Dialog>
  );
}
