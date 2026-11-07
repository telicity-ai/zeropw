// A one-time value the core holds behind a reference (docs/desktop-app.md §4.3): a revealed
// secret, an agent's token, an invite link or a pairing code. The webview receives the text only
// through `onetime_show`, once, and paints it only after the window's capture-exclusion request
// was answered (ui/secure.ts); `onetime_copy` hands it to the clipboard from Rust instead. Either
// one uses the value up. A reference nobody used is discarded when this view goes away.

import { useEffect, useRef, useState } from 'react';
import { t } from '../copy';
import { call, toIpcError } from '../ipc/client';
import { useApp } from './app';
import { Button } from './controls';
import { Icon } from './icons';
import { useSecureGate } from './secure';

export type Handed = 'copied' | 'shown' | 'hidden' | 'gone' | 'discarded';

export function OneTimeValue({ valueRef, masked, label, allowShow = true, allowCopy = true, autoShow = false, hideAfterS, onHanded, multiline }: {
  valueRef: string;
  /** What stands in for the value until it is shown (never derived from it). */
  masked: string;
  label: string;
  allowShow?: boolean;
  allowCopy?: boolean;
  /** Show at once (a value the person just asked to see). */
  autoShow?: boolean;
  /** Drop the shown text after this many seconds. */
  hideAfterS?: number;
  onHanded?(how: Handed): void;
  multiline?: boolean;
}) {
  const { toast, announce } = useApp();
  const [text, setText] = useState<string | null>(null);
  const [handed, setHanded] = useState<Handed | null>(null);
  const [busy, setBusy] = useState(false);
  const [left, setLeft] = useState<number | null>(null);
  const used = useRef(false);
  const alive = useRef(true);
  const refNow = useRef(valueRef);
  refNow.current = valueRef;
  const gate = useSecureGate(text !== null);
  const box = useRef<HTMLDivElement>(null);
  const handedRef = useRef(onHanded);
  handedRef.current = onHanded;

  const settle = (how: Handed) => { setHanded(how); handedRef.current?.(how); };

  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
      if (!used.current) void call('onetime_discard', { ref: refNow.current }).catch(() => undefined);
    };
  }, []);

  const show = async () => {
    if (used.current || busy) return;
    used.current = true; setBusy(true);
    try {
      const out = await call('onetime_show', { ref: valueRef });
      if (!alive.current) return;
      setText(out.text);
      if (hideAfterS) setLeft(hideAfterS);
      settle('shown');
    } catch (e) {
      if (alive.current) { settle('gone'); toast(t(toIpcError(e).reason === 'onetime_ref_unknown' ? 'onetime.gone' : 'error.generic'), 'warn'); }
    } finally { if (alive.current) setBusy(false); }
  };

  const copy = async () => {
    if (used.current || busy) return;
    used.current = true; setBusy(true);
    try {
      const out = await call('onetime_copy', { ref: valueRef });
      if (!alive.current) return;
      if (out.copied) {
        settle('copied');
        const msg = t('onetime.copied', { s: out.clears_in_s });
        toast(msg, 'ok'); announce(msg);
      } else { settle('gone'); toast(t('error.generic'), 'warn'); }
    } catch (e) {
      if (alive.current) { settle('gone'); toast(t(toIpcError(e).reason === 'onetime_ref_unknown' ? 'onetime.gone' : 'error.generic'), 'warn'); }
    } finally { if (alive.current) setBusy(false); }
  };

  useEffect(() => { if (autoShow) void show(); /* once, on mount */ }, []);

  // the countdown that drops a shown value
  useEffect(() => {
    if (left === null || text === null) return;
    if (left <= 0) { setText(null); setLeft(null); settle('hidden'); announce(t('onetime.hidden')); return; }
    const id = setTimeout(() => setLeft((s) => (s === null ? null : s - 1)), 1000);
    return () => clearTimeout(id);
  }, [left, text]);

  useEffect(() => { if (gate) { announce(t('onetime.shown')); box.current?.focus({ preventScroll: true }); } }, [gate]);

  const visible = gate && text !== null;
  return (
    <div className={'onetime' + (visible ? ' is-shown' : '')}>
      <div ref={box} className={'onetime-value mono' + (multiline ? ' is-multiline' : '')} tabIndex={visible ? 0 : -1}
        aria-label={label} data-selectable={visible ? '' : undefined} aria-live="off">
        {visible ? text : text !== null ? t('state.loading') : handed === 'copied' ? t('onetime.copiedMask') : handed === 'hidden' ? t('onetime.hiddenMask') : masked}
      </div>
      <div className="onetime-actions">
        {visible && left !== null && <span className="onetime-timer num"><Icon name="clock" size={12} />{t('onetime.left', { s: left })}</span>}
        {visible && <Button size="sm" tone="ghost" icon="eye-off" onClick={() => { setText(null); setLeft(null); settle('hidden'); }}>{t('act.hide')}</Button>}
        {!handed && !used.current && allowCopy && <Button size="sm" tone="secondary" icon="copy" busy={busy} onClick={() => void copy()}>{t('act.copy')}</Button>}
        {!handed && !used.current && allowShow && !autoShow && <Button size="sm" tone="ghost" icon="eye" blocked={busy} onClick={() => void show()}>{t('act.show')}</Button>}
      </div>
    </div>
  );
}
