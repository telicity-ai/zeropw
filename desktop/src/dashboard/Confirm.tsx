import { useRef, useState, type ReactNode } from 'react';
import { t, type CopyKey } from '../copy';
import { toIpcError } from '../ipc/client';
import { PassField } from '../ui/fields';
import { Callout } from '../ui/form';
import { passErrorKey, useClearOnClose } from './context';
import { Sheet } from './Sheet';

/** A confirmation sheet for a consequential action (DESIGN.md §5.3): what is affected as chips or
 *  a short key/value list, an amber callout only for what cannot be undone, blue notes for what
 *  the action does not do, and the admin passphrase when the core asks for it again. `run` throws
 *  on failure; a wrong passphrase is shown under the field, anything else as one line, or under a
 *  field in `children` when `errorFor` shows it there itself (it returns false). A typed
 *  passphrase is dropped when the action ends and when the sheet closes. `check` runs first and
 *  stops the action when a field in `children` is not ready (it shows why itself). */
export function ConfirmSheet({ id, open, title, lead, confirmLabel, chips, details, warn, info, notes, needPass, check, run, onClose, back, errorFor, children }: {
  id: string; open: boolean; title: string; lead?: string; confirmLabel: string;
  chips?: string[]; details?: Array<[string, string]>; warn?: string; info?: string; notes?: string[]; needPass?: boolean;
  check?(): boolean; run(pass: string): Promise<void>; onClose(): void; back?: { label: string; onClick(): void }; errorFor?(e: unknown): CopyKey | null | false;
  children?: ReactNode;
}) {
  const [pass, setPass] = useState('');
  const [passErr, setPassErr] = useState<CopyKey | null>(null);
  const [err, setErr] = useState<CopyKey | null>(null);
  const [busy, setBusy] = useState(false);
  const passRef = useRef<HTMLInputElement>(null);
  useClearOnClose(open, () => setPass(''));

  const go = async () => {
    if (check && !check()) return;
    if (needPass && !pass) { setPassErr('pass.err.empty'); passRef.current?.focus(); return; }
    setBusy(true); setErr(null);
    try {
      await run(pass);
      setPass('');
    } catch (e) {
      setPass('');
      if (needPass && toIpcError(e).error === 'AuthFailed') { setPassErr(passErrorKey(e)); passRef.current?.focus(); }
      else {
        const key = errorFor?.(e);
        if (key !== false) setErr(key ?? 'error.generic');
      }
    } finally { setBusy(false); }
  };

  return (
    <Sheet id={id} open={open} title={title} lead={lead} primaryLabel={confirmLabel} busy={busy} onPrimary={() => void go()} onClose={onClose} back={back}>
      {chips && chips.length > 0 && <div className="agent-sum">{chips.map((c, i) => <span key={`${i}-${c}`}>{c}</span>)}</div>}
      {details && details.length > 0 && (
        <dl className="kv sheet-kv">
          {details.map(([k, v], i) => <div key={`${i}-${k}`} className="kv-row"><dt>{k}</dt><dd>{v}</dd></div>)}
        </dl>
      )}
      {children}
      {info && <Callout kind="info">{info}</Callout>}
      {notes?.map((n, i) => <Callout key={i} kind="info">{n}</Callout>)}
      {warn && <Callout>{warn}</Callout>}
      {needPass && (
        <div style={{ marginTop: 16 }}>
          <PassField id={`${id}-pass`} value={pass} inputRef={passRef} error={passErr ? t(passErr) : null} onChange={(v) => { setPass(v); setPassErr(null); }} />
        </div>
      )}
      {err && <div className="help err" role="alert">{t(err)}</div>}
    </Sheet>
  );
}
