import { useRef, useState } from 'react';
import { t, type CopyKey } from '../copy';
import { toIpcError } from '../ipc/client';
import { PassField } from '../ui/fields';
import { Callout } from '../ui/form';
import { passErrorKey } from './context';
import { Sheet } from './Sheet';

/** A confirmation sheet for a consequential action (DESIGN.md §5.3): what is affected as chips or
 *  a short key/value list, an amber callout only for what cannot be undone, and the admin
 *  passphrase when the core asks for it again. `run` throws on failure; a wrong passphrase is
 *  shown under the field, anything else as one line. */
export function ConfirmSheet({ id, open, title, lead, confirmLabel, chips, details, warn, info, needPass, run, onClose, back, errorFor }: {
  id: string; open: boolean; title: string; lead?: string; confirmLabel: string;
  chips?: string[]; details?: Array<[string, string]>; warn?: string; info?: string; needPass?: boolean;
  run(pass: string): Promise<void>; onClose(): void; back?: { label: string; onClick(): void }; errorFor?(e: unknown): CopyKey | null;
}) {
  const [pass, setPass] = useState('');
  const [passErr, setPassErr] = useState<CopyKey | null>(null);
  const [err, setErr] = useState<CopyKey | null>(null);
  const [busy, setBusy] = useState(false);
  const passRef = useRef<HTMLInputElement>(null);

  const go = async () => {
    if (needPass && !pass) { setPassErr('pass.err.empty'); passRef.current?.focus(); return; }
    setBusy(true); setErr(null);
    try {
      await run(pass);
      setPass('');
    } catch (e) {
      setPass('');
      if (needPass && toIpcError(e).error === 'AuthFailed') { setPassErr(passErrorKey(e)); passRef.current?.focus(); }
      else setErr(errorFor?.(e) ?? 'error.generic');
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
      {info && <Callout kind="info">{info}</Callout>}
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
