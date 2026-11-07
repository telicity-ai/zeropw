// Seeing or copying one value: the administrator passphrase → `secret_reveal` (audited, re-
// authenticated by the CLI) → the core's one-time reference. "보기" paints it once, after the
// capture-exclusion request was answered, for REVEAL_SECONDS; "복사" hands it to the clipboard
// from Rust without painting it. A dialog closed while the core worked discards the reference.

import { useEffect, useRef, useState } from 'react';
import { t, type CopyKey } from '../../copy';
import { call, toIpcError } from '../../ipc/client';
import type { Commands, VersionId } from '../../ipc/contract';
import { REVEAL_SECONDS } from '../../lib/dash';
import { useApp } from '../../ui/app';
import { Button, PassField } from '../../ui/controls';
import { Dialog, passErrorKey } from '../../ui/Dialog';
import { Banner } from '../../ui/feedback';
import { OneTimeValue } from '../../ui/OneTime';
import { versionText } from './logic';

type VersionArg = Commands['secret_reveal'][0]['version'];

export function RevealDialog({ id, version, mode, onClose }: { id: string; version?: VersionId; mode: 'show' | 'copy'; onClose(): void }) {
  const { toast, announce } = useApp();
  const [pass, setPass] = useState('');
  const [err, setErr] = useState<CopyKey | null>(null);
  const [busy, setBusy] = useState(false);
  const [ref, setRef] = useState<string | null>(null);
  const running = useRef(false);
  const alive = useRef(true);
  const passRef = useRef<HTMLInputElement>(null);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);

  const go = async () => {
    if (running.current || ref) return;
    if (!pass) { setErr('pass.err.empty'); passRef.current?.focus(); return; }
    running.current = true; setBusy(true); setErr(null);
    try {
      const out = await call('secret_reveal', { id, admin_passphrase: pass, ...(version !== undefined ? { version: version as VersionArg } : {}) });
      setPass('');
      // closed while the core worked: the value is never fetched
      if (!alive.current) { void call('onetime_discard', { ref: out.ref }).catch(() => undefined); return; }
      if (mode === 'show') { setRef(out.ref); return; }
      try {
        const c = await call('onetime_copy', { ref: out.ref });
        if (c.copied) {
          const msg = t('vault.toast.copied', { s: c.clears_in_s });
          toast(msg, 'ok'); announce(msg);
          if (alive.current) onClose();
        } else if (alive.current) setErr('error.generic');
      } catch {
        if (alive.current) setErr('error.generic');
      }
    } catch (e) {
      setPass('');
      if (!alive.current) return;
      const r = toIpcError(e).reason;
      setErr(r === 'version_revoked' ? 'vault.err.revoked' : passErrorKey(e));
      passRef.current?.focus();
    } finally { running.current = false; if (alive.current) setBusy(false); }
  };

  const show = mode === 'show';
  const asking = ref === null;
  return (
    <Dialog open title={t(show ? 'vault.reveal.title' : 'vault.copy.title')} onClose={onClose} busy={busy} size="sm"
      description={<><span className="mono">{id}</span>{version !== undefined && <> · {t('vault.version.n', { n: versionText(version) })}</>}{asking && <> · {show ? t('vault.reveal.sub', { s: REVEAL_SECONDS }) : t('vault.copy.sub')}</>}</>}
      onSubmit={asking ? () => void go() : undefined}
      footer={asking ? <>
        <Button tone="ghost" onClick={onClose} blocked={busy}>{t('act.cancel')}</Button>
        <Button tone="primary" type="submit" busy={busy} icon={show ? 'eye' : 'copy'}>{t(show ? 'vault.reveal.go' : 'vault.copy.go')}</Button>
      </> : <Button tone="secondary" onClick={onClose}>{t('act.done')}</Button>}>
      {asking ? (
        <PassField value={pass} onChange={(v) => { setPass(v); setErr(null); }} inputRef={passRef} error={err ? t(err) : null} help={t('vault.reveal.note')} data-autofocus="" />
      ) : (
        <OneTimeValue valueRef={ref} masked={t('vault.current.masked')} label={t('vault.reveal.label', { id })} autoShow allowCopy={false}
          hideAfterS={REVEAL_SECONDS} multiline />
      )}
      {!asking && err && <Banner tone="danger">{t(err)}</Banner>}
    </Dialog>
  );
}
