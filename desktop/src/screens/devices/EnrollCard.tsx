// Register this Mac with the link service once: the server invite code goes to the core in one
// call (a password field, cleared after every attempt) and only into the daemon's request. The
// server address comes from Settings › 연결 서버 (`link_status.default_service`) and can be
// overridden here; nothing here says the server is running.

import { forwardRef, useRef, useState, type Ref } from 'react';
import { t, type CopyKey } from '../../copy';
import { call, toIpcError } from '../../ipc/client';
import type { LinkStatus } from '../../ipc/contract';
import { enrollErrorKey } from '../../lib/pairing';
import { useShell } from '../../app/shell';
import { Button, PassField, TextField } from '../../ui/controls';
import { Banner } from '../../ui/feedback';

export const EnrollCard = forwardRef(function EnrollCard({ link, onEnrolled, note }: { link: LinkStatus; onEnrolled(): void; note?: CopyKey | null }, ref: Ref<HTMLElement>) {
  const { go } = useShell();
  const [code, setCode] = useState('');
  const [service, setService] = useState(link.default_service);
  const [name, setName] = useState(link.device_name);
  const [more, setMore] = useState(false);
  const [err, setErr] = useState<CopyKey | null>(null);
  const [busy, setBusy] = useState(false);
  const running = useRef(false);
  const codeRef = useRef<HTMLInputElement>(null);

  const submit = async () => {
    if (running.current) return;
    const compact = code.replace(/[\s-]/g, '').toUpperCase();
    if (!/^ZPL[A-Z2-7]{26}$/.test(compact)) { setErr('devices.enroll.err.code'); codeRef.current?.focus(); return; }
    running.current = true; setBusy(true); setErr(null);
    try {
      const s = service.trim();
      await call('link_enroll', { invite_code: code, ...(s && s !== link.default_service ? { service: s } : {}), ...(name.trim() ? { name: name.trim() } : {}) });
      setCode('');
      onEnrolled();
    } catch (e) {
      const key = enrollErrorKey(toIpcError(e).reason);
      setCode('');
      setErr(key);
      if (key === 'devices.enroll.err.service') setMore(true);
      codeRef.current?.focus();
    } finally { running.current = false; setBusy(false); }
  };

  return (
    <section className="mac-enroll card card-pad" ref={ref} tabIndex={-1} aria-labelledby="mac-enroll-title">
      <form className="stack" noValidate onSubmit={(e) => { e.preventDefault(); void submit(); }}>
        <div className="stack-sm">
          <h3 id="mac-enroll-title" className="mac-card-title">{t('mac.enroll.title')}</h3>
          <p className="muted text-sm">{t('mac.enroll.sub')}</p>
        </div>
        {note && <Banner tone="info" compact>{t(note)}</Banner>}
        <PassField label={t('mac.enroll.code')} value={code} inputRef={codeRef} mono autoComplete="off" placeholder="ZPL-…" maxLength={64}
          error={err ? t(err) : null} onChange={(v) => { setCode(v); setErr(null); }} />
        <details className="mac-disclosure" open={more} onToggle={(e) => setMore((e.target as HTMLDetailsElement).open)}>
          <summary>{t('mac.enroll.more')} <span className="mono muted">{service}</span></summary>
          <div className="stack">
            <TextField label={t('mac.enroll.server')} mono value={service} help={t('mac.enroll.server.help')}
              onChange={(v) => { setService(v); setErr(null); }} />
            <TextField label={t('mac.enroll.name')} value={name} maxLength={64} help={t('mac.enroll.name.help')} onChange={setName} />
          </div>
        </details>
        <div className="row">
          <Button tone="primary" type="submit" busy={busy}>{t('mac.enroll.go')}</Button>
          <Button tone="ghost" icon="settings" onClick={() => go('settings', { view: 'server' })}>{t('mac.enroll.settings')}</Button>
        </div>
        <p className="field-note">{t('mac.server.note')}</p>
      </form>
    </section>
  );
});
