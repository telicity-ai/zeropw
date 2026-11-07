// The locked vault. Opening it checks the administrator passphrase through the CLI's own
// re-authentication (`vault_unlock`); a wrong one is recorded. Locking only hides this window's
// lists: the local service, agents and sync keep running, which the screen says plainly.

import { useEffect, useRef, useState } from 'react';
import { t, type CopyKey } from '../copy';
import { call } from '../ipc/client';
import type { Control } from '../ipc/contract';
import { Button, PassField } from '../ui/controls';
import { isAuthError, passErrorKey } from '../ui/Dialog';
import { Mark } from '../ui/icons';
import { LanguageSelect } from '../ui/LanguageSelect';

export function LockScreen({ onUnlocked }: { onUnlocked(control: Control): void }) {
  const [pass, setPass] = useState('');
  const [err, setErr] = useState<CopyKey | null>(null);
  const [busy, setBusy] = useState(false);
  const running = useRef(false);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => { const id = setTimeout(() => input.current?.focus(), 60); return () => clearTimeout(id); }, []);

  const open = async () => {
    if (running.current) return;
    if (!pass) { setErr('pass.err.empty'); input.current?.focus(); return; }
    running.current = true; setBusy(true); setErr(null);
    try {
      const control = await call('vault_unlock', { admin_passphrase: pass });
      setPass('');
      onUnlocked(control);
    } catch (e) {
      setPass('');
      setErr(isAuthError(e) ? 'lock.err' : passErrorKey(e));
      input.current?.focus();
    } finally { running.current = false; setBusy(false); }
  };

  return (
    <div className="lock" data-tauri-drag-region="">
      <form className="lock-card" onSubmit={(e) => { e.preventDefault(); void open(); }} noValidate
        onKeyDown={(e) => { if (e.key === 'Enter' && (e.nativeEvent.isComposing || e.keyCode === 229)) e.preventDefault(); }}>
        <span className="lock-mark"><Mark size={34} /></span>
        <h1 className="lock-title" data-page-title="" tabIndex={-1}>{t('lock.title')}</h1>
        <p className="lock-sub">{t('lock.sub')}</p>
        <div className="lock-field">
          <PassField value={pass} onChange={(v) => { setPass(v); setErr(null); }} inputRef={input} error={err ? t(err) : null} hideLabel />
        </div>
        <Button tone="primary" size="lg" type="submit" busy={busy}>{t('lock.open')}</Button>
        <p className="lock-foot">{t('lock.note')}</p>
        <LanguageSelect compact />
      </form>
    </div>
  );
}
