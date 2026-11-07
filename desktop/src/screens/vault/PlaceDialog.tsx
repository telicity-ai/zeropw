// A new place (a project and its environments). A personal place needs one; developers can
// split one into dev, staging and prod. Environments cannot change once made.

import { useRef, useState } from 'react';
import { t, type CopyKey } from '../../copy';
import { call, toIpcError } from '../../ipc/client';
import { envKey } from '../../lib/dash';
import { isValidName } from '../../lib/validators';
import { useApp } from '../../ui/app';
import { Button, Chip, TextField } from '../../ui/controls';
import { Dialog } from '../../ui/Dialog';
import { More } from '../../ui/disclosure';
import { Icon } from '../../ui/icons';

const ENVS = ['main', 'dev', 'staging', 'prod'] as const;

export function PlaceDialog({ onClose, onDone }: { onClose(): void; onDone(place: string): void }) {
  const { toast } = useApp();
  const [name, setName] = useState('');
  const [envs, setEnvs] = useState<string[]>(['main']);
  const [nameErr, setNameErr] = useState<CopyKey | null>(null);
  const [envErr, setEnvErr] = useState(false);
  const [busy, setBusy] = useState(false);
  const running = useRef(false);
  const nameRef = useRef<HTMLInputElement>(null);

  const toggle = (e: string) => {
    setEnvs((xs) => (xs.includes(e) ? xs.filter((x) => x !== e) : ENVS.filter((x) => x === e || xs.includes(x))));
    setEnvErr(false);
  };

  const submit = async () => {
    if (running.current) return;
    if (!isValidName(name)) { setNameErr('vault.err.name'); nameRef.current?.focus(); return; }
    if (!envs.length) { setEnvErr(true); return; }
    running.current = true; setBusy(true);
    try {
      await call('project_create', { name, environments: envs });
      toast(t('vault.toast.place'), 'ok');
      onDone(envKey(name, envs[0]!));
    } catch (e) {
      const r = toIpcError(e).reason;
      setNameErr(r === 'project_exists' ? 'vault.err.exists' : r === 'invalid_name' ? 'vault.err.name' : 'error.generic');
      nameRef.current?.focus();
    } finally { running.current = false; setBusy(false); }
  };

  return (
    <Dialog open title={t('vault.place.title')} description={t('vault.place.sub')} onClose={onClose} busy={busy} size="sm" onSubmit={() => void submit()}
      footer={<>
        <Button tone="ghost" onClick={onClose} blocked={busy}>{t('act.cancel')}</Button>
        <Button tone="primary" type="submit" busy={busy}>{t('vault.place.save')}</Button>
      </>}>
      <TextField label={t('vault.place.name')} mono value={name} inputRef={nameRef} maxLength={64} placeholder={t('vault.place.name.ph')}
        error={nameErr ? t(nameErr) : null} data-autofocus="" onChange={(v) => { setName(v); setNameErr(null); }} />
      <More label={t('vault.place.envs')} hint={envs.join(', ')} open={envErr}>
        <div className="field">
          <div className="field-label"><span id="vault-envs-label">{t('vault.place.envs')}</span></div>
          <div className="chips" role="group" aria-labelledby="vault-envs-label">
            {ENVS.map((e) => <Chip key={e} on={envs.includes(e)} onToggle={() => toggle(e)}>{e}</Chip>)}
          </div>
          <div className={'field-note' + (envErr ? ' is-error' : '')} role={envErr ? 'alert' : undefined}>
            {envErr ? <><Icon name="alert" size={13} />{t('vault.place.err.envs')}</> : t('vault.place.envs.help')}
          </div>
        </div>
      </More>
    </Dialog>
  );
}
