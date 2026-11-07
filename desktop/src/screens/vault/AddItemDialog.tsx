// A new item, or a new value for one (`replace`). The value crosses IPC once in `secret_put`
// (typed), or stays in Rust (a picked file, a generated SSH key); the typed value lives only in
// this dialog's state and goes when the dialog closes.

import { useEffect, useRef, useState } from 'react';
import { t, type CopyKey } from '../../copy';
import { call, toIpcError } from '../../ipc/client';
import type { SecretKind, SecretSource, SecretView } from '../../ipc/contract';
import { publicKeyOf, splitEnv, type EnvPair } from '../../lib/dash';
import { teamWriteErrorKey } from '../../lib/reasons';
import { isValidName } from '../../lib/validators';
import { useApp } from '../../ui/app';
import { Button, PassField, Segmented, SelectField, TextField } from '../../ui/controls';
import { Dialog } from '../../ui/Dialog';
import { Banner, KeyValues } from '../../ui/feedback';
import { Icon } from '../../ui/icons';
import { KindTile } from '../../ui/layout';
import { KINDS, kindLabel, placeOf, placeText } from './logic';
import { PublicKeyBox } from './parts';

type Errs = { id?: CopyKey; value?: CopyKey; env?: CopyKey; form?: CopyKey };

export function AddItemDialog({ replace, pairs, initialPlace, placeHint, initialKind, taken, onClose, onSaved, onNewPlace }: {
  replace?: SecretView;
  pairs: readonly EnvPair[];
  initialPlace: string;
  /** A place just made from this dialog: it becomes the choice. */
  placeHint?: string | null;
  initialKind?: SecretKind;
  taken: readonly string[];
  onClose(): void;
  onSaved(id: string): void;
  onNewPlace(): void;
}) {
  const { toast, announce } = useApp();
  const [kind, setKind] = useState<SecretKind>(replace?.kind ?? initialKind ?? 'password');
  const [id, setId] = useState(replace?.id ?? '');
  const [env, setEnv] = useState(replace ? placeOf(replace) : initialPlace);
  const [value, setValue] = useState('');
  const [file, setFile] = useState<{ file_token: string; name: string } | null>(null);
  const [sshSource, setSshSource] = useState<'gen' | 'file'>('gen');
  const [errs, setErrs] = useState<Errs>({});
  const [busy, setBusy] = useState(false);
  const [pub, setPub] = useState<{ key: string; fp: string | null } | null>(null);
  const running = useRef(false);
  const idRef = useRef<HTMLInputElement>(null);
  const valueRef = useRef<HTMLInputElement>(null);
  const envRef = useRef<HTMLSelectElement>(null);
  const ssh = kind === 'ssh_private_key';
  useEffect(() => { if (placeHint && !replace) { setEnv(placeHint); setErrs((x) => ({ ...x, env: undefined })); } }, [placeHint, replace]);
  const place = pairs.some((p) => p.key === env) ? env : replace ? env : pairs[0]?.key ?? '';

  const pick = async () => {
    try {
      const f = await call('file_pick', { purpose: ssh ? 'ssh_key' : 'secret' });
      if (f) { setFile(f); setValue(''); setErrs((x) => ({ ...x, value: undefined })); }
    } catch { setErrs((x) => ({ ...x, value: 'error.desktopOnly' })); }
  };

  const check = (): boolean => {
    const next: Errs = {};
    if (!splitEnv(place)) next.env = 'vault.err.place';
    if (!replace) {
      if (!isValidName(id)) next.id = 'vault.err.name';
      else if (taken.includes(id)) next.id = 'vault.err.exists';
    }
    if (ssh ? sshSource === 'file' && !file : !value && !file) next.value = ssh ? 'vault.err.sshValue' : 'vault.err.value';
    setErrs(next);
    if (next.env) envRef.current?.focus();
    else if (next.id) idRef.current?.focus();
    else if (next.value) valueRef.current?.focus();
    return !next.env && !next.id && !next.value;
  };

  const submit = async () => {
    if (running.current || !check()) return;
    const pair = splitEnv(place);
    if (!pair) return;
    const source: SecretSource = file ? { file_token: file.file_token } : ssh && sshSource === 'gen' ? { generate_ed25519: true } : { typed: value };
    running.current = true; setBusy(true);
    try {
      const out = await call('secret_put', { id, kind, project: pair.project, environment: pair.environment, source });
      setValue(''); setFile(null);
      const msg = t(replace ? 'vault.toast.replaced' : 'vault.toast.saved');
      // a replaced value still works at the service until it is revoked there
      toast(msg, replace ? 'warn' : 'ok'); announce(msg);
      onSaved(id);
      const pk = publicKeyOf(out);
      if (pk) setPub({ key: pk, fp: typeof out.fingerprint === 'string' ? out.fingerprint : null });
      else onClose();
    } catch (e) {
      const r = toIpcError(e).reason;
      const team = teamWriteErrorKey(r);
      if (team) { setErrs(replace ? { form: team } : { env: team }); envRef.current?.focus(); }
      else if (r === 'invalid_secret_id') { setErrs({ id: 'vault.err.name' }); idRef.current?.focus(); }
      else if (r === 'secret_identity_mismatch') { setErrs({ id: 'vault.err.exists' }); idRef.current?.focus(); }
      else if (r === 'invalid_secret_value' || r === 'file_token_unknown' || r === 'file_unreadable') {
        setFile(null); setErrs({ value: ssh ? 'vault.err.sshValue' : 'vault.err.value' }); valueRef.current?.focus();
      } else setErrs({ form: 'error.generic' });
    } finally { running.current = false; setBusy(false); }
  };

  if (pub) {
    return (
      <Dialog open title={t('vault.pub.title')} description={t('vault.pub.sub')} onClose={onClose} size="md"
        footer={<Button tone="primary" onClick={onClose}>{t('act.done')}</Button>}>
        <PublicKeyBox publicKey={pub.key} fingerprint={pub.fp} autoFocus />
      </Dialog>
    );
  }

  const clearValueErr = () => setErrs((x) => ({ ...x, value: undefined }));
  return (
    <Dialog open title={t(replace ? 'vault.replace.title' : 'vault.add.title')} description={t(replace ? 'vault.replace.sub' : 'vault.add.sub')}
      onClose={onClose} busy={busy} size="md" onSubmit={() => void submit()}
      footer={<>
        <Button tone="ghost" onClick={onClose} blocked={busy}>{t('act.cancel')}</Button>
        <Button tone="primary" type="submit" busy={busy}>{t(replace ? 'vault.replace.save' : 'vault.add.save')}</Button>
      </>}>
      {replace ? (
        <KeyValues dense items={[
          { k: t('vault.add.name'), v: replace.id, mono: true },
          { k: t('vault.meta.place'), v: placeText(placeOf(replace)) },
          { k: t('vault.meta.kind'), v: kindLabel(replace.kind) },
        ]} />
      ) : (
        <>
          <div className="field">
            <div className="field-label"><span id="vault-kind-label">{t('vault.add.kind')}</span></div>
            <div className="vault-kinds" role="radiogroup" aria-labelledby="vault-kind-label">
              {KINDS.map((k) => (
                <button key={k} type="button" role="radio" aria-checked={kind === k} className="vault-kind" tabIndex={kind === k ? 0 : -1}
                  data-autofocus={kind === k ? '' : undefined}
                  onClick={() => { setKind(k); setFile(null); setValue(''); clearValueErr(); }}
                  onKeyDown={(e) => {
                    const dir = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? -1 : 0;
                    if (!dir) return;
                    e.preventDefault();
                    const next = KINDS[(KINDS.indexOf(kind) + dir + KINDS.length) % KINDS.length]!;
                    setKind(next); setFile(null); setValue(''); clearValueErr();
                    (e.currentTarget.parentElement?.querySelector(`[data-kind="${next}"]`) as HTMLElement | null)?.focus();
                  }} data-kind={k}>
                  <KindTile kind={k} />
                  <span className="vault-kind-text">
                    <strong>{kindLabel(k)}</strong>
                    <span>{t(`vault.add.kind.${k}` as CopyKey)}</span>
                  </span>
                  {kind === k && <Icon name="check" size={14} />}
                </button>
              ))}
            </div>
          </div>
          <div className="form-grid">
            <TextField label={t('vault.add.name')} mono value={id} inputRef={idRef} maxLength={64}
              placeholder={t(`vault.add.name.ph.${kind}` as CopyKey)} error={errs.id ? t(errs.id) : null} help={t('vault.add.name.help')}
              onChange={(v) => { setId(v); setErrs((x) => ({ ...x, id: undefined })); }} />
            <div className="stack-sm">
              <SelectField label={t('vault.add.place')} value={place} selectRef={envRef} error={errs.env ? t(errs.env) : null}
                options={pairs.map((p) => ({ value: p.key, label: placeText(p.key) }))}
                onChange={(v) => { setEnv(v); setErrs((x) => ({ ...x, env: undefined })); }}
                aside={<button type="button" className="vault-link" onClick={onNewPlace}>{t('vault.place.add')}</button>} />
            </div>
          </div>
        </>
      )}

      {ssh ? (
        <div className="stack-sm">
          <Segmented label={t('vault.add.ssh.source')} hideLabel={false} value={sshSource}
            options={[{ value: 'gen', label: t('vault.add.ssh.gen'), icon: 'plus' }, { value: 'file', label: t('vault.add.ssh.file'), icon: 'file' }]}
            onChange={(v) => { setSshSource(v); setFile(null); clearValueErr(); }} />
          {sshSource === 'gen'
            ? <p className="vault-note">{t('vault.add.ssh.gen.help')}</p>
            : (
              <div className="vault-file">
                {file
                  ? <span className="vault-file-name"><Icon name="file" size={14} />{t('vault.add.file.loaded', { name: file.name })}</span>
                  : <span className="vault-note">{t('vault.add.ssh.file.help')}</span>}
                <Button size="sm" tone="secondary" icon="file" onClick={() => void pick()}>{t('vault.add.ssh.pick')}</Button>
              </div>
            )}
          {errs.value && <div className="field-note is-error" role="alert"><Icon name="alert" size={13} />{t(errs.value)}</div>}
        </div>
      ) : file ? (
        <div className="field">
          <div className="field-label"><span>{t('vault.add.value')}</span></div>
          <div className="vault-file">
            <span className="vault-file-name"><Icon name="file" size={14} />{t('vault.add.file.loaded', { name: file.name })}</span>
            <Button size="sm" tone="ghost" icon="close" onClick={() => setFile(null)}>{t('vault.add.file.clear')}</Button>
          </div>
        </div>
      ) : (
        <div className="stack-sm">
          <PassField label={t('vault.add.value')} autoComplete="off" value={value} inputRef={valueRef} mono placeholder={t('vault.add.value.ph')}
            error={errs.value ? t(errs.value) : null} onChange={(v) => { setValue(v); clearValueErr(); }}
            data-autofocus={replace ? '' : undefined} />
          <div><Button size="sm" tone="quiet" icon="file" onClick={() => void pick()}>{t('vault.add.file')}</Button></div>
        </div>
      )}

      {errs.form && <Banner tone="danger">{t(errs.form)}</Banner>}
      <Banner tone={replace ? 'info' : 'neutral'} compact>{t(replace ? 'vault.provider.note' : 'vault.add.sameAccount')}</Banner>
    </Dialog>
  );
}
