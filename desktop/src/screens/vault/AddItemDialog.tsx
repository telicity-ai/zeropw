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
import { More } from '../../ui/disclosure';
import { Banner, KeyValues } from '../../ui/feedback';
import { Icon } from '../../ui/icons';
import { kindIcon } from '../../ui/layout';
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
    // an SSH key without a picked file is generated in Rust
    if (!ssh && !value && !file) next.value = 'vault.err.value';
    setErrs(next);
    if (next.env) setTimeout(() => envRef.current?.focus(), 40);
    else if (next.id) idRef.current?.focus();
    else if (next.value) valueRef.current?.focus();
    return !next.env && !next.id && !next.value;
  };

  const submit = async () => {
    if (running.current || !check()) return;
    const pair = splitEnv(place);
    if (!pair) return;
    const source: SecretSource = file ? { file_token: file.file_token } : ssh ? { generate_ed25519: true } : { typed: value };
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
      if (team) { setErrs(replace ? { form: team } : { env: team }); setTimeout(() => envRef.current?.focus(), 40); }
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
  const chooseKind = (k: SecretKind) => { setKind(k); setFile(null); setValue(''); clearValueErr(); };
  // the place is asked only when there is a choice (or it needs fixing); it is always sent
  const askPlace = !replace && (pairs.length > 1 || !!errs.env);
  const fileName = file?.name ?? null;
  const fileChip = fileName ? (
    <div className="vault-file">
      <span className="vault-file-name"><Icon name="file" size={14} />{t('vault.add.file.loaded', { name: fileName })}</span>
      <Button size="sm" tone="ghost" icon="close" onClick={() => setFile(null)}>{t('vault.add.file.clear')}</Button>
    </div>
  ) : null;
  const moreLabel = t(replace ? 'vault.add.file' : 'vault.add.more.placeFile');

  return (
    <Dialog open title={t(replace ? 'vault.replace.title' : 'vault.add.title')} description={replace ? t('vault.replace.sub') : undefined}
      onClose={onClose} busy={busy} size="sm" onSubmit={() => void submit()}
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
          <div className="vault-kind-seg">
            <Segmented<SecretKind> label={t('vault.add.kind')} value={kind} onChange={chooseKind}
              options={KINDS.map((k) => ({ value: k, label: kindLabel(k), icon: kindIcon(k) }))} />
          </div>
          <TextField label={t('vault.add.name')} mono value={id} inputRef={idRef} maxLength={64}
            placeholder={t(`vault.add.name.ph.${kind}` as CopyKey)} error={errs.id ? t(errs.id) : null}
            onChange={(v) => { setId(v); setErrs((x) => ({ ...x, id: undefined })); }} data-autofocus="" />
        </>
      )}

      {ssh ? (
        <div className="stack-sm">
          {fileChip ?? (
            <div className="vault-gen">
              <Icon name="ssh" size={15} />
              <span className="grow">{t('vault.add.ssh.gen.help')}</span>
            </div>
          )}
          {errs.value && <div className="field-note is-error" role="alert"><Icon name="alert" size={13} />{t(errs.value)}</div>}
        </div>
      ) : fileChip ? (
        <div className="field">
          <div className="field-label"><span>{t('vault.add.value')}</span></div>
          {fileChip}
        </div>
      ) : (
        <PassField label={t('vault.add.value')} autoComplete="off" value={value} inputRef={valueRef} mono placeholder={t('vault.add.value.ph')}
          error={errs.value ? t(errs.value) : null} onChange={(v) => { setValue(v); clearValueErr(); }}
          data-autofocus={replace ? '' : undefined} />
      )}

      {errs.form && <Banner tone="danger">{t(errs.form)}</Banner>}
      {replace && <p className="vault-note">{t('vault.provider.note')}</p>}

      <More label={moreLabel} open={!!errs.env}>
        {askPlace && (
          <SelectField label={t('vault.add.place')} value={place} selectRef={envRef} error={errs.env ? t(errs.env) : null}
            options={pairs.map((p) => ({ value: p.key, label: placeText(p.key) }))}
            onChange={(v) => { setEnv(v); setErrs((x) => ({ ...x, env: undefined })); }}
            aside={<button type="button" className="vault-link" onClick={onNewPlace}>{t('vault.place.add')}</button>} />
        )}
        {!replace && !askPlace && (
          <div className="row"><span className="vault-note grow">{t('vault.add.place')} · {placeText(place)}</span>
            <button type="button" className="vault-link" onClick={onNewPlace}>{t('vault.place.add')}</button></div>
        )}
        {!fileChip && (
          <div><Button size="sm" tone="secondary" icon="file" onClick={() => void pick()}>{t(ssh ? 'vault.add.ssh.useFile' : 'vault.add.file')}</Button></div>
        )}
      </More>
    </Dialog>
  );
}
