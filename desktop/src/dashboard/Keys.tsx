import { useEffect, useRef, useState } from 'react';
import { t, type CopyKey } from '../copy';
import { call, toIpcError } from '../ipc/client';
import type { Commands, EnvFileRef, SecretKind, SecretSource, SecretView } from '../ipc/contract';
import { envPairs, groupSecrets, olderVersionCount, publicKeyOf, REVEAL_SECONDS, sortedVersions, splitEnv, type VersionId, teamEnvPairs, type EnvPair } from '../lib/dash';
import { dropErrorKey } from '../lib/envimport';
import { shortTime } from '../lib/format';
import { DEFAULT_ENVIRONMENTS, isValidName } from '../lib/validators';
import { useApp } from '../ui/context';
import { PassField, SelectField, TextField } from '../ui/fields';
import { Callout, Segmented } from '../ui/form';
import { useSecureGate } from '../ui/secure';
import { ConfirmSheet } from './Confirm';
import { passErrorKey, useClearOnClose, useDash, useIntent, useLoad, useSheets, type Intent } from './context';
import { ImportSheet } from './Import';
import { Empty, metaLine, Row, SectionHead, Tag } from './parts';
import { Sheet } from './Sheet';

/** The version goes back to the core exactly as the CLI printed it (a JSON number today). */
type VersionArg = Commands['secret_revoke'][0]['version'];
const versionArg = (v: VersionId): VersionArg => v as VersionArg;
const NO_PAIRS: EnvPair[] = [];

export const KIND_LABEL: Record<SecretKind, CopyKey> = {
  api_key: 'keys.kind.api_key', password: 'keys.kind.password', env_var: 'keys.kind.env_var', ssh_private_key: 'keys.kind.ssh_private_key',
};
const STATUS_LABEL: Record<string, CopyKey> = {
  active: 'st.active', staged: 'st.staged', retired: 'st.retired', revoked: 'st.revoked',
};
export const kindLabel = (k: string): string => (k in KIND_LABEL ? t(KIND_LABEL[k as SecretKind]) : k);
const statusLabel = (s: string): string => (STATUS_LABEL[s] ? t(STATUS_LABEL[s]) : s);

type KeySheet =
  | { kind: 'add'; replace?: SecretView }
  | { kind: 'versions'; id: string }
  | { kind: 'confirm'; action: 'retire' | 'revoke'; id: string; version: VersionId }
  | { kind: 'reveal'; id: string; version?: VersionId }
  | { kind: 'project' }
  | { kind: 'import'; file: EnvFileRef };

/** Keys: secrets and environment variables grouped by project/environment. The list never holds a
 *  value; a value is shown only after the admin passphrase, once, for 30 seconds. */
export function KeysPage({ intent, onIntent, incomingFile, onFileTaken }: {
  intent?: Intent; onIntent(): void; incomingFile?: EnvFileRef | null; onFileTaken?(): void;
}) {
  const { tick } = useDash();
  const { toast } = useApp();
  const [n, setN] = useState(0);
  const load = useLoad(async () => {
    const [p, s] = await Promise.all([call('project_list'), call('secret_list', {})]);
    // a team environment this device joined is listed apart from its projects: a .env can go there too
    return { projects: p.projects, envs: teamEnvPairs(p), secrets: s.secrets };
  }, [tick, n]);
  const reload = () => setN((x) => x + 1);
  const sheets = useSheets<KeySheet>();
  const groups = load.data ? groupSecrets(load.data.secrets, load.data.projects) : null;

  useIntent(intent, onIntent, (i) => {
    if (i === 'add-key') { sheets.open({ kind: 'add' }); return true; }
    if (i === 'import' && incomingFile) { sheets.open({ kind: 'import', file: incomingFile }); onFileTaken?.(); return true; }
    return false;
  });

  // a .env file picked here; one dropped on the window arrives as an intent
  const pickEnv = async () => {
    try {
      const f = await call('file_pick', { purpose: 'env_file' });
      if (f) sheets.open({ kind: 'import', file: await call('env_file_load', { file_token: f.file_token }) });
    } catch (e) {
      const r = toIpcError(e).reason;
      toast(t(r === 'ipc_failed' || r === 'mock_unsupported' ? 'error.desktopOnly' : dropErrorKey(r)), 'warn');
    }
  };

  const addBtn = <button className="btn btn-primary btn-sm" type="button" onClick={() => sheets.open({ kind: 'add' })}>{t('keys.add')}</button>;
  const importBtn = <button className="btn btn-ghost btn-sm" type="button" title={t('keys.import.title')} onClick={() => void pickEnv()}>{t('keys.import')}</button>;

  return (
    <>
      <SectionHead title={t('keys.list')}>
        <button className="btn btn-ghost btn-sm" type="button" onClick={() => sheets.open({ kind: 'project' })}>{t('keys.project.add')}</button>
        {importBtn}
        {groups && groups.length > 0 && addBtn}
      </SectionHead>
      <p className="page-help">{t('keys.envNote')}</p>
      <div className="glass">
        {!groups
          ? <Empty text={load.failed ? t('error.load') : t('boot.loading')} />
          : groups.length === 0
            ? <Empty text={t('page.keys.empty')} action={addBtn} />
            : groups.map((g) => (
              <section key={g.key} className="group" aria-labelledby={`grp-${g.key}`}>
                <h3 className="group-head" id={`grp-${g.key}`}><span>{g.project}</span><span aria-hidden="true">/</span><span>{g.environment}</span></h3>
                <ul className="list">
                  {g.secrets.map((s) => {
                    const older = olderVersionCount(s);
                    return (
                      <Row key={s.id} dot={s.active_version ? 'on' : 'idle'} mono name={s.id} tag={<Tag>{kindLabel(s.kind)}</Tag>}
                        meta={metaLine(s.active_version ? t('keys.version', { n: s.active_version }) : t('keys.noActive'), older > 0 ? t('keys.older', { n: older }) : null)}>
                        <button className="btn btn-ghost btn-sm" type="button" aria-disabled={!s.active_version || undefined}
                          aria-label={t('keys.reveal.aria', { id: s.id })} onClick={() => { if (s.active_version) sheets.open({ kind: 'reveal', id: s.id }); }}>{t('keys.reveal')}</button>
                        <button className="btn btn-text btn-sm" type="button" aria-label={t('keys.versions.aria', { id: s.id })}
                          onClick={() => sheets.open({ kind: 'versions', id: s.id })}>{t('keys.versions')}</button>
                      </Row>
                    );
                  })}
                </ul>
              </section>
            ))}
      </div>

      <AddKeySheet key={sheets.key('add')} open={sheets.isOpen('add')} data={sheets.data('add')} projects={load.data?.projects ?? []}
        taken={load.data?.secrets.map((s) => s.id) ?? []} onClose={sheets.close} onSaved={reload} />
      <VersionsSheet key={sheets.key('versions')} open={sheets.isOpen('versions')} id={sheets.data('versions')?.id ?? ''} onClose={sheets.close}
        onAction={(action, id, version) => sheets.open({ kind: 'confirm', action, id, version })}
        onReveal={(id, version) => sheets.open({ kind: 'reveal', id, version })}
        onReplace={(secret) => sheets.open({ kind: 'add', replace: secret })} />
      <ConfirmVersionSheet key={sheets.key('confirm')} open={sheets.isOpen('confirm')} data={sheets.data('confirm')}
        onBack={(id) => sheets.open({ kind: 'versions', id })} onClose={sheets.close}
        onDone={(id) => { reload(); sheets.open({ kind: 'versions', id }); }} />
      <ProjectSheet key={sheets.key('project')} open={sheets.isOpen('project')} onClose={sheets.close} onDone={() => { sheets.close(); reload(); }} />
      <RevealSheet key={sheets.key('reveal')} open={sheets.isOpen('reveal')} data={sheets.data('reveal')} onClose={sheets.close} />
      <ImportSheet key={sheets.key('import')} open={sheets.isOpen('import')} file={sheets.data('import')?.file} pairs={load.data?.envs ?? NO_PAIRS}
        onClose={sheets.close} onDone={reload} />
    </>
  );
}

// ---------------------------------------------------------------- add or replace

type Kind3 = 'api_key' | 'password' | 'env_var';

function AddKeySheet({ open, data, projects, taken, onClose, onSaved }: {
  open: boolean; data: Extract<KeySheet, { kind: 'add' }> | undefined; projects: Parameters<typeof envPairs>[0]; taken: string[];
  onClose(): void; onSaved(): void;
}) {
  const { toast, field } = useApp();
  const replace = data?.replace;
  const pairs = envPairs(projects);
  const [env, setEnv] = useState(replace ? `${replace.project}/${replace.environment}` : pairs[0]?.key ?? '');
  const [kind, setKind] = useState<SecretKind>(replace?.kind ?? 'api_key');
  const [id, setId] = useState(replace?.id ?? '');
  const [value, setValue] = useState('');
  const [file, setFile] = useState<{ file_token: string; name: string } | null>(null);
  const [gen, setGen] = useState(false);
  const [errs, setErrs] = useState<{ id?: CopyKey; value?: CopyKey; env?: CopyKey; form?: CopyKey }>({});
  const [busy, setBusy] = useState(false);
  const [pub, setPub] = useState<string | null>(null);
  const idRef = useRef<HTMLInputElement>(null);
  const valueRef = useRef<HTMLInputElement>(null);
  const envRef = useRef<HTMLSelectElement>(null);
  const ssh = kind === 'ssh_private_key';

  useEffect(() => { if (!env && pairs[0]) setEnv(pairs[0].key); }, [env, pairs]);
  // a typed value never outlives the sheet
  useClearOnClose(open, () => { setValue(''); setFile(null); });

  const pick = async () => {
    try {
      const f = await call('file_pick', { purpose: ssh ? 'ssh_key' : 'secret' });
      if (f) { setFile(f); setValue(''); setGen(false); setErrs((x) => ({ ...x, value: undefined })); field.ripple(0.04); }
    } catch { setErrs((x) => ({ ...x, value: 'error.desktopOnly' })); }
  };

  const check = (): boolean => {
    const next: typeof errs = {};
    if (!splitEnv(env)) next.env = 'keys.err.env';
    if (!replace) {
      if (!isValidName(id)) next.id = 'proj.err.name';
      else if (taken.includes(id)) next.id = 'keys.err.exists';
    }
    if (!value && !file && !gen) next.value = ssh ? 'conn.ssh.keyerr' : 'keys.err.value';
    setErrs(next);
    if (next.env) envRef.current?.focus();
    else if (next.id) idRef.current?.focus();
    else if (next.value) valueRef.current?.focus();
    return !next.env && !next.id && !next.value;
  };

  const submit = async () => {
    if (!check()) return;
    const pair = splitEnv(env);
    if (!pair) return;
    const source: SecretSource = file ? { file_token: file.file_token } : gen ? { generate_ed25519: true } : { typed: value };
    setBusy(true);
    try {
      const out = await call('secret_put', { id, kind, project: pair.project, environment: pair.environment, source });
      setValue(''); setFile(null); setGen(false);
      // a replaced key still works at the service until it is revoked there
      toast(t(replace ? 'toast.key.replaced' : 'toast.key.saved'), replace ? 'warn' : 'info');
      field.ripple(0.06);
      onSaved();
      // a generated SSH key: its public half has to go onto the server, so show it before closing
      const pk = publicKeyOf(out);
      if (pk) setPub(pk);
      else onClose();
    } catch (e) {
      const r = toIpcError(e).reason;
      if (r === 'invalid_secret_id') { setErrs({ id: 'proj.err.name' }); idRef.current?.focus(); }
      else if (r === 'secret_identity_mismatch') { setErrs({ id: 'keys.err.exists' }); idRef.current?.focus(); }
      else if (r === 'invalid_secret_value' || r === 'file_token_unknown' || r === 'file_unreadable') { setFile(null); setErrs({ value: 'keys.err.value' }); valueRef.current?.focus(); }
      else setErrs({ form: 'error.generic' });
    } finally { setBusy(false); }
  };

  const kinds: Array<{ value: Kind3; label: string }> = [
    { value: 'api_key', label: t('keys.kind.api_key') }, { value: 'password', label: t('keys.kind.password') }, { value: 'env_var', label: t('keys.kind.env_var') },
  ];

  if (pub !== null) {
    return (
      <Sheet id="sheet-key" open={open} title={t(replace ? 'keys.replace.title' : 'keys.add.title')} lead={t('conn.ssh.generated')} onClose={onClose} closeLabel={t('common.done')}>
        <PublicKey text={pub} />
      </Sheet>
    );
  }

  return (
    <Sheet id="sheet-key" open={open} title={t(replace ? 'keys.replace.title' : 'keys.add.title')} lead={t(replace ? 'keys.replace.sub' : 'conn.key.help')}
      primaryLabel={t(replace ? 'keys.replace.confirm' : 'keys.save')} busy={busy} onPrimary={() => void submit()} onClose={onClose}>
      {replace ? (
        <dl className="kv sheet-kv">
          <dt>{t('keys.field.name')}</dt><dd>{replace.id}</dd>
          <dt>{t('keys.field.env')}</dt><dd>{`${replace.project}/${replace.environment}`}</dd>
          <dt>{t('keys.field.kind')}</dt><dd>{kindLabel(replace.kind)}</dd>
        </dl>
      ) : (
        <>
          {pairs.length === 0 && <Callout kind="info">{t('keys.err.noEnv')}</Callout>}
          <SelectField id="key-env" label={t('keys.field.env')} mono value={env} selectRef={envRef} error={errs.env ? t(errs.env) : null}
            options={pairs.map((p) => ({ value: p.key, label: p.key }))} onChange={(v) => { setEnv(v); setErrs((x) => ({ ...x, env: undefined })); }} />
          <div className="field">
            <div className="label"><span id="key-kind-lbl">{t('keys.field.kind')}</span></div>
            <Segmented<Kind3> name="key-kind" labelledBy="key-kind-lbl" value={kind as Kind3} options={kinds}
              onChange={(v) => { setKind(v); setGen(false); }} />
          </div>
          <TextField id="key-id" label={t('keys.field.name')} mono value={id} inputRef={idRef} maxLength={64} placeholder={kind === 'env_var' ? 'database-url' : 'example-api'}
            error={errs.id ? t(errs.id) : null} hint={t('keys.field.name.hint')}
            onChange={(v) => { setId(v); setErrs((x) => ({ ...x, id: undefined })); }} />
        </>
      )}
      <TextField id="key-value" label={t(ssh ? 'conn.key.ssh' : 'keys.field.value')} type="password" mono value={value} inputRef={valueRef}
        error={errs.value ? t(errs.value) : null}
        help={file ? t('keys.value.loaded', { name: file.name }) : gen ? t('conn.ssh.keygen.pending') : undefined}
        suffix={<>
          <button className="icon-btn" type="button" onClick={() => void pick()}>{t('conn.key.file')}</button>
          {ssh && <button className="icon-btn" type="button" aria-pressed={gen} onClick={() => { setGen(!gen); setFile(null); setValue(''); setErrs((x) => ({ ...x, value: undefined })); }}>{t('conn.ssh.keygen')}</button>}
        </>}
        onChange={(v) => { setValue(v); setFile(null); setGen(false); setErrs((x) => ({ ...x, value: undefined })); }} />
      {errs.form && <div className="help err" role="alert">{t(errs.form)}</div>}
      {replace ? <Callout kind="info">{t('keys.provider.note')}</Callout> : <Callout kind="info">{t('keys.sameAccount')}</Callout>}
    </Sheet>
  );
}

/** A public key line (not a secret): selectable so it can be copied onto the server. It takes
 *  focus when it appears, since it replaces the form inside an open sheet. */
export function PublicKey({ text }: { text: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const tm = setTimeout(() => ref.current?.focus({ preventScroll: true }), 40);
    return () => clearTimeout(tm);
  }, []);
  return (
    <div className="field">
      <div className="label"><span id="pubkey-lbl">{t('conn.ssh.pub')}</span></div>
      <div className="pub-key" ref={ref} role="textbox" aria-readonly="true" aria-labelledby="pubkey-lbl" tabIndex={0}>{text}</div>
    </div>
  );
}

// ---------------------------------------------------------------- project

/** A new project and its environments, as in the onboarding (environments are fixed once made). */
function ProjectSheet({ open, onClose, onDone }: { open: boolean; onClose(): void; onDone(): void }) {
  const { toast, field } = useApp();
  const [name, setName] = useState('');
  const [envs, setEnvs] = useState<string[]>([...DEFAULT_ENVIRONMENTS]);
  const [nameErr, setNameErr] = useState<CopyKey | null>(null);
  const [envErr, setEnvErr] = useState(false);
  const [busy, setBusy] = useState(false);
  const nameRef = useRef<HTMLInputElement>(null);
  const firstChip = useRef<HTMLButtonElement>(null);
  const toggle = (e: string) => {
    setEnvs((xs) => (xs.includes(e) ? xs.filter((x) => x !== e) : DEFAULT_ENVIRONMENTS.filter((x) => x === e || xs.includes(x))));
    setEnvErr(false);
  };
  const submit = async () => {
    if (!isValidName(name)) { setNameErr('proj.err.name'); nameRef.current?.focus(); return; }
    if (!envs.length) { setEnvErr(true); firstChip.current?.focus(); return; }
    setBusy(true);
    try {
      await call('project_create', { name, environments: envs });
      field.ripple(0.06);
      toast(t('toast.project.created'));
      onDone();
    } catch (e) {
      const r = toIpcError(e).reason;
      setNameErr(r === 'project_exists' ? 'proj.err.exists' : r === 'invalid_name' ? 'proj.err.name' : 'error.generic');
      nameRef.current?.focus();
    } finally { setBusy(false); }
  };
  return (
    <Sheet id="sheet-project" open={open} title={t('proj.title')} primaryLabel={t('proj.next')} busy={busy} onPrimary={() => void submit()} onClose={onClose}>
      <TextField id="proj-name" label={t('proj.name')} mono value={name} inputRef={nameRef} maxLength={64} error={nameErr ? t(nameErr) : null}
        onChange={(v) => { setName(v); setNameErr(null); }} />
      <div className="field">
        <div className="label"><span id="proj-env-lbl">{t('proj.envs')}</span><span className="hint" id="proj-env-hint">{t('proj.envs.hint')}</span></div>
        <div className="chips" role="group" aria-labelledby="proj-env-lbl" aria-describedby="proj-env-hint proj-env-err">
          {DEFAULT_ENVIRONMENTS.map((e, i) => (
            <button key={e} className="chip" type="button" aria-pressed={envs.includes(e)} ref={i === 0 ? firstChip : undefined} onClick={() => toggle(e)}>
              <i aria-hidden="true" />{e}
            </button>
          ))}
        </div>
        <div className="help err" id="proj-env-err" hidden={!envErr}>{envErr ? t('proj.err.envs') : ''}</div>
      </div>
    </Sheet>
  );
}

// ---------------------------------------------------------------- versions

function VersionsSheet({ open, id, onClose, onAction, onReveal, onReplace }: {
  open: boolean; id: string; onClose(): void; onAction(a: 'retire' | 'revoke', id: string, version: VersionId): void;
  onReveal(id: string, version: VersionId): void; onReplace(s: SecretView): void;
}) {
  const v = useLoad(() => (id ? call('secret_versions', { id }) : Promise.resolve(null)), [id]);
  const s = v.data;
  return (
    <Sheet id="sheet-versions" open={open} title={t('keys.versions.title')} lead={id} onClose={onClose}>
      {!s ? <Empty text={v.failed ? t('error.load') : t('boot.loading')} /> : (
        <>
          <ul className="list flat" aria-label={t('keys.versions.title')}>
            {sortedVersions(s).map((x) => {
              // the CLI prints versions as numbers; they go back to the core exactly as printed
              const ver: VersionId = x.version as VersionId;
              const pub = typeof x.public?.public_key === 'string' && x.public.public_key ? x.public.public_key : null;
              return (
                <Row key={String(ver)} dot={x.status === 'active' ? 'on' : x.status === 'revoked' ? 'warn' : 'idle'}
                  name={t('keys.version', { n: String(ver) })} tag={<Tag warn={x.status === 'revoked'}>{statusLabel(x.status)}</Tag>}
                  meta={metaLine(shortTime(x.created_at), x.public?.fingerprint ?? null)}
                  sub={pub ? <div className="pub-line"><span className="sr-only">{t('conn.ssh.pub')} </span>{pub}</div> : undefined}>
                  {x.status !== 'revoked' && (
                    <>
                      <button className="btn btn-text btn-sm" type="button" aria-label={t('keys.reveal.aria', { id: `${s.id} ${String(ver)}` })} onClick={() => onReveal(s.id, ver)}>{t('keys.reveal')}</button>
                      {x.status === 'staged' && (
                        <button className="btn btn-text btn-sm" type="button" aria-label={t('keys.retire.aria', { id: s.id, n: String(ver) })}
                          onClick={() => onAction('retire', s.id, ver)}>{t('keys.retire')}</button>
                      )}
                      <button className="btn btn-text btn-sm danger" type="button" aria-label={t('keys.revoke.aria', { id: s.id, n: String(ver) })}
                        onClick={() => onAction('revoke', s.id, ver)}>{t('keys.revoke')}</button>
                    </>
                  )}
                </Row>
              );
            })}
          </ul>
          <div className="sheet-acts">
            <button className="btn btn-ghost btn-sm" type="button" onClick={() => onReplace(s)}>{t('keys.replace')}</button>
          </div>
        </>
      )}
    </Sheet>
  );
}

function ConfirmVersionSheet({ open, data, onBack, onClose, onDone }: {
  open: boolean; data: Extract<KeySheet, { kind: 'confirm' }> | undefined; onBack(id: string): void; onClose(): void; onDone(id: string): void;
}) {
  const { toast } = useApp();
  const revoke = data?.action === 'revoke';
  return (
    <ConfirmSheet id="sheet-key-confirm" open={open} title={t(revoke ? 'keys.revoke.title' : 'keys.retire.title')} lead={t(revoke ? 'keys.revoke.sub' : 'keys.retire.sub')}
      confirmLabel={t(revoke ? 'keys.revoke.confirm' : 'keys.retire.confirm')} onClose={onClose}
      chips={data ? [data.id, t('keys.version', { n: String(data.version) })] : []} warn={revoke ? t('keys.revoke.warn') : undefined}
      notes={revoke ? [t('keys.provider.note'), t('session.note')] : undefined}
      back={data ? { label: t('keys.versions'), onClick: () => onBack(data.id) } : undefined}
      run={async () => {
        if (!data) return;
        const out = await call(revoke ? 'secret_revoke' : 'secret_retire', { id: data.id, version: versionArg(data.version) });
        // ZeroPW's revoke only stops the vault from using the version; the service still accepts it
        const provider = revoke || out.provider_revocation_required === true;
        toast(t(revoke ? 'toast.key.revoked' : provider ? 'toast.key.retired.provider' : 'toast.key.retired'), provider ? 'warn' : 'info');
        onDone(data.id);
      }} />
  );
}

// ---------------------------------------------------------------- reveal

/** Admin passphrase → `secret_reveal` → `onetime_show`. The value is painted only after the core
 *  has answered the screen-capture exclusion request (best effort, never a guarantee), stays for
 *  30 seconds, then is dropped from memory; the request is withdrawn after the value has left the
 *  screen. */
function RevealSheet({ open, data, onClose }: { open: boolean; data: Extract<KeySheet, { kind: 'reveal' }> | undefined; onClose(): void }) {
  const { announce } = useApp();
  const [pass, setPass] = useState('');
  const [err, setErr] = useState<CopyKey | null>(null);
  const [busy, setBusy] = useState(false);
  const [text, setText] = useState<string | null>(null);
  const [left, setLeft] = useState(REVEAL_SECONDS);
  const [hidden, setHidden] = useState(false);
  const passRef = useRef<HTMLInputElement>(null);
  const valueRef = useRef<HTMLDivElement>(null);
  const openRef = useRef(open);
  openRef.current = open;
  const visible = useSecureGate(open && text !== null);

  // closing drops the value at once, before the sheet has finished sliding out
  useClearOnClose(open, () => { setText(null); setPass(''); });

  useEffect(() => {
    if (!visible) return;
    const started = Date.now();
    setLeft(REVEAL_SECONDS);
    announce(t('keys.reveal.shown'));
    const focus = setTimeout(() => valueRef.current?.focus({ preventScroll: true }), 30);
    const id = setInterval(() => {
      const l = REVEAL_SECONDS - Math.floor((Date.now() - started) / 1000);
      if (l <= 0) { setText(null); setHidden(true); clearInterval(id); return; }
      setLeft(l);
    }, 250);
    return () => { clearInterval(id); clearTimeout(focus); };
  }, [visible, announce]);

  const reveal = async () => {
    if (!data) return;
    if (!pass) { setErr('pass.err.empty'); passRef.current?.focus(); return; }
    setBusy(true);
    try {
      const r = await call('secret_reveal', { id: data.id, admin_passphrase: pass, ...(data.version !== undefined ? { version: versionArg(data.version) } : {}) });
      setPass('');
      // the sheet was closed while the core worked: the value is not fetched at all
      if (!openRef.current) { call('onetime_discard', { ref: r.ref }).catch(() => undefined); return; }
      const v = await call('onetime_show', { ref: r.ref });
      if (openRef.current) setText(v.text);
    } catch (e) {
      setPass('');
      const r = toIpcError(e).reason;
      setErr(r === 'version_revoked' ? 'keys.err.revoked' : passErrorKey(e));
      passRef.current?.focus();
    } finally { setBusy(false); }
  };

  const stage = text !== null ? 'show' : hidden ? 'hidden' : 'pass';
  return (
    <Sheet id="sheet-reveal" open={open} title={t('keys.reveal.title')} lead={stage === 'pass' ? t('keys.reveal.sub') : undefined}
      primaryLabel={stage === 'pass' ? t('keys.reveal.confirm') : undefined} busy={busy} onPrimary={() => void reveal()} onClose={onClose}>
      {data && <div className="agent-sum"><span>{data.id}</span>{data.version && <span>{t('keys.version', { n: data.version })}</span>}</div>}
      {stage === 'pass' && (
        <PassField id="reveal-pass" value={pass} inputRef={passRef} error={err ? t(err) : null} onChange={(v) => { setPass(v); setErr(null); }} />
      )}
      {stage === 'show' && visible && (
        <div className="secret-box" role="region" aria-label={t('keys.reveal.region')} tabIndex={-1} ref={valueRef}>
          <code className="secret-val">{text}</code>
          <div className="secret-left" aria-hidden="true">{t('keys.reveal.left', { s: left })}</div>
        </div>
      )}
      {stage === 'show' && !visible && <div className="help" role="status">{t('boot.loading')}</div>}
      {stage === 'hidden' && <div className="help" role="status">{t('keys.reveal.hidden')}</div>}
    </Sheet>
  );
}
