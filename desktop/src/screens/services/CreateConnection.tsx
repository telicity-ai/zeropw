// Connect a service once: an HTTP API (through the gateway) or an SSH server (through the signer),
// with its credential either already in the vault (same place, a kind the connection accepts, an
// active version) or new. A new credential is stored first (`secret_put`, under the connection's
// name), then the connection is made with the administrator passphrase. A credential stored by an
// earlier try that then failed is not stored again unless something new was typed. Typed values
// and the passphrase live only in this dialog's state, which goes away when it closes.

import { useRef, useState } from 'react';
import { t, type CopyKey } from '../../copy';
import { call, toIpcError } from '../../ipc/client';
import type { ConnectionView, SecretKind, SecretSource, SecretView } from '../../ipc/contract';
import {
  defaultMethodStates, isBasicUser, isCliPath, isHeaderName, isHostKey, isPlainText, isSshHost, isSshUser, keyChoices, METHODS,
  methodsPayload, nextMethodState, parsePathPrefixes, parsePort, publicKeyOf, shownChoice, splitEnv, SSH_PROGRAM, writeConsequences,
  type EnvPair, type Method, type MethodStates,
} from '../../lib/dash';
import { teamWriteErrorKey } from '../../lib/reasons';
import { isValidName, parseTarget } from '../../lib/validators';
import { useApp } from '../../ui/app';
import { Button, Checkbox, PassField, Segmented, SelectField, TextField } from '../../ui/controls';
import { Dialog, isAuthError, passErrorKey } from '../../ui/Dialog';
import { Banner } from '../../ui/feedback';
import { Icon } from '../../ui/icons';
import { placeLabel } from '../../lib/places';
import { createErrorField, ERR_ORDER, type ErrKey } from './logic';

type ConnType = 'http' | 'ssh';
type Auth = 'bearer' | 'basic' | 'header';
type Cli = '' | 'democli' | 'custom';
type KeySrc = 'new' | 'existing';
type Errs = Partial<Record<ErrKey, CopyKey>>;

const CONSQ: Record<'POST' | 'PUT' | 'PATCH' | 'DELETE', CopyKey> = {
  POST: 'service.c.consq.POST', PUT: 'service.c.consq.PUT', PATCH: 'service.c.consq.PATCH', DELETE: 'service.c.consq.DELETE',
};
const KIND_LABEL: Record<SecretKind, CopyKey> = {
  api_key: 'nav.kind.api_key', password: 'nav.kind.password', env_var: 'nav.kind.env_var', ssh_private_key: 'nav.kind.ssh_private_key',
};

export function CreateConnectionDialog({ pairs, connections, secrets, onClose, onCreated }: {
  pairs: readonly EnvPair[]; connections: readonly ConnectionView[]; secrets: readonly SecretView[];
  onClose(): void; onCreated(id: string): void;
}) {
  const { toast, announce } = useApp();
  const [type, setType] = useState<ConnType>('http');
  const [src, setSrc] = useState<KeySrc>('new');
  const [pickId, setPickId] = useState('');
  const [envChoice, setEnv] = useState(pairs[0]?.key ?? '');
  const env = shownChoice(envChoice, pairs.map((p) => p.key));
  const [id, setId] = useState('');
  const [target, setTarget] = useState('');
  const [allowPriv, setAllowPriv] = useState(false);
  const [auth, setAuth] = useState<Auth>('bearer');
  const [basicUser, setBasicUser] = useState('');
  const [hdrName, setHdrName] = useState('X-Api-Key');
  const [hdrPrefix, setHdrPrefix] = useState('');
  const [methods, setMethods] = useState<MethodStates>(defaultMethodStates);
  const [paths, setPaths] = useState('');
  const [cli, setCli] = useState<Cli>('');
  const [cliPath, setCliPath] = useState('');
  const [ca, setCa] = useState<{ file_token: string; name: string } | null>(null);
  const [sshId, setSshId] = useState('');
  const [host, setHost] = useState('');
  const [port, setPort] = useState('22');
  const [user, setUser] = useState('');
  const [hostKey, setHostKey] = useState('');
  const [sshCli, setSshCli] = useState(SSH_PROGRAM);
  const [value, setValue] = useState('');
  const [file, setFile] = useState<{ file_token: string; name: string } | null>(null);
  const [gen, setGen] = useState(false);
  const [stored, setStored] = useState<{ id: string; env: string; kind: SecretKind; pub: string | null } | null>(null);
  const [pass, setPass] = useState('');
  const [errs, setErrs] = useState<Errs>({});
  const [busy, setBusy] = useState(false);
  const running = useRef(false);
  const [pub, setPub] = useState<string | null>(null);
  const [moreOpen, setMoreOpen] = useState(false);
  const refs = {
    env: useRef<HTMLSelectElement>(null), id: useRef<HTMLInputElement>(null), target: useRef<HTMLInputElement>(null),
    basic: useRef<HTMLInputElement>(null), header: useRef<HTMLInputElement>(null), prefix: useRef<HTMLInputElement>(null),
    methods: useRef<HTMLButtonElement>(null), paths: useRef<HTMLInputElement>(null), cli: useRef<HTMLInputElement>(null),
    host: useRef<HTMLInputElement>(null), port: useRef<HTMLInputElement>(null), user: useRef<HTMLInputElement>(null),
    hostKey: useRef<HTMLInputElement>(null), sshCli: useRef<HTMLInputElement>(null), key: useRef<HTMLInputElement>(null),
    keyFile: useRef<HTMLButtonElement>(null), pass: useRef<HTMLInputElement>(null), pick: useRef<HTMLSelectElement>(null),
  };

  const ssh = type === 'ssh';
  const connId = ssh ? sshId : id;
  const secretKind: SecretKind = ssh ? 'ssh_private_key' : auth === 'basic' ? 'password' : 'api_key';
  const tgt = parseTarget(target.trim());
  const clear = (k: ErrKey) => setErrs((x) => (x[k] ? { ...x, [k]: undefined } : x));
  const err = (k: ErrKey) => (errs[k] ? t(errs[k] as CopyKey) : null);
  const keyStored = !!stored && stored.id === connId && stored.env === env && stored.kind === secretKind;
  const existing = src === 'existing';
  const choices = keyChoices(secrets, env, type);
  const pick = choices.some((c) => c.id === pickId) ? pickId : choices[0]?.id ?? '';
  const secretIds = secrets.map((s) => s.id);

  // the live line under the address: encrypted host, plain http, a private address or an error
  let tgtLine: { text: string; tone: 'ok' | 'warn' | 'err' } | null = null;
  if (!tgt.ok) tgtLine = target.trim() ? { text: t(tgt.error === 'meta' ? 'service.c.url.err.meta' : 'service.c.url.err.format'), tone: 'err' } : null;
  else if (tgt.private && !allowPriv) tgtLine = { text: t('service.c.url.private'), tone: 'warn' };
  else if (!tgt.tls) tgtLine = { text: t('service.c.url.http'), tone: 'warn' };
  else tgtLine = { text: t('service.c.url.ok', { host: tgt.port === 443 ? tgt.host : `${tgt.host}:${tgt.port}` }), tone: 'ok' };

  const consq = writeConsequences(methods);
  const consqText = consq.length
    ? t('service.c.methods.consq', { list: consq.map((c) => t(CONSQ[c.method as keyof typeof CONSQ]) + (c.confirm ? ` (${t('service.c.methods.approve')})` : '')).join(', ') })
    : '';

  const pickKey = async () => {
    try {
      const f = await call('file_pick', { purpose: ssh ? 'ssh_key' : 'secret' });
      if (!f) return;
      setFile(f); setValue(''); setGen(false); clear('key');
      announce(ssh ? t('service.c.key.ssh.loaded', { name: f.name }) : t('service.c.key.loaded', { name: f.name }));
    } catch { setErrs((x) => ({ ...x, key: 'error.desktopOnly' })); }
  };
  const pickCa = async () => {
    try { const f = await call('file_pick', { purpose: 'ca' }); if (f) setCa(f); } catch { toast(t('error.desktopOnly'), 'warn'); }
  };

  const validate = (): ErrKey | null => {
    const e: Errs = {};
    if (!splitEnv(env)) e.env = 'service.c.err.place';
    if (!isValidName(connId)) e.id = 'service.c.err.name';
    else if (connections.some((c) => c.id === connId)) e.id = 'service.c.err.exists';
    // a new credential is stored under the connection's name, which must not belong to another item yet
    else if (!existing && !keyStored && secretIds.includes(connId)) e.id = 'service.c.err.keyExists';
    if (!ssh) {
      if (!tgt.ok) e.target = tgt.error === 'meta' ? 'service.c.url.err.meta' : 'service.c.url.err.format';
      else if (tgt.private && !allowPriv) e.target = 'service.c.url.private';
      if (auth === 'basic' && !isBasicUser(basicUser)) e.basic = 'service.c.basic.err';
      if (auth === 'header' && !isHeaderName(hdrName)) e.header = 'service.c.header.err';
      if (auth === 'header' && !isPlainText(hdrPrefix, 64)) e.prefix = 'service.c.prefix.err';
      if (!methodsPayload(methods).methods.length) e.methods = 'service.c.methods.err';
      if (parsePathPrefixes(paths) === null) e.paths = 'service.c.paths.err';
      if (cli === 'custom' && !isCliPath(cliPath)) e.cli = 'conn.cli.err';
    } else {
      if (!isSshHost(host)) e.host = 'service.c.ssh.host.err';
      if (parsePort(port) === null) e.port = 'service.c.ssh.port.err';
      if (!isSshUser(user)) e.user = 'service.c.ssh.user.err';
      if (!isHostKey(hostKey)) e.hostKey = 'service.c.ssh.hostKey.err';
      if (!isCliPath(sshCli.trim())) e.sshCli = 'conn.cli.err';
    }
    if (existing) { if (!pick) e.key = 'service.c.key.err.pick'; }
    else if (!keyStored && !value && !file && !gen) e.key = ssh ? 'service.c.key.ssh.need' : 'service.c.key.need';
    if (!pass) e.pass = 'pass.err.empty';
    setErrs(e);
    return ERR_ORDER.find((k) => e[k]) ?? null;
  };

  const focusErr = (k: ErrKey) => {
    if (k === 'paths' || k === 'cli' || k === 'sshCli') setMoreOpen(true);
    const el = k === 'key' && existing ? refs.pick.current : k === 'key' && ssh ? refs.keyFile.current
      : (refs as Record<string, { current: HTMLElement | null }>)[k]?.current;
    setTimeout(() => el?.focus(), 0);
  };

  const submit = async () => {
    if (running.current) return;
    const bad = validate();
    if (bad) { focusErr(bad); return; }
    const pair = splitEnv(env);
    if (!pair) return;
    running.current = true; setBusy(true);
    try {
      // the public half of a key generated by an earlier, failed try is still shown at the end
      let pubKey: string | null = !existing && keyStored ? stored?.pub ?? null : null;
      let secretId = connId;
      if (existing) {
        secretId = pick;
      } else if (!keyStored || value || file || gen) {
        const source: SecretSource = file ? { file_token: file.file_token } : gen ? { generate_ed25519: true } : { typed: value };
        const out = await call('secret_put', { id: connId, kind: secretKind, project: pair.project, environment: pair.environment, source });
        setValue(''); setFile(null); setGen(false);
        pubKey = publicKeyOf(out);
        setStored({ id: connId, env, kind: secretKind, pub: pubKey });
      }
      if (ssh) {
        await call('connection_create_ssh', {
          id: connId, project: pair.project, environment: pair.environment, service: connId, secret_id: secretId,
          host, port: parsePort(port) ?? 22, username: user, host_keys: [hostKey.trim()], cli_program: sshCli.trim(), admin_passphrase: pass,
        });
      } else {
        const m = methodsPayload(methods);
        await call('connection_create_http', {
          id: connId, project: pair.project, environment: pair.environment, service: connId, secret_id: secretId,
          target: target.trim().replace(/\/$/, ''), auth, methods: m.methods, confirm_methods: m.confirm_methods,
          path_prefixes: parsePathPrefixes(paths) ?? [], allow_private_network: tgt.ok && tgt.private && allowPriv,
          ...(auth === 'basic' ? { basic_username: basicUser } : {}),
          ...(auth === 'header' ? { header_name: hdrName, ...(hdrPrefix ? { value_prefix: hdrPrefix } : {}) } : {}),
          ...(cli === 'democli' ? { cli_program: 'democli' } : cli === 'custom' ? { cli_program: cliPath } : {}),
          ...(ca ? { ca_file_token: ca.file_token } : {}),
          admin_passphrase: pass,
        });
      }
      setPass('');
      toast(t('service.toast.created'), 'ok');
      onCreated(connId);
      if (pubKey) setPub(pubKey); else onClose();
    } catch (e) {
      setPass('');
      const r = toIpcError(e).reason;
      // a place this Mac may not write to (not one of its team's administrators) is said under it
      const team = teamWriteErrorKey(r);
      const hit: [ErrKey, CopyKey] | null = isAuthError(e) ? ['pass', passErrorKey(e)] : team ? ['env', team] : createErrorField(r, ssh);
      if (hit) { setErrs({ [hit[0]]: hit[1] }); focusErr(hit[0]); }
      else setErrs({ form: 'error.generic' });
    } finally { running.current = false; setBusy(false); }
  };

  if (pub !== null) {
    return (
      <Dialog open title={t('service.c.pub.title')} description={t('service.c.pub.sub')} onClose={onClose} size="md"
        footer={<Button tone="primary" onClick={onClose} data-autofocus="">{t('act.done')}</Button>}>
        <div className="field">
          <span className="field-label">{t('service.c.pub.label')}</span>
          <pre className="code" data-selectable="" tabIndex={0}>{pub}</pre>
        </div>
      </Dialog>
    );
  }

  const keyLabel = t(ssh ? 'service.c.key.ssh' : auth === 'basic' ? 'service.c.key.pw' : 'service.c.key.api');
  const keyHelp = keyStored && !value && !file && !gen ? t('service.c.key.stored')
    : ssh ? (file ? t('service.c.key.ssh.loaded', { name: file.name }) : gen ? t('service.c.key.ssh.genPending') : t('service.c.key.ssh.help'))
      : file ? t('service.c.key.loaded', { name: file.name }) : t('service.c.key.help');
  const placeOptions = pairs.map((p) => ({ value: p.key, label: placeLabel(p.project, p.environment) }));

  return (
    <Dialog open title={t('service.c.title')} description={t('service.c.sub')} onClose={onClose} busy={busy} size="lg" onSubmit={() => void submit()}
      id="service-create"
      footer={<>
        <Button tone="ghost" onClick={onClose} blocked={busy}>{t('act.cancel')}</Button>
        <Button tone="primary" type="submit" busy={busy}>{t('service.c.submit')}</Button>
      </>}>
      {pairs.length === 0 && <Banner tone="info">{t('service.c.noPlace')}</Banner>}
      <div className="form-grid">
        <Segmented<ConnType> label={t('service.c.type')} hideLabel={false} value={type}
          options={[{ value: 'http', label: t('service.c.type.http'), icon: 'globe' }, { value: 'ssh', label: t('service.c.type.ssh'), icon: 'terminal' }]}
          onChange={(v) => { setType(v); setValue(''); setFile(null); setGen(false); setErrs({}); setMoreOpen(false); }} />
        <SelectField label={t('service.c.place')} value={env} selectRef={refs.env} error={err('env')} name="conn-env"
          options={placeOptions} onChange={(v) => { setEnv(v); clear('env'); }} />
      </div>

      {!ssh && (
        <fieldset className="svc-form-group">
          <div className="form-grid svc-grid-name">
            <TextField label={t('service.c.name')} mono value={id} inputRef={refs.id} maxLength={64} error={err('id')} placeholder="example-api" name="conn-id"
              onChange={(v) => { setId(v); clear('id'); }} />
            <TextField label={t('service.c.url')} mono value={target} inputRef={refs.target} placeholder="https://api.example.com" name="conn-target"
              error={err('target')}
              help={tgtLine ? <span className={'svc-tgt is-' + tgtLine.tone} aria-live="polite">{tgtLine.text}</span> : undefined}
              onChange={(v) => { setTarget(v); clear('target'); }} />
          </div>
          {tgt.ok && tgt.private && (
            <Checkbox checked={allowPriv} onChange={(v) => { setAllowPriv(v); clear('target'); }}>{t('service.c.url.allowPrivate')}</Checkbox>
          )}
          <Segmented<Auth> label={t('service.c.auth')} hideLabel={false} value={auth}
            options={[{ value: 'bearer', label: 'Bearer' }, { value: 'basic', label: 'Basic' }, { value: 'header', label: 'Header' }]}
            onChange={(v) => { setAuth(v); setValue(''); clear('basic'); clear('header'); clear('prefix'); }} />
          {auth === 'basic' && (
            <TextField label={t('service.c.basic.user')} mono value={basicUser} inputRef={refs.basic} error={err('basic')} name="conn-basic"
              onChange={(v) => { setBasicUser(v); clear('basic'); }} />
          )}
          {auth === 'header' && (
            <div className="form-grid">
              <TextField label={t('service.c.header.name')} mono value={hdrName} inputRef={refs.header} error={err('header')} name="conn-header"
                onChange={(v) => { setHdrName(v); clear('header'); }} />
              <TextField label={t('service.c.header.prefix')} aside={t('service.c.header.prefix.aside')} mono value={hdrPrefix} inputRef={refs.prefix}
                placeholder="token" error={err('prefix')} name="conn-prefix" onChange={(v) => { setHdrPrefix(v); clear('prefix'); }} />
            </div>
          )}
          <div className={'field' + (errs.methods ? ' has-error' : '')}>
            <div className="field-label"><span id="svc-methods-lbl">{t('service.c.methods')}</span></div>
            <div className="svc-methods" role="group" aria-labelledby="svc-methods-lbl" aria-describedby="svc-methods-note">
              {METHODS.map((m: Method, i) => {
                const st = methods[m];
                return (
                  <button key={m} ref={i === 0 ? refs.methods : undefined} type="button" className="svc-method" data-state={st} aria-pressed={st !== 'off'}
                    aria-label={t(st === 'confirm' ? 'service.c.methods.confirmAria' : st === 'allow' ? 'service.c.methods.on' : 'service.c.methods.off', { m })}
                    onClick={() => { setMethods((x) => ({ ...x, [m]: nextMethodState(m, x[m]) })); clear('methods'); }}>
                    {st === 'allow' ? <Icon name="check" size={12} /> : st === 'confirm' ? <Icon name="shield" size={12} /> : <i className="svc-method-off" aria-hidden="true" />}
                    <span className="mono">{m}</span>
                    {st === 'confirm' && <span className="svc-method-tag" aria-hidden="true">{t('service.c.methods.approve')}</span>}
                  </button>
                );
              })}
            </div>
            <div className={'field-note' + (errs.methods ? ' is-error' : '')} id="svc-methods-note" role={errs.methods ? 'alert' : undefined}>
              {errs.methods ? <><Icon name="alert" size={13} />{err('methods')}</> : <span aria-live="polite">{consqText || t('service.c.methods.hint')}</span>}
            </div>
          </div>
          <details className="svc-more" open={moreOpen} onToggle={(e) => setMoreOpen((e.currentTarget as HTMLDetailsElement).open)}>
            <summary><Icon name="chevron-right" size={13} />{t('service.c.more')}</summary>
            <div className="svc-more-body">
              <TextField label={t('service.c.paths')} help={t('service.c.paths.hint')} mono value={paths} inputRef={refs.paths} placeholder="/v1, /repos"
                error={err('paths')} name="conn-paths" onChange={(v) => { setPaths(v); clear('paths'); }} />
              <SelectField label={t('service.c.cli')} value={cli} name="conn-cli"
                options={[{ value: '', label: t('service.c.cli.none') }, { value: 'democli', label: t('service.c.cli.demo') }, { value: 'custom', label: t('service.c.cli.custom') }]}
                onChange={(v) => { setCli(v as Cli); clear('cli'); }} />
              {cli === 'custom' && (
                <TextField label={t('service.c.cli.path')} mono value={cliPath} inputRef={refs.cli} placeholder="/usr/local/bin/…" name="conn-cli-path"
                  error={err('cli')} onChange={(v) => { setCliPath(v); clear('cli'); }} />
              )}
              <div className="field">
                <div className="field-label"><span>{t('service.c.ca')}</span><span className="field-aside">{t('service.c.ca.hint')}</span></div>
                <div className="row">
                  <Button size="sm" tone="secondary" icon="file" onClick={() => void pickCa()}>{t('service.c.ca.pick')}</Button>
                  {ca && <span className="mono text-sm truncate">{ca.name}</span>}
                </div>
              </div>
            </div>
          </details>
        </fieldset>
      )}

      {ssh && (
        <fieldset className="svc-form-group">
          <div className="svc-grid-ssh">
            <TextField label={t('service.c.name')} mono value={sshId} inputRef={refs.id} maxLength={64} error={err('id')} placeholder="deploy-ssh" name="conn-ssh-id"
              onChange={(v) => { setSshId(v); clear('id'); }} />
            <TextField label={t('service.c.ssh.host')} mono value={host} inputRef={refs.host} error={err('host')} placeholder="git.example.com" name="conn-ssh-host"
              onChange={(v) => { setHost(v); clear('host'); }} />
            <TextField label={t('service.c.ssh.port')} mono value={port} inputRef={refs.port} inputMode="numeric" maxLength={5} error={err('port')} name="conn-ssh-port"
              onChange={(v) => { setPort(v); clear('port'); }} />
          </div>
          <TextField label={t('service.c.ssh.user')} mono value={user} inputRef={refs.user} error={err('user')} placeholder="git" name="conn-ssh-user"
            onChange={(v) => { setUser(v); clear('user'); }} />
          <TextField label={t('service.c.ssh.hostKey')} mono value={hostKey} inputRef={refs.hostKey} placeholder="ssh-ed25519 AAAA…" name="conn-ssh-hostkey"
            error={err('hostKey')} help={t('service.c.ssh.hostKey.help')} onChange={(v) => { setHostKey(v); clear('hostKey'); }} />
          <details className="svc-more" open={moreOpen} onToggle={(e) => setMoreOpen((e.currentTarget as HTMLDetailsElement).open)}>
            <summary><Icon name="chevron-right" size={13} />{t('service.c.more')}</summary>
            <div className="svc-more-body">
              <TextField label={t('service.c.ssh.cli')} mono value={sshCli} inputRef={refs.sshCli} placeholder={SSH_PROGRAM} name="conn-ssh-cli"
                error={err('sshCli')} onChange={(v) => { setSshCli(v); clear('sshCli'); }} />
            </div>
          </details>
        </fieldset>
      )}

      <fieldset className="svc-form-group">
        <Segmented<KeySrc> label={t('service.c.key.source')} hideLabel={false} value={src}
          options={[{ value: 'new', label: t('service.c.key.new') }, { value: 'existing', label: t('service.c.key.existing') }]}
          onChange={(v) => { setSrc(v); clear('key'); clear('id'); if (v === 'existing') { setValue(''); setFile(null); setGen(false); } }} />
        {existing ? (
          choices.length > 0 ? (
            <SelectField label={t('service.c.key.pick')} value={pick} selectRef={refs.pick} error={err('key')} help={t('service.c.key.pick.help')} name="conn-key-pick"
              options={choices.map((c) => ({ value: c.id, label: `${c.id} · ${t(KIND_LABEL[c.kind])}` }))} onChange={(v) => { setPickId(v); clear('key'); }} />
          ) : (
            <Banner tone={errs.key ? 'danger' : 'neutral'} compact>{t('service.c.key.none')}</Banner>
          )
        ) : !ssh ? (
          <TextField label={keyLabel} type="password" autoComplete="off" mono value={value} inputRef={refs.key} error={err('key')} help={keyHelp} name="conn-key"
            suffix={<Button size="sm" tone="quiet" icon="file" onClick={() => void pickKey()}>{t('service.c.key.file')}</Button>}
            onChange={(v) => { setValue(v); setFile(null); clear('key'); }} />
        ) : (
          <div className={'field' + (errs.key ? ' has-error' : '')}>
            <div className="field-label"><span id="svc-key-lbl">{keyLabel}</span></div>
            <div className="row-wrap" role="group" aria-labelledby="svc-key-lbl" aria-describedby="svc-key-note">
              <Button size="sm" tone="secondary" icon="file" ref={refs.keyFile} aria-pressed={!!file} onClick={() => void pickKey()}>{t('service.c.key.ssh.file')}</Button>
              <Button size="sm" tone={gen ? 'secondary' : 'ghost'} icon={gen ? 'check' : 'plus'} aria-pressed={gen}
                onClick={() => { setGen(!gen); setFile(null); clear('key'); if (!gen) announce(t('service.c.key.ssh.genPending')); }}>{t('service.c.key.ssh.gen')}</Button>
            </div>
            <div className={'field-note' + (errs.key ? ' is-error' : '')} id="svc-key-note" role={errs.key ? 'alert' : undefined}>
              {errs.key ? <><Icon name="alert" size={13} />{err('key')}</> : keyHelp}
            </div>
          </div>
        )}
      </fieldset>

      <PassField value={pass} inputRef={refs.pass} error={err('pass')} name="conn-pass" onChange={(v) => { setPass(v); clear('pass'); }} />
      {errs.form && <Banner tone="danger">{t(errs.form)}</Banner>}
      <Banner tone="neutral" compact>{t('service.c.sameAccount')}</Banner>
    </Dialog>
  );
}
