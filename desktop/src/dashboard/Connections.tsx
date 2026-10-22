import { useRef, useState } from 'react';
import { t, type CopyKey } from '../copy';
import { call, toIpcError } from '../ipc/client';
import type { ConnectionView, Project, SecretKind, SecretSource, SecretView } from '../ipc/contract';
import {
  defaultMethodStates, envPairs, isBasicUser, isCliPath, isHeaderName, isHostKey, isPlainText, isSshHost, isSshUser, keyChoices, METHODS,
  methodsPayload, nextMethodState, parsePathPrefixes, parsePort, publicKeyOf, splitEnv, SSH_PROGRAM, summarizeConnection, writeConsequences,
  type Method, type MethodStates,
} from '../lib/dash';
import { isValidName, parseTarget } from '../lib/validators';
import { useApp } from '../ui/context';
import { PassField, SelectField, TextField, useSelectDefault } from '../ui/fields';
import { Callout, Segmented } from '../ui/form';
import { ConfirmSheet } from './Confirm';
import { passErrorKey, useClearOnClose, useDash, useIntent, useLoad, useSheets, type Intent } from './context';
import { kindLabel, PublicKey } from './Keys';
import { ListCard, metaLine, Row, SectionHead, Tag } from './parts';
import { Sheet } from './Sheet';

type ConnSheet = { kind: 'create' } | { kind: 'disable'; id: string };
const CONSQ: Record<'POST' | 'PUT' | 'PATCH' | 'DELETE', CopyKey> = {
  POST: 'conn.consq.POST', PUT: 'conn.consq.PUT', PATCH: 'conn.consq.PATCH', DELETE: 'conn.consq.DELETE',
};

/** Connections: API and SSH services the agents may use through the relay or the signer. */
export function ConnectionsPage({ intent, onIntent }: { intent?: Intent; onIntent(): void }) {
  const { tick, bump } = useDash();
  const [n, setN] = useState(0);
  const load = useLoad(async () => {
    const [c, p, s] = await Promise.all([call('connection_list'), call('project_list'), call('secret_list', {})]);
    return { connections: c.connections, projects: p.projects, secrets: s.secrets };
  }, [tick, n]);
  const reload = () => setN((x) => x + 1);
  const sheets = useSheets<ConnSheet>();
  useIntent(intent, onIntent, (i) => { if (i === 'add-connection') { sheets.open({ kind: 'create' }); return true; } return false; });

  const addBtn = <button className="btn btn-primary btn-sm" type="button" onClick={() => sheets.open({ kind: 'create' })}>{t('conns.add')}</button>;
  const list = load.data?.connections ?? null;

  return (
    <>
      <SectionHead title={t('conns.list')}>{list && list.length > 0 && addBtn}</SectionHead>
      <ListCard items={list} failed={load.failed} empty="page.connections.empty" emptyAction={addBtn} label={t('conns.list')}>
        {(items) => items.map((c) => {
          const s = summarizeConnection(c);
          return (
            <Row key={c.id} dot={s.active ? 'on' : 'idle'} mono name={c.id}
              tag={<Tag>{s.kind === 'http' ? 'API' : s.kind === 'ssh' ? 'SSH' : String(c.kind)}</Tag>}
              meta={metaLine(s.host, s.env, s.active ? null : t('st.disabled'))}>
              {s.active && (
                <button className="btn btn-text btn-sm" type="button" aria-label={t('conns.disable.aria', { id: c.id })}
                  onClick={() => sheets.open({ kind: 'disable', id: c.id })}>{t('conns.disable')}</button>
              )}
            </Row>
          );
        })}
      </ListCard>

      <CreateConnectionSheet key={sheets.key('create')} open={sheets.isOpen('create')} projects={load.data?.projects ?? []}
        connections={list ?? []} secrets={load.data?.secrets ?? []} onClose={sheets.close} onCreated={() => { reload(); bump(); }} />
      <DisableSheet key={sheets.key('disable')} open={sheets.isOpen('disable')} id={sheets.data('disable')?.id ?? ''}
        onClose={sheets.close} onDone={() => { sheets.close(); reload(); }} />
    </>
  );
}

function DisableSheet({ open, id, onClose, onDone }: { open: boolean; id: string; onClose(): void; onDone(): void }) {
  const { toast } = useApp();
  return (
    <ConfirmSheet id="sheet-conn-disable" open={open} title={t('conns.disable.title')} lead={t('conns.disable.sub')}
      confirmLabel={t('conns.disable.confirm')} chips={[id]} warn={t('conns.disable.warn')} notes={[t('session.note')]} onClose={onClose}
      run={async () => { await call('connection_disable', { id }); toast(t('toast.conn.disabled')); onDone(); }} />
  );
}

// ---------------------------------------------------------------- create

type ConnType = 'http' | 'ssh';
type Auth = 'bearer' | 'basic' | 'header';
type Cli = '' | 'democli' | 'custom';
type KeySrc = 'new' | 'existing';
type ErrKey = 'env' | 'id' | 'target' | 'basic' | 'header' | 'prefix' | 'methods' | 'paths' | 'cli' | 'host' | 'port' | 'user' | 'hostKey' | 'sshCli' | 'key' | 'pass' | 'form';
type Errs = Partial<Record<ErrKey, CopyKey>>;

/** The API/SSH form from the mockup's connection step. The key is either a stored one from the
 *  same project/environment (Keys page) or a new one: a new key is stored first (`secret_put`,
 *  named after the connection), then the connection is created with the admin passphrase. A typed
 *  key leaves the screen as soon as it is stored. A generated SSH key's public half is kept until
 *  the connection exists, so it is shown even when the first try failed. */
function CreateConnectionSheet({ open, projects, connections, secrets, onClose, onCreated }: {
  open: boolean; projects: Project[]; connections: ConnectionView[]; secrets: SecretView[]; onClose(): void; onCreated(): void;
}) {
  const { toast, field, announce } = useApp();
  const pairs = envPairs(projects);
  const secretIds = secrets.map((s) => s.id);
  const [type, setType] = useState<ConnType>('http');
  const [src, setSrc] = useState<KeySrc>('new');
  const [pickId, setPickId] = useState('');
  const [env, setEnv] = useState(pairs[0]?.key ?? '');
  useSelectDefault(env, pairs.map((p) => p.key), setEnv);
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
  const [pub, setPub] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const refs = {
    env: useRef<HTMLSelectElement>(null), id: useRef<HTMLInputElement>(null), target: useRef<HTMLInputElement>(null),
    basic: useRef<HTMLInputElement>(null), header: useRef<HTMLInputElement>(null), prefix: useRef<HTMLInputElement>(null),
    methods: useRef<HTMLButtonElement>(null), paths: useRef<HTMLInputElement>(null), cli: useRef<HTMLInputElement>(null),
    host: useRef<HTMLInputElement>(null), port: useRef<HTMLInputElement>(null), user: useRef<HTMLInputElement>(null),
    hostKey: useRef<HTMLInputElement>(null), sshCli: useRef<HTMLInputElement>(null), key: useRef<HTMLInputElement>(null),
    keyFile: useRef<HTMLButtonElement>(null), pass: useRef<HTMLInputElement>(null), more: useRef<HTMLDetailsElement>(null),
    pick: useRef<HTMLSelectElement>(null),
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

  // the typed key and the passphrase never outlive the sheet
  useClearOnClose(open, () => { setValue(''); setFile(null); setPass(''); });

  // target line under the address: encrypted host, plain http, a private address or an error
  let tgtLine: { text: string; cls: string } | null = null;
  if (!tgt.ok) tgtLine = target.trim() ? { text: t(tgt.error === 'meta' ? 'conn.url.err.meta' : 'conn.url.err.format'), cls: 'help err' } : null;
  else if (tgt.private && !allowPriv) tgtLine = { text: t('conn.url.private'), cls: 'help warn' };
  else if (!tgt.tls) tgtLine = { text: t('conn.url.http'), cls: 'help warn' };
  else tgtLine = { text: t('conn.url.ok', { host: tgt.port === 443 ? tgt.host : `${tgt.host}:${tgt.port}` }), cls: 'help' };

  const consq = writeConsequences(methods);
  const consqText = consq.length
    ? `${t('conn.methods.consq')} ${consq.map((c) => t(CONSQ[c.method as keyof typeof CONSQ]) + (c.confirm ? `(${t('conn.methods.approve')})` : '')).join(', ')}`
    : '';

  const pickKey = async () => {
    try {
      const f = await call('file_pick', { purpose: ssh ? 'ssh_key' : 'secret' });
      if (!f) return;
      setFile(f); setValue(''); setGen(false); clear('key'); field.ripple(0.05);
      announce(ssh ? t('conn.ssh.loaded') : t('keys.value.loaded', { name: f.name }));
    } catch { setErrs((x) => ({ ...x, key: 'error.desktopOnly' })); }
  };
  const pickCa = async () => {
    try { const f = await call('file_pick', { purpose: 'ca' }); if (f) setCa(f); } catch { toast(t('error.desktopOnly'), 'warn'); }
  };

  const validate = (): ErrKey | null => {
    const e: Errs = {};
    if (!splitEnv(env)) e.env = 'keys.err.env';
    if (!isValidName(connId)) e.id = 'proj.err.name';
    else if (connections.some((c) => c.id === connId)) e.id = 'conn.err.exists';
    // a new key is stored under the connection's name, which must not belong to another key yet
    else if (!existing && !keyStored && secretIds.includes(connId)) e.id = 'conn.err.keyExists';
    if (!ssh) {
      if (!tgt.ok) e.target = tgt.error === 'meta' ? 'conn.url.err.meta' : 'conn.url.err.format';
      else if (tgt.private && !allowPriv) e.target = 'conn.url.private';
      if (auth === 'basic' && !isBasicUser(basicUser)) e.basic = 'conn.basic.err';
      if (auth === 'header' && !isHeaderName(hdrName)) e.header = 'conn.header.err';
      if (auth === 'header' && !isPlainText(hdrPrefix, 64)) e.prefix = 'conn.header.err';
      if (!methodsPayload(methods).methods.length) e.methods = 'proj.err.envs';
      if (parsePathPrefixes(paths) === null) e.paths = 'conn.paths.err';
      if (cli === 'custom' && !isCliPath(cliPath)) e.cli = 'conn.cli.err';
    } else {
      if (!isSshHost(host)) e.host = 'conn.ssh.host.err';
      if (parsePort(port) === null) e.port = 'conn.ssh.port.err';
      if (!isSshUser(user)) e.user = 'conn.ssh.user.err';
      if (!isHostKey(hostKey)) e.hostKey = 'conn.ssh.hostkey.err';
      if (!isCliPath(sshCli.trim())) e.sshCli = 'conn.cli.err';
    }
    if (existing) { if (!pick) e.key = 'conn.key.err.pick'; }
    else if (!keyStored && !value && !file && !gen) e.key = ssh ? 'conn.ssh.keyerr' : 'conn.key.need';
    if (!pass) e.pass = 'pass.err.empty';
    setErrs(e);
    const order: ErrKey[] = ['env', 'id', 'target', 'basic', 'header', 'prefix', 'methods', 'paths', 'cli', 'host', 'port', 'user', 'hostKey', 'sshCli', 'key', 'pass'];
    return order.find((k) => e[k]) ?? null;
  };

  const focusErr = (k: ErrKey) => {
    // the HTTP and SSH forms each have their own "more" section; only the shown one holds the ref
    if ((k === 'paths' || k === 'cli' || k === 'sshCli') && refs.more.current) refs.more.current.open = true;
    const el = k === 'key' && existing ? refs.pick.current : k === 'key' && ssh ? refs.keyFile.current : (refs as Record<string, { current: HTMLElement | null }>)[k]?.current;
    setTimeout(() => el?.focus(), 0);
  };

  const submit = async () => {
    const bad = validate();
    if (bad) { focusErr(bad); return; }
    const pair = splitEnv(env);
    if (!pair) return;
    setBusy(true);
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
      field.ripple(0.09);
      toast(t('toast.conn.created'));
      onCreated();
      if (pubKey) { setPub(pubKey); setDone(true); } else onClose();
    } catch (e) {
      setPass('');
      const ipc = toIpcError(e);
      const r = ipc.reason;
      const map: Record<string, [ErrKey, CopyKey]> = {
        connection_exists: ['id', 'conn.err.exists'], invalid_connection_id: ['id', 'proj.err.name'], secret_identity_mismatch: ['id', 'conn.err.keyExists'],
        invalid_scheme: ['target', 'conn.url.err.format'], target_must_be_origin: ['target', 'conn.url.err.format'],
        metadata_address_not_allowed: ['target', 'conn.url.err.meta'], target_address_not_allowed: ['target', 'conn.url.private'],
        invalid_host: ['host', 'conn.ssh.host.err'], invalid_port: ['port', 'conn.ssh.port.err'], invalid_ssh_username: ['user', 'conn.ssh.user.err'],
        invalid_host_key: ['hostKey', 'conn.ssh.hostkey.err'], unsupported_host_key: ['hostKey', 'conn.ssh.hostkey.err'], ssh_host_keys_required: ['hostKey', 'conn.ssh.hostkey.err'],
        invalid_header_name: ['header', 'conn.header.err'], invalid_basic_username: ['basic', 'conn.basic.err'],
        invalid_secret_value: ['key', 'keys.err.value'], file_token_unknown: ['key', 'keys.err.value'],
        host_key_required: ['hostKey', 'conn.ssh.hostkey.err'],
        cli_program_required: ['sshCli', 'conn.cli.err'], invalid_cli_program: [ssh ? 'sshCli' : 'cli', 'conn.cli.err'],
        secret_kind_mismatch: ['key', 'conn.key.err.kind'], secret_scope_mismatch: ['key', 'conn.key.err.pick'],
        secret_version_unusable: ['key', 'conn.key.err.unusable'], secret_not_found: ['key', 'conn.key.err.pick'],
      };
      const hit = ipc.error === 'AuthFailed' ? (['pass', passErrorKey(e)] as [ErrKey, CopyKey]) : map[r];
      if (hit) { setErrs({ [hit[0]]: hit[1] }); focusErr(hit[0]); }
      else setErrs({ form: 'error.generic' });
    } finally { setBusy(false); }
  };

  if (done && pub !== null) {
    return (
      <Sheet id="sheet-conn" open={open} title={t('conn.title')} lead={t('conn.ssh.generated')} onClose={onClose} closeLabel={t('common.done')}>
        <PublicKey text={pub} />
      </Sheet>
    );
  }

  const keyLabel = t(ssh ? 'conn.key.ssh' : auth === 'basic' ? 'conn.key.pw' : 'conn.key.api');
  const keyHelp = keyStored && !value && !file && !gen ? t('conn.key.stored')
    : ssh ? (file ? `${t('conn.ssh.loaded')} · ${file.name}` : gen ? t('conn.ssh.keygen.pending') : t('conn.ssh.keyhelp'))
      : file ? t('keys.value.loaded', { name: file.name }) : t('conn.key.help');

  return (
    <Sheet id="sheet-conn" open={open} title={t('conn.title')} lead={t('conn.sub')} primaryLabel={t('conn.next')} busy={busy}
      onPrimary={() => void submit()} onClose={onClose}>
      {pairs.length === 0 && <Callout kind="info">{t('keys.err.noEnv')}</Callout>}
      <div className="row">
        <div className="field">
          <div className="label"><span id="conn-type-lbl">{t('conn.type.aria')}</span></div>
          <Segmented<ConnType> name="conn-type" labelledBy="conn-type-lbl" value={type}
            options={[{ value: 'http', label: 'API' }, { value: 'ssh', label: 'SSH' }]}
            onChange={(v) => { setType(v); setValue(''); setFile(null); setGen(false); setErrs({}); }} />
        </div>
        <SelectField id="conn-env" label={t('conn.env')} mono value={env} selectRef={refs.env} error={err('env')}
          options={pairs.map((p) => ({ value: p.key, label: p.key }))} onChange={(v) => { setEnv(v); clear('env'); }} />
      </div>

      {!ssh && (
        <>
          <div className="row">
            <TextField id="conn-id" label={t('conn.name')} mono value={id} inputRef={refs.id} maxLength={64} error={err('id')} style={{ flex: 0.75 }} placeholder="example-api"
              onChange={(v) => { setId(v); clear('id'); }} />
            <TextField id="conn-target" label={t('conn.url')} mono value={target} inputRef={refs.target} style={{ flex: 1.5 }} placeholder="https://api.example.com"
              invalid={!!errs.target || (!tgt.ok && !!target.trim())} describedBy="conn-target-state" onChange={(v) => { setTarget(v); clear('target'); }} />
          </div>
          <div className={(tgtLine?.cls ?? 'help') + ' tight'} id="conn-target-state" aria-live="polite">{tgtLine?.text ?? ''}</div>
          {tgt.ok && tgt.private && (
            <label className="check tight">
              <input type="checkbox" checked={allowPriv} onChange={(e) => { setAllowPriv(e.target.checked); clear('target'); }} /> <span>{t('conn.url.allowPrivate')}</span>
            </label>
          )}
          <div className="field">
            <div className="label"><span id="conn-auth-lbl">{t('conn.auth')}</span></div>
            <Segmented<Auth> name="conn-auth" labelledBy="conn-auth-lbl" value={auth}
              options={[{ value: 'bearer', label: 'Bearer' }, { value: 'basic', label: 'Basic' }, { value: 'header', label: 'Header' }]}
              onChange={(v) => { setAuth(v); setValue(''); clear('basic'); clear('header'); }} />
          </div>
          {auth === 'basic' && (
            <TextField id="conn-basic" label={t('conn.basic.user')} mono value={basicUser} inputRef={refs.basic} error={err('basic')}
              onChange={(v) => { setBasicUser(v); clear('basic'); }} />
          )}
          {auth === 'header' && (
            <div className="row">
              <TextField id="conn-hdr" label={t('conn.header.name')} mono value={hdrName} inputRef={refs.header} error={err('header')}
                onChange={(v) => { setHdrName(v); clear('header'); }} />
              <TextField id="conn-hdr-prefix" label={t('conn.header.prefix')} mono value={hdrPrefix} inputRef={refs.prefix} placeholder="token"
                error={err('prefix')} onChange={(v) => { setHdrPrefix(v); clear('prefix'); }} />
            </div>
          )}
          <div className="field">
            <div className="label"><span id="conn-methods-lbl">{t('conn.methods')}</span><span className="hint" id="conn-methods-hint">{t('conn.methods.hint')}</span></div>
            <div className="chips" role="group" aria-labelledby="conn-methods-lbl" aria-describedby="conn-methods-hint conn-methods-err">
              {METHODS.map((m: Method, i) => {
                const st = methods[m];
                return (
                  <button key={m} ref={i === 0 ? refs.methods : undefined} className="chip" type="button" data-state={st} aria-pressed={st !== 'off'}
                    aria-label={m + (st === 'confirm' ? `, ${t('conn.methods.approve')}` : '')}
                    onClick={() => { setMethods((x) => ({ ...x, [m]: nextMethodState(m, x[m]) })); clear('methods'); field.ripple(0.02); }}>
                    <i aria-hidden="true" />{m}<span className="req" aria-hidden="true">{st === 'confirm' ? t('conn.methods.approve') : ''}</span>
                  </button>
                );
              })}
            </div>
            <div className="help" aria-live="polite">{consqText}</div>
            <div className="help err" id="conn-methods-err" hidden={!errs.methods}>{err('methods') ?? ''}</div>
          </div>
          <details className="more" ref={refs.more}>
            <summary>{t('conn.more')}</summary>
            <div className="inner">
              <TextField id="conn-paths" label={t('conn.paths')} hint={t('conn.paths.hint')} mono value={paths} inputRef={refs.paths} placeholder="/v1, /repos"
                error={err('paths')} onChange={(v) => { setPaths(v); clear('paths'); }} />
              <SelectField id="conn-cli" label={t('conn.cli')} mono value={cli}
                options={[{ value: '', label: t('conn.cli.none') }, { value: 'democli', label: t('conn.cli.demo') }, { value: 'custom', label: t('conn.cli.custom') }]}
                onChange={(v) => { setCli(v as Cli); clear('cli'); }} />
              {cli === 'custom' && (
                <TextField id="conn-cli-path" label={t('conn.cli.path')} mono value={cliPath} inputRef={refs.cli} placeholder="/usr/local/bin/…"
                  error={err('cli')} onChange={(v) => { setCliPath(v); clear('cli'); }} />
              )}
              <div className="field">
                <div className="label"><span id="conn-ca-lbl">{t('conn.ca')}</span><span className="hint">{t('conn.ca.hint')}</span></div>
                <div className="file-line">
                  <button className="btn btn-ghost btn-sm" type="button" aria-describedby="conn-ca-lbl" onClick={() => void pickCa()}>{t('conn.key.file')}</button>
                  {ca && <span className="mono">{ca.name}</span>}
                </div>
              </div>
            </div>
          </details>
        </>
      )}

      {ssh && (
        <>
          <div className="row">
            <TextField id="conn-ssh-id" label={t('conn.name')} mono value={sshId} inputRef={refs.id} maxLength={64} error={err('id')} style={{ flex: 0.9 }} placeholder="deploy-ssh"
              onChange={(v) => { setSshId(v); clear('id'); }} />
            <TextField id="conn-ssh-host" label={t('conn.ssh.host')} mono value={host} inputRef={refs.host} error={err('host')} style={{ flex: 1.4 }} placeholder="git.example.com"
              onChange={(v) => { setHost(v); clear('host'); }} />
            <TextField id="conn-ssh-port" label={t('conn.ssh.port')} mono value={port} inputRef={refs.port} inputMode="numeric" maxLength={5} error={err('port')}
              style={{ flex: 0.5 }} onChange={(v) => { setPort(v); clear('port'); }} />
          </div>
          <TextField id="conn-ssh-user" label={t('conn.ssh.user')} mono value={user} inputRef={refs.user} error={err('user')} placeholder="git"
            onChange={(v) => { setUser(v); clear('user'); }} />
          <TextField id="conn-ssh-hostkey" label={t('conn.ssh.hostkey')} hint={t('conn.ssh.hostkey.hint')} mono value={hostKey} inputRef={refs.hostKey}
            placeholder="ssh-ed25519 AAAA…" error={err('hostKey')} help={t('conn.ssh.note')} onChange={(v) => { setHostKey(v); clear('hostKey'); }} />
          <details className="more" ref={refs.more}>
            <summary>{t('conn.more')}</summary>
            <div className="inner">
              <TextField id="conn-ssh-cli" label={t('conn.ssh.cli')} mono value={sshCli} inputRef={refs.sshCli} placeholder={SSH_PROGRAM}
                error={err('sshCli')} onChange={(v) => { setSshCli(v); clear('sshCli'); }} />
            </div>
          </details>
        </>
      )}

      <div className="field key-src">
        <div className="label"><span id="conn-key-src-lbl">{t('conn.key.source')}</span></div>
        <Segmented<KeySrc> name="conn-key-src" labelledBy="conn-key-src-lbl" value={src}
          options={[{ value: 'new', label: t('conn.key.new') }, { value: 'existing', label: t('conn.key.existing') }]}
          onChange={(v) => { setSrc(v); clear('key'); clear('id'); if (v === 'existing') { setValue(''); setFile(null); setGen(false); } }} />
      </div>

      {existing ? (
        choices.length > 0 ? (
          <SelectField id="conn-key-pick" label={t('conn.key.existing')} mono value={pick} selectRef={refs.pick} error={err('key')} help={t('conn.key.existing.help')}
            options={choices.map((c) => ({ value: c.id, label: `${c.id} · ${kindLabel(c.kind)}` }))} onChange={(v) => { setPickId(v); clear('key'); }} />
        ) : (
          <div className="field">
            <div className="help" id="conn-key-none">{t('conn.key.none')}</div>
            <div className="help err" hidden={!errs.key}>{err('key') ?? ''}</div>
          </div>
        )
      ) : !ssh ? (
        <TextField id="conn-key" label={keyLabel} type="password" mono value={value} inputRef={refs.key} error={err('key')} help={keyHelp}
          suffix={<button className="icon-btn" type="button" onClick={() => void pickKey()}>{t('conn.key.file')}</button>}
          onChange={(v) => { setValue(v); setFile(null); clear('key'); }} />
      ) : (
        <div className="field">
          <div className="label"><span id="conn-key-lbl">{keyLabel}</span></div>
          <div className="input key-box" role="group" aria-labelledby="conn-key-lbl" aria-describedby="conn-key-help conn-key-err" data-invalid={errs.key ? '' : undefined}>
            <button className="btn btn-ghost btn-sm" type="button" ref={refs.keyFile} aria-pressed={!!file} onClick={() => void pickKey()}>{t('conn.ssh.keyfile')}</button>
            <button className="btn btn-text btn-sm" type="button" aria-pressed={gen}
              onClick={() => { setGen(!gen); setFile(null); clear('key'); if (!gen) announce(t('conn.ssh.keygen.pending')); }}>{t('conn.ssh.keygen')}</button>
          </div>
          <div className="help" id="conn-key-help">{keyHelp}</div>
          <div className="help err" id="conn-key-err" hidden={!errs.key}>{err('key') ?? ''}</div>
        </div>
      )}

      <PassField id="conn-pass" value={pass} inputRef={refs.pass} error={err('pass')} onChange={(v) => { setPass(v); clear('pass'); }} />
      {errs.form && <div className="help err" role="alert">{t(errs.form)}</div>}
      <Callout kind="info">{t('keys.sameAccount')}</Callout>
    </Sheet>
  );
}
