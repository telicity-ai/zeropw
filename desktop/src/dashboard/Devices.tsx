import { useEffect, useRef, useState } from 'react';
import { t, type CopyKey } from '../copy';
import { call, toIpcError } from '../ipc/client';
import type { JoinRequest, LinkStatus, PairingCreated, Project } from '../ipc/contract';
import { deviceRows, pairingEnvs, requestsByDevice, type DeviceRow, type DeviceState } from '../lib/devices';
import { inviteFraction, msLeft } from '../lib/dash';
import { shortTime } from '../lib/format';
import { enrollErrorKey } from '../lib/pairing';
import { poll } from '../lib/poll';
import { formatCountdown, formatFingerprint } from '../lib/validators';
import { useApp } from '../ui/context';
import { useDisclosure } from '../ui/disclosure';
import { PassField, TextField } from '../ui/fields';
import { Callout } from '../ui/form';
import { Sigil } from '../ui/pixels';
import { useSecureGate } from '../ui/secure';
import { ConfirmSheet } from './Confirm';
import { passErrorKey, useClearOnClose, useDash, useLoad, useNow, useSheets, type Intent } from './context';
import { PairJoinBody, usePairJoin } from './pairJoin';
import { Empty, ListCard, metaLine, Row, SectionHead, Tag, type Dot } from './parts';
import { Sheet } from './Sheet';

/** How often the page re-reads the devices while it is visible, and the add-device sheet the
 *  join requests while its code is out. */
export const DEVICES_POLL_MS = 5000;
export const REQUESTS_POLL_MS = 3000;

export const STATE_COPY: Record<DeviceState, CopyKey> = {
  conflict: 'devices.st.conflict', retrying: 'devices.st.retrying', offline: 'devices.st.offline', syncing: 'devices.st.syncing',
  connected: 'devices.st.connected', up_to_date: 'devices.st.up_to_date', waiting: 'devices.st.waiting',
};
const STATE_DOT: Record<DeviceState, Dot> = {
  conflict: 'warn', retrying: 'warn', offline: 'idle', syncing: 'live', connected: 'on', up_to_date: 'on', waiting: 'idle',
};

type DevSheet = { kind: 'add' } | { kind: 'join' } | { kind: 'remove'; row: DeviceRow };

/** The devices page (nav.devices): this Mac at the link service, the Macs paired with it and their sync state, adding a
 *  Mac (a one-time pairing code, then approving the request it makes) and joining another Mac's
 *  vault with its code. Names come from the other Macs and are rendered as text. */
export function DevicesPage({ intent, onIntent }: { intent?: Intent; onIntent(): void }) {
  const { tick, go, bump } = useDash();
  const { toast } = useApp();
  const [n, setN] = useState(0);
  const reload = () => setN((x) => x + 1);
  const data = useLoad(() => call('devices_overview'), [tick, n]);
  const sheets = useSheets<DevSheet>();
  const o = data.data;
  const rows = o ? deviceRows(o) : null;

  // re-read while the page is visible: the state of the other Macs changes on its own
  useEffect(() => {
    const id = setInterval(() => { if (!document.hidden) setN((x) => x + 1); }, DEVICES_POLL_MS);
    return () => clearInterval(id);
  }, []);
  useEffect(() => {
    if (intent === 'pair-add') { sheets.open({ kind: 'add' }); onIntent(); }
    if (intent === 'pair-join') { sheets.open({ kind: 'join' }); onIntent(); }
  }, [intent]);

  const link = o?.link ?? null;
  const add = () => {
    if (!link?.enrolled) { toast(t('pair.add.needEnroll'), 'warn'); return; }
    sheets.open({ kind: 'add' });
  };
  const removeData = sheets.data('remove');
  const conflict = rows?.some((r) => r.state === 'conflict');

  return (
    <>
      <div className="glass pad">
        {!link
          ? <Empty text={data.failed ? t('error.load') : t('boot.loading')} />
          : !link.available
            ? <Callout kind="info">{t('devices.unavailable')}</Callout>
            : !link.running
              ? <Callout kind="info">{t('devices.down')}</Callout>
              : !link.enrolled
                ? <EnrollCard link={link} onEnrolled={() => { toast(t('toast.devices.enrolled')); reload(); bump(); }} />
                : (
                  <ul className="list" aria-label={t('devices.self')}>
                    <Row dot={link.online ? 'on' : 'idle'} name={link.device_name} tag={<Tag>{t('devices.self')}</Tag>}
                      meta={metaLine(link.service_host, t(link.online ? 'devices.self.online' : 'devices.self.offline'))} />
                  </ul>
                )}
      </div>

      <SectionHead title={t('devices.list')}>
        <button className="btn btn-ghost btn-sm" type="button" onClick={() => sheets.open({ kind: 'join' })}>{t('devices.join')}</button>
        <button className="btn btn-primary btn-sm" type="button" aria-disabled={!link?.enrolled || undefined} onClick={add}>{t('devices.add')}</button>
      </SectionHead>
      {o?.devices_error && <Callout kind="info">{t('devices.err.records')}</Callout>}
      {conflict && (
        <Callout kind="info">{t('devices.conflict.help')} <button className="btn btn-ghost btn-sm" type="button" onClick={() => go('logs', 'alerts')}>{t('devices.conflict.go')}</button></Callout>
      )}
      <ListCard items={rows} failed={data.failed} empty="devices.empty" label={t('devices.list')}>
        {(items) => items.map((r) => (
          <DeviceItem key={r.key} row={r} onRemove={() => sheets.open({ kind: 'remove', row: r })} />
        ))}
      </ListCard>

      <AddDeviceSheet key={sheets.key('add')} open={sheets.isOpen('add')} link={link} onClose={() => { sheets.close(); reload(); }} onChanged={reload} />
      <JoinPairSheet key={sheets.key('join')} open={sheets.isOpen('join')} onClose={() => { sheets.close(); reload(); bump(); }} />
      <ConfirmSheet key={sheets.key('remove')} id="sheet-device-remove" open={sheets.isOpen('remove')} title={t('devices.remove.title')} lead={t('devices.remove.sub')}
        confirmLabel={t('devices.remove.confirm')} needPass={!!removeData && removeData.row.envs.length > 0} onClose={sheets.close}
        chips={removeData ? [removeData.row.name, ...(removeData.row.fingerprint ? [formatFingerprint(removeData.row.fingerprint)] : [])] : []}
        warn={t('devices.remove.warn')} info={t('devices.remove.note')}
        errorFor={(e) => (toIpcError(e).reason === 'cannot_remove_self' ? 'error.generic' : null)}
        run={async (pass) => {
          if (!removeData) return;
          const r = removeData.row;
          const out = await call('device_remove', {
            ...(r.fingerprint ? { fingerprint: r.fingerprint } : {}), ...(r.linkId ? { link_device_id: r.linkId } : {}),
            ...(r.envs.length ? { admin_passphrase: pass } : {}),
          });
          reload(); bump();
          if (out.failed.length) {
            toast(t(out.failed.some((f) => f.reason === 'cannot_remove_owner') ? 'devices.remove.owner' : 'devices.remove.partial'), 'warn');
            return;
          }
          if (out.link_error) { toast(t('devices.remove.linkFailed'), 'warn'); return; }
          toast(t('toast.devices.removed'), 'warn');
          sheets.close();
        }} />
    </>
  );
}

/** One paired Mac: its state in plain words, and how it is connected only under the connection details (devices.detail). */
export function DeviceItem({ row, onRemove }: { row: DeviceRow; onRemove(): void }) {
  const d = row.detail;
  const path = d.path === null ? t('devices.detail.none') : t(d.path === 'direct' ? 'devices.path.direct' : 'devices.path.relay');
  return (
    <Row dot={STATE_DOT[row.state]} name={row.name}
      meta={metaLine(t(STATE_COPY[row.state]), row.linkOnly ? t('devices.linkOnly') : t('devices.envs', { n: row.envs.length }), row.fingerprint ? formatFingerprint(row.fingerprint) : null)}
      sub={(
        <details className="device-detail">
          <summary>{t('devices.detail')}</summary>
          <dl className="kv">
            <dt>{t('devices.detail.path')}</dt><dd>{path}{d.pathLabel && <span className="mono"> {d.pathLabel}</span>}</dd>
            <dt>{t('devices.detail.error')}</dt><dd className="mono">{d.lastError ?? t('devices.detail.none')}</dd>
            <dt>{t('devices.detail.contact')}</dt><dd>{d.lastContact ? shortTime(d.lastContact) : t('devices.detail.none')}</dd>
            {d.rttMs !== null && <><dt>{t('devices.detail.rtt')}</dt><dd className="mono">{`${d.rttMs} ms`}</dd></>}
          </dl>
        </details>
      )}>
      <button className="btn btn-text btn-sm" type="button" aria-label={t('devices.remove.aria', { name: row.name })} onClick={onRemove}>{t('devices.remove')}</button>
    </Row>
  );
}

/** Enrol this Mac with the link service: the server invite code once (a password field; it goes
 *  to the core, which puts it only in the daemon's request). The server address and this Mac's
 *  name are in the details with their defaults. */
export function EnrollCard({ link, onEnrolled }: { link: LinkStatus; onEnrolled(): void }) {
  const [code, setCode] = useState('');
  const [service, setService] = useState(link.default_service);
  const [name, setName] = useState(link.device_name);
  const [err, setErr] = useState<CopyKey | null>(null);
  const [busy, setBusy] = useState(false);
  const more = useDisclosure(false);
  const codeRef = useRef<HTMLInputElement>(null);
  const submit = async () => {
    if (busy) return;
    const compact = code.replace(/[\s-]/g, '').toUpperCase();
    if (!/^ZPL[A-Z2-7]{26}$/.test(compact)) { setErr('devices.enroll.err.code'); codeRef.current?.focus(); return; }
    setBusy(true); setErr(null);
    try {
      await call('link_enroll', { invite_code: code, ...(service.trim() && service.trim() !== link.default_service ? { service: service.trim() } : {}), ...(name.trim() ? { name: name.trim() } : {}) });
      setCode('');
      onEnrolled();
    } catch (e) {
      const key = enrollErrorKey(toIpcError(e).reason);
      setCode('');
      setErr(key);
      if (key === 'devices.enroll.err.service') more.reveal();
      codeRef.current?.focus();
    } finally { setBusy(false); }
  };
  return (
    <form className="enroll" noValidate onSubmit={(e) => { e.preventDefault(); void submit(); }}>
      <h3 className="section-title">{t('devices.enroll.title')}</h3>
      <p className="page-help">{t('devices.enroll.sub')}</p>
      <TextField id="enroll-code" label={t('devices.enroll.field')} type="password" mono value={code} inputRef={codeRef} placeholder="ZPL-…" maxLength={64}
        error={err ? t(err) : null} onChange={(v) => { setCode(v); setErr(null); }} />
      <details open={more.open} onToggle={more.onToggle}>
        <summary onClick={more.onSummaryClick}>{t('devices.enroll.server')} <span className="mono">{service}</span></summary>
        <TextField id="enroll-service" label={t('devices.enroll.server')} mono value={service} onChange={(v) => { setService(v); setErr(null); }} />
        <TextField id="enroll-name" label={t('devices.enroll.name')} value={name} maxLength={64} onChange={setName} />
      </details>
      <button className="btn btn-primary btn-sm" type="submit" aria-busy={busy || undefined}>{t('devices.enroll.btn')}</button>
    </form>
  );
}

// ---------------------------------------------------------------- add a Mac

function Ring({ fraction }: { fraction: number }) {
  return (
    <svg className="ring" viewBox="0 0 30 30" aria-hidden="true">
      <circle cx="15" cy="15" r="12" fill="none" stroke="rgba(255,255,255,.08)" strokeWidth="3" />
      <circle cx="15" cy="15" r="12" fill="none" stroke="#7a7cff" strokeWidth="3" strokeDasharray="75.4"
        strokeDashoffset={(75.4 * (1 - fraction)).toFixed(2)} transform="rotate(-90 15 15)" />
    </svg>
  );
}

/** The Mac with the vault: pick environments, re-authenticate, make the pairing code (shown or
 *  copied once), then read the join requests every few seconds while the sheet is open and approve
 *  or refuse each requesting Mac by its picture and code. */
export function AddDeviceSheet({ open, link, onClose, onChanged }: { open: boolean; link: LinkStatus | null; onClose(): void; onChanged(): void }) {
  const { toast, announce, field } = useApp();
  const projects = useLoad(() => call('project_list'), [open]);
  const all = (projects.data?.projects ?? []).flatMap((p: Project) => p.environments.map((e) => `${p.name}/${e}`));
  const [chosen, setChosen] = useState<string[] | null>(null);
  const envs = chosen ?? all;
  const [name, setName] = useState(t('pair.add.name.default'));
  const [pass, setPass] = useState('');
  const [errs, setErrs] = useState<{ envs?: CopyKey; name?: CopyKey; pass?: CopyKey; form?: CopyKey }>({});
  const [busy, setBusy] = useState(false);
  const [made, setMade] = useState<PairingCreated | null>(null);
  const [handed, setHanded] = useState<'copied' | 'shown' | null>(null);
  const [code, setCode] = useState<string | null>(null);
  const [requests, setRequests] = useState<JoinRequest[]>([]);
  const [decided, setDecided] = useState<string[]>([]);
  const passRef = useRef<HTMLInputElement>(null);
  const nameRef = useRef<HTMLInputElement>(null);
  const boxRef = useRef<HTMLDivElement>(null);
  const now = useNow(!!made && open);
  const visible = useSecureGate(open && code !== null);
  const handedRef = useRef(handed);
  handedRef.current = handed;
  useClearOnClose(open, () => { setPass(''); setCode(null); });
  // a code nobody copied or looked at is dropped from the core when the sheet goes
  useEffect(() => {
    if (!open || !made) return;
    const ref = made.ref;
    return () => { if (!handedRef.current) void call('onetime_discard', { ref }).catch(() => undefined); };
  }, [open, made]);

  // join requests, while the code is out and the sheet is open
  useEffect(() => {
    if (!open || !made) return;
    const envs = pairingEnvs(made);
    const handle = poll({
      step: () => call('join_requests', { envs }),
      done: () => false,
      onValue: (r) => setRequests(r.requests),
      every: REQUESTS_POLL_MS,
      until: Date.now() + 30 * 60_000,
    });
    return () => handle.cancel();
  }, [open, made]);

  const toggle = (env: string) => {
    setChosen((xs) => { const cur = xs ?? all; return cur.includes(env) ? cur.filter((x) => x !== env) : all.filter((x) => x === env || cur.includes(x)); });
    setErrs((x) => ({ ...x, envs: undefined }));
  };

  const create = async () => {
    if (busy) return;
    if (made) { onClose(); return; }
    const e: typeof errs = {};
    if (!envs.length) e.envs = all.length ? 'pair.add.envs.err' : 'pair.add.noEnvs';
    if (!name.trim() || name.length > 64 || /[\x00-\x1f\x7f]/.test(name)) e.name = 'pair.add.name.err';
    if (!pass) e.pass = 'pass.err.empty';
    setErrs(e);
    if (e.envs) return;
    if (e.name) { nameRef.current?.focus(); return; }
    if (e.pass) { passRef.current?.focus(); return; }
    setBusy(true);
    try {
      const out = await call('pairing_create', { envs, device_name: name.trim(), admin_passphrase: pass, ...(link?.device_name ? { name: link.device_name } : {}) });
      setPass('');
      setMade(out);
      field.ripple(0.08);
      toast(t('toast.pair.created')); announce(t('toast.pair.created'));
      onChanged();
      setTimeout(() => boxRef.current?.focus({ preventScroll: true }), 60);
    } catch (err) {
      setPass('');
      const ipc = toIpcError(err);
      if (ipc.error === 'AuthFailed') { setErrs({ pass: passErrorKey(err) }); passRef.current?.focus(); }
      else setErrs({ form: ipc.reason === 'link_not_enrolled' ? 'pair.add.needEnroll' : ipc.reason === 'serve_without_link' || ipc.reason === 'serve_not_running' ? 'pair.add.needRelay' : 'error.generic' });
      onChanged();
    } finally { setBusy(false); }
  };

  const copy = async () => {
    if (!made || handed) return;
    try {
      const r = await call('onetime_copy', { ref: made.ref });
      if (r.copied) { setHanded('copied'); toast(t('inv.copied.toast')); }
    } catch { toast(t('error.generic'), 'warn'); }
  };
  const show = async () => {
    if (!made || handed) return;
    try {
      const r = await call('onetime_show', { ref: made.ref });
      setHanded('shown');
      if (open) setCode(r.text);
    } catch { toast(t('error.generic'), 'warn'); }
  };
  useEffect(() => { if (visible) announce(t('pair.code.shown')); }, [visible, announce]);

  const groups = requestsByDevice(requests).filter((g) => !decided.includes(g.fingerprint));
  const left = made ? msLeft(made.expires_at, now) : 0;
  const hash = code && visible ? code.slice(code.indexOf('#') + 1) : '';

  return (
    <Sheet id="sheet-pair-add" open={open} title={t('pair.add.title')} lead={t('pair.add.sub')} primaryLabel={t(made ? 'common.done' : 'pair.add.create')}
      busy={busy} onPrimary={() => void create()} onClose={() => { if (!busy) onClose(); }} noCancel={!!made}>
      {!made && (
        <>
          <div className="field">
            <div className="label"><span id="pair-envs-lbl">{t('pair.add.envs')}</span></div>
            {all.length === 0
              ? <div className="help">{t(projects.data ? 'pair.add.noEnvs' : 'boot.loading')}</div>
              : (
                <div className="chips" role="group" aria-labelledby="pair-envs-lbl" aria-describedby="pair-envs-err">
                  {all.map((env) => (
                    <button key={env} className="chip mono" type="button" aria-pressed={envs.includes(env)} onClick={() => toggle(env)}><i aria-hidden="true" />{env}</button>
                  ))}
                </div>
              )}
            <div className="help err" id="pair-envs-err" hidden={!errs.envs}>{errs.envs ? t(errs.envs) : ''}</div>
          </div>
          <Callout>{t('pair.add.share')}</Callout>
          <TextField id="pair-name" label={t('pair.add.name')} value={name} inputRef={nameRef} maxLength={64} error={errs.name ? t(errs.name) : null}
            onChange={(v) => { setName(v); setErrs((x) => ({ ...x, name: undefined })); }} />
          <PassField id="pair-pass" value={pass} inputRef={passRef} error={errs.pass ? t(errs.pass) : null}
            onChange={(v) => { setPass(v); setErrs((x) => ({ ...x, pass: undefined })); }} />
          {errs.form && <div className="help err" role="alert">{t(errs.form)}</div>}
        </>
      )}
      {made && (
        <>
          <div className="invite-box" tabIndex={-1} role="region" aria-label={t('pair.code.label')} ref={boxRef}>
            <div className="sigil"><Sigil fp={made.fingerprint} /><span className="cap">{t('pair.code.fp')}</span></div>
            <div style={{ minWidth: 0 }}>
              <div className={'link-line' + (hash ? ' full' : '')}>
                <span className="scheme">zeropw://pair#</span>
                {hash ? <span className="link-text">{hash}</span> : <span className="mask">{handed === 'copied' ? t('inv.link.copied') : '••••••••••••'}</span>}
              </div>
              <div className="fp-line">{formatFingerprint(made.fingerprint)}</div>
              <div className="ttl">
                <Ring fraction={inviteFraction(made.expires_at, now)} />
                <div><div className="time">{formatCountdown(left)}</div><div className="sub">{t('pair.code.left')}</div></div>
              </div>
              {!handed && (
                <div className="tools" style={{ marginTop: 8 }}>
                  <button className="btn btn-ghost btn-sm" type="button" onClick={() => void copy()}>{t('inv.copy')}</button>
                  <button className="btn btn-text btn-sm" type="button" onClick={() => void show()}>{t('common.show')}</button>
                </div>
              )}
            </div>
          </div>
          <Callout>{t('pair.code.warn')}</Callout>
          <h3 className="section-title">{t('pair.req.title')}</h3>
          {groups.length === 0
            ? <div className="help" role="status">{t('pair.req.wait')}</div>
            : groups.map((g) => (
              <RequestCard key={g.fingerprint} fingerprint={g.fingerprint} envs={g.envs} attempts={g.attempts}
                onDecided={(approved) => { setDecided((xs) => [...xs, g.fingerprint]); toast(t(approved ? 'toast.pair.approved' : 'toast.pair.denied'), approved ? 'info' : 'warn'); onChanged(); }} />
            ))}
        </>
      )}
    </Sheet>
  );
}

/** One requesting Mac: its picture and code to compare with its own screen, and approve or refuse
 *  with the admin password. */
export function RequestCard({ fingerprint, envs, attempts, onDecided }: { fingerprint: string; envs: string[]; attempts: number; onDecided(approved: boolean): void }) {
  const [pass, setPass] = useState('');
  const [err, setErr] = useState<CopyKey | null>(null);
  const [busy, setBusy] = useState(false);
  const passRef = useRef<HTMLInputElement>(null);
  const fp = formatFingerprint(fingerprint);
  const decide = async (approve: boolean) => {
    if (busy) return;
    if (!pass) { setErr('pass.err.empty'); passRef.current?.focus(); return; }
    setBusy(true); setErr(null);
    try {
      const out = await call(approve ? 'approve_join' : 'deny_join', { envs, fingerprint, admin_passphrase: pass });
      setPass('');
      if (out.envs.some((e) => !e.ok)) { setErr('error.generic'); return; }
      onDecided(approve);
    } catch (e) {
      setPass('');
      setErr(passErrorKey(e));
      passRef.current?.focus();
    } finally { setBusy(false); }
  };
  return (
    <div className="request-card">
      <div className="preview">
        <div className="sigil"><Sigil fp={fingerprint} /><span className="cap">{t('pair.pv.picture')}</span></div>
        <dl className="kv">
          <dt>{t('pair.pv.code')}</dt><dd>{fp}</dd>
          <dt>{t('pair.pv.envs')}</dt><dd>{t('devices.envs', { n: envs.length })}</dd>
          <dt>{t('pair.req.title')}</dt><dd>{t('pair.req.attempts', { n: attempts })}</dd>
        </dl>
      </div>
      <Callout kind="info">{t('pair.req.check')}</Callout>
      <PassField id={`req-pass-${fingerprint.slice(0, 8)}`} value={pass} inputRef={passRef} error={err ? t(err) : null} onChange={(v) => { setPass(v); setErr(null); }} />
      <div className="tools">
        <button className="btn btn-primary btn-sm" type="button" aria-busy={busy || undefined} aria-label={t('pair.req.approve.aria', { fp })} onClick={() => void decide(true)}>{t('pair.req.approve')}</button>
        <button className="btn btn-ghost btn-sm" type="button" aria-label={t('pair.req.deny.aria', { fp })} onClick={() => void decide(false)}>{t('pair.req.deny')}</button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- join another Mac

/** Paste the other Mac's code, check its picture and code, ask to join and wait for approval. */
export function JoinPairSheet({ open, onClose }: { open: boolean; onClose(): void }) {
  const pj = usePairJoin(() => undefined);
  const codeRef = useRef<HTMLInputElement>(null);
  const close = () => { pj.cancel(); pj.reset(); onClose(); };
  useClearOnClose(open, () => { pj.cancel(); pj.reset(); });
  const p = pj.phase;
  const label = p.kind === 'waiting' ? undefined : p.kind === 'done' ? t('common.done') : t('pair.join.confirm');
  return (
    <Sheet id="sheet-pair-join" open={open} title={p.kind === 'waiting' ? t('pair.wait.title') : t('pair.join.title')} lead={t('pair.join.sub')}
      primaryLabel={label} ready={p.kind === 'preview' || p.kind === 'done'} noCancel={p.kind === 'done'} onBlocked={() => codeRef.current?.focus()}
      onPrimary={() => { if (p.kind === 'preview') pj.start(); else if (p.kind === 'done') close(); }}
      closeLabel={p.kind === 'waiting' ? t('pair.wait.cancel') : undefined} onClose={close}>
      <PairJoinBody id="pair-join" pj={pj} inputRef={codeRef} />
    </Sheet>
  );
}
