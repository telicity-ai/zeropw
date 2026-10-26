import { useEffect, useId, useRef, useState } from 'react';
import { t, tLines, type CopyKey, type CopyLine } from '../copy';
import { call, toIpcError } from '../ipc/client';
import type { InviteListItem, InvitePreview, Member, NetInterface, Settings } from '../ipc/contract';
import {
  addressChoices, DEFAULT_TEAM_PORT, defaultListenIp, envKey, inviteFraction, msLeft, parseListen, parsePort, shownChoice, splitEnv, teamEnvPairs, teamEnvsUnread,
} from '../lib/dash';
import { shortTime } from '../lib/format';
import { invitePreviewErrorKey, isStaleRef, joinErrorKey } from '../lib/reasons';
import { InvitePreviewRequests } from '../lib/invitePreview';
import { defaultLocalName, formatCountdown, formatFingerprint, isInviteLink, parseLocalName } from '../lib/validators';
import { useApp } from '../ui/context';
import { useDisclosure } from '../ui/disclosure';
import { PassField, SelectField, TextField } from '../ui/fields';
import { Callout, Segmented } from '../ui/form';
import { Sigil } from '../ui/pixels';
import { useSecureGate } from '../ui/secure';
import { ConfirmSheet } from './Confirm';
import { passErrorKey, useClearOnClose, useDash, useLoad, useNow, useSheets, type Intent } from './context';
import { ListenSetup } from './ListenSetup';
import { Empty, ListCard, metaLine, Row, SectionHead, Tag } from './parts';
import { ListenError, listenErrorLines, readSettings, relayLeftOff, turnOnListen } from './relay';
import { Sheet } from './Sheet';
import { definiteInviteFailure, shareAndInvite } from './invite';

type Incoming = { ref: string; preview: InvitePreview };
type Role = 'user' | 'admin';
type TeamSheet =
  | { kind: 'invite' }
  | { kind: 'share'; env: string }
  | { kind: 'remove'; env: string; member: Member }
  | { kind: 'join'; incoming?: Incoming };
const NOT_SHARED = new Set(['team_env_not_found']);
const INVITE_STATUS: Record<string, CopyKey> = { pending: 'st.pending', used: 'st.used', expired: 'st.expired', revoked: 'st.cancelled' };
const roleText = (r: string): string => (r === 'admin' ? t('inv.role.admin') : r === 'user' ? t('inv.role.user') : r);

/** Team: share an environment, its members and invite links, and joining another device's team.
 *  The environments are the local ones and the team ones, including those joined from another
 *  device, which are in no project. Names, fingerprints and addresses written by other devices
 *  are rendered as text. */
export function TeamPage({ intent, onIntent, incoming, onIncomingTaken }: {
  intent?: Intent; onIntent(): void; incoming: Incoming | null; onIncomingTaken(): void;
}) {
  const { tick, bump, relay, go } = useDash();
  const { toast } = useApp();
  const [n, setN] = useState(0);
  const reload = () => setN((x) => x + 1);
  const base = useLoad(async () => {
    // a damaged settings file (settings_corrupt) is fixed on the Settings page; the environments still load
    const [p, s, i] = await Promise.all([
      call('project_list'), readSettings().catch(() => ({ settings: null, corrupt: false })), call('net_interfaces').catch(() => [] as NetInterface[]),
    ]);
    return { pairs: teamEnvPairs(p), envsUnread: teamEnvsUnread(p), settings: s.settings, settingsCorrupt: s.corrupt, interfaces: i };
  }, [tick, n]);
  const [env, setEnv] = useState('');
  const pairs = base.data?.pairs ?? [];
  // the environment loaded is the one the picker shows, also when the chosen one left the list
  // (a team mapping that can no longer be read)
  const cur = shownChoice(env, pairs.map((p) => p.key));
  const team = useLoad(async () => {
    if (!cur) return null;
    try {
      const m = await call('team_members', { env: cur });
      const i = await call('team_invites', { env: cur }).catch(() => ({ env_id: m.env_id, invites: [] as InviteListItem[] }));
      return { env: cur, shared: true, members: m.members, invites: i.invites.slice().reverse() };
    } catch (e) {
      if (NOT_SHARED.has(toIpcError(e).reason)) return { env: cur, shared: false, members: [] as Member[], invites: [] as InviteListItem[] };
      throw e;
    }
  }, [cur, tick, n]);
  const sheets = useSheets<TeamSheet>();
  const td = team.data && team.data.env === cur ? team.data : null;
  const hasPending = !!td?.invites.some((i) => i.status === 'pending');
  const now = useNow(hasPending);

  const [sheetBusy, setSheetBusy] = useState(false);
  const sheetBusyRef = useRef(false);
  const reportBusy = (busy: boolean) => { sheetBusyRef.current = busy; setSheetBusy(busy); };
  useEffect(() => {
    const requested = intent === 'invite' ? 'invite' : incoming ? 'join' : intent;
    if (!requested || sheetBusyRef.current || sheets.isOpen('invite')) return;
    if (requested === 'invite') { sheets.open({ kind: 'invite' }); onIntent(); }
    if (requested === 'join') { sheets.open({ kind: 'join', ...(incoming ? { incoming } : {}) }); onIncomingTaken(); onIntent(); }
  }, [intent, incoming, sheetBusy, sheets.cur]);


  const revokeInvite = async (inv: InviteListItem) => {
    try {
      await call('team_revoke_invite', { env: cur, invite_id: inv.invite_id });
      toast(t('inv.revoke.toast'), 'warn');
      reload();
    } catch (e) {
      toast(t(toIpcError(e).reason === 'invite_already_used' ? 'team.err.used' : 'error.generic'), 'warn');
      reload();
    }
  };

  const shareData = sheets.data('share');
  const removeData = sheets.data('remove');

  return (
    <>
      <SectionHead title={t('team.env')}>
        <button className="btn btn-ghost btn-sm" type="button" onClick={() => { if (!sheetBusyRef.current) sheets.open({ kind: 'join' }); }}>{t('join.title')}</button>
        <button className="btn btn-primary btn-sm" type="button" onClick={() => { if (!sheetBusyRef.current) sheets.open({ kind: 'invite' }); }}>{t('inv.title')}</button>
      </SectionHead>
      <p className="page-help">{t('team.help')}</p>
      {/* the team mapping could not be read: the projects load, the team environments do not */}
      {base.data?.envsUnread && <Callout kind="info">{t('team.envs.err')}</Callout>}
      <div className="glass pad">
        {pairs.length === 0
          ? <Empty text={base.failed ? t('error.load') : base.data ? t('keys.err.noEnv') : t('boot.loading')} />
          : (
            <div className="env-bar">
              <SelectField id="team-env" label={t('team.env.select')} mono value={cur} options={pairs.map((p) => ({ value: p.key, label: p.key }))} onChange={setEnv} />
              <div className={'share-state' + (td?.shared ? ' on' : '')}>
                <span className="px" aria-hidden="true" />
                <span>{td ? t(td.shared ? 'inv.pre2.on' : 'inv.pre2.off') : t('boot.loading')}</span>
                {td && !td.shared && (
                  <button className="btn btn-ghost btn-sm" type="button" onClick={() => { if (!sheetBusyRef.current) sheets.open({ kind: 'share', env: cur }); }}>{t('inv.pre2.btn')}</button>
                )}
              </div>
            </div>
          )}
        {/* a shared environment syncs only while other-device access is on */}
        {td?.shared && base.data?.settings && !parseListen(base.data.settings.team_listen) && (
          <ListenSetup onBusy={reportBusy} id="team-listen" interfaces={base.data.interfaces} run={relay.run}
            onDone={() => { toast(t('toast.listen.on')); reload(); bump(); }}
            onFailed={(down) => { if (down) relay.report(down); reload(); bump(); }} />
        )}
        {/* nor can it be turned on until the damaged settings file is reset */}
        {td?.shared && base.data?.settingsCorrupt && (
          <Callout kind="info">{t('listen.err.settings')} <ToSettings onClick={() => go('settings')} /></Callout>
        )}
      </div>

      {td?.shared && (
        <>
          <SectionHead title={t('team.members')} />
          <ListCard items={td.members} empty="page.team.empty" label={t('team.members')}>
            {(items) => items.map((m) => (
              <Row key={m.fingerprint} dot={m.status === 'active' ? 'on' : 'idle'} name={String(m.name ?? '')}
                tag={<>{m.owner && <Tag>{t('team.owner')}</Tag>}{m.status !== 'active' && <Tag>{m.status === 'removed' ? t('st.removed') : String(m.status)}</Tag>}</>}
                meta={metaLine(roleText(String(m.role)), formatFingerprint(String(m.fingerprint)))}>
                {!m.owner && m.status === 'active' && (
                  <button className="btn btn-text btn-sm" type="button" aria-label={t('team.remove.aria', { name: String(m.name ?? '') })}
                    onClick={() => { if (!sheetBusyRef.current) sheets.open({ kind: 'remove', env: cur, member: m }); }}>{t('team.remove')}</button>
                )}
              </Row>
            ))}
          </ListCard>

          <SectionHead title={t('team.invites')} />
          <ListCard items={td.invites} empty="team.invites.empty" label={t('team.invites')}>
            {(items) => items.map((i) => {
              const pending = i.status === 'pending' && msLeft(i.expires_at, now) > 0;
              const status = pending ? i.status : i.status === 'pending' ? 'expired' : i.status;
              return (
                <Row key={i.invite_id} dot={pending ? 'live' : 'idle'} name={String(i.name)} tag={<Tag>{roleText(String(i.role))}</Tag>}
                  meta={metaLine(
                    INVITE_STATUS[status] ? t(INVITE_STATUS[status] as CopyKey) : String(status),
                    pending ? `${formatCountdown(msLeft(i.expires_at, now))} ${t('inv.left')}` : null,
                    i.used_by ? formatFingerprint(String(i.used_by)) : null,
                    i.created_at ? shortTime(i.created_at) : null,
                  )}>
                  {pending && (
                    <button className="btn btn-text btn-sm" type="button" aria-label={t('inv.revoke.aria', { name: String(i.name) })}
                      onClick={() => void revokeInvite(i)}>{t('inv.revoke')}</button>
                  )}
                </Row>
              );
            })}
          </ListCard>
        </>
      )}

      <InviteSheet key={sheets.key('invite')} open={sheets.isOpen('invite')} env={cur} pairs={pairs.map((p) => p.key)} onEnv={setEnv}
        shared={td ? td.shared : null} loadFailed={team.failed || base.failed} onRetry={() => { team.reload(); base.reload(); }} onBusy={reportBusy} settings={base.data?.settings ?? null} interfaces={base.data?.interfaces ?? []}
        onChanged={reload} onClose={sheets.close} />
      <ConfirmSheet key={sheets.key('share')} onBusy={reportBusy} id="sheet-share" open={sheets.isOpen('share')} title={t('inv.pre2')} confirmLabel={t('inv.pre2.btn')}
        chips={shareData ? [shareData.env] : []} warn={t('team.share.warn')} needPass onClose={sheets.close}
        errorFor={(e) => (toIpcError(e).reason === 'team_env_already_shared' ? 'team.err.shared' : null)}
        run={async (pass) => {
          const pair = shareData ? splitEnv(shareData.env) : null;
          if (!pair) return;
          await call('team_share', { project: pair.project, environment: pair.environment, admin_passphrase: pass });
          toast(t('toast.share.done'));
          reload();
          sheets.close();
        }} />
      <ConfirmSheet key={sheets.key('remove')} onBusy={reportBusy} id="sheet-remove" open={sheets.isOpen('remove')} title={t('team.remove.title')} lead={t('team.remove.sub')}
        confirmLabel={t('team.remove.confirm')} needPass onClose={sheets.close} warn={t('team.remove.warn')}
        chips={removeData ? [String(removeData.member.name ?? ''), formatFingerprint(String(removeData.member.fingerprint))] : []}
        run={async (pass) => {
          if (!removeData) return;
          await call('team_remove', { env: removeData.env, device: removeData.member.fingerprint, admin_passphrase: pass });
          toast(t('toast.team.removed'), 'warn'); sheets.close(); reload();
        }} />
      <JoinSheet key={sheets.key('join')} open={sheets.isOpen('join')} incoming={sheets.data('join')?.incoming ?? null}
        onBusy={reportBusy} onClose={sheets.close} onEnv={setEnv} onChanged={() => { reload(); bump(); }} onJoined={() => { sheets.close(); reload(); bump(); }} />
    </>
  );
}

/** To the Settings page, where a damaged settings file is reset. */
function ToSettings({ onClick }: { onClick(): void }) {
  return <button className="btn btn-ghost btn-sm" type="button" onClick={onClick}>{t('listen.toSettings')}</button>;
}

// ---------------------------------------------------------------- invite

function Ring({ fraction }: { fraction: number }) {
  const id = useId();
  return (
    <svg className="ring" viewBox="0 0 30 30" aria-hidden="true">
      <defs><linearGradient id={id} x1="0" x2="1"><stop offset="0" stopColor="#5b8cff" /><stop offset="1" stopColor="#9a6bff" /></linearGradient></defs>
      <circle cx="15" cy="15" r="12" fill="none" stroke="rgba(255,255,255,.08)" strokeWidth="3" />
      <circle cx="15" cy="15" r="12" fill="none" stroke={`url(#${id})`} strokeWidth="3" strokeDasharray="75.4"
        strokeDashoffset={(75.4 * (1 - fraction)).toFixed(2)} transform="rotate(-90 15 15)" />
    </svg>
  );
}

/** The mockup's invite step as a sheet: other-device access and sharing first, then role and
 *  name, then a 24-hour one-use link. The link stays in the core until it is copied or shown,
 *  and either hands it over once. */
function InviteSheet({ open, env: pageEnv, pairs, onEnv, shared: pageShared, settings, interfaces, loadFailed, onRetry, onBusy, onChanged, onClose }: {
  open: boolean; env: string; pairs: string[]; onEnv(v: string): void; shared: boolean | null; settings: Settings | null; interfaces: NetInterface[];
  loadFailed: boolean; onRetry(): void; onBusy(busy: boolean): void; onChanged(): void; onClose(): void;
}) {
  const { toast, field, announce } = useApp();
  const { relay } = useDash();
  const listen = parseListen(settings?.team_listen);
  const [ip, setIp] = useState(listen?.ip ?? defaultListenIp(interfaces));
  const [port, setPort] = useState(String(listen?.port ?? DEFAULT_TEAM_PORT));
  const networkDetails = useDisclosure(interfaces.length !== 1);
  const [role, setRole] = useState<Role>('user');
  const [name, setName] = useState('');
  const [pass, setPass] = useState('');
  const [sharedHere, setSharedHere] = useState<string[]>([]);
  // A page reload may choose another listed environment. A submitted operation keeps its
  // actual target until the result is acknowledged or the user explicitly picks a new one.
  const [operation, setOperation] = useState<{ env: string; shared: boolean } | null>(null);
  const env = operation?.env ?? pageEnv;
  const shared = operation?.shared ?? pageShared;
  const [uncertainInvite, setUncertainInvite] = useState(false);
  const [readResult, setReadResult] = useState<{ key: CopyKey; n?: number } | null>(null);
  const formErrorRef = useRef<HTMLDivElement>(null);
  const readResultRef = useRef<HTMLDivElement>(null);
  const running = useRef(false);
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const isShared = shared === true || sharedHere.includes(env);
  const [errs, setErrs] = useState<{ port?: CopyKey; name?: CopyKey; pass?: CopyKey; form?: CopyKey }>({});
  const [listenErr, setListenErr] = useState<CopyLine[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [listenBusy, setListenBusy] = useState(false);
  const [made, setMade] = useState<{ invite_id: string; link_ref: string; expires_at: string; inviter: string; env: string } | null>(null);
  const [link, setLink] = useState<string | null>(null);
  const [handed, setHanded] = useState<'copied' | 'shown' | 'revoked' | null>(null);
  const nameRef = useRef<HTMLInputElement>(null);
  const passRef = useRef<HTMLInputElement>(null);
  const portRef = useRef<HTMLInputElement>(null);
  const listenBtn = useRef<HTMLButtonElement>(null);

  const boxRef = useRef<HTMLDivElement>(null);
  const now = useNow(!!made && open);
  const openRef = useRef(open);
  openRef.current = open;
  // the link is painted only once the screen-capture exclusion request has been answered (best effort)
  const linkVisible = useSecureGate(open && link !== null);

  const handedRef = useRef(handed);
  handedRef.current = handed;

  useEffect(() => { if (!ip && interfaces.length) setIp(defaultListenIp(interfaces)); }, [ip, interfaces]);
  // closing drops a shown link and a typed passphrase at once
  useClearOnClose(open, () => { setLink(null); setPass(''); });
  // a link nobody copied or looked at is dropped from the core too; the invite stays in the list
  // (pending until it expires) and can be cancelled there
  useEffect(() => {
    if (!open || !made) return;
    const m = made;
    return () => { if (!handedRef.current) call('onetime_discard', { ref: m.link_ref }).catch(() => undefined); };
  }, [open, made]);

  useEffect(() => {
    if (!errs.port || !networkDetails.open) return;
    const frame = requestAnimationFrame(() => portRef.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, [errs.port, networkDetails.open]);

  const turnOn = async () => {
    if (running.current) return;
    const p = parsePort(port);
    if (p === null || !ip) { networkDetails.reveal(); setErrs({ port: 'set.listen.port.err' }); portRef.current?.focus(); return; }
    running.current = true; onBusy(true); setListenBusy(true); setListenErr(null);
    try {
      await relay.run(() => turnOnListen(ip, p));
      toast(t('toast.listen.on')); field.ripple(0.05);
      onChanged();
      setTimeout(() => nameRef.current?.focus(), 60);
    } catch (e) {
      // an address the relay cannot open is taken back (./relay.ts); say which and what is running
      networkDetails.reveal();
      setListenErr(listenErrorLines(e));
      const down = relayLeftOff(e);
      if (down) relay.report(down);
      if (e instanceof ListenError) onChanged();
    } finally { running.current = false; if (alive.current) { onBusy(false); setListenBusy(false); } }
  };

  const ready = !!listen && shared !== null && !!env;
  const blocked = () => {
    if (shared === null) { toast(t(loadFailed ? 'error.load' : 'boot.loading'), 'warn'); return; }
    toast(t('inv.blocked'), 'warn');
    (listen ? nameRef.current : listenBtn.current)?.focus();
  };

  const recheckState = async () => {
    running.current = true; onBusy(true); setBusy(true); setReadResult(null);
    setErrs((old) => ({ ...old, form: undefined }));
    try {
      try { await call('team_members', { env }); }
      catch (e) {
        if (!NOT_SHARED.has(toIpcError(e).reason)) throw e;
        if (alive.current) { setOperation((current) => current ? { ...current, shared: false } : current); setReadResult({ key: 'inv.read.unshared' }); }
        return;
      }
      const result = await call('team_invites', { env });
      if (alive.current) { setOperation((current) => current ? { ...current, shared: true } : current); setReadResult({ key: 'inv.read.shared', n: result.invites.length }); }
    } catch {
      if (alive.current) setReadResult({ key: 'inv.read.failed' });
    } finally {
      running.current = false;
      if (alive.current) { onBusy(false); setBusy(false); onChanged(); }
    }
  };

  useEffect(() => {
    if (busy) return;
    const frame = requestAnimationFrame(() => { if (errs.form) formErrorRef.current?.focus(); else if (readResult) readResultRef.current?.focus(); });
    return () => cancelAnimationFrame(frame);
  }, [busy, errs.form, readResult]);

  const create = async () => {
    if (running.current) return;
    if (made) { onClose(); return; }
    if (uncertainInvite) { await recheckState(); return; }
    if (!ready || !listen) { blocked(); return; }
    const e: typeof errs = {};
    if (!name.trim() || name.length > 64 || /[\x00-\x1f\x7f]/.test(name)) e.name = 'inv.name.err';
    if (!pass) e.pass = 'pass.err.empty';
    setErrs(e);
    if (e.name) { nameRef.current?.focus(); return; }
    if (e.pass) { passRef.current?.focus(); return; }
    setOperation({ env, shared: isShared });
    running.current = true; onBusy(true); setBusy(true);
    let sharingCommitted = isShared;
    let sharedThisAttempt = false;
    try {
      const r = await shareAndInvite({ env, role, name: name.trim(), address: `${listen.ip}:${listen.port}`, admin_passphrase: pass }, isShared, () => {
        sharingCommitted = true;
        sharedThisAttempt = true;
        setOperation({ env, shared: true });
        toast(t('toast.share.done'));
        announce(t('toast.share.done'));
        setSharedHere((xs) => xs.includes(env) ? xs : [...xs, env]);
        onChanged();
      });
      if (!alive.current || !openRef.current) {
        void call('onetime_discard', { ref: r.link_ref }).catch(() => undefined);
        toast(t('inv.late', { env }));
        return;
      }
      setPass('');
      setMade({ ...r, env });
      field.ripple(0.08);
      toast(t('inv.created.toast'));
      announce(t('inv.created.toast'));
      onChanged();
      setTimeout(() => boxRef.current?.focus({ preventScroll: true }), 60);
    } catch (err) {
      if (!alive.current || !openRef.current) { toast(t('inv.lateUnknown', { env }), 'warn'); return; }
      setPass('');
      if (toIpcError(err).reason === 'team_env_already_shared') {
        setOperation({ env, shared: true });
        setErrs({ form: 'team.err.shared' });
        onChanged();
      } else if (toIpcError(err).error === 'AuthFailed') {
        setErrs(sharedThisAttempt ? { pass: 'inv.pass.again', form: 'inv.failedShared' } : { pass: passErrorKey(err) });
        passRef.current?.focus();
      } else {
        const uncertain = !definiteInviteFailure(err);
        setUncertainInvite(uncertain);
        onChanged();
        setErrs({ form: uncertain ? 'inv.unknown' : sharingCommitted ? 'inv.failedShared' : 'error.generic' });
      }
    } finally { running.current = false; if (alive.current) { onBusy(false); setBusy(false); } }
  };

  const copy = async () => {
    if (!made || handed) return;
    try {
      const r = await call('onetime_copy', { ref: made.link_ref });
      if (r.copied) { setHanded('copied'); toast(t('inv.copied.toast')); }
    } catch { toast(t('error.generic'), 'warn'); }
  };
  const show = async () => {
    if (!made || handed) return;
    try {
      const r = await call('onetime_show', { ref: made.link_ref });
      setHanded('shown');
      // a sheet closed while the core answered never keeps the link
      if (openRef.current) setLink(r.text);
    } catch { toast(t('error.generic'), 'warn'); }
  };
  useEffect(() => {
    if (!linkVisible) return;
    announce(t('inv.link.shown'));
    const tm = setTimeout(() => boxRef.current?.focus({ preventScroll: true }), 30);
    return () => clearTimeout(tm);
  }, [linkVisible, announce]);
  const revoke = async () => {
    if (!made) return;
    try {
      await call('team_revoke_invite', { env: made.env, invite_id: made.invite_id });
      if (!handed) call('onetime_discard', { ref: made.link_ref }).catch(() => undefined);
      setHanded('revoked'); setLink(null);
      toast(t('inv.revoke.toast'), 'warn');
      onChanged();
    } catch { toast(t('error.generic'), 'warn'); }
  };

  const left = made ? msLeft(made.expires_at, now) : 0;
  const hash = link && linkVisible ? link.slice(link.indexOf('#') + 1) : '';

  return (
    <Sheet id="sheet-invite" open={open} title={t('inv.title')} lead={t('inv.sub')} primaryLabel={t(made ? 'inv.done' : uncertainInvite ? 'inv.recheckState' : shared === null ? loadFailed ? 'inv.retryRead' : 'boot.loading' : isShared ? 'inv.create' : 'inv.shareCreate')} busy={busy || listenBusy}
      ready={!!made || uncertainInvite || ready} onBlocked={() => { if (shared === null && loadFailed) onRetry(); else blocked(); }} onPrimary={() => void create()} onClose={() => { if (!running.current) onClose(); }} noCancel={!!made}>
      <SelectField id="inv-env" label={t('inv.env')} mono value={env} ariaDisabled={!!made || uncertainInvite || busy || listenBusy} options={[...(env && !pairs.includes(env) ? [{ value: env, label: `${env} · ${t('set.listen.unlisted')}` }] : []), ...pairs.map((p) => ({ value: p, label: p }))]} onChange={(v) => { if (!running.current && !made && !uncertainInvite) { setOperation(null); onEnv(v); } }} />
      {!made && (
        <ol className="prereq">
          <li className={listen ? 'done' : undefined}>
            <div className="ph"><span className="px" aria-hidden="true" /><span>{t('inv.pre1')}</span>
              <span className="st">{listen ? `${listen.ip}:${listen.port}` : t('inv.pre1.off')}</span></div>
            <div className="pb">
              {!listen && <>
                <details open={networkDetails.open} onToggle={networkDetails.onToggle}>
                  <summary onClick={networkDetails.onSummaryClick}>{t('sync.address')} <span className="mono">{ip ? `${ip}:${port}` : t('inv.pre1.off')}</span></summary>
              <div className="inline">
                <SelectField id="inv-if" label={t('set.listen.iface')} mono value={ip} options={addressChoices(interfaces, ip)}
                  onChange={(v) => { networkDetails.reveal(); setIp(v); setListenErr(null); }} style={{ flex: 1.7 }} />
                <TextField id="inv-port" label={t('conn.ssh.port')} mono value={port} inputRef={portRef} inputMode="numeric" maxLength={5} style={{ flex: '0 0 84px' }}
                  error={errs.port ? t(errs.port) : null} onChange={(v) => { networkDetails.reveal(); setPort(v); setErrs((x) => ({ ...x, port: undefined })); setListenErr(null); }} />
              </div>
                </details>
                <button className="btn btn-ghost btn-sm" type="button" ref={listenBtn} aria-disabled={busy || listenBusy || undefined} aria-busy={listenBusy || undefined} onClick={() => void turnOn()}>{t('inv.pre1.btn')}</button>
              </>}
              <div className="help">{t('inv.pre1.note')}</div>
              {listenErr && <div className="help err" role="alert">{tLines(listenErr)}</div>}
            </div>
          </li>
          <li className={isShared ? 'done' : undefined}>
            <div className="ph"><span className="px" aria-hidden="true" /><span>{t('inv.pre2')}</span><span className="st">{t(isShared ? 'inv.pre2.on' : 'inv.pre2.off')}</span></div>
            {!isShared && <div className="pb"><Callout>{t('inv.pre2.note')}</Callout><div className="help">{t('inv.shareOnCreate')}</div></div>}
          </li>
        </ol>
      )}
      {!made && (
        <>
          <div className="row">
            <div className="field">
              <div className="label"><span id="inv-role-lbl">{t('inv.role')}</span></div>
              <Segmented<Role> name="inv-role" labelledBy="inv-role-lbl" value={role} onChange={(v) => { if (!running.current) setRole(v); }}
                options={[{ value: 'user', label: t('inv.role.user') }, { value: 'admin', label: t('inv.role.admin') }]} />
            </div>
            <TextField id="inv-name" label={t('inv.name')} value={name} ariaDisabled={busy} inputRef={nameRef} maxLength={64} placeholder={t('inv.name.ph')}
              error={errs.name ? t(errs.name) : null} onChange={(v) => { if (running.current) return; setName(v); setErrs((x) => ({ ...x, name: undefined })); }} />
          </div>
          <PassField id="inv-pass" value={pass} inputRef={passRef} error={errs.pass ? t(errs.pass) : null}
            onChange={(v) => { if (running.current) return; setPass(v); setErrs((x) => ({ ...x, pass: undefined })); }} />
          {sharedHere.includes(env) && <Callout kind="info">{t('toast.share.done')}</Callout>}
          {shared === null && <div className="help" role="status">{t(loadFailed ? 'error.load' : 'boot.loading')}</div>}
          {errs.form && <div className="help err" role="alert" tabIndex={-1} ref={formErrorRef}>{t(errs.form)}</div>}
          {readResult && <div className="help" role="status" tabIndex={-1} ref={readResultRef}>{t(readResult.key, { n: readResult.n ?? 0 })}</div>}
        </>
      )}
      {made && (
        <>
          <div className="agent-sum"><span>{name.trim()}</span><span>{roleText(role)}</span></div>
          <div className="invite-box" tabIndex={-1} role="region" aria-label={t('inv.title')} ref={boxRef}>
            <div className="sigil"><Sigil fp={made.inviter} /><span className="cap">{t('inv.picture')}</span></div>
            <div style={{ minWidth: 0 }}>
              <div className={'link-line' + (hash ? ' full' : '')}>
                <span className="scheme">zeropw://join#</span>
                {hash ? <span className="link-text">{hash}</span> : <span className="mask">{handed === 'revoked' ? t('st.cancelled') : handed === 'copied' ? t('inv.link.copied') : '••••••••••••'}</span>}
              </div>
              <div className="fp-line">{formatFingerprint(made.inviter)}</div>
              <div className="ttl">
                <Ring fraction={handed === 'revoked' ? 0 : inviteFraction(made.expires_at, now)} />
                <div><div className="time">{handed === 'revoked' ? '00:00:00' : formatCountdown(left)}</div><div className="sub">{t('inv.left')}</div></div>
                <div style={{ flex: 1 }} />
                {handed !== 'revoked' && <button className="btn btn-text btn-sm" type="button" onClick={() => void revoke()}>{t('inv.revoke')}</button>}
              </div>
              {!handed && (
                <div className="tools" style={{ marginTop: 8 }}>
                  <button className="btn btn-ghost btn-sm" type="button" onClick={() => void copy()}>{t('inv.copy')}</button>
                  <button className="btn btn-text btn-sm" type="button" onClick={() => void show()}>{t('common.show')}</button>
                </div>
              )}
            </div>
          </div>
          <Callout>{t('inv.warn')}</Callout>
        </>
      )}
    </Sheet>
  );
}

// ---------------------------------------------------------------- join

/** Paste a link (or arrive from a zeropw://join link) → preview → explicit confirm. The preview
 *  is untrusted and shown as text; nothing joins until the button is pressed. After joining, this
 *  device syncs only with other-device access on, so the sheet offers to turn it on right there.
 *  The pasted link leaves the sheet's state when the join is tried and when the sheet closes. */
function JoinSheet({ open, incoming, onBusy, onClose, onEnv, onChanged, onJoined }: {
  open: boolean; incoming: Incoming | null; onBusy(busy: boolean): void; onClose(): void; onEnv(key: string): void; onChanged(): void; onJoined(): void;
}) {
  const { desktop, toast, field, announce } = useApp();
  const [text, setText] = useState('');
  const [err, setErr] = useState<CopyKey | null>(null);
  const [held, setHeld] = useState<{ ref: string; preview: InvitePreview; fromLink: boolean } | null>(null);
  const [local, setLocal] = useState('');
  const localEdited = useRef(false);
  const localDetails = useDisclosure(false);
  const [localErr, setLocalErr] = useState<CopyKey | null>(null);
  const [focusRequest, setFocusRequest] = useState<{ target: 'local' | 'link'; sequence: number } | null>(null);
  const focusSequence = useRef(0);
  const requestFocus = (target: 'local' | 'link') => setFocusRequest({ target, sequence: ++focusSequence.current });
  const [busy, setBusy] = useState(false);
  const { relay, go } = useDash();
  const [joined, setJoined] = useState<{ interfaces: NetInterface[]; settingsCorrupt: boolean } | null>(null);
  const heldRef = useRef(held);
  heldRef.current = held;
  const previews = useRef(new InvitePreviewRequests());
  const running = useRef(false);
  const alive = useRef(true);
  const linkRef = useRef<HTMLInputElement>(null);
  const localRef = useRef<HTMLInputElement>(null);
  const now = useNow(!!held && open);

  const hold = (h: typeof held) => {
    const old = heldRef.current;
    if (old && old.ref !== h?.ref) call('onetime_discard', { ref: old.ref }).catch(() => undefined);
    heldRef.current = h; setHeld(h);
    if (h) { if (!localEdited.current) setLocal(defaultLocalName(h.preview.inviter)); setLocalErr(null); field.ripple(0.05); }
  };

  useEffect(() => {
    const requests = previews.current;
    alive.current = true;
    return () => {
      alive.current = false;
      requests.invalidate();
      queueMicrotask(() => {
        if (alive.current || running.current) return; // joining retains its ref until the IPC call settles
        const held = heldRef.current;
        heldRef.current = null;
        if (held) call('onetime_discard', { ref: held.ref }).catch(() => undefined);
      });
    };
  }, []);

  useEffect(() => {
    if (!incoming) return;
    previews.current.invalidate();
    setText(''); setErr(null);
    if (incoming.preview.expired) { call('onetime_discard', { ref: incoming.ref }).catch(() => undefined); setErr('join.err.expired'); requestFocus('link'); hold(null); return; }
    hold({ ref: incoming.ref, preview: incoming.preview, fromLink: true });
  }, [incoming]); // a new deep link only

  // the held reference is the core's; give it back when the sheet goes away without joining, and
  // drop the pasted link from the sheet's state
  useClearOnClose(open, () => {
    previews.current.invalidate();
    setText('');
    const h = heldRef.current;
    if (h && !running.current) { heldRef.current = null; call('onetime_discard', { ref: h.ref }).catch(() => undefined); }
  });

  const onLink = (v: string) => {
    setFocusRequest(null);
    setText(v);
    const s = v.trim();
    previews.current.invalidate();
    if (!s) { setErr(null); hold(null); return; }
    if (!isInviteLink(s)) { setErr('join.err'); hold(null); return; }
    setErr(null);
    void previews.current.preview(s, () => hold(null),
      (r) => {
        if (r.preview.expired) { call('onetime_discard', { ref: r.ref }).catch(() => undefined); setErr('join.err.expired'); hold(null); return; }
        hold({ ref: r.ref, preview: r.preview, fromLink: false });
      },
      (e) => {
        setErr(invitePreviewErrorKey(toIpcError(e).reason));
        hold(null);
      },
    );
  };

  const paste = () => {
    // the webview cannot read the clipboard; this fills a synthetic link in the browser review build
    const b = new Uint8Array(488);
    globalThis.crypto.getRandomValues(b);
    onLink('zeropw://join#' + [...b].map((x) => 'abcdefghijklmnopqrstuvwxyz234567'[x & 31]).join(''));
    toast(t('toast.paste.mock'));
  };

  useEffect(() => {
    if (!focusRequest || busy || (focusRequest.target === 'local' && !localDetails.open)) return;
    const frame = requestAnimationFrame(() => {
      (focusRequest.target === 'local' ? localRef.current : linkRef.current)?.focus();
      setFocusRequest(null); // focus belongs to this validation event, never a later toggle/edit
    });
    return () => cancelAnimationFrame(frame);
  }, [focusRequest, busy, localDetails.open]);

  const join = async () => {
    if (running.current) return;
    if (joined) { onJoined(); return; }
    const h = heldRef.current;
    if (!h) { requestFocus('link'); linkRef.current?.focus(); return; }
    const parsed = parseLocalName(local);
    if (!parsed) { setErr(null); requestFocus('local'); localDetails.reveal(); setLocalErr('join.local.err'); localRef.current?.focus(); return; }
    running.current = true; onBusy(true); setBusy(true);
    previews.current.invalidate();
    setText('');   // the core holds the invite behind the reference; the link is not needed any more
    try {
      const out = await call('team_join', { ref: h.ref, project: parsed.project, environment: parsed.environment });
      heldRef.current = null;
      if (alive.current) {
        setHeld(null);
        // the page shows the environment just joined
        onEnv(envKey(String(out.project), String(out.environment)));
        field.ripple(0.1);
      }
      // sync needs other-device access; damaged settings must be reset on the Settings page
      const [s, i] = await Promise.all([
        readSettings().catch(() => null),
        call('net_interfaces').catch(() => [] as NetInterface[]),
      ]);
      const listenerOn = !!s && !s.corrupt && !!parseListen(s.settings.team_listen);
      if (!alive.current) {
        toast(t(listenerOn ? 'toast.join.done' : 'toast.join.needListen'));
        return;
      }
      if (!listenerOn) {
        setJoined({ interfaces: i, settingsCorrupt: s?.corrupt ?? false });
        toast(t('toast.join.needListen'));
        announce(t('team.joined.sub'));
        onChanged();
      } else {
        toast(t('toast.join.done'));
        onJoined();
      }
    } catch (e) {
      const reason = toIpcError(e).reason;
      if (!alive.current) {
        heldRef.current = null;
        void call('onetime_discard', { ref: h.ref }).catch(() => undefined);
        toast(t(joinErrorKey(reason)), 'warn');
        return;
      }
      // the core keeps a previewed invite until the join succeeds: a failed try can be repeated,
      // unless the invite expired or the preview itself is gone
      if (reason === 'invite_expired' || isStaleRef(reason)) { heldRef.current = null; setHeld(null); call('onetime_discard', { ref: h.ref }).catch(() => undefined); }
      setErr(joinErrorKey(reason));
      requestFocus('link');
      linkRef.current?.focus();
    } finally { running.current = false; if (alive.current) { onBusy(false); setBusy(false); } }
  };

  if (joined) {
    return (
      <Sheet id="sheet-join" open={open} title={t('join.title')} lead={t('team.joined.sub')} onClose={onJoined} closeLabel={t('sync.later')}>
        {joined.settingsCorrupt
          ? <Callout kind="info">{t('listen.err.settings')} <ToSettings onClick={() => { onJoined(); go('settings'); }} /></Callout>
          : (
            <ListenSetup onBusy={onBusy} id="join-listen" interfaces={joined.interfaces} run={relay.run}
              onDone={() => { toast(t('toast.listen.on')); onJoined(); }}
              onFailed={(down) => { if (down) relay.report(down); onChanged(); }} />
          )}
      </Sheet>
    );
  }

  const p = held?.preview;
  const addr = p ? (p.addresses[0] ?? '') + (p.addresses.length > 1 ? ' ' + t('join.pv.more', { n: p.addresses.length - 1 }) : '') : '';

  return (
    <Sheet id="sheet-join" open={open} title={t('join.title')} lead={t('team.join.sub')} primaryLabel={t('team.join.confirm')} busy={busy}
      ready={!!held} onBlocked={() => linkRef.current?.focus()} onPrimary={() => void join()} onClose={() => { if (!running.current) onClose(); }}>
      <TextField id="join-link" label={t('join.field')} type="password" mono value={text} ariaDisabled={busy} inputRef={linkRef} placeholder="zeropw://join#…"
        error={err ? t(err) : null} help={held?.fromLink ? t('join.fromLink') : undefined}
        suffix={desktop ? undefined : <button className="icon-btn" type="button" onClick={paste}>{t('join.paste')}</button>}
        onChange={(v) => { if (!running.current) onLink(v); }} />
      {p && (
        <>
          <div className="preview" role="region" aria-label={t('join.pv.region')}>
            <div className="sigil"><Sigil fp={p.inviter} /><span className="cap">{t('join.pv.picture')}</span></div>
            <dl className="kv">
              <dt>{t('join.pv.code')}</dt><dd>{formatFingerprint(p.inviter)}</dd>
              <dt>{t('join.pv.env')}</dt><dd>{p.env_id.slice(0, 10) + '…'}</dd>
              <dt>{t('join.pv.role')}</dt><dd>{roleText(p.role)}</dd>
              <dt>{t('join.pv.addr')}</dt><dd>{addr}</dd>
              <dt>{t('join.pv.left')}</dt><dd>{formatCountdown(msLeft(p.expires_at, now))}</dd>
            </dl>
          </div>
          <details open={localDetails.open} onToggle={localDetails.onToggle} style={{ marginTop: 12 }}>
            <summary onClick={() => { localDetails.onSummaryClick(); setFocusRequest(null); }}>{t('join.local')} <span className="mono">{local}</span></summary>
            <TextField id="join-local" label={t('join.local')} mono value={local} disabled={busy} inputRef={localRef} error={localErr ? t(localErr) : null}
              onChange={(v) => { setFocusRequest(null); localEdited.current = true; setLocal(v); setLocalErr(null); }} />
          </details>
          <Callout>{t('join.check')}</Callout>
        </>
      )}
    </Sheet>
  );
}
