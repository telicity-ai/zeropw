// Sharing one place with another person's device: share the place, the devices that joined,
// 24-hour one-use invite links, and joining another person's place by link. Separate from pairing
// this person's own Macs (내 Mac). Names, fingerprints and addresses written by other devices are
// rendered as text only.

import { useEffect, useRef, useState } from 'react';
import { t, tLines, type CopyKey, type CopyLine } from '../../copy';
import { call, toIpcError } from '../../ipc/client';
import type { InviteListItem, InvitePreview, Member, NetInterface, Settings } from '../../ipc/contract';
import { placeLabel } from '../../lib/places';
import { useShell, type Intent } from '../../app/shell';
import {
  addressChoices, DEFAULT_TEAM_PORT, defaultListenIp, envKey, msLeft, parseListen, parsePort, shownChoice, splitEnv, teamEnvPairs, teamEnvsUnread, type EnvPair,
} from '../../lib/dash';
import { shortTime } from '../../lib/format';
import { definiteInviteFailure, shareAndInvite } from '../../lib/invite';
import { InvitePreviewRequests } from '../../lib/invitePreview';
import { invitePreviewErrorKey, isStaleRef, joinErrorKey } from '../../lib/reasons';
import { ListenError, listenErrorLines, readSettings, relayLeftOff, turnOnListen } from '../../lib/relay';
import { defaultLocalName, formatCountdown, formatFingerprint, isInviteLink, parseLocalName } from '../../lib/validators';
import { useApp } from '../../ui/app';
import { Button, PassField, Segmented, SelectField, TextField } from '../../ui/controls';
import { ConfirmDialog, Dialog, isAuthError, passErrorKey } from '../../ui/Dialog';
import { Badge, Banner, Fingerprint, KeyValues, LoadError, Section, SkeletonRows, Status } from '../../ui/feedback';
import { useLoad, useNow } from '../../ui/hooks';
import { IconTile } from '../../ui/layout';
import { OneTimeValue, type Handed } from '../../ui/OneTime';
import { roleText, useIntentOnce } from './common';
import { ListenSetup } from './ListenSetup';
import { Menu, More } from '../../ui/disclosure';

type Incoming = { ref: string; preview: InvitePreview };
type Role = 'user' | 'admin';
type Open =
  | { kind: 'invite' }
  | { kind: 'share'; env: string }
  | { kind: 'remove'; env: string; member: Member }
  | { kind: 'join' };
const NOT_SHARED = new Set(['team_env_not_found']);
const INVITE_STATUS: Record<string, CopyKey> = { pending: 'share.inv.pending', used: 'share.inv.used', expired: 'share.inv.expired', revoked: 'share.inv.revoked' };

export function SharingTab({ intent }: { intent?: Intent }) {
  const { tick, bump, relay, go, clearIntent, invite, takeInvite } = useShell();
  const { toast } = useApp();
  const [n, setN] = useState(0);
  const reload = () => setN((x) => x + 1);
  const base = useLoad(async () => {
    // a damaged settings file (settings_corrupt) is reset in Settings; the places still load
    const [p, s, i] = await Promise.all([
      call('project_list'), readSettings().catch(() => ({ settings: null, corrupt: false as const })), call('net_interfaces').catch(() => [] as NetInterface[]),
    ]);
    return { pairs: teamEnvPairs(p), envsUnread: teamEnvsUnread(p), settings: s.settings as Settings | null, settingsCorrupt: s.corrupt, interfaces: i };
  }, [tick, n]);
  const [env, setEnv] = useState('');
  const pairs: EnvPair[] = base.data?.pairs ?? [];
  // the place loaded is the one the picker shows, also when the chosen one left the list
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
  const td = team.data && team.data.env === cur ? team.data : null;
  const hasPending = !!td?.invites.some((i) => i.status === 'pending');
  const now = useNow(hasPending);
  const [open, setOpen] = useState<Open | null>(null);
  const [seq, setSeq] = useState(0);
  const show = (o: Open) => { if (busyRef.current) return; setOpen(o); setSeq((k) => k + 1); };
  const close = () => setOpen(null);
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const reportBusy = (b: boolean) => { busyRef.current = b; setBusy(b); };
  // the invite link opened outside the app, handed to the join dialog
  const [incoming, setIncoming] = useState<Incoming | null>(null);

  // a deep link (or the join intent) opens the join dialog, never over a running invite or join
  const inviteOpen = open?.kind === 'invite';
  useEffect(() => {
    if (busyRef.current || inviteOpen) return;
    if (invite) {
      takeInvite(invite.ref);
      setIncoming(invite);
      setOpen({ kind: 'join' }); setSeq((k) => k + 1);
      if (intent === 'join') clearIntent();
    }
  }, [invite, busy, inviteOpen]);
  useIntentOnce(intent, clearIntent, (i) => {
    if (i === 'invite') { show({ kind: 'invite' }); return true; }
    if (i === 'join') { if (invite) return false; show({ kind: 'join' }); return true; }
    if (i === 'share') { if (!cur) return false; show({ kind: 'share', env: cur }); return true; }
    return false;
  }, !busy && !inviteOpen && !!base.data);

  const revokeInvite = async (inv: InviteListItem) => {
    try {
      await call('team_revoke_invite', { env: cur, invite_id: inv.invite_id });
      toast(t('share.inv.revoked.toast'), 'warn');
    } catch (e) {
      toast(t(toIpcError(e).reason === 'invite_already_used' ? 'share.err.used' : 'error.generic'), 'warn');
    }
    reload();
  };

  const listen = parseListen(base.data?.settings?.team_listen);
  return (
    <>
      <div className="dev-intro-row">
        <p className="dev-intro">{t('share.intro')} {t('share.intro.devices')}</p>
        <Button size="sm" tone="ghost" icon="laptop" onClick={() => go('devices')}>{t('share.toDevices')}</Button>
      </div>
      {base.data?.envsUnread && <Banner tone="info">{t('share.envs.err')}</Banner>}

      <Section title={t('share.place')} id="dev-share-place" aside={(
        <>
          <Button size="sm" tone="ghost" icon="link" onClick={() => show({ kind: 'join' })}>{t('share.join')}</Button>
          <Button size="sm" tone="primary" icon="plus" onClick={() => show({ kind: 'invite' })}>{t('share.invite')}</Button>
        </>
      )}>
        <div className="card card-pad stack">
          {!base.data && base.error ? <LoadError error={base.error} onRetry={base.reload} />
            : !base.data ? <SkeletonRows n={1} />
              : pairs.length === 0 ? <p className="muted text-sm">{t('share.noPlace')}</p>
                : (
                  <div className="dev-place">
                    <SelectField label={t('share.place')} hideLabel value={cur} fieldClassName="grow"
                      options={pairs.map((p) => ({ value: p.key, label: placeLabel(p.project, p.environment) }))} onChange={setEnv} />
                    <div className="dev-place-state">
                      {td ? <Status tone={td.shared ? 'accent' : 'neutral'}>{t(td.shared ? 'share.state.on' : 'share.state.off')}</Status>
                        : team.error ? <Button size="sm" tone="ghost" icon="refresh" onClick={team.reload}>{t('act.retry')}</Button>
                          : <span className="muted text-sm">{t('state.loading')}</span>}
                      {td && !td.shared && <Button size="sm" tone="secondary" onClick={() => show({ kind: 'share', env: cur })}>{t('share.do')}</Button>}
                    </div>
                  </div>
                )}
          <p className="muted text-xs">{t('share.lan')}</p>
          {/* a shared place syncs only while other-device access is on */}
          {td?.shared && base.data?.settings && !listen && (
            <ListenSetup onBusy={reportBusy} interfaces={base.data.interfaces} run={relay.run}
              onDone={() => { toast(t('share.toast.listenOn'), 'ok'); reload(); bump(); }}
              onFailed={(down) => { if (down) relay.report(down); reload(); bump(); }} />
          )}
          {td?.shared && base.data?.settingsCorrupt && (
            <Banner tone="warn" action={<Button size="sm" tone="ghost" onClick={() => go('settings')}>{t('act.goSettings')}</Button>}>{t('share.settingsBroken')}</Banner>
          )}
        </div>
      </Section>

      {td?.shared && (
        <>
          <Section title={t('share.members')} id="dev-share-members">
            {td.members.length === 0 ? <p className="muted text-sm">{t('share.members.empty')}</p> : (
              <ul className="rows" aria-labelledby="dev-share-members">
                {td.members.map((m) => (
                  <li key={m.fingerprint} className="srow">
                    <IconTile icon="laptop" />
                    <div className="srow-main">
                      <span className="srow-title">{String(m.name ?? '')}</span>
                      <span className="srow-meta">{roleText(String(m.role))} · <span className="mono">{formatFingerprint(String(m.fingerprint))}</span></span>
                    </div>
                    <div className="srow-end">
                      {m.owner && <Badge tone="accent">{t('share.owner')}</Badge>}
                      {m.status !== 'active' && <Badge>{m.status === 'removed' ? t('share.removed') : String(m.status)}</Badge>}
                      {!m.owner && m.status === 'active' && (
                        <Menu label={t('share.member.more.aria', { name: String(m.name ?? '') })}
                          items={[{ label: t('share.remove'), icon: 'close', danger: true, onSelect: () => show({ kind: 'remove', env: cur, member: m }) }]} />
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Section>
          <Section title={t('share.invites')} id="dev-share-invites">
            {td.invites.length === 0 ? <p className="muted text-sm">{t('share.invites.empty')}</p> : (
              <ul className="rows" aria-labelledby="dev-share-invites">
                {td.invites.map((i) => {
                  const pending = i.status === 'pending' && msLeft(i.expires_at, now) > 0;
                  const status = pending ? i.status : i.status === 'pending' ? 'expired' : i.status;
                  const meta = [
                    roleText(String(i.role)),
                    pending ? t('share.inv.left', { time: formatCountdown(msLeft(i.expires_at, now)) }) : null,
                    i.used_by ? t('share.inv.usedBy', { fp: formatFingerprint(String(i.used_by)) }) : null,
                    i.created_at ? shortTime(i.created_at) : null,
                  ].filter(Boolean).join(' · ');
                  return (
                    <li key={i.invite_id} className="srow">
                      <IconTile icon="link" tone="service" />
                      <div className="srow-main"><span className="srow-title">{String(i.name)}</span><span className="srow-meta num">{meta}</span></div>
                      <div className="srow-end">
                        <Badge tone={pending ? 'accent' : 'neutral'}>{INVITE_STATUS[status] ? t(INVITE_STATUS[status] as CopyKey) : String(status)}</Badge>
                        {pending && <Menu label={t('share.inv.more.aria', { name: String(i.name) })}
                          items={[{ label: t('share.inv.revoke'), icon: 'close', danger: true, onSelect: () => void revokeInvite(i) }]} />}
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </Section>
        </>
      )}

      <InviteDialog key={`invite-${seq}`} open={open?.kind === 'invite'} env={cur} pairs={pairs} onEnv={setEnv}
        shared={td ? td.shared : null} loadFailed={!!team.error || !!base.error} onRetry={() => { team.reload(); base.reload(); }}
        onBusy={reportBusy} settings={base.data?.settings ?? null} interfaces={base.data?.interfaces ?? []} onChanged={reload} onClose={close} />
      <ConfirmDialog open={open?.kind === 'share'} title={t('share.do.title')} confirmLabel={t('share.do')} needPass warn={t('share.do.warn')} onClose={close}
        errorFor={(e) => (toIpcError(e).reason === 'team_env_already_shared' ? 'share.err.shared' : null)}
        run={async (pass) => {
          const pair = open?.kind === 'share' ? splitEnv(open.env) : null;
          if (!pair) return;
          await call('team_share', { project: pair.project, environment: pair.environment, admin_passphrase: pass });
          toast(t('share.toast.shared'), 'ok'); reload(); close();
        }}>
        {open?.kind === 'share' && <p className="mono text-sm">{open.env}</p>}
      </ConfirmDialog>
      <ConfirmDialog open={open?.kind === 'remove'} title={t('share.remove.title')} description={t('share.remove.sub')} confirmLabel={t('share.remove.confirm')}
        tone="danger" needPass warn={t('share.remove.warn')} onClose={close}
        run={async (pass) => {
          if (open?.kind !== 'remove') return;
          await call('team_remove', { env: open.env, device: open.member.fingerprint, admin_passphrase: pass });
          toast(t('share.toast.removed'), 'warn'); close(); reload();
        }}>
        {open?.kind === 'remove' && <KeyValues dense items={[{ k: t('share.name'), v: String(open.member.name ?? '') }, { k: t('share.member.fp'), v: <Fingerprint value={String(open.member.fingerprint)} /> }]} />}
      </ConfirmDialog>
      <JoinDialog key={`join-${seq}`} open={open?.kind === 'join'} incoming={incoming} onBusy={reportBusy} onClose={() => { setIncoming(null); close(); }}
        onEnv={setEnv} onChanged={() => { reload(); bump(); }} onJoined={() => { setIncoming(null); close(); reload(); bump(); }} />
    </>
  );
}

// ---------------------------------------------------------------- invite

/** Other-device access and sharing first, then role and name, then a 24-hour one-use link. The
 *  link stays in the core until it is copied or shown, and either hands it over once. */
function InviteDialog({ open, env: pageEnv, pairs, onEnv, shared: pageShared, settings, interfaces, loadFailed, onRetry, onBusy, onChanged, onClose }: {
  open: boolean; env: string; pairs: EnvPair[]; onEnv(v: string): void; shared: boolean | null; settings: Settings | null; interfaces: NetInterface[];
  loadFailed: boolean; onRetry(): void; onBusy(busy: boolean): void; onChanged(): void; onClose(): void;
}) {
  const { toast, announce } = useApp();
  const { relay } = useShell();
  const listen = parseListen(settings?.team_listen);
  const [ip, setIp] = useState(listen?.ip ?? defaultListenIp(interfaces));
  const [port, setPort] = useState(String(listen?.port ?? DEFAULT_TEAM_PORT));
  const [netOpen, setNetOpen] = useState(interfaces.length !== 1);
  const [role, setRole] = useState<Role>('user');
  const [name, setName] = useState('');
  const [pass, setPass] = useState('');
  const [sharedHere, setSharedHere] = useState<string[]>([]);
  // A reload may pick another listed place. A submitted operation keeps its actual target until
  // the result is acknowledged or the user explicitly picks a new one.
  const [operation, setOperation] = useState<{ env: string; shared: boolean } | null>(null);
  const env = operation?.env ?? pageEnv;
  const shared = operation?.shared ?? pageShared;
  const [uncertain, setUncertain] = useState(false);
  const [readResult, setReadResult] = useState<{ key: CopyKey; n?: number } | null>(null);
  const running = useRef(false);
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const isShared = shared === true || sharedHere.includes(env);
  const [errs, setErrs] = useState<{ port?: CopyKey; name?: CopyKey; pass?: CopyKey; form?: CopyKey }>({});
  const [listenErr, setListenErr] = useState<CopyLine[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [listenBusy, setListenBusy] = useState(false);
  const [made, setMade] = useState<{ invite_id: string; link_ref: string; expires_at: string; inviter: string; env: string } | null>(null);
  const [handed, setHanded] = useState<Handed | null>(null);
  const [revoked, setRevoked] = useState(false);
  const nameRef = useRef<HTMLInputElement>(null);
  const passRef = useRef<HTMLInputElement>(null);
  const portRef = useRef<HTMLInputElement>(null);
  const listenBtn = useRef<HTMLButtonElement>(null);
  const formRef = useRef<HTMLDivElement>(null);
  const now = useNow(!!made && open);
  const openRef = useRef(open);
  openRef.current = open;

  useEffect(() => { if (!ip && interfaces.length) setIp(defaultListenIp(interfaces)); }, [ip, interfaces]);
  useEffect(() => { if (!open) setPass(''); }, [open]);
  useEffect(() => {
    if (busy) return;
    const frame = requestAnimationFrame(() => { if (errs.form || readResult) formRef.current?.focus(); });
    return () => cancelAnimationFrame(frame);
  }, [busy, errs.form, readResult]);

  const turnOn = async () => {
    if (running.current) return;
    const p = parsePort(port);
    if (p === null || !ip) { setNetOpen(true); setErrs({ port: 'set.listen.port.err' }); setTimeout(() => portRef.current?.focus(), 50); return; }
    running.current = true; onBusy(true); setListenBusy(true); setListenErr(null);
    try {
      await relay.run(() => turnOnListen(ip, p));
      toast(t('share.toast.listenOn'), 'ok');
      onChanged();
      setTimeout(() => nameRef.current?.focus(), 60);
    } catch (e) {
      // an address the service cannot open is taken back (lib/relay.ts); say which and what runs
      setNetOpen(true);
      setListenErr(listenErrorLines(e));
      const down = relayLeftOff(e);
      if (down) relay.report(down);
      if (e instanceof ListenError) onChanged();
    } finally { running.current = false; onBusy(false); if (alive.current) setListenBusy(false); }
  };

  const ready = !!listen && shared !== null && !!env;
  const blocked = () => {
    if (shared === null) { if (loadFailed) onRetry(); else toast(t('state.loading')); return; }
    toast(t('share.blocked'), 'warn');
    (listen ? nameRef.current : listenBtn.current)?.focus();
  };

  const recheck = async () => {
    running.current = true; onBusy(true); setBusy(true); setReadResult(null);
    setErrs((old) => ({ ...old, form: undefined }));
    try {
      try { await call('team_members', { env }); }
      catch (e) {
        if (!NOT_SHARED.has(toIpcError(e).reason)) throw e;
        if (alive.current) { setOperation((c) => (c ? { ...c, shared: false } : c)); setReadResult({ key: 'share.read.unshared' }); }
        return;
      }
      const result = await call('team_invites', { env });
      if (alive.current) { setOperation((c) => (c ? { ...c, shared: true } : c)); setReadResult({ key: 'share.read.shared', n: result.invites.length }); }
    } catch {
      if (alive.current) setReadResult({ key: 'share.read.failed' });
    } finally {
      running.current = false; onBusy(false);
      if (alive.current) { setBusy(false); onChanged(); }
    }
  };

  const create = async () => {
    if (running.current) return;
    if (made) { onClose(); return; }
    if (uncertain) { await recheck(); return; }
    if (!ready || !listen) { blocked(); return; }
    const e: typeof errs = {};
    if (!name.trim() || name.length > 64 || /[\x00-\x1f\x7f]/.test(name)) e.name = 'share.name.err';
    if (!pass) e.pass = 'pass.err.empty';
    setErrs(e);
    if (e.name) { nameRef.current?.focus(); return; }
    if (e.pass) { passRef.current?.focus(); return; }
    setOperation({ env, shared: isShared });
    running.current = true; onBusy(true); setBusy(true);
    let committed = isShared;
    let sharedNow = false;
    try {
      const r = await shareAndInvite({ env, role, name: name.trim(), address: `${listen.ip}:${listen.port}`, admin_passphrase: pass }, isShared, () => {
        committed = true; sharedNow = true;
        setOperation({ env, shared: true });
        toast(t('share.toast.shared'), 'ok'); announce(t('share.toast.shared'));
        setSharedHere((xs) => (xs.includes(env) ? xs : [...xs, env]));
        onChanged();
      });
      if (!alive.current || !openRef.current) {
        void call('onetime_discard', { ref: r.link_ref }).catch(() => undefined);
        toast(t('share.late', { env }), 'warn');
        return;
      }
      setPass('');
      setMade({ ...r, env });
      toast(t('share.made'), 'ok'); announce(t('share.made'));
      onChanged();
    } catch (err) {
      if (!alive.current || !openRef.current) { toast(t('share.lateUnknown', { env }), 'warn'); return; }
      setPass('');
      if (toIpcError(err).reason === 'team_env_already_shared') {
        setOperation({ env, shared: true });
        setErrs({ form: 'share.err.shared' });
        onChanged();
      } else if (isAuthError(err)) {
        setErrs(sharedNow ? { pass: 'share.pass.again', form: 'share.failedShared' } : { pass: passErrorKey(err) });
        passRef.current?.focus();
      } else {
        // a failure that may have happened after a write: never retried on its own
        const unsure = !definiteInviteFailure(err);
        setUncertain(unsure);
        onChanged();
        setErrs({ form: unsure ? 'share.unknown' : committed ? 'share.failedShared' : 'error.generic' });
      }
    } finally { running.current = false; onBusy(false); if (alive.current) setBusy(false); }
  };

  const revoke = async () => {
    if (!made || revoked) return;
    try {
      await call('team_revoke_invite', { env: made.env, invite_id: made.invite_id });
      setRevoked(true); // unmounts the one-time view, which discards a link nobody took
      toast(t('share.inv.revoked.toast'), 'warn');
      onChanged();
    } catch { toast(t('error.generic'), 'warn'); }
  };

  const envOptions = [
    ...(env && !pairs.some((p) => p.key === env) ? [{ value: env, label: `${env} · ${t('share.unlisted')}` }] : []),
    ...pairs.map((p) => ({ value: p.key, label: placeLabel(p.project, p.environment) })),
  ];
  const locked = !!made || uncertain || busy || listenBusy;
  const primary = made ? t('act.done') : uncertain ? t('share.recheck') : shared === null ? t(loadFailed ? 'share.retryRead' : 'state.loading') : t(isShared ? 'share.create' : 'share.shareCreate');
  const left = made ? msLeft(made.expires_at, now) : 0;

  return (
    <Dialog open={open} title={t('share.invite')} description={t('share.invite.sub')} busy={busy || listenBusy} size="md"
      onClose={() => { if (!running.current) onClose(); }} onSubmit={() => void create()}
      footer={<>
        {!made && <Button tone="ghost" onClick={onClose} blocked={busy || listenBusy}>{t('act.cancel')}</Button>}
        <Button tone="primary" type="submit" busy={busy} blocked={!made && !uncertain && !ready && !busy} onBlocked={blocked}>{primary}</Button>
      </>}>
      <SelectField label={t('share.place')} value={env} options={envOptions} aria-disabled={locked || undefined}
        onChange={(v) => { if (!locked) { setOperation(null); onEnv(v); } }} />
      {!made && (
        <ol className="dev-prereq">
          <li className={listen ? 'is-done' : undefined}>
            <div className="dev-prereq-head">
              <span className="dev-prereq-mark" aria-hidden="true" />
              <span className="grow">{t('share.need.listen')}</span>
              <span className="mono text-sm muted">{listen ? `${listen.ip}:${listen.port}` : t('share.need.listen.off')}</span>
            </div>
            {!listen && (
              <div className="dev-prereq-body">
                <More label={t('share.listen.address')} hint={<span className="mono">{ip ? `${ip}:${port}` : t('share.need.listen.off')}</span>} open={netOpen} onToggle={setNetOpen}>
                  <div className="dev-listen-fields">
                    <SelectField label={t('share.listen.iface')} value={ip} options={addressChoices(interfaces, ip)} fieldClassName="grow"
                      onChange={(v) => { setIp(v); setListenErr(null); }} />
                    <TextField label={t('share.listen.port')} mono value={port} inputRef={portRef} inputMode="numeric" maxLength={5} fieldClassName="dev-port"
                      error={errs.port ? t(errs.port) : null} onChange={(v) => { setPort(v); setErrs((x) => ({ ...x, port: undefined })); setListenErr(null); }} />
                  </div>
                </More>
                <div className="row-wrap">
                  <Button size="sm" tone="secondary" ref={listenBtn} busy={listenBusy} blocked={busy} onClick={() => void turnOn()}>{t('share.listen.on')}</Button>
                  <span className="muted text-xs">{t('share.need.firewall')}</span>
                </div>
                {listenErr && <div className="field-note is-error" role="alert">{tLines(listenErr)}</div>}
              </div>
            )}
          </li>
          <li className={isShared ? 'is-done' : undefined}>
            <div className="dev-prereq-head">
              <span className="dev-prereq-mark" aria-hidden="true" />
              <span className="grow">{t('share.need.share')}</span>
              <span className="text-sm muted">{t(isShared ? 'share.state.on' : 'share.state.off')}</span>
            </div>
            {!isShared && (
              <div className="dev-prereq-body">
                <Banner tone="warn" compact>{t('share.do.warn')}</Banner>
                <p className="muted text-xs">{t('share.need.shareOnCreate')}</p>
              </div>
            )}
          </li>
        </ol>
      )}
      {!made && (
        <>
          <TextField label={t('share.name')} value={name} inputRef={nameRef} maxLength={64} placeholder={t('share.name.ph')} readOnly={busy}
            error={errs.name ? t(errs.name) : null} onChange={(v) => { if (running.current) return; setName(v); setErrs((x) => ({ ...x, name: undefined })); }} />
          <PassField value={pass} inputRef={passRef} readOnly={busy} error={errs.pass ? t(errs.pass) : null}
            onChange={(v) => { if (running.current) return; setPass(v); setErrs((x) => ({ ...x, pass: undefined })); }} />
          <More hint={t('share.more.role', { role: t(role === 'admin' ? 'share.role.admin' : 'share.role.user') })}>
            <Segmented<Role> label={t('share.role')} hideLabel={false} value={role} onChange={(v) => { if (!running.current) setRole(v); }}
              options={[{ value: 'user', label: t('share.role.user') }, { value: 'admin', label: t('share.role.admin') }]} />
          </More>
          {sharedHere.includes(env) && <Banner tone="ok" compact>{t('share.toast.shared')}</Banner>}
          {shared === null && <p className="muted text-sm" role="status">{t(loadFailed ? 'error.load' : 'state.loading')}</p>}
          {(errs.form || readResult) && (
            <div ref={formRef} tabIndex={-1} className="dev-focus-target">
              {errs.form && <Banner tone="danger">{t(errs.form)}</Banner>}
              {readResult && <Banner tone="info">{t(readResult.key, { n: readResult.n ?? 0 })}</Banner>}
            </div>
          )}
        </>
      )}
      {made && (
        <div className="stack">
          <KeyValues dense items={[{ k: t('share.name'), v: name.trim() }, { k: t('share.role'), v: roleText(role) }]} />
          <div className="field">
            <div className="field-label"><span>{t('share.link')}</span><span className="field-aside num">{revoked ? t('share.inv.revoked') : t('share.link.left', { time: formatCountdown(left) })}</span></div>
            {revoked
              ? <div className="onetime"><div className="onetime-value mono">{t('share.link.revokedMask')}</div></div>
              : <OneTimeValue valueRef={made.link_ref} masked={t('share.link.mask')} label={t('share.link.aria')} onHanded={setHanded} />}
          </div>
          <div className="dev-fp">
            <span className="field-label">{t('share.inviter')}</span>
            <Fingerprint value={made.inviter} />
          </div>
          <Banner tone="warn">{t('share.link.warn')}</Banner>
          {!revoked && <div><Button size="sm" tone="quiet" icon="close" onClick={() => void revoke()}>{t('share.inv.revoke')}</Button></div>}
          {handed === 'gone' && <p className="muted text-xs">{t('onetime.gone')}</p>}
        </div>
      )}
    </Dialog>
  );
}

// ---------------------------------------------------------------- join

/** Paste a link (or arrive from a zeropw://join link) → preview → explicit confirm. Nothing joins
 *  until the button is pressed. After joining, sync needs other-device access, offered here. The
 *  pasted link leaves the dialog's state when the join is tried and when the dialog closes. */
function JoinDialog({ open, incoming, onBusy, onClose, onEnv, onChanged, onJoined }: {
  open: boolean; incoming: Incoming | null; onBusy(busy: boolean): void; onClose(): void; onEnv(key: string): void; onChanged(): void; onJoined(): void;
}) {
  const { toast, announce } = useApp();
  const { relay, go } = useShell();
  const [text, setText] = useState('');
  const [err, setErr] = useState<CopyKey | null>(null);
  const [held, setHeld] = useState<{ ref: string; preview: InvitePreview; fromLink: boolean } | null>(null);
  const [local, setLocal] = useState('');
  const localEdited = useRef(false);
  const [localOpen, setLocalOpen] = useState(false);
  const [localErr, setLocalErr] = useState<CopyKey | null>(null);
  const [busy, setBusy] = useState(false);
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
    if (old && old.ref !== h?.ref) void call('onetime_discard', { ref: old.ref }).catch(() => undefined);
    heldRef.current = h; setHeld(h);
    if (h) { if (!localEdited.current) setLocal(defaultLocalName(h.preview.inviter)); setLocalErr(null); }
  };

  useEffect(() => {
    const requests = previews.current;
    alive.current = true;
    return () => {
      alive.current = false;
      requests.invalidate();
      queueMicrotask(() => {
        if (alive.current || running.current) return; // a join keeps its ref until the call settles
        const h = heldRef.current;
        heldRef.current = null;
        if (h) void call('onetime_discard', { ref: h.ref }).catch(() => undefined);
      });
    };
  }, []);

  useEffect(() => {
    if (!incoming) return;
    previews.current.invalidate();
    setText(''); setErr(null);
    if (incoming.preview.expired) { void call('onetime_discard', { ref: incoming.ref }).catch(() => undefined); setErr('join.err.expired'); hold(null); return; }
    hold({ ref: incoming.ref, preview: incoming.preview, fromLink: true });
  }, [incoming]);

  // the held reference is the core's: give it back when the dialog closes without joining
  useEffect(() => {
    if (open) return;
    previews.current.invalidate();
    setText('');
    const h = heldRef.current;
    if (h && !running.current) { heldRef.current = null; void call('onetime_discard', { ref: h.ref }).catch(() => undefined); }
  }, [open]);

  const onLink = (v: string) => {
    setText(v);
    const s = v.trim();
    previews.current.invalidate();
    if (!s) { setErr(null); hold(null); return; }
    if (!isInviteLink(s)) { setErr('join.err'); hold(null); return; }
    setErr(null);
    void previews.current.preview(s, () => hold(null),
      (r) => {
        if (r.preview.expired) { void call('onetime_discard', { ref: r.ref }).catch(() => undefined); setErr('join.err.expired'); hold(null); return; }
        hold({ ref: r.ref, preview: r.preview, fromLink: false });
      },
      (e) => { setErr(invitePreviewErrorKey(toIpcError(e).reason)); hold(null); },
    );
  };

  const join = async () => {
    if (running.current) return;
    if (joined) { onJoined(); return; }
    const h = heldRef.current;
    if (!h) { linkRef.current?.focus(); return; }
    const parsed = parseLocalName(local);
    if (!parsed) { setErr(null); setLocalOpen(true); setLocalErr('share.join.local.err'); setTimeout(() => localRef.current?.focus(), 50); return; }
    running.current = true; onBusy(true); setBusy(true);
    previews.current.invalidate();
    setText(''); // the core holds the invite behind the reference
    try {
      const out = await call('team_join', { ref: h.ref, project: parsed.project, environment: parsed.environment });
      heldRef.current = null;
      if (alive.current) { setHeld(null); onEnv(envKey(String(out.project), String(out.environment))); }
      // sync needs other-device access; damaged settings are reset in Settings
      const [s, i] = await Promise.all([readSettings().catch(() => null), call('net_interfaces').catch(() => [] as NetInterface[])]);
      const listenerOn = !!s && !s.corrupt && !!parseListen(s.settings.team_listen);
      if (!alive.current) { toast(t(listenerOn ? 'share.toast.joined' : 'share.toast.needListen'), 'ok'); return; }
      if (!listenerOn) {
        setJoined({ interfaces: i, settingsCorrupt: s?.corrupt ?? false });
        toast(t('share.toast.needListen'));
        announce(t('share.joined.sub'));
        onChanged();
      } else {
        toast(t('share.toast.joined'), 'ok');
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
      if (reason === 'invite_expired' || isStaleRef(reason)) { heldRef.current = null; setHeld(null); void call('onetime_discard', { ref: h.ref }).catch(() => undefined); }
      setErr(joinErrorKey(reason));
      linkRef.current?.focus();
    } finally { running.current = false; onBusy(false); if (alive.current) setBusy(false); }
  };

  if (joined) {
    return (
      <Dialog open={open} title={t('share.join')} description={t('share.joined.sub')} onClose={onJoined}
        footer={<Button tone="ghost" onClick={onJoined}>{t('share.joined.later')}</Button>}>
        {joined.settingsCorrupt
          ? <Banner tone="warn" action={<Button size="sm" tone="ghost" onClick={() => { onJoined(); go('settings'); }}>{t('act.goSettings')}</Button>}>{t('share.settingsBroken')}</Banner>
          : (
            <ListenSetup onBusy={onBusy} interfaces={joined.interfaces} run={relay.run}
              onDone={() => { toast(t('share.toast.listenOn'), 'ok'); onJoined(); }}
              onFailed={(down) => { if (down) relay.report(down); onChanged(); }} />
          )}
      </Dialog>
    );
  }

  const p = held?.preview;
  const addr = p ? (p.addresses[0] ?? '') + (p.addresses.length > 1 ? ' ' + t('share.join.more', { n: p.addresses.length - 1 }) : '') : '';
  return (
    <Dialog open={open} title={t('share.join')} description={t('share.join.sub')} busy={busy} size="md"
      onClose={() => { if (!running.current) onClose(); }} onSubmit={() => void join()}
      footer={<>
        <Button tone="ghost" onClick={onClose} blocked={busy}>{t('act.cancel')}</Button>
        <Button tone="primary" type="submit" busy={busy} blocked={!held && !busy} onBlocked={() => linkRef.current?.focus()}>{t('share.join.confirm')}</Button>
      </>}>
      <PassField label={t('share.join.field')} autoComplete="off" mono value={text} readOnly={busy} inputRef={linkRef} placeholder="zeropw://join#…"
        error={err ? t(err) : null} help={held?.fromLink ? t('share.join.fromLink') : undefined}
        onChange={(v) => { if (!running.current) onLink(v); }} />
      {p && (
        <>
          <div className="card card-pad stack-sm" role="region" aria-label={t('share.join.pv')}>
            <span className="muted text-sm">{t('share.join.inviter')}</span>
            <Fingerprint value={p.inviter} />
          </div>
          <More hint={t('share.join.details', { role: roleText(p.role) })} open={localOpen} onToggle={setLocalOpen}>
            <KeyValues dense items={[
              { k: t('share.join.env'), v: p.env_id.slice(0, 10) + '…', mono: true },
              { k: t('share.join.role'), v: roleText(p.role) },
              { k: t('share.join.addr'), v: addr, mono: true },
              { k: t('share.join.left'), v: <span className="num">{formatCountdown(msLeft(p.expires_at, now))}</span> },
            ]} />
            <TextField label={t('share.join.local')} mono value={local} readOnly={busy} inputRef={localRef} help={t('share.join.local.help')}
              error={localErr ? t(localErr) : null} onChange={(v) => { localEdited.current = true; setLocal(v); setLocalErr(null); }} />
          </More>
          <Banner tone="warn">{t('share.join.check')}</Banner>
        </>
      )}
    </Dialog>
  );
}
