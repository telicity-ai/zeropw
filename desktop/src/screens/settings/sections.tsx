// The settings sections. Each reads only what it shows; nothing here ever handles a vault value.
// The recovery code crosses IPC once, typed, and is cleared after every attempt.

import { useEffect, useRef, useState } from 'react';
import { IDLE_LOCK_MIN } from '../../app/shell';
import { useShell } from '../../app/shell';
import { t, tLines, type CopyKey, type CopyLine } from '../../copy';
import { call, toIpcError } from '../../ipc/client';
import type { LinkStatus } from '../../ipc/contract';
import { addressChoices, MIN_GATEWAY_PORT, parseListen, parsePort } from '../../lib/dash';
import { restoreErrorKey } from '../../lib/reasons';
import { listenErrorLines, relayLeftOff, turnOnListen } from '../../lib/relay';
import { useApp } from '../../ui/app';
import { Button, PassField, SelectField, TextField } from '../../ui/controls';
import { ConfirmDialog, Dialog } from '../../ui/Dialog';
import { Banner, KeyValues, LoadError, Section, SkeletonRows, Status, type Tone } from '../../ui/feedback';
import { useLoad } from '../../ui/hooks';
import { CorruptBanner, type SettingsCtx } from './SettingsPage';
import { More } from '../../ui/disclosure';
import { LanguageSelect } from '../../ui/LanguageSelect';

/** The deployment host planned for the link service. Typed into the field only when asked; it is
 *  not claimed to be running (no deployment or health check has been confirmed). */
export const PLANNED_SERVICE = 'https://zeropw-turn.telicity.ai';
const SERVICE_SHAPE = /^https?:\/\/[^/?#@\s\\%]+\/?$/i;
const CANCELLED = 'file_dialog_cancelled';

const hostOf = (url: string): string => url.replace(/^https?:\/\//i, '').replace(/\/$/, '');

// ------------------------------------------------------------------------------- security

export function SecuritySection({ ctx }: { ctx: SettingsCtx }) {
  const { lock, control, setControl } = useShell();
  const { toast } = useApp();
  const [dialog, setDialog] = useState<'stop' | 'resume' | 'recover' | null>(null);
  return (
    <>
      <Section>
        <LanguageSelect />
      </Section>
      <Section title={t('settings.lock.title')}>
        <div className="card card-pad stack">
          <p className="text-sm">{t('settings.lock.auto', { min: IDLE_LOCK_MIN })}</p>
          <p className="text-sm muted">{t('settings.lock.start')}</p>
          <Banner tone="neutral" compact>{t('settings.lock.what')}</Banner>
          <div className="row"><Button tone="secondary" icon="lock" onClick={lock}>{t('settings.lock.now')}</Button></div>
        </div>
      </Section>

      <Section title={t('settings.stop.title')}>
        <div className="card card-pad stack">
          <Status tone={control.stopped ? 'warn' : 'ok'}>{t(control.stopped ? 'settings.stop.on' : 'settings.stop.off')}</Status>
          <p className="text-sm muted">{t('settings.stop.what')}</p>
          <div className="row">
            {control.stopped
              ? <Button tone="secondary" icon="play" onClick={() => setDialog('resume')}>{t('svc.resume')}</Button>
              : <Button tone="secondary" icon="stop" onClick={() => setDialog('stop')}>{t('svc.stopAll')}</Button>}
          </div>
        </div>
      </Section>

      <Section title={t('settings.recover.title')}>
        <div className="card card-pad stack">
          <p className="text-sm muted">{t('settings.recover.sub')}</p>
          {ctx.needBackup && (
            <Banner tone="warn" action={<Button size="sm" tone="secondary" onClick={() => ctx.go('backup')}>{t('settings.recover.toBackup')}</Button>}>
              {t('settings.recover.backupNow')}
            </Banner>
          )}
          <div className="row"><Button tone="ghost" icon="key" onClick={() => setDialog('recover')}>{t('settings.recover.open')}</Button></div>
        </div>
      </Section>

      <ConfirmDialog open={dialog === 'stop'} title={t('stop.title')} description={t('stop.sub')} confirmLabel={t('stop.confirm')} tone="danger"
        info={t('stop.session')} onClose={() => setDialog(null)}
        run={async () => { setControl(await call('stop_all')); toast(t('toast.svc.stopped'), 'warn'); setDialog(null); }} />
      <ConfirmDialog open={dialog === 'resume'} title={t('resume.title')} description={t('resume.sub')} confirmLabel={t('resume.confirm')} needPass
        onClose={() => setDialog(null)}
        errorFor={(e): CopyKey | null => (toIpcError(e).reason === 'incident_open' ? 'resume.err.incident' : null)}
        run={async (pass) => { setControl(await call('resume', { admin_passphrase: pass })); toast(t('toast.svc.resumed'), 'ok'); setDialog(null); }} />
      <RecoverDialog open={dialog === 'recover'} onClose={() => setDialog(null)} onDone={() => { setDialog(null); ctx.setNeedBackup(true); }} />
    </>
  );
}

/** The recovery code replaces the device key file (`recover`): a new key file wraps the same
 *  data key again, every agent permission is revoked, and a backup made before it no longer
 *  restores. It needs the current key file and is not a response to a leaked key file. */
function RecoverDialog({ open, onClose, onDone }: { open: boolean; onClose(): void; onDone(): void }) {
  const { toast } = useApp();
  const { bump } = useShell();
  const [code, setCode] = useState('');
  const [err, setErr] = useState<CopyKey | null>(null);
  const [busy, setBusy] = useState(false);
  const running = useRef(false);
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => { if (!open) { setCode(''); setErr(null); } }, [open]);

  const go = async () => {
    if (running.current) return;
    if (!code.trim()) { setErr('settings.recover.empty'); ref.current?.focus(); return; }
    running.current = true; setBusy(true);
    try {
      const out = await call('recover', { recovery_passphrase: code });
      const n = out.grants_revoked;
      toast(typeof n === 'number' ? t('toast.settings.recovered', { n }) : t('toast.settings.recovered.any'), 'warn');
      bump();
      onDone();
    } catch (e) {
      const ipc = toIpcError(e);
      setErr(ipc.error === 'AuthFailed' ? 'settings.recover.err' : ipc.reason === 'kms_missing' ? 'settings.recover.noKey' : 'error.generic');
      ref.current?.focus();
    } finally { running.current = false; setBusy(false); setCode(''); }
  };

  return (
    <Dialog open={open} title={t('settings.recover.title')} description={t('settings.recover.sub')} onClose={onClose} busy={busy} onSubmit={() => void go()}
      footer={<>
        <Button tone="ghost" onClick={onClose} blocked={busy}>{t('act.cancel')}</Button>
        <Button tone="danger" type="submit" busy={busy}>{t('settings.recover.confirm')}</Button>
      </>}>
      <PassField label={t('settings.recover.field')} autoComplete="off" mono value={code} inputRef={ref} placeholder="ABCD-EFGH-…"
        error={err ? t(err) : null} onChange={(v) => { setCode(v); setErr(null); }} />
      <Banner tone="warn">{t('settings.recover.warn')}</Banner>
      <Banner tone="info">{t('settings.recover.leak')}</Banner>
    </Dialog>
  );
}

// --------------------------------------------------------------------------------- server

/** What the server status says, from the link daemon. Never "operating": enrolment and a live
 *  connection are the only things the app can observe. */
export function serverState(link: LinkStatus): { key: CopyKey; tone: Tone } {
  if (!link.available) return { key: 'settings.server.st.unavailable', tone: 'neutral' };
  if (!link.running) return { key: 'settings.server.st.down', tone: 'warn' };
  if (!link.enrolled) return { key: 'settings.server.st.notEnrolled', tone: 'neutral' };
  if (link.revoked) return { key: 'settings.server.st.revoked', tone: 'danger' };
  return link.online ? { key: 'settings.server.st.online', tone: 'ok' } : { key: 'settings.server.st.offline', tone: 'warn' };
}

export function ServerSection({ ctx }: { ctx: SettingsCtx }) {
  const { tick, go } = useShell();
  const { toast } = useApp();
  const [n, setN] = useState(0);
  const link = useLoad(() => call('link_status'), [tick, n]);
  const [value, setValue] = useState<string | null>(null);
  const [err, setErr] = useState<CopyKey | null>(null);
  const [busy, setBusy] = useState(false);
  const running = useRef(false);
  const input = useRef<HTMLInputElement>(null);
  const saved = ctx.settings?.link_service ?? null;
  // filled once from the saved setting; later reads leave the field as the user left it
  useEffect(() => { if (ctx.settings && value === null) setValue(ctx.settings.link_service ?? ''); }, [ctx.settings, value]);
  const field = value ?? '';

  const save = async () => {
    if (running.current || !ctx.settings) return;
    const v = field.trim();
    if (v && !SERVICE_SHAPE.test(v)) { setErr('settings.server.err'); input.current?.focus(); return; }
    running.current = true; setBusy(true); setErr(null);
    try {
      // the current file, so the gateway port and other-device access stay as they are
      const cur = await call('settings_get');
      await call('settings_set', { ...cur, link_service: v ? v.replace(/\/$/, '') : null });
      toast(t(v ? 'settings.server.saved' : 'settings.server.cleared'), 'ok');
      ctx.reload(); setN((x) => x + 1);
    } catch (e) {
      const ipc = toIpcError(e);
      if (ipc.reason === 'link_service_invalid') setErr('settings.server.err');
      else if (ipc.reason === 'settings_corrupt') ctx.reload();
      else setErr('error.generic');
      input.current?.focus();
    } finally { running.current = false; setBusy(false); }
  };

  const l = link.data;
  const state = l ? serverState(l) : null;
  const nextHost = saved ? hostOf(saved) : t('settings.server.noHost');
  return (
    <>
      <Banner tone="info" icon="shield">{t('settings.server.what')}</Banner>
      <CorruptBanner ctx={ctx} />
      <Section title={t('settings.server.status')}>
        {!l ? (link.error ? <LoadError error={link.error} onRetry={() => setN((x) => x + 1)} /> : <SkeletonRows n={1} />) : (
          <div className="card card-pad stack">
            <Status tone={state!.tone}>{t(state!.key)}</Status>
            <KeyValues dense items={[
              l.enrolled ? { k: t('settings.server.enrolledHost'), v: l.service_host, mono: true } : { k: t('settings.server.nextHost'), v: nextHost, mono: !!saved },
            ]} />
            {l.enrolled && <p className="text-sm muted">{t('settings.server.enrolledKeeps')}</p>}
            {l.available && l.running && !l.enrolled && (
              <div className="row"><Button tone="secondary" icon="laptop" onClick={() => go('devices', { intent: 'enroll' })}>{t('settings.server.enroll')}</Button></div>
            )}
          </div>
        )}
      </Section>
      <Section title={t('settings.server.title')}>
        <form className="card card-pad stack" noValidate onSubmit={(e) => { e.preventDefault(); void save(); }}>
          <TextField label={t('settings.server.field')} mono value={field} inputRef={input} placeholder={t('settings.server.placeholder')}
            disabled={!ctx.settings} maxLength={255} help={t('settings.server.help')} error={err ? t(err) : null}
            onChange={(v) => { setValue(v); setErr(null); }} />
          {field.trim().replace(/\/$/, '') === PLANNED_SERVICE && <Banner tone="neutral" compact>{t('settings.server.plannedNote')}</Banner>}
          <div className="row-wrap">
            <Button tone="primary" type="submit" busy={busy} blocked={!ctx.settings}>{t('settings.server.save')}</Button>
            <Button tone="ghost" onClick={() => { setValue(PLANNED_SERVICE); setErr(null); input.current?.focus(); }}>{t('settings.server.planned')}</Button>
          </div>
        </form>
      </Section>
    </>
  );
}

// ----------------------------------------------------------------------------------- sync

export function SyncSection({ ctx }: { ctx: SettingsCtx }) {
  const { tick, relay, bump } = useShell();
  const { toast } = useApp();
  const link = useLoad(() => call('link_status'), [tick]);
  const s = ctx.settings;
  const listen = parseListen(s?.team_listen);
  const { ip = '', tport = '' } = ctx.fields ?? {};
  const [errLines, setErrLines] = useState<CopyLine[] | null>(null);
  const [busy, setBusy] = useState(false);
  const running = useRef(false);
  const portRef = useRef<HTMLInputElement>(null);

  // on: the service restarts with the new address, and an address it cannot open is taken back
  // (lib/relay.ts); off is confirmed first, since changes from other devices stop arriving
  const turnOn = async () => {
    if (!s || running.current) return;
    const p = parsePort(tport);
    if (p === null || !ip) { setErrLines([{ key: 'set.listen.port.err' }]); setTimeout(() => portRef.current?.focus(), 50); return; }
    running.current = true; setBusy(true); setErrLines(null);
    try {
      await relay.run(() => turnOnListen(ip, p));
      toast(t('toast.settings.listenOn'), 'ok');
    } catch (e) {
      setErrLines(listenErrorLines(e));
      const down = relayLeftOff(e);
      if (down) relay.report(down);
      setTimeout(() => portRef.current?.focus(), 50);
    }
    ctx.reload(); bump();
    running.current = false; setBusy(false);
  };

  return (
    <>
      <CorruptBanner ctx={ctx} />
      <Section title={t('settings.sync.title')}>
        {!s ? (ctx.loadFailed ? <LoadError error={null} onRetry={ctx.reload} /> : ctx.corrupt ? null : <SkeletonRows n={1} />) : (
          <form className="card card-pad stack" noValidate onSubmit={(e) => { e.preventDefault(); void turnOn(); }}>
            <Status tone={listen ? 'ok' : 'neutral'}>{listen ? t('settings.sync.on', { address: `${listen.ip}:${listen.port}` }) : t('settings.sync.off')}</Status>
            <p className="text-sm muted">{t('settings.sync.what')}</p>
            <More label={t('settings.sync.address')} hint={<span className="mono">{ip ? `${ip}:${tport}` : '—'}</span>} open={!!errLines}>
              <div className="settings-listen">
                <SelectField label={t('settings.sync.iface')} value={ip} options={addressChoices(ctx.interfaces, ip, listen?.ip)}
                  onChange={(v) => { ctx.setField('ip', v); setErrLines(null); }} />
                <TextField label={t('settings.sync.port')} mono value={tport} inputRef={portRef} inputMode="numeric" maxLength={5}
                  onChange={(v) => { ctx.setField('tport', v); setErrLines(null); }} />
              </div>
            </More>
            {errLines && <div className="field-note is-error" role="alert">{tLines(errLines)}</div>}
            <div className="row-wrap">
              <Button tone="primary" type="submit" busy={busy}>{t(listen ? 'settings.sync.change' : 'settings.sync.turnOn')}</Button>
              {listen && <Button tone="ghost" busy={relay.busy && !busy} onClick={() => { if (!relay.busy) relay.confirmListenOff(); }}>{t('settings.sync.turnOff')}</Button>}
            </div>
          </form>
        )}
      </Section>
      <Section title={t('settings.sync.name')}>
        <div className="card card-pad stack-sm">
          <span className="text-md">{link.data?.device_name ?? '—'}</span>
          <span className="text-sm muted">{t('settings.sync.nameNote')}</span>
        </div>
      </Section>
    </>
  );
}

// ------------------------------------------------------------------------------ developer

export function DeveloperSection({ ctx }: { ctx: SettingsCtx }) {
  const { serve, relay } = useShell();
  const s = ctx.settings;
  const { port = '' } = ctx.fields ?? {};
  const [err, setErr] = useState<CopyKey | null>(null);
  const [busy, setBusy] = useState(false);
  const running = useRef(false);
  const portRef = useRef<HTMLInputElement>(null);

  const savePort = async () => {
    if (!s || running.current) return;
    const p = parsePort(port, MIN_GATEWAY_PORT);
    if (p === null) { setErr('settings.dev.port.err'); setTimeout(() => portRef.current?.focus(), 50); return; }
    // the same port: nothing to save, but a service that is off is started on it
    if (p === s.gateway_port) { if (!serve.running && !relay.busy) void relay.start(); return; }
    running.current = true; setBusy(true);
    try {
      const cur = await call('settings_get');
      await call('settings_set', { ...cur, gateway_port: p });
    } catch (e) {
      setErr(toIpcError(e).reason === 'invalid_port' ? 'settings.dev.port.err' : 'error.generic');
      setTimeout(() => portRef.current?.focus(), 50);
      running.current = false; setBusy(false);
      return;
    }
    await ctx.restart('toast.settings.saved');
    running.current = false; setBusy(false);
  };

  return (
    <>
      <CorruptBanner ctx={ctx} />
      <Section title={t('settings.dev.service')}>
        <div className="card card-pad stack">
          <Status tone={serve.running ? 'ok' : 'neutral'}>{t(serve.running ? 'settings.dev.running' : 'settings.dev.stopped')}</Status>
          <p className="text-sm muted">{t('settings.dev.what')}</p>
          {serve.running && <KeyValues dense items={[
            serve.url ? { k: t('settings.dev.address'), v: serve.url, mono: true } : null,
          ]} />}
          {!serve.running && relay.problem && <Banner tone="danger">{t(relay.problem.key, { reason: relay.problem.reason })}</Banner>}
          <div className="row">
            {serve.running
              ? <Button tone="secondary" icon="refresh" busy={relay.busy} onClick={() => void ctx.restart('toast.settings.restarted')}>{t('settings.dev.restart')}</Button>
              : <Button tone="secondary" icon="play" busy={relay.busy} onClick={() => void relay.start()}>{t('settings.dev.start')}</Button>}
          </div>
        </div>
      </Section>
      {s && (
        <More label={t('settings.dev.port')} hint={<span className="mono">{port}</span>} open={!!err}>
          <form className="card card-pad stack" noValidate onSubmit={(e) => { e.preventDefault(); void savePort(); }}>
            <div className="settings-port">
              <TextField label={t('settings.dev.port')} hideLabel mono value={port} inputRef={portRef} inputMode="numeric" maxLength={5}
                help={t('settings.dev.port.help')} error={err ? t(err) : null} onChange={(v) => { ctx.setField('port', v); setErr(null); }} />
            </div>
            <div className="row"><Button tone="primary" type="submit" busy={busy || relay.busy}>{t('settings.dev.save')}</Button></div>
          </form>
        </More>
      )}
    </>
  );
}

// --------------------------------------------------------------------------------- backup

export function BackupSection({ ctx, onAck }: { ctx: SettingsCtx; onAck(): void }) {
  const { control, bump } = useShell();
  const { toast } = useApp();
  const [busy, setBusy] = useState(false);
  const [restoreOpen, setRestoreOpen] = useState(false);
  const running = useRef(false);

  const backup = async () => {
    if (running.current) return;
    running.current = true; setBusy(true);
    try {
      await call('backup_create');
      toast(t('toast.settings.backup'), 'ok');
      ctx.setNeedBackup(false);
    } catch (e) {
      if (toIpcError(e).reason !== CANCELLED) toast(t('error.generic'), 'warn');
    } finally { running.current = false; setBusy(false); }
  };

  return (
    <>
      {ctx.needBackup && <Banner tone="warn">{t('settings.recover.backupNow')}</Banner>}
      {control.restore_pending && (
        <Banner tone="warn" title={t('svc.held')} action={<Button size="sm" tone="secondary" onClick={onAck}>{t('settings.ack.open')}</Button>}>
          {t('settings.ack.pending')}
        </Banner>
      )}
      <Section title={t('settings.backup.title')}>
        <div className="card card-pad stack">
          <p className="text-sm muted">{t('settings.backup.help')}</p>
          <div className="row"><Button tone="primary" icon="download" busy={busy} onClick={() => void backup()}>{t('settings.backup.create')}</Button></div>
        </div>
      </Section>
      <Section title={t('settings.restore.title')}>
        <div className="card card-pad stack">
          <p className="text-sm muted">{t('settings.restore.sub')}</p>
          <div className="row"><Button tone="secondary" icon="upload" onClick={() => setRestoreOpen(true)}>{t('settings.restore.open')}</Button></div>
        </div>
      </Section>
      <ConfirmDialog open={restoreOpen} title={t('settings.restore.title')} description={t('settings.restore.sub')}
        confirmLabel={t('settings.restore.confirm')} tone="danger" needPass warn={t('settings.restore.warn')} onClose={() => setRestoreOpen(false)}
        errorFor={(e) => restoreErrorKey(toIpcError(e).reason)}
        run={async (pass) => {
          await call('backup_restore', { admin_passphrase: pass });
          toast(t('toast.settings.restored'), 'warn'); setRestoreOpen(false); bump();
        }} />
    </>
  );
}

// ---------------------------------------------------------------------------------- about

export function AboutSection({ ctx }: { ctx: SettingsCtx }) {
  const { tick, serve } = useShell();
  const status = useLoad(() => call('app_status'), [tick]);
  const link = useLoad(() => call('link_status'), [tick]);
  const l = link.data;
  const yes = (v: boolean) => t(v ? 'settings.yes' : 'settings.no');
  const linkText = !l ? '—' : !l.available ? t('settings.about.link.missing') : l.running ? t('settings.about.link.ok') : t('settings.about.link.down');
  return (
    <>
      <Banner tone="neutral" compact>{t('settings.about.note')}</Banner>
      <div className="card card-pad">
        <KeyValues items={[
          { k: t('settings.about.app'), v: t('settings.about.appValue') },
          { k: t('settings.about.service'), v: serve.running ? t('settings.dev.running') : t('settings.dev.stopped') },
          { k: t('settings.about.link'), v: linkText },
          l?.enrolled ? { k: t('settings.about.online'), v: yes(l.online) } : null,
        ]} />
      </div>
      <More label={t('settings.about.details')}>
        <div className="card card-pad">
          <KeyValues dense items={[
            status.data ? { k: t('settings.about.stateDir'), v: status.data.state_dir, mono: true } : null,
            { k: t('settings.about.service'), v: serve.running ? `${serve.url ?? ''}${serve.pid !== null ? ` · pid ${serve.pid}` : ''}` : t('settings.dev.stopped'), mono: serve.running },
            { k: t('settings.about.settings'), v: ctx.corrupt ? t('settings.about.settings.corrupt') : ctx.settings ? t('settings.about.settings.ok') : '—' },
            l?.problem ? { k: t('settings.about.problem'), v: l.problem, mono: true } : null,
            l?.running ? { k: t('settings.about.enrolled'), v: yes(l.enrolled) } : null,
            l?.enrolled ? { k: t('settings.about.host'), v: l.service_host, mono: true } : null,
            l?.enrolled ? { k: t('settings.about.peers'), v: t('settings.about.peersN', { n: l.peers.length }) } : null,
          ]} />
        </div>
        {l && l.peers.length > 0 && (
          <ul className="rows" aria-label={t('settings.about.peers')}>
            {l.peers.map((p) => (
              <li className="srow" key={p.device_id}>
                <div className="srow-main">
                  <span className="srow-title">{p.name}</span>
                  <span className="srow-meta">
                    {[
                      p.path === null ? t('settings.about.path.none') : p.path === 'direct' ? t('settings.about.path.direct') : `${t('settings.about.path.relay')} (${p.path})`,
                      p.rtt_ms !== null ? t('settings.about.rtt', { ms: p.rtt_ms }) : null,
                      p.revoked ? t('settings.server.st.revoked') : null,
                    ].filter(Boolean).join(' · ')}
                  </span>
                  {p.last_error && <span className="srow-meta mono">{p.last_error}</span>}
                </div>
                <div className="srow-end"><Status tone={p.online ? 'ok' : 'neutral'}>{t(p.online ? 'state.on' : 'state.off')}</Status></div>
              </li>
            ))}
          </ul>
        )}
      </More>
      {link.error && <LoadError error={link.error} onRetry={() => undefined} />}
    </>
  );
}

