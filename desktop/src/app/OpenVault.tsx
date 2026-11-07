// The open vault: sidebar plus the current page, and everything the pages share. The shell
// follows the core's events (local service status, stop changes, dropped .env files, opened
// invite links), reads new usage records while the window is visible (the core does not push
// them; docs/desktop-app.md §5) and owns the local service's start/restart state.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { t, type CopyKey } from '../copy';
import { call, on, toIpcError } from '../ipc/client';
import type { AppStatus, Control, EnvFileRef, InvitePreview, ServeStatus } from '../ipc/contract';
import { dropErrorKey } from '../lib/envimport';
import { PendingInviteOwner } from '../lib/pendingInvite';
import { offersListenOff, relayError } from '../lib/reasons';
import { turnOffListen } from '../lib/relay';
import { watchRecords } from '../lib/watch';
import { useApp } from '../ui/app';
import { ConfirmDialog, passErrorKey, isAuthError } from '../ui/Dialog';
import { useHotkey, useLoad, useNarrow } from '../ui/hooks';
import { Icon } from '../ui/icons';
import { ActivityPage } from '../screens/activity/ActivityPage';
import { DeveloperPage } from '../screens/developer/DeveloperPage';
import { DevicesPage } from '../screens/devices/DevicesPage';
import { ServicesPage } from '../screens/services/ServicesPage';
import { SettingsPage } from '../screens/settings/SettingsPage';
import { VaultPage } from '../screens/vault/VaultPage';
import { NO_CONTROL, ShellContext, type Intent, type Page, type RelayApi, type RelayProblem, type Route, type ShellApi, type VaultData } from './shell';
import { Sidebar } from './Sidebar';

const AUDIT_POLL_MS = 4000;

export function Shell({ initialStatus, initialRoute, onRoute, onLock, incoming, onIncomingTaken }: {
  initialStatus: AppStatus;
  initialRoute: Route;
  onRoute(r: Route): void;
  onLock(): void;
  /** The latest invite link opened outside the app. */
  incoming: { ref: string; preview: InvitePreview } | null;
  /** The shell owns the link now (it discards it when the vault closes unused). */
  onIncomingTaken(): void;
}) {
  const { toast, announce } = useApp();
  const [route, setRoute] = useState<Route>(initialRoute);
  const [serve, setServe] = useState<ServeStatus>(initialStatus.serve);
  const [control, setControl] = useState<Control>(initialStatus.control ?? NO_CONTROL);
  const [tick, setTick] = useState(0);
  const [activity, setActivity] = useState(0);
  const [dialog, setDialog] = useState<'stop' | 'resume' | 'listenOff' | null>(null);
  const [envFile, setEnvFile] = useState<EnvFileRef | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [invite, setInvite] = useState<{ ref: string; preview: InvitePreview } | null>(null);
  const rail = useNarrow(820);
  const single = useNarrow(1000);
  const controlRef = useRef(control);
  controlRef.current = control;
  const toastRef = useRef(toast);
  toastRef.current = toast;
  const onRouteRef = useRef(onRoute);
  onRouteRef.current = onRoute;

  // ---- routing
  const go = useCallback((page: Page, opts?: Omit<Route, 'page'>) => {
    const r: Route = { page, ...opts };
    setRoute(r);
    onRouteRef.current({ page: r.page, view: r.view, item: r.item });
  }, []);
  const clearIntent = useCallback(() => setRoute((r) => (r.intent ? { ...r, intent: undefined } : r)), []);
  const firstPage = useRef(true);
  useEffect(() => {
    announce(t(PAGE_LABEL[route.page]));
    if (firstPage.current) { firstPage.current = false; return; }
    document.querySelector<HTMLElement>('[data-page-title]')?.focus({ preventScroll: true });
  }, [route.page, announce]);

  // ---- global state
  const refresh = useCallback(() => {
    call('app_status').then((s) => { setServe(s.serve); if (s.control) setControl(s.control); setTick((k) => k + 1); }, () => setTick((k) => k + 1));
  }, []);
  const bump = useCallback(() => refresh(), [refresh]);

  const vault = useLoad<VaultData>(async () => {
    const [listing, secrets] = await Promise.all([call('project_list'), call('secret_list', {})]);
    return { listing, secrets: secrets.secrets };
  }, [tick]);

  // ---- core events
  useEffect(() => {
    const offs: Array<() => void> = [];
    let dead = false;
    const keep = (p: Promise<() => void>) => p.then((un) => { if (dead) un(); else offs.push(un); }, () => undefined);
    keep(on('serve://status', (s) => setServe(s)));
    keep(on('control://changed', (c) => setControl(c)));
    keep(on('envfile://hover', (h) => setDragOver(h.over)));
    keep(on('envfile://dropped', (d) => {
      setDragOver(false);
      if (d.import_ref && d.name !== undefined) {
        const file = { import_ref: d.import_ref, name: d.name };
        setEnvFile((old) => { if (old && old.import_ref !== file.import_ref) void call('onetime_discard', { ref: old.import_ref }).catch(() => undefined); return file; });
        go('vault', { intent: 'import' });
      } else {
        toastRef.current(t(dropErrorKey(d.error ?? '')), 'warn');
      }
    }));
    window.addEventListener('focus', refresh);
    return () => { dead = true; offs.forEach((f) => f()); window.removeEventListener('focus', refresh); };
  }, [refresh, go]);

  // a dropped file nobody imported is discarded when the vault closes (lock, quit)
  const envFileRef = useRef(envFile);
  envFileRef.current = envFile;
  useEffect(() => () => { const f = envFileRef.current; if (f) void call('onetime_discard', { ref: f.import_ref }).catch(() => undefined); }, []);
  const takeEnvFile = useCallback(() => setEnvFile(null), []);

  // ---- invite links opened while open: the sharing view shows the preview; joining needs a click
  const pending = useRef(new PendingInviteOwner((ref) => { void call('onetime_discard', { ref }).catch(() => undefined); }));
  const lastIncoming = useRef<string | null>(null);
  useEffect(() => {
    if (!incoming || incoming.ref === lastIncoming.current) return;
    lastIncoming.current = incoming.ref;
    pending.current.replace(incoming.ref);
    setInvite(incoming);
    onIncomingTaken();
    go('developer', { view: 'sharing', intent: 'join' });
  }, [incoming, go, onIncomingTaken]);
  useEffect(() => {
    const owner = pending.current;
    return () => owner.dispose();
  }, []);
  const takeInvite = useCallback((ref: string) => {
    if (pending.current.take(ref)) setInvite((i) => (i?.ref === ref ? null : i));
  }, []);

  // ---- usage records: read the tail while visible; new records may come with a stop or an
  // incident the relay opened on its own, so the stop state is read again when they do
  useEffect(() => {
    let dead = false;
    const watch = watchRecords({
      records: () => setActivity((k) => k + 1),
      control: (c) => { setControl(c); refresh(); },
    }, () => controlRef.current);
    const poll = () => { if (!dead && !document.hidden) void watch.poll(); };
    poll();
    const id = setInterval(poll, AUDIT_POLL_MS);
    const vis = () => { if (!document.hidden) poll(); };
    document.addEventListener('visibilitychange', vis);
    let off: (() => void) | null = null;
    on('audit://records', () => poll()).then((un) => { if (dead) un(); else off = un; }, () => undefined);
    return () => { dead = true; watch.stop(); clearInterval(id); document.removeEventListener('visibilitychange', vis); off?.(); };
  }, [refresh]);

  // ---- the local service
  const [relayRuns, setRelayRuns] = useState(0);
  const relayBusy = relayRuns > 0;
  const [relayProblem, setRelayProblem] = useState<RelayProblem | null>(null);
  useEffect(() => { if (serve.running) setRelayProblem(null); }, [serve.running]);
  const report = useCallback((e: unknown) => {
    const err = toIpcError(e);
    const p = relayError(err.reason, err.detail);
    setRelayProblem(p);
    const msg = t(p.key, { reason: p.reason });
    toast(msg, 'warn'); announce(msg);
  }, [toast, announce]);
  const runRelay = useCallback(async <T,>(task: () => Promise<T>): Promise<T> => {
    setRelayRuns((n) => n + 1); setRelayProblem(null);
    try { return await task(); } finally { setRelayRuns((n) => Math.max(0, n - 1)); }
  }, []);
  const start = useCallback(async (): Promise<boolean> => {
    try {
      const s = await runRelay(() => call('serve_start'));
      setServe(s);
      if (!s.running) { report({ error: 'Unavailable', reason: 'serve_not_running' }); return false; }
      toast(t('toast.svc.on'), 'ok');
      return true;
    } catch (e) { report(e); return false; }
  }, [runRelay, report, toast]);
  const [teamListen, setTeamListen] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    call('settings_get').then((s) => { if (live) setTeamListen(s.team_listen); }, () => undefined);
    return () => { live = false; };
  }, [tick, serve.running]);
  const offerListenOff = offersListenOff({ running: serve.running, busy: relayBusy, teamListen, problem: relayProblem });
  const confirmListenOff = useCallback(() => setDialog('listenOff'), []);
  const relay: RelayApi = useMemo(() => ({ busy: relayBusy, problem: relayProblem, start, run: runRelay, report, teamListen, offerListenOff, confirmListenOff }),
    [relayBusy, relayProblem, start, runRelay, report, teamListen, offerListenOff, confirmListenOff]);

  // ---- shortcuts
  useHotkey('l', () => onLock());
  useHotkey(',', () => go('settings'));
  useHotkey('f', () => { go('vault'); setTimeout(() => window.dispatchEvent(new Event('zpw:focus-search')), 0); });
  useHotkey('1', () => go('vault', { view: 'all' }));
  useHotkey('2', () => go('devices'));
  useHotkey('3', () => go('services'));
  useHotkey('4', () => go('developer'));
  useHotkey('5', () => go('activity'));

  const api: ShellApi = useMemo(() => ({
    route, go, clearIntent, tick, activity, bump, control, serve, setControl, setServe, relay, vault,
    envFile, takeEnvFile, invite, takeInvite, lock: onLock, narrow: { rail, single },
  }), [route, go, clearIntent, tick, activity, bump, control, serve, relay, vault, envFile, takeEnvFile, invite, takeInvite, onLock, rail, single]);

  const intent: Intent | undefined = route.intent;
  return (
    <ShellContext.Provider value={api}>
      <div id="app-root" className={'app' + (rail ? ' is-rail' : '')}>
        <Sidebar onStop={() => setDialog('stop')} onResume={() => setDialog('resume')} />
        <main className="main" aria-label={t(PAGE_LABEL[route.page])}>
          <div className="page-host" key={route.page} style={{ display: 'contents' }}>
            {route.page === 'vault' && <VaultPage intent={intent} />}
            {route.page === 'devices' && <DevicesPage intent={intent} />}
            {route.page === 'services' && <ServicesPage intent={intent} />}
            {route.page === 'developer' && <DeveloperPage intent={intent} />}
            {route.page === 'activity' && <ActivityPage intent={intent} />}
            {route.page === 'settings' && <SettingsPage intent={intent} />}
          </div>
        </main>
      </div>
      {dragOver && (
        <div className="drop-layer" aria-hidden="true">
          <div className="drop-card"><Icon name="file" size={22} /><strong>{t('drop.title')}</strong><span>{t('drop.sub')}</span></div>
        </div>
      )}
      <ConfirmDialog open={dialog === 'stop'} title={t('stop.title')} description={t('stop.sub')} confirmLabel={t('stop.confirm')} tone="danger"
        info={t('stop.session')} onClose={() => setDialog(null)}
        run={async () => { setControl(await call('stop_all')); toast(t('toast.svc.stopped'), 'warn'); setDialog(null); }} />
      <ConfirmDialog open={dialog === 'resume'} title={t('resume.title')} description={t('resume.sub')} confirmLabel={t('resume.confirm')} needPass
        onClose={() => setDialog(null)}
        errorFor={(e): CopyKey | null => (toIpcError(e).reason === 'incident_open' ? 'resume.err.incident' : isAuthError(e) ? passErrorKey(e) : null)}
        run={async (pass) => { setControl(await call('resume', { admin_passphrase: pass })); toast(t('toast.svc.resumed'), 'ok'); setDialog(null); }} />
      <ConfirmDialog open={dialog === 'listenOff'} title={t('listenOff.title')} description={t('listenOff.sub')} confirmLabel={t('svc.listenOff')}
        info={t('listenOff.note')} onClose={() => setDialog(null)}
        run={async () => {
          try {
            const s = await runRelay(turnOffListen);
            setTeamListen(null); setServe(s);
            if (!s.running) report({ error: 'Unavailable', reason: 'serve_not_running' });
            else toast(t('toast.listen.off'), 'ok');
          } catch (e) { report(e); } finally { setTick((k) => k + 1); }
          setDialog(null);
        }}>
        {teamListen && <p className="mono text-sm">{teamListen}</p>}
      </ConfirmDialog>
    </ShellContext.Provider>
  );
}

export const PAGE_LABEL: Record<Page, CopyKey> = {
  vault: 'nav.vault', devices: 'nav.devices', services: 'nav.services', developer: 'nav.developer', activity: 'nav.activity', settings: 'nav.settings',
};
