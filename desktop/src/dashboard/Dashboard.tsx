import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { t, type CopyKey } from '../copy';
import { call, on, toIpcError } from '../ipc/client';
import type { AppStatus, Control, EnvFileRef, InvitePreview, ServeStatus } from '../ipc/contract';
import { relayBlocked, relayPill, relayState } from '../lib/dash';
import { dropErrorKey } from '../lib/envimport';
import { hostPort } from '../lib/format';
import { offersListenOff, relayError } from '../lib/reasons';
import { useApp } from '../ui/context';
import { PassField } from '../ui/fields';
import { Callout } from '../ui/form';
import { AgentsPage } from './Agents';
import { ConfirmSheet } from './Confirm';
import { ConnectionsPage } from './Connections';
import {
  DashContext, passErrorKey, SheetHostContext, type DashApi, type Intent, type RelayApi, type RelayProblem, type SheetHost,
} from './context';
import { Home } from './Home';
import { KeysPage } from './Keys';
import { LogsPage } from './Logs';
import { pageMeta, PAGES, type PageId } from './pages';
import { turnOffListen } from './relay';
import { SettingsPage } from './Settings';
import { Sheet } from './Sheet';
import { TeamPage } from './Team';
import { PendingInviteOwner } from './pendingInvite';
import { watchRecords } from './watch';

export type { PageId } from './pages';

const SPHERE_PX = 30;          // radius of the parked sphere
const AUDIT_POLL_MS = 4000;    // usage records are read while the window is visible
const NO_CONTROL: Control = { stopped: false, restore_pending: false, incident_open: false };
type Incoming = { ref: string; preview: InvitePreview };

/** Dashboard shell: sidebar with the small sphere, menu, relay status and stop-all; a page area;
 *  a host for the pages' sheets. */
export function Dashboard({ initialStatus, startPage, incoming }: {
  initialStatus: AppStatus; startPage: PageId; incoming: Incoming | null;
}) {
  const { field, toast, announce, setPill } = useApp();
  const [page, setPage] = useState<PageId>(startPage);
  const [intent, setIntent] = useState<Intent | null>(startPage === 'team' ? 'invite' : null);
  const [serve, setServe] = useState<ServeStatus>(initialStatus.serve);
  const [control, setControl] = useState<Control>(initialStatus.control ?? NO_CONTROL);
  const [sheet, setSheet] = useState<'stop' | 'resume' | 'listenOff' | null>(null);
  const [busy, setBusy] = useState(false);
  const [pass, setPass] = useState('');
  const [passErr, setPassErr] = useState<CopyKey | null>(null);
  const [tick, setTick] = useState(0);
  const [activity, setActivity] = useState(0);
  const [invite, setInvite] = useState<Incoming | null>(null);
  const pendingInvite = useRef(new PendingInviteOwner((ref) => { void call('onetime_discard', { ref }).catch(() => undefined); }));
  const incomingOwnerAlive = useRef(true);
  useEffect(() => {
    incomingOwnerAlive.current = true;
    const owner = pendingInvite.current;
    return () => {
      incomingOwnerAlive.current = false;
      queueMicrotask(() => { if (!incomingOwnerAlive.current) owner.dispose(); });
    };
  }, []);
  const takeIncoming = () => {
    if (invite && pendingInvite.current.take(invite.ref)) setInvite(null);
  };
  const [envFile, setEnvFile] = useState<EnvFileRef | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const toastRef = useRef(toast);
  toastRef.current = toast;
  const [hostEl, setHostEl] = useState<HTMLDivElement | null>(null);
  const [holds, setHolds] = useState(0);
  const slot = useRef<HTMLDivElement>(null);
  const title = useRef<HTMLHeadingElement>(null);
  const passRef = useRef<HTMLInputElement>(null);
  const first = useRef(true);
  const blocked = relayBlocked(control);
  const blockedRef = useRef(blocked);
  blockedRef.current = blocked;
  const controlRef = useRef(control);
  controlRef.current = control;
  const lastIncoming = useRef<string | null>(null);

  // park the sphere in the sidebar header; it follows the slot when the window resizes
  useLayoutEffect(() => {
    const el = slot.current, host = el?.closest<HTMLElement>('.window');
    if (!el || !host) return;
    const place = () => {
      const r = el.getBoundingClientRect(), w = host.getBoundingClientRect();
      if (!w.width || !w.height) return;
      field.setMode('dash', {
        cx: (r.left + r.width / 2 - w.left) / w.width, cy: (r.top + r.height / 2 - w.top) / w.height,
        r: SPHERE_PX / w.height, mem: serve.running ? 1 : 0, peer: 0, agent: 0, svc: 0,
      });
    };
    place();
    if (typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver(place);
    ro.observe(host);
    return () => ro.disconnect();
  }, [field, serve.running]);

  // every request refused (stop-all, or a restore not yet acknowledged): the sphere stops turning
  // and cools to grey (DESIGN.md §3.2)
  useEffect(() => { field.setStopped(blocked); }, [field, blocked]);
  useEffect(() => () => field.setStopped(false), [field]);

  useEffect(() => { setPill(relayPill(serve, control)); }, [control, serve, setPill]);

  const refresh = useCallback(() => {
    call('app_status').then((s) => { setServe(s.serve); if (s.control) setControl(s.control); setTick((k) => k + 1); }, () => undefined);
  }, []);

  // core events: relay status (also when the relay exits on its own) and stop-all changes
  useEffect(() => {
    const offs: Array<() => void> = [];
    let dead = false;
    const keep = (p: Promise<() => void>) => p.then((un) => { if (dead) un(); else offs.push(un); }, () => undefined);
    keep(on('serve://status', (s) => setServe(s)));
    keep(on('control://changed', (c) => setControl(c)));
    // a .env file dropped anywhere on the window opens the import on the keys page
    keep(on('envfile://hover', (h) => setDragOver(h.over)));
    keep(on('envfile://dropped', (d) => {
      setDragOver(false);
      if (d.import_ref && d.name !== undefined) {
        setEnvFile({ import_ref: d.import_ref, name: d.name });
        setPage('keys');
        setIntent('import');
      } else {
        toastRef.current(t(dropErrorKey(d.error ?? '')), 'warn');
      }
    }));
    window.addEventListener('focus', refresh);
    return () => { dead = true; offs.forEach((f) => f()); window.removeEventListener('focus', refresh); };
  }, [refresh]);

  // usage records: read the tail while the window is visible; each new batch is one small ripple.
  // A batch can come with a stop, incident or restore hold the window did not make (the relay
  // opens an incident on its own): then everything is read again, as on focus.
  useEffect(() => {
    let dead = false;
    const watch = watchRecords({
      records: (n) => {
        if (!blockedRef.current) field.ripple(Math.min(0.12, 0.05 + 0.015 * n));
        setActivity((k) => k + 1);
      },
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
  }, [field, refresh]);

  // a zeropw://join link opened while the dashboard is up: the team page shows its preview
  useEffect(() => {
    if (!incoming || incoming.ref === lastIncoming.current) return;
    lastIncoming.current = incoming.ref;
    pendingInvite.current.replace(incoming.ref);
    setInvite(incoming);
    setPage('team');
    setIntent('join');
  }, [incoming]);

  // a page change moves focus to its title and announces it
  useEffect(() => {
    announce(t(pageMeta(page).label));
    if (first.current) { first.current = false; setTimeout(() => title.current?.focus({ preventScroll: true }), 400); return; }
    title.current?.focus({ preventScroll: true });
  }, [page, announce]);

  // the relay: a failed start is shown with its reason until the relay runs again or another
  // start from this window begins; while one runs the relay counts as busy
  const [relayRuns, setRelayRuns] = useState(0);
  const relayBusy = relayRuns > 0;
  const [relayProblem, setRelayProblem] = useState<RelayProblem | null>(null);
  useEffect(() => { if (serve.running) setRelayProblem(null); }, [serve.running]);
  const reportRelay = useCallback((e: unknown) => {
    const err = toIpcError(e);
    const p = relayError(err.reason, err.detail);
    setRelayProblem(p);
    toast(t(p.key, { reason: p.reason }), 'warn');
    announce(t(p.key, { reason: p.reason }));
  }, [toast, announce]);
  const runRelay = useCallback(async <T,>(task: () => Promise<T>): Promise<T> => {
    setRelayRuns((n) => n + 1); setRelayProblem(null);
    try { return await task(); } finally { setRelayRuns((n) => Math.max(0, n - 1)); }
  }, []);
  const startRelay = useCallback(async (): Promise<boolean> => {
    try {
      const s = await runRelay(() => call('serve_start'));
      setServe(s);
      if (!s.running) { reportRelay({ error: 'Unavailable', reason: 'serve_not_running' }); return false; }
      toast(t('toast.relay.on'));
      return true;
    } catch (e) {
      reportRelay(e);
      return false;
    }
  }, [runRelay, reportRelay, toast]);
  // other-device access: an address the relay cannot open keeps the whole relay off, so after a
  // start that failed on the team address (and only then) the relay status offers to turn that
  // access off; turning it off stops team changes from arriving, so it is confirmed first
  const [teamListen, setTeamListen] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    call('settings_get').then((s) => { if (live) setTeamListen(s.team_listen); }, () => undefined);
    return () => { live = false; };
  }, [tick, serve.running]);
  const offerListenOff = offersListenOff({ running: serve.running, busy: relayBusy, teamListen, problem: relayProblem });
  const listenOff = useCallback(async (): Promise<void> => {
    try {
      const s = await runRelay(turnOffListen);
      setTeamListen(null); setServe(s);
      if (!s.running) reportRelay({ error: 'Unavailable', reason: 'serve_not_running' });
      else toast(t('toast.listen.off'));
    } catch (e) {
      reportRelay(e);
    } finally { setTick((k) => k + 1); }
  }, [runRelay, reportRelay, toast]);
  const confirmListenOff = useCallback(() => setSheet('listenOff'), []);
  const relay: RelayApi = useMemo(
    () => ({ busy: relayBusy, problem: relayProblem, start: startRelay, run: runRelay, report: reportRelay, teamListen, offerListenOff, confirmListenOff }),
    [relayBusy, relayProblem, startRelay, runRelay, reportRelay, teamListen, offerListenOff, confirmListenOff],
  );

  const go = useCallback((p: PageId, i?: Intent) => { setPage(p); setIntent(i ?? null); }, []);
  const bump = useCallback(() => { refresh(); }, [refresh]);
  const dash: DashApi = useMemo(() => ({ go, tick, activity, bump, control, serve, setControl, setServe, relay }), [go, tick, activity, bump, control, serve, relay]);
  const sheetHost: SheetHost = useMemo(() => ({ el: hostEl, hold: (d) => setHolds((h) => Math.max(0, h + d)) }), [hostEl]);

  const closeSheet = useCallback(() => { setSheet(null); setPass(''); setPassErr(null); }, []);
  const clearIntent = useCallback(() => setIntent(null), []);

  const stopAll = async () => {
    setBusy(true);
    try {
      setControl(await call('stop_all'));
      toast(t('toast.stopped'));
      closeSheet();
    } catch {
      toast(t('error.generic'), 'warn');
    } finally { setBusy(false); }
  };

  const resume = async () => {
    if (!pass) { setPassErr('resume.err.empty'); passRef.current?.focus(); return; }
    setBusy(true);
    try {
      setControl(await call('resume', { admin_passphrase: pass }));
      toast(t('toast.resumed'));
      closeSheet();
    } catch (e) {
      // an open incident keeps everything stopped until it is closed (rust/src/policy.rs `resume`)
      setPassErr(toIpcError(e).reason === 'incident_open' ? 'resume.err.incident' : passErrorKey(e)); setPass('');
      passRef.current?.focus();
    } finally { setBusy(false); }
  };

  const meta = pageMeta(page);
  const relayNow = relayState(serve, control);
  const relayCls = 'relay' + (relayNow === 'off' ? '' : ' ' + relayNow);
  const relayText = t(relayNow === 'held' ? 'side.relay.held' : relayNow === 'stopped' ? 'side.relay.stopped' : relayNow === 'live' ? 'side.relay.on' : 'side.relay.off');
  const pageIntent = intent ?? undefined;

  return (
    <DashContext.Provider value={dash}>
      <SheetHostContext.Provider value={sheetHost}>
        <div className="dash" inert={holds > 0}>
          <aside className="sidebar">
            <div className="sphere-slot" ref={slot} role="img" aria-label={`${t('side.sphere.aria')} · ${relayText}`} />
            <nav className="side-nav" aria-label={t('nav.aria')}>
              <ul className="nav-list">
                {PAGES.map((p) => (
                  <li key={p.id}>
                    <button className="nav-item" type="button" aria-current={p.id === page ? 'page' : undefined} onClick={() => go(p.id)}>
                      <span className="px" aria-hidden="true" />{t(p.label)}
                    </button>
                  </li>
                ))}
              </ul>
            </nav>
            <div className="side-foot">
              <div className={relayCls}>
                <span className="dot" aria-hidden="true" /><span>{relayText}</span>
                {relayNow === 'live' && <span className="mono">{hostPort(serve.url)}</span>}
                {!serve.running && (
                  <button className="btn btn-text btn-sm relay-start" type="button" aria-busy={relayBusy || undefined} aria-describedby={relayProblem ? 'side-relay-err' : undefined}
                    onClick={() => { if (!relayBusy) void startRelay(); }}>{t(relayProblem ? 'relay.retry' : 'relay.start')}</button>
                )}
              </div>
              {!serve.running && relayProblem && (
                <div className="help err side-err" id="side-relay-err">{t(relayProblem.key, { reason: relayProblem.reason })}</div>
              )}
              {relayNow === 'held' && (
                <button className="btn btn-text btn-sm side-ack" type="button" onClick={() => go('settings', 'ack-restore')}>{t('side.ack')}</button>
              )}
              {offerListenOff && (
                <button className="btn btn-text btn-sm side-listen-off" type="button" onClick={confirmListenOff}>{t('relay.team.off')}</button>
              )}
              {control.stopped
                ? <button className="btn btn-ghost btn-sm" type="button" onClick={() => setSheet('resume')}>{t('side.resume')}</button>
                : <button className="btn btn-ghost btn-sm" type="button" onClick={() => setSheet('stop')}>{t('side.stop')}</button>}
            </div>
          </aside>
          <div className="dash-main">
            <div className="page" key={page}>
              <header className="page-head">
                <h1 tabIndex={-1} ref={title}>{t(meta.label)}</h1>
                <p>{t(meta.sub)}</p>
              </header>
              {page === 'home' && <Home />}
              {page === 'keys' && <KeysPage intent={pageIntent} onIntent={clearIntent} incomingFile={envFile} onFileTaken={() => setEnvFile(null)} />}
              {page === 'connections' && <ConnectionsPage intent={pageIntent} onIntent={clearIntent} />}
              {page === 'agents' && <AgentsPage intent={pageIntent} onIntent={clearIntent} />}
              {page === 'logs' && <LogsPage intent={pageIntent} onIntent={clearIntent} />}
              {page === 'team' && <TeamPage intent={pageIntent} onIntent={clearIntent} incoming={invite} onIncomingTaken={takeIncoming} />}
              {page === 'settings' && <SettingsPage intent={pageIntent} onIntent={clearIntent} />}
            </div>
          </div>
        </div>
        <div className="sheet-host" ref={setHostEl} />
        {dragOver && (
          <div className="drop-zone" aria-hidden="true">
            <div className="drop-card"><span className="px" /><strong>{t('drop.title')}</strong><span>{t('drop.sub')}</span></div>
          </div>
        )}

        <Sheet id="sheet-stop" open={sheet === 'stop'} title={t('stop.title')} lead={t('stop.sub')}
          primaryLabel={t('stop.confirm')} busy={busy} onPrimary={() => void stopAll()} onClose={closeSheet}>
          <Callout kind="info">{t('session.note')}</Callout>
        </Sheet>
        <Sheet id="sheet-resume" open={sheet === 'resume'} title={t('resume.title')} lead={t('resume.sub')}
          primaryLabel={t('resume.confirm')} busy={busy} onPrimary={() => void resume()} onClose={closeSheet}>
          <PassField id="resume-pass" value={pass} inputRef={passRef} label={t('resume.field')}
            onChange={(v) => { setPass(v); setPassErr(null); }} error={passErr ? t(passErr) : null} />
        </Sheet>
        <ConfirmSheet id="sheet-listen-off" open={sheet === 'listenOff'} title={t('relay.team.off')} lead={t('listen.off.sub')}
          confirmLabel={t('listen.off.confirm')} chips={teamListen ? [teamListen] : undefined} info={t('listen.off.note')} onClose={closeSheet}
          run={async () => { await listenOff(); closeSheet(); }} />
      </SheetHostContext.Provider>
    </DashContext.Provider>
  );
}
