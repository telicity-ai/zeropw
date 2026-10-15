import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { t } from '../copy';
import { call, on, toIpcError } from '../ipc/client';
import type { AppStatus, Control, InvitePreview, ServeStatus } from '../ipc/contract';
import { hostPort } from '../lib/format';
import { useApp } from '../ui/context';
import { Home } from './Home';
import { pageMeta, PAGES, type PageId } from './pages';
import { Sheet } from './Sheet';

export type { PageId } from './pages';

const SPHERE_PX = 30;   // radius of the parked sphere
const NO_CONTROL: Control = { stopped: false, restore_pending: false, incident_open: false };

/** Dashboard shell: sidebar with the small sphere, menu, relay status and stop-all; a page area. */
export function Dashboard({ initialStatus, startPage, incoming }: {
  initialStatus: AppStatus; startPage: PageId; incoming: { ref: string; preview: InvitePreview } | null;
}) {
  const { field, toast, announce, setPill } = useApp();
  const [page, setPage] = useState<PageId>(startPage);
  const [serve, setServe] = useState<ServeStatus>(initialStatus.serve);
  const [control, setControl] = useState<Control>(initialStatus.control ?? NO_CONTROL);
  const [sheet, setSheet] = useState<'stop' | 'resume' | null>(null);
  const [busy, setBusy] = useState(false);
  const [pass, setPass] = useState('');
  const [passErr, setPassErr] = useState<'error.auth' | 'resume.err.empty' | 'error.generic' | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const slot = useRef<HTMLDivElement>(null);
  const title = useRef<HTMLHeadingElement>(null);
  const first = useRef(true);

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

  useEffect(() => { field.setStopped(control.stopped); }, [field, control.stopped]);
  useEffect(() => () => field.setStopped(false), [field]);

  useEffect(() => {
    setPill(control.stopped ? { kind: 'stopped' } : serve.running ? { kind: 'live', addr: hostPort(serve.url) } : { kind: 'off' });
  }, [control.stopped, serve, setPill]);

  const refresh = useCallback(() => {
    call('app_status').then((s) => { setServe(s.serve); if (s.control) setControl(s.control); setRefreshKey((k) => k + 1); }, () => undefined);
  }, []);

  // core events: relay status, stop-all changes, a small ripple for each new usage record
  useEffect(() => {
    const offs: Array<() => void> = [];
    let dead = false;
    const keep = (p: Promise<() => void>) => p.then((un) => { if (dead) un(); else offs.push(un); }, () => undefined);
    keep(on('serve://status', (s) => setServe(s)));
    keep(on('control://changed', (c) => setControl(c)));
    keep(on('audit://records', () => field.ripple(0.06)));
    window.addEventListener('focus', refresh);
    return () => { dead = true; offs.forEach((f) => f()); window.removeEventListener('focus', refresh); };
  }, [field, refresh]);

  useEffect(() => { if (incoming) setPage('team'); }, [incoming]);

  // a page change moves focus to its title and announces it
  useEffect(() => {
    announce(t(pageMeta(page).label));
    if (first.current) { first.current = false; setTimeout(() => title.current?.focus({ preventScroll: true }), 400); return; }
    title.current?.focus({ preventScroll: true });
  }, [page, announce]);

  const closeSheet = useCallback(() => { setSheet(null); setPass(''); setPassErr(null); }, []);

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
    if (!pass) { setPassErr('resume.err.empty'); return; }
    setBusy(true);
    try {
      setControl(await call('resume', { admin_passphrase: pass }));
      toast(t('toast.resumed'));
      closeSheet();
    } catch (e) {
      setPassErr(toIpcError(e).error === 'AuthFailed' ? 'error.auth' : 'error.generic');
    } finally { setBusy(false); setPass(''); }
  };

  const meta = pageMeta(page);
  const relayCls = 'relay' + (control.stopped ? ' stopped' : serve.running ? ' live' : '');
  const relayText = control.stopped ? t('side.relay.stopped') : serve.running ? t('side.relay.on') : t('side.relay.off');

  return (
    <>
      <div className="dash" inert={sheet !== null}>
        <aside className="sidebar">
          <div className="sphere-slot" ref={slot} role="img" aria-label={`${t('side.sphere.aria')} · ${relayText}`} />
          <nav className="side-nav" aria-label={t('nav.aria')}>
            <ul className="nav-list">
              {PAGES.map((p) => (
                <li key={p.id}>
                  <button className="nav-item" type="button" aria-current={p.id === page ? 'page' : undefined} onClick={() => setPage(p.id)}>
                    <span className="px" aria-hidden="true" />{t(p.label)}
                  </button>
                </li>
              ))}
            </ul>
          </nav>
          <div className="side-foot">
            <div className={relayCls}>
              <span className="dot" aria-hidden="true" /><span>{relayText}</span>
              {serve.running && !control.stopped && <span className="mono">{hostPort(serve.url)}</span>}
            </div>
            {control.stopped
              ? <button className="btn btn-ghost btn-sm" type="button" onClick={() => setSheet('resume')}>{t('side.resume')}</button>
              : <button className="btn btn-ghost btn-sm" type="button" onClick={() => setSheet('stop')}>{t('side.stop')}</button>}
          </div>
        </aside>
        <div className="dash-main">
          <div className="page">
            <header className="page-head">
              <h1 tabIndex={-1} ref={title}>{t(meta.label)}</h1>
              <p>{t(meta.sub)}</p>
            </header>
            {page === 'home'
              ? <Home serve={serve} control={control} refreshKey={refreshKey} />
              : (
                <div className="glass" style={{ marginTop: 22 }}>
                  <div className="empty"><span className="line"><span className="px" aria-hidden="true" />{meta.empty ? t(meta.empty) : ''}</span></div>
                </div>
              )}
          </div>
        </div>
      </div>

      <Sheet id="sheet-stop" open={sheet === 'stop'} title={t('stop.title')} lead={t('stop.sub')}
        primaryLabel={t('stop.confirm')} busy={busy} onPrimary={() => void stopAll()} onClose={closeSheet} />
      <Sheet id="sheet-resume" open={sheet === 'resume'} title={t('resume.title')} lead={t('resume.sub')}
        primaryLabel={t('resume.confirm')} busy={busy} onPrimary={() => void resume()} onClose={closeSheet}>
        <div className="field">
          <div className="label"><label htmlFor="resume-pass">{t('resume.field')}</label></div>
          <div className="input" data-invalid={passErr ? '' : undefined}>
            <input type="password" id="resume-pass" value={pass} autoComplete="current-password" spellCheck={false}
              aria-invalid={passErr ? true : undefined} aria-describedby="resume-err"
              onChange={(e) => { setPass(e.target.value); setPassErr(null); }} />
          </div>
          <div className="help err" id="resume-err" hidden={!passErr} role="alert">{passErr ? t(passErr) : ''}</div>
        </div>
      </Sheet>
    </>
  );
}
