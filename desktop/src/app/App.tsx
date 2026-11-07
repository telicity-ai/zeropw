// The window: boot, first run, lock screen and the open vault. An existing vault always opens
// locked; it locks again on ⌘L, from the sidebar, or after IDLE_LOCK_MIN minutes without input.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { resolveLocale, setLocale, t, type CopyKey, type Locale } from '../copy';
import { call, inDesktop, on, toIpcError } from '../ipc/client';
import type { AppStatus, Control, InvitePreview } from '../ipc/contract';
import { AppContext, type AppApi, type ToastTone } from '../ui/app';
import { Button } from '../ui/controls';
import { Spinner } from '../ui/feedback';
import { Onboarding } from '../screens/onboarding/Onboarding';
import { LockScreen } from './LockScreen';
import { Shell } from './OpenVault';
import { IDLE_LOCK_MIN, type Route } from './shell';

export { IDLE_LOCK_MIN };

type Phase = 'loading' | 'failed' | 'onboarding' | 'locked' | 'open';
const TOAST_MS = 4200;

interface ToastItem { id: number; msg: string; tone: ToastTone }

export function App() {
  const [desktop] = useState(inDesktop);
  const [phase, setPhase] = useState<Phase>('loading');
  const [failure, setFailure] = useState<CopyKey>('boot.failed');
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [route, setRoute] = useState<Route>({ page: 'vault', view: 'all' });
  const [incoming, setIncoming] = useState<{ ref: string; preview: InvitePreview } | null>(null);
  const systemLanguages = (): readonly string[] => (typeof navigator !== 'undefined' ? (navigator.languages?.length ? navigator.languages : [navigator.language]) : []);
  const [language, setLanguagePref] = useState<Locale | 'system'>('system');
  const [locale, setLocaleState] = useState<Locale>(() => { const l = resolveLocale(null, systemLanguages()); setLocale(l); return l; });
  const applyLanguage = useCallback((pref: Locale | 'system') => {
    const l = resolveLocale(pref === 'system' ? null : pref, systemLanguages());
    setLocale(l);
    setLanguagePref(pref);
    setLocaleState(l);
  }, []);
  // the saved language (settings.json); an unreadable file keeps the system language
  useEffect(() => {
    call('settings_get').then((s) => applyLanguage(s.language ?? 'system'), () => undefined);
  }, [applyLanguage]);
  const setLanguage = useCallback(async (pref: Locale | 'system') => {
    const s = await call('settings_get');
    await call('settings_set', { ...s, language: pref === 'system' ? null : pref });
    applyLanguage(pref);
  }, [applyLanguage]);

  useEffect(() => {
    if (language !== 'system') return;
    const update = () => applyLanguage('system');
    window.addEventListener('languagechange', update);
    return () => window.removeEventListener('languagechange', update);
  }, [language, applyLanguage]);

  // toasts
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const nextId = useRef(1);
  const toast = useCallback((msg: string, tone: ToastTone = 'info') => {
    const id = nextId.current++;
    setToasts((ts) => [...ts.slice(-2), { id, msg, tone }]);
    setTimeout(() => setToasts((ts) => ts.filter((x) => x.id !== id)), TOAST_MS);
  }, []);

  // live region: bursts are joined
  const [live, setLive] = useState('');
  const annQ = useRef<string[]>([]);
  const annT = useRef<ReturnType<typeof setTimeout> | null>(null);
  const announce = useCallback((msg: string) => {
    if (!msg) return;
    annQ.current.push(msg);
    if (annT.current) clearTimeout(annT.current);
    annT.current = setTimeout(() => { setLive(annQ.current.join(' · ')); annQ.current = []; }, 60);
  }, []);

  // macOS vibrancy (tauri.conf.json windowEffects): the page lets the sidebar material show
  useEffect(() => {
    const mac = typeof navigator !== 'undefined' && /Mac/.test(navigator.platform || navigator.userAgent);
    if (desktop && mac) document.documentElement.classList.add('has-vibrancy');
  }, [desktop]);

  const boot = useCallback(() => {
    setPhase('loading');
    call('app_status').then(
      (s) => {
        setStatus(s);
        // review aid for the Vite dev server only (mock core): `?state=ready&open=devices` skips the
        // lock screen and opens a page. Never in the app (desktop) or a production build.
        const review = !desktop && import.meta.env.DEV && typeof location !== 'undefined' ? new URLSearchParams(location.search) : null;
        const open = review?.get('open');
        if (s.initialized && open) {
          setRoute({ page: (['vault', 'devices', 'services', 'developer', 'activity', 'settings'].includes(open) ? open : 'vault') as Route['page'], view: review?.get('view') ?? undefined });
          setPhase('open');
          return;
        }
        setPhase(s.initialized ? 'locked' : 'onboarding');
      },
      (e) => { setFailure(toIpcError(e).reason === 'kms_missing' ? 'boot.failed.kms' : 'boot.failed'); setPhase('failed'); },
    );
  }, [desktop]);
  useEffect(boot, [boot]);

  // zeropw://join links opened outside the app: only {ref, preview} arrive; joining needs a click
  useEffect(() => {
    let off: (() => void) | null = null, dead = false;
    on('invite://preview', (p) => setIncoming({ ref: p.ref, preview: p.preview }))
      .then((un) => { if (dead) un(); else off = un; }, () => undefined);
    return () => { dead = true; off?.(); };
  }, []);

  const lock = useCallback(() => {
    setPhase((p) => (p === 'open' ? 'locked' : p));
  }, []);
  const lockedOnce = useRef(false);
  useEffect(() => {
    if (phase === 'locked' && lockedOnce.current) { toast(t('toast.locked')); announce(t('toast.locked')); }
    if (phase === 'locked') lockedOnce.current = true;
  }, [phase, toast, announce]);

  // idle lock: any key, click or pointer movement in the window counts as use
  useEffect(() => {
    if (phase !== 'open') return;
    let last = Date.now();
    const touch = () => { last = Date.now(); };
    const evs = ['keydown', 'mousedown', 'pointermove', 'wheel'] as const;
    evs.forEach((e) => window.addEventListener(e, touch, { passive: true }));
    const id = setInterval(() => { if (Date.now() - last > IDLE_LOCK_MIN * 60_000) lock(); }, 15_000);
    return () => { evs.forEach((e) => window.removeEventListener(e, touch)); clearInterval(id); };
  }, [phase, lock]);

  const unlocked = useCallback((control: Control) => {
    call('app_status').then((s) => { setStatus(s); setPhase('open'); }, () => {
      setStatus((s) => (s ? { ...s, control } : s));
      setPhase('open');
    });
  }, []);

  const finishOnboarding = useCallback((r: Route) => {
    setRoute(r);
    call('app_status').then((s) => { setStatus(s); setPhase('open'); }, () => boot());
  }, [boot]);

  const takeIncoming = useCallback(() => setIncoming(null), []);
  const api: AppApi = useMemo(() => ({ desktop, toast, announce, locale, language, setLanguage }), [desktop, toast, announce, locale, language, setLanguage]);

  return (
    <AppContext.Provider value={api}>
      {phase !== 'open' && <div className="drag-strip" data-tauri-drag-region="" />}
      {phase === 'loading' && <div className="app-boot" role="status"><div><Spinner />{t('boot.loading')}</div></div>}
      {phase === 'failed' && (
        <div className="app-boot" role="alert">
          <div><p>{t(failure)}</p><Button tone="secondary" icon="refresh" onClick={boot}>{t('act.retry')}</Button></div>
        </div>
      )}
      {phase === 'onboarding' && (
        <Onboarding incoming={incoming} onIncomingTaken={() => setIncoming(null)} onFinish={finishOnboarding} />
      )}
      {phase === 'locked' && <LockScreen onUnlocked={unlocked} />}
      {phase === 'open' && status && (
        <Shell initialStatus={status} initialRoute={route} onRoute={setRoute} onLock={lock} incoming={incoming} onIncomingTaken={takeIncoming} />
      )}
      {!desktop && <div className="dev-tag" aria-hidden="true">{t('dev.mock')}</div>}
      <div className="sr-only" role="status" aria-live="polite">{live}</div>
      <div className="toasts" aria-live="polite">
        {toasts.map((x) => <div key={x.id} className={'toast is-' + x.tone} role="status"><i aria-hidden="true" /><span>{x.msg}</span></div>)}
      </div>
    </AppContext.Provider>
  );
}
