import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { t } from './copy';
import { Field } from './field/field';
import { FieldLayer } from './field/FieldLayer';
import { call, inDesktop, on } from './ipc/client';
import { hostPort } from './lib/format';
import type { AppStatus, InvitePreview } from './ipc/contract';
import { Onboarding } from './onboarding/Onboarding';
import { Dashboard, type PageId } from './dashboard/Dashboard';
import { Titlebar } from './Titlebar';
import { AppContext, type AppApi, type Pill, type ToastKind } from './ui/context';

type Phase = 'loading' | 'onboarding' | 'dashboard' | 'failed';
export interface IncomingInvite { ref: string; preview: InvitePreview }

function reducedMotion(): boolean {
  return typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
}

export function App() {
  const [desktop] = useState(inDesktop);
  // one Field for the app's lifetime (useState, not useMemo: a memo may be recomputed)
  const [field] = useState(() => new Field({ motion: !reducedMotion() }));
  const win = useRef<HTMLDivElement>(null);
  const [motionOn, setMotionOn] = useState(field.motionOn);
  const [phase, setPhase] = useState<Phase>('loading');
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [startPage, setStartPage] = useState<PageId>('home');
  const [inFlow, setInFlow] = useState(false);
  const [pill, setPill] = useState<Pill>({ kind: 'none' });
  const [incoming, setIncoming] = useState<IncomingInvite | null>(null);

  // toast
  const [toastState, setToastState] = useState<{ msg: string; kind: ToastKind; on: boolean }>({ msg: '', kind: 'info', on: false });
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const toast = useCallback((msg: string, kind: ToastKind = 'info') => {
    setToastState({ msg, kind, on: true });
    if (toastTimer.current) clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToastState((s) => ({ ...s, on: false })), 3600);
  }, []);

  // live region: bursts are joined, as in the mockup
  const [live, setLive] = useState('');
  const annQ = useRef<string[]>([]);
  const annT = useRef<ReturnType<typeof setTimeout> | null>(null);
  const announce = useCallback((msg: string) => {
    if (!msg) return;
    annQ.current.push(msg);
    if (annT.current) clearTimeout(annT.current);
    annT.current = setTimeout(() => { setLive(annQ.current.join(' · ')); annQ.current = []; }, 60);
  }, []);

  const setMotion = useCallback((on: boolean) => { field.setMotion(on); setMotionOn(on); }, [field]);
  useEffect(() => {
    if (typeof matchMedia !== 'function') return;
    const mq = matchMedia('(prefers-reduced-motion: reduce)');
    const fn = (e: MediaQueryListEvent) => setMotion(!e.matches);
    mq.addEventListener('change', fn);
    return () => mq.removeEventListener('change', fn);
  }, [setMotion]);

  const boot = useCallback(() => {
    setPhase('loading');
    call('app_status').then(
      (s) => {
        setStatus(s);
        if (s.initialized) {
          setPill(s.control?.stopped ? { kind: 'stopped' } : s.serve.running ? { kind: 'live', addr: hostPort(s.serve.url) } : { kind: 'off' });
          setPhase('dashboard');
        } else {
          setPhase('onboarding');
        }
      },
      () => setPhase('failed'),
    );
  }, []);
  useEffect(boot, [boot]);

  // deep link previews (zeropw://join#…): the core sends only {ref, preview}; joining needs a click
  useEffect(() => {
    let off: (() => void) | null = null, dead = false;
    on('invite://preview', (p) => {
      setIncoming({ ref: p.ref, preview: p.preview });
      setStartPage('team');
    }).then((un) => { if (dead) un(); else off = un; }, () => undefined);
    return () => { dead = true; off?.(); };
  }, []);

  const api: AppApi = useMemo(() => ({ field, desktop, motionOn, toast, announce, setPill }), [field, desktop, motionOn, toast, announce]);

  const finishOnboarding = useCallback((page: PageId) => {
    setStartPage(page);
    setInFlow(false);
    call('app_status').then((s) => setStatus(s), () => undefined).finally(() => setPhase('dashboard'));
  }, []);

  return (
    <AppContext.Provider value={api}>
      <div className={'window' + (motionOn ? '' : ' still')} ref={win} data-onboarding={inFlow ? '' : undefined}>
        <FieldLayer field={field} />
        <Titlebar desktop={desktop} motionOn={motionOn} onToggleMotion={() => setMotion(!motionOn)} pill={pill} />
        {phase === 'loading' && <div className="boot" role="status">{t('boot.loading')}</div>}
        {phase === 'failed' && (
          <div className="boot" role="alert">
            <div>
              <p>{t('boot.failed')}</p>
              <button className="btn btn-ghost btn-sm" type="button" onClick={boot}>{t('common.retry')}</button>
            </div>
          </div>
        )}
        {phase === 'onboarding' && (
          <Onboarding onFlowChange={setInFlow} onFinish={finishOnboarding} incoming={incoming} onIncomingTaken={() => setIncoming(null)} />
        )}
        {phase === 'dashboard' && status && (
          <Dashboard initialStatus={status} startPage={startPage} incoming={incoming} />
        )}
        {!desktop && <div className="mock-tag" aria-hidden="true">{t('dev.mock')}</div>}
        <div className="sr-only" role="status" aria-live="polite">{live}</div>
        <div className={'toast' + (toastState.on ? ' on' : '') + (toastState.kind === 'warn' ? ' warn' : '')} role="status" aria-live="polite">
          <i aria-hidden="true" /><span>{toastState.msg}</span>
        </div>
      </div>
    </AppContext.Provider>
  );
}
