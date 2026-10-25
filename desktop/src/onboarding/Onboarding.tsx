import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { t, type CopyKey } from '../copy';
import { call, IpcError, toIpcError } from '../ipc/client';
import type { InvitePreview, Project } from '../ipc/contract';
import type { PageId } from '../dashboard/Dashboard';
import { hostPort } from '../lib/format';
import { finaleJoinErrorKey } from '../lib/reasons';
import { useApp } from '../ui/context';
import { AdminStep } from './AdminStep';
import { CreateStep } from './CreateStep';
import { Finale, type JoinOutcome } from './Finale';
import { afterRelayFailure, counted, fieldExtras, isCard, neighbour, progressOf, TITLE, type Step } from './flow';
import { JoinStep, type JoinPlan } from './JoinStep';
import { ProjectStep } from './ProjectStep';
import { RecoveryStep } from './RecoveryStep';
import { createVault, type InitAttempts, type InitFailure, type RecoveryChoice } from './vault';
import { Welcome } from './Welcome';
import type { FrameState } from './StepFrame';

const FOCUSABLE = '.step-body input:not([type=checkbox]):not([type=radio]), .step-body select';
const visible = (el: HTMLElement) => (typeof el.checkVisibility === 'function' ? el.checkVisibility() : !!el.offsetParent);

/** First-run onboarding (mockup v0.5): welcome → admin passphrase → recovery code → create vault →
 *  project → done (agent setup is available from the dashboard); or welcome → join → admin → recovery → create → done. */
export function Onboarding({ onFlowChange, onFinish, incoming, onIncomingTaken }: {
  onFlowChange(inFlow: boolean): void; onFinish(page: PageId): void;
  incoming: { ref: string; preview: InvitePreview } | null; onIncomingTaken(): void;
}) {
  const { field, announce, toast, setPill } = useApp();
  const [step, setStep] = useState<Step>('welcome');
  const [shown, setShown] = useState<Step | null>(null);
  const [leaving, setLeaving] = useState<Step | null>(null);
  const [late, setLate] = useState(false);
  const stepRef = useRef<Step>('welcome');
  const pendingFocus = useRef<Step | null>(null);
  const sections = useRef<Partial<Record<Step, HTMLElement | null>>>({});
  const startBtn = useRef<HTMLButtonElement>(null);
  const doneTitle = useRef<HTMLHeadingElement>(null);

  // secrets typed during onboarding stay here only until `vault_init` succeeds
  const secrets = useRef<{ admin: string; recovery: RecoveryChoice | null }>({ admin: '', recovery: null });
  const [adminForCheck, setAdminForCheck] = useState('');
  const [adminKey, setAdminKey] = useState(0);
  const [recoveryKey, setRecoveryKey] = useState(0);
  const [created, setCreated] = useState(false);
  const [project, setProject] = useState<Project | null>(null);
  const [join, setJoin] = useState<JoinPlan | null>(null);
  const joinRef = useRef<JoinPlan | null>(null);
  const [joinOutcome, setJoinOutcome] = useState<JoinOutcome>('idle');
  const [joinError, setJoinError] = useState<CopyKey | null>(null);
  const [recNotice, setRecNotice] = useState<CopyKey | null>(null);
  const attempts = useRef<InitAttempts>({ unsure: false });
  const [deepLink, setDeepLink] = useState<{ ref: string; preview: InvitePreview } | null>(null);
  const lastProgress = useRef<{ index: number; total: number } | null>(null);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);
  const later = (fn: () => void, ms: number) => { timers.current.push(setTimeout(fn, ms)); };

  const go = useCallback((to: Step) => {
    const from = stepRef.current;
    stepRef.current = to;
    setStep(to);
    if (to === 'welcome' && joinRef.current) {
      call('onetime_discard', { ref: joinRef.current.ref }).catch(() => undefined);
      joinRef.current = null; setJoin(null);
    }
    const joining = !!joinRef.current;
    const pr = progressOf(to, joining);
    onFlowChange(pr !== null);
    // a teammate is drawn as a ghost until this device has actually joined (DESIGN.md §3.2)
    field.setPeerGhost(!(to === 'done' && joining));
    field.setMode(to, fieldExtras(to, { joining }));
    const card = isCard(to), cardBefore = from !== to && isCard(from), lateNow = card && (from === 'welcome' || from === 'done');
    setLate(lateNow);
    if (cardBefore) {
      setLeaving(from);
      later(() => setLeaving((l) => (l === from ? null : l)), 380);
    }
    setShown(null);
    announce(pr ? `${pr.index + 1}/${pr.total} · ${t(TITLE[to as Exclude<Step, 'welcome'>])}` : to !== 'welcome' ? t(TITLE[to]) : '');
    if (card) {
      later(() => {
        if (stepRef.current !== to) return;   // the user already moved on
        pendingFocus.current = to;
        setShown(to);
      }, (cardBefore ? 160 : 280) + (lateNow ? 250 : 0));
    }
    if (to === 'welcome') later(() => startBtn.current?.focus({ preventScroll: true }), 300);
    if (to === 'done') later(() => doneTitle.current?.focus({ preventScroll: true }), 400);
  }, [announce, field, onFlowChange]);

  // focus the first field (or the title) once the new step is visible
  useLayoutEffect(() => {
    const s = shown;
    if (!s || pendingFocus.current !== s) return;
    pendingFocus.current = null;
    const sec = sections.current[s];
    if (!sec) return;
    const h2 = sec.querySelector<HTMLElement>('h2');
    if (sec.querySelector('[data-focus-title]')) { h2?.focus({ preventScroll: true }); return; }
    const first = [...sec.querySelectorAll<HTMLElement>(FOCUSABLE)].find((el) => !(el as HTMLInputElement).disabled && visible(el));
    (first ?? h2)?.focus({ preventScroll: true });
  }, [shown]);

  // boot
  useEffect(() => {
    onFlowChange(false);
    field.setPeerGhost(true);
    field.setMode('welcome');
    later(() => field.intro(), 120);
    later(() => startBtn.current?.focus({ preventScroll: true }), 300);
    const tm = timers.current;
    return () => { tm.forEach(clearTimeout); };
  }, []); // mount only

  // Enter advances from text fields only, never while composing Hangul
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Enter' || e.isComposing || e.keyCode === 229) return;
      const tgt = e.target;
      if (!(tgt instanceof HTMLInputElement) || /^(checkbox|radio)$/.test(tgt.type)) return;
      const s = stepRef.current;
      if (s === 'join') return;
      const btn = s === 'welcome' ? startBtn.current : sections.current[s]?.querySelector<HTMLButtonElement>('.nav .btn-primary');
      if (btn) { e.preventDefault(); btn.click(); }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);

  // a zeropw://join link opened before the vault exists fills the join screen
  useEffect(() => {
    if (!incoming || created) return;
    const s = stepRef.current;
    if (s !== 'welcome' && s !== 'join') return;
    setDeepLink(incoming);
    onIncomingTaken();
    if (s !== 'join') { field.chipText('peer', t('join.pv.picture')); go('join'); }
  }, [incoming, created, go, onIncomingTaken, field]);

  // ---- vault creation (the only place the two secrets cross into the core). A vault that exists
  // (even when the relay failed right after `init`) is never created again; see ./vault.ts.
  const initVault = useCallback(async () => {
    await createVault(secrets.current, attempts.current);
    secrets.current = { admin: '', recovery: null };
    setAdminForCheck('');
    setAdminKey((k) => k + 1); setRecoveryKey((k) => k + 1);   // drop the typed values with their steps
  }, []);

  // the recovery code has to change: back to its step, with the reason on screen
  const onRecoveryProblem = useCallback((kind: Extract<InitFailure, 'recovery_expired' | 'recovery_weak'>) => {
    secrets.current.recovery = null;
    if (kind === 'recovery_expired') { setRecoveryKey((k) => k + 1); setRecNotice('rec.expired'); }
    else setRecNotice('rec.own.weak');
    go('recovery');
  }, [go]);

  const startRelay = useCallback(async () => {
    let s = await call('serve_status');
    if (!s.running) s = await call('serve_start');
    if (!s.running) throw new IpcError({ error: 'Unavailable', reason: 'serve_not_running' });
    const addr = hostPort(s.url);
    setPill({ kind: 'live', addr });
    return addr;
  }, [setPill]);

  // the vault exists but the relay would not start (a port another program holds): go on without
  // it; a join still happens on the finale, otherwise the dashboard has the start button and port
  const skipRelay = useCallback(() => {
    setCreated(true);
    setPill({ kind: 'off' });
    if (afterRelayFailure(!!joinRef.current) === 'done') go('done');
    else onFinish('home');
  }, [go, onFinish, setPill]);

  // ---- joining happens on the finale, after the vault exists
  useEffect(() => {
    if (step !== 'done' || !join || joinOutcome !== 'idle') return;
    setJoinOutcome('pending');
    call('team_join', { ref: join.ref, project: join.project, environment: join.environment }).then(
      () => { setJoinOutcome('ok'); field.ripple(0.08); },
      (e) => {
        // a preview older than 60 minutes is gone from the core although the invite may be valid
        const key = finaleJoinErrorKey(toIpcError(e).reason);
        setJoinOutcome('failed'); setJoinError(key); field.setPeerGhost(true);
        toast(t(key), 'warn');
      },
    );
  }, [step, join, joinOutcome, field, toast]);

  const frame = (s: Step): FrameState => ({ active: step === s, cls: shown === s ? 'in' : leaving === s ? 'out' : '' });
  const secRef = (s: Step) => (el: HTMLElement | null) => { sections.current[s] = el; };
  const joining = !!join;
  const pr = progressOf(step, joining);
  if (pr) lastProgress.current = pr;
  const bar = lastProgress.current;
  const segs = counted(joining).length;
  const showCard = isCard(step);
  const back = (s: Step) => () => go(neighbour(s, joining, -1));

  return (
    <>
      <div className="progress" aria-hidden="true">
        <div className="segs">
          {Array.from({ length: segs }, (_, k) => (
            <div key={k} className={'seg' + (pr && k < pr.index ? ' past' : '') + (pr && k === pr.index ? ' cur' : '')} />
          ))}
        </div>
        <div className="plabel">{bar && <><b>{bar.index + 1}</b> / {bar.total}</>}</div>
      </div>
      <main>
        <Welcome visible={step === 'welcome'} startRef={startBtn}
          onStart={() => go('admin')}
          onJoin={() => { field.chipText('peer', t('join.pv.picture')); go('join'); }} />

        <div className={'card-wrap' + (showCard ? '' : ' away') + (late ? ' late' : '')} inert={!showCard}>
          <div className="card">
            <AdminStep key={`a${adminKey}`} frame={frame('admin')} sectionRef={secRef('admin')} onBack={back('admin')}
              onNext={(pass) => { secrets.current.admin = pass; setAdminForCheck(pass); go('recovery'); }} />
            <RecoveryStep key={`r${recoveryKey}`} frame={frame('recovery')} sectionRef={secRef('recovery')} admin={adminForCheck} notice={recNotice}
              onBack={back('recovery')} onNext={(choice) => { secrets.current.recovery = choice; setRecNotice(null); go('create'); }} />
            <CreateStep frame={frame('create')} sectionRef={secRef('create')} created={created}
              initVault={initVault} startRelay={startRelay} onCreated={() => setCreated(true)} onRecoveryProblem={onRecoveryProblem}
              onSkipRelay={skipRelay}
              onBack={() => go('recovery')} onNext={() => go(joinRef.current ? 'done' : 'project')} />
            <ProjectStep frame={frame('project')} sectionRef={secRef('project')} created={project} onBack={back('project')}
              onNext={(p) => { setProject(p); field.ripple(0.06); go('done'); }} />
            <JoinStep frame={frame('join')} sectionRef={secRef('join')} incoming={deepLink}
              onBack={() => { setDeepLink(null); go('welcome'); }}
              onNext={(plan) => {
                joinRef.current = plan; setJoin(plan); setDeepLink(null);
                field.chipText('peer', `${t('join.pv.picture')} · ${plan.preview.inviter.slice(0, 4)}`);
                go('admin'); toast(t('toast.join.later'));
              }} />
          </div>
        </div>

        <Finale visible={step === 'done'} titleRef={doneTitle} project={project} agent={null}
          join={join ? { preview: join.preview, local: join.local } : null} joinOutcome={joinOutcome} joinError={joinError}
          onDashboard={() => onFinish('home')} onInvite={() => onFinish('team')} />
      </main>
    </>
  );
}
