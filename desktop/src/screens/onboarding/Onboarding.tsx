// First run: welcome → administrator passphrase → recovery code → vault creation → first steps.
// Both paths create this Mac's own local vault; the connect path then opens joining with a code
// from the other Mac. The passphrase and the recovery choice live in a ref only until `vault_init`
// succeeds, then they are wiped and the steps that held them unmount.

import { useCallback, useEffect, useRef, useState } from 'react';
import { t } from '../../copy';
import type { Route } from '../../app/shell';
import type { InvitePreview } from '../../ipc/contract';
import { useApp } from '../../ui/app';
import { Button } from '../../ui/controls';
import { Banner } from '../../ui/feedback';
import { Icon, Mark } from '../../ui/icons';
import { canGoBack, COUNTED, doneActions, neighbour, progressOf, STEP_TITLE, type Path, type Step } from './flow';
import { AdminStep, CreateStep, RecoveryStep, StepCard, type CreateResult, type RecoveryNotice } from './steps';
import type { InitAttempts, RecoveryChoice } from './vault';

export function Onboarding({ incoming, onFinish }: {
  incoming: { ref: string; preview: InvitePreview } | null;
  /** The open vault adopts an invite link; the first run only mentions it. */
  onIncomingTaken(): void;
  onFinish(r: Route): void;
}) {
  const { announce } = useApp();
  const [step, setStep] = useState<Step>('welcome');
  const [path, setPath] = useState<Path>('new');
  const [created, setCreated] = useState(false);
  const [admin, setAdmin] = useState('');
  const [notice, setNotice] = useState<RecoveryNotice | null>(null);
  const [createKey, setCreateKey] = useState(0);
  const [result, setResult] = useState<CreateResult | null>(null);
  const secrets = useRef<{ admin: string; recovery: RecoveryChoice | null }>({ admin: '', recovery: null });
  const attempts = useRef<InitAttempts>({ unsure: false });
  const host = useRef<HTMLDivElement>(null);
  const first = useRef(true);

  // each step change moves focus to its first field (or its heading) and is announced
  useEffect(() => {
    const p = progressOf(step);
    const title = step === 'welcome' ? t('setup.welcome.title') : step === 'done' ? t('setup.done.title') : t(STEP_TITLE[step]);
    if (!first.current) announce(p ? t('setup.progress', { n: p.index + 1, total: p.total, title }) : title);
    first.current = false;
    const id = setTimeout(() => {
      const box = host.current?.querySelector<HTMLElement>(`[data-step="${step}"]`);
      const target = box?.querySelector<HTMLElement>('[data-step-focus]') ?? box?.querySelector<HTMLElement>('[data-step-title]');
      target?.focus({ preventScroll: true });
    }, 40);
    return () => clearTimeout(id);
  }, [step, announce]);

  const back = useCallback(() => {
    if (!canGoBack(step, created)) return;
    setStep((s) => neighbour(s, -1));
  }, [step, created]);

  const start = (p: Path) => { setPath(p); setStep('admin'); };

  const adminDone = (pass: string) => { secrets.current.admin = pass; setAdmin(pass); setStep('recovery'); };
  const recoveryDone = (choice: RecoveryChoice) => { secrets.current.recovery = choice; setCreateKey((k) => k + 1); setStep('create'); };

  const onCreated = useCallback(() => {
    // the vault uses them now; nothing here keeps them
    secrets.current = { admin: '', recovery: null };
    setAdmin('');
    setCreated(true);
  }, []);
  const onRecoveryProblem = useCallback((kind: 'recovery_expired' | 'recovery_weak') => {
    secrets.current.recovery = null;
    setNotice((n) => ({ key: kind === 'recovery_expired' ? 'setup.rec.expired' : 'setup.rec.weak', n: (n?.n ?? 0) + 1 }));
    setStep('recovery');
  }, []);
  const getSecrets = useCallback(() => secrets.current, []);

  const p = progressOf(step);
  return (
    <div className="setup" ref={host} aria-label={t('setup.aria')} role="main">
      <div className="setup-card">
        <header className="setup-head" data-tauri-drag-region="">
          <span className="setup-brand"><Mark size={20} /><span>{t('app.name')}</span></span>
          {(p || step === 'done') && (
            <ol className="setup-steps" aria-label={t('setup.aria')}>
              {COUNTED.map((s, i) => {
                const doneHere = step === 'done' || (p !== null && i < p.index);
                return (
                  <li key={s} aria-current={p?.index === i ? 'step' : undefined} data-done={doneHere ? '' : undefined}>
                    <span className="setup-step-dot" aria-hidden="true">{doneHere ? <Icon name="check" size={10} /> : i + 1}</span>
                    <span className="setup-step-label">{t(STEP_TITLE[s as 'admin' | 'recovery' | 'create'])}</span>
                  </li>
                );
              })}
            </ol>
          )}
        </header>

        {step === 'welcome' && (
          <div className="setup-step" data-step="welcome">
            <div className="setup-step-head">
              <h1 className="setup-title" tabIndex={-1} data-step-title="">{t('setup.welcome.title')}</h1>
              <p className="setup-sub">{t('setup.welcome.sub')}</p>
            </div>
            <div className="setup-choices">
              <button type="button" className="setup-choice" data-step-focus="" onClick={() => start('new')}>
                <span className="tile tile-service" aria-hidden="true"><Icon name="vault" /></span>
                <span className="setup-choice-text"><strong>{t('setup.welcome.new')}</strong><span>{t('setup.welcome.new.sub')}</span></span>
                <Icon name="chevron-right" />
              </button>
              <button type="button" className="setup-choice" onClick={() => start('connect')}>
                <span className="tile tile-device" aria-hidden="true"><Icon name="laptop" /></span>
                <span className="setup-choice-text"><strong>{t('setup.welcome.connect')}</strong><span>{t('setup.welcome.connect.sub')}</span></span>
                <Icon name="chevron-right" />
              </button>
            </div>
            {incoming && <Banner tone="accent" icon="link">{t('setup.incoming')}</Banner>}
          </div>
        )}

        {!created && (
          <div hidden={step !== 'admin'}>
            <AdminStep onBack={back} onNext={adminDone} />
          </div>
        )}
        {!created && (
          <div hidden={step !== 'recovery'}>
            <RecoveryStep active={step === 'recovery'} admin={admin} notice={notice} onBack={back} onNext={recoveryDone} />
          </div>
        )}
        {step === 'create' && (
          <CreateStep key={createKey} created={created} secrets={getSecrets} attempts={attempts.current} onCreated={onCreated}
            onRecoveryProblem={onRecoveryProblem} onBack={back} onDone={(r) => { setResult(r); setStep('done'); }} />
        )}

        {step === 'done' && (
          <StepCard name="done" title={t('setup.done.title')} sub={t(path === 'connect' ? 'setup.done.sub.connect' : 'setup.done.sub')}>
            {result && !result.serviceOn && <Banner tone="warn">{t('setup.done.serviceOff')}</Banner>}
            {incoming && <Banner tone="accent" icon="link">{t('setup.incoming')}</Banner>}
            <div className="setup-done-actions">
              {doneActions(path, !!incoming).map((a, i) => (
                <Button key={a.key} tone={a.tone} size={a.tone === 'ghost' ? 'md' : 'lg'} full={a.tone !== 'ghost'}
                  data-step-focus={i === 0 ? '' : undefined} onClick={() => onFinish(a.route)}>{t(a.key)}</Button>
              ))}
            </div>
            <p className="setup-note">{t('setup.done.backup')}</p>
          </StepCard>
        )}
      </div>
    </div>
  );
}
