import { useEffect, useRef, useState, type ChangeEvent, type Ref } from 'react';
import { t } from '../copy';
import { adminReady, adminRules, meterFraction } from '../lib/validators';
import { ri, useApp } from '../ui/context';
import { Meter, Rule } from '../ui/form';
import { BackButton, StepFrame, type FrameState } from './StepFrame';
import { reasonKey, useStrength } from './useStrength';

/** Step 1: admin passphrase. The value stays in this step until the vault is created. */
export function AdminStep({ frame, sectionRef, onBack, onNext }: {
  frame: FrameState; sectionRef: Ref<HTMLElement>; onBack(): void; onNext(pass: string): void;
}) {
  const { field } = useApp();
  const [pass, setPass] = useState('');
  const [pass2, setPass2] = useState('');
  const [show, setShow] = useState(false);
  const { score, reason } = useStrength(pass);
  const rules = adminRules(pass, pass2, score);
  const ok = adminReady(rules);
  const wasReady = useRef(false);
  const typed = useRef(false);
  const passRef = useRef<HTMLInputElement>(null);
  const pass2Ref = useRef<HTMLInputElement>(null);
  const rk = reasonKey(reason);

  // the sphere follows the passphrase strength; a pulse when every rule is met
  useEffect(() => {
    if (!frame.active) { typed.current = false; return; }
    field.setStrength(meterFraction(score));
    if (ok) field.set('coh', 1);
    if (ok && !wasReady.current && typed.current) field.pulse();
    wasReady.current = ok;
  }, [frame.active, score, ok, field]);

  const input = (set: (v: string) => void) => (e: ChangeEvent<HTMLInputElement>) => {
    typed.current = true; field.ripple(0.045); set(e.target.value);
  };

  const next = () => {
    if (!ok) { (rules.len && rules.strong ? pass2Ref.current : passRef.current)?.focus(); return; }
    onNext(pass);
  };

  return (
    <StepFrame name="admin" frame={frame} sectionRef={sectionRef} title={t('admin.title')} lead={t('admin.sub')}
      nav={<>
        <BackButton onClick={onBack} label={t('common.back')} />
        <button className="btn btn-primary" type="button" aria-disabled={!ok} aria-describedby="ob-admin-rules" onClick={next}>{t('common.next')}</button>
      </>}>
      <div className="field r" style={ri(2)}>
        <div className="label"><label htmlFor="ob-admin-pass">{t('admin.field')}</label></div>
        <div className="input">
          <input type={show ? 'text' : 'password'} id="ob-admin-pass" ref={passRef} value={pass} onChange={input(setPass)}
            autoComplete="new-password" spellCheck={false} aria-describedby="ob-admin-rules ob-admin-reason" />
          <span className="suffix">
            <button className="icon-btn" type="button" aria-pressed={show} aria-controls="ob-admin-pass" onClick={() => setShow(!show)}>{t('common.show')}</button>
          </span>
        </div>
        <Meter score={score} filled={!!pass} />
        <div className="reason" id="ob-admin-reason">{rk ? t(rk) : ''}</div>
      </div>
      <div className="field r" style={ri(3)}>
        <div className="label"><label htmlFor="ob-admin-pass2">{t('admin.confirm')}</label></div>
        <div className="input">
          <input type="password" id="ob-admin-pass2" ref={pass2Ref} value={pass2} onChange={input(setPass2)}
            autoComplete="new-password" spellCheck={false} aria-describedby="ob-rule-match" />
        </div>
      </div>
      <ul className="rules r" style={ri(4)} id="ob-admin-rules">
        <Rule ok={rules.len} label={t('admin.rule.len')} />
        <Rule id="ob-rule-match" ok={rules.match} label={t('admin.rule.match')} />
        <Rule ok={rules.strong} label={t('admin.rule.strong')} />
      </ul>
    </StepFrame>
  );
}
