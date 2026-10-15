import { useCallback, useEffect, useRef, useState, type ChangeEvent, type Ref } from 'react';
import { t, type CopyKey } from '../copy';
import { call } from '../ipc/client';
import {
  canonicalRecovery, meterFraction, normalizeGroup, pickVerifySlots, RECOVERY_GROUP_COUNT, recoveryOwnRules, recoveryRefStale, verifyRecoveryGroups,
  verifyStates,
} from '../lib/validators';
import { ri, useApp } from '../ui/context';
import { Callout, Meter, Rule } from '../ui/form';
import { useSecureGate } from '../ui/secure';
import { BackButton, StepFrame, type FrameState } from './StepFrame';
import { useStrength } from './useStrength';
import type { RecoveryChoice } from './vault';

export type { RecoveryChoice } from './vault';

/** Step 2: recovery code. The core generates it (120 bits, six groups) and keeps it behind a
 *  one-time reference for 10 minutes; the groups are painted only once screen-capture protection
 *  is on, then confirmed by typing two of them. `notice` explains why the user was sent back here
 *  (the code expired, or a chosen code is too close to the admin passphrase). */
export function RecoveryStep({ frame, sectionRef, admin, notice, onBack, onNext }: {
  frame: FrameState; sectionRef: Ref<HTMLElement>; admin: string; notice: CopyKey | null; onBack(): void; onNext(choice: RecoveryChoice): void;
}) {
  const { field, announce, toast } = useApp();
  const [groups, setGroups] = useState<string[]>([]);
  const [shownCount, setShownCount] = useState(0);
  const refRef = useRef<string | null>(null);
  const madeAt = useRef(0);
  const [own, setOwn] = useState(notice === 'rec.own.weak');
  const [code, setCode] = useState('');
  const [code2, setCode2] = useState('');
  const [ack, setAck] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [slots, setSlots] = useState<[number, number]>([0, 3]);
  const [v1, setV1] = useState('');
  const [v2, setV2] = useState('');
  const [tried, setTried] = useState(false);
  const [blurred, setBlurred] = useState(false);
  const [note, setNote] = useState<CopyKey | null>(notice);
  const busy = useRef(false);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);
  const ackRef = useRef<HTMLInputElement>(null);
  const codeRef = useRef<HTMLInputElement>(null);
  const code2Ref = useRef<HTMLInputElement>(null);
  const v1Ref = useRef<HTMLInputElement>(null);
  const v2Ref = useRef<HTMLInputElement>(null);
  const { score } = useStrength(own ? code : '');
  const ownRules = recoveryOwnRules(code, code2, admin, score);

  // the groups are a one-time value: they are painted only after the core has turned screen
  // capture protection on, and leave the screen before it is turned off again
  const showGroups = useSecureGate(frame.active && !own && groups.length > 0);

  const resetAck = useCallback(() => { setAck(false); setVerifying(false); setTried(false); }, []);

  const generate = useCallback(async () => {
    if (busy.current) return;
    busy.current = true;
    const old = refRef.current;
    refRef.current = null;
    if (old) call('onetime_discard', { ref: old }).catch(() => undefined);
    timers.current.forEach(clearTimeout); timers.current = [];
    try {
      const r = await call('recovery_generate');
      refRef.current = r.ref;
      madeAt.current = Date.now();
      setGroups(r.groups.slice(0, RECOVERY_GROUP_COUNT));
      setShownCount(0);
    } catch {
      setGroups([]);
      toast(t('error.generic'), 'warn');
    } finally {
      busy.current = false;
      resetAck();
    }
  }, [resetAck, toast]);

  // the staggered reveal starts when the groups are actually on screen
  useEffect(() => {
    if (!showGroups) return;
    timers.current.forEach(clearTimeout); timers.current = [];
    groups.forEach((_, k) => {
      timers.current.push(setTimeout(() => { setShownCount((c) => Math.max(c, k + 1)); field.ripple(0.03); }, 60 * k + 30));
    });
  }, [showGroups, groups, field]);

  useEffect(() => () => { timers.current.forEach(clearTimeout); }, []);

  // a new notice (sent back from vault creation) is shown; a weak chosen code is cleared
  useEffect(() => {
    setNote(notice);
    if (notice === 'rec.own.weak') { setOwn(true); setCode(''); setCode2(''); resetAck(); }
  }, [notice, resetAck]);

  // entering the step: make sure a code exists, ask for the confirmation again
  useEffect(() => {
    if (!frame.active) return;
    if (!own && !refRef.current) void generate();
    else resetAck();
    if (notice === 'rec.own.weak') setTimeout(() => codeRef.current?.focus(), 300);
  }, [frame.active]); // runs on the activation edge only

  // sphere: fully formed for a generated code, follows the strength of a chosen one
  useEffect(() => {
    if (frame.active) field.setStrength(own ? meterFraction(score) : 1);
  }, [frame.active, own, score, field]);

  // hide the groups while the window is in the background
  useEffect(() => {
    if (!frame.active) return;
    const blur = () => setBlurred(true);
    const focus = () => setBlurred(false);
    const vis = () => { if (document.hidden) setBlurred(true); };
    window.addEventListener('blur', blur); window.addEventListener('focus', focus);
    document.addEventListener('visibilitychange', vis);
    return () => { window.removeEventListener('blur', blur); window.removeEventListener('focus', focus); document.removeEventListener('visibilitychange', vis); };
  }, [frame.active]);

  const genOk = groups.length === RECOVERY_GROUP_COUNT && !!refRef.current;
  const ok = own ? ownRules.strong && ownRules.match : genOk;
  const verified = own ? ack : ack && verifyRecoveryGroups(groups, slots, [v1, v2]);
  const ready = ok && ack && verified;
  const vstate = verifyStates(groups, slots, [v1, v2]);
  const wasReady = useRef(false);
  useEffect(() => {
    if (ready && !wasReady.current && frame.active) field.pulse();
    wasReady.current = ready;
  }, [ready, frame.active, field]);

  const toggleOwn = () => {
    const next = !own;
    setOwn(next); setCode(''); setCode2(''); resetAck(); setNote(null);
    field.setStrength(next ? 0 : 1);
    if (next) setTimeout(() => codeRef.current?.focus(), 0);
    else if (!refRef.current) void generate();
  };

  const regen = () => { if (own) setOwn(false); setCode(''); setCode2(''); setNote(null); void generate(); field.setStrength(1); };

  const onAck = (e: ChangeEvent<HTMLInputElement>) => {
    const on = e.target.checked;
    setAck(on); setTried(false);
    if (on && !own) {
      const bytes = new Uint8Array(2);
      globalThis.crypto.getRandomValues(bytes);
      setSlots(pickVerifySlots(bytes)); setV1(''); setV2(''); setVerifying(true);
      announce(t('rec.verify'));
      setTimeout(() => v1Ref.current?.focus(), 50);
    } else {
      setVerifying(false);
    }
  };

  const ownInput = (set: (v: string) => void) => (e: ChangeEvent<HTMLInputElement>) => { field.ripple(0.04); set(e.target.value); resetAck(); };

  const next = () => {
    if (!ready) {
      if (!ack) { ackRef.current?.focus(); return; }
      if (own) { code2Ref.current?.focus(); return; }
      // say which group does not match, under its field, and go there
      setTried(true);
      (vstate[0] ? v1Ref : v2Ref).current?.focus();
      return;
    }
    if (own) {
      const old = refRef.current;
      refRef.current = null;
      if (old) call('onetime_discard', { ref: old }).catch(() => undefined);
      setNote(null);
      onNext({ typed: code });
    } else if (refRef.current) {
      // the core forgets the code after 10 minutes: make a new one now rather than fail later
      if (recoveryRefStale(madeAt.current, Date.now())) {
        setNote('rec.expired'); announce(t('rec.expired'));
        void generate();
        return;
      }
      setNote(null);
      onNext({ ref: refRef.current });
    }
  };

  const hide = verifying || blurred;
  const hint = own && ownRules.same ? t('rec.own.same') : own && ownRules.similar ? t('rec.own.similar') : '';
  const verifyErr = (i: 0 | 1): string | null => {
    const s = vstate[i];
    if (!tried || !s) return null;
    return t(s === 'empty' ? 'rec.verify.need' : 'rec.verify.err', { n: slots[i] + 1 });
  };

  return (
    <StepFrame name="recovery" frame={frame} sectionRef={sectionRef} title={t('rec.title')} lead={t('rec.sub')}
      nav={<>
        <BackButton onClick={onBack} label={t('common.back')} />
        <button className="btn btn-primary" type="button" aria-disabled={!ready} onClick={next}>
          <span>{t('rec.next')}</span> <span className="arrow" aria-hidden="true">→</span>
        </button>
      </>}>
      {note && <div className="help err" role="alert" style={{ margin: '0 0 12px' }}>{t(note)}</div>}
      <div className="r" style={ri(2)} data-focus-title={own ? undefined : ''}>
        {!own && (
          <div>
            <ol className={'groups' + (hide ? ' hide' : '')} aria-labelledby="t-recovery">
              {showGroups && groups.map((g, k) => (
                <li key={k} className={k < shownCount ? 'on' : undefined}><span aria-hidden="true">{k + 1}</span>{g}</li>
              ))}
            </ol>
            <div className={'canon' + (hide ? ' hide' : '')}><span>{t('rec.code.label')}</span><code>{showGroups && shownCount >= groups.length ? canonicalRecovery(groups) : ''}</code></div>
          </div>
        )}
        {own && (
          <div>
            <div className="field">
              <div className="label"><label htmlFor="ob-rec-pass">{t('rec.own.field')}</label><span className={'hint' + (hint ? ' err' : '')} id="ob-rec-hint">{hint}</span></div>
              <div className="input mono">
                <input type="password" id="ob-rec-pass" ref={codeRef} value={code} onChange={ownInput(setCode)} autoComplete="off" spellCheck={false} aria-describedby="ob-rec-hint ob-rule-rec-strong" />
              </div>
              <Meter score={score} filled={!!code} />
            </div>
            <div className="field">
              <div className="label"><label htmlFor="ob-rec-pass2">{t('admin.confirm')}</label></div>
              <div className="input mono">
                <input type="password" id="ob-rec-pass2" ref={code2Ref} value={code2} onChange={ownInput(setCode2)} autoComplete="off" spellCheck={false} aria-describedby="ob-rule-rec-match" />
              </div>
            </div>
            <ul className="rules" style={{ marginBottom: 10 }}>
              <Rule id="ob-rule-rec-strong" ok={ownRules.strong} label={t('rec.own.rule.strong')} />
              <Rule id="ob-rule-rec-match" ok={ownRules.match} label={t('admin.rule.match')} />
            </ul>
          </div>
        )}
        <div className="tools">
          <button className="btn btn-ghost btn-sm" type="button" onClick={regen}>{t('rec.regen')}</button>
          <button className="btn btn-text btn-sm" type="button" aria-expanded={own} onClick={toggleOwn}>{t(own ? 'rec.useGen' : 'rec.own')}</button>
        </div>
      </div>
      <Callout className="r" style={ri(3)}>{t('rec.warn')}</Callout>
      <label className="check r" style={ri(4)}>
        <input type="checkbox" ref={ackRef} checked={ack} onChange={onAck} /> <span>{t('rec.ack')}</span>
      </label>
      {verifying && !own && (
        <div className="verify-row">
          {([0, 1] as const).map((i) => {
            const e = verifyErr(i);
            return (
              <div className="field" key={i}>
                <div className="label"><label htmlFor={`ob-v${i + 1}`}>{t('rec.verify.slot', { n: slots[i] + 1 })}</label></div>
                <div className="input mono" data-invalid={e ? '' : undefined}>
                  <input id={`ob-v${i + 1}`} ref={i === 0 ? v1Ref : v2Ref} maxLength={4} autoComplete="off" spellCheck={false} autoCapitalize="characters"
                    aria-invalid={e ? true : undefined} aria-describedby={`ob-v${i + 1}-err`}
                    value={i === 0 ? v1 : v2} onChange={(ev) => { (i === 0 ? setV1 : setV2)(normalizeGroup(ev.target.value)); setTried(false); }} />
                </div>
                <div className="help err" id={`ob-v${i + 1}-err`} hidden={!e}>{e ?? ''}</div>
              </div>
            );
          })}
        </div>
      )}
    </StepFrame>
  );
}
