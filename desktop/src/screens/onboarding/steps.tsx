// The first run's step cards. Secrets typed here stay in these components (and the parent's ref)
// only until `vault_init` succeeds; the generated recovery code is a one-time value the core
// holds, painted only after the capture-exclusion request was answered (ui/secure.ts).

import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { t, type CopyKey } from '../../copy';
import { call, toIpcError } from '../../ipc/client';
import { hostPort } from '../../lib/format';
import { relayError } from '../../lib/reasons';
import {
  adminReady, adminRules, canonicalRecovery, meterLevel, normalizeGroup, pickVerifySlots, RECOVERY_GROUP_COUNT, recoveryOwnRules,
  recoveryRefStale, verifyRecoveryGroups, verifyStates,
} from '../../lib/validators';
import { useApp } from '../../ui/app';
import { Button, PassField, TextField } from '../../ui/controls';
import { More } from '../../ui/disclosure';
import { Banner } from '../../ui/feedback';
import { Icon } from '../../ui/icons';
import { useSecureGate } from '../../ui/secure';
import { reasonKey, useStrength } from './strength';
import { createVault, ensurePersonalPlace, ensureService, InitError, type InitAttempts, type InitFailure, type RecoveryChoice } from './vault';

// ------------------------------------------------------------------------------------- frame

/** One step: a large title, one line, a form whose Enter goes on, and one primary button (a quiet
 *  back on the left when going back is allowed). */
export function StepCard({ name, title, sub, children, back, next, foot, onSubmit }: {
  name: string; title: ReactNode; sub?: ReactNode; children?: ReactNode;
  back?: (() => void) | null; next?: ReactNode; foot?: ReactNode; onSubmit?(): void;
}) {
  return (
    <form className="setup-step" data-step={name} noValidate
      onSubmit={(e) => { e.preventDefault(); onSubmit?.(); }}
      onKeyDown={(e) => { if (e.key === 'Enter' && (e.nativeEvent.isComposing || e.keyCode === 229)) e.preventDefault(); }}>
      <div className="setup-step-head">
        <h1 className="setup-title" tabIndex={-1} data-step-title="">{title}</h1>
        {sub && <p className="setup-sub">{sub}</p>}
      </div>
      {children !== undefined && <div className="setup-step-body">{children}</div>}
      {(back || next || foot) && (
        <div className="setup-foot">
          <div className="setup-foot-start">
            {back && <Button tone="ghost" icon="chevron-left" onClick={back}>{t('act.back')}</Button>}
            {foot}
          </div>
          <div className="setup-foot-end">{next}</div>
        </div>
      )}
    </form>
  );
}

/** A slim strength bar; its word is read out (colour never carries it alone). */
export function Meter({ score, filled }: { score: number; filled: boolean }) {
  const level = filled ? meterLevel(score) : 0;
  const word = t(`setup.meter.${level}` as CopyKey);
  return (
    <div className="meter" data-level={level} role="img" aria-label={t('setup.meter', { level: word })}>
      <div className="meter-bar"><i style={{ width: `${level * 25}%` }} /></div>
    </div>
  );
}

// ------------------------------------------------------------------------------ admin passphrase

export function AdminStep({ onBack, onNext }: { onBack(): void; onNext(pass: string): void }) {
  const [pass, setPass] = useState('');
  const [pass2, setPass2] = useState('');
  const [tried, setTried] = useState(false);
  const { score, reason } = useStrength(pass);
  const rules = adminRules(pass, pass2, score);
  const ok = adminReady(rules);
  const passRef = useRef<HTMLInputElement>(null);
  const pass2Ref = useRef<HTMLInputElement>(null);
  const firstOk = rules.len && rules.strong;
  // the confirmation appears once the passphrase itself is good enough (and stays once typed in)
  const showConfirm = firstOk || pass2 !== '';
  const rk = reasonKey(reason);

  // one help line: the first rule still unmet, or that it is good
  const help: { key: CopyKey; tone: 'need' | 'ok' } = !pass ? { key: 'setup.admin.need.start', tone: 'need' }
    : !rules.len ? { key: 'setup.admin.need.len', tone: 'need' }
      : !rules.strong ? { key: rk ?? 'setup.admin.need.strong', tone: 'need' }
        : { key: 'setup.admin.ok', tone: 'ok' };

  const next = () => {
    if (!ok) { setTried(true); (firstOk ? pass2Ref.current : passRef.current)?.focus(); return; }
    onNext(pass);
  };

  return (
    <StepCard name="admin" title={t('setup.admin.title')} sub={t('setup.admin.sub')} back={onBack} onSubmit={next}
      next={<Button tone="primary" size="lg" type="submit" blocked={!ok} onBlocked={next}>{t('act.next')}</Button>}>
      <div className="stack-sm">
        <PassField label={t('setup.admin.field')} value={pass} onChange={setPass} inputRef={passRef} autoComplete="new-password"
          data-step-focus="" error={tried && !firstOk ? t(help.key) : null}
          help={<span className={'setup-help is-' + help.tone}>{t(help.key)}</span>} />
        <Meter score={score} filled={!!pass} />
      </div>
      {showConfirm && (
        <PassField label={t('setup.admin.confirm')} value={pass2} onChange={setPass2} inputRef={pass2Ref} autoComplete="new-password" allowShow={false}
          error={(tried || pass2.length >= pass.length) && pass2 !== '' && !rules.match ? t('setup.admin.need.match') : null} />
      )}
    </StepCard>
  );
}

// ---------------------------------------------------------------------------------- recovery

export interface RecoveryNotice { key: Extract<CopyKey, 'setup.rec.expired' | 'setup.rec.weak'>; n: number }

export function RecoveryStep({ active, admin, notice, onBack, onNext }: {
  active: boolean; admin: string; notice: RecoveryNotice | null; onBack(): void; onNext(choice: RecoveryChoice): void;
}) {
  const { announce } = useApp();
  const [groups, setGroups] = useState<string[]>([]);
  const [genFailed, setGenFailed] = useState(false);
  const refRef = useRef<string | null>(null);
  const madeAt = useRef(0);
  const [own, setOwn] = useState(false);
  const [code, setCode] = useState('');
  const [code2, setCode2] = useState('');
  const [ack, setAck] = useState(false);
  const [slots, setSlots] = useState<[number, number]>([0, 3]);
  const [v1, setV1] = useState('');
  const [v2, setV2] = useState('');
  const [tried, setTried] = useState(false);
  const [blurred, setBlurred] = useState(false);
  const [note, setNote] = useState<CopyKey | null>(null);
  const busy = useRef(false);
  const codeRef = useRef<HTMLInputElement>(null);
  const code2Ref = useRef<HTMLInputElement>(null);
  const v1Ref = useRef<HTMLInputElement>(null);
  const v2Ref = useRef<HTMLInputElement>(null);
  const { score } = useStrength(own ? code : '');
  const ownRules = recoveryOwnRules(code, code2, admin, score);

  const showGroups = useSecureGate(active && !own && groups.length > 0);

  const resetAck = useCallback(() => { setAck(false); setTried(false); setV1(''); setV2(''); }, []);

  const discard = () => {
    const old = refRef.current;
    refRef.current = null;
    if (old) void call('onetime_discard', { ref: old }).catch(() => undefined);
  };

  const generate = useCallback(async () => {
    if (busy.current) return;
    busy.current = true;
    discard();
    setGroups([]); setGenFailed(false);
    try {
      const r = await call('recovery_generate');
      refRef.current = r.ref;
      madeAt.current = Date.now();
      setGroups(r.groups.slice(0, RECOVERY_GROUP_COUNT));
    } catch {
      setGenFailed(true);
    } finally {
      busy.current = false;
      resetAck();
    }
  }, [resetAck]);

  // a generated code that was never used goes when this step does
  useEffect(() => () => discard(), []);

  // entering the step: a code exists, and the write-down confirmation is asked again
  useEffect(() => {
    if (!active) return;
    if (!own && !refRef.current) void generate();
    else resetAck();
  }, [active]);

  // sent back from vault creation
  useEffect(() => {
    if (!notice) return;
    setNote(notice.key);
    announce(t(notice.key));
    if (notice.key === 'setup.rec.weak') {
      setOwn(true); setCode(''); setCode2(''); resetAck();
      setTimeout(() => codeRef.current?.focus(), 60);
    } else {
      setOwn(false); setCode(''); setCode2('');
      void generate();
    }
  }, [notice]);

  // the groups leave the screen while the window is in the background
  useEffect(() => {
    if (!active) return;
    const blur = () => setBlurred(true);
    const focus = () => setBlurred(false);
    const vis = () => { if (document.hidden) setBlurred(true); };
    window.addEventListener('blur', blur); window.addEventListener('focus', focus);
    document.addEventListener('visibilitychange', vis);
    return () => { window.removeEventListener('blur', blur); window.removeEventListener('focus', focus); document.removeEventListener('visibilitychange', vis); };
  }, [active]);

  const genOk = groups.length === RECOVERY_GROUP_COUNT && !!refRef.current;
  const ok = own ? ownRules.strong && ownRules.match : genOk;
  const verified = own ? ack : ack && verifyRecoveryGroups(groups, slots, [v1, v2]);
  const vstate = verifyStates(groups, slots, [v1, v2]);
  const verifying = ack && !own;

  const toggleOwn = () => {
    const next = !own;
    setOwn(next); setCode(''); setCode2(''); resetAck(); setNote(null);
    if (next) { discard(); setTimeout(() => codeRef.current?.focus(), 0); }
    else if (!refRef.current) void generate();
  };
  const regen = () => { setOwn(false); setCode(''); setCode2(''); setNote(null); void generate(); };

  const onAck = (on: boolean) => {
    setAck(on); setTried(false);
    if (on && !own) {
      const bytes = new Uint8Array(2);
      globalThis.crypto.getRandomValues(bytes);
      setSlots(pickVerifySlots(bytes)); setV1(''); setV2('');
      announce(t('setup.rec.verify'));
      setTimeout(() => v1Ref.current?.focus(), 40);
    }
  };

  // generated code: "written down" first (shows the two checks), then create; own code: create
  const next = () => {
    if (own) {
      if (!ok) { (ownRules.strong ? code2Ref : codeRef).current?.focus(); return; }
      discard();
      setNote(null);
      onNext({ typed: code });
      return;
    }
    if (!genOk) return;
    if (!ack) { onAck(true); return; }
    if (!verified) {
      setTried(true);
      (vstate[0] ? v1Ref : v2Ref).current?.focus();
      return;
    }
    if (refRef.current) {
      // the core forgets the code after 10 minutes: make a new one now rather than fail later
      if (recoveryRefStale(madeAt.current, Date.now())) {
        setNote('setup.rec.expired'); announce(t('setup.rec.expired'));
        void generate();
        return;
      }
      setNote(null);
      onNext({ ref: refRef.current });
    }
  };
  const primary = own || ack ? t('setup.rec.next') : t('setup.rec.ackBtn');
  const primaryReady = own ? ok : genOk && (!ack || verified);

  const hide = verifying || blurred;
  const ownHint = own && ownRules.same ? t('setup.rec.own.same') : own && ownRules.similar ? t('setup.rec.own.similar') : null;
  const verifyErr = (i: 0 | 1): string | null => {
    const s = vstate[i];
    if (!tried || !s) return null;
    return t(s === 'empty' ? 'setup.rec.verify.need' : 'setup.rec.verify.err', { n: slots[i] + 1 });
  };

  return (
    <StepCard name="recovery" title={t('setup.rec.title')} sub={t(own ? 'setup.rec.own.sub' : 'setup.rec.sub')} back={onBack} onSubmit={next}
      next={<Button tone="primary" size="lg" type="submit" blocked={!primaryReady} onBlocked={next} data-step-focus={!own ? '' : undefined}>{primary}</Button>}>
      {note && <Banner tone="warn">{t(note)}</Banner>}
      {!own && (
        <div className="rec-box">
          <ol className={'rec-groups' + (hide ? ' is-hidden' : '')} aria-label={t('setup.rec.groups')}>
            {Array.from({ length: RECOVERY_GROUP_COUNT }, (_, k) => (
              <li key={k}>
                <span className="rec-n" aria-hidden="true">{k + 1}</span>
                <span className="rec-g mono">{showGroups && !hide ? groups[k] ?? '' : '••••'}</span>
              </li>
            ))}
          </ol>
          {hide && !verifying && <p className="rec-mask" role="status">{t('setup.rec.hidden')}</p>}
          {!groups.length && !genFailed && <p className="rec-mask" role="status">{t('setup.rec.loading')}</p>}
          {genFailed && <Banner tone="danger" action={<Button size="sm" tone="ghost" icon="refresh" onClick={() => void generate()}>{t('act.retry')}</Button>}>{t('setup.rec.genFailed')}</Banner>}
          {verifying && (
            <div className="rec-verify">
              <p className="setup-hint">{t('setup.rec.verify')}</p>
              <div className="rec-verify-fields">
                {([0, 1] as const).map((i) => (
                  <TextField key={i} mono label={t('setup.rec.verify.slot', { n: slots[i] + 1 })} maxLength={4} autoComplete="off" autoCapitalize="characters"
                    inputRef={i === 0 ? v1Ref : v2Ref} value={i === 0 ? v1 : v2} error={verifyErr(i)}
                    onChange={(v) => { (i === 0 ? setV1 : setV2)(normalizeGroup(v)); setTried(false); }} />
                ))}
              </div>
              <button type="button" className="setup-link" onClick={() => onAck(false)}>{t('setup.rec.showAgain')}</button>
            </div>
          )}
        </div>
      )}
      {own && (
        <div className="stack">
          <div className="stack-sm">
            <PassField label={t('setup.rec.own.field')} value={code} onChange={(v) => { setCode(v); resetAck(); }} inputRef={codeRef} autoComplete="off"
              error={ownHint} help={!ownHint && code && !ownRules.strong ? t('setup.rec.own.rule.strong') : undefined} />
            <Meter score={score} filled={!!code} />
          </div>
          {(ownRules.strong || code2 !== '') && (
            <PassField label={t('setup.rec.own.confirm')} value={code2} onChange={(v) => { setCode2(v); resetAck(); }} inputRef={code2Ref} autoComplete="off" allowShow={false}
              error={code2 !== '' && code2.length >= code.length && !ownRules.match ? t('setup.admin.need.match') : null} />
          )}
        </div>
      )}
      <p className="setup-note">{t('setup.rec.warn')}</p>
      <More label={t('setup.rec.more')} open={own}>
        <div className="rec-tools">
          {!own && <Button size="sm" tone="secondary" icon="refresh" onClick={regen}>{t('setup.rec.regen')}</Button>}
          <Button size="sm" tone="secondary" aria-pressed={own} onClick={toggleOwn}>{t(own ? 'setup.rec.useGen' : 'setup.rec.own')}</Button>
        </div>
        {showGroups && !hide && !own && <p className="rec-full"><span>{t('setup.rec.full')}</span><code className="mono" data-selectable="">{canonicalRecovery(groups)}</code></p>}
      </More>
    </StepCard>
  );
}

// ------------------------------------------------------------------------------------ create

type Line = 'vault' | 'place' | 'service';
type LineState = 'idle' | 'active' | 'done' | 'fail';
const LINES: readonly Line[] = ['vault', 'place', 'service'];
const LINE_COPY: Record<Line, CopyKey> = { vault: 'setup.create.line.vault', place: 'setup.create.line.place', service: 'setup.create.line.service' };

export interface CreateResult { serviceOn: boolean; placeOk: boolean }

/** Each line flips when its real call returns. A vault that exists is never made again: retries
 *  go on from the first line that failed after it. The place and the service are not needed to
 *  use the vault locally, so their failures leave the way on open. */
export function CreateStep({ created, secrets, attempts, onCreated, onRecoveryProblem, onBack, onDone }: {
  created: boolean;
  secrets(): { admin: string; recovery: RecoveryChoice | null };
  attempts: InitAttempts;
  onCreated(): void;
  onRecoveryProblem(kind: Extract<InitFailure, 'recovery_expired' | 'recovery_weak'>): void;
  onBack(): void;
  onDone(r: CreateResult): void;
}) {
  const { announce } = useApp();
  const [lines, setLines] = useState<Record<Line, LineState>>({ vault: created ? 'done' : 'idle', place: 'idle', service: 'idle' });
  const [addr, setAddr] = useState<string | null>(null);
  const [fatal, setFatal] = useState<'init' | 'unsure' | null>(null);
  const [placeErr, setPlaceErr] = useState(false);
  const [serviceErr, setServiceErr] = useState<{ key: CopyKey; reason: string } | null>(null);
  const [finished, setFinished] = useState(false);
  const running = useRef(false);
  const madeRef = useRef(created);
  const nextRef = useRef<HTMLButtonElement>(null);
  const result = useRef<CreateResult>({ serviceOn: false, placeOk: false });
  const mark = (l: Line, s: LineState) => setLines((xs) => ({ ...xs, [l]: s }));

  const run = useCallback(async () => {
    if (running.current) return;
    running.current = true;
    setFatal(null); setFinished(false);
    try {
      if (!madeRef.current) {
        mark('vault', 'active');
        try {
          await createVault(secrets(), attempts);
        } catch (e) {
          const kind: InitFailure = e instanceof InitError ? e.kind : 'failed';
          mark('vault', 'fail');
          if (kind === 'recovery_expired' || kind === 'recovery_weak') { onRecoveryProblem(kind); return; }
          setFatal(kind === 'unknown' ? 'unsure' : 'init');
          announce(t(kind === 'unknown' ? 'setup.create.err.unsure' : 'setup.create.err'));
          return;
        }
        madeRef.current = true;
        mark('vault', 'done');
        onCreated();
      }
      let placeOk = true;
      mark('place', 'active');
      try { await ensurePersonalPlace(); mark('place', 'done'); setPlaceErr(false); } catch { placeOk = false; mark('place', 'fail'); setPlaceErr(true); }
      mark('service', 'active');
      let serviceOn = true;
      try {
        const url = await ensureService();
        setAddr(hostPort(url)); mark('service', 'done'); setServiceErr(null);
      } catch (e) {
        serviceOn = false;
        const err = toIpcError(e);
        mark('service', 'fail'); setServiceErr(relayError(err.reason, err.detail));
      }
      setFinished(true);
      result.current = { serviceOn, placeOk };
      if (serviceOn && placeOk) {
        // nothing to decide: go straight to the end (the done step announces itself)
        onDone(result.current);
        return;
      }
      announce(t('setup.create.title.partial'));
      setTimeout(() => nextRef.current?.focus({ preventScroll: true }), 0);
    } finally {
      running.current = false;
    }
  }, [secrets, attempts, onCreated, onRecoveryProblem, onDone, announce]);

  useEffect(() => { void run(); }, []);

  const anyFail = placeErr || !!serviceErr;
  const title = fatal ? t('setup.create.title.fail') : finished ? t('setup.create.title.partial') : t('setup.create.title.run');
  const working = !finished && !fatal;

  return (
    <StepCard name="create" title={title} back={fatal === 'init' ? onBack : null} onSubmit={() => { if (finished) onDone(result.current); }}
      foot={finished && anyFail ? <Button tone="ghost" icon="refresh" onClick={() => void run()}>{t('act.retry')}</Button> : undefined}
      next={fatal
        ? <Button tone="primary" size="lg" icon="refresh" onClick={() => void run()}>{t('act.retry')}</Button>
        : <Button ref={nextRef} tone="primary" size="lg" type="submit" busy={working} blocked={!finished}>{t(anyFail ? 'setup.create.later' : 'act.continue')}</Button>}>
      <ol className="mk-lines" aria-live="polite">
        {LINES.map((l) => {
          const s = lines[l];
          return (
            <li key={l} data-state={s}>
              <span className="mk-mark" aria-hidden="true">
                {s === 'done' ? <Icon name="check" size={12} /> : s === 'fail' ? <Icon name="close" size={12} /> : s === 'active' ? <span className="spinner" /> : null}
              </span>
              <span className="mk-label">{t(LINE_COPY[l])}</span>
              {l === 'service' && addr && <span className="mk-aside mono">{addr}</span>}
              {(s === 'active' || s === 'done' || s === 'fail') && <span className="sr-only">{t(`setup.create.state.${s}` as CopyKey)}</span>}
            </li>
          );
        })}
      </ol>
      {fatal && <Banner tone="danger">{t(fatal === 'unsure' ? 'setup.create.err.unsure' : 'setup.create.err')}</Banner>}
      {placeErr && <Banner tone="warn">{t('setup.create.err.place')}</Banner>}
      {serviceErr && (
        <Banner tone="warn" title={t('setup.create.err.service')}>
          {t(serviceErr.key, { reason: serviceErr.reason })}. {t('setup.create.service.ok')}
        </Banner>
      )}
      <p className="setup-note">{t('setup.create.note')}</p>
    </StepCard>
  );
}
