import { useCallback, useEffect, useRef, useState, type Ref } from 'react';
import { t, type CopyKey } from '../copy';
import { toIpcError } from '../ipc/client';
import { relayError } from '../lib/reasons';
import { ri, useApp, wait } from '../ui/context';
import { Callout } from '../ui/form';
import { BackButton, StepFrame, type FrameState } from './StepFrame';
import { InitError, type InitFailure } from './vault';

const ITEMS: CopyKey[] = ['create.item.1', 'create.item.2', 'create.item.3', 'create.item.4', 'create.item.5', 'create.item.6', 'create.item.7'];
const KEYS_DONE = 5;      // items 1-6 finish with `vault_init`
const RELAY = 6;          // item 7 is the relay (`serve`)
type ItemState = '' | 'active' | 'done' | 'fail';
type Failed = 'init' | 'unsure' | 'relay';

/** Step 3: create the vault. The list owns the clock: each finished line contracts the sphere,
 *  the last one bursts it. Lines 1-6 wait for `vault_init`, line 7 for the relay.
 *  A vault that exists is never made again: when only the relay failed, the retry starts the relay,
 *  and the user can also go on without it (`onSkipRelay`): the vault is made, and the dashboard has
 *  the relay's start button and port setting, so a port that stays busy is not a dead end. When the
 *  core could not say whether the vault exists, only a retry is offered (going back could change
 *  secrets a vault may already use). A recovery code that expired or is too close to the admin
 *  passphrase sends the user back to the recovery step (`onRecoveryProblem`). */
export function CreateStep({ frame, sectionRef, created, initVault, startRelay, onCreated, onRecoveryProblem, onSkipRelay, onBack, onNext }: {
  frame: FrameState; sectionRef: Ref<HTMLElement>; created: boolean;
  initVault(): Promise<void>; startRelay(): Promise<string | null>; onCreated(): void;
  onRecoveryProblem(kind: Extract<InitFailure, 'recovery_expired' | 'recovery_weak'>): void;
  /** Go on with the vault made and the relay off. */
  onSkipRelay(): void;
  onBack(): void; onNext(): void;
}) {
  const { field, announce } = useApp();
  const [items, setItems] = useState<ItemState[]>(ITEMS.map(() => ''));
  const [addr, setAddr] = useState<string | null>(null);
  const [error, setError] = useState<CopyKey | null>(null);
  const [relayWhy, setRelayWhy] = useState<{ key: CopyKey; reason: string } | null>(null);
  const [failedAt, setFailedAt] = useState<Failed | null>(null);
  const [finished, setFinished] = useState(created);
  const [vaultMade, setVaultMade] = useState(created);
  const running = useRef(false);
  const nextRef = useRef<HTMLButtonElement>(null);
  const activeRef = useRef(frame.active);
  activeRef.current = frame.active;

  const mark = (k: number, s: ItemState) => setItems((xs) => xs.map((x, i) => (i === k ? s : x)));

  const run = useCallback(async (from: 'init' | 'relay') => {
    if (running.current) return;
    running.current = true;
    setError(null); setRelayWhy(null); setFailedAt(null);
    const step = field.motionOn ? 380 : 140;
    let k = from === 'relay' ? RELAY : 0;
    try {
      if (from === 'init') {
        setItems(ITEMS.map(() => ''));
        await wait(field.motionOn ? 600 : 100);
        const init = initVault();
        init.catch(() => undefined);
        for (; k <= KEYS_DONE; k++) {
          mark(k, 'active');
          await wait(step);
          if (k === KEYS_DONE) await init;
          mark(k, 'done');
          field.createStep(k + 1, ITEMS.length - 1);
        }
        setVaultMade(true);
      }
      k = RELAY;
      mark(k, 'active');
      await wait(step);
      const a = await startRelay();
      setAddr(a);
      mark(k, 'done');
      field.createBurst();
      await wait(field.motionOn ? 280 : 0);
      setFinished(true);
      onCreated();
      announce(t('create.title.done'));
      if (activeRef.current) setTimeout(() => nextRef.current?.focus({ preventScroll: true }), 0);
    } catch (e) {
      const kind: InitFailure = e instanceof InitError ? e.kind : 'failed';
      mark(k, 'fail');
      field.setMode('create');
      field.set('scale', 1);
      if (k === RELAY) {
        const why = relayError(toIpcError(e).reason, toIpcError(e).detail);
        setFailedAt('relay'); setError('create.err.serve'); setRelayWhy(why);
        announce(`${t('create.err.serve')} ${t(why.key, { reason: why.reason })} ${t('create.relay.vaultOk')}`);
      } else if (kind === 'recovery_expired' || kind === 'recovery_weak') {
        setFailedAt('init');
        onRecoveryProblem(kind);
      } else {
        const msg: CopyKey = kind === 'unknown' ? 'create.err.unsure' : 'create.err';
        setFailedAt(kind === 'unknown' ? 'unsure' : 'init'); setError(msg); announce(t(msg));
      }
    } finally {
      running.current = false;
    }
  }, [field, initVault, startRelay, onCreated, onRecoveryProblem, announce]);

  useEffect(() => {
    if (!frame.active || finished || created || running.current || failedAt) return;
    void run('init');
  }, [frame.active, finished, created, failedAt, run]);

  // leaving after a failed init (back to the recovery code) starts over on the way back
  useEffect(() => {
    if (frame.active || failedAt !== 'init' || running.current) return;
    setFailedAt(null); setError(null); setItems(ITEMS.map(() => ''));
  }, [frame.active, failedAt]);

  const done = finished || created;
  const title = done ? t('create.title.done') : t('create.title.run');
  const retry = failedAt === 'relay' || vaultMade ? 'relay' : 'init';

  return (
    <StepFrame name="create" frame={frame} sectionRef={sectionRef} title={title}
      nav={<>
        {failedAt === 'init' ? <BackButton onClick={onBack} label={t('common.back')} />
          : failedAt === 'relay' ? <button className="btn btn-ghost" type="button" onClick={onSkipRelay}>{t('create.relay.later')}</button>
            : <span />}
        {failedAt
          ? <button className="btn btn-primary" type="button" onClick={() => void run(retry)}>{t('common.retry')}</button>
          : <button className="btn btn-primary" type="button" ref={nextRef} aria-disabled={!done} onClick={() => { if (done) onNext(); }}>{t('common.next')}</button>}
      </>}>
      <ul className="mk-list r" style={ri(1)} data-focus-title="">
        {ITEMS.map((key, k) => {
          const s = done ? 'done' : items[k];
          return (
            <li key={key} className={s || undefined}>
              <span className="px" aria-hidden="true" />
              <span>{t(key)}</span>
              {k === RELAY && addr && <span className="mono">{addr}</span>}
              <span className="sr-only">{s === 'done' ? ' ✓' : ''}</span>
            </li>
          );
        })}
      </ul>
      {error && <div className="help err" role="alert">{t(error)}{relayWhy && <><br />{t(relayWhy.key, { reason: relayWhy.reason })}</>}</div>}
      {failedAt === 'relay' && <Callout kind="info">{t('create.relay.vaultOk')}</Callout>}
      {/* same-account access is disclosed while the vault is being made, not only afterwards */}
      <Callout className="note on">{t('create.note')}</Callout>
    </StepFrame>
  );
}
