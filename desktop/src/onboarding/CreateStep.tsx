import { useCallback, useEffect, useRef, useState, type Ref } from 'react';
import { t, type CopyKey } from '../copy';
import { ri, useApp, wait } from '../ui/context';
import { Callout } from '../ui/form';
import { BackButton, StepFrame, type FrameState } from './StepFrame';

const ITEMS: CopyKey[] = ['create.item.1', 'create.item.2', 'create.item.3', 'create.item.4', 'create.item.5', 'create.item.6', 'create.item.7'];
const KEYS_DONE = 5;      // items 1-6 finish with `vault_init`
const RELAY = 6;          // item 7 is the relay (`serve`)
type ItemState = '' | 'active' | 'done' | 'fail';

/** Step 3: create the vault. The list owns the clock: each finished line contracts the sphere,
 *  the last one bursts it. Lines 1-6 wait for `vault_init`, line 7 for the relay. */
export function CreateStep({ frame, sectionRef, created, initVault, startRelay, onCreated, onBack, onNext }: {
  frame: FrameState; sectionRef: Ref<HTMLElement>; created: boolean;
  initVault(): Promise<void>; startRelay(): Promise<string | null>; onCreated(): void;
  onBack(): void; onNext(): void;
}) {
  const { field, announce } = useApp();
  const [items, setItems] = useState<ItemState[]>(ITEMS.map(() => ''));
  const [addr, setAddr] = useState<string | null>(null);
  const [error, setError] = useState<CopyKey | null>(null);
  const [failedAt, setFailedAt] = useState<'init' | 'relay' | null>(null);
  const [noteOn, setNoteOn] = useState(false);
  const [finished, setFinished] = useState(created);
  const running = useRef(false);
  const nextRef = useRef<HTMLButtonElement>(null);
  const activeRef = useRef(frame.active);
  activeRef.current = frame.active;

  const mark = (k: number, s: ItemState) => setItems((xs) => xs.map((x, i) => (i === k ? s : x)));

  const run = useCallback(async (from: 'init' | 'relay') => {
    if (running.current) return;
    running.current = true;
    setError(null); setFailedAt(null);
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
      requestAnimationFrame(() => setNoteOn(true));
      announce(t('create.title.done'));
      if (activeRef.current) setTimeout(() => nextRef.current?.focus({ preventScroll: true }), 0);
    } catch {
      mark(k, 'fail');
      setFailedAt(k === RELAY ? 'relay' : 'init');
      setError(k === RELAY ? 'create.err.serve' : 'create.err');
      announce(t(k === RELAY ? 'create.err.serve' : 'create.err'));
      field.setMode('create');
      field.set('scale', 1);
    } finally {
      running.current = false;
    }
  }, [field, initVault, startRelay, onCreated, announce]);

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

  return (
    <StepFrame name="create" frame={frame} sectionRef={sectionRef} title={title}
      nav={<>
        {failedAt === 'init' ? <BackButton onClick={onBack} label={t('common.back')} /> : <span />}
        {failedAt
          ? <button className="btn btn-primary" type="button" onClick={() => void run(failedAt)}>{t('common.retry')}</button>
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
      {error && <div className="help err" role="alert">{t(error)}</div>}
      {done && <Callout className={'note' + (noteOn ? ' on' : '')}>{t('create.note')}</Callout>}
    </StepFrame>
  );
}
