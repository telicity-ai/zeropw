import { useRef, type Ref } from 'react';
import { t } from '../copy';
import type { PairingJoinResult } from '../ipc/contract';
import { PairJoinBody, usePairJoin } from '../dashboard/pairJoin';
import { BackButton, StepFrame, type FrameState } from './StepFrame';

/** New vault, then "connect another Mac" (proj.pair) (docs/remote-sync.md §4): paste the other Mac's pairing code,
 *  check its picture and code, ask to join, and wait here while the other Mac approves. Leaving
 *  the step stops waiting; nothing joins without the other Mac's approval. */
export function PairStep({ frame, sectionRef, onBack, onDone }: {
  frame: FrameState; sectionRef: Ref<HTMLElement>; onBack(): void; onDone(result: PairingJoinResult): void;
}) {
  const pj = usePairJoin(onDone);
  const codeRef = useRef<HTMLInputElement>(null);
  const p = pj.phase;
  const back = () => { pj.cancel(); pj.reset(); onBack(); };
  const primary = () => {
    if (p.kind === 'preview') pj.start();
    else if (p.kind === 'idle' || p.kind === 'stopped') codeRef.current?.focus();
  };
  return (
    <StepFrame name="pair" frame={frame} sectionRef={sectionRef} title={t(p.kind === 'waiting' ? 'pair.wait.title' : 'pair.join.title')} lead={t('pair.join.sub')}
      nav={<>
        {p.kind === 'waiting'
          ? <button className="btn btn-text" type="button" onClick={() => pj.cancel()}>{t('pair.wait.cancel')}</button>
          : <BackButton onClick={back} label={t('common.back')} />}
        {p.kind !== 'waiting' && p.kind !== 'done' && (
          <button className="btn btn-primary" type="button" aria-disabled={p.kind !== 'preview' || undefined} onClick={primary}>
            <span>{t('pair.join.confirm')}</span> <span className="arrow" aria-hidden="true">→</span>
          </button>
        )}
      </>}>
      <PairJoinBody id="ob-pair" pj={pj} inputRef={codeRef} />
    </StepFrame>
  );
}
