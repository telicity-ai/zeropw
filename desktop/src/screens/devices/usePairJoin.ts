// The joining Mac's side of pairing (docs/remote-sync.md §4): paste a code, preview it offline,
// then ask to join and retry every few seconds until the other Mac approved every place, the
// time is up, the core says it cannot succeed, or the person stops. The pasted code lives in
// the core behind a reference; the field is emptied as soon as the core has it, and a held
// reference is discarded on cancel, reset and unmount.

import { useCallback, useEffect, useRef, useState } from 'react';
import { t, type CopyKey } from '../../copy';
import { call, toIpcError } from '../../ipc/client';
import type { PairingJoinResult, PairingPreview } from '../../ipc/contract';
import { finalJoinReason, isFinalPairingReason, isPairingCode, pairingPreviewErrorKey, pairingStopKey, pairingWaitHintKey } from '../../lib/pairing';
import { poll, type PollHandle } from '../../lib/poll';
import { useApp } from '../../ui/app';

/** How often a pending join is tried again, and for how long at most (the code lasts 10 minutes
 *  on the other Mac; a new code is the way after that). */
export const PAIR_POLL_MS = 3000;
export const PAIR_WAIT_MS = 10 * 60_000;

export type PairPhase =
  | { kind: 'idle' }
  | { kind: 'preview'; ref: string; preview: PairingPreview }
  | { kind: 'waiting'; ref: string; preview: PairingPreview; result: PairingJoinResult | null; hint: CopyKey | null }
  | { kind: 'done'; preview: PairingPreview; result: PairingJoinResult }
  | { kind: 'stopped'; key: CopyKey };

const discard = (ref: string) => { void call('onetime_discard', { ref }).catch(() => undefined); };
const heldRef = (p: PairPhase): string | null => (p.kind === 'preview' || p.kind === 'waiting' ? p.ref : null);

export function usePairJoin(onDone: (result: PairingJoinResult) => void) {
  const { toast, announce } = useApp();
  const [text, setTextState] = useState('');
  const [error, setError] = useState<CopyKey | null>(null);
  const [phase, setPhaseState] = useState<PairPhase>({ kind: 'idle' });
  const phaseRef = useRef(phase);
  const setPhase = (p: PairPhase) => { phaseRef.current = p; setPhaseState(p); };
  const seq = useRef(0);
  const polling = useRef<PollHandle<PairingJoinResult> | null>(null);
  const alive = useRef(true);
  const done = useRef(onDone);
  done.current = onDone;

  const reset = useCallback(() => {
    seq.current++;
    polling.current?.cancel(); polling.current = null;
    const ref = heldRef(phaseRef.current);
    if (ref) discard(ref);
    setTextState(''); setError(null);
    phaseRef.current = { kind: 'idle' }; setPhaseState({ kind: 'idle' });
  }, []);

  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
      polling.current?.cancel(); polling.current = null;
      const ref = heldRef(phaseRef.current);
      phaseRef.current = { kind: 'idle' };
      if (ref) discard(ref);
    };
  }, []);

  const setText = (v: string) => {
    if (phaseRef.current.kind === 'waiting') return;
    setTextState(v);
    const request = ++seq.current;
    const old = heldRef(phaseRef.current);
    if (old) discard(old);
    setPhase({ kind: 'idle' });
    const s = v.trim();
    if (!s) { setError(null); return; }
    if (!isPairingCode(s)) { setError('pair.join.err'); return; }
    setError(null);
    call('pairing_preview', { text: s }).then(
      (r) => {
        if (request !== seq.current || !alive.current) { discard(r.ref); return; }
        setTextState('');   // the core holds the code now
        setPhase({ kind: 'preview', ref: r.ref, preview: r.preview });
      },
      (e) => { if (request === seq.current && alive.current) setError(pairingPreviewErrorKey(toIpcError(e).reason)); },
    );
  };

  const start = () => {
    const p = phaseRef.current;
    if (p.kind !== 'preview') return;
    const { ref, preview } = p;
    setPhase({ kind: 'waiting', ref, preview, result: null, hint: null });
    announce(t('mac.wait.title'));
    let last: PairingJoinResult | null = null;
    const handle = poll<PairingJoinResult>({
      step: () => call('pairing_join', { ref }),
      done: (r) => r.done,
      // stop once nothing can change any more: every place not joined failed for good
      final: (r) => finalJoinReason(r.environments),
      finalError: (e) => { const reason = toIpcError(e).reason; return isFinalPairingReason(reason) ? reason : null; },
      onValue: (r) => {
        last = r;
        if (!alive.current) return;
        const failed = r.environments.find((e) => e.state === 'failed' && !(e.reason && isFinalPairingReason(e.reason)));
        const hint = pairingWaitHintKey(failed?.reason, failed?.detail);
        const cur = phaseRef.current;
        if (cur.kind === 'waiting' && cur.ref === ref) setPhase({ ...cur, result: r, hint });
      },
      every: PAIR_POLL_MS,
      until: Date.now() + PAIR_WAIT_MS,
    });
    polling.current = handle;
    void handle.result.then((out) => {
      if (polling.current === handle) polling.current = null;
      if (!alive.current) return;
      // every place joined, or some did and the rest cannot: the joined ones sync now
      const partial = out.kind === 'failed' && last?.environments.some((e) => e.state === 'joined') ? last : null;
      if (out.kind === 'done' || partial) {
        const result = out.kind === 'done' ? out.value : (partial as PairingJoinResult);
        if (partial) discard(ref);
        setPhase({ kind: 'done', preview, result });
        toast(t('mac.toast.joined'), 'ok');
        done.current(result);
      } else if (out.kind === 'cancelled') {
        // whoever cancelled (stop, reset, leaving) already discarded the code
      } else {
        discard(ref);
        setPhase({ kind: 'stopped', key: out.kind === 'expired' ? 'pair.expired' : pairingStopKey(out.reason) });
      }
    });
  };

  const cancel = () => {
    const p = phaseRef.current;
    polling.current?.cancel(); polling.current = null;
    if (p.kind === 'waiting') {
      discard(p.ref);
      setPhase({ kind: 'stopped', key: 'mac.cancelled' });
    }
  };

  return { text, setText, error, phase, start, cancel, reset };
}

export type PairJoin = ReturnType<typeof usePairJoin>;
