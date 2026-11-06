import { useCallback, useEffect, useRef, useState, type Ref } from 'react';
import { t, type CopyKey } from '../copy';
import { call, toIpcError } from '../ipc/client';
import type { PairingJoinResult, PairingPreview } from '../ipc/contract';
import { isFinalPairingReason, isPairingCode, pairingPreviewErrorKey, pairingStopKey, pairingWaitHintKey } from '../lib/pairing';
import { poll, type PollHandle } from '../lib/poll';
import { formatCountdown, formatFingerprint } from '../lib/validators';
import { useApp } from '../ui/context';
import { TextField } from '../ui/fields';
import { Callout } from '../ui/form';
import { Sigil } from '../ui/pixels';
import { msLeft } from '../lib/dash';
import { useNow } from './context';

/** How often a pending join is tried again, and for how long at most (the code lasts 10 minutes
 *  on the other Mac; its invitations longer, but a new code is the way after that). */
export const PAIR_POLL_MS = 3000;
export const PAIR_WAIT_MS = 10 * 60_000;

export type PairPhase =
  | { kind: 'idle' }
  | { kind: 'preview'; ref: string; preview: PairingPreview }
  | { kind: 'waiting'; ref: string; preview: PairingPreview; result: PairingJoinResult | null; hint: CopyKey | null }
  | { kind: 'done'; preview: PairingPreview; result: PairingJoinResult }
  | { kind: 'stopped'; key: CopyKey };

/** The joining Mac's side of pairing (docs/remote-sync.md §4): paste a code, preview it offline,
 *  then ask to join and retry every few seconds until the other Mac approved every environment,
 *  the time is up, the core says it cannot succeed, or the user stops. The pasted code lives in
 *  the core behind a reference; the field is emptied as soon as the core has it. */
export function usePairJoin(onDone: (result: PairingJoinResult) => void) {
  const { toast, field } = useApp();
  const [text, setTextState] = useState('');
  const [error, setError] = useState<CopyKey | null>(null);
  const [phase, setPhase] = useState<PairPhase>({ kind: 'idle' });
  const phaseRef = useRef(phase);
  phaseRef.current = phase;
  const seq = useRef(0);
  const polling = useRef<PollHandle<PairingJoinResult> | null>(null);
  const alive = useRef(true);
  const done = useRef(onDone);
  done.current = onDone;

  const discard = (ref: string) => { void call('onetime_discard', { ref }).catch(() => undefined); };
  const heldRef = (p: PairPhase): string | null => (p.kind === 'preview' || p.kind === 'waiting' ? p.ref : null);

  const reset = useCallback(() => {
    seq.current++;
    polling.current?.cancel(); polling.current = null;
    const ref = heldRef(phaseRef.current);
    if (ref) discard(ref);
    setTextState(''); setError(null); setPhase({ kind: 'idle' });
  }, []);

  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
      polling.current?.cancel();
      const ref = heldRef(phaseRef.current);
      queueMicrotask(() => { if (!alive.current && ref) discard(ref); });
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
        field.ripple(0.05);
      },
      (e) => { if (request === seq.current) setError(pairingPreviewErrorKey(toIpcError(e).reason)); },
    );
  };

  const start = () => {
    const p = phaseRef.current;
    if (p.kind !== 'preview') return;
    const { ref, preview } = p;
    setPhase({ kind: 'waiting', ref, preview, result: null, hint: null });
    const handle = poll<PairingJoinResult>({
      step: () => call('pairing_join', { ref }),
      done: (r) => r.done,
      final: (r) => r.environments.find((e) => e.state === 'failed' && e.reason && isFinalPairingReason(e.reason))?.reason ?? null,
      finalError: (e) => { const reason = toIpcError(e).reason; return isFinalPairingReason(reason) ? reason : null; },
      onValue: (r) => {
        if (!alive.current) return;
        const hint = pairingWaitHintKey(r.environments.find((e) => e.state === 'failed')?.reason);
        setPhase((cur) => (cur.kind === 'waiting' && cur.ref === ref ? { ...cur, result: r, hint } : cur));
      },
      every: PAIR_POLL_MS,
      until: Date.now() + PAIR_WAIT_MS,
    });
    polling.current = handle;
    void handle.result.then((out) => {
      if (polling.current === handle) polling.current = null;
      if (!alive.current) return;
      if (out.kind === 'done') {
        setPhase({ kind: 'done', preview, result: out.value });
        field.ripple(0.1);
        toast(t('toast.pair.done'));
        done.current(out.value);
      } else if (out.kind === 'cancelled') {
        discard(ref);
      } else {
        discard(ref);
        setPhase({ kind: 'stopped', key: out.kind === 'expired' ? 'pair.expired' : pairingStopKey(out.reason) });
      }
    });
  };

  const cancel = () => {
    const p = phaseRef.current;
    polling.current?.cancel(); polling.current = null;
    if (p.kind === 'waiting') { discard(p.ref); setPhase({ kind: 'stopped', key: 'pair.cancelled' }); }
  };

  return { text, setText, error, phase, start, cancel, reset };
}

export type PairJoin = ReturnType<typeof usePairJoin>;

/** The paste field, the preview, the wait for approval and the outcome (shared by the
 *  dashboard sheet and the onboarding step). Everything from the other Mac is shown as text. */
export function PairJoinBody({ id, pj, inputRef }: { id: string; pj: PairJoin; inputRef?: Ref<HTMLInputElement> }) {
  const p = pj.phase;
  const preview = p.kind === 'preview' || p.kind === 'waiting' || p.kind === 'done' ? p.preview : null;
  const now = useNow(p.kind === 'preview');
  if (p.kind === 'waiting' || p.kind === 'done') {
    const self = p.result?.environments.find((e) => e.self_fingerprint)?.self_fingerprint ?? null;
    return (
      <>
        {p.kind === 'waiting'
          ? <div className="help" role="status">{t('pair.wait.sub')}</div>
          : <div className="help" role="status">{t('pair.done')}</div>}
        <div className="pair-faces">
          <div className="preview">
            <div className="sigil">{self ? <Sigil fp={self} /> : null}<span className="cap">{t('pair.wait.self')}</span></div>
            <dl className="kv"><dt>{t('pair.pv.code')}</dt><dd>{self ? formatFingerprint(self) : t('boot.loading')}</dd></dl>
          </div>
          <div className="preview">
            <div className="sigil"><Sigil fp={p.preview.fingerprint} /><span className="cap">{t('pair.pv.picture')}</span></div>
            <dl className="kv">
              <dt>{t('pair.pv.name')}</dt><dd>{p.preview.name}</dd>
              <dt>{t('pair.pv.code')}</dt><dd>{formatFingerprint(p.preview.fingerprint)}</dd>
            </dl>
          </div>
        </div>
        <ul className="pair-envs" aria-label={t('pair.pv.envs')}>
          {p.preview.environments.map((e) => {
            const r = p.result?.environments.find((x) => x.env === e.env);
            const st = r?.state ?? 'pending';
            return (
              <li key={e.env} className={'pair-env ' + st}>
                <span className="px" aria-hidden="true" /><span className="mono">{e.env}</span>
                <span className="st">{t(st === 'joined' ? 'pair.env.joined' : st === 'failed' ? 'pair.env.failed' : 'pair.env.pending')}</span>
              </li>
            );
          })}
        </ul>
        {p.kind === 'waiting' && p.hint && <div className="help">{t(p.hint)}</div>}
      </>
    );
  }
  return (
    <>
      <TextField id={`${id}-code`} label={t('pair.join.field')} type="password" mono value={pj.text} inputRef={inputRef} placeholder="zeropw://pair#…"
        error={pj.error ? t(pj.error) : p.kind === 'stopped' ? t(p.key) : null} onChange={pj.setText} />
      {preview && (
        <>
          <div className="preview" role="region" aria-label={t('pair.pv.region')}>
            <div className="sigil"><Sigil fp={preview.fingerprint} /><span className="cap">{t('pair.pv.picture')}</span></div>
            <dl className="kv">
              <dt>{t('pair.pv.name')}</dt><dd>{preview.name}</dd>
              <dt>{t('pair.pv.code')}</dt><dd>{formatFingerprint(preview.fingerprint)}</dd>
              <dt>{t('pair.pv.envs')}</dt><dd>{t('devices.envs', { n: preview.environments.length })}</dd>
              <dt>{t('pair.pv.server')}</dt><dd>{preview.service_host}</dd>
              {preview.expires_at && <><dt>{t('pair.pv.left')}</dt><dd>{formatCountdown(msLeft(preview.expires_at, now))}</dd></>}
            </dl>
          </div>
          <Callout>{t('pair.pv.check')}</Callout>
        </>
      )}
    </>
  );
}
