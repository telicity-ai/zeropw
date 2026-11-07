// Join another Mac's vault with its one-time code: paste, compare the other Mac's confirmation
// code, ask, then wait while that Mac approves. Names and places come from the other Mac and
// are rendered as text only.

import { useRef } from 'react';
import { t } from '../../copy';
import { msLeft } from '../../lib/dash';
import { formatCountdown } from '../../lib/validators';
import { placeLabel } from '../../lib/places';
import { Button, PassField } from '../../ui/controls';
import { Dialog } from '../../ui/Dialog';
import { Banner, Fingerprint, KeyValues, Spinner, Status } from '../../ui/feedback';
import { useNow } from '../../ui/hooks';
import type { PairJoin } from './usePairJoin';

function placeOf(env: string): string {
  const [p, e] = env.split('/');
  return p && e ? placeLabel(p, e) : env;
}

export function JoinMacDialog({ open, pj, onClose }: { open: boolean; pj: PairJoin; onClose(): void }) {
  const p = pj.phase;
  const field = useRef<HTMLInputElement>(null);
  const now = useNow(open && p.kind === 'preview');
  const close = () => { pj.cancel(); pj.reset(); onClose(); };
  const waiting = p.kind === 'waiting';

  const footer = p.kind === 'done'
    ? <Button tone="primary" onClick={close}>{t('act.done')}</Button>
    : waiting
      ? <Button tone="ghost" onClick={close}>{t('mac.wait.cancel')}</Button>
      : <>
        <Button tone="ghost" onClick={close}>{t('act.cancel')}</Button>
        <Button tone="primary" type="submit" blocked={p.kind !== 'preview'} onBlocked={() => field.current?.focus()}>{t('mac.joinDlg.send')}</Button>
      </>;

  return (
    <Dialog open={open} title={t(waiting ? 'mac.wait.title' : 'mac.joinDlg.title')} description={t(waiting ? 'mac.wait.sub' : 'mac.joinDlg.sub')}
      onClose={close} size="md" footer={footer} onSubmit={p.kind === 'preview' ? pj.start : undefined} id="dlg-mac-join">
      {(p.kind === 'idle' || p.kind === 'preview' || p.kind === 'stopped') && (
        <>
          <PassField label={t('mac.joinDlg.code')} value={pj.text} onChange={pj.setText} inputRef={field} mono autoComplete="off"
            placeholder="zeropw://pair#…" allowShow={false}
            error={pj.error ? t(pj.error) : p.kind === 'stopped' ? t(p.key) : null} />
          {p.kind === 'preview' && (
            <div className="mac-preview" role="region" aria-label={t('mac.pv.name')}>
              <KeyValues items={[
                { k: t('mac.pv.name'), v: p.preview.name },
                { k: t('mac.pv.fp'), v: <Fingerprint value={p.preview.fingerprint} /> },
                { k: t('mac.pv.places'), v: p.preview.environments.map((e) => placeOf(e.env)).join(', ') },
                { k: t('mac.pv.server'), v: p.preview.service_host, mono: true },
                !!p.preview.expires_at && { k: t('mac.pv.left'), v: <span className="num">{formatCountdown(msLeft(p.preview.expires_at, now))}</span> },
              ]} />
              <Banner tone="info" compact>{t('mac.joinDlg.check')}</Banner>
            </div>
          )}
        </>
      )}
      {(p.kind === 'waiting' || p.kind === 'done') && <JoinProgress phase={p} />}
    </Dialog>
  );
}

function JoinProgress({ phase: p }: { phase: Extract<PairJoin['phase'], { kind: 'waiting' | 'done' }> }) {
  const self = p.result?.environments.find((e) => e.self_fingerprint)?.self_fingerprint ?? null;
  const failed = p.kind === 'done' ? p.result.environments.filter((e) => e.state === 'failed') : [];
  return (
    <>
      {p.kind === 'done' && <Banner tone="ok">{t('mac.done')}</Banner>}
      <div className="mac-compare">
        <div className="mac-compare-side is-self">
          <span className="mac-compare-label">{t('mac.wait.self')}</span>
          {self ? <Fingerprint value={self} /> : <span className="muted text-sm row"><Spinner />{t('mac.wait.selfPending')}</span>}
        </div>
        <div className="mac-compare-side">
          <span className="mac-compare-label">{t('mac.wait.other')}</span>
          <strong className="wrap-anywhere">{p.preview.name}</strong>
          <Fingerprint value={p.preview.fingerprint} />
        </div>
      </div>
      <ul className="mac-envs" aria-label={t('mac.pv.places')}>
        {p.preview.environments.map((e) => {
          const r = p.result?.environments.find((x) => x.env === e.env);
          const st = r?.state ?? 'pending';
          return (
            <li key={e.env}>
              <span className="wrap-anywhere">{placeOf(e.env)}</span>
              <Status tone={st === 'joined' ? 'ok' : st === 'failed' ? 'danger' : 'neutral'} pulse={st === 'pending' && p.kind === 'waiting'}>
                {t(st === 'joined' ? 'mac.env.joined' : st === 'failed' ? 'mac.env.failed' : 'mac.env.pending')}
              </Status>
            </li>
          );
        })}
      </ul>
      {p.kind === 'waiting' && p.hint && <Banner tone="warn" compact>{t(p.hint)}</Banner>}
      {failed.length > 0 && (
        <Banner tone="warn">{t(failed.some((e) => e.reason === 'pairing_env_exists') ? 'pair.failed.exists' : 'mac.partial')}</Banner>
      )}
    </>
  );
}
