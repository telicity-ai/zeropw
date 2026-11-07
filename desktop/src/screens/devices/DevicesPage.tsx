// 내 Mac (docs/remote-sync.md §4): this Mac at the link service, the Macs paired with it and how
// far each one has synced, adding a Mac with a one-time code that must be approved here, and
// joining another Mac's vault with its code. Everything is read from the core
// (`devices_overview`, re-read every 10 s while the window is visible); names come from other
// Macs and are rendered as text. How a Mac is connected (direct or relayed, timings, error
// codes) is only under 고급 진단.
//
// One column: there are rarely more than a few Macs, so this Mac comes first, then the paired
// Macs as a plain grouped list; a row opens that Mac's detail in place, with a back button.

import { useEffect, useMemo, useRef, useState, type Ref } from 'react';
import { t, type CopyKey } from '../../copy';
import { call, toIpcError } from '../../ipc/client';
import type { DevicesOverview } from '../../ipc/contract';
import { deviceRows, syncRowState, type DeviceRow } from '../../lib/devices';
import { shortTime } from '../../lib/format';
import { placeLabel } from '../../lib/places';
import { useShell, type Intent } from '../../app/shell';
import { useApp } from '../../ui/app';
import { Button } from '../../ui/controls';
import { ConfirmDialog } from '../../ui/Dialog';
import { Menu, More } from '../../ui/disclosure';
import { Banner, Fingerprint, KeyValues, LoadError, Section, SkeletonRows, Status } from '../../ui/feedback';
import { useLoad, usePoll } from '../../ui/hooks';
import { Icon } from '../../ui/icons';
import { PaneHeader, StaticRow } from '../../ui/layout';
import { AddMacDialog } from './AddMacDialog';
import { ConnectMenu } from './ConnectMenu';
import { EnrollCard } from './EnrollCard';
import { JoinMacDialog } from './JoinMacDialog';
import { addBlocker, macState, SELF_COPY, SELF_TONE, selfState, STATE_COPY, STATE_TONE, UNSUPPORTED_ERROR, type MacState } from './states';
import { usePairJoin } from './usePairJoin';

export const DEVICES_POLL_MS = 10_000;

type DialogState = { kind: 'add' } | { kind: 'join' } | { kind: 'remove'; row: DeviceRow } | null;

function placeOf(env: string): string {
  const [p, e] = env.split('/');
  return p && e ? placeLabel(p, e) : env;
}

export function DevicesPage({ intent }: { intent?: Intent }) {
  const { tick, go, bump, clearIntent, route } = useShell();
  const { toast, announce } = useApp();
  const data = useLoad(() => call('devices_overview'), [tick]);
  usePoll(() => data.reload(), DEVICES_POLL_MS);
  const o = data.data;
  const rows = useMemo(() => (o ? deviceRows(o) : []), [o]);
  const link = o?.link ?? null;
  const [open, setOpen] = useState<string | null>(route.item ?? null);
  const [dialog, setDialog] = useState<DialogState>(null);
  const [enrollNote, setEnrollNote] = useState<CopyKey | null>(null);
  const enrollRef = useRef<HTMLElement>(null);
  const pj = usePairJoin(() => { data.reload(); bump(); });

  const focusEnroll = (note: CopyKey | null) => {
    setOpen(null); setEnrollNote(note);
    setTimeout(() => enrollRef.current?.focus({ preventScroll: false }), 60);
  };

  const add = () => {
    const why = addBlocker(link);
    if (!why) { setDialog({ kind: 'add' }); return; }
    if (why === 'mac.needEnroll') { focusEnroll('mac.enroll.focus'); return; }
    toast(t(why), 'warn');
  };

  // intents from elsewhere (onboarding, settings); pair-add waits until the link state is known
  useEffect(() => {
    if (!intent) return;
    if (intent === 'pair-join') { setDialog({ kind: 'join' }); clearIntent(); return; }
    if (intent === 'enroll') { focusEnroll(null); clearIntent(); return; }
    if (intent === 'pair-add' && link) {
      if (addBlocker(link) === null) setDialog({ kind: 'add' });
      else focusEnroll(link.enrolled ? null : 'mac.enroll.focus');
      clearIntent();
    }
  }, [intent, link]);

  const conflict = rows.some((r) => r.state === 'conflict');
  const row = open ? rows.find((r) => r.key === open) ?? null : null;
  const removing = dialog?.kind === 'remove' ? dialog.row : null;
  const back = () => { setOpen(null); setTimeout(() => document.querySelector<HTMLElement>(`[data-mac="${CSS.escape(open ?? '')}"]`)?.focus(), 0); };

  return (
    <div className="page mac-page">
      <section className="pane" aria-label={row ? row.name : t('mac.title')}>
        <PaneHeader title={t('mac.title')} onBack={row ? back : undefined}
          actions={row
            ? <Menu label={t('mac.more.aria', { name: row.name })} items={[{ label: t('mac.remove'), icon: 'close', danger: true, onSelect: () => setDialog({ kind: 'remove', row }) }]} />
            : <ConnectMenu blocker={addBlocker(link)} onAdd={add} onJoin={() => setDialog({ kind: 'join' })} />} />
        <div className="pane-body">
          <div className="pane-content">
            {o?.devices_error && <Banner tone="warn">{t('mac.err.records')}</Banner>}
            {conflict && !row && (
              <Banner tone="warn" action={<Button size="sm" tone="secondary" onClick={() => go('activity', { view: 'alerts' })}>{t('mac.conflict.go')}</Button>}>
                {t('mac.conflict.help')}
              </Banner>
            )}
            {!o && data.loading && <SkeletonRows n={3} />}
            {!o && !data.loading && data.error && <LoadError error={data.error} onRetry={data.reload} />}
            {o && row && <MacDetail o={o} row={row} />}
            {o && !row && (
              <>
                <SelfSection o={o} enrollRef={enrollRef} enrollNote={enrollNote}
                  onEnrolled={() => { const m = t('mac.toast.enrolled'); toast(m, 'ok'); announce(m); setEnrollNote(null); data.reload(); bump(); }}
                  onRetry={data.reload} />
                <Section title={t('mac.others')} id="mac-others">
                  {rows.length === 0
                    ? <p className="mac-empty">{t('mac.empty')}</p>
                    : (
                      <div className="rows" role="list" aria-labelledby="mac-others">
                        {rows.map((r) => {
                          const st = macState(r);
                          return (
                            <div role="listitem" key={r.key} className="mac-row-wrap">
                              <button type="button" className="srow is-button mac-row" data-mac={r.key} onClick={() => setOpen(r.key)}>
                                <Icon name="laptop" size={18} />
                                <span className="srow-main">
                                  <span className="srow-title">{r.name}</span>
                                  <span className="srow-meta">{r.linkOnly ? t('mac.linkOnly') : t('mac.places', { n: r.envs.length })}</span>
                                </span>
                                <span className="srow-end">
                                  <Status tone={STATE_TONE[st]} pulse={st === 'syncing'}>{t(STATE_COPY[st])}</Status>
                                  <Icon name="chevron-right" size={13} className="mac-row-chevron" />
                                </span>
                              </button>
                            </div>
                          );
                        })}
                      </div>
                    )}
                </Section>
              </>
            )}
          </div>
        </div>
      </section>

      <AddMacDialog open={dialog?.kind === 'add'} link={link} onClose={() => { setDialog(null); data.reload(); }} onChanged={data.reload} />
      <JoinMacDialog open={dialog?.kind === 'join'} pj={pj} onClose={() => { setDialog(null); data.reload(); bump(); }} />
      <ConfirmDialog open={!!removing} title={t('mac.remove.title', { name: removing?.name ?? '' })} description={t('mac.remove.sub')}
        confirmLabel={t('mac.remove')} tone="danger" needPass={!!removing && removing.envs.length > 0}
        warn={t('mac.remove.warn')} info={t('mac.remove.note')} onClose={() => setDialog(null)}
        errorFor={(e): CopyKey | null => {
          const r = toIpcError(e).reason;
          return r === 'cannot_remove_owner' ? 'mac.remove.owner' : r === 'remove_partial' ? 'mac.remove.partial' : r === 'link_revoke_failed' ? 'mac.remove.linkFailed' : null;
        }}
        run={async (pass) => {
          if (!removing) return;
          const out = await call('device_remove', {
            ...(removing.fingerprint ? { fingerprint: removing.fingerprint } : {}),
            ...(removing.linkId ? { link_device_id: removing.linkId } : {}),
            ...(removing.envs.length ? { admin_passphrase: pass } : {}),
          });
          data.reload(); bump();
          if (out.failed.length) {
            throw { error: 'StateError', reason: out.failed.some((f) => f.reason === 'cannot_remove_owner') ? 'cannot_remove_owner' : 'remove_partial' };
          }
          if (out.link_error) throw { error: 'StateError', reason: 'link_revoke_failed' };
          toast(t('mac.toast.removed'), 'ok');
          setOpen(null); setDialog(null);
        }}>
        {removing?.fingerprint && <div className="mac-remove-fp"><span className="muted text-sm">{t('mac.kv.fingerprint')}</span><Fingerprint value={removing.fingerprint} /></div>}
      </ConfirmDialog>
    </div>
  );
}

function SelfSection({ o, enrollRef, enrollNote, onEnrolled, onRetry }: {
  o: DevicesOverview; enrollRef: Ref<HTMLElement>; enrollNote: CopyKey | null; onEnrolled(): void; onRetry(): void;
}) {
  const link = o.link;
  const st = selfState(link);
  return (
    <section className="mac-self" aria-labelledby="mac-self-title">
      <div className="mac-head">
        <h2 className="detail-title" id="mac-self-title">{link.device_name || t('mac.self')}</h2>
        <div className="detail-sub">
          <span>{t('mac.self')}</span>
          <Status tone={SELF_TONE[st]}>{t(SELF_COPY[st])}</Status>
        </div>
      </div>
      {st === 'unavailable' && <p className="mac-note">{t('mac.unavailable')}</p>}
      {st === 'down' && (
        <Banner tone="warn" action={<Button size="sm" tone="secondary" icon="refresh" onClick={onRetry}>{t('act.retry')}</Button>}>
          {t('mac.down')}{link.problem && <span className="mono muted"> · {t('mac.down.code', { code: link.problem })}</span>}
        </Banner>
      )}
      {st === 'revoked' && <Banner tone="danger">{t('devices.revoked')}</Banner>}
      {st === 'unenrolled' && <EnrollCard ref={enrollRef} link={link} onEnrolled={onEnrolled} note={enrollNote} />}
      {(st === 'online' || st === 'offline' || st === 'revoked') && (
        <div className="rows">
          <StaticRow title={t('mac.kv.server')} end={<span className="mono text-sm">{link.service_host}</span>} />
          {!!o.self_fingerprint && <StaticRow title={t('mac.kv.fingerprint')} end={<Fingerprint value={o.self_fingerprint} short />} />}
        </div>
      )}
      {st !== 'unenrolled' && st !== 'unavailable' && link.device_id && (
        <More label={t('mac.diag')}>
          <KeyValues dense items={[
            { k: t('mac.diag.linkId'), v: link.device_id, mono: true },
            !!o.self_fingerprint && { k: t('mac.kv.fingerprint'), v: <Fingerprint value={o.self_fingerprint} /> },
          ]} />
        </More>
      )}
    </section>
  );
}

interface PlaceRow { env: string; state: MacState | 'removed' | 'unread'; lastContact: string | null; nextAttempt: string | null; conflicts: number }

function placeRows(o: DevicesOverview, row: DeviceRow): PlaceRow[] {
  return row.envs.map((env) => {
    const ev = o.envs.find((e) => e.env === env);
    const member = ev?.members?.members.find((m) => m.fingerprint === row.fingerprint);
    if (member && member.status !== 'active') return { env, state: 'removed', lastContact: null, nextAttempt: null, conflicts: 0 };
    const sp = ev?.sync?.peers.find((p) => p.fingerprint === row.fingerprint) ?? null;
    const conflicts = ev?.sync && Number.isFinite(ev.sync.conflicts) ? ev.sync.conflicts : 0;
    let state: PlaceRow['state'];
    if (!ev || (!ev.sync && (ev.sync_error || ev.members_error))) state = 'unread';
    else if (conflicts > 0) state = 'conflict';
    else if (sp?.last_error === UNSUPPORTED_ERROR) state = 'unsupported';
    else state = sp ? syncRowState(sp) : 'waiting';
    return { env, state, lastContact: sp?.last_contact_at ?? null, nextAttempt: sp?.next_attempt_at ?? null, conflicts };
  });
}

function MacDetail({ o, row }: { o: DevicesOverview; row: DeviceRow }) {
  const { go } = useShell();
  const st = macState(row);
  const d = row.detail;
  const places = placeRows(o, row);
  return (
    <>
      <div className="mac-head">
        <h2 className="detail-title wrap-anywhere" tabIndex={-1} data-autofocus="">{row.name}</h2>
        <div className="detail-sub">
          <Status tone={STATE_TONE[st]} pulse={st === 'syncing'}>{t(STATE_COPY[st])}</Status>
          {row.linkOnly && <span>{t('mac.linkOnly')}</span>}
        </div>
      </div>
      {st === 'unsupported' && <Banner tone="warn">{t('mac.unsupported.help')}</Banner>}
      {st === 'conflict' && (
        <Banner tone="warn" action={<Button size="sm" tone="secondary" onClick={() => go('activity', { view: 'alerts' })}>{t('mac.conflict.go')}</Button>}>
          {t('mac.conflict.help')}
        </Banner>
      )}
      {row.fingerprint && (
        <div className="mac-fp">
          <span className="mac-fp-label">{t('mac.kv.fingerprint')}</span>
          <Fingerprint value={row.fingerprint} />
        </div>
      )}
      {!row.linkOnly && (
        <Section title={t('mac.detail.places')}>
          {places.length === 0
            ? <p className="mac-note">{t('mac.detail.noPlaces')}</p>
            : (
              <div className="rows">
                {places.map((p) => (
                  <StaticRow key={p.env} title={placeOf(p.env)}
                    meta={p.state === 'removed' ? t('mac.detail.removed') : p.state === 'unread' ? t('mac.detail.unread')
                      : [p.lastContact ? t('mac.detail.lastContact', { time: shortTime(p.lastContact) }) : t('mac.detail.never'),
                        p.nextAttempt && (p.state === 'retrying' || p.state === 'offline') ? t('mac.detail.nextAttempt', { time: shortTime(p.nextAttempt) }) : null,
                        p.conflicts > 0 ? t('mac.detail.conflicts', { n: p.conflicts }) : null].filter(Boolean).join(' · ')}
                    end={p.state === 'removed' || p.state === 'unread'
                      ? <Status tone="neutral">{t(p.state === 'removed' ? 'mac.detail.removed' : 'state.unknown')}</Status>
                      : <Status tone={STATE_TONE[p.state]} pulse={p.state === 'syncing'}>{t(STATE_COPY[p.state])}</Status>} />
                ))}
              </div>
            )}
        </Section>
      )}
      <More label={t('mac.diag')}>
        <KeyValues dense items={[
          { k: t('mac.diag.path'), v: d.path === null ? t('mac.diag.none') : <>{t(d.path === 'direct' ? 'mac.diag.direct' : 'mac.diag.relay')}{d.pathLabel && <span className="mono muted"> {d.pathLabel}</span>}</> },
          { k: t('mac.diag.rtt'), v: d.rttMs === null ? t('mac.diag.none') : t('mac.diag.ms', { n: d.rttMs }), mono: d.rttMs !== null },
          { k: t('mac.diag.transport'), v: d.transport ?? t('mac.diag.none'), mono: !!d.transport },
          { k: t('mac.diag.error'), v: d.lastError ?? t('mac.diag.none'), mono: !!d.lastError },
          !!row.linkId && { k: t('mac.diag.linkId'), v: row.linkId, mono: true },
        ]} />
      </More>
    </>
  );
}
