// 내 Mac (docs/remote-sync.md §4): this Mac at the link service, the Macs paired with it and how
// far each one has synced, adding a Mac with a one-time code that must be approved here, and
// joining another Mac's vault with its code. Everything is read from the core
// (`devices_overview`, re-read every 10 s while the window is visible); names come from other
// Macs and are rendered as text. How a Mac is connected (direct or relayed, timings, error
// codes) is only under 고급 진단.

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
import { Badge, Banner, EmptyState, Fingerprint, KeyValues, LoadError, Section, SkeletonRows, Status } from '../../ui/feedback';
import { useLoad, usePoll } from '../../ui/hooks';
import { IconTile, ListRow, PaneHeader, StaticRow, useListKeys } from '../../ui/layout';
import { AddMacDialog } from './AddMacDialog';
import { EnrollCard } from './EnrollCard';
import { JoinMacDialog } from './JoinMacDialog';
import { addBlocker, macState, SELF_COPY, SELF_TONE, selfState, STATE_COPY, STATE_TONE, UNSUPPORTED_ERROR, type MacState } from './states';
import { usePairJoin } from './usePairJoin';

export const DEVICES_POLL_MS = 10_000;
const SELF = 'self';

type DialogState = { kind: 'add' } | { kind: 'join' } | { kind: 'remove'; row: DeviceRow } | null;

function placeOf(env: string): string {
  const [p, e] = env.split('/');
  return p && e ? placeLabel(p, e) : env;
}

export function DevicesPage({ intent }: { intent?: Intent }) {
  const { tick, go, bump, clearIntent, narrow, route } = useShell();
  const { toast, announce } = useApp();
  const data = useLoad(() => call('devices_overview'), [tick]);
  usePoll(() => data.reload(), DEVICES_POLL_MS);
  const o = data.data;
  const rows = useMemo(() => (o ? deviceRows(o) : []), [o]);
  const link = o?.link ?? null;
  const [sel, setSel] = useState<string>(route.item ?? SELF);
  const [detailOpen, setDetailOpen] = useState(!!route.item);
  const [dialog, setDialog] = useState<DialogState>(null);
  const [enrollNote, setEnrollNote] = useState<CopyKey | null>(null);
  const enrollRef = useRef<HTMLElement>(null);
  const pj = usePairJoin(() => { data.reload(); bump(); });

  const ids = useMemo(() => [SELF, ...rows.map((r) => r.key)], [rows]);
  const selected = ids.includes(sel) ? sel : SELF;
  const select = (id: string) => { setSel(id); setDetailOpen(true); };
  const keys = useListKeys(ids, selected, select);

  const focusEnroll = (note: CopyKey | null) => {
    setSel(SELF); setDetailOpen(true); setEnrollNote(note);
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
  const row = rows.find((r) => r.key === selected) ?? null;
  const single = narrow.single;
  const listHidden = single && detailOpen;
  const detailHidden = single && !detailOpen;
  const removing = dialog?.kind === 'remove' ? dialog.row : null;

  return (
    <div className={'page mac-page' + (single ? ' is-single' : '')}>
      <section className={'pane pane-list' + (listHidden ? ' is-hidden' : '')} aria-label={t('mac.list')}>
        <PaneHeader title={t('mac.title')} actions={<>
          <Button size="sm" tone="ghost" icon="link" onClick={() => setDialog({ kind: 'join' })}>{t('mac.join')}</Button>
          <Button size="sm" tone="primary" icon="plus" blocked={addBlocker(link) !== null} onBlocked={add} onClick={add}>{t('mac.add')}</Button>
        </>} />
        <div className="pane-body">
          {!o && data.loading && <SkeletonRows n={3} />}
          {!o && !data.loading && data.error && <div className="pane-toolbar"><LoadError error={data.error} onRetry={data.reload} /></div>}
          {o && (
            <div role="listbox" aria-label={t('mac.list')} className="list" onKeyDown={keys}>
              <div className="list-group-head" aria-hidden="true">{t('mac.self')}</div>
              <SelfRow o={o} selected={selected === SELF} onSelect={() => select(SELF)} />
              <div className="list-group-head" aria-hidden="true">{t('mac.others')}</div>
              {rows.map((r) => {
                const st = macState(r);
                return (
                  <ListRow key={r.key} id={r.key} selected={selected === r.key} onSelect={() => select(r.key)}
                    lead={<IconTile icon="laptop" />} title={r.name}
                    meta={<Status tone={STATE_TONE[st]} pulse={st === 'syncing'}>{t(STATE_COPY[st])}</Status>}
                    end={<span className="text-xs">{r.linkOnly ? '' : t('mac.places', { n: r.envs.length })}</span>} />
                );
              })}
              {rows.length === 0 && (
                <EmptyState compact icon="laptop" title={t('mac.empty')}>{t('mac.empty.sub')}</EmptyState>
              )}
            </div>
          )}
        </div>
      </section>
      <section className={'pane pane-detail' + (detailHidden ? ' is-hidden' : '')} aria-label={row ? row.name : t('mac.self')}>
        <PaneHeader level={2} title={row ? row.name : t('mac.self')} onBack={single ? () => setDetailOpen(false) : undefined}
          actions={row ? <Button size="sm" tone="ghost" icon="close" onClick={() => setDialog({ kind: 'remove', row })}>{t('mac.remove')}</Button> : undefined} />
        <div className="pane-body">
          <div className="pane-content">
            {o?.devices_error && <Banner tone="warn">{t('mac.err.records')}</Banner>}
            {conflict && (
              <Banner tone="warn" action={<Button size="sm" tone="secondary" onClick={() => go('activity', { view: 'alerts' })}>{t('mac.conflict.go')}</Button>}>
                {t('mac.conflict.help')}
              </Banner>
            )}
            {!o && data.loading && <SkeletonRows n={2} />}
            {!o && !data.loading && data.error && <LoadError error={data.error} onRetry={data.reload} />}
            {o && !row && (
              <SelfDetail o={o} enrollRef={enrollRef} enrollNote={enrollNote}
                onEnrolled={() => { const m = t('mac.toast.enrolled'); toast(m, 'ok'); announce(m); setEnrollNote(null); data.reload(); bump(); }}
                onRetry={data.reload} />
            )}
            {o && row && <MacDetail o={o} row={row} />}
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
          setSel(SELF); setDialog(null);
        }}>
        {removing?.fingerprint && <div className="mac-remove-fp"><span className="muted text-sm">{t('mac.kv.fingerprint')}</span><Fingerprint value={removing.fingerprint} /></div>}
      </ConfirmDialog>
    </div>
  );
}

function SelfRow({ o, selected, onSelect }: { o: DevicesOverview; selected: boolean; onSelect(): void }) {
  const st = selfState(o.link);
  return (
    <ListRow id={SELF} selected={selected} onSelect={onSelect} lead={<IconTile icon="laptop" />}
      title={o.link.device_name || t('mac.self')}
      meta={<Status tone={SELF_TONE[st]}>{t(SELF_COPY[st])}</Status>}
      end={<Badge tone="accent">{t('mac.self')}</Badge>} />
  );
}

function SelfDetail({ o, enrollRef, enrollNote, onEnrolled, onRetry }: {
  o: DevicesOverview; enrollRef: Ref<HTMLElement>; enrollNote: CopyKey | null; onEnrolled(): void; onRetry(): void;
}) {
  const link = o.link;
  const st = selfState(link);
  return (
    <>
      <div className="detail-head">
        <IconTile icon="laptop" size="lg" />
        <div className="grow">
          <h3 className="detail-title">{link.device_name || t('mac.self')}</h3>
          <div className="detail-sub"><Status tone={SELF_TONE[st]}>{t(SELF_COPY[st])}</Status></div>
        </div>
      </div>
      {st === 'unavailable' && <Banner tone="neutral">{t('mac.unavailable')}</Banner>}
      {st === 'down' && (
        <Banner tone="warn" action={<Button size="sm" tone="secondary" icon="refresh" onClick={onRetry}>{t('act.retry')}</Button>}>
          {t('mac.down')}{link.problem && <span className="mono muted"> · {t('mac.down.code', { code: link.problem })}</span>}
        </Banner>
      )}
      {st === 'revoked' && <Banner tone="danger">{t('devices.revoked')}</Banner>}
      {st === 'unenrolled' && <EnrollCard ref={enrollRef} link={link} onEnrolled={onEnrolled} note={enrollNote} />}
      {(st === 'online' || st === 'offline' || st === 'revoked') && (
        <Section title={t('mac.self')}>
          <div className="card card-pad">
            <KeyValues items={[
              { k: t('mac.kv.name'), v: link.device_name },
              { k: t('mac.kv.server'), v: link.service_host, mono: true },
              { k: t('mac.kv.serverState'), v: <Status tone={SELF_TONE[st]}>{t(SELF_COPY[st])}</Status> },
              !!o.self_fingerprint && { k: t('mac.kv.fingerprint'), v: <Fingerprint value={o.self_fingerprint} /> },
            ]} />
          </div>
          <p className="field-note">{t('mac.server.note')}</p>
        </Section>
      )}
      {st !== 'unenrolled' && st !== 'unavailable' && link.device_id && (
        <details className="mac-disclosure">
          <summary>{t('mac.diag')}</summary>
          <KeyValues dense items={[{ k: t('mac.diag.linkId'), v: link.device_id, mono: true }]} />
        </details>
      )}
    </>
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
  const st = macState(row);
  const d = row.detail;
  const places = placeRows(o, row);
  return (
    <>
      <div className="detail-head">
        <IconTile icon="laptop" size="lg" />
        <div className="grow">
          <h3 className="detail-title wrap-anywhere">{row.name}</h3>
          <div className="detail-sub">
            <Badge tone={STATE_TONE[st]}>{t(STATE_COPY[st])}</Badge>
            {row.linkOnly && <span>{t('mac.linkOnly')}</span>}
          </div>
        </div>
      </div>
      {st === 'unsupported' && <Banner tone="warn">{t('mac.unsupported.help')}</Banner>}
      {row.fingerprint && (
        <div className="card card-pad mac-fp-card">
          <span className="muted text-sm">{t('mac.kv.fingerprint')}</span>
          <Fingerprint value={row.fingerprint} />
        </div>
      )}
      {!row.linkOnly && (
        <Section title={t('mac.detail.places')}>
          {places.length === 0
            ? <p className="muted text-sm">{t('mac.detail.noPlaces')}</p>
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
      <details className="mac-disclosure">
        <summary>{t('mac.diag')}</summary>
        <KeyValues dense items={[
          { k: t('mac.diag.path'), v: d.path === null ? t('mac.diag.none') : <>{t(d.path === 'direct' ? 'mac.diag.direct' : 'mac.diag.relay')}{d.pathLabel && <span className="mono muted"> {d.pathLabel}</span>}</> },
          { k: t('mac.diag.rtt'), v: d.rttMs === null ? t('mac.diag.none') : t('mac.diag.ms', { n: d.rttMs }), mono: d.rttMs !== null },
          { k: t('mac.diag.transport'), v: d.transport ?? t('mac.diag.none'), mono: !!d.transport },
          { k: t('mac.diag.error'), v: d.lastError ?? t('mac.diag.none'), mono: !!d.lastError },
          !!row.linkId && { k: t('mac.diag.linkId'), v: row.linkId, mono: true },
        ]} />
      </details>
    </>
  );
}
