// 활동: the usage log, alerts and incidents. Records never contain values (rust/src/audit.rs);
// lib/records.ts turns their codes into plain words and keeps anything it does not know on a
// second line as the core wrote it.

import { useEffect, useMemo, useState } from 'react';
import { useShell, type Intent } from '../../app/shell';
import { t, type CopyKey } from '../../copy';
import { call, toIpcError } from '../../ipc/client';
import type { Incident } from '../../ipc/contract';
import { openIncidentScope, valueText } from '../../lib/dash';
import { shortTime } from '../../lib/format';
import { recordView, type RecordView } from '../../lib/records';
import { useApp } from '../../ui/app';
import { Button, Segmented } from '../../ui/controls';
import { ConfirmDialog } from '../../ui/Dialog';
import { Badge, Banner, EmptyState, KeyValues, LoadError, SkeletonRows } from '../../ui/feedback';
import { Icon } from '../../ui/icons';
import { useLoad } from '../../ui/hooks';
import { PaneHeader, SearchBox } from '../../ui/layout';
import { DeclareDialog, SCOPE_LABEL } from './DeclareDialog';

export type ActivityTab = 'records' | 'alerts' | 'incidents';
export const RECORD_LIMIT = 200;
const TABS: readonly ActivityTab[] = ['records', 'alerts', 'incidents'];
const tabOf = (view: string | undefined): ActivityTab => (TABS.includes(view as ActivityTab) ? (view as ActivityTab) : 'records');

export const scopeText = (s: string): string => (s in SCOPE_LABEL ? t(SCOPE_LABEL[s as keyof typeof SCOPE_LABEL]) : s);

/** A failed or refused outcome: shown in the danger colour, with its word. */
const FAILED_RESULTS = new Set(['denied', 'failed', 'blocked', 'error']);
const FAILED_EVENT = /(^auth_failed$|_denied$|_rejected$|_refused$|_failed$)/;
export function isFailure(rec: Record<string, unknown>): boolean {
  return (typeof rec.result === 'string' && FAILED_RESULTS.has(rec.result)) || (typeof rec.event === 'string' && FAILED_EVENT.test(rec.event));
}

export interface Shown {
  view: RecordView;
  conflict: boolean;
  failed: boolean;
  /** Who acted (the caller), through what (the connection), and the rest of the plain parts. */
  actor: string;
  target: string;
  details: string[];
  text: string;
}

/** Rows for a list of records or alerts: newest first, with the text a filter matches. */
export function shownRecords(list: readonly Record<string, unknown>[], kind: 'audit' | 'alert'): Shown[] {
  return list.slice().reverse().map((rec) => {
    const view = recordView(rec, kind);
    const conflict = kind === 'alert' && rec.alert === 'team_op_overridden';
    // recordView puts the caller first and the connection second when they are there
    let i = 0;
    const actor = valueText(rec.caller) ? view.meta[i++] ?? '' : '';
    const target = valueText(rec.connection) ? view.meta[i++] ?? '' : '';
    const details = view.meta.slice(i);
    return {
      view, conflict, failed: kind === 'audit' && isFailure(rec), actor, target, details,
      text: [view.title, ...view.meta, ...view.raw].join(' ').toLowerCase(),
    };
  });
}

export function ActivityPage({ intent }: { intent?: Intent }) {
  const { route, go, clearIntent, tick, activity, bump } = useShell();
  const { toast, locale } = useApp();
  const tab = tabOf(route.view);
  const setTab = (v: ActivityTab) => go('activity', { view: v });
  const [query, setQuery] = useState('');
  const [n, setN] = useState(0);
  const reload = () => setN((x) => x + 1);
  const [dialog, setDialog] = useState<{ kind: 'declare' } | { kind: 'close'; incident: Incident } | null>(null);

  useEffect(() => {
    if (!intent) return;
    if (intent === 'alerts' || intent === 'incidents') go('activity', { view: intent });
    else clearIntent();
  }, [intent, go, clearIntent]);

  const records = useLoad(() => (tab === 'records' ? call('audit_tail', { limit: RECORD_LIMIT }) : Promise.resolve(null)), [tab, tick, activity, n]);
  const alerts = useLoad(() => (tab === 'alerts' ? call('alerts', { limit: RECORD_LIMIT }) : Promise.resolve(null)), [tab, tick, activity, n]);
  const incidents = useLoad(async () => {
    if (tab !== 'incidents') return null;
    // the core decides whether an incident is open by its pointer (control), not by the files
    const [i, p, c] = await Promise.all([call('incident_list'), call('principal_list'), call('control_get')]);
    return { incidents: i.incidents.slice().reverse(), principals: p.principals, control: c };
  }, [tab, tick, activity, n]);

  const list = useMemo(() => {
    if (tab === 'records' && records.data) return shownRecords(records.data.records, 'audit');
    if (tab === 'alerts' && alerts.data) return shownRecords(alerts.data.alerts as unknown as Record<string, unknown>[], 'alert');
    return null;
  }, [tab, records.data, alerts.data, locale]);
  const q = query.trim().toLowerCase();
  const filtered = list ? (q ? list.filter((r) => r.text.includes(q)) : list) : null;
  const skipped = (tab === 'records' ? records.data?.unparseable_lines : tab === 'alerts' ? alerts.data?.unparseable_lines : 0) ?? 0;
  const anyConflict = tab === 'alerts' && !!list?.some((r) => r.conflict);
  const load = tab === 'records' ? records : alerts;
  const openScope = incidents.data ? openIncidentScope(incidents.data.incidents, incidents.data.control) : null;
  const closing = dialog?.kind === 'close' ? dialog.incident : null;

  return (
    <div className="page activity-page">
      <div className="pane">
        <PaneHeader title={t('activity.title')} actions={<>
          <Segmented<ActivityTab> label={t('activity.tabs')} value={tab} onChange={setTab} size="sm"
            options={TABS.map((v) => ({ value: v, label: t(`activity.tab.${v}` as CopyKey) }))} />
          {tab === 'incidents' && <Button size="sm" tone="secondary" icon="alert" onClick={() => setDialog({ kind: 'declare' })}>{t('activity.inc.declare')}</Button>}
        </>} />
        <div className="pane-body">
          <div className="pane-content is-wide activity">
            {tab !== 'incidents' && (
              <>
                <div className="activity-tools">
                  <SearchBox value={query} onChange={setQuery} label={t('activity.filter')} placeholder={t('activity.filter.placeholder')} />
                </div>
                {anyConflict && <Banner tone="warn" icon="conflict" title={t('activity.conflict')}>{t('activity.conflict.note')}</Banner>}
                {!filtered ? (load.error ? <LoadError error={load.error} onRetry={reload} /> : <SkeletonRows />) : filtered.length === 0 ? (
                  q ? <EmptyState compact icon="search" title={t('activity.filter.none')} />
                    : tab === 'records'
                      ? <EmptyState icon="activity" title={t('activity.records.empty')}>{t('activity.records.empty.sub')}</EmptyState>
                      : <EmptyState icon="info" title={t('activity.alerts.empty')} />
                ) : (
                  <div className="log" role="table" aria-label={t(`activity.tab.${tab}` as CopyKey)}>
                    <div className="log-head" role="row">
                      <span role="columnheader">{t('activity.col.time')}</span>
                      <span role="columnheader">{t(tab === 'alerts' ? 'activity.col.alert' : 'activity.col.event')}</span>
                      <span role="columnheader">{t('activity.col.actor')}</span>
                      <span role="columnheader">{t('activity.col.target')}</span>
                    </div>
                    {filtered.map((r, i) => <RecordRow key={i} shown={r} />)}
                    <div className="log-foot" role="row"><span role="cell">{t('activity.limit', { n: RECORD_LIMIT })}</span></div>
                  </div>
                )}
                {skipped > 0 && <p className="muted text-xs">{t('activity.skipped', { n: skipped })}</p>}
              </>
            )}
            {tab === 'incidents' && (
              !incidents.data ? (incidents.error ? <LoadError error={incidents.error} onRetry={reload} /> : <SkeletonRows />)
                : incidents.data.incidents.length === 0 ? (
                  <EmptyState icon="shield" title={t('activity.inc.empty')}
                    action={<Button tone="secondary" icon="alert" onClick={() => setDialog({ kind: 'declare' })}>{t('activity.inc.declare')}</Button>}>
                    {t('activity.inc.empty.sub')}
                  </EmptyState>
                ) : (
                  <ul className="rows" aria-label={t('activity.tab.incidents')}>
                    {incidents.data.incidents.map((x) => <IncidentItem key={x.id} incident={x} onClose={() => setDialog({ kind: 'close', incident: x })} />)}
                  </ul>
                )
            )}
          </div>
        </div>
      </div>

      <DeclareDialog key={dialog?.kind === 'declare' ? 'declare-open' : 'declare'} open={dialog?.kind === 'declare'}
        principals={incidents.data?.principals ?? []} openScope={openScope} onClose={() => setDialog(null)}
        onDone={() => { setDialog(null); reload(); bump(); }} onRefresh={() => { reload(); bump(); }}
        onAgents={() => { setDialog(null); go('developer', { view: 'agents' }); }} />
      <ConfirmDialog open={!!closing} title={t('activity.inc.close.title')} description={t('activity.inc.close.sub')}
        confirmLabel={t('activity.inc.close.confirm')} needPass info={t('activity.inc.close.note')} onClose={() => setDialog(null)}
        errorFor={(e) => (toIpcError(e).reason === 'incident_already_closed' ? 'activity.inc.err.closed' : null)}
        run={async (pass) => {
          if (!closing) return;
          await call('incident_close', { id: closing.id, admin_passphrase: pass });
          toast(t('toast.activity.closed'), 'ok'); setDialog(null); reload(); bump();
        }}>
        {closing && <KeyValues dense items={[{ k: 'ID', v: closing.id, mono: true }, { k: t('activity.inc.scope'), v: scopeText(closing.scope) }]} />}
      </ConfirmDialog>
    </div>
  );
}

function RecordRow({ shown }: { shown: Shown }) {
  const v = shown.view;
  const [open, setOpen] = useState(false);
  const more = shown.details.length > 0 || v.raw.length > 0;
  return (
    <div className={'log-row' + (shown.failed ? ' is-failed' : '') + (open ? ' is-open' : '')} role="row">
      <time className="log-time num" role="cell" dateTime={v.ts}>{shortTime(v.ts)}</time>
      <span className="log-event" role="cell">
        <span className="log-title">{v.title}</span>
        {shown.failed && <span className="log-flag">{t('activity.failed')}</span>}
        {shown.conflict && <Badge tone="warn">{t('activity.conflict')}</Badge>}
      </span>
      <span className="log-actor" role="cell">{shown.actor}</span>
      <span className="log-target" role="cell">
        <span className="truncate">{shown.target}</span>
        {more && (
          <button type="button" className="log-more" aria-expanded={open} aria-label={t(open ? 'activity.raw.hide' : 'activity.raw.show')} title={t(open ? 'activity.raw.hide' : 'activity.raw.show')}
            onClick={() => setOpen((o) => !o)}>
            <Icon name="chevron-down" size={12} />
          </button>
        )}
      </span>
      {open && (
        <div className="log-detail" role="cell">
          {shown.details.length > 0 && <span>{shown.details.join(' · ')}</span>}
          {v.raw.length > 0 && <span className="mono" data-selectable="">{v.raw.join('  ')}</span>}
        </div>
      )}
    </div>
  );
}

function IncidentItem({ incident: x, onClose }: { incident: Incident; onClose(): void }) {
  const open = x.status === 'open';
  const principals = Array.isArray(x.principals) ? (x.principals as unknown[]).map(valueText).join(', ') : '';
  const meta = [t('activity.inc.scopeOf', { scope: scopeText(x.scope) }), shortTime(x.opened_at), valueText(x.runtime), principals].filter(Boolean);
  return (
    <li className="srow">
      <div className="srow-main">
        <span className="srow-title row"><span className="mono">{x.id}</span><Badge tone={open ? 'warn' : 'neutral'}>{t(open ? 'activity.inc.open' : 'activity.inc.closed')}</Badge></span>
        <span className="srow-meta">{meta.join(' · ')}</span>
        {x.detail !== undefined && x.detail !== null && valueText(x.detail) && <span className="srow-meta mono">{valueText(x.detail)}</span>}
      </div>
      {open && (
        <div className="srow-end">
          <Button size="sm" tone="secondary" aria-label={t('activity.inc.close.aria', { id: x.id })} onClick={onClose}>{t('activity.inc.close')}</Button>
        </div>
      )}
    </li>
  );
}
