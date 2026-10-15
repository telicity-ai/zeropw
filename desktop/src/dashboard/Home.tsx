import { t, type CopyKey } from '../copy';
import { call } from '../ipc/client';
import { hostPort, shortTime } from '../lib/format';
import { valueText } from '../lib/dash';
import { Callout } from '../ui/form';
import { useDash, useLoad, type Intent } from './context';
import type { PageId } from './pages';
import { ListCard, metaLine, Row, SectionHead } from './parts';

interface Tile { k: string; v: string; s: string; st: 'on' | 'idle' | 'warn' }
const QUICK: Array<{ label: CopyKey; page: PageId; intent: Intent }> = [
  { label: 'quick.key', page: 'keys', intent: 'add-key' },
  { label: 'quick.conn', page: 'connections', intent: 'add-connection' },
  { label: 'quick.agent', page: 'agents', intent: 'add-agent' },
  { label: 'quick.invite', page: 'team', intent: 'invite' },
];

/** Home: status summary, quick actions and recent alerts. Alert fields come from the audit log
 *  and are rendered as text only. */
export function Home() {
  const { serve, control, tick, activity, go, relay } = useDash();
  const alerts = useLoad(() => call('alerts', { limit: 5 }), [tick, activity]);
  const list = alerts.data ? alerts.data.alerts.slice().reverse() : null;
  const skipped = alerts.data?.unparseable_lines ?? 0;

  const tiles: Tile[] = [
    { k: t('home.vault'), v: t('home.vault.v'), s: t('home.vault.s'), st: 'on' },
    serve.running
      ? { k: t('home.relay'), v: t('home.relay.on'), s: hostPort(serve.url) ?? '', st: 'on' }
      : { k: t('home.relay'), v: t('home.relay.off'), s: '', st: 'idle' },
    control.restore_pending
      ? { k: t('home.control'), v: t('home.control.restore'), s: '', st: 'warn' }
      : control.stopped
        ? { k: t('home.control'), v: t('home.control.stopped'), s: '', st: 'idle' }
        : { k: t('home.control'), v: t('home.control.open'), s: '', st: 'on' },
    control.incident_open
      ? { k: t('home.incident'), v: t('home.incident.open'), s: '', st: 'warn' }
      : { k: t('home.incident'), v: t('home.incident.none'), s: '', st: 'on' },
  ];

  return (
    <>
      <div className="stat-grid">
        {tiles.map((x) => (
          <div key={x.k} className={'tile' + (x.st === 'on' ? '' : ' ' + x.st)}>
            <div className="k"><i aria-hidden="true" />{x.k}</div>
            <div className="v">{x.v}{x.s && <small>{x.s}</small>}</div>
          </div>
        ))}
      </div>
      {!serve.running && (
        <Callout kind="info" className="relay-note">
          {t('home.relay.offNote')}{' '}
          <button className="btn btn-ghost btn-sm" type="button" aria-busy={relay.busy || undefined} aria-describedby={relay.problem ? 'home-relay-err' : undefined}
            onClick={() => { if (!relay.busy) void relay.start(); }}>{t(relay.problem ? 'relay.retry' : 'relay.start')}</button>
          {relay.problem && <span className="help err" id="home-relay-err" style={{ display: 'block' }}>{t(relay.problem.key, { reason: relay.problem.reason })}</span>}
        </Callout>
      )}
      <SectionHead id="home-quick" title={t('quick.title')} />
      <div className="quick" role="group" aria-labelledby="home-quick">
        {QUICK.map((q) => (
          <button key={q.label} className="quick-btn" type="button" onClick={() => go(q.page, q.intent)}>
            <span className="px" aria-hidden="true" /><span>{t(q.label)}</span><span className="arrow" aria-hidden="true">→</span>
          </button>
        ))}
      </div>
      <SectionHead title={t('home.alerts')}>
        <button className="btn btn-text btn-sm" type="button" onClick={() => go('logs')}>{t('home.alerts.all')}</button>
      </SectionHead>
      <ListCard items={list} failed={alerts.failed} empty="home.alerts.empty" label={t('home.alerts')}>
        {(items) => items.map((a, i) => (
          <Row key={`${valueText(a.ts)}-${i}`} dot="warn" name={valueText(a.alert)}
            meta={metaLine(shortTime(valueText(a.ts)), valueText(a.caller), valueText(a.connection), valueText(a.reason))} />
        ))}
      </ListCard>
      {skipped > 0 && <div className="help">{t('home.alerts.skipped', { n: skipped })}</div>}
    </>
  );
}
