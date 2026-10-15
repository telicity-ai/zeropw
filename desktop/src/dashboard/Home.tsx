import { useEffect, useState } from 'react';
import { t } from '../copy';
import { call } from '../ipc/client';
import type { Alert, Control, ServeStatus } from '../ipc/contract';
import { hostPort, shortTime } from '../lib/format';

interface Tile { k: string; v: string; s: string; st: 'on' | 'idle' | 'warn' }

/** Home: status summary and recent alerts. Alert fields come from the audit log and are rendered
 *  as text only. */
export function Home({ serve, control, refreshKey }: { serve: ServeStatus; control: Control; refreshKey: number }) {
  const [alerts, setAlerts] = useState<Alert[] | null>(null);
  const [skipped, setSkipped] = useState(0);

  useEffect(() => {
    let dead = false;
    call('alerts', { limit: 5 }).then(
      (r) => { if (!dead) { setAlerts(r.alerts.slice().reverse()); setSkipped(r.unparseable_lines); } },
      () => { if (!dead) setAlerts([]); },
    );
    return () => { dead = true; };
  }, [refreshKey]);

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
      <h2 className="section-title">{t('home.alerts')}</h2>
      <div className="glass">
        {alerts && alerts.length > 0 ? (
          <ul className="list">
            {alerts.map((a, i) => (
              <li key={`${a.ts}-${i}`} className="list-row">
                <span className="stdot warn" aria-hidden="true" />
                <div className="main">
                  <div className="name">{a.alert}</div>
                  <div className="meta">{[shortTime(a.ts), a.caller, a.connection, a.reason].filter(Boolean).join(' · ')}</div>
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <div className="empty"><span className="line"><span className="px" aria-hidden="true" />{alerts ? t('home.alerts.empty') : t('boot.loading')}</span></div>
        )}
        {skipped > 0 && <div className="help" style={{ padding: '0 18px 14px' }}>{t('home.alerts.skipped', { n: skipped })}</div>}
      </div>
    </>
  );
}
