import { useEffect, useState } from 'react';
import { t, type CopyKey } from '../copy';
import { call, toIpcError } from '../ipc/client';
import type { NetInterface, Settings } from '../ipc/contract';
import { DEFAULT_TEAM_PORT, defaultListenIp, interfaceLabel, parsePort } from '../lib/dash';
import { relayError } from '../lib/reasons';
import { SelectField, TextField } from '../ui/fields';
import { Callout } from '../ui/form';
import { turnOnListen } from './relay';

/** Other-device access (`team_listen`) offered where team sync needs it: right after joining a
 *  team (team page and the end of the onboarding) and on a shared environment while it is off.
 *  Without it this device's relay runs no team sync, so it never receives the team's changes
 *  (keys, revocations, removals). Picks an address from `net_interfaces`, saves it and restarts
 *  the relay. Works inside and outside the dashboard (no dashboard context needed). */
export function ListenSetup({ id, settings, interfaces, onDone, className, note = true }: {
  id: string; settings: Settings | null; interfaces: NetInterface[]; onDone(address: string): void; className?: string;
  /** Show why sync needs it (off where the surrounding text already says so). */
  note?: boolean;
}) {
  const [ip, setIp] = useState(() => defaultListenIp(interfaces));
  const [port, setPort] = useState(String(DEFAULT_TEAM_PORT));
  const [err, setErr] = useState<{ key: CopyKey; reason?: string } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { if (!ip && interfaces.length) setIp(defaultListenIp(interfaces)); }, [ip, interfaces]);

  const turnOn = async () => {
    if (busy) return;
    const p = parsePort(port);
    if (p === null || !ip) { setErr({ key: 'set.listen.port.err' }); return; }
    setBusy(true); setErr(null);
    try {
      const current = settings ?? await call('settings_get');
      await turnOnListen(current, ip, p);
      onDone(`${ip}:${p}`);
    } catch (e) {
      const reason = toIpcError(e).reason;
      if (reason === 'invalid_listen') setErr({ key: 'set.listen.port.err' });
      else if (reason.startsWith('serve_') || reason === 'admin_binary_missing' || reason === 'invalid_port') setErr(relayError(reason));
      else setErr({ key: 'error.generic' });
    } finally { setBusy(false); }
  };

  return (
    <div className={'listen-setup' + (className ? ' ' + className : '')}>
      {note && <Callout kind="info">{t('sync.need')}</Callout>}
      <div className="inline">
        <SelectField id={`${id}-if`} label={t('set.listen.iface')} mono value={ip} options={interfaces.map((i) => ({ value: i.ip, label: interfaceLabel(i) }))}
          onChange={(v) => { setIp(v); setErr(null); }} style={{ flex: 1.7 }} />
        <TextField id={`${id}-port`} label={t('conn.ssh.port')} mono value={port} inputMode="numeric" maxLength={5} style={{ flex: '0 0 84px' }}
          invalid={err?.key === 'set.listen.port.err'} describedBy={`${id}-err`} onChange={(v) => { setPort(v); setErr(null); }} />
        <button className="btn btn-ghost btn-sm tall" type="button" aria-busy={busy || undefined} onClick={() => void turnOn()}>{t('inv.pre1.btn')}</button>
      </div>
      <div className="help">{t('inv.pre1.note')}</div>
      <div className="help err" id={`${id}-err`} role="alert" hidden={!err}>{err ? t(err.key, { reason: err.reason ?? '' }) : ''}</div>
    </div>
  );
}
