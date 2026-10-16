import { useEffect, useState } from 'react';
import { t, tLines, type CopyLine } from '../copy';
import type { NetInterface, ServeStatus } from '../ipc/contract';
import { DEFAULT_TEAM_PORT, defaultListenIp, interfaceLabel, parsePort } from '../lib/dash';
import { SelectField, TextField } from '../ui/fields';
import { Callout } from '../ui/form';
import { ListenError, listenErrorLines, relayLeftOff, turnOnListen } from './relay';

/** Other-device access (`team_listen`) offered where team sync needs it: right after joining a
 *  team (team page and the end of the onboarding) and on a shared environment while it is off.
 *  Without it this device's relay runs no team sync, so it never receives the team's changes
 *  (keys, revocations, removals). Picks an address from `net_interfaces` and starts the relay
 *  with it; an address the relay cannot open is taken back (./relay.ts `turnOnListen`). Works
 *  inside and outside the dashboard (no dashboard context needed). */
export function ListenSetup({ id, interfaces, onDone, onFailed, run, className, note = true }: {
  id: string; interfaces: NetInterface[];
  /** On, with the relay running again on `serve`. */
  onDone(address: string, serve: ServeStatus): void;
  /** After a failure: `relayDown` is why the relay is left off, or null when it runs again. */
  onFailed?(relayDown: unknown): void;
  /** Runs the restart (the dashboard's relay status counts it as busy); as it is when absent. */
  run?<T>(task: () => Promise<T>): Promise<T>;
  className?: string;
  /** Show why sync needs it (off where the surrounding text already says so). */
  note?: boolean;
}) {
  const [ip, setIp] = useState(() => defaultListenIp(interfaces));
  const [port, setPort] = useState(String(DEFAULT_TEAM_PORT));
  const [err, setErr] = useState<CopyLine[] | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { if (!ip && interfaces.length) setIp(defaultListenIp(interfaces)); }, [ip, interfaces]);

  const turnOn = async () => {
    if (busy) return;
    const p = parsePort(port);
    if (p === null || !ip) { setErr([{ key: 'set.listen.port.err' }]); return; }
    setBusy(true); setErr(null);
    try {
      const on = () => turnOnListen(ip, p);
      onDone(`${ip}:${p}`, await (run ? run(on) : on()));
    } catch (e) {
      setErr(listenErrorLines(e));
      if (e instanceof ListenError) onFailed?.(relayLeftOff(e));
    } finally { setBusy(false); }
  };

  const portInvalid = !!err && err.length === 1 && err[0]?.key === 'set.listen.port.err';
  return (
    <div className={'listen-setup' + (className ? ' ' + className : '')}>
      {note && <Callout kind="info">{t('sync.need')}</Callout>}
      <div className="inline">
        <SelectField id={`${id}-if`} label={t('set.listen.iface')} mono value={ip} options={interfaces.map((i) => ({ value: i.ip, label: interfaceLabel(i) }))}
          onChange={(v) => { setIp(v); setErr(null); }} style={{ flex: 1.7 }} />
        <TextField id={`${id}-port`} label={t('conn.ssh.port')} mono value={port} inputMode="numeric" maxLength={5} style={{ flex: '0 0 84px' }}
          invalid={portInvalid} describedBy={`${id}-err`} onChange={(v) => { setPort(v); setErr(null); }} />
        <button className="btn btn-ghost btn-sm tall" type="button" aria-busy={busy || undefined} onClick={() => void turnOn()}>{t('inv.pre1.btn')}</button>
      </div>
      <div className="help">{t('inv.pre1.note')}</div>
      <div className="help err" id={`${id}-err`} role="alert" hidden={!err}>{err ? tLines(err) : ''}</div>
    </div>
  );
}
