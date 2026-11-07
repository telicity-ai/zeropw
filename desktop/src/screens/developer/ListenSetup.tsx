// Other-device access (`team_listen`) where sharing needs it: on a shared place while it is off
// and right after joining. Without it the local service runs no team sync, so this Mac never
// receives the shared changes (values, revocations, removals). An address the service cannot
// open is taken back (lib/relay.ts `turnOnListen`); the lines say what failed and what runs.

import { useEffect, useRef, useState } from 'react';
import { t, tLines, type CopyLine } from '../../copy';
import type { NetInterface, ServeStatus } from '../../ipc/contract';
import { addressChoices, DEFAULT_TEAM_PORT, defaultListenIp, parsePort } from '../../lib/dash';
import { ListenError, listenErrorLines, relayLeftOff, turnOnListen } from '../../lib/relay';
import { Button, SelectField, TextField } from '../../ui/controls';
import { Banner } from '../../ui/feedback';
import { More } from '../../ui/disclosure';

export function ListenSetup({ interfaces, onDone, onFailed, run, note = true, onBusy }: {
  interfaces: NetInterface[];
  /** On, with the local service running again on `serve`. */
  onDone(address: string, serve: ServeStatus): void;
  /** After a failure that changed settings: why the service is left off, or null when it runs. */
  onFailed?(relayDown: unknown): void;
  /** Runs the restart so the sidebar counts it as busy. */
  run<T>(task: () => Promise<T>): Promise<T>;
  note?: boolean;
  onBusy?(busy: boolean): void;
}) {
  const [ip, setIp] = useState(() => defaultListenIp(interfaces));
  const [port, setPort] = useState(String(DEFAULT_TEAM_PORT));
  const [open, setOpen] = useState(interfaces.length !== 1);
  const [err, setErr] = useState<CopyLine[] | null>(null);
  const [busy, setBusy] = useState(false);
  const running = useRef(false);
  const portRef = useRef<HTMLInputElement>(null);
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => { if (!ip && interfaces.length) setIp(defaultListenIp(interfaces)); }, [ip, interfaces]);

  const portInvalid = !!err && err.length === 1 && err[0]?.key === 'set.listen.port.err';
  useEffect(() => {
    if (!portInvalid || !open) return;
    const frame = requestAnimationFrame(() => portRef.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, [portInvalid, open]);

  const turnOn = async () => {
    if (running.current) return;
    const p = parsePort(port);
    if (p === null || !ip) { setOpen(true); setErr([{ key: 'set.listen.port.err' }]); setTimeout(() => portRef.current?.focus(), 50); return; }
    running.current = true; onBusy?.(true); setBusy(true); setErr(null);
    try {
      onDone(`${ip}:${p}`, await run(() => turnOnListen(ip, p)));
    } catch (e) {
      if (!alive.current) return;
      setOpen(true);
      setErr(listenErrorLines(e));
      if (e instanceof ListenError) onFailed?.(relayLeftOff(e));
    } finally {
      running.current = false; onBusy?.(false);
      if (alive.current) setBusy(false);
    }
  };

  return (
    <div className="dev-listen">
      {note && <Banner tone="info">{t('share.listen.need')}</Banner>}
      <More label={t('share.listen.address')} hint={<span className="mono">{ip ? `${ip}:${port}` : t('share.need.listen.off')}</span>} open={open} onToggle={setOpen}>
        <div className="dev-listen-fields">
          <SelectField label={t('share.listen.iface')} value={ip} options={addressChoices(interfaces, ip)}
            onChange={(v) => { setIp(v); setErr(null); }} fieldClassName="grow" />
          <TextField label={t('share.listen.port')} mono value={port} inputRef={portRef} inputMode="numeric" maxLength={5}
            error={portInvalid ? t('set.listen.port.err') : null} fieldClassName="dev-port"
            onChange={(v) => { setPort(v); setErr(null); }} />
        </div>
      </More>
      <div className="row-wrap">
        <Button size="sm" tone="primary" busy={busy} onClick={() => void turnOn()}>{t('share.listen.on')}</Button>
        <span className="muted text-xs">{t('share.need.firewall')}</span>
      </div>
      {err && !portInvalid && <div className="field-note is-error" role="alert">{tLines(err)}</div>}
    </div>
  );
}
