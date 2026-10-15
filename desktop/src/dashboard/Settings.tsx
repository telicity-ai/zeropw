import { useEffect, useRef, useState } from 'react';
import { t, type CopyKey } from '../copy';
import { call, toIpcError } from '../ipc/client';
import type { NetInterface } from '../ipc/contract';
import { DEFAULT_TEAM_PORT, interfaceLabel, MIN_GATEWAY_PORT, parseListen, parsePort } from '../lib/dash';
import { useApp } from '../ui/context';
import { SelectField, TextField } from '../ui/fields';
import { Callout } from '../ui/form';
import { ConfirmSheet } from './Confirm';
import { useDash, useLoad, useSheets } from './context';
import { Empty, SectionHead } from './parts';
import { Sheet } from './Sheet';
import { restartRelay } from './Team';

type SetSheet = { kind: 'restore' } | { kind: 'ack' } | { kind: 'recover' };
const CANCELLED = new Set(['file_dialog_cancelled']);

/** Settings: the relay port, this device's address for other devices, backup, restore and
 *  recovery with the recovery code. Files are picked in native dialogs owned by the core. */
export function SettingsPage() {
  const { tick, bump, control } = useDash();
  const { toast } = useApp();
  const [n, setN] = useState(0);
  const load = useLoad(async () => {
    const [s, i] = await Promise.all([call('settings_get'), call('net_interfaces').catch(() => [] as NetInterface[])]);
    return { settings: s, interfaces: i };
  }, [tick, n]);
  const reload = () => setN((x) => x + 1);
  const sheets = useSheets<SetSheet>();
  const s = load.data?.settings ?? null;
  const ifaces = load.data?.interfaces ?? [];
  const listen = parseListen(s?.team_listen);

  const [port, setPort] = useState('');
  const [portErr, setPortErr] = useState<CopyKey | null>(null);
  const [ip, setIp] = useState('');
  const [tport, setTport] = useState('');
  const [tErr, setTErr] = useState<CopyKey | null>(null);
  const [busy, setBusy] = useState<'port' | 'listen' | 'backup' | null>(null);
  const portRef = useRef<HTMLInputElement>(null);
  const tportRef = useRef<HTMLInputElement>(null);

  // fill the fields once the settings arrive
  useEffect(() => {
    if (!s) return;
    setPort((p) => p || String(s.gateway_port));
    setIp((v) => v || listen?.ip || ifaces[0]?.ip || '');
    setTport((v) => v || String(listen?.port ?? DEFAULT_TEAM_PORT));
  }, [s, listen, ifaces]);

  const savePort = async () => {
    if (!s) return;
    const p = parsePort(port, MIN_GATEWAY_PORT);
    if (p === null) { setPortErr('set.port.err'); portRef.current?.focus(); return; }
    if (p === s.gateway_port) return;
    setBusy('port');
    try {
      await call('settings_set', { gateway_port: p, team_listen: s.team_listen });
      await restartRelay();
      toast(t('toast.set.saved'));
      reload(); bump();
    } catch (e) {
      setPortErr(toIpcError(e).reason === 'invalid_port' ? 'set.port.err' : 'error.generic');
      portRef.current?.focus();
    } finally { setBusy(null); }
  };

  const setListen = async (on: boolean) => {
    if (!s) return;
    let value: string | null = null;
    if (on) {
      const p = parsePort(tport);
      if (p === null || !ip) { setTErr('set.listen.port.err'); tportRef.current?.focus(); return; }
      value = `${ip}:${p}`;
    }
    setBusy('listen');
    try {
      await call('settings_set', { gateway_port: s.gateway_port, team_listen: value });
      await restartRelay();
      toast(t(on ? 'toast.listen.on' : 'toast.listen.off'));
      reload(); bump();
    } catch (e) {
      setTErr(toIpcError(e).reason === 'invalid_listen' ? 'set.listen.port.err' : 'error.generic');
    } finally { setBusy(null); }
  };

  const backup = async () => {
    setBusy('backup');
    try {
      await call('backup_create');
      toast(t('toast.backup.done'));
    } catch (e) {
      if (!CANCELLED.has(toIpcError(e).reason)) toast(t('error.generic'), 'warn');
    } finally { setBusy(null); }
  };

  return (
    <>
      <SectionHead title={t('set.relay')} />
      <div className="glass pad">
        {!s ? <Empty text={load.failed ? t('error.load') : t('boot.loading')} /> : (
          <div className="inline">
            <TextField id="set-port" label={t('set.port')} hint={t('set.port.hint')} mono value={port} inputRef={portRef} inputMode="numeric" maxLength={5}
              error={portErr ? t(portErr) : null} onChange={(v) => { setPort(v); setPortErr(null); }} />
            <button className="btn btn-ghost btn-sm tall" type="button" aria-busy={busy === 'port' || undefined} onClick={() => void savePort()}>{t('set.save')}</button>
          </div>
        )}
      </div>

      <SectionHead title={t('inv.pre1')} />
      <div className="glass pad">
        {!s ? <Empty text={load.failed ? t('error.load') : t('boot.loading')} /> : (
          <>
            <div className={'share-state' + (listen ? ' on' : '')} role="status">
              <span className="px" aria-hidden="true" />
              <span>{listen ? t('inv.pre1.on') : t('inv.pre1.off')}</span>
              {listen && <span className="mono">{`${listen.ip}:${listen.port}`}</span>}
            </div>
            <div className="inline" style={{ marginTop: 14 }}>
              <SelectField id="set-if" label={t('set.listen.iface')} mono value={ip} options={ifaces.map((i) => ({ value: i.ip, label: interfaceLabel(i) }))}
                onChange={(v) => { setIp(v); setTErr(null); }} style={{ flex: 1.7 }} />
              <TextField id="set-tport" label={t('conn.ssh.port')} mono value={tport} inputRef={tportRef} inputMode="numeric" maxLength={5} style={{ flex: '0 0 92px' }}
                error={tErr ? t(tErr) : null} onChange={(v) => { setTport(v); setTErr(null); }} />
              <button className="btn btn-ghost btn-sm tall" type="button" aria-busy={busy === 'listen' || undefined} onClick={() => void setListen(true)}>
                {t(listen ? 'set.listen.change' : 'inv.pre1.btn')}
              </button>
              {listen && <button className="btn btn-text btn-sm tall" type="button" onClick={() => void setListen(false)}>{t('set.listen.off')}</button>}
            </div>
            <div className="help">{t('inv.pre1.note')}</div>
          </>
        )}
      </div>

      <SectionHead title={t('set.backup')} />
      <p className="page-help">{t('done.backup')}</p>
      <div className="glass pad">
        {control.restore_pending && (
          <Callout className="flush">
            {t('set.ack.pending')}{' '}
            <button className="btn btn-ghost btn-sm" type="button" onClick={() => sheets.open({ kind: 'ack' })}>{t('set.ack.title')}</button>
          </Callout>
        )}
        <div className="btn-row">
          <button className="btn btn-ghost btn-sm" type="button" aria-busy={busy === 'backup' || undefined} onClick={() => void backup()}>{t('set.backup.create')}</button>
          <button className="btn btn-ghost btn-sm" type="button" onClick={() => sheets.open({ kind: 'restore' })}>{t('set.restore')}</button>
          <button className="btn btn-text btn-sm" type="button" onClick={() => sheets.open({ kind: 'recover' })}>{t('set.recover')}</button>
        </div>
      </div>

      <ConfirmSheet key={sheets.key('restore')} id="sheet-restore" open={sheets.isOpen('restore')} title={t('set.restore')} lead={t('set.restore.sub')}
        confirmLabel={t('set.restore.confirm')} needPass warn={t('set.restore.warn')} onClose={sheets.close}
        errorFor={(e) => (CANCELLED.has(toIpcError(e).reason) ? 'set.restore.cancelled' : null)}
        run={async (pass) => {
          await call('backup_restore', { admin_passphrase: pass });
          toast(t('toast.restore.done'), 'warn'); sheets.close(); bump();
        }} />
      <ConfirmSheet key={sheets.key('ack')} id="sheet-ack" open={sheets.isOpen('ack')} title={t('set.ack.title')} lead={t('set.ack.sub')}
        confirmLabel={t('set.ack.confirm')} needPass onClose={sheets.close}
        run={async (pass) => {
          await call('restore_ack', { admin_passphrase: pass });
          toast(t('toast.ack.done')); sheets.close(); bump();
        }} />
      <RecoverSheet key={sheets.key('recover')} open={sheets.isOpen('recover')} onClose={sheets.close} onDone={() => { sheets.close(); bump(); }} />
    </>
  );
}

/** Recovery with the recovery code: only for a lost device key. The code goes to the core once. */
function RecoverSheet({ open, onClose, onDone }: { open: boolean; onClose(): void; onDone(): void }) {
  const { toast } = useApp();
  const [code, setCode] = useState('');
  const [err, setErr] = useState<CopyKey | null>(null);
  const [busy, setBusy] = useState(false);
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => { if (!open) setCode(''); }, [open]);

  const go = async () => {
    if (!code.trim()) { setErr('set.recover.empty'); ref.current?.focus(); return; }
    setBusy(true);
    try {
      await call('recover', { recovery_passphrase: code });
      setCode('');
      toast(t('toast.recovered'));
      onDone();
    } catch (e) {
      setCode('');
      setErr(toIpcError(e).error === 'AuthFailed' ? 'set.recover.err' : 'error.generic');
      ref.current?.focus();
    } finally { setBusy(false); }
  };

  return (
    <Sheet id="sheet-recover" open={open} title={t('set.recover')} lead={t('set.recover.sub')} primaryLabel={t('set.recover.confirm')} busy={busy}
      onPrimary={() => void go()} onClose={onClose}>
      <TextField id="recover-code" label={t('rec.own.field')} type="password" mono value={code} inputRef={ref} placeholder="ABCD-EFGH-…"
        error={err ? t(err) : null} onChange={(v) => { setCode(v); setErr(null); }} />
      <Callout>{t('rec.warn')}</Callout>
    </Sheet>
  );
}
