import { useEffect, useRef, useState } from 'react';
import { t, tLines, type CopyKey, type CopyLine } from '../copy';
import { call, toIpcError } from '../ipc/client';
import type { NetInterface } from '../ipc/contract';
import { addressChoices, DEFAULT_GATEWAY_PORT, MIN_GATEWAY_PORT, parseListen, parsePort, settingsFields, type SettingsFields } from '../lib/dash';
import { restoreErrorKey } from '../lib/reasons';
import { useApp } from '../ui/context';
import { SelectField, TextField } from '../ui/fields';
import { Callout } from '../ui/form';
import { ConfirmSheet } from './Confirm';
import { useClearOnClose, useDash, useIntent, useLoad, useSheets, type Intent } from './context';
import { Empty, SectionHead } from './parts';
import { listenErrorLines, readSettings, relayLeftOff, resetSettings, restartRelay, turnOnListen } from './relay';
import { Sheet } from './Sheet';

type SetSheet = { kind: 'restore' } | { kind: 'ack' } | { kind: 'recover' } | { kind: 'reset' };
const CANCELLED = new Set(['file_dialog_cancelled']);

/** Settings: the relay port, this device's address for other devices, backup, restore and
 *  replacing the device key with the recovery code. Files are picked in native dialogs owned by
 *  the core. The sidebar sends the user here to acknowledge a restore (`ack-restore`). A settings
 *  file the core refuses as damaged is never reset on its own: the page says so and offers to
 *  write the defaults over it, after a confirmation. */
export function SettingsPage({ intent, onIntent }: { intent?: Intent; onIntent(): void }) {
  const { tick, bump, control, serve, relay } = useDash();
  const { toast } = useApp();
  const [n, setN] = useState(0);
  const load = useLoad(async () => {
    const [s, i] = await Promise.all([readSettings(), call('net_interfaces').catch(() => [] as NetInterface[])]);
    return { ...s, interfaces: i };
  }, [tick, n]);
  const reload = () => setN((x) => x + 1);
  const sheets = useSheets<SetSheet>();
  const s = load.data?.settings ?? null;
  const corrupt = load.data?.corrupt === true;
  const unread = t(corrupt ? 'set.corrupt' : load.failed ? 'error.load' : 'boot.loading');
  const ifaces = load.data?.interfaces ?? [];
  const listen = parseListen(s?.team_listen);
  useIntent(intent, onIntent, (i) => {
    if (i !== 'ack-restore') return false;
    if (control.restore_pending) sheets.open({ kind: 'ack' });
    return true;
  });

  const [fields, setFields] = useState<SettingsFields | null>(null);
  const { port = '', ip = '', tport = '' } = fields ?? {};
  const setField = (k: keyof SettingsFields, v: string) => setFields((f) => ({ ...(f ?? { port: '', ip: '', tport: '' }), [k]: v }));
  const [portErr, setPortErr] = useState<CopyKey | null>(null);
  const [tErr, setTErr] = useState<CopyLine[] | null>(null);
  const [busy, setBusy] = useState<'port' | 'listen' | 'backup' | null>(null);
  // after the device key is replaced, earlier backups no longer restore: ask for a new one
  const [needBackup, setNeedBackup] = useState(false);
  const portRef = useRef<HTMLInputElement>(null);
  const tportRef = useRef<HTMLInputElement>(null);

  // fill the fields when the settings first arrive; later loads leave them as the user left them
  useEffect(() => { if (s) setFields((f) => settingsFields(f, s, ifaces)); }, [s, ifaces]);

  /** Restart the relay after a saved change; a relay that does not come back shows why. */
  const restart = async (done: CopyKey) => {
    try {
      await relay.run(restartRelay);
      toast(t(done));
    } catch (e) {
      relay.report(e);
    }
    reload(); bump();
  };

  const savePort = async () => {
    if (!s) return;
    const p = parsePort(port, MIN_GATEWAY_PORT);
    if (p === null) { setPortErr('set.port.err'); portRef.current?.focus(); return; }
    // the same port: nothing to save, but a relay that is off is started on it
    if (p === s.gateway_port) { if (!serve.running && !relay.busy) void relay.start(); return; }
    setBusy('port');
    try {
      await call('settings_set', { gateway_port: p, team_listen: s.team_listen });
    } catch (e) {
      setPortErr(toIpcError(e).reason === 'invalid_port' ? 'set.port.err' : 'error.generic');
      portRef.current?.focus();
      setBusy(null);
      return;
    }
    await restart('toast.set.saved');
    setBusy(null);
  };

  // on: the relay is started with the new address, and an address it cannot open is taken back
  // (./relay.ts); off is asked first, since team changes stop arriving (the dashboard's sheet)
  const listenOn = async () => {
    if (!s || busy) return;
    const p = parsePort(tport);
    if (p === null || !ip) { setTErr([{ key: 'set.listen.port.err' }]); tportRef.current?.focus(); return; }
    setBusy('listen'); setTErr(null);
    try {
      await relay.run(() => turnOnListen(ip, p));
      toast(t('toast.listen.on'));
    } catch (e) {
      setTErr(listenErrorLines(e));
      const down = relayLeftOff(e);
      if (down) relay.report(down);
      tportRef.current?.focus();
    }
    reload(); bump();
    setBusy(null);
  };

  const backup = async () => {
    setBusy('backup');
    try {
      await call('backup_create');
      toast(t('toast.backup.done'));
      setNeedBackup(false);
    } catch (e) {
      if (!CANCELLED.has(toIpcError(e).reason)) toast(t('error.generic'), 'warn');
    } finally { setBusy(null); }
  };

  return (
    <>
      <SectionHead title={t('set.relay')} />
      <div className="glass pad">
        {!s ? (
          corrupt ? (
            <Callout kind="info" className="flush">
              {t('set.corrupt')}{' '}
              <button className="btn btn-ghost btn-sm" type="button" onClick={() => sheets.open({ kind: 'reset' })}>{t('set.reset')}</button>
            </Callout>
          ) : <Empty text={unread} />
        ) : (
          <div className="inline">
            <TextField id="set-port" label={t('set.port')} hint={t('set.port.hint')} mono value={port} inputRef={portRef} inputMode="numeric" maxLength={5}
              error={portErr ? t(portErr) : null} onChange={(v) => { setField('port', v); setPortErr(null); }} />
            <button className="btn btn-ghost btn-sm tall" type="button" aria-busy={busy === 'port' || undefined} onClick={() => void savePort()}>{t('set.save')}</button>
          </div>
        )}
      </div>

      <SectionHead title={t('inv.pre1')} />
      <div className="glass pad">
        {!s ? <Empty text={unread} /> : (
          <>
            <div className={'share-state' + (listen ? ' on' : '')} role="status">
              <span className="px" aria-hidden="true" />
              <span>{listen ? t('inv.pre1.on') : t('inv.pre1.off')}</span>
              {listen && <span className="mono">{`${listen.ip}:${listen.port}`}</span>}
            </div>
            <div className="inline" style={{ marginTop: 14 }}>
              <SelectField id="set-if" label={t('set.listen.iface')} mono value={ip} options={addressChoices(ifaces, ip)}
                onChange={(v) => { setField('ip', v); setTErr(null); }} style={{ flex: 1.7 }} />
              <TextField id="set-tport" label={t('conn.ssh.port')} mono value={tport} inputRef={tportRef} inputMode="numeric" maxLength={5} style={{ flex: '0 0 92px' }}
                error={tErr ? tLines(tErr) : null} onChange={(v) => { setField('tport', v); setTErr(null); }} />
              <button className="btn btn-ghost btn-sm tall" type="button" aria-busy={busy === 'listen' || undefined} onClick={() => void listenOn()}>
                {t(listen ? 'set.listen.change' : 'inv.pre1.btn')}
              </button>
              {listen && (
                <button className="btn btn-text btn-sm tall" type="button" aria-busy={relay.busy || undefined}
                  onClick={() => { if (!relay.busy) relay.confirmListenOff(); }}>{t('set.listen.off')}</button>
              )}
            </div>
            <div className="help">{t('inv.pre1.note')}</div>
          </>
        )}
      </div>

      <SectionHead title={t('set.backup')} />
      <p className="page-help">{t('set.backup.help')}</p>
      <div className="glass pad">
        {needBackup && <Callout className="flush">{t('set.recover.backupNow')}</Callout>}
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
        errorFor={(e) => restoreErrorKey(toIpcError(e).reason)}
        run={async (pass) => {
          await call('backup_restore', { admin_passphrase: pass });
          toast(t('toast.restore.done'), 'warn'); sheets.close(); bump();
        }} />
      <ConfirmSheet key={sheets.key('ack')} id="sheet-ack" open={sheets.isOpen('ack')} title={t('set.ack.title')} lead={t('set.ack.sub')}
        confirmLabel={t('set.ack.confirm')} needPass onClose={sheets.close}
        run={async (pass) => {
          const out = await call('restore_ack', { admin_passphrase: pass });
          // restore-ack lifts only the restore hold; a global stop stays until it is resumed
          toast(t(out.stopped === true ? 'toast.ack.stopped' : 'toast.ack.done'), out.stopped === true ? 'warn' : 'info'); sheets.close(); bump();
        }} />
      <ConfirmSheet key={sheets.key('reset')} id="sheet-settings-reset" open={sheets.isOpen('reset')} title={t('set.reset')}
        lead={t('set.reset.sub', { port: DEFAULT_GATEWAY_PORT })} confirmLabel={t('set.reset')} info={t('set.reset.note')} onClose={sheets.close}
        run={async () => {
          await resetSettings();
          sheets.close();
          setFields(null);
          await restart('toast.set.reset');
        }} />
      <RecoverSheet key={sheets.key('recover')} open={sheets.isOpen('recover')} onClose={sheets.close} onDone={() => { sheets.close(); setNeedBackup(true); bump(); }} />
    </>
  );
}

/** The recovery code replaces the device key file (`recover`): a new key file wraps the same
 *  data key again (rust/src/context.rs, rust/src/vault.rs `Vault::recover`), every agent
 *  permission is revoked and the handles rotate, and a backup made before it no longer restores
 *  (`backup_kms_mismatch`). It needs the current key file. It is not a response to a leaked key
 *  file: whoever holds the old file and a copy of the vault still has the data key, and so can
 *  read values stored in this vault later too (telicity-ai/zeropw#22). The sheet says to revoke
 *  every key at its service and to start a new vault (remove the app data) for new keys. The code
 *  goes to the core once. */
function RecoverSheet({ open, onClose, onDone }: { open: boolean; onClose(): void; onDone(): void }) {
  const { toast } = useApp();
  const [code, setCode] = useState('');
  const [err, setErr] = useState<CopyKey | null>(null);
  const [busy, setBusy] = useState(false);
  const ref = useRef<HTMLInputElement>(null);
  useClearOnClose(open, () => setCode(''));

  const go = async () => {
    if (!code.trim()) { setErr('set.recover.empty'); ref.current?.focus(); return; }
    setBusy(true);
    try {
      const out = await call('recover', { recovery_passphrase: code });
      setCode('');
      const n = out.grants_revoked;
      toast(typeof n === 'number' ? t('toast.recovered', { n }) : t('toast.recovered.any'), 'warn');
      onDone();
    } catch (e) {
      setCode('');
      const ipc = toIpcError(e);
      setErr(ipc.error === 'AuthFailed' ? 'set.recover.err' : ipc.reason === 'kms_missing' ? 'set.recover.noKey' : 'error.generic');
      ref.current?.focus();
    } finally { setBusy(false); }
  };

  return (
    <Sheet id="sheet-recover" open={open} title={t('set.recover')} lead={t('set.recover.sub')} primaryLabel={t('set.recover.confirm')} busy={busy}
      onPrimary={() => void go()} onClose={onClose}>
      <TextField id="recover-code" label={t('rec.own.field')} type="password" mono value={code} inputRef={ref} placeholder="ABCD-EFGH-…"
        error={err ? t(err) : null} onChange={(v) => { setCode(v); setErr(null); }} />
      <Callout>{t('set.recover.warn')}</Callout>
      <Callout kind="info">{t('set.recover.leak')}</Callout>
    </Sheet>
  );
}
