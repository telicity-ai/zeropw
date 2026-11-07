// 설정: a section list and the chosen section, like macOS System Settings. The saved settings
// fill the fields once; later reads (after a save, on focus) never refill a field under the
// user's typing. A settings file the core refuses as damaged is never reset on its own: the
// sections that need it say so and offer to write the defaults over it, after a confirmation.

import { useEffect, useMemo, useState } from 'react';
import { useShell, type Intent } from '../../app/shell';
import { t, type CopyKey } from '../../copy';
import { call } from '../../ipc/client';
import type { NetInterface } from '../../ipc/contract';
import { DEFAULT_GATEWAY_PORT, settingsFields, type SettingsFields } from '../../lib/dash';
import { readSettings, resetSettings, restartRelay } from '../../lib/relay';
import { useApp } from '../../ui/app';
import { Button } from '../../ui/controls';
import { ConfirmDialog } from '../../ui/Dialog';
import { Banner } from '../../ui/feedback';
import { useLoad } from '../../ui/hooks';
import type { IconName } from '../../ui/icons';
import { IconTile, ListRow, PaneHeader, useListKeys } from '../../ui/layout';
import { AboutSection, BackupSection, DeveloperSection, SecuritySection, ServerSection, SyncSection } from './sections';

export type SectionId = 'security' | 'server' | 'sync' | 'developer' | 'backup' | 'about';
export const SECTIONS: readonly { id: SectionId; icon: IconName }[] = [
  { id: 'security', icon: 'lock' }, { id: 'server', icon: 'server' }, { id: 'sync', icon: 'sync' },
  { id: 'developer', icon: 'code' }, { id: 'backup', icon: 'download' }, { id: 'about', icon: 'info' },
];
const isSection = (v: string | undefined): v is SectionId => SECTIONS.some((s) => s.id === v);

/** What every section shares: the saved settings, the fields typed into, and page-level flags. */
export interface SettingsCtx {
  settings: Awaited<ReturnType<typeof readSettings>>['settings'];
  corrupt: boolean;
  interfaces: NetInterface[];
  loadFailed: boolean;
  fields: SettingsFields | null;
  setField(k: keyof SettingsFields, v: string): void;
  reload(): void;
  /** Restart the local service after a saved change; a service that does not come back says why. */
  restart(done: CopyKey): Promise<void>;
  askReset(): void;
  /** The device key was just replaced: earlier backups no longer restore. */
  needBackup: boolean;
  setNeedBackup(v: boolean): void;
  go(id: SectionId): void;
}

export function SettingsPage({ intent }: { intent?: Intent }) {
  const shell = useShell();
  const { route, go, clearIntent, tick, bump, control, relay, narrow } = shell;
  const { toast } = useApp();
  const view = isSection(route.view) ? route.view : null;
  const section: SectionId = view ?? 'security';
  const showList = !narrow.single || view === null;
  const showDetail = !narrow.single || view !== null;
  const [n, setN] = useState(0);
  const reload = () => setN((x) => x + 1);
  const load = useLoad(async () => {
    const [s, i] = await Promise.all([readSettings(), call('net_interfaces').catch(() => [] as NetInterface[])]);
    return { ...s, interfaces: i };
  }, [tick, n]);
  const settings = load.data?.settings ?? null;
  const interfaces = useMemo(() => load.data?.interfaces ?? [], [load.data]);
  const [fields, setFields] = useState<SettingsFields | null>(null);
  const [needBackup, setNeedBackup] = useState(false);
  const [resetOpen, setResetOpen] = useState(false);
  const [ackOpen, setAckOpen] = useState(false);

  // fill the fields when the settings first arrive; later loads leave them as the user left them
  useEffect(() => { if (settings) setFields((f) => settingsFields(f, settings, interfaces)); }, [settings, interfaces]);

  const goSection = (id: SectionId) => go('settings', { view: id });

  useEffect(() => {
    if (!intent) return;
    if (intent === 'ack-restore') {
      go('settings', { view: 'backup' });
      if (control.restore_pending) setAckOpen(true);
    } else if (intent === 'backup' || intent === 'server') {
      go('settings', { view: intent });
    } else clearIntent();
  }, [intent, go, clearIntent, control.restore_pending]);

  const restart = async (done: CopyKey) => {
    try {
      await relay.run(restartRelay);
      toast(t(done), 'ok');
    } catch (e) { relay.report(e); }
    reload(); bump();
  };

  const ctx: SettingsCtx = {
    settings, corrupt: load.data?.corrupt === true, interfaces, loadFailed: !!load.error && !load.data, fields,
    setField: (k, v) => setFields((f) => ({ ...(f ?? { port: '', ip: '', tport: '' }), [k]: v })),
    reload, restart, askReset: () => setResetOpen(true), needBackup, setNeedBackup, go: goSection,
  };

  const ids = SECTIONS.map((s) => s.id);
  const onKeys = useListKeys(ids, view ?? (narrow.single ? null : 'security'), (id) => goSection(id as SectionId));

  return (
    <div className={'page settings' + (narrow.single ? ' is-single' : '')}>
      {showList && (
        <div className="pane pane-list">
          <PaneHeader title={t('settings.title')} />
          <div className="pane-body">
            <div className="list" role="listbox" aria-label={t('settings.sections')}>
              {SECTIONS.map((s) => (
                <ListRow key={s.id} id={s.id} selected={!narrow.single && section === s.id} onSelect={() => goSection(s.id)} onKeyDown={onKeys}
                  lead={<IconTile icon={s.icon} />} title={t(`settings.sec.${s.id}` as CopyKey)} meta={t(`settings.sec.${s.id}.sub` as CopyKey)}
                  end={s.id === 'backup' && control.restore_pending ? <span className="nav-dot" aria-hidden="true" /> : undefined} />
              ))}
            </div>
          </div>
        </div>
      )}
      {showDetail && (
        <div className="pane pane-detail">
          <PaneHeader level={narrow.single ? 1 : 2} title={t(`settings.sec.${section}` as CopyKey)}
            onBack={narrow.single ? () => go('settings') : undefined}
            actions={section === 'about' ? <Button size="sm" tone="ghost" icon="refresh" onClick={() => { reload(); bump(); }}>{t('settings.reload')}</Button> : undefined} />
          <div className="pane-body">
            <div className="pane-content settings-content" key={section}>
              {section === 'security' && <SecuritySection ctx={ctx} />}
              {section === 'server' && <ServerSection ctx={ctx} />}
              {section === 'sync' && <SyncSection ctx={ctx} />}
              {section === 'developer' && <DeveloperSection ctx={ctx} />}
              {section === 'backup' && <BackupSection ctx={ctx} onAck={() => setAckOpen(true)} />}
              {section === 'about' && <AboutSection ctx={ctx} />}
            </div>
          </div>
        </div>
      )}

      <ConfirmDialog open={resetOpen} title={t('settings.reset.title')} description={t('settings.reset.sub', { port: DEFAULT_GATEWAY_PORT })}
        confirmLabel={t('settings.reset')} info={t('settings.reset.note')} onClose={() => setResetOpen(false)}
        run={async () => {
          await resetSettings();
          setResetOpen(false);
          setFields(null);
          await restart('toast.settings.reset');
        }} />
      <ConfirmDialog open={ackOpen} title={t('settings.ack.title')} description={t('settings.ack.sub')} confirmLabel={t('settings.ack.confirm')}
        needPass onClose={() => setAckOpen(false)}
        run={async (pass) => {
          const out = await call('restore_ack', { admin_passphrase: pass });
          // restore-ack lifts only the restore hold; a global stop stays until it is resumed
          const stopped = out.stopped === true;
          toast(t(stopped ? 'toast.settings.ack.stopped' : 'toast.settings.ack'), stopped ? 'warn' : 'ok');
          setAckOpen(false); bump();
        }} />
    </div>
  );
}

/** The damaged-settings banner the sections that need the file show. */
export function CorruptBanner({ ctx }: { ctx: SettingsCtx }) {
  if (!ctx.corrupt) return null;
  return (
    <Banner tone="warn" title={t('settings.corrupt')} action={<Button size="sm" tone="secondary" onClick={ctx.askReset}>{t('settings.reset')}</Button>}>
      {t('settings.corrupt.sub')}
    </Banner>
  );
}
