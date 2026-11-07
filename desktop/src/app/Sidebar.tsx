// The sidebar: the vault and its filters first, then this person's Macs, service connections,
// developer tools and activity, settings last. The footer says whether the local service runs
// and whether every use is stopped.

import { useMemo } from 'react';
import { t, type CopyKey } from '../copy';
import type { SecretKind } from '../ipc/contract';
import { envKey, envPairs, relayState } from '../lib/dash';
import { Button, IconButton } from '../ui/controls';
import { Icon, Mark, type IconName } from '../ui/icons';
import { kindIcon } from '../ui/layout';
import { placeLabel } from '../lib/places';
import { useShell, type Page } from './shell';

const KINDS: readonly SecretKind[] = ['password', 'api_key', 'env_var', 'ssh_private_key'];

export function Sidebar({ onStop, onResume }: { onStop(): void; onResume(): void }) {
  const { route, go, vault, control, serve, relay, lock } = useShell();
  const secrets = vault.data?.secrets ?? [];
  const counts = useMemo(() => {
    const c = new Map<string, number>();
    for (const s of secrets) {
      c.set(`kind:${s.kind}`, (c.get(`kind:${s.kind}`) ?? 0) + 1);
      const p = `place:${envKey(String(s.project), String(s.environment))}`;
      c.set(p, (c.get(p) ?? 0) + 1);
    }
    return c;
  }, [secrets]);
  const places = useMemo(() => (vault.data ? envPairs(vault.data.listing.projects) : []), [vault.data]);
  const onVault = route.page === 'vault';
  const view = onVault ? route.view ?? 'all' : null;
  const state = relayState(serve, control);

  const navItem = (page: Page, icon: IconName, label: CopyKey, dot?: 'warn' | 'danger' | 'accent' | null) => (
    <li key={page}>
      <button type="button" className="nav-item" aria-current={route.page === page ? 'page' : undefined} onClick={() => go(page)} title={t(label)}>
        <Icon name={icon} /><span className="nav-label">{t(label)}</span>
        {dot && <span className={'nav-dot' + (dot === 'danger' ? ' is-danger' : dot === 'accent' ? ' is-accent' : '')} aria-hidden="true" />}
      </button>
    </li>
  );

  return (
    <aside className="sidebar" aria-label={t('nav.aria')}>
      <div className="sidebar-top" data-tauri-drag-region="">
        <IconButton icon="lock" label={t('lock.shortcut')} size="sm" onClick={lock} />
      </div>
      <div className="sidebar-vault" data-tauri-drag-region="">
        <span className="mark"><Mark size={20} /></span>
        <span className="sidebar-vault-name truncate">{t('app.name')}</span>
      </div>
      <nav className="sidebar-scroll" aria-label={t('nav.aria')}>
        <ul className="nav-group" aria-label={t('nav.vault')}>
          <li className="nav-heading" aria-hidden="true">{t('nav.vault')}</li>
          <li>
            <button type="button" className="nav-item" aria-current={view === 'all' ? 'page' : undefined} onClick={() => go('vault', { view: 'all' })} title={t('nav.all')}>
              <Icon name="vault" /><span className="nav-label">{t('nav.all')}</span><span className="nav-count">{secrets.length || ''}</span>
            </button>
          </li>
          {KINDS.map((k) => (
            <li key={k}>
              <button type="button" className="nav-item" aria-current={view === `kind:${k}` ? 'page' : undefined} onClick={() => go('vault', { view: `kind:${k}` })} title={t(`nav.kind.${k}` as CopyKey)}>
                <Icon name={kindIcon(k)} /><span className="nav-label">{t(`nav.kind.${k}` as CopyKey)}</span><span className="nav-count">{counts.get(`kind:${k}`) || ''}</span>
              </button>
            </li>
          ))}
        </ul>
        {places.length > 1 && (
          <ul className="nav-group" aria-label={t('nav.places')}>
            <li className="nav-heading" aria-hidden="true">{t('nav.places')}</li>
            {places.map((p) => (
              <li key={p.key}>
                <button type="button" className="nav-item" aria-current={view === `place:${p.key}` ? 'page' : undefined} onClick={() => go('vault', { view: `place:${p.key}` })} title={p.key}>
                  <Icon name="folder" /><span className="nav-label">{placeLabel(p.project, p.environment)}</span><span className="nav-count">{counts.get(`place:${p.key}`) || ''}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
        <ul className="nav-group">
          {navItem('devices', 'laptop', 'nav.devices')}
          {navItem('services', 'plug', 'nav.services')}
          {navItem('developer', 'code', 'nav.developer')}
          {navItem('activity', 'activity', 'nav.activity', control.incident_open ? 'danger' : null)}
        </ul>
      </nav>
      <div className="sidebar-foot">
        <div className={'svc is-' + state} title={t('svc.what')}>
          <span className="svc-dot" aria-hidden="true" />
          <span className="svc-text">
            <span>{t(state === 'live' ? 'svc.on' : state === 'stopped' ? 'svc.stopped' : state === 'held' ? 'svc.held' : 'svc.off')}</span>

          </span>
          {!serve.running && state !== 'held' && (
            <Button size="sm" tone="ghost" icon="play" busy={relay.busy} onClick={() => void relay.start()}>{t(relay.problem ? 'act.retry' : 'svc.start')}</Button>
          )}
        </div>
        {!serve.running && relay.problem && <div className="svc-err" role="alert">{t(relay.problem.key, { reason: relay.problem.reason })}</div>}
        {state === 'held' && <Button size="sm" tone="ghost" icon="alert" onClick={() => go('settings', { view: 'backup', intent: 'ack-restore' })}>{t('svc.ack')}</Button>}
        {relay.offerListenOff && <Button size="sm" tone="ghost" onClick={relay.confirmListenOff}>{t('svc.listenOff')}</Button>}
        {control.stopped
          ? <Button size="sm" tone="ghost" icon="play" onClick={onResume}>{t('svc.resume')}</Button>
          : <Button size="sm" tone="quiet" icon="stop" className="svc-stop" onClick={onStop}>{t('svc.stopAll')}</Button>}
        <ul className="nav-group">{navItem('settings', 'settings', 'nav.settings')}</ul>
      </div>
    </aside>
  );
}

export { PERSONAL_ENV, PERSONAL_PROJECT, placeLabel } from '../lib/places';
