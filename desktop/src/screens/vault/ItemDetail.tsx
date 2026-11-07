// One item, laid out like a macOS detail: its name and one line of kind and place, the value row
// (masked; seeing or copying it re-authenticates), a few facts, the versions, the services that
// authenticate with it and what deleting means today. Sections sit on the white surface; grouped
// lists use the light group fill, never a card inside a card.

import { t } from '../../copy';
import type { ConnectionView, SecretView, VersionId } from '../../ipc/contract';
import { sortedVersions } from '../../lib/dash';
import { shortTime } from '../../lib/format';
import { Button, IconButton } from '../../ui/controls';
import { Menu, type MenuEntry } from '../../ui/disclosure';
import { Banner, Section } from '../../ui/feedback';
import { Icon } from '../../ui/icons';
import { kindIcon, PaneHeader, StaticRow } from '../../ui/layout';
import { itemState, kindLabel, newestAt, placeOf, placeText, versionText } from './logic';
import { PublicKeyBox, versionStatusText } from './parts';

export interface DetailActions {
  reveal(version?: VersionId): void;
  copy(): void;
  replace(): void;
  retire(version: VersionId): void;
  revoke(version: VersionId): void;
  openConnection(id: string): void;
  addConnection(): void;
}

export function ItemDetail({ item, shared, conns, connsFailed, onBack, act }: {
  item: SecretView; shared: boolean; conns: readonly ConnectionView[]; connsFailed: boolean; onBack?(): void; act: DetailActions;
}) {
  const state = itemState(item);
  const versions = sortedVersions(item);
  const active = versions.find((v) => String(v.version) === String(item.active_version));
  const pub = active?.public ?? versions.find((v) => v.public?.public_key)?.public ?? null;
  const updated = newestAt(item);
  const canUse = state === 'active';

  const menu: (MenuEntry | 'sep')[] = [
    { label: t('vault.act.replace'), icon: 'edit', onSelect: act.replace },
    { label: t('vault.conns.add'), icon: 'plug', onSelect: act.addConnection },
    ...(canUse ? ['sep' as const, {
      label: t('vault.version.revoke.aria', { n: versionText(item.active_version as VersionId) }), icon: 'stop' as const, danger: true,
      onSelect: () => act.revoke(item.active_version as VersionId),
    }] : []),
  ];

  return (
    <>
      <PaneHeader level={2} title="" onBack={onBack}
        actions={state !== 'deleted' ? <Menu label={t('vault.detail.more')} items={menu} /> : undefined} />
      <div className="pane-body">
        <div className="pane-content vault-detail" aria-label={t('vault.detail.aria')}>
          <header className="vault-head">
            <span className={`vault-head-glyph tile-${item.kind}`} aria-hidden="true"><Icon name={kindIcon(item.kind)} size={20} /></span>
            <div className="grow">
              <h2 className="detail-title" data-selectable="">{item.id}</h2>
              <p className="detail-sub">
                {kindLabel(item.kind)} · <span title={placeOf(item)}>{placeText(placeOf(item))}</span>
                {shared && <> · {t('vault.detail.shared')}</>}
              </p>
            </div>
          </header>

          {state === 'deleted' ? (
            <Banner tone="danger" title={t('vault.deleted.title')}>{t('vault.deleted.text')}</Banner>
          ) : canUse ? (
            <Section title={t('vault.current')}>
              <div className="vault-value">
                <span className="vault-value-mask" aria-label={t('vault.current.hidden')}>{t('vault.current.masked')}</span>
                <IconButton icon="eye" label={t('vault.act.reveal')} onClick={() => act.reveal()} />
                <Button tone="primary" size="sm" icon="copy" onClick={act.copy}>{t('vault.act.copy')}</Button>
              </div>
            </Section>
          ) : (
            <Section title={t('vault.current')}>
              <div className="vault-value is-empty">
                <span className="grow">{t('vault.current.none')}</span>
                <Button size="sm" tone="secondary" onClick={act.replace}>{t('vault.act.replace')}</Button>
              </div>
            </Section>
          )}

          {item.kind === 'ssh_private_key' && pub?.public_key && (
            <Section title={t('vault.pub')}><PublicKeyBox publicKey={pub.public_key} fingerprint={pub.fingerprint} /></Section>
          )}

          <Section title={t('vault.versions')}>
            <div className="rows">
              {versions.map((v) => {
                const ver = v.version as VersionId;
                const n = versionText(ver);
                const live = v.status !== 'revoked' && state !== 'deleted';
                const items: (MenuEntry | 'sep')[] = [
                  { label: t('vault.version.reveal'), icon: 'eye', onSelect: () => act.reveal(ver) },
                  ...(v.status === 'staged' ? [{ label: t('vault.version.retire'), icon: 'pause' as const, onSelect: () => act.retire(ver) }] : []),
                  'sep',
                  { label: t('vault.version.revoke'), icon: 'stop', danger: true, onSelect: () => act.revoke(ver) },
                ];
                return (
                  <StaticRow key={n}
                    title={<span className="vault-ver"><span>{t('vault.version.n', { n })}</span><span className={'vault-ver-st is-' + v.status}>{versionStatusText(v.status)}</span></span>}
                    meta={<span className="num">{shortTime(v.created_at)}{v.public?.fingerprint ? ` · ${v.public.fingerprint}` : ''}</span>}
                    end={live ? <Menu label={t('vault.version.more.aria', { n })} items={items} /> : null} />
                );
              })}
            </div>
            {updated > 0 && <p className="vault-note">{t('vault.meta.updatedAt', { time: shortTime(new Date(updated).toISOString()) })}{shared ? ` · ${t('vault.shared.note')}` : ''}</p>}
          </Section>

          <Section title={t('vault.conns')} aside={connsFailed || conns.length > 0 ? undefined : (
            <Button size="sm" tone="ghost" icon="plus" onClick={act.addConnection}>{t('vault.conns.add')}</Button>
          )}>
            {connsFailed ? <p className="vault-note is-warn">{t('vault.conns.err')}</p>
              : conns.length === 0 ? <p className="vault-note">{t('vault.conns.none')}</p> : (
                <div className="rows">
                  {conns.map((c) => (
                    <StaticRow key={c.id} onClick={() => act.openConnection(c.id)} label={c.id}
                      lead={<Icon name={c.kind === 'ssh' ? 'terminal' : 'globe'} className="vault-conn-glyph" />}
                      title={c.id}
                      meta={connTarget(c)}
                      end={<>{c.status !== 'active' && <span className="vault-note">{t('vault.conns.off')}</span>}<Icon name="chevron-right" size={14} /></>} />
                  ))}
                </div>
              )}
          </Section>

          <Section title={t('vault.delete')}>
            <p className="vault-note">{t('vault.delete.text')}</p>
          </Section>
        </div>
      </div>
    </>
  );
}

/** Where a connection goes, from the CLI's own fields (host only; never a credential). */
function connTarget(c: ConnectionView): string {
  const http = c.http_target as { host?: unknown; port?: unknown } | null | undefined;
  const ssh = c.ssh_target as { host?: unknown; username?: unknown } | null | undefined;
  if (http && typeof http.host === 'string') return http.host + (typeof http.port === 'number' && http.port !== 443 ? `:${http.port}` : '');
  if (ssh && typeof ssh.host === 'string') return (typeof ssh.username === 'string' ? `${ssh.username}@` : '') + ssh.host;
  return String(c.kind);
}
