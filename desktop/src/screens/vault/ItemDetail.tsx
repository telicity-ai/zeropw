// One item: what it is, its current value (behind re-authentication), its versions, the
// services that authenticate with it, whether its place syncs, and what deleting means today.

import type { ReactNode } from 'react';
import { t } from '../../copy';
import type { ConnectionView, SecretView, VersionId } from '../../ipc/contract';
import { sortedVersions } from '../../lib/dash';
import { shortTime } from '../../lib/format';
import { useApp } from '../../ui/app';
import { Button } from '../../ui/controls';
import { Badge, Banner, KeyValues, Section } from '../../ui/feedback';
import { Icon } from '../../ui/icons';
import { KindTile, PaneHeader, StaticRow } from '../../ui/layout';
import { itemState, kindLabel, newestAt, placeOf, placeText, versionText } from './logic';
import { PublicKeyBox, VersionBadge } from './parts';

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
  const { toast } = useApp();
  const state = itemState(item);
  const versions = sortedVersions(item);
  const active = versions.find((v) => String(v.version) === String(item.active_version));
  const pub = active?.public ?? versions.find((v) => v.public?.public_key)?.public ?? null;
  const updated = newestAt(item);
  const blocked = () => toast(t('vault.act.blocked'), 'warn');
  const canUse = state === 'active';

  return (
    <>
      <PaneHeader level={2} title={item.id} onBack={onBack} />
      <div className="pane-body">
        <div className="pane-content vault-detail" aria-label={t('vault.detail.aria')}>
          <div className="detail-head">
            <KindTile kind={item.kind} size="lg" />
            <div className="grow">
              <h3 className="detail-title" data-selectable="">{item.id}</h3>
              <div className="detail-sub">
                <span>{kindLabel(item.kind)}</span><span className="sep" aria-hidden="true" />
                <span>{placeText(placeOf(item))}</span>
                {shared && <Badge tone="accent" icon="sync">{t('vault.detail.shared')}</Badge>}
                {state === 'deleted' && <Badge tone="danger">{t('vault.row.deleted')}</Badge>}
              </div>
            </div>
          </div>

          {state === 'deleted' ? (
            <Banner tone="danger" title={t('vault.deleted.title')}>{t('vault.deleted.text')}</Banner>
          ) : (
            <div className="detail-actions">
              <Button tone="primary" icon="eye" blocked={!canUse} onBlocked={blocked} onClick={() => act.reveal()}>{t('vault.act.reveal')}</Button>
              <Button tone="secondary" icon="copy" blocked={!canUse} onBlocked={blocked} onClick={act.copy}>{t('vault.act.copy')}</Button>
              <Button tone="ghost" icon="edit" onClick={act.replace}>{t('vault.act.replace')}</Button>
            </div>
          )}

          {state !== 'deleted' && (
            <Section title={t('vault.current')}>
              {canUse ? (
                <div className="vault-current">
                  <span className="vault-current-mask mono" aria-hidden="true">{t('vault.current.masked')}</span>
                  <span className="vault-current-meta">{t('vault.version.n', { n: versionText(item.active_version as VersionId) })}</span>
                </div>
              ) : <Banner tone="warn" compact>{t('vault.current.none')}</Banner>}
              <p className="vault-note">{t('vault.current.help')}</p>
            </Section>
          )}

          <KeyValues items={[
            { k: t('vault.meta.kind'), v: kindLabel(item.kind) },
            { k: t('vault.meta.place'), v: <span title={placeOf(item)}>{placeText(placeOf(item))}</span> },
            updated ? { k: t('vault.meta.updated'), v: <span className="num">{shortTime(new Date(updated).toISOString())}</span> } : null,
          ]} />

          {shared && <Banner tone="info" icon="sync">{t('vault.shared.note')}</Banner>}

          {item.kind === 'ssh_private_key' && pub?.public_key && (
            <Section title={t('vault.pub')}><PublicKeyBox publicKey={pub.public_key} fingerprint={pub.fingerprint} /></Section>
          )}

          <Section title={t('vault.versions')}>
            <div className="rows">
              {versions.map((v) => {
                const ver = v.version as VersionId;
                const n = versionText(ver);
                const live = v.status !== 'revoked' && state !== 'deleted';
                const actions: ReactNode = live ? (
                  <>
                    <Button size="sm" tone="ghost" aria-label={t('vault.version.reveal.aria', { n })} onClick={() => act.reveal(ver)}>{t('act.show')}</Button>
                    {v.status === 'staged' && <Button size="sm" tone="ghost" aria-label={t('vault.version.retire.aria', { n })} onClick={() => act.retire(ver)}>{t('vault.version.retire')}</Button>}
                    <Button size="sm" tone="quiet" className="vault-danger-text" aria-label={t('vault.version.revoke.aria', { n })} onClick={() => act.revoke(ver)}>{t('vault.version.revoke')}</Button>
                  </>
                ) : null;
                return (
                  <StaticRow key={n}
                    lead={<span className={'vault-ver-dot is-' + v.status} aria-hidden="true" />}
                    title={<span className="row">{t('vault.version.n', { n })}<VersionBadge status={v.status} /></span>}
                    meta={<span className="num">{shortTime(v.created_at)}{v.public?.fingerprint ? ` · ${v.public.fingerprint}` : ''}</span>}
                    end={actions} />
                );
              })}
            </div>
          </Section>

          <Section title={t('vault.conns')} aside={!connsFailed && conns.length > 0 ? undefined : (
            <Button size="sm" tone="ghost" icon="plus" onClick={act.addConnection}>{t('vault.conns.add')}</Button>
          )}>
            {connsFailed ? <Banner tone="warn" compact>{t('vault.conns.err')}</Banner>
              : conns.length === 0 ? <p className="vault-note">{t('vault.conns.none')}</p> : (
                <div className="rows">
                  {conns.map((c) => (
                    <StaticRow key={c.id} onClick={() => act.openConnection(c.id)} label={c.id}
                      lead={<span className="tile tile-service" aria-hidden="true"><Icon name={c.kind === 'ssh' ? 'terminal' : 'globe'} /></span>}
                      title={c.id}
                      meta={connTarget(c)}
                      end={<>{c.status !== 'active' && <Badge>{t('vault.conns.off')}</Badge>}<Icon name="chevron-right" size={14} /></>} />
                  ))}
                </div>
              )}
          </Section>

          <Section title={t('vault.delete')}>
            <Banner tone="neutral" icon="info">{t('vault.delete.text')}</Banner>
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
