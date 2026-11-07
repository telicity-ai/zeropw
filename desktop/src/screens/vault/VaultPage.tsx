// The vault: every stored item (never a value) in a searchable list, and the selected item's
// detail. The list follows the sidebar's filter (all, a kind, a place) through the route.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { t, type CopyKey } from '../../copy';
import { call, toIpcError } from '../../ipc/client';
import type { EnvFileRef, SecretKind, SecretView, VersionId } from '../../ipc/contract';
import { teamEnvPairs } from '../../lib/dash';
import { dropErrorKey } from '../../lib/envimport';
import { useShell, type Intent } from '../../app/shell';
import { useApp } from '../../ui/app';
import { Button, IconButton } from '../../ui/controls';
import { ConfirmDialog } from '../../ui/Dialog';
import { Menu } from '../../ui/disclosure';
import { EmptyState, LoadError, SkeletonRows } from '../../ui/feedback';
import { useHotkey, useLoad } from '../../ui/hooks';
import { Icon } from '../../ui/icons';
import { KindTile, ListRow, Meta, PaneHeader, SearchBox, useListKeys } from '../../ui/layout';
import { AddItemDialog } from './AddItemDialog';
import { ImportDialog } from './ImportDialog';
import { ItemDetail } from './ItemDetail';
import {
  connectionsUsing, defaultPlace, filterItems, isShared, itemState, kindLabel, parseView, placeOf, placeText, sortItems, versionText, type SortBy,
} from './logic';
import { PlaceDialog } from './PlaceDialog';
import { RevealDialog } from './RevealDialog';

type Dlg =
  | { kind: 'add'; initialKind?: SecretKind }
  | { kind: 'replace'; item: SecretView }
  | { kind: 'reveal'; id: string; version?: VersionId; mode: 'show' | 'copy' }
  | { kind: 'version'; action: 'retire' | 'revoke'; id: string; version: VersionId }
  | { kind: 'import'; file: EnvFileRef };

export function VaultPage({ intent }: { intent?: Intent }) {
  const { route, go, vault, clearIntent, envFile, takeEnvFile, narrow, tick } = useShell();
  const { toast, locale } = useApp();
  const view = route.view ?? 'all';
  const filter = parseView(view);
  const [query, setQuery] = useState('');
  const [sort, setSort] = useState<SortBy>('name');
  const [dlg, setDlg] = useState<Dlg | null>(null);
  const [placeOpen, setPlaceOpen] = useState(false);
  const [newPlace, setNewPlace] = useState<string | null>(null);
  const [detailOpen, setDetailOpen] = useState(!!route.item);
  const searchRef = useRef<HTMLInputElement>(null);
  const keyNav = useRef(false);
  const conns = useLoad(() => call('connection_list'), [tick, vault.data]);

  const secrets = vault.data?.secrets ?? null;
  const listing = vault.data?.listing ?? null;
  const pairs = useMemo(() => (listing ? teamEnvPairs(listing) : []), [listing]);
  const multiPlace = pairs.length > 1;
  const shown = useMemo(() => (secrets ? sortItems(filterItems(secrets, filter, query), sort) : []), [secrets, view, query, sort, locale]);
  const ids = useMemo(() => shown.map((s) => s.id), [shown]);
  const selectedId = route.item && ids.includes(route.item) ? route.item : narrow.single ? null : ids[0] ?? null;
  const selected = selectedId ? shown.find((s) => s.id === selectedId) ?? null : null;
  const connList = conns.data?.connections ?? [];
  const connCount = useCallback((s: SecretView) => connectionsUsing(connList, s).length, [connList]);

  const select = useCallback((id: string) => {
    go('vault', { view, item: id });
    if (narrow.single && !keyNav.current) setDetailOpen(true);
  }, [go, view, narrow.single]);
  const listKeys = useListKeys(ids, selectedId, (id) => { keyNav.current = true; select(id); setTimeout(() => { keyNav.current = false; }, 0); }, () => setDetailOpen(true));

  // search: ⌘F and the sidebar's search button
  useEffect(() => {
    const focus = () => { searchRef.current?.focus(); searchRef.current?.select(); };
    window.addEventListener('zpw:focus-search', focus);
    return () => window.removeEventListener('zpw:focus-search', focus);
  }, []);
  const addKind = filter.by === 'kind' ? filter.kind : undefined;
  useHotkey('n', () => setDlg({ kind: 'add', initialKind: addKind }));
  useEffect(() => { setQuery(''); }, [view]);

  // a .env file picked here; one dropped on the window arrives as the `import` intent
  const pickEnv = async () => {
    try {
      const f = await call('file_pick', { purpose: 'env_file' });
      if (f) setDlg({ kind: 'import', file: await call('env_file_load', { file_token: f.file_token }) });
    } catch (e) {
      const r = toIpcError(e).reason;
      toast(t(r === 'ipc_failed' || r === 'mock_unsupported' || r === 'not_in_desktop' ? 'error.desktopOnly' : dropErrorKey(r)), 'warn');
    }
  };

  useEffect(() => {
    if (!intent) return;
    if (intent === 'add') { setDlg({ kind: 'add', initialKind: addKind }); clearIntent(); }
    else if (intent === 'import') {
      if (envFile) {
        // a file opened before this one and not yet imported gives way (ImportDialog discards it)
        setDlg({ kind: 'import', file: envFile });
        takeEnvFile();
      }
      clearIntent();
    }
  }, [intent, envFile, clearIntent, takeEnvFile, addKind]);

  const taken = useMemo(() => (secrets ?? []).map((s) => s.id), [secrets]);
  const title = filter.by === 'kind' ? t(`nav.kind.${filter.kind}` as CopyKey) : filter.by === 'place' ? placeText(filter.place) : t('nav.all');
  const close = () => setDlg(null);

  const listBody = () => {
    if (!secrets) return vault.error ? <div className="vault-pad"><LoadError error={vault.error} onRetry={vault.reload} /></div> : <SkeletonRows n={6} />;
    if (secrets.length === 0) {
      return (
        <EmptyState icon="vault" title={t('vault.empty.title')} action={<>
          <Button tone="primary" icon="plus" onClick={() => setDlg({ kind: 'add' })}>{t('vault.empty.add')}</Button>
          <Button tone="secondary" icon="download" onClick={() => void pickEnv()}>{t('vault.import')}</Button>
        </>}>{t('vault.empty.text')}</EmptyState>
      );
    }
    if (shown.length === 0) {
      return query.trim()
        ? <EmptyState compact icon="search" title={t('vault.empty.search.title')}>{t('vault.empty.search.text', { q: query.trim() })}</EmptyState>
        : <EmptyState compact icon={filter.by === 'kind' ? 'key' : 'folder'} title={t('vault.empty.filter.title')}
          action={<Button size="sm" tone="secondary" icon="plus" onClick={() => setDlg({ kind: 'add', initialKind: filter.by === 'kind' ? filter.kind : undefined })}>{t('vault.add')}</Button>}>
          {t('vault.empty.filter.text')}</EmptyState>;
    }
    return (
      <div className="list" role="listbox" aria-label={t('vault.list.aria')}>
        {shown.map((s) => {
          const st = itemState(s);
          const nConn = connCount(s);
          return (
            <ListRow key={`${placeOf(s)}/${s.id}`} id={s.id} selected={s.id === selectedId} onSelect={() => select(s.id)} onKeyDown={listKeys}
              lead={<KindTile kind={s.kind} />}
              title={s.id}
              meta={<Meta parts={[
                kindLabel(s.kind),
                multiPlace && filter.by !== 'place' ? placeText(placeOf(s)) : null,
                st === 'deleted' ? t('vault.row.deleted') : st === 'none' ? t('vault.row.noActive') : null,
                nConn > 0 ? t('vault.row.conns', { n: nConn }) : null,
              ]} />}
              end={st === 'none' ? <span className="vault-warn-icon" title={t('vault.row.noActive')}><Icon name="alert" size={13} /></span> : undefined} />
          );
        })}
      </div>
    );
  };

  const listHidden = narrow.single && detailOpen && !!selected;
  const detailHidden = narrow.single && !listHidden;
  return (
    <div className={'page vault-page' + (narrow.single ? ' is-single' : '')}>
      <section className={'pane pane-list' + (listHidden ? ' is-hidden' : '')} aria-label={title}>
        <PaneHeader title={title} sub={secrets ? String(shown.length) : undefined} actions={<>
          <Menu label={t('vault.list.more')} items={[
            { label: t('vault.sort.name'), checked: sort === 'name', onSelect: () => setSort('name') },
            { label: t('vault.sort.recent'), checked: sort === 'recent', onSelect: () => setSort('recent') },
            'sep',
            { label: t('vault.import'), icon: 'download', onSelect: () => void pickEnv() },
            { label: t('vault.place.add'), icon: 'folder', onSelect: () => setPlaceOpen(true) },
          ]} />
          <IconButton icon="plus" label={t('vault.add.aria')} size="sm" onClick={() => setDlg({ kind: 'add', initialKind: filter.by === 'kind' ? filter.kind : undefined })} />
        </>} />
        {secrets && secrets.length > 0 && (
          <div className="pane-toolbar">
            <SearchBox ref={searchRef} value={query} onChange={setQuery} placeholder={t('vault.search')} label={t('vault.search.aria')}
              onKeyDown={(e) => {
                if (e.key === 'ArrowDown' && ids[0]) {
                  e.preventDefault();
                  const first = selectedId ?? ids[0];
                  keyNav.current = true; select(first); setTimeout(() => { keyNav.current = false; }, 0);
                  setTimeout(() => document.querySelector<HTMLElement>(`.vault-page [data-id="${CSS.escape(first)}"]`)?.focus(), 0);
                }
              }} />
          </div>
        )}
        <div className="pane-body">{listBody()}</div>
      </section>
      <section className={'pane pane-detail' + (detailHidden ? ' is-hidden' : '')} aria-label={t('vault.detail.aria')}>
        {selected ? (
          <ItemDetail key={`${placeOf(selected)}/${selected.id}`} item={selected} shared={isShared(listing?.team_environments, placeOf(selected))}
            conns={connectionsUsing(connList, selected)} connsFailed={!!conns.error && !conns.data}
            onBack={narrow.single ? () => setDetailOpen(false) : undefined}
            act={{
              reveal: (version) => setDlg({ kind: 'reveal', id: selected.id, version, mode: 'show' }),
              copy: () => setDlg({ kind: 'reveal', id: selected.id, mode: 'copy' }),
              replace: () => setDlg({ kind: 'replace', item: selected }),
              retire: (version) => setDlg({ kind: 'version', action: 'retire', id: selected.id, version }),
              revoke: (version) => setDlg({ kind: 'version', action: 'revoke', id: selected.id, version }),
              openConnection: (id) => go('services', { item: id }),
              addConnection: () => go('services', { intent: 'add-connection' }),
            }} />
        ) : (
          <>
            <PaneHeader level={2} title="" />
            <div className="pane-body">{secrets && secrets.length > 0 && <p className="vault-pick">{t('vault.empty.pick')}</p>}</div>
          </>
        )}
      </section>

      {(dlg?.kind === 'add' || dlg?.kind === 'replace') && (
        <AddItemDialog key={dlg.kind} replace={dlg.kind === 'replace' ? dlg.item : undefined} pairs={pairs}
          initialPlace={newPlace ?? defaultPlace(pairs, filter)} placeHint={newPlace} initialKind={dlg.kind === 'add' ? dlg.initialKind : undefined} taken={taken}
          onClose={() => { close(); setNewPlace(null); }}
          onSaved={(id) => { vault.reload(); if (dlg.kind === 'add') go('vault', { view: view.startsWith('place:') || view.startsWith('kind:') ? view : 'all', item: id }); }}
          onNewPlace={() => setPlaceOpen(true)} />
      )}
      {placeOpen && (
        <PlaceDialog onClose={() => setPlaceOpen(false)} onDone={(place) => {
          setPlaceOpen(false); setNewPlace(place); vault.reload();
          // a place made from the add dialog becomes its choice
        }} />
      )}
      {dlg?.kind === 'reveal' && <RevealDialog id={dlg.id} version={dlg.version} mode={dlg.mode} onClose={close} />}
      {dlg?.kind === 'version' && <VersionConfirm data={dlg} onClose={close} onDone={() => { close(); vault.reload(); }} />}
      {dlg?.kind === 'import' && <ImportDialog key={dlg.file.import_ref} file={dlg.file} pairs={pairs} onClose={close} onDone={vault.reload} />}
    </div>
  );
}

function VersionConfirm({ data, onClose, onDone }: { data: Extract<Dlg, { kind: 'version' }>; onClose(): void; onDone(): void }) {
  const { toast } = useApp();
  const revoke = data.action === 'revoke';
  const n = versionText(data.version);
  return (
    <ConfirmDialog open title={t(revoke ? 'vault.revoke.title' : 'vault.retire.title', { n })} description={t(revoke ? 'vault.revoke.sub' : 'vault.retire.sub')}
      confirmLabel={t(revoke ? 'vault.version.revoke' : 'vault.version.retire')} tone={revoke ? 'danger' : 'primary'} size="md"
      warn={revoke ? `${t('vault.revoke.warn')}. ${t('vault.provider.note')}` : undefined} info={revoke ? t('vault.revoke.session') : undefined}
      onClose={onClose}
      errorFor={(e): CopyKey | null => (toIpcError(e).reason === 'version_revoked' ? 'vault.err.revoked' : null)}
      run={async () => {
        // the version goes back exactly as the CLI printed it
        const out = await call(revoke ? 'secret_revoke' : 'secret_retire', { id: data.id, version: data.version });
        const provider = revoke || out.provider_revocation_required === true;
        toast(t(revoke ? 'vault.toast.revoked' : provider ? 'vault.toast.retired.provider' : 'vault.toast.retired'), provider ? 'warn' : 'ok');
        onDone();
      }}>
      <p className="mono text-sm" data-selectable="">{data.id}</p>
    </ConfirmDialog>
  );
}
