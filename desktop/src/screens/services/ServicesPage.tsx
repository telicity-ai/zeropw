// Service connections: HTTP APIs the gateway authenticates and SSH servers the signer signs for.
// A connection is made once (service, credential, destination, permissions); agents then use
// any supported operation within it without registering commands. The list never shows a value.

import { useEffect, useMemo, useRef, useState } from 'react';
import { t, type CopyKey } from '../../copy';
import { call, toIpcError } from '../../ipc/client';
import type { ConnectionView, Grant, Principal, SecretKind } from '../../ipc/contract';
import { isCliPath, SSH_PROGRAM, summarizeConnection, teamEnvPairs, splitEnv } from '../../lib/dash';
import { shortTime } from '../../lib/format';
import { sshProgramError } from '../../lib/reasons';
import { placeLabel } from '../../lib/places';
import { useShell, type Intent } from '../../app/shell';
import { useApp } from '../../ui/app';
import { Button, TextField } from '../../ui/controls';
import { ConfirmDialog } from '../../ui/Dialog';
import { Badge, Banner, EmptyState, KeyValues, LoadError, Section, SkeletonRows, Status, type KV } from '../../ui/feedback';
import { useLoad, useNow } from '../../ui/hooks';
import { Icon } from '../../ui/icons';
import { IconTile, ListRow, Meta, PaneHeader, SearchBox, StaticRow, useListKeys } from '../../ui/layout';
import { CreateConnectionDialog } from './CreateConnection';
import { connectionFacts, liveGrantsFor } from './logic';

type DialogState = { kind: 'create' } | { kind: 'disable'; id: string } | { kind: 'ssh-cli'; id: string } | null;

/** Words for a connection's state, by summary. */
function stateOf(c: ConnectionView): { key: CopyKey; tone: 'ok' | 'neutral' | 'warn' } {
  const s = summarizeConnection(c);
  if (!s.active) return { key: 'service.state.off', tone: 'neutral' };
  if (s.noCli) return { key: 'service.state.nocli', tone: 'warn' };
  return { key: 'service.state.active', tone: 'ok' };
}

const placeOf = (c: ConnectionView): string => {
  const p = splitEnv(`${String(c.project)}/${String(c.environment)}`);
  return p ? placeLabel(p.project, p.environment) : `${String(c.project)}/${String(c.environment)}`;
};

export function ServicesPage({ intent }: { intent?: Intent }) {
  const { route, go, clearIntent, tick, activity, bump, vault, narrow } = useShell();
  const load = useLoad(async () => {
    const [c, g, p] = await Promise.all([
      call('connection_list'),
      call('grant_list', {}).then((r) => r.grants, () => null),
      call('principal_list').then((r) => r.principals, () => null),
    ]);
    return { connections: c.connections, grants: g, principals: p };
  }, [tick, activity]);
  const [dialog, setDialog] = useState<DialogState>(null);
  const [q, setQ] = useState('');
  const [selected, setSelected] = useState<string | null>(route.item ?? null);
  const [showDetail, setShowDetail] = useState(!!route.item);
  const search = useRef<HTMLInputElement>(null);

  useEffect(() => { if (route.item) { setSelected(route.item); setShowDetail(true); } }, [route.item]);
  useEffect(() => {
    if (intent === 'add-connection') { setDialog({ kind: 'create' }); clearIntent(); }
  }, [intent, clearIntent]);

  const all = load.data?.connections ?? null;
  const shown = useMemo(() => {
    if (!all) return [];
    const needle = q.trim().toLowerCase();
    const sorted = all.slice().sort((a, b) => {
      const sa = summarizeConnection(a), sb = summarizeConnection(b);
      if (sa.active !== sb.active) return sa.active ? -1 : 1;
      return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    });
    if (!needle) return sorted;
    return sorted.filter((c) => {
      const s = summarizeConnection(c);
      return [c.id, s.host, s.env, placeOf(c)].some((x) => x.toLowerCase().includes(needle));
    });
  }, [all, q]);
  const current = shown.find((c) => c.id === selected) ?? (narrow.single ? null : shown[0] ?? null);
  const ids = shown.map((c) => c.id);
  const select = (id: string) => setSelected(id);
  const onKeys = useListKeys(ids, current?.id ?? null, select, () => setShowDetail(true));
  const reload = () => { load.reload(); };

  const pairs = useMemo(() => (vault.data ? teamEnvPairs(vault.data.listing) : []), [vault.data]);
  const addBtn = <Button tone="primary" size="sm" icon="plus" onClick={() => setDialog({ kind: 'create' })}>{t('service.add')}</Button>;
  const single = narrow.single;
  const listHidden = single && showDetail && !!current;

  return (
    <div className={'page svc-page' + (single ? ' is-single' : '')}>
      <section className={'pane pane-list' + (listHidden ? ' is-hidden' : '')} aria-label={t('service.list.aria')}>
        <PaneHeader title={t('service.title')} actions={all && all.length > 0 ? addBtn : undefined} />
        {all && all.length > 0 && (
          <div className="pane-toolbar">
            <SearchBox ref={search} value={q} onChange={setQ} placeholder={t('service.search')} label={t('service.search')}
              onKeyDown={(e) => { if (e.key === 'ArrowDown' && ids[0]) { e.preventDefault(); select(current?.id ?? ids[0]); document.querySelector<HTMLElement>(`.svc-page [data-id="${CSS.escape(current?.id ?? ids[0])}"]`)?.focus(); } }} />
          </div>
        )}
        <div className="pane-body">
          {!all && load.error && <div className="svc-pad"><LoadError error={load.error} onRetry={reload} /></div>}
          {!all && !load.error && <SkeletonRows n={3} />}
          {all && all.length === 0 && (
            <EmptyState icon="plug" title={t('service.empty.title')} action={addBtn}>{t('service.empty.text')}</EmptyState>
          )}
          {all && all.length > 0 && shown.length === 0 && <EmptyState compact icon="search" title={t('service.search.none', { q: q.trim() })} />}
          {shown.length > 0 && (
            <div className="list" role="listbox" aria-label={t('service.list.aria')} onKeyDown={onKeys}>
              {shown.map((c) => {
                const s = summarizeConnection(c), st = stateOf(c);
                return (
                  <ListRow key={c.id} id={c.id} selected={current?.id === c.id} label={c.id}
                    onSelect={() => { select(c.id); if (single) setShowDetail(true); }}
                    lead={<IconTile icon={s.kind === 'ssh' ? 'terminal' : 'globe'} tone="service" />}
                    title={<span className="mono">{c.id}</span>}
                    meta={<Meta parts={[s.host, placeOf(c), st.tone !== 'ok' ? t(st.key) : null]} />}
                    end={<Badge tone={s.kind === 'ssh' ? 'info' : 'accent'}>{t(s.kind === 'ssh' ? 'service.kind.ssh' : s.kind === 'http' ? 'service.kind.http' : 'service.kind.other')}</Badge>} />
                );
              })}
            </div>
          )}
        </div>
      </section>
      <section className={'pane pane-detail' + (single && !listHidden ? ' is-hidden' : '')} aria-label={current?.id ?? t('service.title')}>
        {current ? (
          <ConnectionDetail c={current} grants={load.data?.grants ?? null} principals={load.data?.principals ?? null}
            secretKind={vault.data?.secrets.find((s) => s.id === current.secret_id && String(s.project) === String(current.project) && String(s.environment) === String(current.environment))?.kind ?? null}
            onBack={single ? () => setShowDetail(false) : undefined}
            onSshCli={() => setDialog({ kind: 'ssh-cli', id: current.id })}
            onDisable={() => setDialog({ kind: 'disable', id: current.id })}
            onOpenItem={(id) => go('vault', { view: 'all', item: id })}
            onGrant={() => go('developer', { view: 'agents', intent: 'add-grant' })} />
        ) : (
          <>
            <PaneHeader title={t('service.title')} level={2} />
            <div className="pane-body">{all && all.length > 0 && <EmptyState compact icon="plug" title={t('service.pick.title')}>{t('service.pick.text')}</EmptyState>}</div>
          </>
        )}
      </section>

      {dialog?.kind === 'create' && (
        <CreateConnectionDialog pairs={pairs} connections={all ?? []} secrets={vault.data?.secrets ?? []}
          onClose={() => setDialog(null)}
          onCreated={(id) => { setSelected(id); reload(); vault.reload(); bump(); }} />
      )}
      {dialog?.kind === 'ssh-cli' && (
        <SshProgramDialog id={dialog.id} onClose={() => setDialog(null)} onStale={reload} onDone={() => { setDialog(null); reload(); bump(); }} />
      )}
      {dialog?.kind === 'disable' && (
        <DisableDialog id={dialog.id} onClose={() => setDialog(null)} onDone={() => { setDialog(null); reload(); }} />
      )}
    </div>
  );
}

function ConnectionDetail({ c, grants, principals, secretKind, onBack, onSshCli, onDisable, onOpenItem, onGrant }: {
  c: ConnectionView; grants: Grant[] | null; principals: Principal[] | null; secretKind: SecretKind | null;
  onBack?(): void; onSshCli(): void; onDisable(): void; onOpenItem(id: string): void; onGrant(): void;
}) {
  const s = summarizeConnection(c);
  const st = stateOf(c);
  const f = connectionFacts(c);
  const now = useNow(!!grants?.length, 15_000);
  const live = grants ? liveGrantsFor(grants, c.id, now) : [];
  const runtimeOf = (p: string) => principals?.find((x) => x.id === p)?.runtime ?? null;

  let target: KV[] = [];
  let scope: KV[] = [];
  if (f.kind === 'http') {
    const auth = f.auth.mode === 'basic' ? t('service.d.auth.basic', { user: f.auth.basicUser || '—' })
      : f.auth.mode === 'header' ? (f.auth.prefix ? t('service.d.auth.headerPrefix', { name: f.auth.headerName, prefix: f.auth.prefix }) : t('service.d.auth.header', { name: f.auth.headerName }))
        : f.auth.mode === 'bearer' ? t('service.d.auth.bearer') : f.auth.mode || '—';
    target = [
      { k: t('service.d.address'), v: <span className="row-wrap"><span className="mono">{f.origin}</span><Badge tone={f.tls ? 'ok' : 'warn'} icon={f.tls ? 'lock' : 'alert'}>{t(f.tls ? 'service.d.tls.on' : 'service.d.tls.off')}</Badge></span> },
      { k: t('service.d.auth'), v: auth },
      f.privateAllowed ? { k: t('service.d.private'), v: t('state.on') } as KV : null,
      { k: t('service.d.ca'), v: f.ca ? t('service.d.ca.custom') : t('state.none') },
      { k: t('service.d.cli'), v: f.cli ? <span className="mono">{f.cli}</span> : t('service.d.cli.none') },
    ].filter((x): x is KV => !!x);
    scope = [
      {
        k: t('service.d.methods'),
        v: (
          <span className="svc-method-list">
            {f.methods.map((m) => (
              <span key={m} className={'svc-method-fact' + (f.confirm.includes(m) ? ' is-confirm' : '')}>
                <span className="mono">{m}</span>{f.confirm.includes(m) && <span className="svc-method-tag">{t('service.d.confirm')}</span>}
              </span>
            ))}
          </span>
        ),
      },
      { k: t('service.d.paths'), v: f.paths.length ? <span className="mono">{f.paths.join(', ')}</span> : t('service.d.paths.all') },
    ];
  } else if (f.kind === 'ssh') {
    target = [
      { k: t('service.d.host'), v: <span className="mono">{f.host}{f.port !== '22' ? `:${f.port}` : ''}</span> },
      { k: t('service.d.user'), v: <span className="mono">{f.user}</span> },
      { k: t('service.d.hostKey'), v: <span className="mono svc-hostkey">{f.hostKeys.join('\n') || '—'}</span> },
      { k: t('service.d.ssh'), v: f.cli ? <span className="mono">{f.cli}</span> : <span className="svc-warn-text">{t('service.d.ssh.none')}</span> },
    ];
  }

  return (
    <>
      <PaneHeader level={2} title={<span className="mono">{c.id}</span>} onBack={onBack}
        actions={<>
          {s.active && s.noCli && <Button size="sm" tone="primary" icon="terminal" onClick={onSshCli}>{t('service.sshcli')}</Button>}
          {s.active && <Button size="sm" tone="ghost" icon="stop" onClick={onDisable}>{t('service.disable')}</Button>}
        </>} />
      <div className="pane-body">
        <div className="pane-content svc-detail">
          <div className="detail-head">
            <IconTile icon={s.kind === 'ssh' ? 'terminal' : 'globe'} tone="service" size="lg" />
            <div className="grow">
              <h3 className="detail-title mono">{c.id}</h3>
              <div className="detail-sub">
                <Badge tone={s.kind === 'ssh' ? 'info' : 'accent'}>{t(s.kind === 'ssh' ? 'service.kind.ssh' : s.kind === 'http' ? 'service.kind.http' : 'service.kind.other')}</Badge>
                <Status tone={st.tone}>{t(st.key)}</Status>
                <span>{placeOf(c)}</span>
              </div>
            </div>
          </div>
          {s.active && s.noCli && <Banner tone="warn" action={<Button size="sm" tone="secondary" onClick={onSshCli}>{t('service.sshcli')}</Button>}>{t('service.d.nocli')}</Banner>}
          {!s.active && <Banner tone="neutral">{t('service.d.off')}</Banner>}

          {target.length > 0 && <Section title={t('service.d.target')}><div className="card card-pad"><KeyValues items={target} /></div></Section>}
          {scope.length > 0 && <Section title={t('service.d.scope')}><div className="card card-pad"><KeyValues items={scope} /></div></Section>}

          <Section title={t('service.d.credential')}>
            <div className="rows">
              <StaticRow lead={<span className={`tile tile-${secretKind ?? 'api_key'}`} aria-hidden="true"><Icon name={secretKind === 'ssh_private_key' ? 'ssh' : secretKind === 'password' ? 'password' : 'key'} /></span>}
                title={<span className="mono">{String(c.secret_id)}</span>}
                meta={<Meta parts={[secretKind ? t(`nav.kind.${secretKind}` as CopyKey) : null, placeOf(c)]} />}
                end={<Button size="sm" tone="ghost" iconEnd="arrow-right" onClick={() => onOpenItem(String(c.secret_id))}>{t('service.d.openItem')}</Button>} />
            </div>
          </Section>

          <Section title={t('service.d.agents')} aside={s.active ? <Button size="sm" tone="ghost" icon="plus" onClick={onGrant}>{t('service.d.agents.give')}</Button> : undefined}>
            {grants === null ? <Banner tone="neutral" compact>{t('service.d.agents.err')}</Banner>
              : live.length === 0 ? <p className="muted text-sm">{t('service.d.agents.none')}</p>
                : (
                  <div className="rows">
                    {live.map((g) => (
                      <StaticRow key={g.id} lead={<span className="tile" aria-hidden="true"><Icon name="user" /></span>}
                        title={<span className="mono">{g.principal}</span>}
                        meta={<Meta parts={[runtimeOf(g.principal), t('service.d.agents.until', { time: shortTime(g.expires_at) }),
                          g.max_uses !== null && g.max_uses !== undefined ? t('service.d.agents.uses', { uses: String(g.uses), max: String(g.max_uses) }) : t('service.d.agents.usesOpen', { uses: String(g.uses) })]} />} />
                    ))}
                  </div>
                )}
          </Section>

          <Section title={t('service.d.status')}>
            <div className="card card-pad">
              <KeyValues dense items={[
                { k: t('service.d.created'), v: typeof c.created_at === 'string' ? shortTime(c.created_at) : '—' },
                c.policy_version !== undefined && c.policy_version !== null ? { k: t('service.d.policy'), v: String(c.policy_version) } : null,
              ]} />
            </div>
          </Section>

          <Banner tone="info" title={t('service.scope.title')}>{t('service.scope.text')}</Banner>
        </div>
      </div>
    </>
  );
}

/** Gives an SSH connection made without an ssh the one its agents run. The CLI fills a missing
 *  ssh only and the connection's grants go stale, so the dialog says both. A path the core
 *  refuses (none there on this Mac included) goes under the field. */
function SshProgramDialog({ id, onClose, onStale, onDone }: { id: string; onClose(): void; onStale(): void; onDone(): void }) {
  const { toast } = useApp();
  const [path, setPath] = useState(SSH_PROGRAM);
  const [pathErr, setPathErr] = useState<CopyKey | null>(null);
  const pathRef = useRef<HTMLInputElement>(null);
  const FIELD = 'service_field_error';
  return (
    <ConfirmDialog open title={t('service.sshcli.title')} description={t('service.sshcli.sub')} confirmLabel={t('service.sshcli.confirm')} needPass size="md"
      info={t('service.sshcli.regrant')} warn={t('service.sshcli.warn')} onClose={onClose}
      run={async (pass) => {
        if (!isCliPath(path.trim())) {
          setPathErr('conn.cli.err'); pathRef.current?.focus();
          throw { error: 'InvalidInput', reason: FIELD };
        }
        await call('connection_set_cli_program', { id, cli_program: path.trim(), admin_passphrase: pass });
        toast(t('service.toast.sshcli'), 'ok');
        onDone();
      }}
      errorFor={(e) => {
        const reason = toIpcError(e).reason;
        if (reason === FIELD) return false;
        const why = sshProgramError(reason);
        if (why && 'field' in why) { setPathErr(why.field); pathRef.current?.focus(); return false; }
        // the list was out of date: show the connection as it is now
        if (why?.stale) onStale();
        return why?.form ?? null;
      }}>
      <p className="mono text-sm">{id}</p>
      <TextField label={t('service.sshcli.field')} mono value={path} inputRef={pathRef} placeholder={SSH_PROGRAM} name="sshcli-path"
        error={pathErr ? t(pathErr) : null} onChange={(v) => { setPath(v); setPathErr(null); }} />
    </ConfirmDialog>
  );
}

function DisableDialog({ id, onClose, onDone }: { id: string; onClose(): void; onDone(): void }) {
  const { toast } = useApp();
  return (
    <ConfirmDialog open title={t('service.disable.title')} description={t('service.disable.sub')} confirmLabel={t('service.disable.confirm')} tone="danger"
      warn={t('service.disable.warn')} info={t('service.disable.info')} onClose={onClose}
      run={async () => { await call('connection_disable', { id }); toast(t('service.toast.disabled'), 'warn'); onDone(); }}>
      <p className="mono text-sm">{id}</p>
    </ConfirmDialog>
  );
}
