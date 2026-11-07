// Agents: each agent with its live grants, the in-app terminals still running, and the dialogs
// to add an agent, give and revoke permission, disable an agent and end a terminal. An agent
// gets the local service's address and a caller token, never an original value.

import { useEffect, useRef, useState } from 'react';
import { t, type CopyKey } from '../../copy';
import { call, toIpcError } from '../../ipc/client';
import type { ConnectionView, Grant, Principal } from '../../ipc/contract';
import { GRANT_TTLS, liveGrants, parseMaxUses, type GrantTtl } from '../../lib/dash';
import { isAccountName, isValidName, runtimeFor } from '../../lib/validators';
import { useShell, type Intent } from '../../app/shell';
import { useApp } from '../../ui/app';
import { Button, PassField, Segmented, SelectField, TextField } from '../../ui/controls';
import { ConfirmDialog, Dialog, isAuthError, passErrorKey } from '../../ui/Dialog';
import { Badge, Banner, EmptyState, KeyValues, LoadError, Section, SkeletonRows, Status } from '../../ui/feedback';
import { useLoad, useNow } from '../../ui/hooks';
import { IconTile } from '../../ui/layout';
import { AppTerminal, focusTerminalIn, type TerminalSource } from '../../ui/Terminal';
import { ChoiceCards } from './Choice';
import { grantText, runtimeText, useIntentOnce } from './common';

type Where = 'other' | 'same';
interface TermView { key: string; name: string; source: TerminalSource; terminalId: string | null }
type Open =
  | { kind: 'create' }
  | { kind: 'grant'; principal?: string }
  | { kind: 'revoke'; grant: Grant }
  | { kind: 'disable'; id: string }
  | { kind: 'end'; terminalId: string; principal: string; asUser: string | null };
const TERM_DOM = 'dev-term';
const TTL_LABEL: Record<GrantTtl, CopyKey> = { '1h': 'grant.ttl.1h', '8h': 'grant.ttl.8h', '24h': 'grant.ttl.24h' };

export function AgentsTab({ intent }: { intent?: Intent }) {
  const { tick, activity, go, clearIntent } = useShell();
  const { toast } = useApp();
  const [n, setN] = useState(0);
  const reload = () => setN((x) => x + 1);
  const load = useLoad(async () => {
    const [p, g, c, tl] = await Promise.all([call('principal_list'), call('grant_list', {}), call('connection_list'), call('terminal_list')]);
    return { principals: p.principals, grants: g.grants, connections: c.connections, terminals: tl.terminals };
  }, [tick, activity, n]);
  const d = load.data;
  // grants expire while the page is open: liveness comes from the clock, not the stored status
  const now = useNow(!!d && d.grants.length > 0, 15_000);
  const [open, setOpen] = useState<Open | null>(null);
  const [seq, setSeq] = useState(0);
  const show = (o: Open) => { setOpen(o); setSeq((k) => k + 1); };
  const close = () => setOpen(null);
  const [view, setView] = useState<TermView | null>(null);
  const activeConns = (d?.connections ?? []).filter((c) => c.status === 'active');
  const activeAgents = (d?.principals ?? []).filter((p) => p.status === 'active');

  useIntentOnce(intent, clearIntent, (i) => {
    if (i === 'add-agent') { show({ kind: 'create' }); return true; }
    if (i === 'add-grant') { show({ kind: 'grant' }); return true; }
    return false;
  });

  const showTerminal = (v: TermView) => {
    setView(v);
    setTimeout(() => {
      document.getElementById(TERM_DOM)?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      focusTerminalIn(TERM_DOM);
    }, 300);
  };

  const addBtn = <Button size="sm" tone="primary" icon="plus" onClick={() => show({ kind: 'create' })}>{t('agent.add')}</Button>;

  return (
    <>
      <Banner tone="neutral" icon="shield">{t('agent.intro')}</Banner>

      <Section title={t('agent.list')} id="dev-agents-h" aside={d && d.principals.length > 0 && (
        <>
          <Button size="sm" tone="ghost" onClick={() => show({ kind: 'grant' })}>{t('grant.title')}</Button>
          {addBtn}
        </>
      )}>
        {!d && load.error ? <LoadError error={load.error} onRetry={load.reload} />
          : !d ? <SkeletonRows n={2} />
            : d.principals.length === 0 ? (
              <EmptyState icon="user" title={t('agent.empty.title')} action={addBtn} compact>{t('agent.empty.body')}</EmptyState>
            ) : (
              <ul className="rows" aria-labelledby="dev-agents-h">
                {d.principals.map((p: Principal) => {
                  const active = p.status === 'active';
                  const gs = liveGrants(d.grants, p.id, now);
                  return (
                    <li key={p.id} className="dev-agent">
                      <div className="srow">
                        <IconTile icon="user" />
                        <div className="srow-main">
                          <span className="srow-title mono">{p.id}</span>
                          <span className="srow-meta">{runtimeText(p.runtime)}{gs.length === 0 && ` · ${t('agent.nogrant')}`}</span>
                        </div>
                        <div className="srow-end">
                          {!active && <Badge>{t('agent.off')}</Badge>}
                          {active && (
                            <>
                              <Button size="sm" tone="ghost" aria-label={t('grant.give.aria', { id: p.id })} onClick={() => show({ kind: 'grant', principal: p.id })}>{t('grant.give')}</Button>
                              <Button size="sm" tone="quiet" aria-label={t('agent.disable.aria', { id: p.id })} onClick={() => show({ kind: 'disable', id: p.id })}>{t('agent.disable')}</Button>
                            </>
                          )}
                        </div>
                      </div>
                      {gs.length > 0 && (
                        <ul className="dev-grants" aria-label={t('agent.grants.aria', { id: p.id })}>
                          {gs.map((g) => (
                            <li key={g.id}>
                              <span className="mono dev-grant-conn">{g.connection}</span>
                              <span className="dev-grant-meta">{grantText(g)}</span>
                              <Button size="sm" tone="quiet" aria-label={t('grant.revoke.aria', { agent: p.id, conn: g.connection })}
                                onClick={() => show({ kind: 'revoke', grant: g })}>{t('grant.revoke')}</Button>
                            </li>
                          ))}
                        </ul>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
      </Section>

      <Section title={t('agent.terminals')} id="dev-terms-h">
        {!d ? (load.error ? null : <SkeletonRows n={1} />)
          : d.terminals.length === 0 ? <p className="muted text-sm">{t('agent.terminals.empty')}</p>
            : (
              <ul className="rows" aria-labelledby="dev-terms-h">
                {d.terminals.map((x) => {
                  const shown = view?.terminalId === x.terminal_id;
                  return (
                    <li key={x.terminal_id} className="srow">
                      <IconTile icon="terminal" />
                      <div className="srow-main">
                        <span className="srow-title mono">{x.principal}</span>
                        <span className="srow-meta">{x.as_user ? t('agent.terminal.other', { user: x.as_user }) : t('agent.terminal.same')}</span>
                      </div>
                      <div className="srow-end">
                        {x.alive ? <Status tone="ok">{t('agent.terminal.live')}</Status> : <Badge>{t('term.dead')}</Badge>}
                        <Button size="sm" tone="ghost" aria-expanded={shown} aria-controls={TERM_DOM}
                          aria-label={t(shown ? 'term.hide.aria' : 'term.attach.aria', { name: x.principal })}
                          onClick={() => (shown ? setView(null) : showTerminal({ key: `attach-${x.terminal_id}`, name: x.principal, source: { kind: 'attach', terminalId: x.terminal_id }, terminalId: x.terminal_id }))}>
                          {t(shown ? 'term.hide' : 'term.attach')}
                        </Button>
                        <Button size="sm" tone="quiet" aria-label={t('term.end.aria', { id: x.principal })}
                          onClick={() => show({ kind: 'end', terminalId: x.terminal_id, principal: x.principal, asUser: x.as_user })}>{t('term.end')}</Button>
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
        {view && (
          <div className="dev-term-panel" role="region" aria-label={t('agent.terminal.region', { name: view.name })}>
            <AppTerminal key={view.key} domId={TERM_DOM} name={view.name} source={view.source}
              onOpened={(id) => { setView((v) => (v && v.key === view.key ? { ...v, terminalId: id } : v)); reload(); }}
              onFailed={() => setView(null)} onClosed={reload} />
          </div>
        )}
      </Section>

      <CreateAgentDialog key={`create-${seq}`} open={open?.kind === 'create'} onClose={close} onCreated={reload}
        onOpenTerminal={(v) => { close(); showTerminal(v); }} />
      <GrantDialog key={`grant-${seq}`} open={open?.kind === 'grant'} principal={open?.kind === 'grant' ? open.principal : undefined}
        principals={activeAgents} connections={activeConns} onClose={close}
        onDone={() => { close(); reload(); }} onConnections={() => { close(); go('services', { intent: 'add-connection' }); }} />
      <ConfirmDialog open={open?.kind === 'revoke'} title={t('grant.revoke.title')} description={t('grant.revoke.sub')}
        confirmLabel={t('grant.revoke.confirm')} tone="danger" info={t('agent.session')} onClose={close}
        run={async () => {
          if (open?.kind !== 'revoke') return;
          await call('grant_revoke', { id: open.grant.id }); toast(t('grant.toast.revoked'), 'ok'); close(); reload();
        }}>
        {open?.kind === 'revoke' && <KeyValues dense items={[{ k: t('grant.agent'), v: open.grant.principal, mono: true }, { k: t('grant.conn'), v: open.grant.connection, mono: true }]} />}
      </ConfirmDialog>
      <ConfirmDialog open={open?.kind === 'disable'} title={t('agent.disable.title')} description={t('agent.disable.sub')}
        confirmLabel={t('agent.disable.confirm')} tone="danger" warn={t('agent.disable.warn')} info={t('agent.session')} onClose={close}
        run={async () => {
          if (open?.kind !== 'disable') return;
          await call('principal_disable', { id: open.id }); toast(t('agent.toast.disabled'), 'ok'); close(); reload();
        }}>
        {open?.kind === 'disable' && <p className="mono text-sm">{open.id}</p>}
      </ConfirmDialog>
      {/* Ending a terminal stops what the app can reach. A program run as another account, or
          detached with setsid, tmux or screen, can outlive it with its token; only disabling the
          agent stops that token (docs/desktop-app.md §4.4). */}
      <ConfirmDialog open={open?.kind === 'end'} title={t('term.end.title')} description={t('term.end.sub')}
        confirmLabel={t('term.end.confirm')} tone="danger" onClose={close}
        run={async () => {
          if (open?.kind !== 'end') return;
          const id = open.terminalId;
          await call('terminal_close', { terminal_id: id });
          if (view?.terminalId === id) setView(null);
          close(); reload();
        }}>
        {open?.kind === 'end' && (
          <Banner tone="info" action={d?.principals.some((p) => p.id === open.principal && p.status === 'active')
            ? <Button size="sm" tone="ghost" onClick={() => show({ kind: 'disable', id: open.principal })}>{t('term.end.disableToo')}</Button> : undefined}>
            {open.asUser ? t('term.end.note.other', { user: open.asUser }) : t('term.end.note')}
          </Banner>
        )}
      </ConfirmDialog>
    </>
  );
}

// ---------------------------------------------------------------- add an agent

function CreateAgentDialog({ open, onClose, onCreated, onOpenTerminal }: {
  open: boolean; onClose(): void; onCreated(): void; onOpenTerminal(v: TermView): void;
}) {
  const { toast } = useApp();
  const [name, setName] = useState('agent-2');
  const [where, setWhere] = useState<Where | ''>('');
  const [account, setAccount] = useState('agent');
  const [nameErr, setNameErr] = useState<CopyKey | null>(null);
  const [whereErr, setWhereErr] = useState(false);
  const [accErr, setAccErr] = useState(false);
  const [busy, setBusy] = useState(false);
  const [made, setMade] = useState<{ id: string; tokenRef: string; asUser: string | null } | null>(null);
  const [copied, setCopied] = useState(false);
  const [copyBusy, setCopyBusy] = useState(false);
  const used = useRef(false);
  const running = useRef(false);
  const madeRef = useRef(made);
  madeRef.current = made;
  const nameRef = useRef<HTMLInputElement>(null);
  const accRef = useRef<HTMLInputElement>(null);

  // a token nobody used is dropped from the core when the dialog goes away
  const discard = () => {
    const m = madeRef.current;
    if (m && !used.current) { used.current = true; void call('onetime_discard', { ref: m.tokenRef }).catch(() => undefined); }
  };
  useEffect(() => { if (!open) discard(); }, [open]);
  useEffect(() => () => discard(), []);

  const create = async () => {
    if (running.current) return;
    if (!isValidName(name)) { setNameErr('agent.err.name'); nameRef.current?.focus(); return; }
    if (!where) { setWhereErr(true); return; }
    if (where === 'other' && !isAccountName(account)) { setAccErr(true); accRef.current?.focus(); return; }
    running.current = true; setBusy(true);
    try {
      const r = await call('principal_create', { id: name, runtime: runtimeFor(where, account) });
      setMade({ id: r.id, tokenRef: r.token_ref, asUser: where === 'other' ? account : null });
      onCreated();
    } catch (e) {
      const reason = toIpcError(e).reason;
      setNameErr(reason === 'principal_exists' ? 'agent.err.exists' : reason === 'invalid_name' ? 'agent.err.name' : 'error.generic');
      nameRef.current?.focus();
    } finally { running.current = false; setBusy(false); }
  };

  const copy = async () => {
    if (!made || copied || used.current || copyBusy) return;
    setCopyBusy(true);
    try {
      const r = await call('onetime_copy', { ref: made.tokenRef });
      if (r.copied) { used.current = true; setCopied(true); toast(t('term.toast.copied'), 'ok'); }
    } catch { toast(t('error.generic'), 'warn'); } finally { setCopyBusy(false); }
  };

  const openTerm = () => {
    if (!made) return;
    if (copied) { onClose(); return; }
    used.current = true;
    onOpenTerminal({ key: `open-${made.tokenRef}`, name: made.id, source: { kind: 'open', tokenRef: made.tokenRef, asUser: made.asUser }, terminalId: null });
  };

  if (made) {
    return (
      <Dialog open={open} title={t('agent.made.title')} description={t(copied ? 'agent.made.copied' : 'agent.made.sub')} onClose={onClose}
        footerStart={!copied ? <Button tone="ghost" icon="copy" busy={copyBusy} onClick={() => void copy()}>{t('agent.copyToken')}</Button> : undefined}
        footer={copied
          ? <Button tone="primary" onClick={onClose}>{t('act.done')}</Button>
          : <><Button tone="ghost" onClick={onClose}>{t('act.close')}</Button><Button tone="primary" icon="terminal" onClick={openTerm} data-autofocus="">{t('agent.openTerminal')}</Button></>}>
        <div role="status">
          <KeyValues dense items={[
            { k: t('agent.name'), v: made.id, mono: true },
            { k: t('agent.where'), v: made.asUser ? t('agent.where.other.text', { user: made.asUser }) : t('agent.where.same.text') },
          ]} />
        </div>
        {!made.asUser && <Banner tone="warn">{t('agent.where.warn')}</Banner>}
        <Banner tone="info">{t('agent.made.next')}</Banner>
      </Dialog>
    );
  }

  return (
    <Dialog open={open} title={t('agent.create.title')} description={t('agent.create.sub')} onClose={onClose} busy={busy}
      onSubmit={() => void create()}
      footer={<><Button tone="ghost" onClick={onClose} blocked={busy}>{t('act.cancel')}</Button><Button tone="primary" type="submit" busy={busy}>{t('agent.create.confirm')}</Button></>}>
      <TextField label={t('agent.name')} mono value={name} inputRef={nameRef} maxLength={64} help={t('agent.name.help')}
        error={nameErr ? t(nameErr) : null} onChange={(v) => { setName(v); setNameErr(null); }} />
      <ChoiceCards<Where> label={t('agent.where')} value={where} error={whereErr ? t('agent.where.required') : null}
        onChange={(v) => { setWhere(v); setWhereErr(false); }}
        options={[
          { value: 'other', title: <>{t('agent.where.other')} <Badge tone="accent">{t('agent.where.other.sub')}</Badge></>, sub: t('agent.where.other.help') },
          { value: 'same', title: t('agent.where.same'), sub: t('agent.where.same.text') },
        ]} />
      {where === 'other' && (
        <TextField label={t('agent.where.user')} mono value={account} inputRef={accRef}
          error={accErr ? t('agent.where.user.err') : null} onChange={(v) => { setAccount(v); setAccErr(false); }} />
      )}
      {where === 'same' && <Banner tone="warn">{t('agent.where.warn')}</Banner>}
    </Dialog>
  );
}

// ---------------------------------------------------------------- grant

function GrantDialog({ open, principal, principals, connections, onClose, onDone, onConnections }: {
  open: boolean; principal: string | undefined; principals: Principal[]; connections: ConnectionView[];
  onClose(): void; onDone(): void; onConnections(): void;
}) {
  const { toast } = useApp();
  const [who, setWho] = useState(principal ?? principals[0]?.id ?? '');
  const [conn, setConn] = useState(connections[0]?.id ?? '');
  const [ttl, setTtl] = useState<GrantTtl>('1h');
  const [max, setMax] = useState('');
  const [pass, setPass] = useState('');
  const [errs, setErrs] = useState<{ who?: CopyKey; conn?: CopyKey; max?: CopyKey; pass?: CopyKey; form?: CopyKey }>({});
  const [busy, setBusy] = useState(false);
  const running = useRef(false);
  const maxRef = useRef<HTMLInputElement>(null);
  const passRef = useRef<HTMLInputElement>(null);
  const whoRef = useRef<HTMLSelectElement>(null);
  const connRef = useRef<HTMLSelectElement>(null);

  // the selects always hold one of their options (the lists load after the dialog opens)
  useEffect(() => { if (!principals.some((p) => p.id === who) && principals[0]) setWho(principal && principals.some((p) => p.id === principal) ? principal : principals[0].id); }, [who, principal, principals]);
  useEffect(() => { if (!connections.some((c) => c.id === conn) && connections[0]) setConn(connections[0].id); }, [conn, connections]);
  useEffect(() => { if (!open) setPass(''); }, [open]);

  if (connections.length === 0) {
    return (
      <Dialog open={open} title={t('grant.title')} description={t('grant.sub')} onClose={onClose} size="sm"
        footer={<><Button tone="ghost" onClick={onClose}>{t('act.close')}</Button><Button tone="primary" icon="plug" onClick={onConnections}>{t('grant.noconn.go')}</Button></>}>
        <EmptyState icon="plug" title={t('grant.noconn.title')} compact>{t('grant.noconn.body')}</EmptyState>
      </Dialog>
    );
  }

  const submit = async () => {
    if (running.current) return;
    const m = parseMaxUses(max);
    const e: typeof errs = {};
    if (!principals.some((p) => p.id === who)) e.who = 'grant.err.agent';
    if (!connections.some((c) => c.id === conn)) e.conn = 'grant.err.conn';
    if (!m.ok) e.max = 'grant.max.err';
    if (!pass) e.pass = 'pass.err.empty';
    setErrs(e);
    if (e.who) { whoRef.current?.focus(); return; }
    if (e.conn) { connRef.current?.focus(); return; }
    if (e.max) { maxRef.current?.focus(); return; }
    if (e.pass) { passRef.current?.focus(); return; }
    running.current = true; setBusy(true);
    try {
      await call('grant_create', { principal: who, connection: conn, ttl, admin_passphrase: pass, ...(m.ok && m.value ? { max_uses: m.value } : {}) });
      setPass('');
      toast(t('grant.toast.created'), 'ok');
      onDone();
    } catch (err) {
      setPass('');
      if (isAuthError(err)) { setErrs({ pass: passErrorKey(err) }); passRef.current?.focus(); }
      else setErrs({ form: 'error.generic' });
    } finally { running.current = false; setBusy(false); }
  };

  return (
    <Dialog open={open} title={t('grant.title')} description={t('grant.sub')} onClose={onClose} busy={busy} onSubmit={() => void submit()}
      footer={<><Button tone="ghost" onClick={onClose} blocked={busy}>{t('act.cancel')}</Button><Button tone="primary" type="submit" busy={busy}>{t('grant.confirm')}</Button></>}>
      {principals.length === 0 && <Banner tone="warn">{t('grant.noagent')}</Banner>}
      <div className="form-grid">
        <SelectField label={t('grant.agent')} value={who} selectRef={whoRef} error={errs.who ? t(errs.who) : null}
          options={principals.map((p) => ({ value: p.id, label: p.id }))} onChange={(v) => { setWho(v); setErrs((x) => ({ ...x, who: undefined })); }} />
        <SelectField label={t('grant.conn')} value={conn} selectRef={connRef} error={errs.conn ? t(errs.conn) : null}
          options={connections.map((c) => ({ value: c.id, label: c.id }))} onChange={(v) => { setConn(v); setErrs((x) => ({ ...x, conn: undefined })); }} />
      </div>
      <Segmented<GrantTtl> label={t('grant.ttl')} hideLabel={false} value={ttl} onChange={setTtl}
        options={GRANT_TTLS.map((x) => ({ value: x, label: t(TTL_LABEL[x]) }))} />
      <TextField label={t('grant.max')} aside={t('grant.max.aside')} help={t('grant.max.help')} mono value={max} inputRef={maxRef} inputMode="numeric" maxLength={9}
        error={errs.max ? t(errs.max) : null} onChange={(v) => { setMax(v); setErrs((x) => ({ ...x, max: undefined })); }} />
      <PassField value={pass} inputRef={passRef} error={errs.pass ? t(errs.pass) : null}
        onChange={(v) => { setPass(v); setErrs((x) => ({ ...x, pass: undefined })); }} />
      {errs.form && <Banner tone="danger">{t(errs.form)}</Banner>}
    </Dialog>
  );
}
