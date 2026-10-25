import { useEffect, useRef, useState } from 'react';
import { t, type CopyKey } from '../copy';
import { call, toIpcError } from '../ipc/client';
import type { ConnectionView, Grant, Principal } from '../ipc/contract';
import { GRANT_TTLS, liveGrants, parseMaxUses, pendingApprovals, type ApprovalView, type GrantTtl } from '../lib/dash';
import { shortTime } from '../lib/format';
import { isAccountName, isValidName, runtimeFor } from '../lib/validators';
import { useApp } from '../ui/context';
import { PassField, SelectField, TextField, useSelectDefault } from '../ui/fields';
import { Callout, Segmented } from '../ui/form';
import { AppTerminal, focusTerminalIn, type TerminalSource } from '../ui/Terminal';
import { ConfirmSheet } from './Confirm';
import { passErrorKey, useClearOnClose, useDash, useIntent, useLoad, useNow, useSheets, type Intent } from './context';
import { Empty, ListCard, metaLine, Row, SectionHead, Tag } from './parts';
import { Sheet } from './Sheet';

type Where = 'other' | 'same';
type AgentSheet =
  | { kind: 'create' }
  | { kind: 'grant'; principal?: string }
  | { kind: 'revoke'; grant: Grant }
  | { kind: 'disable'; id: string }
  | { kind: 'end'; terminalId: string; principal: string; asUser: string | null }
  | { kind: 'approve'; approval: ApprovalView };
interface View { key: string; name: string; source: TerminalSource; terminalId: string | null }
const TTL_LABEL: Record<GrantTtl, CopyKey> = { '1h': 'agent.ttl.1', '8h': 'agent.ttl.8', '24h': 'agent.ttl.24' };
const TERM_DOM = 'dash-term';

/** `user-agent` → other account `agent`; `default` → this account. */
function runtimeText(runtime: string): string {
  if (runtime === 'default') return `${t('agent.where.same')} · ${t('agent.where.same.sub')}`;
  if (runtime.startsWith('user-')) return `${t('agent.where.other')} · ${runtime.slice(5)}`;
  return runtime;
}

function grantText(g: Grant): string {
  const uses = g.max_uses !== null && g.max_uses !== undefined
    ? t('grant.usesOf', { n: String(g.uses), max: String(g.max_uses) }) : t('grant.uses', { n: String(g.uses) });
  return metaLine(t('grant.until', { time: shortTime(String(g.expires_at)) }), uses);
}

/** The approval row's second line: who asked, through which connection, when, and the body. */
function approvalMeta(a: ApprovalView): string {
  return metaLine(a.caller, a.connection, shortTime(a.created_at), bodySummary(a));
}

function bodySummary(a: ApprovalView): string {
  if (!a.bodyBytes) return t('appr.body.none');
  return metaLine(t('appr.body.size', { n: a.bodyBytes }), a.contentType, a.bodyHash);
}

/** Everything the approval is bound to, as text (the request is untrusted). */
function ApprovalDetails({ a }: { a: ApprovalView }) {
  return (
    <>
      <dl className="kv sheet-kv">
        <div className="kv-row"><dt>{t('appr.req')}</dt><dd>{`${a.method} ${a.target}`}</dd></div>
        <div className="kv-row"><dt>{t('grant.agent')}</dt><dd>{a.caller}</dd></div>
        <div className="kv-row"><dt>{t('grant.conn')}</dt><dd>{a.connection}</dd></div>
        <div className="kv-row"><dt>{t('appr.when')}</dt><dd>{shortTime(a.created_at)}</dd></div>
        {a.origin && <div className="kv-row"><dt>{t('appr.origin')}</dt><dd>{a.origin}</dd></div>}
        <div className="kv-row"><dt>{t('appr.body')}</dt><dd>{bodySummary(a)}</dd></div>
      </dl>
      {a.bodyPreview !== null && a.bodyPreview !== '' && (
        <div className="field">
          <div className="label"><span id="appr-body-lbl">{t('appr.body.preview')}</span>{a.bodyTruncated && <span className="hint">{t('appr.body.cut')}</span>}</div>
          <pre className="body-preview" role="region" aria-labelledby="appr-body-lbl" tabIndex={0}>{a.bodyPreview}</pre>
        </div>
      )}
      {!!a.bodyBytes && a.bodyPreview === null && <div className="help">{t('appr.body.binary')}</div>}
    </>
  );
}

/** Agents: principals with their grants, the in-app terminals that are still running, and the
 *  queue of requests waiting for approval. Paths and names in requests are rendered as text. */
export function AgentsPage({ intent, onIntent }: { intent?: Intent; onIntent(): void }) {
  const { tick, activity, go } = useDash();
  const { toast } = useApp();
  const [n, setN] = useState(0);
  const load = useLoad(async () => {
    const [p, g, c, tl, a] = await Promise.all([
      call('principal_list'), call('grant_list', {}), call('connection_list'), call('terminal_list'), call('approvals_list'),
    ]);
    return { principals: p.principals, grants: g.grants, connections: c.connections, terminals: tl.terminals, approvals: pendingApprovals(a.approvals) };
  }, [tick, activity, n]);
  const reload = () => setN((x) => x + 1);
  const sheets = useSheets<AgentSheet>();
  const [view, setView] = useState<View | null>(null);
  const d = load.data;
  // grants expire while the page is open: liveness is derived from the clock, not the stored status
  const now = useNow(!!d && d.grants.length > 0, 15_000);
  const activeConns = (d?.connections ?? []).filter((c) => c.status === 'active');

  useIntent(intent, onIntent, (i) => {
    if (i === 'add-agent') { sheets.open({ kind: 'create' }); return true; }
    if (i === 'add-grant') { sheets.open({ kind: 'grant' }); return true; }
    return false;
  });

  const showTerminal = (v: View) => {
    setView(v);
    setTimeout(() => {
      document.getElementById(TERM_DOM)?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      focusTerminalIn(TERM_DOM);
    }, 350);
  };

  const addBtn = <button className="btn btn-primary btn-sm" type="button" onClick={() => sheets.open({ kind: 'create' })}>{t('agents.add')}</button>;

  return (
    <>
      <SectionHead title={t('agents.list')}>
        {d && d.principals.length > 0 && (
          <>
            <button className="btn btn-ghost btn-sm" type="button" onClick={() => sheets.open({ kind: 'grant' })}>{t('grant.title')}</button>
            {addBtn}
          </>
        )}
      </SectionHead>
      <ListCard items={d?.principals ?? null} failed={load.failed} empty="page.agents.empty" emptyAction={addBtn} label={t('agents.list')}>
        {(items) => items.map((p: Principal) => {
          const active = p.status === 'active';
          const gs = liveGrants(d?.grants ?? [], p.id, now);
          return (
            <Row key={p.id} dot={active ? (gs.length ? 'on' : 'idle') : 'idle'} mono name={p.id}
              tag={active ? undefined : <Tag>{t('st.disabled')}</Tag>}
              meta={metaLine(runtimeText(p.runtime), gs.length ? null : t('done.tile.agent.nogrant'))}
              sub={gs.length > 0 && (
                <ul className="sub-list" aria-label={t('agents.grants.aria', { id: p.id })}>
                  {gs.map((g) => (
                    <li key={g.id}>
                      <span className="mono">{g.connection}</span>
                      <span className="sub-meta">{grantText(g)}</span>
                      <button className="btn btn-text btn-sm" type="button" aria-label={t('grant.revoke.aria', { agent: p.id, conn: g.connection })}
                        onClick={() => sheets.open({ kind: 'revoke', grant: g })}>{t('grant.revoke')}</button>
                    </li>
                  ))}
                </ul>
              )}>
              {active && (
                <>
                  <button className="btn btn-ghost btn-sm" type="button" aria-label={t('grant.for.aria', { id: p.id })}
                    onClick={() => sheets.open({ kind: 'grant', principal: p.id })}>{t('grant.give')}</button>
                  <button className="btn btn-text btn-sm" type="button" aria-label={t('agents.disable.aria', { id: p.id })}
                    onClick={() => sheets.open({ kind: 'disable', id: p.id })}>{t('agents.disable')}</button>
                </>
              )}
            </Row>
          );
        })}
      </ListCard>

      <SectionHead title={t('agents.terminals')} />
      <ListCard items={d?.terminals ?? null} failed={load.failed} empty="agents.terminals.empty" label={t('agents.terminals')}>
        {(items) => items.map((x) => {
          const shown = view?.terminalId === x.terminal_id;
          return (
            <Row key={x.terminal_id} dot={x.alive ? 'live' : 'idle'} mono name={x.principal}
              tag={x.alive ? undefined : <Tag>{t('term.dead')}</Tag>} meta={metaLine(x.as_user ? `${t('agent.where.other')} · ${x.as_user}` : t('agent.where.same'))}>
              <button className="btn btn-ghost btn-sm" type="button" aria-expanded={shown} aria-controls={TERM_DOM}
                aria-label={t(shown ? 'term.hide.aria' : 'term.attach.aria', { name: x.principal })}
                onClick={() => (shown ? setView(null) : showTerminal({ key: `attach-${x.terminal_id}`, name: x.principal, source: { kind: 'attach', terminalId: x.terminal_id }, terminalId: x.terminal_id }))}>
                {t(shown ? 'term.hide' : 'term.attach')}
              </button>
              <button className="btn btn-text btn-sm" type="button" aria-label={t('term.end.aria', { id: x.principal })}
                onClick={() => sheets.open({ kind: 'end', terminalId: x.terminal_id, principal: x.principal, asUser: x.as_user })}>{t('term.end')}</button>
            </Row>
          );
        })}
      </ListCard>
      {view && (
        <div className="term-panel">
          <AppTerminal key={view.key} domId={TERM_DOM} name={view.name} source={view.source}
            onOpened={(id) => { setView((v) => (v && v.key === view.key ? { ...v, terminalId: id } : v)); reload(); }}
            onFailed={() => setView(null)} onClosed={reload} />
        </div>
      )}

      <SectionHead title={t('agents.approvals')} />
      <ListCard items={d?.approvals ?? null} failed={load.failed} empty="appr.empty" label={t('agents.approvals')}>
        {(items) => items.map((a) => (
          <Row key={a.digest} dot="warn" mono name={a.method} meta={approvalMeta(a)}
            sub={<div className="target">{a.target}</div>}>
            <button className="btn btn-primary btn-sm" type="button" aria-label={t('appr.approve.aria', { req: `${a.method} ${a.target}` })}
              onClick={() => sheets.open({ kind: 'approve', approval: a })}>{t('appr.approve')}</button>
          </Row>
        ))}
      </ListCard>

      <CreateAgentSheet key={sheets.key('create')} open={sheets.isOpen('create')} onClose={sheets.close} onCreated={reload}
        onOpenTerminal={(v) => { sheets.close(); showTerminal(v); }} />
      <GrantSheet key={sheets.key('grant')} open={sheets.isOpen('grant')} principal={sheets.data('grant')?.principal}
        principals={(d?.principals ?? []).filter((p) => p.status === 'active')} connections={activeConns}
        onClose={sheets.close} onDone={() => { sheets.close(); reload(); }} onConnections={() => { sheets.close(); go('connections', 'add-connection'); }} />
      <ConfirmSheet key={sheets.key('revoke')} id="sheet-grant-revoke" open={sheets.isOpen('revoke')} title={t('grant.revoke.title')} lead={t('grant.revoke.sub')}
        confirmLabel={t('grant.revoke.confirm')} onClose={sheets.close} notes={[t('session.note')]}
        chips={(() => { const g = sheets.data('revoke')?.grant; return g ? [g.principal, g.connection] : []; })()}
        run={async () => {
          const g = sheets.data('revoke')?.grant;
          if (!g) return;
          await call('grant_revoke', { id: g.id }); toast(t('toast.grant.revoked')); sheets.close(); reload();
        }} />
      <ConfirmSheet key={sheets.key('disable')} id="sheet-agent-disable" open={sheets.isOpen('disable')} title={t('agents.disable.title')} lead={t('agents.disable.sub')}
        confirmLabel={t('agents.disable.confirm')} onClose={sheets.close} chips={[sheets.data('disable')?.id ?? '']} warn={t('agents.disable.warn')}
        notes={[t('session.note')]}
        run={async () => {
          const id = sheets.data('disable')?.id;
          if (!id) return;
          await call('principal_disable', { id }); toast(t('toast.agent.disabled')); sheets.close(); reload();
        }} />
      {/* Ending a terminal stops what the app can reach. A program run as another account, or
          detached with setsid, tmux or screen, can outlive it with its token; only disabling the
          agent stops that token (docs/desktop-app.md §4.4). */}
      <ConfirmSheet key={sheets.key('end')} id="sheet-term-end" open={sheets.isOpen('end')} title={t('term.end.title')} lead={t('term.end.sub')}
        confirmLabel={t('term.end.confirm')} onClose={sheets.close} chips={[sheets.data('end')?.principal ?? '']}
        run={async () => {
          const x = sheets.data('end');
          if (!x) return;
          await call('terminal_close', { terminal_id: x.terminalId });
          if (view?.terminalId === x.terminalId) setView(null);
          sheets.close(); reload();
        }}>
        {(() => {
          const x = sheets.data('end');
          if (!x) return null;
          const active = !!d?.principals.some((p) => p.id === x.principal && p.status === 'active');
          return (
            <Callout kind="info">
              {x.asUser ? t('term.end.note.other', { user: x.asUser }) : t('term.end.note')}
              {active && (
                <>
                  {' '}
                  <button className="btn btn-ghost btn-sm" type="button" onClick={() => sheets.open({ kind: 'disable', id: x.principal })}>{t('agents.disable.title')}</button>
                </>
              )}
            </Callout>
          );
        })()}
      </ConfirmSheet>
      <ConfirmSheet key={sheets.key('approve')} id="sheet-approve" open={sheets.isOpen('approve')} title={t('appr.title')} lead={t('appr.sub')}
        confirmLabel={t('appr.confirm')} onClose={sheets.close} needPass
        errorFor={(e) => (toIpcError(e).reason === 'approval_not_pending' || toIpcError(e).reason === 'approval_not_found' ? 'appr.err.gone' : null)}
        run={async (pass) => {
          const a = sheets.data('approve')?.approval;
          if (!a) return;
          await call('approvals_approve', { digest: a.digest, admin_passphrase: pass });
          toast(t('toast.appr.done')); sheets.close(); reload();
        }}>
        {(() => { const a = sheets.data('approve')?.approval; return a ? <ApprovalDetails a={a} /> : null; })()}
      </ConfirmSheet>
    </>
  );
}

// ---------------------------------------------------------------- create an agent

function CreateAgentSheet({ open, onClose, onCreated, onOpenTerminal }: {
  open: boolean; onClose(): void; onCreated(): void; onOpenTerminal(v: View): void;
}) {
  const { toast, field } = useApp();
  const [name, setName] = useState('agent-2');
  const [where, setWhere] = useState<Where | null>(null);
  const [account, setAccount] = useState('agent');
  const [nameErr, setNameErr] = useState<CopyKey | null>(null);
  const [whereErr, setWhereErr] = useState(false);
  const [accErr, setAccErr] = useState(false);
  const [busy, setBusy] = useState(false);
  const [made, setMade] = useState<{ id: string; tokenRef: string; asUser: string | null } | null>(null);
  const [copied, setCopied] = useState(false);
  const used = useRef(false);
  const madeRef = useRef(made);
  madeRef.current = made;
  const nameRef = useRef<HTMLInputElement>(null);
  const whereFirst = useRef<HTMLInputElement | null>(null);
  const accRef = useRef<HTMLInputElement>(null);
  const summaryRef = useRef<HTMLDivElement>(null);

  // a token nobody used is dropped from the core when the sheet goes away
  useEffect(() => {
    if (open) return;
    const m = madeRef.current;
    if (m && !used.current) { used.current = true; call('onetime_discard', { ref: m.tokenRef }).catch(() => undefined); }
  }, [open]);

  const create = async () => {
    if (!isValidName(name)) { setNameErr('agent.err.name'); nameRef.current?.focus(); return; }
    if (!where) { setWhereErr(true); whereFirst.current?.focus(); return; }
    if (where === 'other' && !isAccountName(account)) { setAccErr(true); accRef.current?.focus(); return; }
    setBusy(true);
    try {
      const r = await call('principal_create', { id: name, runtime: runtimeFor(where, account) });
      setMade({ id: r.id, tokenRef: r.token_ref, asUser: where === 'other' ? account : null });
      field.ripple(0.08);
      onCreated();
      setTimeout(() => summaryRef.current?.focus({ preventScroll: true }), 40);
    } catch (e) {
      const reason = toIpcError(e).reason;
      setNameErr(reason === 'principal_exists' ? 'agent.err.exists' : reason === 'invalid_name' ? 'agent.err.name' : 'error.generic');
      nameRef.current?.focus();
    } finally { setBusy(false); }
  };

  const copy = async () => {
    if (!made || copied) return;
    try {
      const r = await call('onetime_copy', { ref: made.tokenRef });
      if (r.copied) { used.current = true; setCopied(true); toast(t('toast.copy.token')); }
    } catch { toast(t('error.generic'), 'warn'); }
  };

  const openTerm = () => {
    if (!made) return;
    if (copied) { onClose(); return; }
    used.current = true;
    onOpenTerminal({ key: `open-${made.tokenRef}`, name: made.id, source: { kind: 'open', tokenRef: made.tokenRef, asUser: made.asUser }, terminalId: null });
  };

  if (made) {
    return (
      <Sheet id="sheet-agent" open={open} title={t('agent.title')} lead={t(copied ? 'agents.copied' : 'agents.token.sub')}
        primaryLabel={t(copied ? 'common.done' : 'agent.connect')} onPrimary={openTerm} onClose={onClose} noCancel={copied} cancelLabel={t('common.close')}>
        <div className="agent-sum" tabIndex={-1} ref={summaryRef} role="status">
          <span>{made.id}</span>
          <span className={made.asUser ? undefined : 'warn'}>{made.asUser ? `${t('agent.where.other')} · ${made.asUser}` : `${t('agent.where.same')} · ${t('agent.where.same.sub')}`}</span>
          <span>{t('done.tile.agent.nogrant')}</span>
        </div>
        <div className="sheet-acts">
          <button className="btn btn-ghost btn-sm" type="button" aria-disabled={copied || undefined} onClick={() => void copy()}>{t('term.copy')}</button>
        </div>
      </Sheet>
    );
  }

  return (
    <Sheet id="sheet-agent" open={open} title={t('agent.title')} lead={t('agent.sub')} primaryLabel={t('agents.create')} busy={busy}
      onPrimary={() => void create()} onClose={onClose}>
      <TextField id="agent-name" label={t('agent.name')} mono value={name} inputRef={nameRef} maxLength={64} error={nameErr ? t(nameErr) : null}
        onChange={(v) => { setName(v); setNameErr(null); }} />
      <div className="field">
        <div className="label"><span id="agent-where-lbl">{t('agent.where')}</span></div>
        <Segmented<Where> name="agent-where" labelledBy="agent-where-lbl" two value={where} firstRef={(el) => { whereFirst.current = el; }}
          onChange={(v) => { setWhere(v); setWhereErr(false); }}
          options={[
            { value: 'other', label: t('agent.where.other'), sub: t('agent.where.other.sub') },
            { value: 'same', label: t('agent.where.same'), sub: t('agent.where.same.sub') },
          ]} />
        <div className="help err" hidden={!whereErr} role="alert">{whereErr ? t('agent.where.required') : ''}</div>
        {where === 'other' && (
          <div style={{ marginTop: 10 }}>
            <TextField id="agent-account" label={t('agent.where.user')} mono value={account} inputRef={accRef} error={accErr ? t('agent.where.user.err') : null}
              onChange={(v) => { setAccount(v); setAccErr(false); }} />
          </div>
        )}
        {where === 'same' && <Callout>{t('agent.where.warn')}</Callout>}
      </div>
    </Sheet>
  );
}

// ---------------------------------------------------------------- grant

function GrantSheet({ open, principal, principals, connections, onClose, onDone, onConnections }: {
  open: boolean; principal: string | undefined; principals: Principal[]; connections: ConnectionView[];
  onClose(): void; onDone(): void; onConnections(): void;
}) {
  const { toast, field } = useApp();
  const [who, setWho] = useState(principal ?? principals[0]?.id ?? '');
  const [conn, setConn] = useState(connections[0]?.id ?? '');
  useSelectDefault(who, principals.map((p) => p.id), setWho);
  useSelectDefault(conn, connections.map((c) => c.id), setConn);
  const [ttl, setTtl] = useState<GrantTtl>('1h');
  const [max, setMax] = useState('');
  const [pass, setPass] = useState('');
  const [errs, setErrs] = useState<{ who?: CopyKey; conn?: CopyKey; max?: CopyKey; pass?: CopyKey; form?: CopyKey }>({});
  const [busy, setBusy] = useState(false);
  const maxRef = useRef<HTMLInputElement>(null);
  const passRef = useRef<HTMLInputElement>(null);
  const whoRef = useRef<HTMLSelectElement>(null);
  const connRef = useRef<HTMLSelectElement>(null);

  useEffect(() => { if (!who && principals[0]) setWho(principal ?? principals[0].id); }, [who, principal, principals]);
  useEffect(() => { if (!conn && connections[0]) setConn(connections[0].id); }, [conn, connections]);
  useClearOnClose(open, () => setPass(''));

  if (connections.length === 0) {
    return (
      <Sheet id="sheet-grant" open={open} title={t('grant.title')} lead={t('grant.sub')} primaryLabel={t('conns.add')} onPrimary={onConnections} onClose={onClose}>
        <Empty text={t('grant.noconn')} />
      </Sheet>
    );
  }

  const submit = async () => {
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
    setBusy(true);
    try {
      await call('grant_create', { principal: who, connection: conn, ttl, admin_passphrase: pass, ...(m.ok && m.value ? { max_uses: m.value } : {}) });
      setPass('');
      field.ripple(0.07);
      toast(t('toast.grant.created'));
      onDone();
    } catch (err) {
      setPass('');
      if (toIpcError(err).error === 'AuthFailed') { setErrs({ pass: passErrorKey(err) }); passRef.current?.focus(); }
      else setErrs({ form: 'error.generic' });
    } finally { setBusy(false); }
  };

  return (
    <Sheet id="sheet-grant" open={open} title={t('grant.title')} lead={t('grant.sub')} primaryLabel={t('grant.confirm')} busy={busy}
      onPrimary={() => void submit()} onClose={onClose}>
      <div className="row">
        <SelectField id="grant-agent" label={t('grant.agent')} mono value={who} selectRef={whoRef} error={errs.who ? t(errs.who) : null}
          options={principals.map((p) => ({ value: p.id, label: p.id }))} onChange={(v) => { setWho(v); setErrs((x) => ({ ...x, who: undefined })); }} />
        <SelectField id="grant-conn" label={t('grant.conn')} mono value={conn} selectRef={connRef} error={errs.conn ? t(errs.conn) : null}
          options={connections.map((c) => ({ value: c.id, label: c.id }))} onChange={(v) => { setConn(v); setErrs((x) => ({ ...x, conn: undefined })); }} />
      </div>
      <div className="field">
        <div className="label"><span id="grant-ttl-lbl">{t('agent.ttl')}</span></div>
        <Segmented<GrantTtl> name="grant-ttl" labelledBy="grant-ttl-lbl" value={ttl} onChange={setTtl}
          options={GRANT_TTLS.map((x) => ({ value: x, label: t(TTL_LABEL[x]) }))} />
      </div>
      <TextField id="grant-max" label={t('grant.max')} hint={t('grant.max.hint')} mono value={max} inputRef={maxRef} inputMode="numeric" maxLength={9}
        error={errs.max ? t(errs.max) : null} onChange={(v) => { setMax(v); setErrs((x) => ({ ...x, max: undefined })); }} />
      <PassField id="grant-pass" value={pass} inputRef={passRef} error={errs.pass ? t(errs.pass) : null}
        onChange={(v) => { setPass(v); setErrs((x) => ({ ...x, pass: undefined })); }} />
      {errs.form && <div className="help err" role="alert">{t(errs.form)}</div>}
    </Sheet>
  );
}
