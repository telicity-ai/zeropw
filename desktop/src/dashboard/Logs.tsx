import { useRef, useState } from 'react';
import { t, type CopyKey } from '../copy';
import { call, toIpcError } from '../ipc/client';
import type { Incident, Principal } from '../ipc/contract';
import { declarableScopes, declareOutcome, isPlainText, openIncident, runtimeStopsAll, valueText, type IncidentScope } from '../lib/dash';
import { shortTime } from '../lib/format';
import { recordView } from '../lib/records';
import { isValidName } from '../lib/validators';
import { useApp } from '../ui/context';
import { PassField, SelectField, TextField, useSelectDefault } from '../ui/fields';
import { Callout, Segmented } from '../ui/form';
import { ConfirmSheet } from './Confirm';
import { passErrorKey, useClearOnClose, useDash, useLoad, useSheets } from './context';
import { ListCard, metaLine, Row, Tag } from './parts';
import { Sheet } from './Sheet';

type Tab = 'audit' | 'alerts' | 'incidents';
type Scope = IncidentScope;
type LogSheet = { kind: 'declare' } | { kind: 'close'; incident: Incident };
const LIMIT = 200;
const SCOPE_LABEL: Record<Scope, CopyKey> = { principal: 'inc.scope.principal', runtime: 'inc.scope.runtime', all: 'inc.scope.all' };
const scopeText = (s: string): string => (s in SCOPE_LABEL ? t(SCOPE_LABEL[s as Scope]) : s);

/** A usage record or an alert in plain words (lib/records.ts). What the table does not know (a
 *  new code, the CLI's own English, the other fields) stays on a second line as the core wrote it. */
export function RecordRow({ rec, kind }: { rec: Record<string, unknown>; kind: 'audit' | 'alert' }) {
  const v = recordView(rec, kind);
  return (
    <Row dot={kind === 'alert' ? 'warn' : 'idle'} name={v.title} meta={metaLine(shortTime(v.ts), ...v.meta)}
      sub={v.raw.length > 0 && <div className="meta wrap">{v.raw.join('  ')}</div>} />
  );
}

/** Records: the usage log, alerts and incidents (declare and close). */
export function LogsPage() {
  const { tick: shellTick, activity, bump, go } = useDash();
  const tick = shellTick + activity;
  const { toast } = useApp();
  const [tab, setTab] = useState<Tab>('audit');
  const [n, setN] = useState(0);
  const audit = useLoad(() => (tab === 'audit' ? call('audit_tail', { limit: LIMIT }) : Promise.resolve(null)), [tab, tick, n]);
  const alerts = useLoad(() => (tab === 'alerts' ? call('alerts', { limit: LIMIT }) : Promise.resolve(null)), [tab, tick, n]);
  const incidents = useLoad(async () => {
    if (tab !== 'incidents') return null;
    const [i, p] = await Promise.all([call('incident_list'), call('principal_list')]);
    return { incidents: i.incidents.slice().reverse(), principals: p.principals };
  }, [tab, tick, n]);
  const reload = () => setN((x) => x + 1);
  const sheets = useSheets<LogSheet>();
  const skipped = (tab === 'audit' ? audit.data?.unparseable_lines : tab === 'alerts' ? alerts.data?.unparseable_lines : 0) ?? 0;

  const declareBtn = <button className="btn btn-ghost btn-sm" type="button" onClick={() => sheets.open({ kind: 'declare' })}>{t('inc.declare')}</button>;
  const closing = sheets.data('close')?.incident;
  const openInc = incidents.data ? openIncident(incidents.data.incidents) : null;

  return (
    <>
      <div className="tabs-row">
        <Segmented<Tab> name="logs-tab" ariaLabel={t('logs.tabs.aria')} value={tab} onChange={setTab}
          options={[{ value: 'audit', label: t('logs.tab.audit') }, { value: 'alerts', label: t('logs.tab.alerts') }, { value: 'incidents', label: t('logs.tab.incidents') }]} />
        {tab === 'incidents' && declareBtn}
      </div>

      {tab === 'audit' && (
        <ListCard items={audit.data ? audit.data.records.slice().reverse() : null} failed={audit.failed} empty="page.logs.empty" label={t('logs.tab.audit')}>
          {(items) => items.map((r, i) => <RecordRow key={i} rec={r} kind="audit" />)}
        </ListCard>
      )}
      {tab === 'alerts' && (
        <ListCard items={alerts.data ? alerts.data.alerts.slice().reverse() : null} failed={alerts.failed} empty="home.alerts.empty" label={t('logs.tab.alerts')}>
          {(items) => items.map((r, i) => <RecordRow key={i} rec={r as unknown as Record<string, unknown>} kind="alert" />)}
        </ListCard>
      )}
      {tab === 'incidents' && (
        <ListCard items={incidents.data?.incidents ?? null} failed={incidents.failed} empty="inc.empty" label={t('logs.tab.incidents')}>
          {(items) => items.map((x) => {
            const open = x.status === 'open';
            const principals = Array.isArray(x.principals) ? (x.principals as unknown[]).map(valueText).join(', ') : '';
            return (
              <Row key={x.id} dot={open ? 'warn' : 'idle'} mono name={x.id} tag={<Tag warn={open}>{t(open ? 'st.open' : 'st.closed')}</Tag>}
                meta={metaLine(scopeText(x.scope), shortTime(x.opened_at), valueText(x.runtime), principals)}
                sub={x.detail ? <div className="meta wrap">{valueText(x.detail)}</div> : undefined}>
                {open && (
                  <button className="btn btn-ghost btn-sm" type="button" aria-label={t('inc.close.aria', { id: x.id })}
                    onClick={() => sheets.open({ kind: 'close', incident: x })}>{t('inc.close')}</button>
                )}
              </Row>
            );
          })}
        </ListCard>
      )}
      {skipped > 0 && <div className="help">{t('home.alerts.skipped', { n: skipped })}</div>}

      <DeclareSheet key={sheets.key('declare')} open={sheets.isOpen('declare')} principals={incidents.data?.principals ?? []}
        openScope={openInc?.scope ?? null} onClose={sheets.close} onDone={() => { sheets.close(); reload(); bump(); }}
        onRefresh={() => { reload(); bump(); }} onAgents={() => { sheets.close(); go('agents'); }} />
      <ConfirmSheet key={sheets.key('close')} id="sheet-inc-close" open={sheets.isOpen('close')} title={t('inc.close.title')} lead={t('inc.close.sub')}
        confirmLabel={t('inc.close.confirm')} onClose={sheets.close} needPass chips={closing ? [closing.id, scopeText(closing.scope)] : []}
        info={t('inc.close.note')}
        errorFor={(e) => (toIpcError(e).reason === 'incident_already_closed' ? 'inc.err.closed' : null)}
        run={async (pass) => {
          if (!closing) return;
          await call('incident_close', { id: closing.id, admin_passphrase: pass });
          toast(t('toast.inc.closed')); sheets.close(); reload(); bump();
        }} />
    </>
  );
}

/** Declare an incident. While one is open the core only widens it, so only wider scopes are
 *  offered, and output saying the open incident was met unchanged is shown as such: a declaration
 *  that contained no one never reads as a lockdown (DESIGN.md §1.3). */
function DeclareSheet({ open, principals, openScope, onClose, onDone, onRefresh, onAgents }: {
  open: boolean; principals: Principal[]; openScope: string | null; onClose(): void; onDone(): void; onRefresh(): void; onAgents(): void;
}) {
  const { toast, field } = useApp();
  const runtimes = [...new Set(principals.map((p) => p.runtime))];
  const scopes = declarableScopes(openScope);
  const [picked, setScope] = useState<Scope | null>(scopes[0] ?? null);
  // an incident opened meanwhile (detection, another window) can take the picked scope away: the
  // sheet then waits for a new choice instead of declaring a scope nobody picked
  const scope: Scope | null = picked && scopes.includes(picked) ? picked : null;
  const [unchanged, setUnchanged] = useState(false);
  const [who, setWho] = useState(principals[0]?.id ?? '');
  const [runtime, setRuntime] = useState(runtimes[0] ?? '');
  useSelectDefault(who, principals.map((p) => p.id), setWho);
  useSelectDefault(runtime, runtimes, setRuntime);
  const [reason, setReason] = useState('');
  const [pass, setPass] = useState('');
  const [errs, setErrs] = useState<{ who?: CopyKey; runtime?: CopyKey; reason?: CopyKey; pass?: CopyKey; form?: CopyKey }>({});
  const [busy, setBusy] = useState(false);
  const whoRef = useRef<HTMLSelectElement>(null);
  const rtRef = useRef<HTMLSelectElement>(null);
  const reasonRef = useRef<HTMLInputElement>(null);
  const passRef = useRef<HTMLInputElement>(null);
  const scopeRef = useRef<HTMLInputElement | null>(null);
  const pick = who || principals[0]?.id || '';
  const rt = runtime || runtimes[0] || '';
  // a runtime incident that covers every active agent stops everything, like the `all` scope
  const stopsAll = scope === 'all' || (scope === 'runtime' && runtimeStopsAll(principals, rt));
  const toAgents = <button className="btn btn-ghost btn-sm" type="button" onClick={onAgents}>{t('inc.toAgents')}</button>;
  useClearOnClose(open, () => setPass(''));

  const submit = async () => {
    if (!scope) return;
    const e: typeof errs = {};
    if (scope === 'principal' && !principals.some((p) => p.id === pick)) e.who = 'grant.err.agent';
    if (scope === 'runtime' && !isValidName(rt)) e.runtime = 'inc.err.runtime';
    if (!isPlainText(reason, 200)) e.reason = 'inc.err.reason';
    if (scope === 'all' && !pass) e.pass = 'pass.err.empty';
    setErrs(e);
    if (e.who) { whoRef.current?.focus(); return; }
    if (e.runtime) { rtRef.current?.focus(); return; }
    if (e.reason) { reasonRef.current?.focus(); return; }
    if (e.pass) { passRef.current?.focus(); return; }
    setBusy(true);
    setUnchanged(false);
    try {
      const out = await call('incident_declare', {
        scope, ...(scope === 'principal' ? { principal: pick } : {}), ...(scope === 'runtime' ? { runtime: rt } : {}),
        ...(reason.trim() ? { reason: reason.trim() } : {}), ...(scope === 'all' ? { admin_passphrase: pass } : {}),
      });
      setPass('');
      const outcome = declareOutcome(out);
      if (outcome === 'unchanged') { setUnchanged(true); onRefresh(); return; }
      field.ripple(0.1);
      toast(t(outcome === 'widened' ? 'toast.inc.widened' : 'toast.inc.declared'), 'warn');
      onDone();
    } catch (err) {
      setPass('');
      if (toIpcError(err).error === 'AuthFailed') { setErrs({ pass: passErrorKey(err) }); passRef.current?.focus(); }
      else setErrs({ form: 'error.generic' });
    } finally { setBusy(false); }
  };

  const absorbed = unchanged && <div role="alert"><Callout kind="info">{t('inc.unchanged')} {toAgents}</Callout></div>;
  // an open incident of the widest scope leaves nothing to declare, and this sheet blocks nothing
  if (scopes.length === 0) {
    return (
      <Sheet id="sheet-inc-full" open={open} title={t('inc.declare.title')} lead={t('inc.declare.sub')} onClose={onClose}>
        {absorbed}
        <Callout kind="info">{t('inc.open.full')}</Callout>
      </Sheet>
    );
  }
  return (
    <Sheet id="sheet-inc-declare" open={open} title={t('inc.declare.title')} lead={t('inc.declare.sub')}
      primaryLabel={t(openScope === null ? 'inc.declare.confirm' : 'inc.widen.confirm')} busy={busy} ready={scope !== null}
      onPrimary={() => void submit()} onBlocked={() => scopeRef.current?.focus()} onClose={onClose}>
      {absorbed}
      {openScope !== null && !unchanged && <Callout kind="info">{t('inc.open.note')} {toAgents}</Callout>}
      <div className="field">
        <div className="label"><span id="inc-scope-lbl">{t('inc.scope')}</span></div>
        <Segmented<Scope> name="inc-scope" labelledBy="inc-scope-lbl" value={scope} onChange={(v) => { setScope(v); setErrs({}); setUnchanged(false); }}
          options={scopes.map((s) => ({ value: s, label: t(SCOPE_LABEL[s]) }))} firstRef={(el) => { scopeRef.current = el; }} />
      </div>
      {scope === 'principal' && (
        <SelectField id="inc-who" label={t('grant.agent')} mono value={pick} selectRef={whoRef} error={errs.who ? t(errs.who) : null}
          options={principals.map((p) => ({ value: p.id, label: p.id }))} onChange={(v) => { setWho(v); setErrs((x) => ({ ...x, who: undefined })); }} />
      )}
      {scope === 'runtime' && (
        <SelectField id="inc-runtime" label={t('inc.scope.runtime')} mono value={rt} selectRef={rtRef} error={errs.runtime ? t(errs.runtime) : null}
          options={runtimes.map((r) => ({ value: r, label: r }))} onChange={(v) => { setRuntime(v); setErrs((x) => ({ ...x, runtime: undefined })); }} />
      )}
      <TextField id="inc-reason" label={t('inc.reason')} hint={t('inc.reason.hint')} value={reason} inputRef={reasonRef} maxLength={200}
        error={errs.reason ? t(errs.reason) : null} onChange={(v) => { setReason(v); setErrs((x) => ({ ...x, reason: undefined })); }} />
      <Callout>{t('inc.declare.warn')}</Callout>
      {stopsAll && <Callout kind="info">{t('inc.all.note')}</Callout>}
      <Callout kind="info">{t('session.note')}</Callout>
      {scope === 'all' && (
        <>
          <div style={{ marginTop: 16 }}>
            <PassField id="inc-pass" value={pass} inputRef={passRef} error={errs.pass ? t(errs.pass) : null}
              onChange={(v) => { setPass(v); setErrs((x) => ({ ...x, pass: undefined })); }} />
          </div>
        </>
      )}
      {errs.form && <div className="help err" role="alert">{t(errs.form)}</div>}
    </Sheet>
  );
}
