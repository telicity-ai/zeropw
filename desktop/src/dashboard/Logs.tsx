import { useRef, useState } from 'react';
import { t, type CopyKey } from '../copy';
import { call, toIpcError } from '../ipc/client';
import type { Incident, Principal } from '../ipc/contract';
import { isPlainText, recordFields, runtimeStopsAll, valueText } from '../lib/dash';
import { shortTime } from '../lib/format';
import { isValidName } from '../lib/validators';
import { useApp } from '../ui/context';
import { PassField, SelectField, TextField } from '../ui/fields';
import { Callout, Segmented } from '../ui/form';
import { ConfirmSheet } from './Confirm';
import { passErrorKey, useClearOnClose, useDash, useLoad, useSheets } from './context';
import { ListCard, metaLine, Row, Tag } from './parts';
import { Sheet } from './Sheet';

type Tab = 'audit' | 'alerts' | 'incidents';
type Scope = 'principal' | 'runtime' | 'all';
type LogSheet = { kind: 'declare' } | { kind: 'close'; incident: Incident };
const LIMIT = 200;
const SCOPE_LABEL: Record<Scope, CopyKey> = { principal: 'inc.scope.principal', runtime: 'inc.scope.runtime', all: 'inc.scope.all' };
const scopeText = (s: string): string => (s in SCOPE_LABEL ? t(SCOPE_LABEL[s as Scope]) : s);

/** Fields of a record as text lines: every field the core wrote, nothing interpreted. */
function RecordRow({ rec, titleKey, warn }: { rec: Record<string, unknown>; titleKey: string; warn?: boolean }) {
  const f = recordFields(rec, titleKey);
  return (
    <Row dot={warn ? 'warn' : 'idle'} mono name={f.title || '?'} meta={metaLine(shortTime(f.ts))}
      sub={f.fields.length > 0 && <div className="meta wrap">{f.fields.join('  ')}</div>} />
  );
}

/** Records: the usage log, alerts and incidents (declare and close). */
export function LogsPage() {
  const { tick: shellTick, activity, bump } = useDash();
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

  return (
    <>
      <div className="tabs-row">
        <Segmented<Tab> name="logs-tab" ariaLabel={t('logs.tabs.aria')} value={tab} onChange={setTab}
          options={[{ value: 'audit', label: t('logs.tab.audit') }, { value: 'alerts', label: t('logs.tab.alerts') }, { value: 'incidents', label: t('logs.tab.incidents') }]} />
        {tab === 'incidents' && declareBtn}
      </div>

      {tab === 'audit' && (
        <ListCard items={audit.data ? audit.data.records.slice().reverse() : null} failed={audit.failed} empty="page.logs.empty" label={t('logs.tab.audit')}>
          {(items) => items.map((r, i) => <RecordRow key={i} rec={r} titleKey="event" />)}
        </ListCard>
      )}
      {tab === 'alerts' && (
        <ListCard items={alerts.data ? alerts.data.alerts.slice().reverse() : null} failed={alerts.failed} empty="home.alerts.empty" label={t('logs.tab.alerts')}>
          {(items) => items.map((r, i) => <RecordRow key={i} rec={r as unknown as Record<string, unknown>} titleKey="alert" warn />)}
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
        onClose={sheets.close} onDone={() => { sheets.close(); reload(); bump(); }} />
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

function DeclareSheet({ open, principals, onClose, onDone }: { open: boolean; principals: Principal[]; onClose(): void; onDone(): void }) {
  const { toast, field } = useApp();
  const runtimes = [...new Set(principals.map((p) => p.runtime))];
  const [scope, setScope] = useState<Scope>('principal');
  const [who, setWho] = useState(principals[0]?.id ?? '');
  const [runtime, setRuntime] = useState(runtimes[0] ?? '');
  const [reason, setReason] = useState('');
  const [pass, setPass] = useState('');
  const [errs, setErrs] = useState<{ who?: CopyKey; runtime?: CopyKey; reason?: CopyKey; pass?: CopyKey; form?: CopyKey }>({});
  const [busy, setBusy] = useState(false);
  const whoRef = useRef<HTMLSelectElement>(null);
  const rtRef = useRef<HTMLSelectElement>(null);
  const reasonRef = useRef<HTMLInputElement>(null);
  const passRef = useRef<HTMLInputElement>(null);
  const pick = who || principals[0]?.id || '';
  const rt = runtime || runtimes[0] || '';
  // a runtime incident that covers every active agent stops everything, like the `all` scope
  const stopsAll = scope === 'all' || (scope === 'runtime' && runtimeStopsAll(principals, rt));
  useClearOnClose(open, () => setPass(''));

  const submit = async () => {
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
    try {
      await call('incident_declare', {
        scope, ...(scope === 'principal' ? { principal: pick } : {}), ...(scope === 'runtime' ? { runtime: rt } : {}),
        ...(reason.trim() ? { reason: reason.trim() } : {}), ...(scope === 'all' ? { admin_passphrase: pass } : {}),
      });
      setPass('');
      field.ripple(0.1);
      toast(t('toast.inc.declared'), 'warn');
      onDone();
    } catch (err) {
      setPass('');
      if (toIpcError(err).error === 'AuthFailed') { setErrs({ pass: passErrorKey(err) }); passRef.current?.focus(); }
      else setErrs({ form: 'error.generic' });
    } finally { setBusy(false); }
  };

  return (
    <Sheet id="sheet-inc-declare" open={open} title={t('inc.declare.title')} lead={t('inc.declare.sub')} primaryLabel={t('inc.declare.confirm')}
      busy={busy} onPrimary={() => void submit()} onClose={onClose}>
      <div className="field">
        <div className="label"><span id="inc-scope-lbl">{t('inc.scope')}</span></div>
        <Segmented<Scope> name="inc-scope" labelledBy="inc-scope-lbl" value={scope} onChange={(v) => { setScope(v); setErrs({}); }}
          options={(['principal', 'runtime', 'all'] as const).map((s) => ({ value: s, label: t(SCOPE_LABEL[s]) }))} />
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
