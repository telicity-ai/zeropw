// Declare an incident. While one is open the core only widens it, so only wider scopes are
// offered, and an answer saying the open incident was met unchanged is shown as such: a
// declaration that contained nobody never reads as a lockdown.

import { useEffect, useRef, useState } from 'react';
import { t, type CopyKey } from '../../copy';
import { call } from '../../ipc/client';
import type { Principal } from '../../ipc/contract';
import { declarableScopes, declareOutcome, isPlainText, runtimeStopsAll, type IncidentScope } from '../../lib/dash';
import { isValidName } from '../../lib/validators';
import { useApp } from '../../ui/app';
import { Button, PassField, Segmented, SelectField, TextField } from '../../ui/controls';
import { Dialog, isAuthError, passErrorKey } from '../../ui/Dialog';
import { Banner } from '../../ui/feedback';
import { More } from '../../ui/disclosure';

export const SCOPE_LABEL: Record<IncidentScope, CopyKey> = { principal: 'inc.scope.principal', runtime: 'inc.scope.runtime', all: 'inc.scope.all' };

type Errs = { who?: CopyKey; runtime?: CopyKey; reason?: CopyKey; pass?: CopyKey; form?: CopyKey; scope?: CopyKey };

export function DeclareDialog({ open, principals, openScope, onClose, onDone, onRefresh, onAgents }: {
  open: boolean; principals: readonly Principal[]; openScope: string | null;
  onClose(): void; onDone(): void; onRefresh(): void; onAgents(): void;
}) {
  const { toast } = useApp();
  const runtimes = [...new Set(principals.map((p) => p.runtime))];
  const scopes = declarableScopes(openScope);
  const [picked, setPicked] = useState<IncidentScope | null>(scopes[0] ?? null);
  // an incident opened meanwhile can take the picked scope away: then wait for a new choice
  const scope: IncidentScope | null = picked && scopes.includes(picked) ? picked : null;
  const [who, setWho] = useState(principals[0]?.id ?? '');
  const [runtime, setRuntime] = useState(runtimes[0] ?? '');
  const [reason, setReason] = useState('');
  const [pass, setPass] = useState('');
  const [errs, setErrs] = useState<Errs>({});
  const [busy, setBusy] = useState(false);
  const [unchanged, setUnchanged] = useState(false);
  const running = useRef(false);
  const whoRef = useRef<HTMLSelectElement>(null);
  const rtRef = useRef<HTMLSelectElement>(null);
  const reasonRef = useRef<HTMLInputElement>(null);
  const passRef = useRef<HTMLInputElement>(null);
  const segRef = useRef<HTMLDivElement>(null);

  // selects keep an existing option: the principal or runtime may leave the list
  const pick = principals.some((p) => p.id === who) ? who : principals[0]?.id ?? '';
  const rt = runtimes.includes(runtime) ? runtime : runtimes[0] ?? '';
  useEffect(() => { if (!open) setPass(''); }, [open]);

  const stopsAll = scope === 'all' || (scope === 'runtime' && runtimeStopsAll(principals, rt));
  const toAgents = <Button size="sm" tone="ghost" onClick={onAgents}>{t('activity.inc.toAgents')}</Button>;

  const submit = async () => {
    if (running.current) return;
    if (!scope) { setErrs({ scope: 'activity.inc.err.scope' }); segRef.current?.querySelector<HTMLElement>('[role="radio"]')?.focus(); return; }
    const e: Errs = {};
    if (scope === 'principal' && !principals.some((p) => p.id === pick)) e.who = 'activity.inc.err.agent';
    if (scope === 'runtime' && !isValidName(rt)) e.runtime = 'activity.inc.err.runtime';
    if (!isPlainText(reason, 200)) e.reason = 'activity.inc.err.reason';
    if (scope === 'all' && !pass) e.pass = 'pass.err.empty';
    setErrs(e);
    if (e.who) { whoRef.current?.focus(); return; }
    if (e.runtime) { rtRef.current?.focus(); return; }
    if (e.reason) { setTimeout(() => reasonRef.current?.focus(), 50); return; }
    if (e.pass) { passRef.current?.focus(); return; }
    running.current = true; setBusy(true); setUnchanged(false);
    try {
      const out = await call('incident_declare', {
        scope,
        ...(scope === 'principal' ? { principal: pick } : {}),
        ...(scope === 'runtime' ? { runtime: rt } : {}),
        ...(reason.trim() ? { reason: reason.trim() } : {}),
        ...(scope === 'all' ? { admin_passphrase: pass } : {}),
      });
      const outcome = declareOutcome(out);
      if (outcome === 'unchanged') { setUnchanged(true); onRefresh(); return; }
      toast(t(outcome === 'widened' ? 'toast.activity.widened' : 'toast.activity.declared'), 'warn');
      onDone();
    } catch (err) {
      if (isAuthError(err)) { setErrs({ pass: passErrorKey(err) }); passRef.current?.focus(); }
      else setErrs({ form: 'error.generic' });
    } finally {
      running.current = false; setBusy(false); setPass('');
    }
  };

  const absorbed = unchanged && <Banner tone="info" action={toAgents}>{t('activity.inc.unchanged')}</Banner>;

  if (scopes.length === 0) {
    return (
      <Dialog open={open} title={t('activity.inc.declare.title')} description={t('activity.inc.declare.sub')} onClose={onClose} size="sm"
        footer={<Button tone="primary" onClick={onClose}>{t('act.close')}</Button>}>
        {absorbed}
        <Banner tone="info">{t('activity.inc.open.full')}</Banner>
      </Dialog>
    );
  }

  return (
    <Dialog open={open} title={t('activity.inc.declare.title')} description={t('activity.inc.declare.sub')} onClose={onClose} busy={busy}
      onSubmit={() => void submit()}
      footer={<>
        <Button tone="ghost" onClick={onClose} blocked={busy}>{t('act.cancel')}</Button>
        <Button tone="danger" type="submit" busy={busy} blocked={!scope} onBlocked={() => void submit()}>
          {t(openScope === null ? 'activity.inc.declare.confirm' : 'activity.inc.widen.confirm')}
        </Button>
      </>}>
      {absorbed}
      {openScope !== null && !unchanged && <Banner tone="info" action={toAgents}>{t('activity.inc.open.note')}</Banner>}
      <div className="stack-sm" ref={segRef}>
        <Segmented<IncidentScope> label={t('activity.inc.scope')} hideLabel={false} value={(scope ?? '') as IncidentScope}
          onChange={(v) => { setPicked(v); setErrs({}); setUnchanged(false); }}
          options={scopes.map((s) => ({ value: s, label: t(SCOPE_LABEL[s]) }))} />
        {errs.scope && <div className="field-note is-error" role="alert">{t(errs.scope)}</div>}
      </div>
      {scope === 'principal' && (
        principals.length === 0
          ? <Banner tone="neutral">{t('activity.inc.noAgents')}</Banner>
          : <SelectField label={t('activity.inc.agent')} value={pick} selectRef={whoRef} error={errs.who ? t(errs.who) : null}
            options={principals.map((p) => ({ value: p.id, label: p.id }))} onChange={(v) => { setWho(v); setErrs((x) => ({ ...x, who: undefined })); }} />
      )}
      {scope === 'runtime' && (
        <SelectField label={t('activity.inc.runtime')} value={rt} selectRef={rtRef} error={errs.runtime ? t(errs.runtime) : null}
          options={runtimes.map((r) => ({ value: r, label: r }))} onChange={(v) => { setRuntime(v); setErrs((x) => ({ ...x, runtime: undefined })); }} />
      )}
      <Banner tone="warn">{t('activity.inc.declare.warn')}</Banner>
      {stopsAll && <Banner tone="info">{t('activity.inc.all.note')}</Banner>}
      {scope === 'all' && (
        <PassField value={pass} inputRef={passRef} error={errs.pass ? t(errs.pass) : null}
          onChange={(v) => { setPass(v); setErrs((x) => ({ ...x, pass: undefined })); }} />
      )}
      <More hint={t('activity.inc.more')} open={!!errs.reason}>
        <TextField label={t('activity.inc.reason')} aside={t('activity.inc.reason.aside')} value={reason} inputRef={reasonRef} maxLength={200}
          error={errs.reason ? t(errs.reason) : null} onChange={(v) => { setReason(v); setErrs((x) => ({ ...x, reason: undefined })); }} />
        <Banner tone="neutral">{t('activity.inc.session')}</Banner>
      </More>
      {errs.form && <Banner tone="danger">{t(errs.form)}</Banner>}
    </Dialog>
  );
}
