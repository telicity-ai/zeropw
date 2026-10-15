import { useEffect, useRef, useState, type Ref } from 'react';
import { t, type CopyKey } from '../copy';
import { call, toIpcError } from '../ipc/client';
import { isAccountName, isValidName, runtimeFor } from '../lib/validators';
import { ri, useApp } from '../ui/context';
import { Callout, Segmented } from '../ui/form';
import { AgentTerminal, focusTerminal } from './AgentTerminal';
import { StepFrame, type FrameState } from './StepFrame';

export type Where = 'other' | 'same';
export interface AgentInfo { id: string; where: Where; account: string | null }

/** Step 5 (can wait): create an agent and open the in-app terminal for it. No service is
 *  connected during onboarding, so permissions are granted later from the dashboard. */
export function AgentStep({ frame, sectionRef, onOpened, onSkip, onDone }: {
  frame: FrameState; sectionRef: Ref<HTMLElement>; onOpened(a: AgentInfo): void; onSkip(): void; onDone(): void;
}) {
  const { field, toast } = useApp();
  const [name, setName] = useState('agent-1');
  const [where, setWhere] = useState<Where | null>(null);
  const [account, setAccount] = useState('agent');
  const [nameErr, setNameErr] = useState<CopyKey | null>(null);
  const [accErr, setAccErr] = useState(false);
  const [busy, setBusy] = useState(false);
  const [agent, setAgent] = useState<(AgentInfo & { tokenRef: string }) | null>(null);
  const [verified, setVerified] = useState(false);
  const [termFailed, setTermFailed] = useState(false);
  const nameRef = useRef<HTMLInputElement>(null);
  const accRef = useRef<HTMLInputElement>(null);
  const whereFirst = useRef<HTMLInputElement | null>(null);
  const wrapRef = useRef<HTMLDivElement>(null);

  // the agent node's chip follows the name being typed
  useEffect(() => { if (frame.active && !agent) field.chipText('agent', name); }, [frame.active, agent, name, field]);

  const open = async () => {
    if (busy) return;
    if (!where) { whereFirst.current?.focus(); toast(t('agent.where.required'), 'warn'); return; }
    if (!isValidName(name)) { setNameErr('agent.err.name'); nameRef.current?.focus(); return; }
    if (where === 'other' && !isAccountName(account)) { setAccErr(true); accRef.current?.focus(); return; }
    setBusy(true);
    try {
      const acc = where === 'other' ? account : null;
      const r = await call('principal_create', { id: name, runtime: runtimeFor(where, account) });
      const info: AgentInfo = { id: r.id, where, account: acc };
      setAgent({ ...info, tokenRef: r.token_ref });
      onOpened(info);
      field.chipText('agent', r.id);
      field.ripple(0.08);
      setTimeout(() => {
        wrapRef.current?.scrollIntoView({ block: 'nearest', behavior: field.motionOn ? 'smooth' : 'auto' });
        focusTerminal();
      }, 380);
    } catch (e) {
      const err = toIpcError(e);
      setNameErr(err.reason === 'principal_exists' ? 'agent.err.exists' : err.reason === 'invalid_name' ? 'agent.err.name' : 'error.generic');
      nameRef.current?.focus();
    } finally {
      setBusy(false);
    }
  };

  const ready = !!agent && (verified || termFailed);
  const primary = () => {
    if (!agent) { void open(); return; }
    if (ready) onDone(); else focusTerminal();
  };

  const summary: Array<[string, boolean]> = agent ? [
    [agent.id, false],
    [agent.where === 'other' ? `${t('agent.where.other')} · ${agent.account ?? ''}` : `${t('agent.where.same')} · ${t('agent.where.same.sub')}`, agent.where === 'same'],
    [t('done.tile.agent.nogrant'), false],
  ] : [];

  return (
    <StepFrame name="agent" frame={frame} sectionRef={sectionRef} title={t('agent.title')} lead={t('agent.sub')}
      nav={<>
        <button className="btn btn-text" type="button" onClick={onSkip}>{t('agent.skip')}</button>
        <button className="btn btn-primary" type="button" aria-busy={busy} aria-disabled={agent ? !ready : undefined} onClick={primary}>
          {t(agent ? 'agent.done' : 'agent.connect')}
        </button>
      </>}>
      {!agent && (
        <div>
          <div className="row r" style={ri(2)}>
            <div className="field">
              <div className="label"><label htmlFor="ob-agent-id">{t('agent.name')}</label></div>
              <div className="input mono" data-invalid={nameErr ? '' : undefined}>
                <input id="ob-agent-id" ref={nameRef} value={name} spellCheck={false} autoComplete="off" maxLength={64}
                  aria-invalid={nameErr ? true : undefined} aria-describedby="ob-agent-err"
                  onChange={(e) => { setName(e.target.value); setNameErr(null); }} />
              </div>
              <div className="help err" id="ob-agent-err" hidden={!nameErr}>{nameErr ? t(nameErr) : ''}</div>
            </div>
            <div aria-hidden="true" />
          </div>
          <div className="help r" style={{ ...ri(2), margin: '-6px 0 12px' }}>{t('agent.noconn')}</div>
          <div className="field r" style={ri(3)}>
            <div className="label"><span id="ob-lbl-where">{t('agent.where')}</span></div>
            <Segmented<Where> name="ob-where" labelledBy="ob-lbl-where" two value={where} onChange={setWhere}
              firstRef={(el) => { whereFirst.current = el; }}
              options={[
                { value: 'other', label: t('agent.where.other'), sub: t('agent.where.other.sub') },
                { value: 'same', label: t('agent.where.same'), sub: t('agent.where.same.sub') },
              ]} />
            {where === 'other' && (
              <div className="inline" style={{ marginTop: 10 }}>
                <div className="field" style={{ margin: 0, flex: 1 }}>
                  <div className="input mono" data-invalid={accErr ? '' : undefined}>
                    <span className="prefix" aria-hidden="true">{t('agent.where.user')}</span>
                    <input ref={accRef} value={account} spellCheck={false} autoComplete="off" aria-label={t('agent.where.user')}
                      aria-invalid={accErr ? true : undefined} aria-describedby="ob-acc-err"
                      onChange={(e) => { setAccount(e.target.value); setAccErr(false); }} />
                  </div>
                  <div className="help err" id="ob-acc-err" hidden={!accErr}>{accErr ? t('agent.where.user.err') : ''}</div>
                </div>
              </div>
            )}
            {where === 'same' && <Callout>{t('agent.where.warn')}</Callout>}
          </div>
        </div>
      )}
      {agent && (
        <div className="agent-sum">
          {summary.map(([txt, warn]) => <span key={txt} className={warn ? 'warn' : undefined}>{txt}</span>)}
        </div>
      )}
      <div className={'reveal-wrap' + (agent ? ' on' : '')} inert={!agent} ref={wrapRef}>
        <div>
          {agent && (
            <AgentTerminal name={agent.id} tokenRef={agent.tokenRef} asUser={agent.where === 'other' ? agent.account : null}
              onVerified={() => { setVerified(true); field.pulse(); toast(t('toast.agent.ready')); }}
              onFailed={() => setTermFailed(true)} />
          )}
          {verified && (
            <div className="term-ok" role="status">
              <span aria-hidden="true">✓ </span>{t('term.ok')}<span className="help" style={{ display: 'block', marginTop: 2 }}>{t('term.next')}</span>
            </div>
          )}
        </div>
      </div>
    </StepFrame>
  );
}
