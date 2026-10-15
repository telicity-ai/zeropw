import { useRef, useState, type Ref } from 'react';
import { t, type CopyKey } from '../copy';
import { call, toIpcError } from '../ipc/client';
import type { Project } from '../ipc/contract';
import { DEFAULT_ENVIRONMENTS, isValidName } from '../lib/validators';
import { ri, useApp } from '../ui/context';
import { BackButton, StepFrame, type FrameState } from './StepFrame';

/** Step 4: first project and its environments (fixed once created). */
export function ProjectStep({ frame, sectionRef, created, onBack, onNext }: {
  frame: FrameState; sectionRef: Ref<HTMLElement>; created: Project | null; onBack(): void; onNext(p: Project): void;
}) {
  const { field } = useApp();
  const [name, setName] = useState('demo');
  const [envs, setEnvs] = useState<string[]>([...DEFAULT_ENVIRONMENTS]);
  const [nameErr, setNameErr] = useState<CopyKey | null>(null);
  const [envErr, setEnvErr] = useState(false);
  const [busy, setBusy] = useState(false);
  const nameRef = useRef<HTMLInputElement>(null);
  const firstChip = useRef<HTMLButtonElement>(null);

  const toggle = (e: string) => {
    setEnvs((xs) => (xs.includes(e) ? xs.filter((x) => x !== e) : DEFAULT_ENVIRONMENTS.filter((x) => x === e || xs.includes(x))));
    setEnvErr(false); field.ripple(0.03);
  };

  const submit = async () => {
    if (busy) return;
    if (!isValidName(name)) { setNameErr('proj.err.name'); nameRef.current?.focus(); return; }
    if (!envs.length) { setEnvErr(true); firstChip.current?.focus(); return; }
    // going back and forth must not create the same project twice
    if (created && created.name === name && created.environments.join() === envs.join()) { onNext(created); return; }
    setBusy(true);
    try {
      const p = await call('project_create', { name, environments: envs });
      onNext(p);
    } catch (e) {
      const err = toIpcError(e);
      setNameErr(err.reason === 'project_exists' ? 'proj.err.exists' : err.reason === 'invalid_name' ? 'proj.err.name' : 'error.generic');
      nameRef.current?.focus();
    } finally {
      setBusy(false);
    }
  };

  return (
    <StepFrame name="project" frame={frame} sectionRef={sectionRef} title={t('proj.title')}
      nav={<>
        <BackButton onClick={onBack} label={t('common.back')} />
        <button className="btn btn-primary" type="button" aria-busy={busy} onClick={() => void submit()}>{t('proj.next')}</button>
      </>}>
      <div className="field r" style={ri(1)}>
        <div className="label"><label htmlFor="ob-proj-name">{t('proj.name')}</label></div>
        <div className="input mono" data-invalid={nameErr ? '' : undefined}>
          <input id="ob-proj-name" ref={nameRef} value={name} maxLength={64} spellCheck={false} autoComplete="off"
            aria-invalid={nameErr ? true : undefined} aria-describedby="ob-proj-err"
            onChange={(e) => { setName(e.target.value); setNameErr(null); }} />
        </div>
        <div className="help err" id="ob-proj-err" hidden={!nameErr}>{nameErr ? t(nameErr) : ''}</div>
      </div>
      <div className="field r" style={ri(2)}>
        <div className="label"><span id="ob-lbl-env">{t('proj.envs')}</span><span className="hint" id="ob-env-hint">{t('proj.envs.hint')}</span></div>
        <div className="chips" role="group" aria-labelledby="ob-lbl-env" aria-describedby="ob-env-hint ob-env-err">
          {DEFAULT_ENVIRONMENTS.map((e, i) => (
            <button key={e} className="chip" type="button" aria-pressed={envs.includes(e)} ref={i === 0 ? firstChip : undefined} onClick={() => toggle(e)}>
              <i aria-hidden="true" />{e}
            </button>
          ))}
        </div>
        <div className="help err" id="ob-env-err" hidden={!envErr}>{envErr ? t('proj.err.envs') : ''}</div>
      </div>
    </StepFrame>
  );
}
