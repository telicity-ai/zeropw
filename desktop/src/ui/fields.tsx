import { useEffect } from 'react';
import type { CSSProperties, HTMLAttributes, ReactNode, Ref } from 'react';
import { t } from '../copy';

// Labelled inputs for the dashboard sheets (DESIGN.md §7): every input has a <label>; the hint,
// help and error lines are tied to it with aria-describedby; an error marks the box invalid.
// Error text arrives already translated so these stay free of copy keys.

interface Common {
  id: string; label: ReactNode; error?: string | null; hint?: ReactNode; help?: ReactNode;
  mono?: boolean; disabled?: boolean; ariaDisabled?: boolean; className?: string; style?: CSSProperties; describedBy?: string;
}

const describe = (id: string, hint: boolean, help: boolean, extra?: string) =>
  [hint ? `${id}-hint` : '', help ? `${id}-help` : '', `${id}-err`, extra ?? ''].filter(Boolean).join(' ');

function Frame({ id, label, error, hint, help, className, style, children }: Common & { children: ReactNode }) {
  return (
    <div className={'field' + (className ? ' ' + className : '')} style={style}>
      <div className="label">
        <label htmlFor={id}>{label}</label>
        {hint !== undefined && <span className="hint" id={`${id}-hint`}>{hint}</span>}
      </div>
      {children}
      {help !== undefined && <div className="help" id={`${id}-help`}>{help}</div>}
      <div className="help err" id={`${id}-err`} hidden={!error}>{error ?? ''}</div>
    </div>
  );
}

export function TextField(props: Common & {
  value: string; onChange(v: string): void; type?: 'text' | 'password'; placeholder?: string; inputRef?: Ref<HTMLInputElement>;
  autoComplete?: string; maxLength?: number; inputMode?: HTMLAttributes<HTMLInputElement>['inputMode']; suffix?: ReactNode; prefix?: ReactNode;
  /** Mark the box invalid when the explanation lives in another line (`describedBy`). */
  invalid?: boolean;
}) {
  const { id, value, onChange, type = 'text', placeholder, inputRef, autoComplete = 'off', maxLength, inputMode, suffix, prefix, mono, error, disabled } = props;
  const bad = !!error || !!props.invalid;
  return (
    <Frame {...props}>
      <div className={'input' + (mono ? ' mono' : '')} data-invalid={bad ? '' : undefined}>
        {prefix !== undefined && <span className="prefix" aria-hidden="true">{prefix}</span>}
        <input id={id} ref={inputRef} type={type} value={value} placeholder={placeholder} autoComplete={autoComplete} spellCheck={false}
          autoCapitalize="off" autoCorrect="off" maxLength={maxLength} inputMode={inputMode} disabled={disabled} aria-disabled={props.ariaDisabled || undefined}
          aria-invalid={bad ? true : undefined} aria-describedby={describe(id, props.hint !== undefined, props.help !== undefined, props.describedBy)}
          onChange={(e) => onChange(e.target.value)} />
        {suffix !== undefined && <span className="suffix">{suffix}</span>}
      </div>
    </Frame>
  );
}

export interface Choice { value: string; label: string }

/** Keep a select's state on one of its options: the lists usually arrive after the sheet's
 *  state is created, and a <select> whose value matches no option still shows the first one,
 *  so the screen and the state would disagree. */
export function useSelectDefault(value: string, options: readonly string[], set: (v: string) => void): void {
  const first = options[0];
  const known = options.includes(value);
  useEffect(() => { if (!known && first !== undefined) set(first); }, [known, first, set]);
}

export function SelectField(props: Common & { value: string; onChange(v: string): void; options: Choice[]; selectRef?: Ref<HTMLSelectElement> }) {
  const { id, value, onChange, options, selectRef, mono, error, disabled } = props;
  return (
    <Frame {...props}>
      <div className={'input select' + (mono ? ' mono' : '')} data-invalid={error ? '' : undefined}>
        <select id={id} ref={selectRef} value={value} disabled={disabled} aria-disabled={props.ariaDisabled || undefined} aria-invalid={error ? true : undefined}
          aria-describedby={describe(id, props.hint !== undefined, props.help !== undefined, props.describedBy)} onChange={(e) => onChange(e.target.value)}>
          {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
      </div>
    </Frame>
  );
}

/** The admin passphrase, asked again for a consequential action. */
export function PassField({ id, value, onChange, error, inputRef, label }: {
  id: string; value: string; onChange(v: string): void; error?: string | null; inputRef?: Ref<HTMLInputElement>; label?: string;
}) {
  return (
    <TextField id={id} label={label ?? t('pass.field')} type="password" value={value} onChange={onChange} error={error ?? null}
      inputRef={inputRef} autoComplete="current-password" />
  );
}
