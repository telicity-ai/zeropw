// Buttons and form controls. Every field wires its label, help and error through ids so screen
// readers read them; errors replace help in the same slot so the layout does not jump.

import {
  forwardRef, useId, useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type KeyboardEvent, type ReactNode, type Ref,
  type SelectHTMLAttributes, type TextareaHTMLAttributes,
} from 'react';
import { t } from '../copy';
import { Icon, type IconName } from './icons';

// ------------------------------------------------------------------------------------- buttons

export type ButtonTone = 'primary' | 'secondary' | 'ghost' | 'danger' | 'quiet';
export type ButtonSize = 'sm' | 'md' | 'lg';

export interface ButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'type'> {
  tone?: ButtonTone;
  size?: ButtonSize;
  icon?: IconName;
  iconEnd?: IconName;
  /** Shows a spinner and ignores clicks; focus stays on the button. */
  busy?: boolean;
  /** Looks and reads as disabled but stays focusable (`aria-disabled`); clicks go to `onBlocked`. */
  blocked?: boolean;
  onBlocked?(): void;
  type?: 'button' | 'submit';
  full?: boolean;
}

export const Button = forwardRef(function Button(
  { tone = 'secondary', size = 'md', icon, iconEnd, busy, blocked, onBlocked, type = 'button', full, className, children, onClick, ...rest }: ButtonProps,
  ref: Ref<HTMLButtonElement>,
) {
  const cls = ['btn', `btn-${tone}`, `btn-${size}`, full ? 'btn-full' : '', busy ? 'is-busy' : '', className ?? ''].filter(Boolean).join(' ');
  return (
    <button ref={ref} type={type} className={cls} aria-busy={busy || undefined} aria-disabled={blocked || busy || undefined}
      onClick={(e) => {
        if (busy) { e.preventDefault(); return; }
        if (blocked) { e.preventDefault(); onBlocked?.(); return; }
        onClick?.(e);
      }} {...rest}>
      {busy ? <span className="spinner" aria-hidden="true" /> : icon ? <Icon name={icon} /> : null}
      {children !== undefined && <span className="btn-label">{children}</span>}
      {iconEnd && !busy && <Icon name={iconEnd} />}
    </button>
  );
});

/** A square button with only an icon; `label` is its accessible name and tooltip. */
export const IconButton = forwardRef(function IconButton(
  { icon, label, tone = 'quiet', size = 'md', className, ...rest }: Omit<ButtonProps, 'children' | 'icon'> & { icon: IconName; label: string },
  ref: Ref<HTMLButtonElement>,
) {
  return <Button ref={ref} tone={tone} size={size} icon={icon} aria-label={label} title={label} className={'btn-icon ' + (className ?? '')} {...rest} />;
});

// -------------------------------------------------------------------------------------- fields

export interface FieldShellProps {
  label: ReactNode;
  help?: ReactNode;
  error?: ReactNode | null;
  /** Shown next to the label, quiet (e.g. "선택"). */
  aside?: ReactNode;
  className?: string;
  children(ids: { id: string; describedBy: string | undefined; invalid: boolean }): ReactNode;
  hideLabel?: boolean;
}

/** Label, control, then one line for help or the error. */
export function FieldShell({ label, help, error, aside, className, children, hideLabel }: FieldShellProps) {
  const id = useId();
  const noteId = `${id}-note`;
  const hasNote = !!error || !!help;
  return (
    <div className={'field' + (error ? ' has-error' : '') + (className ? ' ' + className : '')}>
      <div className={'field-label' + (hideLabel ? ' sr-only' : '')}>
        <label htmlFor={id}>{label}</label>
        {aside && <span className="field-aside">{aside}</span>}
      </div>
      {children({ id, describedBy: hasNote ? noteId : undefined, invalid: !!error })}
      {hasNote && (
        <div className={'field-note' + (error ? ' is-error' : '')} id={noteId} role={error ? 'alert' : undefined}>
          {error ? <><Icon name="alert" size={13} />{error}</> : help}
        </div>
      )}
    </div>
  );
}

type InputProps = Omit<InputHTMLAttributes<HTMLInputElement>, 'onChange' | 'value' | 'prefix'> & {
  value: string;
  onChange(v: string): void;
  prefix?: ReactNode;
  suffix?: ReactNode;
};

export interface TextFieldProps extends InputProps {
  label: ReactNode;
  help?: ReactNode;
  error?: ReactNode | null;
  aside?: ReactNode;
  mono?: boolean;
  inputRef?: Ref<HTMLInputElement>;
  hideLabel?: boolean;
  fieldClassName?: string;
}

export function TextField({ label, help, error, aside, mono, inputRef, prefix, suffix, value, onChange, hideLabel, fieldClassName, className, ...rest }: TextFieldProps) {
  return (
    <FieldShell label={label} help={help} error={error} aside={aside} hideLabel={hideLabel} className={fieldClassName}>
      {({ id, describedBy, invalid }) => (
        <div className={'input' + (invalid ? ' is-invalid' : '') + (mono ? ' is-mono' : '')}>
          {prefix && <span className="input-affix">{prefix}</span>}
          <input id={id} ref={inputRef} value={value} aria-invalid={invalid || undefined} aria-describedby={describedBy}
            spellCheck={false} autoCorrect="off" autoCapitalize="off" className={className}
            onChange={(e) => onChange(e.target.value)} {...rest} />
          {suffix && <span className="input-affix">{suffix}</span>}
        </div>
      )}
    </FieldShell>
  );
}

/** A secret input: never autocompleted from history except a passphrase manager's current
 *  password, with a show toggle that only the person at the keyboard can flip. */
export function PassField({ label = t('pass.label'), autoComplete = 'current-password', allowShow = true, ...rest }: Omit<TextFieldProps, 'type' | 'label'> & { label?: ReactNode; allowShow?: boolean }) {
  const [shown, setShown] = useState(false);
  return (
    <TextField {...rest} label={label} type={shown ? 'text' : 'password'} autoComplete={autoComplete}
      suffix={allowShow ? (
        <button type="button" className="input-toggle" aria-pressed={shown} aria-label={t(shown ? 'pass.hide' : 'pass.show')} title={t(shown ? 'pass.hide' : 'pass.show')}
          onClick={() => setShown((v) => !v)}>
          <Icon name={shown ? 'eye-off' : 'eye'} size={15} />
        </button>
      ) : rest.suffix} />
  );
}

export interface SelectFieldProps extends Omit<SelectHTMLAttributes<HTMLSelectElement>, 'onChange' | 'value'> {
  label: ReactNode;
  value: string;
  onChange(v: string): void;
  options: readonly { value: string; label: string; disabled?: boolean }[];
  help?: ReactNode;
  error?: ReactNode | null;
  aside?: ReactNode;
  selectRef?: Ref<HTMLSelectElement>;
  hideLabel?: boolean;
  fieldClassName?: string;
}

export function SelectField({ label, value, onChange, options, help, error, aside, selectRef, hideLabel, fieldClassName, ...rest }: SelectFieldProps) {
  return (
    <FieldShell label={label} help={help} error={error} aside={aside} hideLabel={hideLabel} className={fieldClassName}>
      {({ id, describedBy, invalid }) => (
        <div className={'select' + (invalid ? ' is-invalid' : '')}>
          <select id={id} ref={selectRef} value={value} aria-invalid={invalid || undefined} aria-describedby={describedBy}
            onChange={(e) => onChange(e.target.value)} {...rest}>
            {options.map((o) => <option key={o.value} value={o.value} disabled={o.disabled}>{o.label}</option>)}
          </select>
          <Icon name="chevron-down" size={14} />
        </div>
      )}
    </FieldShell>
  );
}

export function TextAreaField({ label, help, error, aside, value, onChange, mono, ...rest }: Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, 'onChange' | 'value'> & {
  label: ReactNode; help?: ReactNode; error?: ReactNode | null; aside?: ReactNode; value: string; onChange(v: string): void; mono?: boolean;
}) {
  return (
    <FieldShell label={label} help={help} error={error} aside={aside}>
      {({ id, describedBy, invalid }) => (
        <textarea id={id} className={'textarea' + (invalid ? ' is-invalid' : '') + (mono ? ' is-mono' : '')} value={value}
          aria-invalid={invalid || undefined} aria-describedby={describedBy} spellCheck={false}
          onChange={(e) => onChange(e.target.value)} {...rest} />
      )}
    </FieldShell>
  );
}

export function Checkbox({ checked, onChange, children, help, disabled }: { checked: boolean; onChange(v: boolean): void; children: ReactNode; help?: ReactNode; disabled?: boolean }) {
  const id = useId();
  return (
    <div className="check">
      <input id={id} type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} aria-describedby={help ? `${id}-h` : undefined} />
      <span className="check-box" aria-hidden="true"><Icon name="check" size={12} /></span>
      <label htmlFor={id}>{children}{help && <span className="check-help" id={`${id}-h`}>{help}</span>}</label>
    </div>
  );
}

/** An on/off switch (role="switch"). */
export function Switch({ checked, onChange, label, disabled }: { checked: boolean; onChange(v: boolean): void; label: string; disabled?: boolean }) {
  return (
    <button type="button" role="switch" aria-checked={checked} aria-label={label} disabled={disabled} className="switch" onClick={() => onChange(!checked)}>
      <span className="switch-thumb" aria-hidden="true" />
    </button>
  );
}

export interface SegOption<V extends string> { value: V; label: ReactNode; icon?: IconName; disabled?: boolean }

/** A single choice among a few options (radio group; arrow keys move). */
export function Segmented<V extends string>({ label, value, options, onChange, size = 'md', hideLabel = true }: {
  label: string; value: V; options: readonly SegOption<V>[]; onChange(v: V): void; size?: 'sm' | 'md'; hideLabel?: boolean;
}) {
  const id = useId();
  const enabled = options.filter((o) => !o.disabled);
  const move = (e: KeyboardEvent<HTMLButtonElement>, dir: number) => {
    e.preventDefault();
    const i = enabled.findIndex((o) => o.value === value);
    const next = enabled[(i + dir + enabled.length) % enabled.length];
    if (next) {
      onChange(next.value);
      const btn = (e.currentTarget.parentElement?.querySelector(`[data-value="${next.value}"]`) as HTMLButtonElement | null);
      btn?.focus();
    }
  };
  return (
    <div className="seg-wrap">
      <span id={id} className={hideLabel ? 'sr-only' : 'field-label'}>{label}</span>
      <div className={'seg seg-' + size} role="radiogroup" aria-labelledby={id}>
        {options.map((o) => (
          <button key={o.value} type="button" role="radio" data-value={o.value} aria-checked={o.value === value} disabled={o.disabled}
            tabIndex={o.value === value ? 0 : -1} className="seg-opt" onClick={() => onChange(o.value)}
            onKeyDown={(e) => {
              if (e.key === 'ArrowRight' || e.key === 'ArrowDown') move(e, 1);
              else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') move(e, -1);
            }}>
            {o.icon && <Icon name={o.icon} size={14} />}{o.label}
          </button>
        ))}
      </div>
    </div>
  );
}

/** A toggle chip in a multi-select row (aria-pressed). */
export function Chip({ on, onToggle, children, tone, disabled, label }: { on: boolean; onToggle(): void; children: ReactNode; tone?: 'warn'; disabled?: boolean; label?: string }) {
  return (
    <button type="button" className={'chip' + (on ? ' is-on' : '') + (tone ? ' chip-' + tone : '')} aria-pressed={on} aria-label={label} disabled={disabled} onClick={onToggle}>
      {on && <Icon name="check" size={12} />}{children}
    </button>
  );
}
