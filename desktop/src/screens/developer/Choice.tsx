// An explicit choice between a few options, as native radios (nothing is picked until the
// person picks; arrow keys move between options).

import { useId, type ReactNode } from 'react';

export function ChoiceCards<V extends string>({ label, value, options, onChange, error }: {
  label: string; value: V | ''; options: readonly { value: V; title: ReactNode; sub?: ReactNode }[]; onChange(v: V): void; error?: ReactNode | null;
}) {
  const id = useId();
  return (
    <fieldset className="dev-choice" aria-describedby={error ? `${id}-err` : undefined} aria-invalid={error ? true : undefined}>
      <legend className="field-label">{label}</legend>
      <div className="dev-choice-opts">
        {options.map((o) => (
          <label key={o.value} className={'dev-choice-opt' + (value === o.value ? ' is-on' : '')}>
            <input type="radio" name={id} value={o.value} checked={value === o.value} onChange={() => onChange(o.value)} />
            <span className="dev-choice-title">{o.title}</span>
            {o.sub && <span className="dev-choice-sub">{o.sub}</span>}
          </label>
        ))}
      </div>
      {error && <div className="field-note is-error" id={`${id}-err`} role="alert">{error}</div>}
    </fieldset>
  );
}
