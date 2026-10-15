import { useCallback, useLayoutEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react';
import { t, type CopyKey } from '../copy';
import { meterCellsOn, meterLevel, METER_CELLS, type MeterLevel } from '../lib/validators';

const LEVEL: Record<MeterLevel, CopyKey> = { 1: 'admin.meter.1', 2: 'admin.meter.2', 3: 'admin.meter.3', 4: 'admin.meter.4' };

/** 24-cell strength meter; decorative, the rules carry the meaning for assistive tech. */
export function Meter({ score, filled }: { score: number; filled: boolean }) {
  const on = filled ? meterCellsOn(score) : 0;
  const cells: ReactNode[] = [];
  for (let k = 0; k < METER_CELLS; k++) {
    const style: CSSProperties | undefined = k < on
      ? { background: `color-mix(in oklab, var(--azure) ${100 - (k / (METER_CELLS - 1)) * 100}%, var(--iris))` }
      : undefined;
    cells.push(<i key={k} className={k < on ? 'on' : undefined} style={style} />);
  }
  return (
    <div className="meter" aria-hidden="true">
      <div className="cells">{cells}</div>
      <span className="mlabel">{filled ? t(LEVEL[meterLevel(score)]) : ''}</span>
    </div>
  );
}

/** Rule chip: ✓ glyph plus a hidden "✓" so the state is not colour-only. */
export function Rule({ id, ok, label }: { id?: string; ok: boolean; label: string }) {
  return (
    <li className={'rule' + (ok ? ' ok' : '')} id={id}>
      <span className="g" aria-hidden="true">{ok ? '✓' : '○'}</span>
      <span>{label}</span>
      <span className="sr-only">{ok ? ' ✓' : ''}</span>
    </li>
  );
}

export function Callout({ kind = 'warn', children, className, id, style }: {
  kind?: 'warn' | 'info'; children: ReactNode; className?: string; id?: string; style?: CSSProperties;
}) {
  return (
    <div className={'callout' + (kind === 'info' ? ' info' : '') + (className ? ' ' + className : '')} id={id} style={style}>
      <span className="px" aria-hidden="true" />
      <span>{children}</span>
    </div>
  );
}

export interface SegOption<V extends string> { value: V; label: ReactNode; sub?: ReactNode }

/** Radios styled as a segmented bar (DESIGN.md §5.4) with a sliding thumb. */
export function Segmented<V extends string>(props: {
  name: string; options: SegOption<V>[]; value: V | null; onChange(v: V): void;
  labelledBy?: string; ariaLabel?: string; disabled?: boolean; two?: boolean; firstRef?: (el: HTMLInputElement | null) => void;
}) {
  const { name, options, value, onChange, labelledBy, ariaLabel, disabled, two, firstRef } = props;
  const root = useRef<HTMLDivElement>(null);
  const thumb = useRef<HTMLSpanElement>(null);
  const [focusV, setFocusV] = useState<V | null>(null);

  const place = useCallback(() => {
    const r = root.current, th = thumb.current;
    if (!r || !th) return;
    const on = r.querySelector<HTMLLabelElement>('label.on');
    th.style.opacity = on ? '1' : '0';
    if (on) { th.style.left = on.offsetLeft + 'px'; th.style.width = on.offsetWidth + 'px'; }
  }, []);

  useLayoutEffect(() => { place(); }, [place, value]);
  useLayoutEffect(() => {
    const r = root.current;
    if (!r || typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver(place);
    ro.observe(r);
    return () => ro.disconnect();
  }, [place]);

  return (
    <div className="segmented" role="radiogroup" aria-labelledby={labelledBy} aria-label={ariaLabel} ref={root}>
      <span className="thumb" aria-hidden="true" ref={thumb} />
      {options.map((o, i) => (
        <label key={o.value} className={[o.value === value ? 'on' : '', focusV === o.value ? 'focus' : '', disabled ? 'dis' : '', two ? 'two' : ''].filter(Boolean).join(' ') || undefined}>
          <input
            type="radio" name={name} value={o.value} checked={o.value === value} disabled={disabled}
            ref={i === 0 ? firstRef : undefined}
            onChange={() => onChange(o.value)}
            onFocus={(e) => setFocusV(e.currentTarget.matches(':focus-visible') ? o.value : null)}
            onBlur={() => setFocusV(null)}
          />
          {o.sub !== undefined ? <span><span>{o.label}</span><span className="seg-sub">{o.sub}</span></span> : o.label}
        </label>
      ))}
    </div>
  );
}
