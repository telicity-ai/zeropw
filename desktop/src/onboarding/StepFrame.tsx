import { useEffect, useRef, type ReactNode, type Ref } from 'react';
import { ri } from '../ui/context';

export interface FrameState {
  /** This step is the current one (receives input). */
  active: boolean;
  /** Class for the reveal: 'in' once shown, 'out' while leaving. */
  cls: '' | 'in' | 'out';
}

/** A card step: fixed head, scrolling body, nav pinned at the bottom (DESIGN.md §4). */
export function StepFrame(props: {
  name: string; frame: FrameState; title: ReactNode; lead?: ReactNode; children: ReactNode; nav: ReactNode;
  sectionRef?: Ref<HTMLElement>;
}) {
  const { name, frame, title, lead, children, nav, sectionRef } = props;
  const body = useRef<HTMLDivElement>(null);
  useEffect(() => { if (frame.active && body.current) body.current.scrollTop = 0; }, [frame.active]);
  const titleId = `t-${name}`;
  return (
    <section className={'step' + (frame.cls ? ' ' + frame.cls : '')} data-step={name} aria-labelledby={titleId} inert={!frame.active} ref={sectionRef}>
      <div className="step-head">
        <h2 className="r" style={ri(0)} id={titleId} tabIndex={-1}>{title}</h2>
        {lead !== undefined && <p className="lead r" style={ri(1)}>{lead}</p>}
      </div>
      <div className="step-body" ref={body}>{children}</div>
      <div className="nav">{nav}</div>
    </section>
  );
}

export function BackButton({ onClick, label }: { onClick(): void; label: string }) {
  return (
    <button className="btn btn-text" type="button" onClick={onClick}>
      <span aria-hidden="true">←</span> <span>{label}</span>
    </button>
  );
}
