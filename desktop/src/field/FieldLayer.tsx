import { useLayoutEffect, useRef } from 'react';
import { t } from '../copy';
import type { Field } from './field';

/** Canvases, aura and floating chips for the pixel field. The Field instance outlives this
 *  component's renders; it is attached to the DOM here and detached on unmount. The host is the
 *  element these nodes are rendered into (the window), read from the DOM because a parent's ref
 *  is not set yet when a child's layout effect runs. */
export function FieldLayer({ field }: { field: Field }) {
  const glow = useRef<HTMLCanvasElement>(null);
  const cv = useRef<HTMLCanvasElement>(null);
  const aura = useRef<HTMLDivElement>(null);
  const hint = useRef<HTMLDivElement>(null);
  const svc = useRef<HTMLSpanElement>(null), svcL = useRef<HTMLSpanElement>(null);
  const agent = useRef<HTMLSpanElement>(null), agentL = useRef<HTMLSpanElement>(null);
  const peer = useRef<HTMLSpanElement>(null), peerL = useRef<HTMLSpanElement>(null);

  useLayoutEffect(() => {
    const host = cv.current?.parentElement;
    if (!host || !cv.current || !glow.current) return;
    const chip = (el: HTMLSpanElement | null, label: HTMLSpanElement | null) => (el && label ? { el, label } : undefined);
    const chips: NonNullable<Parameters<Field['attach']>[0]['chips']> = {};
    const s = chip(svc.current, svcL.current), a = chip(agent.current, agentL.current), p = chip(peer.current, peerL.current);
    if (s) chips.svc = s;
    if (a) chips.agent = a;
    if (p) chips.peer = p;
    field.attach({ host, field: cv.current, glow: glow.current, aura: aura.current, hint: hint.current, chips });
    let ro: ResizeObserver | null = null;
    const onResize = () => field.resize();
    if (typeof ResizeObserver !== 'undefined') { ro = new ResizeObserver(onResize); ro.observe(host); }
    else window.addEventListener('resize', onResize);
    return () => { ro?.disconnect(); window.removeEventListener('resize', onResize); field.detach(); };
  }, [field]);

  return (
    <>
      <canvas className="field glow" ref={glow} aria-hidden="true" />
      <canvas className="field" ref={cv} aria-hidden="true" />
      <div className="aura" ref={aura} aria-hidden="true" />
      <div className="vignette" aria-hidden="true" />
      <span className="node-chip svc" ref={svc} aria-hidden="true"><i /><span ref={svcL} /></span>
      <span className="node-chip" ref={agent} aria-hidden="true"><i /><span ref={agentL} /></span>
      <span className="node-chip peer" ref={peer} aria-hidden="true"><i /><span ref={peerL} /></span>
      <div className="drag-hint" ref={hint} aria-hidden="true">{t('top.drag')}</div>
    </>
  );
}
