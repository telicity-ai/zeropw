import { useId, useMemo } from 'react';
import { logoCells, sigilCells } from '../lib/sigil';

function Gradient({ id }: { id: string }) {
  return (
    <defs>
      <linearGradient id={id} x1="0" y1="0" x2="1" y2="1">
        <stop offset="0" stopColor="#8fb0ff" />
        <stop offset="1" stopColor="#c4a8ff" />
      </linearGradient>
    </defs>
  );
}

export function Logo({ size = 14 }: { size?: number }) {
  const id = useId();
  const cells = useMemo(logoCells, []);
  return (
    <svg width={size} height={size} viewBox="0 0 9 9" shapeRendering="crispEdges" aria-hidden="true">
      <Gradient id={id} />
      {cells.map(([x, y]) => <rect key={`${x}-${y}`} x={x} y={y} width="1" height="1" fill={`url(#${id})`} />)}
    </svg>
  );
}

/** Device check picture; `fp` is untrusted text and only feeds the hash. */
export function Sigil({ fp }: { fp: string }) {
  const id = useId();
  const cells = useMemo(() => sigilCells(fp), [fp]);
  return (
    <svg viewBox="0 0 11 11" shapeRendering="crispEdges" aria-hidden="true">
      <Gradient id={id} />
      {cells.map(([x, y]) => <rect key={`${x}-${y}`} x={x} y={y} width="1" height="1" fill={`url(#${id})`} />)}
    </svg>
  );
}
