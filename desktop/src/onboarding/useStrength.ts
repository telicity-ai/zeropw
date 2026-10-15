import { useEffect, useRef, useState } from 'react';
import type { CopyKey } from '../copy';
import { call } from '../ipc/client';

const REASONS: Record<string, CopyKey> = {
  common: 'admin.reason.common',
  repeat: 'admin.reason.repeat',
  year: 'admin.reason.year',
  short: 'admin.reason.short',
};

/** Map the core's stable reason code to copy; unknown codes show nothing. */
export const reasonKey = (reason: string | null): CopyKey | null => (reason ? REASONS[reason] ?? null : null);

/** Score a passphrase in the core (`password_strength`). Stale answers are dropped. */
export function useStrength(value: string): { score: number; reason: string | null } {
  const [res, setRes] = useState<{ score: number; reason: string | null }>({ score: 0, reason: null });
  const seq = useRef(0);
  useEffect(() => {
    const n = ++seq.current;
    if (!value) { setRes({ score: 0, reason: null }); return; }
    call('password_strength', { value }).then(
      (r) => { if (n === seq.current) setRes({ score: Number.isFinite(r.score) ? r.score : 0, reason: r.reason }); },
      () => { if (n === seq.current) setRes({ score: 0, reason: null }); },
    );
  }, [value]);
  return value ? res : { score: 0, reason: null };
}
