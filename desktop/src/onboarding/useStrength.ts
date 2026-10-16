import { useEffect, useRef, useState } from 'react';
import type { CopyKey } from '../copy';
import { call } from '../ipc/client';

// Reason codes from desktop/core/src/strength.rs. The score is the zxcvbn score, 0 to 4.
const REASONS: Record<string, CopyKey> = {
  common_password: 'admin.reason.common',
  similar_to_common: 'admin.reason.common',
  single_word: 'admin.reason.common',
  name: 'admin.reason.common',
  repeated: 'admin.reason.repeat',
  keyboard_pattern: 'admin.reason.repeat',
  sequence: 'admin.reason.repeat',
  date: 'admin.reason.year',
  too_short: 'admin.reason.short',
  too_guessable: 'admin.reason.short',
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
