// Passphrase strength from the core (`password_strength`, zxcvbn in desktop/core/src/strength.rs).
// Every change crosses IPC (docs/desktop-app.md §7); answers older than the latest are dropped.

import { useEffect, useRef, useState } from 'react';
import type { CopyKey } from '../../copy';
import { call } from '../../ipc/client';

const REASONS: Record<string, CopyKey> = {
  common_password: 'setup.reason.common',
  similar_to_common: 'setup.reason.common',
  single_word: 'setup.reason.common',
  name: 'setup.reason.common',
  repeated: 'setup.reason.repeat',
  keyboard_pattern: 'setup.reason.repeat',
  sequence: 'setup.reason.repeat',
  date: 'setup.reason.year',
  too_short: 'setup.reason.short',
  too_guessable: 'setup.reason.short',
};

/** The core's stable reason code as copy; unknown codes show nothing. */
export const reasonKey = (reason: string | null): CopyKey | null => (reason ? REASONS[reason] ?? null : null);

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
