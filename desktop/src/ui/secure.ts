import { useEffect } from 'react';
import { call } from '../ipc/client';

// Window content protection (docs/desktop-app.md §8.8): on while any one-time value (recovery
// code, revealed key, invite link) is on screen. Holders are counted so one view closing does not
// lift the protection another still needs.

let holders = 0;
const send = (on: boolean) => { call('secure_view', { on }).catch(() => undefined); };

/** Take a hold; the returned function releases it (idempotent). */
export function holdSecureView(): () => void {
  holders += 1;
  if (holders === 1) send(true);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    holders = Math.max(0, holders - 1);
    if (holders === 0) send(false);
  };
}

/** Keep the window protected while `on` is true and the component is mounted. */
export function useSecureView(on: boolean): void {
  useEffect(() => (on ? holdSecureView() : undefined), [on]);
}

/** Current number of holders (tests). */
export const secureViewHolders = (): number => holders;
