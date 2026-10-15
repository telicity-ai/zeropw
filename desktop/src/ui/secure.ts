import { useEffect, useState } from 'react';
import { call } from '../ipc/client';

// Window content protection (docs/desktop-app.md §8.8) while a one-time value (recovery code,
// revealed key, invite link) is on screen. The protection is switched on and confirmed by the
// core before the value is painted, and switched off only after the value has left the screen.
// Holders are counted so one view closing does not lift the protection another still needs, and
// the `secure_view` calls go out one at a time so an "off" can never overtake a later "on".
// Nothing in the UI claims the protection: where the platform cannot give it, values are shown
// all the same and no text says otherwise.

/** true: the core reports the window is protected; false: it is not (or the call failed);
 *  null: the core answered without saying (an older core whose `secure_view` returns nothing). */
export type Protection = boolean | null;
export interface SecureHold {
  /** Settles once the core has applied the protection. */
  ready: Promise<Protection>;
  /** Give the hold back (idempotent). */
  release(): void;
}

let holders = 0;
let queue: Promise<unknown> = Promise.resolve();
let lastOn: Promise<Protection> = Promise.resolve(null);

/** Read either answer shape of `secure_view`: nothing, or `{protected: boolean}`. */
export function protectionOf(answer: unknown): Protection {
  if (answer && typeof answer === 'object' && typeof (answer as { protected?: unknown }).protected === 'boolean') {
    return (answer as { protected: boolean }).protected;
  }
  return null;
}

function send(on: boolean): Promise<Protection> {
  const p = queue.then(() => call('secure_view', { on }).then((r: unknown) => protectionOf(r), () => false as Protection));
  queue = p.catch(() => undefined);
  return p;
}

/** Take a hold; `ready` settles after the core has turned the protection on. */
export function holdSecureView(): SecureHold {
  holders += 1;
  if (holders === 1) lastOn = send(true);
  const ready = lastOn;
  let released = false;
  return {
    ready,
    release: () => {
      if (released) return;
      released = true;
      holders = Math.max(0, holders - 1);
      if (holders === 0) void send(false);
    },
  };
}

/** Run `fn` once the frame without the value has been painted. */
export function afterPaint(fn: () => void): void {
  if (typeof requestAnimationFrame === 'function') requestAnimationFrame(() => requestAnimationFrame(fn));
  else setTimeout(fn, 32);
}

/** Gate for a one-time value: returns true only while `want` is true and the core has confirmed
 *  the protection. When `want` turns false the gate closes in the same render (the value leaves
 *  the DOM at once) and the hold is given back after the next paint. */
export function useSecureGate(want: boolean): boolean {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!want) return;
    const hold = holdSecureView();
    let live = true;
    void hold.ready.then(() => { if (live) setOpen(true); });
    return () => {
      live = false;
      setOpen(false);
      afterPaint(hold.release);
    };
  }, [want]);
  return want && open;
}

/** Current number of holders (tests). */
export const secureViewHolders = (): number => holders;
