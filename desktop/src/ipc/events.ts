// Core event subscriptions with a synchronous unsubscribe, for React effects. `on` resolves
// asynchronously; an effect cleaned up before it resolves must still drop the listener.

import type { Events, InvitePreview } from './contract';
import { on } from './client';

/** Listen to a core event until the returned function is called. */
export function subscribe<E extends keyof Events>(name: E, handler: (payload: Events[E]) => void): () => void {
  let off: (() => void) | null = null;
  let done = false;
  on(name, handler).then(
    (un) => {
      if (done) un();
      else off = un;
    },
    () => undefined,
  );
  return () => {
    done = true;
    off?.();
    off = null;
  };
}

/** A `zeropw://join#…` link was opened outside the app. The core sends only the one-time
 *  reference and the preview, never the link; joining still needs the user's confirmation
 *  (`team_join` with this `ref`). The same invite may be announced more than once while the
 *  app starts; treat a repeated `ref` as the same invite. */
export function onInvitePreview(handler: (invite: { ref: string; preview: InvitePreview }) => void): () => void {
  return subscribe('invite://preview', handler);
}
