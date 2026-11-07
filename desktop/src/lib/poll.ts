// Polling with explicit stop conditions: the joining Mac retries pending joins every few seconds
// until every environment joined, the code expired, a reason says it cannot succeed, or the user
// cancelled; the inviting Mac reads join requests while the add-device sheet is open. Errors that
// may pass (the daemon restarting, a slow network) are retried; nothing polls forever.

export type PollOutcome<T> =
  | { kind: 'done'; value: T }
  | { kind: 'expired'; value: T | null }
  | { kind: 'cancelled' }
  | { kind: 'failed'; reason: string };

export interface PollOptions<T> {
  /** One attempt (an IPC call). */
  step(): Promise<T>;
  /** The attempt's result ends the polling. */
  done(value: T): boolean;
  /** A result that cannot get better: its reason. */
  final?(value: T): string | null;
  /** An error that cannot get better (the rest are retried): its reason. */
  finalError?(e: unknown): string | null;
  onValue?(value: T): void;
  onError?(e: unknown): void;
  /** Wait between attempts. */
  every: number;
  /** Stop with `expired` at or after this time (ms since the epoch). */
  until: number;
  now?(): number;
  sleep?(ms: number): Promise<void>;
}

export interface PollHandle<T> { cancel(): void; readonly result: Promise<PollOutcome<T>> }

const defaultSleep = (ms: number) => new Promise<void>((r) => { setTimeout(r, ms); });

/** Start polling. Attempts never overlap: the next starts `every` ms after the previous ended. */
export function poll<T>(o: PollOptions<T>): PollHandle<T> {
  let cancelled = false;
  let wake: (() => void) | null = null;
  const now = o.now ?? Date.now;
  const sleep = (ms: number) => new Promise<void>((resolve) => {
    wake = resolve;
    void (o.sleep ?? defaultSleep)(ms).then(() => { wake = null; resolve(); });
  });
  const result = (async (): Promise<PollOutcome<T>> => {
    let last: T | null = null;
    for (;;) {
      if (cancelled) return { kind: 'cancelled' };
      if (now() >= o.until) return { kind: 'expired', value: last };
      try {
        const value = await o.step();
        if (cancelled) return { kind: 'cancelled' };
        last = value;
        o.onValue?.(value);
        if (o.done(value)) return { kind: 'done', value };
        const reason = o.final?.(value) ?? null;
        if (reason) return { kind: 'failed', reason };
      } catch (e) {
        if (cancelled) return { kind: 'cancelled' };
        const reason = o.finalError?.(e) ?? null;
        if (reason) return { kind: 'failed', reason };
        o.onError?.(e);
      }
      await sleep(Math.max(0, Math.min(o.every, o.until - now())));
    }
  })();
  return {
    cancel() { cancelled = true; const w = wake as (() => void) | null; wake = null; w?.(); },
    result,
  };
}
