import { call } from '../ipc/client';
import type { Control } from '../ipc/contract';
import { newRecordCount, recordSig, sameControl } from '../lib/dash';

export interface RecordWatch {
  /** Read the tail once; a read still running makes this one a no-op. */
  poll(): Promise<void>;
  /** A read still running reports nothing. */
  stop(): void;
}

/** How the dashboard follows usage records (`audit_tail`; the core does not push them). The first
 *  read only marks where the log ends. A later read that finds new records reports how many, then
 *  reads the stop, incident and restore state again (`control_get`) and reports it when it differs
 *  from `current()`: that state also changes without the window asking, when the relay opens an
 *  incident or stops everything on its own (docs/compromise-response.md) or a command runs in the
 *  app's terminal, and each of those leaves a record. Failed reads are tried again next time,
 *  including a failed state read after new records. */
export function watchRecords(
  on: { records(n: number): void; control(c: Control): void },
  current: () => Control,
): RecordWatch {
  // `due`: records came since the state was last read successfully
  let dead = false, inflight = false, first = true, due = false, sig: string | null = null;
  return {
    async poll() {
      if (dead || inflight) return;
      inflight = true;
      try {
        const r = await call('audit_tail', { limit: 50 });
        if (dead) return;
        const n = first ? 0 : newRecordCount(sig, r.records);
        first = false;
        sig = recordSig(r.records[r.records.length - 1]);
        if (n > 0) { on.records(n); due = true; }
        if (!due) return;
        const c = await call('control_get');
        due = false;
        if (!dead && !sameControl(c, current())) on.control(c);
      } catch {
        // the next poll tries again
      } finally { inflight = false; }
    },
    stop() { dead = true; },
  };
}
