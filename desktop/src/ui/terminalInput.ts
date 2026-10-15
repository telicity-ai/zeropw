// Keyboard input for one in-app terminal (docs/desktop-app.md §4.4). Input goes to the core one
// `terminal_write` at a time, in the order it was typed, cut to the core's per-call limit.
// The core refuses input with `terminal_busy` while the program leaves 256 KiB unread. The
// refused chunk is dropped, and so is everything typed behind it before the refusal was known:
// sent later, it would land after newer input and splice lines together. The terminal then says
// that input was dropped (`busy`), and the next input typed after that is tried again.

import { toIpcError } from '../ipc/client';

/** The core refuses one `terminal_write` over this many UTF-8 bytes (`terminal_write_too_large`). */
export const MAX_WRITE_BYTES = 64 * 1024;

const utf8Length = (cp: number): number => (cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4);

/** Cut text into pieces of at most `max` UTF-8 bytes, never inside a character. */
export function splitUtf8(text: string, max = MAX_WRITE_BYTES): string[] {
  const out: string[] = [];
  let start = 0, bytes = 0, i = 0;
  while (i < text.length) {
    const cp = text.codePointAt(i) ?? 0;
    const units = cp > 0xffff ? 2 : 1;
    const n = utf8Length(cp);
    if (bytes + n > max && i > start) {
      out.push(text.slice(start, i));
      start = i; bytes = 0;
    }
    bytes += n; i += units;
  }
  if (i > start) out.push(text.slice(start, i));
  return out;
}

export interface TerminalInputEvents {
  /** Input was refused because the program is not reading it; it was dropped. */
  busy(): void;
  /** Input went through again after a refusal. */
  accepted(): void;
  /** The terminal no longer exists. */
  gone(): void;
}

export class TerminalInput {
  private queue: string[] = [];
  private sending = false;
  private refused = false;
  private stopped = false;
  private running: Promise<void> = Promise.resolve();

  constructor(private readonly send: (data: string) => Promise<unknown>, private readonly on: TerminalInputEvents) {}

  write(data: string): void {
    if (this.stopped || !data) return;
    this.queue.push(...splitUtf8(data));
    if (!this.sending) this.running = this.pump();
  }

  /** The view went away: nothing more is sent. */
  dispose(): void {
    this.stopped = true;
    this.queue = [];
  }

  /** Settles once everything written so far was sent or dropped. */
  idle(): Promise<void> {
    return this.running;
  }

  private async pump(): Promise<void> {
    this.sending = true;
    while (this.queue.length > 0 && !this.stopped) {
      const chunk = this.queue.shift() as string;
      try {
        await this.send(chunk);
        if (this.refused) { this.refused = false; this.on.accepted(); }
      } catch (e) {
        const reason = toIpcError(e).reason;
        if (reason === 'terminal_busy') {
          this.queue = [];
          this.refused = true;
          this.on.busy();
        } else if (reason === 'terminal_not_found') {
          this.dispose();
          this.on.gone();
        }
      }
    }
    // no await between the last check of the queue and this: a write that arrives later starts a new pump
    this.sending = false;
  }
}
